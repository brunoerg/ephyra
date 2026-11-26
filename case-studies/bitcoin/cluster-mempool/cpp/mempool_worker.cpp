// Standalone crash-isolated worker for Bitcoin Core Cluster Mempool testing.
// Speaks a simple text protocol over stdin/stdout (one command per line, one response per line).
// Compiled in two variants:
//   - cluster_worker_san (ASan + UBSan + ABORT_ON_FAILED_ASSUME)
//   - cluster_worker_cov (Clang source-based coverage)
//
// Any C++ assert(), Assume(), ASan, or UBSan violation aborts this child process cleanly,
// letting the Ephyra Rust parent capture stderr, assign a signature, and shrink the counterexample!

#include <chain.h>
#include <cluster_linearize.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <node/mempool_persist.h>
#include <node/miner.h>
#include <node/mini_miner.h>
#include <node/mining_types.h>
#include <policy/ephemeral_policy.h>
#include <policy/feerate.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <policy/settings.h>
#include <policy/truc_policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txgraph.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using node::BlockAssembler;
using node::BlockCreateOptions;
using node::DumpMempool;
using node::ImportMempoolOptions;
using node::LoadMempool;
using node::MiniMiner;
using node::NodeContext;

// Satisfy libtest_util's setup_common.cpp test hooks.
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    return std::vector<const char*>{};
};
const std::function<std::string()> G_TEST_GET_FULL_NAME = []() {
    return std::string{"ephyra_cluster_mempool_worker"};
};

namespace {

struct DummyChainState final : public Chainstate {
    void SetMempool(CTxMemPool* mempool) { m_mempool = mempool; }
};

struct MockedTxPool : public CTxMemPool {
    void RollingFeeUpdate() EXCLUSIVE_LOCKS_REQUIRED(!cs)
    {
        LOCK(cs);
        lastRollingFeeUpdate = GetTime();
        blockSinceLastRollingFeeBump = true;
    }
};

static std::unique_ptr<const TestingSetup> g_setup;
static std::vector<COutPoint> g_mature_coinbases;
static int64_t g_base_time = 0;

static void init_node()
{
    if (g_setup) return;
    g_setup = MakeNoLogFileContext<const TestingSetup>();
    g_base_time = WITH_LOCK(g_setup->m_node.chainman->GetMutex(),
                            return TicksSinceEpoch<std::chrono::seconds>(g_setup->m_node.chainman->ActiveTip()->Time()));
    SetMockTime(std::chrono::seconds{g_base_time + 100});
    // Mine 2 * COINBASE_MATURITY blocks with P2WSH_OP_TRUE coinbases so we have 100 mature UTXOs.
    // Wait: let's use P2WSH_EMPTY (which is standard and takes empty/true witness stack) OR P2WSH_OP_TRUE.
    // Both P2WSH_OP_TRUE and P2WSH_EMPTY are standard; P2WSH_OP_TRUE uses WITNESS_STACK_ELEM_OP_TRUE.
    for (int i = 0; i < COINBASE_MATURITY + 32; ++i) {
        COutPoint op = MineBlock(g_setup->m_node, {
            .coinbase_output_script = P2WSH_OP_TRUE,
        });
        if (i < 32) {
            g_mature_coinbases.push_back(op);
        }
    }
    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

static std::vector<std::string> split_ws(const std::string& line)
{
    std::istringstream iss(line);
    std::vector<std::string> out;
    std::string tok;
    while (iss >> tok) out.push_back(tok);
    return out;
}

static std::optional<CTransactionRef> decode_tx_hex(const std::string& hex)
{
    auto bytes = TryParseHex<uint8_t>(hex);
    if (!bytes) return std::nullopt;
    try {
        SpanReader sr{*bytes};
        CMutableTransaction mtx;
        sr >> TX_WITH_WITNESS(mtx);
        return MakeTransactionRef(std::move(mtx));
    } catch (...) {
        return std::nullopt;
    }
}

static std::string diagram_to_str(const std::vector<FeePerWeight>& diag)
{
    std::ostringstream oss;
    oss << diag.size();
    for (const auto& p : diag) {
        oss << " " << p.fee << ":" << p.size;
    }
    return oss.str();
}

static std::vector<FeeFrac> diagram_to_chunks(const std::vector<FeePerWeight>& diag)
{
    std::vector<FeeFrac> chunks;
    for (size_t i = 1; i < diag.size(); ++i) {
        chunks.emplace_back(diag[i].fee - diag[i - 1].fee, diag[i].size - diag[i - 1].size);
    }
    return chunks;
}

struct Session {
    std::unique_ptr<CTxMemPool> pool_owner;
    MockedTxPool* pool{nullptr};
    std::vector<CTransactionRef> last_mined_vtx;
    int64_t mock_time{0};
    bool require_standard{true};
    bool had_reorg{false};

    void reset(unsigned limit_cluster_count, unsigned limit_cluster_size_kvb,
               unsigned max_mempool_mb, unsigned min_relay_sat_kvb,
               bool req_std, unsigned bytes_per_sigop)
    {
        init_node();
        const auto& node = g_setup->m_node;
        auto& chainstate = static_cast<DummyChainState&>(node.chainman->ActiveChainstate());
        mock_time = g_base_time + 10000;
        SetMockTime(std::chrono::seconds{mock_time});
        require_standard = req_std;
        had_reorg = false;
        last_mined_vtx.clear();

        nBytesPerSigOp = bytes_per_sigop;

        CTxMemPool::Options opts{MemPoolOptionsForTest(node)};
        opts.limits.cluster_count = std::clamp(limit_cluster_count, 1U, MAX_CLUSTER_COUNT_LIMIT);
        opts.limits.cluster_size_vbytes = std::clamp<int64_t>(limit_cluster_size_kvb, 1, 250) * 1000;
        opts.max_size_bytes = static_cast<int64_t>(max_mempool_mb) * 1'000'000;
        opts.min_relay_feerate = CFeeRate(min_relay_sat_kvb);
        opts.incremental_relay_feerate = CFeeRate(1000);
        opts.require_standard = req_std;
        opts.check_ratio = 1;
        opts.expiry = std::chrono::hours{336};

        bilingual_str error;
        pool_owner = std::make_unique<CTxMemPool>(std::move(opts), error);
        // If max_size_bytes was smaller than 40*cluster_size, Flatten sets error; clamp in caller or ignore.
        pool = static_cast<MockedTxPool*>(pool_owner.get());
        chainstate.SetMempool(pool);
    }

    void check_mempool()
    {
        const auto& node = g_setup->m_node;
        auto& chainstate = static_cast<DummyChainState&>(node.chainman->ActiveChainstate());
        WITH_LOCK(::cs_main, pool->check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1));
    }
};

} // namespace

int main()
{
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    Session sess;
    std::string line;

    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        auto tok = split_ws(line);
        if (tok.empty()) continue;
        const std::string& cmd = tok[0];

        if (cmd == "QUIT") {
            std::cout << "OK\n" << std::flush;
            break;
        } else if (cmd == "INIT") {
            // INIT <cluster_count> <cluster_size_kvb> <max_mempool_mb> <min_relay_sat_kvb> <require_std 0|1> <bytes_per_sigop>
            unsigned cc = std::stoul(tok.at(1));
            unsigned cs = std::stoul(tok.at(2));
            unsigned mm = std::stoul(tok.at(3));
            unsigned mr = std::stoul(tok.at(4));
            bool rs = std::stoul(tok.at(5)) != 0;
            unsigned bps = std::stoul(tok.at(6));
            sess.reset(cc, cs, mm, mr, rs, bps);
            std::cout << "OK " << g_mature_coinbases.size();
            for (const auto& op : g_mature_coinbases) {
                std::cout << " " << op.hash.GetHex() << ":" << op.n;
            }
            std::cout << "\n" << std::flush;
        } else if (cmd == "SUBMIT_TX") {
            // SUBMIT_TX <hex>
            auto tx = decode_tx_hex(tok.at(1));
            if (!tx) {
                std::cout << "ERR decode_failed\n" << std::flush;
                continue;
            }
            const auto& node = g_setup->m_node;
            auto& chainstate = static_cast<DummyChainState&>(node.chainman->ActiveChainstate());

            std::vector<FeePerWeight> diag_before;
            size_t size_before = 0;
            bool had_conflicts = false;
            {
                LOCK(sess.pool->cs);
                diag_before = sess.pool->GetFeerateDiagram();
                size_before = sess.pool->size();
                for (const auto& in : (*tx)->vin) {
                    if (sess.pool->GetConflictTx(in.prevout) != nullptr) had_conflicts = true;
                }
            }

            const auto res = WITH_LOCK(::cs_main,
                return AcceptToMemoryPool(chainstate, *tx, GetTime(), /*bypass_limits=*/false, /*test_accept=*/false));
            node.validation_signals->SyncWithValidationInterfaceQueue();

            bool accepted = res.m_result_type == MempoolAcceptResult::ResultType::VALID;
            bool replaced = !res.m_replaced_transactions.empty();

            std::vector<FeePerWeight> diag_after;
            size_t size_after = 0;
            {
                LOCK(sess.pool->cs);
                diag_after = sess.pool->GetFeerateDiagram();
                size_after = sess.pool->size();
            }

            // Compare feerate diagram before vs after
            auto cb = diagram_to_chunks(diag_before);
            auto ca = diagram_to_chunks(diag_after);
            auto cmp = CompareChunks(ca, cb);
            int cmp_code = (cmp < 0) ? -1 : (cmp == 0) ? 0 : (cmp > 0) ? 1 : 2;

            sess.check_mempool();
            if (accepted && !sess.had_reorg) {
                CheckMempoolTRUCInvariants(*sess.pool);
            }

            std::cout << "OK " << (accepted ? 1 : 0)
                      << " " << (replaced ? 1 : 0)
                      << " " << res.m_replaced_transactions.size()
                      << " " << (had_conflicts ? 1 : 0)
                      << " " << cmp_code
                      << " " << size_before << " " << size_after
                      << " " << (*tx)->GetHash().GetHex()
                      << " " << (res.m_state.IsInvalid() ? res.m_state.GetRejectReason() : "valid")
                      << "\n" << std::flush;
        } else if (cmd == "SUBMIT_PKG") {
            // SUBMIT_PKG <n> <hex1> <hex2> ...
            size_t n = std::stoul(tok.at(1));
            Package pkg;
            pkg.reserve(n);
            bool ok = true;
            for (size_t i = 0; i < n; ++i) {
                auto tx = decode_tx_hex(tok.at(2 + i));
                if (!tx) { ok = false; break; }
                pkg.push_back(*tx);
            }
            if (!ok) {
                std::cout << "ERR decode_failed\n" << std::flush;
                continue;
            }
            const auto& node = g_setup->m_node;
            auto& chainstate = static_cast<DummyChainState&>(node.chainman->ActiveChainstate());

            std::vector<FeePerWeight> diag_before;
            size_t size_before = 0;
            {
                LOCK(sess.pool->cs);
                diag_before = sess.pool->GetFeerateDiagram();
                size_before = sess.pool->size();
            }

            const auto res = WITH_LOCK(::cs_main,
                return ProcessNewPackage(chainstate, *sess.pool, pkg, /*test_accept=*/false, /*client_maxfeerate=*/{}));
            node.validation_signals->SyncWithValidationInterfaceQueue();

            if (res.m_state.GetResult() != PackageValidationResult::PCKG_POLICY) {
                const bool expect_valid = res.m_state.IsValid();
                auto err = CheckPackageMempoolAcceptResult(pkg, res, expect_valid, sess.pool);
                if (err.has_value()) {
                    std::cerr << "CHECK_PKG_RESULT_FAILED: " << *err << "\n";
                    std::abort();
                }
            }

            size_t n_accepted = 0;
            size_t n_replaced = 0;
            for (const auto& [wtxid, txres] : res.m_tx_results) {
                if (txres.m_result_type == MempoolAcceptResult::ResultType::VALID) ++n_accepted;
                n_replaced += txres.m_replaced_transactions.size();
            }

            std::vector<FeePerWeight> diag_after;
            size_t size_after = 0;
            {
                LOCK(sess.pool->cs);
                diag_after = sess.pool->GetFeerateDiagram();
                size_after = sess.pool->size();
            }
            auto cb = diagram_to_chunks(diag_before);
            auto ca = diagram_to_chunks(diag_after);
            auto cmp = CompareChunks(ca, cb);
            int cmp_code = (cmp < 0) ? -1 : (cmp == 0) ? 0 : (cmp > 0) ? 1 : 2;

            sess.check_mempool();
            if (n_accepted > 0 && !sess.had_reorg) {
                CheckMempoolTRUCInvariants(*sess.pool);
            }

            std::cout << "OK " << (res.m_state.IsValid() ? 1 : 0)
                      << " " << n_accepted
                      << " " << n_replaced
                      << " " << cmp_code
                      << " " << size_before << " " << size_after
                      << " " << (res.m_state.IsInvalid() ? res.m_state.GetRejectReason() : "valid")
                      << "\n" << std::flush;
        } else if (cmd == "PRIORITISE") {
            // PRIORITISE <txid_hex> <delta_sat>
            auto txid_opt = Txid::FromHex(tok.at(1));
            int64_t delta = std::stoll(tok.at(2));
            if (!txid_opt) {
                std::cout << "ERR bad_txid\n" << std::flush;
                continue;
            }
            sess.pool->PrioritiseTransaction(*txid_opt, delta);
            sess.check_mempool();
            std::cout << "OK\n" << std::flush;
        } else if (cmd == "ADVANCE_TIME") {
            // ADVANCE_TIME <seconds>
            int64_t dt = std::stoll(tok.at(1));
            sess.mock_time += dt;
            SetMockTime(std::chrono::seconds{sess.mock_time});
            sess.pool->RollingFeeUpdate();
            std::cout << "OK " << sess.mock_time << "\n" << std::flush;
        } else if (cmd == "TRIM") {
            // TRIM <max_bytes>
            size_t lim = std::stoull(tok.at(1));
            size_t before = sess.pool->size();
            {
                LOCK2(::cs_main, sess.pool->cs);
                sess.pool->TrimToSize(lim);
            }
            sess.check_mempool();
            size_t after = sess.pool->size();
            std::cout << "OK " << before << " " << after << " " << sess.pool->DynamicMemoryUsage() << "\n" << std::flush;
        } else if (cmd == "EXPIRE") {
            // EXPIRE <age_seconds>
            int64_t age = std::stoll(tok.at(1));
            int removed = 0;
            {
                LOCK2(::cs_main, sess.pool->cs);
                removed = sess.pool->Expire(std::chrono::seconds{sess.mock_time - age});
            }
            sess.check_mempool();
            std::cout << "OK " << removed << " " << sess.pool->size() << "\n" << std::flush;
        } else if (cmd == "MINE_BLOCK") {
            // MINE_BLOCK <block_max_weight> <block_min_feerate_sat_kvb> <remove_from_pool 0|1>
            uint64_t max_w = std::stoull(tok.at(1));
            int64_t min_fr = std::stoll(tok.at(2));
            bool do_remove = std::stoul(tok.at(3)) != 0;

            const auto& node = g_setup->m_node;
            auto& chainstate = static_cast<DummyChainState&>(node.chainman->ActiveChainstate());
            BlockCreateOptions options{
                .block_min_fee_rate = CFeeRate{min_fr},
                .block_max_weight = std::clamp<uint64_t>(max_w, DEFAULT_BLOCK_RESERVED_WEIGHT + 4000, MAX_BLOCK_WEIGHT),
                .test_block_validity = true,
            };
            auto assembler = BlockAssembler{chainstate, sess.pool, options};
            auto tmpl = assembler.CreateNewBlock();
            size_t n_txs = tmpl->block.vtx.size() - 1; // excluding coinbase
            int64_t total_fees = 0;
            for (auto f : tmpl->vTxFees) total_fees += f;

            // Verify every included chunk satisfies block_min_fee_rate.
            bool mono_ok = true;
            for (const auto& pf : tmpl->m_package_feerates) {
                if (ByRatio{pf} < ByRatio{options.block_min_fee_rate->GetFeePerVSize()}) {
                    mono_ok = false;
                }
            }

            if (do_remove && n_txs > 0) {
                // Simulate mining this block and immediately reorging it back into the mempool
                // (mirrors src/test/fuzz/tx_pool.cpp:173-187, keeping chainstate.CoinsTip() consistent
                // while exercising removeForBlock + bypass_limits re-entry + UpdateTransactionsFromBlock / TxGraph::Trim!).
                LOCK2(::cs_main, sess.pool->cs);
                sess.pool->removeForBlock(tmpl->block.vtx);
                std::vector<Txid> hashes_to_update;
                for (size_t i = 1; i < tmpl->block.vtx.size(); ++i) {
                    const auto& tx = tmpl->block.vtx[i];
                    const auto res = AcceptToMemoryPool(chainstate, tx, GetTime(), /*bypass_limits=*/true, /*test_accept=*/false);
                    if (res.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                        hashes_to_update.push_back(tx->GetHash());
                    } else {
                        sess.pool->removeRecursive(*tx, MemPoolRemovalReason::REORG);
                    }
                }
                sess.pool->UpdateTransactionsFromBlock(hashes_to_update);
                sess.had_reorg = true;
            }
            sess.check_mempool();
            std::cout << "OK " << n_txs << " " << total_fees << " " << (mono_ok ? 1 : 0) << " " << sess.pool->size() << "\n" << std::flush;
        } else if (cmd == "REORG_BACK") {
            // Re-insert last_mined_vtx as on DisconnectBlock + UpdateTransactionsFromBlock (triggers TxGraph::Trim!)
            const auto& node = g_setup->m_node;
            auto& chainstate = static_cast<DummyChainState&>(node.chainman->ActiveChainstate());
            size_t reinserted = 0;
            {
                LOCK2(::cs_main, sess.pool->cs);
                std::vector<Txid> hashes_to_update;
                for (const auto& tx : sess.last_mined_vtx) {
                    const auto res = AcceptToMemoryPool(chainstate, tx, GetTime(), /*bypass_limits=*/true, /*test_accept=*/false);
                    if (res.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                        hashes_to_update.push_back(tx->GetHash());
                        ++reinserted;
                    } else {
                        sess.pool->removeRecursive(*tx, MemPoolRemovalReason::REORG);
                    }
                }
                sess.pool->UpdateTransactionsFromBlock(hashes_to_update);
            }
            sess.had_reorg = true;
            sess.last_mined_vtx.clear();
            sess.check_mempool();
            std::cout << "OK " << reinserted << " " << sess.pool->size() << "\n" << std::flush;
        } else if (cmd == "CHECK_EPHEMERAL") {
            // Verify CheckMempoolEphemeralInvariants (only valid if no dust tx was prioritised)
            CheckMempoolEphemeralInvariants(*sess.pool);
            std::cout << "OK\n" << std::flush;
        } else if (cmd == "MINIMINER") {
            // MINIMINER <target_feerate_sat_kvb> <n_outpoints> <txid:vout> ...
            int64_t target_fr = std::stoll(tok.at(1));
            size_t n = std::stoul(tok.at(2));
            std::vector<COutPoint> ops;
            ops.reserve(n);
            for (size_t i = 0; i < n; ++i) {
                const auto& s = tok.at(3 + i);
                auto colon = s.find(':');
                auto txid = Txid::FromHex(s.substr(0, colon));
                uint32_t vout = std::stoul(s.substr(colon + 1));
                if (txid) ops.emplace_back(*txid, vout);
            }
            MiniMiner mm(*sess.pool, ops);
            auto ready = mm.IsReadyToCalculate();
            size_t bump_count = 0;
            int64_t min_bump = 0;
            int64_t sum_bump = 0;
            int64_t total_bump = 0;
            int64_t has_total_bump = 0;
            int topo_ok = 1;
            if (ready) {
                auto bumps = mm.CalculateBumpFees(CFeeRate{target_fr});
                bump_count = bumps.size();
                bool first = true;
                for (const auto& [op, fee] : bumps) {
                    if (first || fee < min_bump) { min_bump = fee; first = false; }
                    sum_bump += fee;
                }
                MiniMiner mm2(*sess.pool, ops);
                if (mm2.IsReadyToCalculate()) {
                    auto tb = mm2.CalculateTotalBumpFees(CFeeRate{target_fr});
                    if (tb.has_value()) {
                        has_total_bump = 1;
                        total_bump = *tb;
                    }
                }
                MiniMiner mm3(*sess.pool, ops);
                if (mm3.IsReadyToCalculate()) {
                    mm3.BuildMockTemplate(CFeeRate{target_fr});
                    auto in_blk = mm3.GetMockTemplateTxids();
                    // Check topological closure: if tx is in mock template, every in-mempool parent
                    // (not to-be-replaced) must also be in mock template.
                    LOCK(sess.pool->cs);
                    for (const auto& txid : in_blk) {
                        if (auto ptx = sess.pool->get(txid)) {
                            for (const auto& vin : ptx->vin) {
                                if (sess.pool->exists(vin.prevout.hash) && !in_blk.contains(vin.prevout.hash)) {
                                    topo_ok = 0;
                                }
                            }
                        }
                    }
                }
                MiniMiner mm4(*sess.pool, ops);
                if (mm4.IsReadyToCalculate()) {
                    auto lin = mm4.Linearize();
                    LOCK(sess.pool->cs);
                    for (const auto& [txid, seq] : lin) {
                        if (auto ptx = sess.pool->get(txid)) {
                            for (const auto& vin : ptx->vin) {
                                auto pit = lin.find(vin.prevout.hash);
                                if (pit != lin.end() && pit->second > seq) {
                                    topo_ok = 0;
                                }
                            }
                        }
                    }
                }
            }
            std::cout << "OK " << (ready ? 1 : 0)
                      << " " << bump_count
                      << " " << min_bump
                      << " " << has_total_bump
                      << " " << total_bump
                      << " " << sum_bump
                      << " " << topo_ok
                      << "\n" << std::flush;
        } else if (cmd == "RBF_AND_QUERIES") {
            // RBF_AND_QUERIES <tx_hex>
            auto tx = decode_tx_hex(tok.at(1));
            if (!tx) {
                std::cout << "ERR decode_failed\n" << std::flush;
                continue;
            }
            RBFTransactionState st_empty = IsRBFOptInEmptyMempool(**tx);
            RBFTransactionState st_pool;
            size_t anc_count = 0, cluster_count = 0, anc_size = 0;
            CAmount anc_fees = 0;
            bool has_desc = false;
            bool policy_ok = false;
            int64_t min_fee = 0;
            {
                LOCK(sess.pool->cs);
                st_pool = IsRBFOptIn(**tx, *sess.pool);
                min_fee = sess.pool->GetMinFee().GetFeePerK();
            }
            sess.pool->GetTransactionAncestry((*tx)->GetHash(), anc_count, cluster_count, &anc_size, &anc_fees);
            has_desc = sess.pool->HasDescendants((*tx)->GetHash());
            policy_ok = sess.pool->CheckPolicyLimits(*tx);
            auto prios = sess.pool->GetPrioritisedTransactions();
            std::cout << "OK " << static_cast<int>(st_empty)
                      << " " << static_cast<int>(st_pool)
                      << " " << anc_count
                      << " " << cluster_count
                      << " " << (has_desc ? 1 : 0)
                      << " " << (policy_ok ? 1 : 0)
                      << " " << min_fee
                      << " " << prios.size()
                      << "\n" << std::flush;
        } else if (cmd == "EXTRACT_RELAY") {
            // EXTRACT_RELAY <n_to_sort> <extra_missing_count>
            size_t n_to_sort = std::stoul(tok.at(1));
            size_t extra_missing = std::stoul(tok.at(2));
            std::vector<Wtxid> wtxids;
            {
                LOCK(sess.pool->cs);
                for (const auto& e : sess.pool->entryAll()) {
                    wtxids.push_back(e.get().GetTx().GetWitnessHash());
                    // Include a duplicate for every other entry to test deduplication
                    if (wtxids.size() % 3 == 0) wtxids.push_back(e.get().GetTx().GetWitnessHash());
                }
                for (size_t i = 0; i < extra_missing; ++i) {
                    wtxids.push_back(Wtxid::FromUint256(uint256{static_cast<uint8_t>(i + 1)}));
                }
                size_t before = wtxids.size();
                auto res = sess.pool->ExtractBestByMiningScoreWithTopology(wtxids, n_to_sort);
                const size_t expected_count = std::min(n_to_sort, before);
                Assert(wtxids.size() <= before - expected_count);
                Assert(res.size() == expected_count || wtxids.empty());
                if (n_to_sort > 0) {
                    for (const auto& w : wtxids) {
                        Assert(sess.pool->GetIter(w).has_value());
                    }
                    std::set<Wtxid> uniq_rem(wtxids.begin(), wtxids.end());
                    Assert(uniq_rem.size() == wtxids.size());
                    for (const auto& it : res) {
                        Assert(!uniq_rem.contains(it->GetTx().GetWitnessHash()));
                    }
                }
                std::cout << "OK " << before << " " << res.size() << " " << wtxids.size() << "\n" << std::flush;
            }
        } else if (cmd == "DUMP_LOAD") {
            // DUMP_LOAD <path> <apply_deltas 0|1>
            fs::path p = fs::PathFromString(tok.at(1));
            bool apply_deltas = std::stoul(tok.at(2)) != 0;
            bool dumped = DumpMempool(*sess.pool, p, fsbridge::fopen, /*skip_file_commit=*/true);
            if (!dumped) {
                std::cout << "ERR dump_failed\n" << std::flush;
                continue;
            }
            // Load into a fresh mempool with identical options
            const auto& node = g_setup->m_node;
            auto& chainstate = static_cast<DummyChainState&>(node.chainman->ActiveChainstate());
            CTxMemPool::Options opts = sess.pool->m_opts;
            bilingual_str err;
            auto pool2 = std::make_unique<CTxMemPool>(std::move(opts), err);
            chainstate.SetMempool(pool2.get());
            ImportMempoolOptions iopts{
                .use_current_time = false,
                .apply_fee_delta_priority = apply_deltas,
                .apply_unbroadcast_set = true,
            };
            bool loaded = LoadMempool(*pool2, p, chainstate, std::move(iopts));
            WITH_LOCK(::cs_main, pool2->check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1));
            CheckMempoolTRUCInvariants(*pool2);
            size_t sz1 = sess.pool->size();
            size_t sz2 = pool2->size();
            // Restore original pool
            chainstate.SetMempool(sess.pool);
            std::error_code ec;
            std::filesystem::remove(tok.at(1), ec);
            std::cout << "OK " << (loaded ? 1 : 0) << " " << sz1 << " " << sz2 << "\n" << std::flush;
        } else if (cmd == "STATE") {
            // Return mempool size, total_tx_size, total_fee, dynamic_mem, and txids + feerate diagram
            LOCK(sess.pool->cs);
            auto diag = sess.pool->GetFeerateDiagram();
            auto info = sess.pool->infoAll();
            std::cout << "OK " << sess.pool->size()
                      << " " << sess.pool->GetTotalTxSize()
                      << " " << sess.pool->GetTotalFee()
                      << " " << sess.pool->DynamicMemoryUsage()
                      << " " << info.size();
            for (const auto& ti : info) {
                std::cout << " " << ti.tx->GetHash().GetHex() << ":" << ti.fee << ":" << ti.nFeeDelta;
            }
            std::cout << " | " << diagram_to_str(diag) << "\n" << std::flush;
        } else {
            std::cout << "ERR unknown_cmd\n" << std::flush;
        }
    }
    return 0;
}
