#include "txgraph_shim.h"

#include <cluster_linearize.h>
#include <txgraph.h>
#include <util/bitset.h>
#include <util/check.h>
#include <util/feefrac.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <compare>
#include <memory>
#include <optional>
#include <vector>

using namespace cluster_linearize;

namespace {

static constexpr uint32_t MAX_SLOTS = 256;
static constexpr size_t MAX_BUILDERS = 4;

struct ShimRef final : public TxGraph::Ref {
    uint32_t slot{0};
    uint64_t txid{0};
    ShimRef() noexcept = default;
    ShimRef(uint32_t s, uint64_t id) noexcept : slot(s), txid(id) {}
    ShimRef(ShimRef&& other) noexcept : TxGraph::Ref(std::move(other)), slot(other.slot), txid(other.txid) {}
};

static inline TxGraph::Level to_level(int32_t level) {
    return level == 0 ? TxGraph::Level::MAIN : TxGraph::Level::TOP;
}

static inline uint32_t copy_refs(const std::vector<TxGraph::Ref*>& refs, uint32_t* out, uint32_t cap) {
    uint32_t n = static_cast<uint32_t>(refs.size());
    uint32_t lim = std::min(n, cap);
    for (uint32_t i = 0; i < lim; ++i) {
        out[i] = static_cast<const ShimRef*>(refs[i])->slot;
    }
    return n;
}

} // namespace

struct TgHandle {
    std::unique_ptr<TxGraph> graph;
    std::array<std::unique_ptr<ShimRef>, MAX_SLOTS> refs;
    ShimRef empty_ref{UINT32_MAX, 0};
    std::array<std::unique_ptr<TxGraph::BlockBuilder>, MAX_BUILDERS> builders;

    const TxGraph::Ref& get_ref(uint32_t slot) const {
        if (slot >= MAX_SLOTS || !refs[slot]) return empty_ref;
        return *refs[slot];
    }
};

extern "C" {

TgHandle* tg_create(uint32_t max_cluster_count, uint64_t max_cluster_size, uint64_t acceptable_cost) {
    auto* h = new TgHandle();
    auto fallback = [](const TxGraph::Ref& a, const TxGraph::Ref& b) noexcept -> std::strong_ordering {
        uint64_t ta = static_cast<const ShimRef&>(a).txid;
        uint64_t tb = static_cast<const ShimRef&>(b).txid;
        return ta <=> tb;
    };
    h->graph = MakeTxGraph(max_cluster_count, max_cluster_size, acceptable_cost, fallback);
    return h;
}

void tg_destroy(TgHandle* h) {
    if (!h) return;
    for (auto& b : h->builders) b.reset();
    for (auto& r : h->refs) r.reset();
    h->graph.reset();
    delete h;
}

int32_t tg_add_tx(TgHandle* h, uint32_t slot, int64_t fee, int32_t size, uint64_t txid) {
    if (slot >= MAX_SLOTS || h->refs[slot] != nullptr) return 0;
    h->refs[slot] = std::make_unique<ShimRef>(slot, txid);
    h->graph->AddTransaction(*h->refs[slot], FeePerWeight{fee, size});
    return 1;
}

int32_t tg_remove_tx(TgHandle* h, uint32_t slot) {
    h->graph->RemoveTransaction(h->get_ref(slot));
    return 1;
}

int32_t tg_destroy_ref(TgHandle* h, uint32_t slot) {
    if (slot >= MAX_SLOTS) return 0;
    h->refs[slot].reset();
    return 1;
}

int32_t tg_move_ref(TgHandle* h, uint32_t from_slot, uint32_t to_slot) {
    if (from_slot >= MAX_SLOTS || to_slot >= MAX_SLOTS || from_slot == to_slot) return 0;
    if (!h->refs[from_slot] || h->refs[to_slot]) return 0;
    // Move-construct a brand new ShimRef at a different heap address to exercise TxGraph::Ref(Ref&&) and UpdateRef!
    auto moved = std::make_unique<ShimRef>(std::move(*h->refs[from_slot]));
    moved->slot = to_slot;
    h->refs[from_slot].reset();
    h->refs[to_slot] = std::move(moved);
    return 1;
}

int32_t tg_add_dep(TgHandle* h, uint32_t parent_slot, uint32_t child_slot) {
    h->graph->AddDependency(h->get_ref(parent_slot), h->get_ref(child_slot));
    return 1;
}

int32_t tg_set_fee(TgHandle* h, uint32_t slot, int64_t fee) {
    h->graph->SetTransactionFee(h->get_ref(slot), fee);
    return 1;
}

void tg_start_staging(TgHandle* h) { h->graph->StartStaging(); }
void tg_abort_staging(TgHandle* h) { h->graph->AbortStaging(); }
void tg_commit_staging(TgHandle* h) { h->graph->CommitStaging(); }
int32_t tg_have_staging(TgHandle* h) { return h->graph->HaveStaging() ? 1 : 0; }
int32_t tg_do_work(TgHandle* h, uint64_t max_cost) { return h->graph->DoWork(max_cost) ? 1 : 0; }

uint32_t tg_trim(TgHandle* h, uint32_t* out_slots, uint32_t cap) {
    auto removed = h->graph->Trim();
    return copy_refs(removed, out_slots, cap);
}

int32_t tg_is_oversized(TgHandle* h, int32_t level) {
    return h->graph->IsOversized(to_level(level)) ? 1 : 0;
}

int32_t tg_exists(TgHandle* h, uint32_t slot, int32_t level) {
    return h->graph->Exists(h->get_ref(slot), to_level(level)) ? 1 : 0;
}

TgFeeFrac tg_get_individual_feerate(TgHandle* h, uint32_t slot) {
    auto f = h->graph->GetIndividualFeerate(h->get_ref(slot));
    return TgFeeFrac{f.fee, f.size};
}

TgFeeFrac tg_get_main_chunk_feerate(TgHandle* h, uint32_t slot) {
    auto f = h->graph->GetMainChunkFeerate(h->get_ref(slot));
    return TgFeeFrac{f.fee, f.size};
}

uint32_t tg_get_tx_count(TgHandle* h, int32_t level) {
    return h->graph->GetTransactionCount(to_level(level));
}

uint32_t tg_get_cluster(TgHandle* h, uint32_t slot, int32_t level, uint32_t* out_slots, uint32_t cap) {
    auto res = h->graph->GetCluster(h->get_ref(slot), to_level(level));
    return copy_refs(res, out_slots, cap);
}

uint32_t tg_get_ancestors(TgHandle* h, uint32_t slot, int32_t level, uint32_t* out_slots, uint32_t cap) {
    auto res = h->graph->GetAncestors(h->get_ref(slot), to_level(level));
    return copy_refs(res, out_slots, cap);
}

uint32_t tg_get_descendants(TgHandle* h, uint32_t slot, int32_t level, uint32_t* out_slots, uint32_t cap) {
    auto res = h->graph->GetDescendants(h->get_ref(slot), to_level(level));
    return copy_refs(res, out_slots, cap);
}

uint32_t tg_get_ancestors_union(TgHandle* h, const uint32_t* in_slots, uint32_t in_len, int32_t level, uint32_t* out_slots, uint32_t cap) {
    std::vector<const TxGraph::Ref*> ptrs;
    ptrs.reserve(in_len);
    for (uint32_t i = 0; i < in_len; ++i) ptrs.push_back(&h->get_ref(in_slots[i]));
    auto res = h->graph->GetAncestorsUnion(ptrs, to_level(level));
    return copy_refs(res, out_slots, cap);
}

uint32_t tg_get_descendants_union(TgHandle* h, const uint32_t* in_slots, uint32_t in_len, int32_t level, uint32_t* out_slots, uint32_t cap) {
    std::vector<const TxGraph::Ref*> ptrs;
    ptrs.reserve(in_len);
    for (uint32_t i = 0; i < in_len; ++i) ptrs.push_back(&h->get_ref(in_slots[i]));
    auto res = h->graph->GetDescendantsUnion(ptrs, to_level(level));
    return copy_refs(res, out_slots, cap);
}

int32_t tg_compare_main_order(TgHandle* h, uint32_t slot_a, uint32_t slot_b) {
    auto ord = h->graph->CompareMainOrder(h->get_ref(slot_a), h->get_ref(slot_b));
    if (ord < 0) return -1;
    if (ord > 0) return 1;
    return 0;
}

uint32_t tg_count_distinct_clusters(TgHandle* h, const uint32_t* in_slots, uint32_t in_len, int32_t level) {
    std::vector<const TxGraph::Ref*> ptrs;
    ptrs.reserve(in_len);
    for (uint32_t i = 0; i < in_len; ++i) ptrs.push_back(&h->get_ref(in_slots[i]));
    return h->graph->CountDistinctClusters(ptrs, to_level(level));
}

void tg_get_main_staging_diagrams(
    TgHandle* h,
    TgFeeFrac* out_main, uint32_t main_cap, uint32_t* out_main_len,
    TgFeeFrac* out_staging, uint32_t staging_cap, uint32_t* out_staging_len
) {
    auto [m, s] = h->graph->GetMainStagingDiagrams();
    *out_main_len = static_cast<uint32_t>(m.size());
    for (uint32_t i = 0; i < std::min<uint32_t>(m.size(), main_cap); ++i) {
        out_main[i] = TgFeeFrac{m[i].fee, m[i].size};
    }
    *out_staging_len = static_cast<uint32_t>(s.size());
    for (uint32_t i = 0; i < std::min<uint32_t>(s.size(), staging_cap); ++i) {
        out_staging[i] = TgFeeFrac{s[i].fee, s[i].size};
    }
}

uint32_t tg_get_worst_main_chunk(TgHandle* h, uint32_t* out_slots, uint32_t cap, TgFeeFrac* out_feerate) {
    auto [refs, rate] = h->graph->GetWorstMainChunk();
    if (out_feerate) *out_feerate = TgFeeFrac{rate.fee, rate.size};
    return copy_refs(refs, out_slots, cap);
}

size_t tg_get_main_memory_usage(TgHandle* h) {
    return h->graph->GetMainMemoryUsage();
}

void tg_sanity_check(TgHandle* h) {
    h->graph->SanityCheck();
}

int32_t tg_bb_open(TgHandle* h) {
    for (size_t i = 0; i < MAX_BUILDERS; ++i) {
        if (!h->builders[i]) {
            h->builders[i] = h->graph->GetBlockBuilder();
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

void tg_bb_close(TgHandle* h, int32_t bb_id) {
    if (bb_id >= 0 && static_cast<size_t>(bb_id) < MAX_BUILDERS) {
        h->builders[bb_id].reset();
    }
}

int32_t tg_bb_current(TgHandle* h, int32_t bb_id, uint32_t* out_slots, uint32_t cap, uint32_t* out_len, TgFeeFrac* out_feerate) {
    if (bb_id < 0 || static_cast<size_t>(bb_id) >= MAX_BUILDERS || !h->builders[bb_id]) return 0;
    auto cur = h->builders[bb_id]->GetCurrentChunk();
    if (!cur.has_value()) return 0;
    *out_len = copy_refs(cur->first, out_slots, cap);
    if (out_feerate) *out_feerate = TgFeeFrac{cur->second.fee, cur->second.size};
    return 1;
}

void tg_bb_include(TgHandle* h, int32_t bb_id) {
    if (bb_id >= 0 && static_cast<size_t>(bb_id) < MAX_BUILDERS && h->builders[bb_id]) {
        h->builders[bb_id]->Include();
    }
}

void tg_bb_skip(TgHandle* h, int32_t bb_id) {
    if (bb_id >= 0 && static_cast<size_t>(bb_id) < MAX_BUILDERS && h->builders[bb_id]) {
        h->builders[bb_id]->Skip();
    }
}

// =========================================================================
// cluster_linearize direct C API
// =========================================================================

using Set64 = BitSet<64>;

static DepGraph<Set64> build_depgraph(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks
) {
    DepGraph<Set64> dg;
    for (uint32_t i = 0; i < n; ++i) {
        dg.AddTransaction(FeeFrac{fees[i], sizes[i]});
    }
    for (uint32_t i = 0; i < n; ++i) {
        Set64 parents;
        uint64_t m = parent_masks[i];
        for (uint32_t p = 0; p < n; ++p) {
            if ((m >> p) & 1ULL) parents.Set(p);
        }
        if (parents.Any()) dg.AddDependencies(parents, i);
    }
    return dg;
}

void cl_linearize(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks,
    uint64_t max_cost,
    uint64_t rng_seed,
    const uint32_t* old_lin,
    uint32_t old_lin_len,
    int32_t is_topological,
    TgLinResult* out
) {
    auto dg = build_depgraph(n, fees, sizes, parent_masks);
    std::vector<DepGraphIndex> old_v;
    if (old_lin && old_lin_len > 0) {
        old_v.assign(old_lin, old_lin + old_lin_len);
    }
    auto fallback = [](DepGraphIndex a, DepGraphIndex b) noexcept -> std::strong_ordering {
        return a <=> b;
    };
    auto [lin, optimal, cost] = Linearize(dg, max_cost, rng_seed, fallback, old_v, is_topological != 0);
    auto chunks = ChunkLinearization(dg, lin);
    out->count = static_cast<uint32_t>(lin.size());
    for (uint32_t i = 0; i < lin.size(); ++i) out->order[i] = lin[i];
    out->optimal = optimal ? 1 : 0;
    out->cost = cost;
    out->chunk_count = static_cast<uint32_t>(chunks.size());
    for (uint32_t i = 0; i < chunks.size(); ++i) {
        out->chunks[i] = TgFeeFrac{chunks[i].fee, chunks[i].size};
    }
}

void cl_postlinearize(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks,
    const uint32_t* init_lin,
    TgLinResult* out
) {
    auto dg = build_depgraph(n, fees, sizes, parent_masks);
    std::vector<DepGraphIndex> lin(init_lin, init_lin + n);
    PostLinearize(dg, lin);
    auto chunks = ChunkLinearization(dg, lin);
    out->count = static_cast<uint32_t>(lin.size());
    for (uint32_t i = 0; i < lin.size(); ++i) out->order[i] = lin[i];
    out->optimal = 0;
    out->cost = 0;
    out->chunk_count = static_cast<uint32_t>(chunks.size());
    for (uint32_t i = 0; i < chunks.size(); ++i) {
        out->chunks[i] = TgFeeFrac{chunks[i].fee, chunks[i].size};
    }
}

void cl_chunk_linearization(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks,
    const uint32_t* lin,
    uint32_t* out_chunk_count,
    TgFeeFrac* out_chunks,
    int32_t* out_all_connected
) {
    auto dg = build_depgraph(n, fees, sizes, parent_masks);
    std::vector<DepGraphIndex> lv(lin, lin + n);
    auto infos = ChunkLinearizationInfo(dg, lv);
    *out_chunk_count = static_cast<uint32_t>(infos.size());
    int32_t all_conn = 1;
    for (uint32_t i = 0; i < infos.size(); ++i) {
        out_chunks[i] = TgFeeFrac{infos[i].feerate.fee, infos[i].feerate.size};
        if (!dg.IsConnected(infos[i].transactions)) all_conn = 0;
    }
    if (out_all_connected) *out_all_connected = all_conn;
}

int32_t cl_compare_chunks(
    const TgFeeFrac* a, uint32_t a_len,
    const TgFeeFrac* b, uint32_t b_len
) {
    std::vector<FeeFrac> va, vb;
    va.reserve(a_len);
    vb.reserve(b_len);
    for (uint32_t i = 0; i < a_len; ++i) va.emplace_back(a[i].fee, a[i].size);
    for (uint32_t i = 0; i < b_len; ++i) vb.emplace_back(b[i].fee, b[i].size);
    auto cmp = CompareChunks(va, vb);
    if (cmp < 0) return -1;
    if (cmp == 0) return 0;
    if (cmp > 0) return 1;
    return 2; // partial_ordering::unordered
}

void cl_exhaustive_linearize(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks,
    TgLinResult* out
) {
    Assume(n <= 10);
    auto dg = build_depgraph(n, fees, sizes, parent_masks);
    std::vector<DepGraphIndex> best_lin;
    std::vector<FeeFrac> best_chunks;
    std::vector<DepGraphIndex> perm(n);
    for (uint32_t i = 0; i < n; ++i) perm[i] = i;
    do {
        uint32_t topo_len = 0;
        Set64 done;
        while (topo_len < n) {
            auto idx = perm[topo_len];
            done.Set(idx);
            if (!dg.Ancestors(idx).IsSubsetOf(done)) break;
            ++topo_len;
        }
        if (topo_len == n) {
            auto chunks = ChunkLinearization(dg, perm);
            auto cmp = CompareChunks(chunks, best_chunks);
            if (best_lin.empty() || cmp > 0 || (cmp == 0 && chunks.size() > best_chunks.size())) {
                best_lin = perm;
                best_chunks = std::move(chunks);
            }
        } else {
            auto first_bad = perm.begin() + topo_len;
            std::reverse(first_bad + 1, perm.end());
        }
    } while (std::next_permutation(perm.begin(), perm.end()));

    out->count = static_cast<uint32_t>(best_lin.size());
    for (uint32_t i = 0; i < best_lin.size(); ++i) out->order[i] = best_lin[i];
    out->optimal = 1;
    out->cost = 0;
    out->chunk_count = static_cast<uint32_t>(best_chunks.size());
    for (uint32_t i = 0; i < best_chunks.size(); ++i) {
        out->chunks[i] = TgFeeFrac{best_chunks[i].fee, best_chunks[i].size};
    }
}

} // extern "C"
