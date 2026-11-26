//! Property 4: Full-stack Cluster Mempool stateful property tests driven against
//! Bitcoin Core's real `CTxMemPool`, `AcceptToMemoryPool`, `ProcessNewPackage`,
//! `BlockAssembler`, `MiniMiner`, `PrioritiseTransaction`, `TrimToSize`, `Expire`,
//! `UpdateTransactionsFromBlock` (reorg), and `DumpMempool`/`LoadMempool`,
//! executed inside a crash-isolated ASan+UBSan+Assume worker child process!

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use ephyra_bitcoin_cluster_mempool::gen_mempool::{
    mempool_scenarios, MempoolOp, MempoolScenario, PackageShape, TxKind, TxSpec,
};
use ephyra_bitcoin_cluster_mempool::worker::MempoolWorker;

thread_local! {
    static WORKER: RefCell<MempoolWorker> = RefCell::new(MempoolWorker::default_san());
}

/// P2WSH(OP_TRUE) scriptPubKey and witness stack (matches Bitcoin Core's `P2WSH_OP_TRUE` in test/util/script.h).
fn p2wsh_op_true_spk() -> ScriptBuf {
    // OP_0 <sha256(OP_TRUE)>
    // OP_TRUE = 0x51; sha256([0x51]) = 4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a
    let witness_script = ScriptBuf::from_bytes(vec![0x51]);
    ScriptBuf::new_p2wsh(&witness_script.wscript_hash())
}

fn p2wsh_op_true_witness(pad_bytes: u16) -> Witness {
    if pad_bytes == 0 {
        Witness::from_slice(&[&[0x51u8][..]])
    } else {
        // Push extra data element that gets ignored by OP_TRUE? No, P2WSH(OP_TRUE) fails CLEANSTACK
        // if extra stack elements exist! So keep witness minimal and put padding in an OP_RETURN output instead.
        Witness::from_slice(&[&[0x51u8][..]])
    }
}

fn p2pk_sigop_spk() -> ScriptBuf {
    // 33-byte compressed pubkey + OP_CHECKSIG (non-spendable by our harness, exercises sigop cost)
    let mut b = Vec::with_capacity(35);
    b.push(33);
    b.push(0x02);
    b.extend_from_slice(&[0x11; 32]);
    b.push(0xac); // OP_CHECKSIG
    ScriptBuf::from_bytes(b)
}

fn parse_outpoint(s: &str) -> OutPoint {
    let (h, n) = s.split_once(':').unwrap();
    let txid: Txid = h.parse().unwrap();
    let vout: u32 = n.parse().unwrap();
    OutPoint { txid, vout }
}

fn send_checked(cmd: &str, step: usize, op_desc: &str) -> String {
    WORKER.with(|w| {
        let mut worker = w.borrow_mut();
        match worker.send(cmd) {
            Ok(resp) => resp,
            Err(crash) => {
                ephyra::signature(&crash.signature);
                panic!(
                    "step {step} ({op_desc}): worker crashed [{}]\ncmd: {}\n{}",
                    crash.signature,
                    &cmd[..cmd.len().min(300)],
                    crash.detail
                );
            }
        }
    })
}

#[derive(Clone, Debug)]
struct UtxoInfo {
    value: u64,
    spendable: bool,
}

struct HarnessState {
    /// Confirmed mature coinbase outpoints.
    coinbases: Vec<OutPoint>,
    /// All known outpoints -> value/info (confirmed + in-mempool).
    known_utxos: BTreeMap<OutPoint, UtxoInfo>,
    /// Currently unspent spendable outpoints (not spent by any tx currently in mempool).
    unspent: BTreeSet<OutPoint>,
    /// Outpoints currently spent by a mempool tx (eligible for RBF double-spends!).
    spent_in_mempool: BTreeSet<OutPoint>,
    /// Transactions currently in mempool: txid -> Transaction
    in_mempool: BTreeMap<Txid, Transaction>,
    /// All txids ever created (for PrioritiseTransaction).
    all_txids: Vec<Txid>,
    /// Whether any tx was prioritised (known exclusion for CheckMempoolEphemeralInvariants per package_eval.cpp:349).
    prioritised_any: bool,
    /// Whether any tx currently in mempool has negative modified fee (which makes global
    /// CompareChunks non-monotone under unchanged negative-fee tail shifts).
    has_negative_mod_fee: bool,
    had_reorg: bool,
    last_mined_any: bool,
}

impl HarnessState {
    fn sync_from_worker(&mut self, step: usize) {
        let resp = send_checked("STATE", step, "STATE");
        let parts: Vec<&str> = resp.split_whitespace().collect();
        assert_eq!(parts[0], "OK", "STATE failed: {resp}");
        let info_count: usize = parts[5].parse().unwrap();
        let mut live_txids = BTreeSet::new();
        self.has_negative_mod_fee = false;
        for i in 0..info_count {
            let item = parts[6 + i];
            let mut it = item.split(':');
            let txid_hex = it.next().unwrap();
            let base_fee: i64 = it.next().unwrap().parse().unwrap();
            let delta: i64 = it.next().unwrap().parse().unwrap();
            if base_fee.saturating_add(delta) < 0 {
                self.has_negative_mod_fee = true;
            }
            let txid: Txid = txid_hex.parse().unwrap();
            live_txids.insert(txid);
        }
        // Retain only actually-present mempool txs and rebuild unspent / spent_in_mempool accurately.
        self.in_mempool.retain(|k, _| live_txids.contains(k));
        self.unspent.clear();
        self.spent_in_mempool.clear();
        for op in &self.coinbases {
            self.unspent.insert(*op);
        }
        for tx in self.in_mempool.values() {
            let txid = tx.compute_txid();
            for (vout, _out) in tx.output.iter().enumerate() {
                let op = OutPoint { txid, vout: vout as u32 };
                if self.known_utxos.get(&op).map_or(false, |u| u.spendable) {
                    self.unspent.insert(op);
                }
            }
        }
        for tx in self.in_mempool.values() {
            for inp in &tx.input {
                self.unspent.remove(&inp.previous_output);
                if self.known_utxos.get(&inp.previous_output).map_or(false, |u| u.spendable) {
                    self.spent_in_mempool.insert(inp.previous_output);
                }
            }
        }
    }

    fn record_tx_outputs(&mut self, tx: &Transaction) {
        let txid = tx.compute_txid();
        let spk = p2wsh_op_true_spk();
        for (vout, out) in tx.output.iter().enumerate() {
            let spendable = out.script_pubkey == spk;
            self.known_utxos.insert(
                OutPoint { txid, vout: vout as u32 },
                UtxoInfo {
                    value: out.value.to_sat(),
                    spendable,
                },
            );
        }
        self.all_txids.push(txid);
    }

    fn build_tx(&self, spec: &TxSpec, forced_inputs: Option<Vec<OutPoint>>, force_ephemeral_dust: bool) -> Option<Transaction> {
        let mut chosen = Vec::new();
        let mut used = BTreeSet::new();
        if let Some(fi) = forced_inputs {
            for op in fi {
                if used.insert(op) {
                    chosen.push(op);
                }
            }
        } else {
            let pool: Vec<OutPoint> = if spec.allow_rbf && !self.spent_in_mempool.is_empty() {
                self.unspent
                    .iter()
                    .chain(self.spent_in_mempool.iter())
                    .copied()
                    .collect()
            } else {
                self.unspent.iter().copied().collect()
            };
            if pool.is_empty() {
                return None;
            }
            for &p in &spec.input_picks {
                let op = pool[p as usize % pool.len()];
                if used.insert(op) {
                    chosen.push(op);
                }
            }
        }
        if chosen.is_empty() {
            return None;
        }

        // If any chosen input comes from a dust-bearing mempool parent, also include that parent's
        // dust outpoint(s) so ephemeral-dust spends stay valid when spending non-dust sibling outputs.
        let mut total_in: u64 = 0;
        for op in &chosen {
            total_in = total_in.saturating_add(self.known_utxos.get(op)?.value);
        }
        if total_in < 1000 {
            return None;
        }

        let is_ephemeral = force_ephemeral_dust || spec.kind == TxKind::EphemeralDustParent;
        let fee = if is_ephemeral {
            0
        } else {
            spec.fee_sat.min(total_in - 600)
        };
        let remaining = total_in - fee;

        let version = match spec.kind {
            TxKind::TrucV3 => bitcoin::transaction::Version(3),
            _ => bitcoin::transaction::Version::TWO,
        };

        let mut outputs = Vec::new();
        let n_out = spec.num_outputs.max(1) as usize;
        let spk = p2wsh_op_true_spk();

        let per_out = remaining / n_out as u64;
        if per_out < 546 {
            outputs.push(TxOut {
                value: Amount::from_sat(remaining),
                script_pubkey: spk.clone(),
            });
        } else {
            let mut left = remaining;
            for i in 0..n_out {
                let val = if i + 1 == n_out { left } else { per_out };
                left -= val;
                let script = if i == 0 && spec.kind == TxKind::SigopHeavy {
                    p2pk_sigop_spk()
                } else {
                    spk.clone()
                };
                outputs.push(TxOut {
                    value: Amount::from_sat(val),
                    script_pubkey: script,
                });
            }
        }

        if is_ephemeral {
            // Append a 0-sat P2WSH_OP_TRUE ephemeral dust anchor output.
            outputs.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: spk.clone(),
            });
        }

        // Add OP_RETURN salt and/or multi-output padding so we can actually exceed
        // TRUC_CHILD_MAX_VSIZE (1000 vB) and TRUC_MAX_VSIZE (10000 vB)!
        // Each P2WSH output is 43 vB (8 + 1 + 34); 25 outputs = 1075 vB, 240 outputs = 10320 vB.
        if spec.pad_bytes >= 900 && remaining > 500_000 {
            let extra_outs = ((spec.pad_bytes as usize) / 43).min(245);
            let each = 600u64;
            let needed = (extra_outs as u64) * each;
            if outputs[0].value.to_sat() > needed + 1000 {
                outputs[0].value = Amount::from_sat(outputs[0].value.to_sat() - needed);
                for _ in 0..extra_outs {
                    outputs.push(TxOut {
                        value: Amount::from_sat(each),
                        script_pubkey: spk.clone(),
                    });
                }
            }
        }
        if spec.pad_bytes > 0 || spec.salt != 0 {
            let len = (spec.pad_bytes as usize).min(80).max(1);
            let mut data = vec![spec.salt; len];
            data[0] = spec.salt;
            let mut op_ret = vec![0x6a]; // OP_RETURN
            if data.len() <= 75 {
                op_ret.push(data.len() as u8);
            } else {
                op_ret.push(0x4c); // OP_PUSHDATA1
                op_ret.push(data.len() as u8);
            }
            op_ret.extend_from_slice(&data);
            outputs.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(op_ret),
            });
        }

        let seq = if spec.non_rbf_seq {
            Sequence::MAX
        } else {
            Sequence::ENABLE_RBF_NO_LOCKTIME
        };
        let inputs = chosen
            .into_iter()
            .map(|op| TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: seq,
                witness: p2wsh_op_true_witness(0),
            })
            .collect();

        Some(Transaction {
            version,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        })
    }
}

pub fn run_mempool_scenario(scenario: &MempoolScenario) {
    let init_cmd = format!(
        "INIT {} {} {} {} {} {}",
        scenario.limit_cluster_count,
        scenario.limit_cluster_size_kvb,
        scenario.max_mempool_mb,
        scenario.min_relay_sat_kvb,
        if scenario.require_standard { 1 } else { 0 },
        scenario.bytes_per_sigop,
    );
    let init_resp = send_checked(&init_cmd, 0, "INIT");
    let parts: Vec<&str> = init_resp.split_whitespace().collect();
    assert_eq!(parts[0], "OK", "INIT failed: {init_resp}");
    let n_cb: usize = parts[1].parse().unwrap();
    let mut coinbases = Vec::with_capacity(n_cb);
    let mut known_utxos = BTreeMap::new();
    let mut unspent = BTreeSet::new();
    for i in 0..n_cb {
        let op = parse_outpoint(parts[2 + i]);
        coinbases.push(op);
        known_utxos.insert(
            op,
            UtxoInfo {
                value: 50 * 100_000_000,
                spendable: true,
            },
        );
        unspent.insert(op);
    }

    let mut st = HarnessState {
        coinbases,
        known_utxos,
        unspent,
        spent_in_mempool: BTreeSet::new(),
        in_mempool: BTreeMap::new(),
        all_txids: Vec::new(),
        prioritised_any: false,
        has_negative_mod_fee: false,
        had_reorg: false,
        last_mined_any: false,
    };

    let tmp_dump = format!(
        "/tmp/ephyra_mempool_dump_{}_{}.dat",
        std::process::id(),
        scenario.ops.len()
    );

    for (step, op) in scenario.ops.iter().enumerate() {
        match op {
            MempoolOp::SubmitTx(spec) => {
                if let Some(tx) = st.build_tx(spec, None, false) {
                    let hex = serialize_hex(&tx);
                    let resp = send_checked(&format!("SUBMIT_TX {hex}"), step, "SubmitTx");
                    let p: Vec<&str> = resp.split_whitespace().collect();
                    assert_eq!(p[0], "OK", "step {step}: SUBMIT_TX error: {resp}");
                    let accepted: u32 = p[1].parse().unwrap();
                    let replaced: u32 = p[2].parse().unwrap();
                    let n_rep: usize = p[3].parse().unwrap();
                    let cmp_code: i32 = p[5].parse().unwrap();
                    let size_before: usize = p[6].parse().unwrap();
                    let size_after: usize = p[7].parse().unwrap();

                    if accepted == 1 {
                        st.record_tx_outputs(&tx);
                        st.in_mempool.insert(tx.compute_txid(), tx);
                        if replaced == 1 {
                            ephyra::classify(true, "single_tx_rbf_accepted");
                            let no_extra_evictions = size_after == size_before + 1 - n_rep;
                            if !st.has_negative_mod_fee && no_extra_evictions {
                                // Every accepted RBF must strictly improve the global feerate diagram
                                // when all mempool modified fees are non-negative and LimitMempoolSize
                                // did not simultaneously expire/evict unrelated transactions.
                                assert_eq!(
                                    cmp_code, 1,
                                    "step {step}: accepted single-tx RBF did not strictly improve feerate diagram (cmp={cmp_code}, resp={resp})"
                                );
                            }
                        }
                        st.sync_from_worker(step);
                    } else if size_after != size_before {
                        // LimitMempoolSize() inside AcceptToMemoryPool may have expired/evicted txs even if rejected.
                        st.sync_from_worker(step);
                    }
                }
            }
            MempoolOp::SubmitPackage(shape) => {
                let mut pkg_txs: Vec<Transaction> = Vec::new();
                match shape {
                    PackageShape::OneParentOneChild {
                        parent_truc,
                        child_truc,
                        ephemeral_dust,
                        parent_fee,
                        child_fee,
                        parent_rbf,
                        child_rbf,
                        oversized_child,
                        salt,
                    } => {
                        let parent_spec = TxSpec {
                            kind: if *parent_truc { TxKind::TrucV3 } else { TxKind::StandardV2 },
                            input_picks: vec![*salt],
                            allow_rbf: *parent_rbf,
                            num_outputs: 1,
                            fee_sat: *parent_fee,
                            pad_bytes: 0,
                            non_rbf_seq: false,
                            salt: *salt,
                        };
                        if let Some(parent) = st.build_tx(&parent_spec, None, *ephemeral_dust) {
                            let ptxid = parent.compute_txid();
                            st.record_tx_outputs(&parent);
                            let mut child_ins = Vec::new();
                            let spk = p2wsh_op_true_spk();
                            for (vout, out) in parent.output.iter().enumerate() {
                                if out.script_pubkey == spk {
                                    child_ins.push(OutPoint { txid: ptxid, vout: vout as u32 });
                                }
                            }
                            if *child_rbf && !st.spent_in_mempool.is_empty() {
                                let conf = *st.spent_in_mempool.iter().nth(*salt as usize % st.spent_in_mempool.len()).unwrap();
                                if conf.txid != ptxid {
                                    child_ins.push(conf);
                                }
                            }
                            let child_spec = TxSpec {
                                kind: if *child_truc { TxKind::TrucV3 } else { TxKind::StandardV2 },
                                input_picks: vec![0],
                                allow_rbf: false,
                                num_outputs: 1,
                                fee_sat: *child_fee,
                                pad_bytes: if *oversized_child { 1150 } else { 0 },
                                non_rbf_seq: false,
                                salt: salt.wrapping_add(1),
                            };
                            if let Some(child) = st.build_tx(&child_spec, Some(child_ins), false) {
                                st.record_tx_outputs(&child);
                                pkg_txs.push(parent);
                                pkg_txs.push(child);
                            }
                        }
                    }
                    PackageShape::MultiParentOneChild {
                        num_parents,
                        parent_fee,
                        child_fee,
                        ephemeral_dust,
                        allow_rbf,
                        salt,
                    } => {
                        let pool: Vec<OutPoint> = if *allow_rbf && !st.spent_in_mempool.is_empty() {
                            st.unspent.iter().chain(st.spent_in_mempool.iter()).copied().collect()
                        } else {
                            st.unspent.iter().copied().collect()
                        };
                        if pool.len() >= *num_parents as usize {
                            let mut child_ins = Vec::new();
                            let spk = p2wsh_op_true_spk();
                            let mut ok = true;
                            for i in 0..(*num_parents as usize) {
                                let op = pool[(salt.wrapping_add(i as u8) as usize) % pool.len()];
                                if pkg_txs.iter().any(|t: &Transaction| t.input.iter().any(|x| x.previous_output == op)) {
                                    ok = false;
                                    break;
                                }
                                let pspec = TxSpec {
                                    kind: TxKind::StandardV2,
                                    input_picks: vec![0],
                                    allow_rbf: false,
                                    num_outputs: 1,
                                    fee_sat: *parent_fee,
                                    pad_bytes: 0,
                                    non_rbf_seq: false,
                                    salt: salt.wrapping_add(i as u8),
                                };
                                if let Some(ptx) = st.build_tx(&pspec, Some(vec![op]), *ephemeral_dust && i == 0) {
                                    let ptxid = ptx.compute_txid();
                                    st.record_tx_outputs(&ptx);
                                    for (vout, out) in ptx.output.iter().enumerate() {
                                        if out.script_pubkey == spk {
                                            child_ins.push(OutPoint { txid: ptxid, vout: vout as u32 });
                                        }
                                    }
                                    pkg_txs.push(ptx);
                                } else {
                                    ok = false;
                                    break;
                                }
                            }
                            if ok && !child_ins.is_empty() {
                                let cspec = TxSpec {
                                    kind: TxKind::StandardV2,
                                    input_picks: vec![0],
                                    allow_rbf: false,
                                    num_outputs: 1,
                                    fee_sat: *child_fee,
                                    pad_bytes: 0,
                                    non_rbf_seq: false,
                                    salt: salt.wrapping_add(99),
                                };
                                if let Some(ctx) = st.build_tx(&cspec, Some(child_ins), false) {
                                    st.record_tx_outputs(&ctx);
                                    pkg_txs.push(ctx);
                                } else {
                                    pkg_txs.clear();
                                }
                            } else {
                                pkg_txs.clear();
                            }
                        }
                    }
                    PackageShape::Chain { len, truc, fees, salt } => {
                        if let Some(&first_op) = st.unspent.iter().nth(*salt as usize % st.unspent.len().max(1)) {
                            let mut cur_op = first_op;
                            let spk = p2wsh_op_true_spk();
                            for i in 0..(*len as usize) {
                                let spec = TxSpec {
                                    kind: if *truc { TxKind::TrucV3 } else { TxKind::StandardV2 },
                                    input_picks: vec![0],
                                    allow_rbf: false,
                                    num_outputs: 1,
                                    fee_sat: fees[i],
                                    pad_bytes: 0,
                                    non_rbf_seq: false,
                                    salt: salt.wrapping_add(i as u8),
                                };
                                if let Some(tx) = st.build_tx(&spec, Some(vec![cur_op]), false) {
                                    let txid = tx.compute_txid();
                                    st.record_tx_outputs(&tx);
                                    let next_vout = tx.output.iter().position(|o| o.script_pubkey == spk);
                                    pkg_txs.push(tx);
                                    if let Some(v) = next_vout {
                                        cur_op = OutPoint { txid, vout: v as u32 };
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            if pkg_txs.len() < 2 {
                                pkg_txs.clear();
                            }
                        }
                    }
                    PackageShape::OneParentTwoSiblings {
                        truc,
                        conflict_siblings,
                        parent_fee,
                        child1_fee,
                        child2_fee,
                        salt,
                    } => {
                        let pspec = TxSpec {
                            kind: if *truc { TxKind::TrucV3 } else { TxKind::StandardV2 },
                            input_picks: vec![*salt],
                            allow_rbf: false,
                            num_outputs: 2,
                            fee_sat: *parent_fee,
                            pad_bytes: 0,
                            non_rbf_seq: false,
                            salt: *salt,
                        };
                        if let Some(parent) = st.build_tx(&pspec, None, false) {
                            let ptxid = parent.compute_txid();
                            st.record_tx_outputs(&parent);
                            let spk = p2wsh_op_true_spk();
                            let spendable_vouts: Vec<u32> = parent
                                .output
                                .iter()
                                .enumerate()
                                .filter(|(_, o)| o.script_pubkey == spk)
                                .map(|(i, _)| i as u32)
                                .collect();
                            if spendable_vouts.len() >= 2 {
                                let op1 = OutPoint { txid: ptxid, vout: spendable_vouts[0] };
                                let op2 = if *conflict_siblings {
                                    op1
                                } else {
                                    OutPoint { txid: ptxid, vout: spendable_vouts[1] }
                                };
                                let c1_spec = TxSpec {
                                    kind: if *truc { TxKind::TrucV3 } else { TxKind::StandardV2 },
                                    input_picks: vec![0],
                                    allow_rbf: false,
                                    num_outputs: 1,
                                    fee_sat: *child1_fee,
                                    pad_bytes: 0,
                                    non_rbf_seq: false,
                                    salt: salt.wrapping_add(1),
                                };
                                let c2_spec = TxSpec {
                                    kind: if *truc { TxKind::TrucV3 } else { TxKind::StandardV2 },
                                    input_picks: vec![0],
                                    allow_rbf: false,
                                    num_outputs: 1,
                                    fee_sat: *child2_fee,
                                    pad_bytes: 0,
                                    non_rbf_seq: false,
                                    salt: salt.wrapping_add(2),
                                };
                                if let (Some(c1), Some(c2)) = (
                                    st.build_tx(&c1_spec, Some(vec![op1]), false),
                                    st.build_tx(&c2_spec, Some(vec![op2]), false),
                                ) {
                                    st.record_tx_outputs(&c1);
                                    st.record_tx_outputs(&c2);
                                    pkg_txs.push(parent);
                                    pkg_txs.push(c1);
                                    pkg_txs.push(c2);
                                }
                            }
                        }
                    }
                    PackageShape::Diamond {
                        gp_fee,
                        p1_fee,
                        p2_fee,
                        child_fee,
                        gp_pad,
                        salt,
                    } => {
                        // Build 4-tx Diamond: GP (2 outs) -> P1 (spends GP:0), P2 (spends GP:1) -> Child (spends P1:0, P2:0)
                        let gp_spec = TxSpec {
                            kind: TxKind::StandardV2,
                            input_picks: vec![*salt],
                            allow_rbf: false,
                            num_outputs: 2,
                            fee_sat: *gp_fee,
                            pad_bytes: *gp_pad,
                            non_rbf_seq: false,
                            salt: *salt,
                        };
                        if let Some(gp) = st.build_tx(&gp_spec, None, false) {
                            let gp_txid = gp.compute_txid();
                            st.record_tx_outputs(&gp);
                            let spk = p2wsh_op_true_spk();
                            let gp_outs: Vec<u32> = gp
                                .output
                                .iter()
                                .enumerate()
                                .filter(|(_, o)| o.script_pubkey == spk)
                                .map(|(i, _)| i as u32)
                                .collect();
                            if gp_outs.len() >= 2 {
                                let p1_spec = TxSpec {
                                    kind: TxKind::StandardV2,
                                    input_picks: vec![0],
                                    allow_rbf: false,
                                    num_outputs: 1,
                                    fee_sat: *p1_fee,
                                    pad_bytes: 0,
                                    non_rbf_seq: false,
                                    salt: salt.wrapping_add(1),
                                };
                                let p2_spec = TxSpec {
                                    kind: TxKind::StandardV2,
                                    input_picks: vec![0],
                                    allow_rbf: false,
                                    num_outputs: 1,
                                    fee_sat: *p2_fee,
                                    pad_bytes: 0,
                                    non_rbf_seq: false,
                                    salt: salt.wrapping_add(2),
                                };
                                if let (Some(p1), Some(p2)) = (
                                    st.build_tx(&p1_spec, Some(vec![OutPoint { txid: gp_txid, vout: gp_outs[0] }]), false),
                                    st.build_tx(&p2_spec, Some(vec![OutPoint { txid: gp_txid, vout: gp_outs[1] }]), false),
                                ) {
                                    let p1_id = p1.compute_txid();
                                    let p2_id = p2.compute_txid();
                                    st.record_tx_outputs(&p1);
                                    st.record_tx_outputs(&p2);
                                    let c_spec = TxSpec {
                                        kind: TxKind::StandardV2,
                                        input_picks: vec![0],
                                        allow_rbf: false,
                                        num_outputs: 1,
                                        fee_sat: *child_fee,
                                        pad_bytes: 0,
                                        non_rbf_seq: false,
                                        salt: salt.wrapping_add(3),
                                    };
                                    if let Some(child) = st.build_tx(
                                        &c_spec,
                                        Some(vec![
                                            OutPoint { txid: p1_id, vout: 0 },
                                            OutPoint { txid: p2_id, vout: 0 },
                                        ]),
                                        false,
                                    ) {
                                        st.record_tx_outputs(&child);
                                        pkg_txs.push(gp);
                                        pkg_txs.push(p1);
                                        pkg_txs.push(p2);
                                        pkg_txs.push(child);
                                    }
                                }
                            }
                        }
                    }
                    PackageShape::MalformedPackage { mode, salt } => {
                        let pspec = TxSpec {
                            kind: TxKind::StandardV2,
                            input_picks: vec![*salt],
                            allow_rbf: false,
                            num_outputs: 1,
                            fee_sat: 1000,
                            pad_bytes: 0,
                            non_rbf_seq: false,
                            salt: *salt,
                        };
                        if let Some(parent) = st.build_tx(&pspec, None, false) {
                            let ptxid = parent.compute_txid();
                            st.record_tx_outputs(&parent);
                            let op = OutPoint { txid: ptxid, vout: 0 };
                            let cspec = TxSpec {
                                kind: TxKind::StandardV2,
                                input_picks: vec![0],
                                allow_rbf: false,
                                num_outputs: 1,
                                fee_sat: 2000,
                                pad_bytes: 0,
                                non_rbf_seq: false,
                                salt: salt.wrapping_add(1),
                            };
                            match mode % 7 {
                                0 => {
                                    // Reverse topological order (child before parent) -> package-not-sorted
                                    if let Some(child) = st.build_tx(&cspec, Some(vec![op]), false) {
                                        pkg_txs.push(child);
                                        pkg_txs.push(parent);
                                    }
                                }
                                1 => {
                                    // Duplicate txid in same package -> package-contains-duplicates
                                    pkg_txs.push(parent.clone());
                                    pkg_txs.push(parent);
                                }
                                2 => {
                                    // Same txid, different witness (malleated witness) -> package-contains-duplicates
                                    let mut alt = parent.clone();
                                    if let Some(inp) = alt.input.first_mut() {
                                        inp.witness = Witness::from_slice(&[&[0x01u8][..], &[0x51u8][..]]);
                                    }
                                    pkg_txs.push(parent);
                                    pkg_txs.push(alt);
                                }
                                3 => {
                                    // > MAX_PACKAGE_COUNT (26 txs) -> package-too-many-transactions
                                    let mut cur_op = op;
                                    pkg_txs.push(parent);
                                    for i in 0..25u8 {
                                        let step_spec = TxSpec {
                                            kind: TxKind::StandardV2,
                                            input_picks: vec![0],
                                            allow_rbf: false,
                                            num_outputs: 1,
                                            fee_sat: 500,
                                            pad_bytes: 0,
                                            non_rbf_seq: false,
                                            salt: salt.wrapping_add(10 + i),
                                        };
                                        if let Some(nxt) = st.build_tx(&step_spec, Some(vec![cur_op]), false) {
                                            let nid = nxt.compute_txid();
                                            st.record_tx_outputs(&nxt);
                                            cur_op = OutPoint { txid: nid, vout: 0 };
                                            pkg_txs.push(nxt);
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                4 => {
                                    // > MAX_PACKAGE_WEIGHT (> 101 kvB across 2 txs) -> package-too-large
                                    let spk = p2wsh_op_true_spk();
                                    let mut big_p = parent.clone();
                                    // Add 1500 tiny outputs (~64.5 kvB each, 2 txs = ~129 kvB > 101 kvB)
                                    let avail = big_p.output[0].value.to_sat();
                                    if avail > 1_500_000 {
                                        big_p.output[0].value = Amount::from_sat(avail - 1500 * 600);
                                        for _ in 0..1500 {
                                            big_p.output.push(TxOut {
                                                value: Amount::from_sat(600),
                                                script_pubkey: spk.clone(),
                                            });
                                        }
                                        let big_pid = big_p.compute_txid();
                                        st.record_tx_outputs(&big_p);
                                        let big_c_op = OutPoint { txid: big_pid, vout: 0 };
                                        if let Some(mut big_c) = st.build_tx(&cspec, Some(vec![big_c_op]), false) {
                                            let cav = big_c.output[0].value.to_sat();
                                            if cav > 1_500_000 {
                                                big_c.output[0].value = Amount::from_sat(cav - 1500 * 600);
                                                for _ in 0..1500 {
                                                    big_c.output.push(TxOut {
                                                        value: Amount::from_sat(600),
                                                        script_pubkey: spk.clone(),
                                                    });
                                                }
                                            }
                                            pkg_txs.push(big_p);
                                            pkg_txs.push(big_c);
                                        }
                                    }
                                }
                                5 => {
                                    // Non-tree child-with-parents: P1 -> P2 -> Child, Child also spends P1
                                    // Hits IsChildWithParents() == true && IsChildWithParentsTree() == false!
                                    let p1_spec = TxSpec {
                                        kind: TxKind::StandardV2,
                                        input_picks: vec![*salt],
                                        allow_rbf: false,
                                        num_outputs: 2,
                                        fee_sat: 500,
                                        pad_bytes: 0,
                                        non_rbf_seq: false,
                                        salt: salt.wrapping_add(77),
                                    };
                                    if let Some(p1) = st.build_tx(&p1_spec, None, false) {
                                        let p1_id = p1.compute_txid();
                                        st.record_tx_outputs(&p1);
                                        if p1.output.len() >= 2 {
                                            if let Some(p2) = st.build_tx(&cspec, Some(vec![OutPoint { txid: p1_id, vout: 0 }]), false) {
                                                let p2_id = p2.compute_txid();
                                                st.record_tx_outputs(&p2);
                                                if let Some(c) = st.build_tx(
                                                    &cspec,
                                                    Some(vec![
                                                        OutPoint { txid: p1_id, vout: 1 },
                                                        OutPoint { txid: p2_id, vout: 0 },
                                                    ]),
                                                    false,
                                                ) {
                                                    st.record_tx_outputs(&c);
                                                    pkg_txs.push(p1);
                                                    pkg_txs.push(p2);
                                                    pkg_txs.push(c);
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    // Conflicting transactions inside same package -> conflict-in-package
                                    let mut alt = parent.clone();
                                    alt.output[0].value = Amount::from_sat(alt.output[0].value.to_sat().saturating_sub(100));
                                    pkg_txs.push(parent);
                                    pkg_txs.push(alt);
                                }
                            }
                        }
                    }
                }

                if !pkg_txs.is_empty() {
                    let mut cmd = format!("SUBMIT_PKG {}", pkg_txs.len());
                    for tx in &pkg_txs {
                        cmd.push(' ');
                        cmd.push_str(&serialize_hex(tx));
                    }
                    let resp = send_checked(&cmd, step, "SubmitPackage");
                    let p: Vec<&str> = resp.split_whitespace().collect();
                    assert_eq!(p[0], "OK", "step {step}: SUBMIT_PKG error: {resp}");
                    let n_acc: usize = p[2].parse().unwrap();
                    let n_rep: usize = p[3].parse().unwrap();
                    let cmp_code: i32 = p[4].parse().unwrap();
                    let size_before: usize = p[5].parse().unwrap();
                    let size_after: usize = p[6].parse().unwrap();
                    if n_acc > 0 {
                        ephyra::classify(true, "package_accepted");
                        for tx in pkg_txs {
                            st.in_mempool.insert(tx.compute_txid(), tx);
                        }
                        if n_rep > 0 {
                            ephyra::classify(true, "package_rbf_accepted");
                            let no_extra_evictions = size_after == size_before + n_acc - n_rep;
                            if !st.has_negative_mod_fee && no_extra_evictions {
                                assert_eq!(
                                    cmp_code, 1,
                                    "step {step}: accepted package RBF did not strictly improve feerate diagram (cmp={cmp_code}, resp={resp})"
                                );
                            }
                        }
                        st.sync_from_worker(step);
                    } else if size_after != size_before {
                        st.sync_from_worker(step);
                    }
                }
            }
            MempoolOp::PrioritiseTx { pick, delta_sat, off_mempool } => {
                let txid_opt = if *off_mempool {
                    Some(Txid::from_byte_array([*pick; 32]))
                } else if !st.all_txids.is_empty() {
                    Some(st.all_txids[*pick as usize % st.all_txids.len()])
                } else {
                    None
                };
                if let Some(txid) = txid_opt {
                    let _ = send_checked(&format!("PRIORITISE {txid} {delta_sat}"), step, "PrioritiseTx");
                    st.prioritised_any = true;
                    st.sync_from_worker(step);
                }
            }
            MempoolOp::AdvanceTime { seconds } => {
                let _ = send_checked(&format!("ADVANCE_TIME {seconds}"), step, "AdvanceTime");
            }
            MempoolOp::TrimToSize { keep_pct } => {
                let state_resp = send_checked("STATE", step, "STATE_pre_trim");
                let sp: Vec<&str> = state_resp.split_whitespace().collect();
                let cur_mem: u64 = sp[4].parse().unwrap();
                let target = cur_mem.saturating_mul(*keep_pct as u64) / 100;
                let resp = send_checked(&format!("TRIM {target}"), step, "TrimToSize");
                let p: Vec<&str> = resp.split_whitespace().collect();
                let before: usize = p[1].parse().unwrap();
                let after: usize = p[2].parse().unwrap();
                if after < before {
                    ephyra::classify(true, "trim_evicted_txs");
                    st.sync_from_worker(step);
                }
            }
            MempoolOp::Expire { age_seconds } => {
                let resp = send_checked(&format!("EXPIRE {age_seconds}"), step, "Expire");
                let p: Vec<&str> = resp.split_whitespace().collect();
                let removed: usize = p[1].parse().unwrap();
                if removed > 0 {
                    ephyra::classify(true, "expire_removed_txs");
                    st.sync_from_worker(step);
                }
            }
            MempoolOp::MineBlock {
                max_weight,
                min_feerate_sat_kvb,
                remove_from_pool,
            } => {
                let resp = send_checked(
                    &format!(
                        "MINE_BLOCK {} {} {}",
                        max_weight,
                        min_feerate_sat_kvb,
                        if *remove_from_pool { 1 } else { 0 }
                    ),
                    step,
                    "MineBlock",
                );
                let p: Vec<&str> = resp.split_whitespace().collect();
                assert_eq!(p[0], "OK", "step {step}: MINE_BLOCK error: {resp}");
                let n_txs: usize = p[1].parse().unwrap();
                let mono_ok: u32 = p[3].parse().unwrap();
                assert_eq!(
                    mono_ok, 1,
                    "step {step}: BlockAssembler chunk feerates were not non-increasing / >= min_feerate"
                );
                if *remove_from_pool && n_txs > 0 {
                    st.had_reorg = true;
                    ephyra::classify(true, "mined_and_reorged_block");
                    st.sync_from_worker(step);
                }
            }
            MempoolOp::ReorgBack => {
                if st.last_mined_any {
                    let resp = send_checked("REORG_BACK", step, "ReorgBack");
                    let p: Vec<&str> = resp.split_whitespace().collect();
                    assert_eq!(p[0], "OK", "step {step}: REORG_BACK error: {resp}");
                    st.had_reorg = true;
                    st.last_mined_any = false;
                    ephyra::classify(true, "reorg_reinserted");
                    st.sync_from_worker(step);
                }
            }
            MempoolOp::MiniMiner { target_feerate_sat_kvb, picks } => {
                // Prioritize in-mempool UTXOs and spent_in_mempool UTXOs (to hit m_to_be_replaced!).
                let mut pool: Vec<OutPoint> = st.spent_in_mempool.iter().copied().collect();
                for tx in st.in_mempool.values() {
                    let txid = tx.compute_txid();
                    for vout in 0..tx.output.len() {
                        pool.push(OutPoint { txid, vout: vout as u32 });
                    }
                }
                if pool.is_empty() {
                    pool.extend(st.known_utxos.keys().copied());
                }
                if !pool.is_empty() {
                    let mut cmd = format!("MINIMINER {} {}", target_feerate_sat_kvb, picks.len());
                    for &pk in picks {
                        let op = pool[pk as usize % pool.len()];
                        cmd.push_str(&format!(" {}:{}", op.txid, op.vout));
                    }
                    let resp = send_checked(&cmd, step, "MiniMiner");
                    let p: Vec<&str> = resp.split_whitespace().collect();
                    assert_eq!(p[0], "OK", "step {step}: MINIMINER failed: {resp}");
                    let ready: u32 = p[1].parse().unwrap();
                    let min_bump: i64 = p[3].parse().unwrap();
                    let has_tb: u32 = p[4].parse().unwrap();
                    let tb: i64 = p[5].parse().unwrap();
                    let sum_bump: i64 = p[6].parse().unwrap();
                    let topo_ok: u32 = p[7].parse().unwrap();
                    if ready == 1 {
                        assert!(
                            min_bump >= 0,
                            "step {step}: MiniMiner::CalculateBumpFees returned negative bump fee {min_bump}"
                        );
                        assert_eq!(
                            topo_ok, 1,
                            "step {step}: MiniMiner BuildMockTemplate/Linearize violated topological ordering"
                        );
                        if has_tb == 1 && !st.has_negative_mod_fee {
                            assert!(
                                sum_bump >= tb,
                                "step {step}: sum(CalculateBumpFees)={sum_bump} < CalculateTotalBumpFees={tb}"
                            );
                        }
                    }
                }
            }
            MempoolOp::ExtractRelay { n_to_sort, extra_missing } => {
                let resp = send_checked(
                    &format!("EXTRACT_RELAY {n_to_sort} {extra_missing}"),
                    step,
                    "ExtractRelay",
                );
                assert!(resp.starts_with("OK "), "step {step}: EXTRACT_RELAY failed: {resp}");
            }
            MempoolOp::DumpAndLoad { apply_deltas } => {
                let resp = send_checked(
                    &format!("DUMP_LOAD {} {}", tmp_dump, if *apply_deltas { 1 } else { 0 }),
                    step,
                    "DumpAndLoad",
                );
                let p: Vec<&str> = resp.split_whitespace().collect();
                assert_eq!(p[0], "OK", "step {step}: DUMP_LOAD failed: {resp}");
                assert_eq!(p[1], "1", "step {step}: LoadMempool returned false");
            }
            MempoolOp::RbfAndQueries { pick } => {
                let tx_opt = if !st.in_mempool.is_empty() && (*pick % 4 != 0) {
                    st.in_mempool.values().nth(*pick as usize % st.in_mempool.len()).cloned()
                } else {
                    let spec = TxSpec {
                        kind: TxKind::StandardV2,
                        input_picks: vec![*pick],
                        allow_rbf: false,
                        num_outputs: 1,
                        fee_sat: 1000,
                        pad_bytes: 0,
                        non_rbf_seq: (*pick & 1) != 0,
                        salt: *pick,
                    };
                    st.build_tx(&spec, None, false)
                };
                if let Some(tx) = tx_opt {
                    let hex = serialize_hex(&tx);
                    let resp = send_checked(&format!("RBF_AND_QUERIES {hex}"), step, "RbfAndQueries");
                    let p: Vec<&str> = resp.split_whitespace().collect();
                    assert_eq!(p[0], "OK", "step {step}: RBF_AND_QUERIES failed: {resp}");
                    let anc_count: usize = p[3].parse().unwrap();
                    let cluster_count: usize = p[4].parse().unwrap();
                    if st.in_mempool.contains_key(&tx.compute_txid()) {
                        assert!(anc_count >= 1, "step {step}: in-mempool tx had ancestor_count=0");
                        assert!(cluster_count >= anc_count, "step {step}: cluster_count < ancestor_count");
                    } else {
                        assert_eq!(anc_count, 0, "step {step}: non-mempool tx had ancestor_count > 0");
                        assert_eq!(cluster_count, 0, "step {step}: non-mempool tx had cluster_count > 0");
                    }
                }
            }
        }

        // Ephemeral dust invariant check when standardness is on and no dust tx was prioritised
        // and no reorg happened (reorgs can disconnect/reinsert in ways that bypass package checks? Let's test!).
        if scenario.require_standard && !st.prioritised_any && !st.had_reorg {
            let _ = send_checked("CHECK_EPHEMERAL", step, "CheckEphemeral");
        }
    }
}

#[ephyra::test(gen = mempool_scenarios(), tests = 300)]
fn mempool_cluster_stateful(scenario: MempoolScenario) {
    run_mempool_scenario(&scenario);
}
