//! Property 5: Focused Ephyra property tests for `node::MiniMiner` (`src/node/mini_miner.cpp`),
//! testing `CalculateBumpFees`, `CalculateTotalBumpFees`, and `BuildMockTemplate` on
//! valid-by-construction transaction DAGs (including diamonds, multi-parent CPFP, and chains)
//! with `target_feerate` sampled directly across the cluster's feerate spectrum!

use std::cell::RefCell;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use ephyra::{Gen, GenExt, Source};
use ephyra_bitcoin_cluster_mempool::worker::MempoolWorker;
use std::ops::ControlFlow;

thread_local! {
    static MM_WORKER: RefCell<MempoolWorker> = RefCell::new(MempoolWorker::default_san());
}

fn p2wsh_op_true_spk() -> ScriptBuf {
    let witness_script = ScriptBuf::from_bytes(vec![0x51]);
    ScriptBuf::new_p2wsh(&witness_script.wscript_hash())
}

fn parse_outpoint(s: &str) -> OutPoint {
    let (h, n) = s.split_once(':').unwrap();
    OutPoint {
        txid: h.parse::<Txid>().unwrap(),
        vout: n.parse().unwrap(),
    }
}

/// A small valid DAG (2..=8 txs) submitted into a real Bitcoin Core `CTxMemPool`,
/// plus a target feerate and subset of tx outputs to query in `MiniMiner`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiniMinerCase {
    pub fees: Vec<u64>,
    /// Extra 43-vB outputs for each tx to vary tx sizes cleanly.
    pub extra_outs: Vec<u8>,
    /// `parent_masks[i]` has bit `p` (< i) set iff tx `i` spends an output of tx `p`.
    pub parent_masks: Vec<u16>,
    /// Target feerate in sat/kvB.
    pub target_feerate_sat_kvb: u64,
    /// Bitmask of transactions whose output we request bump fees for.
    pub query_mask: u16,
}

#[ephyra::generator]
pub fn valid_mm_case(c: &MiniMinerCase) -> bool {
    let n = c.fees.len();
    if n < 2 || n > 8 || c.extra_outs.len() != n || c.parent_masks.len() != n {
        return false;
    }
    if c.query_mask == 0 || (c.query_mask & !((1u16 << n) - 1)) != 0 {
        return false;
    }
    for i in 0..n {
        if c.fees[i] > 50_000_000 || c.extra_outs[i] > 40 {
            return false;
        }
        let allowed = if i == 0 { 0u16 } else { (1u16 << i) - 1 };
        if (c.parent_masks[i] & !allowed) != 0 {
            return false;
        }
    }
    c.target_feerate_sat_kvb <= 500_000
}

fn gen_mm_case(g: &mut Source) -> MiniMinerCase {
    let shape = g.int(0u8..=3);
    let (n, parent_masks) = match shape {
        0 => {
            // Classic 4-tx Diamond: 0 -> {1, 2} -> 3
            (4usize, vec![0u16, 0b0001, 0b0001, 0b0110])
        }
        1 => {
            // 5-tx double-diamond / multi-parent
            (5usize, vec![0u16, 0b0001, 0b0001, 0b0110, 0b1010])
        }
        _ => {
            let n = g.int(2usize..=7);
            let mut masks = vec![0u16; n];
            for i in 1..n {
                for p in 0..i {
                    if g.bool_with(0.45) {
                        masks[i] |= 1u16 << p;
                    }
                }
            }
            (n, masks)
        }
    };

    let mut fees = Vec::with_capacity(n);
    let mut extra_outs = Vec::with_capacity(n);
    for i in 0..n {
        let f = match g.int(0u8..=4) {
            0 => g.int(200u64..=2_000),
            1 => g.int(2_000u64..=25_000),
            2 => g.int(25_000u64..=200_000),
            _ => g.int(500u64..=10_000),
        };
        fees.push(f);
        // Allow large roots (up to 40 extra outputs ≈ 1800 vB) to create high-weight low-feerate ancestors
        extra_outs.push(if i == 0 && g.bool_with(0.5) {
            g.int(15u8..=40)
        } else {
            match g.int(0u8..=3) {
                0 => g.int(10u8..=35),
                _ => g.int(0u8..=5),
            }
        });
    }

    // Estimate each tx's approximate vsize (~110 + 43*extra_outs + 41*parents) and sample
    // target_feerate_sat_kvb either near a cluster/tx feerate or across the broad spectrum.
    let total_fee: u64 = fees.iter().sum();
    let total_vsize_est: u64 = (0..n)
        .map(|i| 110u64 + 43 * (extra_outs[i] as u64) + 41 * (parent_masks[i].count_ones() as u64))
        .sum::<u64>()
        .max(1);
    let cluster_fr = (total_fee * 1000 / total_vsize_est).clamp(1_000, 490_000);

    let target_feerate_sat_kvb = match g.int(0u8..=4) {
        0 => {
            // Sample near the cluster's average feerate.
            let lo = (cluster_fr * 7 / 10).max(500);
            let hi = (cluster_fr * 11 / 10).min(495_000).max(lo + 1);
            g.int(lo..=hi)
        }
        1 => g.int(1_000u64..=15_000),
        2 => g.int(15_000u64..=80_000),
        3 => g.int(80_000u64..=250_000),
        _ => g.int(500u64..=50_000),
    };

    let query_mask = g.int(1u16..=((1u16 << n) - 1));

    MiniMinerCase {
        fees,
        extra_outs,
        parent_masks,
        target_feerate_sat_kvb,
        query_mask,
    }
}

fn shrink_mm_case(c: &MiniMinerCase, visit: &mut dyn FnMut(MiniMinerCase) -> ControlFlow<()>) -> ControlFlow<()> {
    let n = c.fees.len();
    if n > 2 {
        let mut s = c.clone();
        s.fees.pop();
        s.extra_outs.pop();
        s.parent_masks.pop();
        s.query_mask &= (1u16 << (n - 1)) - 1;
        if s.query_mask == 0 {
            s.query_mask = 1u16 << (n - 2);
        }
        visit(s)?;
    }
    for i in 0..n {
        if c.extra_outs[i] > 0 {
            let mut s = c.clone();
            s.extra_outs[i] /= 2;
            visit(s)?;
        }
        if c.fees[i] > 100 {
            let mut s = c.clone();
            s.fees[i] /= 2;
            visit(s)?;
        }
    }
    if c.query_mask.count_ones() > 1 {
        for i in 0..n {
            if (c.query_mask & (1u16 << i)) != 0 {
                let mut s = c.clone();
                s.query_mask ^= 1u16 << i;
                visit(s)?;
            }
        }
    }
    ControlFlow::Continue(())
}

fn mutate_mm_case(c: &MiniMinerCase, g: &mut Source) -> MiniMinerCase {
    let mut s = c.clone();
    let n = s.fees.len();
    match g.int(0u8..=3) {
        0 => {
            let i = g.index(n);
            s.fees[i] = g.int(200u64..=200_000);
        }
        1 => {
            let i = g.index(n);
            s.extra_outs[i] = g.int(0u8..=35);
        }
        2 => {
            s.target_feerate_sat_kvb = g.int(1_000u64..=200_000);
        }
        _ => {
            s.query_mask = g.int(1u16..=((1u16 << n) - 1));
        }
    }
    s
}

pub fn mm_case_metrics(c: &MiniMinerCase, size: usize) -> Vec<(&'static str, f64)> {
    let n = c.fees.len() as f64;
    let edges: f64 = c.parent_masks.iter().map(|m| m.count_ones() as f64).sum();
    let queried = c.query_mask.count_ones() as f64;
    vec![
        ("txs", n),
        ("edges", edges),
        ("queried", queried),
        ("target_kvb", c.target_feerate_sat_kvb as f64),
        ("txs_per_size", n / (size + 1) as f64),
    ]
}

#[ephyra::generator(valid_mm_case, metrics = mm_case_metrics)]
pub fn mm_cases() -> impl Gen<Value = MiniMinerCase> {
    gen_mm_case.with_shrink(shrink_mm_case).with_mutate(mutate_mm_case)
}

#[ephyra::test(gen = mm_cases(), tests = 500)]
fn miniminer_bump_fees_and_linearize_invariants(c: MiniMinerCase) {
    MM_WORKER.with(|w| {
        let mut worker = w.borrow_mut();
        let init = worker.send("INIT 64 101 300 0 1 20").unwrap();
        let parts: Vec<&str> = init.split_whitespace().collect();
        assert_eq!(parts[0], "OK");
        let coinbases: Vec<OutPoint> = (0..16).map(|i| parse_outpoint(parts[2 + i])).collect();

        let n = c.fees.len();
        let spk = p2wsh_op_true_spk();
        let mut child_count = vec![0usize; n];
        for i in 0..n {
            for p in 0..i {
                if ((c.parent_masks[i] >> p) & 1) != 0 {
                    child_count[p] += 1;
                }
            }
        }

        let mut next_cb = 0usize;
        let mut tx_outputs: Vec<Vec<(OutPoint, u64)>> = vec![Vec::new(); n];
        let mut next_out_idx = vec![0usize; n];
        let mut query_ops: Vec<OutPoint> = Vec::new();

        for i in 0..n {
            let mut ins = Vec::new();
            let mut total_in = 0u64;
            for p in 0..i {
                if ((c.parent_masks[i] >> p) & 1) != 0 {
                    let idx = next_out_idx[p];
                    next_out_idx[p] += 1;
                    let (op, val) = tx_outputs[p][idx];
                    ins.push(op);
                    total_in += val;
                }
            }
            if ins.is_empty() {
                let op = coinbases[next_cb];
                next_cb += 1;
                ins.push(op);
                total_in += 50 * 100_000_000;
            }
            let fee = c.fees[i].min(total_in - 100_000);
            let n_outs = (child_count[i] + 1 + c.extra_outs[i] as usize).max(1);
            let remaining = total_in - fee;
            let each = remaining / n_outs as u64;
            let mut outs = Vec::with_capacity(n_outs);
            let mut left = remaining;
            for o in 0..n_outs {
                let val = if o + 1 == n_outs { left } else { each };
                left -= val;
                outs.push(TxOut {
                    value: Amount::from_sat(val),
                    script_pubkey: spk.clone(),
                });
            }
            let tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: ins
                    .into_iter()
                    .map(|op| TxIn {
                        previous_output: op,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: Witness::from_slice(&[&[0x51u8][..]]),
                    })
                    .collect(),
                output: outs,
            };
            let txid = tx.compute_txid();
            for (vout, o) in tx.output.iter().enumerate() {
                tx_outputs[i].push((OutPoint { txid, vout: vout as u32 }, o.value.to_sat()));
            }
            let resp = worker.send(&format!("SUBMIT_TX {}", serialize_hex(&tx))).unwrap();
            assert!(resp.starts_with("OK 1 "), "tx {i} rejected: {resp}");
        }

        for i in 0..n {
            if ((c.query_mask >> i) & 1) != 0 {
                let (op, _) = *tx_outputs[i].last().unwrap();
                query_ops.push(op);
            }
        }

        let mut cmd = format!("MINIMINER {} {}", c.target_feerate_sat_kvb, query_ops.len());
        for op in &query_ops {
            cmd.push_str(&format!(" {}:{}", op.txid, op.vout));
        }
        let resp = worker.send(&cmd).unwrap();
        let p: Vec<&str> = resp.split_whitespace().collect();
        assert_eq!(p[0], "OK", "MINIMINER failed: {resp}");
        let ready: u32 = p[1].parse().unwrap();
        let min_bump: i64 = p[3].parse().unwrap();
        let has_tb: u32 = p[4].parse().unwrap();
        let tb: i64 = p[5].parse().unwrap();
        let sum_bump: i64 = p[6].parse().unwrap();
        let topo_ok: u32 = p[7].parse().unwrap();

        if ready == 1 {
            assert!(
                min_bump >= 0,
                "CalculateBumpFees returned negative bump fee: {min_bump}"
            );
            assert_eq!(
                topo_ok, 1,
                "MiniMiner BuildMockTemplate/Linearize violated topological ordering (case={c:?})"
            );
            if has_tb == 1 {
                assert!(
                    sum_bump >= tb,
                    "sum(CalculateBumpFees)={sum_bump} < CalculateTotalBumpFees={tb}"
                );
            }
        }
    });
}
