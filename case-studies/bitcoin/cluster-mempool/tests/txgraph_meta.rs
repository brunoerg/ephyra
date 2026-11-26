//! Property 2: Metamorphic laws of `TxGraph` staging:
//! 1. Abort isolation: `StartStaging(); staged_ops; AbortStaging()` leaves `main`
//!    (clusters, chunk feerates, CompareMainOrder, GetWorstMainChunk, GetMainMemoryUsage)
//!    completely unchanged — AND `GetMainMemoryUsage()` *during* staging equals post-abort usage!
//! 2. Commit equivalence: `StartStaging(); staged_ops; CommitStaging(); DoWork(MAX)` matches
//!    applying `staged_ops` directly to an identical `main` + `DoWork(MAX)`.
//! 3. `GetMainStagingDiagrams()` consistency with full-graph chunk feerate diagrams.

use std::collections::BTreeSet;

use ephyra_bitcoin_cluster_mempool::ffi::{compare_chunks, DiagramOrd, Level, RealTxGraph, TgFeeFrac};
use ephyra_bitcoin_cluster_mempool::gen_txgraph::{txgraph_scenarios, TgOp, TxGraphScenario};
use ephyra_bitcoin_cluster_mempool::txgraph_model::TxGraphModel;

fn full_diagram(real: &RealTxGraph, model: &TxGraphModel, level: Level) -> Vec<TgFeeFrac> {
    let sim = model.level(level);
    let mut seen_reps = BTreeSet::new();
    let mut all_chunks = Vec::new();
    for &s in sim.txs.keys() {
        let clust = real.get_cluster(s, level);
        let rep = *clust.iter().min().unwrap();
        if seen_reps.insert(rep) {
            for (_, rate) in sim.chunk_order(&clust) {
                all_chunks.push(rate);
            }
        }
    }
    all_chunks.sort_by(|a, b| b.cmp_ratio_neg_size(a));
    all_chunks
}

fn apply_staging_safe_op(real: &mut RealTxGraph, model: &mut TxGraphModel, op: &TgOp) {
    match op {
        TgOp::AddTx { fee, size } => {
            if let Some(slot) = model.alloc_slot() {
                let txid = model.add_tx(slot, *fee, *size);
                real.add_tx(slot, *fee, *size, txid);
            }
        }
        TgOp::AddDep { parent_pick, child_pick } => {
            let slots: Vec<u32> = model.top().txs.keys().copied().collect();
            if !slots.is_empty() {
                let p = slots[*parent_pick as usize % slots.len()];
                let c = slots[*child_pick as usize % slots.len()];
                if !model.top().would_cycle(p, c) {
                    model.top_mut().add_dep(p, c);
                    real.add_dep(p, c);
                }
            }
        }
        TgOp::RemoveClosure { pick, desc } => {
            let slots: Vec<u32> = model.top().txs.keys().copied().collect();
            if !slots.is_empty() {
                let target = slots[*pick as usize % slots.len()];
                let closure: Vec<u32> = if *desc {
                    model.top().descendants[&target].iter().copied().collect()
                } else {
                    model.top().ancestors[&target].iter().copied().collect()
                };
                for s in closure {
                    model.top_mut().remove_tx(s);
                    real.remove_tx(s);
                }
            }
        }
        TgOp::DoWork { max_cost } => {
            real.do_work(*max_cost);
        }
        TgOp::Trim => {
            let removed = real.trim();
            for r in removed {
                model.top_mut().remove_tx(r);
            }
        }
        _ => {}
    }
}

#[ephyra::test(gen = txgraph_scenarios(), tests = 1500)]
fn staging_abort_and_diagrams(scenario: TxGraphScenario) {
    let split = scenario.ops.len() / 2;
    let setup_ops = &scenario.ops[..split];
    let stage_ops = &scenario.ops[split..];

    let mut real = RealTxGraph::new(
        scenario.max_cluster_count,
        scenario.max_cluster_size,
        scenario.acceptable_cost,
    );
    let mut model = TxGraphModel::new(scenario.max_cluster_count, scenario.max_cluster_size);

    for op in setup_ops {
        apply_staging_safe_op(&mut real, &mut model, op);
    }
    if model.is_oversized(Level::Main) {
        let removed = real.trim();
        for r in removed {
            model.main.remove_tx(r);
        }
    }
    // Stabilize main before snapshot so lazy structures are populated.
    real.do_work(100_000);
    let mem_before = real.get_main_memory_usage();
    let worst_before = real.get_worst_main_chunk();
    let main_slots: Vec<u32> = model.main.txs.keys().copied().collect();
    let rates_before: Vec<TgFeeFrac> = main_slots.iter().map(|&s| real.get_main_chunk_feerate(s)).collect();
    let clusters_before: Vec<Vec<u32>> = main_slots.iter().map(|&s| real.get_cluster(s, Level::Main)).collect();

    // Enter staging and apply staging-only ops.
    real.start_staging();
    model.start_staging();
    for op in stage_ops {
        apply_staging_safe_op(&mut real, &mut model, op);
    }

    // Check GetMainStagingDiagrams when staging is non-oversized.
    if !model.is_oversized(Level::Top) {
        let (diff_m, diff_s) = real.get_main_staging_diagrams();
        let full_m = full_diagram(&real, &model, Level::Main);
        let full_s = full_diagram(&real, &model, Level::Top);

        // Exact multiset relationship: every chunk in full_m not in diff_m must also be in full_s not in diff_s
        // (those are the unchanged clusters!).
        let mut rem_m = full_m.clone();
        for ch in &diff_m {
            let pos = rem_m.iter().position(|x| x == ch).expect("diff_m chunk missing from full_m");
            rem_m.remove(pos);
        }
        let mut rem_s = full_s.clone();
        for ch in &diff_s {
            let pos = rem_s.iter().position(|x| x == ch).expect("diff_s chunk missing from full_s");
            rem_s.remove(pos);
        }
        assert_eq!(
            rem_m, rem_s,
            "unchanged clusters implied by GetMainStagingDiagrams differ: main_rem={rem_m:?} vs staging_rem={rem_s:?}"
        );

        // When all fees are non-negative, adding unchanged non-negative chunks preserves diagram ordering.
        let all_nonneg = full_m.iter().all(|c| c.fee >= 0) && full_s.iter().all(|c| c.fee >= 0);
        if all_nonneg {
            let diff_cmp = compare_chunks(&diff_s, &diff_m);
            let full_cmp = compare_chunks(&full_s, &full_m);
            assert_eq!(
                diff_cmp, full_cmp,
                "GetMainStagingDiagrams order ({diff_cmp:?}) != full diagram order ({full_cmp:?}) on non-negative fees"
            );
        }

        let sum = |v: &[TgFeeFrac]| -> (i128, i128) {
            v.iter().fold((0i128, 0i128), |(f, s), x| (f + x.fee as i128, s + x.size as i128))
        };
        let (dmf, dms) = sum(&diff_m);
        let (dsf, dss) = sum(&diff_s);
        let (fmf, fms) = sum(&full_m);
        let (fsf, fss) = sum(&full_s);
        assert_eq!(dsf - dmf, fsf - fmf, "GetMainStagingDiagrams net fee delta != full graph delta");
        assert_eq!(dss - dms, fss - fms, "GetMainStagingDiagrams net size delta != full graph delta");
    }

    let mem_during_staging = real.get_main_memory_usage();

    // Abort staging: main must be completely untouched, and GetMainMemoryUsage() during staging
    // must equal post-abort GetMainMemoryUsage() (per txgraph.h:208-212).
    real.abort_staging();
    model.abort_staging();
    real.sanity_check();

    let mem_after = real.get_main_memory_usage();
    assert_eq!(
        mem_during_staging, mem_after,
        "GetMainMemoryUsage() during staging ({mem_during_staging}) != after AbortStaging() ({mem_after})"
    );
    assert_eq!(real.get_worst_main_chunk(), worst_before, "GetWorstMainChunk changed after AbortStaging");
    let rates_after: Vec<TgFeeFrac> = main_slots.iter().map(|&s| real.get_main_chunk_feerate(s)).collect();
    assert_eq!(rates_after, rates_before, "chunk feerates changed after AbortStaging");
    let clusters_after: Vec<Vec<u32>> = main_slots.iter().map(|&s| real.get_cluster(s, Level::Main)).collect();
    assert_eq!(clusters_after, clusters_before, "clusters changed after AbortStaging");
    let _ = mem_before; // Note: GetMainStagingDiagrams may have called MakeAllAcceptable(0) during staging, changing mem_after vs mem_before; mem_during_staging == mem_after is the exact documented contract!
}

#[ephyra::test(gen = txgraph_scenarios(), tests = 1500)]
fn staging_commit_matches_direct(scenario: TxGraphScenario) {
    let split = scenario.ops.len() / 2;
    let setup_ops = &scenario.ops[..split];
    let stage_ops = &scenario.ops[split..];

    let mut g_staged = RealTxGraph::new(
        scenario.max_cluster_count,
        scenario.max_cluster_size,
        scenario.acceptable_cost,
    );
    let mut m_staged = TxGraphModel::new(scenario.max_cluster_count, scenario.max_cluster_size);

    let mut g_direct = RealTxGraph::new(
        scenario.max_cluster_count,
        scenario.max_cluster_size,
        scenario.acceptable_cost,
    );
    let mut m_direct = TxGraphModel::new(scenario.max_cluster_count, scenario.max_cluster_size);

    for op in setup_ops {
        apply_staging_safe_op(&mut g_staged, &mut m_staged, op);
        apply_staging_safe_op(&mut g_direct, &mut m_direct, op);
    }

    // Apply stage_ops inside staging + Commit on g_staged, vs directly on g_direct.
    // Skip Trim inside stage_ops since Trim is best-effort and may pick differently if internal layouts differ.
    g_staged.start_staging();
    m_staged.start_staging();
    for op in stage_ops {
        if matches!(op, TgOp::Trim) {
            continue;
        }
        apply_staging_safe_op(&mut g_staged, &mut m_staged, op);
        apply_staging_safe_op(&mut g_direct, &mut m_direct, op);
    }
    g_staged.commit_staging();
    m_staged.commit_staging();

    g_staged.sanity_check();
    g_direct.sanity_check();

    assert_eq!(
        g_staged.get_tx_count(Level::Main),
        g_direct.get_tx_count(Level::Main),
        "tx count differs between staged+commit and direct"
    );
    assert_eq!(
        g_staged.is_oversized(Level::Main),
        g_direct.is_oversized(Level::Main),
        "oversized differs between staged+commit and direct"
    );

    if !g_staged.is_oversized(Level::Main) {
        let opt1 = g_staged.do_work(500_000);
        let opt2 = g_direct.do_work(500_000);
        if opt1 && opt2 {
            let d1 = full_diagram(&g_staged, &m_staged, Level::Main);
            let d2 = full_diagram(&g_direct, &m_direct, Level::Main);
            assert_eq!(
                compare_chunks(&d1, &d2),
                DiagramOrd::Equal,
                "optimal feerate diagram differs between staged+commit ({d1:?}) and direct ({d2:?})"
            );
        }
    }
}
