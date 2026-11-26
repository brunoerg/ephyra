//! Coverage gap report binary for Tier 1 (`src/txgraph.cpp` & `src/cluster_linearize.h`).
//! Run with: `cargo run --release --features cpp-cov --bin cov_report -- [N_CASES]`

#[cfg(feature = "cpp-cov")]
fn main() {
    use std::collections::BTreeSet;
    use ephyra::{Gen, Source};
    use ephyra_bitcoin_cluster_mempool::cov::inner as cov;
    use ephyra_bitcoin_cluster_mempool::ffi::{linearize, postlinearize};
    use ephyra_bitcoin_cluster_mempool::gen_txgraph::{full_depgraphs, txgraph_scenarios};

    let n_cases: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    let all_counters = cov::target_counters();
    let funcs = cov::target_functions();
    println!(
        "Target C++ coverage map: {} functions, {} counters",
        funcs.len(),
        all_counters.len()
    );

    let tg_gen = txgraph_scenarios();
    let dg_gen = full_depgraphs();

    let mut reached = BTreeSet::new();
    for i in 0..n_cases {
        let mut src = Source::new(i as u64 + 1, (i as f64 + 1.0).log2() as usize);
        let sc = tg_gen.generate(&mut src);
        let hits = cov::covered(&all_counters, || {
            // Run via thin subset (same executor as txgraph_model)
            run_quick_txgraph(&sc);
        });
        reached.extend(hits);

        let dg = dg_gen.generate(&mut src);
        let hits2 = cov::covered(&all_counters, || {
            let init: Vec<u32> = (0..dg.n() as u32).collect();
            let post = postlinearize(&dg.fees, &dg.sizes, &dg.parent_masks, &init);
            let lin1 = linearize(
                &dg.fees,
                &dg.sizes,
                &dg.parent_masks,
                dg.max_cost,
                dg.rng_seed,
                Some(post.order_slice()),
                true,
            );
            let rev: Vec<u32> = (0..dg.n() as u32).rev().collect();
            let lin2 = linearize(
                &dg.fees,
                &dg.sizes,
                &dg.parent_masks,
                dg.max_cost,
                dg.rng_seed ^ 1,
                Some(&rev),
                false,
            );
            let _ = ephyra_bitcoin_cluster_mempool::ffi::compare_chunks(
                lin1.chunks_slice(),
                lin2.chunks_slice(),
            );
        });
        reached.extend(hits2);
    }

    println!(
        "After {n_cases} cases: {}/{} counters reached ({:.1}%)",
        reached.len(),
        all_counters.len(),
        100.0 * reached.len() as f64 / all_counters.len().max(1) as f64
    );

    // Rank functions by unreached counter count (top 30 gaps).
    let mut gaps: Vec<(usize, usize, String)> = funcs
        .iter()
        .map(|(name, range)| {
            let total = range.len();
            let hit = range.clone().filter(|c| reached.contains(c)).count();
            (total - hit, total, name.clone())
        })
        .filter(|(missed, _, _)| *missed > 0)
        .collect();
    gaps.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.2.cmp(&b.2)));

    println!("\nTop 30 unreached C++ functions (missed / total):");
    for (missed, total, name) in gaps.iter().take(30) {
        println!("  {:4} / {:4}  {}", missed, total, name);
    }
}

#[cfg(feature = "cpp-cov")]
fn run_quick_txgraph(scenario: &ephyra_bitcoin_cluster_mempool::gen_txgraph::TxGraphScenario) {
    use std::collections::BTreeSet;
    use ephyra_bitcoin_cluster_mempool::ffi::{Level, RealTxGraph, MAX_SLOTS};
    use ephyra_bitcoin_cluster_mempool::gen_txgraph::TgOp;
    use ephyra_bitcoin_cluster_mempool::txgraph_model::TxGraphModel;

    let mut real = RealTxGraph::new(
        scenario.max_cluster_count,
        scenario.max_cluster_size,
        scenario.acceptable_cost,
    );
    let mut model = TxGraphModel::new(scenario.max_cluster_count, scenario.max_cluster_size);
    let mut builders = Vec::new();
    for op in &scenario.ops {
        let can_mut = builders.is_empty() || model.staging.is_some();
        match op {
            TgOp::AddTx { fee, size } if can_mut => {
                if let Some(slot) = model.alloc_slot() {
                    let txid = model.add_tx(slot, *fee, *size);
                    real.add_tx(slot, *fee, *size, txid);
                }
            }
            TgOp::AddDep { parent_pick, child_pick } if can_mut => {
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
            TgOp::RemoveClosure { pick, desc } if can_mut => {
                let slots: Vec<u32> = model.top().txs.keys().copied().collect();
                if !slots.is_empty() {
                    let t = slots[*pick as usize % slots.len()];
                    let cl: Vec<u32> = if *desc {
                        model.top().descendants[&t].iter().copied().collect()
                    } else {
                        model.top().ancestors[&t].iter().copied().collect()
                    };
                    for s in cl {
                        model.top_mut().remove_tx(s);
                        real.remove_tx(s);
                    }
                }
            }
            TgOp::DestroyRef { pick, only_removed, desc } => {
                if *only_removed {
                    let dead: Vec<u32> = (0..MAX_SLOTS as u32)
                        .filter(|&s| {
                            model.live_refs[s as usize]
                                && !model.main.has(s)
                                && !model.staging.as_ref().map_or(false, |st| st.has(s))
                        })
                        .collect();
                    if !dead.is_empty() {
                        let s = dead[*pick as usize % dead.len()];
                        model.destroy_ref(s);
                        real.destroy_ref(s);
                    }
                } else if builders.is_empty() {
                    let live: Vec<u32> = (0..MAX_SLOTS as u32).filter(|&s| model.live_refs[s as usize]).collect();
                    if !live.is_empty() {
                        let start = live[*pick as usize % live.len()];
                        let mut td = BTreeSet::from([start]);
                        loop {
                            let b = td.len();
                            for s in td.iter().copied().collect::<Vec<_>>() {
                                if model.main.has(s) {
                                    td.extend(if *desc { &model.main.descendants[&s] } else { &model.main.ancestors[&s] });
                                }
                                if let Some(st) = &model.staging {
                                    if st.has(s) {
                                        td.extend(if *desc { &st.descendants[&s] } else { &st.ancestors[&s] });
                                    }
                                }
                            }
                            if td.len() == b { break; }
                        }
                        for s in td {
                            model.destroy_ref(s);
                            real.destroy_ref(s);
                        }
                    }
                }
            }
            TgOp::MoveRef { pick } if builders.is_empty() => {
                let live: Vec<u32> = (0..MAX_SLOTS as u32).filter(|&s| model.live_refs[s as usize]).collect();
                if let (Some(&from), Some(to)) = (live.get(*pick as usize % live.len().max(1)), model.alloc_slot()) {
                    model.move_ref(from, to);
                    real.move_ref(from, to);
                }
            }
            TgOp::SetFee { pick, fee } if builders.is_empty() => {
                let live: Vec<u32> = (0..MAX_SLOTS as u32).filter(|&s| model.live_refs[s as usize]).collect();
                if !live.is_empty() {
                    let s = live[*pick as usize % live.len()];
                    model.set_fee(s, *fee);
                    real.set_fee(s, *fee);
                }
            }
            TgOp::StartStaging if model.staging.is_none() => { model.start_staging(); real.start_staging(); }
            TgOp::CommitStaging if model.staging.is_some() && builders.is_empty() => { model.commit_staging(); real.commit_staging(); }
            TgOp::AbortStaging if model.staging.is_some() => { model.abort_staging(); real.abort_staging(); }
            TgOp::DoWork { max_cost } if builders.is_empty() => { let _ = real.do_work(*max_cost); }
            TgOp::Trim if can_mut => {
                for r in real.trim() { model.top_mut().remove_tx(r); }
            }
            TgOp::OpenBuilder if !model.is_oversized(Level::Main) && builders.len() < 4 => {
                if let Some(id) = real.bb_open() { builders.push(id); }
            }
            TgOp::BuilderStep { which, skip } if !builders.is_empty() => {
                let id = builders[*which as usize % builders.len()];
                if real.bb_current(id).is_some() {
                    if *skip { real.bb_skip(id); } else { real.bb_include(id); }
                }
            }
            TgOp::CloseBuilder { which } if !builders.is_empty() => {
                let id = builders.swap_remove(*which as usize % builders.len());
                real.bb_close(id);
            }
            TgOp::CheckQueries { pick_a, pick_b, level_top } => {
                let lvl = if *level_top { Level::Top } else { Level::Main };
                let _ = real.is_oversized(Level::Main);
                let _ = real.is_oversized(Level::Top);
                let _ = real.get_tx_count(Level::Main);
                let _ = real.get_tx_count(Level::Top);
                let mut live: Vec<u32> = (0..MAX_SLOTS as u32).filter(|&s| model.live_refs[s as usize]).collect();
                live.push(MAX_SLOTS as u32);
                if !live.is_empty() {
                    let a = live[*pick_a as usize % live.len()];
                    let b = live[*pick_b as usize % live.len()];
                    let _ = real.exists(a, lvl);
                    let _ = real.get_individual_feerate(a);
                    if !model.is_oversized(lvl) {
                        let _ = real.get_ancestors(a, lvl);
                        let _ = real.get_descendants(a, lvl);
                        let _ = real.get_cluster(a, lvl);
                        let _ = real.get_ancestors_union(&[a, b], lvl);
                        let _ = real.get_descendants_union(&[a, b], lvl);
                        let _ = real.count_distinct_clusters(&[a, b], lvl);
                    }
                    if !model.is_oversized(Level::Main) {
                        let _ = real.get_main_chunk_feerate(a);
                        let _ = real.get_worst_main_chunk();
                        let _ = real.get_main_memory_usage();
                        if model.main.has(a) && model.main.has(b) {
                            let _ = real.compare_main_order(a, b);
                        }
                    }
                    if model.staging.is_some() && !model.is_oversized(Level::Main) && !model.is_oversized(Level::Top) {
                        let (dm, ds) = real.get_main_staging_diagrams();
                        let _ = ephyra_bitcoin_cluster_mempool::ffi::compare_chunks(&ds, &dm);
                    }
                }
            }
            _ => {}
        }
        real.sanity_check();
    }
    for id in builders {
        real.bb_close(id);
    }
}

#[cfg(not(feature = "cpp-cov"))]
fn main() {
    eprintln!("Rebuild with --features cpp-cov");
    std::process::exit(1);
}
