//! Property 1: Full stateful simulation of Bitcoin Core's `TxGraph` against our
//! independent pure-Rust `TxGraphModel`.

use std::collections::BTreeSet;

use ephyra_bitcoin_cluster_mempool::ffi::{Level, RealTxGraph, TgFeeFrac, MAX_SLOTS};
use ephyra_bitcoin_cluster_mempool::gen_txgraph::{txgraph_scenarios, TgOp, TxGraphScenario};
use ephyra_bitcoin_cluster_mempool::txgraph_model::TxGraphModel;

fn pick_from_vec<T: Copy>(v: &[T], pick: u8) -> Option<T> {
    if v.is_empty() {
        None
    } else {
        Some(v[pick as usize % v.len()])
    }
}

fn check_state_invariants(real: &RealTxGraph, model: &TxGraphModel, step: usize) {
    real.sanity_check();
    assert_eq!(
        real.have_staging(),
        model.staging.is_some(),
        "step {step}: have_staging mismatch"
    );
    assert_eq!(
        real.get_tx_count(Level::Main),
        model.main.txs.len() as u32,
        "step {step}: main tx count mismatch"
    );
    assert_eq!(
        real.get_tx_count(Level::Top),
        model.top().txs.len() as u32,
        "step {step}: top tx count mismatch"
    );
    assert_eq!(
        real.is_oversized(Level::Main),
        model.is_oversized(Level::Main),
        "step {step}: main is_oversized mismatch"
    );
    assert_eq!(
        real.is_oversized(Level::Top),
        model.is_oversized(Level::Top),
        "step {step}: top is_oversized mismatch"
    );
}

fn check_full_main_order_and_builders(real: &mut RealTxGraph, model: &TxGraphModel, has_open_builders: bool, step: usize) {
    if model.is_oversized(Level::Main) {
        return;
    }

    // 1. Verify CompareMainOrder is a strict total order on all main transactions
    //    and respects topology + chunk feerates.
    let main_slots: Vec<u32> = model.main.txs.keys().copied().collect();
    let mut sorted = main_slots.clone();
    sorted.sort_by(|&a, &b| real.compare_main_order(a, b));

    // Check pairwise antisymmetry & strict order on a sample (or all if <= 32).
    let check_n = sorted.len().min(32);
    for i in 0..check_n {
        assert_eq!(
            real.compare_main_order(sorted[i], sorted[i]),
            std::cmp::Ordering::Equal,
            "step {step}: CompareMainOrder not reflexive"
        );
        for j in (i + 1)..check_n {
            assert_eq!(
                real.compare_main_order(sorted[i], sorted[j]),
                std::cmp::Ordering::Less,
                "step {step}: CompareMainOrder not transitive/strict"
            );
            assert_eq!(
                real.compare_main_order(sorted[j], sorted[i]),
                std::cmp::Ordering::Greater,
                "step {step}: CompareMainOrder not antisymmetric"
            );
        }
    }

    // Topology check on sorted order: every parent appears before its child.
    let mut pos = std::collections::BTreeMap::new();
    for (idx, &s) in sorted.iter().enumerate() {
        pos.insert(s, idx);
    }
    for (&s, ancs) in &model.main.ancestors {
        for &a in ancs {
            if a != s {
                assert!(
                    pos[&a] < pos[&s],
                    "step {step}: CompareMainOrder placed child {s} before ancestor {a}"
                );
            }
        }
    }

    // Non-increasing chunk feerates along sorted order.
    let mut prev_chunk_rate: Option<TgFeeFrac> = None;
    for &s in &sorted {
        let cr = real.get_main_chunk_feerate(s);
        assert!(cr.size > 0, "step {step}: empty main chunk feerate for live tx {s}");
        if let Some(prev) = prev_chunk_rate {
            assert!(
                prev.cmp_ratio(&cr).is_ge(),
                "step {step}: CompareMainOrder chunk feerates increased: {prev:?} -> {cr:?}"
            );
        }
        prev_chunk_rate = Some(cr);
    }

    // 2. Drain a fresh BlockBuilder (if slot available) and compare against GetWorstMainChunk & CompareMainOrder.
    if !has_open_builders {
        if let Some(bb) = real.bb_open() {
            let mut emitted: Vec<u32> = Vec::new();
            let mut last_chunk: Option<(Vec<u32>, TgFeeFrac)> = None;
            let mut prev_rate: Option<TgFeeFrac> = None;
            while let Some((chunk, rate)) = real.bb_current(bb) {
                assert!(!chunk.is_empty(), "step {step}: BlockBuilder returned empty chunk");
                let mut sum_fee = 0i64;
                let mut sum_size = 0i32;
                let set: BTreeSet<u32> = chunk.iter().copied().collect();
                assert_eq!(set.len(), chunk.len(), "step {step}: duplicate tx in BlockBuilder chunk");
                assert!(
                    model.main.is_connected_subset(&set),
                    "step {step}: BlockBuilder chunk is disconnected: {chunk:?}"
                );
                for &s in &chunk {
                    let (f, sz, _) = model.main.txs[&s];
                    sum_fee += f;
                    sum_size += sz;
                    assert_eq!(
                        real.get_main_chunk_feerate(s),
                        rate,
                        "step {step}: GetMainChunkFeerate disagrees with BlockBuilder"
                    );
                }
                assert_eq!(rate, TgFeeFrac::new(sum_fee, sum_size), "step {step}: BlockBuilder feerate sum mismatch");
                if let Some(prev) = prev_rate {
                    assert!(
                        prev.cmp_ratio(&rate).is_ge(),
                        "step {step}: BlockBuilder chunk feerates increased: {prev:?} -> {rate:?}"
                    );
                }
                prev_rate = Some(rate);
                emitted.extend_from_slice(&chunk);
                last_chunk = Some((chunk, rate));
                real.bb_include(bb);
            }
            real.bb_close(bb);

            assert_eq!(
                emitted.len(),
                main_slots.len(),
                "step {step}: BlockBuilder emitted {} of {} txs",
                emitted.len(),
                main_slots.len()
            );
            assert!(
                model.main.is_topological(&emitted),
                "step {step}: BlockBuilder output is not topological"
            );

            // Check GetWorstMainChunk matches the final chunk of BlockBuilder (reversed).
            let (worst_slots, worst_rate) = real.get_worst_main_chunk();
            match last_chunk {
                None => {
                    assert!(worst_slots.is_empty() && worst_rate.is_empty());
                }
                Some((last_slots, last_rate)) => {
                    assert_eq!(worst_rate, last_rate, "step {step}: GetWorstMainChunk feerate != last BlockBuilder chunk");
                    let wset: BTreeSet<u32> = worst_slots.iter().copied().collect();
                    let lset: BTreeSet<u32> = last_slots.iter().copied().collect();
                    assert_eq!(wset, lset, "step {step}: GetWorstMainChunk txs != last BlockBuilder chunk");
                    // Reverse-topological check: every element is preceded by all its descendants in the chunk.
                    let mut seen = BTreeSet::new();
                    for &s in &worst_slots {
                        seen.insert(s);
                        for &d in &model.main.descendants[&s] {
                            if wset.contains(&d) {
                                assert!(
                                    seen.contains(&d),
                                    "step {step}: GetWorstMainChunk not reverse-topological: {s} before descendant {d}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn run_scenario(scenario: &TxGraphScenario) {
    let mut real = RealTxGraph::new(
        scenario.max_cluster_count,
        scenario.max_cluster_size,
        scenario.acceptable_cost,
    );
    let mut model = TxGraphModel::new(scenario.max_cluster_count, scenario.max_cluster_size);
    let mut open_builders: Vec<(i32, BTreeSet<u32>, Option<TgFeeFrac>)> = Vec::new();

    for (step, op) in scenario.ops.iter().enumerate() {
        let can_mutate_top = open_builders.is_empty() || model.staging.is_some();

        match op {
            TgOp::AddTx { fee, size } if can_mutate_top => {
                if let Some(slot) = model.alloc_slot() {
                    let txid = model.add_tx(slot, *fee, *size);
                    assert!(real.add_tx(slot, *fee, *size, txid));
                }
            }
            TgOp::AddDep { parent_pick, child_pick } if can_mutate_top => {
                // Include live slots, removed-but-live Refs, and empty sentinel (MAX_SLOTS)
                // to exercise TxGraphImpl::AddDependency's no-op branches on empty/removed Refs.
                let mut pool: Vec<u32> = (0..MAX_SLOTS as u32)
                    .filter(|&s| model.live_refs[s as usize])
                    .collect();
                if *parent_pick == 255 || *child_pick == 255 {
                    pool.push(MAX_SLOTS as u32);
                }
                if let (Some(p), Some(c)) = (pick_from_vec(&pool, *parent_pick), pick_from_vec(&pool, *child_pick)) {
                    if !model.top().would_cycle(p, c) && p != c {
                        model.top_mut().add_dep(p, c);
                        real.add_dep(p, c);
                    }
                }
            }
            TgOp::RemoveClosure { pick, desc } if can_mutate_top => {
                // Occasionally call RemoveTransaction on an empty or already-removed Ref (must be a no-op).
                if *pick == 255 {
                    real.remove_tx(MAX_SLOTS as u32);
                } else {
                    let slots: Vec<u32> = model.top().txs.keys().copied().collect();
                    if let Some(target) = pick_from_vec(&slots, *pick) {
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
            }
            TgOp::DestroyRef { pick, only_removed, desc } => {
                if *only_removed {
                    // Destroy a Ref that is no longer in main or staging.
                    let dead: Vec<u32> = (0..MAX_SLOTS as u32)
                        .filter(|&s| {
                            model.live_refs[s as usize]
                                && !model.main.has(s)
                                && !model.staging.as_ref().map_or(false, |st| st.has(s))
                        })
                        .collect();
                    if let Some(s) = pick_from_vec(&dead, *pick) {
                        model.destroy_ref(s);
                        real.destroy_ref(s);
                    }
                } else if open_builders.is_empty() {
                    let live: Vec<u32> = (0..MAX_SLOTS as u32)
                        .filter(|&s| model.live_refs[s as usize])
                        .collect();
                    if let Some(start) = pick_from_vec(&live, *pick) {
                        // Close under ancestors or descendants across BOTH main and staging.
                        let mut to_destroy = BTreeSet::new();
                        to_destroy.insert(start);
                        loop {
                            let before = to_destroy.len();
                            let cur: Vec<u32> = to_destroy.iter().copied().collect();
                            for s in cur {
                                if model.main.has(s) {
                                    let set = if *desc { &model.main.descendants[&s] } else { &model.main.ancestors[&s] };
                                    to_destroy.extend(set.iter().copied());
                                }
                                if let Some(st) = &model.staging {
                                    if st.has(s) {
                                        let set = if *desc { &st.descendants[&s] } else { &st.ancestors[&s] };
                                        to_destroy.extend(set.iter().copied());
                                    }
                                }
                            }
                            if to_destroy.len() == before {
                                break;
                            }
                        }
                        for s in to_destroy {
                            model.destroy_ref(s);
                            real.destroy_ref(s);
                        }
                    }
                }
            }
            TgOp::MoveRef { pick } if open_builders.is_empty() => {
                let live: Vec<u32> = (0..MAX_SLOTS as u32)
                    .filter(|&s| model.live_refs[s as usize])
                    .collect();
                if let (Some(from), Some(to)) = (pick_from_vec(&live, *pick), model.alloc_slot()) {
                    model.move_ref(from, to);
                    assert!(real.move_ref(from, to));
                }
            }
            TgOp::SetFee { pick, fee } if open_builders.is_empty() => {
                let live: Vec<u32> = (0..MAX_SLOTS as u32)
                    .filter(|&s| model.live_refs[s as usize])
                    .collect();
                if let Some(s) = pick_from_vec(&live, *pick) {
                    model.set_fee(s, *fee);
                    real.set_fee(s, *fee);
                }
            }
            TgOp::StartStaging => {
                if model.staging.is_none() {
                    model.start_staging();
                    real.start_staging();
                }
            }
            TgOp::CommitStaging => {
                if model.staging.is_some() && open_builders.is_empty() {
                    model.commit_staging();
                    real.commit_staging();
                }
            }
            TgOp::AbortStaging => {
                if model.staging.is_some() {
                    model.abort_staging();
                    real.abort_staging();
                }
            }
            TgOp::DoWork { max_cost } if open_builders.is_empty() => {
                let _ = real.do_work(*max_cost);
            }
            TgOp::Trim if can_mutate_top => {
                let was_oversized = model.is_oversized(Level::Top);
                let overs_before: Vec<BTreeSet<u32>> = model
                    .top()
                    .components()
                    .into_iter()
                    .filter(|c| {
                        c.len() > model.max_cluster_count as usize
                            || c.iter().map(|s| model.top().txs[s].1 as u64).sum::<u64>() > model.max_cluster_size
                    })
                    .collect();
                let removed = real.trim();
                let rem_set: BTreeSet<u32> = removed.iter().copied().collect();
                assert_eq!(rem_set.len(), removed.len(), "step {step}: Trim returned duplicate refs");
                if !was_oversized {
                    assert!(removed.is_empty(), "step {step}: Trim removed txs from non-oversized graph");
                } else {
                    // Every removed tx must belong to an oversized cluster, and every oversized cluster must lose >= 1 tx.
                    for &r in &rem_set {
                        assert!(
                            overs_before.iter().any(|c| c.contains(&r)),
                            "step {step}: Trim removed tx {r} from a non-oversized cluster"
                        );
                    }
                    for oc in &overs_before {
                        assert!(
                            oc.iter().any(|s| rem_set.contains(s)),
                            "step {step}: Trim failed to touch oversized cluster {oc:?}"
                        );
                    }
                    // Removal must be descendant-closed.
                    for &r in &rem_set {
                        for &d in &model.top().descendants[&r] {
                            assert!(
                                rem_set.contains(&d),
                                "step {step}: Trim removed {r} without descendant {d}"
                            );
                        }
                    }
                    for &r in &rem_set {
                        model.top_mut().remove_tx(r);
                    }
                    assert!(
                        !real.is_oversized(Level::Top),
                        "step {step}: graph still oversized after Trim()"
                    );
                }
            }
            TgOp::OpenBuilder => {
                if !model.is_oversized(Level::Main) && open_builders.len() < 4 {
                    if let Some(id) = real.bb_open() {
                        open_builders.push((id, BTreeSet::new(), None));
                    }
                }
            }
            TgOp::BuilderStep { which, skip } => {
                if !open_builders.is_empty() {
                    let idx = *which as usize % open_builders.len();
                    let (id, ref mut done, ref mut last_rate) = open_builders[idx];
                    if let Some((chunk, rate)) = real.bb_current(id) {
                        if let Some(prev) = *last_rate {
                            assert!(
                                prev.cmp_ratio(&rate).is_ge(),
                                "step {step}: interleaved BlockBuilder feerate increased"
                            );
                        }
                        *last_rate = Some(rate);
                        if *skip {
                            // Skipping skips the rest of the chunk's cluster.
                            let comp = model.main.component_of(chunk[0]);
                            done.extend(comp);
                            real.bb_skip(id);
                        } else {
                            for &s in &chunk {
                                assert!(done.insert(s), "step {step}: BlockBuilder emitted {s} twice");
                            }
                            real.bb_include(id);
                        }
                    } else {
                        assert_eq!(
                            done.len(),
                            model.main.txs.len(),
                            "step {step}: BlockBuilder ended early (done {} vs {})",
                            done.len(),
                            model.main.txs.len()
                        );
                    }
                }
            }
            TgOp::CloseBuilder { which } => {
                if !open_builders.is_empty() {
                    let idx = *which as usize % open_builders.len();
                    let (id, _, _) = open_builders.swap_remove(idx);
                    real.bb_close(id);
                }
            }
            TgOp::CheckQueries { pick_a, pick_b, level_top } => {
                let lvl = if *level_top { Level::Top } else { Level::Main };
                let sim = model.level(lvl);
                let mut live: Vec<u32> = (0..MAX_SLOTS as u32)
                    .filter(|&s| model.live_refs[s as usize])
                    .collect();
                live.push(MAX_SLOTS as u32); // Include empty Ref to test empty-Ref query handling!
                if let Some(a) = pick_from_vec(&live, *pick_a) {
                    assert_eq!(real.exists(a, lvl), sim.has(a), "step {step}: Exists mismatch");
                    assert_eq!(
                        real.get_individual_feerate(a),
                        model.individual_feerate(a),
                        "step {step}: GetIndividualFeerate mismatch"
                    );
                    if !model.is_oversized(lvl) {
                        let ancs: BTreeSet<u32> = real.get_ancestors(a, lvl).into_iter().collect();
                        let want_ancs = sim.ancestors.get(&a).cloned().unwrap_or_default();
                        assert_eq!(ancs, want_ancs, "step {step}: GetAncestors mismatch");

                        let descs: BTreeSet<u32> = real.get_descendants(a, lvl).into_iter().collect();
                        let want_descs = sim.descendants.get(&a).cloned().unwrap_or_default();
                        assert_eq!(descs, want_descs, "step {step}: GetDescendants mismatch");

                        let clust = real.get_cluster(a, lvl);
                        let clust_set: BTreeSet<u32> = clust.iter().copied().collect();
                        assert_eq!(clust_set.len(), clust.len(), "step {step}: GetCluster duplicates");
                        assert_eq!(clust_set, sim.component_of(a), "step {step}: GetCluster set mismatch");
                        if !clust.is_empty() {
                            assert!(sim.is_topological(&clust), "step {step}: GetCluster not topological");
                        }

                        if let Some(b) = pick_from_vec(&live, *pick_b) {
                            let pair = [a, b];
                            let au: BTreeSet<u32> = real.get_ancestors_union(&pair, lvl).into_iter().collect();
                            let mut want_au = want_ancs.clone();
                            if let Some(sb) = sim.ancestors.get(&b) {
                                want_au.extend(sb.iter().copied());
                            }
                            assert_eq!(au, want_au, "step {step}: GetAncestorsUnion mismatch");

                            let du: BTreeSet<u32> = real.get_descendants_union(&pair, lvl).into_iter().collect();
                            let mut want_du = want_descs.clone();
                            if let Some(sb) = sim.descendants.get(&b) {
                                want_du.extend(sb.iter().copied());
                            }
                            assert_eq!(du, want_du, "step {step}: GetDescendantsUnion mismatch");

                            let mut distinct = BTreeSet::new();
                            for &s in &pair {
                                if sim.has(s) {
                                    distinct.insert(*sim.component_of(s).iter().next().unwrap());
                                }
                            }
                            assert_eq!(
                                real.count_distinct_clusters(&pair, lvl),
                                distinct.len() as u32,
                                "step {step}: CountDistinctClusters mismatch"
                            );
                        }
                    }
                }
            }
            _ => {}
        }

        check_state_invariants(&real, &model, step);
    }

    // Close any remaining builders and run final exhaustive verification.
    for (id, _, _) in open_builders.drain(..) {
        real.bb_close(id);
    }
    check_state_invariants(&real, &model, scenario.ops.len());
    check_full_main_order_and_builders(&mut real, &model, false, scenario.ops.len());
}

#[ephyra::test(gen = txgraph_scenarios(), tests = 2000)]
fn txgraph_matches_model(scenario: TxGraphScenario) {
    run_scenario(&scenario);
}
