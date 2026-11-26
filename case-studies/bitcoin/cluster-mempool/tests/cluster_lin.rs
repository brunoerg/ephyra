//! Property 3: `cluster_linearize.h` exact optimality, monotonicity,
//! PostLinearize guarantees, and scaling/relabeling metamorphic laws.

use ephyra_bitcoin_cluster_mempool::ffi::{
    chunk_linearization, compare_chunks, exhaustive_linearize, linearize, postlinearize, DiagramOrd,
};
use ephyra_bitcoin_cluster_mempool::gen_txgraph::{
    full_depgraphs, small_depgraphs, DepGraphCase, SAFE_FEE_MAX, SAFE_FEE_MIN,
};

fn is_topological(parent_masks: &[u64], order: &[u32]) -> bool {
    if order.len() != parent_masks.len() {
        return false;
    }
    let mut done_mask = 0u64;
    for &idx in order {
        if idx as usize >= parent_masks.len() {
            return false;
        }
        let bit = 1u64 << idx;
        if (done_mask & bit) != 0 {
            return false; // duplicate
        }
        if (parent_masks[idx as usize] & !done_mask) != 0 {
            return false; // missing parent
        }
        done_mask |= bit;
    }
    true
}

fn is_tree_shaped(parent_masks: &[u64]) -> bool {
    let n = parent_masks.len();
    // Compute transitive reduction? Simpler: check if raw in-degree <= 1 OR raw out-degree <= 1
    // (sufficient condition for tree-shaped DAG).
    let in_tree = parent_masks.iter().all(|m| m.count_ones() <= 1);
    let mut out_deg = vec![0u32; n];
    for &m in parent_masks {
        for p in 0..n {
            if ((m >> p) & 1) != 0 {
                out_deg[p] += 1;
            }
        }
    }
    let out_tree = out_deg.iter().all(|&d| d <= 1);
    in_tree || out_tree
}

#[ephyra::test(gen = small_depgraphs(), tests = 5000)]
fn linearize_small_matches_exhaustive(c: DepGraphCase) {
    let exact = exhaustive_linearize(&c.fees, &c.sizes, &c.parent_masks);
    let res = linearize(
        &c.fees,
        &c.sizes,
        &c.parent_masks,
        1_000_000,
        c.rng_seed,
        None,
        true,
    );

    assert!(
        is_topological(&c.parent_masks, res.order_slice()),
        "Linearize output not topological: {:?}",
        res.order_slice()
    );
    let (_, all_conn) = chunk_linearization(&c.fees, &c.sizes, &c.parent_masks, res.order_slice());
    assert!(all_conn, "Linearize produced disconnected chunk");

    let cmp = compare_chunks(res.chunks_slice(), exact.chunks_slice());
    if res.optimal != 0 {
        assert_eq!(
            cmp,
            DiagramOrd::Equal,
            "Linearize claimed optimal=true but diagram {:?} != exact {:?}",
            res.chunks_slice(),
            exact.chunks_slice()
        );
        assert_eq!(
            res.chunk_count, exact.chunk_count,
            "Linearize claimed optimal=true with minimal chunks, got {} vs exact {}",
            res.chunk_count, exact.chunk_count
        );
    } else {
        assert!(
            matches!(cmp, DiagramOrd::Less | DiagramOrd::Equal),
            "Linearize beat exact optimal?! {cmp:?}"
        );
    }

    // Tree-shaped PostLinearize optimality guarantee (cluster_linearize.h:1863-1864).
    if is_tree_shaped(&c.parent_masks) {
        let init: Vec<u32> = (0..c.n() as u32).collect();
        let post = postlinearize(&c.fees, &c.sizes, &c.parent_masks, &init);
        assert!(is_topological(&c.parent_masks, post.order_slice()));
        let cmp_tree = compare_chunks(post.chunks_slice(), exact.chunks_slice());
        assert_eq!(
            cmp_tree,
            DiagramOrd::Equal,
            "PostLinearize on tree-shaped graph not optimal: {:?} vs exact {:?}",
            post.chunks_slice(),
            exact.chunks_slice()
        );
    }
}

#[ephyra::test(gen = full_depgraphs(), tests = 3000)]
fn linearize_and_postlinearize_laws(c: DepGraphCase) {
    let n = c.n();
    let init: Vec<u32> = (0..n as u32).collect(); // Always valid topological because p < i!
    let (init_chunks, _) = chunk_linearization(&c.fees, &c.sizes, &c.parent_masks, &init);

    // 1. PostLinearize guarantees: topological, connected chunks, diagram >= init.
    let post = postlinearize(&c.fees, &c.sizes, &c.parent_masks, &init);
    assert!(
        is_topological(&c.parent_masks, post.order_slice()),
        "PostLinearize broke topology"
    );
    let (_, post_conn) = chunk_linearization(&c.fees, &c.sizes, &c.parent_masks, post.order_slice());
    assert!(post_conn, "PostLinearize produced disconnected chunk");
    let cmp_post = compare_chunks(post.chunks_slice(), &init_chunks);
    assert!(
        matches!(cmp_post, DiagramOrd::Greater | DiagramOrd::Equal),
        "PostLinearize worsened diagram: {cmp_post:?}"
    );

    // 2. PostLinearize moved-leaf property (cluster_linearize.h:1865-1869):
    //    Take a leaf (node with no children), move it to the end of `post`, optionally raise its fee,
    //    and PostLinearize again: result must be >= `post` (with original fees, or higher fee).
    let mut has_child = vec![false; n];
    for &m in &c.parent_masks {
        for p in 0..n {
            if ((m >> p) & 1) != 0 {
                has_child[p] = true;
            }
        }
    }
    if let Some(leaf) = (0..n).rfind(|&i| !has_child[i]) {
        let mut l2: Vec<u32> = post.order_slice().iter().copied().filter(|&x| x != leaf as u32).collect();
        l2.push(leaf as u32);
        let l3 = postlinearize(&c.fees, &c.sizes, &c.parent_masks, &l2);
        let cmp_leaf = compare_chunks(l3.chunks_slice(), post.chunks_slice());
        assert!(
            matches!(cmp_leaf, DiagramOrd::Greater | DiagramOrd::Equal),
            "PostLinearize violated moved-leaf guarantee: {cmp_leaf:?}"
        );
    }

    // 3. Linearize starting from `post` must never worsen diagram (`>= post`) and must be connected.
    let lin_from_old = linearize(
        &c.fees,
        &c.sizes,
        &c.parent_masks,
        c.max_cost,
        c.rng_seed,
        Some(post.order_slice()),
        true,
    );
    assert!(is_topological(&c.parent_masks, lin_from_old.order_slice()));
    if lin_from_old.optimal != 0 {
        let (_, lin_conn) = chunk_linearization(&c.fees, &c.sizes, &c.parent_masks, lin_from_old.order_slice());
        assert!(lin_conn, "Linearize(old) claimed optimal=true but produced disconnected chunk");
    }
    let cmp_old = compare_chunks(lin_from_old.chunks_slice(), post.chunks_slice());
    assert!(
        matches!(cmp_old, DiagramOrd::Greater | DiagramOrd::Equal),
        "Linearize(old_linearization) worsened diagram: {cmp_old:?}"
    );
    // Applying PostLinearize to Linearize(old) must restore connected chunks without worsening diagram.
    let post_after = postlinearize(&c.fees, &c.sizes, &c.parent_masks, lin_from_old.order_slice());
    let (_, pa_conn) = chunk_linearization(&c.fees, &c.sizes, &c.parent_masks, post_after.order_slice());
    assert!(pa_conn, "PostLinearize after Linearize(old) produced disconnected chunk");
    assert!(
        matches!(compare_chunks(post_after.chunks_slice(), lin_from_old.chunks_slice()), DiagramOrd::Greater | DiagramOrd::Equal),
        "PostLinearize after Linearize(old) worsened diagram"
    );

    // 3b. Non-topological old_linearization with is_topological=false:
    //     Linearize must call MakeTopological() and still return a valid topological ordering.
    let mut rev_lin: Vec<u32> = (0..n as u32).rev().collect();
    if n >= 2 {
        rev_lin.rotate_left(1);
    }
    let lin_nontopo = linearize(
        &c.fees,
        &c.sizes,
        &c.parent_masks,
        c.max_cost,
        c.rng_seed ^ 0x9e37_79b9_7f4a_7c15,
        Some(&rev_lin),
        false,
    );
    assert!(
        is_topological(&c.parent_masks, lin_nontopo.order_slice()),
        "Linearize(non-topo, is_topological=false) returned non-topological ordering"
    );
    if lin_nontopo.optimal != 0 && lin_from_old.optimal != 0 {
        assert_eq!(
            compare_chunks(lin_nontopo.chunks_slice(), lin_from_old.chunks_slice()),
            DiagramOrd::Equal,
            "two optimal Linearize runs disagreed on diagram"
        );
    }

    // 4. Feerate-scaling metamorphic invariance: scaling all fees by 2 (when safe)
    //    must yield an exact 2x-scaled optimal diagram when both runs reach optimal=true.
    let can_scale_fees = c.fees.iter().all(|&f| f >= SAFE_FEE_MIN / 2 && f <= SAFE_FEE_MAX / 2);
    if can_scale_fees && n <= 20 {
        let scaled_fees: Vec<i64> = c.fees.iter().map(|&f| f * 2).collect();
        let r1 = linearize(&c.fees, &c.sizes, &c.parent_masks, 200_000, c.rng_seed, None, true);
        let r2 = linearize(&scaled_fees, &c.sizes, &c.parent_masks, 200_000, c.rng_seed, None, true);
        if r1.optimal != 0 && r2.optimal != 0 {
            let scaled_r1_chunks: Vec<_> = r1
                .chunks_slice()
                .iter()
                .map(|ch| ephyra_bitcoin_cluster_mempool::ffi::TgFeeFrac::new(ch.fee * 2, ch.size))
                .collect();
            assert_eq!(
                compare_chunks(&scaled_r1_chunks, r2.chunks_slice()),
                DiagramOrd::Equal,
                "fee scaling x2 changed optimal diagram"
            );
        }
    }

    // Steer targeted search toward high-cost clusters!
    ephyra::target(lin_from_old.cost as f64);
}
