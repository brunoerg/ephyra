//! Valid-by-construction Ephyra generators, shrinkers, mutators, and metrics
//! for `TxGraph` stateful scenarios and `cluster_linearize::DepGraph` clusters.

use std::ops::ControlFlow;

use ephyra::{Gen, GenExt, Source};

/// Fee generation range safe for summing up to 64 transactions without overflowing `i64`
/// (Bitcoin Core's own `txgraph` fuzzer uses `[-0x8000000000000, 0x7ffffffffffff]`, ~2.25e15 sat).
pub const SAFE_FEE_MIN: i64 = -0x8000_0000_0000_0;
pub const SAFE_FEE_MAX: i64 = 0x7fff_ffff_ffff_f;
pub const MAX_TX_SIZE: i32 = 0x3f_ffff;

/// A valid DAG cluster for `cluster_linearize` (`1 <= n <= 64`, topological order `p < i` for all edges).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepGraphCase {
    pub fees: Vec<i64>,
    pub sizes: Vec<i32>,
    /// `parent_masks[i]` has bit `p` set iff `p` is a direct parent of `i` (`p < i`, guaranteeing acyclicity).
    pub parent_masks: Vec<u64>,
    pub max_cost: u64,
    pub rng_seed: u64,
}

impl DepGraphCase {
    pub fn n(&self) -> usize {
        self.fees.len()
    }
    pub fn edge_count(&self) -> usize {
        self.parent_masks.iter().map(|m| m.count_ones() as usize).sum()
    }
}

#[ephyra::generator]
pub fn valid_depgraph(c: &DepGraphCase) -> bool {
    let n = c.fees.len();
    if n == 0 || n > 64 || c.sizes.len() != n || c.parent_masks.len() != n {
        return false;
    }
    for i in 0..n {
        if c.sizes[i] <= 0 || c.sizes[i] > MAX_TX_SIZE {
            return false;
        }
        if c.fees[i] < SAFE_FEE_MIN || c.fees[i] > SAFE_FEE_MAX {
            return false;
        }
        // Strict upper-triangular mask guarantees acyclicity (only bits < i allowed).
        let allowed = if i == 0 { 0u64 } else { (1u64 << i) - 1 };
        if (c.parent_masks[i] & !allowed) != 0 {
            return false;
        }
    }
    true
}

fn draw_fee(g: &mut Source) -> i64 {
    match g.int(0u8..=9) {
        0 => 0,
        1 => g.int(-20i64..=20),
        2 => g.int(-10_000i64..=10_000),
        3 => *g.pick(&[SAFE_FEE_MIN, SAFE_FEE_MAX, -1, 1, 1000, -1000]),
        _ => g.int(0i64..=500),
    }
}

fn draw_size(g: &mut Source) -> i32 {
    match g.int(0u8..=7) {
        0 => 1,
        1 => *g.pick(&[1, 2, 10, 100, 400, 1000, MAX_TX_SIZE]),
        2 => g.int(1i32..=MAX_TX_SIZE),
        _ => g.int(1i32..=255),
    }
}

fn gen_depgraph_with_max_n(g: &mut Source, max_n: usize) -> DepGraphCase {
    let cap = max_n.min(64).max(1);
    let n = g.int(1usize..=cap);
    let mut fees = Vec::with_capacity(n);
    let mut sizes = Vec::with_capacity(n);
    let mut parent_masks = vec![0u64; n];

    // Topology archetype: mix chains, trees, diamonds, dense DAGs, and disconnected clusters.
    let topo = g.int(0u8..=5);
    for i in 0..n {
        fees.push(draw_fee(g));
        sizes.push(draw_size(g));
        if i == 0 {
            continue;
        }
        match topo {
            0 => {
                // Chain
                parent_masks[i] = 1u64 << (i - 1);
            }
            1 => {
                // In-tree (at most 1 parent)
                if g.bool_with(0.85) {
                    let p = g.index(i);
                    parent_masks[i] = 1u64 << p;
                }
            }
            2 => {
                // Out-tree / star / multi-parent diamond
                let k = g.int(1usize..=i.min(3));
                for _ in 0..k {
                    let p = g.index(i);
                    parent_masks[i] |= 1u64 << p;
                }
            }
            3 => {
                // Layered / bipartite-ish DAG (hard for linearization!)
                for p in 0..i {
                    if g.bool_with(0.35) {
                        parent_masks[i] |= 1u64 << p;
                    }
                }
            }
            4 => {
                // Sparse random DAG
                for p in 0..i {
                    if g.bool_with(0.15) {
                        parent_masks[i] |= 1u64 << p;
                    }
                }
            }
            _ => {
                // Dense DAG (lots of diamonds / bottlenecks)
                for p in 0..i {
                    if g.bool_with(0.6) {
                        parent_masks[i] |= 1u64 << p;
                    }
                }
            }
        }
    }

    let max_cost = match g.int(0u8..=5) {
        0 => 0,
        1 => g.int(1u64..=50),
        2 => g.int(50u64..=2000),
        _ => 100_000,
    };
    let rng_seed = g.int(0u64..=u64::MAX);

    DepGraphCase {
        fees,
        sizes,
        parent_masks,
        max_cost,
        rng_seed,
    }
}

fn shrink_depgraph(c: &DepGraphCase, visit: &mut dyn FnMut(DepGraphCase) -> ControlFlow<()>) -> ControlFlow<()> {
    let n = c.n();
    // 1. Drop the last node (preserves strict upper-triangular masks with zero reindexing!).
    if n > 1 {
        let mut s = c.clone();
        s.fees.pop();
        s.sizes.pop();
        s.parent_masks.pop();
        visit(s)?;

        // Also try halving node count if n >= 4.
        if n >= 4 {
            let half = n / 2;
            let mut s = c.clone();
            s.fees.truncate(half);
            s.sizes.truncate(half);
            s.parent_masks.truncate(half);
            visit(s)?;
        }
    }
    // 2. Remove individual edges.
    for i in 1..n {
        let mut m = c.parent_masks[i];
        while m != 0 {
            let bit = m & m.wrapping_neg();
            m ^= bit;
            let mut s = c.clone();
            s.parent_masks[i] ^= bit;
            visit(s)?;
        }
    }
    // 3. Shrink fees toward 0 and sizes toward 1.
    for i in 0..n {
        if c.fees[i] != 0 {
            let mut s = c.clone();
            s.fees[i] = 0;
            visit(s)?;
            if c.fees[i].abs() > 1 {
                let mut s = c.clone();
                s.fees[i] = c.fees[i] / 2;
                visit(s)?;
            }
        }
        if c.sizes[i] > 1 {
            let mut s = c.clone();
            s.sizes[i] = 1;
            visit(s)?;
            if c.sizes[i] > 2 {
                let mut s = c.clone();
                s.sizes[i] = c.sizes[i] / 2;
                visit(s)?;
            }
        }
    }
    if c.max_cost > 0 {
        let mut s = c.clone();
        s.max_cost /= 2;
        visit(s)?;
    }
    ControlFlow::Continue(())
}

fn mutate_depgraph(c: &DepGraphCase, g: &mut Source) -> DepGraphCase {
    let mut out = c.clone();
    let n = out.n();
    match g.int(0u8..=4) {
        0 => {
            // Tweak one fee
            let i = g.index(n);
            out.fees[i] = draw_fee(g);
        }
        1 => {
            // Tweak one size
            let i = g.index(n);
            out.sizes[i] = draw_size(g);
        }
        2 if n > 1 => {
            // Flip one valid edge (p < i)
            let i = g.int(1usize..n);
            let p = g.index(i);
            out.parent_masks[i] ^= 1u64 << p;
        }
        3 if n < 64 => {
            // Append a new node
            let mut mask = 0u64;
            for p in 0..n {
                if g.bool_with(0.3) {
                    mask |= 1u64 << p;
                }
            }
            out.fees.push(draw_fee(g));
            out.sizes.push(draw_size(g));
            out.parent_masks.push(mask);
        }
        _ => {
            out.rng_seed = g.int(0u64..=u64::MAX);
        }
    }
    out
}

/// Metrics for DepGraphCase:
/// - `nodes`: raw transaction count `n` (denominator 1; range 1..=64).
/// - `edges`: raw direct dependency count (denominator 1; 0 = disconnected, higher = denser DAG).
/// - `neg_fee`: 1.0 if any fee < 0, else 0.0.
/// - `nodes_per_size`: `nodes / (size + 1)` showing size responsiveness.
pub fn depgraph_metrics(c: &DepGraphCase, size: usize) -> Vec<(&'static str, f64)> {
    let n = c.n() as f64;
    let edges = c.edge_count() as f64;
    let neg = if c.fees.iter().any(|&f| f < 0) { 1.0 } else { 0.0 };
    let zero = if c.fees.iter().any(|&f| f == 0) { 1.0 } else { 0.0 };
    vec![
        ("nodes", n),
        ("edges", edges),
        ("neg_fee", neg),
        ("zero_fee", zero),
        ("nodes_per_size", n / (size + 1) as f64),
    ]
}

#[ephyra::generator(valid_depgraph, metrics = depgraph_metrics)]
pub fn small_depgraphs() -> impl Gen<Value = DepGraphCase> {
    (|g: &mut Source| gen_depgraph_with_max_n(g, 9))
        .with_shrink(shrink_depgraph)
        .with_mutate(|c, g| {
            let mut m = mutate_depgraph(c, g);
            if m.n() > 9 {
                m.fees.truncate(9);
                m.sizes.truncate(9);
                m.parent_masks.truncate(9);
            }
            m
        })
}

#[ephyra::generator(valid_depgraph, metrics = depgraph_metrics)]
pub fn full_depgraphs() -> impl Gen<Value = DepGraphCase> {
    (|g: &mut Source| gen_depgraph_with_max_n(g, 64))
        .with_shrink(shrink_depgraph)
        .with_mutate(mutate_depgraph)
}

// =========================================================================
// TxGraph Stateful Operation Sequences
// =========================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TgOp {
    AddTx {
        fee: i64,
        size: i32,
    },
    AddDep {
        parent_pick: u8,
        child_pick: u8,
    },
    /// Remove a transaction plus either all its descendants (`desc=true`) or all its ancestors (`desc=false`),
    /// respecting TxGraph's documented removal/dependency reordering contract.
    RemoveClosure {
        pick: u8,
        desc: bool,
    },
    /// Destroy a Ref (either already removed, or live with closure across both graphs).
    DestroyRef {
        pick: u8,
        only_removed: bool,
        desc: bool,
    },
    /// Move-construct a live Ref to a new heap address (`TxGraph::Ref(Ref&&)` / `UpdateRef`).
    MoveRef {
        pick: u8,
    },
    SetFee {
        pick: u8,
        fee: i64,
    },
    StartStaging,
    CommitStaging,
    AbortStaging,
    DoWork {
        max_cost: u64,
    },
    Trim,
    OpenBuilder,
    BuilderStep {
        which: u8,
        skip: bool,
    },
    CloseBuilder {
        which: u8,
    },
    /// Exercise all read queries + SanityCheck + BlockBuilder/GetWorstMainChunk/CompareMainOrder checks.
    CheckQueries {
        pick_a: u8,
        pick_b: u8,
        level_top: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxGraphScenario {
    pub max_cluster_count: u32,
    pub max_cluster_size: u64,
    pub acceptable_cost: u64,
    pub ops: Vec<TgOp>,
}

#[ephyra::generator]
pub fn valid_txgraph_scenario(s: &TxGraphScenario) -> bool {
    s.max_cluster_count >= 1
        && s.max_cluster_count <= 64
        && s.max_cluster_size >= 1
        && s.max_cluster_size <= (MAX_TX_SIZE as u64) * 64
        && !s.ops.is_empty()
        && s.ops.len() <= 160
        && s.ops.iter().all(|op| match op {
            TgOp::AddTx { fee, size } => {
                *size >= 1 && *size <= MAX_TX_SIZE && *fee >= SAFE_FEE_MIN && *fee <= SAFE_FEE_MAX
            }
            TgOp::SetFee { fee, .. } => *fee >= SAFE_FEE_MIN && *fee <= SAFE_FEE_MAX,
            _ => true,
        })
}

fn draw_tg_op(g: &mut Source) -> TgOp {
    match g.int(0u8..=23) {
        0..=5 => TgOp::AddTx {
            fee: draw_fee(g),
            size: draw_size(g),
        },
        6..=10 => TgOp::AddDep {
            parent_pick: g.int(0u8..=255),
            child_pick: g.int(0u8..=255),
        },
        11..=12 => TgOp::RemoveClosure {
            pick: g.int(0u8..=255),
            desc: g.bool(),
        },
        13 => TgOp::DestroyRef {
            pick: g.int(0u8..=255),
            only_removed: g.bool(),
            desc: g.bool(),
        },
        14 => TgOp::MoveRef {
            pick: g.int(0u8..=255),
        },
        15 => TgOp::SetFee {
            pick: g.int(0u8..=255),
            fee: draw_fee(g),
        },
        16 => TgOp::StartStaging,
        17 => TgOp::CommitStaging,
        18 => TgOp::AbortStaging,
        19 => TgOp::DoWork {
            max_cost: match g.int(0u8..=3) {
                0 => 0,
                1 => g.int(1u64..=100),
                2 => g.int(100u64..=5_000),
                _ => 50_000,
            },
        },
        20 => TgOp::Trim,
        21 => TgOp::OpenBuilder,
        22 => {
            if g.bool_with(0.7) {
                TgOp::BuilderStep {
                    which: g.int(0u8..=3),
                    skip: g.bool_with(0.3),
                }
            } else {
                TgOp::CloseBuilder {
                    which: g.int(0u8..=3),
                }
            }
        }
        _ => TgOp::CheckQueries {
            pick_a: g.int(0u8..=255),
            pick_b: g.int(0u8..=255),
            level_top: g.bool(),
        },
    }
}

fn gen_txgraph_scenario(g: &mut Source) -> TxGraphScenario {
    // Mix small cluster limits (triggers oversizedness & Trim often!) with realistic 64-tx clusters.
    let max_cluster_count = match g.int(0u8..=4) {
        0 => g.int(1u32..=4),
        1 => g.int(4u32..=12),
        2 => g.int(12u32..=32),
        _ => g.int(1u32..=64),
    };
    let max_cluster_size = match g.int(0u8..=3) {
        0 => g.int(1u64..=500),
        1 => g.int(500u64..=10_000),
        _ => g.int(1u64..=(MAX_TX_SIZE as u64) * 64),
    };
    let acceptable_cost = match g.int(0u8..=3) {
        0 => 0,
        1 => g.int(1u64..=200),
        _ => g.int(0u64..=10_000),
    };
    let len = g.int(1usize..=80);
    let mut ops = Vec::with_capacity(len);
    for _ in 0..len {
        ops.push(draw_tg_op(g));
    }
    TxGraphScenario {
        max_cluster_count,
        max_cluster_size,
        acceptable_cost,
        ops,
    }
}

fn shrink_txgraph_scenario(
    s: &TxGraphScenario,
    visit: &mut dyn FnMut(TxGraphScenario) -> ControlFlow<()>,
) -> ControlFlow<()> {
    let n = s.ops.len();
    if n > 1 {
        // Halve ops from the tail
        let mut c = s.clone();
        c.ops.truncate(n / 2);
        visit(c)?;

        // Drop each single op (from the back first, fast convergence)
        for i in (0..n).rev() {
            let mut c = s.clone();
            c.ops.remove(i);
            visit(c)?;
        }
    }
    // Simplify individual op payloads (fees -> 0, sizes -> 1)
    for i in 0..n {
        match s.ops[i] {
            TgOp::AddTx { fee, size } => {
                if fee != 0 {
                    let mut c = s.clone();
                    c.ops[i] = TgOp::AddTx { fee: 0, size };
                    visit(c)?;
                }
                if size > 1 {
                    let mut c = s.clone();
                    c.ops[i] = TgOp::AddTx { fee, size: 1 };
                    visit(c)?;
                }
            }
            TgOp::SetFee { pick, fee } if fee != 0 => {
                let mut c = s.clone();
                c.ops[i] = TgOp::SetFee { pick, fee: 0 };
                visit(c)?;
            }
            _ => {}
        }
    }
    if s.acceptable_cost > 0 {
        let mut c = s.clone();
        c.acceptable_cost /= 2;
        visit(c)?;
    }
    ControlFlow::Continue(())
}

fn mutate_txgraph_scenario(s: &TxGraphScenario, g: &mut Source) -> TxGraphScenario {
    let mut out = s.clone();
    match g.int(0u8..=4) {
        0 if out.ops.len() < 160 => {
            let pos = g.int(0usize..=out.ops.len());
            out.ops.insert(pos, draw_tg_op(g));
        }
        1 if out.ops.len() > 1 => {
            let pos = g.index(out.ops.len());
            out.ops.remove(pos);
        }
        2 => {
            let pos = g.index(out.ops.len());
            out.ops[pos] = draw_tg_op(g);
        }
        3 if out.ops.len() >= 2 => {
            let a = g.index(out.ops.len());
            let b = g.index(out.ops.len());
            out.ops.swap(a, b);
        }
        _ => {
            out.max_cluster_count = g.int(1u32..=64);
        }
    }
    out
}

/// Metrics for TxGraphScenario:
/// - `ops`: raw operation count (1..=160).
/// - `max_cluster_count`: configured limit (1..=64).
/// - `has_staging`: 1.0 if scenario contains `StartStaging`, else 0.0.
/// - `has_trim`: 1.0 if scenario contains `Trim`, else 0.0.
/// - `has_builder`: 1.0 if scenario contains `OpenBuilder`, else 0.0.
/// - `ops_per_size`: `ops / (size + 1)`.
pub fn txgraph_scenario_metrics(s: &TxGraphScenario, size: usize) -> Vec<(&'static str, f64)> {
    let ops = s.ops.len() as f64;
    let has_staging = if s.ops.iter().any(|o| matches!(o, TgOp::StartStaging)) { 1.0 } else { 0.0 };
    let has_trim = if s.ops.iter().any(|o| matches!(o, TgOp::Trim)) { 1.0 } else { 0.0 };
    let has_builder = if s.ops.iter().any(|o| matches!(o, TgOp::OpenBuilder)) { 1.0 } else { 0.0 };
    vec![
        ("ops", ops),
        ("max_cluster_count", s.max_cluster_count as f64),
        ("has_staging", has_staging),
        ("has_trim", has_trim),
        ("has_builder", has_builder),
        ("ops_per_size", ops / (size + 1) as f64),
    ]
}

#[ephyra::generator(valid_txgraph_scenario, metrics = txgraph_scenario_metrics)]
pub fn txgraph_scenarios() -> impl Gen<Value = TxGraphScenario> {
    gen_txgraph_scenario
        .with_shrink(shrink_txgraph_scenario)
        .with_mutate(mutate_txgraph_scenario)
}
