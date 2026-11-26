//! Valid-by-construction Ephyra generators, shrinkers, mutators, and metrics
//! for full-stack Bitcoin Core Cluster Mempool (`CTxMemPool`, `MemPoolAccept`,
//! `ProcessNewPackage`, TRUC, Ephemeral Dust, RBF, `PrioritiseTransaction`,
//! `BlockAssembler`, `MiniMiner`, `TrimToSize`, `Expire`, `DumpMempool`/`LoadMempool`).

use std::ops::ControlFlow;

use ephyra::{Gen, GenExt, Source};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxKind {
    /// Standard v2 tx spending 1..=3 UTXOs.
    StandardV2,
    /// TRUC v3 tx (BIP431: max 10kvB parent / 1kvB child, 1p1c topology).
    TrucV3,
    /// Zero-fee tx with an ephemeral dust (0-sat P2WSH) output.
    EphemeralDustParent,
    /// Tx with extra P2PK sigop outputs to exercise sigops-adjusted weight.
    SigopHeavy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxSpec {
    pub kind: TxKind,
    /// Input indices into the pool of available UTXOs (including RBF-conflicting ones if `allow_rbf`).
    pub input_picks: Vec<u8>,
    pub allow_rbf: bool,
    pub num_outputs: u8,
    /// Fee in satoshis (clamped to input total by builder; 0 for ephemeral dust).
    pub fee_sat: u64,
    /// Extra witness/OP_RETURN or multi-output padding to hit size boundaries (e.g. TRUC 1000 vB, 10000 vB).
    pub pad_bytes: u16,
    /// If true, set nSequence = MAX (final, does not signal BIP125 opt-in RBF).
    pub non_rbf_seq: bool,
    /// Salt byte to ensure distinct txids even for similar specs.
    pub salt: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageShape {
    /// 1 parent (possibly 0-fee or ephemeral dust) + 1 CPFP child spending parent's outputs (including dust!).
    OneParentOneChild {
        parent_truc: bool,
        child_truc: bool,
        ephemeral_dust: bool,
        parent_fee: u64,
        child_fee: u64,
        parent_rbf: bool,
        child_rbf: bool,
        /// Optional oversized child (>1000 vB) or oversized parent (>10000 vB) to test TRUC size limits.
        oversized_child: bool,
        salt: u8,
    },
    /// 2..=4 parents + 1 child spending all parents (multi-parent package / package RBF).
    MultiParentOneChild {
        num_parents: u8,
        parent_fee: u64,
        child_fee: u64,
        ephemeral_dust: bool,
        allow_rbf: bool,
        salt: u8,
    },
    /// Chain of 2..=5 transactions in one package (optionally TRUC v3 to test 3-gen TRUC rejection).
    Chain {
        len: u8,
        truc: bool,
        fees: Vec<u64>,
        salt: u8,
    },
    /// 1 parent + 2 sibling children in one package (tests TRUC descendant limits & package topology).
    OneParentTwoSiblings {
        truc: bool,
        conflict_siblings: bool,
        parent_fee: u64,
        child1_fee: u64,
        child2_fee: u64,
        salt: u8,
    },
    /// Deliberately malformed package shapes: reverse topological order, duplicate txid, or same-txid-diff-witness.
    MalformedPackage {
        mode: u8,
        salt: u8,
    },
    /// 4-tx Diamond DAG (GP -> P1, P2 -> Child).
    Diamond {
        gp_fee: u64,
        p1_fee: u64,
        p2_fee: u64,
        child_fee: u64,
        gp_pad: u16,
        salt: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MempoolOp {
    SubmitTx(TxSpec),
    SubmitPackage(PackageShape),
    PrioritiseTx {
        pick: u8,
        delta_sat: i64,
        /// If true, pick a not-yet-in-mempool synthetic txid.
        off_mempool: bool,
    },
    AdvanceTime {
        seconds: u32,
    },
    TrimToSize {
        /// Fraction 0..=100 of current dynamic memory usage (0 forces full eviction).
        keep_pct: u8,
    },
    Expire {
        age_seconds: u32,
    },
    MineBlock {
        max_weight: u32,
        min_feerate_sat_kvb: u32,
        remove_from_pool: bool,
    },
    ReorgBack,
    MiniMiner {
        target_feerate_sat_kvb: u32,
        picks: Vec<u8>,
    },
    ExtractRelay {
        n_to_sort: u8,
        extra_missing: u8,
    },
    DumpAndLoad {
        apply_deltas: bool,
    },
    RbfAndQueries {
        pick: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolScenario {
    pub limit_cluster_count: u32,
    pub limit_cluster_size_kvb: u32,
    pub max_mempool_mb: u32,
    pub min_relay_sat_kvb: u32,
    pub require_standard: bool,
    pub bytes_per_sigop: u32,
    pub ops: Vec<MempoolOp>,
}

#[ephyra::generator]
pub fn valid_mempool_scenario(s: &MempoolScenario) -> bool {
    s.limit_cluster_count >= 1
        && s.limit_cluster_count <= 64
        && s.limit_cluster_size_kvb >= 1
        && s.limit_cluster_size_kvb <= 250
        && s.max_mempool_mb <= 300
        && s.min_relay_sat_kvb <= 100_000
        && s.bytes_per_sigop <= 10_000
        && !s.ops.is_empty()
        && s.ops.len() <= 60
        && s.ops.iter().all(|op| match op {
            MempoolOp::SubmitTx(t) => !t.input_picks.is_empty() && t.num_outputs >= 1 && t.num_outputs <= 6,
            MempoolOp::SubmitPackage(PackageShape::MultiParentOneChild { num_parents, .. }) => {
                *num_parents >= 2 && *num_parents <= 4
            }
            MempoolOp::SubmitPackage(PackageShape::Chain { len, fees, .. }) => {
                *len >= 2 && *len <= 5 && fees.len() == *len as usize
            }
            MempoolOp::TrimToSize { keep_pct } => *keep_pct <= 120,
            _ => true,
        })
}

fn draw_sat_fee(g: &mut Source) -> u64 {
    match g.int(0u8..=6) {
        0 => 0,
        1 => g.int(100u64..=2_000),
        2 => g.int(2_000u64..=50_000),
        3 => g.int(50_000u64..=5_000_000),
        _ => g.int(500u64..=20_000),
    }
}

fn draw_tx_spec(g: &mut Source) -> TxSpec {
    let kind = match g.int(0u8..=7) {
        0..=3 => TxKind::StandardV2,
        4..=5 => TxKind::TrucV3,
        6 => TxKind::EphemeralDustParent,
        _ => TxKind::SigopHeavy,
    };
    let n_in = g.int(1usize..=3);
    let mut input_picks = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        input_picks.push(g.int(0u8..=255));
    }
    let fee_sat = if kind == TxKind::EphemeralDustParent {
        0
    } else {
        draw_sat_fee(g)
    };
    let pad_bytes = match g.int(0u8..=5) {
        0 => 0,
        1 => g.int(0u16..=300),
        2 => g.int(950u16..=1200), // straddles TRUC_CHILD_MAX_VSIZE (1000 vB)
        3 => 10_200,               // exceeds TRUC_MAX_VSIZE (10000 vB)
        _ => g.int(0u16..=80),
    };
    TxSpec {
        kind,
        input_picks,
        allow_rbf: g.bool_with(0.45),
        num_outputs: g.int(1u8..=4),
        fee_sat,
        pad_bytes,
        non_rbf_seq: g.bool_with(0.3),
        salt: g.int(0u8..=255),
    }
}

fn draw_package(g: &mut Source) -> PackageShape {
    match g.int(0u8..=8) {
        0..=2 => {
            let ephemeral_dust = g.bool_with(0.4);
            let parent_truc = g.bool_with(0.5);
            let child_truc = if g.bool_with(0.8) { parent_truc } else { !parent_truc };
            PackageShape::OneParentOneChild {
                parent_truc,
                child_truc,
                ephemeral_dust,
                parent_fee: if ephemeral_dust { 0 } else { draw_sat_fee(g) },
                child_fee: draw_sat_fee(g),
                parent_rbf: g.bool_with(0.35),
                child_rbf: g.bool_with(0.45),
                oversized_child: g.bool_with(0.15),
                salt: g.int(0u8..=255),
            }
        }
        3 => {
            let ephemeral_dust = g.bool_with(0.3);
            PackageShape::MultiParentOneChild {
                num_parents: g.int(2u8..=4),
                parent_fee: if ephemeral_dust { 0 } else { draw_sat_fee(g) },
                child_fee: draw_sat_fee(g).max(1000),
                ephemeral_dust,
                allow_rbf: g.bool_with(0.4),
                salt: g.int(0u8..=255),
            }
        }
        4 => {
            let len = g.int(2u8..=5);
            let mut fees = Vec::with_capacity(len as usize);
            for _ in 0..len {
                fees.push(draw_sat_fee(g));
            }
            PackageShape::Chain {
                len,
                truc: g.bool_with(0.35),
                fees,
                salt: g.int(0u8..=255),
            }
        }
        5 => PackageShape::OneParentTwoSiblings {
            truc: g.bool_with(0.6),
            conflict_siblings: g.bool_with(0.4),
            parent_fee: draw_sat_fee(g),
            child1_fee: draw_sat_fee(g).max(500),
            child2_fee: draw_sat_fee(g).max(500),
            salt: g.int(0u8..=255),
        },
        6..=7 => PackageShape::Diamond {
            gp_fee: draw_sat_fee(g),
            p1_fee: draw_sat_fee(g),
            p2_fee: draw_sat_fee(g),
            child_fee: draw_sat_fee(g),
            gp_pad: *g.pick(&[0, 100, 1200]),
            salt: g.int(0u8..=255),
        },
        _ => PackageShape::MalformedPackage {
            mode: g.int(0u8..=6),
            salt: g.int(0u8..=255),
        },
    }
}

fn draw_mempool_op(g: &mut Source) -> MempoolOp {
    match g.int(0u8..=24) {
        0..=7 => MempoolOp::SubmitTx(draw_tx_spec(g)),
        8..=13 => MempoolOp::SubmitPackage(draw_package(g)),
        14 => MempoolOp::PrioritiseTx {
            pick: g.int(0u8..=255),
            // Keep priority deltas within [-MAX_MONEY, +MAX_MONEY].
            delta_sat: match g.int(0u8..=5) {
                0 => 0,
                1 => g.int(-100_000i64..=100_000),
                2 => g.int(-50_000_000i64..=50_000_000),
                3 => *g.pick(&[-2_100_000_000_000_000, 2_100_000_000_000_000, -1, 1]),
                4 => g.int(-10_000_000_000i64..=10_000_000_000),
                _ => g.int(-500_000i64..=500_000),
            },
            off_mempool: g.bool_with(0.25),
        },
        15 => MempoolOp::AdvanceTime {
            seconds: match g.int(0u8..=3) {
                0 => g.int(1u32..=60),
                1 => g.int(60u32..=36_000),
                _ => g.int(0u32..=2_000_000),
            },
        },
        16 => MempoolOp::TrimToSize {
            keep_pct: match g.int(0u8..=3) {
                0 => 0,
                1 => g.int(10u8..=80),
                _ => g.int(50u8..=110),
            },
        },
        17 => MempoolOp::Expire {
            age_seconds: g.int(0u32..=500_000),
        },
        18 => MempoolOp::MineBlock {
            max_weight: match g.int(0u8..=3) {
                0 => 12_000,
                1 => g.int(12_000u32..=60_000),
                _ => 4_000_000,
            },
            min_feerate_sat_kvb: match g.int(0u8..=3) {
                0 => 0,
                1 => 1000,
                _ => g.int(0u32..=25_000),
            },
            remove_from_pool: g.bool_with(0.6),
        },
        19 => MempoolOp::ReorgBack,
        20 => {
            let n = g.int(1usize..=5);
            let mut picks = Vec::with_capacity(n);
            for _ in 0..n {
                picks.push(g.int(0u8..=255));
            }
            MempoolOp::MiniMiner {
                target_feerate_sat_kvb: g.int(0u32..=50_000),
                picks,
            }
        }
        21 => MempoolOp::ExtractRelay {
            n_to_sort: g.int(0u8..=30),
            extra_missing: g.int(0u8..=5),
        },
        22 => MempoolOp::DumpAndLoad {
            apply_deltas: g.bool_with(0.8),
        },
        _ => MempoolOp::RbfAndQueries {
            pick: g.int(0u8..=255),
        },
    }
}

fn gen_mempool_scenario(g: &mut Source) -> MempoolScenario {
    let limit_cluster_count = match g.int(0u8..=3) {
        0 => g.int(2u32..=6), // Tight cluster limit triggers frequent rejections and Trim() on reorg!
        1 => g.int(6u32..=16),
        _ => 64,
    };
    let limit_cluster_size_kvb = match g.int(0u8..=2) {
        0 => g.int(2u32..=15),
        _ => 101,
    };
    let len = g.int(4usize..=32);
    let mut ops = Vec::with_capacity(len);
    for _ in 0..len {
        ops.push(draw_mempool_op(g));
    }
    MempoolScenario {
        limit_cluster_count,
        limit_cluster_size_kvb,
        max_mempool_mb: *g.pick(&[5, 20, 100, 300]),
        min_relay_sat_kvb: *g.pick(&[0, 100, 1000, 5000]),
        require_standard: g.bool_with(0.85),
        bytes_per_sigop: *g.pick(&[20, 20, 20, 0, 2000]),
        ops,
    }
}

fn shrink_mempool_scenario(
    s: &MempoolScenario,
    visit: &mut dyn FnMut(MempoolScenario) -> ControlFlow<()>,
) -> ControlFlow<()> {
    let n = s.ops.len();
    if n > 1 {
        let mut c = s.clone();
        c.ops.truncate(n / 2);
        visit(c)?;

        for i in (0..n).rev() {
            let mut c = s.clone();
            c.ops.remove(i);
            visit(c)?;
        }
    }
    for i in 0..n {
        if let MempoolOp::SubmitTx(ref t) = s.ops[i] {
            if t.pad_bytes > 0 {
                let mut c = s.clone();
                if let MempoolOp::SubmitTx(ref mut mt) = c.ops[i] {
                    mt.pad_bytes = 0;
                }
                visit(c)?;
            }
            if t.input_picks.len() > 1 {
                let mut c = s.clone();
                if let MempoolOp::SubmitTx(ref mut mt) = c.ops[i] {
                    mt.input_picks.pop();
                }
                visit(c)?;
            }
        }
    }
    ControlFlow::Continue(())
}

fn mutate_mempool_scenario(s: &MempoolScenario, g: &mut Source) -> MempoolScenario {
    let mut out = s.clone();
    match g.int(0u8..=3) {
        0 if out.ops.len() < 60 => {
            let pos = g.int(0usize..=out.ops.len());
            out.ops.insert(pos, draw_mempool_op(g));
        }
        1 if out.ops.len() > 1 => {
            let pos = g.index(out.ops.len());
            out.ops.remove(pos);
        }
        2 => {
            let pos = g.index(out.ops.len());
            out.ops[pos] = draw_mempool_op(g);
        }
        _ => {
            out.limit_cluster_count = g.int(1u32..=64);
        }
    }
    out
}

/// Metrics for MempoolScenario:
/// - `ops`: raw count of operations (1..=60).
/// - `packages`: raw count of `SubmitPackage` ops.
/// - `has_reorg`: 1.0 if scenario contains `ReorgBack`, else 0.0.
/// - `has_trim`: 1.0 if scenario contains `TrimToSize`, else 0.0.
/// - `has_dump`: 1.0 if scenario contains `DumpAndLoad`, else 0.0.
/// - `ops_per_size`: `ops / (size + 1)`.
pub fn mempool_scenario_metrics(s: &MempoolScenario, size: usize) -> Vec<(&'static str, f64)> {
    let ops = s.ops.len() as f64;
    let packages = s
        .ops
        .iter()
        .filter(|o| matches!(o, MempoolOp::SubmitPackage(_)))
        .count() as f64;
    let has_reorg = if s.ops.iter().any(|o| matches!(o, MempoolOp::ReorgBack)) { 1.0 } else { 0.0 };
    let has_trim = if s.ops.iter().any(|o| matches!(o, MempoolOp::TrimToSize { .. })) { 1.0 } else { 0.0 };
    let has_dump = if s.ops.iter().any(|o| matches!(o, MempoolOp::DumpAndLoad { .. })) { 1.0 } else { 0.0 };
    vec![
        ("ops", ops),
        ("packages", packages),
        ("has_reorg", has_reorg),
        ("has_trim", has_trim),
        ("has_dump", has_dump),
        ("ops_per_size", ops / (size + 1) as f64),
    ]
}

#[ephyra::generator(valid_mempool_scenario, metrics = mempool_scenario_metrics)]
pub fn mempool_scenarios() -> impl Gen<Value = MempoolScenario> {
    gen_mempool_scenario
        .with_shrink(shrink_mempool_scenario)
        .with_mutate(mutate_mempool_scenario)
}
