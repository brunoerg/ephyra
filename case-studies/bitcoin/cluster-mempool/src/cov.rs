//! In-process C++ LLVM coverage reading for `src/txgraph.cpp` and `src/cluster_linearize.h`.

#[cfg(feature = "cpp-cov")]
pub mod inner {
    use std::collections::BTreeSet;
    use ephyra::coverage::{self, Functions};

    /// Match Bitcoin Core's TxGraph & cluster_linearize C++ symbols (Itanium-mangled).
    pub fn is_target_cpp(name: &str) -> bool {
        let sym = name.rsplit(':').next().unwrap_or(name);
        sym.contains("TxGraph")
            || sym.contains("ClusterImpl")
            || sym.contains("cluster_linearize")
            || sym.contains("DepGraph")
            || sym.contains("SpanningForestState")
            || sym.contains("PostLinearize")
            || sym.contains("Linearize")
            || sym.contains("ChunkLinearization")
            || sym.contains("CompareChunks")
    }

    pub fn target_counters() -> BTreeSet<usize> {
        Functions::get()
            .all()
            .iter()
            .filter(|f| is_target_cpp(&f.name))
            .flat_map(|f| f.counters.clone())
            .collect()
    }

    pub fn target_functions() -> Vec<(String, std::ops::Range<usize>)> {
        Functions::get()
            .all()
            .iter()
            .filter(|f| is_target_cpp(&f.name))
            .map(|f| (f.name.clone(), f.counters.clone()))
            .collect()
    }

    pub fn covered(within: &BTreeSet<usize>, f: impl FnOnce()) -> BTreeSet<usize> {
        let before = coverage::snapshot().expect("cpp-cov requires instrumented C++ build");
        f();
        let after = coverage::snapshot().expect("cpp-cov requires instrumented C++ build");
        before
            .delta(&after)
            .hits()
            .iter()
            .map(|(c, _)| *c)
            .filter(|c| within.contains(c))
            .collect()
    }
}
