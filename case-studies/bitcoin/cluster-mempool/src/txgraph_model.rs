//! Pure-Rust reference model of Bitcoin Core's `TxGraph` (main + optional staging).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::ffi::{Level, TgFeeFrac, MAX_SLOTS};

#[derive(Clone, Debug)]
pub struct SimLevel {
    /// Active transactions: slot -> (fee, size, txid)
    pub txs: BTreeMap<u32, (i64, i32, u64)>,
    /// Transitive closure of ancestors (including self): slot -> set of ancestor slots
    pub ancestors: BTreeMap<u32, BTreeSet<u32>>,
    /// Transitive closure of descendants (including self): slot -> set of descendant slots
    pub descendants: BTreeMap<u32, BTreeSet<u32>>,
    /// Cached oversizedness override (for the documented rule: destroying a Ref while staging
    /// exists does not clear main's oversizedness until staging is aborted or committed).
    pub sticky_oversized: bool,
}

impl SimLevel {
    pub fn new() -> Self {
        Self {
            txs: BTreeMap::new(),
            ancestors: BTreeMap::new(),
            descendants: BTreeMap::new(),
            sticky_oversized: false,
        }
    }

    pub fn add_tx(&mut self, slot: u32, fee: i64, size: i32, txid: u64) {
        self.txs.insert(slot, (fee, size, txid));
        let mut s = BTreeSet::new();
        s.insert(slot);
        self.ancestors.insert(slot, s.clone());
        self.descendants.insert(slot, s);
    }

    pub fn has(&self, slot: u32) -> bool {
        self.txs.contains_key(&slot)
    }

    pub fn would_cycle(&self, parent: u32, child: u32) -> bool {
        if !self.has(parent) || !self.has(child) {
            return false;
        }
        self.ancestors[&parent].contains(&child)
    }

    pub fn add_dep(&mut self, parent: u32, child: u32) {
        if !self.has(parent) || !self.has(child) || self.ancestors[&child].contains(&parent) {
            return;
        }
        let par_ancs: Vec<u32> = self.ancestors[&parent].iter().copied().collect();
        let chl_descs: Vec<u32> = self.descendants[&child].iter().copied().collect();
        for &a in &par_ancs {
            let d = self.descendants.get_mut(&a).unwrap();
            for &c in &chl_descs {
                d.insert(c);
            }
        }
        for &c in &chl_descs {
            let a_set = self.ancestors.get_mut(&c).unwrap();
            for &a in &par_ancs {
                a_set.insert(a);
            }
        }
    }

    pub fn remove_tx(&mut self, slot: u32) {
        if self.txs.remove(&slot).is_none() {
            return;
        }
        self.ancestors.remove(&slot);
        self.descendants.remove(&slot);
        for set in self.ancestors.values_mut() {
            set.remove(&slot);
        }
        for set in self.descendants.values_mut() {
            set.remove(&slot);
        }
    }

    pub fn rename_slot(&mut self, from: u32, to: u32) {
        if let Some(val) = self.txs.remove(&from) {
            self.txs.insert(to, val);
        }
        if let Some(mut ancs) = self.ancestors.remove(&from) {
            ancs.remove(&from);
            ancs.insert(to);
            self.ancestors.insert(to, ancs);
        }
        if let Some(mut descs) = self.descendants.remove(&from) {
            descs.remove(&from);
            descs.insert(to);
            self.descendants.insert(to, descs);
        }
        for set in self.ancestors.values_mut() {
            if set.remove(&from) {
                set.insert(to);
            }
        }
        for set in self.descendants.values_mut() {
            if set.remove(&from) {
                set.insert(to);
            }
        }
    }

    pub fn set_fee(&mut self, slot: u32, fee: i64) {
        if let Some(entry) = self.txs.get_mut(&slot) {
            entry.0 = fee;
        }
    }

    pub fn components(&self) -> Vec<BTreeSet<u32>> {
        let mut unvisited: BTreeSet<u32> = self.txs.keys().copied().collect();
        let mut comps = Vec::new();
        while let Some(&start) = unvisited.iter().next() {
            let mut comp = BTreeSet::new();
            let mut q = VecDeque::new();
            q.push_back(start);
            comp.insert(start);
            unvisited.remove(&start);
            while let Some(u) = q.pop_front() {
                for &v in self.ancestors[&u].iter().chain(self.descendants[&u].iter()) {
                    if unvisited.remove(&v) {
                        comp.insert(v);
                        q.push_back(v);
                    }
                }
            }
            comps.push(comp);
        }
        comps
    }

    pub fn component_of(&self, slot: u32) -> BTreeSet<u32> {
        if !self.has(slot) {
            return BTreeSet::new();
        }
        let mut comp = BTreeSet::new();
        let mut q = VecDeque::new();
        q.push_back(slot);
        comp.insert(slot);
        while let Some(u) = q.pop_front() {
            for &v in self.ancestors[&u].iter().chain(self.descendants[&u].iter()) {
                if comp.insert(v) {
                    q.push_back(v);
                }
            }
        }
        comp
    }

    pub fn compute_oversized(&self, max_count: u32, max_size: u64) -> bool {
        for c in self.components() {
            if c.len() > max_count as usize {
                return true;
            }
            let sz: u64 = c.iter().map(|s| self.txs[s].1 as u64).sum();
            if sz > max_size {
                return true;
            }
        }
        false
    }

    pub fn is_oversized(&self, max_count: u32, max_size: u64) -> bool {
        self.sticky_oversized || self.compute_oversized(max_count, max_size)
    }

    pub fn is_topological(&self, order: &[u32]) -> bool {
        let mut seen = BTreeSet::new();
        for &s in order {
            seen.insert(s);
            if !self.ancestors[&s].is_subset(&seen) {
                return false;
            }
        }
        true
    }

    /// Chunk a topological ordering of a single cluster into maximal highest-feerate prefixes.
    pub fn chunk_order(&self, order: &[u32]) -> Vec<(Vec<u32>, TgFeeFrac)> {
        let mut chunks: Vec<(Vec<u32>, TgFeeFrac)> = Vec::new();
        for &s in order {
            let (fee, size, _) = self.txs[&s];
            let mut cur_txs = vec![s];
            let mut cur_rate = TgFeeFrac::new(fee, size);
            while let Some((prev_txs, prev_rate)) = chunks.last() {
                if cur_rate.cmp_ratio(prev_rate).is_gt() {
                    let mut merged = prev_txs.clone();
                    merged.extend(cur_txs);
                    cur_txs = merged;
                    cur_rate = TgFeeFrac::new(prev_rate.fee + cur_rate.fee, prev_rate.size + cur_rate.size);
                    chunks.pop();
                } else {
                    break;
                }
            }
            chunks.push((cur_txs, cur_rate));
        }
        chunks
    }

    pub fn is_connected_subset(&self, subset: &BTreeSet<u32>) -> bool {
        if subset.is_empty() {
            return true;
        }
        let start = *subset.iter().next().unwrap();
        let mut vis = BTreeSet::new();
        let mut q = VecDeque::new();
        vis.insert(start);
        q.push_back(start);
        while let Some(u) = q.pop_front() {
            for &v in self.ancestors[&u].iter().chain(self.descendants[&u].iter()) {
                if subset.contains(&v) && vis.insert(v) {
                    q.push_back(v);
                }
            }
        }
        vis.len() == subset.len()
    }
}

#[derive(Clone, Debug)]
pub struct TxGraphModel {
    pub max_cluster_count: u32,
    pub max_cluster_size: u64,
    pub main: SimLevel,
    pub staging: Option<SimLevel>,
    /// Live C++ Ref slots (even if removed from one or both levels).
    pub live_refs: [bool; MAX_SLOTS],
    pub next_txid: u64,
}

impl TxGraphModel {
    pub fn new(max_cluster_count: u32, max_cluster_size: u64) -> Self {
        Self {
            max_cluster_count,
            max_cluster_size,
            main: SimLevel::new(),
            staging: None,
            live_refs: [false; MAX_SLOTS],
            next_txid: 1,
        }
    }

    pub fn alloc_slot(&self) -> Option<u32> {
        (0..MAX_SLOTS).find(|&i| !self.live_refs[i]).map(|i| i as u32)
    }

    pub fn top(&self) -> &SimLevel {
        self.staging.as_ref().unwrap_or(&self.main)
    }

    pub fn top_mut(&mut self) -> &mut SimLevel {
        self.staging.as_mut().unwrap_or(&mut self.main)
    }

    pub fn level(&self, lvl: Level) -> &SimLevel {
        match lvl {
            Level::Main => &self.main,
            Level::Top => self.top(),
        }
    }

    pub fn is_oversized(&self, lvl: Level) -> bool {
        self.level(lvl).is_oversized(self.max_cluster_count, self.max_cluster_size)
    }

    pub fn add_tx(&mut self, slot: u32, fee: i64, size: i32) -> u64 {
        let txid = self.next_txid;
        self.next_txid += 1;
        self.live_refs[slot as usize] = true;
        self.top_mut().add_tx(slot, fee, size, txid);
        txid
    }

    pub fn start_staging(&mut self) {
        assert!(self.staging.is_none());
        let mut st = self.main.clone();
        st.sticky_oversized = false;
        self.staging = Some(st);
    }

    pub fn abort_staging(&mut self) {
        assert!(self.staging.is_some());
        self.staging = None;
        self.main.sticky_oversized = false;
    }

    pub fn commit_staging(&mut self) {
        let mut st = self.staging.take().expect("commit without staging");
        st.sticky_oversized = false;
        self.main = st;
    }

    pub fn set_fee(&mut self, slot: u32, fee: i64) {
        self.main.set_fee(slot, fee);
        if let Some(st) = &mut self.staging {
            st.set_fee(slot, fee);
        }
    }

    pub fn move_ref(&mut self, from: u32, to: u32) {
        assert!(self.live_refs[from as usize] && !self.live_refs[to as usize]);
        self.live_refs[from as usize] = false;
        self.live_refs[to as usize] = true;
        self.main.rename_slot(from, to);
        if let Some(st) = &mut self.staging {
            st.rename_slot(from, to);
        }
    }

    /// Destroy Ref (removes from BOTH main and staging; per txgraph.h, while staging exists,
    /// destroying a Ref does NOT clear main's oversizedness until staging ends).
    pub fn destroy_ref(&mut self, slot: u32) {
        if self.staging.is_some() && self.main.is_oversized(self.max_cluster_count, self.max_cluster_size) {
            self.main.sticky_oversized = true;
        }
        self.live_refs[slot as usize] = false;
        self.main.remove_tx(slot);
        if let Some(st) = &mut self.staging {
            st.remove_tx(slot);
        }
    }

    pub fn individual_feerate(&self, slot: u32) -> TgFeeFrac {
        if let Some(&(f, s, _)) = self.main.txs.get(&slot) {
            return TgFeeFrac::new(f, s);
        }
        if let Some(st) = &self.staging {
            if let Some(&(f, s, _)) = st.txs.get(&slot) {
                return TgFeeFrac::new(f, s);
            }
        }
        TgFeeFrac::default()
    }
}
