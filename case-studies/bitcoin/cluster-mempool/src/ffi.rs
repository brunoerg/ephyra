//! Safe Rust wrapper over `cpp/txgraph_shim.h` (direct FFI to Bitcoin Core's `TxGraph` and `cluster_linearize`).

use std::cmp::Ordering;

pub const MAX_SLOTS: usize = 256;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgFeeFrac {
    pub fee: i64,
    pub size: i32,
}

impl TgFeeFrac {
    pub fn new(fee: i64, size: i32) -> Self {
        Self { fee, size }
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0 && self.fee == 0
    }
    /// Exact feerate ratio comparison (`a.fee / a.size` vs `b.fee / b.size`) using i128.
    pub fn cmp_ratio(&self, other: &Self) -> Ordering {
        if self.size == 0 && other.size == 0 {
            return Ordering::Equal;
        }
        let lhs = (self.fee as i128) * (other.size as i128);
        let rhs = (other.fee as i128) * (self.size as i128);
        lhs.cmp(&rhs)
    }
    /// `ByRatioNegSize`: higher feerate first, smaller size on ties.
    pub fn cmp_ratio_neg_size(&self, other: &Self) -> Ordering {
        self.cmp_ratio(other).then_with(|| other.size.cmp(&self.size))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TgLinResult {
    pub count: u32,
    pub order: [u32; 64],
    pub optimal: i32,
    pub cost: u64,
    pub chunk_count: u32,
    pub chunks: [TgFeeFrac; 64],
}

impl Default for TgLinResult {
    fn default() -> Self {
        Self {
            count: 0,
            order: [0; 64],
            optimal: 0,
            cost: 0,
            chunk_count: 0,
            chunks: [TgFeeFrac::default(); 64],
        }
    }
}

impl TgLinResult {
    pub fn order_slice(&self) -> &[u32] {
        &self.order[..self.count as usize]
    }
    pub fn chunks_slice(&self) -> &[TgFeeFrac] {
        &self.chunks[..self.chunk_count as usize]
    }
}

#[repr(C)]
pub struct TgHandle {
    _private: [u8; 0],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Main = 0,
    Top = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagramOrd {
    Less,
    Equal,
    Greater,
    Incomparable,
}

extern "C" {
    fn tg_create(max_cluster_count: u32, max_cluster_size: u64, acceptable_cost: u64) -> *mut TgHandle;
    fn tg_destroy(h: *mut TgHandle);

    fn tg_add_tx(h: *mut TgHandle, slot: u32, fee: i64, size: i32, txid: u64) -> i32;
    fn tg_remove_tx(h: *mut TgHandle, slot: u32) -> i32;
    fn tg_destroy_ref(h: *mut TgHandle, slot: u32) -> i32;
    fn tg_move_ref(h: *mut TgHandle, from_slot: u32, to_slot: u32) -> i32;
    fn tg_add_dep(h: *mut TgHandle, parent_slot: u32, child_slot: u32) -> i32;
    fn tg_set_fee(h: *mut TgHandle, slot: u32, fee: i64) -> i32;

    fn tg_start_staging(h: *mut TgHandle);
    fn tg_abort_staging(h: *mut TgHandle);
    fn tg_commit_staging(h: *mut TgHandle);
    fn tg_have_staging(h: *mut TgHandle) -> i32;
    fn tg_do_work(h: *mut TgHandle, max_cost: u64) -> i32;
    fn tg_trim(h: *mut TgHandle, out_slots: *mut u32, cap: u32) -> u32;

    fn tg_is_oversized(h: *mut TgHandle, level: i32) -> i32;
    fn tg_exists(h: *mut TgHandle, slot: u32, level: i32) -> i32;
    fn tg_get_individual_feerate(h: *mut TgHandle, slot: u32) -> TgFeeFrac;
    fn tg_get_main_chunk_feerate(h: *mut TgHandle, slot: u32) -> TgFeeFrac;
    fn tg_get_tx_count(h: *mut TgHandle, level: i32) -> u32;
    fn tg_get_cluster(h: *mut TgHandle, slot: u32, level: i32, out_slots: *mut u32, cap: u32) -> u32;
    fn tg_get_ancestors(h: *mut TgHandle, slot: u32, level: i32, out_slots: *mut u32, cap: u32) -> u32;
    fn tg_get_descendants(h: *mut TgHandle, slot: u32, level: i32, out_slots: *mut u32, cap: u32) -> u32;
    fn tg_get_ancestors_union(h: *mut TgHandle, in_slots: *const u32, in_len: u32, level: i32, out_slots: *mut u32, cap: u32) -> u32;
    fn tg_get_descendants_union(h: *mut TgHandle, in_slots: *const u32, in_len: u32, level: i32, out_slots: *mut u32, cap: u32) -> u32;
    fn tg_compare_main_order(h: *mut TgHandle, slot_a: u32, slot_b: u32) -> i32;
    fn tg_count_distinct_clusters(h: *mut TgHandle, in_slots: *const u32, in_len: u32, level: i32) -> u32;
    fn tg_get_main_staging_diagrams(
        h: *mut TgHandle,
        out_main: *mut TgFeeFrac, main_cap: u32, out_main_len: *mut u32,
        out_staging: *mut TgFeeFrac, staging_cap: u32, out_staging_len: *mut u32,
    );
    fn tg_get_worst_main_chunk(h: *mut TgHandle, out_slots: *mut u32, cap: u32, out_feerate: *mut TgFeeFrac) -> u32;
    fn tg_get_main_memory_usage(h: *mut TgHandle) -> usize;
    fn tg_sanity_check(h: *mut TgHandle);

    fn tg_bb_open(h: *mut TgHandle) -> i32;
    fn tg_bb_close(h: *mut TgHandle, bb_id: i32);
    fn tg_bb_current(h: *mut TgHandle, bb_id: i32, out_slots: *mut u32, cap: u32, out_len: *mut u32, out_feerate: *mut TgFeeFrac) -> i32;
    fn tg_bb_include(h: *mut TgHandle, bb_id: i32);
    fn tg_bb_skip(h: *mut TgHandle, bb_id: i32);

    fn cl_linearize(
        n: u32, fees: *const i64, sizes: *const i32, parent_masks: *const u64,
        max_cost: u64, rng_seed: u64, old_lin: *const u32, old_lin_len: u32, is_topological: i32,
        out: *mut TgLinResult,
    );
    fn cl_postlinearize(
        n: u32, fees: *const i64, sizes: *const i32, parent_masks: *const u64,
        init_lin: *const u32, out: *mut TgLinResult,
    );
    fn cl_chunk_linearization(
        n: u32, fees: *const i64, sizes: *const i32, parent_masks: *const u64,
        lin: *const u32, out_chunk_count: *mut u32, out_chunks: *mut TgFeeFrac, out_all_connected: *mut i32,
    );
    fn cl_compare_chunks(a: *const TgFeeFrac, a_len: u32, b: *const TgFeeFrac, b_len: u32) -> i32;
    fn cl_exhaustive_linearize(
        n: u32, fees: *const i64, sizes: *const i32, parent_masks: *const u64,
        out: *mut TgLinResult,
    );
}

pub struct RealTxGraph {
    raw: *mut TgHandle,
}

impl RealTxGraph {
    pub fn new(max_cluster_count: u32, max_cluster_size: u64, acceptable_cost: u64) -> Self {
        let raw = unsafe { tg_create(max_cluster_count, max_cluster_size, acceptable_cost) };
        assert!(!raw.is_null());
        Self { raw }
    }

    pub fn add_tx(&mut self, slot: u32, fee: i64, size: i32, txid: u64) -> bool {
        unsafe { tg_add_tx(self.raw, slot, fee, size, txid) != 0 }
    }
    pub fn remove_tx(&mut self, slot: u32) {
        unsafe { tg_remove_tx(self.raw, slot); }
    }
    pub fn destroy_ref(&mut self, slot: u32) {
        unsafe { tg_destroy_ref(self.raw, slot); }
    }
    pub fn move_ref(&mut self, from: u32, to: u32) -> bool {
        unsafe { tg_move_ref(self.raw, from, to) != 0 }
    }
    pub fn add_dep(&mut self, parent: u32, child: u32) {
        unsafe { tg_add_dep(self.raw, parent, child); }
    }
    pub fn set_fee(&mut self, slot: u32, fee: i64) {
        unsafe { tg_set_fee(self.raw, slot, fee); }
    }
    pub fn start_staging(&mut self) {
        unsafe { tg_start_staging(self.raw); }
    }
    pub fn abort_staging(&mut self) {
        unsafe { tg_abort_staging(self.raw); }
    }
    pub fn commit_staging(&mut self) {
        unsafe { tg_commit_staging(self.raw); }
    }
    pub fn have_staging(&self) -> bool {
        unsafe { tg_have_staging(self.raw) != 0 }
    }
    pub fn do_work(&mut self, max_cost: u64) -> bool {
        unsafe { tg_do_work(self.raw, max_cost) != 0 }
    }
    pub fn trim(&mut self) -> Vec<u32> {
        let mut buf = vec![0u32; MAX_SLOTS];
        let n = unsafe { tg_trim(self.raw, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        buf.truncate(n.min(MAX_SLOTS));
        buf
    }
    pub fn is_oversized(&self, level: Level) -> bool {
        unsafe { tg_is_oversized(self.raw, level as i32) != 0 }
    }
    pub fn exists(&self, slot: u32, level: Level) -> bool {
        unsafe { tg_exists(self.raw, slot, level as i32) != 0 }
    }
    pub fn get_individual_feerate(&self, slot: u32) -> TgFeeFrac {
        unsafe { tg_get_individual_feerate(self.raw, slot) }
    }
    pub fn get_main_chunk_feerate(&self, slot: u32) -> TgFeeFrac {
        unsafe { tg_get_main_chunk_feerate(self.raw, slot) }
    }
    pub fn get_tx_count(&self, level: Level) -> u32 {
        unsafe { tg_get_tx_count(self.raw, level as i32) }
    }
    pub fn get_cluster(&self, slot: u32, level: Level) -> Vec<u32> {
        let mut buf = vec![0u32; MAX_SLOTS];
        let n = unsafe { tg_get_cluster(self.raw, slot, level as i32, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        buf.truncate(n.min(MAX_SLOTS));
        buf
    }
    pub fn get_ancestors(&self, slot: u32, level: Level) -> Vec<u32> {
        let mut buf = vec![0u32; MAX_SLOTS];
        let n = unsafe { tg_get_ancestors(self.raw, slot, level as i32, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        buf.truncate(n.min(MAX_SLOTS));
        buf
    }
    pub fn get_descendants(&self, slot: u32, level: Level) -> Vec<u32> {
        let mut buf = vec![0u32; MAX_SLOTS];
        let n = unsafe { tg_get_descendants(self.raw, slot, level as i32, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        buf.truncate(n.min(MAX_SLOTS));
        buf
    }
    pub fn get_ancestors_union(&self, slots: &[u32], level: Level) -> Vec<u32> {
        let mut buf = vec![0u32; MAX_SLOTS];
        let n = unsafe {
            tg_get_ancestors_union(self.raw, slots.as_ptr(), slots.len() as u32, level as i32, buf.as_mut_ptr(), buf.len() as u32)
        } as usize;
        buf.truncate(n.min(MAX_SLOTS));
        buf
    }
    pub fn get_descendants_union(&self, slots: &[u32], level: Level) -> Vec<u32> {
        let mut buf = vec![0u32; MAX_SLOTS];
        let n = unsafe {
            tg_get_descendants_union(self.raw, slots.as_ptr(), slots.len() as u32, level as i32, buf.as_mut_ptr(), buf.len() as u32)
        } as usize;
        buf.truncate(n.min(MAX_SLOTS));
        buf
    }
    pub fn compare_main_order(&self, a: u32, b: u32) -> Ordering {
        match unsafe { tg_compare_main_order(self.raw, a, b) } {
            x if x < 0 => Ordering::Less,
            x if x > 0 => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }
    pub fn count_distinct_clusters(&self, slots: &[u32], level: Level) -> u32 {
        unsafe { tg_count_distinct_clusters(self.raw, slots.as_ptr(), slots.len() as u32, level as i32) }
    }
    pub fn get_main_staging_diagrams(&self) -> (Vec<TgFeeFrac>, Vec<TgFeeFrac>) {
        let mut m = vec![TgFeeFrac::default(); MAX_SLOTS];
        let mut s = vec![TgFeeFrac::default(); MAX_SLOTS];
        let mut ml = 0u32;
        let mut sl = 0u32;
        unsafe {
            tg_get_main_staging_diagrams(
                self.raw,
                m.as_mut_ptr(), m.len() as u32, &mut ml,
                s.as_mut_ptr(), s.len() as u32, &mut sl,
            );
        }
        m.truncate(ml as usize);
        s.truncate(sl as usize);
        (m, s)
    }
    pub fn get_worst_main_chunk(&self) -> (Vec<u32>, TgFeeFrac) {
        let mut buf = vec![0u32; MAX_SLOTS];
        let mut rate = TgFeeFrac::default();
        let n = unsafe { tg_get_worst_main_chunk(self.raw, buf.as_mut_ptr(), buf.len() as u32, &mut rate) } as usize;
        buf.truncate(n.min(MAX_SLOTS));
        (buf, rate)
    }
    pub fn get_main_memory_usage(&self) -> usize {
        unsafe { tg_get_main_memory_usage(self.raw) }
    }
    pub fn sanity_check(&self) {
        unsafe { tg_sanity_check(self.raw); }
    }
    pub fn bb_open(&mut self) -> Option<i32> {
        let id = unsafe { tg_bb_open(self.raw) };
        if id >= 0 { Some(id) } else { None }
    }
    pub fn bb_close(&mut self, id: i32) {
        unsafe { tg_bb_close(self.raw, id); }
    }
    pub fn bb_current(&mut self, id: i32) -> Option<(Vec<u32>, TgFeeFrac)> {
        let mut buf = vec![0u32; MAX_SLOTS];
        let mut len = 0u32;
        let mut rate = TgFeeFrac::default();
        let ok = unsafe { tg_bb_current(self.raw, id, buf.as_mut_ptr(), buf.len() as u32, &mut len, &mut rate) };
        if ok != 0 {
            buf.truncate(len as usize);
            Some((buf, rate))
        } else {
            None
        }
    }
    pub fn bb_include(&mut self, id: i32) {
        unsafe { tg_bb_include(self.raw, id); }
    }
    pub fn bb_skip(&mut self, id: i32) {
        unsafe { tg_bb_skip(self.raw, id); }
    }
}

impl Drop for RealTxGraph {
    fn drop(&mut self) {
        unsafe { tg_destroy(self.raw); }
    }
}

pub fn linearize(
    fees: &[i64],
    sizes: &[i32],
    parent_masks: &[u64],
    max_cost: u64,
    rng_seed: u64,
    old_lin: Option<&[u32]>,
    is_topological: bool,
) -> TgLinResult {
    let n = fees.len();
    assert_eq!(n, sizes.len());
    assert_eq!(n, parent_masks.len());
    assert!(n <= 64);
    let mut out = TgLinResult::default();
    let (ptr, len) = match old_lin {
        Some(s) => (s.as_ptr(), s.len() as u32),
        None => (std::ptr::null(), 0),
    };
    unsafe {
        cl_linearize(
            n as u32, fees.as_ptr(), sizes.as_ptr(), parent_masks.as_ptr(),
            max_cost, rng_seed, ptr, len, if is_topological { 1 } else { 0 }, &mut out,
        );
    }
    out
}

pub fn postlinearize(fees: &[i64], sizes: &[i32], parent_masks: &[u64], init_lin: &[u32]) -> TgLinResult {
    let n = fees.len();
    assert_eq!(n, sizes.len());
    assert_eq!(n, parent_masks.len());
    assert_eq!(n, init_lin.len());
    let mut out = TgLinResult::default();
    unsafe {
        cl_postlinearize(n as u32, fees.as_ptr(), sizes.as_ptr(), parent_masks.as_ptr(), init_lin.as_ptr(), &mut out);
    }
    out
}

pub fn chunk_linearization(fees: &[i64], sizes: &[i32], parent_masks: &[u64], lin: &[u32]) -> (Vec<TgFeeFrac>, bool) {
    let n = fees.len();
    let mut count = 0u32;
    let mut chunks = [TgFeeFrac::default(); 64];
    let mut all_conn = 0i32;
    unsafe {
        cl_chunk_linearization(
            n as u32, fees.as_ptr(), sizes.as_ptr(), parent_masks.as_ptr(),
            lin.as_ptr(), &mut count, chunks.as_mut_ptr(), &mut all_conn,
        );
    }
    (chunks[..count as usize].to_vec(), all_conn != 0)
}

pub fn compare_chunks(a: &[TgFeeFrac], b: &[TgFeeFrac]) -> DiagramOrd {
    match unsafe { cl_compare_chunks(a.as_ptr(), a.len() as u32, b.as_ptr(), b.len() as u32) } {
        -1 => DiagramOrd::Less,
        0 => DiagramOrd::Equal,
        1 => DiagramOrd::Greater,
        _ => DiagramOrd::Incomparable,
    }
}

pub fn exhaustive_linearize(fees: &[i64], sizes: &[i32], parent_masks: &[u64]) -> TgLinResult {
    let n = fees.len();
    assert!(n <= 10);
    let mut out = TgLinResult::default();
    unsafe {
        cl_exhaustive_linearize(n as u32, fees.as_ptr(), sizes.as_ptr(), parent_masks.as_ptr(), &mut out);
    }
    out
}
