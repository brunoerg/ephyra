#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TgHandle TgHandle;

typedef struct TgFeeFrac {
    int64_t fee;
    int32_t size;
} TgFeeFrac;

typedef struct TgLinResult {
    uint32_t count;
    uint32_t order[64];
    int32_t optimal;
    uint64_t cost;
    uint32_t chunk_count;
    TgFeeFrac chunks[64];
} TgLinResult;

// Lifecycle
TgHandle* tg_create(uint32_t max_cluster_count, uint64_t max_cluster_size, uint64_t acceptable_cost);
void tg_destroy(TgHandle* h);

// Mutators (tx_slot is a caller-chosen slot index 0..MAX_SLOTS-1; txid is fallback order key)
// Returns 1 on success, 0 if invalid slot.
int32_t tg_add_tx(TgHandle* h, uint32_t slot, int64_t fee, int32_t size, uint64_t txid);
int32_t tg_remove_tx(TgHandle* h, uint32_t slot);
int32_t tg_destroy_ref(TgHandle* h, uint32_t slot);
int32_t tg_move_ref(TgHandle* h, uint32_t from_slot, uint32_t to_slot);
int32_t tg_add_dep(TgHandle* h, uint32_t parent_slot, uint32_t child_slot);
int32_t tg_set_fee(TgHandle* h, uint32_t slot, int64_t fee);

// Staging & work
void tg_start_staging(TgHandle* h);
void tg_abort_staging(TgHandle* h);
void tg_commit_staging(TgHandle* h);
int32_t tg_have_staging(TgHandle* h);
int32_t tg_do_work(TgHandle* h, uint64_t max_cost);
// Writes removed slot IDs to out_slots (capacity cap), returns count.
uint32_t tg_trim(TgHandle* h, uint32_t* out_slots, uint32_t cap);

// Queries (level: 0 = MAIN, 1 = TOP)
int32_t tg_is_oversized(TgHandle* h, int32_t level);
int32_t tg_exists(TgHandle* h, uint32_t slot, int32_t level);
TgFeeFrac tg_get_individual_feerate(TgHandle* h, uint32_t slot);
TgFeeFrac tg_get_main_chunk_feerate(TgHandle* h, uint32_t slot);
uint32_t tg_get_tx_count(TgHandle* h, int32_t level);
uint32_t tg_get_cluster(TgHandle* h, uint32_t slot, int32_t level, uint32_t* out_slots, uint32_t cap);
uint32_t tg_get_ancestors(TgHandle* h, uint32_t slot, int32_t level, uint32_t* out_slots, uint32_t cap);
uint32_t tg_get_descendants(TgHandle* h, uint32_t slot, int32_t level, uint32_t* out_slots, uint32_t cap);
uint32_t tg_get_ancestors_union(TgHandle* h, const uint32_t* in_slots, uint32_t in_len, int32_t level, uint32_t* out_slots, uint32_t cap);
uint32_t tg_get_descendants_union(TgHandle* h, const uint32_t* in_slots, uint32_t in_len, int32_t level, uint32_t* out_slots, uint32_t cap);
int32_t tg_compare_main_order(TgHandle* h, uint32_t slot_a, uint32_t slot_b);
uint32_t tg_count_distinct_clusters(TgHandle* h, const uint32_t* in_slots, uint32_t in_len, int32_t level);
// Returns chunk counts in *out_main_len and *out_staging_len.
void tg_get_main_staging_diagrams(
    TgHandle* h,
    TgFeeFrac* out_main, uint32_t main_cap, uint32_t* out_main_len,
    TgFeeFrac* out_staging, uint32_t staging_cap, uint32_t* out_staging_len
);
uint32_t tg_get_worst_main_chunk(TgHandle* h, uint32_t* out_slots, uint32_t cap, TgFeeFrac* out_feerate);
size_t tg_get_main_memory_usage(TgHandle* h);
void tg_sanity_check(TgHandle* h);

// BlockBuilder (supports up to 4 concurrent builders per handle, id 0..3)
int32_t tg_bb_open(TgHandle* h);
void tg_bb_close(TgHandle* h, int32_t bb_id);
// Returns 1 if chunk available, 0 if exhausted.
int32_t tg_bb_current(TgHandle* h, int32_t bb_id, uint32_t* out_slots, uint32_t cap, uint32_t* out_len, TgFeeFrac* out_feerate);
void tg_bb_include(TgHandle* h, int32_t bb_id);
void tg_bb_skip(TgHandle* h, int32_t bb_id);

// cluster_linearize direct API
// deps_mask[i] is bitmask of direct parents of node i (must be acyclic; j < i or DAG).
void cl_linearize(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks,
    uint64_t max_cost,
    uint64_t rng_seed,
    const uint32_t* old_lin,
    uint32_t old_lin_len,
    int32_t is_topological,
    TgLinResult* out
);

void cl_postlinearize(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks,
    const uint32_t* init_lin,
    TgLinResult* out
);

void cl_chunk_linearization(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks,
    const uint32_t* lin,
    uint32_t* out_chunk_count,
    TgFeeFrac* out_chunks,
    int32_t* out_all_connected
);

// Compare two chunk diagrams: returns -1 (<), 0 (==), 1 (>), 2 (incomparable).
int32_t cl_compare_chunks(
    const TgFeeFrac* a, uint32_t a_len,
    const TgFeeFrac* b, uint32_t b_len
);

// Exhaustive exact optimal linearization for small clusters (n <= 10).
void cl_exhaustive_linearize(
    uint32_t n,
    const int64_t* fees,
    const int32_t* sizes,
    const uint64_t* parent_masks,
    TgLinResult* out
);

#ifdef __cplusplus
}
#endif
