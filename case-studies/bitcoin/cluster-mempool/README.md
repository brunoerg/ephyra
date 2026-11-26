# Ephyra Case Study: Bitcoin Core Cluster Mempool & `TxGraph`

Property-based, model-based, and coverage-guided testing of Bitcoin Core's Cluster Mempool using **Ephyra**, with Clang-20 LLVM coverage feedback and Clang-20 AddressSanitizer + UndefinedBehaviorSanitizer + `-DABORT_ON_FAILED_ASSUME`.

## Architecture

Two complementary tiers cover both algorithmic/graph invariants at high speed and full-stack mempool/policy/miner interactions under sanitizers:

- **Tier 1 (In-process FFI + Live C++ LLVM Coverage)**:
  - `cpp/txgraph_shim.{h,cpp}` linked directly against `../bitcoin/build_ephyra_cov` (`-fprofile-instr-generate -fcoverage-mapping -DABORT_ON_FAILED_ASSUME`), with `ephyra/coverage` + `ephyra/coverage-force` feeding C++ `__llvm_prf_cnts` live to Ephyra.
  - Covers `src/txgraph.cpp` and `src/cluster_linearize.h`.
- **Tier 2 (Crash-Isolated Sanitizer & Coverage Worker Subprocess)**:
  - `cpp/mempool_worker.cpp` compiled into `target/workers/cluster_worker_san` (`-fsanitize=address,undefined -DABORT_ON_FAILED_ASSUME`) and `target/workers/cluster_worker_cov` (`-fprofile-instr-generate -fcoverage-mapping -DABORT_ON_FAILED_ASSUME`).
  - Select worker mode via `CLUSTER_WORKER_MODE=san|cov` (defaults to `san`).
  - Covers `CTxMemPool`, `AcceptToMemoryPool`, `ProcessNewPackage`, `PrioritiseTransaction`, `TrimToSize`, `Expire`, `BlockAssembler::CreateNewBlock`, `removeForBlock` + reorg `UpdateTransactionsFromBlock`, `MiniMiner` (`CalculateBumpFees`, `CalculateTotalBumpFees`, `BuildMockTemplate`, `Linearize`), `ExtractBestByMiningScoreWithTopology`, `DumpMempool`/`LoadMempool`, and `policy/{rbf,truc_policy,ephemeral_policy,packages}.cpp`.

## Prerequisites (Bitcoin Core Sibling Checkout)

Expects a Bitcoin Core checkout at `../../../../bitcoin` (relative to this crate) with two Clang-20 library builds:

```bash
# 1. Coverage build (required for Tier 1 FFI and Tier 2 coverage worker)
cmake -S ../bitcoin -B ../bitcoin/build_ephyra_cov -G Ninja \
  -DCMAKE_C_COMPILER=clang-20 -DCMAKE_CXX_COMPILER=clang++-20 \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping -DABORT_ON_FAILED_ASSUME" \
  -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping -DABORT_ON_FAILED_ASSUME" \
  -DENABLE_WALLET=OFF -DBUILD_GUI=OFF -DBUILD_CLI=OFF -DBUILD_DAEMON=OFF -DENABLE_IPC=OFF -DBUILD_TESTS=ON
cmake --build ../bitcoin/build_ephyra_cov --target \
  bitcoin_node bitcoin_common bitcoin_consensus bitcoin_crypto bitcoin_util bitcoin_clientversion \
  test_util minisketch secp256k1 leveldb crc32c univalue

# 2. Sanitizer build (required for Tier 2 ASan+UBSan worker)
cmake -S ../bitcoin -B ../bitcoin/build_ephyra_san -G Ninja \
  -DCMAKE_C_COMPILER=clang-20 -DCMAKE_CXX_COMPILER=clang++-20 \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DSANITIZERS=address,undefined \
  -DCMAKE_C_FLAGS="-ftrivial-auto-var-init=pattern -DABORT_ON_FAILED_ASSUME" \
  -DCMAKE_CXX_FLAGS="-ftrivial-auto-var-init=pattern -DABORT_ON_FAILED_ASSUME" \
  -DENABLE_WALLET=OFF -DBUILD_GUI=OFF -DBUILD_CLI=OFF -DBUILD_DAEMON=OFF -DENABLE_IPC=OFF -DBUILD_TESTS=ON
cmake --build ../bitcoin/build_ephyra_san --target \
  bitcoin_node bitcoin_common bitcoin_consensus bitcoin_crypto bitcoin_util bitcoin_clientversion \
  test_util minisketch secp256k1 leveldb crc32c univalue

# 3. Build the Tier 2 worker binaries
bash scripts/build_workers.sh
```

## Property Test Suite

| Test Target | Property | Tier / Mode |
| --- | --- | --- |
| `tests/txgraph_model.rs` | `txgraph_matches_model` (stateful reference model vs `TxGraph`) | Tier 1 FFI + LLVM cov |
| `tests/txgraph_meta.rs` | `staging_abort_and_diagrams` (abort invariance + diagram laws) | Tier 1 FFI + LLVM cov |
| `tests/txgraph_meta.rs` | `staging_commit_matches_direct` (commit equivalence to direct execution) | Tier 1 FFI + LLVM cov |
| `tests/cluster_lin.rs` | `linearize_small_matches_exhaustive` (SFL vs exact DP ≤ 12 txs) | Tier 1 FFI + LLVM cov |
| `tests/cluster_lin.rs` | `linearize_and_postlinearize_laws` (up to 64 txs, optimality & monotonicity) | Tier 1 FFI + LLVM cov |
| `tests/mempool_cluster.rs` | `mempool_cluster_stateful` (full stack: RBF, TRUC, ephemeral dust, reorg, dump/load, miner) | Tier 2 ASan+UBSan+Assume |
| `tests/mini_miner_prop.rs` | `miniminer_bump_fees_and_linearize_invariants` (`CalculateBumpFees`, `Linearize`, `BuildMockTemplate`) | Tier 2 ASan+UBSan+Assume |

## Coverage Highlights

- **Tier 1 (`txgraph.cpp` + `cluster_linearize.h` in-process LLVM counters)**: `915 / 967` (**94.6%**) counters reached.
- **Tier 2 (`cluster_worker_cov`, `llvm-cov-20` across 10 Bitcoin Core files, 4,730 lines)**: **85.41% lines**, **72.16% branches**, **88.86% functions**:
  - `policy/ephemeral_policy.cpp`: 96.15% lines / 96.88% branches / 100.00% funcs
  - `cluster_linearize.h`: 95.34% lines / 89.34% branches / 100.00% funcs
  - `policy/truc_policy.cpp`: 90.56% lines / 89.02% branches / 100.00% funcs
  - `policy/rbf.cpp`: 89.86% lines / 92.31% branches / 100.00% funcs
  - `node/mini_miner.cpp`: 86.42% lines / 80.91% branches / 91.67% funcs
  - `txmempool.cpp`: 82.90% lines / 68.28% branches / 85.51% funcs
  - `txgraph.cpp`: 82.88% lines / 65.95% branches / 86.19% funcs
  - `node/mempool_persist.cpp`: 80.92% lines / 66.00% branches / 100.00% funcs
  - `node/miner.cpp`: 79.17% lines / 60.00% branches / 83.33% funcs
  - `policy/packages.cpp`: 75.44% lines / 73.68% branches / 70.59% funcs

## Running

```bash
cd case-studies/bitcoin/cluster-mempool

# Verify all 5 generators
../../../target/release/ephyra check --no-instrument --tests 1000

# Run Tier 1 (in-process TxGraph & cluster_linearize properties)
cargo test --release --test txgraph_model --test txgraph_meta --test cluster_lin

# Run Tier 2 (crash-isolated ASan+UBSan+Assume worker)
cargo test --release --test mempool_cluster --test mini_miner_prop -- --test-threads=1

# Run Tier 1 C++ coverage report
cargo run --release --features cpp-cov --bin cov_report -- 5000
```
