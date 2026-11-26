#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BITCOIN="$(cd "$DIR/../../../../bitcoin" && pwd)"
OUT="$DIR/target/workers"
mkdir -p "$OUT"

build_one() {
    local mode="$1"
    local bdir="$2"
    shift 2
    local extra_flags=("$@")

    echo "Building cluster_worker_${mode} against ${bdir}..."
    clang++-20 -std=c++20 -O2 -g \
        -DABORT_ON_FAILED_ASSUME \
        -Wno-unused-parameter -Wno-unused-function \
        "${extra_flags[@]}" \
        -I"$BITCOIN/src" \
        -I"$bdir/src" \
        "$DIR/cpp/mempool_worker.cpp" \
        -Wl,--start-group \
        "$bdir/lib/libtest_util.a" \
        "$bdir/lib/libbitcoin_node.a" \
        "$bdir/lib/libbitcoin_common.a" \
        "$bdir/lib/libbitcoin_consensus.a" \
        "$bdir/lib/libbitcoin_util.a" \
        "$bdir/lib/libbitcoin_crypto.a" \
        "$bdir/lib/libbitcoin_clientversion.a" \
        "$bdir/src/libminisketch.a" \
        "$bdir/src/secp256k1/lib/libsecp256k1.a" \
        "$bdir/src/libleveldb.a" \
        "$bdir/src/libcrc32c.a" \
        "$bdir/src/univalue/libunivalue.a" \
        -Wl,--end-group \
        -lpthread -ldl \
        -o "$OUT/cluster_worker_${mode}"
    echo "Built $OUT/cluster_worker_${mode}"
}

build_one san "$BITCOIN/build_ephyra_san" -fsanitize=address,undefined -fno-omit-frame-pointer
build_one cov "$BITCOIN/build_ephyra_cov" -fprofile-instr-generate -fcoverage-mapping
