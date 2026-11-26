use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bitcoin_dir = manifest_dir
        .join("../../../../bitcoin")
        .canonicalize()
        .expect("expected ../bitcoin sibling checkout");
    let cov_build = bitcoin_dir.join("build_ephyra_cov");
    assert!(
        cov_build.exists(),
        "expected coverage build at {}",
        cov_build.display()
    );

    let cpp_cov = env::var("CARGO_FEATURE_CPP_COV").is_ok();

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .compiler("clang++-20")
        .std("c++20")
        .opt_level(2)
        .debug(true)
        .flag("-DABORT_ON_FAILED_ASSUME")
        .flag("-Wno-unused-parameter")
        .include(bitcoin_dir.join("src"))
        .include(cov_build.join("src"))
        .file(manifest_dir.join("cpp/txgraph_shim.cpp"));

    if cpp_cov {
        // Instrument Bitcoin Core's txgraph.cpp directly (and cluster_linearize.h inside it + shim),
        // keeping Rust uninstrumented so ephyra::coverage tracks C++ counters.
        build
            .flag("-fprofile-instr-generate")
            .flag("-fcoverage-mapping")
            .file(bitcoin_dir.join("src/txgraph.cpp"));
    } else {
        build.file(bitcoin_dir.join("src/txgraph.cpp"));
    }

    build.compile("txgraph_shim");

    // Link minimal Bitcoin Core util + crypto + clientversion libs needed by txgraph.cpp.
    println!("cargo:rustc-link-search=native={}", cov_build.join("lib").display());
    println!("cargo:rustc-link-lib=static=bitcoin_util");
    println!("cargo:rustc-link-lib=static=bitcoin_crypto");
    println!("cargo:rustc-link-lib=static=bitcoin_clientversion");
    println!("cargo:rustc-link-lib=stdc++");

    if cpp_cov {
        // Link clang-20 profile runtime for in-process LLVM coverage reading.
        println!("cargo:rustc-link-arg=-fprofile-instr-generate");
        println!("cargo:rustc-link-arg=-Wl,-u,atexit");
    } else {
        // Even without cpp-cov, build_ephyra_cov's libbitcoin_util.a was compiled with -fprofile-instr-generate.
        println!("cargo:rustc-link-arg=-fprofile-instr-generate");
        println!("cargo:rustc-link-arg=-Wl,-u,atexit");
    }

    println!("cargo:rerun-if-changed=cpp/txgraph_shim.h");
    println!("cargo:rerun-if-changed=cpp/txgraph_shim.cpp");
    println!("cargo:rerun-if-changed=build.rs");
}
