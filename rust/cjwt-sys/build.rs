//! Compiles the C library from the repository root (../../src) the way its Makefile's default build does:
//! -O3, no -march, run-time dispatch, and on x86-64 Linux OpenSSL's extracted SHA-256 block function for batch 1.
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let src = root.join("src");
    for f in [
        "jwt.c",
        "jwt_mb.inc",
        "jwt_pk.inc",
        "jwt_pk_ec.inc",
        "jwt_ed25519.inc",
        "sha256_x86_64_ossl.S",
    ] {
        println!("cargo:rerun-if-changed={}", src.join(f).display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        root.join("include/jwt.h").display()
    );
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let ossl = arch == "x86_64" && os == "linux";
    let mut b = cc::Build::new();
    b.file(src.join("jwt.c"))
        .include(root.join("include"))
        .opt_level(3)
        .flag_if_supported("-Wno-deprecated-declarations")
        .flag_if_supported("-Wno-unused-function")
        .warnings(false);
    if ossl {
        b.define("JWT_OSSL_SHA256", None)
            .file(src.join("sha256_x86_64_ossl.S"));
    }
    b.compile("cursedjwt");
}
