//! On x86-64 Linux with the `asm` feature: assemble OpenSSL's extracted SHA-256 block function (the C library's
//! `src/sha256_x86_64_ossl.S`, symbols renamed so both libraries can link into one program) for single messages,
//! where it beats compiled code by ~30% on a Cascade Lake.  Everything else is Rust.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(cjwt_ossl)");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if std::env::var_os("CARGO_FEATURE_ASM").is_none() || arch != "x86_64" || os != "linux" {
        return;
    }
    println!("cargo:rerun-if-changed=asm/sha256_x86_64_ossl.S");
    println!("cargo:rerun-if-changed=asm/ossl_cap.c");
    #[cfg(feature = "asm")]
    {
        cc::Build::new()
            .file("asm/sha256_x86_64_ossl.S")
            .file("asm/ossl_cap.c")
            .define("jwt_ossl_sha256_block", "cjwt_rs_sha256_block")
            .define("jwt_ossl_ia32cap_P", "cjwt_rs_ia32cap_P")
            .opt_level(2)
            .compile("cjwt_ossl");
        println!("cargo:rustc-cfg=cjwt_ossl");
    }
}
