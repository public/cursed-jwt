//! Shared test helpers: an independent HS256 minter (the `hmac` + `sha2` crates), base64url encoding, a small
//! deterministic PRNG, and the vector files the C test suite generates.
#![allow(dead_code)]

use cursed_jwt::{Engine, Verdict};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::PathBuf;

pub const SECRET: &[u8] = b"cursed-jwt-test-secret";

/// xorshift64*: deterministic, no dependency.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    /// Random bytes of a random length below `n`.
    pub fn rbytes(&mut self, n: usize) -> Vec<u8> {
        let l = self.below(n);
        self.bytes(l)
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

pub fn b64u(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let v = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        let n = c.len() + 1;
        for i in 0..n {
            s.push(A[(v >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

pub fn hmac_ref(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// A signed token from raw header and payload bytes.
pub fn sign_with(header: &[u8], payload: &[u8], key: &[u8]) -> Vec<u8> {
    let msg = format!("{}.{}", b64u(header), b64u(payload));
    let sig = b64u(&hmac_ref(key, msg.as_bytes()));
    format!("{msg}.{sig}").into_bytes()
}

pub fn sign(payload: &[u8]) -> Vec<u8> {
    sign_with(br#"{"alg":"HS256","typ":"JWT"}"#, payload, SECRET)
}

/// Every engine this CPU can run.
pub fn engines() -> Vec<Engine> {
    Engine::ALL
        .iter()
        .copied()
        .filter(|e| e.is_available())
        .collect()
}

/// `~` stands for a backslash (keeps JSON escapes readable in the test source).
pub fn j(s: &str) -> Vec<u8> {
    s.replace('~', "\\").into_bytes()
}

/// (status, uid, username, escape) in the C library's terms: 0 OK, 1 INVALID, 2 BAD_PAYLOAD.
pub fn flat(v: &Verdict) -> (u8, i64, Vec<u8>, bool) {
    match v {
        Ok(c) => (
            0,
            c.uid(),
            c.username_bytes().to_vec(),
            c.username_needs_escape(),
        ),
        Err(cursed_jwt::Error::Invalid) => (1, 0, vec![], false),
        Err(cursed_jwt::Error::BadPayload) => (2, 0, vec![], false),
    }
}

pub fn flat_c(r: &cjwt_sys::CResult) -> (u8, i64, Vec<u8>, bool) {
    if r.status == 0 {
        (0, r.uid, r.username.clone(), r.escape)
    } else {
        (r.status, 0, vec![], false)
    }
}

pub fn unhex(h: &str) -> Vec<u8> {
    if h == "-" {
        return vec![];
    }
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// A vector file the C suite builds (`make build/hmac_vectors.txt build/pk_vectors.txt build/tokens.json`), looked
/// for in `$CURSED_JWT_VECTORS` and then in the repository's `build/`.  `None` (the test is skipped) when absent,
/// unless `CURSED_JWT_REQUIRE_VECTORS` is set.
pub fn vector_file(name: &str) -> Option<PathBuf> {
    let dirs = [
        std::env::var("CURSED_JWT_VECTORS").ok().map(PathBuf::from),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build")),
    ];
    for d in dirs.into_iter().flatten() {
        let p = d.join(name);
        if p.exists() {
            return Some(p);
        }
    }
    if std::env::var("CURSED_JWT_REQUIRE_VECTORS").is_ok() {
        panic!("{name} not found (run `make build/{name}` at the repository root)");
    }
    eprintln!("{name}: not found, skipped (run `make build/{name}` at the repository root)");
    None
}

/// Iterations: `CURSED_JWT_TEST_N` overrides the quick default.
pub fn iters(quick: usize) -> usize {
    std::env::var("CURSED_JWT_TEST_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(quick)
}
