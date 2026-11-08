//! HS256 full verify (split, header, signature decode, HMAC, payload base64url, JSON, claims), Rust and the C
//! library in the same process, at batch 1 / 3 / 8 / 16; and the raw HMAC of each Rust engine.
//!
//! Tokens are the shape tests/gen_tokens.py mints (~140-byte signing inputs: 3 inner SHA-256 blocks + 1
//! outer).  `cargo bench --bench hs256 -- --quick` for a short run.
#![allow(missing_docs)]
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use cursed_jwt::{Engine, Error, Hs256Key, Verdict};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::hint::black_box;

const SECRET: &[u8] = b"cursed-jwt-test-secret";
const NOW: i64 = 1_800_000_000;
const ADJ: [&str; 10] = [
    "golden", "silver", "swift", "quiet", "amber", "crimson", "lunar", "rapid", "misty", "brave",
];
const NOUN: [&str; 10] = [
    "ember", "comet", "nebula", "harbor", "falcon", "meadow", "quartz", "willow", "tundra", "orbit",
];

fn b64u(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let v = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..c.len() + 1 {
            s.push(A[(v >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

pub fn tokens(n: usize) -> Vec<Vec<u8>> {
    let head = b64u(br#"{"alg":"HS256","typ":"JWT"}"#);
    (1..=n)
        .map(|i| {
            let name = format!("{}_{}_{i}", ADJ[i % 10], NOUN[(i / 10) % 10]);
            let pl =
                format!(r#"{{"sub":"{i}","username":"{name}","iat":1792832174,"exp":2108192174}}"#);
            let msg = format!("{head}.{}", b64u(pl.as_bytes()));
            let mut m = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
            m.update(msg.as_bytes());
            format!("{msg}.{}", b64u(&m.finalize().into_bytes())).into_bytes()
        })
        .collect()
}

fn full(c: &mut Criterion) {
    let toks = tokens(16);
    let k = Hs256Key::new(SECRET);
    let ck = cjwt_sys::Key::new(SECRET);
    let mut g = c.benchmark_group("hs256_verify");
    eprintln!(
        "rust engine {}, C engine {}",
        Engine::best().name(),
        cjwt_sys::engine()
    );
    for n in [1usize, 3, 8, 16] {
        let t = &toks[..n];
        g.throughput(Throughput::Elements(n as u64));
        let mut out: Vec<Verdict> = vec![Err(Error::Invalid); n];
        g.bench_with_input(BenchmarkId::new("rust", n), &n, |b, _| {
            b.iter(|| {
                k.verify_batch(black_box(t), NOW, &mut out);
                assert!(out[n - 1].is_ok());
            })
        });
        let (p, l) = cjwt_sys::token_ptrs(t);
        let mut cout = cjwt_sys::results(n);
        g.bench_with_input(BenchmarkId::new("c", n), &n, |b, _| {
            b.iter(|| {
                ck.verify_raw(black_box(&p), &l, NOW, &mut cout);
                assert!(cout[n - 1].status == 0);
            })
        });
    }
    g.finish();
}

fn hmac_engines(c: &mut Criterion) {
    let toks = tokens(16);
    let msgs: Vec<&[u8]> = toks
        .iter()
        .map(|t| &t[..t.iter().rposition(|&b| b == b'.').unwrap()])
        .collect();
    let k = Hs256Key::new(SECRET);
    let mut g = c.benchmark_group("hs256_hmac");
    let ck = cjwt_sys::Key::new(SECRET);
    let p: Vec<*const u8> = msgs.iter().map(|m| m.as_ptr()).collect();
    let l: Vec<i32> = msgs.iter().map(|m| m.len() as i32).collect();
    for (name, f) in cjwt_sys::hmac_engines() {
        for n in [1usize, 8, 16] {
            g.throughput(Throughput::Elements(n as u64));
            let mut mac = vec![[0u32; 8]; n];
            g.bench_with_input(BenchmarkId::new(format!("c-{name}"), n), &n, |b, _| {
                b.iter(|| ck.hmac_raw(f, black_box(&p[..n]), &l[..n], &mut mac))
            });
        }
    }
    for e in Engine::ALL.into_iter().filter(|e| e.is_available()) {
        for n in [1usize, 8, 16] {
            g.throughput(Throughput::Elements(n as u64));
            let mut tags = vec![[0u8; 32]; n];
            g.bench_with_input(BenchmarkId::new(e.name(), n), &n, |b, _| {
                b.iter(|| k.hmac_batch(e, black_box(&msgs[..n]), &mut tags))
            });
        }
    }
    g.finish();
}

criterion_group!(benches, full, hmac_engines);
criterion_main!(benches);
