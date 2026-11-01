//! A loop to profile under perf: `prof rust|c|rust-hmac|c-hmac BATCH SECONDS` verifies (or only HMACs) the
//! benchmark's 16 tokens in batches of BATCH for SECONDS and prints ns per token.
use cursed_jwt::{Engine, Error, Hs256Key, Verdict};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::hint::black_box;
use std::time::{Duration, Instant};

const SECRET: &[u8] = b"cursed-jwt-test-secret";

fn b64u(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let v = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..c.len() + 1 {
            s.push(A[(v >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a.get(1).map(String::as_str).unwrap_or("rust");
    let n: usize = a.get(2).and_then(|v| v.parse().ok()).unwrap_or(8);
    let secs: f64 = a.get(3).and_then(|v| v.parse().ok()).unwrap_or(3.0);
    let head = b64u(br#"{"alg":"HS256","typ":"JWT"}"#);
    let toks: Vec<Vec<u8>> = (1..=n)
        .map(|i| {
            let pl = format!(r#"{{"sub":"{i}","username":"user_{i}","iat":1792832174,"exp":2108192174}}"#);
            let msg = format!("{head}.{}", b64u(pl.as_bytes()));
            let mut m = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
            m.update(msg.as_bytes());
            format!("{msg}.{}", b64u(&m.finalize().into_bytes())).into_bytes()
        })
        .collect();
    let msgs: Vec<&[u8]> = toks.iter().map(|t| &t[..t.iter().rposition(|&b| b == b'.').unwrap()]).collect();
    let k = Hs256Key::new(SECRET);
    let ck = cjwt_sys::Key::new(SECRET);
    let (p, l) = cjwt_sys::token_ptrs(&toks);
    let mut out: Vec<Verdict> = vec![Err(Error::Invalid); n];
    let mut cout = cjwt_sys::results(n);
    let mut tags = vec![[0u8; 32]; n];
    let e = Engine::best();
    let start = Instant::now();
    let mut iters = 0u64;
    while start.elapsed() < Duration::from_secs_f64(secs) {
        for _ in 0..1000 {
            match mode {
                "c" => ck.verify_raw(black_box(&p), &l, 1_800_000_000, &mut cout),
                "rust-hmac" => k.hmac_batch(e, black_box(&msgs), &mut tags),
                _ => k.verify_batch(black_box(&toks), 1_800_000_000, &mut out),
            }
        }
        iters += 1000;
    }
    let ns = start.elapsed().as_nanos() as f64 / (iters as f64 * n as f64);
    println!("{mode} batch {n} engine {}: {ns:.1} ns/token", e.name());
}
