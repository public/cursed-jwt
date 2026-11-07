//! RS256 / ES256 / EdDSA: full token verify, Rust and the C library in the same process, with small claims
//! (the 4-claim shape) and realistic ones (~400 bytes of typical claims), at batch 1 and 16; and raw signature
//! verification of the Rust port against the `p256`, `ed25519-dalek` and `rsa` crates.
#![allow(missing_docs, clippy::type_complexity)]
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use cursed_jwt::{Ed25519Key, Error, Es256Key, Rs256Key, Verdict};
use rand::SeedableRng;
use std::hint::black_box;

const NOW: i64 = 1_800_000_000;

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

fn payload(i: usize, realistic: bool) -> String {
    if !realistic {
        return format!(
            r#"{{"sub":"{i}","username":"user_{i}","iat":1792832174,"exp":2108192174}}"#
        );
    }
    format!(
        r#"{{"iss":"https://auth.example.com/","aud":["api.example.com","https://example.com/userinfo"],"sub":"{i}","username":"user_{i}","email":"user_{i}@example.com","email_verified":true,"name":"Example User {i}","roles":["reader","writer"],"scope":"openid profile email offline_access","jti":"6f1c2b0e-3a7d-4b6e-9c1f-{i:012}","nbf":1792832174,"iat":1792832174,"exp":2108192174}}"#
    )
}

/// Signing inputs and signed tokens for one algorithm.
struct Set {
    msgs: Vec<String>,
    sigs: Vec<Vec<u8>>,
    toks: Vec<Vec<u8>>,
}

fn set(alg: &str, realistic: bool, sign: &dyn Fn(&[u8]) -> Vec<u8>) -> Set {
    let head = b64u(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#).as_bytes());
    let msgs: Vec<String> = (1..=16)
        .map(|i| format!("{head}.{}", b64u(payload(i, realistic).as_bytes())))
        .collect();
    let sigs: Vec<Vec<u8>> = msgs.iter().map(|m| sign(m.as_bytes())).collect();
    let toks = msgs
        .iter()
        .zip(&sigs)
        .map(|(m, s)| format!("{m}.{}", b64u(s)).into_bytes())
        .collect();
    Set { msgs, sigs, toks }
}

fn tokens(
    c: &mut Criterion,
    name: &str,
    s: &Set,
    rust: &dyn Fn(&[Vec<u8>], &mut [Verdict]),
    ck: &cjwt_sys::PKey,
) {
    let mut g = c.benchmark_group(name);
    for n in [1usize, 16] {
        g.throughput(Throughput::Elements(n as u64));
        let t = &s.toks[..n];
        let mut out: Vec<Verdict> = vec![Err(Error::Invalid); n];
        g.bench_with_input(BenchmarkId::new("rust", n), &n, |b, _| {
            b.iter(|| {
                rust(black_box(t), &mut out);
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

fn raw(
    c: &mut Criterion,
    name: &str,
    s: &Set,
    rust: &dyn Fn(&[&[u8]], &[&[u8]], &mut [bool]),
    krate: &dyn Fn(&[u8], &[u8]) -> bool,
) {
    let mut g = c.benchmark_group(name);
    let m: Vec<&[u8]> = s.msgs.iter().map(|m| m.as_bytes()).collect();
    let sg: Vec<&[u8]> = s.sigs.iter().map(|s| &s[..]).collect();
    for n in [1usize, 16] {
        g.throughput(Throughput::Elements(n as u64));
        let mut ok = vec![false; n];
        g.bench_with_input(BenchmarkId::new("rust", n), &n, |b, _| {
            b.iter(|| {
                rust(black_box(&m[..n]), &sg[..n], &mut ok);
                assert!(ok[n - 1]);
            })
        });
        g.bench_with_input(BenchmarkId::new("crate", n), &n, |b, _| {
            b.iter(|| {
                for i in 0..n {
                    assert!(krate(black_box(m[i]), sg[i]));
                }
            })
        });
    }
    g.finish();
}

fn es256(c: &mut Criterion) {
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let vk = *sk.verifying_key();
    let pt = vk.to_encoded_point(false);
    let (x, y): ([u8; 32], [u8; 32]) = (
        pt.x().unwrap()[..].try_into().unwrap(),
        pt.y().unwrap()[..].try_into().unwrap(),
    );
    let k = Es256Key::new(&x, &y).unwrap();
    let ck = cjwt_sys::PKey::es256(&x, &y).unwrap();
    let sign = |m: &[u8]| -> Vec<u8> {
        let s: Signature = sk.sign(m);
        s.to_bytes().to_vec()
    };
    for (realistic, tag) in [(false, "small"), (true, "realistic")] {
        let s = set("ES256", realistic, &sign);
        tokens(
            c,
            &format!("es256_verify_{tag}"),
            &s,
            &|t, o| k.verify_batch(t, NOW, o),
            &ck,
        );
        if !realistic {
            raw(
                c,
                "es256_raw",
                &s,
                &|m, sg, ok| k.verify_signatures(m, sg, ok),
                &|m, sg| vk.verify(m, &Signature::from_slice(sg).unwrap()).is_ok(),
            );
        }
    }
}

fn eddsa(c: &mut Criterion) {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let vk = sk.verifying_key();
    let k = Ed25519Key::new(&vk.to_bytes()).unwrap();
    let ck = cjwt_sys::PKey::ed25519(&vk.to_bytes()).unwrap();
    let sign = |m: &[u8]| sk.sign(m).to_bytes().to_vec();
    for (realistic, tag) in [(false, "small"), (true, "realistic")] {
        let s = set("EdDSA", realistic, &sign);
        tokens(
            c,
            &format!("eddsa_verify_{tag}"),
            &s,
            &|t, o| k.verify_batch(t, NOW, o),
            &ck,
        );
        if !realistic {
            raw(
                c,
                "eddsa_raw",
                &s,
                &|m, sg, ok| k.verify_signatures(m, sg, ok),
                &|m, sg| {
                    vk.verify(m, &ed25519_dalek::Signature::from_slice(sg).unwrap())
                        .is_ok()
                },
            );
        }
    }
}

fn rs256(c: &mut Criterion) {
    use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
    use rsa::signature::{SignatureEncoding, Signer, Verifier};
    use rsa::traits::PublicKeyParts;
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pubk = priv_key.to_public_key();
    let (n, e) = (pubk.n().to_bytes_be(), pubk.e().to_bytes_be());
    let k = Rs256Key::new(&n, &e).unwrap();
    let ck = cjwt_sys::PKey::rs256(&n, &e).unwrap();
    let skey = SigningKey::<sha2::Sha256>::new(priv_key);
    let vkey = VerifyingKey::<sha2::Sha256>::new(pubk);
    let sign = |m: &[u8]| skey.sign(m).to_vec();
    for (realistic, tag) in [(false, "small"), (true, "realistic")] {
        let s = set("RS256", realistic, &sign);
        tokens(
            c,
            &format!("rs256_verify_{tag}"),
            &s,
            &|t, o| k.verify_batch(t, NOW, o),
            &ck,
        );
        if !realistic {
            raw(
                c,
                "rs256_raw",
                &s,
                &|m, sg, ok| k.verify_signatures(m, sg, ok),
                &|m, sg| vkey.verify(m, &Signature::try_from(sg).unwrap()).is_ok(),
            );
        }
    }
}

criterion_group!(benches, es256, eddsa, rs256);
criterion_main!(benches);
