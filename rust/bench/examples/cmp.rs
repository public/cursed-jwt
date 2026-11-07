//! Rust vs C in one process, for decisions: every arm (full HS256 verify on each side's default engine, raw HMAC
//! on each engine both sides have, RS256 / ES256 / EdDSA full verify) is timed once per round, in a fresh random
//! order each round, and the summary gives medians, the spread, and the median of the per-round Rust/C ratios.
//!
//!     cmp [--secs S] [--rounds R] [--batches 1,3,8,16,32] [--groups hs,hmac,pk] [--hmac-batches 1,4,8,16]
//!
//! Raw lines go to stdout as `raw <round> <group> <engine> <batch> <rust|c> <ns/token>`, then the summary.
//! Every arm's output is checked against the other side's before anything is timed.
#![allow(missing_docs, clippy::type_complexity)]
use cursed_jwt::{Ed25519Key, Engine, Error, Es256Key, Hs256Key, Rs256Key, Verdict};
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;

const SECRET: &[u8] = b"cursed-jwt-test-secret";
const NOW: i64 = 1_800_000_000;
const N: usize = 32;

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

fn signing_inputs(alg: &str) -> Vec<String> {
    let head = b64u(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#).as_bytes());
    (1..=N)
        .map(|i| {
            let pl = format!(
                r#"{{"sub":"{i}","username":"user_{i}","iat":1792832174,"exp":2108192174}}"#
            );
            format!("{head}.{}", b64u(pl.as_bytes()))
        })
        .collect()
}

fn sign_all(msgs: &[String], sign: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<Vec<u8>> {
    msgs.iter()
        .map(|m| format!("{m}.{}", b64u(&sign(m.as_bytes()))).into_bytes())
        .collect()
}

/// One timed thing: `run()` processes `per` tokens.
struct Arm {
    group: &'static str,
    engine: String,
    batch: usize,
    side: &'static str,
    per: usize,
    run: Box<dyn FnMut()>,
}

fn time(a: &mut Arm, secs: f64) -> f64 {
    // calibrate: enough calls for ~1/20 of the slot, then whole slot
    let t = Instant::now();
    let mut calls = 0u64;
    while t.elapsed().as_secs_f64() < secs / 20.0 {
        (a.run)();
        calls += 1;
    }
    let chunk = calls.max(1);
    let t = Instant::now();
    let mut done = 0u64;
    loop {
        for _ in 0..chunk {
            (a.run)();
        }
        done += chunk;
        if t.elapsed().as_secs_f64() >= secs {
            break;
        }
    }
    t.elapsed().as_nanos() as f64 / (done as f64 * a.per as f64)
}

fn list(v: &str) -> Vec<usize> {
    v.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

fn verdicts_agree(r: &[Verdict], c: &[cjwt_sys::jwt_result_t]) -> bool {
    r.iter()
        .zip(c)
        .all(|(r, c)| matches!(r, Ok(cl) if c.status == 0 && cl.uid() == c.uid))
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let opt = |k: &str, d: &str| -> String {
        a.iter()
            .position(|x| x == k)
            .and_then(|i| a.get(i + 1).cloned())
            .unwrap_or_else(|| d.to_string())
    };
    let secs: f64 = opt("--secs", "0.25").parse().unwrap();
    let rounds: usize = opt("--rounds", "7").parse().unwrap();
    let batches = list(&opt("--batches", "1,3,8,16,32"));
    let hbatches = list(&opt("--hmac-batches", "1,4,8,16"));
    let groups = opt("--groups", "hs,hmac,pk");
    let seed: u64 = opt("--seed", "1").parse().unwrap();
    println!(
        "# rust default engine {} | C default engine {} | C cpu features 0x{:x} | rust cpu features 0x{:x}",
        Engine::best().name(),
        cjwt_sys::engine(),
        cjwt_sys::cpu_features(),
        cursed_jwt::CpuFeatures::get().bits()
    );
    let mut arms: Vec<Arm> = Vec::new();

    // ---- HS256 full verify, default engines ----
    let hmsgs = signing_inputs("HS256");
    let htoks: &'static Vec<Vec<u8>> = Box::leak(Box::new(sign_all(&hmsgs, &|m| {
        let mut h = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
        h.update(m);
        h.finalize().into_bytes().to_vec()
    })));
    let hk: &'static Hs256Key = Box::leak(Box::new(Hs256Key::new(SECRET)));
    let ck: &'static cjwt_sys::Key = Box::leak(Box::new(cjwt_sys::Key::new(SECRET)));
    if groups.contains("hs") {
        for &b in &batches {
            let t = &htoks[..b];
            let mut out: Vec<Verdict> = vec![Err(Error::Invalid); b];
            let (p, l) = cjwt_sys::token_ptrs(t);
            let mut cout = cjwt_sys::results(b);
            hk.verify_batch(t, NOW, &mut out);
            ck.verify_raw(&p, &l, NOW, &mut cout);
            assert!(verdicts_agree(&out, &cout), "hs b{b}: rust and C disagree");
            arms.push(Arm {
                group: "hs",
                engine: "default".into(),
                batch: b,
                side: "rust",
                per: b,
                run: Box::new(move || hk.verify_batch(black_box(t), NOW, &mut out)),
            });
            arms.push(Arm {
                group: "hs",
                engine: "default".into(),
                batch: b,
                side: "c",
                per: b,
                run: Box::new(move || ck.verify_raw(black_box(&p), &l, NOW, &mut cout)),
            });
        }
    }

    // ---- raw HMAC per engine (the engines both sides have on this CPU) ----
    if groups.contains("hmac") {
        let msgs: &'static Vec<&'static [u8]> = Box::leak(Box::new(
            htoks
                .iter()
                .map(|t| &t[..t.iter().rposition(|&c| c == b'.').unwrap()])
                .collect(),
        ));
        for (name, f) in cjwt_sys::hmac_engines() {
            let Some(&e) = Engine::ALL.iter().find(|e| e.name() == name) else {
                continue; // "ossl": the batch-1 path, measured by hs b1
            };
            if !e.is_available() || e == Engine::Scalar {
                continue;
            }
            for &b in &hbatches {
                let m = &msgs[..b];
                let mut tags = vec![[0u8; 32]; b];
                let p: Vec<*const u8> = m.iter().map(|x| x.as_ptr()).collect();
                let l: Vec<i32> = m.iter().map(|x| x.len() as i32).collect();
                let mut mac = vec![[0u32; 8]; b];
                hk.hmac_batch(e, m, &mut tags);
                ck.hmac_raw(f, &p, &l, &mut mac);
                for (t, w) in tags.iter().zip(&mac) {
                    let wb: Vec<u8> = w.iter().flat_map(|x| x.to_be_bytes()).collect();
                    assert_eq!(&t[..], &wb[..], "hmac {name} b{b}: rust and C disagree");
                }
                arms.push(Arm {
                    group: "hmac",
                    engine: name.into(),
                    batch: b,
                    side: "rust",
                    per: b,
                    run: Box::new(move || hk.hmac_batch(e, black_box(m), &mut tags)),
                });
                arms.push(Arm {
                    group: "hmac",
                    engine: name.into(),
                    batch: b,
                    side: "c",
                    per: b,
                    run: Box::new(move || ck.hmac_raw(f, black_box(&p), &l, &mut mac)),
                });
            }
        }
    }

    // ---- public-key full verify ----
    if groups.contains("pk") {
        type Rv = Box<dyn Fn(&[Vec<u8>], &mut [Verdict])>;
        let mut pks: Vec<(&'static str, Rv, cjwt_sys::PKey, Vec<Vec<u8>>)> = Vec::new();
        {
            use ed25519_dalek::Signer;
            let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
            let pkb = sk.verifying_key().to_bytes();
            let k = Ed25519Key::new(&pkb).unwrap();
            let toks = sign_all(&signing_inputs("EdDSA"), &|m| {
                sk.sign(m).to_bytes().to_vec()
            });
            pks.push((
                "eddsa",
                Box::new(move |t, o| k.verify_batch(t, NOW, o)),
                cjwt_sys::PKey::ed25519(&pkb).unwrap(),
                toks,
            ));
        }
        {
            use p256::ecdsa::signature::Signer;
            use p256::ecdsa::{Signature, SigningKey};
            let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
            let pt = sk.verifying_key().to_encoded_point(false);
            let x: [u8; 32] = pt.x().unwrap()[..].try_into().unwrap();
            let y: [u8; 32] = pt.y().unwrap()[..].try_into().unwrap();
            let k = Es256Key::new(&x, &y).unwrap();
            let toks = sign_all(&signing_inputs("ES256"), &|m| {
                let s: Signature = sk.sign(m);
                s.to_bytes().to_vec()
            });
            pks.push((
                "es256",
                Box::new(move |t, o| k.verify_batch(t, NOW, o)),
                cjwt_sys::PKey::es256(&x, &y).unwrap(),
                toks,
            ));
        }
        {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::{SignatureEncoding, Signer};
            use rsa::traits::PublicKeyParts;
            let mut rng = rand::rngs::StdRng::seed_from_u64(1);
            let pk = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let pubk = pk.to_public_key();
            let (n, e) = (pubk.n().to_bytes_be(), pubk.e().to_bytes_be());
            let k = Rs256Key::new(&n, &e).unwrap();
            let skey = SigningKey::<sha2::Sha256>::new(pk);
            let toks = sign_all(&signing_inputs("RS256"), &|m| skey.sign(m).to_vec());
            pks.push((
                "rs256",
                Box::new(move |t, o| k.verify_batch(t, NOW, o)),
                cjwt_sys::PKey::rs256(&n, &e).unwrap(),
                toks,
            ));
        }
        for (name, rv, ckey, toks) in pks {
            let rv: &'static Rv = Box::leak(Box::new(rv));
            let ckey: &'static cjwt_sys::PKey = Box::leak(Box::new(ckey));
            let toks: &'static Vec<Vec<u8>> = Box::leak(Box::new(toks));
            for b in [1usize, 16] {
                let t = &toks[..b];
                let mut out: Vec<Verdict> = vec![Err(Error::Invalid); b];
                let (p, l) = cjwt_sys::token_ptrs(t);
                let mut cout = cjwt_sys::results(b);
                rv(t, &mut out);
                ckey.verify_raw(&p, &l, NOW, &mut cout);
                assert!(
                    verdicts_agree(&out, &cout),
                    "{name} b{b}: rust and C disagree"
                );
                arms.push(Arm {
                    group: name,
                    engine: "-".into(),
                    batch: b,
                    side: "rust",
                    per: b,
                    run: Box::new(move || rv(black_box(t), &mut out)),
                });
                arms.push(Arm {
                    group: name,
                    engine: "-".into(),
                    batch: b,
                    side: "c",
                    per: b,
                    run: Box::new(move || ckey.verify_raw(black_box(&p), &l, NOW, &mut cout)),
                });
            }
        }
    }

    // ---- rounds ----
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut res: BTreeMap<(String, String, usize), [Vec<f64>; 2]> = BTreeMap::new();
    let mut order: Vec<usize> = (0..arms.len()).collect();
    let pk_scale = |g: &str| if g == "hs" || g == "hmac" { 1.0 } else { 4.0 };
    for r in 0..rounds {
        order.shuffle(&mut rng);
        for &i in &order {
            let arm = &mut arms[i];
            let ns = time(arm, secs * pk_scale(arm.group));
            println!(
                "raw\t{r}\t{}\t{}\t{}\t{}\t{ns:.2}",
                arm.group, arm.engine, arm.batch, arm.side
            );
            let e = res
                .entry((arm.group.to_string(), arm.engine.clone(), arm.batch))
                .or_default();
            e[(arm.side == "c") as usize].push(ns);
        }
    }

    // ---- summary ----
    fn med(v: &mut [f64]) -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = v.len();
        if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        }
    }
    println!(
        "# group\tengine\tbatch\trust_med\trust_min\trust_max\tc_med\tc_min\tc_max\tratio_med\tratio_min\tratio_max"
    );
    for ((g, e, b), [rv, cv]) in res.iter_mut() {
        let mut ratio: Vec<f64> = rv.iter().zip(cv.iter()).map(|(r, c)| r / c).collect();
        let (rmin, rmax) = (
            rv.iter().cloned().fold(f64::MAX, f64::min),
            rv.iter().cloned().fold(0.0, f64::max),
        );
        let (cmin, cmax) = (
            cv.iter().cloned().fold(f64::MAX, f64::min),
            cv.iter().cloned().fold(0.0, f64::max),
        );
        let (qmin, qmax) = (
            ratio.iter().cloned().fold(f64::MAX, f64::min),
            ratio.iter().cloned().fold(0.0, f64::max),
        );
        println!(
            "sum\t{g}\t{e}\t{b}\t{:.1}\t{rmin:.1}\t{rmax:.1}\t{:.1}\t{cmin:.1}\t{cmax:.1}\t{:.3}\t{qmin:.3}\t{qmax:.3}",
            med(rv),
            med(cv),
            med(&mut ratio)
        );
    }
}
