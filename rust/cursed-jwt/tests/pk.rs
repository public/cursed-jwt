//! RS256 / ES256 / EdDSA against the vectors tests/make_pk_vectors.py writes (Wycheproof, NIST CAVP, RFC
//! 7515/8032/8037, pyca/cryptography; each cross-checked against pyca/cryptography there), alone, in random
//! sub-batches and in whole shuffled key groups; and every JWT vector against the C library as well.
#![cfg(feature = "pk")]
#![allow(clippy::large_enum_variant, clippy::type_complexity)]
mod common;
use common::*;
use cursed_jwt::{Ed25519Key, Error, Es256Key, PublicKey, Rs256Key, Verdict};
use std::collections::HashMap;

enum Key {
    Es(Box<Es256Key>, cjwt_sys::PKey),
    Rs(Rs256Key, cjwt_sys::PKey),
    Ed(Box<Ed25519Key>, cjwt_sys::PKey),
}

impl Key {
    fn sigs(&self, m: &[&[u8]], s: &[&[u8]], ok: &mut [bool]) {
        match self {
            Key::Es(k, _) => k.verify_signatures(m, s, ok),
            Key::Rs(k, _) => k.verify_signatures(m, s, ok),
            Key::Ed(k, _) => k.verify_signatures(m, s, ok),
        }
    }
    fn tokens(&self, t: &[&[u8]], now: i64, out: &mut [Verdict]) {
        match self {
            Key::Es(k, _) => k.verify_batch(t, now, out),
            Key::Rs(k, _) => k.verify_batch(t, now, out),
            Key::Ed(k, _) => k.verify_batch(t, now, out),
        }
    }
    fn c(&self) -> &cjwt_sys::PKey {
        match self {
            Key::Es(_, c) | Key::Rs(_, c) | Key::Ed(_, c) => c,
        }
    }
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[32 - b.len()..].copy_from_slice(b);
    a
}

/// The key for a vector line, or None where both libraries reject it (both must agree).
fn key(kind: &str, k1: &[u8], k2: &[u8]) -> Option<Key> {
    let k = match kind {
        "es" | "ES256" => {
            let (x, y) = (arr32(k1), arr32(k2));
            let (r, c) = (Es256Key::new(&x, &y), cjwt_sys::PKey::es256(&x, &y));
            assert_eq!(r.is_some(), c.is_some(), "ES256 key acceptance differs");
            Key::Es(Box::new(r?), c?)
        }
        "rs" | "RS256" => {
            let (r, c) = (Rs256Key::new(k1, k2), cjwt_sys::PKey::rs256(k1, k2));
            assert_eq!(r.is_some(), c.is_some(), "RS256 key acceptance differs");
            Key::Rs(r?, c?)
        }
        _ => {
            let a = arr32(k1);
            let (r, c) = (Ed25519Key::new(&a), cjwt_sys::PKey::ed25519(&a));
            assert_eq!(r.is_some(), c.is_some(), "Ed25519 key acceptance differs");
            Key::Ed(Box::new(r?), c?)
        }
    };
    Some(k)
}

#[test]
fn pk_vectors() {
    let Some(p) = vector_file("pk_vectors.txt") else {
        return;
    };
    let text = std::fs::read_to_string(p).unwrap();
    let mut keys: HashMap<String, Option<Key>> = HashMap::new();
    // per key: (msg, sig, expect, src)
    let mut groups: HashMap<String, Vec<(Vec<u8>, Vec<u8>, bool, String)>> = HashMap::new();
    let (mut nsig, mut njwt, mut npair) = (0, 0, 0);
    let mut r = Rng(5);
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "es" | "rs" | "ed" => {
                let (k1, k2) = (unhex(f[2]), if f[0] == "ed" { vec![] } else { unhex(f[3]) });
                let o = if f[0] == "ed" { 0 } else { 1 };
                let (msg, sig, expect) = (unhex(f[3 + o]), unhex(f[4 + o]), f[5 + o] == "1");
                let id = format!("{} {} {}", f[0], f[2], if o == 1 { f[3] } else { "" });
                let k = keys
                    .entry(id.clone())
                    .or_insert_with(|| key(f[0], &k1, &k2));
                if k.is_none() {
                    assert!(!expect, "{}: valid signature under a rejected key", f[1]);
                    continue;
                }
                groups
                    .entry(id)
                    .or_default()
                    .push((msg, sig, expect, f[1].to_string()));
                nsig += 1;
            }
            "jwt" => {
                let (k1, k2) = (unhex(f[3]), unhex(f[4]));
                let k = key(f[2], &k1, &k2).expect("JWT vector key rejected");
                let now: i64 = f[6].parse().unwrap();
                let want = (
                    f[7].parse::<u8>().unwrap(),
                    f[8].parse::<i64>().unwrap(),
                    unhex(f[9]),
                );
                let tok = f[5].as_bytes();
                let mut out = [Err(Error::Invalid)];
                k.tokens(&[tok], now, &mut out);
                let g = flat(&out[0]);
                assert_eq!((g.0, g.1, g.2.clone()), want, "{}", f[1]);
                assert_eq!(
                    g,
                    flat_c(&k.c().verify_batch(&[tok], now)[0]),
                    "{} vs C",
                    f[1]
                );
                // inside a batch of damaged copies
                let mut toks: Vec<Vec<u8>> = (0..r.below(8)).map(|_| tok.to_vec()).collect();
                for t in toks.iter_mut() {
                    let i = r.below(t.len());
                    t[i] ^= 1 << r.below(7);
                }
                let at = r.below(toks.len() + 1);
                toks.insert(at, tok.to_vec());
                let refs: Vec<&[u8]> = toks.iter().map(|t| &t[..]).collect();
                let mut out = vec![Err(Error::Invalid); refs.len()];
                k.tokens(&refs, now, &mut out);
                let c = k.c().verify_batch(&refs, now);
                for (o, c) in out.iter().zip(&c) {
                    assert_eq!(flat(o), flat_c(c), "{} in a batch", f[1]);
                }
                assert_eq!(flat(&out[at]), g);
                njwt += 1;
            }
            "rspair" => {
                // genuine signatures turned into s1 x, s2 / x: each one alone is invalid (no screening here)
                let k = Rs256Key::new(&unhex(f[2]), &unhex(f[3])).unwrap();
                let (m1, s1, m2, s2) = (unhex(f[4]), unhex(f[5]), unhex(f[6]), unhex(f[7]));
                let mut ok = [true; 2];
                k.verify_signatures(&[&m1, &m2], &[&s1, &s2], &mut ok);
                assert_eq!(ok, [false, false], "{}", f[1]);
                npair += 1;
            }
            _ => panic!("unknown vector line {}", f[0]),
        }
    }
    // each key's group: alone, in random sub-batches, and shuffled into one batch
    for (id, v) in &groups {
        let k = keys[id].as_ref().unwrap();
        for (m, s, e, src) in v {
            let mut ok = [!e];
            k.sigs(&[m], &[s], &mut ok);
            assert_eq!(ok[0], *e, "{src} alone");
        }
        let mut idx: Vec<usize> = (0..v.len()).collect();
        for i in (1..idx.len()).rev() {
            idx.swap(i, r.below(i + 1));
        }
        let m: Vec<&[u8]> = idx.iter().map(|&i| &v[i].0[..]).collect();
        let s: Vec<&[u8]> = idx.iter().map(|&i| &v[i].1[..]).collect();
        let mut ok = vec![false; m.len()];
        k.sigs(&m, &s, &mut ok);
        for (j, &i) in idx.iter().enumerate() {
            assert_eq!(ok[j], v[i].2, "{} in its shuffled group", v[i].3);
        }
        let mut j = 0;
        while j < m.len() {
            let n = (1 + r.below(24)).min(m.len() - j);
            let mut ok = vec![false; n];
            k.sigs(&m[j..j + n], &s[j..j + n], &mut ok);
            for q in 0..n {
                assert_eq!(ok[q], v[idx[j + q]].2, "{} in a sub-batch", v[idx[j + q]].3);
            }
            j += n;
        }
    }
    eprintln!(
        "{nsig} signature vectors under {} keys, {njwt} JWTs, {npair} screening pairs",
        groups.len()
    );
    assert!(nsig > 5000 && njwt > 300 && npair == 4);
}

#[test]
fn public_key_enum_and_rejects() {
    // a point not on the curve, an even modulus, a 1024-bit modulus, a non-canonical Ed25519 y
    assert!(Es256Key::new(&[1; 32], &[2; 32]).is_none());
    assert!(Rs256Key::new(&[0xc0; 256], &[1, 0, 1]).is_none());
    assert!(Rs256Key::new(&[0xc1; 128], &[1, 0, 1]).is_none());
    assert!(Rs256Key::new(&[0xc1; 256], &[1]).is_none());
    assert!(Ed25519Key::new(&[0xff; 32]).is_none());
    // RFC 8032 test 1's key, through the enum
    let a: [u8; 32] = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        .try_into()
        .unwrap();
    let k = PublicKey::EdDsa(Box::new(Ed25519Key::new(&a).unwrap()));
    let mut out = [Err(Error::Invalid)];
    k.verify_batch(&[b"a.b.c"], 0, &mut out);
    assert!(out[0].is_err());
}
