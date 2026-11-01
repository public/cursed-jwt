//! Tokens from the fuzzer input, verified by every Rust engine (the whole batch and each token alone) and by the
//! C library: all results must be identical.  Byte 0 is a config: bit 0 re-signs every token with the test
//! secret (so inputs reach the JSON and claims code), bits 1-2 pick `now`.  Tokens are separated by '\n'.
#![no_main]
use cursed_jwt::{Engine, Error, Hs256Key, Verdict};
use hmac::{Hmac, Mac};
use libfuzzer_sys::fuzz_target;
use sha2::Sha256;

const SECRET: &[u8] = b"cursed-jwt-test-secret";

fn b64u(b: &[u8]) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = Vec::new();
    for c in b.chunks(3) {
        let v = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..c.len() + 1 {
            s.push(A[(v >> (18 - 6 * i) & 63) as usize]);
        }
    }
    s
}

/// The signing input with a fresh HS256 signature.
fn resign(t: &[u8]) -> Vec<u8> {
    let msg = match t.iter().rposition(|&b| b == b'.') {
        Some(d) => &t[..d],
        None => t,
    };
    let mut m = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    m.update(msg);
    [msg, b".", &b64u(&m.finalize().into_bytes())].concat()
}

fn flat(v: &Verdict) -> (u8, i64, Vec<u8>, bool) {
    match v {
        Ok(c) => (
            0,
            c.uid(),
            c.username_bytes().to_vec(),
            c.username_needs_escape(),
        ),
        Err(Error::Invalid) => (1, 0, vec![], false),
        Err(Error::BadPayload) => (2, 0, vec![], false),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let now = [1_800_000_000i64, 0, -1, i64::MAX][(cfg >> 1 & 3) as usize];
    let toks: Vec<Vec<u8>> = rest
        .split(|&b| b == b'\n')
        .take(40)
        .map(|t| if cfg & 1 != 0 { resign(t) } else { t.to_vec() })
        .collect();
    let ck = cjwt_sys::Key::new(SECRET);
    let want: Vec<_> = ck
        .verify_batch(&toks, now)
        .iter()
        .map(|r| {
            if r.status == 0 {
                (0, r.uid, r.username.clone(), r.escape)
            } else {
                (r.status, 0, vec![], false)
            }
        })
        .collect();
    let k = Hs256Key::new(SECRET);
    for e in Engine::ALL.into_iter().filter(|e| e.is_available()) {
        let mut out: Vec<Verdict> = vec![Err(Error::Invalid); toks.len()];
        k.verify_batch_with(e, &toks, now, &mut out);
        for (i, (g, w)) in out.iter().zip(&want).enumerate() {
            assert_eq!(&flat(g), w, "engine {} token {i}", e.name());
            let mut one = [Err(Error::Invalid)];
            k.verify_batch_with(e, &toks[i..i + 1], now, &mut one);
            assert_eq!(&flat(&one[0]), w, "engine {} token {i} alone", e.name());
        }
    }
});
