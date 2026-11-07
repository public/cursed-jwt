//! Differential tests against the C library (linked through cjwt-sys): random and mutated tokens must get
//! identical results, field by field, on every Rust engine and at random batch sizes.
mod common;
use common::*;
use cursed_jwt::{Error, Hs256Key, Verdict};

const NOW: i64 = 1_800_000_000;

/// A random claim value near the interesting boundaries.
fn value(r: &mut Rng, key: &str) -> String {
    let nums = [
        format!("{NOW}"),
        format!("{}", NOW + 1),
        format!("{}", NOW - 1),
        format!("{NOW}.5"),
        format!("{}.999", NOW - 1),
        format!("{}e0", NOW + 7),
        "1e400".into(),
        "-1".into(),
        "0".into(),
        "99999999999999999999".into(),
        format!("{}", NOW + 3600),
        format!("0{}", NOW + 3600),
        format!("{}.", NOW + 3600),
    ];
    let strs = [
        "\"7\"",
        "\"0\"",
        "\"007\"",
        "\"9223372036854775807\"",
        "\"9223372036854775808\"",
        "\"-1\"",
        "\"\"",
        "\"bob\"",
        "\"a~\"b\"",
        "\"~u0031\"",
        "\"~ud83d~ude00\"",
        "\"~ud83d\"",
        "\"caf\u{e9}\"",
        "\"x~ny\"",
        "\"~u0000\"",
    ];
    let other = [
        "null",
        "true",
        "false",
        "[]",
        "{}",
        "[1,[2,{\"a\":3}]]",
        "{\"sub\":\"1\"}",
    ];
    match (key, r.below(10)) {
        ("exp" | "nbf" | "iat", 0..=6) => nums[r.below(nums.len())].clone(),
        ("username", 0..=2) => format!("\"{}\"", "u".repeat(250 + r.below(10))),
        (_, 0..=5) => strs[r.below(strs.len())].replace('~', "\\"),
        (_, 6 | 7) => nums[r.below(nums.len())].clone(),
        _ => other[r.below(other.len())].into(),
    }
}

fn payload(r: &mut Rng) -> Vec<u8> {
    let keys = [
        "sub", "username", "exp", "nbf", "iat", "x", "s~u0075b", "exp",
    ];
    let mut v: Vec<String> = Vec::new();
    if r.below(3) > 0 {
        // the common shape, so the shape matcher is exercised too
        v.push(format!("\"sub\":\"{}\"", r.below(100000)));
        v.push(format!("\"username\":\"user{}\"", r.below(1000)));
        v.push(format!("\"iat\":{}", NOW - 10));
        v.push(format!("\"exp\":{}", value(r, "exp")));
    }
    for _ in 0..r.below(5) {
        let k = keys[r.below(keys.len())];
        let val = value(r, k);
        v.push(format!("\"{}\":{}", k.replace('~', "\\"), val));
    }
    if r.below(4) == 0 {
        let i = r.below(v.len() + 1);
        let j = r.below(v.len() + 1);
        if i < v.len() && j < v.len() {
            v.swap(i, j);
        }
    }
    let ws = [" ", "", "\n", "\t", ""];
    let sep = ws[r.below(ws.len())];
    let mut s = format!("{{{sep}{}{sep}}}", v.join(&format!(",{sep}")));
    if r.below(5) == 0 && !s.is_empty() {
        // byte-level damage: the JSON stays signed, so the parser decides
        let mut b = s.into_bytes();
        let i = r.below(b.len());
        match r.below(4) {
            0 => b[i] = r.next() as u8,
            1 => {
                b.remove(i);
            }
            2 => {
                let ins = b",:\"\\{}[]0e.-";
                b.insert(i, ins[r.below(ins.len())])
            }
            _ => b.truncate(i),
        }
        return b;
    }
    if r.below(20) == 0 {
        s = format!("{}", r.below(10));
    }
    s.into_bytes()
}

fn header(r: &mut Rng) -> Vec<u8> {
    let h = [
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"alg":"HS256"}"#,
        r#"{"typ":"JWT","alg":"HS256"}"#,
        r#"{"alg":"HS~u0032~u00356"}"#,
        r#"{"alg":"HS256","alg":"HS256"}"#,
        r#"{"alg":"none"}"#,
        r#"{"alg":"HS512"}"#,
        r#" {"alg" : "HS256" , "kid":[1,{"a":null}]} "#,
        r#"{"alg":"HS256",}"#,
    ];
    j(h[r.below(h.len())])
}

/// A token, sometimes damaged after signing.
fn token(r: &mut Rng) -> Vec<u8> {
    let key: &[u8] = if r.below(20) == 0 { b"wrong" } else { SECRET };
    let mut t = sign_with(&header(r), &payload(r), key);
    if r.below(6) == 0 {
        let i = r.below(t.len());
        match r.below(5) {
            0 => t[i] ^= 1 << r.below(8),
            1 => t[i] = b"A_-+/=.\0"[r.below(8)],
            2 => {
                t.remove(i);
            }
            3 => t.insert(i, b'A'),
            _ => t.truncate(i),
        }
    }
    t
}

#[test]
fn random_tokens_match_c() {
    let mut r = Rng(0xD1FF);
    let ck = cjwt_sys::Key::new(SECRET);
    let k = Hs256Key::new(SECRET);
    same_tags_as_c(&k);
    let engines = engines();
    let mut agree = [0usize; 3];
    for it in 0..iters(400) {
        let n = 1 + r.below(40);
        let toks: Vec<Vec<u8>> = (0..n).map(|_| token(&mut r)).collect();
        let now = if r.below(10) == 0 {
            [0, -5, 1, i64::MAX][r.below(4)]
        } else {
            NOW
        };
        let want: Vec<_> = ck.verify_batch(&toks, now).iter().map(flat_c).collect();
        for &e in &engines {
            let mut out: Vec<Verdict> = vec![Err(Error::Invalid); n];
            let bs = 1 + r.below(n);
            for (t, o) in toks.chunks(bs).zip(out.chunks_mut(bs)) {
                k.verify_batch_with(e, t, now, o);
            }
            for (i, (g, w)) in out.iter().zip(&want).enumerate() {
                assert_eq!(
                    &flat(g),
                    w,
                    "it {it} token {i} engine {} now {now}: {}",
                    e.name(),
                    String::from_utf8_lossy(&toks[i])
                );
            }
        }
        for w in &want {
            agree[w.0 as usize] += 1;
        }
    }
    eprintln!(
        "agreed with C: {} OK, {} INVALID, {} BAD_PAYLOAD",
        agree[0], agree[1], agree[2]
    );
    assert!(agree.iter().all(|&a| a > 50), "{agree:?}");
}

/// The same tags as the C library for a spread of message lengths: the same key schedule.
fn same_tags_as_c(k: &Hs256Key) {
    let ck = cjwt_sys::Key::new(SECRET);
    let msgs: Vec<Vec<u8>> = (0..64).map(|i| vec![i as u8; i * 7]).collect();
    let refs: Vec<&[u8]> = msgs.iter().map(|m| &m[..]).collect();
    let c = ck.hmac_scalar(&refs);
    let mut t = vec![[0u8; 32]; refs.len()];
    k.hmac_batch(cursed_jwt::Engine::Scalar, &refs, &mut t);
    for (c, t) in c.iter().zip(&t) {
        let cb: Vec<u8> = c.iter().flat_map(|w| w.to_be_bytes()).collect();
        assert_eq!(&cb[..], &t[..]);
    }
}

#[test]
fn proptest_payloads_match_c() {
    use proptest::prelude::*;
    let ck = cjwt_sys::Key::new(SECRET);
    let k = Hs256Key::new(SECRET);
    let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
        cases: iters(256) as u32,
        ..Default::default()
    });
    // arbitrary bytes as the payload, and arbitrary JSON-ish text from a small alphabet
    let strat = prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..120),
        proptest::collection::vec(
            proptest::sample::select(b"{}[]\":,0123456789.eE-+ \\usbnamexpfltr".to_vec()),
            0..120
        ),
    ];
    runner
        .run(&strat, |pl| {
            let t = sign(&pl);
            let w = flat_c(&ck.verify_batch(&[&t], NOW)[0]);
            for e in engines() {
                let mut out = [Err(Error::Invalid)];
                k.verify_batch_with(e, &[&t], NOW, &mut out);
                prop_assert_eq!(&flat(&out[0]), &w);
            }
            Ok(())
        })
        .unwrap();
}

/// The canonical-header fast split leaves a '.' inside the payload to the payload decoder: such tokens, even with
/// a valid signature over the whole signing input, must stay INVALID, as the C library's scans make them.
#[test]
fn dot_inside_payload() {
    let ck = cjwt_sys::Key::new(SECRET);
    let k = Hs256Key::new(SECRET);
    let canon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let pl = b64u(br#"{"sub":"7","username":"bob","exp":4102444800}"#);
    for cut in [1, 5, pl.len() / 2, pl.len() - 1] {
        let msg = format!("{canon}.{}.{}", &pl[..cut], &pl[cut..]);
        let tok = format!("{msg}.{}", b64u(&hmac_ref(SECRET, msg.as_bytes())));
        let c = flat_c(&ck.verify_batch(&[tok.as_bytes()], NOW)[0]);
        for e in engines() {
            let mut out = [Err(Error::Invalid)];
            k.verify_batch_with(e, &[tok.as_bytes()], NOW, &mut out);
            assert_eq!(flat(&out[0]), c, "cut {cut}");
            assert_eq!(c.0, 1);
        }
    }
}
