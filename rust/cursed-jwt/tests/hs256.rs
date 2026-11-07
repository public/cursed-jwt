//! HS256: crafted tokens with exact expected results (ported from tests/test_jwt.c), every engine and batch
//! size; the external vectors; random HMACs against the `hmac` crate.
mod common;
use common::*;
use cursed_jwt::{Engine, Error, Hs256Key, Verdict};

const NOW: i64 = 1_800_000_000;

struct Case {
    tok: Vec<u8>,
    want: (u8, i64, Vec<u8>, bool),
    what: String,
}

fn cases() -> Vec<Case> {
    let mut c = Vec::new();
    let fut = NOW + 3600;
    let past = NOW - 3600;
    let mut add = |tok: Vec<u8>, st: u8, uid: i64, name: &[u8], esc: bool, what: &str| {
        c.push(Case {
            tok,
            want: (st, uid, if st == 0 { name.to_vec() } else { vec![] }, esc),
            what: what.into(),
        })
    };
    macro_rules! okc {
        ($pl:expr, $uid:expr, $name:expr, $esc:expr) => {{
            let pl: Vec<u8> = $pl;
            add(
                sign(&pl),
                0,
                $uid,
                $name,
                $esc,
                &String::from_utf8_lossy(&pl),
            )
        }};
    }
    macro_rules! bad {
        ($pl:expr) => {{
            let pl: Vec<u8> = $pl;
            add(sign(&pl), 1, 0, b"", false, &String::from_utf8_lossy(&pl))
        }};
    }
    macro_rules! badp {
        ($pl:expr) => {{
            let pl: Vec<u8> = $pl;
            add(sign(&pl), 2, 0, b"", false, &String::from_utf8_lossy(&pl))
        }};
    }
    let f = |s: String| j(&s);
    let good = sign(&f(format!(
        r#"{{"sub":"7","username":"bob","iat":{NOW},"exp":{fut}}}"#
    )));
    add(good.clone(), 0, 7, b"bob", false, "good");
    add(b"abc".to_vec(), 1, 0, b"", false, "garbage");
    {
        let d = good.iter().rposition(|&b| b == b'.').unwrap();
        let mut t = good[..=d].to_vec();
        t.extend_from_slice(b"c2lnbmF0dXJlLWlzLW5vdC12YWxpZC1hdC1hbGwtYXQtYWxsLTEyMzQ");
        add(t, 1, 0, b"", false, "bad signature");
        let hb = b64u(br#"{"alg":"none","typ":"JWT"}"#);
        let p1 = good.iter().position(|&b| b == b'.').unwrap() + 1;
        let pl = &good[p1..d];
        add(
            format!("{hb}.{}.", String::from_utf8_lossy(pl)).into_bytes(),
            1,
            0,
            b"",
            false,
            "alg=none",
        );
        add(
            format!(
                "{hb}.{}{}",
                String::from_utf8_lossy(pl),
                String::from_utf8_lossy(&good[d..])
            )
            .into_bytes(),
            1,
            0,
            b"",
            false,
            "alg=none, real sig",
        );
    }
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","iat":{},"exp":{past}}}"#,
        past - 3600
    )));
    badp!(f(format!(
        r#"{{"sub":"abc","username":"bob","iat":{NOW},"exp":{fut}}}"#
    )));
    badp!(f(format!(r#"{{"sub":"7","iat":{NOW},"exp":{fut}}}"#)));
    for s in [
        "0",
        "1",
        "true",
        r#""0""#,
        r#""-1""#,
        r#""1.5""#,
        r#""abc""#,
        "null",
        r#""""#,
        r#"" 1""#,
        r#""1 ""#,
        r#""+1""#,
        r#""1e3""#,
        r#""9223372036854775808""#,
        "{}",
        r#"["1"]"#,
    ] {
        badp!(f(format!(r#"{{"sub":{s},"username":"bob","exp":{fut}}}"#)));
    }
    okc!(
        f(format!(
            r#"{{"sub":"9223372036854775807","username":"bob","exp":{fut}}}"#
        )),
        i64::MAX,
        b"bob",
        false
    );
    okc!(
        f(format!(r#"{{"sub":"007","username":"bob","exp":{fut}}}"#)),
        7,
        b"bob",
        false
    );
    okc!(
        f(format!(
            r#"{{"sub":"~u0031~u0032","username":"bob","exp":{fut}}}"#
        )),
        12,
        b"bob",
        false
    );
    for n in ["0", "true", "null", "{}", "[]", "false", "1.5"] {
        badp!(f(format!(r#"{{"sub":"7","username":{n},"exp":{fut}}}"#)));
    }
    // time claims
    bad!(f(r#"{"sub":"7","username":"bob"}"#.into()));
    bad!(f(r#"{"sub":"7","username":"bob","exp":0}"#.into()));
    bad!(f(
        r#"{"sub":"7","username":"bob","exp":"3000000000"}"#.into()
    ));
    bad!(f(r#"{"sub":"7","username":"bob","exp":null}"#.into()));
    bad!(f(r#"{"sub":"7","username":"bob","exp":true}"#.into()));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","exp":[{fut}]}}"#
    )));
    bad!(f(format!(r#"{{"sub":"7","username":"bob","exp":{NOW}}}"#)));
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"bob","exp":{}}}"#,
            NOW + 1
        )),
        7,
        b"bob",
        false
    );
    okc!(
        f(format!(r#"{{"sub":"7","username":"bob","exp":{NOW}.25}}"#)),
        7,
        b"bob",
        false
    );
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","exp":{}.75}}"#,
        NOW - 1
    )));
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"bob","exp":{:.6}}}"#,
            fut as f64 + 0.123456
        )),
        7,
        b"bob",
        false
    );
    okc!(
        f(r#"{"sub":"7","username":"bob","exp":4.1e9}"#.into()),
        7,
        b"bob",
        false
    );
    okc!(
        f(r#"{"sub":"7","username":"bob","exp":99999999999999999999999}"#.into()),
        7,
        b"bob",
        false
    );
    bad!(f(
        r#"{"sub":"7","username":"bob","exp":-99999999999999999999999}"#.into()
    ));
    bad!(f(r#"{"sub":"7","username":"bob","exp":1e3}"#.into()));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","exp":{fut},"nbf":{fut}}}"#
    )));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","exp":{fut},"nbf":"bad"}}"#
    )));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","exp":{fut},"nbf":null}}"#
    )));
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"bob","exp":{fut},"nbf":{NOW}}}"#
        )),
        7,
        b"bob",
        false
    );
    okc!(
        f(format!(
            r#"{{"nbf":{past},"exp":{fut},"username":"bob","sub":"7"}}"#
        )),
        7,
        b"bob",
        false
    );
    bad!(f(format!(r#"{{"sub":"abc","exp":{past}}}"#)));
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"bob","iat":"whenever","x":[1,{{"a":[]}},"~n"],"exp":{fut}}}"#
        )),
        7,
        b"bob",
        false
    );
    // duplicates and escaped keys
    bad!(f(format!(
        r#"{{"sub":"7","sub":"8","username":"bob","exp":{fut}}}"#
    )));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","username":"eve","exp":{fut}}}"#
    )));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","exp":{fut},"exp":{fut}}}"#
    )));
    bad!(f(format!(
        r#"{{"sub":"7","~u0073ub":"8","username":"bob","exp":{fut}}}"#
    )));
    okc!(
        f(format!(
            r#"{{"~u0073ub":"8","user~u006eame":"bob","~u0065xp":{fut}}}"#
        )),
        8,
        b"bob",
        false
    );
    // usernames
    okc!(
        f(format!(r#"{{"sub":"7","username":"","exp":{fut}}}"#)),
        7,
        b"",
        false
    );
    okc!(
        f(format!(r#"{{"sub":"7","username":"a~"b","exp":{fut}}}"#)),
        7,
        b"a\"b",
        true
    );
    okc!(
        f(format!(r#"{{"sub":"7","username":"a~~b","exp":{fut}}}"#)),
        7,
        b"a\\b",
        true
    );
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"tab~there","exp":{fut}}}"#
        )),
        7,
        b"tab\there",
        true
    );
    okc!(
        f(format!(r#"{{"sub":"7","username":"sl~/ash","exp":{fut}}}"#)),
        7,
        b"sl/ash",
        false
    );
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"caf~u00e9","exp":{fut}}}"#
        )),
        7,
        b"caf\xc3\xa9",
        false
    );
    okc!(
        [
            &br#"{"sub":"7","username":"caf"#[..],
            b"\xc3\xa9 \xf0\x9f\x92\xa9",
            format!(r#"","exp":{fut}}}"#).as_bytes()
        ]
        .concat(),
        7,
        b"caf\xc3\xa9 \xf0\x9f\x92\xa9",
        false
    );
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"~ud83d~udca9","exp":{fut}}}"#
        )),
        7,
        b"\xf0\x9f\x92\xa9",
        false
    );
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"x~ud83dy","exp":{fut}}}"#
        )),
        7,
        b"x\xef\xbf\xbdy",
        false
    );
    okc!(
        f(format!(
            r#"{{"sub":"7","username":"nul~u0000","exp":{fut}}}"#
        )),
        7,
        b"nul\0",
        true
    );
    let raw = |mid: &[u8]| {
        [
            &br#"{"sub":"7","username":"#[..],
            mid,
            format!(r#"","exp":{fut}}}"#).as_bytes(),
        ]
        .concat()
    };
    bad!(raw(b"\"bad\xc3")); // truncated UTF-8
    bad!(raw(b"\"bad\xc0\xaf")); // overlong
    bad!(raw(b"\"bad\xed\xa0\x80")); // raw surrogate
    bad!(raw(b"\"ctl\x01"));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bad~x","exp":{fut}}}"#
    )));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bad~u12","exp":{fut}}}"#
    )));
    let long = "n".repeat(399);
    badp!(f(format!(
        r#"{{"sub":"7","username":"{long}","exp":{fut}}}"#
    )));
    let n255 = "n".repeat(255);
    okc!(
        f(format!(r#"{{"sub":"7","username":"{n255}","exp":{fut}}}"#)),
        7,
        n255.as_bytes(),
        false
    );
    let pad = "p".repeat(3000);
    okc!(
        f(format!(
            r#"{{"sub":"7","pad":"{pad}","username":"bob","exp":{fut}}}"#
        )),
        7,
        b"bob",
        false
    );
    // malformed JSON
    bad!(f(format!(r#"{{"sub":"7","username":"bob","exp":{fut},}}"#)));
    bad!(f(format!(r#"{{"sub":"7","username":"bob","exp":{fut}}}x"#)));
    bad!(f(format!(r#"{{"sub":"7","username":"bob","exp":{fut}"#)));
    bad!(f(r#"["sub","7"]"#.into()));
    bad!(f(r#""just a string""#.into()));
    bad!(f(format!(r#"{{"sub":"7" "username":"bob","exp":{fut}}}"#)));
    bad!(f(format!(r#"{{"sub":"7","username":"bob","exp":0{fut}}}"#)));
    bad!(f(format!(r#"{{"sub":"7","username":"bob","exp":+{fut}}}"#)));
    bad!(f(format!(r#"{{"sub":"7","username":"bob","exp":{fut}.}}"#)));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","x":tru,"exp":{fut}}}"#
    )));
    bad!(f(format!(
        r#"{{"sub":"7","username":"bob","x":NaN,"exp":{fut}}}"#
    )));
    bad!(f(format!(r#"{{'sub':"7","username":"bob","exp":{fut}}}"#)));
    let deep = format!(
        r#"{{"x":{}1{},"sub":"7","username":"bob","exp":{fut}}}"#,
        "[".repeat(36),
        "]".repeat(36)
    );
    bad!(f(deep));
    let ok31 = format!(
        r#"{{"x":{}1{},"sub":"7","username":"bob","exp":{fut}}}"#,
        "[".repeat(31),
        "]".repeat(31)
    );
    okc!(f(ok31), 7, b"bob", false);
    let deep32 = format!(
        r#"{{"x":{}1{},"sub":"7","username":"bob","exp":{fut}}}"#,
        "[".repeat(32),
        "]".repeat(32)
    );
    bad!(f(deep32));
    add(sign(b""), 1, 0, b"", false, "empty payload json");
    okc!(
        f(format!(
            " \n{{ \"sub\" : \"7\" ,\t\"username\" :\"bob\" , \"exp\" : {fut} }} \r\n"
        )),
        7,
        b"bob",
        false
    );
    // headers
    let pl = f(format!(r#"{{"sub":"7","username":"bob","exp":{fut}}}"#));
    let hs = |h: &str, k: &[u8]| sign_with(&j(h), &pl, k);
    add(
        hs(r#"{"typ":"JWT","alg":"HS256"}"#, SECRET),
        0,
        7,
        b"bob",
        false,
        "typ first",
    );
    add(
        hs(r#"{"alg":"HS256"}"#, SECRET),
        0,
        7,
        b"bob",
        false,
        "alg only",
    );
    add(
        hs(r#" { "alg" : "HS~u0032~u00356", "kid":[1,2] } "#, SECRET),
        0,
        7,
        b"bob",
        false,
        "escaped alg",
    );
    for (h, w) in [
        (r#"{"alg":"none"}"#, "alg none (signed)"),
        (r#"{"alg":"HS512"}"#, "HS512"),
        (r#"{"alg":"hs256"}"#, "hs256"),
        (r#"{"alg":0}"#, "alg 0"),
        ("{}", "{}"),
        (r#"{"typ":"JWT"}"#, "no alg"),
        (r#"{"alg":"HS256","alg":"HS256"}"#, "dup alg"),
        (r#"{"alg":"HS256""#, "hdr truncated"),
        (r#"["alg","HS256"]"#, "hdr array"),
    ] {
        add(hs(h, SECRET), 1, 0, b"", false, w);
    }
    add(
        hs(r#"{"alg":"HS256","typ":"JWT"}"#, b"wrong-secret"),
        1,
        0,
        b"",
        false,
        "wrong secret",
    );
    // structural damage on the good token
    {
        const B64U: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let l = good.len();
        let mut t = good.clone();
        t[l - 1] = if t[l - 1] == b'A' { b'B' } else { b'A' };
        add(t, 1, 0, b"", false, "last sig char changed");
        let mut t = good.clone();
        let v = B64U.iter().position(|&c| c == t[l - 1]).unwrap();
        t[l - 1] = B64U[v | 1];
        add(t, 1, 0, b"", false, "non-canonical sig");
        let mut t = good.clone();
        t[3] ^= 1;
        add(t, 1, 0, b"", false, "header bit flip");
        let mut t = good.clone();
        t[40] = if t[40] == b'x' { b'y' } else { b'x' };
        add(t, 1, 0, b"", false, "payload char changed");
        let g = String::from_utf8(good.clone()).unwrap();
        add(
            format!("{g}=").into_bytes(),
            1,
            0,
            b"",
            false,
            "sig padding",
        );
        add(
            format!("{g}.").into_bytes(),
            1,
            0,
            b"",
            false,
            "trailing dot",
        );
        add(
            format!("{g}A").into_bytes(),
            1,
            0,
            b"",
            false,
            "sig too long",
        );
        add(good[..l - 1].to_vec(), 1, 0, b"", false, "sig too short");
        add(
            format!("x.{g}").into_bytes(),
            1,
            0,
            b"",
            false,
            "extra segment",
        );
        add(
            format!(".{}", &g[g.find('.').unwrap() + 1..]).into_bytes(),
            1,
            0,
            b"",
            false,
            "empty header",
        );
        add(
            format!("{}..{}", &g[..36], &g[g.rfind('.').unwrap() + 1..]).into_bytes(),
            1,
            0,
            b"",
            false,
            "empty payload",
        );
        add(
            format!("Bearer {g}").into_bytes(),
            1,
            0,
            b"",
            false,
            "with Bearer prefix",
        );
        let mut t = good.clone();
        t[37] = b'+';
        add(t, 1, 0, b"", false, "base64 (not url) char");
        let mut t = good.clone();
        t[10] = 0;
        add(t, 1, 0, b"", false, "NUL inside");
    }
    {
        let raw = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30*";
        let sg = b64u(&hmac_ref(SECRET, raw));
        add(
            [&raw[..], b".", sg.as_bytes()].concat(),
            1,
            0,
            b"",
            false,
            "signed garbage payload",
        );
    }
    add(vec![], 1, 0, b"", false, "empty");
    c
}

#[test]
fn crafted_every_engine_and_batch() {
    let c = cases();
    let k = Hs256Key::new(SECRET);
    let toks: Vec<&[u8]> = c.iter().map(|c| &c.tok[..]).collect();
    for e in engines() {
        let mut bsz = 1;
        while bsz <= c.len() {
            let mut out: Vec<Verdict> = vec![Err(Error::Invalid); c.len()];
            for (t, o) in toks.chunks(bsz).zip(out.chunks_mut(bsz)) {
                k.verify_batch_with(e, t, NOW, o);
            }
            for (i, (case, got)) in c.iter().zip(&out).enumerate() {
                assert_eq!(
                    flat(got),
                    case.want,
                    "case {i} [{}] engine {} batch {bsz}",
                    case.what,
                    e.name()
                );
            }
            bsz = if bsz < 8 { bsz + 1 } else { bsz * 3 };
        }
    }
    eprintln!("{} crafted cases, engines {:?}", c.len(), engines());
}

#[test]
fn default_engine_and_single() {
    let c = cases();
    let k = Hs256Key::new(SECRET);
    for case in &c {
        assert_eq!(
            flat(&k.verify(&case.tok, NOW)),
            case.want,
            "[{}]",
            case.what
        );
    }
    eprintln!("default engine: {}", Engine::best().name());
}

#[test]
fn hmac_random_vs_hmac_crate() {
    let mut r = Rng(0x1234_5678);
    for it in 0..iters(300) {
        let key = r.rbytes(200);
        let k = Hs256Key::new(&key);
        let n = 1 + r.below(70);
        let msgs: Vec<Vec<u8>> = (0..n).map(|_| r.rbytes(700)).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| &m[..]).collect();
        let want: Vec<[u8; 32]> = msgs.iter().map(|m| hmac_ref(&key, m)).collect();
        for e in engines() {
            let mut got = vec![[0u8; 32]; n];
            k.hmac_batch(e, &refs, &mut got);
            assert_eq!(got, want, "iteration {it} engine {}", e.name());
        }
    }
}

#[test]
fn tokens_json() {
    let Some(p) = vector_file("tokens.json") else {
        return;
    };
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    let recs = v.as_array().unwrap();
    let toks: Vec<&[u8]> = recs
        .iter()
        .map(|r| r["token"].as_str().unwrap().as_bytes())
        .collect();
    let k = Hs256Key::new(SECRET);
    let n = toks.len().min(iters(20000));
    for e in engines() {
        for bs in [1, 8, 3, 16, 64, 100] {
            let mut out: Vec<Verdict> = vec![Err(Error::Invalid); n];
            for (t, o) in toks[..n].chunks(bs).zip(out.chunks_mut(bs)) {
                k.verify_batch_with(e, t, NOW, o);
            }
            for (r, o) in recs.iter().zip(&out) {
                let c = o.as_ref().unwrap_or_else(|e| panic!("{e:?}"));
                assert_eq!(c.uid(), r["id"].as_i64().unwrap());
                assert_eq!(c.username(), r["username"].as_str().unwrap());
                assert!(!c.username_needs_escape());
            }
        }
    }
}

/// RFC 4231, NIST CAVP, Wycheproof, pyca/cryptography random cases and RFC 7515 A.1, as tests/make_vectors.py
/// writes them (each cross-checked against pyca/cryptography there).  Every HMAC vector runs on every engine
/// at a random lane of a batch of random messages under the same key.
#[test]
fn external_vectors() {
    let Some(p) = vector_file("hmac_vectors.txt") else {
        return;
    };
    let text = std::fs::read_to_string(p).unwrap();
    let mut r = Rng(99);
    let (mut nh, mut nj) = (0, 0);
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "hmac" => {
                let (key, msg, tag, expect) = (unhex(f[2]), unhex(f[3]), unhex(f[4]), f[5] == "1");
                let k = Hs256Key::new(&key);
                let n = 1 + r.below(24);
                let at = r.below(n);
                let mut msgs: Vec<Vec<u8>> = (0..n).map(|_| r.rbytes(300)).collect();
                msgs[at] = msg.clone();
                let refs: Vec<&[u8]> = msgs.iter().map(|m| &m[..]).collect();
                for e in engines() {
                    let mut got = vec![[0u8; 32]; n];
                    k.hmac_batch(e, &refs, &mut got);
                    assert_eq!(
                        got[at][..tag.len()] == tag[..],
                        expect,
                        "{} engine {}",
                        f[1],
                        e.name()
                    );
                    for (i, m) in msgs.iter().enumerate() {
                        if i != at {
                            assert_eq!(got[i], hmac_ref(&key, m));
                        }
                    }
                }
                nh += 1;
            }
            "jws" => {
                let k = Hs256Key::new(&unhex(f[2]));
                let now: i64 = f[4].parse().unwrap();
                let st: u8 = f[5].parse().unwrap();
                for e in engines() {
                    let mut out = [Err(Error::Invalid)];
                    k.verify_batch_with(e, &[f[3].as_bytes()], now, &mut out);
                    assert_eq!(flat(&out[0]).0, st, "{} engine {}", f[1], e.name());
                }
                nj += 1;
            }
            _ => panic!("unknown vector line {line}"),
        }
    }
    eprintln!("{nh} HMAC vectors, {nj} JWS vectors");
    assert!(nh > 400 && nj >= 3);
}

#[test]
fn b64_vs_c_and_scalar() {
    let mut r = Rng(7);
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for _ in 0..iters(5000) {
        let n = r.below(300);
        let mut s: Vec<u8> = (0..n).map(|_| A[r.below(64)]).collect();
        if r.below(4) == 0 && n > 0 {
            let i = r.below(n);
            s[i] = r.next() as u8;
        }
        let c = cjwt_sys::b64url_decode(&s);
        let mut d = vec![0u8; n / 4 * 3 + 2];
        let got = cursed_jwt::b64url_decode(&mut d, &s).map(|l| d[..l].to_vec());
        let mut d2 = vec![0u8; n / 4 * 3 + 2];
        let sc = cursed_jwt::b64url_decode_scalar(&mut d2, &s).map(|l| d2[..l].to_vec());
        assert_eq!(got, c, "{}", String::from_utf8_lossy(&s));
        assert_eq!(sc, c);
    }
}
