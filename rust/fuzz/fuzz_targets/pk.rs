//! RS256 / ES256 / EdDSA: real signed tokens (signed by the p256, ed25519-dalek and rsa crates), damaged by the
//! fuzzer input, must get the same result from the Rust port and the C library, alone and in a batch with the
//! undamaged tokens.  Byte 0 picks the algorithm and what to damage: the signature bytes (re-encoded, so the
//! damage reaches the arithmetic: s at 0 / n-1 / n, S + L, flipped bits), the payload, or the raw token.
#![no_main]
use cursed_jwt::{Ed25519Key, Error, Es256Key, Rs256Key, Verdict};
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use std::sync::OnceLock;

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

struct Alg {
    head: String,
    sign: Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
    rust: Box<dyn Fn(&[&[u8]], i64, &mut [Verdict]) + Send + Sync>,
    c: cjwt_sys::PKey,
}

fn algs() -> &'static [Alg; 3] {
    static A: OnceLock<[Alg; 3]> = OnceLock::new();
    A.get_or_init(|| {
        use p256::ecdsa::signature::Signer as _;
        let es = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let pt = es.verifying_key().to_encoded_point(false);
        let (x, y): ([u8; 32], [u8; 32]) = (pt.x().unwrap()[..].try_into().unwrap(), pt.y().unwrap()[..].try_into().unwrap());
        let esk = Es256Key::new(&x, &y).unwrap();
        let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let edk = Ed25519Key::new(&ed.verifying_key().to_bytes()).unwrap();
        let edc = cjwt_sys::PKey::ed25519(&ed.verifying_key().to_bytes()).unwrap();
        use rsa::traits::PublicKeyParts;
        let rp = rsa::RsaPrivateKey::new(&mut rand::rngs::StdRng::seed_from_u64(1), 2048).unwrap();
        let (n, e) = (rp.n().to_bytes_be(), rp.e().to_bytes_be());
        let rsk = Rs256Key::new(&n, &e).unwrap();
        let rsc = cjwt_sys::PKey::rs256(&n, &e).unwrap();
        let rss = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rp);
        let head = |a: &str| b64u(format!(r#"{{"alg":"{a}","typ":"JWT"}}"#).as_bytes());
        [
            Alg {
                head: head("ES256"),
                sign: Box::new(move |m| {
                    let s: p256::ecdsa::Signature = es.sign(m);
                    s.to_bytes().to_vec()
                }),
                rust: Box::new(move |t, now, o| esk.verify_batch(t, now, o)),
                c: cjwt_sys::PKey::es256(&x, &y).unwrap(),
            },
            Alg {
                head: head("EdDSA"),
                sign: Box::new(move |m| {
                    use ed25519_dalek::Signer;
                    ed.sign(m).to_bytes().to_vec()
                }),
                rust: Box::new(move |t, now, o| edk.verify_batch(t, now, o)),
                c: edc,
            },
            Alg {
                head: head("RS256"),
                sign: Box::new(move |m| {
                    use rsa::signature::{SignatureEncoding, Signer};
                    rss.sign(m).to_vec()
                }),
                rust: Box::new(move |t, now, o| rsk.verify_batch(t, now, o)),
                c: rsc,
            },
        ]
    })
}

fn flat(v: &Verdict) -> (u8, i64, Vec<u8>) {
    match v {
        Ok(c) => (0, c.uid(), c.username_bytes().to_vec()),
        Err(Error::Invalid) => (1, 0, vec![]),
        Err(Error::BadPayload) => (2, 0, vec![]),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&cfg, rest)) = data.split_first() else { return };
    let a = &algs()[(cfg % 3) as usize];
    let pl = br#"{"sub":"42","username":"fuzz","iat":1792832174,"exp":2108192174}"#;
    let msg = format!("{}.{}", a.head, b64u(pl));
    let mut sig = (a.sign)(msg.as_bytes());
    let good = format!("{msg}.{}", b64u(&sig)).into_bytes();
    let tok = match cfg / 3 % 3 {
        0 => {
            // damage the signature bytes; ES256 / EdDSA: optionally set r, s or S to a boundary value first
            let n: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
                0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51];
            if cfg % 3 == 0 && cfg & 0x80 != 0 {
                let half = if cfg & 0x40 != 0 { 32 } else { 0 };
                sig[half..half + 32].copy_from_slice(n);
                let last = half + 31;
                sig[last] = sig[last].wrapping_add(rest.first().copied().unwrap_or(0) % 3).wrapping_sub(1);
            }
            for (i, &b) in rest.iter().enumerate().skip(1).take(16) {
                let at = (b as usize * 31 + i) % sig.len();
                sig[at] ^= rest.get(i + 1).copied().unwrap_or(1);
            }
            format!("{msg}.{}", b64u(&sig)).into_bytes()
        }
        1 => {
            // a different payload under a valid signature of it: the JSON and claims code with real PK keys
            let m = format!("{}.{}", a.head, b64u(rest));
            let s = (a.sign)(m.as_bytes());
            format!("{m}.{}", b64u(&s)).into_bytes()
        }
        _ => {
            let mut t = good.clone();
            for (i, &b) in rest.iter().enumerate().take(8) {
                let at = (b as usize * 7 + i) % t.len();
                t[at] = rest.get(i + 8).copied().unwrap_or(b'A');
            }
            t
        }
    };
    let now = 1_800_000_000;
    let batch: Vec<&[u8]> = vec![&good, &tok, &good];
    let mut out = vec![Err(Error::Invalid); 3];
    (a.rust)(&batch, now, &mut out);
    let c = a.c.verify_batch(&batch, now);
    for (o, c) in out.iter().zip(&c) {
        let cw = if c.status == 0 { (0, c.uid, c.username.clone()) } else { (c.status, 0, vec![]) };
        assert_eq!(flat(o), cw);
    }
    assert!(out[0].is_ok() && out[2].is_ok());
    let mut one = [Err(Error::Invalid)];
    (a.rust)(&[&tok], now, &mut one);
    assert_eq!(flat(&one[0]), flat(&out[1]));
});
