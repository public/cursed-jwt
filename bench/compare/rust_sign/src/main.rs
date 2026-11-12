// jsonwebtoken 9 signing: HS256 and EdDSA tokens of the claims set of bench/bench_sign.c (a serde struct, the common
// usage), plus ring's and ed25519-dalek's raw Ed25519 sign.  ns/token, best of 5 passes.
use ed25519_dalek::Signer;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Serialize;
use std::time::Instant;

#[derive(Serialize)]
struct Claims {
    sub: String,
    username: String,
    iat: u64,
    exp: u64,
}

// the signing input of bench/bench_sign.c's claims set under the EdDSA header
const SI: &[u8] = b"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJ1c2VybmFtZSI6ImFsaWNlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9";

fn best<F: FnMut()>(name: &str, mut f: F) {
    let mut b = f64::MAX;
    for _ in 0..5 {
        let t0 = Instant::now();
        let mut n = 0u64;
        while t0.elapsed().as_millis() < 200 {
            for _ in 0..64 {
                f();
            }
            n += 64;
        }
        b = b.min(t0.elapsed().as_nanos() as f64 / n as f64);
    }
    println!("  {:<34} b1   {:9.1} ns/token", name, b);
}

fn main() {
    let c = Claims {
        sub: "123456".into(),
        username: "alice".into(),
        iat: 1700000000,
        exp: 4102444800,
    };
    let hk = EncodingKey::from_secret(b"bench-secret-0123456789abcdef0123");
    let seed: Vec<u8> = (0..32u32).map(|i| (i * 7 + 1) as u8).collect();
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    // PKCS#8 v1 for an Ed25519 seed: the fixed 16-byte prefix, then the seed
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    der.extend_from_slice(&seed);
    let ek = EncodingKey::from_ed_der(&der);
    let mut sink = 0usize;
    let hh = Header::new(Algorithm::HS256);
    let he = Header::new(Algorithm::EdDSA);
    best("jsonwebtoken HS256 encode", || {
        sink += encode(&hh, &c, &hk).unwrap().len()
    });
    best("jsonwebtoken EdDSA encode", || {
        sink += encode(&he, &c, &ek).unwrap().len()
    });
    best("ring Ed25519 sign (raw)", || sink += kp.sign(SI).as_ref().len());
    let dk = ed25519_dalek::SigningKey::from_bytes(&seed.clone().try_into().unwrap());
    best("ed25519-dalek sign (raw)", || sink += dk.sign(SI).to_bytes().len());
    // ES256: a PKCS#8 P-256 key generated once (ring signs with a random nonce mixed with the key)
    let rng = SystemRandom::new();
    let p8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let ek = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, p8.as_ref(), &rng).unwrap();
    best("ring ECDSA P-256 sign (raw)", || {
        sink += ek.sign(&rng, SI).unwrap().as_ref().len()
    });
    let _ = kp.public_key();
    if sink == 42 {
        println!();
    }
}
