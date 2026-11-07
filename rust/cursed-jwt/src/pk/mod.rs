//! RS256, ES256 and EdDSA (Ed25519): the same front end and claim rules as HS256, with a public key instead of a
//! secret.  The key fixes the algorithm: a token's header `alg` must equal it (no algorithm confusion).
//!
//! None of them batches the way HMAC does, but a verifier's key is long-lived, and key setup does the expensive
//! per-key work once (the C library's design, PK.md):
//! - ES256: signed-digit comb tables for both G and the public point Q, so a verify is two fixed-base
//!   multiplications with no doublings; the s^-1 of a chunk share one inversion.
//! - EdDSA: the same for B and -A, with complete twisted-Edwards additions; the R' of a chunk share one inversion.
//! - RS256: s^e mod n with Montgomery constants precomputed, product-scanning multiplication in fixed-size copies
//!   for 2048/3072/4096-bit moduli, and the expected PKCS#1 v1.5 block compared word-wise.
//!
//! The field and scalar arithmetic of P-256 and curve25519 is fiat-crypto's generated, formally verified Rust,
//! except P-256's field multiplication, which uses the special form of p (as the C code does; the tests
//! cross-check it against fiat's).  Verification handles only public data, so none of this is constant-time.
#![forbid(unsafe_code)]

use alloc::boxed::Box;

use crate::engine::{b64_decode, Engine};
use crate::hs256::{claims_one, split_header, Scratch};
use crate::json::Now;
use crate::{Error, Verdict};

pub(crate) mod ed25519;
mod p256;
mod rsa;

pub use ed25519::Ed25519Key;
pub use p256::Es256Key;
pub use rsa::Rs256Key;

/// What the front end needs from an algorithm.
pub(crate) trait PkAlg {
    /// `alg` as the header must spell it.
    const NAME: &'static [u8];
    /// `{"alg":"<NAME>","typ":"JWT"}` in base64url: skips the header parse.
    const CANON: &'static [u8; 36];
    /// Signature length in bytes (RS256: the modulus length).
    fn sig_bytes(&self) -> usize;
    /// `ok[i]` = whether `sig[i]` is a valid signature of `msg[i]`; every slice has the same length (at most
    /// [`CHUNK`]) and every signature is `sig_bytes()` long.
    fn verify_chunk(&self, msg: &[&[u8]], sig: &[&[u8]], ok: &mut [bool]);
}

/// Tokens per front-end chunk.
pub(crate) const CHUNK: usize = 16;

/// Largest signature: RSA-4096.
const SIG_MAX: usize = 512;

/// SHA-256 of each message through the multi-buffer engines, as 4 little-endian limbs of the big-endian digest.
pub(crate) fn hash_limbs(msgs: &[&[u8]], out: &mut [[u64; 4]]) {
    let mut d = [[0u32; 8]; CHUNK];
    for (mc, oc) in msgs.chunks(CHUNK).zip(out.chunks_mut(CHUNK)) {
        Engine::default_cached().sha256(mc, &mut d[..mc.len()]);
        for (o, d) in oc.iter_mut().zip(&d) {
            for w in 0..4 {
                o[3 - w] = (d[2 * w] as u64) << 32 | d[2 * w + 1] as u64;
            }
        }
    }
}

fn verify_batch<A: PkAlg, T: AsRef<[u8]>>(k: &A, toks: &[T], now: i64, out: &mut [Verdict]) {
    let jn = Now::new(now);
    let mut sc = Scratch::new();
    let sb = k.sig_bytes();
    let sig_chars = (sb * 4).div_ceil(3);
    let mut sbuf = [[0u8; SIG_MAX + 2]; CHUNK];
    for (tc, oc) in toks.chunks(CHUNK).zip(out.chunks_mut(CHUNK)) {
        let mut msg: [&[u8]; CHUNK] = [&[]; CHUNK];
        let mut idx = [0u8; CHUNK];
        let mut poff = [0usize; CHUNK];
        let mut c = 0;
        for (i, (t, r)) in tc.iter().zip(oc.iter_mut()).enumerate() {
            let t = t.as_ref();
            let good = split_header(t, sig_chars, A::CANON, A::NAME, &mut sc);
            let Some((d1, d2)) = good else {
                *r = Err(Error::Invalid);
                continue;
            };
            if b64_decode(&mut sbuf[c], &t[d2 + 1..]) != Some(sb) {
                *r = Err(Error::Invalid);
                continue;
            }
            msg[c] = &t[..d2];
            idx[c] = i as u8;
            poff[c] = d1 + 1;
            c += 1;
        }
        let mut sig: [&[u8]; CHUNK] = [&[]; CHUNK];
        for (s, b) in sig.iter_mut().zip(&sbuf).take(c) {
            *s = &b[..sb];
        }
        let mut ok = [false; CHUNK];
        k.verify_chunk(&msg[..c], &sig[..c], &mut ok[..c]);
        for j in 0..c {
            let Some(r) = oc.get_mut(idx[j] as usize) else {
                continue;
            };
            if ok[j] {
                claims_one(&msg[j][poff[j]..], &jn, &mut sc, r);
            } else {
                *r = Err(Error::Invalid);
            }
        }
    }
}

fn verify_signatures<A: PkAlg>(k: &A, msgs: &[&[u8]], sigs: &[&[u8]], ok: &mut [bool]) {
    for ((mc, sc), oc) in msgs
        .chunks(CHUNK)
        .zip(sigs.chunks(CHUNK))
        .zip(ok.chunks_mut(CHUNK))
    {
        // wrong-length signatures are rejected here; the rest go to the algorithm together
        let mut m: [&[u8]; CHUNK] = [&[]; CHUNK];
        let mut s: [&[u8]; CHUNK] = [&[]; CHUNK];
        let mut at = [0usize; CHUNK];
        let mut c = 0;
        for (i, (mi, si)) in mc.iter().zip(sc).enumerate() {
            oc[i] = false;
            if si.len() == k.sig_bytes() {
                (m[c], s[c], at[c]) = (mi, si, i);
                c += 1;
            }
        }
        let mut r = [false; CHUNK];
        k.verify_chunk(&m[..c], &s[..c], &mut r[..c]);
        for j in 0..c {
            oc[at[j]] = r[j];
        }
    }
}

macro_rules! pk_api {
    ($t:ty) => {
        impl $t {
            /// Verifies `tokens[i]` into `out[i]` (the same rules as [`crate::Hs256Key::verify_batch`]).  If the
            /// slices differ in length, only the common prefix is verified.
            pub fn verify_batch<T: AsRef<[u8]>>(
                &self,
                tokens: &[T],
                now: i64,
                out: &mut [Verdict],
            ) {
                verify_batch(self, tokens, now, out)
            }

            /// Verifies one token.
            pub fn verify(&self, token: &[u8], now: i64) -> Verdict {
                let mut out = [Err(Error::Invalid)];
                self.verify_batch(&[token], now, &mut out);
                let [r] = out;
                r
            }

            /// Raw signature checks: `ok[i]` = whether `sigs[i]` (JOSE format: r || s for ES256, R || S for
            /// EdDSA, the modulus length for RS256) signs `msgs[i]`.  For tests and benchmarks.
            pub fn verify_signatures(&self, msgs: &[&[u8]], sigs: &[&[u8]], ok: &mut [bool]) {
                verify_signatures(self, msgs, sigs, ok)
            }
        }
    };
}
pk_api!(Es256Key);
pk_api!(Rs256Key);
pk_api!(Ed25519Key);

/// Any of the three public-key algorithms.
#[derive(Clone, Debug)]
pub enum PublicKey {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256(Box<Rs256Key>),
    /// ECDSA on P-256 with SHA-256.
    Es256(Box<Es256Key>),
    /// Ed25519 (RFC 8037 `"alg":"EdDSA"`).
    EdDsa(Box<Ed25519Key>),
}

impl PublicKey {
    /// Verifies `tokens[i]` into `out[i]` with the key's algorithm.
    pub fn verify_batch<T: AsRef<[u8]>>(&self, tokens: &[T], now: i64, out: &mut [Verdict]) {
        match self {
            PublicKey::Rs256(k) => k.verify_batch(tokens, now, out),
            PublicKey::Es256(k) => k.verify_batch(tokens, now, out),
            PublicKey::EdDsa(k) => k.verify_batch(tokens, now, out),
        }
    }
}
