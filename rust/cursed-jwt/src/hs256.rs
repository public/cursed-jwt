//! The HS256 batch front end: split, header, signature decode, one multi-buffer HMAC call per chunk,
//! constant-time tag compare, then payload base64url, JSON and claims for the tokens whose tag matched.
#![forbid(unsafe_code)]

use crate::engine::{b64_decode, Engine};
use crate::json::{self, Now};
use crate::sha256::{Midstates, CH};
use crate::{Claims, Error, Verdict, TOKEN_MAX};

/// `{"alg":"HS256","typ":"JWT"}`, the header nearly every token carries: skips the header parse.
const CANON_HDR: &[u8; 36] = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

/// An HS256 secret, prepared once: the HMAC ipad/opad midstates.
///
/// Every call recomputes every signature; nothing is cached across calls except these midstates, which are a
/// function of the secret alone.
#[derive(Clone)]
pub struct Hs256Key {
    pub(crate) m: Midstates,
}

impl core::fmt::Debug for Hs256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hs256Key(..)")
    }
}

impl Hs256Key {
    /// A secret of any length (longer than 64 bytes is hashed first, per RFC 2104).
    pub fn new(secret: &[u8]) -> Self {
        Hs256Key {
            m: Midstates::new(secret),
        }
    }

    /// Verifies one token (the bytes after `Bearer `).  `now` is the current Unix time in whole seconds; a
    /// token is live iff `nbf <= now < exp`.
    pub fn verify(&self, token: &[u8], now: i64) -> Verdict {
        let mut out = [Err(Error::Invalid)];
        self.verify_batch(&[token], now, &mut out);
        let [r] = out;
        r
    }

    /// Verifies `tokens[i]` into `out[i]` with the best engine for this CPU.  If the slices differ in length,
    /// only the common prefix is verified.
    pub fn verify_batch<T: AsRef<[u8]>>(&self, tokens: &[T], now: i64, out: &mut [Verdict]) {
        verify(&self.m, Engine::default_cached(), tokens, now, out);
    }

    /// [`Hs256Key::verify_batch`] on a chosen engine (for tests and benchmarks).
    pub fn verify_batch_with<T: AsRef<[u8]>>(
        &self,
        engine: Engine,
        tokens: &[T],
        now: i64,
        out: &mut [Verdict],
    ) {
        verify(&self.m, engine, tokens, now, out);
    }

    /// Raw HMAC-SHA256 tags of `msgs` on `engine` (for tests and benchmarks).
    pub fn hmac_batch(&self, engine: Engine, msgs: &[&[u8]], tags: &mut [[u8; 32]]) {
        for (mc, tc) in msgs.chunks(CH).zip(tags.chunks_mut(CH)) {
            let mut w = [[0u32; 8]; CH];
            engine.hmac(&self.m, mc, &mut w[..mc.len()]);
            for (t, w) in tc.iter_mut().zip(&w) {
                *t = crate::sha256::words_to_bytes(w);
            }
        }
    }
}

/// Splits a token into header, payload and signature and checks the header: `(d1, d2)`, the two dot positions.
///
/// Fast path for the canonical 36-character header: it has no '.', so d1 = 36, and the signature has a fixed
/// length, so d2 is fixed too; that skips both scans.  A '.' inside the payload, which the scans would have
/// rejected here, is rejected later instead (the payload is not base64url), so the result is the same.
#[inline(always)]
pub(crate) fn split_header(
    t: &[u8],
    sig_chars: usize,
    canon: &[u8; 36],
    alg: &[u8],
    sc: &mut Scratch,
) -> Option<(usize, usize)> {
    if t.len() > 36 + 2 + sig_chars && t.len() <= TOKEN_MAX {
        let d2 = t.len() - 1 - sig_chars;
        if t[36] == b'.' && t[d2] == b'.' && t.first_chunk::<36>() == Some(canon) {
            return Some((36, d2));
        }
    }
    let (d1, d2) = split(t, sig_chars)?;
    header_ok(&t[..d1], canon, alg, sc).then_some((d1, d2))
}

/// Splits a token into header, payload and signature, all non-empty, the signature `sig_chars` long.
#[inline(always)]
pub(crate) fn split(t: &[u8], sig_chars: usize) -> Option<(usize, usize)> {
    if t.is_empty() || t.len() > TOKEN_MAX {
        return None;
    }
    let d1 = memchr(b'.', t)?;
    let d2 = d1 + 1 + memchr(b'.', &t[d1 + 1..])?;
    if t.len() - (d2 + 1) != sig_chars || d1 == 0 || d2 == d1 + 1 {
        return None;
    }
    Some((d1, d2))
}

#[inline(always)]
fn memchr(c: u8, s: &[u8]) -> Option<usize> {
    memchr::memchr(c, s)
}

/// Scratch space for decoding a header or payload: a small buffer for the usual sizes, a token-sized one only
/// when needed (both zero-initialised on first use, never per token).
pub(crate) struct Scratch {
    small: [u8; SMALL],
    mid: Option<[u8; MID]>,
    big: Option<[u8; BIG]>,
}

const SMALL: usize = 256;
const MID: usize = 1024;
const BIG: usize = crate::b64::decoded_cap(TOKEN_MAX);

impl Scratch {
    pub fn new() -> Self {
        Scratch {
            small: [0; SMALL],
            mid: None,
            big: None,
        }
    }

    /// base64url-decodes `src` and returns the bytes, or `None` if it is not canonical base64url.
    #[inline(always)]
    pub fn decode(&mut self, src: &[u8]) -> Option<&[u8]> {
        let need = crate::b64::decoded_cap(src.len());
        let buf: &mut [u8] = if need <= SMALL {
            &mut self.small
        } else if need <= MID {
            self.mid.get_or_insert([0; MID])
        } else {
            self.big.get_or_insert([0; BIG])
        };
        let n = b64_decode(buf, src)?;
        buf.get(..n)
    }
}

/// The header check shared with the public-key algorithms: the canonical header, or a JSON header whose `alg`
/// is exactly `alg`.
#[inline(always)]
fn header_ok(h64: &[u8], canon: &[u8; 36], alg: &[u8], sc: &mut Scratch) -> bool {
    h64.first_chunk::<36>() == Some(canon) && h64.len() == 36
        || sc.decode(h64).is_some_and(|h| json::header_ok(h, alg))
}

/// Payload of a token whose signature checked out: base64url, JSON, claims, written into `r` in place.  A slot
/// that already holds `Ok` (a result buffer reused across calls) is refilled rather than rebuilt, which saves
/// initialising a username buffer per token.
#[inline(always)]
pub(crate) fn claims_one(p64: &[u8], now: &Now, sc: &mut Scratch, r: &mut Verdict) {
    let Some(pl) = sc.decode(p64) else {
        *r = Err(Error::Invalid);
        return;
    };
    if r.is_err() {
        *r = Ok(Claims::EMPTY);
    }
    if let Ok(c) = r {
        if let Err(e) = json::claims(pl, now, c) {
            *r = Err(e);
        }
    }
}

/// Constant-time tag comparison over all 32 bytes, as the C code does it: one OR of the word differences, kept
/// opaque to the optimiser so it cannot become an early-exit compare.
#[inline(always)]
fn tag_eq(a: &[u32; 8], b: &[u32; 8]) -> bool {
    let d = a.iter().zip(b).fold(0u32, |d, (x, y)| d | (x ^ y));
    core::hint::black_box(d) == 0
}

/// Big-endian words of a 32-byte tag.
#[inline(always)]
pub(crate) fn be_words(b: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for (w, c) in w.iter_mut().zip(b.as_chunks::<4>().0) {
        *w = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    w
}

/// Structure, header and signature encoding of one token: the expected tag and the two dot positions.
#[inline(always)]
fn candidate(t: &[u8], sc: &mut Scratch) -> Option<([u32; 8], (usize, usize))> {
    let (d1, d2) = split_header(t, 43, CANON_HDR, b"HS256", sc)?;
    let mut sb = [0u8; 64];
    if b64_decode(&mut sb, &t[d2 + 1..]) != Some(32) {
        return None;
    }
    Some((be_words(sb.first_chunk::<32>()?), (d1, d2)))
}

fn verify<T: AsRef<[u8]>>(k: &Midstates, eng: Engine, toks: &[T], now: i64, out: &mut [Verdict]) {
    // chunk buffers sized to the batch, so a single token does not initialise sixteen tokens' worth
    if toks.len() == 1 {
        verify_ch::<T, 1>(k, eng, toks, now, out)
    } else if toks.len() <= 4 {
        verify_ch::<T, 4>(k, eng, toks, now, out)
    } else {
        verify_ch::<T, CH>(k, eng, toks, now, out)
    }
}

#[inline(always)]
fn verify_ch<T: AsRef<[u8]>, const C: usize>(
    k: &Midstates,
    eng: Engine,
    toks: &[T],
    now: i64,
    out: &mut [Verdict],
) {
    let jn = Now::new(now);
    let mut sc = Scratch::new();
    for (tc, oc) in toks.chunks(C).zip(out.chunks_mut(C)) {
        let mut msg: [&[u8]; C] = [&[]; C];
        let mut want = [[0u32; 8]; C];
        let mut idx = [0u8; C];
        let mut poff = [0usize; C];
        let mut c = 0;
        for (i, (t, r)) in tc.iter().zip(oc.iter_mut()).enumerate() {
            // a candidate's slot is written after its MAC check; every other token's here
            let t = t.as_ref();
            let Some(sig) = candidate(t, &mut sc) else {
                *r = Err(Error::Invalid);
                continue;
            };
            let (d1, d2) = sig.1;
            want[c] = sig.0;
            msg[c] = &t[..d2];
            idx[c] = i as u8;
            poff[c] = d1 + 1;
            c += 1;
        }
        let mut mac = [[0u32; 8]; C];
        eng.hmac(k, &msg[..c], &mut mac[..c]);
        for j in 0..c {
            let Some(r) = oc.get_mut(idx[j] as usize) else {
                continue;
            };
            // constant time over all 32 bytes
            if !tag_eq(&mac[j], &want[j]) {
                *r = Err(Error::Invalid);
                continue;
            }
            claims_one(&msg[j][poff[j]..], &jn, &mut sc, r);
        }
    }
}
