//! RS256: RSASSA-PKCS1-v1_5 with SHA-256, verification only (the C library's portable design).
//!
//! s^e mod n with e = 65537 is 16 squarings and one multiplication.  The key holds R^2 mod n and -n^-1 mod 2^64,
//! and the expected EMSA-PKCS1-v1_5 block is compared word-wise, so the decrypted block is never parsed.
//! Montgomery multiplication is product scanning (one column of a b + m n at a time in a 3-word accumulator),
//! and squaring computes each a_j a_k (j < k) once and doubles it: 16 of RS256's 18 products are squarings.  The
//! loops are instantiated for 2048, 3072 and 4096-bit moduli so their trip counts are constants.
#![forbid(unsafe_code)]

use super::{hash_limbs, PkAlg, CHUNK};

/// Limbs of the largest modulus (4096 bits).
const MAXL: usize = 64;

/// An RS256 public key.
#[derive(Clone)]
pub struct Rs256Key {
    nl: usize,
    k: usize,
    n0: u64,
    e: u64,
    n: [u64; MAXL],
    r2: [u64; MAXL],
    em: [u64; MAXL],
}

impl core::fmt::Debug for Rs256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Rs256Key({} bits)", 8 * self.k)
    }
}

/// (c0, c1, c2) += x y
#[inline(always)]
fn mac(c: &mut (u64, u64, u64), x: u64, y: u64) {
    let z = x as u128 * y as u128;
    let s = c.0 as u128 + (z as u64) as u128;
    c.0 = s as u64;
    let s = c.1 as u128 + (z >> 64) + (s >> 64);
    c.1 = s as u64;
    c.2 = c.2.wrapping_add((s >> 64) as u64);
}

/// r = t - n if that does not borrow past `top`, else t.
#[inline(always)]
fn fin(r: &mut [u64], t: &[u64], top: u64, n: &[u64]) {
    let mut d = [0u64; MAXL];
    let mut bw = 0u64;
    for j in 0..t.len() {
        let z = (t[j] as u128).wrapping_sub(n[j] as u128 + bw as u128);
        d[j] = z as u64;
        bw = (z >> 127) as u64;
    }
    r.copy_from_slice(if top >= bw { &d[..t.len()] } else { t });
}

/// The m n half of column i, shared by mul and sqr; `c` holds the a b part of the column.
#[inline(always)]
fn col(c: &mut (u64, u64, u64), i: usize, m: &mut [u64], t: &mut [u64], n: &[u64], n0: u64) {
    let nl = n.len();
    // (zipped slices, not indices: the bounds are checked once per column, not once per product)
    if i < nl {
        for (x, y) in m[..i].iter().zip(n[1..=i].iter().rev()) {
            mac(c, *x, *y);
        }
        m[i] = c.0.wrapping_mul(n0);
        mac(c, m[i], n[0]);
    } else {
        for (x, y) in m[i - nl + 1..nl].iter().zip(n[i - nl + 1..nl].iter().rev()) {
            mac(c, *x, *y);
        }
        t[i - nl] = c.0;
    }
    *c = (c.1, c.2, 0);
}

/// r = a b R^-1 mod n for a, b < n.
#[inline(always)]
fn mont_mul(r: &mut [u64], a: &[u64], b: &[u64], n: &[u64], n0: u64) {
    let nl = n.len();
    let (mut m, mut t) = ([0u64; MAXL], [0u64; MAXL]);
    let mut c = (0u64, 0u64, 0u64);
    for i in 0..2 * nl - 1 {
        let (lo, hi) = if i < nl { (0, i) } else { (i - nl + 1, nl - 1) };
        for (x, y) in a[lo..=hi].iter().zip(b[i - hi..=i - lo].iter().rev()) {
            mac(&mut c, *x, *y);
        }
        col(&mut c, i, &mut m[..nl], &mut t[..nl], n, n0);
    }
    t[nl - 1] = c.0;
    fin(r, &t[..nl], c.1, n);
}

/// r = a^2 R^-1 mod n for a < n.
#[inline(always)]
fn mont_sqr(r: &mut [u64], a: &[u64], n: &[u64], n0: u64) {
    let nl = n.len();
    let (mut m, mut t) = ([0u64; MAXL], [0u64; MAXL]);
    let mut c = (0u64, 0u64, 0u64);
    for i in 0..2 * nl - 1 {
        let lo = if i < nl { 0 } else { i - nl + 1 };
        // the sum of a_j a_(i-j) for j < i - j, then doubled
        let mut q = (0u64, 0u64, 0u64);
        let hx = i.div_ceil(2).max(lo); // j < i - j  <=>  j < ceil(i / 2)
        for (x, y) in a[lo..hx].iter().zip(a[i + 1 - hx..=i - lo].iter().rev()) {
            mac(&mut q, *x, *y);
        }
        q = (q.0 << 1, q.1 << 1 | q.0 >> 63, q.2 << 1 | q.1 >> 63);
        if i & 1 == 0 {
            mac(&mut q, a[i >> 1], a[i >> 1]);
        }
        let s = c.0 as u128 + q.0 as u128;
        c.0 = s as u64;
        let s = c.1 as u128 + q.1 as u128 + (s >> 64);
        c.1 = s as u64;
        c.2 = c.2.wrapping_add(q.2).wrapping_add((s >> 64) as u64);
        col(&mut c, i, &mut m[..nl], &mut t[..nl], n, n0);
    }
    t[nl - 1] = c.0;
    fin(r, &t[..nl], c.1, n);
}

/// x = s^e R mod n from sR (Montgomery domain); left-to-right binary.
#[inline(always)]
fn pow(x: &mut [u64], sr: &[u64], e: u64, n: &[u64], n0: u64) {
    x.copy_from_slice(sr);
    let mut t = [0u64; MAXL];
    let t = &mut t[..n.len()];
    for b in (0..63 - e.leading_zeros()).rev() {
        mont_sqr(t, x, n, n0);
        if e >> b & 1 != 0 {
            mont_mul(x, t, sr, n, n0);
        } else {
            x.copy_from_slice(t);
        }
    }
}

/// s^e mod n == em, with `nl` limbs (a constant in each instantiation below).
#[inline(always)]
fn check_n(k: &Rs256Key, nl: usize, s: &[u64], em: &[u64]) -> bool {
    let n = &k.n[..nl];
    let mut sr = [0u64; MAXL];
    let mut x = [0u64; MAXL];
    let mut one = [0u64; MAXL];
    one[0] = 1;
    mont_mul(&mut sr[..nl], s, &k.r2[..nl], n, k.n0);
    pow(&mut x[..nl], &sr[..nl], k.e, n, k.n0);
    let mut y = [0u64; MAXL];
    mont_mul(&mut y[..nl], &x[..nl], &one[..nl], n, k.n0);
    y[..nl].iter().zip(em).fold(0, |d, (a, b)| d | (a ^ b)) == 0
}

fn check_32(k: &Rs256Key, s: &[u64], em: &[u64]) -> bool {
    check_n(k, 32, s, em)
}
fn check_48(k: &Rs256Key, s: &[u64], em: &[u64]) -> bool {
    check_n(k, 48, s, em)
}
fn check_64(k: &Rs256Key, s: &[u64], em: &[u64]) -> bool {
    check_n(k, 64, s, em)
}

/// DigestInfo prefix of SHA-256 (RFC 8017 section 9.2).
const SHA256_DI: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Big-endian bytes into little-endian limbs (`b.len() <= 8 o.len()`).
fn be_limbs(o: &mut [u64], b: &[u8]) {
    o.fill(0);
    for (i, &x) in b.iter().rev().enumerate() {
        o[i >> 3] |= (x as u64) << (8 * (i & 7));
    }
}

impl Rs256Key {
    /// Modulus and public exponent, big-endian: a 2048..4096-bit odd n and an odd e in [3, 2^64).  `None`
    /// otherwise.
    pub fn new(n: &[u8], e: &[u8]) -> Option<Self> {
        let n = &n[n.iter().position(|&b| b != 0).unwrap_or(n.len())..];
        let e = &e[e.iter().position(|&b| b != 0).unwrap_or(e.len())..];
        if !(256..=512).contains(&n.len())
            || n.last()? & 1 == 0
            || e.is_empty()
            || e.len() > 8
            || e.last()? & 1 == 0
        {
            return None;
        }
        let ev = e.iter().fold(0u64, |v, &b| v << 8 | b as u64);
        if ev < 3 {
            return None;
        }
        let k = n.len();
        let nl = k.div_ceil(8);
        let mut key = Rs256Key {
            nl,
            k,
            n0: 0,
            e: ev,
            n: [0; MAXL],
            r2: [0; MAXL],
            em: [0; MAXL],
        };
        be_limbs(&mut key.n[..nl], n);
        // Newton: n^-1 mod 2^64
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(key.n[0].wrapping_mul(inv)));
        }
        key.n0 = inv.wrapping_neg();
        // R^2 mod n by doubling 1 2 * 64 * nl times
        let mut x = [0u64; MAXL];
        x[0] = 1;
        let nn = &key.n[..nl];
        for _ in 0..2 * 64 * nl {
            let mut c = 0;
            for v in x[..nl].iter_mut() {
                let t = *v;
                *v = t << 1 | c;
                c = t >> 63;
            }
            let ge = c != 0 || {
                let mut ge = true;
                for j in (0..nl).rev() {
                    if x[j] != nn[j] {
                        ge = x[j] > nn[j];
                        break;
                    }
                }
                ge
            };
            if ge {
                let mut bw = 0u64;
                for j in 0..nl {
                    let z = (x[j] as u128).wrapping_sub(nn[j] as u128 + bw as u128);
                    x[j] = z as u64;
                    bw = (z >> 127) as u64;
                }
            }
        }
        key.r2[..nl].copy_from_slice(&x[..nl]);
        // EM = 00 01 FF..FF 00 DigestInfo H, with H = 0 (the hash goes into limbs 0..3 per token)
        let mut em = [0u8; 512];
        let ps = k - 3 - 19 - 32;
        em[1] = 1;
        em[2..2 + ps].fill(0xff);
        em[3 + ps..3 + ps + 19].copy_from_slice(&SHA256_DI);
        be_limbs(&mut key.em[..nl], &em[..k]);
        Some(key)
    }

    fn lt_n(&self, s: &[u64]) -> bool {
        for j in (0..self.nl).rev() {
            if s[j] != self.n[j] {
                return s[j] < self.n[j];
            }
        }
        false
    }
}

impl PkAlg for Rs256Key {
    const NAME: &'static [u8] = b"RS256";
    const CANON: &'static [u8; 36] = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";

    fn sig_bytes(&self) -> usize {
        self.k
    }

    fn verify_chunk(&self, msg: &[&[u8]], sig: &[&[u8]], ok: &mut [bool]) {
        let mut hs = [[0u64; 4]; CHUNK];
        hash_limbs(msg, &mut hs[..msg.len()]);
        let nl = self.nl;
        let check: fn(&Rs256Key, &[u64], &[u64]) -> bool = match nl {
            32 => check_32,
            48 => check_48,
            64 => check_64,
            _ => |k, s, em| check_n(k, k.nl, s, em),
        };
        for (i, (s, h)) in sig.iter().zip(&hs).enumerate() {
            let mut sl = [0u64; MAXL];
            be_limbs(&mut sl[..nl], s);
            if !self.lt_n(&sl) {
                ok[i] = false;
                continue;
            }
            let mut em = self.em;
            em[..4].copy_from_slice(h);
            ok[i] = check(self, &sl[..nl], &em[..nl]);
        }
    }
}
