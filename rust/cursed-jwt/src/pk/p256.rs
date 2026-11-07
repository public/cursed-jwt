//! ES256: ECDSA on P-256 with comb tables for both G and the public point (the C library's design).
//!
//! R = u1 G + u2 Q.  Key setup builds signed-digit comb tables of k 2^(W j) P for P = G and P = Q, so a verify
//! is 2 ceil(257/W) mixed additions and no doublings.  The x-coordinate check is projective (X == r Z^2), so no
//! inversion per token, and the s^-1 of a chunk share one inversion (Montgomery's trick).
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use fiat_crypto::p256_64 as fp;
use fiat_crypto::p256_scalar_64 as fs;

use super::{hash_limbs, PkAlg, CHUNK};

/// Comb window: 33 rows of 128 points per base point, 264 KB each.
const W: usize = 8;
const NW: usize = 257_usize.div_ceil(W);
const H: usize = 1 << (W - 1);

/// Little-endian 64-bit limbs; field elements are in fiat's Montgomery domain.
type Fe = [u64; 4];

#[derive(Clone, Copy, Default)]
struct Aff {
    x: Fe,
    y: Fe,
}

#[derive(Clone, Copy)]
struct Jac {
    x: Fe,
    y: Fe,
    z: Fe,
    inf: bool,
}

const P: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0,
    0xffff_ffff_0000_0001,
];
const N: [u64; 4] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];
const B: [u8; 32] = hex32("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
const GX: [u8; 32] = hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
const GY: [u8; 32] = hex32("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut o = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        o[i] = nib(b[2 * i]) << 4 | nib(b[2 * i + 1]);
        i += 1;
    }
    o
}

const fn nib(c: u8) -> u8 {
    if c <= b'9' {
        c - b'0'
    } else {
        c - b'a' + 10
    }
}

/// Big-endian bytes to little-endian limbs.
fn limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut o = [0u64; 4];
    for (i, o) in o.iter_mut().enumerate() {
        let c = &b[8 * (3 - i)..8 * (4 - i)];
        *o = u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    }
    o
}

fn lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn is_zero(a: &[u64; 4]) -> bool {
    a.iter().all(|&x| x == 0)
}

fn to_mont(a: &[u64; 4]) -> Fe {
    let mut o = fp::fiat_p256_montgomery_domain_field_element([0; 4]);
    fp::fiat_p256_to_montgomery(
        &mut o,
        &fp::fiat_p256_non_montgomery_domain_field_element(*a),
    );
    o.0
}

fn one() -> Fe {
    let mut o = fp::fiat_p256_montgomery_domain_field_element([0; 4]);
    fp::fiat_p256_set_one(&mut o);
    o.0
}

// ---- field: a + b, a - b, a b for a, b < p ----

#[inline(always)]
fn add(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u64; 4];
    let mut c = 0u64;
    for i in 0..4 {
        let z = a[i] as u128 + b[i] as u128 + c as u128;
        t[i] = z as u64;
        c = (z >> 64) as u64;
    }
    let mut r = [0u64; 4];
    let mut bw = 0u64;
    for i in 0..4 {
        let d = (t[i] as u128).wrapping_sub(P[i] as u128 + bw as u128);
        r[i] = d as u64;
        bw = (d >> 127) as u64;
    }
    // borrow and no carry: a + b < p
    if bw & !c & 1 != 0 {
        t
    } else {
        r
    }
}

#[inline(always)]
fn sub(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u64; 4];
    let mut bw = 0u64;
    for i in 0..4 {
        let d = (a[i] as u128).wrapping_sub(b[i] as u128 + bw as u128);
        t[i] = d as u64;
        bw = (d >> 127) as u64;
    }
    let mask = 0u64.wrapping_sub(bw);
    let mut c = 0u64;
    for i in 0..4 {
        let z = t[i] as u128 + (P[i] & mask) as u128 + c as u128;
        t[i] = z as u64;
        c = (z >> 64) as u64;
    }
    t
}

#[inline(always)]
fn neg(a: &Fe) -> Fe {
    sub(&[0; 4], a)
}

const P1: u64 = 0x0000_0000_ffff_ffff;
const P3: u64 = 0xffff_ffff_0000_0001;

/// a b / 2^256 mod p (Montgomery, CIOS).  p's limbs are 2^64-1, 2^32-1, 0, 2^64-2^32+1 and -p^-1 = 1 mod 2^64, so
/// each reduction round takes m = t0 and needs two multiplications instead of four (as OpenSSL's ecp_nistz256
/// does).  The tests cross-check it against fiat_p256_mul.
#[inline(always)]
fn mul(a: &Fe, b: &Fe) -> Fe {
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for &bi in b {
        let bi = bi as u128;
        let z = a[0] as u128 * bi + t0 as u128;
        t0 = z as u64;
        let z = a[1] as u128 * bi + t1 as u128 + (z >> 64);
        t1 = z as u64;
        let z = a[2] as u128 * bi + t2 as u128 + (z >> 64);
        t2 = z as u64;
        let z = a[3] as u128 * bi + t3 as u128 + (z >> 64);
        t3 = z as u64;
        let z = t4 as u128 + (z >> 64);
        t4 = z as u64;
        let t5 = (z >> 64) as u64;
        // t0 + m (2^64 - 1) = m 2^64: limb 0 becomes 0 and carries m
        let m = t0 as u128;
        let z = m * P1 as u128 + t1 as u128 + m;
        t0 = z as u64;
        let z = t2 as u128 + (z >> 64);
        t1 = z as u64;
        let z = m * P3 as u128 + t3 as u128 + (z >> 64);
        t2 = z as u64;
        let z = t4 as u128 + (z >> 64);
        t3 = z as u64;
        t4 = t5 + (z >> 64) as u64;
    }
    // t < 2p: subtract p once if t >= p
    let t = [t0, t1, t2, t3];
    let mut r = [0u64; 4];
    let mut bw = 0u64;
    for i in 0..4 {
        let d = (t[i] as u128).wrapping_sub(P[i] as u128 + bw as u128);
        r[i] = d as u64;
        bw = (d >> 127) as u64;
    }
    if t4 >= bw {
        r
    } else {
        t
    }
}

#[inline(always)]
fn sqr(a: &Fe) -> Fe {
    mul(a, a)
}

/// a^(p-2): key setup only.
fn inv(a: &Fe) -> Fe {
    let mut e = P;
    e[0] -= 2;
    let mut r = one();
    for i in (0..256).rev() {
        r = sqr(&r);
        if e[i >> 6] >> (i & 63) & 1 != 0 {
            r = mul(&r, a);
        }
    }
    r
}

// ---- points ----

/// dbl-2001-b (a = -3), 3M + 5S
fn dbl(p: &Jac) -> Jac {
    if p.inf || is_zero(&p.y) {
        return Jac { inf: true, ..*p };
    }
    let delta = sqr(&p.z);
    let gamma = sqr(&p.y);
    let beta = mul(&p.x, &gamma);
    let a = mul(&sub(&p.x, &delta), &add(&p.x, &delta));
    let alpha = add(&a, &add(&a, &a)); // 3 (X - delta)(X + delta)
    let z = sub(&sub(&sqr(&add(&p.y, &p.z)), &gamma), &delta);
    let b2 = add(&beta, &beta);
    let b4 = add(&b2, &b2);
    let x = sub(&sqr(&alpha), &add(&b4, &b4));
    let g2 = sqr(&gamma);
    let g2 = add(&g2, &g2);
    let g2 = add(&g2, &g2);
    let g8 = add(&g2, &g2); // 8 gamma^2
    let y = sub(&mul(&alpha, &sub(&b4, &x)), &g8);
    Jac {
        x,
        y,
        z,
        inf: false,
    }
}

/// p += q (affine), madd-2007-bl, 7M + 4S; the exceptional cases (q = +-p) branch.
fn madd(p: &mut Jac, qx: &Fe, qy: &Fe) {
    if p.inf {
        *p = Jac {
            x: *qx,
            y: *qy,
            z: one(),
            inf: false,
        };
        return;
    }
    let z1z1 = sqr(&p.z);
    let u2 = mul(qx, &z1z1);
    let s2 = mul(&mul(qy, &p.z), &z1z1);
    let h = sub(&u2, &p.x);
    let r = sub(&s2, &p.y);
    if is_zero(&h) {
        if is_zero(&r) {
            *p = dbl(p);
        } else {
            p.inf = true;
        }
        return;
    }
    let r = add(&r, &r);
    let hh = sqr(&h);
    let i = add(&hh, &hh);
    let i = add(&i, &i);
    let j = mul(&h, &i);
    let v = mul(&p.x, &i);
    let x3 = sub(&sub(&sub(&sqr(&r), &j), &v), &v);
    let z3 = sub(&sub(&sqr(&add(&p.z, &h)), &z1z1), &hh);
    let yj = mul(&p.y, &j);
    let y3 = sub(&mul(&r, &sub(&v, &x3)), &add(&yj, &yj));
    *p = Jac {
        x: x3,
        y: y3,
        z: z3,
        inf: false,
    };
}

#[inline(always)]
fn add_digit(acc: &mut Jac, row: &[Aff; H], d: i16) {
    if d > 0 {
        let q = &row[(d - 1) as usize];
        madd(acc, &q.x, &q.y);
    } else if d < 0 {
        let q = &row[(-d - 1) as usize];
        madd(acc, &q.x, &neg(&q.y));
    }
}

/// tab[w][k-1] = k 2^(W w) P in affine coordinates, k = 1..H.
fn table(px: &Fe, py: &Fe) -> Vec<[Aff; H]> {
    let mut tab = alloc::vec![[Aff::default(); H]; NW];
    let mut jac = alloc::vec![Jac { x: [0; 4], y: [0; 4], z: [0; 4], inf: true }; H];
    let mut pre = alloc::vec![[0u64; 4]; H];
    let (mut bx, mut by) = (*px, *py);
    for row in tab.iter_mut() {
        jac[0] = Jac {
            x: [0; 4],
            y: [0; 4],
            z: [0; 4],
            inf: true,
        };
        madd(&mut jac[0], &bx, &by);
        for k in 1..H {
            jac[k] = jac[k - 1];
            madd(&mut jac[k], &bx, &by);
        }
        // to affine with one inversion; no k B is infinity since k < n
        pre[0] = jac[0].z;
        for k in 1..H {
            pre[k] = mul(&pre[k - 1], &jac[k].z);
        }
        let mut iv = inv(&pre[H - 1]);
        for k in (0..H).rev() {
            let zi = if k > 0 {
                let zi = mul(&iv, &pre[k - 1]);
                iv = mul(&iv, &jac[k].z);
                zi
            } else {
                iv
            };
            let zi2 = sqr(&zi);
            row[k] = Aff {
                x: mul(&jac[k].x, &zi2),
                y: mul(&jac[k].y, &mul(&zi2, &zi)),
            };
        }
        // next base: 2^W B = 2 (H B)
        let d = dbl(&jac[H - 1]);
        let iv = inv(&d.z);
        let z2 = sqr(&iv);
        bx = mul(&d.x, &z2);
        by = mul(&d.y, &mul(&z2, &iv));
    }
    tab
}

fn on_curve(x: &Fe, y: &Fe) -> bool {
    // y^2 = x^3 - 3x + b
    let b = to_mont(&limbs(&B));
    let l = sqr(y);
    let r = mul(&sqr(x), x);
    let t = add(&add(x, x), x);
    let r = add(&sub(&r, &t), &b);
    l == r
}

/// u = sum d_w 2^(W w), d_w in [-H+1, H].
fn recode(u: &[u64; 4]) -> [i16; NW] {
    let mut d = [0i16; NW];
    let mut carry = 0i32;
    for (w, dw) in d.iter_mut().enumerate() {
        let bit = w * W;
        let (li, sh) = (bit >> 6, bit & 63);
        let mut v = if li < 4 { u[li] >> sh } else { 0 };
        if sh + W > 64 && li + 1 < 4 {
            v |= u[li + 1] << (64 - sh);
        }
        let c = (v & ((1 << W) - 1)) as i32 + carry;
        if c > H as i32 {
            *dw = (c - 2 * H as i32) as i16;
            carry = 1;
        } else {
            *dw = c as i16;
            carry = 0;
        }
    }
    d
}

// ---- scalars mod n ----

fn shr1(a: &mut [u64; 4], top: u64) {
    a[0] = a[0] >> 1 | a[1] << 63;
    a[1] = a[1] >> 1 | a[2] << 63;
    a[2] = a[2] >> 1 | a[3] << 63;
    a[3] = a[3] >> 1 | top << 63;
}

fn add256(r: &mut [u64; 4], b: &[u64; 4]) -> u64 {
    let mut c = 0u64;
    for i in 0..4 {
        let z = r[i] as u128 + b[i] as u128 + c as u128;
        r[i] = z as u64;
        c = (z >> 64) as u64;
    }
    c
}

/// r -= b, returning the borrow.
fn sub256(r: &mut [u64; 4], b: &[u64; 4]) -> u64 {
    let mut bw = 0u64;
    for i in 0..4 {
        let d = (r[i] as u128).wrapping_sub(b[i] as u128 + bw as u128);
        r[i] = d as u64;
        bw = (d >> 127) as u64;
    }
    bw
}

fn halve_mod_n(x: &mut [u64; 4]) {
    if x[0] & 1 != 0 {
        let c = add256(x, &N);
        shr1(x, c);
    } else {
        shr1(x, 0);
    }
}

fn sub_mod_n(r: &mut [u64; 4], b: &[u64; 4]) {
    if sub256(r, b) != 0 {
        add256(r, &N);
    }
}

fn is_one(a: &[u64; 4]) -> bool {
    a[0] == 1 && a[1] | a[2] | a[3] == 0
}

/// 1/a mod n for 0 < a < n, plain integers: binary extended Euclid.  Variable-time, which is fine: s is part of
/// the signature, public.  About 5x cheaper than a^(n-2).
fn sc_inv_plain(a: &[u64; 4]) -> [u64; 4] {
    let (mut u, mut v) = (*a, N);
    let (mut x1, mut x2) = ([1u64, 0, 0, 0], [0u64; 4]);
    while !is_one(&u) && !is_one(&v) {
        if is_zero(&u) || is_zero(&v) {
            return [0; 4]; // gcd != 1: cannot happen for 0 < a < n prime
        }
        while u[0] & 1 == 0 {
            shr1(&mut u, 0);
            halve_mod_n(&mut x1);
        }
        while v[0] & 1 == 0 {
            shr1(&mut v, 0);
            halve_mod_n(&mut x2);
        }
        if !lt(&u, &v) {
            sub256(&mut u, &v);
            sub_mod_n(&mut x1, &x2);
        } else {
            sub256(&mut v, &u);
            sub_mod_n(&mut x2, &x1);
        }
    }
    if is_one(&u) {
        x1
    } else {
        x2
    }
}

use fs::fiat_p256_scalar_montgomery_domain_field_element as Sc;

fn sc_to_mont(a: &[u64; 4]) -> Sc {
    let mut o = Sc([0; 4]);
    fs::fiat_p256_scalar_to_montgomery(
        &mut o,
        &fs::fiat_p256_scalar_non_montgomery_domain_field_element(*a),
    );
    o
}

fn sc_from_mont(a: &Sc) -> [u64; 4] {
    let mut o = fs::fiat_p256_scalar_non_montgomery_domain_field_element([0; 4]);
    fs::fiat_p256_scalar_from_montgomery(&mut o, a);
    o.0
}

fn sc_mul(a: &Sc, b: &Sc) -> Sc {
    let mut o = Sc([0; 4]);
    fs::fiat_p256_scalar_mul(&mut o, a, b);
    o
}

/// The same in fiat's Montgomery domain: (aR)^-1 R^3 / R = a^-1 R.
fn sc_inv(am: &Sc) -> Sc {
    let r3 = sc_to_mont(&sc_to_mont(&sc_to_mont(&[1, 0, 0, 0]).0).0);
    sc_mul(&Sc(sc_inv_plain(&am.0)), &r3)
}

/// An ES256 public key with its precomputed tables (528 KB).
#[derive(Clone)]
pub struct Es256Key {
    tg: Vec<[Aff; H]>,
    tq: Vec<[Aff; H]>,
}

impl core::fmt::Debug for Es256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Es256Key(..)")
    }
}

impl Es256Key {
    /// The public point's affine coordinates, big-endian.  `None` if it is not a point on P-256.
    pub fn new(x: &[u8; 32], y: &[u8; 32]) -> Option<Self> {
        let (xi, yi) = (limbs(x), limbs(y));
        if !lt(&xi, &P) || !lt(&yi, &P) {
            return None;
        }
        let (qx, qy) = (to_mont(&xi), to_mont(&yi));
        if !on_curve(&qx, &qy) {
            return None;
        }
        let tg = table(&to_mont(&limbs(&GX)), &to_mont(&limbs(&GY)));
        let tq = table(&qx, &qy);
        Some(Es256Key { tg, tq })
    }

    /// R = u1 G + u2 Q from the recoded digits, and the check x(R) mod n == r.
    fn check(&self, d1: &[i16; NW], d2: &[i16; NW], r: &[u64; 4]) -> bool {
        let mut acc = Jac {
            x: [0; 4],
            y: [0; 4],
            z: [0; 4],
            inf: true,
        };
        for j in 0..NW {
            add_digit(&mut acc, &self.tg[j], d1[j]);
            add_digit(&mut acc, &self.tq[j], d2[j]);
        }
        if acc.inf {
            return false;
        }
        // x(R) mod n == r  <=>  X == r' Z^2 for r' in {r, r + n} with r' < p
        let z2 = sqr(&acc.z);
        if mul(&to_mont(r), &z2) == acc.x {
            return true;
        }
        let mut rn = *r;
        let c = add256(&mut rn, &N);
        c == 0 && lt(&rn, &P) && mul(&to_mont(&rn), &z2) == acc.x
    }
}

impl PkAlg for Es256Key {
    const NAME: &'static [u8] = b"ES256";
    const CANON: &'static [u8; 36] = b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";

    fn sig_bytes(&self) -> usize {
        64
    }

    fn verify_chunk(&self, msg: &[&[u8]], sig: &[&[u8]], ok: &mut [bool]) {
        let mut hs = [[0u64; 4]; CHUNK];
        hash_limbs(msg, &mut hs[..msg.len()]);
        let mut r = [[0u64; 4]; CHUNK];
        let mut sm = [Sc([0; 4]); CHUNK];
        let mut em = [Sc([0; 4]); CHUNK];
        let mut at = [0usize; CHUNK];
        let mut c = 0;
        for (i, (s, h)) in sig.iter().zip(&hs).enumerate() {
            ok[i] = false;
            let Some((rb, sb)) = s.split_first_chunk::<32>() else {
                continue;
            };
            let Ok(sb) = <&[u8; 32]>::try_from(sb) else {
                continue;
            };
            let (ri, si) = (limbs(rb), limbs(sb));
            if is_zero(&ri) || is_zero(&si) || !lt(&ri, &N) || !lt(&si, &N) {
                continue;
            }
            let mut e = *h;
            if !lt(&e, &N) {
                sub256(&mut e, &N); // e < 2^256 < 2n: one subtraction
            }
            r[c] = ri;
            sm[c] = sc_to_mont(&si);
            em[c] = sc_to_mont(&e);
            at[c] = i;
            c += 1;
        }
        if c == 0 {
            return;
        }
        // every s^-1 with one inversion (Montgomery's trick), then u1 = e/s, u2 = r/s
        let mut pre = [Sc([0; 4]); CHUNK];
        pre[0] = sm[0];
        for i in 1..c {
            pre[i] = sc_mul(&pre[i - 1], &sm[i]);
        }
        let mut iv = sc_inv(&pre[c - 1]);
        for i in (0..c).rev() {
            let w = if i > 0 {
                let w = sc_mul(&iv, &pre[i - 1]);
                iv = sc_mul(&iv, &sm[i]);
                w
            } else {
                iv
            };
            let u1 = sc_from_mont(&sc_mul(&em[i], &w));
            let u2 = sc_from_mont(&sc_mul(&sc_to_mont(&r[i]), &w));
            ok[at[i]] = self.check(&recode(&u1), &recode(&u2), &r[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fiat_mul(a: &Fe, b: &Fe) -> Fe {
        let mut o = fp::fiat_p256_montgomery_domain_field_element([0; 4]);
        fp::fiat_p256_mul(
            &mut o,
            &fp::fiat_p256_montgomery_domain_field_element(*a),
            &fp::fiat_p256_montgomery_domain_field_element(*b),
        );
        o.0
    }

    /// The special-form multiplication against fiat-crypto's verified one, on random and edge inputs.
    #[test]
    fn mul_matches_fiat() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let pm1 = [P[0] - 1, P[1], P[2], P[3]];
        let edge = [
            [0u64; 4],
            [1, 0, 0, 0],
            pm1,
            [0, 0, 0, 1 << 63],
            [!0, 0, 0, 0],
        ];
        for i in 0..20000 {
            let mut a = [rnd(), rnd(), rnd(), rnd()];
            let mut b = [rnd(), rnd(), rnd(), rnd()];
            if i < 25 {
                a = edge[i % 5];
                b = edge[i / 5];
            }
            while !lt(&a, &P) {
                a[3] >>= 1;
            }
            while !lt(&b, &P) {
                b[3] >>= 1;
            }
            assert_eq!(mul(&a, &b), fiat_mul(&a, &b), "{a:x?} {b:x?}");
            let mut fa = fp::fiat_p256_montgomery_domain_field_element([0; 4]);
            fp::fiat_p256_add(
                &mut fa,
                &fp::fiat_p256_montgomery_domain_field_element(a),
                &fp::fiat_p256_montgomery_domain_field_element(b),
            );
            assert_eq!(add(&a, &b), fa.0);
            fp::fiat_p256_sub(
                &mut fa,
                &fp::fiat_p256_montgomery_domain_field_element(a),
                &fp::fiat_p256_montgomery_domain_field_element(b),
            );
            assert_eq!(sub(&a, &b), fa.0);
        }
    }

    #[test]
    fn scalar_inverse() {
        let a = [12345, 678, 9, 10];
        let i = sc_inv_plain(&a);
        let p = sc_from_mont(&sc_mul(&sc_to_mont(&a), &sc_to_mont(&i)));
        assert_eq!(p, [1, 0, 0, 0]);
    }
}
