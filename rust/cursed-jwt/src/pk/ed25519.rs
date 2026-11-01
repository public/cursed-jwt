//! EdDSA (Ed25519, RFC 8032; JWS `"alg":"EdDSA"`, RFC 8037), verification only (the C library's design).
//!
//! Key setup builds signed-digit comb tables of k 2^(W j) P for the base point B and for -A, and a verify is
//!     R' = [S] B + [k] (-A),   k = SHA-512(R || A || M) mod L
//! with 2 ceil(254/W) mixed additions and no doublings.  Twisted Edwards addition with a = -1 is complete, so the
//! additions never branch.  The R' of a chunk are normalised with one shared inversion, and a signature is valid
//! iff encode(R') == R byte for byte, with S < L: RFC 8032's cofactorless check, the one OpenSSL (and so
//! pyca/cryptography and Wycheproof's valid set) implements.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use fiat_crypto::curve25519_64 as f;
use fiat_crypto::curve25519_scalar_64 as fsc;
use sha2::{Digest, Sha512};

use super::{PkAlg, CHUNK};

/// Comb window: 37 rows of 64 points per base point, 284 KB each.
const W: usize = 7;
const NW: usize = 254_usize.div_ceil(W);
const H: usize = 1 << (W - 1);

/// fiat's unsaturated 5 x 51-bit limbs, carried ("tight").
type Fe = [u64; 5];

#[derive(Clone, Copy)]
struct P3 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// y + x, y - x, 2 d x y of an affine point.
#[derive(Clone, Copy, Default)]
struct Niels {
    ypx: Fe,
    ymx: Fe,
    xy2d: Fe,
}

#[inline(always)]
fn mul(a: &Fe, b: &Fe) -> Fe {
    let mut o = f::fiat_25519_tight_field_element([0; 5]);
    f::fiat_25519_carry_mul(
        &mut o,
        &f::fiat_25519_loose_field_element(*a),
        &f::fiat_25519_loose_field_element(*b),
    );
    o.0
}

#[inline(always)]
fn sqr(a: &Fe) -> Fe {
    let mut o = f::fiat_25519_tight_field_element([0; 5]);
    f::fiat_25519_carry_square(&mut o, &f::fiat_25519_loose_field_element(*a));
    o.0
}

#[inline(always)]
fn carry(l: f::fiat_25519_loose_field_element) -> Fe {
    let mut o = f::fiat_25519_tight_field_element([0; 5]);
    f::fiat_25519_carry(&mut o, &l);
    o.0
}

#[inline(always)]
fn add(a: &Fe, b: &Fe) -> Fe {
    let mut l = f::fiat_25519_loose_field_element([0; 5]);
    f::fiat_25519_add(
        &mut l,
        &f::fiat_25519_tight_field_element(*a),
        &f::fiat_25519_tight_field_element(*b),
    );
    carry(l)
}

#[inline(always)]
fn sub(a: &Fe, b: &Fe) -> Fe {
    let mut l = f::fiat_25519_loose_field_element([0; 5]);
    f::fiat_25519_sub(
        &mut l,
        &f::fiat_25519_tight_field_element(*a),
        &f::fiat_25519_tight_field_element(*b),
    );
    carry(l)
}

#[inline(always)]
fn neg(a: &Fe) -> Fe {
    let mut l = f::fiat_25519_loose_field_element([0; 5]);
    f::fiat_25519_opp(&mut l, &f::fiat_25519_tight_field_element(*a));
    carry(l)
}

fn small(v: u64) -> Fe {
    [v, 0, 0, 0, 0]
}

fn to_bytes(a: &Fe) -> [u8; 32] {
    let mut o = [0u8; 32];
    f::fiat_25519_to_bytes(&mut o, &f::fiat_25519_tight_field_element(*a));
    o
}

fn from_bytes(b: &[u8; 32]) -> Fe {
    let mut o = f::fiat_25519_tight_field_element([0; 5]);
    f::fiat_25519_from_bytes(&mut o, b);
    o.0
}

/// a^e for e given little-endian.
fn pow(a: &Fe, e: &[u8; 32]) -> Fe {
    let mut r = small(1);
    for i in (0..256).rev() {
        r = sqr(&r);
        if e[i >> 3] >> (i & 7) & 1 != 0 {
            r = mul(&r, a);
        }
    }
    r
}

fn sqn(a: &Fe, n: usize) -> Fe {
    let mut o = sqr(a);
    for _ in 1..n {
        o = sqr(&o);
    }
    o
}

/// a^(p-2) with ref10's addition chain: 254 squarings and 11 multiplications.
fn inv(z: &Fe) -> Fe {
    let t0 = sqr(z); // 2
    let t1 = mul(z, &sqn(&t0, 2)); // 9
    let t0 = mul(&t0, &t1); // 11
    let t1 = mul(&t1, &sqr(&t0)); // 2^5 - 1
    let t1 = mul(&sqn(&t1, 5), &t1); // 2^10 - 1
    let t2 = mul(&sqn(&t1, 10), &t1); // 2^20 - 1
    let t2 = mul(&sqn(&t2, 20), &t2); // 2^40 - 1
    let t1 = mul(&sqn(&t2, 10), &t1); // 2^50 - 1
    let t2 = mul(&sqn(&t1, 50), &t1); // 2^100 - 1
    let t2 = mul(&sqn(&t2, 100), &t2); // 2^200 - 1
    let t1 = mul(&sqn(&t2, 50), &t1); // 2^250 - 1
    mul(&sqn(&t1, 5), &t0) // 2^255 - 21 = p - 2
}

const P_SQRT_EXP: [u8; 32] = {
    // (p - 5) / 8, little-endian
    let mut e = [0xff; 32];
    e[0] = 0xfd;
    e[31] = 0x0f;
    e
};
const PM1_4: [u8; 32] = {
    // (p - 1) / 4, little-endian
    let mut e = [0xff; 32];
    e[0] = 0xfb;
    e[31] = 0x1f;
    e
};
const P_LE: [u8; 32] = {
    let mut e = [0xff; 32];
    e[0] = 0xed;
    e[31] = 0x7f;
    e
};

struct Consts {
    d: Fe,
    d2: Fe,
    sqrtm1: Fe,
}

fn consts() -> Consts {
    let d = mul(&neg(&small(121665)), &inv(&small(121666)));
    Consts {
        d,
        d2: add(&d, &d),
        sqrtm1: pow(&small(2), &PM1_4),
    }
}

/// RFC 8032 5.1.3: y from the low 255 bits (canonical, < p), x = sqrt((y^2-1)/(d y^2+1)) with the sign bit's
/// parity.  `None` if there is no such point.
fn decode(s: &[u8; 32], c: &Consts) -> Option<P3> {
    let mut b = *s;
    let sign = b[31] >> 7;
    b[31] &= 0x7f;
    let mut i = 31;
    while i > 0 && b[i] == P_LE[i] {
        i -= 1;
    }
    if b[i] >= P_LE[i] {
        return None; // y >= p: not canonical
    }
    let y = from_bytes(&b);
    let y2 = sqr(&y);
    let u = sub(&y2, &small(1));
    let v = add(&mul(&y2, &c.d), &small(1));
    // x = u v^3 (u v^7)^((p-5)/8)
    let v3 = mul(&sqr(&v), &v);
    let t = mul(&mul(&sqr(&v3), &v), &u);
    let mut x = mul(&mul(&pow(&t, &P_SQRT_EXP), &v3), &u);
    let vx2 = mul(&sqr(&x), &v);
    if to_bytes(&vx2) != to_bytes(&u) {
        if to_bytes(&vx2) != to_bytes(&neg(&u)) {
            return None;
        }
        x = mul(&x, &c.sqrtm1);
    }
    let xb = to_bytes(&x);
    if xb == [0; 32] && sign != 0 {
        return None;
    }
    if xb[0] & 1 != sign {
        x = neg(&x);
    }
    Some(P3 {
        x,
        y,
        z: small(1),
        t: mul(&x, &y),
    })
}

/// P += Q (Niels), ref10's ge_madd: 8M
#[inline(always)]
fn madd(p: &mut P3, q: &Niels) {
    let a = mul(&sub(&p.y, &p.x), &q.ymx);
    let b = mul(&add(&p.y, &p.x), &q.ypx);
    let c = mul(&p.t, &q.xy2d);
    let d = add(&p.z, &p.z);
    let (e, f, g, h) = (sub(&b, &a), sub(&d, &c), add(&d, &c), add(&b, &a));
    *p = P3 {
        x: mul(&e, &f),
        y: mul(&g, &h),
        t: mul(&e, &h),
        z: mul(&f, &g),
    };
}

/// P += -Q (Niels): swap y+x and y-x, negate 2dxy
#[inline(always)]
fn msub(p: &mut P3, q: &Niels) {
    let a = mul(&sub(&p.y, &p.x), &q.ypx);
    let b = mul(&add(&p.y, &p.x), &q.ymx);
    let c = mul(&p.t, &q.xy2d);
    let d = add(&p.z, &p.z);
    let (e, f, g, h) = (sub(&b, &a), add(&d, &c), sub(&d, &c), add(&b, &a));
    *p = P3 {
        x: mul(&e, &f),
        y: mul(&g, &h),
        t: mul(&e, &h),
        z: mul(&f, &g),
    };
}

/// P + Q, both extended (add-2008-hwcd-3, a = -1): table building only.
fn add_p3(p: &P3, q: &P3, c: &Consts) -> P3 {
    let a = mul(&sub(&p.y, &p.x), &sub(&q.y, &q.x));
    let b = mul(&add(&p.y, &p.x), &add(&q.y, &q.x));
    let cc = mul(&mul(&p.t, &q.t), &c.d2);
    let d = mul(&p.z, &q.z);
    let d = add(&d, &d);
    let (e, f, g, h) = (sub(&b, &a), sub(&d, &cc), add(&d, &cc), add(&b, &a));
    P3 {
        x: mul(&e, &f),
        y: mul(&g, &h),
        t: mul(&e, &h),
        z: mul(&f, &g),
    }
}

/// dbl-2008-hwcd, a = -1
fn dbl(p: &P3) -> P3 {
    let a = sqr(&p.x);
    let b = sqr(&p.y);
    let c = sqr(&p.z);
    let c = add(&c, &c);
    let e = sub(&sub(&sqr(&add(&p.x, &p.y)), &a), &b);
    let g = sub(&b, &a); // D + B with D = -A
    let f = sub(&g, &c); // G - C
    let h = sub(&neg(&a), &b); // D - B
    P3 {
        x: mul(&e, &f),
        y: mul(&g, &h),
        t: mul(&e, &h),
        z: mul(&f, &g),
    }
}

/// tab[w][k-1] = k 2^(W w) P in Niels form, k = 1..H.
fn table(p: &P3, c: &Consts) -> Vec<[Niels; H]> {
    let mut tab = alloc::vec![[Niels::default(); H]; NW];
    let mut jac = alloc::vec![*p; H];
    let mut pre = alloc::vec![[0u64; 5]; H];
    let mut base = *p;
    for row in tab.iter_mut() {
        jac[0] = base;
        for k in 1..H {
            jac[k] = add_p3(&jac[k - 1], &base, c);
        }
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
            let (x, y) = (mul(&jac[k].x, &zi), mul(&jac[k].y, &zi));
            row[k] = Niels {
                ypx: add(&y, &x),
                ymx: sub(&y, &x),
                xy2d: mul(&mul(&x, &y), &c.d2),
            };
        }
        base = dbl(&jac[H - 1]); // 2^W base = 2 (H base)
    }
    tab
}

// ---- scalars mod L ----

const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn lt_l(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if s[i] != L[i] {
            return s[i] < L[i];
        }
    }
    false
}

fn le_limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut o = [0u64; 4];
    for (o, c) in o.iter_mut().zip(b.as_chunks::<8>().0) {
        *o = u64::from_le_bytes(*c);
    }
    o
}

/// x mod L for x < 2^256: subtract 8L, 4L, 2L, L when they fit (2^256 < 16 L).
fn reduce256(x: &mut [u64; 4]) {
    let l = le_limbs(&L);
    for sh in (0..4).rev() {
        let mut m = [0u64; 4];
        let mut cy = 0;
        for i in 0..4 {
            m[i] = l[i] << sh | cy;
            cy = if sh > 0 { l[i] >> (64 - sh) } else { 0 };
        }
        let mut ge = true;
        for i in (0..4).rev() {
            if x[i] != m[i] {
                ge = x[i] > m[i];
                break;
            }
        }
        if !ge {
            continue;
        }
        let mut bw = 0u64;
        for i in 0..4 {
            let z = (x[i] as u128).wrapping_sub(m[i] as u128 + bw as u128);
            x[i] = z as u64;
            bw = (z >> 127) as u64;
        }
    }
}

use fsc::fiat_25519_scalar_montgomery_domain_field_element as Sc;

fn sc_mont(a: &[u64; 4]) -> Sc {
    let mut o = Sc([0; 4]);
    fsc::fiat_25519_scalar_to_montgomery(
        &mut o,
        &fsc::fiat_25519_scalar_non_montgomery_domain_field_element(*a),
    );
    o
}

/// k = h mod L for a 512-bit little-endian h = lo + hi 2^256, through fiat's Montgomery arithmetic mod L.
fn reduce512(h: &[u8; 64]) -> [u64; 4] {
    let (lb, hb) = h.split_at(32);
    let (mut lo, mut hi) = (
        le_limbs(lb.try_into().unwrap_or(&[0; 32])),
        le_limbs(hb.try_into().unwrap_or(&[0; 32])),
    );
    reduce256(&mut lo);
    reduce256(&mut hi);
    let r = sc_mont(&[1, 0, 0, 0]); // R
    let r2 = sc_mont(&r.0); // R^2
    let r3 = sc_mont(&r2.0); // R^3
    let mut a = Sc([0; 4]);
    let mut b = Sc([0; 4]);
    fsc::fiat_25519_scalar_mul(&mut a, &Sc(lo), &r2); // lo R
    fsc::fiat_25519_scalar_mul(&mut b, &Sc(hi), &r3); // hi R^2
    let mut s = Sc([0; 4]);
    fsc::fiat_25519_scalar_add(&mut s, &a, &b); // (lo + hi R) R
    let mut o = fsc::fiat_25519_scalar_non_montgomery_domain_field_element([0; 4]);
    fsc::fiat_25519_scalar_from_montgomery(&mut o, &s);
    o.0
}

/// Signed base-2^W digits of a scalar < 2^253.
fn recode(u: &[u64; 4]) -> [i8; NW] {
    let mut d = [0i8; NW];
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
            *dw = (c - 2 * H as i32) as i8;
            carry = 1;
        } else {
            *dw = c as i8;
            carry = 0;
        }
    }
    d
}

/// An Ed25519 public key with its precomputed tables (568 KB).
#[derive(Clone)]
pub struct Ed25519Key {
    tb: Vec<[Niels; H]>,
    ta: Vec<[Niels; H]>,
    a: [u8; 32],
}

impl core::fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ed25519Key(..)")
    }
}

/// The base point's encoding (y = 4/5).
const B_ENC: [u8; 32] = {
    let mut e = [0x66; 32];
    e[0] = 0x58;
    e
};

impl Ed25519Key {
    /// The 32-byte public key.  `None` if it does not decode to a point.
    pub fn new(public: &[u8; 32]) -> Option<Self> {
        let c = consts();
        let a = decode(public, &c)?;
        let b = decode(&B_ENC, &c)?;
        let minus_a = P3 {
            x: neg(&a.x),
            t: neg(&a.t),
            ..a
        };
        Some(Ed25519Key {
            tb: table(&b, &c),
            ta: table(&minus_a, &c),
            a: *public,
        })
    }
}

impl PkAlg for Ed25519Key {
    const NAME: &'static [u8] = b"EdDSA";
    const CANON: &'static [u8; 36] = b"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";

    fn sig_bytes(&self) -> usize {
        64
    }

    fn verify_chunk(&self, msg: &[&[u8]], sig: &[&[u8]], ok: &mut [bool]) {
        let id = P3 {
            x: small(0),
            y: small(1),
            z: small(1),
            t: small(0),
        };
        let mut rp = [id; CHUNK];
        let mut at = [0usize; CHUNK];
        let mut c = 0;
        for (i, (m, s)) in msg.iter().zip(sig).enumerate() {
            ok[i] = false;
            let Some((rb, sb)) = s.split_first_chunk::<32>() else {
                continue;
            };
            let Ok(sb) = <&[u8; 32]>::try_from(sb) else {
                continue;
            };
            if !lt_l(sb) {
                continue; // S must be canonical
            }
            let h: [u8; 64] = Sha512::new()
                .chain_update(rb)
                .chain_update(self.a)
                .chain_update(m)
                .finalize()
                .into();
            let (ds, dk) = (recode(&le_limbs(sb)), recode(&reduce512(&h)));
            // the identity: the additions are complete
            let p = &mut rp[c];
            for j in 0..NW {
                match ds[j] {
                    d if d > 0 => madd(p, &self.tb[j][(d - 1) as usize]),
                    d if d < 0 => msub(p, &self.tb[j][(-d - 1) as usize]),
                    _ => {}
                }
                match dk[j] {
                    d if d > 0 => madd(p, &self.ta[j][(d - 1) as usize]),
                    d if d < 0 => msub(p, &self.ta[j][(-d - 1) as usize]),
                    _ => {}
                }
            }
            at[c] = i;
            c += 1;
        }
        if c == 0 {
            return;
        }
        // encode every R' with one inversion of all the Z (Montgomery's trick)
        let mut pre = [[0u64; 5]; CHUNK];
        pre[0] = rp[0].z;
        for i in 1..c {
            pre[i] = mul(&pre[i - 1], &rp[i].z);
        }
        let mut iv = inv(&pre[c - 1]);
        for i in (0..c).rev() {
            let zi = if i > 0 {
                let zi = mul(&iv, &pre[i - 1]);
                iv = mul(&iv, &rp[i].z);
                zi
            } else {
                iv
            };
            let mut enc = to_bytes(&mul(&rp[i].y, &zi));
            enc[31] |= (to_bytes(&mul(&rp[i].x, &zi))[0] & 1) << 7;
            ok[at[i]] = sig[at[i]].get(..32) == Some(&enc[..]);
        }
    }
}
