//! AArch64: NEON 4-lane multi-buffer SHA-256, the SHA2-instruction engine with 1/2/4 interleaved streams, and
//! the NEON base64url decoder.  NEON is part of the AArch64 baseline; the SHA2 instructions are checked at run
//! time.
#![allow(clippy::missing_safety_doc)]

use core::arch::aarch64::*;

use super::{CpuFeatures, Engine, Midstates};
use crate::sha256::{self, Plan, Simd, CH, K256, SHA_IV, ZERO_BLOCK};

pub(crate) fn detect() -> u32 {
    let mut f = 0;
    #[cfg(feature = "std")]
    {
        if std::arch::is_aarch64_feature_detected!("sha2") {
            f |= CpuFeatures::SHA2;
        }
        if std::arch::is_aarch64_feature_detected!("sha3") {
            f |= CpuFeatures::SHA512;
        }
    }
    #[cfg(not(feature = "std"))]
    {
        if cfg!(target_feature = "sha2") {
            f |= CpuFeatures::SHA2;
        }
        if cfg!(target_feature = "sha3") {
            f |= CpuFeatures::SHA512;
        }
    }
    f
}

pub(crate) fn available(e: Engine, f: CpuFeatures) -> bool {
    match e {
        Engine::Scalar | Engine::Neon => true,
        Engine::Sha2 | Engine::Sha2x1 | Engine::Sha2x2 => f.has(CpuFeatures::SHA2),
        _ => false,
    }
}

/// 4 lanes of u32 in one NEON register.
#[derive(Clone, Copy)]
pub(crate) struct Neon(uint32x4_t);

/// 16 big-endian bytes as 4 words.
#[inline(always)]
fn ld_be(b: &[u8; 16]) -> uint32x4_t {
    // SAFETY: vld1q_u8 reads 16 bytes, exactly the referenced array; NEON is baseline on AArch64.
    unsafe { vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(b.as_ptr()))) }
}

#[inline(always)]
fn sub16(b: &[u8; 64], j: usize) -> &[u8; 16] {
    let (c, _) = b.as_chunks::<16>();
    &c[j & 3]
}

#[inline(always)]
fn tr4(r: [uint32x4_t; 4]) -> [uint32x4_t; 4] {
    // SAFETY: register-only NEON permutes; NEON is baseline on AArch64.
    unsafe {
        let t0 = vtrn1q_u32(r[0], r[1]);
        let t1 = vtrn2q_u32(r[0], r[1]);
        let t2 = vtrn1q_u32(r[2], r[3]);
        let t3 = vtrn2q_u32(r[2], r[3]);
        let (a, b, c, d) = (
            vreinterpretq_u64_u32(t0),
            vreinterpretq_u64_u32(t1),
            vreinterpretq_u64_u32(t2),
            vreinterpretq_u64_u32(t3),
        );
        [
            vreinterpretq_u32_u64(vtrn1q_u64(a, c)),
            vreinterpretq_u32_u64(vtrn1q_u64(b, d)),
            vreinterpretq_u32_u64(vtrn2q_u64(a, c)),
            vreinterpretq_u32_u64(vtrn2q_u64(b, d)),
        ]
    }
}

#[inline(always)]
fn st4(v: uint32x4_t, o: &mut [u32]) {
    let mut a = [0u32; 4];
    // SAFETY: vst1q_u32 writes 16 bytes, exactly the array `a`; NEON is baseline on AArch64.
    unsafe { vst1q_u32(a.as_mut_ptr(), v) };
    o.iter_mut().zip(a).for_each(|(o, a)| *o = a);
}

// SAFETY (all of `impl Simd<4> for Neon`): register-only NEON arithmetic, plus `vld1q_u32` of a `&[u32; 4]`
// (16 bytes, the whole array); NEON is baseline on AArch64.
impl Simd<4> for Neon {
    #[inline(always)]
    fn splat(x: u32) -> Self {
        // SAFETY: see the impl.
        Neon(unsafe { vdupq_n_u32(x) })
    }
    #[inline(always)]
    fn add(self, b: Self) -> Self {
        // SAFETY: see the impl.
        Neon(unsafe { vaddq_u32(self.0, b.0) })
    }
    #[inline(always)]
    fn shr<const R: i32, const RU: u32>(self) -> Self {
        // SAFETY: see the impl.
        Neon(unsafe { vshrq_n_u32::<R>(self.0) })
    }
    #[inline(always)]
    fn ror<const R: i32, const L32: i32>(self) -> Self {
        // shift right, then shift-left-insert
        // SAFETY: see the impl.
        Neon(unsafe { vsliq_n_u32::<L32>(vshrq_n_u32::<R>(self.0), self.0) })
    }
    #[inline(always)]
    fn xor3(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: see the impl.
        Neon(unsafe { veorq_u32(veorq_u32(a.0, b.0), c.0) })
    }
    #[inline(always)]
    fn ch(e: Self, f: Self, g: Self) -> Self {
        // BSL is literally Ch
        // SAFETY: see the impl.
        Neon(unsafe { vbslq_u32(e.0, f.0, g.0) })
    }
    #[inline(always)]
    fn maj(a: Self, b: Self, c: Self) -> Self {
        // a ^ b ? c : b
        // SAFETY: see the impl.
        Neon(unsafe { vbslq_u32(veorq_u32(a.0, b.0), c.0, b.0) })
    }
    #[inline(always)]
    fn sel(m: Self, x: Self, y: Self) -> Self {
        // SAFETY: see the impl.
        Neon(unsafe { vbslq_u32(m.0, x.0, y.0) })
    }
    #[inline(always)]
    fn mask(live: impl Fn(usize) -> bool) -> Self {
        let m: [u32; 4] = core::array::from_fn(|l| if live(l) { !0 } else { 0 });
        // SAFETY: see the impl.
        Neon(unsafe { vld1q_u32(m.as_ptr()) })
    }
    #[inline(always)]
    fn load16<'b>(block: impl Fn(usize) -> &'b [u8; 64]) -> [Self; 16] {
        let blocks = [block(0), block(1), block(2), block(3)];
        let mut w = [Neon::splat(0); 16];
        for j in 0..4 {
            let t = tr4([
                ld_be(sub16(blocks[0], j)),
                ld_be(sub16(blocks[1], j)),
                ld_be(sub16(blocks[2], j)),
                ld_be(sub16(blocks[3], j)),
            ]);
            for (k, v) in t.into_iter().enumerate() {
                w[4 * j + k] = Neon(v);
            }
        }
        w
    }
    #[inline(always)]
    fn store8(s: &[Self; 8], out: &mut [[u32; 8]; 4]) {
        let lo = tr4([s[0].0, s[1].0, s[2].0, s[3].0]);
        let hi = tr4([s[4].0, s[5].0, s[6].0, s[7].0]);
        for (l, o) in out.iter_mut().enumerate() {
            let (a, b) = o.split_at_mut(4);
            st4(lo[l], a);
            st4(hi[l], b);
        }
    }
}

/// Smallest group the NEON engine takes; a single message runs through the scalar template.
const NEON_MIN_LANES: usize = 2;

/// The NEON engine (baseline on AArch64, so no check is needed).
#[derive(Clone, Copy)]
struct KNeon;

impl sha256::Kernel<4> for KNeon {
    #[inline(always)]
    fn lanes<const RAW: bool>(
        self,
        k: &Midstates,
        g: &sha256::Group<'_, 4>,
        mac: &mut [[u32; 8]; 4],
    ) {
        sha256::kernel::<Neon, 4, RAW>(k, g, mac)
    }
}

// ---- ARMv8 SHA2 instructions: S independent streams interleaved to hide the instruction latency ----

#[inline(always)]
fn k4(r: usize) -> uint32x4_t {
    let (k, _) = K256.as_chunks::<4>();
    // SAFETY: vld1q_u32 reads 16 bytes, the referenced [u32; 4].
    unsafe { vld1q_u32(k[r & 15].as_ptr()) }
}

/// 64 rounds on S streams; m[s] holds stream s's 16 message words.  The 16 quad-rounds are unrolled by a
/// macro (as the C code's `#pragma unroll(full)`), so the message words stay in registers.
///
/// `#[inline(always)]` without a target feature (the two cannot be combined), so it inlines into the
/// sha2-enabled `ce_lanes`, its only caller: as a separate function the 4-stream state went through memory on
/// every block (7-10% slower than the C code).
#[inline(always)]
fn ce_compress<const S: usize>(
    st0: &mut [uint32x4_t; S],
    st1: &mut [uint32x4_t; S],
    m: &mut [[uint32x4_t; 4]; S],
) {
    let (a0, a1) = (*st0, *st1);
    macro_rules! quad {
        ($r:expr, $sched:expr) => {{
            let kr = k4($r);
            for s in 0..S {
                // SAFETY: register-only SHA2 / NEON intrinsics; only called from `ce_lanes`, which enables sha2
                // and runs after the CPU check.
                unsafe {
                    let wk = vaddq_u32(m[s][$r & 3], kr);
                    let t = st0[s];
                    st0[s] = vsha256hq_u32(st0[s], st1[s], wk);
                    st1[s] = vsha256h2q_u32(st1[s], t, wk);
                    if $sched {
                        m[s][$r & 3] = vsha256su1q_u32(
                            vsha256su0q_u32(m[s][$r & 3], m[s][($r + 1) & 3]),
                            m[s][($r + 2) & 3],
                            m[s][($r + 3) & 3],
                        );
                    }
                }
            }
        }};
    }
    quad!(0, true);
    quad!(1, true);
    quad!(2, true);
    quad!(3, true);
    quad!(4, true);
    quad!(5, true);
    quad!(6, true);
    quad!(7, true);
    quad!(8, true);
    quad!(9, true);
    quad!(10, true);
    quad!(11, true);
    quad!(12, false);
    quad!(13, false);
    quad!(14, false);
    quad!(15, false);
    for s in 0..S {
        // SAFETY: register-only NEON adds.
        unsafe {
            st0[s] = vaddq_u32(st0[s], a0[s]);
            st1[s] = vaddq_u32(st1[s], a1[s]);
        }
    }
}

/// S plans with the same block count; RAW: plain SHA-256 (no outer hash).
#[inline]
#[target_feature(enable = "sha2")]
fn ce_lanes<const S: usize, const RAW: bool>(
    k: &Midstates,
    p: [&Plan<'_>; S],
    out: &mut [[u32; 8]; S],
) {
    let (ih, oh) = k.ih.split_at(4);
    let ih0 = ld4(ih);
    let ih1 = ld4(oh);
    let mut st0 = [ih0; S];
    let mut st1 = [ih1; S];
    let mut tails = [[0u8; 128]; S];
    for s in 0..S {
        p[s].tail(&mut tails[s]);
    }
    let nb = p[0].nb;
    let full = p.map(|q| q.m.as_chunks::<64>().0);
    let mut m = [[ih0; 4]; S];
    for b in 0..nb as usize {
        for s in 0..S {
            let blk = match full[s].get(b) {
                Some(x) => x,
                None => tails[s]
                    .as_chunks::<64>()
                    .0
                    .get(b - full[s].len())
                    .unwrap_or(&ZERO_BLOCK),
            };
            m[s] = [
                ld_be(sub16(blk, 0)),
                ld_be(sub16(blk, 1)),
                ld_be(sub16(blk, 2)),
                ld_be(sub16(blk, 3)),
            ];
        }
        ce_compress::<S>(&mut st0, &mut st1, &mut m);
    }
    if !RAW {
        let pad2 = ld4(&[0x8000_0000, 0, 0, 0]);
        let pad3 = ld4(&[0, 0, 0, (64 + 32) * 8]);
        let (o0, o1) = k.oh.split_at(4);
        for s in 0..S {
            m[s] = [st0[s], st1[s], pad2, pad3];
            st0[s] = ld4(o0);
            st1[s] = ld4(o1);
        }
        ce_compress::<S>(&mut st0, &mut st1, &mut m);
    }
    for s in 0..S {
        let (a, b) = out[s].split_at_mut(4);
        st4(st0[s], a);
        st4(st1[s], b);
    }
}

#[inline(always)]
fn ld4(x: &[u32]) -> uint32x4_t {
    let mut a = [0u32; 4];
    a.iter_mut().zip(x).for_each(|(a, x)| *a = *x);
    // SAFETY: vld1q_u32 reads 16 bytes, exactly the array `a`.
    unsafe { vld1q_u32(a.as_ptr()) }
}

/// The SHA2 driver: plans sorted by block count, groups of up to S that share a block count.
#[target_feature(enable = "sha2")]
fn ce_drive<const S: usize, const RAW: bool>(k: &Midstates, msgs: &[&[u8]], mac: &mut [[u32; 8]]) {
    let off = if RAW { 0 } else { 64 };
    if let ([m], [o]) = (msgs, &mut *mac) {
        let mut w = [[0u32; 8]; 1];
        ce_lanes::<1, RAW>(k, [&Plan::new(m, off)], &mut w);
        *o = w[0];
        return;
    }
    for (mc, oc) in msgs.chunks(CH).zip(mac.chunks_mut(CH)) {
        let mut plans = [Plan::EMPTY; CH];
        for (p, m) in plans.iter_mut().zip(mc) {
            *p = Plan::new(m, off);
        }
        let plans = &plans[..mc.len()];
        let mut idx = [0u8; CH];
        sha256::sort_by_nb(plans, &mut idx);
        let idx = &idx[..mc.len()];
        let mut g = 0;
        while g < idx.len() {
            let mut s = S.min(idx.len() - g);
            let nb0 = plans[idx[g] as usize].nb;
            for i in 1..s {
                if plans[idx[g + i] as usize].nb != nb0 {
                    s = i;
                    break;
                }
            }
            let pl = |i: usize| &plans[idx[g + i] as usize];
            let mut put = |i: usize, w: &[u32; 8]| {
                if let Some(o) = oc.get_mut(idx[g + i] as usize) {
                    *o = *w;
                }
            };
            // a constant stream count per call, so ce_lanes fully specialises
            match s {
                4 => {
                    let mut o = [[0u32; 8]; 4];
                    ce_lanes::<4, RAW>(k, [pl(0), pl(1), pl(2), pl(3)], &mut o);
                    o.iter().enumerate().for_each(|(i, w)| put(i, w));
                }
                3 => {
                    let mut o = [[0u32; 8]; 2];
                    ce_lanes::<2, RAW>(k, [pl(0), pl(1)], &mut o);
                    o.iter().enumerate().for_each(|(i, w)| put(i, w));
                    let mut o = [[0u32; 8]; 1];
                    ce_lanes::<1, RAW>(k, [pl(2)], &mut o);
                    put(2, &o[0]);
                }
                2 => {
                    let mut o = [[0u32; 8]; 2];
                    ce_lanes::<2, RAW>(k, [pl(0), pl(1)], &mut o);
                    o.iter().enumerate().for_each(|(i, w)| put(i, w));
                }
                _ => {
                    let mut o = [[0u32; 8]; 1];
                    ce_lanes::<1, RAW>(k, [pl(0)], &mut o);
                    put(0, &o[0]);
                }
            }
            g += s;
        }
    }
}

pub(crate) fn hmac(e: Engine, k: &Midstates, msgs: &[&[u8]], out: &mut [[u32; 8]]) -> bool {
    let f = CpuFeatures::get();
    match e {
        Engine::Neon => sha256::drive::<KNeon, 4, false, NEON_MIN_LANES>(KNeon, k, msgs, out),
        Engine::Sha2 | Engine::Sha2x1 | Engine::Sha2x2 if f.has(CpuFeatures::SHA2) => {
            // SAFETY: the CPU has the SHA2 instructions (checked just above).
            unsafe {
                match e {
                    Engine::Sha2 => ce_drive::<4, false>(k, msgs, out),
                    Engine::Sha2x2 => ce_drive::<2, false>(k, msgs, out),
                    _ => ce_drive::<1, false>(k, msgs, out),
                }
            }
        }
        _ => return false,
    }
    true
}

pub(crate) fn sha256(e: Engine, msgs: &[&[u8]], out: &mut [[u32; 8]]) -> bool {
    let f = CpuFeatures::get();
    match e {
        Engine::Neon => sha256::drive::<KNeon, 4, true, NEON_MIN_LANES>(KNeon, &SHA_IV, msgs, out),
        // SAFETY: the CPU has the SHA2 instructions (checked in the guard).
        Engine::Sha2 | Engine::Sha2x1 | Engine::Sha2x2 if f.has(CpuFeatures::SHA2) => unsafe {
            ce_drive::<4, true>(&SHA_IV, msgs, out)
        },
        _ => return false,
    }
    true
}

// ---- base64url: 64 chars -> 48 bytes per step ----

/// vld4 de-interleaves the 4 sextets of every quantum into 4 registers, vqtbl4/vqtbx4 translate through the
/// 128-byte table, vst3 re-interleaves the 3 output bytes.  Table misses give 0xFF; bytes >= 0x80 index nothing
/// and are caught by OR-ing in the input.
#[inline(always)]
fn b64_64(src: &[u8; 64], dst: &mut [u8; 48], lo: uint8x16x4_t, hi: uint8x16x4_t) -> uint8x16_t {
    // SAFETY: vld4q_u8 reads 64 bytes (`src`), vst3q_u8 writes 48 bytes (`dst`); the rest is register-only NEON,
    // which is baseline on AArch64.
    unsafe {
        let x40 = vdupq_n_u8(0x40);
        let xlat = |v: uint8x16_t| vqtbx4q_u8(vqtbl4q_u8(lo, v), hi, veorq_u8(v, x40));
        let c = vld4q_u8(src.as_ptr());
        let (a, b, cc, d) = (xlat(c.0), xlat(c.1), xlat(c.2), xlat(c.3));
        let err = vorrq_u8(
            vorrq_u8(vorrq_u8(a, b), vorrq_u8(cc, d)),
            vorrq_u8(vorrq_u8(c.0, c.1), vorrq_u8(c.2, c.3)),
        );
        let out = uint8x16x3_t(
            vorrq_u8(vshlq_n_u8::<2>(a), vshrq_n_u8::<4>(b)),
            vorrq_u8(vshlq_n_u8::<4>(b), vshrq_n_u8::<2>(cc)),
            vorrq_u8(vshlq_n_u8::<6>(cc), d),
        );
        vst3q_u8(dst.as_mut_ptr(), out);
        err
    }
}

pub(crate) fn b64_decode(dst: &mut [u8], src: &[u8]) -> Option<Option<usize>> {
    if dst.len() < crate::b64::decoded_cap(src.len()) {
        return Some(None);
    }
    let tab = &crate::b64::TAB;
    let (t, _) = tab.as_chunks::<64>();
    // SAFETY: vld1q_u8_x4 reads 64 bytes, exactly each referenced [u8; 64] half of the table.
    let (lo, hi) = unsafe { (vld1q_u8_x4(t[0].as_ptr()), vld1q_u8_x4(t[1].as_ptr())) };
    // SAFETY: register-only NEON.
    let mut err = unsafe { vdupq_n_u8(0) };
    let (blocks, rest) = src.as_chunks::<64>();
    let mut o = 0;
    let (out, _) = dst.as_chunks_mut::<48>();
    for (b, d) in blocks.iter().zip(out.iter_mut()) {
        let e = b64_64(b, d, lo, hi);
        // SAFETY: register-only NEON.
        err = unsafe { vorrq_u8(err, e) };
        o += 48;
    }
    let q = rest.len() & !3;
    if q != 0 {
        // whole quanta of the tail: one more step over an 'A'-padded copy
        let mut buf = [b'A'; 64];
        buf[..q].copy_from_slice(&rest[..q]);
        let mut tmp = [0u8; 48];
        let e = b64_64(&buf, &mut tmp, lo, hi);
        dst[o..o + q / 4 * 3].copy_from_slice(&tmp[..q / 4 * 3]);
        // SAFETY: register-only NEON.
        err = unsafe { vorrq_u8(err, e) };
        o += q / 4 * 3;
    }
    // SAFETY: register-only NEON.
    if unsafe { vmaxvq_u8(err) } & 0x80 != 0 {
        return Some(None);
    }
    let t = crate::b64::tail(&mut dst[o..], &rest[q..]);
    Some(t.map(|t| o + t))
}
