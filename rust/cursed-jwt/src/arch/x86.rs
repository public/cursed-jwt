//! x86-64: AVX2 and AVX-512VL 8-lane multi-buffer SHA-256 (the same template; AVX-512VL adds `vprord` and
//! `vpternlogd` on ymm registers), their 16-lane interleaved flavours, the 16-lane zmm engine, and the AVX2
//! base64url decoder.  All of them are checked for at run time.
//!
//! The AVX-512 engines run on ymm registers by default: a zmm burst drops a Cascade Lake core's frequency
//! licence for everything that follows (19% slower for 0.5-1 ms, measured on the C library).  The zmm engine is
//! the default only where `CpuFeatures::FAST_ZMM` says 512-bit vectors cost no clock speed (AMD Zen 4/5).

use core::arch::x86_64::*;

use super::{CpuFeatures, Engine, Midstates};
use crate::sha256::{
    self, drive, drive_x2, Group, Kernel, Plan, Simd, K256, SHA_IV, X2, ZERO_BLOCK,
};

pub(crate) fn detect() -> u32 {
    #[cfg(cjwt_ossl)]
    ossl::init();
    let mut f = 0;
    macro_rules! has {
        ($($t:tt),+) => {{
            #[cfg(feature = "std")]
            {
                true $(&& std::is_x86_feature_detected!($t))+
            }
            #[cfg(not(feature = "std"))]
            {
                true $(&& cfg!(target_feature = $t))+
            }
        }};
    }
    if has!("avx2", "bmi1", "bmi2") {
        f |= CpuFeatures::AVX2;
    }
    if f & CpuFeatures::AVX2 != 0 && has!("avx512f", "avx512vl", "avx512bw", "avx512dq", "avx512cd")
    {
        f |= CpuFeatures::AVX512VL;
        if has!("avx512ifma") {
            f |= CpuFeatures::IFMA;
        }
        if amd_family_19h_or_later() {
            f |= CpuFeatures::FAST_ZMM;
        }
    }
    if has!("bmi2", "adx") {
        f |= CpuFeatures::BMI2_ADX;
    }
    if has!("bmi2") {
        f |= CpuFeatures::BMI2;
    }
    if has!("sha", "sse4.1", "ssse3") {
        f |= CpuFeatures::SHANI;
        // every Zen has SHA-NI, and there 4 interleaved streams beat every vector engine at every batch size
        // (the C library's measurements on Zen 2, 3 and 4); Intel's SHA-NI parts keep the vector engines
        if is_amd() {
            f |= CpuFeatures::FAST_SHANI;
        }
    }
    f
}

fn is_amd() -> bool {
    let v = __cpuid(0);
    v.ebx == 0x6874_7541 && v.edx == 0x6974_6e65 && v.ecx == 0x444d_4163 // "AuthenticAMD"
}

/// AMD Zen 4 (family 19h) and later run 512-bit integer work without a frequency-licence drop.
fn amd_family_19h_or_later() -> bool {
    let v = __cpuid(0);
    let amd = v.ebx == 0x6874_7541 && v.edx == 0x6974_6e65 && v.ecx == 0x444d_4163; // "AuthenticAMD"
    let a = __cpuid(1).eax;
    let base = (a >> 8) & 0xF;
    let fam = if base == 0xF {
        base + ((a >> 20) & 0xFF)
    } else {
        base
    };
    amd && fam >= 0x19
}

pub(crate) fn available(e: Engine, f: CpuFeatures) -> bool {
    match e {
        Engine::Scalar => true,
        Engine::Avx2 | Engine::Avx2x2 => f.has(CpuFeatures::AVX2),
        Engine::Avx512 | Engine::Avx512x2 | Engine::Zmm => {
            f.has(CpuFeatures::AVX2 | CpuFeatures::AVX512VL)
        }
        Engine::ShaNi | Engine::ShaNix1 | Engine::ShaNix2 => f.has(CpuFeatures::SHANI),
        _ => false,
    }
}

// ---- 8 x u32 in a ymm register ----

#[inline(always)]
fn bswap32() -> __m256i {
    // SAFETY: register-only AVX constructor (AVX is implied by the AVX2 every caller of the engines has).
    unsafe {
        _mm256_setr_epi8(
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10,
            9, 8, 15, 14, 13, 12,
        )
    }
}

/// Transposes 8 rows of 8 words.
#[inline(always)]
fn tr8(r: &[__m256i; 8]) -> [__m256i; 8] {
    // SAFETY: register-only AVX2 shuffles; only reached from AVX2-enabled engine functions.
    unsafe {
        let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
        let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
        let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
        let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
        let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
        let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
        let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
        let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);
        [
            _mm256_permute2x128_si256::<0x20>(u0, u4),
            _mm256_permute2x128_si256::<0x20>(u1, u5),
            _mm256_permute2x128_si256::<0x20>(u2, u6),
            _mm256_permute2x128_si256::<0x20>(u3, u7),
            _mm256_permute2x128_si256::<0x31>(u0, u4),
            _mm256_permute2x128_si256::<0x31>(u1, u5),
            _mm256_permute2x128_si256::<0x31>(u2, u6),
            _mm256_permute2x128_si256::<0x31>(u3, u7),
        ]
    }
}

#[inline(always)]
fn ld32(b: &[u8; 64], h: usize) -> __m256i {
    let (c, _) = b.as_chunks::<32>();
    // SAFETY: _mm256_loadu_si256 reads 32 bytes, exactly the referenced [u8; 32]; unaligned loads are allowed.
    unsafe { _mm256_loadu_si256(c[h & 1].as_ptr().cast()) }
}

#[inline(always)]
fn load16_ymm<'b>(block: impl Fn(usize) -> &'b [u8; 64]) -> [__m256i; 16] {
    let bs = bswap32();
    let blocks = [
        block(0),
        block(1),
        block(2),
        block(3),
        block(4),
        block(5),
        block(6),
        block(7),
    ];
    // SAFETY: register-only AVX2 byte shuffle; only reached from AVX2-enabled engine functions.
    let row = |l: usize, h: usize| unsafe { _mm256_shuffle_epi8(ld32(blocks[l], h), bs) };
    let a = tr8(&[
        row(0, 0),
        row(1, 0),
        row(2, 0),
        row(3, 0),
        row(4, 0),
        row(5, 0),
        row(6, 0),
        row(7, 0),
    ]);
    let b = tr8(&[
        row(0, 1),
        row(1, 1),
        row(2, 1),
        row(3, 1),
        row(4, 1),
        row(5, 1),
        row(6, 1),
        row(7, 1),
    ]);
    [
        a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6],
        b[7],
    ]
}

#[inline(always)]
fn store8_ymm(s: &[__m256i; 8], out: &mut [[u32; 8]; 8]) {
    let o = tr8(s);
    for (d, v) in out.iter_mut().zip(o) {
        // SAFETY: _mm256_storeu_si256 writes 32 bytes, exactly the referenced [u32; 8].
        unsafe { _mm256_storeu_si256(d.as_mut_ptr().cast(), v) };
    }
}

#[inline(always)]
fn mask_ymm(live: impl Fn(usize) -> bool) -> __m256i {
    let m = |l: usize| if live(l) { -1 } else { 0 };
    // SAFETY: register-only AVX constructor.
    unsafe { _mm256_setr_epi32(m(0), m(1), m(2), m(3), m(4), m(5), m(6), m(7)) }
}

/// The AVX2 operations, for `Avx2` and for `Ymm512` (which differs only in its rounds).
macro_rules! avx2_ops {
    ($t:ident) => {
        #[inline(always)]
        fn splat(x: u32) -> Self {
            // SAFETY: see the impl.
            $t(unsafe { _mm256_set1_epi32(x as i32) })
        }
        #[inline(always)]
        fn add(self, b: Self) -> Self {
            // SAFETY: see the impl.
            $t(unsafe { _mm256_add_epi32(self.0, b.0) })
        }
        #[inline(always)]
        fn shr<const R: i32, const RU: u32>(self) -> Self {
            // SAFETY: see the impl.
            $t(unsafe { _mm256_srli_epi32::<R>(self.0) })
        }
        #[inline(always)]
        fn ror<const R: i32, const L32: i32>(self) -> Self {
            // SAFETY: see the impl.
            $t(unsafe {
                _mm256_or_si256(
                    _mm256_srli_epi32::<R>(self.0),
                    _mm256_slli_epi32::<L32>(self.0),
                )
            })
        }
        #[inline(always)]
        fn xor3(a: Self, b: Self, c: Self) -> Self {
            // SAFETY: see the impl.
            $t(unsafe { _mm256_xor_si256(_mm256_xor_si256(a.0, b.0), c.0) })
        }
        #[inline(always)]
        fn ch(e: Self, f: Self, g: Self) -> Self {
            // SAFETY: see the impl.
            $t(unsafe { _mm256_xor_si256(g.0, _mm256_and_si256(e.0, _mm256_xor_si256(f.0, g.0))) })
        }
        #[inline(always)]
        fn maj(a: Self, b: Self, c: Self) -> Self {
            // b ^ ((a ^ b) & (b ^ c)): b ^ c is the previous round's a ^ b, which the unrolled compress reuses
            // SAFETY: see the impl.
            $t(unsafe {
                _mm256_xor_si256(
                    b.0,
                    _mm256_and_si256(_mm256_xor_si256(a.0, b.0), _mm256_xor_si256(b.0, c.0)),
                )
            })
        }
        #[inline(always)]
        fn sel(m: Self, x: Self, y: Self) -> Self {
            // SAFETY: see the impl.
            $t(unsafe { _mm256_blendv_epi8(y.0, x.0, m.0) })
        }
        #[inline(always)]
        fn mask(live: impl Fn(usize) -> bool) -> Self {
            $t(mask_ymm(live))
        }
        #[inline(always)]
        fn load16<'b>(block: impl Fn(usize) -> &'b [u8; 64]) -> [Self; 16] {
            load16_ymm(block).map($t)
        }
        #[inline(always)]
        fn store8(s: &[Self; 8], out: &mut [[u32; 8]; 8]) {
            store8_ymm(
                &[
                    s[0].0, s[1].0, s[2].0, s[3].0, s[4].0, s[5].0, s[6].0, s[7].0,
                ],
                out,
            )
        }
    };
}

/// AVX2, 8 lanes.  Only constructed inside `#[target_feature(enable = "avx2,...")]` engine functions, which run
/// after the CPU check.
#[derive(Clone, Copy)]
pub(crate) struct Avx2(__m256i);

// SAFETY (every `unsafe` block in `impl Simd<8> for Avx2`): register-only AVX2 intrinsics; the type only exists
// inside AVX2-enabled engine functions, which run after `CpuFeatures::AVX2` was checked.
impl Simd<8> for Avx2 {
    avx2_ops!(Avx2);
}

/// The default AVX-512 engine: its loads, transposes, stores and masks are the AVX2 engine's, compiled in an
/// AVX2-only region, and only the 64 rounds (`compress_avx512`) run with AVX-512VL enabled, out of line with the
/// state in memory, as the C code has them.  Two reasons:
/// - inlined into the kernel, the eight entry-state values stay live through the rounds and push the 32
///   registers into 41 spills (C: none): 18% slower than C on a Xeon Platinum 8260 (exp1387);
/// - in an AVX-512 region the compiler lowers array copies and zeroing with zmm stores, and one zmm instruction
///   drops a Cascade Lake core's frequency licence; an AVX2 region cannot contain any.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Ymm512(__m256i);

// SAFETY (every `unsafe` block in `impl Simd<8> for Ymm512`): as for `Avx2` (the type only exists inside the
// AVX-512 engine's kernel, which runs after `CpuFeatures::AVX512VL`, implying AVX2, was checked).
impl Simd<8> for Ymm512 {
    #[inline(always)]
    fn compress(s: &mut [Self; 8], w: &mut [Self; 16]) {
        // SAFETY: Ymm512 and Avx512 are both #[repr(transparent)] over __m256i, so the arrays have the same
        // layout; and the type only exists inside the AVX-512 engine, which runs after `CpuFeatures::AVX512VL` was
        // checked, so the CPU has every feature `compress_avx512` enables.
        unsafe {
            let s = &mut *(s as *mut [Self; 8]).cast::<[Avx512; 8]>();
            let w = &mut *(w as *mut [Self; 16]).cast::<[Avx512; 16]>();
            compress_avx512(s, w)
        }
    }
    avx2_ops!(Ymm512);
}

/// The 64 rounds of the default AVX-512 engine (see `Ymm512`), on the state and message words in place.
#[target_feature(enable = "avx512f,avx512vl,avx512bw,avx512dq,avx512cd,avx2,bmi1,bmi2")]
#[inline(never)]
fn compress_avx512(s: &mut [Avx512; 8], w: &mut [Avx512; 16]) {
    sha256::compress::<Avx512, 8>(s, w)
}

/// vpternlogd truth tables (index = a << 2 | b << 1 | c).
const TL_XOR3: i32 = 0x96;
const TL_CH: i32 = 0xCA;
const TL_MAJ: i32 = 0xE8;

/// AVX-512VL on ymm, 8 lanes: the AVX2 engine with `vprord` rotates and `vpternlogd` for the three-input
/// functions.  Only constructed inside AVX-512-enabled engine functions, which run after the CPU check.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Avx512(__m256i);

// SAFETY (every `unsafe` block in `impl Simd<8> for Avx512`): register-only AVX2 / AVX-512VL intrinsics; the type
// only exists inside AVX-512-enabled engine functions, which run after `CpuFeatures::AVX512VL` was checked.
impl Simd<8> for Avx512 {
    #[inline(always)]
    fn splat(x: u32) -> Self {
        // SAFETY: see the impl.
        Avx512(unsafe { _mm256_set1_epi32(x as i32) })
    }
    #[inline(always)]
    fn add(self, b: Self) -> Self {
        // SAFETY: see the impl.
        Avx512(unsafe { _mm256_add_epi32(self.0, b.0) })
    }
    #[inline(always)]
    fn shr<const R: i32, const RU: u32>(self) -> Self {
        // SAFETY: see the impl.
        Avx512(unsafe { _mm256_srli_epi32::<R>(self.0) })
    }
    #[inline(always)]
    fn ror<const R: i32, const L32: i32>(self) -> Self {
        // SAFETY: see the impl.
        Avx512(unsafe { _mm256_ror_epi32::<R>(self.0) })
    }
    #[inline(always)]
    fn xor3(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: see the impl.
        Avx512(unsafe { _mm256_ternarylogic_epi32::<TL_XOR3>(a.0, b.0, c.0) })
    }
    #[inline(always)]
    fn ch(e: Self, f: Self, g: Self) -> Self {
        // SAFETY: see the impl.
        Avx512(unsafe { _mm256_ternarylogic_epi32::<TL_CH>(e.0, f.0, g.0) })
    }
    #[inline(always)]
    fn maj(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: see the impl.
        Avx512(unsafe { _mm256_ternarylogic_epi32::<TL_MAJ>(a.0, b.0, c.0) })
    }
    #[inline(always)]
    fn sel(m: Self, x: Self, y: Self) -> Self {
        // SAFETY: see the impl.
        Avx512(unsafe { _mm256_ternarylogic_epi32::<TL_CH>(m.0, x.0, y.0) })
    }
    #[inline(always)]
    fn mask(live: impl Fn(usize) -> bool) -> Self {
        Avx512(mask_ymm(live))
    }
    #[inline(always)]
    fn load16<'b>(block: impl Fn(usize) -> &'b [u8; 64]) -> [Self; 16] {
        load16_ymm(block).map(Avx512)
    }
    #[inline(always)]
    fn store8(s: &[Self; 8], out: &mut [[u32; 8]; 8]) {
        store8_ymm(
            &[
                s[0].0, s[1].0, s[2].0, s[3].0, s[4].0, s[5].0, s[6].0, s[7].0,
            ],
            out,
        )
    }
}

/// 16 lanes in zmm registers (loads and stores reuse the ymm 8 x 8 transposes and glue the halves).
#[derive(Clone, Copy)]
pub(crate) struct Zmm(__m512i);

// SAFETY (every `unsafe` block in `impl Simd<16> for Zmm`): register-only AVX-512F intrinsics, and
// `_mm512_loadu_si512` of a `&[u32; 16]` (64 bytes, the whole array); the type only exists inside the
// AVX-512-enabled zmm engine function, which runs after `CpuFeatures::AVX512VL` was checked.
impl Simd<16> for Zmm {
    #[inline(always)]
    fn splat(x: u32) -> Self {
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_set1_epi32(x as i32) })
    }
    #[inline(always)]
    fn add(self, b: Self) -> Self {
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_add_epi32(self.0, b.0) })
    }
    #[inline(always)]
    fn shr<const R: i32, const RU: u32>(self) -> Self {
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_srli_epi32::<RU>(self.0) })
    }
    #[inline(always)]
    fn ror<const R: i32, const L32: i32>(self) -> Self {
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_ror_epi32::<R>(self.0) })
    }
    #[inline(always)]
    fn xor3(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_ternarylogic_epi32::<TL_XOR3>(a.0, b.0, c.0) })
    }
    #[inline(always)]
    fn ch(e: Self, f: Self, g: Self) -> Self {
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_ternarylogic_epi32::<TL_CH>(e.0, f.0, g.0) })
    }
    #[inline(always)]
    fn maj(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_ternarylogic_epi32::<TL_MAJ>(a.0, b.0, c.0) })
    }
    #[inline(always)]
    fn sel(m: Self, x: Self, y: Self) -> Self {
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_ternarylogic_epi32::<TL_CH>(m.0, x.0, y.0) })
    }
    #[inline(always)]
    fn mask(live: impl Fn(usize) -> bool) -> Self {
        let m: [u32; 16] = core::array::from_fn(|l| if live(l) { !0 } else { 0 });
        // SAFETY: see the impl.
        Zmm(unsafe { _mm512_loadu_si512(m.as_ptr().cast()) })
    }
    #[inline(always)]
    fn load16<'b>(block: impl Fn(usize) -> &'b [u8; 64]) -> [Self; 16] {
        let (lo, hi) = (load16_ymm(&block), load16_ymm(|l| block(l + 8)));
        core::array::from_fn(|i| {
            // SAFETY: see the impl.
            Zmm(unsafe { _mm512_inserti64x4::<1>(_mm512_castsi256_si512(lo[i]), hi[i]) })
        })
    }
    #[inline(always)]
    fn store8(s: &[Self; 8], out: &mut [[u32; 8]; 16]) {
        let (c, _) = out.as_chunks_mut::<8>();
        let (a, b) = c.split_at_mut(1);
        // SAFETY: see the impl.
        let lo = s.map(|v| unsafe { _mm512_castsi512_si256(v.0) });
        // SAFETY: see the impl.
        let hi = s.map(|v| unsafe { _mm512_extracti64x4_epi64::<1>(v.0) });
        store8_ymm(&lo, &mut a[0]);
        store8_ymm(&hi, &mut b[0]);
    }
}

/// Fewest live messages for an 8-lane group; smaller groups run one message at a time (OpenSSL's extracted code
/// with the `asm` feature on Linux, else the scalar template compiled with BMI2, so its rotates are `rorx`).
/// AVX2 with the OpenSSL code: two messages one at a time (2 x 753 ns) beat one 2-lane group (822 ns) on a Xeon
/// Platinum 8260 (C library measurements); from 3 lanes the vector wins.
const MIN_LANES: usize = 2;
const MIN_AVX2: usize = if cfg!(cjwt_ossl) { 3 } else { 2 };

/// OpenSSL's sha256_block_data_order for x86-64 (SHA-NI, AVX2+BMI2, AVX, SSSE3 and plain x86-64 paths, chosen
/// by its own capability word), assembled by build.rs from the C library's `src/sha256_x86_64_ossl.S`.
#[cfg(cjwt_ossl)]
mod ossl {
    use crate::sha256::{Midstates, Plan};

    extern "C" {
        fn cjwt_rs_sha256_block(h: *mut u32, blocks: *const u8, n: usize);
        fn cjwt_rs_ossl_init();
    }

    /// Fills the capability word from CPUID.  Before it runs the word is zero, which selects the plain x86-64
    /// path: correct, only slower.
    pub(super) fn init() {
        // SAFETY: writes the library's own static capability array; idempotent (racing callers store equal
        // values, and the block function only reads it).
        unsafe { cjwt_rs_ossl_init() }
    }

    fn blocks(st: &mut [u32; 8], b: &[[u8; 64]]) {
        if !b.is_empty() {
            // SAFETY: reads `b.len()` 64-byte blocks, exactly the slice, and updates the 8 state words of `st`.
            unsafe { cjwt_rs_sha256_block(st.as_mut_ptr(), b.as_ptr().cast(), b.len()) }
        }
    }

    /// One message: the full blocks in place, then the tail, then (unless RAW) the outer hash.
    #[inline(always)]
    pub(super) fn one<const RAW: bool>(k: &Midstates, p: &Plan<'_>) -> [u32; 8] {
        let mut st = k.ih;
        blocks(&mut st, p.m.as_chunks::<64>().0);
        let mut tail = [[0u8; 64]; 2];
        p.tail(tail.as_flattened_mut());
        let nt = (p.nb - p.nf) as usize;
        blocks(&mut st, &tail[..nt]);
        if RAW {
            return st;
        }
        let mut ob = [0u8; 64];
        for (c, w) in ob.as_chunks_mut::<4>().0.iter_mut().zip(st) {
            *c = w.to_be_bytes();
        }
        ob[32] = 0x80;
        ob[62..].copy_from_slice(&(((64 + 32) * 8) as u16).to_be_bytes());
        let mut mac = k.oh;
        blocks(&mut mac, &[ob]);
        mac
    }
}

/// Engine tokens: zero-sized, constructed only in `hmac` / `sha256` below, after `available` checked the CPU
/// features the engine's functions enable.
#[derive(Clone, Copy)]
struct KAvx2(());
#[derive(Clone, Copy)]
struct KAvx2x2(());
#[derive(Clone, Copy)]
struct KAvx512(());
#[derive(Clone, Copy)]
struct KAvx512x2(());
#[derive(Clone, Copy)]
struct KZmm(());

#[cfg(not(cjwt_ossl))]
#[target_feature(enable = "bmi1,bmi2")]
fn one_bmi2<const RAW: bool>(k: &Midstates, p: &Plan<'_>) -> [u32; 8] {
    sha256::one::<RAW>(k, p)
}

macro_rules! kernel {
    ($tok:ident, $v:ty, $l:literal, $fname:ident, $feat:literal) => {
        #[target_feature(enable = $feat)]
        fn $fname<const RAW: bool>(k: &Midstates, g: &Group<'_, $l>, mac: &mut [[u32; 8]; $l]) {
            sha256::kernel::<$v, $l, RAW>(k, g, mac)
        }
        impl Kernel<$l> for $tok {
            #[inline(always)]
            fn lanes<const RAW: bool>(
                self,
                k: &Midstates,
                g: &Group<'_, $l>,
                mac: &mut [[u32; 8]; $l],
            ) {
                // SAFETY: a token exists only after the CPU check for these features (see the token types).
                unsafe { $fname::<RAW>(k, g, mac) }
            }
            #[inline(always)]
            fn one<const RAW: bool>(self, k: &Midstates, p: &Plan<'_>) -> [u32; 8] {
                #[cfg(cjwt_ossl)]
                return ossl::one::<RAW>(k, p);
                // SAFETY: every x86 engine requires BMI1 and BMI2 (see `available`), checked before the token
                // was made.
                #[cfg(not(cjwt_ossl))]
                unsafe {
                    one_bmi2::<RAW>(k, p)
                }
            }
        }
    };
}

kernel!(KAvx2, Avx2, 8, kernel_avx2, "avx2,bmi1,bmi2");
kernel!(KAvx2x2, X2<Avx2>, 16, kernel_avx2x2, "avx2,bmi1,bmi2");
kernel!(KAvx512, Ymm512, 8, kernel_avx512, "avx2,bmi1,bmi2");
kernel!(
    KAvx512x2,
    X2<Avx512>,
    16,
    kernel_avx512x2,
    "avx512f,avx512vl,avx512bw,avx512dq,avx512cd,avx2,bmi1,bmi2"
);
kernel!(
    KZmm,
    Zmm,
    16,
    kernel_zmm,
    "avx512f,avx512vl,avx512bw,avx512dq,avx512cd,avx2,bmi1,bmi2"
);

pub(crate) fn hmac(e: Engine, k: &Midstates, msgs: &[&[u8]], out: &mut [[u32; 8]]) -> bool {
    let f = CpuFeatures::get();
    if !available(e, f) {
        return false;
    }
    // `available` checked the CPU features each engine's functions enable (AVX2 + BMI1/2, plus AVX-512
    // F/VL/BW/DQ/CD for the AVX-512 ones), so the tokens may be made
    match e {
        Engine::Avx2 => drive::<KAvx2, 8, false, MIN_AVX2>(KAvx2(()), k, msgs, out),
        Engine::Avx2x2 => {
            drive_x2::<KAvx2x2, KAvx2, MIN_AVX2>(KAvx2x2(()), KAvx2(()), k, msgs, out)
        }
        Engine::Avx512 => drive::<KAvx512, 8, false, MIN_LANES>(KAvx512(()), k, msgs, out),
        Engine::Avx512x2 => {
            drive_x2::<KAvx512x2, KAvx512, MIN_LANES>(KAvx512x2(()), KAvx512(()), k, msgs, out)
        }
        Engine::Zmm => drive_x2::<KZmm, KAvx512, MIN_LANES>(KZmm(()), KAvx512(()), k, msgs, out),
        // SAFETY: `available` checked the SHA extensions, SSE4.1 and SSSE3, which the drivers enable.
        Engine::ShaNi => unsafe { ni_drive::<4, false>(k, msgs, out) },
        // SAFETY: as above.
        Engine::ShaNix2 => unsafe { ni_drive::<2, false>(k, msgs, out) },
        // SAFETY: as above.
        Engine::ShaNix1 => unsafe { ni_drive::<1, false>(k, msgs, out) },
        _ => return false,
    }
    true
}

pub(crate) fn sha256(e: Engine, msgs: &[&[u8]], out: &mut [[u32; 8]]) -> bool {
    let f = CpuFeatures::get();
    if !available(e, f) {
        return false;
    }
    // as in `hmac`
    match e {
        Engine::Avx2 | Engine::Avx2x2 => {
            drive::<KAvx2, 8, true, MIN_AVX2>(KAvx2(()), &SHA_IV, msgs, out)
        }
        Engine::Avx512 | Engine::Avx512x2 | Engine::Zmm => {
            drive::<KAvx512, 8, true, MIN_LANES>(KAvx512(()), &SHA_IV, msgs, out)
        }
        // SAFETY: as in `hmac`.
        Engine::ShaNi | Engine::ShaNix1 | Engine::ShaNix2 => unsafe {
            ni_drive::<4, true>(&SHA_IV, msgs, out)
        },
        _ => return false,
    }
    true
}

// ---- SHA-NI: S independent streams interleaved for latency hiding (the ARM SHA2 engine's layout) ----
// The state lives as ABEF / CDGH, the order sha256rnds2 wants; ni_ld / ni_st convert from and to h0..h7.

#[inline(always)]
fn ni_ld(h: &[u32; 8]) -> (__m128i, __m128i) {
    let (c, _) = h.as_chunks::<4>();
    // SAFETY: each _mm_loadu_si128 reads 16 bytes, exactly one referenced [u32; 4]; the rest are register-only
    // SSE4.1 / SSSE3 shuffles, and this is only reached from the SHA-NI functions, which enable them.
    unsafe {
        let t = _mm_shuffle_epi32::<0xB1>(_mm_loadu_si128(c[0].as_ptr().cast())); // CDAB
        let u = _mm_shuffle_epi32::<0x1B>(_mm_loadu_si128(c[1].as_ptr().cast())); // EFGH
        (_mm_alignr_epi8::<8>(t, u), _mm_blend_epi16::<0xF0>(u, t))
    }
}

#[inline(always)]
fn ni_st(abef: __m128i, cdgh: __m128i, h: &mut [u32; 8]) {
    let (c, _) = h.as_chunks_mut::<4>();
    let (lo, hi) = c.split_at_mut(1);
    // SAFETY: each _mm_storeu_si128 writes 16 bytes, exactly one referenced [u32; 4]; the rest as in `ni_ld`.
    unsafe {
        let t = _mm_shuffle_epi32::<0x1B>(abef); // FEBA
        let u = _mm_shuffle_epi32::<0xB1>(cdgh); // DCHG
        _mm_storeu_si128(lo[0].as_mut_ptr().cast(), _mm_blend_epi16::<0xF0>(t, u)); // DCBA
        _mm_storeu_si128(hi[0].as_mut_ptr().cast(), _mm_alignr_epi8::<8>(u, t));
        // HGFE
    }
}

#[inline(always)]
fn ni_k4(r: usize) -> __m128i {
    let (k, _) = K256.as_chunks::<4>();
    // SAFETY: _mm_loadu_si128 reads 16 bytes, the referenced [u32; 4].
    unsafe { _mm_loadu_si128(k[r & 15].as_ptr().cast()) }
}

/// 64 rounds on S streams; m[s] holds stream s's 16 message words.  Unrolled by a macro and inlined into
/// `ni_lanes`, its only caller, so the message words stay in registers.
#[inline(always)]
fn ni_compress<const S: usize>(
    st0: &mut [__m128i; S],
    st1: &mut [__m128i; S],
    m: &mut [[__m128i; 4]; S],
) {
    let (a0, a1) = (*st0, *st1);
    macro_rules! quad {
        ($r:expr, $sched:expr) => {{
            let kr = ni_k4($r);
            for s in 0..S {
                // SAFETY: register-only SHA / SSE intrinsics; only called from `ni_lanes`, which enables
                // sha, sse4.1 and ssse3 and runs after the CPU check.
                unsafe {
                    let wk = _mm_add_epi32(m[s][$r & 3], kr);
                    st1[s] = _mm_sha256rnds2_epu32(st1[s], st0[s], wk);
                    st0[s] = _mm_sha256rnds2_epu32(st0[s], st1[s], _mm_shuffle_epi32::<0x0E>(wk));
                    if $sched {
                        // W[4(r+4)..] from the last four groups: msg1, + W[t-7] (alignr), msg2
                        let w = _mm_sha256msg1_epu32(m[s][$r & 3], m[s][($r + 1) & 3]);
                        let w = _mm_add_epi32(w, _mm_alignr_epi8::<4>(m[s][($r + 3) & 3], m[s][($r + 2) & 3]));
                        m[s][$r & 3] = _mm_sha256msg2_epu32(w, m[s][($r + 3) & 3]);
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
        // SAFETY: register-only SSE2 adds.
        unsafe {
            st0[s] = _mm_add_epi32(st0[s], a0[s]);
            st1[s] = _mm_add_epi32(st1[s], a1[s]);
        }
    }
}

/// S plans with the same block count; RAW: plain SHA-256 (no outer hash).
#[inline]
#[target_feature(enable = "sha,sse4.1,ssse3")]
fn ni_lanes<const S: usize, const RAW: bool>(
    k: &Midstates,
    p: [&Plan<'_>; S],
    out: &mut [[u32; 8]; S],
) {
    let bswap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
    let (ih0, ih1) = ni_ld(&k.ih);
    let mut st0 = [ih0; S];
    let mut st1 = [ih1; S];
    let mut tails = [[0u8; 128]; S];
    for s in 0..S {
        p[s].tail(&mut tails[s]);
    }
    let full = p.map(|q| q.m.as_chunks::<64>().0);
    let mut m = [[ih0; 4]; S];
    for b in 0..p[0].nb as usize {
        for s in 0..S {
            let blk = match full[s].get(b) {
                Some(x) => x,
                None => tails[s]
                    .as_chunks::<64>()
                    .0
                    .get(b - full[s].len())
                    .unwrap_or(&ZERO_BLOCK),
            };
            let (c, _) = blk.as_chunks::<16>();
            // SAFETY: each _mm_loadu_si128 reads 16 bytes, exactly one referenced [u8; 16] (a 64-byte block
            // has four); the shuffle is SSSE3, which this function enables.
            let ld = |j: usize| unsafe {
                _mm_shuffle_epi8(_mm_loadu_si128(c[j].as_ptr().cast()), bswap)
            };
            m[s] = [ld(0), ld(1), ld(2), ld(3)];
        }
        ni_compress::<S>(&mut st0, &mut st1, &mut m);
    }
    if !RAW {
        let (oh0, oh1) = ni_ld(&k.oh);
        for s in 0..S {
            let mut d = [0u32; 8];
            ni_st(st0[s], st1[s], &mut d);
            let (lo, hi) = ni_ld_plain(&d);
            m[s] = [
                lo,
                hi,
                _mm_set_epi32(0, 0, 0, 0x8000_0000u32 as i32),
                _mm_set_epi32((64 + 32) * 8, 0, 0, 0),
            ];
            st0[s] = oh0;
            st1[s] = oh1;
        }
        ni_compress::<S>(&mut st0, &mut st1, &mut m);
    }
    for s in 0..S {
        ni_st(st0[s], st1[s], &mut out[s]);
    }
}

/// h0..h3 and h4..h7 as message words (the inner digest is the outer hash's W0..W7).
#[inline(always)]
fn ni_ld_plain(d: &[u32; 8]) -> (__m128i, __m128i) {
    let (c, _) = d.as_chunks::<4>();
    // SAFETY: each _mm_loadu_si128 reads 16 bytes, exactly one referenced [u32; 4].
    unsafe {
        (
            _mm_loadu_si128(c[0].as_ptr().cast()),
            _mm_loadu_si128(c[1].as_ptr().cast()),
        )
    }
}

/// The SHA-NI engine's token: exists only after the CPU check (made in `hmac` / `sha256`).
#[derive(Clone, Copy)]
struct KNi(());

impl sha256::Streams for KNi {
    const THREE: bool = true;
    #[inline(always)]
    fn run<const S: usize, const RAW: bool>(
        self,
        k: &Midstates,
        p: [&Plan<'_>; S],
        out: &mut [[u32; 8]; S],
    ) {
        // SAFETY: a KNi exists only after the CPU was checked for SHA, SSE4.1 and SSSE3.
        unsafe { ni_lanes::<S, RAW>(k, p, out) }
    }
}

#[target_feature(enable = "sha,sse4.1,ssse3")]
fn ni_drive<const S: usize, const RAW: bool>(k: &Midstates, msgs: &[&[u8]], mac: &mut [[u32; 8]]) {
    sha256::drive_streams::<KNi, S, RAW>(KNi(()), k, msgs, mac)
}

// ---- base64url: 32 chars -> 24 bytes per step (Mula/Lemire packing; base64url via range compares) ----

#[inline(always)]
/// Decodes 32 characters into the low 24 bytes of the result; also returns 0xFF in every invalid byte.
fn b64_32(src: &[u8; 32]) -> (__m256i, __m256i) {
    // SAFETY: _mm256_loadu_si256 reads 32 bytes (`src`); the rest are register-only AVX2 intrinsics, and this is
    // only reached from the AVX2-enabled decoder.
    unsafe {
        let v = _mm256_loadu_si256(src.as_ptr().cast());
        let rng = |lo: u8, hi: u8| {
            _mm256_and_si256(
                _mm256_cmpgt_epi8(v, _mm256_set1_epi8(lo as i8 - 1)),
                _mm256_cmpgt_epi8(_mm256_set1_epi8(hi as i8 + 1), v),
            )
        };
        let (up, lw, dg) = (rng(b'A', b'Z'), rng(b'a', b'z'), rng(b'0', b'9'));
        let da = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(b'-' as i8));
        let us = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(b'_' as i8));
        let off = _mm256_or_si256(
            _mm256_or_si256(
                _mm256_and_si256(up, _mm256_set1_epi8(-65)),
                _mm256_and_si256(lw, _mm256_set1_epi8(-71)),
            ),
            _mm256_or_si256(
                _mm256_and_si256(dg, _mm256_set1_epi8(4)),
                _mm256_or_si256(
                    _mm256_and_si256(da, _mm256_set1_epi8(17)),
                    _mm256_and_si256(us, _mm256_set1_epi8(-32)),
                ),
            ),
        );
        let ok = _mm256_or_si256(
            _mm256_or_si256(up, lw),
            _mm256_or_si256(dg, _mm256_or_si256(da, us)),
        );
        let mut x = _mm256_add_epi8(v, off);
        x = _mm256_maddubs_epi16(x, _mm256_set1_epi32(0x0140_0140));
        x = _mm256_madd_epi16(x, _mm256_set1_epi32(0x0001_1000));
        x = _mm256_shuffle_epi8(
            x,
            _mm256_setr_epi8(
                2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1, 2, 1, 0, 6, 5, 4, 10, 9, 8,
                14, 13, 12, -1, -1, -1, -1,
            ),
        );
        x = _mm256_permutevar8x32_epi32(x, _mm256_setr_epi32(0, 1, 2, 4, 5, 6, 7, 7));
        (x, _mm256_xor_si256(ok, _mm256_set1_epi8(-1))) // 0xFF where invalid
    }
}

#[target_feature(enable = "avx2")]
fn b64_avx2(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    if dst.len() < crate::b64::decoded_cap(src.len()) {
        return None;
    }
    let (blocks, rest) = src.as_chunks::<32>();
    let mut bad = _mm256_setzero_si256();
    let mut o = 0;
    for b in blocks {
        let (x, e) = b64_32(b);
        bad = _mm256_or_si256(bad, e);
        // the 32-byte store writes 8 bytes past the 24 decoded ones: directly when dst has room, else via a copy
        match dst
            .get_mut(o..o + 32)
            .and_then(|d| <&mut [u8; 32]>::try_from(d).ok())
        {
            // SAFETY: _mm256_storeu_si256 writes 32 bytes, exactly the referenced [u8; 32].
            Some(d) => unsafe { _mm256_storeu_si256(d.as_mut_ptr().cast(), x) },
            None => {
                let mut t = [0u8; 32];
                // SAFETY: as above, into the local array.
                unsafe { _mm256_storeu_si256(t.as_mut_ptr().cast(), x) };
                dst.get_mut(o..o + 24)?.copy_from_slice(&t[..24]);
            }
        }
        o += 24;
    }
    let q = rest.len() & !3;
    if q != 0 {
        // whole quanta of the tail: one more step over an 'A'-padded copy
        let mut buf = [b'A'; 32];
        buf[..q].copy_from_slice(&rest[..q]);
        let (x, e) = b64_32(&buf);
        bad = _mm256_or_si256(bad, e);
        let mut t = [0u8; 32];
        // SAFETY: _mm256_storeu_si256 writes 32 bytes, exactly the local array.
        unsafe { _mm256_storeu_si256(t.as_mut_ptr().cast(), x) };
        dst.get_mut(o..o + q / 4 * 3)?
            .copy_from_slice(&t[..q / 4 * 3]);
        o += q / 4 * 3;
    }
    if _mm256_testz_si256(bad, bad) == 0 {
        return None;
    }
    let t = crate::b64::tail(dst.get_mut(o..)?, &rest[q..])?;
    Some(o + t)
}

pub(crate) fn b64_decode(dst: &mut [u8], src: &[u8]) -> Option<Option<usize>> {
    if !CpuFeatures::get().has(CpuFeatures::AVX2) {
        return None;
    }
    // SAFETY: the CPU has AVX2 (checked just above).
    Some(unsafe { b64_avx2(dst, src) })
}

// ---- EdDSA: the comb additions compiled for BMI2 ----
// The field arithmetic is the safe generic code of `pk::ed25519`; inside this region LLVM multiplies with mulx,
// whose free destination registers remove most of the moves and spills that mul's rax/rdx pinning causes.

#[cfg(feature = "pk")]
use crate::pk::ed25519::{self as ed, Niels, P3};

#[cfg(feature = "pk")]
#[target_feature(enable = "bmi2")]
#[inline(never)]
fn ed_madd_bmi2(p: &mut P3, q: &Niels) {
    ed::madd_impl(p, q)
}

#[cfg(feature = "pk")]
#[target_feature(enable = "bmi2")]
#[inline(never)]
fn ed_msub_bmi2(p: &mut P3, q: &Niels) {
    ed::msub_impl(p, q)
}

/// `pk::ed25519::combs` through the BMI2 madd / msub; false (nothing done) on a CPU without BMI2.
#[cfg(feature = "pk")]
pub(crate) fn ed25519_combs(
    p: &mut P3,
    tb: &[[Niels; ed::H]],
    ta: &[[Niels; ed::H]],
    ds: &[i8; ed::NW],
    dk: &[i8; ed::NW],
) -> bool {
    if !CpuFeatures::get().has(CpuFeatures::BMI2) {
        return false;
    }
    ed::combs(
        p,
        tb,
        ta,
        ds,
        dk,
        // SAFETY: the check above found BMI2, the feature these two functions enable.
        |p, q| unsafe { ed_madd_bmi2(p, q) },
        // SAFETY: as above.
        |p, q| unsafe { ed_msub_bmi2(p, q) },
    );
    true
}
