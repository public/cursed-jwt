//! Run-time CPU dispatch: which SHA-256 engines this machine can run, and the default choice.
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch;
use crate::sha256::{self, Midstates};

static BITS: AtomicU32 = AtomicU32::new(0);

/// CPU features the engines care about (the same bits as the C library's `JWT_CPU_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuFeatures(u32);

impl CpuFeatures {
    /// x86-64: AVX2 with BMI1 and BMI2.
    pub const AVX2: u32 = 1;
    /// x86-64: AVX-512 F, VL, BW, DQ and CD (with AVX2).
    pub const AVX512VL: u32 = 2;
    /// x86-64: BMI2 and ADX.
    pub const BMI2_ADX: u32 = 4;
    /// x86-64: the SHA extensions.
    pub const SHANI: u32 = 8;
    /// x86-64: AVX-512 IFMA.
    pub const IFMA: u32 = 16;
    /// AArch64: the SHA-256 instructions.
    pub const SHA2: u32 = 32;
    /// AArch64: the SHA-512 instructions.
    pub const SHA512: u32 = 64;
    /// x86-64: 512-bit vectors cost no clock speed (AMD Zen 4 / 5), so the 16-lane zmm engine is the default.
    pub const FAST_ZMM: u32 = 128;
    /// x86-64: SHA-NI that beats the vector engines (AMD Zen), so the 4-stream SHA-NI engine is the default.
    pub const FAST_SHANI: u32 = 256;
    /// x86-64: BMI2 (mulx; the EdDSA field arithmetic uses it).
    pub const BMI2: u32 = 512;
    const DETECTED: u32 = 1 << 31;

    /// The features of this CPU, detected once.  With the `std` feature, the environment variable
    /// `JWT_CPU_MASK=0x..` masks them (for tests and benchmarks: `JWT_CPU_MASK=0` runs everything on the
    /// fallbacks), and `JWT_CPU_FORCE_ZMM=1` claims `FAST_ZMM` on any AVX-512 CPU.
    #[inline(always)]
    pub fn get() -> Self {
        let f = BITS.load(Ordering::Relaxed);
        if f != 0 {
            return CpuFeatures(f & !Self::DETECTED);
        }
        Self::init()
    }

    #[cold]
    #[inline(never)]
    fn init() -> Self {
        let f = Self::detect() | Self::DETECTED;
        BITS.store(f, Ordering::Relaxed); // racing detectors all store the same value
        CpuFeatures(f & !Self::DETECTED)
    }

    fn detect() -> u32 {
        #[allow(unused_mut)]
        let mut f = arch::detect();
        #[cfg(feature = "std")]
        {
            if f & Self::AVX512VL != 0
                && std::env::var("JWT_CPU_FORCE_ZMM").is_ok_and(|v| v.starts_with('1'))
            {
                f |= Self::FAST_ZMM;
            }
            if let Ok(m) = std::env::var("JWT_CPU_MASK") {
                let m = m.trim();
                let v = match m.strip_prefix("0x").or_else(|| m.strip_prefix("0X")) {
                    Some(h) => u32::from_str_radix(h, 16).ok(),
                    None => m.parse().ok(),
                };
                if let Some(v) = v {
                    f &= v;
                }
            }
        }
        f
    }

    /// The raw bits.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `bits` is set.
    pub fn has(self, bits: u32) -> bool {
        self.0 & bits == bits
    }
}

/// A SHA-256 engine.  Every variant exists on every target; [`Engine::is_available`] says which ones this CPU
/// can run.  An engine that is not available falls back to [`Engine::Scalar`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Engine {
    /// Portable, one message at a time.
    Scalar,
    /// AArch64 NEON, 4 lanes.
    Neon,
    /// AArch64 SHA2 instructions, 4 interleaved streams.
    Sha2,
    /// AArch64 SHA2 instructions, one stream at a time.
    Sha2x1,
    /// AArch64 SHA2 instructions, 2 interleaved streams.
    Sha2x2,
    /// x86-64 AVX2, 8 lanes.
    Avx2,
    /// x86-64 AVX2, 16 lanes as two interleaved 8-lane groups.
    Avx2x2,
    /// x86-64 AVX-512VL on 256-bit registers, 8 lanes (`vprord`, `vpternlogd`; no frequency-licence drop).
    Avx512,
    /// x86-64 AVX-512VL, 16 lanes as two interleaved ymm groups.
    Avx512x2,
    /// x86-64 AVX-512 on 512-bit registers, 16 lanes (the default only where zmm costs no clock speed).
    Zmm,
    /// x86-64 SHA extensions, 4 interleaved streams (the default on AMD Zen).
    ShaNi,
    /// x86-64 SHA extensions, one stream at a time.
    ShaNix1,
    /// x86-64 SHA extensions, 2 interleaved streams.
    ShaNix2,
}

impl Engine {
    /// Every engine, available or not.
    pub const ALL: [Engine; 13] = [
        Engine::Scalar,
        Engine::Neon,
        Engine::Sha2,
        Engine::Sha2x1,
        Engine::Sha2x2,
        Engine::Avx2,
        Engine::Avx2x2,
        Engine::Avx512,
        Engine::Avx512x2,
        Engine::Zmm,
        Engine::ShaNi,
        Engine::ShaNix1,
        Engine::ShaNix2,
    ];

    /// Whether this CPU (and this build's target) can run the engine.
    pub fn is_available(self) -> bool {
        arch::available(self, CpuFeatures::get())
    }

    /// The engine [`crate::Hs256Key::verify_batch`] uses: SHA-NI on AMD, then AVX-512VL (or zmm on AMD Zen 4/5),
    /// then AVX2, then scalar on x86-64; SHA2 instructions, then NEON on AArch64.
    pub fn best() -> Engine {
        let f = CpuFeatures::get();
        let order = [
            Engine::Sha2,
            Engine::ShaNi,
            Engine::Zmm,
            Engine::Avx512,
            Engine::Avx2,
            Engine::Neon,
        ];
        for e in order {
            if (e == Engine::Zmm && !f.has(CpuFeatures::FAST_ZMM))
                || (e == Engine::ShaNi && !f.has(CpuFeatures::FAST_SHANI))
            {
                continue;
            }
            if arch::available(e, f) {
                return e;
            }
        }
        Engine::Scalar
    }

    /// Short name, as the C library's `jwt_engine()` prints it.
    pub fn name(self) -> &'static str {
        match self {
            Engine::Scalar => "scalar",
            Engine::Neon => "neon",
            Engine::Sha2 => "sha2",
            Engine::Sha2x1 => "sha2x1",
            Engine::Sha2x2 => "sha2x2",
            Engine::Avx2 => "avx2",
            Engine::Avx2x2 => "avx2x2",
            Engine::Avx512 => "avx512vl",
            Engine::Avx512x2 => "avx512x2",
            Engine::Zmm => "zmm",
            Engine::ShaNi => "shani",
            Engine::ShaNix1 => "shanix1",
            Engine::ShaNix2 => "shanix2",
        }
    }

    /// The engine `best()` picks, detected once.
    pub(crate) fn default_cached() -> Engine {
        static E: AtomicU32 = AtomicU32::new(u32::MAX);
        let v = E.load(Ordering::Relaxed);
        if let Some(&e) = Engine::ALL.get(v as usize) {
            return e;
        }
        let e = Engine::best();
        let i = Engine::ALL.iter().position(|&x| x == e).unwrap_or(0);
        E.store(i as u32, Ordering::Relaxed);
        e
    }

    /// HMAC-SHA256 of each message under the key's midstates, as 8 big-endian state words.
    pub(crate) fn hmac(self, k: &Midstates, msgs: &[&[u8]], out: &mut [[u32; 8]]) {
        if self == Engine::Scalar || !arch::hmac(self, k, msgs, out) {
            sha256::drive::<sha256::Scalar, 1, false, 1>(sha256::Scalar, k, msgs, out);
        }
    }

    /// Plain SHA-256 of each message (the RS256 / ES256 signing inputs).
    #[cfg_attr(not(feature = "pk"), allow(dead_code))]
    pub(crate) fn sha256(self, msgs: &[&[u8]], out: &mut [[u32; 8]]) {
        if self == Engine::Scalar || !arch::sha256(self, msgs, out) {
            sha256::drive::<sha256::Scalar, 1, true, 1>(sha256::Scalar, &sha256::SHA_IV, msgs, out);
        }
    }
}

/// base64url decode with the best decoder this CPU has (see [`crate::b64`]).
#[inline(always)]
pub(crate) fn b64_decode(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    match arch::b64_decode(dst, src) {
        Some(r) => r,
        None => crate::b64::decode_scalar(dst, src),
    }
}
