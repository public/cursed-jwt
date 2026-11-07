//! The crate's only unsafe code: `core::arch` intrinsics for the SIMD engines, each behind a run-time check.
//!
//! Soundness rests on one rule: every `#[target_feature]` function here is called only after
//! [`CpuFeatures::get`] reported the features it enables, and that check is made in this module, next to the
//! call (masking features through `JWT_CPU_MASK` can only remove them).  Inside those functions, the `unsafe`
//! blocks are loads and stores through references to arrays of exactly the size the intrinsic reads or writes,
//! and calls of intrinsics whose features the enclosing function enables.  Each block says which.
//!
//! The SIMD types implement the safe `sha256::Simd` trait; the multi-buffer template itself
//! (`sha256::lanes`) is safe generic code, compiled here inside each engine's target-feature region.

use crate::engine::{CpuFeatures, Engine};
use crate::sha256::Midstates;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::{available, b64_decode, detect, hmac, sha256};
#[cfg(target_arch = "x86_64")]
pub(crate) use x86::{available, b64_decode, detect, hmac, sha256};

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod portable {
    use super::*;
    pub(crate) fn detect() -> u32 {
        0
    }
    pub(crate) fn available(e: Engine, _f: CpuFeatures) -> bool {
        e == Engine::Scalar
    }
    pub(crate) fn hmac(_e: Engine, _k: &Midstates, _m: &[&[u8]], _o: &mut [[u32; 8]]) -> bool {
        false
    }
    pub(crate) fn sha256(_e: Engine, _m: &[&[u8]], _o: &mut [[u32; 8]]) -> bool {
        false
    }
    pub(crate) fn b64_decode(_d: &mut [u8], _s: &[u8]) -> Option<Option<usize>> {
        None
    }
}
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) use portable::{available, b64_decode, detect, hmac, sha256};
