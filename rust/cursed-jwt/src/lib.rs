//! Batch JWT verification.
//!
//! Instead of checking HS256 tokens one at a time, [`Hs256Key::verify_batch`] checks many at once with one
//! multi-buffer SIMD HMAC-SHA256 pass, one token per vector lane: 8 lanes with AVX-512VL (on ymm registers) or
//! AVX2 on x86-64, 4 interleaved SHA2-instruction streams or 4 NEON lanes on AArch64, scalar code elsewhere.
//! The engine is picked at run time from the CPU.  RS256, ES256 and EdDSA (Ed25519) share the same front end
//! and claim rules (feature `pk`, on by default).
//!
//! This is the Rust port of the C library in the same repository; it accepts and rejects exactly the same
//! tokens (the tests check that differentially against the C code).
//!
//! ```
//! use cursed_jwt::{Error, Hs256Key};
//!
//! let key = Hs256Key::new(b"cursed-jwt-test-secret");
//! let tokens: [&[u8]; 2] = [b"not.a.token", b"eyJhbGciOiJIUzI1NiJ9.e30.AAAA"];
//! let mut out = [Err(Error::Invalid), Err(Error::Invalid)];
//! key.verify_batch(&tokens, 1_700_000_000, &mut out);
//! assert!(out.iter().all(|r| r.is_err()));
//! ```
//!
//! # Claim semantics
//!
//! Checks run in this order: structure, header, signature (always computed), payload JSON, time claims,
//! `sub` / `username`.  A token is live iff `nbf <= now < exp`; `exp` is required.  `sub` must be a string of
//! ASCII digits with value 1..=2^63-1, and `username` a string of at most [`USERNAME_MAX`] bytes once decoded;
//! otherwise the result is [`Error::BadPayload`].  Everything else that is wrong is [`Error::Invalid`].  The
//! README of the repository has the full table.
//!
//! # Unsafe code
//!
//! Every module is `#![forbid(unsafe_code)]` except `arch`, which holds the `core::arch` intrinsics of the SIMD
//! engines behind run-time feature checks.
#![no_std]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[allow(unsafe_code)]
mod arch;
mod b64;
mod engine;
mod hs256;
mod json;
mod sha256;

pub use engine::{CpuFeatures, Engine};
pub use hs256::Hs256Key;

pub use b64::{decode_scalar as b64url_decode_scalar, decoded_cap as b64url_decoded_cap};

/// base64url decode (RFC 4648 section 5: no padding, canonical trailing bits) with the fastest decoder this CPU
/// has.  Returns the decoded length, or `None` if `src` is not canonical unpadded base64url or `dst` is shorter
/// than [`b64url_decoded_cap`]`(src.len())`.
pub fn b64url_decode(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    engine::b64_decode(dst, src)
}

/// Longest username accepted, in decoded bytes; longer ones give [`Error::BadPayload`].
pub const USERNAME_MAX: usize = 255;
/// Longest token accepted, in bytes; longer ones give [`Error::Invalid`].
pub const TOKEN_MAX: usize = 8192;

/// Why a token was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// Malformed, wrong `alg`, bad signature, expired or not yet valid.
    Invalid,
    /// Signature and time are fine, but `sub` or `username` is missing or unusable.
    BadPayload,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Invalid => "invalid token",
            Error::BadPayload => "unusable sub or username claim",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The claims of a valid token.
#[derive(Clone)]
pub struct Claims {
    uid: i64,
    len: u16,
    escape: bool,
    buf: [u8; USERNAME_MAX],
}

impl Claims {
    const EMPTY: Claims = Claims {
        uid: 0,
        len: 0,
        escape: false,
        buf: [0; USERNAME_MAX],
    };

    /// The integer in `sub`, at least 1.
    pub fn uid(&self) -> i64 {
        self.uid
    }

    /// `username`, decoded and unescaped (always valid UTF-8).
    pub fn username(&self) -> &str {
        core::str::from_utf8(self.username_bytes()).unwrap_or_default()
    }

    /// `username` as bytes.
    pub fn username_bytes(&self) -> &[u8] {
        self.buf.get(..self.len as usize).unwrap_or_default()
    }

    /// Whether `username` contains `"`, `\` or a byte below 0x20 and so must be JSON-escaped before it is
    /// written into a JSON string.  When false the bytes can go verbatim between quotes.
    pub fn username_needs_escape(&self) -> bool {
        self.escape
    }

    fn set_username(&mut self, u: &[u8], escape: bool) {
        let n = u.len().min(USERNAME_MAX);
        self.buf[..n].copy_from_slice(&u[..n]);
        self.len = n as u16;
        self.escape = escape;
    }
}

impl core::fmt::Debug for Claims {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Claims")
            .field("uid", &self.uid)
            .field("username", &self.username())
            .finish()
    }
}

impl PartialEq for Claims {
    fn eq(&self, o: &Self) -> bool {
        self.uid == o.uid && self.escape == o.escape && self.username_bytes() == o.username_bytes()
    }
}
impl Eq for Claims {}

/// The result of verifying one token.
pub type Verdict = Result<Claims, Error>;
