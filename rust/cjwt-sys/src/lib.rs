//! Test-only bindings to the C library (`include/jwt.h`), for the differential tests and for benchmarking the
//! C and Rust code in the same run.  Not published; the Rust crate never links it.
//!
//! The wrappers take slices and return owned values; the `unsafe` here is the FFI boundary only.
#![allow(non_camel_case_types, unsafe_code)]

use std::os::raw::{c_char, c_int, c_uint};

pub const JWT_OK: u8 = 0;
pub const JWT_INVALID: u8 = 1;
pub const JWT_BAD_PAYLOAD: u8 = 2;
pub const USERNAME_MAX: usize = 255;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct jwt_key_t {
    pub ih: [u32; 8],
    pub oh: [u32; 8],
}

#[repr(C)]
pub struct jwt_result_t {
    pub status: u8,
    pub username_escape: u8,
    pub username_len: u16,
    pub uid: i64,
    pub username: *const c_char,
    pub ubuf: [c_char; USERNAME_MAX + 1],
}

#[repr(C)]
pub struct jwt_pkey_t {
    _p: [u8; 0],
}

pub type verify_fn = unsafe extern "C" fn(
    *const jwt_key_t,
    c_int,
    *const *const c_char,
    *const c_int,
    i64,
    *mut jwt_result_t,
);
pub type hmac_fn =
    unsafe extern "C" fn(*const jwt_key_t, c_int, *const *const u8, *const c_int, *mut [u32; 8]);

extern "C" {
    pub fn jwt_key_init(k: *mut jwt_key_t, secret: *const u8, len: usize);
    pub fn jwt_verify_batch(
        k: *const jwt_key_t,
        n: c_int,
        tok: *const *const c_char,
        len: *const c_int,
        now: i64,
        out: *mut jwt_result_t,
    );
    pub fn jwt_verify_batch_scalar(
        k: *const jwt_key_t,
        n: c_int,
        tok: *const *const c_char,
        len: *const c_int,
        now: i64,
        out: *mut jwt_result_t,
    );
    pub fn jwt_cpu_features() -> c_uint;
    pub fn jwt_engine() -> *const c_char;
    pub fn jwt_hmac_scalar(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_b64url_decode(dst: *mut u8, src: *const c_char, n: c_int) -> c_int;
    pub fn jwt_pkey_es256(x: *const u8, y: *const u8) -> *mut jwt_pkey_t;
    pub fn jwt_pkey_rs256(n: *const u8, nlen: usize, e: *const u8, elen: usize) -> *mut jwt_pkey_t;
    pub fn jwt_pkey_ed25519(a: *const u8) -> *mut jwt_pkey_t;
    pub fn jwt_pkey_free(k: *mut jwt_pkey_t);
    pub fn jwt_verify_batch_pk(
        k: *const jwt_pkey_t,
        n: c_int,
        tok: *const *const c_char,
        len: *const c_int,
        now: i64,
        out: *mut jwt_result_t,
    );
    pub fn jwt_sha256_batch(n: c_int, msg: *const *const u8, len: *const c_int, dig: *mut [u32; 8]);
}

/// One token's result, owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CResult {
    pub status: u8,
    pub uid: i64,
    pub username: Vec<u8>,
    pub escape: bool,
}

fn collect(out: &[jwt_result_t]) -> Vec<CResult> {
    out.iter()
        .map(|r| CResult {
            status: r.status,
            uid: r.uid,
            username: r.ubuf[..r.username_len as usize]
                .iter()
                .map(|&c| c.to_ne_bytes()[0])
                .collect(),
            escape: r.username_escape != 0,
        })
        .collect()
}

fn blank(n: usize) -> Vec<jwt_result_t> {
    (0..n)
        .map(|_| jwt_result_t {
            status: 0,
            username_escape: 0,
            username_len: 0,
            uid: 0,
            username: std::ptr::null(),
            ubuf: [0; USERNAME_MAX + 1],
        })
        .collect()
}

fn ptrs<T: AsRef<[u8]>>(toks: &[T]) -> (Vec<*const c_char>, Vec<c_int>) {
    (
        toks.iter()
            .map(|t| t.as_ref().as_ptr().cast::<c_char>())
            .collect(),
        toks.iter().map(|t| t.as_ref().len() as c_int).collect(),
    )
}

/// An HS256 key of the C library.
pub struct Key(jwt_key_t);

impl Key {
    pub fn new(secret: &[u8]) -> Key {
        let mut k = jwt_key_t {
            ih: [0; 8],
            oh: [0; 8],
        };
        // SAFETY: k is a valid jwt_key_t; secret is readable for its length.
        unsafe { jwt_key_init(&mut k, secret.as_ptr(), secret.len()) };
        Key(k)
    }
    pub fn midstates(&self) -> ([u32; 8], [u32; 8]) {
        (self.0.ih, self.0.oh)
    }
    pub fn verify_batch<T: AsRef<[u8]>>(&self, toks: &[T], now: i64) -> Vec<CResult> {
        let mut out = blank(toks.len());
        self.verify_into(toks, now, &mut out);
        collect(&out)
    }
    /// For benchmarks: no allocation per call beyond the caller's buffers.
    pub fn verify_into<T: AsRef<[u8]>>(&self, toks: &[T], now: i64, out: &mut [jwt_result_t]) {
        let (p, l) = ptrs(toks);
        self.verify_raw(&p, &l, now, out);
    }
    pub fn verify_raw(&self, p: &[*const c_char], l: &[c_int], now: i64, out: &mut [jwt_result_t]) {
        assert!(p.len() == l.len() && out.len() >= p.len());
        // SAFETY: p[i] is readable for l[i] bytes (the caller built them from slices), out has room for n.
        unsafe {
            jwt_verify_batch(
                &self.0,
                p.len() as c_int,
                p.as_ptr(),
                l.as_ptr(),
                now,
                out.as_mut_ptr(),
            )
        };
    }
    pub fn verify_batch_scalar<T: AsRef<[u8]>>(&self, toks: &[T], now: i64) -> Vec<CResult> {
        let (p, l) = ptrs(toks);
        let mut out = blank(toks.len());
        // SAFETY: as in verify_raw.
        unsafe {
            jwt_verify_batch_scalar(
                &self.0,
                p.len() as c_int,
                p.as_ptr(),
                l.as_ptr(),
                now,
                out.as_mut_ptr(),
            )
        };
        collect(&out)
    }
    pub fn hmac_scalar(&self, msgs: &[&[u8]]) -> Vec<[u32; 8]> {
        let (p, l): (Vec<*const u8>, Vec<c_int>) = (
            msgs.iter().map(|m| m.as_ptr()).collect(),
            msgs.iter().map(|m| m.len() as c_int).collect(),
        );
        let mut mac = vec![[0u32; 8]; msgs.len()];
        // SAFETY: as in verify_raw.
        unsafe {
            jwt_hmac_scalar(
                &self.0,
                p.len() as c_int,
                p.as_ptr(),
                l.as_ptr(),
                mac.as_mut_ptr(),
            )
        };
        mac
    }
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    pub fn jwt_hmac_neon(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_hmac_sha2(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
}
#[cfg(target_arch = "x86_64")]
extern "C" {
    pub fn jwt_hmac_avx2(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_hmac_avx2x2(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_hmac_avx512(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_hmac_avx512x2(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_hmac_zmm(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_hmac_shani_1(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_hmac_shani_2(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
    pub fn jwt_hmac_shani_4(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
}
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
extern "C" {
    pub fn jwt_hmac_ossl(
        k: *const jwt_key_t,
        n: c_int,
        msg: *const *const u8,
        len: *const c_int,
        mac: *mut [u32; 8],
    );
}

/// The C HMAC engines this CPU can run, by the Rust engine names (plus "ossl", the extracted OpenSSL single
/// stream on x86-64 Linux).
pub fn hmac_engines() -> Vec<(&'static str, hmac_fn)> {
    let f = cpu_features();
    #[allow(unused_mut)]
    let mut v: Vec<(&'static str, hmac_fn)> = vec![("scalar", jwt_hmac_scalar)];
    #[cfg(target_arch = "aarch64")]
    {
        v.push(("neon", jwt_hmac_neon));
        if f & 32 != 0 {
            v.push(("sha2", jwt_hmac_sha2));
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if f & 1 != 0 {
            v.push(("avx2", jwt_hmac_avx2));
            v.push(("avx2x2", jwt_hmac_avx2x2));
        }
        if f & 2 != 0 {
            v.push(("avx512vl", jwt_hmac_avx512));
            v.push(("avx512x2", jwt_hmac_avx512x2));
            v.push(("zmm", jwt_hmac_zmm));
        }
        if f & 8 != 0 {
            v.push(("shani", jwt_hmac_shani_4));
            v.push(("shanix1", jwt_hmac_shani_1));
            v.push(("shanix2", jwt_hmac_shani_2));
        }
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    v.push(("ossl", jwt_hmac_ossl));
    let _ = f;
    v
}

impl Key {
    /// HMAC tags through a chosen C engine (pointer arrays prebuilt by the caller).
    pub fn hmac_raw(&self, f: hmac_fn, p: &[*const u8], l: &[c_int], mac: &mut [[u32; 8]]) {
        assert!(p.len() == l.len() && mac.len() >= p.len());
        // SAFETY: p[i] readable for l[i] bytes, mac has room for n tags; f is one of hmac_engines().
        unsafe {
            f(
                &self.0,
                p.len() as c_int,
                p.as_ptr(),
                l.as_ptr(),
                mac.as_mut_ptr(),
            )
        };
    }
}

/// Blank result buffers for [`Key::verify_into`] / [`PKey::verify_into`].
pub fn results(n: usize) -> Vec<jwt_result_t> {
    blank(n)
}

/// The C library's engine name and CPU features.
pub fn engine() -> String {
    // SAFETY: jwt_engine returns a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(jwt_engine()) }
        .to_string_lossy()
        .into_owned()
}
pub fn cpu_features() -> u32 {
    // SAFETY: no arguments.
    unsafe { jwt_cpu_features() }
}

/// base64url decode, or None.
pub fn b64url_decode(src: &[u8]) -> Option<Vec<u8>> {
    let mut d = vec![0u8; src.len() / 4 * 3 + 3 + 32];
    // SAFETY: d has the room jwt.h asks for (n/4*3 + 3 + 32 bytes of slack).
    let n = unsafe {
        jwt_b64url_decode(
            d.as_mut_ptr(),
            src.as_ptr().cast::<c_char>(),
            src.len() as c_int,
        )
    };
    (n >= 0).then(|| {
        d.truncate(n as usize);
        d
    })
}

/// A public key of the C library (freed on drop).
pub struct PKey(*mut jwt_pkey_t);

// SAFETY: the C key is read-only after setup.
unsafe impl Send for PKey {}
// SAFETY: as above.
unsafe impl Sync for PKey {}

impl PKey {
    pub fn es256(x: &[u8; 32], y: &[u8; 32]) -> Option<PKey> {
        // SAFETY: two 32-byte arrays.
        let k = unsafe { jwt_pkey_es256(x.as_ptr(), y.as_ptr()) };
        (!k.is_null()).then_some(PKey(k))
    }
    pub fn rs256(n: &[u8], e: &[u8]) -> Option<PKey> {
        // SAFETY: slices readable for their lengths.
        let k = unsafe { jwt_pkey_rs256(n.as_ptr(), n.len(), e.as_ptr(), e.len()) };
        (!k.is_null()).then_some(PKey(k))
    }
    pub fn ed25519(a: &[u8; 32]) -> Option<PKey> {
        // SAFETY: a 32-byte array.
        let k = unsafe { jwt_pkey_ed25519(a.as_ptr()) };
        (!k.is_null()).then_some(PKey(k))
    }
    pub fn verify_batch<T: AsRef<[u8]>>(&self, toks: &[T], now: i64) -> Vec<CResult> {
        let mut out = blank(toks.len());
        self.verify_into(toks, now, &mut out);
        collect(&out)
    }
    pub fn verify_into<T: AsRef<[u8]>>(&self, toks: &[T], now: i64, out: &mut [jwt_result_t]) {
        let (p, l) = ptrs(toks);
        self.verify_raw(&p, &l, now, out);
    }
    pub fn verify_raw(&self, p: &[*const c_char], l: &[c_int], now: i64, out: &mut [jwt_result_t]) {
        assert!(p.len() == l.len() && out.len() >= p.len());
        // SAFETY: as in Key::verify_raw; self.0 is a live key.
        unsafe {
            jwt_verify_batch_pk(
                self.0,
                p.len() as c_int,
                p.as_ptr(),
                l.as_ptr(),
                now,
                out.as_mut_ptr(),
            )
        };
    }
}

impl Drop for PKey {
    fn drop(&mut self) {
        // SAFETY: self.0 came from jwt_pkey_* and is freed once.
        unsafe { jwt_pkey_free(self.0) }
    }
}

/// Pointer and length arrays for a batch (benchmarks build these once).
pub fn token_ptrs<T: AsRef<[u8]>>(toks: &[T]) -> (Vec<*const c_char>, Vec<c_int>) {
    ptrs(toks)
}
