//! The Rust port behind the symbols tests/pyshim.c exports, with the same structure layouts as include/jwt.h,
//! so the independent Python model in tests/test_hypothesis.py checks the Rust code unchanged:
//!   python3 -I tests/test_hypothesis.py rust/target/release/libcursed_jwt_pyshim.{so,dylib} 200
//! Test-only; the `unsafe` is the C ABI boundary (raw pointers from ctypes).
#![allow(unsafe_code, clippy::missing_safety_doc)]

use cursed_jwt::{
    Ed25519Key, Engine, Error, Es256Key, Hs256Key, PublicKey, Rs256Key, Verdict, USERNAME_MAX,
};
use std::os::raw::{c_char, c_int};

#[repr(C)]
pub struct JwtResult {
    status: u8,
    username_escape: u8,
    username_len: u16,
    uid: i64,
    username: *const c_char,
    ubuf: [u8; USERNAME_MAX + 1],
}

fn engines() -> Vec<Option<Engine>> {
    let mut v = vec![None]; // "default": verify_batch
    v.extend(
        Engine::ALL
            .into_iter()
            .filter(|e| e.is_available())
            .map(Some),
    );
    v
}

unsafe fn tokens<'a>(n: c_int, tok: *const *const c_char, len: *const c_int) -> Vec<&'a [u8]> {
    (0..n.max(0) as usize)
        .map(|i| unsafe {
            std::slice::from_raw_parts(*tok.add(i) as *const u8, (*len.add(i)).max(0) as usize)
        })
        .collect()
}

unsafe fn write(out: *mut JwtResult, v: &[Verdict]) {
    for (i, r) in v.iter().enumerate() {
        let o = unsafe { &mut *out.add(i) };
        o.ubuf = [0; USERNAME_MAX + 1];
        o.username = o.ubuf.as_ptr() as *const c_char;
        (o.status, o.uid, o.username_len, o.username_escape) = match r {
            Ok(c) => {
                let u = c.username_bytes();
                o.ubuf[..u.len()].copy_from_slice(u);
                (0, c.uid(), u.len() as u16, c.username_needs_escape() as u8)
            }
            Err(Error::Invalid) => (1, 0, 0, 0),
            Err(Error::BadPayload) => (2, 0, 0, 0),
        };
    }
}

#[no_mangle]
pub extern "C" fn jt_engines() -> c_int {
    engines().len() as c_int
}

#[no_mangle]
pub extern "C" fn jt_engine_name(i: c_int) -> *const c_char {
    let names = [
        c"default",
        c"scalar",
        c"neon",
        c"sha2",
        c"sha2x1",
        c"sha2x2",
        c"avx2",
        c"avx2x2",
        c"avx512vl",
        c"avx512x2",
        c"zmm",
    ];
    match engines().get(i as usize) {
        Some(None) => names[0].as_ptr(),
        Some(Some(e)) => names
            .iter()
            .find(|n| n.to_str() == Ok(e.name()))
            .unwrap_or(&names[1])
            .as_ptr(),
        None => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn jt_sizeof_key() -> usize {
    std::mem::size_of::<Hs256Key>()
}

#[no_mangle]
pub extern "C" fn jt_sizeof_result() -> usize {
    std::mem::size_of::<JwtResult>()
}

#[no_mangle]
pub unsafe extern "C" fn jwt_key_init(k: *mut Hs256Key, secret: *const u8, len: usize) {
    let s = unsafe { std::slice::from_raw_parts(secret, len) };
    unsafe { k.write_unaligned(Hs256Key::new(s)) };
}

#[no_mangle]
pub unsafe extern "C" fn jt_verify(
    i: c_int,
    k: *const Hs256Key,
    n: c_int,
    tok: *const *const c_char,
    len: *const c_int,
    now: i64,
    out: *mut JwtResult,
) {
    let key = unsafe { k.read_unaligned() };
    let t = unsafe { tokens(n, tok, len) };
    let mut v: Vec<Verdict> = vec![Err(Error::Invalid); t.len()];
    match engines().get(i as usize) {
        Some(Some(e)) => key.verify_batch_with(*e, &t, now, &mut v),
        _ => key.verify_batch(&t, now, &mut v),
    }
    unsafe { write(out, &v) };
}

fn boxed(k: Option<PublicKey>) -> *mut PublicKey {
    k.map_or(std::ptr::null_mut(), |k| Box::into_raw(Box::new(k)))
}

#[no_mangle]
pub unsafe extern "C" fn jwt_pkey_es256(x: *const [u8; 32], y: *const [u8; 32]) -> *mut PublicKey {
    boxed(unsafe { Es256Key::new(&*x, &*y) }.map(|k| PublicKey::Es256(Box::new(k))))
}

#[no_mangle]
pub unsafe extern "C" fn jwt_pkey_rs256(
    n: *const u8,
    nlen: usize,
    e: *const u8,
    elen: usize,
) -> *mut PublicKey {
    let (n, e) = unsafe {
        (
            std::slice::from_raw_parts(n, nlen),
            std::slice::from_raw_parts(e, elen),
        )
    };
    boxed(Rs256Key::new(n, e).map(|k| PublicKey::Rs256(Box::new(k))))
}

#[no_mangle]
pub unsafe extern "C" fn jwt_pkey_ed25519(a: *const [u8; 32]) -> *mut PublicKey {
    boxed(unsafe { Ed25519Key::new(&*a) }.map(|k| PublicKey::EdDsa(Box::new(k))))
}

#[no_mangle]
pub unsafe extern "C" fn jwt_pkey_free(k: *mut PublicKey) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}

#[no_mangle]
pub unsafe extern "C" fn jwt_verify_batch_pk(
    k: *const PublicKey,
    n: c_int,
    tok: *const *const c_char,
    len: *const c_int,
    now: i64,
    out: *mut JwtResult,
) {
    let t = unsafe { tokens(n, tok, len) };
    let mut v: Vec<Verdict> = vec![Err(Error::Invalid); t.len()];
    unsafe { &*k }.verify_batch(&t, now, &mut v);
    unsafe { write(out, &v) };
}
