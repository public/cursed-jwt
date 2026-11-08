//! base64url: the SIMD decoder, the scalar one and the C library's must agree on every input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cap = cursed_jwt::b64url_decoded_cap(data.len());
    let (mut a, mut b) = (vec![0u8; cap], vec![0u8; cap]);
    let x = cursed_jwt::b64url_decode(&mut a, data).map(|n| a[..n].to_vec());
    let y = cursed_jwt::b64url_decode_scalar(&mut b, data).map(|n| b[..n].to_vec());
    assert_eq!(x, y);
    assert_eq!(x, cjwt_sys::b64url_decode(data));
});
