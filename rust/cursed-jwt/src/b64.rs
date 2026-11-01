//! base64url decoding (RFC 4648 section 5, no padding, canonical trailing bits).
#![forbid(unsafe_code)]

const fn sextet(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => 0xFF,
    }
}

/// Sextet value of each base64url character, 0xFF for everything else.
pub(crate) static TAB: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = sextet(i as u8);
        i += 1;
    }
    t
};

/// Bytes `decode` can write for `n` input characters.
pub const fn decoded_cap(n: usize) -> usize {
    n / 4 * 3 + 2
}

/// The final 0, 2 or 3 characters: checks the length class and that the unused trailing bits are zero.
#[inline(always)]
pub(crate) fn tail(dst: &mut [u8], s: &[u8]) -> Option<usize> {
    match *s {
        [] => Some(0),
        [x, y] => {
            let (a, b) = (TAB[x as usize] as u32, TAB[y as usize] as u32);
            if (a | b) & 0xC0 != 0 || b & 15 != 0 {
                return None;
            }
            *dst.first_mut()? = (a << 2 | b >> 4) as u8;
            Some(1)
        }
        [x, y, z] => {
            let (a, b, c) = (
                TAB[x as usize] as u32,
                TAB[y as usize] as u32,
                TAB[z as usize] as u32,
            );
            if (a | b | c) & 0xC0 != 0 || c & 3 != 0 {
                return None;
            }
            let d = dst.get_mut(..2)?;
            d[0] = (a << 2 | b >> 4) as u8;
            d[1] = (b << 4 | c >> 2) as u8;
            Some(2)
        }
        _ => None,
    }
}

/// Portable decoder.  Returns the decoded length, or `None` for a non-base64url character, a length of 1 mod 4,
/// non-zero trailing bits or a `dst` shorter than [`decoded_cap`].
pub fn decode_scalar(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    let q = src.len() / 4;
    if dst.len() < decoded_cap(src.len()) {
        return None;
    }
    let mut bad = 0u32;
    for (o, s) in dst
        .as_chunks_mut::<3>()
        .0
        .iter_mut()
        .zip(src.as_chunks::<4>().0)
    {
        let (a, b, c, d) = (
            TAB[s[0] as usize] as u32,
            TAB[s[1] as usize] as u32,
            TAB[s[2] as usize] as u32,
            TAB[s[3] as usize] as u32,
        );
        bad |= a | b | c | d;
        let v = a << 18 | b << 12 | c << 6 | d;
        o[0] = (v >> 16) as u8;
        o[1] = (v >> 8) as u8;
        o[2] = v as u8;
    }
    if bad & 0xC0 != 0 {
        return None;
    }
    let t = tail(dst.get_mut(3 * q..)?, src.get(4 * q..)?)?;
    Some(3 * q + t)
}
