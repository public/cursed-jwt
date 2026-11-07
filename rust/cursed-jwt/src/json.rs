//! Strict JSON for the header and payload, and the claim rules.
//!
//! The grammar is RFC 8259 exactly: no comments, no trailing commas, no NaN, UTF-8 validated inside strings,
//! nesting depth at most 32.  Choices for claims (README.md, "Claim semantics"):
//! - a repeated `sub` / `username` / `exp` / `nbf` (or `alg` in the header) is INVALID, rather than a guess;
//! - keys are compared after unescaping, so `"sub"` is `sub`;
//! - a lone surrogate escape in `username` decodes to U+FFFD.
//!
//! A shape matcher recognises the common compact payload `{"sub":"…","username":"…","iat":N,"exp":N}` exactly
//! and defers everything else to the strict parser, so both give identical results for every input.
#![forbid(unsafe_code)]

use crate::{Claims, Error, USERNAME_MAX};

/// Outcome of the payload rules.
pub(crate) type Status = Result<(), Error>;

/// 1 for bytes that end the fast path inside a string: '"', '\\', < 0x20, >= 0x80
static JSTOP: [bool; 256] = {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = i < 0x20 || i >= 0x80 || i == b'"' as usize || i == b'\\' as usize;
        i += 1;
    }
    t
};

struct Cur<'a> {
    s: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(s: &'a [u8]) -> Self {
        Cur { s, p: 0 }
    }
    #[inline(always)]
    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.s.get(self.p) {
            self.p += 1;
        }
    }
    #[inline(always)]
    fn peek(&self) -> Option<u8> {
        self.s.get(self.p).copied()
    }
    #[inline(always)]
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.p += 1;
            true
        } else {
            false
        }
    }
    #[inline(always)]
    fn at_end(&self) -> bool {
        self.p >= self.s.len()
    }
}

fn hex4(p: &[u8]) -> Option<u32> {
    let mut r = 0;
    for &ch in p.get(..4)? {
        let d = match ch {
            b'0'..=b'9' => ch - b'0',
            _ if (b'a'..=b'f').contains(&(ch | 0x20)) => (ch | 0x20) - b'a' + 10,
            _ => return None,
        };
        r = r << 4 | d as u32;
    }
    Some(r)
}

/// A validated string at the cursor (which must be at '"'): its raw contents and whether it has escapes.
#[inline(always)]
fn jstr<'a>(c: &mut Cur<'a>) -> Option<(&'a [u8], bool)> {
    let s = c.s;
    if s.get(c.p) != Some(&b'"') {
        return None;
    }
    let start = c.p + 1;
    let mut p = start;
    let mut esc = false;
    loop {
        while p < s.len() && !JSTOP[s[p] as usize] {
            p += 1;
        }
        let ch = *s.get(p)?;
        if ch == b'"' {
            break;
        }
        if ch < 0x20 {
            return None;
        }
        if ch == b'\\' {
            esc = true;
            match *s.get(p + 1)? {
                b'u' => {
                    hex4(s.get(p + 2..p + 6)?)?;
                    p += 6;
                }
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => p += 2,
                _ => return None,
            }
            continue;
        }
        // UTF-8: reject overlongs, surrogates, > U+10FFFF
        let (len, mut cp) = match ch {
            0xC2..=0xDF => (2, (ch & 0x1F) as u32),
            0xE0..=0xEF => (3, (ch & 0x0F) as u32),
            0xF0..=0xF4 => (4, (ch & 0x07) as u32),
            _ => return None,
        };
        for &b in s.get(p + 1..p + len)? {
            if b & 0xC0 != 0x80 {
                return None;
            }
            cp = cp << 6 | (b & 0x3F) as u32;
        }
        if (len == 3 && (cp < 0x800 || (0xD800..=0xDFFF).contains(&cp)))
            || (len == 4 && !(0x10000..=0x10FFFF).contains(&cp))
        {
            return None;
        }
        p += len;
    }
    c.p = p + 1;
    Some((&s[start..p], esc))
}

/// Unescapes a validated raw string into `dst`; `None` if it does not fit.
fn junescape(dst: &mut [u8], s: &[u8]) -> Option<usize> {
    let mut o = 0;
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            *dst.get_mut(o)? = s[i];
            o += 1;
            i += 1;
            continue;
        }
        let x = *s.get(i + 1)?;
        i += 2;
        let mut cp = match x {
            b'b' => 8,
            b'f' => 12,
            b'n' => 10,
            b'r' => 13,
            b't' => 9,
            b'u' => {
                let v = hex4(s.get(i..)?)?;
                i += 4;
                v
            }
            _ => x as u32, // " \ /
        };
        if x == b'u' {
            if (0xD800..=0xDBFF).contains(&cp) {
                let lo = match (s.get(i), s.get(i + 1), s.get(i + 2..i + 6).and_then(hex4)) {
                    (Some(b'\\'), Some(b'u'), Some(lo)) if (0xDC00..=0xDFFF).contains(&lo) => {
                        Some(lo)
                    }
                    _ => None,
                };
                match lo {
                    Some(lo) => {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        i += 6;
                    }
                    None => cp = 0xFFFD,
                }
            } else if (0xDC00..=0xDFFF).contains(&cp) {
                cp = 0xFFFD;
            }
        }
        let ch = char::from_u32(cp).unwrap_or('\u{FFFD}');
        let need = ch.len_utf8();
        ch.encode_utf8(dst.get_mut(o..o + need)?);
        o += need;
    }
    Some(o)
}

/// A JSON number at the cursor: validates the grammar, returns its span and whether it is a plain integer of
/// at most 18 digits.
#[inline(always)]
fn jnum<'a>(c: &mut Cur<'a>) -> Option<(&'a [u8], bool)> {
    let s = c.s;
    let start = c.p;
    let mut p = c.p;
    let digit = |p: usize| matches!(s.get(p), Some(b'0'..=b'9'));
    if s.get(p) == Some(&b'-') {
        p += 1;
    }
    let d = p;
    match s.get(p)? {
        b'0' => p += 1,
        b'1'..=b'9' => {
            while digit(p) {
                p += 1;
            }
        }
        _ => return None,
    }
    let digits = p - d;
    let mut simple = true;
    if s.get(p) == Some(&b'.') {
        simple = false;
        p += 1;
        if !digit(p) {
            return None;
        }
        while digit(p) {
            p += 1;
        }
    }
    if let Some(b'e' | b'E') = s.get(p) {
        simple = false;
        p += 1;
        if let Some(b'+' | b'-') = s.get(p) {
            p += 1;
        }
        if !digit(p) {
            return None;
        }
        while digit(p) {
            p += 1;
        }
    }
    c.p = p;
    Some((&s[start..p], simple && digits <= 18))
}

/// Value of a validated integer span of at most 18 digits (optional '-').
fn jint(s: &[u8]) -> i64 {
    let (neg, d) = match s.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, s),
    };
    let v = d.iter().fold(0i64, |v, &c| v * 10 + (c - b'0') as i64);
    if neg {
        -v
    } else {
        v
    }
}

/// "now", formatted once per batch: an all-digit JSON integer (no leading zeros, by the grammar) compares with
/// it by digit count, then bytewise, with no number conversion.
pub(crate) struct Now {
    t: i64,
    len: usize,
    s: [u8; 24],
}

impl Now {
    pub fn new(now: i64) -> Self {
        let mut s = [0u8; 24];
        let mut tmp = [0u8; 24];
        let mut l = 0;
        let mut u = if now > 0 { now as u64 } else { 0 };
        loop {
            tmp[l] = b'0' + (u % 10) as u8;
            l += 1;
            u /= 10;
            if u == 0 {
                break;
            }
        }
        for i in 0..l {
            s[i] = tmp[l - 1 - i];
        }
        Now {
            t: now,
            len: if now > 0 { l } else { 0 },
            s,
        }
    }
}

/// Compares a JSON number with now: Less / Equal / Greater for num < / == / > now.
#[inline(always)]
fn jnum_cmp(s: &[u8], isint: bool, now: &Now) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    if isint && now.len != 0 && s.first() != Some(&b'-') {
        return s.len().cmp(&now.len).then_with(|| s.cmp(&now.s[..now.len]));
    }
    if isint {
        return jint(s).cmp(&now.t);
    }
    let d: f64 = match core::str::from_utf8(s).ok().and_then(|t| t.parse().ok()) {
        Some(d) => d,
        None => return Ordering::Less,
    };
    let n = now.t as f64;
    if d < n {
        Ordering::Less
    } else if d > n {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

fn jskip(c: &mut Cur<'_>, depth: u32) -> bool {
    c.ws();
    let Some(ch) = c.peek() else { return false };
    match ch {
        b'"' => jstr(c).is_some(),
        b'{' | b'[' => {
            let close = if ch == b'{' { b'}' } else { b']' };
            let obj = ch == b'{';
            if depth >= 32 {
                return false;
            }
            c.p += 1;
            c.ws();
            if c.eat(close) {
                return true;
            }
            loop {
                if obj {
                    c.ws();
                    if jstr(c).is_none() {
                        return false;
                    }
                    c.ws();
                    if !c.eat(b':') {
                        return false;
                    }
                }
                if !jskip(c, depth + 1) {
                    return false;
                }
                c.ws();
                if c.eat(b',') {
                    continue;
                }
                return c.eat(close);
            }
        }
        b't' => lit(c, b"true"),
        b'f' => lit(c, b"false"),
        b'n' => lit(c, b"null"),
        _ => jnum(c).is_some(),
    }
}

fn lit(c: &mut Cur<'_>, w: &[u8]) -> bool {
    if c.s.get(c.p..c.p + w.len()) == Some(w) {
        c.p += w.len();
        true
    } else {
        false
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Other = 0,
    Sub = 1,
    Username = 2,
    Exp = 3,
    Nbf = 4,
    Alg = 5,
}

#[inline(always)]
fn jkey(s: &[u8], esc: bool) -> Key {
    let mut buf = [0u8; 16];
    let s = if esc {
        match junescape(&mut buf, s) {
            Some(n) => &buf[..n],
            None => return Key::Other,
        }
    } else {
        s
    };
    match s {
        b"sub" => Key::Sub,
        b"exp" => Key::Exp,
        b"nbf" => Key::Nbf,
        b"alg" => Key::Alg,
        b"username" => Key::Username,
        _ => Key::Other,
    }
}

/// Header: an object whose "alg" is exactly `want` (after unescaping), once.
#[inline(always)]
pub(crate) fn header_ok(h: &[u8], want: &[u8]) -> bool {
    let mut c = Cur::new(h);
    let mut alg = 0;
    c.ws();
    if !c.eat(b'{') {
        return false;
    }
    c.ws();
    if c.peek() == Some(b'}') {
        return false; // {} has no alg
    }
    loop {
        c.ws();
        let Some((s, esc)) = jstr(&mut c) else {
            return false;
        };
        let key = jkey(s, esc);
        c.ws();
        if !c.eat(b':') {
            return false;
        }
        c.ws();
        if key == Key::Alg {
            if alg > 0 {
                return false;
            }
            alg += 1;
            let Some((s, esc)) = jstr(&mut c) else {
                return false;
            };
            let mut v = [0u8; 8];
            let s = if esc {
                match junescape(&mut v, s) {
                    Some(n) => &v[..n],
                    None => return false,
                }
            } else {
                s
            };
            if s != want {
                return false;
            }
        } else if !jskip(&mut c, 1) {
            return false;
        }
        c.ws();
        if c.eat(b',') {
            continue;
        }
        if !c.eat(b'}') {
            return false;
        }
        break;
    }
    c.ws();
    c.at_end() && alg == 1
}

/// "sub": ASCII digits only (leading zeros allowed), 1 <= value <= i64::MAX.
#[inline(always)]
fn sub_value(s: &[u8]) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    let mut v: i64 = 0;
    for &ch in s {
        if !ch.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((ch - b'0') as i64)?;
    }
    (v > 0).then_some(v)
}

fn needs_escape(s: &[u8]) -> bool {
    s.iter().any(|&ch| ch < 0x20 || ch == b'"' || ch == b'\\')
}

/// The strict parser: payload claims into `r`.  Malformed, expired or not yet valid is INVALID; then `sub` /
/// `username` problems are BAD_PAYLOAD.
pub(crate) fn payload_check(pl: &[u8], now: &Now, r: &mut Claims) -> Status {
    let mut c = Cur::new(pl);
    let mut seen = 0u32;
    let mut bad = false;
    c.ws();
    if !c.eat(b'{') {
        return Err(Error::Invalid);
    }
    c.ws();
    if c.peek() == Some(b'}') {
        return Err(Error::Invalid); // no exp
    }
    loop {
        c.ws();
        let (s, esc) = jstr(&mut c).ok_or(Error::Invalid)?;
        let key = jkey(s, esc);
        c.ws();
        if !c.eat(b':') {
            return Err(Error::Invalid);
        }
        c.ws();
        if key != Key::Other && key != Key::Alg {
            if seen & (1 << key as u32) != 0 {
                return Err(Error::Invalid);
            }
            seen |= 1 << key as u32;
        }
        let ch = c.peek().ok_or(Error::Invalid)?;
        match key {
            Key::Exp | Key::Nbf => {
                if ch != b'-' && !ch.is_ascii_digit() {
                    return Err(Error::Invalid); // must be a number
                }
                let (s, isint) = jnum(&mut c).ok_or(Error::Invalid)?;
                let cmp = jnum_cmp(s, isint, now);
                if if key == Key::Exp {
                    cmp.is_le()
                } else {
                    cmp.is_gt()
                } {
                    return Err(Error::Invalid);
                }
            }
            Key::Sub => {
                if ch != b'"' {
                    bad = true;
                    if !jskip(&mut c, 1) {
                        return Err(Error::Invalid);
                    }
                } else {
                    let (s, esc) = jstr(&mut c).ok_or(Error::Invalid)?;
                    let mut buf = [0u8; 32];
                    let v = if esc {
                        junescape(&mut buf, s).and_then(|n| sub_value(&buf[..n]))
                    } else {
                        sub_value(s)
                    };
                    match v {
                        Some(v) => r.uid = v,
                        None => bad = true,
                    }
                }
            }
            Key::Username => {
                if ch != b'"' {
                    bad = true;
                    if !jskip(&mut c, 1) {
                        return Err(Error::Invalid);
                    }
                } else {
                    let (s, esc) = jstr(&mut c).ok_or(Error::Invalid)?;
                    if !esc {
                        // raw JSON string content without escapes cannot contain '"', '\' or < 0x20
                        if s.len() > USERNAME_MAX {
                            bad = true;
                        } else {
                            r.set_username(s, false);
                        }
                    } else {
                        let mut ubuf = [0u8; USERNAME_MAX];
                        match junescape(&mut ubuf, s) {
                            Some(m) => {
                                let u = &ubuf[..m];
                                r.set_username(u, needs_escape(u));
                            }
                            None => bad = true,
                        }
                    }
                }
            }
            _ => {
                if !jskip(&mut c, 1) {
                    return Err(Error::Invalid);
                }
            }
        }
        c.ws();
        if c.eat(b',') {
            continue;
        }
        if !c.eat(b'}') {
            return Err(Error::Invalid);
        }
        break;
    }
    c.ws();
    if !c.at_end() {
        return Err(Error::Invalid);
    }
    if seen & (1 << Key::Exp as u32) == 0 {
        return Err(Error::Invalid);
    }
    if bad || seen & (1 << Key::Sub as u32) == 0 || seen & (1 << Key::Username as u32) == 0 {
        return Err(Error::BadPayload);
    }
    Ok(())
}

/// 8 bytes at `i` as a little-endian word, zero past the end of `b`.
#[inline(always)]
fn word8(b: &[u8], i: usize) -> u64 {
    match b.get(i..i + 8) {
        Some(s) => u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
        // near the end: byte by byte (a copy_from_slice here became a memcpy call per read, ~4 ns a token)
        None => b
            .get(i..)
            .unwrap_or_default()
            .iter()
            .take(8)
            .enumerate()
            .fold(0, |v, (k, &x)| v | (x as u64) << (8 * k)),
    }
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGH: u64 = 0x8080_8080_8080_8080;

/// Leading ASCII digits at `i`, at most `max` (SWAR: borrows and carries only travel towards later bytes).
#[inline(always)]
fn jdigits(b: &[u8], i: usize, max: usize) -> usize {
    let mut n = 0;
    loop {
        let x = word8(b, i + n);
        let nd = (x.wrapping_sub(0x30 * ONES) | x.wrapping_add(0x46 * ONES)) & HIGH;
        let d = if nd != 0 {
            (nd.trailing_zeros() >> 3) as usize
        } else {
            8
        };
        n += d;
        if d != 8 || n >= max {
            return n;
        }
    }
}

/// Offset from `i` of the first '"', '\\', control or non-ASCII byte, at most `max` (SWAR; the lowest flagged
/// byte of each test is exact, since borrows only travel upwards).
#[inline(always)]
fn jstrspan(b: &[u8], i: usize, max: usize) -> usize {
    let mut n = 0;
    while n < max {
        let x = word8(b, i + n);
        let q = x ^ (b'"' as u64 * ONES);
        let bs = x ^ (b'\\' as u64 * ONES);
        let m = (q.wrapping_sub(ONES) & !q)
            | (bs.wrapping_sub(ONES) & !bs)
            | (x.wrapping_sub(0x20 * ONES) & !x)
            | x;
        let m = m & HIGH;
        if m != 0 {
            return (n + (m.trailing_zeros() >> 3) as usize).min(max);
        }
        n += 8;
    }
    max
}

/// The shape matcher: exactly `{"sub":"<digits>","username":"<plain ASCII>","iat":<int>,"exp":<int>}` with no
/// whitespace and no leading zeros; `None` for anything else (the strict parser then decides).
#[inline(always)]
pub(crate) fn payload_shape(pl: &[u8], now: &Now, r: &mut Claims) -> Option<Status> {
    const SUB: &[u8] = b"{\"sub\":\"";
    const USER: &[u8] = b"\",\"username\":\"";
    const IAT: &[u8] = b"\",\"iat\":";
    const EXP: &[u8] = b",\"exp\":";
    let n = pl.len();
    if n < 44 || !pl.starts_with(SUB) {
        return None;
    }
    let mut p = SUB.len();
    let sub = p;
    let subl = jdigits(pl, p, 24);
    p += subl;
    if subl == 0 || subl > 20 || pl.get(p..p + USER.len()) != Some(USER) {
        return None;
    }
    p += USER.len();
    let user = p;
    let ul = jstrspan(pl, p, n - p);
    p += ul;
    if ul > USERNAME_MAX || pl.get(p..p + IAT.len()) != Some(IAT) {
        return None;
    }
    p += IAT.len();
    let il = jdigits(pl, p, 24);
    if il == 0 || il > 18 || (pl.get(p) == Some(&b'0') && il > 1) {
        return None;
    }
    p += il;
    if pl.get(p..p + EXP.len()) != Some(EXP) {
        return None;
    }
    p += EXP.len();
    let exp = p;
    let el = jdigits(pl, p, 24);
    if el == 0
        || el > 18
        || (pl.get(p) == Some(&b'0') && el > 1)
        || p + el + 1 != n
        || pl.get(p + el) != Some(&b'}')
    {
        return None;
    }
    if jnum_cmp(&pl[exp..exp + el], true, now).is_le() {
        return Some(Err(Error::Invalid));
    }
    let Some(uid) = sub_value(&pl[sub..sub + subl]) else {
        return Some(Err(Error::BadPayload));
    };
    r.uid = uid;
    r.set_username(&pl[user..user + ul], false);
    Some(Ok(()))
}

/// Payload JSON to claims: the shape matcher, then the strict parser.
#[inline(always)]
pub(crate) fn claims(pl: &[u8], now: &Now, r: &mut Claims) -> Status {
    match payload_shape(pl, now, r) {
        Some(s) => s,
        None => payload_check(pl, now, r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_surrogates() {
        // '~' stands for a backslash
        let esc = |s: &str| s.replace('~', "\\").into_bytes();
        let mut d = [0u8; 16];
        let n = junescape(&mut d, &esc("~ud83d~ude00")).unwrap();
        assert_eq!(&d[..n], [0xF0, 0x9F, 0x98, 0x80]);
        let n = junescape(&mut d, &esc("~ud83dx")).unwrap();
        assert_eq!(&d[..n], [0xEF, 0xBF, 0xBD, b'x']);
        let n = junescape(&mut d, &esc("~ude00")).unwrap();
        assert_eq!(&d[..n], [0xEF, 0xBF, 0xBD]);
    }

    #[test]
    fn strspan_matches_table() {
        let mut b = [b'a'; 40];
        for i in 0..40 {
            for &c in &[b'"', b'\\', 0x1f, 0x80, 0xff, 0] {
                b[i] = c;
                assert_eq!(jstrspan(&b, 0, 40), i);
                assert_eq!(jstrspan(&b, 0, i), i);
                b[i] = b'a';
            }
        }
    }

    #[test]
    fn now_compare() {
        let now = Now::new(1000);
        assert!(jnum_cmp(b"999", true, &now).is_lt());
        assert!(jnum_cmp(b"1000", true, &now).is_eq());
        assert!(jnum_cmp(b"1000.5", false, &now).is_gt());
        assert!(jnum_cmp(b"-5", true, &now).is_lt());
        assert!(jnum_cmp(b"1e400", false, &now).is_gt());
    }
}
