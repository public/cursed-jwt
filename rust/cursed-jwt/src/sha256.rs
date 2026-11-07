//! SHA-256 and HMAC-SHA256 over many messages at once: message plans, the key's ipad/opad midstates, and the
//! multi-buffer "template" every engine is instantiated from.
//!
//! One vector register holds the same state word of `L` independent messages, so `L` messages hash in roughly
//! the time of one.  The template is generic over [`Simd`]; `u32` is the one-lane (scalar) instantiation, and
//! the SIMD instantiations live in `arch` (the crate's only unsafe code), which compiles this same template
//! inside `#[target_feature]` functions.
#![forbid(unsafe_code)]

pub(crate) const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
pub(crate) const IV256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
pub(crate) static ZERO_BLOCK: [u8; 64] = [0; 64];

/// Lanes of independent `u32` words: what the template needs from a vector ISA.  `L` is the lane count.
///
/// `ror::<R, L32>` rotates right by `R`; `L32` must be `32 - R`, and `shr::<R, RU>` takes the same count twice,
/// signed and unsigned: stable Rust has no const arithmetic or casts on generic parameters, and the intrinsics
/// take their counts as const generics of either type.
pub(crate) trait Simd<const L: usize>: Copy {
    /// 64 rounds on `s` (the template's [`compress`], inline, unless an engine keeps it out of line).
    #[inline(always)]
    fn compress(s: &mut [Self; 8], w: &mut [Self; 16]) {
        compress::<Self, L>(s, w)
    }
    fn splat(x: u32) -> Self;
    fn add(self, b: Self) -> Self;
    fn shr<const R: i32, const RU: u32>(self) -> Self;
    fn ror<const R: i32, const L32: i32>(self) -> Self;
    /// a ^ b ^ c
    fn xor3(a: Self, b: Self, c: Self) -> Self;
    /// e ? f : g, bitwise
    fn ch(e: Self, f: Self, g: Self) -> Self;
    /// majority
    fn maj(a: Self, b: Self, c: Self) -> Self;
    /// m ? x : y, bitwise (m is all-ones or all-zeros per lane)
    fn sel(m: Self, x: Self, y: Self) -> Self;
    /// All-ones in the lanes where `live(lane)`, zeros elsewhere.
    fn mask(live: impl Fn(usize) -> bool) -> Self;
    /// w[0..15] = the big-endian words of the 64-byte blocks, `block(lane)` per lane
    fn load16<'b>(block: impl Fn(usize) -> &'b [u8; 64]) -> [Self; 16];
    /// out[l][j] = lane l of s[j]
    fn store8(s: &[Self; 8], out: &mut [[u32; 8]; L]);
}

/// The one-lane instantiation: plain scalar code.
impl Simd<1> for u32 {
    #[inline(always)]
    fn splat(x: u32) -> Self {
        x
    }
    #[inline(always)]
    fn add(self, b: Self) -> Self {
        self.wrapping_add(b)
    }
    #[inline(always)]
    fn shr<const R: i32, const RU: u32>(self) -> Self {
        self >> RU
    }
    #[inline(always)]
    fn ror<const R: i32, const L32: i32>(self) -> Self {
        self.rotate_right(R as u32)
    }
    #[inline(always)]
    fn xor3(a: Self, b: Self, c: Self) -> Self {
        a ^ b ^ c
    }
    #[inline(always)]
    fn ch(e: Self, f: Self, g: Self) -> Self {
        g ^ (e & (f ^ g))
    }
    #[inline(always)]
    fn maj(a: Self, b: Self, c: Self) -> Self {
        b ^ ((a ^ b) & (b ^ c))
    }
    #[inline(always)]
    fn sel(m: Self, x: Self, y: Self) -> Self {
        (m & x) | (!m & y)
    }
    #[inline(always)]
    fn mask(live: impl Fn(usize) -> bool) -> Self {
        if live(0) {
            !0
        } else {
            0
        }
    }
    #[inline(always)]
    fn load16<'b>(block: impl Fn(usize) -> &'b [u8; 64]) -> [Self; 16] {
        load_be16(block(0))
    }
    #[inline(always)]
    fn store8(s: &[Self; 8], out: &mut [[u32; 8]; 1]) {
        out[0] = *s;
    }
}

/// 16 lanes as two interleaved 8-lane groups: two independent dependency chains for the scheduler (one 8-lane
/// compress is latency-bound on Skylake-SP).
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) struct X2<V>(pub V, pub V);

impl<V: Simd<8>> Simd<16> for X2<V> {
    #[inline(always)]
    fn splat(x: u32) -> Self {
        X2(V::splat(x), V::splat(x))
    }
    #[inline(always)]
    fn add(self, b: Self) -> Self {
        X2(self.0.add(b.0), self.1.add(b.1))
    }
    #[inline(always)]
    fn shr<const R: i32, const RU: u32>(self) -> Self {
        X2(self.0.shr::<R, RU>(), self.1.shr::<R, RU>())
    }
    #[inline(always)]
    fn ror<const R: i32, const L32: i32>(self) -> Self {
        X2(self.0.ror::<R, L32>(), self.1.ror::<R, L32>())
    }
    #[inline(always)]
    fn xor3(a: Self, b: Self, c: Self) -> Self {
        X2(V::xor3(a.0, b.0, c.0), V::xor3(a.1, b.1, c.1))
    }
    #[inline(always)]
    fn ch(e: Self, f: Self, g: Self) -> Self {
        X2(V::ch(e.0, f.0, g.0), V::ch(e.1, f.1, g.1))
    }
    #[inline(always)]
    fn maj(a: Self, b: Self, c: Self) -> Self {
        X2(V::maj(a.0, b.0, c.0), V::maj(a.1, b.1, c.1))
    }
    #[inline(always)]
    fn sel(m: Self, x: Self, y: Self) -> Self {
        X2(V::sel(m.0, x.0, y.0), V::sel(m.1, x.1, y.1))
    }
    #[inline(always)]
    fn mask(live: impl Fn(usize) -> bool) -> Self {
        X2(V::mask(&live), V::mask(|l| live(l + 8)))
    }
    #[inline(always)]
    fn load16<'b>(block: impl Fn(usize) -> &'b [u8; 64]) -> [Self; 16] {
        let (a, b) = (V::load16(&block), V::load16(|l| block(l + 8)));
        [
            X2(a[0], b[0]),
            X2(a[1], b[1]),
            X2(a[2], b[2]),
            X2(a[3], b[3]),
            X2(a[4], b[4]),
            X2(a[5], b[5]),
            X2(a[6], b[6]),
            X2(a[7], b[7]),
            X2(a[8], b[8]),
            X2(a[9], b[9]),
            X2(a[10], b[10]),
            X2(a[11], b[11]),
            X2(a[12], b[12]),
            X2(a[13], b[13]),
            X2(a[14], b[14]),
            X2(a[15], b[15]),
        ]
    }
    #[inline(always)]
    fn store8(s: &[Self; 8], out: &mut [[u32; 8]; 16]) {
        let (a, b) = halves_mut(out);
        V::store8(
            &[
                s[0].0, s[1].0, s[2].0, s[3].0, s[4].0, s[5].0, s[6].0, s[7].0,
            ],
            a,
        );
        V::store8(
            &[
                s[0].1, s[1].1, s[2].1, s[3].1, s[4].1, s[5].1, s[6].1, s[7].1,
            ],
            b,
        );
    }
}

#[inline(always)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn halves_mut<T>(x: &mut [T; 16]) -> (&mut [T; 8], &mut [T; 8]) {
    let (c, _) = x.as_chunks_mut::<8>();
    let (a, b) = c.split_at_mut(1);
    (&mut a[0], &mut b[0])
}

#[inline(always)]
pub(crate) fn load_be16(b: &[u8; 64]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (wi, c) in w.iter_mut().zip(b.as_chunks::<4>().0) {
        *wi = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    w
}

/// 64 rounds, fully unrolled (the round macro renames the eight working variables instead of moving them).
#[inline(always)]
pub(crate) fn compress<V: Simd<L>, const L: usize>(s: &mut [V; 8], w: &mut [V; 16]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *s;
    macro_rules! rnd {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $t:expr, $wt:expr) => {{
            let s1 = V::xor3($e.ror::<6, 26>(), $e.ror::<11, 21>(), $e.ror::<25, 7>());
            let t1 = $h
                .add(s1)
                .add(V::ch($e, $f, $g).add(V::splat(K256[$t])))
                .add($wt);
            let t2 = V::xor3($a.ror::<2, 30>(), $a.ror::<13, 19>(), $a.ror::<22, 10>())
                .add(V::maj($a, $b, $c));
            $d = $d.add(t1);
            $h = t1.add(t2);
        }};
    }
    // w[t & 15] becomes W[t] for t >= 16
    macro_rules! sched {
        ($t:expr) => {{
            let w15 = w[($t - 15) & 15];
            let w2 = w[($t - 2) & 15];
            let s0 = V::xor3(w15.ror::<7, 25>(), w15.ror::<18, 14>(), w15.shr::<3, 3>());
            let s1 = V::xor3(w2.ror::<17, 15>(), w2.ror::<19, 13>(), w2.shr::<10, 10>());
            w[$t & 15] = w[$t & 15].add(s0).add(w[($t - 7) & 15].add(s1));
            w[$t & 15]
        }};
    }
    macro_rules! wd {
        ($t:expr) => {
            w[$t]
        };
    }
    macro_rules! r8 {
        ($t:expr, $wm:ident) => {
            rnd!(a, b, c, d, e, f, g, h, $t, $wm!($t));
            rnd!(h, a, b, c, d, e, f, g, $t + 1, $wm!($t + 1));
            rnd!(g, h, a, b, c, d, e, f, $t + 2, $wm!($t + 2));
            rnd!(f, g, h, a, b, c, d, e, $t + 3, $wm!($t + 3));
            rnd!(e, f, g, h, a, b, c, d, $t + 4, $wm!($t + 4));
            rnd!(d, e, f, g, h, a, b, c, $t + 5, $wm!($t + 5));
            rnd!(c, d, e, f, g, h, a, b, $t + 6, $wm!($t + 6));
            rnd!(b, c, d, e, f, g, h, a, $t + 7, $wm!($t + 7));
        };
    }
    r8!(0, wd);
    r8!(8, wd);
    r8!(16, sched);
    r8!(24, sched);
    r8!(32, sched);
    r8!(40, sched);
    r8!(48, sched);
    r8!(56, sched);
    let out = [a, b, c, d, e, f, g, h];
    for (si, o) in s.iter_mut().zip(out) {
        *si = si.add(o);
    }
}

/// One scalar compression of a 64-byte block into `st`.
#[inline(always)]
pub(crate) fn compress_block(st: &mut [u32; 8], blk: &[u8; 64]) {
    let mut w = load_be16(blk);
    compress::<u32, 1>(st, &mut w);
}

/// A message to hash after `off` bytes already absorbed (64, the ipad block, for HMAC; 0 for plain SHA-256): it
/// needs `nb = ceil((L + 9) / 64)` more blocks, `nf` of them straight out of the message and the rest (1 or 2)
/// from a tail holding the leftover bytes, 0x80, zeros and the bit length.
#[derive(Clone, Copy)]
pub(crate) struct Plan<'a> {
    pub m: &'a [u8],
    pub nf: u32,
    pub nb: u32,
    pub off: u32,
}

impl<'a> Plan<'a> {
    pub const EMPTY: Plan<'static> = Plan {
        m: &[],
        nf: 0,
        nb: 0,
        off: 0,
    };

    #[inline(always)]
    pub fn new(m: &'a [u8], off: u32) -> Self {
        let l = m.len();
        let nf = (l >> 6) as u32;
        let nt = if (l & 63) + 9 > 64 { 2 } else { 1 };
        Plan {
            m,
            nf,
            nb: nf + nt,
            off,
        }
    }

    /// The 1 or 2 padded tail blocks, written into a zeroed 128-byte `t`.
    #[inline(always)]
    pub fn tail(&self, t: &mut [u8]) {
        let full = (self.nf as usize) << 6;
        let rem = self.m.get(full..).unwrap_or(&[]);
        let nt = (self.nb - self.nf) as usize;
        let bits = (self.off as u64 + self.m.len() as u64) * 8;
        t[..rem.len()].copy_from_slice(rem);
        t[rem.len()] = 0x80;
        t[nt * 64 - 8..nt * 64].copy_from_slice(&bits.to_be_bytes());
    }
}

/// The secret's HMAC midstates: SHA-256 state after compressing key ^ ipad, and after key ^ opad.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Midstates {
    pub ih: [u32; 8],
    pub oh: [u32; 8],
}

/// Plain SHA-256 runs the HMAC machinery from the IV, with no ipad block and no outer hash.
pub(crate) const SHA_IV: Midstates = Midstates {
    ih: IV256,
    oh: [0; 8],
};

/// SHA-256 of a whole message, scalar (key setup only).
pub(crate) fn sha256_scalar(m: &[u8]) -> [u8; 32] {
    words_to_bytes(&one::<true>(&SHA_IV, &Plan::new(m, 0)))
}

pub(crate) fn words_to_bytes(st: &[u32; 8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (c, w) in o.as_chunks_mut::<4>().0.iter_mut().zip(st) {
        c.copy_from_slice(&w.to_be_bytes());
    }
    o
}

impl Midstates {
    /// RFC 2104: a secret longer than a block is hashed first.
    pub fn new(secret: &[u8]) -> Self {
        let mut key = [0u8; 64];
        if secret.len() > 64 {
            key[..32].copy_from_slice(&sha256_scalar(secret));
        } else {
            key[..secret.len()].copy_from_slice(secret);
        }
        let pass = |pad: u8| {
            let mut blk = [0u8; 64];
            for (b, k) in blk.iter_mut().zip(&key) {
                *b = k ^ pad;
            }
            let mut st = IV256;
            compress_block(&mut st, &blk);
            st
        };
        let ih = pass(0x36);
        let oh = pass(0x5c);
        Midstates { ih, oh }
    }
}

/// A group of up to `L` messages, prepared outside the vector code: plans, block counts and padded tails.
pub(crate) struct Group<'a, const L: usize> {
    /// each lane's whole message blocks, read in place
    full: [&'a [[u8; 64]]; L],
    /// each lane's 1 or 2 padded tail blocks (zeros after them, and for absent lanes)
    tails: [[[u8; 64]; 2]; L],
    nb: [u32; L],
    maxnb: u32,
    ragged: bool,
}

impl<'a, const L: usize> Group<'a, L> {
    /// The plans `idx[..]` of `plans` (at most `L`).
    #[inline(always)]
    pub fn new(plans: &[Plan<'a>], idx: &[u8]) -> Self {
        let mut g = Group {
            full: [&[]; L],
            tails: [[[0; 64]; 2]; L],
            nb: [0; L],
            maxnb: 0,
            ragged: false,
        };
        let mut n = 0;
        for (l, &i) in idx.iter().take(L).enumerate() {
            let Some(p) = plans.get(i as usize) else {
                continue;
            };
            g.full[l] = p.m.as_chunks::<64>().0;
            g.nb[l] = p.nb;
            p.tail(g.tails[l].as_flattened_mut());
            g.maxnb = g.maxnb.max(p.nb);
            n = l + 1;
        }
        g.ragged = g.nb[..n].iter().any(|&b| b != g.maxnb);
        g
    }

    /// Lane `l`'s block `b`: the message itself, then its tail, then (for lanes that ran out) a zero block.
    /// After the kernel's unrolling `l` is a constant, so this is one compare and a load.
    #[inline(always)]
    fn blk(&self, l: usize, b: u32) -> &[u8; 64] {
        let f = self.full[l];
        match f.get(b as usize) {
            Some(x) => x,
            None => self.tails[l]
                .get(b as usize - f.len())
                .unwrap_or(&ZERO_BLOCK),
        }
    }

    #[inline(always)]
    fn live(&self, l: usize, b: u32) -> bool {
        b < self.nb[l]
    }
}

/// One vector's worth of HMACs (or plain SHA-256s with `RAW`) for a prepared group: absent lanes hash a zero
/// block, and lanes that run out of blocks early keep their state through a mask select.
///
/// This is the code each engine compiles inside its target-feature region.  It initialises no arrays and copies
/// none: in an AVX-512 region the compiler would lower those with 512-bit stores, and one zmm instruction drops a
/// Cascade Lake core's frequency licence (the C code avoids that with a `prefer-vector-width=256` tuning that
/// Rust cannot set per function).
#[inline(always)]
pub(crate) fn kernel<V: Simd<L>, const L: usize, const RAW: bool>(
    k: &Midstates,
    g: &Group<'_, L>,
    mac: &mut [[u32; 8]; L],
) {
    let ih = &k.ih;
    let mut st = [
        V::splat(ih[0]),
        V::splat(ih[1]),
        V::splat(ih[2]),
        V::splat(ih[3]),
        V::splat(ih[4]),
        V::splat(ih[5]),
        V::splat(ih[6]),
        V::splat(ih[7]),
    ];
    for b in 0..g.maxnb {
        let mut w = V::load16(|l| g.blk(l, b));
        let mut s = st;
        V::compress(&mut s, &mut w);
        if g.ragged {
            let m = V::mask(|l| g.live(l, b));
            st = [
                V::sel(m, s[0], st[0]),
                V::sel(m, s[1], st[1]),
                V::sel(m, s[2], st[2]),
                V::sel(m, s[3], st[3]),
                V::sel(m, s[4], st[4]),
                V::sel(m, s[5], st[5]),
                V::sel(m, s[6], st[6]),
                V::sel(m, s[7], st[7]),
            ];
        } else {
            st = s;
        }
    }
    if !RAW {
        // outer hash: one block = inner digest || 0x80 || zeros || bitlen(64 + 32)
        let z = V::splat(0);
        let mut w = [
            st[0],
            st[1],
            st[2],
            st[3],
            st[4],
            st[5],
            st[6],
            st[7],
            V::splat(0x8000_0000),
            z,
            z,
            z,
            z,
            z,
            z,
            V::splat((64 + 32) * 8),
        ];
        let oh = &k.oh;
        st = [
            V::splat(oh[0]),
            V::splat(oh[1]),
            V::splat(oh[2]),
            V::splat(oh[3]),
            V::splat(oh[4]),
            V::splat(oh[5]),
            V::splat(oh[6]),
            V::splat(oh[7]),
        ];
        V::compress(&mut st, &mut w);
    }
    V::store8(&st, mac);
}

/// An engine's group function: runs [`kernel`] for one prepared group inside the engine's target-feature
/// region.  Implemented by zero-sized tokens that exist only once the CPU has been checked for the engine.
pub(crate) trait Kernel<const L: usize>: Copy {
    fn lanes<const RAW: bool>(self, k: &Midstates, g: &Group<'_, L>, mac: &mut [[u32; 8]; L]);
    /// One message alone (groups below the engine's minimum size).
    fn one<const RAW: bool>(self, k: &Midstates, p: &Plan<'_>) -> [u32; 8] {
        one::<RAW>(k, p)
    }
}

/// The portable engine.
#[derive(Clone, Copy)]
pub(crate) struct Scalar;

impl Kernel<1> for Scalar {
    #[inline(always)]
    fn lanes<const RAW: bool>(self, k: &Midstates, g: &Group<'_, 1>, mac: &mut [[u32; 8]; 1]) {
        kernel::<u32, 1, RAW>(k, g, mac)
    }
}

/// Message indices of a chunk sorted by block count (insertion sort: a chunk is small and nearly always uniform).
#[inline(always)]
pub(crate) fn sort_by_nb(plans: &[Plan<'_>], idx: &mut [u8; CH]) {
    for (i, p) in plans.iter().enumerate() {
        let mut j = i;
        while j > 0 && plans[idx[j - 1] as usize].nb > p.nb {
            idx[j] = idx[j - 1];
            j -= 1;
        }
        idx[j] = i as u8;
    }
}

/// Chunk size of the drivers: plans are sorted within a chunk.
pub(crate) const CH: usize = 16;

#[inline(always)]
fn put(oc: &mut [[u32; 8]], g: &[u8], tmp: &[[u32; 8]]) {
    for (&i, t) in g.iter().zip(tmp) {
        if let Some(o) = oc.get_mut(i as usize) {
            *o = *t;
        }
    }
}

/// One message through the scalar template.
#[inline(always)]
pub(crate) fn one<const RAW: bool>(k: &Midstates, p: &Plan<'_>) -> [u32; 8] {
    let plans = [*p];
    let g = Group::<1>::new(&plans, &[0]);
    let mut o = [[0u32; 8]; 1];
    kernel::<u32, 1, RAW>(k, &g, &mut o);
    o[0]
}

/// n messages, any lengths: plan, sort by block count, run groups of `L` lanes on engine `e`; groups with fewer
/// than `MIN` live messages go one at a time.  `RAW`: plain SHA-256 instead of HMAC.
#[inline(always)]
pub(crate) fn drive<K: Kernel<L>, const L: usize, const RAW: bool, const MIN: usize>(
    e: K,
    k: &Midstates,
    msgs: &[&[u8]],
    mac: &mut [[u32; 8]],
) {
    let off = if RAW { 0 } else { 64 };
    if let ([m], [o]) = (msgs, &mut *mac) {
        *o = e.one::<RAW>(k, &Plan::new(m, off));
        return;
    }
    for (mc, oc) in msgs.chunks(CH).zip(mac.chunks_mut(CH)) {
        let mut plans = [Plan::EMPTY; CH];
        for (p, m) in plans.iter_mut().zip(mc) {
            *p = Plan::new(m, off);
        }
        let plans = &plans[..mc.len()];
        let mut idx = [0u8; CH];
        sort_by_nb(plans, &mut idx);
        for g in idx[..mc.len()].chunks(L) {
            if g.len() < MIN {
                for &i in g {
                    if let (Some(p), Some(o)) = (plans.get(i as usize), oc.get_mut(i as usize)) {
                        *o = e.one::<RAW>(k, p);
                    }
                }
                continue;
            }
            let grp = Group::<L>::new(plans, g);
            let mut tmp = [[0u32; 8]; L];
            e.lanes::<RAW>(k, &grp, &mut tmp);
            put(oc, g, &tmp);
        }
    }
}

/// Driver for the 16-lane flavours: groups of 9..16 go to the 16-lane engine, smaller ones to the 8-lane engine
/// (or one at a time below `MIN8`).
#[inline(always)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) fn drive_x2<K16: Kernel<16>, K8: Kernel<8>, const MIN8: usize>(
    e16: K16,
    e8: K8,
    k: &Midstates,
    msgs: &[&[u8]],
    mac: &mut [[u32; 8]],
) {
    if let ([m], [o]) = (msgs, &mut *mac) {
        *o = e8.one::<false>(k, &Plan::new(m, 64));
        return;
    }
    for (mc, oc) in msgs.chunks(CH).zip(mac.chunks_mut(CH)) {
        let mut plans = [Plan::EMPTY; CH];
        for (p, m) in plans.iter_mut().zip(mc) {
            *p = Plan::new(m, 64);
        }
        let plans = &plans[..mc.len()];
        let mut idx = [0u8; CH];
        sort_by_nb(plans, &mut idx);
        let idx = &idx[..mc.len()];
        if idx.len() >= 9 {
            let grp = Group::<16>::new(plans, idx);
            let mut tmp = [[0u32; 8]; 16];
            e16.lanes::<false>(k, &grp, &mut tmp);
            put(oc, idx, &tmp);
        } else if idx.len() >= MIN8 {
            let grp = Group::<8>::new(plans, idx);
            let mut tmp = [[0u32; 8]; 8];
            e8.lanes::<false>(k, &grp, &mut tmp);
            put(oc, idx, &tmp);
        } else {
            for &i in idx {
                if let (Some(p), Some(o)) = (plans.get(i as usize), oc.get_mut(i as usize)) {
                    *o = e8.one::<false>(k, p);
                }
            }
        }
    }
}

/// An instruction-set SHA-256 engine (ARMv8 SHA2, x86 SHA-NI) that hashes `S` messages with the same block count
/// in interleaved streams.  Implemented by zero-sized tokens that exist only once the CPU has been checked.
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(dead_code)
)]
pub(crate) trait Streams: Copy {
    /// Three plans left over run as one 3-stream group instead of 2 + 1 (the 1-stream group is latency-bound).
    const THREE: bool = false;
    fn run<const S: usize, const RAW: bool>(
        self,
        k: &Midstates,
        p: [&Plan<'_>; S],
        out: &mut [[u32; 8]; S],
    );
}

/// The stream engines' driver: plans sorted by block count, groups of up to `S` (1, 2 or 4) that share a block
/// count, each with a constant stream count so the engine fully specialises.
#[inline(always)]
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(dead_code)
)]
pub(crate) fn drive_streams<E: Streams, const S: usize, const RAW: bool>(
    e: E,
    k: &Midstates,
    msgs: &[&[u8]],
    mac: &mut [[u32; 8]],
) {
    let off = if RAW { 0 } else { 64 };
    if let ([m], [o]) = (msgs, &mut *mac) {
        let mut w = [[0u32; 8]; 1];
        e.run::<1, RAW>(k, [&Plan::new(m, off)], &mut w);
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
        sort_by_nb(plans, &mut idx);
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
            // five left with one block count: 3 + 2, not 4 + a latency-bound single stream
            if E::THREE && s == 4 && idx.len() - g == 5 && plans[idx[g + 4] as usize].nb == nb0 {
                s = 3;
            }
            let pl = |i: usize| &plans[idx[g + i] as usize];
            let mut put = |i: usize, w: &[u32; 8]| {
                if let Some(o) = oc.get_mut(idx[g + i] as usize) {
                    *o = *w;
                }
            };
            match s {
                4 => {
                    let mut o = [[0u32; 8]; 4];
                    e.run::<4, RAW>(k, [pl(0), pl(1), pl(2), pl(3)], &mut o);
                    o.iter().enumerate().for_each(|(i, w)| put(i, w));
                }
                3 if E::THREE => {
                    let mut o = [[0u32; 8]; 3];
                    e.run::<3, RAW>(k, [pl(0), pl(1), pl(2)], &mut o);
                    o.iter().enumerate().for_each(|(i, w)| put(i, w));
                }
                3 => {
                    let mut o = [[0u32; 8]; 2];
                    e.run::<2, RAW>(k, [pl(0), pl(1)], &mut o);
                    o.iter().enumerate().for_each(|(i, w)| put(i, w));
                    let mut o = [[0u32; 8]; 1];
                    e.run::<1, RAW>(k, [pl(2)], &mut o);
                    put(2, &o[0]);
                }
                2 => {
                    let mut o = [[0u32; 8]; 2];
                    e.run::<2, RAW>(k, [pl(0), pl(1)], &mut o);
                    o.iter().enumerate().for_each(|(i, w)| put(i, w));
                }
                _ => {
                    let mut o = [[0u32; 8]; 1];
                    e.run::<1, RAW>(k, [pl(0)], &mut o);
                    put(0, &o[0]);
                }
            }
            g += s;
        }
    }
}
