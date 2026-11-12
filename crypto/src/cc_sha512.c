/* cc_sha512.c — SHA-512 (FIPS 180-4), #included by cursed_crypto.c.  Part of cursed-jwt, MIT licence (see LICENSE).
 *
 * Constant time: the compression function is additions, rotations and boolean operations on the state and the
 * message words, with no data-dependent branch or memory address; the buffering branches on lengths only.  So it is
 * safe on secrets (Ed25519 signing hashes the private key and the nonce prefix with it).  Ed25519 verification uses
 * the same block function (sha512_ram in cc_ed25519.inc). */

/* memset, then an empty asm that claims to read the memory: the stores can't be dropped as dead */
void cc_wipe(void *p, size_t len) {
    memset(p, 0, len);
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#else
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) *v++ = 0;
#endif
}

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull,
    0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull, 0x12835b0145706fbeull,
    0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull, 0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull, 0x983e5152ee66dfabull,
    0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull,
    0x53380d139d95b3dfull, 0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull, 0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
    0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull,
    0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull, 0xca273eceea26619cull,
    0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
    0x113f9804bef90daeull, 0x1b710b35131c471bull, 0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};
static const uint64_t SHA512_IV[8] = { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
                                       0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                       0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull };
#define ROR64(x, n) ((x) >> (n) | (x) << (64 - (n)))
static void sha512_block(uint64_t st[8], const uint8_t *p) {
    uint64_t w[80], a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 16; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = v << 8 | p[8 * i + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + ((e & f) ^ (~e & g)) + K512[i] + w[i];
        uint64_t t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
    }
    st[0] += a, st[1] += b, st[2] += c, st[3] += d, st[4] += e, st[5] += f, st[6] += g, st[7] += h;
    cc_wipe(w, sizeof w); /* the schedule holds the message (a secret, when signing) */
}

void cc_sha512_init(cc_sha512_ctx *c) {
    memcpy(c->h, SHA512_IV, sizeof c->h);
    c->total = 0, c->fill = 0;
}
void cc_sha512_update(cc_sha512_ctx *c, const void *data, size_t len) {
    const uint8_t *m = (const uint8_t *)data;
    c->total += len;
    if (c->fill) {
        size_t k = 128 - c->fill < len ? 128 - c->fill : len;
        memcpy(c->buf + c->fill, m, k), c->fill += (unsigned)k, m += k, len -= k;
        if (c->fill < 128) return;
        sha512_block(c->h, c->buf), c->fill = 0;
    }
    for (; len >= 128; m += 128, len -= 128) sha512_block(c->h, m);
    memcpy(c->buf, m, len), c->fill = (unsigned)len;
}
void cc_sha512_final(cc_sha512_ctx *c, uint8_t out[64]) {
    unsigned f = c->fill;
    c->buf[f++] = 0x80;
    if (f > 112) memset(c->buf + f, 0, 128 - f), sha512_block(c->h, c->buf), f = 0;
    memset(c->buf + f, 0, 128 - f);
    uint64_t bits = c->total * 8; /* messages < 2^61 bytes: the top 64 bits of the 128-bit length are zero */
    for (int i = 0; i < 8; i++) c->buf[127 - i] = (uint8_t)(bits >> (8 * i));
    sha512_block(c->h, c->buf);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(c->h[i] >> (56 - 8 * j));
    cc_wipe(c, sizeof *c);
}
void cc_sha512(const void *data, size_t len, uint8_t out[64]) {
    cc_sha512_ctx c;
    cc_sha512_init(&c);
    cc_sha512_update(&c, data, len);
    cc_sha512_final(&c, out);
}
