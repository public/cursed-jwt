/* cc_sign_es256.inc — ES256 (ECDSA P-256 with SHA-256) signing, #included by cc_sign.c.  Part of cursed-jwt, MIT
 * licence (see LICENSE).
 *
 *     k = RFC 6979 (HMAC-SHA256 DRBG on d and h = SHA-256(M) mod n);  (x, y) = [k] G;  r = x mod n
 *     s = k^-1 (h + r d) mod n;  signature r || s, 32 bytes big-endian each (JWS)
 *
 * Constant time in d, k and everything computed from them, by the same rules as Ed25519 signing (cc_sign.c): no
 * branch or memory address depends on a secret.  The only data-dependent branches are RFC 6979's retry conditions
 * (k outside [1, n), r = 0 or s = 0: probability ~2^-32 or less), taken on a declassified bit; they reveal only that
 * a candidate was rejected, which says nothing about the k finally used.
 *   - The nonce: RFC 6979 3.2 on cc_hmac_* (constant time in the key); bits2octets' reduction mod n by one masked
 *     conditional subtraction.
 *   - [k] G on x86-64 Linux (-DJWT_ES256_ASM, the Makefile's default there): s2n-bignum's p256_scalarmulbase
 *     (crypto/src/s2n/, vendored; formally verified; cmov table reads, returns the affine point) over the static
 *     table CC_P256_GTAB (cc_p256_table.inc), with the _alt version where BMI2 + ADX are missing.
 *   - Elsewhere: fiat-crypto's p256 field (Montgomery form), 65 signed radix-16 digits of k, every digit reading its
 *     whole 8-entry row of the same table by masks, Renes-Costello-Batina complete projective addition for a = -3
 *     (no exceptional case, the identity included: no branch), then 1 / Z by Fermat with a fixed window.
 *   - k^-1 mod n: s2n-bignum's bignum_modinv (constant-time divsteps) on x86-64 Linux, else Fermat on fiat's
 *     p256_scalar with a fixed window over the public exponent n - 2.
 *   - s in fiat's p256_scalar Montgomery arithmetic; d is kept in Montgomery form.
 *   - Optional verify-after-sign (cc_skey_verify_after_sign): every signature is checked with the public key before
 *     it is released; a failure (a fault) zeroes it, and cc_sign_batch returns the number of failures. */

#include "cc_p256_table.inc"

#if defined(CC_ES256_ASM) && !defined(CC_NO_ES256_ASM) && defined(__x86_64__) && defined(__ELF__)
#define CC_ES256_S2N 1
void cc_s2n_p256_scalarmulbase(uint64_t res[8], const uint64_t scalar[4], uint64_t blocksize, const uint64_t *table);
void cc_s2n_p256_scalarmulbase_alt(uint64_t res[8], const uint64_t scalar[4], uint64_t blocksize,
                                   const uint64_t *table);
void cc_s2n_bignum_modinv(uint64_t k, uint64_t *z, const uint64_t *a, const uint64_t *b, uint64_t *t);
#endif

/* declassify: mark a value derived from secrets as public where the algorithm makes it so (RFC 6979's retry bits).
 * tests/test_ct.c defines it as VALGRIND_MAKE_MEM_DEFINED. */
#ifndef CC_DECLASSIFY
#define CC_DECLASSIFY(p, n) ((void)0)
#endif

typedef uint64_t es_fe[4]; /* field element mod p, Montgomery form (fiat) */
typedef uint64_t es_sc[4]; /* scalar mod n */

static const uint64_t ES_N[4] = { 0xf3b9cac2fc632551ull, 0xbce6faada7179e84ull, 0xffffffffffffffffull,
                                  0xffffffff00000000ull };
static const es_fe ES_B_M = { 0xd89cdf6229c4bddfull, 0xacf005cd78843090ull, 0xe5a220abf7212ed6ull,
                              0xdc30061d04874834ull }; /* b R mod p */
static const es_fe ES_ONE_M = { 0x0000000000000001ull, 0xffffffff00000000ull, 0xffffffffffffffffull,
                                0x00000000fffffffeull }; /* R mod p */

static uint64_t es_mask(uint64_t bit) { /* all ones if bit else 0, opaque to the optimiser */
    uint64_t m = 0 - bit;
#if defined(__GNUC__)
    __asm__("" : "+r"(m));
#endif
    return m;
}
static void es_be_to_limbs(uint64_t o[4], const uint8_t b[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = v << 8 | b[31 - 8 * i - (7 - j)];
        o[i] = v;
    }
}
static void es_limbs_to_be(uint8_t b[32], const uint64_t o[4]) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) b[31 - 8 * i - j] = (uint8_t)(o[i] >> (8 * j));
}
/* o = a - n if a >= n else a (one masked conditional subtraction: a < 2n); returns 1 if it subtracted */
static uint64_t es_sub_n_once(uint64_t o[4], const uint64_t a[4]) {
    uint64_t t[4], bw = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 d = (unsigned __int128)a[i] - ES_N[i] - bw;
        t[i] = (uint64_t)d, bw = (uint64_t)(d >> 64) & 1;
    }
    uint64_t keep = es_mask(bw); /* borrow: a < n, keep a */
    for (int i = 0; i < 4; i++) o[i] = (a[i] & keep) | (t[i] & ~keep);
    return bw ^ 1;
}
/* 1 iff 1 <= a < n, without a branch */
static uint64_t es_in_range(const uint64_t a[4]) {
    uint64_t bw = 0, z = a[0] | a[1] | a[2] | a[3];
    for (int i = 0; i < 4; i++) {
        unsigned __int128 d = (unsigned __int128)a[i] - ES_N[i] - bw;
        bw = (uint64_t)(d >> 64) & 1;
    }
    return bw & (uint64_t)((z | (0 - z)) >> 63);
}

/* ---- field: fiat calls ---- */
/* o = a^e for a public exponent e (4 little-endian limbs), fixed 4-bit window: the operations depend on e only */
static void es_fe_pow(es_fe o, const es_fe a, const uint64_t e[4]) {
    es_fe t[16], r;
    memcpy(t[0], ES_ONE_M, sizeof(es_fe)), memcpy(t[1], a, sizeof(es_fe));
    for (int i = 2; i < 16; i++) fiat_p256_mul(t[i], t[i - 1], a);
    memcpy(r, ES_ONE_M, sizeof r);
    for (int i = 63; i >= 0; i--) {
        for (int s = 0; s < 4; s++) fiat_p256_square(r, r);
        unsigned d = (unsigned)(e[i / 16] >> (4 * (i % 16)) & 15); /* public */
        if (d) fiat_p256_mul(r, r, t[d]);
    }
    memcpy(o, r, sizeof r);
    cc_wipe(t, sizeof t), cc_wipe(r, sizeof r);
}
static void es_sc_pow(es_sc o, const es_sc a, const uint64_t e[4]) { /* the same mod n, Montgomery form */
    es_sc t[16], r, one = { 1 };
    fiat_p256_scalar_to_montgomery(t[0], one);
    memcpy(t[1], a, sizeof(es_sc));
    for (int i = 2; i < 16; i++) fiat_p256_scalar_mul(t[i], t[i - 1], a);
    memcpy(r, t[0], sizeof r);
    for (int i = 63; i >= 0; i--) {
        for (int s = 0; s < 4; s++) fiat_p256_scalar_square(r, r);
        unsigned d = (unsigned)(e[i / 16] >> (4 * (i % 16)) & 15); /* public */
        if (d) fiat_p256_scalar_mul(r, r, t[d]);
    }
    memcpy(o, r, sizeof r);
    cc_wipe(t, sizeof t), cc_wipe(r, sizeof r);
}

/* ---- points: projective (X : Y : Z), Montgomery form; the identity is (0 : 1 : 0) ---- */
typedef struct {
    es_fe X, Y, Z;
} es_pt;
/* P3 = P1 + P2, Renes-Costello-Batina 2016, Algorithm 4 (complete, a = -3): 12M + 2 m_b, no exceptional case */
static void es_add(es_pt *P3, const es_pt *P1, const es_pt *P2) {
    es_fe t0, t1, t2, t3, t4, X3, Y3, Z3;
    fiat_p256_mul(t0, P1->X, P2->X), fiat_p256_mul(t1, P1->Y, P2->Y), fiat_p256_mul(t2, P1->Z, P2->Z);
    fiat_p256_add(t3, P1->X, P1->Y), fiat_p256_add(t4, P2->X, P2->Y), fiat_p256_mul(t3, t3, t4);
    fiat_p256_add(t4, t0, t1), fiat_p256_sub(t3, t3, t4), fiat_p256_add(t4, P1->Y, P1->Z);
    fiat_p256_add(X3, P2->Y, P2->Z), fiat_p256_mul(t4, t4, X3), fiat_p256_add(X3, t1, t2);
    fiat_p256_sub(t4, t4, X3), fiat_p256_add(X3, P1->X, P1->Z), fiat_p256_add(Y3, P2->X, P2->Z);
    fiat_p256_mul(X3, X3, Y3), fiat_p256_add(Y3, t0, t2), fiat_p256_sub(Y3, X3, Y3);
    fiat_p256_mul(Z3, ES_B_M, t2), fiat_p256_sub(X3, Y3, Z3), fiat_p256_add(Z3, X3, X3);
    fiat_p256_add(X3, X3, Z3), fiat_p256_sub(Z3, t1, X3), fiat_p256_add(X3, t1, X3);
    fiat_p256_mul(Y3, ES_B_M, Y3), fiat_p256_add(t1, t2, t2), fiat_p256_add(t2, t1, t2);
    fiat_p256_sub(Y3, Y3, t2), fiat_p256_sub(Y3, Y3, t0), fiat_p256_add(t1, Y3, Y3);
    fiat_p256_add(Y3, t1, Y3), fiat_p256_add(t1, t0, t0), fiat_p256_add(t0, t1, t0);
    fiat_p256_sub(t0, t0, t2), fiat_p256_mul(t1, t4, Y3), fiat_p256_mul(t2, t0, Y3);
    fiat_p256_mul(Y3, X3, Z3), fiat_p256_add(Y3, Y3, t2), fiat_p256_mul(X3, t3, X3);
    fiat_p256_sub(X3, X3, t1), fiat_p256_mul(Z3, t4, Z3), fiat_p256_mul(t1, t3, t0);
    fiat_p256_add(Z3, Z3, t1);
    memcpy(P3->X, X3, sizeof X3), memcpy(P3->Y, Y3, sizeof Y3), memcpy(P3->Z, Z3, sizeof Z3);
}
/* Q = d * (row's base): all 8 entries read by masks; d = 0 gives the identity; d < 0 negates y */
static void es_select(es_pt *Q, const uint64_t *row, int8_t d) {
    uint64_t neg = (uint64_t)(uint8_t)d >> 7;
    uint64_t mag = (uint64_t)(d - ((-(int64_t)neg & d) * 2)); /* |d|, 0..8 */
    uint64_t acc[8] = { 0 }, any = 0;
    for (int j = 0; j < 8; j++) {
        uint64_t m = es_mask((uint64_t)((((mag ^ (uint64_t)(j + 1)) - 1) >> 63) & 1));
        for (int w = 0; w < 8; w++) acc[w] |= row[8 * j + w] & m;
        any |= m;
    }
    for (int w = 0; w < 4; w++) Q->X[w] = acc[w], Q->Z[w] = ES_ONE_M[w] & any;
    for (int w = 0; w < 4; w++) Q->Y[w] = (acc[4 + w] & any) | (ES_ONE_M[w] & ~any); /* the identity's Y = 1 */
    es_fe ny;
    fiat_p256_opp(ny, Q->Y);
    uint64_t mn = es_mask(neg);
    for (int w = 0; w < 4; w++) Q->Y[w] ^= (Q->Y[w] ^ ny[w]) & mn;
    cc_wipe(acc, sizeof acc), cc_wipe(ny, sizeof ny);
}
#if defined(CC_ES256_S2N) && defined(CC_TUNED_ES256_NISTZ)
/* -DCC_TUNED_ES256_NISTZ (opt-in: make TUNED=1 or TUNED_ES256_NISTZ=1), for x86-64 CPUs without ADX: [k] G as
 * OpenSSL's ecp_nistz256_points_mul does it for the generator (crypto/src/ecp_nistz256_x86_64_ossl.S): 37 Booth-recoded
 * 7-bit windows of k, each reading its whole 64-point row of OpenSSL's table (gather_w7: every entry loaded, masks
 * select one) and added by ecp_nistz256_point_add_affine, then 1 / Z by s2n-bignum's bignum_modinv (constant-time
 * divsteps, as for k^-1) instead of OpenSSL's Fermat chain.  No branch or address depends on k.  The additions are not
 * complete, but for k in [1, n) the running sum never equals the table point added (as in OpenSSL); the identity
 * (a zero digit) is handled by the assembly with masks.  About 26% faster than s2n's p256_scalarmulbase_alt with the
 * blocksize-4 table on Cascade Lake (README.md, Options). */
#define CC_ES256_NISTZ 1
typedef struct {
    uint64_t X[4], Y[4], Z[4];
} nz_pt;
typedef struct {
    uint64_t X[4], Y[4];
} nz_apt;
void cc_ossl_ecp_nistz256_gather_w7(nz_apt *v, const nz_apt *tbl, int idx);
void cc_ossl_ecp_nistz256_neg(uint64_t r[4], const uint64_t a[4]);
void cc_ossl_ecp_nistz256_point_add_affine(nz_pt *r, const nz_pt *a, const nz_apt *b);
void cc_ossl_ecp_nistz256_mul_mont(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
void cc_ossl_ecp_nistz256_sqr_mont(uint64_t r[4], const uint64_t a[4]);
void cc_ossl_ecp_nistz256_to_mont(uint64_t r[4], const uint64_t a[4]);
void cc_ossl_ecp_nistz256_from_mont(uint64_t r[4], const uint64_t a[4]);
extern const nz_apt cc_ossl_ecp_nistz256_precomputed[37][64];
static const uint64_t ES_P[4] = { 0xffffffffffffffffull, 0x00000000ffffffffull, 0x0000000000000000ull,
                                  0xffffffff00000001ull };
static unsigned nz_booth7(unsigned in) { /* OpenSSL's _booth_recode_w7: arithmetic only */
    unsigned s = ~((in >> 7) - 1), d = (1u << 8) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);
    return (d << 1) + (s & 1);
}
static void nz_neg_if(uint64_t y[4], unsigned neg) { /* y = -y mod p if neg (0 or 1), by masks */
    uint64_t t[4], m = es_mask(neg);
    cc_ossl_ecp_nistz256_neg(t, y);
    for (int i = 0; i < 4; i++) y[i] ^= (y[i] ^ t[i]) & m;
    cc_wipe(t, sizeof t);
}
static void nz_base_mul(uint64_t res[8], const uint64_t k[4]) {
    uint8_t s[33];
    nz_pt p;
    nz_apt t;
    for (int i = 0; i < 32; i++) s[i] = (uint8_t)(k[i / 8] >> (8 * (i % 8)));
    s[32] = 0;
    unsigned w = nz_booth7((unsigned)(s[0] << 1) & 0xff), idx = 7;
    cc_ossl_ecp_nistz256_gather_w7((nz_apt *)&p, cc_ossl_ecp_nistz256_precomputed[0], (int)(w >> 1));
    nz_neg_if(p.Y, w & 1);
    /* the table encodes the identity as (0, 0); in Jacobian form it is Z = 0, so Z = R (one) unless X = Y = 0 */
    uint64_t acc = 0;
    for (int i = 0; i < 4; i++) acc |= p.X[i] | p.Y[i];
    uint64_t one = es_mask((~acc & (acc - 1)) >> 63 ^ 1); /* all ones unless acc == 0 */
    for (int i = 0; i < 4; i++) p.Z[i] = ES_ONE_M[i] & one;
    for (int i = 1; i < 37; i++) {
        unsigned off = (idx - 1) / 8; /* public: the window's position */
        w = ((unsigned)s[off] | (unsigned)s[off + 1] << 8) >> ((idx - 1) % 8) & 0xff;
        idx += 7;
        w = nz_booth7(w);
        cc_ossl_ecp_nistz256_gather_w7(&t, cc_ossl_ecp_nistz256_precomputed[i], (int)(w >> 1));
        nz_neg_if(t.Y, w & 1);
        cc_ossl_ecp_nistz256_point_add_affine(&p, &p, &t);
    }
    uint64_t zp[4], zi[4], z2[4], tm[12];
    cc_ossl_ecp_nistz256_from_mont(zp, p.Z);
    cc_s2n_bignum_modinv(4, zi, zp, ES_P, tm); /* Z != 0: k in [1, n) */
    cc_ossl_ecp_nistz256_to_mont(zi, zi);
    cc_ossl_ecp_nistz256_sqr_mont(z2, zi);
    cc_ossl_ecp_nistz256_mul_mont(res, p.X, z2);
    cc_ossl_ecp_nistz256_mul_mont(z2, z2, zi);
    cc_ossl_ecp_nistz256_mul_mont(res + 4, p.Y, z2);
    cc_ossl_ecp_nistz256_from_mont(res, res), cc_ossl_ecp_nistz256_from_mont(res + 4, res + 4);
    cc_wipe(s, sizeof s), cc_wipe(&p, sizeof p), cc_wipe(&t, sizeof t), cc_wipe(zp, sizeof zp), cc_wipe(zi, sizeof zi),
        cc_wipe(z2, sizeof z2), cc_wipe(tm, sizeof tm), cc_wipe(&w, sizeof w);
}
#endif
/* x, y (big-endian bytes) of [k] G for k < n given as 4 little-endian limbs */
static void es_base_mul(uint8_t x[32], uint8_t y[32], const uint64_t k[4]) {
#ifdef CC_ES256_S2N
    uint64_t res[8];
    if (cc_cpu() & CC_CPU_BMI2_ADX) cc_s2n_p256_scalarmulbase(res, k, 4, CC_P256_GTAB); /* (a CPU branch) */
#ifdef CC_ES256_NISTZ
    else nz_base_mul(res, k);
#else
    else cc_s2n_p256_scalarmulbase_alt(res, k, 4, CC_P256_GTAB);
#endif
    es_limbs_to_be(x, res), es_limbs_to_be(y, res + 4);
    cc_wipe(res, sizeof res);
#else
    int8_t e[65];
    for (int i = 0; i < 64; i++) e[i] = (int8_t)(k[i / 16] >> (4 * (i % 16)) & 15);
    e[64] = 0;
    int8_t carry = 0; /* to signed digits in [-8, 8): arithmetic only */
    for (int i = 0; i < 64; i++) {
        e[i] = (int8_t)(e[i] + carry);
        carry = (int8_t)((e[i] + 8) >> 4);
        e[i] = (int8_t)(e[i] - carry * 16);
    }
    e[64] = carry;
    es_pt P, Q;
    memset(&P, 0, sizeof P), memcpy(P.Y, ES_ONE_M, sizeof(es_fe)); /* the identity */
    for (int i = 0; i < 65; i++) es_select(&Q, CC_P256_GTAB + 64 * i, e[i]), es_add(&P, &P, &Q);
    static const uint64_t pm2[4] = { 0xfffffffffffffffdull, 0x00000000ffffffffull, 0x0000000000000000ull,
                                     0xffffffff00000001ull }; /* p - 2 */
    es_fe zi, ax, ay;
    es_fe_pow(zi, P.Z, pm2);
    fiat_p256_mul(ax, P.X, zi), fiat_p256_mul(ay, P.Y, zi);
    fiat_p256_from_montgomery(ax, ax), fiat_p256_from_montgomery(ay, ay);
    es_limbs_to_be(x, ax), es_limbs_to_be(y, ay);
    cc_wipe(e, sizeof e), cc_wipe(&P, sizeof P), cc_wipe(&Q, sizeof Q), cc_wipe(zi, sizeof zi), cc_wipe(ax, sizeof ax),
        cc_wipe(ay, sizeof ay);
#endif
}
/* o = a^-1 mod n, a in [1, n), plain (not Montgomery) form */
static void es_inv_n(uint64_t o[4], const uint64_t a[4]) {
#ifdef CC_ES256_S2N
    uint64_t t[12];
    cc_s2n_bignum_modinv(4, o, a, ES_N, t);
    cc_wipe(t, sizeof t);
#else
    static const uint64_t nm2[4] = { 0xf3b9cac2fc63254full, 0xbce6faada7179e84ull, 0xffffffffffffffffull,
                                     0xffffffff00000000ull }; /* n - 2 */
    es_sc am, im;
    fiat_p256_scalar_to_montgomery(am, a);
    es_sc_pow(im, am, nm2);
    fiat_p256_scalar_from_montgomery(o, im);
    cc_wipe(am, sizeof am), cc_wipe(im, sizeof im);
#endif
}

/* ---- RFC 6979 3.2 (SHA-256, q = n, qlen = hlen = 256) ---- */
typedef struct {
    uint8_t K[32], V[32];
    cc_hmac_key_t hk; /* K's HMAC midstates: K changes 3 times in 8 HMACs, so each key is set up once */
} es_drbg;
static void es_hmac(uint8_t out[32], const cc_hmac_key_t *hk, const uint8_t *m, int len) {
    cc_hmac_sha256_bytes(hk, 1, &m, &len, (uint8_t(*)[32])out);
}
static void es_setk(es_drbg *g) { cc_hmac_key_init(&g->hk, g->K, 32); }
/* x = int2octets(d), h = bits2octets(H(m)) = int2octets(H(m) mod n) */
static void es_drbg_init(es_drbg *g, const uint8_t x[32], const uint8_t h[32]) {
    uint8_t buf[97];
    memset(g->V, 1, 32), memset(g->K, 0, 32);
    es_setk(g);
    for (int t = 0; t < 2; t++) { /* K = HMAC_K(V || t || x || h), V = HMAC_K(V) */
        memcpy(buf, g->V, 32), buf[32] = (uint8_t)t, memcpy(buf + 33, x, 32), memcpy(buf + 65, h, 32);
        es_hmac(g->K, &g->hk, buf, 97);
        es_setk(g);
        es_hmac(g->V, &g->hk, g->V, 32);
    }
    cc_wipe(buf, sizeof buf);
}
/* the next candidate k (as limbs); 1 if it is in [1, n) (declassified), else the caller asks again */
static int es_drbg_next(es_drbg *g, uint64_t k[4], int retry) {
    if (retry) { /* K = HMAC_K(V || 0x00), V = HMAC_K(V) */
        uint8_t buf[33];
        memcpy(buf, g->V, 32), buf[32] = 0;
        es_hmac(g->K, &g->hk, buf, 33);
        es_setk(g);
        es_hmac(g->V, &g->hk, g->V, 32);
        cc_wipe(buf, sizeof buf);
    }
    es_hmac(g->V, &g->hk, g->V, 32);
    es_be_to_limbs(k, g->V);
    uint64_t ok = es_in_range(k);
    CC_DECLASSIFY(&ok, sizeof ok);
    return (int)ok;
}

/* ---- key and signing ---- */
static void es_sign_one(const cc_skey_t *key, const uint8_t hash[32], uint8_t sig[64]) {
    uint64_t z[4], k[4], ki[4], x[4];
    uint8_t h[32], xb[32], yb[32];
    es_drbg g;
    es_be_to_limbs(z, hash);
    es_sub_n_once(z, z); /* bits2int(H) mod n (H < 2^256 < 2n) */
    es_limbs_to_be(h, z);
    es_drbg_init(&g, key->es_d, h);
    for (int retry = 0;; retry = 1) {
        if (!es_drbg_next(&g, k, retry)) continue;
        es_base_mul(xb, yb, k);
        es_be_to_limbs(x, xb);
        es_sub_n_once(x, x); /* r = x mod n (x < p < 2n) */
        es_sc rm, zm, km, sm;
        fiat_p256_scalar_to_montgomery(rm, x);
        fiat_p256_scalar_to_montgomery(zm, z);
        es_inv_n(ki, k);
        fiat_p256_scalar_to_montgomery(km, ki);
        fiat_p256_scalar_mul(sm, rm, key->es_dm); /* r d */
        fiat_p256_scalar_add(sm, sm, zm);         /* z + r d */
        fiat_p256_scalar_mul(sm, sm, km);         /* k^-1 (z + r d) */
        uint64_t s[4];
        fiat_p256_scalar_from_montgomery(s, sm);
        uint64_t zero = ((x[0] | x[1] | x[2] | x[3]) == 0) | ((s[0] | s[1] | s[2] | s[3]) == 0);
        CC_DECLASSIFY(&zero, sizeof zero);
        es_limbs_to_be(sig, x), es_limbs_to_be(sig + 32, s);
        cc_wipe(rm, sizeof rm), cc_wipe(zm, sizeof zm), cc_wipe(km, sizeof km), cc_wipe(sm, sizeof sm),
            cc_wipe(s, sizeof s);
        if (!zero) break; /* r = 0 or s = 0: the next k (RFC 6979 3.4) */
    }
    cc_wipe(k, sizeof k), cc_wipe(ki, sizeof ki), cc_wipe(z, sizeof z), cc_wipe(x, sizeof x), cc_wipe(h, sizeof h),
        cc_wipe(&g, sizeof g), cc_wipe(xb, sizeof xb), cc_wipe(yb, sizeof yb);
}

cc_skey_t *cc_skey_es256(const uint8_t d[32]) {
    uint64_t dl[4];
    es_be_to_limbs(dl, d);
    uint64_t ok = es_in_range(dl);
    CC_DECLASSIFY(&ok, sizeof ok); /* the caller learns whether its key is valid anyway */
    if (!ok) {
        cc_wipe(dl, sizeof dl);
        return NULL;
    }
    cc_skey_t *k = calloc(1, sizeof *k);
    if (!k) {
        cc_wipe(dl, sizeof dl);
        return NULL;
    }
    k->alg = CC_PK_ES256;
    memcpy(k->es_d, d, 32);
    fiat_p256_scalar_to_montgomery(k->es_dm, dl);
    es_base_mul(k->es_qx, k->es_qy, dl);
    cc_wipe(dl, sizeof dl);
    return k;
}
void cc_skey_es256_public(const cc_skey_t *k, uint8_t x[32], uint8_t y[32]) {
    memcpy(x, k->es_qx, 32), memcpy(y, k->es_qy, 32);
}
int cc_skey_verify_after_sign(cc_skey_t *k, int on) {
    if (k->alg != CC_PK_ES256) return on ? -1 : 0; /* Ed25519: not offered (no fault model to justify its cost) */
    if (on && !k->vk && !(k->vk = cc_pkey_es256(k->es_qx, k->es_qy))) return -1;
    if (!on && k->vk) cc_pkey_free(k->vk), k->vk = NULL;
    return 0;
}

static int es_sign_batch(const cc_skey_t *k, int n, const uint8_t *const *msg, const int *len, uint8_t *const *sig) {
    enum { CH = 16 };
    int bad = 0;
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH;
        uint8_t hb[CH][32];
        cc_sha256_bytes(m, msg + base, len + base, hb); /* the messages are public; batched */
        for (int i = 0; i < m; i++) es_sign_one(k, hb[i], sig[base + i]);
        if (k->vk) { /* verify-after-sign: public data from here */
            uint8_t ok[CH];
            int sl[CH];
            const uint8_t *sp[CH];
            for (int i = 0; i < m; i++) sl[i] = 64, sp[i] = sig[base + i];
            cc_verify_batch(k->vk, m, msg + base, len + base, sp, sl, ok);
            for (int i = 0; i < m; i++)
                if (!ok[i]) memset(sig[base + i], 0, 64), bad++;
        }
    }
    return bad;
}
