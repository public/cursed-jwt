/* test_rsaz: the -DJWT_RSAZ RSA-2048 path against OpenSSL's BN_mod_exp (an independent implementation).
 * For each key and signature value s < n, em = s^e mod n from libcrypto must be accepted by rsa_one_ifma, and em with
 * any one of several single bits flipped must be rejected; the s2n / C path (rsa_one) must agree on every case. The
 * two-way path (rsa_two_ifma) runs each case beside the previous one: both accepted, and a bad em on either side
 * rejected on that side only.
 * Keys: fresh RSA-2048 keys with e = 65537, 3 and a random odd 32-bit e, plus moduli at both ends of the 2048-bit
 * range. s: 0, 1, 2, n-1, n-2, 2^2047, 2^2048 - n reduced, all-ones below n, and random values.
 * Built as a unity build so the static functions are reachable: cc -DJWT_RSAZ [-DJWT_S2N ...] tests/test_rsaz.c
 * src/rsaz-4k-avx512.S ... -lcrypto. On a CPU without IFMA it says so and exits 77 (skipped). */
#include "../src/jwt.c"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static int fails, cases;
static uint64_t prev_s[32], prev_em[32]; /* the previous case under the same key, for the two-way kernel */
static int have_prev;
#ifdef JWT_RSAZ8
static uint64_t ring_s[8][RSA_MAXL], ring_em[8][RSA_MAXL]; /* the last 8 cases under the same key */
static int ring_n;
#endif
static void limbs_of(uint64_t *o, const BIGNUM *b) {
    memset(o, 0, 32 * 8);
    BN_bn2lebinpad(b, (unsigned char *)o, 256);
}

static void check(const rsa_key_t *k, mont_ops_t mo, const BIGNUM *bn, const BIGNUM *be, const BIGNUM *s, BN_CTX *ctx,
                  const char *what) {
    BIGNUM *r = BN_new();
    BN_mod_exp(r, s, be, bn, ctx);
    uint64_t sl[32], em[32];
    limbs_of(sl, s), limbs_of(em, r);
    cases++;
    if (!rsa_one_ifma(k, sl, em)) {
        fails++;
        fprintf(stderr, "FAIL accept: %s\n", what);
    }
    if (!rsa_one(k, mo, sl, em)) {
        fails++;
        fprintf(stderr, "FAIL reference path disagrees: %s\n", what);
    }
    if (have_prev) { /* two-way: this case beside the previous one; each side must be judged on its own */
        uint8_t o0 = 0, o1 = 0;
        uint64_t bad[32];
        cases++;
        rsa_two_ifma(k, sl, prev_s, em, prev_em, &o0, &o1);
        if (!o0 || !o1) fails++, fprintf(stderr, "FAIL two-way accept (%d %d): %s\n", o0, o1, what);
        memcpy(bad, em, sizeof bad), bad[5] ^= 1ull << 17;
        cases++;
        rsa_two_ifma(k, sl, prev_s, bad, prev_em, &o0, &o1);
        if (o0 || !o1) fails++, fprintf(stderr, "FAIL two-way, bad left (%d %d): %s\n", o0, o1, what);
        memcpy(bad, prev_em, sizeof bad), bad[31] ^= 1ull << 40;
        cases++;
        rsa_two_ifma(k, sl, prev_s, em, bad, &o0, &o1);
        if (!o0 || o1) fails++, fprintf(stderr, "FAIL two-way, bad right (%d %d): %s\n", o0, o1, what);
        cases++;
        rsa_two_ifma(k, sl, sl, em, em, &o0, &o1); /* the same token on both sides */
        if (!o0 || !o1) fails++, fprintf(stderr, "FAIL two-way, same token: %s\n", what);
    }
    memcpy(prev_s, sl, sizeof prev_s), memcpy(prev_em, em, sizeof prev_em), have_prev = 1;
#ifdef JWT_RSAZ8
    memset(ring_s[ring_n % 8], 0, sizeof ring_s[0]), memset(ring_em[ring_n % 8], 0, sizeof ring_em[0]);
    memcpy(ring_s[ring_n % 8], sl, sizeof sl), memcpy(ring_em[ring_n % 8], em, sizeof em), ring_n++;
    if (ring_n >= 8 && k->ifma8) { /* eight-lane: all eight accepted; then one bad lane, rejected alone */
        int at8[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
        uint8_t o8[8];
        cases++;
        rsa_eight_ifma(k, ring_s, ring_em, at8, o8);
        for (int l = 0; l < 8; l++)
            if (!o8[l]) fails++, fprintf(stderr, "FAIL eight-lane accept lane %d: %s\n", l, what);
        int bad_l = ring_n % 8;
        ring_em[bad_l][bad_l * 3] ^= 1ull << (7 * bad_l);
        cases++;
        rsa_eight_ifma(k, ring_s, ring_em, at8, o8);
        for (int l = 0; l < 8; l++)
            if (o8[l] != (l != bad_l))
                fails++, fprintf(stderr, "FAIL eight-lane, bad lane %d, lane %d: %s\n", bad_l, l, what);
        ring_em[bad_l][bad_l * 3] ^= 1ull << (7 * bad_l);
    }
#endif
    static const int bits[] = { 0, 1, 51, 52, 63, 64, 1023, 2027, 2028, 2047 };
    for (unsigned i = 0; i < sizeof bits / sizeof *bits; i++) {
        uint64_t bad[32];
        memcpy(bad, em, sizeof bad);
        bad[bits[i] / 64] ^= 1ull << (bits[i] % 64);
        cases++;
        if (rsa_one_ifma(k, sl, bad)) {
            fails++;
            fprintf(stderr, "FAIL reject bit %d: %s\n", bits[i], what);
        }
    }
    BN_free(r);
}

static void one_key(const BIGNUM *bn, unsigned long e, int nrand, BN_CTX *ctx, const char *name) {
    uint8_t nb[256], eb[8];
    BN_bn2binpad(bn, nb, 256);
    int el = 0;
    for (int i = 7; i >= 0; i--)
        if ((e >> (8 * i)) || el) eb[el++] = (uint8_t)(e >> (8 * i));
    cc_pkey_t *pk = cc_pkey_rs256(nb, 256, eb, (size_t)el);
    if (!pk) {
        fails++;
        fprintf(stderr, "FAIL key setup %s\n", name);
        return;
    }
    const rsa_key_t *k = &pk->rsa;
    have_prev = 0;
#ifdef JWT_RSAZ8
    if (((uintptr_t)k->n52x8 | (uintptr_t)k->rr52x8 | (uintptr_t)k->k0x8) & 63) {
        fails++, fprintf(stderr, "FAIL key %s: eight-lane constants not 64-byte aligned\n", name);
        cc_pkey_free(pk);
        return;
    }
#endif
#ifdef JWT_RSAZ8
    ring_n = 0;
    if (!k->ifma8) printf("  (eight-lane path inactive for %s: needs e = 65537 and FAST_ZMM)\n", name);
#endif
    if (!k->ifma) {
        fails++;
        fprintf(stderr, "FAIL key %s did not take the IFMA path\n", name);
        cc_pkey_free(pk);
        return;
    }
    mont_ops_t mo = mont_for(k);
    BIGNUM *be = BN_new(), *s = BN_new(), *t = BN_new();
    BN_set_word(be, e);
    char what[128];
#define CASE(label) snprintf(what, sizeof what, "%s e=%lu s=%s", name, e, label), check(k, mo, bn, be, s, ctx, what)
    BN_zero(s);
    CASE("0");
    BN_one(s);
    CASE("1");
    BN_set_word(s, 2);
    CASE("2");
    BN_sub(s, bn, BN_value_one());
    CASE("n-1");
    BN_sub(s, s, BN_value_one());
    CASE("n-2");
    BN_zero(s);
    BN_set_bit(s, 2047);
    if (BN_cmp(s, bn) < 0) CASE("2^2047");
    BN_zero(t);
    BN_set_bit(t, 2048);
    BN_mod(s, t, bn, ctx);
    CASE("2^2048 mod n");
    BN_set_bit(t, 2048);
    BN_sub_word(t, 1);
    BN_mask_bits(t, BN_num_bits(bn) - 1);
    BN_copy(s, t);
    CASE("ones below n");
    for (int i = 0; i < nrand; i++) {
        BN_rand_range(s, bn);
        CASE("random");
    }
    BN_free(be), BN_free(s), BN_free(t);
    cc_pkey_free(pk);
}

static BIGNUM *gen_n(unsigned long e) {
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    BIGNUM *be = BN_new();
    BN_set_word(be, e);
    EVP_PKEY_keygen_init(c);
    EVP_PKEY_CTX_set_rsa_keygen_bits(c, 2048);
    EVP_PKEY_CTX_set1_rsa_keygen_pubexp(c, be);
    if (EVP_PKEY_keygen(c, &pk) <= 0) {
        fprintf(stderr, "keygen failed\n");
        exit(2);
    }
    BIGNUM *n = NULL;
    EVP_PKEY_get_bn_param(pk, "n", &n);
    EVP_PKEY_free(pk), EVP_PKEY_CTX_free(c), BN_free(be);
    return n;
}

int main(int argc, char **argv) {
    int nkeys = argc > 1 ? atoi(argv[1]) : 4, nrand = argc > 2 ? atoi(argv[2]) : 50;
    if (!ifma_ok()) {
        printf("test_rsaz: no AVX-512 IFMA on this CPU, skipped\n");
        return 77;
    }
    BN_CTX *ctx = BN_CTX_new();
    char name[64];
    for (int i = 0; i < nkeys; i++) {
        BIGNUM *n = gen_n(65537);
        snprintf(name, sizeof name, "key%d", i);
        one_key(n, 65537, nrand, ctx, name);
        BN_free(n);
    }
    {
        BIGNUM *n = gen_n(3);
        one_key(n, 3, nrand, ctx, "key-e3");
        BN_free(n);
    }
    {
        uint32_t r;
        RAND_bytes((unsigned char *)&r, 4);
        unsigned long e = (r | 0x80000001u);
        BIGNUM *n = gen_n(e);
        one_key(n, e, nrand, ctx, "key-e32");
        BN_free(n);
    }
    /* odd moduli at the ends of the 2048-bit range (not RSA keys: the arithmetic doesn't care) */
    {
        BIGNUM *n = BN_new();
        BN_zero(n);
        BN_set_bit(n, 2047);
        BN_add_word(n, 1);
        one_key(n, 65537, nrand, ctx, "n=2^2047+1");
        BN_free(n);
    }
    {
        BIGNUM *n = BN_new();
        BN_zero(n);
        BN_set_bit(n, 2048);
        BN_sub_word(n, 1);
        one_key(n, 65537, nrand, ctx, "n=2^2048-1");
        BN_free(n);
    }
    {
        BIGNUM *n = BN_new();
        BN_rand(n, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        one_key(n, 65537, nrand, ctx, "n=random odd");
        BN_free(n);
    }
    printf("test_rsaz: %d cases, %d failures\n", cases, fails);
    BN_CTX_free(ctx);
    return fails != 0;
}
