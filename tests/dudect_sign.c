/* dudect_sign: statistical constant-time tests (dudect: Reparaz, Balasch, Verbauwhede, DATE 2017) of signing, on real
 * hardware: class 0 is one fixed private key, class 1 a random one from a pool, the messages the same.  The method is
 * dudect_hmac.c's rev 3 (class sequence drawn up front, pools selected by index, a branch-history scrub before each
 * sample, equal-sized pools for both classes); |t| > 10 is a leak, < 4.5 consistent with constant time.
 *   ed BATCH        cc_sign_batch of BATCH 100-byte messages: the key's secrets (a, prefix) and its public key are
 *                   copied into one working key before each sample (the table of multiples of B is the same for
 *                   every key)
 *   edkey           cc_skey_ed25519 from a 32-byte seed, then cc_skey_free (SHA-512, reduction, [a] B, encoding)
 *   hs BATCH        jwt_key_init then jwt_sign_batch of BATCH payloads (the dispatched HMAC and the encoder)
 *   es BATCH        ES256 cc_sign_batch of BATCH 100-byte messages: d (big-endian and Montgomery form) copied into
 *                   one working key before each sample (RFC 6979, [k] G, k^-1, s all follow from it)
 *   eskey           cc_skey_es256 from a 32-byte d (top bit cleared), then cc_skey_free ([d] G)
 *   aa-ed / aa-hs / aa-es BATCH   A/A negative controls: both classes the same fixed key, from two separate pools
 *   control         positive control: an early-exit 32-byte compare, mismatch at byte 0 or byte 31; must say LEAK
 *   vt-control      positive control in Ed25519 terms: [s] B with the verify side's variable-time comb (signed digits,
 *                   zero digits skipped, the table indexed by the digit) on a fixed vs random s; must say LEAK
 * Usage: dudect_sign TEST [BATCH] [N]; N measurements (default 200,000; signing is ~1000x an HMAC). */
#include "jwt.c"
#include <math.h>
#include <stdio.h>
#include <x86intrin.h>

static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) { return rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17; }
static inline uint64_t cyc(void) {
    unsigned a;
    return __rdtscp(&a);
}
typedef struct {
    double n, mean, m2;
} welch_t;
static void push(welch_t *w, double x) {
    w->n++;
    double d = x - w->mean;
    w->mean += d / w->n, w->m2 += d * (x - w->mean);
}
static double tstat(const welch_t *a, const welch_t *b) {
    double va = a->m2 / (a->n - 1), vb = b->m2 / (b->n - 1);
    return (a->mean - b->mean) / sqrt(va / a->n + vb / b->n);
}
static int cmp_u64(const void *x, const void *y) {
    uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;
    return a < b ? -1 : a > b;
}

enum { POOL = 64, MAXB = 32 };
typedef struct {
    sg_sc a_m;
    uint8_t prefix[32], pub[32];
} edsec_t;
typedef struct {
    uint8_t b[32];
} key32_t;
static int test, batch;
static edsec_t edfix[POOL], edrand[POOL], edfix2[POOL], *edpool[2];
static key32_t kfix[POOL], krand[POOL], kfix2[POOL], *kpool[2];
typedef struct {
    uint64_t dm[4];
    uint8_t d[32];
} essec_t;
static essec_t esfix[POOL], esrand[POOL], esfix2[POOL], *espool[2];
static cc_skey_t *kwe; /* the working ES256 key */
static cc_skey_t *kw;  /* the working signing key */
static uint8_t seedcur[32], cmpa[32], cmpb0[32], cmpb1[32], cmpcur[32];
static uint8_t msgs[MAXB][100], sig[MAXB][64], *sp[MAXB];
static const uint8_t *mp[MAXB];
static int ml[MAXB];
static char pls[MAXB][96], outs[MAXB][256], *op_[MAXB];
static const char *pp[MAXB];
static int pn[MAXB], on[MAXB];
static volatile int sink;
#ifndef CC_ED_S2N
static ed_key_t *vtk;
#endif

__attribute__((noinline)) static int leaky_eq(const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 32; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}
static volatile int scrub_sink;
__attribute__((noinline)) static void scrub_history(void) {
    int a = 0;
    for (int i = 0; i < 512; i++) a += i & 1 ? 3 : 5;
    scrub_sink = a;
}
static void prepare(int c, int i) {
    switch (test) {
        case 0: { /* ed */
            const edsec_t *s = &edpool[c][i & (POOL - 1)];
            memcpy(kw->a_m, s->a_m, sizeof kw->a_m), memcpy(kw->prefix, s->prefix, 32), memcpy(kw->pub, s->pub, 32);
            break;
        }
        case 1:
        case 2:
        case 4: memcpy(seedcur, kpool[c][i & (POOL - 1)].b, 32); break; /* edkey, hs, vt-control */
        case 5: {                                                       /* es */
            const essec_t *e = &espool[c][i & (POOL - 1)];
            memcpy(kwe->es_dm, e->dm, sizeof kwe->es_dm), memcpy(kwe->es_d, e->d, 32);
            break;
        }
        case 6: memcpy(seedcur, kpool[c][i & (POOL - 1)].b, 32), seedcur[0] &= 0x7f; break; /* eskey */
        default: memcpy(cmpcur, c ? cmpb1 : cmpb0, 32); break;                              /* control */
    }
}
static void op(void) {
    switch (test) {
        case 0: cc_sign_batch(kw, batch, mp, ml, sp); break;
        case 1: {
            cc_skey_t *k = cc_skey_ed25519(seedcur);
            sink = k->pub[0];
            cc_skey_free(k);
            break;
        }
        case 2: {
            jwt_key_t k;
            jwt_key_init(&k, seedcur, 32);
            jwt_sign_batch(&k, batch, pp, pn, op_, on);
            break;
        }
        case 4: {
#ifndef CC_ED_S2N
            uint64_t s[4];
            int16_t d[ED_NW];
            le_to_limbs(s, seedcur);
            s[3] &= 0x0fffffffffffffffull;
            ed_recode(d, s);
            ed_p3 P;
            f_set(P.X, 0), f_set(P.Y, 1), f_set(P.Z, 1), f_set(P.T, 0);
            for (int j = 0; j < ED_NW; j++) {
                if (d[j] > 0) ed_madd(&P, &vtk->tb[j][d[j] - 1]);
                else if (d[j] < 0) ed_msub(&P, &vtk->tb[j][-d[j] - 1]);
            }
            sink = (int)P.X[0];
#endif
            break;
        }
        case 5: cc_sign_batch(kwe, batch, mp, ml, sp); break;
        case 6: {
            cc_skey_t *k = cc_skey_es256(seedcur);
            sink = k->es_qx[0];
            cc_skey_free(k);
            break;
        }
        default: sink = leaky_eq(cmpa, cmpcur); break;
    }
}
static void es_secrets(essec_t *o, const uint8_t d32[32]) {
    uint8_t d[32];
    memcpy(d, d32, 32), d[0] &= 0x7f;
    cc_skey_t *k = cc_skey_es256(d);
    memcpy(o->dm, k->es_dm, sizeof o->dm), memcpy(o->d, k->es_d, 32);
    cc_skey_free(k);
}

static void ed_secrets(edsec_t *o, const uint8_t seed[32]) {
    cc_skey_t *k = cc_skey_ed25519(seed);
    memcpy(o->a_m, k->a_m, sizeof o->a_m), memcpy(o->prefix, k->prefix, 32), memcpy(o->pub, k->pub, 32);
    cc_skey_free(k);
}

int main(int argc, char **argv) {
    const char *t = argc > 1 ? argv[1] : "ed";
    batch = argc > 2 ? atoi(argv[2]) : 1;
    long N = argc > 3 ? atol(argv[3]) : 200000;
    if (batch < 1 || batch > MAXB) return 2;
    int aa = !strncmp(t, "aa-", 3);
    const char *base = aa ? t + 3 : t;
    test = !strcmp(base, "ed")           ? 0
           : !strcmp(base, "edkey")      ? 1
           : !strcmp(base, "hs")         ? 2
           : !strcmp(base, "vt-control") ? 4
           : !strcmp(base, "control")    ? 3
           : !strcmp(base, "es")         ? 5
           : !strcmp(base, "eskey")      ? 6
                                         : -1;
    if (test < 0) return fprintf(stderr, "unknown test %s\n", t), 2;
#ifdef CC_ED_S2N
    if (test == 4) return printf("vt-control: not in an s2n build\n"), 0;
#endif
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)rnd();
    edsec_t fixs;
    ed_secrets(&fixs, seed);
    essec_t fixe;
    es_secrets(&fixe, seed);
    key32_t fixk;
    memcpy(fixk.b, seed, 32);
    for (int r = 0; r < POOL; r++) {
        edfix[r] = edfix2[r] = fixs, kfix[r] = kfix2[r] = fixk;
        for (int i = 0; i < 32; i++) krand[r].b[i] = (uint8_t)rnd();
        ed_secrets(&edrand[r], krand[r].b);
        esfix[r] = esfix2[r] = fixe;
        es_secrets(&esrand[r], krand[r].b);
    }
    espool[0] = esfix, espool[1] = aa ? esfix2 : esrand;
    {
        uint8_t d[32];
        memcpy(d, seed, 32), d[0] &= 0x7f;
        kwe = cc_skey_es256(d);
    }
    edpool[0] = edfix, edpool[1] = aa ? edfix2 : edrand;
    kpool[0] = kfix, kpool[1] = aa ? kfix2 : krand;
    kw = cc_skey_ed25519(seed);
    for (int j = 0; j < MAXB; j++) {
        for (int i = 0; i < 100; i++) msgs[j][i] = (uint8_t)rnd();
        mp[j] = msgs[j], ml[j] = 100, sp[j] = sig[j];
        pn[j] = snprintf(pls[j], sizeof pls[j], "{\"sub\":\"%d\",\"username\":\"user%02d\",\"exp\":4102444800}",
                         1000 + j, j);
        pp[j] = pls[j], op_[j] = outs[j];
    }
    for (int i = 0; i < 32; i++) cmpa[i] = cmpb0[i] = cmpb1[i] = (uint8_t)rnd();
    cmpb0[0] ^= 1, cmpb1[31] ^= 1;
#ifndef CC_ED_S2N
    if (test == 4) {
        uint8_t pub[32];
        cc_skey_public(kw, pub);
        vtk = ed_key_new(pub); /* its tb is the verify side's comb table of B */
    }
#endif
    uint64_t *x = malloc(sizeof *x * N);
    uint8_t *cls = malloc(N), *seq = malloc(N);
    for (long i = 0; i < N; i++) seq[i] = (uint8_t)(rnd() & 1);
    for (long i = 0; i < 2000; i++) prepare((int)(rnd() & 1), (int)i), op(); /* warm up */
    for (long i = 0; i < N; i++) {
        int c = seq[i];
        prepare(c, (int)i);
        scrub_history();
        _mm_mfence(), _mm_lfence();
        uint64_t t0 = cyc();
        op();
        uint64_t t1 = cyc();
        x[i] = t1 - t0, cls[i] = (uint8_t)c;
    }
    uint64_t *s = malloc(sizeof *s * N);
    memcpy(s, x, sizeof *s * N);
    qsort(s, N, sizeof *s, cmp_u64);
    static const double pc[] = { 1.0, 0.5, 0.75, 0.9, 0.95, 0.99 };
    double tmax = 0;
    char detail[256] = "";
    int dn = 0;
    for (int p = 0; p < 6; p++) {
        uint64_t cut = pc[p] >= 1.0 ? ~0ull : s[(long)(pc[p] * (N - 1))];
        welch_t a = { 0 }, b = { 0 };
        for (long i = 0; i < N; i++)
            if (x[i] <= cut) push(cls[i] ? &b : &a, (double)x[i]);
        double tv = tstat(&a, &b);
        if (fabs(tv) > fabs(tmax)) tmax = tv;
        dn += snprintf(detail + dn, sizeof detail - dn, " p%.0f:%+.2f", pc[p] * 100, tv);
    }
    printf("%s b%d: N=%ld median %lu cyc, max|t| %.2f %s [%s ] engine %s\n", t, batch, N, (unsigned long)s[N / 2],
           fabs(tmax),
           fabs(tmax) > 10    ? "LEAK"
           : fabs(tmax) > 4.5 ? "inconclusive"
                              : "ok",
           detail, jwt_engine());
    cc_skey_free(kw);
    return 0;
}
