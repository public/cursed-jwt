/* cjwt_envoy.c: see cjwt_envoy.h.  One translation unit: it includes cursed-jwt's src/jwt.c (here built with
 * -DJWT_S2N) to reuse its static JSON scanner (jstr / jskip / jnum / junescape), HMAC engine dispatch and PK
 * kernels, so the hot paths are exactly cursed-jwt's.  Build: see Makefile. */
#include "../../src/jwt.c"
#include "cjwt_envoy.h"

#include <math.h>

const char *cje_status_str(int st) {
    static const char *s[] = { "Ok",
                               "JwtBadFormat",
                               "JwtHeaderParseErrorBadBase64",
                               "JwtHeaderParseErrorBadJson",
                               "JwtHeaderBadAlg",
                               "JwtHeaderBadKid",
                               "JwtPayloadParseErrorBadBase64",
                               "JwtPayloadParseErrorBadJson",
                               "JwtPayloadParseErrorClaim",
                               "JwtSignatureParseErrorBadBase64",
                               "JwksKidAlgMismatch",
                               "JwtVerificationFail",
                               "JwtNotYetValid",
                               "JwtExpired",
                               "JwtAudienceNotAllowed",
                               "JwtUnknownIssuer" };
    return st >= 0 && st < (int)(sizeof s / sizeof *s) ? s[st] : "?";
}


/* ---- Envoy compatibility: what protobuf's JSON parser (JsonStringToMessage into a Struct) refuses on top of
 * RFC 8259 -- duplicate keys in any object, numbers outside double range, lone surrogate escapes -- so that we
 * reject exactly the tokens Envoy rejects (test/diff.cpp checks it). ---------------------------------------- */

/* a string with escapes: every \uD800-\uDBFF must be followed by \uDC00-\uDFFF, and no lone low surrogate */
static int esc_surrogates_ok(const uint8_t *s, int n) {
    for (int i = 0; i < n; i++) {
        if (s[i] != '\\') continue;
        if (s[i + 1] != 'u') {
            i++;
            continue;
        }
        uint32_t v, lo;
        hex4(s + i + 2, &v);
        i += 5;
        if (v >= 0xDC00 && v <= 0xDFFF) return 0;
        if (v >= 0xD800 && v <= 0xDBFF) {
            if (i + 6 >= n) return 0;
            if (s[i + 1] != '\\' || s[i + 2] != 'u' || !hex4(s + i + 3, &lo) || lo < 0xDC00 || lo > 0xDFFF) return 0;
            i += 6;
        }
    }
    return 1;
}

JWT_INLINE int jstr_env(jcur_t *c, const uint8_t **s, int *n, int *esc) {
    if (!jstr(c, s, n, esc)) return 0;
    return !*esc || esc_surrogates_ok(*s, *n);
}

/* a number span that strtod would turn into +-inf (protobuf: "out of range") */
static int num_finite(const uint8_t *s, int n, int isint) {
    if (isint || n < 16) {
        int e = 0;
        for (int i = 0; i < n; i++) e |= s[i] == 'e' || s[i] == 'E';
        if (!e && n < 300) return 1;
    }
    char buf[64], *big = NULL, *b = buf;
    if (n >= (int)sizeof buf) b = big = malloc(n + 1);
    if (!b) return 0;
    memcpy(b, s, n), b[n] = 0;
    double d = strtod(b, NULL);
    free(big);
    return !isinf(d);
}

/* duplicate-key set for one object: keys as (pointer, length, escaped) spans; exact compare after a 64-bit filter */
#define KEYSET_MAX 128 /* members per object we check exactly; a bigger object is refused (Envoy takes it) */
typedef struct {
    const uint8_t *k[KEYSET_MAX];
    int n[KEYSET_MAX], esc[KEYSET_MAX], cnt;
    uint64_t bloom;
} keyset_t;

static int key_eq(const uint8_t *a, int an, int ae, const uint8_t *b, int bn, int be) {
    if (!ae && !be) return an == bn && !memcmp(a, b, an);
    uint8_t x[256], y[256];
    int xn = ae ? junescape(x, sizeof x, a, an) : (an <= 256 ? (memcpy(x, a, an), an) : -1);
    int yn = be ? junescape(y, sizeof y, b, bn) : (bn <= 256 ? (memcpy(y, b, bn), bn) : -1);
    if (xn < 0 || yn < 0) return an == bn && ae == be && !memcmp(a, b, an); /* long keys: raw compare */
    return xn == yn && !memcmp(x, y, xn);
}

/* 1 if new, 0 if a duplicate or the object is too big.  A key with escapes matches anything in the filter, so it
 * is always compared exactly. */
static int keyset_add(keyset_t *ks, const uint8_t *k, int n, int esc) {
    if (ks->cnt == KEYSET_MAX) return 0;
    uint64_t bit = esc ? ~0ull : 1ull << ((n * 7 + (n ? k[0] * 3 + k[n - 1] : 0)) & 63);
    if (ks->bloom & bit)
        for (int i = 0; i < ks->cnt; i++)
            if (key_eq(ks->k[i], ks->n[i], ks->esc[i], k, n, esc)) return 0;
    ks->k[ks->cnt] = k, ks->n[ks->cnt] = n, ks->esc[ks->cnt] = esc, ks->cnt++;
    ks->bloom |= bit;
    return 1;
}

/* jskip with the checks above (objects: duplicate keys; numbers: finite; strings: surrogates) */
static int jskip_env(jcur_t *c, int depth) {
    jws(c);
    if (c->p >= c->e) return 0;
    const uint8_t *s;
    int n, esc, isint;
    switch (*c->p) {
        case '"': return jstr_env(c, &s, &n, &esc);
        case '[':
            if (depth >= 32) return 0;
            c->p++;
            jws(c);
            if (c->p < c->e && *c->p == ']') return c->p++, 1;
            for (;;) {
                if (!jskip_env(c, depth + 1)) return 0;
                jws(c);
                if (c->p >= c->e) return 0;
                if (*c->p == ',') {
                    c->p++;
                    continue;
                }
                if (*c->p == ']') return c->p++, 1;
                return 0;
            }
        case '{': {
            if (depth >= 32) return 0;
            keyset_t ks;
            ks.cnt = 0, ks.bloom = 0;
            c->p++;
            jws(c);
            if (c->p < c->e && *c->p == '}') return c->p++, 1;
            for (;;) {
                jws(c);
                if (!jstr_env(c, &s, &n, &esc)) return 0;
                if (!keyset_add(&ks, s, n, esc)) return 0;
                jws(c);
                if (c->p >= c->e || *c->p++ != ':') return 0;
                if (!jskip_env(c, depth + 1)) return 0;
                jws(c);
                if (c->p >= c->e) return 0;
                if (*c->p == ',') {
                    c->p++;
                    continue;
                }
                if (*c->p == '}') return c->p++, 1;
                return 0;
            }
        }
        case 't':
            if (c->e - c->p >= 4 && !memcmp(c->p, "true", 4)) return c->p += 4, 1;
            return 0;
        case 'f':
            if (c->e - c->p >= 5 && !memcmp(c->p, "false", 5)) return c->p += 5, 1;
            return 0;
        case 'n':
            if (c->e - c->p >= 4 && !memcmp(c->p, "null", 4)) return c->p += 4, 1;
            return 0;
        default: return jnum(c, &s, &n, &isint) && num_finite(s, n, isint);
    }
}

/* ---- token parsing ------------------------------------------------------------------------------------------- */

typedef struct {
    uint8_t *p, *e; /* bump allocator for unescaped strings */
} arena_t;

/* a validated JSON string -> cje_str_t (zero-copy unless it has escapes) */
static int str_out(arena_t *a, const uint8_t *s, int n, int esc, cje_str_t *out) {
    if (!esc) {
        out->p = (const char *)s, out->n = n;
        return 1;
    }
    int m = junescape(a->p, (int)(a->e - a->p), s, n);
    if (m < 0) return 0;
    out->p = (const char *)a->p, out->n = m, a->p += m;
    return 1;
}

/* Envoy's GetUInt64: a JSON number, 0 <= v < 2^64, truncated */
static int num_u64(jcur_t *c, uint64_t *v) {
    const uint8_t *s;
    int n, isint;
    if (c->p >= c->e || !((*c->p >= '0' && *c->p <= '9') || *c->p == '-')) return 0;
    if (!jnum(c, &s, &n, &isint) || !num_finite(s, n, isint)) return -1;
    if (isint && *s != '-') {
        *v = (uint64_t)jint(s, n);
        return 1;
    }
    char buf[64];
    if (n >= (int)sizeof buf) return 0;
    memcpy(buf, s, n), buf[n] = 0;
    double d = strtod(buf, NULL);
    if (!(d >= 0) || d >= 18446744073709551615.0) return 0;
    *v = (uint64_t)d;
    return 1;
}

enum { KX_OTHER, KX_ISS, KX_SUB, KX_AUD, KX_EXP, KX_NBF, KX_IAT, KX_JTI, KX_ALG, KX_KID };
static int key_id(const uint8_t *s, int n, int esc) {
    uint8_t b[8];
    if (esc) {
        if ((n = junescape(b, sizeof b, s, n)) < 0) return KX_OTHER;
        s = b;
    }
    if (n != 3) return KX_OTHER;
    uint32_t k = (uint32_t)s[0] | (uint32_t)s[1] << 8 | (uint32_t)s[2] << 16;
#define K3(a, b, c) ((uint32_t)(a) | (uint32_t)(b) << 8 | (uint32_t)(c) << 16)
    switch (k) {
        case K3('i', 's', 's'): return KX_ISS;
        case K3('s', 'u', 'b'): return KX_SUB;
        case K3('a', 'u', 'd'): return KX_AUD;
        case K3('e', 'x', 'p'): return KX_EXP;
        case K3('n', 'b', 'f'): return KX_NBF;
        case K3('i', 'a', 't'): return KX_IAT;
        case K3('j', 't', 'i'): return KX_JTI;
        case K3('a', 'l', 'g'): return KX_ALG;
        case K3('k', 'i', 'd'): return KX_KID;
    }
#undef K3
    return KX_OTHER;
}

/* Walk one JSON object; header = 1 reads alg / kid, else the payload claims.  Returns CJE_OK or a status. */
static int parse_obj(cje_jwt_t *j, arena_t *a, const uint8_t *p, int n, int header) {
    const int bad_json = header ? CJE_HEADER_JSON : CJE_PAYLOAD_JSON;
    jcur_t c = { p, p + n };
    const uint8_t *s;
    int len, esc, seen = 0, st = CJE_OK;
    keyset_t ks;
    ks.cnt = 0, ks.bloom = 0;
    jws(&c);
    if (c.p >= c.e || *c.p++ != '{') return bad_json;
    jws(&c);
    if (c.p < c.e && *c.p == '}') {
        c.p++;
        goto end;
    }
    for (;;) {
        jws(&c);
        if (!jstr_env(&c, &s, &len, &esc)) return bad_json;
        if (!keyset_add(&ks, s, len, esc)) return bad_json; /* any repeated key, like protobuf */
        int key = key_id(s, len, esc);
        if (header ? key != KX_ALG && key != KX_KID : key == KX_ALG || key == KX_KID) key = KX_OTHER;
        jws(&c);
        if (c.p >= c.e || *c.p++ != ':') return bad_json;
        jws(&c);
        if (key != KX_OTHER) seen |= 1u << key;
        cje_str_t *dst = NULL;
        uint64_t *num = NULL;
        switch (key) {
            case KX_ALG: {
                if (c.p >= c.e || *c.p != '"') {
                    if (!jskip_env(&c, 1)) return bad_json;
                    st = st ? st : CJE_HEADER_ALG;
                    break;
                }
                cje_str_t v;
                if (!jstr_env(&c, &s, &len, &esc) || !str_out(a, s, len, esc, &v)) return bad_json;
                j->alg = v.n != 5                   ? CJE_ALG_NONE
                         : !memcmp(v.p, "HS256", 5) ? CJE_HS256
                         : !memcmp(v.p, "RS256", 5) ? CJE_RS256
                         : !memcmp(v.p, "ES256", 5) ? CJE_ES256
                                                    : CJE_ALG_NONE;
                if (!j->alg && !st) st = CJE_HEADER_ALG;
                break;
            }
            case KX_KID: dst = &j->kid; break;
            case KX_ISS: dst = &j->iss; break;
            case KX_SUB: dst = &j->sub; break;
            case KX_JTI: dst = &j->jti; break;
            case KX_EXP: num = &j->exp; break;
            case KX_NBF: num = &j->nbf; break;
            case KX_IAT: num = &j->iat; break;
            case KX_AUD:
                if (c.p < c.e && *c.p == '"') {
                    if (!jstr_env(&c, &s, &len, &esc) || !str_out(a, s, len, esc, &j->aud[0])) return bad_json;
                    j->naud = 1;
                } else if (c.p < c.e && *c.p == '[') {
                    c.p++;
                    jws(&c);
                    if (c.p < c.e && *c.p == ']') {
                        c.p++;
                        break;
                    }
                    for (;;) {
                        jws(&c);
                        if (c.p < c.e && *c.p == '"' && j->naud < CJE_MAX_AUD) {
                            if (!jstr_env(&c, &s, &len, &esc) || !str_out(a, s, len, esc, &j->aud[j->naud++]))
                                return bad_json;
                        } else {
                            if (!jskip_env(&c, 2)) return bad_json;
                            if (!st) st = CJE_PAYLOAD_CLAIM; /* not a string (or too many audiences) */
                        }
                        jws(&c);
                        if (c.p >= c.e) return bad_json;
                        if (*c.p == ',') {
                            c.p++;
                            continue;
                        }
                        if (*c.p++ != ']') return bad_json;
                        break;
                    }
                } else {
                    if (!jskip_env(&c, 1)) return bad_json;
                    if (!st) st = CJE_PAYLOAD_CLAIM;
                }
                break;
            default:
                if (!jskip_env(&c, 1)) return bad_json;
        }
        if (dst) {
            if (c.p < c.e && *c.p == '"') {
                if (!jstr_env(&c, &s, &len, &esc) || !str_out(a, s, len, esc, dst)) return bad_json;
            } else {
                if (!jskip_env(&c, 1)) return bad_json;
                if (!st) st = key == KX_KID ? CJE_HEADER_KID : CJE_PAYLOAD_CLAIM;
            }
        } else if (num) {
            int r = num_u64(&c, num);
            if (r < 0) return bad_json;
            if (r == 0) {
                if (!jskip_env(&c, 1)) return bad_json;
                if (!st) st = CJE_PAYLOAD_CLAIM;
            }
        }
        jws(&c);
        if (c.p >= c.e) return bad_json;
        if (*c.p == ',') {
            c.p++;
            continue;
        }
        if (*c.p++ != '}') return bad_json;
        break;
    }
end:
    jws(&c);
    if (c.p != c.e) return bad_json;
    if (header && !(seen & 1u << KX_ALG)) return CJE_HEADER_ALG;
    return st;
}

int cje_parse(cje_jwt_t *j, const char *t, int L) {
    j->alg = 0, j->naud = 0, j->iat = j->nbf = j->exp = 0;
    j->kid.n = j->iss.n = j->sub.n = j->jti.n = 0;
    j->kid.p = j->iss.p = j->sub.p = j->jti.p = "";
    j->tok = t, j->sig_len = 0;
    if (L <= 0 || L > CJE_TOKEN_MAX) return CJE_BAD_FORMAT;
    const char *d1 = memchr(t, '.', L);
    if (!d1) return CJE_BAD_FORMAT;
    const char *d2 = memchr(d1 + 1, '.', L - (d1 + 1 - t));
    if (!d2 || memchr(d2 + 1, '.', L - (d2 + 1 - t))) return CJE_BAD_FORMAT;
    int hl = (int)(d1 - t), pl = (int)(d2 - d1 - 1), sl = (int)(t + L - (d2 + 1));
    if (!hl || !pl || !sl) return CJE_BAD_FORMAT;
    j->signing_len = (int)(d2 - t), j->payload_off = hl + 1, j->payload_len = pl;

    uint8_t *hb = j->buf;
    int hn = jwt_b64url_decode(hb, t, hl);
    if (hn < 0) return CJE_HEADER_B64;
    uint8_t *pb = hb + hn + 32;
    int pn = jwt_b64url_decode(pb, d1 + 1, pl);
    if (pn < 0) return CJE_PAYLOAD_B64;
    j->payload = pb, j->payload_n = pn;
    arena_t a = { pb + pn + 32, j->buf + sizeof j->buf };
    int st = parse_obj(j, &a, hb, hn, 1);
    if (st) return st;
    if ((st = parse_obj(j, &a, pb, pn, 0))) return st;
    if (sl > (int)(sizeof j->sig - 64) / 3 * 4 + 3) return CJE_SIG_B64;
    int sn = jwt_b64url_decode(j->sig, d2 + 1, sl);
    if (sn < 0) return CJE_SIG_B64;
    j->sig_len = sn;
    return CJE_OK;
}

int cje_check_time(const cje_jwt_t *j, uint64_t now, uint64_t skew) {
    if (now + skew < j->nbf) return CJE_NOT_YET_VALID;
    if (j->exp && now > j->exp + skew) return CJE_EXPIRED;
    return CJE_OK;
}

/* ---- keys ---------------------------------------------------------------------------------------------------- */

typedef struct {
    int alg;  /* 0 = no alg in the JWK (any of its type) */
    int type; /* CJE_HS256 (oct), CJE_RS256 (RSA), CJE_ES256 (EC) */
    char kid[128];
    int kid_len;
    jwt_key_t hk;
    jwt_pkey_t *pk;
} cje_key_t;

struct cje_jwks {
    int n;
    cje_key_t k[32];
};

int cje_jwks_size(const cje_jwks_t *k) { return k->n; }

void cje_jwks_free(cje_jwks_t *k) {
    if (!k) return;
    for (int i = 0; i < k->n; i++) jwt_pkey_free(k->k[i].pk);
    free(k);
}

/* base64url with or without '=' padding (JWKS producers do both) */
static int b64_any(uint8_t *dst, int cap, const uint8_t *s, int n) {
    while (n && s[n - 1] == '=') n--;
    if (n / 4 * 3 + 3 + 32 > cap) return -1;
    return jwt_b64url_decode(dst, (const char *)s, n);
}

cje_jwks_t *cje_jwks_parse(const char *json, size_t len, const char **err) {
    cje_jwks_t *ks = calloc(1, sizeof *ks);
    jcur_t c = { (const uint8_t *)json, (const uint8_t *)json + len };
    const uint8_t *s;
    int n, esc, found = 0;
    *err = "bad JSON";
    if (!ks) return NULL;
    jws(&c);
    if (c.p >= c.e || *c.p++ != '{') goto fail;
    for (;;) {
        jws(&c);
        if (!jstr(&c, &s, &n, &esc)) goto fail;
        int is_keys = n == 4 && !memcmp(s, "keys", 4);
        jws(&c);
        if (c.p >= c.e || *c.p++ != ':') goto fail;
        jws(&c);
        if (!is_keys) {
            if (!jskip(&c, 1)) goto fail;
        } else {
            found = 1;
            if (c.p >= c.e || *c.p++ != '[') goto fail;
            jws(&c);
            if (c.p < c.e && *c.p == ']') {
                c.p++;
                goto next;
            }
            for (;;) { /* one JWK */
                jws(&c);
                if (c.p >= c.e || *c.p++ != '{') goto fail;
                if (ks->n == (int)(sizeof ks->k / sizeof *ks->k)) {
                    *err = "too many keys";
                    goto fail;
                }
                cje_key_t *k = &ks->k[ks->n];
                static uint8_t f[8][1100]; /* kty alg kid n e x y k (only in config parsing, main thread) */
                int fl[8] = { -1, -1, -1, -1, -1, -1, -1, -1 };
                static const char *names[8] = { "kty", "alg", "kid", "n", "e", "x", "y", "k" };
                for (;;) {
                    jws(&c);
                    if (!jstr(&c, &s, &n, &esc)) goto fail;
                    int fi = -1;
                    for (int q = 0; q < 8; q++)
                        if ((int)strlen(names[q]) == n && !memcmp(s, names[q], n)) fi = q;
                    jws(&c);
                    if (c.p >= c.e || *c.p++ != ':') goto fail;
                    jws(&c);
                    if (fi >= 0 && c.p < c.e && *c.p == '"') {
                        if (!jstr(&c, &s, &n, &esc)) goto fail;
                        fl[fi] = esc ? junescape(f[fi], sizeof f[fi], s, n) : (n <= (int)sizeof f[fi] ? n : -1);
                        if (!esc && fl[fi] >= 0) memcpy(f[fi], s, n);
                        if (fl[fi] < 0) {
                            *err = "JWK field too long";
                            goto fail;
                        }
                    } else if (!jskip(&c, 2)) goto fail;
                    jws(&c);
                    if (c.p >= c.e) goto fail;
                    if (*c.p == ',') {
                        c.p++;
                        continue;
                    }
                    if (*c.p++ != '}') goto fail;
                    break;
                }
                if (fl[2] >= 0) {
                    if (fl[2] >= (int)sizeof k->kid) {
                        *err = "kid too long";
                        goto fail;
                    }
                    memcpy(k->kid, f[2], fl[2]), k->kid_len = fl[2];
                }
                k->alg = fl[1] == 5 && !memcmp(f[1], "HS256", 5)   ? CJE_HS256
                         : fl[1] == 5 && !memcmp(f[1], "RS256", 5) ? CJE_RS256
                         : fl[1] == 5 && !memcmp(f[1], "ES256", 5) ? CJE_ES256
                         : fl[1] < 0                               ? 0
                                                                   : -1;
                uint8_t b1[1100], b2[1100];
                int l1, l2;
                if (fl[0] == 3 && !memcmp(f[0], "oct", 3) && fl[7] >= 0) {
                    k->type = CJE_HS256;
                    if ((l1 = b64_any(b1, sizeof b1, f[7], fl[7])) < 0) {
                        *err = "bad oct k";
                        goto fail;
                    }
                    jwt_key_init(&k->hk, b1, l1);
                } else if (fl[0] == 3 && !memcmp(f[0], "RSA", 3) && fl[3] >= 0 && fl[4] >= 0) {
                    k->type = CJE_RS256;
                    if ((l1 = b64_any(b1, sizeof b1, f[3], fl[3])) < 0 ||
                        (l2 = b64_any(b2, sizeof b2, f[4], fl[4])) < 0 || !(k->pk = jwt_pkey_rs256(b1, l1, b2, l2))) {
                        *err = "bad RSA key";
                        goto fail;
                    }
                } else if (fl[0] == 2 && !memcmp(f[0], "EC", 2) && fl[5] >= 0 && fl[6] >= 0) {
                    k->type = CJE_ES256;
                    if (b64_any(b1, sizeof b1, f[5], fl[5]) != 32 || b64_any(b2, sizeof b2, f[6], fl[6]) != 32 ||
                        !(k->pk = jwt_pkey_es256(b1, b2))) {
                        *err = "bad EC key (P-256 only)";
                        goto fail;
                    }
                } else {
                    k->type = 0; /* a key type we don't verify with (Envoy would also take RS384, EdDSA, ...) */
                }
                if (k->type && k->alg >= 0) ks->n++;
                else jwt_pkey_free(k->pk), memset(k, 0, sizeof *k);
                jws(&c);
                if (c.p >= c.e) goto fail;
                if (*c.p == ',') {
                    c.p++;
                    continue;
                }
                if (*c.p++ != ']') goto fail;
                break;
            }
        }
    next:
        jws(&c);
        if (c.p >= c.e) goto fail;
        if (*c.p == ',') {
            c.p++;
            continue;
        }
        if (*c.p++ != '}') goto fail;
        break;
    }
    if (!found || !ks->n) {
        *err = "no usable keys";
        goto fail;
    }
    *err = NULL;
    return ks;
fail:
    cje_jwks_free(ks);
    return NULL;
}

/* ---- signatures ---------------------------------------------------------------------------------------------- */

static int hs256_ok(const jwt_key_t *k, const uint8_t *msg, int len, const uint8_t *sig, int slen) {
    if (slen != 32) return 0;
    uint32_t mac[1][8], diff = 0;
    JWT_LOAD_FN(hmac_impl)(k, 1, &msg, &len, mac);
    for (int w = 0; w < 8; w++) diff |= mac[0][w] ^ be32(sig + 4 * w);
    return !diff;
}

void cje_raw_verify(const cje_jwks_t *ks, int ki, int n, const uint8_t *const *msg, const int *len,
                    const uint8_t *const *sig, const int *slen, uint8_t *ok) {
    const cje_key_t *k = &ks->k[ki];
    if (k->type == CJE_HS256) {
        enum { CH = 64 };
        for (int b = 0; b < n; b += CH) {
            int m = n - b < CH ? n - b : CH;
            uint32_t mac[CH][8];
            JWT_LOAD_FN(hmac_impl)(&k->hk, m, msg + b, len + b, mac);
            for (int i = 0; i < m; i++) {
                uint32_t diff = slen[b + i] != 32;
                for (int w = 0; w < 8 && !diff; w++) diff |= mac[i][w] ^ be32(sig[b + i] + 4 * w);
                ok[b + i] = !diff;
            }
        }
    } else {
        jwt_pk_verify_raw(k->pk, n, msg, len, sig, slen, ok);
    }
}

int cje_verify_sig(const cje_jwks_t *ks, const cje_jwt_t *j) {
    int matched = 0;
    const uint8_t *msg = (const uint8_t *)j->tok;
    for (int i = 0; i < ks->n; i++) {
        const cje_key_t *k = &ks->k[i];
        if (j->kid.n && k->kid_len && (j->kid.n != k->kid_len || memcmp(j->kid.p, k->kid, k->kid_len))) continue;
        if (k->alg && k->alg != j->alg) continue;
        if (k->type != j->alg) continue; /* Envoy: the key type must fit the alg family */
        matched = 1;
        int ok;
        if (k->type == CJE_HS256) {
            ok = hs256_ok(&k->hk, msg, j->signing_len, j->sig, j->sig_len);
        } else {
            uint8_t r = 0;
            const uint8_t *sp = j->sig;
            int sl = j->sig_len;
            jwt_pk_verify_raw(k->pk, 1, &msg, &j->signing_len, &sp, &sl, &r);
            ok = r;
        }
        if (ok) return CJE_OK;
    }
    return matched ? CJE_VERIFY_FAIL : CJE_KID_ALG_MISMATCH;
}

/* ---- audiences (Envoy's CheckAudience: scheme and one trailing slash ignored) ------------------------------- */

static void aud_norm(const char **p, int *n) {
    if (*n >= 8 && !memcmp(*p, "https://", 8)) *p += 8, *n -= 8;
    else if (*n >= 7 && !memcmp(*p, "http://", 7)) *p += 7, *n -= 7;
    if (*n && (*p)[*n - 1] == '/') (*n)--;
}

int cje_aud_allowed(const cje_jwt_t *j, const cje_str_t *allowed, int nallowed) {
    if (!nallowed) return 1;
    for (int i = 0; i < j->naud; i++) {
        const char *p = j->aud[i].p;
        int n = j->aud[i].n;
        aud_norm(&p, &n);
        for (int a = 0; a < nallowed; a++) {
            const char *q = allowed[a].p;
            int m = allowed[a].n;
            aud_norm(&q, &m);
            if (m == n && !memcmp(p, q, n)) return 1;
        }
    }
    return 0;
}
