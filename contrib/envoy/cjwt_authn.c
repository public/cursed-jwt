/* cjwt_authn.c: an Envoy HTTP filter (dynamic module, Envoy >= v1.40 ABI) that verifies JWTs with cursed-jwt.
 * The subset of jwt_authn most deployments use: one provider, one header extractor, local JWKS.
 *
 * Loaded at run time by a stock Envoy release build (envoy.filters.http.dynamic_modules), so no Envoy build is
 * needed.  Config (filter_config, a google.protobuf.Struct or a StringValue holding JSON):
 *   {
 *     "issuer": "https://auth.example.com/",          // optional: the token's iss must equal it
 *     "audiences": ["https://api.example.com"],       // optional: like jwt_authn (scheme and trailing / ignored)
 *     "jwks": {"keys": [...]},                         // required: HS256 (oct), RS256 (RSA), ES256 (EC P-256)
 *     "header": "authorization", "value_prefix": "Bearer ",   // the extractor (these are the defaults)
 *     "forward": false,                                // false: remove the token header after success (jwt_authn)
 *     "forward_payload_header": "x-jwt-payload",       // optional: the base64url payload, as jwt_authn does
 *     "clock_skew_seconds": 60
 *   }
 * Responses follow jwt_authn's: the same check order, 401 (403 for a disallowed audience) with its status text as
 * the body and a www-authenticate header.  Not implemented: JWKS fetching, multiple providers / requirement trees, claim
 * to header mapping, payload_in_metadata, the JWT cache, query-parameter and cookie extractors.
 */
#include "cjwt_envoy.c"
#include "source/extensions/dynamic_modules/abi/abi.h"

#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#define EXPORT __attribute__((visibility("default")))

typedef struct {
    cje_jwks_t *jwks;
    char issuer[256];
    int issuer_len; /* -1: not checked */
    cje_str_t aud[CJE_MAX_AUD];
    int naud;
    char audbuf[2048];
    char header[64], prefix[32], payload_header[64];
    int header_len, prefix_len, payload_header_len;
    bool forward, noop;
    uint64_t skew;
} cfg_t;

/* ---- config ---------------------------------------------------------------------------------------------------- */

static int cfg_str(jcur_t *c, char *dst, int cap, int *out_len) {
    const uint8_t *s;
    int n, esc;
    jws(c);
    if (!jstr(c, &s, &n, &esc)) return 0;
    int m = esc ? junescape((uint8_t *)dst, cap - 1, s, n) : (n < cap ? (memcpy(dst, s, n), n) : -1);
    if (m < 0) return 0;
    dst[m] = 0, *out_len = m;
    return 1;
}

static const char *cfg_parse(cfg_t *g, const uint8_t *p, size_t n) {
    jcur_t c = { p, p + n };
    const uint8_t *s;
    int len, esc;
    const char *err = NULL;
    jws(&c);
    if (c.p >= c.e || *c.p++ != '{') return "config is not a JSON object";
    jws(&c);
    if (c.p < c.e && *c.p == '}') return "config needs jwks";
    for (;;) {
        jws(&c);
        if (!jstr(&c, &s, &len, &esc)) return "bad config JSON";
        char key[64];
        if (len >= (int)sizeof key) return "unknown config key";
        memcpy(key, s, len), key[len] = 0;
        jws(&c);
        if (c.p >= c.e || *c.p++ != ':') return "bad config JSON";
        jws(&c);
        if (!strcmp(key, "jwks")) {
            const uint8_t *v = c.p;
            if (c.p < c.e && *c.p == '"') { /* a JSON string holding the JWKS (like local_jwks.inline_string) */
                if (!jstr(&c, &s, &len, &esc)) return "bad jwks";
                uint8_t *tmp = malloc(len + 1);
                int m = esc ? junescape(tmp, len, s, len) : (memcpy(tmp, s, len), len);
                g->jwks = cje_jwks_parse((const char *)tmp, m, &err);
                free(tmp);
            } else {
                if (!jskip(&c, 1)) return "bad jwks";
                g->jwks = cje_jwks_parse((const char *)v, c.p - v, &err);
            }
            if (!g->jwks) return err;
        } else if (!strcmp(key, "issuer")) {
            if (!cfg_str(&c, g->issuer, sizeof g->issuer, &g->issuer_len)) return "bad issuer";
        } else if (!strcmp(key, "header")) {
            if (!cfg_str(&c, g->header, sizeof g->header, &g->header_len)) return "bad header";
            for (int i = 0; i < g->header_len; i++)
                g->header[i] = (char)(g->header[i] | (g->header[i] >= 'A' && g->header[i] <= 'Z' ? 0x20 : 0));
        } else if (!strcmp(key, "value_prefix")) {
            if (!cfg_str(&c, g->prefix, sizeof g->prefix, &g->prefix_len)) return "bad value_prefix";
        } else if (!strcmp(key, "forward_payload_header")) {
            if (!cfg_str(&c, g->payload_header, sizeof g->payload_header, &g->payload_header_len))
                return "bad forward_payload_header";
        } else if (!strcmp(key, "forward")) {
            if (c.e - c.p >= 4 && !memcmp(c.p, "true", 4)) g->forward = true, c.p += 4;
            else if (c.e - c.p >= 5 && !memcmp(c.p, "false", 5)) g->forward = false, c.p += 5;
            else return "forward must be a bool";
        } else if (!strcmp(key, "noop")) { /* benchmark only: skip everything (the cost of the module route itself) */
            if (c.e - c.p >= 4 && !memcmp(c.p, "true", 4)) g->noop = true, c.p += 4;
            else return "noop must be true";
            if (!g->jwks) g->jwks = calloc(1, sizeof *g->jwks);
        } else if (!strcmp(key, "clock_skew_seconds")) {
            uint64_t v;
            if (num_u64(&c, &v) != 1) return "bad clock_skew_seconds";
            g->skew = v;
        } else if (!strcmp(key, "audiences")) {
            if (c.p >= c.e || *c.p++ != '[') return "audiences must be a list";
            int used = 0;
            jws(&c);
            if (c.p < c.e && *c.p == ']') c.p++;
            else
                for (;;) {
                    int l;
                    if (g->naud == CJE_MAX_AUD) return "too many audiences";
                    if (!cfg_str(&c, g->audbuf + used, (int)sizeof g->audbuf - used, &l)) return "bad audience";
                    g->aud[g->naud].p = g->audbuf + used, g->aud[g->naud].n = l, g->naud++, used += l + 1;
                    jws(&c);
                    if (c.p < c.e && *c.p == ',') {
                        c.p++;
                        continue;
                    }
                    if (c.p >= c.e || *c.p++ != ']') return "bad audiences";
                    break;
                }
        } else {
            return "unknown config key";
        }
        jws(&c);
        if (c.p >= c.e) return "bad config JSON";
        if (*c.p == ',') {
            c.p++;
            continue;
        }
        if (*c.p++ != '}') return "bad config JSON";
        break;
    }
    if (!g->jwks) return "config needs jwks";
    return NULL;
}

/* ---- hooks ----------------------------------------------------------------------------------------------------- */

EXPORT envoy_dynamic_module_type_abi_version_module_ptr envoy_dynamic_module_on_program_init(void) {
    return ENVOY_DYNAMIC_MODULES_ABI_VERSION;
}

EXPORT envoy_dynamic_module_type_http_filter_config_module_ptr envoy_dynamic_module_on_http_filter_config_new(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr filter_config_envoy_ptr,
    envoy_dynamic_module_type_envoy_buffer name, envoy_dynamic_module_type_envoy_buffer config) {
    (void)filter_config_envoy_ptr, (void)name;
    cfg_t *g = calloc(1, sizeof *g);
    if (!g) return NULL;
    g->issuer_len = -1, g->skew = 60;
    memcpy(g->header, "authorization", g->header_len = 13);
    memcpy(g->prefix, "Bearer ", g->prefix_len = 7);
    const char *err = cfg_parse(g, (const uint8_t *)config.ptr, config.length);
    if (err) {
        fprintf(stderr, "cjwt_authn: %s\n", err);
        cje_jwks_free(g->jwks), free(g);
        return NULL;
    }
    return g;
}

EXPORT void
envoy_dynamic_module_on_http_filter_config_destroy(envoy_dynamic_module_type_http_filter_config_module_ptr p) {
    cfg_t *g = (cfg_t *)p;
    cje_jwks_free(g->jwks), free(g);
}

/* The filter is stateless: the per-stream module pointer is the config itself (no allocation per request). */
EXPORT envoy_dynamic_module_type_http_filter_module_ptr
envoy_dynamic_module_on_http_filter_new(envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr,
                                        envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr) {
    (void)filter_envoy_ptr;
    return (envoy_dynamic_module_type_http_filter_module_ptr)filter_config_ptr;
}

/* jwt_authn's response bodies (JwtVerify::getStatusString) for our status codes */
static const char *envoy_message(int st) {
    switch (st) {
        case CJE_BAD_FORMAT: return "Jwt is not in the form of Header.Payload.Signature with two dots and 3 sections";
        case CJE_HEADER_B64: return "Jwt header is an invalid Base64url encoded";
        case CJE_HEADER_JSON: return "Jwt header is an invalid JSON";
        case CJE_HEADER_ALG: return "Jwt header [alg] is not supported";
        case CJE_HEADER_KID: return "Jwt header [kid] field is not a string";
        case CJE_PAYLOAD_B64: return "Jwt payload is an invalid Base64url encoded";
        case CJE_PAYLOAD_JSON: return "Jwt payload is an invalid JSON";
        case CJE_PAYLOAD_CLAIM:
            return "Jwt payload [aud] field is not a string or string list"; /* one code for all claims */
        case CJE_SIG_B64: return "Jwt signature is an invalid Base64url encoded";
        case CJE_KID_ALG_MISMATCH: return "Jwks doesn't have key to match kid or alg from Jwt";
        case CJE_NOT_YET_VALID: return "Jwt not yet valid";
        case CJE_EXPIRED: return "Jwt is expired";
        case CJE_AUDIENCE: return "Audiences in Jwt are not allowed";
        case CJE_ISSUER: return "Jwt issuer is not configured";
        default: return "Jwt verification fails";
    }
}

/* -1: the token is missing.  401 with www-authenticate, or 403 for a disallowed audience, like jwt_authn. */
static void reject(envoy_dynamic_module_type_http_filter_envoy_ptr f, int st) {
    static char hk[] = "www-authenticate", hv_missing[] = "Bearer realm=\"http://host/\"",
                hv_bad[] = "Bearer realm=\"http://host/\", error=\"invalid_token\"";
    const char *body = st < 0 ? "Jwt is missing" : envoy_message(st);
    envoy_dynamic_module_type_module_http_header h = { hk, sizeof hk - 1, st < 0 ? hv_missing : hv_bad,
                                                       st < 0 ? sizeof hv_missing - 1 : sizeof hv_bad - 1 };
    static char details[] = "jwt_authn_access_denied";
    envoy_dynamic_module_type_module_buffer b = { (char *)body, strlen(body) }, d = { details, sizeof details - 1 };
    envoy_dynamic_module_callback_http_send_response(f, st == CJE_AUDIENCE ? 403 : 401, &h, 1, b, d);
}

static __thread cje_jwt_t tl_jwt; /* 16 KB, one per worker thread; used only inside one hook call */

EXPORT envoy_dynamic_module_type_on_http_filter_request_headers_status
envoy_dynamic_module_on_http_filter_request_headers(envoy_dynamic_module_type_http_filter_envoy_ptr f,
                                                    envoy_dynamic_module_type_http_filter_module_ptr p,
                                                    bool end_of_stream) {
    (void)end_of_stream;
    const cfg_t *g = (const cfg_t *)p;
    if (g->noop) return envoy_dynamic_module_type_on_http_filter_request_headers_status_Continue;
    envoy_dynamic_module_type_module_buffer key = { (char *)g->header, (size_t)g->header_len };
    envoy_dynamic_module_type_envoy_buffer v = { NULL, 0 };
    if (!envoy_dynamic_module_callback_http_get_header(f, envoy_dynamic_module_type_http_header_type_RequestHeader, key,
                                                       &v, 0, NULL) ||
        !v.ptr || v.length <= (size_t)g->prefix_len || memcmp(v.ptr, g->prefix, g->prefix_len)) {
        reject(f, -1);
        return envoy_dynamic_module_type_on_http_filter_request_headers_status_StopIteration;
    }
    const char *tok = v.ptr + g->prefix_len;
    int tl = (int)(v.length - g->prefix_len);
    cje_jwt_t *j = &tl_jwt;
    int st = cje_parse(j, tok, tl);
    if (!st && g->issuer_len >= 0 && (j->iss.n != g->issuer_len || memcmp(j->iss.p, g->issuer, g->issuer_len)))
        st = CJE_ISSUER;
    /* jwt_authn's order: parse, issuer, time, audience, then the signature */
    if (!st) st = cje_check_time(j, (uint64_t)time(NULL), g->skew);
    if (!st && !cje_aud_allowed(j, g->aud, g->naud)) st = CJE_AUDIENCE;
    if (!st) st = cje_verify_sig(g->jwks, j);
    if (st) {
        reject(f, st);
        return envoy_dynamic_module_type_on_http_filter_request_headers_status_StopIteration;
    }
    if (g->payload_header_len) {
        envoy_dynamic_module_type_module_buffer hk = { (char *)g->payload_header, (size_t)g->payload_header_len },
                                                hv = { (char *)tok + j->payload_off, (size_t)j->payload_len };
        envoy_dynamic_module_callback_http_set_header(f, envoy_dynamic_module_type_http_header_type_RequestHeader, hk,
                                                      hv);
    }
    if (!g->forward) { /* the token's buffer is Envoy's: drop it only after the last use */
        envoy_dynamic_module_type_module_buffer nul = { NULL, 0 };
        envoy_dynamic_module_callback_http_set_header(f, envoy_dynamic_module_type_http_header_type_RequestHeader, key,
                                                      nul);
    }
    return envoy_dynamic_module_type_on_http_filter_request_headers_status_Continue;
}

/* ---- the rest of the required hooks: pass-through ------------------------------------------------------------- */

#define FP envoy_dynamic_module_type_http_filter_envoy_ptr f, envoy_dynamic_module_type_http_filter_module_ptr p
EXPORT envoy_dynamic_module_type_on_http_filter_request_body_status
envoy_dynamic_module_on_http_filter_request_body(FP, bool e) {
    (void)f, (void)p, (void)e;
    return envoy_dynamic_module_type_on_http_filter_request_body_status_Continue;
}
EXPORT envoy_dynamic_module_type_on_http_filter_request_trailers_status
envoy_dynamic_module_on_http_filter_request_trailers(FP) {
    (void)f, (void)p;
    return envoy_dynamic_module_type_on_http_filter_request_trailers_status_Continue;
}
EXPORT envoy_dynamic_module_type_on_http_filter_response_headers_status
envoy_dynamic_module_on_http_filter_response_headers(FP, bool e) {
    (void)f, (void)p, (void)e;
    return envoy_dynamic_module_type_on_http_filter_response_headers_status_Continue;
}
EXPORT envoy_dynamic_module_type_on_http_filter_response_body_status
envoy_dynamic_module_on_http_filter_response_body(FP, bool e) {
    (void)f, (void)p, (void)e;
    return envoy_dynamic_module_type_on_http_filter_response_body_status_Continue;
}
EXPORT envoy_dynamic_module_type_on_http_filter_response_trailers_status
envoy_dynamic_module_on_http_filter_response_trailers(FP) {
    (void)f, (void)p;
    return envoy_dynamic_module_type_on_http_filter_response_trailers_status_Continue;
}
EXPORT void envoy_dynamic_module_on_http_filter_stream_complete(FP) { (void)f, (void)p; }
EXPORT void envoy_dynamic_module_on_http_filter_destroy(envoy_dynamic_module_type_http_filter_module_ptr p) { (void)p; }
EXPORT void envoy_dynamic_module_on_http_filter_http_callout_done(FP, uint64_t id,
                                                                  envoy_dynamic_module_type_http_callout_result r,
                                                                  envoy_dynamic_module_type_envoy_http_header *h,
                                                                  size_t hn, envoy_dynamic_module_type_envoy_buffer *b,
                                                                  size_t bn) {
    (void)f, (void)p, (void)id, (void)r, (void)h, (void)hn, (void)b, (void)bn;
}
EXPORT void envoy_dynamic_module_on_http_filter_http_stream_headers(FP, uint64_t id,
                                                                    envoy_dynamic_module_type_envoy_http_header *h,
                                                                    size_t hn, bool e) {
    (void)f, (void)p, (void)id, (void)h, (void)hn, (void)e;
}
EXPORT void envoy_dynamic_module_on_http_filter_http_stream_data(FP, uint64_t id,
                                                                 const envoy_dynamic_module_type_envoy_buffer *d,
                                                                 size_t dn, bool e) {
    (void)f, (void)p, (void)id, (void)d, (void)dn, (void)e;
}
EXPORT void envoy_dynamic_module_on_http_filter_http_stream_trailers(FP, uint64_t id,
                                                                     envoy_dynamic_module_type_envoy_http_header *t,
                                                                     size_t tn) {
    (void)f, (void)p, (void)id, (void)t, (void)tn;
}
EXPORT void envoy_dynamic_module_on_http_filter_http_stream_complete(FP, uint64_t id) { (void)f, (void)p, (void)id; }
EXPORT void
envoy_dynamic_module_on_http_filter_http_stream_reset(FP, uint64_t id,
                                                      envoy_dynamic_module_type_http_stream_reset_reason r) {
    (void)f, (void)p, (void)id, (void)r;
}
EXPORT void envoy_dynamic_module_on_http_filter_scheduled(FP, uint64_t id) { (void)f, (void)p, (void)id; }
EXPORT void envoy_dynamic_module_on_http_filter_downstream_above_write_buffer_high_watermark(FP) { (void)f, (void)p; }
EXPORT void envoy_dynamic_module_on_http_filter_downstream_below_write_buffer_low_watermark(FP) { (void)f, (void)p; }
