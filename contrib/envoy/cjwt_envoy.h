/* cjwt_envoy.h: cursed-jwt with Envoy jwt_authn's claim profile.
 *
 * cursed-jwt itself is built around one fixed claim set (sub as a user id, username).  Envoy's JwtVerify::Jwt reads
 * a different, generic set: header alg + kid, payload iss / sub / jti (strings), aud (string or list of strings),
 * iat / nbf / exp (non-negative numbers, truncated to uint64), and accepts any other claims as long as the JSON is
 * valid.  This layer gives that profile on top of cursed-jwt's base64url, strict RFC 8259 JSON, HMAC dispatch and
 * RS256 / ES256 kernels.  Differences from Envoy are listed in README.md ("Differences from jwt_authn").
 *
 * Thread-safe: no global state beyond cursed-jwt's resolved engines; a key set is read-only once built. */
#ifndef CJWT_ENVOY_H
#define CJWT_ENVOY_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum { CJE_ALG_NONE, CJE_HS256, CJE_RS256, CJE_ES256 };

/* Status codes, a subset of Envoy's JwtVerify::Status with the same meanings. */
enum {
    CJE_OK = 0,
    CJE_BAD_FORMAT,       /* JwtBadFormat: not 3 non-empty dot-separated segments, too long */
    CJE_HEADER_B64,       /* JwtHeaderParseErrorBadBase64 */
    CJE_HEADER_JSON,      /* JwtHeaderParseErrorBadJson */
    CJE_HEADER_ALG,       /* JwtHeaderBadAlg / JwtHeaderNotImplementedAlg (we implement HS256, RS256, ES256) */
    CJE_HEADER_KID,       /* JwtHeaderBadKid */
    CJE_PAYLOAD_B64,      /* JwtPayloadParseErrorBadBase64 */
    CJE_PAYLOAD_JSON,     /* JwtPayloadParseErrorBadJson */
    CJE_PAYLOAD_CLAIM,    /* iss/sub/jti not a string, aud not string(s), iat/nbf/exp not a number or out of range */
    CJE_SIG_B64,          /* JwtSignatureParseErrorBadBase64 */
    CJE_KID_ALG_MISMATCH, /* JwksKidAlgMismatch: no key with this kid and alg */
    CJE_VERIFY_FAIL,      /* JwtVerificationFail */
    CJE_NOT_YET_VALID,    /* JwtNotYetValid */
    CJE_EXPIRED,          /* JwtExpired */
    CJE_AUDIENCE,         /* JwtAudienceNotAllowed */
    CJE_ISSUER,           /* JwtUnknownIssuer */
};
const char *cje_status_str(int st);

#define CJE_TOKEN_MAX 8192
#define CJE_MAX_AUD   16

typedef struct {
    const char *p;
    int n;
} cje_str_t; /* points into cje_jwt_t.buf (unescaped) */

typedef struct {
    int alg;
    cje_str_t kid, iss, sub, jti;
    cje_str_t aud[CJE_MAX_AUD];
    int naud;
    uint64_t iat, nbf, exp; /* 0 when absent, like Envoy */
    /* spans of the original token: the JWS signing input and the base64url payload (for forward_payload_header) */
    const char *tok;
    int signing_len, payload_off, payload_len;
    int sig_len;
    uint8_t sig[512 + 64];
    /* decoded header and payload, then unescaped strings; base64 needs 32 bytes of slack */
    uint8_t *payload;
    int payload_n;
    uint8_t buf[CJE_TOKEN_MAX * 3 / 4 + CJE_TOKEN_MAX + 128];
} cje_jwt_t;

/* Split, base64url-decode and JSON-parse one token (no signature check).  Envoy: Jwt::parseFromString. */
int cje_parse(cje_jwt_t *j, const char *tok, int len);

/* A JWKS: HS256 secrets ("oct"), RSA-2048..4096 ("RSA", RS256) and P-256 ("EC", ES256) keys, each with an
 * optional kid and alg. */
typedef struct cje_jwks cje_jwks_t;
/* From JWKS JSON ({"keys":[...]}).  NULL on a parse error; *err says why. */
cje_jwks_t *cje_jwks_parse(const char *json, size_t n, const char **err);
void cje_jwks_free(cje_jwks_t *k);
int cje_jwks_size(const cje_jwks_t *k);

/* Signature check of a parsed token against the key set: kid / alg selection as Envoy's verifyJwtWithoutTimeChecking
 * (a key is tried when kids are equal or either is empty, and the key's alg is empty or equal). */
int cje_verify_sig(const cje_jwks_t *k, const cje_jwt_t *j);

/* nbf / exp against now (seconds) with clock skew, like Jwt::verifyTimeConstraint. */
int cje_check_time(const cje_jwt_t *j, uint64_t now, uint64_t skew);

/* 1 iff some token audience equals some allowed one (scheme and trailing '/' ignored, like CheckAudience);
 * 1 when nallowed == 0. */
int cje_aud_allowed(const cje_jwt_t *j, const cje_str_t *allowed, int nallowed);

/* Raw signature check of n messages with one key (for the crypto-only benchmark rows).  ok[i] = 1 iff valid. */
void cje_raw_verify(const cje_jwks_t *k, int key_index, int n, const uint8_t *const *msg, const int *len,
                    const uint8_t *const *sig, const int *slen, uint8_t *ok);

#ifdef __cplusplus
}
#endif
#endif
