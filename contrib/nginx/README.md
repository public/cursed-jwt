# contrib/nginx: JWT verification for nginx with cursed-jwt

`ngx_http_cursed_jwt_module` is an nginx module that checks `Authorization: Bearer` tokens in the access phase with
cursed-jwt. It handles HS256, RS256 and ES256. On one Xeon core it serves **1.7–3.0×** the requests per second of
[kjdev/nginx-auth-jwt](https://github.com/kjdev/nginx-auth-jwt) (OpenSSL + jansson), and **2.3–4.7×** with batching
(numbers below).

It is a prototype: one key per location and no claims exported to variables (see [Limits](#limits)).

## Build

```sh
cd contrib/nginx
make                     # build/libcursedjwt_nginx.a: the library, -fPIC, fast public-key build (fetches s2n-bignum)
cd /path/to/nginx-1.x
./configure --with-compat --add-dynamic-module=/path/to/cursed-jwt/contrib/nginx
make modules             # objs/ngx_http_cursed_jwt_module.so
```

- `--with-compat` lets the `.so` load into an nginx binary built with the same version and `--with-compat`, such as
  most distribution packages. `--add-module=` builds the module into nginx statically instead.
- The module links libcrypto (`-lcrypto`), which cursed-jwt uses for RSA moduli other than 2048 bits. On macOS (untested)
  add `--with-cc-opt=-I$(brew --prefix openssl@3)/include --with-ld-opt=-L$(brew --prefix openssl@3)/lib`.
- Pass an absolute path to `--add-dynamic-module`. The `config` file finds the library and `include/jwt.h` relative to
  it; set `CURSED_JWT` (a cursed-jwt tree) and `CURSED_JWT_LIB` (the archive) to use others.
- `make SCREEN=1` builds with `-DJWT_RSA_SCREEN`, the opt-in batched RSA screen ([PK.md](../../PK.md)).

## Configuration

```nginx
load_module modules/ngx_http_cursed_jwt_module.so;

location /api/ {
    cursed_jwt          "api";             # realm for WWW-Authenticate; "off" disables (e.g. in a nested location)
    cursed_jwt_key_file conf/api.jwks;     # first key of a JWKS: kty oct -> HS256, RSA -> RS256, EC P-256 -> ES256
    cursed_jwt_batch    16;                # optional: verify up to 16 requests per event-loop round in one call
    proxy_pass http://backend;
}
```

All three directives are valid in `http`, `server` and `location`, and are inherited.

- A valid token lets the request continue. Anything else gets **401** with `WWW-Authenticate: Bearer realm="…"`:
  no header, a header that is not `Bearer`, a bad signature, `exp` passed or missing, `nbf` in the future, malformed
  JSON or base64url, or an `alg` other than the key's.
- **The key fixes the algorithm.** A token whose header `alg` differs is rejected, so there is no algorithm confusion
  and no `none`.
- `error_page 401 …` works as usual, including a redirect to a named location.

### Batch mode

With `cursed_jwt_batch N` (N > 1) the access handler queues the request and returns `NGX_AGAIN` instead of verifying
at once.
- The first request queued in an event-loop round posts an event. nginx runs posted events after it has handled every
  I/O event of that `epoll_wait` / `kevent` round, so the batch holds every request that arrived together.
- The posted handler verifies them in one `jwt_verify_batch` / `jwt_verify_batch_pk` call (up to N per call) and
  resumes each request.
- No timer is involved, so a request never waits for others to arrive. Under light load a batch is one request, and
  the cost is one posted-event hop.
- Requests that are freed while queued, or while their batch-mates resume (client gone, an HTTP/2 connection torn
  down), are dropped through a pool cleanup. So are requests that an internal redirect moves elsewhere.
- More than 1,024 requests in one round: the rest are verified inline.

Batching helps HS256 (multi-buffer HMAC) and ES256 (shared inversions, warm tables) the most. Without `SCREEN=1`,
RS256 gains only from keeping the code and data hot.

## Claim rules, and differences from kjdev/nginx-auth-jwt

Claims follow cursed-jwt's rules ([README](../../README.md)): `exp` required and `> now`, `nbf <= now` when present,
strict RFC 8259 JSON. `iss`, `aud` and `iat` are not checked. The library's `sub` / `username` requirement is not
applied: a token without them passes as long as its signature and times are valid (`JWT_BAD_PAYLOAD` counts as
accepted).

| | kjdev auth_jwt 0.15.0 | cursed_jwt |
|---|---|---|
| keys | JWKS or keyval, many keys, `kid` / `alg` matching, keys from a subrequest, variables | the **first** key of one JWKS file per location; `kid` ignored |
| algorithms | HS/RS/PS/ES/EdDSA families | HS256, RS256 (2048–4096-bit, e < 2^64), ES256 |
| `exp` | required by default (`auth_jwt_validate_exp`), `auth_jwt_leeway` | required, no leeway |
| `nbf` | only with `auth_jwt_require` | checked when present |
| JSON | jansson, duplicate keys rejected | strict RFC 8259 (UTF-8 validated, nesting ≤ 32); duplicate `exp` / `nbf` / `sub` rejected |
| claims → variables, `auth_jwt_require*`, revocation, nested JWT | yes | no |
| token size | header limits | ≤ 8,192 bytes |

## Limits

- One key per location, no `kid` selection, no key rotation without a reload.
- No claim variables (`$jwt_claim_sub` and the like), no `aud` / `iss` checks, no leeway.
- EdDSA is in the library but not wired up here.
- The JWKS reader is minimal: the first key of the file, no escaped characters in its strings (key material never
  has any).
- The parsed key is not freed on a config reload: one small leak per reload.

## Performance

Measured on an Intel Xeon Platinum 8260 VM (Cascade Lake, 1 vCPU, Ubuntu 24.04, kernel 6.8, gcc 13.3,
`-O2 -march=native`) with nginx 1.30.6, one worker.
- Load came from a second VM: 64 keep-alive connections, closed loop, 2 s warm-up, 6 s measured.
- Every request carries a valid token, and the content handler is `empty_gif`.
- The server CPU was saturated in every auth phase (0.92–0.96 CPU-seconds per second), so req/s is the server's
  limit.
- *small* claims are `sub`, `iat` and `exp`; *real* claims are an OIDC-style access token (~730-byte payload).
- *auth µs* is server CPU per request minus that of the same route with no auth (8.5–8.9 µs, 95k req/s).
- `auth_request` is a subrequest to a Go [golang-jwt](https://github.com/golang-jwt/jwt) v5 verifier over a keep-alive
  upstream on the same VM; its CPU counts too.

| alg | claims | cursed_jwt req/s (auth µs) | cursed_jwt_batch 16 | kjdev auth_jwt | auth_request + Go |
|---|---|---|---|---|---|
| HS256 | small | 69,623 (4.0) | **87,770** (1.1) | 32,438 (19.1) | 17,432 (43.1) |
| HS256 | real | 42,313 (12.9) | **69,703** (4.2) | 16,977 (46.4) | 9,392 (90.3) |
| RS256 | small | 28,214 (24.0) | **38,633** (15.0) | 16,661 (46.2) | 8,192 (103.3) |
| RS256 | real | 22,331 (32.2) | **29,874** (21.7) | 10,541 (77.5) | 5,727 (152.7) |
| ES256 | small | 22,871 (31.3) | **32,906** (19.1) | 8,075 (105.8) | 5,112 (173.4) |
| ES256 | real | 19,413 (39.7) | **30,180** (22.2) | 6,420 (136.0) | 4,202 (206.9) |

p99 latency fell in the same proportion, because at saturation it is mostly queueing. For example, RS256 real: 6.1 ms
inline, 4.7 ms batched, 13.2 ms kjdev, 25.9 ms `auth_request`.

Where kjdev's time goes:
- OpenSSL 3.0's P-256 verify costs ~82 µs per token on this CPU, against 16–24 µs for cursed-jwt.
- jansson needs ~18 µs to parse a 730-byte claim set, against ~1.4 µs for cursed-jwt's parser.
- The module itself adds ~14 µs per request around the verify.

## Testing

```sh
make test     # = make && ./test.sh
```

`test.sh` downloads nginx 1.30.6 (SHA-256 checked) and builds it with the module. It generates keys and tokens with
Python's `cryptography`, independently of cursed-jwt, then checks:
- HS256, RS256 and ES256 with small and OIDC-style claims;
- each one inline, batched, and batched behind an `error_page` redirect;
- valid → 200; tampered signature, expired, missing token or the wrong algorithm → 401 (403 through the redirect);
- the `WWW-Authenticate` header;
- 400 concurrent valid requests through the batch route.

It needs libcrypto headers, curl, and Python with `cryptography`. CI runs it on Linux.

The batch path has also been run under ASan + UBSan with 64 concurrent connections, clients that reset mid-request,
and `error_page` redirects, with no report from the module (UBSan flags one line in nginx's own `ngx_init_cycle`).
