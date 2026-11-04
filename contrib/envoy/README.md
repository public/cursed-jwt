# cjwt_authn: an Envoy JWT filter on cursed-jwt

An Envoy HTTP filter that checks JWTs with cursed-jwt.
- **Stock Envoy:** it loads into an unmodified Envoy release (v1.40 or later) as a
  [dynamic module](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/dynamic_modules_filter),
  so you don't build Envoy.
- **Same answers:** it covers the part of `jwt_authn` most deployments use and gives the same answers for it: the
  same check order, statuses, response bodies, forwarded payload header and token removal.
- **About half the CPU:** on a Xeon it spends 50–60 % less Envoy CPU per request than `jwt_authn`.

**Status: contrib, experimental.**
- It is tested against `jwt_authn` and Envoy's own JWT library (below).
- It has not run in production.
- The dynamic-modules ABI it uses (v0.2.0) can change between Envoy releases.

## Measured

Envoy v1.40.2 (the stock release binary), one worker, `direct_response` 200.  Load comes from a keep-alive generator
cycling through 1,024 distinct tokens with realistic claims (~730 B of payload JSON).  The box is an Intel Xeon
Platinum 8260 with 1 vCPU, shared with the load generator.  CPU is the Envoy process's utime + stime per response.

| alg | `jwt_authn` µs/req | cjwt_authn µs/req | Envoy CPU | requests served |
|---|---:|---:|---:|---:|
| RS256 | 135.7 | **68.0** | −50 % | 1.90× |
| ES256 | 184.6 | **74.5** | −60 % | 2.33× |
| HS256 | 110.9 | **49.4** | −55 % | 2.08× |
| RS256, small claims | 90.0 | **58.8** | −35 % | 1.48× |

For reference:
- **Envoy alone:** 30.9 µs/req with no auth filter, and no token header in the request.
- **Dynamic module that does nothing:** 33.1 µs, so the module route itself costs ~2 µs.
- **When tokens repeat:** `jwt_authn` with its `jwt_cache_config` serves them from a cache at 46.6–48.2 µs.  For
  RS256 and ES256 that beats this filter, which has no cache (yet).

Where the time goes, from the stage-split microbench (`make bench`).  Envoy's JWT library parses the header and payload
into a `google.protobuf.Struct`, which costs ~97 µs on realistic claims; cursed-jwt's parse takes ~1.6 µs.
Signature checks are 1.1× (RS256) to 2.8× (ES256) faster.  The full study, with the scripts for the load runs, is in
the lab: [cursed-scratchpad](https://github.com/public/cursed-scratchpad), `explore/envoy-integration/`.

## Build

The filter is one C file: `cjwt_authn.c` includes `cjwt_envoy.c`, which includes cursed-jwt's `src/jwt.c`.
- It is built with s2n-bignum's verified assembly for P-256 and RSA, fetched and built pinned by the root Makefile.
- It needs Envoy's ABI header, which `./fetch.sh envoy` downloads pinned.
- The result is a self-contained `libcjwt_authn.so` (~450 KB on x86-64).  It exports only the ABI hooks and keeps
  its own crypto symbols hidden, so nothing clashes with Envoy's BoringSSL.

Linux only, because Envoy loads a `.so`.  On macOS, build inside the Dockerfile's image:

```bash
cd contrib/envoy && ./fetch.sh envoy && make
```

```bash
docker build -t cjwt-envoy:build contrib/envoy
```

```bash
docker run --rm -v "$PWD":/r -w /r/contrib/envoy cjwt-envoy:build make
```

## Use

Put `libcjwt_authn.so` in a directory, point `ENVOY_DYNAMIC_MODULES_SEARCH_PATH` at it, and add the filter before the
router.  [example/envoy.yaml](example/envoy.yaml) is a complete config.  The filter config:

| key | default | meaning |
|---|---|---|
| `jwks` | required | the key set: an object `{"keys": [...]}` or a JSON string.  HS256 (`oct`), RS256 (`RSA`), ES256 (`EC`, P-256) |
| `issuer` | not checked | the token's `iss` must equal it |
| `audiences` | not checked | one of the token's `aud` must match, as in `jwt_authn` (scheme and trailing `/` ignored) |
| `header`, `value_prefix` | `authorization`, `Bearer ` | where the token is read from |
| `forward` | `false` | `false` removes the token header after a successful check, as `jwt_authn` does |
| `forward_payload_header` | none | set this header to the token's base64url payload |
| `clock_skew_seconds` | 60 | allowed skew for `exp` and `nbf` |

Key selection follows `jwt_authn`:
- If the token has a `kid`, only keys with that `kid` are tried.
- Otherwise every key whose type fits the token's `alg` is tried.

Responses also follow `jwt_authn`:
- A missing or invalid token gets 401, and a disallowed audience gets 403.
- The body is the same status text, and a `www-authenticate` header is set.

## Tests

| command | what it checks | needs |
|---|---|---|
| `make functional` | `jwt_authn` and cjwt_authn in the stock `envoyproxy/envoy:v1.40.2` image give identical answers | Docker |
| `make test` | differential test against Envoy's own JWT library: header and payload JSON mutated and re-signed, two seeds of 3,000 cases; 0 unexplained disagreements | `make deps` |
| `make asan` | the same differential test (another seed) with the claims layer under ASan + UBSan | `make deps` |
| `make bench` | ns per token per stage (base64url, JSON, claims, signature), Envoy's library vs this one | `make deps` |

`make functional` sends each alg (HS256, RS256, ES256) the same 8 requests:
- valid tokens, with realistic and small claims
- a bad signature
- a wrong audience, a wrong issuer, an expired token
- garbage, and no token

`make test` and `make bench` first check that both libraries give the same verdict and claims on every token.

`make deps` builds abseil, protobuf and BoringSSL at the versions Envoy v1.40.2 pins, fetched by `./fetch.sh deps`
(pinned, SHA-256 checked).  It needs cmake and ninja, both in the Dockerfile.  Tokens are signed with
pyca/cryptography, independently of both libraries.

## Differences from `jwt_authn`

Deliberate, and found by the differential test:
- **JSON that RFC 8259 forbids is rejected**, though protobuf's parser accepts it.  The mutation test found three
  kinds: raw control characters (< 0x20) inside strings, trailing commas (`[1,]`, `{"a":1,}`) and unquoted keys
  (`{alg:"HS256"}`).  No JSON encoder emits them.  The test counts a case as a known difference only when an
  independent strict validator also rejects the JSON.  Any case where this filter accepts a token Envoy rejects is a
  failure.
- **A repeated registered claim** (`iss`, `aud`, `exp`, …) is rejected.  Envoy's `Struct` keeps one of the values.
- **Objects with more than 128 keys** are rejected, because the duplicate-key check is bounded.
- **Messages:** a malformed claim gets a generic message, where Envoy names the claim.  The `www-authenticate` realm
  is fixed.

Not implemented (yet):
- remote JWKS (`remote_jwks`) and refresh
- several providers, and per-route requirement rules
- `claim_to_headers` and `payload_in_metadata`
- a token cache
- tokens in query parameters or cookies
- algorithms other than HS256, RS256 and ES256

## Files

```
cjwt_authn.c       the filter (dynamic-modules ABI hooks, config, per-request checks)
cjwt_envoy.[ch]    jwt_authn's claim profile on top of cursed-jwt: parse, JWKS, signature, time, audience
fetch.sh           pinned fetch: Envoy's ABI header and JWT library, and the deps Envoy pins (into third_party/)
build-deps.sh      builds those deps (only for make test / make bench)
Dockerfile         Ubuntu 24.04 + clang 18, cmake, ninja, python3-cryptography, curl
example/           a complete Envoy config using the filter
test/              gen_tokens.py, make_configs.py, functional.sh, diff.cpp
bench/             bench.cpp, and the one-line shim that lets Envoy's JWT library build outside Envoy
```

Envoy's files are Apache-2.0 and are fetched, not committed.
