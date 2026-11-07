/* bench_codspeed.cpp — CodSpeed benchmarks of the public API (Google Benchmark).
 * HS256 tokens are minted at start-up with the library's own scalar HMAC (no OpenSSL, no Python); the RS256 / ES256 /
 * EdDSA keys and tokens come from pk_fixtures.h (bench/codspeed/gen_fixtures.py).  Every benchmark checks its
 * result once before timing, so a broken token set fails loudly instead of benchmarking the reject path. */
#include <benchmark/benchmark.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "jwt.h"
#include "pk_fixtures.h"

static const char SECRET[] = "cursed-jwt-test-secret";
static const int64_t NOW = 1850000000; /* inside every fixture's [iat, exp) */
static const int MAXB = 64;

static std::string b64url(const uint8_t *p, size_t n) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string s;
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8 | p[i + 2];
        s += T[v >> 18], s += T[(v >> 12) & 63], s += T[(v >> 6) & 63], s += T[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)p[i] << 16;
        s += T[v >> 18], s += T[(v >> 12) & 63];
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8;
        s += T[v >> 18], s += T[(v >> 12) & 63], s += T[(v >> 6) & 63];
    }
    return s;
}
static std::string b64url(const std::string &s) { return b64url((const uint8_t *)s.data(), s.size()); }

static void die(const char *what) {
    std::fprintf(stderr, "bench_codspeed: %s\n", what);
    std::exit(1);
}

/* A set of tokens laid out as jwt_verify_batch wants them. */
struct TokenSet {
    std::vector<std::string> s;
    std::vector<const char *> tok;
    std::vector<int> len;
    void finish() {
        for (auto &t : s) tok.push_back(t.c_str()), len.push_back((int)t.size());
    }
};

/* HS256 tokens shaped like tests/gen_tokens.py.  shaped = the key order most minting libraries emit (jwt.c's
 * shape-matched fast path); otherwise the claims are reordered so every token goes through the strict parser. */
static TokenSet make_hs256(const jwt_key_t &key, int n, bool shaped) {
    static const char *ADJ[] = { "golden",  "silver", "swift", "quiet", "amber",
                                 "crimson", "lunar",  "rapid", "misty", "brave" };
    static const char *NOUN[] = { "ember",  "comet",  "nebula", "harbor", "falcon",
                                  "meadow", "quartz", "willow", "tundra", "orbit" };
    const std::string head = b64url(std::string("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
    TokenSet t;
    for (int i = 1; i <= n; i++) {
        std::string name = std::string(ADJ[i % 10]) + "_" + NOUN[(i / 10) % 10] + "_" + std::to_string(i);
        std::string sub = "\"sub\":\"" + std::to_string(i) + "\"", user = "\"username\":\"" + name + "\"";
        std::string pl = shaped ? "{" + sub + "," + user + ",\"iat\":1792832174,\"exp\":2108192174}"
                                : "{\"exp\":2108192174, \"iat\":1792832174, " + user + ", " + sub + "}";
        std::string msg = head + "." + b64url(pl);
        const uint8_t *m = (const uint8_t *)msg.data();
        int ml = (int)msg.size();
        uint32_t mac[1][8];
        jwt_hmac_scalar(&key, 1, &m, &ml, mac);
        uint8_t sig[32];
        for (int j = 0; j < 8; j++)
            for (int b = 0; b < 4; b++) sig[4 * j + b] = (uint8_t)(mac[0][j] >> (24 - 8 * b));
        t.s.push_back(msg + "." + b64url(sig, 32));
    }
    t.finish();
    return t;
}

struct Hs256 {
    jwt_key_t key;
    TokenSet shaped, strict, forged;
    Hs256() {
        jwt_key_init(&key, SECRET, sizeof SECRET - 1);
        shaped = make_hs256(key, MAXB, true);
        strict = make_hs256(key, MAXB, false);
        forged = make_hs256(key, MAXB, true);
        forged.tok.clear(), forged.len.clear();
        for (auto &s : forged.s) s[s.size() - 2] = s[s.size() - 2] == 'A' ? 'B' : 'A'; /* flip a signature bit */
        forged.finish();
    }
};
static const Hs256 &hs() {
    static Hs256 h;
    return h;
}

static void expect(const jwt_result_t *out, int n, int status) {
    for (int i = 0; i < n; i++)
        if (out[i].status != status) die("unexpected verification status");
}

typedef void verify_fn(const jwt_key_t *, int, const char *const *, const int *, int64_t, jwt_result_t *);

static void run_verify(benchmark::State &state, verify_fn *fn, const TokenSet &t, int status) {
    const int n = (int)state.range(0);
    static jwt_result_t out[MAXB];
    fn(&hs().key, n, t.tok.data(), t.len.data(), NOW, out);
    expect(out, n, status);
    for (auto _ : state) {
        fn(&hs().key, n, t.tok.data(), t.len.data(), NOW, out);
        benchmark::DoNotOptimize(out);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations() * n);
}

/* ---- HS256 full verify (signature, base64url, JSON, claims) ---- */
void BM_HS256_Verify(benchmark::State &state) { run_verify(state, jwt_verify_batch, hs().shaped, JWT_OK); }
BENCHMARK(BM_HS256_Verify)->Arg(1)->Arg(3)->Arg(8)->Arg(64);

void BM_HS256_VerifyStrictJson(benchmark::State &state) { run_verify(state, jwt_verify_batch, hs().strict, JWT_OK); }
BENCHMARK(BM_HS256_VerifyStrictJson)->Arg(1)->Arg(8);

void BM_HS256_VerifyForged(benchmark::State &state) { run_verify(state, jwt_verify_batch, hs().forged, JWT_INVALID); }
BENCHMARK(BM_HS256_VerifyForged)->Arg(8);

void BM_HS256_VerifyScalar(benchmark::State &state) { run_verify(state, jwt_verify_batch_scalar, hs().shaped, JWT_OK); }
BENCHMARK(BM_HS256_VerifyScalar)->Arg(1)->Arg(8);

void BM_HS256_KeyInit(benchmark::State &state) {
    std::string secret((size_t)state.range(0), 'k'); /* > 64 bytes is hashed first (RFC 2104) */
    jwt_key_t k;
    for (auto _ : state) {
        jwt_key_init(&k, secret.data(), secret.size());
        benchmark::DoNotOptimize(k);
    }
}
BENCHMARK(BM_HS256_KeyInit)->Arg(32)->Arg(256);

/* ---- primitives: raw HMAC-SHA256, plain SHA-256, base64url ---- */
void BM_HmacScalar(benchmark::State &state) {
    const int n = (int)state.range(0);
    const TokenSet &t = hs().shaped;
    std::vector<const uint8_t *> m;
    for (int i = 0; i < n; i++) m.push_back((const uint8_t *)t.tok[i]);
    std::vector<int> l(t.len.begin(), t.len.begin() + n);
    std::vector<uint32_t> mac(8 * (size_t)n);
    for (auto _ : state) {
        jwt_hmac_scalar(&hs().key, n, m.data(), l.data(), reinterpret_cast<uint32_t(*)[8]>(mac.data()));
        benchmark::DoNotOptimize(mac.data());
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations() * n);
}
BENCHMARK(BM_HmacScalar)->Arg(1)->Arg(8);

void BM_Sha256Batch(benchmark::State &state) {
    const int n = (int)state.range(0);
    const TokenSet &t = hs().shaped;
    std::vector<const uint8_t *> m;
    for (int i = 0; i < n; i++) m.push_back((const uint8_t *)t.tok[i]);
    std::vector<int> l(t.len.begin(), t.len.begin() + n);
    std::vector<uint32_t> dig(8 * (size_t)n);
    for (auto _ : state) {
        jwt_sha256_batch(n, m.data(), l.data(), reinterpret_cast<uint32_t(*)[8]>(dig.data()));
        benchmark::DoNotOptimize(dig.data());
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations() * n);
}
BENCHMARK(BM_Sha256Batch)->Arg(1)->Arg(8);

static void run_b64(benchmark::State &state, int (*Decode)(uint8_t *, const char *, int)) {
    std::vector<uint8_t> raw((size_t)state.range(0));
    for (size_t i = 0; i < raw.size(); i++) raw[i] = (uint8_t)(i * 131 + 7);
    const std::string src = b64url(raw.data(), raw.size());
    std::vector<uint8_t> dst(raw.size() + 64);
    if (Decode(dst.data(), src.data(), (int)src.size()) != (int)raw.size() ||
        std::memcmp(dst.data(), raw.data(), raw.size()) != 0)
        die("base64url round trip failed");
    for (auto _ : state) {
        benchmark::DoNotOptimize(Decode(dst.data(), src.data(), (int)src.size()));
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(state.iterations() * (int64_t)src.size());
}
void BM_B64urlDecode(benchmark::State &state) { run_b64(state, jwt_b64url_decode); }
BENCHMARK(BM_B64urlDecode)->Arg(96)->Arg(4096);
void BM_B64urlDecodeScalar(benchmark::State &state) { run_b64(state, jwt_b64url_decode_scalar); }
BENCHMARK(BM_B64urlDecodeScalar)->Arg(96)->Arg(4096);

/* ---- RS256 / ES256 / EdDSA ---- */
static std::vector<uint8_t> unhex(const char *h) {
    std::vector<uint8_t> v(std::strlen(h) / 2);
    for (size_t i = 0; i < v.size(); i++) v[i] = (uint8_t)std::strtoul(std::string(h + 2 * i, 2).c_str(), nullptr, 16);
    return v;
}

static jwt_pkey_t *make_es256() {
    auto x = unhex(es256_k1), y = unhex(es256_k2);
    return jwt_pkey_es256(x.data(), y.data());
}
static jwt_pkey_t *make_rs256() {
    auto n = unhex(rs256_2048_k1), e = unhex(rs256_2048_k2);
    return jwt_pkey_rs256(n.data(), n.size(), e.data(), e.size());
}
static jwt_pkey_t *make_eddsa() { return jwt_pkey_ed25519(unhex(eddsa_k1).data()); }

static void run_pk_verify(benchmark::State &state, jwt_pkey_t *(*Make)(), const char *const *Tok) {
    const int n = (int)state.range(0);
    jwt_pkey_t *k = Make();
    if (!k) die("public key rejected");
    TokenSet t;
    for (int i = 0; i < PK_FIXTURE_N; i++) t.s.push_back(Tok[i]);
    t.finish();
    static jwt_result_t out[PK_FIXTURE_N];
    jwt_verify_batch_pk(k, n, t.tok.data(), t.len.data(), NOW, out);
    expect(out, n, JWT_OK);
    for (auto _ : state) {
        jwt_verify_batch_pk(k, n, t.tok.data(), t.len.data(), NOW, out);
        benchmark::DoNotOptimize(out);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations() * n);
    jwt_pkey_free(k);
}
void BM_ES256_Verify(benchmark::State &state) { run_pk_verify(state, make_es256, es256_tok); }
BENCHMARK(BM_ES256_Verify)->Arg(1)->Arg(16);
void BM_RS256_2048_Verify(benchmark::State &state) { run_pk_verify(state, make_rs256, rs256_2048_tok); }
BENCHMARK(BM_RS256_2048_Verify)->Arg(1)->Arg(16);
void BM_EdDSA_Verify(benchmark::State &state) { run_pk_verify(state, make_eddsa, eddsa_tok); }
BENCHMARK(BM_EdDSA_Verify)->Arg(1)->Arg(16);

/* Key setup: ES256 builds its comb tables (528 KB) here, RS256 its Montgomery constants. */
static void run_pk_setup(benchmark::State &state, jwt_pkey_t *(*Make)()) {
    for (auto _ : state) {
        jwt_pkey_t *k = Make();
        if (!k) die("public key rejected");
        benchmark::DoNotOptimize(k);
        jwt_pkey_free(k);
    }
}
void BM_ES256_KeySetup(benchmark::State &state) { run_pk_setup(state, make_es256); }
BENCHMARK(BM_ES256_KeySetup);
void BM_RS256_2048_KeySetup(benchmark::State &state) { run_pk_setup(state, make_rs256); }
BENCHMARK(BM_RS256_2048_KeySetup);
void BM_EdDSA_KeySetup(benchmark::State &state) { run_pk_setup(state, make_eddsa); }
BENCHMARK(BM_EdDSA_KeySetup);

BENCHMARK_MAIN();
