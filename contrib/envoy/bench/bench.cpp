// bench.cpp: Envoy v1.40.2's JWT library (source/common/jwt, ex google/jwt_verify_lib; what jwt_authn runs) against
// cursed-jwt with Envoy's claim profile (cjwt_envoy.c), one token at a time, split into stages.
//
//   bench TOKDIR [SECONDS_PER_ROW]
//
// Rows, per alg (HS256 / RS256 / ES256) and claim set (small / realistic), ns per token, best of 5 timed passes over
// 64 distinct tokens:
//   b64       base64url decode of header, payload and signature only
//   json      header + payload JSON only (Envoy: JsonStringToMessage into a protobuf Struct; ours: strict RFC 8259
//             scan that extracts the registered claims)
//   parse     the whole parse: split, b64, JSON, claim getters (Envoy: Jwt::parseFromString; ours: cje_parse)
//   verify    signature check with key selection from a 3-key JWKS, including the SHA-256 of the signing input
//             (Envoy: verifyJwtWithoutTimeChecking; ours: cje_verify_sig)
//   total     parse + verify + time check + audience check: what jwt_authn's authenticator does per uncached token
//   raw/bN    ours only: the signature kernel alone at batch N (what batching across streams could buy)
// Before timing, both libraries must accept every good token, reject every bad one, and agree on iss/sub/aud/exp.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "source/common/jwt/check_audience.h"
#include "source/common/jwt/jwks.h"
#include "source/common/jwt/jwt.h"
#include "source/common/jwt/verify.h"
#include "source/common/protobuf/protobuf.h"

#include "cjwt_envoy.h"
#include "jwt.h" // cursed-jwt: jwt_b64url_decode

using namespace Envoy;

static double now_ns() {
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e9 + t.tv_nsec;
}

static std::vector<std::string> lines(const std::string &path) {
    std::ifstream f(path);
    std::vector<std::string> v;
    for (std::string l; std::getline(f, l);)
        if (!l.empty()) v.push_back(l);
    return v;
}

static volatile uint64_t sink;
static double secs = 0.25;

// ns per call of fn(i) over i in [0, n), best of 5 passes of ~secs/5 each
template <class F> static double timeit(int n, F fn) {
    int reps = 1;
    for (;;) { // calibrate
        double t0 = now_ns();
        for (int r = 0; r < reps; r++)
            for (int i = 0; i < n; i++) fn(i);
        double dt = now_ns() - t0;
        if (dt > secs * 1e9 / 20) break;
        reps *= 2;
    }
    double best = 1e30;
    for (int pass = 0; pass < 5; pass++) {
        double t0 = now_ns();
        for (int r = 0; r < reps; r++)
            for (int i = 0; i < n; i++) fn(i);
        double dt = (now_ns() - t0) / (reps * (double)n);
        if (dt < best) best = dt;
    }
    return best;
}

static void row(const char *alg, const char *set, const char *stage, double envoy, double ours) {
    if (envoy > 0) printf("%s\t%s\t%s\t%.0f\t%.0f\t%.2f\n", alg, set, stage, envoy, ours, envoy / ours);
    else printf("%s\t%s\t%s\t-\t%.0f\t-\n", alg, set, stage, ours);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s TOKDIR [SECONDS_PER_ROW]\n", argv[0]);
        return 2;
    }
    std::string dir = argv[1];
    if (argc > 2) secs = atof(argv[2]);
    std::ifstream jf(dir + "/jwks.json");
    std::stringstream ss;
    ss << jf.rdbuf();
    const std::string jwks_json = ss.str();

    auto ejwks = JwtVerify::Jwks::createFrom(jwks_json, JwtVerify::Jwks::JWKS);
    if (ejwks->getStatus() != JwtVerify::Status::Ok) {
        fprintf(stderr, "envoy jwks: %s\n", JwtVerify::getStatusString(ejwks->getStatus()).c_str());
        return 1;
    }
    const char *err;
    cje_jwks_t *cjwks = cje_jwks_parse(jwks_json.data(), jwks_json.size(), &err);
    if (!cjwks) {
        fprintf(stderr, "cjwt jwks: %s\n", err);
        return 1;
    }
    const std::vector<std::string> cfg_aud = { "https://api.example.com" };
    JwtVerify::CheckAudience echeck(cfg_aud);
    const cje_str_t caud[] = { { "https://api.example.com", 23 } };
    const uint64_t now = (uint64_t)time(nullptr);
    int fails = 0;

    printf("alg\tset\tstage\tenvoy_ns\tours_ns\tspeedup\n");
    const char *algs[] = { "HS256", "RS256", "ES256" };
    for (int ai = 0; ai < 3; ai++) {
        const char *alg = algs[ai];
        for (const char *set : { "small", "realistic" }) {
            auto toks = lines(dir + "/" + alg + "_" + set + ".txt");
            const int n = (int)toks.size();
            std::vector<JwtVerify::Jwt> ej(n);
            std::vector<cje_jwt_t> *cj = new std::vector<cje_jwt_t>(n);

            // ---- agreement ----
            for (int i = 0; i < n; i++) {
                auto st = ej[i].parseFromString(toks[i]);
                if (st == JwtVerify::Status::Ok) st = JwtVerify::verifyJwt(ej[i], *ejwks, cfg_aud, now);
                int cs = cje_parse(&(*cj)[i], toks[i].data(), (int)toks[i].size());
                if (!cs) cs = cje_verify_sig(cjwks, &(*cj)[i]);
                if (!cs) cs = cje_check_time(&(*cj)[i], now, 60);
                if (!cs && !cje_aud_allowed(&(*cj)[i], caud, 1)) cs = CJE_AUDIENCE;
                const auto &e = ej[i];
                const auto &c = (*cj)[i];
                bool same = st == JwtVerify::Status::Ok && cs == CJE_OK && e.iss_ == std::string(c.iss.p, c.iss.n) &&
                            e.sub_ == std::string(c.sub.p, c.sub.n) && e.exp_ == c.exp && e.nbf_ == c.nbf &&
                            e.iat_ == c.iat && e.jti_ == std::string(c.jti.p, c.jti.n) &&
                            (int)e.audiences_.size() == c.naud;
                for (int a = 0; same && a < c.naud; a++) same = e.audiences_[a] == std::string(c.aud[a].p, c.aud[a].n);
                if (!same) {
                    fprintf(stderr, "DISAGREE %s %s #%d: envoy %s, ours %s\n", alg, set, i,
                            JwtVerify::getStatusString(st).c_str(), cje_status_str(cs));
                    fails++;
                }
            }
            if (!strcmp(set, "realistic")) {
                auto bad = lines(dir + "/bad_" + alg + ".txt");
                for (size_t i = 0; i < bad.size(); i++) {
                    JwtVerify::Jwt e;
                    auto st = e.parseFromString(bad[i]);
                    if (st == JwtVerify::Status::Ok) st = JwtVerify::verifyJwtWithoutTimeChecking(e, *ejwks);
                    cje_jwt_t *c = new cje_jwt_t;
                    int cs = cje_parse(c, bad[i].data(), (int)bad[i].size());
                    if (!cs) cs = cje_verify_sig(cjwks, c);
                    delete c;
                    if (st == JwtVerify::Status::Ok || cs == CJE_OK) {
                        fprintf(stderr, "ACCEPTED A BAD TOKEN %s #%zu: envoy %s, ours %s\n", alg, i,
                                JwtVerify::getStatusString(st).c_str(), cje_status_str(cs));
                        fails++;
                    }
                }
            }

            // ---- b64 ----
            std::vector<std::string> sh(n), sp(n), sg(n);
            for (int i = 0; i < n; i++) {
                size_t d1 = toks[i].find('.'), d2 = toks[i].find('.', d1 + 1);
                sh[i] = toks[i].substr(0, d1), sp[i] = toks[i].substr(d1 + 1, d2 - d1 - 1),
                sg[i] = toks[i].substr(d2 + 1);
            }
            std::string o1, o2, o3;
            double e_b64 = timeit(n, [&](int i) {
                absl::WebSafeBase64Unescape(sh[i], &o1);
                absl::WebSafeBase64Unescape(sp[i], &o2);
                absl::WebSafeBase64Unescape(sg[i], &o3);
                sink += o1.size() + o2.size() + o3.size();
            });
            static uint8_t buf[3][16384];
            double c_b64 = timeit(n, [&](int i) {
                sink += jwt_b64url_decode(buf[0], sh[i].data(), (int)sh[i].size()) +
                        jwt_b64url_decode(buf[1], sp[i].data(), (int)sp[i].size()) +
                        jwt_b64url_decode(buf[2], sg[i].data(), (int)sg[i].size());
            });
            row(alg, set, "b64", e_b64, c_b64);

            // ---- json ----
            std::vector<std::string> dh(n), dp(n);
            for (int i = 0; i < n; i++) {
                absl::WebSafeBase64Unescape(sh[i], &dh[i]);
                absl::WebSafeBase64Unescape(sp[i], &dp[i]);
            }
            double e_json = timeit(n, [&](int i) {
                Protobuf::Struct h, p;
                Protobuf::util::JsonParseOptions opt;
                sink += Protobuf::util::JsonStringToMessage(dh[i], &h, opt).ok();
                sink += Protobuf::util::JsonStringToMessage(dp[i], &p, opt).ok();
            });
            // ours: the parse minus its b64 (cje_parse is one pass; time it on tokens and subtract the b64 of header and
            // payload, measured the same way)
            cje_jwt_t *tmp = new cje_jwt_t;
            double c_parse = timeit(n, [&](int i) { sink += cje_parse(tmp, toks[i].data(), (int)toks[i].size()); });
            double c_b64hp = timeit(n, [&](int i) {
                sink += jwt_b64url_decode(buf[0], sh[i].data(), (int)sh[i].size()) +
                        jwt_b64url_decode(buf[1], sp[i].data(), (int)sp[i].size());
            });
            double c_b64s = c_b64 - c_b64hp;
            row(alg, set, "json", e_json, c_parse - c_b64 > 1 ? c_parse - c_b64 : 1);

            // ---- parse ----
            double e_parse = timeit(n, [&](int i) {
                JwtVerify::Jwt j;
                sink += (int)j.parseFromString(toks[i]);
            });
            row(alg, set, "parse", e_parse, c_parse);
            (void)c_b64s;

            // ---- verify ----
            double e_ver =
                timeit(n, [&](int i) { sink += (int)JwtVerify::verifyJwtWithoutTimeChecking(ej[i], *ejwks); });
            double c_ver = timeit(n, [&](int i) { sink += cje_verify_sig(cjwks, &(*cj)[i]); });
            row(alg, set, "verify", e_ver, c_ver);

            // ---- total ----
            double e_tot = timeit(n, [&](int i) {
                JwtVerify::Jwt j;
                auto st = j.parseFromString(toks[i]);
                if (st == JwtVerify::Status::Ok) st = JwtVerify::verifyJwtWithoutTimeChecking(j, *ejwks);
                if (st == JwtVerify::Status::Ok) st = j.verifyTimeConstraint(now);
                if (st == JwtVerify::Status::Ok && !echeck.areAudiencesAllowed(j.audiences_))
                    st = JwtVerify::Status::JwtAudienceNotAllowed;
                sink += (int)st;
            });
            double c_tot = timeit(n, [&](int i) {
                int st = cje_parse(tmp, toks[i].data(), (int)toks[i].size());
                if (!st) st = cje_verify_sig(cjwks, tmp);
                if (!st) st = cje_check_time(tmp, now, 60);
                if (!st && !cje_aud_allowed(tmp, caud, 1)) st = CJE_AUDIENCE;
                sink += st;
            });
            row(alg, set, "total", e_tot, c_tot);

            // ---- raw kernel at batch N (ours) ----
            if (!strcmp(set, "realistic")) {
                std::vector<const uint8_t *> m(n), s(n);
                std::vector<int> ml(n), sl(n);
                std::vector<uint8_t> ok(n);
                for (int i = 0; i < n; i++)
                    m[i] = (const uint8_t *)toks[i].data(), ml[i] = (*cj)[i].signing_len, s[i] = (*cj)[i].sig,
                    sl[i] = (*cj)[i].sig_len;
                for (int b : { 1, 8, 16 }) {
                    double t = timeit(n / b,
                                      [&](int i) {
                                          cje_raw_verify(cjwks, ai, b, &m[i * b], &ml[i * b], &s[i * b], &sl[i * b],
                                                         &ok[i * b]);
                                      }) /
                               b;
                    for (int i = 0; i < n; i++) fails += !ok[i];
                    char nm[16];
                    snprintf(nm, sizeof nm, "raw/b%d", b);
                    row(alg, set, nm, 0, t);
                }
            }
            delete tmp;
            delete cj;
        }
    }
    cje_jwks_free(cjwks);
    if (fails) fprintf(stderr, "%d FAILURES\n", fails);
    return fails ? 1 : 0;
}
