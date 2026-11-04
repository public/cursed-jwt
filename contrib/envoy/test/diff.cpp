// diff.cpp: differential test of the claims layer (cjwt_envoy.c) against Envoy's JWT library on mutated tokens.
//
//   diff TOKDIR [N] [SEED]
//
// Takes the realistic HS256 tokens, mutates the header or payload JSON (whitespace, escapes, types, duplicates,
// nesting, truncation, numbers, unicode, random bytes), re-encodes and re-signs it with BoringSSL's HMAC under the
// JWKS oct key, and requires both libraries to give the same verdict and, on success, the same alg / kid / iss /
// sub / jti / aud / iat / nbf / exp.  Known, deliberate differences are counted separately (see README.md, "Differences from jwt_authn").
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "openssl/hmac.h"
#include "source/common/jwt/jwks.h"
#include "source/common/jwt/jwt.h"
#include "source/common/jwt/verify.h"

#include "cjwt_envoy.h"

using namespace Envoy;

static std::string b64(const std::string &s) { return absl::WebSafeBase64Escape(s); }

static std::string unb64(const std::string &s) {
    std::string o;
    absl::WebSafeBase64Unescape(s, &o);
    return o;
}

// A strict RFC 8259 validator (syntax and UTF-8 only), independent of both libraries: a case where Envoy accepts
// and we reject is a known difference only if this rejects the JSON too.
static bool rfc_ws(const std::string &s, size_t &i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++;
    return true;
}
static bool rfc_str(const std::string &s, size_t &i) {
    if (i >= s.size() || s[i++] != '"') return false;
    while (i < s.size()) {
        unsigned char c = s[i++];
        if (c == '"') return true;
        if (c < 0x20) return false;
        if (c == '\\') {
            if (i >= s.size()) return false;
            char e = s[i++];
            if (e == 'u') {
                for (int k = 0; k < 4; k++, i++)
                    if (i >= s.size() || !isxdigit((unsigned char)s[i])) return false;
            } else if (!strchr("\"\\/bfnrt", e) || !e) {
                return false;
            }
        } else if (c >= 0x80) { // UTF-8: no overlongs, no surrogates, at most U+10FFFF
            int n = c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc2 ? 1 : -1;
            if (n < 0 || c > 0xf4 || i + n > s.size()) return false;
            unsigned char c1 = s[i];
            if ((c == 0xe0 && c1 < 0xa0) || (c == 0xed && c1 > 0x9f) || (c == 0xf0 && c1 < 0x90) ||
                (c == 0xf4 && c1 > 0x8f))
                return false;
            for (int k = 0; k < n; k++)
                if (((unsigned char)s[i++] & 0xc0) != 0x80) return false;
        }
    }
    return false;
}
static bool rfc_val(const std::string &s, size_t &i, int depth);
static bool rfc_num(const std::string &s, size_t &i) {
    size_t st = i;
    if (i < s.size() && s[i] == '-') i++;
    if (i < s.size() && s[i] == '0') i++;
    else if (i < s.size() && s[i] >= '1' && s[i] <= '9')
        while (i < s.size() && isdigit((unsigned char)s[i])) i++;
    else return false;
    if (i < s.size() && s[i] == '.') {
        if (++i >= s.size() || !isdigit((unsigned char)s[i])) return false;
        while (i < s.size() && isdigit((unsigned char)s[i])) i++;
    }
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        if (++i < s.size() && (s[i] == '+' || s[i] == '-')) i++;
        if (i >= s.size() || !isdigit((unsigned char)s[i])) return false;
        while (i < s.size() && isdigit((unsigned char)s[i])) i++;
    }
    return i > st;
}
static bool rfc_val(const std::string &s, size_t &i, int depth) {
    if (depth > 200 || !rfc_ws(s, i) || i >= s.size()) return false;
    char c = s[i];
    if (c == '{' || c == '[') {
        char close = c == '{' ? '}' : ']';
        i++;
        rfc_ws(s, i);
        if (i < s.size() && s[i] == close) return ++i, true;
        for (;;) {
            if (c == '{') {
                rfc_ws(s, i);
                if (!rfc_str(s, i) || !rfc_ws(s, i) || i >= s.size() || s[i++] != ':') return false;
            }
            if (!rfc_val(s, i, depth + 1)) return false;
            rfc_ws(s, i);
            if (i >= s.size()) return false;
            if (s[i] == close) return ++i, true;
            if (s[i++] != ',') return false;
        }
    }
    if (c == '"') return rfc_str(s, i);
    for (const char *lit : { "true", "false", "null" }) {
        size_t n = strlen(lit);
        if (s.compare(i, n, lit) == 0) return i += n, true;
    }
    return rfc_num(s, i);
}
static bool rfc8259(const std::string &s) {
    size_t i = 0;
    return rfc_val(s, i, 0) && rfc_ws(s, i) && i == s.size();
}

int main(int argc, char **argv) {
    std::string dir = argv[1];
    int N = argc > 2 ? atoi(argv[2]) : 2000;
    std::mt19937_64 rng(argc > 3 ? atoll(argv[3]) : 1);
    std::ifstream jf(dir + "/jwks.json");
    std::stringstream ss;
    ss << jf.rdbuf();
    const std::string jwks_json = ss.str();
    auto ejwks = JwtVerify::Jwks::createFrom(jwks_json, JwtVerify::Jwks::JWKS);
    const char *err;
    cje_jwks_t *cj = cje_jwks_parse(jwks_json.data(), jwks_json.size(), &err);
    // the oct key
    size_t kp = jwks_json.find("\"k\":\"") + 5;
    std::string secret = unb64(jwks_json.substr(kp, jwks_json.find('"', kp) - kp));

    std::vector<std::string> toks;
    {
        std::ifstream f(dir + "/HS256_realistic.txt");
        for (std::string l; std::getline(f, l);)
            if (!l.empty()) toks.push_back(l);
    }
    // the validator must accept every unmutated header and payload, and reject what RFC 8259 forbids
    for (const std::string &t : toks) {
        size_t d1 = t.find('.'), d2 = t.find('.', d1 + 1);
        if (!rfc8259(unb64(t.substr(0, d1))) || !rfc8259(unb64(t.substr(d1 + 1, d2 - d1 - 1)))) {
            fprintf(stderr, "rfc8259 validator rejects a generated token\n");
            return 2;
        }
    }
    for (const char *bad : { "{\"a\":1,}", "[1,]", "{a:1}", "{\"a\":\"\x01\"}", "01", "1.", "\"\xc0\xaf\"",
                             "\"\xed\xa0\x80\"", "{\"a\":1}x", "\"\\x\"", "nul", "{\"a\" 1}" })
        if (rfc8259(bad)) {
            fprintf(stderr, "rfc8259 validator accepts %s\n", bad);
            return 2;
        }
    for (const char *good : { "{}", "[]", "-0.5e+3", "\"\\u00e9\\ud83d\\ude00\"", "\"\xc3\xa9\xf0\x9f\x98\x80\"",
                              " {\"a\" : [ true , null ] } " })
        if (!rfc8259(good)) {
            fprintf(stderr, "rfc8259 validator rejects %s\n", good);
            return 2;
        }
    auto pick = [&](size_t n) { return (size_t)(rng() % n); };
    static const char *frags[] = { " ",
                                   "\n",
                                   "\t",
                                   ",",
                                   ":",
                                   "{",
                                   "}",
                                   "[",
                                   "]",
                                   "\"",
                                   "\\",
                                   "\\u0041",
                                   "\\ud83d\\ude00",
                                   "\\ud800",
                                   "1e3",
                                   "-1",
                                   "0.5",
                                   "1.0",
                                   "18446744073709551616",
                                   "true",
                                   "null",
                                   "\"x\"",
                                   "\xc3\xa9",
                                   "\xff",
                                   "\xed\xa0\x80",
                                   "\x01",
                                   "00",
                                   "\"aud\":[1]",
                                   "\"exp\":\"1\"",
                                   "\"iss\":\"a\",\"iss\":\"b\"",
                                   "\"\\u0069ss\":\"https://auth.example.com/\"",
                                   "\"sub\":null",
                                   "\"aud\":[]",
                                   "\"nbf\":9e18",
                                   "\"exp\":-0" };
    int agree = 0, disagree = 0, known = 0, accepted = 0;
    cje_jwt_t *c = new cje_jwt_t;
    for (int it = 0; it < N; it++) {
        const std::string &t = toks[pick(toks.size())];
        size_t d1 = t.find('.'), d2 = t.find('.', d1 + 1);
        std::string h = unb64(t.substr(0, d1)), p = unb64(t.substr(d1 + 1, d2 - d1 - 1));
        const std::string h0 = h, p0 = p;
        std::string &tgt = rng() % 5 == 0 ? h : p;
        int kind = (int)(rng() % 4), reps = 1 + (int)(rng() % 3);
        for (int r = 0; r < reps; r++) {
            size_t at = tgt.empty() ? 0 : pick(tgt.size() + 1);
            if (kind == 0) tgt.insert(at, frags[pick(sizeof frags / sizeof *frags)]);             // insert a fragment
            else if (kind == 1 && !tgt.empty()) tgt.erase(at < tgt.size() ? at : 0, 1 + pick(3)); // delete bytes
            else if (kind == 2 && !tgt.empty()) tgt[at < tgt.size() ? at : 0] = (char)(rng() & 0xff); // flip a byte
            else { // a whole claim, valid JSON, after the opening brace
                const char *cl[] = { "\"exp\":1.9e9,",
                                     "\"nbf\":4102444800,",
                                     "\"aud\":\"api.example.com\",",
                                     "\"x\":{\"y\":[[[]]]},",
                                     "\"iss\":\"https://auth.example.com/\",",
                                     "\"iat\":1e400,",
                                     "\"kid\":7,",
                                     "\"alg\":\"none\"," };
                tgt.insert(1, cl[pick(8)]);
            }
        }
        std::string hb = b64(h), pb = b64(p), si = hb + "." + pb;
        unsigned char mac[32];
        unsigned int ml = 32;
        HMAC(EVP_sha256(), secret.data(), secret.size(), (const uint8_t *)si.data(), si.size(), mac, &ml);
        std::string tok = si + "." + b64(std::string((char *)mac, 32));

        JwtVerify::Jwt e;
        auto es = e.parseFromString(tok);
        if (es == JwtVerify::Status::Ok) es = JwtVerify::verifyJwtWithoutTimeChecking(e, *ejwks);
        int cs = cje_parse(c, tok.data(), (int)tok.size());
        if (!cs) cs = cje_verify_sig(cj, c);
        bool eok = es == JwtVerify::Status::Ok, cok = cs == CJE_OK;
        bool same = eok == cok;
        if (same && eok) {
            same = e.iss_ == std::string(c->iss.p, c->iss.n) && e.sub_ == std::string(c->sub.p, c->sub.n) &&
                   e.jti_ == std::string(c->jti.p, c->jti.n) && e.kid_ == std::string(c->kid.p, c->kid.n) &&
                   e.exp_ == c->exp && e.nbf_ == c->nbf && e.iat_ == c->iat && (int)e.audiences_.size() == c->naud;
            for (int a = 0; same && a < c->naud; a++) same = e.audiences_[a] == std::string(c->aud[a].p, c->aud[a].n);
            accepted++;
        }
        if (same) {
            agree++;
            continue;
        }
        // Deliberate differences: we refuse a repeated registered claim (Envoy's Struct keeps one); we implement only
        // HS256/RS256/ES256 algs; protobuf's JSON parser accepts some non-RFC-8259 input.
        bool dup = false;
        for (const char *k :
             { "\"iss\"", "\"sub\"", "\"aud\"", "\"exp\"", "\"nbf\"", "\"iat\"", "\"jti\"", "\"alg\"", "\"kid\"" })
            for (const std::string *s : { &h, &p }) {
                size_t f = s->find(k);
                if (f != std::string::npos && s->find(k, f + 1) != std::string::npos) dup = true;
            }
        // protobuf's JSON parser also accepts input RFC 8259 forbids (raw control characters in strings, trailing
        // commas, unquoted keys, ...); we keep the RFC rules.  Judged by the strict validator above, not by either library.
        bool non_rfc = !rfc8259(h) || !rfc8259(p);
        if (eok && !cok && (dup || non_rfc)) {
            known++;
            continue;
        }
        disagree++;
        if (disagree <= 20) {
            const std::string &orig = &tgt == &h ? h0 : p0; // show where the mutation is
            size_t at = 0;
            while (at < orig.size() && at < tgt.size() && orig[at] == tgt[at]) at++;
            size_t from = at > 24 ? at - 24 : 0;
            std::string shown = (&tgt == &h ? "header @" : "payload @") + std::to_string(at) + ": ..." +
                                absl::CEscape(tgt.substr(from, 60)) + "...";
            fprintf(stderr, "DIFF envoy=%s ours=%s  %s\n", JwtVerify::getStatusString(es).c_str(), cje_status_str(cs),
                    shown.c_str());
        }
    }
    printf(
        "diff: %d cases, %d agree (%d accepted by both), %d known differences (non-RFC 8259 JSON that protobuf accepts, or a repeated claim), %d DISAGREE\n",
        N, agree, accepted, known, disagree);
    delete c;
    cje_jwks_free(cj);
    return disagree ? 1 : 0;
}
