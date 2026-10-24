// jwt-cpp (github.com/Thalhammer/jwt-cpp, picojson traits) doing the same job: decode, verify HS256,
// check exp, read sub + username.  ns/token over all test tokens, best of 5 passes.
#include <jwt-cpp/jwt.h>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    std::ifstream f(argc > 1 ? argv[1] : "tokens.json");
    std::stringstream ss;
    ss << f.rdbuf();
    std::string all = ss.str();
    std::vector<std::string> toks;
    for (size_t p = 0; (p = all.find("\"token\":\"", p)) != std::string::npos;) {
        p += 9;
        size_t e = all.find('"', p);
        toks.push_back(all.substr(p, e - p));
        p = e;
    }
    const char *secret = getenv("JWT_SECRET") ? getenv("JWT_SECRET") : "cursed-jwt-test-secret";
    auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{secret});
    long sink = 0, ok = 0;
    double best = 1e30;
    for (int pass = 0; pass < 5; pass++) {
        ok = 0;
        auto t0 = std::chrono::steady_clock::now();
        for (auto &t : toks) {
            try {
                auto d = jwt::decode(t);
                verifier.verify(d); // signature + exp (if present) + alg
                if (!d.has_expires_at()) continue; // exp is required (as cursed-jwt does)
                long uid = std::stol(d.get_subject());
                std::string name = d.get_payload_claim("username").as_string();
                sink += uid + (long)name.size();
                ok++;
            } catch (const std::exception &) {
            }
        }
        double ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / toks.size();
        if (ns < best) best = ns;
    }
    // a forged token must be rejected
    std::string forged = toks[0];
    forged[forged.size() - 2] = forged[forged.size() - 2] == 'A' ? 'B' : 'A';
    bool rejected = false;
    try { verifier.verify(jwt::decode(forged)); } catch (const std::exception &) { rejected = true; }
    printf("jwt-cpp (picojson, OpenSSL)        %8.1f ns/token   accepted %ld/%zu, forged rejected: %s (sink %ld)\n",
           best, ok, toks.size(), rejected ? "yes" : "NO", sink % 7);
    return 0;
}
