// jwt-cpp (github.com/Thalhammer/jwt-cpp, picojson traits) signing: HS256 and EdDSA tokens of the claims set of
// bench/bench_sign.c, built with jwt::create() as its README does.  ns/token, best of 5 passes.
#include <jwt-cpp/jwt.h>
#include <openssl/pem.h>
#include <chrono>
#include <cstdio>
#include <string>

template <class F> static void best(const char *name, F f) {
    double b = 1e18;
    for (int pass = 0; pass < 5; pass++) {
        long n = 0;
        auto t0 = std::chrono::steady_clock::now();
        double el;
        do {
            for (int i = 0; i < 64; i++) f();
            n += 64;
            el = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count();
        } while (el < 2e8);
        if (el / n < b) b = el / n;
    }
    printf("  %-34s b1   %9.1f ns/token\n", name, b);
}

int main() {
    const std::string secret = "bench-secret-0123456789abcdef0123";
    unsigned char seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (unsigned char)(i * 7 + 1);
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed, 32);
    BIO *b1 = BIO_new(BIO_s_mem()), *b2 = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b1, k, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_bio_PUBKEY(b2, k);
    char *p1, *p2;
    long l1 = BIO_get_mem_data(b1, &p1), l2 = BIO_get_mem_data(b2, &p2);
    std::string priv(p1, l1), pub(p2, l2);
    long sink = 0;
    auto make = [] {
        return jwt::create()
            .set_type("JWT")
            .set_payload_claim("sub", jwt::claim(std::string("123456")))
            .set_payload_claim("username", jwt::claim(std::string("alice")))
            .set_issued_at(std::chrono::system_clock::from_time_t(1700000000))
            .set_expires_at(std::chrono::system_clock::from_time_t(4102444800));
    };
    jwt::algorithm::hs256 hs{ secret };
    jwt::algorithm::ed25519 ed{ pub, priv };
    best("jwt-cpp HS256 create().sign()", [&] { sink += (long)make().sign(hs).size(); });
    best("jwt-cpp EdDSA create().sign()", [&] { sink += (long)make().sign(ed).size(); });
    return sink == 42;
}
