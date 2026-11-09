/* ossl_cap.c: the capability word OpenSSL's extracted SHA-256 block function (sha256_x86_64_ossl.S, assembled with
 * its symbols renamed to cjwt_rs_*) dispatches on, laid out like OPENSSL_ia32cap_P for the bits it reads: word 0 bit
 * 30 "Intel CPU", word 1 = CPUID.1:ECX (SSSE3, AVX), word 2 = CPUID.7.0:EBX (BMI1, AVX2, BMI2, SHA).  AVX and AVX2
 * are cleared unless the OS saves ymm state (XCR0).  The same code as cc_ossl_cap_init in src/jwt.c.  Hidden, so the
 * assembly's PC-relative reference also links into shared objects. */
#include <cpuid.h>

__attribute__((visibility("hidden"))) unsigned int cjwt_rs_ia32cap_P[4];

void cjwt_rs_ossl_init(void) {
    unsigned a, b, c, d, w0 = 0, w1 = 0, w2 = 0;
    if (__get_cpuid(0, &a, &b, &c, &d) && b == 0x756e6547 && d == 0x49656e69 && c == 0x6c65746e) w0 |= 1u << 30;
    if (__get_cpuid(1, &a, &b, &c, &d)) w1 = c;
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) w2 = b;
    int ymm = 0;
    if (w1 & (1u << 27)) { /* OSXSAVE: XCR0 bits 1 (SSE) and 2 (AVX) */
        unsigned lo, hi;
        __asm__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        ymm = (lo & 6) == 6;
    }
    if (!ymm) w1 &= ~(1u << 28), w2 &= ~(1u << 5);
    cjwt_rs_ia32cap_P[0] = w0, cjwt_rs_ia32cap_P[1] = w1, cjwt_rs_ia32cap_P[2] = w2;
}
