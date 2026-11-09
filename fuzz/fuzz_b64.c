/* fuzz_b64.c — libFuzzer harness for base64url decoding: the SIMD decoder, the scalar decoder and a reference
 * written here from RFC 4648 (alphabet, no padding, length mod 4 != 1, zero trailing bits) must all agree. */
#include "jwt.c"

#include <stdio.h>

static int ref_decode(uint8_t *dst, const uint8_t *s, int n) {
    if (n % 4 == 1) return -1;
    uint32_t acc = 0;
    int bits = 0, o = 0;
    for (int i = 0; i < n; i++) {
        uint8_t c = s[i];
        int v = c >= 'A' && c <= 'Z'   ? c - 'A'
                : c >= 'a' && c <= 'z' ? c - 'a' + 26
                : c >= '0' && c <= '9' ? c - '0' + 52
                : c == '-'             ? 62
                : c == '_'             ? 63
                                       : -1;
        if (v < 0) return -1;
        acc = acc << 6 | (uint32_t)v, bits += 6;
        if (bits >= 8) bits -= 8, dst[o++] = (uint8_t)(acc >> bits);
        acc &= (1u << bits) - 1;
    }
    return acc ? -1 : o; /* leftover bits must be zero */
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 16384) return 0;
    static uint8_t a[16384 + 64], b[16384 + 64], c[16384 + 64], in[16384 + 64];
    memcpy(in, data, size);
    memset(in + size, 'A', 64); /* readable slack after the input, as in a token buffer */
    int n = (int)size;
    int ra = jwt_b64url_decode(a, (const char *)in, n), rb = jwt_b64url_decode_scalar(b, (const char *)in, n);
    int rc = ref_decode(c, in, n);
    if (ra != rc || rb != rc || (rc > 0 && (memcmp(a, c, (size_t)rc) || memcmp(b, c, (size_t)rc)))) {
        fprintf(stderr, "b64: simd %d scalar %d reference %d on %.*s\n", ra, rb, rc, n, (const char *)in);
        abort();
    }
#if defined(CC_X86)
    /* the VBMI decoder is dispatched only on VBMI && FAST_ZMM, so reach it directly wherever VBMI exists */
    if (jwt_cpu_features() & JWT_CPU_VBMI) {
        static uint8_t d[16384 + 64];
        int rd = b64url_decode_vbmi(d, (const char *)in, n);
        if (rd != rc || (rc > 0 && memcmp(d, c, (size_t)rc))) {
            fprintf(stderr, "b64: vbmi %d reference %d on %.*s\n", rd, rc, n, (const char *)in);
            abort();
        }
    }
#endif
    return 0;
}
