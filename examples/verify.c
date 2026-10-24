/* verify.c — the public API end to end: mint nothing, just verify what's on the command line.
 *   build/verify SECRET TOKEN [TOKEN...]   (links build/libcursedjwt.a; no OpenSSL needed)
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "jwt.h"

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s SECRET TOKEN [TOKEN...]\n", argv[0]); return 2; }
    enum { MAXN = 64 };
    int n = argc - 2 < MAXN ? argc - 2 : MAXN;
    const char *tok[MAXN]; int len[MAXN];
    static jwt_result_t out[MAXN];
    for (int i = 0; i < n; i++) tok[i] = argv[i + 2], len[i] = (int)strlen(argv[i + 2]);
    jwt_key_t key;
    jwt_key_init(&key, argv[1], strlen(argv[1]));
    jwt_verify_batch(&key, n, tok, len, (int64_t)time(NULL), out);   /* one SIMD HMAC pass for all n */
    int bad = 0;
    for (int i = 0; i < n; i++) {
        if (out[i].status == JWT_OK)
            printf("%d: OK sub=%lld username=%.*s%s\n", i, (long long)out[i].uid, (int)out[i].username_len,
                   out[i].username, out[i].username_escape ? " (needs JSON escaping)" : "");
        else
            printf("%d: %s\n", i, out[i].status == JWT_INVALID ? "INVALID" : "BAD_PAYLOAD"), bad++;
    }
    return bad != 0;
}
