/* replay.c — runs files (or every file in directories) through a fuzz harness without libFuzzer, so the corpora run
 * as ordinary tests on any compiler: `replay_verify fuzz/corpus/verify ...`.  Linked with one fuzz_*.c. */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static long ran;
static void one(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n + 1);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { perror(path); exit(2); }
    fclose(f);
    LLVMFuzzerTestOneInput(buf, (size_t)n);
    free(buf);
    ran++;
}
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        struct stat st;
        if (stat(argv[i], &st)) { perror(argv[i]); return 2; }
        if (!S_ISDIR(st.st_mode)) { one(argv[i]); continue; }
        DIR *d = opendir(argv[i]);
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            char p[4096];
            snprintf(p, sizeof p, "%s/%s", argv[i], e->d_name);
            one(p);
        }
        closedir(d);
    }
    printf("replayed %ld inputs: OK\n", ran);
    return 0;
}
