#!/usr/bin/env python3
"""gen-sha256-x16.py: generate crypto/src/sha256_x16_avx512.S, a 16-lane AVX-512 SHA-256 block kernel.

    python3 scripts/gen-sha256-x16.py > crypto/src/sha256_x16_avx512.S

A GAS port of Intel ipsec-mb's lib/avx512_t1/sha256_x16_avx512.asm with its transpose
(lib/include/transpose_avx512.inc), v3.0.0 (75c6991), Copyright (c) 2017-2026 Intel Corporation, BSD-3-Clause (see
THIRD_PARTY.md).  Same register plan and instruction order: A-H in zmm0-7, temporaries in zmm8-15, the whole message
schedule W0-W15 in zmm16-31; the next block's rows load during rounds 48-63 (lanes l and l + 8 share a register, 32
bytes each), so a block costs one 16 x 16 transpose (32 vshufps + 16 vpermi2q) and 16 vpshufb.  Changes: the input
is nb * 16 block pointers, block-major (cursed-jwt's HMAC plans are not contiguous), and a second entry point takes
one block already transposed and in host order (the HMAC outer block, built from the inner state rows).

    void jwt_sha256_x16(uint32_t st[8][16], const uint8_t *const *blk, size_t nb);  nb >= 1
    void jwt_sha256_x16_rows(uint32_t st[8][16], const uint32_t w[16][16]);         one block

st[j] is state word j of the 16 lanes (64-byte aligned rows), updated in place; w[t] is message word t of the 16
lanes.  Plain Python 3, no dependencies; the output is committed.
"""

import sys

# fmt: off
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
# fmt: on

z = lambda i: "%%zmm%d" % i
y = lambda i: "%%ymm%d" % i
T1, TMP = z(8), [z(9 + i) for i in range(7)]  # TMP0..TMP6
W = [16 + i for i in range(16)]  # register numbers of W0..W15
SAVE = 0  # digest save area: 8 x 64 bytes at 0(%rsp)
GP = ["%r8", "%r9", "%r10", "%r11"]


class Gen:
    def __init__(self):
        self.out = []
        self.v = [z(i) for i in range(8)]  # current names of A..H

    def e(self, s):
        self.out.append("\t" + s)

    def rotate(self):  # ROTATE_ARGS: H becomes the new A
        self.v = [self.v[7]] + self.v[:7]

    def round(self, t, wt):
        """ipsec-mb PROCESS_LOOP: T1 = H + K + W + Ch + S1; D += T1; H = S0 + Maj + T1; TMP3 = next K"""
        A, B, C, D, E, F, G, H = self.v
        T0, T_1, T2, T3 = TMP[0], TMP[1], TMP[2], TMP[3]
        e = self.e
        e("vpaddd\t%s,%s,%s" % (T3, H, T1))
        e("vmovdqa32\t%s,%s" % (E, T0))
        e("vprord\t$6,%s,%s" % (E, T_1))
        e("vprord\t$11,%s,%s" % (E, T2))
        e("vprord\t$25,%s,%s" % (E, T3))
        e("vpternlogd\t$0xCA,%s,%s,%s" % (G, F, T0))
        e("vpaddd\t%s,%s,%s" % (wt, T1, T1))
        e("vpternlogd\t$0x96,%s,%s,%s" % (T3, T2, T_1))
        e("vpaddd\t%s,%s,%s" % (T0, T1, T1))
        e("vpaddd\t%s,%s,%s" % (T_1, T1, T1))
        e("vpaddd\t%s,%s,%s" % (T1, D, D))
        e("vprord\t$2,%s,%s" % (A, H))
        e("vprord\t$13,%s,%s" % (A, T2))
        e("vprord\t$22,%s,%s" % (A, T3))
        e("vmovdqa32\t%s,%s" % (A, T0))
        e("vpternlogd\t$0xE8,%s,%s,%s" % (C, B, T0))
        e("vpternlogd\t$0x96,%s,%s,%s" % (T3, T2, H))
        e("vpaddd\t%s,%s,%s" % (T0, H, H))
        e("vpaddd\t%s,%s,%s" % (T1, H, H))
        e("vpbroadcastd\t%d(%%rax),%s" % (4 * (t + 1), T3))  # next K (the table has a 65th entry)
        self.rotate()

    def sched(self, j):
        """ipsec-mb MSG_SCHED_ROUND_16_63: W[j] += s1(W[j+14]) + W[j+9] + s0(W[j+1]) (indices mod 16)"""
        wt, w1, w9, w14 = (z(W[(j + d) % 16]) for d in (0, 1, 9, 14))
        T4, T5, T6 = TMP[4], TMP[5], TMP[6]
        e = self.e
        e("vprord\t$17,%s,%s" % (w14, T4))
        e("vprord\t$19,%s,%s" % (w14, T5))
        e("vpsrld\t$10,%s,%s" % (w14, T6))
        e("vpternlogd\t$0x96,%s,%s,%s" % (T6, T5, T4))
        e("vpaddd\t%s,%s,%s" % (T4, wt, wt))
        e("vpaddd\t%s,%s,%s" % (w9, wt, wt))
        e("vprord\t$7,%s,%s" % (w1, T4))
        e("vprord\t$18,%s,%s" % (w1, T5))
        e("vpsrld\t$3,%s,%s" % (w1, T6))
        e("vpternlogd\t$0x96,%s,%s,%s" % (T6, T5, T4))
        e("vpaddd\t%s,%s,%s" % (T4, wt, wt))

    def load_row(self, j, base):
        """ipsec-mb MSG_SCHED_ROUND_00_15 / TRANSPOSE16_U32_LOAD_*: W[j] = lane l (32 bytes) | lane l + 8 (32 bytes),
        l = j for j < 8 (bytes 0-31) and l = j - 8 for j >= 8 (bytes 32-63); base = offset of the block's pointers"""
        l, off = (j, 0) if j < 8 else (j - 8, 32)
        e = self.e
        e("movq\t%d(%%rsi),%s" % (base + 8 * l, GP[0]))
        e("movq\t%d(%%rsi),%s" % (base + 8 * (l + 8), GP[1]))
        e("vmovdqu32\t%d(%s),%s" % (off, GP[0], y(W[j])))
        e("vinserti64x4\t$1,%d(%s),%s,%s" % (off, GP[1], z(W[j]), z(W[j])))

    def transpose(self):
        """ipsec-mb TRANSPOSE16_U32_PRELOADED, register for register (t0, t1 = TMP0, TMP1; m0, m1 = TMP4, TMP5)"""
        r = [z(w) for w in W]
        t0, t1, m0, m1 = TMP[0], TMP[1], TMP[4], TMP[5]
        e = self.e

        def shuf(d, a, b, i):
            e("vshufps\t$%s,%s,%s,%s" % (i, b, a, d))

        def perm(d, m, a, b):  # d = permute2(a, m, b): vmovdqu32 m -> d; vpermi2q b, a, d
            e("vmovdqu32\t%s,%s" % (m, d))
            e("vpermi2q\t%s,%s,%s" % (b, a, d))

        for q in range(4):  # rows 4q..4q+3
            a, b, c, d = r[4 * q : 4 * q + 4]
            # quarter 0: t0 / t1; quarters 1-3 reuse r2, r6, r10 as ipsec-mb does
            x0 = t0 if q == 0 else [None, r[2], r[6], r[10]][q]
            shuf(x0, a, b, "0x44")
            shuf(a, a, b, "0xEE")
            shuf(t1, c, d, "0x44")
            shuf(c, c, d, "0xEE")
            shuf(d, x0, t1, "0xDD")
            shuf(b, a, c, "0x88")
            shuf(a, a, c, "0xDD")
            shuf(x0, x0, t1, "0x88")
            if q == 0:
                e("vmovdqa64\t.Ljwt_x16_tm1(%%rip),%s" % m0)
                e("vmovdqa64\t.Ljwt_x16_tm2(%%rip),%s" % m1)
        # quarters now hold (ipsec-mb's names): q0: t0 r3 r1 r0 ; q1: r2 r7 r5 r4 ; q2: r6 r11 r9 r8 ; q3: r10 r15 r13 r12
        perm(t1, m0, r[9], r[13])
        perm(r[14], m1, r[9], r[13])
        perm(r[9], m0, r[11], r[15])
        perm(r[13], m1, r[11], r[15])
        perm(r[11], m0, r[8], r[12])
        perm(r[15], m1, r[8], r[12])
        perm(r[8], m0, r[6], r[10])
        perm(r[12], m1, r[6], r[10])
        e("vmovdqu32\t%s,%s" % (t1, r[10]))
        perm(t1, m0, r[1], r[5])
        perm(r[6], m1, r[1], r[5])
        perm(r[1], m0, r[3], r[7])
        perm(r[5], m1, r[3], r[7])
        perm(r[3], m0, r[0], r[4])
        perm(r[7], m1, r[0], r[4])
        perm(r[0], m0, t0, r[2])
        perm(r[4], m1, t0, r[2])
        e("vmovdqu32\t%s,%s" % (t1, r[2]))

    def prologue(self, name):
        o = self.out
        o.append(".globl\t%s\n.hidden\t%s\n.type\t%s,@function\n.align\t32\n%s:\n.cfi_startproc" % ((name,) * 4))
        self.e("pushq\t%rbp")
        o.append(".cfi_adjust_cfa_offset 8\n.cfi_offset %rbp,-16")
        self.e("movq\t%rsp,%rbp")
        o.append(".cfi_def_cfa_register %rbp")
        self.e("subq\t$512,%rsp")
        self.e("andq\t$-64,%rsp")
        self.e("leaq\t.Ljwt_x16_K(%rip),%rax")
        for i in range(8):
            self.e("vmovdqu32\t%d(%%rdi),%s" % (64 * i, z(i)))

    def save(self):
        for i, v in enumerate(self.v):
            self.e("vmovdqa32\t%s,%d(%%rsp)" % (v, SAVE + 64 * i))
        self.e("vpbroadcastd\t(%%rax),%s" % TMP[3])  # K[0]

    def add_saved(self):
        for i, v in enumerate(self.v):
            self.e("vpaddd\t%d(%%rsp),%s,%s" % (SAVE + 64 * i, v, v))

    def epilogue(self, name):
        for i, v in enumerate(self.v):
            self.e("vmovdqu32\t%s,%d(%%rdi)" % (v, 64 * i))
        self.e("vzeroupper")
        self.e("movq\t%rbp,%rsp")
        self.e("popq\t%rbp")
        self.out.append(".cfi_def_cfa %rsp,8\n.cfi_restore %rbp")
        self.e("ret")
        self.out.append(".cfi_endproc\n.size\t%s,.-%s\n" % (name, name))


def blocks(g):
    name = "jwt_sha256_x16"
    g.prologue(name)
    for j in range(16):  # the first block's rows
        g.load_row(j, 0)
    g.out.append(".align\t32\n.Ljwt_x16_loop:")
    # 64 rounds rotate the names 64 times (a multiple of 8), so the loop body starts with the same names each time
    g.save()
    g.transpose()
    g.e("vbroadcasti32x4\t.Ljwt_x16_bswap(%%rip),%s" % TMP[2])
    for j in range(16):
        g.e("vpshufb\t%s,%s,%s" % (TMP[2], z(W[j]), z(W[j])))
    for t in range(48):
        g.round(t, z(W[t % 16]))
        g.sched(t % 16)
    g.e("subq\t$1,%rdx")
    g.e("je\t.Ljwt_x16_last")
    for t in range(48, 64):  # the last 16 rounds load the next block's rows into the W registers they free
        g.round(t, z(W[t % 16]))
        g.load_row(t % 16, 128)
    g.e("addq\t$128,%rsi")
    g.add_saved()
    g.e("jmp\t.Ljwt_x16_loop")
    g.out.append(".align\t32\n.Ljwt_x16_last:")
    for t in range(48, 64):
        g.round(t, z(W[t % 16]))
    g.add_saved()
    g.epilogue(name)


def rows(g):
    name = "jwt_sha256_x16_rows"
    g.prologue(name)
    for j in range(16):
        g.e("vmovdqu32\t%d(%%rsi),%s" % (64 * j, z(W[j])))
    g.save()
    for t in range(48):
        g.round(t, z(W[t % 16]))
        g.sched(t % 16)
    for t in range(48, 64):
        g.round(t, z(W[t % 16]))
    g.add_saved()
    g.epilogue(name)


def main():
    out = [
        "/* sha256_x16_avx512.S: 16-lane AVX-512 SHA-256 block kernel, a GAS port of Intel ipsec-mb's",
        " * sha256_x16_avx512.asm (BSD-3-Clause, Copyright (c) 2017-2026 Intel Corporation; see THIRD_PARTY.md).",
        " * Generated by scripts/gen-sha256-x16.py; do not edit, regenerate. */",
        "#if defined(__x86_64__) && defined(__ELF__)",
        ".text",
    ]
    for f in (blocks, rows):
        g = Gen()
        f(g)
        out += g.out
    out.append(".section\t.rodata\n.align\t64\n.Ljwt_x16_K:")
    for i in range(0, 64, 4):
        out.append(".long\t" + ",".join("0x%08x" % k for k in K[i : i + 4]))
    out.append(".long\t0  /* K[64]: read, never used, by the last round's look-ahead */")
    out.append(".align\t64\n.Ljwt_x16_tm1:\n.quad\t0,1,8,9,4,5,12,13\n.Ljwt_x16_tm2:\n.quad\t2,3,10,11,6,7,14,15")
    out.append(".Ljwt_x16_bswap:\n.byte\t3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12")
    out.append('.previous\n.section .note.GNU-stack,"",@progbits\n#endif')
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
