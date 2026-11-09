#!/usr/bin/env python3
"""gen-shani-mb.py: generate crypto/src/sha256_shani_mb.S, cursed-jwt's hand-scheduled multi-stream SHA-NI kernels.

    python3 scripts/gen-shani-mb.py > crypto/src/sha256_shani_mb.S

Emits cc_shani_mb3 and cc_shani_mb4 (S = 3, 4 independent streams; the code takes any S <= 4):

    void cc_shani_mbS(__m128i st[2 * S], const uint8_t *const *blk, size_t nb);

st[2s], st[2s + 1] are stream s's state as ABEF / CDGH (the layout sha256rnds2 wants; src/jwt.c's ni_ld / ni_st
convert), updated in place.  blk holds nb * S block pointers, block-major (blk[b * S + s] is stream s's block b,
64 bytes, big-endian words as in a message).  nb >= 1.

Why hand-written: legacy-SSE SHA-NI reaches only xmm0-15.  Compiled intrinsics for 4 streams (jwt_hmac_shani_4) keep
each stream's whole 16-word schedule in registers, run out, and GCC spills the *state*, which puts a store-to-load
forward on every 4-round step of every stream's dependency chain.  Here the register budget is fixed by hand:
  - xmm0: W + K, the implicit sha256rnds2 operand (reloaded per stream and half-step; renaming keeps them apart);
  - xmm1-8: the 2 * S state registers, never spilled;
  - one register per stream for the newest message group W[r+3] (the schedule's recurrence runs through it, so its
    chain has no memory hop);
  - the three older groups of each stream in a 64-byte ring on the stack, read as m128 operands (msg1, palignr,
    paddd), written once per step; their loads are off every dependency chain that matters;
  - the byte-swap mask and K from memory; the block's input state saved on the stack and added back from memory;
  - whatever is left over: temporaries for the schedule, allocated from a pool (the retired group's register becomes
    a temporary, so there is no register-to-register copy of the new group).
Streams are interleaved per step: every stream's 4 rounds, then every stream's schedule update.

Measured (raw HMAC of 570-byte messages, 11 blocks each, batch 16): Genoa (Zen 4) 180 ns against 195 for the
compiled 4-stream engine, Turin (Zen 5) 196 against 216.  Tried and dropped: OpenSSL's 2-way
sha256_multi_block_shaext as a 2 x 2 engine (208 / 231 ns), and keeping W + K in a second stack ring so each 2-round
half is a load + sha256rnds2 (191 / 195 ns: no faster on Zen 5, slower on Zen 4).

The generator is a plain Python 3 script with no dependencies; the output is committed, so building needs neither.
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
PTR = ["%r8", "%r9", "%r10", "%r11"]
RING = 0  # stream s, slot j at RING + 64 s + 16 j (%rsp)
SAVE = 256  # state register i at SAVE + 16 i (%rsp)
FRAME = 384


def x(i):
    return "%%xmm%d" % i


def kernel(S, out):
    abef = [x(1 + 2 * s) for s in range(S)]
    cdgh = [x(2 + 2 * s) for s in range(S)]
    newest = [x(1 + 2 * S + s) for s in range(S)]  # register holding stream s's newest W group
    pool = [x(i) for i in range(1 + 3 * S, 16)]  # free temporaries (>= 3 for S <= 4)
    assert len(pool) >= 3
    ring = lambda s, j: "%d(%%rsp)" % (RING + 64 * s + 16 * (j & 3))
    e = out.append
    name = "cc_shani_mb%d" % S

    e(".globl\t%s\n.hidden\t%s\n.type\t%s,@function\n.align\t32\n%s:\n.cfi_startproc" % ((name,) * 4))
    e("\tpushq\t%rbp\n.cfi_adjust_cfa_offset 8\n.cfi_offset %rbp,-16\n\tmovq\t%rsp,%rbp\n.cfi_def_cfa_register %rbp")
    e("\tsubq\t$%d,%%rsp\n\tandq\t$-64,%%rsp" % FRAME)
    for i in range(2 * S):
        e("\tmovdqu\t%d(%%rdi),%s" % (16 * i, x(1 + i)))
    e(".align\t32\n.L%s_block:" % name)
    for s in range(S):
        e("\tmovq\t%d(%%rsi),%s" % (8 * s, PTR[s]))
    e("\taddq\t$%d,%%rsi" % (8 * S))
    for s in range(S):
        e("\tmovdqa\t%s,%d(%%rsp)\n\tmovdqa\t%s,%d(%%rsp)" % (abef[s], SAVE + 32 * s, cdgh[s], SAVE + 32 * s + 16))
    t = pool[0]
    for s in range(S):  # W[0..2] to the ring, W[3] to the newest register
        for j in range(3):
            e(
                "\tmovdqu\t%d(%s),%s\n\tpshufb\t.Ljwt_mb_bswap(%%rip),%s\n\tmovdqa\t%s,%s"
                % (16 * j, PTR[s], t, t, t, ring(s, j))
            )
        e("\tmovdqu\t48(%s),%s\n\tpshufb\t.Ljwt_mb_bswap(%%rip),%s" % (PTR[s], newest[s], newest[s]))
    top = [3] * S  # index of the group in the newest register, per stream

    def w(s, i):  # operand for W group i of stream s
        return newest[s] if i == top[s] else ring(s, i)

    for r in range(16):
        for s in range(S):
            e("\tmovdqa\t.Ljwt_mb_K+%d(%%rip),%%xmm0" % (16 * r))
            e("\tpaddd\t%s,%%xmm0" % w(s, r))
            e("\tsha256rnds2\t%%xmm0,%s,%s" % (abef[s], cdgh[s]))
            e("\tpshufd\t$0x0e,%xmm0,%xmm0")
            e("\tsha256rnds2\t%%xmm0,%s,%s" % (cdgh[s], abef[s]))
        if r >= 12:
            continue
        for s in range(S):  # W[r+4] = msg2(msg1(W[r], W[r+1]) + alignr(W[r+3], W[r+2], 4), W[r+3])
            tt, u = pool.pop(0), pool.pop(0)
            n = newest[s]
            e("\tmovdqa\t%s,%s" % (n, tt))
            e("\tpalignr\t$4,%s,%s" % (ring(s, r + 2), tt))
            e("\tmovdqa\t%s,%s" % (ring(s, r), u))
            e("\tsha256msg1\t%s,%s" % (ring(s, r + 1), u))
            e("\tpaddd\t%s,%s" % (tt, u))
            e("\tsha256msg2\t%s,%s" % (n, u))
            e("\tmovdqa\t%s,%s" % (n, ring(s, r + 3)))  # W[r+3] retires to the ring (W[r-1]'s slot)
            newest[s] = u
            top[s] = r + 4
            pool += [tt, n]  # the retired register joins the pool
    for s in range(S):
        e("\tpaddd\t%d(%%rsp),%s\n\tpaddd\t%d(%%rsp),%s" % (SAVE + 32 * s, abef[s], SAVE + 32 * s + 16, cdgh[s]))
    e("\tdecq\t%%rdx\n\tjnz\t.L%s_block" % name)
    for i in range(2 * S):
        e("\tmovdqu\t%s,%d(%%rdi)" % (x(1 + i), 16 * i))
    e("\tmovq\t%rbp,%rsp\n\tpopq\t%rbp\n.cfi_def_cfa %rsp,8\n.cfi_restore %rbp\n\tret")
    e(".cfi_endproc\n.size\t%s,.-%s\n" % (name, name))


def main():
    out = [
        "/* sha256_shani_mb.S: cursed-jwt's hand-scheduled 3/4-stream SHA-NI SHA-256 block kernels.",
        " * Generated by scripts/gen-shani-mb.py (see there for the register plan); do not edit, regenerate. */",
        "#if defined(__x86_64__) && defined(__ELF__)",
        ".text",
    ]
    for S in (3, 4):  # 2 streams fit in registers compiled (src/jwt.c ni_hmac), and that measured 1.5-2% faster
        kernel(S, out)
    out.append(".section\t.rodata\n.align\t64\n.Ljwt_mb_K:")
    for i in range(0, 64, 4):
        out.append(".long\t" + ",".join("0x%08x" % k for k in K[i : i + 4]))
    out.append(".Ljwt_mb_bswap:\n.byte\t3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12")
    out.append('.previous\n.section .note.GNU-stack,"",@progbits\n#endif')
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
