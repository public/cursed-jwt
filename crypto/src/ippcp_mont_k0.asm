; ippcp_mont_k0.asm: Intel Cryptography Primitives' (ippcp) x86-64 schoolbook multiply / square and Montgomery
; reduction for BMI2 CPUs without ADX (mulx, add/adc carry chains), as ippcp builds them for its k0 target.  Generated
; from ippcp v2.4.0 (commit d9ac7a1) sources/ippcp/asm_intel64/pcpbnumulschoolsrvl9.asm and the files it includes by
; scripts/extract-ippcp-mont.sh.  Do not edit; regenerate.
;
; Copyright (C) 2013-2024 Intel Corporation
; Licensed under the Apache License, Version 2.0; see THIRD_PARTY.md and http://www.apache.org/licenses/LICENSE-2.0
;
; Modified for cursed-crypto (Apache-2.0 section 4(b)): the NASM preprocessor's output for the k0 target, with its
; line markers and blank lines removed, its align expansions folded back into `align`, and the three functions
; renamed cpMulAdc_BNU_school -> cc_ipp_mul_school, cpSqrAdc_BNU_school -> cc_ipp_sqr_school,
; cpMontRedAdc_BNU -> cc_ipp_mont_red and given hidden visibility.  The machine code is ippcp's, unchanged.
%use smartalign
ALIGNMODE p6,16
[section .note.GNU-stack noalloc noexec nowrite progbits]
[segment .text align=64]
align 64
 mla_1x1:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, qword [rcx]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mov r8, rbx
 ret
.LEnd_mla_1x1:
align 64
 mul_1x1:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx,qword [rcx]
 mulx rdx,rax,qword [rsi]
 mov qword [rdi], rax
 mov qword [rdi+8], rdx
 ret
.LEnd_mul_1x1:
align 64
 mla_2x2:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, qword [rcx]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mov r9, rbp
 mov rdx, qword [rcx+8]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mov r9, rbp
 ret
.LEnd_mla_2x2:
align 64
 mul_2x2:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_2x2
 mov qword [rdi+8*2], r8
 mov qword [rdi+8*3], r9
 ret
.LEnd_mul_2x2:
align 64
 mla_3x3:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, qword [rcx]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mov r10, rbx
 mov rdx, qword [rcx+8]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mov r10, rbx
 mov rdx, qword [rcx+8*2]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8*2], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mov r10, rbx
 ret
.LEnd_mla_3x3:
align 64
 mul_3x3:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_3x3
 mov qword [rdi+8*3], r8
 mov qword [rdi+8*4], r9
 mov qword [rdi+8*5], r10
 ret
.LEnd_mul_3x3:
align 64
 mla_4x2:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, qword [rcx]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 mov rdx, qword [rcx+8]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 ret
.LEnd_mla_4x2:
align 64
 mla_4x4:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_4x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_4x2
 sub rdi, 8*2
 sub rcx, 8*2
 ret
.LEnd_mla_4x4:
align 64
 mul_4x4:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_4x4
 mov qword [rdi+8*4], r8
 mov qword [rdi+8*5], r9
 mov qword [rdi+8*6], r10
 mov qword [rdi+8*7], r11
 ret
.LEnd_mul_4x4:
align 64
 mla_5x2:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rcx+8*0]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mov r12, rbx
 mov rdx, [rcx+8*1]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mov r12, rbx
 ret
.LEnd_mla_5x2:
align 64
 mla_5x5:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rcx]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mov r12, rbx
 add rdi, 8
 add rcx, 8
 call mla_5x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_5x2
 sub rdi, 8*3
 sub rcx, 8*3
 ret
.LEnd_mla_5x5:
align 64
 mul_5x5:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_5x5
 mov qword [rdi+8*5], r8
 mov qword [rdi+8*6], r9
 mov qword [rdi+8*7], r10
 mov qword [rdi+8*8], r11
 mov qword [rdi+8*9], r12
 ret
.LEnd_mul_5x5:
align 64
 mla_6x2:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rcx+8*0]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mov r13, rbp
 mov rdx, [rcx+8*1]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mov r13, rbp
 ret
.LEnd_mla_6x2:
align 64
 mla_6x6:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_6x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_6x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_6x2
 sub rdi, 8*4
 sub rcx, 8*4
 ret
.LEnd_mla_6x6:
align 64
 mul_6x6:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_6x6
 mov qword [rdi+8*6], r8
 mov qword [rdi+8*7], r9
 mov qword [rdi+8*8], r10
 mov qword [rdi+8*9], r11
 mov qword [rdi+8*10],r12
 mov qword [rdi+8*11],r13
 ret
.LEnd_mul_6x6:
align 64
 mla_7x2:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rcx+8*0]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mov r14, rbx
 mov rdx, [rcx+8*1]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mov r14, rbx
 ret
.LEnd_mla_7x2:
align 64
 mla_7x7:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rcx]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mov r14, rbx
 add rdi, 8
 add rcx, 8
 call mla_7x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_7x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_7x2
 sub rdi, 8*5
 sub rcx, 8*5
 ret
.LEnd_mla_7x7:
align 64
 mul_7x7:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_7x7
 mov qword [rdi+8*7], r8
 mov qword [rdi+8*8], r9
 mov qword [rdi+8*9], r10
 mov qword [rdi+8*10],r11
 mov qword [rdi+8*11],r12
 mov qword [rdi+8*12],r13
 mov qword [rdi+8*13],r14
 ret
.LEnd_mul_7x7:
align 64
 mla_8x1:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rcx]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mulx rbp,r14,[rsi+8*7]
 add r14, r15
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mov r15, rbp
 ret
.LEnd_mla_8x1:
align 64
 mla_8x2:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rcx+8*0]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mulx rbp,r14,[rsi+8*7]
 add r14, r15
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mov r15, rbp
 mov rdx, [rcx+8*1]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mulx rbp,r14,[rsi+8*7]
 add r14, r15
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mov r15, rbp
 ret
.LEnd_mla_8x2:
align 64
 mla_8x3:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x1
 add rdi, 8
 add rcx, 8
 call mla_8x2
 sub rdi, 8
 sub rcx, 8
 ret
.LEnd_mla_8x3:
align 64
 mla_8x4:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 sub rdi, 8*2
 sub rcx, 8*2
 ret
.LEnd_mla_8x4:
align 64
 mla_8x5:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x1
 add rdi, 8
 add rcx, 8
 call mla_8x4
 sub rdi, 8
 sub rcx, 8
 ret
.LEnd_mla_8x5:
align 64
 mla_8x6:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x4
 sub rdi, 8*2
 sub rcx, 8*2
 ret
.LEnd_mla_8x6:
align 64
 mla_8x7:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x1
 add rdi, 8
 add rcx, 8
 call mla_8x6
 sub rdi, 8
 sub rcx, 8
 ret
.LEnd_mla_8x7:
align 64
 mla_8x8:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 sub rdi, 8*6
 sub rcx, 8*6
 ret
.LEnd_mla_8x8:
align 64
 mul_8x8:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x8
 mov qword [rdi+8*8], r8
 mov qword [rdi+8*9], r9
 mov qword [rdi+8*10],r10
 mov qword [rdi+8*11],r11
 mov qword [rdi+8*12],r12
 mov qword [rdi+8*13],r13
 mov qword [rdi+8*14],r14
 mov qword [rdi+8*15],r15
 ret
.LEnd_mul_8x8:
align 64
 mul_9x9:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x8
 mov rdx, [rcx+8*8]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8*8], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mulx rbp,r14,[rsi+8*7]
 add r14, r15
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mov r15, rbp
 push r15
 mov rdx, [rsi+8*8]
 mov r15, [rdi+8*8]
 mulx rbx,rax,[rcx]
 add rax, r15
 adc rbx, 0
 mov [rdi+8*8], rax
 mulx rbp,r15,[rcx+8]
 add r15, r8
 adc rbp, 0
 add r15, rbx
 adc rbp, 0
 mulx rbx,r8,[rcx+8*2]
 add r8, r9
 adc rbx, 0
 add r8, rbp
 adc rbx, 0
 mulx rbp,r9,[rcx+8*3]
 add r9, r10
 adc rbp, 0
 add r9, rbx
 adc rbp, 0
 mulx rbx,r10,[rcx+8*4]
 add r10, r11
 adc rbx, 0
 add r10, rbp
 adc rbx, 0
 mulx rbp,r11,[rcx+8*5]
 add r11, r12
 adc rbp, 0
 add r11, rbx
 adc rbp, 0
 mulx rbx,r12,[rcx+8*6]
 add r12, r13
 adc rbx, 0
 add r12, rbp
 adc rbx, 0
 mulx rbp,r13,[rcx+8*7]
 add r13, r14
 adc rbp, 0
 add r13, rbx
 adc rbp, 0
 mov r14, rbp
 mov qword [rdi+8*9], r15
 mulx r15,rbp,[rcx+8*8]
 pop rax
 add r14, rax
 adc r15,0
 add r14, rbp
 adc r15, 0
 mov qword [rdi+8*10],r8
 mov qword [rdi+8*11],r9
 mov qword [rdi+8*12],r10
 mov qword [rdi+8*13],r11
 mov qword [rdi+8*14],r12
 mov qword [rdi+8*15],r13
 mov qword [rdi+8*16],r14
 mov qword [rdi+8*17],r15
 ret
.LEnd_mul_9x9:
align 64
 mul_10x10:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x8
 add rdi, 8*8
 add rcx, 8*8
 call mla_8x2
 push r15
 push r14
 add rsi, 8*8
 sub rcx, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 mov r15, r13
 mov r14, r12
 mov r13, r11
 mov r12, r10
 mov r11, r9
 mov r10, r8
 mov r9, qword [rdi+8*1]
 mov r8, qword [rdi+8*0]
 call mla_8x2
 mov qword [rdi+8*2],r8
 mov qword [rdi+8*3],r9
 mov qword [rdi+8*4],r10
 mov qword [rdi+8*5],r11
 mov qword [rdi+8*6],r12
 mov qword [rdi+8*7],r13
 add rdi, 8*8
 xor r10, r10
 pop r8
 pop r9
 add r8, r14
 adc r9, r15
 adc r10,0
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 add rcx, 8*8
 call mla_2x2
 add rdi, 8*2
 add r8, r10
 adc r9, 0
 mov qword [rdi+8*0],r8
 mov qword [rdi+8*1],r9
 ret
.LEnd_mul_10x10:
align 64
 mul_11x11:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x8
 add rdi, 8*8
 add rcx, 8*8
 call mla_8x3
 push r15
 push r14
 push r13
 add rsi, 8*8
 sub rcx, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 mov r15, r12
 mov r14, r11
 mov r13, r10
 mov r12, r9
 mov r11, r8
 mov r10,qword [rdi+8*2]
 mov r9, qword [rdi+8*1]
 mov r8, qword [rdi+8*0]
 call mla_8x3
 mov qword [rdi+8*3],r8
 mov qword [rdi+8*4],r9
 mov qword [rdi+8*5],r10
 mov qword [rdi+8*6],r11
 mov qword [rdi+8*7],r12
 add rdi, 8*8
 xor r11, r11
 pop r8
 pop r9
 pop r10
 add r8, r13
 adc r9, r14
 adc r10,r15
 adc r11,0
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 add rcx, 8*8
 call mla_3x3
 add rdi, 8*3
 add r8, r11
 adc r9, 0
 adc r10,0
 mov qword [rdi+8*0],r8
 mov qword [rdi+8*1],r9
 mov qword [rdi+8*2],r10
 ret
.LEnd_mul_11x11:
align 64
 mul_12x12:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x8
 add rdi, 8*8
 add rcx, 8*8
 call mla_8x4
 push r15
 push r14
 push r13
 push r12
 add rsi, 8*8
 sub rcx, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 mov r15, r11
 mov r14, r10
 mov r13, r9
 mov r12, r8
 mov r11,qword [rdi+8*3]
 mov r10,qword [rdi+8*2]
 mov r9, qword [rdi+8*1]
 mov r8, qword [rdi+8*0]
 call mla_8x4
 mov qword [rdi+8*4],r8
 mov qword [rdi+8*5],r9
 mov qword [rdi+8*6],r10
 mov qword [rdi+8*7],r11
 add rdi, 8*8
 xor rax, rax
 pop r8
 pop r9
 pop r10
 pop r11
 add r8, r12
 adc r9, r13
 adc r10,r14
 adc r11,r15
 adc rax,0
 push rax
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 add rcx, 8*8
 call mla_4x4
 add rdi, 8*4
 pop rax
 add r8, rax
 adc r9, 0
 adc r10,0
 adc r11,0
 mov qword [rdi+8*0],r8
 mov qword [rdi+8*1],r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 ret
.LEnd_mul_12x12:
align 64
 mul_13x13:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x8
 add rdi, 8*8
 add rcx, 8*8
 call mla_8x5
 push r15
 push r14
 push r13
 push r12
 push r11
 add rsi, 8*8
 sub rcx, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 mov r15, r10
 mov r14, r9
 mov r13, r8
 mov r12,qword [rdi+8*4]
 mov r11,qword [rdi+8*3]
 mov r10,qword [rdi+8*2]
 mov r9, qword [rdi+8*1]
 mov r8, qword [rdi+8*0]
 call mla_8x5
 mov qword [rdi+8*5], r8
 mov qword [rdi+8*6], r9
 mov qword [rdi+8*7], r10
 add rdi, 8*8
 xor rax, rax
 pop r8
 pop r9
 pop r10
 pop rbx
 pop rbp
 add r8, r11
 adc r9, r12
 adc r10,r13
 adc rbx,r14
 adc rbp,r15
 adc rax,0
 push rax
 mov r11, rbx
 mov r12, rbp
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 add rcx, 8*8
 call mla_5x5
 add rdi, 8*5
 pop rax
 add r8, rax
 adc r9, 0
 adc r10,0
 adc r11,0
 adc r12,0
 mov qword [rdi+8*0],r8
 mov qword [rdi+8*1],r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 mov qword [rdi+8*4],r12
 ret
.LEnd_mul_13x13:
align 64
 mul_14x14:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_7x7
 add rdi, 8*7
 add rsi, 8*7
 call mla_7x7
 mov qword [rdi+8*7], r8
 mov qword [rdi+8*8], r9
 mov qword [rdi+8*9], r10
 mov qword [rdi+8*10],r11
 mov qword [rdi+8*11],r12
 mov qword [rdi+8*12],r13
 mov qword [rdi+8*13],r14
 mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 add rcx, 8*7
 sub rsi, 8*7
 call mla_7x7
 xor rdx, rdx
 mov rax, qword [rdi+8*7]
 add r8, rax
 mov rax, qword [rdi+8*8]
 adc r9, rax
 mov rax, qword [rdi+8*9]
 adc r10, rax
 mov rax, qword [rdi+8*10]
 adc r11, rax
 mov rax, qword [rdi+8*11]
 adc r12, rax
 mov rax, qword [rdi+8*12]
 adc r13, rax
 mov rax, qword [rdi+8*13]
 adc r14, rax
 adc rdx, 0
 push rdx
 add rdi, 8*7
 add rsi, 8*7
 call mla_7x7
 sub rdi, 8*14
 sub rsi, 8*7
 sub rcx, 8*7
 pop rdx
 add r8, rdx
 adc r9, 0
 adc r10, 0
 adc r11, 0
 adc r12, 0
 adc r13, 0
 adc r14, 0
 mov qword [rdi+8*21],r8
 mov qword [rdi+8*22],r9
 mov qword [rdi+8*23],r10
 mov qword [rdi+8*24],r11
 mov qword [rdi+8*25],r12
 mov qword [rdi+8*26],r13
 mov qword [rdi+8*27],r14
 ret
.LEnd_mul_14x14:
align 64
 mul_15x15:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x8
 add rdi, 8*8
 add rcx, 8*8
 call mla_8x7
 mov qword [rdi+8*7], r8
 mov qword [rdi+8*8], r9
 mov qword [rdi+8*9], r10
 mov qword [rdi+8*10],r11
 mov qword [rdi+8*11],r12
 mov qword [rdi+8*12],r13
 mov qword [rdi+8*13],r14
 mov qword [rdi+8*14],r15
 add rsi, 8*8
 sub rcx, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mla_8x7
 mov qword [rdi+8*7], r8
 add rdi, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 add rcx, 8*8
 mov r8, r9
 mov r9, r10
 mov r10,r11
 mov r11,r12
 mov r12,r13
 mov r13,r14
 mov r14,r15
 xor rdx, rdx
 mov rax, qword [rdi+8*0]
 add r8, rax
 mov rax, qword [rdi+8*1]
 adc r9, rax
 mov rax, qword [rdi+8*2]
 adc r10, rax
 mov rax, qword [rdi+8*3]
 adc r11, rax
 mov rax, qword [rdi+8*4]
 adc r12, rax
 mov rax, qword [rdi+8*5]
 adc r13, rax
 mov rax, qword [rdi+8*6]
 adc r14, rax
 adc rdx, 0
 push rdx
 call mla_7x7
 add rdi, 8*7
 pop rax
 add r8, rax
 adc r9, 0
 adc r10,0
 adc r11,0
 adc r12,0
 adc r13,0
 adc r14,0
 mov qword [rdi+8*0],r8
 mov qword [rdi+8*1],r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 mov qword [rdi+8*4],r12
 mov qword [rdi+8*5],r13
 mov qword [rdi+8*6],r14
 ret
.LEnd_mul_15x15:
align 64
 mul_16x16:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call mla_8x8
 add rdi, 8*8
 add rsi, 8*8
 call mla_8x8
 mov qword [rdi+8*8], r8
 mov qword [rdi+8*9], r9
 mov qword [rdi+8*10],r10
 mov qword [rdi+8*11],r11
 mov qword [rdi+8*12],r12
 mov qword [rdi+8*13],r13
 mov qword [rdi+8*14],r14
 mov qword [rdi+8*15],r15
 mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 add rcx, 8*8
 sub rsi, 8*8
 call mla_8x8
 xor rdx, rdx
 mov rax, qword [rdi+8*8]
 add r8, rax
 mov rax, qword [rdi+8*9]
 adc r9, rax
 mov rax, qword [rdi+8*10]
 adc r10, rax
 mov rax, qword [rdi+8*11]
 adc r11, rax
 mov rax, qword [rdi+8*12]
 adc r12, rax
 mov rax, qword [rdi+8*13]
 adc r13, rax
 mov rax, qword [rdi+8*14]
 adc r14, rax
 mov rax, qword [rdi+8*15]
 adc r15, rax
 adc rdx, 0
 push rdx
 add rdi, 8*8
 add rsi, 8*8
 call mla_8x8
 sub rdi, 8*16
 sub rsi, 8*8
 sub rcx, 8*8
 pop rdx
 add r8, rdx
 adc r9, 0
 adc r10, 0
 adc r11, 0
 adc r12, 0
 adc r13, 0
 adc r14, 0
 adc r15, 0
 mov qword [rdi+8*24],r8
 mov qword [rdi+8*25],r9
 mov qword [rdi+8*26],r10
 mov qword [rdi+8*27],r11
 mov qword [rdi+8*28],r12
 mov qword [rdi+8*29],r13
 mov qword [rdi+8*30],r14
 mov qword [rdi+8*31],r15
 ret
.LEnd_mul_16x16:
mul_lxl_basic DQ mul_1x1 - mul_lxl_basic
 DQ mul_2x2 - mul_lxl_basic
 DQ mul_3x3 - mul_lxl_basic
 DQ mul_4x4 - mul_lxl_basic
 DQ mul_5x5 - mul_lxl_basic
 DQ mul_6x6 - mul_lxl_basic
 DQ mul_7x7 - mul_lxl_basic
 DQ mul_8x8 - mul_lxl_basic
 DQ mul_9x9 - mul_lxl_basic
 DQ mul_10x10-mul_lxl_basic
 DQ mul_11x11-mul_lxl_basic
 DQ mul_12x12-mul_lxl_basic
 DQ mul_13x13-mul_lxl_basic
 DQ mul_14x14-mul_lxl_basic
 DQ mul_15x15-mul_lxl_basic
 DQ mul_16x16-mul_lxl_basic
mla_lxl_short DQ mla_1x1 - mla_lxl_short
 DQ mla_2x2 - mla_lxl_short
 DQ mla_3x3 - mla_lxl_short
 DQ mla_4x4 - mla_lxl_short
 DQ mla_5x5 - mla_lxl_short
 DQ mla_6x6 - mla_lxl_short
 DQ mla_7x7 - mla_lxl_short
mla_8xl_tail DQ mla_8x1 - mla_8xl_tail
 DQ mla_8x2 - mla_8xl_tail
 DQ mla_8x3 - mla_8xl_tail
 DQ mla_8x4 - mla_8xl_tail
 DQ mla_8x5 - mla_8xl_tail
 DQ mla_8x6 - mla_8xl_tail
 DQ mla_8x7 - mla_8xl_tail
align 64
 mul_8Nx8M:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rbx
 push rdi
 push rsi
 push rdx
.mul_loopA:
 push rdx
 call mla_8x8
 add rdi, 8*8
 add rsi, 8*8
 pop rdx
 sub rdx, 8
 jnz .mul_loopA
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 mov qword [rdi+8*4],r12
 mov qword [rdi+8*5],r13
 mov qword [rdi+8*6],r14
 mov qword [rdi+8*7],r15
 jmp .mla_entry
.mla_loopB:
 push rbx
 push rdi
 push rsi
 push rdx
 xor rax, rax
 push rax
 mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
.loopA:
 push rdx
 call mla_8x8
 add rdi, 8*8
 add rsi, 8*8
 pop rdx
 sub rdx, 8
 jz .exit_loopA
 pop rax
 neg rax
 mov rax, qword [rdi+8*0]
 adc r8, rax
 mov rax, qword [rdi+8*1]
 adc r9, rax
 mov rax, qword [rdi+8*2]
 adc r10, rax
 mov rax, qword [rdi+8*3]
 adc r11, rax
 mov rax, qword [rdi+8*4]
 adc r12, rax
 mov rax, qword [rdi+8*5]
 adc r13, rax
 mov rax, qword [rdi+8*6]
 adc r14, rax
 mov rax, qword [rdi+8*7]
 adc r15, rax
 sbb rax, rax
 push rax
 jmp .loopA
.exit_loopA:
 pop rax
 neg rax
 adc r8, 0
 mov qword [rdi+8*0], r8
 adc r9, 0
 mov qword [rdi+8*1], r9
 adc r10,0
 mov qword [rdi+8*2],r10
 adc r11,0
 mov qword [rdi+8*3],r11
 adc r12,0
 mov qword [rdi+8*4],r12
 adc r13,0
 mov qword [rdi+8*5],r13
 adc r14,0
 mov qword [rdi+8*6],r14
 adc r15,0
 mov qword [rdi+8*7],r15
.mla_entry:
 pop rdx
 pop rsi
 pop rdi
 add rdi, 8*8
 add rcx, 8*8
 pop rbx
 sub rbx, 8
 jnz .mla_loopB
 ret
.LEnd_mul_8Nx8M:
align 64
 mla_simple:
 db 0F3h, 00Fh, 01Eh, 0FAh
 xor rax, rax
 mov r11, rdx
 cmp r11, rbx
 jge .ms_mla_entry
 xor r11, rbx
 xor rbx, r11
 xor r11, rbx
 xor rsi, rcx
 xor rcx, rsi
 xor rsi, rcx
 jmp .ms_mla_entry
.ms_loopB:
 push rbx
 push rdi
 push rsi
 push r11
 push rax
 mov rdx, qword [rcx]
 xor r10, r10
.ms_loopA:
 mulx r9,r8,qword [rsi]
 add rdi, 8
 add rsi, 8
 add r8, r10
 adc r9, 0
 add r8, qword [rdi-8]
 adc r9, 0
 mov qword [rdi-8], r8
 mov r10, r9
 sub r11, 1
 jnz .ms_loopA
 pop rax
 shr rax, 1
 adc r10, qword [rdi]
 mov qword [rdi], r10
 adc rax, 0
 pop r11
 pop rsi
 pop rdi
 pop rbx
 add rdi, 8
 add rcx, 8
.ms_mla_entry:
 sub rbx, 1
 jnc .ms_loopB
 ret
.LEnd_mla_simple:
align 64
 mul_NxM:
 db 0F3h, 00Fh, 01Eh, 0FAh
 sub rsp, 56
 cmp rbx, 8
 jge .regular_entry
 cmp rdx, 8
 jge .irregular_entry
 mov r8, rdx
 add r8, rbx
 mov rbp, rdi
 xor rax, rax
..@370.L_1:
 mov qword [rbp], rax
 add rbp, 8
 sub r8, 1
 jnz ..@370.L_1
 call mla_simple
 jmp .quit
.irregular_entry:
 mov [rsp+0], rbx
 mov [rsp+24], rdx
 mov [rsp+32], rdx
 lea rax, [rel mla_8xl_tail]
 mov rbp, [rax+rbx*8-8]
 add rax, rbp
 mov [rsp+48], rax
 jmp .irr_init_entry
.irr_init_loop:
 mov [rsp+32], rdx
 call rax
 mov rbx, [rsp+0]
 mov qword [rdi+rbx*8+8*0], r8
 mov qword [rdi+rbx*8+8*1], r9
 mov qword [rdi+rbx*8+8*2], r10
 mov qword [rdi+rbx*8+8*3], r11
 mov qword [rdi+rbx*8+8*4], r12
 mov qword [rdi+rbx*8+8*5], r13
 mov qword [rdi+rbx*8+8*6], r14
 mov qword [rdi+rbx*8+8*7], r15
 add rsi, 8*8
 add rdi, 8*8
 xor r8, r8
 xor r9, r9
 xor r10,r10
 xor r11,r11
 xor r12,r12
 xor r13,r13
 xor r14,r14
 xor r15,r15
 mov r8, qword [rdi]
 cmp rbx, 1
 jz .continue
 mov r9, qword [rdi+8]
 cmp rbx, 2
 jz .continue
 mov r10, qword [rdi+8*2]
 cmp rbx, 3
 jz .continue
 mov r11, qword [rdi+8*3]
 cmp rbx, 4
 jz .continue
 mov r12, qword [rdi+8*4]
 cmp rbx, 5
 jz .continue
 mov r13, qword [rdi+8*5]
 cmp rbx, 6
 jz .continue
 mov r14, qword [rdi+8*6]
.continue:
 mov rdx, [rsp+32]
.irr_init_entry:
 sub rdx, 8
 mov rax, [rsp+48]
 jnc .irr_init_loop
 add rdx, 8
 jz .quit
 lea rbp, [rdi+rbx*8]
 xor rax, rax
..@372.L_1:
 mov qword [rbp], rax
 add rbp, 8
 sub rdx, 1
 jnz ..@372.L_1
 mov rdx, [rsp+32]
 call mla_simple
 jmp .quit
.regular_entry:
 sub rbx, 8
 xor rax, rax
 mov [rsp+0], rbx
 mov [rsp+8], rdi
 mov [rsp+16], rsi
 mov [rsp+24], rdx
 mov [rsp+32], rdx
 mov [rsp+40], rax
 mov rbp, rdx
 and rbp, 7
 lea rax, [rel mla_8xl_tail]
 mov rbp, [rax+rbp*8-8]
 add rax, rbp
 mov [rsp+48], rax
 sub rdx, 8
.init_loopA:
 mov [rsp+32], rdx
 call mla_8x8
 mov rdx, [rsp+32]
 add rdi, 8*8
 add rsi, 8*8
 sub rdx, 8
 jnc .init_loopA
 add rdx, 8
 jz .init_complete
 mov [rsp+32], rdx
 mov rax, [rsp+48]
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call rax
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 mov rdx, [rsp+32]
 lea rdi, [rdi+rdx*8]
.init_complete:
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 mov qword [rdi+8*4],r12
 mov qword [rdi+8*5],r13
 mov qword [rdi+8*6],r14
 mov qword [rdi+8*7],r15
 jmp .mla_entry
.mla_loopB:
 mov [rsp+0], rbx
 mov [rsp+8], rdi
 xor rax, rax
 mov [rsp+40], rax
 mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 sub rdx, 8
.loopA:
 mov [rsp+32], rdx
 call mla_8x8
 mov rdx, [rsp+32]
 add rdi, 8*8
 add rsi, 8*8
 sub rdx, 8
 jc .exit_loopA
 mov rax, [rsp+40]
 shr rax, 1
 mov rbx, qword [rdi+8*0]
 adc r8, rbx
 mov rbx, qword [rdi+8*1]
 adc r9, rbx
 mov rbx, qword [rdi+8*2]
 adc r10, rbx
 mov rbx, qword [rdi+8*3]
 adc r11, rbx
 mov rbx, qword [rdi+8*4]
 adc r12, rbx
 mov rbx, qword [rdi+8*5]
 adc r13, rbx
 mov rbx, qword [rdi+8*6]
 adc r14, rbx
 mov rbx, qword [rdi+8*7]
 adc r15, rbx
 adc rax, 0
 mov [rsp+40], rax
 jmp .loopA
.exit_loopA:
 add rdx, 8
 jz .complete_reg_loopB
 mov [rsp+32], rdx
 xor rax, rax
.put_zero:
 mov qword [rdi+rdx*8], rax
 add rdx,1
 cmp rdx, 8
 jl .put_zero
 mov rax, [rsp+40]
 shr rax, 1
 mov rbx, [rdi+8*0]
 adc r8, rbx
 mov rbx, [rdi+8*1]
 adc r9, rbx
 mov rbx, [rdi+8*2]
 adc r10, rbx
 mov rbx, [rdi+8*3]
 adc r11, rbx
 mov rbx, [rdi+8*4]
 adc r12, rbx
 mov rbx, [rdi+8*5]
 adc r13, rbx
 mov rbx, [rdi+8*6]
 adc r14, rbx
 mov rbx, [rdi+8*7]
 adc r15, rbx
 adc rax, 0
 mov [rsp+40], rax
 mov rax, [rsp+48]
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call rax
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 mov rdx, [rsp+32]
 lea rdi, [rdi+rdx*8]
 mov rax, [rsp+40]
 shr rax, 1
 dec rdx
 jz .mt_1
 dec rdx
 jz .mt_2
 dec rdx
 jz .mt_3
 dec rdx
 jz .mt_4
 dec rdx
 jz .mt_5
 dec rdx
 jz .mt_6
.mt_7: adc r9, 0
.mt_6: adc r10,0
.mt_5: adc r11,0
.mt_4: adc r12,0
.mt_3: adc r13,0
.mt_2: adc r14,0
.mt_1: adc r15,0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 mov qword [rdi+8*4],r12
 mov qword [rdi+8*5],r13
 mov qword [rdi+8*6],r14
 mov qword [rdi+8*7],r15
 jmp .mla_entry
.complete_reg_loopB:
 mov rax, [rsp+40]
 add r8, rax
 adc r9, 0
 adc r10,0
 adc r11,0
 adc r12,0
 adc r13,0
 adc r14,0
 adc r15,0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 mov qword [rdi+8*4],r12
 mov qword [rdi+8*5],r13
 mov qword [rdi+8*6],r14
 mov qword [rdi+8*7],r15
.mla_entry:
 mov rbx, [rsp+0]
 mov rdi, [rsp+8]
 mov rdx, [rsp+24]
 mov rsi, [rsp+16]
 add rcx, 8*8
 add rdi, 8*8
 sub rbx, 8
 jnc .mla_loopB
 add rbx, 8
 jz .quit
 mov [rsp+0], rbx
 lea rax, [rel mla_8xl_tail]
 mov rbp, [rax+rbx*8-8]
 add rax, rbp
 mov [rsp+48], rax
 lea rbp, [rdi+rdx*8]
 xor rax, rax
..@395.L_1:
 mov qword [rbp], rax
 add rbp, 8
 sub rbx, 1
 jnz ..@395.L_1
 xor rax, rax
 mov [rsp+40], rax
 sub rdx, 8
.tail_loopA:
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov [rsp+32], rdx
 mov rax, [rsp+48]
 call rax
.entry_tail_loopA:
 mov rax, [rsp+40]
 shr rax, 1
 adc r8, 0
 adc r9, 0
 adc r10, 0
 adc r11, 0
 adc r12, 0
 adc r13, 0
 adc r14, 0
 adc r15, 0
 adc rax, 0
 mov rbx, [rsp+0]
 mov rbp, rbx
 dec rbp
 jz .tt_1
 dec rbp
 jz .tt_2
 dec rbp
 jz .tt_3
 dec rbp
 jz .tt_4
 dec rbp
 jz .tt_5
 dec rbp
 jz .tt_6
.tt_7: 
 mov rbp, [rdi+rbx*8+8*1]
 adc r9, rbp
.tt_6: 
 mov rbp, [rdi+rbx*8+8*2]
 adc r10, rbp
.tt_5: 
 mov rbp, [rdi+rbx*8+8*3]
 adc r11, rbp
.tt_4: 
 mov rbp, [rdi+rbx*8+8*4]
 adc r12, rbp
.tt_3: 
 mov rbp, [rdi+rbx*8+8*5]
 adc r13, rbp
.tt_2: 
 mov rbp, [rdi+rbx*8+8*6]
 adc r14, rbp
.tt_1: 
 mov rbp, [rdi+rbx*8+8*7]
 adc r15, rbp
 adc rax, 0
 mov [rsp+40], rax
 mov qword [rdi+rbx*8+8*0], r8
 mov qword [rdi+rbx*8+8*1], r9
 mov qword [rdi+rbx*8+8*2], r10
 mov qword [rdi+rbx*8+8*3], r11
 mov qword [rdi+rbx*8+8*4], r12
 mov qword [rdi+rbx*8+8*5], r13
 mov qword [rdi+rbx*8+8*6], r14
 mov qword [rdi+rbx*8+8*7], r15
 mov rdx, [rsp+32]
 add rsi, 8*8
 add rdi, 8*8
 sub rdx, 8
 jnc .tail_loopA
 add rdx, 8
 jz .quit
 mov rax, [rsp+40]
 mov rbp, rbx
 dec rbp
 mov r8, qword [rdi+rbx*8+8*0]
 add r8, rax
 mov qword [rdi+rbx*8+8*0], r8
 jz .simple
 dec rbp
 mov r9, qword [rdi+rbx*8+8*1]
 adc r9, 0
 mov qword [rdi+rbx*8+8*1], r9
 jz .simple
 dec rbp
 mov r10,qword [rdi+rbx*8+8*2]
 adc r10, 0
 mov qword [rdi+rbx*8+8*2], r10
 jz .simple
 dec rbp
 mov r11,qword [rdi+rbx*8+8*3]
 adc r11, 0
 mov qword [rdi+rbx*8+8*3], r11
 jz .simple
 dec rbp
 mov r12,qword [rdi+rbx*8+8*4]
 adc r12, 0
 mov qword [rdi+rbx*8+8*4], r12
 jz .simple
 dec rbp
 mov r13,qword [rdi+rbx*8+8*5]
 adc r13, 0
 mov qword [rdi+rbx*8+8*5], r13
 jz .simple
 dec rbp
 mov r14,qword [rdi+rbx*8+8*6]
 adc r14, 0
 mov qword [rdi+rbx*8+8*6], r14
.simple:
 call mla_simple
.quit:
 add rsp, 56
 ret
.LEnd_mul_NxM:
align 64
 sqr_1:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, qword [rsi]
 mulx rdx,rax,rdx
 mov qword [rdi], rax
 mov qword [rdi+8], rdx
 ret
.LEnd_sqr_1:
align 64
 sqr_2:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, qword [rsi]
 mulx r9,r8,qword [rsi+8*1]
 mulx r11,r10,rdx
 mov rdx, qword [rsi+8]
 mulx rdx,rax,rdx
 xor rcx, rcx
 add r8, r8
 adc r9, r9
 adc rcx, 0
 mov qword [rdi+8*0], r10
 add r11, r8
 mov qword [rdi+8*1], r11
 adc rax, r9
 mov qword [rdi+8*2], rax
 adc rdx, rcx
 mov qword [rdi+8*3], rdx
 ret
.LEnd_sqr_2:
align 64
 sqr_3:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rsi]
 mulx r9,r8,[rsi+8*1]
 mulx r10,rax,[rsi+8*2]
 add r9, rax
 adc r10, 0
 mov rdx, qword [rsi+8*1]
 mulx r11,rax,qword [rsi+8*2]
 add r10, rax
 adc r11, 0
 mov rdx, qword [rsi+ 8*0]
 xor rcx, rcx
 add r8, r8
 adc r9, r9
 adc r10, r10
 adc r11, r11
 adc rcx, rcx
 mulx rax,rdx,rdx
 mov [rdi+8*0], rdx
 mov rdx, [rsi+8*1]
 add r8, rax
 mov [rdi+8*1], r8
 mulx rax,rdx,rdx
 adc r9, rdx
 mov [rdi+8*2], r9
 mov rdx, [rsi+8*2]
 adc r10, rax
 mov [rdi+8*3], r10
 mulx rax,rdx,rdx
 adc r11, rdx
 mov [rdi+8*4], r11
 adc rcx, rax
 mov [rdi+8*5], rcx
 ret
.LEnd_sqr_3:
align 64
 sqr_4:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rsi]
 mulx r9,r8,[rsi+8*1]
 mulx r10,rax,[rsi+8*2]
 add r9, rax
 adc r10, 0
 mulx r11,rax,[rsi+8*3]
 add r10, rax
 adc r11, 0
 mov rdx, qword [rsi+8*1]
 mulx rcx,rax,qword [rsi+8*2]
 xor r12, r12
 add r10, rax
 adc r11, rcx
 adc r12, 0
 mulx rcx,rax,qword [rsi+8*3]
 add r11, rax
 adc r12, rcx
 mov rdx, qword [rsi+8*2]
 mulx r13,rax,qword [rsi+8*3]
 add r12, rax
 adc r13, 0
 mov rdx, [rsi+8*0]
 xor rcx, rcx
 add r8, r8
 adc r9, r9
 adc r10, r10
 adc r11, r11
 adc r12, r12
 adc r13, r13
 adc rcx, 0
 mulx rax,rdx,rdx
 mov [rdi+8*0], rdx
 mov rdx, [rsi+8*1]
 add r8, rax
 mov [rdi+8*1], r8
 mulx rax,rdx,rdx
 adc r9, rdx
 mov [rdi+8*2], r9
 mov rdx, [rsi+8*2]
 adc r10, rax
 mov [rdi+8*3], r10
 mulx rax,rdx,rdx
 adc r11, rdx
 mov [rdi+8*4], r11
 mov rdx, [rsi+8*3]
 adc r12, rax
 mov [rdi+8*5], r12
 mulx rax,rdx,rdx
 adc r13, rdx
 mov [rdi+8*6], r13
 adc rcx, rax
 mov [rdi+8*7], rcx
 ret
.LEnd_sqr_4:
align 64
 sqr_5:
 db 0F3h, 00Fh, 01Eh, 0FAh
mov rdx, [rsi]
 mulx r9,r8,[rsi+8*1]
 mulx r10,rax,[rsi+8*2]
 add r9, rax
 adc r10, 0
 mulx r11,rax,[rsi+8*3]
 add r10, rax
 adc r11, 0
 mulx r12,rax,[rsi+8*4]
 add r11, rax
 adc r12, 0
 mov rdx, [rsi + 8*1]
 mulx rbp,rax,[rsi+8*2]
 add r10, rax
 adc rbp, 0
 mulx rcx,rax,[rsi+8*3]
 add r11, rax
 adc rcx, 0
 add r11, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*4]
 add r12, rax
 adc rcx, 0
 add r12, rbp
 adc rcx, 0
 mov rbp, rcx
 mov r13, rbp
 mov rdx, qword [rsi+8*2]
 mulx rcx,rax,qword [rsi+8*3]
 xor r14, r14
 add r12, rax
 adc r13, rcx
 adc r14, 0
 mulx rcx,rax,qword [rsi+8*4]
 add r13, rax
 adc r14, rcx
 mov rdx, qword [rsi+8*3]
 mulx r15,rax,qword [rsi+8*4]
 add r14, rax
 adc r15, 0
 mov rdx, [rsi+8*0]
 xor rcx, rcx
 add r8, r8
 adc r9, r9
 adc r10, r10
 adc r11, r11
 adc r12, r12
 adc r13, r13
 adc r14, r14
 adc r15, r15
 adc rcx, 0
 mulx rax,rdx,rdx
 mov [rdi+8*0], rdx
 mov rdx, [rsi+8*1]
 add r8, rax
 mov [rdi+8*1], r8
 mulx rax,rdx,rdx
 adc r9, rdx
 mov [rdi+8*2], r9
 mov rdx, [rsi+8*2]
 adc r10, rax
 mov [rdi+8*3], r10
 mulx rax,rdx,rdx
 adc r11, rdx
 mov [rdi+8*4], r11
 mov rdx, [rsi+8*3]
 adc r12, rax
 mov [rdi+8*5], r12
 mulx rax,rdx,rdx
 adc r13, rdx
 mov [rdi+8*6], r13
 mov rdx, [rsi+8*4]
 adc r14, rax
 mov [rdi+8*7], r14
 mulx rax,rdx,rdx
 adc r15, rdx
 mov [rdi+8*8], r15
 mov rdx, [rsi+8*5]
 adc rcx, rax
 mov [rdi+8*9], rcx
 ret
.LEnd_sqr_5:
align 64
 sqr_6:
 db 0F3h, 00Fh, 01Eh, 0FAh
mov rdx, [rsi]
 mulx r9,r8,[rsi+8*1]
 mulx r10,rax,[rsi+8*2]
 add r9, rax
 adc r10, 0
 mulx r11,rax,[rsi+8*3]
 add r10, rax
 adc r11, 0
 mulx r12,rax,[rsi+8*4]
 add r11, rax
 adc r12, 0
 mulx r13,rax,[rsi+8*5]
 add r12, rax
 adc r13, 0
 mov rdx, [rsi + 8*1]
 mulx rbp,rax,[rsi+8*2]
 add r10, rax
 adc rbp, 0
 mulx rcx,rax,[rsi+8*3]
 add r11, rax
 adc rcx, 0
 add r11, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*4]
 add r12, rax
 adc rcx, 0
 add r12, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*5]
 add r13, rax
 adc rcx, 0
 add r13, rbp
 adc rcx, 0
 mov rbp, rcx
 mov r14, rbp
 mov rdx, [rsi+8*2]
 mulx rbp,rax,[rsi+8*3]
 add r12, rax
 adc rbp, 0
 mulx rcx,rax,[rsi+8*4]
 add r13, rax
 adc rcx, 0
 add r13, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*5]
 add r14, rax
 adc rcx, 0
 add r14, rbp
 adc rcx, 0
 mov rbp, rcx
 mov r15, rbp
 mov rdx, qword [rsi+8*3]
 mulx rcx,rax,qword [rsi+8*4]
 xor rbx, rbx
 add r14, rax
 adc r15, rcx
 adc rbx, 0
 mulx rcx,rax,qword [rsi+8*5]
 add r15, rax
 adc rbx, rcx
 mov rdx, qword [rsi+8*4]
 mulx rbp,rax,qword [rsi+8*5]
 add rbx, rax
 adc rbp, 0
 mov rdx, [rsi+8*0]
 xor rcx, rcx
 add r8, r8
 adc r9, r9
 adc r10, r10
 adc r11, r11
 adc r12, r12
 adc r13, r13
 adc r14, r14
 adc r15, r15
 adc rbx, rbx
 adc rbp, rbp
 adc rcx, 0
 mulx rax,rdx,rdx
 mov [rdi+8*0], rdx
 mov rdx, [rsi+8*1]
 add r8, rax
 mov [rdi+8*1], r8
 mulx rax,rdx,rdx
 adc r9, rdx
 mov [rdi+8*2], r9
 mov rdx, [rsi+8*2]
 adc r10, rax
 mov [rdi+8*3], r10
 mulx rax,rdx,rdx
 adc r11, rdx
 mov [rdi+8*4], r11
 mov rdx, [rsi+8*3]
 adc r12, rax
 mov [rdi+8*5], r12
 mulx rax,rdx,rdx
 adc r13, rdx
 mov [rdi+8*6], r13
 mov rdx, [rsi+8*4]
 adc r14, rax
 mov [rdi+8*7], r14
 mulx rax,rdx,rdx
 adc r15, rdx
 mov [rdi+8*8], r15
 mov rdx, [rsi+8*5]
 adc rbx, rax
 mov [rdi+8*9], rbx
 mulx rax,rdx,rdx
 adc rbp, rdx
 mov [rdi+8*10], rbp
 adc rcx, rax
 mov [rdi+8*11], rcx
 ret
.LEnd_sqr_6:
align 64
 sqr_7:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rsi]
 mulx r9,r8,[rsi+8*1]
 mulx r10,rax,[rsi+8*2]
 add r9, rax
 adc r10, 0
 mulx r11,rax,[rsi+8*3]
 add r10, rax
 adc r11, 0
 mulx r12,rax,[rsi+8*4]
 add r11, rax
 adc r12, 0
 mulx r13,rax,[rsi+8*5]
 add r12, rax
 adc r13, 0
 mulx r14,rax,[rsi+8*6]
 add r13, rax
 adc r14, 0
 mov rdx, [rsi + 8*1]
 mulx rbp,rax,[rsi+8*2]
 add r10, rax
 adc rbp, 0
 mulx rcx,rax,[rsi+8*3]
 add r11, rax
 adc rcx, 0
 add r11, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*4]
 add r12, rax
 adc rcx, 0
 add r12, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*5]
 add r13, rax
 adc rcx, 0
 add r13, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*6]
 add r14, rax
 adc rcx, 0
 add r14, rbp
 adc rcx, 0
 mov rbp, rcx
 mov r15, rbp
 mov rdx, [rsi+8*2]
 mulx rbp,rax,[rsi+8*3]
 add r12, rax
 adc rbp, 0
 xor rbx, rbx
 mulx rcx,rax,[rsi+8*4]
 add r13, rax
 adc rcx, 0
 add r13, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*5]
 add r14, rax
 adc rcx, 0
 add r14, rbp
 adc rcx, 0
 mov rbp, rcx
 add r15, rbp
 adc rbx, 0
 mov rax, [rsi+8*3]
 mul qword [rsi+8*4]
 add r14, rax
 adc rdx, 0
 add r15, rdx
 adc rbx, 0
 mov rdx, [rsi+8*0]
 xor rcx, rcx
 add r8, r8
 adc r9, r9
 adc r10, r10
 adc r11, r11
 adc r12, r12
 adc r13, r13
 adc r14, r14
 adc rcx, 0
 mulx rax,rdx,rdx
 mov [rdi+8*0], rdx
 mov rdx, [rsi+8*1]
 add r8, rax
 mov [rdi+8*1], r8
 mulx rax,rdx,rdx
 adc r9, rdx
 mov [rdi+8*2], r9
 mov rdx, [rsi+8*2]
 adc r10, rax
 mov [rdi+8*3], r10
 mulx rax,rdx,rdx
 adc r11, rdx
 mov [rdi+8*4], r11
 mov rdx, [rsi+8*3]
 adc r12, rax
 mov [rdi+8*5], r12
 mulx rax,rdx,rdx
 adc r13, rdx
 mov [rdi+8*6], r13
 adc r14, rax
 mov [rdi+8*7], r14
 adc rcx, 0
 mov rax, [rsi+8*2]
 xor r8, r8
 mul qword [rsi+8*6]
 add r15, rax
 adc rdx, 0
 add rbx, rdx
 adc r8, 0
 mov rdx, [rsi+8*3]
 mulx r14,rax,[rsi+8*5]
 add r15, rax
 adc rbx, r14
 adc r8, 0
 mulx r14,rax,[rsi+8*6]
 add rbx, rax
 adc r8, r14
 mov rdx, [rsi+8*4]
 mulx r14,rax,[rsi+8*5]
 xor r9, r9
 add rbx, rax
 adc r8, r14
 adc r9, 0
 mulx r14,rax,[rsi+8*6]
 add r8, rax
 adc r9, r14
 mov rax, [rsi+8*5]
 xor r10, r10
 mul qword [rsi + 8*6]
 add r9, rax
 adc r10, rdx
 mov rdx, [rsi+8*4]
 xor r11, r11
 add r15, r15
 adc rbx, rbx
 adc r8, r8
 adc r9, r9
 adc r10, r10
 adc r11, 0
 mulx rax,rdx,rdx
 add rdx, rcx
 adc rax, 0
 add r15, rdx
 mov rdx, [rsi+8*5]
 mov [rdi+8*8], r15
 adc rbx, rax
 mov [rdi+8*9], rbx
 mulx rax,rdx,rdx
 adc r8, rdx
 mov [rdi+8*10], r8
 mov rdx, [rsi+8*6]
 adc r9, rax
 mov [rdi+8*11], r9
 mulx rax,rdx,rdx
 adc r10, rdx
 mov [rdi+8*12], r10
 adc r11, rax
 mov [rdi+8*13], r11
 ret
.LEnd_sqr_7:
align 64
 sqr_8:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rsi]
 mulx r9,r8,[rsi+8*1]
 mulx r10,rax,[rsi+8*2]
 add r9, rax
 adc r10, 0
 mulx r11,rax,[rsi+8*3]
 add r10, rax
 adc r11, 0
 mulx r12,rax,[rsi+8*4]
 add r11, rax
 adc r12, 0
 mulx r13,rax,[rsi+8*5]
 add r12, rax
 adc r13, 0
 mulx r14,rax,[rsi+8*6]
 add r13, rax
 adc r14, 0
 mulx r15,rax,[rsi+8*7]
 add r14, rax
 adc r15, 0
 mov rdx, [rsi + 8*1]
 mulx rbp,rax,[rsi+8*2]
 add r10, rax
 adc rbp, 0
 xor rbx, rbx
 mulx rcx,rax,[rsi+8*3]
 add r11, rax
 adc rcx, 0
 add r11, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*4]
 add r12, rax
 adc rcx, 0
 add r12, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*5]
 add r13, rax
 adc rcx, 0
 add r13, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*6]
 add r14, rax
 adc rcx, 0
 add r14, rbp
 adc rcx, 0
 mov rbp, rcx
 add r15, rbp
 adc rbx, 0
 mov rdx, [rsi+8*2]
 mulx rbp,rax,[rsi+8*3]
 add r12, rax
 adc rbp, 0
 mulx rcx,rax,[rsi+8*4]
 add r13, rax
 adc rcx, 0
 add r13, rbp
 adc rcx, 0
 mov rbp, rcx
 mulx rcx,rax,[rsi+8*5]
 add r14, rax
 adc rcx, 0
 add r14, rbp
 adc rcx, 0
 mov rbp, rcx
 add r15, rbp
 adc rbx, 0
 mov rax, [rsi+8*3]
 mul qword [rsi+8*4]
 add r14, rax
 adc rdx, 0
 add r15, rdx
 adc rbx, 0
 mov rdx, [rsi+8*0]
 xor rcx, rcx
 add r8, r8
 adc r9, r9
 adc r10, r10
 adc r11, r11
 adc r12, r12
 adc r13, r13
 adc r14, r14
 adc rcx, 0
 mulx rax,rdx,rdx
 mov [rdi+8*0], rdx
 mov rdx, [rsi+8*1]
 add r8, rax
 mov [rdi+8*1], r8
 mulx rax,rdx,rdx
 adc r9, rdx
 mov [rdi+8*2], r9
 mov rdx, [rsi+8*2]
 adc r10, rax
 mov [rdi+8*3], r10
 mulx rax,rdx,rdx
 adc r11, rdx
 mov [rdi+8*4], r11
 mov rdx, [rsi+8*3]
 adc r12, rax
 mov [rdi+8*5], r12
 mulx rax,rdx,rdx
 adc r13, rdx
 mov [rdi+8*6], r13
 adc r14, rax
 mov [rdi+8*7], r14
 adc rcx, 0
 mov rax, [rsi+8*1]
 xor r8, r8
 mul qword [rsi+8*7]
 add r15, rax
 adc rdx, 0
 add rbx, rdx
 adc r8, 0
 mov rdx, [rsi+8*2]
 mulx r14,rax,[rsi+8*6]
 add r15, rax
 adc rbx, r14
 adc r8, 0
 mulx r14,rax,[rsi+8*7]
 xor r9, r9
 add rbx, rax
 adc r8, r14
 adc r9, 0
 mov rdx, [rsi+8*3]
 mulx r14,rax,[rsi+8*5]
 add r15, rax
 adc r14, 0
 add rbx, r14
 adc r8, 0
 adc r9, 0
 mulx r14,rax,[rsi+8*6]
 add rbx, rax
 adc r14, 0
 add r8, r14
 adc r9, 0
 mulx r14,rax,[rsi+8*7]
 add r8, rax
 adc r14, 0
 add r9, r14
 mov rdx, [rsi+8*4]
 mulx r10,rax,[rsi+8*5]
 add rbx, rax
 adc r10, 0
 mulx r14,rax,[rsi+8*6]
 add r8, rax
 adc r14, 0
 add r8, r10
 adc r14, 0
 mov r10, r14
 mulx r14,rax,[rsi+8*7]
 add r9, rax
 adc r14, 0
 add r9, r10
 adc r14, 0
 mov r10, r14
 mov rdx, [rsi+8*5]
 mulx r11,rax,[rsi+8*6]
 add r9, rax
 adc r11, 0
 mulx r14,rax,[rsi+8*7]
 add r10, rax
 adc r14, 0
 add r10, r11
 adc r14, 0
 mov r11, r14
 mov rax, [rsi+8*6]
 mul qword [rsi+8*7]
 add r11, rax
 adc rdx, 0
 mov r12, rdx
 mov rdx, [rsi+8*4]
 xor r13, r13
 add r15, r15
 adc rbx, rbx
 adc r8, r8
 adc r9, r9
 adc r10, r10
 adc r11, r11
 adc r12, r12
 adc r13, 0
 mulx rax,rdx,rdx
 add rdx, rcx
 adc rax, 0
 add r15, rdx
 mov rdx, [rsi+8*5]
 mov [rdi+8*8], r15
 adc rbx, rax
 mov [rdi+8*9], rbx
 mulx rax,rdx,rdx
 adc r8, rdx
 mov [rdi+8*10], r8
 mov rdx, [rsi+8*6]
 adc r9, rax
 mov [rdi+8*11], r9
 mulx rax,rdx,rdx
 adc r10, rdx
 mov [rdi+8*12], r10
 mov rdx, [rsi+8*7]
 adc r11, rax
 mov [rdi+8*13], r11
 mulx rax,rdx,rdx
 adc r12, rdx
 mov [rdi+8*14], r12
 adc r13, rax
 mov [rdi+8*15], r13
 ret
.LEnd_sqr_8:
align 64
 add_diag_4:
 db 0F3h, 00Fh, 01Eh, 0FAh
mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 xor rbp, rbp
 add r8, r8
 adc r9, r9
 adc r10,r10
 adc r11,r11
 adc r12,r12
 adc r13,r13
 adc r14,r14
 adc r15,r15
 adc rbp, 0
 mov rdx, [rsi+8*0]
 mulx rdx,rax,rdx
 add rax, rbx
 adc rdx, 0
 add r8, rax
 mov rbx, rbp
 adc r9, rdx
 mov rdx, [rsi+8*1]
 mulx rdx,rax,rdx
 adc r10,rax
 adc r11,rdx
 mov rdx, [rsi+8*2]
 mulx rdx,rax,rdx
 adc r12,rax
 adc r13,rdx
 mov rdx, [rsi+8*3]
 mulx rdx,rax,rdx
 adc r14,rax
 adc r15,rdx
 adc rbx, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2], r10
 mov qword [rdi+8*3], r11
 mov qword [rdi+8*4], r12
 mov qword [rdi+8*5], r13
 mov qword [rdi+8*6], r14
 mov qword [rdi+8*7], r15
 ret
.LEnd_add_diag_4:
align 64
 sqr8_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mov rdx, [rsi+8*0]
 mov [rdi+8*0], r8
 mulx rbp,rax,[rsi+8*1]
 add r9, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*2]
 add r10, rax
 adc rbx, 0
 add r10, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*3]
 add r11, rax
 adc rbp, 0
 add r11, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*4]
 add r12, rax
 adc rbx, 0
 add r12, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*5]
 add r13, rax
 adc rbp, 0
 add r13, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, [rsi+8*1]
 mov [rdi+8*1], r9
 mulx rbx,rax,[rsi+8*2]
 add r11, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*3]
 add r12, rax
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*4]
 add r13, rax
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*5]
 add r14, rax
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6]
 add r15, rax
 adc rbx, 0
 add r15, rbp
 adc rbx, 0
 mulx r9,rax,[rsi+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, [rsi+8*2]
 mov [rdi+8*2], r10
 mulx rbp,rax,[rsi+8*3]
 add r13, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*4]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*5]
 add r15, rax
 adc rbp, 0
 add r15, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6]
 add r8, rax
 adc rbx, 0
 add r8, rbp
 adc rbx, 0
 mulx r10,rax,[rsi+8*7]
 add r9, rax
 adc r10, 0
 add r9, rbx
 adc r10, 0
 mov rdx, [rsi+8*3]
 mov [rdi+8*3], r11
 mulx rbx,rax,[rsi+8*4]
 add r15, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*5]
 add r8, rax
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6]
 add r9, rax
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx r11,rax,[rsi+8*7]
 add r10, rax
 adc r11, 0
 add r10, rbx
 adc r11, 0
 mov rdx, [rsi+8*4]
 mov [rdi+8*4], r12
 mulx rbp,rax,[rsi+8*5]
 add r9, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6]
 add r10, rax
 adc rbx, 0
 add r10, rbp
 adc rbx, 0
 mulx r12,rax,[rsi+8*7]
 add r11, rax
 adc r12, 0
 add r11, rbx
 adc r12, 0
 mov rdx, [rsi+8*5]
 mov [rdi+8*5], r13
 mulx rbx,rax,[rsi+8*6]
 add r11, rax
 adc rbx, 0
 mulx r13,rax,[rsi+8*7]
 add r12, rax
 adc r13, 0
 add r12, rbx
 adc r13, 0
 mov rdx, [rsi+8*6]
 mov [rdi+8*6], r14
 mulx r14,rax,[rsi+8*7]
 add r13, rax
 adc r14, 0
 ret
.LEnd_sqr8_triangle:
align 64
 sqr_9:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 xor r15, r15
 call mla_8x1
 mov qword [rdi+8*(1+0)], r8
 mov qword [rdi+8*(1+1)], r9
 mov qword [rdi+8*(1+2)], r10
 mov qword [rdi+8*(1+3)], r11
 mov qword [rdi+8*(1+4)], r12
 mov qword [rdi+8*(1+5)], r13
 mov qword [rdi+8*(1+6)], r14
 mov qword [rdi+8*(1+7)], r15
 xor rbx, rbx
 mov qword [rdi+8*(1+8)], rbx
 sub rdi, 8*8
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 xor rbp, rbp
 add r8, r8
 adc r9, r9
 adc rbp, 0
 mov rdx, [rsi+8*0]
 mulx rdx,rax,rdx
 add rax, rbx
 adc rdx, 0
 add r8, rax
 mov rbx, rbp
 adc r9, rdx
 adc rbx, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 sub rsi, 8*8
 sub rdi, 8*16
 ret
.LEnd_sqr_9:
align 64
 sqr_10:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 xor r15, r15
 call mla_8x2
 mov qword [rdi+8*(2+0)], r8
 mov qword [rdi+8*(2+1)], r9
 mov qword [rdi+8*(2+2)], r10
 mov qword [rdi+8*(2+3)], r11
 mov qword [rdi+8*(2+4)], r12
 mov qword [rdi+8*(2+5)], r13
 mov qword [rdi+8*(2+6)], r14
 mov rdx, qword [rsi+8*8]
 mulx r8,rax,[rsi+8*2+8*7]
 add r15, rax
 adc r8, 0
 xor rbx, rbx
 mov qword [rdi+8*(2+7)], r15
 mov qword [rdi+8*(2+8)], r8
 mov qword [rdi+8*(2+9)], rbx
 sub rdi, 8*8
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 xor rbp, rbp
 add r8, r8
 adc r9, r9
 adc r10,r10
 adc r11,r11
 adc rbp, 0
 mov rdx, [rsi+8*0]
 mulx rdx,rax,rdx
 add rax, rbx
 adc rdx, 0
 add r8, rax
 mov rbx, rbp
 adc r9, rdx
 mov rdx, [rsi+8*1]
 mulx rdx,rax,rdx
 adc r10,rax
 adc r11,rdx
 adc rbx, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2], r10
 mov qword [rdi+8*3], r11
 sub rsi, 8*8
 sub rdi, 8*16
 ret
.LEnd_sqr_10:
align 64
 sqr_11:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 xor r15, r15
 call mla_8x1
 add rdi, 8*1
 add rcx, 8*1
 call mla_8x2
 sub rdi, 8*1
 sub rcx, 8*1
 mov qword [rdi+8*(3+0)], r8
 mov qword [rdi+8*(3+1)], r9
 mov qword [rdi+8*(3+2)], r10
 mov qword [rdi+8*(3+3)], r11
 mov qword [rdi+8*(3+4)], r12
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(3+5)], r13
 mulx rbx,rax,[rsi+8*3+8*6]
 add r14, rax
 adc rbx, 0
 mulx r8,rax,[rsi+8*3+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(3+6)], r14
 mulx r9,rax,[rsi+8*3+8*7]
 add r8, rax
 adc r9, 0
 xor rbx, rbx
 mov qword [rdi+8*(3+7)], r15
 mov qword [rdi+8*(3+8)], r8
 mov qword [rdi+8*(3+9)], r9
 mov qword [rdi+8*(3+10)],rbx
 sub rdi, 8*8
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 xor rbp, rbp
 add r8, r8
 adc r9, r9
 adc r10,r10
 adc r11,r11
 adc r12,r12
 adc r13,r13
 adc rbp, 0
 mov rdx, [rsi+8*0]
 mulx rdx,rax,rdx
 add rax, rbx
 adc rdx, 0
 add r8, rax
 mov rbx, rbp
 adc r9, rdx
 mov rdx, [rsi+8*1]
 mulx rdx,rax,rdx
 adc r10,rax
 adc r11,rdx
 mov rdx, [rsi+8*2]
 mulx rdx,rax,rdx
 adc r12,rax
 adc r13,rdx
 adc rbx, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2], r10
 mov qword [rdi+8*3], r11
 mov qword [rdi+8*4], r12
 mov qword [rdi+8*5], r13
 sub rsi, 8*(4*2)
 sub rdi, 8*(8*2)
 ret
.LEnd_sqr_11:
align 64
 sqr_12:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 xor r15, r15
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 sub rdi, 8*2
 sub rcx, 8*2
 mov qword [rdi+8*(4+0)], r8
 mov qword [rdi+8*(4+1)], r9
 mov qword [rdi+8*(4+2)], r10
 mov qword [rdi+8*(4+3)], r11
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(4+4)], r12
 mulx rbp,rax,[rsi+8*4+8*5]
 add r13, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*4+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*4+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(4+5)], r13
 mulx rbx,rax,[rsi+8*4+8*6]
 add r15, rax
 adc rbx, 0
 mulx r9,rax,[rsi+8*4+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, qword [rsi+8*10]
 mov [rdi+8*(4+6)], r14
 mulx r10,rax,[rsi+8*4+8*7]
 add r9, rax
 adc r10, 0
 xor rbx, rbx
 mov qword [rdi+8*(4+7)], r15
 mov qword [rdi+8*(4+8)], r8
 mov qword [rdi+8*(4+9)], r9
 mov qword [rdi+8*(4+10)],r10
 mov qword [rdi+8*(4+11)],rbx
 sub rdi, 8*8
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 sub rsi, 8*(4*2)
 sub rdi, 8*(8*2)
 ret
.LEnd_sqr_12:
align 64
 sqr_13:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 xor r15, r15
 call mla_8x1
 add rdi, 8
 add rcx, 8
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 sub rdi, 8*3
 sub rcx, 8*3
 mov qword [rdi+8*(5+0)], r8
 mov qword [rdi+8*(5+1)], r9
 mov qword [rdi+8*(5+2)], r10
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(5+3)], r11
 mulx rbx,rax,[rsi+8*5+8*4]
 add r12, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*5+8*5]
 add r13, rax
 adc rbp, 0
 add r13, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*5+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*5+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(5+4)], r12
 mulx rbp,rax,[rsi+8*5+8*5]
 add r14, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*5+8*6]
 add r15, rax
 adc rbx, 0
 add r15, rbp
 adc rbx, 0
 mulx r9,rax,[rsi+8*5+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, qword [rsi+8*10]
 mov [rdi+8*(5+5)], r13
 mulx rbx,rax,[rsi+8*5+8*6]
 add r8, rax
 adc rbx, 0
 mulx r10,rax,[rsi+8*5+8*7]
 add r9, rax
 adc r10, 0
 add r9, rbx
 adc r10, 0
 mov rdx, qword [rsi+8*11]
 mov [rdi+8*(5+6)], r14
 mulx r11,rax,[rsi+8*5+8*7]
 add r10, rax
 adc r11, 0
 xor rbx, rbx
 mov qword [rdi+8*(5+7)], r15
 mov qword [rdi+8*(5+8)], r8
 mov qword [rdi+8*(5+9)], r9
 mov qword [rdi+8*(5+10)],r10
 mov qword [rdi+8*(5+11)],r11
 mov qword [rdi+8*(5+12)],rbx
 sub rdi, 8*8
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 xor rbp, rbp
 add r8, r8
 adc r9, r9
 adc rbp, 0
 mov rdx, [rsi+8*0]
 mulx rdx,rax,rdx
 add rax, rbx
 adc rdx, 0
 add r8, rax
 mov rbx, rbp
 adc r9, rdx
 adc rbx, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 sub rsi, 8*(4*3)
 sub rdi, 8*(8*3)
 ret
.LEnd_sqr_13:
align 64
 sqr_14:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 xor r15, r15
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 sub rdi, 8*4
 sub rcx, 8*4
 mov qword [rdi+8*(6+0)], r8
 mov qword [rdi+8*(6+1)], r9
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(6+2)], r10
 mulx rbp,rax,[rsi+8*6+8*3]
 add r11, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6+8*4]
 add r12, rax
 adc rbx, 0
 add r12, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*6+8*5]
 add r13, rax
 adc rbp, 0
 add r13, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*6+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(6+3)], r11
 mulx rbx,rax,[rsi+8*6+8*4]
 add r13, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*6+8*5]
 add r14, rax
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6+8*6]
 add r15, rax
 adc rbx, 0
 add r15, rbp
 adc rbx, 0
 mulx r9,rax,[rsi+8*6+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, qword [rsi+8*10]
 mov [rdi+8*(6+4)], r12
 mulx rbp,rax,[rsi+8*6+8*5]
 add r15, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6+8*6]
 add r8, rax
 adc rbx, 0
 add r8, rbp
 adc rbx, 0
 mulx r10,rax,[rsi+8*6+8*7]
 add r9, rax
 adc r10, 0
 add r9, rbx
 adc r10, 0
 mov rdx, qword [rsi+8*11]
 mov [rdi+8*(6+5)], r13
 mulx rbx,rax,[rsi+8*6+8*6]
 add r9, rax
 adc rbx, 0
 mulx r11,rax,[rsi+8*6+8*7]
 add r10, rax
 adc r11, 0
 add r10, rbx
 adc r11, 0
 mov rdx, qword [rsi+8*12]
 mov [rdi+8*(6+6)], r14
 mulx r12,rax,[rsi+8*6+8*7]
 add r11, rax
 adc r12, 0
 xor rbx, rbx
 mov qword [rdi+8*(6+7)], r15
 mov qword [rdi+8*(6+8)], r8
 mov qword [rdi+8*(6+9)], r9
 mov qword [rdi+8*(6+10)],r10
 mov qword [rdi+8*(6+11)],r11
 mov qword [rdi+8*(6+12)],r12
 mov qword [rdi+8*(6+13)],rbx
 sub rdi, 8*8
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 xor rbp, rbp
 add r8, r8
 adc r9, r9
 adc r10,r10
 adc r11,r11
 adc rbp, 0
 mov rdx, [rsi+8*0]
 mulx rdx,rax,rdx
 add rax, rbx
 adc rdx, 0
 add r8, rax
 mov rbx, rbp
 adc r9, rdx
 mov rdx, [rsi+8*1]
 mulx rdx,rax,rdx
 adc r10,rax
 adc r11,rdx
 adc rbx, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2], r10
 mov qword [rdi+8*3], r11
 sub rsi, 8*(4*3)
 sub rdi, 8*(8*3)
 ret
.LEnd_sqr_14:
align 64
 sqr_15:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 xor r15, r15
 call mla_8x1
 add rdi, 8
 add rcx, 8
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 sub rdi, 8*5
 sub rcx, 8*5
 mov qword [rdi+8*(7+0)], r8
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(7+1)], r9
 mulx rbx,rax,[rsi+8*7+8*2]
 add r10, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*7+8*3]
 add r11, rax
 adc rbp, 0
 add r11, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*4]
 add r12, rax
 adc rbx, 0
 add r12, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*7+8*5]
 add r13, rax
 adc rbp, 0
 add r13, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*7+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(7+2)], r10
 mulx rbp,rax,[rsi+8*7+8*3]
 add r12, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*4]
 add r13, rax
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*7+8*5]
 add r14, rax
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*6]
 add r15, rax
 adc rbx, 0
 add r15, rbp
 adc rbx, 0
 mulx r9,rax,[rsi+8*7+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, qword [rsi+8*10]
 mov [rdi+8*(7+3)], r11
 mulx rbx,rax,[rsi+8*7+8*4]
 add r14, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*7+8*5]
 add r15, rax
 adc rbp, 0
 add r15, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*6]
 add r8, rax
 adc rbx, 0
 add r8, rbp
 adc rbx, 0
 mulx r10,rax,[rsi+8*7+8*7]
 add r9, rax
 adc r10, 0
 add r9, rbx
 adc r10, 0
 mov rdx, qword [rsi+8*11]
 mov [rdi+8*(7+4)], r12
 mulx rbp,rax,[rsi+8*7+8*5]
 add r8, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*6]
 add r9, rax
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx r11,rax,[rsi+8*7+8*7]
 add r10, rax
 adc r11, 0
 add r10, rbx
 adc r11, 0
 mov rdx, qword [rsi+8*12]
 mov [rdi+8*(7+5)], r13
 mulx rbx,rax,[rsi+8*7+8*6]
 add r10, rax
 adc rbx, 0
 mulx r12,rax,[rsi+8*7+8*7]
 add r11, rax
 adc r12, 0
 add r11, rbx
 adc r12, 0
 mov rdx, qword [rsi+8*13]
 mov [rdi+8*(7+6)], r14
 mulx r13,rax,[rsi+8*7+8*7]
 add r12, rax
 adc r13, 0
 xor rbx, rbx
 mov qword [rdi+8*(7+7)], r15
 mov qword [rdi+8*(7+8)], r8
 mov qword [rdi+8*(7+9)], r9
 mov qword [rdi+8*(7+10)],r10
 mov qword [rdi+8*(7+11)],r11
 mov qword [rdi+8*(7+12)],r12
 mov qword [rdi+8*(7+13)],r13
 mov qword [rdi+8*(7+14)],rbx
 sub rdi, 8*8
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 xor rbp, rbp
 add r8, r8
 adc r9, r9
 adc r10,r10
 adc r11,r11
 adc r12,r12
 adc r13,r13
 adc rbp, 0
 mov rdx, [rsi+8*0]
 mulx rdx,rax,rdx
 add rax, rbx
 adc rdx, 0
 add r8, rax
 mov rbx, rbp
 adc r9, rdx
 mov rdx, [rsi+8*1]
 mulx rdx,rax,rdx
 adc r10,rax
 adc r11,rdx
 mov rdx, [rsi+8*2]
 mulx rdx,rax,rdx
 adc r12,rax
 adc r13,rdx
 adc rbx, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2], r10
 mov qword [rdi+8*3], r11
 mov qword [rdi+8*4], r12
 mov qword [rdi+8*5], r13
 sub rsi, 8*(4*3)
 sub rdi, 8*(8*3)
 ret
.LEnd_sqr_15:
align 64
 sqr_16:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 mov rcx, rsi
 add rsi, 8*8
 add rdi, 8*8
 xor r15, r15
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 add rdi, 8*2
 add rcx, 8*2
 call mla_8x2
 sub rdi, 8*6
 sub rcx, 8*6
 add rdi, 8*8
 call sqr8_triangle
 xor rbx, rbx
 mov qword [rdi+8*7], r15
 mov qword [rdi+8*8], r8
 mov qword [rdi+8*9], r9
 mov qword [rdi+8*10],r10
 mov qword [rdi+8*11],r11
 mov qword [rdi+8*12],r12
 mov qword [rdi+8*13],r13
 mov qword [rdi+8*14],r14
 mov qword [rdi+8*15],rbx
 sub rsi, 8*8
 sub rdi, 8*16
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 call add_diag_4
 sub rsi, 8*12
 sub rdi, 8*24
 ret
.LEnd_sqr_16:
align 64
 sqr9_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 xor r15, r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 call mla_8x1
 xor rax, rax
 mov qword [rdi+8*(1+0)], r8
 mov qword [rdi+8*(1+1)], r9
 mov qword [rdi+8*(1+2)], r10
 mov qword [rdi+8*(1+3)], r11
 mov qword [rdi+8*(1+4)], r12
 mov qword [rdi+8*(1+5)], r13
 mov qword [rdi+8*(1+6)], r14
 mov qword [rdi+8*(1+7)], r15
 mov qword [rdi+8*(1+8)], rax
 sub rdi, 8*8
 ret
.LEnd_sqr9_triangle:
align 64
 sqr10_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 xor r15, r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 call mla_8x2
 mov qword [rdi+8*(2+0)], r8
 mov qword [rdi+8*(2+1)], r9
 mov qword [rdi+8*(2+2)], r10
 mov qword [rdi+8*(2+3)], r11
 mov qword [rdi+8*(2+4)], r12
 mov qword [rdi+8*(2+5)], r13
 mov qword [rdi+8*(2+6)], r14
 mov rdx, qword [rsi+8*8]
 mulx r8,rax,[rsi+8*2+8*7]
 add r15, rax
 adc r8, 0
 xor rax, rax
 mov qword [rdi+8*(2+7)], r15
 mov qword [rdi+8*(2+8)], r8
 mov qword [rdi+8*(2+9)], rax
 sub rdi, 8*8
 ret
.LEnd_sqr10_triangle:
align 64
 sqr11_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 xor r15, r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 call mla_8x3
 mov qword [rdi+8*(3+0)], r8
 mov qword [rdi+8*(3+1)], r9
 mov qword [rdi+8*(3+2)], r10
 mov qword [rdi+8*(3+3)], r11
 mov qword [rdi+8*(3+4)], r12
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(3+5)], r13
 mulx rbx,rax,[rsi+8*3+8*6]
 add r14, rax
 adc rbx, 0
 mulx r8,rax,[rsi+8*3+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(3+6)], r14
 mulx r9,rax,[rsi+8*3+8*7]
 add r8, rax
 adc r9, 0
 xor rax, rax
 mov qword [rdi+8*(3+7)], r15
 mov qword [rdi+8*(3+8)], r8
 mov qword [rdi+8*(3+9)], r9
 mov qword [rdi+8*(3+10)],rax
 sub rdi, 8*8
 ret
.LEnd_sqr11_triangle:
align 64
 sqr12_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 xor r15, r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 call mla_8x4
 mov qword [rdi+8*(4+0)], r8
 mov qword [rdi+8*(4+1)], r9
 mov qword [rdi+8*(4+2)], r10
 mov qword [rdi+8*(4+3)], r11
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(4+4)], r12
 mulx rbp,rax,[rsi+8*4+8*5]
 add r13, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*4+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*4+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(4+5)], r13
 mulx rbx,rax,[rsi+8*4+8*6]
 add r15, rax
 adc rbx, 0
 mulx r9,rax,[rsi+8*4+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, qword [rsi+8*10]
 mov [rdi+8*(4+6)], r14
 mulx r10,rax,[rsi+8*4+8*7]
 add r9, rax
 adc r10, 0
 xor rax, rax
 mov qword [rdi+8*(4+7)], r15
 mov qword [rdi+8*(4+8)], r8
 mov qword [rdi+8*(4+9)], r9
 mov qword [rdi+8*(4+10)],r10
 mov qword [rdi+8*(4+11)],rax
 sub rdi, 8*8
 ret
.LEnd_sqr12_triangle:
align 64
 sqr13_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 xor r15, r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 call mla_8x5
 mov qword [rdi+8*(5+0)], r8
 mov qword [rdi+8*(5+1)], r9
 mov qword [rdi+8*(5+2)], r10
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(5+3)], r11
 mulx rbx,rax,[rsi+8*5+8*4]
 add r12, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*5+8*5]
 add r13, rax
 adc rbp, 0
 add r13, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*5+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*5+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(5+4)], r12
 mulx rbp,rax,[rsi+8*5+8*5]
 add r14, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*5+8*6]
 add r15, rax
 adc rbx, 0
 add r15, rbp
 adc rbx, 0
 mulx r9,rax,[rsi+8*5+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, qword [rsi+8*10]
 mov [rdi+8*(5+5)], r13
 mulx rbx,rax,[rsi+8*5+8*6]
 add r8, rax
 adc rbx, 0
 mulx r10,rax,[rsi+8*5+8*7]
 add r9, rax
 adc r10, 0
 add r9, rbx
 adc r10, 0
 mov rdx, qword [rsi+8*11]
 mov [rdi+8*(5+6)], r14
 mulx r11,rax,[rsi+8*5+8*7]
 add r10, rax
 adc r11, 0
 xor rax, rax
 mov qword [rdi+8*(5+7)], r15
 mov qword [rdi+8*(5+8)], r8
 mov qword [rdi+8*(5+9)], r9
 mov qword [rdi+8*(5+10)],r10
 mov qword [rdi+8*(5+11)],r11
 mov qword [rdi+8*(5+12)],rax
 sub rdi, 8*8
 ret
.LEnd_sqr13_triangle:
align 64
 sqr14_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 xor r15, r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 call mla_8x6
 mov qword [rdi+8*(6+0)], r8
 mov qword [rdi+8*(6+1)], r9
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(6+2)], r10
 mulx rbp,rax,[rsi+8*6+8*3]
 add r11, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6+8*4]
 add r12, rax
 adc rbx, 0
 add r12, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*6+8*5]
 add r13, rax
 adc rbp, 0
 add r13, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*6+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(6+3)], r11
 mulx rbx,rax,[rsi+8*6+8*4]
 add r13, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*6+8*5]
 add r14, rax
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6+8*6]
 add r15, rax
 adc rbx, 0
 add r15, rbp
 adc rbx, 0
 mulx r9,rax,[rsi+8*6+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, qword [rsi+8*10]
 mov [rdi+8*(6+4)], r12
 mulx rbp,rax,[rsi+8*6+8*5]
 add r15, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*6+8*6]
 add r8, rax
 adc rbx, 0
 add r8, rbp
 adc rbx, 0
 mulx r10,rax,[rsi+8*6+8*7]
 add r9, rax
 adc r10, 0
 add r9, rbx
 adc r10, 0
 mov rdx, qword [rsi+8*11]
 mov [rdi+8*(6+5)], r13
 mulx rbx,rax,[rsi+8*6+8*6]
 add r9, rax
 adc rbx, 0
 mulx r11,rax,[rsi+8*6+8*7]
 add r10, rax
 adc r11, 0
 add r10, rbx
 adc r11, 0
 mov rdx, qword [rsi+8*12]
 mov [rdi+8*(6+6)], r14
 mulx r12,rax,[rsi+8*6+8*7]
 add r11, rax
 adc r12, 0
 xor rax, rax
 mov qword [rdi+8*(6+7)], r15
 mov qword [rdi+8*(6+8)], r8
 mov qword [rdi+8*(6+9)], r9
 mov qword [rdi+8*(6+10)],r10
 mov qword [rdi+8*(6+11)],r11
 mov qword [rdi+8*(6+12)],r12
 mov qword [rdi+8*(6+13)],rax
 sub rdi, 8*8
 ret
.LEnd_sqr14_triangle:
align 64
 sqr15_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 xor r15, r15
 lea rcx, [rsi+8*8]
 add rdi, 8*8
 call mla_8x7
 mov qword [rdi+8*(7+0)], r8
 mov rdx, qword [rsi+8*8]
 mov [rdi+8*(7+1)], r9
 mulx rbx,rax,[rsi+8*7+8*2]
 add r10, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*7+8*3]
 add r11, rax
 adc rbp, 0
 add r11, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*4]
 add r12, rax
 adc rbx, 0
 add r12, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*7+8*5]
 add r13, rax
 adc rbp, 0
 add r13, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*6]
 add r14, rax
 adc rbx, 0
 add r14, rbp
 adc rbx, 0
 mulx r8,rax,[rsi+8*7+8*7]
 add r15, rax
 adc r8, 0
 add r15, rbx
 adc r8, 0
 mov rdx, qword [rsi+8*9]
 mov [rdi+8*(7+2)], r10
 mulx rbp,rax,[rsi+8*7+8*3]
 add r12, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*4]
 add r13, rax
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mulx rbp,rax,[rsi+8*7+8*5]
 add r14, rax
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*6]
 add r15, rax
 adc rbx, 0
 add r15, rbp
 adc rbx, 0
 mulx r9,rax,[rsi+8*7+8*7]
 add r8, rax
 adc r9, 0
 add r8, rbx
 adc r9, 0
 mov rdx, qword [rsi+8*10]
 mov [rdi+8*(7+3)], r11
 mulx rbx,rax,[rsi+8*7+8*4]
 add r14, rax
 adc rbx, 0
 mulx rbp,rax,[rsi+8*7+8*5]
 add r15, rax
 adc rbp, 0
 add r15, rbx
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*6]
 add r8, rax
 adc rbx, 0
 add r8, rbp
 adc rbx, 0
 mulx r10,rax,[rsi+8*7+8*7]
 add r9, rax
 adc r10, 0
 add r9, rbx
 adc r10, 0
 mov rdx, qword [rsi+8*11]
 mov [rdi+8*(7+4)], r12
 mulx rbp,rax,[rsi+8*7+8*5]
 add r8, rax
 adc rbp, 0
 mulx rbx,rax,[rsi+8*7+8*6]
 add r9, rax
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx r11,rax,[rsi+8*7+8*7]
 add r10, rax
 adc r11, 0
 add r10, rbx
 adc r11, 0
 mov rdx, qword [rsi+8*12]
 mov [rdi+8*(7+5)], r13
 mulx rbx,rax,[rsi+8*7+8*6]
 add r10, rax
 adc rbx, 0
 mulx r12,rax,[rsi+8*7+8*7]
 add r11, rax
 adc r12, 0
 add r11, rbx
 adc r12, 0
 mov rdx, qword [rsi+8*13]
 mov [rdi+8*(7+6)], r14
 mulx r13,rax,[rsi+8*7+8*7]
 add r12, rax
 adc r13, 0
 xor rax, rax
 mov qword [rdi+8*(7+7)], r15
 mov qword [rdi+8*(7+8)], r8
 mov qword [rdi+8*(7+9)], r9
 mov qword [rdi+8*(7+10)],r10
 mov qword [rdi+8*(7+11)],r11
 mov qword [rdi+8*(7+12)],r12
 mov qword [rdi+8*(7+13)],r13
 mov qword [rdi+8*(7+14)],rax
 sub rdi, 8*8
 ret
.LEnd_sqr15_triangle:
align 64
 sqr16_triangle:
 db 0F3h, 00Fh, 01Eh, 0FAh
 call sqr8_triangle
 mov qword [rdi+8*7], r15
 xor r15, r15
 mov rcx, rsi
 add rsi, 8*8
 add rdi, 8*8
 call mla_8x8
 add rdi, 8*8
 call sqr8_triangle
 xor rax, rax
 mov qword [rdi+8*7], r15
 mov qword [rdi+8*8], r8
 mov qword [rdi+8*9], r9
 mov qword [rdi+8*10],r10
 mov qword [rdi+8*11],r11
 mov qword [rdi+8*12],r12
 mov qword [rdi+8*13],r13
 mov qword [rdi+8*14],r14
 mov qword [rdi+8*15],rax
 sub rsi, 8*8
 sub rdi, 8*16
 ret
.LEnd_sqr16_triangle:
sqr_l_basic dq sqr_1 - sqr_l_basic
 dq sqr_2 - sqr_l_basic
 dq sqr_3 - sqr_l_basic
 dq sqr_4 - sqr_l_basic
 dq sqr_5 - sqr_l_basic
 dq sqr_6 - sqr_l_basic
 dq sqr_7 - sqr_l_basic
 dq sqr_8 - sqr_l_basic
 dq sqr_9 - sqr_l_basic
 dq sqr_10- sqr_l_basic
 dq sqr_11- sqr_l_basic
 dq sqr_12- sqr_l_basic
 dq sqr_13- sqr_l_basic
 dq sqr_14- sqr_l_basic
 dq sqr_15- sqr_l_basic
 dq sqr_16- sqr_l_basic
sqrN_triangle dq sqr9_triangle - sqrN_triangle
 dq sqr10_triangle - sqrN_triangle
 dq sqr11_triangle - sqrN_triangle
 dq sqr12_triangle - sqrN_triangle
 dq sqr13_triangle - sqrN_triangle
 dq sqr14_triangle - sqrN_triangle
 dq sqr15_triangle - sqrN_triangle
 dq sqr16_triangle - sqrN_triangle
align 64
 sqr_8N:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdi
 push rsi
 push rdx
 push rdi
 push rsi
 push rdx
 push rdx
 call sqr8_triangle
 pop rdx
 mov qword [rdi+8*7], r15
 xor r15, r15
 add rdi, 8*8
 sub rdx, 8
 mov rcx, rsi
 add rsi, 8*8
.initLoop:
 push rdx
 call mla_8x8
 pop rdx
 add rsi, 8*8
 add rdi, 8*8
 sub rdx, 8
 jnz .initLoop
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 mov qword [rdi+8*4],r12
 mov qword [rdi+8*5],r13
 mov qword [rdi+8*6],r14
 mov qword [rdi+8*7],r15
 jmp .update_Triangle
.outerLoop:
 push rdi
 push rsi
 push rdx
 xor rax, rax
 push rax
 mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10, qword [rdi+8*2]
 mov r11, qword [rdi+8*3]
 mov r12, qword [rdi+8*4]
 mov r13, qword [rdi+8*5]
 mov r14, qword [rdi+8*6]
 mov r15, qword [rdi+8*7]
.innerLoop_entry:
 push rdx
 call sqr8_triangle
 pop rdx
 mov qword [rdi+8*7], r15
 xor r15, r15
 add rdi, 8*8
 sub rdx, 8
 jz .skipInnerLoop
 mov rcx, rsi
 add rsi, 8*8
.innerLoop:
 pop rax
 neg rax
 mov rax, qword [rdi+8*0]
 adc r8, rax
 mov rax, qword [rdi+8*1]
 adc r9, rax
 mov rax, qword [rdi+8*2]
 adc r10, rax
 mov rax, qword [rdi+8*3]
 adc r11, rax
 mov rax, qword [rdi+8*4]
 adc r12, rax
 mov rax, qword [rdi+8*5]
 adc r13, rax
 mov rax, qword [rdi+8*6]
 adc r14, rax
 mov rax, qword [rdi+8*7]
 adc r15, rax
 sbb rax, rax
 push rax
 push rdx
 call mla_8x8
 pop rdx
 add rsi, 8*8
 add rdi, 8*8
 sub rdx, 8
 jnz .innerLoop
.skipInnerLoop:
 pop rax
 neg rax
 adc r8, 0
 mov qword [rdi+8*0], r8
 adc r9, 0
 mov qword [rdi+8*1], r9
 adc r10,0
 mov qword [rdi+8*2],r10
 adc r11,0
 mov qword [rdi+8*3],r11
 adc r12,0
 mov qword [rdi+8*4],r12
 adc r13,0
 mov qword [rdi+8*5],r13
 adc r14,0
 mov qword [rdi+8*6],r14
 adc r15,0
 mov qword [rdi+8*7],r15
.update_Triangle:
 pop rdx
 pop rsi
 pop rdi
 add rsi, 8*8
 add rdi, 8*(8*2)
 sub rdx, 8
 jnz .outerLoop
 pop rcx
 pop rsi
 pop rdi
 xor rbx, rbx
.update_loop:
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 sub rcx, 4
 jnz .update_loop
 ret
.LEnd_sqr_8N:
align 64
 sqr_N:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdi
 push rsi
 push rdx
 push rdi
 push rsi
 push rdx
 mov rbp, rdx
 and rbp, 7
 lea rax, [rel mla_8xl_tail]
 mov rbp, [rax+rbp*8-8]
 add rax, rbp
 push rax
 sub rdx, 8
 push rdx
 call sqr8_triangle
 pop rdx
 mov qword [rdi+8*7], r15
 add rdi, 8*8
 xor r15, r15
 mov rcx, rsi
 add rsi, 8*8
 sub rdx, 8
.initLoop:
 push rdx
 call mla_8x8
 pop rdx
 add rsi, 8*8
 add rdi, 8*8
 sub rdx, 8
 jnc .initLoop
 add rdx, 8
 xor rsi, rcx
 xor rcx, rsi
 xor rsi, rcx
 mov rax, [rsp]
 push rdx
 call rax
 pop rdx
 lea rdi, [rdi+rdx*8]
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2],r10
 mov qword [rdi+8*3],r11
 mov qword [rdi+8*4],r12
 mov qword [rdi+8*5],r13
 mov qword [rdi+8*6],r14
 mov qword [rdi+8*7],r15
 jmp .update_Triangle
.outerLoop:
 push rdi
 push rsi
 push rdx
 push rax
 xor rax, rax
 push rax
 mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10, qword [rdi+8*2]
 mov r11, qword [rdi+8*3]
 mov r12, qword [rdi+8*4]
 mov r13, qword [rdi+8*5]
 mov r14, qword [rdi+8*6]
 mov r15, qword [rdi+8*7]
 sub rdx, 8
 push rdx
 call sqr8_triangle
 pop rdx
 mov qword [rdi+8*7], r15
 add rdi, 8*8
 xor r15, r15
 mov rcx, rsi
 add rsi, 8*8
 sub rdx, 8
.innerLoop:
 pop rax
 neg rax
 mov rax, qword [rdi+8*0]
 adc r8, rax
 mov rax, qword [rdi+8*1]
 adc r9, rax
 mov rax, qword [rdi+8*2]
 adc r10, rax
 mov rax, qword [rdi+8*3]
 adc r11, rax
 mov rax, qword [rdi+8*4]
 adc r12, rax
 mov rax, qword [rdi+8*5]
 adc r13, rax
 mov rax, qword [rdi+8*6]
 adc r14, rax
 mov rax, qword [rdi+8*7]
 adc r15, rax
 sbb rax, rax
 push rax
 push rdx
 call mla_8x8
 pop rdx
 add rsi, 8*8
 add rdi, 8*8
 sub rdx, 8
 jnc .innerLoop
 add rdx, 8
 pxor xmm0, xmm0
 movdqu OWORD [rdi+rdx*8], xmm0
 movdqu OWORD [rdi+rdx*8+8*2], xmm0
 movdqu OWORD [rdi+rdx*8+8*4], xmm0
 movdqu OWORD [rdi+rdx*8+8*6], xmm0
 pop rax
 neg rax
 mov rax, qword [rdi+8*0]
 adc r8, rax
 mov rax, qword [rdi+8*1]
 adc r9, rax
 mov rax, qword [rdi+8*2]
 adc r10, rax
 mov rax, qword [rdi+8*3]
 adc r11, rax
 mov rax, qword [rdi+8*4]
 adc r12, rax
 mov rax, qword [rdi+8*5]
 adc r13, rax
 mov rax, qword [rdi+8*6]
 adc r14, rax
 mov rax, qword [rdi+8*7]
 adc r15, rax
 sbb rax, rax
 neg rax
 mov qword [rdi+8*8], rax
 xor rsi, rcx
 xor rcx, rsi
 xor rsi, rcx
 mov rax, [rsp]
 push rdx
 call rax
 pop rdx
 lea rdi, [rdi+rdx*8]
 xor rax, rax
 mov rax, qword [rdi+8*0]
 add r8, rax
 mov qword [rdi+8*0], r8
 mov rax, qword [rdi+8*1]
 adc r9, rax
 mov qword [rdi+8*1], r9
 mov rax, qword [rdi+8*2]
 adc r10, rax
 mov qword [rdi+8*2], r10
 mov rax, qword [rdi+8*3]
 adc r11, rax
 mov qword [rdi+8*3], r11
 mov rax, qword [rdi+8*4]
 adc r12, rax
 mov qword [rdi+8*4], r12
 mov rax, qword [rdi+8*5]
 adc r13, rax
 mov qword [rdi+8*5], r13
 mov rax, qword [rdi+8*6]
 adc r14, rax
 mov qword [rdi+8*6], r14
 mov rax, qword [rdi+8*7]
 adc r15, rax
 mov qword [rdi+8*7], r15
.update_Triangle:
 pop rax
 pop rdx
 pop rsi
 pop rdi
 add rsi, 8*8
 add rdi, 8*(8*2)
 sub rdx, 8
 cmp rdx, 16
 jg .outerLoop
 mov rbp, rdx
 sub rbp, 8
 lea rax, [rel sqrN_triangle]
 mov rbp, [rax+rbp*8-8]
 add rax, rbp
 sub rsp, 8*32
 push rdi
 push rdx
 mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 lea rdi, [rsp+8*2]
 call rax
 mov rsi, rdi
 pop rdx
 pop rdi
 movdqu xmm0, OWORD [rsi]
 movdqu xmm1, OWORD [rsi+8*2]
 movdqu xmm2, OWORD [rsi+8*4]
 movdqu xmm3, OWORD [rsi+8*6]
 add rsi, 8*8
 movdqu OWORD [rdi], xmm0
 movdqu OWORD [rdi+8*2], xmm1
 movdqu OWORD [rdi+8*4], xmm2
 movdqu OWORD [rdi+8*6], xmm3
 add rdi, 8*8
 lea rax, [rdx-8]
 xor rbx, rbx
.update1:
 mov r8, qword [rsi]
 mov r9, qword [rdi]
 add rsi, 8
 neg rbx
 adc r8, r9
 sbb rbx, rbx
 mov qword [rdi], r8
 add rdi, 8
 sub rax, 1
 jg .update1
.update2:
 mov r8, qword [rsi]
 add rsi, 8
 neg rbx
 adc r8, 0
 sbb rbx, rbx
 mov qword [rdi], r8
 add rdi, 8
 sub rdx, 1
 jg .update2
 add rsp, 8*32
.add_diagonals:
 pop rcx
 pop rsi
 pop rdi
 sub rcx, 4
 xor rbx, rbx
.add_diagonal_loop:
 call add_diag_4
 add rdi, 8*8
 add rsi, 8*4
 sub rcx, 4
 jnc .add_diagonal_loop
 add rcx, 4
 jz .quit
.add_diagonal_rest:
mov r8, qword [rdi+8*0]
 mov r9, qword [rdi+8*1]
 xor rbp, rbp
 add r8, r8
 adc r9, r9
 adc rbp, 0
 mov rdx, [rsi+8*0]
 mulx rdx,rax,rdx
 add rax, rbx
 adc rdx, 0
 add r8, rax
 mov rbx, rbp
 adc r9, rdx
 adc rbx, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 add rdi, 8*2
 add rsi, 8
 sub rcx, 1
 jnz .add_diagonal_rest
.quit:
 ret
.LEnd_sqr_N:
align 64
 sub_N:
 db 0F3h, 00Fh, 01Eh, 0FAh
 xor rax, rax
.sub_next:
 lea rdi, [rdi+8]
 mov r8, qword [rsi]
 mov r9, qword [rcx]
 lea rsi, [rsi+8]
 lea rcx, [rcx+8]
 sbb r8, r9
 mov qword [rdi-8], r8
 dec rdx
 jnz .sub_next
 adc rax, 0
 ret
.LEnd_sub_N:
align 64
 copy_ae_N:
 db 0F3h, 00Fh, 01Eh, 0FAh
 lea rdi, [rdi+8]
 mov r8, qword [rsi]
 mov r9, qword [rcx]
 lea rsi, [rsi+8]
 lea rcx, [rcx+8]
 cmovae r8, r9
 mov qword [rdi-8], r8
 dec rdx
 jnz copy_ae_N
 ret
.LEnd_copy_ae_N:
align 64
 mred1_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov r8, rbx
 ret
.LEnd_mred1_start:
align 64
 mred2_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mov r9, rbp
 ret
.LEnd_mred2_start:
align 64
 mred3_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mov r10, rbx
 ret
.LEnd_mred3_start:
align 64
 mred4_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 ret
.LEnd_mred4_start:
align 64
 mred5_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mov r12, rbx
 ret
.LEnd_mred5_start:
align 64
 mred6_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mov r13, rbp
 ret
.LEnd_mred6_start:
align 64
 mred7_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mov r14, rbx
 ret
.LEnd_mred7_start:
align 64
 mred8_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*4]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mulx rbp,r12,[rsi+8*5]
 add r12, r13
 adc rbp, 0
 add r12, rbx
 adc rbp, 0
 mulx rbx,r13,[rsi+8*6]
 add r13, r14
 adc rbx, 0
 add r13, rbp
 adc rbx, 0
 mulx rbp,r14,[rsi+8*7]
 add r14, r15
 adc rbp, 0
 add r14, rbx
 adc rbp, 0
 mov r15, rbp
 ret
.LEnd_mred8_start:
align 64
 mred8x1_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdx
 mulx rbx,rdx,r8
 mov qword [rcx+8*0], rdx
 call mred8_start
 mov [rdi], rax
 pop rdx
 ret
.LEnd_mred8x1_start:
align 64
 mred8x2_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdx
 mulx rbx,rdx,r8
 mov qword [rcx+8*0], rdx
 call mred8_start
 mov [rdi], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*1], rdx
 call mred8_start
 mov [rdi+8*1], rax
 pop rdx
 ret
.LEnd_mred8x2_start:
align 64
 mred8x3_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdx
 mulx rbx,rdx,r8
 mov qword [rcx+8*0], rdx
 call mred8_start
 mov [rdi], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*1], rdx
 call mred8_start
 mov [rdi+8*1], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*2], rdx
 call mred8_start
 mov [rdi+8*2], rax
 pop rdx
 ret
.LEnd_mred8x3_start:
align 64
 mred8x4_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdx
 mulx rbx,rdx,r8
 mov qword [rcx+8*0], rdx
 call mred8_start
 mov [rdi], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*1], rdx
 call mred8_start
 mov [rdi+8*1], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*2], rdx
 call mred8_start
 mov [rdi+8*2], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*3], rdx
 call mred8_start
 mov [rdi+8*3], rax
 pop rdx
 ret
.LEnd_mred8x4_start:
align 64
 mred8x5_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdx
 mulx rbx,rdx,r8
 mov qword [rcx+8*0], rdx
 call mred8_start
 mov [rdi], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*1], rdx
 call mred8_start
 mov [rdi+8*1], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*2], rdx
 call mred8_start
 mov [rdi+8*2], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*3], rdx
 call mred8_start
 mov [rdi+8*3], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*4], rdx
 call mred8_start
 mov [rdi+8*4], rax
 pop rdx
 ret
.LEnd_mred8x5_start:
align 64
 mred8x6_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdx
 mulx rbx,rdx,r8
 mov qword [rcx+8*0], rdx
 call mred8_start
 mov [rdi], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*1], rdx
 call mred8_start
 mov [rdi+8*1], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*2], rdx
 call mred8_start
 mov [rdi+8*2], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*3], rdx
 call mred8_start
 mov [rdi+8*3], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*4], rdx
 call mred8_start
 mov [rdi+8*4], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*5], rdx
 call mred8_start
 mov [rdi+8*5], rax
 pop rdx
 ret
.LEnd_mred8x6_start:
align 64
 mred8x7_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdx
 mulx rbx,rdx,r8
 mov qword [rcx+8*0], rdx
 call mred8_start
 mov [rdi], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*1], rdx
 call mred8_start
 mov [rdi+8*1], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*2], rdx
 call mred8_start
 mov [rdi+8*2], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*3], rdx
 call mred8_start
 mov [rdi+8*3], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*4], rdx
 call mred8_start
 mov [rdi+8*4], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*5], rdx
 call mred8_start
 mov [rdi+8*5], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*6], rdx
 call mred8_start
 mov [rdi+8*6], rax
 pop rdx
 ret
.LEnd_mred8x7_start:
align 64
 mred8x8_start:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rdx
 mulx rbx,rdx,r8
 mov qword [rcx+8*0], rdx
 call mred8_start
 mov [rdi], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*1], rdx
 call mred8_start
 mov [rdi+8*1], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*2], rdx
 call mred8_start
 mov [rdi+8*2], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*3], rdx
 call mred8_start
 mov [rdi+8*3], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*4], rdx
 call mred8_start
 mov [rdi+8*4], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*5], rdx
 call mred8_start
 mov [rdi+8*5], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*6], rdx
 call mred8_start
 mov [rdi+8*6], rax
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 mov qword [rcx+8*7], rdx
 call mred8_start
 mov [rdi+8*7], rax
 pop rdx
 ret
.LEnd_mred8x8_start:
align 64
 mred_5:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred5_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred5_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred5_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred5_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred5_start
 pop rax
 xor rax, rax
 mov rbx, [rdi+8*(5+0)]
 add r8, rbx
 mov qword [rdi+8*(5+0)], r8
 mov rbx, [rdi+8*(5+1)]
 adc r9, rbx
 mov qword [rdi+8*(5+1)], r9
 mov rbx, [rdi+8*(5+2)]
 adc r10, rbx
 mov qword [rdi+8*(5+2)], r10
 mov rbx, [rdi+8*(5+3)]
 adc r11, rbx
 mov qword [rdi+8*(5+3)], r11
 mov rbx, [rdi+8*(5+4)]
 adc r12, rbx
 mov qword [rdi+8*(5+4)], r12
 adc rax, 0
 mov rbx, [rsi+8*0]
 sub r8, rbx
 mov rbx, [rsi+8*1]
 sbb r9, rbx
 mov rbx, [rsi+8*2]
 sbb r10, rbx
 mov rbx, [rsi+8*3]
 sbb r11, rbx
 mov rbx, [rsi+8*4]
 sbb r12, rbx
 sbb rax, 0
 mov rax, qword [rdi+8*(5+0)]
 mov rbx, qword [rdi+8*(5+1)]
 mov rcx, qword [rdi+8*(5+2)]
 mov rdx, qword [rdi+8*(5+3)]
 mov rbp, qword [rdi+8*(5+4)]
 cmovae rax, r8
 cmovae rbx, r9
 cmovae rcx, r10
 cmovae rdx, r11
 cmovae rbp, r12
 mov qword [r15+8*0], rax
 mov qword [r15+8*1], rbx
 mov qword [r15+8*2], rcx
 mov qword [r15+8*3], rdx
 mov qword [r15+8*4], rbp
 ret
.LEnd_mred_5:
align 64
 mred_6:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred6_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred6_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred6_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred6_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred6_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred6_start
 pop rax
 xor rax, rax
 mov rbx, [rdi+8*(6+0)]
 add r8, rbx
 mov qword [rdi+8*(6+0)], r8
 mov rbx, [rdi+8*(6+1)]
 adc r9, rbx
 mov qword [rdi+8*(6+1)], r9
 mov rbx, [rdi+8*(6+2)]
 adc r10, rbx
 mov qword [rdi+8*(6+2)], r10
 mov rbx, [rdi+8*(6+3)]
 adc r11, rbx
 mov qword [rdi+8*(6+3)], r11
 mov rbx, [rdi+8*(6+4)]
 adc r12, rbx
 mov qword [rdi+8*(6+4)], r12
 mov rbx, [rdi+8*(6+5)]
 adc r13, rbx
 mov qword [rdi+8*(6+5)], r13
 adc rax, 0
 mov rbx, [rsi+8*0]
 sub r8, rbx
 mov rbx, [rsi+8*1]
 sbb r9, rbx
 mov rbx, [rsi+8*2]
 sbb r10, rbx
 mov rbx, [rsi+8*3]
 sbb r11, rbx
 mov rbx, [rsi+8*4]
 sbb r12, rbx
 mov rbx, [rsi+8*5]
 sbb r13, rbx
 sbb rax, 0
 mov rax, qword [rdi+8*(6+0)]
 mov rbx, qword [rdi+8*(6+1)]
 mov rcx, qword [rdi+8*(6+2)]
 mov rdx, qword [rdi+8*(6+3)]
 mov rbp, qword [rdi+8*(6+4)]
 mov rsi, qword [rdi+8*(6+5)]
 cmovae rax, r8
 cmovae rbx, r9
 cmovae rcx, r10
 cmovae rdx, r11
 cmovae rbp, r12
 cmovae rsi, r13
 mov qword [r15+8*0], rax
 mov qword [r15+8*1], rbx
 mov qword [r15+8*2], rcx
 mov qword [r15+8*3], rdx
 mov qword [r15+8*4], rbp
 mov qword [r15+8*5], rsi
 ret
.LEnd_mred_6:
align 64
 mred_7:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred7_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred7_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred7_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred7_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred7_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred7_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred7_start
 pop rax
 xor rax, rax
 mov rbx, [rdi+8*(7+0)]
 add r8, rbx
 mov qword [rdi+8*(7+0)], r8
 mov rbx, [rdi+8*(7+1)]
 adc r9, rbx
 mov qword [rdi+8*(7+1)], r9
 mov rbx, [rdi+8*(7+2)]
 adc r10, rbx
 mov qword [rdi+8*(7+2)], r10
 mov rbx, [rdi+8*(7+3)]
 adc r11, rbx
 mov qword [rdi+8*(7+3)], r11
 mov rbx, [rdi+8*(7+4)]
 adc r12, rbx
 mov qword [rdi+8*(7+4)], r12
 mov rbx, [rdi+8*(7+5)]
 adc r13, rbx
 mov qword [rdi+8*(7+5)], r13
 mov rbx, [rdi+8*(7+6)]
 adc r14, rbx
 mov qword [rdi+8*(7+6)], r14
 adc rax, 0
 mov rbx, [rsi+8*0]
 sub r8, rbx
 mov rbx, [rsi+8*1]
 sbb r9, rbx
 mov rbx, [rsi+8*2]
 sbb r10, rbx
 mov rbx, [rsi+8*3]
 sbb r11, rbx
 mov rbx, [rsi+8*4]
 sbb r12, rbx
 mov rbx, [rsi+8*5]
 sbb r13, rbx
 mov rbx, [rsi+8*6]
 sbb r14, rbx
 sbb rax, 0
 mov rax, qword [rdi+8*(7+0)]
 mov rbx, qword [rdi+8*(7+1)]
 mov rcx, qword [rdi+8*(7+2)]
 mov rdx, qword [rdi+8*(7+3)]
 mov rbp, qword [rdi+8*(7+4)]
 mov rsi, qword [rdi+8*(7+5)]
 mov rdi, qword [rdi+8*(7+6)]
 cmovae rax, r8
 cmovae rbx, r9
 cmovae rcx, r10
 cmovae rdx, r11
 cmovae rbp, r12
 cmovae rsi, r13
 cmovae rdi, r14
 mov qword [r15+8*0], rax
 mov qword [r15+8*1], rbx
 mov qword [r15+8*2], rcx
 mov qword [r15+8*3], rdx
 mov qword [r15+8*4], rbp
 mov qword [r15+8*5], rsi
 mov qword [r15+8*6], rdi
 ret
.LEnd_mred_7:
align 64
 mred_8:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 push r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred8_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred8_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred8_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred8_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred8_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred8_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred8_start
 mov rdx, [rsp]
 mulx rbx,rdx,r8
 call mred8_start
 pop rax
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov qword [rdi+8*(8+0)], r8
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov qword [rdi+8*(8+1)], r9
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov qword [rdi+8*(8+2)], r10
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov qword [rdi+8*(8+3)], r11
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov qword [rdi+8*(8+4)], r12
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov qword [rdi+8*(8+5)], r13
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov qword [rdi+8*(8+6)], r14
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 mov qword [rdi+8*(8+7)], r15
 adc rax, 0
 mov rbx, [rsi+8*0]
 sub r8, rbx
 mov rbx, [rsi+8*1]
 sbb r9, rbx
 mov rbx, [rsi+8*2]
 sbb r10, rbx
 mov rbx, [rsi+8*3]
 sbb r11, rbx
 mov rbx, [rsi+8*4]
 sbb r12, rbx
 mov rbx, [rsi+8*5]
 sbb r13, rbx
 mov rbx, [rsi+8*6]
 sbb r14, rbx
 mov rbx, [rsi+8*7]
 sbb r15, rbx
 sbb rax, 0
 pop rsi
 mov rax, qword [rdi+8*(8+0)]
 mov rbx, qword [rdi+8*(8+1)]
 mov rcx, qword [rdi+8*(8+2)]
 mov rdx, qword [rdi+8*(8+3)]
 cmovae rax, r8
 cmovae rbx, r9
 cmovae rcx, r10
 cmovae rdx, r11
 mov qword [rsi+8*0], rax
 mov qword [rsi+8*1], rbx
 mov qword [rsi+8*2], rcx
 mov qword [rsi+8*3], rdx
 mov rax, qword [rdi+8*(8+4)]
 mov rbx, qword [rdi+8*(8+5)]
 mov rcx, qword [rdi+8*(8+6)]
 mov rdx, qword [rdi+8*(8+7)]
 cmovae rax, r12
 cmovae rbx, r13
 cmovae rcx, r14
 cmovae rdx, r15
 mov qword [rsi+8*4], rax
 mov qword [rsi+8*5], rbx
 mov qword [rsi+8*6], rcx
 mov qword [rsi+8*7], rdx
 ret
.LEnd_mred_8:
align 64
 mred_9:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 push r8
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call mla_8x1
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 pop rax
 shr rax, 1
 mov qword [rdi+8*(9-8)+8*0], r8
 mov qword [rdi+8*(9-8)+8*1], r9
 mov qword [rdi+8*(9-8)+8*2], r10
 mov qword [rdi+8*(9-8)+8*3], r11
 mov qword [rdi+8*(9-8)+8*4], r12
 mov qword [rdi+8*(9-8)+8*5], r13
 mov qword [rdi+8*(9-8)+8*6], r14
 mov rbx, [rdi+8*(9-8)+8*7]
 adc r15, rbx
 mov [rdi+8*(9-8)+8*7], r15
 adc rax, 0
 push rax
 sub rsi, 8*8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rdx, [rsp+8]
 call mred8x1_start
 xor rax, rax
 mov qword [rdi+8*(9-8)+8*0], r8
 mov qword [rdi+8*(9-8)+8*1], r9
 mov qword [rdi+8*(9-8)+8*2], r10
 mov qword [rdi+8*(9-8)+8*3], r11
 mov qword [rdi+8*(9-8)+8*4], r12
 mov qword [rdi+8*(9-8)+8*5], r13
 mov qword [rdi+8*(9-8)+8*6], r14
 mov r8, r15
 add r8, qword [rdi+8*(9-8)+8*7]
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 call mla_1x1
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(9-8)+8*0]
 adc r8, rbx
 adc rax, 0
 pop rbx
 add r8, rbx
 mov qword [rdi+8*(9-8)+8*0], r8
 adc rax, 0
 pop rcx
 add rsp, 8*8
 lea rcx, [rsi-8*8]
 lea rsi, [rdi+8*(9-8)-8*8]
 pop rdi
 mov rbx, rax
 mov rdx, dword 9
 call sub_N
 sub rbx, rax
 sub rdi, 8*9
 sub rsi, 8*9
 mov rcx, rdi
 mov rdx, dword 9
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_9:
align 64
 mred_10:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 push r8
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call mla_8x2
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 pop rax
 shr rax, 1
 mov qword [rdi+8*(10-8)+8*0], r8
 mov qword [rdi+8*(10-8)+8*1], r9
 mov qword [rdi+8*(10-8)+8*2], r10
 mov qword [rdi+8*(10-8)+8*3], r11
 mov qword [rdi+8*(10-8)+8*4], r12
 mov qword [rdi+8*(10-8)+8*5], r13
 mov rbx, [rdi+8*(10-8)+8*6]
 adc r14, rbx
 mov [rdi+8*(10-8)+8*6], r14
 mov rbx, [rdi+8*(10-8)+8*7]
 adc r15, rbx
 mov [rdi+8*(10-8)+8*7], r15
 adc rax, 0
 push rax
 sub rsi, 8*8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rdx, [rsp+8]
 call mred8x2_start
 xor rax, rax
 mov qword [rdi+8*(10-8)+8*0], r8
 mov qword [rdi+8*(10-8)+8*1], r9
 mov qword [rdi+8*(10-8)+8*2], r10
 mov qword [rdi+8*(10-8)+8*3], r11
 mov qword [rdi+8*(10-8)+8*4], r12
 mov qword [rdi+8*(10-8)+8*5], r13
 mov r8, r14
 mov r9, r15
 add r8, qword [rdi+8*(10-8)+8*6]
 adc r9, qword [rdi+8*(10-8)+8*7]
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 call mla_2x2
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(10-8)+8*0]
 adc r8, rbx
 mov rbx, [rdi+8*(10-8)+8*1]
 adc r9, rbx
 adc rax, 0
 pop rbx
 add r8, rbx
 adc r9, 0
 mov qword [rdi+8*(10-8)+8*0], r8
 mov qword [rdi+8*(10-8)+8*1], r9
 adc rax, 0
 pop rcx
 add rsp, 8*8
 lea rcx, [rsi-8*8]
 lea rsi, [rdi+8*(10-8)-8*8]
 pop rdi
 mov rbx, rax
 mov rdx, dword 10
 call sub_N
 sub rbx, rax
 sub rdi, 8*10
 sub rsi, 8*10
 mov rcx, rdi
 mov rdx, dword 10
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_10:
align 64
 mred_11:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 push r8
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call mla_8x3
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 pop rax
 shr rax, 1
 mov qword [rdi+8*(11-8)+8*0], r8
 mov qword [rdi+8*(11-8)+8*1], r9
 mov qword [rdi+8*(11-8)+8*2], r10
 mov qword [rdi+8*(11-8)+8*3], r11
 mov qword [rdi+8*(11-8)+8*4], r12
 mov rbx, [rdi+8*(11-8)+8*5]
 adc r13, rbx
 mov [rdi+8*(11-8)+8*5], r13
 mov rbx, [rdi+8*(11-8)+8*6]
 adc r14, rbx
 mov [rdi+8*(11-8)+8*6], r14
 mov rbx, [rdi+8*(11-8)+8*7]
 adc r15, rbx
 mov [rdi+8*(11-8)+8*7], r15
 adc rax, 0
 push rax
 sub rsi, 8*8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rdx, [rsp+8]
 call mred8x3_start
 xor rax, rax
 mov qword [rdi+8*(11-8)+8*0], r8
 mov qword [rdi+8*(11-8)+8*1], r9
 mov qword [rdi+8*(11-8)+8*2], r10
 mov qword [rdi+8*(11-8)+8*3], r11
 mov qword [rdi+8*(11-8)+8*4], r12
 mov r8, r13
 mov r9, r14
 mov r10,r15
 add r8, qword [rdi+8*(11-8)+8*5]
 adc r9, qword [rdi+8*(11-8)+8*6]
 adc r10,qword [rdi+8*(11-8)+8*7]
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 call mla_3x3
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(11-8)+8*0]
 adc r8, rbx
 mov rbx, [rdi+8*(11-8)+8*1]
 adc r9, rbx
 mov rbx, [rdi+8*(11-8)+8*2]
 adc r10, rbx
 adc rax, 0
 pop rbx
 add r8, rbx
 adc r9, 0
 adc r10,0
 mov qword [rdi+8*(11-8)+8*0], r8
 mov qword [rdi+8*(11-8)+8*1], r9
 mov qword [rdi+8*(11-8)+8*2], r10
 adc rax, 0
 pop rcx
 add rsp, 8*8
 lea rcx, [rsi-8*8]
 lea rsi, [rdi+8*(11-8)-8*8]
 pop rdi
 mov rbx, rax
 mov rdx, dword 11
 call sub_N
 sub rbx, rax
 sub rdi, 8*11
 sub rsi, 8*11
 mov rcx, rdi
 mov rdx, dword 11
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_11:
align 64
 mred_12:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 push r8
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call mla_8x4
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 pop rax
 shr rax, 1
 mov qword [rdi+8*(12-8)+8*0], r8
 mov qword [rdi+8*(12-8)+8*1], r9
 mov qword [rdi+8*(12-8)+8*2], r10
 mov qword [rdi+8*(12-8)+8*3], r11
 mov rbx, [rdi+8*(12-8)+8*4]
 adc r12, rbx
 mov [rdi+8*(12-8)+8*4], r12
 mov rbx, [rdi+8*(12-8)+8*5]
 adc r13, rbx
 mov [rdi+8*(12-8)+8*5], r13
 mov rbx, [rdi+8*(12-8)+8*6]
 adc r14, rbx
 mov [rdi+8*(12-8)+8*6], r14
 mov rbx, [rdi+8*(12-8)+8*7]
 adc r15, rbx
 mov [rdi+8*(12-8)+8*7], r15
 adc rax, 0
 push rax
 sub rsi, 8*8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rdx, [rsp+8]
 call mred8x4_start
 xor rax, rax
 mov qword [rdi+8*(12-8)+8*0], r8
 mov qword [rdi+8*(12-8)+8*1], r9
 mov qword [rdi+8*(12-8)+8*2], r10
 mov qword [rdi+8*(12-8)+8*3], r11
 mov r8, r12
 mov r9, r13
 mov r10,r14
 mov r11,r15
 add r8, qword [rdi+8*(12-8)+8*4]
 adc r9, qword [rdi+8*(12-8)+8*5]
 adc r10,qword [rdi+8*(12-8)+8*6]
 adc r11,qword [rdi+8*(12-8)+8*7]
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 call mla_4x4
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(12-8)+8*0]
 adc r8, rbx
 mov rbx, [rdi+8*(12-8)+8*1]
 adc r9, rbx
 mov rbx, [rdi+8*(12-8)+8*2]
 adc r10, rbx
 mov rbx, [rdi+8*(12-8)+8*3]
 adc r11, rbx
 adc rax, 0
 pop rbx
 add r8, rbx
 adc r9, 0
 adc r10,0
 adc r11,0
 mov qword [rdi+8*(12-8)+8*0], r8
 mov qword [rdi+8*(12-8)+8*1], r9
 mov qword [rdi+8*(12-8)+8*2], r10
 mov qword [rdi+8*(12-8)+8*3], r11
 adc rax, 0
 pop rcx
 add rsp, 8*8
 lea rcx, [rsi-8*8]
 lea rsi, [rdi+8*(12-8)-8*8]
 pop rdi
 mov rbx, rax
 mov rdx, dword 12
 call sub_N
 sub rbx, rax
 sub rdi, 8*12
 sub rsi, 8*12
 mov rcx, rdi
 mov rdx, dword 12
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_12:
align 64
 mred_13:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 push r8
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call mla_8x5
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 pop rax
 shr rax, 1
 mov qword [rdi+8*(13-8)+8*0], r8
 mov qword [rdi+8*(13-8)+8*1], r9
 mov qword [rdi+8*(13-8)+8*2], r10
 mov rbx, [rdi+8*(13-8)+8*3]
 adc r11, rbx
 mov [rdi+8*(13-8)+8*3], r11
 mov rbx, [rdi+8*(13-8)+8*4]
 adc r12, rbx
 mov [rdi+8*(13-8)+8*4], r12
 mov rbx, [rdi+8*(13-8)+8*5]
 adc r13, rbx
 mov [rdi+8*(13-8)+8*5], r13
 mov rbx, [rdi+8*(13-8)+8*6]
 adc r14, rbx
 mov [rdi+8*(13-8)+8*6], r14
 mov rbx, [rdi+8*(13-8)+8*7]
 adc r15, rbx
 mov [rdi+8*(13-8)+8*7], r15
 adc rax, 0
 push rax
 sub rsi, 8*8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rdx, [rsp+8]
 call mred8x5_start
 xor rax, rax
 mov qword [rdi+8*(13-8)+8*0], r8
 mov qword [rdi+8*(13-8)+8*1], r9
 mov qword [rdi+8*(13-8)+8*2], r10
 mov r8, r11
 mov r9, r12
 mov r10,r13
 mov r11,r14
 mov r12,r15
 add r8, qword [rdi+8*(13-8)+8*3]
 adc r9, qword [rdi+8*(13-8)+8*4]
 adc r10,qword [rdi+8*(13-8)+8*5]
 adc r11,qword [rdi+8*(13-8)+8*6]
 adc r12,qword [rdi+8*(13-8)+8*7]
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 call mla_5x5
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(13-8)+8*0]
 adc r8, rbx
 mov rbx, [rdi+8*(13-8)+8*1]
 adc r9, rbx
 mov rbx, [rdi+8*(13-8)+8*2]
 adc r10, rbx
 mov rbx, [rdi+8*(13-8)+8*3]
 adc r11, rbx
 mov rbx, [rdi+8*(13-8)+8*4]
 adc r12, rbx
 adc rax, 0
 pop rbx
 add r8, rbx
 adc r9, 0
 adc r10,0
 adc r11,0
 adc r12,0
 mov qword [rdi+8*(13-8)+8*0], r8
 mov qword [rdi+8*(13-8)+8*1], r9
 mov qword [rdi+8*(13-8)+8*2], r10
 mov qword [rdi+8*(13-8)+8*3], r11
 mov qword [rdi+8*(13-8)+8*4], r12
 adc rax, 0
 pop rcx
 add rsp, 8*8
 lea rcx, [rsi-8*8]
 lea rsi, [rdi+8*(13-8)-8*8]
 pop rdi
 mov rbx, rax
 mov rdx, dword 13
 call sub_N
 sub rbx, rax
 sub rdi, 8*13
 sub rsi, 8*13
 mov rcx, rdi
 mov rdx, dword 13
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_13:
align 64
 mred_14:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 push r8
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call mla_8x6
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 pop rax
 shr rax, 1
 mov qword [rdi+8*(14-8)+8*0], r8
 mov qword [rdi+8*(14-8)+8*1], r9
 mov rbx, [rdi+8*(14-8)+8*2]
 adc r10, rbx
 mov [rdi+8*(14-8)+8*2], r10
 mov rbx, [rdi+8*(14-8)+8*3]
 adc r11, rbx
 mov [rdi+8*(14-8)+8*3], r11
 mov rbx, [rdi+8*(14-8)+8*4]
 adc r12, rbx
 mov [rdi+8*(14-8)+8*4], r12
 mov rbx, [rdi+8*(14-8)+8*5]
 adc r13, rbx
 mov [rdi+8*(14-8)+8*5], r13
 mov rbx, [rdi+8*(14-8)+8*6]
 adc r14, rbx
 mov [rdi+8*(14-8)+8*6], r14
 mov rbx, [rdi+8*(14-8)+8*7]
 adc r15, rbx
 mov [rdi+8*(14-8)+8*7], r15
 adc rax, 0
 push rax
 sub rsi, 8*8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rdx, [rsp+8]
 call mred8x6_start
 xor rax, rax
 mov qword [rdi+8*(14-8)+8*0], r8
 mov qword [rdi+8*(14-8)+8*1], r9
 mov r8, r10
 mov r9, r11
 mov r10,r12
 mov r11,r13
 mov r12,r14
 mov r13,r15
 add r8, qword [rdi+8*(14-8)+8*2]
 adc r9, qword [rdi+8*(14-8)+8*3]
 adc r10,qword [rdi+8*(14-8)+8*4]
 adc r11,qword [rdi+8*(14-8)+8*5]
 adc r12,qword [rdi+8*(14-8)+8*6]
 adc r13,qword [rdi+8*(14-8)+8*7]
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 call mla_6x6
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(14-8)+8*0]
 adc r8, rbx
 mov rbx, [rdi+8*(14-8)+8*1]
 adc r9, rbx
 mov rbx, [rdi+8*(14-8)+8*2]
 adc r10, rbx
 mov rbx, [rdi+8*(14-8)+8*3]
 adc r11, rbx
 mov rbx, [rdi+8*(14-8)+8*4]
 adc r12, rbx
 mov rbx, [rdi+8*(14-8)+8*5]
 adc r13, rbx
 adc rax, 0
 pop rbx
 add r8, rbx
 adc r9, 0
 adc r10,0
 adc r11,0
 adc r12,0
 adc r13,0
 mov qword [rdi+8*(14-8)+8*0], r8
 mov qword [rdi+8*(14-8)+8*1], r9
 mov qword [rdi+8*(14-8)+8*2], r10
 mov qword [rdi+8*(14-8)+8*3], r11
 mov qword [rdi+8*(14-8)+8*4], r12
 mov qword [rdi+8*(14-8)+8*5], r13
 adc rax, 0
 pop rcx
 add rsp, 8*8
 lea rcx, [rsi-8*8]
 lea rsi, [rdi+8*(14-8)-8*8]
 pop rdi
 mov rbx, rax
 mov rdx, dword 14
 call sub_N
 sub rbx, rax
 sub rdi, 8*14
 sub rsi, 8*14
 mov rcx, rdi
 mov rdx, dword 14
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_14:
align 64
 mred_15:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 push r8
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 call mla_8x7
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 pop rax
 shr rax, 1
 mov qword [rdi+8*(15-8)+8*0], r8
 mov rbx, [rdi+8*(15-8)+8*1]
 adc r9, rbx
 mov [rdi+8*(15-8)+8*1], r9
 mov rbx, [rdi+8*(15-8)+8*2]
 adc r10, rbx
 mov [rdi+8*(15-8)+8*2], r10
 mov rbx, [rdi+8*(15-8)+8*3]
 adc r11, rbx
 mov [rdi+8*(15-8)+8*3], r11
 mov rbx, [rdi+8*(15-8)+8*4]
 adc r12, rbx
 mov [rdi+8*(15-8)+8*4], r12
 mov rbx, [rdi+8*(15-8)+8*5]
 adc r13, rbx
 mov [rdi+8*(15-8)+8*5], r13
 mov rbx, [rdi+8*(15-8)+8*6]
 adc r14, rbx
 mov [rdi+8*(15-8)+8*6], r14
 mov rbx, [rdi+8*(15-8)+8*7]
 adc r15, rbx
 mov [rdi+8*(15-8)+8*7], r15
 adc rax, 0
 push rax
 sub rsi, 8*8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rdx, [rsp+8]
 call mred8x7_start
 xor rax, rax
 mov qword [rdi+8*(15-8)+8*0], r8
 mov r8, r9
 mov r9, r10
 mov r10,r11
 mov r11,r12
 mov r12,r13
 mov r13,r14
 mov r14,r15
 add r8, qword [rdi+8*(15-8)+8*1]
 adc r9, qword [rdi+8*(15-8)+8*2]
 adc r10,qword [rdi+8*(15-8)+8*3]
 adc r11,qword [rdi+8*(15-8)+8*4]
 adc r12,qword [rdi+8*(15-8)+8*5]
 adc r13,qword [rdi+8*(15-8)+8*6]
 adc r14,qword [rdi+8*(15-8)+8*7]
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 call mla_7x7
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(15-8)+8*0]
 adc r8, rbx
 mov rbx, [rdi+8*(15-8)+8*1]
 adc r9, rbx
 mov rbx, [rdi+8*(15-8)+8*2]
 adc r10, rbx
 mov rbx, [rdi+8*(15-8)+8*3]
 adc r11, rbx
 mov rbx, [rdi+8*(15-8)+8*4]
 adc r12, rbx
 mov rbx, [rdi+8*(15-8)+8*5]
 adc r13, rbx
 mov rbx, [rdi+8*(15-8)+8*6]
 adc r14, rbx
 adc rax, 0
 pop rbx
 add r8, rbx
 adc r9, 0
 adc r10,0
 adc r11,0
 adc r12,0
 adc r13,0
 adc r14,0
 mov qword [rdi+8*(15-8)+8*0], r8
 mov qword [rdi+8*(15-8)+8*1], r9
 mov qword [rdi+8*(15-8)+8*2], r10
 mov qword [rdi+8*(15-8)+8*3], r11
 mov qword [rdi+8*(15-8)+8*4], r12
 mov qword [rdi+8*(15-8)+8*5], r13
 mov qword [rdi+8*(15-8)+8*6], r14
 adc rax, 0
 pop rcx
 add rsp, 8*8
 lea rcx, [rsi-8*8]
 lea rsi, [rdi+8*(15-8)-8*8]
 pop rdi
 mov rbx, rax
 mov rdx, dword 15
 call sub_N
 sub rbx, rax
 sub rdi, 8*15
 sub rsi, 8*15
 mov rcx, rdi
 mov rdx, dword 15
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_15:
align 64
 mred_16:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rsi, 8*8
 add rdi, 8*8
 push rdx
 call mla_8x8
 pop rdx
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(8+0)]
 adc r8, rbx
 mov [rdi+8*(8+0)], r8
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov [rdi+8*(8+1)], r9
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov [rdi+8*(8+2)], r10
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov [rdi+8*(8+3)], r11
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov [rdi+8*(8+4)], r12
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov [rdi+8*(8+5)], r13
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov [rdi+8*(8+6)], r14
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 mov [rdi+8*(8+7)], r15
 adc rax, 0
 push rax
 sub rsi, 8*8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 call mla_8x8
 sub rsi, 8*8
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(8+0)]
 adc r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 pop rbx
 add r8, rbx
 adc r9, 0
 adc r10, 0
 adc r11, 0
 adc r12, 0
 adc r13, 0
 adc r14, 0
 adc r15, 0
 adc rax, 0
 mov qword [rdi+8*(8+0)], r8
 mov qword [rdi+8*(8+1)], r9
 mov qword [rdi+8*(8+2)], r10
 mov qword [rdi+8*(8+3)], r11
 mov qword [rdi+8*(8+4)], r12
 mov qword [rdi+8*(8+5)], r13
 mov qword [rdi+8*(8+6)], r14
 mov qword [rdi+8*(8+7)], r15
 add rsp, 8*8
 pop rbp
 mov rbx, [rdi+8*0 ]
 sub rbx, [rsi+8*0 ]
 mov [rbp+8*0 ], rbx
 mov rbx, [rdi+8*1 ]
 sbb rbx, [rsi+8*1 ]
 mov [rbp+8*1 ], rbx
 mov rbx, [rdi+8*2 ]
 sbb rbx, [rsi+8*2 ]
 mov [rbp+8*2 ], rbx
 mov rbx, [rdi+8*3 ]
 sbb rbx, [rsi+8*3 ]
 mov [rbp+8*3 ], rbx
 mov rbx, [rdi+8*4 ]
 sbb rbx, [rsi+8*4 ]
 mov [rbp+8*4 ], rbx
 mov rbx, [rdi+8*5 ]
 sbb rbx, [rsi+8*5 ]
 mov [rbp+8*5 ], rbx
 mov rbx, [rdi+8*6 ]
 sbb rbx, [rsi+8*6 ]
 mov [rbp+8*6 ], rbx
 mov rbx, [rdi+8*7 ]
 sbb rbx, [rsi+8*7 ]
 mov [rbp+8*7 ], rbx
 mov rbx, [rsi+8*8 ]
 sbb r8, rbx
 mov rbx, [rsi+8*9 ]
 sbb r9, rbx
 mov rbx, [rsi+8*10]
 sbb r10, rbx
 mov rbx, [rsi+8*11]
 sbb r11, rbx
 mov rbx, [rsi+8*12]
 sbb r12, rbx
 mov rbx, [rsi+8*13]
 sbb r13, rbx
 mov rbx, [rsi+8*14]
 sbb r14, rbx
 mov rbx, [rsi+8*15]
 sbb r15, rbx
 sbb rax, 0
 mov rax, qword [rdi+8*8 ]
 mov rbx, qword [rdi+8*9 ]
 mov rcx, qword [rdi+8*10]
 mov rdx, qword [rdi+8*11]
 cmovae rax, r8
 cmovae rbx, r9
 cmovae rcx, r10
 cmovae rdx, r11
 mov qword [rbp+8*8 ], rax
 mov qword [rbp+8*9 ], rbx
 mov qword [rbp+8*10], rcx
 mov qword [rbp+8*11], rdx
 mov rax, qword [rdi+8*12]
 mov rbx, qword [rdi+8*13]
 mov rcx, qword [rdi+8*14]
 mov rdx, qword [rdi+8*15]
 cmovae rax, r12
 cmovae rbx, r13
 cmovae rcx, r14
 cmovae rdx, r15
 mov qword [rbp+8*12], rax
 mov qword [rbp+8*13], rbx
 mov qword [rbp+8*14], rcx
 mov qword [rbp+8*15], rdx
 mov r8, qword [rbp+8*0]
 mov r9, qword [rbp+8*1]
 mov r10, qword [rbp+8*2]
 mov r11, qword [rbp+8*3]
 mov r12, qword [rbp+8*4]
 mov r13, qword [rbp+8*5]
 mov r14, qword [rbp+8*6]
 mov r15, qword [rbp+8*7]
 mov rax, qword [rdi+8*0]
 mov rbx, qword [rdi+8*1]
 mov rcx, qword [rdi+8*2]
 mov rdx, qword [rdi+8*3]
 cmovae rax, r8
 cmovae rbx, r9
 cmovae rcx, r10
 cmovae rdx, r11
 mov qword [rbp+8*0], rax
 mov qword [rbp+8*1], rbx
 mov qword [rbp+8*2], rcx
 mov qword [rbp+8*3], rdx
 mov rax, qword [rdi+8*4]
 mov rbx, qword [rdi+8*5]
 mov rcx, qword [rdi+8*6]
 mov rdx, qword [rdi+8*7]
 cmovae rax, r12
 cmovae rbx, r13
 cmovae rcx, r14
 cmovae rdx, r15
 mov qword [rbp+8*4], rax
 mov qword [rbp+8*5], rbx
 mov qword [rbp+8*6], rcx
 mov qword [rbp+8*7], rdx
 ret
.LEnd_mred_16:
mred_short DQ mred_5 - mred_short
 DQ mred_6 - mred_short
 DQ mred_7 - mred_short
 DQ mred_8 - mred_short
 DQ mred_9 - mred_short
 DQ mred_10 - mred_short
 DQ mred_11 - mred_short
 DQ mred_12 - mred_short
 DQ mred_13 - mred_short
 DQ mred_14 - mred_short
 DQ mred_15 - mred_short
 DQ mred_16 - mred_short
mred8x_start DQ mred8x1_start - mred8x_start
 DQ mred8x2_start - mred8x_start
 DQ mred8x3_start - mred8x_start
 DQ mred8x4_start - mred8x_start
 DQ mred8x5_start - mred8x_start
 DQ mred8x6_start - mred8x_start
 DQ mred8x7_start - mred8x_start
align 64
 mred_8N:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 mov rbx, rdx
 xor rax, rax
.passLoop:
 push rdi
 push rsi
 push rdx
 push r8
 push rbx
 push rax
 push rdx
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 pop rdx
 xor rax, rax
 mov rbx, [rdi+8*(8+0)]
 add r8, rbx
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 adc rax, 0
 push rax
 jmp .entryInnerLoop
.innerLoop:
 push rdx
 call mla_8x8
 pop rdx
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(8+0)]
 adc r8, rbx
 mov [rdi+8*(8+0)], r8
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov [rdi+8*(8+1)], r9
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov [rdi+8*(8+2)], r10
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov [rdi+8*(8+3)], r11
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov [rdi+8*(8+4)], r12
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov [rdi+8*(8+5)], r13
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov [rdi+8*(8+6)], r14
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 mov [rdi+8*(8+7)], r15
 adc rax, 0
 push rax
.entryInnerLoop:
 add rdi, 8*8
 add rsi, 8*8
 sub rdx, 8
 jg .innerLoop
 pop rax
 pop rbx
 add r8, rbx
 adc r9, 0
 adc r10, 0
 adc r11, 0
 adc r12, 0
 adc r13, 0
 adc r14, 0
 adc r15, 0
 adc rax, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2], r10
 mov qword [rdi+8*3], r11
 mov qword [rdi+8*4], r12
 mov qword [rdi+8*5], r13
 mov qword [rdi+8*6], r14
 mov qword [rdi+8*7], r15
 pop rbx
 pop r8
 pop rdx
 pop rsi
 pop rdi
 add rdi, 8*8
 sub rbx, 8
 jg .passLoop
 add rsp, 8*8
 mov r14, rdx
 lea r15, [rdx*8]
 mov rbx, rax
 mov rcx, rsi
 mov rsi, rdi
 pop rdi
 call sub_N
 sub rbx, rax
 mov rdx, r14
 sub rdi, r15
 sub rsi, r15
 mov rcx, rdi
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_8N:
align 64
 mred_N:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push r15
 sub rsp, 8*8
 mov rcx, rsp
 mov rbx, rdx
 sub rbx, 8
 xor rax, rax
 mov r15, dword 7
 and r15, rdx
 lea rbp, [rel mla_8xl_tail]
 mov r15, [rbp+r15*8-8]
 add rbp, r15
.passLoop:
 push rdi
 push rsi
 push rdx
 push r8
 push rbx
 push rax
 push rbp
 sub rdx, 8
 push rdx
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 call mred8x8_start
 pop rdx
 xor rax, rax
 push rax
 jmp .entryInnerLoop
.innerLoop:
 push rdx
 call mla_8x8
 pop rdx
.entryInnerLoop:
 pop rax
 shr rax, 1
 mov rbx, [rdi+8*(8+0)]
 adc r8, rbx
 mov [rdi+8*(8+0)], r8
 mov rbx, [rdi+8*(8+1)]
 adc r9, rbx
 mov [rdi+8*(8+1)], r9
 mov rbx, [rdi+8*(8+2)]
 adc r10, rbx
 mov [rdi+8*(8+2)], r10
 mov rbx, [rdi+8*(8+3)]
 adc r11, rbx
 mov [rdi+8*(8+3)], r11
 mov rbx, [rdi+8*(8+4)]
 adc r12, rbx
 mov [rdi+8*(8+4)], r12
 mov rbx, [rdi+8*(8+5)]
 adc r13, rbx
 mov [rdi+8*(8+5)], r13
 mov rbx, [rdi+8*(8+6)]
 adc r14, rbx
 mov [rdi+8*(8+6)], r14
 mov rbx, [rdi+8*(8+7)]
 adc r15, rbx
 mov [rdi+8*(8+7)], r15
 adc rax, 0
 push rax
 add rdi, 8*8
 add rsi, 8*8
 sub rdx, 8
 jnc .innerLoop
 add rdx, 8
 jz .complete_regular_pass
 mov rax, [rsp+8]
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 push rdx
 call rax
 pop rdx
 xor rcx, rsi
 xor rsi, rcx
 xor rcx, rsi
 lea rdi, [rdi+rdx*8]
 pop rax
 shr rax, 1
 mov rbx, rdx
 dec rbx
 jz .mt_1
 dec rbx
 jz .mt_2
 dec rbx
 jz .mt_3
 dec rbx
 jz .mt_4
 dec rbx
 jz .mt_5
 dec rbx
 jz .mt_6
.mt_7: 
 mov rbx, [rdi+8*1]
 adc r9, rbx
.mt_6: 
 mov rbx, [rdi+8*2]
 adc r10, rbx
.mt_5: 
 mov rbx, [rdi+8*3]
 adc r11, rbx
.mt_4: 
 mov rbx, [rdi+8*4]
 adc r12, rbx
.mt_3: 
 mov rbx, [rdi+8*5]
 adc r13, rbx
.mt_2: 
 mov rbx, [rdi+8*6]
 adc r14, rbx
.mt_1: 
 mov rbx, [rdi+8*7]
 adc r15, rbx
 adc rax, 0
 push rax
.complete_regular_pass:
 pop rax
 pop rbp
 pop rbx
 add r8, rbx
 adc r9, 0
 adc r10, 0
 adc r11, 0
 adc r12, 0
 adc r13, 0
 adc r14, 0
 adc r15, 0
 adc rax, 0
 mov qword [rdi+8*0], r8
 mov qword [rdi+8*1], r9
 mov qword [rdi+8*2], r10
 mov qword [rdi+8*3], r11
 mov qword [rdi+8*4], r12
 mov qword [rdi+8*5], r13
 mov qword [rdi+8*6], r14
 mov qword [rdi+8*7], r15
 pop rbx
 pop r8
 pop rdx
 pop rsi
 pop rdi
 add rdi, 8*8
 sub rbx, 8
 jnc .passLoop
 add rbx, 8
 jz .complete_reduction
 push rdi
 push rsi
 push rdx
 push r8
 push rbx
 push rax
 push rbp
 sub rdx, 8
 push rdx
 mov rdx, r8
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 lea rax, [rel mred8x_start]
 mov rbp, [rax+rbx*8-8]
 add rax, rbp
 call rax
 pop rdx
 xor rax, rax
 push rax
 jmp .entryTailLoop
.tailLoop:
 mov r8, qword [rdi]
 mov r9, qword [rdi+8]
 mov r10,qword [rdi+8*2]
 mov r11,qword [rdi+8*3]
 mov r12,qword [rdi+8*4]
 mov r13,qword [rdi+8*5]
 mov r14,qword [rdi+8*6]
 mov r15,qword [rdi+8*7]
 mov rax, [rsp+8]
 push rdx
 call rax
 pop rdx
.entryTailLoop:
 pop rax
 shr rax, 1
 adc r8, 0
 adc r9, 0
 adc r10, 0
 adc r11, 0
 adc r12, 0
 adc r13, 0
 adc r14, 0
 adc r15, 0
 adc rax, 0
 mov rbx, [rsp+8*2]
 cmp rbx, 1
 jz .tt_1
 cmp rbx, 2
 jz .tt_2
 cmp rbx, 3
 jz .tt_3
 cmp rbx, 4
 jz .tt_4
 cmp rbx, 5
 jz .tt_5
 cmp rbx, 6
 jz .tt_6
.tt_7: 
 mov rbp, [rdi+rbx*8+8*1]
 adc r9, rbp
.tt_6: 
 mov rbp, [rdi+rbx*8+8*2]
 adc r10, rbp
.tt_5: 
 mov rbp, [rdi+rbx*8+8*3]
 adc r11, rbp
.tt_4: 
 mov rbp, [rdi+rbx*8+8*4]
 adc r12, rbp
.tt_3: 
 mov rbp, [rdi+rbx*8+8*5]
 adc r13, rbp
.tt_2: 
 mov rbp, [rdi+rbx*8+8*6]
 adc r14, rbp
.tt_1: 
 mov rbp, [rdi+rbx*8+8*7]
 adc r15, rbp
 adc rax, 0
 push rax
 mov qword [rdi+rbx*8+8*0], r8
 mov qword [rdi+rbx*8+8*1], r9
 mov qword [rdi+rbx*8+8*2], r10
 mov qword [rdi+rbx*8+8*3], r11
 mov qword [rdi+rbx*8+8*4], r12
 mov qword [rdi+rbx*8+8*5], r13
 mov qword [rdi+rbx*8+8*6], r14
 mov qword [rdi+rbx*8+8*7], r15
 add rsi, 8*8
 add rdi, 8*8
 sub rdx, 8
 jnc .tailLoop
 add rdx, 8
 mov rbx, rdx
 mov r8, qword [rdi]
 dec rbx
 jz .get_tail_proc
 mov r9, qword [rdi+8]
 dec rbx
 jz .get_tail_proc
 mov r10, qword [rdi+8*2]
 dec rbx
 jz .get_tail_proc
 mov r11, qword [rdi+8*3]
 dec rbx
 jz .get_tail_proc
 mov r12, qword [rdi+8*4]
 dec rbx
 jz .get_tail_proc
 mov r13, qword [rdi+8*5]
 dec rbx
 jz .get_tail_proc
 mov r14, qword [rdi+8*6]
.get_tail_proc:
 lea rax, [rel mla_lxl_short]
 mov rbp, [rax+rdx*8-8]
 add rax, rbp
 push rdx
 call rax
 pop rdx
 lea rdi, [rdi+rdx*8]
 pop rax
 shr rax, 1
 mov rbx, rdx
 mov rbp, [rdi+8*0]
 adc r8, rbp
 dec rbx
 jz .add_carry1
 mov rbp, [rdi+8*1]
 adc r9, rbp
 dec rbx
 jz .add_carry1
 mov rbp, [rdi+8*2]
 adc r10, rbp
 dec rbx
 jz .add_carry1
 mov rbp, [rdi+8*3]
 adc r11, rbp
 dec rbx
 jz .add_carry1
 mov rbp, [rdi+8*4]
 adc r12, rbp
 dec rbx
 jz .add_carry1
 mov rbp, [rdi+8*5]
 adc r13, rbp
 dec rbx
 jz .add_carry1
 mov rbp, [rdi+8*6]
 adc r14, rbp
.add_carry1:
 adc rax, 0
 pop rbp
 pop rbx
 add r8, rbx
 mov qword [rdi+8*0], r8
 dec rdx
 jz .add_carry2
 adc r9, 0
 mov qword [rdi+8*1], r9
 dec rdx
 jz .add_carry2
 adc r10, 0
 mov qword [rdi+8*2], r10
 dec rdx
 jz .add_carry2
 adc r11, 0
 mov qword [rdi+8*3], r11
 dec rdx
 jz .add_carry2
 adc r12, 0
 mov qword [rdi+8*4], r12
 dec rdx
 jz .add_carry2
 adc r13, 0
 mov qword [rdi+8*5], r13
 dec rdx
 jz .add_carry2
 adc r14, 0
 mov qword [rdi+8*6], r14
.add_carry2:
 adc rax, 0
 pop rbx
 pop r8
 pop rdx
 pop rsi
 pop rdi
 lea rdi, [rdi+rbx*8]
.complete_reduction:
 add rsp, 8*8
 mov r14, rdx
 lea r15, [rdx*8]
 mov rbx, rax
 mov rcx, rsi
 mov rsi, rdi
 pop rdi
 call sub_N
 sub rbx, rax
 mov rdx, r14
 sub rdi, r15
 sub rsi, r15
 mov rcx, rdi
 shr rbx,1
 call copy_ae_N
 ret
.LEnd_mred_N:
align 64
[global cc_ipp_mul_school:function hidden (cc_ipp_mul_school.LEnd_cpMulAdc_BNU_school - cc_ipp_mul_school)]
 cc_ipp_mul_school:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 movsxd rdx, edx
 movsxd rbx, r8d
 xor r8, r8
 xor r9, r9
 xor r10, r10
 xor r11, r11
 xor r12, r12
 xor r13, r13
 xor r14, r14
 xor r15, r15
 cmp rdx, rbx
 jl .swap_operans
 jg .test_8N_case
 cmp rdx, 16
 jg .test_8N_case
 cmp rdx, 4
 jg .more_then_4
 cmp edx, 3
 ja .mul_4_4
 jz .mul_3_3
 jp .mul_2_2
.mul_1_1:
 mov rdx, [rcx]
 mulx r8,rbp,[rsi]
 mov [rdi], rbp
 mov qword [rdi+8*1], r8
 jmp .quit
.mul_2_2:
 mov rdx, [rcx]
 mulx r8,rbp,[rsi]
 mov [rdi], rbp
 mulx r9,rbx,[rsi+8]
 add r8, rbx
 adc r9, 0
 mov rdx, [rcx+8*1]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8*1], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mov r9, rbp
 mov qword [rdi+8*2], r8
 mov qword [rdi+8*3], r9
 jmp .quit
.mul_3_3:
 mov rdx, [rcx]
 mulx r8,rbp,[rsi]
 mov [rdi], rbp
 mulx r9,rbx,[rsi+8]
 add r8, rbx
 mulx r10,rbp,[rsi+8*2]
 adc r9, rbp
 adc r10, 0
 mov rdx, [rcx+8*1]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8*1], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mov r10, rbx
 mov rdx, [rcx+8*2]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8*2], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mov r10, rbx
 mov qword [rdi+8*3], r8
 mov qword [rdi+8*4], r9
 mov qword [rdi+8*5], r10
 jmp .quit
.mul_4_4:
 mov rdx, [rcx]
 mulx r8,rbp,[rsi]
 mov [rdi], rbp
 mulx r9,rbx,[rsi+8]
 add r8, rbx
 mulx r10,rbp,[rsi+8*2]
 adc r9, rbp
 mulx r11,rbx,[rsi+8*3]
 adc r10, rbx
 adc r11, 0
 mov rdx, [rcx+8*1]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8*1], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 mov rdx, [rcx+8*2]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8*2], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 mov rdx, [rcx+8*3]
 mulx rbx,rax,[rsi]
 add rax, r8
 adc rbx, 0
 mov [rdi+8*3], rax
 mulx rbp,r8,[rsi+8]
 add r8, r9
 adc rbp, 0
 add r8, rbx
 adc rbp, 0
 mulx rbx,r9,[rsi+8*2]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*3]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 mov qword [rdi+8*4], r8
 mov qword [rdi+8*5], r9
 mov qword [rdi+8*6], r10
 mov qword [rdi+8*7], r11
 jmp .quit
.more_then_4:
 lea rax, [rel mul_lxl_basic]
 mov rbp, [rax+rdx*8-8]
 add rax, rbp
 call rax
 jmp .quit
.swap_operans:
 xor rsi, rcx
 xor rcx, rsi
 xor rsi, rcx
 xor rdx, rbx
 xor rbx, rdx
 xor rdx, rbx
.test_8N_case:
 mov rax, rdx
 or rax, rbx
 and rax, 7
 jnz .general_mul
 call mul_8Nx8M
 jmp .quit
.general_mul:
 call mul_NxM
 jmp .quit
.quit:
 vzeroupper
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.LEnd_cpMulAdc_BNU_school:
align 64
[global cc_ipp_sqr_school:function hidden (cc_ipp_sqr_school.LEnd_cpSqrAdc_BNU_school - cc_ipp_sqr_school)]
 cc_ipp_sqr_school:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 movsxd rdx, edx
 xor r8, r8
 xor r9, r9
 xor r10, r10
 xor r11, r11
 xor r12, r12
 xor r13, r13
 xor r14, r14
 xor r15, r15
 cmp rdx, 16
 jg .test_8N_case
 lea rax, [rel sqr_l_basic]
 mov rbp, [rax+rdx*8-8]
 add rax, rbp
 call rax
 jmp .quit
.test_8N_case:
 test rdx, 7
 jnz .general_sqr
 call sqr_8N
 jmp .quit
.general_sqr:
 call sqr_N
.quit:
 vzeroupper
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.LEnd_cpSqrAdc_BNU_school:
align 64
[global cc_ipp_mont_red:function hidden (cc_ipp_mont_red.LEnd_cpMontRedAdc_BNU - cc_ipp_mont_red)]
 cc_ipp_mont_red:
 db 0F3h, 00Fh, 01Eh, 0FAh
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 mov r15, rdi
 mov rdi, rsi
 mov rsi, rdx
 movsxd rdx, ecx
 cmp rdx, 16
 ja .test_8N_case
 cmp rdx, 4
 ja .above4
 cmp rdx, 3
 ja .red_4
 jz .red_3
 jp .red_2
.red_1:
 mov r9, qword [rdi+8*0]
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mov r9, rbp
 xor rbx, rbx
 add r9, qword [rdi+8*(1+0)]
 mov qword [rdi+8*(1+0)], r9
 adc rbx, 0
 sub r9, qword [rsi+8*0]
 sbb rbx, 0
 mov rax, qword [rdi+8*(1+0)]
 cmovae rax, r9
 mov qword [r15+8*0], rax
 jmp .quit
.red_2:
 mov r9, qword [rdi+8*0]
 mov r10, qword [rdi+8*1]
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mov r10, rbx
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mov r10, rbx
 xor rbx, rbx
 add r9, qword [rdi+8*(2+0)]
 mov qword [rdi+8*(2+0)], r9
 adc r10, qword [rdi+8*(2+1)]
 mov qword [rdi+8*(2+1)], r10
 adc rbx, 0
 sub r9, qword [rsi+8*0]
 sbb r10, qword [rsi+8*1]
 sbb rbx, 0
 mov rax, qword [rdi+8*(2+0)]
 cmovae rax, r9
 mov qword [r15+8*0], rax
 mov rax, qword [rdi+8*(2+1)]
 cmovae rax, r10
 mov qword [r15+8*1], rax
 jmp .quit
.red_3:
 mov r9, qword [rdi+8*0]
 mov r10, qword [rdi+8*1]
 mov r11, qword [rdi+8*2]
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*2]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*2]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*2]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mov r11, rbp
 xor rbx, rbx
 add r9, qword [rdi+8*(3+0)]
 mov qword [rdi+8*(3+0)], r9
 adc r10, qword [rdi+8*(3+1)]
 mov qword [rdi+8*(3+1)], r10
 adc r11, qword [rdi+8*(3+2)]
 mov qword [rdi+8*(3+2)], r11
 adc rbx, 0
 sub r9, qword [rsi+8*0]
 sbb r10, qword [rsi+8*1]
 sbb r11, qword [rsi+8*2]
 sbb rbx, 0
 mov rax, qword [rdi+8*(3+0)]
 cmovae rax, r9
 mov qword [r15+8*0], rax
 mov rax, qword [rdi+8*(3+1)]
 cmovae rax, r10
 mov qword [r15+8*1], rax
 mov rax, qword [rdi+8*(3+2)]
 cmovae rax, r11
 mov qword [r15+8*2], rax
 jmp .quit
.red_4:
 mov r9, qword [rdi+8*0]
 mov r10, qword [rdi+8*1]
 mov r11, qword [rdi+8*2]
 mov r12, qword [rdi+8*3]
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*2]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*3]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mov r12, rbx
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*2]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*3]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mov r12, rbx
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*2]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*3]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mov r12, rbx
 mov rdx, r8
 imul rdx, r9
 mulx rbp,rax,[rsi]
 add rax, r9
 adc rbp, 0
 mulx rbx,r9,[rsi+8]
 add r9, r10
 adc rbx, 0
 add r9, rbp
 adc rbx, 0
 mulx rbp,r10,[rsi+8*2]
 add r10, r11
 adc rbp, 0
 add r10, rbx
 adc rbp, 0
 mulx rbx,r11,[rsi+8*3]
 add r11, r12
 adc rbx, 0
 add r11, rbp
 adc rbx, 0
 mov r12, rbx
 xor rbx, rbx
 add r9, qword [rdi+8*(4+0)]
 mov qword [rdi+8*(4+0)], r9
 adc r10, qword [rdi+8*(4+1)]
 mov qword [rdi+8*(4+1)], r10
 adc r11, qword [rdi+8*(4+2)]
 mov qword [rdi+8*(4+2)], r11
 adc r12, qword [rdi+8*(4+3)]
 mov qword [rdi+8*(4+3)], r12
 adc rbx, 0
 sub r9, qword [rsi+8*0]
 sbb r10, qword [rsi+8*1]
 sbb r11, qword [rsi+8*2]
 sbb r12, qword [rsi+8*3]
 sbb rbx, 0
 mov rax, qword [rdi+8*(4+0)]
 cmovae rax, r9
 mov qword [r15+8*0], rax
 mov rax, qword [rdi+8*(4+1)]
 cmovae rax, r10
 mov qword [r15+8*1], rax
 mov rax, qword [rdi+8*(4+2)]
 cmovae rax, r11
 mov qword [r15+8*2], rax
 mov rax, qword [rdi+8*(4+3)]
 cmovae rax, r12
 mov qword [r15+8*3], rax
 jmp .quit
.above4:
 mov rbp, rdx
 sub rbp, 4
 lea rax, [rel mred_short]
 mov rbp, [rax+rbp*8-8]
 add rax, rbp
 call rax
 jmp .quit
.test_8N_case:
 test rdx, 7
 jnz .general_case
 call mred_8N
 jmp .quit
.general_case:
 call mred_N
.quit:
 vzeroupper
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.LEnd_cpMontRedAdc_BNU:
