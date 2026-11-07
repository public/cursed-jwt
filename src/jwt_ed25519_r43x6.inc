/* jwt_ed25519_r43x6.inc — AVX-512 IFMA field arithmetic for the EdDSA comb additions, #included by jwt_ed25519.inc
 * on x86-64 with -DJWT_S2N.
 *
 * Everything between the "Firedancer" markers is copied from Firedancer (https://github.com/firedancer-io/firedancer,
 * commit 9d6f0a3), Copyright 2022 Firedancer Contributors, Apache License 2.0 (licenses/Firedancer-LICENSE.txt):
 *   src/util/simd/fd_avx512_wwl.h, fd_avx512_wwv.h   the wwl_* / wwv_* macros used below (a subset);
 *   src/ballet/ed25519/avx512/fd_r43x6_inl.h          lines 36-391: the FD_R43X6_QUAD_* macros, quad_mul_fast;
 *   src/ballet/ed25519/avx512/fd_curve25519_secure.c  FD_R43X6_GE_ADD_TABLE_ALT.
 * Modifications: only the type and attribute definitions just below the first marker (in place of Firedancer's
 * fd_util headers), static linkage, and the target pragma around the whole file. cursed-jwt's own code follows the
 * second marker. */
#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("avx512f,avx512vl,avx512bw,avx512dq,avx512ifma"))),                 \
                             apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f,avx512vl,avx512bw,avx512dq,avx512ifma")
#endif
/* ---- Firedancer ---------------------------------------------------------------------------------------------- */
// clang-format off
typedef __m512i wwl_t;
typedef wwl_t fd_r43x6_t;
#define FD_FN_CONST
#define FD_FN_UNUSED __attribute__((unused))
#define wwl(x0,x1,x2,x3,x4,x5,x6,x7) _mm512_setr_epi64( (x0), (x1), (x2), (x3), (x4), (x5), (x6), (x7) )
#define wwl_bcast(x)         _mm512_set1_epi64( (x) ) /* wwl(x, x, ... x) */
#define wwl_permute(p,x)     _mm512_permutexvar_epi64( (p), (x) )
#define wwl_select(p,x,y)    _mm512_permutex2var_epi64( (x), (p), (y) )
#define wwl_zero()           _mm512_setzero_si512()  /* wwl(0, 0, ... 0) */
#define wwl_add(x,y)         _mm512_add_epi64  ( (x), (y) ) /* wwl( x0+y0,      x1+y1,      ... x7+y7      ) */
#define wwl_sub(x,y)         _mm512_sub_epi64  ( (x), (y) ) /* wwl( x0-y0,      x1-y1,      ... x7-y7      ) */
#define wwl_shl(x,n)         _mm512_slli_epi64  ( (x), (uint)(n) ) /* wwl( x0<<n,  x1<<n,  ... x7<<n  ) */
#define wwl_shr(x,n)         _mm512_srai_epi64  ( (x), (uint)(n) ) /* wwl( x0>>n,  x1>>n,  ... x7>>n  ) */
#define wwl_shru(x,n)        _mm512_srli_epi64  ( (x), (uint)(n) ) /* wwl( x0>>n,  x1>>n,  ... x7>>n  ) (unsigned right shift) */
#define wwl_shr_vector(x,y)  _mm512_srav_epi64  ( (x), (y)       ) /* wwl( x0>>y0, x1>>y1, ... x7>>y7 ) */
#define wwl_shru_vector(x,y) _mm512_srlv_epi64  ( (x), (y)       ) /* wwl( x0>>y0, x1>>y1, ... x7>>y7 ) (unsigned right shift) */
#define wwl_and(x,y)         _mm512_and_epi64   ( (x), (y)       ) /* wwl( x0&y0,  x1&y1,  ... x7&y7  ) */
#define wwl_if(c,x,y)          _mm512_mask_blend_epi64 ( (__mmask8)(c), (y), (x) )    /* wwl( c0? x0    :y0, ... ) */
#define wwl_pack_halves(x,imm0,y,imm1) _mm512_shuffle_i64x2( (x), (y), 68+10*(imm0)+160*(imm1) )
#define wwl_pack_h0_h1(x,y) _mm512_mask_blend_epi64( (__mmask8)0xF0, (x), (y) )
#define wwl_madd52lo(a,b,c) _mm512_madd52lo_epu64( (a), (b), (c) )
#define wwl_madd52hi(a,b,c) _mm512_madd52hi_epu64( (a), (b), (c) )
#define wwv_add(x,y)         _mm512_add_epi64  ( (x), (y) ) /* wwv( x0+y0,      x1+y1,      ... x7+y7      ) */
#define wwv_sub(x,y)         _mm512_sub_epi64  ( (x), (y) ) /* wwv( x0-y0,      x1-y1,      ... x7-y7      ) */
#define wwv_add_if(c,x,y,z)    _mm512_mask_add_epi64   ( (z), (__mmask8)(c), (x), (y) ) /* wwv( c0?(x0+y0):z0, ... ) */


/* FD_R43X6_QUAD_DECL(Q) declares the wwl_t's Q03, Q14 and Q25 in the
   local scope to represent fd_r43x6_t X, Y, Z and T, but in a more
   efficient way for data parallel GF(p) operations under the hood.
   Organization:

     Q03 = [ X0 Y0 Z0 T0 | X3 Y3 Z3 T3 ]
     Q14 = [ X1 Y1 Z1 T1 | X4 Y4 Z4 T4 ]
     Q25 = [ X2 Y2 Z2 T2 | X5 Y5 Z5 T5 ]

   where Xi is the i-th limb of X. */

#define FD_R43X6_QUAD_DECL( Q ) wwl_t Q##03, Q##14, Q##25

/* FD_R43X6_QUAD_MOV( D, S ) does D = S.  D and S are FD_R43X6_QUAD
   declarations in the local scope. */

#define FD_R43X6_QUAD_MOV( D, S ) do { D##03 = S##03; D##14 = S##14; D##25 = S##25; } while(0)

/* FD_R43X6_QUAD_PACK(Q,x,y,z,t) does Q = (x,y,z,t) where Q is a
   FD_R43X6_QUAD declared in the local scope, x, y, z and t are
   arbitrary fd_r43x6_t. */

#define FD_R43X6_QUAD_PACK( Q, x,y,z,t ) do {                           \
    wwl_t _r0 = (x);                                                    \
    wwl_t _r1 = (y);                                                    \
    wwl_t _r2 = (z);                                                    \
    wwl_t _r3 = (t);                                                    \
    /* At this point _r0 = x0 x1 x2 x3 x4 x5 -- -- */                   \
    /*               _r1 = y0 y1 y2 y3 y4 y5 -- -- */                   \
    /*               _r2 = z0 z1 z2 z3 z4 z5 -- -- */                   \
    /*               _r3 = t0 t1 t2 t3 t4 t5 -- -- */                   \
    /* Transpose 2x2 blocks                        */                   \
    /* No _mm256_permute2f128_si256 equivalent? Sigh ... */             \
    wwl_t _t0 = wwl_select( wwl(  0, 1, 8, 9, 4, 5,12,13 ), _r0, _r2 ); \
    wwl_t _t1 = wwl_select( wwl(  0, 1, 8, 9, 4, 5,12,13 ), _r1, _r3 ); \
    wwl_t _t2 = wwl_select( wwl(  2, 3,10,11, 6, 7,12,13 ), _r0, _r2 ); \
    wwl_t _t3 = wwl_select( wwl(  2, 3,10,11, 6, 7,12,13 ), _r1, _r3 ); \
    /* At this point _t0 = x0 x1 z0 z1 x4 x5 z4 z5 */                   \
    /*               _t1 = y0 y1 t0 t1 y4 y5 t4 t5 */                   \
    /*               _t2 = x2 x3 z2 z3 -- -- -- -- */                   \
    /*               _t3 = y2 y3 t2 t3 -- -- -- -- */                   \
    /* Transpose 1x1 blocks                        */                   \
    wwl_t _c04 = _mm512_unpacklo_epi64( _t0, _t1 );                     \
    wwl_t _c15 = _mm512_unpackhi_epi64( _t0, _t1 );                     \
    wwl_t _c26 = _mm512_unpacklo_epi64( _t2, _t3 );                     \
    wwl_t _c37 = _mm512_unpackhi_epi64( _t2, _t3 );                     \
    /* At this point _c04 = x0 y0 z0 t0 x4 y4 z4 t4 */                  \
    /*               _c15 = x1 y1 t1 t1 x5 y5 z5 t5 */                  \
    /*               _c26 = x2 y2 z2 t2 -- -- -- -- */                  \
    /*               _c37 = x3 y3 z3 t3 -- -- -- -- */                  \
    Q##03 = wwl_pack_halves( _c04,0, _c37,0 );                          \
    Q##14 = wwl_pack_h0_h1 ( _c15,   _c04   );                          \
    Q##25 = wwl_pack_h0_h1 ( _c26,   _c15   );                          \
  } while(0)

/* FD_R43X6_QUAD_UNPACK(x,y,z,t,Q) does (x,y,z,t) = Q where x, y, z and
   t are arbitrary fd_r43x6_t and Q is a FD_R43X6_QUAD declared in the
   local scope. */

#define FD_R43X6_QUAD_UNPACK( x,y,z,t, Q ) do {               \
    wwl_t _r0 = Q##03;                                        \
    wwl_t _r1 = Q##14;                                        \
    wwl_t _r2 = Q##25;                                        \
    wwl_t _r3 = wwl_zero();                                   \
    /* At this point _r0 = x0 y0 z0 t0 x3 y3 z3 t3 */         \
    /*               _r1 = x1 y1 z1 t1 x4 y4 z4 t4 */         \
    /*               _r2 = x2 y2 z2 t2 x5 y5 z5 t5 */         \
    /*               _r3 =  0  0  0  0  0  0  0  0 */         \
    /* Transpose 1x1 blocks */                                \
    wwl_t _c0 = _mm512_unpacklo_epi64( _r0, _r1 );            \
    wwl_t _c1 = _mm512_unpackhi_epi64( _r0, _r1 );            \
    wwl_t _c2 = _mm512_unpacklo_epi64( _r2, _r3 );            \
    wwl_t _c3 = _mm512_unpackhi_epi64( _r2, _r3 );            \
    /* At this point _c0 = x0 x1 z0 z1 x3 x4 z3 z4 */         \
    /*               _c1 = y0 y1 t0 t1 y3 y4 t3 t4 */         \
    /*               _c2 = x2  0 z2  0 x5  0 z5  0 */         \
    /*               _c3 = y2  0 t2  0 y5  0 t5  0 */         \
    (x) = wwl_select( wwl(  0,1, 8, 4,5,12, 9,9 ), _c0,_c2 ); \
    (y) = wwl_select( wwl(  0,1, 8, 4,5,12, 9,9 ), _c1,_c3 ); \
    (z) = wwl_select( wwl(  2,3,10, 6,7,14, 9,9 ), _c0,_c2 ); \
    (t) = wwl_select( wwl(  2,3,10, 6,7,14, 9,9 ), _c1,_c3 ); \
  } while(0)

/* FD_R43X6_QUAD_PERMUTE(D,S) does:
     D = [ S(imm0) S(imm1) S(imm2) S(imm3) ]
   where imm* are in [0,3] (0/1/2/3->X/Y/Z/T) */

#define FD_R43X6_QUAD_PERMUTE( D, imm0,imm1,imm2,imm3, S ) do {                                  \
    wwl_t const _perm = wwl( (imm0),(imm1),(imm2),(imm3), 4+(imm0),4+(imm1),4+(imm2),4+(imm3) ); \
    D##03 = wwl_permute( _perm, S##03 );                                                         \
    D##14 = wwl_permute( _perm, S##14 );                                                         \
    D##25 = wwl_permute( _perm, S##25 );                                                         \
  } while(0)

/* FD_R43X6_QUAD_LANE_IF does:
     D = [ imm0 ? SX : TX, imm1 ? SY : TY, imm2 ? SZ : TZ, imm3 ? ST : TT ]
   imm* should be in [0,1]. */

#define FD_R43X6_QUAD_LANE_IF( D, imm0,imm1,imm2,imm3, S, T ) do { \
    int _mask = 17*(imm0) + 34*(imm1) + 68*(imm2) + 136*(imm3);    \
    D##03 = wwl_if( _mask, S##03, T##03 );                         \
    D##14 = wwl_if( _mask, S##14, T##14 );                         \
    D##25 = wwl_if( _mask, S##25, T##25 );                         \
  } while(0)

/* FD_R43X6_QUAD_LANE_ADD_FAST does:
     D = [ (imm0 ? (PX+QX) : SX) (imm1 ? (PY+QY) : SY) (imm2 ? (PZ+QZ) : SZ) (imm3 ? (PT+QT) : ST) ]
   imm* should be in [0,1]. */

#define FD_R43X6_QUAD_LANE_ADD_FAST( D, S, imm0,imm1,imm2,imm3, P, Q ) do { \
    int _mask = 17*(imm0) + 34*(imm1) + 68*(imm2) + 136*(imm3);             \
    D##03 = wwv_add_if( _mask, P##03, Q##03, S##03 );                       \
    D##14 = wwv_add_if( _mask, P##14, Q##14, S##14 );                       \
    D##25 = wwv_add_if( _mask, P##25, Q##25, S##25 );                       \
  } while(0)

/* FD_R43X6_QUAD_LANE_SUB_FAST does:
     D = [ (imm0 ? (PX-QX) : SX) (imm1 ? (PY-QY) : SY) (imm2 ? (PZ-QZ) : SZ) (imm3 ? (PT-QT) : ST) ]
   imm* should be in [0,1]. */
#define FD_R43X6_QUAD_LANE_SUB_FAST( D, S, imm0,imm1,imm2,imm3, P, Q ) do { \
    int _mask = 17*(imm0) + 34*(imm1) + 68*(imm2) + 136*(imm3); \
    FD_R43X6_QUAD_DECL( M );                                    \
    M##03 = wwl( 8796093022189L, 8796093022189L, 8796093022189L, 8796093022189L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L ); \
    M##14 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L ); \
    M##25 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 1099511627775L, 1099511627775L, 1099511627775L, 1099511627775L ); \
    M##03 = wwv_sub( M##03, Q##03 );                            \
    M##14 = wwv_sub( M##14, Q##14 );                            \
    M##25 = wwv_sub( M##25, Q##25 );                            \
    D##03 = wwv_add_if( _mask, P##03, M##03, S##03 );           \
    D##14 = wwv_add_if( _mask, P##14, M##14, S##14 );           \
    D##25 = wwv_add_if( _mask, P##25, M##25, S##25 );           \
  } while(0)

/* FD_R43X6_QUAD_FOLD_UNSIGNED(R,P) does:
     R = [ fd_r43x6_fold_unsigned(PX) fd_r43x6_fold_unsigned(PY) fd_r43x6_fold_unsigned(PZ) fd_r43x6_fold_unsigned(PT) ] */

#define FD_R43X6_QUAD_FOLD_UNSIGNED( R, P ) do {                                            \
    long const _m43 = (1L<<43) - 1L;                                                        \
    long const _m40 = (1L<<40) - 1L;                                                        \
                                                                                            \
    wwl_t const _m43_m43 = wwl_bcast( _m43 );                                               \
    wwl_t const _m43_m40 = wwl( _m43,_m43,_m43,_m43, _m40,_m40,_m40,_m40 );                 \
    wwl_t const _s43_s40 = wwl(  43L, 43L, 43L, 43L,  40L, 40L, 40L, 40L );                 \
                                                                                            \
    wwl_t _Ph03    = wwl_shru       ( P##03, 43      );                                     \
    wwl_t _Ph14    = wwl_shru       ( P##14, 43      );                                     \
    wwl_t _Ph25    = wwl_shru_vector( P##25, _s43_s40 );                                    \
    wwl_t _19_Ph25 = wwl_add( _Ph25, wwl_add( wwl_shl( _Ph25, 1 ), wwl_shl( _Ph25, 4 ) ) ); \
                                                                                            \
    R##03 = wwl_add( wwl_and( P##03, _m43_m43 ), wwl_pack_halves( _19_Ph25,1, _Ph25,0 ) );  \
    R##14 = wwl_add( wwl_and( P##14, _m43_m43 ), _Ph03 );                                   \
    R##25 = wwl_add( wwl_and( P##25, _m43_m40 ), _Ph14 );                                   \
  } while(0)

/* FD_R43X6_QUAD_FOLD_SIGNED(R,P) does:
     R = [ fd_r43x6_fold_signed(PX) fd_r43x6_fold_signed(PY) fd_r43x6_fold_signed(PZ) fd_r43x6_fold_signed(PT) ] */
#define FD_R43X6_QUAD_FOLD_SIGNED( R, P ) do {                                                                \
    long const _b0  = 19L<<23;                                                                                \
    long const _bb  =  1L<<20;                                                                                \
    long const _m43 = (1L<<43) - 1L;                                                                          \
    long const _m40 = (1L<<40) - 1L;                                                                          \
                                                                                                              \
    wwl_t const _bias03  = wwl(  _b0, _b0, _b0, _b0,  _bb, _bb, _bb, _bb );                                   \
    wwl_t const _bias    = wwl_bcast( _bb );                                                                  \
    wwl_t const _m43_m43 = wwl_bcast( _m43 );                                                                 \
    wwl_t const _m43_m40 = wwl( _m43,_m43,_m43,_m43, _m40,_m40,_m40,_m40 );                                   \
    wwl_t const _s43_s40 = wwl(  43L, 43L, 43L, 43L,  40L, 40L, 40L, 40L );                                   \
                                                                                                              \
    wwl_t _P03 = wwl_sub( P##03, _bias03 );                                                                   \
    wwl_t _P14 = wwl_sub( P##14, _bias   );                                                                   \
    wwl_t _P25 = wwl_sub( P##25, _bias   );                                                                   \
                                                                                                              \
    wwl_t _Ph03    = wwl_shr       ( _P03, 43       );                                                        \
    wwl_t _Ph14    = wwl_shr       ( _P14, 43       );                                                        \
    wwl_t _Ph25    = wwl_shr_vector( _P25, _s43_s40 );                                                        \
    wwl_t _19_Ph25 = wwl_add( _Ph25, wwl_add( wwl_shl( _Ph25, 1 ), wwl_shl( _Ph25, 4 ) ) );                   \
                                                                                                              \
    R##03 = wwl_add( wwl_and( _P03, _m43_m43 ), wwl_add( wwl_pack_halves( _19_Ph25,1, _Ph25,0 ), _bias03 ) ); \
    R##14 = wwl_add( wwl_and( _P14, _m43_m43 ), wwl_add( _Ph03,                                  _bias   ) ); \
    R##25 = wwl_add( wwl_and( _P25, _m43_m40 ), wwl_add( _Ph14,                                  _bias   ) ); \
  } while(0)

/* FD_R43X6_QUAD_MUL_FAST(R,P,Q) does (
     [ fd_r43x6_mul_fast(PX,QX) fd_r43x6_mul_fast(PY,QY) fd_r43x6_mul_fast(PZ,QZ) fd_r43x6_mul_fast(PT,QT) ]
   Written this way so that pointer escapes don't inhibit optimizations. */

#define FD_R43X6_QUAD_MUL_FAST( R, P, Q ) do {                                                                   \
    FD_R43X6_QUAD_DECL( _R ); fd_r43x6_quad_mul_fast( &_R03,&_R14,&_R25, P##03,P##14,P##25, Q##03,Q##14,Q##25 ); \
    FD_R43X6_QUAD_MOV( R, _R );                                                                                  \
  } while(0)

FD_FN_UNUSED static void /* let compiler decide if worth inlining */
fd_r43x6_quad_mul_fast( fd_r43x6_t * _z03, fd_r43x6_t * _z14, fd_r43x6_t * _z25,
                        fd_r43x6_t    x03, fd_r43x6_t    x14, fd_r43x6_t    x25,
                        fd_r43x6_t    y03, fd_r43x6_t    y14, fd_r43x6_t    y25 ) {

  /* Grade school-ish from the original mul:

                                       x5   x4   x3   x2   x1   x0
                                  x    y5   y4   y3   y2   y1   y0
                                  --------------------------------
                                     p50l p40l p30l p20l p10l p00l
                                p50h p40h p30h p20h p10h p00h
                                p51l p41l p31l p21l p11l p01l
                           p51h p41h p31h p21h p11h p01h
                           p52l p42l p32l p22l p12l p02l
                      p52h p42h p32h p22h p12h p02h
                      p53l p43l p33l p23l p13l p03l
                 p53h p43h p33h p23h p13h p03h
                 p54l p44l p34l p24l p14l p04l
            p54h p44h p34h p24h p14h p04h
            p55l p45l p35l p25l p15l p05l
       p55h p45h p35h p25h p15h p05h
       -----------------------------------------------------------
        zb5  zb4  zb3  zb2  zb1  zb0  za5  za4  za3  za2  za1  za0

     Reorganize the partials into low and high parts:

                                     p50l p40l p30l p20l p10l p00l
                                p51l p41l p31l p21l p11l p01l
                           p52l p42l p32l p22l p12l p02l
                      p53l p43l p33l p23l p13l p03l
                 p54l p44l p34l p24l p14l p04l
            p55l p45l p35l p25l p15l p05l

                                p50h p40h p30h p20h p10h p00h
                           p51h p41h p31h p21h p11h p01h
                      p52h p42h p32h p22h p12h p02h
                 p53h p43h p33h p23h p13h p03h
            p54h p44h p34h p24h p14h p04h
       p55h p45h p35h p25h p15h p05h

     We start with 3 8-lane vectors per input.  These hold 4 fd_r43x6_t
     organized as:

       x03 = [ X0 X3 ], y03 = [ Y0 Y3 ],
       x14 = [ X1 X4 ], y14 = [ Y1 Y4 ],
       x25 = [ X2 X5 ], y25 = [ Y2 Y5 ]

     Above, Xi indicates limb i for the 4 input.  We can quickly form
     "xii = [ Xi Xi ]" by packing halves of the x inputs.  And then
     doing madd52lo of this on a similarly packed yjk we get:

       LO( xii * yjk ) = [ pijl pikl ]

     Doing x00, x11, x22, x33, x44, x55 against y03, y14, y25 yields all
     the low partials, organized:

       [ p00l p03l ], [ p01l p04l ], [ p02l p05l ],
       [ p10l p13l ], [ p11l p14l ], [ p12l p15l ],
       [ p20l p23l ], [ p21l p24l ], [ p22l p25l ],
       [ p30l p33l ], [ p31l p34l ], [ p32l p35l ],
       [ p40l p43l ], [ p41l p44l ], [ p42l p45l ],
       [ p50l p53l ], [ p51l p54l ], [ p52l p55l ]

     If we use the lower half of these results to accumulate the
     partials for the first 3 rows, we have:

       p0_q3 = [ p00l p03l ]
       p1_q4 = [ p10l p13l ] + [ p01l p04l ]
       p2_q5 = [ p20l p23l ] + [ p11l p14l ] + [ p02l p05l ]
       p3_q6 = [ p30l p33l ] + [ p21l p24l ] + [ p12l p15l ]
       p4_q7 = [ p40l p43l ] + [ p31l p34l ] + [ p22l p25l ]
       p5_q8 = [ p50l p53l ] + [ p41l p44l ] + [ p32l p35l ]
       p6_q9 =                 [ p51l p54l ] + [ p42l p45l ]
       p7_qa =                                 [ p52l p55l ]

     We also see that doing this implicitly accumulates the last 3 rows
     of partials at the same time.  Note also that we can use the
     accumulate features of MADD to do these accumulations and we have
     lots of independent MADD chains.

     The exact same applies for the HI partials.  When we sum the LO and
     HI partials, we need to shift the HI parts left by 9 for the
     reasons described in the scalar version.  When we sum the lower and
     upper halves to finish the partial accumulation, we repack them
     into two FD_R43X6_QUAD representations at the same time.

     This yields the below.  This has massive ILP with utilization of
     all lanes with no wasted or redundant multiplications and very
     minimal fast shuffling. */

  wwl_t const _zz = wwl_zero();

  wwl_t x00   = wwl_pack_halves( x03,0, x03,0 );
  wwl_t x11   = wwl_pack_halves( x14,0, x14,0 );
  wwl_t x22   = wwl_pack_halves( x25,0, x25,0 );
  wwl_t x33   = wwl_pack_halves( x03,1, x03,1 );
  wwl_t x44   = wwl_pack_halves( x14,1, x14,1 );
  wwl_t x55   = wwl_pack_halves( x25,1, x25,1 );

# if 1 /* This version is faster even though it has more adds due to higher ILP */
  wwl_t p0_q3 = wwl_madd52lo(                             _zz, x00, y03 );
  wwl_t p1_q4 = wwl_madd52lo( wwl_madd52lo(               _zz, x11, y03 ), x00, y14 );
  wwl_t p2_q5 = wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz, x22, y03 ), x11, y14 ), x00, y25 );
  wwl_t p3_q6 = wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz, x33, y03 ), x22, y14 ), x11, y25 );
  wwl_t p4_q7 = wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz, x44, y03 ), x33, y14 ), x22, y25 );
  wwl_t p5_q8 = wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz, x55, y03 ), x44, y14 ), x33, y25 );
  wwl_t p6_q9 =               wwl_madd52lo( wwl_madd52lo( _zz,             x55, y14 ), x44, y25 );
  wwl_t p7_qa =                             wwl_madd52lo( _zz,                         x55, y25 );

  /**/  p1_q4 = wwl_add( p1_q4, wwl_shl( wwl_madd52hi(                             _zz, x00, y03 ),                         9 ) );
  /**/  p2_q5 = wwl_add( p2_q5, wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz, x11, y03 ), x00, y14 ),             9 ) );
  /**/  p3_q6 = wwl_add( p3_q6, wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz, x22, y03 ), x11, y14 ), x00, y25 ), 9 ) );
  /**/  p4_q7 = wwl_add( p4_q7, wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz, x33, y03 ), x22, y14 ), x11, y25 ), 9 ) );
  /**/  p5_q8 = wwl_add( p5_q8, wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz, x44, y03 ), x33, y14 ), x22, y25 ), 9 ) );
  /**/  p6_q9 = wwl_add( p6_q9, wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz, x55, y03 ), x44, y14 ), x33, y25 ), 9 ) );
  /**/  p7_qa = wwl_add( p7_qa, wwl_shl(               wwl_madd52hi( wwl_madd52hi( _zz,             x55, y14 ), x44, y25 ), 9 ) );
  wwl_t p8_qb =                 wwl_shl(                             wwl_madd52hi( _zz,                         x55, y25 ), 9 );
# else
  wwl_t p1_q4 = wwl_shl( wwl_madd52hi(                             _zz,   x00, y03 ),                         9 );
  wwl_t p2_q5 = wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz,   x11, y03 ), x00, y14 ),             9 );
  wwl_t p3_q6 = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,   x22, y03 ), x11, y14 ), x00, y25 ), 9 );
  wwl_t p4_q7 = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,   x33, y03 ), x22, y14 ), x11, y25 ), 9 );
  wwl_t p5_q8 = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,   x44, y03 ), x33, y14 ), x22, y25 ), 9 );
  wwl_t p6_q9 = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,   x55, y03 ), x44, y14 ), x33, y25 ), 9 );
  wwl_t p7_qa = wwl_shl(               wwl_madd52hi( wwl_madd52hi( _zz,               x55, y14 ), x44, y25 ), 9 );
  wwl_t p8_qb = wwl_shl(                             wwl_madd52hi( _zz,                           x55, y25 ), 9 );

  wwl_t p0_q3 =          wwl_madd52lo(                             _zz,   x00, y03 );
  /**/  p1_q4 =          wwl_madd52lo( wwl_madd52lo(               p1_q4, x11, y03 ), x00, y14 );
  /**/  p2_q5 =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( p2_q5, x22, y03 ), x11, y14 ), x00, y25 );
  /**/  p3_q6 =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( p3_q6, x33, y03 ), x22, y14 ), x11, y25 );
  /**/  p4_q7 =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( p4_q7, x44, y03 ), x33, y14 ), x22, y25 );
  /**/  p5_q8 =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( p5_q8, x55, y03 ), x44, y14 ), x33, y25 );
  /**/  p6_q9 =                        wwl_madd52lo( wwl_madd52lo( p6_q9,             x55, y14 ), x44, y25 );
  /**/  p7_qa =                                      wwl_madd52lo( p7_qa,                         x55, y25 );
# endif

  wwl_t q6_p3 = wwl_pack_halves( p3_q6,1, p3_q6,0 );
  wwl_t q7_p4 = wwl_pack_halves( p4_q7,1, p4_q7,0 );
  wwl_t q8_p5 = wwl_pack_halves( p5_q8,1, p5_q8,0 );

  wwl_t za03  = wwv_add_if( 0xF0, p0_q3, q6_p3, p0_q3 );
  wwl_t za14  = wwv_add_if( 0xF0, p1_q4, q7_p4, p1_q4 );
  wwl_t za25  = wwv_add_if( 0xF0, p2_q5, q8_p5, p2_q5 );

  wwl_t zb03  = wwv_add_if( 0x0F, p6_q9, q6_p3, p6_q9 );
  wwl_t zb14  = wwv_add_if( 0x0F, p7_qa, q7_p4, p7_qa );
  wwl_t zb25  = wwv_add_if( 0x0F, p8_qb, q8_p5, p8_qb );

  /* At this point:

       z = <za0,za1,za2,za3,za4,za5> + 2^258 <zb0,zb1,zb2,zb3,zb4,zb5>
         = <za0,za1,za2,za3,za4,za5> +   152 <zb0,zb1,zb2,zb3,zb4,zb5>

     and we can sum this directly (see scalar version for proof).  Like
     the scalar version, we do the multiplication via shift-and-add
     techniques because mullo is slow. */

  wwl_t z03 = wwl_add( wwl_add( za03, wwl_shl( zb03, 7 ) ), wwl_add( wwl_shl( zb03, 4 ), wwl_shl( zb03, 3 ) ) );
  wwl_t z14 = wwl_add( wwl_add( za14, wwl_shl( zb14, 7 ) ), wwl_add( wwl_shl( zb14, 4 ), wwl_shl( zb14, 3 ) ) );
  wwl_t z25 = wwl_add( wwl_add( za25, wwl_shl( zb25, 7 ) ), wwl_add( wwl_shl( zb25, 4 ), wwl_shl( zb25, 3 ) ) );

  FD_R43X6_QUAD_MOV( *_z, z );
}

/* FD_R43X6_GE_ADD_TABLE_ALT is similar to FD_R43X6_GE_ADD,
   with 3 minor differences:
   1. order of arguments: P3, P1 points in extended Edwards coordinates,
      T2 precomputed table point
   2. T2 = (Y-X : Y+X : Z==1 : kT), all coords are u44
   3. temp vars as input, so we can safely clear them in the caller
*/
#define FD_R43X6_GE_ADD_TABLE_ALT( P3, P1, T2, _ta, _tb ) do {                                                                  \
    FD_R43X6_QUAD_MOV          ( _ta, T2 );                     /* _ta = (Y2-X2,Y2+X2,Z2=1,T2*2d), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,2,3, P1 );            /* _tb = (Y1,   X1,   Z1,  T1   ), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,0, _tb, P1 );  /* _tb = (Y1-X1,X1,   Z1,  T1   ), s62|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,1,0, _tb, P1 );  /* _tb = (Y1-X1,Y1+X1,Z1*2,T1   ), s62|s62|s62|s61 */ \
    FD_R43X6_QUAD_FOLD_SIGNED  ( _tb, _tb );                    /* _tb = (Y1-X1,Y1+X1,Z1*2,T1   ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (A,    B,    D,   C    ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( _ta, _ta );                    /* _ta = (A,    B,    D,   C    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,3,2, _ta );           /* _tb = (B,    A,    C,   D    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,1, _tb, _ta ); /* _tb = (E,    A,    C,   F    ), s45|u44|u44|s45 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,1,0, _tb, _ta ); /* _tb = (E,    H,    G,   F    ), s45|u45|u45|s45 */ \
    FD_R43X6_QUAD_FOLD_SIGNED  ( _tb, _tb );                    /* _tb = (E,    H,    G,   F    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 0,2,2,0, _tb );           /* _ta = (E,    G,    G,   E    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 3,1,3,1, _tb );           /* _tb = (F,    H,    F,   H    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (X3,   Y3,   Z3,  T3   ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( P3, _ta );                     /* P3  = (X3,   Y3,   Z3,  T3   ), u44|u44|u44|u44 */ \
  } while(0)

// clang-format on
/* ---- end of Firedancer --------------------------------------------------------------------------------------- */

/* ---- cursed-jwt ---------------------------------------------------------------------------------------------- */
/* With AVX-512 IFMA on a CPU where zmm costs no clock speed (FAST_ZMM: AMD Zen 4 / 5), the comb additions run on
 * Firedancer's 4-way radix-2^43 field: P's X, Y, Z, T sit in three zmm registers (limbs i and i + 3 of all four
 * coordinates in each), so the 4 multiplications of each step of the mixed addition run as one quad multiply.
 * The comb tables stay in jwt_ed25519.inc's canonical 4 x 64-bit (y - x, y + x, 2dxy) form, shared with the
 * s2n-bignum path; each looked-up entry is split into 43-bit limbs in registers (AVX-512F only, no VBMI). */
static int ed_r43_ok(void) {
    return (jwt_cpu() & (JWT_CPU_IFMA | JWT_CPU_FAST_ZMM)) == (JWT_CPU_IFMA | JWT_CPU_FAST_ZMM);
}
/* a canonical 255-bit element (4 x 64-bit limbs) -> radix 2^43 in lanes 0..5 (lanes 6, 7 zero) */
static inline wwl_t ed_r43_from4(const uint64_t v[4]) {
    __m512i w = _mm512_castsi256_si512(_mm256_loadu_si256((const __m256i *)v));
    /* limb i = bits 43i..43i+42: word wi >> si, OR word wi+1 << (64 - si) (a shift >= 64 gives 0) */
    __m512i a = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 0, 1, 2, 2, 3, 0, 0), w);
    __m512i b = _mm512_permutexvar_epi64(_mm512_setr_epi64(1, 1, 2, 3, 3, 3, 0, 0), w);
    __m512i lo = _mm512_srlv_epi64(a, _mm512_setr_epi64(0, 43, 22, 1, 44, 23, 64, 64));
    __m512i hi = _mm512_sllv_epi64(b, _mm512_setr_epi64(64, 21, 42, 63, 20, 64, 64, 64));
    const long m43 = (1L << 43) - 1;
    return _mm512_and_si512(_mm512_or_si512(lo, hi), _mm512_setr_epi64(m43, m43, m43, m43, m43, m43, 0, 0));
}
/* tests: ed_r43_from4's 8 lanes as longs, from code built without AVX-512 */
FD_FN_UNUSED static void ed_r43_from4_store(long out[8], const uint64_t v[4]) {
    _mm512_storeu_si512((void *)out, ed_r43_from4(v));
}
/* 6 non-negative limbs < 2^44 (radix 2^43) -> the canonical element mod p, little-endian bytes */
static void ed_r43_canon(uint8_t out[32], const long l[8]) {
    uint64_t w[5] = { 0, 0, 0, 0, 0 };
    for (int i = 0; i < 6; i++) { /* add l_i 2^(43 i) */
        int pos = 43 * i, wi = pos >> 6, sh = pos & 63;
        u128 v = (u128)(uint64_t)l[i] << sh, c = 0;
        for (int j = wi; j < 5 && (v || c); j++) {
            c += (u128)w[j] + (uint64_t)v;
            w[j] = (uint64_t)c, c >>= 64, v >>= 64;
        }
    }
    for (int r = 0; r < 2; r++) { /* fold 2^255 = 19 (mod p): value < 2^259, then < 2^255 + 19 * 2^4, then < 2^255 */
        uint64_t hi = w[3] >> 63 | w[4] << 1;
        w[3] &= 0x7fffffffffffffffull, w[4] = 0;
        u128 c = (u128)hi * 19;
        for (int j = 0; j < 5; j++) c += w[j], w[j] = (uint64_t)c, c >>= 64;
    }
    static const uint64_t p[4] = { 0xffffffffffffffedull, ~0ull, ~0ull, 0x7fffffffffffffffull };
    int ge = 1; /* value >= p ? */
    for (int j = 3; j >= 0; j--)
        if (w[j] != p[j]) {
            ge = w[j] > p[j];
            break;
        }
    if (ge) {
        uint64_t bw = 0;
        for (int j = 0; j < 4; j++) {
            u128 d = (u128)w[j] - p[j] - bw;
            w[j] = (uint64_t)d, bw = (uint64_t)(d >> 64) & 1;
        }
    }
    memcpy(out, w, 32); /* x86-64 is little-endian */
}
/* P = sum of the comb entries the digits select (signed: negative digits subtract); X, Y, Z back in fiat's limbs */
static void ed_comb_r43(const ed_key_t *k, const int16_t *ds, const int16_t *dk, ed_p3 *P) {
    FD_R43X6_QUAD_DECL(A);
    FD_R43X6_QUAD_DECL(T);
    FD_R43X6_QUAD_DECL(ta);
    FD_R43X6_QUAD_DECL(tb);
    const wwl_t one = _mm512_setr_epi64(1, 0, 0, 0, 0, 0, 0, 0), zero = _mm512_setzero_si512();
    FD_R43X6_QUAD_PACK(A, zero, one, one, zero); /* the identity (0, 1, 1, 0) */
    uint64_t nq[12];
#define ED_R43_ADD(q)                                                                                                  \
    do {                                                                                                               \
        const uint64_t *q_ = (q);                                                                                      \
        FD_R43X6_QUAD_PACK(T, ed_r43_from4(q_), ed_r43_from4(q_ + 4), one, ed_r43_from4(q_ + 8));                      \
        FD_R43X6_GE_ADD_TABLE_ALT(A, A, T, ta, tb);                                                                    \
    } while (0)
    for (int j = 0; j < ED_NW; j++) {
        if (ds[j] > 0) ED_R43_ADD(k->tb[j][ds[j] - 1]);
        else if (ds[j] < 0) {
            ed_neg4(nq, k->tb[j][-ds[j] - 1]);
            ED_R43_ADD(nq);
        }
        if (dk[j] > 0) ED_R43_ADD(k->ta[j][dk[j] - 1]);
        else if (dk[j] < 0) {
            ed_neg4(nq, k->ta[j][-dk[j] - 1]);
            ED_R43_ADD(nq);
        }
    }
#undef ED_R43_ADD
    wwl_t x, y, z, t;
    FD_R43X6_QUAD_UNPACK(x, y, z, t, A);
    (void)t;
    long l[8] __attribute__((aligned(64)));
    uint8_t b[32];
    _mm512_store_si512((void *)l, x), ed_r43_canon(b, l), fiat_25519_from_bytes(P->X, b);
    _mm512_store_si512((void *)l, y), ed_r43_canon(b, l), fiat_25519_from_bytes(P->Y, b);
    _mm512_store_si512((void *)l, z), ed_r43_canon(b, l), fiat_25519_from_bytes(P->Z, b);
}
#if defined(__clang__)
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
