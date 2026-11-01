/* jwt_pk_ec.inc — the P-256 point arithmetic used per token, #included by jwt_pk.inc once per field backend:
 * EC(name) names it, fe_mul / fe_sqr / fe_add / fe_sub are the field operations (portable C, or s2n-bignum's asm,
 * chosen at run time).  Key setup always uses the C instantiation. */

/* dbl-2001-b (a = -3), 3M + 5S */
static void EC(p256_dbl)(p256_jac_t *o, const p256_jac_t *p) {
    if (p->inf || fe_iszero(p->y)) {
        o->inf = 1;
        return;
    }
    fe_t delta, gamma, beta, alpha, t, u;
    fe_sqr(delta, p->z);
    fe_sqr(gamma, p->y);
    fe_mul(beta, p->x, gamma);
    fe_sub(t, p->x, delta);
    fe_add(u, p->x, delta);
    fe_mul(alpha, t, u);
    fe_add(t, alpha, alpha);
    fe_add(alpha, alpha, t); /* 3 (X - delta)(X + delta) */
    fe_add(t, p->y, p->z);
    fe_sqr(t, t);
    fe_sub(t, t, gamma);
    fe_sub(o->z, t, delta);
    fe_add(beta, beta, beta);
    fe_add(beta, beta, beta); /* 4 beta */
    fe_sqr(t, alpha);
    fe_add(u, beta, beta);
    fe_sub(o->x, t, u);
    fe_sub(t, beta, o->x);
    fe_mul(t, alpha, t);
    fe_sqr(gamma, gamma);
    fe_add(gamma, gamma, gamma);
    fe_add(gamma, gamma, gamma);
    fe_add(gamma, gamma, gamma); /* 8 gamma^2 */
    fe_sub(o->y, t, gamma);
    o->inf = 0;
}

/* p += q (affine), madd-2007-bl, 7M + 4S; exceptional cases (q = +-p) branch */
static void EC(p256_madd)(p256_jac_t *p, const fe_t qx, const fe_t qy) {
    if (p->inf) {
        memcpy(p->x, qx, 32), memcpy(p->y, qy, 32), fiat_p256_set_one(p->z), p->inf = 0;
        return;
    }
    fe_t z1z1, u2, s2, h, hh, i, j, r, v, t;
    fe_sqr(z1z1, p->z);
    fe_mul(u2, qx, z1z1);
    fe_mul(s2, qy, p->z);
    fe_mul(s2, s2, z1z1);
    fe_sub(h, u2, p->x);
    fe_sub(r, s2, p->y);
    if (fe_iszero(h)) {
        if (fe_iszero(r)) {
            p256_jac_t d = *p;
            EC(p256_dbl)(p, &d);
        } else {
            p->inf = 1;
        }
        return;
    }
    fe_add(r, r, r);
    fe_sqr(hh, h);
    fe_add(i, hh, hh);
    fe_add(i, i, i);
    fe_mul(j, h, i);
    fe_mul(v, p->x, i);
    fe_sqr(t, r);
    fe_sub(t, t, j);
    fe_sub(t, t, v);
    fe_sub(t, t, v); /* X3 */
    fe_add(p->z, p->z, h);
    fe_sqr(p->z, p->z);
    fe_sub(p->z, p->z, z1z1);
    fe_sub(p->z, p->z, hh);
    fe_sub(v, v, t);
    fe_mul(v, r, v);
    fe_mul(j, p->y, j);
    fe_add(j, j, j);
    fe_sub(p->y, v, j);
    memcpy(p->x, t, 32);
}

JWT_INLINE void EC(p256_add_digit)(p256_jac_t *acc, const p256_aff_t *row, int d) {
    if (!d) return;
    if (d > 0) {
        EC(p256_madd)(acc, row[d - 1].x, row[d - 1].y);
    } else {
        fe_t ny;
        fe_opp(ny, row[-d - 1].y);
        EC(p256_madd)(acc, row[-d - 1].x, ny);
    }
}

/* the point additions and the x-coordinate check for c tokens whose digits are recoded */
static void EC(es_points)(const jwt_pkey_t *k, int c, int16_t (*d1)[P256_NW], int16_t (*d2)[P256_NW], uint64_t (*r)[4],
                          const int *at, uint8_t *ok) {
    /* the point additions, JWT_ES_ILV tokens in lockstep: each token's 66 additions are one serial chain,
     * so running several side by side lets the core overlap their multiplications */
    for (int i0 = 0; i0 < c; i0 += JWT_ES_ILV) {
        int ni = c - i0 < JWT_ES_ILV ? c - i0 : JWT_ES_ILV;
        p256_jac_t acc[JWT_ES_ILV];
        for (int q = 0; q < ni; q++) acc[q].inf = 1;
        for (int j = 0; j < P256_NW; j++) {
            for (int q = 0; q < ni; q++) EC(p256_add_digit)(&acc[q], k->tg[j], d1[i0 + q][j]);
            for (int q = 0; q < ni; q++) EC(p256_add_digit)(&acc[q], k->tq[j], d2[i0 + q][j]);
        }
        for (int q = 0; q < ni; q++) {
            int i = i0 + q;
            if (acc[q].inf) continue;
            /* x(R) mod n == r  <=>  X == r' Z^2 for r' in {r, r + n} with r' < p */
            fe_t z2, rf, t;
            fe_sqr(z2, acc[q].z);
            fiat_p256_to_montgomery(rf, r[i]);
            fe_mul(t, rf, z2);
            int good = fe_eq(t, acc[q].x);
            uint64_t rn[4];
            fiat_p256_scalar_uint1 cy = 0;
            for (int j = 0; j < 4; j++) fiat_p256_scalar_addcarryx_u64(&rn[j], &cy, cy, r[i][j], P256_N[j]);
            if (!good && !cy && u256_lt(rn, P256_P)) {
                fiat_p256_to_montgomery(rf, rn);
                fe_mul(t, rf, z2);
                good = fe_eq(t, acc[q].x);
            }
            ok[at[i]] = (uint8_t)good;
        }
    }
}
