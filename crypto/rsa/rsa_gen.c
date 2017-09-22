/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * NB: these functions have been "upgraded", the deprecated versions (which
 * are compatibility wrappers using these functions) are in rsa_depr.c. -
 * Geoff
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include "rsa_locl.h"

/*
static int rsa_builtin_keygen(RSA *rsa, int bits, BIGNUM *e_value,
                              BN_GENCB *cb);
                              */

/*
 * NB: this wrapper would normally be placed in rsa_lib.c and the static
 * implementation would probably be in rsa_eay.c. Nonetheless, is kept here
 * so that we don't introduce a new linker dependency. Eg. any application
 * that wasn't previously linking object code related to key-generation won't
 * have to now just because key-generation is part of RSA_METHOD.
 */
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)
{
    /*
    if (rsa->meth->rsa_keygen)
        return rsa->meth->rsa_keygen(rsa, bits, e_value, cb);
    */
    return rsa_builtin_keygen(rsa, bits, e_value, cb);
}

/**
 * @brief RSAキーペア生成
 */
static int rsa_builtin_keygen(RSA *rsa,
                              int bits,             // RSA鍵ビット数 2048 (16以上のみ許可)
                              BIGNUM *e_value,      // 最初は0x100001がセットされている
                              BN_GENCB *cb)
{
    BIGNUM *tmp;
    int bitsp, bitsq, ok = -1, n = 0;
    BN_CTX *ctx = NULL;

    /*
     * When generating ridiculously small keys, we can get stuck
     * continually regenerating the same prime values.
     */
    if (bits < 16) {
        ok = 0;             /* we set our own err */
        RSAerr(RSA_F_RSA_BUILTIN_KEYGEN, RSA_R_KEY_SIZE_TOO_SMALL);
        goto err;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    BIGNUM *r0 = BN_CTX_get(ctx); // 0
    BIGNUM *r1 = BN_CTX_get(ctx); // 0
    BIGNUM *r2 = BN_CTX_get(ctx); // 0
    BIGNUM *r3 = BN_CTX_get(ctx); // 0
    if (r3 == NULL)
        goto err;

    bitsp = (bits + 1) / 2;
    bitsq = bits - bitsp;

    /* We need the RSA components non-NULL */
    if (!rsa->n && ((rsa->n = BN_new()) == NULL))
        goto err;
    if (!rsa->d && ((rsa->d = BN_secure_new()) == NULL))
        goto err;
    if (!rsa->e && ((rsa->e = BN_new()) == NULL))
        goto err;
    if (!rsa->p && ((rsa->p = BN_secure_new()) == NULL))
        goto err;
    if (!rsa->q && ((rsa->q = BN_secure_new()) == NULL))
        goto err;
    if (!rsa->dmp1 && ((rsa->dmp1 = BN_secure_new()) == NULL))
        goto err;
    if (!rsa->dmq1 && ((rsa->dmq1 = BN_secure_new()) == NULL))
        goto err;
    if (!rsa->iqmp && ((rsa->iqmp = BN_secure_new()) == NULL))
        goto err;

    if (BN_copy(rsa->e, e_value) == NULL)
        goto err;

    // generate p : prime
    for (;;) {
        if (!BN_generate_prime_ex(rsa->p, bitsp, 0, NULL, NULL, cb))
            goto err;
        // r2 = p-1
        if (!BN_sub(r2, rsa->p, BN_value_one()))
            goto err;
        // r1 = gcd(p-1, rsa->e)
        if (!BN_gcd(r1, r2, rsa->e, ctx))
            goto err;
        // p-1, e は互いに素である
        if (BN_is_one(r1))
            break;
        // progress
        if (!BN_GENCB_call(cb, 2, n++))
            goto err;
    }
    // progress
    if (!BN_GENCB_call(cb, 3, 0))
        goto err;

    // generate q : prime
    for (;;) {
        // pと異なる素数を生成
        do {
            if (!BN_generate_prime_ex(rsa->q, bitsq, 0, NULL, NULL, cb))
                goto err;
        } while (BN_cmp(rsa->p, rsa->q) == 0);
        // r2 <- q-1
        if (!BN_sub(r2, rsa->q, BN_value_one()))
            goto err;
        // r1 <- gcd(q-1, e)
        if (!BN_gcd(r1, r2, rsa->e, ctx))
            goto err;
        // q-1, eは互いに素である
        if (BN_is_one(r1))
            break;
        // progress
        if (!BN_GENCB_call(cb, 2, n++))
            goto err;
    }
    // progress
    if (!BN_GENCB_call(cb, 3, 1))
        goto err;

    // p, q の大きさの順序を揃える
    if (BN_cmp(rsa->p, rsa->q) < 0) {
        tmp = rsa->p;
        rsa->p = rsa->q;
        rsa->q = tmp;
    }
    // p > q となっている

    /* calculate n = p * q */
    if (!BN_mul(rsa->n, rsa->p, rsa->q, ctx))
        goto err;

    /* calculate d = e ^ -1 mod (p-1)*(q-1) */
    if (!BN_sub(r1, rsa->p, BN_value_one()))
        goto err;               /* p-1 */
    if (!BN_sub(r2, rsa->q, BN_value_one()))
        goto err;               /* q-1 */
    if (!BN_mul(r0, r1, r2, ctx)){
        goto err;               /* (p-1)(q-1) */
    }
    {
        BIGNUM *pr0 = BN_new();

        if (pr0 == NULL)
            goto err;
        BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);
        if (!BN_mod_inverse(rsa->d, rsa->e, pr0, ctx)) {
            BN_free(pr0);
            goto err;               /* d */
        }
        /* We MUST free pr0 before any further use of r0 */
        BN_free(pr0);
    }

    // calculate d mod (p-1)
    // calculate d mod (q-1)
    {
        BIGNUM *d = BN_new();

        if (d == NULL)
            goto err;
        BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);

        if (   /* calculate d mod (p-1) */
               !BN_mod(rsa->dmp1, d, r1, ctx)
               /* calculate d mod (q-1) */
            || !BN_mod(rsa->dmq1, d, r2, ctx)) {
            BN_free(d);
            goto err;
        }
        /* We MUST free d before any further use of rsa->d */
        BN_free(d);
    }
    // calculate inverse of q mod p
    {
        BIGNUM *p = BN_new();

        if (p == NULL)
            goto err;
        BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);

        /* calculate inverse of q mod p */
        if (!BN_mod_inverse(rsa->iqmp, rsa->q, p, ctx)) {
            BN_free(p);
            goto err;
        }
        /* We MUST free p before any further use of rsa->p */
        BN_free(p);
    }

    ok = 1;
 err:
    if (ok == -1) {
        RSAerr(RSA_F_RSA_BUILTIN_KEYGEN, ERR_LIB_BN);
        ok = 0;
    }
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ok;
}
