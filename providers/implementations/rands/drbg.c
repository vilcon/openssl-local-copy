/*
 * Copyright 2011-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "crypto/rand.h"
#include "drbg_local.h"
#include "internal/thread_once.h"
#include "crypto/cryptlib.h"
#include "prov/seeding.h"
#include "prov/rand_pool.h"
#include "prov/provider_ctx.h"
#include "prov/providercommonerr.h"

/*
 * Support framework for NIST SP 800-90A DRBG
 *
 * See manual page PROV_DRBG(7) for a general overview.
 *
 * The OpenSSL model is to have new and free functions, and that new
 * does all initialization.  That is not the NIST model, which has
 * instantiation and un-instantiate, and re-use within a new/free
 * lifecycle.  (No doubt this comes from the desire to support hardware
 * DRBG, where allocation of resources on something like an HSM is
 * a much bigger deal than just re-setting an allocated resource.)
 */

/* NIST SP 800-90A DRBG recommends the use of a personalization string. */
static const char ossl_pers_string[] = DRBG_DEFAULT_PERS_STRING;

static const OSSL_DISPATCH *find_call(const OSSL_DISPATCH *dispatch,
                                      int function);

static int rand_drbg_restart(PROV_DRBG *drbg);

int drbg_lock(void *vctx)
{
    PROV_DRBG *drbg = vctx;

    if (drbg == NULL || drbg->lock == NULL)
        return 1;
    return CRYPTO_THREAD_write_lock(drbg->lock);
}

void drbg_unlock(void *vctx)
{
    PROV_DRBG *drbg = vctx;

    if (drbg != NULL && drbg->lock != NULL)
        CRYPTO_THREAD_unlock(drbg->lock);
}

static int drbg_lock_parent(PROV_DRBG *drbg)
{
    void *parent = drbg->parent;

    if (parent != NULL
            && drbg->parent_lock != NULL
            && !drbg->parent_lock(parent)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_LOCKING_NOT_ENABLED);
        return 0;
    }
    return 1;
}

static void drbg_unlock_parent(PROV_DRBG *drbg)
{
    void *parent = drbg->parent;

    if (parent != NULL && drbg->parent_unlock != NULL)
        drbg->parent_unlock(parent);
}

static int get_parent_strength(PROV_DRBG *drbg, unsigned int *str)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    void *parent = drbg->parent;
    int res;

    if (drbg->parent_get_ctx_params == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PARENT_STRENGTH);
        return 0;
    }

    *params = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, str);
    if (!drbg_lock_parent(drbg)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_LOCK_PARENT);
        return 0;
    }
    res = drbg->parent_get_ctx_params(parent, params);
    drbg_unlock_parent(drbg);
    if (!res) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PARENT_STRENGTH);
        return 0;
    }
    return 1;
}

static unsigned int get_parent_reseed_count(PROV_DRBG *drbg)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    void *parent = drbg->parent;
    unsigned int r;

    *params = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_CTR, &r);
    if (!drbg_lock_parent(drbg)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_LOCK_PARENT);
        goto err;
    }
    if (!drbg->parent_get_ctx_params(parent, params)) {
        drbg_unlock_parent(drbg);
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_RESEED_PROP_CTR);
        goto err;
    }
    drbg_unlock_parent(drbg);
    return r;

 err:
    r = tsan_load(&drbg->reseed_counter) - 2;
    if (r == 0)
        r = UINT_MAX;
    return r;
}

/*
 * Implements the get_entropy() callback (see RAND_DRBG_set_callbacks())
 *
 * If the DRBG has a parent, then the required amount of entropy input
 * is fetched using the parent's RAND_DRBG_generate().
 *
 * Otherwise, the entropy is polled from the system entropy sources
 * using prov_pool_acquire_entropy().
 *
 * If a random pool has been added to the DRBG using RAND_add(), then
 * its entropy will be used up first.
 */
static size_t prov_drbg_get_entropy(PROV_DRBG *drbg, unsigned char **pout,
                                    int entropy, size_t min_len,
                                    size_t max_len, int prediction_resistance)
{
    size_t ret = 0;
    size_t entropy_available = 0;
    RAND_POOL *pool;
    unsigned int p_str;

    if (drbg->parent != NULL) {
        if (!get_parent_strength(drbg, &p_str))
            return 0;
        if (drbg->strength > p_str) {
            /*
             * We currently don't support the algorithm from NIST SP 800-90C
             * 10.1.2 to use a weaker DRBG as source
             */
            RANDerr(0, PROV_R_PARENT_STRENGTH_TOO_WEAK);
            return 0;
        }
    }

    if (drbg->seed_pool != NULL) {
        pool = drbg->seed_pool;
        pool->entropy_requested = entropy;
    } else {
        pool = rand_pool_new(entropy, 1, min_len, max_len);
        if (pool == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    if (drbg->parent != NULL) {
        size_t bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
        unsigned char *buffer = rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            size_t bytes = 0;

            if (drbg->parent_generate == NULL)
                goto err;
            /*
             * Our lock is already held, but we need to lock our parent before
             * generating bits from it. (Note: taking the lock will be a no-op
             * if locking if drbg->parent->lock == NULL.)
             */
            drbg_lock_parent(drbg);
            /*
             * Get random data from parent.  Include our DRBG address as
             * additional input, in order to provide a distinction between
             * different DRBG child instances.
             *
             * Note: using the sizeof() operator on a pointer triggers
             *       a warning in some static code analyzers, but it's
             *       intentional and correct here.
             */
            if (drbg->parent_generate(drbg->parent, buffer, bytes_needed,
                                      drbg->strength, prediction_resistance,
                                      (unsigned char *)&drbg,
                                      sizeof(drbg)) != 0)
                bytes = bytes_needed;
            drbg_unlock_parent(drbg);
            drbg->parent_reseed_counter = get_parent_reseed_count(drbg);

            rand_pool_add_end(pool, bytes, 8 * bytes);
            entropy_available = rand_pool_entropy_available(pool);
        }
    } else {
        /* Get entropy by polling system entropy sources. */
        entropy_available = prov_pool_acquire_entropy(pool);
    }

    if (entropy_available > 0) {
        ret   = rand_pool_length(pool);
        *pout = rand_pool_detach(pool);
    }

err:
    if (drbg->seed_pool == NULL)
        rand_pool_free(pool);
    return ret;
}

/*
 * Implements the cleanup_entropy() callback (see RAND_DRBG_set_callbacks())
 *
 */
static void prov_drbg_cleanup_entropy(PROV_DRBG *drbg,
                                      unsigned char *out, size_t outlen)
{
    if (drbg->seed_pool == NULL) {
        OPENSSL_secure_clear_free(out, outlen);
    }
}

static size_t get_entropy(PROV_DRBG *drbg, unsigned char **pout, int entropy,
                          size_t min_len, size_t max_len,
                          int prediction_resistance)
{
#ifdef FIPS_MODULE
    if (drbg->parent == NULL)
        return prov_crngt_get_entropy(drbg, pout, entropy, min_len, max_len,
                                      prediction_resistance);
#endif

    return prov_drbg_get_entropy(drbg, pout, entropy, min_len, max_len,
                                 prediction_resistance);
}

static void cleanup_entropy(PROV_DRBG *drbg, unsigned char *out, size_t outlen)
{
#ifdef FIPS_MODULE
    if (drbg->parent == NULL)
        prov_crngt_cleanup_entropy(drbg, out, outlen);
    else
#endif
        prov_drbg_cleanup_entropy(drbg, out, outlen);
}

#ifndef PROV_RAND_GET_RANDOM_NONCE
typedef struct prov_drbg_nonce_global_st {
    CRYPTO_RWLOCK *rand_nonce_lock;
    int rand_nonce_count;
} PROV_DRBG_NONCE_GLOBAL;

/*
 * drbg_ossl_ctx_new() calls drgb_setup() which calls rand_drbg_get_nonce()
 * which needs to get the rand_nonce_lock out of the OPENSSL_CTX...but since
 * drbg_ossl_ctx_new() hasn't finished running yet we need the rand_nonce_lock
 * to be in a different global data object. Otherwise we will go into an
 * infinite recursion loop.
 */
static void *prov_drbg_nonce_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    PROV_DRBG_NONCE_GLOBAL *dngbl = OPENSSL_zalloc(sizeof(*dngbl));

    if (dngbl == NULL)
        return NULL;

    dngbl->rand_nonce_lock = CRYPTO_THREAD_lock_new();
    if (dngbl->rand_nonce_lock == NULL) {
        OPENSSL_free(dngbl);
        return NULL;
    }

    return dngbl;
}

static void prov_drbg_nonce_ossl_ctx_free(void *vdngbl)
{
    PROV_DRBG_NONCE_GLOBAL *dngbl = vdngbl;

    if (dngbl == NULL)
        return;

    CRYPTO_THREAD_lock_free(dngbl->rand_nonce_lock);

    OPENSSL_free(dngbl);
}

static const OPENSSL_CTX_METHOD drbg_nonce_ossl_ctx_method = {
    prov_drbg_nonce_ossl_ctx_new,
    prov_drbg_nonce_ossl_ctx_free,
};

/* Get a nonce from the operating system */
static size_t prov_drbg_get_nonce(PROV_DRBG *drbg,
                                  unsigned char **pout,
                                  int entropy, size_t min_len, size_t max_len)
{
    size_t ret = 0, n;
    RAND_POOL *pool;
    unsigned char *buf = NULL;
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(drbg->provctx);
    PROV_DRBG_NONCE_GLOBAL *dngbl
        = openssl_ctx_get_data(libctx, OPENSSL_CTX_DRBG_NONCE_INDEX,
                               &drbg_nonce_ossl_ctx_method);
    struct {
        void *instance;
        int count;
    } data;
    
    if (dngbl == NULL)
        return 0;

    if (drbg->parent != NULL) {
        if (drbg->parent_nonce != NULL) {
            n = drbg->parent_nonce(drbg->parent, NULL, 0, drbg->min_noncelen,
                                   drbg->max_noncelen);
            if (n > 0 && (buf = OPENSSL_malloc(n)) != NULL) {
                ret = drbg->parent_nonce(drbg->parent, buf, 0,
                                         drbg->min_noncelen,
                                         drbg->max_noncelen);
                if (ret == n) {
                    *pout = buf;
                    return ret;
                }
                OPENSSL_free(buf);
            }
        }
    }

    /* Use the built in nonce source */
    memset(&data, 0, sizeof(data));
    pool = rand_pool_new(0, 0, min_len, max_len);
    if (pool == NULL)
        return 0;

    if (prov_pool_add_nonce_data(pool) == 0)
        goto err;

    data.instance = drbg;
    CRYPTO_atomic_add(&dngbl->rand_nonce_count, 1, &data.count,
                      dngbl->rand_nonce_lock);

    if (rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0) == 0)
        goto err;

    ret   = rand_pool_length(pool);
    *pout = rand_pool_detach(pool);

 err:
    rand_pool_free(pool);

    return ret;
}

static void prov_drbg_clear_nonce(PROV_DRBG *drbg, unsigned char *nonce,
                                  size_t noncelen)
{
    OPENSSL_clear_free(nonce, noncelen);
}
#else
# define prov_drbg_clear_nonce(drbg, nonce, len) \
    OPENSSL_clear_free((nonce), (len))
#endif /* PROV_RAND_GET_RANDOM_NONCE */

/*
 * Instantiate |drbg|, after it has been initialized.  Use |pers| and
 * |perslen| as prediction-resistance input.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_DRBG_instantiate(PROV_DRBG *drbg, unsigned int strength,
                          int prediction_resistance,
                          const unsigned char *pers, size_t perslen)
{
    unsigned char *nonce = NULL, *entropy = NULL;
    size_t noncelen = 0, entropylen = 0;
    size_t min_entropy, min_entropylen, max_entropylen;

    if (strength > drbg->strength) {
        PROVerr(0, PROV_R_INSUFFICIENT_DRBG_STRENGTH);
        goto end;
    }
    min_entropy = drbg->strength;
    min_entropylen = drbg->min_entropylen;
    max_entropylen = drbg->max_entropylen;

    if (pers == NULL) {
        pers = (const unsigned char *)ossl_pers_string;
        perslen = sizeof(ossl_pers_string);
    }
    if (perslen > drbg->max_perslen) {
        PROVerr(0, PROV_R_PERSONALISATION_STRING_TOO_LONG);
        goto end;
    }

    if (drbg->state != EVP_RAND_STATE_UNINITIALISED) {
        if (drbg->state == EVP_RAND_STATE_ERROR)
            PROVerr(0, PROV_R_IN_ERROR_STATE);
        else
            PROVerr(0, PROV_R_ALREADY_INSTANTIATED);
        goto end;
    }

    drbg->state = EVP_RAND_STATE_ERROR;

    if (drbg->min_noncelen > 0) {
        if (drbg->parent_nonce != NULL) {
            noncelen = drbg->parent_nonce(drbg->parent, NULL, drbg->strength,
                                          drbg->min_noncelen,
                                          drbg->max_noncelen);
            if (noncelen == 0) {
                PROVerr(0, PROV_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
            nonce = OPENSSL_malloc(noncelen);
            if (nonce == NULL) {
                PROVerr(0, PROV_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
            if (noncelen != drbg->parent_nonce(drbg->parent, nonce,
                                               drbg->strength,
                                               drbg->min_noncelen,
                                               drbg->max_noncelen)) {
                PROVerr(0, PROV_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
#ifndef PROV_RAND_GET_RANDOM_NONCE
        } else if (drbg->parent != NULL) {
#endif
            /*
             * NIST SP800-90Ar1 section 9.1 says you can combine getting
             * the entropy and nonce in 1 call by increasing the entropy
             * with 50% and increasing the minimum length to accommodate
             * the length of the nonce. We do this in case a nonce is
             * required and there is no parental nonce capability.
             */
            min_entropy += drbg->strength / 2;
            min_entropylen += drbg->min_noncelen;
            max_entropylen += drbg->max_noncelen;
        }
#ifndef PROV_RAND_GET_RANDOM_NONCE
        else { /* parent == NULL */
            noncelen = prov_drbg_get_nonce(drbg, &nonce, drbg->strength / 2,
                                           drbg->min_noncelen, 
                                           drbg->max_noncelen);
            if (noncelen < drbg->min_noncelen
                    || noncelen > drbg->max_noncelen) {
                PROVerr(0, PROV_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
        }
#endif
    }

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if (!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    entropylen = get_entropy(drbg, &entropy, min_entropy,
                             min_entropylen, max_entropylen,
                             prediction_resistance);
    if (entropylen < min_entropylen
            || entropylen > max_entropylen) {
        PROVerr(0, PROV_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!drbg->instantiate(drbg, entropy, entropylen, nonce, noncelen,
                           pers, perslen)) {
        PROVerr(0, PROV_R_ERROR_INSTANTIATING_DRBG);
        goto end;
    }

    drbg->state = EVP_RAND_STATE_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_counter, drbg->reseed_next_counter);

 end:
    if (entropy != NULL)
        cleanup_entropy(drbg, entropy, entropylen);
    prov_drbg_clear_nonce(drbg, nonce, noncelen);
    if (drbg->state == EVP_RAND_STATE_READY)
        return 1;
    return 0;
}

/*
 * Uninstantiate |drbg|. Must be instantiated before it can be used.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_DRBG_uninstantiate(PROV_DRBG *drbg)
{
    drbg->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

/*
 * Reseed |drbg|, mixing in the specified data
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_DRBG_reseed(PROV_DRBG *drbg, int prediction_resistance,
                     const unsigned char *ent, size_t ent_len,
                     const unsigned char *adin, size_t adinlen)
{
    unsigned char *entropy = NULL;
    size_t entropylen = 0;

    if (drbg->state != EVP_RAND_STATE_READY) {
        /* try to recover from previous errors */
        rand_drbg_restart(drbg);

        if (drbg->state == EVP_RAND_STATE_ERROR) {
            PROVerr(0, PROV_R_IN_ERROR_STATE);
            return 0;
        }
        if (drbg->state == EVP_RAND_STATE_UNINITIALISED) {
            PROVerr(0, PROV_R_NOT_INSTANTIATED);
            return 0;
        }
    }

    if (ent != NULL) {
        if (ent_len < drbg->min_entropylen) {
            RANDerr(0, RAND_R_ENTROPY_OUT_OF_RANGE);
            drbg->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
        if (ent_len > drbg->max_entropylen) {
            RANDerr(0, RAND_R_ENTROPY_INPUT_TOO_LONG);
            drbg->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
    }

    if (adin == NULL) {
        adinlen = 0;
    } else if (adinlen > drbg->max_adinlen) {
        PROVerr(0, PROV_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    drbg->state = EVP_RAND_STATE_ERROR;

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if (!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    if (ent != NULL) {
#ifdef FIP_MODULE
        /*
         * NIST SP-800-90A mandates that entropy *shall not* be provided
         * by the consuming application. Instead the data is added as additional
         * input.
         *
         * (NIST SP-800-90Ar1, Sections 9.1 and 9.2)
         */
        if (!drbg->reseed(drbg, NULL, 0, ent, ent_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_RESEED);
            return 0;
        }
#else
        if (!drbg->reseed(drbg, ent, ent_len, adin, adinlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_RESEED);
            return 0;
        }
        /* There isn't much point adding the same additional input twice */
        adin = NULL;
        adinlen = 0;
#endif
    }

    /* Reseed using our sources in addition */
    entropylen = get_entropy(drbg, &entropy, drbg->strength,
                             drbg->min_entropylen, drbg->max_entropylen,
                             prediction_resistance);
    if (entropylen < drbg->min_entropylen
            || entropylen > drbg->max_entropylen) {
        PROVerr(0, PROV_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!drbg->reseed(drbg, entropy, entropylen, adin, adinlen))
        goto end;

    drbg->state = EVP_RAND_STATE_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_counter, drbg->reseed_next_counter);
    if (drbg->parent != NULL)
        drbg->parent_reseed_counter = get_parent_reseed_count(drbg);

 end:
    cleanup_entropy(drbg, entropy, entropylen);
    if (drbg->state == EVP_RAND_STATE_READY)
        return 1;
    return 0;
}

/*
 * Generate |outlen| bytes into the buffer at |out|.  Reseed if we need
 * to or if |prediction_resistance| is set.  Additional input can be
 * sent in |adin| and |adinlen|.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 *
 */
int PROV_DRBG_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen,
                       unsigned int strength, int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    int fork_id;
    int reseed_required = 0;

    if (drbg->state != EVP_RAND_STATE_READY) {
        /* try to recover from previous errors */
        rand_drbg_restart(drbg);

        if (drbg->state == EVP_RAND_STATE_ERROR) {
            PROVerr(0, PROV_R_IN_ERROR_STATE);
            return 0;
        }
        if (drbg->state == EVP_RAND_STATE_UNINITIALISED) {
            PROVerr(0, PROV_R_NOT_INSTANTIATED);
            return 0;
        }
    }
    if (strength > drbg->strength) {
        PROVerr(0, PROV_R_INSUFFICIENT_DRBG_STRENGTH);
        return 0;
    }

    if (outlen > drbg->max_request) {
        PROVerr(0, PROV_R_REQUEST_TOO_LARGE_FOR_DRBG);
        return 0;
    }
    if (adinlen > drbg->max_adinlen) {
        PROVerr(0, PROV_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    fork_id = openssl_get_fork_id();

    if (drbg->fork_id != fork_id) {
        drbg->fork_id = fork_id;
        reseed_required = 1;
    }

    if (drbg->reseed_interval > 0) {
        if (drbg->reseed_gen_counter >= drbg->reseed_interval)
            reseed_required = 1;
    }
    if (drbg->reseed_time_interval > 0) {
        time_t now = time(NULL);
        if (now < drbg->reseed_time
            || now - drbg->reseed_time >= drbg->reseed_time_interval)
            reseed_required = 1;
    }
    if (drbg->parent != NULL
            && get_parent_reseed_count(drbg) != drbg->parent_reseed_counter)
        reseed_required = 1;

    if (reseed_required || prediction_resistance) {
        if (!PROV_DRBG_reseed(drbg, prediction_resistance, NULL, 0,
                              adin, adinlen)) {
            PROVerr(0, PROV_R_RESEED_ERROR);
            return 0;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!drbg->generate(drbg, out, outlen, adin, adinlen)) {
        drbg->state = EVP_RAND_STATE_ERROR;
        PROVerr(0, PROV_R_GENERATE_ERROR);
        return 0;
    }

    drbg->reseed_gen_counter++;

    return 1;
}

/*
 * Restart |drbg|, using the specified entropy or additional input
 *
 * Tries its best to get the drbg instantiated by all means,
 * regardless of its current state.
 *
 * Optionally, a |buffer| of |len| random bytes can be passed,
 * which is assumed to contain at least |entropy| bits of entropy.
 *
 * If |entropy| > 0, the buffer content is used as entropy input.
 *
 * If |entropy| == 0, the buffer content is used as additional input
 *
 * Returns 1 on success, 0 on failure.
 *
 * This function is used internally only.
 */
static int rand_drbg_restart(PROV_DRBG *drbg)
{
    if (drbg->seed_pool != NULL) {
        drbg->state = EVP_RAND_STATE_ERROR;
        rand_pool_free(drbg->seed_pool);
        drbg->seed_pool = NULL;
        RANDerr(0, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* repair error state */
    if (drbg->state == EVP_RAND_STATE_ERROR)
        drbg->uninstantiate(drbg);

    /* repair uninitialized state */
    if (drbg->state == EVP_RAND_STATE_UNINITIALISED)
        /* reinstantiate drbg */
        PROV_DRBG_instantiate(drbg, drbg->strength, 0, NULL, 0);

    rand_pool_free(drbg->seed_pool);
    drbg->seed_pool = NULL;
    return drbg->state == EVP_RAND_STATE_READY;
}

/* Provider support from here down */
static const OSSL_DISPATCH *find_call(const OSSL_DISPATCH *dispatch,
                                      int function)
{
    if (dispatch != NULL)
        while (dispatch->function_id != 0) {
            if (dispatch->function_id == function)
                return dispatch;
            dispatch++;
        }
    return NULL;
}

int drbg_enable_locking(void *vctx)
{
    PROV_DRBG *drbg = vctx;

    if (drbg != NULL && drbg->lock == NULL) {
        if (drbg->parent_enable_locking != NULL)
            if (!drbg->parent_enable_locking(drbg->parent)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_LOCKING_NOT_ENABLED);
                return 0;
            }
        drbg->lock = CRYPTO_THREAD_lock_new();
        if (drbg->lock == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_CREATE_LOCK);
            return 0;
        }
    }
    return 1;
}

/*
 * Allocate memory and initialize a new DRBG. The DRBG is allocated on
 * the secure heap if |secure| is nonzero and the secure heap is enabled.
 * The |parent|, if not NULL, will be used as random source for reseeding.
 * This also requires the parent's provider context and the parent's lock.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
PROV_DRBG *prov_rand_drbg_new
    (void *provctx, void *parent, const OSSL_DISPATCH *p_dispatch,
     int (*dnew)(PROV_DRBG *ctx),
     int (*instantiate)(PROV_DRBG *drbg,
                        const unsigned char *entropy, size_t entropylen,
                        const unsigned char *nonce, size_t noncelen,
                        const unsigned char *pers, size_t perslen),
     int (*uninstantiate)(PROV_DRBG *ctx),
     int (*reseed)(PROV_DRBG *drbg, const unsigned char *ent, size_t ent_len,
                   const unsigned char *adin, size_t adin_len),
     int (*generate)(PROV_DRBG *, unsigned char *out, size_t outlen,
                     const unsigned char *adin, size_t adin_len))
{
    PROV_DRBG *drbg = OPENSSL_zalloc(sizeof(*drbg));
    unsigned int p_str;
    const OSSL_DISPATCH *pfunc;

    if (drbg == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    drbg->provctx = provctx;
    drbg->instantiate = instantiate;
    drbg->uninstantiate = uninstantiate;
    drbg->reseed = reseed;
    drbg->generate = generate;
    drbg->fork_id = openssl_get_fork_id();

    /* Extract parent's functions */
    drbg->parent = parent;
    if ((pfunc = find_call(p_dispatch, OSSL_FUNC_RAND_ENABLE_LOCKING)) != NULL)
        drbg->parent_enable_locking = OSSL_FUNC_rand_enable_locking(pfunc);
    if ((pfunc = find_call(p_dispatch, OSSL_FUNC_RAND_LOCK)) != NULL)
        drbg->parent_lock = OSSL_FUNC_rand_lock(pfunc);
    if ((pfunc = find_call(p_dispatch, OSSL_FUNC_RAND_UNLOCK)) != NULL)
        drbg->parent_unlock = OSSL_FUNC_rand_unlock(pfunc);
    if ((pfunc = find_call(p_dispatch, OSSL_FUNC_RAND_GET_CTX_PARAMS)) != NULL)
        drbg->parent_get_ctx_params = OSSL_FUNC_rand_get_ctx_params(pfunc);
    if ((pfunc = find_call(p_dispatch, OSSL_FUNC_RAND_GENERATE)) != NULL)
        drbg->parent_generate = OSSL_FUNC_rand_generate(pfunc);
    if ((pfunc = find_call(p_dispatch, OSSL_FUNC_RAND_NONCE)) != NULL)
        drbg->parent_nonce = OSSL_FUNC_rand_nonce(pfunc);

    /* Set some default maximums up */
    drbg->max_entropylen = DRBG_MAX_LENGTH;
    drbg->max_noncelen = DRBG_MAX_LENGTH;
    drbg->max_perslen = DRBG_MAX_LENGTH;
    drbg->max_adinlen = DRBG_MAX_LENGTH;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_counter = 1;
    drbg->reseed_interval = RESEED_INTERVAL;
    drbg->reseed_time_interval = TIME_INTERVAL;

    if (!dnew(drbg))
        goto err;

    if (parent != NULL) {
        if (!get_parent_strength(drbg, &p_str))
            goto err;
        if (drbg->strength > p_str) {
            /*
             * We currently don't support the algorithm from NIST SP 800-90C
             * 10.1.2 to use a weaker DRBG as source
             */
            ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_STRENGTH_TOO_WEAK);
            goto err;
        }
    }
    return drbg;

 err:
    prov_rand_drbg_free(drbg);
    return NULL;
}

void prov_rand_drbg_free(PROV_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    rand_pool_free(drbg->adin_pool);
    CRYPTO_THREAD_lock_free(drbg->lock);
    OPENSSL_free(drbg);
}

int drbg_get_ctx_params(PROV_DRBG *drbg, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->state))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->strength))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_request))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MIN_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->min_entropylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_entropylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MIN_NONCELEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->min_noncelen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_NONCELEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_noncelen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_PERSLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_perslen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_ADINLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_adinlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_set_uint(p, drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_TIME);
    if (p != NULL && !OSSL_PARAM_set_time_t(p, drbg->reseed_time))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_set_time_t(p, drbg->reseed_time_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_CTR);
    if (p != NULL
            && !OSSL_PARAM_set_uint(p, tsan_load(&drbg->reseed_counter)))
        return 0;
    return 1;
}

int drbg_set_ctx_params(PROV_DRBG *drbg, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_get_time_t(p, &drbg->reseed_time_interval))
        return 0;
    return 1;
}
