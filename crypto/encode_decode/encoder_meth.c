/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/encoder.h>
#include <openssl/ui.h>
#include "internal/core.h"
#include "internal/namemap.h"
#include "internal/property.h"
#include "internal/provider.h"
#include "crypto/encoder.h"
#include "encoder_local.h"

/*
 * Encoder can have multiple names, separated with colons in a name string
 */
#define NAME_SEPARATOR ':'

/* Simple method structure constructor and destructor */
static OSSL_ENCODER_METHOD *ossl_encoder_method_new(void)
{
    OSSL_ENCODER_METHOD *encoder_meth = NULL;

    if ((encoder_meth = OPENSSL_zalloc(sizeof(*encoder_meth))) == NULL
        || (encoder_meth->base.lock = CRYPTO_THREAD_lock_new()) == NULL) {
        OSSL_ENCODER_METHOD_free(encoder_meth);
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    encoder_meth->base.refcnt = 1;

    return encoder_meth;
}

int OSSL_ENCODER_METHOD_up_ref(OSSL_ENCODER_METHOD *encoder_meth)
{
    int ref = 0;

    CRYPTO_UP_REF(&encoder_meth->base.refcnt, &ref, encoder_meth->base.lock);
    return 1;
}

void OSSL_ENCODER_METHOD_free(OSSL_ENCODER_METHOD *encoder_meth)
{
    int ref = 0;

    if (encoder_meth == NULL)
        return;

    CRYPTO_DOWN_REF(&encoder_meth->base.refcnt, &ref, encoder_meth->base.lock);
    if (ref > 0)
        return;
    ossl_provider_free(encoder_meth->base.prov);
    CRYPTO_THREAD_lock_free(encoder_meth->base.lock);
    OPENSSL_free(encoder_meth);
}

/* Permanent encoder method store, constructor and destructor */
static void encoder_store_free(void *vstore)
{
    ossl_method_store_free(vstore);
}

static void *encoder_store_new(OSSL_LIB_CTX *ctx)
{
    return ossl_method_store_new(ctx);
}


static const OSSL_LIB_CTX_METHOD encoder_store_method = {
    encoder_store_new,
    encoder_store_free,
};

/* Data to be passed through ossl_method_construct() */
struct encoder_data_st {
    OSSL_LIB_CTX *libctx;
    OSSL_METHOD_CONSTRUCT_METHOD *mcm;
    int id;                      /* For get_encoder_from_store() */
    const char *names;           /* For get_encoder_from_store() */
    const char *propquery;       /* For get_encoder_from_store() */
};

/*
 * Generic routines to fetch / create ENCODER methods with
 * ossl_method_construct()
 */

/* Temporary encoder method store, constructor and destructor */
static void *alloc_tmp_encoder_store(OSSL_LIB_CTX *ctx)
{
    return ossl_method_store_new(ctx);
}

static void dealloc_tmp_encoder_store(void *store)
{
    if (store != NULL)
        ossl_method_store_free(store);
}

/* Get the permanent encoder store */
static OSSL_METHOD_STORE *get_encoder_store(OSSL_LIB_CTX *libctx)
{
    return ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_ENCODER_STORE_INDEX,
                                 &encoder_store_method);
}

/* Get encoder methods from a store, or put one in */
static void *get_encoder_from_store(OSSL_LIB_CTX *libctx, void *store,
                                    void *data)
{
    struct encoder_data_st *methdata = data;
    void *method = NULL;
    int id;

    if ((id = methdata->id) == 0) {
        OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

        id = ossl_namemap_name2num(namemap, methdata->names);
    }

    if (store == NULL
        && (store = get_encoder_store(libctx)) == NULL)
        return NULL;

    if (!ossl_method_store_fetch(store, id, methdata->propquery, &method))
        return NULL;
    return method;
}

static int put_encoder_in_store(OSSL_LIB_CTX *libctx, void *store,
                                void *method, const OSSL_PROVIDER *prov,
                                int operation_id, const char *names,
                                const char *propdef, void *unused)
{
    OSSL_NAMEMAP *namemap;
    int id;

    if ((namemap = ossl_namemap_stored(libctx)) == NULL
        || (id = ossl_namemap_name2num(namemap, names)) == 0)
        return 0;

    if (store == NULL && (store = get_encoder_store(libctx)) == NULL)
        return 0;

    return ossl_method_store_add(store, prov, id, propdef, method,
                                 (int (*)(void *))OSSL_ENCODER_METHOD_up_ref,
                                 (void (*)(void *))OSSL_ENCODER_METHOD_free);
}

/* Create and populate a encoder method */
static void *encoder_from_dispatch(int id, const OSSL_ALGORITHM *algodef,
                                   OSSL_PROVIDER *prov)
{
    OSSL_ENCODER_METHOD *encoder_meth = NULL;
    const OSSL_DISPATCH *fns = algodef->implementation;

    if ((encoder_meth = ossl_encoder_method_new()) == NULL)
        return NULL;
    encoder_meth->base.id = id;
    encoder_meth->base.propdef = algodef->property_definition;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_ENCODER_NEWCTX:
            if (encoder_meth->newctx == NULL)
                encoder_meth->newctx =
                    OSSL_FUNC_encoder_newctx(fns);
            break;
        case OSSL_FUNC_ENCODER_FREECTX:
            if (encoder_meth->freectx == NULL)
                encoder_meth->freectx =
                    OSSL_FUNC_encoder_freectx(fns);
            break;
        case OSSL_FUNC_ENCODER_GET_PARAMS:
            if (encoder_meth->get_params == NULL)
                encoder_meth->get_params =
                    OSSL_FUNC_encoder_get_params(fns);
            break;
        case OSSL_FUNC_ENCODER_GETTABLE_PARAMS:
            if (encoder_meth->gettable_params == NULL)
                encoder_meth->gettable_params =
                    OSSL_FUNC_encoder_gettable_params(fns);
            break;
        case OSSL_FUNC_ENCODER_SET_CTX_PARAMS:
            if (encoder_meth->set_ctx_params == NULL)
                encoder_meth->set_ctx_params =
                    OSSL_FUNC_encoder_set_ctx_params(fns);
            break;
        case OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS:
            if (encoder_meth->settable_ctx_params == NULL)
                encoder_meth->settable_ctx_params =
                    OSSL_FUNC_encoder_settable_ctx_params(fns);
            break;
        case OSSL_FUNC_ENCODER_DOES_SELECTION:
            if (encoder_meth->does_selection == NULL)
                encoder_meth->does_selection =
                    OSSL_FUNC_encoder_does_selection(fns);
            break;
        case OSSL_FUNC_ENCODER_ENCODE:
            if (encoder_meth->encode == NULL)
                encoder_meth->encode = OSSL_FUNC_encoder_encode(fns);
            break;
        case OSSL_FUNC_ENCODER_IMPORT_OBJECT:
            if (encoder_meth->import_object == NULL)
                encoder_meth->import_object =
                    OSSL_FUNC_encoder_import_object(fns);
            break;
        case OSSL_FUNC_ENCODER_FREE_OBJECT:
            if (encoder_meth->free_object == NULL)
                encoder_meth->free_object =
                    OSSL_FUNC_encoder_free_object(fns);
            break;
        }
    }
    /*
     * Try to check that the method is sensible.
     * If you have a constructor, you must have a destructor and vice versa.
     * You must have the encoding driver functions.
     */
    if (!((encoder_meth->newctx == NULL && encoder_meth->freectx == NULL)
          || (encoder_meth->newctx != NULL && encoder_meth->freectx != NULL)
          || (encoder_meth->import_object != NULL && encoder_meth->free_object != NULL)
          || (encoder_meth->import_object == NULL && encoder_meth->free_object == NULL))
        || encoder_meth->encode == NULL
        || encoder_meth->gettable_params == NULL
        || encoder_meth->get_params == NULL) {
        OSSL_ENCODER_METHOD_free(encoder_meth);
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }

    if (prov != NULL && !ossl_provider_up_ref(prov)) {
        OSSL_ENCODER_METHOD_free(encoder_meth);
        return NULL;
    }

    encoder_meth->base.prov = prov;
    return encoder_meth;
}


/*
 * The core fetching functionality passes the names of the implementation.
 * This function is responsible to getting an identity number for them,
 * then call encoder_from_dispatch() with that identity number.
 */
static void *construct_encoder(const OSSL_ALGORITHM *algodef,
                               OSSL_PROVIDER *prov, void *unused)
{
    /*
     * This function is only called if get_encoder_from_store() returned
     * NULL, so it's safe to say that of all the spots to create a new
     * namemap entry, this is it.  Should the name already exist there, we
     * know that ossl_namemap_add() will return its corresponding number.
     */
    OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);
    const char *names = algodef->algorithm_names;
    int id = ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR);
    void *method = NULL;

    if (id != 0)
        method = encoder_from_dispatch(id, algodef, prov);

    return method;
}

/* Intermediary function to avoid ugly casts, used below */
static void destruct_encoder(void *method, void *data)
{
    OSSL_ENCODER_METHOD_free(method);
}

static int up_ref_encoder(void *method)
{
    return OSSL_ENCODER_METHOD_up_ref(method);
}

static void free_encoder(void *method)
{
    OSSL_ENCODER_METHOD_free(method);
}

/* Fetching support.  Can fetch by numeric identity or by name */
static OSSL_ENCODER_METHOD *
inner_ossl_encoder_method_fetch(OSSL_LIB_CTX *libctx, int id, const char *name,
                                const char *properties)
{
    OSSL_METHOD_STORE *store = get_encoder_store(libctx);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);
    void *method = NULL;

    if (store == NULL || namemap == NULL)
        return NULL;

    /*
     * If we have been passed neither a name_id or a name, we have an
     * internal programming error.
     */
    if (!ossl_assert(id != 0 || name != NULL))
        return NULL;

    if (id == 0)
        id = ossl_namemap_name2num(namemap, name);

    if (id == 0
        || !ossl_method_store_cache_get(store, id, properties, &method)) {
        OSSL_METHOD_CONSTRUCT_METHOD mcm = {
            alloc_tmp_encoder_store,
            dealloc_tmp_encoder_store,
            get_encoder_from_store,
            put_encoder_in_store,
            construct_encoder,
            destruct_encoder
        };
        struct encoder_data_st mcmdata;

        mcmdata.libctx = libctx;
        mcmdata.mcm = &mcm;
        mcmdata.id = id;
        mcmdata.names = name;
        mcmdata.propquery = properties;
        if ((method = ossl_method_construct(libctx, OSSL_OP_ENCODER,
                                            0 /* !force_cache */,
                                            &mcm, &mcmdata)) != NULL) {
            /*
             * If construction did create a method for us, we know that
             * there is a correct name_id and meth_id, since those have
             * already been calculated in get_encoder_from_store() and
             * put_encoder_in_store() above.
             */
            if (id == 0)
                id = ossl_namemap_name2num(namemap, name);
            ossl_method_store_cache_set(store, id, properties, method,
                                        up_ref_encoder, free_encoder);
        }
    }

    return method;
}

OSSL_ENCODER_METHOD *OSSL_ENCODER_METHOD_fetch(OSSL_LIB_CTX *libctx,
                                               const char *name,
                                               const char *properties)
{
    return inner_ossl_encoder_method_fetch(libctx, 0, name, properties);
}

OSSL_ENCODER_METHOD *
ossl_encoder_method_fetch_by_number(OSSL_LIB_CTX *libctx, int id,
                                    const char *properties)
{
    return inner_ossl_encoder_method_fetch(libctx, id, NULL, properties);
}

/*
 * Library of basic method functions
 */

const OSSL_PROVIDER *
OSSL_ENCODER_METHOD_provider(const OSSL_ENCODER_METHOD *encoder_meth)
{
    if (!ossl_assert(encoder_meth != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return encoder_meth->base.prov;
}

const char *
OSSL_ENCODER_METHOD_properties(const OSSL_ENCODER_METHOD *encoder_meth)
{
    if (!ossl_assert(encoder_meth != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return encoder_meth->base.propdef;
}

int OSSL_ENCODER_METHOD_number(const OSSL_ENCODER_METHOD *encoder_meth)
{
    if (!ossl_assert(encoder_meth != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return encoder_meth->base.id;
}

int OSSL_ENCODER_METHOD_is_a(const OSSL_ENCODER_METHOD *encoder_meth,
                             const char *name)
{
    if (encoder_meth->base.prov != NULL) {
        OSSL_LIB_CTX *libctx = ossl_provider_libctx(encoder_meth->base.prov);
        OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

        return ossl_namemap_name2num(namemap, name) == encoder_meth->base.id;
    }
    return 0;
}

struct encoder_do_all_data_st {
    void (*user_fn)(void *method, void *arg);
    void *user_arg;
};

static void encoder_do_one(OSSL_PROVIDER *provider,
                           const OSSL_ALGORITHM *algodef,
                           int no_store, void *vdata)
{
    struct encoder_do_all_data_st *data = vdata;
    OSSL_LIB_CTX *libctx = ossl_provider_libctx(provider);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);
    const char *names = algodef->algorithm_names;
    int id = ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR);
    void *method = NULL;

    if (id != 0)
        method =
            encoder_from_dispatch(id, algodef, provider);

    if (method != NULL) {
        data->user_fn(method, data->user_arg);
        OSSL_ENCODER_METHOD_free(method);
    }
}

void
OSSL_ENCODER_METHOD_do_all_provided(OSSL_LIB_CTX *libctx,
                                    void (*fn)(OSSL_ENCODER_METHOD *encoder_meth,
                                               void *arg),
                                    void *arg)
{
    struct encoder_do_all_data_st data;

    data.user_fn = (void (*)(void *, void *))fn;
    data.user_arg = arg;

    /*
     * No pre- or post-condition for this call, as this only creates methods
     * temporarly and then promptly destroys them.
     */
    ossl_algorithm_do_all(libctx, OSSL_OP_ENCODER, NULL, NULL,
                          encoder_do_one, NULL, &data);
}

void OSSL_ENCODER_METHOD_names_do_all(const OSSL_ENCODER_METHOD *encoder_meth,
                                      void (*fn)(const char *name, void *data),
                                      void *data)
{
    if (encoder_meth == NULL)
        return;

    if (encoder_meth->base.prov != NULL) {
        OSSL_LIB_CTX *libctx = ossl_provider_libctx(encoder_meth->base.prov);
        OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

        ossl_namemap_doall_names(namemap, encoder_meth->base.id, fn, data);
    }
}

const OSSL_PARAM *
OSSL_ENCODER_METHOD_gettable_params(OSSL_ENCODER_METHOD *encoder_meth)
{
    if (encoder_meth != NULL && encoder_meth->gettable_params != NULL) {
        void *provctx =
            ossl_provider_ctx(OSSL_ENCODER_METHOD_provider(encoder_meth));

        return encoder_meth->gettable_params(provctx);
    }
    return NULL;
}

int OSSL_ENCODER_METHOD_get_params(OSSL_ENCODER_METHOD *encoder_meth,
                                   OSSL_PARAM params[])
{
    if (encoder_meth != NULL && encoder_meth->get_params != NULL)
        return encoder_meth->get_params(params);
    return 0;
}

const OSSL_PARAM *
OSSL_ENCODER_METHOD_settable_ctx_params(OSSL_ENCODER_METHOD *encoder_meth)
{
    if (encoder_meth != NULL && encoder_meth->settable_ctx_params != NULL) {
        void *provctx =
            ossl_provider_ctx(OSSL_ENCODER_METHOD_provider(encoder_meth));

        return encoder_meth->settable_ctx_params(provctx);
    }
    return NULL;
}

/*
 * Encoder context support
 */

OSSL_ENCODER *OSSL_ENCODER_new(void)
{
    OSSL_ENCODER *encoder;

    if ((encoder = OPENSSL_zalloc(sizeof(*encoder))) == NULL)
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);

    return encoder;
}

int OSSL_ENCODER_set_params(OSSL_ENCODER *encoder, const OSSL_PARAM params[])
{
    int ok = 1;
    size_t i;
    size_t l;

    if (!ossl_assert(encoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (encoder->encoder_insts == NULL)
        return 1;

    l = OSSL_ENCODER_get_num_methods(encoder);
    for (i = 0; i < l; i++) {
        OSSL_ENCODER_INSTANCE *encoder_inst =
            sk_OSSL_ENCODER_INSTANCE_value(encoder->encoder_insts, i);
        OSSL_ENCODER_METHOD *encoder_meth =
            OSSL_ENCODER_INSTANCE_get_method(encoder_inst);
        void *encoderctx =
            OSSL_ENCODER_INSTANCE_get_method_ctx(encoder_inst);

        if (encoderctx == NULL || encoder_meth->set_ctx_params == NULL)
            continue;
        if (!encoder_meth->set_ctx_params(encoderctx, params))
            ok = 0;
    }
    return ok;
}

void OSSL_ENCODER_free(OSSL_ENCODER *encoder)
{
    if (encoder != NULL) {
        sk_OSSL_ENCODER_INSTANCE_pop_free(encoder->encoder_insts,
                                          ossl_encoder_instance_free);
        OPENSSL_free(encoder->construct_data);
        ossl_pw_clear_passphrase_data(&encoder->pwdata);
        OPENSSL_free(encoder);
    }
}
