/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/thread_once.h"
#include <openssl/dsa.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/x509.h>
#include <openssl/store.h>

/*-
 *  OSSL_STORE_INFO stuff
 *  ---------------------
 */

struct ossl_store_info_st {
    int type;
    union {
        struct {
            char *name;
            char *desc;
        } name;                  /* when type == OSSL_STORE_INFO_NAME */

        EVP_PKEY *params;        /* when type == OSSL_STORE_INFO_PARAMS */
        EVP_PKEY *pkey;          /* when type == OSSL_STORE_INFO_PKEY */
        X509 *x509;              /* when type == OSSL_STORE_INFO_CERT */
        X509_CRL *crl;           /* when type == OSSL_STORE_INFO_CRL */
        void *data;              /* used internally */
    } _;
};

DEFINE_STACK_OF(OSSL_STORE_INFO)

/*-
 *  OSSL_STORE_LOADER stuff
 *  -----------------------
 */

int ossl_store_register_loader_int(OSSL_STORE_LOADER *loader);
OSSL_STORE_LOADER *ossl_store_unregister_loader_int(const char *scheme);

/* loader stuff */
struct ossl_store_loader_st {
    const char *scheme;
    OSSL_STORE_open_fn open;
    OSSL_STORE_ctrl_fn ctrl;
    OSSL_STORE_load_fn load;
    OSSL_STORE_eof_fn eof;
    OSSL_STORE_error_fn error;
    OSSL_STORE_close_fn close;
};
DEFINE_LHASH_OF(OSSL_STORE_LOADER);

const OSSL_STORE_LOADER *ossl_store_get0_loader_int(const char *scheme);
void ossl_store_destroy_loaders_int(void);

/*-
 *  OSSL_STORE init stuff
 *  ---------------------
 */

int ossl_store_init_once(void);
