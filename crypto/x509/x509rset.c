/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "internal/x509_int.h"

int X509_REQ_set_version(X509_REQ *x, long version)
{
    if (x == NULL)
        return 0;
    x->req_info.enc.modified = 1;
    return ASN1_INTEGER_set(x->req_info.version, version);
}

int X509_REQ_set_subject_name(X509_REQ *x, X509_NAME *name)
{
    if (x == NULL)
        return 0;
    x->req_info.enc.modified = 1;
    return X509_NAME_set(&x->req_info.subject, name);
}

int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey)
{
    if (x == NULL)
        return 0;
    x->req_info.enc.modified = 1;
    return X509_PUBKEY_set(&x->req_info.pubkey, pkey);
}

int X509_REQ_up_ref(X509_REQ *x)
{
    int i;

    if (CRYPTO_UP_REF(&x->references, &i, x->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("X509_REQ", x);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}
