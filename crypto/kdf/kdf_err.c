/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/kdferr.h>

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA KDF_str_functs[] = {
    {ERR_PACK(ERR_LIB_KDF, KDF_F_PKEY_TLS1_PRF_CTRL_STR, 0),
     "pkey_tls1_prf_ctrl_str"},
    {ERR_PACK(ERR_LIB_KDF, KDF_F_PKEY_TLS1_PRF_DERIVE, 0),
     "pkey_tls1_prf_derive"},
    {0, NULL}
};

static const ERR_STRING_DATA KDF_str_reasons[] = {
    {ERR_PACK(ERR_LIB_KDF, 0, KDF_R_INVALID_DIGEST), "invalid digest"},
    {ERR_PACK(ERR_LIB_KDF, 0, KDF_R_MISSING_PARAMETER), "missing parameter"},
    {ERR_PACK(ERR_LIB_KDF, 0, KDF_R_VALUE_MISSING), "value missing"},
    {0, NULL}
};

#endif

int ERR_load_KDF_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(KDF_str_functs[0].error) == NULL) {
        ERR_load_strings_const(KDF_str_functs);
        ERR_load_strings_const(KDF_str_reasons);
    }
#endif
    return 1;
}
