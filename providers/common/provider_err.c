/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "prov/providercommonerr.h"

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA PROV_str_reasons[] = {
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_AES_KEY_SETUP_FAILED),
    "aes key setup failed"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_BAD_DECRYPT), "bad decrypt"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_BAD_ENCODING), "bad encoding"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_BAD_LENGTH), "bad length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_BOTH_MODE_AND_MODE_INT),
    "both mode and mode int"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_CIPHER_OPERATION_FAILED),
    "cipher operation failed"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_FAILED_TO_GENERATE_KEY),
    "failed to generate key"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_FAILED_TO_GET_PARAMETER),
    "failed to get parameter"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_FAILED_TO_SET_PARAMETER),
    "failed to set parameter"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INAVLID_UKM_LENGTH),
    "inavlid ukm length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_AAD), "invalid aad"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_CONSTANT_LENGTH),
    "invalid constant length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_CUSTOM_LENGTH),
    "invalid custom length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_DATA), "invalid data"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_DIGEST), "invalid digest"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_ITERATION_COUNT),
    "invalid iteration count"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_IVLEN), "invalid ivlen"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_IV_LENGTH), "invalid iv length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_KEYLEN), "invalid keylen"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_KEY_LEN), "invalid key len"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_KEY_LENGTH),
    "invalid key length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_MAC), "invalid mac"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_MODE), "invalid mode"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_MODE_INT), "invalid mode int"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_SALT_LENGTH),
    "invalid salt length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_SEED_LENGTH),
    "invalid seed length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_TAG), "invalid tag"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_INVALID_TAGLEN), "invalid taglen"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_CEK_ALG), "missing cek alg"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_CIPHER), "missing cipher"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_CONSTANT), "missing constant"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_KEY), "missing key"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_MAC), "missing mac"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_MESSAGE_DIGEST),
    "missing message digest"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_PASS), "missing pass"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_SALT), "missing salt"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_SECRET), "missing secret"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_SEED), "missing seed"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_SESSION_ID),
    "missing session id"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_TYPE), "missing type"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISSING_XCGHASH), "missing xcghash"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_NOT_SUPPORTED), "not supported"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_NOT_XOF_OR_INVALID_LENGTH),
    "not xof or invalid length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_NO_KEY_SET), "no key set"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_OUTPUT_BUFFER_TOO_SMALL),
    "output buffer too small"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_TAG_NOTSET), "tag notset"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_TAG_NOT_NEEDED), "tag not needed"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_UNABLE_TO_LOAD_SHA1),
    "unable to load sha1"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_UNABLE_TO_LOAD_SHA256),
    "unable to load sha256"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_UNSUPPORTED_CEK_ALG),
    "unsupported cek alg"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_UNSUPPORTED_KEY_SIZE),
    "unsupported key size"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_UNSUPPORTED_MAC_TYPE),
    "unsupported mac type"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_UNSUPPORTED_NUMBER_OF_ROUNDS),
    "unsupported number of rounds"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_VALUE_ERROR), "value error"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_WRONG_FINAL_BLOCK_LENGTH),
    "wrong final block length"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_WRONG_OUTPUT_BUFFER_SIZE),
    "wrong output buffer size"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_XTS_DATA_UNIT_IS_TOO_LARGE),
    "xts data unit is too large"},
    {ERR_PACK(ERR_LIB_PROV, 0, PROV_R_XTS_DUPLICATED_KEYS),
    "xts duplicated keys"},
    {0, NULL}
};

#endif

int ERR_load_PROV_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(PROV_str_reasons[0].error) == NULL)
        ERR_load_strings_const(PROV_str_reasons);
#endif
    return 1;
}
