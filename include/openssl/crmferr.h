/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CRMFERR_H
# define OPENSSL_CRMFERR_H
# pragma once

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>
# include <openssl/cryptoerr_legacy.h>


# ifndef OPENSSL_NO_CRMF


/*
 * CRMF reason codes.
 */
#  define CRMF_R_BAD_PBM_ITERATIONCOUNT                    100
#  define CRMF_R_CMS_NOT_SUPPORTED                         122
#  define CRMF_R_CRMFERROR                                 102
#  define CRMF_R_ERROR                                     103
#  define CRMF_R_ERROR_DECODING_CERTIFICATE                104
#  define CRMF_R_ERROR_DECODING_ENCRYPTEDKEY               123
#  define CRMF_R_ERROR_DECRYPTING_CERTIFICATE              105
#  define CRMF_R_ERROR_DECRYPTING_ENCRYPTEDKEY             124
#  define CRMF_R_ERROR_DECRYPTING_ENCRYPTEDVALUE           125
#  define CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY            106
#  define CRMF_R_ERROR_SETTING_PURPOSE                     126
#  define CRMF_R_ERROR_VERIFYING_ENCRYPTEDKEY              127
#  define CRMF_R_FAILURE_OBTAINING_RANDOM                  107
#  define CRMF_R_ITERATIONCOUNT_BELOW_100                  108
#  define CRMF_R_MALFORMED_IV                              101
#  define CRMF_R_NULL_ARGUMENT                             109
#  define CRMF_R_POPOSKINPUT_NOT_SUPPORTED                 113
#  define CRMF_R_POPO_INCONSISTENT_PUBLIC_KEY              117
#  define CRMF_R_POPO_MISSING                              121
#  define CRMF_R_POPO_MISSING_PUBLIC_KEY                   118
#  define CRMF_R_POPO_MISSING_SUBJECT                      119
#  define CRMF_R_POPO_RAVERIFIED_NOT_ACCEPTED              120
#  define CRMF_R_SETTING_MAC_ALGOR_FAILURE                 110
#  define CRMF_R_SETTING_OWF_ALGOR_FAILURE                 111
#  define CRMF_R_UNSUPPORTED_ALGORITHM                     112
#  define CRMF_R_UNSUPPORTED_CIPHER                        114
#  define CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO      115
#  define CRMF_R_UNSUPPORTED_POPO_METHOD                   116

# endif
#endif
