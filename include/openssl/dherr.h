/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_DHERR_H
# define OPENSSL_DHERR_H

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_DH

#  ifdef  __cplusplus
extern "C"
#  endif
int ERR_load_DH_strings(void);

/*
 * DH function codes.
 */
# if !OPENSSL_API_3
#   define DH_F_COMPUTE_KEY                                 0
#   define DH_F_DHPARAMS_PRINT_FP                           0
#   define DH_F_DH_BUF2KEY                                  0
#   define DH_F_DH_BUILTIN_GENPARAMS                        0
#   define DH_F_DH_CHECK_EX                                 0
#   define DH_F_DH_CHECK_PARAMS_EX                          0
#   define DH_F_DH_CHECK_PUB_KEY_EX                         0
#   define DH_F_DH_CMS_DECRYPT                              0
#   define DH_F_DH_CMS_SET_PEERKEY                          0
#   define DH_F_DH_CMS_SET_SHARED_INFO                      0
#   define DH_F_DH_KEY2BUF                                  0
#   define DH_F_DH_METH_DUP                                 0
#   define DH_F_DH_METH_NEW                                 0
#   define DH_F_DH_METH_SET1_NAME                           0
#   define DH_F_DH_NEW_BY_NID                               0
#   define DH_F_DH_NEW_METHOD                               0
#   define DH_F_DH_PARAM_DECODE                             0
#   define DH_F_DH_PKEY_PUBLIC_CHECK                        0
#   define DH_F_DH_PRIV_DECODE                              0
#   define DH_F_DH_PRIV_ENCODE                              0
#   define DH_F_DH_PUB_DECODE                               0
#   define DH_F_DH_PUB_ENCODE                               0
#   define DH_F_DO_DH_PRINT                                 0
#   define DH_F_GENERATE_KEY                                0
#   define DH_F_PKEY_DH_CTRL_STR                            0
#   define DH_F_PKEY_DH_DERIVE                              0
#   define DH_F_PKEY_DH_INIT                                0
#   define DH_F_PKEY_DH_KEYGEN                              0
# endif

/*
 * DH reason codes.
 */
#  define DH_R_BAD_GENERATOR                               101
#  define DH_R_BN_DECODE_ERROR                             109
#  define DH_R_BN_ERROR                                    106
#  define DH_R_CHECK_INVALID_J_VALUE                       115
#  define DH_R_CHECK_INVALID_Q_VALUE                       116
#  define DH_R_CHECK_PUBKEY_INVALID                        122
#  define DH_R_CHECK_PUBKEY_TOO_LARGE                      123
#  define DH_R_CHECK_PUBKEY_TOO_SMALL                      124
#  define DH_R_CHECK_P_NOT_PRIME                           117
#  define DH_R_CHECK_P_NOT_SAFE_PRIME                      118
#  define DH_R_CHECK_Q_NOT_PRIME                           119
#  define DH_R_DECODE_ERROR                                104
#  define DH_R_INVALID_PARAMETER_NAME                      110
#  define DH_R_INVALID_PARAMETER_NID                       114
#  define DH_R_INVALID_PUBKEY                              102
#  define DH_R_KDF_PARAMETER_ERROR                         112
#  define DH_R_KEYS_NOT_SET                                108
#  define DH_R_MISSING_PUBKEY                              125
#  define DH_R_MODULUS_TOO_LARGE                           103
#  define DH_R_MODULUS_TOO_SMALL                           126
#  define DH_R_NOT_SUITABLE_GENERATOR                      120
#  define DH_R_NO_PARAMETERS_SET                           107
#  define DH_R_NO_PRIVATE_VALUE                            100
#  define DH_R_PARAMETER_ENCODING_ERROR                    105
#  define DH_R_PEER_KEY_ERROR                              111
#  define DH_R_SHARED_INFO_ERROR                           113
#  define DH_R_UNABLE_TO_CHECK_GENERATOR                   121

# endif
#endif
