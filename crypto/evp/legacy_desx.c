/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"

/* EVP_desx_cbc() */
IMPLEMENT_EVP_CIPHER_CONST2(desx, NID_desx_cbc, 192, 8, 8, cbc, CBC, 0)
