/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <internal/dso.h>
#include <internal/nelem.h>
#include "e_pkcs11_err.c"

#define CK_PTR *

#ifdef _WIN32
# pragma pack(push, cryptoki, 1)
# define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType __declspec(dllimport) (* name)
#else
# define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

#ifndef NULL_PTR
# define NULL_PTR 0
#endif

#include "pkcs11.h"

#define PKCS11_CMD_MODULE_PATH            ENGINE_CMD_BASE
#define PKCS11_CMD_PIN                    (ENGINE_CMD_BASE + 1)

static const ENGINE_CMD_DEFN pkcs11_cmd_defns[] = {
    {PKCS11_CMD_MODULE_PATH,
     "MODULE_PATH",
     "Module path",
     ENGINE_CMD_FLAG_STRING},
    {PKCS11_CMD_PIN,
     "PIN",
     "PIN",
     ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

struct X509_sig_st {
    X509_ALGOR *algor;
    ASN1_OCTET_STRING *digest;
};

typedef struct PKCS11_CTX_st {
    CK_BYTE *id;
    CK_BYTE *label;
    CK_BYTE *pin;
    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    char *module_path;
} PKCS11_CTX;

static CK_RV pkcs11_initialize(const char *library_path);
static void pkcs11_finalize(void);
static int pkcs11_start_session(PKCS11_CTX *ctx);
static void pkcs11_end_session(CK_SESSION_HANDLE session);
static int pkcs11_login(PKCS11_CTX *ctx, CK_USER_TYPE userType);
static int pkcs11_logout(CK_SESSION_HANDLE session);
static CK_RV pkcs11_load_functions(const char *library_path);
static int pkcs11_parse_uri(const char *path, char *token, char **value);
static int pkcs11_parse(PKCS11_CTX *ctx, const char *path);
static EVP_PKEY *pkcs11_load_pkey(PKCS11_CTX *ctx);
static char pkcs11_hex_int(char nib1, char nib2);
static int pkcs11_rsa_sign(int alg, const unsigned char *md,
                           unsigned int md_len, unsigned char *sigret,
                           unsigned int *siglen, const RSA *rsa);
static int pkcs11_rsa_priv_enc(int flen, const unsigned char *from,
                               unsigned char *to, RSA *rsa, int padding);
static PKCS11_CTX *pkcs11_ctx_new(void);
static void pkcs11_ctx_free(PKCS11_CTX *ctx);
static int pkcs11_get_slot(PKCS11_CTX *ctx);
static int pkcs11_find_private_key(PKCS11_CTX *ctx);
static CK_FUNCTION_LIST *pkcs11_funcs;
static void PKCS11_trace(char *format, ...);
static int pkcs11_encode_pkcs1(unsigned char **out, int *out_len, int type,
                               const unsigned char *m, unsigned int m_len);

/* Engine stuff */
static int bind_pkcs11(ENGINE *e);
static int pkcs11_init(ENGINE *e);
static int pkcs11_destroy(ENGINE *e);
static int pkcs11_finish(ENGINE *e);
static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                                UI_METHOD * ui_method,
                                                void *callback_data);
static const char *engine_id = "pkcs11";
static const char *engine_name = "A minimal PKCS#11 engine only for sign";
static int pkcs11_idx = -1;
static RSA_METHOD *pkcs11_rsa = NULL;
typedef CK_RV pkcs11_pFunc(CK_FUNCTION_LIST **pkcs11_funcs);

static int pkcs11_init(ENGINE *e)
{
    PKCS11_CTX *ctx;

    if (pkcs11_idx < 0) {
        pkcs11_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (pkcs11_idx < 0)
            goto memerr;
    }
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    if (ctx == NULL) {
        ctx = pkcs11_ctx_new();

        if (ctx == NULL)
            goto memerr;

        ENGINE_set_ex_data(e, pkcs11_idx, ctx);
    }

    return 1;

 memerr:
    PKCS11err(PKCS11_F_PKCS11_INIT, ERR_R_MALLOC_FAILURE);
    return 0;
}

static int pkcs11_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int ret = 1;
    char *tmpstr;
    PKCS11_CTX *ctx;

    if (pkcs11_idx == -1 && !pkcs11_init(e)) {
        PKCS11err(PKCS11_F_PKCS11_CTRL, PKCS11_R_ENGINE_NOT_INITIALIZED);
        return 0;
    }
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);

    switch (cmd) {
    case PKCS11_CMD_MODULE_PATH:
        tmpstr = OPENSSL_strdup(p);
        if (tmpstr != NULL) {
            ctx->module_path = tmpstr;
            PKCS11_trace("Setting module path to %s\n", ctx->module_path);
        } else {
            PKCS11err(PKCS11_F_PKCS11_CTRL, ERR_R_MALLOC_FAILURE);
            ret = 0;
        }
        break;

    case PKCS11_CMD_PIN:
        tmpstr = OPENSSL_strdup(p);
        if (tmpstr != NULL) {
            ctx->pin = (CK_BYTE *) tmpstr;
            PKCS11_trace("Setting pin\n");
        } else {
            PKCS11err(PKCS11_F_PKCS11_CTRL, ERR_R_MALLOC_FAILURE);
            ret = 0;
        }
        break;
    }

    return ret;
}

static int pkcs11_encode_pkcs1(unsigned char **out, int *out_len, int type,
                               const unsigned char *m, unsigned int m_len)
{
    X509_SIG sig;
    X509_ALGOR algor;
    ASN1_TYPE parameter;
    ASN1_OCTET_STRING digest;
    uint8_t *der = NULL;
    int len;

    sig.algor = &algor;
    sig.algor->algorithm = OBJ_nid2obj(type);
    if (sig.algor->algorithm == NULL) {
        PKCS11err(PKCS11_F_PKCS11_ENCODE_PKCS1,
                  PKCS11_R_UNKNOWN_ALGORITHM_TYPE);
        return 0;
    }
    if (OBJ_length(sig.algor->algorithm) == 0) {
        PKCS11err(PKCS11_F_PKCS11_ENCODE_PKCS1,
               PKCS11_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
        return 0;
    }
    parameter.type = V_ASN1_NULL;
    parameter.value.ptr = NULL;
    sig.algor->parameter = &parameter;

    sig.digest = &digest;
    sig.digest->data = (unsigned char *)m;
    sig.digest->length = m_len;

    len = i2d_X509_SIG(&sig, &der);
    if (len < 0)
        return 0;

    *out = der;
    *out_len = len;
    return 1;
}

static int pkcs11_rsa_sign(int alg, const unsigned char *md,
                           unsigned int md_len, unsigned char *sigret,
                           unsigned int *siglen, const RSA *rsa)
{
    CK_RV rv;
    PKCS11_CTX *ctx;
    CK_ULONG num;
    CK_MECHANISM sign_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_TRUE;
    CK_ATTRIBUTE keyAttribute[1];
    unsigned char *tmps = NULL;
    int encoded_len = 0;
    const unsigned char *encoded = NULL;

    num = RSA_size(rsa);
    if (!pkcs11_encode_pkcs1(&tmps, &encoded_len, alg, md, md_len))
        goto err;
    encoded = tmps;
    if (encoded_len > num - RSA_PKCS1_PADDING_SIZE) {
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, PKCS11_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        goto err;
    }

    ctx = ENGINE_get_ex_data(RSA_get0_engine(rsa), pkcs11_idx);
    sign_mechanism.mechanism = CKM_RSA_PKCS;
    rv = pkcs11_funcs->C_SignInit(ctx->session, &sign_mechanism, ctx->key);

    if (rv != CKR_OK) {
        PKCS11_trace("C_SignInit failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, PKCS11_R_SIGN_INIT_FAILED);
        goto err;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);
    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, ctx->key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if (bAwaysAuthentificate && !pkcs11_login(ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    /* Sign */
    rv = pkcs11_funcs->C_Sign(ctx->session, (CK_BYTE *) encoded, encoded_len,
                              sigret, &num);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Sign failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, PKCS11_R_SIGN_FAILED);
        goto err;
    }
    *siglen = num;

    pkcs11_logout(ctx->session);
    pkcs11_end_session(ctx->session);
    pkcs11_finalize();
    return 1;

 err:
    return 0;
}

static int pkcs11_rsa_priv_enc(int flen, const unsigned char *from,
                               unsigned char *to, RSA *rsa, int padding)
{
    CK_RV rv;
    PKCS11_CTX *ctx;
    CK_ULONG num;
    CK_MECHANISM enc_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_TRUE;
    CK_ATTRIBUTE keyAttribute[1];
    int useSign = 0;

    num = RSA_size(rsa);
    ctx = ENGINE_get_ex_data(RSA_get0_engine(rsa), pkcs11_idx);
    enc_mechanism.mechanism = CKM_RSA_PKCS;
    rv = pkcs11_funcs->C_EncryptInit(ctx->session, &enc_mechanism, ctx->key);

    if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
        PKCS11_trace("C_EncryptInit failed try SignInit, error: %#08X\n", rv);
        rv = pkcs11_funcs->C_SignInit(ctx->session, &enc_mechanism, ctx->key);

        if (rv != CKR_OK) {
            PKCS11_trace("C_SignInit failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_SIGN_INIT_FAILED);
            goto err;
        }
        useSign = 1;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);
    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, ctx->key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if (bAwaysAuthentificate && !pkcs11_login(ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    if (!useSign) {
        /* Encrypt */
        rv = pkcs11_funcs->C_Encrypt(ctx->session, (CK_BYTE *) from,
                                     flen, to, &num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Encrypt failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_ENCRYPT_FAILED);
            goto err;
        }
    } else {
        /* Sign */
        rv = pkcs11_funcs->C_Sign(ctx->session, (CK_BYTE *) from,
                                  flen, to, &num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Sign failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_SIGN_FAILED);
            goto err;
        }
    }

    pkcs11_logout(ctx->session);
    pkcs11_end_session(ctx->session);
    pkcs11_finalize();
    return 1;

 err:
    return 0;
}

/**
 * Load the PKCS#11 functions into global function list.
 * @param library_path
 * @return
 */
static CK_RV pkcs11_load_functions(const char *library_path)
{
    CK_RV rv;
    static DSO *pkcs11_dso = NULL;
    pkcs11_pFunc *pFunc;

    pkcs11_dso = DSO_load(NULL, library_path, NULL, 0);

    if (pkcs11_dso == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_FUNCTIONS,
                  PKCS11_R_LIBRARY_PATH_NOT_FOUND);
        return CKR_GENERAL_ERROR;
    }

    pFunc = (pkcs11_pFunc *)DSO_bind_func(pkcs11_dso, "C_GetFunctionList");

    if (pFunc == NULL) {
        PKCS11_trace("C_GetFunctionList() not found in module %s\n",
                     library_path);
        PKCS11err(PKCS11_F_PKCS11_LOAD_FUNCTIONS,
                  PKCS11_R_GETFUNCTIONLIST_NOT_FOUND);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rv = pFunc(&pkcs11_funcs);

    return rv;
}

/**
 * Initialize the PKCS#11 library.
 * This loads the function list and initializes PKCS#11.
 * @param library_path
 * @return
 */
static CK_RV pkcs11_initialize(const char *library_path)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;

    if (library_path == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_load_functions(library_path);
    if (rv != CKR_OK) {
        PKCS11_trace("Getting PKCS11 function list failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE,
                  PKCS11_R_GETTING_FUNCTION_LIST_FAILED);
        return rv;
    }

    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = pkcs11_funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Initialize failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE, PKCS11_R_INITIALIZE_FAILED);
        return rv;
    }

    return CKR_OK;
}

static void pkcs11_finalize(void)
{
    pkcs11_funcs->C_Finalize(NULL);
}

static int pkcs11_get_slot(PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_ULONG slotCount;
    CK_SLOT_ID slotId;
    CK_SLOT_ID_PTR slotList;
    unsigned int i;

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, NULL, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        goto err;
    }

    if (slotCount == 0) {
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_SLOT_NOT_FOUND);
        goto err;
    }

    slotList = OPENSSL_malloc(sizeof(CK_SLOT_ID) * slotCount);

    if (slotList == NULL) {
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, slotList, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        OPENSSL_free(slotList);
        goto err;
    }

    slotId = slotList[0]; /* Default value if slot not set*/
    for (i = 1; i < slotCount; i++) {
        if (ctx->slotid == slotList[i]) slotId = slotList[i];
    }

    ctx->slotid = slotId;
    OPENSSL_free(slotList);
    return 1;

 err:
    return 0;
}

static int pkcs11_start_session(PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;

    rv = pkcs11_funcs->C_OpenSession(ctx->slotid, CKF_SERIAL_SESSION, NULL,
                                     NULL, &session);
    if (rv != CKR_OK) {
        PKCS11_trace("C_OpenSession failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_START_SESSION,
                  PKCS11_R_OPEN_SESSION_ERROR);
        return 0;
    }
    ctx->session = session;
    return 1;
}

static int pkcs11_login(PKCS11_CTX *ctx, CK_USER_TYPE userType)
{
    /* Binary pins not supported */
    CK_RV rv;

    if (ctx->pin != NULL) {
        rv = pkcs11_funcs->C_Login(ctx->session, userType, ctx->pin,
                                   strlen((char *)ctx->pin));
        if (rv != CKR_OK) {
            PKCS11_trace("C_Login failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_LOGIN, PKCS11_R_LOGIN_FAILED);
            goto err;
        }
    return 1;
    }
 err:
    return 0;
}

static int pkcs11_logout(CK_SESSION_HANDLE session)
{
    CK_RV rv;

    rv = pkcs11_funcs->C_Logout(session);
    if (rv != CKR_USER_NOT_LOGGED_IN && rv != CKR_OK) {
        PKCS11_trace("C_Logout failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOGOUT, PKCS11_R_LOGOUT_FAILED);
        goto err;
    }
    return 1;

 err:
    return 0;
}

static void pkcs11_end_session(CK_SESSION_HANDLE session)
{
    pkcs11_funcs->C_CloseSession(session);
}

static int pkcs11_find_private_key(PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_OBJECT_HANDLE objhandle;
    unsigned long count;
    CK_ATTRIBUTE tmpl[3];

    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &key_class;
    tmpl[0].ulValueLen = sizeof(key_class);
    tmpl[1].type = CKA_KEY_TYPE;
    tmpl[1].pValue = &key_type;
    tmpl[1].ulValueLen = sizeof(key_type);

    if (ctx->id != NULL) {
        tmpl[2].type = CKA_ID;
        tmpl[2].pValue = ctx->id;
        tmpl[2].ulValueLen = strlen((char *)ctx->id);
    } else {
        tmpl[2].type = CKA_LABEL;
        tmpl[2].pValue = ctx->label;
        tmpl[2].ulValueLen = strlen((char *)ctx->label);
    }

    rv = pkcs11_funcs->C_FindObjectsInit(ctx->session, tmpl, OSSL_NELEM(tmpl));

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_INIT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjects(ctx->session, &objhandle, 1, &count);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjectsFinal(ctx->session);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsFinal failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_FINAL_FAILED);
        goto err;
    }

    ctx->key = objhandle;
    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, ctx->key,
                                           tmpl, OSSL_NELEM(tmpl));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }
    return 1;

 err:
    return 0;
}

static char pkcs11_hex_int(char nib1, char nib2)
{
    int ret = (nib1-(nib1 <= 57 ? 48 : (nib1 < 97 ? 55 : 87)))*16;
    ret += (nib2-(nib2 <= 57 ? 48 : (nib2 < 97 ? 55 : 87)));
    return ret;
}

static int pkcs11_parse_uri(const char *path, char *token, char **value)
{
    char *tmp, *end, *hex2bin;
    size_t vlen, i, j = 0, tmplen;

    if ((tmp = strstr(path, token)) == NULL)
        return 0;
    tmp += strlen(token);
    tmplen = strlen(tmp);
    *value = OPENSSL_malloc(tmplen + 1);

    if (*value == NULL) {
        PKCS11err(PKCS11_F_PKCS11_PARSE_URI, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    end = strpbrk(tmp, ";");

    BIO_snprintf(*value, end == NULL ? tmplen + 1 :
                 (size_t) (end - tmp + 1), "%s", tmp);
    hex2bin = OPENSSL_malloc(strlen(*value) + 1);

    if (hex2bin == NULL) {
        PKCS11err(PKCS11_F_PKCS11_PARSE_URI, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    vlen = strlen(*value);
    for (i = 0; i < vlen; i++) {
        if (*(*value+i) == '%' && i < (vlen-2)) {
            *(hex2bin+j) = pkcs11_hex_int(*(*value+i+1), *(*value+i+2));
            i += 2;
        } else {
            *(hex2bin+j) = *(*value+i);
        }
        j++;
    }
    *(hex2bin+j) = '\0';
    free(*value);
    *value = hex2bin;
    return 1;

 err:
    free(*value);
    *value = NULL;
    return 0;
}

static int pkcs11_get_console_pin(char **pin)
{
#ifndef OPENSSL_NO_UI_CONSOLE
    int i;
    const int buflen = 512;
    char *strbuf = OPENSSL_malloc(buflen);

    if (strbuf == NULL) {
        PKCS11err(PKCS11_F_PKCS11_GET_CONSOLE_PIN, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    for (;;) {
        char prompt[200];
        BIO_snprintf(prompt, sizeof(prompt), "Enter PIN: ");
        strbuf[0] = '\0';
        i = EVP_read_pw_string((char *)strbuf, 512, prompt, 1);
        if (i == 0) {
            if (strbuf[0] == '\0') {
                goto err;
            }
            *pin = strbuf;
            return 1;
        }
        if (i < 0) {
            PKCS11_trace("bad password read\n");
            goto err;
        }
    }

 err:
    OPENSSL_free(strbuf);
#endif

    return 0;
}

static int pkcs11_parse(PKCS11_CTX *ctx, const char *path)
{
    char *id, *module_path = NULL;
    char *pin = NULL, *label = NULL, *slotid = NULL;

    ctx->slotid = 0;
    if (strncmp(path, "pkcs11:", 7) == 0) {
        path += 7;
	if (ctx->module_path == NULL &&
            !pkcs11_parse_uri(path,"module-path=", &module_path))
            goto err;
        if (ctx->module_path == NULL) ctx->module_path = module_path;
	if (!pkcs11_parse_uri(path,"id=", &id) &&
            !pkcs11_parse_uri(path,"object=", &label)) {
            PKCS11_trace("ID and OBJECT are null\n");
            goto err;
        }
	if (!pkcs11_parse_uri(path,"slot-id=", &slotid)) {
           slotid = NULL;
        }
        pkcs11_parse_uri(path,"pin-value=", &pin);
        if (pin != NULL)
            ctx->pin = (CK_BYTE *) pin;
    } else if (path == NULL) {
       PKCS11_trace("inkey is null\n");
       goto err;
    } else {
        if (ctx->module_path == NULL) {
            PKCS11_trace("Module path is null\n");
            goto err;
        }
        id = OPENSSL_strdup(path);

        if (id == NULL) {
            PKCS11err(PKCS11_F_PKCS11_PARSE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        slotid = NULL;

    }
    if (label != NULL)
        ctx->label = (CK_BYTE *) label;
    else
        ctx->id = (CK_BYTE *) id;
    if (slotid != NULL)
        ctx->slotid = (CK_SLOT_ID) atoi(slotid);

    if (ctx->pin == NULL) {
        if (!pkcs11_get_console_pin(&pin))
            goto err;
        ctx->pin = (CK_BYTE *) pin;
        if (ctx->pin == NULL) {
            PKCS11_trace("PIN is invalid\n");
            goto err;
        }
    }

    return 1;

 err:
    return 0;
}

static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                                UI_METHOD * ui_method,
                                                void *callback_data)
{
    CK_RV rv;
    PKCS11_CTX *ctx;

    ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    if (!pkcs11_parse(ctx, path))
        goto err;

    rv = pkcs11_initialize(ctx->module_path);

    if (rv != CKR_OK)
        goto err;
    if (!pkcs11_get_slot(ctx))
        goto err;
    if (!pkcs11_start_session(ctx))
        goto err;
    if (!pkcs11_login(ctx, CKU_USER))
        goto err;
    if (!pkcs11_find_private_key(ctx))
        goto err;

    return pkcs11_load_pkey(ctx);

 err:
    PKCS11_trace("pkcs11_engine_load_private_key failed\n");
    return 0;
}

static EVP_PKEY *pkcs11_load_pkey(PKCS11_CTX *ctx)
{
    EVP_PKEY *k = NULL;
    CK_RV rv;
    CK_ATTRIBUTE rsa_attributes[2];
    RSA *rsa = NULL;

    rsa_attributes[0].type = CKA_MODULUS;
    rsa_attributes[0].pValue = NULL;
    rsa_attributes[0].ulValueLen = 0;
    rsa_attributes[1].type = CKA_PUBLIC_EXPONENT;
    rsa_attributes[1].pValue = NULL;
    rsa_attributes[1].ulValueLen = 0;
    rsa = RSA_new();

    if (rsa == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, ctx->key,
                                           rsa_attributes,
                                           OSSL_NELEM(rsa_attributes));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }
    if  (rsa_attributes[0].ulValueLen == 0 ||
         rsa_attributes[1].ulValueLen == 0)
        goto err;

    rsa_attributes[0].pValue = OPENSSL_malloc(rsa_attributes[0].ulValueLen);
    rsa_attributes[1].pValue = OPENSSL_malloc(rsa_attributes[1].ulValueLen);

    if (rsa_attributes[0].pValue == NULL ||
        rsa_attributes[1].pValue == NULL) {
        OPENSSL_free(rsa_attributes[0].pValue);
        OPENSSL_free(rsa_attributes[1].pValue);
        goto err;
    }
    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, ctx->key,
                                           rsa_attributes,
                                           OSSL_NELEM(rsa_attributes));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }
    RSA_set0_key(rsa,
                 BN_bin2bn(rsa_attributes[0].pValue,
                           rsa_attributes[0].ulValueLen, NULL),
                 BN_bin2bn(rsa_attributes[1].pValue,
                           rsa_attributes[1].ulValueLen, NULL),
                 NULL);

    if((k = EVP_PKEY_new()) != NULL) {
        EVP_PKEY_set1_RSA(k, rsa);
    }

    OPENSSL_free(rsa_attributes[0].pValue);
    OPENSSL_free(rsa_attributes[1].pValue);
    return k;

 err:
    OPENSSL_free(rsa_attributes[0].pValue);
    OPENSSL_free(rsa_attributes[1].pValue);
    return NULL;
}

static int bind_pkcs11(ENGINE *e)
{

    if ((pkcs11_rsa = RSA_meth_new("PKCS#11 RSA method", 0)) == NULL
         || !RSA_meth_set_sign(pkcs11_rsa, pkcs11_rsa_sign)
         || !RSA_meth_set_priv_enc(pkcs11_rsa, pkcs11_rsa_priv_enc)) {
        PKCS11err(PKCS11_F_BIND_PKCS11, PKCS11_R_RSA_INIT_FAILED);
        return 0;
    }

    if (!ENGINE_set_id(e, engine_id)
        || !ENGINE_set_name(e, engine_name)
        || !ENGINE_set_RSA(e, pkcs11_rsa)
        || !ENGINE_set_load_privkey_function(e, pkcs11_engine_load_private_key)
        || !ENGINE_set_destroy_function(e, pkcs11_destroy)
        || !ENGINE_set_init_function(e, pkcs11_init)
        || !ENGINE_set_finish_function(e, pkcs11_finish)
        || !ENGINE_set_cmd_defns(e, pkcs11_cmd_defns)
        || !ENGINE_set_ctrl_function(e, pkcs11_ctrl))
        goto end;

    ERR_load_PKCS11_strings();
    return 1;

 end:
    PKCS11_trace("ENGINE_set failed\n");
    return 0;
}

static void PKCS11_trace(char *format, ...)
{
#ifdef DEBUG
# ifndef OPENSSL_NO_STDIO
    BIO *out;
    va_list args;

    out = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (out == NULL) {
        PKCS11err(PKCS11_F_PKCS11_TRACE, PKCS11_R_FILE_OPEN_ERROR);
        return;
    }

    va_start(args, format);
    BIO_vprintf(out, format, args);
    va_end(args);
    BIO_free(out);
# endif
#endif
}

static PKCS11_CTX *pkcs11_ctx_new(void)
{
    PKCS11_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        PKCS11err(PKCS11_F_PKCS11_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return ctx;
}

static int pkcs11_finish(ENGINE *e)
{
    PKCS11_CTX *ctx;
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    pkcs11_ctx_free(ctx);
    ENGINE_set_ex_data(e, pkcs11_idx, NULL);
    return 1;
}

static int pkcs11_destroy(ENGINE *e)
{
    RSA_meth_free(pkcs11_rsa);
    pkcs11_rsa = NULL;
    PKCS11_trace("Calling pkcs11_destroy with engine: %p\n", e);
    ERR_unload_PKCS11_strings();
    return 1;
}

static void pkcs11_ctx_free(PKCS11_CTX *ctx)
{
    PKCS11_trace("Calling pkcs11_ctx_free with %p\n", ctx);
    OPENSSL_free(ctx);
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_id) != 0))
        return 0;
    if (!bind_pkcs11(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
IMPLEMENT_DYNAMIC_CHECK_FN()
#else
static ENGINE *engine_pkcs11(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_pkcs11(ret)) {
        ENGINE_free(ret);
        return NULL;
    }

void engine_load_pkcs11_int(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_pkcs11();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#endif

