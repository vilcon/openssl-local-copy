/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_lcidm.h"
#include "internal/quic_types.h"
#include "internal/quic_vlint.h"
#include "internal/common.h"
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/*
 * QUIC Local Connection ID Manager
 * ================================
 */

typedef struct quic_lcidm_conn_st QUIC_LCIDM_CONN;

enum {
    LCID_TYPE_ODCID,        /* This LCID is the ODCID from the peer */
    LCID_TYPE_INITIAL,      /* This is our Initial SCID */
    LCID_TYPE_NCID          /* This LCID was issued via a NCID frame */
};

typedef struct quic_lcid_st {
    QUIC_CONN_ID                cid;
    uint64_t                    seq_num;

    /* Back-pointer to the owning QUIC_LCIDM_CONN structure. */
    QUIC_LCIDM_CONN             *conn;

    /* LCID_TYPE_* */
    unsigned int                type                : 2;
} QUIC_LCID;

DEFINE_LHASH_OF_EX(QUIC_LCID);
DEFINE_LHASH_OF_EX(QUIC_LCIDM_CONN);

struct quic_lcidm_conn_st {
    size_t              num_active_lcid;
    LHASH_OF(QUIC_LCID) *lcids;
    void                *opaque;
    QUIC_LCID           *odcid_lcid;
    uint64_t            next_seq_num;

    /* Have we enrolled an ODCID? */
    unsigned int        done_odcid          : 1;
};

struct quic_lcidm_st {
    OSSL_LIB_CTX                *libctx;
    LHASH_OF(QUIC_LCID)         *lcids; /* (QUIC_CONN_ID) -> (QUIC_LCID *)  */
    LHASH_OF(QUIC_LCIDM_CONN)   *conns; /* (void *opaque) -> (QUIC_LCIDM_CONN *) */
    size_t                      lcid_len; /* Length in bytes for all LCIDs */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    QUIC_CONN_ID                next_lcid;
#endif
};

static unsigned long bin_hash(const unsigned char *buf, size_t buf_len)
{
    unsigned long hash = 0;
    size_t i;

    for (i = 0; i < buf_len; ++i)
        hash ^= ((unsigned long)buf[i]) << (8 * (i % sizeof(unsigned long)));

    return hash;
}

static unsigned long lcid_hash(const QUIC_LCID *lcid)
{
    return bin_hash(lcid->cid.id, lcid->cid.id_len);
}

static int lcid_comp(const QUIC_LCID *a, const QUIC_LCID *b)
{
    return !ossl_quic_conn_id_eq(&a->cid, &b->cid);
}

static unsigned long lcidm_conn_hash(const QUIC_LCIDM_CONN *conn)
{
    return (unsigned long)(uintptr_t)conn->opaque;
}

static int lcidm_conn_comp(const QUIC_LCIDM_CONN *a, const QUIC_LCIDM_CONN *b)
{
    return a->opaque != b->opaque;
}

QUIC_LCIDM *ossl_quic_lcidm_new(OSSL_LIB_CTX *libctx, size_t lcid_len)
{
    QUIC_LCIDM *lcidm = NULL;

    if (lcid_len > QUIC_MAX_CONN_ID_LEN)
        goto err;

    if ((lcidm = OPENSSL_zalloc(sizeof(*lcidm))) == NULL)
        goto err;

    if ((lcidm->lcids = lh_QUIC_LCID_new(lcid_hash, lcid_comp)) == NULL)
        goto err;

    if ((lcidm->conns = lh_QUIC_LCIDM_CONN_new(lcidm_conn_hash,
                                               lcidm_conn_comp)) == NULL)
        goto err;

    lcidm->libctx   = libctx;
    lcidm->lcid_len = lcid_len;
    return lcidm;

err:
    if (lcidm != NULL) {
        lh_QUIC_LCID_free(lcidm->lcids);
        lh_QUIC_LCIDM_CONN_free(lcidm->conns);
        OPENSSL_free(lcidm);
    }
    return NULL;
}

static void lcidm_delete_conn(QUIC_LCIDM *lcidm, QUIC_LCIDM_CONN *conn);

static void lcidm_delete_conn_(QUIC_LCIDM_CONN *conn, void *arg)
{
    lcidm_delete_conn((QUIC_LCIDM *)arg, conn);
}

void ossl_quic_lcidm_free(QUIC_LCIDM *lcidm)
{
    if (lcidm == NULL)
        return;

    lh_QUIC_LCIDM_CONN_doall_arg(lcidm->conns, lcidm_delete_conn_, lcidm);

    lh_QUIC_LCID_free(lcidm->lcids);
    lh_QUIC_LCIDM_CONN_free(lcidm->conns);
    OPENSSL_free(lcidm);
}

static QUIC_LCID *lcidm_get_lcid(const QUIC_LCIDM *lcidm, const QUIC_CONN_ID *lcid)
{
    QUIC_LCID key;

    key.cid = *lcid;

    if (key.cid.id_len > QUIC_MAX_CONN_ID_LEN)
        return NULL;

    return lh_QUIC_LCID_retrieve(lcidm->lcids, &key);
}

static QUIC_LCIDM_CONN *lcidm_get_conn(const QUIC_LCIDM *lcidm, void *opaque)
{
    QUIC_LCIDM_CONN key;

    key.opaque = opaque;

    return lh_QUIC_LCIDM_CONN_retrieve(lcidm->conns, &key);
}

static QUIC_LCIDM_CONN *lcidm_upsert_conn(const QUIC_LCIDM *lcidm, void *opaque)
{
    QUIC_LCIDM_CONN *conn = lcidm_get_conn(lcidm, opaque);

    if (conn != NULL)
        return conn;

    if ((conn = OPENSSL_zalloc(sizeof(*conn))) == NULL)
        return NULL;

    if ((conn->lcids = lh_QUIC_LCID_new(lcid_hash, lcid_comp)) == NULL) {
        OPENSSL_free(conn);
        return NULL;
    }

    conn->opaque = opaque;
    lh_QUIC_LCIDM_CONN_insert(lcidm->conns, conn);
    return conn;
}

static void lcidm_delete_conn_lcid(QUIC_LCIDM *lcidm, QUIC_LCID *lcid)
{
    lh_QUIC_LCID_delete(lcidm->lcids, lcid);
    lh_QUIC_LCID_delete(lcid->conn->lcids, lcid);
    --lcid->conn->num_active_lcid;
    OPENSSL_free(lcid);
}

/* doall_arg wrapper */
static void lcidm_delete_conn_lcid_(QUIC_LCID *lcid, void *arg)
{
    lcidm_delete_conn_lcid((QUIC_LCIDM *)arg, lcid);
}

static void lcidm_delete_conn(QUIC_LCIDM *lcidm, QUIC_LCIDM_CONN *conn)
{
    lh_QUIC_LCID_doall_arg(conn->lcids, lcidm_delete_conn_lcid_, lcidm);
    lh_QUIC_LCIDM_CONN_delete(lcidm->conns, conn);
    lh_QUIC_LCID_free(conn->lcids);
    OPENSSL_free(conn);
}

static QUIC_LCID *lcidm_conn_new_lcid(QUIC_LCIDM *lcidm, QUIC_LCIDM_CONN *conn,
                                      const QUIC_CONN_ID *lcid)
{
    QUIC_LCID *lcid_obj;

    if (lcid->id_len > QUIC_MAX_CONN_ID_LEN)
        return NULL;

    if ((lcid_obj = OPENSSL_zalloc(sizeof(*lcid_obj))) == NULL)
        return NULL;

    lcid_obj->cid = *lcid;
    lcid_obj->conn = conn;
    lh_QUIC_LCID_insert(conn->lcids, lcid_obj);
    lh_QUIC_LCID_insert(lcidm->lcids, lcid_obj);
    ++conn->num_active_lcid;
    return lcid_obj;
}

size_t ossl_quic_lcidm_get_lcid_len(const QUIC_LCIDM *lcidm)
{
    return lcidm->lcid_len;
}

size_t ossl_quic_lcidm_get_num_active_lcid(const QUIC_LCIDM *lcidm,
                                           void *opaque)
{
    QUIC_LCIDM_CONN *conn;

    conn = lcidm_get_conn(lcidm, opaque);
    if (conn == NULL)
        return 0;

    return conn->num_active_lcid;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

static int gen_rand_conn_id(OSSL_LIB_CTX *libctx, size_t len, QUIC_CONN_ID *cid)
{
    if (len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    cid->id_len = (unsigned char)len;

    if (RAND_bytes_ex(libctx, cid->id, len, len * 8) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_RAND_LIB);
        cid->id_len = 0;
        return 0;
    }

    return 1;
}

#endif

static int lcidm_generate_cid(QUIC_LCIDM *lcidm,
                              QUIC_CONN_ID *cid)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    int i;

    lcidm->next_lcid.id_len = (unsigned char)lcidm->lcid_len;
    *cid = lcidm->next_lcid;

    for (i = lcidm->lcid_len - 1; i >= 0; --i)
        if (++lcidm->next_lcid.id[i] != 0)
            break;

    return 1;
#else
    return gen_rand_conn_id(lcidm->libctx, lcidm->lcid_len, cid);
#endif
}

static int lcidm_generate(QUIC_LCIDM *lcidm,
                          void *opaque,
                          unsigned int type,
                          QUIC_CONN_ID *lcid_out,
                          uint64_t *seq_num)
{
    QUIC_LCIDM_CONN *conn;
    QUIC_LCID key, *lcid_obj;

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    if ((type == LCID_TYPE_INITIAL && conn->next_seq_num > 0)
        || conn->next_seq_num > OSSL_QUIC_VLINT_MAX)
        return 0;

    if (!lcidm_generate_cid(lcidm, lcid_out))
        return 0;

    key.cid = *lcid_out;
    if (lh_QUIC_LCID_retrieve(lcidm->lcids, &key) != NULL)
        return 0;

    if ((lcid_obj = lcidm_conn_new_lcid(lcidm, conn, lcid_out)) == NULL)
        return 0;

    lcid_obj->seq_num   = conn->next_seq_num;
    lcid_obj->type      = type;

    if (seq_num != NULL)
        *seq_num = lcid_obj->seq_num;

    ++conn->next_seq_num;
    return 1;
}

int ossl_quic_lcidm_enrol_odcid(QUIC_LCIDM *lcidm,
                                void *opaque,
                                const QUIC_CONN_ID *initial_odcid)
{
    QUIC_LCIDM_CONN *conn;
    QUIC_LCID key, *lcid_obj;

    if (initial_odcid == NULL || initial_odcid->id_len < QUIC_MIN_ODCID_LEN
        || initial_odcid->id_len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    if (conn->done_odcid)
        return 0;

    key.cid = *initial_odcid;
    if (lh_QUIC_LCID_retrieve(lcidm->lcids, &key) != NULL)
        return 0;

    if ((lcid_obj = lcidm_conn_new_lcid(lcidm, conn, initial_odcid)) == NULL)
        return 0;

    lcid_obj->seq_num   = LCIDM_ODCID_SEQ_NUM;
    lcid_obj->type      = LCID_TYPE_ODCID;

    conn->odcid_lcid    = lcid_obj;
    conn->done_odcid    = 1;
    return 1;
}

int ossl_quic_lcidm_generate_initial(QUIC_LCIDM *lcidm,
                                     void *opaque,
                                     QUIC_CONN_ID *initial_lcid)
{
    return lcidm_generate(lcidm, opaque, LCID_TYPE_INITIAL,
                          initial_lcid, NULL);
}

int ossl_quic_lcidm_generate(QUIC_LCIDM *lcidm,
                             void *opaque,
                             OSSL_QUIC_FRAME_NEW_CONN_ID *ncid_frame)
{
    ncid_frame->seq_num         = 0;
    ncid_frame->retire_prior_to = 0;

    return lcidm_generate(lcidm, opaque, LCID_TYPE_NCID,
                          &ncid_frame->conn_id,
                          &ncid_frame->seq_num);
}

int ossl_quic_lcidm_retire_odcid(QUIC_LCIDM *lcidm, void *opaque)
{
    QUIC_LCIDM_CONN *conn;

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    if (conn->odcid_lcid == NULL)
        return 0;

    lcidm_delete_conn_lcid(lcidm, conn->odcid_lcid);
    conn->odcid_lcid = NULL;
    return 1;
}

struct retire_args {
    QUIC_LCID           *earliest_seq_num_lcid;
    uint64_t            earliest_seq_num, retire_prior_to;
};

static void retire_for_conn(QUIC_LCID *lcid, void *arg)
{
    struct retire_args *args = arg;

    /* ODCID LCID cannot be retired via this API */
    if (lcid->type == LCID_TYPE_ODCID
        || lcid->seq_num >= args->retire_prior_to)
        return;

    if (lcid->seq_num < args->earliest_seq_num) {
        args->earliest_seq_num = lcid->seq_num;
        args->earliest_seq_num_lcid = lcid;
    }
}

int ossl_quic_lcidm_retire(QUIC_LCIDM *lcidm,
                           void *opaque,
                           uint64_t retire_prior_to,
                           const QUIC_CONN_ID *containing_pkt_dcid,
                           QUIC_CONN_ID *retired_lcid,
                           uint64_t *retired_seq_num,
                           int *did_retire)
{
    QUIC_LCIDM_CONN key, *conn;
    struct retire_args args = {0};

    key.opaque = opaque;

    if (did_retire == NULL)
        return 0;

    *did_retire = 0;
    if ((conn = lh_QUIC_LCIDM_CONN_retrieve(lcidm->conns, &key)) == NULL)
        return 1;

    args.retire_prior_to    = retire_prior_to;
    args.earliest_seq_num   = UINT64_MAX;
    lh_QUIC_LCID_doall_arg(conn->lcids, retire_for_conn, &args);
    if (args.earliest_seq_num_lcid == NULL)
        return 1;

    if (containing_pkt_dcid != NULL
        && ossl_quic_conn_id_eq(&args.earliest_seq_num_lcid->cid,
                                containing_pkt_dcid))
        return 0;

    *did_retire = 1;
    if (retired_lcid != NULL)
        *retired_lcid = args.earliest_seq_num_lcid->cid;
    if (retired_seq_num != NULL)
        *retired_seq_num = args.earliest_seq_num_lcid->seq_num;

    lcidm_delete_conn_lcid(lcidm, args.earliest_seq_num_lcid);
    return 1;
}

int ossl_quic_lcidm_cull(QUIC_LCIDM *lcidm, void *opaque)
{
    QUIC_LCIDM_CONN key, *conn;

    key.opaque = opaque;

    if ((conn = lh_QUIC_LCIDM_CONN_retrieve(lcidm->conns, &key)) == NULL)
        return 0;

    lcidm_delete_conn(lcidm, conn);
    return 1;
}

int ossl_quic_lcidm_lookup(QUIC_LCIDM *lcidm,
                           const QUIC_CONN_ID *lcid,
                           uint64_t *seq_num,
                           void **opaque)
{
    QUIC_LCID *lcid_obj;

    if (lcid == NULL)
        return 0;

    if ((lcid_obj = lcidm_get_lcid(lcidm, lcid)) == NULL)
        return 0;

    if (seq_num != NULL)
        *seq_num        = lcid_obj->seq_num;

    if (opaque != NULL)
        *opaque         = lcid_obj->conn->opaque;

    return 1;
}

int ossl_quic_lcidm_debug_remove(QUIC_LCIDM *lcidm,
                                 const QUIC_CONN_ID *lcid)
{
    QUIC_LCID key, *lcid_obj;

    key.cid = *lcid;
    if ((lcid_obj = lh_QUIC_LCID_retrieve(lcidm->lcids, &key)) == NULL)
        return 0;

    lcidm_delete_conn_lcid(lcidm, lcid_obj);
    return 1;
}

int ossl_quic_lcidm_debug_add(QUIC_LCIDM *lcidm, void *opaque,
                              const QUIC_CONN_ID *lcid,
                              uint64_t seq_num)
{
    QUIC_LCIDM_CONN *conn;
    QUIC_LCID key, *lcid_obj;

    if (lcid == NULL || lcid->id_len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    key.cid = *lcid;
    if (lh_QUIC_LCID_retrieve(lcidm->lcids, &key) != NULL)
        return 0;

    if ((lcid_obj = lcidm_conn_new_lcid(lcidm, conn, lcid)) == NULL)
        return 0;

    lcid_obj->seq_num   = seq_num;
    lcid_obj->type      = LCID_TYPE_NCID;
    return 1;
}
