/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"                /* strcasecmp on Windows */
#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/encoder.h>
#include <openssl/buffer.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/trace.h>
#include "encoder_local.h"

struct encoder_process_data_st {
    OSSL_ENCODER *encoder;

    /* Current BIO */
    BIO *bio;

    /* Index of the current encoder instance to be processed */
    int current_encoder_inst_index;

    /* Processing data passed down through recursion */
    int level;                   /* Recursion level */
    OSSL_ENCODER_INSTANCE *next_encoder_inst;
    int count_output_structure;

    /* Processing data passed up through recursion */
    OSSL_ENCODER_INSTANCE *prev_encoder_inst;
    unsigned char *running_output;
    size_t running_output_length;
};

static int encoder_process(struct encoder_process_data_st *data);

int OSSL_ENCODER_to_bio(OSSL_ENCODER *encoder, BIO *out)
{
    struct encoder_process_data_st data;

    memset(&data, 0, sizeof(data));
    data.encoder = encoder;
    data.bio = out;
    data.current_encoder_inst_index = OSSL_ENCODER_get_num_methods(encoder);

    return encoder_process(&data) > 0;
}

#ifndef OPENSSL_NO_STDIO
static BIO *bio_from_file(FILE *fp)
{
    BIO *b;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_BUF_LIB);
        return NULL;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    return b;
}

int OSSL_ENCODER_to_fp(OSSL_ENCODER *encoder, FILE *fp)
{
    BIO *b = bio_from_file(fp);
    int ret = 0;

    if (b != NULL)
        ret = OSSL_ENCODER_to_bio(encoder, b);

    BIO_free(b);
    return ret;
}
#endif

int OSSL_ENCODER_to_data(OSSL_ENCODER *encoder, unsigned char **pdata,
                         size_t *pdata_len)
{
    BIO *out = BIO_new(BIO_s_mem());
    BUF_MEM *buf = NULL;
    int ret = 0;

    if (pdata_len == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (OSSL_ENCODER_to_bio(encoder, out)
        && BIO_get_mem_ptr(out, &buf) > 0) {
        ret = 1; /* Hope for the best. A too small buffer will clear this */

        if (pdata != NULL && *pdata != NULL) {
            if (*pdata_len < buf->length)
                /*
                 * It's tempting to do |*pdata_len = (size_t)buf->length|
                 * However, it's believed to be confusing more than helpful,
                 * so we don't.
                 */
                ret = 0;
            else
                *pdata_len -= buf->length;
        } else {
            /* The buffer with the right size is already allocated for us */
            *pdata_len = (size_t)buf->length;
        }

        if (ret) {
            if (pdata != NULL) {
                if (*pdata != NULL) {
                    memcpy(*pdata, buf->data, buf->length);
                    *pdata += buf->length;
                } else {
                    /* In this case, we steal the data from BIO_s_mem() */
                    *pdata = (unsigned char *)buf->data;
                    buf->data = NULL;
                }
            }
        }
    }
    BIO_free(out);
    return ret;
}

int OSSL_ENCODER_set_selection(OSSL_ENCODER *encoder, int selection)
{
    if (!ossl_assert(encoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!ossl_assert(selection != 0)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    encoder->selection = selection;
    return 1;
}

int OSSL_ENCODER_set_output_type(OSSL_ENCODER *encoder, const char *output_type)
{
    if (!ossl_assert(encoder != NULL) || !ossl_assert(output_type != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    encoder->output_type = output_type;
    return 1;
}

int OSSL_ENCODER_set_output_structure(OSSL_ENCODER *encoder,
                                      const char *output_structure)
{
    if (!ossl_assert(encoder != NULL)
        || !ossl_assert(output_structure != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    encoder->output_structure = output_structure;
    return 1;
}

static OSSL_ENCODER_INSTANCE *
ossl_encoder_instance_new(OSSL_ENCODER_METHOD *encoder_meth, void *encoderctx)
{
    OSSL_ENCODER_INSTANCE *encoder_inst = NULL;
    OSSL_PARAM params[4];

    if (!ossl_assert(encoder_meth != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (encoder_meth->get_params == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER,
                  OSSL_ENCODER_R_MISSING_GET_PARAMS);
        return 0;
    }

    if ((encoder_inst = OPENSSL_zalloc(sizeof(*encoder_inst))) == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /*
     * Cache the input and output types for this encoder.  The output type
     * is mandatory.
     */
    params[0] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_ENCODER_PARAM_OUTPUT_TYPE,
                                      (char **)&encoder_inst->output_type, 0);
    params[1] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE,
                                      (char **)&encoder_inst->output_structure,
                                      0);
    params[2] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_ENCODER_PARAM_INPUT_TYPE,
                                      (char **)&encoder_inst->input_type, 0);
    params[3] = OSSL_PARAM_construct_end();

    if (!encoder_meth->get_params(params)
        || !OSSL_PARAM_modified(&params[0]))
        goto err;

    if (!OSSL_ENCODER_METHOD_up_ref(encoder_meth)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    encoder_inst->encoder_meth = encoder_meth;
    encoder_inst->encoderctx = encoderctx;
    return encoder_inst;
 err:
    ossl_encoder_instance_free(encoder_inst);
    return NULL;
}

void ossl_encoder_instance_free(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst != NULL) {
        if (encoder_inst->encoder_meth != NULL)
            encoder_inst->encoder_meth->freectx(encoder_inst->encoderctx);
        encoder_inst->encoderctx = NULL;
        OSSL_ENCODER_METHOD_free(encoder_inst->encoder_meth);
        encoder_inst->encoder_meth = NULL;
        OPENSSL_free(encoder_inst);
    }
}

static int ossl_encoder_add_encoder_inst(OSSL_ENCODER *encoder,
                                         OSSL_ENCODER_INSTANCE *ei)
{
    int ok;

    if (encoder->encoder_insts == NULL
        && (encoder->encoder_insts =
            sk_OSSL_ENCODER_INSTANCE_new_null()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ok = (sk_OSSL_ENCODER_INSTANCE_push(encoder->encoder_insts, ei) > 0);
    if (ok) {
        OSSL_TRACE_BEGIN(ENCODER) {
            BIO_printf(trc_out,
                       "(encoder %p) Added encoder instance %p (method %p) with:\n",
                       (void *)encoder, (void *)ei, (void *)ei->encoder_meth);
            BIO_printf(trc_out,
                       "    output type: %s, output structure: %s, input type :%s\n",
                       ei->output_type, ei->output_structure, ei->input_type);
        } OSSL_TRACE_END(ENCODER);
    }
    return ok;
}

int OSSL_ENCODER_add_method(OSSL_ENCODER *encoder,
                            OSSL_ENCODER_METHOD *encoder_meth)
{
    OSSL_ENCODER_INSTANCE *encoder_inst = NULL;
    const OSSL_PROVIDER *prov = NULL;
    void *encoderctx = NULL;
    void *provctx = NULL;

    if (!ossl_assert(encoder != NULL) || !ossl_assert(encoder_meth != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    prov = OSSL_ENCODER_METHOD_provider(encoder_meth);
    provctx = OSSL_PROVIDER_get0_provider_ctx(prov);

    if ((encoderctx = encoder_meth->newctx(provctx)) == NULL
        || (encoder_inst =
            ossl_encoder_instance_new(encoder_meth, encoderctx)) == NULL)
        goto err;
    /* Avoid double free of encoderctx on further errors */
    encoderctx = NULL;

    if (!ossl_encoder_add_encoder_inst(encoder, encoder_inst))
        goto err;

    return 1;
 err:
    ossl_encoder_instance_free(encoder_inst);
    if (encoderctx != NULL)
        encoder_meth->freectx(encoderctx);
    return 0;
}

int OSSL_ENCODER_add_extra_methods(OSSL_ENCODER *encoder,
                                   OSSL_LIB_CTX *libctx, const char *propq)
{
    return 1;
}

int OSSL_ENCODER_get_num_methods(OSSL_ENCODER *encoder)
{
    if (encoder == NULL || encoder->encoder_insts == NULL)
        return 0;
    return sk_OSSL_ENCODER_INSTANCE_num(encoder->encoder_insts);
}

int OSSL_ENCODER_set_construct(OSSL_ENCODER *encoder,
                               OSSL_ENCODER_CONSTRUCT *construct)
{
    if (!ossl_assert(encoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    encoder->construct = construct;
    return 1;
}

int OSSL_ENCODER_set_construct_data(OSSL_ENCODER *encoder,
                                    void *construct_data)
{
    if (!ossl_assert(encoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    encoder->construct_data = construct_data;
    return 1;
}

int OSSL_ENCODER_set_cleanup(OSSL_ENCODER *encoder,
                             OSSL_ENCODER_CLEANUP *cleanup)
{
    if (!ossl_assert(encoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    encoder->cleanup = cleanup;
    return 1;
}

OSSL_ENCODER_METHOD *
OSSL_ENCODER_INSTANCE_get_method(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->encoder_meth;
}

void *
OSSL_ENCODER_INSTANCE_get_method_ctx(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->encoderctx;
}

const char *
OSSL_ENCODER_INSTANCE_get_input_type(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->input_type;
}

const char *
OSSL_ENCODER_INSTANCE_get_output_type(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->output_type;
}

const char *
OSSL_ENCODER_INSTANCE_get_output_structure(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->output_structure;
}

static int encoder_process(struct encoder_process_data_st *data)
{
    OSSL_ENCODER_INSTANCE *current_encoder_inst = NULL;
    OSSL_ENCODER_METHOD *current_encoder_meth = NULL;
    OSSL_ENCODER *current_encoder_ctx = NULL;
    BIO *allocated_out = NULL;
    const void *original_data = NULL;
    OSSL_PARAM abstract[10];
    const OSSL_PARAM *current_abstract = NULL;
    int i;
    int ok = -1;  /* -1 signifies that the lookup loop gave nothing */
    int top = 0;

    if (data->next_encoder_inst == NULL) {
        /* First iteration, where we prepare for what is to come */

        data->count_output_structure =
            data->encoder->output_structure == NULL ? -1 : 0;
        top = 1;
    }

    for (i = data->current_encoder_inst_index; i-- > 0;) {
        OSSL_ENCODER_METHOD *next_encoder_meth = NULL;
        const char *current_output_type;
        const char *current_output_structure;
        struct encoder_process_data_st new_data;

        if (!top)
            next_encoder_meth =
                OSSL_ENCODER_INSTANCE_get_method(data->next_encoder_inst);

        current_encoder_inst =
            sk_OSSL_ENCODER_INSTANCE_value(data->encoder->encoder_insts, i);
        current_encoder_meth =
            OSSL_ENCODER_INSTANCE_get_method(current_encoder_inst);
        current_encoder_ctx =
            OSSL_ENCODER_INSTANCE_get_method_ctx(current_encoder_inst);
        current_output_type =
            OSSL_ENCODER_INSTANCE_get_output_type(current_encoder_inst);
        current_output_structure =
            OSSL_ENCODER_INSTANCE_get_output_structure(current_encoder_inst);
        memset(&new_data, 0, sizeof(new_data));
        new_data.encoder = data->encoder;
        new_data.current_encoder_inst_index = i;
        new_data.next_encoder_inst = current_encoder_inst;
        new_data.count_output_structure = data->count_output_structure;
        new_data.level = data->level + 1;

        OSSL_TRACE_BEGIN(ENCODER) {
            BIO_printf(trc_out,
                       "[%d] (encoder %p) Considering encoder instance %p (method %p)\n",
                       data->level, (void *)data->encoder,
                       (void *)current_encoder_inst,
                       (void *)current_encoder_meth);
        } OSSL_TRACE_END(ENCODER);

        /*
         * If this is the top call, we check if the output type of the current
         * encoder matches the desired output type.
         * If this isn't the top call, i.e. this is deeper in the recursion,
         * we instead check if the output type of the current encoder matches
         * the name of the next encoder (the one found by the parent call).
         */
        if (top) {
            if (data->encoder->output_type != NULL
                && strcasecmp(current_output_type,
                              data->encoder->output_type) != 0) {
                OSSL_TRACE_BEGIN(ENCODER) {
                    BIO_printf(trc_out,
                               "[%d]    Skipping because current output type (%s) != encoder output type (%s)\n",
                               data->level,
                               current_output_type, data->encoder->output_type);
                } OSSL_TRACE_END(ENCODER);
                continue;
            }
        } else {
            if (!OSSL_ENCODER_METHOD_is_a(next_encoder_meth,
                                          current_output_type)) {
                OSSL_TRACE_BEGIN(ENCODER) {
                    BIO_printf(trc_out,
                               "[%d]    Skipping because current output type (%s) != name of encoder %p\n",
                               data->level, current_output_type,
                               (void *)next_encoder_meth);
                } OSSL_TRACE_END(ENCODER);
                continue;
            }
        }

        /*
         * If the caller and the current encoder specify an output structure,
         * Check if they match.  If they do, count the match, otherwise skip
         * the current encoder.
         */
        if (data->encoder->output_structure != NULL
            && current_output_structure != NULL) {
            if (strcasecmp(data->encoder->output_structure,
                           current_output_structure) != 0) {
                OSSL_TRACE_BEGIN(ENCODER) {
                    BIO_printf(trc_out,
                               "[%d]    Skipping because current output structure (%s) != encoder output structure (%s)\n",
                               data->level,
                               current_output_structure,
                               data->encoder->output_structure);
                } OSSL_TRACE_END(ENCODER);
                continue;
            }

            data->count_output_structure++;
        }

        /*
         * Recurse to process the encoder implementations before the current
         * one.
         */
        ok = encoder_process(&new_data);

        data->prev_encoder_inst = new_data.prev_encoder_inst;
        data->running_output = new_data.running_output;
        data->running_output_length = new_data.running_output_length;

        /*
         * ok == -1     means that the recursion call above gave no further
         *              encoders, and that the one we're currently at should
         *              be tried.
         * ok == 0      means that something failed in the recursion call
         *              above, making the result unsuitable for a chain.
         *              In this case, we simply continue to try finding a
         *              suitable encoder at this recursion level.
         * ok == 1      means that the recursion call was successful, and we
         *              try to use the result at this recursion level.
         */
        if (ok != 0)
            break;

        OSSL_TRACE_BEGIN(ENCODER) {
            BIO_printf(trc_out,
                       "[%d]    Skipping because recusion level %d failed\n",
                       data->level, new_data.level);
        } OSSL_TRACE_END(ENCODER);
    }

    /*
     * If |i < 0|, we didn't find any useful encoder in this recursion, so
     * we do the rest of the process only if |i >= 0|.
     */
    if (i < 0) {
        ok = -1;

        OSSL_TRACE_BEGIN(ENCODER) {
            BIO_printf(trc_out,
                       "[%d] (encoder %p) No suitable encoder found\n",
                       data->level, (void *)data->encoder);
        } OSSL_TRACE_END(ENCODER);
    } else {
        /* Preparations */

        switch (ok) {
        case 0:
            break;
        case -1:
            /*
             * We have reached the beginning of the encoder instance sequence,
             * so we prepare the object to be encoded.
             */

            /*
             * |data->count_output_structure| is one of these values:
             *
             * -1       There is no desired output structure
             *  0       There is a desired output structure, and it wasn't
             *          matched by any of the encoder instances that were
             *          considered
             * >0       There is a desired output structure, and at least one
             *          of the encoder instances matched it
             */
            if (data->count_output_structure == 0)
                return 0;

            original_data =
                data->encoder->construct(current_encoder_inst,
                                     data->encoder->construct_data);

            /* Assume that the constructor recorded an error */
            if (original_data != NULL)
                ok = 1;
            else
                ok = 0;
            break;
        case 1:
            if (!ossl_assert(data->running_output != NULL)) {
                ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR);
                ok = 0;
                break;
            }

            {
                /*
                 * Create an object abstraction from the latest output, which
                 * was stolen from the previous round.
                 */

                OSSL_PARAM *abstract_p = abstract;
                const char *prev_input_type =
                    OSSL_ENCODER_INSTANCE_get_input_type(data->prev_encoder_inst);
                const char *prev_output_structure =
                    OSSL_ENCODER_INSTANCE_get_output_structure(data->prev_encoder_inst);

                if (prev_input_type != NULL)
                    *abstract_p++ =
                        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                         (char *)prev_input_type, 0);
                if (prev_output_structure != NULL)
                    *abstract_p++ =
                        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                                         (char *)prev_output_structure,
                                                         0);
                *abstract_p++ =
                    OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      data->running_output,
                                                      data->running_output_length);
                *abstract_p = OSSL_PARAM_construct_end();
                current_abstract = abstract;
            }
            break;
        }

        /* Calling the encoder implementation */

        if (ok) {
            BIO *current_out = NULL;

            /*
             * If we're at the last encoder instance to use, we're setting up
             * final output.  Otherwise, set up an intermediary memory output.
             */
            if (top)
                current_out = data->bio;
            else if ((current_out = allocated_out = BIO_new(BIO_s_mem()))
                     == NULL)
                ok = 0;     /* Assume BIO_new() recorded an error */

            if (ok) {
                ok = current_encoder_meth->encode(current_encoder_ctx,
                                                  (OSSL_CORE_BIO *)current_out,
                                                  original_data,
                                                  current_abstract,
                                                  data->encoder->selection,
                                                  ossl_pw_passphrase_callback_enc,
                                                  &data->encoder->pwdata);
                OSSL_TRACE_BEGIN(ENCODER) {
                    BIO_printf(trc_out,
                               "[%d] (encoder %p) Running encoder instance %p => %d\n",
                               data->level, (void *)data->encoder,
                               (void *)current_encoder_inst, ok);
                } OSSL_TRACE_END(ENCODER);
            }

            data->prev_encoder_inst = current_encoder_inst;
        }
    }

    /* Cleanup and collecting the result */

    OPENSSL_free(data->running_output);
    data->running_output = NULL;

    /*
     * Steal the output from the BIO_s_mem, if we did allocate one.
     * That'll be the data for an object abstraction in the next round.
     */
    if (allocated_out != NULL) {
        BUF_MEM *buf;

        BIO_get_mem_ptr(allocated_out, &buf);
        data->running_output = (unsigned char *)buf->data;
        data->running_output_length = buf->length;
        memset(buf, 0, sizeof(*buf));
    }

    BIO_free(allocated_out);
    if (original_data != NULL)
        data->encoder->cleanup(data->encoder->construct_data);
    return ok;
}
