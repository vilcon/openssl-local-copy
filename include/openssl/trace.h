/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TRACE_H
# define OSSL_TRACE_H

# include <stdarg.h>

# include <openssl/bio.h>

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * OSSL_trace_cb is the type tracing callback provided by the application.
 * It MUST return the number of bytes written, or 0 on error (in other words,
 * it can never write zero bytes).
 *
 * The |buffer| will always contain text, which may consist of several lines.
 * The |data| argument points to whatever data was provided by the application
 * when registering the tracer function.
 *
 */
typedef size_t (*OSSL_trace_cb)(const char *buffer, size_t count, void *data);

/*
 * TRACE CATEGORIES
 *
 * The trace messages of the OpenSSL libraries are organized into different
 * categories. For every trace category, the application can register a separate
 * tracer callback. When a callback is registered, a so called trace channel is
 * created for this category. This channel consists essentially of an internal
 * BIO which sends all trace output it receives to the registered application
 * callback.
 *
 * The ANY category is used as a fallback category.
 */
# define OSSL_TRACE_CATEGORY_ANY                 0 /* The fallback */
# define OSSL_TRACE_CATEGORY_TRACE               1
# define OSSL_TRACE_CATEGORY_INIT                2
# define OSSL_TRACE_CATEGORY_TLS                 3
# define OSSL_TRACE_CATEGORY_SSL                 OSSL_TRACE_CATEGORY_TLS
# define OSSL_TRACE_CATEGORY_TLS_CIPHER          4
# define OSSL_TRACE_CATEGORY_SSL_CIPHER          OSSL_TRACE_CATEGORY_TLS_CIPHER
# define OSSL_TRACE_CATEGORY_ENGINE_CONF         5
# define OSSL_TRACE_CATEGORY_ENGINE_TABLE        6
# define OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT    7
# define OSSL_TRACE_CATEGORY_PKCS5V2             8
# define OSSL_TRACE_CATEGORY_PKCS12_KEYGEN       9
# define OSSL_TRACE_CATEGORY_PKCS12_DECRYPT     10
# define OSSL_TRACE_CATEGORY_X509V3_POLICY      11
# define OSSL_TRACE_CATEGORY_BN_CTX             12
# define OSSL_TRACE_CATEGORY_NUM                13

# ifndef OPENSSL_NO_TRACE

/* Returns the trace category number for the given |name| */
int OSSL_trace_get_category(const char *name);

/*
 * Enables tracing for the given |category| by providing a BIO sink
 * as |channel|. If a null pointer is passed as |channel|, an existing
 * trace channel is removed and tracing for the category is disabled.
 *
 * Returns 1 on success and 0 on failure
 */
int OSSL_trace_set_channel(int category, BIO* channel);

/*
 * Enables tracing for the given |category| by creating an internal
 * trace channel which sends the output to the given |callback|.
 * If a null pointer is passed as callback, an existing trace channel
 * is removed and tracing for the category is disabled.
 *
 * Returns 1 on success and 0 on failure
 */
int OSSL_trace_set_callback(int category, OSSL_trace_cb callback, void *data);

/*
 * Returns 1 if tracing for the specified category is enabled, otherwise 0
 */
int OSSL_trace_enabled(int category);

/*
 * Locks and returns the trace channel associated with the given category,
 * or NULL if no channel is associated with the category.
 *
 * Usage: see OSSL_TRACE_BEG()/OSSL_TRACE_END()

 *
 * Or simpler, via macro:
 *
 *    OSSL_TRACE_BEG(<CAT>) {
 *        ...
 *        BIO_fprintf(trc_out, ...);
 *    } OSSL_TRACE_END(<CAT>);
 */
BIO *OSSL_trace_begin(int category);
void OSSL_trace_end(int category, BIO *channel);

# else
#  define OSSL_trace_get_category(name)       (-1)
#  define OSSL_trace_set_channel(category, channel) (channel == NULL)
#  define OSSL_trace_set_callback(category, callback, data) (callback == NULL)
#  define OSSL_trace_get_channel(category)  (NULL)
#  define OSSL_trace_enabled(category)  (0)
#  define OSSL_trace_begin(category)  (NULL)
#  define OSSL_trace_end(category, channel)  ((void)(0))

# endif

/*
 * OSSL_TRACE* Convenience Macros
 */

/*
 * OSSL_TRACE_BEGIN, OSSL_TRACE_END - Define a Trace Group
 *
 * These two macros can be used to create a block which is executed only
 * if the corresponding trace category is enabled. Inside this block, a
 * local variable named |trc_out| is defined, which points to the channel
 * associated with the given trace category.
 *
 * Usage: (using 'SSL' as an example category)
 *
 *     OSSL_TRACE_BEGIN(SSL) {
 *
 *         BIO_fprintf(trc_out, ... );
 *
 *     } OSSL_TRACE_END(SSL);
 *
 *
 * This expands to the following code
 *
 *     do {
 *         BIO *trc_out = OSSL_trace_begin(OSSL_TRACE_CATEGORY_SSL);
 *         if (trc_out != NULL) {
 *             ...
 *             BIO_fprintf(trc_out, ...);
 *         }
 *         OSSL_trace_end(OSSL_TRACE_CATEGORY_SSL, trc_out);
 *     } while (0);
 *
 * The use of the inner '{...}' group and the trailing ';' is enforced
 * by the definition of the macros in order to make the code look as much
 * like C code as possible.
 *
 * Before returning from inside the trace block, it is necessary to
 * call OSSL_TRACE_CANCEL(category).
 *
 */

#  define OSSL_TRACE_BEGIN(category) \
    do { \
        BIO *trc_out = OSSL_trace_begin(OSSL_TRACE_CATEGORY_##category); \
 \
        if (trc_out != NULL)

#  define OSSL_TRACE_END(category) \
        OSSL_trace_end(OSSL_TRACE_CATEGORY_##category, trc_out); \
    } while (0)

#  define OSSL_TRACE_CANCEL(category) \
        OSSL_trace_end(OSSL_TRACE_CATEGORY_##category, trc_out) \


#  ifdef OSSL_DEBUG_TRACE
#   define OSSL_TRACE_ASSERT_CATEGORY(category) \
#  else
#   define OSSL_TRACE_ASSERT_CATEGORY(category) \
    ((void)0)
#  endif



/*
 * OSSL_TRACE_ENABLED() - Check whether tracing is enabled for |category|
 *
 * Usage:
 *
 *     if (OSSL_TRACE_ENABLED(SSL)) {
 *         ...
 *     }
 */
# define OSSL_TRACE_ENABLED(category) \
    OSSL_trace_enabled(OSSL_TRACE_CATEGORY_##category)


/*
 * OSSL_TRACE*() - OneShot Trace Macros
 *
 * These macros are intended to produce a simple printf-style trace output.
 * Unfortunately, C90 macros don't support variable arguments, so the
 * "vararg" OSSL_TRACEV() macro has a rather weird usage pattern:
 *
 *    OSSL_TRACEV(category, (trc_out, "format string", ...args...));
 *
 * Where 'channel' is the literal symbol of this name, not a variable.
 * For that reason, it is currently not intended to be used directly,
 * but only as helper macro for the other oneshot trace macros
 * OSSL_TRACE(), OSSL_TRACE1(), OSSL_TRACE2(), ...
 *
 * Usage:
 *
 *    OSSL_TRACE(INIT, "Hello world!\n");
 *    OSSL_TRACE1(SSL, "The answer is %d\n", 42);
 *    OSSL_TRACE2(SSL, "The ultimate question to answer %d is '%s'\n",
 *                42, "What do you get when you multiply six by nine?");
 */

#  define OSSL_TRACEV(category, args) \
    OSSL_TRACE_BEGIN(category) \
        BIO_printf args; \
    OSSL_TRACE_END(category)

#  define OSSL_TRACE(category, text) \
    OSSL_TRACEV(category, (trc_out, "%s", text))

#  define OSSL_TRACE1(category, format, arg1) \
    OSSL_TRACEV(category, (trc_out, format, arg1))
#  define OSSL_TRACE2(category, format, arg1, arg2) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2))
#  define OSSL_TRACE3(category, format, arg1, arg2, arg3) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3))
#  define OSSL_TRACE4(category, format, arg1, arg2, arg3, arg4) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4))
#  define OSSL_TRACE5(category, format, arg1, arg2, arg3, arg4, arg5) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5))
#  define OSSL_TRACE6(category, format, arg1, arg2, arg3, arg4, arg5, arg6) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6))
#  define OSSL_TRACE7(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7))
#  define OSSL_TRACE8(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8))
#  define OSSL_TRACE9(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9))

#endif
