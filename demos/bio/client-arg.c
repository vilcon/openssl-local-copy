/*
 * Copyright 2013-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int main(int argc, char **argv)
{
    BIO *sbio = NULL, *out = NULL;
    int len;
    char tmpbuf[1024];
    SSL_CTX *ctx;
    SSL_CONF_CTX *cctx;
    SSL *ssl;
    char **args = argv + 1;
    const char *connect_str = "localhost:4433";
    int nargs = argc - 1;
    int ret = EXIT_FAILURE;

    ctx = SSL_CTX_new(TLS_client_method());
    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    while (*args && **args == '-') {
        int rv;
        /* Parse standard arguments */
        rv = SSL_CONF_cmd_argv(cctx, &nargs, &args);
        if (rv == -3) {
            fprintf(stderr, "Missing argument for %s\n", *args);
            goto end;
        }
        if (rv < 0) {
            fprintf(stderr, "Error in command %s\n", *args);
            ERR_print_errors_fp(stderr);
            goto end;
        }
        /* If rv > 0 we processed something so proceed to next arg */
        if (rv > 0)
            continue;
        /* Otherwise application specific argument processing */
        if (strcmp(*args, "-connect") == 0) {
            int colon_pos;
            char *connect_str = args[1];
            char *port_str = connect_str;
            char *endptr;
            long port;
            char *host;
            int i;
            
            colon_pos = strcspn(connect_str, ":");
            host = (char *)malloc(colon_pos + 1);

            if (!host) {
                fprintf(stderr, "Error: could not allocate memory\n");
                goto end;
            }
            for (i = 0; i < colon_pos; i++) {
                host[i] = connect_str[i];
            }
            
            host[colon_pos] = '\0';
            port_str += colon_pos + 1;
            port = strtol(port_str, &endptr, 10);

            if (nargs < 2) {
                fprintf(stderr, "Missing argument after -connect\n");
                goto end;
            }
            if (colon_pos == strlen(connect_str)) {
                fprintf(stderr, "Invalid -connect argument: must be in the format 'host:port'\n");
                goto end;
            }
            if (*endptr != '\0' || port <= 0 || port > 65535) {
                fprintf(stderr, "Invalid -connect argument: invalid port number '%s'\n", port_str);
                free(host);
                goto end;
            }
            args += 2;
            nargs -= 2;
            /* Use host and port here */
            BIO_set_conn_hostname(sbio, host);
            BIO_set_conn_port(sbio, port_str);

            free(host);
            continue;
        } else {
            fprintf(stderr, "Unknown argument %s\n", *args);
            goto end;
        }
    }

    if (!SSL_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "Finish error\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /*
     * We'd normally set some stuff like the verify paths and * mode here
     * because as things stand this will connect to * any server whose
     * certificate is signed by any CA.
     */

    sbio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(sbio, &ssl);

    if (!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        goto end;
    }

    /* We might want to do other things with ssl here */

    BIO_set_conn_hostname(sbio, connect_str);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (BIO_do_connect(sbio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /* Could examine ssl here to get connection info */

    BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    for (;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0)
            break;
        BIO_write(out, tmpbuf, len);
    }
    ret = EXIT_SUCCESS;
 end:
    SSL_CONF_CTX_free(cctx);
    BIO_free_all(sbio);
    BIO_free(out);
    return ret;
}
