/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "apps_os_wrapper.h"
#include "testutil.h"
#include <string.h>
#include <errno.h>

#define binname "apps_internals_test"

static int test_app_rename(void)
{
    size_t argc = test_get_argument_count();

    if (argc != 3) {
        TEST_error("Usage: %s: app_rename srcfile dstfile\n", binname);
        return 0;
    }
    if (app_rename(test_get_argument(1), test_get_argument(2)) == 0) {
        return 1;
    }
    TEST_info("got error on rename: '%s'\n", strerror(errno));

    return 0;
}

int setup_tests(void)
{
    char *command = test_get_argument(0);

    if (strcmp(command, "app_rename") == 0)
        return test_app_rename();
    
    TEST_error("%s: command '%s' is not supported for testing\n", binname, command);
    return 0;
}

