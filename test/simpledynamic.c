/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>              /* For NULL */
#include <openssl/macros.h>      /* For NON_EMPTY_TRANSLATION_UNIT */
#include "simpledynamic.h"

#if defined(DSO_DLFCN)

int sd_load(const char *filename, SD *lib)
{
    int dl_flags = (RTLD_GLOBAL|RTLD_LAZY);
#ifdef _AIX
    if (filename[strlen(filename) - 1] == ')')
        dl_flags |= RTLD_MEMBER;
#endif
    *lib = dlopen(filename, dl_flags);
    return *lib == NULL ? 0 : 1;
}

int sd_sym(SD lib, const char *symname, SD_SYM *sym)
{
    *sym = dlsym(lib, symname);
    return *sym != NULL;
}

int sd_close(SD lib)
{
    return dlclose(lib) != 0 ? 0 : 1;
}

#elif defined(DSO_WIN32)

nt sd_load(const char *filename, SD *lib)
{
    *lib = LoadLibraryA(filename);
    return *lib == NULL ? 0 : 1;
}

int sd_sym(SD lib, const char *symname, SD_SYM *sym)
{
    *sym = (SD_SYM)GetProcAddress(lib, symname);
    return *sym != NULL;
}

int sd_close(SD lib)
{
    return FreeLibrary(lib) == 0 ? 0 : 1;
}

#else

NON_EMPTY_TRANSLATION_UNIT

#endif
