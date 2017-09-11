#ifndef KERL_H
#define KERL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#define KERL_HASH_SIZE 48
#define TRITS_BLOCK_SIZE 243

#ifndef EXPORT
#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
#endif

typedef struct _Kerl {
  unsigned char state[KERL_HASH_SIZE];
} Kerl;

EXPORT void init_kerl(Kerl* ctx);

EXPORT bool kerl_absorb(Kerl* ctx, char* const trits, const size_t off,
                        const size_t len);
EXPORT bool kerl_squeeze(Kerl* ctx, char* trits, const size_t off,
                         const size_t len);
EXPORT void kerl_reset(Kerl* ctx);

#endif
