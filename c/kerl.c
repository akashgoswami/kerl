#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include "kerl.h"
#include "bignum.h"
#include "bignum-str.h"

void
Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input,
        unsigned long long int inputByteLen, unsigned char delimitedSuffix,
        unsigned char *output, unsigned long long int outputByteLen);


// Static definition of three in bignum style
static uint32_t __three = 3;
bignum bignum_3 = { &__three, &__three, 1, BIGNUM_F_IMMUTABLE };

// Set it to one to enable extended logging
static int debug = 0;

static bignum bignum_alloc(void)
{
  size_t words = 48; // Limiting the space to 48 bytes, it could do more.
  size_t bytes = words * BIGNUM_BYTES;
  uint32_t *v = malloc(bytes);
  assert(v);
  memset(v, 0, bytes);
  return (bignum) {
    v, v, words, 0
  };
}

static void bignum_free(bignum *b)
{
  if (!b)
    return;
  assert(bignum_check(b) == OK);
  free(b->v);
  memset(b, 0, sizeof *b);
}

// Take a 2's complement representaiton of the bignumber
static void bignum_2s_complement(bignum *dest, bignum* src)
{
  int i = 0;
  if (!dest || !src) {
    fprintf(stderr, "\nbignum_2s_complement: passed NULL parameter");
    return;
  }
  assert(bignum_check(dest) == OK);
  assert(bignum_check(src) == OK);

  if (bignum_is_negative(src)) {

    bignum_setu(dest, 0);
    for ( i = 0; i < KERL_HASH_SIZE; i++) {
      bignum_set_byte(dest, ~bignum_get_byte(src, i), i);
    }
    bignum_addl(dest, &bignum_1);
  } else {
    bignum_dup(dest,src);
  }
}

// Take a 2's complement representaiton of the bignumber
static void bignum_swap_endian(bignum *dest, bignum* src)
{
  int i = 0;
  if (!dest || !src) {
    fprintf(stderr, "\nbignum_swap_endian: passed NULL parameter");
    return;
  }
  assert(bignum_check(dest) == OK);
  assert(bignum_check(src) == OK);

  bignum_setu(dest, 0);
  for ( i = 0; i < KERL_HASH_SIZE; i++) {
    bignum_set_byte(dest, bignum_get_byte(src, KERL_HASH_SIZE-1 -i), i);
  }

  bignum_setsign(dest, bignum_getsign(src));
}

static void hexdump (unsigned char *code, uint32_t len)
{
  uint32_t i = 0;
  for (i = 0; i< len; i++) printf("%02x",code[i]);
}

static void print(const char *label, const bignum *b)
{
  char buf[4096];
  error e = bignum_fmt_hex(b, buf, sizeof buf);
  assert(e == OK);
  printf("%s = 0x%s\n", label, buf);
}

static void kerl_transform(Kerl* ctx)
{
  if ( debug ) {
    printf("\nKerl Context before transform = ");
    hexdump(ctx->state, KERL_HASH_SIZE);
  }

  // use 0x1 as we dont want any padding
  Keccak(832, 768, ctx->state, KERL_HASH_SIZE, 0x01, ctx->state, KERL_HASH_SIZE);

  if ( debug ) {
    printf("\nKerl Context after transform = ");
    hexdump(ctx->state, KERL_HASH_SIZE);
  }

}


static void trits_to_bigint(bignum* result, char *trits, int offset, int size)
{
  int i = 0;

  bignum value = bignum_alloc();
  bignum acc = bignum_alloc();
  bignum b = bignum_alloc();
  bignum t = bignum_alloc();

  bignum_set(&acc, 0);

  for ( i = size - 1 ; i >= 0; i--) {

    bignum_mul(&b, &acc, &bignum_3);
    bignum_set(&t, trits[offset + i]);
    bignum_addl(&b, &t);
    bignum_dup(&acc, &b);
  }

  bignum_dup(result, &acc);

  bignum_free(&value);
  bignum_free(&acc);
  bignum_free(&b);
  bignum_free(&t);

}

static void bigint_to_trits(bignum* value, char* trits, size_t offset, size_t len)
{

  int i = 0, remainder = 0;
  bool isneg = false;
  bignum abs =  bignum_alloc();
  bignum rem =  bignum_alloc();
  bignum div =  bignum_alloc();

  bignum_dup(&abs, value);

  if (bignum_is_negative(&abs)) {
    bignum_abs(&abs);
    isneg = true;
  }

  for (i = 0; i < len; i++) {
    // divide abs by three and save divisor and remainder
    bignum_divmod(&div, &rem, &abs, &bignum_3);

    bignum_dup(&abs, &div);
    remainder = bignum_get_byte(&rem, 0);

    if (remainder > 1) {
      remainder = -1;
      bignum_addl(&abs, &bignum_1);
    }
    trits[i+offset] = remainder;
  }

  if (isneg) {
    //negate all the trits
    for (i = 0; i < len; i++) {
      trits[i+ offset] = -trits[i + offset];
    }
  }
}


// Converts bignum to bytes and loads in Kerl
static void saveContext(Kerl* ctx, bignum* value)
{
  int i = 0;
  bignum bigendian = bignum_alloc();
  bignum bytevalue = bignum_alloc();

  if (bignum_is_negative(value)) {
    bignum_2s_complement(&bytevalue, value);
    bignum_swap_endian(&bigendian, &bytevalue);
  } else {
    bignum_swap_endian(&bigendian, value);
  }

  for (i = 0; i <KERL_HASH_SIZE; i++) {
    ctx->state[i]  = bignum_get_byte(&bigendian, i);
  }

  bignum_free(&bigendian);
  bignum_free(&bytevalue);

  return;
}

// Fetches kerl context in bytes and load into a bignum
static void getContext(Kerl* ctx, bignum* value)
{

  int i = 0;
  int neg = 0;
  //bignum_setu(value, 0);
  bignum bytevalue = bignum_alloc();
  bignum bigendian = bignum_alloc();

  if (ctx->state[0] & 0x80) {
    neg = 1;
  }

  for (i = 0; i <KERL_HASH_SIZE; i++) {
    bignum_set_byte(&bytevalue, ctx->state[47-i], i);
  }

  if (neg) {
    // make sure sign is negative before calling two's complement
    bignum_neg(&bytevalue);
    bignum_2s_complement(value, &bytevalue);

    //make resulting value negative
    bignum_neg(value);
  } else {
    bignum_dup(value, &bytevalue);
  }

  bignum_free(&bigendian);
  bignum_free(&bytevalue);

}

/*
    Exported function
*/

void init_kerl(Kerl* ctx)
{
  memset(ctx->state, 0, KERL_HASH_SIZE * sizeof(char));
}



bool kerl_absorb(Kerl* ctx, char* const trits, const size_t off,
                 const size_t len)
{
  size_t offset = off;
  size_t length = len;

  if (ctx == NULL || trits == NULL) {
    fprintf(stderr, "\nkerl_absorb: passed NULL parameter");
    return false;
  }

  if (length % TRITS_BLOCK_SIZE != 0) {
    fprintf(stderr, "\nkerl_absorb: illegal length %zu not a multiple of %u",
            length, TRITS_BLOCK_SIZE);
    return false;
  }

  bignum b = bignum_alloc();

  do {
    // Last trit must be zero as per specs
    trits[offset+ TRITS_BLOCK_SIZE-1] = 0;

    trits_to_bigint(&b, trits, offset, length);

    if (debug) {
      print("\nkerl_absorb: Trits Converted to bigint = ", &b);
    }

    // Store the converted bignum in bytes format to kerl state
    saveContext(ctx, &b);

    offset += TRITS_BLOCK_SIZE;
    kerl_transform(ctx);

  } while ((length -= TRITS_BLOCK_SIZE) > 0);

  bignum_free(&b);

  return true;
}


bool kerl_squeeze(Kerl* ctx, char* trits, const size_t off, const size_t len)
{
  size_t offset = off;
  size_t length = len;

  int i = 0;

  if (ctx == NULL || trits == NULL) {
    fprintf(stderr, "\nkerl_squeeze: passed NULL parameter");
    return false;
  }

  if (length % TRITS_BLOCK_SIZE != 0) {
    fprintf(stderr, "\nkerl_squeeze: illegal length %zu not a multiple of %u",
            length, TRITS_BLOCK_SIZE);
    return false;
  }

  bignum b = bignum_alloc();

  do {

    getContext(ctx, &b);

    bigint_to_trits(&b, trits, offset, length);

    trits[TRITS_BLOCK_SIZE-1] = 0;

    offset += TRITS_BLOCK_SIZE;

    //Only do the next iteration if needed.
    if ( offset < length ) {
      //calculate hash again for next iteration
      for (i = 0; i < KERL_HASH_SIZE; i++) {
        ctx->state[i] = ~ctx->state[i];
      }
      kerl_transform(ctx);
    }

  } while ((length -= TRITS_BLOCK_SIZE) > 0);

  bignum_free(&b);

  return true;
}
