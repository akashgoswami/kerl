#include <stdlib.h>
#include <stdint.h>

#include "../kerl.h"
#include "converter.h"

#define TEST_VECTOR "test/test.vec"

void decdump (char *code, uint32_t len)
{
  uint32_t i = 0;
  for (i = 0; i< len; i++) printf("%d,",code[i]);
}

int main(int argc, char* argv[])
{
  init_converter();
  int len = 81;
  int length = 243;
  int i = 0;
  int failed = 0;
  Kerl k;
  init_kerl(&k);

  char const* const fileName = TEST_VECTOR;
  FILE* file = fopen(fileName, "r");
  if (file == NULL) {
    fprintf(stderr, "\nUnable to open test file %s\n", TEST_VECTOR);
    return 0;
  }
  else
  {
    printf("\nSuccessfully opened test vector. Now starting tests\n");
  }

  char line[1024];
  char input[512];
  char output[512];

  while (fgets(line, sizeof(line), file) && ++i) {

    memset(input, 0, 512);
    memset(output, 0, 512);

    sscanf(line,"%81s,%81s", input, output);
    //printf("\n%s === %s",input, output);

    char* trits = trits_from_trytes(input, len);
    kerl_absorb(&k, trits, 0, length);
    kerl_squeeze(&k, trits, 0, length);

    char *ret = trytes_from_trits(trits, 0, len * 3);

    if (strncmp(ret, output, 81) != 0) {
      printf("\n Seed %s calculated %s expected %s",input, ret, output);
      failed++;
    }
    //printf("\nTransformed %s", ret);
    free((void *)trits);
    free((void *)ret);

  }
  fclose(file);
  printf("\nTotal test %d Failure %d\n", i, failed);
  return 0;
}

