/* SHA-256's compression by "hardware" (tests/c/hooks_impl.c). */
#include <stdint.h>
void test_sha256_block(uint32_t state[8], const uint8_t block[64]);
#define UT_SHA256_BLOCK test_sha256_block
