/* PBKDF2 by "hardware" that cannot load a SHA-256 state (tests/c/hooks_impl.c). */
#include <stddef.h>
#include <stdint.h>
void test_pbkdf2(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                 uint32_t iterations, uint8_t *out, size_t outlen);
#define UT_PBKDF2_SHA256 test_pbkdf2
