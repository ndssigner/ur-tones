/*
 * ur-tones: a configuration of one's own. Copy this file, keep the lines you
 * change, and build with -DUT_CONFIG_FILE="my_ur_tones_config.h" (or give
 * each option with -D…). Every option has a safe default; the defaults suit
 * a 32-bit MCU with 64 KB of RAM or more. ur_tones.h stops the build with an
 * #error for a value that cannot work.
 *
 * RAM figures are for the library's structs, which the application places
 * (statically, on the stack or in its own memory): the library allocates
 * nothing.
 */

/* ---- sizes -------------------------------------------------------------- */

/* Fragments in a multi-part message (UR's fountain codes). Each encoder and
 * each decoder keeps 12 bytes per fragment for UR's degree table (8 with
 * UT_USE_DOUBLE on a CPU whose doubles are 8 bytes too: the same). 256
 * fragments of 100 bytes carry about 25 KB. 1 to 65535. */
/* #define UT_MAX_PARTS 256 */

/* Tones in one group the receiver keeps (a frame, or keypad mode). The
 * receiver holds UT_READY + 1 groups of UT_GROUP + 1 bytes. At least 560
 * (UT_MAX_FRAME): the longest frame. */
/* #define UT_GROUP 600 */

/* Groups heard and waiting to be taken with ut_listener_group(); when full,
 * the oldest is dropped. 1 is enough if the application takes each group
 * before the next one ends (a frame lasts several seconds). */
/* #define UT_READY 4 */

/* Live keys waiting for ut_listener_live(), 1 byte each. */
/* #define UT_LIVE 64 */

/* Samples the receiver keeps after bringing the rate down to about 8 kHz,
 * 2 bytes each. At least 560 (a 25 ms window and a 10 ms hop at up to
 * 16 kHz, whatever the input rate). */
/* #define UT_RING 1024 */

/* ---- arithmetic ----------------------------------------------------------- */

/* 1: UR's fountain codes use the CPU's (or the compiler's) doubles instead
 * of the library's integer doubles. The same results either way; faster on
 * a CPU with a double-precision FPU (Cortex-M7, ESP32-S3's is single only). */
/* #define UT_USE_DOUBLE 0 */

/* ---- where code and tables go ------------------------------------------- */

/* Constant tables (about 1.4 KB: SHA-256's constants, the bytewords, the
 * sine quarter, base58, Reed-Solomon's) are declared with UT_ROM and read
 * through UT_ROM_U8/U16/U32(pointer). Elsewhere const data already stays in
 * flash; on AVR it is copied to RAM unless placed in program memory:
 *
 *   #include <avr/pgmspace.h>
 *   #define UT_ROM PROGMEM
 *   #define UT_ROM_U8(p) pgm_read_byte(p)
 *   #define UT_ROM_U16(p) pgm_read_word(p)
 *   #define UT_ROM_U32(p) pgm_read_dword(p)
 */

/* The hot loops (Goertzel, synthesis, SHA-256's compression) carry UT_HOT.
 * On MCUs that run code from flash through a cache (XIP), putting them in
 * RAM avoids the waits:
 *
 *   RP2040, RP2350 (Pico SDK's linker scripts copy .time_critical.* to RAM):
 *   #define UT_HOT __attribute__((section(".time_critical.ur_tones")))
 *   ESP32 family (ESP-IDF):
 *   #include "esp_attr.h"
 *   #define UT_HOT IRAM_ATTR
 */

/* ---- hardware hooks ----------------------------------------------------------- */

/* SHA-256's compression, for accelerators that can load a state (the seed
 * PIN runs PBKDF2-HMAC-SHA256: 10,000 iterations, 2 blocks each, from the
 * ipad/opad states the library keeps). ESP32-S3/C3/C6, STM32 parts with a
 * HASH peripheral (context swap), nRF CC3xx, or an assembly routine:
 *
 *   void my_sha256_block(uint32_t state[8], const uint8_t block[64]);
 *   #define UT_SHA256_BLOCK my_sha256_block
 */

/* PBKDF2-HMAC-SHA256 whole, for accelerators that only hash whole messages
 * from the standard start (the RP2350's SHA-256, the original ESP32's), or
 * a firmware that already carries mbedTLS (mbedtls_pkcs5_pbkdf2_hmac_ext) or
 * wolfSSL: the library's own PBKDF2 and HMAC are then left out.
 *
 *   void my_pbkdf2(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
 *                  uint32_t iterations, uint8_t *out, size_t outlen);
 *   #define UT_PBKDF2_SHA256 my_pbkdf2
 */
