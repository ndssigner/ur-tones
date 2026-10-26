/*
 * ur-tones on the Raspberry Pi Pico (RP2040: two Cortex-M0+ at 125 MHz, no
 * FPU, 264 KB of RAM, code run from flash through a 16 KB cache).
 *
 *   -DUT_CONFIG_FILE="ut_config_rp2040.h"   (CMakeLists.txt: UR_TONES_CONFIG_FILE)
 *
 * The default sizes fit the RAM easily; only the hot loops move. Measured
 * at 125 MHz (examples/pico's bench; tools/portability.sh m0plus):
 *   code             19.2 KB (Thumb-1, -Os)
 *   ut_listener      5,300 bytes of RAM; stack: about 2.6 KB at most
 *   seed PIN         1.46 s (PBKDF2, 10,000 iterations)
 *   receiver         127 ms of CPU per second of audio at 16 kHz
 *   repair           2.6 ms for a frame with 16 bytes wrong
 * docs/porting.md has the rest.
 */
#ifndef UT_CONFIG_RP2040_H
#define UT_CONFIG_RP2040_H

/* Goertzel, synthesis and SHA-256's compression run from RAM: the Pico SDK's
 * linker script copies .time_critical.* there at boot, so the PIN's 20,000
 * blocks and the receiver's windows never wait for the flash. noinline, as
 * the SDK's __no_inline_not_in_flash_func: a static function inlined into a
 * caller in flash would run from flash with it. */
#define UT_HOT __attribute__((noinline, section(".time_critical.ur_tones")))

/* No FPU: the fountain codes keep the library's integer doubles
 * (UT_USE_DOUBLE 0, the default); the CPU's would be software doubles. */

#endif
