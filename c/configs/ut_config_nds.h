/*
 * ur-tones on the Nintendo DSi (ARM946E-S at 134 MHz, ARMv5TE, no FPU,
 * 16 MB of RAM, 32 KB of ITCM), as NDS-Signer builds it (devkitARM, -O2).
 *
 *   -DUT_CONFIG_FILE="ut_config_nds.h"   (tools/portability.sh arm946)
 *
 * The default sizes fit the RAM easily; nothing moves. Measured on a DSi XL
 * in DSi mode (NDS-Signer's developer build, Diagnostics -> Benchmark:
 * examples/pico's bench, at the microphone's rate of about 16,364 Hz):
 *   code             26.5 KB at -Os, 33.8 KB at -O2 (ARM, whole library)
 *   ut_listener      5,300 bytes of RAM
 *   seed PIN         1.06 s (PBKDF2, 10,000 iterations)
 *   receiver         44 ms of CPU per second of audio
 *   repair           2 ms for 5 misheard tones
 * docs/porting.md has the rest.
 *
 * UT_HOT was tried in ITCM, __attribute__((noinline, section(".itcm"),
 * long_call)) as libnds' ITCM_CODE: the PIN took 1.01 s and the receiver
 * 43 ms. The ARM946E-S's 8 KB instruction cache already holds these loops,
 * so it is left out.
 */
#ifndef UT_CONFIG_NDS_H
#define UT_CONFIG_NDS_H

/* No FPU: the fountain codes keep the library's integer doubles
 * (UT_USE_DOUBLE 0, the default). */

#endif
