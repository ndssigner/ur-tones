# Porting the C library

*[Español](es/porting.md)*

`c/ur_tones.c` and `c/ur_tones.h` are plain C99 with no `malloc`, no mutable
global state and no floating point. They build for anything with a C compiler
and a few KB of RAM. This guide shows where a device's hardware plugs in, what
each option and part costs, the configurations that have been tried, and how
to add one.

## The layers: where hardware plugs in

| Layer | Calls | Plug in here |
| --- | --- | --- |
| 1. samples ⇄ detections | `ut_detector_*`, `ut_synth_*` | An ADC, I2S or a codec in; a DAC, PWM or I2S out, at any rate of 8 kHz or more. |
| | `ut_classify` | Your own DSP (a CMSIS-DSP FFT, a DSP core): give it the 8 DTMF powers of a window, and it decides as the library does. |
| 2. detections ⇄ groups | `ut_keys_*` | Tones, echoes, pauses and keypad mode. `ut_keys_tone` + `ut_keys_time` take a **DTMF decoder chip**'s events (MT8870, HT9170: a key and its start and end). |
| | `ut_player_*` | A **DTMF generator chip** (HT9200): which key, for how long, then how long silent. |
| 3. groups ⇄ frames | `ut_frame_decode`, `ut_frame_encode` | Frames as bytes (`ut_frame`): sync, base 15, Reed-Solomon, a lost or extra tone repaired. |
| 4. frames ⇄ messages | `ut_frame_to_ur`, `ut_ur_to_frame`, seeds, `ut_fountain_*`, keys | UR text, seeds and the PIN, multi-part URs, PSBTs, public keys. |

`ut_listener` is layers 1 and 2 together: samples in, groups out. That is
what most devices with a microphone or a line in need.

**Accelerators** take over the hashing through two hooks
(`c/ur_tones_config.example.h` shows both):

- `UT_SHA256_BLOCK`: SHA-256's compression, for hardware that can load a state (ESP32-S3/C3/C6, STM32 with a HASH peripheral, nRF CC3xx).
- `UT_PBKDF2_SHA256`: the whole PBKDF2, for hardware that only hashes whole messages (the RP2350's SHA-256), or for a firmware that already carries mbedTLS or wolfSSL.

The seed PIN is 10,000 PBKDF2 iterations, or 20,000 SHA-256 blocks: that is
where an accelerator pays off. A hook sees the PIN and its key, so it must
clear its own buffers and the accelerator's registers, as the portable code
does.

## What each part costs

Code for a Cortex-M0+ (Thumb-1, `arm-none-eabi-gcc -Os`), from
`tools/portability.sh m0plus`:

| Build | Code |
| --- | ---: |
| Everything (default) | 19.2 KB |
| `UT_NO_AUDIO`: no detector, synthesis or `ut_listener` (a DTMF chip does it) | 16.7 KB |
| `UT_NO_KEYPAD`: no keypad mode | 18.4 KB |
| `UT_NO_SEED`: no seeds, PIN or keypad mode | 17.4 KB |
| `UT_NO_FOUNTAIN`: no multi-part URs or PSBTs as CBOR | 15.3 KB |
| `UT_NO_KEYS`: no xpubs, descriptors or their URs | 16.7 KB |
| `UT_NO_SEED`, `UT_NO_FOUNTAIN`, `UT_NO_KEYS`: frames and audio | 9.7 KB |
| The same with `UT_NO_AUDIO`: frames only | 7.2 KB |

The library allocates nothing. RAM is the structs the application places
(statically, on the stack, or in its own memory), with the default sizes:

| Struct | Bytes | Grows with |
| --- | ---: | --- |
| `ut_listener` (= `ut_detector` + `ut_keys`) | 5,300 | |
| `ut_detector` | 2,120 | `UT_RING`: 2 bytes per sample kept (≥ 560) |
| `ut_keys` | 3,176 | `UT_GROUP` (≥ 560) × (`UT_READY` + 1), `UT_LIVE` |
| `ut_fountain_encoder` | 3,104 | `UT_MAX_PARTS`: 12 bytes per fragment |
| `ut_fountain_decoder` | 3,200 | `UT_MAX_PARTS`: 12 bytes per fragment |
| `ut_frame` | 476 | |
| `ut_synth` | 56 | |

The **stack** is the other cost: on a Cortex-M0+, the deepest call
(`ut_ur_to_frame`, which parses a UR) takes about 2.6 KB, a frame's repair
about 2.3 KB, and a seed's PIN about 2.1 KB. Some SDKs give `main` less than
that by default (the Pico SDK: 2 KB).

Regenerate the figures with:

```
tools/portability.sh m0plus
```

## Options, hooks and switches

All of them go in a configuration header of your own, named with
`-DUT_CONFIG_FILE="my_config.h"` (or `UR_TONES_CONFIG_FILE` with CMake).
`c/ur_tones_config.example.h` explains each one; impossible values stop the
build with an `#error`.

- **Sizes:** `UT_MAX_PARTS`, `UT_GROUP`, `UT_READY`, `UT_LIVE`, `UT_RING` (above).
- **Arithmetic:** `UT_USE_DOUBLE 1` uses the CPU's doubles for the fountain codes instead of the library's integer ones: same results, faster with a double-precision FPU.
- **Placement:**
  - `UT_ROM` and `UT_ROM_U8/U16/U32` put the constant tables (about 1.4 KB) in program memory on Harvard CPUs (AVR: `PROGMEM`).
  - `UT_HOT` marks the hot loops (Goertzel, synthesis, SHA-256's compression) to run from RAM on CPUs that run code from flash through a cache. Include `noinline`: a static function inlined into its caller runs from wherever the caller does.
- **Hooks:** `UT_SHA256_BLOCK`, `UT_PBKDF2_SHA256` (above).
- **Switches:** `UT_NO_AUDIO`, `UT_NO_SEED`, `UT_NO_KEYPAD`, `UT_NO_FOUNTAIN`, `UT_NO_KEYS` (above).

## Secrets

The seed calls clear every copy they make of the entropy, the PIN and its key
before they return, errors included. `tests/c/wipe.c` checks this by searching
the stack. The application's buffers are its own to clear: the entropy and the
PIN it passes, what it gets back, a `ut_frame`, and the tones a
`ut_listener` heard (`ut_listener_init` clears them).

## Configurations

### Raspberry Pi Pico (RP2040): measured

[`c/configs/ut_config_rp2040.h`](../c/configs/ut_config_rp2040.h): the
default sizes, and `UT_HOT` in the SDK's `.time_critical` section. CI builds
it with warnings as errors and builds [`examples/pico`](../examples/pico), an
example that listens by cable (ADC with DMA at 16 kHz), sends (PWM), and
measures. On a Pico at 125 MHz:

| | |
| --- | --- |
| Seed PIN (PBKDF2, 10,000 iterations) | 1.46 s |
| Receiver (`ut_listener_push`) | 127 ms of CPU per second of audio at 16 kHz (13%) |
| A frame with 16 bytes to repair (`ut_frame_to_ur`) | 2.6 ms |
| Received by cable from a computer | frames and a keypad-mode seed, 0 bytes repaired |

The example's PWM output is built but not yet tested on a board.

### Nintendo DSi (ARM946E-S, no FPU): measured

[`c/configs/ut_config_nds.h`](../c/configs/ut_config_nds.h): the defaults.
CI builds it with warnings as errors (`tools/portability.sh arm946`).
[NDS-Signer](https://github.com/ndssigner/nds-signer) uses it to listen
through the microphone and to play through the speaker; its developer
build's Diagnostics -> Benchmark runs `examples/pico`'s bench. On a DSi XL
(134 MHz, devkitARM, `-O2`):

| | |
| --- | --- |
| Code (ARM, whole library) | 26.5 KB at `-Os`, 33.8 KB at `-O2` |
| Seed PIN (PBKDF2, 10,000 iterations) | 1.06 s |
| Receiver (`ut_listener_push`) | 44 ms of CPU per second of audio at 16,364 Hz (4.4%) |
| A frame with 5 misheard tones (`ut_frame_to_ur`) | 2 ms |
| Through the air, on a DSi XL | seeds, with and without a PIN; a PSBT both ways with Sparrow |

`UT_HOT` in ITCM was measured too and left out: the PIN went from 1.06 s
to 1.01 s, as the 8 KB instruction cache already holds the hot loops.

### Planned

Raspberry Pi Pico 2 (RP2350, with `UT_PBKDF2_SHA256` on its SHA-256
accelerator), ESP32 boards, STM32 and other Cortex-M parts, AVR, MSP430 and
RISC-V. None of them has been built or measured yet.

## A new port, step by step

1. Build `c/ur_tones.c` with the target's compiler, warnings as errors (`-Wall -Wextra -Werror`). Watch for a 16-bit `int`: results are `int32_t`, but say what your compiler reports.
2. Write `c/configs/ut_config_<target>.h`: sizes for its RAM, `UT_ROM` and `UT_HOT` if it needs them, hooks for its accelerators.
3. Check the stack your calls need against what the SDK gives `main`.
4. Feed it real audio: the vectors' frames and a keypad-mode seed (`vectors/ur-tones-v0.json`; `reference/python/ur_tones.py` renders them to a WAV). Note how many bytes Reed-Solomon repaired. Keypad mode needs at least 80 ms tones and 80 ms silences (SPEC §1.1).
5. Measure what `examples/pico`'s `bench` measures: the PIN, the receiver's CPU per second of audio, a repair.
6. If the toolchain is in Debian or Ubuntu's apt, add it to `tools/portability.sh` and to CI's `portability` job.

## Help wanted: ports

If you have one of these boards or toolchains, a port is very welcome:

- Raspberry Pi Pico 2 (RP2350): a Cortex-M33 build, and `UT_PBKDF2_SHA256` on its SHA-256 accelerator.
- AVR (`UT_ROM` as `PROGMEM`) and MSP430, with an audit for 16-bit `int` (`-Wconversion`); RISC-V; a Cortex-M4F with `UT_USE_DOUBLE 1`.
- The library's tests under QEMU (32-bit, big-endian) or simavr.
- Packaging: an ESP-IDF component, a Zephyr module, PlatformIO, an Arduino library; examples for ESP-IDF, Arduino, and an MT8870 decoder chip.
- Recordings of real devices sending and receiving, for the test vectors.

A contribution should bring the target's build line, its
`c/configs/ut_config_<target>.h`, the figures it measured (and how), and a CI
job when its toolchain is in apt. Open a pull request
([CONTRIBUTING.md](../CONTRIBUTING.md)). A port changes no part of the
format, so it needs no issue first.
