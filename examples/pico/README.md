# ur-tones on a Raspberry Pi Pico

A Pico (RP2040) that listens to ur-tones by cable, sends a UR as tones, and
measures the library, over its USB serial port. It is the C library with
[`c/configs/ut_config_rp2040.h`](../../c/configs/ut_config_rp2040.h), built
with the Pico SDK through the repository's `CMakeLists.txt`.

## Wiring

**Line in** (GP27, ADC1), from a phone's or a computer's headphone output:

```
jack tip ──┤├── 1 µF (− to the jack) ──┬── 1 kΩ ── 4.7 kΩ ──┬── GP27
                                       │                    │
              3V3 ── 10 kΩ ────────────┤                   10 nF
                                       │                    │
             AGND ── 10 kΩ ────────────┘                   AGND
jack sleeve ── AGND
```

The two 10 kΩ resistors hold the input at 1.65 V, the middle of the ADC's
range; the 1 µF capacitor blocks the source's own bias; 5.7 kΩ and 10 nF are
an anti-aliasing filter below the 8 kHz Nyquist frequency. Start at a low
volume and turn it up until frames come through: a level that clips loses
tones.

**Line out** (GP15, PWM at 125 kHz), to a wired earbud, a small amplifier or
another device's line in:

```
GP15 ── 1 kΩ ──┬── 10 µF (+ to the resistor) ── jack tip
               │
              47 nF (optional: smooths the 125 kHz carrier)
               │
GND ───────────┴──────────────────────────── jack sleeve (on a 4-pole
                                             jack, the third ring from the tip)
```

For a loopback test, connect the line out to the line in: the Pico hears
what it sends.

## Build and flash

```
cmake -S examples/pico -B build/pico -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build/pico
```

Hold BOOTSEL while plugging the Pico in, and copy
`build/pico/ur_tones_pico.uf2` to the drive that appears (or
`picotool load -x build/pico/ur_tones_pico.uf2`). Then open its USB serial
port in any terminal (the baud rate does not matter).

## Use

- **Listening** is always on. Each frame heard is printed as its UR with the
  bytes Reed-Solomon repaired. A keypad-mode group prints only the length of
  the seed it carries, never the seed.
- **`send <ur>`** plays the UR as one frame (40 ms tones, 20 ms gaps, the
  cable pace), at 15,625 samples per second.
- **`bench`** prints how long the seed PIN takes (PBKDF2, 10,000 iterations),
  the receiver's CPU time per second of audio, and the time to repair a frame
  with 5 misheard tones.

Try it:

1. Loopback: `send` a UR from [`vectors/ur-tones-v0.json`](../../vectors/ur-tones-v0.json);
   the Pico prints the same UR, with 0 bytes repaired.
2. Web tool → Pico: play a frame from the web tool by cable into the line in.
3. Pico → web tool: `send` a UR with the line out into the computer's line
   in (or an earbud next to its microphone) and decode it in the web tool.

## Figures

On a Pico at 125 MHz, with this configuration; [`docs/porting.md`](../../docs/porting.md)
has the sizes for every part of the library.

| | |
| --- | --- |
| Library code (Thumb-1, `-Os`) | 19.2 KB |
| `ut_listener` | 5,300 bytes |
| Deepest stack (`ut_ur_to_frame`) | about 2.6 KB (`PICO_STACK_SIZE` is set to 4 KB) |
| This example, whole | 92 KB of flash, 25 KB of RAM |
