---
name: A port
about: ur-tones on a new MCU, DSP, DTMF chip, platform or language
title: "Port: "
labels: port
---

**Target.** Chip or platform, toolchain, how audio goes in and out (ADC,
I2S, codec, DTMF decoder/generator chip).

**Plan.** Which layers you use, which hooks (SHA-256, PBKDF2, your own DSP
via ut_classify), which switches (UT_NO_*).

**What you'll bring.** The build line, a configuration header for
`c/configs/`, measured figures (RAM, flash, the PIN's time, CPU while
listening), a CI job if the toolchain is in Ubuntu's apt.

**Status.** Planned / in progress / working (link).
