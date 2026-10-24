# Contributing

ur-tones wants to be a common way for air-gapped Bitcoin tools to talk —
wallets, signers, coordinators — over sound, where QR codes don't fit: no
camera, no screen able to show them, an audio cable, a recorder. A standard
is only useful if anyone can implement it, check their implementation, and
propose changes in the open. So every change, including those that
NDS-Signer or DTMF-Signer (the projects it came from) need, comes through a
public issue or pull request here, under the same rules.

Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## What is here

- **The specification**, [SPEC.md](SPEC.md): the format itself. This is the
  standard.
- **The test vectors**, `vectors/`: the contract. An implementation that
  reproduces them, both ways, speaks ur-tones.
- **Implementations**: the Python reference (`reference/python/`), the C
  library for small devices (`c/`), the web tool (`web/`). They follow the
  specification; when one and the specification disagree, the
  specification wins (or gets fixed, through the process below).

## Kinds of change

### 1. A change to the format (SPEC.md)

Anything that changes what goes over the air or the cable: tones, timing,
frame layout, error correction, keypad mode, the seed PIN, which UR types
are carried and how.

1. **Open an issue first** ("Change to the specification"). Say what
   problem it solves, who needs it, and what it costs older devices. Wait
   for the discussion before writing code.
2. **Then one pull request with everything together**: `SPEC.md`, the
   Python reference, new or changed vectors (`tools/gen_vectors.py`), and the
   C and JavaScript implementations, so that all of them still agree. A
   format change that only one implementation follows is not accepted.
3. **Versions.** While ur-tones is a draft (v0.x), a release may change the
   format; its notes say so. From v1, a frame's format version (SPEC §2)
   changes instead, and receivers keep reading the earlier versions.

### 2. A change to an implementation

A fix, speed, a smaller footprint, a new building block, a new UR type that
the specification already allows. A pull request is enough; for something
large, an issue first saves work. It must keep every test passing, and add
the tests that show the change.

### 3. An interoperability report

Two devices that don't understand each other, a recording the receivers
miss. Open an issue ("Interoperability report") with both sides' versions,
the cable or the room, and, best of all, the **recording (WAV)** of what was
heard. **Use test seeds and testnet PSBTs only**: a recording of a real seed
is a copy of it.

### 4. A port

ur-tones on a microcontroller, a DSP, a DTMF chip, a phone, another
language. Ports are welcome as pull requests to `c/configs/` and the docs,
or as projects of their own that report here. Bring the build line, the
configuration header (`-DUT_CONFIG_FILE`), what you measured (RAM, flash,
the PIN's time, CPU while listening) and, if the toolchain is in Ubuntu's
apt, a CI job. Open an issue ("A port") to say you're on it.

## Projects that use ur-tones

Use a **released version** (a tag, `v0.x.y`), as a git submodule or a copy,
never `main`: `main` may change between releases. When a project needs a
change here, it proposes it like anyone else: an issue for the format, a
pull request for the implementations, from its own branch or fork, and it
moves to the release that includes it.

## Before a pull request

```bash
python3 tests/test_reference.py      # the Python reference
python3 tests/test_c.py              # the C library (cc)
python3 tests/test_c_multipart.py    # multi-part URs and keys (cc; Node.js too)
python3 tests/test_c_layers.py       # configuration, layers, hooks, switches (cc)
node web/test.mjs                    # the JavaScript (Node.js ≥ 18)
cc -std=c99 -Wall -Werror -mgeneral-regs-only -c c/ur_tones.c -o /dev/null   # no FP
```

All must pass; CI runs them on every pull request.

## Rules

- **Test data only**: test seeds (BIP-39's, the vectors'), testnet PSBTs, in
  code, tests, issues and recordings.
- **Nothing reaches a network.** The tools and the web tool work offline;
  no telemetry, no fetching.
- **The C library** stays C99, without `malloc`, without floating point by
  default (CPUs without an FPU), and without mutable global state; sizes go
  through the configuration header (`c/ur_tones_config.example.h`), and a
  new option says what it costs in RAM.
- **The style of the file you touch**: its naming, comments and tests.
- **Small pull requests**, one subject each, with a commit message that says
  why.

By contributing you agree that your contribution is under the project's MIT
license.
