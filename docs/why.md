# Why ur-tones

*[Español](es/por-que.md)*

## A signer without a camera or a big screen

[SeedSigner](https://seedsigner.com) showed that an air-gapped Bitcoin
signer can be cheap and stateless: a Raspberry Pi Zero, a small colour
screen and a camera, with data going in and out as QR codes. QR codes have
two needs, though: **a camera** to read them and **a screen able to show
them** (an animated QR code needs a few hundred pixels across, refreshed
several times a second).

ur-tones replaces both with **sound**. A signer then needs only:

- a **microphone** to listen (or a headset jack's microphone input, for a
  cable);
- a **speaker** to answer (or the same jack's headphone output);
- a **small screen**, just for the menus and for checking the transaction
  (amounts, addresses), plus a few buttons.

That opens the door to signers built on **modest microcontrollers**: a
Raspberry Pi Pico (RP2040/RP2350) or an ESP32 board, a 1" OLED screen,
four buttons and a 3.5 mm jack. ur-tones' C library is written for such
hardware: C99, no `malloc`, **no floating point** (integer Goertzel, a sine
table), about 12 KB of ARM Thumb code. It already runs on a 2008 handheld,
the Nintendo DSi ([NDS-Signer](https://github.com/ndssigner/nds-signer)),
listening by its microphone.

It is an old idea: home computers of the 1980s kept their programs on
cassette as tones. Here, the "programs" are PSBTs, xpubs and seeds.

> **What exists today and what does not.** The format, the reference
> implementation, the C library and the web tool exist, and NDS-Signer
> listens to tones on a real DSi (seeds with and without a PIN, a PSBT from
> Sparrow through the air). A signer firmware for a microcontroller does
> **not** exist yet: the PSBT parsing, BIP-32 and the signing (e.g.
> libsecp256k1) would have to be written or ported to it, as other
> microcontroller wallets have done. And wallets do not speak tones yet: on
> the computer, the [web tool](https://ndssigner.github.io/ur-tones/) is the
> bridge (copy the PSBT from Sparrow, play it; listen to the signed one,
> copy it back).

### SeedSigner vs a ur-tones signer

| | SeedSigner (official) | A ur-tones signer (hypothetical) |
| :--- | :--- | :--- |
| **Board** | Raspberry Pi Zero v1.3 (1 GHz, 512 MB RAM, Linux) | Raspberry Pi Pico / Pico 2 (RP2040 / RP2350, 133–150 MHz, 264–520 KB RAM), or an ESP32 |
| **Screen** | 1.3" 240×240 colour LCD (must show animated QR codes) | Any small screen: a 0.96–1.3" 128×64 OLED is enough for menus and to check addresses page by page |
| **Input of data** | Camera (reads QR codes) | Microphone, or the microphone input of a 3.5 mm headset jack (cable) |
| **Output of data** | Animated QR codes on the screen | Tones from a small speaker, or the jack's headphone output |
| **Radios** | None on the v1.3 (the Zero W has Wi-Fi/Bluetooth) | None on the Pico / Pico 2 (the "W" versions and every ESP32 have Wi-Fi/Bluetooth: prefer boards without) |
| **Approximate cost of parts** | ≈ 50–80 USD (board, screen HAT, camera, microSD, case) | ≈ 10–20 USD (board, OLED, buttons, jack or MEMS microphone + small amplifier) |
| **Power** | 5 V, around 1 W; boots Linux (tens of seconds) | Around 0.1 W, could run on AA batteries; ready in about a second |
| **Speed** | An animated QR code: seconds | By cable, ≈ 16 tones/s (a 450-byte PSBT in under 2 minutes); through the air, 80 + 80 ms per tone (about 2.7× slower) |
| **Who can capture the data** | Anyone with a camera in sight of the screen | By cable, nobody; through the air, any microphone in the room (hence the PIN for seeds) |
| **Entering a seed** | SeedQR (camera), or word by word | Tones (with an optional PIN), the keypad mode by hand on any phone, or word by word |
| **Firmware** | Mature, widely used, reviewed (Python) | Does not exist yet (only the sound layer, in C) |

The costs are rough, 2026 figures for parts bought one by one; they vary a
lot by country and stock. A signer using tones gives up speed; in exchange
it can be built from parts sold everywhere, small, cheap and easy to verify
(no camera driver, no Linux).

## Offline devices it works with

Tones are plain audio, so a ur-tones signer can trade data with old,
offline audio gear: to **carry** a PSBT or a signed PSBT between the signer
and the computer, to **keep** a backup, or to **key** a seed by hand.

| Device | Plays | Records | Use | Notes |
| :--- | :---: | :---: | :--- | :--- |
| Cassette walkman / recorder | ✓ | ✓ (recorders) | Seed backup; carrying PSBTs | Tape speed drift (wow and flutter, a few %) may matter; untested |
| MiniDisc | ✓ | ✓ | Seed backup; carrying PSBTs | Lossy (ATRAC) but good for tones; untested |
| Audio CD (burned) | ✓ | — | Seed backup (play only) | Burn the WAV as an audio track; CD-Rs age: keep two; untested |
| iPod (classic, nano, shuffle) and other MP3 players | ✓ | — (most) | Carrying a PSBT to the signer; seed backup | MP3 at 128 kbps or more should keep tones; untested |
| MP3 players with a voice recorder, digital voice recorders (dictaphones) | ✓ | ✓ | Carrying PSBTs both ways; seed backup | The closest fit: play and record, no network; untested |
| Feature phone (no SIM, or flight mode) | ✓ | ✓ (voice memos) | Recording and playing; keying a seed by hand in keypad mode | Its key tones must be real DTMF; never with a SIM in a call (the network hears them) |
| An offline laptop, phone or tablet with the web tool | ✓ | ✓ | Everything: the web tool plays and listens | **Tested** (browsers, by cable and through the air) |
| Nintendo DSi with NDS-Signer | ✓ (plays) | ✓ (listens) | Receiving PSBTs and seeds; sending the signed PSBT, and a seed with its PIN | Listening **tested** on a real DSi; playing is new |

"Untested" means just that: try it with a **test** seed or a testnet PSBT
before trusting it, and if it fails, record what was heard (*Listen →
Record what is heard*) and open an issue. Reed-Solomon repairs a few
misheard tones per frame, and a multi-part PSBT survives lost frames, but
a format this young has not met every tape deck yet.

## Another kind of seed backup

The same tones make a backup: the seed as a **sequence of tones encrypted
with a PIN** (SPEC §4), kept on a cassette, a MiniDisc, a CD or an MP3
file, and the **PIN kept somewhere else**, unrelated and out of reach.
Whoever finds the recording without the PIN gets a different, valid and
empty wallet; whoever has the PIN without the recording has nothing.

To restore it, play it to the signer (or to the web tool, offline) and type
the PIN; check the **fingerprint** that both sides show.

Be honest with yourself about its limits:

- **The PIN can be guessed offline** by someone who has the recording and
  knows what it is. Each guess costs 10,000 HMAC-SHA256 (the PIN) plus the
  BIP-39 and BIP-32 derivations and a lookup of the resulting addresses.
  As an order of magnitude, at a million guesses per second (a few
  high-end GPUs): an **8-character PIN (40 bits) falls within two weeks**;
  **12 characters (60 bits) take tens of thousands of years**; 16 are out
  of reach. So use **12 characters or more**: the PIN that the web tool
  and NDS-Signer make up (🎲) has 12, in three groups of four, and is
  written down anyway, so its length costs nothing to remember. Shorter
  PINs are accepted, with a warning.
- **Keep it off the internet.** A recording in cloud storage or e-mail is a
  recording anyone may copy and attack at leisure.
- **Media age.** Tapes stretch, CD-Rs fade, files rot. Keep two copies on
  different media, and play the backup to a signer now and then (with the
  fingerprint) to check that it still reads.
- **It is a draft format.** Do not make it the only backup of real funds
  yet; next to a backup on paper or metal, it adds a copy that does not
  look like a seed.

See also [Seedcraft](https://github.com/ndssigner/seedcraft), which backs a
seed up as a sequence of physical things.
