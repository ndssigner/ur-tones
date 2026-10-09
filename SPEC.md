# ur-tones (draft v0)

**Status: draft for discussion.** Nothing here is final until v1, and the
encoding may still change. Do not store real funds' seeds with a draft.

A way to move Bitcoin data — PSBTs, seeds, xpubs, descriptors — as **DTMF
tones**, the sounds of a telephone keypad: through an audio cable, or through
the air, between devices that share no network, no camera and no storage. And
to keep a seed as a sound recording, or **key it in by hand** on any phone.

- **Data mode** carries [UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
  parts, the same ones that animated QR codes carry, in frames with
  Reed-Solomon error correction, written so that no tone ever follows
  itself: an echo cannot pass for a second tone. Any software that speaks UR
  only needs the sound layer.
- **Keypad mode** carries a seed as the digits of a Standard SeedQR, between
  `*` and `#`, with the 12 keys that every telephone has.

The reference implementation is `reference/python/ur_tones.py`;
`vectors/ur-tones-v0.json` has test vectors (public test seeds and testnet
PSBTs only). From the [NDS-Signer](https://github.com/ndssigner/nds-signer)
project, but meant for any wallet or signer.

## 1. Tones

The 16 DTMF tones of ITU-T Q.23: each is the sum of one low and one high
frequency (Hz):

| | 1209 | 1336 | 1477 | 1633 |
| ---: | :---: | :---: | :---: | :---: |
| **697** | `1` | `2` | `3` | `A` |
| **770** | `4` | `5` | `6` | `B` |
| **852** | `7` | `8` | `9` | `C` |
| **941** | `*` | `0` | `#` | `D` |

In data mode the tones are taken in this order, the **key order**:
`0 1 2 3 4 5 6 7 8 9 A B C D * #` (positions 0–15).

### 1.1 Timing

- A tone lasts **at least 40 ms**. The receiver finds where each tone starts
  and ends, so the sender chooses the pace — a person pressing keys works
  too.
- **Data mode**: at least 20 ms of silence after each tone. Recommended:
  **40 ms tone + 20 ms silence by cable** (about 16 tones per second);
  **80 ms + 80 ms through the air**. The silences inside a frame are at most
  150 ms; frames are separated by **at least 300 ms** of silence
  (recommended 400 ms by cable, 600 ms through the air).
- **Keypad mode** played by a machine: at least 80 ms + 80 ms. Its digits
  repeat (`00`, `66`): the silence between two equal tones must be clearly
  longer than a flicker.

### 1.2 Levels and sampling

Any sample rate of 8000 Hz or more. Each frequency at about −10 dBFS, the
high one 2 dB louder than the low one (it is attenuated more on the way). A
receiver should accept frequencies within ±1.5 %, and be tolerant of the
level difference between the two: small speakers lose the low tones, so
through the air it can reach 15 dB or more. Appendix A describes a receiver.

## 2. Data mode

### 2.1 Frame

After at least 300 ms of silence:

    C B | A D | the codeword, as tones (§2.2) | silence

`C B` is a **lead-in**: it gives the receiver time to settle, and may be
lost. `A D` is the **sync**: a keypad cannot send it, so a receiver tells the
modes apart. The **codeword** is a shortened Reed-Solomon codeword over
GF(256) with **32 parity bytes** at the end, the same code as QR codes
(primitive polynomial x⁸ + x⁴ + x³ + x² + 1, generator with roots α⁰ … α³¹).
It repairs **16 wrong bytes**: any two misheard tones, and almost always
four — a noisy room (a fan, a television) costs a few. Decoding it is light
work even for a modest device: at most 255 bytes, and 32 syndromes.
Its data bytes are:

| Bytes | Field |
| :--- | :--- |
| 1 | format version (high nibble): 0; kind (low nibble): 0 = a single-part UR, 1 = a part of a multi-part UR |
| 1 | UR type code (§2.3) |
| 1 | body length L (1–255) |
| (1 + n) | only with type code 0: the type's length n and its n ASCII characters |
| L | body |
| (1) | a zero byte, when §2.2 needs it |

The codeword is at most 255 bytes, so a body has at most 219 bytes (less
with a named type). A frame that does not decode is discarded; in a
multi-part message the next frames make up for it (§2.4).

### 2.2 From bytes to tones

The codeword's bits, most significant first, are cut into groups of 15
(the last one completed with zeros). Each group is a number from 0 to 32767,
written as **4 digits in base 15** (most significant first; 15⁴ = 50625).
Each digit d becomes the tone **d + 1 positions after the previous tone** in
key order, wrapping round from `#` to `0`; the previous tone of the first
digit is the sync's `D`. So a tone never follows itself, and a receiver that
hears the same tone twice in a row knows that the second is an echo.

The receiver reads the tones back in groups of 4, and gets ⌊15 · groups / 8⌋
bytes. So that this is exactly the codeword, the sender adds a zero byte
after the body when the padding of the last group would otherwise be 8 bits
or more.

Because the tones come in groups of 4, a receiver knows when one tone was
lost (one short of a multiple of 4) or one too many was heard (one over).
It can try putting one in, or taking one out, every few places: once the
groups line up again, Reed-Solomon repairs the few bytes around the mistake,
and accepts only the right attempt.

### 2.3 UR types

| Code | Type | Code | Type |
| :---: | :--- | :---: | :--- |
| 0 | named in the frame | 6 | `account-descriptor` |
| 1 | `crypto-psbt` | 7 | `crypto-output` |
| 2 | `psbt` | 8 | `output-descriptor` |
| 3 | `crypto-seed` | 9 | `bytes` |
| 4 | `seed` | 10 | `crypto-hdkey` |
| 5 | `crypto-account` | 11 | `hdkey` |

Codes 12–255 are reserved. Any other type goes by name (code 0).

### 2.4 Body: the UR, without bytewords

The body is the binary content that the UR's bytewords would spell, without
the bytewords' CRC-32:

- **kind 0**: the message's CBOR (the UR `ur:<type>/<bytewords>`).
- **kind 1**: the part's CBOR, `[seqNum, seqLen, messageLen, checksum,
  fragment]` (the UR `ur:<type>/<seqNum>-<seqLen>/<bytewords>`).

So a receiver rebuilds the exact UR text — `ur:`, the type, the sequence
numbers read from the part's CBOR, and the body in minimal bytewords with
its CRC-32 — and hands it to any UR decoder. Messages too big for one frame
are sent as multi-part URs, with UR's fountain codes: the sender plays parts
in a loop, mixed parts included, until the receiver has enough; a lost frame
costs one frame, not the whole message. Recommended fragment length: 100
bytes (about 19 s per frame by cable, 51 s through the air).

A seed goes as `crypto-seed` or `seed`.

## 3. Keypad mode

For a seed, with the 12 keys of any telephone:

    * | the seed's Standard SeedQR digits | #

The digits are those of a [Standard SeedQR](https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md):
each word's index in the BIP-39 English list (0–2047), in four digits, so 48
digits for 12 words and 96 for 24. A person can key them from the word list
and its numbers, on a phone, onto an answering machine or a voice recorder,
at any pace.

There is no error correction: the BIP-39 checksum catches most mistakes. Send
it two or three times; a receiver compares the copies.

Keypad mode is for **cables and quiet rooms**: its digits repeat, and in an
echoey room the echo of a tone can be as loud as the same tone pressed
again. A receiver must not guess (a guessed seed is a wrong seed): through
the air, prefer data mode.

## 4. PIN, for seeds

Optional, for seeds only, in either mode. A PSBT is not encrypted: it gives
no access to funds (§6).

A PIN is letters (A–Z) and digits (0–9), case-insensitive: it is converted to
upper case first. The seed's entropy E becomes E ⊕ K, where K =
PBKDF2-HMAC-SHA256(password = the upper-case PIN as ASCII, salt =
`"ur-tones/seed-pin/v0"`, iterations = 10 000, length = len(E)). In keypad
mode the words are then recomputed from the new entropy, checksum included.
Whether a PIN was used is not recorded: the receiver asks for it, and a
wrong PIN gives a different, valid (empty) wallet.

What it is for: **someone overhearing or recording the tones** (through the
air, or a recording that is found) gets a seed that is not yours unless they
also know the PIN. Each guess costs 10 000 HMACs, but a short PIN can be
guessed: use 8 characters or more. It is not a replacement for a BIP-39
passphrase.

## 5. Cables

By cable, nothing else can hear the tones and the levels are steady. The
cable carries analogue sound in one direction and nothing else; one cable per
direction.

- **Headphone output → line input** (computers, recorders, USB sound
  adapters): a 3.5 mm stereo cable, **TRS male to TRS male**.
- **Headphone output → a phone's or laptop's headset socket** (one socket for
  headphones and microphone, **TRRS**, usually the CTIA wiring): the
  microphone is on the second ring. Use a **headset splitter** (TRRS male to
  two TRS female, headphones and microphone) with a TRS–TRS cable into its
  microphone socket, or a **TRS-to-TRRS microphone cable** made for phones.
  Some phones only accept a microphone that looks like one (about 1–2 kΩ):
  splitters and cables made for external microphones handle this; plain
  cables may not.
- **Simplest and most reliable receiver: a USB sound adapter** with separate
  headphone and microphone sockets (a few euros), with a TRS–TRS cable.
- **Levels:** a headphone output is much louder than a microphone input
  expects. Start with the sender's volume low (20–30 %) and raise it until
  the receiver hears clean tones; or use an **attenuating cable** (−20 to
  −40 dB), sold for recording from line outputs into microphone inputs.
- **Hum:** prefer devices on battery. Two devices plugged into the mains and
  joined by a cable can hum (a ground loop).

### 5.1 Nintendo DS Lite, DSi and DSi XL

Their audio socket is **two sockets in one** (GBATEK, “DSi mainboard, P4”):

| Pins | What |
| :--- | :--- |
| 1–3 | a **standard 3.5 mm stereo headphone socket** (ground, left, right) |
| 4–5 | a switch: a plug in the headphone socket mutes the speakers |
| 6–8 | a **proprietary microphone socket**, the small slot with two metal contacts next to the 3.5 mm one: microphone, a switch, ground. A plug in it disconnects the internal microphone |

The microphone input is for an **electret microphone**: the console feeds it a
bias voltage (MICBIAS, about 2–3.3 V) and expects a few millivolts.

- **From the DSi** (it plays the tones): a standard **TRS–TRS cable** from its
  headphone socket into the receiver, as above. The plug mutes the DSi's
  speakers, so nothing goes into the room.
- **Into the DSi** (it listens): there is no standard plug. Either
  - **an earphone on the DSi's microphone**: one earbud of the sender's
    headphones, at low volume, held or taped against the microphone hole (in
    the hinge, between the screens). Almost nothing leaks into the room. No
    soldering; the simplest way, and the only one on a 3DS (it has no
    external microphone socket);
  - or **a cable made from a DS headset**: Nintendo's DS Lite/DSi headset, or
    a third-party one, has a double plug (3.5 mm + the microphone prong). Cut
    its cable, find the microphone wire and its ground (with the console on,
    the microphone contact shows the bias voltage, 2–3 V, on a multimeter),
    and join them to the sender's headphone output through an attenuator
    with a DC-blocking capacitor, so that neither the bias nor the level
    harms anything:

          sender's headphone tip (left) ──[ 10 kΩ ]──┬──(+ 4.7 µF)── DSi microphone contact
                                                    [100 Ω]
          sender's headphone sleeve ─────────────────┴─────────────── DSi ground

    About −40 dB: a headphone output of 0.5–1 V becomes 5–10 mV, an
    electret microphone's level. The capacitor's + goes towards the DSi.

  NDS-Signer controls the DSi's sound chip, so it can also lower the
  microphone's gain in software. All of this is still to be tested on
  hardware.

### 5.2 Through the air

Through the air, the phone's or computer's microphone in front of the
speaker: it works, slower (§1.1), and better in a quiet room with soft
furnishings than in a bare, echoey one. Any microphone in the room — a phone,
a smart speaker, a laptop — can record it: **a seed through the air only with
a PIN** (§4), and a cable is still better.

## 6. Security considerations

- **A recording of a seed is the seed**, like a paper backup: whoever finds
  it, has it. Never keep it as a voice note on a phone: they are synchronised
  to the cloud. Use a recorder, a cassette or a card that stays offline.
- **Seeds by cable**, by keypad into a device that is offline, or through
  the air with a PIN (§4).
- A PSBT does not give access to funds, but it does tell about them: amounts,
  addresses, change.
- Tones are not authenticated: the signer must show what it signs, as with
  QR codes.
- The receiver accepts only well-formed frames; a UR decoder must still check
  what it gets, as with QR codes.

## 7. Open questions for v1

- The DSi by cable (§5.1): the headset-cable attenuator and the earphone on
  the microphone, measured on hardware.
- Faster modulations (beyond DTMF) as an optional mode, for large PSBTs.
- Frame length versus error rate through the air: measurements.

## Appendix A. A receiver (informative)

What the reference implementation does, tuned on a simulated channel (a
small speaker, a room's echo, noise; `tests/acoustic.py`) and on recordings:

1. Bring the audio down to about 8 kHz (the tones are all under 1.7 kHz):
   at 44.1 or 48 kHz, average every 5 or 6 samples. Four to six times less
   work, which matters on a modest phone or a game console.
2. Every 10 ms, measure the eight frequencies over the last 25 ms with the
   Goertzel algorithm (or any narrow band filter).
3. That moment holds a key when the strongest low and the strongest high
   frequency are each at least **twice as strong** as the runner-up in their
   group, together carry at least a fifth of the energy, and are within
   20 dB of each other. Stricter tests (6 dB, 8 dB of twist) fail through
   the air.
4. A tone is one key for at least 30 ms. A key that drops out for up to
   30 ms and comes back is the same tone (flicker).
5. Echoes: a room keeps a tone ringing after it stops, weaker. The same key
   again is a new tone only if it comes back nearly as loud as before
   (within 6 dB) after a dip, or after a silence; a weaker return is the echo.
6. Group the tones by the silences between them (§1.1). A group that starts
   with `*` and goes on with digits is keypad mode and ends at `#`, whatever
   the silences. Any other group is a data frame: drop the tones that repeat
   the one before (echoes, §2.2), find the sync among its first tones, and
   decode.
