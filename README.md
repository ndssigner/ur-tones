# ur-tones

Move Bitcoin data — PSBTs, seeds, xpubs, descriptors — as **telephone tones
(DTMF)**: through an audio cable, or through the air, between devices that
share no network, no camera and no storage. The same
[UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
parts that animated QR codes carry, so a wallet that speaks UR only needs the
sound layer. And a seed can be keyed in by hand on any phone.

From the [NDS-Signer](https://github.com/ndssigner/nds-signer) project (an
air-gapped signer for the Nintendo DSi), but meant for any wallet or signer.
Its sister project, [Seedcraft](https://github.com/ndssigner/seedcraft),
backs seeds up as sequences of things.

> ⚠️ **Draft.** The format can still change. Do not move the seed of real funds
> with a draft format.

## In short

- **Data mode**: a UR part per frame — lead-in, sync, a Reed-Solomon codeword
  (16 parity bytes) written in base 15 as the step from one tone to the
  next, so a tone **never follows itself**: an echo cannot pass for a second
  tone. One misheard tone is always repaired, two almost always, and one
  lost or extra tone too. Long PSBTs go as multi-part URs with their fountain
  codes: a lost frame costs one frame.
- **Keypad mode**: a seed as `*`, the Standard SeedQR digits (four per word),
  `#`. Any phone can key it, at any pace. For cables and quiet rooms.
- **PIN for seeds**: so that whoever overhears or records the tones gets a
  different seed. Transactions are not encrypted (they give no access to
  funds).
- **Pace**: by cable, 40 ms tones with 20 ms of silence (about 16 tones per
  second: a 450-byte PSBT in about 1½ minutes); through the air, 80 + 80 ms.
- **Cables**: which ones, levels, and the Nintendo DSi's odd socket: see
  [SPEC.md §5](SPEC.md#5-cables).

See [SPEC.md](SPEC.md).

## Web tool

[`dist/ur-tones.html`](https://ndssigner.github.io/ur-tones/) — also in each
[release](https://github.com/ndssigner/ur-tones/releases), to use offline.
For wallets that do not speak tones yet:

- **Play**: paste a PSBT (from Sparrow: *Copy as Base64*, or open the `.psbt`
  file), UR texts or a test seed, and play them as tones — by cable or
  through the air — or save a WAV.
- **Listen** with the microphone (or open a WAV) and get the PSBT back, to
  paste into Sparrow (*File → Open Transaction → From Text*), with a live
  view of the level, the tones, the frames and the parts heard.

It is a single file that cannot connect anywhere: its Content-Security-Policy
forbids every network request, external script and `eval`; only its own
inline script and style run, pinned by their SHA-256. It stores nothing.
Check it with your operating system (`shasum -a 256 ur-tones.html`) against
the hash published with the release; `node web/build.mjs` rebuilds it byte
for byte. **For learning and testing**: handle real seeds only on an
air-gapped device.

## In this repository

- `SPEC.md`: the specification (draft v0).
- `reference/python/ur_tones.py`: reference implementation, standard library
  only; the frames and seeds also run on MicroPython (NDS-Signer).
- `vectors/ur-tones-v0.json`: test vectors, public test seeds and testnet
  PSBTs only (`tools/gen_vectors.py`, cross-checked with the UR library
  SeedSigner bundles and with embit).
- `tests/test_reference.py`: vectors, error repair, and audio through a
  simulated acoustic channel (`tests/acoustic.py`: a small speaker, a room's
  echo, noise), at several paces and sample rates, and keyed at a person's
  pace.
- `web/`: the web tool (`web/test.mjs` checks it against the same vectors,
  Node's crypto and the simulated channel).

```bash
python3 tests/test_reference.py      # the Python reference
node web/test.mjs                    # the JavaScript (Node.js ≥ 18)
node web/build.mjs                   # dist/ur-tones.html + its SHA-256
python3 tools/bundle.py v0.1.0       # the release zip, reproducible
```

Recordings help most: if the tool misses tones in your setup, a WAV of it
(with a **test** seed or a testnet PSBT) is the best bug report.

## License

MIT, see [LICENSE](LICENSE). The UR fountain codes are ported from Foundation
Devices' ur2 (BSD-2-Clause-Patent); the bytewords list is Blockchain
Commons'.
