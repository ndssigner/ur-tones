#!/usr/bin/env python3
"""Writes vectors/ur-tones-v0.json: public test seeds, testnet PSBTs and
the BIP-39 test seed's public keys as ur-tones. Needs embit (mnemonic ->
entropy, to cross-check the keypad digits; BIP-32, for the xpubs), the UR
library that SeedSigner bundles (Foundation Devices' ur2: fountain-coded
multi-part URs, to cross-check the UR texts) and urtypes (selfcustody's
crypto-hdkey, crypto-output and crypto-account, for the keys' CBOR); the
reference implementation itself needs none of them.

    PYTHONPATH=<embit>/src:<urtypes>/src tools/gen_vectors.py <seedsigner>/src > vectors/ur-tones-v0.json
"""
import base64
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference" / "python"))
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "seedsigner" / "helpers"))
from embit import bip32, bip39  # noqa: E402
from urtypes import Bytes  # noqa: E402
from urtypes.crypto import Account, CoinInfo, HDKey, Keypath, Output, PathComponent  # noqa: E402
from urtypes.crypto.output import SCRIPT_EXPRESSION_TAG_MAP as SCRIPTS  # noqa: E402
from ur2.ur import UR  # noqa: E402
from ur2.ur_encoder import UREncoder  # noqa: E402
from ur2.ur_decoder import URDecoder  # noqa: E402

import ur_tones as st  # noqa: E402

# Public test seeds ONLY: NDS-Signer's test seed and SeedSigner's SeedQR test
# vectors (docs/seed_qr/README.md). Never put a real seed here.
SEEDS = [
    ("NDS-Signer test seed", "height demise useless trap grow lion found off key clown transfer enroll"),
    ("SeedSigner SeedQR test vector 4", "forum undo fragile fade shy sign arrest garment culture tube off merit"),
    ("SeedSigner SeedQR test vector 5", "good battle boil exact add seed angle hurry success glad carbon whisper"),
    ("SeedSigner SeedQR test vector 1", "attack pizza motion avocado network gather crop fresh patrol unusual wild "
     "holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire"),
    ("SeedSigner SeedQR test vector 3", "sound federal bonus bleak light raise false engage round stock update "
     "render quote truck quality fringe palace foot recipe labor glow tortoise potato still"),
]

# Testnet PSBTs from SeedSigner's tests (tests/test_decodepsbtqr.py,
# tests/test_psbt_parser.py). Public test data, no real funds.
PSBTS = [
    ("SeedSigner test PSBT, single-sig", "cHNidP8BAHICAAAAAQDo5ey+2HIrNUkExsFhsImv1OK1cYA9x/bRjYQD+0UaAQAAAAD9////Apg6AAAAAAAAF6kUVuVZEcdpQ2zgABa9dRUNYHD4VuaHgSYAAAAAAAAWABQaLE4t0JbDRg4pNnmcf+cAWIcyawAAAAAAAQEfqGEAAAAAAAAWABRyuw9od6yuS0yiZljV0X12wG9e5CIGA/ZlEZvQubb6PmcnK+vlnd8aftYnrQ8wHYSxsD8tDp61GIshjoFUAACAAQAAgAAAAIAAAAAAAAAAAAAAAA=="),
    ("SeedSigner test PSBT, multisig", "cHNidP8BAH4CAAAAAXfY5crHl+bXtTvKvdo2MaFQeIXw+P+3kzZwBRgw84lFAQAAAAD9////AhjaAAAAAAAAF6kUSop8lEmO4FB1AyV1GJe2bygA7ASHSGsBAAAAAAAiACCHttDIHkeECumMJgZ2643Hhd8rXFnv0ZbDSYM8esN9UIouEwBPAQQ1h88Dv3UWAIAAAACfHgAYuw3ODwXCSP0valI9edAB1t3EInR2TXkbOd+F+AJgmJs8XUkZD5zQAgd3+/ijOqVphlWUMzxDnRorBQYEgxDHUdwHMQAAgAEAAIAAAACAAAEBIBFGAgAAAAAAF6kU7ijES3iWT8u0+44/blPlLfh9WkyHAQMEAQAAAAEEFgAUX7JspW1r0gC+WkUHwGABJ8DU9f8iBgO1/adRC+r8XJ/bjnfdwk3740n0m8gE3+xN8GHsNrxDUxjHUdwHMQAAgAEAAIAAAACAAQAAAAAAAAAAAQAWABT8V9vY29XR8niVYdVSF9H4zRTAbiICArH6DjPShnzXiaAnc2BR1f61QQliH0BOhqAvksByf3e9GMdR3AcxAACAAQAAgAAAAIABAAAAAQAAAAAA"),
]
# Public keys of the BIP-39 test seed (never holds funds), as wallets such
# as Sparrow, SeedSigner or Passport export them. The BIP-84 xpub is the one
# BIP-84 itself publishes (as a zpub), checked below.
KEY_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
BIP84_XPUB = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
# purpose -> the script expressions around the key, outermost first
ACCOUNT_SCRIPTS = {44: [403], 49: [400, 404], 84: [404], 86: [409]}
PINS = [None, "1234"]
FRAGMENT = 100  # bytes per part (SPEC §2.3)


def cbor_bytes(b):
    n = len(b)
    head = bytes([0x40 | n]) if n < 24 else bytes([0x58, n]) if n < 256 else bytes([0x59]) + n.to_bytes(2, "big")
    return head + b


def main():
    vectors = []
    for name, mnemonic in SEEDS:
        entropy = bip39.mnemonic_to_bytes(mnemonic)
        indices = [bip39.WORDLIST.index(w) for w in mnemonic.split()]
        for pin in PINS:
            keypad = st.seed_to_keypad(entropy, pin)
            if pin is None:
                assert keypad == "*" + "".join("%04d" % i for i in indices) + "#"
            ur = st.seed_to_ur(entropy, pin)
            seed_cbor = b"\xa1\x01" + cbor_bytes(st.pin_xor(entropy, pin) if pin else entropy)
            assert UREncoder.encode(UR("crypto-seed", seed_cbor)) == ur
            vectors.append({"name": name, "mnemonic": mnemonic, "entropy": entropy.hex(), "pin": pin,
                            "keypad": keypad, "ur": ur, "frames": [st.ur_to_frame(ur)]})
    for name, b64 in PSBTS:
        psbt = base64.b64decode(b64)
        encoder = UREncoder(UR("crypto-psbt", cbor_bytes(psbt)), FRAGMENT)
        parts = []
        if encoder.is_single_part():
            parts = [encoder.next_part()]
        else:
            parts = [encoder.next_part() for _ in range(encoder.fountain_encoder.seq_len() + 3)]
        frames = [st.ur_to_frame(p) for p in parts]
        # the frames give back the same UR texts, and those the PSBT
        decoder = URDecoder()
        for f, p in zip(frames, parts):
            assert st.frame_to_ur(f) == (p, 0)
            decoder.receive_part(st.frame_to_ur(f)[0])
        assert decoder.is_success() and decoder.result_message().cbor == cbor_bytes(psbt)
        vectors.append({"name": name, "psbt_base64": b64, "fragment": FRAGMENT,
                        "urs": parts, "frames": frames})
    # xpubs and descriptors: crypto-hdkey, crypto-output, crypto-account, and bytes
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(KEY_SEED))
    master_fp = root.my_fingerprint

    def account_key(purpose, children=False):
        acc = root.derive("m/%dh/0h/0h" % purpose).to_public()
        return HDKey({"key": acc.key.sec(), "chain_code": acc.chain_code,
                      "use_info": CoinInfo(0, 0),
                      "origin": Keypath([PathComponent(purpose, True), PathComponent(0, True), PathComponent(0, True)],
                                        master_fp, 3),
                      "children": Keypath([PathComponent(0, False), PathComponent(None, False)], None, None)
                      if children else None,
                      "parent_fingerprint": acc.fingerprint}), acc.to_base58()

    def output(purpose, children=False):
        key, _ = account_key(purpose, children)
        return Output([SCRIPTS[t] for t in ACCOUNT_SCRIPTS[purpose]], key)

    hdkey, xpub = account_key(84)
    assert xpub == BIP84_XPUB and hdkey.bip32_key() == xpub
    wpkh = output(84, True)
    account = Account(master_fp, [output(p) for p in sorted(ACCOUNT_SCRIPTS)])
    text = b"ur-tones: any bytes, such as a wallet file or a multisig setup"
    for name, type_, item, extra in [
            ("BIP-39 test seed, BIP-84 account xpub", "crypto-hdkey", hdkey, {"xpub": xpub}),
            ("BIP-39 test seed, BIP-84 output descriptor", "crypto-output", wpkh,
             {"descriptor": wpkh.descriptor()}),
            ("BIP-39 test seed, account with BIP-44/49/84/86", "crypto-account", account,
             {"descriptors": [o.descriptor() for o in account.output_descriptors]}),
            ("bytes", "bytes", Bytes(text), {"text": text.decode()})]:
        cbor = item.to_cbor()
        assert type(item).from_cbor(cbor) == item
        ur = UREncoder.encode(UR(type_, cbor))
        encoder = UREncoder(UR(type_, cbor), FRAGMENT)
        if encoder.is_single_part():
            parts = [encoder.next_part()]
        else:
            parts = [encoder.next_part() for _ in range(encoder.fountain_encoder.seq_len() + 3)]
        frames = [st.ur_to_frame(p) for p in parts]
        decoder = URDecoder()
        for f, p in zip(frames, parts):
            assert st.frame_to_ur(f) == (p, 0)
            decoder.receive_part(st.frame_to_ur(f)[0])
        assert decoder.is_success() and decoder.result_message().cbor == cbor
        try:
            st.ur_to_frame(ur)
            fits = True
        except ValueError:
            fits = False
        vectors.append({"name": name, "type": type_, "cbor": cbor.hex(), **extra, "ur": ur,
                        "fits_one_frame": fits, "fragment": FRAGMENT, "urs": parts, "frames": frames})
    # a type without a code goes by name
    ur = st.ur_text("x-ur-tones-test", st.KIND_SINGLE, cbor_bytes(b"ur-tones"))
    vectors.append({"name": "named UR type", "urs": [ur], "frames": [st.ur_to_frame(ur)]})
    json.dump({"format": "ur-tones", "version": 0,
               "note": "Public test seeds and testnet PSBTs only. Never put a real seed here.",
               "vectors": vectors}, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
