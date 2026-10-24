#!/usr/bin/env python3
"""Tests of the C library's multi-part URs and public keys (c/ur_tones.c),
built twice: with integers only (the default) and with the CPU's doubles
(UT_USE_DOUBLE=1). Both must give the very same results:

- which fragments a part mixes, against ur2's algorithm run here with
  Python's own floats (IEEE doubles), for many sequence lengths;
- the parts themselves, against ur2's in the vectors (mixed ones included);
- decoding: in order, with parts lost, from the mixed ones alone;
- PSBTs as CBOR;
- public keys: Blockchain Commons' account-descriptor vector byte for byte,
  urtypes' descriptors and xpubs (vectors), BIP-84's zpub, and the same
  CBOR as the web tool (web/src/keys.js, through Node.js, if present).

    python3 tests/test_c_multipart.py    # builds build/libur_tones* (cc)
"""
import base64
import ctypes
import hashlib
import json
import pathlib
import random
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "vectors" / "ur-tones-v0.json").read_text())["vectors"]
BCR = json.loads((ROOT / "vectors" / "bcr-keys.json").read_text())
failures = checks = 0


def check(ok, what):
    global failures, checks
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def build(name, *flags):
    out = ROOT / "build" / (name + (".dylib" if sys.platform == "darwin" else ".so"))
    out.parent.mkdir(exist_ok=True)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-pedantic", "-Werror", "-O2", "-shared", "-fPIC", *flags,
                    str(ROOT / "c" / "ur_tones.c"), "-o", str(out)], check=True)
    lib = ctypes.CDLL(str(out))
    c_char_p, c_size_t, c_int, u8p, u32 = ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32
    lib.ut_fountain_choose.argtypes = [ctypes.c_void_p, u32, u32, u32, u8p]
    lib.ut_fountain_encoder_init.argtypes = [ctypes.c_void_p, u8p, c_size_t, c_size_t]
    lib.ut_fountain_next_ur.argtypes = [ctypes.c_void_p, c_char_p, c_char_p, c_size_t]
    lib.ut_fountain_decoder_init.argtypes = [ctypes.c_void_p, u8p, c_size_t]
    lib.ut_fountain_receive.argtypes = [ctypes.c_void_p, c_char_p]
    lib.ut_fountain_result.argtypes = [ctypes.c_void_p, ctypes.POINTER(c_char_p), ctypes.POINTER(u8p), ctypes.POINTER(c_size_t)]
    lib.ut_psbt_to_cbor.argtypes = [u8p, c_size_t, u8p, c_size_t]
    lib.ut_cbor_to_psbt.argtypes = [u8p, c_size_t, ctypes.POINTER(u8p), ctypes.POINTER(c_size_t)]
    lib.ut_xpub_text.argtypes = [ctypes.POINTER(XPub), c_char_p, c_char_p, c_size_t]
    lib.ut_descriptor_text.argtypes = [c_char_p, ctypes.POINTER(XPub), c_char_p, c_size_t]
    lib.ut_hdkey_cbor.argtypes = [ctypes.POINTER(XPub), c_int, u8p, c_size_t]
    lib.ut_output_cbor.argtypes = [c_char_p, ctypes.POINTER(XPub), c_int, u8p, c_size_t]
    lib.ut_account_cbor.argtypes = [u32, ctypes.POINTER(c_char_p), ctypes.POINTER(XPub), c_size_t, c_int, u8p, c_size_t]
    lib.ut_ur_to_frame.argtypes = [c_char_p, c_char_p, c_size_t]
    lib.ut_frame_to_ur.argtypes = [c_char_p, c_char_p, c_size_t, ctypes.POINTER(c_int)]
    fp = ctypes.POINTER(Frame)
    lib.ut_frame_from_ur.argtypes = [c_char_p, fp]
    lib.ut_frame_ur.argtypes = [fp, c_char_p, c_size_t]
    lib.ut_fountain_next_frame.argtypes = [ctypes.c_void_p, c_char_p, fp]
    lib.ut_fountain_receive_frame.argtypes = [ctypes.c_void_p, fp]
    return lib


class Frame(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_uint8), ("type", ctypes.c_char * 219), ("body", ctypes.c_uint8 * 255), ("n", ctypes.c_uint8)]


class XPub(ctypes.Structure):
    _fields_ = [("key", ctypes.c_uint8 * 33), ("chain", ctypes.c_uint8 * 32), ("parent_fp", ctypes.c_uint32),
                ("source_fp", ctypes.c_uint32), ("path", ctypes.POINTER(ctypes.c_uint32)), ("depth", ctypes.c_size_t),
                ("testnet", ctypes.c_int)]


STRUCT = 64 * 1024  # bigger than the encoder's and decoder's structs; opaque here
SAMPLER = ctypes.create_string_buffer(STRUCT)  # ut_fountain_choose's table, zeroed


def buf(data):
    return (ctypes.c_uint8 * max(1, len(data))).from_buffer_copy(data or b"\0")


# ---- ur2's choice of fragments, with Python's floats (IEEE doubles) ----------
M64 = (1 << 64) - 1


def py_choose(seq_num, seq_len, checksum):
    if seq_num <= seq_len:
        return {seq_num - 1}
    h = hashlib.sha256(seq_num.to_bytes(4, "big") + checksum.to_bytes(4, "big")).digest()
    s = [int.from_bytes(h[8 * i:8 * i + 8], "big") for i in range(4)]

    def rotl(x, k):
        return ((x << k) | (x >> (64 - k))) & M64

    def nxt():
        r = (rotl((s[1] * 5) & M64, 7) * 9) & M64
        t = (s[1] << 17) & M64
        s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]
        s[2] ^= t
        s[3] = rotl(s[3], 45)
        return r

    def dbl():
        return nxt() / (float(M64) + 1)
    # RandomSampler, as ur2 (random_sampler.py)
    probs = [1.0 / i for i in range(1, seq_len + 1)]
    total = 0
    for p in probs:
        total += p
    n = len(probs)
    P = [(p * float(n)) / total for p in probs]
    S, L = [], []
    for j in range(n - 1, -1, -1):
        (S if P[j] < 1 else L).append(j)
    prob, alias = [0] * n, [0] * n
    while S and L:
        a, g = S.pop(), L.pop()
        prob[a] = P[a]
        alias[a] = g
        P[g] += P[a] - 1
        (S if P[g] < 1 else L).append(g)
    while L:
        prob[L.pop()] = 1
    while S:
        prob[S.pop()] = 1
    r1, r2 = dbl(), dbl()
    i = int(float(n) * r1)
    degree = (i if r2 < prob[i] else alias[i]) + 1
    remaining, out = list(range(seq_len)), []
    while remaining:
        out.append(remaining.pop(int(dbl() * len(remaining) + 0)))
    return set(out[:degree])


def c_choose(lib, seq_num, seq_len, checksum):
    b = (ctypes.c_uint8 * ((seq_len + 7) // 8))()
    assert lib.ut_fountain_choose(SAMPLER, seq_num, seq_len, checksum, b) == 0
    return {i for i in range(seq_len) if b[i // 8] >> (i % 8) & 1}


def encode_urs(lib, type_, msg, fragment, count):
    enc, keep = ctypes.create_string_buffer(STRUCT), buf(msg)
    assert lib.ut_fountain_encoder_init(enc, keep, len(msg), fragment) == 0
    out = ctypes.create_string_buffer(1200)
    urs = []
    for _ in range(count):
        n = lib.ut_fountain_next_ur(enc, type_.encode(), out, 1200)
        assert n > 0, n
        urs.append(out.value.decode())
    return urs


def encode_frames(lib, type_, msg, fragment, count):
    """The same parts as encode_urs, made as frames, shown as UR texts."""
    enc, keep = ctypes.create_string_buffer(STRUCT), buf(msg)
    assert lib.ut_fountain_encoder_init(enc, keep, len(msg), fragment) == 0
    out, f, urs = ctypes.create_string_buffer(1200), Frame(), []
    for _ in range(count):
        assert lib.ut_fountain_next_frame(enc, type_.encode(), ctypes.byref(f)) > 0
        assert lib.ut_frame_ur(ctypes.byref(f), out, 1200) > 0
        urs.append(out.value.decode())
    return urs


def decode_urs(lib, urs, work=None, frames=lambda k: False):
    """(the message, how many URs it took) or (None, the last result); frames(k):
    whether the k-th goes in as a frame (ut_fountain_receive_frame)."""
    """(the message, how many URs it took) or (None, the last result)"""
    dec = ctypes.create_string_buffer(STRUCT)
    w = (ctypes.c_uint8 * (work or 8192))()
    lib.ut_fountain_decoder_init(dec, w, len(w))
    r = 0
    f = Frame()
    for k, ur in enumerate(urs):
        if frames(k):
            assert lib.ut_frame_from_ur(ur.encode(), ctypes.byref(f)) > 0
            r = lib.ut_fountain_receive_frame(dec, ctypes.byref(f))
        else:
            r = lib.ut_fountain_receive(dec, ur.encode())
        if r == 1:
            t, m, n = ctypes.c_char_p(), ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
            lib.ut_fountain_result(dec, ctypes.byref(t), ctypes.byref(m), ctypes.byref(n))
            return bytes(m[:n.value]), k + 1, t.value.decode()
        if r < 0:
            return None, r, None
    return None, r, None


def cbor_bytes(b):
    n = len(b)
    return (bytes([0x40 | n]) if n < 24 else bytes([0x58, n]) if n < 256 else bytes([0x59]) + n.to_bytes(2, "big")) + b


# ---- keys -----------------------------------------------------------------------
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(82, "big")
    assert hashlib.sha256(hashlib.sha256(raw[:78]).digest()).digest()[:4] == raw[78:]
    return raw[:78]


def key_of(descriptor):
    """(script with @0, XPub, path kept alive) from "wpkh([fp/84'/0'/0']xpub…)" (one key, no children)"""
    d = descriptor.split("#")[0]
    start, end = d.index("["), d.index("]")
    origin = d[start + 1:end].split("/")
    rest = d[end + 1:]
    xpub = rest[:rest.index(")")]
    raw = b58decode(xpub)
    path = (ctypes.c_uint32 * 8)(*[int(c.rstrip("'h")) | (0x80000000 if c[-1] in "'h" else 0) for c in origin[1:]])
    k = XPub()
    k.key[:] = raw[45:78]
    k.chain[:] = raw[13:45]
    k.parent_fp = int.from_bytes(raw[5:9], "big")
    k.source_fp = int(origin[0], 16)
    k.path, k.depth, k.testnet = path, len(origin) - 1, raw[:4] == bytes.fromhex("043587cf")
    script = d[:start] + "@0" + rest[rest.index(")"):]
    return script, k, path


def c_out(f, *args):
    out = (ctypes.c_uint8 * 80000)()
    n = f(*args, out, 80000)
    return bytes(out[:n]) if n >= 0 else n


def c_text(f, *args):
    out = ctypes.create_string_buffer(1024)
    n = f(*args, out, 1024)
    return out.value.decode() if n >= 0 else n


def js(requests):
    """The web tool's keys.js on the same inputs: [[text, current]] -> [{type, cbor}]"""
    node = shutil.which("node")
    if not node:
        return None
    script = """
import { readFileSync } from "node:fs"; import vm from "node:vm";
const ctx = vm.createContext({ TextEncoder, TextDecoder });
for (const f of ["bip39-english.js", "crypto.js", "ur-tones.js", "keys.js"]) vm.runInContext(readFileSync(process.argv[1] + f, "utf8"), ctx);
const K = vm.runInContext("UrTonesKeys", ctx), reqs = JSON.parse(readFileSync(0, "utf8"));
const hex = (b) => Buffer.from(b).toString("hex");
console.log(JSON.stringify(reqs.map(([req, arg]) => {
  if (req === "describe") { const [type, cbor] = arg; return K.describe(type, Uint8Array.from(Buffer.from(cbor, "hex"))); }
  const u = K.fromText(req).toUR(arg); return { type: u.type, cbor: hex(u.cbor) };
})));
"""
    r = subprocess.run([node, "--input-type=module", "-e", script, str(ROOT / "web" / "src") + "/"],
                       input=json.dumps(requests), capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def main():
    rng = random.Random(7)
    libs = {"integers": build("libur_tones"), "doubles": build("libur_tones_double", "-DUT_USE_DOUBLE=1")}

    # which fragments: against ur2's algorithm with real doubles, every length up to 64, then a spread to 256
    lengths = list(range(1, 65)) + list(range(65, 257, 11)) + [255, 256]
    cases = [(seq_num, n, rng.getrandbits(32)) for n in lengths for seq_num in
             list(range(1, min(n, 3) + 1)) + list(range(n + 1, n + 31))]
    want = {c: py_choose(*c) for c in cases}
    for name, lib in libs.items():
        bad = [c for c in cases if c_choose(lib, *c) != want[c]]
        check(not bad, "%s: choice of fragments as ur2, %d cases; first wrong: %s" % (name, len(cases), bad[:3]))

    # the parts themselves, against ur2's (the vectors)
    for v in [v for v in VECTORS if v.get("urs") and len(v["urs"]) > 1]:
        msg = cbor_bytes(base64.b64decode(v["psbt_base64"])) if "psbt_base64" in v else bytes.fromhex(v["cbor"])
        type_ = v["urs"][0][3:v["urs"][0].index("/")]
        for name, lib in libs.items():
            check(encode_urs(lib, type_, msg, v["fragment"], len(v["urs"])) == v["urs"], "%s: parts = ur2's: %s" % (name, v["name"]))
            check(encode_frames(lib, type_, msg, v["fragment"], len(v["urs"])) == v["urs"], "%s: parts as frames = ur2's: %s" % (name, v["name"]))

    # decoding: in order, with parts lost, from mixed parts alone; a small message as one UR
    for v in [v for v in VECTORS if v.get("urs") and len(v["urs"]) > 1]:
        msg = cbor_bytes(base64.b64decode(v["psbt_base64"])) if "psbt_base64" in v else bytes.fromhex(v["cbor"])
        type_ = v["urs"][0][3:v["urs"][0].index("/")]
        for name, lib in libs.items():
            got, used, t = decode_urs(lib, v["urs"])
            check(got == msg and t == type_, "%s: decoded in order: %s" % (name, v["name"]))
            got, _, t = decode_urs(lib, v["urs"], frames=lambda k: True)
            check(got == msg and t == type_, "%s: decoded from frames: %s" % (name, v["name"]))
            got, _, t = decode_urs(lib, v["urs"], frames=lambda k: k % 2 == 1)
            check(got == msg and t == type_, "%s: frames and texts mixed: %s" % (name, v["name"]))
            urs = encode_urs(lib, type_, msg, v["fragment"], 400)
            seq_len = int(urs[0].split("/")[1].split("-")[1])
            for trial in range(20):
                kept = [u for u in urs if rng.random() > 0.4]
                got, used, _ = decode_urs(lib, kept, frames=lambda k: trial % 2 == 1)
                check(got == msg and used <= 3 * seq_len + 10, "%s: 40%% of parts lost (%s), %s URs" % (name, v["name"], used))
            got, used, _ = decode_urs(lib, urs[seq_len:], frames=lambda k: True)
            check(got == msg, "%s: from mixed parts alone (%s), %s URs" % (name, v["name"], used))
            got, r, _ = decode_urs(lib, urs[:1] + encode_urs(lib, type_, msg[:-1] + bytes([msg[-1] ^ 1]), v["fragment"], 3)[1:2])
            check(got is None and r == -10, "%s: a part of another message refused" % name)
            got, r, _ = decode_urs(lib, urs, work=len(msg))
            check(got is None and r == -2, "%s: too little work memory refused" % name)
    for name, lib in libs.items():
        small = cbor_bytes(b"\x70\x73\x62\x74\xff" + bytes(40))
        urs = encode_urs(lib, "crypto-psbt", small, 100, 2)
        check(urs[0] == urs[1] and "/1-" not in urs[0] and decode_urs(lib, urs)[0] == small, "%s: a small message is one UR, in a loop" % name)
        check(encode_frames(lib, "crypto-psbt", small, 100, 1) == urs[:1] and decode_urs(lib, urs, frames=lambda k: True)[0] == small,
              "%s: a small message as one frame" % name)
        # every part goes in a frame and back
        out, fixed = ctypes.create_string_buffer(1200), ctypes.c_int()
        ok = True
        for ur in encode_urs(lib, "crypto-psbt", cbor_bytes(bytes(range(256)) * 3), 100, 12):
            ok &= lib.ut_ur_to_frame(ur.encode(), out, 1200) > 0
            ok &= lib.ut_frame_to_ur(out.value, out, 1200, ctypes.byref(fixed)) > 0 and out.value.decode() == ur
        check(ok, "%s: parts of 100 bytes fit a frame" % name)

    # PSBTs as CBOR
    lib = libs["integers"]
    for n in (0, 23, 24, 255, 256, 70000):
        psbt = bytes(rng.getrandbits(8) for _ in range(n))
        c = c_out(lib.ut_psbt_to_cbor, buf(psbt), n)
        p, ln = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
        ok = c == (cbor_bytes(psbt) if n < 65536 else bytes([0x5A]) + n.to_bytes(4, "big") + psbt)
        cb = buf(c)  # kept: p points into it
        ok &= lib.ut_cbor_to_psbt(cb, len(c), ctypes.byref(p), ctypes.byref(ln)) == 0 and bytes(p[:ln.value]) == psbt
        check(ok, "PSBT as CBOR and back, %d bytes" % n)

    # public keys
    acct = BCR["account_descriptor"]
    keys = [key_of(d) for d in acct["descriptors"]]
    scripts = (ctypes.c_char_p * len(keys))(*[s.encode() for s, _, _ in keys])
    xs = (XPub * len(keys))(*[k for _, k, _ in keys])
    for name, lib in libs.items():
        got = c_out(lib.ut_account_cbor, keys[0][1].source_fp, scripts, xs, len(keys), 1)
        check(isinstance(got, bytes) and got.hex() == acct["cbor"], "%s: account-descriptor = BCR-2023-019's vector, byte for byte" % name)
        check(all(c_text(lib.ut_descriptor_text, s.encode(), ctypes.byref(k)).split("#")[0] == d
                  for (s, k, _), d in zip(keys, acct["descriptors"])), "%s: descriptors = BCR-2023-019's" % name)
    for v in [v for v in VECTORS if v.get("type") == "crypto-account"]:
        ks = [key_of(d) for d in v["descriptors"]]
        check(all(c_text(lib.ut_descriptor_text, s.encode(), ctypes.byref(k)) == d for (s, k, _), d in zip(ks, v["descriptors"])),
              "descriptors with checksums = urtypes'")
        s84, k84, _ = next(x for x in ks if x[0] == "wpkh(@0)")
        hd = next(x for x in VECTORS if x.get("type") == "crypto-hdkey")
        check(c_text(lib.ut_xpub_text, ctypes.byref(k84), b"xpub") == hd["xpub"], "xpub text")
        check(c_text(lib.ut_xpub_text, ctypes.byref(k84), b"zpub") ==
              "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs", "zpub text (BIP-84's)")
        check(c_text(lib.ut_descriptor_text, b"wpkh(@0", ctypes.byref(k84)) == -1 and
              c_text(lib.ut_descriptor_text, b"raw(@0)", ctypes.byref(k84)) == -1, "bad scripts refused")
        # the same CBOR as the web tool, both generations
        reqs = [["\n".join(v["descriptors"]), cur] for cur in (True, False)] + [[d, cur] for d in v["descriptors"] for cur in (True, False)]
        web = js(reqs)
        if web is None:
            print("(no Node.js: the comparison with the web tool is skipped)")
            continue
        sc = (ctypes.c_char_p * len(ks))(*[s.encode() for s, _, _ in ks])
        kx = (XPub * len(ks))(*[k for _, k, _ in ks])
        mine = [c_out(lib.ut_account_cbor, ks[0][1].source_fp, sc, kx, len(ks), int(cur)) for cur in (True, False)]
        mine += [c_out(lib.ut_output_cbor, s.encode(), ctypes.byref(k), int(cur)) for s, k, _ in ks for cur in (True, False)]
        check([m.hex() for m in mine] == [w["cbor"] for w in web], "account and output CBOR = the web tool's (current and older types)")
        for cur, type_ in ((1, "hdkey"), (0, "crypto-hdkey")):
            h = c_out(lib.ut_hdkey_cbor, ctypes.byref(k84), cur)
            back = js([["describe", [type_, h.hex()]]])[0]
            check(back["keys"][0]["xpub"] == hd["xpub"] and back["keys"][0]["origin"] == "[73c5da0a/84'/0'/0']", "%s read by the web tool" % type_)
    t = XPub()
    t.key[:] = keys[0][1].key; t.chain[:] = keys[0][1].chain
    t.parent_fp, t.source_fp, t.path, t.depth, t.testnet = 1, 2, keys[0][2], 3, 1
    tp = c_text(lib.ut_xpub_text, ctypes.byref(t), b"zpub")  # testnet: vpub
    check(tp.startswith("vpub") and b58decode(tp)[:4] == bytes.fromhex("045f1cf6"), "testnet: vpub")
    h = c_out(lib.ut_hdkey_cbor, ctypes.byref(t), 1)
    check(bytes.fromhex("05d99d71a10201") in h, "testnet: use-info {network: 1}")

    print("%s: %d checks, %d failures" % ("ok" if not failures else "FAIL", checks, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
