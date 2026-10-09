#!/usr/bin/env python3
"""Tests of the C library (c/ur_tones.c) against the test vectors and the
Python reference: frames both ways, repairs, keypad, seed URs, the PIN,
SHA-256, PBKDF2, CRC-32, and audio — C synthesis heard by the Python
receiver, Python synthesis heard by the C receiver, and C to C, through the
simulated acoustic channel (tests/acoustic.py).

    python3 tests/test_c.py              # builds build/libur_tones (cc)
"""
import ctypes
import hashlib
import json
import pathlib
import random
import subprocess
import sys
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
sys.path.insert(0, str(ROOT / "tests"))
import ur_tones as st  # noqa: E402
import acoustic  # noqa: E402

VECTORS = json.loads((ROOT / "vectors" / "ur-tones-v0.json").read_text())["vectors"]
failures = checks = 0


def check(ok, what):
    global failures, checks
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def build():
    out = ROOT / "build" / ("libur_tones" + (".dylib" if sys.platform == "darwin" else ".so"))
    out.parent.mkdir(exist_ok=True)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-pedantic", "-Werror", "-O2", "-shared", "-fPIC",
                    str(ROOT / "c" / "ur_tones.c"), "-o", str(out)], check=True)
    return ctypes.CDLL(str(out))


lib = build()
c_char_p, c_size_t, c_int = ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int
u8p = ctypes.POINTER(ctypes.c_uint8)
lib.ut_ur_to_frame.argtypes = [c_char_p, c_char_p, c_size_t]
lib.ut_frame_to_ur.argtypes = [c_char_p, c_char_p, c_size_t, ctypes.POINTER(c_int)]
lib.ut_seed_to_keypad.argtypes = [u8p, c_size_t, c_char_p, c_char_p, c_size_t]
lib.ut_keypad_to_seed.argtypes = [c_char_p, c_char_p, u8p]
lib.ut_seed_to_ur.argtypes = [u8p, c_size_t, c_char_p, c_char_p, c_size_t]
lib.ut_ur_to_seed.argtypes = [c_char_p, c_char_p, u8p]
lib.ut_sha256.argtypes = [u8p, c_size_t, u8p]
lib.ut_pbkdf2_sha256.argtypes = [u8p, c_size_t, u8p, c_size_t, ctypes.c_uint32, u8p, c_size_t]
lib.ut_crc32.argtypes = [u8p, c_size_t]
lib.ut_crc32.restype = ctypes.c_uint32


def buf(data):
    return (ctypes.c_uint8 * max(1, len(data))).from_buffer_copy(data or b"\0")


def to_frame(ur):
    out = ctypes.create_string_buffer(1200)
    n = lib.ut_ur_to_frame(ur.encode(), out, 1200)
    return out.value.decode() if n >= 0 else n


def from_frame(tones):
    out, fixed = ctypes.create_string_buffer(1200), c_int(-1)
    n = lib.ut_frame_to_ur(tones.encode(), out, 1200, ctypes.byref(fixed))
    return (out.value.decode(), fixed.value) if n >= 0 else n


def pin_arg(pin):
    return pin.encode() if pin else None


# ---- the C library's audio, through ctypes structs ---------------------------

class Synth(ctypes.Structure):
    _fields_ = [("tones", c_char_p), ("count", c_size_t), ("index", c_size_t)] + \
               [(n, ctypes.c_uint32) for n in ("rate", "tone_n", "gap_n", "pause_n", "ramp", "pos")] + \
               [("stage", c_int)] + [(n, ctypes.c_uint32) for n in ("ph1", "ph2", "inc1", "inc2")]


LISTENER_SIZE = 64 * 1024  # bigger than sizeof(ut_listener); opaque here
lib.ut_synth_init.argtypes = [ctypes.POINTER(Synth), c_char_p] + [ctypes.c_uint32] * 4
lib.ut_synth_read.argtypes = [ctypes.POINTER(Synth), ctypes.POINTER(ctypes.c_int16), c_size_t]
lib.ut_synth_read.restype = c_size_t
lib.ut_listener_init.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
lib.ut_listener_push.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int16), c_size_t]
lib.ut_listener_flush.argtypes = [ctypes.c_void_p]
lib.ut_listener_group.argtypes = [ctypes.c_void_p, c_char_p, c_size_t]


def c_render(groups, rate, tone, gap, pause=400):
    """Groups of tones as the C synthesiser plays them, one after another."""
    out = []
    for g in groups:
        keep = ctypes.create_string_buffer(g.encode())
        s = Synth()
        lib.ut_synth_init(ctypes.byref(s), keep, rate, tone, gap, pause)
        chunk = (ctypes.c_int16 * 4096)()
        while True:
            n = lib.ut_synth_read(ctypes.byref(s), chunk, 4096)
            if not n:
                break
            out += [v / 32768 for v in chunk[:n]]
    return out


def c_listen(samples, rate):
    """Groups heard by the C receiver, fed in chunks like a microphone."""
    l = ctypes.create_string_buffer(LISTENER_SIZE)
    lib.ut_listener_init(l, rate)
    pcm = [max(-32767, min(32767, round(x * 32767))) for x in samples]
    groups, out = [], ctypes.create_string_buffer(700)
    for i in range(0, len(pcm), 1024):
        part = (ctypes.c_int16 * len(pcm[i:i + 1024]))(*pcm[i:i + 1024])
        lib.ut_listener_push(l, part, len(pcm[i:i + 1024]))
        while lib.ut_listener_group(l, out, 700) > 0:
            groups.append(out.value.decode())
    lib.ut_listener_flush(l)
    while lib.ut_listener_group(l, out, 700) > 0:
        groups.append(out.value.decode())
    return groups


def decode(group, pin=None):
    if group.startswith("*"):
        try:
            return st.keypad_to_seed(group, pin).hex()
        except st.DecodeError:
            return "error"
    r = from_frame(group)
    return r[0] if isinstance(r, tuple) else "error"


def main():
    rng = random.Random(5)
    # building blocks
    for n in (0, 1, 55, 56, 63, 64, 65, 200):
        data = bytes((i * 7 + 3) & 255 for i in range(n))
        out = buf(bytes(32))
        lib.ut_sha256(buf(data), n, out)
        check(bytes(out) == hashlib.sha256(data).digest(), "sha256 %d" % n)
        check(lib.ut_crc32(buf(data), n) == zlib.crc32(data), "crc32 %d" % n)
    out = buf(bytes(32))
    lib.ut_pbkdf2_sha256(buf(b"ABC12345"), 8, buf(st.PIN_SALT), len(st.PIN_SALT), 10000, out, 32)
    check(bytes(out) == hashlib.pbkdf2_hmac("sha256", b"ABC12345", st.PIN_SALT, 10000, 32), "pbkdf2")

    for v in VECTORS:
        name = "%s pin=%s" % (v["name"], v.get("pin"))
        if "entropy" in v:
            e, pin = bytes.fromhex(v["entropy"]), v["pin"]
            out = ctypes.create_string_buffer(200)
            check(lib.ut_seed_to_keypad(buf(e), len(e), pin_arg(pin), out, 200) > 0 and out.value.decode() == v["keypad"], "keypad " + name)
            ent = buf(bytes(32))
            n = lib.ut_keypad_to_seed(v["keypad"].encode(), pin_arg(pin), ent)
            check(n == len(e) and bytes(ent)[:n] == e, "keypad back " + name)
            check(lib.ut_seed_to_ur(buf(e), len(e), pin_arg(pin), out, 200) > 0 and out.value.decode() == v["ur"], "seed UR " + name)
            n = lib.ut_ur_to_seed(v["ur"].encode(), pin_arg(pin), ent)
            check(n == len(e) and bytes(ent)[:n] == e, "seed UR back " + name)
            check(lib.ut_ur_to_seed(v["ur"].upper().encode(), pin_arg(pin), ent) == len(e), "seed UR in capitals " + name)
        for ur, frame in zip(v.get("urs", [v.get("ur")]), v["frames"]):
            check(to_frame(ur) == frame, "frame " + name)
            check(from_frame(frame) == (ur, 0), "frame back " + name)
            n = len(frame) - 4
            # misheard tones (as the Python tests), a lost and an extra tone, the lead-in lost
            for wrong in (1, 2, 4):
                bad = list(frame)
                for i in rng.sample(range(n), wrong):
                    i += 4
                    bad[i] = rng.choice([k for k in st.KEYS if k not in (bad[i], bad[i - 1], (bad + [""])[i + 1])])
                got = from_frame("".join(bad))
                check(got == st.frame_to_ur("".join(bad)) if wrong < 4 else isinstance(got, tuple) == isinstance(
                    _py(lambda: st.frame_to_ur("".join(bad))), tuple), "%d misheard: C = Python %s" % (wrong, name))
            i = rng.randrange(4, len(frame))
            check(from_frame(frame[:i] + frame[i + 1:])[0] == ur, "lost tone " + name)
            extra = next(k for k in st.KEYS if k not in (frame[i - 1], frame[i]))
            check(from_frame(frame[:i] + extra + frame[i:])[0] == ur, "extra tone " + name)
            check(from_frame(frame[2:])[0] == ur and from_frame(frame[3:])[0] == ur, "lead-in lost " + name)
    check(lib.ut_seed_to_keypad(buf(bytes(16)), 16, b"no-pin!", ctypes.create_string_buffer(200), 200) == -8, "bad PIN refused")

    # audio
    seed = next(v for v in VECTORS if v.get("pin") is None and "keypad" in v)
    pinned = next(v for v in VECTORS if v.get("pin") and "keypad" in v)
    psbt = next(v for v in VECTORS if "psbt_base64" in v)
    groups = [seed["keypad"], seed["frames"][0], pinned["frames"][0], psbt["frames"][0]]
    expect = [seed["entropy"], seed["ur"], pinned["ur"], psbt["urs"][0]]
    for rate, tone, gap, ch in [(8000, 40, 20, dict(speaker_fc=50, rt60=0, noise=0.003, fade=0)),
                                (16364, 80, 80, dict(speaker_fc=600, rt60=0.3, wet=0.4, noise=0.005)),
                                (48000, 80, 80, dict(speaker_fc=900, rt60=0.4, wet=0.6, noise=0.03))]:
        label = "%d Hz %d/%d %s" % (rate, tone, gap, ch)
        c_audio = acoustic.channel(c_render(groups, rate, tone, gap), rate, random.Random(rate), **ch)
        check([decode(g) for g in st.listen(c_audio, rate)] == expect, "C synthesis, Python ears: " + label)
        check([decode(g) for g in c_listen(c_audio, rate)] == expect, "C synthesis, C ears: " + label)
        py_audio = acoustic.channel(st.render(groups, rate, tone, gap), rate, random.Random(rate + 1), **ch)
        check([decode(g) for g in c_listen(py_audio, rate)] == expect, "Python synthesis, C ears: " + label)
    # keypad mode keyed by a person: uneven tones and long pauses
    audio = []
    for k in seed["keypad"]:
        audio += st.render([k], 8000, rng.randint(60, 250), 0, pause_ms=rng.randint(150, 1200))
    check([decode(g) for g in c_listen(audio, 8000)] == [seed["entropy"]], "keypad at a person's pace, C ears")

    print("%s: %d vectors, %d checks, %d failures" % ("ok" if not failures else "FAIL", len(VECTORS), checks, failures))
    sys.exit(1 if failures else 0)


def _py(f):
    try:
        return f()
    except st.DecodeError as e:
        return e


if __name__ == "__main__":
    main()
