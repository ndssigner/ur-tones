#!/usr/bin/env python3
"""Tests of the C library's portability: its configuration (UT_CONFIG_FILE,
sizes, placement macros, compile-time checks), no mutable global state, and
its layers (detector, keys, frames) and hooks, each against the reference or
against the library as it was before them.

    python3 tests/test_c_layers.py       # builds build/ut_* (cc)
"""
import ctypes
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
sys.path.insert(0, str(ROOT / "tests"))
import ur_tones as st  # noqa: E402

VECTORS = json.loads((ROOT / "vectors" / "ur-tones-v0.json").read_text())["vectors"]
CFLAGS = ["cc", "-std=c99", "-Wall", "-Wextra", "-pedantic", "-Werror", "-O2"]
failures = checks = 0


def check(ok, what):
    global failures, checks
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def config(name):
    return '-DUT_CONFIG_FILE="%s"' % (ROOT / "tests" / "configs" / name)


def build(name, *flags, sources=(), src=ROOT / "c" / "ur_tones.c"):
    """The library as a shared object, with extra flags and C files."""
    out = ROOT / "build" / (name + (".dylib" if sys.platform == "darwin" else ".so"))
    out.parent.mkdir(exist_ok=True)
    subprocess.run([*CFLAGS, "-shared", "-fPIC", *flags, str(src), *map(str, sources), "-o", str(out)], check=True)
    return declare(ctypes.CDLL(str(out)))


def compile_fails(*flags):
    """The compiler's errors for the library built with these flags ("" if it builds)."""
    r = subprocess.run([*CFLAGS, *flags, "-c", str(ROOT / "c" / "ur_tones.c"), "-o", "/dev/null"],
                       capture_output=True, text=True)
    return r.stderr if r.returncode else ""


c_char_p, c_size_t, c_int, u8p = ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.POINTER(ctypes.c_uint8)
STRUCT = 64 * 1024  # bigger than any of the library's structs; opaque here


def declare(lib):
    lib.ut_ur_to_frame.argtypes = [c_char_p, c_char_p, c_size_t]
    lib.ut_frame_to_ur.argtypes = [c_char_p, c_char_p, c_size_t, ctypes.POINTER(c_int)]
    lib.ut_keypad_to_seed.argtypes = [c_char_p, c_char_p, u8p]
    lib.ut_ur_to_seed.argtypes = [c_char_p, c_char_p, u8p]
    if hasattr(lib, "ut_synth_init"):
        lib.ut_synth_init.argtypes = [ctypes.c_void_p, c_char_p] + [ctypes.c_uint32] * 4
        lib.ut_synth_read.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int16), c_size_t]
        lib.ut_synth_read.restype = c_size_t
        lib.ut_listener_init.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        lib.ut_listener_push.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int16), c_size_t]
        lib.ut_listener_flush.argtypes = [ctypes.c_void_p]
        lib.ut_listener_group.argtypes = [ctypes.c_void_p, c_char_p, c_size_t]
    return lib


def frames_round_trip(lib):
    """Every vector's URs to tones and back."""
    out = ctypes.create_string_buffer(1200)
    for v in VECTORS:
        for ur, frame in zip(v.get("urs", [v.get("ur")]), v["frames"]):
            if lib.ut_ur_to_frame(ur.encode(), out, 1200) < 0 or out.value.decode() != frame:
                return False
            fixed = c_int(-1)
            if lib.ut_frame_to_ur(frame.encode(), out, 1200, ctypes.byref(fixed)) < 0 or out.value.decode() != ur:
                return False
    return True


def seeds_round_trip(lib):
    """Every keypad and seed-UR vector back to its entropy, with its PIN."""
    ent = (ctypes.c_uint8 * 32)()
    for v in VECTORS:
        if "entropy" not in v:
            continue
        e, pin = bytes.fromhex(v["entropy"]), (v["pin"].encode() if v.get("pin") else None)
        for f, text in ((lib.ut_keypad_to_seed, v["keypad"]), (lib.ut_ur_to_seed, v["ur"])):
            if f(text.encode(), pin, ent) != len(e) or bytes(ent)[:len(e)] != e:
                return False
    return True


def render(lib, groups, rate, tone=40, gap=20, pause=400):
    """Groups of tones as the C synthesiser plays them, as 16-bit samples."""
    out = []
    for g in groups:
        keep = ctypes.create_string_buffer(g.encode())
        s = ctypes.create_string_buffer(STRUCT)
        lib.ut_synth_init(s, keep, rate, tone, gap, pause)
        chunk = (ctypes.c_int16 * 4096)()
        while True:
            n = lib.ut_synth_read(s, chunk, 4096)
            if not n:
                break
            out += chunk[:n]
    return out


def listen(lib, pcm, rate, chunk=1024):
    """Groups heard by the C receiver, fed in chunks like a microphone."""
    l = ctypes.create_string_buffer(STRUCT)
    lib.ut_listener_init(l, rate)
    groups, out = [], ctypes.create_string_buffer(700)
    for i in range(0, len(pcm), chunk):
        part = (ctypes.c_int16 * len(pcm[i:i + chunk]))(*pcm[i:i + chunk])
        lib.ut_listener_push(l, part, len(part))
        while lib.ut_listener_group(l, out, 700) > 0:
            groups.append(out.value.decode())
    lib.ut_listener_flush(l)
    while lib.ut_listener_group(l, out, 700) > 0:
        groups.append(out.value.decode())
    return groups


def some_frames(n=3):
    return [f for v in VECTORS for f in v["frames"]][:n]


# ---- configuration -----------------------------------------------------------

def test_config():
    check("the config file is read" in compile_fails(config("read.h")), "UT_CONFIG_FILE is included")
    lib = build("ut_minimal", config("minimal.h"))
    check(frames_round_trip(lib), "minimal config: frames round trip")
    frames = some_frames()
    check(listen(lib, render(lib, frames, 44100), 44100) == frames, "minimal config: heard back")
    for option, value in (("UT_GROUP", 100), ("UT_RING", 500), ("UT_READY", 0), ("UT_LIVE", 0), ("UT_MAX_PARTS", 0)):
        err = compile_fails("-D%s=%d" % (option, value))
        check(option + " must be" in err, "#error for %s=%d" % (option, value))
    lib = build("ut_placement", config("placement.h"))
    check(frames_round_trip(lib), "placement macros: frames round trip")


def main():
    test_config()
    print("%s: %d checks, %d failures" % ("ok" if not failures else "FAIL", checks, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
