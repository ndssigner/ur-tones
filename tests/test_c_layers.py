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
    arr = (ctypes.c_int16 * max(1, len(pcm)))(*pcm)
    for i in range(0, len(pcm), chunk):
        part = ctypes.cast(ctypes.byref(arr, 2 * i), ctypes.POINTER(ctypes.c_int16))
        lib.ut_listener_push(l, part, min(chunk, len(pcm) - i))
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


# ---- no mutable global state ------------------------------------------------

def writable_symbols():
    """Symbols the library's object file keeps in writable memory."""
    obj = ROOT / "build" / "ur_tones.o"
    subprocess.run([*CFLAGS, "-c", str(ROOT / "c" / "ur_tones.c"), "-o", str(obj)], check=True)
    if sys.platform == "darwin":
        out = subprocess.run(["nm", "-m", str(obj)], capture_output=True, text=True, check=True).stdout
        return [l for l in out.splitlines() if any(s in l for s in ("(__DATA,__data)", "(__DATA,__bss)", "(__DATA,__common)"))]
    out = subprocess.run(["nm", str(obj)], capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines() if len(l.split()) >= 2 and l.split()[-2] in "bBdDC"]


def test_globals():
    found = writable_symbols()
    check(not found, "no writable globals: %s" % found)
    sys.path.insert(0, str(ROOT / "tools"))
    import gen_tables
    exp, log = gen_tables.tables()
    src = (ROOT / "c" / "ur_tones.c").read_text()
    check(gen_tables.c_array("EXP", exp) + gen_tables.c_array("LOG", log) in src, "Reed-Solomon tables as generated")


# ---- unsigned char (ARM's default) -------------------------------------------

def test_unsigned_char():
    lib = build("ut_uchar", "-funsigned-char")
    check(frames_round_trip(lib), "unsigned char: frames round trip")
    check(seeds_round_trip(lib), "unsigned char: keypad and seed URs")


def test_int32_results():
    """Results that are lengths or errors are int32_t: 16-bit ints can't hold a big PSBT's."""
    h = (ROOT / "c" / "ur_tones.h").read_text()
    import re
    bad = re.findall(r"^int (ut_\w+)\(", h, re.M)
    check(not bad, "int32_t results, not int: %s" % bad)


# ---- layer 1: the detector -----------------------------------------------------

class Det(ctypes.Structure):
    _fields_ = [("key", ctypes.c_char), ("level", ctypes.c_int16)]


def declare_detector(lib):
    lib.ut_detector_init.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    lib.ut_detector_push.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int16), c_size_t,
                                     ctypes.POINTER(c_size_t), ctypes.POINTER(Det), c_size_t]
    lib.ut_detector_push.restype = c_size_t
    lib.ut_detector_tick.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    lib.ut_classify.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_uint64, ctypes.c_uint32,
                                ctypes.c_char_p, ctypes.POINTER(ctypes.c_int16)]


def goertzel_powers(x, rate):
    """The eight |X|^2 with the C library's integer recurrence (cos in Q15)."""
    import math
    out = []
    for f in st.LOW + st.HIGH:
        c = round(math.cos(2 * math.pi * f / rate) * 32768)
        s1 = s2 = 0
        for v in x:
            s1, s2 = v + ((2 * c * s1) >> 15) - s2, s1
        out.append(s1 * s1 + s2 * s2 - ((2 * c * s1) >> 15) * s2)
    return out


def tone(f1, a1, f2, a2, rate=8000, n=200):
    import math
    return [round(a1 * math.sin(2 * math.pi * f1 * i / rate) + a2 * math.sin(2 * math.pi * f2 * i / rate)) for i in range(n)]


def classify(lib, x):
    p = (ctypes.c_int64 * 8)(*goertzel_powers(x, 8000))
    key, level = ctypes.create_string_buffer(1), ctypes.c_int16(0)
    lib.ut_classify(p, sum(v * v for v in x), len(x), key, ctypes.byref(level))
    return key.raw[:1].replace(b"\0", b""), level.value


def test_detector():
    lib = build("ut_layers")
    declare_detector(lib)
    d = ctypes.create_string_buffer(STRUCT)
    num, den = ctypes.c_uint32(), ctypes.c_uint32()
    for rate, want in ((8000, (80, 8000)), (11025, (110, 11025)), (16000, (160, 16000)),
                       (44100, (440, 44100)), (48000, (480, 48000)), (96000, (960, 96000))):
        lib.ut_detector_init(d, rate)
        lib.ut_detector_tick(d, ctypes.byref(num), ctypes.byref(den))
        check((num.value, den.value) == want, "tick at %d Hz: %s" % (rate, (num.value, den.value)))
    check(classify(lib, tone(770, 8000, 1336, 10000))[0] == b"5", "classify: key 5")
    check(classify(lib, tone(770, 8, 1336, 10)) == (b"", -990), "classify: too quiet")
    check(classify(lib, tone(770, 8000, 1336, 0))[0] == b"", "classify: low tone alone")
    check(classify(lib, tone(770, 8000, 1336, 450))[0] == b"", "classify: 25 dB twist")
    two_low = [a + b for a, b in zip(tone(697, 6000, 1336, 9000), tone(770, 6000, 1336, 0))]
    check(classify(lib, two_low)[0] == b"", "classify: two low tones")
    # the detector, in pieces: as many detections as windows, keys where the tones are
    frame = some_frames(1)[0]
    pcm = render(lib, [frame], 8000)
    lib.ut_detector_init(d, 8000)
    dets, used, out = [], c_size_t(), (Det * 4)()
    arr = (ctypes.c_int16 * len(pcm))(*pcm)
    i = 0
    while i < len(pcm):
        m = min(1000, len(pcm) - i)
        at = ctypes.cast(ctypes.byref(arr, 2 * i), ctypes.POINTER(ctypes.c_int16))
        k = lib.ut_detector_push(d, at, m, ctypes.byref(used), out, 4)
        dets += [out[j].key.decode() if out[j].key != b"\0" else "" for j in range(k)]
        i += used.value
    check(len(dets) == (len(pcm) - 200) // 80 + 1, "one detection per hop: %d" % len(dets))
    heard = "".join(k for i, k in enumerate(dets) if k and (i == 0 or dets[i - 1] != k))
    check(heard == frame, "detections follow the frame's keys")


# ---- layer 2: keys, from detections ---------------------------------------------

def build_old():
    """The library as it was before the layers (commit 148c6f7): the oracle."""
    old = ROOT / "build" / "old"
    old.mkdir(parents=True, exist_ok=True)
    for f in ("ur_tones.c", "ur_tones.h"):
        (old / f).write_bytes(subprocess.run(["git", "show", "148c6f7:c/" + f], cwd=ROOT, capture_output=True,
                                             check=True).stdout)
    return build("ut_old", src=old / "ur_tones.c")


def declare_keys(lib):
    lib.ut_keys_init.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
    lib.ut_keys_detection.argtypes = [ctypes.c_void_p, ctypes.c_char, ctypes.c_int16]
    lib.ut_keys_flush.argtypes = [ctypes.c_void_p]
    lib.ut_keys_group.argtypes = [ctypes.c_void_p, c_char_p, c_size_t]
    lib.ut_keys_live.argtypes = [ctypes.c_void_p, c_char_p, c_size_t]


def take_groups(lib, k):
    out, groups = ctypes.create_string_buffer(700), []
    while lib.ut_keys_group(k, out, 700) > 0:
        groups.append(out.value.decode())
    return groups


def py_groups(tones, hop_ms):
    """Groups from (key, start, end) tones, as the reference's listen() makes them."""
    groups, current, last_end = [], "", None

    def keypad():
        return current[:1] == "*" and (len(current) == 1 or current[1:].isdigit())

    def close():
        g = current
        if not keypad() and not g.startswith("*"):
            g = "".join(k for i, k in enumerate(g) if i == 0 or k != g[i - 1])
        groups.append(g)

    for key, start, end in tones:
        if current and last_end is not None and (start - last_end) * hop_ms > 225 and not keypad():
            close()
            current = ""
        if keypad() and key not in "0123456789#":
            close()
            current = ""
        current += key
        last_end = end
        if current[:1] == "*" and key == "#" and current[1:-1].isdigit():
            close()
            current = ""
    if current:
        close()
    return groups


def random_detections(rng, n):
    """Keys with flicker, glitches, dips and echoes, and no silence of 300 ms."""
    out = []
    while len(out) < n:
        key = rng.choice(list(st.KEYS) + [None] * 4)
        run = rng.randint(1, 12)
        level = rng.randint(-40, -10)
        for i in range(run):
            if key is not None and rng.random() < 0.15:
                level -= rng.choice((3, 9, 12))        # a dip, or an echo's weaker tail
            elif key is not None and rng.random() < 0.1:
                level += rng.choice((7, 9))            # pressed again
            out.append((key, level) if key is not None else (None, -99))
        if key is None and run > 25:
            out = out[:-(run - 25)]
    return out[:n]


def test_keys_from_detections():
    import random
    lib = build("ut_layers")
    declare_keys(lib)
    old = build_old()
    # the segmenter and grouper against the reference, detection by detection
    rng = random.Random(7)
    k = ctypes.create_string_buffer(STRUCT)
    bad = 0
    for trial in range(200):
        dets = random_detections(rng, rng.randint(20, 400))
        lib.ut_keys_init(k, 80, 8000)
        groups = []
        for key, level in dets:
            lib.ut_keys_detection(k, (key or "\0").encode(), 10 * level)
            groups += take_groups(lib, k)
        lib.ut_keys_flush(k)
        groups += take_groups(lib, k)
        want = py_groups(st.segment([(key, float(level)) for key, level in dets]), 10.0)
        bad += groups != want
    check(not bad, "segmenter and grouper = the reference's (%d of 200 differ)" % bad)
    # the same groups as before, through the whole receiver, at many rates, through a room
    import acoustic
    vec_frames, seeds = some_frames(2), [v["keypad"] for v in VECTORS if "keypad" in v][:2]
    for rate in (8000, 11025, 22050, 44100, 48000, 96000):
        for seed in range(2):
            r = random.Random(rate + seed)
            groups = [r.choice(vec_frames)[:r.randint(40, 120)], r.choice(seeds),
                      "".join(r.choice(st.KEYS) for _ in range(r.randint(5, 40)))]
            pcm = render(lib, groups, rate, 80, 80, 600)
            room = acoustic.channel([v / 32768 for v in pcm], rate, r, speaker_fc=600, rt60=0.4, wet=0.6, noise=0.02)
            pcm = [max(-32767, min(32767, round(v * 32767))) for v in room]
            check(listen(lib, pcm, rate) == listen(old, pcm, rate), "same groups as before at %d Hz (%d)" % (rate, seed))
    # chunking changes nothing
    pcm = render(lib, some_frames(1), 8000)[:40000]
    whole = listen(lib, pcm, 8000, 4096)
    check(listen(lib, pcm, 8000, 1) == whole and listen(lib, pcm, 8000, 7) == whole, "chunks of 1, 7, 4096 samples")
    # a long group, no silence: one group, truncated at UT_GROUP (600)
    keys = "".join("0123456789"[i % 10] for i in range(1700))
    heard = listen(lib, render(lib, [keys], 8000, 40, 20, 400), 8000, 4096)
    check(heard == [keys[:600]], "100 s without a silence: one group of 600 tones (%s)" % [len(g) for g in heard])
    # the listener's size
    exe = ROOT / "build" / "sizes"
    subprocess.run(["cc", "-std=c99", "-I", str(ROOT / "c"), str(ROOT / "tests" / "c" / "sizes.c"), "-o", str(exe)], check=True)
    sizes = dict(l.split() for l in subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout.splitlines())
    check(int(sizes["ut_listener"]) < 6144, "ut_listener under 6 KB: %s" % sizes["ut_listener"])


# ---- layer 2: keys, from tone events (decoder chips) --------------------------------

def events(lib, tones, start=0, close=True):
    """Groups from (key, start ms, end ms) tones, as a decoder chip gives them."""
    k = ctypes.create_string_buffer(STRUCT)
    lib.ut_keys_init(k, 1, 1000)
    groups = []
    for key, a, b in tones:
        lib.ut_keys_tone(k, key.encode(), (start + a) & 0xFFFFFFFF, (start + b) & 0xFFFFFFFF)
        groups += take_groups(lib, k)
    if close:
        lib.ut_keys_time(k, (start + tones[-1][2] + 301) & 0xFFFFFFFF)
        groups += take_groups(lib, k)
    return groups, k


def played(keys, tone=40, gap=20, at=0):
    out = []
    for key in keys:
        out.append((key, at, at + tone))
        at += tone + gap
    return out


def test_tone_events():
    lib = build("ut_layers")
    declare_keys(lib)
    lib.ut_keys_tone.argtypes = [ctypes.c_void_p, ctypes.c_char, ctypes.c_uint32, ctypes.c_uint32]
    lib.ut_keys_time.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    check(events(lib, [("1", 0, 80), ("2", 304, 384)])[0] == ["12"], "224 ms apart: one group")
    check(events(lib, [("1", 0, 80), ("2", 306, 386)])[0] == ["1", "2"], "226 ms apart: two groups")
    groups, k = events(lib, [("5", 1000, 1080)], close=False)
    lib.ut_keys_time(k, 1080 + 299)
    check(take_groups(lib, k) == [], "299 ms of silence: still open")
    lib.ut_keys_time(k, 1080 + 301)
    check(take_groups(lib, k) == ["5"], "301 ms of silence: closed")
    seed = next(v["keypad"] for v in VECTORS if "keypad" in v)
    slow = [(key, 1000 * i, 1000 * i + 100) for i, key in enumerate(seed)]
    groups, k = events(lib, slow, close=False)
    for t in range(0, 1000 * len(seed), 250):
        lib.ut_keys_time(k, t)
        groups += take_groups(lib, k)
    check(groups == [seed], "keypad mode, a key a second: one group")
    check(events(lib, played("AAB"))[0] == ["AB"], "data: a repeat is an echo")
    _, k = events(lib, played("12A"), close=False)
    live = ctypes.create_string_buffer(64)
    lib.ut_keys_live(k, live, 64)
    check(live.value == b"12A", "live keys from tones")
    check(events(lib, played("123", 80, 80), start=0xFFFFFF00)[0] == ["123"], "the clock wraps mid-group")
    check(events(lib, played("1") + played("2", at=500), start=0xFFFFFF00)[0] == ["1", "2"], "the clock wraps mid-pause")
    out, ok = ctypes.create_string_buffer(1200), True
    for v in VECTORS:
        for ur, frame in zip(v.get("urs", [v.get("ur")]), v["frames"]):
            groups, _ = events(lib, played(frame))
            fixed = c_int()
            ok &= len(groups) == 1 and lib.ut_frame_to_ur(groups[0].encode(), out, 1200, ctypes.byref(fixed)) > 0 \
                and out.value.decode() == ur
    check(ok, "every vector frame from a decoder chip")


# ---- layer 2: the player (generator chips) --------------------------------------------

class Timing(ctypes.Structure):
    _fields_ = [("tone_ms", ctypes.c_uint16), ("gap_ms", ctypes.c_uint16), ("pause_ms", ctypes.c_uint16)]


def test_player():
    lib = build("ut_layers")
    lib.ut_player_init.argtypes = [ctypes.c_void_p, c_char_p, ctypes.POINTER(Timing)]
    lib.ut_player_next.argtypes = [ctypes.c_void_p, c_char_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    p, keep = ctypes.create_string_buffer(STRUCT), ctypes.create_string_buffer(b"CBAD1")
    lib.ut_player_init(p, keep, ctypes.byref(Timing(40, 20, 400)))
    steps, key, on, off = [], ctypes.create_string_buffer(1), ctypes.c_uint32(), ctypes.c_uint32()
    while lib.ut_player_next(p, key, ctypes.byref(on), ctypes.byref(off)):
        steps.append((key.raw.decode().strip("\0"), on.value, off.value))
    check(steps == [("", 0, 400)] + [(k, 40, 20) for k in "CBAD1"] + [("", 0, 400)], "player steps: %s" % steps)
    # the synthesiser plays the same spans (within 1 ms)
    pcm = render(lib, ["CBAD1"], 8000, 40, 20, 400)
    spans, i = [], 0
    while i < len(pcm):
        if pcm[i]:
            j = i
            while j < len(pcm) and any(pcm[j:j + 4]):
                j += 1
            spans.append((i, j))
            i = j
        i += 1
    t, want = 0, []
    for k, a, b in steps:
        if k:
            want.append((t + 0, t + 8 * a))
        t += 8 * (a + b)
    check(len(spans) == len(want) and all(abs(s[0] - w[0]) <= 8 and abs(s[1] - w[1]) <= 8 for s, w in zip(spans, want)),
          "synth and player agree: %s vs %s" % (spans[:3], want[:3]))


def main():
    test_config()
    test_globals()
    test_unsigned_char()
    test_int32_results()
    test_detector()
    test_keys_from_detections()
    test_tone_events()
    test_player()
    print("%s: %d checks, %d failures" % ("ok" if not failures else "FAIL", checks, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
