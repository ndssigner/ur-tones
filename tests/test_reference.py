#!/usr/bin/env python3
"""Tests of the ur-tones reference implementation against vectors/ur-tones-v0.json:
URs and seeds to tones and back, error correction, and audio (rendered,
with noise, detuned, at several paces and sample rates) back to tones.

    python3 tests/test_reference.py
"""
import json
import pathlib
import random
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
sys.path.insert(0, str(ROOT / "tests"))
import ur_tones as st  # noqa: E402
import acoustic  # noqa: E402  (tests/acoustic.py)

VECTORS = json.loads((ROOT / "vectors" / "ur-tones-v0.json").read_text())["vectors"]
failures = 0
checks = 0


def check(ok, what):
    global failures, checks
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def raises(f, *args):
    try:
        f(*args)
    except st.DecodeError:
        return True
    return False


def substitute(frame, positions, rng):
    """The frame with other tones at those positions (after the lead-in and
    sync), never repeating a neighbour, as a receiver could mishear them."""
    tones = list(frame)
    for i in positions:
        i += 4
        tones[i] = rng.choice([k for k in st.KEYS if k not in (tones[i], tones[i - 1], (tones + [""])[i + 1])])
    return "".join(tones)


def noisy(samples, level, rng):
    return [x + rng.gauss(0, level) for x in samples]


def main():
    rng = random.Random(1)
    for v in VECTORS:
        name = "%s pin=%s" % (v["name"], v.get("pin"))
        if "entropy" in v:
            entropy, pin = bytes.fromhex(v["entropy"]), v["pin"]
            check(st.seed_to_keypad(entropy, pin) == v["keypad"], "keypad " + name)
            check(st.keypad_to_seed(v["keypad"], pin) == entropy, "keypad back " + name)
            check(st.seed_to_ur(entropy, pin) == v["ur"], "seed UR " + name)
            check(st.ur_to_seed(v["ur"], pin) == entropy, "seed UR back " + name)
            urs = [v["ur"]]
            # a mistyped digit: the BIP-39 checksum catches most (not all)
            if pin is None:
                caught = sum(raises(st.keypad_to_seed, v["keypad"][:i] + str((int(v["keypad"][i]) + 1) % 10)
                                    + v["keypad"][i + 1:]) for i in range(1, len(v["keypad"]) - 1))
                check(caught >= 0.8 * (len(v["keypad"]) - 2), "keypad checksum %s: %d" % (name, caught))
        else:
            urs = v["urs"]
        for ur, frame in zip(urs, v["frames"]):
            check(st.ur_to_frame(ur) == frame, "frame " + name)
            check(st.frame_to_ur(frame) == (ur, 0), "frame back " + name)
            n = len(frame) - 4
            # any one misheard tone is repaired; two, almost always
            check(all(st.frame_to_ur(substitute(frame, [i], rng))[0] == ur for i in range(n)),
                  "every single misheard tone repaired " + name)
            two = sum(1 for _ in range(20) if not raises(st.frame_to_ur, f2 := substitute(frame, rng.sample(range(n), 2), rng))
                      and st.frame_to_ur(f2)[0] == ur)
            check(two >= 18, "two misheard tones repaired %d/20 %s" % (two, name))
            # one lost or one extra tone anywhere is repaired; the lead-in may be lost
            for i in rng.sample(range(4, len(frame)), 5):
                check(st.frame_to_ur(frame[:i] + frame[i + 1:])[0] == ur, "lost tone %d %s" % (i, name))
                extra = rng.choice([k for k in st.KEYS if k not in (frame[i - 1], frame[i])])
                check(st.frame_to_ur(frame[:i] + extra + frame[i:])[0] == ur, "extra tone %d %s" % (i, name))
            check(st.frame_to_ur(frame[2:])[0] == ur and st.frame_to_ur(frame[3:])[0] == ur, "lead-in lost " + name)
            # two lost tones: discarded, never misread
            bad = frame[:10] + frame[11:30] + frame[31:]
            check(raises(st.frame_to_ur, bad) or st.frame_to_ur(bad)[0] == ur, "two lost tones not misread " + name)

    # audio: a keypad seed, a seed frame and a PSBT frame, in one recording
    seed = next(v for v in VECTORS if v.get("pin") is None and "keypad" in v)
    psbt = next(v for v in VECTORS if "psbt_base64" in v)
    groups = [seed["keypad"], seed["frames"][0], psbt["frames"][0]]
    expect = [("seed", bytes.fromhex(seed["entropy"])), ("ur", seed["ur"]), ("ur", psbt["urs"][0])]
    channels = [  # (rate, tone ms, gap ms, detune, channel)
        (8000, 40, 20, 1.0, dict(speaker_fc=50, rt60=0, noise=0.003, fade=0)),           # cable, fast
        (16000, 50, 50, 1.015, dict(speaker_fc=50, rt60=0, noise=0.01, fade=0)),
        (8000, 80, 80, 0.985, dict(speaker_fc=600, rt60=0.3, wet=0.4, noise=0.005)),     # quiet room
        (44100, 80, 80, 1.0, dict(speaker_fc=900, rt60=0.4, wet=0.6, noise=0.04)),       # noisy room
    ]
    for rate, tone, gap, detune, ch in channels:
        if rate > 16000 and "--fast" in sys.argv:
            continue
        audio = acoustic.channel(st.render(groups, rate, tone, gap, detune=detune), rate, rng, **ch)
        got = st.receive(audio, rate)
        check([g[:2] for g in got] == expect, "audio %d Hz %d/%d ms detune %.3f %s: %s"
              % (rate, tone, gap, detune, ch, [g[:2] for g in got]))
    # data frames through a very echoey room still arrive (keypad mode does not: see SPEC §3)
    audio = acoustic.channel(st.render(groups[1:], 8000, 80, 80), 8000, rng, speaker_fc=900, rt60=0.6, wet=0.8, noise=0.01)
    check([g[:2] for g in st.receive(audio, 8000)] == expect[1:], "echoey room, data mode")

    # keypad mode keyed by a person: uneven tones and long pauses
    keys = seed["keypad"]
    audio = []
    for k in keys:
        audio += st.render([k], 8000, rng.randint(60, 250), 0, pause_ms=rng.randint(150, 1200))
    check(st.receive(audio, 8000) == [expect[0]], "keypad at a person's pace")

    # a WAV file round trip
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "seed.wav"
        st.write_wav(path, st.render([seed["frames"][0]], 44100), 44100)
        samples, rate = st.read_wav(path)
        check(st.receive(samples, rate) == [expect[1]], "WAV round trip")

    print("%s: %d vectors, %d checks, %d failures" % ("ok" if not failures else "FAIL",
                                                      len(VECTORS), checks, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
