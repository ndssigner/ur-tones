"""A simulated acoustic channel, to test receivers: a small speaker (low
tones attenuated), a room (Schroeder reverb), noise and slow fading."""
import math


def highpass(x, rate, fc):
    a = 1 / (1 + 2 * math.pi * fc / rate)
    y, px, py = [], 0.0, 0.0
    for v in x:
        py = a * (py + v - px)
        px = v
        y.append(py)
    return y


def comb(x, d, g):
    buf = [0.0] * d
    y, i = [], 0
    for v in x:
        out = buf[i]
        buf[i] = v + g * out
        i = (i + 1) % d
        y.append(out)
    return y


def allpass(x, d, g):
    buf = [0.0] * d
    y, i = [], 0
    for v in x:
        b = buf[i]
        out = -g * v + b
        buf[i] = v + g * out
        i = (i + 1) % d
        y.append(out)
    return y


def room(x, rate, rt60=0.4, wet=0.6):
    """Schroeder reverb: four combs in parallel, two allpasses in series."""
    acc = [0.0] * len(x)
    for ms in (29.7, 37.1, 41.1, 43.7):
        d = int(rate * ms / 1000)
        g = 10 ** (-3 * ms / 1000 / rt60)
        for i, v in enumerate(comb(x, d, g)):
            acc[i] += v / 4
    for ms, g in ((5.0, 0.7), (1.7, 0.7)):
        acc = allpass(acc, int(rate * ms / 1000), g)
    return [d + wet * w for d, w in zip(x, acc)]


def channel(x, rate, rng, speaker_fc=900.0, rt60=0.4, wet=0.6, noise=0.01, fade=0.3):
    y = highpass(highpass(x, rate, speaker_fc), rate, speaker_fc)
    if rt60:
        y = room(y, rate, rt60, wet)
    ph = rng.random() * 6.28
    return [v * (1 - fade / 2 + fade / 2 * math.sin(ph + 2 * math.pi * 0.7 * i / rate)) + rng.gauss(0, noise)
            for i, v in enumerate(y)]
