"""ur-tones, reference implementation (draft v0, SPEC.md).

Data mode: a UR (single-part, or one part of a multi-part UR) <-> a frame of
DTMF tones: Reed-Solomon codeword, written in base 15 as the step from one
tone to the next, so that no tone is ever followed by itself. Keypad mode: a
seed <-> its Standard SeedQR digits between * and #. Audio: tones <->
samples, with a Goertzel receiver (SPEC appendix A).

Standard library only, and MicroPython-friendly for the frames and seeds
(NDS-Signer runs them; its audio is in C). The bytewords word list is
Blockchain Commons' (BCR-2020-012), as in every UR implementation.
"""
import hashlib
import math
import struct

FORMAT_VERSION = 0
KEYS = "0123456789ABCD*#"  # nibble value -> key
LEAD = "CB"  # lead-in: lets the receiver settle; may be lost
SYNC = "AD"
PARITY = 16  # Reed-Solomon parity bytes per frame: repairs 8 wrong bytes
KIND_SINGLE, KIND_PART = 0, 1
UR_TYPES = ["", "crypto-psbt", "psbt", "crypto-seed", "seed", "crypto-account",
            "account-descriptor", "crypto-output", "output-descriptor", "bytes",
            "crypto-hdkey", "hdkey"]

LOW = (697, 770, 852, 941)
HIGH = (1209, 1336, 1477, 1633)
PAD = ("123A", "456B", "789C", "*0#D")  # [low][high] -> key
FREQS = {PAD[r][c]: (LOW[r], HIGH[c]) for r in range(4) for c in range(4)}


PIN_SALT = b"ur-tones/seed-pin/v0"
PIN_ITERATIONS = 10000


class DecodeError(ValueError):
    pass


# ---- PIN, for seeds only (SPEC §4) --------------------------------------

def normalize_pin(pin):
    """A PIN is letters A-Z and digits 0-9, case-insensitive (SPEC §4)."""
    pin = pin.upper()
    if not pin or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for ch in pin):
        raise ValueError("a PIN is letters A-Z and digits 0-9")
    return pin


def pin_xor(entropy, pin):
    """Entropy XOR PBKDF2-HMAC-SHA256(PIN). Its own inverse."""
    key = hashlib.pbkdf2_hmac("sha256", normalize_pin(pin).encode("ascii"), PIN_SALT,
                              PIN_ITERATIONS, len(entropy))
    return bytes(a ^ b for a, b in zip(entropy, key))


# ---- Reed-Solomon over GF(256), as in QR codes ------------------------

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _div(a, b):
    if b == 0:
        raise ZeroDivisionError
    return 0 if a == 0 else _EXP[(_LOG[a] + 255 - _LOG[b]) % 255]


def _poly_eval(p, x):
    """p[0] is the highest degree coefficient."""
    y = p[0]
    for c in p[1:]:
        y = _mul(y, x) ^ c
    return y


def rs_correct(codewords, nsym):
    """Corrects up to nsym // 2 wrong codewords (data + error correction).
    Returns (corrected codewords, number corrected)."""
    n = len(codewords)
    synd = [_poly_eval(codewords, _EXP[i]) for i in range(nsym)]
    if not any(synd):
        return list(codewords), 0
    # Berlekamp-Massey: error locator Lambda(x), lowest degree first
    lam, prev, L, m, b = [1], [1], 0, 1, 1
    for i in range(nsym):
        d = synd[i]
        for j in range(1, L + 1):
            d ^= _mul(lam[j], synd[i - j])
        if d == 0:
            m += 1
            continue
        coef = _div(d, b)
        shifted = [0] * m + [_mul(coef, c) for c in prev]
        new = [x ^ y for x, y in zip(lam + [0] * len(shifted), shifted + [0] * len(lam))]
        if 2 * L <= i:
            prev, L, b, m = lam, i + 1 - L, d, 1
        else:
            m += 1
        lam = new
    lam = lam[:L + 1]
    if L == 0 or 2 * L > nsym:
        raise DecodeError("too many errors to correct")
    # Chien search: position p (from the end, degree p) is wrong if
    # Lambda(alpha^-p) == 0
    positions = [p for p in range(n) if _poly_eval(lam[::-1], _EXP[(255 - p) % 255]) == 0]
    if len(positions) != L:
        raise DecodeError("too many errors to correct")
    # Forney: Omega(x) = S(x) Lambda(x) mod x^nsym
    omega = [0] * nsym
    for i, s in enumerate(synd):
        for j, l in enumerate(lam):
            if i + j < nsym:
                omega[i + j] ^= _mul(s, l)
    fixed = list(codewords)
    for p in positions:
        xinv = _EXP[(255 - p) % 255]
        num = 0
        for i, o in enumerate(omega):
            num ^= _mul(o, _EXP[(_LOG[xinv] * i) % 255] if xinv else 0)
        den = 0
        for j in range(1, len(lam), 2):  # formal derivative: odd terms
            den ^= _mul(lam[j], _EXP[(_LOG[xinv] * (j - 1)) % 255])
        # first consecutive root alpha^0: magnitude = X * Omega(X^-1) / Lambda'(X^-1)
        mag = _mul(_EXP[p % 255], _div(num, den))
        fixed[n - 1 - p] ^= mag
    if any(_poly_eval(fixed, _EXP[i]) for i in range(nsym)):
        raise DecodeError("too many errors to correct")
    return fixed, len(positions)


# ---- Reed-Solomon encoder (the code of rs_correct: QR codes' code) ----------

def _generator(nsym):
    """Product of (x - alpha^i), i = 0 .. nsym - 1; highest degree first."""
    g = [1]
    for i in range(nsym):
        g = [a ^ _mul(b, _EXP[i]) for a, b in zip(g + [0], [0] + g)]
    return g


def rs_encode(data, nsym=PARITY):
    """The parity bytes: remainder of data(x) * x^nsym divided by g(x)."""
    g = _generator(nsym)
    rem = list(data) + [0] * nsym
    for i in range(len(data)):
        coef = rem[i]
        if coef:
            for j in range(1, len(g)):
                rem[i + j] ^= _mul(g[j], coef)
    return bytes(rem[len(data):])


# ---- CRC-32 (as zlib's) -------------------------------------------------

_CRC = []
for _n in range(256):
    _c = _n
    for _k in range(8):
        _c = 0xEDB88320 ^ (_c >> 1) if _c & 1 else _c >> 1
    _CRC.append(_c)


def crc32(data):
    c = 0xFFFFFFFF
    for b in data:
        c = _CRC[(c ^ b) & 255] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


# ---- bytewords (minimal style: first and last letter of each word) ---------

BYTEWORDS = (
    "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebody"
    "bragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyan"
    "darkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepic"
    "evenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuel"
    "fundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawk"
    "heathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjade"
    "jazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwi"
    "knoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmany"
    "mathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobey"
    "oboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquad"
    "quizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilk"
    "skewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoys"
    "triptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswall"
    "wandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszero"
    "zestzinczonezoom")
_MINIMAL = [BYTEWORDS[4 * i] + BYTEWORDS[4 * i + 3] for i in range(256)]
_FROM_MINIMAL = {w: i for i, w in enumerate(_MINIMAL)}


def bytewords_minimal(data):
    """data + its CRC-32, in minimal bytewords (as in a UR's text)."""
    data = bytes(data) + struct.pack(">I", crc32(data))
    return "".join(_MINIMAL[b] for b in data)


def from_bytewords_minimal(text):
    if len(text) % 2:
        raise DecodeError("bytewords: odd length")
    try:
        data = bytes(_FROM_MINIMAL[text[i:i + 2]] for i in range(0, len(text), 2))
    except KeyError:
        raise DecodeError("bytewords: not a word")
    if len(data) < 5 or struct.pack(">I", crc32(data[:-4])) != data[-4:]:
        raise DecodeError("bytewords: wrong checksum")
    return data[:-4]


# ---- tiny CBOR: just what a multi-part UR's part needs ----------------------

def _cbor_uint(buf, i):
    """(value, next index) of the unsigned integer at buf[i]."""
    if buf[i] >> 5 != 0:
        raise DecodeError("CBOR: not an unsigned integer")
    info = buf[i] & 31
    if info < 24:
        return info, i + 1
    size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if size is None:
        raise DecodeError("CBOR: bad integer")
    return int.from_bytes(buf[i + 1:i + 1 + size], "big"), i + 1 + size


def part_sequence(body):
    """(seqNum, seqLen) of a multi-part UR part's CBOR."""
    if not body or body[0] != 0x85:
        raise DecodeError("not a UR part: [seqNum, seqLen, messageLen, checksum, fragment]")
    seq, i = _cbor_uint(body, 1)
    count, _ = _cbor_uint(body, i)
    return seq, count


# ---- base-15 differential tones (SPEC §2.2) ---------------------------------

def to_tones(data, previous):
    """Bytes as tones: every 15 bits (zero-padded at the end) are 4 base-15
    digits d, and each tone is d + 1 keys after the one before it, in KEYS
    order (wrapping round): never the same tone twice in a row."""
    bits = int.from_bytes(data, "big") if data else 0
    nbits = 8 * len(data)
    chunks = -(-nbits // 15)
    bits <<= 15 * chunks - nbits
    out, prev = [], KEYS.index(previous)
    for c in range(chunks - 1, -1, -1):
        v = (bits >> (15 * c)) & 0x7FFF
        for e in (3375, 225, 15, 1):
            prev = (prev + 1 + v // e) % 16
            v %= e
            out.append(KEYS[prev])
    return "".join(out)


def from_tones(tones, previous):
    """The bytes of to_tones(): floor(15 * chunks / 8) of them. Lenient:
    misheard tones give wrong bytes, for Reed-Solomon, not an error."""
    if len(tones) % 4:
        raise DecodeError("tones: not a whole number of 4-tone groups")
    try:
        keys = [KEYS.index(k) for k in tones]
    except ValueError:
        raise DecodeError("not a DTMF key")
    bits, prev = 0, KEYS.index(previous)
    for i in range(0, len(keys), 4):
        v = 0
        for k in keys[i:i + 4]:
            d = (k - prev - 1) % 16  # 15: a repeated tone, impossible
            v, prev = v * 15 + min(d, 14), k
        # a misheard tone can give an impossible group: keep 15 bits of it,
        # wrong bytes that Reed-Solomon repairs
        bits = bits << 15 | (v & 0x7FFF)
    nbits = 15 * len(keys) // 4
    n = nbits // 8
    return (bits >> (nbits - 8 * n)).to_bytes(n, "big") if n else b""


# ---- data mode: UR <-> frame -------------------------------------------------

def parse_ur(ur):
    """(type, kind, body) of a UR's text."""
    ur = ur.strip().lower()
    if not ur.startswith("ur:"):
        raise ValueError("not a UR")
    path = ur[3:].split("/")
    if len(path) == 2:
        kind = KIND_SINGLE
    elif len(path) == 3:
        kind = KIND_PART
    else:
        raise ValueError("not a UR: ur:<type>/[<seq>-<count>/]<bytewords>")
    body = from_bytewords_minimal(path[-1])
    if kind == KIND_PART:
        seq, count = (int(x) for x in path[1].split("-"))
        if part_sequence(body) != (seq, count):
            raise ValueError("the part's sequence does not match its CBOR")
    return path[0], kind, body


def ur_text(type_, kind, body):
    """The UR's text, as any UR decoder takes it."""
    if kind == KIND_PART:
        seq, count = part_sequence(body)
        return "ur:%s/%d-%d/%s" % (type_, seq, count, bytewords_minimal(body))
    return "ur:%s/%s" % (type_, bytewords_minimal(body))


def ur_to_frame(ur):
    """The tones of the frame that carries this UR (SPEC §2.1)."""
    type_, kind, body = parse_ur(ur)
    if not 1 <= len(body) <= 255:
        raise ValueError("a frame's body is 1 to 255 bytes")
    if type_ in UR_TYPES[1:]:
        head = bytes([FORMAT_VERSION << 4 | kind, UR_TYPES.index(type_), len(body)])
    else:
        name = type_.encode("ascii")
        head = bytes([FORMAT_VERSION << 4 | kind, 0, len(body), len(name)]) + name
    data = head + body
    if len(data) + PARITY > 255:
        raise ValueError("too long for one frame: use a multi-part UR")
    # a byte of padding when the base-15 digits would leave 8 bits or more
    # spare, so that the receiver can tell the codeword's length (SPEC §2.2)
    if 15 * -(-8 * (len(data) + PARITY) // 15) - 8 * (len(data) + PARITY) >= 8:
        data += b"\x00"
    return LEAD + SYNC + to_tones(data + rs_encode(data), SYNC[-1])


def frame_to_ur(tones):
    """(UR text, bytes corrected) of a frame's tones, lead-in included or
    not. Finds the sync among the first tones, and repairs one lost or one
    extra tone (the count of tones tells which) by trying every third place,
    with Reed-Solomon as the judge. Raises DecodeError."""
    starts = [i + len(SYNC) for i in range(0, 4) if tones[i:i + len(SYNC)] == SYNC]
    if not starts and tones[:1] == SYNC[-1]:
        starts = [1]  # the sync's first tone was lost
    if not starts:
        raise DecodeError("no sync")
    error = DecodeError("frame")
    for start in starts:
        data = tones[start:]
        candidates = [data]
        # Near enough is enough: a tone dropped or added within 3 places of
        # the right one restores the groups, and leaves a few wrong bytes
        # that Reed-Solomon repairs.
        if len(data) % 4 == 1:    # one extra tone
            candidates += [data[:i] + data[i + 1:] for i in range(1, len(data), 3)]
        elif len(data) % 4 == 3:  # one lost tone
            candidates += [data[:i] + _filler(data, i) + data[i:] for i in range(1, len(data), 3)]
        for c in candidates:
            try:
                return _frame_body(c)
            except DecodeError as e:
                error = e
    raise error


def _filler(tones, i):
    """A key different from both neighbours of place i."""
    return next(k for k in KEYS if k not in tones[i - 1:i + 1])


def _frame_body(tones):
    codeword = from_tones(tones, SYNC[-1])
    if not PARITY + 4 <= len(codeword) <= 255:
        raise DecodeError("frame length")
    codeword, corrected = rs_correct(codeword, PARITY)
    data = bytes(codeword[:-PARITY])
    version, kind = data[0] >> 4, data[0] & 15
    if version != FORMAT_VERSION or kind not in (KIND_SINGLE, KIND_PART):
        raise DecodeError("unknown format version or kind")
    code, length, i = data[1], data[2], 3
    if code == 0:
        n = data[3]
        type_ = data[4:4 + n].decode("ascii", "replace")
        i = 4 + n
    elif code < len(UR_TYPES):
        type_ = UR_TYPES[code]
    else:
        raise DecodeError("unknown UR type code")
    body, pad = data[i:i + length], data[i + length:]
    if len(body) != length or pad not in (b"", b"\x00"):
        raise DecodeError("length")
    return ur_text(type_, kind, body), corrected


# ---- seeds -------------------------------------------------------------------

def _indices(entropy):
    """BIP-39 word indices (checksum included) of the entropy."""
    bits = len(entropy) * 8
    n = int.from_bytes(entropy, "big") << (bits // 32)
    n |= hashlib.sha256(entropy).digest()[0] >> (8 - bits // 32)
    words = (bits + bits // 32) // 11
    return [(n >> (11 * (words - 1 - i))) & 2047 for i in range(words)]


def _entropy(indices):
    """The entropy of BIP-39 word indices; checks the checksum."""
    words = len(indices)
    if words not in (12, 24) or any(not 0 <= i < 2048 for i in indices):
        raise DecodeError("12 or 24 words, each 0-2047")
    n = 0
    for i in indices:
        n = n << 11 | i
    cs = words // 3
    entropy = (n >> cs).to_bytes(words * 4 // 3, "big")
    if _indices(entropy)[-1] != indices[-1]:
        raise DecodeError("wrong BIP-39 checksum")
    return entropy


def seed_to_keypad(entropy, pin=None):
    """The keypad-mode tones of a seed (SPEC §3)."""
    if pin:
        entropy = pin_xor(entropy, pin)
    return "*" + "".join("%04d" % i for i in _indices(entropy)) + "#"


def keypad_to_seed(tones, pin=None):
    """The entropy of keypad-mode tones. Raises DecodeError."""
    if not (tones.startswith("*") and tones.endswith("#")) or not tones[1:-1].isdigit():
        raise DecodeError("keypad mode is *, digits, #")
    digits = tones[1:-1]
    if len(digits) % 4:
        raise DecodeError("four digits per word")
    entropy = _entropy([int(digits[i:i + 4]) for i in range(0, len(digits), 4)])
    return pin_xor(entropy, pin) if pin else entropy


def seed_to_ur(entropy, pin=None, type_="crypto-seed"):
    """A single-part crypto-seed (or seed) UR: CBOR {1: entropy}."""
    if pin:
        entropy = pin_xor(entropy, pin)
    head = b"\xa1\x01\x50" if len(entropy) == 16 else b"\xa1\x01\x58\x20"  # map {1: bytes}
    return ur_text(type_, KIND_SINGLE, head + entropy)


def ur_to_seed(ur, pin=None):
    type_, kind, body = parse_ur(ur)
    if type_ not in ("crypto-seed", "seed") or kind != KIND_SINGLE:
        raise DecodeError("not a single-part seed UR")
    if len(body) < 3 or body[:2] != b"\xa1\x01" or body[2] not in (0x50, 0x58):
        raise DecodeError("seed CBOR: {1: entropy} expected")
    entropy = body[3:] if body[2] == 0x50 else body[4:4 + body[3]]
    if len(entropy) not in (16, 32):
        raise DecodeError("entropy of 16 or 32 bytes expected")
    return pin_xor(entropy, pin) if pin else entropy


# ---- audio: tones -> samples -------------------------------------------------

LOW_LEVEL = 10 ** (-12 / 20)   # -12 dBFS
HIGH_LEVEL = 10 ** (-10 / 20)  # -10 dBFS: the high tone 2 dB louder


def render(groups, rate=8000, tone_ms=50, gap_ms=50, pause_ms=400, detune=1.0):
    """Samples (floats, -1 to 1) of groups of tones, each group after a pause.
    detune scales every frequency (to test a receiver's tolerance)."""
    out = [0.0] * int(rate * pause_ms / 1000)
    n = int(rate * tone_ms / 1000)
    ramp = max(1, int(rate * 0.002))  # 2 ms fades: no clicks
    for g, group in enumerate(groups):
        if g:
            out += [0.0] * int(rate * pause_ms / 1000)
        for key in group:
            lo, hi = FREQS[key]
            w1, w2 = 2 * math.pi * lo * detune / rate, 2 * math.pi * hi * detune / rate
            for i in range(n):
                env = min(1.0, i / ramp, (n - 1 - i) / ramp)
                out.append(env * (LOW_LEVEL * math.sin(w1 * i) + HIGH_LEVEL * math.sin(w2 * i)))
            out += [0.0] * int(rate * gap_ms / 1000)
    out += [0.0] * int(rate * pause_ms / 1000)
    return out


# ---- audio: samples -> tones (SPEC appendix A) -------------------------------

WINDOW_S, HOP_S = 0.025, 0.010  # 25 ms Goertzel windows, every 10 ms


def detect(samples, rate):
    """(key or None, level in dB) every 10 ms. Tolerant on purpose (sound
    through the air: small speakers lose the low tones, rooms echo): the
    strongest low and high frequencies must each be twice as strong as the
    runner-up in their group, carry a fair share of the energy, and differ
    by less than 20 dB."""
    import operator  # desktop only: NDS-Signer listens in C
    n, hop = int(rate * WINDOW_S), int(rate * HOP_S)
    basis = []
    for f in LOW + HIGH:
        w = 2 * math.pi * f / rate
        basis.append(([math.cos(w * i) for i in range(n)], [math.sin(w * i) for i in range(n)]))
    out = []
    for start in range(0, len(samples) - n + 1, hop):
        x = samples[start:start + n]
        total = sum(map(operator.mul, x, x))
        if total / n < 10 ** (-55 / 10):  # quieter than -55 dBFS: silence
            out.append((None, -99.0))
            continue
        power = []
        for c, s in basis:
            re, im = sum(map(operator.mul, x, c)), sum(map(operator.mul, x, s))
            power.append((re * re + im * im) * 2 / n)
        low, high = power[:4], power[4:]
        r, c = max(range(4), key=low.__getitem__), max(range(4), key=high.__getitem__)
        lo, hi = low[r], high[c]
        ok = (lo > 2 * max(p for i, p in enumerate(low) if i != r)
              and hi > 2 * max(p for i, p in enumerate(high) if i != c)
              and lo + hi > 0.2 * total
              and 0.01 < hi / lo < 100)
        out.append((PAD[r][c] if ok else None, 10 * math.log10((lo + hi) / n + 1e-12)))
    return out


def segment(detections, min_hops=3, bridge_hops=3, dip_db=8.0, near_db=6.0):
    """[(key, start hop, end hop)]. A tone is one key for at least min_hops
    (30 ms); a key that drops out for up to bridge_hops and comes back is the
    same tone (flicker). Echoes: a room keeps a tone ringing after it stops,
    weaker. So the same key again counts as a new tone only if it comes back
    nearly as loud as before (within near_db of the last peak) after dipping
    (by dip_db), or after a silence; a weaker return is the echo."""
    tones = []
    cur = None   # [key, start, end, peak, dipped]
    last = None  # (key, peak) of the last tone
    gap = 0

    def close():
        nonlocal last
        if cur and cur[2] - cur[1] >= min_hops:
            if last and last[0] == cur[0] and cur[3] < last[1] - near_db and tones and tones[-1][0] == cur[0]:
                tones[-1] = (cur[0], tones[-1][1], cur[2])      # an echo of it
            else:
                tones.append((cur[0], cur[1], cur[2]))
                last = (cur[0], cur[3])

    for i, (k, lvl) in enumerate(detections):
        if cur and k == cur[0] and gap <= bridge_hops:
            if cur[4] and lvl > cur[3] - near_db:                 # pressed again
                close()
                cur = [k, i, i + 1, lvl, False]
            else:
                cur[2] = i + 1
                if not cur[4]:
                    cur[3] = max(cur[3], lvl)
                if lvl < cur[3] - dip_db:
                    cur[4] = True
            gap = 0
        elif k is None or (cur and gap <= bridge_hops and k != cur[0] and _short_run(detections, i, k, min_hops)):
            gap += 1
            if cur and gap > bridge_hops:
                close()
                cur = None
        else:
            close()
            cur = [k, i, i + 1, lvl, False]
            gap = 0
    close()
    return tones


def _short_run(detections, i, k, min_hops):
    """True if key k lasts fewer than min_hops from hop i (a glitch)."""
    n = 0
    while i + n < len(detections) and detections[i + n][0] == k and n < min_hops:
        n += 1
    return n < min_hops


def listen(samples, rate):
    """Groups of tones (strings), split by silences longer than 225 ms (SPEC
    §1.1). A group that starts with * and then digits is keypad mode and runs
    to its #, whatever the silences. In a data frame a tone never follows
    itself, so a repeat there is an echo, and is dropped."""
    tones = segment(detect(samples, rate))
    hop_ms = 1000 * int(rate * HOP_S) / rate
    groups, current, last_end = [], "", None

    def keypad():
        return current[:1] == "*" and (len(current) == 1 or current[1:].isdigit())

    def close():
        g = current
        if not keypad() and not g.startswith("*"):
            g = "".join(k for i, k in enumerate(g) if i == 0 or k != g[i - 1])
        groups.append(g)

    for key, start, end in tones:
        long_pause = last_end is not None and (start - last_end) * hop_ms > 225
        if current and long_pause and not keypad():
            close()
            current = ""
        if keypad() and key not in "0123456789#":
            close()                 # not keypad after all
            current = ""
        current += key
        last_end = end
        if current[:1] == "*" and key == "#" and current[1:-1].isdigit():
            close()
            current = ""
    if current:
        close()
    return groups


def receive(samples, rate, pin=None):
    """What a receiver gets from audio: a list of ("ur", text), ("seed",
    entropy) or ("error", reason, tones)."""
    out = []
    for group in listen(samples, rate):
        try:
            if group.startswith("*"):
                out.append(("seed", keypad_to_seed(group, pin)))
            else:
                out.append(("ur", frame_to_ur(group)[0]))
        except DecodeError as e:
            out.append(("error", str(e), group))
    return out


# ---- WAV files ---------------------------------------------------------------

def write_wav(path, samples, rate):
    import wave
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(struct.pack("<h", max(-32767, min(32767, round(s * 32767))))
                               for s in samples))


def read_wav(path):
    """(samples as floats, rate). 16-bit PCM; stereo is mixed down."""
    import wave
    with wave.open(str(path), "rb") as w:
        if w.getsampwidth() != 2:
            raise ValueError("16-bit PCM only")
        ch, rate, frames = w.getnchannels(), w.getframerate(), w.readframes(w.getnframes())
    pcm = struct.unpack("<%dh" % (len(frames) // 2), frames)
    return [sum(pcm[i:i + ch]) / (ch * 32768) for i in range(0, len(pcm), ch)], rate
