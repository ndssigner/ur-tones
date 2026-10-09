// ur-tones (draft v0), JavaScript implementation: a port of
// reference/python/ur_tones.py, plus multi-part URs (UR's fountain codes,
// ported from the Python library SeedSigner bundles, Foundation Devices'
// ur2, BSD-2-Clause-Patent) and a streaming receiver for a microphone.
// Checked against the same test vectors (web/test.mjs). Needs UrTonesCrypto.
"use strict";

const UrTones = (() => {
	const S = UrTonesCrypto;
	const { DecodeError } = S;
	const FORMAT_VERSION = 0;
	const KEYS = "0123456789ABCD*#";
	const LEAD = "CB"; // lead-in: lets the receiver settle; may be lost
	const SYNC = "AD";
	const PARITY = 16; // Reed-Solomon parity bytes: repairs 8 wrong bytes
	const KIND_SINGLE = 0, KIND_PART = 1;
	const UR_TYPES = ["", "crypto-psbt", "psbt", "crypto-seed", "seed", "crypto-account",
		"account-descriptor", "crypto-output", "output-descriptor", "bytes", "crypto-hdkey", "hdkey"];
	const LOW = [697, 770, 852, 941], HIGH = [1209, 1336, 1477, 1633];
	const PAD = ["123A", "456B", "789C", "*0#D"];
	const FREQS = {};
	PAD.forEach((row, r) => [...row].forEach((k, c) => { FREQS[k] = [LOW[r], HIGH[c]]; }));

	const concat = (...parts) => {
		const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
		let i = 0;
		for (const p of parts) { out.set(p, i); i += p.length; }
		return out;
	};
	const u32be = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

	// ---- CRC-32 (as zlib) --------------------------------------------
	const CRC_TABLE = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		CRC_TABLE[n] = c >>> 0;
	}
	function crc32(data) {
		let c = 0xffffffff;
		for (const b of data) c = CRC_TABLE[(c ^ b) & 255] ^ (c >>> 8);
		return (c ^ 0xffffffff) >>> 0;
	}

	// ---- bytewords, minimal style --------------------------------------
	const BYTEWORDS =
		"ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebody" +
		"bragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyan" +
		"darkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepic" +
		"evenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuel" +
		"fundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawk" +
		"heathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjade" +
		"jazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwi" +
		"knoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmany" +
		"mathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobey" +
		"oboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquad" +
		"quizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilk" +
		"skewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoys" +
		"triptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswall" +
		"wandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszero" +
		"zestzinczonezoom";
	const MINIMAL = Array.from({ length: 256 }, (_, i) => BYTEWORDS[4 * i] + BYTEWORDS[4 * i + 3]);
	const FROM_MINIMAL = new Map(MINIMAL.map((w, i) => [w, i]));

	function bytewordsMinimal(data) {
		return [...concat(data, u32be(crc32(data)))].map((b) => MINIMAL[b]).join("");
	}
	function fromBytewordsMinimal(text) {
		if (text.length % 2) throw new DecodeError("bytewords: odd length");
		const data = new Uint8Array(text.length / 2);
		for (let i = 0; i < data.length; i++) {
			const b = FROM_MINIMAL.get(text.slice(2 * i, 2 * i + 2));
			if (b === undefined) throw new DecodeError("bytewords: not a word");
			data[i] = b;
		}
		if (data.length < 5) throw new DecodeError("bytewords: too short");
		const body = data.slice(0, -4);
		if (crc32(body) !== ((data[data.length - 4] << 24 | data[data.length - 3] << 16 | data[data.length - 2] << 8 | data[data.length - 1]) >>> 0))
			throw new DecodeError("bytewords: wrong checksum");
		return body;
	}

	// ---- tiny CBOR ----------------------------------------------------
	function cborHead(major, n) {
		if (n < 24) return Uint8Array.of(major << 5 | n);
		if (n < 256) return Uint8Array.of(major << 5 | 24, n);
		if (n < 65536) return Uint8Array.of(major << 5 | 25, n >> 8, n & 255);
		return concat(Uint8Array.of(major << 5 | 26), u32be(n));
	}
	const cborBytes = (b) => concat(cborHead(2, b.length), b);
	function cborRead(buf, i, major) {
		if (i >= buf.length || buf[i] >> 5 !== major) throw new DecodeError("CBOR: unexpected item");
		const info = buf[i] & 31;
		if (info < 24) return [info, i + 1];
		const size = { 24: 1, 25: 2, 26: 4 }[info];
		if (!size || i + size >= buf.length) throw new DecodeError("CBOR: bad length");
		let v = 0;
		for (let j = 1; j <= size; j++) v = v * 256 + buf[i + j];
		return [v, i + 1 + size];
	}
	function cborReadBytes(buf, i) {
		const [n, j] = cborRead(buf, i, 2);
		if (j + n > buf.length) throw new DecodeError("CBOR: truncated");
		return [buf.slice(j, j + n), j + n];
	}

	// ---- UR fountain codes (BCR-2020-005), as ur2 ----------------------
	const M64 = (1n << 64n) - 1n;
	const rotl = (x, k) => ((x << k) | (x >> (64n - k))) & M64;
	class Xoshiro256 {
		constructor(seed32) { // seeded from a SHA-256 digest
			this.s = [0, 1, 2, 3].map((i) => seed32.slice(8 * i, 8 * i + 8).reduce((v, b) => (v << 8n) | BigInt(b), 0n));
		}
		next() {
			const s = this.s;
			const result = (rotl((s[1] * 5n) & M64, 7n) * 9n) & M64;
			const t = (s[1] << 17n) & M64;
			s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
			s[2] ^= t;
			s[3] = rotl(s[3], 45n);
			return result;
		}
		nextDouble() { return Number(this.next()) / 18446744073709551616; }
		nextInt(low, high) { return Math.floor(this.nextDouble() * (high - low + 1) + low); }
	}
	function randomSampler(probs) { // Vose's alias method, as ur2
		const n = probs.length, total = probs.reduce((a, b) => a + b, 0);
		const P = probs.map((p) => (p * n) / total);
		const small = [], large = [];
		for (let i = n - 1; i >= 0; i--) (P[i] < 1 ? small : large).push(i);
		const prob = new Array(n).fill(0), alias = new Array(n).fill(0);
		while (small.length && large.length) {
			const a = small.pop(), g = large.pop();
			prob[a] = P[a]; alias[a] = g;
			P[g] += P[a] - 1;
			(P[g] < 1 ? small : large).push(g);
		}
		while (large.length) prob[large.pop()] = 1;
		while (small.length) prob[small.pop()] = 1;
		return (rng) => {
			const r1 = rng(), r2 = rng();
			const i = Math.floor(n * r1);
			return r2 < prob[i] ? i : alias[i];
		};
	}
	function chooseFragments(seqNum, seqLen, checksum) {
		if (seqNum <= seqLen) return [seqNum - 1];
		const rng = new Xoshiro256(S.sha256(concat(u32be(seqNum), u32be(checksum))));
		const degree = randomSampler(Array.from({ length: seqLen }, (_, i) => 1 / (i + 1)))(() => rng.nextDouble()) + 1;
		const remaining = Array.from({ length: seqLen }, (_, i) => i), shuffled = [];
		while (remaining.length) shuffled.push(remaining.splice(rng.nextInt(0, remaining.length - 1), 1)[0]);
		return shuffled.slice(0, degree).sort((a, b) => a - b);
	}
	function nominalFragmentLength(messageLen, minLen, maxLen) {
		let len = 0;
		for (let count = 1; count <= Math.floor(messageLen / minLen); count++) {
			len = Math.ceil(messageLen / count);
			if (len <= maxLen) break;
		}
		return len;
	}

	class FountainEncoder {
		constructor(message, maxFragmentLen = 100, minFragmentLen = 10) {
			this.messageLen = message.length;
			this.checksum = crc32(message);
			this.fragmentLen = nominalFragmentLength(message.length, minFragmentLen, maxFragmentLen);
			this.fragments = [];
			for (let i = 0; i < message.length; i += this.fragmentLen) {
				const f = new Uint8Array(this.fragmentLen);
				f.set(message.slice(i, i + this.fragmentLen));
				this.fragments.push(f);
			}
			this.seqNum = 0;
		}
		get seqLen() { return this.fragments.length; }
		nextPart() { // the part's CBOR: [seqNum, seqLen, messageLen, checksum, fragment]
			this.seqNum = (this.seqNum + 1) >>> 0;
			const data = new Uint8Array(this.fragmentLen);
			for (const i of chooseFragments(this.seqNum, this.seqLen, this.checksum))
				this.fragments[i].forEach((b, j) => { data[j] ^= b; });
			return concat(Uint8Array.of(0x85), cborHead(0, this.seqNum), cborHead(0, this.seqLen),
				cborHead(0, this.messageLen), cborHead(0, this.checksum), cborBytes(data));
		}
	}

	function parsePart(body) {
		if (body[0] !== 0x85) throw new DecodeError("not a UR part");
		let i = 1;
		const v = [];
		for (let k = 0; k < 4; k++) { const [x, j] = cborRead(body, i, 0); v.push(x); i = j; }
		const [data] = cborReadBytes(body, i);
		return { seqNum: v[0], seqLen: v[1], messageLen: v[2], checksum: v[3], data };
	}

	class FountainDecoder {
		constructor() { this.expected = null; this.simple = new Map(); this.mixed = new Map(); this.queue = []; this.result = null; this.error = null; this.received = 0; }
		get done() { return this.result !== null || this.error !== null; }
		progress() { return this.expected ? this.simple.size / this.expected.seqLen : 0; }
		receive(body) { // a part's CBOR; true if it was useful
			if (this.done) return false;
			const p = parsePart(body);
			if (!this.expected) this.expected = { seqLen: p.seqLen, messageLen: p.messageLen, checksum: p.checksum, fragmentLen: p.data.length };
			else {
				const e = this.expected;
				if (p.seqLen !== e.seqLen || p.messageLen !== e.messageLen || p.checksum !== e.checksum || p.data.length !== e.fragmentLen) return false;
			}
			this.received++;
			const before = this.simple.size + this.mixed.size * 1000;
			this.queue.push({ idx: chooseFragments(p.seqNum, p.seqLen, p.checksum), data: p.data });
			while (!this.done && this.queue.length) {
				const part = this.queue.shift();
				if (part.idx.length === 1) this.simplePart(part); else this.mixedPart(part);
			}
			return this.done || this.simple.size + this.mixed.size * 1000 !== before;
		}
		reduce(a, b) { // a without b, if b's fragments are a strict subset of a's
			if (b.idx.length < a.idx.length && b.idx.every((i) => a.idx.includes(i)))
				return { idx: a.idx.filter((i) => !b.idx.includes(i)), data: a.data.map((x, j) => x ^ b.data[j]) };
			return a;
		}
		simplePart(p) {
			const index = p.idx[0];
			if (this.simple.has(index)) return;
			this.simple.set(index, p);
			if (this.simple.size === this.expected.seqLen) {
				const msg = concat(...[...this.simple.keys()].sort((a, b) => a - b).map((i) => this.simple.get(i).data)).slice(0, this.expected.messageLen);
				if (crc32(msg) === this.expected.checksum) this.result = msg;
				else this.error = "wrong message checksum";
				return;
			}
			this.reduceMixedBy(p);
		}
		reduceMixedBy(p) {
			const next = new Map();
			for (const m of this.mixed.values()) {
				const r = this.reduce(m, p);
				if (r.idx.length === 1) this.queue.push(r); else next.set(r.idx.join(","), r);
			}
			this.mixed = next;
		}
		mixedPart(p) {
			if (this.mixed.has(p.idx.join(","))) return;
			for (const r of this.simple.values()) p = this.reduce(p, r);
			for (const r of this.mixed.values()) p = this.reduce(p, r);
			if (p.idx.length === 1) { this.queue.push(p); return; }
			this.reduceMixedBy(p);
			this.mixed.set(p.idx.join(","), p);
		}
	}

	// ---- URs and frames -------------------------------------------------
	function parseUR(text) {
		const ur = text.trim().toLowerCase();
		if (!ur.startsWith("ur:")) throw new DecodeError("not a UR");
		const path = ur.slice(3).split("/");
		if (path.length !== 2 && path.length !== 3) throw new DecodeError("not a UR");
		const kind = path.length === 2 ? KIND_SINGLE : KIND_PART;
		const body = fromBytewordsMinimal(path[path.length - 1]);
		if (kind === KIND_PART) {
			const p = parsePart(body);
			if (path[1] !== `${p.seqNum}-${p.seqLen}`) throw new DecodeError("the part's sequence does not match its CBOR");
		}
		return { type: path[0], kind, body };
	}
	function urText(type, kind, body) {
		if (kind === KIND_PART) {
			const p = parsePart(body);
			return `ur:${type}/${p.seqNum}-${p.seqLen}/${bytewordsMinimal(body)}`;
		}
		return `ur:${type}/${bytewordsMinimal(body)}`;
	}

	// Reed-Solomon encoder (the decoder is UrTonesCrypto.rsCorrect)
	const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
	for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
	for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
	const mul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];
	function rsEncode(data, nsym = PARITY) {
		let g = [1];
		for (let i = 0; i < nsym; i++) g = [...g, 0].map((a, j) => a ^ mul(j ? g[j - 1] : 0, EXP[i]));
		const rem = [...data, ...new Array(nsym).fill(0)];
		for (let i = 0; i < data.length; i++) {
			const c = rem[i];
			if (c) for (let j = 1; j < g.length; j++) rem[i + j] ^= mul(g[j], c);
		}
		return Uint8Array.from(rem.slice(data.length));
	}

	// ---- base-15 differential tones (SPEC §2.2) -----------------------------
	// every 15 bits are 4 base-15 digits d; each tone is d + 1 keys after the
	// one before it (KEYS order, wrapping): never the same tone twice in a row
	function toTones(data, previous) {
		const nbits = 8 * data.length, chunks = Math.ceil(nbits / 15);
		let bits = 0n;
		for (const b of data) bits = (bits << 8n) | BigInt(b);
		bits <<= BigInt(15 * chunks - nbits);
		let prev = KEYS.indexOf(previous), out = "";
		for (let c = chunks - 1; c >= 0; c--) {
			let v = Number((bits >> BigInt(15 * c)) & 0x7fffn);
			for (const e of [3375, 225, 15, 1]) {
				prev = (prev + 1 + Math.floor(v / e)) % 16;
				v %= e;
				out += KEYS[prev];
			}
		}
		return out;
	}
	// lenient: misheard tones give wrong bytes, for Reed-Solomon
	function fromTones(tones, previous) {
		if (tones.length % 4) throw new DecodeError("tones: not a whole number of 4-tone groups");
		let bits = 0n, prev = KEYS.indexOf(previous);
		for (let i = 0; i < tones.length; i += 4) {
			let v = 0;
			for (const ch of tones.slice(i, i + 4)) {
				const k = KEYS.indexOf(ch);
				if (k < 0) throw new DecodeError("not a DTMF key");
				const d = (((k - prev - 1) % 16) + 16) % 16; // 15: a repeated tone, impossible
				v = v * 15 + Math.min(d, 14);
				prev = k;
			}
			bits = (bits << 15n) | BigInt(v & 0x7fff);
		}
		const nbits = 15 * tones.length / 4, n = Math.floor(nbits / 8);
		bits >>= BigInt(nbits - 8 * n);
		const out = new Uint8Array(n);
		for (let i = n - 1; i >= 0; i--) { out[i] = Number(bits & 0xffn); bits >>= 8n; }
		return out;
	}

	function urToFrame(ur) {
		const { type, kind, body } = parseUR(ur);
		if (body.length < 1 || body.length > 255) throw new DecodeError("a frame's body is 1 to 255 bytes");
		const code = UR_TYPES.indexOf(type);
		const head = code > 0 ? Uint8Array.of(FORMAT_VERSION << 4 | kind, code, body.length)
			: concat(Uint8Array.of(FORMAT_VERSION << 4 | kind, 0, body.length, type.length), Uint8Array.from(type, (c) => c.charCodeAt(0) & 127));
		let data = concat(head, body);
		if (data.length + PARITY > 255) throw new DecodeError("too long for one frame: use a multi-part UR");
		const n = data.length + PARITY;
		// a byte of padding when the base-15 digits would leave 8 bits or more spare
		if (15 * Math.ceil(8 * n / 15) - 8 * n >= 8) data = concat(data, Uint8Array.of(0));
		return LEAD + SYNC + toTones(concat(data, rsEncode(data)), SYNC[1]);
	}
	const filler = (t, i) => [...KEYS].find((k) => k !== t[i - 1] && k !== t[i]);
	// finds the sync among the first tones; repairs one lost or one extra tone
	// (the count tells which) by trying every third place: once the groups
	// line up again, Reed-Solomon repairs the rest, and judges
	function frameToUR(tones) {
		const starts = [];
		for (let i = 0; i < 4; i++) if (tones.slice(i, i + 2) === SYNC) starts.push(i + 2);
		if (!starts.length && tones[0] === SYNC[1]) starts.push(1);
		if (!starts.length) throw new DecodeError("no sync");
		let error = new DecodeError("frame");
		for (const start of starts) {
			const data = tones.slice(start), candidates = [data];
			if (data.length % 4 === 1) for (let i = 1; i < data.length; i += 3) candidates.push(data.slice(0, i) + data.slice(i + 1));
			else if (data.length % 4 === 3) for (let i = 1; i < data.length; i += 3) candidates.push(data.slice(0, i) + filler(data, i) + data.slice(i));
			for (const c of candidates) {
				try { return frameBody(c); } catch (e) { error = e; }
			}
		}
		throw error;
	}
	function frameBody(tones) {
		const cw = [...fromTones(tones, SYNC[1])];
		if (cw.length < PARITY + 4 || cw.length > 255) throw new DecodeError("frame length");
		const [fixed, corrected] = S.rsCorrect(cw, PARITY);
		const data = Uint8Array.from(fixed.slice(0, -PARITY));
		const version = data[0] >> 4, kind = data[0] & 15;
		if (version !== FORMAT_VERSION || (kind !== KIND_SINGLE && kind !== KIND_PART)) throw new DecodeError("unknown format version or kind");
		let type, i = 3;
		if (data[1] === 0) { type = String.fromCharCode(...data.slice(4, 4 + data[3])); i = 4 + data[3]; }
		else if (data[1] < UR_TYPES.length) type = UR_TYPES[data[1]];
		else throw new DecodeError("unknown UR type code");
		const body = data.slice(i, i + data[2]), pad = data.slice(i + data[2]);
		if (body.length !== data[2] || pad.length > 1 || (pad.length && pad[0])) throw new DecodeError("length");
		return { ur: urText(type, kind, body), type, kind, body, corrected };
	}

	// a message (CBOR) as the URs to send: one, or the first parts of a loop
	function messageToURs(type, cbor, fragment = 100, extra = 0) {
		const enc = new FountainEncoder(cbor, fragment);
		if (enc.seqLen === 1) return { urs: [urText(type, KIND_SINGLE, cbor)], encoder: null };
		const urs = [];
		for (let i = 0; i < enc.seqLen + extra; i++) urs.push(urText(type, KIND_PART, enc.nextPart()));
		return { urs, encoder: enc, type };
	}
	const psbtToURs = (psbt, fragment, extra) => messageToURs("crypto-psbt", cborBytes(psbt), fragment, extra);
	function cborToPsbt(cbor) { // crypto-psbt and psbt: a byte string
		const [psbt, end] = cborReadBytes(cbor, 0);
		if (end !== cbor.length) throw new DecodeError("PSBT CBOR: trailing bytes");
		return psbt;
	}

	// ---- seeds ---------------------------------------------------------
	function indices(entropy) {
		const bits = [...entropy].map((b) => b.toString(2).padStart(8, "0")).join("")
			+ [...S.sha256(entropy)].map((b) => b.toString(2).padStart(8, "0")).join("").slice(0, entropy.length / 4);
		return bits.match(/.{11}/g).map((b) => parseInt(b, 2));
	}
	function fromIndices(idx) {
		if ((idx.length !== 12 && idx.length !== 24) || idx.some((i) => !(i >= 0 && i < 2048))) throw new DecodeError("12 or 24 words, each 0-2047");
		const bits = idx.map((i) => i.toString(2).padStart(11, "0")).join("");
		const nbytes = idx.length * 4 / 3;
		const entropy = Uint8Array.from(bits.slice(0, nbytes * 8).match(/.{8}/g).map((b) => parseInt(b, 2)));
		if (indices(entropy).at(-1) !== idx.at(-1)) throw new DecodeError("wrong BIP-39 checksum");
		return entropy;
	}
	const seedToKeypad = (entropy, pin) => "*" + indices(pin ? S.pinXor(entropy, pin) : entropy).map((i) => String(i).padStart(4, "0")).join("") + "#";
	function keypadToSeed(tones, pin) {
		if (!/^\*\d+#$/.test(tones)) throw new DecodeError("keypad mode is *, digits, #");
		const digits = tones.slice(1, -1);
		if (digits.length % 4) throw new DecodeError("four digits per word");
		const e = fromIndices(digits.match(/.{4}/g).map(Number));
		return pin ? S.pinXor(e, pin) : e;
	}
	function seedToUR(entropy, pin, type = "crypto-seed") {
		const e = pin ? S.pinXor(entropy, pin) : entropy;
		return urText(type, KIND_SINGLE, concat(Uint8Array.of(0xa1, 0x01), cborBytes(e)));
	}
	function urToSeed(ur, pin) {
		const { type, kind, body } = parseUR(ur);
		if ((type !== "crypto-seed" && type !== "seed") || kind !== KIND_SINGLE) throw new DecodeError("not a single-part seed UR");
		if (body[0] !== 0xa1 || body[1] !== 0x01) throw new DecodeError("seed CBOR: {1: entropy} expected");
		const [e] = cborReadBytes(body, 2);
		if (e.length !== 16 && e.length !== 32) throw new DecodeError("entropy of 16 or 32 bytes expected");
		return pin ? S.pinXor(e, pin) : e;
	}

	// ---- audio: tones -> samples ------------------------------------------
	const LOW_LEVEL = 10 ** (-12 / 20), HIGH_LEVEL = 10 ** (-10 / 20);
	function render(groups, rate = 8000, toneMs = 50, gapMs = 50, pauseMs = 400) {
		const n = Math.floor(rate * toneMs / 1000), gap = Math.floor(rate * gapMs / 1000), pause = Math.floor(rate * pauseMs / 1000);
		const total = pause * (groups.length + 1) + groups.reduce((s, g) => s + g.length * (n + gap), 0);
		const out = new Float32Array(total);
		const ramp = Math.max(1, Math.floor(rate * 0.002));
		let pos = pause;
		groups.forEach((group, gi) => {
			if (gi) pos += pause;
			for (const key of group) {
				const [lo, hi] = FREQS[key];
				const w1 = 2 * Math.PI * lo / rate, w2 = 2 * Math.PI * hi / rate;
				for (let i = 0; i < n; i++) {
					const env = Math.min(1, i / ramp, (n - 1 - i) / ramp);
					out[pos + i] = env * (LOW_LEVEL * Math.sin(w1 * i) + HIGH_LEVEL * Math.sin(w2 * i));
				}
				pos += n + gap;
			}
		});
		return out;
	}
	function wav(samples, rate) { // 16-bit mono PCM
		const buf = new DataView(new ArrayBuffer(44 + 2 * samples.length));
		const str = (o, s) => [...s].forEach((c, i) => buf.setUint8(o + i, c.charCodeAt(0)));
		str(0, "RIFF"); buf.setUint32(4, 36 + 2 * samples.length, true); str(8, "WAVEfmt ");
		buf.setUint32(16, 16, true); buf.setUint16(20, 1, true); buf.setUint16(22, 1, true);
		buf.setUint32(24, rate, true); buf.setUint32(28, rate * 2, true); buf.setUint16(32, 2, true); buf.setUint16(34, 16, true);
		str(36, "data"); buf.setUint32(40, 2 * samples.length, true);
		samples.forEach((s, i) => buf.setInt16(44 + 2 * i, Math.max(-32767, Math.min(32767, Math.round(s * 32767))), true));
		return new Uint8Array(buf.buffer);
	}
	function readWav(bytes) { // 16-bit PCM, any channels -> {samples, rate}
		const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		const tag = (o) => String.fromCharCode(...bytes.slice(o, o + 4));
		if (tag(0) !== "RIFF" || tag(8) !== "WAVE") throw new DecodeError("not a WAV file");
		let o = 12, fmt = null;
		while (o + 8 <= bytes.length) {
			const id = tag(o), size = v.getUint32(o + 4, true);
			if (id === "fmt ") fmt = { ch: v.getUint16(o + 10, true), rate: v.getUint32(o + 12, true), bits: v.getUint16(o + 22, true) };
			if (id === "data") {
				if (!fmt || fmt.bits !== 16) throw new DecodeError("16-bit PCM WAV only");
				const n = Math.floor(Math.min(size, bytes.length - o - 8) / (2 * fmt.ch));
				const out = new Float32Array(n);
				for (let i = 0; i < n; i++) {
					let s = 0;
					for (let c = 0; c < fmt.ch; c++) s += v.getInt16(o + 8 + 2 * (i * fmt.ch + c), true);
					out[i] = s / (fmt.ch * 32768);
				}
				return { samples: out, rate: fmt.rate };
			}
			o += 8 + size + (size & 1);
		}
		throw new DecodeError("WAV without data");
	}

	// ---- audio: samples -> tones (SPEC appendix A) ---------------------------
	// a detection every 10 ms over 25 ms; tolerant on purpose (through the
	// air small speakers lose the low tones, and rooms echo)
	function makeDetector(rate) {
		const n = Math.floor(rate * 0.025), hop = Math.floor(rate * 0.010);
		const basis = [...LOW, ...HIGH].map((f) => {
			const w = 2 * Math.PI * f / rate, c = new Float64Array(n), s = new Float64Array(n);
			for (let i = 0; i < n; i++) { c[i] = Math.cos(w * i); s[i] = Math.sin(w * i); }
			return [c, s];
		});
		const window = (x) => { // [key or null, level in dB]
			let total = 0;
			for (let i = 0; i < n; i++) total += x[i] * x[i];
			if (total / n < 10 ** -5.5) return [null, -99]; // quieter than -55 dBFS
			const power = basis.map(([c, s]) => {
				let re = 0, im = 0;
				for (let i = 0; i < n; i++) { re += x[i] * c[i]; im += x[i] * s[i]; }
				return (re * re + im * im) * 2 / n;
			});
			const best = (a) => a.reduce((b, p, i) => p > a[b] ? i : b, 0);
			const low = power.slice(0, 4), high = power.slice(4), r = best(low), c = best(high), lo = low[r], hi = high[c];
			const ok = lo > 2 * Math.max(...low.filter((_, i) => i !== r)) && hi > 2 * Math.max(...high.filter((_, i) => i !== c))
				&& lo + hi > 0.2 * total && hi / lo > 0.01 && hi / lo < 100;
			return [ok ? PAD[r][c] : null, 10 * Math.log10((lo + hi) / n + 1e-12)];
		};
		return { n, hop, window };
	}
	// a key lasting fewer than minHops from i: a glitch
	function shortRun(det, i, k, minHops) {
		let m = 0;
		while (i + m < det.length && det[i + m][0] === k && m < minHops) m++;
		return m < minHops;
	}
	// [[key, start, end]], exactly as ur_tones.segment(): tones of 30 ms or
	// more; flicker bridged; the same key again is a new tone only if it
	// comes back nearly as loud (an echo is weaker)
	function segment(det, minHops = 3, bridgeHops = 3, dipDb = 8, nearDb = 6) {
		const tones = [];
		let cur = null, last = null, gap = 0;
		const close = () => {
			if (cur && cur[2] - cur[1] >= minHops) {
				const prev = tones[tones.length - 1];
				if (last && last[0] === cur[0] && cur[3] < last[1] - nearDb && prev && prev[0] === cur[0])
					tones[tones.length - 1] = [cur[0], prev[1], cur[2]];
				else { tones.push([cur[0], cur[1], cur[2]]); last = [cur[0], cur[3]]; }
			}
		};
		det.forEach(([k, lvl], i) => {
			if (cur && k === cur[0] && gap <= bridgeHops) {
				if (cur[4] && lvl > cur[3] - nearDb) { close(); cur = [k, i, i + 1, lvl, false]; }
				else {
					cur[2] = i + 1;
					if (!cur[4]) cur[3] = Math.max(cur[3], lvl);
					if (lvl < cur[3] - dipDb) cur[4] = true;
				}
				gap = 0;
			} else if (k === null || (cur && gap <= bridgeHops && k !== cur[0] && shortRun(det, i, k, minHops))) {
				gap++;
				if (cur && gap > bridgeHops) { close(); cur = null; }
			} else { close(); cur = [k, i, i + 1, lvl, false]; gap = 0; }
		});
		close();
		return tones;
	}

	// Streaming: push(samples) as they come. Detections are kept until a
	// silence of 300 ms, then segmented exactly as the reference does (no
	// tone spans such a silence) and grouped: onGroup(tones). onLive(key)
	// shows keys as they are heard (a rough, immediate view).
	class Listener {
		constructor(rate, { onGroup = () => {}, onLive = () => {}, onLevel = () => {} } = {}) {
			Object.assign(this, { rate, onGroup, onLive, onLevel });
			this.d = makeDetector(rate);
			this.hopMs = 1000 * this.d.hop / rate;
			this.buf = new Float32Array(0);
			this.det = []; this.silent = 0; this.liveKey = null; this.liveRun = 0;
			this.current = ""; this.lastEnd = null; this.offset = 0;
		}
		push(samples) {
			const buf = new Float32Array(this.buf.length + samples.length);
			buf.set(this.buf); buf.set(samples, this.buf.length);
			let start = 0;
			for (; start + this.d.n <= buf.length; start += this.d.hop) this.step(this.d.window(buf.subarray(start, start + this.d.n)));
			this.buf = buf.slice(start);
		}
		step([k, lvl]) {
			this.onLevel(lvl);
			this.det.push([k, lvl]);
			if (k === this.liveKey) { if (++this.liveRun === 3 && k) this.onLive(k); } else { this.liveKey = k; this.liveRun = 1; }
			this.silent = k === null ? this.silent + 1 : 0;
			if (this.silent * this.hopMs >= 300 && this.det.length > this.silent) this.batch();
		}
		batch() {
			const tones = segment(this.det), base = this.offset;
			this.offset += this.det.length;
			this.det = []; this.silent = 0;
			for (const [key, start, end] of tones) this.tone(key, base + start, base + end);
			if (!this.keypad()) this.close();
		}
		keypad() { return /^\*\d*$/.test(this.current); }
		tone(key, start, end) {
			const longPause = this.lastEnd !== null && (start - this.lastEnd) * this.hopMs > 225;
			if (this.current && longPause && !this.keypad()) this.close();
			if (this.keypad() && !"0123456789#".includes(key)) this.close();
			this.current += key;
			this.lastEnd = end;
			if (key === "#" && /^\*\d*#$/.test(this.current)) this.close();
		}
		close() {
			let g = this.current;
			this.current = "";
			if (!g) return;
			// in a data frame a tone never follows itself: a repeat is an echo
			if (!g.startsWith("*")) g = [...g].filter((k, i) => i === 0 || k !== g[i - 1]).join("");
			this.onGroup(g);
		}
		flush() { if (this.det.length) this.batch(); this.close(); }
	}
	function listen(samples, rate) {
		const groups = [];
		const l = new Listener(rate, { onGroup: (g) => groups.push(g) });
		l.push(samples); l.flush();
		return groups;
	}

	return {
		FORMAT_VERSION, KEYS, LEAD, SYNC, PARITY, toTones, fromTones, segment, UR_TYPES, FREQS, DecodeError,
		crc32, bytewordsMinimal, fromBytewordsMinimal, cborBytes, parseUR, urText, urToFrame, frameToUR,
		FountainEncoder, FountainDecoder, parsePart, messageToURs, psbtToURs, cborToPsbt,
		seedToKeypad, keypadToSeed, seedToUR, urToSeed, render, wav, readWav, Listener, listen,
	};
})();
