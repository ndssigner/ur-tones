// ur-tones web tool: SHA-256, HMAC, PBKDF2, the seed PIN, BIP-39 and
// Reed-Solomon (QR codes' code), without WebCrypto (synchronous, and works
// from file://). Checked against Node's crypto and the vectors (web/test.mjs).
"use strict";

const UrTonesCrypto = (() => {
	const PIN_SALT = "ur-tones/seed-pin/v0";
	const PIN_ITERATIONS = 10000;

	class DecodeError extends Error {}

	// ---- SHA-256, HMAC, PBKDF2 (no dependency on WebCrypto) ----------

	const K = new Uint32Array([
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

	function sha256(data) {
		const len = data.length;
		const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
		padded.set(data);
		padded[len] = 0x80;
		const bitLen = len * 8;
		const view = new DataView(padded.buffer);
		view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
		view.setUint32(padded.length - 4, bitLen >>> 0);
		const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
		const w = new Uint32Array(64);
		const rotr = (x, n) => (x >>> n) | (x << (32 - n));
		for (let off = 0; off < padded.length; off += 64) {
			for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + 4 * i);
			for (let i = 16; i < 64; i++) {
				const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
				const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
				w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
			}
			let [a, b, c, d, e, f, g, hh] = h;
			for (let i = 0; i < 64; i++) {
				const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
				const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
				hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
			}
			h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
		}
		const out = new Uint8Array(32);
		const ov = new DataView(out.buffer);
		for (let i = 0; i < 8; i++) ov.setUint32(4 * i, h[i]);
		return out;
	}

	function concat(a, b) {
		const out = new Uint8Array(a.length + b.length);
		out.set(a);
		out.set(b, a.length);
		return out;
	}

	function hmacSha256(key, msg) {
		if (key.length > 64) key = sha256(key);
		const k = new Uint8Array(64);
		k.set(key);
		const ipad = k.map((x) => x ^ 0x36), opad = k.map((x) => x ^ 0x5c);
		return sha256(concat(opad, sha256(concat(ipad, msg))));
	}

	function pbkdf2Sha256(password, salt, iterations, length) {
		const out = new Uint8Array(length);
		for (let block = 1, pos = 0; pos < length; block++) {
			const index = new Uint8Array([block >>> 24, block >>> 16 & 255, block >>> 8 & 255, block & 255]);
			let u = hmacSha256(password, concat(salt, index));
			const t = u.slice();
			for (let i = 1; i < iterations; i++) {
				u = hmacSha256(password, u);
				for (let j = 0; j < 32; j++) t[j] ^= u[j];
			}
			out.set(t.subarray(0, Math.min(32, length - pos)), pos);
			pos += 32;
		}
		return out;
	}

	const ascii = (s) => new Uint8Array([...s].map((ch) => ch.charCodeAt(0)));

	// A PIN is letters A-Z and digits 0-9, case-insensitive (SPEC §3.2).
	function normalizePin(pin) {
		pin = pin.toUpperCase();
		if (!/^[A-Z0-9]+$/.test(pin)) throw new Error("a PIN is letters A-Z and digits 0-9");
		return pin;
	}

	function pinXor(entropy, pin) {
		const key = pbkdf2Sha256(ascii(normalizePin(pin)), ascii(PIN_SALT), PIN_ITERATIONS, entropy.length);
		return entropy.map((b, i) => b ^ key[i]);
	}

	// ---- BIP-39 ------------------------------------------------------

	function mnemonicToEntropy(text) {
		const words = text.trim().toLowerCase().split(/\s+/);
		if (words.length !== 12 && words.length !== 24) throw new Error("a seed has 12 or 24 words");
		let bits = "";
		for (const w of words) {
			const i = BIP39_ENGLISH.indexOf(w);
			if (i < 0) throw new Error("\"" + w + "\" is not a BIP-39 word");
			bits += i.toString(2).padStart(11, "0");
		}
		const entBits = words.length * 32 / 3;
		const entropy = new Uint8Array(entBits / 8);
		for (let i = 0; i < entropy.length; i++) entropy[i] = parseInt(bits.slice(8 * i, 8 * i + 8), 2);
		const check = [...sha256(entropy)].map((b) => b.toString(2).padStart(8, "0")).join("");
		if (bits.slice(entBits) !== check.slice(0, entBits / 32)) throw new Error("wrong checksum: not a valid seed");
		return entropy;
	}

	function entropyToMnemonic(entropy) {
		const bits = [...entropy].map((b) => b.toString(2).padStart(8, "0")).join("")
			+ [...sha256(entropy)].map((b) => b.toString(2).padStart(8, "0")).join("").slice(0, entropy.length / 4);
		const words = [];
		for (let i = 0; i < bits.length; i += 11) words.push(BIP39_ENGLISH[parseInt(bits.slice(i, i + 11), 2)]);
		return words.join(" ");
	}

	// ---- Reed-Solomon over GF(256), as in QR codes -------------------

	const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
	for (let i = 0, x = 1; i < 255; i++) {
		EXP[i] = x; LOG[x] = i;
		x <<= 1;
		if (x & 0x100) x ^= 0x11d;
	}
	for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
	const mul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];
	const div = (a, b) => a === 0 ? 0 : EXP[(LOG[a] + 255 - LOG[b]) % 255];
	const polyEval = (p, x) => p.reduce((y, c) => mul(y, x) ^ c, 0);

	function rsCorrect(codewords, nsym) {
		const n = codewords.length;
		const synd = [];
		for (let i = 0; i < nsym; i++) synd.push(polyEval(codewords, EXP[i]));
		if (synd.every((s) => s === 0)) return [codewords.slice(), 0];
		let lam = [1], prev = [1], L = 0, m = 1, b = 1;
		for (let i = 0; i < nsym; i++) {
			let d = synd[i];
			for (let j = 1; j <= L; j++) d ^= mul(lam[j] || 0, synd[i - j]);
			if (d === 0) { m++; continue; }
			const coef = div(d, b);
			const shifted = new Array(m).fill(0).concat(prev.map((c) => mul(coef, c)));
			const size = Math.max(lam.length, shifted.length);
			const next = [];
			for (let j = 0; j < size; j++) next.push((lam[j] || 0) ^ (shifted[j] || 0));
			if (2 * L <= i) { prev = lam; L = i + 1 - L; b = d; m = 1; } else m++;
			lam = next;
		}
		lam = lam.slice(0, L + 1);
		while (lam.length < L + 1) lam.push(0);
		if (L === 0 || 2 * L > nsym) throw new DecodeError("too many errors to correct");
		const positions = [];
		for (let p = 0; p < n; p++) if (polyEval([...lam].reverse(), EXP[(255 - p) % 255]) === 0) positions.push(p);
		if (positions.length !== L) throw new DecodeError("too many errors to correct");
		const omega = new Array(nsym).fill(0);
		synd.forEach((s, i) => lam.forEach((l, j) => { if (i + j < nsym) omega[i + j] ^= mul(s, l); }));
		const fixed = codewords.slice();
		for (const p of positions) {
			const xinv = EXP[(255 - p) % 255];
			let num = 0, den = 0;
			omega.forEach((o, i) => { num ^= mul(o, EXP[(LOG[xinv] * i) % 255]); });
			for (let j = 1; j < lam.length; j += 2) den ^= mul(lam[j], EXP[(LOG[xinv] * (j - 1)) % 255]);
			fixed[n - 1 - p] ^= mul(EXP[p % 255], div(num, den));
		}
		for (let i = 0; i < nsym; i++) if (polyEval(fixed, EXP[i]) !== 0) throw new DecodeError("too many errors to correct");
		return [fixed, positions.length];
	}

	return { PIN_SALT, DecodeError, sha256, pbkdf2Sha256, normalizePin, pinXor, mnemonicToEntropy, entropyToMnemonic, rsCorrect };
})();
