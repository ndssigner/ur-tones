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

	// ---- a seed's fingerprint (BIP-32), to compare sender and receiver ----
	// SHA-512 (in 32-bit halves), HMAC-SHA512, PBKDF2-SHA512, RIPEMD-160 and
	// secp256k1 (BigInt): the master key's fingerprint, as wallets show it.

	const K512 = [
		"428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc", "3956c25bf348b538",
		"59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118", "d807aa98a3030242", "12835b0145706fbe",
		"243185be4ee4b28c", "550c7dc3d5ffb4e2", "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235",
		"c19bf174cf692694", "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
		"2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5", "983e5152ee66dfab",
		"a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4", "c6e00bf33da88fc2", "d5a79147930aa725",
		"06ca6351e003826f", "142929670a0e6e70", "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed",
		"53380d139d95b3df", "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
		"a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30", "d192e819d6ef5218",
		"d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8", "19a4c116b8d2d0c8", "1e376c085141ab53",
		"2748774cdf8eeb99", "34b0bcb5e19b48a8", "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373",
		"682e6ff3d6b2b8a3", "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
		"90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b", "ca273eceea26619c",
		"d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178", "06f067aa72176fba", "0a637dc5a2c898a6",
		"113f9804bef90dae", "1b710b35131c471b", "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc",
		"431d67c49c100d4c", "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"]
		.flatMap((x) => [parseInt(x.slice(0, 8), 16) | 0, parseInt(x.slice(8), 16) | 0]);

	function sha512(data) {
		const len = data.length;
		const padded = new Uint8Array(((len + 17 + 127) >> 7) << 7);
		padded.set(data);
		padded[len] = 0x80;
		const view = new DataView(padded.buffer);
		view.setUint32(padded.length - 8, Math.floor(len / 0x20000000));
		view.setUint32(padded.length - 4, (len * 8) >>> 0);
		const H = new Int32Array([0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
			0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179]);
		const W = new Int32Array(160);
		// a 64-bit value is (hi, lo); rotr / shr by n bits
		const rh = (h, l, n) => n < 32 ? (h >>> n) | (l << (32 - n)) : (l >>> (n - 32)) | (h << (64 - n));
		const rl = (h, l, n) => n < 32 ? (l >>> n) | (h << (32 - n)) : (h >>> (n - 32)) | (l << (64 - n));
		for (let off = 0; off < padded.length; off += 128) {
			for (let i = 0; i < 32; i++) W[i] = view.getInt32(off + i * 4);
			for (let i = 16; i < 80; i++) {
				const h15 = W[2 * i - 30], l15 = W[2 * i - 29], h2 = W[2 * i - 4], l2 = W[2 * i - 3];
				const s0h = rh(h15, l15, 1) ^ rh(h15, l15, 8) ^ (h15 >>> 7);
				const s0l = rl(h15, l15, 1) ^ rl(h15, l15, 8) ^ ((l15 >>> 7) | (h15 << 25));
				const s1h = rh(h2, l2, 19) ^ rh(h2, l2, 61) ^ (h2 >>> 6);
				const s1l = rl(h2, l2, 19) ^ rl(h2, l2, 61) ^ ((l2 >>> 6) | (h2 << 26));
				let lo = (s0l >>> 0) + (s1l >>> 0) + (W[2 * i - 13] >>> 0) + (W[2 * i - 31] >>> 0);
				let hi = s0h + s1h + W[2 * i - 14] + W[2 * i - 32] + Math.floor(lo / 0x100000000);
				W[2 * i] = hi | 0; W[2 * i + 1] = lo | 0;
			}
			let [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl] = H;
			for (let i = 0; i < 80; i++) {
				const S1h = rh(eh, el, 14) ^ rh(eh, el, 18) ^ rh(eh, el, 41);
				const S1l = rl(eh, el, 14) ^ rl(eh, el, 18) ^ rl(eh, el, 41);
				const chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl);
				let lo = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + (K512[2 * i + 1] >>> 0) + (W[2 * i + 1] >>> 0);
				const t1h = (hh + S1h + chh + K512[2 * i] + W[2 * i] + Math.floor(lo / 0x100000000)) | 0, t1l = lo | 0;
				const S0h = rh(ah, al, 28) ^ rh(ah, al, 34) ^ rh(ah, al, 39);
				const S0l = rl(ah, al, 28) ^ rl(ah, al, 34) ^ rl(ah, al, 39);
				const mjh = (ah & bh) ^ (ah & ch) ^ (bh & ch), mjl = (al & bl) ^ (al & cl) ^ (bl & cl);
				lo = (S0l >>> 0) + (mjl >>> 0);
				const t2h = (S0h + mjh + Math.floor(lo / 0x100000000)) | 0, t2l = lo | 0;
				hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
				lo = (dl >>> 0) + (t1l >>> 0);
				eh = (dh + t1h + Math.floor(lo / 0x100000000)) | 0; el = lo | 0;
				dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
				lo = (t1l >>> 0) + (t2l >>> 0);
				ah = (t1h + t2h + Math.floor(lo / 0x100000000)) | 0; al = lo | 0;
			}
			const v = [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl];
			for (let i = 0; i < 16; i += 2) {
				const lo = (H[i + 1] >>> 0) + (v[i + 1] >>> 0);
				H[i] = H[i] + v[i] + Math.floor(lo / 0x100000000);
				H[i + 1] = lo | 0;
			}
		}
		const out = new Uint8Array(64), ov = new DataView(out.buffer);
		for (let i = 0; i < 16; i++) ov.setInt32(i * 4, H[i]);
		return out;
	}

	function hmacSha512(key, msg) {
		if (key.length > 128) key = sha512(key);
		const k = new Uint8Array(128);
		k.set(key);
		const ipad = k.map((x) => x ^ 0x36), opad = k.map((x) => x ^ 0x5c);
		return sha512(concat(opad, sha512(concat(ipad, msg))));
	}

	function pbkdf2Sha512(password, salt, iterations) {   // one block: 64 bytes
		let u = hmacSha512(password, concat(salt, new Uint8Array([0, 0, 0, 1])));
		const t = u.slice();
		for (let i = 1; i < iterations; i++) {
			u = hmacSha512(password, u);
			for (let j = 0; j < 64; j++) t[j] ^= u[j];
		}
		return t;
	}

	function ripemd160(data) {
		const len = data.length;
		const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
		padded.set(data);
		padded[len] = 0x80;
		const view = new DataView(padded.buffer);
		view.setUint32(padded.length - 8, (len * 8) >>> 0, true);
		view.setUint32(padded.length - 4, Math.floor(len / 0x20000000), true);
		const R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
			3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
			4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
		const R2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
			15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
			12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
		const S1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
			11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
			9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
		const S2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
			9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
			8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
		const K1 = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e], K2 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
		const f = (j, x, y, z) => j < 16 ? x ^ y ^ z : j < 32 ? (x & y) | (~x & z) : j < 48 ? (x | ~y) ^ z
			: j < 64 ? (x & z) | (y & ~z) : x ^ (y | ~z);
		const rotl = (x, n) => (x << n) | (x >>> (32 - n));
		const h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
		const X = new Int32Array(16);
		for (let off = 0; off < padded.length; off += 64) {
			for (let i = 0; i < 16; i++) X[i] = view.getInt32(off + i * 4, true);
			let [a1, b1, c1, d1, e1] = h, [a2, b2, c2, d2, e2] = h;
			for (let j = 0; j < 80; j++) {
				const r = j >> 4;
				let t = (rotl((a1 + f(j, b1, c1, d1) + X[R1[j]] + K1[r]) | 0, S1[j]) + e1) | 0;
				a1 = e1; e1 = d1; d1 = rotl(c1, 10); c1 = b1; b1 = t;
				t = (rotl((a2 + f(79 - j, b2, c2, d2) + X[R2[j]] + K2[r]) | 0, S2[j]) + e2) | 0;
				a2 = e2; e2 = d2; d2 = rotl(c2, 10); c2 = b2; b2 = t;
			}
			const t = (h[1] + c1 + d2) | 0;
			h[1] = (h[2] + d1 + e2) | 0; h[2] = (h[3] + e1 + a2) | 0; h[3] = (h[4] + a1 + b2) | 0;
			h[4] = (h[0] + b1 + c2) | 0; h[0] = t;
		}
		const out = new Uint8Array(20), ov = new DataView(out.buffer);
		for (let i = 0; i < 5; i++) ov.setInt32(i * 4, h[i], true);
		return out;
	}

	// secp256k1: k·G, compressed (Jacobian coordinates, BigInt)
	const P = 2n ** 256n - 2n ** 32n - 977n;
	const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
	const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
	const mod = (a) => { a %= P; return a < 0n ? a + P : a; };
	function inv(a) {   // a^(p-2)
		let r = 1n, b = mod(a), e = P - 2n;
		while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; }
		return r;
	}
	function dbl([x, y, z]) {
		if (y === 0n) return [0n, 1n, 0n];
		const s = mod(4n * x * y * y), m = mod(3n * x * x);
		const x3 = mod(m * m - 2n * s);
		return [x3, mod(m * (s - x3) - 8n * y * y * y * y), mod(2n * y * z)];
	}
	function add(p1, p2) {
		if (p1[2] === 0n) return p2;
		if (p2[2] === 0n) return p1;
		const [x1, y1, z1] = p1, [x2, y2, z2] = p2;
		const z1z1 = z1 * z1 % P, z2z2 = z2 * z2 % P;
		const u1 = x1 * z2z2 % P, u2 = x2 * z1z1 % P;
		const s1 = y1 * z2 * z2z2 % P, s2 = y2 * z1 * z1z1 % P;
		if (u1 === u2) return s1 === s2 ? dbl(p1) : [0n, 1n, 0n];
		const hh = mod(u2 - u1), r = mod(s2 - s1), h2 = hh * hh % P, h3 = h2 * hh % P;
		const x3 = mod(r * r - h3 - 2n * u1 * h2);
		return [x3, mod(r * (u1 * h2 - x3) - s1 * h3), z1 * z2 % P * hh % P];
	}
	function pubkey(priv) {
		let k = BigInt("0x" + hex(priv)), q = [0n, 1n, 0n], g = [GX, GY, 1n];
		while (k > 0n) { if (k & 1n) q = add(q, g); g = dbl(g); k >>= 1n; }
		const zi = inv(q[2]), zi2 = zi * zi % P;
		const x = q[0] * zi2 % P, y = q[1] * zi2 % P * zi % P;
		return concat(new Uint8Array([y & 1n ? 3 : 2]), fromHexString(x.toString(16).padStart(64, "0")));
	}
	const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
	const fromHexString = (s) => Uint8Array.from(s.match(/../g), (x) => parseInt(x, 16));

	// The seed's fingerprint without a passphrase (8 hex digits), as NDS-Signer,
	// SeedSigner and wallets show it: HASH160 of the BIP-32 master public key.
	function fingerprint(entropy) {
		const seed = pbkdf2Sha512(ascii(entropyToMnemonic(entropy)), ascii("mnemonic"), 2048);
		const master = hmacSha512(ascii("Bitcoin seed"), seed);
		return hex(ripemd160(sha256(pubkey(master.subarray(0, 32))))).slice(0, 8);
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

	return { PIN_SALT, DecodeError, sha256, sha512, ripemd160, fingerprint, pbkdf2Sha256, normalizePin, pinXor, mnemonicToEntropy, entropyToMnemonic, rsCorrect };
})();
