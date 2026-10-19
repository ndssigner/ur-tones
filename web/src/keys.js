// ur-tones web tool: public keys as URs. xpubs (and SLIP-132's ypub,
// zpub…), output descriptors and accounts, both as the current UR types
// (hdkey, output-descriptor and account-descriptor: BCR-2020-007 v2,
// BCR-2023-010, BCR-2023-019) and as the older ones (crypto-hdkey,
// crypto-output, crypto-account: BCR-2020-007 v1, BCR-2020-010,
// BCR-2020-015). Public keys only: a private key (xprv, WIF) is refused.
// Checked against those documents' test vectors and urtypes (web/test.mjs).
"use strict";

const UrTonesKeys = (() => {
	const S = UrTonesCrypto;
	const { DecodeError } = S;
	const cat = (...parts) => {
		const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
		let i = 0;
		for (const p of parts) { out.set(p, i); i += p.length; }
		return out;
	};
	const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
	const fromHex = (s) => Uint8Array.from(s.match(/../g), (x) => parseInt(x, 16));
	const u32 = (b, i) => ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
	const be32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

	// ---- Base58Check ----------------------------------------------------
	const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	const sha256d = (b) => S.sha256(S.sha256(b));
	function toBase58Check(payload) {
		const data = cat(payload, sha256d(payload).slice(0, 4));
		let n = 0n, s = "";
		for (const b of data) n = n * 256n + BigInt(b);
		while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
		for (const b of data) { if (b) break; s = "1" + s; }
		return s;
	}
	function fromBase58Check(s) {
		let n = 0n;
		for (const c of s) {
			const i = B58.indexOf(c);
			if (i < 0) throw new DecodeError("not Base58");
			n = n * 58n + BigInt(i);
		}
		const bytes = [];
		while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
		for (const c of s) { if (c !== "1") break; bytes.unshift(0); }
		const d = Uint8Array.from(bytes), p = d.slice(0, -4);
		if (d.length < 5 || hex(sha256d(p).slice(0, 4)) !== hex(d.slice(-4))) throw new DecodeError("wrong Base58 checksum");
		return p;
	}

	// ---- extended public keys (BIP-32), with SLIP-132's prefixes ----------
	// version -> [prefix, network (0 main, 1 test), script around the key or null]
	const VERSIONS = {
		"0488b21e": ["xpub", 0, null], "049d7cb2": ["ypub", 0, "sh(wpkh(@0))"], "04b24746": ["zpub", 0, "wpkh(@0)"],
		"0295b43f": ["Ypub", 0, "sh(wsh(cosigner(@0)))"], "02aa7ed3": ["Zpub", 0, "wsh(cosigner(@0))"],
		"043587cf": ["tpub", 1, null], "044a5262": ["upub", 1, "sh(wpkh(@0))"], "045f1cf6": ["vpub", 1, "wpkh(@0)"],
		"024289ef": ["Upub", 1, "sh(wsh(cosigner(@0)))"], "02575483": ["Vpub", 1, "wsh(cosigner(@0))"],
	};
	const VERSION_OF = Object.fromEntries(Object.entries(VERSIONS).map(([v, [p]]) => [p, v]));
	const PRIVATE = "a private key: only public keys (xpub…) go here";
	function parseXpub(s) {
		const p = fromBase58Check(s);
		if (p.length !== 78) throw new DecodeError("not an extended key");
		const v = VERSIONS[hex(p.slice(0, 4))];
		if (p[45] === 0) throw new DecodeError(PRIVATE);
		if (!v) throw new DecodeError("unknown extended key version");
		return { prefix: v[0], network: v[1], script: v[2], depth: p[4], parent: u32(p, 5), child: u32(p, 9),
			chain: p.slice(13, 45), key: p.slice(45, 78) };
	}
	const xpubText = (k, prefix) => toBase58Check(cat(fromHex(VERSION_OF[prefix || (k.network ? "tpub" : "xpub")]),
		Uint8Array.of(k.depth), be32(k.parent), be32(k.child), k.chain, k.key));

	// ---- CBOR, deterministic (dCBOR): what these types need ---------------
	class Tag { constructor(tag, value) { this.tag = tag; this.value = value; } }
	function head(major, n) {
		if (n < 24) return Uint8Array.of(major << 5 | n);
		if (n < 256) return Uint8Array.of(major << 5 | 24, n);
		if (n < 65536) return Uint8Array.of(major << 5 | 25, n >> 8, n & 255);
		return cat(Uint8Array.of(major << 5 | 26), be32(n));
	}
	// maps are objects with integer keys (in ascending order, as dCBOR sorts them)
	function encode(v) {
		if (v instanceof Tag) return cat(head(6, v.tag), encode(v.value));
		if (ArrayBuffer.isView(v)) return cat(head(2, v.length), v);
		if (typeof v === "number") return head(0, v);
		if (typeof v === "boolean") return Uint8Array.of(v ? 0xf5 : 0xf4);
		if (typeof v === "string") { const b = new TextEncoder().encode(v); return cat(head(3, b.length), b); }
		if (Array.isArray(v)) return cat(head(4, v.length), ...v.map(encode));
		const keys = Object.keys(v).map(Number).filter((k) => v[k] !== undefined).sort((a, b) => a - b);
		return cat(head(5, keys.length), ...keys.flatMap((k) => [head(0, k), encode(v[k])]));
	}
	function decode(buf) {
		let i = 0;
		const item = (depth) => {
			if (depth > 32 || i >= buf.length) throw new DecodeError("CBOR: truncated");
			const major = buf[i] >> 5, info = buf[i++] & 31;
			if (major === 7) {
				if (info === 20 || info === 21) return info === 21;
				throw new DecodeError("CBOR: unexpected simple value");
			}
			let n = info;
			if (info >= 24) {
				const size = { 24: 1, 25: 2, 26: 4 }[info];
				if (!size || i + size > buf.length) throw new DecodeError("CBOR: bad length");
				n = 0;
				for (let j = 0; j < size; j++) n = n * 256 + buf[i++];
			}
			if (major === 0) return n;
			if (major === 2 || major === 3) {
				if (i + n > buf.length) throw new DecodeError("CBOR: truncated");
				const b = buf.slice(i, i += n);
				return major === 2 ? b : new TextDecoder("utf-8", { fatal: true }).decode(b);
			}
			if (major === 4) return Array.from({ length: n }, () => item(depth + 1));
			if (major === 5) {
				const m = {};
				for (let j = 0; j < n; j++) {
					const k = item(depth + 1);
					if (typeof k !== "number") throw new DecodeError("CBOR: map keys are integers here");
					m[k] = item(depth + 1);
				}
				return m;
			}
			if (major === 6) return new Tag(n, item(depth + 1));
			throw new DecodeError("CBOR: unexpected item");
		};
		const v = item(0);
		if (i !== buf.length) throw new DecodeError("CBOR: trailing bytes");
		return v;
	}

	// ---- the two generations of tags ---------------------------------------
	const CURRENT = { hdkey: 40303, keypath: 40304, coin: 40305, eckey: 40306, output: 40308,
		types: { hdkey: "hdkey", output: "output-descriptor", account: "account-descriptor" } };
	const LEGACY = { hdkey: 303, keypath: 304, coin: 305, eckey: 306,
		types: { hdkey: "crypto-hdkey", output: "crypto-output", account: "crypto-account" } };
	const GEN = { "hdkey": CURRENT, "output-descriptor": CURRENT, "account-descriptor": CURRENT,
		"crypto-hdkey": LEGACY, "crypto-output": LEGACY, "crypto-account": LEGACY };
	// BCR-2020-010's script expressions (crypto-output)
	const SCRIPTS = { sh: 400, wsh: 401, pk: 402, pkh: 403, wpkh: 404, combo: 405, multi: 406, sortedmulti: 407, tr: 409, cosigner: 410 };
	const SCRIPT_OF = Object.fromEntries(Object.entries(SCRIPTS).map(([k, v]) => [v, k]));

	// ---- descriptors' text: checksum, paths, keys ---------------------------
	const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
	const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	const GENERATOR = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
	function checksum(s) { // Bitcoin Core's descriptor checksum
		const symbols = [], groups = [];
		for (const c of s) {
			const v = INPUT_CHARSET.indexOf(c);
			if (v < 0) throw new DecodeError("a character descriptors do not use");
			symbols.push(v & 31); groups.push(v >> 5);
			if (groups.length === 3) symbols.push(groups.shift() * 9 + groups.shift() * 3 + groups.shift());
		}
		if (groups.length === 1) symbols.push(groups[0]);
		else if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
		let chk = 1n;
		for (const value of [...symbols, 0, 0, 0, 0, 0, 0, 0, 0]) {
			const top = chk >> 35n;
			chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(value);
			for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= GENERATOR[i];
		}
		chk ^= 1n;
		return Array.from({ length: 8 }, (_, i) => CHECKSUM_CHARSET[Number((chk >> BigInt(5 * (7 - i))) & 31n)]).join("");
	}
	const withChecksum = (s) => s + "#" + checksum(s);

	// a path: [{index, hardened} | {wildcard, hardened} | {pair: [{index, hardened}, …]}]
	function parsePath(text) {
		return text.split("/").filter(Boolean).map((c) => {
			const h = /['hH]$/.test(c), v = h ? c.slice(0, -1) : c;
			if (v === "*") return { wildcard: true, hardened: h };
			if (/^<.*>$/.test(c)) return { pair: c.slice(1, -1).split(";").map((x) => parsePath(x)[0]) };
			if (!/^\d+$/.test(v) || +v >= 0x80000000) throw new DecodeError("a bad derivation step: " + c);
			return { index: +v, hardened: h };
		});
	}
	const stepText = (c) => c.pair ? "<" + c.pair.map(stepText).join(";") + ">" : (c.wildcard ? "*" : c.index) + (c.hardened ? "'" : "");
	const pathText = (p) => p.map((c) => "/" + stepText(c)).join("");
	function pathToCbor(path, gen) {
		return path.flatMap((c) => {
			if (c.pair) {
				if (gen !== CURRENT) throw new DecodeError("<a;b> paths only in the current UR types");
				return [c.pair.flatMap((x) => [x.index, x.hardened])];
			}
			return [c.wildcard ? [] : c.index, c.hardened];
		});
	}
	function pathFromCbor(a) {
		const out = [];
		for (let i = 0; i < a.length;) {
			const c = a[i];
			if (Array.isArray(c) && c.length) {
				const pair = [];
				for (let j = 0; j < c.length; j += 2) pair.push({ index: c[j], hardened: c[j + 1] });
				out.push({ pair }); i += 1;
			} else { out.push(Array.isArray(c) ? { wildcard: true, hardened: a[i + 1] } : { index: c, hardened: a[i + 1] }); i += 2; }
		}
		return out;
	}

	// a key: {hd: parsed xpub, fp (source fingerprint) or null, origin (path), children (path)} or {ec: bytes}
	const KEY_RE = /(\[([0-9a-fA-F]{8})((?:\/[0-9]+['hH]?)*)\])?([1-9A-HJ-NP-Za-km-z]{100,115}|0[23][0-9a-fA-F]{64}|04[0-9a-fA-F]{128}|[0-9a-fA-F]{64})((?:\/(?:[0-9]+['hH]?|<[0-9;'hH]+>|\*['hH]?))*)/g;
	function parseKey(m) {
		const [, , fp, origin, body, children] = m;
		if (/^[0-9a-fA-F]+$/.test(body)) {
			if (children) throw new DecodeError("a plain public key has no derivation");
			return { ec: fromHex(body.toLowerCase()), fp: fp ? parseInt(fp, 16) : null, origin: origin ? parsePath(origin) : [] };
		}
		return { hd: parseXpub(body), fp: fp ? parseInt(fp, 16) : null, origin: origin ? parsePath(origin) : null, children: parsePath(children) };
	}
	function keyText(k) {
		const origin = k.fp !== null ? `[${k.fp.toString(16).padStart(8, "0")}${pathText(k.origin || [])}]` : "";
		return k.ec ? origin + hex(k.ec) : origin + xpubText(k.hd) + pathText(k.children);
	}

	// one descriptor's text -> {source with @0, @1…, keys}
	function parseDescriptor(text) {
		let s = text.trim();
		const sum = /#([a-z0-9]{8})$/.exec(s);
		if (sum) {
			s = s.slice(0, -9);
			if (checksum(s) !== sum[1]) throw new DecodeError("wrong descriptor checksum");
		}
		if (/\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b|[xtyzuvYZUV]prv/.test(s)) throw new DecodeError(PRIVATE);
		if (!/^[a-z]+\(.*\)$/.test(s)) throw new DecodeError("not a descriptor");
		const keys = [];
		const source = s.replace(KEY_RE, (...m) => { keys.push(parseKey(m)); return "@" + (keys.length - 1); });
		if (!keys.length) throw new DecodeError("a descriptor without keys");
		return { source, keys };
	}
	const descriptorText = (d) => withChecksum(d.source.replace(/@(\d+)/g, (_, i) => keyText(d.keys[+i])));

	// ---- keys <-> CBOR ---------------------------------------------------------
	function keyToCbor(k, gen) {
		if (k.ec) return new Tag(gen.eckey, { 3: k.ec });
		const hd = k.hd, origin = k.origin || (hd.depth ? [{ index: hd.child & 0x7fffffff, hardened: hd.child >= 0x80000000 }] : []);
		if (k.origin && k.origin.length !== hd.depth) throw new DecodeError("the key's origin path and its depth disagree");
		return new Tag(gen.hdkey, {
			3: hd.key, 4: hd.chain,
			5: hd.network ? new Tag(gen.coin, { 2: 1 }) : undefined,
			6: origin.length || k.fp !== null ? new Tag(gen.keypath, { 1: pathToCbor(origin, gen), 2: k.fp ?? undefined,
				3: origin.length !== hd.depth ? hd.depth : undefined }) : undefined,
			7: k.children && k.children.length ? new Tag(gen.keypath, { 1: pathToCbor(k.children, gen) }) : undefined,
			8: hd.depth ? hd.parent : undefined,
		});
	}
	const untag = (v, tags) => {
		if (!(v instanceof Tag) || !tags.includes(v.tag)) throw new DecodeError("unexpected CBOR tag");
		return v.value;
	};
	function keyFromCbor(v, masterFp = null) {
		if (v instanceof Tag && (v.tag === 40306 || v.tag === 306)) {
			if (v.value[2]) throw new DecodeError(PRIVATE);
			return { ec: v.value[3], fp: null, origin: [] };
		}
		const m = untag(v, [40303, 303]);
		return hdFromMap(m, masterFp);
	}
	function hdFromMap(m, masterFp = null) {
		if (m[1]) throw new DecodeError("a master key: not an account's public key");
		if (m[2]) throw new DecodeError(PRIVATE);
		if (!ArrayBuffer.isView(m[3]) || m[3].length !== 33) throw new DecodeError("hdkey: no public key");
		const origin = m[6] ? untag(m[6], [40304, 304]) : { 1: [] };
		const path = pathFromCbor(origin[1] || []);
		const depth = origin[3] ?? path.length, last = path[path.length - 1];
		const use = m[5] ? untag(m[5], [40305, 305]) : {};
		const fp = origin[2] ?? (path.length === depth ? masterFp : null);
		return {
			hd: { network: use[2] ? 1 : 0, depth, parent: m[8] ?? (path.length === 1 && fp !== null ? fp : 0),
				child: last && !last.pair && !last.wildcard ? last.index + (last.hardened ? 0x80000000 : 0) : 0,
				chain: m[4] || new Uint8Array(32), key: m[3] },
			fp, origin: path.length === depth ? path : null,
			children: m[7] ? pathFromCbor(untag(m[7], [40304, 304])[1] || []) : [],
		};
	}

	// a descriptor -> crypto-output (BCR-2020-010): the script functions as tags
	function legacyOutput(d, gen) {
		const parse = (s) => {
			const m = /^([a-z]+)\((.*)\)$/.exec(s);
			if (!m) {
				if (!/^@\d+$/.test(s)) throw new DecodeError("not in crypto-output: " + s);
				return keyToCbor(d.keys[+s.slice(1)], gen);
			}
			const tag = SCRIPTS[m[1]];
			if (!tag) throw new DecodeError(`${m[1]}() only in the current UR types`);
			if (m[1] === "multi" || m[1] === "sortedmulti") {
				const [k, ...keys] = m[2].split(",");
				return new Tag(tag, { 1: +k, 2: keys.map((x) => parse(x)) });
			}
			if (m[2].includes(",")) throw new DecodeError(`${m[1]}() with several arguments only in the current UR types`);
			return new Tag(tag, parse(m[2]));
		};
		return parse(d.source);
	}
	function legacyOutputText(v, masterFp) {
		const keys = [];
		const walk = (x) => {
			if (x instanceof Tag && SCRIPT_OF[x.tag]) {
				const name = SCRIPT_OF[x.tag];
				if (name === "multi" || name === "sortedmulti") return `${name}(${x.value[1]},${x.value[2].map(walk).join(",")})`;
				return `${name}(${walk(x.value)})`;
			}
			keys.push(keyFromCbor(x, masterFp));
			return "@" + (keys.length - 1);
		};
		const source = walk(v);
		return { source, keys };
	}
	function outputFromCbor(m, masterFp) {
		if (typeof m[1] !== "string") throw new DecodeError("output-descriptor: no source");
		return { source: m[1], keys: (m[2] || []).map((k) => keyFromCbor(k, masterFp)), name: m[3], note: m[4] };
	}

	// ---- what the send screen accepts --------------------------------------------
	// text: an xpub (or ypub, zpub…), a descriptor, or several descriptors of
	// one account (one per line). Returns {what, descriptors, toUR(current)}.
	function fromText(text) {
		const lines = text.trim().split(/\s*\n\s*/).filter(Boolean);
		if (lines.length === 1 && /^[1-9A-HJ-NP-Za-km-z]{100,115}$/.test(lines[0])) {
			const hd = parseXpub(lines[0]), key = { hd, fp: null, origin: null, children: [] };
			if (!hd.script) return {
				what: "xpub", key, descriptors: [],
				toUR: (current) => { const g = current ? CURRENT : LEGACY; return { type: g.types.hdkey, cbor: encode(keyToCbor(key, g).value) }; },
			};
			const d = { source: hd.script, keys: [key] };
			return { what: hd.prefix, descriptors: [descriptorText(d)], toUR: (current) => outputUR(d, current) };
		}
		const ds = lines.map(parseDescriptor);
		if (ds.length === 1) return { what: "descriptor", descriptors: ds.map(descriptorText), toUR: (current) => outputUR(ds[0], current) };
		// an account: several descriptors, each one account-level key from the same master
		const fps = new Set(ds.flatMap((d) => d.keys.map((k) => k.fp)));
		if (fps.size !== 1 || fps.has(null) || ds.some((d) => d.keys.length !== 1 || !d.keys[0].hd || d.keys[0].children.length))
			throw new DecodeError("an account: one key per descriptor, all from one master fingerprint, without /0/*");
		const mfp = [...fps][0];
		return {
			what: "account", descriptors: ds.map(descriptorText),
			toUR: (current) => current
				? { type: CURRENT.types.account, cbor: encode({ 1: mfp, 2: ds.map((d) => new Tag(CURRENT.output, outputMap(d))) }) }
				: { type: LEGACY.types.account, cbor: encode({ 1: mfp, 2: ds.map((d) => legacyOutput(d, LEGACY)) }) },
		};
	}
	const outputMap = (d) => ({ 1: d.source, 2: d.keys.map((k) => keyToCbor(k, CURRENT)), 3: d.name, 4: d.note });
	const outputUR = (d, current) => current
		? { type: CURRENT.types.output, cbor: encode(outputMap(d)) }
		: { type: LEGACY.types.output, cbor: encode(legacyOutput(d, LEGACY)) };
	const looksLikeKeys = (text) => /^\s*(\[|[xyzXYZtuvUV](?:pub|prv)|[a-z]+\()/.test(text);

	// ---- what the listen screen shows ----------------------------------------------
	// {descriptors: [text], keys: [{xpub, slip132 or null, origin text}], name}
	function describe(type, cbor) {
		const v = decode(cbor);
		let ds, mfp = null;
		if (type === "hdkey" || type === "crypto-hdkey") ds = [{ source: "@0", keys: [hdFromMap(v)] }];
		else if (type === "output-descriptor") ds = [outputFromCbor(v)];
		else if (type === "crypto-output") ds = [legacyOutputText(v)];
		else if (type === "account-descriptor" || type === "crypto-account") {
			mfp = v[1];
			ds = (v[2] || []).map((o) => type === "account-descriptor" ? outputFromCbor(untag(o, [40308]), mfp) : legacyOutputText(o, mfp));
		} else throw new DecodeError("not a key UR type");
		const keys = ds.flatMap((d) => d.keys.filter((k) => k.hd).map((k) => {
			const script = d.keys.length === 1 && !k.children.length && Object.values(VERSIONS).find(([p, n, s]) => s === d.source && n === k.hd.network);
			return { xpub: xpubText(k.hd), slip132: script ? xpubText(k.hd, script[0]) : null,
				origin: k.fp !== null ? `[${k.fp.toString(16).padStart(8, "0")}${pathText(k.origin || [])}]` : "" };
		}));
		const bare = type.endsWith("hdkey");
		return { descriptors: bare ? [] : ds.map(descriptorText), keys, names: ds.map((d) => d.name).filter(Boolean) };
	}
	const KEY_TYPES = Object.keys(GEN);

	return { KEY_TYPES, Tag, encode, decode, checksum, parseXpub, xpubText, toBase58Check, fromBase58Check,
		parseDescriptor, descriptorText, fromText, looksLikeKeys, describe };
})();
