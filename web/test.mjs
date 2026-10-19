// Tests of the web tool's JavaScript against the reference test vectors
// (vectors/ur-tones-v0.json) and Node.js's own crypto, plus audio through a
// simulated acoustic channel (as tests/acoustic.py).
//     node web/test.mjs
import { createHash, pbkdf2Sync } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const here = new URL(".", import.meta.url);
const read = (p) => readFileSync(new URL(p, here), "utf8");
const ctx = vm.createContext({});
for (const f of ["src/bip39-english.js", "src/crypto.js", "src/ur-tones.js"])
	vm.runInContext(read(f), ctx, { filename: f });
vm.runInContext("globalThis.C = UrTonesCrypto; globalThis.U = UrTones;", ctx);
const C = ctx.C, U = ctx.U;

let failures = 0, checks = 0;
const check = (ok, what) => { checks++; if (!ok) { failures++; console.log("FAIL", what); } };
const hex = (b) => Buffer.from(b).toString("hex");
let seed = 1;
const rand = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
const gauss = () => { let s = 0; for (let i = 0; i < 6; i++) s += rand(1000001) / 1000000; return (s - 3) / 0.7071; };

// crypto primitives against Node
for (const len of [0, 1, 55, 56, 63, 64, 65, 200]) {
	const data = Uint8Array.from({ length: len }, (_, i) => (i * 7 + 3) & 255);
	check(hex(C.sha256(data)) === createHash("sha256").update(data).digest("hex"), "sha256 len " + len);
}
for (const len of [0, 1, 111, 112, 127, 128, 129, 300]) {
	const data = Uint8Array.from({ length: len }, (_, i) => (i * 13 + 5) & 255);
	check(hex(C.sha512(data)) === createHash("sha512").update(data).digest("hex"), "sha512 len " + len);
}
const enc = new TextEncoder();
check(hex(C.ripemd160(new Uint8Array(0))) === "9c1185a5c5e9fc54612808977ee8f548b2258d31", "ripemd160 empty");
check(hex(C.ripemd160(enc.encode("abc"))) === "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "ripemd160 abc");
check(hex(C.ripemd160(enc.encode("a".repeat(1000)))) === "aa69deee9a8922e92f8105e007f76110f381e9cf", "ripemd160 1000 a");
// fingerprints as wallets show them (the BIP-39 test seed; NDS-Signer's test seed)
check(C.fingerprint(C.mnemonicToEntropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")) === "73c5da0a", "fingerprint abandon");
check(C.fingerprint(C.mnemonicToEntropy("height demise useless trap grow lion found off key clown transfer enroll")) === "8b218e81", "fingerprint height");
check(hex(C.pbkdf2Sha256(enc.encode("1234"), enc.encode(C.PIN_SALT), 10000, 32))
	=== pbkdf2Sync("1234", C.PIN_SALT, 10000, 32, "sha256").toString("hex"), "pbkdf2");

// new seeds from dice: SeedSigner's tests (tests/test_mnemonic_generation.py), and Coldcard's sample for 24 words
for (const [rolls, words, mnemonic] of [
	["12345612345612345612345612345612345612345612345612", 12, "unveil nice picture region tragic fault cream strike tourist control recipe tourist"],
	["11111111111111111111111111111111111111111111111111", 12, "diet glad hat rural panther lawsuit act drop gallery urge where fit"],
	["522222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555", 24, "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious"],
	["222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555556", 24, "lizard broken love tired depend eyebrow excess lonely advance father various cram ignore panic feed plunge miss regret boring unique galaxy fan detail fly"],
]) check(C.entropyToMnemonic(C.diceEntropy(rolls, words)) === mnemonic, "dice " + rolls.slice(0, 12));
check(hex(C.sha256(enc.encode("123456"))) === hex(C.mnemonicToEntropy("mirror reject rookie talk pudding throw happy era myth already payment own sentence push head sting video explain letter bomb casual hotel rather garment")), "dice: Coldcard's sample");
for (const [rolls, words] of [["1".repeat(49), 12], ["1".repeat(51), 12], ["1".repeat(49) + "7", 12], ["1".repeat(50), 24], ["1".repeat(99), 18]])
	check((() => { try { C.diceEntropy(rolls, words); return false; } catch (e) { return true; } })(), `dice refused: ${rolls.length} for ${words}`);
{
	const rolls = "3".repeat(50), extra = Uint8Array.from({ length: 32 }, (_, i) => i);
	check(hex(C.diceEntropy(rolls, 12, extra)) === createHash("sha256").update(rolls).update(extra).digest("hex").slice(0, 32), "dice mixed with extra bytes");
}

// vectors
const vectors = JSON.parse(read("../vectors/ur-tones-v0.json")).vectors;
check(C.fingerprint(C.mnemonicToEntropy(vectors.find((v) => v.mnemonic && v.mnemonic.split(" ").length === 24).mnemonic)) === "8c65eb9f", "fingerprint 24 words (embit)");
const bytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const substitute = (frame, positions) => {
	const t = [...frame];
	for (let i of positions) {
		i += 4;
		const choices = [...U.KEYS].filter((k) => k !== t[i] && k !== t[i - 1] && k !== t[i + 1]);
		t[i] = choices[rand(choices.length)];
	}
	return t.join("");
};
for (const v of vectors) {
	const name = `${v.name} pin=${v.pin}`;
	if (v.entropy) {
		const e = bytes(v.entropy);
		check(C.mnemonicToEntropy(v.mnemonic) && hex(C.mnemonicToEntropy(v.mnemonic)) === v.entropy, "mnemonic " + name);
		check(U.seedToKeypad(e, v.pin) === v.keypad, "keypad " + name);
		check(hex(U.keypadToSeed(v.keypad, v.pin)) === v.entropy, "keypad back " + name);
		check(U.seedToUR(e, v.pin) === v.ur, "seed UR " + name);
		check(hex(U.urToSeed(v.ur, v.pin)) === v.entropy, "seed UR back " + name);
	}
	(v.urs || [v.ur]).forEach((ur, i) => {
		const frame = v.frames[i];
		check(U.urToFrame(ur) === frame, "frame " + name);
		const back = U.frameToUR(frame);
		check(back.ur === ur && back.corrected === 0, "frame back " + name);
		const n = frame.length - 4;
		let all = true;
		for (let j = 0; j < n; j += 7) all = all && U.frameToUR(substitute(frame, [j])).ur === ur;
		check(all, "misheard tones repaired " + name);
		const j = 4 + rand(n);
		check(U.frameToUR(frame.slice(0, j) + frame.slice(j + 1)).ur === ur, "lost tone " + name);
		const extra = [...U.KEYS].find((k) => k !== frame[j - 1] && k !== frame[j]);
		check(U.frameToUR(frame.slice(0, j) + extra + frame.slice(j)).ur === ur, "extra tone " + name);
	});
	if (v.psbt_base64) {
		const psbt = Uint8Array.from(Buffer.from(v.psbt_base64, "base64"));
		const seqLen = new U.FountainEncoder(U.cborBytes(psbt), v.fragment).seqLen;
		const out = U.psbtToURs(psbt, v.fragment, v.urs.length - seqLen);
		check(JSON.stringify(out.urs) === JSON.stringify(v.urs), "fountain encoder = ur2 " + name);
		for (const drop of [[], [0, 1]]) {
			const dec = new U.FountainDecoder(), fe = new U.FountainEncoder(U.cborBytes(psbt), v.fragment);
			let sent = 0;
			while (!dec.done && sent < 200) { const part = fe.nextPart(); if (!drop.includes(sent++)) dec.receive(part); }
			check(dec.result && Buffer.from(U.cborToPsbt(dec.result)).toString("base64") === v.psbt_base64, `fountain decoder, dropping ${drop} ${name}`);
		}
	}
}

// xpubs, descriptors and bytes: the parts are ur2's, the frames to play are
// those, and the parts come back as the whole UR (what the web tool shows)
for (const v of vectors.filter((v) => v.cbor)) {
	const cbor = bytes(v.cbor), seqLen = new U.FountainEncoder(cbor, v.fragment).seqLen;
	check(U.urText(v.type, 0, cbor) === v.ur, "whole UR " + v.name);
	check(U.fitsOneFrame(v.ur) === v.fits_one_frame, "fits one frame " + v.name);
	check(JSON.stringify(U.messageToURs(v.type, cbor, v.fragment, v.urs.length - seqLen).urs) === JSON.stringify(v.urs), "fountain encoder = ur2 " + v.name);
	const gen = U.messageFrames(v.type, cbor, v.fragment);
	check(v.frames.every((f) => gen.next().value === f), "frames to play " + v.name);
	if (seqLen > 1) {
		const dec = new U.FountainDecoder();
		for (const f of v.frames) dec.receive(U.frameToUR(f).body);
		check(dec.result && U.urText(v.type, 0, dec.result) === v.ur, "parts back as the whole UR " + v.name);
	}
}
// a seed in parts (other senders may split one): back as the whole UR, then the seed
{
	const s = vectors.find((v) => v.entropy && v.pin), dec = new U.FountainDecoder();
	const enc = new U.FountainEncoder(U.parseUR(s.ur).body, 8, 4);
	for (let i = 0; i < enc.seqLen + 2; i++) dec.receive(U.frameToUR(U.urToFrame(U.urText("crypto-seed", 1, enc.nextPart()))).body);
	check(dec.result && hex(U.urToSeed(U.urText("crypto-seed", 0, dec.result), s.pin)) === s.entropy, "seed in parts");
}

// a simulated acoustic channel: a small speaker, a room, noise, fading
function channel(x, rate, { speakerFc = 900, rt60 = 0.4, wet = 0.6, noise = 0.01, fade = 0.3 } = {}) {
	const hp = (inp) => { const a = 1 / (1 + 2 * Math.PI * speakerFc / rate); let px = 0, py = 0; return inp.map((v) => { py = a * (py + v - px); px = v; return py; }); };
	let y = hp(hp(Array.from(x)));
	if (rt60) {
		const acc = new Array(y.length).fill(0);
		for (const ms of [29.7, 37.1, 41.1, 43.7]) {
			const d = Math.floor(rate * ms / 1000), g = 10 ** (-3 * ms / 1000 / rt60), buf = new Array(d).fill(0);
			y.forEach((v, i) => { const o = buf[i % d]; buf[i % d] = v + g * o; acc[i] += o / 4; });
		}
		let z = acc;
		for (const [ms, g] of [[5.0, 0.7], [1.7, 0.7]]) {
			const d = Math.floor(rate * ms / 1000), buf = new Array(d).fill(0);
			z = z.map((v, i) => { const b = buf[i % d], o = -g * v + b; buf[i % d] = v + g * o; return o; });
		}
		y = y.map((v, i) => v + wet * z[i]);
	}
	return Float32Array.from(y, (v, i) => v * (1 - fade / 2 + fade / 2 * Math.sin(2 * Math.PI * 0.7 * i / rate)) + noise * gauss());
}
{
	const s = vectors.find((v) => v.entropy && !v.pin), p = vectors.find((v) => v.psbt_base64);
	const groups = [s.keypad, s.frames[0], p.frames[0]];
	const expect = [s.entropy, s.ur, p.urs[0]];
	const decoded = (got) => got.map((g) => g.startsWith("*") ? hex(U.keypadToSeed(g)) : (() => { try { return U.frameToUR(g).ur; } catch (e) { return "error"; } })());
	for (const [rate, tone, gap, ch] of [
		[8000, 40, 20, { speakerFc: 50, rt60: 0, noise: 0.003, fade: 0 }],   // cable, fast
		[48000, 50, 50, { speakerFc: 50, rt60: 0, noise: 0.01, fade: 0 }],
		[8000, 80, 80, { speakerFc: 600, rt60: 0.3, wet: 0.4, noise: 0.005 }], // quiet room
		[16000, 80, 80, { speakerFc: 900, rt60: 0.4, wet: 0.6, noise: 0.04 }], // noisy room
	]) {
		const audio = channel(U.render(groups, rate, tone, gap), rate, ch);
		const got = [];
		const l = new U.Listener(rate, { onGroup: (g) => got.push(g) });
		for (let i = 0; i < audio.length; i += 4096) l.push(audio.subarray(i, i + 4096)); // as a microphone
		l.flush();
		check(JSON.stringify(decoded(got)) === JSON.stringify(expect), `audio ${rate} Hz ${tone}/${gap} ${JSON.stringify(ch)}: ${got.map((g) => g.slice(0, 8))}`);
	}
	const w = U.readWav(U.wav(U.render([s.frames[0]], 44100), 44100));
	check(JSON.stringify(decoded(U.listen(w.samples, w.rate))) === JSON.stringify([s.ur]), "WAV round trip");
}

console.log(`${failures ? "FAIL" : "ok"}: ${vectors.length} vectors, ${checks} checks, ${failures} failures`);
process.exit(failures ? 1 : 0);
