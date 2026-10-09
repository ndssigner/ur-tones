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
const enc = new TextEncoder();
check(hex(C.pbkdf2Sha256(enc.encode("1234"), enc.encode(C.PIN_SALT), 10000, 32))
	=== pbkdf2Sync("1234", C.PIN_SALT, 10000, 32, "sha256").toString("hex"), "pbkdf2");

// vectors
const vectors = JSON.parse(read("../vectors/ur-tones-v0.json")).vectors;
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
