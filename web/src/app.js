// ur-tones web tool: user interface. Everything the user types or
// hears is shown as text (textContent), never as HTML. Nothing is stored:
// closing the page forgets everything.
"use strict";

(() => {
	const S = UrTonesCrypto, TN = UrTones;
	const $ = (id) => document.getElementById(id);
	const st = {
		lang: (navigator.language || "en").toLowerCase().startsWith("es") ? "es" : "en",
		screen: "send",
		send: { text: "", mode: "data", pin: "", made: "", pace: "cable" },
	};
	const T = () => UR_TONES_TEXT[st.lang];
	// SPEC §1.1. Keypad mode's digits repeat: never faster than 80 + 80 ms
	const PACES = { cable: { tone: 40, gap: 20, pause: 200 }, air: { tone: 80, gap: 80, pause: 300 } };
	const paceFor = (input, sendSt) => input.kind === "seed" && sendSt.mode === "keypad"
		? { tone: 80, gap: 80, pause: 300 } : PACES[sendSt.pace];

	// ---- tiny DOM helpers --------------------------------------------
	function h(tag, props, ...children) {
		const e = document.createElement(tag);
		for (const [k, v] of Object.entries(props || {})) {
			if (v === undefined || v === null || v === false) continue;
			if (k === "class") e.className = v;
			else if (k === "on") for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
			else if (k === "text") e.textContent = v;
			else e.setAttribute(k, v);
		}
		for (const c of children.flat()) if (c !== null && c !== undefined && c !== false)
			e.append(c instanceof Node ? c : document.createTextNode(String(c)));
		return e;
	}
	const cleanPin = (v) => v.toUpperCase().replace(/[^A-Z0-9]/g, "");
	// A seed's fingerprint (about half a second: PBKDF2 and secp256k1), kept per seed
	const fingerprints = new Map();
	function fingerprintOf(entropy) {
		const key = Array.from(entropy, (b) => b.toString(16).padStart(2, "0")).join("");
		if (!fingerprints.has(key)) fingerprints.set(key, S.fingerprint(entropy));
		return fingerprints.get(key);
	}
	// The fingerprint, filled in a moment later so the page does not wait for it
	function fingerprintBox(entropy, help) {
		const t = T(), value = h("b", { class: "fp-value", text: "…" });
		setTimeout(() => { value.textContent = fingerprintOf(entropy); }, 30);
		return h("div", { class: "fp" }, h("span", { class: "label", text: t.fingerprint }), value, h("span", { class: "hint", text: help }));
	}
	// A made-up PIN (SPEC §4): 12 characters without 0/O or 1/I, 60 bits; 32 divides 256, so no bias.
	// Shown in groups of 4, typed without the spaces. Shorter PINs are accepted, with a warning.
	const PIN_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ", PIN_LENGTH = 12;
	const makePin = () => Array.from(crypto.getRandomValues(new Uint8Array(PIN_LENGTH)), (b) => PIN_ALPHABET[b % 32]).join("");
	const groups = (pin) => pin.match(/.{1,4}/g).join(" ");
	// The PIN box, and 🎲 to make one up here and type it on the other device
	// (st.pin, and st.made: the PIN made up here, shown big until it is edited)
	function pinField(st, onChange) {
		const t = T();
		const shown = h("div", {});
		const show = () => shown.replaceChildren(...(st.pin && st.pin === st.made
			? [h("div", { class: "pin-big", text: groups(st.pin) }), h("div", { class: "hint", text: t.pinMadeHelp })]
			: st.pin && st.pin.length < PIN_LENGTH ? [h("div", { class: "hint warn", text: t.pinShort })] : []));
		const input = h("input", { class: "pin", autocomplete: "off", autocapitalize: "characters", spellcheck: "false", placeholder: "PIN", value: st.pin,
			on: { input: (e) => { st.pin = cleanPin(e.target.value); e.target.value = st.pin; show(); },
				change: () => onChange && onChange() } });
		const dice = h("button", { class: "btn ghost", title: t.pinMake, on: { click: () => {
			st.pin = st.made = makePin();
			input.value = st.pin;
			show();
			if (onChange) onChange();
		} } }, "🎲 " + t.pinMake);
		show();
		return h("div", {}, h("div", { class: "row" }, input, dice), shown);
	}
	const toBase64 = (b) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(""));
	const fromBase64 = (s) => Uint8Array.from(atob(s.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
	const fromHex = (s) => Uint8Array.from(s.replace(/\s+/g, "").match(/../g) || [], (x) => parseInt(x, 16));
	function download(bytes, name, type) {
		const url = URL.createObjectURL(new Blob([bytes], { type }));
		const a = h("a", { href: url, download: name });
		document.body.append(a); a.click(); a.remove();
		setTimeout(() => URL.revokeObjectURL(url), 10000);
	}
	function copyButton(getText) {
		const t = T();
		const b = h("button", { class: "btn ghost", on: { click: async () => {
			const text = getText();
			try { await navigator.clipboard.writeText(text); }
			catch (e) { // no clipboard API (file://, older browsers): select and copy
				const ta = h("textarea", {}); ta.value = text; document.body.append(ta); ta.select();
				document.execCommand("copy"); ta.remove();
			}
			b.textContent = "✓ " + t.copied; setTimeout(() => { b.textContent = t.copy; }, 1500);
		} } }, t.copy);
		return b;
	}

	// ---- what to send ------------------------------------------------
	const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff];
	// the BIP-39 test vector everyone knows: never holds funds
	const TEST_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	function parseInput(text) {
		const s = text.trim();
		if (!s) return null;
		try {
			if (/^ur:/i.test(s)) {
				const urs = s.split(/\s+/).filter(Boolean);
				const parsed = urs.map((u) => TN.parseUR(u));
				if (parsed.some((p) => p.type !== parsed[0].type)) return { kind: "bad" };
				return { kind: "urs", urs, type: parsed[0].type };
			}
			let psbt = null;
			if (/^cHNidP8/.test(s)) psbt = fromBase64(s);
			else if (/^70736274ff[0-9a-f\s]*$/i.test(s)) psbt = fromHex(s);
			if (psbt) return { kind: "psbt", psbt, parts: new TN.FountainEncoder(TN.cborBytes(psbt), 100).seqLen };
			const words = s.toLowerCase().split(/\s+/);
			if (words.length === 12 || words.length === 24) return { kind: "seed", entropy: S.mnemonicToEntropy(words.join(" ")), words: words.length };
		} catch (e) { /* not that */ }
		return { kind: "bad" };
	}
	// frames to play, forever (a round, then more): a generator
	function* frames(input, sendSt) {
		if (input.kind === "seed") {
			const pin = sendSt.pin || null;
			const f = sendSt.mode === "keypad" ? TN.seedToKeypad(input.entropy, pin) : TN.urToFrame(TN.seedToUR(input.entropy, pin));
			for (;;) yield f;
		}
		if (input.kind === "urs") {
			const fs = input.urs.map(TN.urToFrame);
			for (;;) yield* fs;
		}
		const enc = new TN.FountainEncoder(TN.cborBytes(input.psbt), 100);
		if (enc.seqLen === 1) { const f = TN.urToFrame(TN.urText("crypto-psbt", 0, TN.cborBytes(input.psbt))); for (;;) yield f; }
		for (;;) yield TN.urToFrame(TN.urText("crypto-psbt", 1, enc.nextPart()));
	}
	const roundLength = (input) => input.kind === "psbt" ? input.parts : input.kind === "urs" ? input.urs.length : 1;

	// ---- player ------------------------------------------------------
	const player = { ctx: null, source: null, timer: null, on: false };
	function stopPlaying() {
		player.on = false;
		clearInterval(player.timer);
		if (player.source) { player.source.onended = null; try { player.source.stop(); } catch (e) { /* stopped */ } }
		player.source = null;
	}
	// view: { status, keys, bar } of the send screen's live panel
	function play(input, sendSt, view) {
		stopPlaying();
		player.ctx = player.ctx || new AudioContext();
		player.ctx.resume();
		player.on = true;
		const gen = frames(input, sendSt);
		const pace = paceFor(input, sendSt);
		const total = roundLength(input);
		let n = 0;
		const next = () => {
			if (!player.on) return;
			const frame = gen.next().value;
			n++;
			const rate = player.ctx.sampleRate;
			const samples = TN.render([frame], rate, pace.tone, pace.gap, pace.pause);
			const buf = player.ctx.createBuffer(1, samples.length, rate);
			buf.copyToChannel(samples, 0);
			const src = player.ctx.createBufferSource();
			src.buffer = buf; src.connect(player.ctx.destination);
			src.onended = next;
			const t0 = player.ctx.currentTime + 0.05;
			src.start(t0);
			player.source = src;
			view.status.textContent = T().playing(((n - 1) % total) + 1, total);
			const spans = [...frame].map((k) => h("span", { text: k }));
			view.keys.replaceChildren(...spans);
			let last = -1;
			clearInterval(player.timer);
			player.timer = setInterval(() => {
				const i = Math.floor(((player.ctx.currentTime - t0) * 1000 - pace.pause) / (pace.tone + pace.gap));
				if (i === last) return;
				if (spans[last]) spans[last].classList.remove("on");
				last = i;
				if (spans[i]) { spans[i].classList.add("on"); spans[i].scrollIntoView({ block: "nearest" }); }
				view.bar.style.width = Math.max(0, Math.min(100, 100 * i / frame.length)) + "%";
			}, 40);
		};
		next();
	}

	// ---- small building blocks ----------------------------------------
	const field = (label, ...children) => h("div", { class: "field" }, h("div", { class: "label", text: label }), ...children);
	// segmented control: [value, label, help]; the chosen one's help below it
	function seg(items, value, set) {
		const help = (items.find(([v]) => v === value) || [])[2];
		return h("div", {}, h("div", { class: "seg" }, items.map(([v, label]) =>
			h("button", { class: v === value ? "on" : "", on: { click: () => set(v) } }, label))),
			help ? h("div", { class: "hint", text: help }) : null);
	}
	const bar = () => h("div", { class: "bar-track" }, h("div", {}));
	const panel = (...children) => h("section", { class: "panel" }, ...children);

	// ---- send ---------------------------------------------------------
	function sendScreen() {
		const t = T(), s = st.send;
		const view = { status: h("div", { class: "status", text: "" }), keys: h("div", { class: "keys" }), bar: h("div", {}) };
		const info = h("div", { class: "detected" });
		const options = h("div", { class: "stack" }), live = h("div", { class: "stack" });
		const area = h("textarea", { class: "input", rows: 4, spellcheck: "false", autocomplete: "off", placeholder: "cHNidP8BA… · ur:crypto-psbt/… · abandon ability …" });
		area.value = s.text;
		const fileInput = h("input", { type: "file", class: "hidden", on: { change: async (e) => {
			const f = e.target.files[0];
			if (!f) return;
			const b = new Uint8Array(await f.arrayBuffer());
			s.text = PSBT_MAGIC.every((x, i) => b[i] === x) ? toBase64(b) : new TextDecoder().decode(b).trim();
			area.value = s.text; update();
		} } });
		function update() {
			stopPlaying();
			const input = parseInput(s.text);
			info.className = "detected " + (!input ? "" : input.kind !== "bad" ? "ok" : "bad");
			info.textContent = !input ? "" : input.kind === "psbt" ? t.detected.psbt(input.psbt.length, input.parts)
				: input.kind === "urs" ? t.detected.urs(input.urs.length, input.type)
				: input.kind === "seed" ? t.detected.seed(input.words) : t.detected.bad;
			options.replaceChildren(); live.replaceChildren();
			if (!input || input.kind === "bad") {
				live.append(h("div", { class: "empty" }, h("div", { text: t.inputHint }),
					h("button", { class: "btn ghost small", on: { click: () => { s.text = area.value = TEST_SEED; update(); } } }, t.tryTestSeed)));
				return;
			}
			const again = (fn) => (v) => { fn(v); update(); };
			if (input.kind === "seed") {
				options.append(seedAlert(),
					field(t.seedMode, seg([["data", t.modeData, t.modeDataHelp], ["keypad", t.modeKeypad, t.modeKeypadHelp]], s.mode, again((v) => { s.mode = v; }))),
					field(t.pin, pinField(s, () => update()), h("div", { class: "hint", text: t.pinHint })));
			}
			if (!(input.kind === "seed" && s.mode === "keypad"))
				options.append(field(t.pace, seg([["cable", t.paceCable, t.paceCableHelp], ["air", t.paceAir, t.paceAirHelp]], s.pace, again((v) => { s.pace = v; }))));
			if (input.kind === "seed" && s.pace === "air" && s.mode !== "keypad")
				options.append(h("div", { class: s.pin ? "note" : "alert", text: s.pin ? t.airSeedPin : t.airSeed }));

			const pace = paceFor(input, s), gen = frames(input, s);
			const round = Array.from({ length: roundLength(input) }, () => gen.next().value);
			const secs = round.reduce((a, f) => a + f.length * (pace.tone + pace.gap) + 2 * pace.pause, 0) / 1000;
			view.status.textContent = t.ready;
			view.keys.replaceChildren(...[...round[0]].map((k) => h("span", { text: k })));
			view.bar.style.width = "0";
			live.append(
				h("div", { class: "row" },
					h("button", { class: "btn big", on: { click: () => play(input, s, view) } }, t.play),
					h("button", { class: "btn ghost big", on: { click: () => { stopPlaying(); view.status.textContent = t.ready; view.bar.style.width = "0"; } } }, t.stop),
					h("span", { class: "meta", text: t.duration(secs) }),
					h("button", { class: "btn ghost small push", title: t.wavRound, on: { click: () => {
						const extra = input.kind === "psbt" && input.parts > 1 ? Math.ceil(input.parts / 2) + 1 : 0;
						const g = frames(input, s), list = Array.from({ length: round.length + extra }, () => g.next().value);
						download(TN.wav(TN.render(list, 44100, pace.tone, pace.gap, 2 * pace.pause), 44100), "ur-tones.wav", "audio/wav");
					} } }, t.saveWav)),
				input.kind === "seed" ? fingerprintBox(input.entropy, t.fingerprintSend) : null,
				view.status, h("div", { class: "bar-track" }, view.bar), view.keys);
			if (input.kind === "seed" && s.mode === "keypad") {
				const digits = round[0].slice(1, -1).match(/.{4}/g);
				live.append(h("div", { class: "hint", text: t.keyByHand }),
					h("div", { class: "words" }, digits.map((d, i) => h("div", {}, h("span", { text: String(i + 1) }), d))));
			}
		}
		area.addEventListener("input", () => { s.text = area.value; update(); });
		update();
		return h("div", { class: "tool" },
			panel(field(t.input, area,
				h("div", { class: "row" }, info, h("button", { class: "btn ghost small push", on: { click: () => fileInput.click() } }, t.openFile), fileInput)),
				options),
			panel(live));
	}

	// ---- listening -----------------------------------------------------
	// A fresh AudioContext each time, and every node kept referenced while in use:
	// a reused context (or a source node collected by the garbage collector) can
	// stay silent after the microphone is stopped and started again.
	const mic = { ctx: null, stream: null, src: null, proc: null };
	function stopMic() {
		if (mic.proc) { mic.proc.onaudioprocess = null; mic.proc.disconnect(); }
		if (mic.src) mic.src.disconnect();
		if (mic.stream) mic.stream.getTracks().forEach((tr) => tr.stop());
		if (mic.ctx) mic.ctx.close().catch(() => {});
		mic.ctx = mic.stream = mic.src = mic.proc = null;
	}

	function listenScreen() {
		const t = T();
		const L = { decoder: null, done: false, pin: "", made: "" };
		const meter = h("div", {}), levelText = h("span", { class: "meta", text: "" });
		const heard = h("div", { class: "heard" }), list = h("div", { class: "frames" });
		const progress = h("div", {}), progressText = h("span", { class: "meta", text: "" });
		const result = h("div", {}), err = h("div", {});
		const micBtn = h("button", { class: "btn big" }, t.mic), micState = h("div", { class: "status", text: t.idle });
		// optional recording of what the microphone hears, for bug reports:
		// about 8 kHz, 16 bits, 10 minutes at most (about 10 MB)
		const rec = { on: false, rate: 0, dec: 1, pend: [], chunks: [], n: 0, max: 0 };
		const recInfo = h("span", { class: "meta" });
		const recSave = h("button", { class: "btn ghost small", disabled: "", on: { click: () => {
			const all = new Float32Array(rec.n);
			let o = 0;
			for (const c of rec.chunks) { for (let i = 0; i < c.length; i++) all[o + i] = c[i] / 32768; o += c.length; }
			download(TN.wav(all, rec.rate / rec.dec), "ur-tones-recording.wav", "audio/wav");
		} } }, t.recSave);
		const recBox = h("input", { type: "checkbox", on: { change: (e) => { rec.on = e.target.checked; } } });
		function record(x) {
			if (!rec.on || rec.n >= rec.max) return;
			const d = rec.dec, all = rec.pend.concat(Array.from(x)), m = Math.floor(all.length / d), out = new Int16Array(m);
			for (let i = 0; i < m; i++) {
				let sum = 0;
				for (let j = 0; j < d; j++) sum += all[i * d + j];
				out[i] = Math.max(-32767, Math.min(32767, Math.round(sum / d * 32767)));
			}
			rec.pend = all.slice(m * d);
			rec.chunks.push(out); rec.n += m;
			recInfo.textContent = t.recLength(Math.round(rec.n / (rec.rate / d)));
			recSave.disabled = false;
		}
		const pin = pinField(L);

		function addFrame(ok, text) {
			list.prepend(h("div", { class: ok ? "ok" : "bad", text }));
			while (list.children.length > 12) list.lastChild.remove();
		}
		function finish(node) {
			L.done = true; stopMic(); micBtn.textContent = t.mic; micState.className = "status"; micState.textContent = t.idle;
			result.replaceChildren(node);
			result.scrollIntoView({ behavior: "smooth", block: "nearest" });
		}
		const done = (title, ...body) => h("div", { class: "result" }, h("div", { class: "result-title", text: "✓ " + title }), ...body);
		function gotMessage(type, cbor, ur) {
			if (type === "crypto-psbt" || type === "psbt") {
				const psbt = TN.cborToPsbt(cbor), b64 = toBase64(psbt);
				const out = h("textarea", { class: "input mono", rows: 4, readonly: "" }); out.value = b64;
				finish(done(t.gotPsbt, out,
					h("div", { class: "row" }, copyButton(() => b64),
						h("button", { class: "btn ghost", on: { click: () => download(psbt, "transaction.psbt", "application/octet-stream") } }, t.savePsbt)),
					h("div", { class: "hint", text: t.toSparrow })));
			} else if ((type === "crypto-seed" || type === "seed") && ur) {
				gotSeed(TN.urToSeed(ur, L.pin || null));
			} else {
				const out = h("textarea", { class: "input mono", rows: 3, readonly: "" }); out.value = ur;
				finish(done(t.gotUR, out, h("div", { class: "row" }, copyButton(() => ur))));
			}
		}
		function gotSeed(entropy) {
			const words = S.entropyToMnemonic(entropy).split(" ");
			finish(done(t.gotSeed, seedAlert(), fingerprintBox(entropy, t.fingerprintReceive),
				h("div", { class: "words" }, words.map((w, i) => h("div", {}, h("span", { text: String(i + 1) }), w))),
				L.pin ? h("div", { class: "hint", text: t.pinApplied }) : null));
		}
		function onGroup(g) {
			if (L.done) return;
			try {
				if (g.startsWith("*")) {
					const e = TN.keypadToSeed(g, L.pin || null);
					addFrame(true, t.frameOk(0) + " * … #");
					gotSeed(e);
				} else {
					const f = TN.frameToUR(g);
					addFrame(true, t.frameOk(f.corrected) + "  " + f.ur.slice(0, 48) + "…");
					if (f.kind === 0) return gotMessage(f.type, f.body, f.ur);
					const p = TN.parsePart(f.body);
					const e = L.decoder && L.decoder.expected;
					if (!L.decoder || (e && (e.seqLen !== p.seqLen || e.checksum !== p.checksum))) { L.decoder = new TN.FountainDecoder(); L.type = f.type; }
					L.decoder.receive(f.body);
					progress.style.width = Math.round(100 * L.decoder.progress()) + "%";
					progressText.textContent = t.progress(L.decoder.simple.size, p.seqLen);
					if (L.decoder.result) gotMessage(L.type, L.decoder.result, null);
				}
			} catch (e) { addFrame(false, t.frameBad(e.message) + "  " + g.slice(0, 24)); }
		}
		const newListener = (rate) => new TN.Listener(rate, {
			onGroup,
			onLive: (k) => { heard.textContent = (heard.textContent + k).slice(-160); },
			onLevel: (db) => {
				meter.style.width = Math.max(0, Math.min(100, (db + 70) * 1.6)) + "%";
				levelText.textContent = Math.round(db) + " dB";
			},
		});
		function reset() {
			L.decoder = null; L.done = false; result.replaceChildren(); list.replaceChildren(); heard.textContent = "";
			progressText.textContent = ""; progress.style.width = "0"; err.replaceChildren();
		}

		micBtn.addEventListener("click", async () => {
			if (mic.stream) { stopMic(); micBtn.textContent = t.mic; micState.className = "status"; micState.textContent = t.idle; return; }
			reset();
			micBtn.disabled = true;
			micState.className = "status"; micState.textContent = t.micStarting;
			try {
				mic.stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false } });
			} catch (e) {
				micState.textContent = t.idle;
				err.replaceChildren(h("div", { class: "alert", text: t.micDenied })); return;
			} finally { micBtn.disabled = false; }
			if (!micBtn.isConnected) { stopMic(); return; }   // left this screen meanwhile
			mic.ctx = new AudioContext();
			await mic.ctx.resume().catch(() => {});
			const listener = newListener(mic.ctx.sampleRate);
			mic.src = mic.ctx.createMediaStreamSource(mic.stream);
			mic.proc = mic.ctx.createScriptProcessor(2048, 1, 1);
			let ready = false;
			Object.assign(rec, { rate: mic.ctx.sampleRate, dec: Math.max(1, Math.floor(mic.ctx.sampleRate / 8000)), pend: [], chunks: [], n: 0 });
			rec.max = Math.floor(600 * rec.rate / rec.dec);
			recSave.disabled = true; recInfo.textContent = "";
			mic.proc.onaudioprocess = (e) => {
				const x = e.inputBuffer.getChannelData(0);
				if (!ready && x.some((v) => v !== 0)) {   // the first real sound: from now on nothing is lost
					ready = true;
					micState.className = "status live"; micState.textContent = t.micReady;
				}
				listener.push(x); record(x);
			};
			mic.src.connect(mic.proc); mic.proc.connect(mic.ctx.destination);
			micBtn.textContent = t.micStop;
		});
		const wavInput = h("input", { type: "file", accept: ".wav,audio/wav", class: "hidden", on: { change: async (e) => {
			const f = e.target.files[0];
			if (!f) return;
			reset();
			try {
				const { samples, rate } = TN.readWav(new Uint8Array(await f.arrayBuffer()));
				const l = newListener(rate);
				l.push(samples); l.flush();
			} catch (x) { err.replaceChildren(h("div", { class: "alert", text: x.message })); }
			e.target.value = "";
		} } });

		return h("div", { class: "tool" },
			panel(
				h("div", { class: "row" }, micBtn, h("button", { class: "btn ghost small push", on: { click: () => wavInput.click() } }, t.openWav), wavInput),
				micState, h("div", { class: "hint", text: t.micHint }), err,
				field(t.pin, pin, h("div", { class: "hint", text: t.pinHint })),
				h("details", { class: "more" }, h("summary", { text: t.recTitle }), h("div", { class: "hint", text: t.recHelp }),
					h("label", { class: "row check" }, recBox, t.recOn), h("div", { class: "row" }, recSave, recInfo))),
			panel(
				h("div", { class: "row between" }, h("span", { class: "label", text: t.level }), levelText),
				h("div", { class: "bar-track meter" }, meter),
				field(t.heard, heard),
				h("div", { class: "row between" }, h("span", { class: "label", text: t.message }), progressText),
				h("div", { class: "bar-track" }, progress),
				field(t.frames, list),
				result));
	}

	const textScreen = (title, paras) => () => h("div", { class: "page" }, h("h2", { text: title() }),
		...paras().map((p) => Array.isArray(p) ? h("div", { class: "item" }, h("b", { text: p[0] }), h("div", { text: p[1] })) : h("p", { text: p })));

	// ---- donate ------------------------------------------------------
	const DONATE = { bitcoin: "bc1qx5snc0wlc8cg9gwxhyx27y6pkru8rnngyq7uja", lightning: "ndssigner@coinos.io",
		lnurl: "LNURL1DP68GURN8GHJ7CM0D9HX7UEWD9HJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHKUERNWD5KWMN9WGQ8XE42" };
	function donate() {
		const t = T();
		const box = (img, title, address, extra) => h("div", { class: "donate-box" },
			h("img", { src: img, alt: title, width: 160, height: 160 }), h("b", { text: title }),
			h("code", { text: address }), copyButton(() => address), extra || null);
		return h("div", { class: "page" },
			h("h2", { text: t.donateTitle }), h("p", { text: t.donateText }),
			h("div", { class: "donate" },
				box(DONATE_IMAGES.bitcoin, "Bitcoin", DONATE.bitcoin),
				box(DONATE_IMAGES.lightning, "Lightning", DONATE.lightning,
					h("details", { class: "more" }, h("summary", { text: t.donateLnurl }), h("code", { class: "wrap", text: DONATE.lnurl }), copyButton(() => DONATE.lnurl)))),
			h("p", { class: "hint", text: t.donateMore }));
	}

	// ---- shell -------------------------------------------------------
	const TABS = ["send", "listen", "cables"];
	function shell() {
		const t = T();
		document.documentElement.lang = st.lang;
		$("draft").textContent = t.draft;
		$("draft").title = t.warnTest;
		$("tagline").textContent = t.subtitle;
		$("lang").textContent = t.langName;
		$("about").textContent = t.about;
		$("donate").textContent = "💛 " + t.donateTitle;
		$("tabs").replaceChildren(...TABS.map((name) => h("button", { class: st.screen === name ? "on" : "", on: { click: () => go(name) } }, t[name])));
	}
	// the connection, always in sight; the warnings themselves appear next to a seed (seedAlert)
	const online = () => {
		const t = T(), on = navigator.onLine;
		$("net").className = "net " + (on ? "on" : "off");
		$("net").textContent = on ? t.netOn : t.netOff;
		$("net").title = on ? t.warnOnline : "";
	};
	const seedAlert = () => h("div", { class: "alert" }, navigator.onLine ? T().seedOnline : T().seedTest);
	addEventListener("online", online);
	addEventListener("offline", online);
	$("lang").addEventListener("click", () => { st.lang = T().langSwitch; render(); });
	$("logo").addEventListener("click", () => go("send"));
	$("about").addEventListener("click", () => go("about"));
	$("donate").addEventListener("click", () => go("donate"));
	function go(screen) { stopPlaying(); stopMic(); st.screen = screen; render(); scrollTo(0, 0); }
	function render() {
		shell(); online();
		$("app").replaceChildren(({
			send: sendScreen, listen: listenScreen,
			cables: textScreen(() => T().cables, () => T().cableText),
			about: textScreen(() => T().about, () => T().aboutText),
			donate,
		})[st.screen]());
	}

	render();
})();
