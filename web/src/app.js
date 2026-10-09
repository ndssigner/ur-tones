// ur-tones web tool: user interface. Everything the user types or
// hears is shown as text (textContent), never as HTML. Nothing is stored:
// closing the page forgets everything.
"use strict";

(() => {
	const S = UrTonesCrypto, TN = UrTones;
	const $ = (id) => document.getElementById(id);
	const st = {
		lang: (navigator.language || "en").toLowerCase().startsWith("es") ? "es" : "en",
		screen: "home",
		send: { text: "", mode: "data", pin: "", pace: "cable" },
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
			view.status.textContent = T().playing(n, total);
			const spans = [...frame].map((k) => h("span", { text: k }));
			view.keys.replaceChildren(...spans);
			clearInterval(player.timer);
			player.timer = setInterval(() => {
				const i = Math.floor(((player.ctx.currentTime - t0) * 1000 - pace.pause) / (pace.tone + pace.gap));
				spans.forEach((s, j) => s.classList.toggle("on", j === i));
			}, 40);
		};
		next();
	}

	// ---- screens -----------------------------------------------------
	function home() {
		const t = T();
		const choice = (big, title, help, screen) => h("button", { class: "choice", on: { click: () => go(screen) } },
			h("div", { class: "big", text: big }), h("b", { text: title }), h("span", { text: help }));
		return h("div", {},
			h("div", { class: "choices" },
				choice("🔊", t.send, t.sendHelp, "send"),
				choice("👂", t.listen, t.listenHelp, "listen"),
				choice("🔌", t.cables, t.cablesHelp, "cables")));
	}

	function sendScreen() {
		const t = T(), s = st.send;
		const view = { status: h("div", { class: "status" }), keys: h("div", { class: "keys" }) };
		const info = h("div", { class: "status" });
		const options = h("div", {});
		const area = h("textarea", { class: "seed", spellcheck: "false", autocomplete: "off", placeholder: "cHNidP8BA… / ur:crypto-psbt/… / abandon ability …" });
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
			view.keys.replaceChildren(); view.status.textContent = "";
			const input = parseInput(s.text);
			info.className = "status " + (input && input.kind !== "bad" ? "ok" : "bad");
			info.textContent = !input ? "" : input.kind === "psbt" ? t.detected.psbt(input.psbt.length, input.parts)
				: input.kind === "urs" ? t.detected.urs(input.urs.length, input.type)
				: input.kind === "seed" ? t.detected.seed(input.words) : t.detected.bad;
			options.replaceChildren();
			if (!input || input.kind === "bad") return;
			const seg = (items, value, set) => h("div", { class: "seg" }, items.map(([v, label, help]) =>
				h("button", { class: v === value ? "on" : "", on: { click: () => { set(v); update(); } } }, label, h("small", { text: help }))));
			if (input.kind === "seed") {
				const pin = h("input", { class: "pin", autocomplete: "off", autocapitalize: "characters", spellcheck: "false", placeholder: "PIN", value: s.pin,
					on: { input: (e) => { s.pin = cleanPin(e.target.value); e.target.value = s.pin; }, change: () => update() } });
				options.append(h("h3", { text: t.seedMode }),
					seg([["data", t.modeData, t.modeDataHelp], ["keypad", t.modeKeypad, t.modeKeypadHelp]], s.mode, (v) => { s.mode = v; }),
					h("h3", { text: t.pinTitle }), h("p", { class: "help", text: t.pinHelp }), pin);
			}
			options.append(h("h3", { text: t.pace }),
				seg([["cable", t.paceCable, t.paceCableHelp], ["air", t.paceAir, t.paceAirHelp]], s.pace, (v) => { s.pace = v; }));
			if (input.kind === "seed" && s.pace === "air") options.append(h("div", { class: s.pin.length >= 8 ? "note" : "error", text: s.pin.length >= 8 ? t.airSeedPin : t.airSeed }));
			const pace = paceFor(input, s), gen = frames(input, s);
			const round = Array.from({ length: roundLength(input) }, () => gen.next().value);
			const secs = round.reduce((a, f) => a + f.length * (pace.tone + pace.gap) + 2 * pace.pause, 0) / 1000;
			options.append(h("p", { class: "help", text: t.duration(secs) }));
			if (input.kind === "seed" && s.mode === "keypad") {
				const digits = round[0].slice(1, -1).match(/.{4}/g);
				options.append(h("p", { class: "help", text: t.keyByHand }),
					h("div", { class: "words" }, digits.map((d, i) => h("div", {}, h("span", { text: String(i + 1) }), d))));
			}
			options.append(h("div", { class: "row" },
				h("button", { class: "btn", on: { click: () => play(input, s, view) } }, t.play),
				h("button", { class: "btn ghost", on: { click: () => { stopPlaying(); view.status.textContent = ""; } } }, t.stop),
				h("button", { class: "btn ghost", title: t.wavRound, on: { click: () => {
					const extra = input.kind === "psbt" && input.parts > 1 ? Math.ceil(input.parts / 2) + 1 : 0;
					const g = frames(input, s), list = Array.from({ length: round.length + extra }, () => g.next().value);
					download(TN.wav(TN.render(list, 44100, pace.tone, pace.gap, 2 * pace.pause), 44100), "ur-tones.wav", "audio/wav");
				} } }, t.saveWav)), view.status, view.keys);
		}
		area.addEventListener("input", () => { s.text = area.value; update(); });
		const card = h("div", { class: "card" },
			h("h2", { text: "🔊 " + t.send }),
			h("h3", { text: t.pasteTitle }), h("p", { class: "help", text: t.pasteHelp }), area,
			h("div", { class: "row" }, h("button", { class: "btn ghost small", on: { click: () => fileInput.click() } }, t.openFile), fileInput),
			info, options,
			h("div", { class: "nav" }, h("button", { class: "btn ghost", on: { click: () => go("home") } }, t.home)));
		update();
		return card;
	}

	// ---- listening -----------------------------------------------------
	const mic = { ctx: null, stream: null, proc: null };
	function stopMic() {
		if (mic.proc) mic.proc.disconnect();
		if (mic.stream) mic.stream.getTracks().forEach((tr) => tr.stop());
		mic.proc = mic.stream = null;
	}

	function listenScreen() {
		const t = T();
		const L = { decoder: null, done: false, pin: "" };
		const meter = h("div", {}), heard = h("div", { class: "keys heard" }), list = h("div", { class: "frames" });
		const progress = h("div", { class: "progress" }, h("div", {})), progressText = h("div", { class: "help" });
		const result = h("div", {}), err = h("div", {});
		const micBtn = h("button", { class: "btn" }, t.mic);
		const pin = h("input", { class: "pin", autocomplete: "off", autocapitalize: "characters", spellcheck: "false", placeholder: "PIN",
			on: { input: (e) => { L.pin = cleanPin(e.target.value); e.target.value = L.pin; } } });

		function addFrame(ok, text) {
			list.prepend(h("div", { class: ok ? "ok" : "bad", text }));
			while (list.children.length > 8) list.lastChild.remove();
		}
		function finish(node) { L.done = true; stopMic(); micBtn.textContent = t.mic; result.replaceChildren(node); result.scrollIntoView({ behavior: "smooth" }); }
		function gotMessage(type, cbor, ur) {
			if (type === "crypto-psbt" || type === "psbt") {
				const psbt = TN.cborToPsbt(cbor), b64 = toBase64(psbt);
				const out = h("textarea", { class: "seed", readonly: "" }); out.value = b64;
				finish(h("div", { class: "card done" }, h("h2", { text: t.gotPsbt }), out,
					h("div", { class: "row" }, copyButton(() => b64),
						h("button", { class: "btn ghost", on: { click: () => download(psbt, "transaction.psbt", "application/octet-stream") } }, t.savePsbt)),
					h("p", { class: "help", text: t.toSparrow })));
			} else if ((type === "crypto-seed" || type === "seed") && ur) {
				gotSeed(TN.urToSeed(ur, L.pin || null));
			} else {
				const out = h("textarea", { class: "seed", readonly: "" }); out.value = ur;
				finish(h("div", { class: "card done" }, h("h2", { text: t.gotUR }), out, h("div", { class: "row" }, copyButton(() => ur))));
			}
		}
		function gotSeed(entropy) {
			const words = S.entropyToMnemonic(entropy).split(" ");
			finish(h("div", { class: "card done" }, h("h2", { text: t.gotSeed }), h("p", { text: t.seedWords }),
				h("div", { class: "words" }, words.map((w, i) => h("div", {}, h("span", { text: String(i + 1) }), w))),
				L.pin ? h("p", { class: "help", text: t.pinApplied }) : null));
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
					addFrame(true, t.frameOk(f.corrected) + " " + f.ur.slice(0, 40) + "…");
					if (f.kind === 0) return gotMessage(f.type, f.body, f.ur);
					const p = TN.parsePart(f.body);
					const e = L.decoder && L.decoder.expected;
					if (!L.decoder || (e && (e.seqLen !== p.seqLen || e.checksum !== p.checksum))) { L.decoder = new TN.FountainDecoder(); L.type = f.type; }
					L.decoder.receive(f.body);
					progress.firstChild.style.width = Math.round(100 * L.decoder.progress()) + "%";
					progressText.textContent = t.progress(L.decoder.simple.size, p.seqLen);
					if (L.decoder.result) gotMessage(L.type, L.decoder.result, null);
				}
			} catch (e) { addFrame(false, t.frameBad(e.message) + " " + g.slice(0, 20)); }
		}
		const newListener = (rate) => new TN.Listener(rate, {
			onGroup,
			onLive: (k) => { heard.textContent = (heard.textContent + k).slice(-120); },
			onLevel: (db) => { meter.style.width = Math.max(0, Math.min(100, (db + 70) * 1.6)) + "%"; },
		});
		function reset() { L.decoder = null; L.done = false; result.replaceChildren(); list.replaceChildren(); heard.textContent = ""; progressText.textContent = ""; progress.firstChild.style.width = "0"; err.replaceChildren(); }

		micBtn.addEventListener("click", async () => {
			if (mic.stream) { stopMic(); micBtn.textContent = t.mic; return; }
			reset();
			try {
				mic.stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false } });
			} catch (e) { err.replaceChildren(h("div", { class: "error", text: t.micDenied })); return; }
			mic.ctx = mic.ctx || new AudioContext();
			mic.ctx.resume();
			const listener = newListener(mic.ctx.sampleRate);
			const src = mic.ctx.createMediaStreamSource(mic.stream);
			mic.proc = mic.ctx.createScriptProcessor(4096, 1, 1);
			mic.proc.onaudioprocess = (e) => listener.push(e.inputBuffer.getChannelData(0));
			src.connect(mic.proc); mic.proc.connect(mic.ctx.destination);
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
			} catch (x) { err.replaceChildren(h("div", { class: "error", text: x.message })); }
			e.target.value = "";
		} } });

		return h("div", { class: "card" },
			h("h2", { text: "👂 " + t.listen }),
			h("p", { class: "help", text: t.micHelp }),
			h("div", { class: "row" }, micBtn, h("button", { class: "btn ghost", on: { click: () => wavInput.click() } }, t.openWav), wavInput),
			err,
			h("details", { class: "more" }, h("summary", { text: t.pinTitle }), h("p", { class: "help", text: t.pinHelp }), pin),
			h("h3", { text: t.level }), h("div", { class: "meter" }, meter),
			h("h3", { text: t.heard }), heard,
			h("h3", { text: t.frames }), progress, progressText, list,
			result,
			h("div", { class: "nav" }, h("button", { class: "btn ghost", on: { click: () => go("home") } }, t.home)));
	}

	const textScreen = (title, paras) => () => h("div", { class: "card" }, h("h2", { text: title() }),
		...paras().map((p) => Array.isArray(p) ? h("div", { class: "note" }, h("b", { text: p[0] }), h("div", { text: p[1] })) : h("p", { text: p })),
		h("div", { class: "nav" }, h("button", { class: "btn ghost", on: { click: () => go("home") } }, T().home)));

	// ---- shell -------------------------------------------------------
	function shell() {
		const t = T();
		document.documentElement.lang = st.lang;
		$("warn").textContent = t.warnTest;
		$("online").textContent = t.warnOnline;
		$("tagline").textContent = t.subtitle;
		$("lang").textContent = "🌐 " + t.langName;
		$("about").textContent = t.about;
	}
	const online = () => $("online").classList.toggle("hidden", !navigator.onLine);
	addEventListener("online", online);
	addEventListener("offline", online);
	$("lang").addEventListener("click", () => { st.lang = T().langSwitch; render(); });
	$("logo").addEventListener("click", () => go("home"));
	$("about").addEventListener("click", () => go("about"));
	function go(screen) { stopPlaying(); stopMic(); st.screen = screen; render(); scrollTo(0, 0); }
	function render() {
		shell(); online();
		$("app").replaceChildren(({
			home, send: sendScreen, listen: listenScreen,
			cables: textScreen(() => "🔌 " + T().cables, () => T().cableText),
			about: textScreen(() => T().about, () => T().aboutText),
		})[st.screen]());
	}
	render();
})();
