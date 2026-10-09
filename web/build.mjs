// Builds the single-file web tool: dist/ur-tones.html.
//     node web/build.mjs
// Deterministic (no dates, no random): the same sources give the same file,
// so anyone can rebuild it and compare its SHA-256 with the published one.
// The Content-Security-Policy allows only this file's own script and style,
// by their SHA-256 hashes, and no network at all.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

const here = new URL(".", import.meta.url);
const read = (p) => readFileSync(new URL(p, here), "utf8");
const cspHash = (text) => "sha256-" + createHash("sha256").update(text, "utf8").digest("base64");

const script = ["src/bip39-english.js", "src/crypto.js", "src/ur-tones.js", "src/i18n.js", "src/app.js"]
	.map((f) => `// ---- ${f} ----\n${read(f)}`).join("\n");
const style = read("src/style.css");
const formatVersion = /const FORMAT_VERSION = (\d+);/.exec(read("src/ur-tones.js"))[1];

const html = read("src/index.html")
	.replace("{{SCRIPT_HASH}}", cspHash(script))
	.replace("{{STYLE_HASH}}", cspHash(style))
	.replace("{{FORMAT_VERSION}}", formatVersion)
	.replace("{{STYLE}}", () => style)
	.replace("{{SCRIPT}}", () => script);
if (html.includes("{{")) throw new Error("unfilled placeholder");

mkdirSync(new URL("../dist/", here), { recursive: true });
writeFileSync(new URL("../dist/ur-tones.html", here), html);
console.log(createHash("sha256").update(html).digest("hex") + "  dist/ur-tones.html");
