"""The README's hero images, docs/images/hero-{light,dark}.png: the web tool's
start-page hero with its logo, in English, rendered by headless Chrome from a
copy of the built page (without its CSP, which only matters to the real one).

    node web/build.mjs && python3 tools/readme_hero.py

Needs Google Chrome (CHROME=/path/to/chrome to use another).
"""
import os, pathlib, re, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PAGE, HEIGHT, EXTRA = "dist/ur-tones.html", 372, ".pad figcaption { display: none; }"
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


def page(mode):
	s = (ROOT / PAGE).read_text()
	s = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>', "", s)
	s = s.replace("(prefers-color-scheme: dark)", "all" if mode == "dark" else "(prefers-color-scheme: never)")
	s = s.replace("<head>", '<head><script>Object.defineProperty(navigator, "language", { get: () => "en-US" });</script>', 1)
	s = s.replace("</head>", """<style>
body > header.top, body > footer, .intro > :not(.hero), .hero .row { display: none !important; }
.wrap { padding: 36px 48px 40px !important; max-width: 1180px; }
.hero { padding: 0 !important; }
.hero-text > .brand { margin-bottom: 4px; cursor: default; overflow: visible; } .hero-text > .brand b { font-size: 36px; }
""" + EXTRA + "</style></head>", 1)
	return s.replace("</body>", """<script>addEventListener("load", () => {
	const wrap = document.createElement("div"); wrap.className = "brand";
	wrap.append(document.querySelector("#logo b").cloneNode(true));
	document.querySelector(".hero-text").prepend(wrap);
});</script></body>""")


with tempfile.TemporaryDirectory() as tmp:
	for mode in ("light", "dark"):
		html = pathlib.Path(tmp, mode + ".html")
		html.write_text(page(mode))
		out = ROOT / "docs" / "images" / f"hero-{mode}.png"
		subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--hide-scrollbars",
			"--force-device-scale-factor=2", f"--window-size=1280,{HEIGHT}", "--virtual-time-budget=4000",
			f"--screenshot={out}", html.as_uri()], check=True, capture_output=True)
		print(out.relative_to(ROOT))
