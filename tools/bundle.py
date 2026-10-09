"""The release bundle: dist/ur-tones-<version>.zip and dist/SHA256SUMS (its
hash; the files inside have their own SHA256SUMS).

    node web/build.mjs
    python3 tools/bundle.py v0.1.0

Reproducible: fixed order, dates and permissions, and stored (not
compressed) so the bytes do not depend on the zlib version. The PDFs are
already compressed. Anyone can rebuild it and compare its SHA-256.
"""
import hashlib
import pathlib
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = [  # (path in the repository, name in the bundle)
    ("dist/ur-tones.html", "ur-tones.html"),
    ("SPEC.md", "SPEC.md"),
    ("c/ur_tones.h", "c/ur_tones.h"),
    ("c/ur_tones.c", "c/ur_tones.c"),
    ("LICENSE", "LICENSE"),
]

README = """ur-tones {version}
https://github.com/ndssigner/ur-tones

Draft: do not move the seed of real funds with a draft format.

ur-tones.html    Web tool. Open it in a browser, offline. Paste a PSBT (from
                 Sparrow, say) and play it as telephone tones; listen to tones
                 (microphone or WAV file) and get the PSBT, a UR or a test seed
                 back. It cannot connect anywhere.
SPEC.md          The specification, cables included.
c/               The C library for small devices (no malloc, no floating point).
SHA256SUMS       Check the files: sha256sum -c SHA256SUMS

Borrador: no muevas con un formato en borrador la semilla de fondos reales.

ur-tones.html    Herramienta web. Ábrela en un navegador, sin conexión. Pega una
                 PSBT (de Sparrow, por ejemplo) y reprodúcela en tonos de
                 teléfono; escucha tonos (micrófono o archivo WAV) y recupera la
                 PSBT, un UR o una semilla de prueba. No puede conectarse.
SPEC.md          La especificación, cables incluidos.
c/               La librería en C para aparatos pequeños (sin malloc ni coma flotante).
SHA256SUMS       Comprueba los ficheros: sha256sum -c SHA256SUMS
"""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def add(z, name, data):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.external_attr = 0o644 << 16
    info.create_system = 3  # Unix, whatever the host
    z.writestr(info, data, compress_type=zipfile.ZIP_STORED)


def main():
    version = sys.argv[1]
    top = "ur-tones-%s/" % version
    contents = [(name, (ROOT / path).read_bytes()) for path, name in FILES]
    contents.append(("README.txt", README.format(version=version).encode()))
    sums = "".join("%s  %s\n" % (sha256(data), name) for name, data in contents)
    contents.append(("SHA256SUMS", sums.encode()))
    out = ROOT / "dist" / ("ur-tones-%s.zip" % version)
    out.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(out, "w") as z:
        for name, data in contents:
            add(z, top + name, data)
    data = out.read_bytes()
    line = "%s  %s\n" % (sha256(data), out.name)
    (ROOT / "dist" / "SHA256SUMS").write_text(line)
    sys.stdout.write(line)


if __name__ == "__main__":
    main()
