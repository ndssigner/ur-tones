#!/usr/bin/env python3
"""The Reed-Solomon tables of c/ur_tones.c: GF(256) with the polynomial
0x11D (as in QR codes), EXP doubled to 512 entries so a product needs no
modulo. Prints them as C; tests/test_c_layers.py checks the file's copy.

    python3 tools/gen_tables.py
"""


def tables():
    exp, log, x = [0] * 512, [0] * 256, 1
    for i in range(255):
        exp[i], log[x] = x, i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


def c_array(name, values):
    rows = [", ".join(str(v) for v in values[i:i + 16]) for i in range(0, len(values), 16)]
    return "static const uint8_t %s[%d] UT_ROM = {\n\t%s};\n" % (name, len(values), ",\n\t".join(rows))


if __name__ == "__main__":
    exp, log = tables()
    print(c_array("EXP", exp) + c_array("LOG", log), end="")
