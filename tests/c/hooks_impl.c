/* Stand-ins for hardware: a SHA-256 compression and a PBKDF2 written apart
 * from the library's, counting their calls, for the hooks UT_SHA256_BLOCK and
 * UT_PBKDF2_SHA256 (tests/configs/hook_*.h, tests/test_c_layers.py). */
#include <stdint.h>
#include <string.h>

uint32_t ut_test_blocks, ut_test_pbkdf2;

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t rotr(uint32_t x, int n) { return x >> n | x << (32 - n); }

void test_sha256_block(uint32_t state[8], const uint8_t block[64])
{
	uint32_t w[64], v[8];
	ut_test_blocks++;
	for (int i = 0; i < 64; i++) {
		if (i < 16)
			w[i] = (uint32_t)block[4 * i] << 24 | (uint32_t)block[4 * i + 1] << 16 | (uint32_t)block[4 * i + 2] << 8 | block[4 * i + 3];
		else
			w[i] = w[i - 16] + (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >> 3) + w[i - 7]
			       + (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >> 10);
	}
	memcpy(v, state, sizeof v);
	for (int i = 0; i < 64; i++) {
		uint32_t t1 = v[7] + (rotr(v[4], 6) ^ rotr(v[4], 11) ^ rotr(v[4], 25)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + K[i] + w[i];
		uint32_t t2 = (rotr(v[0], 2) ^ rotr(v[0], 13) ^ rotr(v[0], 22)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
		memmove(v + 1, v, 7 * sizeof v[0]);
		v[4] += t1;
		v[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++) state[i] += v[i];
}

/* a whole SHA-256 of a + b, as hardware that cannot load a state would do it */
static void sha256_two(const uint8_t *a, size_t na, const uint8_t *b, size_t nb, uint8_t out[32])
{
	uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	uint8_t buf[64];
	size_t fill = 0, total = na + nb;
	for (size_t i = 0; i < total; i++) {
		buf[fill++] = i < na ? a[i] : b[i - na];
		if (fill == 64) { test_sha256_block(h, buf); fill = 0; }
	}
	buf[fill++] = 0x80;
	if (fill > 56) { memset(buf + fill, 0, 64 - fill); test_sha256_block(h, buf); fill = 0; }
	memset(buf + fill, 0, 56 - fill);
	for (int i = 0; i < 8; i++) buf[56 + i] = (uint8_t)((uint64_t)total * 8 >> (56 - 8 * i));
	test_sha256_block(h, buf);
	for (int i = 0; i < 32; i++) out[i] = (uint8_t)(h[i / 4] >> (24 - 8 * (i % 4)));
}

static void hmac(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t n, uint8_t out[32])
{
	uint8_t k[64] = {0}, pad[64], inner[32];
	if (keylen > 64) sha256_two(key, keylen, NULL, 0, k);
	else memcpy(k, key, keylen);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
	sha256_two(pad, 64, msg, n, inner);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
	sha256_two(pad, 64, inner, 32, out);
}

void test_pbkdf2(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                 uint32_t iterations, uint8_t *out, size_t outlen)
{
	ut_test_pbkdf2++;
	for (uint32_t block = 1, pos = 0; pos < outlen; block++, pos += 32) {
		uint8_t msg[128], u[32], t[32];
		size_t n = saltlen < 124 ? saltlen : 124;
		memcpy(msg, salt, n);
		for (int i = 0; i < 4; i++) msg[n + i] = (uint8_t)(block >> (24 - 8 * i));
		hmac(pw, pwlen, msg, n + 4, u);
		memcpy(t, u, 32);
		for (uint32_t i = 1; i < iterations; i++) {
			hmac(pw, pwlen, u, 32, u);
			for (int j = 0; j < 32; j++) t[j] ^= u[j];
		}
		memcpy(out + pos, t, outlen - pos < 32 ? outlen - pos : 32);
	}
}
