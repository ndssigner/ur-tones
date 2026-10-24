/*
 * ur-tones (draft v0), C99 implementation for small devices (see ur_tones.h).
 * SPDX-License-Identifier: MIT
 *
 * A port of reference/python/ur_tones.py with integers only. The bytewords
 * word list is Blockchain Commons' (BCR-2020-012).
 */
#include "ur_tones.h"

#include <string.h>

static const char KEYS[] = "0123456789ABCD*#";
static const char PAD[4][5] = {"123A", "456B", "789C", "*0#D"};
static const uint16_t LOW[4] = {697, 770, 852, 941};
static const uint16_t HIGH[4] = {1209, 1336, 1477, 1633};
static const char LEAD[] = "CB", SYNC[] = "AD";
static const char *const UR_TYPES[] = {"", "crypto-psbt", "psbt", "crypto-seed", "seed", "crypto-account",
	"account-descriptor", "crypto-output", "output-descriptor", "bytes", "crypto-hdkey", "hdkey"};
#define NTYPES (sizeof UR_TYPES / sizeof UR_TYPES[0])
#define FORMAT_VERSION 0
#define KIND_SINGLE 0
#define KIND_PART 1

static int key_index(char k)
{
	for (int i = 0; i < 16; i++)
		if (KEYS[i] == k)
			return i;
	return -1;
}

/* ---- SHA-256, HMAC, PBKDF2 ---------------------------------------------- */

static const uint32_t K256[64] UT_ROM = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

typedef struct {
	uint32_t h[8];
	uint8_t buf[64];
	uint64_t len;
} sha256_ctx;

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static UT_HOT void sha256_block(sha256_ctx *c, const uint8_t *p)
{
	uint32_t w[64], a, b, d, e, f, g, h, cc;
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + UT_ROM_U32(&K256[i]) + w[i];
		uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
		h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
	static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	memcpy(c->h, iv, sizeof iv);
	c->len = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n)
{
	while (n) {
		size_t used = (size_t)(c->len % 64), take = 64 - used < n ? 64 - used : n;
		memcpy(c->buf + used, p, take);
		c->len += take; p += take; n -= take;
		if (c->len % 64 == 0)
			sha256_block(c, c->buf);
	}
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
	uint64_t bits = c->len * 8;
	uint8_t pad = 0x80, zero = 0, lenb[8];
	sha256_update(c, &pad, 1);
	while (c->len % 64 != 56)
		sha256_update(c, &zero, 1);
	for (int i = 0; i < 8; i++)
		lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
	sha256_update(c, lenb, 8);
	for (int i = 0; i < 8; i++) {
		out[4 * i] = (uint8_t)(c->h[i] >> 24); out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
		out[4 * i + 2] = (uint8_t)(c->h[i] >> 8); out[4 * i + 3] = (uint8_t)c->h[i];
	}
}

void ut_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
	sha256_ctx c;
	sha256_init(&c);
	sha256_update(&c, data, len);
	sha256_final(&c, out);
}

/* HMAC-SHA256 with the inner and outer states prepared once (PBKDF2 reuses them) */
typedef struct { sha256_ctx inner, outer; } hmac_ctx;

static void hmac_init(hmac_ctx *m, const uint8_t *key, size_t keylen)
{
	uint8_t k[64] = {0}, pad[64];
	if (keylen > 64)
		ut_sha256(key, keylen, k);
	else
		memcpy(k, key, keylen);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
	sha256_init(&m->inner); sha256_update(&m->inner, pad, 64);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
	sha256_init(&m->outer); sha256_update(&m->outer, pad, 64);
}

static void hmac(const hmac_ctx *m, const uint8_t *msg, size_t n, uint8_t out[32])
{
	sha256_ctx c = m->inner;
	uint8_t ih[32];
	sha256_update(&c, msg, n);
	sha256_final(&c, ih);
	c = m->outer;
	sha256_update(&c, ih, 32);
	sha256_final(&c, out);
}

void ut_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                      uint32_t iterations, uint8_t *out, size_t outlen)
{
	hmac_ctx m;
	hmac_init(&m, pw, pwlen);
	for (uint32_t block = 1, pos = 0; pos < outlen; block++, pos += 32) {
		uint8_t msg[128], u[32], t[32];
		size_t n = saltlen < 124 ? saltlen : 124;
		memcpy(msg, salt, n);
		msg[n] = (uint8_t)(block >> 24); msg[n + 1] = (uint8_t)(block >> 16);
		msg[n + 2] = (uint8_t)(block >> 8); msg[n + 3] = (uint8_t)block;
		hmac(&m, msg, n + 4, u);
		memcpy(t, u, 32);
		for (uint32_t i = 1; i < iterations; i++) {
			hmac(&m, u, 32, u);
			for (int j = 0; j < 32; j++) t[j] ^= u[j];
		}
		memcpy(out + pos, t, outlen - pos < 32 ? outlen - pos : 32);
	}
}

/* The seed PIN (SPEC §4): entropy ^= PBKDF2(upper-case PIN). */
static int pin_xor(uint8_t *entropy, size_t len, const char *pin)
{
	static const char salt[] = "ur-tones/seed-pin/v0";
	uint8_t key[32], up[64];
	size_t n = 0;
	if (!pin || !*pin)
		return UT_OK;
	for (; pin[n]; n++) {
		char ch = pin[n];
		if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
		if (n >= sizeof up || !((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')))
			return UT_ERR_PIN;
		up[n] = (uint8_t)ch;
	}
	ut_pbkdf2_sha256(up, n, (const uint8_t *)salt, sizeof salt - 1, 10000, key, len);
	for (size_t i = 0; i < len; i++) entropy[i] ^= key[i];
	return UT_OK;
}

/* ---- CRC-32 (as zlib's) --------------------------------------------------- */

uint32_t ut_crc32(const uint8_t *data, size_t len)
{
	uint32_t c = 0xFFFFFFFFu;
	for (size_t i = 0; i < len; i++) {
		c ^= data[i];
		for (int k = 0; k < 8; k++)
			c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
	}
	return c ^ 0xFFFFFFFFu;
}

/* ---- Reed-Solomon over GF(256), as in QR codes --------------------------- */

/* tools/gen_tables.py: the polynomial 0x11D; EXP doubled, so a product needs no modulo */
static const uint8_t EXP[512] UT_ROM = {
	1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38,
	76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192,
	157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35,
	70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
	95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240,
	253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226,
	217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206,
	129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204,
	133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84,
	168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115,
	230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255,
	227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65,
	130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166,
	81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9,
	18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22,
	44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1,
	2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76,
	152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157,
	39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35, 70,
	140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161, 95,
	190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253,
	231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217,
	175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206, 129,
	31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133,
	23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168,
	77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230,
	209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227,
	219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65, 130,
	25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81,
	162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18,
	36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44,
	88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1, 2};
static const uint8_t LOG[256] UT_ROM = {
	0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75,
	4, 100, 224, 14, 52, 141, 239, 129, 28, 193, 105, 248, 200, 8, 76, 113,
	5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218, 240, 18, 130, 69,
	29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166,
	6, 191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136,
	54, 208, 148, 206, 143, 150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64,
	30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250, 133, 186, 61,
	202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87,
	7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24,
	227, 165, 153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46,
	55, 63, 209, 91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97,
	242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57, 83, 71, 109, 65, 162,
	31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246,
	108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90,
	203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215,
	79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175};

#define GF_EXP(i) UT_ROM_U8(&EXP[i])
#define GF_LOG(i) UT_ROM_U8(&LOG[i])
static uint8_t gmul(uint8_t a, uint8_t b) { return (a && b) ? GF_EXP(GF_LOG(a) + GF_LOG(b)) : 0; }
static uint8_t gdiv(uint8_t a, uint8_t b) { return a ? GF_EXP((GF_LOG(a) + 255 - GF_LOG(b)) % 255) : 0; }

/* p[0] is the highest degree coefficient */
static uint8_t poly_eval(const uint8_t *p, size_t n, uint8_t x)
{
	uint8_t y = 0;
	for (size_t i = 0; i < n; i++) y = gmul(y, x) ^ p[i];
	return y;
}

void ut_rs_encode(const uint8_t *data, size_t n, size_t nsym, uint8_t *parity)
{
	uint8_t g[UT_PARITY + 1] = {1}, rem[UT_PARITY];
	for (size_t i = 0; i < nsym; i++) {          /* product of (x - alpha^i) */
		for (size_t j = i + 1; j > 0; j--) g[j] = g[j] ^ gmul(g[j - 1], GF_EXP(i));
	}
	memset(rem, 0, nsym);
	for (size_t i = 0; i < n; i++) {
		uint8_t coef = data[i] ^ rem[0];
		memmove(rem, rem + 1, nsym - 1);
		rem[nsym - 1] = 0;
		if (coef)
			for (size_t j = 0; j < nsym; j++) rem[j] ^= gmul(g[j + 1], coef);
	}
	memcpy(parity, rem, nsym);
}

int32_t ut_rs_correct(uint8_t *cw, size_t n, size_t nsym)
{
	uint8_t synd[UT_PARITY], lam[UT_PARITY + 1] = {1}, prev[UT_PARITY + 1] = {1}, next[UT_PARITY + 1];
	uint8_t omega[UT_PARITY] = {0}, rev[UT_PARITY + 1];
	size_t L = 0, m = 1, lamlen = 1, prevlen = 1;
	uint8_t b = 1;
	int any = 0, positions[UT_PARITY], npos = 0;
	if (nsym > UT_PARITY || n > 255)
		return UT_ERR_ARG;
	for (size_t i = 0; i < nsym; i++) {
		synd[i] = poly_eval(cw, n, GF_EXP(i));
		any |= synd[i];
	}
	if (!any)
		return 0;
	/* Berlekamp-Massey: error locator Lambda(x), lowest degree first */
	for (size_t i = 0; i < nsym; i++) {
		uint8_t d = synd[i];
		for (size_t j = 1; j <= L && j < lamlen; j++) d ^= gmul(lam[j], synd[i - j]);
		if (!d) { m++; continue; }
		uint8_t coef = gdiv(d, b);
		size_t shiftlen = m + prevlen, size = lamlen > shiftlen ? lamlen : shiftlen;
		if (size > UT_PARITY + 1) size = UT_PARITY + 1;
		for (size_t j = 0; j < size; j++) {
			uint8_t s = (j >= m && j - m < prevlen) ? gmul(coef, prev[j - m]) : 0;
			next[j] = (j < lamlen ? lam[j] : 0) ^ s;
		}
		if (2 * L <= i) {
			memcpy(prev, lam, lamlen); prevlen = lamlen;
			L = i + 1 - L; b = d; m = 1;
		} else
			m++;
		memcpy(lam, next, size); lamlen = size;
	}
	if (L == 0 || 2 * L > nsym)
		return UT_ERR_DECODE;
	for (size_t j = lamlen; j <= L; j++) lam[j] = 0;
	/* Chien search: position p (from the end) is wrong if Lambda(alpha^-p) == 0 */
	for (size_t j = 0; j <= L; j++) rev[j] = lam[L - j];
	for (size_t p = 0; p < n; p++)
		if (!poly_eval(rev, L + 1, GF_EXP((255 - p % 255) % 255))) {
			if (npos == (int)UT_PARITY) return UT_ERR_DECODE;
			positions[npos++] = (int)p;
		}
	if (npos != (int)L)
		return UT_ERR_DECODE;
	/* Forney: Omega(x) = S(x) Lambda(x) mod x^nsym */
	for (size_t i = 0; i < nsym; i++)
		for (size_t j = 0; j <= L && i + j < nsym; j++) omega[i + j] ^= gmul(synd[i], lam[j]);
	for (int q = 0; q < npos; q++) {
		int p = positions[q];
		uint8_t xinv = GF_EXP((255 - p % 255) % 255), num = 0, den = 0;
		for (size_t i = 0; i < nsym; i++)
			num ^= gmul(omega[i], GF_EXP((GF_LOG(xinv) * i) % 255));
		for (size_t j = 1; j <= L; j += 2)
			den ^= gmul(lam[j], GF_EXP((GF_LOG(xinv) * (j - 1)) % 255));
		if (!den) return UT_ERR_DECODE;
		cw[n - 1 - p] ^= gmul(GF_EXP(p % 255), gdiv(num, den));
	}
	for (size_t i = 0; i < nsym; i++)
		if (poly_eval(cw, n, GF_EXP(i))) return UT_ERR_DECODE;
	return npos;
}

/* ---- bytewords (minimal: first and last letter of each word) --------------- */

static const char BYTEWORDS[] UT_ROM =
	"ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebody"
	"bragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyan"
	"darkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepic"
	"evenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuel"
	"fundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawk"
	"heathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjade"
	"jazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwi"
	"knoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmany"
	"mathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobey"
	"oboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquad"
	"quizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilk"
	"skewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoys"
	"triptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswall"
	"wandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszero"
	"zestzinczonezoom";

#define BW(i) ((char)UT_ROM_U8((const uint8_t *)&BYTEWORDS[i]))

static int byteword(char a, char b)
{
	for (int i = 0; i < 256; i++)
		if (BW(4 * i) == a && BW(4 * i + 3) == b)
			return i;
	return -1;
}

/* bytes + their CRC-32, in minimal bytewords */
static int put_bytewords(const uint8_t *data, size_t n, char *out, size_t cap)
{
	uint32_t crc = ut_crc32(data, n);
	if (2 * (n + 4) + 1 > cap)
		return UT_ERR_SPACE;
	for (size_t i = 0; i < n + 4; i++) {
		uint8_t b = i < n ? data[i] : (uint8_t)(crc >> (8 * (3 - (i - n))));
		out[2 * i] = BW(4 * b);
		out[2 * i + 1] = BW(4 * b + 3);
	}
	out[2 * (n + 4)] = 0;
	return (int)(2 * (n + 4));
}

/* ---- tiny CBOR ---------------------------------------------------------------- */

static size_t cbor_head(uint8_t *p, int major, uint32_t v)
{
	if (v < 24) { p[0] = (uint8_t)(major << 5 | v); return 1; }
	if (v < 256) { p[0] = (uint8_t)(major << 5 | 24); p[1] = (uint8_t)v; return 2; }
	if (v < 65536) { p[0] = (uint8_t)(major << 5 | 25); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; return 3; }
	p[0] = (uint8_t)(major << 5 | 26);
	for (int i = 0; i < 4; i++) p[1 + i] = (uint8_t)(v >> (24 - 8 * i));
	return 5;
}

static int cbor_read(const uint8_t *p, size_t n, size_t *i, int major, uint32_t *v)
{
	if (*i >= n || p[*i] >> 5 != major) return UT_ERR_UR;
	unsigned info = p[*i] & 31, size = info < 24 ? 0 : info == 24 ? 1 : info == 25 ? 2 : info == 26 ? 4 : 99;
	if (size == 99 || *i + size >= n) return UT_ERR_UR;
	if (!size) { *v = info; (*i)++; return UT_OK; }
	*v = 0;
	for (unsigned j = 1; j <= size; j++) *v = *v << 8 | p[*i + j];
	*i += 1 + size;
	return UT_OK;
}

/* (seqNum, seqLen) of a multi-part UR part's CBOR */
static int part_sequence(const uint8_t *body, size_t n, uint32_t *seq, uint32_t *count)
{
	size_t i = 1;
	if (!n || body[0] != 0x85) return UT_ERR_UR;
	if (cbor_read(body, n, &i, 0, seq) || cbor_read(body, n, &i, 0, count)) return UT_ERR_UR;
	return UT_OK;
}

/* ---- UR texts --------------------------------------------------------------- */

typedef struct {
	char type[256];
	int kind;
	uint8_t body[300];
	size_t n;
} ur_t;

static int parse_ur(const char *text, ur_t *u)
{
	char t[UT_MAX_UR];
	size_t len = 0, slash[3], ns = 0;
	while (*text == ' ' || *text == '\n' || *text == '\r' || *text == '\t') text++;
	for (; text[len] && !(text[len] == ' ' || text[len] == '\n' || text[len] == '\r'); len++) {
		if (len + 1 >= sizeof t) return UT_ERR_TOO_LONG; /* longer than any one frame's UR */
		char ch = text[len];
		t[len] = (char)((ch >= 'A' && ch <= 'Z') ? ch + 32 : ch);
		if (t[len] == '/') { if (ns == 3) return UT_ERR_UR; slash[ns++] = len; }
	}
	t[len] = 0;
	if (len < 4 || memcmp(t, "ur:", 3) || ns < 1 || ns > 2) return UT_ERR_UR;
	size_t tl = slash[0] - 3;
	if (!tl || tl > 255) return UT_ERR_UR;
	memcpy(u->type, t + 3, tl); u->type[tl] = 0;
	for (size_t i = 0; i < tl; i++) {
		char ch = u->type[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) return UT_ERR_UR;
	}
	u->kind = ns == 1 ? KIND_SINGLE : KIND_PART;
	const char *words = t + slash[ns - 1] + 1;
	size_t wl = len - slash[ns - 1] - 1;
	if (wl % 2 || wl < 10) return UT_ERR_UR;
	if (wl / 2 - 4 > sizeof u->body) return UT_ERR_TOO_LONG;
	uint8_t all[sizeof u->body + 4];
	for (size_t i = 0; i < wl / 2; i++) {
		int b = byteword(words[2 * i], words[2 * i + 1]);
		if (b < 0) return UT_ERR_UR;
		all[i] = (uint8_t)b;
	}
	u->n = wl / 2 - 4;
	uint32_t crc = ut_crc32(all, u->n);
	for (int i = 0; i < 4; i++)
		if (all[u->n + i] != (uint8_t)(crc >> (24 - 8 * i))) return UT_ERR_CHECKSUM;
	memcpy(u->body, all, u->n);
	if (u->kind == KIND_PART) {
		uint32_t seq, count, s2 = 0, c2 = 0;
		const char *p = t + slash[0] + 1;
		if (part_sequence(u->body, u->n, &seq, &count)) return UT_ERR_UR;
		while (*p >= '0' && *p <= '9') s2 = s2 * 10 + (uint32_t)(*p++ - '0');
		if (*p++ != '-') return UT_ERR_UR;
		while (*p >= '0' && *p <= '9') c2 = c2 * 10 + (uint32_t)(*p++ - '0');
		if (*p != '/' || s2 != seq || c2 != count) return UT_ERR_UR;
	}
	return UT_OK;
}

static int put_str(char *out, size_t cap, size_t *pos, const char *s)
{
	size_t n = strlen(s);
	if (*pos + n + 1 > cap) return UT_ERR_SPACE;
	memcpy(out + *pos, s, n + 1);
	*pos += n;
	return UT_OK;
}

static int put_uint(char *out, size_t cap, size_t *pos, uint32_t v)
{
	char tmp[11];
	int i = 10;
	tmp[i] = 0;
	do { tmp[--i] = (char)('0' + v % 10); v /= 10; } while (v);
	return put_str(out, cap, pos, tmp + i);
}

static int ur_text(const char *type, int kind, const uint8_t *body, size_t n, char *out, size_t cap)
{
	size_t pos = 0;
	int r;
	if ((r = put_str(out, cap, &pos, "ur:")) || (r = put_str(out, cap, &pos, type)) || (r = put_str(out, cap, &pos, "/")))
		return r;
	if (kind == KIND_PART) {
		uint32_t seq, count;
		if (part_sequence(body, n, &seq, &count)) return UT_ERR_UR;
		if ((r = put_uint(out, cap, &pos, seq)) || (r = put_str(out, cap, &pos, "-")) ||
		    (r = put_uint(out, cap, &pos, count)) || (r = put_str(out, cap, &pos, "/")))
			return r;
	}
	r = put_bytewords(body, n, out + pos, cap - pos);
	return r < 0 ? r : (int)pos + r;
}

/* ---- base-15 differential tones (SPEC §2.2) ---------------------------------- */

static int to_tones(const uint8_t *data, size_t n, char previous, char *out, size_t cap)
{
	size_t nbits = 8 * n, chunks = (nbits + 14) / 15;
	int prev = key_index(previous);
	if (4 * chunks + 1 > cap) return UT_ERR_SPACE;
	for (size_t c = 0; c < chunks; c++) {
		uint32_t v = 0;
		for (size_t b = 0; b < 15; b++) {
			size_t bit = 15 * c + b;
			v = v << 1 | (bit < nbits ? (uint32_t)(data[bit / 8] >> (7 - bit % 8) & 1) : 0);
		}
		static const uint32_t E[4] = {3375, 225, 15, 1};
		for (int i = 0; i < 4; i++) {
			prev = (int)((prev + 1 + v / E[i]) % 16);
			v %= E[i];
			out[4 * c + i] = KEYS[prev];
		}
	}
	out[4 * chunks] = 0;
	return (int)(4 * chunks);
}

/* lenient: misheard tones give wrong bytes, for Reed-Solomon */
static int from_tones(const char *tones, size_t len, char previous, uint8_t *out, size_t cap)
{
	size_t groups = len / 4, nbits = 15 * groups, n = nbits / 8;
	int prev = key_index(previous);
	if (len % 4) return UT_ERR_DECODE;
	if (n > cap) return UT_ERR_SPACE;
	memset(out, 0, n);
	for (size_t g = 0; g < groups; g++) {
		uint32_t v = 0;
		for (int i = 0; i < 4; i++) {
			int k = key_index(tones[4 * g + i]);
			if (k < 0) return UT_ERR_DECODE;
			int d = ((k - prev - 1) % 16 + 16) % 16;   /* 15: a repeated tone, impossible */
			v = v * 15 + (uint32_t)(d > 14 ? 14 : d);
			prev = k;
		}
		v &= 0x7FFF;
		for (int b = 0; b < 15; b++) {
			size_t bit = 15 * g + (size_t)b;
			if (bit < 8 * n && (v >> (14 - b) & 1))
				out[bit / 8] |= (uint8_t)(0x80 >> bit % 8);
		}
	}
	return (int)n;
}

/* ---- frames -------------------------------------------------------------------- */

int32_t ut_frame_from_ur(const char *ur, ut_frame *f)
{
	ur_t u;
	int r = parse_ur(ur, &u);
	if (r) return r;
	size_t tl = strlen(u.type);
	if (u.n < 1 || u.n > 255 || tl > UT_MAX_TYPE) return UT_ERR_TOO_LONG;
	f->kind = (uint8_t)u.kind;
	memcpy(f->type, u.type, tl + 1);
	memcpy(f->body, u.body, u.n);
	f->n = (uint8_t)u.n;
	return f->n;
}

int32_t ut_frame_ur(const ut_frame *f, char *ur, size_t cap)
{
	return ur_text(f->type, f->kind, f->body, f->n, ur, cap);
}

int32_t ut_frame_encode(const ut_frame *f, char *tones, size_t cap)
{
	uint8_t cw[256];
	size_t n = 0, code = 0;
	if (f->n < 1 || (f->kind != UT_KIND_SINGLE && f->kind != UT_KIND_PART)) return UT_ERR_ARG;
	for (size_t i = 1; i < NTYPES; i++)
		if (!strcmp(UR_TYPES[i], f->type)) code = i;
	cw[n++] = (uint8_t)(FORMAT_VERSION << 4 | f->kind);
	cw[n++] = (uint8_t)code;
	cw[n++] = f->n;
	if (!code) {
		size_t tl = strlen(f->type);
		if (n + 1 + tl > 255) return UT_ERR_TOO_LONG;
		cw[n++] = (uint8_t)tl;
		memcpy(cw + n, f->type, tl); n += tl;
	}
	if (n + f->n + UT_PARITY > 255) return UT_ERR_TOO_LONG;
	memcpy(cw + n, f->body, f->n); n += f->n;
	/* a byte of padding when the base-15 digits would leave 8 bits or more spare */
	size_t total = n + UT_PARITY;
	if (15 * ((8 * total + 14) / 15) - 8 * total >= 8) {
		if (total + 1 > 255) return UT_ERR_TOO_LONG;
		cw[n++] = 0;
	}
	ut_rs_encode(cw, n, UT_PARITY, cw + n);
	n += UT_PARITY;
	if (cap < 5) return UT_ERR_SPACE;
	memcpy(tones, LEAD, 2); memcpy(tones + 2, SYNC, 2);
	int r = to_tones(cw, n, SYNC[1], tones + 4, cap - 4);
	return r < 0 ? r : r + 4;
}

int32_t ut_ur_to_frame(const char *ur, char *tones, size_t cap)
{
	ut_frame f;
	int32_t r = ut_frame_from_ur(ur, &f);
	return r < 0 ? r : ut_frame_encode(&f, tones, cap);
}

/* the codeword after the sync, checked: Reed-Solomon, header, a part's sequence */
static int frame_body(const char *tones, size_t len, ut_frame *f, int *corrected)
{
	uint8_t cw[300];
	int n = from_tones(tones, len, SYNC[1], cw, sizeof cw);
	if (n < 0) return n;
	if (n < UT_PARITY + 4 || n > 255) return UT_ERR_DECODE;
	int fixed = ut_rs_correct(cw, (size_t)n, UT_PARITY);
	if (fixed < 0) return fixed;
	size_t dlen = (size_t)n - UT_PARITY, i = 3;
	int version = cw[0] >> 4, kind = cw[0] & 15;
	if (version != FORMAT_VERSION || (kind != KIND_SINGLE && kind != KIND_PART)) return UT_ERR_DECODE;
	if (cw[1] == 0) {
		size_t tl = cw[3];
		if (4 + tl > dlen || tl > UT_MAX_TYPE) return UT_ERR_DECODE;
		memcpy(f->type, cw + 4, tl); f->type[tl] = 0;
		i = 4 + tl;
	} else if (cw[1] < NTYPES)
		strcpy(f->type, UR_TYPES[cw[1]]);
	else
		return UT_ERR_DECODE;
	size_t blen = cw[2];
	if (i + blen > dlen || dlen - i - blen > 1 || (dlen - i - blen == 1 && cw[i + blen])) return UT_ERR_DECODE;
	uint32_t seq, count;
	if (kind == KIND_PART && part_sequence(cw + i, blen, &seq, &count)) return UT_ERR_DECODE;
	f->kind = (uint8_t)kind;
	memcpy(f->body, cw + i, blen);
	f->n = (uint8_t)blen;
	if (corrected) *corrected = fixed;
	return (int)blen;
}

int32_t ut_frame_decode(const char *tones, ut_frame *f, int *corrected)
{
	size_t len = strlen(tones), starts[4], ns = 0;
	int err = UT_ERR_SYNC;
	char cand[UT_MAX_FRAME + 2];
	for (size_t i = 0; i < 4 && i + 2 <= len; i++)
		if (tones[i] == SYNC[0] && tones[i + 1] == SYNC[1]) starts[ns++] = i + 2;
	if (!ns && len && tones[0] == SYNC[1]) starts[ns++] = 1;   /* the sync's first tone was lost */
	for (size_t s = 0; s < ns; s++) {
		const char *data = tones + starts[s];
		size_t dl = len - starts[s];
		if (dl > UT_MAX_FRAME) return UT_ERR_DECODE;
		int r = frame_body(data, dl, f, corrected);
		if (r >= 0) return r;
		err = r;
		/* one extra or one lost tone (the count tells which): drop or add one
		 * every third place; once the groups line up again, Reed-Solomon
		 * repairs the few wrong bytes around the mistake, and judges */
		for (size_t i = 1; i < dl && (dl % 4 == 1 || dl % 4 == 3); i += 3) {
			size_t cl = 0;
			if (dl % 4 == 1) {
				memcpy(cand, data, i); memcpy(cand + i, data + i + 1, dl - i - 1); cl = dl - 1;
			} else {
				char fill = 0;
				for (int k = 0; k < 16 && !fill; k++)
					if (KEYS[k] != data[i - 1] && KEYS[k] != data[i]) fill = KEYS[k];
				memcpy(cand, data, i); cand[i] = fill; memcpy(cand + i + 1, data + i, dl - i); cl = dl + 1;
			}
			r = frame_body(cand, cl, f, corrected);
			if (r >= 0) return r;
		}
	}
	return err;
}

int32_t ut_frame_to_ur(const char *tones, char *ur, size_t cap, int *corrected)
{
	ut_frame f;
	int fixed = 0;
	int32_t r = ut_frame_decode(tones, &f, &fixed);
	if (r < 0) return r;
	r = ut_frame_ur(&f, ur, cap);
	if (r >= 0 && corrected) *corrected = fixed;
	return r;
}

/* ---- seeds ---------------------------------------------------------------------- */

static void indices(const uint8_t *e, size_t len, uint16_t *idx)
{
	uint8_t h[32];
	size_t words = len * 3 / 4, nbits = 8 * len + len / 4;
	ut_sha256(e, len, h);
	for (size_t w = 0; w < words; w++) {
		uint16_t v = 0;
		for (size_t b = 0; b < 11; b++) {
			size_t bit = 11 * w + b;
			int x = bit < 8 * len ? e[bit / 8] >> (7 - bit % 8) & 1 : h[(bit - 8 * len) / 8] >> (7 - (bit - 8 * len) % 8) & 1;
			v = (uint16_t)(v << 1 | (uint16_t)x);
		}
		idx[w] = v;
	}
	(void)nbits;
}

int32_t ut_seed_to_keypad(const uint8_t *entropy, size_t len, const char *pin, char *out, size_t cap)
{
	uint8_t e[32];
	uint16_t idx[24];
	int r;
	if (len != 16 && len != 32) return UT_ERR_SEED;
	memcpy(e, entropy, len);
	if ((r = pin_xor(e, len, pin))) return r;
	indices(e, len, idx);
	size_t words = len * 3 / 4;
	if (4 * words + 3 > cap) return UT_ERR_SPACE;
	out[0] = '*';
	for (size_t w = 0; w < words; w++)
		for (int d = 0; d < 4; d++) {
			static const uint16_t P[4] = {1000, 100, 10, 1};
			out[1 + 4 * w + (size_t)d] = (char)('0' + idx[w] / P[d] % 10);
		}
	out[1 + 4 * words] = '#';
	out[2 + 4 * words] = 0;
	memset(e, 0, sizeof e);
	return (int32_t)(2 + 4 * words);
}

int32_t ut_keypad_to_seed(const char *tones, const char *pin, uint8_t *entropy)
{
	size_t len = strlen(tones), nd = len - 2, words = nd / 4;
	uint16_t idx[24], check[24];
	if (len < 3 || tones[0] != '*' || tones[len - 1] != '#' || nd % 4 || (words != 12 && words != 24)) return UT_ERR_SEED;
	for (size_t w = 0; w < words; w++) {
		unsigned v = 0;
		for (int d = 0; d < 4; d++) {
			char ch = tones[1 + 4 * w + (size_t)d];
			if (ch < '0' || ch > '9') return UT_ERR_SEED;
			v = v * 10 + (unsigned)(ch - '0');
		}
		if (v > 2047) return UT_ERR_SEED;
		idx[w] = (uint16_t)v;
	}
	size_t elen = words * 4 / 3;
	memset(entropy, 0, elen);
	for (size_t bit = 0; bit < 8 * elen; bit++)
		if (idx[bit / 11] >> (10 - bit % 11) & 1) entropy[bit / 8] |= (uint8_t)(0x80 >> bit % 8);
	indices(entropy, elen, check);
	if (check[words - 1] != idx[words - 1]) return UT_ERR_CHECKSUM;
	int r = pin_xor(entropy, elen, pin);
	return r ? r : (int32_t)elen;
}

int32_t ut_seed_to_ur(const uint8_t *entropy, size_t len, const char *pin, char *ur, size_t cap)
{
	uint8_t body[36];
	size_t n = 0;
	int r;
	if (len != 16 && len != 32) return UT_ERR_SEED;
	body[n++] = 0xA1; body[n++] = 0x01;
	n += cbor_head(body + n, 2, (uint32_t)len);
	memcpy(body + n, entropy, len);
	if ((r = pin_xor(body + n, len, pin))) return r;
	n += len;
	r = ur_text("crypto-seed", KIND_SINGLE, body, n, ur, cap);
	memset(body, 0, sizeof body);
	return r;
}

int32_t ut_ur_to_seed(const char *ur, const char *pin, uint8_t *entropy)
{
	ur_t u;
	size_t i = 2;
	uint32_t len;
	int r = parse_ur(ur, &u);
	if (r) return r;
	if ((strcmp(u.type, "crypto-seed") && strcmp(u.type, "seed")) || u.kind != KIND_SINGLE) return UT_ERR_SEED;
	if (u.n < 3 || u.body[0] != 0xA1 || u.body[1] != 0x01 || cbor_read(u.body, u.n, &i, 2, &len)) return UT_ERR_SEED;
	if ((len != 16 && len != 32) || i + len > u.n) return UT_ERR_SEED;
	memcpy(entropy, u.body + i, len);
	memset(&u, 0, sizeof u);
	r = pin_xor(entropy, len, pin);
	return r ? r : (int32_t)len;
}

/* ---- IEEE 754 doubles, for UR's fountain codes ---------------------------------
 * ur2 (and every UR library) picks a mixed part's fragments with doubles: a
 * receiver must make the very same roundings. By default they are made here
 * with integers (round to nearest, ties to even; normal numbers and zero are
 * all these values ever are). UT_USE_DOUBLE=1 uses the CPU's own instead. */

typedef ut_f64 f64;
#if UT_USE_DOUBLE
static f64 f_u64(uint64_t x) { return (f64)x; }
static f64 f_add(f64 a, f64 b) { return a + b; }
static f64 f_sub(f64 a, f64 b) { return a - b; }
static f64 f_mul(f64 a, f64 b) { return a * b; }
static f64 f_div(f64 a, f64 b) { return a / b; }
static int f_lt(f64 a, f64 b) { return a < b; }
static uint32_t f_floor(f64 a) { return (uint32_t)a; }
static f64 f_over_2_64(uint64_t x) { return (f64)x / 18446744073709551616.0; }
#else /* f64: the IEEE 754 bits */
#define F_FRAC ((UINT64_C(1) << 52) - 1)

/* value = m * 2^e (m > 0, any bits): rounded to 53 bits, packed. A bit 0 that
 * was "jammed" (ORed in for lost bits) always sits below the rounding point. */
static f64 f_pack(int neg, int e, uint64_t m)
{
	int top = 63;
	while (!(m >> top)) top--;
	if (top > 52) {
		int s = top - 52;
		uint64_t lost = m & ((UINT64_C(1) << s) - 1), half = UINT64_C(1) << (s - 1);
		m >>= s; e += s;
		if (lost > half || (lost == half && (m & 1))) m++;
		if (m >> 53) { m >>= 1; e++; }
	} else { m <<= 52 - top; e -= 52 - top; }
	return (uint64_t)neg << 63 | (uint64_t)(e + 1075) << 52 | (m & F_FRAC);
}
static void f_unpack(f64 a, int *neg, int *e, uint64_t *m)
{
	*neg = (int)(a >> 63);
	*e = (int)(a >> 52 & 0x7FF) - 1075;
	*m = (a & F_FRAC) | UINT64_C(1) << 52;
}
static f64 f_u64(uint64_t x) { return x ? f_pack(0, 0, x) : 0; }
static f64 f_add(f64 a, f64 b)
{
	int na, ea, nb, eb;
	uint64_t ma, mb, m;
	if (!(a << 1)) return b;
	if (!(b << 1)) return a;
	f_unpack(a, &na, &ea, &ma); f_unpack(b, &nb, &eb, &mb);
	if (eb > ea || (eb == ea && mb > ma)) { f64 t = a; a = b; b = t; return f_add(a, b); }
	ma <<= 9; mb <<= 9;                       /* 9 guard bits */
	int d = ea - eb;
	if (d > 62) mb = 1;
	else if (d) mb = mb >> d | ((mb << (64 - d)) != 0);
	m = na == nb ? ma + mb : ma - mb;
	return m ? f_pack(na, ea - 9, m) : 0;
}
static f64 f_sub(f64 a, f64 b) { return f_add(a, b ^ UINT64_C(1) << 63); }
static f64 f_mul(f64 a, f64 b)
{
	int na, ea, nb, eb;
	uint64_t ma, mb;
	if (!(a << 1) || !(b << 1)) return 0;
	f_unpack(a, &na, &ea, &ma); f_unpack(b, &nb, &eb, &mb);
	/* the 106-bit product, in 32-bit pieces */
	uint64_t al = ma & 0xFFFFFFFF, ah = ma >> 32, bl = mb & 0xFFFFFFFF, bh = mb >> 32;
	uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
	uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFF) + (hl & 0xFFFFFFFF);
	uint64_t lo = (ll & 0xFFFFFFFF) | mid << 32, hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
	/* keep the top 64 bits of the 128, the rest jammed into bit 0 */
	uint64_t m = hi << 22 | lo >> 42 | ((lo & ((UINT64_C(1) << 42) - 1)) != 0);
	return f_pack(na ^ nb, ea + eb + 42, m);
}
static f64 f_div(f64 a, f64 b)
{
	int na, ea, nb, eb;
	uint64_t ma, mb, q = 0;
	if (!(a << 1)) return 0;
	f_unpack(a, &na, &ea, &ma); f_unpack(b, &nb, &eb, &mb);
	for (int i = 0; i < 62; i++) {            /* 62 quotient bits */
		q <<= 1;
		if (ma >= mb) { ma -= mb; q |= 1; }
		ma <<= 1;
	}
	return f_pack(na ^ nb, ea - eb - 61, q | (ma != 0));
}
static int f_lt(f64 a, f64 b)
{
	uint64_t ka = a >> 63 ? ~a : a | UINT64_C(1) << 63, kb = b >> 63 ? ~b : b | UINT64_C(1) << 63;
	return ka < kb;
}
static uint32_t f_floor(f64 a) /* a >= 0, < 2^32 */
{
	int neg, e;
	uint64_t m;
	if (!(a << 1)) return 0;
	f_unpack(a, &neg, &e, &m);
	return e >= 0 ? (uint32_t)(m << e) : -e > 63 ? 0 : (uint32_t)(m >> -e);
}
static f64 f_over_2_64(uint64_t x) { return x ? f_u64(x) - ((uint64_t)64 << 52) : 0; }
#endif

/* ---- UR fountain codes (BCR-2020-005), as ur2 -------------------------------------- */

typedef struct { uint64_t s[4]; } xoshiro;
static uint64_t rotl64(uint64_t x, int k) { return x << k | x >> (64 - k); }
static uint64_t xo_next(xoshiro *x)
{
	uint64_t *s = x->s, r = rotl64(s[1] * 5, 7) * 9, t = s[1] << 17;
	s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
	s[2] ^= t;
	s[3] = rotl64(s[3], 45);
	return r;
}
static f64 xo_double(xoshiro *x) { return f_over_2_64(xo_next(x)); }

/* Vose's alias method over the degrees 1..n with weights 1/d, as ur2 builds
 * it (the same operations in the same order: the same roundings) */
static void sampler_build(ut_sampler *t, uint32_t n)
{
	f64 total = 0, one = f_u64(1), fn = f_u64(n);
	uint16_t *stack = t->stack;       /* small ones from the front, large ones from the back */
	uint32_t ns = 0, nl = 0;
	for (uint32_t i = 0; i < n; i++) total = f_add(total, f_div(one, f_u64(i + 1)));
	for (uint32_t i = 0; i < n; i++) t->prob[i] = f_div(f_mul(f_div(one, f_u64(i + 1)), fn), total);
	for (uint32_t j = n; j-- > 0;) {
		if (f_lt(t->prob[j], one)) stack[ns++] = (uint16_t)j;
		else stack[n - 1 - nl++] = (uint16_t)j;
	}
	while (ns && nl) {
		uint16_t a = stack[--ns], g = stack[n - nl--];
		t->alias[a] = g;                  /* prob[a] stays as it is: final */
		t->prob[g] = f_add(t->prob[g], f_sub(t->prob[a], one));
		if (f_lt(t->prob[g], one)) stack[ns++] = g;
		else stack[n - 1 - nl++] = g;
	}
	while (nl) t->prob[stack[n - nl--]] = one;
	while (ns) t->prob[stack[--ns]] = one;
	t->n = n;
}

static void put_be32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (24 - 8 * i)); }

/* the fragments a part carries, as bits of `set` (seq_len bits) */
static void choose(ut_sampler *t, uint32_t seq_num, uint32_t seq_len, uint32_t checksum, uint8_t *set)
{
	memset(set, 0, (seq_len + 7) / 8);
	if (seq_num <= seq_len) { set[(seq_num - 1) / 8] |= (uint8_t)(1 << (seq_num - 1) % 8); return; }
	uint8_t seed[8], h[32];
	xoshiro x;
	put_be32(seed, seq_num); put_be32(seed + 4, checksum);
	ut_sha256(seed, 8, h);
	for (int i = 0; i < 4; i++) {
		x.s[i] = 0;
		for (int j = 0; j < 8; j++) x.s[i] = x.s[i] << 8 | h[8 * i + j];
	}
	if (t->n != seq_len) sampler_build(t, seq_len);
	f64 r1 = xo_double(&x), r2 = xo_double(&x);
	uint32_t i = f_floor(f_mul(f_u64(seq_len), r1));
	uint32_t degree = (f_lt(r2, t->prob[i]) ? i : t->alias[i]) + 1;
	/* the first `degree` items of ur2's shuffle of 0..seq_len-1 */
	for (uint32_t k = 0; k < degree; k++) {
		uint32_t pick = f_floor(f_mul(xo_double(&x), f_u64(seq_len - k))), j = 0;
		for (;; j++) {
			if (set[j / 8] >> j % 8 & 1) continue;
			if (!pick--) break;
		}
		set[j / 8] |= (uint8_t)(1 << j % 8);
	}
}

int32_t ut_fountain_choose(ut_sampler *t, uint32_t seq_num, uint32_t seq_len, uint32_t checksum, uint8_t *set)
{
	if (!t || !seq_num || !seq_len || seq_len > UT_MAX_PARTS) return UT_ERR_ARG;
	choose(t, seq_num, seq_len, checksum, set);
	return UT_OK;
}

static uint32_t fragment_length(uint32_t len, uint32_t max)
{
	uint32_t n = len < 10 ? 1 : len / 10;  /* ur2's minimum fragment: 10 bytes */
	for (uint32_t count = 1; count <= n; count++) {
		uint32_t f = (len + count - 1) / count;
		if (f <= max) return f;
	}
	return len;
}

int32_t ut_fountain_encoder_init(ut_fountain_encoder *e, const uint8_t *msg, size_t len, size_t max_fragment)
{
	if (!len || len > UINT32_MAX || !max_fragment || max_fragment > UT_MAX_FRAGMENT) return UT_ERR_ARG;
	e->msg = msg;
	e->len = (uint32_t)len;
	e->checksum = ut_crc32(msg, len);
	e->fragment = fragment_length(e->len, (uint32_t)max_fragment);
	e->seq_len = (e->len + e->fragment - 1) / e->fragment;
	e->seq_num = 0;
	e->sampler.n = 0;
	return e->seq_len > UT_MAX_PARTS ? UT_ERR_TOO_LONG : UT_OK;
}

int32_t ut_fountain_next_part(ut_fountain_encoder *e, uint8_t *out, size_t cap)
{
	uint8_t set[(UT_MAX_PARTS + 7) / 8], h[5 * 4];
	size_t n = 0;
	uint32_t f = e->fragment;
	e->seq_num++;
	n += cbor_head(h, 4, 5);
	n += cbor_head(h + n, 0, e->seq_num);
	if (n + 4 * 5 + 5 + f > cap) return UT_ERR_SPACE;
	memcpy(out, h, n);
	n += cbor_head(out + n, 0, e->seq_len);
	n += cbor_head(out + n, 0, e->len);
	n += cbor_head(out + n, 0, e->checksum);
	n += cbor_head(out + n, 2, f);
	choose(&e->sampler, e->seq_num, e->seq_len, e->checksum, set);
	memset(out + n, 0, f);
	for (uint32_t i = 0; i < e->seq_len; i++) {
		if (!(set[i / 8] >> i % 8 & 1)) continue;
		for (uint32_t j = 0; j < f && i * f + j < e->len; j++) out[n + j] ^= e->msg[i * f + j];
	}
	return (int32_t)(n + f);
}

int32_t ut_fountain_next_frame(ut_fountain_encoder *e, const char *type, ut_frame *f)
{
	size_t tl = strlen(type);
	int32_t n;
	if (tl > UT_MAX_TYPE) return UT_ERR_TOO_LONG;
	memcpy(f->type, type, tl + 1);
	if (e->seq_len == 1) {
		if (e->len > sizeof f->body) return UT_ERR_TOO_LONG;
		memcpy(f->body, e->msg, e->len);
		f->kind = KIND_SINGLE;
		f->n = (uint8_t)e->len;
		return f->n;
	}
	if ((n = ut_fountain_next_part(e, f->body, sizeof f->body)) < 0) return n;
	f->kind = KIND_PART;
	f->n = (uint8_t)n;
	return n;
}

int32_t ut_fountain_next_ur(ut_fountain_encoder *e, const char *type, char *ur, size_t cap)
{
	uint8_t body[UT_MAX_FRAGMENT + 32];
	int32_t n;
	if (e->seq_len == 1) return ur_text(type, KIND_SINGLE, e->msg, e->len, ur, cap);
	if ((n = ut_fountain_next_part(e, body, sizeof body)) < 0) return n;
	return ur_text(type, KIND_PART, body, (size_t)n, ur, cap);
}

/* ---- the receiving end ------------------------------------------------------------ */
/* Work memory: the message (seq_len fragments), which fragments are known
 * (bits), then a pool of mixed parts, each its fragments' bits and its data. */

static int has(const uint8_t *set, uint32_t i) { return set[i / 8] >> i % 8 & 1; }
static uint32_t count_bits(const uint8_t *set, uint32_t nbytes)
{
	uint32_t c = 0;
	for (uint32_t i = 0; i < nbytes; i++) for (uint8_t b = set[i]; b; b &= (uint8_t)(b - 1)) c++;
	return c;
}
static uint8_t *pool_entry(ut_fountain_decoder *d, uint32_t k) { return d->pool + (size_t)k * (d->set_bytes + d->fragment); }

/* takes out of (set, data) the fragments already known */
static void reduce_known(ut_fountain_decoder *d, uint8_t *set, uint8_t *data)
{
	for (uint32_t i = 0; i < d->seq_len; i++) {
		if (!has(set, i) || !has(d->known, i)) continue;
		for (uint32_t j = 0; j < d->fragment; j++) data[j] ^= d->msg[(size_t)i * d->fragment + j];
		set[i / 8] &= (uint8_t)~(1 << i % 8);
	}
}
static uint32_t first_bit(const uint8_t *set, uint32_t n)
{
	uint32_t i = 0;
	while (i < n && !has(set, i)) i++;
	return i;
}
static void learn(ut_fountain_decoder *d, uint32_t i, const uint8_t *data)
{
	memcpy(d->msg + (size_t)i * d->fragment, data, d->fragment);
	d->known[i / 8] |= (uint8_t)(1 << i % 8);
	d->nknown++;
}
/* mixed parts that became simple, or empty, as fragments were learnt */
static void sweep(ut_fountain_decoder *d)
{
	for (int changed = 1; changed;) {
		changed = 0;
		for (uint32_t k = 0; k < d->nmixed;) {
			uint8_t *e = pool_entry(d, k), *data = e + d->set_bytes;
			reduce_known(d, e, data);
			uint32_t c = count_bits(e, d->set_bytes);
			if (c > 1) { k++; continue; }
			if (c == 1) { learn(d, first_bit(e, d->seq_len), data); changed = 1; }
			if (k != --d->nmixed) memcpy(e, pool_entry(d, d->nmixed), d->set_bytes + d->fragment);
		}
	}
}
static int subset(const uint8_t *a, const uint8_t *b, uint32_t n) /* a within b */
{
	for (uint32_t i = 0; i < n; i++) if (a[i] & ~b[i]) return 0;
	return 1;
}

int32_t ut_fountain_decoder_init(ut_fountain_decoder *d, uint8_t *work, size_t work_len)
{
	memset(d, 0, sizeof *d);
	d->work = work;
	d->work_len = work_len;
	return work ? UT_OK : UT_ERR_ARG;
}

static int receive_part(ut_fountain_decoder *d, const uint8_t *body, size_t n)
{
	uint32_t seq_num, seq_len, len, checksum, f;
	size_t i = 1;
	uint8_t set[(UT_MAX_PARTS + 7) / 8], data[UT_MAX_FRAGMENT];
	if (!n || body[0] != 0x85 || cbor_read(body, n, &i, 0, &seq_num) || cbor_read(body, n, &i, 0, &seq_len) ||
	    cbor_read(body, n, &i, 0, &len) || cbor_read(body, n, &i, 0, &checksum) || cbor_read(body, n, &i, 2, &f) ||
	    i + f != n || !seq_num || !seq_len || !f || f > UT_MAX_FRAGMENT || (uint64_t)seq_len * f < len ||
	    (uint64_t)(seq_len - 1) * f >= len)
		return UT_ERR_UR;
	if (seq_len > UT_MAX_PARTS) return UT_ERR_TOO_LONG;
	if (!d->seq_len) {                    /* the first part: lay out the work memory */
		size_t sb = (seq_len + 7) / 8, need = (size_t)seq_len * f + sb;
		if (need + sb + f > d->work_len) return UT_ERR_SPACE;
		d->seq_len = seq_len; d->len = len; d->checksum = checksum; d->fragment = f; d->set_bytes = (uint32_t)sb;
		d->msg = d->work;
		d->known = d->work + (size_t)seq_len * f;
		memset(d->known, 0, sb);
		d->pool = d->known + sb;
		d->max_mixed = (uint32_t)((d->work_len - need) / (sb + f));
	} else if (seq_len != d->seq_len || len != d->len || checksum != d->checksum || f != d->fragment)
		return UT_ERR_MESSAGE;
	if (d->done) return 1;
	choose(&d->sampler, seq_num, seq_len, checksum, set);
	memcpy(data, body + i, f);
	reduce_known(d, set, data);
	uint32_t c = count_bits(set, d->set_bytes);
	if (c > 1) {                          /* mixed: take out the mixed parts it contains */
		for (uint32_t k = 0; k < d->nmixed && c > 1; k++) {
			uint8_t *e = pool_entry(d, k);
			if (!memcmp(e, set, d->set_bytes)) { c = 0; break; }  /* had it */
			if (!subset(e, set, d->set_bytes)) continue;
			for (uint32_t j = 0; j < d->set_bytes; j++) set[j] &= (uint8_t)~e[j];
			for (uint32_t j = 0; j < f; j++) data[j] ^= e[d->set_bytes + j];
			c = count_bits(set, d->set_bytes);
		}
	}
	if (c == 1) learn(d, first_bit(set, seq_len), data);
	else if (c > 1) {
		/* mixed parts that contain it get it taken out */
		for (uint32_t k = 0; k < d->nmixed; k++) {
			uint8_t *e = pool_entry(d, k);
			if (!subset(set, e, d->set_bytes)) continue;
			for (uint32_t j = 0; j < d->set_bytes; j++) e[j] &= (uint8_t)~set[j];
			for (uint32_t j = 0; j < f; j++) e[d->set_bytes + j] ^= data[j];
		}
		if (d->nmixed < d->max_mixed) {   /* else dropped: a later part will do */
			uint8_t *e = pool_entry(d, d->nmixed++);
			memcpy(e, set, d->set_bytes);
			memcpy(e + d->set_bytes, data, f);
		}
	}
	sweep(d);
	if (d->nknown < d->seq_len) return 0;
	if (ut_crc32(d->msg, d->len) != d->checksum) { d->seq_len = 0; return UT_ERR_CHECKSUM; }
	d->done = 1;
	return 1;
}

static int32_t receive(ut_fountain_decoder *d, const char *type, int kind, const uint8_t *body, size_t n)
{
	if (d->type[0] && strcmp(d->type, type)) return UT_ERR_MESSAGE;
	if (strlen(type) >= sizeof d->type) return UT_ERR_UR;
	strcpy(d->type, type);
	if (kind == KIND_SINGLE) {
		if (d->seq_len) return UT_ERR_MESSAGE;
		if (n > d->work_len) return UT_ERR_SPACE;
		memcpy(d->work, body, n);
		d->msg = d->work; d->len = (uint32_t)n; d->seq_len = d->nknown = 1; d->done = 1;
		return 1;
	}
	return receive_part(d, body, n);
}

int32_t ut_fountain_receive(ut_fountain_decoder *d, const char *ur)
{
	ur_t u;
	int r = parse_ur(ur, &u);
	if (r) return r;
	return receive(d, u.type, u.kind, u.body, u.n);
}

int32_t ut_fountain_receive_frame(ut_fountain_decoder *d, const ut_frame *f)
{
	return receive(d, f->type, f->kind, f->body, f->n);
}

int32_t ut_fountain_result(const ut_fountain_decoder *d, const char **type, const uint8_t **msg, size_t *len)
{
	if (!d->done) return UT_ERR_ARG;
	if (type) *type = d->type;
	*msg = d->msg;
	*len = d->len;
	return UT_OK;
}

/* ---- PSBTs: crypto-psbt and psbt are a CBOR byte string --------------------------- */

int32_t ut_psbt_to_cbor(const uint8_t *psbt, size_t len, uint8_t *out, size_t cap)
{
	if (len > UINT32_MAX) return UT_ERR_ARG;
	if (cap < len + 5) return UT_ERR_SPACE;
	size_t n = cbor_head(out, 2, (uint32_t)len);
	memmove(out + n, psbt, len);
	return (int32_t)(n + len);
}

int32_t ut_cbor_to_psbt(const uint8_t *cbor, size_t len, const uint8_t **psbt, size_t *psbt_len)
{
	size_t i = 0;
	uint32_t n;
	if (cbor_read(cbor, len, &i, 2, &n) || i + n != len) return UT_ERR_UR;
	*psbt = cbor + i;
	*psbt_len = n;
	return UT_OK;
}

/* ---- a signer's public keys: xpubs, descriptors, hdkey and the rest ------------------ */

typedef struct { uint8_t *p; size_t cap, n; int err; } writer;
static void w_bytes(writer *w, const void *b, size_t n)
{
	if (w->n + n > w->cap) { w->err = UT_ERR_SPACE; return; }
	memcpy(w->p + w->n, b, n);
	w->n += n;
}
static void w_head(writer *w, int major, uint32_t v) { uint8_t h[5]; w_bytes(w, h, cbor_head(h, major, v)); }
static void w_byte(writer *w, uint8_t b) { w_bytes(w, &b, 1); }

/* tags: the current ones (BCR-2020-006, 403xx) and the older ones */
enum { T_HDKEY, T_KEYPATH, T_COIN, T_OUTPUT };
static const uint32_t TAGS[2][4] = {{303, 304, 305, 0}, {40303, 40304, 40305, 40308}};
static const char *const SCRIPT_NAMES[] = {"sh", "wsh", "pk", "pkh", "wpkh", "combo", "tr", "cosigner"};
static const uint16_t SCRIPT_TAGS[] = {400, 401, 402, 403, 404, 405, 409, 410};

static void w_hdkey(writer *w, const ut_xpub *k, int current)
{
	const uint32_t *t = TAGS[current ? 1 : 0];
	w_head(w, 6, t[T_HDKEY]);
	w_head(w, 5, 3 + (k->testnet ? 1 : 0) + (k->depth ? 1 : 0));
	w_byte(w, 3); w_head(w, 2, 33); w_bytes(w, k->key, 33);
	w_byte(w, 4); w_head(w, 2, 32); w_bytes(w, k->chain, 32);
	if (k->testnet) { w_byte(w, 5); w_head(w, 6, t[T_COIN]); w_head(w, 5, 1); w_byte(w, 2); w_byte(w, 1); }
	w_byte(w, 6); w_head(w, 6, t[T_KEYPATH]); w_head(w, 5, 2);
	w_byte(w, 1); w_head(w, 4, (uint32_t)(2 * k->depth));
	for (size_t i = 0; i < k->depth; i++) { w_head(w, 0, k->path[i] & 0x7FFFFFFF); w_byte(w, k->path[i] >> 31 ? 0xF5 : 0xF4); }
	w_byte(w, 2); w_head(w, 0, k->source_fp);
	if (k->depth) { w_byte(w, 8); w_head(w, 0, k->parent_fp); }
}

/* "sh(wpkh(@0))" -> its script functions, outermost first; 0 if not one key's */
static int script_names(const char *s, uint8_t *idx, int max)
{
	int n = 0;
	while (strncmp(s, "@0", 2)) {
		int found = -1;
		for (int i = 0; i < (int)(sizeof SCRIPT_TAGS / sizeof SCRIPT_TAGS[0]); i++) {
			size_t l = strlen(SCRIPT_NAMES[i]);
			if (!strncmp(s, SCRIPT_NAMES[i], l) && s[l] == '(') { found = i; s += l + 1; break; }
		}
		if (found < 0 || n == max) return 0;
		idx[n++] = (uint8_t)found;
	}
	s += 2;
	for (int i = 0; i < n; i++) if (*s++ != ')') return 0;
	return *s ? 0 : n;
}

static void w_output(writer *w, const char *script, const ut_xpub *k, int current)
{
	uint8_t idx[4];
	int n = script_names(script, idx, 4);
	if (!n) { w->err = UT_ERR_ARG; return; }
	if (current) {
		size_t l = strlen(script);
		w_head(w, 5, 2);
		w_byte(w, 1); w_head(w, 3, (uint32_t)l); w_bytes(w, script, l);
		w_byte(w, 2); w_head(w, 4, 1); w_hdkey(w, k, 1);
	} else {
		for (int i = 0; i < n; i++) w_head(w, 6, SCRIPT_TAGS[idx[i]]);
		w_hdkey(w, k, 0);
	}
}

int32_t ut_hdkey_cbor(const ut_xpub *k, int current, uint8_t *out, size_t cap)
{
	uint8_t tmp[256];
	writer w = {tmp, sizeof tmp, 0, 0};
	w_hdkey(&w, k, current);
	if (w.err) return w.err;
	size_t skip = 3;                      /* the UR body is the map: without its tag */
	if (w.n - skip > cap) return UT_ERR_SPACE;
	memcpy(out, tmp + skip, w.n - skip);
	return (int32_t)(w.n - skip);
}

int32_t ut_output_cbor(const char *script, const ut_xpub *k, int current, uint8_t *out, size_t cap)
{
	writer w = {out, cap, 0, 0};
	w_output(&w, script, k, current);
	return w.err ? w.err : (int32_t)w.n;
}

int32_t ut_account_cbor(uint32_t master_fp, const char *const *scripts, const ut_xpub *keys, size_t n,
                    int current, uint8_t *out, size_t cap)
{
	writer w = {out, cap, 0, 0};
	if (!n || n > 23) return UT_ERR_ARG;
	w_head(&w, 5, 2);
	w_byte(&w, 1); w_head(&w, 0, master_fp);
	w_byte(&w, 2); w_head(&w, 4, (uint32_t)n);
	for (size_t i = 0; i < n; i++) {
		if (current) w_head(&w, 6, TAGS[1][T_OUTPUT]);
		w_output(&w, scripts[i], &keys[i], current);
	}
	return w.err ? w.err : (int32_t)w.n;
}

/* ---- the same keys as text: an xpub (or ypub, zpub…), a descriptor ---------------- */

static const char B58[] UT_ROM = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const struct { const char *prefix; uint32_t main, test; } VERSIONS[] = {
	{"xpub", 0x0488B21E, 0x043587CF}, {"ypub", 0x049D7CB2, 0x044A5262}, {"zpub", 0x04B24746, 0x045F1CF6},
	{"Ypub", 0x0295B43F, 0x024289EF}, {"Zpub", 0x02AA7ED3, 0x02575483},
};

int32_t ut_xpub_text(const ut_xpub *k, const char *prefix, char *out, size_t cap)
{
	uint8_t d[82], h[32];
	int v = -1;
	for (int i = 0; i < 5; i++) if (!strcmp(prefix, VERSIONS[i].prefix)) v = i;
	if (v < 0 || (k->depth && !k->path)) return UT_ERR_ARG;
	put_be32(d, k->testnet ? VERSIONS[v].test : VERSIONS[v].main);
	d[4] = (uint8_t)k->depth;
	put_be32(d + 5, k->depth ? k->parent_fp : 0);
	put_be32(d + 9, k->depth ? k->path[k->depth - 1] : 0);
	memcpy(d + 13, k->chain, 32);
	memcpy(d + 45, k->key, 33);
	ut_sha256(d, 78, h); ut_sha256(h, 32, h);
	memcpy(d + 78, h, 4);
	/* Base58: 82 bytes, at most 112 digits; repeated division of the big number */
	char tmp[120];
	size_t nd = 0, zeros = 0;
	while (zeros < 82 && !d[zeros]) zeros++;
	for (size_t start = zeros; start < 82;) {
		uint32_t rem = 0;
		for (size_t i = start; i < 82; i++) {
			uint32_t cur = rem << 8 | d[i];
			d[i] = (uint8_t)(cur / 58);
			rem = cur % 58;
		}
		tmp[nd++] = (char)UT_ROM_U8((const uint8_t *)&B58[rem]);
		while (start < 82 && !d[start]) start++;
	}
	if (zeros + nd + 1 > cap) return UT_ERR_SPACE;
	for (size_t i = 0; i < zeros; i++) out[i] = '1';
	for (size_t i = 0; i < nd; i++) out[zeros + i] = tmp[nd - 1 - i];
	out[zeros + nd] = 0;
	return (int32_t)(zeros + nd);
}

/* Bitcoin Core's descriptor checksum */
static void desc_checksum(const char *s, char out[9])
{
	static const char INPUT[] = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
	static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	static const uint64_t GEN[5] = {0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD};
	uint64_t c = 1;
	int cls = 0, ncls = 0;
#define FEED(v) do { uint64_t top = c >> 35; c = (c & 0x7FFFFFFFF) << 5 ^ (uint64_t)(v); \
	for (int g = 0; g < 5; g++) if (top >> g & 1) c ^= GEN[g]; } while (0)
	for (; *s; s++) {
		const char *p = strchr(INPUT, *s);
		int v = p && *s ? (int)(p - INPUT) : 0;
		FEED(v & 31);
		cls = cls * 3 + (v >> 5);
		if (++ncls == 3) { FEED(cls); cls = ncls = 0; }
	}
	if (ncls) FEED(cls);
	for (int i = 0; i < 8; i++) FEED(0);
#undef FEED
	c ^= 1;
	for (int i = 0; i < 8; i++) out[i] = CHARSET[c >> (5 * (7 - i)) & 31];
	out[8] = 0;
}

int32_t ut_descriptor_text(const char *script, const ut_xpub *k, char *out, size_t cap)
{
	char key[320], xpub[120];
	size_t pos = 0, kp = 0;
	const char *at = strstr(script, "@0");
	int r;
	uint8_t idx[4];
	if (!at || !script_names(script, idx, 4)) return UT_ERR_ARG;
	if ((r = ut_xpub_text(k, "xpub", xpub, sizeof xpub)) < 0) return r;
	static const char HEX[] = "0123456789abcdef";
	key[kp++] = '[';
	for (int i = 0; i < 8; i++) key[kp++] = HEX[k->source_fp >> (28 - 4 * i) & 15];
	key[kp] = 0;
	for (size_t i = 0; i < k->depth; i++) {
		if ((r = put_str(key, sizeof key, &kp, "/")) || (r = put_uint(key, sizeof key, &kp, k->path[i] & 0x7FFFFFFF))) return r;
		if (k->path[i] >> 31 && (r = put_str(key, sizeof key, &kp, "'"))) return r;
	}
	if ((r = put_str(key, sizeof key, &kp, "]")) || (r = put_str(key, sizeof key, &kp, xpub))) return r;
	if ((size_t)(at - script) + 1 > cap) return UT_ERR_SPACE;
	memcpy(out, script, (size_t)(at - script)); pos = (size_t)(at - script); out[pos] = 0;
	if ((r = put_str(out, cap, &pos, key)) || (r = put_str(out, cap, &pos, at + 2))) return r;
	char sum[9];
	desc_checksum(out, sum);
	if ((r = put_str(out, cap, &pos, "#")) || (r = put_str(out, cap, &pos, sum))) return r;
	return (int32_t)pos;
}

/* ---- sine, levels ------------------------------------------------------------- */

/* sin over a quarter turn, Q15 (257 entries) */
static const uint16_t QSIN[257] UT_ROM = {
	0, 201, 402, 603, 804, 1005, 1206, 1407, 1608, 1809, 2009, 2210,
	2410, 2611, 2811, 3012, 3212, 3412, 3612, 3811, 4011, 4210, 4410, 4609,
	4808, 5007, 5205, 5404, 5602, 5800, 5998, 6195, 6393, 6590, 6786, 6983,
	7179, 7375, 7571, 7767, 7962, 8157, 8351, 8545, 8739, 8933, 9126, 9319,
	9512, 9704, 9896, 10087, 10278, 10469, 10659, 10849, 11039, 11228, 11417, 11605,
	11793, 11980, 12167, 12353, 12539, 12725, 12910, 13094, 13279, 13462, 13645, 13828,
	14010, 14191, 14372, 14553, 14732, 14912, 15090, 15269, 15446, 15623, 15800, 15976,
	16151, 16325, 16499, 16673, 16846, 17018, 17189, 17360, 17530, 17700, 17869, 18037,
	18204, 18371, 18537, 18703, 18868, 19032, 19195, 19357, 19519, 19680, 19841, 20000,
	20159, 20317, 20475, 20631, 20787, 20942, 21096, 21250, 21403, 21554, 21705, 21856,
	22005, 22154, 22301, 22448, 22594, 22739, 22884, 23027, 23170, 23311, 23452, 23592,
	23731, 23870, 24007, 24143, 24279, 24413, 24547, 24680, 24811, 24942, 25072, 25201,
	25329, 25456, 25582, 25708, 25832, 25955, 26077, 26198, 26319, 26438, 26556, 26674,
	26790, 26905, 27019, 27133, 27245, 27356, 27466, 27575, 27683, 27790, 27896, 28001,
	28105, 28208, 28310, 28411, 28510, 28609, 28706, 28803, 28898, 28992, 29085, 29177,
	29268, 29358, 29447, 29534, 29621, 29706, 29791, 29874, 29956, 30037, 30117, 30195,
	30273, 30349, 30424, 30498, 30571, 30643, 30714, 30783, 30852, 30919, 30985, 31050,
	31113, 31176, 31237, 31297, 31356, 31414, 31470, 31526, 31580, 31633, 31685, 31736,
	31785, 31833, 31880, 31926, 31971, 32014, 32057, 32098, 32137, 32176, 32213, 32250,
	32285, 32318, 32351, 32382, 32412, 32441, 32469, 32495, 32521, 32545, 32567, 32589,
	32609, 32628, 32646, 32663, 32678, 32692, 32705, 32717, 32728, 32737, 32745, 32752,
	32757, 32761, 32765, 32766, 32767,
};

static int32_t sin_step(uint32_t idx)   /* idx: 0..1024, a full turn is 1024 */
{
	uint32_t q = (idx >> 8) & 3, i = idx & 255;
	int32_t v = UT_ROM_U16(&QSIN[q & 1 ? 256 - i : i]);
	return q & 2 ? -v : v;
}

/* sin of a 32-bit phase (a full turn is 2^32), Q15, linearly interpolated */
static int32_t isin(uint32_t phase)
{
	uint32_t idx = phase >> 22, frac = (phase >> 6) & 0xFFFF;
	int32_t a = sin_step(idx), b = sin_step((idx + 1) & 1023);
	return a + (int32_t)(((int64_t)(b - a) * frac) >> 16);
}

/* 10 log10(v) in tenths of a dB, for v >= 1 (an approximation good to 0.1 dB) */
static int db10(uint64_t v)
{
	static const uint8_t L2F[16] = {0, 22, 44, 63, 82, 100, 118, 134, 150, 165, 179, 193, 207, 220, 232, 244};
	int msb = 0;
	if (!v) return -990;
	while ((v >> msb) > 1) msb++;
	uint32_t frac = msb >= 4 ? (uint32_t)(v >> (msb - 4)) & 15 : (uint32_t)(v << (4 - msb)) & 15;
	int32_t log2q8 = msb * 256 + L2F[frac];          /* log2(v) in 1/256 */
	return (int)(log2q8 * 30103 / 256000);           /* 10 log10(v) = 3.0103 log2(v) */
}

/* ---- synthesis ----------------------------------------------------------------- */

#define LOW_Q15 8231    /* -12 dBFS */
#define HIGH_Q15 10362  /* -10 dBFS: the high tone 2 dB louder */

static uint32_t phase_inc(uint32_t f, uint32_t rate) { return (uint32_t)(((uint64_t)f << 32) / rate); }

void ut_synth_init(ut_synth *s, const char *tones, uint32_t rate, uint32_t tone_ms, uint32_t gap_ms, uint32_t pause_ms)
{
	memset(s, 0, sizeof *s);
	s->tones = tones;
	s->count = strlen(tones);
	s->rate = rate;
	s->tone_n = rate * tone_ms / 1000;
	s->gap_n = rate * gap_ms / 1000;
	s->pause_n = rate * pause_ms / 1000;
	s->ramp = rate * 2 / 1000 ? rate * 2 / 1000 : 1;   /* 2 ms fades: no clicks */
}

static void start_tone(ut_synth *s)
{
	int r = 0, c = 0;
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			if (PAD[i][j] == s->tones[s->index]) { r = i; c = j; }
	s->inc1 = phase_inc(LOW[r], s->rate);
	s->inc2 = phase_inc(HIGH[c], s->rate);
	s->stage = 1;
	s->pos = 0;
}

UT_HOT size_t ut_synth_read(ut_synth *s, int16_t *out, size_t n)
{
	size_t w = 0;
	while (w < n && s->stage != 4) {
		if (s->stage == 1) {            /* a tone: low + high, with 2 ms fades */
			while (w < n && s->pos < s->tone_n) {
				uint32_t i = s->pos, down = s->tone_n - 1 - i, e = i < down ? i : down;
				if (e > s->ramp) e = s->ramp;
				uint32_t p1 = (uint32_t)((uint64_t)s->inc1 * i), p2 = (uint32_t)((uint64_t)s->inc2 * i);
				int32_t v = (LOW_Q15 * isin(p1) + HIGH_Q15 * isin(p2)) >> 15;
				if (e < s->ramp)                  /* only in the fades: 32-bit, cheap */
					v = v * (int32_t)e / (int32_t)s->ramp;
				out[w++] = (int16_t)(v > 32767 ? 32767 : v < -32767 ? -32767 : v);
				s->pos++;
			}
			if (s->pos == s->tone_n) { s->stage = 2; s->pos = 0; }
			continue;
		}
		uint32_t len = s->stage == 2 ? s->gap_n : s->pause_n;   /* silence */
		while (w < n && s->pos < len) { out[w++] = 0; s->pos++; }
		if (s->pos < len) break;
		s->pos = 0;
		if (s->stage == 3) { s->stage = 4; break; }
		if (s->stage == 2) s->index++;
		if (s->index < s->count) start_tone(s);
		else s->stage = 3;
	}
	return w;
}

/* ---- the same timing as steps, for a generator chip --------------------------- */

void ut_player_init(ut_player *p, const char *tones, const ut_timing *t)
{
	memset(p, 0, sizeof *p);
	p->tones = tones;
	p->count = strlen(tones);
	p->t = *t;
}

int32_t ut_player_next(ut_player *p, char *key, uint32_t *on_ms, uint32_t *off_ms)
{
	*key = 0;
	*on_ms = 0;
	*off_ms = p->t.pause_ms;
	switch (p->stage) {
	case 0:
		p->stage = p->count ? 1 : 2;
		return 1;
	case 1:
		*key = p->tones[p->index++];
		*on_ms = p->t.tone_ms;
		*off_ms = p->t.gap_ms;
		if (p->index == p->count) p->stage = 2;
		return 1;
	case 2:
		p->stage = 3;
		return 1;
	default:
		return 0;
	}
}

/* ---- listening (SPEC appendix A) ------------------------------------------------ */

void ut_detector_init(ut_detector *d, uint32_t rate)
{
	memset(d, 0, sizeof *d);
	d->rate = rate;
	d->dec = rate / 8000 ? rate / 8000 : 1;          /* down to about 8 kHz */
	d->srate = rate / d->dec;
	d->n = d->srate * 25 / 1000;                    /* 25 ms windows */
	d->hop = d->srate * 10 / 1000;                  /* every 10 ms */
	for (int i = 0; i < 8; i++) {
		uint32_t f = i < 4 ? LOW[i] : HIGH[i - 4];
		d->coeff[i] = isin(phase_inc(f, d->srate) + 0x40000000u);   /* cos(w), Q15 */
	}
	d->level = -990;
}

void ut_detector_tick(const ut_detector *d, uint32_t *num, uint32_t *den)
{
	*num = d->hop * d->dec;
	*den = d->rate;
}

void ut_classify(const int64_t power[8], uint64_t energy, uint32_t n, char *key, int16_t *level)
{
	*key = 0;
	*level = -990;
	/* quieter than -55 dBFS: silence (32768^2 * 10^-5.5 per sample) */
	if (energy < (uint64_t)3395 * n) return;
	int r = 0, cc = 0;
	for (int i = 1; i < 4; i++) {
		if (power[i] > power[r]) r = i;
		if (power[4 + i] > power[4 + cc]) cc = i;
	}
	int64_t lo = power[r], hi = power[4 + cc], lo2 = 0, hi2 = 0;
	for (int i = 0; i < 4; i++) {
		if (i != r && power[i] > lo2) lo2 = power[i];
		if (i != cc && power[4 + i] > hi2) hi2 = power[4 + i];
	}
	/* power * 2 / n compared with the energy (the reference's normalisation) */
	int ok = lo > 2 * lo2 && hi > 2 * hi2
	         && 2 * (lo + hi) > (int64_t)energy * n / 5
	         && 100 * hi > lo && 100 * lo > hi;
	/* the tone's level in dBFS: |X|^2 of a full-scale sine is (n/2 * 32768)^2 */
	*level = (int16_t)(db10((uint64_t)(lo + hi > 0 ? lo + hi : 1)) - db10((uint64_t)n * n / 4 * 32768u * 32768u));
	if (ok) *key = PAD[r][cc];
}

/* one 10 ms detection over the last 25 ms */
static UT_HOT void detect(ut_detector *d, ut_det *out)
{
	uint64_t total = 0;
	int64_t power[8] = {0};
	uint32_t n = d->n;
	for (uint32_t i = 0; i < n; i++) {
		int32_t x = d->ring[(d->next + i) % UT_RING];
		total += (uint64_t)((int64_t)x * x);
	}
	if (total >= (uint64_t)3395 * n)       /* not silence: worth the eight filters */
		for (int f = 0; f < 8; f++) {
			int64_t s1 = 0, s2 = 0, c = d->coeff[f];       /* cos(w), Q15 */
			for (uint32_t i = 0; i < n; i++) {
				int64_t s0 = d->ring[(d->next + i) % UT_RING] + ((2 * c * s1) >> 15) - s2;
				s2 = s1; s1 = s0;
			}
			power[f] = s1 * s1 + s2 * s2 - ((2 * c * s1) >> 15) * s2;    /* |X|^2 */
		}
	ut_classify(power, total, n, &out->key, &out->level);
	d->level = out->level;
}

size_t ut_detector_push(ut_detector *d, const int16_t *x, size_t n, size_t *used, ut_det *out, size_t cap)
{
	size_t i = 0, k = 0;
	for (; i < n && k < cap; i++) {
		d->dec_sum += x[i];
		if (++d->dec_count < d->dec) continue;
		d->ring[d->total % UT_RING] = (int16_t)(d->dec_sum / (int32_t)d->dec);
		d->dec_sum = 0;
		d->dec_count = 0;
		d->total++;
		if (d->total >= d->next + d->n) {
			detect(d, &out[k++]);
			d->next += d->hop;
		}
	}
	if (used) *used = i;
	return k;
}

/* ---- layer 2: detections to groups --------------------------------------------- */

void ut_keys_init(ut_keys *k, uint32_t tick_num, uint32_t tick_den)
{
	memset(k, 0, sizeof *k);
	k->num = tick_num;
	k->den = tick_den;
}

/* t ticks last more than ms milliseconds */
static int longer(const ut_keys *k, uint32_t t, uint32_t ms)
{
	return (uint64_t)t * k->num * 1000 > (uint64_t)ms * k->den;
}

static void group_close(ut_keys *k)
{
	char *g = k->current;
	uint32_t n = k->clen;
	k->clen = 0;
	if (!n) return;
	if (g[0] != '*') {          /* in a data frame a tone never follows itself: a repeat is an echo */
		uint32_t w = 1;
		for (uint32_t i = 1; i < n; i++)
			if (g[i] != g[w - 1]) g[w++] = g[i];
		n = w;
	}
	if (k->rcount == UT_READY) {          /* drop the oldest */
		k->rhead = (k->rhead + 1) % UT_READY;
		k->rcount--;
	}
	char *dst = k->ready[(k->rhead + k->rcount) % UT_READY];
	memcpy(dst, g, n);
	dst[n] = 0;
	k->rcount++;
}

static int keypad_open(const ut_keys *k)
{
	if (!k->clen || k->current[0] != '*') return 0;
	for (uint32_t i = 1; i < k->clen; i++)
		if (k->current[i] < '0' || k->current[i] > '9') return 0;
	return 1;
}

/* a tone from start to end (ticks) */
static void tone(ut_keys *k, char key, uint32_t start, uint32_t end)
{
	int long_pause = k->have_end && longer(k, start - k->last_end, 225);
	if (k->clen && long_pause && !keypad_open(k)) group_close(k);
	if (keypad_open(k) && !((key >= '0' && key <= '9') || key == '#')) group_close(k);
	if (k->clen < UT_GROUP) k->current[k->clen++] = key;
	k->last_end = end;
	k->have_end = 1;
	if (key == '#' && k->current[0] == '*' && k->clen > 2) {
		int digits = 1;
		for (uint32_t i = 1; i + 1 < k->clen; i++)
			if (k->current[i] < '0' || k->current[i] > '9') digits = 0;
		if (digits) group_close(k);
	}
}

/* As ur_tones.segment(): tones of 30 ms or more; flicker bridged; the same key
 * again is a new tone only if it comes back nearly as loud (an echo is weaker).
 * Detections wait in `look` until the two after them have come (a glitch is
 * a key lasting fewer than 3), or the input pauses. */
#define MIN_HOPS 3
#define BRIDGE_HOPS 3
#define DIP 80                  /* 8 dB */
#define NEAR 60                 /* 6 dB */

static void seg_close(ut_keys *k)
{
	if (!k->have_cur || k->cur_end - k->cur_start < MIN_HOPS) return;
	if (k->last_key && k->last_key == k->cur_key && k->cur_peak < k->last_peak - NEAR && k->have_prev && k->prev_key == k->cur_key) {
		k->prev_end = k->cur_end;       /* an echo of it */
		return;
	}
	if (k->have_prev) tone(k, k->prev_key, k->prev_start, k->prev_end);
	k->prev_key = k->cur_key; k->prev_start = k->cur_start; k->prev_end = k->cur_end; k->have_prev = 1;
	k->last_key = k->cur_key; k->last_peak = k->cur_peak;
}

static void seg_start(ut_keys *k, char key, uint32_t i, int lvl)
{
	k->cur_key = key; k->cur_start = i; k->cur_end = i + 1; k->cur_peak = lvl; k->dipped = 0; k->have_cur = 1;
}

/* the oldest detection waiting, with what follows it in `look` */
static void seg_step(ut_keys *k)
{
	char key = k->look[0].key;
	int lvl = k->look[0].level;
	uint32_t i = k->at;
	if (k->have_cur && key && key == k->cur_key && k->gap <= BRIDGE_HOPS) {
		if (k->dipped && lvl > k->cur_peak - NEAR) {      /* pressed again */
			seg_close(k);
			seg_start(k, key, i, lvl);
		} else {
			k->cur_end = i + 1;
			if (!k->dipped && lvl > k->cur_peak) k->cur_peak = lvl;
			if (lvl < k->cur_peak - DIP) k->dipped = 1;
		}
		k->gap = 0;
	} else {
		uint32_t m = 0;
		while (m < k->nlook && k->look[m].key == key && m < MIN_HOPS) m++;
		if (!key || (k->have_cur && k->gap <= BRIDGE_HOPS && key != k->cur_key && m < MIN_HOPS)) {
			k->gap++;
			if (k->have_cur && k->gap > BRIDGE_HOPS) { seg_close(k); k->have_cur = 0; }
		} else {
			seg_close(k);
			seg_start(k, key, i, lvl);
			k->gap = 0;
		}
	}
	k->at++;
	k->nlook--;
	memmove(k->look, k->look + 1, k->nlook * sizeof k->look[0]);
}

/* the input pauses: what waits is decided, the last tone goes out */
static void seg_cut(ut_keys *k)
{
	while (k->nlook) seg_step(k);
	seg_close(k);
	if (k->have_prev) tone(k, k->prev_key, k->prev_start, k->prev_end);
	k->have_cur = k->have_prev = 0;
	k->last_key = 0;
	k->gap = 0;
	k->since = 0;
	k->silent = 0;
}

void ut_keys_detection(ut_keys *k, char key, int16_t level)
{
	if (key == k->live_key) {
		if (++k->live_run == 3 && key && k->nlive < UT_LIVE) k->live[k->nlive++] = key;
	} else {
		k->live_key = key;
		k->live_run = 1;
	}
	k->look[k->nlook].key = key;
	k->look[k->nlook].level = level;
	k->nlook++;
	k->since++;
	k->silent = key ? 0 : k->silent + 1;
	if (k->nlook == MIN_HOPS) seg_step(k);
	/* 300 ms of silence after something: segment what came before */
	if ((uint64_t)k->silent * k->num * 1000 >= (uint64_t)300 * k->den && k->since > k->silent) {
		seg_cut(k);
		if (!keypad_open(k)) group_close(k);
	}
}

void ut_keys_tone(ut_keys *k, char key, uint32_t start, uint32_t end)
{
	if (k->nlive < UT_LIVE) k->live[k->nlive++] = key;
	tone(k, key, start, end);
}

void ut_keys_time(ut_keys *k, uint32_t now)
{
	if (k->clen && !keypad_open(k) && (uint64_t)(now - k->last_end) * k->num * 1000 >= (uint64_t)300 * k->den)
		group_close(k);
}

void ut_keys_flush(ut_keys *k)
{
	if (k->since) seg_cut(k);
	group_close(k);
}

int32_t ut_keys_group(ut_keys *k, char *out, size_t cap)
{
	if (!k->rcount) return 0;
	const char *g = k->ready[k->rhead];
	size_t n = strlen(g);
	if (n + 1 > cap) return UT_ERR_SPACE;
	memcpy(out, g, n + 1);
	k->rhead = (k->rhead + 1) % UT_READY;
	k->rcount--;
	return (int32_t)n;
}

int32_t ut_keys_live(ut_keys *k, char *out, size_t cap)
{
	size_t n = k->nlive < cap - 1 ? k->nlive : cap - 1;
	memcpy(out, k->live, n);
	out[n] = 0;
	k->nlive = 0;
	return (int32_t)n;
}

/* ---- listening: layers 1 and 2 together -------------------------------------- */

void ut_listener_init(ut_listener *l, uint32_t rate)
{
	uint32_t num, den;
	ut_detector_init(&l->det, rate);
	ut_detector_tick(&l->det, &num, &den);
	ut_keys_init(&l->keys, num, den);
	l->level = -990;
}

void ut_listener_push(ut_listener *l, const int16_t *x, size_t n)
{
	ut_det d[8];
	while (n) {
		size_t used, k = ut_detector_push(&l->det, x, n, &used, d, 8);
		for (size_t i = 0; i < k; i++) {
			l->level = d[i].level;
			ut_keys_detection(&l->keys, d[i].key, d[i].level);
		}
		x += used;
		n -= used;
	}
}

void ut_listener_flush(ut_listener *l) { ut_keys_flush(&l->keys); }
int32_t ut_listener_group(ut_listener *l, char *out, size_t cap) { return ut_keys_group(&l->keys, out, cap); }
int32_t ut_listener_live(ut_listener *l, char *out, size_t cap) { return ut_keys_live(&l->keys, out, cap); }
