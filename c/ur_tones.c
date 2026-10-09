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

static const uint32_t K256[64] = {
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

static void sha256_block(sha256_ctx *c, const uint8_t *p)
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
		uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
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

static uint8_t EXP[512], LOG[256];
static int gf_ready;

static void gf_init(void)
{
	if (gf_ready)
		return;
	unsigned x = 1;
	for (int i = 0; i < 255; i++) {
		EXP[i] = (uint8_t)x; LOG[x] = (uint8_t)i;
		x <<= 1;
		if (x & 0x100) x ^= 0x11D;
	}
	for (int i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
	gf_ready = 1;
}

static uint8_t gmul(uint8_t a, uint8_t b) { return (a && b) ? EXP[LOG[a] + LOG[b]] : 0; }
static uint8_t gdiv(uint8_t a, uint8_t b) { return a ? EXP[(LOG[a] + 255 - LOG[b]) % 255] : 0; }

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
	gf_init();
	for (size_t i = 0; i < nsym; i++) {          /* product of (x - alpha^i) */
		for (size_t j = i + 1; j > 0; j--) g[j] = g[j] ^ gmul(g[j - 1], EXP[i]);
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

int ut_rs_correct(uint8_t *cw, size_t n, size_t nsym)
{
	uint8_t synd[UT_PARITY], lam[UT_PARITY + 1] = {1}, prev[UT_PARITY + 1] = {1}, next[UT_PARITY + 1];
	uint8_t omega[UT_PARITY] = {0}, rev[UT_PARITY + 1];
	size_t L = 0, m = 1, lamlen = 1, prevlen = 1;
	uint8_t b = 1;
	int any = 0, positions[UT_PARITY], npos = 0;
	gf_init();
	if (nsym > UT_PARITY || n > 255)
		return UT_ERR_ARG;
	for (size_t i = 0; i < nsym; i++) {
		synd[i] = poly_eval(cw, n, EXP[i]);
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
		if (!poly_eval(rev, L + 1, EXP[(255 - p % 255) % 255])) {
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
		uint8_t xinv = EXP[(255 - p % 255) % 255], num = 0, den = 0;
		for (size_t i = 0; i < nsym; i++)
			num ^= gmul(omega[i], EXP[(LOG[xinv] * i) % 255]);
		for (size_t j = 1; j <= L; j += 2)
			den ^= gmul(lam[j], EXP[(LOG[xinv] * (j - 1)) % 255]);
		if (!den) return UT_ERR_DECODE;
		cw[n - 1 - p] ^= gmul(EXP[p % 255], gdiv(num, den));
	}
	for (size_t i = 0; i < nsym; i++)
		if (poly_eval(cw, n, EXP[i])) return UT_ERR_DECODE;
	return npos;
}

/* ---- bytewords (minimal: first and last letter of each word) --------------- */

static const char BYTEWORDS[] =
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

static int byteword(char a, char b)
{
	for (int i = 0; i < 256; i++)
		if (BYTEWORDS[4 * i] == a && BYTEWORDS[4 * i + 3] == b)
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
		out[2 * i] = BYTEWORDS[4 * b];
		out[2 * i + 1] = BYTEWORDS[4 * b + 3];
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
		if (len + 1 >= sizeof t) return UT_ERR_UR;
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
	if (wl % 2 || wl < 10 || wl / 2 - 4 > sizeof u->body) return UT_ERR_UR;
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

int ut_ur_to_frame(const char *ur, char *tones, size_t cap)
{
	ur_t u;
	uint8_t cw[256];
	size_t n = 0, code = 0;
	int r = parse_ur(ur, &u);
	if (r) return r;
	if (u.n < 1 || u.n > 255) return UT_ERR_TOO_LONG;
	for (size_t i = 1; i < NTYPES; i++)
		if (!strcmp(UR_TYPES[i], u.type)) code = i;
	cw[n++] = (uint8_t)(FORMAT_VERSION << 4 | u.kind);
	cw[n++] = (uint8_t)code;
	cw[n++] = (uint8_t)u.n;
	if (!code) {
		size_t tl = strlen(u.type);
		if (n + 1 + tl > 255) return UT_ERR_TOO_LONG;
		cw[n++] = (uint8_t)tl;
		memcpy(cw + n, u.type, tl); n += tl;
	}
	if (n + u.n + UT_PARITY > 255) return UT_ERR_TOO_LONG;
	memcpy(cw + n, u.body, u.n); n += u.n;
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
	r = to_tones(cw, n, SYNC[1], tones + 4, cap - 4);
	return r < 0 ? r : r + 4;
}

static int frame_body(const char *tones, size_t len, char *ur, size_t cap, int *corrected)
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
	char type[256];
	if (cw[1] == 0) {
		size_t tl = cw[3];
		if (4 + tl > dlen) return UT_ERR_DECODE;
		memcpy(type, cw + 4, tl); type[tl] = 0;
		i = 4 + tl;
	} else if (cw[1] < NTYPES)
		strcpy(type, UR_TYPES[cw[1]]);
	else
		return UT_ERR_DECODE;
	size_t blen = cw[2];
	if (i + blen > dlen || dlen - i - blen > 1 || (dlen - i - blen == 1 && cw[i + blen])) return UT_ERR_DECODE;
	int r = ur_text(type, kind, cw + i, blen, ur, cap);
	if (r >= 0 && corrected) *corrected = fixed;
	return r < 0 ? (r == UT_ERR_SPACE ? r : UT_ERR_DECODE) : r;
}

int ut_frame_to_ur(const char *tones, char *ur, size_t cap, int *corrected)
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
		int r = frame_body(data, dl, ur, cap, corrected);
		if (r >= 0 || r == UT_ERR_SPACE) return r;
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
			r = frame_body(cand, cl, ur, cap, corrected);
			if (r >= 0 || r == UT_ERR_SPACE) return r;
		}
	}
	return err;
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

int ut_seed_to_keypad(const uint8_t *entropy, size_t len, const char *pin, char *out, size_t cap)
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
	return (int)(2 + 4 * words);
}

int ut_keypad_to_seed(const char *tones, const char *pin, uint8_t *entropy)
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
	return r ? r : (int)elen;
}

int ut_seed_to_ur(const uint8_t *entropy, size_t len, const char *pin, char *ur, size_t cap)
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

int ut_ur_to_seed(const char *ur, const char *pin, uint8_t *entropy)
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
	return r ? r : (int)len;
}

/* ---- sine, levels ------------------------------------------------------------- */

/* sin over a quarter turn, Q15 (257 entries) */
static const int16_t QSIN[257] = {
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
	int32_t v = q & 1 ? QSIN[256 - i] : QSIN[i];
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

size_t ut_synth_read(ut_synth *s, int16_t *out, size_t n)
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

/* ---- listening (SPEC appendix A) ------------------------------------------------ */

void ut_listener_init(ut_listener *l, uint32_t rate)
{
	memset(l, 0, sizeof *l);
	l->rate = rate;
	l->dec = rate / 8000 ? rate / 8000 : 1;          /* down to about 8 kHz */
	l->srate = rate / l->dec;
	l->n = l->srate * 25 / 1000;                    /* 25 ms windows */
	l->hop = l->srate * 10 / 1000;                  /* every 10 ms */
	if (l->n > UT_RING - l->hop) l->n = UT_RING - l->hop;
	for (int i = 0; i < 8; i++) {
		uint32_t f = i < 4 ? LOW[i] : HIGH[i - 4];
		/* 2 cos(w) = 2 sin(w + pi/2), Q14 */
		l->coeff[i] = isin(phase_inc(f, l->srate) + 0x40000000u);   /* cos(w), Q15 */
	}
	l->last_end = -1;
	l->level = -990;
}

/* one 10 ms detection over the last 25 ms */
static void detect(ut_listener *l, char *key, int16_t *level)
{
	uint64_t total = 0;
	int64_t power[8];
	uint32_t n = l->n;
	for (uint32_t i = 0; i < n; i++) {
		int32_t x = l->ring[(l->next + i) % UT_RING];
		total += (uint64_t)((int64_t)x * x);
	}
	*key = 0;
	*level = -990;
	/* quieter than -55 dBFS: silence (32768^2 * 10^-5.5 per sample) */
	if (total < (uint64_t)3395 * n) return;
	for (int f = 0; f < 8; f++) {
		int64_t s1 = 0, s2 = 0, c = l->coeff[f];       /* cos(w), Q15 */
		for (uint32_t i = 0; i < n; i++) {
			int64_t s0 = l->ring[(l->next + i) % UT_RING] + ((2 * c * s1) >> 15) - s2;
			s2 = s1; s1 = s0;
		}
		power[f] = s1 * s1 + s2 * s2 - ((2 * c * s1) >> 15) * s2;    /* |X|^2 */
	}
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
	/* power * 2 / n compared with total (the reference's normalisation) */
	int ok = lo > 2 * lo2 && hi > 2 * hi2
	         && 2 * (lo + hi) > (int64_t)total * n / 5
	         && 100 * hi > lo && 100 * lo > hi;
	/* the tone's level in dBFS: |X|^2 of a full-scale sine is (n/2 * 32768)^2 */
	*level = (int16_t)(db10((uint64_t)(lo + hi > 0 ? lo + hi : 1)) - db10((uint64_t)n * n / 4 * 32768u * 32768u));
	if (ok) *key = PAD[r][cc];
}

/* a key lasting fewer than min_hops from i: a glitch */
static int short_run(const ut_listener *l, uint32_t i, char k, uint32_t min_hops)
{
	uint32_t m = 0;
	while (i + m < l->ndet && l->det[i + m].key == k && m < min_hops) m++;
	return m < min_hops;
}

static void group_close(ut_listener *l)
{
	char *g = l->current;
	uint32_t n = l->clen;
	l->clen = 0;
	if (!n) return;
	if (g[0] != '*') {          /* in a data frame a tone never follows itself: a repeat is an echo */
		uint32_t w = 1;
		for (uint32_t i = 1; i < n; i++)
			if (g[i] != g[w - 1]) g[w++] = g[i];
		n = w;
	}
	if (l->rcount == UT_READY) {          /* drop the oldest */
		l->rhead = (l->rhead + 1) % UT_READY;
		l->rcount--;
	}
	char *dst = l->ready[(l->rhead + l->rcount) % UT_READY];
	memcpy(dst, g, n);
	dst[n] = 0;
	l->rcount++;
}

static int keypad_open(const ut_listener *l)
{
	if (!l->clen || l->current[0] != '*') return 0;
	for (uint32_t i = 1; i < l->clen; i++)
		if (l->current[i] < '0' || l->current[i] > '9') return 0;
	return 1;
}

static void tone(ut_listener *l, char key, int64_t start, int64_t end)
{
	/* (start - last_end) hops of hop*dec/rate s: more than 225 ms? */
	int long_pause = l->last_end >= 0 && (uint64_t)(start - l->last_end) * l->hop * l->dec * 1000 > (uint64_t)225 * l->rate;
	if (l->clen && long_pause && !keypad_open(l)) group_close(l);
	if (keypad_open(l) && !((key >= '0' && key <= '9') || key == '#')) group_close(l);
	if (l->clen < UT_GROUP) l->current[l->clen++] = key;
	l->last_end = end;
	if (key == '#' && l->current[0] == '*' && l->clen > 2) {
		int digits = 1;
		for (uint32_t i = 1; i + 1 < l->clen; i++)
			if (l->current[i] < '0' || l->current[i] > '9') digits = 0;
		if (digits) group_close(l);
	}
}

/* as ur_tones.segment(): tones of 30 ms or more; flicker bridged; the same key
 * again is a new tone only if it comes back nearly as loud (an echo is weaker) */
static void segment(ut_listener *l)
{
	const uint32_t min_hops = 3, bridge_hops = 3;
	const int dip = 80, near = 60;           /* 8 dB, 6 dB */
	char cur_key = 0, last_key = 0, prev_key = 0;
	int64_t cur_start = 0, cur_end = 0, prev_start = 0, prev_end = 0;
	int cur_peak = 0, last_peak = 0, dipped = 0, have_cur = 0, have_prev = 0;
	uint32_t gap = 0;

#define CLOSE() do { \
		if (have_cur && cur_end - cur_start >= (int64_t)min_hops) { \
			if (last_key && last_key == cur_key && cur_peak < last_peak - near && have_prev && prev_key == cur_key) \
				prev_end = cur_end; \
			else { \
				if (have_prev) tone(l, prev_key, l->offset + prev_start, l->offset + prev_end); \
				prev_key = cur_key; prev_start = cur_start; prev_end = cur_end; have_prev = 1; \
				last_key = cur_key; last_peak = cur_peak; \
			} \
		} \
	} while (0)

	for (uint32_t i = 0; i < l->ndet; i++) {
		char k = l->det[i].key;
		int lvl = l->det[i].level;
		if (have_cur && k && k == cur_key && gap <= bridge_hops) {
			if (dipped && lvl > cur_peak - near) {
				CLOSE();
				cur_key = k; cur_start = i; cur_end = i + 1; cur_peak = lvl; dipped = 0;
			} else {
				cur_end = i + 1;
				if (!dipped && lvl > cur_peak) cur_peak = lvl;
				if (lvl < cur_peak - dip) dipped = 1;
			}
			gap = 0;
		} else if (!k || (have_cur && gap <= bridge_hops && k != cur_key && short_run(l, i, k, min_hops))) {
			gap++;
			if (have_cur && gap > bridge_hops) { CLOSE(); have_cur = 0; }
		} else {
			CLOSE();
			cur_key = k; cur_start = i; cur_end = i + 1; cur_peak = lvl; dipped = 0; have_cur = 1;
			gap = 0;
		}
	}
	CLOSE();
	if (have_prev) tone(l, prev_key, l->offset + prev_start, l->offset + prev_end);
#undef CLOSE
}

static void batch(ut_listener *l)
{
	segment(l);
	l->offset += l->ndet;
	l->ndet = 0;
	l->silent = 0;
	if (!keypad_open(l)) group_close(l);
}

static void step(ut_listener *l)
{
	char k;
	int16_t lvl;
	detect(l, &k, &lvl);
	l->level = lvl;
	if (l->ndet == UT_MAX_DETS) batch(l);           /* a very long group: cut it */
	l->det[l->ndet].key = k;
	l->det[l->ndet].level = lvl;
	l->ndet++;
	if (k == l->live_key) {
		if (++l->live_run == 3 && k && l->nlive < UT_LIVE) l->live[l->nlive++] = k;
	} else {
		l->live_key = k;
		l->live_run = 1;
	}
	l->silent = k ? 0 : l->silent + 1;
	/* 300 ms of silence: segment what came before */
	if ((uint64_t)l->silent * l->hop * l->dec * 1000 >= (uint64_t)300 * l->rate && l->ndet > l->silent) batch(l);
}

void ut_listener_push(ut_listener *l, const int16_t *x, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		l->dec_sum += x[i];
		if (++l->dec_count < l->dec) continue;
		l->ring[l->total % UT_RING] = (int16_t)(l->dec_sum / (int32_t)l->dec);
		l->dec_sum = 0;
		l->dec_count = 0;
		l->total++;
		if (l->total >= l->next + l->n) {
			step(l);
			l->next += l->hop;
		}
	}
}

void ut_listener_flush(ut_listener *l)
{
	if (l->ndet) batch(l);
	group_close(l);
}

int ut_listener_group(ut_listener *l, char *out, size_t cap)
{
	if (!l->rcount) return 0;
	const char *g = l->ready[l->rhead];
	size_t n = strlen(g);
	if (n + 1 > cap) return UT_ERR_SPACE;
	memcpy(out, g, n + 1);
	l->rhead = (l->rhead + 1) % UT_READY;
	l->rcount--;
	return (int)n;
}

int ut_listener_live(ut_listener *l, char *out, size_t cap)
{
	size_t n = l->nlive < cap - 1 ? l->nlive : cap - 1;
	memcpy(out, l->live, n);
	out[n] = 0;
	l->nlive = 0;
	return (int)n;
}
