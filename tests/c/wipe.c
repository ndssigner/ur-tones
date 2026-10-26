/* Does the library leave secrets behind on the stack? Each call that handles a
 * seed or a PIN runs over a stack cleared beforehand; then the same stretch of
 * stack is searched for the entropy, the PIN's key (PBKDF2), the upper-case PIN
 * and HMAC's pads of it (tests/test_c_layers.py, test_wipe).
 *
 *     wipe <entropy hex> <PIN>      prints one line per leak, then "checked N"
 *
 * Reading a stack that another call left is outside the C standard; it is
 * what an attacker who can dump the RAM sees, and on the usual compilers this
 * finds it. */
#include <stdio.h>
#include <string.h>
#include "ur_tones.h"

#define DEPTH 32768

static uint8_t entropy[32], key[32], up[64], ipad[64], opad[64];
static size_t elen, plen;
static char pin[64], bad_pin[] = "no-pin!", text[4096], tones[4096], lost[4096];
static uint8_t out[32];
static int leaks, checked;

static void __attribute__((noinline)) scrub(void)
{
	volatile uint8_t s[DEPTH];
	for (size_t i = 0; i < DEPTH; i++) s[i] = 0;
}

static int found(const volatile uint8_t *s, const uint8_t *p, size_t n)
{
	for (size_t i = 0; i + n <= DEPTH; i++) {
		size_t j = 0;
		while (j < n && s[i + j] == p[j]) j++;
		if (j == n) return 1;
	}
	return 0;
}

static void __attribute__((noinline)) search(const char *call, int pinned)
{
	volatile uint8_t s[DEPTH];
	struct { const char *what; const uint8_t *p; size_t n; } secrets[] = {
		{"entropy", entropy, elen}, {"PIN key", key, elen}, {"PIN", up, plen},
		{"HMAC ipad", ipad, plen}, {"HMAC opad", opad, plen}};
	checked++;
	for (size_t k = 0; k < (pinned ? 5u : 1u); k++)
		if (found(s, secrets[k].p, secrets[k].n)) {
			printf("%s leaves the %s\n", call, secrets[k].what);
			leaks++;
		}
}

#define CHECK(call, pinned) do { scrub(); (void)(call); search(#call, pinned); } while (0)

int main(int argc, char **argv)
{
	if (argc != 3) return 2;
	for (elen = 0; argv[1][2 * elen] && elen < sizeof entropy; elen++)
		sscanf(argv[1] + 2 * elen, "%2hhx", &entropy[elen]);
	for (plen = 0; argv[2][plen] && plen < sizeof up; plen++) {
		char ch = argv[2][plen];
		up[plen] = (uint8_t)(ch >= 'a' && ch <= 'z' ? ch - 32 : ch);
		pin[plen] = (char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);   /* the library upper-cases it */
		ipad[plen] = up[plen] ^ 0x36;
		opad[plen] = up[plen] ^ 0x5c;
	}
	ut_pbkdf2_sha256(up, plen, (const uint8_t *)"ur-tones/seed-pin/v0", 20, 10000, key, elen);

	CHECK(ut_seed_to_keypad(entropy, elen, pin, text, sizeof text), 1);
	CHECK(ut_keypad_to_seed(text, pin, out), 1);
	CHECK(ut_seed_to_ur(entropy, elen, pin, text, sizeof text), 1);
	CHECK(ut_ur_to_seed(text, pin, out), 1);
	CHECK(ut_ur_to_frame(text, tones, sizeof tones), 1);
	CHECK(ut_frame_to_ur(tones, text, sizeof text, NULL), 1);

	/* without a PIN the entropy travels as it is: copies of it are secrets */
	CHECK(ut_seed_to_keypad(entropy, elen, NULL, text, sizeof text), 0);
	CHECK(ut_keypad_to_seed(text, NULL, out), 0);
	CHECK(ut_seed_to_ur(entropy, elen, NULL, text, sizeof text), 0);
	CHECK(ut_ur_to_seed(text, NULL, out), 0);
	CHECK(ut_ur_to_frame(text, tones, sizeof tones), 0);
	CHECK(ut_frame_to_ur(tones, text, sizeof text, NULL), 0);
	memcpy(lost, tones, 40); strcpy(lost + 40, tones + 41);           /* a lost tone: realigned */
	CHECK(ut_frame_to_ur(lost, text, sizeof text, NULL), 0);

	/* a refused PIN, after the entropy was copied */
	CHECK(ut_seed_to_keypad(entropy, elen, bad_pin, text, sizeof text), 0);
	CHECK(ut_seed_to_ur(entropy, elen, bad_pin, text, sizeof text), 0);

	printf("checked %d\n", checked);
	return leaks != 0;
}
