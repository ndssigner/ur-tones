/*
 * ur-tones (draft v0), C99 implementation for small devices (SPEC.md).
 * SPDX-License-Identifier: MIT
 *
 * Frames (UR text <-> tones), keypad mode, seed URs, the seed PIN, tone
 * synthesis and a streaming receiver. No malloc, no floating point: integer
 * Goertzel, a sine table and fixed buffers, for CPUs without an FPU (the
 * Nintendo DSi's ARM9). Checked against the Python reference and the test
 * vectors by tests/test_c.py.
 *
 * Tones are ASCII keys: 0-9 A-D * #. Strings are NUL-terminated. Functions
 * that write return the length written (>= 0) or a negative UT_ERR_*.
 */
#ifndef UR_TONES_H
#define UR_TONES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UT_PARITY 32          /* Reed-Solomon parity bytes per frame */
#define UT_MAX_FRAME 560      /* tones in the longest frame, plus room */
#define UT_MAX_UR 1100        /* characters in the longest UR text a frame carries */
#define UT_MAX_KEYPAD 100     /* "*" + 96 digits + "#" + NUL */

enum {
	UT_OK = 0,
	UT_ERR_ARG = -1,       /* a bad argument */
	UT_ERR_SPACE = -2,     /* the output buffer is too small */
	UT_ERR_UR = -3,        /* not a UR text, or a bad one */
	UT_ERR_CHECKSUM = -4,  /* bytewords CRC-32, or BIP-39 checksum */
	UT_ERR_TOO_LONG = -5,  /* too long for one frame: use a multi-part UR */
	UT_ERR_SYNC = -6,      /* no sync at the start of the tones */
	UT_ERR_DECODE = -7,    /* more errors than Reed-Solomon repairs, or a bad frame */
	UT_ERR_PIN = -8,       /* a PIN is letters A-Z and digits 0-9 */
	UT_ERR_SEED = -9,      /* not a seed (12 or 24 words; a crypto-seed UR) */
};

/* ---- frames: a UR text (single-part, or one part of a multi-part UR) ---- */

/* The tones of the frame that carries `ur` (lead-in, sync, codeword). */
int ut_ur_to_frame(const char *ur, char *tones, size_t cap);

/* The UR text of a frame's tones (lead-in optional). Repairs up to 16 wrong
 * bytes, and one lost or one extra tone. `corrected` (may be NULL) gets the
 * number of bytes repaired. */
int ut_frame_to_ur(const char *tones, char *ur, size_t cap, int *corrected);

/* ---- seeds ---------------------------------------------------------------
 * entropy: 16 or 32 bytes. pin: NULL or "" for none, else letters and
 * digits (case-insensitive). */
int ut_seed_to_keypad(const uint8_t *entropy, size_t len, const char *pin, char *out, size_t cap);
/* Returns the entropy's length (16 or 32) written to `entropy` (32 bytes). */
int ut_keypad_to_seed(const char *tones, const char *pin, uint8_t *entropy);
int ut_seed_to_ur(const uint8_t *entropy, size_t len, const char *pin, char *ur, size_t cap);
int ut_ur_to_seed(const char *ur, const char *pin, uint8_t *entropy);

/* ---- synthesis -------------------------------------------------------- */

typedef struct {
	const char *tones;
	size_t count, index;
	uint32_t rate, tone_n, gap_n, pause_n, ramp, pos;
	int stage;                /* 0 pause, 1 tone, 2 gap, 3 final pause, 4 done */
	uint32_t ph1, ph2, inc1, inc2;
} ut_synth;

/* Plays `tones` (kept, not copied) at `rate` Hz: a pause, each tone and its
 * gap, a final pause (SPEC §1.1), as signed 16-bit mono samples. */
void ut_synth_init(ut_synth *s, const char *tones, uint32_t rate,
                   uint32_t tone_ms, uint32_t gap_ms, uint32_t pause_ms);
/* Writes up to n samples; returns how many (0: done). */
size_t ut_synth_read(ut_synth *s, int16_t *out, size_t n);

/* ---- listening -------------------------------------------------------- */

#define UT_MAX_DETS 8192      /* 10 ms detections kept between silences: 82 s */
#define UT_RING 1024          /* samples, after bringing them down to ~8 kHz */
#define UT_GROUP 600          /* tones in a group */
#define UT_READY 4            /* groups waiting to be taken */
#define UT_LIVE 64            /* live keys waiting to be taken */

typedef struct {
	uint32_t rate, dec, srate, n, hop;
	int32_t coeff[8];                   /* cos(w), Q15 */
	int32_t dec_sum;
	uint32_t dec_count;
	int16_t ring[UT_RING];
	uint32_t total, next;               /* samples seen; start of the next window */
	struct { char key; int16_t level; } det[UT_MAX_DETS];
	uint32_t ndet, silent, offset;
	char current[UT_GROUP + 1];
	uint32_t clen;
	int64_t last_end;                   /* hop of the last tone's end, or -1 */
	char ready[UT_READY][UT_GROUP + 1];
	uint32_t rhead, rcount;
	char live_key;
	uint32_t live_run;
	char live[UT_LIVE];
	uint32_t nlive;
	int level;                          /* the last window's tone level, in 0.1 dBFS (-990: silence) */
} ut_listener;

void ut_listener_init(ut_listener *l, uint32_t rate);
/* Signed 16-bit mono samples, as they come. */
void ut_listener_push(ut_listener *l, const int16_t *x, size_t n);
/* At the end of a recording: closes what is pending. */
void ut_listener_flush(ut_listener *l);
/* The next group of tones heard (a frame, or keypad mode), or 0 if none. */
int ut_listener_group(ut_listener *l, char *out, size_t cap);
/* Keys heard since the last call, as they come (a rough, immediate view). */
int ut_listener_live(ut_listener *l, char *out, size_t cap);

/* ---- building blocks, exposed for tests ---------------------------------- */
void ut_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void ut_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                      uint32_t iterations, uint8_t *out, size_t outlen);
uint32_t ut_crc32(const uint8_t *data, size_t len);
/* Corrects up to nsym / 2 wrong bytes in place; returns how many, or UT_ERR_DECODE. */
int ut_rs_correct(uint8_t *codeword, size_t n, size_t nsym);
void ut_rs_encode(const uint8_t *data, size_t n, size_t nsym, uint8_t *parity);

#ifdef __cplusplus
}
#endif
#endif /* UR_TONES_H */
