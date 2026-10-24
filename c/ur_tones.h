/*
 * ur-tones (draft v0), C99 implementation for small devices (SPEC.md).
 * SPDX-License-Identifier: MIT
 *
 * Frames (UR text <-> tones), keypad mode, seed URs, the seed PIN, tone
 * synthesis and a streaming receiver; UR's fountain codes (multi-part URs,
 * both ways), PSBTs as CBOR, and a signer's public keys as xpub text,
 * descriptors and the hdkey, output-descriptor and account-descriptor URs
 * (and their older crypto-* forms). No malloc, no floating point: integer
 * Goertzel, a sine table, IEEE doubles done with integers where UR needs
 * them, and fixed buffers, for CPUs without an FPU (the Nintendo DSi's
 * ARM9, a Raspberry Pi Pico). Checked against the Python reference, the test
 * vectors, ur2's parts and Blockchain Commons' vectors by tests/test_c*.py.
 *
 * Layers, each with its own calls, so a device plugs its hardware in where
 * it fits and uses the rest:
 *
 *   1. samples <-> detections   ut_detector (ADC, I2S, a microphone at any
 *      rate; ut_classify for one's own DSP), ut_synth (DAC, PWM, I2S)
 *   2. detections <-> groups    ut_keys: tones, echoes, pauses, keypad mode;
 *      ut_keys_tone for a DTMF decoder chip (MT8870, HT9170), ut_player for
 *      a generator chip (HT9200)
 *   3. groups <-> frames        ut_frame_decode/encode: sync, base 15,
 *      Reed-Solomon, a lost or extra tone repaired
 *   4. frames <-> messages      UR texts, seeds and the PIN, fountain codes
 *      (on frames or on texts), PSBTs, public keys
 *
 * ut_listener is layers 1 and 2 together; ut_frame_to_ur and ut_ur_to_frame
 * are layer 3 with UR text.
 *
 * Configuration: every option below can be set with -D… or, better, in a
 * header of one's own named by -DUT_CONFIG_FILE="my_config.h" (included
 * first; see ur_tones_config.example.h, which lists each option with what
 * it costs). Impossible values stop the build with an #error.
 *
 * Tones are ASCII keys: 0-9 A-D * #. Strings are NUL-terminated. Functions
 * that write return the length written (>= 0) or a negative UT_ERR_*, as an
 * int32_t (an int is 16 bits on some MCUs; a PSBT can be longer).
 */
#ifndef UR_TONES_H
#define UR_TONES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef UT_CONFIG_FILE
#include UT_CONFIG_FILE
#endif

/* ---- options (ur_tones_config.example.h explains each) ---- */
#ifndef UT_USE_DOUBLE
#define UT_USE_DOUBLE 0       /* 1: the CPU's doubles for the fountain codes (same results) */
#endif
#ifndef UT_MAX_PARTS
#define UT_MAX_PARTS 256      /* fragments in a multi-part message: 12 B each per encoder/decoder */
#endif
#ifndef UT_GROUP
#define UT_GROUP 600          /* tones in a group the receiver keeps */
#endif
#ifndef UT_READY
#define UT_READY 4            /* groups waiting to be taken: UT_GROUP + 1 bytes each */
#endif
#ifndef UT_LIVE
#define UT_LIVE 64            /* live keys waiting to be taken */
#endif
#ifndef UT_RING
#define UT_RING 1024          /* samples (at ~8 kHz) the receiver keeps: 2 B each */
#endif
/* Placement: UT_ROM on constant tables, read through UT_ROM_U8/U16/U32 (on
 * AVR: PROGMEM and pgm_read_byte/word/dword); UT_HOT on the hot loops (on
 * the RP2040/RP2350: a .time_critical section, run from RAM). */
#ifndef UT_ROM
#define UT_ROM
#endif
#ifndef UT_ROM_U8
#define UT_ROM_U8(p) (*(p))
#endif
#ifndef UT_ROM_U16
#define UT_ROM_U16(p) (*(p))
#endif
#ifndef UT_ROM_U32
#define UT_ROM_U32(p) (*(p))
#endif
#ifndef UT_HOT
#define UT_HOT
#endif

/* ---- protocol limits (SPEC.md; not options) ---- */
#define UT_PARITY 32          /* Reed-Solomon parity bytes per frame */
#define UT_MAX_FRAME 560      /* tones in the longest frame, plus room */
#define UT_MAX_UR 1100        /* characters in the longest UR text a frame carries */
#define UT_MAX_KEYPAD 100     /* "*" + 96 digits + "#" + NUL */
#define UT_MAX_FRAGMENT 200   /* bytes in a multi-part UR's fragment (a frame carries one part) */

#if UT_GROUP < UT_MAX_FRAME
#error "UT_GROUP must be at least UT_MAX_FRAME (560): a frame's tones must fit a group"
#endif
#if UT_RING < 560
#error "UT_RING must be at least 560: a 25 ms window and a 10 ms hop at up to 16 kHz"
#endif
#if UT_READY < 1
#error "UT_READY must be at least 1"
#endif
#if UT_LIVE < 1
#error "UT_LIVE must be at least 1"
#endif
#if UT_MAX_PARTS < 1 || UT_MAX_PARTS > 65535
#error "UT_MAX_PARTS must be from 1 to 65535"
#endif

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
	UT_ERR_MESSAGE = -10,  /* a part of another message (start a new decoder) */
};

/* ---- layer 3 · frames: tones <-> a UR's bytes (SPEC §2) --------------------
 * A frame carries one UR (single-part, or one part of a multi-part UR): its
 * type and its CBOR, protected by Reed-Solomon. ut_frame holds them as bytes,
 * for devices that never need the UR as text. */

#define UT_MAX_TYPE 218       /* a type of one's own, its length byte, 3 header bytes,
                                 1 body byte and the parity fill a codeword */
enum { UT_KIND_SINGLE = 0, UT_KIND_PART = 1 };

typedef struct {
	uint8_t kind;                 /* UT_KIND_SINGLE, UT_KIND_PART */
	char type[UT_MAX_TYPE + 1];   /* the UR type, e.g. "crypto-psbt" */
	uint8_t body[255];            /* the UR's CBOR */
	uint8_t n;
} ut_frame;

/* Tones (lead-in optional) to a frame; repairs as ut_frame_to_ur. Returns n. */
int32_t ut_frame_decode(const char *tones, ut_frame *f, int *corrected);
/* A frame to its tones (lead-in, sync, codeword). */
int32_t ut_frame_encode(const ut_frame *f, char *tones, size_t cap);
/* A UR text to a frame (UT_ERR_TOO_LONG if it can't fit one). Returns n. */
int32_t ut_frame_from_ur(const char *ur, ut_frame *f);
/* A frame to its UR text. */
int32_t ut_frame_ur(const ut_frame *f, char *ur, size_t cap);

/* The same, UR text in and out: */

/* The tones of the frame that carries `ur` (lead-in, sync, codeword). */
int32_t ut_ur_to_frame(const char *ur, char *tones, size_t cap);

/* The UR text of a frame's tones (lead-in optional). Repairs up to 16 wrong
 * bytes, and one lost or one extra tone. `corrected` (may be NULL) gets the
 * number of bytes repaired. */
int32_t ut_frame_to_ur(const char *tones, char *ur, size_t cap, int *corrected);

/* ---- seeds ---------------------------------------------------------------
 * entropy: 16 or 32 bytes. pin: NULL or "" for none, else letters and
 * digits (case-insensitive). */
int32_t ut_seed_to_keypad(const uint8_t *entropy, size_t len, const char *pin, char *out, size_t cap);
/* Returns the entropy's length (16 or 32) written to `entropy` (32 bytes). */
int32_t ut_keypad_to_seed(const char *tones, const char *pin, uint8_t *entropy);
int32_t ut_seed_to_ur(const uint8_t *entropy, size_t len, const char *pin, char *ur, size_t cap);
int32_t ut_ur_to_seed(const char *ur, const char *pin, uint8_t *entropy);

/* ---- multi-part URs: UR's fountain codes (BCR-2020-005), as ur2 ----------
 * A message (a UR's CBOR, e.g. a PSBT's) longer than one fragment goes as
 * parts in a loop: the first seq_len are its fragments, the rest mix
 * several. A receiver needs about seq_len parts, any of them, mixed ones
 * included: a lost frame costs one frame. */

#if UT_USE_DOUBLE
typedef double ut_f64;
#else
typedef uint64_t ut_f64;      /* an IEEE 754 double's bits */
#endif
typedef struct {              /* the degree table (Vose's alias method) */
	uint32_t n;
	ut_f64 prob[UT_MAX_PARTS];
	uint16_t alias[UT_MAX_PARTS], stack[UT_MAX_PARTS];
} ut_sampler;

typedef struct {
	const uint8_t *msg;       /* kept, not copied */
	uint32_t len, checksum, fragment, seq_len, seq_num;
	ut_sampler sampler;
} ut_fountain_encoder;

/* max_fragment: 100 is SPEC §2.4's (about 19 s per frame by cable). */
int32_t ut_fountain_encoder_init(ut_fountain_encoder *e, const uint8_t *msg, size_t len, size_t max_fragment);
/* The next UR to send, forever: the message as one UR if it fits one
 * fragment, else the next part ("ur:<type>/<n>-<seq_len>/…"). Each goes in
 * a frame (ut_ur_to_frame). */
int32_t ut_fountain_next_ur(ut_fountain_encoder *e, const char *type, char *ur, size_t cap);
/* The same as a frame (ut_frame_encode), with no UR text on the way. */
int32_t ut_fountain_next_frame(ut_fountain_encoder *e, const char *type, ut_frame *f);
/* The next part's CBOR: [seqNum, seqLen, messageLen, checksum, fragment]. */
int32_t ut_fountain_next_part(ut_fountain_encoder *e, uint8_t *out, size_t cap);

typedef struct {
	char type[64];
	uint8_t *work, *msg, *known, *pool;
	size_t work_len;
	uint32_t seq_len, len, checksum, fragment, set_bytes, nknown, nmixed, max_mixed;
	int done;
	ut_sampler sampler;
} ut_fountain_decoder;

/* work: memory for the message and the mixed parts waiting to be used: at
 * least the message's length plus a few fragments; twice the message keeps
 * every useful part. The result is read from it. */
#define UT_FOUNTAIN_WORK(message_len) (2 * (message_len) + 4 * UT_MAX_FRAGMENT)
int32_t ut_fountain_decoder_init(ut_fountain_decoder *d, uint8_t *work, size_t work_len);
/* A UR heard (ut_frame_to_ur): the whole message or one of its parts.
 * Returns 1 when the message is complete (and its CRC-32 checks), 0 while
 * more are needed (progress: nknown of seq_len fragments), or an error:
 * UT_ERR_MESSAGE for a part of another message. */
int32_t ut_fountain_receive(ut_fountain_decoder *d, const char *ur);
/* The same from a frame (ut_frame_decode); frames and texts may be mixed. */
int32_t ut_fountain_receive_frame(ut_fountain_decoder *d, const ut_frame *f);
int32_t ut_fountain_result(const ut_fountain_decoder *d, const char **type, const uint8_t **msg, size_t *len);
/* The fragments a part carries, as bits of `set` ((seq_len + 7) / 8 bytes).
 * Exposed for tests. `t` keeps the degree table for one seq_len: zero it
 * before its first use. */
int32_t ut_fountain_choose(ut_sampler *t, uint32_t seq_num, uint32_t seq_len, uint32_t checksum, uint8_t *set);

/* ---- PSBTs: the CBOR of crypto-psbt and psbt (a byte string) ---------------- */
int32_t ut_psbt_to_cbor(const uint8_t *psbt, size_t len, uint8_t *out, size_t cap);
/* *psbt points into cbor. */
int32_t ut_cbor_to_psbt(const uint8_t *cbor, size_t len, const uint8_t **psbt, size_t *psbt_len);

/* ---- a signer's public keys ------------------------------------------------
 * An account's extended public key, which the signer derives (BIP-32): out
 * as xpub text (or ypub, zpub, Ypub, Zpub: SLIP-132), as a descriptor with
 * its checksum, or as the CBOR of a UR to send: hdkey, output-descriptor
 * (BCR-2023-010) and account-descriptor (BCR-2023-019) when current is 1,
 * crypto-hdkey, crypto-output and crypto-account (the older types, for
 * older wallets) when 0. A script is the key's descriptor around "@0":
 * "pkh(@0)", "sh(wpkh(@0))", "wpkh(@0)", "tr(@0)", "wsh(cosigner(@0))"… */
typedef struct {
	uint8_t key[33];          /* compressed public key */
	uint8_t chain[32];        /* chain code */
	uint32_t parent_fp;       /* the parent key's fingerprint */
	uint32_t source_fp;       /* the master key's fingerprint */
	const uint32_t *path;     /* from the master key; hardened: | 0x80000000 */
	size_t depth;             /* steps in path */
	int testnet;
} ut_xpub;
/* prefix: "xpub", "ypub", "zpub", "Ypub" or "Zpub"; a testnet key comes out as
 * tpub, upub, vpub, Upub or Vpub. */
int32_t ut_xpub_text(const ut_xpub *k, const char *prefix, char *out, size_t cap);
int32_t ut_descriptor_text(const char *script, const ut_xpub *k, char *out, size_t cap);
int32_t ut_hdkey_cbor(const ut_xpub *k, int current, uint8_t *out, size_t cap);
int32_t ut_output_cbor(const char *script, const ut_xpub *k, int current, uint8_t *out, size_t cap);
/* An account: one script and key per entry (BIP-44, 49, 84, 86, 48…). */
int32_t ut_account_cbor(uint32_t master_fp, const char *const *scripts, const ut_xpub *keys, size_t n,
                        int current, uint8_t *out, size_t cap);

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

/* ---- sending through a DTMF generator chip (HT9200…) ---------------------
 * The same timing as ut_synth, as steps: a key (0: silence) held for on_ms,
 * then off_ms of silence. */
typedef struct { uint16_t tone_ms, gap_ms, pause_ms; } ut_timing;
#define UT_TIMING_CABLE { 40, 20, 400 }   /* SPEC §1.1's recommendations */
#define UT_TIMING_AIR   { 80, 80, 600 }

typedef struct {
	const char *tones;        /* kept, not copied */
	size_t count, index;
	ut_timing t;
	int stage;                /* 0 opening pause, 1 tones, 2 final pause, 3 done */
} ut_player;

void ut_player_init(ut_player *p, const char *tones, const ut_timing *t);
/* The next step: the opening pause (key 0), each key with its gap, the
 * final pause (key 0). Returns 1, or 0 when done. */
int32_t ut_player_next(ut_player *p, char *key, uint32_t *on_ms, uint32_t *off_ms);

/* ---- layer 1 · samples to detections (SPEC appendix A) -------------------
 * Every 10 ms, the eight DTMF frequencies over the last 25 ms (Goertzel, in
 * integers, after bringing the rate down to about 8 kHz): one detection, a
 * key or none, and the tone's level. A device with its own DSP (CMSIS-DSP,
 * an FFT, a vector unit) can compute the eight powers itself and call
 * ut_classify, so that every receiver decides the same way. */

typedef struct {
	char key;                 /* 0-9 A-D * #, or 0: none */
	int16_t level;            /* the tone's level in 0.1 dBFS; -990: silence */
} ut_det;

typedef struct {
	uint32_t rate, dec, srate, n, hop;
	int32_t coeff[8];         /* cos(w), Q15 */
	int32_t dec_sum;
	uint32_t dec_count;
	int16_t ring[UT_RING];
	uint32_t total, next;     /* samples kept; start of the next window */
	int level;                /* the last window's level, as ut_det's */
} ut_detector;

void ut_detector_init(ut_detector *d, uint32_t rate);
/* Signed 16-bit mono samples in; detections out, up to `cap`. *used: how
 * many samples it took (all of them unless `out` filled up first). */
size_t ut_detector_push(ut_detector *d, const int16_t *x, size_t n, size_t *used, ut_det *out, size_t cap);
/* How long a detection lasts, in seconds: num / den (for ut_keys_init). */
void ut_detector_tick(const ut_detector *d, uint32_t *num, uint32_t *den);
/* SPEC appendix A's decision, from the eight Goertzel powers |X|^2 of an
 * n-sample window of 16-bit samples (low group 697-941 Hz, then high group
 * 1209-1633 Hz) and the window's energy (the sum of its samples squared). */
void ut_classify(const int64_t power[8], uint64_t energy, uint32_t n, char *key, int16_t *level);

/* ---- layer 2 · detections to groups of keys (SPEC appendix A) ------------
 * A tone is one key for at least 30 ms; a key that drops out for up to 30 ms
 * is the same tone (flicker); the same key again is a new tone only if it
 * comes back nearly as loud (an echo is weaker). Tones then make groups:
 * split by silences over 225 ms, except keypad mode ("*", digits, "#"),
 * which runs to its "#"; in a data frame a repeated key is an echo, dropped.
 * Streaming: a few bytes of state, whatever the length of the input.
 *
 * Time goes in ticks of num / den seconds: a detector's (ut_detector_tick),
 * or 1 / 1000 for milliseconds. */

typedef struct {
	uint32_t num, den;                  /* a tick lasts num / den s */
	/* the segmenter */
	ut_det look[3];                     /* detections waiting for the ones after them */
	uint32_t nlook, at, since, silent;  /* at: the next detection's tick */
	char cur_key, last_key, prev_key;
	uint8_t have_cur, have_prev, dipped;
	uint32_t cur_start, cur_end, prev_start, prev_end, gap;
	int cur_peak, last_peak;
	/* the grouper */
	char current[UT_GROUP + 1];
	uint32_t clen, last_end;
	uint8_t have_end;
	char ready[UT_READY][UT_GROUP + 1];
	uint32_t rhead, rcount;
	/* the live view */
	char live_key;
	uint32_t live_run, nlive;
	char live[UT_LIVE];
} ut_keys;

void ut_keys_init(ut_keys *k, uint32_t tick_num, uint32_t tick_den);
/* One detection per tick (ut_detector_push's, or one's own DSP's). */
void ut_keys_detection(ut_keys *k, char key, int16_t level);
/* Or, from a DTMF decoder chip (MT8870, HT9170: StD's rising and falling
 * edges), a whole tone, start and end in ticks; the chip has done what the
 * segmenter does. One ut_keys takes detections or tones, not both. Ticks
 * may wrap around 2^32. */
void ut_keys_tone(ut_keys *k, char key, uint32_t start, uint32_t end);
/* With tones: time passes. Closes a group after 300 ms of silence (a frame's
 * end), as detections of silence do. */
void ut_keys_time(ut_keys *k, uint32_t now);
/* At the end of the input: closes what is pending. */
void ut_keys_flush(ut_keys *k);
/* The next group of keys (a frame, or keypad mode), or 0 if none. */
int32_t ut_keys_group(ut_keys *k, char *out, size_t cap);
/* Keys since the last call, as they come (a rough, immediate view). */
int32_t ut_keys_live(ut_keys *k, char *out, size_t cap);

/* ---- listening: layers 1 and 2 together ---------------------------------- */

typedef struct {
	ut_detector det;
	ut_keys keys;
	int level;                /* the last window's tone level, in 0.1 dBFS (-990: silence) */
} ut_listener;

void ut_listener_init(ut_listener *l, uint32_t rate);
/* Signed 16-bit mono samples, as they come. */
void ut_listener_push(ut_listener *l, const int16_t *x, size_t n);
/* At the end of a recording: closes what is pending. */
void ut_listener_flush(ut_listener *l);
/* The next group of tones heard (a frame, or keypad mode), or 0 if none. */
int32_t ut_listener_group(ut_listener *l, char *out, size_t cap);
/* Keys heard since the last call, as they come (a rough, immediate view). */
int32_t ut_listener_live(ut_listener *l, char *out, size_t cap);

/* ---- building blocks, exposed for tests ---------------------------------- */
void ut_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void ut_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                      uint32_t iterations, uint8_t *out, size_t outlen);
uint32_t ut_crc32(const uint8_t *data, size_t len);
/* Corrects up to nsym / 2 wrong bytes in place; returns how many, or UT_ERR_DECODE. */
int32_t ut_rs_correct(uint8_t *codeword, size_t n, size_t nsym);
void ut_rs_encode(const uint8_t *data, size_t n, size_t nsym, uint8_t *parity);

#ifdef __cplusplus
}
#endif
#endif /* UR_TONES_H */
