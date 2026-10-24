/* NDS-Signer's uses of the library (arm9/src/nds_bridge.c, tones_audio.c),
 * with their types: they must keep compiling (tests/test_c_layers.py). */
#include <stdbool.h>
#include <string.h>
#include "ur_tones.h"

static ut_listener s_listener;
static ut_synth s_synth;
static char s_play[UT_MAX_FRAME + 1];

int ndsbTonesFrameToUr(const char *tones, char *ur, size_t cap, int *corrected) { return ut_frame_to_ur(tones, ur, cap, corrected); }
int ndsbTonesUrToFrame(const char *ur, char *tones, size_t cap) { return ut_ur_to_frame(ur, tones, cap); }
int ndsbTonesKeypadToSeed(const char *tones, const char *pin, uint8_t *entropy) { return ut_keypad_to_seed(tones, pin, entropy); }
int ndsbTonesUrToSeed(const char *ur, const char *pin, uint8_t *entropy) { return ut_ur_to_seed(ur, pin, entropy); }

int ndsbTonesSeedToFrame(const uint8_t *entropy, size_t len, const char *pin, char *tones, size_t cap)
{
	char ur[200];
	int n = ut_seed_to_ur(entropy, len, pin, ur, sizeof ur);
	if (n >= 0)
		n = ut_ur_to_frame(ur, tones, cap);
	memset(ur, 0, sizeof ur);
	return n;
}

int tonesListenPoll(const int16_t *pcm, size_t want, char *group, size_t cap, char *live, size_t livecap, int *level)
{
	ut_listener_init(&s_listener, 16384);
	ut_listener_push(&s_listener, pcm, want);
	*level = s_listener.level;
	ut_listener_live(&s_listener, live, livecap);
	int n = ut_listener_group(&s_listener, group, cap);
	return n > 0 ? n : 0;
}

int tonesPlay(const char *tones, int16_t *pcm, size_t n, unsigned *count, unsigned long long p)
{
	if (strlen(tones) > UT_MAX_FRAME)
		return 0;
	strcpy(s_play, tones);
	ut_synth_init(&s_synth, s_play, 32768, 40, 20, 200);
	size_t got = ut_synth_read(&s_synth, pcm, n);
	*count = (unsigned)s_synth.count;
	unsigned long long step = s_synth.tone_n + s_synth.gap_n;
	return got && p > s_synth.pause_n && step;
}
