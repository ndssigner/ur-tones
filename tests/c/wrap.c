/* The detector after days of listening: its windows anywhere in the ring
 * (tests/test_c_layers.py). Built with the library's source, to reach in. */
#include <stdio.h>
#include "../../c/ur_tones.c"

int main(void)
{
	static ut_detector d;
	static ut_synth s;
	static int16_t pcm[8000 * 4];
	ut_det out[1000];
	const char *keys = "CBAD1234";
	ut_synth_init(&s, keys, 8000, 80, 80, 200);
	size_t n = ut_synth_read(&s, pcm, sizeof pcm / sizeof pcm[0]);
	ut_detector_init(&d, 8000);
	d.pos = UT_RING - 37;                     /* windows straddle the ring's end */
	size_t used, k = ut_detector_push(&d, pcm, n, &used, out, 1000);
	char heard[64];
	size_t h = 0;
	for (size_t i = 0; i < k; i++)
		if (out[i].key && (i == 0 || out[i - 1].key != out[i].key) && h < sizeof heard - 1) heard[h++] = out[i].key;
	heard[h] = 0;
	printf("%lu %s\n", (unsigned long)k, heard);
	return !(k == (n - 200) / 80 + 1 && !strcmp(heard, keys));
}
