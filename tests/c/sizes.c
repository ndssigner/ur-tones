/* The size of each public struct, one "name bytes" per line (tests/test_c_layers.py). */
#include <stdio.h>
#include "ur_tones.h"

#define SHOW(t) printf("%s %lu\n", #t, (unsigned long)sizeof(t))

int main(void)
{
	SHOW(ut_detector);
	SHOW(ut_keys);
	SHOW(ut_listener);
	SHOW(ut_synth);
	SHOW(ut_fountain_encoder);
	SHOW(ut_fountain_decoder);
	return 0;
}
