/*
 * ur-tones on a Raspberry Pi Pico (RP2040): listens, sends and measures, over
 * USB serial (examples/pico/README.md has the wiring).
 *
 *   listening, always: line in on GP27 (ADC1) at 16 kHz, by DMA into a ring;
 *     each group heard is printed as its UR (and the bytes repaired), or, for
 *     keypad mode, as a seed's length only (never the seed)
 *   send <ur>   the UR as one frame of tones: PWM on GP15
 *   level       the input's swing and the last tone's level, to set the volume
 *   bench       how long a PIN, a second of audio and a repair take
 */
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/adc.h"
#include "hardware/clocks.h"
#include "hardware/dma.h"
#include "hardware/irq.h"
#include "hardware/pwm.h"
#include "ur_tones.h"

#define PIN_LED     25
#define ADC_PIN     27
#define ADC_INPUT   1                 /* GP27 = ADC1 */
#define RATE        16000
#define RING_BITS   12                /* 4096 bytes = 2048 samples, 128 ms */
#define RING_N      (1u << (RING_BITS - 1))
#define PIN_OUT     15
#define PWM_DIV     4
#define PWM_WRAP    250               /* 125 MHz / 4 / 250 = 125 kHz carrier */
#define PWM_SUB     8                 /* a sample every 8 cycles: 15,625 Hz */
#define OUT_N       1024

static uint16_t ring[RING_N] __attribute__((aligned(1u << RING_BITS)));
static int dma_chan;
static ut_listener listener;

static ut_synth synth;
static char out_tones[UT_MAX_FRAME + 1];   /* the synthesiser keeps a pointer */
static int16_t out_ring[OUT_N];
static volatile uint32_t out_head, out_tail;
static bool sending;
static uint slice;

/* ---- line in: ADC by DMA -------------------------------------------------- */

static void adc_dma_start(void)
{
	adc_init();
	adc_gpio_init(ADC_PIN);
	adc_select_input(ADC_INPUT);
	adc_fifo_setup(true, true, 1, false, false);   /* FIFO, DREQ at 1 sample, 12 bits */
	adc_set_clkdiv(48000000.0f / RATE - 1);        /* 48 MHz ADC clock */

	dma_chan = dma_claim_unused_channel(true);
	dma_channel_config c = dma_channel_get_default_config(dma_chan);
	channel_config_set_transfer_data_size(&c, DMA_SIZE_16);
	channel_config_set_read_increment(&c, false);
	channel_config_set_write_increment(&c, true);
	channel_config_set_ring(&c, true, RING_BITS);  /* wrap the write address */
	channel_config_set_dreq(&c, DREQ_ADC);
	dma_channel_configure(dma_chan, &c, ring, &adc_hw->fifo, 0xFFFFFFFFu, true);
	adc_run(true);
}

static uint32_t ring_write_index(void)
{
	return ((uintptr_t)dma_hw->ch[dma_chan].write_addr - (uintptr_t)ring) / 2 % RING_N;
}

/* ---- line out: PWM, a sample every PWM_SUB cycles -------------------------- */

static void __not_in_flash_func(on_wrap)(void)
{
	static uint32_t sub;
	pwm_clear_irq(slice);
	if (++sub < PWM_SUB) return;
	sub = 0;
	int32_t s = 0;
	if (out_tail != out_head) {
		s = out_ring[out_tail];
		out_tail = (out_tail + 1) % OUT_N;
	}
	pwm_set_gpio_level(PIN_OUT, (uint16_t)(PWM_WRAP / 2 + s * (PWM_WRAP / 2 - 1) / 32768));
}

static uint32_t out_rate(void)
{
	return clock_get_hz(clk_sys) / (PWM_DIV * PWM_WRAP * PWM_SUB);
}

static void pwm_start(void)
{
	gpio_set_function(PIN_OUT, GPIO_FUNC_PWM);
	slice = pwm_gpio_to_slice_num(PIN_OUT);
	pwm_config cfg = pwm_get_default_config();
	pwm_config_set_clkdiv_int(&cfg, PWM_DIV);
	pwm_config_set_wrap(&cfg, PWM_WRAP - 1);
	pwm_init(slice, &cfg, false);   /* runs only while sending: its edges are noise for the ADC */
	pwm_set_gpio_level(PIN_OUT, PWM_WRAP / 2);      /* silence: mid scale */
	irq_set_exclusive_handler(PWM_IRQ_WRAP, on_wrap);
	irq_set_enabled(PWM_IRQ_WRAP, true);
}

static void pwm_run(bool on)
{
	pwm_clear_irq(slice);
	pwm_set_irq_enabled(slice, on);
	pwm_set_enabled(slice, on);
}

/* Tops up the samples the PWM interrupt plays. */
static void feed(void)
{
	static bool draining;
	if (draining && out_tail == out_head) {
		draining = false;
		pwm_run(false);
		printf("sent\n");
	}
	while (sending && (out_head + 1) % OUT_N != out_tail) {
		int16_t s;
		if (!ut_synth_read(&synth, &s, 1)) {
			sending = false;
			draining = true;
			break;
		}
		out_ring[out_head] = s;
		out_head = (out_head + 1) % OUT_N;
	}
}

/* ---- what was heard ------------------------------------------------------- */

static void heard(char *group, int32_t n)
{
	static char ur[UT_MAX_UR];
	if (group[0] == '*') {
		uint8_t entropy[32];
		int32_t r = ut_keypad_to_seed(group, NULL, entropy);   /* the PIN, if any, is the receiver's */
		memset(entropy, 0, sizeof entropy);
		if (r > 0)
			printf("keypad: a seed of %ld bytes (checksum good)\n", (long)r);
		else
			printf("keypad: %ld digits, not a seed (%ld)\n", (long)n - 2, (long)r);
	} else {
		int fixed = 0;
		int32_t r = ut_frame_to_ur(group, ur, sizeof ur, &fixed);
		if (r > 0)
			printf("%s\n  (%d bytes repaired)\n", ur, fixed);
		else
			printf("%ld tones, not a frame (%ld)\n", (long)n, (long)r);
	}
	memset(group, 0, (size_t)n);
}

static uint32_t rd;   /* the next sample to read in ring */
static uint16_t vmin = 4095, vmax;   /* the input's swing since the last `level` */

static void listen(void)
{
	static char group[UT_GROUP + 1];
	int16_t block[160];
	uint32_t wr = ring_write_index();
	while (rd != wr) {
		size_t n = 0;
		while (rd != wr && n < sizeof block / sizeof block[0]) {
			uint16_t v = ring[rd] & 0x0FFF;
			if (v < vmin) vmin = v;
			if (v > vmax) vmax = v;
			block[n++] = (int16_t)(((int32_t)v - 2048) * 16);
			rd = (rd + 1) % RING_N;
		}
		ut_listener_push(&listener, block, n);
	}
	int32_t n = ut_listener_group(&listener, group, sizeof group);
	if (n > 0) {
		gpio_put(PIN_LED, !gpio_get(PIN_LED));
		heard(group, n);
	}
}

/* After a long pause (bench), starts again from now: the DMA has gone round
 * the ring meanwhile. */
static void listen_again(void)
{
	ut_listener_init(&listener, RATE);
	rd = ring_write_index();
}

/* ---- commands --------------------------------------------------------------- */

static void send(const char *ur)
{
	int32_t r = ut_ur_to_frame(ur, out_tones, sizeof out_tones);
	if (r < 0) {
		printf("not sent: %ld\n", (long)r);
		return;
	}
	ut_synth_init(&synth, out_tones, out_rate(), 40, 20, 400);
	sending = true;
	pwm_run(true);
	printf("sending %ld tones at %lu Hz\n", (long)r, (unsigned long)out_rate());
}

static const char BENCH_UR[] =
	"ur:bytes/hdfmkpjpdpjyjljtihjkftcxhsjtkkcxidkkjyihjkdwcxjkkpiaiscxhsjkcxhscxkthsjzjzihjycxiyinjzihcxjljp"
	"cxhscxjnkpjzjyinjkiniocxjkihjykpjowyfwiadt";

static void bench(void)
{
	static char tones[UT_MAX_FRAME + 1], ur[UT_MAX_UR], group[UT_GROUP + 1];
	static ut_listener l;
	static ut_synth s;
	uint8_t entropy[16] = {0};
	int16_t block[160];

	uint64_t t = time_us_64();
	int32_t r = ut_seed_to_keypad(entropy, 16, "ABC123", tones, sizeof tones);
	printf("PIN (PBKDF2, 10,000 iterations): %lu us (%ld)\n", (unsigned long)(time_us_64() - t), (long)r);

	r = ut_ur_to_frame(BENCH_UR, tones, sizeof tones);
	ut_listener_init(&l, RATE);
	ut_synth_init(&s, tones, RATE, 40, 20, 400);
	uint64_t busy = 0, samples = 0;
	size_t n;
	while ((n = ut_synth_read(&s, block, sizeof block / sizeof block[0]))) {
		t = time_us_64();
		ut_listener_push(&l, block, n);
		busy += time_us_64() - t;
		samples += n;
	}
	ut_listener_flush(&l);
	int32_t got = ut_listener_group(&l, group, sizeof group);
	printf("receiver: %lu us of CPU per second of audio at %d Hz (%s)\n",
	       (unsigned long)(busy * RATE / samples), RATE,
	       got == r && !strcmp(group, tones) ? "frame heard" : "frame NOT heard");

	for (size_t i = 8; i < (size_t)r; i += 40)            /* 5 tones misheard, far apart */
		tones[i] = tones[i] == '0' ? '1' : '0';
	int fixed = 0;
	t = time_us_64();
	r = ut_frame_to_ur(tones, ur, sizeof ur, &fixed);
	printf("repair: %lu us for %d bytes (%s)\n", (unsigned long)(time_us_64() - t), fixed,
	       r > 0 && !strcmp(ur, BENCH_UR) ? "UR back" : "UR NOT back");
}

static void command(char *line)
{
	if (!strncmp(line, "send ", 5))
		send(line + 5);
	else if (!strcmp(line, "level")) {
		int swing = vmax > vmin ? vmax - vmin : 0;
		printf("input swing %d of 4095 (%s), last tone %d.%d dBFS\n", swing,
		       swing < 100 ? "too low: turn the volume up" : swing > 3800 ? "clipping: turn it down" : "good",
		       listener.level / 10, (listener.level < 0 ? -listener.level : listener.level) % 10);
		vmin = 4095; vmax = 0;
	} else if (!strcmp(line, "bench")) {
		bench();
		listen_again();
	}
	else if (*line)
		printf("commands: send <ur>, level, bench\n");
}

int main(void)
{
	static char line[UT_MAX_UR + 8];
	size_t len = 0;
	stdio_init_all();
	gpio_init(PIN_LED);
	gpio_set_dir(PIN_LED, GPIO_OUT);
	ut_listener_init(&listener, RATE);
	adc_dma_start();
	pwm_start();

	for (;;) {
		feed();
		listen();
		int c = getchar_timeout_us(0);
		if (c == PICO_ERROR_TIMEOUT)
			continue;
		if (c == '\r' || c == '\n') {
			line[len] = 0;
			len = 0;
			command(line);
		} else if (len + 1 < sizeof line) {
			line[len++] = (char)c;
		}
	}
}
