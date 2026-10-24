/* Placement macros set to something visible (tests/test_c_layers.py). */
#define UT_HOT __attribute__((noinline))
#define UT_ROM_U8(p) (*(const volatile uint8_t *)(p))
#define UT_ROM_U16(p) (*(const volatile uint16_t *)(p))
#define UT_ROM_U32(p) (*(const volatile uint32_t *)(p))
