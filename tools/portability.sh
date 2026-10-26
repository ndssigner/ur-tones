#!/bin/sh
# The C library built for a microcontroller, as CI checks it: warnings are
# errors, with the default configuration and with the target's own
# (c/configs/), then the code and data each part takes and the size of each
# struct an application places.
#
#     tools/portability.sh m0plus     # RP2040 (Cortex-M0+): arm-none-eabi-gcc
#     tools/portability.sh arm946     # Nintendo DSi (ARM946E-S): arm-none-eabi-gcc
#
# Prints the figures docs/porting.md quotes; exits non-zero on any failure.
set -eu
cd "$(dirname "$0")/.."

case "${1:-}" in
m0plus)
	cc="arm-none-eabi-gcc -mcpu=cortex-m0plus -mthumb"
	prefix=arm-none-eabi-
	config=c/configs/ut_config_rp2040.h
	;;
arm946)
	cc="arm-none-eabi-gcc -march=armv5te -mtune=arm946e-s -marm"
	prefix=arm-none-eabi-
	config=c/configs/ut_config_nds.h
	;;
*)
	echo "usage: $0 m0plus|arm946" >&2
	exit 2
	;;
esac

flags="-std=c99 -Os -Wall -Wextra -Werror -ffunction-sections -fdata-sections -Ic"
out=build/portability-$1
mkdir -p "$out"

# $cc and $flags split into words on purpose; the config's name stays one.
# shellcheck disable=SC2086
build() {   # build <output> <source> [-DUT_CONFIG_FILE=…]
	o=$1; src=$2; shift 2
	$cc $flags "$@" -c "$src" -o "$o"
}

build "$out/default.o" c/ur_tones.c
build "$out/target.o" c/ur_tones.c "-DUT_CONFIG_FILE=\"$PWD/$config\""
for name in default target; do
	[ $name = default ] && what="default configuration" || what=$(basename "$config")
	echo "== $1, $what (text = code and constants, data + bss = RAM)"
	"${prefix}size" "$out/$name.o"
done

# The structs, as objects the size of each one, read back by nm.
printf '#include "ur_tones.h"\n%s\n%s\n' \
	"ut_detector s_ut_detector; ut_keys s_ut_keys; ut_listener s_ut_listener; ut_synth s_ut_synth;" \
	"ut_fountain_encoder s_ut_fountain_encoder; ut_fountain_decoder s_ut_fountain_decoder; ut_frame s_ut_frame;" \
	> "$out/structs.c"
build "$out/structs.o" "$out/structs.c" -fno-common "-DUT_CONFIG_FILE=\"$PWD/$config\""
echo "== structs an application places (bytes)"
"${prefix}nm" -S --size-sort "$out/structs.o" | while read -r _ size _ sym; do
	printf '%-22s %6d\n' "${sym#s_}" "$((0x$size))"
done
