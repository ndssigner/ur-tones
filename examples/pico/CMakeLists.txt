# ur-tones on a Raspberry Pi Pico: examples/pico/README.md.
#
#     cmake -S examples/pico -B build/pico -DPICO_SDK_PATH=…/pico-sdk
#     cmake --build build/pico        # build/pico/ur_tones_pico.uf2
cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico CACHE STRING "Board")
include(pico_sdk_import.cmake)
project(ur_tones_pico C CXX ASM)
pico_sdk_init()

set(UR_TONES_CONFIG_FILE ${CMAKE_CURRENT_LIST_DIR}/../../c/configs/ut_config_rp2040.h)
add_subdirectory(../.. ur-tones)

add_executable(ur_tones_pico main.c)
target_link_libraries(ur_tones_pico ur_tones pico_stdlib hardware_adc hardware_dma hardware_pwm)
# The library's deepest call (ut_ur_to_frame) takes about 2.6 KB of stack on
# the M0+; the SDK's default is 2 KB. 4 KB is all of SCRATCH_Y.
target_compile_definitions(ur_tones_pico PRIVATE PICO_STACK_SIZE=0x1000)

pico_enable_stdio_usb(ur_tones_pico 1)
pico_enable_stdio_uart(ur_tones_pico 0)
pico_add_extra_outputs(ur_tones_pico)
