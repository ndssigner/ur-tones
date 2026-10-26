# The C library as a CMake target, for a Pico SDK project or any other:
#
#     add_subdirectory(path/to/ur-tones ur-tones)
#     target_link_libraries(my_app ur_tones)
#
# with -DUR_TONES_CONFIG_FILE=…/my_config.h (or set() before add_subdirectory)
# for a configuration of one's own; c/configs/ has the tested ones.
cmake_minimum_required(VERSION 3.13)
project(ur_tones C)

set(UR_TONES_CONFIG_FILE "" CACHE FILEPATH "Configuration header for the C library (UT_CONFIG_FILE); empty for the defaults")

add_library(ur_tones STATIC c/ur_tones.c)
target_include_directories(ur_tones PUBLIC c)
set_target_properties(ur_tones PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
if(UR_TONES_CONFIG_FILE)
    target_compile_definitions(ur_tones PUBLIC UT_CONFIG_FILE="${UR_TONES_CONFIG_FILE}")
endif()
