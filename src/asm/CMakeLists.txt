cmake_minimum_required(VERSION 3.14)

# set the project name
project(test C ASM)

add_executable(
    gcd.elf
    gcd/gcd.S
    shared/boot.S
)
SET(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/shared/link_script.ld)

SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -nostartfiles -fno-exceptions  -Xlinker -T ${LINKER_SCRIPT} -Wl,-Map=gcd.map")

add_custom_command(TARGET gcd.elf POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary gcd.elf gcd.bin
        COMMENT "Invoking: objcopy")


enable_testing()

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(
    NAME emulation_tests
    COMMAND python3 -m pytest ${CMAKE_CURRENT_SOURCE_DIR}/test --binary=../build/gcd.bin
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIRECTORY}
)

set_tests_properties(emulation_tests PROPERTIES DEPENDS gcd.elf)
