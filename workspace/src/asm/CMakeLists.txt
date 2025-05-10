cmake_minimum_required(VERSION 3.14)

# Set the project name
project(test C ASM)

# Add executable target
add_executable(
    sort.elf
    sort/sort.S
    shared/boot.S
)

# Configure linker settings
set(CODE_ADDRESS 0)  # Default value, can be changed
set(HALT_ADDRESS 16384)  # Default value, can be changed
set(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/shared/link_script.ld)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostartfiles -Wl,--defsym=CODE_ADDRESS=${CODE_ADDRESS} -Wl,--defsym=HALT_ADDRESS=${HALT_ADDRESS} -fno-exceptions -Xlinker -T ${LINKER_SCRIPT} -Wl,-Map=sort.map")

# Create binary file from ELF
add_custom_command(
    TARGET sort.elf POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:sort.elf> sort.bin
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:sort.elf> ${CMAKE_CURRENT_BINARY_DIR}/sort.elf
    COMMENT "Generating binary file from ELF"
)

# Testing configuration
enable_testing()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_custom_target(
    rebuild_and_test ALL
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target sort.elf
    COMMAND ${Python3_EXECUTABLE} -m pytest ${CMAKE_CURRENT_SOURCE_DIR}/test
            --binary=${CMAKE_CURRENT_BINARY_DIR}/sort.bin
            --code-address=${CODE_ADDRESS} --halt-address=${HALT_ADDRESS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
    COMMENT "Rebuilding and running tests"
)

# Function to discover and add pytest tests
function(add_pytest_tests)
    # Run pytest with --collect-only to get test names
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -m pytest --collect-only -q
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
        OUTPUT_VARIABLE pytest_tests
        ERROR_VARIABLE pytest_error
        RESULT_VARIABLE pytest_result
    )
    
    if(NOT pytest_result EQUAL 0)
        message(WARNING "Failed to discover pytest tests: ${pytest_error}")
        return()
    endif()
    
    # Parse the output to get individual test names
    string(REGEX REPLACE "\n" ";" test_list "${pytest_tests}")
    
    foreach(test_case ${test_list})
        if(test_case MATCHES "::")
            # Add each test as a separate CTest
            add_test(
                NAME pytest_${test_case}
                COMMAND ${Python3_EXECUTABLE} -m pytest ${test_case} 
                --binary=${CMAKE_CURRENT_BINARY_DIR}/sort.bin 
                --code-address=${CODE_ADDRESS} --halt-address=${HALT_ADDRESS}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
            )
            set_tests_properties(pytest_${test_case} PROPERTIES DEPENDS sort.elf)
        endif()
    endforeach()
endfunction()

# Call the function to discover tests
add_pytest_tests()