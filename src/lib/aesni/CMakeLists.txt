cmake_minimum_required(VERSION 3.20)
enable_testing()

find_program(YASM yasm)

add_custom_command(OUTPUT aesnix64asm.o COMMAND ${YASM}
  ARGS -D__linux__ -g dwarf2 -f elf64 -o aesnix64asm.o  ${CMAKE_CURRENT_SOURCE_DIR}/aesnix64asm.s)

add_library(aesni aesnix64asm.o)
set_target_properties(aesni PROPERTIES LINKER_LANGUAGE C)

############
# aesni_test
############
find_program (BASH_PROGRAM bash)
add_executable(aesni_test EXCLUDE_FROM_ALL test/aesni_test.c)
add_test(NAME aesni_test COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/test/aesni_test.sh)
target_link_libraries(aesni_test  PRIVATE aesni)

add_dependencies(build_tests aesni_test)