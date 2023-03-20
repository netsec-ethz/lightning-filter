cmake_minimum_required(VERSION 3.20)

# Add clang-tidy
option(CMAKE_RUN_CLANG_TIDY "Run clang-tidy with the compiler." OFF)
if(CMAKE_RUN_CLANG_TIDY)
    find_program(CLANG_TIDY_COMMAND NAMES clang-tidy REQUIRED)

    # clang's -line-filter seems not to work in combination with the config file.
    #set(CMAKE_C_CLANG_TIDY
    #    ${CLANG_TIDY_COMMAND};-line-filter=[{'name':'rte_ip.c','lines':[[150,170]]}];--config-file=${CMAKE_CURRENT_SOURCE_DIR}/.clang-tidy)
    set(CMAKE_C_CLANG_TIDY
        ${CLANG_TIDY_COMMAND};--config-file=${CMAKE_CURRENT_SOURCE_DIR}/.clang-tidy;)

    # Create a preprocessor definition that depends on .clang-tidy content so
    # the compile command will change when .clang-tidy changes.  This ensures
    # that a subsequent build re-runs clang-tidy on all sources even if they
    # do not otherwise need to be recompiled.  Nothing actually uses this
    # definition.  We add it to targets on which we run clang-tidy just to
    # get the build dependency on the .clang-tidy file.
    file(SHA1 ${CMAKE_CURRENT_SOURCE_DIR}/.clang-tidy clang_tidy_sha1)
    set(CLANG_TIDY_DEFINITIONS "CLANG_TIDY_SHA1=${clang_tidy_sha1}")
    unset(clang_tidy_sha1)

else()
    set(CMAKE_C_CLANG_TIDY "" CACHE STRING "" FORCE)
endif()

configure_file(.clang-tidy .clang-tidy COPYONLY)
