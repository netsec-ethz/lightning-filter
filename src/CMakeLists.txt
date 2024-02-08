cmake_minimum_required(VERSION 3.20)

include(CMakeLint.cmake)

# Define an option to build the executable statically
option(BUILD_STATIC "Build a static executable" ON)
if(BUILD_STATIC)
  set(EXEC lfstatic)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
else()
  set(EXEC lfshared)
endif()

# Define executable
add_executable(${EXEC} main.c)

# Add symbolic link to the binary after the target has been built.
add_custom_command(TARGET ${EXEC} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E create_symlink
                   ${EXEC} lf)

# Set C standard and compile flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
add_compile_options(-pedantic --pedantic-errors)
target_compile_options(${EXEC} PRIVATE -O3 -fno-strict-overflow -fno-strict-aliasing)
target_compile_options(${EXEC} PRIVATE -Wall -Wextra -Werror)
target_compile_options(${EXEC} PRIVATE -Wcast-qual -Wcast-align -Wunused -Wshadow -Wwrite-strings)
target_compile_options(${EXEC} PRIVATE -Wstack-protector -fstack-protector-all)
# Warn if an undefined indentifier is evaluated in an #if directive.
# Requires all usd identifiers to be defined but can prevent identifier typos.
target_compile_options(${EXEC} PRIVATE -Wundef)
target_compile_options(${EXEC} PRIVATE -Wenum-conversion)

# Version Information
find_package(Git)
if(Git_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} describe --abbrev=8 --dirty --always --tags
    OUTPUT_VARIABLE GIT_REPO_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE)
    message("${PROJECT_NAME} git repo version: ${GIT_REPO_VERSION}")
    add_compile_definitions(${EXEC} PRIVATE LF_VERSION_GIT=${GIT_REPO_VERSION})
endif()

# Include additional CMake files
include(CMakeOptions.cmake)
include(plugins/CMakePlugins.cmake)

# Add all source files
target_sources(${EXEC} PRIVATE params.c setup.c duplicate_filter.c config.c configmanager.c)
target_sources(${EXEC} PRIVATE keyfetcher.c keymanager.c ratelimiter.c statistics.c version.c)
target_sources(${EXEC} PRIVATE worker.c worker_check.c)
target_sources(${EXEC} PRIVATE lib/crypto/crypto.c lib/hash/murmurhash.c lib/ipc/ipc.c)
target_sources(${EXEC} PRIVATE lib/mirror/mirror.c)
target_sources(${EXEC} PRIVATE plugins/plugins.c)

# Link DPDK statically
add_definitions(${DPDK_STATIC_CFLAGS}) # TODO: target
target_link_libraries(${EXEC} PRIVATE ${DPDK_STATIC_LDFLAGS} ${DPDK_STATIC_LIBS})
target_include_directories(${EXEC} PRIVATE ${DPDK_STATIC_INCLUDE_DIRS})

# Link OpenSSL
target_link_libraries(${EXEC} PRIVATE OpenSSL::SSL)

# Include JSON Parser
add_subdirectory(lib/json-parser/)
target_link_libraries(${EXEC} PRIVATE jsonparser)

# Tests
add_subdirectory(test)
add_subdirectory(lib/crypto/test)
add_subdirectory(lib/ratelimiter/test)