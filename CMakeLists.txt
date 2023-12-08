cmake_minimum_required(VERSION 3.20)

project(LightningFilter
        VERSION 0.1.0
        LANGUAGES C)

# DPDK library
find_package(PkgConfig REQUIRED)
pkg_search_module(DPDK REQUIRED libdpdk=23.11.0)

# OpenSSL library
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 3.0 REQUIRED)

# Tests:
# Tests are added as dependency to build_test target
# and are run with the run_test target.
enable_testing()
add_custom_target(build_tests)
# 'run_tests' triggers 'ctest'.
add_custom_target(run_tests COMMAND ${CMAKE_CTEST_COMMAND})
# 'run_tests' implies 'build_tests'
add_dependencies(run_tests build_tests)

# Source code (and tests)
add_subdirectory(src)

# IDEA: (fstreun) include the lib directory to avoid "lib/" in the import statements
# include_directories(src/lib)