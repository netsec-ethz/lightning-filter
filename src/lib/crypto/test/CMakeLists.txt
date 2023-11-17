cmake_minimum_required(VERSION 3.20)

enable_testing()

############
# crypto_hash_test
############
add_executable(crypto_hash_test EXCLUDE_FROM_ALL crypto_hash_test.c)
add_test(NAME crypto_hash_test COMMAND crypto_hash_test)
# Dependencies
target_sources(crypto_hash_test PRIVATE ../crypto.c)
# Crypto
target_link_libraries(crypto_hash_test  PRIVATE OpenSSL::SSL)
if(LF_CBCMAC STREQUAL "AESNI")
    target_link_libraries(crypto_hash_test  PRIVATE aesni)
endif()

add_dependencies(build_tests crypto_hash_test)

############
# crypto_mac_test
############
find_program (BASH_PROGRAM bash)
add_executable(crypto_mac_test EXCLUDE_FROM_ALL crypto_mac.c)
add_test(NAME crypto_mac_test COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/crypto_mac_test.sh)
# Dependencies
target_sources(crypto_mac_test PRIVATE ../crypto.c)
target_sources(crypto_mac_test PRIVATE ../../aesni)
# Crypto
target_link_libraries(crypto_mac_test  PRIVATE OpenSSL::SSL)
if(LF_CBCMAC STREQUAL "AESNI")
    target_link_libraries(crypto_mac_test  PRIVATE aesni)
endif()

add_dependencies(build_tests crypto_mac_test)

############
# crypto_drkey_test
############
add_executable(crypto_drkey_test EXCLUDE_FROM_ALL crypto_drkey_test.c)
add_test(NAME crypto_drkey_test COMMAND crypto_drkey_test)
# Dependencies
target_sources(crypto_drkey_test PRIVATE ../crypto.c)
# Crypto
target_link_libraries(crypto_drkey_test  PRIVATE OpenSSL::SSL)
if(LF_CBCMAC STREQUAL "AESNI")
    target_link_libraries(crypto_drkey_test  PRIVATE aesni)
endif()

add_dependencies(build_tests crypto_drkey_test)