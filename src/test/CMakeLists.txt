enable_testing()

############
# config_parser_test
############
add_executable(config_parser_test EXCLUDE_FROM_ALL config_parser_test.c)
add_test(NAME config_parser_test COMMAND config_parser_test)
# Dependencies
target_sources(config_parser_test PRIVATE log_mock.c)
target_sources(config_parser_test PRIVATE ../config.c)
# Include JSON Parser
target_link_libraries(config_parser_test PRIVATE jsonparser)
# requires math library
target_link_libraries(config_parser_test PRIVATE m)
# Copy configuration file to the build directory
add_custom_target(config_parser_test_file
    ${CMAKE_COMMAND} -E
    copy_if_different
    ${CMAKE_CURRENT_LIST_DIR}/config_parser_test1.json
    ${CMAKE_CURRENT_BINARY_DIR}/
)
add_dependencies(config_parser_test config_parser_test_file)

############
# duplicate_filter_test
############
add_executable(duplicate_filter_test EXCLUDE_FROM_ALL duplicate_filter_test.c)
add_test(NAME duplicate_filter_test COMMAND duplicate_filter_test --no-huge)
# Dependencies
target_sources(duplicate_filter_test PRIVATE log_mock.c)
target_sources(duplicate_filter_test PRIVATE ../duplicate_filter.c ../lib/hash/murmurhash.c)
# DPDK
add_definitions(${DPDK_STATIC_CFLAGS}) # TODO: target
target_include_directories(duplicate_filter_test PRIVATE ${DPDK_SATIC_INCLUDE_DIRS})
target_link_libraries(duplicate_filter_test PRIVATE ${DPDK_STATIC_LDFLAGS})

############
# duplicate_filter_test
############
add_executable(rcu_test EXCLUDE_FROM_ALL rcu_test.c)
add_test(NAME rcu_test COMMAND rcu_test --no-huge)
# DPDK
add_definitions(${DPDK_STATIC_CFLAGS}) # TODO: target
target_include_directories(rcu_test PRIVATE ${DPDK_SATIC_INCLUDE_DIRS})
target_link_libraries(rcu_test PRIVATE ${DPDK_STATIC_LDFLAGS})

############
# keymanager_test
############
add_executable(keymanager_test EXCLUDE_FROM_ALL keymanager_test.c)
add_test(NAME keymanager_test COMMAND keymanager_test --no-huge)
# Dependencies
target_sources(keymanager_test PRIVATE log_mock.c)
target_sources(keymanager_test PRIVATE ../mock/drkey_fetcher_mock.c ../keyfetcher.c ../keymanager.c ../lib/crypto/crypto.c ../config.c ../lib/ipc/ipc.c)
# DPDK
add_definitions(${DPDK_STATIC_CFLAGS}) # TODO: target
target_include_directories(keymanager_test PRIVATE ${DPDK_SATIC_INCLUDE_DIRS})
target_link_libraries(keymanager_test PRIVATE ${DPDK_STATIC_LDFLAGS})
# Include JSON Parser
target_link_libraries(keymanager_test PRIVATE jsonparser)
# Crypto
target_link_libraries(keymanager_test  PRIVATE OpenSSL::SSL)
if(LF_CBCMAC STREQUAL "AESNI")
    target_link_libraries(keymanager_test  PRIVATE aesni)
endif()

# Copy configuration file to the build directory
add_custom_target(keymanager_test_file
    ${CMAKE_COMMAND} -E
    copy_if_different
    ${CMAKE_CURRENT_LIST_DIR}/keymanager_test1.json
    ${CMAKE_CURRENT_LIST_DIR}/keymanager_test2.json
    ${CMAKE_CURRENT_LIST_DIR}/keymanager_test3.json
    ${CMAKE_CURRENT_BINARY_DIR}/
)
add_dependencies(keymanager_test keymanager_test_file)

############
# ratelimiter_test
############
add_executable(ratelimiter_test EXCLUDE_FROM_ALL ratelimiter_test.c)
add_test(NAME ratelimiter_test COMMAND ratelimiter_test --no-huge)
# Dependencies
target_sources(ratelimiter_test PRIVATE log_mock.c)
target_sources(ratelimiter_test PRIVATE ../ratelimiter.c ../config.c ../lib/ipc/ipc.c)
# DPDK
add_definitions(${DPDK_STATIC_CFLAGS}) # TODO: target
target_include_directories(ratelimiter_test PRIVATE ${DPDK_SATIC_INCLUDE_DIRS})
target_link_libraries(ratelimiter_test PRIVATE ${DPDK_STATIC_LDFLAGS})
# Include JSON Parser
target_link_libraries(ratelimiter_test PRIVATE jsonparser)
# Copy configuration file to the build directory
add_custom_target(ratelimiter_test_file
    ${CMAKE_COMMAND} -E
    copy_if_different
    ${CMAKE_CURRENT_LIST_DIR}/ratelimiter_test1.json
    ${CMAKE_CURRENT_BINARY_DIR}/
)
add_dependencies(ratelimiter_test ratelimiter_test_file)

# Add the tests to the global build_test target.
add_dependencies(build_tests config_parser_test duplicate_filter_test rcu_test keymanager_test ratelimiter_test)