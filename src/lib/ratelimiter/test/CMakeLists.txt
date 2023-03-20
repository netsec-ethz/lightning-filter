cmake_minimum_required(VERSION 3.20)

enable_testing()

############
# token_bucket_test
############
add_executable(token_bucket_test EXCLUDE_FROM_ALL token_bucket_test.c)
add_test(NAME token_bucket_test COMMAND token_bucket_test)

add_dependencies(build_tests token_bucket_test)
