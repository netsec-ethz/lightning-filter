cmake_minimum_required(VERSION 3.20)

# Include JSON Parser
add_library(jsonparser STATIC json.c)
target_compile_definitions(jsonparser PUBLIC JSON_TRACK_SOURCE)