cmake_minimum_required(VERSION 3.20)

set(LF_LOG_DP_LEVEL "WARNING" CACHE STRING "Minimal log level for data path logs (MIN, ... , WARNING, ... , DEBUG, MAX")
add_compile_definitions(LF_LOG_DP_LEVEL=LF_LOG_${LF_LOG_DP_LEVEL})

set(LF_WORKER "SCION" CACHE STRING "The worker type (SCION, IPV4, FWD).")
if(LF_WORKER STREQUAL "SCION")
    target_sources(${EXEC}  PRIVATE worker_scion.c)
    target_sources(${EXEC} PRIVATE lib/scion/scion.c)
elseif(LF_WORKER STREQUAL "IPV4")
    target_sources(${EXEC}  PRIVATE worker_ip.c)
elseif(LF_WORKER STREQUAL "FWD")
    target_sources(${EXEC}  PRIVATE mock/worker_fwd.c)
else()
    message( FATAL_ERROR "Unknown WORKER parameter: ${LF_WORKER}" )
endif()
add_compile_definitions(LF_WORKER=${LF_WORKER})
add_compile_definitions(LF_WORKER_${LF_WORKER}=1)

set(LF_DRKEY_FETCHER "SCION" CACHE STRING "The drkey fetcher type (SCION, MOCK).")
if(LF_DRKEY_FETCHER STREQUAL "SCION")
    # add SCION DRKey fetcher implementation
    target_sources(${EXEC}  PRIVATE drkey_fetcher_scion.c)
    # link the golang SCION DRKey fetcher library
    add_subdirectory(lib/scion_drkey/)
    target_link_libraries(${EXEC} PRIVATE drkey pthread)
    # and include the generated header files
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
elseif(LF_DRKEY_FETCHER STREQUAL "MOCK")
    target_sources(${EXEC}  PRIVATE mock/drkey_fetcher_mock.c)
else()
    message( FATAL_ERROR "Unknown LF_DRKEY_FETCHER parameter: ${LF_DRKEY_FETCHER}" )
endif()
add_compile_definitions(LF_DRKEY_FETCHER=${LF_DRKEY_FETCHER})
add_compile_definitions(LF_DRKEY_FETCHER_${LF_DRKEY_FETCHER}=1)

set(LF_CBCMAC "OPENSSL" CACHE STRING "CBC MAC implementation (OPENSSL, AESNI). AESNI requires hardware support.")
if(LF_CBCMAC STREQUAL "AESNI")
    add_subdirectory(lib/aesni/)
    target_link_libraries(${EXEC}  PRIVATE aesni)
elseif(LF_CBCMAC STREQUAL "OPENSSL")
    target_link_libraries(${EXEC}  PRIVATE OpenSSL::SSL)
else()
    message( FATAL_ERROR "Unknown LF_CBCMAC parameter: ${LF_CBCMAC}" )
endif()
add_compile_definitions(LF_CBCMAC=${LF_CBCMAC})
add_compile_definitions(LF_CBCMAC_${LF_CBCMAC}=1)

# Add CMake option which is translated into a compiler flag (default: ON or OFF).
function(option_compile_definition flag help default )
    option(${flag} ${help} ${default})
    if(${flag})
        SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -D${flag}=1" PARENT_SCOPE)
        #add_compile_definitions(${flag}=1)
        # This function does not seem to work inside a function.
    else()
        SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -D${flag}=0" PARENT_SCOPE)
        #add_compile_definitions(${flag}=0)
        # This function does not seem to work inside a function.
    endif()
endfunction()

option_compile_definition(LF_PDUMP "Enable packet capture framework" OFF)

option_compile_definition(LF_IPV6 "Use IPv6 (ON, OFF)" OFF)
option_compile_definition(LF_OFFLOAD_CKSUM "Offload checksum calculation to NIC (ON, OFF)" ON)
option_compile_definition(LF_JUMBO_FRAME "Enable jumbo frame support (ON, OFF)" OFF)

# Options to omit actions
option_compile_definition(LF_WORKER_OMIT_TIME_UPDATE "Omit time update for workers (OFF, ON)" OFF)
option_compile_definition(LF_WORKER_OMIT_KEY_GET "Omit key fetching for workers (OFF, ON)" OFF)
option_compile_definition(LF_WORKER_OMIT_DECAPSULATION "Omit decapsulation (OFF, ON)" OFF)

# Options to omit core checks
option_compile_definition(LF_WORKER_OMIT_HASH_CHECK "Omit hash check (OFF, ON)" OFF)
option_compile_definition(LF_WORKER_OMIT_MAC_CHECK "Omit mac check (OFF, ON)" OFF)
option_compile_definition(LF_WORKER_OMIT_TIMESTAMP_CHECK "Omit timestamp check (OFF, ON)" OFF)
option_compile_definition(LF_WORKER_OMIT_DUPLICATE_CHECK "Omit duplicate check (OFF, ON)" OFF)
option_compile_definition(LF_WORKER_OMIT_RATELIMIT_CHECK "Omit ratelimiter check (OFF, ON)" OFF)

# Option to ignore check results
option(LF_WORKER_IGNORE_CHECKS "Ignore check results (but still perform all checks)" OFF)
if(LF_WORKER_IGNORE_CHECKS)
    set(LF_WORKER_IGNORE_MAC_CHECK ON)
    set(LF_WORKER_IGNORE_TIMESTAMP_CHECK ON)
    set(LF_WORKER_IGNORE_DUPLICATE_CHECK ON)
    set(LF_WORKER_IGNORE_HASH_CHECK ON)
    set(LF_WORKER_IGNORE_PATH_TIMESTAMP_CHECK ON)
    set(LF_WORKER_IGNORE_KEY_VALIDITY_CHECK ON)
endif()

option_compile_definition(LF_WORKER_IGNORE_MAC_CHECK "Ignore MAC check result" OFF)
option_compile_definition(LF_WORKER_IGNORE_TIMESTAMP_CHECK "Ignore timestamp check result" OFF)
option_compile_definition(LF_WORKER_IGNORE_DUPLICATE_CHECK "Ignore duplicate check result" OFF)
option_compile_definition(LF_WORKER_IGNORE_HASH_CHECK "Ignore hash check result" OFF)
option_compile_definition(LF_WORKER_IGNORE_PATH_TIMESTAMP_CHECK "Ignore path timestamp check result" OFF)
option_compile_definition(LF_WORKER_IGNORE_KEY_VALIDITY_CHECK "Ignore the validity of the key and just use it" OFF)

# Compiler Options
option(NO_UNUSED "Disable compiler warnings for unused variables" OFF)
if(NO_UNUSED)
    target_compile_options(${EXEC} PRIVATE -Wno-unused)
endif()