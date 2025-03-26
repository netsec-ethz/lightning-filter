# Plugins
set(LF_PLUGINS "" CACHE STRING "List of enabled plugins seperated by ; (e.g., \"wg_ratelimiter;host_ratelimiter\").")

# Provide the list of plugins as a string with all plugins
# separated by a white space to the compiler
string(REPLACE ";" " " LF_PLUGINS_STRING "${LF_PLUGINS}")
add_compile_definitions(LF_PLUGINS="${LF_PLUGINS_STRING}")


message( STATUS ${LF_PLUGINS_STRING})

if ("wg_ratelimiter" IN_LIST LF_PLUGINS)
    message( STATUS "Plugin WireGuard Ratelimiter enabled")
    add_compile_definitions(LF_PLUGIN_WG_RATELIMITER=1)
    target_sources(${EXEC} PRIVATE plugins/wg_ratelimiter.c)
else()
    add_compile_definitions(LF_PLUGIN_WG_RATELIMITER=0)
endif()

if ("dst_ratelimiter" IN_LIST LF_PLUGINS)
    message( STATUS "Plugin Destination Ratelimiter enabled")
    add_compile_definitions(LF_PLUGIN_DST_RATELIMITER=1)
    target_sources(${EXEC} PRIVATE plugins/dst_ratelimiter.c)
else()
    add_compile_definitions(LF_PLUGIN_DST_RATELIMITER=0)
endif()
