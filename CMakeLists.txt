cmake_minimum_required(VERSION 3.20)
project(TitanAMSI VERSION 2.0.1 LANGUAGES CXX)

# =============================================================================
#  Compiler Settings
# =============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "TITAN AMSI Monitor only builds on Windows.")
endif()

# =============================================================================
#  Strip conflicting MSVC default flags injected by CMake's Debug/RelWithDebInfo
#  configurations.  CMake adds /Od (disable optimisation) and /RTC1 (run-time
#  checks) to the default Debug flags.  Both are incompatible with our /O2.
#  We surgically remove them from every per-config flag variable so there is no
#  conflict regardless of which -DCMAKE_BUILD_TYPE the user passes.
#
#  This must happen BEFORE any add_executable / target_compile_options call.
# =============================================================================
foreach(flag_var
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_MINSIZEREL)
    # Remove /Od  (disable optimisation — conflicts with /O2)
    string(REGEX REPLACE "/Od" "" ${flag_var} "${${flag_var}}")
    # Remove /RTC1 and /RTC<any-suffix>  (run-time checks — incompatible with /O2)
    string(REGEX REPLACE "/RTC[^ ]*" "" ${flag_var} "${${flag_var}}")
    # Collapse any double spaces left behind
    string(REGEX REPLACE "  +" " " ${flag_var} "${${flag_var}}")
endforeach()

# =============================================================================
#  Compile-time tunables  (override with -DAMSI_RING_SIZE=... etc.)
# =============================================================================
set(AMSI_RING_SIZE         "16777216"  CACHE STRING "Capture ring size in bytes (default 16 MB)")
set(AMSI_HASH_CACHE_CAP    "50000"     CACHE STRING "LRU hash cache capacity")
set(AMSI_LOG_FLUSH_MS      "100"       CACHE STRING "Logger flush interval in ms")
set(AMSI_MAX_SCRIPT_BYTES  "5242880"   CACHE STRING "Max raw script size captured (default 5 MB)")
set(AMSI_LOG_BUF_SIZE      "1048576"   CACHE STRING "Log double-buffer size per side (default 1 MB)")

# =============================================================================
#  Source Files
# =============================================================================
set(TITAN_SOURCES
    main.cpp
    capture.cpp
    condenser.cpp
    filter.cpp
    logger.cpp
)

set(TITAN_HEADERS
    titan_amsi.h
)

# =============================================================================
#  Main Executable
# =============================================================================
add_executable(titan_amsi ${TITAN_SOURCES} ${TITAN_HEADERS})

target_include_directories(titan_amsi PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(titan_amsi PRIVATE
    AMSI_RING_SIZE=${AMSI_RING_SIZE}
    AMSI_HASH_CACHE_CAP=${AMSI_HASH_CACHE_CAP}
    AMSI_LOG_FLUSH_MS=${AMSI_LOG_FLUSH_MS}
    AMSI_MAX_SCRIPT_BYTES=${AMSI_MAX_SCRIPT_BYTES}
    AMSI_LOG_BUF_SIZE=${AMSI_LOG_BUF_SIZE}
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00
    UNICODE
    _UNICODE
)

# =============================================================================
#  Compiler Flags
# =============================================================================
target_compile_options(titan_amsi PRIVATE
    /O2           # Full optimisation
    /W4           # Warning level 4
    /WX           # Warnings as errors
    /GS           # Buffer security checks
    /Gy           # Function-level linking
    /Oi           # Intrinsic functions
    /arch:AVX2    # AVX2 for xxHash SIMD benefit (remove if targeting older CPUs)
    /fp:fast      # Fast floating point
    /EHsc         # C++ exception handling
    /sdl          # Additional security checks (SDL)
    /permissive-  # Conformance mode: catches subtle UB earlier
)

# =============================================================================
#  Linker Flags + Required Windows Libraries
# =============================================================================
target_link_options(titan_amsi PRIVATE
    /LTCG
    /OPT:REF
    /OPT:ICF
    /SUBSYSTEM:CONSOLE
)

target_link_libraries(titan_amsi PRIVATE
    advapi32.lib
    tdh.lib
    psapi.lib
    shell32.lib
    ntdll.lib
)

# =============================================================================
#  Output Directories
# =============================================================================
set_target_properties(titan_amsi PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/pdb"
)

# =============================================================================
#  Post-Build: copy default config next to executable
# =============================================================================
add_custom_command(TARGET titan_amsi POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/titan_amsi_config.json"
        "$<TARGET_FILE_DIR:titan_amsi>/titan_amsi_config.json"
    COMMENT "Copying default config to output directory"
)

# =============================================================================
#  Install Rules
# =============================================================================
install(TARGETS titan_amsi RUNTIME DESTINATION bin)
install(FILES titan_amsi_config.json DESTINATION bin)

# =============================================================================
#  Build Summary
# =============================================================================
message(STATUS "")
message(STATUS "========== TITAN AMSI Monitor Build Config ==========")
message(STATUS "  Version         : ${PROJECT_VERSION}")
message(STATUS "  Ring size       : ${AMSI_RING_SIZE} bytes")
message(STATUS "  Hash cache      : ${AMSI_HASH_CACHE_CAP} entries")
message(STATUS "  Log flush       : ${AMSI_LOG_FLUSH_MS} ms")
message(STATUS "  Max script      : ${AMSI_MAX_SCRIPT_BYTES} bytes")
message(STATUS "  Output dir      : ${CMAKE_BINARY_DIR}/bin")
message(STATUS "======================================================")
message(STATUS "")