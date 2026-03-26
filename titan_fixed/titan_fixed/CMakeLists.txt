cmake_minimum_required(VERSION 3.20)

project(TitanProcess
    VERSION     3.0.0
    DESCRIPTION "TITAN V3 — Process ETW monitor, signal amplifier, noise suppressor"
    LANGUAGES   CXX
)

# ── C++ standard ─────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ── Windows target ────────────────────────────────────────────────────────────
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

# ── Source files ──────────────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    agent.cpp
    event.cpp
    filter.cpp
    logger.cpp
    process_monitor.cpp
)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(titan_process ${SOURCES})

# ── Include paths ─────────────────────────────────────────────────────────────
target_include_directories(titan_process PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# ── Linked libraries ──────────────────────────────────────────────────────────
target_link_libraries(titan_process PRIVATE
    advapi32        # Token/SID: OpenProcessToken, LookupAccountSidW, etc.
    bcrypt          # BCrypt SHA-256 (fingerprint + bloom keys)
    crypt32         # CryptQueryObject, Authenticode cert extraction
    wintrust        # WinVerifyTrust — signature verification
    normaliz        # NormalizeString — Unicode NFC
    kernel32        # Standard Win32 runtime
    ntdll           # NtQueryInformationProcess (via GetProcAddress)
    tdh             # ETW decoding helpers
    secur32         # Secure32
    user32          # Win32 message/window support
    ole32           # CoCreateGuid
)

# ── Compiler warnings & hardening ─────────────────────────────────────────────
if(MSVC)
    target_compile_options(titan_process PRIVATE
        /W4
        /WX
        /permissive-
        /Zc:__cplusplus
        /w44388
        /w44302
        /wd4068
        /wd4996 
        /wd4244# Suppress CRT deprecation (gmtime, etc.)
        /sdl
    )

    # Debug
    target_compile_options(titan_process PRIVATE
        $<$<CONFIG:Debug>:/Od /RTC1 /MDd>
    )

    # Release — /GS retained deliberately (security agent, no /GS-)
    target_compile_options(titan_process PRIVATE
        $<$<CONFIG:Release>:/O2 /GL /Oi /GS>
    )
    target_link_options(titan_process PRIVATE
        $<$<CONFIG:Release>:/LTCG>
    )

    string(REPLACE "/W3" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif()

# ── Output directories ────────────────────────────────────────────────────────
set_target_properties(titan_process PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"
)

# ── Create runtime directories at configure time ──────────────────────────────
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/logs")
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/data")   # Bloom filter persistence

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS titan_process RUNTIME DESTINATION bin)

# ── Summary ───────────────────────────────────────────────────────────────────
message(STATUS "---------------------------------------------------")
message(STATUS "  Project : ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  C++     : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build   : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Output  : ${CMAKE_BINARY_DIR}/bin")
message(STATUS "  Logs    : ${CMAKE_BINARY_DIR}/logs")
message(STATUS "  Data    : ${CMAKE_BINARY_DIR}/data  (bloom filters)")
message(STATUS "---------------------------------------------------")