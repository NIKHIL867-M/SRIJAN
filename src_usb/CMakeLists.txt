cmake_minimum_required(VERSION 3.20)

project(TitanUSB
    VERSION     1.0.0
    DESCRIPTION "USB device monitoring and session logging agent"
    LANGUAGES   CXX
)

# ── C++ standard ─────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)   # Enforce pure ISO C++20; no GNU extensions

# ── Windows target ────────────────────────────────────────────────────────────
# Require Windows 10 (0x0A00). Silences GetVersionEx deprecation and enables
# modern Win32 APIs (RtlGetVersion, newer SetupDi functions, etc.).
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    WIN32_LEAN_AND_MEAN         # Exclude rarely-used Windows headers
    NOMINMAX                    # Prevent windows.h from defining min/max macros
    UNICODE                     # Use Unicode Win32 APIs by default
    _UNICODE
)

# ── Source files ──────────────────────────────────────────────────────────────
set(SOURCES
    src_usb/test_main.cpp
    src_usb/usb_monitor.cpp
    src_usb/usb_kernel_listener.cpp
    src_usb/usb_identity.cpp
    src_usb/usb_session.cpp
    src_usb/usb_session_manager.cpp
    src_usb/usb_logger.cpp
    src_usb/usb_watcher.cpp
)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(usb_test ${SOURCES})

# ── Include paths ─────────────────────────────────────────────────────────────
target_include_directories(usb_test PRIVATE src_usb)

# ── Linked libraries ──────────────────────────────────────────────────────────
target_link_libraries(usb_test PRIVATE
    setupapi     # SetupDiGetClassDevs, SetupDiGetDeviceRegistryProperty, etc.
    advapi32     # Registry access
    ole32        # CoCreateGuid
    user32       # RegisterDeviceNotification, PostMessage
    kernel32     # Standard Win32 runtime
    cfgmgr32     # CM_Get_Device_IDA, CM_Get_Parent
)

# ── Compiler warnings & hardening ─────────────────────────────────────────────
if(MSVC)
    target_compile_options(usb_test PRIVATE
        /W4             # Maximum practical warning level
        /WX             # Treat all warnings as errors — keeps the build clean
        /permissive-    # Strict ISO C++ conformance; no MSVC-only extensions
        /Zc:__cplusplus # Report __cplusplus correctly (needed for C++20 detection)

        # Extra warnings not enabled by /W4:
        /w44388         # Signed/unsigned mismatch
        /w44302         # Truncation from pointer to smaller integer type
        /wd4068         # Suppress unknown-pragma warnings from third-party headers

        # SDL checks — additional security-relevant diagnostics
        /sdl
    )

    # ── Debug: no optimisation, full runtime checks, debug CRT ───────────────
    target_compile_options(usb_test PRIVATE
        $<$<CONFIG:Debug>:/Od /RTC1 /MDd>
    )

    # ── Release: speed, whole-program optimisation ────────────────────────────
    # FIX: Removed /GS- from Release flags.
    #   /GS- disables buffer-security checks — a deliberate security regression
    #   that was present in the original CMakeLists.  The performance impact of
    #   /GS is negligible (<1%) and the protection it provides (stack cookie
    #   checks, /sdl-enhanced pointer validation) is essential for a security
    #   agent.  /GS is the default and is retained here explicitly for clarity.
    target_compile_options(usb_test PRIVATE
        $<$<CONFIG:Release>:/O2 /GL /Oi /GS>
    )
    target_link_options(usb_test PRIVATE
        $<$<CONFIG:Release>:/LTCG>   # Link-time code generation (pairs with /GL)
    )

    # Suppress the /W3 vs /W4 override noise — CMake injects /W3 by default;
    # removing it prevents the "overriding /W3 with /W4" warning.
    string(REPLACE "/W3" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif()

# ── Output directories ────────────────────────────────────────────────────────
set_target_properties(usb_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"   # Debug symbols alongside exe
)

# ── Create log directory at configure time ────────────────────────────────────
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/logs")

# ── Install rules ─────────────────────────────────────────────────────────────
install(TARGETS usb_test RUNTIME DESTINATION bin)

# ── Configuration summary ─────────────────────────────────────────────────────
message(STATUS "---------------------------------------------------")
message(STATUS "  Project : ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  C++     : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build   : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Output  : ${CMAKE_BINARY_DIR}/bin")
message(STATUS "  Logs    : ${CMAKE_BINARY_DIR}/logs")
message(STATUS "---------------------------------------------------")