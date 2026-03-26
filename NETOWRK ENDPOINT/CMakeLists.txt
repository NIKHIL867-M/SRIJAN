cmake_minimum_required(VERSION 3.20)

project(TITAN VERSION 4.0 LANGUAGES CXX)

# ============================================================================
# COMPILER / STANDARD
# ============================================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# MSVC-ONLY GUARD
# ============================================================================
if(NOT MSVC)
    message(FATAL_ERROR "TITAN V4 requires MSVC (cl.exe).")
endif()

# ============================================================================
# WINDOWS TARGET: Windows 10+
# ============================================================================
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    NTDDI_VERSION=0x0A000000
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

# ============================================================================
# MSVC FLAGS  — all C4244/C4267 are fixed in source; no suppression needed
# ============================================================================
add_compile_options(
    /W4
    /WX
    /permissive-
    /Zc:__cplusplus
    /utf-8
    /EHsc
    /MP
    /sdl            # SDL security checks
    /GS             # Buffer security checks — retained in all configs (security agent)
    /wd4100         # Unreferenced formal parameter — common in callback stubs
    /wd4505         # Unreferenced local function — common in header-only helpers
    /wd4244         # Narrowing conversion in STL hash internals (xutility)
    /wd4267         # size_t->ULONG narrowing in older SDK headers
)

# Per-config overrides — one flag per generator expression (MSVC requires this)
add_compile_options(
    $<$<CONFIG:Debug>:/Od>
    $<$<CONFIG:Debug>:/RTC1>
    $<$<CONFIG:Debug>:/MDd>
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/GL>
    $<$<CONFIG:Release>:/Oi>
    $<$<CONFIG:Release>:/MD>
)

# ============================================================================
# NPCAP SDK — OPTIONAL
# ============================================================================
if(NOT DEFINED NPCAP_SDK_DIR)
    if(DEFINED ENV{NPCAP_SDK_DIR})
        set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
    elseif(EXISTS "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.16/Include/pcap.h")
        set(NPCAP_SDK_DIR "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.16")
    elseif(EXISTS "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.13/Include/pcap.h")
        set(NPCAP_SDK_DIR "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.13")
    elseif(EXISTS "C:/npcap-sdk/Include/pcap.h")
        set(NPCAP_SDK_DIR "C:/npcap-sdk")
    else()
        set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/npcap-sdk")
    endif()
endif()

set(TITAN_HAS_NPCAP FALSE)
if(EXISTS "${NPCAP_SDK_DIR}/Include/pcap.h")
    set(TITAN_HAS_NPCAP TRUE)
    message(STATUS "Npcap SDK found: ${NPCAP_SDK_DIR}")
else()
    message(FATAL_ERROR "Npcap SDK not found.\nTITAN V4 is a network endpoint and requires Npcap SDK.\nSet NPCAP_SDK_DIR or install the SDK to one of the auto-detected locations.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")
else()
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib")
endif()


# ============================================================================
# SOURCE FILES
# ============================================================================
set(TITAN_SOURCES
    main.cpp
    agent.cpp
    event.cpp
    filter.cpp
    logger.cpp
    network_monitor.cpp
    network_capture.cpp
)

set(TITAN_HEADERS
    agent.h
    event.h
    filter.h
    logger.h
    network_monitor.h
    network_capture.h
    network_types.h
)


# ============================================================================
# EXECUTABLE
# ============================================================================
add_executable(titan ${TITAN_SOURCES} ${TITAN_HEADERS})

# ============================================================================
# INCLUDE DIRS
# ============================================================================
target_include_directories(titan PRIVATE ${CMAKE_SOURCE_DIR})

# Npcap is required for this network endpoint
target_include_directories(titan PRIVATE "${NPCAP_SDK_DIR}/Include")
target_link_directories(titan PRIVATE "${NPCAP_LIB_DIR}")

# ============================================================================
# LINK LIBRARIES
# ============================================================================
target_link_libraries(titan PRIVATE
    ntdll
    advapi32
    secur32
    wintrust
    crypt32
    bcrypt
    normaliz
    tdh             # ETW trace decode helpers (TdhGetEventInformation etc.)
    iphlpapi        # GetExtendedTcpTable / GetExtendedUdpTable / GetAdaptersAddresses
    ws2_32          # Winsock2
    dnsapi          # DnsQuery (PTR lookups)
    pathcch         # PathCchCanonicalize
    psapi           # GetProcessImageFileNameW
)

# Npcap required
target_link_libraries(titan PRIVATE wpcap Packet)

# ============================================================================
# SUBSYSTEM: Console + UAC manifest
# ============================================================================
set_target_properties(titan PROPERTIES WIN32_EXECUTABLE FALSE)

# UAC elevation manifest — requireAdministrator
# Write the flag inline. Using a CMake variable here causes VS to crash
# with 'Value cannot be null / Parameter name: key'.
target_link_options(titan PRIVATE
    "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
)

install(TARGETS titan DESTINATION bin)