#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// TITAN — Precompiled header / universal preamble
// Every .h and .cpp in this module must include this FIRST, before anything
// else. This guarantees the Windows SDK macros are set before any SDK header
// is ever seen by the compiler, in every translation unit.
// ═══════════════════════════════════════════════════════════════════════════

#include <sdkddkver.h>  // Must be first — pins _WIN32_WINNT etc.

// ── Windows SDK control macros ────────────────────────────────────────────────
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN     // Exclude rarely-used Windows headers
#endif
#ifndef NOMINMAX
#define NOMINMAX                // Prevent windows.h min/max macros
#endif
#ifndef UNICODE
#define UNICODE                 // Use wide-char Windows APIs
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00     // Windows 10+
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

// ── Core Windows header — always first after macros ───────────────────────────
#include <windows.h>

// ── STL headers used across the whole module ─────────────────────────────────
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <cstring>