// usb_identity.cpp
#include "usb_identity.h"

#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#   define NOMINMAX
#endif

#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

static void LogError(const std::string& msg) {
    std::cerr << "[UsbIdentity] ERROR: " << msg << '\n';
}

static std::string WideToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.data(),
        static_cast<int>(wstr.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
        &result[0], size, nullptr, nullptr);
    return result;
}

static std::string NarrowToUTF8(const std::string& narrow) {
    if (narrow.empty()) return {};
    int size = MultiByteToWideChar(CP_ACP, 0, narrow.c_str(), -1, nullptr, 0);
    if (size <= 0) return {};
    std::wstring wstr(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_ACP, 0, narrow.c_str(), -1, &wstr[0], size);
    return WideToUTF8(wstr);
}

// Read a REG_SZ or REG_MULTI_SZ device property into outValue.
static bool GetDeviceProperty(HDEVINFO devInfo, PSP_DEVINFO_DATA devInfoData,
    DWORD property, std::string& outValue)
{
    DWORD dataType = 0;
    char  buffer[1024] = {};
    DWORD bufferSize = sizeof(buffer);

    if (!SetupDiGetDeviceRegistryPropertyA(devInfo, devInfoData, property,
        &dataType,
        reinterpret_cast<PBYTE>(buffer),
        bufferSize, &bufferSize))
        return false;

    if (dataType != REG_SZ && dataType != REG_MULTI_SZ) return false;
    outValue = NarrowToUTF8(buffer);
    return true;
}

// Resolve a device interface path to its PnP instance ID.
static bool GetDeviceInstanceId(const std::string& devicePath,
    std::string& instanceId)
{
    HDEVINFO devInfo = SetupDiGetClassDevsA(nullptr, nullptr, nullptr,
        DIGCF_DEVICEINTERFACE | DIGCF_ALLCLASSES);
    if (devInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVICE_INTERFACE_DATA interfaceData = { sizeof(SP_DEVICE_INTERFACE_DATA) };
    if (!SetupDiOpenDeviceInterfaceA(devInfo, devicePath.c_str(), 0, &interfaceData)) {
        SetupDiDestroyDeviceInfoList(devInfo);
        return false;
    }

    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailA(devInfo, &interfaceData,
        nullptr, 0, &requiredSize, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        SetupDiDestroyDeviceInfoList(devInfo);
        return false;
    }

    std::vector<char> buffer(static_cast<size_t>(requiredSize), '\0');
    auto detailData = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_A>(buffer.data());
    detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    if (!SetupDiGetDeviceInterfaceDetailA(devInfo, &interfaceData,
        detailData, requiredSize,
        &requiredSize, &devInfoData))
    {
        SetupDiDestroyDeviceInfoList(devInfo);
        return false;
    }

    char buf[256] = {};
    if (CM_Get_Device_IDA(devInfoData.DevInst, buf, sizeof(buf), 0) != CR_SUCCESS) {
        SetupDiDestroyDeviceInfoList(devInfo);
        return false;
    }

    instanceId = buf;
    SetupDiDestroyDeviceInfoList(devInfo);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolveDeviceIdentity
// ─────────────────────────────────────────────────────────────────────────────
bool ResolveDeviceIdentity(const std::string& devicePath, UsbIdentity& identity)
{
    identity = UsbIdentity{};
    identity.devicePath = devicePath;

    std::string instanceId;
    if (!GetDeviceInstanceId(devicePath, instanceId)) {
        LogError("Failed to get instance ID from: " + devicePath);
        return false;
    }
    identity.instanceId = instanceId;

    HDEVINFO devInfo = SetupDiCreateDeviceInfoList(nullptr, nullptr);
    if (devInfo == INVALID_HANDLE_VALUE) {
        LogError("SetupDiCreateDeviceInfoList failed");
        return false;
    }

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    if (!SetupDiOpenDeviceInfoA(devInfo, instanceId.c_str(),
        nullptr, 0, &devInfoData))
    {
        LogError("SetupDiOpenDeviceInfoA failed for: " + instanceId);
        SetupDiDestroyDeviceInfoList(devInfo);
        return false;
    }

    // ── VID / PID from hardware IDs ───────────────────────────────────────
    auto extractVidPid = [](const std::string& ids,
        std::string& vid, std::string& pid)
        {
            auto extract = [&](const std::string& prefix, std::string& out) {
                size_t pos = ids.find(prefix);
                if (pos != std::string::npos && pos + prefix.size() + 4 <= ids.size())
                    out = ids.substr(pos + prefix.size(), 4);
                };
            extract("VID_", vid);
            extract("PID_", pid);
        };

    std::string hardwareIds;
    if (GetDeviceProperty(devInfo, &devInfoData, SPDRP_HARDWAREID, hardwareIds))
        extractVidPid(hardwareIds, identity.vid, identity.pid);

    if (identity.vid.empty() || identity.pid.empty()) {
        std::string compatIds;
        if (GetDeviceProperty(devInfo, &devInfoData, SPDRP_COMPATIBLEIDS, compatIds))
            extractVidPid(compatIds, identity.vid, identity.pid);
    }

    // ── Friendly strings ──────────────────────────────────────────────────
    GetDeviceProperty(devInfo, &devInfoData, SPDRP_MFG, identity.manufacturer);
    GetDeviceProperty(devInfo, &devInfoData, SPDRP_DEVICEDESC, identity.product);

    // ── Serial number from instance ID tail ───────────────────────────────
    // Instance ID format: "USB\VID_xxxx&PID_xxxx\<serial_or_composite>"
    //
    // Real serials: "4C530001211027116283", "AA00112233445566", "20190722"
    //   → no '&' character, length >= 4
    //
    // Composite (no serial) IDs: "5&2AD35BE9&0&1", "6&3A1B2C3D&0&2"
    //   → always contain '&'
    //
    // FIX: The previous code required pure hex [0-9A-Fa-f] chars, which
    //      incorrectly rejected legitimate serials containing letters like
    //      'G'-'Z' (e.g. SanDisk uses alphanumeric serials like "AA00112233").
    //      The ONLY reliable distinguisher between a real serial and a
    //      composite instance suffix is the presence of '&'.  We now accept
    //      any printable ASCII serial that does not contain '&'.
    size_t lastSlash = instanceId.find_last_of('\\');
    if (lastSlash != std::string::npos && lastSlash + 1 < instanceId.size()) {
        std::string candidate = instanceId.substr(lastSlash + 1);
        // Composite IDs always contain '&'; real serials never do.
        // Minimum length 4 guards against degenerate single-char suffixes.
        if (candidate.size() >= 4 && candidate.find('&') == std::string::npos) {
            identity.serialNumber = candidate;
        }
    }

    SetupDiDestroyDeviceInfoList(devInfo);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// IsStorageDevice
//
// Walks the PnP parent chain from the USB interface node upward until it
// finds a child device whose class is "DiskDrive", "CDROM", or "Volume".
// This correctly handles the case where WM_DEVICECHANGE fires on the USB
// interface node (class="USB") rather than directly on the storage child.
// ─────────────────────────────────────────────────────────────────────────────
bool IsStorageDevice(const UsbIdentity& identity)
{
    // Open the USB interface node first.
    HDEVINFO devInfo = SetupDiCreateDeviceInfoList(nullptr, nullptr);
    if (devInfo == INVALID_HANDLE_VALUE) {
        LogError("IsStorageDevice: SetupDiCreateDeviceInfoList failed");
        return false;
    }

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    if (!SetupDiOpenDeviceInfoA(devInfo, identity.instanceId.c_str(),
        nullptr, 0, &devInfoData))
    {
        LogError("IsStorageDevice: SetupDiOpenDeviceInfoA failed: " + identity.instanceId);
        SetupDiDestroyDeviceInfoList(devInfo);
        return false;
    }

    // Check this node's class first (handles the rare case where the event
    // fires directly on the DiskDrive node).
    char className[256] = {};
    DWORD sz = sizeof(className);
    if (SetupDiGetDeviceRegistryPropertyA(
        devInfo, &devInfoData, SPDRP_CLASS,
        nullptr, reinterpret_cast<PBYTE>(className), sz, &sz))
    {
        std::string cls = NarrowToUTF8(className);
        if (cls == "DiskDrive" || cls == "CDROM" || cls == "Volume") {
            SetupDiDestroyDeviceInfoList(devInfo);
            return true;
        }
    }

    // Walk child devices: enumerate all devices whose parent is this node
    // and check if any is a storage class device.
    DEVINST parentInst = devInfoData.DevInst;
    SetupDiDestroyDeviceInfoList(devInfo);

    // Enumerate children of this device instance via CM_ APIs.
    DEVINST childInst = 0;
    if (CM_Get_Child(&childInst, parentInst, 0) != CR_SUCCESS)
        return false;

    // Walk all siblings at this level.
    do {
        char childId[256] = {};
        if (CM_Get_Device_IDA(childInst, childId, sizeof(childId), 0) != CR_SUCCESS)
            continue;

        // Open the child in SetupDi to read its class property.
        HDEVINFO childDevInfo = SetupDiCreateDeviceInfoList(nullptr, nullptr);
        if (childDevInfo == INVALID_HANDLE_VALUE) continue;

        SP_DEVINFO_DATA childData = { sizeof(SP_DEVINFO_DATA) };
        if (SetupDiOpenDeviceInfoA(childDevInfo, childId, nullptr, 0, &childData)) {
            char childClass[256] = {};
            DWORD csz = sizeof(childClass);
            if (SetupDiGetDeviceRegistryPropertyA(
                childDevInfo, &childData, SPDRP_CLASS,
                nullptr, reinterpret_cast<PBYTE>(childClass), csz, &csz))
            {
                std::string cls = NarrowToUTF8(childClass);
                if (cls == "DiskDrive" || cls == "CDROM" || cls == "Volume") {
                    SetupDiDestroyDeviceInfoList(childDevInfo);
                    return true;
                }
            }
        }
        SetupDiDestroyDeviceInfoList(childDevInfo);

        DEVINST sibling = 0;
        if (CM_Get_Sibling(&sibling, childInst, 0) != CR_SUCCESS) break;
        childInst = sibling;

    } while (true);

    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// GetMountPointsForDevice
//
// Finds all drive-letter roots associated with the USB device identified by
// devicePath.  Walks the PnP parent chain of each mounted volume to confirm
// the volume belongs to this specific USB device.
//
// FIX 1 (preciseMatchUsed): The flag now tracks whether the SetupDi code path
//   successfully ran for at least one drive, not just whether a match was found.
//   This prevents the fallback from triggering on systems where the precise
//   path ran but simply found no removable drives (e.g. a webcam — correctly
//   returning empty rather than falling back to all removable drives).
//
// FIX 2 (DRIVE_FIXED): USB HDDs and some USB 3 flash drives enumerate as
//   DRIVE_FIXED rather than DRIVE_REMOVABLE.  We now check both.  The PnP
//   parent-chain walk confirms the volume is actually on our USB device, so
//   false-positives (internal SATA drives) are impossible.
// ─────────────────────────────────────────────────────────────────────────────
bool GetMountPointsForDevice(const std::string& devicePath,
    std::vector<std::string>& mountPoints)
{
    mountPoints.clear();

    std::string instanceId;
    if (!GetDeviceInstanceId(devicePath, instanceId)) {
        LogError("GetMountPoints: Failed to get instance ID: " + devicePath);
        return false;
    }

    // Upper-case the target instance ID for case-insensitive comparison.
    std::string instanceUpper = instanceId;
    for (char& c : instanceUpper)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    DWORD drives = GetLogicalDrives();

    // FIX: preciseMatchUsed now means "did we successfully attempt the
    // SetupDi-based matching for at least one candidate drive".  If the
    // precise path ran but found no match, we should NOT fall back to the
    // dumb "all removable drives" heuristic — that heuristic would assign
    // the wrong mount point (or return results for non-storage devices).
    bool preciseMatchAttempted = false;

    // Index into a compile-time string to get the drive letter without any
    // integer-promotion to int (avoids C4244 under /W4 /sdl /WX).
    static constexpr char kDriveLetters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (int idx = 0; idx < 26; ++idx, drives >>= 1) {
        if (!(drives & 1u)) continue;

        const char driveLetter = kDriveLetters[idx];
        std::string root = std::string(1, driveLetter) + ":\\";

        // FIX: Accept DRIVE_FIXED as well as DRIVE_REMOVABLE.
        // USB HDDs and certain USB flash drives report as DRIVE_FIXED.
        // The PnP parent-chain walk below confirms USB ownership, so
        // internal SATA drives (also DRIVE_FIXED) are correctly excluded.
        UINT driveType = GetDriveTypeA(root.c_str());
        if (driveType != DRIVE_REMOVABLE && driveType != DRIVE_FIXED) continue;

        // Skip the system drive explicitly — never a USB device.
        char sysDir[MAX_PATH] = {};
        GetSystemDirectoryA(sysDir, MAX_PATH);
        if (sysDir[0] != '\0' && driveLetter == sysDir[0]) continue;

        // Obtain the volume GUID path to open via SetupDi.
        char volumeGuid[MAX_PATH] = {};
        if (!GetVolumeNameForVolumeMountPointA(root.c_str(), volumeGuid, MAX_PATH))
            continue;

        // Open a temporary SetupDi handle covering all device interfaces so
        // we can look up the volume's PnP device instance.
        HDEVINFO volDevInfo = SetupDiGetClassDevsA(
            nullptr, nullptr, nullptr,
            DIGCF_DEVICEINTERFACE | DIGCF_ALLCLASSES);
        if (volDevInfo == INVALID_HANDLE_VALUE) continue;

        SP_DEVICE_INTERFACE_DATA ifData = { sizeof(SP_DEVICE_INTERFACE_DATA) };
        bool matched = false;

        if (SetupDiOpenDeviceInterfaceA(volDevInfo, volumeGuid, 0, &ifData)) {
            DWORD reqSize = 0;
            SetupDiGetDeviceInterfaceDetailA(volDevInfo, &ifData,
                nullptr, 0, &reqSize, nullptr);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<char> buf(static_cast<size_t>(reqSize), '\0');
                auto detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_A>(buf.data());
                detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);

                SP_DEVINFO_DATA volInfoData = { sizeof(SP_DEVINFO_DATA) };
                if (SetupDiGetDeviceInterfaceDetailA(volDevInfo, &ifData,
                    detail, reqSize, &reqSize, &volInfoData))
                {
                    // FIX: Mark that we successfully ran the precise path for
                    // this candidate drive.  Whether or not we find a match
                    // below, the fallback must NOT run — we know the answer.
                    preciseMatchAttempted = true;

                    // Walk up the PnP parent chain to find our USB device.
                    // Depth limit 8 covers: Volume → Disk → USB storage →
                    // USB hub → USB controller (typically 3-4 hops).
                    DEVINST current = volInfoData.DevInst;
                    for (int depth = 0; depth < 8 && !matched; ++depth) {
                        char nodeId[256] = {};
                        if (CM_Get_Device_IDA(current, nodeId,
                            sizeof(nodeId), 0) == CR_SUCCESS)
                        {
                            std::string nodeIdStr = nodeId;
                            for (char& ch : nodeIdStr)
                                ch = static_cast<char>(
                                    std::toupper(static_cast<unsigned char>(ch)));

                            if (nodeIdStr == instanceUpper)
                                matched = true;
                        }

                        if (!matched) {
                            DEVINST parent = 0;
                            if (CM_Get_Parent(&parent, current, 0) == CR_SUCCESS)
                                current = parent;
                            else
                                break;
                        }
                    }
                }
            }
        }

        SetupDiDestroyDeviceInfoList(volDevInfo);

        if (matched)
            mountPoints.push_back(root);
    }

    // Fallback: ONLY if the precise SetupDi path never ran at all (e.g. every
    // candidate volume GUID query failed at the OS level), fall back to the
    // simple "all removable drives" heuristic.
    //
    // Critically, we do NOT fall back when preciseMatchAttempted is true but
    // no match was found — that means the device genuinely has no drive letter
    // (webcam, keyboard, audio dongle, etc.) and we should return empty.
    if (mountPoints.empty() && !preciseMatchAttempted) {
        std::cerr << "[UsbIdentity] Precise mount-point matching could not run; "
            "falling back to all removable drives.\n";
        drives = GetLogicalDrives();
        for (int idx = 0; idx < 26; ++idx, drives >>= 1) {
            if (!(drives & 1u)) continue;
            const char driveLetter = kDriveLetters[idx];
            std::string root = std::string(1, driveLetter) + ":\\";
            if (GetDriveTypeA(root.c_str()) == DRIVE_REMOVABLE)
                mountPoints.push_back(root);
        }
    }

    return !mountPoints.empty();
}