// usb_identity.h
#pragma once

#include <string>
#include <vector>
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
// UsbIdentity
//
// Resolved identity of a single USB device.  Populated by
// ResolveDeviceIdentity() while the device is still attached.
// ─────────────────────────────────────────────────────────────────────────────
struct UsbIdentity {
    std::string vid;           // Vendor  ID — 4-char hex, e.g. "0781"
    std::string pid;           // Product ID — 4-char hex, e.g. "5567"
    std::string serialNumber;  // USB serial number (empty if device has none)
    std::string manufacturer;  // Manufacturer string from device
    std::string product;       // Product / friendly name
    std::string instanceId;    // PnP instance ID, e.g. "USB\VID_0781&PID_5567\..."
    std::string devicePath;    // Device interface path from WM_DEVICECHANGE

    bool        hasSerial()  const { return !serialNumber.empty(); }
    std::string hardwareId() const { return vid + ":" + pid; }
};

// ─────────────────────────────────────────────────────────────────────────────
// ResolveDeviceIdentity
//
// Fills identity from a device interface path (as received in the
// DBT_DEVICEARRIVAL notification).  Must be called while the device is still
// attached.  Returns true on success.
// ─────────────────────────────────────────────────────────────────────────────
bool ResolveDeviceIdentity(const std::string& devicePath, UsbIdentity& identity);

// ─────────────────────────────────────────────────────────────────────────────
// IsStorageDevice
//
// Returns true if the device is a USB mass-storage device (flash drive,
// external HDD, card reader).  Keyboards, mice, hubs, audio, etc. return false.
// ─────────────────────────────────────────────────────────────────────────────
bool IsStorageDevice(const UsbIdentity& identity);

// ─────────────────────────────────────────────────────────────────────────────
// GetMountPointsForDevice
//
// Finds drive letter roots (e.g. "E:\\") associated with the device identified
// by devicePath.  Uses the PnP parent chain to match the correct volume even
// when multiple USB drives are attached simultaneously.
// Returns true if at least one mount point is found.
// ─────────────────────────────────────────────────────────────────────────────
bool GetMountPointsForDevice(const std::string& devicePath,
    std::vector<std::string>& mountPoints);