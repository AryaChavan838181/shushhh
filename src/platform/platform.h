#pragma once

#include <string>
#include <vector>

// ============================================================
// Platform Abstraction Layer
// ============================================================
// Provides OS-agnostic interfaces for Tor management, process
// launching, and filesystem queries. Implementations live in
// platform_win32.cpp and platform_linux.cpp.

/// Check whether Tor is already listening on 127.0.0.1:9050.
bool platform_is_tor_running();

/// Return the directory that contains the currently running executable.
/// e.g. "E:\\" on Windows USB, "/media/user/USB" on Linux.
std::string platform_get_exe_dir();

/// Return the system temporary directory path (no trailing separator).
/// e.g. "C:\\Users\\X\\AppData\\Local\\Temp" or "/tmp".
std::string platform_get_temp_dir();

/// Attempt to launch Tor as a hidden/background process.
/// Searches for tor binary relative to exe_dir, sets up DataDirectory
/// in temp, and provides GeoIP paths if available.
/// Returns true if Tor was successfully started.
bool platform_launch_tor(const std::string& exe_dir);
