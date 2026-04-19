#pragma once

#include <string>

// ============================================================
// F-11 · Watchdog auto-wipe
// ============================================================
// On pendrive insertion, shushhh writes a wipe script to %TEMP%
// and launches a detached sentinel process that polls for USB
// disconnection. When the pendrive is removed, the sentinel
// executes the wipe and self-deletes.

// Detect the drive letter of the USB drive shushhh is running from.
// Returns the drive letter (e.g., 'E') or '\0' if detection fails.
char detect_usb_drive();

// Launch the watchdog sentinel process.
// Creates shushhh_wipe.bat in %TEMP% and starts monitoring the given drive.
// The watchdog survives even if shushhh.exe is closed or killed.
// Returns true if the watchdog was launched successfully.
bool launch_watchdog(char drive_letter);

// Write the wipe batch script to %TEMP%.
// Called internally by launch_watchdog().
bool write_wipe_script(const std::string& temp_dir);
