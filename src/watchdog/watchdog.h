#pragma once

#include <string>

// ============================================================
// F-11 · Watchdog auto-wipe
// ============================================================
// On pendrive insertion, shushhh writes a wipe script to the system
// temp directory and launches a detached sentinel thread that polls
// for USB disconnection. When the pendrive is removed, the sentinel
// executes the wipe and self-deletes.

// Detect the USB drive / mount point shushhh is running from.
// Returns:
//   Windows: drive letter as string, e.g. "E"
//   Linux:   mount path, e.g. "/media/user/USBDRIVE"
//   Empty string if detection fails or not running from removable media.
std::string detect_usb_drive();

// Launch the watchdog sentinel thread.
// Creates a wipe script in the system temp directory and starts
// monitoring the given drive/mount for removal.
// Returns true if the watchdog was launched successfully.
bool launch_watchdog(const std::string& drive_or_mount);

// Write the platform-appropriate wipe script to the temp directory.
// Called internally by launch_watchdog().
bool write_wipe_script(const std::string& temp_dir);
