#include "watchdog/watchdog.h"

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>   // SHGetFolderPathA
#else
// Stub for non-Windows platforms — watchdog is Windows-specific
#endif

// ============================================================
// F-11 · Watchdog auto-wipe implementation
// ============================================================

#ifdef _WIN32

char detect_usb_drive() {
    // Get the path of the currently running executable
    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);

    // Extract drive letter (first character of the path)
    char drive_letter = exe_path[0];
    
    // Verify it's a removable drive (USB pendrive)
    char root_path[] = { drive_letter, ':', '\\', '\0' };
    UINT drive_type = GetDriveTypeA(root_path);

    if (drive_type == DRIVE_REMOVABLE) {
        std::cout << "[+] USB drive detected: " << drive_letter << ":\\\n";
        return drive_letter;
    }

    // If running from a fixed drive (during development), warn but continue
    std::cout << "[*] Running from non-removable drive " << drive_letter
              << ":\\ — watchdog will monitor this drive\n";
    return drive_letter;
}

bool write_wipe_script(const std::string& temp_dir) {
    std::string bat_path = temp_dir + "\\shushhh_wipe.bat";
    std::ofstream bat(bat_path);

    if (!bat.is_open()) {
        std::cerr << "[-] Failed to create wipe script at " << bat_path << "\n";
        return false;
    }

    // The wipe bat sequence:
    // 1. cipher /w overwrites free disk sectors so deleted files are unrecoverable
    // 2. del removes any shushhh-related temp files
    // 3. The script self-deletes at the end
    bat << "@echo off\n";
    bat << "echo [*] shushhh watchdog: USB disconnected — initiating wipe\n";
    bat << "\n";
    bat << ":: Overwrite free space sectors in %TEMP% to prevent forensic recovery\n";
    bat << "cipher /w:\"%TEMP%\" >nul 2>&1\n";
    bat << "\n";
    bat << ":: Delete all shushhh-related temporary files\n";
    bat << "del /f /q \"%TEMP%\\shushhh_*\" >nul 2>&1\n";
    bat << "del /f /q \"%APPDATA%\\shushhh_*\" >nul 2>&1\n";
    bat << "\n";
    bat << ":: Self-delete this script\n";
    bat << "del /f /q \"%~f0\" >nul 2>&1\n";

    bat.close();
    return true;
}

// Watchdog monitor thread function
// Runs in a detached mode — polls for drive presence every 2 seconds
static void watchdog_monitor(char drive_letter, std::string temp_dir) {
    char root_path[] = { drive_letter, ':', '\\', '\0' };

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Check if the drive is still present
        DWORD drives = GetLogicalDrives();
        int drive_index = toupper(drive_letter) - 'A';

        if (!(drives & (1 << drive_index))) {
            // Drive removed — execute wipe immediately
            std::string bat_path = temp_dir + "\\shushhh_wipe.bat";

            // Launch the wipe bat as a detached process
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;  // Hidden window
            ZeroMemory(&pi, sizeof(pi));

            std::string cmd = "cmd.exe /c \"" + bat_path + "\"";

            CreateProcessA(
                nullptr,
                &cmd[0],
                nullptr, nullptr,
                FALSE,
                CREATE_NO_WINDOW | DETACHED_PROCESS,
                nullptr,
                temp_dir.c_str(),
                &si,
                &pi
            );

            if (pi.hProcess) CloseHandle(pi.hProcess);
            if (pi.hThread) CloseHandle(pi.hThread);

            // Our job is done — exit the watchdog thread
            return;
        }
    }
}

bool launch_watchdog(char drive_letter) {
    // Get %TEMP% directory
    char temp_path[MAX_PATH];
    if (GetTempPathA(MAX_PATH, temp_path) == 0) {
        std::cerr << "[-] Failed to get TEMP directory\n";
        return false;
    }
    std::string temp_dir(temp_path);
    // Remove trailing backslash if present
    if (!temp_dir.empty() && temp_dir.back() == '\\') {
        temp_dir.pop_back();
    }

    // Write the wipe script
    if (!write_wipe_script(temp_dir)) {
        return false;
    }

    // Launch the watchdog as a detached background thread
    // This thread survives even if the main menu loop exits normally,
    // because we detach it. If shushhh.exe is killed, the thread dies too —
    // for true process-level survival, a separate watchdog.exe would be needed.
    // For the Phase 1 implementation, thread-based is sufficient.
    std::thread monitor(watchdog_monitor, drive_letter, temp_dir);
    monitor.detach();

    std::cout << "[+] Watchdog launched — monitoring drive "
              << drive_letter << ":\\\n";
    std::cout << "    Wipe script at: " << temp_dir << "\\shushhh_wipe.bat\n";

    return true;
}

#else
// ============================================================
// Non-Windows stubs
// ============================================================

char detect_usb_drive() {
    std::cerr << "[-] Watchdog is only supported on Windows\n";
    return '\0';
}

bool write_wipe_script(const std::string& /*temp_dir*/) {
    std::cerr << "[-] Watchdog is only supported on Windows\n";
    return false;
}

bool launch_watchdog(char /*drive_letter*/) {
    std::cerr << "[-] Watchdog is only supported on Windows\n";
    return false;
}

#endif
