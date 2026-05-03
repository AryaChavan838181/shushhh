#include "watchdog/watchdog.h"
#include "platform/platform.h"

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <fstream>
#include <sstream>
#endif

namespace fs = std::filesystem;

// ============================================================
// F-11 · Watchdog auto-wipe implementation
// ============================================================

#ifdef _WIN32

// ---- Windows Implementation ----

std::string detect_usb_drive() {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    char drive_letter = exe_path[0];

    char root_path[] = { drive_letter, ':', '\\', '\0' };
    UINT drive_type = GetDriveTypeA(root_path);

    if (drive_type == DRIVE_REMOVABLE) {
        std::cerr << "[+] USB drive detected: " << drive_letter << ":\\\n";
    } else {
        std::cerr << "[*] Running from non-removable drive " << drive_letter
                  << ":\\ — watchdog will monitor this drive\n";
    }
    return std::string(1, drive_letter);
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

// Watchdog monitor thread — polls for drive presence every 2 seconds
static void watchdog_monitor(std::string drive_str, std::string temp_dir) {
    char drive_letter = drive_str[0];
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        DWORD drives = GetLogicalDrives();
        int drive_index = toupper(drive_letter) - 'A';

        if (!(drives & (1 << drive_index))) {
            // Drive removed — execute wipe immediately
            std::string bat_path = temp_dir + "\\shushhh_wipe.bat";

            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
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

            return;
        }
    }
}

bool launch_watchdog(const std::string& drive_or_mount) {
    std::string temp_dir = platform_get_temp_dir();

    if (!write_wipe_script(temp_dir)) {
        return false;
    }

    std::thread monitor(watchdog_monitor, drive_or_mount, temp_dir);
    monitor.detach();

    std::cerr << "[+] Watchdog launched — monitoring drive "
              << drive_or_mount << ":\\\n";
    std::cerr << "    Wipe script at: " << temp_dir << "\\shushhh_wipe.bat\n";

    return true;
}

#else

// ---- Linux Implementation ----

// Detect the mount point of the USB device the executable is running from.
// Reads /proc/mounts to find which mount point contains the exe path.
// Returns empty string if not running from a removable/external mount.
std::string detect_usb_drive() {
    std::string exe_dir = platform_get_exe_dir();

    // Check if running from typical removable mount points
    // Linux auto-mounts USB to /media/<user>/<label> or /run/media/<user>/<label>
    if (exe_dir.find("/media/") == 0 || exe_dir.find("/run/media/") == 0) {
        // Extract the mount root (e.g., /media/user/USBDRIVE)
        // Count path segments: /media/<user>/<label>
        size_t count = 0;
        size_t pos = 0;
        std::string mount_root;
        for (size_t i = 1; i < exe_dir.size(); ++i) {
            if (exe_dir[i] == '/') {
                count++;
                if ((exe_dir.find("/media/") == 0 && count == 3) ||
                    (exe_dir.find("/run/media/") == 0 && count == 4)) {
                    mount_root = exe_dir.substr(0, i);
                    break;
                }
            }
        }
        if (mount_root.empty()) mount_root = exe_dir;
        std::cerr << "[+] USB mount detected: " << mount_root << "\n";
        return mount_root;
    }

    // Not on a removable mount — return the exe dir anyway for development
    std::cerr << "[*] Running from " << exe_dir
              << " — watchdog will monitor this path\n";
    return exe_dir;
}

bool write_wipe_script(const std::string& temp_dir) {
    std::string sh_path = temp_dir + "/shushhh_wipe.sh";
    std::ofstream sh(sh_path);

    if (!sh.is_open()) {
        std::cerr << "[-] Failed to create wipe script at " << sh_path << "\n";
        return false;
    }

    sh << "#!/bin/bash\n";
    sh << "echo '[*] shushhh watchdog: USB disconnected — initiating wipe'\n";
    sh << "\n";
    sh << "# Delete all shushhh-related temporary files\n";
    sh << "rm -rf /tmp/shushhh_* 2>/dev/null\n";
    sh << "rm -rf \"${XDG_RUNTIME_DIR}/shushhh_*\" 2>/dev/null\n";
    sh << "\n";
    sh << "# Overwrite freed disk space (if shred is available)\n";
    sh << "if command -v shred &>/dev/null; then\n";
    sh << "    find /tmp -maxdepth 1 -name 'shushhh_*' -exec shred -u {} \\; 2>/dev/null\n";
    sh << "fi\n";
    sh << "\n";
    sh << "# Self-delete\n";
    sh << "rm -f \"$0\" 2>/dev/null\n";

    sh.close();

    // Make script executable
    chmod(sh_path.c_str(), 0700);

    return true;
}

// Watchdog monitor thread — polls for mount point presence every 2 seconds
static void watchdog_monitor_linux(std::string mount_path, std::string temp_dir) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Check if mount point still exists and is accessible
        struct stat st;
        if (stat(mount_path.c_str(), &st) != 0) {
            // Mount point gone — USB yanked
            std::string sh_path = temp_dir + "/shushhh_wipe.sh";

            pid_t pid = fork();
            if (pid == 0) {
                // Child: run wipe script
                setsid();
                execl("/bin/bash", "bash", sh_path.c_str(), (char*)nullptr);
                _exit(127);
            }
            return;
        }
    }
}

bool launch_watchdog(const std::string& drive_or_mount) {
    std::string temp_dir = platform_get_temp_dir();

    if (!write_wipe_script(temp_dir)) {
        return false;
    }

    std::thread monitor(watchdog_monitor_linux, drive_or_mount, temp_dir);
    monitor.detach();

    std::cerr << "[+] Watchdog launched — monitoring " << drive_or_mount << "\n";
    std::cerr << "    Wipe script at: " << temp_dir << "/shushhh_wipe.sh\n";

    return true;
}

#endif
