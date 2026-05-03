#ifdef _WIN32

#include "platform/platform.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <filesystem>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")

// ============================================================
// Windows: Check if Tor is running on port 9050
// ============================================================
bool platform_is_tor_running() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return false; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9050);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bool running = (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == 0);
    closesocket(sock);
    WSACleanup();
    return running;
}

// ============================================================
// Windows: Get executable's directory
// ============================================================
std::string platform_get_exe_dir() {
    char buf[MAX_PATH];
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string path(buf);
    auto pos = path.find_last_of("\\/");
    return (pos != std::string::npos) ? path.substr(0, pos) : ".";
}

// ============================================================
// Windows: Get temp directory
// ============================================================
std::string platform_get_temp_dir() {
    char buf[MAX_PATH];
    GetTempPathA(MAX_PATH, buf);
    std::string tmp(buf);
    if (!tmp.empty() && (tmp.back() == '\\' || tmp.back() == '/'))
        tmp.pop_back();
    return tmp;
}

// ============================================================
// Windows: Launch Tor silently
// ============================================================
bool platform_launch_tor(const std::string& exe_dir) {
    // Search for tor.exe relative to the executable's own directory
    std::vector<std::string> search_paths = {
        exe_dir + "\\tor.exe",
        exe_dir + "\\tor\\tor\\tor.exe",
        exe_dir + "\\tor\\tor.exe",
        "tor\\tor\\tor.exe",
        "tor\\tor.exe",
        "tor.exe",
    };

    std::string tor_path;
    for (const auto& p : search_paths) {
        if (std::filesystem::exists(p)) { tor_path = p; break; }
    }
    if (tor_path.empty()) return false;

    tor_path = std::filesystem::absolute(tor_path).string();

    // Use a dedicated temp directory so Tor doesn't hit permission errors
    std::string data_dir = platform_get_temp_dir() + "\\shushhh_tor_data";
    std::filesystem::create_directories(data_dir);

    std::string cmd = "\"" + tor_path + "\" --DataDirectory \"" + data_dir + "\"";

    // Explicitly provide GeoIP files if they exist (crucial for bootstrapping)
    std::string geoip_path = exe_dir + "\\tor\\data\\geoip";
    std::string geoip6_path = exe_dir + "\\tor\\data\\geoip6";
    if (std::filesystem::exists(geoip_path)) cmd += " --GeoIPFile \"" + geoip_path + "\"";
    if (std::filesystem::exists(geoip6_path)) cmd += " --GeoIPv6File \"" + geoip6_path + "\"";

    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); ZeroMemory(&pi, sizeof(pi));
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessA(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return false;
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return true;
}

#endif // _WIN32
