#ifndef _WIN32

#include "platform/platform.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <filesystem>
#include <vector>
#include <string>
#include <climits>   // PATH_MAX
#include <cstdlib>   // system()
#include <signal.h>

// ============================================================
// Linux: Check if Tor is running on port 9050
// ============================================================
bool platform_is_tor_running() {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9050);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bool running = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(sock);
    return running;
}

// ============================================================
// Linux: Get executable's directory via /proc/self/exe
// ============================================================
std::string platform_get_exe_dir() {
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) return ".";
    buf[len] = '\0';
    std::string path(buf);
    auto pos = path.find_last_of('/');
    return (pos != std::string::npos) ? path.substr(0, pos) : ".";
}

// ============================================================
// Linux: Get temp directory
// ============================================================
std::string platform_get_temp_dir() {
    const char* tmp = std::getenv("TMPDIR");
    if (tmp && tmp[0]) return std::string(tmp);
    return "/tmp";
}

// ============================================================
// Linux: Launch Tor as a background process
// ============================================================
bool platform_launch_tor(const std::string& exe_dir) {
    // Search for tor binary relative to executable, then on PATH
    std::vector<std::string> search_paths = {
        exe_dir + "/tor",
        exe_dir + "/tor/tor/tor",
        exe_dir + "/tor/tor",
    };

    std::string tor_path;
    for (const auto& p : search_paths) {
        if (std::filesystem::exists(p)) { tor_path = p; break; }
    }

    // If no bundled tor found, check if system tor exists on PATH
    if (tor_path.empty()) {
        // Check common system locations
        std::vector<std::string> system_paths = {
            "/usr/bin/tor",
            "/usr/local/bin/tor",
        };
        for (const auto& p : system_paths) {
            if (std::filesystem::exists(p)) { tor_path = p; break; }
        }
    }

    if (tor_path.empty()) return false;

    tor_path = std::filesystem::absolute(tor_path).string();

    // DataDirectory in temp
    std::string data_dir = platform_get_temp_dir() + "/shushhh_tor_data";
    std::filesystem::create_directories(data_dir);

    // GeoIP files
    std::string geoip_arg, geoip6_arg;
    std::string geoip_path = exe_dir + "/tor/data/geoip";
    std::string geoip6_path = exe_dir + "/tor/data/geoip6";
    if (std::filesystem::exists(geoip_path)) geoip_arg = geoip_path;
    if (std::filesystem::exists(geoip6_path)) geoip6_arg = geoip6_path;

    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        // Child process — become a daemon
        setsid();

        // Redirect stdin/stdout/stderr to /dev/null
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2) close(devnull);
        }

        // Build argv
        std::vector<const char*> argv;
        argv.push_back(tor_path.c_str());
        argv.push_back("--DataDirectory");
        argv.push_back(data_dir.c_str());
        
        std::string geoip_flag = "--GeoIPFile";
        std::string geoip6_flag = "--GeoIPv6File";
        if (!geoip_arg.empty()) {
            argv.push_back(geoip_flag.c_str());
            argv.push_back(geoip_arg.c_str());
        }
        if (!geoip6_arg.empty()) {
            argv.push_back(geoip6_flag.c_str());
            argv.push_back(geoip6_arg.c_str());
        }
        argv.push_back(nullptr);

        execvp(tor_path.c_str(), const_cast<char* const*>(argv.data()));
        _exit(127); // execvp failed
    }

    // Parent — child is now running independently
    return true;
}

#endif // !_WIN32
