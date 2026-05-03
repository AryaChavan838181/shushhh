// ============================================================
// tor_manager.cpp — Tor Process Management for Android
// ============================================================
// Extracts the bundled Tor binary (libTor.so) from APK assets
// at first launch, sets executable permissions, and manages
// the tor subprocess.
// All traffic is then proxied through socks5h://127.0.0.1:9050.

#include "tor_manager.h"

#include <jni.h>
#include <android/log.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/system_properties.h>
#include <cstring>
#include <string>
#include <cerrno>

#define LOG_TAG "shushhh_tor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Global Tor process PID
static pid_t g_tor_pid = -1;
static std::string g_tor_binary_path;
static std::string g_tor_data_dir;
static std::string g_tor_dir;

// ─── Extract a single asset file to the filesystem ───
static bool extract_asset(AAssetManager* mgr, const char* asset_path, const std::string& dest_path) {
    AAsset* asset = AAssetManager_open(mgr, asset_path, AASSET_MODE_STREAMING);
    if (!asset) {
        LOGW("Asset not found: %s (may be optional)", asset_path);
        return false;
    }

    int fd = open(dest_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        AAsset_close(asset);
        LOGE("Failed to create file: %s (errno=%d: %s)", dest_path.c_str(), errno, strerror(errno));
        return false;
    }

    char buf[8192];
    int bytes_read;
    size_t total = 0;
    while ((bytes_read = AAsset_read(asset, buf, sizeof(buf))) > 0) {
        write(fd, buf, bytes_read);
        total += bytes_read;
    }

    close(fd);
    AAsset_close(asset);

    // Make executable
    chmod(dest_path.c_str(), 0755);

    LOGI("Extracted asset: %s -> %s (%zu bytes)", asset_path, dest_path.c_str(), total);
    return true;
}

// ─── Check if Tor SOCKS5 port is listening ───
bool is_tor_running() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9050);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    // Use non-blocking connect with select for 1 second timeout
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    bool running = false;
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        running = true;
    } else if (errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(sock + 1, NULL, &wfds, NULL, &tv) > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
            if (error == 0) running = true;
        }
    }

    close(sock);
    return running;
}

// ─── Extract Tor binary and data from APK assets ───
bool setup_tor(JNIEnv* env, jobject context, jobject asset_manager_obj) {
    // Get files directory path
    jclass ctx_class = env->GetObjectClass(context);
    jmethodID getFilesDir = env->GetMethodID(ctx_class, "getFilesDir", "()Ljava/io/File;");
    jobject filesDir = env->CallObjectMethod(context, getFilesDir);
    jclass fileClass = env->GetObjectClass(filesDir);
    jmethodID getAbsPath = env->GetMethodID(fileClass, "getAbsolutePath", "()Ljava/lang/String;");
    jstring path = (jstring)env->CallObjectMethod(filesDir, getAbsPath);
    const char* pathStr = env->GetStringUTFChars(path, nullptr);
    std::string files_dir(pathStr);
    env->ReleaseStringUTFChars(path, pathStr);

    g_tor_dir = files_dir + "/tor";
    g_tor_binary_path = g_tor_dir + "/tor";
    g_tor_data_dir = files_dir + "/tor_data";

    LOGI("Tor setup: files_dir=%s", files_dir.c_str());

    // Create directories
    mkdir(g_tor_dir.c_str(), 0755);
    mkdir(g_tor_data_dir.c_str(), 0755);

    // Extract from assets for geoip data
    AAssetManager* mgr = AAssetManager_fromJava(env, asset_manager_obj);
    if (!mgr) {
        LOGE("Failed to get AAssetManager");
        return false;
    }

    // Get nativeLibraryDir to bypass Android 10+ W^X restrictions
    jmethodID getAppInfo = env->GetMethodID(ctx_class, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, getAppInfo);
    jclass appInfoClass = env->GetObjectClass(appInfo);
    jfieldID nativeLibraryDirField = env->GetFieldID(appInfoClass, "nativeLibraryDir", "Ljava/lang/String;");
    jstring nativeLibraryDir = (jstring)env->GetObjectField(appInfo, nativeLibraryDirField);
    const char* nativeLibPath = env->GetStringUTFChars(nativeLibraryDir, nullptr);
    std::string native_lib_dir(nativeLibPath);
    env->ReleaseStringUTFChars(nativeLibraryDir, nativeLibPath);

    g_tor_binary_path = native_lib_dir + "/libTor.so";
    LOGI("Using Tor binary from nativeLibraryDir: %s", g_tor_binary_path.c_str());

    struct stat st;

    // Extract geoip data (non-fatal if missing)
    std::string geoip_path = g_tor_dir + "/geoip";
    std::string geoip6_path = g_tor_dir + "/geoip6";
    std::string torrc_path = g_tor_dir + "/torrc-defaults";

    if (stat(geoip_path.c_str(), &st) != 0 || st.st_size == 0) {
        extract_asset(mgr, "tor/geoip", geoip_path);
    }
    if (stat(geoip6_path.c_str(), &st) != 0 || st.st_size == 0) {
        extract_asset(mgr, "tor/geoip6", geoip6_path);
    }
    if (stat(torrc_path.c_str(), &st) != 0 || st.st_size == 0) {
        extract_asset(mgr, "tor/torrc-defaults", torrc_path);
    }

    return true;
}

// ─── Launch Tor subprocess ───
bool launch_tor() {
    if (is_tor_running()) {
        LOGI("Tor is already running on port 9050");
        return true;
    }

    // Check if a previous Tor process died
    if (g_tor_pid > 0) {
        int status;
        pid_t result = waitpid(g_tor_pid, &status, WNOHANG);
        if (result == g_tor_pid) {
            LOGW("Previous Tor process (PID %d) exited with status %d", g_tor_pid,
                 WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            g_tor_pid = -1;
        } else if (result == 0) {
            LOGI("Tor process (PID %d) is still running, waiting for port...", g_tor_pid);
            return true; // Still running, just not listening yet
        }
    }

    if (g_tor_binary_path.empty()) {
        LOGE("Tor binary path not set — call setup_tor first");
        return false;
    }

    // Verify binary exists
    struct stat st;
    if (stat(g_tor_binary_path.c_str(), &st) != 0) {
        LOGE("Tor binary not found at: %s", g_tor_binary_path.c_str());
        return false;
    }
    LOGI("Tor binary: %s (%ld bytes)", g_tor_binary_path.c_str(), (long)st.st_size);

    // Verify binary is executable
    if (access(g_tor_binary_path.c_str(), X_OK) != 0) {
        LOGE("Tor binary not executable, setting permissions...");
        chmod(g_tor_binary_path.c_str(), 0755);
        if (access(g_tor_binary_path.c_str(), X_OK) != 0) {
            LOGE("Still not executable after chmod: errno=%d (%s)", errno, strerror(errno));
            return false;
        }
    }

    // Create a log file for Tor output (for debugging)
    std::string log_path = g_tor_data_dir + "/tor.log";

    pid_t pid = fork();
    if (pid == 0) {
        // Child process — exec tor

        // Redirect stdout/stderr to log file for debugging
        int logfd = open(log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (logfd >= 0) {
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
            close(logfd);
        }

        // Build torrc path
        std::string geoip_path = g_tor_dir + "/geoip";
        std::string geoip6_path = g_tor_dir + "/geoip6";

        // Build args
        const char* args[20];
        int argc = 0;
        args[argc++] = "tor";
        args[argc++] = "--SocksPort";
        args[argc++] = "9050";
        args[argc++] = "--DataDirectory";
        args[argc++] = g_tor_data_dir.c_str();

        // Add geoip if available
        if (access(geoip_path.c_str(), R_OK) == 0) {
            args[argc++] = "--GeoIPFile";
            args[argc++] = geoip_path.c_str();
        }
        if (access(geoip6_path.c_str(), R_OK) == 0) {
            args[argc++] = "--GeoIPv6File";
            args[argc++] = geoip6_path.c_str();
        }

        // Disable control port for security
        args[argc++] = "--ControlPort";
        args[argc++] = "0";

        // Log notice level for bootstrapping feedback
        args[argc++] = "--Log";
        args[argc++] = "notice stdout";

        args[argc] = nullptr;

        LOGI("exec: %s with %d args", g_tor_binary_path.c_str(), argc);
        execv(g_tor_binary_path.c_str(), (char* const*)args);

        // If exec failed — log error and exit
        FILE* f = fopen(log_path.c_str(), "a");
        if (f) {
            fprintf(f, "execv failed: errno=%d (%s)\n", errno, strerror(errno));
            fprintf(f, "binary: %s\n", g_tor_binary_path.c_str());
            fclose(f);
        }
        _exit(127);
    } else if (pid > 0) {
        g_tor_pid = pid;
        LOGI("Tor launched with PID %d", pid);

        // Brief wait and check if it crashed immediately
        usleep(500000); // 500ms
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            // Process already exited — something went wrong
            int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            LOGE("Tor exited immediately with code %d", exit_code);

            // Read log for diagnostics
            FILE* f = fopen(log_path.c_str(), "r");
            if (f) {
                char buf[2048];
                size_t n = fread(buf, 1, sizeof(buf) - 1, f);
                buf[n] = '\0';
                fclose(f);
                LOGE("Tor log:\n%s", buf);
            }
            g_tor_pid = -1;
            return false;
        }

        LOGI("Tor process running (PID %d), waiting for SOCKS port...", pid);
        return true;
    } else {
        LOGE("fork() failed: errno=%d (%s)", errno, strerror(errno));
        return false;
    }
}

// ─── Kill Tor subprocess ───
void kill_tor() {
    if (g_tor_pid > 0) {
        kill(g_tor_pid, SIGTERM);
        LOGI("Sent SIGTERM to Tor (PID %d)", g_tor_pid);

        // Wait briefly for clean shutdown
        usleep(500000); // 500ms
        int status;
        if (waitpid(g_tor_pid, &status, WNOHANG) == 0) {
            // Still running — force kill
            kill(g_tor_pid, SIGKILL);
            waitpid(g_tor_pid, &status, 0);
            LOGI("Force killed Tor (PID %d)", g_tor_pid);
        }
        g_tor_pid = -1;
    }
}
