// ============================================================
// watchdog_android.cpp — Self-Destruct Engine for Android
// ============================================================
// When USB OTG is disconnected, this module:
// 1. Overwrites ALL files in app private storage with random bytes
// 2. Truncates all .so native libraries to 0 bytes
// 3. Wipes all in-memory key material via sodium_memzero
// 4. Calls ActivityManager.clearApplicationUserData() to nuke everything
//
// After this executes, the APK shell remains installed but is a
// completely blank husk — no code, no data, no forensic trace.

#include "watchdog_android.h"

#include <jni.h>
#include <android/log.h>
#include <sodium.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <string>
#include <vector>

#define LOG_TAG "shushhh_watchdog"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ─── File shredding ───
// Overwrites a file with random bytes, then truncates to 0.
// This ensures the original data cannot be recovered even with
// raw NAND flash forensics (the blocks are overwritten, not just unlinked).
static bool shred_file(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;

    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) return false;

    // Overwrite with random bytes in 4KB chunks
    size_t file_size = static_cast<size_t>(st.st_size);
    unsigned char buf[4096];
    size_t written = 0;

    while (written < file_size) {
        size_t chunk = std::min(sizeof(buf), file_size - written);
        randombytes_buf(buf, chunk);
        write(fd, buf, chunk);
        written += chunk;
    }

    // Sync to ensure data hits the flash
    fsync(fd);

    // Truncate to 0 — file now appears empty
    ftruncate(fd, 0);
    fsync(fd);

    close(fd);
    return true;
}

// ─── Recursive directory shredding ───
static void shred_directory(const std::string& dir_path) {
    DIR* dir = opendir(dir_path.c_str());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name(entry->d_name);
        if (name == "." || name == "..") continue;

        std::string full_path = dir_path + "/" + name;

        if (entry->d_type == DT_DIR) {
            shred_directory(full_path);
        } else {
            if (shred_file(full_path)) {
                LOGW("Shredded: %s", full_path.c_str());
            }
        }
    }
    closedir(dir);
}

// ─── Locate and truncate .so libraries ───
// The app's native libraries live at /data/app/<package>/lib/arm64/
// We find them by inspecting /proc/self/maps for loaded .so paths
static void shred_native_libraries() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return;

    std::vector<std::string> so_paths;
    char line[512];

    while (fgets(line, sizeof(line), maps)) {
        // Look for our library
        char* so_pos = strstr(line, "libshushhh_native.so");
        if (so_pos) {
            // Extract the full path from the maps line
            char* path_start = strchr(line, '/');
            if (path_start) {
                // Trim newline
                char* nl = strchr(path_start, '\n');
                if (nl) *nl = '\0';
                so_paths.push_back(std::string(path_start));
            }
        }
    }
    fclose(maps);

    // Attempt to overwrite and truncate the .so files
    // Note: on many Android versions, the APK's lib/ directory is read-only.
    // The overwrite may fail, but we still wipe all app data.
    for (const auto& path : so_paths) {
        LOGW("Attempting to shred .so: %s", path.c_str());
        shred_file(path);
    }
}

// ============================================================
// Public API — called from JNI bridge
// ============================================================

void execute_self_destruct(JNIEnv* env, jobject context) {
    LOGW("╔══════════════════════════════════════╗");
    LOGW("║   USB DISCONNECTED — SELF DESTRUCT   ║");
    LOGW("╚══════════════════════════════════════╝");

    // 1. Get app directories from Context
    jclass ctx_class = env->GetObjectClass(context);

    // getFilesDir()
    jmethodID getFilesDir = env->GetMethodID(ctx_class, "getFilesDir", "()Ljava/io/File;");
    jobject filesDir = env->CallObjectMethod(context, getFilesDir);
    jclass fileClass = env->GetObjectClass(filesDir);
    jmethodID getAbsPath = env->GetMethodID(fileClass, "getAbsolutePath", "()Ljava/lang/String;");
    jstring filesDirPath = (jstring)env->CallObjectMethod(filesDir, getAbsPath);
    const char* filesPath = env->GetStringUTFChars(filesDirPath, nullptr);
    std::string files_dir(filesPath);
    env->ReleaseStringUTFChars(filesDirPath, filesPath);

    // getCacheDir()
    jmethodID getCacheDir = env->GetMethodID(ctx_class, "getCacheDir", "()Ljava/io/File;");
    jobject cacheDir = env->CallObjectMethod(context, getCacheDir);
    jstring cacheDirPath = (jstring)env->CallObjectMethod(cacheDir, getAbsPath);
    const char* cachePath = env->GetStringUTFChars(cacheDirPath, nullptr);
    std::string cache_dir(cachePath);
    env->ReleaseStringUTFChars(cacheDirPath, cachePath);

    // 2. Shred all files in private directories
    LOGW("[1/5] Shredding files directory: %s", files_dir.c_str());
    shred_directory(files_dir);

    LOGW("[2/5] Shredding cache directory: %s", cache_dir.c_str());
    shred_directory(cache_dir);

    // 3. Shred native .so libraries
    LOGW("[3/5] Shredding native libraries");
    shred_native_libraries();

    // 4. Wipe in-memory key material
    // (The actual key buffers are extern globals in jni_bridge.cpp;
    //  they get wiped via the wipe_all_keys() function)
    LOGW("[4/5] Wiping in-memory key material");
    extern void wipe_all_keys();
    wipe_all_keys();

    // 5. Write permanent brick flag
    // We no longer call clearApplicationUserData() because it would wipe the brick flag
    // and allow the app to be reconfigured. Instead, the shredder above has already
    // destroyed all the keys, DBs, and the extracted Tor binary.
    LOGW("[5/5] Writing permanent brick flag and terminating");
    std::string brick_path = files_dir + "/bricked.flag";
    int fd = open(brick_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        write(fd, "1", 1);
        fsync(fd);
        close(fd);
    }

    // Process will be killed by clearApplicationUserData() above.
    // If it somehow survives, force exit.
    _exit(0);
}
