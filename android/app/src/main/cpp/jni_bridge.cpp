// ============================================================
// jni_bridge.cpp — JNI Interface for Shushhh Android
// ============================================================
// Bridges the Java/WebView UI to the C++ crypto core.
// All crypto operations happen in native code — Java only
// handles UI rendering and USB event detection.

#include <jni.h>
#include <android/log.h>
#include <android/asset_manager_jni.h>

#include "crypto/crypto.h"
#include "auth/auth.h"
#include "tor_manager.h"
#include "watchdog_android.h"

#include <sodium.h>
#include <nlohmann/json.hpp>
#include <string>
#include <mutex>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>

#define LOG_TAG "shushhh_jni"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============================================================
// Global State (mirrors Main.cpp from Windows version)
// ============================================================

static std::string g_keyserver_url = "http://127.0.0.1:5000";
static std::string g_msgserver_url = "http://127.0.0.1:5001";

static HybridKeyPair g_my_keypair;
static bool g_has_keypair = false;
static MessageSession g_current_session;
static bool g_has_session = false;
static std::string g_my_username;
static std::string g_peer_username;

static std::vector<std::string> g_chat_history;
static std::mutex g_chat_mutex;
static std::atomic<bool> g_keep_fetching{false};
static std::thread g_fetcher_thread;
static std::string g_files_dir;

// ============================================================
// Wipe all keys — called by watchdog before self-destruct
// ============================================================

void wipe_all_keys() {
    if (g_has_keypair) {
        secure_wipe(g_my_keypair.x25519_private, 32);
        secure_wipe(g_my_keypair.kyber_private.data(), g_my_keypair.kyber_private.size());
        g_has_keypair = false;
    }
    if (g_has_session) {
        secure_wipe(g_current_session.send_key.data(), g_current_session.send_key.size());
        secure_wipe(g_current_session.recv_key.data(), g_current_session.recv_key.size());
        secure_wipe(g_current_session.root_key.data(), g_current_session.root_key.size());
        g_has_session = false;
    }
    LOGI("All key material wiped from memory");
}

// ============================================================
// Helpers
// ============================================================

static std::string to_hex(const unsigned char* data, size_t len) {
    std::string hex;
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex += buf;
    }
    return hex;
}

static bool from_hex(const std::string& hex, unsigned char* out, size_t out_len) {
    if (hex.size() != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte;
        sscanf(hex.substr(i * 2, 2).c_str(), "%02x", &byte);
        out[i] = static_cast<unsigned char>(byte);
    }
    return true;
}

static std::string to_base64(const unsigned char* data, size_t len) {
    size_t b64_maxlen = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::string b64(b64_maxlen, '\0');
    sodium_bin2base64(&b64[0], b64_maxlen, data, len, sodium_base64_VARIANT_ORIGINAL);
    b64.resize(strlen(b64.c_str()));
    return b64;
}

// ============================================================
// Background Fetcher (same logic as Windows version)
// ============================================================

static JavaVM* g_jvm = nullptr;

static void fetcher_loop() {
    while (g_keep_fetching) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (g_my_username.empty()) continue;

        std::string my_tag = to_hex(sha256_hash(g_my_username).data(), 32);
        std::string url = g_msgserver_url + "/fetch?tag=" + my_tag;
        std::string resp = tor_get(url);
        if (resp.empty()) continue;

        try {
            auto j = nlohmann::json::parse(resp);
            if (j["status"] != "ok") continue;
            auto& messages = j["messages"];

            for (auto& msg : messages) {
                std::string event_id = msg["event_id"];
                std::string blob = msg["blob"];

                // Check for handshake
                try {
                    auto j_blob = nlohmann::json::parse(blob);
                    if (j_blob.contains("type") && j_blob["type"] == "handshake") {
                        HandshakePayload hs = json_to_handshake(j_blob.dump());
                        std::string inner = process_ephemeral_handshake(
                            g_my_keypair.x25519_private, hs);

                        if (!inner.empty()) {
                            auto inner_j = nlohmann::json::parse(inner);
                            std::string sender = inner_j["sender"];
                            std::string kyber_ct_b64 = inner_j["kyber_ciphertext"];

                            std::string pub_keys_json = PasswordLogin::fetch_public_keys(
                                g_keyserver_url, sender);
                            if (!pub_keys_json.empty()) {
                                auto pj = nlohmann::json::parse(pub_keys_json);
                                unsigned char their_x25519[32];
                                from_hex(pj["x25519"], their_x25519, 32);

                                std::vector<unsigned char> kyber_ct(1088);
                                size_t b64_len = 0;
                                sodium_base642bin(kyber_ct.data(), kyber_ct.size(),
                                    kyber_ct_b64.c_str(), kyber_ct_b64.size(),
                                    nullptr, &b64_len, nullptr,
                                    sodium_base64_VARIANT_ORIGINAL);

                                g_current_session = create_session_responder(
                                    g_my_keypair, their_x25519, kyber_ct);
                                g_has_session = true;
                                g_peer_username = sender;

                                std::lock_guard<std::mutex> lock(g_chat_mutex);
                                g_chat_history.push_back(
                                    "[SYSTEM] Secure 0-RTT session with " + sender);
                            }
                            nlohmann::json ack;
                            ack["event_id"] = event_id;
                            tor_post(g_msgserver_url + "/ack", ack.dump());
                        }
                        continue;
                    }
                } catch (...) {}

                // Standard message
                if (g_has_session) {
                    EncryptedMessage enc_msg = json_to_encrypted(blob);
                    std::string plaintext = session_decrypt(g_current_session, enc_msg);
                    if (!plaintext.empty()) {
                        std::lock_guard<std::mutex> lock(g_chat_mutex);
                        g_chat_history.push_back(g_peer_username + "> " + plaintext);

                        nlohmann::json ack;
                        ack["event_id"] = event_id;
                        tor_post(g_msgserver_url + "/ack", ack.dump());
                    }
                }
            }
        } catch (...) {}
    }
}

// ============================================================
// JNI Functions
// ============================================================

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

// ─── Crypto Init ───
JNIEXPORT jboolean JNICALL
Java_com_shushhh_app_NativeBridge_nativeCryptoInit(JNIEnv* env, jclass) {
    bool ok = crypto_init();
    LOGI("crypto_init() = %s", ok ? "success" : "FAILED");
    return ok ? JNI_TRUE : JNI_FALSE;
}

// ─── Server Configuration ───
JNIEXPORT void JNICALL
Java_com_shushhh_app_NativeBridge_nativeSetServerUrls(JNIEnv* env, jclass,
    jstring keyServer, jstring msgServer) {
    const char* ks = env->GetStringUTFChars(keyServer, nullptr);
    const char* ms = env->GetStringUTFChars(msgServer, nullptr);
    std::string ks_str(ks);
    std::string ms_str(ms);
    
    // The Android build of libcurl lacks SSL support (CURL_USE_OPENSSL=OFF) to save space.
    // Since we use payload encryption and Ed25519 signatures, HTTP over Tor is secure here.
    if (ks_str.find("https://") == 0) ks_str.replace(0, 8, "http://");
    if (ms_str.find("https://") == 0) ms_str.replace(0, 8, "http://");
    
    g_keyserver_url = ks_str;
    g_msgserver_url = ms_str;
    env->ReleaseStringUTFChars(keyServer, ks);
    env->ReleaseStringUTFChars(msgServer, ms);
    LOGI("Server URLs set: KS=%s MS=%s", g_keyserver_url.c_str(), g_msgserver_url.c_str());
}

// ─── Tor Management ───
JNIEXPORT jboolean JNICALL
Java_com_shushhh_app_NativeBridge_nativeSetupTor(JNIEnv* env, jclass,
    jobject context, jobject assetManager) {
    return setup_tor(env, context, assetManager) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_shushhh_app_NativeBridge_nativeLaunchTor(JNIEnv* env, jclass) {
    return launch_tor() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_shushhh_app_NativeBridge_nativeIsTorRunning(JNIEnv* env, jclass) {
    return is_tor_running() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_shushhh_app_NativeBridge_nativeGetTorIp(JNIEnv* env, jclass) {
    std::string ip = tor_get("http://api.ipify.org");
    // If it failed or returned HTML, return empty string
    if (ip.empty() || ip.find("<") != std::string::npos) {
        return nullptr;
    }
    return env->NewStringUTF(ip.c_str());
}

// ─── Authentication ───
JNIEXPORT jboolean JNICALL
Java_com_shushhh_app_NativeBridge_nativeRegister(JNIEnv* env, jclass,
    jstring username, jstring password) {
    const char* u = env->GetStringUTFChars(username, nullptr);
    const char* p = env->GetStringUTFChars(password, nullptr);

    PasswordLogin login;
    login.set_credentials(std::string(u), std::string(p));
    bool ok = login.register_account(g_keyserver_url);

    env->ReleaseStringUTFChars(username, u);
    env->ReleaseStringUTFChars(password, p);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_shushhh_app_NativeBridge_nativeLogin(JNIEnv* env, jclass,
    jstring username, jstring password, jstring filesDir) {
    const char* u = env->GetStringUTFChars(username, nullptr);
    const char* p = env->GetStringUTFChars(password, nullptr);
    const char* fd = env->GetStringUTFChars(filesDir, nullptr);

    g_files_dir = std::string(fd);
    g_my_username = std::string(u);

    PasswordLogin login;
    login.set_credentials(std::string(u), std::string(p));

    // Authenticate
    bool ok = login.authenticate(g_keyserver_url);
    if (!ok) {
        env->ReleaseStringUTFChars(username, u);
        env->ReleaseStringUTFChars(password, p);
        env->ReleaseStringUTFChars(filesDir, fd);
        return JNI_FALSE;
    }

    // Load or generate identity
    std::string identity_path = g_files_dir + "/identity.dat";
    if (login.load_identity(g_my_keypair, identity_path)) {
        g_has_keypair = true;
    } else {
        g_my_keypair = generate_hybrid_keypair();
        login.save_identity(g_my_keypair, identity_path);
        g_has_keypair = true;

        // Upload public keys
        nlohmann::json pub_keys;
        pub_keys["x25519"] = to_hex(g_my_keypair.x25519_public, 32);
        pub_keys["kyber"] = to_hex(g_my_keypair.kyber_public.data(),
                                    g_my_keypair.kyber_public.size());
        login.upload_public_keys(g_keyserver_url, pub_keys.dump());
    }

    // Start background fetcher
    g_keep_fetching = true;
    g_fetcher_thread = std::thread(fetcher_loop);
    g_fetcher_thread.detach();

    env->ReleaseStringUTFChars(username, u);
    env->ReleaseStringUTFChars(password, p);
    env->ReleaseStringUTFChars(filesDir, fd);
    return JNI_TRUE;
}

// ─── Session Management ───
JNIEXPORT jstring JNICALL
Java_com_shushhh_app_NativeBridge_nativeConnect(JNIEnv* env, jclass,
    jstring peerUsername) {
    const char* peer = env->GetStringUTFChars(peerUsername, nullptr);
    std::string peer_name(peer);
    env->ReleaseStringUTFChars(peerUsername, peer);

    // Fetch peer's public keys
    std::string pub_keys_json = PasswordLogin::fetch_public_keys(g_keyserver_url, peer_name);
    if (pub_keys_json.empty()) {
        return env->NewStringUTF("{\"error\":\"Peer not found\"}");
    }

    try {
        auto j = nlohmann::json::parse(pub_keys_json);
        unsigned char their_x[32];
        from_hex(j["x25519"], their_x, 32);
        std::vector<unsigned char> their_k(1184);
        from_hex(j["kyber"], their_k.data(), 1184);

        std::vector<unsigned char> kyber_ct;
        g_current_session = create_session_initiator(g_my_keypair, their_x, their_k, kyber_ct);
        g_has_session = true;
        g_peer_username = peer_name;

        // Build and send 0-RTT handshake
        nlohmann::json inner;
        inner["sender"] = g_my_username;
        size_t b64_maxlen = sodium_base64_ENCODED_LEN(kyber_ct.size(),
            sodium_base64_VARIANT_ORIGINAL);
        std::string ct_b64(b64_maxlen, '\0');
        sodium_bin2base64(&ct_b64[0], b64_maxlen, kyber_ct.data(), kyber_ct.size(),
            sodium_base64_VARIANT_ORIGINAL);
        inner["kyber_ciphertext"] = ct_b64.c_str();

        HandshakePayload hs = generate_ephemeral_handshake(their_x, inner.dump());
        nlohmann::json outer;
        outer["type"] = "handshake";
        outer["ephemeral_public"] = to_base64(hs.ephemeral_public, 32);
        outer["blob"] = nlohmann::json::parse(encrypted_to_json(hs.encrypted_blob));

        nlohmann::json drop;
        drop["tag"] = to_hex(sha256_hash(g_peer_username).data(), 32);
        drop["blob"] = outer.dump();
        tor_post(g_msgserver_url + "/drop", drop.dump());

        {
            std::lock_guard<std::mutex> lock(g_chat_mutex);
            g_chat_history.push_back("[SYSTEM] Handshake sent to " + g_peer_username);
        }

        return env->NewStringUTF("{\"status\":\"ok\"}");
    } catch (...) {
        return env->NewStringUTF("{\"error\":\"Connection failed\"}");
    }
}

// ─── Send Message ───
JNIEXPORT jboolean JNICALL
Java_com_shushhh_app_NativeBridge_nativeSendMessage(JNIEnv* env, jclass,
    jstring message) {
    if (!g_has_session) return JNI_FALSE;

    const char* msg = env->GetStringUTFChars(message, nullptr);
    std::string plaintext(msg);
    env->ReleaseStringUTFChars(message, msg);

    if (plaintext.empty()) return JNI_FALSE;

    EncryptedMessage enc = session_encrypt(g_current_session, plaintext);
    nlohmann::json drop;
    drop["tag"] = to_hex(sha256_hash(g_peer_username).data(), 32);
    drop["blob"] = encrypted_to_json(enc);
    tor_post(g_msgserver_url + "/drop", drop.dump());

    {
        std::lock_guard<std::mutex> lock(g_chat_mutex);
        g_chat_history.push_back(g_my_username + "> " + plaintext);
    }

    return JNI_TRUE;
}

// ─── Get Chat History (returns JSON array of messages) ───
JNIEXPORT jstring JNICALL
Java_com_shushhh_app_NativeBridge_nativeGetMessages(JNIEnv* env, jclass) {
    nlohmann::json arr = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(g_chat_mutex);
        for (const auto& msg : g_chat_history) {
            arr.push_back(msg);
        }
    }
    return env->NewStringUTF(arr.dump().c_str());
}

// ─── Get Session State ───
JNIEXPORT jstring JNICALL
Java_com_shushhh_app_NativeBridge_nativeGetState(JNIEnv* env, jclass) {
    nlohmann::json state;
    state["has_keypair"] = g_has_keypair;
    state["has_session"] = g_has_session;
    state["username"] = g_my_username;
    state["peer"] = g_peer_username;
    state["tor_running"] = is_tor_running();
    state["msg_count"] = g_chat_history.size();
    return env->NewStringUTF(state.dump().c_str());
}

// ─── Self Destruct ───
JNIEXPORT void JNICALL
Java_com_shushhh_app_NativeBridge_nativeExecuteSelfDestruct(JNIEnv* env, jclass,
    jobject context) {
    // Stop fetcher
    g_keep_fetching = false;

    // Kill Tor
    kill_tor();

    // Execute full self-destruct sequence
    execute_self_destruct(env, context);
}

// ─── Cleanup ───
JNIEXPORT void JNICALL
Java_com_shushhh_app_NativeBridge_nativeCleanup(JNIEnv* env, jclass) {
    g_keep_fetching = false;
    kill_tor();
    wipe_all_keys();
    LOGI("Native cleanup complete");
}

} // extern "C"
