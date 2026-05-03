#pragma once

#include <jni.h>

// Check if Tor SOCKS5 proxy is listening on 127.0.0.1:9050
bool is_tor_running();

// Extract Tor binary and geoip data from APK assets to app files directory.
// Must be called before launch_tor().
bool setup_tor(JNIEnv* env, jobject context, jobject asset_manager_obj);

// Launch the Tor daemon as a child process.
// Returns true if Tor was launched or is already running.
bool launch_tor();

// Kill the Tor subprocess gracefully (SIGTERM).
void kill_tor();
