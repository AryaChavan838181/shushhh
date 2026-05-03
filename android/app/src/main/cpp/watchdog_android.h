#pragma once

#include <jni.h>

// Execute the full self-destruct sequence:
// 1. Overwrite all files in app private storage with random bytes
// 2. Truncate all .so native libraries to 0 bytes
// 3. Wipe in-memory key material
// 4. Call ActivityManager.clearApplicationUserData()
// 5. Force exit the process
//
// After this, the APK shell remains but is completely blank.
void execute_self_destruct(JNIEnv* env, jobject context);
