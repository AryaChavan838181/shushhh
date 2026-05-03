# shushhh — Android

> Quantum-Safe · Anonymous · USB-Tethered · Self-Destructing Android Messenger

---

## What Is This?

The Android port of **shushhh** — the same quantum-safe encrypted messenger, running on your phone. Install the APK from a USB OTG drive, and when the drive is unplugged, the app **self-destructs** — overwriting all native code, keys, and data with random bytes. Anyone analyzing the app afterward finds an empty shell.

## Architecture

```
┌───────────────────────────────────┐
│           WebView UI              │  ← Touch-optimized HTML/CSS/JS
├───────────────────────────────────┤
│     Java Layer (Activity +        │  ← USB monitoring, WebView host
│     Foreground Service)           │
├───────────────────────────────────┤
│     JNI Bridge (jni_bridge.cpp)   │  ← Connects Java ↔ C++
├───────────────────────────────────┤
│     C++ Crypto Core               │  ← crypto.cpp + auth.cpp (REUSED)
│     (libsodium + liboqs + curl)   │     100% same code as Windows
├───────────────────────────────────┤
│     Tor Subprocess                │  ← Bundled arm64 tor binary
└───────────────────────────────────┘
```

## Self-Destruct Mechanism

When USB OTG is disconnected:

1. **BroadcastReceiver** fires `ACTION_USB_DEVICE_DETACHED`
2. **Foreground Service** triggers native `execute_self_destruct()`
3. All files in app storage → overwritten with `randombytes_buf()` → truncated to 0
4. Native `.so` libraries → truncated to 0 bytes (hollow husk)
5. All in-memory keys → `sodium_memzero()`
6. `ActivityManager.clearApplicationUserData()` → kills process

**Result:** APK shell remains, but contains literally nothing. Empty files, no code, no data.

## Build Instructions

### Prerequisites

- **Android Studio** with NDK 26+ and CMake 3.22+
- **Git** (for cloning dependency repos)
- **PowerShell** (for build scripts — you're on Windows)

### Step 1: Build Native Dependencies

```powershell
cd android
.\build_libs.ps1
```

This cross-compiles libsodium, liboqs, and libcurl for `arm64-v8a` and places the `.a` files and headers in `app/src/main/cpp/`.

### Step 2: Download Tor Bundle

```powershell
.\download_tor.ps1
```

Downloads the official Tor Expert Bundle for Android arm64 and extracts the `tor` binary to `app/src/main/assets/tor/`.

**Manual alternative:** Download `tor-expert-bundle-android-aarch64-*.tar.gz` from [https://dist.torproject.org/torbrowser/](https://dist.torproject.org/torbrowser/) and place the `tor` binary at `app/src/main/assets/tor/tor`.

### Step 3: Build APK

```powershell
# Using Gradle wrapper
.\gradlew assembleDebug

# Or in Android Studio: Build → Build Bundle(s) / APK(s) → Build APK(s)
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

### Step 4: Deploy to USB

Copy the APK to a USB OTG drive:

```powershell
Copy-Item app\build\outputs\apk\debug\app-debug.apk E:\shushhh.apk
```

### Step 5: Install on Phone

1. Plug the USB OTG drive into the Android phone
2. Open a file manager, navigate to the USB drive
3. Tap `shushhh.apk` → Install
4. Launch the app
5. **DO NOT unplug the USB** until you're done messaging

When you unplug the USB drive, the app self-destructs.

## Technology Stack

| Component | Library |
|---|---|
| Language | C++17 (native) + Java (Android) |
| Classical Crypto | libsodium (X25519, ChaCha20-Poly1305, Ed25519, HKDF) |
| Post-Quantum Crypto | liboqs (ML-KEM-768 / Kyber) |
| HTTP Client | libcurl (with SOCKS5 Tor proxy) |
| JSON | nlohmann/json (header-only) |
| Anonymity | Tor Expert Bundle (arm64) |
| UI | WebView (HTML/CSS/JS) |
| USB Detection | Android USB Host API + BroadcastReceiver |

## Security Properties

All security properties from the Windows version are preserved:
- ✅ End-to-end encryption (ChaCha20-Poly1305)
- ✅ Post-quantum key exchange (X25519 + ML-KEM-768)
- ✅ Forward secrecy (symmetric HKDF ratchet)
- ✅ Anonymous routing (Tor SOCKS5)
- ✅ Zero forensic trace (self-destruct on USB disconnect)
- ✅ Blind relay server (no server-side decryption)
- ✅ Ed25519 authenticated server responses
- ✅ Screenshot prevention (FLAG_SECURE)

---

*shushhh — now on Android. Same crypto. Same paranoia. Touch screen.*
