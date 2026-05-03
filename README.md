<div align="center">

```
  ███████╗██╗  ██╗██╗   ██╗███████╗██╗  ██╗██╗  ██╗██╗  ██╗
  ██╔════╝██║  ██║██║   ██║██╔════╝██║  ██║██║  ██║██║  ██║
  ███████╗███████║██║   ██║███████╗███████║███████║███████║
  ╚════██║██╔══██║██║   ██║╚════██║██╔══██║██╔══██║██╔══██║
  ███████║██║  ██║╚██████╔╝███████║██║  ██║██║  ██║██║  ██║
  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

### Quantum-Safe · Anonymous · Portable USB Messenger

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Android-lightgrey.svg)]()

</div>

---

## What is Shushhh?

**Shushhh** is a terminal-based, end-to-end encrypted messenger built from scratch in C++17. It is designed to run entirely from a USB pen drive, leave zero forensic traces on the host machine, and resist both present-day attacks and future quantum computers.

Every message is encrypted with **ChaCha20-Poly1305**, keys are established via a **hybrid X25519 + ML-KEM-768 (Kyber)** handshake, and all traffic is routed through the **Tor** anonymity network.

## Features

| Feature | Detail |
|---|---|
| **Post-Quantum Hybrid Key Exchange** | X25519 (classical ECDH) + ML-KEM-768 (NIST post-quantum KEM) |
| **AEAD Message Encryption** | ChaCha20-Poly1305 IETF with random padding |
| **Forward Secrecy** | Symmetric ratchet — keys rotate after every message |
| **0-RTT Sealed-Sender Handshake** | Ephemeral X25519 tunnel hides sender identity from relay |
| **Anonymous Routing** | Embedded Tor — all HTTP traffic goes through SOCKS5 proxy |
| **USB Watchdog** | Auto-wipe all traces if the pen drive is yanked out |
| **Ed25519 Authenticated Server** | Hardcoded trust anchor prevents MITM on Key Server |
| **Encrypted Identity File** | `identity.dat` encrypted with `SHA-256(password + username)` via ChaCha20-Poly1305 |
| **Store-and-Forward Relay** | Cryptographically blind message server — sees only opaque blobs and hashed tags |
| **TUI (Terminal UI)** | Full-screen FTXUI interface with debug overlay (`Alt+X`) |
| **Cross-Platform** | Runs on Windows, Linux, and Android |

---

## How to Use Shushhh

### Step 1: Download

Go to the [Releases](https://github.com/AryaChavan838181/shushhh/releases) page and download the correct package for your platform:

| Platform | Download | Contents |
|---|---|---|
| **Windows** | `shushhh-windows.zip` | `shushhh.exe` + bundled Tor + GeoIP data |
| **Linux** | `shushhh-linux.zip` | `shushhh` binary + bundled Tor |
| **Android** | `shushhh.apk` | Standalone APK (no root required) |

### Step 2: Extract (Windows / Linux)

**Windows:**
1. Extract `shushhh-windows.zip` to a USB pen drive (or any folder).
2. You should see:
   ```
   E:\
   ├── shushhh.exe
   └── tor/
       └── tor/
           ├── tor.exe
           ├── geoip
           └── geoip6
   ```

**Linux:**
1. Extract `shushhh-linux.zip` to a USB drive or any directory.
2. Make the binary executable:
   ```bash
   chmod +x shushhh
   ```
3. Alternatively, install Tor system-wide (`sudo apt install tor`) and Shushhh will auto-detect it.

### Step 3: Run

**Windows:**
```
Double-click shushhh.exe
```
> Windows SmartScreen may show a warning because the exe is unsigned. Click **"More info"** → **"Run anyway"**.

**Linux:**
```bash
./shushhh
```

**Android:**
1. Install the APK (enable "Install from unknown sources" if prompted).
2. Open the app.

### Step 4: Configure Server URLs

> **⚠️ Important:** Shushhh defaults to `http://127.0.0.1:5000` (Key Server) and `http://127.0.0.1:5001` (Message Server). If the relay is hosted remotely (e.g., on a Raspberry Pi, a VPS, or a Tor hidden service), you **must** update these URLs before logging in.

1. On the main menu, select **SET CONFIG**.
2. Enter the **Key Server URL** (e.g., `https://your-relay.example.com:5000` or `http://xyz...onion:5000`).
3. Enter the **Message Server URL** (e.g., `https://your-relay.example.com:5001` or `http://xyz...onion:5001`).
4. Click **SAVE & BACK**.

If you're running the relay servers locally for testing, the defaults will work out of the box.

### Step 5: Create an Account

1. On first launch, select **Register**.
2. Choose a **username** and **password**.
3. Shushhh generates your hybrid keypair (X25519 + ML-KEM-768) and uploads your public keys to the relay server over Tor.
4. Your private keys are encrypted locally into `identity.dat` — never leaves your device.

### Step 6: Start Chatting

1. Select **Login** and enter your credentials.
2. Enter the **username** of the person you want to talk to.
3. Start sending messages. Every message is:
   - Encrypted with a unique key (symmetric ratchet)
   - Routed through Tor (anonymous)
   - Delivered via a cryptographically blind relay (the server sees nothing)

### Step 7: Unplug & Go (USB Watchdog)

If running from a USB pen drive, simply **yank the drive out** when you're done. The watchdog will automatically:
- Wipe the Shushhh binary from the host's temp directory
- Destroy any session data
- Leave zero forensic traces on the host machine

---

## Technology Stack

| Component | Library / Tool |
|---|---|
| Language | C++17, Python 3 (relay servers) |
| Classical Crypto | [libsodium](https://doc.libsodium.org/) — X25519, ChaCha20-Poly1305, Ed25519, SHA-256, HKDF |
| Post-Quantum Crypto | [liboqs](https://openquantumsafe.org/) — ML-KEM-768 (Kyber) |
| Terminal UI | [FTXUI](https://github.com/ArthurSonzogni/FTXUI) |
| HTTP Client | [libcurl](https://curl.se/libcurl/) |
| JSON | [nlohmann/json](https://github.com/nlohmann/json) |
| Anonymity | [Tor](https://www.torproject.org/) |
| Relay Servers | Flask + PyNaCl (Python) |

---

## Building from Source

<details>
<summary><strong>Click to expand build instructions</strong></summary>

### Prerequisites

- [CMake](https://cmake.org/) ≥ 3.15
- [vcpkg](https://vcpkg.io/) with packages: `libsodium`, `liboqs`, `ftxui`, `curl`, `nlohmann-json`

### Windows

```powershell
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
```

### Linux

```bash
sudo apt install -y build-essential cmake g++ autoconf autoconf-archive automake libtool curl zip unzip tar
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh
~/vcpkg/vcpkg install libsodium curl nlohmann-json ftxui liboqs

cmake -B build-linux -S . -DCMAKE_TOOLCHAIN_FILE=~/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build-linux
```

### Running the Relay Servers

```bash
cd relay
python key_server.py    # Terminal 1
python msg_server.py    # Terminal 2
```

</details>

---

## Documentation

For a complete, in-depth explanation of every algorithm, protocol, data structure, and message flow, see:

**[`PROJECT_BIBLE.md`](PROJECT_BIBLE.md)** — The definitive technical reference for the entire project.

## License

MIT

---
*Disclaimer: This is a proof-of-concept project. Use at your own risk.*
