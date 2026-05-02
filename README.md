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
| **Self-Contained Installer** | Single `.exe` with `shushhh.exe` and `tor.exe` embedded as Win32 resources |

## Technology Stack

| Component | Library / Tool |
|---|---|
| Language | C++17, Python 3 (relay servers) |
| Classical Crypto | [libsodium](https://doc.libsodium.org/) — X25519, ChaCha20-Poly1305, Ed25519, SHA-256, HMAC-SHA256, HKDF |
| Post-Quantum Crypto | [liboqs](https://openquantumsafe.org/) — ML-KEM-768 (Kyber) |
| Terminal UI | [FTXUI](https://github.com/ArthurSonzogni/FTXUI) |
| HTTP Client | [libcurl](https://curl.se/libcurl/) |
| JSON | [nlohmann/json](https://github.com/nlohmann/json) |
| Anonymity | [Tor Expert Bundle](https://www.torproject.org/) |
| Relay Servers | Flask + PyNaCl (Python) |

## Quick Start

### Prerequisites

- Windows 10/11 (x64)
- [CMake](https://cmake.org/) ≥ 3.15
- [vcpkg](https://vcpkg.io/) with the following packages installed for triplet `x64-windows-static`:
  - `libsodium`, `liboqs`, `ftxui`, `curl`, `nlohmann-json`

### Build

```powershell
# Configure
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static

<<<<<<< HEAD
# Build (Release)
cmake --build build --config Release
```
=======
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AryaChavan838181/shushhh.git
    cd shushhh
    ```
>>>>>>> 380e785d6fcbbe88ccc12740e83bea680e949a12

### Run

```powershell
# Start relay servers (in separate terminals)
cd relay
python key_server.py
python msg_server.py

# Launch the messenger
.\build\Release\shushhh.exe
```

### Deploy to USB

The self-contained installer embeds `shushhh.exe` and `tor.exe` as Win32 resources. Place `tor/tor/tor.exe` in the project root before building, then:

```powershell
.\build\Release\shushhh_installer.exe
```

Select a USB drive from the auto-detected list and click **INSTALL**.

## Documentation

For a complete, in-depth explanation of every algorithm, protocol, data structure, and message flow, see:

**[`PROJECT_BIBLE.md`](PROJECT_BIBLE.md)** — The definitive technical reference for the entire project.

<<<<<<< HEAD
## License

MIT
=======
---
*Disclaimer: This is a proof-of-concept project. Use at your own risk.*
>>>>>>> 380e785d6fcbbe88ccc12740e83bea680e949a12
