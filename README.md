<div align="center">
  <pre style="color: #4169E1; font-weight: bold;">
  ███████╗██╗  ██╗██╗   ██╗███████╗██╗  ██╗██╗  ██╗██╗  ██╗
  ██╔════╝██║  ██║██║   ██║██╔════╝██║  ██║██║  ██║██║  ██║
  ███████╗███████║██║   ██║███████╗███████║███████║███████║
  ╚════██║██╔══██║██║   ██║╚════██║██╔══██║██╔══██║██╔══██║
  ███████║██║  ██║╚██████╔╝███████║██║  ██║██║  ██║██║  ██║
  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
  </pre>

  <h3>Quantum-Safe Encrypted Messenger</h3>

  <p>
    A high-security, anonymous, terminal-based messaging application featuring Post-Quantum Cryptography (ML-KEM-768) and Tor integration.
  </p>
</div>

---

## 🔒 Features

*   **Quantum-Safe Cryptography**: Utilizes a hybrid key exchange combining classical **X25519** and post-quantum **Kyber (ML-KEM-768)** to protect against "harvest now, decrypt later" attacks.
*   **0-RTT End-to-End Encryption**: Fast, secure session establishment. All messages are encrypted with **XChaCha20-Poly1305** using a ratcheting protocol for forward secrecy.
*   **Anonymous Routing (Tor)**: Built-in Tor integration hides your IP address and routes all traffic through the Tor network.
*   **Self-Contained Portable USB**: Deploy `shushhh` to a USB drive. A built-in **Watchdog** monitors the drive; if the USB is yanked out, it instantly securely wipes all ephemeral data from the host machine using forensic wiping (`cipher /w`).
*   **Ninja/Spy Aesthetic TUI**: A beautiful, high-contrast Terminal User Interface built with [FTXUI](https://github.com/ArthurSonzogni/FTXUI).

## 🛠️ Technology Stack

*   **C++17**: Core application logic and UI.
*   **libsodium**: Classical cryptography (X25519, XChaCha20-Poly1305, Argon2, Ed25519).
*   **liboqs**: Post-quantum cryptography (ML-KEM-768).
*   **FTXUI**: Terminal UI framework.
*   **Tor**: Embedded anonymous routing.

## 🚀 Getting Started

### Prerequisites

You need `cmake` and `vcpkg` installed on Windows to build the project.

Dependencies managed via `vcpkg`:
*   `libsodium`
*   `liboqs`
*   `ftxui`
*   `curl`
*   `nlohmann-json`

### Build Instructions

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AryaChavan838181/shushhh.git
    cd shushhh
    ```

2.  **Configure CMake:**
    Make sure to point to your `vcpkg` toolchain.
    ```powershell
    cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
    ```

3.  **Build the Project:**
    ```powershell
    cmake --build build --config Release
    ```

## 💾 Standalone USB Installer

`shushhh` comes with a custom installer that embeds the executable (and optionally Tor) directly into a single `shushhh_installer.exe`. 

Run the installer, select a target USB drive from the TUI list, and it will safely deploy the hidden environment to the drive.

## 🕵️ Usage

1.  Launch `shushhh.exe`.
2.  **Register/Login**: Your keys are generated locally. The public keys are uploaded to the Key Server, while the private keys remain encrypted on your device.
3.  **Setup**: Enter your peer's username to initiate a secure connection.
4.  **Chat**: Messages are sent directly through the secure relay over Tor.

> **Note:** Press `Alt+X` inside the app to toggle the Debug Window and view background logs, cryptographic handshakes, and Tor status.

## 🛡️ Security Architecture

*   **Authentication**: Password hashing is done via **Argon2**, and Key Server requests are signed with **Ed25519** signatures.
*   **Identity**: Your identity file (`identity.dat`) is encrypted at rest using your password hash.
*   **Anti-Forensics**: The watchdog ensures no decrypted data or temporary routing files remain on the host computer if the drive is unexpectedly disconnected.

---
*Disclaimer: This is a proof-of-concept project. Use at your own risk.*
