# shushhh — Project Overview

> Paranoid Pendrive Messenger | v0.3 | C++17 | libsodium | Tor

---

## What is shushhh?

shushhh is a portable, end-to-end encrypted messenger that runs entirely from a USB pendrive. No software is installed on the host machine. No messages are stored beyond the moment of delivery. No server operator can read any communication. The host laptop retains zero forensic evidence after the pendrive is removed.

The system is designed for two parties — each carrying a pendrive — who need to communicate through hostile environments where the network, the relay server, and the host computer itself may all be compromised.

---

## Core Security Invariants

These are non-negotiable properties of the system. Any code change that violates these is wrong by definition.

- Messages are encrypted **client-side before leaving the device**. The relay server receives opaque ciphertext only.
- Session keys **never reach the server**. The relay is cryptographically blind.
- Messages are **deleted from the relay on ACK**. No chat history exists server-side.
- Failed decryptions are **never ACK'd**, preventing Ratchet-freeze vulnerabilities.
- All network traffic **routes through Tor** (SOCKS5 proxy, `socks5h://127.0.0.1:9050`).
- The host laptop retains **zero forensic trace** after pendrive removal.
- Key material is **wiped from memory immediately** after use via `sodium_memzero()`.
- All security-sensitive comparisons use **`sodium_memcmp()`** — never `==` or `memcmp()`.

---

## Repository Structure

```text
shushhh/
├── Main.cpp                    # Entry point, menu loop, libcurl/Tor send
├── src/
│   ├── crypto/
│   │   ├── crypto.h            # All structs and function declarations
│   │   └── crypto.cpp          # All crypto implementations
│   ├── auth/
│   │   ├── auth.h
│   │   └── auth.cpp            # Identity, Login, Key Server logic
│   └── installer/
│       ├── Installer.h
│       └── Installer.cpp       # Stealth USB deployment logic
├── relay/
│   ├── key_server.py           # Authenticates users and serves Public Keys
│   └── msg_server.py           # Blind drop-box for encrypted message blobs
├── CMakeLists.txt              # Build config (vcpkg, static linking)
├── AGENT.md                    # Developer and AI agent guide
├── TRACKER.md                  # Feature tracker (What / How / Why)
└── docs/
    └── PROJECT_OVERVIEW.md     # This file
```

---

## Technology Stack

| Library | Purpose |
|---|---|
| libsodium | X25519, ChaCha20-Poly1305, HKDF, Ed25519, secure wipe |
| liboqs | ML-KEM-768 (Kyber) post-quantum key exchange |
| libcurl | HTTP transport with SOCKS5 Tor proxy |
| nlohmann/json | JSON serialization for EncryptedMessage |
| Tor | Network anonymization via .onion hidden service |
| SQLite | Relay message store (server-side) |
| LUKS | Full-disk encryption on relay volume (server-side) |
| CMake + vcpkg | Build system, static dependency management |

**Build triplet:** `x64-windows-static` — all client deps statically linked, single self-contained binary, no installation required.

---

## Key Data Structures

```cpp
// 32-byte X25519 keypair
struct KeyPair {
    unsigned char private_key[32];
    unsigned char public_key[32];
};

// A single encrypted message ready for transport
struct EncryptedMessage {
    unsigned char nonce[12];           // random per-message nonce (ChaCha20-Poly1305 IETF)
    std::vector<unsigned char> ciphertext;
    unsigned char tag[16];             // Poly1305 authentication tag
};

// Full session state between two clients
struct MessageSession {
    KeyPair my_keypair;
    unsigned char their_public_key[32];
    std::vector<unsigned char> root_key;    // derived from X25519 + Kyber
    std::vector<unsigned char> send_key;    // ratchets forward after each send
    std::vector<unsigned char> recv_key;    // ratchets forward after each recv
    uint32_t send_counter;                  // replay protection + ratchet index
    uint32_t recv_counter;
};
```

---

## Split-Server Architecture

```text
[Pendrive A]  ──Tor──►  [.onion Key Server]  ◄──Tor──  [Pendrive B]
      │                        (Port 5000)                   │
      │                                                      │
      └─────────Tor──►  [.onion Msg Server]  ◄──Tor──────────┘
                               (Port 5001) 
```

We utilize a **Split-Server** architecture to decouple identity from messaging:
1. **Key Server:** Handles `/auth`, stores X25519 and ML-KEM-768 public keys, and verifies Ed25519 signatures. It knows who exists but holds no messages.
2. **Message Server:** A completely blind drop-box. It holds opaque ciphertexts mapped to a `SHA256(username)` tag. It has no concept of identity, authentication, or keys.

---

## Detailed End-to-End Lifecycle Flowchart

### 1. Deployment & Launch
```text
[ Pendrive Inserted ]
       │
       ▼
[ User runs shushhh.exe ] ──(Installer.cpp logic)──► Copies Tor & hidden dependencies to the USB.
       │                                             Sets Windows File Attributes to Hidden.
       ▼
[ Watchdog Spawned ] ───────► Runs in background, constantly polling the USB drive letter.
       │                      If USB is unplugged -> instantly runs cipher /w and deletes everything.
       ▼
[ Tor Daemon Auto-Launch ] ─► shushhh.exe silently spins up tor.exe in the background on port 9050.
```

### 2. Authentication & Identity
```text
[ Main Menu ]
       │
       ▼
[ User Selects "Login" or "Register" ]
       │
       ▼
[ Client hashes Password + Username ] ─(Client-side)─► Raw password is wiped from RAM.
       │
       ▼
[ HTTPS POST to Key Server (Port 5000) ]
       │
       ▼
[ Key Server /auth ] ────────► Checks hash. If valid, signs an Ed25519 token.
       │                       Stores/Serves the user's X25519 and ML-KEM-768 Public Keys.
       ▼
[ Client Receives Token ] ───► Verifies Ed25519 signature against hardcoded Trust Anchor.
                               Loads or generates `identity.dat` from USB (AES-encrypted).
```

### 3. Session Handshake (Hybrid Post-Quantum)
```text
[ User Selects "Create Session" ]
       │
       ▼
[ Initiator (Alice) ] ────────► Types recipient username ("Bob").
       │
       ▼
[ Key Server Fetch ] ─────────► Alice automatically fetches Bob's X25519 & Kyber Public Keys from Key Server.
       │
       ▼
[ KEM Encapsulation ] ────────► Alice performs ECDH on X25519, and Encapsulates ML-KEM-768.
       │                        Produces a 1088-byte Kyber Ciphertext.
       ▼
[ Key Derivation (HKDF) ] ────► Root Key = HKDF(X25519_Secret || Kyber_Secret)
       │                        Session initialized: send_key_0, recv_key_0.
       ▼
[ Handshake Transfer ] ───────► Alice sends the 1088-byte Kyber Ciphertext to Bob (via secure out-of-band).
       │
       ▼
[ Responder (Bob) ] ──────────► Pastes the Kyber Ciphertext.
       │                        Performs ECDH, Decapsulates ML-KEM-768 to extract the same Kyber Secret.
       ▼
[ Key Derivation (HKDF) ] ────► Root Key = HKDF(X25519_Secret || Kyber_Secret)
                                Session perfectly synchronized.
```

### 4. Message Encryption & Send (The Ratchet)
```text
[ User Types Message ] ───────► "Target coordinates secured."
       │
       ▼
[ Padding ] ──────────────────► Appends random bytes to make the plaintext exactly 512 bytes (defeats traffic analysis).
       │
       ▼
[ Encryption ] ───────────────► crypto_aead_chacha20poly1305_ietf_encrypt(padded_msg, send_key_N, nonce)
       │                        Outputs: Ciphertext + 16-byte MAC Tag.
       ▼
[ Turn the Ratchet ] ─────────► send_key_N+1 = HKDF(send_key_N)
       │                        secure_wipe(send_key_N).
       ▼
[ JSON Serialization ] ───────► Packages Base64(nonce, ciphertext, tag).
       │
       ▼
[ HTTP POST to Msg Server ] ──► POST /drop (Port 5001).
                                Tag = SHA256(Bob's Username).
```

### 5. Message Fetch & Decrypt (Anti-Freeze Logic)
```text
[ Bob Selects "Fetch" ] ──────► GET /fetch?tag=SHA256(Bob's Username)
       │
       ▼
[ Msg Server Responds ] ──────► Returns JSON array of opaque blobs.
       │
       ▼
[ JSON Deserialization ] ─────► Extracts Base64 nonce, ciphertext, tag.
       │
       ▼
[ Decryption Attempt ] ───────► crypto_aead_chacha20poly1305_ietf_decrypt(blob, recv_key_N, nonce, tag)
       │
       ├─ [ If MAC Tag Fails / Keys Mismatched ]
       │      │
       │      ▼
       │  Message Rejected.
       │  Ratchet is FROZEN (does not advance).
       │  ACK is NOT sent to server (prevents permanent desync).
       │
       └─ [ If Decryption Succeeds ]
              │
              ▼
          Message printed to screen!
              │
              ▼
          [ Turn the Ratchet ] ──► recv_key_N+1 = HKDF(recv_key_N)
              │                    secure_wipe(recv_key_N)
              ▼
          [ Send ACK ] ──────────► POST /ack to Msg Server.
              │
              ▼
          [ Msg Server ] ────────► Hard Deletes Message from SQLite DB.
```

---

## Watchdog Auto-Wipe

### Flow

```text
pendrive inserted
        │
        ▼
shushhh.exe launches from USB (no install)
        │
        ▼
launch_watchdog() — CreateProcess(DETACHED_PROCESS)
        │  extracts watchdog.exe + shushhh_wipe.bat to %TEMP%
        │  watchdog survives shushhh.exe being closed or killed
        │
        ▼
watchdog poll loop (every 2 seconds)
        │
        ├─ GetLogicalDrives() — is USB drive letter still present?
        │
        ├─ YES → sleep 2s, repeat
        │
        └─ NO  → execute wipe sequence immediately
                      │
                      ▼
                 cipher /w:%TEMP%              ← overwrites free disk sectors
                 del /f /q %TEMP%\shushhh_*   ← removes temp files
                 del /f /q %APPDATA%\shushhh_*
                 [watchdog self-deletes]       ← zero artifacts remain
```

### Why `cipher /w` Matters

Standard `del` only removes the directory entry — the data sectors remain on disk and are recoverable with forensic tools (Recuva, Autopsy, FTK Imager). `cipher /w` overwrites all free space sectors with random data, making previously deleted files unrecoverable. This is the difference between "file deleted" and "file destroyed".

---

## Cryptographic Primitive Selection

| Primitive | Algorithm | Why |
|---|---|---|
| Key exchange | X25519 | Constant-time, 128-bit classical security, widely audited |
| PQ key exchange | ML-KEM-768 (Kyber) | NIST FIPS 203, 128-bit post-quantum security, lattice-based |
| Symmetric encryption | ChaCha20-Poly1305 | AEAD — authentication built in, timing-attack resistant |
| Key derivation | HKDF-SHA256 (RFC 5869) | Separates extraction from expansion, context-bound via info string |
| Auth signatures | Ed25519 | Fast, small, deterministic, constant-time verify |
| Memory wipe | sodium_memzero() | Cannot be optimized away by compiler |
| Comparison | sodium_memcmp() | Constant-time — prevents timing side-channel |

### Why Hybrid PQ (X25519 + Kyber)?

```text
X25519 alone  →  broken by Shor's algorithm on quantum computer
Kyber alone   →  newer primitive, less real-world analysis
X25519 + Kyber →  attacker must break BOTH simultaneously
                   classical attacker: stopped by X25519
                   quantum attacker:   stopped by Kyber
```

Combined IKM into HKDF:
```text
combined_ikm = x25519_shared_secret[32] || kyber_shared_secret[32]
root_key     = HKDF-SHA256(ikm=combined_ikm, info="shushhh_session_key_v1", len=32)
```

---

## Threat Model

| Threat | Mitigation | Phase |
|---|---|---|
| Passive network interception | ChaCha20-Poly1305 E2E encryption | Done |
| Message length analysis | All blobs padded to uniform 512 bytes | Done |
| IP / routing exposure | Tor 3-hop hidden service | Done |
| Replay attacks | send_counter / recv_counter + Ratchet | Done |
| Quantum computer (Shor's) | ML-KEM-768 hybrid key exchange | Done |
| Key capture (past sessions) | Symmetric ratchet + secure_wipe | Done |
| Relay server compromise | Server is blind — no session keys | Done |
| MITM on authentication | Ed25519 signed server responses | Done |
| Host laptop forensics | Watchdog wipe on USB disconnect | Done |
| Timing attacks on auth | sodium_memcmp() constant-time | Done |
| Physical seizure of relay | LUKS encryption + disguised schema | Done |

---

## Implementation Phases

### Phase 0 — Core Crypto (Completed)
- [x] F-01 libsodium initialization
- [x] F-02 X25519 key exchange
- [x] F-03 ChaCha20-Poly1305 encryption with 512-byte padding
- [x] F-04 HKDF-SHA256 key derivation
- [x] F-05 MessageSession management
- [x] F-06 JSON serialization + Tor transport via libcurl
- [x] F-07 Secure memory wipe

### Phase 1 — Infrastructure (Completed)
- [x] F-08 LoginProvider interface + PasswordLogin
- [x] F-09 Ed25519 signed server auth responses
- [x] F-10 Split Server (Key Server / Msg Server)
- [x] F-11 Watchdog auto-wipe on USB disconnect + Stealth Installer

### Phase 2 — Advanced Security (Completed)
- [x] F-12 ML-KEM-768 hybrid key exchange (liboqs)
- [x] F-13 Symmetric ratchet (forward secrecy) + Anti-Freeze Logic

### Future
- [ ] F-14 Alternative LoginProvider (advanced auth method TBD)
- [ ] F-15 Double ratchet (Signal-protocol-style break-in recovery via continuous Kyber)

---

## Cross-Platform Notes

The crypto core (`crypto.h` / `crypto.cpp`) is fully platform-agnostic C++17. All dependencies (libsodium, libcurl, liboqs, nlohmann/json) build on Windows, Linux, and Android.

Platform-specific code is limited to:
- **Watchdog wipe / Installer** — uses `CreateProcess`, `GetLogicalDrives`, `cipher /w`, `SetFileAttributesW` (Windows)
- **UI layer** — currently a terminal loop in `Main.cpp`

When adding Linux or Android targets, isolate these behind a `Platform` interface.

---

## Security Rules for Contributors

- Never log, print, or serialize raw key material
- Never store keys or plaintext to disk on the host
- Never skip `secure_wipe()` after key material goes out of scope
- Never use `==` or `memcmp()` for auth tags, hashes, or passwords
- Never send traffic outside `socks5h://127.0.0.1:9050` (or local test relays)
- Never store raw passwords — hash client-side, store salted hash server-side
- Never hardcode keys, credentials, or server addresses in source
- **Never unconditionally ACK messages** — only delete messages that successfully decrypt.

---

*shushhh — built from scratch. Designed to be unreadable, untraceable, and uncompromising.*