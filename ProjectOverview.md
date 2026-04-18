# shushhh — Project Overview

> Paranoid Pendrive Messenger | v0.2 | C++17 | libsodium | Tor

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
- All network traffic **routes through Tor** (SOCKS5 proxy, `socks5h://127.0.0.1:9050`).
- The host laptop retains **zero forensic trace** after pendrive removal.
- Key material is **wiped from memory immediately** after use via `sodium_memzero()`.
- All security-sensitive comparisons use **`sodium_memcmp()`** — never `==` or `memcmp()`.

---

## Repository Structure

```
shushhh/
├── Main.cpp                    # Entry point, menu loop, libcurl/Tor send
├── src/
│   └── crypto/
│       ├── crypto.h            # All structs and function declarations
│       └── crypto.cpp          # All crypto implementations
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
| liboqs | ML-KEM-768 (Kyber) post-quantum key exchange — Phase 2 |
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
    std::vector<unsigned char> root_key;    // derived from X25519 (+ Kyber in Phase 2)
    std::vector<unsigned char> send_key;    // ratchets forward after each send (Phase 2)
    std::vector<unsigned char> recv_key;    // ratchets forward after each recv (Phase 2)
    uint32_t send_counter;                  // replay protection + ratchet index
    uint32_t recv_counter;
};
```

---

## Key Functions

| Function | File | Purpose |
|---|---|---|
| `crypto_init()` | crypto.cpp | Initialize libsodium — must be called first |
| `generate_x25519_keypair()` | crypto.cpp | Generate fresh X25519 keypair |
| `compute_x25519_shared_secret()` | crypto.cpp | ECDH shared secret derivation |
| `hkdf_derive(ikm, salt, info, len)` | crypto.cpp | HKDF-SHA256 — all keys flow through here |
| `encrypt_message(plaintext, key, 512)` | crypto.cpp | Pad + nonce + ChaCha20-Poly1305 encrypt |
| `decrypt_message(encrypted, key)` | crypto.cpp | Verify Poly1305 tag + decrypt + strip padding |
| `session_encrypt(session, plaintext)` | crypto.cpp | Per-message encrypt with counter management |
| `session_decrypt(session, encrypted)` | crypto.cpp | Per-message decrypt with counter management |
| `encrypted_to_json(msg)` | crypto.cpp | Serialize EncryptedMessage to base64 JSON |
| `json_to_encrypted(json_str)` | crypto.cpp | Deserialize JSON back to EncryptedMessage |
| `secure_wipe(ptr, len)` | crypto.cpp | `sodium_memzero()` wrapper — compiler-safe erase |

---

## System Architecture

### Physical Components

```
[Pendrive A]  ──Tor──►  [.onion Relay]  ◄──Tor──  [Pendrive B]
     │                        │                          │
  shushhh.exe            blind store               shushhh.exe
  all crypto             forward only              all crypto
  watchdog               LUKS + SQLite             watchdog
```

- **Pendrive A and B** never communicate directly. All traffic flows through the relay over separate Tor circuits. The relay sees neither party's real IP.
- **The relay** cannot decrypt anything. It stores hashed routing tags and opaque ciphertext blobs.

### Three Layers of Anonymity

1. **Content** — ChaCha20-Poly1305 E2E encryption. Server sees ciphertext only.
2. **Routing** — Tor hidden service. Neither party's IP is exposed.
3. **Identity** — Recipient routing tag = `SHA-256(their_public_key)`. No real identifiers stored.

---

## Message Send Path (Full Transformation Chain)

### One-time Session Setup

```
generate_x25519_keypair()           →  32-byte pub/priv keypair
kyber_keygen() [Phase 2]            →  1184-byte pub, 2400-byte priv (ML-KEM-768)

[exchange public keys out-of-band]

compute_x25519_shared_secret()      →  32-byte X25519 shared secret
kyber_encapsulate() [Phase 2]       →  32-byte Kyber secret + 1088-byte ciphertext to peer

hkdf_derive(
    ikm   = x25519_secret || kyber_secret,   // 64 bytes total in Phase 2, 32 in Phase 0
    salt  = nullptr,
    info  = "shushhh_session_key_v1",
    len   = 32
)                                   →  session.send_key / session.recv_key
```

### Per-message Send

```
user types plaintext
        │
        ▼
session_encrypt(session, plaintext)
        │  calls encrypt_message()
        │
        ├─ randombytes_buf(nonce, 12)         →  fresh 12-byte nonce every message
        ├─ length prefix (4-byte big-endian)  →  prepended to plaintext
        ├─ randombytes_buf(padding)            →  random fill to exactly 512 bytes
        └─ chacha20poly1305_encrypt()         →  ciphertext + 16-byte Poly1305 tag
        │
        ▼
EncryptedMessage { nonce[12], ciphertext, tag[16] }
        │
        ▼  [Phase 2 — ratchet]
hkdf_derive(send_key, info="shushhh_ratchet_v1:N")  →  next_key
secure_wipe(send_key)                                →  old key gone forever
send_key = next_key
send_counter++
        │
        ▼
encrypted_to_json()
        │  base64_encode(nonce) + base64_encode(ciphertext) + base64_encode(tag)
        │
        ▼
{"nonce":"...","ciphertext":"...","tag":"..."}
        │
        ▼
libcurl POST
        │  CURLOPT_PROXY = socks5h://127.0.0.1:9050
        │  CURLOPT_URL   = http://[relay].onion/drop
        │
        ▼
Tor network (3 hops)
        │
        ▼
.onion relay — stores blob, keyed by SHA-256(recipient_public_key)
```

### Per-message Receive

```
.onion relay (GET /fetch?tag=SHA256(my_pub))
        │
        ▼
JSON payload arrives via Tor
        │
        ▼
json_to_encrypted()
        │  base64_decode all fields → EncryptedMessage struct
        │
        ▼
session_decrypt(session, encrypted)
        │  calls decrypt_message()
        │
        ├─ reassemble ciphertext || tag
        ├─ chacha20poly1305_decrypt()     →  verify Poly1305 tag first
        │    tag fail → return ""         →  message rejected entirely
        ├─ strip 4-byte length header
        └─ strip random padding
        │
        ▼
plaintext string returned to caller
        │
        ▼  [Phase 2 — ratchet]
hkdf_derive(recv_key, info="shushhh_ratchet_v1:N")  →  next_key
secure_wipe(recv_key)
recv_key = next_key
recv_counter++
        │
        ▼
ACK sent to relay → message hard-deleted from server
```

---

## Authentication Flow

### LoginProvider Interface (Phase 1)

```cpp
class LoginProvider {
public:
    virtual bool authenticate() = 0;
    virtual std::vector<unsigned char> get_credential_hash() = 0;
    virtual ~LoginProvider() = default;
};

// Phase 1 implementation
class PasswordLogin : public LoginProvider { ... };

// Future: swap in without touching anything else
class FutureLogin : public LoginProvider { ... };
```

### Password Auth Sequence

```
user enters username + password (never touches host disk)
        │
        ▼
SHA-256(password + username)            →  credential hash (client-side)
        │  raw password never leaves device
        ▼
encrypt_message(hash, auth_key)         →  encrypted credential blob
        │
        ▼
POST to /auth via Tor
        │
        ▼  [server side]
lookup (username, stored_salt)
SHA-256(password + stored_salt)
sodium_memcmp(computed, stored)         →  constant-time — no timing leak
        │
        ▼
crypto_sign_ed25519(response, server_priv_key)   →  signed response
        │
        ▼  [client side]
crypto_sign_ed25519_verify(response, server_pub_key)
        │  server pubkey hardcoded in binary — MITM impossible
        ▼
session established
```

---

## Relay Server Design

### Endpoints

| Endpoint | Method | Action |
|---|---|---|
| `/auth` | POST | Verify credentials, return signed token |
| `/drop` | POST | Store ciphertext blob for recipient |
| `/fetch` | GET | Return blobs for authenticated recipient |
| `/ack` | POST | Confirm delivery — hard-delete message |

### Storage Schema (Disguised)

The SQLite schema is deliberately named to look like analytics telemetry:

```sql
CREATE TABLE telemetry_events (
    event_id          TEXT PRIMARY KEY,     -- random UUID
    device_fingerprint TEXT NOT NULL,       -- SHA-256(recipient_public_key)
    payload           BLOB NOT NULL,        -- EncryptedMessage JSON blob
    ts                INTEGER NOT NULL,     -- unix timestamp
    ttl               INTEGER DEFAULT 604800 -- auto-expire 7 days
);
```

A forensic examiner without context sees what appears to be application analytics data. The payload column contains ChaCha20-Poly1305 ciphertext that is unreadable without the session key, which never reaches the server.

### Storage Security Layers

```
Layer 1: E2E encryption        — server cannot decrypt payload
Layer 2: Hashed routing tags   — server never sees real identities
Layer 3: Disguised schema      — looks like telemetry to a casual examiner
Layer 4: LUKS disk encryption  — raw partition is random noise without volume key
Layer 5: Delete on ACK         — messages exist on server for minimum possible time
```

---

## Watchdog Auto-Wipe

### Flow

```
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

```
X25519 alone  →  broken by Shor's algorithm on quantum computer
Kyber alone   →  newer primitive, less real-world analysis
X25519 + Kyber →  attacker must break BOTH simultaneously
                   classical attacker: stopped by X25519
                   quantum attacker:   stopped by Kyber
```

Combined IKM into HKDF:
```
combined_ikm = x25519_shared_secret[32] || kyber_shared_secret[32]
root_key     = HKDF-SHA256(ikm=combined_ikm, info="shushhh_session_key_v1", len=32)
```

Only `create_session()` changes. Everything downstream is untouched.

---

## Threat Model

| Threat | Mitigation | Phase |
|---|---|---|
| Passive network interception | ChaCha20-Poly1305 E2E encryption | Done |
| Message length analysis | All blobs padded to uniform 512 bytes | Done |
| IP / routing exposure | Tor 3-hop hidden service | Done |
| Replay attacks | send_counter / recv_counter | Done |
| Quantum computer (Shor's) | ML-KEM-768 hybrid key exchange | Phase 2 |
| Key capture (past sessions) | Symmetric ratchet + secure_wipe | Phase 2 |
| Relay server compromise | Server is blind — no session keys | Phase 1 |
| MITM on authentication | Ed25519 signed server responses | Phase 1 |
| Host laptop forensics | Watchdog wipe on USB disconnect | Phase 1 |
| Timing attacks on auth | sodium_memcmp() constant-time | Phase 1 |
| Physical seizure of relay | LUKS encryption + disguised schema | Phase 1 |

---

## Implementation Phases

### Phase 0 — Start
- [ ] F-01 libsodium initialization
- [ ] F-02 X25519 key exchange
- [ ] F-03 ChaCha20-Poly1305 encryption with 512-byte padding
- [ ] F-04 HKDF-SHA256 key derivation
- [ ] F-05 MessageSession management
- [ ] F-06 JSON serialization + Tor transport via libcurl
- [ ] F-07 Secure memory wipe

### Phase 1 — Next
- [ ] F-08 LoginProvider interface + PasswordLogin
- [ ] F-09 Ed25519 signed server auth responses
- [ ] F-10 .onion store-and-forward relay server
- [ ] F-11 Watchdog auto-wipe on USB disconnect

### Phase 2 — Planned
- [ ] F-12 ML-KEM-768 hybrid key exchange (liboqs)
- [ ] F-13 Symmetric ratchet (forward secrecy)

### Future
- [ ] F-14 Alternative LoginProvider (advanced auth method TBD)
- [ ] F-15 Double ratchet (Signal-protocol-style break-in recovery)

---

## Cross-Platform Notes

The crypto core (`crypto.h` / `crypto.cpp`) is fully platform-agnostic C++17. All dependencies (libsodium, libcurl, liboqs, nlohmann/json) build on Windows, Linux, and Android.

Platform-specific code is limited to:
- **Watchdog wipe** — uses `CreateProcess`, `GetLogicalDrives`, `cipher /w` (Windows)
- **UI layer** — currently a terminal loop in `Main.cpp`

When adding Linux or Android targets, isolate these behind a `Platform` interface:

```cpp
class Platform {
public:
    virtual void launch_watchdog() = 0;
    virtual bool is_pendrive_present() = 0;
    virtual void wipe_temp_files() = 0;
    static std::unique_ptr<Platform> create();
};
```

CMake selects the right implementation per target:
```cmake
if(WIN32)
    target_sources(shushhh PRIVATE platform/windows_platform.cpp)
elseif(ANDROID)
    target_sources(shushhh PRIVATE platform/android_platform.cpp)
elseif(UNIX)
    target_sources(shushhh PRIVATE platform/linux_platform.cpp)
endif()
```

**Linking strategy by target:**

| Target | Linking | Reason |
|---|---|---|
| Windows pendrive | Static | Zero host dependencies |
| Linux pendrive | Static | One binary, runs on any distro |
| Linux relay server | Dynamic .so | Known environment, dynamic is fine |
| Android | Shared .so via JNI | Android's APK model requires it |

---

## Build Commands

```bash
# Configure
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows-static

# Build
cmake --build build --config Release

# Run
./build/shushhh.exe
```

### vcpkg dependencies
```bash
vcpkg install libsodium:x64-windows-static
vcpkg install curl:x64-windows-static
vcpkg install nlohmann-json:x64-windows-static
# Phase 2:
# build liboqs separately and link manually (not in vcpkg registry)
```

---

## Security Rules for Contributors

- Never log, print, or serialize raw key material
- Never store keys or plaintext to disk on the host
- Never skip `secure_wipe()` after key material goes out of scope
- Never use `==` or `memcmp()` for auth tags, hashes, or passwords
- Never send traffic outside `socks5h://127.0.0.1:9050`
- Never store raw passwords — hash client-side, store salted hash server-side
- Never hardcode keys, credentials, or server addresses in source

---

*shushhh — built from scratch. Designed to be unreadable, untraceable, and uncompromising.*