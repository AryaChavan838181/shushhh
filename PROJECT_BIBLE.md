# The Shushhh Protocol Bible

> **Version 2.0** — Definitive single source of truth for the Shushhh secure messenger.
> This document covers: threat model, cryptographic architecture, wire formats, byte-level data structures, protocol flows, relay server design, anti-forensics, cross-platform abstractions, and the complete source map.

---

## Table of Contents

1. [Threat Model](#part-1-threat-model)
2. [Cryptographic Primitives](#part-2-cryptographic-primitives)
3. [Data Structures & Key Sizes](#part-3-data-structures--key-sizes)
4. [Identity & Authentication](#part-4-identity--authentication)
5. [Protocol Flow: Alice & Bob](#part-5-protocol-flow-alice--bob)
6. [Relay Server Architecture](#part-6-relay-server-architecture)
7. [Wire Formats & Serialization](#part-7-wire-formats--serialization)
8. [Anti-Forensics & Watchdog](#part-8-anti-forensics--watchdog)
9. [Cross-Platform Architecture](#part-9-cross-platform-architecture)
10. [Source Map](#part-10-source-map)
11. [Security Guarantees](#part-11-security-guarantees)

---

## Part 1: Threat Model

Shushhh is designed to resist the following adversaries:

| Adversary | Capability | Shushhh Defense |
|---|---|---|
| **Network Observer** | Can see all traffic on the wire (ISP, nation-state) | All traffic routed through Tor — observer sees only encrypted Tor cells to random relays |
| **Compromised Relay** | Full access to the Key Server and Message Server databases | Key Server holds only public keys (useless). Message Server holds only opaque ChaCha20-Poly1305 blobs and SHA-256 hashed routing tags — cannot read content, cannot identify users |
| **Quantum Computer** | Can run Shor's algorithm to break X25519 ECDH | Hybrid handshake: X25519 **+** ML-KEM-768 (Kyber). Both must be broken simultaneously |
| **Device Seizure (post-session)** | Physical access to the device after conversation ends | Symmetric ratchet: every message key is derived then wiped via `sodium_memzero()`. Past keys are irrecoverable |
| **Device Seizure (mid-session)** | Physical access while shushhh is running | Current session key is compromised, but all *previous* messages used keys that were already wiped. Forward secrecy holds |
| **MITM on Key Server** | Attacker intercepts key fetch responses | Key Server signs all responses with Ed25519. Client has the server's public key hardcoded at compile time — signature verification fails if tampered |
| **USB Forensics** | Examiner analyzes the host PC after user unplugs USB | Watchdog detects USB removal, executes wipe script from temp dir. On Windows: `cipher /w` overwrites free space. On Linux: `shred` destroys temp files |

### What Shushhh Does NOT Protect Against

- **Endpoint compromise while typing** — If malware is running on the host with a keylogger, it can capture plaintext as it's typed. Shushhh protects data *in transit and at rest*, not against a fully compromised endpoint.
- **Rubber-hose cryptanalysis** — If someone forces you to reveal your password, they can decrypt `identity.dat` and impersonate you.
- **Traffic analysis on message timing** — Tor hides IP addresses but an observer who controls both ends of the Tor circuit could correlate message timing. This is a fundamental Tor limitation.

---

## Part 2: Cryptographic Primitives

### 2.1 X25519 (Curve25519 ECDH)

- **Standard:** RFC 7748
- **Library:** libsodium (`crypto_scalarmult`, `crypto_box_keypair`)
- **Key sizes:** 32-byte private key, 32-byte public key, 32-byte shared secret
- **Purpose:** Classical key agreement. Two parties each contribute a keypair; the ECDH operation produces a 32-byte shared secret that only they can compute.
- **Security level:** 128-bit classical security. Broken by quantum computers running Shor's algorithm — this is why Shushhh pairs it with ML-KEM-768.
- **Implementation detail:** `crypto_scalarmult()` performs raw scalar multiplication on Curve25519. It returns `-1` if the result is the all-zero point (which indicates a malicious public key crafted to force a weak shared secret). Shushhh checks this return value and aborts the session if it fails.

### 2.2 ML-KEM-768 (Kyber) — Post-Quantum KEM

- **Standard:** NIST FIPS 203 (August 2024)
- **Library:** liboqs (`OQS_KEM_alg_ml_kem_768`)
- **Key sizes:**
  - Public key: **1184 bytes**
  - Private key: **2400 bytes**
  - Ciphertext: **1088 bytes**
  - Shared secret: **32 bytes**
- **Purpose:** Key Encapsulation Mechanism resistant to quantum computers. The encapsulator generates a random shared secret and encrypts it under the recipient's public key. Only the holder of the private key can decapsulate it.
- **Security level:** NIST Level 3 (equivalent to AES-192). Resistant to both classical and quantum attacks.
- **How it works in Shushhh:**
  1. Bob calls `OQS_KEM_encaps(alice_pubkey)` → gets `(shared_secret, ciphertext)`
  2. Bob sends `ciphertext` to Alice
  3. Alice calls `OQS_KEM_decaps(ciphertext, alice_privkey)` → recovers the same `shared_secret`
  4. This shared secret is combined with the X25519 secret via HKDF

### 2.3 HKDF-SHA256 (Key Derivation)

- **Standard:** RFC 5869
- **Library:** libsodium (`crypto_auth_hmacsha256`)
- **Purpose:** Takes raw, potentially non-uniform key material and produces cryptographically strong, uniform keys.
- **Two phases:**
  1. **Extract:** `PRK = HMAC-SHA256(salt, IKM)` — compresses input key material into a fixed-length pseudorandom key
  2. **Expand:** `OKM = T(1) || T(2) || ...` where `T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)` — stretches the PRK into arbitrary-length output
- **Usage in Shushhh:**
  - **Root key derivation:** `HKDF(X25519_secret || Kyber_secret, info="shushhh_session_key_v1")` → 32-byte root key
  - **Symmetric ratchet:** `HKDF(current_key, info="shushhh_ratchet_v1:<counter>")` → next key
  - **Outer handshake key:** `HKDF(ephemeral_ECDH_secret, info="shushhh_outer_handshake_v1")` → 32-byte tunnel key
- **Security note:** The HMAC state is wiped with `sodium_memzero()` after each Extract/Expand call to prevent intermediate key material from lingering in RAM.

### 2.4 ChaCha20-Poly1305 IETF (AEAD Encryption)

- **Standard:** RFC 8439
- **Library:** libsodium (`crypto_aead_chacha20poly1305_ietf_encrypt/decrypt`)
- **Parameters:**
  - Key: 32 bytes
  - Nonce: 12 bytes (randomly generated per message via `randombytes_buf`)
  - Auth tag: 16 bytes (Poly1305 MAC)
- **How encryption works:**
  1. A 12-byte random nonce is generated
  2. ChaCha20 stream cipher encrypts the padded plaintext
  3. Poly1305 computes a 16-byte authentication tag over the ciphertext
  4. Output: `nonce || ciphertext || tag`
- **How decryption works:**
  1. Poly1305 tag is verified FIRST — if it doesn't match, decryption is rejected immediately (no decrypted data is ever returned)
  2. ChaCha20 decrypts the ciphertext
  3. Length header is read, padding is stripped
- **Padding scheme:** Every plaintext is prepended with a 4-byte big-endian length header, then padded to a target size (default 512 bytes, 1024 for handshakes, 8192 for identity files) with random bytes. This defeats traffic analysis — all messages look the same size on the wire.

### 2.5 Ed25519 (Digital Signatures)

- **Standard:** RFC 8032
- **Library:** libsodium (`crypto_sign_ed25519_*`)
- **Key sizes:** 64-byte private key, 32-byte public key, 64-byte signature
- **Purpose:** The Key Server signs all authentication responses with its Ed25519 private key. The client has the server's public key **hardcoded at compile time** (in `auth.cpp`, the `SERVER_ED25519_PUBKEY[32]` array). If an attacker intercepts the response and substitutes fake keys, the signature verification fails and the client aborts.
- **Trust model:** This is a **Trust On First Use (TOFU) / hardcoded anchor** model. The server's public key is generated once by `relay/setup_keys.py` and then baked into the C++ binary. There is no certificate authority — the trust anchor IS the compiled binary.

### 2.6 SHA-256 (Hashing)

- **Library:** libsodium (`crypto_hash_sha256`)
- **Output:** 32 bytes (256 bits)
- **Usage:**
  - **Credential hashing:** `SHA-256(password + username)` — computed client-side, raw password never leaves device
  - **Recipient routing tags:** `SHA-256(username)` → 64-char hex string used as the relay address. The relay never sees the actual username.

### 2.7 sodium_memzero (Secure Memory Wipe)

- **Library:** libsodium
- **Purpose:** Zeroes out memory in a way that the compiler **cannot** optimize away. On Windows it calls `SecureZeroMemory()`, on BSD it calls `explicit_memset()`, elsewhere it uses a volatile write loop.
- **Where it's used:** After EVERY key derivation, after EVERY decryption, after reading passwords, after HKDF Extract/Expand, after session creation. The Shushhh codebase calls `secure_wipe()` (a wrapper around `sodium_memzero`) **34+ times** across `crypto.cpp` alone.

---

## Part 3: Data Structures & Key Sizes

### 3.1 HybridKeyPair

```cpp
struct HybridKeyPair {
    unsigned char x25519_private[32];   // Curve25519 scalar (clamped)
    unsigned char x25519_public[32];    // Curve25519 point
    std::vector<unsigned char> kyber_private; // 2400 bytes — ML-KEM-768 secret key
    std::vector<unsigned char> kyber_public;  // 1184 bytes — ML-KEM-768 public key
};
```

**Total key material per user:** 32 + 32 + 2400 + 1184 = **3,648 bytes**

### 3.2 EncryptedMessage

```cpp
struct EncryptedMessage {
    unsigned char nonce[12];             // Random per-message
    std::vector<unsigned char> ciphertext; // ChaCha20 output (padded to target_size)
    unsigned char tag[16];               // Poly1305 authentication tag
};
```

**Wire format (after JSON serialization):**
```json
{
  "nonce": "<base64, 16 chars>",
  "ciphertext": "<base64, ~684 chars for 512-byte target>",
  "tag": "<base64, 24 chars>"
}
```

### 3.3 MessageSession

```cpp
struct MessageSession {
    HybridKeyPair my_keypair;
    unsigned char their_x25519_public_key[32];
    std::vector<unsigned char> their_kyber_public_key; // 1184 bytes
    std::vector<unsigned char> root_key;    // 32 bytes — derived from HKDF
    std::vector<unsigned char> send_key;    // 32 bytes — ratchets on each send
    std::vector<unsigned char> recv_key;    // 32 bytes — ratchets on each recv
    uint32_t send_counter;                  // Monotonic, for ratchet info string
    uint32_t recv_counter;
};
```

### 3.4 HandshakePayload (0-RTT Sealed Sender)

```cpp
struct HandshakePayload {
    unsigned char ephemeral_public[32]; // One-time X25519 public key
    EncryptedMessage encrypted_blob;    // Inner payload encrypted with outer tunnel key
};
```

### 3.5 Plaintext Padding Layout

```
Byte offset:  [0..3]         [4..4+len-1]       [4+len..target_size-1]
Content:      BE length hdr   actual plaintext    random padding bytes
```

- The 4-byte big-endian header stores the real plaintext length
- Random padding fills the rest to `target_size` (512 default)
- This ensures ALL messages on the wire are the same size — prevents traffic analysis

---

## Part 4: Identity & Authentication

### 4.1 Account Registration Flow

1. User enters username + password in the TUI
2. Client computes `credential_hash = SHA-256(password + username)` — raw password is wiped immediately
3. Client POSTs `{username, credential_hash}` to Key Server `/register`
4. Server generates a random 32-byte salt, computes `salted = SHA-256(credential_hash + salt)`, stores `(username, salt, salted)` in SQLite
5. The server **never** sees the raw password — it only receives and stores a salted hash of a hash

### 4.2 Authentication Flow

1. Client POSTs `{username, credential_hash}` to `/auth`
2. Server looks up the stored salt, recomputes `SHA-256(credential_hash + salt)`, compares with stored value using `hmac.compare_digest()` (constant-time comparison to prevent timing attacks)
3. If valid, server creates a JSON token `{username, timestamp, nonce}` and signs it with Ed25519
4. Server returns `{status: "ok", payload: "<token>", signature: "<base64>"}`
5. Client verifies the Ed25519 signature against the hardcoded `SERVER_ED25519_PUBKEY[32]`
6. If signature is invalid → **MITM detected** → client aborts immediately

### 4.3 identity.dat — Encrypted Key Storage

The user's private keys are persisted to disk as an encrypted file:

1. Keypair is serialized to JSON: `{x25519_private, x25519_public, kyber_private, kyber_public}` (all hex-encoded)
2. Encrypted with `ChaCha20-Poly1305(key=credential_hash, target_size=8192)`
3. Written to `identity.dat` as a JSON blob containing `{nonce, ciphertext, tag}`

**To decrypt:** The user must provide the correct username + password → recompute `SHA-256(password + username)` → use as the decryption key. Wrong password = Poly1305 tag mismatch = instant rejection.

### 4.4 LoginProvider Abstraction

```cpp
class LoginProvider {
    virtual bool authenticate(const std::string& server_url) = 0;
    virtual std::vector<unsigned char> get_credential_hash() = 0;
    virtual std::string get_username() const = 0;
};
```

This is an abstract interface. The current implementation is `PasswordLogin`, but the architecture supports future auth methods (hardware tokens, biometrics, challenge-response) without touching the rest of the codebase.

---

## Part 5: Protocol Flow — Alice & Bob

### Phase 1: Identity Creation & Registration

1. Alice launches shushhh and selects **Register**
2. She enters username `alice` and password `hunter2`
3. Client computes `credential_hash = SHA-256("hunter2" + "alice")` = 32 bytes
4. Raw password `"hunter2"` is **immediately wiped** from RAM via `sodium_memzero()`
5. Client POSTs `{username: "alice", credential_hash: <base64>}` to Key Server `/register`
6. Server stores `SHA-256(credential_hash + random_salt)` — double-hashed
7. Client authenticates (`/auth`) to get a signed token
8. Client generates `HybridKeyPair`: X25519 keypair (32+32 bytes) + ML-KEM-768 keypair (1184+2400 bytes)
9. Private keys encrypted into `identity.dat` using `credential_hash` as ChaCha20 key
10. Public keys uploaded to Key Server via `/upload_key` with the signed auth token

### Phase 2: Bob Initiates a Conversation (0-RTT Sealed Sender)

This is the most complex part of the protocol. Bob wants to send "Hello" to Alice **without any prior interaction**.

**Step 1 — Key Fetch:**
Bob enters "alice" in the TUI. Client calls `GET /get_key/alice`. Server returns Alice's public keys (X25519 + ML-KEM-768).

**Step 2 — Hybrid Key Exchange (Inner Session):**
`
X25519_Secret   = crypto_scalarmult(Bob_X25519_Priv, Alice_X25519_Pub)     // 32 bytes
(Kyber_Secret, Kyber_CT) = OQS_KEM_encaps(Alice_Kyber_Pub)                // 32 + 1088 bytes
IKM             = X25519_Secret || Kyber_Secret                            // 64 bytes
RootKey         = HKDF-SHA256(IKM, info="shushhh_session_key_v1")          // 32 bytes
`

**Step 3 — Ephemeral Outer Tunnel (Sealed Sender):**
Bob generates a **throwaway** X25519 keypair `(Eph_Priv, Eph_Pub)` just for this handshake:
`
Outer_Secret    = crypto_scalarmult(Eph_Priv, Alice_X25519_Pub)            // 32 bytes
Outer_Key       = HKDF-SHA256(Outer_Secret, info="shushhh_outer_handshake_v1") // 32 bytes
Inner_Payload   = JSON({sender: "bob", kyber_ciphertext: base64(Kyber_CT)})
Encrypted_Blob  = ChaCha20-Poly1305(Inner_Payload, Outer_Key, target=1024)
`

**Step 4 — Transmission:**
`json
POST /drop
{
  "tag": "SHA256('alice')",           // 64-char hex — relay routing address
  "blob": {
    "type": "handshake",
    "ephemeral_public": "<base64(Eph_Pub)>",
    "blob": {"nonce":"...","ciphertext":"...","tag":"..."}
  }
}
`

The relay sees: a hex tag and an opaque JSON blob. It cannot determine who sent it, who it's for, or what it contains.

**Why the outer tunnel?** Without it, the relay would see `sender: "bob"` in the handshake payload. The ephemeral X25519 tunnel encrypts the inner payload so that ONLY Alice (who holds the corresponding private key) can decrypt it and learn who is contacting her. This is the "Sealed Sender" property.

### Phase 3: Alice Receives the Handshake

1. Alice's background fetcher thread polls `GET /fetch?tag=SHA256('alice')` every 2 seconds
2. She downloads Bob's blob and detects `"type": "handshake"`
3. She decrypts the outer tunnel:
   `
   Outer_Secret = crypto_scalarmult(Alice_X25519_Priv, Eph_Pub)
   Outer_Key    = HKDF(Outer_Secret, info="shushhh_outer_handshake_v1")
   Inner_JSON   = decrypt(encrypted_blob, Outer_Key)
   `
4. She parses `{sender: "bob", kyber_ciphertext: "..."}`
5. She fetches Bob's public keys from the Key Server
6. She creates the responder session:
   `
   X25519_Secret = crypto_scalarmult(Alice_X25519_Priv, Bob_X25519_Pub)
   Kyber_Secret  = OQS_KEM_decaps(Kyber_CT, Alice_Kyber_Priv)
   RootKey       = HKDF(X25519_Secret || Kyber_Secret, "shushhh_session_key_v1")
   `
7. Both Alice and Bob now hold the **same RootKey** — session established
8. Alice ACKs the handshake (`POST /ack {event_id}`) to hard-delete it from the relay

### Phase 4: Symmetric Ratchet (Every Message)

Once the RootKey is established, **every single message** uses a unique key:

`
Message 1: send_key = RootKey
            encrypt("Hello", send_key)
            next_key = HKDF(send_key, info="shushhh_ratchet_v1:0")
            sodium_memzero(send_key)    // OLD KEY DESTROYED
            send_key = next_key
            send_counter++

Message 2: encrypt("How are you?", send_key)
            next_key = HKDF(send_key, info="shushhh_ratchet_v1:1")
            sodium_memzero(send_key)    // OLD KEY DESTROYED
            send_key = next_key
            send_counter++
`

**Critical property:** Each key is derived from the previous one via HKDF (a one-way function). Even if an attacker steals `Key_100`, they cannot reverse HKDF to find `Key_99`, `Key_98`, etc. This is **Perfect Forward Secrecy**.

The receiver performs the same ratchet independently:
- `recv_key` starts as `RootKey`
- After each successful decryption, `recv_key = HKDF(recv_key, "shushhh_ratchet_v1:<counter>")`
- Old `recv_key` is wiped

---

## Part 6: Relay Server Architecture

### 6.1 Key Server (`relay/key_server.py`)

| Endpoint | Method | Purpose |
|---|---|---|
| `/register` | POST | Create user account (stores salted credential hash) |
| `/auth` | POST | Authenticate, returns Ed25519-signed token |
| `/upload_key` | POST | Upload X25519 + Kyber public keys (requires signed token) |
| `/get_key/<user>` | GET | Retrieve public keys for a username |

**Database schema (`keyserver.db`):**
`sql
app_config(config_key TEXT PK, config_salt TEXT, config_value TEXT)
user_keys(username TEXT PK, public_keys TEXT, updated_at INTEGER)
`

**Security:** The Key Server holds public keys and salted password hashes. Even if fully compromised, the attacker cannot decrypt messages (they'd need private keys, which never leave the client).

### 6.2 Message Server (`relay/msg_server.py`)

| Endpoint | Method | Purpose |
|---|---|---|
| `/drop` | POST | Store encrypted blob for a recipient tag |
| `/fetch` | GET | Retrieve pending messages by tag |
| `/ack` | POST | Hard-delete a delivered message |

**Database schema (`telemetry.db` — deliberately disguised):**
`sql
telemetry_events(
    event_id TEXT PK,
    device_fingerprint TEXT,    -- actually SHA-256(username)
    payload BLOB,              -- actually encrypted message blob
    ts INTEGER,
    ttl INTEGER DEFAULT 604800 -- 7-day auto-expiry
)
`

**Plausible deniability:** The table name `telemetry_events` and column names like `device_fingerprint` are chosen to look like analytics telemetry if the database is seized. There is no column called "message", "sender", or "recipient".

**The server is cryptographically blind:**
- It sees `device_fingerprint` = `SHA-256(username)` — cannot reverse the hash to get the username
- It sees `payload` = ChaCha20-Poly1305 ciphertext — cannot read the content
- It does NOT know who sent the message (no sender field)
- Messages auto-expire after 7 days and are hard-deleted on ACK

---

## Part 7: Wire Formats & Serialization

### 7.1 Standard Message (on the wire)

`json
{
  "tag": "a1b2c3d4...64 hex chars...",
  "blob": "{\"nonce\":\"<b64>\",\"ciphertext\":\"<b64>\",\"tag\":\"<b64>\"}"
}
`

### 7.2 Handshake Message (on the wire)

`json
{
  "tag": "a1b2c3d4...64 hex chars...",
  "blob": "{\"type\":\"handshake\",\"ephemeral_public\":\"<b64, 44 chars>\",\"blob\":{\"nonce\":\"<b64>\",\"ciphertext\":\"<b64>\",\"tag\":\"<b64>\"}}"
}
`

### 7.3 Base64 Encoding

All binary-to-text encoding uses **libsodium's** `sodium_bin2base64` (standard base64, not URL-safe). This avoids an OpenSSL dependency.

---

## Part 8: Anti-Forensics & Watchdog

### 8.1 RAM Hygiene

`secure_wipe()` wraps `sodium_memzero()` and is called after:
- Every HKDF Extract/Expand (wipes HMAC state and PRK)
- Every encryption (wipes plaintext buffer)
- Every decryption (wipes decrypted buffer)
- Every session creation (wipes raw X25519 and Kyber shared secrets, wipes IKM)
- Password entry (wipes raw password string)
- Application exit (wipes all session keys and private keys)

### 8.2 USB Watchdog (Windows)

1. On startup, `detect_usb_drive()` calls `GetModuleFileNameA()` to find the exe path, then `GetDriveTypeA()` to check if it's `DRIVE_REMOVABLE`
2. `write_wipe_script()` creates `%TEMP%\shushhh_wipe.bat`:
   - `cipher /w:%TEMP%` — overwrites free disk sectors (3-pass: zeros, ones, random)
   - `del /f /q %TEMP%\shushhh_*` — deletes temp files
   - Self-deletes the bat file
3. A detached thread polls `GetLogicalDrives()` every 2 seconds
4. When the drive bit disappears → USB yanked → `CreateProcessA()` launches the bat hidden (`CREATE_NO_WINDOW | DETACHED_PROCESS`)

### 8.3 USB Watchdog (Linux)

1. `detect_usb_drive()` reads `platform_get_exe_dir()` (via `/proc/self/exe`), checks if path starts with `/media/` or `/run/media/`
2. `write_wipe_script()` creates `/tmp/shushhh_wipe.sh`:
   - `rm -rf /tmp/shushhh_*` — deletes temp files
   - `shred -u` — cryptographic overwrite if `shred` is available
   - Self-deletes
3. A detached thread calls `stat()` on the mount path every 2 seconds
4. When `stat()` returns non-zero → mount gone → `fork()` + `setsid()` + `execl("/bin/bash", script)`

---

## Part 9: Cross-Platform Architecture

### 9.1 Platform Abstraction Layer (`src/platform/`)

`
platform.h              — Interface (4 functions)
platform_win32.cpp      — Windows implementation (WinSock, CreateProcessA, GetModuleFileNameA)
platform_linux.cpp      — Linux implementation (POSIX sockets, fork/execvp, /proc/self/exe)
`

| Function | Windows | Linux |
|---|---|---|
| `platform_is_tor_running()` | `connect()` via WinSock to `127.0.0.1:9050` | `connect()` via POSIX socket to `127.0.0.1:9050` |
| `platform_get_exe_dir()` | `GetModuleFileNameA()` | `readlink("/proc/self/exe")` |
| `platform_get_temp_dir()` | `GetTempPathA()` | Returns `/tmp` |
| `platform_launch_tor()` | `CreateProcessA()` with `CREATE_NO_WINDOW` | `fork()` + `execvp()` |

### 9.2 Tor Discovery Order

1. Bundled: `<exe_dir>/tor/tor/tor.exe` (Windows) or `<exe_dir>/tor/tor` (Linux)
2. Adjacent: `<exe_dir>/tor.exe` or `<exe_dir>/tor`
3. System (Linux only): `/usr/bin/tor`, `/usr/local/bin/tor`

### 9.3 Build System (`CMakeLists.txt`)

- `if(WIN32)` → compiles `platform_win32.cpp`, links `ws2_32 crypt32 bcrypt`
- `else()` → compiles `platform_linux.cpp`, links `Threads::Threads`
- Installer target (Win32 resource embedding) is wrapped in `if(WIN32)` — excluded on Linux

---

## Part 10: Source Map

`
shushhh/
├── Main.cpp                          — FTXUI TUI, app state machine, fetcher thread
├── CMakeLists.txt                    — Cross-platform build (vcpkg)
├── PROJECT_BIBLE.md                  — This file
├── README.md                         — User-facing documentation
├── identity.dat                      — Encrypted private keys (generated at runtime)
│
├── src/
│   ├── crypto/
│   │   ├── crypto.h                  — All crypto function declarations & structs
│   │   └── crypto.cpp                — X25519, ML-KEM-768, ChaCha20, HKDF, Ed25519, ratchet
│   ├── auth/
│   │   ├── auth.h                    — LoginProvider interface, PasswordLogin, tor_post/tor_get
│   │   └── auth.cpp                  — Authentication, registration, identity persistence
│   ├── platform/
│   │   ├── platform.h                — Cross-platform interface
│   │   ├── platform_win32.cpp        — Windows: WinSock, CreateProcess, GetModuleFileName
│   │   └── platform_linux.cpp        — Linux: POSIX sockets, fork/exec, /proc/self/exe
│   └── watchdog/
│       ├── watchdog.h                — Watchdog API (detect_usb_drive, launch_watchdog)
│       └── watchdog.cpp              — USB detection + wipe script + monitor thread
│
├── relay/
│   ├── key_server.py                 — Flask: registration, auth, key distribution
│   ├── msg_server.py                 — Flask: blind store-and-forward relay
│   ├── setup_keys.py                 — Generates Ed25519 server keypair
│   ├── server_key.bin                — Ed25519 private key (32 bytes)
│   └── requirements.txt             — flask, pynacl
│
└── tor/                              — Bundled Tor Expert Bundle (not in git)
    └── tor/
        ├── tor.exe
        ├── geoip
        └── geoip6
`

---

## Part 11: Security Guarantees

| Property | Mechanism | Strength |
|---|---|---|
| **Confidentiality** | ChaCha20 stream cipher | 256-bit key |
| **Integrity** | Poly1305 MAC (16-byte tag) | Forgery probability < 2^-128 |
| **Anonymity** | Tor onion routing (3 hops) | IP hidden from relay and observer |
| **Classical Key Security** | X25519 ECDH | 128-bit (Curve25519) |
| **Quantum Key Security** | ML-KEM-768 (Kyber) | NIST Level 3 (~AES-192) |
| **Forward Secrecy** | HKDF symmetric ratchet + `sodium_memzero` | Past keys irrecoverable |
| **Sender Anonymity** | Ephemeral X25519 outer tunnel | Relay cannot identify sender |
| **MITM Resistance** | Hardcoded Ed25519 server public key | Compile-time trust anchor |
| **Anti-Forensics (RAM)** | `sodium_memzero()` on all secrets | Compiler-proof wipe |
| **Anti-Forensics (Disk)** | Watchdog wipe (`cipher /w` / `shred`) | Multi-pass overwrite |
| **Credential Security** | Double-hashed: `SHA-256(SHA-256(pw+user) + salt)` | Server never sees password |

---

*End of Bible. This document should be updated whenever a cryptographic primitive, protocol step, or architectural component changes.*
