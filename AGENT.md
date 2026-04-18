# AGENT.md — shushhh Development Guide

> This file is the primary reference for any AI agent or developer working on the shushhh codebase. Read it fully before writing any code.

---

## Project Overview

**shushhh** is a paranoid, pendrive-based encrypted messenger. The entire application runs from a USB drive — nothing is installed on the host machine. It is designed for two parties who each carry a pendrive, plug into any laptop, and communicate through a Tor-routed .onion relay with no persistent data on either the host or the server.

### Core Security Properties (non-negotiable invariants)
- Messages are encrypted end-to-end **before** leaving the client. The relay server is cryptographically blind.
- Session keys are **never** stored on disk, sent to the server, or left in memory after use.
- The relay holds ciphertext blobs keyed by a hashed recipient identifier — no real identities.
- Messages are **deleted from the relay on ACK** — no chat history exists server-side.
- The host laptop retains **zero forensic trace** after the pendrive is removed (watchdog wipe).
- All network traffic routes through Tor (SOCKS5 proxy on `127.0.0.1:9050`).

### What is NOT in scope
- Persistent chat history
- Multi-device sync
- Group messaging
- Any server-side decryption capability
- Any plaintext stored to disk

---

## Repository Structure

```
shushhh/
├── Main.cpp                  # Entry point, UI loop, Tor/curl integration
├── src/
│   └── crypto/
│       ├── crypto.h          # All structs and function declarations
│       └── crypto.cpp        # All crypto implementations
├── CMakeLists.txt            # Build configuration (vcpkg)
├── AGENT.md                  # This file
├── TRACKER.md                # Feature implementation tracker
└── docs/
    └── PROJECT_OVERVIEW.md   # Architecture and submission document
```

---

## Build and Test Commands

### Prerequisites
- CMake >= 3.15
- vcpkg (at `C:/vcpkg` on Windows, adjust path for other platforms)
- Dependencies installed via vcpkg:
  ```
  vcpkg install libsodium:x64-windows-static
  vcpkg install curl:x64-windows-static
  vcpkg install nlohmann-json:x64-windows-static
  ```
- For post-quantum (Phase 2): `liboqs` from the Open Quantum Safe project

### Build
```bash
# From project root
cmake -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

### Run
```bash
./build/shushhh.exe
```

### Adding liboqs (Phase 2 — Kyber)
```bash
# Clone and build liboqs
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -DOQS_BUILD_ONLY_LIB=ON ..
cmake --build . --config Release
```
Then link in `CMakeLists.txt`:
```cmake
find_library(OQS_LIB oqs PATHS path/to/liboqs/build/lib)
target_link_libraries(shushhh PRIVATE ${OQS_LIB})
target_include_directories(shushhh PRIVATE path/to/liboqs/include)
```

### Test Sequence
1. Run `FullCryptoTest()` via menu option 4 — verifies key exchange, encryption, decryption, HKDF, and session round-trip
2. Run option 2 + 3 to test session creation and Tor-routed send
3. Check that `shared1 == shared2`, decryption succeeds, and memory wipe confirmation prints

---

## Code Style Guidelines

### Language and Standard
- C++17 strictly. No C++20 features.
- All new files placed under `src/` with appropriate subdirectory.
- Header guards via `#pragma once`.

### Naming
```cpp
// Structs: PascalCase
struct MessageSession { ... };

// Functions: snake_case
std::vector<unsigned char> hkdf_derive(...);

// Constants: UPPER_SNAKE_CASE
const size_t DEFAULT_PAD_SIZE = 512;

// Local variables: snake_case
auto shared_secret = compute_x25519_shared_secret(...);
```

### Memory Safety Rules
- **Always** call `secure_wipe(ptr, len)` on any buffer holding key material before it goes out of scope.
- Never use `memset` for security-sensitive zeroing — it can be optimised out by the compiler. Use `sodium_memzero()` directly or via the `secure_wipe()` wrapper.
- Prefer `std::vector<unsigned char>` over raw arrays for key material so RAII handles deallocation.
- Use `sodium_memcmp()` for all security-sensitive comparisons — never `==` or `memcmp()`.

### Error Handling
- Crypto functions return empty `std::string` or empty `std::vector` on failure.
- Always check return values. Never silently ignore a failed `crypto_aead_*` call.
- Print errors to `std::cerr` with `[-]` prefix. Print success to `std::cout` with `[+]` prefix.

### No Global State
- No global key material. All session state lives in `MessageSession` structs passed by reference.
- No static buffers for cryptographic data.

### Comments
- Comment **why**, not **what**. The what is in the code.
- Every non-trivial crypto decision must have a comment explaining the security reasoning.

---

## Architecture: Key Data Structures

```cpp
// A 32-byte X25519 keypair
struct KeyPair {
    unsigned char private_key[32];
    unsigned char public_key[32];
};

// A single encrypted blob ready for transport
struct EncryptedMessage {
    unsigned char nonce[12];          // random per-message, ChaCha20-Poly1305 IETF
    std::vector<unsigned char> ciphertext;
    unsigned char tag[16];            // Poly1305 auth tag
};

// Full session state between two clients
struct MessageSession {
    KeyPair my_keypair;
    unsigned char their_public_key[32];
    std::vector<unsigned char> root_key;   // from X25519 (+ Kyber in Phase 2)
    std::vector<unsigned char> send_key;   // ratchets forward on each send
    std::vector<unsigned char> recv_key;   // ratchets forward on each recv
    uint32_t send_counter;                 // replay protection
    uint32_t recv_counter;
};
```

## Architecture: Key Functions

| Function | File | Purpose |
|---|---|---|
| `crypto_init()` | crypto.cpp | Initialize libsodium — must be called first |
| `generate_x25519_keypair()` | crypto.cpp | Generate a fresh keypair |
| `compute_x25519_shared_secret()` | crypto.cpp | ECDH shared secret |
| `hkdf_derive()` | crypto.cpp | HKDF key derivation — feeds all session keys |
| `encrypt_message()` | crypto.cpp | Pad + encrypt with ChaCha20-Poly1305 |
| `decrypt_message()` | crypto.cpp | Decrypt + verify tag + strip padding |
| `session_encrypt()` | crypto.cpp | Per-message encrypt, increments counter |
| `session_decrypt()` | crypto.cpp | Per-message decrypt, increments counter |
| `encrypted_to_json()` | crypto.cpp | Serialize EncryptedMessage to base64 JSON |
| `json_to_encrypted()` | crypto.cpp | Deserialize JSON back to EncryptedMessage |
| `secure_wipe()` | crypto.cpp | Wrapper over sodium_memzero |

---

## Security Considerations

### What an agent MUST NOT do
- Never log, print, or serialize raw key material (private keys, session keys, root keys)
- Never store any key or plaintext to a file on the host system
- Never skip the `secure_wipe()` call after key material is no longer needed
- Never use `==` to compare auth tags, hashes, or passwords — always `sodium_memcmp()`
- Never send data outside of the Tor SOCKS5 proxy — all `curl` calls must set `CURLOPT_PROXY` to `socks5h://127.0.0.1:9050`
- Never store the raw password — hash before sending, store hashed+salted on server only
- Never hardcode keys, credentials, or server addresses in source

### Threat Model Summary
| Threat | Mitigation |
|---|---|
| Passive network interception | ChaCha20-Poly1305 E2E encryption |
| Traffic analysis (message size) | All blobs padded to uniform 512 bytes |
| Traffic analysis (timing/routing) | Tor hidden service, 3-hop anonymization |
| Quantum computer (future) | ML-KEM-768 hybrid key exchange (Phase 2) |
| Relay server compromise | Server is blind — no session keys ever reach it |
| Host laptop forensics | Watchdog wipe on USB disconnect |
| MITM on auth | Ed25519 signed server responses, server pubkey baked in binary |
| Replay attacks | send_counter / recv_counter in MessageSession |
| Timing attacks on password compare | sodium_memcmp() constant-time comparison |
| Key capture (past sessions) | Symmetric ratchet + secure_wipe (Phase 2) |

### Cryptographic Primitives
- **Key exchange**: X25519 (libsodium `crypto_box_keypair` / `crypto_scalarmult`)
- **Symmetric encryption**: ChaCha20-Poly1305 IETF (`crypto_aead_chacha20poly1305_ietf_*`)
- **Key derivation**: HKDF-SHA256 (manual implementation using `crypto_auth_hmacsha256_*`)
- **Serialization**: libsodium base64 (`sodium_bin2base64` / `sodium_base642bin`)
- **Memory wipe**: `sodium_memzero`
- **Comparison**: `sodium_memcmp`
- **Phase 2 — PQ**: ML-KEM-768 via liboqs (`OQS_KEM_alg_ml_kem_768`)
- **Phase 2 — Auth**: Ed25519 (`crypto_sign_ed25519`)

### LoginProvider Extension Point
The login system is built as an abstract interface:
```cpp
class LoginProvider {
public:
    virtual bool authenticate() = 0;
    virtual std::vector<unsigned char> get_credential_hash() = 0;
    virtual ~LoginProvider() = default;
};
```
`PasswordLogin` is the Phase 1 implementation. Any future auth method (hardware token, biometric, challenge-response) subclasses `LoginProvider` without touching the rest of the codebase.

---

## Testing Instructions

### Unit-level (in-process)
Call `FullCryptoTest()` from the menu. It validates:
- X25519 shared secret symmetry (both sides compute identical output)
- `encrypt_message` → `decrypt_message` round-trip
- HKDF determinism (same inputs → same output)
- Session encrypt/decrypt via `session_encrypt` + `session_decrypt`
- `encrypted_to_json` → `json_to_encrypted` round-trip

### Integration test checklist
- [ ] Tor is running (`tor` daemon on localhost:9050)
- [ ] Option 3 "Send Test Message" completes without curl error
- [ ] Server receives a JSON blob with `nonce`, `ciphertext`, `tag` fields
- [ ] Server cannot decrypt the blob without the session key

### Security regression tests (run after any crypto change)
- Flip one byte in ciphertext → `decrypt_message` must return empty string
- Flip one byte in tag → `decrypt_message` must return empty string
- Same nonce reuse across two encrypts → messages must differ (nonce is random each time)
- `shared1 == shared2` must be true on every keypair generation

### What to check before every commit
1. No raw private keys printed anywhere
2. `secure_wipe` called on all local key buffers before function returns
3. All curl calls have `CURLOPT_PROXY` set to Tor
4. No plaintext files written to disk
