# TRACKER.md — shushhh Feature Implementation Tracker

> Updated as features move through design → in-progress → complete.
> Each entry follows the What / How / Why format.

---

## Status Legend
- `[Start]` — Implemented and tested
- `[IN PROGRESS]` — Currently being built
- `[NEXT]` — Designed, ready to implement
- `[PLANNED]` — Designed, not yet started
- `[FUTURE]` — Intentionally deferred

---

## Phase 0 — Foundation `[START]`

### F-01 · libsodium initialization
**Status:** `[START]`

**What:** Initialize libsodium at startup before any cryptographic operation is performed.

**How:** `crypto_init()` in `crypto.cpp` calls `sodium_init()`. Returns `false` on failure, causing `main()` to abort. Called as the very first operation in `main()`.

**Why:** libsodium requires runtime initialization to seed its CSPRNG and verify platform support. Any crypto call before `sodium_init()` is undefined behavior. Failing hard on init failure is safer than silently continuing with an uninitialized library.

---

### F-02 · X25519 key exchange
**Status:** `[Start]`

**What:** Generate an X25519 keypair per client and compute a shared secret via ECDH.

**How:** `generate_x25519_keypair()` wraps `crypto_box_keypair()`. `compute_x25519_shared_secret()` wraps `crypto_scalarmult()`. Both parties compute the same 32-byte shared secret from their own private key and the other's public key.

**Why:** X25519 is the standard for ephemeral Diffie-Hellman. It provides forward secrecy when combined with the ratchet (Phase 2). libsodium's implementation is constant-time and hardened against timing side-channels. This is the classical-security half of the hybrid PQ scheme.

---

### F-03 · ChaCha20-Poly1305 message encryption
**Status:** `[Start]`

**What:** Encrypt and authenticate every message using ChaCha20-Poly1305 IETF with a random 12-byte nonce and a 16-byte Poly1305 auth tag.

**How:** `encrypt_message()` in `crypto.cpp`:
1. Generates a fresh nonce via `randombytes_buf()`
2. Prepends a 4-byte big-endian length header to plaintext
3. Pads the buffer to `target_size` (default 512 bytes) with random bytes
4. Calls `crypto_aead_chacha20poly1305_encrypt()`
5. Splits the output into ciphertext + tag fields of `EncryptedMessage`

`decrypt_message()` reverses this: reassembles ciphertext ‖ tag, calls `crypto_aead_chacha20poly1305_decrypt()`, verifies the tag, strips the length header, and strips padding.

**Why:** ChaCha20-Poly1305 provides authenticated encryption — a failed tag means the message is rejected entirely, preventing padding oracle and chosen-ciphertext attacks. Random nonce per message prevents keystream reuse. Uniform 512-byte padding defeats traffic analysis based on message length. The Poly1305 tag is separated and stored in `EncryptedMessage.tag` to make transport serialization clean.

---

### F-04 · HKDF key derivation
**Status:** `[Start]`

**What:** Derive session keys (and later ratchet keys) from the raw shared secret using HKDF-SHA256.

**How:** `hkdf_derive()` in `crypto.cpp` implements RFC 5869 HKDF using libsodium's `crypto_auth_hmacsha256_*` primitives. Takes `ikm` (input key material), optional `salt`, an `info` context string, and desired output length. The `info` string `"shushhh_session_key_v1"` is used for session key derivation.

**Why:** Raw X25519 output is not uniformly distributed and should not be used as a key directly. HKDF extracts and expands it into proper key material. The `info` string binds the derived key to its specific purpose — a key derived with `"shushhh_session_key_v1"` cannot be confused with one derived with a different context. This function is the single derivation path for all keys in the system, making it the natural place to feed in the Kyber secret in Phase 2.

---

### F-05 · MessageSession management
**Status:** `[Start]`

**What:** Establish a typed session object that holds all state for an encrypted conversation between two parties.

**How:** `create_session()` takes a `KeyPair` and the peer's public key, computes the shared secret, runs `hkdf_derive()` with the session context string, and populates a `MessageSession` struct with `send_key`, `recv_key`, `send_counter`, and `recv_counter`. `session_encrypt()` and `session_decrypt()` wrap `encrypt_message()` and `decrypt_message()` with counter management.

**Why:** Encapsulating all session state in one struct makes the ratchet upgrade (Phase 2) a localized change — only `session_encrypt()` and `session_decrypt()` need modification. The counters are already in place for replay protection. Having separate `send_key` and `recv_key` fields (even though they're identical in Phase 0) means the asymmetric ratchet requires no struct changes.

---

### F-06 · JSON serialization over Tor
**Status:** `[Start]`

**What:** Serialize `EncryptedMessage` to a JSON string with all binary fields base64-encoded, then POST it through a Tor SOCKS5 proxy via libcurl.

**How:** `encrypted_to_json()` uses libsodium's `sodium_bin2base64()` and `nlohmann::json` to produce `{"nonce":"...","ciphertext":"...","tag":"..."}`. `json_to_encrypted()` reverses this. In `Main.cpp`, libcurl is configured with `CURLOPT_PROXY` pointing to `socks5h://127.0.0.1:9050` (the `h` means DNS resolution also goes through Tor).

**Why:** JSON with base64 is universally parseable and HTTP-friendly. The `socks5h://` scheme ensures the DNS request for the .onion address does not leak to the host network. All traffic — including the DNS resolution — travels through Tor, so neither the destination nor the content is visible to a network observer.

---

### F-07 · Secure memory wipe
**Status:** `[Start]`

**What:** Zero out sensitive memory (keys, shared secrets) immediately after use.

**How:** `secure_wipe()` wraps `sodium_memzero()`. Called explicitly after any key material is no longer needed, including in `FullCryptoTest()` after the demo session.

**Why:** Compilers are permitted to optimize away `memset()` calls on memory that is about to be freed or go out of scope, since the program won't read the memory again. `sodium_memzero()` uses platform-specific mechanisms (`SecureZeroMemory` on Windows, `explicit_memset` on BSD, a volatile write loop elsewhere) that the compiler cannot elide. This limits the window during which a memory dump could recover key material.

---

## Phase 1 — Authentication & Relay `[PLANNED]`

### F-08 · LoginProvider interface
**Status:** `[PLANNED]`

**What:** An abstract C++ base class that defines the authentication contract. `PasswordLogin` is the first concrete implementation.

**How:**
```cpp
class LoginProvider {
public:
    virtual bool authenticate() = 0;
    virtual std::vector<unsigned char> get_credential_hash() = 0;
    virtual ~LoginProvider() = default;
};

class PasswordLogin : public LoginProvider {
    bool authenticate() override;
    std::vector<unsigned char> get_credential_hash() override;
};
```
Client-side: `SHA-256(password + username)` is computed locally — the raw password never leaves the machine. The hash is then encrypted with `encrypt_message()` before being sent to the server.

Server-side: stores `(username, random_salt, SHA-256(password + salt))`. Compares with `sodium_memcmp()` for constant-time equality.

**Why:** The interface decouples authentication from the rest of the system. When the next login method is ready (hardware token, challenge-response, biometric challenge), it subclasses `LoginProvider` and nothing else changes. Hashing on the client means even a compromised Tor circuit cannot expose the raw password. Constant-time comparison prevents timing-based credential enumeration.

---

### F-09 · Ed25519 signed server auth response
**Status:** `[PLANNED]`

**What:** The server signs every authentication response with its Ed25519 private key. The client verifies the signature using the server's public key, which is hardcoded into the binary.

**How:** Server uses `crypto_sign_ed25519_detached()` to sign the response payload. Client calls `crypto_sign_ed25519_verify_detached()`. Server keypair generated once at setup; public key compiled into the client binary.

**Why:** Without this, a MITM who intercepts the Tor circuit could return a fake "authenticated" response. With the signed response, forging it requires the server's Ed25519 private key. Since the verification key is in the binary, the client has a trust anchor independent of the network path.

---

### F-10 · .onion store-and-forward relay
**Status:** `[PLANNED]`

**What:** A server running as a Tor hidden service that accepts `POST /drop` (store message) and `GET /fetch` (retrieve messages) endpoints. Stores ciphertext blobs keyed by `SHA-256(recipient_public_key)`. Deletes messages on delivery ACK.

**How:**
- Recipient tag = `SHA-256(their_public_key)` — computed client-side and included in the JSON payload
- Server stores `(tag, blob, timestamp)` in SQLite
- Schema disguised as `telemetry_events(event_id, device_fingerprint, payload, ts)` where `device_fingerprint` = tag and `payload` = the encrypted JSON blob
- Storage volume is LUKS-encrypted
- Messages older than 7 days auto-expire even without ACK

**Why:** The relay never holds session keys so it cannot decrypt messages. Using a hash of the public key as the delivery tag means the server never sees real user identifiers. The disguised schema provides plausible deniability — an adversary with physical access to the server sees what appears to be analytics telemetry. LUKS means the disk looks like random noise without the volume key.

---

### F-11 · Watchdog auto-wipe
**Status:** `[PLANNED]`

**What:** On pendrive insertion, shushhh writes a watchdog binary and wipe script to `%TEMP%` and launches it as a detached process. The watchdog polls for the USB drive letter every 2 seconds. On disconnect it runs the wipe sequence and self-deletes.

**How:**
1. `Main.cpp` calls `launch_watchdog()` immediately after `crypto_init()`
2. Watchdog binary + `shushhh_wipe.bat` extracted from embedded resources to `%TEMP%`
3. Watchdog launched via `CreateProcess()` with `DETACHED_PROCESS` flag
4. Watchdog polls `GetLogicalDrives()` or `PathFileExists(drive_letter)` every 2 seconds
5. On missing drive: executes wipe bat, then schedules self-deletion via `cmd /c ping 127.0.0.1 -n 3 >nul & del watchdog.exe`

Wipe bat sequence:
```bat
cipher /w:%TEMP%          :: overwrite free space sectors
del /f /q %TEMP%\shushhh_*
del /f /q %APPDATA%\shushhh_*
```

**Why:** `cipher /w` overwrites free disk space so deleted files cannot be forensically recovered with tools like Recuva or Autopsy. The detached process model means the wipe executes even if shushhh is killed or crashes before the drive is removed. The self-deleting watchdog leaves no artifacts after it runs.

---

## Phase 2 — Quantum Resistance `[PLANNED]`

### F-12 · ML-KEM-768 (Kyber) hybrid key exchange
**Status:** `[PLANNED]`

**What:** Add ML-KEM-768 (NIST FIPS 203) key exchange via liboqs alongside the existing X25519. Both produce 32-byte shared secrets; both are combined via `hkdf_derive()` into a single root key.

**How:** Modify `create_session()` only:
```cpp
// existing X25519
auto x25519_secret = compute_x25519_shared_secret(my_priv, their_x25519_pub);

// new Kyber
OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
OQS_KEM_encaps(kem, kyber_ciphertext.data(), kyber_secret.data(), their_kyber_pub);

// combine: 32 + 32 = 64 bytes into HKDF
std::vector<uint8_t> ikm = concat(x25519_secret, kyber_secret);
session.root_key = hkdf_derive(ikm.data(), 64, nullptr, 0, "shushhh_session_key_v1", 32);
```
Receiver side: `OQS_KEM_decaps()` to recover `kyber_secret`, then same HKDF call.
The 1088-byte Kyber encapsulation ciphertext is sent during the handshake (separate from messages).

**Why:** X25519 is broken by Shor's algorithm on a sufficiently large quantum computer. ML-KEM (Kyber) is based on Module Learning With Errors — a lattice problem for which no efficient quantum algorithm exists. The hybrid approach means security is maintained against both classical attackers (X25519) and quantum attackers (Kyber). If either primitive is broken, the other still provides security. Only `create_session()` changes — all downstream encryption, padding, JSON, and transport is untouched.

---

### F-13 · Symmetric ratchet (forward secrecy)
**Status:** `[PLANNED]`

**What:** After each message, derive the next `send_key` (or `recv_key`) from the current one via `hkdf_derive()`, then immediately `secure_wipe()` the old key.

**How:** Modify `session_encrypt()`:
```cpp
EncryptedMessage session_encrypt(MessageSession& session, const std::string& plaintext) {
    EncryptedMessage enc = encrypt_message(plaintext, session.send_key.data());

    std::string info = "shushhh_ratchet_v1:" + std::to_string(session.send_counter);
    auto next_key = hkdf_derive(session.send_key.data(), 32, nullptr, 0, info, 32);
    secure_wipe(session.send_key.data(), 32);
    session.send_key = next_key;
    session.send_counter++;

    return enc;
}
```
Mirror for `session_decrypt()` using `recv_key` and `recv_counter`.

**Why:** Forward secrecy means capturing today's `send_key` cannot decrypt yesterday's messages — those keys have been wiped. The counter in the HKDF `info` string ensures each ratchet step produces a unique key even if the same input key were somehow reused. This requires zero new infrastructure — `hkdf_derive()` and `secure_wipe()` are already implemented. The counters in `MessageSession` are already there.

---

## Phase 3 — Future `[FUTURE]`

### F-14 · Alternative LoginProvider
**Status:** `[FUTURE]`

**What:** Replace `PasswordLogin` with a more paranoid authentication mechanism (exact design TBD by project owner).

**How:** Subclass `LoginProvider`, implement `authenticate()` and `get_credential_hash()`. Swap the instantiation in `main()`. No other changes required.

**Why:** The LoginProvider interface in Phase 1 exists precisely to make this a one-file change. The "crazy idea" authentication can be as unconventional as needed — hardware challenge, steganographic key, etc. — without touching the crypto or transport layers.

---

### F-15 · DH ratchet (Signal-protocol-style double ratchet)
**Status:** `[FUTURE]`

**What:** Upgrade the symmetric ratchet (F-13) to a full double ratchet where each message also carries a new ephemeral Diffie-Hellman public key. The root key is re-derived on each DH step.

**How:** Each `EncryptedMessage` gains an ephemeral X25519 (and optionally Kyber) public key field. On receive, a new DH exchange is performed and the root key updated. This adds break-in recovery — even if an attacker captures a session key, subsequent messages are secured by a new DH exchange they cannot complete.

**Why:** The symmetric ratchet alone provides forward secrecy but not break-in recovery. The double ratchet provides both. For a pendrive messenger where devices are physically portable and potentially seizeable, break-in recovery is a meaningful upgrade.

---

## Completed Feature Summary

| ID | Feature | Status |
|---|---|---|
| F-01 | libsodium initialization | `[Start]` |
| F-02 | X25519 key exchange | `[Start]` |
| F-03 | ChaCha20-Poly1305 encryption | `[Start]` |
| F-04 | HKDF key derivation | `[Start]` |
| F-05 | MessageSession management | `[Start]` |
| F-06 | JSON serialization over Tor | `[Start]` |
| F-07 | Secure memory wipe | `[Start]` |
| F-08 | LoginProvider interface | `[PLANNED]` |
| F-09 | Ed25519 signed auth response | `[PLANNED]` |
| F-10 | .onion store-and-forward relay | `[PLANNED]` |
| F-11 | Watchdog auto-wipe | `[PLANNED]` |
| F-12 | ML-KEM-768 hybrid key exchange | `[PLANNED]` |
| F-13 | Symmetric ratchet | `[PLANNED]` |
| F-14 | Alternative LoginProvider | `[FUTURE]` |
| F-15 | Double ratchet | `[FUTURE]` |
