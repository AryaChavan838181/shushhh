#pragma once

#include <string>
#include <vector>
#include <cstdint>

// ============================================================
// Data Structures
// ============================================================

// 32-byte X25519 keypair
struct KeyPair {
    unsigned char private_key[32];
    unsigned char public_key[32];
};

// A single encrypted blob ready for transport
struct EncryptedMessage {
    unsigned char nonce[12];            // random per-message, ChaCha20-Poly1305 IETF
    std::vector<unsigned char> ciphertext;
    unsigned char tag[16];              // Poly1305 auth tag
};

// Full session state between two clients
struct MessageSession {
    KeyPair my_keypair;
    unsigned char their_public_key[32];
    std::vector<unsigned char> root_key;    // from X25519 (+ Kyber in Phase 2)
    std::vector<unsigned char> send_key;    // ratchets forward on each send (Phase 2)
    std::vector<unsigned char> recv_key;    // ratchets forward on each recv (Phase 2)
    uint32_t send_counter;                  // replay protection
    uint32_t recv_counter;
};

// ============================================================
// F-01 · libsodium initialization
// ============================================================

// Initialize libsodium. Must be called before any other crypto function.
// Returns true on success, false on failure (caller should abort).
bool crypto_init();

// ============================================================
// F-02 · X25519 key exchange
// ============================================================

// Generate a fresh X25519 keypair.
KeyPair generate_x25519_keypair();

// Compute the 32-byte ECDH shared secret from our private key and their public key.
// Returns empty vector on failure.
std::vector<unsigned char> compute_x25519_shared_secret(
    const unsigned char* my_private_key,
    const unsigned char* their_public_key
);

// ============================================================
// F-04 · HKDF key derivation (RFC 5869)
// ============================================================

// Derive key material from input key material using HKDF-SHA256.
// Returns empty vector on failure.
std::vector<unsigned char> hkdf_derive(
    const unsigned char* ikm, size_t ikm_len,
    const unsigned char* salt, size_t salt_len,
    const std::string& info,
    size_t output_len
);

// ============================================================
// F-03 · ChaCha20-Poly1305 message encryption
// ============================================================

// Encrypt plaintext with ChaCha20-Poly1305 IETF.
// Prepends a 4-byte big-endian length header, pads to target_size with random bytes.
// Returns an EncryptedMessage with nonce, ciphertext, and tag fields populated.
EncryptedMessage encrypt_message(
    const std::string& plaintext,
    const unsigned char* key,
    size_t target_size = 512
);

// Decrypt an EncryptedMessage. Verifies the Poly1305 tag, strips length header and padding.
// Returns empty string on any failure (tag mismatch, malformed input, etc.).
std::string decrypt_message(
    const EncryptedMessage& encrypted,
    const unsigned char* key
);

// ============================================================
// F-05 · MessageSession management
// ============================================================

// Create a session from our keypair and the peer's public key.
// Computes shared secret via X25519, derives keys via HKDF.
MessageSession create_session(
    const KeyPair& my_keypair,
    const unsigned char* their_public_key
);

// Encrypt a message within a session context. Increments send_counter.
EncryptedMessage session_encrypt(MessageSession& session, const std::string& plaintext);

// Decrypt a message within a session context. Increments recv_counter.
std::string session_decrypt(MessageSession& session, const EncryptedMessage& encrypted);

// ============================================================
// F-06 · JSON serialization
// ============================================================

// Serialize an EncryptedMessage to a JSON string with base64-encoded fields.
// Format: {"nonce":"...","ciphertext":"...","tag":"..."}
std::string encrypted_to_json(const EncryptedMessage& msg);

// Deserialize a JSON string back to an EncryptedMessage.
// Returns an EncryptedMessage with empty ciphertext on failure.
EncryptedMessage json_to_encrypted(const std::string& json_str);

// ============================================================
// F-07 · Secure memory wipe
// ============================================================

// Securely zero out memory using sodium_memzero (compiler cannot elide).
void secure_wipe(void* ptr, size_t len);

// ============================================================
// Phase 1 · SHA-256 hashing
// ============================================================

// Compute SHA-256 hash of arbitrary data. Used for:
// - Credential hashing: SHA-256(password + username)
// - Recipient routing tags: SHA-256(public_key)
std::vector<unsigned char> sha256_hash(
    const unsigned char* data, size_t data_len
);

// Convenience overload for string input.
std::vector<unsigned char> sha256_hash(const std::string& data);

// ============================================================
// Phase 1 · Ed25519 signatures (F-09)
// ============================================================

// Ed25519 signing keypair (separate from X25519 — different curves)
struct SigningKeyPair {
    unsigned char private_key[64];   // crypto_sign_ed25519 secret key is 64 bytes
    unsigned char public_key[32];
};

// Generate a fresh Ed25519 signing keypair.
SigningKeyPair generate_ed25519_keypair();

// Create a detached Ed25519 signature over a message.
std::vector<unsigned char> ed25519_sign_detached(
    const unsigned char* message, size_t message_len,
    const unsigned char* private_key
);

// Verify a detached Ed25519 signature.
// Returns true if the signature is valid.
bool ed25519_verify_detached(
    const unsigned char* signature,
    const unsigned char* message, size_t message_len,
    const unsigned char* public_key
);

// ============================================================
// Phase 1 · Recipient tag (F-10 relay routing)
// ============================================================

// Compute SHA-256(public_key) — used as the delivery tag on the relay.
// The relay never sees real identities, only this hash.
std::string compute_recipient_tag(const unsigned char* public_key);

// ============================================================
// Testing
// ============================================================

// Run the full crypto test suite. Validates:
// - X25519 shared secret symmetry
// - encrypt_message / decrypt_message roundtrip
// - HKDF determinism
// - Session encrypt / decrypt roundtrip
// - JSON serialization roundtrip
// - SHA-256 consistency (Phase 1)
// - Ed25519 sign/verify roundtrip (Phase 1)
void FullCryptoTest();
