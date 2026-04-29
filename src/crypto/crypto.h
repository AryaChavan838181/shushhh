#pragma once

#include <string>
#include <vector>
#include <cstdint>

// ============================================================
// Data Structures
// ============================================================

// Hybrid X25519 + ML-KEM-768 (Kyber) keypair
struct HybridKeyPair {
    unsigned char x25519_private[32];
    unsigned char x25519_public[32];

    std::vector<unsigned char> kyber_private; // 2400 bytes
    std::vector<unsigned char> kyber_public;  // 1184 bytes
};

// A single encrypted blob ready for transport
struct EncryptedMessage {
    unsigned char nonce[12];            // random per-message, ChaCha20-Poly1305 IETF
    std::vector<unsigned char> ciphertext;
    unsigned char tag[16];              // Poly1305 auth tag
};

// Full session state between two clients
struct MessageSession {
    HybridKeyPair my_keypair;
    unsigned char their_x25519_public_key[32];
    std::vector<unsigned char> their_kyber_public_key;

    std::vector<unsigned char> root_key;    // from X25519 + Kyber
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
// F-02 & F-12 · Hybrid key exchange
// ============================================================

// Generate a fresh HybridKeyPair (X25519 + ML-KEM-768).
HybridKeyPair generate_hybrid_keypair();

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
// F-05 & F-12 · Hybrid MessageSession management
// ============================================================

// Create a session as the initiator.
// Takes the peer's hybrid public keys.
// Populates out_kyber_ciphertext with the 1088-byte ML-KEM-768 encapsulation
// which must be sent to the responder.
MessageSession create_session_initiator(
    const HybridKeyPair& my_keypair,
    const unsigned char* their_x25519_public,
    const std::vector<unsigned char>& their_kyber_public,
    std::vector<unsigned char>& out_kyber_ciphertext
);

// Create a session as the responder.
// Takes the initiator's X25519 public key and the Kyber ciphertext they generated.
MessageSession create_session_responder(
    const HybridKeyPair& my_keypair,
    const unsigned char* their_x25519_public,
    const std::vector<unsigned char>& kyber_ciphertext
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
// Phase 2 · 0-RTT Ephemeral Handshake (Sealed Sender)
// ============================================================

struct HandshakePayload {
    unsigned char ephemeral_public[32];
    EncryptedMessage encrypted_blob;
};

// Generates an anonymous handshake. Encrypts the JSON payload (containing sender identity and Kyber ciphertext)
// using an outer tunnel derived from a fresh Ephemeral X25519 key and the recipient's Identity X25519 public key.
HandshakePayload generate_ephemeral_handshake(
    const unsigned char* recipient_identity_public,
    const std::string& inner_json_payload
);

// Processes an incoming handshake. Decrypts the payload using the recipient's private Identity X25519 key
// and the provided Ephemeral X25519 public key. Returns empty string on failure.
std::string process_ephemeral_handshake(
    const unsigned char* my_identity_private,
    const HandshakePayload& handshake
);

// Helper for Handshake serialization
std::string handshake_to_json(const HandshakePayload& hs);
HandshakePayload json_to_handshake(const std::string& json_str);

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
// - ML-KEM-768 / Hybrid Session roundtrip (Phase 2)
// - Symmetric Ratchet validation (Phase 2)
void FullCryptoTest();
