#include "crypto/crypto.h"

#include <sodium.h>
#include <oqs/oqs.h>
#include <nlohmann/json.hpp>

#include <iostream>
#include <cstring>
#include <algorithm>

using json = nlohmann::json;

// ============================================================
// F-01 · libsodium initialization
// ============================================================

bool crypto_init() {
    if (sodium_init() < 0) {
        std::cerr << "[-] Fatal: sodium_init() failed — cannot proceed without CSPRNG\n";
        return false;
    }
    std::cout << "[+] libsodium initialized successfully\n";
    return true;
}

// ============================================================
// F-02 & F-12 · Hybrid key exchange (X25519 + ML-KEM-768)
// ============================================================

HybridKeyPair generate_hybrid_keypair() {
    HybridKeyPair kp;
    // crypto_box_keypair generates a Curve25519 keypair suitable for X25519 ECDH
    crypto_box_keypair(kp.x25519_public, kp.x25519_private);

    // Generate ML-KEM-768 (Kyber) keypair
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem != nullptr) {
        kp.kyber_public.resize(kem->length_public_key);
        kp.kyber_private.resize(kem->length_secret_key);
        if (OQS_KEM_keypair(kem, kp.kyber_public.data(), kp.kyber_private.data()) != OQS_SUCCESS) {
            std::cerr << "[-] ML-KEM-768 key generation failed\n";
        }
        OQS_KEM_free(kem);
    } else {
        std::cerr << "[-] Failed to initialize ML-KEM-768 subsystem\n";
    }

    return kp;
}

std::vector<unsigned char> compute_x25519_shared_secret(
    const unsigned char* my_private_key,
    const unsigned char* their_public_key
) {
    std::vector<unsigned char> shared(32);

    // crypto_scalarmult performs the raw X25519 scalar multiplication
    // Returns -1 if the result is the all-zero point (malicious input)
    if (crypto_scalarmult(shared.data(), my_private_key, their_public_key) != 0) {
        std::cerr << "[-] X25519 scalar multiplication failed — possible malicious public key\n";
        return {};
    }

    return shared;
}

// ============================================================
// F-04 · HKDF key derivation (RFC 5869)
// ============================================================

// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
static std::vector<unsigned char> hkdf_extract(
    const unsigned char* salt, size_t salt_len,
    const unsigned char* ikm, size_t ikm_len
) {
    // If no salt provided, use a string of HashLen zeros (RFC 5869 §2.2)
    unsigned char default_salt[crypto_auth_hmacsha256_KEYBYTES] = {0};
    const unsigned char* actual_salt = salt;
    size_t actual_salt_len = salt_len;

    if (actual_salt == nullptr || actual_salt_len == 0) {
        actual_salt = default_salt;
        actual_salt_len = crypto_auth_hmacsha256_KEYBYTES;
    }

    std::vector<unsigned char> prk(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state state;

    // HMAC-SHA256 with salt as key and IKM as message
    crypto_auth_hmacsha256_init(&state, actual_salt, actual_salt_len);
    crypto_auth_hmacsha256_update(&state, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&state, prk.data());

    // Wipe the HMAC state — it contains intermediate key material
    secure_wipe(&state, sizeof(state));

    return prk;
}

// HKDF-Expand: OKM = T(1) || T(2) || ... where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
static std::vector<unsigned char> hkdf_expand(
    const unsigned char* prk, size_t prk_len,
    const std::string& info,
    size_t output_len
) {
    // RFC 5869: output_len <= 255 * HashLen
    size_t hash_len = crypto_auth_hmacsha256_BYTES;
    size_t n = (output_len + hash_len - 1) / hash_len;
    if (n > 255) {
        std::cerr << "[-] HKDF-Expand: requested output too long\n";
        return {};
    }

    std::vector<unsigned char> okm;
    okm.reserve(n * hash_len);

    std::vector<unsigned char> t_prev; // T(0) is empty

    for (size_t i = 1; i <= n; ++i) {
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, prk, prk_len);

        // T(i-1) — empty for the first iteration
        if (!t_prev.empty()) {
            crypto_auth_hmacsha256_update(&state, t_prev.data(), t_prev.size());
        }

        // info string
        crypto_auth_hmacsha256_update(&state,
            reinterpret_cast<const unsigned char*>(info.data()), info.size());

        // counter byte (1-indexed)
        unsigned char counter = static_cast<unsigned char>(i);
        crypto_auth_hmacsha256_update(&state, &counter, 1);

        t_prev.resize(hash_len);
        crypto_auth_hmacsha256_final(&state, t_prev.data());

        okm.insert(okm.end(), t_prev.begin(), t_prev.end());

        secure_wipe(&state, sizeof(state));
    }

    // Truncate to requested length
    okm.resize(output_len);
    return okm;
}

std::vector<unsigned char> hkdf_derive(
    const unsigned char* ikm, size_t ikm_len,
    const unsigned char* salt, size_t salt_len,
    const std::string& info,
    size_t output_len
) {
    // Extract
    auto prk = hkdf_extract(salt, salt_len, ikm, ikm_len);
    if (prk.empty()) {
        std::cerr << "[-] HKDF extract failed\n";
        return {};
    }

    // Expand
    auto okm = hkdf_expand(prk.data(), prk.size(), info, output_len);

    // Wipe the PRK — it's the extracted key material, no longer needed
    secure_wipe(prk.data(), prk.size());

    return okm;
}

// ============================================================
// F-03 · ChaCha20-Poly1305 message encryption
// ============================================================

EncryptedMessage encrypt_message(
    const std::string& plaintext,
    const unsigned char* key,
    size_t target_size
) {
    EncryptedMessage msg;

    // -- Build the padded plaintext buffer --
    // Format: [4-byte big-endian length] [plaintext bytes] [random padding to target_size]
    uint32_t pt_len = static_cast<uint32_t>(plaintext.size());
    size_t padded_len = target_size;

    // Ensure target_size can hold header + plaintext
    if (4 + plaintext.size() > target_size) {
        padded_len = 4 + plaintext.size();
    }

    std::vector<unsigned char> buffer(padded_len);

    // 4-byte big-endian length header
    buffer[0] = static_cast<unsigned char>((pt_len >> 24) & 0xFF);
    buffer[1] = static_cast<unsigned char>((pt_len >> 16) & 0xFF);
    buffer[2] = static_cast<unsigned char>((pt_len >> 8)  & 0xFF);
    buffer[3] = static_cast<unsigned char>((pt_len)       & 0xFF);

    // Copy plaintext after header
    std::memcpy(buffer.data() + 4, plaintext.data(), plaintext.size());

    // Fill remainder with random bytes to defeat traffic analysis on message length
    if (padded_len > 4 + plaintext.size()) {
        randombytes_buf(buffer.data() + 4 + plaintext.size(),
                        padded_len - 4 - plaintext.size());
    }

    // -- Generate fresh nonce --
    // 12-byte random nonce for ChaCha20-Poly1305 IETF — collision probability negligible
    randombytes_buf(msg.nonce, sizeof(msg.nonce));

    // -- Encrypt --
    // Output = ciphertext || tag (crypto_aead appends tag to ciphertext)
    size_t combined_len = padded_len + crypto_aead_chacha20poly1305_IETF_ABYTES;
    std::vector<unsigned char> combined(combined_len);
    unsigned long long actual_len = 0;

    crypto_aead_chacha20poly1305_ietf_encrypt(
        combined.data(), &actual_len,
        buffer.data(), padded_len,
        nullptr, 0,        // no additional data
        nullptr,           // nsec (unused in this construction)
        msg.nonce,
        key
    );

    // -- Split ciphertext and tag --
    // libsodium appends the 16-byte Poly1305 tag after the ciphertext
    size_t ct_len = actual_len - crypto_aead_chacha20poly1305_IETF_ABYTES;
    msg.ciphertext.assign(combined.begin(), combined.begin() + ct_len);
    std::memcpy(msg.tag, combined.data() + ct_len, 16);

    // Wipe the plaintext buffer — it held the raw message
    secure_wipe(buffer.data(), buffer.size());

    return msg;
}

std::string decrypt_message(
    const EncryptedMessage& encrypted,
    const unsigned char* key
) {
    // -- Reassemble ciphertext || tag for libsodium --
    std::vector<unsigned char> combined;
    combined.reserve(encrypted.ciphertext.size() + 16);
    combined.insert(combined.end(), encrypted.ciphertext.begin(), encrypted.ciphertext.end());
    combined.insert(combined.end(), encrypted.tag, encrypted.tag + 16);

    // -- Decrypt and verify tag --
    std::vector<unsigned char> decrypted(encrypted.ciphertext.size());
    unsigned long long decrypted_len = 0;

    int result = crypto_aead_chacha20poly1305_ietf_decrypt(
        decrypted.data(), &decrypted_len,
        nullptr,           // nsec (unused)
        combined.data(), combined.size(),
        nullptr, 0,        // no additional data
        encrypted.nonce,
        key
    );

    if (result != 0) {
        std::cerr << "[-] Decryption failed — authentication tag mismatch (message tampered or wrong key)\n";
        return "";
    }

    // -- Strip length header and padding --
    if (decrypted_len < 4) {
        std::cerr << "[-] Decrypted data too short to contain length header\n";
        secure_wipe(decrypted.data(), decrypted.size());
        return "";
    }

    uint32_t msg_len = (static_cast<uint32_t>(decrypted[0]) << 24) |
                       (static_cast<uint32_t>(decrypted[1]) << 16) |
                       (static_cast<uint32_t>(decrypted[2]) << 8)  |
                       (static_cast<uint32_t>(decrypted[3]));

    if (msg_len > decrypted_len - 4) {
        std::cerr << "[-] Length header exceeds decrypted payload — corrupted message\n";
        secure_wipe(decrypted.data(), decrypted.size());
        return "";
    }

    std::string plaintext(reinterpret_cast<char*>(decrypted.data() + 4), msg_len);

    // Wipe the decrypted buffer — it contained plaintext
    secure_wipe(decrypted.data(), decrypted.size());

    return plaintext;
}

// ============================================================
// F-05 & F-12 · Hybrid MessageSession management
// ============================================================

MessageSession create_session_initiator(
    const HybridKeyPair& my_keypair,
    const unsigned char* their_x25519_public,
    const std::vector<unsigned char>& their_kyber_public,
    std::vector<unsigned char>& out_kyber_ciphertext
) {
    MessageSession session;

    // Copy keypair and peer's public keys into session
    session.my_keypair = my_keypair;
    std::memcpy(session.their_x25519_public_key, their_x25519_public, 32);
    session.their_kyber_public_key = their_kyber_public;

    // 1. Compute X25519 shared secret
    auto x25519_secret = compute_x25519_shared_secret(my_keypair.x25519_private, their_x25519_public);
    if (x25519_secret.empty()) {
        std::cerr << "[-] Session creation failed — X25519 computation failed\n";
        return session;
    }

    // 2. Compute ML-KEM-768 shared secret via encapsulation
    std::vector<unsigned char> kyber_secret;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem != nullptr) {
        out_kyber_ciphertext.resize(kem->length_ciphertext);
        kyber_secret.resize(kem->length_shared_secret);
        if (OQS_KEM_encaps(kem, out_kyber_ciphertext.data(), kyber_secret.data(), their_kyber_public.data()) != OQS_SUCCESS) {
             std::cerr << "[-] Session creation failed — ML-KEM-768 encapsulation failed\n";
             OQS_KEM_free(kem);
             return session;
        }
        OQS_KEM_free(kem);
    } else {
        std::cerr << "[-] ML-KEM subsystem unavailable\n";
        return session;
    }

    // 3. Combine secrets into Initial Keying Material (IKM) -> 32 + 32 = 64 bytes
    std::vector<unsigned char> ikm;
    ikm.reserve(x25519_secret.size() + kyber_secret.size());
    ikm.insert(ikm.end(), x25519_secret.begin(), x25519_secret.end());
    ikm.insert(ikm.end(), kyber_secret.begin(), kyber_secret.end());

    // Derive root key via HKDF
    session.root_key = hkdf_derive(
        ikm.data(), ikm.size(),
        nullptr, 0,
        "shushhh_session_key_v1",
        32
    );

    // Initial send/recv keys are derived from the root
    session.send_key = session.root_key;
    session.recv_key = session.root_key;
    session.send_counter = 0;
    session.recv_counter = 0;

    // Wipe the raw shared secrets immediately
    secure_wipe(x25519_secret.data(), x25519_secret.size());
    secure_wipe(kyber_secret.data(), kyber_secret.size());
    secure_wipe(ikm.data(), ikm.size());

    std::cout << "[+] Session created (Initiator) — hybrid keys derived, counters initialized\n";
    return session;
}

MessageSession create_session_responder(
    const HybridKeyPair& my_keypair,
    const unsigned char* their_x25519_public,
    const std::vector<unsigned char>& kyber_ciphertext
) {
    MessageSession session;
    session.my_keypair = my_keypair;
    std::memcpy(session.their_x25519_public_key, their_x25519_public, 32);
    // Peer's kyber pubkey is unknown to responder, and unneeded for messaging

    // 1. Compute X25519 shared secret
    auto x25519_secret = compute_x25519_shared_secret(my_keypair.x25519_private, their_x25519_public);
    if (x25519_secret.empty()) {
        std::cerr << "[-] Session creation failed — X25519 computation failed\n";
        return session;
    }

    // 2. Compute ML-KEM-768 shared secret via decapsulation
    std::vector<unsigned char> kyber_secret;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem != nullptr) {
        kyber_secret.resize(kem->length_shared_secret);
        if (OQS_KEM_decaps(kem, kyber_secret.data(), kyber_ciphertext.data(), my_keypair.kyber_private.data()) != OQS_SUCCESS) {
            std::cerr << "[-] Session creation failed — ML-KEM-768 decapsulation failed\n";
            OQS_KEM_free(kem);
            return session;
        }
        OQS_KEM_free(kem);
    } else {
        std::cerr << "[-] ML-KEM subsystem unavailable\n";
        return session;
    }

    // 3. Combine secrets
    std::vector<unsigned char> ikm;
    ikm.reserve(x25519_secret.size() + kyber_secret.size());
    ikm.insert(ikm.end(), x25519_secret.begin(), x25519_secret.end());
    ikm.insert(ikm.end(), kyber_secret.begin(), kyber_secret.end());

    // Derive root key via HKDF
    session.root_key = hkdf_derive(
        ikm.data(), ikm.size(),
        nullptr, 0,
        "shushhh_session_key_v1",
        32
    );

    session.send_key = session.root_key;
    session.recv_key = session.root_key;
    session.send_counter = 0;
    session.recv_counter = 0;

    secure_wipe(x25519_secret.data(), x25519_secret.size());
    secure_wipe(kyber_secret.data(), kyber_secret.size());
    secure_wipe(ikm.data(), ikm.size());

    std::cout << "[+] Session created (Responder) — hybrid keys derived, counters initialized\n";
    return session;
}

EncryptedMessage session_encrypt(MessageSession& session, const std::string& plaintext) {
    EncryptedMessage enc = encrypt_message(plaintext, session.send_key.data());

    // F-13: Symmetric Ratchet — derive next send key, verify wiping old key
    std::string info = "shushhh_ratchet_v1:" + std::to_string(session.send_counter);
    auto next_key = hkdf_derive(session.send_key.data(), 32, nullptr, 0, info, 32);
    
    secure_wipe(session.send_key.data(), session.send_key.size());
    session.send_key = next_key;
    session.send_counter++;

    return enc;
}

std::string session_decrypt(MessageSession& session, const EncryptedMessage& encrypted) {
    std::string plaintext = decrypt_message(encrypted, session.recv_key.data());
    
    if (!plaintext.empty()) {
        // F-13: Symmetric Ratchet — derive next recv key, verify wiping old key
        std::string info = "shushhh_ratchet_v1:" + std::to_string(session.recv_counter);
        auto next_key = hkdf_derive(session.recv_key.data(), 32, nullptr, 0, info, 32);
        
        secure_wipe(session.recv_key.data(), session.recv_key.size());
        session.recv_key = next_key;
        session.recv_counter++;
    }
    
    return plaintext;
}

// ============================================================
// F-06 · JSON serialization
// ============================================================

// Helper: binary to base64 string using libsodium (not OpenSSL — no extra dependency)
static std::string to_base64(const unsigned char* data, size_t len) {
    size_t b64_maxlen = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::string b64(b64_maxlen, '\0');
    sodium_bin2base64(&b64[0], b64_maxlen, data, len, sodium_base64_VARIANT_ORIGINAL);
    // sodium_bin2base64 null-terminates; resize to actual string length
    b64.resize(std::strlen(b64.c_str()));
    return b64;
}

// Helper: base64 string to binary vector
static std::vector<unsigned char> from_base64(const std::string& b64) {
    std::vector<unsigned char> bin(b64.size()); // upper bound
    size_t bin_len = 0;
    if (sodium_base642bin(bin.data(), bin.size(), b64.c_str(), b64.size(),
                          nullptr, &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        std::cerr << "[-] Base64 decode failed\n";
        return {};
    }
    bin.resize(bin_len);
    return bin;
}

std::string encrypted_to_json(const EncryptedMessage& msg) {
    json j;
    j["nonce"]      = to_base64(msg.nonce, sizeof(msg.nonce));
    j["ciphertext"] = to_base64(msg.ciphertext.data(), msg.ciphertext.size());
    j["tag"]        = to_base64(msg.tag, sizeof(msg.tag));
    return j.dump();
}

EncryptedMessage json_to_encrypted(const std::string& json_str) {
    EncryptedMessage msg;
    std::memset(msg.nonce, 0, sizeof(msg.nonce));
    std::memset(msg.tag, 0, sizeof(msg.tag));

    try {
        json j = json::parse(json_str);

        auto nonce_bin = from_base64(j["nonce"].get<std::string>());
        auto ct_bin    = from_base64(j["ciphertext"].get<std::string>());
        auto tag_bin   = from_base64(j["tag"].get<std::string>());

        if (nonce_bin.size() != 12 || tag_bin.size() != 16) {
            std::cerr << "[-] JSON deserialization: invalid nonce or tag length\n";
            return msg;
        }

        std::memcpy(msg.nonce, nonce_bin.data(), 12);
        msg.ciphertext = std::move(ct_bin);
        std::memcpy(msg.tag, tag_bin.data(), 16);

    } catch (const json::exception& e) {
        std::cerr << "[-] JSON parse error: " << e.what() << "\n";
    }

    return msg;
}

// ============================================================
// F-07 · Secure memory wipe
// ============================================================

void secure_wipe(void* ptr, size_t len) {
    // sodium_memzero uses platform-specific mechanisms that the compiler
    // cannot optimize away (SecureZeroMemory on Windows, explicit_memset on BSD,
    // volatile write loop elsewhere)
    sodium_memzero(ptr, len);
}

// ============================================================
// Phase 1 · SHA-256 hashing
// ============================================================

std::vector<unsigned char> sha256_hash(
    const unsigned char* data, size_t data_len
) {
    std::vector<unsigned char> hash(crypto_hash_sha256_BYTES); // 32 bytes
    crypto_hash_sha256(hash.data(), data, data_len);
    return hash;
}

std::vector<unsigned char> sha256_hash(const std::string& data) {
    return sha256_hash(
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size()
    );
}

// ============================================================
// Phase 1 · Ed25519 signatures (F-09)
// ============================================================

SigningKeyPair generate_ed25519_keypair() {
    SigningKeyPair kp;
    crypto_sign_ed25519_keypair(kp.public_key, kp.private_key);
    return kp;
}

std::vector<unsigned char> ed25519_sign_detached(
    const unsigned char* message, size_t message_len,
    const unsigned char* private_key
) {
    std::vector<unsigned char> sig(crypto_sign_ed25519_BYTES); // 64 bytes
    unsigned long long sig_len = 0;

    if (crypto_sign_ed25519_detached(sig.data(), &sig_len,
                                     message, message_len,
                                     private_key) != 0) {
        std::cerr << "[-] Ed25519 signing failed\n";
        return {};
    }

    sig.resize(sig_len);
    return sig;
}

bool ed25519_verify_detached(
    const unsigned char* signature,
    const unsigned char* message, size_t message_len,
    const unsigned char* public_key
) {
    return crypto_sign_ed25519_verify_detached(
        signature, message, message_len, public_key
    ) == 0;
}

// ============================================================
// Phase 1 · Recipient tag (F-10 relay routing)
// ============================================================

std::string compute_recipient_tag(const unsigned char* public_key) {
    auto hash = sha256_hash(public_key, 32);

    // Convert to hex string for use as the relay routing tag
    std::string tag;
    tag.reserve(64);
    for (unsigned char byte : hash) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        tag.append(buf, 2);
    }

    return tag;
}

// ============================================================
// FullCryptoTest — validates all crypto operations
// ============================================================

void FullCryptoTest() {
    std::cout << "\n========================================\n";
    std::cout << "      shushhh Full Crypto Test Suite\n";
    std::cout << "========================================\n\n";

    bool all_passed = true;

    // --- Test 1: X25519 shared secret symmetry ---
    std::cout << "[*] Test 1: X25519 shared secret symmetry\n";
    {
        HybridKeyPair alice = generate_hybrid_keypair();
        HybridKeyPair bob   = generate_hybrid_keypair();

        auto shared1 = compute_x25519_shared_secret(alice.x25519_private, bob.x25519_public);
        auto shared2 = compute_x25519_shared_secret(bob.x25519_private, alice.x25519_public);

        if (shared1.empty() || shared2.empty()) {
            std::cerr << "    [-] FAIL: shared secret computation returned empty\n";
            all_passed = false;
        } else if (sodium_memcmp(shared1.data(), shared2.data(), 32) == 0) {
            std::cout << "    [+] PASS: shared1 == shared2\n";
        } else {
            std::cerr << "    [-] FAIL: shared1 != shared2\n";
            all_passed = false;
        }

        // Wipe test key material
        secure_wipe(alice.x25519_private, 32);
        secure_wipe(bob.x25519_private, 32);
        secure_wipe(alice.kyber_private.data(), alice.kyber_private.size());
        secure_wipe(bob.kyber_private.data(), bob.kyber_private.size());
        secure_wipe(shared1.data(), shared1.size());
        secure_wipe(shared2.data(), shared2.size());
    }

    // --- Test 2: encrypt / decrypt roundtrip ---
    std::cout << "[*] Test 2: ChaCha20-Poly1305 encrypt/decrypt roundtrip\n";
    {
        // Use a known key for this test (NOT for production — test only)
        unsigned char test_key[32];
        randombytes_buf(test_key, 32);

        std::string original = "The quick brown fox jumps over the lazy dog.";
        EncryptedMessage enc = encrypt_message(original, test_key);
        std::string decrypted = decrypt_message(enc, test_key);

        if (decrypted == original) {
            std::cout << "    [+] PASS: decrypted matches original\n";
        } else {
            std::cerr << "    [-] FAIL: decrypted does not match original\n";
            all_passed = false;
        }

        // Test tamper detection — flip one byte in ciphertext
        // Temporarily suppress stderr: decrypt_message will print an error,
        // but that error is the *expected* outcome of this test
        if (!enc.ciphertext.empty()) {
            enc.ciphertext[0] ^= 0x01;
            std::streambuf* orig_cerr = std::cerr.rdbuf(nullptr); // mute stderr
            std::string tampered = decrypt_message(enc, test_key);
            std::cerr.rdbuf(orig_cerr); // restore stderr
            if (tampered.empty()) {
                std::cout << "    [+] PASS: tampered ciphertext correctly rejected\n";
            } else {
                std::cerr << "    [-] FAIL: tampered ciphertext was not rejected\n";
                all_passed = false;
            }
        }

        secure_wipe(test_key, 32);
    }

    // --- Test 3: HKDF determinism ---
    std::cout << "[*] Test 3: HKDF determinism\n";
    {
        unsigned char ikm[32];
        randombytes_buf(ikm, 32);

        auto key1 = hkdf_derive(ikm, 32, nullptr, 0, "test_context", 32);
        auto key2 = hkdf_derive(ikm, 32, nullptr, 0, "test_context", 32);

        if (key1.size() == 32 && key2.size() == 32 &&
            sodium_memcmp(key1.data(), key2.data(), 32) == 0) {
            std::cout << "    [+] PASS: same inputs produce same output\n";
        } else {
            std::cerr << "    [-] FAIL: HKDF not deterministic\n";
            all_passed = false;
        }

        // Verify different info string produces different key
        auto key3 = hkdf_derive(ikm, 32, nullptr, 0, "different_context", 32);
        if (key3.size() == 32 && sodium_memcmp(key1.data(), key3.data(), 32) != 0) {
            std::cout << "    [+] PASS: different info string produces different key\n";
        } else {
            std::cerr << "    [-] FAIL: info string did not change output\n";
            all_passed = false;
        }

        secure_wipe(ikm, 32);
        secure_wipe(key1.data(), key1.size());
        secure_wipe(key2.data(), key2.size());
        secure_wipe(key3.data(), key3.size());
    }

    // --- Test 4: Session encrypt / decrypt roundtrip ---
    std::cout << "[*] Test 4: Hybrid Session (ML-KEM-768 + X25519) roundtrip + Ratchet\n";
    {
        HybridKeyPair alice = generate_hybrid_keypair();
        HybridKeyPair bob   = generate_hybrid_keypair();

        std::vector<unsigned char> kyber_ciphertext;
        MessageSession alice_session = create_session_initiator(alice, bob.x25519_public, bob.kyber_public, kyber_ciphertext);
        MessageSession bob_session   = create_session_responder(bob, alice.x25519_public, kyber_ciphertext);

        // Save original keys for ratchet verification
        auto alice_send_key_initial = alice_session.send_key;
        auto bob_recv_key_initial = bob_session.recv_key;

        std::string message = "hello from alice to bob via shushhh (quantum safe!)";
        EncryptedMessage enc = session_encrypt(alice_session, message);
        std::string dec = session_decrypt(bob_session, enc);

        if (dec == message) {
            std::cout << "    [+] PASS: hybrid session roundtrip successful\n";
        } else {
            std::cerr << "    [-] FAIL: hybrid session roundtrip failed\n";
            all_passed = false;
        }

        // Verify counters incremented
        if (alice_session.send_counter == 1 && bob_session.recv_counter == 1) {
            std::cout << "    [+] PASS: counters incremented correctly\n";
        } else {
            std::cerr << "    [-] FAIL: counter mismatch\n";
            all_passed = false;
        }

        // Verify ratchet worked (keys changed)
        if (alice_send_key_initial != alice_session.send_key && bob_recv_key_initial != bob_session.recv_key) {
            std::cout << "    [+] PASS: symmetric ratchet rotated keys successfully\n";
        } else {
            std::cerr << "    [-] FAIL: keys did not rotate after message\n";
            all_passed = false;
        }

        // Wipe session key material
        secure_wipe(alice.x25519_private, 32);
        secure_wipe(bob.x25519_private, 32);
        secure_wipe(alice.kyber_private.data(), alice.kyber_private.size());
        secure_wipe(bob.kyber_private.data(), bob.kyber_private.size());
        
        secure_wipe(alice_session.my_keypair.x25519_private, 32);
        secure_wipe(bob_session.my_keypair.x25519_private, 32);
        secure_wipe(alice_session.my_keypair.kyber_private.data(), alice_session.my_keypair.kyber_private.size());
        secure_wipe(bob_session.my_keypair.kyber_private.data(), bob_session.my_keypair.kyber_private.size());

        secure_wipe(kyber_ciphertext.data(), kyber_ciphertext.size());
        
        secure_wipe(alice_session.root_key.data(), alice_session.root_key.size());
        secure_wipe(alice_session.send_key.data(), alice_session.send_key.size());
        secure_wipe(alice_session.recv_key.data(), alice_session.recv_key.size());
        
        secure_wipe(bob_session.root_key.data(), bob_session.root_key.size());
        secure_wipe(bob_session.send_key.data(), bob_session.send_key.size());
        secure_wipe(bob_session.recv_key.data(), bob_session.recv_key.size());
    }

    // --- Test 5: JSON serialization roundtrip ---
    std::cout << "[*] Test 5: JSON serialization roundtrip\n";
    {
        unsigned char test_key[32];
        randombytes_buf(test_key, 32);

        std::string original = "json roundtrip test message";
        EncryptedMessage enc = encrypt_message(original, test_key);
        std::string json_str = encrypted_to_json(enc);
        EncryptedMessage restored = json_to_encrypted(json_str);

        // Verify nonce matches
        bool nonce_ok = (sodium_memcmp(enc.nonce, restored.nonce, 12) == 0);
        // Verify tag matches
        bool tag_ok = (sodium_memcmp(enc.tag, restored.tag, 16) == 0);
        // Verify ciphertext matches
        bool ct_ok = (enc.ciphertext.size() == restored.ciphertext.size()) &&
                     (enc.ciphertext.size() > 0) &&
                     (sodium_memcmp(enc.ciphertext.data(), restored.ciphertext.data(),
                                    enc.ciphertext.size()) == 0);

        if (nonce_ok && tag_ok && ct_ok) {
            std::cout << "    [+] PASS: JSON roundtrip preserves all fields\n";
        } else {
            std::cerr << "    [-] FAIL: JSON roundtrip corrupted data"
                      << " (nonce=" << nonce_ok << " tag=" << tag_ok << " ct=" << ct_ok << ")\n";
            all_passed = false;
        }

        // Verify the restored message actually decrypts
        std::string dec = decrypt_message(restored, test_key);
        if (dec == original) {
            std::cout << "    [+] PASS: restored message decrypts correctly\n";
        } else {
            std::cerr << "    [-] FAIL: restored message decryption failed\n";
            all_passed = false;
        }

        secure_wipe(test_key, 32);
    }

    // --- Test 6: SHA-256 consistency ---
    std::cout << "[*] Test 6: SHA-256 consistency\n";
    {
        auto hash1 = sha256_hash("test input");
        auto hash2 = sha256_hash("test input");
        auto hash3 = sha256_hash("different input");

        if (hash1.size() == 32 && sodium_memcmp(hash1.data(), hash2.data(), 32) == 0) {
            std::cout << "    [+] PASS: same input produces same hash\n";
        } else {
            std::cerr << "    [-] FAIL: SHA-256 not consistent\n";
            all_passed = false;
        }

        if (sodium_memcmp(hash1.data(), hash3.data(), 32) != 0) {
            std::cout << "    [+] PASS: different input produces different hash\n";
        } else {
            std::cerr << "    [-] FAIL: SHA-256 collision on trivial inputs\n";
            all_passed = false;
        }
    }

    // --- Test 7: Ed25519 sign/verify roundtrip ---
    std::cout << "[*] Test 7: Ed25519 sign/verify roundtrip\n";
    {
        SigningKeyPair kp = generate_ed25519_keypair();
        std::string message = "shushhh server auth response test";

        auto sig = ed25519_sign_detached(
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            kp.private_key
        );

        if (!sig.empty()) {
            bool valid = ed25519_verify_detached(
                sig.data(),
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size(),
                kp.public_key
            );
            if (valid) {
                std::cout << "    [+] PASS: valid signature verified\n";
            } else {
                std::cerr << "    [-] FAIL: valid signature rejected\n";
                all_passed = false;
            }

            // Tamper with message — should reject
            std::string tampered = "tampered server auth response test";
            bool invalid = ed25519_verify_detached(
                sig.data(),
                reinterpret_cast<const unsigned char*>(tampered.data()),
                tampered.size(),
                kp.public_key
            );
            if (!invalid) {
                std::cout << "    [+] PASS: tampered message correctly rejected\n";
            } else {
                std::cerr << "    [-] FAIL: tampered message was not rejected\n";
                all_passed = false;
            }
        } else {
            std::cerr << "    [-] FAIL: signing returned empty\n";
            all_passed = false;
        }

        secure_wipe(kp.private_key, 64);
    }

    // --- Test 8: Recipient tag computation ---
    std::cout << "[*] Test 8: Recipient tag computation\n";
    {
        unsigned char pub[32];
        randombytes_buf(pub, 32);

        std::string tag1 = compute_recipient_tag(pub);
        std::string tag2 = compute_recipient_tag(pub);

        if (tag1.size() == 64 && tag1 == tag2) {
            std::cout << "    [+] PASS: tag is 64 hex chars and deterministic\n";
        } else {
            std::cerr << "    [-] FAIL: tag computation inconsistent\n";
            all_passed = false;
        }
    }

    // --- Summary ---
    std::cout << "\n========================================\n";
    if (all_passed) {
        std::cout << "  [+] ALL TESTS PASSED\n";
    } else {
        std::cerr << "  [-] SOME TESTS FAILED — review output above\n";
    }
    std::cout << "========================================\n\n";
}
