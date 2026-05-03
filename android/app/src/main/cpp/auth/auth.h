#pragma once

#include <string>
#include <vector>
#include <memory>

struct HybridKeyPair; // Forward declaration

// ============================================================
// F-08 · LoginProvider interface
// ============================================================

// Abstract authentication contract.
// Any auth method (password, hardware token, biometric, challenge-response)
// subclasses this without touching the rest of the codebase.
class LoginProvider {
public:
    // Perform the full authentication flow (prompt user, contact server, verify).
    // Returns true if authentication succeeds.
    virtual bool authenticate(const std::string& server_url) = 0;

    // Return the credential hash (used as identity proof in transport).
    virtual std::vector<unsigned char> get_credential_hash() = 0;

    // Return the username (needed for session identity).
    virtual std::string get_username() const = 0;

    virtual ~LoginProvider() = default;
};

// ============================================================
// F-08 · PasswordLogin implementation
// ============================================================

// Phase 1 concrete implementation of LoginProvider.
// Computes SHA-256(password + username) client-side — raw password never leaves device.
class PasswordLogin : public LoginProvider {
public:
    bool authenticate(const std::string& server_url) override;
    std::vector<unsigned char> get_credential_hash() override;
    std::string get_username() const override;

    // Set credentials programmatically (used by UI)
    void set_credentials(const std::string& u, const std::string& p);

    // Register a new account on the server.
    // Returns true on success.
    bool register_account(const std::string& server_url);

    // Upload public keys to the Key Server. Requires successful authentication.
    bool upload_public_keys(const std::string& server_url, const std::string& public_keys_json);

    // Fetch public keys for a specific username from the Key Server.
    static std::string fetch_public_keys(const std::string& server_url, const std::string& target_username);

    // Persist identity to disk (encrypted with credential_hash_).
    bool save_identity(const HybridKeyPair& keypair, const std::string& filepath);

    // Load identity from disk (decrypted with credential_hash_).
    bool load_identity(HybridKeyPair& keypair, const std::string& filepath);

private:
    std::string username_;
    std::vector<unsigned char> credential_hash_;
    bool authenticated_ = false;
    std::string auth_token_;
    std::string auth_signature_;

    // Prompt for username and password from stdin.
    // Password input is masked (no echo).
    void prompt_credentials();
};

// ============================================================
// Tor HTTP helpers (used by auth and messaging)
// ============================================================

// POST JSON payload to a URL through Tor SOCKS5 proxy.
// Returns the response body, or empty string on failure.
std::string tor_post(const std::string& url, const std::string& json_payload);

// GET a URL through Tor SOCKS5 proxy.
// Returns the response body, or empty string on failure.
std::string tor_get(const std::string& url);

// ============================================================
// Server public key for Ed25519 verification (F-09)
// ============================================================

// The server's Ed25519 public key — hardcoded in binary.
// Generated once via relay/setup_keys.py, then pasted here.
// This is the MITM-proof trust anchor.
// Default: all zeros (placeholder — replace after running setup_keys.py)
extern const unsigned char SERVER_ED25519_PUBKEY[32];
