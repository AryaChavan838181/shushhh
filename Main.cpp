#include "crypto/crypto.h"

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>

#include <curl/curl.h>

// ============================================================
// Utility: hex encode/decode for public key display and input
// ============================================================

static std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

static bool from_hex(const std::string& hex, unsigned char* out, size_t out_len) {
    if (hex.size() != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte;
        std::istringstream iss(hex.substr(i * 2, 2));
        iss >> std::hex >> byte;
        if (iss.fail()) return false;
        out[i] = static_cast<unsigned char>(byte);
    }
    return true;
}

// ============================================================
// libcurl write callback — captures response body
// ============================================================

static size_t shushhh_write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), total);
    return total;
}

// ============================================================
// Send encrypted JSON payload through Tor
// ============================================================

static bool send_via_tor(const std::string& json_payload, const std::string& onion_url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[-] curl_easy_init() failed\n";
        return false;
    }

    std::string response;
    std::string url = onion_url + "/drop";

    // All traffic MUST route through Tor — socks5h:// means DNS also goes through Tor
    curl_easy_setopt(curl, CURLOPT_PROXY, "socks5h://127.0.0.1:9050");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, shushhh_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    // Set content type header
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "[-] Tor send failed: " << curl_easy_strerror(res) << "\n";
        std::cerr << "    Make sure Tor is running on 127.0.0.1:9050\n";
        return false;
    }

    std::cout << "[+] Message sent via Tor successfully\n";
    if (!response.empty()) {
        std::cout << "    Server response: " << response << "\n";
    }
    return true;
}

// ============================================================
// Interactive Menu
// ============================================================

static void print_menu() {
    std::cout << "\n";
    std::cout << "  ┌──────────────────────────────────┐\n";
    std::cout << "  │           s h u s h h h          │\n";
    std::cout << "  │     paranoid pendrive messenger   │\n";
    std::cout << "  ├──────────────────────────────────┤\n";
    std::cout << "  │  1. Generate keypair              │\n";
    std::cout << "  │  2. Create session                │\n";
    std::cout << "  │  3. Send test message via Tor     │\n";
    std::cout << "  │  4. Run full crypto test          │\n";
    std::cout << "  │  5. Exit                          │\n";
    std::cout << "  └──────────────────────────────────┘\n";
    std::cout << "  > ";
}

int main() {
    // F-01: libsodium must initialize before anything else
    if (!crypto_init()) {
        std::cerr << "[-] Fatal: cannot continue without libsodium\n";
        return 1;
    }

    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Session state — persists across menu iterations
    KeyPair my_keypair;
    bool has_keypair = false;

    MessageSession session;
    bool has_session = false;

    std::string onion_url = "http://your_onion_address.onion"; // placeholder — set at runtime

    int choice = 0;

    while (true) {
        print_menu();
        std::cin >> choice;
        std::cin.ignore(); // flush newline

        switch (choice) {

        // ── Option 1: Generate keypair ──
        case 1: {
            my_keypair = generate_x25519_keypair();
            has_keypair = true;
            std::cout << "[+] Keypair generated\n";
            std::cout << "    Public key: " << to_hex(my_keypair.public_key, 32) << "\n";
            // Private key is NEVER displayed — security invariant
            break;
        }

        // ── Option 2: Create session ──
        case 2: {
            if (!has_keypair) {
                std::cerr << "[-] Generate a keypair first (option 1)\n";
                break;
            }

            std::cout << "Enter peer's public key (64 hex chars): ";
            std::string peer_hex;
            std::getline(std::cin, peer_hex);

            unsigned char their_pub[32];
            if (!from_hex(peer_hex, their_pub, 32)) {
                std::cerr << "[-] Invalid hex — must be exactly 64 hex characters\n";
                break;
            }

            session = create_session(my_keypair, their_pub);
            has_session = true;

            // Wipe the temporary public key buffer
            secure_wipe(their_pub, 32);
            break;
        }

        // ── Option 3: Send test message via Tor ──
        case 3: {
            if (!has_session) {
                std::cerr << "[-] Create a session first (option 2)\n";
                break;
            }

            std::cout << "Enter .onion URL (or press Enter for default): ";
            std::string url_input;
            std::getline(std::cin, url_input);
            if (!url_input.empty()) {
                onion_url = url_input;
            }

            std::cout << "Enter message: ";
            std::string message;
            std::getline(std::cin, message);

            EncryptedMessage enc = session_encrypt(session, message);
            std::string json_payload = encrypted_to_json(enc);

            std::cout << "[*] Encrypted JSON payload (" << json_payload.size() << " bytes)\n";

            send_via_tor(json_payload, onion_url);
            break;
        }

        // ── Option 4: Full crypto test ──
        case 4: {
            FullCryptoTest();
            break;
        }

        // ── Option 5: Exit ──
        case 5: {
            std::cout << "[+] Wiping session state and exiting\n";

            // Wipe all key material before exit
            if (has_keypair) {
                secure_wipe(my_keypair.private_key, 32);
                secure_wipe(my_keypair.public_key, 32);
            }
            if (has_session) {
                secure_wipe(session.my_keypair.private_key, 32);
                secure_wipe(session.my_keypair.public_key, 32);
                secure_wipe(session.their_public_key, 32);
                if (!session.root_key.empty())
                    secure_wipe(session.root_key.data(), session.root_key.size());
                if (!session.send_key.empty())
                    secure_wipe(session.send_key.data(), session.send_key.size());
                if (!session.recv_key.empty())
                    secure_wipe(session.recv_key.data(), session.recv_key.size());
            }

            curl_global_cleanup();
            std::cout << "[+] Clean exit — no key material in memory\n";
            return 0;
        }

        default:
            std::cerr << "[-] Invalid option\n";
            break;
        }
    }

    curl_global_cleanup();
    return 0;
}
