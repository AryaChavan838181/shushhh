#include "crypto/crypto.h"
#include "auth/auth.h"
#include "watchdog/watchdog.h"

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <memory>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

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
// Interactive Menu
// ============================================================

static void print_menu() {
    std::cout << "\n";
    std::cout << "  +------------------------------------+\n";
    std::cout << "  |           s h u s h h h            |\n";
    std::cout << "  |     paranoid pendrive messenger     |\n";
    std::cout << "  +------------------------------------+\n";
    std::cout << "  |  1. Generate keypair                |\n";
    std::cout << "  |  2. Create session                  |\n";
    std::cout << "  |  3. Send message                    |\n";
    std::cout << "  |  4. Fetch messages                  |\n";
    std::cout << "  |  5. Run full crypto test            |\n";
    std::cout << "  |  6. Exit                            |\n";
    std::cout << "  +------------------------------------+\n";
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

    // ================================================================
    // F-11: Launch watchdog — monitors USB and wipes on disconnect
    // ================================================================
    char usb_drive = detect_usb_drive();
    if (usb_drive != '\0') {
        launch_watchdog(usb_drive);
    }

    // ================================================================
    // F-08: Login / Registration flow
    // ================================================================
    std::string server_url = "http://127.0.0.1:5000"; // Default — localhost for testing

    std::cout << "\n";
    std::cout << "  +------------------------------------+\n";
    std::cout << "  |         Authentication             |\n";
    std::cout << "  +------------------------------------+\n";
    std::cout << "  |  1. Login                          |\n";
    std::cout << "  |  2. Register new account           |\n";
    std::cout << "  |  3. Skip (offline mode)            |\n";
    std::cout << "  +------------------------------------+\n";

    std::cout << "\n  Server URL (Enter for default " << server_url << "): ";
    std::string url_input;
    std::getline(std::cin, url_input);
    if (!url_input.empty()) {
        server_url = url_input;
    }

    std::cout << "  > ";
    int auth_choice = 0;
    std::cin >> auth_choice;
    std::cin.ignore();

    auto login = std::make_unique<PasswordLogin>();
    bool authenticated = false;

    switch (auth_choice) {
    case 1: {
        authenticated = login->authenticate(server_url);
        if (!authenticated) {
            std::cerr << "[-] Authentication failed — continuing in offline mode\n";
        }
        break;
    }
    case 2: {
        if (login->register_account(server_url)) {
            std::cout << "[+] Now logging in with the new account...\n";
            authenticated = login->authenticate(server_url);
        }
        break;
    }
    case 3:
        std::cout << "[*] Offline mode — some features require server connection\n";
        break;
    default:
        std::cout << "[*] Skipping authentication\n";
        break;
    }

    // ================================================================
    // Session state — persists across menu iterations
    // ================================================================
    HybridKeyPair my_keypair;
    bool has_keypair = false;

    MessageSession session;
    bool has_session = false;

    int choice = 0;

    while (true) {
        print_menu();
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {

        // -- Option 1: Generate keypair --
        case 1: {
            my_keypair = generate_hybrid_keypair();
            has_keypair = true;
            std::cout << "[+] Hybrid Keypair (X25519 + ML-KEM-768) generated\n";
            std::cout << "    [X25519]: " << to_hex(my_keypair.x25519_public, 32) << "\n";
            std::cout << "    [Kyber] : " << to_hex(my_keypair.kyber_public.data(), 16) << "... (" << my_keypair.kyber_public.size() << " bytes total)\n";
            std::cout << "\n--- SHARE THIS ENTIRE STRING WITH YOUR PEER ---\n";
            std::cout << to_hex(my_keypair.x25519_public, 32) 
                      << to_hex(my_keypair.kyber_public.data(), my_keypair.kyber_public.size()) << "\n";
            std::cout << "-----------------------------------------------\n";
            std::cout << "    Recipient tag: " << compute_recipient_tag(my_keypair.x25519_public) << "\n";
            // Private key is NEVER displayed — security invariant
            break;
        }

        // -- Option 2: Create session --
        case 2: {
            if (!has_keypair) {
                std::cerr << "[-] Generate a keypair first (option 1)\n";
                break;
            }

            std::cout << "[?] Are you the (1) Initiator or (2) Responder? ";
            int role;
            std::cin >> role;
            std::cin.ignore();

            if (role == 1) {
                // Initiator Flow
                std::cout << "Enter peer's full hybrid public key (" << (32 + my_keypair.kyber_public.size()) * 2 << " hex chars):\n> ";
                std::string peer_hex;
                std::getline(std::cin, peer_hex);

                size_t expected_len = (32 + my_keypair.kyber_public.size()) * 2;
                if (peer_hex.size() != expected_len) {
                    std::cerr << "[-] Invalid hex length — expected " << expected_len << " chars\n";
                    break;
                }

                unsigned char their_x25519[32];
                if (!from_hex(peer_hex.substr(0, 64), their_x25519, 32)) {
                    std::cerr << "[-] Invalid hex in X25519 part\n";
                    break;
                }

                std::vector<unsigned char> their_kyber(my_keypair.kyber_public.size());
                if (!from_hex(peer_hex.substr(64), their_kyber.data(), their_kyber.size())) {
                    std::cerr << "[-] Invalid hex in Kyber part\n";
                    break;
                }

                std::vector<unsigned char> kyber_ciphertext;
                session = create_session_initiator(my_keypair, their_x25519, their_kyber, kyber_ciphertext);
                has_session = true;

                std::cout << "\n--- SEND THIS ML-KEM-768 CIPHERTEXT TO THE RESPONDER ---\n";
                std::cout << to_hex(kyber_ciphertext.data(), kyber_ciphertext.size()) << "\n";
                std::cout << "----------------------------------------------------------\n";

                secure_wipe(their_x25519, 32);
                secure_wipe(their_kyber.data(), their_kyber.size());

            } else if (role == 2) {
                // Responder Flow
                std::cout << "Enter initiator's short X25519 public key (64 hex chars):\n> ";
                std::string init_x25519_hex;
                std::getline(std::cin, init_x25519_hex);

                unsigned char their_x25519[32];
                if (init_x25519_hex.size() != 64 || !from_hex(init_x25519_hex, their_x25519, 32)) {
                    std::cerr << "[-] Invalid X25519 hex\n";
                    break;
                }

                std::cout << "Enter ML-KEM-768 ciphertext from initiator (" << 1088 * 2 << " hex chars):\n> ";
                std::string ct_hex;
                std::getline(std::cin, ct_hex);

                std::vector<unsigned char> kyber_ct(1088); // ML-KEM-768 ciphertext is 1088 bytes
                if (ct_hex.size() != 1088 * 2 || !from_hex(ct_hex, kyber_ct.data(), kyber_ct.size())) {
                    std::cerr << "[-] Invalid ciphertext hex\n";
                    break;
                }

                session = create_session_responder(my_keypair, their_x25519, kyber_ct);
                has_session = true;

                secure_wipe(their_x25519, 32);
                secure_wipe(kyber_ct.data(), kyber_ct.size());
            } else {
                std::cerr << "[-] Invalid role\n";
            }
            break;
        }

        // -- Option 3: Send message --
        case 3: {
            if (!has_session) {
                std::cerr << "[-] Create a session first (option 2)\n";
                break;
            }

            std::cout << "Enter recipient's X25519 public key for routing (64 hex, or Enter to skip): ";
            std::string recip_hex;
            std::getline(std::cin, recip_hex);

            std::cout << "Enter message: ";
            std::string message;
            std::getline(std::cin, message);

            EncryptedMessage enc = session_encrypt(session, message);
            std::string json_payload = encrypted_to_json(enc);

            // Build the drop payload with routing tag
            std::string drop_payload;
            if (!recip_hex.empty()) {
                unsigned char recip_pub[32];
                if (from_hex(recip_hex, recip_pub, 32)) {
                    std::string tag = compute_recipient_tag(recip_pub);
                    nlohmann::json drop;
                    drop["tag"] = tag;
                    drop["blob"] = json_payload;
                    drop_payload = drop.dump();
                    secure_wipe(recip_pub, 32);
                } else {
                    std::cerr << "[-] Invalid recipient hex — sending raw blob\n";
                    drop_payload = json_payload;
                }
            } else {
                drop_payload = json_payload;
            }

            std::cout << "[*] Encrypted payload (" << drop_payload.size() << " bytes)\n";

            std::string url = server_url + "/drop";
            std::string resp = tor_post(url, drop_payload);
            if (!resp.empty()) {
                std::cout << "[+] Message sent\n";
                std::cout << "    Server: " << resp << "\n";
            }
            break;
        }

        // -- Option 4: Fetch messages --
        case 4: {
            if (!has_keypair) {
                std::cerr << "[-] Generate a keypair first (option 1)\n";
                break;
            }

            std::string my_tag = compute_recipient_tag(my_keypair.x25519_public);
            std::string url = server_url + "/fetch?tag=" + my_tag;

            std::cout << "[*] Fetching messages for tag: " << my_tag.substr(0, 16) << "...\n";

            std::string resp = tor_get(url);
            if (resp.empty()) {
                std::cerr << "[-] No response from server\n";
                break;
            }

            try {
                auto j = nlohmann::json::parse(resp);
                if (j["status"] != "ok") {
                    std::cerr << "[-] Server error: " << j.value("message", "unknown") << "\n";
                    break;
                }

                auto& messages = j["messages"];
                if (messages.empty()) {
                    std::cout << "[*] No pending messages\n";
                    break;
                }

                std::cout << "[+] " << messages.size() << " message(s) received:\n\n";

                for (auto& msg : messages) {
                    std::string event_id = msg["event_id"];
                    std::string blob = msg["blob"];

                    // Try to decrypt if we have a session
                    if (has_session) {
                        EncryptedMessage enc_msg = json_to_encrypted(blob);
                        std::string plaintext = session_decrypt(session, enc_msg);

                        if (!plaintext.empty()) {
                            std::cout << "    [" << event_id.substr(0, 8) << "] "
                                      << plaintext << "\n";
                        } else {
                            std::cout << "    [" << event_id.substr(0, 8)
                                      << "] (could not decrypt — wrong session key?)\n";
                        }
                    } else {
                        std::cout << "    [" << event_id.substr(0, 8)
                                  << "] (encrypted — create session to decrypt)\n";
                    }

                    // ACK the message — hard-delete from server
                    nlohmann::json ack_payload;
                    ack_payload["event_id"] = event_id;
                    std::string ack_url = server_url + "/ack";
                    tor_post(ack_url, ack_payload.dump());
                }
                std::cout << "\n[+] All messages ACK'd — deleted from server\n";

            } catch (const nlohmann::json::exception& e) {
                std::cerr << "[-] Failed to parse fetch response: " << e.what() << "\n";
            }
            break;
        }

        // -- Option 5: Full crypto test --
        case 5: {
            FullCryptoTest();
            break;
        }

        // -- Option 6: Exit --
        case 6: {
            std::cout << "[+] Wiping session state and exiting\n";

            // Wipe all key material before exit
            if (has_keypair) {
                secure_wipe(my_keypair.x25519_private, 32);
                secure_wipe(my_keypair.x25519_public, 32);
                secure_wipe(my_keypair.kyber_private.data(), my_keypair.kyber_private.size());
                secure_wipe(my_keypair.kyber_public.data(), my_keypair.kyber_public.size());
            }
            if (has_session) {
                secure_wipe(session.my_keypair.x25519_private, 32);
                secure_wipe(session.my_keypair.x25519_public, 32);
                secure_wipe(session.my_keypair.kyber_private.data(), session.my_keypair.kyber_private.size());
                secure_wipe(session.my_keypair.kyber_public.data(), session.my_keypair.kyber_public.size());
                secure_wipe(session.their_x25519_public_key, 32);
                secure_wipe(session.their_kyber_public_key.data(), session.their_kyber_public_key.size());
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
