#include "crypto/crypto.h"
#include "auth/auth.h"
#include "watchdog/watchdog.h"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <filesystem>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

// FTXUI
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/event.hpp>

using namespace ftxui;

// ============================================================
// Global Log Buffer — captures ALL stdout/stderr
// ============================================================
std::ostringstream g_log_stream;
std::mutex g_log_mutex;

void log_msg(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_stream << msg;
}

std::string get_logs() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    return g_log_stream.str();
}

// ============================================================
// Globals & State
// ============================================================
std::string keyserver_url = "http://127.0.0.1:5000";
std::string msgserver_url = "http://127.0.0.1:5001";

HybridKeyPair my_keypair;
bool has_keypair = false;
MessageSession current_session;
bool has_session = false;
std::string my_username;
std::string peer_username;

std::vector<std::string> chat_history;
std::mutex chat_mutex;
std::atomic<bool> keep_running{true};

// ============================================================
// Tor Utilities
// ============================================================
static bool is_tor_running() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return false; }
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9050);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bool running = (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == 0);
    closesocket(sock);
    WSACleanup();
    return running;
}

static bool launch_tor_silently() {
    std::string tor_path = "tor.exe";
    if (!std::filesystem::exists(tor_path) && std::filesystem::exists("tor/tor.exe")) tor_path = "tor/tor.exe";
    if (!std::filesystem::exists(tor_path)) return false;
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(tor_path.c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return false;
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return true;
}

// ============================================================
// Helpers
// ============================================================
static std::string to_base64(const unsigned char* data, size_t len) {
    size_t b64_maxlen = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::string b64(b64_maxlen, '\0');
    sodium_bin2base64(&b64[0], b64_maxlen, data, len, sodium_base64_VARIANT_ORIGINAL);
    b64.resize(strlen(b64.c_str()));
    return b64;
}

static std::string to_hex(const unsigned char* data, size_t len) {
    std::string hex;
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex += buf;
    }
    return hex;
}

static bool from_hex(const std::string& hex, unsigned char* out, size_t out_len) {
    if (hex.size() != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte;
        sscanf(hex.substr(i*2, 2).c_str(), "%02x", &byte);
        out[i] = static_cast<unsigned char>(byte);
    }
    return true;
}

// ============================================================
// Background Fetcher Thread
// ============================================================
void fetcher_thread(ScreenInteractive* screen) {
    while (keep_running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        if (my_username.empty()) continue; // Not logged in yet
        
        std::string my_tag = to_hex(sha256_hash(my_username).data(), 32);
        std::string url = msgserver_url + "/fetch?tag=" + my_tag;
        std::string resp = tor_get(url);
        
        if (resp.empty()) continue;
        
        try {
            auto j = nlohmann::json::parse(resp);
            if (j["status"] != "ok") continue;
            auto& messages = j["messages"];
            
            for (auto& msg : messages) {
                std::string event_id = msg["event_id"];
                std::string blob = msg["blob"];
                
                // 1. Is it an Ephemeral Handshake?
                try {
                    auto j_blob = nlohmann::json::parse(blob);
                    if (j_blob.contains("type") && j_blob["type"] == "handshake") {
                        HandshakePayload hs = json_to_handshake(j_blob.dump());
                        std::string inner_payload = process_ephemeral_handshake(my_keypair.x25519_private, hs);
                        
                        if (!inner_payload.empty()) {
                            auto inner = nlohmann::json::parse(inner_payload);
                            std::string sender = inner["sender"];
                            std::string kyber_ct_b64 = inner["kyber_ciphertext"];
                            
                            // Auto-fetch sender keys
                            std::string pub_keys_json = PasswordLogin::fetch_public_keys(keyserver_url, sender);
                            if (!pub_keys_json.empty()) {
                                auto pj = nlohmann::json::parse(pub_keys_json);
                                unsigned char their_x25519[32];
                                from_hex(pj["x25519"], their_x25519, 32);
                                
                                std::vector<unsigned char> kyber_ct(1088);
                                size_t b64_len = 0;
                                sodium_base642bin(kyber_ct.data(), kyber_ct.size(), kyber_ct_b64.c_str(), kyber_ct_b64.size(), nullptr, &b64_len, nullptr, sodium_base64_VARIANT_ORIGINAL);
                                
                                current_session = create_session_responder(my_keypair, their_x25519, kyber_ct);
                                has_session = true;
                                peer_username = sender;
                                
                                std::lock_guard<std::mutex> lock(chat_mutex);
                                chat_history.push_back("[SYSTEM] [+] Secure 0-RTT session established with " + sender);
                            }
                            // ACK Handshake
                            nlohmann::json ack; ack["event_id"] = event_id;
                            tor_post(msgserver_url + "/ack", ack.dump());
                        }
                        continue;
                    }
                } catch(...) {}

                // 2. Standard Message
                if (has_session) {
                    EncryptedMessage enc_msg = json_to_encrypted(blob);
                    std::string plaintext = session_decrypt(current_session, enc_msg);
                    if (!plaintext.empty()) {
                        std::lock_guard<std::mutex> lock(chat_mutex);
                        chat_history.push_back(peer_username + "> " + plaintext);
                        
                        nlohmann::json ack; ack["event_id"] = event_id;
                        tor_post(msgserver_url + "/ack", ack.dump());
                    }
                }
            }
            if (!messages.empty() && screen) {
                screen->PostEvent(Event::Custom); // Force UI redraw
            }
        } catch (...) {}
    }
}

// ============================================================
// Styled Button Helper
// ============================================================
Component StyledButton(const std::string& label, std::function<void()> on_click) {
    auto opt = ButtonOption::Ascii();
    opt.transform = [](const EntryState& s) {
        auto el = text(s.label) | center | border;
        if (s.focused) {
            el = el | color(Color::Black) | bgcolor(Color::Blue) | bold;
        } else {
            el = el | color(Color::White) | bgcolor(Color::Black);
        }
        return el;
    };
    return Button(label, std::move(on_click), opt);
}

// ============================================================
// Main UI Application
// ============================================================
int main() {
    // --- Redirect stderr to log buffer (stdout is needed by FTXUI) ---
    std::streambuf* orig_cerr = std::cerr.rdbuf(g_log_stream.rdbuf());

    if (!crypto_init()) {
        std::cerr.rdbuf(orig_cerr);
        return 1;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Auto-Tor
    if (!is_tor_running()) launch_tor_silently();
    
    char usb_drive = detect_usb_drive();
    if (usb_drive != '\0') launch_watchdog(usb_drive);
    
    auto screen = ScreenInteractive::Fullscreen();
    
    // --- Styles ---
    auto style_normal = color(Color::White) | bgcolor(Color::Black);
    auto style_focus  = color(Color::Black) | bgcolor(Color::Blue);
    auto input_opt    = InputOption();
    input_opt.transform = [&](InputState state) {
        auto el = state.element | size(WIDTH, GREATER_THAN, 30);
        if (state.focused) {
            return el | style_focus | bold;
        } else if (state.is_placeholder) {
            return el | color(Color::GrayDark) | bgcolor(Color::Black);
        } else {
            return el | style_normal;
        }
    };
    
    auto pass_opt = input_opt;
    pass_opt.password = true;

    // --- State ---
    enum AppState { INIT, CONFIG, LOGIN, REGISTER, SETUP, CHAT };
    AppState current_state = INIT;
    std::string ui_error = "";
    bool show_debug = false;
    
    // --- Config Components ---
    std::string input_ks = keyserver_url;
    std::string input_ms = msgserver_url;
    Component comp_ks = Input(&input_ks, "http://127.0.0.1:5000", input_opt);
    Component comp_ms = Input(&input_ms, "http://127.0.0.1:5001", input_opt);
    auto btn_save_cfg = StyledButton("  SAVE & BACK  ", [&] {
        if(!input_ks.empty()) keyserver_url = input_ks;
        if(!input_ms.empty()) msgserver_url = input_ms;
        current_state = INIT;
    });
    auto config_container = Container::Vertical({comp_ks, comp_ms, btn_save_cfg});

    // --- Init Components ---
    auto btn_to_login = StyledButton("     LOGIN      ", [&] { current_state = LOGIN; ui_error = ""; });
    auto btn_to_reg   = StyledButton("   REGISTER     ", [&] { current_state = REGISTER; ui_error = ""; });
    auto btn_to_cfg   = StyledButton("  SET CONFIG    ", [&] { current_state = CONFIG; });
    auto btn_exit     = StyledButton("     EXIT       ", [&] { screen.Exit(); });
    auto init_container = Container::Vertical({btn_to_login, btn_to_reg, btn_to_cfg, btn_exit});

    // --- Login/Register Components ---
    std::string input_user, input_pass;
    Component comp_user = Input(&input_user, "username", input_opt);
    Component comp_pass = Input(&input_pass, "password", pass_opt);
    
    auto auth_action = [&](bool is_register) {
        PasswordLogin login;
        login.set_credentials(input_user, input_pass);
        bool success = false;
        
        if (is_register) {
            success = login.register_account(keyserver_url);
            if (!success) { ui_error = "[-] Registration failed"; return; }
            // After registering, also authenticate to get auth token for key upload
            success = login.authenticate(keyserver_url);
            if (!success) { ui_error = "[-] Registered but login failed"; return; }
        } else {
            success = login.authenticate(keyserver_url);
            if (!success) { ui_error = "[-] Authentication failed"; return; }
        }

        // If we reach here, authentication succeeded
        my_username = input_user;
        if (login.load_identity(my_keypair, "identity.dat")) {
            has_keypair = true;
        } else {
            my_keypair = generate_hybrid_keypair();
            login.save_identity(my_keypair, "identity.dat");
            has_keypair = true;
            nlohmann::json pub_keys;
            pub_keys["x25519"] = to_hex(my_keypair.x25519_public, 32);
            pub_keys["kyber"] = to_hex(my_keypair.kyber_public.data(), my_keypair.kyber_public.size());
            login.upload_public_keys(keyserver_url, pub_keys.dump());
        }
        current_state = SETUP;
        ui_error = "";
    };

    auto btn_login = StyledButton("     LOGIN      ", [&] { auth_action(false); });
    auto login_container = Container::Vertical({comp_user, comp_pass, btn_login});
    
    auto btn_register = StyledButton("   REGISTER     ", [&] { auth_action(true); });
    auto register_container = Container::Vertical({comp_user, comp_pass, btn_register});
    
    // --- Setup Components ---
    std::string input_peer;
    Component comp_peer = Input(&input_peer, "target_username", input_opt);
    auto btn_connect = StyledButton("    CONNECT     ", [&]() {
        std::string pub_keys_json = PasswordLogin::fetch_public_keys(keyserver_url, input_peer);
        if (pub_keys_json.empty()) {
            ui_error = "[-] Peer not found";
            return;
        }
        try {
            auto j = nlohmann::json::parse(pub_keys_json);
            unsigned char their_x[32]; from_hex(j["x25519"], their_x, 32);
            std::vector<unsigned char> their_k(1184); from_hex(j["kyber"], their_k.data(), 1184);
            
            std::vector<unsigned char> kyber_ct;
            current_session = create_session_initiator(my_keypair, their_x, their_k, kyber_ct);
            has_session = true;
            peer_username = input_peer;
            
            // Build 0-RTT Handshake
            nlohmann::json inner;
            inner["sender"] = my_username;
            size_t b64_maxlen = sodium_base64_ENCODED_LEN(kyber_ct.size(), sodium_base64_VARIANT_ORIGINAL);
            std::string ct_b64(b64_maxlen, '\0');
            sodium_bin2base64(&ct_b64[0], b64_maxlen, kyber_ct.data(), kyber_ct.size(), sodium_base64_VARIANT_ORIGINAL);
            inner["kyber_ciphertext"] = ct_b64.c_str();
            
            HandshakePayload hs = generate_ephemeral_handshake(their_x, inner.dump());
            nlohmann::json outer;
            outer["type"] = "handshake";
            outer["ephemeral_public"] = to_base64(hs.ephemeral_public, 32);
            outer["blob"] = nlohmann::json::parse(encrypted_to_json(hs.encrypted_blob));
            
            nlohmann::json drop;
            drop["tag"] = to_hex(sha256_hash(peer_username).data(), 32);
            drop["blob"] = outer.dump();
            tor_post(msgserver_url + "/drop", drop.dump());
            
            current_state = CHAT;
            std::lock_guard<std::mutex> lock(chat_mutex);
            chat_history.push_back("[SYSTEM] [+] Handshake sent to " + peer_username);
        } catch(...) { ui_error = "[-] Parse error"; }
    });
    auto btn_wait = StyledButton(" WAIT FOR MSGS  ", [&]() { current_state = CHAT; });
    auto setup_container = Container::Vertical({comp_peer, btn_connect, btn_wait});
    
    // --- Chat Components ---
    std::string input_msg;
    Component comp_msg = Input(&input_msg, "Type message...", input_opt);
    auto btn_send = StyledButton("  SEND  ", [&]() {
        if (!has_session || input_msg.empty()) return;
        EncryptedMessage enc = session_encrypt(current_session, input_msg);
        nlohmann::json drop;
        drop["tag"] = to_hex(sha256_hash(peer_username).data(), 32);
        drop["blob"] = encrypted_to_json(enc);
        tor_post(msgserver_url + "/drop", drop.dump());
        
        std::lock_guard<std::mutex> lock(chat_mutex);
        chat_history.push_back(my_username + "> " + input_msg);
        input_msg = "";
    });
    auto chat_container = Container::Horizontal({comp_msg, btn_send});
    
    // --- Renderer ---
    auto main_container = Container::Tab(
        {init_container, config_container, login_container, register_container, setup_container, chat_container},
        (int*)&current_state
    );

    auto renderer = Renderer(main_container, [&] {
        Element page;
        std::string hint = " [ESC] Quit  [Alt+X] Debug ";

        if (current_state == INIT) {
            page = vbox({
                text("") | size(HEIGHT, EQUAL, 1),
                text("  ███████╗██╗  ██╗██╗   ██╗███████╗██╗  ██╗██╗  ██╗██╗  ██╗") | color(Color::Blue) | bold,
                text("  ██╔════╝██║  ██║██║   ██║██╔════╝██║  ██║██║  ██║██║  ██║") | color(Color::Blue) | bold,
                text("  ███████╗███████║██║   ██║███████╗███████║███████║███████║") | color(Color::Blue) | bold,
                text("  ╚════██║██╔══██║██║   ██║╚════██║██╔══██║██╔══██║██╔══██║") | color(Color::Blue) | bold,
                text("  ███████║██║  ██║╚██████╔╝███████║██║  ██║██║  ██║██║  ██║") | color(Color::Blue) | bold,
                text("  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝") | color(Color::Blue) | bold,
                text("") | size(HEIGHT, EQUAL, 1),
                text("  Quantum-Safe Encrypted Messenger") | color(Color::GrayLight) | center,
                text("") | size(HEIGHT, EQUAL, 2),
                btn_to_login->Render() | center,
                text("") | size(HEIGHT, EQUAL, 1),
                btn_to_reg->Render() | center,
                text("") | size(HEIGHT, EQUAL, 1),
                btn_to_cfg->Render() | center,
                text("") | size(HEIGHT, EQUAL, 2),
                separator() | color(Color::GrayDark),
                text("") | size(HEIGHT, EQUAL, 1),
                btn_exit->Render() | center,
            }) | center | style_normal;
        } else if (current_state == CONFIG) {
            page = window(text(" [ CONFIGURATION ] ") | bold | color(Color::Blue), vbox({
                text("") | size(HEIGHT, EQUAL, 1),
                text("  Key Server URL:") | color(Color::GrayLight),
                comp_ks->Render() | size(WIDTH, GREATER_THAN, 40),
                text("") | size(HEIGHT, EQUAL, 1),
                text("  Message Server URL:") | color(Color::GrayLight),
                comp_ms->Render() | size(WIDTH, GREATER_THAN, 40),
                text("") | size(HEIGHT, EQUAL, 2),
                btn_save_cfg->Render() | center,
                text("") | size(HEIGHT, EQUAL, 1),
            })) | center | size(WIDTH, GREATER_THAN, 50) | style_normal;
        } else if (current_state == LOGIN || current_state == REGISTER) {
            std::string title = current_state == LOGIN ? " [ LOGIN ] " : " [ REGISTER ] ";
            auto btn = current_state == LOGIN ? btn_login->Render() : btn_register->Render();
            page = window(text(title) | bold | color(Color::Blue), vbox({
                text("") | size(HEIGHT, EQUAL, 1),
                text("  Username:") | color(Color::GrayLight),
                comp_user->Render() | size(WIDTH, GREATER_THAN, 35),
                text("") | size(HEIGHT, EQUAL, 1),
                text("  Password:") | color(Color::GrayLight),
                comp_pass->Render() | size(WIDTH, GREATER_THAN, 35),
                text("") | size(HEIGHT, EQUAL, 2),
                btn | center,
                text("") | size(HEIGHT, EQUAL, 1),
                (ui_error.empty() ? text("") : text("  " + ui_error) | color(Color::Red) | bold),
                text("") | size(HEIGHT, EQUAL, 1),
            })) | center | size(WIDTH, GREATER_THAN, 45) | style_normal;
        } else if (current_state == SETUP) {
            page = window(text(" [ SECURE ROUTING ] ") | bold | color(Color::Blue), vbox({
                text("") | size(HEIGHT, EQUAL, 1),
                text("  Connect to Peer:") | color(Color::GrayLight),
                comp_peer->Render() | size(WIDTH, GREATER_THAN, 35),
                text("") | size(HEIGHT, EQUAL, 2),
                btn_connect->Render() | center,
                text("") | size(HEIGHT, EQUAL, 1),
                separator() | color(Color::GrayDark),
                text("") | size(HEIGHT, EQUAL, 1),
                btn_wait->Render() | center,
                text("") | size(HEIGHT, EQUAL, 1),
                (ui_error.empty() ? text("") : text("  " + ui_error) | color(Color::Red) | bold),
                text("") | size(HEIGHT, EQUAL, 1),
            })) | center | size(WIDTH, GREATER_THAN, 45) | style_normal;
        } else {
            // CHAT
            Elements history_elements;
            {
                std::lock_guard<std::mutex> lock(chat_mutex);
                for (const auto& msg : chat_history) {
                    if (msg.find(my_username + ">") == 0) {
                        history_elements.push_back(text(" " + msg) | color(Color::Green));
                    } else if (msg.find(peer_username + ">") == 0) {
                        history_elements.push_back(text(" " + msg) | color(Color::Cyan));
                    } else {
                        history_elements.push_back(text(" " + msg) | color(Color::GrayDark));
                    }
                }
            }
            if (history_elements.empty()) {
                history_elements.push_back(text("  Waiting for messages...") | color(Color::GrayDark));
            }
            
            page = vbox({
                hbox({
                    text(" SECURE ") | color(Color::Black) | bgcolor(Color::Green) | bold,
                    text("  " + my_username) | color(Color::Blue) | bold,
                    text("  <->  ") | color(Color::GrayDark),
                    text(peer_username.empty() ? "waiting..." : peer_username) | color(Color::Cyan) | bold,
                    filler(),
                    text(hint) | color(Color::GrayDark),
                }) | bgcolor(Color::Black),
                separator() | color(Color::Blue),
                window(text(" Chat ") | color(Color::Blue), vbox(std::move(history_elements))) | flex,
                separator() | color(Color::Blue),
                hbox({
                    text(" > ") | color(Color::Blue) | bold,
                    comp_msg->Render() | flex,
                    text(" "),
                    btn_send->Render(),
                }) | bgcolor(Color::Black),
            }) | style_normal;
        }

        // Status bar at bottom
        auto status_bar = hbox({
            text(" shushhh v2.0 ") | color(Color::Black) | bgcolor(Color::Blue) | bold,
            filler(),
            text(hint) | color(Color::GrayDark),
        });

        Element final_page;
        if (current_state == CHAT) {
            final_page = page; // chat has its own status
        } else {
            final_page = vbox({ page | flex, status_bar });
        }

        // Debug overlay
        if (show_debug) {
            std::string logs = get_logs();
            // Split logs into lines, show last 20
            std::vector<Element> log_lines;
            std::istringstream iss(logs);
            std::string line;
            std::vector<std::string> all_lines;
            while (std::getline(iss, line)) {
                all_lines.push_back(line);
            }
            size_t start = all_lines.size() > 25 ? all_lines.size() - 25 : 0;
            for (size_t i = start; i < all_lines.size(); ++i) {
                log_lines.push_back(text(" " + all_lines[i]) | color(Color::GrayLight));
            }
            if (log_lines.empty()) {
                log_lines.push_back(text("  (no logs yet)") | color(Color::GrayDark));
            }

            auto debug_panel = window(
                text(" [ DEBUG LOG ] Alt+X to close ") | bold | color(Color::Yellow),
                vbox(std::move(log_lines))
            ) | size(HEIGHT, LESS_THAN, 15) | size(WIDTH, LESS_THAN, 80) | bgcolor(Color::Black) | color(Color::White);

            final_page = vbox({
                final_page | flex,
                debug_panel,
            });
        }

        return final_page;
    });
    
    auto event_listener = CatchEvent(renderer, [&](Event event) {
        // Escape to quit
        if (event == Event::Escape) {
            screen.Exit();
            return true;
        }
        // Ctrl+C
        if (event == Event::CtrlC) {
            screen.Exit();
            return true;
        }
        // Alt+X toggle debug
        if (event == Event::AltX) {
            show_debug = !show_debug;
            return true;
        }
        return false;
    });

    // Start fetcher thread
    std::thread fetcher(fetcher_thread, &screen);
    
    // Run UI
    screen.Loop(event_listener);
    
    // Cleanup
    keep_running = false;
    fetcher.join();
    
    // Restore stderr
    std::cerr.rdbuf(orig_cerr);
    
    // Wipe keys
    if (has_keypair) {
        secure_wipe(my_keypair.x25519_private, 32);
        secure_wipe(my_keypair.kyber_private.data(), my_keypair.kyber_private.size());
    }
    if (has_session) {
        secure_wipe(current_session.send_key.data(), 32);
        secure_wipe(current_session.recv_key.data(), 32);
        secure_wipe(current_session.root_key.data(), 32);
    }
    
    curl_global_cleanup();
    return 0;
}
