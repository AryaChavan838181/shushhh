#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <windows.h>

#include "resource_ids.h"

// FTXUI
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/event.hpp>

using namespace ftxui;
namespace fs = std::filesystem;

// ============================================================
// Drive Detection
// ============================================================
struct DriveInfo {
    char letter;
    std::string label;
    uint64_t total_bytes;
    uint64_t free_bytes;
    UINT drive_type;
    
    std::string display_name() const {
        const char* type_str = (drive_type == DRIVE_REMOVABLE) ? "USB" : "HDD";
        double gb_total = total_bytes / (1024.0 * 1024.0 * 1024.0);
        double gb_free  = free_bytes / (1024.0 * 1024.0 * 1024.0);
        char buf[128];
        if (label.empty())
            snprintf(buf, sizeof(buf), "[%s] %c:\\ (%.1f GB / %.1f GB free)", type_str, letter, gb_total, gb_free);
        else
            snprintf(buf, sizeof(buf), "[%s] %c:\\ %s (%.1f GB / %.1f GB free)", type_str, letter, label.c_str(), gb_total, gb_free);
        return std::string(buf);
    }
};

std::vector<DriveInfo> detect_drives() {
    std::vector<DriveInfo> drives;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1 << i))) continue;
        char letter = 'A' + i;
        if (letter == 'C') continue; // Skip system drive
        char root[] = { letter, ':', '\\', '\0' };
        UINT type = GetDriveTypeA(root);
        if (type != DRIVE_REMOVABLE && type != DRIVE_FIXED) continue;
        
        DriveInfo info;
        info.letter = letter;
        info.drive_type = type;
        char vol[MAX_PATH+1] = {0};
        GetVolumeInformationA(root, vol, MAX_PATH, nullptr, nullptr, nullptr, nullptr, 0);
        info.label = vol;
        ULARGE_INTEGER fb, tb;
        if (GetDiskFreeSpaceExA(root, nullptr, &tb, &fb)) {
            info.total_bytes = tb.QuadPart;
            info.free_bytes = fb.QuadPart;
        } else { info.total_bytes = info.free_bytes = 0; }
        drives.push_back(info);
    }
    return drives;
}

// ============================================================
// Resource Extraction
// ============================================================
bool extract_resource(int resource_id, const std::string& output_path) {
    HRSRC hRes = FindResourceA(nullptr, MAKEINTRESOURCEA(resource_id), RT_RCDATA);
    if (!hRes) return false;
    HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData) return false;
    DWORD size = SizeofResource(nullptr, hRes);
    void* data = LockResource(hData);
    if (!data || size == 0) return false;
    
    // Ensure parent directories exist
    fs::path p(output_path);
    if (p.has_parent_path()) fs::create_directories(p.parent_path());
    
    std::ofstream out(output_path, std::ios::binary);
    if (!out) return false;
    out.write(static_cast<const char*>(data), size);
    return out.good();
}

bool has_resource(int resource_id) {
    return FindResourceA(nullptr, MAKEINTRESOURCEA(resource_id), RT_RCDATA) != nullptr;
}

// ============================================================
// Hide file (Windows)
// ============================================================
void hide_file(const std::string& filepath) {
    std::wstring w(filepath.begin(), filepath.end());
    DWORD attr = GetFileAttributesW(w.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES)
        SetFileAttributesW(w.c_str(), attr | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

// ============================================================
// Styled Button
// ============================================================
Component StyledButton(const std::string& label, std::function<void()> on_click) {
    auto opt = ButtonOption::Ascii();
    opt.transform = [](const EntryState& s) {
        auto el = text(s.label) | center | border;
        if (s.focused) el = el | color(Color::Black) | bgcolor(Color::Blue) | bold;
        else           el = el | color(Color::White) | bgcolor(Color::Black);
        return el;
    };
    return Button(label, std::move(on_click), opt);
}

// ============================================================
// Main
// ============================================================
int main() {
    auto screen = ScreenInteractive::Fullscreen();
    
    enum State { SELECT, INSTALLING, DONE, ERR };
    State state = SELECT;
    
    auto drives = detect_drives();
    std::vector<std::string> drive_names;
    for (auto& d : drives) drive_names.push_back(d.display_name());
    
    int selected = 0;
    std::vector<std::string> logs;
    std::string error_msg;
    
    bool has_shushhh = has_resource(IDR_SHUSHHH_EXE);
    bool has_tor     = has_resource(IDR_TOR_EXE);
    
    // RadioBox for drive selection
    auto radio_opt = RadioboxOption::Simple();
    radio_opt.transform = [](const EntryState& s) {
        auto prefix = s.state ? text(" (*) ") : text(" ( ) ");
        auto el = hbox({prefix, text(s.label)});
        if (s.focused) el = el | color(Color::Black) | bgcolor(Color::Blue) | bold;
        else if (s.state) el = el | color(Color::Cyan) | bold;
        else el = el | color(Color::White);
        return el;
    };
    auto drive_radio = Radiobox(&drive_names, &selected, radio_opt);
    
    auto do_install = [&]() {
        if (drives.empty()) { error_msg = "No drives detected!"; state = ERR; return; }
        if (!has_shushhh) { error_msg = "shushhh.exe not embedded in installer!"; state = ERR; return; }
        
        state = INSTALLING;
        logs.clear();
        auto& target = drives[selected];
        std::string root = std::string(1, target.letter) + ":\\";
        logs.push_back("[*] Target: " + target.display_name());
        
        // Extract shushhh.exe
        logs.push_back("[*] Extracting shushhh.exe...");
        std::string dest_shushhh = root + "shushhh.exe";
        if (!extract_resource(IDR_SHUSHHH_EXE, dest_shushhh)) {
            error_msg = "Failed to extract shushhh.exe"; state = ERR; return;
        }
        logs.push_back("[+] shushhh.exe extracted");
        
        // Extract tor.exe into tor/ subdirectory
        if (has_tor) {
            logs.push_back("[*] Extracting tor.exe...");
            std::string dest_tor = root + "tor\\tor\\tor.exe";
            if (extract_resource(IDR_TOR_EXE, dest_tor)) {
                hide_file(root + "tor");
                hide_file(dest_tor);
                logs.push_back("[+] tor.exe extracted & hidden");
            } else {
                logs.push_back("[-] Failed to extract tor.exe");
            }
        } else {
            logs.push_back("[!] Tor not embedded — skipping");
        }
        
        logs.push_back("");
        logs.push_back("[+] USB preparation complete!");
        logs.push_back("[+] Only shushhh.exe is visible on the drive.");
        state = DONE;
    };
    
    // Buttons
    auto btn_install = StyledButton("    INSTALL     ", do_install);
    auto btn_refresh = StyledButton("   REFRESH      ", [&] {
        drives = detect_drives();
        drive_names.clear();
        for (auto& d : drives) drive_names.push_back(d.display_name());
        selected = 0;
    });
    auto btn_exit = StyledButton("     EXIT       ", [&] { screen.Exit(); });
    auto btn_back = StyledButton("     BACK       ", [&] { state = SELECT; });
    
    auto sel_ctr = Container::Vertical({drive_radio, btn_install, btn_refresh, btn_exit});
    auto done_ctr = Container::Vertical({btn_back, btn_exit});
    int tab = 0;
    auto main_ctr = Container::Tab({sel_ctr, done_ctr}, &tab);
    
    auto renderer = Renderer(main_ctr, [&] {
        tab = (state == SELECT) ? 0 : 1;
        Element page;
        
        if (state == SELECT) {
            Elements dl;
            if (drives.empty()) {
                dl.push_back(text("  No removable drives detected.") | color(Color::Red));
                dl.push_back(text("  Insert a USB drive and click REFRESH.") | color(Color::GrayDark));
            } else {
                dl.push_back(drive_radio->Render());
            }
            
            // Show embedded status
            auto status_shushhh = has_shushhh 
                ? text("  [+] shushhh.exe embedded") | color(Color::Green) 
                : text("  [-] shushhh.exe NOT embedded") | color(Color::Red);
            auto status_tor = has_tor 
                ? text("  [+] tor.exe embedded") | color(Color::Green) 
                : text("  [!] tor.exe not embedded (optional)") | color(Color::Yellow);
            
            page = vbox({
                text("") | size(HEIGHT, EQUAL, 1),
                text("  ┌───────────────────────────────────────┐") | color(Color::Blue) | bold,
                text("  │     shushhh USB INSTALLER             │") | color(Color::Blue) | bold,
                text("  │     Self-Contained Package            │") | color(Color::Blue) | bold,
                text("  └───────────────────────────────────────┘") | color(Color::Blue) | bold,
                text("") | size(HEIGHT, EQUAL, 1),
                status_shushhh,
                status_tor,
                text("") | size(HEIGHT, EQUAL, 1),
                text("  Select target drive:") | color(Color::GrayLight) | bold,
                text("") | size(HEIGHT, EQUAL, 1),
                vbox(std::move(dl)) | border | color(Color::GrayDark) | size(WIDTH, GREATER_THAN, 55),
                text("") | size(HEIGHT, EQUAL, 1),
                btn_install->Render() | center,
                text("") | size(HEIGHT, EQUAL, 1),
                btn_refresh->Render() | center,
                text("") | size(HEIGHT, EQUAL, 1),
                separator() | color(Color::GrayDark),
                text("") | size(HEIGHT, EQUAL, 1),
                btn_exit->Render() | center,
            }) | center | color(Color::White) | bgcolor(Color::Black);
        } else {
            Elements le;
            for (auto& l : logs) {
                Color c = Color::White;
                if (l.find("[+]") == 0) c = Color::Green;
                else if (l.find("[-]") == 0) c = Color::Red;
                else if (l.find("[!]") == 0) c = Color::Yellow;
                else if (l.find("[*]") == 0) c = Color::Cyan;
                le.push_back(text("  " + l) | color(c));
            }
            if (!error_msg.empty())
                le.push_back(text("  ERROR: " + error_msg) | color(Color::Red) | bold);
            
            std::string title = (state == DONE) ? " [ COMPLETE ] " : " [ ERROR ] ";
            Color tc = (state == DONE) ? Color::Green : Color::Red;
            
            page = vbox({
                text("") | size(HEIGHT, EQUAL, 2),
                window(text(title) | bold | color(tc), vbox(std::move(le))) | size(WIDTH, GREATER_THAN, 55),
                text("") | size(HEIGHT, EQUAL, 2),
                btn_back->Render() | center,
                text("") | size(HEIGHT, EQUAL, 1),
                btn_exit->Render() | center,
            }) | center | color(Color::White) | bgcolor(Color::Black);
        }
        
        auto bar = hbox({
            text(" shushhh installer v2.0 ") | color(Color::Black) | bgcolor(Color::Blue) | bold,
            filler(),
            text(" [ESC] Quit ") | color(Color::GrayDark),
        });
        return vbox({ page | flex, bar });
    });
    
    auto handler = CatchEvent(renderer, [&](Event e) {
        if (e == Event::Escape || e == Event::CtrlC) { screen.Exit(); return true; }
        return false;
    });
    
    screen.Loop(handler);
    return 0;
}
