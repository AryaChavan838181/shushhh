#include <iostream>
#include <string>
#include <filesystem>
#include <windows.h>

namespace fs = std::filesystem;

void hide_file(const std::string& filepath) {
    std::wstring wfilepath(filepath.begin(), filepath.end());
    DWORD attributes = GetFileAttributesW(wfilepath.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        // Add Hidden and System attributes
        SetFileAttributesW(wfilepath.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        std::cout << "[+] Hid file: " << filepath << "\n";
    } else {
        std::cerr << "[-] Failed to get attributes for hiding: " << filepath << "\n";
    }
}

int main() {
    std::cout << "==================================================\n";
    std::cout << "  shushhh STANDALONE USB BUILDER\n";
    std::cout << "==================================================\n\n";

    std::cout << "Enter target USB drive letter (e.g., E): ";
    std::string drive_letter;
    std::getline(std::cin, drive_letter);

    if (drive_letter.empty() || drive_letter.length() > 1) {
        std::cerr << "[-] Invalid drive letter.\n";
        return 1;
    }

    // Convert to uppercase
    drive_letter[0] = toupper(drive_letter[0]);
    std::string target_dir = drive_letter + ":\\";

    if (!fs::exists(target_dir)) {
        std::cerr << "[-] Drive " << target_dir << " not found or inaccessible.\n";
        return 1;
    }

    std::cout << "\n[*] Targeting USB Drive: " << target_dir << "\n";

    // Assuming installer is run from the build folder, shushhh.exe should be next to it.
    std::string shushhh_src = "shushhh.exe";
    std::string tor_src = "tor.exe";
    
    // Fallbacks if they placed Tor in a subfolder
    if (!fs::exists(tor_src) && fs::exists("tor/tor.exe")) {
        tor_src = "tor/tor.exe";
    }

    if (!fs::exists(shushhh_src)) {
        std::cerr << "[-] Could not find " << shushhh_src << " in current directory.\n";
        std::cerr << "    Make sure shushhh_installer.exe is in the same folder as shushhh.exe.\n";
        return 1;
    }

    std::string dest_shushhh = target_dir + "shushhh.exe";
    std::string dest_tor = target_dir + "tor.exe";

    std::cout << "[*] Copying " << shushhh_src << " to " << dest_shushhh << "...\n";
    try {
        fs::copy_file(shushhh_src, dest_shushhh, fs::copy_options::overwrite_existing);
        std::cout << "[+] Copied successfully.\n";
    } catch (const fs::filesystem_error& e) {
        std::cerr << "[-] Copy failed: " << e.what() << "\n";
        return 1;
    }

    if (fs::exists(tor_src)) {
        std::cout << "[*] Copying " << tor_src << " to " << dest_tor << "...\n";
        try {
            fs::copy_file(tor_src, dest_tor, fs::copy_options::overwrite_existing);
            std::cout << "[+] Copied successfully.\n";
            hide_file(dest_tor);
        } catch (const fs::filesystem_error& e) {
            std::cerr << "[-] Copy failed: " << e.what() << "\n";
        }
    } else {
        std::cerr << "[-] Could not find tor.exe. Continuing anyway, but USB will need Tor added manually.\n";
    }

    std::cout << "\n[+] USB Drive preparation complete!\n";
    std::cout << "[+] When you plug this drive into a computer, only shushhh.exe will be visible.\n";
    std::cout << "\nPress Enter to exit...";
    std::cin.get();

    return 0;
}
