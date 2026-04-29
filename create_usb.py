"""
create_usb.py — USB setup utility for Shushhh

This script prepares a USB drive to act as a portable, stealthy messaging client.
It copies the necessary executables and hides sensitive binaries (like tor.exe)
from standard Windows Explorer views.
"""

import os
import shutil
import ctypes
import sys

def run_as_admin():
    """Request UAC elevation if not already running as admin (needed for some attrib operations)."""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    
    print("[*] Requesting Administrator privileges...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

def hide_file(filepath):
    """Set the Hidden (+H) and System (+S) attributes on a Windows file/folder."""
    # FILE_ATTRIBUTE_HIDDEN = 0x02
    # FILE_ATTRIBUTE_SYSTEM = 0x04
    ret = ctypes.windll.kernel32.SetFileAttributesW(filepath, 0x02 | 0x04)
    if not ret:
        print(f"[-] Failed to hide {filepath}")
    else:
        print(f"[+] Hid {filepath}")

def main():
    print("=" * 50)
    print("  shushhh USB BUILDER")
    print("=" * 50)

    # Prompt for target drive
    drive_letter = input("Enter target USB drive letter (e.g., E): ").strip().upper()
    if not drive_letter or len(drive_letter) > 1:
        print("[-] Invalid drive letter")
        return

    target_dir = f"{drive_letter}:\\"
    if not os.path.exists(target_dir):
        print(f"[-] Drive {target_dir} not found")
        return

    print(f"\n[*] Targeting USB Drive: {target_dir}")

    # Define source paths (assuming they are in the current working directory or build dir)
    shushhh_exe = "build/shushhh.exe"  # Adjust based on where cmake outputs it
    tor_exe = "tor/tor/tor.exe"            # Assuming the user downloaded the Tor Expert Bundle here
    
    if not os.path.exists(shushhh_exe):
        print(f"[-] Could not find {shushhh_exe}. Please build the project first.")
        return
    
    if not os.path.exists(tor_exe):
        print(f"[-] Could not find {tor_exe}. Please download the Tor Expert Bundle and place tor.exe in a 'tor' folder.")
        # We will continue anyway for demonstration purposes
        print("[!] Proceeding without tor.exe (will need to be added manually)")
    
    # Target paths on the USB
    dest_shushhh = os.path.join(target_dir, "shushhh.exe")
    dest_tor = os.path.join(target_dir, "tor.exe")
    
    # 1. Copy shushhh.exe (Visible)
    print(f"[*] Copying shushhh.exe to {dest_shushhh}...")
    try:
        shutil.copy2(shushhh_exe, dest_shushhh)
        print("[+] Copied successfully.")
    except Exception as e:
        print(f"[-] Copy failed: {e}")
        return

    # 2. Copy tor.exe (Hidden)
    if os.path.exists(tor_exe):
        print(f"[*] Copying tor.exe to {dest_tor}...")
        try:
            shutil.copy2(tor_exe, dest_tor)
            print("[+] Copied successfully.")
            # Hide it!
            hide_file(dest_tor)
        except Exception as e:
            print(f"[-] Copy failed: {e}")
            return
            
    print("\n[+] USB Drive preparation complete!")
    print("[+] When you plug this drive into a computer, only shushhh.exe will be visible.")

if __name__ == "__main__":
    main()
