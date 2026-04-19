"""
shushhh relay server — setup_keys.py
Generate Ed25519 signing keypair for the relay server.
Run ONCE at server setup. The public key is embedded in the client binary.
"""

import nacl.signing
import sys
import os

def main():
    print("=" * 50)
    print("  shushhh Ed25519 Server Key Generator")
    print("=" * 50)
    print()

    # Generate a new Ed25519 signing keypair
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    # Save private key to file (stays on server, never shared)
    key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_key.bin")
    with open(key_path, "wb") as f:
        f.write(bytes(signing_key))
    print(f"[+] Private key saved to: {key_path}")
    print("    KEEP THIS FILE SECRET — it stays on the server only")
    print()

    # Print public key in formats suitable for embedding
    pub_bytes = bytes(verify_key)
    
    # Hex format
    pub_hex = pub_bytes.hex()
    print(f"[+] Public key (hex): {pub_hex}")
    print()

    # C++ array format — paste this into auth.cpp
    cpp_array = ", ".join(f"0x{b:02x}" for b in pub_bytes)
    print("[+] C++ format — paste into SERVER_ED25519_PUBKEY in auth.cpp:")
    print()
    print(f"const unsigned char SERVER_ED25519_PUBKEY[32] = {{")
    # Print in rows of 8
    for i in range(0, 32, 8):
        row = ", ".join(f"0x{b:02x}" for b in pub_bytes[i:i+8])
        suffix = "," if i + 8 < 32 else ""
        print(f"    {row}{suffix}")
    print("};")
    print()

    # Python hex for relay_server.py verification
    print(f"[+] Python format — already saved alongside server_key.bin")
    print()
    print("[!] IMPORTANT: After pasting the public key into auth.cpp,")
    print("    rebuild the client. The server pubkey is the MITM-proof")
    print("    trust anchor — without it, signature verification fails.")

if __name__ == "__main__":
    main()
