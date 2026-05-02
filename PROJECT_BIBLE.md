# The Shushhh Protocol Bible

This document is the definitive single source of truth for the Shushhh secure messenger. It details the system architecture, cryptosystem mechanics, and the exact step-by-step message exchange protocol flow. 

---

## Part 1: Cryptographic Architecture & Primitives

Shushhh relies on a combination of classical elliptic-curve cryptography and NIST-standardized post-quantum cryptography to achieve **Post-Quantum Forward Secrecy**.

### 1. Classical Key Exchange: X25519
*   **What it is:** An Elliptic Curve Diffie-Hellman (ECDH) key agreement protocol over Curve25519.
*   **Purpose:** Allows two parties to generate a shared secret over an insecure channel. Even if an attacker monitors the channel, they cannot derive the secret.
*   **Role in Shushhh:** Forms the "classical" half of the hybrid key exchange. Protects against all present-day adversaries.

### 2. Post-Quantum Key Encapsulation: ML-KEM-768 (Kyber)
*   **What it is:** A Module Learning with Errors (MLWE) based Key Encapsulation Mechanism (KEM), standardized by NIST as FIPS 203.
*   **Purpose:** Resists attacks from large-scale quantum computers (which can easily break X25519 using Shor's algorithm). 
*   **Role in Shushhh:** Forms the "quantum-safe" half of the hybrid key exchange. Alice encapsulates a secret using Bob's public ML-KEM key.

### 3. Key Derivation: HKDF-SHA256
*   **What it is:** HMAC-based Extract-and-Expand Key Derivation Function.
*   **Purpose:** Takes multiple raw entropy inputs (like the X25519 shared secret and the ML-KEM shared secret) and combines them into a single, cryptographically strong, uniform key.
*   **Role in Shushhh:** Used to fuse the classical and post-quantum secrets together into a single "Root Key", and subsequently used in the Symmetric Ratchet to derive message keys.

### 4. Authenticated Encryption: ChaCha20-Poly1305
*   **What it is:** An Authenticated Encryption with Associated Data (AEAD) cipher suite. ChaCha20 is a stream cipher, and Poly1305 is an authenticator (MAC).
*   **Purpose:** Encrypts data for confidentiality and authenticates it so that any tampering is instantly detected.
*   **Role in Shushhh:** Used to encrypt all actual message payloads and the `identity.dat` file.

### 5. Perfect Forward Secrecy via Symmetric Ratcheting
*   **What it is:** A technique where a new, unique encryption key is generated for *every single message*.
*   **Purpose:** If an attacker compromises a user's device and steals their current session key, they cannot use it to decrypt past messages, because the keys used for past messages have been irreversibly erased.
*   **Mechanic:** 
    1. Message `N` is encrypted with `Key_N`.
    2. `Key_{N+1}` is derived via `HKDF-SHA256(Key_N, "ratchet")`.
    3. `Key_N` is aggressively wiped from RAM using `sodium_memzero()`.

---

## Part 2: The Infrastructure

Shushhh uses a **Cryptographically Blind Relay** architecture routed entirely over **Tor**.

1.  **Anonymity Layer (Tor):** The messenger executable automatically launches a bundled Tor instance. All HTTP communication to the servers is proxied through `127.0.0.1:9050` (SOCKS5), ensuring IP addresses and geographical locations are completely hidden.
2.  **Key Server (Ed25519 Authenticated):** A central repository where users upload their public keys (X25519 and ML-KEM). The server uses a hardcoded Ed25519 keypair to sign responses, preventing Man-in-the-Middle (MITM) attacks even if the Tor exit node or the server itself is compromised.
3.  **Message Server (Blind Store-and-Forward):** A dumb relay. It routes messages based on a SHA-256 hash of the recipient's public key (the "Tag"). The server cannot read the tags, cannot read the message contents, and does not know who is talking to whom.

---

## Part 3: Alice & Bob — The Protocol Flow

This section walks through the complete lifecycle of a secure conversation between Alice and Bob.

### Phase 1: Identity Creation & Registration
1.  **Local Generation:** Alice creates an account. Shushhh generates a hybrid keypair:
    *   `X25519_Priv_A`, `X25519_Pub_A`
    *   `MLKEM_Priv_A`, `MLKEM_Pub_A`
2.  **Storage:** The private keys are encrypted locally into `identity.dat` using ChaCha20-Poly1305, keyed by `SHA-256(AlicePassword + AliceUsername)`.
3.  **Upload:** Alice connects to the Key Server via Tor and uploads her public keys.

### Phase 2: Bob Wants to Talk to Alice
1.  **Key Fetch:** Bob enters "Alice" in the UI. His client queries the Key Server for Alice's public keys.
2.  **Server Signature Validation:** The Key Server returns Alice's keys, signed by the server's Ed25519 private key. Bob's client verifies this signature using the hardcoded `SERVER_ED25519_PUBKEY`. If valid, Bob proceeds.

### Phase 3: The 0-RTT "Sealed Sender" Handshake
Bob wants to say "Hello" to Alice. Instead of doing a back-and-forth handshake first, he uses a **0-RTT (Zero Round-Trip Time)** approach.

1.  **Ephemeral Key Generation:** Bob generates a temporary (ephemeral) X25519 keypair specifically for this initial handshake: `X25519_Priv_B_Eph`, `X25519_Pub_B_Eph`.
2.  **Classical Secret (X25519):** Bob computes the ECDH shared secret:
    *   `SS_Classical = X25519(X25519_Priv_B_Eph, X25519_Pub_A)`
3.  **Post-Quantum Secret (ML-KEM):** Bob encapsulates a secret against Alice's Kyber public key:
    *   `(SS_PQ, Ciphertext_PQ) = MLKEM_Encapsulate(MLKEM_Pub_A)`
4.  **Root Key Derivation:** Bob combines them using HKDF:
    *   `RootKey = HKDF_SHA256(SS_Classical || SS_PQ)`
5.  **Payload Encryption:** Bob encrypts his "Hello" message with `RootKey` using ChaCha20-Poly1305.
6.  **Transmission:** Bob sends the following to the Message Server:
    *   Target: `SHA256(X25519_Pub_A)` (Alice's routing tag)
    *   Payload: `X25519_Pub_B_Eph` + `Ciphertext_PQ` + `Encrypted("Hello")`

### Phase 4: Alice Receives the Message
1.  **Polling:** Alice is polling the Message Server using her routing tag. She downloads Bob's blob.
2.  **Classical Decapsulation:** Alice uses her long-term private key and Bob's ephemeral public key:
    *   `SS_Classical = X25519(X25519_Priv_A, X25519_Pub_B_Eph)`
3.  **Post-Quantum Decapsulation:** Alice decapsulates the Kyber ciphertext using her private Kyber key:
    *   `SS_PQ = MLKEM_Decapsulate(Ciphertext_PQ, MLKEM_Priv_A)`
4.  **Key Recovery:** Alice derives the exact same Root Key:
    *   `RootKey = HKDF_SHA256(SS_Classical || SS_PQ)`
5.  **Decryption:** Alice decrypts the ChaCha20-Poly1305 payload and reads "Hello".

### Phase 5: The Symmetric Ratchet
Once the `RootKey` is established, the session enters the ratcheting phase. The ephemeral keys and the ML-KEM ciphertexts are no longer needed.

1.  Alice wants to reply "Hi Bob".
2.  Alice derives the next key: `Key_2 = HKDF_SHA256(RootKey, "ratchet")`.
3.  Alice immediately deletes `RootKey` from her RAM.
4.  Alice encrypts "Hi Bob" using `Key_2` and sends it.
5.  Bob downloads the message. Because Bob knows `RootKey`, he also calculates `Key_2 = HKDF_SHA256(RootKey, "ratchet")`.
6.  Bob decrypts the message, deletes `RootKey`, and saves `Key_2` as the new state.
7.  This process repeats endlessly, advancing the ratchet with every single message. If a key is stolen at `Key_100`, the attacker cannot reverse the HKDF hash to find `Key_99`, ensuring Perfect Forward Secrecy.

---

## Summary of Security Guarantees
*   **Confidentiality:** Guaranteed by ChaCha20 stream cipher.
*   **Integrity / Authenticity:** Guaranteed by Poly1305 MAC.
*   **Anonymity:** Guaranteed by Tor.
*   **Forward Secrecy:** Guaranteed by Symmetric HKDF Ratcheting.
*   **Quantum Resistance:** Guaranteed by ML-KEM-768.
*   **Anti-Forensics:** Guaranteed by `sodium_memzero` and the USB Watchdog.
