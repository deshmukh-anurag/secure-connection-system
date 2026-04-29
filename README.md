# Secure Drone Communication (Drone ↔ Ground Control Station)

This project simulates a secure telemetry channel between a **Drone (client)** and a **Ground Control Station (server)**, integrating:
- Symmetric crypto (AES)
- Asymmetric crypto (RSA)
- Diffie–Hellman (DH) key exchange
- Password authentication (hash + salt)
- Digital signatures
- Message integrity (HMAC)
- Replay protection

## High-level workflow
1. **Registration (server side)**: server stores only `(salt, password_hash)` for a drone ID.
2. **Authentication**: drone provides password, server verifies using stored salt+hash.
3. **Key Exchange (DH)**: drone and server generate DH keys and compute the same shared secret.
4. **Hybrid keying**:
   - Drone generates a random **AES session key**.
   - Drone encrypts (wraps) this AES key using **server RSA public key** (RSA-OAEP-SHA256).
5. **Key derivation (HKDF)**:
   - Both sides derive two keys from: `DH_shared_secret || AES_session_key`
   - Output keys:
     - `enc_key` (32 bytes) for AES encryption
     - `mac_key` (32 bytes) for HMAC
6. **Encrypt telemetry**: drone encrypts telemetry using **AES-CTR**.
7. **Bind security metadata**: drone creates a packet containing:
   - drone_id, timestamp, nonce, ciphertext, enc_session_key
8. **Integrity + authenticity**:
   - Drone computes **HMAC-SHA256** over the canonical bytes of signed fields.
   - Drone signs the same canonical bytes using **RSA-PSS (SHA-256)**.
9. **Server validation**:
   - Checks timestamp freshness window.
   - Decrypts AES session key (RSA private key).
   - Derives `enc_key` and `mac_key` (HKDF).
   - Verifies signature.
   - Verifies HMAC.
   - Enforces replay protection.
   - Decrypts ciphertext.
10. **Bonus demo**: the same packet is resent to show replay detection.

## Packet format
In `main.py`, the drone sends a dictionary like:
```json
{
  "drone_id": "DR001",
  "timestamp": 1713720000,
  "nonce": "<base64>",
  "ciphertext": "<base64>",
  "enc_session_key": "<base64>",
  "mac": "<base64>",
  "signature": "<base64>"
}
```

**Signed/MACed fields** are canonicalized with JSON `sort_keys=True` and compact separators so both sides compute identical bytes.

## Project structure
- `main.py`
  - End-to-end simulation of Drone → Server flow and replay attack demo.
  - Defines packet creation, canonicalization, and server-side `process_packet()`.
- `authentication.py`
  - Password hashing + verification using **SHA-256(salt || password)**.
- `key_exchange.py`
  - DH key generation and shared secret.
  - HKDF-based key derivation: produces `enc_key` and `mac_key`.
- `encryption.py`
  - AES-CTR encrypt/decrypt.
  - RSA-OAEP wrap/unwrap of AES session key.
- `signature.py`
  - RSA key generation.
  - RSA-PSS sign/verify (SHA-256).
- `integrity.py`
  - HMAC-SHA256 generation and verification.
- `replay.py`
  - Timestamp creation + freshness check.
  - Replay tracking using a unique message id: `drone_id:timestamp:nonce`.

## How to run
1. Install dependencies:
```bash
pip install -r requirements.txt
```
2. Run the simulation:
```bash
python main.py
```
Expected output shows authentication success, DH secret establishment, RSA wrapping, encryption, verification, and replay blocked.

## Security properties (what this prevents)
- **Confidentiality**: telemetry encrypted with AES-CTR using a derived encryption key.
- **Key confidentiality in transit**: AES session key is wrapped using RSA-OAEP.
- **Integrity**: HMAC-SHA256 over signed fields.
- **Authenticity / non-repudiation**: RSA-PSS signature over the same fields.
- **Replay protection**: timestamp freshness window + message-id tracking.

## Important notes / limitations
- This is a **simulation** (no sockets/network). In a real deployment you would also:
  - Use authenticated DH/ECDH (e.g., certificates) to prevent MITM during key exchange.
  - Prefer an AEAD mode like **AES-GCM** or **ChaCha20-Poly1305** instead of separate AES+HMAC.
  - Store password hashes using a slow password KDF (bcrypt/scrypt/argon2) rather than raw SHA-256.
  - Add server-side key management and rotation policies.

## Troubleshooting
- If `pip install` fails, confirm Python version and that the `cryptography` package builds/installs correctly.
- If signature/MAC verification fails, ensure the canonicalization logic is unchanged on both sides.
