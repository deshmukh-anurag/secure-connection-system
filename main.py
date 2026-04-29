import base64
import json
import os

from authentication import generate_challenge, compute_response, verify_response
from key_exchange import generate_ecdh_keys, derive_shared_secret
from encryption import generate_rsa_keypair, rsa_encrypt, rsa_decrypt, aes_cbc_encrypt, aes_cbc_decrypt
from signature import generate_ecdsa_keys, ecdsa_sign, ecdsa_verify
from integrity import generate_hmac, verify_hmac
from replay import generate_nonce, validate_nonce

class DroneClient:
    def __init__(self, drone_id, pre_shared_secret):
        self.drone_id = drone_id
        self.pre_shared_secret = pre_shared_secret
        self.ecdsa_priv, self.ecdsa_pub = generate_ecdsa_keys()
        self.ecdh_priv, self.ecdh_pub = generate_ecdh_keys()
        self.aes_session_key = os.urandom(32)
        
    def respond_to_challenge(self, challenge):
        print(f"[Drone] Responding to authentication challenge...")
        return compute_response(challenge, self.pre_shared_secret)
        
    def get_public_keys(self):
        return self.ecdh_pub, self.ecdsa_pub
        
    def prepare_secure_payload(self, server_rsa_pub, server_ecdh_pub):
        print("\n[Drone] Initiating secure payload preparation...")
        
        # 1. Establish derived MAC key using ECDH
        derived_key = derive_shared_secret(self.ecdh_priv, server_ecdh_pub)
        mac_key = derived_key[:32] # 32 bytes for HMAC
        
        # 2. Encrypt AES session key with Server's RSA public key
        enc_session_key = rsa_encrypt(server_rsa_pub, self.aes_session_key)
        
        # 3. Encrypt telemetry data with AES-CBC using the AES session key
        telemetry = {
            "drone_id": self.drone_id,
            "latitude": 34.0522,
            "longitude": -118.2437,
            "speed": 65
        }
        plaintext = json.dumps(telemetry).encode()
        iv, ciphertext = aes_cbc_encrypt(self.aes_session_key, plaintext)
        
        # 4. Generate Nonce for replay protection
        nonce = generate_nonce()
        
        # 5. Pack data
        packet = {
            "drone_id": self.drone_id,
            "nonce": base64.b64encode(nonce).decode(),
            "enc_session_key": base64.b64encode(enc_session_key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        
        # 6. Integrity and Authentication of payload
        canonical_data = json.dumps(packet, sort_keys=True).encode()
        mac = generate_hmac(mac_key, canonical_data)
        signature = ecdsa_sign(self.ecdsa_priv, canonical_data)
        
        packet["mac"] = base64.b64encode(mac).decode()
        packet["signature"] = base64.b64encode(signature).decode()
        
        print("[Drone] Payload securely prepared and signed.")
        return packet


class GroundStation:
    def __init__(self, expected_drone_id, pre_shared_secret):
        self.expected_drone_id = expected_drone_id
        self.pre_shared_secret = pre_shared_secret
        self.rsa_priv, self.rsa_pub = generate_rsa_keypair()
        self.ecdh_priv, self.ecdh_pub = generate_ecdh_keys()
        
    def authenticate_drone(self, drone):
        print("\n[Ground Station] Sending authentication challenge to drone...")
        challenge = generate_challenge()
        response = drone.respond_to_challenge(challenge)
        
        if verify_response(challenge, response, self.pre_shared_secret):
            print("[Ground Station] Drone authentication SUCCESSFUL.")
            return True
        else:
            print("[Ground Station] Drone authentication FAILED.")
            return False
            
    def receive_payload(self, packet, drone_ecdh_pub, drone_ecdsa_pub):
        print("\n[Ground Station] Receiving secure payload...")
        
        # Extract fields
        try:
            nonce = base64.b64decode(packet.pop("nonce"))
            enc_session_key = base64.b64decode(packet.pop("enc_session_key"))
            iv = base64.b64decode(packet.pop("iv"))
            ciphertext = base64.b64decode(packet.pop("ciphertext"))
            mac = base64.b64decode(packet.pop("mac"))
            signature = base64.b64decode(packet.pop("signature"))
        except KeyError as e:
            raise ValueError(f"Missing field in packet: {e}")
            
        # Reconstruct canonical data for verification
        packet["nonce"] = base64.b64encode(nonce).decode()
        packet["enc_session_key"] = base64.b64encode(enc_session_key).decode()
        packet["iv"] = base64.b64encode(iv).decode()
        packet["ciphertext"] = base64.b64encode(ciphertext).decode()
        canonical_data = json.dumps(packet, sort_keys=True).encode()
        
        # 1. Replay Protection check
        print("[Ground Station] Checking for replay attacks...")
        validate_nonce(nonce)
        print("[Ground Station] Nonce is fresh.")
        
        # 2. Digital Signature check
        print("[Ground Station] Verifying ECDSA signature...")
        ecdsa_verify(drone_ecdsa_pub, canonical_data, signature)
        print("[Ground Station] Signature verified.")
        
        # 3. Message Integrity check
        print("[Ground Station] Verifying message integrity (HMAC)...")
        derived_key = derive_shared_secret(self.ecdh_priv, drone_ecdh_pub)
        mac_key = derived_key[:32]
        if not verify_hmac(mac_key, canonical_data, mac):
            raise ValueError("MAC verification failed!")
        print("[Ground Station] MAC verified.")
        
        # 4. Decrypt AES session key using RSA
        print("[Ground Station] Decrypting AES session key via RSA-OAEP...")
        aes_session_key = rsa_decrypt(self.rsa_priv, enc_session_key)
        
        # 5. Decrypt Payload
        print("[Ground Station] Decrypting telemetry data using AES-CBC...")
        plaintext = aes_cbc_decrypt(aes_session_key, iv, ciphertext)
        
        print("\n[Ground Station] >>> SECURE DATA RECOVERED:")
        print(json.loads(plaintext.decode()))
        return True


def simulate():
    print("=== SECURE DRONE COMMUNICATION PROTOCOL ===")
    
    # Pre-shared secret for HMAC Challenge-Response
    SHARED_SECRET = b"super_secret_drone_auth_key_99"
    DRONE_ID = "DRN-Alpha-1"
    
    drone = DroneClient(DRONE_ID, SHARED_SECRET)
    station = GroundStation(DRONE_ID, SHARED_SECRET)
    
    # Step 1: Authentication
    if not station.authenticate_drone(drone):
        print("Aborting communication.")
        return
        
    # Step 2: Key Exchange & Data Preparation
    drone_ecdh_pub, drone_ecdsa_pub = drone.get_public_keys()
    
    packet = drone.prepare_secure_payload(station.rsa_pub, station.ecdh_pub)
    
    # Step 3: Ground Station Processes Packet
    try:
        # Create a deep copy to prevent mutation issues in the simulation
        station.receive_payload(json.loads(json.dumps(packet)), drone_ecdh_pub, drone_ecdsa_pub)
    except Exception as e:
        print(f"FAILED TO PROCESS PACKET: {e}")
        
    # Step 4: Bonus - Replay Attack Simulation
    print("\n\n=== BONUS: REPLAY ATTACK SIMULATION ===")
    print("An attacker intercepts the packet and tries to resend it...")
    try:
        station.receive_payload(json.loads(json.dumps(packet)), drone_ecdh_pub, drone_ecdsa_pub)
        print("CRITICAL SECURITY FAILURE: Replay attack succeeded!")
    except ValueError as e:
        print(f"SUCCESS: Replay attack prevented! Reason: {e}")


if __name__ == "__main__":
    simulate()
