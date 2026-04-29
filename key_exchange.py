from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ecdh_keys():
    """Generates an Elliptic Curve key pair for ECDH."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    """Derives a shared secret using ECDH and HKDF."""
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Use HKDF to expand the shared key into a 32-byte key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'drone-secure-ecdh-handshake',
    ).derive(shared_key)
    
    return derived_key
