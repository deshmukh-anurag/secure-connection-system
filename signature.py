from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def generate_ecdsa_keys():
    """Generates an Elliptic Curve key pair for ECDSA signatures."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdsa_sign(private_key, message):
    """Sign a message using ECDSA with SHA-256."""
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def ecdsa_verify(public_key, message, signature):
    """Verify an ECDSA signature. Raises an exception if invalid."""
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))