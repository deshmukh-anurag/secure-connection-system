import hmac
import hashlib

def generate_hmac(key, message):
    """Generate HMAC-SHA256."""
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_hmac(key, message, mac_to_verify):
    """Verify HMAC-SHA256."""
    expected_mac = generate_hmac(key, message)
    return hmac.compare_digest(expected_mac, mac_to_verify)