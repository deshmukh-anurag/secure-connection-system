import os
import hmac
import hashlib

def generate_challenge():
    """Server generates a random challenge."""
    return os.urandom(32)

def compute_response(challenge, pre_shared_secret):
    """Client computes response using a pre-shared secret key."""
    return hmac.new(pre_shared_secret, challenge, hashlib.sha256).digest()

def verify_response(challenge, response, pre_shared_secret):
    """Server verifies the client's response."""
    expected = compute_response(challenge, pre_shared_secret)
    return hmac.compare_digest(expected, response)