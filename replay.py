import os

class NonceValidator:
    def __init__(self):
        self._nonce_cache = set()

    def generate_nonce(self):
        """Generate a random 16-byte nonce."""
        return os.urandom(16)

    def validate_nonce(self, nonce):
        """Check if nonce has been used before to prevent replay attacks."""
        if nonce in self._nonce_cache:
            raise ValueError("Replay Attack Detected: Nonce has already been used.")
        self._nonce_cache.add(nonce)

    def clear(self):
        """Clear cache (for testing purposes)."""
        self._nonce_cache.clear()

# Global default validator
default_validator = NonceValidator()

def generate_nonce():
    return default_validator.generate_nonce()

def validate_nonce(nonce):
    default_validator.validate_nonce(nonce)
