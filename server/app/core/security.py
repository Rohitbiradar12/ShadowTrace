import hashlib
import secrets

API_KEY_PREFIX = "stk"
ENROLLMENT_TOKEN_PREFIX = "ste"


def generate_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def generate_device_id() -> str:
    return f"dev_{secrets.token_hex(8)}"


def hash_token(token: str) -> str:
    # Tokens are 256-bit random values, so a fast hash is sufficient (no brute-force risk).
    return hashlib.sha256(token.encode()).hexdigest()
