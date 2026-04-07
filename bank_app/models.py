# app/models.py
import hashlib
import hmac
import sys
from pathlib import Path

# Import PBKDF2-based key derivation from the main project
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from crypto_utils import CryptoUtils
    _USE_PBKDF2 = True
except ImportError:
    _USE_PBKDF2 = False  # Fallback to plain SHA-256 if unavailable

# Simple in-memory "database"
_users = {}


def init_users():
    """
    Initialize some demo users. In a real system this would be a database.
    """
    global _users
    _users = {
        "alice": {"password_hash": None, "balance": 5000},
        "bob": {"password_hash": None, "balance": 3000},
    }
    for username in _users:
        default_password = f"{username}123"
        _users[username]["password_hash"] = hash_password(default_password)


def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a random salt (secure).
    Returns a 'salt_hex:key_hex' string so the salt is stored alongside the hash.

    WHY THIS MATTERS (educational):
      Plain SHA-256 with no salt is trivially cracked by rainbow tables.
      PBKDF2 + random salt makes every hash unique and computationally expensive
      to reverse — even if two users share the same password.
    """
    if _USE_PBKDF2:
        key, salt = CryptoUtils.derive_key_from_password(password)
        return f"{salt.hex()}:{key.hex()}"
    # Fallback: plain SHA-256 (insecure — shown for comparison only)
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(username: str, password: str) -> bool:
    if username not in _users:
        return False
    stored = _users[username]["password_hash"]
    if _USE_PBKDF2 and ":" in stored:
        # PBKDF2 path: re-derive with the stored salt and compare securely
        salt_hex, key_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        derived_key, _ = CryptoUtils.derive_key_from_password(password, salt=salt)
        return hmac.compare_digest(derived_key, bytes.fromhex(key_hex))
    # Fallback: plain SHA-256 comparison
    return stored == hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_user(username: str, password: str, starting_balance: int = 1000) -> bool:
    if username in _users:
        return False
    _users[username] = {
        "password_hash": hash_password(password),
        "balance": starting_balance,
    }
    return True


def change_user_password(username: str, new_password: str) -> None:
    if username in _users:
        _users[username]["password_hash"] = hash_password(new_password)


def get_balance(username: str):
    if username not in _users:
        return None
    return _users[username]["balance"]


def transfer(from_user: str, to_user: str, amount: int) -> tuple[bool, str]:
    if from_user not in _users:
        return False, "Sender does not exist."
    if to_user not in _users:
        return False, "Recipient does not exist."
    if amount <= 0:
        return False, "Amount must be positive."
    if _users[from_user]["balance"] < amount:
        return False, "Insufficient balance."

    _users[from_user]["balance"] -= amount
    _users[to_user]["balance"] += amount
    return True, f"Transferred {amount} credits to {to_user}."


def get_all_users():
    """
    For debugging / demo only – returns a copy of all user data.
    """
    return {u: dict(info) for u, info in _users.items()}