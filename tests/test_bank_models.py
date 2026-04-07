# tests/test_bank_models.py
"""Unit tests for bank_app/models.py — PBKDF2 hashing, user management, transfers"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# bank_app imports flask; make sure it can be imported
try:
    from bank_app.models import (
        init_users, hash_password, verify_password,
        create_user, get_balance, transfer,
        change_user_password, get_all_users,
    )
    from bank_app.models import _USE_PBKDF2
except ImportError as e:
    pytest.skip(f"bank_app not importable: {e}", allow_module_level=True)


@pytest.fixture(autouse=True)
def reset_users():
    """Re-initialise the in-memory DB before every test for isolation"""
    init_users()
    yield


class TestPasswordHashing:
    def test_hash_returns_string(self):
        h = hash_password("securepass")
        assert isinstance(h, str)

    def test_same_password_different_hash_each_call(self):
        """PBKDF2 uses a random salt — hashes must differ"""
        h1 = hash_password("securepass")
        h2 = hash_password("securepass")
        if _USE_PBKDF2:
            assert h1 != h2, "PBKDF2 hashes should differ due to random salt"

    def test_hash_contains_salt_if_pbkdf2(self):
        """PBKDF2 format: salt_hex:key_hex"""
        h = hash_password("securepass")
        if _USE_PBKDF2:
            assert ":" in h, "PBKDF2 hash should be 'salt:key' format"


class TestVerifyPassword:
    def test_correct_default_password_accepted(self):
        assert verify_password("alice", "alice123") is True

    def test_wrong_password_rejected(self):
        assert verify_password("alice", "wrongpassword") is False

    def test_nonexistent_user_rejected(self):
        assert verify_password("nobody", "anypassword") is False

    def test_empty_password_rejected(self):
        assert verify_password("alice", "") is False

    def test_bob_default_password_works(self):
        assert verify_password("bob", "bob123") is True

    def test_case_sensitive_password(self):
        assert verify_password("alice", "Alice123") is False


class TestCreateUser:
    def test_create_new_user_succeeds(self):
        ok = create_user("charlie", "charlie_pass", starting_balance=500)
        assert ok is True

    def test_created_user_can_login(self):
        create_user("charlie", "charlie_pass")
        assert verify_password("charlie", "charlie_pass") is True

    def test_duplicate_user_fails(self):
        ok = create_user("alice", "new_password")
        assert ok is False

    def test_new_user_has_correct_balance(self):
        create_user("dave", "pass", starting_balance=2500)
        assert get_balance("dave") == 2500


class TestGetBalance:
    def test_alice_starting_balance(self):
        assert get_balance("alice") == 5000

    def test_bob_starting_balance(self):
        assert get_balance("bob") == 3000

    def test_nonexistent_user_returns_none(self):
        assert get_balance("ghost") is None


class TestTransfer:
    def test_successful_transfer(self):
        ok, msg = transfer("alice", "bob", 100)
        assert ok is True
        assert get_balance("alice") == 4900
        assert get_balance("bob") == 3100

    def test_transfer_balance_conservation(self):
        """Total credits must be conserved"""
        total_before = get_balance("alice") + get_balance("bob")
        transfer("alice", "bob", 500)
        total_after = get_balance("alice") + get_balance("bob")
        assert total_before == total_after

    def test_insufficient_balance_rejected(self):
        ok, msg = transfer("alice", "bob", 999999)
        assert ok is False

    def test_zero_amount_rejected(self):
        ok, _ = transfer("alice", "bob", 0)
        assert ok is False

    def test_negative_amount_rejected(self):
        ok, _ = transfer("alice", "bob", -100)
        assert ok is False

    def test_nonexistent_sender_rejected(self):
        ok, _ = transfer("ghost", "bob", 100)
        assert ok is False

    def test_nonexistent_recipient_rejected(self):
        ok, _ = transfer("alice", "ghost", 100)
        assert ok is False


class TestChangePassword:
    def test_change_password_allows_new_login(self):
        change_user_password("alice", "new_secure_pass")
        assert verify_password("alice", "new_secure_pass") is True

    def test_old_password_rejected_after_change(self):
        change_user_password("alice", "new_secure_pass")
        assert verify_password("alice", "alice123") is False
