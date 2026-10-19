"""ALPHA: Basic password security utilities."""

import hashlib
import hmac
import secrets


def validate_password(password: str) -> bool:
    """Check a basic password policy."""
    if not isinstance(password, str):
        return False

    return (
        len(password) >= 12
        and any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
    )


def hash_password(password: str) -> tuple[str, str]:
    """Hash a password with a random salt using PBKDF2-HMAC-SHA256."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000,
    )

    return salt.hex(), digest.hex()


def verify_password(
    password: str,
    salt_hex: str,
    expected_hash_hex: str,
) -> bool:
    """Verify a password against its stored salt and hash."""
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(expected_hash_hex)
    except (ValueError, TypeError):
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000,
    )

    return hmac.compare_digest(digest, expected_hash)


if __name__ == "__main__":
    password = input("Enter a test password: ")

    if validate_password(password):
        salt, password_hash = hash_password(password)

        print("Password policy: passed")
        print("Salt:", salt)
        print("Password hash:", password_hash)
    else:
        print("Use at least 12 characters, including uppercase,")
        print("lowercase letters and a number.")
