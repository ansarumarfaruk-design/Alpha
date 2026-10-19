"""
ALPHA Input Validation
Validates basic user input before processing.
"""

import re


def validate_username(username: str) -> bool:
    """Allow 3–24 ASCII letters, digits, and underscores."""

    if not isinstance(username, str):
        return False

    return bool(
        re.fullmatch(r"[A-Za-z0-9_]{3,24}", username)
    )


def validate_email(email: str) -> bool:
    """Perform basic email-format validation."""

    if not isinstance(email, str) or len(email) > 254:
        return False

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(re.fullmatch(pattern, email))


def validate_post(content: str) -> bool:
    """Check that a post contains 1–5000 characters."""

    if not isinstance(content, str):
        return False

    content = content.strip()

    return 1 <= len(content) <= 5000


def validate_comment(content: str) -> bool:
    """Check that a comment contains 1–1000 characters."""

    if not isinstance(content, str):
        return False

    content = content.strip()

    return 1 <= len(content) <= 1000


if __name__ == "__main__":
    print("ALPHA Input Validator")
    print("---------------------")

    username = "AlphaCreator"
    email = "creator@example.com"
    post = "Welcome to ALPHA!"

    print("Username valid:", validate_username(username))
    print("Email format valid:", validate_email(email))
    print("Post valid:", validate_post(post))
