"""
ALPHA Account Verification System

Provides a basic verification-request workflow.
A blue badge must only be granted after server-side review.
"""

from dataclasses import dataclass
from enum import Enum


class VerificationStatus(str, Enum):
    NOT_VERIFIED = "not_verified"
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


@dataclass
class CreatorAccount:
    user_id: str
    display_name: str
    is_public_figure: bool = False
    identity_confirmed: bool = False
    status: VerificationStatus = VerificationStatus.NOT_VERIFIED


def submit_verification_request(
    account: CreatorAccount,
) -> str:
    """Submit an account for verification review."""

    if not account.user_id or not account.display_name.strip():
        raise ValueError("Valid account information is required.")

    if account.status == VerificationStatus.VERIFIED:
        return "This account is already verified."

    if account.status == VerificationStatus.PENDING:
        return "A verification request is already pending."

    account.status = VerificationStatus.PENDING
    return "Verification request submitted for review."


def approve_verification(
    account: CreatorAccount,
    reviewer_authorized: bool = False,
) -> str:
    """
    Approve verification only after authorized review.

    In production, reviewer authorization and account data
    must be checked securely on the server.
    """

    if not reviewer_authorized:
        return "Permission denied: authorized reviewer required."

    if account.status != VerificationStatus.PENDING:
        return "No pending verification request."

    if not account.is_public_figure or not account.identity_confirmed:
        return "Eligibility and identity checks are required."

    account.status = VerificationStatus.VERIFIED
    return "Account verified successfully."


def get_badge(account: CreatorAccount) -> str:
    """Return the badge displayed beside the account name."""

    if account.status == VerificationStatus.VERIFIED:
        return "🔵✓"

    return ""


if __name__ == "__main__":
    creator = CreatorAccount(
        user_id="creator-001",
        display_name="Example Creator",
        is_public_figure=True,
        identity_confirmed=True,
    )

    print(submit_verification_request(creator))

    print(
        approve_verification(
            creator,
            reviewer_authorized=True,
        )
    )

    print("Badge:", get_badge(creator))
