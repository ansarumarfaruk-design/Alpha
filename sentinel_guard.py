"""
SENTINEL GUARD
ALPHA Security Monitoring Prototype

Features:
- Security event monitoring
- Request rate limiting
- Suspicious activity detection
- Security audit logging
- Temporary client blocking
- Security statistics
- JSON report generation

Python: 3.10+
Standard library only.

IMPORTANT:
This is a demonstration module, not a complete production
security system. Integrate it with a trusted backend.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# =========================================================
# CONFIGURATION
# =========================================================

APP_NAME = "ALPHA"
ENGINE_NAME = "SENTINEL GUARD"
ENGINE_VERSION = "1.0.0"

MAX_REQUESTS = 60
REQUEST_WINDOW_SECONDS = 60

MAX_FAILED_LOGINS = 8
FAILED_LOGIN_WINDOW_SECONDS = 300

TEMP_BLOCK_SECONDS = 300

LOG_DIRECTORY = Path("sentinel_logs")
LOG_FILE = LOG_DIRECTORY / "security_events.jsonl"


# =========================================================
# TIME UTILITIES
# =========================================================

def utc_timestamp() -> str:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def monotonic_time() -> float:
    """Return a monotonic timestamp for time-window checks."""

    return time.monotonic()


# =========================================================
# DATA MODELS
# =========================================================

@dataclass
class SecurityEvent:
    event_id: str
    event_type: str
    timestamp: str
    severity: str
    client_id: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert event into a JSON-compatible dictionary."""

        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "client_id": self.client_id,
            "details": self.details,
        }


@dataclass
class ClientState:
    request_times: deque[float] = field(
        default_factory=deque
    )

    failed_login_times: deque[float] = field(
        default_factory=deque
    )

    blocked_until: float = 0.0

    total_requests: int = 0

    total_failed_logins: int = 0


# =========================================================
# SECURITY EVENT LOGGER
# =========================================================

class SecurityEventLogger:
    """
    Records security events.

    Never place passwords, authentication tokens, session
    cookies, or other credentials in event details.
    """

    ALLOWED_SEVERITIES = {
        "INFO",
        "WARNING",
        "HIGH",
        "CRITICAL",
    }

    def __init__(
        self,
        log_file: Path = LOG_FILE,
    ) -> None:

        self.log_file = log_file
        self.lock = threading.Lock()

        self.log_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.logger = logging.getLogger(
            f"sentinel.{id(self)}"
        )

        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        if not self.logger.handlers:
            handler = logging.FileHandler(
                self.log_file,
                encoding="utf-8",
            )

            handler.setFormatter(
                logging.Formatter("%(message)s")
            )

            self.logger.addHandler(handler)

    def record(
        self,
        event_type: str,
        client_id: str = "system",
        severity: str = "INFO",
        details: dict[str, Any] | None = None,
    ) -> SecurityEvent:

        if severity not in self.ALLOWED_SEVERITIES:
            raise ValueError("Invalid severity.")

        event = SecurityEvent(
            event_id=secrets.token_hex(12),
            event_type=event_type,
            timestamp=utc_timestamp(),
            severity=severity,
            client_id=client_id,
            details=details or {},
        )

        serialized = json.dumps(
            event.to_dict(),
            ensure_ascii=False,
        )

        with self.lock:
            self.logger.info(serialized)

        return event


# =========================================================
# INPUT VALIDATION
# =========================================================

class InputValidator:
    """Validate basic identifiers and request metadata."""

    CLIENT_ID_PATTERN = re.compile(
        r"^[A-Za-z0-9_.:-]{1,64}$"
    )

    EVENT_TYPE_PATTERN = re.compile(
        r"^[a-z][a-z0-9_]{1,63}$"
    )

    @classmethod
    def validate_client_id(
        cls,
        client_id: str,
    ) -> bool:

        if not isinstance(client_id, str):
            return False

        return bool(
            cls.CLIENT_ID_PATTERN.fullmatch(client_id)
        )

    @classmethod
    def validate_event_type(
        cls,
        event_type: str,
    ) -> bool:

        if not isinstance(event_type, str):
            return False

        return bool(
            cls.EVENT_TYPE_PATTERN.fullmatch(event_type)
        )

    @staticmethod
    def validate_method(method: str) -> bool:

        allowed_methods = {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
            "HEAD",
        }

        return (
            isinstance(method, str)
            and method.upper() in allowed_methods
        )


# =========================================================
# RATE LIMITING
# =========================================================

class RequestRateLimiter:
    """
    In-memory sliding-window request limiter.

    Suitable for demonstrations and single-process tests.
    Production deployments should use shared storage.
    """

    def __init__(
        self,
        max_requests: int = MAX_REQUESTS,
        window_seconds: int = REQUEST_WINDOW_SECONDS,
    ) -> None:

        if max_requests < 1:
            raise ValueError(
                "max_requests must be positive."
            )

        if window_seconds < 1:
            raise ValueError(
                "window_seconds must be positive."
            )

        self.max_requests = max_requests
        self.window_seconds = window_seconds

        self.requests: dict[str, deque[float]] = (
            defaultdict(deque)
        )

        self.lock = threading.Lock()

    def allow(
        self,
        client_id: str,
    ) -> bool:

        now = monotonic_time()
        cutoff = now - self.window_seconds

        with self.lock:
            timestamps = self.requests[client_id]

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                return False

            timestamps.append(now)
            return True

    def remaining(
        self,
        client_id: str,
    ) -> int:

        now = monotonic_time()
        cutoff = now - self.window_seconds

        with self.lock:
            timestamps = self.requests[client_id]

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            return max(
                0,
                self.max_requests - len(timestamps),
            )


# =========================================================
# FAILED LOGIN MONITOR
# =========================================================

class LoginAttemptMonitor:
    """
    Tracks failed login attempts for an identifier.

    In a real system, combine account-based and IP-based
    limits and use a proper authentication service.
    """

    def __init__(
        self,
        max_failures: int = MAX_FAILED_LOGINS,
        window_seconds: int = FAILED_LOGIN_WINDOW_SECONDS,
    ) -> None:

        self.max_failures = max_failures
        self.window_seconds = window_seconds

        self.failures: dict[str, deque[float]] = (
            defaultdict(deque)
        )

        self.lock = threading.Lock()

    def record_failure(
        self,
        account_key: str,
    ) -> int:

        now = monotonic_time()
        cutoff = now - self.window_seconds

        with self.lock:
            attempts = self.failures[account_key]

            while attempts and attempts[0] <= cutoff:
                attempts.popleft()

            attempts.append(now)

            return len(attempts)

    def clear(
        self,
        account_key: str,
    ) -> None:

        with self.lock:
            self.failures.pop(account_key, None)

    def is_limited(
        self,
        account_key: str,
    ) -> bool:

        now = monotonic_time()
        cutoff = now - self.window_seconds

        with self.lock:
            attempts = self.failures[account_key]

            while attempts and attempts[0] <= cutoff:
                attempts.popleft()

            return len(attempts) >= self.max_failures


# =========================================================
# TEMPORARY CLIENT BLOCKING
# =========================================================

class TemporaryBlockManager:
    """Manage temporary blocks in the current process."""

    def __init__(
        self,
        block_seconds: int = TEMP_BLOCK_SECONDS,
    ) -> None:

        self.block_seconds = block_seconds

        self.blocked_until: dict[str, float] = {}

        self.lock = threading.Lock()

    def block(
        self,
        client_id: str,
    ) -> None:

        with self.lock:
            self.blocked_until[client_id] = (
                monotonic_time() + self.block_seconds
            )

    def is_blocked(
        self,
        client_id: str,
    ) -> bool:

        now = monotonic_time()

        with self.lock:
            expiry = self.blocked_until.get(
                client_id,
                0.0,
            )

            if expiry <= now:
                self.blocked_until.pop(
                    client_id,
                    None,
                )

                return False

            return True

    def unblock(
        self,
        client_id: str,
    ) -> bool:

        with self.lock:
            return (
                self.blocked_until.pop(
                    client_id,
                    None,
                )
                is not None
            )


# =========================================================
# SECURITY ENGINE
# =========================================================

class SentinelGuard:
    """
    Main security monitoring controller.

    This component does not authenticate users itself.
    It provides monitoring and simple rate-limiting logic.
    """

    def __init__(self) -> None:

        self.events = SecurityEventLogger()

        self.rate_limiter = RequestRateLimiter()

        self.login_monitor = LoginAttemptMonitor()

        self.block_manager = TemporaryBlockManager()

        self.statistics: Counter[str] = Counter()

        self.lock = threading.Lock()

        self.events.record(
            event_type="security_engine_started",
            severity="INFO",
            details={
                "application": APP_NAME,
                "engine": ENGINE_NAME,
                "version": ENGINE_VERSION,
            },
        )

    def process_request(
        self,
        client_id: str,
        method: str = "GET",
    ) -> dict[str, Any]:

        if not InputValidator.validate_client_id(
            client_id
        ):

            self.events.record(
                event_type="invalid_client_identifier",
                severity="WARNING",
            )

            return {
                "allowed": False,
                "reason": "Invalid client identifier.",
            }

        if not InputValidator.validate_method(method):

            self.events.record(
                event_type="invalid_http_method",
                client_id=client_id,
                severity="WARNING",
            )

            return {
                "allowed": False,
                "reason": "Invalid HTTP method.",
            }

        if self.block_manager.is_blocked(client_id):

            self.events.record(
                event_type="blocked_client_request",
                client_id=client_id,
                severity="WARNING",
            )

            with self.lock:
                self.statistics["blocked_requests"] += 1

            return {
                "allowed": False,
                "reason": "Client temporarily blocked.",
            }

        if not self.rate_limiter.allow(client_id):

            self.events.record(
                event_type="request_rate_limit_exceeded",
                client_id=client_id,
                severity="HIGH",
            )

            with self.lock:
                self.statistics["rate_limited_requests"] += 1

            return {
                "allowed": False,
                "reason": "Request rate limit exceeded.",
            }

        with self.lock:
            self.statistics["allowed_requests"] += 1

        return {
            "allowed": True,
            "reason": "Request accepted by monitoring layer.",
            "remaining_requests": (
                self.rate_limiter.remaining(client_id)
            ),
        }

    def record_login_failure(
        self,
        account_key: str,
    ) -> dict[str, Any]:

        if not isinstance(account_key, str) or not account_key:
            return {
                "success": False,
                "reason": "Invalid account identifier.",
            }

        failures = self.login_monitor.record_failure(
            account_key
        )

        self.events.record(
            event_type="login_failure",
            client_id="account:" + account_key[:48],
            severity="WARNING",
            details={
                "recent_failure_count": failures,
            },
        )

        with self.lock:
            self.statistics["login_failures"] += 1

        limited = self.login_monitor.is_limited(
            account_key
        )

        if limited:

            self.events.record(
                event_type="login_attempts_limited",
                client_id="account:" + account_key[:48],
                severity="HIGH",
            )

        return {
            "success": True,
            "failure_count": failures,
            "limited": limited,
        }

    def record_login_success(
        self,
        account_key: str,
    ) -> None:

        self.login_monitor.clear(account_key)

        self.events.record(
            event_type="login_success",
            client_id="account:" + account_key[:48],
            severity="INFO",
        )

        with self.lock:
            self.statistics["login_successes"] += 1

    def block_client(
        self,
        client_id: str,
    ) -> None:

        if not InputValidator.validate_client_id(
            client_id
        ):
            raise ValueError("Invalid client identifier.")

        self.block_manager.block(client_id)

        self.events.record(
            event_type="client_temporarily_blocked",
            client_id=client_id,
            severity="HIGH",
        )

    def get_statistics(self) -> dict[str, int]:

        with self.lock:
            return dict(self.statistics)

    def generate_report(self) -> dict[str, Any]:

        return {
            "application": APP_NAME,
            "engine": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "generated_at": utc_timestamp(),
            "statistics": self.get_statistics(),
        }

    def save_report(
        self,
        destination: Path = Path("sentinel_report.json"),
    ) -> Path:

        report = self.generate_report()

        destination.write_text(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return destination


# =========================================================
# LOCAL DEMONSTRATION
# =========================================================

def run_demo() -> None:

    print("=" * 54)
    print(f"{APP_NAME} — {ENGINE_NAME}")
    print(f"Version: {ENGINE_VERSION}")
    print("=" * 54)

    guard = SentinelGuard()

    demo_client = "demo_user_001"

    print("\n[1] Normal request")

    result = guard.process_request(
        client_id=demo_client,
        method="GET",
    )

    print(json.dumps(result, indent=2))

    print("\n[2] Failed login monitoring")

    demo_account = "demo_account_001"

    for attempt in range(3):

        result = guard.record_login_failure(
            demo_account
        )

        print(
            f"Attempt {attempt + 1}: "
            f"{json.dumps(result)}"
        )

    print("\n[3] Temporary block demonstration")

    guard.block_client(demo_client)

    result = guard.process_request(
        client_id=demo_client,
        method="GET",
    )

    print(json.dumps(result, indent=2))

    print("\n[4] Security statistics")

    print(
        json.dumps(
            guard.get_statistics(),
            indent=2,
        )
    )

    print("\n[5] Export security report")

    report_path = guard.save_report()

    print(f"Report saved to: {report_path}")

    print("\nDemo complete.")


if __name__ == "__main__":
    run_demo()
