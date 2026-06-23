"""
Identity Guard — Step 3 of the mem0shield pipeline.

Detects:
- Claims to be a different user than user_id ("I am user X" when user_id != X)
- Role/privilege escalation ("I have admin access", "my access level is root")
- Injection of false system identity into user content
"""

from __future__ import annotations

import re
import logging
from typing import Optional

from mem0shield.models import ScanResult, ThreatType
from mem0shield.config import ShieldConfig

logger = logging.getLogger(__name__)


# ── Pattern sets ──────────────────────────────────────────────────────────────

# Claims of being another user / system identity
_IDENTITY_CLAIM_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r"\buser_id\s*[=:]\s*\S+", re.I), 0.90,
     "Explicit user_id claim in message content"),
    (re.compile(r"\bmy\s+(account|user)\s+(is|id\s+is|name\s+is)\s+\S+", re.I), 0.85,
     "Account identity claim"),
    (re.compile(r"I\s+am\s+(user|account)\s*[:#]?\s*\S+", re.I), 0.87,
     "User identity claim: 'I am user X'"),
]

# Role / privilege escalation
_ESCALATION_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r"\b(I\s+am|I'm)\s+(an?\s+)?(admin|administrator|root|superuser|system\s+user)\b", re.I),
     0.93, "Admin/root identity claim"),
    (re.compile(r"\bI\s+have\s+(admin|root|full|elevated|system)\s+(access|permissions?|rights?|privileges?)\b",
                re.I), 0.91, "Privilege escalation claim"),
    (re.compile(r"\bmy\s+access\s+level\s+is\s+(admin|root|elevated|superuser|god|full)\b", re.I),
     0.92, "Access level claim"),
    (re.compile(r"\bas\s+(an?\s+)?(admin|administrator|root|superuser)\b[,\s]+", re.I),
     0.88, "Role assertion: 'as an admin'"),
    (re.compile(r"\bwith\s+(my\s+)?(admin|root|system)\s+(access|privileges?|permissions?)\b", re.I),
     0.87, "Implicit privilege claim"),
]

# Privileged role words — used for cross-reference checks
_PRIVILEGED_ROLES = frozenset({
    "admin", "administrator", "root", "superuser", "system",
    "operator", "moderator", "god", "owner",
})


def _extract_text(messages: list[dict]) -> str:
    parts: list[str] = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    parts.append(part.get("text", ""))
    return " ".join(parts)


def _extract_claimed_user(text: str) -> Optional[str]:
    """Try to extract the user name/id being claimed in the message."""
    # Pattern: user_id=X or user_id: X
    m = re.search(r"user_id\s*[=:]\s*(\S+)", text, re.I)
    if m:
        return m.group(1).strip("\"'")

    # Pattern: I am user X / my account is X
    m = re.search(r"(?:I\s+am\s+user\s+|my\s+account\s+is\s+)(\S+)", text, re.I)
    if m:
        return m.group(1).strip("\"'.,;")

    return None


class IdentityGuard:
    """
    Guards against identity spoofing and privilege escalation attempts
    embedded in the message content being stored.
    """

    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        self._config = config or ShieldConfig()

    def scan(self, messages: list[dict], user_id: str) -> ScanResult:
        text = _extract_text(messages)

        # 1. Check for explicit user_id mismatches
        result = self._check_identity_mismatch(text, user_id)
        if not result.passed:
            return result

        # 2. Check for role escalation
        result = self._check_escalation(text)
        if not result.passed:
            return result

        return ScanResult(
            passed=True,
            confidence=0.0,
            reason="No identity or privilege escalation detected",
            raw_input=text,
            flagged_by="IdentityGuard",
        )

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_identity_mismatch(self, text: str, user_id: str) -> ScanResult:
        for pattern, confidence, reason in _IDENTITY_CLAIM_PATTERNS:
            if pattern.search(text):
                claimed = _extract_claimed_user(text)
                if claimed and claimed.lower() != user_id.lower():
                    return ScanResult(
                        passed=False,
                        threat_type=ThreatType.IDENTITY_SPOOFING,
                        confidence=confidence,
                        reason=(
                            f"{reason} — claimed='{claimed}', actual user_id='{user_id}'"
                        ),
                        raw_input=text,
                        flagged_by="IdentityGuard.identity_mismatch",
                    )
                elif claimed is None:
                    # Pattern matched but couldn't extract claimed user — medium confidence
                    return ScanResult(
                        passed=False,
                        threat_type=ThreatType.IDENTITY_SPOOFING,
                        confidence=confidence * 0.7,
                        reason=f"{reason} (user_id unresolvable)",
                        raw_input=text,
                        flagged_by="IdentityGuard.identity_mismatch",
                    )

        return ScanResult(
            passed=True,
            confidence=0.0,
            reason="No identity mismatch",
            raw_input=text,
            flagged_by="IdentityGuard",
        )

    def _check_escalation(self, text: str) -> ScanResult:
        best_confidence = 0.0
        best_reason = ""

        for pattern, confidence, reason in _ESCALATION_PATTERNS:
            if pattern.search(text):
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_reason = reason

        if best_confidence >= self._config.scan_hit_threshold:
            return ScanResult(
                passed=False,
                threat_type=ThreatType.IDENTITY_SPOOFING,
                confidence=best_confidence,
                reason=best_reason,
                raw_input=text,
                flagged_by="IdentityGuard.escalation",
            )

        return ScanResult(
            passed=True,
            confidence=0.0,
            reason="No escalation detected",
            raw_input=text,
            flagged_by="IdentityGuard",
        )
