from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mem0shield.models import ScanResult


class MemoryPoisonAttempt(Exception):
    """Base exception for all mem0shield threat detections."""

    def __init__(self, result: "ScanResult") -> None:
        self.result = result
        super().__init__(
            f"[mem0shield] Memory poison attempt detected "
            f"(threat={result.threat_type}, confidence={result.confidence:.2f}): "
            f"{result.reason}"
        )


class InjectionAttempt(MemoryPoisonAttempt):
    """Raised when a prompt injection pattern is detected in an add() call."""


class IdentityViolation(MemoryPoisonAttempt):
    """Raised when an identity spoofing or role escalation attempt is detected."""


class FloodAttempt(MemoryPoisonAttempt):
    """Raised when a rate-limit or near-duplicate flood is detected."""


class ContradictionFlood(MemoryPoisonAttempt):
    """Raised when contradictions are being added at an abnormally high rate."""


class TemporalFabrication(MemoryPoisonAttempt):
    """Raised when fabricated historical claims are detected."""
