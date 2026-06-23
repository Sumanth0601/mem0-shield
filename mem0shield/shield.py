"""
ShieldedMemory / ShieldedMemoryClient — Phase 3: Main wrapper.

Drop-in replacements for mem0.Memory (OSS) and mem0.MemoryClient (Cloud).

Usage:
    from mem0 import Memory
    from mem0shield import ShieldedMemory, ShieldConfig

    memory = ShieldedMemory(Memory(), config=ShieldConfig(mode="strict"))
    memory.add(messages, user_id="alice")
    memory.search("what does alice prefer?", user_id="alice")
"""

from __future__ import annotations

import logging
from typing import Any

from mem0shield.config import ShieldConfig
from mem0shield.exceptions import (
    InjectionAttempt,
    IdentityViolation,
    FloodAttempt,
    ContradictionFlood,
    TemporalFabrication,
    MemoryPoisonAttempt,
)
from mem0shield.models import ThreatType, ScanResult, PipelineResult
from mem0shield.pipeline.injection import InjectionScanner
from mem0shield.pipeline.contradiction import ContradictionDetector
from mem0shield.pipeline.identity import IdentityGuard
from mem0shield.pipeline.flood import FloodThrottle
from mem0shield.pipeline.scorer import ConfidenceScorer
from mem0shield.pipeline.auditor import PostRetrievalAuditor

logger = logging.getLogger(__name__)


def _threat_exception(result: ScanResult) -> MemoryPoisonAttempt:
    """Map a ThreatType to the appropriate exception subclass."""
    mapping = {
        ThreatType.PROMPT_INJECTION: InjectionAttempt,
        ThreatType.FACT_INJECTION: InjectionAttempt,
        ThreatType.IDENTITY_SPOOFING: IdentityViolation,
        ThreatType.MEMORY_FLOOD: FloodAttempt,
        ThreatType.CONTRADICTION_FLOOD: ContradictionFlood,
        ThreatType.TEMPORAL_FABRICATION: TemporalFabrication,
    }
    exc_class = mapping.get(result.threat_type, MemoryPoisonAttempt)
    return exc_class(result)


class _Pipeline:
    """Orchestrates all pipeline steps for a single add() call."""

    def __init__(self, config: ShieldConfig, backend: Any) -> None:
        self._config = config
        self._backend = backend
        self._injection = InjectionScanner(config)
        self._contradiction = ContradictionDetector(config)
        self._identity = IdentityGuard(config)
        self._flood = FloodThrottle(config)
        self._scorer = ConfidenceScorer(config)

    def run(self, messages: list[dict], user_id: str) -> PipelineResult:
        scan_results: list[ScanResult] = []

        if self._config.enable_injection_scan:
            scan_results.append(self._injection.scan(messages, user_id))

        if self._config.enable_identity_guard:
            scan_results.append(self._identity.scan(messages, user_id))

        if self._config.enable_flood_throttle:
            scan_results.append(self._flood.scan(messages, user_id))

        if self._config.enable_contradiction_detection:
            # ContradictionDetector needs the backend to query existing memories
            scan_results.append(
                self._contradiction.scan(messages, user_id, backend=self._backend)
            )

        raw = " ".join(
            m.get("content", "") for m in messages if isinstance(m.get("content"), str)
        )
        return self._scorer.score(scan_results, raw_input=raw)


class ShieldedMemory:
    """
    Drop-in wrapper around ``mem0.Memory`` (OSS local instance).

    All ``add()`` calls are passed through the mem0shield defence pipeline
    before reaching the underlying memory store. All ``search()`` results
    are post-audited before being returned to the caller.
    """

    def __init__(self, backend: Any, config: ShieldConfig | None = None) -> None:
        self._backend = backend
        self._config = config or ShieldConfig()
        self._pipeline = _Pipeline(self._config, backend)
        self._auditor = PostRetrievalAuditor(self._config)

    # ── add() ─────────────────────────────────────────────────────────────────

    def add(self, messages: list[dict], user_id: str, **kwargs: Any) -> Any:
        pipeline_result = self._pipeline.run(messages, user_id)

        if not pipeline_result.passed:
            # Build a ScanResult to pass to the exception
            flagging_scan = next(
                (r for r in pipeline_result.scan_results if not r.passed),
                ScanResult(
                    passed=False,
                    threat_type=pipeline_result.primary_threat,
                    confidence=pipeline_result.overall_confidence,
                    reason=pipeline_result.primary_reason,
                    raw_input=pipeline_result.raw_input,
                ),
            )

            if self._config.mode == "strict":
                raise _threat_exception(flagging_scan)
            elif self._config.mode == "warn":
                logger.warning(
                    "[mem0shield] Suspicious input from user '%s' "
                    "(threat=%s, confidence=%.2f): %s",
                    user_id,
                    pipeline_result.primary_threat,
                    pipeline_result.overall_confidence,
                    pipeline_result.primary_reason,
                )

        # In audit mode, attach metadata so the memory is traceable
        if self._config.mode == "audit":
            metadata = kwargs.pop("metadata", {}) or {}
            metadata["shield_scan"] = {
                "passed": pipeline_result.passed,
                "confidence": pipeline_result.overall_confidence,
                "threat_type": pipeline_result.primary_threat,
                "reason": pipeline_result.primary_reason,
            }
            kwargs["metadata"] = metadata

        return self._backend.add(messages, user_id=user_id, **kwargs)

    # ── search() ──────────────────────────────────────────────────────────────

    def search(self, query: str, user_id: str, **kwargs: Any) -> list[dict]:
        results = self._backend.search(query, user_id=user_id, **kwargs)
        return self._auditor.audit(results, user_id)

    # ── Passthrough ───────────────────────────────────────────────────────────

    def get_all(self, user_id: str, **kwargs: Any) -> Any:
        return self._backend.get_all(user_id=user_id, **kwargs)

    def delete(self, memory_id: str) -> Any:
        return self._backend.delete(memory_id)

    def delete_all(self, user_id: str, **kwargs: Any) -> Any:
        return self._backend.delete_all(user_id=user_id, **kwargs)

    def update(self, memory_id: str, data: str) -> Any:
        return self._backend.update(memory_id, data)

    def history(self, memory_id: str) -> Any:
        return self._backend.history(memory_id)

    def reset(self) -> Any:
        return self._backend.reset()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def config(self) -> ShieldConfig:
        return self._config

    @property
    def pipeline(self) -> _Pipeline:
        return self._pipeline


class ShieldedMemoryClient(ShieldedMemory):
    """
    Drop-in wrapper around ``mem0.MemoryClient`` (Mem0 Cloud API).

    Identical interface to ``ShieldedMemory`` — just accepts a
    ``MemoryClient`` instance instead of ``Memory``.
    """
    # The parent class handles both backends identically via duck-typing.
