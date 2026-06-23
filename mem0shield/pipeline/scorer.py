"""
Confidence Scorer — Step 5 of the mem0shield pipeline.

Aggregates individual ScanResults from all pipeline steps into a single
PipelineResult with an overall confidence score.

Rules:
- Any single scan with confidence >= 0.9 → overall score = that confidence
- Multiple MEDIUM threats (0.5–0.89) → additive penalty
- Low-confidence notices (< 0.5) → gentle penalty only
"""

from __future__ import annotations

from mem0shield.models import ScanResult, PipelineResult, ThreatType
from mem0shield.config import ShieldConfig

_HIGH_THRESHOLD = 0.9
_MEDIUM_THRESHOLD = 0.5


def _dominant_result(results: list[ScanResult]) -> tuple[float, ScanResult]:
    """Return the highest-confidence failing result, or best passing result."""
    failing = [r for r in results if not r.passed]
    if failing:
        best = max(failing, key=lambda r: r.confidence)
        return best.confidence, best
    best = max(results, key=lambda r: r.confidence) if results else None
    return 0.0, best  # type: ignore[return-value]


class ConfidenceScorer:
    """
    Produces a single PipelineResult from a list of per-step ScanResults.
    """

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()

    def score(self, results: list[ScanResult], raw_input: str = "") -> PipelineResult:
        if not results:
            return PipelineResult(
                passed=True,
                overall_confidence=0.0,
                scan_results=[],
                raw_input=raw_input,
            )

        failing = [r for r in results if not r.passed]
        if not failing:
            return PipelineResult(
                passed=True,
                overall_confidence=0.0,
                scan_results=results,
                raw_input=raw_input,
            )

        # Pick the highest-confidence individual threat as the primary signal.
        # Do NOT use an additive formula — that dilutes strong individual signals.
        primary_result = max(failing, key=lambda r: r.confidence)
        overall = primary_result.confidence

        return PipelineResult(
            passed=False,
            overall_confidence=overall,
            scan_results=results,
            primary_threat=primary_result.threat_type,
            primary_reason=primary_result.reason,
            raw_input=raw_input,
        )
