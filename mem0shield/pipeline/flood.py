"""
Flood Throttle — Step 4 of the mem0shield pipeline.

Two rules:
  1. Rate limit  — max N add() calls per user per 60-second window.
  2. Semantic dedup — cosine similarity >0.92 with recent messages → near-duplicate.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Optional

import numpy as np

from mem0shield.models import ScanResult, ThreatType
from mem0shield.config import ShieldConfig

logger = logging.getLogger(__name__)


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


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


class FloodThrottle:
    """
    In-memory per-user rate limiter and near-duplicate detector.

    State is ephemeral (process-lifetime). In a distributed deployment you
    would back this with Redis — this implementation is designed to be
    replaceable at the `_windows` / `_recent_embeddings` layer.
    """

    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        self._config = config or ShieldConfig()
        # Per-user sliding window of add() timestamps (last 60 s)
        self._windows: dict[str, deque] = defaultdict(lambda: deque())
        # Per-user list of recent embeddings (last max_similar_memories)
        self._recent_embeddings: dict[str, list[np.ndarray]] = defaultdict(list)
        self._model = None  # lazy-loaded

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, messages: list[dict], user_id: str) -> ScanResult:
        text = _extract_text(messages)

        # Rule 1 — rate limit
        rate_result = self._check_rate(user_id, text)
        if not rate_result.passed:
            return rate_result

        # Rule 2 — semantic dedup
        dedup_result = self._check_dedup(user_id, text)
        if not dedup_result.passed:
            return dedup_result

        # All checks passed — record this add() in the window
        self._record(user_id, text)

        return ScanResult(
            passed=True,
            confidence=0.0,
            reason="Rate and dedup checks passed",
            raw_input=text,
            flagged_by="FloodThrottle",
        )

    def reset(self, user_id: str) -> None:
        """Clear state for a user (useful for testing)."""
        self._windows.pop(user_id, None)
        self._recent_embeddings.pop(user_id, None)

    # ── Internal checks ───────────────────────────────────────────────────────

    def _check_rate(self, user_id: str, text: str) -> ScanResult:
        now = time.time()
        window = self._windows[user_id]
        # Expire entries older than 60 seconds
        while window and window[0] < now - 60:
            window.popleft()

        if len(window) >= self._config.max_adds_per_minute:
            confidence = min(0.85 + 0.01 * (len(window) - self._config.max_adds_per_minute), 1.0)
            return ScanResult(
                passed=False,
                threat_type=ThreatType.MEMORY_FLOOD,
                confidence=confidence,
                reason=(
                    f"Rate limit exceeded: {len(window)} add() calls in the last 60s "
                    f"(limit: {self._config.max_adds_per_minute})"
                ),
                raw_input=text,
                flagged_by="FloodThrottle.rate",
            )

        return ScanResult(
            passed=True, confidence=0.0, reason="Rate OK", raw_input=text,
            flagged_by="FloodThrottle",
        )

    def _check_dedup(self, user_id: str, text: str) -> ScanResult:
        recent = self._recent_embeddings[user_id]
        if not recent:
            return ScanResult(
                passed=True, confidence=0.0, reason="No recent embeddings to compare",
                raw_input=text, flagged_by="FloodThrottle",
            )

        model = self._get_model()
        new_emb = model.encode(text, convert_to_numpy=True)

        max_sim = 0.0
        for emb in recent:
            sim = _cosine_similarity(new_emb, emb)
            if sim > max_sim:
                max_sim = sim

        if max_sim >= self._config.flood_dedup_threshold:
            return ScanResult(
                passed=False,
                threat_type=ThreatType.MEMORY_FLOOD,
                confidence=min(max_sim, 1.0),
                reason=(
                    f"Near-duplicate detected: cosine similarity {max_sim:.3f} "
                    f"≥ threshold {self._config.flood_dedup_threshold}"
                ),
                raw_input=text,
                flagged_by="FloodThrottle.dedup",
            )

        return ScanResult(
            passed=True, confidence=0.0, reason="Dedup OK", raw_input=text,
            flagged_by="FloodThrottle",
        )

    def _record(self, user_id: str, text: str) -> None:
        """Record this add() in the rate window and embeddings cache."""
        self._windows[user_id].append(time.time())

        model = self._get_model()
        emb = model.encode(text, convert_to_numpy=True)
        recent = self._recent_embeddings[user_id]
        recent.append(emb)
        # Keep only the last max_similar_memories embeddings
        if len(recent) > self._config.max_similar_memories:
            recent.pop(0)

    def _get_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
        return self._model
