"""
Contradiction Detector — Step 2 of the mem0shield pipeline.

Algorithm:
1. Embed the incoming message with sentence-transformers.
2. Retrieve top-k existing memories via mem0.search().
3. For each retrieved memory with high topic similarity, ask the LLM
   whether they contradict each other.
4. Track per-user contradiction counts in a sliding time window.
5. Flag CONTRADICTION_FLOOD when the rate exceeds config threshold.
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


class ContradictionDetector:
    """
    Detects when new messages contradict existing memories, and specifically
    when contradictions are being added at an adversarially high rate.
    """

    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        self._config = config or ShieldConfig()
        self._model = None  # lazy-loaded sentence-transformer
        self._llm_client: Optional[object] = None  # lazy-loaded openai
        # Per-user sliding windows of contradiction timestamps
        self._contradiction_windows: dict[str, deque] = defaultdict(
            lambda: deque()
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(
        self,
        messages: list[dict],
        user_id: str,
        backend=None,  # mem0.Memory or mem0.MemoryClient instance
    ) -> ScanResult:
        text = _extract_text(messages)

        if backend is None:
            # Cannot check contradictions without access to existing memories
            return ScanResult(
                passed=True,
                confidence=0.0,
                reason="No backend provided — contradiction check skipped",
                raw_input=text,
                flagged_by="ContradictionDetector",
            )

        try:
            existing = self._fetch_existing(backend, text, user_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[mem0shield] Could not fetch existing memories: %s", exc)
            return ScanResult(
                passed=True,
                confidence=0.0,
                reason="Memory fetch failed — contradiction check skipped",
                raw_input=text,
                flagged_by="ContradictionDetector",
            )

        if not existing:
            return ScanResult(
                passed=True,
                confidence=0.0,
                reason="No existing memories to compare against",
                raw_input=text,
                flagged_by="ContradictionDetector",
            )

        contradictions = self._find_contradictions(text, existing)
        if not contradictions:
            return ScanResult(
                passed=True,
                confidence=0.0,
                reason="No contradictions detected",
                raw_input=text,
                flagged_by="ContradictionDetector",
            )

        # Record contradiction in the sliding window
        now = time.time()
        window = self._contradiction_windows[user_id]
        # Expire old entries
        cutoff = now - self._config.contradiction_window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        window.append(now)

        flood_count = len(window)
        threshold = self._config.contradiction_flood_threshold

        if flood_count >= threshold:
            confidence = min(0.7 + 0.03 * (flood_count - threshold), 1.0)
            return ScanResult(
                passed=False,
                threat_type=ThreatType.CONTRADICTION_FLOOD,
                confidence=confidence,
                reason=(
                    f"Contradiction flood detected: {flood_count} contradictions "
                    f"in the last {self._config.contradiction_window_seconds}s "
                    f"(threshold: {threshold})"
                ),
                raw_input=text,
                contradicting_memories=contradictions,
                flagged_by="ContradictionDetector",
            )

        # Single contradiction — likely legitimate preference change; just note it
        return ScanResult(
            passed=True,
            confidence=0.1 * len(contradictions),
            reason=(
                f"Contradiction noted ({len(contradictions)} found) but below flood threshold "
                f"({flood_count}/{threshold})"
            ),
            raw_input=text,
            contradicting_memories=contradictions,
            flagged_by="ContradictionDetector",
        )

    # ── Internals ─────────────────────────────────────────────────────────────

    def _fetch_existing(self, backend, text: str, user_id: str) -> list[str]:
        """Retrieve up to 10 existing memories for this user."""
        result = backend.search(text, user_id=user_id, limit=10)
        memories: list[str] = []

        # mem0 returns a dict with a "results" key, or a list directly
        if isinstance(result, dict):
            items = result.get("results", [])
        else:
            items = result or []

        for item in items:
            if isinstance(item, dict):
                mem = item.get("memory", item.get("text", ""))
            else:
                mem = str(item)
            if mem:
                memories.append(mem)

        return memories

    def _find_contradictions(
        self, new_text: str, existing: list[str]
    ) -> list[str]:
        """Return list of existing memory texts that contradict new_text."""
        model = self._get_model()
        new_emb = model.encode(new_text, convert_to_numpy=True)
        contradictions: list[str] = []

        for memory in existing:
            mem_emb = model.encode(memory, convert_to_numpy=True)
            sim = _cosine_similarity(new_emb, mem_emb)

            if sim >= self._config.contradiction_similarity_threshold:
                # Same topic — check if they actually contradict
                if self._are_contradictory(new_text, memory):
                    contradictions.append(memory)

        return contradictions

    def _are_contradictory(self, a: str, b: str) -> bool:
        """Ask the LLM whether statements A and B contradict each other."""
        if not self._config.use_llm_classifier:
            # Fallback heuristic: look for opposite polarity keywords
            return self._heuristic_contradiction(a, b)

        try:
            client = self._get_llm_client()
            response = client.chat.completions.create(
                model=self._config.llm_model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a fact-checking assistant. "
                            "Given two statements A and B, decide if they logically contradict "
                            "each other. Reply with exactly YES or NO."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"A: {a}\nB: {b}",
                    },
                ],
                max_tokens=5,
                temperature=0,
            )
            answer = response.choices[0].message.content.strip().upper()
            return answer.startswith("YES")
        except Exception as exc:  # noqa: BLE001
            logger.warning("[mem0shield] LLM contradiction check failed: %s", exc)
            return self._heuristic_contradiction(a, b)

    @staticmethod
    def _heuristic_contradiction(a: str, b: str) -> bool:
        """
        Lightweight heuristic: detects polarity reversal.
        Handles both preference language (love/hate) and factual negation
        ("no allergies" vs "allergic", "not X" vs "is X").
        """
        negation_words = {"not", "never", "don't", "doesn't", "hate", "dislike", "no", "none", "without"}
        positive_words = {"love", "like", "enjoy", "prefer", "want", "yes",
                          "allergic", "allergy", "confirmed", "diagnosed", "documented"}

        a_lower = a.lower()
        b_lower = b.lower()

        a_neg = any(w in a_lower for w in negation_words)
        b_neg = any(w in b_lower for w in negation_words)
        a_pos = any(w in a_lower for w in positive_words)
        b_pos = any(w in b_lower for w in positive_words)

        # One has strong negative signal, other has strong positive signal
        return (a_neg and b_pos) or (a_pos and b_neg)

    def _get_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
        return self._model

    def _get_llm_client(self):
        if self._llm_client is None:
            import openai  # noqa: PLC0415
            self._llm_client = openai.OpenAI()
        return self._llm_client
