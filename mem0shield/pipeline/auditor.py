"""
Post-Retrieval Auditor — Steps 6–7 of the mem0shield pipeline.

After mem0.search() returns memories:
  Step 6 — Provenance Check: was this memory flagged at ingest time?
  Step 7 — Conflict Surfacer: highlight contradictory memories in the result set.
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from mem0shield.models import AuditResult
from mem0shield.config import ShieldConfig

logger = logging.getLogger(__name__)


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


class PostRetrievalAuditor:
    """
    Audits search results for provenance flags and contradictions.

    Returns the same memories with AuditResult metadata attached.
    Consumers can choose to filter or surface flagged memories.
    """

    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        self._config = config or ShieldConfig()
        self._model = None  # lazy-loaded

    def audit(
        self,
        search_results: list[dict] | dict,
        user_id: str,
    ) -> list[dict]:
        """
        Audit a list of memories returned by mem0.search().

        Returns the same list with an added `_shield_audit` key per memory.
        """
        if isinstance(search_results, dict):
            items = search_results.get("results", [])
        else:
            items = search_results or []

        if not items:
            return items

        texts = [self._get_memory_text(item) for item in items]

        # Step 7 — find contradictions within the result set itself
        contradiction_map = self._find_result_contradictions(texts)

        audited: list[dict] = []
        for i, item in enumerate(items):
            memory_id = item.get("id", f"mem_{i}") if isinstance(item, dict) else f"mem_{i}"
            flagged = self._was_flagged_on_ingest(item)
            contradicting = contradiction_map.get(i, [])

            trust_score = self._compute_trust(flagged, len(contradicting))

            audit = AuditResult(
                memory_id=str(memory_id),
                flagged_on_ingest=flagged,
                has_contradiction=bool(contradicting),
                contradicting_memories=contradicting,
                trust_score=trust_score,
            )

            entry = dict(item) if isinstance(item, dict) else {"memory": item}
            entry["_shield_audit"] = audit.model_dump()
            audited.append(entry)

        return audited

    # ── Internals ─────────────────────────────────────────────────────────────

    def _get_memory_text(self, item: dict | str) -> str:
        if isinstance(item, str):
            return item
        return item.get("memory", item.get("text", ""))

    def _was_flagged_on_ingest(self, item: dict | str) -> bool:
        """Check if the memory was flagged by mem0shield at ingest time."""
        if not isinstance(item, dict):
            return False
        metadata = item.get("metadata", {}) or {}
        shield_scan = metadata.get("shield_scan", {})
        if not shield_scan:
            return False
        # It was passed to add() with a shield_scan but still stored —
        # that means it had a non-zero confidence (warn/audit mode)
        return shield_scan.get("confidence", 0.0) > 0.0

    def _find_result_contradictions(
        self, texts: list[str]
    ) -> dict[int, list[str]]:
        """
        For each memory in the result set, find other memories in the same
        set that contradict it.

        Returns a mapping: index → list of contradicting memory texts.
        """
        if len(texts) < 2:
            return {}

        try:
            model = self._get_model()
            embeddings = [model.encode(t, convert_to_numpy=True) for t in texts]
        except Exception as exc:  # noqa: BLE001
            logger.warning("[mem0shield] Could not compute embeddings for audit: %s", exc)
            return {}

        result: dict[int, list[str]] = {}
        threshold = self._config.contradiction_similarity_threshold

        for i in range(len(texts)):
            for j in range(i + 1, len(texts)):
                sim = _cosine_similarity(embeddings[i], embeddings[j])
                if sim >= threshold:
                    if self._heuristic_contradiction(texts[i], texts[j]):
                        result.setdefault(i, []).append(texts[j])
                        result.setdefault(j, []).append(texts[i])

        return result

    @staticmethod
    def _heuristic_contradiction(a: str, b: str) -> bool:
        negation_words = {"not", "never", "don't", "doesn't", "hate", "dislike", "no", "none", "without"}
        positive_words = {"love", "like", "enjoy", "prefer", "want", "yes",
                          "allergic", "allergy", "confirmed", "diagnosed", "documented"}
        a_lower = a.lower()
        b_lower = b.lower()
        a_neg = any(w in a_lower for w in negation_words)
        b_neg = any(w in b_lower for w in negation_words)
        a_pos = any(w in a_lower for w in positive_words)
        b_pos = any(w in b_lower for w in positive_words)
        return (a_neg and b_pos) or (a_pos and b_neg)

    @staticmethod
    def _compute_trust(flagged_on_ingest: bool, num_contradictions: int) -> float:
        score = 1.0
        if flagged_on_ingest:
            score -= 0.4
        score -= min(0.1 * num_contradictions, 0.5)
        return max(round(score, 2), 0.0)

    def _get_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
        return self._model
