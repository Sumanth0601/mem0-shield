from __future__ import annotations

from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class ShieldConfig(BaseSettings):
    """
    Configuration for mem0shield.

    All settings can be overridden via environment variables prefixed with
    MEM0SHIELD_. For example:
        MEM0SHIELD_MODE=strict
        MEM0SHIELD_ENABLE_LLM_CLASSIFIER=true
    """

    # ── Enforcement mode ──────────────────────────────────────────────────────
    # strict → block and raise MemoryPoisonAttempt on any detected threat
    # warn   → log a warning but allow the add() through
    # audit  → allow through, attach shield metadata for post-retrieval audit
    mode: Literal["strict", "warn", "audit"] = "warn"

    # ── Defence toggles ───────────────────────────────────────────────────────
    enable_injection_scan: bool = True
    enable_contradiction_detection: bool = True
    enable_identity_guard: bool = True
    enable_flood_throttle: bool = True

    # ── Flood throttle ────────────────────────────────────────────────────────
    max_adds_per_minute: int = 30
    # Cosine similarity above which two messages are considered near-duplicates
    flood_dedup_threshold: float = 0.92
    # Max number of near-duplicate memories before flagging
    max_similar_memories: int = 5

    # ── Contradiction detection ───────────────────────────────────────────────
    # Cosine similarity above which two memories are considered on the same topic
    contradiction_similarity_threshold: float = 0.85
    # How many contradictions in a time window triggers a flood flag
    contradiction_flood_threshold: int = 6
    contradiction_window_seconds: int = 60

    # ── LLM classifier (optional) ─────────────────────────────────────────────
    # When enabled, ambiguous inputs (injection confidence 0.3–0.7) are sent
    # to the LLM for a second opinion.
    use_llm_classifier: bool = False
    llm_model: str = "gpt-4o-mini"

    # ── Confidence thresholds ─────────────────────────────────────────────────
    # Overall pipeline confidence above which strict/warn modes activate
    block_threshold: float = 0.8
    # Confidence floor for a single scan result to be considered a "hit"
    scan_hit_threshold: float = 0.3

    model_config = SettingsConfigDict(env_prefix="MEM0SHIELD_")
