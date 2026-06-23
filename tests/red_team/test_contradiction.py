"""
Red-team tests: Contradiction flood attacks.
"""

from __future__ import annotations

import pytest

from mem0shield import ShieldedMemory, ShieldConfig
from mem0shield.exceptions import ContradictionFlood


def _msg(text: str) -> list[dict]:
    return [{"role": "user", "content": text}]


def _shielded(mock_memory, threshold: int = 4) -> ShieldedMemory:
    return ShieldedMemory(
        mock_memory,
        config=ShieldConfig(
            mode="strict",
            enable_injection_scan=False,
            enable_identity_guard=False,
            enable_flood_throttle=False,
            enable_contradiction_detection=True,
            contradiction_flood_threshold=threshold,
            contradiction_window_seconds=120,
            # Lowered similarity threshold for test sentences
            contradiction_similarity_threshold=0.40,
            use_llm_classifier=False,
        ),
    )


class TestContradictionFlood:
    def test_single_contradiction_allowed(self, mock_memory):
        """A single contradiction (user changed their mind) must be allowed."""
        memory = _shielded(mock_memory)

        # Add initial preference
        memory.add(_msg("I love spicy food."), user_id="alice")

        # Single contradiction — legitimate preference change
        result = memory.add(_msg("I don't like spicy food anymore."), user_id="alice")
        assert result is not None
        print("\n[ALLOWED] Single contradiction — legitimate preference change")

    def test_contradiction_flood_blocked(self, mock_memory):
        """
        Sending many contradictions in a short window should be blocked
        once the threshold is exceeded.
        """
        memory = _shielded(mock_memory, threshold=4)

        # Seed a preference
        memory.add(_msg("I love spicy food."), user_id="bob")

        # Flood with contradictions
        blocked = False
        for i in range(10):
            try:
                if i % 2 == 0:
                    memory.add(_msg("I love spicy food, always have."), user_id="bob")
                else:
                    memory.add(_msg("I hate spicy food, never liked it."), user_id="bob")
            except ContradictionFlood as exc:
                blocked = True
                print(f"\n[BLOCKED at i={i}] {exc.result.reason}")
                break

        assert blocked, "Expected ContradictionFlood to be raised before 10 iterations"

    def test_contradictions_surfaced_in_retrieval(self, mock_memory):
        """
        Contradictory memories that did make it into the store should be
        surfaced with _shield_audit.has_contradiction = True in search results.
        """
        # Use warn mode so contradictions pass through
        memory = ShieldedMemory(
            mock_memory,
            config=ShieldConfig(
                mode="warn",
                enable_injection_scan=False,
                enable_identity_guard=False,
                enable_flood_throttle=False,
                enable_contradiction_detection=True,
                contradiction_similarity_threshold=0.40,
                use_llm_classifier=False,
            ),
        )

        memory.add(_msg("I love spicy food."), user_id="carol")
        memory.add(_msg("I hate spicy food and never eat it."), user_id="carol")

        results = memory.search("spicy food", user_id="carol")

        # At least some results should have audit metadata
        assert results, "Expected search results"
        audited = [r for r in results if "_shield_audit" in r]
        assert audited, "Expected at least one audited result"
        print(f"\n[AUDIT] {len(audited)} memories audited for contradictions")
