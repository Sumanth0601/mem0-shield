"""
Red-team tests: Memory flood attacks (rate limiting and near-duplicate detection).
"""

from __future__ import annotations

import time

import pytest

from mem0shield import ShieldedMemory, ShieldConfig
from mem0shield.exceptions import FloodAttempt


def _msg(text: str) -> list[dict]:
    return [{"role": "user", "content": text}]


def _shielded(mock_memory, max_per_minute: int = 5, dedup_threshold: float = 0.92) -> ShieldedMemory:
    return ShieldedMemory(
        mock_memory,
        config=ShieldConfig(
            mode="strict",
            enable_injection_scan=False,
            enable_identity_guard=False,
            enable_flood_throttle=True,
            enable_contradiction_detection=False,
            max_adds_per_minute=max_per_minute,
            flood_dedup_threshold=dedup_threshold,
            max_similar_memories=5,
        ),
    )


class TestRateLimit:
    def test_rate_limit_enforced(self, mock_memory):
        """After max_adds_per_minute, further adds should be blocked."""
        memory = _shielded(mock_memory, max_per_minute=5)
        blocked = False

        for i in range(10):
            try:
                memory.add(_msg(f"My favourite number is {i}."), user_id="alice")
            except FloodAttempt as exc:
                blocked = True
                print(f"\n[BLOCKED at i={i}] {exc.result.reason}")
                break

        assert blocked, "Expected FloodAttempt to be raised after rate limit"

    def test_different_users_independent_windows(self, mock_memory):
        """Rate limit windows are per-user, not global."""
        memory = _shielded(mock_memory, max_per_minute=3)

        # Fill alice's window — semantically diverse so dedup doesn't trigger
        alice_facts = [
            "My name is Alice and I live in Berlin.",
            "I work as a surgeon at the city hospital.",
            "My favourite food is sushi.",
        ]
        for fact in alice_facts:
            memory.add(_msg(fact), user_id="alice")

        # bob should still work fine (independent window)
        result = memory.add(_msg("Bob fact: I enjoy hiking on weekends."), user_id="bob")
        assert result is not None
        print("\n[ALLOWED] bob's window is independent of alice's")


class TestNearDuplicateBlocked:
    def test_near_duplicate_blocked(self, mock_memory):
        """Nearly identical messages should be blocked after the first one."""
        memory = _shielded(mock_memory, dedup_threshold=0.92)

        memory.add(_msg("I love eating pizza for dinner."), user_id="alice")

        blocked = False
        for _ in range(5):
            try:
                memory.add(_msg("I love eating pizza for dinner."), user_id="alice")
            except FloodAttempt as exc:
                blocked = True
                print(f"\n[BLOCKED] {exc.result.reason} (confidence={exc.result.confidence:.3f})")
                break

        assert blocked, "Expected FloodAttempt for exact duplicate"

    def test_semantically_similar_blocked(self, mock_memory):
        """Very similar but not identical messages should also be blocked."""
        memory = _shielded(mock_memory, dedup_threshold=0.92)

        memory.add(_msg("I enjoy pizza for dinner every night."), user_id="alice")

        blocked = False
        for _ in range(5):
            try:
                memory.add(_msg("I enjoy pizza for dinner every night."), user_id="alice")
            except FloodAttempt:
                blocked = True
                break

        assert blocked, "Expected FloodAttempt for near-duplicate"


class TestLegitimateAllowed:
    def test_legitimate_burst_allowed(self, mock_memory):
        """
        An onboarding flow may legitimately send several distinct memories in
        quick succession. These should pass as long as they are semantically
        different and under the rate limit.
        """
        # Higher rate limit to simulate onboarding
        memory = _shielded(mock_memory, max_per_minute=20)

        onboarding_facts = [
            "My name is Alice.",
            "I live in San Francisco.",
            "I prefer vegetarian meals.",
            "I speak English and Spanish.",
            "I work as a software engineer.",
            "I enjoy hiking and photography.",
            "My timezone is America/Los_Angeles.",
            "I prefer dark mode in all apps.",
            "I have a cat named Luna.",
            "My favourite music genre is jazz.",
        ]

        for fact in onboarding_facts:
            result = memory.add(_msg(fact), user_id="alice")
            assert result is not None

        print(f"\n[ALLOWED] Onboarding burst of {len(onboarding_facts)} distinct facts")
