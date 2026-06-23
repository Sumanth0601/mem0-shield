"""
conftest.py — shared fixtures for mem0shield tests.

Uses mem0's in-memory vector store (Qdrant in-memory mode) so no API keys
or external services are required.
"""

from __future__ import annotations

import os
import pytest

# Force mem0 to use the in-memory vector store (no Qdrant server needed)
os.environ.setdefault("MEM0_VECTOR_STORE", "memory")
# Disable OpenAI calls for embeddings in mem0 unless explicitly set
os.environ.setdefault("MEM0SHIELD_USE_LLM_CLASSIFIER", "false")


def _make_mem0_config() -> dict:
    """
    Minimal mem0 config that works without any API keys.
    Uses Qdrant in-memory + a local embedding model.
    """
    return {
        "vector_store": {
            "provider": "qdrant",
            "config": {
                "collection_name": "test_memories",
                "embedding_model_dims": 384,
                "on_disk": False,
            },
        },
        "embedder": {
            "provider": "huggingface",
            "config": {"model": "multi-qa-MiniLM-L6-cos-v1"},
        },
        "llm": {
            "provider": "openai",
            "config": {
                "model": "gpt-4o-mini",
                "api_key": os.environ.get("OPENAI_API_KEY", "sk-test-dummy"),
            },
        },
    }


@pytest.fixture
def mem0_config() -> dict:
    return _make_mem0_config()


@pytest.fixture
def mock_memory():
    """
    A simple in-process mock memory backend that does NOT call any external
    services. Used for unit tests that only test the shield logic itself.
    """
    return MockMemory()


class MockMemory:
    """Minimal mock that mimics the mem0.Memory interface."""

    def __init__(self):
        self._store: dict[str, list[dict]] = {}
        self._id_counter = 0

    def add(self, messages: list[dict], user_id: str, **kwargs) -> dict:
        texts = [m.get("content", "") for m in messages if isinstance(m.get("content"), str)]
        text = " ".join(texts)
        self._id_counter += 1
        memory = {
            "id": f"mem_{self._id_counter}",
            "memory": text,
            "user_id": user_id,
            "metadata": kwargs.get("metadata", {}),
        }
        self._store.setdefault(user_id, []).append(memory)
        return {"results": [memory]}

    def search(self, query: str, user_id: str, limit: int = 10, **kwargs) -> dict:
        memories = self._store.get(user_id, [])
        # Simple substring match for tests
        results = [
            m for m in memories
            if any(word.lower() in m["memory"].lower()
                   for word in query.lower().split()[:3])
        ] or memories  # fall back to all if no match
        return {"results": results[:limit]}

    def get_all(self, user_id: str, **kwargs) -> dict:
        return {"results": self._store.get(user_id, [])}

    def delete(self, memory_id: str) -> None:
        for memories in self._store.values():
            memories[:] = [m for m in memories if m["id"] != memory_id]

    def delete_all(self, user_id: str, **kwargs) -> None:
        self._store.pop(user_id, None)

    def reset(self) -> None:
        self._store.clear()
        self._id_counter = 0
