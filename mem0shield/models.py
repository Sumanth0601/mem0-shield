from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    FACT_INJECTION = "fact_injection"
    IDENTITY_SPOOFING = "identity_spoofing"
    CONTRADICTION_FLOOD = "contradiction_flood"
    MEMORY_FLOOD = "memory_flood"
    TEMPORAL_FABRICATION = "temporal_fabrication"


class ScanResult(BaseModel):
    passed: bool
    threat_type: Optional[ThreatType] = None
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    raw_input: str
    sanitized_input: Optional[str] = None
    # Extra metadata for contradiction/audit use
    contradicting_memories: list[str] = Field(default_factory=list)
    flagged_by: str = ""  # name of the pipeline step that flagged


class AuditResult(BaseModel):
    memory_id: str
    flagged_on_ingest: bool
    has_contradiction: bool
    contradicting_memories: list[str] = Field(default_factory=list)
    trust_score: float = Field(ge=0.0, le=1.0)


class PipelineResult(BaseModel):
    """Aggregated result of all pipeline steps for a single add() call."""
    passed: bool
    overall_confidence: float = Field(ge=0.0, le=1.0)
    scan_results: list[ScanResult] = Field(default_factory=list)
    primary_threat: Optional[ThreatType] = None
    primary_reason: str = ""
    raw_input: str = ""
