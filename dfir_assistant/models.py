"""Core data structures shared by parsers, detections, IOC extraction and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Event:
    """One normalised log record.

    `ref` (for example ``E-000012``) is the citation ID that findings, IOCs and the
    timeline use to point back at this exact line.
    """

    kind: str
    source_type: str
    source_file: str
    line_no: int
    raw: str
    timestamp: datetime | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    ref: str = ""

    @property
    def location(self) -> str:
        return f"{self.source_file}:{self.line_no}"


@dataclass
class Finding:
    """A rule hit. `evidence` is never empty: a finding without evidence is not allowed."""

    rule_id: str
    title: str
    severity: str
    description: str
    entity: str | None
    evidence: list[Event]
    finding_id: str = ""

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError(f"{self.rule_id} finding has no supporting evidence")

    @property
    def first_seen(self) -> datetime | None:
        stamps = [e.timestamp for e in self.evidence if e.timestamp is not None]
        return min(stamps) if stamps else None

    @property
    def last_seen(self) -> datetime | None:
        stamps = [e.timestamp for e in self.evidence if e.timestamp is not None]
        return max(stamps) if stamps else None

    @property
    def evidence_refs(self) -> list[str]:
        return [e.ref for e in self.evidence]
