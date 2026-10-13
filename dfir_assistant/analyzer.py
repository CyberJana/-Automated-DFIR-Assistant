"""Pipeline: parse every input, assign citation IDs, run detections, extract IOCs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .detections import run_detections
from .ioc import Indicator, extract_indicators
from .models import SEVERITY_ORDER, EPOCH, Event, Finding
from .parsers import parse_file


@dataclass
class SourceInfo:
    path: str
    sha256: str
    format: str
    lines_total: int
    lines_parsed: int
    lines_skipped: int


@dataclass
class AnalysisResult:
    sources: list[SourceInfo]
    events: list[Event]
    findings: list[Finding]
    indicators: list[Indicator]
    syslog_year: int
    generated_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def findings_by_event(self) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for finding in self.findings:
            for event in finding.evidence:
                mapping.setdefault(event.ref, []).append(finding.finding_id)
        return mapping


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze(paths: list[str | Path], fmt: str = "auto", year: int | None = None) -> AnalysisResult:
    year = year or datetime.now(timezone.utc).year
    sources: list[SourceInfo] = []
    events: list[Event] = []
    for path in paths:
        parsed = parse_file(path, fmt=fmt, year=year)
        sources.append(SourceInfo(
            path=str(path),
            sha256=sha256_file(Path(path)),
            format=parsed.format,
            lines_total=parsed.lines_total,
            lines_parsed=len(parsed.events),
            lines_skipped=parsed.lines_skipped,
        ))
        events.extend(parsed.events)

    for number, event in enumerate(events, 1):
        event.ref = f"E-{number:06d}"

    findings = run_detections(events)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen or EPOCH, f.rule_id, f.entity or ""))
    for number, finding in enumerate(findings, 1):
        finding.finding_id = f"F-{number:03d}"

    return AnalysisResult(
        sources=sources,
        events=events,
        findings=findings,
        indicators=extract_indicators(events),
        syslog_year=year,
    )
