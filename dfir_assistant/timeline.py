"""Timeline export. Events are sorted by UTC time; each row keeps its evidence ID and source reference."""

from __future__ import annotations

import csv
from pathlib import Path

from .detections import sort_events
from .models import Event

COLUMNS = [
    "timestamp_utc", "evidence_id", "source_type", "host", "kind", "user", "src_ip",
    "finding_ids", "source_file", "line_no", "raw",
]
FORMULA_PREFIXES = ("=", "+", "-", "@")


def csv_safe(value: object) -> str:
    """Neutralise spreadsheet formula injection: raw log text can start with '=' or '+'."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def timeline_rows(events: list[Event], findings_by_event: dict[str, list[str]]) -> list[list[str]]:
    rows = []
    for event in sort_events(events):
        stamp = event.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if event.timestamp else ""
        rows.append([
            stamp, event.ref, event.source_type, event.host or "", event.kind, event.user or "",
            event.src_ip or "", " ".join(findings_by_event.get(event.ref, [])),
            event.source_file, str(event.line_no), event.raw,
        ])
    return rows


def write_timeline_csv(events: list[Event], findings_by_event: dict[str, list[str]], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLUMNS)
        for row in timeline_rows(events, findings_by_event):
            writer.writerow([csv_safe(cell) for cell in row])
