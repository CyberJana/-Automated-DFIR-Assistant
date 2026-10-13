"""Investigation report (Markdown) plus machine-readable outputs.

Every finding section lists the evidence IDs (E-xxxxxx) and the file:line source references it rests on,
so each conclusion can be traced back to the raw log line.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .analyzer import AnalysisResult
from .models import EPOCH, SEVERITY_ORDER, Event, Finding
from .timeline import write_timeline_csv

MAX_EXCERPTS_PER_FINDING = 10
MAX_REFS_IN_TABLE = 5
MAX_SUMMARY_FINDINGS = 10


def _ts(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "unknown"


def _cell(text: object) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def _event_summary(event: Event) -> str:
    parts = [event.kind]
    if event.user:
        parts.append(f"user={event.user}")
    if event.src_ip:
        parts.append(f"src={event.src_ip}")
    if event.fields.get("path"):
        parts.append(f"path={event.fields['path']}")
    return " ".join(parts)


def _refs_text(refs: list[str]) -> str:
    if len(refs) <= MAX_REFS_IN_TABLE:
        return ", ".join(refs)
    return ", ".join(refs[:MAX_REFS_IN_TABLE]) + f" (+{len(refs) - MAX_REFS_IN_TABLE} more)"


def _finding_heading(finding: Finding) -> str:
    return f"### {finding.finding_id} · {finding.severity.upper()} · {finding.title}"


def _render_finding(finding: Finding, ai_lines: list[str] | None) -> list[str]:
    out = [
        _finding_heading(finding),
        "",
        f"- **Rule:** {finding.rule_id}",
        f"- **Entity:** {finding.entity or 'n/a'}",
        f"- **Window (UTC):** {_ts(finding.first_seen)} → {_ts(finding.last_seen)}",
        f"- **Why it was flagged:** {finding.description}",
        f"- **Evidence IDs:** {', '.join(finding.evidence_refs)}",
        "- **Source references:** " + ", ".join(f"`{e.location}`" for e in finding.evidence[:MAX_EXCERPTS_PER_FINDING])
        + (" …" if len(finding.evidence) > MAX_EXCERPTS_PER_FINDING else ""),
        "",
        "Log excerpts (verbatim):",
        "",
        "```text",
    ]
    for event in finding.evidence[:MAX_EXCERPTS_PER_FINDING]:
        out.append(f"[{event.ref}] {event.raw}")
    if len(finding.evidence) > MAX_EXCERPTS_PER_FINDING:
        out.append(f"... {len(finding.evidence) - MAX_EXCERPTS_PER_FINDING} more; see findings.json")
    out += ["```", ""]

    if ai_lines is not None:
        out.append("**AI-assisted analysis** (local model; only lines citing this finding's evidence are kept):")
        out.append("")
        out += [f"- {line}" for line in ai_lines] if ai_lines else ["- _No cited AI analysis survived validation._"]
        out.append("")
    return out


def render_report(result: AnalysisResult, ai_summaries: dict[str, list[str]] | None = None) -> str:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in result.findings:
        counts[finding.severity] += 1
    skipped = sum(s.lines_skipped for s in result.sources)

    lines: list[str] = [
        "# DFIR Investigation Report",
        "",
        f"- **Generated (UTC):** {result.generated_utc.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Events normalised:** {len(result.events)} · **Findings:** {len(result.findings)} · "
        f"**Indicators:** {len(result.indicators)} · **Lines skipped:** {skipped}",
        f"- **Timezone and year:** all times are UTC. Syslog lines carry no year, so {result.syslog_year} was used.",
        "- **Method:** deterministic rules and IOC patterns. Each conclusion cites evidence IDs (`E-xxxxxx`) that "
        "map to the source file and line in `timeline.csv` and `findings.json`.",
        "",
        "## 1. Sources and chain of custody",
        "",
        "| File | SHA-256 | Format | Lines | Parsed | Skipped |",
        "|---|---|---|---|---|---|",
    ]
    for src in result.sources:
        lines.append(f"| `{_cell(src.path)}` | `{src.sha256}` | {src.format} | {src.lines_total} | "
                     f"{src.lines_parsed} | {src.lines_skipped} |")

    lines += ["", "## 2. Executive summary", ""]
    lines.append("Findings by severity: " + ", ".join(f"{sev} {n}" for sev, n in counts.items()) + ".")
    lines.append("")
    if not result.findings:
        lines.append("No rule-based findings were raised on the supplied logs.")
    for finding in result.findings[:MAX_SUMMARY_FINDINGS]:
        lines.append(f"- **{finding.finding_id}** ({finding.severity.upper()}) {finding.title}. "
                     f"Evidence: {_refs_text(finding.evidence_refs)}")
    if len(result.findings) > MAX_SUMMARY_FINDINGS:
        lines.append(f"- … {len(result.findings) - MAX_SUMMARY_FINDINGS} more; see section 3.")

    lines += ["", "## 3. Findings", ""]
    if not result.findings:
        lines.append("_None._")
    for finding in result.findings:
        ai_lines = None if ai_summaries is None else ai_summaries.get(finding.finding_id, [])
        lines += _render_finding(finding, ai_lines)

    lines += ["## 4. Indicators of compromise", "",
              "Values are defanged for safe sharing. Internal = private or loopback address.", "",
              "| Type | Value (defanged) | Internal | Evidence |", "|---|---|---|---|"]
    for ioc in result.indicators:
        internal = "yes" if ioc.internal else ""
        lines.append(f"| {ioc.ioc_type} | `{_cell(ioc.defanged)}` | {internal} | {_refs_text(ioc.evidence_refs)} |")
    if not result.indicators:
        lines.append("| - | _none found_ | | |")

    by_event = result.findings_by_event()
    linked = sorted({e.ref: e for f in result.findings for e in f.evidence}.values(),
                    key=lambda e: (e.timestamp is None, e.timestamp or EPOCH, e.source_file, e.line_no))
    lines += ["", "## 5. Timeline of finding-linked events", "",
              f"{len(linked)} of {len(result.events)} events are shown. The full timeline is in `timeline.csv`.", "",
              "| UTC time | Evidence | Finding(s) | Event | Source |", "|---|---|---|---|---|"]
    for event in linked:
        lines.append(f"| {_ts(event.timestamp)} | {event.ref} | {', '.join(by_event.get(event.ref, []))} | "
                     f"{_cell(_event_summary(event))} | `{_cell(event.location)}` |")

    lines += ["", "## 6. Limitations", "",
              "- Rules are heuristics. A match is a lead for analyst review, not proof of compromise.",
              "- Only the supplied files were analysed. Missing logs can hide activity.",
              "- Lines the parser could not read are counted in section 1 and are not analysed.",
              "- IOCs are pulled from every field of each line, including user-agents and referers. Review "
              "them before blocking anything.",
              "- AI text, when present, is advisory. It is kept only when every sentence cites valid evidence.", ""]
    return "\n".join(lines)


def write_outputs(result: AnalysisResult, out_dir: Path, ai_summaries: dict[str, list[str]] | None = None) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.md"
    timeline_path = out_dir / "timeline.csv"
    iocs_path = out_dir / "iocs.csv"
    findings_path = out_dir / "findings.json"

    report_path.write_text(render_report(result, ai_summaries), encoding="utf-8")
    write_timeline_csv(result.events, result.findings_by_event(), timeline_path)

    with iocs_path.open("w", encoding="utf-8", newline="") as fh:
        fh.write("type,value_defanged,internal,evidence_ids\n")
        for ioc in result.indicators:
            row = [ioc.ioc_type, ioc.defanged, "yes" if ioc.internal else "no", " ".join(ioc.evidence_refs)]
            fh.write(",".join('"' + c.replace('"', '""') + '"' for c in row) + "\n")

    payload = {
        "generated_utc": result.generated_utc.isoformat(),
        "sources": [vars(s) for s in result.sources],
        "findings": [
            {
                "id": f.finding_id,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "entity": f.entity,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
                "evidence": [
                    {"ref": e.ref, "location": e.location, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                     "kind": e.kind, "raw": e.raw}
                    for e in f.evidence
                ],
                "ai_summary": (ai_summaries or {}).get(f.finding_id) if ai_summaries is not None else None,
            }
            for f in result.findings
        ],
        "indicators": [
            {"type": i.ioc_type, "value": i.value, "defanged": i.defanged, "internal": i.internal,
             "evidence_ids": i.evidence_refs}
            for i in result.indicators
        ],
    }
    findings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return [report_path, timeline_path, iocs_path, findings_path]
