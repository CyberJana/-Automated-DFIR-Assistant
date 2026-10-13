"""Optional AI-written narrative, restricted to a LOCAL model.

Policy enforced in code:
  * Evidence is never sent to a public or remote AI service. The endpoint must resolve to a loopback
    host (127.0.0.1, localhost, ::1); anything else is refused before any data leaves the process.
  * Proxies and redirects are disabled for the request, so the data cannot be forwarded elsewhere.
  * Every AI line must cite evidence IDs ([E-000123]) that belong to the finding it describes.
    Uncited, mis-cited or invented-citation lines are dropped. The deterministic findings never depend on AI.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from urllib.parse import urlparse

from .models import Finding

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
CITATION_RE = re.compile(r"\[(E-\d{6})\]")
MAX_PROMPT_EVIDENCE = 15
MAX_LINE_CHARS = 300
MAX_LINES_PER_FINDING = 3

Generate = Callable[[str], str]


def validate_local_endpoint(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError(f"invalid AI endpoint: {url!r}")
    if host not in LOOPBACK_HOSTS:
        raise ValueError(
            f"refusing AI endpoint host {host!r}: evidence may only be sent to a loopback (local) model"
        )
    return url


def build_prompt(finding: Finding) -> str:
    evidence_lines = [f"[{e.ref}] {e.raw[:MAX_LINE_CHARS]}" for e in finding.evidence[:MAX_PROMPT_EVIDENCE]]
    return (
        "You are assisting a digital forensics analyst. Use ONLY the log evidence below. Do not invent facts.\n"
        f"Finding {finding.finding_id} ({finding.severity}, rule {finding.rule_id}): {finding.title}\n"
        f"Deterministic description: {finding.description}\n"
        f"Write at most {MAX_LINES_PER_FINDING} short sentences: why this is suspicious, and what the analyst "
        "should check next. Every sentence MUST cite the evidence ID(s) it relies on in square brackets, "
        "for example [E-000004].\n\n"
        "Evidence:\n" + "\n".join(evidence_lines) + "\n"
    )


def keep_cited_lines(text: str, finding: Finding) -> list[str]:
    allowed = set(finding.evidence_refs)
    kept: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("-*• ").strip()
        if not line:
            continue
        cited = CITATION_RE.findall(line)
        if cited and all(ref in allowed for ref in cited):
            kept.append(line)
    return kept[:MAX_LINES_PER_FINDING]


def summarize_findings(findings: list[Finding], generate: Generate) -> tuple[dict[str, list[str]], list[str]]:
    """Return (cited lines per finding ID, error messages). Failures leave the finding with no AI text."""
    summaries: dict[str, list[str]] = {}
    errors: list[str] = []
    for finding in findings:
        try:
            summaries[finding.finding_id] = keep_cited_lines(generate(build_prompt(finding)), finding)
        except (OSError, ValueError, KeyError) as exc:
            summaries[finding.finding_id] = []
            errors.append(f"{finding.finding_id}: {exc}")
    return summaries, errors


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class OllamaClient:
    """Minimal client for a local Ollama-compatible /api/generate endpoint."""

    def __init__(self, endpoint: str, model: str, timeout: float = 120.0) -> None:
        self.endpoint = validate_local_endpoint(endpoint)
        self.model = model
        self.timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def generate(self, prompt: str) -> str:
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode()
        request = urllib.request.Request(
            self.endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except urllib.error.URLError as exc:
            raise OSError(f"local model unreachable: {exc.reason}") from exc
        return str(payload.get("response", ""))
