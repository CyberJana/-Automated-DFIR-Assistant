"""Log parsers. Each one turns a raw line into a normalised `Event` (or None if it does not match).

Supported formats:
  linux_auth     Linux syslog / auth.log lines (sshd and sudo are classified; others kept as linux.other)
  web_access     Apache / Nginx "combined" access logs
  windows_jsonl  Windows events as JSON lines, one flat object per line (see README for key names)
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Event

FORMATS = ("linux_auth", "web_access", "windows_jsonl")
SNIFF_LINES = 50

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<prog>[\w./-]+)(?:\[\d+\])?:\s(?P<msg>.*)$"
)
SSH_FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
SUDO_RE = re.compile(
    r"^(?P<user>\S+) : .*?PWD=(?P<pwd>\S+) ; USER=(?P<runas>\S+) ; COMMAND=(?P<cmd>.+)$"
)
WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

WIN_KINDS = {
    4624: "win.logon_success",
    4625: "win.logon_failure",
    4688: "win.process_create",
    4720: "win.user_created",
    4732: "win.group_member_added",
    7045: "win.service_installed",
    1102: "win.audit_log_cleared",
}


class UnknownFormatError(ValueError):
    """Raised when a file's format cannot be detected; pass --format explicitly."""


@dataclass
class ParseResult:
    format: str
    events: list[Event]
    lines_total: int
    lines_skipped: int


def _parse_syslog_ts(value: str, year: int) -> datetime | None:
    # Classic syslog timestamps have no year and no timezone; we assume UTC and the given year.
    try:
        return datetime.strptime(f"{year} {' '.join(value.split())}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_iso(value: object) -> datetime | None:
    if not value:
        return None
    # Windows exports often carry 7 fractional digits, which fromisoformat rejects on older Pythons.
    text = re.sub(r"(\.\d{6})\d+", r"\1", str(value)).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _clean_ip(value: object) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text if text and text not in {"-", "::"} else None


def parse_linux_auth(line: str, source: str, line_no: int, year: int) -> Event | None:
    match = SYSLOG_RE.match(line)
    if not match:
        return None
    base = {
        "source_type": "linux_auth",
        "source_file": source,
        "line_no": line_no,
        "raw": line,
        "timestamp": _parse_syslog_ts(match["ts"], year),
        "host": match["host"],
    }
    prog, msg = match["prog"], match["msg"]

    if prog == "sshd":
        if failed := SSH_FAILED_RE.search(msg):
            return Event(kind="ssh.failed_login", user=failed["user"], src_ip=failed["ip"],
                         fields={"method": failed["method"]}, **base)
        if accepted := SSH_ACCEPTED_RE.search(msg):
            return Event(kind="ssh.accepted_login", user=accepted["user"], src_ip=accepted["ip"],
                         fields={"method": accepted["method"]}, **base)
        if invalid := SSH_INVALID_RE.search(msg):
            return Event(kind="ssh.invalid_user", user=invalid["user"], src_ip=invalid["ip"], **base)

    if prog == "sudo" and (sudo := SUDO_RE.match(msg.strip())):
        return Event(kind="sudo.command", user=sudo["user"],
                     fields={"runas": sudo["runas"], "command": sudo["cmd"], "pwd": sudo["pwd"]},
                     **base)

    return Event(kind="linux.other", **base)


def parse_web_access(line: str, source: str, line_no: int, year: int) -> Event | None:
    match = WEB_RE.match(line)
    if not match:
        return None
    try:
        timestamp = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        timestamp = None
    return Event(
        kind="web.request",
        source_type="web_access",
        source_file=source,
        line_no=line_no,
        raw=line,
        timestamp=timestamp,
        src_ip=match["ip"],
        user=None if match["user"] == "-" else match["user"],
        fields={
            "method": match["method"],
            "path": match["path"],
            "status": int(match["status"]),
            "referer": match["referer"] or "",
            "ua": match["ua"] or "",
        },
    )


def parse_windows_jsonl(line: str, source: str, line_no: int, year: int) -> Event | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    try:
        event_id = int(obj.get("EventID", obj.get("event_id")))
    except (TypeError, ValueError):
        return None

    is_group_add = event_id == 4732
    user = obj.get("MemberName") if is_group_add else None
    if isinstance(user, str) and user.upper().startswith("CN="):
        user = user[3:].split(",", 1)[0]  # "CN=svc_backup,CN=Users,..." -> "svc_backup"
    user = user or obj.get("TargetUserName") or obj.get("SubjectUserName") or obj.get("user")
    group = obj.get("GroupName") or (obj.get("TargetUserName") if is_group_add else None)
    command = obj.get("CommandLine") or obj.get("ProcessCommandLine")
    return Event(
        kind=WIN_KINDS.get(event_id, "win.event"),
        source_type="windows_jsonl",
        source_file=source,
        line_no=line_no,
        raw=line,
        timestamp=_parse_iso(obj.get("TimeCreated") or obj.get("@timestamp") or obj.get("timestamp")),
        host=obj.get("Computer") or obj.get("host"),
        user=str(user) if user else None,
        src_ip=_clean_ip(obj.get("IpAddress") or obj.get("SourceIp")),
        fields={
            "event_id": event_id,
            "logon_type": str(obj["LogonType"]) if "LogonType" in obj else None,
            "command": command,
            "image": obj.get("NewProcessName") or obj.get("Image") or obj.get("ImagePath"),
            "group": group,
            "service": obj.get("ServiceName"),
        },
    )


_PARSERS: dict[str, Callable[[str, str, int, int], Event | None]] = {
    "linux_auth": parse_linux_auth,
    "web_access": parse_web_access,
    "windows_jsonl": parse_windows_jsonl,
}


def detect_format(sample: list[str]) -> str:
    for line in sample:
        if line.startswith("{"):
            return "windows_jsonl"
        if WEB_RE.match(line):
            return "web_access"
        if SYSLOG_RE.match(line):
            return "linux_auth"
    raise UnknownFormatError("could not detect log format; pass --format explicitly")


def parse_file(path: str | Path, fmt: str = "auto", year: int | None = None) -> ParseResult:
    path = Path(path)
    year = year or datetime.now(timezone.utc).year

    sample: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                sample.append(line.rstrip("\r\n"))
                if len(sample) >= SNIFF_LINES:
                    break
    chosen = detect_format(sample) if fmt == "auto" else fmt
    if chosen not in _PARSERS:
        raise UnknownFormatError(f"unsupported format: {chosen}")
    parser = _PARSERS[chosen]

    events: list[Event] = []
    total = skipped = 0
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            text = line.rstrip("\r\n")
            if not text.strip():
                continue
            total += 1
            event = parser(text, str(path), line_no, year)
            if event is None:
                skipped += 1
            else:
                events.append(event)
    return ParseResult(format=chosen, events=events, lines_total=total, lines_skipped=skipped)
