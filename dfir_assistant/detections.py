"""Rule-based detections. Every rule returns findings that cite the exact events that triggered them."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import timedelta
from pathlib import PurePosixPath
from urllib.parse import unquote_plus

from .models import EPOCH, Event, Finding

RuleFn = Callable[[list[Event]], list[Finding]]

BRUTE_WINDOW = timedelta(minutes=10)
BRUTE_THRESHOLD = 5
SUCCESS_LOOKBACK = timedelta(minutes=30)
SUCCESS_MIN_FAILURES = 3
WEB_404_WINDOW = timedelta(minutes=5)
WEB_404_THRESHOLD = 20
WIN_FAIL_WINDOW = timedelta(minutes=10)
WIN_FAIL_THRESHOLD = 5

SHELL_NAMES = {"sh", "bash", "zsh", "dash", "ksh", "su"}
INJECTION_PATTERNS = {
    "sql_injection": re.compile(
        r"union(\s|\+)+select|'\s*or\s+'?1'?\s*=\s*'?1|\bsleep\s*\(|information_schema|\bxp_cmdshell\b", re.I
    ),
    "xss": re.compile(r"<script|onerror\s*=|onload\s*=|javascript:", re.I),
    "path_traversal": re.compile(r"\.\.[/\\]|%2e%2e", re.I),
    "command_injection": re.compile(
        r";\s*(cat|id|whoami|uname|wget|curl)\b|\|\s*(sh|bash)\b|\$\([^)]*\)", re.I
    ),
    "local_file_inclusion": re.compile(r"/etc/(passwd|shadow)\b|c:\\windows", re.I),
}
SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wfuzz|feroxbuster|acunetix|nessus|zgrab|w3af", re.I
)
WIN_SUSPICIOUS_COMMANDS = {
    "encoded_powershell": re.compile(r"-enc\w*\s+[A-Za-z0-9+/=]{20,}", re.I),
    "download_cradle": re.compile(
        r"downloadstring|downloadfile|invoke-webrequest|net\.webclient|bitsadmin.*/transfer|certutil.*-urlcache",
        re.I,
    ),
    "invoke_expression": re.compile(r"\biex\b|invoke-expression", re.I),
    "lolbin_script": re.compile(r"mshta(\.exe)?\s+(https?:|javascript:)|rundll32(\.exe)?\s+.*javascript:", re.I),
}


# Explicit internal ranges. Python's ipaddress also flags the RFC 5737 documentation ranges as private,
# which would hide the attacker addresses used in the samples, so those are deliberately treated as external.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in INTERNAL_NETWORKS)


def sort_events(events: Iterable[Event]) -> list[Event]:
    return sorted(events, key=lambda e: (e.timestamp is None, e.timestamp or EPOCH, e.source_file, e.line_no))


def _kind(events: list[Event], *kinds: str) -> list[Event]:
    return [e for e in events if e.kind in kinds]


def group_by(events: Iterable[Event], key: Callable[[Event], str | None]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        value = key(event)
        if value:
            groups[value].append(event)
    return groups


def find_bursts(events: Iterable[Event], window: timedelta, threshold: int) -> list[list[Event]]:
    """Return non-overlapping runs of >= `threshold` events that fall inside a `window`-long span."""
    ordered = sort_events(e for e in events if e.timestamp is not None)
    bursts: list[list[Event]] = []
    i = 0
    while i < len(ordered):
        j = i
        while j < len(ordered) and ordered[j].timestamp - ordered[i].timestamp <= window:
            j += 1
        if j - i >= threshold:
            bursts.append(ordered[i:j])
            i = j
        else:
            i += 1
    return bursts


def _decoded(path: str) -> str:
    # Attackers often double-encode payloads, so decode twice.
    return unquote_plus(unquote_plus(path))


def _minutes(delta: timedelta) -> int:
    return int(delta.total_seconds() // 60)


# ---------------------------------------------------------------- Linux / SSH and sudo

def rule_ssh_bruteforce(events: list[Event]) -> list[Finding]:
    findings = []
    failed = _kind(events, "ssh.failed_login")
    for ip, group in group_by(failed, lambda e: e.src_ip).items():
        for burst in find_bursts(group, BRUTE_WINDOW, BRUTE_THRESHOLD):
            users = ", ".join(sorted({e.user for e in burst if e.user}))
            findings.append(Finding(
                rule_id="R-SSH-001",
                title=f"SSH brute-force from {ip}",
                severity="high",
                description=(f"{len(burst)} failed SSH logins within {_minutes(BRUTE_WINDOW)} minutes. "
                             f"Usernames tried: {users}."),
                entity=ip,
                evidence=burst,
            ))
    return findings


def rule_ssh_success_after_failures(events: list[Event]) -> list[Finding]:
    failures = [e for e in _kind(events, "ssh.failed_login") if e.timestamp and e.src_ip]
    findings = []
    for ok in _kind(events, "ssh.accepted_login"):
        if ok.timestamp is None or not ok.src_ip:
            continue
        prior = [f for f in failures
                 if f.src_ip == ok.src_ip and ok.timestamp - SUCCESS_LOOKBACK <= f.timestamp <= ok.timestamp]
        if len(prior) >= SUCCESS_MIN_FAILURES:
            findings.append(Finding(
                rule_id="R-SSH-002",
                title=f"Successful SSH login for '{ok.user}' from {ok.src_ip} after {len(prior)} failures",
                severity="high",
                description=(f"Login succeeded within {_minutes(SUCCESS_LOOKBACK)} minutes of {len(prior)} failed "
                             "attempts from the same source. This pattern often indicates a password was guessed."),
                entity=ok.src_ip,
                evidence=prior + [ok],
            ))
    return findings


def rule_ssh_root_login(events: list[Event]) -> list[Finding]:
    return [
        Finding(
            rule_id="R-SSH-003",
            title=f"Direct root login over SSH from {e.src_ip}",
            severity="high",
            description="root authenticated directly over SSH; direct root login should normally be disabled.",
            entity=e.src_ip,
            evidence=[e],
        )
        for e in _kind(events, "ssh.accepted_login")
        if e.user == "root"
    ]


def rule_ssh_user_enumeration(events: list[Event]) -> list[Finding]:
    findings = []
    invalid = _kind(events, "ssh.invalid_user")
    for ip, group in group_by(invalid, lambda e: e.src_ip).items():
        for burst in find_bursts(group, BRUTE_WINDOW, BRUTE_THRESHOLD):
            names = ", ".join(sorted({e.user for e in burst if e.user}))
            findings.append(Finding(
                rule_id="R-SSH-004",
                title=f"Username enumeration over SSH from {ip}",
                severity="medium",
                description=f"{len(burst)} attempts for non-existent users within {_minutes(BRUTE_WINDOW)} minutes: {names}.",
                entity=ip,
                evidence=burst,
            ))
    return findings


def rule_sudo_shell(events: list[Event]) -> list[Finding]:
    findings = []
    for e in _kind(events, "sudo.command"):
        parts = e.fields.get("command", "").split()
        if not parts or PurePosixPath(parts[0]).name not in SHELL_NAMES:
            continue
        findings.append(Finding(
            rule_id="R-SUDO-001",
            title=f"Interactive shell via sudo by '{e.user}'",
            severity="medium",
            description=f"sudo was used to start '{parts[0]}' as {e.fields.get('runas')}.",
            entity=e.user,
            evidence=[e],
        ))
    return findings


# ---------------------------------------------------------------- Web access

def rule_web_injection(events: list[Event]) -> list[Finding]:
    hits: dict[str, list[Event]] = defaultdict(list)
    categories: dict[str, set[str]] = defaultdict(set)
    for e in _kind(events, "web.request"):
        if not e.src_ip:
            continue
        text = _decoded(e.fields["path"])
        matched = {name for name, pattern in INJECTION_PATTERNS.items() if pattern.search(text)}
        if matched:
            hits[e.src_ip].append(e)
            categories[e.src_ip].update(matched)
    return [
        Finding(
            rule_id="R-WEB-001",
            title=f"Web attack payloads from {ip} ({', '.join(sorted(categories[ip]))})",
            severity="high",
            description=f"{len(evts)} request(s) contain attack payload patterns in the URL.",
            entity=ip,
            evidence=evts,
        )
        for ip, evts in hits.items()
    ]


def rule_web_scanner_ua(events: list[Event]) -> list[Finding]:
    scanners = [e for e in _kind(events, "web.request") if SCANNER_UA.search(e.fields.get("ua", ""))]
    return [
        Finding(
            rule_id="R-WEB-002",
            title=f"Security scanner user-agent from {ip}",
            severity="medium",
            description=f"{len(evts)} request(s) used a known offensive-tool user-agent.",
            entity=ip,
            evidence=evts,
        )
        for ip, evts in group_by(scanners, lambda e: e.src_ip).items()
    ]


def rule_web_404_flood(events: list[Event]) -> list[Finding]:
    not_found = [e for e in _kind(events, "web.request") if e.fields.get("status") == 404]
    findings = []
    for ip, group in group_by(not_found, lambda e: e.src_ip).items():
        for burst in find_bursts(group, WEB_404_WINDOW, WEB_404_THRESHOLD):
            findings.append(Finding(
                rule_id="R-WEB-003",
                title=f"404 flood from {ip}",
                severity="medium",
                description=f"{len(burst)} HTTP 404 responses within {_minutes(WEB_404_WINDOW)} minutes; "
                            "typical of directory or endpoint enumeration.",
                entity=ip,
                evidence=burst,
            ))
    return findings


# ---------------------------------------------------------------- Windows events

def rule_win_failed_logon_burst(events: list[Event]) -> list[Finding]:
    failures = _kind(events, "win.logon_failure")
    findings = []
    for key, group in group_by(failures, lambda e: e.src_ip or e.user).items():
        for burst in find_bursts(group, WIN_FAIL_WINDOW, WIN_FAIL_THRESHOLD):
            findings.append(Finding(
                rule_id="R-WIN-001",
                title=f"Windows failed-logon burst for {key}",
                severity="high",
                description=f"{len(burst)} failed logons (event 4625) within {_minutes(WIN_FAIL_WINDOW)} minutes.",
                entity=key,
                evidence=burst,
            ))
    return findings


def rule_win_rdp_from_public_ip(events: list[Event]) -> list[Finding]:
    return [
        Finding(
            rule_id="R-WIN-002",
            title=f"RDP logon for '{e.user}' from public IP {e.src_ip}",
            severity="medium",
            description="Interactive remote logon (type 10) from a non-private address.",
            entity=e.src_ip,
            evidence=[e],
        )
        for e in _kind(events, "win.logon_success")
        if str(e.fields.get("logon_type")) == "10" and e.src_ip and not is_private_ip(e.src_ip)
    ]


def rule_win_suspicious_process(events: list[Event]) -> list[Finding]:
    findings = []
    for e in _kind(events, "win.process_create"):
        command = e.fields.get("command") or ""
        categories = [name for name, pattern in WIN_SUSPICIOUS_COMMANDS.items() if pattern.search(command)]
        if categories:
            findings.append(Finding(
                rule_id="R-WIN-003",
                title=f"Suspicious process command on {e.host or 'host'} ({', '.join(categories)})",
                severity="high",
                description="Process command line matches obfuscated or download-and-execute patterns.",
                entity=e.host,
                evidence=[e],
            ))
    return findings


def rule_win_admin_group_add(events: list[Event]) -> list[Finding]:
    return [
        Finding(
            rule_id="R-WIN-004",
            title=f"'{e.user}' added to group '{e.fields.get('group')}'",
            severity="high",
            description="Account added to a local administrators group (event 4732).",
            entity=e.user,
            evidence=[e],
        )
        for e in _kind(events, "win.group_member_added")
        if "administrators" in str(e.fields.get("group") or "").lower()
    ]


def rule_win_service_installed(events: list[Event]) -> list[Finding]:
    return [
        Finding(
            rule_id="R-WIN-005",
            title=f"New service '{e.fields.get('service')}' installed",
            severity="medium",
            description=f"Service installation (event 7045) with image {e.fields.get('image')}. "
                        "Verify the binary path and publisher.",
            entity=e.host,
            evidence=[e],
        )
        for e in _kind(events, "win.service_installed")
    ]


def rule_win_audit_log_cleared(events: list[Event]) -> list[Finding]:
    return [
        Finding(
            rule_id="R-WIN-006",
            title=f"Security audit log cleared on {e.host or 'host'}",
            severity="high",
            description="Event 1102: audit log was cleared, a common anti-forensics step.",
            entity=e.host,
            evidence=[e],
        )
        for e in _kind(events, "win.audit_log_cleared")
    ]


def rule_win_user_created(events: list[Event]) -> list[Finding]:
    return [
        Finding(
            rule_id="R-WIN-007",
            title=f"User account '{e.user}' created",
            severity="medium",
            description="New account created (event 4720). Confirm it was expected.",
            entity=e.user,
            evidence=[e],
        )
        for e in _kind(events, "win.user_created")
    ]


RULES: list[RuleFn] = [
    rule_ssh_bruteforce,
    rule_ssh_success_after_failures,
    rule_ssh_root_login,
    rule_ssh_user_enumeration,
    rule_sudo_shell,
    rule_web_injection,
    rule_web_scanner_ua,
    rule_web_404_flood,
    rule_win_failed_logon_burst,
    rule_win_rdp_from_public_ip,
    rule_win_suspicious_process,
    rule_win_admin_group_add,
    rule_win_service_installed,
    rule_win_audit_log_cleared,
    rule_win_user_created,
]


def run_detections(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(events))
    return findings
