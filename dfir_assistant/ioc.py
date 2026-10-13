"""Indicator-of-compromise (IOC) extraction. Values are stored raw and defanged only when displayed."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .detections import is_private_ip
from .models import Event

IPV4_RE = re.compile(
    r"(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"
)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\\]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
HASH_RES = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
IGNORED_IPS = {"0.0.0.0", "255.255.255.255"}


@dataclass
class Indicator:
    ioc_type: str
    value: str
    evidence_refs: list[str] = field(default_factory=list)
    internal: bool = False

    @property
    def defanged(self) -> str:
        return defang(self.ioc_type, self.value)


def defang(ioc_type: str, value: str) -> str:
    if ioc_type in {"ip", "domain"}:
        return value.replace(".", "[.]")
    if ioc_type == "url":
        scheme, _, rest = value.partition("://")
        netloc, slash, path = rest.partition("/")
        return f"{'hxxps' if scheme.lower() == 'https' else 'hxxp'}://{netloc.replace('.', '[.]')}{slash}{path}"
    if ioc_type == "email":
        local, _, domain = value.partition("@")
        return f"{local}[@]{domain.replace('.', '[.]')}"
    return value


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _extract(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;)")
        found.append(("url", url))
        host = urlparse(url).hostname
        if host and not _is_ip(host):
            found.append(("domain", host.lower()))
    for match in EMAIL_RE.finditer(text):
        email = match.group(0).lower()
        found.append(("email", email))
        found.append(("domain", email.split("@", 1)[1]))
    for match in IPV4_RE.finditer(text):
        if match.group(0) not in IGNORED_IPS:
            found.append(("ip", match.group(0)))
    for ioc_type, pattern in HASH_RES.items():
        found.extend((ioc_type, m.group(0).lower()) for m in pattern.finditer(text))
    found.extend(("cve", m.group(0).upper()) for m in CVE_RE.finditer(text))
    return found


def extract_indicators(events: list[Event]) -> list[Indicator]:
    """Collect unique IOCs; each keeps the evidence refs of every event that contained it."""
    index: dict[tuple[str, str], Indicator] = {}
    for event in events:
        for ioc_type, value in _extract(event.raw):
            key = (ioc_type, value)
            indicator = index.get(key)
            if indicator is None:
                indicator = Indicator(ioc_type, value, internal=ioc_type == "ip" and is_private_ip(value))
                index[key] = indicator
            if event.ref not in indicator.evidence_refs:
                indicator.evidence_refs.append(event.ref)
    order = {"url": 0, "domain": 1, "email": 2, "ip": 3, "sha256": 4, "sha1": 5, "md5": 6, "cve": 7}
    return sorted(index.values(), key=lambda i: (order.get(i.ioc_type, 9), i.value))
