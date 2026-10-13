# Automated DFIR Assistant

A Python tool for first-pass digital forensics and incident response (DFIR) triage of security logs.
Given log files, it:

1. **Parses** the logs into one normalised event model.
2. **Flags suspicious activity** with rules. Each finding cites the exact log lines behind it.
3. **Extracts indicators of compromise (IOCs)** such as IPs, URLs, domains, hashes and CVEs. Values are defanged for sharing.
4. **Builds a timeline** of every event, sorted in UTC and exported to CSV.
5. **Generates an investigation report** in Markdown, with an optional AI-written narrative.

It uses only the Python standard library (3.10+). There are no dependencies to install.

## Quick start

```bash
# Analyse the bundled synthetic samples; output goes to ./out
python -m dfir_assistant analyze samples/linux_auth.log samples/web_access.log samples/windows_events.jsonl \
    --out out --year 2026

# Run the test suite
python -m unittest discover -s tests -t .
```

Outputs written to `--out`:

| File | Contents |
|---|---|
| `report.md` | Investigation report: sources and hashes, executive summary, findings with evidence, IOCs, timeline, limitations |
| `findings.json` | Machine-readable findings, each with its evidence IDs, `file:line` locations and raw lines |
| `timeline.csv` | Every normalised event in UTC order, with its evidence ID and any finding IDs it supports |
| `iocs.csv` | Defanged IOCs with the evidence IDs where each one appears |

### Options

- `--format {auto,linux_auth,web_access,windows_jsonl}`: format per run. Default `auto` detects it from the file's content.
- `--year YEAR`: year to assume for syslog timestamps, which carry none. Default is the current UTC year.
- `--ai-endpoint URL --ai-model NAME`: optional narrative from a **local** model. See [AI use and data handling](#ai-use-and-data-handling).

## Supported inputs

| Format | Typical source | Notes |
|---|---|---|
| `linux_auth` | `/var/log/auth.log`, `/var/log/secure`, syslog | sshd (failed, accepted, invalid user) and sudo are classified. Other lines are kept as `linux.other`. |
| `web_access` | Apache / Nginx "combined" access logs | Timezone offsets are converted to UTC. |
| `windows_jsonl` | Windows events exported as JSON lines, one flat object per line | Keys read: `TimeCreated` (or `@timestamp`), `EventID`, `Computer`, `TargetUserName`, `SubjectUserName`, `IpAddress`, `LogonType`, `CommandLine`, `NewProcessName`, `GroupName`, `MemberName`, `ServiceName`, `ImagePath`. |

Lines that cannot be parsed are counted per file in section 1 of the report and are not analysed.
Input is never modified.

## Detection rules

| Rule | Severity | What it flags |
|---|---|---|
| R-SSH-001 | high | 5+ failed SSH logins from one IP within 10 minutes (brute force) |
| R-SSH-002 | high | Successful SSH login within 30 minutes of 3+ failures from the same IP |
| R-SSH-003 | high | Direct root login over SSH |
| R-SSH-004 | medium | 5+ attempts for non-existent users from one IP within 10 minutes |
| R-SUDO-001 | medium | sudo used to start a shell (`sh`, `bash`, `su`, ...) |
| R-WEB-001 | high | URL payloads for SQL injection, XSS, path traversal, command injection or local file inclusion (URL-decoded, twice) |
| R-WEB-002 | medium | Offensive-tool user-agent (sqlmap, nikto, nmap, ...) |
| R-WEB-003 | medium | 20+ HTTP 404 responses from one IP within 5 minutes |
| R-WIN-001 | high | 5+ failed logons (4625) from one source within 10 minutes |
| R-WIN-002 | medium | Interactive RDP logon (type 10) from a non-internal IP |
| R-WIN-003 | high | Encoded PowerShell, download cradles, `Invoke-Expression`, or `mshta`/`rundll32` script execution |
| R-WIN-004 | high | Account added to the Administrators group (4732) |
| R-WIN-005 | medium | New service installed (7045) |
| R-WIN-006 | high | Security audit log cleared (1102) |
| R-WIN-007 | medium | New user account created (4720) |

"Internal" means RFC 1918, loopback, link-local, CGNAT or IPv6 unique-local addresses. The RFC 5737 documentation ranges used in the samples are treated as external.

Rules are heuristics. A match is a lead for analyst review, not proof of compromise. Thresholds are constants at the top of `dfir_assistant/detections.py`.

## Evidence and citations

Every event gets a stable ID (`E-000001`, ...) in input order. Every finding, IOC and timeline row cites those IDs. Each finding in `report.md` lists:

- the rule ID, the entity, and the first and last timestamp in the window;
- the evidence IDs;
- the `file:line` source references;
- verbatim raw log lines.

Findings are built from the events themselves, so a finding cannot exist without evidence (`Finding` rejects an empty evidence list). The test suite checks that every cited ID exists and that every finding's evidence appears in the report.

## AI use and data handling

Some of the work benefits from a language model, such as a readable narrative and suggested next checks. Log evidence is sensitive, so AI use is restricted in code:

- **Local models only.** `--ai-endpoint` must resolve to a loopback host (`127.0.0.1`, `localhost` or `::1`). Any other host is refused before a request is made. Proxies and HTTP redirects are disabled for that request.
- **Opt-in.** Without `--ai-endpoint`, nothing is sent anywhere. Detections, IOCs and the report are fully deterministic.
- **Citation required.** A model line is kept only if it cites evidence IDs belonging to the finding it describes. Uncited lines, and lines citing other IDs, are dropped. Lines that survive appear under "AI-assisted analysis" in the report, beside the deterministic description.
- **Failures are non-fatal.** If the model is unreachable, that finding simply has no AI text and the error goes to stderr.

Example with a local [Ollama](https://ollama.com) server:

```bash
ollama pull llama3.1
python -m dfir_assistant analyze samples/*.log --out out --year 2026 \
    --ai-endpoint http://127.0.0.1:11434/api/generate --ai-model llama3.1
```

Do not paste real evidence into public AI services. Use the local-only option above, or no AI at all.

The bundled `samples/` are **synthetic**. They use RFC 5737 documentation IP addresses and example domains, and they contain no real data.

## Project layout

```
dfir_assistant/
  models.py       Event and Finding data classes; citation IDs
  parsers.py      Format detection and parsers for the three supported formats
  detections.py   Detection rules (R-*), burst/window helpers, internal-IP logic
  ioc.py          IOC extraction and defanging
  analyzer.py     Pipeline: parse -> assign IDs -> detect -> extract IOCs
  timeline.py     Timeline export with CSV formula-injection protection
  ai_assist.py    Optional local-only AI narrative with citation validation
  report.py       Markdown report and JSON/CSV writers
  cli.py          Command-line interface
samples/          Synthetic logs for demo and tests
tests/            unittest suite (no third-party packages)
```

## Limitations

- Only the three formats above are supported. Add a parser in `parsers.py` and register it in `_PARSERS`.
- Syslog timestamps have no year or timezone. The year is supplied with `--year` and times are treated as UTC. Check this for logs from other timezones.
- Rules are simple and tuned to the sample scenario. Test them against your own environment before relying on them.
- IOCs are extracted from every field, including user-agents and referers, so they include some benign-looking values.
