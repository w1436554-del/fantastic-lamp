# SentinelPT

Scoped, consent-based penetration-testing toolkit for systems you own or are explicitly authorized to assess.

## Features
- Explicit target and host allowlists
- Bounded TCP connect scanning with optional non-invasive banner collection
- DNS name resolution for allowlisted hostnames
- HTTP security-header auditing
- Structured findings and JSON reports
- Safe defaults and hard caps

## Usage

```bash
python -m sentinelpt scan --target 127.0.0.1 --allow 127.0.0.1 --ports 22,80,443 --out report.json
python -m sentinelpt http --url https://example.com --allow-host example.com --out http-report.json
```

The toolkit intentionally excludes credential attacks, exploitation, persistence, stealth/evasion, and destructive actions.

Only scan systems you own or have explicit authorization to assess.
