# SentinelPT

Scoped, consent-based penetration-testing toolkit for systems you own or are explicitly authorized to assess.

## Features
- Explicit target/host allowlists
- TCP connect scanning with bounded concurrency
- Basic service identification and non-invasive banners
- HTTP security-header checks
- JSON reports
- Safe defaults

## Usage
```bash
python -m sentinelpt scan --target 127.0.0.1 --allow 127.0.0.1 --ports 22,80,443 --out report.json
python -m sentinelpt http --url https://example.com --allow-host example.com --out http-report.json
```

The toolkit intentionally excludes credential attacks, exploitation, persistence, stealth/evasion, and destructive actions.
