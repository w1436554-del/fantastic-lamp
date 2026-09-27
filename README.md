# SentinelPT

Scoped, consent-based penetration-testing toolkit for systems and networks you own or are explicitly authorized to assess.

## Features
- Explicit target/host/network allowlists
- Bounded TCP connect scanning
- CIDR network scanning with a hard host cap
- Optional non-invasive service banners
- HTTP security-header auditing
- Structured JSON reports
- Safe, non-destructive defaults

## Usage

Single host:
```bash
python -m sentinelpt scan --target 127.0.0.1 --allow 127.0.0.1 --ports 22,80,443 --out report.json
```

Authorized private network:
```bash
python -m sentinelpt network --target 192.168.1.0/24 --allow 192.168.1.0/24 --ports 22,80,443,445,3389 --out network-report.json
```

HTTP audit:
```bash
python -m sentinelpt http --url https://example.com --allow-host example.com --out http-report.json
```

The network mode is intentionally limited to an explicitly allowlisted CIDR and defaults to a maximum of 1024 hosts. It performs TCP connect checks only; it does not exploit services, brute-force credentials, evade detection, persist, or modify remote systems.

Only scan systems you own or have explicit authorization to assess.
