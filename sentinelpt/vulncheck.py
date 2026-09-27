from dataclasses import dataclass, asdict

@dataclass
class Finding:
    check_id: str
    severity: str
    title: str
    evidence: str
    remediation: str

def classify_header_findings(result: dict) -> list[dict]:
    findings=[]
    for header in result.get("missing_security_headers", []):
        severity = "medium" if header in {"Content-Security-Policy","Strict-Transport-Security"} else "low"
        findings.append(asdict(Finding(
            check_id=f"HTTP-{header.upper().replace('-','_')}",
            severity=severity,
            title=f"Missing {header}",
            evidence=f"The response did not include {header}.",
            remediation=f"Configure the web server/application to send an appropriate {header} policy."
        )))
    return findings
