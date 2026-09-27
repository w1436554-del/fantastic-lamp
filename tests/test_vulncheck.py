from sentinelpt.vulncheck import classify_header_findings

def test_missing_headers_create_findings():
    findings=classify_header_findings({"missing_security_headers":["Content-Security-Policy"]})
    assert findings[0]["severity"]=="medium"
    assert findings[0]["check_id"]=="HTTP-CONTENT_SECURITY_POLICY"
