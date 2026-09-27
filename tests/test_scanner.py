from sentinelpt.scanner import scan

def test_rejects_invalid_port():
    try:
        scan("127.0.0.1", [0])
    except ValueError:
        pass
    else:
        raise AssertionError("invalid port was accepted")
