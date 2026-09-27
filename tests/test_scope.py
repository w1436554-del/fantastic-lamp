import pytest
from sentinelpt.scope import ScopeError, validate_target, validate_url

def test_target_allowlist():
    assert validate_target("127.0.0.1",{"127.0.0.1"})=="127.0.0.1"

def test_target_rejected():
    with pytest.raises(ScopeError): validate_target("example.org",{"127.0.0.1"})

def test_url_host_allowlist():
    assert validate_url("https://example.com/a",{"example.com"})[1]=="example.com"
