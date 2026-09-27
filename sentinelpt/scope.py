from urllib.parse import urlparse

class ScopeError(ValueError):
    pass

def validate_target(target: str, allowed: set[str]) -> str:
    target = target.strip()
    if not target or target not in allowed:
        raise ScopeError(f"Target {target!r} is not in the explicit allowlist.")
    return target

def validate_network_target(target: str, allowed: set[str]) -> str:
    target = target.strip()
    if target not in allowed:
        raise ScopeError(f"Network {target!r} is not in the explicit allowlist.")
    try:
        import ipaddress
        ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        raise ScopeError("Network target must be a valid IP/CIDR.") from e
    return target

def validate_url(url: str, allowed_hosts: set[str]) -> tuple[str, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("URL must use http or https and include a hostname.")
    host = parsed.hostname.lower()
    if host not in {h.lower() for h in allowed_hosts}:
        raise ScopeError(f"Host {host!r} is not in the explicit allowlist.")
    return parsed.geturl(), host
