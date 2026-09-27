import socket
from ipaddress import ip_address
from .scope import ScopeError

def resolve_target(target: str, allowed: set[str]) -> list[str]:
    target = target.strip()
    if target not in allowed:
        raise ScopeError(f"Target {target!r} is not in the explicit allowlist.")
    try:
        ip_address(target)
        return [target]
    except ValueError:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        return sorted({item[4][0] for item in infos})
