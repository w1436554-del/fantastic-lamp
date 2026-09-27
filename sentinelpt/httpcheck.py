import ssl
import urllib.request

SECURITY_HEADERS = {
    "strict-transport-security":"HSTS",
    "content-security-policy":"CSP",
    "x-content-type-options":"X-Content-Type-Options",
    "x-frame-options":"X-Frame-Options",
    "referrer-policy":"Referrer-Policy",
    "permissions-policy":"Permissions-Policy",
}

def check(url: str, timeout: float=5) -> dict:
    req=urllib.request.Request(url, headers={"User-Agent":"SentinelPT/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            headers={k.lower():v for k,v in resp.headers.items()}
            return {"url":url,"status":resp.status,"final_url":resp.geturl(),
                    "headers":{name:headers.get(key) for key,name in SECURITY_HEADERS.items()},
                    "missing_security_headers":[name for key,name in SECURITY_HEADERS.items() if key not in headers]}
    except Exception as e:
        return {"url":url,"error":f"{type(e).__name__}: {e}"}
