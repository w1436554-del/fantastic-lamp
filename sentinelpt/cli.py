import argparse, json
from .scope import validate_target, validate_url
from .scanner import scan
from .httpcheck import check
from .report import write
from .vulncheck import classify_header_findings

def ports(value):
    out=[]
    for part in value.split(","):
        part=part.strip()
        if "-" in part:
            a,b=map(int,part.split("-",1)); out.extend(range(a,b+1))
        elif part: out.append(int(part))
    return out

def main():
    parser=argparse.ArgumentParser(prog="sentinelpt", description="Scoped, non-destructive penetration-testing toolkit")
    sub=parser.add_subparsers(dest="cmd", required=True)

    s=sub.add_parser("scan", help="TCP connect scan with optional banner collection")
    s.add_argument("--target", required=True)
    s.add_argument("--allow", action="append", required=True)
    s.add_argument("--ports", required=True)
    s.add_argument("--timeout", type=float, default=.75)
    s.add_argument("--workers", type=int, default=32)
    s.add_argument("--out", default="report.json")

    h=sub.add_parser("http", help="HTTP response and security-header audit")
    h.add_argument("--url", required=True)
    h.add_argument("--allow-host", action="append", required=True)
    h.add_argument("--timeout", type=float, default=5)
    h.add_argument("--out", default="http-report.json")

    a=parser.parse_args()
    if a.cmd=="scan":
        target=validate_target(a.target,set(a.allow))
        data={"tool":"SentinelPT","version":"0.2.0","mode":"non-destructive","target":target,
              "results":scan(target,ports(a.ports),a.timeout,a.workers)}
    else:
        url,_=validate_url(a.url,set(a.allow_host))
        result=check(url,a.timeout)
        result["findings"]=classify_header_findings(result)
        data={"tool":"SentinelPT","version":"0.2.0","mode":"non-destructive","result":result}
    write(data,a.out)
    print(json.dumps(data,indent=2))

if __name__=="__main__": main()
