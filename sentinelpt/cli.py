import argparse, json
from .scope import validate_target, validate_network_target, validate_url
from .scanner import scan, scan_network
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

    s=sub.add_parser("scan", help="TCP connect scan of one explicitly allowed host")
    s.add_argument("--target", required=True)
    s.add_argument("--allow", action="append", required=True)
    s.add_argument("--ports", required=True)
    s.add_argument("--timeout", type=float, default=.75)
    s.add_argument("--workers", type=int, default=32)
    s.add_argument("--out", default="report.json")

    n=sub.add_parser("network", help="Bounded TCP scan of one explicitly allowed CIDR")
    n.add_argument("--target", required=True, help="CIDR, e.g. 192.168.1.0/24")
    n.add_argument("--allow", action="append", required=True, help="Must exactly include the CIDR")
    n.add_argument("--ports", required=True)
    n.add_argument("--timeout", type=float, default=.75)
    n.add_argument("--workers", type=int, default=32)
    n.add_argument("--max-hosts", type=int, default=1024)
    n.add_argument("--out", default="network-report.json")

    h=sub.add_parser("http", help="HTTP response and security-header audit")
    h.add_argument("--url", required=True)
    h.add_argument("--allow-host", action="append", required=True)
    h.add_argument("--timeout", type=float, default=5)
    h.add_argument("--out", default="http-report.json")

    a=parser.parse_args()
    if a.cmd=="scan":
        target=validate_target(a.target,set(a.allow))
        data={"tool":"SentinelPT","version":"0.3.0","mode":"non-destructive","target":target,
              "results":scan(target,ports(a.ports),a.timeout,a.workers)}
    elif a.cmd=="network":
        target=validate_network_target(a.target,set(a.allow))
        data={"tool":"SentinelPT","version":"0.3.0","mode":"non-destructive","target":target,
              "results":scan_network(target,ports(a.ports),a.timeout,a.workers,a.max_hosts)}
    else:
        url,_=validate_url(a.url,set(a.allow_host))
        result=check(url,a.timeout)
        result["findings"]=classify_header_findings(result)
        data={"tool":"SentinelPT","version":"0.3.0","mode":"non-destructive","result":result}
    write(data,a.out)
    print(json.dumps(data,indent=2))

if __name__=="__main__": main()
