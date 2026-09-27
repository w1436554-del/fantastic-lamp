import argparse, json
from .scope import validate_target, validate_url
from .scanner import scan
from .httpcheck import check
from .report import write

def ports(value):
    out=[]
    for part in value.split(","):
        if "-" in part:
            a,b=map(int,part.split("-",1)); out.extend(range(a,b+1))
        else: out.append(int(part))
    return out

def main():
    parser=argparse.ArgumentParser(prog="sentinelpt")
    sub=parser.add_subparsers(dest="cmd",required=True)
    s=sub.add_parser("scan"); s.add_argument("--target",required=True); s.add_argument("--allow",action="append",required=True)
    s.add_argument("--ports",required=True); s.add_argument("--timeout",type=float,default=.75); s.add_argument("--workers",type=int,default=32); s.add_argument("--out",default="report.json")
    h=sub.add_parser("http"); h.add_argument("--url",required=True); h.add_argument("--allow-host",action="append",required=True); h.add_argument("--timeout",type=float,default=5); h.add_argument("--out",default="http-report.json")
    a=parser.parse_args()
    if a.cmd=="scan":
        target=validate_target(a.target,set(a.allow)); data={"tool":"SentinelPT","target":target,"results":scan(target,ports(a.ports),a.timeout,a.workers)}
    else:
        url,_=validate_url(a.url,set(a.allow_host)); data={"tool":"SentinelPT","result":check(url,a.timeout)}
    write(data,a.out); print(json.dumps(data,indent=2))

if __name__=="__main__": main()
