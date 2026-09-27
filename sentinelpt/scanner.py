import concurrent.futures
import socket
import time
from dataclasses import asdict, dataclass

@dataclass
class PortResult:
    port: int
    state: str
    service: str | None = None
    banner: str | None = None
    latency_ms: float | None = None
    error: str | None = None

COMMON = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",443:"https",445:"smb",3306:"mysql",5432:"postgresql",6379:"redis",8080:"http-alt",8443:"https-alt"}

def check_port(host: str, port: int, timeout: float) -> PortResult:
    started=time.perf_counter()
    try:
        with socket.create_connection((host,port), timeout=timeout) as s:
            s.settimeout(min(timeout,0.5))
            banner=None
            try:
                data=s.recv(256)
                if data:
                    banner=data.decode("utf-8","replace").strip()
            except (socket.timeout, OSError):
                pass
            return PortResult(port,"open",COMMON.get(port),banner,(time.perf_counter()-started)*1000)
    except ConnectionRefusedError:
        return PortResult(port,"closed",COMMON.get(port),None,(time.perf_counter()-started)*1000)
    except socket.timeout:
        return PortResult(port,"filtered_or_timeout",COMMON.get(port),None,(time.perf_counter()-started)*1000)
    except OSError as e:
        return PortResult(port,"unreachable_or_filtered",COMMON.get(port),None,(time.perf_counter()-started)*1000,type(e).__name__)

def scan(host: str, ports: list[int], timeout=.75, workers=32) -> list[dict]:
    ports=sorted(set(ports))
    if not ports: raise ValueError("At least one port is required.")
    if any(p<1 or p>65535 for p in ports): raise ValueError("Ports must be between 1 and 65535.")
    if len(ports)>4096: raise ValueError("Refusing more than 4096 ports in one scan.")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(workers,len(ports)))) as ex:
        results=list(ex.map(lambda p: check_port(host,p,timeout),ports))
    return [asdict(r) for r in results]
