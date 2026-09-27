from dataclasses import dataclass, field

@dataclass
class ScanConfig:
    timeout: float = 0.75
    workers: int = 32
    max_ports: int = 4096
    banner_bytes: int = 256
    user_agent: str = "SentinelPT/0.2"
    tags: list[str] = field(default_factory=list)
