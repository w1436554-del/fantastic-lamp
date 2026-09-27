import json
from pathlib import Path

def write(data, path: str):
    Path(path).write_text(json.dumps(data,indent=2,sort_keys=True),encoding="utf-8")
    return path
