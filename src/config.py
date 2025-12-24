import os

def _env_int(name: str, default: int, min_v: int, max_v: int) -> int:
    v = os.environ.get(name)
    try:
        val = int(v) if v is not None else default
    except Exception:
        val = default
    if val < min_v:
        return min_v
    if val > max_v:
        return max_v
    return val

DEFAULT_TARGET_CIDR = os.environ.get("TARGET_CIDR", "")
DEFAULT_PING_WORKERS = _env_int("PING_WORKERS", 50, 1, 100)
DEFAULT_NMAP_WORKERS = _env_int("NMAP_WORKERS", 10, 1, 50)
DEFAULT_REFRESH_INTERVAL_MS = 30000
