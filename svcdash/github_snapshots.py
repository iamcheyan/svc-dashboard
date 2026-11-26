"""Read the public GitHub snapshot published by the scheduled Actions workflow."""
import json
import os
import threading
import time
import urllib.error
import urllib.request

URL = os.environ.get(
    "SVC_GITHUB_SNAPSHOT_URL",
    "https://raw.githubusercontent.com/iamcheyan/svc-dashboard/github-data/github-snapshots.json",
)
CACHE_TTL = 60
_cache = {"fetched_at": 0.0, "attempted_at": 0.0, "data": None}
_lock = threading.Lock()


def read_snapshot(force=False):
    """Fetch the public snapshot with a short memory cache and last-good fallback."""
    now = time.time()
    if not force and now - _cache["attempted_at"] < CACHE_TTL:
        return _cache["data"] or {"ok": False, "updated_at": 0, "error": "unavailable"}

    with _lock:
        now = time.time()
        if not force and now - _cache["attempted_at"] < CACHE_TTL:
            return _cache["data"] or {"ok": False, "updated_at": 0, "error": "unavailable"}
        request = urllib.request.Request(URL, headers={"User-Agent": "svc-dashboard/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=6) as response:
                data = json.loads(response.read())
            if not isinstance(data, dict) or data.get("ok") is not True:
                raise ValueError("invalid GitHub snapshot")
            _cache.update({"fetched_at": now, "attempted_at": now, "data": data})
            return data
        except (urllib.error.URLError, OSError, TimeoutError, ValueError, TypeError):
            _cache["attempted_at"] = now
            if _cache["data"] is not None:
                return _cache["data"]
            return {"ok": False, "updated_at": 0, "error": "unavailable"}
