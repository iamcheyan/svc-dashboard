"""Read-only view of the host's systemd journal."""
import json
import shutil
import subprocess
import time


def read(lines=200, priority=None):
    """Return recent host journal entries, optionally at or above a severity."""
    try:
        lines = max(20, min(500, int(lines)))
    except (TypeError, ValueError):
        lines = 200
    args = ["journalctl", "--no-pager", "--output=json", "--all", "--lines", str(lines)]
    if priority is not None:
        try:
            priority = max(0, min(7, int(priority)))
        except (TypeError, ValueError):
            priority = None
    if priority is not None:
        args += ["--priority", str(priority)]
    if not shutil.which("journalctl"):
        return {"ok": False, "msg": "journalctl is not installed", "entries": []}
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "msg": str(exc)[:240], "entries": []}
    if proc.returncode:
        return {"ok": False, "msg": (proc.stderr.strip() or "journalctl failed")[:240], "entries": []}

    entries = []
    for raw in proc.stdout.splitlines():
        try:
            item = json.loads(raw)
            priority_value = int(item.get("PRIORITY", 6))
            if priority is not None and priority_value > priority:
                continue
            micros = int(item.get("__REALTIME_TIMESTAMP", 0))
            message = item.get("MESSAGE", "")
            if isinstance(message, list):
                message = bytes(message).decode("utf-8", "replace")
            entries.append({
                "ts": micros / 1_000_000 if micros else 0,
                "priority": priority_value,
                "unit": str(item.get("_SYSTEMD_UNIT") or item.get("UNIT") or item.get("SYSLOG_IDENTIFIER") or item.get("_COMM") or "system")[:160],
                "message": str(message)[:12000],
            })
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    entries.sort(key=lambda x: x["ts"], reverse=True)
    return {"ok": True, "updated": time.time(), "entries": entries[:lines]}
