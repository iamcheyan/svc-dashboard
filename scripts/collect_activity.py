#!/usr/bin/env python3
"""Refresh the persisted activity feed from discovered Git repositories."""
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from svcdash.repos import _REPO_EVENTS_PATH, refresh_repo_commits


def main():
    events = refresh_repo_commits()
    snapshot = json.loads(_REPO_EVENTS_PATH.read_text())
    latest = max((int(e.get("ts", 0)) for e in events), default=0)
    latest_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(latest)) if latest else "none"
    print(f"repositories={len(snapshot.get('paths', []))} events={len(events)} latest={latest_text}", flush=True)


if __name__ == "__main__":
    main()
