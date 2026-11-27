"""Read public push activity published by GitHub Actions, with fallback to user Atom feed."""
import os
import json
import re
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from svcdash.github_snapshots import read_snapshot

FEED_URL = os.environ.get("SVC_GITHUB_FEED") or "https://github.com/iamcheyan.atom"
FEED_CACHE_SEC = 300
ACTIVITY_PATH = Path(os.environ.get('SVC_GITHUB_ACTIVITY_CACHE', '/home/tetsuya/.cache/svc-dashboard/public-activity.json'))

_atom_cache = {"t": 0.0, "etag": None, "data": []}


def _parse_atom(xml_bytes):
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return []

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    items = []

    for entry in root.findall("atom:entry", ns):
        title = (entry.findtext("atom:title", "", ns) or "").strip()
        pub_str = entry.findtext("atom:published", "", ns) or ""
        ts = 0.0
        if pub_str:
            try:
                dt = datetime.fromisoformat(pub_str.replace(" UTC", "+00:00"))
                ts = dt.timestamp()
            except Exception:
                ts = time.time()

        link_el = entry.find("atom:link", ns)
        event_url = link_el.attrib.get("href", "") if link_el is not None else ""
        content = entry.findtext("atom:content", "", ns) or ""

        repo = ""
        repo_m = re.search(r"in\s*<a[^>]*href=\"/[^/]+/([^/\"]+)\"[^>]*>", content)
        if repo_m:
            repo = repo_m.group(1)
        elif "pushed" in title:
            rm = re.search(r"pushed\s+([A-Za-z0-9_.-]+)", title)
            if rm:
                repo = rm.group(1)

        branch_m = re.search(r"href=\"/[^/]+/[^/]+/tree/([^\"]+)\"", content)
        branch = branch_m.group(1) if branch_m else ""

        commit_blocks = re.findall(
            r"href=\"/[^/\"]+/[^/\"]+/commit/([0-9a-fA-F]+)\"[^>]*>([0-9a-fA-F]+)</a></code>.*?"
            r"<blockquote>\s*(.*?)\s*</blockquote>",
            content, re.DOTALL
        )

        if commit_blocks:
            for full_sha, short_sha, msg in commit_blocks:
                clean_msg = re.sub(r"<[^>]+>", "", msg).strip()
                c_url = f"https://github.com/iamcheyan/{repo}/commit/{full_sha}" if repo else event_url
                items.append({
                    "ts": ts,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                    "gid": short_sha[:7],
                    "name": repo or "git",
                    "kind": "commit",
                    "text": f"{clean_msg} — iamcheyan",
                    "subject": clean_msg,
                    "author": "iamcheyan",
                    "src": "github",
                    "url": c_url,
                    "repo": repo,
                    "sha": full_sha,
                    "short_sha": short_sha[:7],
                    "branch": branch,
                    "origin": "github",
                    "files": [],
                })
        else:
            items.append({
                "ts": ts,
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                "gid": event_url.split("/")[-1][:7] if event_url else "gh",
                "name": repo or "git",
                "kind": "commit",
                "text": title,
                "subject": title,
                "author": "iamcheyan",
                "src": "github",
                "url": event_url,
                "repo": repo,
                "sha": "",
                "short_sha": "",
                "branch": branch,
                "origin": "github",
                "files": [],
            })

    return items


def fetch_github_events(url=FEED_URL, timeout=8):
    now = time.time()
    if _atom_cache["data"] and now - _atom_cache["t"] < FEED_CACHE_SEC:
        return _atom_cache["data"]

    req = urllib.request.Request(url, headers={"User-Agent": "svc-dashboard/1.0"})
    if _atom_cache.get("etag"):
        req.add_header("If-None-Match", _atom_cache["etag"])

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            etag = resp.headers.get("ETag")
            raw = resp.read()
            items = _parse_atom(raw)
            _atom_cache.update({"t": now, "etag": etag or _atom_cache["etag"], "data": items})
            return items
    except urllib.error.HTTPError as e:
        if e.code == 304:
            _atom_cache["t"] = now
            return _atom_cache["data"]
        return _atom_cache["data"]
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return _atom_cache["data"]


def github_events(total=60):
    """Return recent public pushes from snapshot, with fallback to Atom feed."""
    activity = read_snapshot().get('activity') or {}
    try:
        local = json.loads(ACTIVITY_PATH.read_text(encoding='utf-8'))
        if (local.get('ok') is True and isinstance(local.get('events'), list)
                and local.get('updated_at', 0) > activity.get('updated_at', 0)):
            activity = local
    except (OSError, ValueError, TypeError):
        pass
    if activity.get('ok') is True:
        return [dict(event, time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event['ts'])))
                for event in activity['events'][:total]]

    # Fallback to Atom feed when snapshot is unavailable
    events = fetch_github_events()
    return sorted(events or [], key=lambda item: -float(item.get("ts") or 0))[:total]
