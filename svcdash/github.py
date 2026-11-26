import os, re, time, urllib.request, xml.etree.ElementTree as ET
from datetime import datetime

FEED_URL = os.environ.get("SVC_GITHUB_FEED") or "https://github.com/iamcheyan.atom"
FEED_CACHE_SEC = 300  # 5 分钟本地缓存，防触发 GitHub 限流

_cache = {"t": 0.0, "etag": None, "data": []}


def fetch_github_events(url=FEED_URL, timeout=8):
    """从 GitHub Atom RSS 拉取并解析公开动态(带 5 分钟缓存与 ETag 协商)。
    纯标准库实现，异常安全(网络不通时优雅降级返回上次缓存或空列表)。"""
    now = time.time()
    if _cache["data"] and now - _cache["t"] < FEED_CACHE_SEC:
        return _cache["data"]

    req = urllib.request.Request(url, headers={"User-Agent": "svc-dashboard/1.0"})
    if _cache.get("etag"):
        req.add_header("If-None-Match", _cache["etag"])

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            etag = resp.headers.get("ETag")
            raw = resp.read()
            items = _parse_atom(raw)
            _cache.update({"t": now, "etag": etag or _cache["etag"], "data": items})
            return items
    except urllib.error.HTTPError as e:
        if e.code == 304:  # 未修改，复用缓存
            _cache["t"] = now
            return _cache["data"]
        # 其他 HTTP 状态降级
        return _cache["data"]
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return _cache["data"]


def _parse_atom(xml_bytes):
    """解析 GitHub 用户 Atom XML，提取 Push 及其中包含的单个 Commit。"""
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

        # 匹配仓库名称
        repo = ""
        repo_m = re.search(r"in\s*<a[^>]*href=\"/[^/]+/([^/\"]+)\"[^>]*>", content)
        if repo_m:
            repo = repo_m.group(1)
        elif "pushed" in title:
            rm = re.search(r"pushed\s+([A-Za-z0-9_.-]+)", title)
            if rm:
                repo = rm.group(1)

        # 匹配分支名
        branch_m = re.search(r"href=\"/[^/]+/[^/]+/tree/([^\"]+)\"", content)
        branch = branch_m.group(1) if branch_m else ""

        # 提取单个提交: sha / short_sha / 提交信息
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
            # 非单个 commit 的动态(如新建分支、push summary)
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


def github_events(total=60):
    """Return only GitHub Atom feed events, ordered newest first."""
    events = fetch_github_events()
    return sorted(events or [], key=lambda item: -float(item.get("ts") or 0))
