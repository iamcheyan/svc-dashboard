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


def merge_commits(local_commits, gh_events, total=60):
    """将本地 Git 提交与 GitHub 远程动态合二为一：
    - 本地与 GitHub 均有：合并为一条，origin='both'，附带 GitHub 直达链接。
    - 仅 GitHub 有(其他电脑推送/本地未 pull)：origin='github'，标记远端更新。
    - 仅本地有(未推送)：origin='local'，标记本地未推。
    按时间戳倒序输出前 total 条。"""
    gh_by_key = {}
    gh_unmatched = []

    for ge in (gh_events or []):
        r = (ge.get("repo") or ge.get("name") or "").lower()
        sha = (ge.get("short_sha") or ge.get("gid") or "")[:7].lower()
        if r and sha and len(sha) >= 4:
            gh_by_key[(r, sha)] = ge
        else:
            gh_unmatched.append(ge)

    merged = []
    matched_gh_keys = set()

    for lc in (local_commits or []):
        r = (lc.get("name") or "").lower()
        sha = (lc.get("gid") or "")[:7].lower()
        key = (r, sha)
        ge = gh_by_key.get(key)
        if not ge and sha:
            # 宽松匹配：SHA 匹配且仓库名互相包含(如本地 zircon 对齐远程 Zircon-Godot)
            for (gr, gsha), cand in gh_by_key.items():
                if gsha == sha and (r in gr or gr in r):
                    ge = cand
                    key = (gr, gsha)
                    break
        if ge:
            # 两端均有：合并，标记已同步
            matched_gh_keys.add(key)
            item = dict(lc)
            item["origin"] = "both"
            item["url"] = ge.get("url") or f"https://github.com/iamcheyan/{lc['name']}/commit/{lc['gid']}"
            merged.append(item)
        else:
            # 仅本地有
            item = dict(lc)
            item["origin"] = "local"
            merged.append(item)

    # 补充仅 GitHub 有的提交(其他电脑推送，本地尚未 pull)
    for (r, sha), ge in gh_by_key.items():
        if (r, sha) not in matched_gh_keys:
            merged.append(ge)

    # 补充其余通用 GitHub 动态
    merged.extend(gh_unmatched)

    # 按时间倒序
    merged.sort(key=lambda x: -float(x.get("ts") or 0))
    return merged[:total]
