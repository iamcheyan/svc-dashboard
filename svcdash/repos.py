import json, os, re, subprocess, time
from svcdash.goals import watchdog_goals, parse_completed_goals
from svcdash.agents import scan_omp, scan_codex
# ---------------- 仓库层: agent/goal 改动过的 git 仓库 ----------------
# 仓库集合来自现成数据源(watchdog GOALS workdir / 完成台账 workdir /
# 在跑 omp/codex 的 cwd),逐级向上找 .git 定位仓库根,不做全盘扫描。
# 提交事件(git log)60s 缓存;完整统计(du 大小/文件占比)600s 缓存,
# /api/repos?refresh=1 按需强制重算。

_repo_set_cache = {"t": 0.0, "repos": None}
_repo_ev_cache = {"t": 0.0, "data": None}
_repo_stats_cache = {"t": 0.0, "data": None}


def _git(repo, args, timeout=6):
    """只读跑 git;服务以 root 跑、仓库属主是 tetsuya,用 safe.directory=*
    跳过 dubious-ownership;--no-optional-locks 防止 status 刷新别人的索引。"""
    cmd = ["git", "-c", "safe.directory=*", "-c", "core.quotepath=off",
           "--no-optional-locks", "-C", repo] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _git_root(path):
    """从 path 逐级向上找 .git 目录;找不到返回 None。纯 os 调用,不 spawn。"""
    p = os.path.realpath(path)
    while True:
        if os.path.isdir(os.path.join(p, ".git")):
            return p
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent


def agent_repos():
    """agent/goal 任务改动过的 git 仓库根列表(去重,按 .git mtime 倒序)。"""
    now = time.time()
    if _repo_set_cache["repos"] is not None and now - _repo_set_cache["t"] < 60:
        return _repo_set_cache["repos"]
    dirs = []
    for g in watchdog_goals().values():
        if g.get("workdir"):
            dirs.append(g["workdir"])
    for c in parse_completed_goals(limit=100):
        if c.get("workdir"):
            dirs.append(c["workdir"])
    for a in scan_omp() + scan_codex():
        if a.get("cwd"):
            dirs.append(a["cwd"])
    roots = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        r = _git_root(d)
        if not r:
            continue
        try:
            roots[r] = os.path.getmtime(os.path.join(r, ".git"))
        except OSError:
            roots[r] = 0.0
    repos = [p for p, _ in sorted(roots.items(), key=lambda kv: -kv[1])]
    _repo_set_cache.update({"t": now, "repos": repos})
    return repos


def parse_repo_commits(per_repo=12, total=60):
    """各 agent 仓库最近提交 -> commit 事件(60s 缓存)。
    事件 shape 与 merge_events 其余来源同构: kind/src 均为 "commit"。"""
    now = time.time()
    if _repo_ev_cache["data"] is not None and now - _repo_ev_cache["t"] < 60:
        return _repo_ev_cache["data"]
    out = []
    for repo in agent_repos():
        name = os.path.basename(repo.rstrip("/"))
        text = _git(repo, ["log", "-n", str(per_repo),
                           "--format=%h%x1f%ct%x1f%s%x1f%an"])
        for line in text.splitlines():
            parts = line.split("\x1f")
            if len(parts) != 4:
                continue
            h, ct, subj, author = parts
            try:
                ts = float(ct)
            except ValueError:
                continue
            out.append({"ts": ts,
                        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                        "gid": h, "name": name, "kind": "commit",
                        "text": f"{subj} — {author}", "src": "commit"})
    out.sort(key=lambda x: -x["ts"])
    out = out[:total]
    _repo_ev_cache.update({"t": now, "data": out})
    return out


def _repo_one_stats(repo):
    """单仓库统计: 分支/提交数/最近提交/大小(du)/未提交数/文件后缀占比。"""
    st = {"name": os.path.basename(repo.rstrip("/")), "path": repo,
          "branch": _git(repo, ["rev-parse", "--abbrev-ref", "HEAD"]).strip() or "—"}
    cnt = _git(repo, ["rev-list", "--count", "HEAD"]).strip()
    st["commits"] = int(cnt) if cnt.isdigit() else None
    parts = _git(repo, ["log", "-1", "--format=%h%x1f%ct%x1f%s%x1f%an"]).strip().split("\x1f")
    if len(parts) == 4 and parts[1].isdigit():
        ts = int(parts[1])
        st["last"] = {"hash": parts[0], "ts": ts,
                      "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                      "subject": parts[2], "author": parts[3]}
    else:
        st["last"] = None
    # 工作区大小: du 是最贵的一项,超时则 size=None 前端显示 —
    try:
        r = subprocess.run(["du", "-sb", repo], capture_output=True, text=True, timeout=20)
        st["size"] = int(r.stdout.split()[0]) if r.returncode == 0 else None
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        st["size"] = None
    st["dirty"] = len([x for x in _git(repo, ["status", "--porcelain"]).splitlines() if x.strip()])
    # 文件占比: git ls-files 只读索引,按后缀计数(后缀 ≤6 字符)
    exts, n_files = {}, 0
    for f in _git(repo, ["ls-files"]).splitlines():
        if not f:
            continue
        n_files += 1
        i = f.rfind(".")
        ext = f[i:].lower() if 0 < i and len(f) - i <= 6 else "—"
        exts[ext] = exts.get(ext, 0) + 1
    st["files"] = n_files
    top = sorted(exts.items(), key=lambda kv: -kv[1])[:5]
    st["exts"] = [[k, v, round(v * 100.0 / n_files, 1)] for k, v in top] if n_files else []
    return st


def repo_stats(refresh=False):
    """/api/repos 数据: 各仓库完整统计。600s 缓存;仓库集合变化或
    ?refresh=1 时重算。"""
    repos = agent_repos()
    now = time.time()
    if (not refresh and _repo_stats_cache["data"] is not None
            and now - _repo_stats_cache["t"] < 600
            and {r["path"] for r in _repo_stats_cache["data"]["repos"]} == set(repos)):
        return _repo_stats_cache["data"]
    out = []
    for repo in repos:
        try:
            out.append(_repo_one_stats(repo))
        except Exception:
            continue
    out.sort(key=lambda x: -((x.get("last") or {}).get("ts") or 0))
    data = {"updated": time.time(), "repos": out}
    _repo_stats_cache.update({"t": time.time(), "data": data})
    return data
