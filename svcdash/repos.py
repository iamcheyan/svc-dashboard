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
    st["files"] = sum(1 for f in _git(repo, ["ls-files"]).splitlines() if f)
    st["traj"] = _traj_data(repo)["strip"]   # agent 操作轨迹条(近14天逐日色块)
    return st


# ---------------- Agent 操作轨迹(时间条 + 事件流) ----------------
# 每仓库: git 提交(commit) + watchdog 事件(nudge/pause/restart=warn,
# recover=good) + goal 完成(done)。逐日分桶,主色优先级 done>commit>warn>good。
# cleanup/other 不进色条,只在详情事件流里出现。
_TRAJ_KIND_CLS = {"commit": "commit", "complete": "done", "recover": "good",
                  "restart": "warn", "nudge": "warn", "pause": "warn"}
_TRAJ_DAYS = 14
_traj_cache = {"t": 0.0, "data": {}}          # repo -> {"strip", "events"}
_traj_wd_cache = {"t": 0.0, "by_root": None}  # 60s: watchdog/完成事件按仓库根分桶(共享快照)


def _traj_watchdog_by_root():
    """watchdog + 完成台账事件, 按 git 仓库根分桶(60s 缓存, 全仓库共享一次解析)。"""
    now = time.time()
    if _traj_wd_cache["by_root"] is not None and now - _traj_wd_cache["t"] < 60:
        return _traj_wd_cache["by_root"]
    from svcdash.goals import parse_watchdog_events
    wd_goals = watchdog_goals()
    by_root = {}
    for e in parse_watchdog_events(limit=240):
        g = wd_goals.get(e.get("gid") or "") or {}
        root = _git_root(g.get("workdir") or "")
        if root:
            by_root.setdefault(root, []).append(e)
    for c in parse_completed_goals(limit=100):
        root = _git_root(c.get("workdir") or "")
        if root:
            by_root.setdefault(root, []).append(
                {"ts": c["ts"], "kind": "complete", "gid": c["gid"],
                 "name": c.get("label") or c["gid"][:8],
                 "text": "status=" + c.get("status", "")})
    _traj_wd_cache.update({"t": now, "by_root": by_root})
    return by_root


def _traj_data(repo):
    """单仓库轨迹: strip(近14天逐日主色) + events(时间倒序详情, 上限200)。"""
    now = time.time()
    cached = _traj_cache["data"].get(repo)
    if cached and now - _traj_cache["t"] < 60:
        return cached
    evs = []
    for line in _git(repo, ["log", "-n", "400", "--format=%h%x1f%ct%x1f%s"]).splitlines():
        parts = line.split("\x1f")
        if len(parts) != 3:
            continue
        try:
            ts = float(parts[1])
        except ValueError:
            continue
        evs.append({"ts": ts, "kind": "commit", "gid": parts[0], "name": "", "text": parts[2]})
    evs.extend(_traj_watchdog_by_root().get(repo) or [])
    evs.sort(key=lambda x: -x["ts"])
    # 逐日分桶
    by_day = {}
    for e in evs:
        cls = _TRAJ_KIND_CLS.get(e["kind"])
        if not cls:
            continue
        lt = time.localtime(e["ts"])
        d = by_day.setdefault((lt.tm_year, lt.tm_mon, lt.tm_mday), {})
        d[cls] = d.get(cls, 0) + 1
    base = time.localtime()
    noon = time.mktime((base.tm_year, base.tm_mon, base.tm_mday, 12, 0, 0, 0, 0, -1))
    strip = []
    for i in range(_TRAJ_DAYS - 1, -1, -1):
        lt = time.localtime(noon - i * 86400)
        c = by_day.get((lt.tm_year, lt.tm_mon, lt.tm_mday)) or {}
        cls = next((k for k in ("done", "commit", "warn", "good") if c.get(k)), None)
        strip.append({"d": "%d/%d" % (lt.tm_mon, lt.tm_mday), "cls": cls,
                      "n": sum(c.values()),
                      "c": {k: c[k] for k in ("commit", "warn", "good", "done") if c.get(k)}})
    data = {"strip": strip,
            "events": [{"ts": e["ts"],
                        "time": time.strftime("%m-%d %H:%M", time.localtime(e["ts"])),
                        "kind": e["kind"], "cls": _TRAJ_KIND_CLS.get(e["kind"]) or "",
                        "name": e.get("name") or "", "text": (e.get("text") or "")[:200]}
                       for e in evs[:200]]}
    _traj_cache["data"][repo] = data
    _traj_cache["t"] = now
    return data


def repo_trajectory(name):
    """/api/trajectory?repo=NAME -> 单仓库完整轨迹(strip + 事件流)。"""
    for repo in agent_repos():
        if os.path.basename(repo.rstrip("/")) == name:
            d = _traj_data(repo)
            return {"ok": True, "repo": name, "path": repo, "days": _TRAJ_DAYS, **d}
    return {"ok": False, "msg": "unknown repo"}


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
