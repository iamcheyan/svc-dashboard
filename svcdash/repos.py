import json, os, re, subprocess, threading, time
from pathlib import Path
from svcdash.goals import watchdog_goals, parse_completed_goals
from svcdash.agents import scan_omp, scan_codex
from svcdash.i18n import t, DEFAULT_LANG
# ---------------- 仓库层: development git 仓库 + agent/goal 改动仓库 ----------------
# 仓库集合包括 ~/development 下的 Git 项目，也补充 Hermes worktree 与
# agent/goal 使用过的仓库根。只跳过依赖与缓存目录。
# 提交事件(git log)60s 缓存;仓库统计600s缓存并异步刷新,
# /api/repos?refresh=1 按需强制重算。

_DEVELOPMENT_ROOT = "/home/tetsuya/development"
_HERMES_WORKTREES_ROOT = "/home/tetsuya/.hermes/worktrees"
_REPO_SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules",
                   "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
                   "target", "build", "dist", "vendor"}

_repo_set_cache = {"t": 0.0, "repos": None}
_repo_ev_cache = {"t": 0.0, "data": None, "paths": []}
_repo_ev_lock = threading.Lock()
_repo_stats_cache = {"t": 0.0, "data": None}
_REPO_STATS_PATH = Path("/home/tetsuya/.cache/svc-dashboard/repos.json")
_REPO_EVENTS_PATH = Path("/home/tetsuya/.cache/svc-dashboard/events.json")
# 需求 #138: 仓库清单与逐仓库提交事件都落盘缓存，
# 避免每分钟重复 walk 文件系统、重复解析未变动仓库的 git log。
_REPO_LIST_PATH = Path("/home/tetsuya/.cache/svc-dashboard/repos-list.json")
_REPO_PER_PATH = Path("/home/tetsuya/.cache/svc-dashboard/repo-events-cache.json")
_REPO_LIST_TTL = 600        # 仓库清单 10 分钟重扫一次
_repo_refresh_lock = threading.Lock()


def _load_repo_list():
    """读取磁盘仓库清单；无缓存或损坏时返回 None。"""
    try:
        data = json.loads(_REPO_LIST_PATH.read_text())
        if isinstance(data, dict) and isinstance(data.get("repos"), list):
            return data
    except (OSError, ValueError, TypeError):
        pass
    return None


def _save_repo_list(repos):
    try:
        _REPO_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _REPO_LIST_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps({"updated": time.time(),
                                   "repos": [os.path.realpath(p) for p in repos]},
                                  ensure_ascii=False, separators=(",", ":")))
        os.replace(tmp, _REPO_LIST_PATH)
    except OSError:
        pass


def _load_repo_events_cache():
    """每仓库事件缓存: {path: {"sig": str, "events": [...]}}。"""
    try:
        data = json.loads(_REPO_PER_PATH.read_text())
        if isinstance(data, dict) and isinstance(data.get("repos"), dict):
            return data["repos"]
    except (OSError, ValueError, TypeError):
        pass
    return {}


def _save_repo_events_cache(cache):
    try:
        _REPO_PER_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _REPO_PER_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps({"updated": time.time(), "repos": cache},
                                  ensure_ascii=False, separators=(",", ":")))
        os.replace(tmp, _REPO_PER_PATH)
    except OSError:
        pass


def _load_repo_events_snapshot():
    try:
        data = json.loads(_REPO_EVENTS_PATH.read_text())
        if isinstance(data, dict) and isinstance(data.get("events"), list):
            updated = data.get("updated")
            snapshot_time = float(updated) if isinstance(updated, (int, float)) else 0.0
            _repo_ev_cache.update({"t": snapshot_time, "data": data["events"],
                                   "paths": data.get("paths") or []})
    except (OSError, ValueError, TypeError):
        pass


def _save_repo_events_snapshot(data, repos):
    try:
        _REPO_EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _REPO_EVENTS_PATH.with_suffix(".tmp")
        payload = {"updated": time.time(), "paths": [os.path.realpath(p) for p in repos],
                   "events": data}
        tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        os.replace(tmp, _REPO_EVENTS_PATH)
    except OSError:
        pass


def _load_repo_stats_snapshot():
    try:
        data = json.loads(_REPO_STATS_PATH.read_text())
        if isinstance(data, dict) and isinstance(data.get("repos"), list):
            updated = data.get("updated")
            snapshot_time = float(updated) if isinstance(updated, (int, float)) else 0.0
            _repo_stats_cache.update({"t": snapshot_time, "data": data})
    except (OSError, ValueError, TypeError):
        pass


def _save_repo_stats_snapshot(data):
    try:
        _REPO_STATS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _REPO_STATS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
        os.replace(tmp, _REPO_STATS_PATH)
    except OSError:
        pass


def _refresh_repo_stats(repos):
    try:
        out = []
        for repo in repos:
            try:
                out.append(_repo_one_stats(repo))
            except Exception:
                continue
        out.sort(key=lambda x: -((x.get("last") or {}).get("ts") or 0))
        data = {"updated": time.time(), "repos": out}
        _repo_stats_cache.update({"t": time.time(), "data": data})
        _save_repo_stats_snapshot(data)
    finally:
        _repo_refresh_lock.release()



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


def agent_repos(force: bool = False):
    """development 下全部 Git 仓库，并补充 agent/goal 使用过的仓库根。

    仓库清单落盘缓存 _REPO_LIST_TTL 秒（需求 #138 轻量化），
    但每次只用 os.path.isdir 校验存活，不重新 walk 文件系统。
    """
    now = time.time()
    if not force and _repo_set_cache["repos"] is not None and now - _repo_set_cache["t"] < 60:
        return _repo_set_cache["repos"]
    if not force:
        cached_list = _load_repo_list()
        if cached_list:
            updated = float(cached_list.get("updated") or 0)
            if now - updated < _REPO_LIST_TTL:
                alive = [p for p in cached_list["repos"] if os.path.isdir(p)]
                if alive:
                    _repo_set_cache.update({"t": now, "repos": alive})
                    return alive
    roots = {}
    for scan_root in (_DEVELOPMENT_ROOT, _HERMES_WORKTREES_ROOT):
        if os.path.isdir(scan_root):
            for current, dirs, _files in os.walk(scan_root, followlinks=False):
                if ".git" in dirs or os.path.isfile(os.path.join(current, ".git")):
                    repo = os.path.realpath(current)
                    try:
                        roots[repo] = os.path.getmtime(os.path.join(current, ".git"))
                    except OSError:
                        roots[repo] = 0.0
                    dirs.remove(".git") if ".git" in dirs else None
                dirs[:] = [d for d in dirs if d not in _REPO_SKIP_DIRS]
    # 家目录顶层的独立仓库（如 ~/chezmoi、~/dotfiles、~/nvim）不在
    # ~/development 下，但也是用户关心的活动来源。只查一层，不做深度 walk。
    home = os.path.expanduser("~")
    try:
        for entry in os.scandir(home):
            if not entry.is_dir(follow_symlinks=False):
                continue
            if os.path.isdir(os.path.join(entry.path, ".git")):
                repo = os.path.realpath(entry.path)
                try:
                    roots[repo] = os.path.getmtime(os.path.join(repo, ".git"))
                except OSError:
                    roots[repo] = 0.0
    except OSError:
        pass
    # Linked worktrees share one common Git directory and should appear as one repo.
    grouped = {}
    for repo, mtime in roots.items():
        common = _git(repo, ["rev-parse", "--git-common-dir"]).strip()
        common = os.path.realpath(os.path.join(repo, common)) if common else repo
        current = grouped.get(common)
        if current is None or (repo.startswith(_DEVELOPMENT_ROOT + os.sep)
                               and not current[0].startswith(_DEVELOPMENT_ROOT + os.sep)):
            grouped[common] = (repo, mtime)
    roots = {repo: mtime for repo, mtime in grouped.values()}
    discovered_roots = set(roots)
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
    for d in dirs:
        if not os.path.isdir(d):
            continue
        r = _git_root(d)
        if not r:
            continue
        if r in discovered_roots:
            continue
        try:
            roots[r] = os.path.getmtime(os.path.join(r, ".git"))
        except OSError:
            roots[r] = 0.0
    repos = [p for p, _ in sorted(roots.items(), key=lambda kv: -kv[1])]
    _repo_set_cache.update({"t": now, "repos": repos})
    _save_repo_list(repos)
    return repos


def _parse_one_repo(repo, per_repo=30):
    """解析单个仓库的最近提交事件（含改动文件）。"""
    name = os.path.basename(repo.rstrip("/"))
    text = _git(repo, ["log", "--all", "-n", str(per_repo), "--name-status",
                       "--format=COMMIT%x1f%h%x1f%ct%x1f%s%x1f%an"])
    out = []
    cur = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("COMMIT\x1f"):
            if cur:
                out.append(cur)
            parts = line.split("\x1f")
            if len(parts) != 5:
                cur = None
                continue
            _, h, ct, subj, author = parts
            try:
                ts = float(ct)
            except ValueError:
                cur = None
                continue
            cur = {
                "ts": ts,
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                "gid": h,
                "name": name,
                "repo": name,
                "kind": "commit",
                "text": f"{subj} — {author}",
                "subject": subj,
                "author": author,
                "src": "commit",
                "files": [],
            }
        elif cur and "\t" in raw_line:
            f_parts = raw_line.split("\t")
            st = f_parts[0].strip()[:1].upper() if f_parts[0].strip() else "M"
            cur["files"].append({"status": st, "path": f_parts[-1].strip()})
    if cur:
        out.append(cur)
    return out


def _repo_signature(repo):
    """轻量签名: 一次 git 调用取全部分支最新提交号+时间。
    签名不变则说明该仓库没有新提交，可直接复用缓存，不跑 log --name-status。"""
    text = _git(repo, ["log", "--all", "-1", "--format=%H%x1f%ct"]).strip()
    return text


def _parse_repo_commits_sync(per_repo=30, total=150, force=False):
    """Rebuild and persist the repo commit feed; used by the periodic collector.

    需求 #138: 逐仓库增量——先用一次 git log -1 拿签名，未变动的仓库
    直接复用磁盘缓存事件，只有 HEAD/分支变化时才跑完整的 log --name-status。
    """
    with _repo_ev_lock:
        now = time.time()
        if _repo_ev_cache["data"] is None:
            _load_repo_events_snapshot()
        # Reload the snapshot so an independent collector invocation sees the
        # latest persisted version before deciding whether a refresh is needed.
        if _repo_ev_cache["data"] is not None:
            _load_repo_events_snapshot()
        if not force and _repo_ev_cache["data"] is not None and now - _repo_ev_cache["t"] < 60:
            return _repo_ev_cache["data"]
        repos = agent_repos()
        prev = _load_repo_events_cache()
        new_cache = {}
        out = []
        seen_commits = set()
        for repo in repos:
            sig = _repo_signature(repo)
            ent = prev.get(repo)
            if (sig and ent and ent.get("sig") == sig
                    and isinstance(ent.get("events"), list)):
                repo_events = ent["events"]
            else:
                repo_events = _parse_one_repo(repo, per_repo=per_repo)
            new_cache[repo] = {"sig": sig, "events": repo_events}
            for e in repo_events:
                gid = e.get("gid")
                if gid in seen_commits:
                    continue
                seen_commits.add(gid)
                out.append(e)
        # 签名集合未变且事件数量一致时不必重写磁盘（省 I/O）。
        prev_sigs = {k: v.get("sig") for k, v in prev.items()}
        new_sigs = {k: v.get("sig") for k, v in new_cache.items()}
        if prev_sigs != new_sigs:
            _save_repo_events_cache(new_cache)
        try:
            from svcdash.github import fetch_github_events, merge_commits
            out = merge_commits(out, fetch_github_events(), total=total)
        except Exception:
            out.sort(key=lambda x: -x["ts"])
            out = out[:total]
        _repo_ev_cache.update({"t": now, "data": out})
        _save_repo_events_snapshot(out, repos)
        return out


def refresh_repo_commits():
    """Collect all discovered project commits and atomically persist the shared feed."""
    return _parse_repo_commits_sync(force=True)


def parse_repo_commits(per_repo=30, total=150):
    """Read the latest persisted activity feed without scanning repositories."""
    with _repo_ev_lock:
        _load_repo_events_snapshot()
        return (_repo_ev_cache["data"] or [])[:total]



def _repo_one_stats(repo, include_traj=False):
    """轻量仓库索引;完整轨迹仅在打开仓库详情时计算。"""
    st = {"name": os.path.basename(repo.rstrip("/")), "path": repo,
          "branch": _git(repo, ["rev-parse", "--abbrev-ref", "HEAD"]).strip() or "—",
          "branches": 0}
    branches = _git(repo, ["branch", "--format=%(refname:short)"]).splitlines()
    st["branches"] = len(branches)
    cnt = _git(repo, ["rev-list", "--count", "HEAD"]).strip()
    st["commits"] = int(cnt) if cnt.isdigit() else None
    parts = _git(repo, ["log", "--all", "-1", "--format=%h%x1f%ct%x1f%s%x1f%an"]).strip().split("\x1f")
    if len(parts) == 4 and parts[1].isdigit():
        ts = int(parts[1])
        st["last"] = {"hash": parts[0], "ts": ts,
                      "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                      "subject": parts[2], "author": parts[3]}
    else:
        st["last"] = None
    st["size"] = None
    st["dirty"] = len([x for x in _git(repo, ["status", "--porcelain"]).splitlines() if x.strip()])
    st["files"] = sum(1 for f in _git(repo, ["ls-files"]).splitlines() if f)
    if include_traj:
        st["traj"] = _traj_data(repo)["strip"]
    return st


# ---------------- Agent 操作轨迹(时间条 + 事件流) ----------------
# 每仓库三类数据源(codex-trajectory 思想: 把原始日志投影成事件账本+时间轴):
# 1. git 提交(commit); 2. watchdog 事件(nudge/pause/restart=warn, recover=good)
#    + goal 完成台账(done); 3. OMP 会话 JSONL 全信号(见下方 _omp_parse_file)。
# 逐日色块为双行: 上行=里程碑(done>commit>warn>good), 下行=活动健康
# (error: 失败率>=10%且>=5次 > agent 工具调用; 空闲日仅上半灰条)。
# cleanup/other 只进事件流不进色条。
_TRAJ_KIND_CLS = {"commit": "commit", "complete": "done", "recover": "good",
                  "restart": "warn", "nudge": "warn", "pause": "warn",
                  "tool": "agent", "compact": "agent",
                  "error": "error", "turn": "turn", "say": "say", "exit": "exit",
                  "spawn": "spawn", "replan": "replan", "model": "model"}
_TRAJ_MILESTONE = ("done", "commit", "warn", "good")          # 上行
_TRAJ_C_KEYS = ("commit", "warn", "good", "done", "agent", "error", "turn",
                "say", "compact", "exit", "spawn", "replan", "model")  # tooltip 顺序
_TRAJ_DAYS = 14
_traj_cache = {"t": 0.0, "data": {}}          # repo -> {"strip", "events"}
_traj_wd_cache = {"t": 0.0, "by_root": None}  # 60s: watchdog/完成事件按仓库根分桶(共享快照)


# OMP 会话日志适配: ~/.omp/agent/sessions/*/*.jsonl 共 ~500MB, 按
# (path, mtime, size) 文件级增量缓存 —— 只重读在写的活跃会话; 行级先做
# 子串预筛再 json.loads(80%+ 行是 message/toolResult, 无需解析)。
# 覆盖 OMP 全部可用信号(对齐 codex-trajectory 的信息面):
#   工具调用/工具失败(含退出码与耗时)/上下文压缩(tokensBefore)/用户轮次/
#   助手声明(>=160字)/子代理 init/会话退出(signal=异常)/goal 完成(含 token
#   用量与时长)/重规划(title_change)/模型切换。
_omp_files_cache = {}   # path -> (mtime, size, cwd, label, day_counts, events)
_OMP_MARKERS = ('"tool_execution_start"', '"type":"compaction"', '"type": "compaction"',
                '"type":"session"', '"type": "session"', '"type":"session_init"',
                '"customType":"session_exit"', '"customType":"goal-completed"',
                '"type":"title_change"', '"type":"model_change"',
                '"isError":true', '"isError": true',
                '"role":"user"', '"role": "user"')


def _omp_parse_iso(ts):
    """ISO8601 Z 时间戳 -> epoch 秒;失败返回 None。"""
    from datetime import datetime, timezone
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return None


def _omp_txt(content):
    """message.content(块数组或纯文本) -> 首个 text 块的纯文本。"""
    if isinstance(content, list):
        for b in content:
            if isinstance(b, dict) and b.get("type") == "text":
                return " ".join(str(b.get("text") or "").split())
        return ""
    return " ".join(str(content or "").split())


def _omp_parse_file(path):
    """流式解析单个会话文件 -> (cwd, label, day_counts, events)。
    day_counts: {(y,m,d): {kind: n}} 全量计数; events: (ts, kind, name, text) 尾部500条。"""
    cwd, label = "", ""
    counts, evs = {}, []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not any(m in line for m in _OMP_MARKERS):
                    # assistant 声明行双条件预筛: 3.8万行里只解析带 text 块的
                    if ('"role":"assistant"' not in line
                            or '"type":"text"' not in line):
                        continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                ty = d.get("type")
                ts = _omp_parse_iso(d.get("timestamp") or "")
                if ty == "session":
                    cwd = d.get("cwd") or ""
                elif ty == "session_init":
                    if ts:
                        ag = str(d.get("agent") or "agent")
                        evs.append((ts, "spawn", ag, "subagent init · " + ag))
                elif ty == "compaction":
                    if ts:
                        tok = d.get("tokensBefore")
                        evs.append((ts, "compact", "",
                                    f"context compaction · {tok} tok" if tok is not None
                                    else "context compaction"))
                elif ty == "title":
                    label = (d.get("title") or "").strip()
                elif ty == "title_change":
                    if ts and d.get("trigger") == "replan":
                        evs.append((ts, "replan", label, str(d.get("title") or "")[:70]))
                elif ty == "model_change":
                    if ts:
                        evs.append((ts, "model", str(d.get("model") or "?"),
                                    "fallback" if d.get("resolvedModelIsFallback") else "switch"))
                elif ty == "custom":
                    ct = d.get("customType")
                    data = d.get("data") or {}
                    if ct == "tool_execution_start":
                        t2 = _omp_parse_iso(data.get("startedAt") or d.get("timestamp") or "")
                        if t2:
                            evs.append((t2, "tool", str(data.get("toolName") or "?"),
                                        str(data.get("intent") or "")[:80]))
                    elif ct == "session_exit" and ts:
                        evs.append((ts, "exit", "",
                                    "%s/%s" % (data.get("kind") or "?", data.get("reason") or "?")))
                    elif ct == "goal-completed" and ts:
                        mins = int((data.get("timeUsedSeconds") or 0) // 60)
                        evs.append((ts, "complete", "",
                                    "OMP goal · %s tok · %d min" % (data.get("tokensUsed") or "?", mins)))
                elif ty == "message":
                    m = d.get("message") or {}
                    role = m.get("role")
                    if role == "user" and ts:
                        txt = _omp_txt(m.get("content"))
                        if txt:
                            evs.append((ts, "turn", "", txt[:80]))
                    elif role == "assistant" and ts:
                        c = m.get("content")
                        if isinstance(c, list):
                            for b in c:
                                if (isinstance(b, dict) and b.get("type") == "text"
                                        and len(b.get("text") or "") >= 160):
                                    evs.append((ts, "say", "",
                                                " ".join(str(b.get("text") or "").split())[:110]))
                                    break
                    elif role == "toolResult" and m.get("isError") and ts:
                        det = m.get("details") or {}
                        wall = det.get("wallTimeMs")
                        parts = []
                        if det.get("exitCode") is not None:
                            parts.append("exit %s" % det["exitCode"])
                        if isinstance(wall, (int, float)):
                            parts.append("%.1fs" % (wall / 1000))
                        txt = _omp_txt(m.get("content"))
                        if txt:
                            parts.append(txt[:70])
                        evs.append((ts, "error", str(m.get("toolName") or "?"), " · ".join(parts)))
    except OSError:
        pass
    for ts, kind, _n, _t in evs:
        lt = time.localtime(ts)
        k = (lt.tm_year, lt.tm_mon, lt.tm_mday)
        c = counts.setdefault(k, {})
        c[kind] = c.get(kind, 0) + 1
    return cwd, label, counts, evs[-500:]


def _traj_omp_by_root(window_sec):
    """OMP 会话事件按仓库根分桶(文件级增量缓存, 无时间过期)。"""
    from svcdash.agents import OMP_SESSION_ROOT
    cutoff = time.time() - window_sec
    by_root = {}
    if not os.path.isdir(OMP_SESSION_ROOT):
        return by_root
    for dp, _dn, fns in os.walk(OMP_SESSION_ROOT):
        for fn in fns:
            if not fn.endswith(".jsonl"):
                continue
            p = os.path.join(dp, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_mtime < cutoff:
                continue                      # 窗口外的会话文件整体跳过
            ent = _omp_files_cache.get(p)
            if ent and ent[0] == st.st_mtime and ent[1] == st.st_size:
                cwd, label, counts, evs = ent[2], ent[3], ent[4], ent[5]
            else:
                cwd, label, counts, evs = _omp_parse_file(p)
                _omp_files_cache[p] = (st.st_mtime, st.st_size, cwd, label, counts, evs)
            if not cwd:
                continue
            root = _git_root(cwd)
            if not root:
                continue
            bucket = by_root.setdefault(root, {"days": {}, "events": []})
            for k, kinds in counts.items():
                d = bucket["days"].setdefault(k, {})
                for kk, n in kinds.items():
                    d[kk] = d.get(kk, 0) + n
            # 存引用而非逐事件 dict(86k 事件建 dict 会吃 ~40MB, 128M 限额吃不消);
            # dict 投影推迟到 _traj_data 请求时做, 用后即弃。
            gid = fn.rsplit("_", 1)[-1][:8]
            bucket["events"].append((gid, label or gid, evs))
    return by_root


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
    """单仓库轨迹: strip(近14天逐日双行色块) + events(时间倒序详情, 上限500)。"""
    now = time.time()
    cached = _traj_cache["data"].get(repo)
    if cached and now - _traj_cache["t"] < 60:
        return cached
    evs = []
    for line in _git(repo, ["log", "--all", "-n", "400", "--format=%h%x1f%ct%x1f%s"]).splitlines():
        parts = line.split("\x1f")
        if len(parts) != 3:
            continue
        try:
            ts = float(parts[1])
        except ValueError:
            continue
        evs.append({"ts": ts, "kind": "commit", "gid": parts[0], "name": "", "text": parts[2]})
    wd_evs = _traj_watchdog_by_root().get(repo) or []
    evs.extend(wd_evs)
    omp = _traj_omp_by_root(_TRAJ_DAYS * 86400).get(repo) or {}
    # 完成去重: OMP goal-completed 与完成台账记同一 goal —— 台账时间戳 30min
    # 窗内已有时, 丢弃 OMP 侧重复(不同 goal 同日完成互不影响)
    wd_done_ts = [e["ts"] for e in wd_evs if e["kind"] == "complete"]
    cutoff = time.time() - _TRAJ_DAYS * 86400
    for gid, name, tuples in omp.get("events") or []:
        for ts, kind, tool, intent in tuples:
            if kind == "complete" and any(abs(ts - w) < 1800 for w in wd_done_ts):
                continue
            if ts < cutoff:
                continue
            evs.append({"ts": ts, "kind": kind, "gid": gid, "name": name,
                        "text": (tool + (" · " + intent if intent else ""))[:120]})
    evs.sort(key=lambda x: -x["ts"])
    # 逐日分桶: 里程碑(事件计数) + 活动类别(omp days 全量计数)
    by_day = {}
    for e in evs:
        cls = _TRAJ_KIND_CLS.get(e["kind"])
        if cls not in _TRAJ_MILESTONE:
            continue        # 活动类别由 omp days(全量)入桶, 不重复计
        lt = time.localtime(e["ts"])
        d = by_day.setdefault((lt.tm_year, lt.tm_mon, lt.tm_mday), {})
        d[cls] = d.get(cls, 0) + 1
    for k, kinds in (omp.get("days") or {}).items():
        d = by_day.setdefault(k, {})
        for kk, n in kinds.items():
            key = "agent" if kk == "tool" else kk
            if key == "complete":
                continue      # 完成计数走里程碑桶(已去重)
            d[key] = d.get(key, 0) + n
    base = time.localtime()
    noon = time.mktime((base.tm_year, base.tm_mon, base.tm_mday, 12, 0, 0, 0, 0, -1))
    strip = []
    for i in range(_TRAJ_DAYS - 1, -1, -1):
        lt = time.localtime(noon - i * 86400)
        c = by_day.get((lt.tm_year, lt.tm_mon, lt.tm_mday)) or {}
        top = next((k for k in _TRAJ_MILESTONE if c.get(k)), None)
        err, tools = c.get("error", 0), c.get("agent", 0)
        bot = ("error" if err >= 10 and err * 100 >= tools * 8
               else ("agent" if tools else None))
        keys = [k for k in _TRAJ_C_KEYS if c.get(k)]
        strip.append({"d": "%d/%d" % (lt.tm_mon, lt.tm_mday), "cls": top, "bot": bot,
                      "n": sum(c[k] for k in keys),
                      "c": {k: c[k] for k in keys}})
    data = {"strip": strip,
            "events": [{"ts": e["ts"],
                        "time": time.strftime("%m-%d %H:%M", time.localtime(e["ts"])),
                        "kind": e["kind"], "cls": _TRAJ_KIND_CLS.get(e["kind"]) or "",
                        "name": e.get("name") or "", "text": (e.get("text") or "")[:200]}
                       for e in evs[:500]]}
    _traj_cache["data"][repo] = data
    _traj_cache["t"] = now
    return data


def repo_trajectory(name, lang=DEFAULT_LANG):
    """/api/trajectory?repo=NAME -> 单仓库完整轨迹(strip + 事件流)。"""
    for repo in agent_repos():
        if os.path.basename(repo.rstrip("/")) == name:
            d = _traj_data(repo)
            return {"ok": True, "repo": name, "path": repo, "days": _TRAJ_DAYS, **d}
    return {"ok": False, "msg": t(lang, "mm_traj_unknown_repo")}


def repo_commit_diff(repo_name, commit_sha, max_bytes=100 * 1024, lang=DEFAULT_LANG):
    """获取指定仓库特定提交的 diff (含安全过滤与截断防护)"""
    if not repo_name or not commit_sha:
        return {"ok": False, "error": t(lang, "mm_diff_missing")}
    if not re.match(r"^[A-Za-z0-9_.-]+$", repo_name) or not re.match(r"^[0-9a-fA-F]{4,40}$", commit_sha):
        return {"ok": False, "error": t(lang, "mm_diff_invalid")}

    target_repo = None
    for r in agent_repos():
        bn = os.path.basename(r.rstrip("/"))
        if bn.lower() == repo_name.lower():
            target_repo = r
            break

    if not target_repo:
        return {"ok": False, "error": t(lang, "mm_diff_repo_notfound", repo=repo_name)}

    raw = _git(target_repo, ["show", "--stat", "-p", "--color=never", commit_sha])
    if not raw:
        return {"ok": False, "error": t(lang, "mm_diff_commit_notfound", sha=commit_sha, repo=repo_name)}

    truncated = False
    if len(raw) > max_bytes:
        raw = raw[:max_bytes] + "\n\n... [Diff truncated: exceeded size limit] ..."
        truncated = True

    return {
        "ok": True,
        "repo": repo_name,
        "sha": commit_sha,
        "diff": raw,
        "truncated": truncated
    }


def repo_stats(refresh=False):
    """Return the persisted repo index immediately; refresh stale data in one worker."""
    repos = agent_repos()
    if _repo_stats_cache["data"] is None:
        _load_repo_stats_snapshot()
    cached = _repo_stats_cache["data"]
    cached_paths = {r.get("path") for r in cached["repos"]} if cached else set()
    missing = set(repos) - cached_paths
    stale = time.time() - _repo_stats_cache["t"] >= 60
    if (refresh or missing or stale or cached is None) and _repo_refresh_lock.acquire(False):
        threading.Thread(target=_refresh_repo_stats, args=(repos,), daemon=True,
                         name="svc-repo-index-refresh").start()
    if cached is None:
        return {"updated": time.time(), "repos": [{
            "name": os.path.basename(p.rstrip("/")), "path": p, "branch": "…",
            "commits": None, "last": None, "size": None, "dirty": 0,
            "files": 0, "traj": []} for p in repos]}
    if missing:
        cached = dict(cached)
        cached["repos"] = cached["repos"] + [{
            "name": os.path.basename(p.rstrip("/")), "path": p, "branch": "…",
            "commits": None, "last": None, "size": None, "dirty": 0,
            "files": 0, "traj": []} for p in repos if p not in cached_paths]
    return cached
