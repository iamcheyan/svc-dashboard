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
    for line in _git(repo, ["log", "-n", "400", "--format=%h%x1f%ct%x1f%s"]).splitlines():
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
