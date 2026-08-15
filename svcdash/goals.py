import glob, json, os, re, subprocess, time
from svcdash.i18n import t, DEFAULT_LANG
from svcdash.agents import (_tmux_run, _omp_tmux_panes, _tmux_capture,
                            _tmux_by_cwd, scan_tmux, _omp_tail,
                            OMP_SESSION_ROOT, _event_text)
# ---------------- Goal 进度卡片 / 负载水位 / 事件时间线 ----------------
# 只读采集: goal_watchdog.sh 的 GOALS 数组 + goal-completed 台账 +
# watchdog 日志 + tmux pane 实时画面 + session jsonl 活跃度。
# 全部在请求时同步采集(8s 缓存),无后台线程;解析失败一律降级不抛错。
WATCHDOG_SCRIPT = "/home/tetsuya/development/Mir3-Research/scripts/goal_watchdog.sh"
WATCHDOG_LOG = "/home/tetsuya/.omp/logs/goal-watchdog.log"
GOAL_COMPLETED_LOG = "/home/tetsuya/.omp/logs/goal-completed.log"
OMP_BIN = "/home/tetsuya/.bun/bin/omp"
CTX_WARN_K = 800.0    # 上下文 > 800K 黄色警示
CTX_STOP_K = 1200.0   # 上下文 > 1.2M 红色"建议停止"
GOAL_STALLED_SEC = 600  # 最近活动 > 10 分钟标灰(watchdog 会处理)

_wd_goals_cache = {"t": 0.0, "data": None}


def watchdog_goals():
    """解析 goal_watchdog.sh 的 GOALS 数组: gid|jsonl|tmux会话|workdir|LABEL。
    第5字段以 / 开头时是 state 文件路径而非 LABEL。"""
    now = time.time()
    if _wd_goals_cache["data"] is not None and now - _wd_goals_cache["t"] < 30:
        return _wd_goals_cache["data"]
    goals = {}
    try:
        with open(WATCHDOG_SCRIPT, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        block = re.search(r"GOALS=\((.*?)\n\)", text, re.S)
        if block:
            for entry in re.findall(r'"([^"]+)"', block.group(1)):
                parts = entry.split("|")
                if len(parts) < 4:
                    continue
                label = parts[4].strip() if len(parts) > 4 and not parts[4].startswith("/") else ""
                goals[parts[0]] = {"jsonl": parts[1], "session": parts[2],
                                   "workdir": parts[3], "label": label}
    except OSError:
        pass
    _wd_goals_cache.update({"t": now, "data": goals})
    return goals


def _tail_lines(path, limit=64 * 1024):
    """读文件尾部 limit 字节的非空行;失败返回空列表。"""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit))
            raw = f.read().decode("utf-8", "replace")
        return [ln for ln in raw.splitlines() if ln.strip()]
    except OSError:
        return []


def _wd_event_kind(msg):
    """watchdog 日志消息 -> 事件类型。
    cleanup 判在 complete 之前: 'cleanup: recorded completed goal' 里
    含 'completed' 子串,先判 complete 会把清理行误标成完成。
    resumed/recovered = 恢复; relaunch/recreate = 进程死亡后重启。"""
    low = msg.lower()
    if "cleanup" in low:
        return "cleanup"
    if "commit" in low:
        return "commit"
    if "complete" in low:
        return "complete"
    if "resumed" in low or "recovered" in low:
        return "recover"
    if "relaunch" in low or "recreat" in low:
        return "restart"
    if "driving" in low or "nudge" in low:
        return "nudge"
    if "paused" in low:
        return "pause"
    return "other"


_COMPL_RE = re.compile(
    r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\] goal=([\w-]+) label=(.*?) status=(\w+)[ \t]*\n"
    r"\s*transcript=(\S+)[ \t]*\n"
    r"\s*workdir=(\S+)[ \t]*\n"
    r"\s*resume_cmd:\s*(.+?)[ \t]*\n", re.S)


def parse_completed_goals(limit=50):
    """goal-completed.log -> 完成条目列表(时间倒序,最多 limit 条)。
    格式不对的块直接跳过,不抛错。"""
    try:
        with open(GOAL_COMPLETED_LOG, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return []
    out = []
    try:
        for m in _COMPL_RE.finditer(text):
            try:
                ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                continue
            out.append({"ts": ts, "time": m.group(1), "gid": m.group(2),
                        "label": m.group(3).strip(), "status": m.group(4),
                        "transcript": m.group(5), "workdir": m.group(6),
                        "resume_cmd": m.group(7).strip()})
    except Exception:
        pass
    out.sort(key=lambda x: -x["ts"])
    return out[:limit]


_WD_LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \[([0-9a-f]+)\] (.*)$")



def parse_watchdog_events(limit=20):
    """goal-watchdog.log 尾部 -> 事件列表(时间倒序);不匹配的行跳过。"""
    wd = watchdog_goals()
    out = []
    for line in _tail_lines(WATCHDOG_LOG, limit=96 * 1024):
        m = _WD_LINE_RE.match(line)
        if not m:
            continue
        try:
            ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
        gid, msg = m.group(2), m.group(3)
        g = wd.get(gid) or {}
        name = g.get("label") or g.get("session") or ""
        if not name:
            sm = re.search(r"session '([^']+)'", msg)
            name = sm.group(1) if sm else gid[:8]
        out.append({"ts": ts, "time": m.group(1), "gid": gid, "name": name,
                    "kind": _wd_event_kind(msg), "text": msg})
        if len(out) >= limit * 3:  # 只需尾部,再多就停
            break
    out = out[-limit:]
    out.sort(key=lambda x: -x["ts"])
    return out


def merge_events(wd_events, completed, commits=None, limit=24):
    """watchdog 事件 + 完成台账 + 仓库提交合并为一条时间线(时间倒序)。
    每条带 src 标记(watchdog / done / commit),前端日志页按来源筛选。"""
    merged = [{"ts": e["ts"], "time": e["time"], "gid": e["gid"], "name": e["name"],
               "kind": e["kind"], "text": e["text"], "src": "watchdog"}
              for e in wd_events]
    for c in completed:
        merged.append({"ts": c["ts"], "time": c["time"], "gid": c["gid"],
                       "name": c["label"] or c["gid"][:8], "kind": "complete",
                       "text": c["transcript"], "src": "done"})
    merged.extend(commits or [])
    merged.sort(key=lambda x: -x["ts"])
    return merged[:limit]

_CTX_GOAL_RE = re.compile(r"\bGoal\s+(\d+(?:\.\d+)?)\s*([KM]?)\b")
_CTX_EDGE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([KM])\s*[─━─]{2,}\s*╮")
_RETRY_RE = re.compile(r"Retrying \((\d+)(?:\)|\s*/\s*10)")
_PHASE_RE = re.compile(r"^[IVXLCDM]+\.\s+\S.*?\d+\s*/\s*\d+\s*$")


def parse_ctx_k(text):
    """从 pane 文本解析 omp TUI 上下文体积,返回 K 为单位的数值;抓不到返回 None。
    两种形态: 头部 `Goal 45K` / 边框右侧 `──── 554K ──╮`。"""
    m = _CTX_GOAL_RE.search(text) or _CTX_EDGE_RE.search(text)
    if not m:
        return None
    try:
        n = float(m.group(1))
    except (ValueError, IndexError):
        return None
    unit = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
    if unit == "M":
        n *= 1024
    elif unit == "G":
        n *= 1024 * 1024
    return n  # 无单位按 K 计


def ctx_level(k):
    """>1.2M 建议停止 / >800K 偏高 / 其余正常。"""
    if k is None:
        return "none"
    if k > CTX_STOP_K:
        return "stop"
    if k > CTX_WARN_K:
        return "warn"
    return "ok"


def parse_retry(text):
    """pane 文本里的 `Retrying (N)/10`;返回次数字符串或 None。"""
    m = _RETRY_RE.search(text)
    return m.group(1) if m else None


def parse_progress(text, limit=2):
    """尽力抓 pane 里 Todo 进度清单(`├─/└─` 行与 `II. Phase 1 · 0/3` 阶段行)。
    抓不到返回空列表,绝不报错。"""
    out = []
    try:
        for raw in text.splitlines():
            s = raw.strip().strip("│").strip()
            if not s or set(s) <= set("─━╭╮╰╯| "):
                continue
            hit = None
            if s.startswith(("├─", "└─")):
                hit = s
            else:
                t = re.sub(r"^[\s│]+", "", raw).strip()
                if _PHASE_RE.match(t):
                    hit = t
            if hit:
                hit = " ".join(hit.split())
                # 去掉残留的树形符号和纯 Output 占位行(视觉噪音,信息量为零)
                clean = re.sub(r"^[├└─│\s]+", "", hit).strip()
                if not clean or clean.lower() in ("output", "outputs"):
                    continue
                out.append(clean[:72])
    except Exception:
        return []
    return out[-limit:] if out else []


def fmt_ago(sec, lang=DEFAULT_LANG):
    """秒数 -> `42 秒前 / 5 分钟前 / 3 小时前`。"""
    if sec is None:
        return "—"
    sec = max(0, int(sec))
    if sec < 60:
        return t(lang, "g_ago_s", s=sec)
    if sec < 3600:
        return t(lang, "g_ago_m", m=sec // 60)
    return t(lang, "g_ago_h", h=sec // 3600)


def _goal_jsonl_info(path):
    """读 session jsonl 尾部,返回 (最后一次 goal 状态, objective 摘要)。"""
    status, objective = None, ""
    for raw in reversed(_omp_tail(path, limit=256 * 1024)):
        try:
            event = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if event.get("type") == "mode_change":
            goal = (event.get("data") or {}).get("goal") or {}
            if goal:
                status = str(goal.get("status") or "active").lower()
                objective = " ".join(str(goal.get("objective") or "").split())
                break
    return status, objective


def _fold(s):
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())




_goals_cache = {"t": 0.0, "data": None}


def scan_goals():
    """在跑 goal 一览: watchdog GOALS 数组 + 现存 tmux omp 会话,实时采集
    状态灯/上下文体积/最近活动/重试/进度清单/resume 命令。8s 缓存。"""
    now = time.time()
    if _goals_cache["data"] is not None and now - _goals_cache["t"] < 8:
        return _goals_cache["data"]
    wd = watchdog_goals()
    done = {c["gid"] for c in parse_completed_goals(limit=100)}
    panes = scan_tmux()
    live_sessions = {p["session"] for p in panes}
    cards, covered = [], set()

    def build(name, session, gid, jsonl_path, label, workdir):
        card = {"name": name or session or "—", "session": session or "—",
                "gid": gid or "", "label": label or "", "workdir": workdir or "",
                "light": "lost", "retry": None, "ctx_k": None, "ctx_raw": "",
                "ctx_level": "none", "idle_sec": None, "progress": [],
                "resume_cmd": "", "objective": ""}
        alive = bool(session) and session in live_sessions
        # jsonl: 活动时间 + goal 状态/objective
        jstatus = None
        if jsonl_path and os.path.exists(jsonl_path):
            try:
                card["idle_sec"] = max(0, int(now - os.path.getmtime(jsonl_path)))
            except OSError:
                pass
            jstatus, objective = _goal_jsonl_info(jsonl_path)
            card["objective"] = (objective or "")[:96]
        # tmux pane: 上下文体积 / 重试 / 进度清单
        if alive:
            ref = next((f'{p["session"]}:{p["pane"]}' for p in panes
                        if p["session"] == session), None)
            text = _tmux_run(["capture-pane", "-p", "-t", ref, "-S", "-300"]) if ref else ""
            if text:
                card["ctx_k"] = parse_ctx_k(text)
                card["retry"] = parse_retry(text)
                card["progress"] = parse_progress(text)
        if card["ctx_k"] is not None:
            k = card["ctx_k"]
            card["ctx_raw"] = (f"{k / 1024:.1f}M" if k >= 1024 else f"{k:.0f}K")
        card["ctx_level"] = ctx_level(card["ctx_k"])
        # 状态灯: 会话丢失 > 已完成 > API重试 > 暂停 > 活跃
        if not alive:
            card["light"] = "lost"
        elif jstatus in ("completed", "complete", "done") or (gid and gid in done):
            card["light"] = "done"
        elif card["retry"]:
            card["light"] = "retry"
        elif jstatus == "paused":
            card["light"] = "paused"
        else:
            card["light"] = "active"
        if gid:
            card["resume_cmd"] = f"{OMP_BIN} --resume {gid} --auto-approve"
        card["stalled"] = card["idle_sec"] is not None and card["idle_sec"] > GOAL_STALLED_SEC
        return card

    # 1) watchdog 登记的 goal: tmux 会话还在,或 jsonl 半小时内还有活动
    for gid, g in wd.items():
        if gid in done:
            continue
        jsonl = g.get("jsonl") or ""
        alive = g.get("session") in live_sessions
        recent = False
        if jsonl and os.path.exists(jsonl):
            try:
                recent = now - os.path.getmtime(jsonl) < 1800
            except OSError:
                pass
        if not (alive or recent):
            continue
        covered.add(g.get("session"))
        cards.append(build(g.get("label") or g.get("session"), g.get("session"),
                           gid, jsonl, g.get("label"), g.get("workdir")))

    # 2) 现存 tmux 里的 omp 会话(watchdog 未登记的临时 goal,含 dashboard 自己)
    for p in panes:
        if p["session"] in covered:
            continue
        if p["command"] != "bun" and "omp" not in p["title"].lower():
            continue
        covered.add(p["session"])
        jsonl, gid = None, ""
        folded = _fold(p["cwd"])
        best = None
        for q in glob.glob(os.path.join(OMP_SESSION_ROOT, "*", "*.jsonl")):
            if folded and folded in _fold(os.path.basename(os.path.dirname(q))):
                try:
                    m = os.path.getmtime(q)
                except OSError:
                    continue
                if best is None or m > best[0]:
                    best = (m, q)
        if best:
            jsonl = best[1]
            base = os.path.basename(jsonl)
            m2 = re.search(r"_([0-9a-f-]{36})\.jsonl$", base)
            gid = m2.group(1) if m2 else ""
        cards.append(build(p["session"], p["session"], gid, jsonl, "", p["cwd"]))

    order = {"active": 0, "retry": 1, "paused": 2, "done": 3, "lost": 4}
    cards.sort(key=lambda c: (order.get(c["light"], 9), c["idle_sec"] or 0))
    _goals_cache.update({"t": now, "data": cards})
    return cards


def goal_detail(gid, session=""):
    """Goal 详情: 当前状态、watchdog 配置、tmux 实时画面和近期 JSONL 活动。"""
    wd = watchdog_goals()
    g = wd.get(gid or "", {})
    if not g and session:   # 按 session 兜底匹配 watchdog 行
        g = next((v for v in wd.values() if v.get("session") == session), {})
    cards = scan_goals()
    card = next((c for c in cards if (gid and c.get("gid") == gid)
                 or (session and c.get("session") == session)), None)
    tmux = g.get("session") or session or (card or {}).get("session", "")
    panes = scan_tmux()
    pane = next((p for p in panes if p["session"] == tmux), None)
    capture = _tmux_capture(f'{tmux}:{pane["pane"]}' if pane else "") or []
    path = g.get("jsonl", "")
    if not path:
        # 兜底1: watchdog 行按 session 反查到的完整 gid 已在 ev_gid; 兜底2: scan_omp 的会话 id
        omg = next((o for o in scan_omp() if o.get("id")), None) if not gid else None
        for cand in (gid, omg and omg.get("id")):
            if not cand:
                continue
            for q in glob.glob(os.path.join(OMP_SESSION_ROOT, "**", f"*_{cand}.jsonl"), recursive=True):
                path = q
                break
            if path:
                break
        # 兜底3: 按 tmux session 名在 sessions 目录找最新 jsonl(文件名无会话id时)
        if not path and tmux:
            cands = sorted(glob.glob(os.path.join(OMP_SESSION_ROOT, "**", "*.jsonl"), recursive=True), key=os.path.getmtime, reverse=True)
            for q in cands[:80]:
                try:
                    with open(q, "rb") as fh:
                        head = fh.read(4096).decode("utf-8", "ignore")
                    if tmux in head or (card and card.get("name") and card["name"] in head):
                        path = q
                        break
                except OSError:
                    continue
    activities = []
    if path and os.path.exists(path):
        for raw in reversed(_tail_lines(path, limit=256 * 1024)):
            try:
                event = json.loads(raw)
            except (ValueError, TypeError):
                continue
            row = _event_text(event, DEFAULT_LANG)
            if row and row[0] != "evt":
                activities.append({"kind": row[0], "text": row[1]})
            if len(activities) >= 40:
                break
        activities.reverse()
    # watchdog 日志里 gid 是 8 位短 id([01a0006d] 前缀), 与完整 session gid 按[:8]对齐;
    # 查询可能只给 session 名 → 经 watchdog_goals() 反查完整 gid 再匹配
    ev_gid = gid or next((k for k, v in wd.items() if v.get("session") == tmux), "")
    short = ev_gid[:8]
    events = [e for e in parse_watchdog_events(limit=80)
              if short and str(e.get("gid", ""))[:8] == short]
    return {"ok": True, "goal": card or {"gid": gid, "session": tmux},
            "watchdog": {"gid": gid, "jsonl": path, "session": tmux,
                         "workdir": g.get("workdir") or (card or {}).get("workdir", ""),
                         "label": g.get("label", "")},
            "pane": pane, "capture": capture, "activities": activities,
            "events": events}


# 快捷工具入口: 端口存活才显示(chips)
TOOL_LINKS = [("dbeditor", 8810), ("dbviewer", 8800),
              ("wilviewer", 8765), ("mapviewer", 8899)]
