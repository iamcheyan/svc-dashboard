import glob, json, os, re, subprocess, time
from datetime import datetime
from svcdash.i18n import t, DEFAULT_LANG
# ---------------- OMP Goal 状态 ----------------
# 只读扫描 OMP 的 session JSONL 与 tmux pane，不执行任何控制命令。
OMP_SESSION_ROOT = "/home/tetsuya/.omp/agent/sessions"
_omp_cache = {"t": 0.0, "data": None}

def _omp_tail(path, limit=512 * 1024):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit))
            raw = f.read().decode("utf-8", "replace")
        return raw.splitlines()[1:] if size > limit else raw.splitlines()
    except OSError:
        return []

def _omp_tmux_panes():
    panes = []
    try:
        fmt = "#{session_name}|#{window_index}.#{pane_index}|#{pane_current_command}|#{pane_title}|#{pane_current_path}"
        cmd = ["tmux", "list-panes", "-a", "-F", fmt]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout
        if not out.strip() and os.geteuid() == 0:
            out = subprocess.run(["sudo", "-u", "tetsuya"] + cmd,
                                 capture_output=True, text=True, timeout=2).stdout
        for line in out.splitlines():
            p = line.split("|", 4)
            if len(p) == 5 and (p[2] == "bun" or "omp" in p[3].lower()):
                panes.append({"tmux": f"{p[0]}:{p[1]}", "title": p[3], "cwd": p[4]})
    except (OSError, subprocess.SubprocessError):
        pass
    return panes

def scan_omp():
    now = time.time()
    if _omp_cache["data"] is not None and now - _omp_cache["t"] < 8:
        return _omp_cache["data"]
    panes = _omp_tmux_panes()
    # 只扫 <OMP_SESSION_ROOT>/<workdir>/*.jsonl 一层 —— recursive glob 会把
    # 会话子目录里的附件(如 zdocs goal 的 Maps.jsonl/ProtoS2C.jsonl 等
    # agent 产物)也当 session 读,徒增 IO 且永远解析不出 goal。
    # 会话文件名形如 2026-08-13T22-47-04-284Z_<uuid>.jsonl,据此过滤。
    session_files = []
    for root, dirs, files in os.walk(OMP_SESSION_ROOT):
        if os.path.dirname(root) == OMP_SESSION_ROOT:
            dirs[:] = []  # 不深入会话子目录
        for fn in files:
            if fn.endswith(".jsonl") and re.search(r"_[0-9a-f-]{36}\.jsonl$", fn):
                session_files.append(os.path.join(root, fn))
    results = []
    for path in session_files:
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        goal, last_ts, last_tool = None, mtime, ""
        for raw in _omp_tail(path):
            try:
                event = json.loads(raw)
            except (ValueError, TypeError):
                continue
            ts = event.get("timestamp")
            if ts:
                try:
                    last_ts = max(last_ts, datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
                except ValueError:
                    pass
            data = event.get("data") or {}
            if event.get("type") == "mode_change" and data.get("goal"):
                goal = data["goal"]
            if event.get("type") == "custom" and data.get("toolName"):
                last_tool = str(data["toolName"])
        if not goal:
            continue
        session_id = os.path.basename(path).rsplit("_", 1)[-1][:-6]
        status = str(goal.get("status") or "active").lower()
        if status in ("completed", "complete", "done"):
            health = "completed"
        elif status == "blocked":
            health = "blocked"
        elif now - last_ts > 900:
            health = "idle"
        else:
            health = "running"
        objective = " ".join(str(goal.get("objective") or "").split())
        if len(objective) > 180:
            objective = objective[:180] + "…"
        parent = os.path.basename(os.path.dirname(path))
        folded = re.sub(r"[^a-z0-9]", "", parent.lower())
        matches = [x for x in panes if parent and parent in x["cwd"]]
        if not matches and folded:
            matches = [x for x in panes if folded in re.sub(r"[^a-z0-9]", "", x["cwd"].lower())]
        results.append({
            "id": session_id, "cwd": matches[0]["cwd"] if matches else parent,
            "tmux": matches[0]["tmux"] if matches else "—",
            "pane_title": matches[0]["title"] if matches else "—",
            "goal": objective, "status": status, "health": health,
            "last_activity": datetime.fromtimestamp(last_ts).isoformat(timespec="seconds"),
            "idle_seconds": max(0, int(now - last_ts)), "tool": last_tool or "—",
        })
    results.sort(key=lambda x: (x["health"] not in ("running", "blocked"), -x["idle_seconds"]))
    _omp_cache.update({"t": now, "data": results})
    return results


# ---------------- Codex Agent 状态 ----------------
# 进程 + shell_snapshot 会话标识,只读。
CODEX_SNAPSHOT_DIR = "/home/tetsuya/.codex/shell_snapshots"
_codex_cache = {"t": 0.0, "data": None}


def scan_codex():
    now = time.time()
    if _codex_cache["data"] is not None and now - _codex_cache["t"] < 8:
        return _codex_cache["data"]
    agents = []
    try:
        out = subprocess.run(["ps", "-eo", "pid,etime,args"], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return agents
    for line in out.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, etime, args = parts
        # 只认 native codex 执行体,排除 node wrapper 和 fnm 的壳
        if "codex-linux-x64" not in args:
            continue
        cwd = "—"
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            pass
        agents.append({"agent": "codex", "pid": pid, "etime": etime,
                       "cwd": cwd, "health": "running"})
    # 会话标识:shell_snapshots 最新文件
    sid, snap_ts = "—", None
    try:
        snaps = [f for f in os.listdir(CODEX_SNAPSHOT_DIR) if f.endswith(".sh")]
        if snaps:
            newest = max(snaps, key=lambda f: os.path.getmtime(os.path.join(CODEX_SNAPSHOT_DIR, f)))
            sid = newest.split(".", 1)[0]
            snap_ts = os.path.getmtime(os.path.join(CODEX_SNAPSHOT_DIR, newest))
    except OSError:
        pass
    for a in agents:
        a["session_id"] = sid
        a["last_activity"] = datetime.fromtimestamp(snap_ts).isoformat(timespec="seconds") if snap_ts else "—"
        a["idle_seconds"] = max(0, int(now - snap_ts)) if snap_ts else 0
    _codex_cache.update({"t": now, "data": agents})
    return agents


# ---------------- TMUX 状态 ----------------
# 全量会话/窗格:会话、窗格、命令、标题、cwd、尺寸、活动状态。
_tmux_cache = {"t": 0.0, "data": None}


def scan_tmux():
    now = time.time()
    if _tmux_cache["data"] is not None and now - _tmux_cache["t"] < 5:
        return _tmux_cache["data"]
    panes = []
    fmt = ("#{session_name}|#{window_index}.#{pane_index}|#{pane_current_command}|"
           "#{pane_title}|#{pane_current_path}|#{pane_width}x#{pane_height}|#{pane_active}|"
           "#{pane_pid}")
    cmd = ["tmux", "list-panes", "-a", "-F", fmt]
    out = ""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout
    except Exception:
        pass
    if not out.strip() and os.geteuid() == 0:
        try:
            out = subprocess.run(["sudo", "-u", "tetsuya"] + cmd,
                                 capture_output=True, text=True, timeout=2).stdout
        except Exception:
            pass
    for line in out.splitlines():
        p = line.split("|", 7)
        if len(p) != 8:
            continue
        session, winpane, cmdline, title, path, size, active, pid = p
        panes.append({
            "session": session, "pane": winpane, "command": cmdline or "—",
            "title": title or "—", "cwd": path or "—", "size": size or "—",
            "active": active == "1", "pid": pid or "—",
        })
    panes.sort(key=lambda x: (not x["active"], x["session"], x["pane"]))
    _tmux_cache.update({"t": now, "data": panes})
    return panes


# ---------------- Agent 日志 / 实时画面 ----------------
# 点击 agent 标题展开:OMP jsonl 事件时间线 + tmux 窗格 capture-pane。
def _event_text(event, lang=DEFAULT_LANG):
    """把一条 omp session 事件压成可读摘要行,返回 (kind, text)。

    注意: 局部变量禁止命名 t —— 它会遮蔽 i18n 函数 t(lang,key),
    曾导致 /api/agentlog 对 session_exit/compaction 事件 500。
    """
    etype = event.get("type", "")
    ts = event.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
    except (ValueError, AttributeError):
        ts = ""
    data = event.get("data") or {}
    msg = event.get("message") or {}
    role = msg.get("role", "")
    if etype == "message" and role == "assistant":
        parts = []
        content = msg.get("content") or []
        if isinstance(content, str):
            parts.append(content)
        else:
            for c in content:
                if isinstance(c, dict) and c.get("type") == "text":
                    parts.append(c.get("text", ""))
        text = " ".join(str(p) for p in parts if p)
        return ("assistant", f"[{ts}] {text[:160]}")
    if etype == "message" and role == "user":
        text = msg.get("content", "")
        if isinstance(text, list):
            text = " ".join(c.get("text", "") for c in text if isinstance(c, dict) and c.get("type") == "text")
        return ("user", f"[{ts}] → {str(text)[:100]}")
    if etype == "message" and role == "toolResult":
        out = msg.get("output") or msg.get("content") or ""
        if isinstance(out, list):
            out = " ".join(str(c.get("text", "")) for c in out if isinstance(c, dict))
        return ("tool", f"[{ts}] ↩ {str(out)[:90]}")
    if etype == "custom":
        ct = data.get("customType") or event.get("customType") or ""
        if "tool_execution_start" in ct:
            return ("tool", f"[{ts}] tool: {data.get('toolName', '—')}")
        if "tool_execution_end" in ct:
            return ("tool", f"[{ts}] ok: {data.get('toolName', '—')}")
        if "session_exit" in ct:
            return ("exit", f"[{ts}] {t(lang, 'aev_exit', r=data.get('reason', '—'))}")
        if "mode_change" in ct:
            goal = data.get("goal") or {}
            obj = " ".join(str(goal.get("objective") or "").split())
            return ("goal", f"[{ts}] {t(lang, 'aev_goal', o=obj[:120])}")
        return ("evt", f"[{ts}] · {ct}")
    if etype == "compaction":
        return ("goal", f"[{ts}] {t(lang, 'aev_comp', s=str(event.get('summary', ''))[:120])}")
    return ("evt", f"[{ts}] · {etype}") if ts else None


def scan_agent_log(sid, lang=DEFAULT_LANG):
    """OMP session 事件时间线(尾部最近 ~18 条)。"""
    if not sid:
        return []
    path = None
    for p in glob.glob(os.path.join(OMP_SESSION_ROOT, "**", "*.jsonl"), recursive=True):
        if os.path.basename(p).rsplit("_", 1)[-1][:-6] == sid:
            path = p
            break
    if not path:
        return []
    events = []
    for raw in reversed(_omp_tail(path)):
        try:
            event = json.loads(raw)
        except (ValueError, TypeError):
            continue
        row = _event_text(event, lang)
        if row and row[0] != "evt":
            events.append(row)
        if len(events) >= 18:
            break
    return list(reversed(events))


def _tmux_capture(tmux_ref):
    """capture-pane 最近 40 行;tmux_ref 形如 zircon:1.1 或 'zircon:1.1'。"""
    if not tmux_ref or tmux_ref == "—":
        return None
    cmd = ["tmux", "capture-pane", "-t", tmux_ref, "-p", "-e"]
    out = ""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
        if not out.strip() and os.geteuid() == 0:
            out = subprocess.run(["sudo", "-u", "tetsuya"] + cmd,
                                 capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    lines = [ln for ln in out.splitlines() if ln.strip()]
    return lines[-40:] if lines else None


def _tmux_by_cwd(cwd):
    """按 cwd 在全量 tmux 窗格里找 'session:pane'。"""
    if not cwd:
        return None
    for p in scan_tmux():
        if p["cwd"] and (p["cwd"] == cwd or cwd.startswith(p["cwd"])):
            return f'{p["session"]}:{p["pane"]}'
    return None
def _tmux_run(args, timeout=2):
    """以当前用户跑 tmux 子命令;root 时降级 sudo -u tetsuya(输出为空才降级)。"""
    cmd = ["tmux"] + args
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    if not out.strip() and os.geteuid() == 0:
        try:
            out = subprocess.run(["sudo", "-n", "-u", "tetsuya"] + cmd,
                                 capture_output=True, text=True, timeout=timeout).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
    return out
