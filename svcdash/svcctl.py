#!/usr/bin/env python3
"""通用服务暂停/恢复: 任意监听服务的冻结与解冻, 台账落本系统文件。

语义(与 MANAGE_UNITS 的 proc 型"暂停=杀进程"不同):
- docker 服务 → docker pause/unpause(cgroup 冻结整容器);
- 其余服务   → 对监听该端口的全部进程 SIGSTOP/SIGCONT。
  SIGSTOP 后端口仍处 LISTEN(连接排队不 accept), SIGCONT 立即恢复 —— 不需要
  知道启动命令, 天然可逆。

台账(记录在 dashboard 自己的目录, 不动 systemd):
- paused.json  : 当前暂停集合(重启后仍生效, resume 依据)
- actions.log  : 暂停/恢复历史(时间/端口/服务名/PID)

守卫: dashboard 自身 / sshd(22) / 受保护进程(omp/chrome 等)一律拒绝。
"""
import json, os, signal, subprocess, time

from svcdash.i18n import t, DEFAULT_LANG
from svcdash.procscan import listen_sockets, inode_to_pid
from svcdash.manage import _proc_owner_name, _proc_protected, PROTECTED_PROC_NAMES

STATE_DIR = "/home/tetsuya/.omp/svc-dashboard"
STATE_FILE = os.path.join(STATE_DIR, "paused.json")
HISTORY_FILE = os.path.join(STATE_DIR, "actions.log")
NO_PAUSE_PORTS = {22}          # sshd: 冻结后无法建立新连接, 自锁风险
SELF_PORTS = {80}              # dashboard 自身(默认端口)


def _log(action, rec):
    os.makedirs(STATE_DIR, exist_ok=True)
    line = "%s %s :%s %s pids=[%s]\n" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), action, rec.get("port"),
        rec.get("name", "?"), ",".join(str(p) for p in rec.get("pids", [])))
    try:
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)


def history(limit=30):
    """actions.log 尾部 -> 倒序列表。"""
    try:
        with open(HISTORY_FILE, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        return list(reversed(lines[-limit:]))
    except OSError:
        return []


def pids_on_port(port):
    """该端口当前监听进程 pid 列表(纯 /proc, 无 sudo)。"""
    try:
        inode_map = inode_to_pid()
    except Exception:
        return []
    pids = set()
    for sock in listen_sockets():
        if sock["port"] == port:
            pid = inode_map.get(sock["inode"])
            if pid:
                pids.add(pid)
    return sorted(pids)


def can_pause(entry, self_port=None):
    """服务条目是否允许 svcctl 暂停(前端按此渲染按钮; pause() 里再验一遍)。
    entry 取 /api 的 services 元素或 {port, pids, is_self, type, container_id}。"""
    try:
        port = int(entry.get("port") or 0)
    except (TypeError, ValueError):
        return False
    if port <= 0 or port in NO_PAUSE_PORTS:
        return False
    if entry.get("is_self"):
        return False
    if self_port and port == self_port:
        return False
    pids = entry.get("pids") or pids_on_port(port)
    if entry.get("type") == "docker" and entry.get("container_id"):
        return True                      # docker pause 不依赖宿主 pid
    if not pids:
        return False
    return not any(_proc_protected(p) for p in pids)


def _docker(cid, verb, timeout=15):
    try:
        proc = subprocess.run(["docker", verb, cid], capture_output=True,
                              text=True, timeout=timeout, start_new_session=True)
        return proc.returncode == 0, (proc.stderr or proc.stdout).strip()[:160]
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)[:160]


def svcctl_action(port, action, lang=DEFAULT_LANG):
    """POST /api/svcctl 入口: {port, action: pause|resume} -> 结果 dict。"""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "msg": "bad port"}
    if action not in ("pause", "resume"):
        return {"ok": False, "msg": "bad action"}
    return pause(port, lang) if action == "pause" else resume(port, lang)


def pause(port, lang=DEFAULT_LANG, self_port=None):
    state = load_state()
    if any(r.get("port") == port for r in state):
        return {"ok": False, "msg": t(lang, "sc_already_paused")}
    pids = pids_on_port(port)
    rec = {"port": port, "pids": pids, "ts": time.time(),
           "name": "?", "cmdline": "", "cwd": None, "unit": None,
           "container_id": None, "kind": "sig"}
    # 用端口上信息最全的进程补台账上下文
    from svcdash.procscan import proc_info
    for p in pids:
        info = proc_info(p)
        if info["name"] != "?":
            rec.update({"name": info["name"], "cmdline": info["cmdline"],
                        "cwd": info["cwd"], "unit": info.get("unit")})
            break
    guard = can_pause({"port": port, "pids": pids}, self_port=self_port)
    if port in NO_PAUSE_PORTS or port == (self_port or 80) or port in SELF_PORTS:
        guard = False
    if not guard:
        return {"ok": False, "msg": t(lang, "sc_refused", port=port)}
    # docker 发布端口 → 冻结整个容器
    from svcdash.procscan import docker_port_map
    dmap = docker_port_map()
    if port in dmap and dmap[port][1]:
        cname, cid = dmap[port]
        ok, err = _docker(cid, "pause")
        if not ok:
            return {"ok": False, "msg": "docker pause: " + err}
        rec.update({"kind": "docker", "container_id": cid, "name": cname})
    else:
        if not pids:
            return {"ok": False, "msg": t(lang, "sc_no_proc", port=port)}
        stopped = []
        for p in pids:
            if _proc_protected(p):
                return {"ok": False,
                        "msg": t(lang, "m_no_touch", name=_proc_owner_name(p))}
            try:
                os.kill(p, signal.SIGSTOP)
                stopped.append(p)
            except ProcessLookupError:
                continue
            except PermissionError:
                return {"ok": False, "msg": t(lang, "m_fail", a="pause", c="perm")}
        if not stopped:
            return {"ok": False, "msg": t(lang, "sc_no_proc", port=port)}
        rec["pids"] = stopped
    state.append(rec)
    save_state(state)
    _log("pause", rec)
    return {"ok": True, "msg": t(lang, "sc_paused", port=port),
            "rec": {k: rec.get(k) for k in ("port", "name", "pids", "kind", "ts")}}


def resume(port, lang=DEFAULT_LANG):
    state = load_state()
    rec = next((r for r in state if r.get("port") == port), None)
    if not rec:
        return {"ok": False, "msg": t(lang, "sc_not_paused", port=port)}
    if rec.get("kind") == "docker" and rec.get("container_id"):
        ok, err = _docker(rec["container_id"], "unpause")
        if not ok:
            return {"ok": False, "msg": "docker unpause: " + err}
    else:
        for p in rec.get("pids", []):
            try:
                os.kill(p, signal.SIGCONT)
            except (ProcessLookupError, PermissionError):
                continue
    save_state([r for r in state if r.get("port") != port])
    _log("resume", rec)
    return {"ok": True, "msg": t(lang, "sc_resumed", port=port)}


def status():
    """GET /api/svcctl: 当前暂停集合 + 历史。"""
    return {"ok": True, "paused": load_state(), "history": history()}