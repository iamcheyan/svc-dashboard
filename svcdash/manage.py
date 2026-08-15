import os, re, signal, socket, subprocess, time
from svcdash.i18n import t, DEFAULT_LANG
from svcdash.procscan import _kill_tree, listen_sockets, inode_to_pid
# ---------------- 服务管理 (systemd 单元 + 手动进程服务) ----------------
# kind="systemd": 本机关键 systemd 单元,启动/停止/重启/暂停(SIGSTOP)/恢复(SIGCONT),
#                 需要 root,走与 _run_sudo_ss 相同的免密 sudo 通道执行 systemctl。
# kind="proc":    手动拉起的非 systemd 进程(wilviewer/mapviewer 等),无 unit 文件。
#                 状态按端口检测;「暂停」= 终止进程(释放端口),「启用」= 重新 detach 拉起。
#                 dashboard 自身(监听 DEFAULT_PORT=80)绝不纳入,且 _proc_stop 有端口守卫。

MANAGE_UNITS = [
    {"id": "zircon-server", "kind": "systemd", "unit": "zircon-server.service",
     "label": "Zircon 服务器 (ServerCore)", "desc": "Mir3 传奇3 服务器主进程"},
    {"id": "zircon-bots", "kind": "systemd", "unit": "zircon-bots.service",
     "label": "Zircon 机器人 (BotRunner)", "desc": "AI 机器人运行器"},
    {"id": "tailscaled", "kind": "systemd", "unit": "tailscaled.service",
     "label": "Tailscale", "desc": "Tailscale 组网服务"},
    {"id": "wilviewer", "kind": "proc", "port": 8765,
     "label": "WilViewer 图档服务", "desc": "Mir3 客户端图档浏览 (8765)",
     "user": "tetsuya",
     "cwd": "/home/tetsuya/development/Mir3-Research",
     "cmd": ["/home/tetsuya/mir3-venv/bin/python", "Tools/web/wilviewer.py",
             "--root", "/tmp/nas_mnt/NAS/TMP/EI传奇3.0客户端", "--port", "8765"]},
    {"id": "mapviewer", "kind": "proc", "port": 8899,
     "label": "MapViewer 地图服务", "desc": "Mir3 地图浏览 (8899)",
     "user": "tetsuya",
     "cwd": "/home/tetsuya/development/Mir3-Research",
     "cmd": ["/home/tetsuya/mir3-venv/bin/python", "Tools/maps/mapviewer.py",
             "/tmp/nas_mnt/NAS/TMP/EI传奇3.0客户端/Map",
             "--data", "/tmp/nas_mnt/NAS/TMP/EI传奇3.0客户端/Data", "--port", "8899"]},
]

ACTION_LABELS = {"start": "启动", "stop": "停止", "restart": "重启",
                 "pause": "暂停", "resume": "恢复"}


def _sysctl(*args, timeout=10):
    """走免密 sudo 执行 systemctl;超时杀整个进程组,不留孤儿。"""
    try:
        proc = subprocess.Popen(
            ["sudo", "-n", "systemctl", *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out.strip(), err.strip()
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


# 受保护进程: 绝不能出现在可管理列表,也不能被任何 proc 操作触碰。
# omp(agent 引擎)与 chrome 等用户明确要求排除;bun/node 是 omp 的运行时。
PROTECTED_PROC_NAMES = ("omp", "chrome", "chromium", "bun", "node", "code")


def _proc_owner_name(pid):
    """读 /proc/<pid>/comm 拿进程名(如 omp/chrome);读不到返回空串。"""
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _proc_protected(pid):
    """目标进程是否受保护(omp/chrome 等),受保护则拒绝操作。"""
    name = _proc_owner_name(pid)
    if not name:
        return False
    base = name.lower().split("/")[-1]
    return any(base == p or base.startswith(p) for p in PROTECTED_PROC_NAMES)


def _proc_pid_on_port(port):
    """手动进程服务: 返回监听该端口的进程 pid;0=无。

    纯 /proc 扫描(读 /proc/net/tcp{6} 的 LISTEN inode → 进程 fd),无 sudo,
    不触发慢速 ss。对同用户进程可读;root 服务读不到 fd 时返回 0(降级为未运行)。
    """
    try:
        inode_map = inode_to_pid()
    except Exception:
        return 0
    for sock in listen_sockets():
        if sock["port"] != port:
            continue
        pid = inode_map.get(sock["inode"], 0)
        if pid:
            return pid
    return 0


def _proc_status(cfg):
    """手动进程服务状态: 端口有监听进程 => active,否则 inactive。"""
    pid = _proc_pid_on_port(cfg["port"])
    if pid:
        return {"ok": True, "active": "active", "sub": "running", "load": "loaded",
                "pid": str(pid), "stopped": False, "desc": cfg["desc"]}
    return {"ok": True, "active": "inactive", "sub": "not-running", "load": "not-found",
            "pid": "", "stopped": False, "desc": cfg["desc"]}


def _proc_stop(cfg, lang):
    """手动进程服务「暂停」: 终止监听该端口的进程(SIGTERM → 兜底 SIGKILL)。

    守卫1: dashboard 自身(监听 DEFAULT_PORT)绝不能停 —— 停了入口就没了。
    守卫2: 受保护进程(omp / chrome 等)绝不能停 —— 用户明确排除。
    """
    if cfg["port"] == DEFAULT_PORT:
        return {"ok": False, "msg": t(lang, "m_no_self")}
    pid = _proc_pid_on_port(cfg["port"])
    if not pid:
        return {"ok": True, "msg": t(lang, "m_done_stop")}
    if _proc_protected(pid):
        return {"ok": False, "msg": t(lang, "m_no_touch", name=_proc_owner_name(pid))}
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return {"ok": True, "msg": t(lang, "m_done_stop")}
    except PermissionError:
        return {"ok": False, "msg": t(lang, "m_fail", a=ACTION_LABELS["stop"], c="perm")}
    for _ in range(20):  # 最多等 2s
        time.sleep(0.1)
        if not _proc_pid_on_port(cfg["port"]):
            return {"ok": True, "msg": t(lang, "m_done_stop")}
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    return {"ok": True, "msg": t(lang, "m_done_stop")}


def _proc_start(cfg, lang):
    """手动进程服务「启用」: 后台 detach 拉起,日志到 ~/.omp/logs/svc-<id>.log。

    守卫: 端口已有受保护进程(omp/chrome)时拒绝,防止误伤。
    dashboard 若以 root 运行,用 sudo -u <cfg.user> 以服务属主身份拉起 ——
    手动服务依赖属主的 user-site 包(如 wilviewer 的 PIL),root 环境会缺。
    """
    pid = _proc_pid_on_port(cfg["port"])
    if pid:
        if _proc_protected(pid):
            return {"ok": False, "msg": t(lang, "m_no_touch", name=_proc_owner_name(pid))}
        return {"ok": True, "msg": t(lang, "m_done_start")}
    runas = cfg.get("user") if os.geteuid() == 0 else None
    cmd = (["sudo", "-n", "-u", runas] + cfg["cmd"]) if runas else cfg["cmd"]
    log_dir = os.path.expanduser("~/.omp/logs")
    if runas:
        log_dir = f"/home/{runas}/.omp/logs"
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"svc-{cfg['id']}.log")
    try:
        logf = open(log_path, "ab")
    except OSError:
        logf = subprocess.DEVNULL
    if runas and logf is not subprocess.DEVNULL:
        try:
            import pwd
            pw = pwd.getpwnam(runas)
            os.chown(log_path, pw.pw_uid, pw.pw_gid)
        except (ImportError, KeyError, OSError):
            pass
    try:
        proc = subprocess.Popen(
            cmd, cwd=cfg.get("cwd"), stdin=subprocess.DEVNULL,
            stdout=logf, stderr=logf, start_new_session=True,
        )
    except Exception as e:
        if logf is not subprocess.DEVNULL:
            logf.close()
        return {"ok": False, "msg": str(e)}
    if logf is not subprocess.DEVNULL:
        logf.close()
    for _ in range(200):  # 最多等 20s,确认端口起来(wilviewer 冷启动加载百万帧索引需数秒)
        time.sleep(0.1)
        if _proc_pid_on_port(cfg["port"]):
            return {"ok": True, "msg": t(lang, "m_done_start")}
    return {"ok": True, "msg": t(lang, "m_started_async")}


def manage_status(unit_id, lang=DEFAULT_LANG):
    """查询一个受管单元的状态: ActiveState / SubState / MainPID / 是否被 SIGSTOP 挂起。"""
    cfg = next((u for u in MANAGE_UNITS if u["id"] == unit_id), None)
    if not cfg:
        return {"id": unit_id, "ok": False, "msg": t(lang, "m_unknown_unit", id=unit_id)}
    if cfg["kind"] == "proc":
        return _proc_status(cfg)
    unit = cfg["unit"]
    code, out, err = _sysctl("show", unit, "-p", "LoadState", "-p", "ActiveState",
                             "-p", "SubState", "-p", "MainPID", "-p", "Description")
    if code != 0:
        return {"id": unit_id, "ok": False, "msg": err or t(lang, "m_show_fail", c=code)}
    info = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k] = v
    pid = info.get("MainPID") or ""
    stopped = False
    if pid and pid.isdigit() and int(pid) > 1:
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as f:
                fields = f.read().split()
            # 第 3 字段 = 进程状态; 'T' = 被 SIGSTOP 挂起
            stopped = len(fields) > 2 and fields[2] == "T"
        except OSError:
            pass
    return {"id": unit_id, "ok": True,
            "active": info.get("ActiveState", "?"),
            "sub": info.get("SubState", "?"),
            "load": info.get("LoadState", "?"),
            "pid": pid, "stopped": stopped,
            "desc": info.get("Description", cfg["desc"])}


def manage_action(unit_id, action, lang=DEFAULT_LANG):
    """执行 start / stop / restart / pause(SIGSTOP) / resume(SIGCONT)。

    kind="proc" 时语义对齐用户预期: 「暂停」= 终止进程(释放端口),
    「启用/恢复」= 重新 detach 拉起。systemd 单元保持 SIGSTOP/SIGCONT。
    """
    cfg = next((u for u in MANAGE_UNITS if u["id"] == unit_id), None)
    if not cfg:
        return {"ok": False, "msg": t(lang, "m_unknown_unit", id=unit_id)}
    if action not in ACTION_LABELS:
        return {"ok": False, "msg": t(lang, "m_unknown_action", a=action)}
    if cfg["kind"] == "proc":
        if action in ("start", "resume"):
            return _proc_start(cfg, lang)
        if action in ("stop", "pause"):
            return _proc_stop(cfg, lang)
        if action == "restart":
            _proc_stop(cfg, lang)
            return _proc_start(cfg, lang)
    if action in ("pause", "resume"):
        sig = "STOP" if action == "pause" else "CONT"
        code, out, err = _sysctl("kill", "-s", sig, "--kill-who=main", cfg["unit"])
    else:
        code, out, err = _sysctl(action, cfg["unit"])
    if code == 0:
        return {"ok": True, "msg": t(lang, "m_done_" + action)}
    return {"ok": False, "msg": err or out or t(lang, "m_fail", a=ACTION_LABELS[action], c=code)}
