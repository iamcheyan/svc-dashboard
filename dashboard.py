#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
svc-dashboard — 列出本机正在监听(对外提供)的 TCP 服务。

  访问  http://<本机IP>:8000/    服务列表(每次打开都会重新扫描)
       http://<本机IP>:8000/api JSON 数据
  页面右上角: 手动刷新按钮 + 自动刷新开关(默认 10 秒)。

用法:
  python3 dashboard.py                 # 默认监听 8000
  python3 dashboard.py --port 9000     # 换端口
  python3 dashboard.py --scan          # 只打印 JSON,不启动服务

原理: 纯标准库。扫描 /proc/net/tcp{6} 找 LISTEN socket,
再通过 /proc/<pid>/fd 的 socket inode 反查进程,读取 comm/cmdline/cwd/cgroup,
据此区分 容器 / systemd 单元 / 直接进程。无需 root。
"""
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DEFAULT_PORT = 8000
AUTO_REFRESH_SEC = 10
LISTEN_HOST = "0.0.0.0"


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def readlink(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def parse_ip(hexstr, family):
    """/proc/net/tcp 里的小端十六进制地址 -> 点分/冒号形式。"""
    try:
        if family == socket.AF_INET:
            raw = bytes.fromhex(hexstr)[::-1]
            return socket.inet_ntop(socket.AF_INET, raw)
        raw = bytes.fromhex(hexstr)
        words = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
        return socket.inet_ntop(socket.AF_INET6, words)
    except (ValueError, OSError):
        return "?"


def listen_sockets():
    """扫描 /proc/net/tcp{6},收集处于 LISTEN 状态的 socket。"""
    socks = []
    for path, family in (("/proc/net/tcp", socket.AF_INET),
                         ("/proc/net/tcp6", socket.AF_INET6)):
        for line in read(path).splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":  # 0A == LISTEN
                continue
            addr_hex, port_hex = parts[1].rsplit(":", 1)
            socks.append({
                "family": family,
                "ip": parse_ip(addr_hex, family),
                "port": int(port_hex, 16),
                "inode": parts[9],
            })
    return socks


# ---------------- 特权增强(sudo 抓 root 服务) ----------------
# 非 root 进程读不到异主进程的 /proc/<pid>/fd,所以 PID/名称/cwd 抓不到。
# 这里用 `sudo -n ss -tlnp` 拿权威信息: 后台线程每 5 秒刷新一次并缓存,
# 失败(无 sudo 权限/被禁)时自动降级为空映射,页面照常显示。

_priv = {"lock": threading.Lock(), "t": 0.0, "map": {}}


def _run_sudo_ss():
    try:
        out = subprocess.run(
            ["sudo", "-n", "ss", "-H", "-tlnp"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0:
            return {}
        mapping = {}
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proc = parts[5] if len(parts) > 5 else ""
            m = re.search(r'users:\(\("([^"]+)"', proc)
            if not m:
                continue
            name = m.group(1)
            pm = re.search(r"pid=(\d+)", proc)
            if not pm:
                continue
            pid = int(pm.group(1))
            # 1.2.3.4:80 / [::]:80 / *:80
            addr = parts[3]
            mm = re.match(r"^(\*|\[?[0-9a-fA-F:.]+\]?):(\d+)$", addr)
            if not mm:
                continue
            port = int(mm.group(2))
            info = {"name": name, "pid": pid}
            try:
                with open(f"/proc/{pid}/cgroup") as f:
                    info["cgroup"] = f.read()
            except OSError:
                pass
            try:
                info["cwd"] = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                pass
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw = f.read().decode("utf-8", "replace")
                info["cmdline"] = raw.replace("\0", " ").strip()
            except OSError:
                pass
            mapping.setdefault(port, []).append(info)
        return mapping
    except Exception:
        return {}


def _priv_worker():
    while True:
        mapping = _run_sudo_ss()
        with _priv["lock"]:
            _priv["map"] = mapping
            _priv["t"] = time.time()
        time.sleep(5)


def _start_priv_thread():
    threading.Thread(target=_priv_worker, daemon=True).start()


def priv_lookup(port, ip):
    """返回 sudo 层记录的该端口进程列表;无数据时返回 None(用不到就降级)。"""
    with _priv["lock"]:
        if not _priv["map"]:
            return None
        return _priv["map"].get(port)


def inode_to_pid():
    """socket inode -> 持有该 socket 的进程 pid。"""
    mapping = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        fd_dir = f"/proc/{name}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            target = readlink(f"{fd_dir}/{fd}")
            if target and target.startswith("socket:["):
                mapping.setdefault(target[8:-1], int(name))
    return mapping


CID_RE = re.compile(
    r"(?:docker|libpod|kubepods|crio|containerd)[^\n]*[=\-]([0-9a-f]{64})")


def classify(cgroup_text):
    """根据 cgroup 判断: 容器内 / systemd 单元 / 直接进程。
    scope: user=用户自己启动的, system=系统服务, docker=容器。"""
    m = CID_RE.search(cgroup_text)
    if m:
        return {"type": "docker", "container_id": m.group(1)[:12],
                "unit": None, "scope": "docker"}
    for line in cgroup_text.splitlines():
        path = line.split(":", 2)[-1]
        mm = re.search(r"/([^/]+\.(?:service|scope))$", path)
        if mm:
            unit = mm.group(1)
            if unit.startswith(("user@", "session-")):
                continue
            if "user.slice" in path:
                scope = "user"
            elif os.path.exists(f"/etc/systemd/system/{unit}"):
                scope = "user"  # 管理员自定义单元(用户自己装的), 如游戏服务器
            else:
                scope = "system"
            return {"type": "systemd", "unit": unit, "container_id": None,
                    "scope": scope}
    return {"type": "direct", "unit": None, "container_id": None,
            "scope": "user"}


INTERPRETERS = {"python3", "python", "node", "dotnet", "java", "ruby",
                "perl", "php", "bash", "sh", "sudo", "nohup", "npm",
                "npx", "bun", "deno", "uvicorn", "gunicorn", "go"}


def nice_name(cmdline):
    """从 cmdline 里挑一个能认出的名字,如 python3 run.py -> run.py。"""
    parts = cmdline.split()
    if not parts:
        return None
    base = os.path.basename(parts[0])
    if base in INTERPRETERS:
        for a in parts[1:]:
            if not a.startswith("-") and ("/" in a or a.endswith((".py", ".js", ".jar", ".dll"))):
                return os.path.basename(a)
    return base or None


def proc_info(pid):
    info = {"name": "?", "cmdline": "", "cwd": None,
            "type": "direct", "unit": None, "container_id": None}
    comm = read(f"/proc/{pid}/comm").strip()
    cmdline = read(f"/proc/{pid}/cmdline").replace("\0", " ").strip()
    info["cmdline"] = cmdline
    info["name"] = nice_name(cmdline) or comm or "?"
    cwd = readlink(f"/proc/{pid}/cwd")
    if cwd:
        info["cwd"] = cwd
    info.update(classify(read(f"/proc/{pid}/cgroup")))
    return info


_docker_cache = {"t": 0.0, "map": {}}


def docker_port_map():
    """docker ps 的端口映射: 宿主机端口 -> (容器名, 容器短ID)。5 秒缓存。"""
    now = time.time()
    if now - _docker_cache["t"] < 5:
        return _docker_cache["map"]
    mapping = {}
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=2,
        ).stdout
    except Exception:
        pass
    else:
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            cid, name, ports = parts[0], parts[1], parts[2]
            for chunk in ports.split(","):
                m = re.search(r":(\d+)->", chunk.strip())
                if m:
                    mapping.setdefault(int(m.group(1)), (name, cid[:12]))
    _docker_cache.update({"t": now, "map": mapping})
    return mapping


def gather():
    """扫描一次,返回服务列表(按端口排序,同端口合并)。"""
    socks = listen_sockets()
    inode_pid = inode_to_pid()
    docker_ports = docker_port_map()
    self_pid = os.getpid()
    _start_priv_thread()

    by_key = {}
    for s in socks:
        key = (s["ip"], s["port"])
        pid = inode_pid.get(s["inode"])
        entry = by_key.setdefault(key, {
            "ip": s["ip"], "port": s["port"], "pids": [],
            "name": "?", "cmdline": "", "cwd": None,
            "type": "direct", "unit": None, "container_id": None,
            "scope": "user", "docker_proxy": False, "is_self": False,
        })
        if pid is None:
            # 自己的进程找不到? 用 sudo ss 层的数据兜底
            priv = priv_lookup(s["port"], s["ip"])
            if priv:
                p0 = priv[0]
                entry["pids"] = [p0["pid"]]
                entry["name"] = p0["name"]
                entry["cmdline"] = p0.get("cmdline", "")
                cwd = p0.get("cwd")
                if cwd:
                    entry["cwd"] = cwd
                if p0.get("cgroup"):
                    info = classify(p0["cgroup"])
                    if entry["type"] == "direct" and info["type"] != "direct":
                        entry["type"] = info["type"]
                        entry["unit"] = info["unit"]
                        entry["container_id"] = info["container_id"]
                        entry["scope"] = info.get("scope", "user")
            continue
        entry["pids"].append(pid)
        info = proc_info(pid)
        # 取信息最全的那个进程(通常 pid 最小的主进程)
        if entry["name"] == "?" or (info["name"] != "?" and len(entry["pids"]) == 1):
            entry["name"] = info["name"]
        if not entry["cmdline"]:
            entry["cmdline"] = info["cmdline"]
        if not entry["cwd"]:
            entry["cwd"] = info["cwd"]
        if entry["type"] == "direct" and info["type"] != "direct":
            entry["type"] = info["type"]
            entry["unit"] = info["unit"]
            entry["container_id"] = info["container_id"]
            entry["scope"] = info.get("scope", "user")
        if pid == self_pid:
            entry["is_self"] = True

    entries = []
    for key, e in sorted(by_key.items(), key=lambda kv: kv[0][1]):
        # docker-proxy / rootlesskit 是宿主机进程,但端口属于容器发布。
        # 注意: 不要要求 type == "direct" — root 扫描下 docker-proxy 会被 cgroup
        # 归类为 systemd(docker.service),那样容器重命名分支永远不触发。
        if e["name"] in ("docker-proxy", "rootlesskit", "rootlessport") \
                and e["port"] in docker_ports:
            cname, cid = docker_ports[e["port"]]
            e["type"] = "docker"
            e["container_id"] = cid
            e["scope"] = "docker"
            e["docker_proxy"] = True
            e["name"] = f"{cname} (docker)"
        e["pids"] = sorted(set(e["pids"]))
        entries.append(e)
    return entries


# ---------------- 系统信息(负载/CPU/内存/磁盘) ----------------

def _read_proc_stat():
    """读 /proc/stat 的 cpu 行,返回 (idle, total) 累计 jiffies。"""
    for line in read("/proc/stat").splitlines():
        if line.startswith("cpu "):
            fields = [int(x) for x in line.split()[1:]]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            return idle, sum(fields)
    return 0, 0


def cpu_usage_once():
    """一次性采样 CPU 使用率(两次读 /proc/stat, 间隔 0.3s)。"""
    i0, t0 = _read_proc_stat()
    time.sleep(0.3)
    i1, t1 = _read_proc_stat()
    dt = t1 - t0
    if dt <= 0:
        return 0.0
    return round(100 * (1 - (i1 - i0) / dt), 1)


def mem_info():
    total = available = 0
    for line in read("/proc/meminfo").splitlines():
        parts = line.split()
        if parts[0] == "MemTotal:":
            total = int(parts[1]) * 1024
        elif parts[0] == "MemAvailable:":
            available = int(parts[1]) * 1024
    used = total - available
    percent = round(100 * used / total, 1) if total else 0.0
    return {"total": total, "used": used, "available": available,
            "percent": percent}


def disk_info(path="/"):
    try:
        u = shutil.disk_usage(path)
        return {"total": u.total, "used": u.used, "free": u.free,
                "percent": round(100 * u.used / u.total, 1) if u.total else 0.0}
    except OSError:
        return None


def sys_info():
    info = {"hostname": socket.gethostname()}
    try:
        info["loadavg"] = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        info["loadavg"] = None
    info["cpu_count"] = os.cpu_count() or 0
    info["cpu_usage"] = cpu_usage_once()
    info["mem"] = mem_info()
    info["disk"] = disk_info("/")
    try:
        with open("/proc/uptime") as f:
            info["uptime"] = float(f.read().split()[0])
    except OSError:
        info["uptime"] = None
    return info


def fmt_bytes(n):
    if not n:
        return "—"
    g = n / (1024 ** 3)
    return f"{g:.0f} G" if g >= 100 else f"{g:.1f} G"


def fmt_uptime(sec):
    if not sec:
        return "—"
    d, rem = divmod(int(sec), 86400)
    h, m = divmod(rem, 3600)
    m //= 60
    if d:
        return f"{d} 天 {h} 小时"
    if h:
        return f"{h} 小时 {m} 分"
    return f"{m} 分"


def render_sysbar(s):
    """系统信息卡片条(打开页面时渲染一次,手动刷新才更新)。"""
    loadavg = " / ".join(f"{x:.2f}" for x in s["loadavg"]) if s.get("loadavg") else "—"
    cpu = f'{s["cpu_usage"]}% · {s["cpu_count"]} 核'
    mem = s.get("mem") or {}
    mem_txt = f'{fmt_bytes(mem.get("used"))} / {fmt_bytes(mem.get("total"))} ({mem.get("percent", 0)}%)'
    disk = s.get("disk") or {}
    disk_txt = f'{fmt_bytes(disk.get("used"))} / {fmt_bytes(disk.get("total"))} ({disk.get("percent", 0)}%)'
    cards = [
        ("负载", loadavg),
        ("CPU", cpu),
        ("内存", mem_txt),
        ("磁盘 /", disk_txt),
        ("运行", fmt_uptime(s.get("uptime"))),
    ]
    return '<div class="sysbar" id="sysbar">' + "".join(
        f'<div class="stat"><div class="label">{lbl}</div>'
        f'<div class="value">{val}</div></div>' for lbl, val in cards) + "</div>"


# ---------------- 页面 ----------------

BADGE = {
    "docker": ("容器", "badge-docker"),
    "systemd": ("systemd", "badge-systemd"),
    "direct": ("进程", "badge-direct"),
}


# ---------------- 定时任务 / 看门狗扫描 ----------------
# 不硬编码任何任务:自动枚举 cron(用户/root/系统/cron.d)与 systemd timers
# (系统 + 用户),按名称启发式打类型标签。

CRON_FILES = [
    ("user", "/var/spool/cron/crontabs/tetsuya"),
    ("root", "/var/spool/cron/crontabs/root"),
    ("system", "/etc/crontab"),
]
CRON_D_DIR = "/etc/cron.d"
WATCHDOG_RE = re.compile(r"watchdog|monitor|health|guard|keepalive|heartbeat", re.I)
REMINDER_RE = re.compile(r"reminder|notice|notify|remind", re.I)
_tasks_cache = {"t": 0.0, "data": None}

WEEKDAYS = {"0": "日", "1": "一", "2": "二", "3": "三",
            "4": "四", "5": "五", "6": "六", "7": "日"}


def human_cron(fields):
    """5 字段 cron 或 systemd OnCalendar 表达式 -> 人类可读中文。"""
    if isinstance(fields, str):
        s = fields.strip()
        # systemd OnCalendar 格式
        if s == "hourly":
            return "每小时"
        if s == "daily":
            return "每天"
        if s == "weekly":
            return "每周"
        if s == "monthly":
            return "每月"
        if s.startswith("*-*-* "):
            hm = s.split(None, 1)[1]
            if hm == "6,18:00":
                return "每天 6:00 / 18:00"
            if ":" in hm:
                h, m = hm.split(":", 1)
                return f"每天 {h}:{m}"
            return f"每天 {hm}"
        if s.startswith("*:"):
            # systemd `*:0/5` = 每 5 分钟
            step = s[2:].split("/", 1)
            return f"每 {step[1]} 分钟" if len(step) == 2 else f"每 {step[0]} 分钟"
        if s.startswith("*-*-* "):
            return s.replace("*-*-* ", "每天 ")
        return s
    m, h, dom, mon, dow = fields
    star = dom == "*" and mon == "*" and dow == "*"
    if m.startswith("*/") and h == "*" and star:
        return f"每 {m[2:]} 分钟"
    if m == "0" and h.startswith("*/") and star:
        return f"每 {h[2:]} 小时"
    if m == "0" and h not in "*" and star:
        return f"每天 {h}:00"
    if m == "0" and h not in "*" and dom == "*" and mon == "*" and dow not in "*":
        days = "/".join(WEEKDAYS.get(d, d) for d in dow.split(","))
        return f"每周{days} {h}:00"
    if m not in "*" and h not in "*" and dom not in "*" and mon not in "*" and dow == "*":
        return f"{mon}月{dom}日 {h}:{int(m):02d}"
    return " ".join(fields)


def classify_task(name, command):
    """按名称/命令启发式分类型: watchdog / reminder / scheduled。"""
    text = f"{name} {command}"
    if WATCHDOG_RE.search(text):
        return "watchdog"
    if REMINDER_RE.search(text):
        return "reminder"
    return "scheduled"


def parse_cron_lines(lines, scope):
    """解析 crontab 文本行 -> 任务 dict 列表。"""
    tasks = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 6 or not re.match(r"^[0-9*/,\-]+$", parts[0]):
            continue
        fields, cmd = parts[:5], " ".join(parts[5:])
        name = os.path.basename(cmd.split()[0])
        if name in ("run-parts", "test"):
            name = cmd
        tasks.append({
            "name": name, "kind": "cron", "scope": scope,
            "schedule": human_cron(fields), "expr": " ".join(fields),
            "next": None, "last": None, "state": "enabled",
            "type": classify_task(name, cmd), "command": cmd,
        })
    return tasks


def _read_cron_file(path, scope, out):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            out.extend(parse_cron_lines(f, scope))
    except OSError:
        pass


def scan_cron():
    tasks = []
    for scope, path in CRON_FILES:
        _read_cron_file(path, scope, tasks)
    try:
        for fn in sorted(os.listdir(CRON_D_DIR)):
            if fn.startswith("."):
                continue
            _read_cron_file(os.path.join(CRON_D_DIR, fn), "system", tasks)
    except OSError:
        pass
    return tasks


def _run_timers(scope):
    """枚举 timer units 并读结构化信息。"""
    env = None
    cmd = ["systemctl"]
    if scope == "user":
        # 通过 machinectl 访问 tetsuya 的 user manager(root 直接连不上 user bus)
        cmd += ["--machine=tetsuya@.host", "--user"]
    try:
        r = subprocess.run(cmd + ["list-unit-files", "--type=timer", "--no-pager", "--plain"],
                           capture_output=True, text=True, timeout=5, env=env)
    except Exception:
        return []
    tasks = []
    for line in r.stdout.splitlines():
        unit, _, state = line.partition(" ")
        if not unit.endswith(".timer"):
            continue
        try:
            show = subprocess.run(cmd + ["show", unit, "-p", "NextElapseUSec", "-p",
                                         "LastTriggerUSec", "-p", "ActiveState",
                                         "-p", "Description", "-p", "FragmentPath"],
                                  capture_output=True, text=True, timeout=5, env=env).stdout
            info = dict(l.split("=", 1) for l in show.splitlines() if "=" in l)
            path = ""
            frag = info.get("FragmentPath")
            if frag:
                try:
                    with open(frag, encoding="utf-8", errors="replace") as f:
                        path = f.read()
                except OSError:
                    pass
            if not path:  # 兜底:远程 cat 不支持时
                path = subprocess.run(cmd + ["cat", unit], capture_output=True,
                                      text=True, timeout=5, env=env).stdout
        except Exception:
            continue
        cal = ""
        m = re.search(r"OnCalendar\s*=\s*(.+)", path)
        if m:
            cal = m.group(1).strip()
        m2 = re.search(r"OnUnitActiveSec\s*=\s*(.+)", path)
        if m2:
            cal = f"每 {m2.group(1).strip()}"
        schedule = human_cron(cal) if cal else "按 unit 配置"
        def to_ts(v):
            if not v or v == "n/a":
                return None
            try:
                return int(datetime.strptime(v.rsplit(None, 1)[0], "%a %Y-%m-%d %H:%M:%S").timestamp())
            except Exception:
                return None
        next_ts = to_ts(info.get("NextElapseUSec"))
        last_ts = to_ts(info.get("LastTriggerUSec"))
        name = unit[:-6]
        svc = name  # timer 配套 service 名,用于分类上下文
        tasks.append({
            "name": name, "kind": "timer", "scope": scope,
            "schedule": schedule, "expr": f"OnCalendar={cal}" if cal else "",
            "next": next_ts, "last": last_ts,
            "state": info.get("ActiveState", "?"),
            "type": classify_task(svc, f"{info.get('Description', '')} {unit}"),
            "command": unit,
        })
    return tasks


INTERP = {"uv", "sh", "bash", "python3", "python", "perl", "node", "bun"}


def _cmd_key(cmd):
    """从命令提取可匹配 cron 日志的标识:解释器取其后缀脚本,否则取首个词 basename。"""
    parts = cmd.split()
    if not parts:
        return None
    base = os.path.basename(parts[0])
    if base in INTERP:
        for p in parts[1:]:
            if p and not p.startswith("-") and not p.startswith("$"):
                return os.path.basename(p)
    return base


def _cron_last_runs():
    """从 journalctl -u cron 流式提取每个命令的最后执行时间戳。"""
    last = {}
    try:
        p = subprocess.Popen(
            ["journalctl", "-u", "cron", "-o", "short-iso", "--no-pager"],
            stdout=subprocess.PIPE, text=True, errors="replace")
    except Exception:
        return last
    re_line = re.compile(r"^(\S+T\S+[+-]\d{2}:?\d{2})\s+\S+\s+CRON\[\d+\]:\s+\(\S+\)\s+CMD\s+\((.*)\)\s*$")
    for line in p.stdout:
        m = re_line.match(line)
        if not m:
            continue
        ts, cmdline = m.groups()
        key = _cmd_key(cmdline)
        if not key:
            continue
        try:
            epoch = int(datetime.fromisoformat(ts).timestamp())
        except Exception:
            continue
        if key not in last or epoch > last[key]:
            last[key] = epoch
    try:
        p.stdout.close()
    except Exception:
        pass
    return last


def scan_tasks():
    """汇总所有定时/看门狗任务(8 秒缓存)。"""
    now = time.time()
    if _tasks_cache["data"] is not None and now - _tasks_cache["t"] < 8:
        return _tasks_cache["data"]
    tasks = scan_cron() + _run_timers("system") + _run_timers("user")
    last_runs = _cron_last_runs()
    for t in tasks:
        if t["kind"] == "cron":
            t["last"] = last_runs.get(_cmd_key(t["command"]))
    tasks.sort(key=lambda t: (t["type"] != "watchdog", t["name"]))
    _tasks_cache.update({"t": now, "data": tasks})
    return tasks


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
    results = []
    for path in glob.glob(os.path.join(OMP_SESSION_ROOT, "**", "*.jsonl"), recursive=True):
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
def _event_text(event):
    """把一条 omp session 事件压成可读摘要行,返回 (kind, text)。"""
    t = event.get("type", "")
    ts = event.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
    except (ValueError, AttributeError):
        ts = ""
    data = event.get("data") or {}
    msg = event.get("message") or {}
    role = msg.get("role", "")
    if t == "message" and role == "assistant":
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
    if t == "message" and role == "user":
        text = msg.get("content", "")
        if isinstance(text, list):
            text = " ".join(c.get("text", "") for c in text if isinstance(c, dict) and c.get("type") == "text")
        return ("user", f"[{ts}] → {str(text)[:100]}")
    if t == "message" and role == "toolResult":
        out = msg.get("output") or msg.get("content") or ""
        if isinstance(out, list):
            out = " ".join(str(c.get("text", "")) for c in out if isinstance(c, dict))
        return ("tool", f"[{ts}] ↩ {str(out)[:90]}")
    if t == "custom":
        ct = data.get("customType") or event.get("customType") or ""
        if "tool_execution_start" in ct:
            return ("tool", f"[{ts}] ⚙ {data.get('toolName', '—')}")
        if "tool_execution_end" in ct:
            return ("tool", f"[{ts}] ✓ {data.get('toolName', '—')}")
        if "session_exit" in ct:
            return ("exit", f"[{ts}] ✕ 会话结束: {data.get('reason', '—')}")
        if "mode_change" in ct:
            goal = data.get("goal") or {}
            obj = " ".join(str(goal.get("objective") or "").split())
            return ("goal", f"[{ts}] 🔀 目标: {obj[:120]}")
        return ("evt", f"[{ts}] · {ct}")
    if t == "compaction":
        return ("goal", f"[{ts}] ↻ 压缩: {str(event.get('summary', ''))[:120]}")
    return ("evt", f"[{ts}] · {t}") if ts else None


def scan_agent_log(sid):
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
        row = _event_text(event)
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

def render_html(host_header, entries, updated_ts):
    rows = []
    for e in entries:
        ip, port = e["ip"], e["port"]
        is_loopback = ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")
        badge_text, badge_cls = BADGE.get(e["type"], ("进程", "badge-direct"))
        detail = ""
        if e.get("is_self"):
            badge_text, badge_cls = "本页", "badge-self"
        elif e.get("docker_proxy"):
            badge_text = "Docker映射"
        elif e["type"] == "docker" and e.get("container_id"):
            detail = f'<span class="detail" title="容器ID">{escape(e["container_id"])}</span>'
        elif e["type"] == "systemd" and e.get("unit"):
            detail = f'<span class="detail" title="systemd 单元">{escape(e["unit"])}</span>'
        cmd = escape(e["cmdline"] or "—")
        cwd = escape(e["cwd"] or "—")
        pids = ", ".join(str(p) for p in e.get("pids") or ["?"])
        hostname = host_header.split(":")[0]  # 去掉端口,用访问 dashboard 的主机名
        if is_loopback:
            link = f"http://127.0.0.1:{port}/"
            loop = '<span class="local">仅本机</span>'
        else:
            link = f"http://{hostname}:{port}/"
            loop = ""
        rows.append(
            f'<tr>'
            f'<td class="name"><span class="svc">{escape(e["name"])}</span>'
            f'<span class="badge {badge_cls}">{badge_text}</span>{detail}</td>'
            f'<td class="port"><a href="{link}" target="_blank" rel="noopener">{port}</a></td>'
            f'<td class="addr">{escape(ip)} {loop}</td>'
            f'<td class="pid">{pids}</td>'
            f'<td class="cmd">{cmd}</td>'
            f'<td class="cwd">{cwd}</td>'
            f'</tr>')
    table = "\n".join(rows)
    hostname = socket.gethostname()
    return (PAGE_TEMPLATE
            .replace("{{HOST}}", escape(host_header))
            .replace("{{HOSTNAME}}", escape(hostname))
            .replace("{{AUTO}}", str(AUTO_REFRESH_SEC))
            .replace("{{SYSBAR}}", render_sysbar(sys_info()))
            .replace("{{UPDATED}}", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(updated_ts)))
            .replace("{{COUNT}}", str(len(entries)))
            .replace("<!--TABLE-->", table))


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>服务一览 · {{HOSTNAME}}</title>
<link rel="icon" href="data:,">
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background: #0a0a0a; color: #d6d6d6; }
  header { position: sticky; top: 0; z-index: 10; background: rgba(10,10,10,.9); backdrop-filter: blur(6px);
           border-bottom: 1px solid #1f1f1f; padding: 12px 24px;
           display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  header h1 { font-size: 17px; margin: 0; font-weight: 600; color: #f2f2f2; }
  header .meta { color: #8a8a8a; font-size: 12.5px; }
  header .spacer { flex: 1; }
  button { background: #262626; color: #eee; border: 1px solid #333; border-radius: 8px; padding: 7px 14px;
           font-size: 13px; cursor: pointer; }
  button:hover { background: #333; }
  button.spinning { opacity: .7; }
  label.auto { font-size: 13px; color: #b0b0b0; display: flex; align-items: center; gap: 6px; cursor: pointer; }
  main { padding: 16px 24px 40px; }
  .sysbar { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
  .stat { background: #141414; border: 1px solid #222; border-radius: 10px;
          padding: 10px 16px; min-width: 130px; }
  .stat .label { color: #777; font-size: 11px; margin-bottom: 3px; }
  .stat .value { font-size: 14px; font-weight: 600; font-family: ui-monospace, monospace; color: #e8e8e8; white-space: nowrap; }
  .tbadge { display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 10.5px;
            margin-right: 6px; vertical-align: 1px; }
  .tbadge.wd { background: #2a2010; color: #e0a84c; border: 1px solid #4a3a18; }
  .tbadge.rd { background: #1e2832; color: #6ea8dc; border: 1px solid #26405a; }
  .tbadge.sc { background: #1c1c1c; color: #9a9a9a; border: 1px solid #2e2e2e; }
  .filters { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; align-items: center; }
  .filters .spacer { flex: 1; }
  .watchdog-panel { background: #141414; border: 1px solid #222; border-radius: 10px;
                    padding: 12px 14px; margin-bottom: 14px; }
  .watchdog-panel h2 { margin: 0 0 8px; font-size: 13px; color: #9a9a9a; font-weight: 500; }
  .watchdog-panel table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  .watchdog-panel th { text-align: left; color: #777; font-weight: 400; font-size: 11.5px;
                       padding: 4px 8px; border-bottom: 1px solid #1f1f1f; white-space: nowrap; }
  .watchdog-panel td { padding: 5px 8px; border-bottom: 1px solid #1a1a1a; vertical-align: top; }
  .watchdog-panel tr:last-child td { border-bottom: none; }
  .watchdog-panel .tname { font-family: ui-monospace, monospace; color: #e8e8e8; word-break: break-all; }
  .watchdog-panel .tsch { color: #b0b0b0; white-space: nowrap; }
  .watchdog-panel .tscope { color: #888; font-size: 11px; }
  .watchdog-panel .tcmd { color: #9a9a9a; font-family: ui-monospace, monospace; font-size: 11px;
                          word-break: break-all; max-width: 420px; }
  .watchdog-panel .tlink { cursor: pointer; }
  .watchdog-panel .tlink:hover { color: #8ab4f8; text-decoration: underline; }
  .watchdog-panel .agent-detail td { background: #101418; padding: 10px 14px; }
  .agentlog { max-height: 380px; overflow-y: auto; }
  .aglog-title { font-size: 12px; color: #8a8a8a; margin: 6px 0 4px; display: flex;
                 align-items: center; gap: 8px; }
  .aglog-refresh { background: #1d2733; border: 1px solid #2c3a4d; color: #9db8d9;
                   padding: 2px 10px; font-size: 11px; border-radius: 6px; cursor: pointer; }
  .aglog-refresh:hover { background: #243445; }
  .aglog-list { display: flex; flex-direction: column; gap: 2px; }
  .aglog-row { display: flex; gap: 10px; font-family: ui-monospace, monospace; font-size: 11.5px;
               line-height: 1.55; }
  .aglog-ts { color: #5c7a9a; white-space: nowrap; flex: none; }
  .aglog-txt { color: #c9c9c9; word-break: break-all; }
  .termlog { background: #0a0e12; border: 1px solid #1c242e; border-radius: 6px; padding: 8px 10px;
             font-family: ui-monospace, monospace; font-size: 11px; line-height: 1.45;
             color: #9fd4a0; overflow-x: auto; white-space: pre; margin: 2px 0 8px; }
  .aglog-empty { color: #666; font-size: 12px; padding: 8px 0; }
  .chip { background: #161616; color: #b0b0b0; border: 1px solid #2a2a2a; border-radius: 999px;
          padding: 5px 14px; font-size: 12.5px; cursor: pointer; }
  .chip:hover { background: #1f1f1f; }
  .chip.active { background: #f2f2f2; border-color: #f2f2f2; color: #111; }
  .chip span { opacity: .6; margin-left: 4px; font-size: 11px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th { text-align: left; color: #8a8a8a; font-weight: 500; font-size: 12px;
             padding: 8px 10px; border-bottom: 1px solid #222; position: sticky; top: 52px;
             background: #0a0a0a; }
  tbody td { padding: 9px 10px; border-bottom: 1px solid #1c1c1c; vertical-align: top; }
  tbody tr:hover { background: #131313; }
  .name { white-space: nowrap; }
  .svc { font-weight: 600; color: #eee; }
  .port a { color: #e8e8e8; font-weight: 600; text-decoration: none; font-family: ui-monospace, monospace; font-size: 14px; }
  .port a:hover { text-decoration: underline; color: #fff; }
  .addr, .pid { color: #8a8a8a; font-family: ui-monospace, monospace; white-space: nowrap; }
  .cmd, .cwd { color: #b0b0b0; white-space: pre-wrap; word-break: break-all;
               font-family: ui-monospace, monospace; min-width: 220px; }
  table[data-col="cmd"] td.cwd { display: none; }
  table[data-col="cwd"] td.cmd { display: none; }
  th.colswitch { min-width: 220px; }
  .tcol { background: transparent; border: 1px solid #2a2a2a; color: #8a8a8a;
          border-radius: 6px; padding: 2px 11px; font-size: 11.5px; cursor: pointer; }
  .tcol:hover { color: #eee; border-color: #3a3a3a; }
  .tcol.active { background: #262626; color: #f2f2f2; border-color: #3a3a3a; }
  .badge { display: inline-block; margin-left: 8px; padding: 2px 7px; border-radius: 999px;
           font-size: 11px; font-weight: 500; vertical-align: 1px; }
  .badge-docker  { background: #1c1c1c; color: #c9c9c9; border: 1px solid #333; }
  .badge-systemd { background: #1c1c1c; color: #a8a8a8; border: 1px solid #2e2e2e; }
  .badge-direct  { background: #161616; color: #8f8f8f; border: 1px solid #2a2a2a; }
  .badge-self    { background: #262626; color: #f2f2f2; border: 1px solid #3a3a3a; }
  .detail { display: block; color: #777; font-size: 11px; font-family: ui-monospace, monospace; margin-top: 2px; }
  .local { color: #999; font-size: 11px; }
  .empty { color: #8a8a8a; text-align: center; padding: 48px 0; }
  @media (max-width: 900px) { .cmd, .cwd { min-width: 120px; } }
</style>
</head>
<body>
<header>
  <h1>服务一览
    <a href="https://github.com/iamcheyan/svc-dashboard" target="_blank" rel="noopener"
       title="GitHub 仓库" style="text-decoration:none; margin-left:8px; vertical-align:-3px;">
      <svg width="18" height="18" viewBox="0 0 16 16" fill="#d6d6d6" aria-hidden="true">
        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
      </svg>
    </a>
  </h1>
  <span class="meta">{{HOSTNAME}} · 更新于 <span id="updated">{{UPDATED}}</span> · <span id="count">{{COUNT}}</span> 个监听端口</span>
  <span class="spacer"></span>
  <label class="auto"><input type="checkbox" id="auto" checked> 自动刷新 ({{AUTO}}s)</label>
  <button id="refresh">⟳ 刷新</button>
</header>
<main>
{{SYSBAR}}
<div class="filters" id="filters">
  <button class="chip active" data-f="user">用户服务 <span id="n-user"></span></button>
  <button class="chip" data-f="docker">Docker <span id="n-docker"></span></button>
  <button class="chip" data-f="system">系统服务 <span id="n-system"></span></button>
  <button class="chip" data-f="all">全部 <span id="n-all"></span></button>
  <span class="spacer"></span>
  <button class="chip" data-f="omp">agent任务 <span id="n-omp"></span></button>
  <button class="chip" data-f="watchdog">定时任务 <span id="n-watchdog"></span></button>
  <button class="chip" data-f="tmux">tmux状态 <span id="n-tmux"></span></button>
</div>
<div id="tasks" hidden></div>
<table id="svc" data-col="cmd">
  <thead><tr>
    <th>服务</th><th>端口</th><th>监听地址</th><th>PID</th>
    <th class="colswitch">
      <button class="tcol active" data-col="cmd">启动命令</button>
      <button class="tcol" data-col="cwd">工作目录</button>
    </th>
  </tr></thead>
  <tbody>
<!--TABLE-->
  </tbody>
</table>
</main>
<script>
const AUTO = {{AUTO}};
let autoOn = true;
let filter = "user"; // 默认只显示用户服务, 隐藏系统服务
let services = [];
const $ = (id) => document.getElementById(id);

const FILTERS = {
  user:   (e) => e.scope !== "system",
  docker: (e) => e.scope === "docker",
  system: (e) => e.scope === "system",
  omp:     () => false, // OMP 走独立面板,不混进服务表
  watchdog: () => false, // 看门狗走独立面板,不混进服务表
  all:    () => true,
};

function row(e) {
  const badge = {docker:["容器","badge-docker"], systemd:["systemd","badge-systemd"], direct:["进程","badge-direct"]}[e.type] || ["进程","badge-direct"];
  let text = badge[0], detail = "";
  if (e.is_self) { text = "本页"; badge[1] = "badge-self"; }
  else if (e.docker_proxy) { text = "Docker映射"; }
  else if (e.type === "docker" && e.container_id) detail = `<span class='detail' title='容器ID'>${e.container_id}</span>`;
  else if (e.type === "systemd" && e.unit) detail = `<span class='detail' title='systemd 单元'>${e.unit}</span>`;
  const ip = e.ip;
  const loopback = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
  const link = loopback ? `http://127.0.0.1:${e.port}/` : `http://${location.hostname}:${e.port}/`;
  const loop = loopback ? ' <span class="local">仅本机</span>' : "";
  const cmd = e.cmdline || "—";
  const cwd = e.cwd || "—";
  const esc = (s) => s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  return `<tr>
    <td class='name'><span class='svc'>${esc(e.name)}</span><span class='badge ${badge[1]}'>${text}</span>${detail}</td>
    <td class='port'><a href='${link}' target='_blank' rel='noopener'>${e.port}</a></td>
    <td class='addr'>${esc(ip)}${loop}</td>
    <td class='pid'>${e.pids.join(", ")}</td>
    <td class='cmd'>${esc(cmd)}</td>
    <td class='cwd'>${esc(cwd)}</td>
  </tr>`;
}

function applyFilter() {
  const shown = FILTERS[filter] ? services.filter(FILTERS[filter]) : [];
  ["user", "docker", "system", "all"].forEach(f =>
    $("n-" + f).textContent = services.filter(FILTERS[f]).length);
  document.querySelectorAll(".chip").forEach(c =>
    c.classList.toggle("active", c.dataset.f === filter));
  if (filter === "omp") {
    $("svc").style.display = "none";
    loadAgents().then(renderAgentPanel);
    $("count").textContent = "agent任务";
    return;
  }
  if (filter === "tmux") {
    $("svc").style.display = "none";
    loadTmux().then(renderTmuxPanel);
    $("count").textContent = "tmux状态";
    return;
  }
  if (filter === "watchdog") {
    // 看门狗模式:隐藏服务表,显示看门狗面板
    $("svc").style.display = "none";
    loadTasks().then(renderWatchdogPanel);
    $("count").textContent = "定时任务";
    return;
  }
  $("svc").style.display = "";
  $("tasks").hidden = true;
  const tbody = $("svc").querySelector("tbody");
  tbody.innerHTML = shown.length ? shown.map(row).join("") :
    '<tr><td class="empty" colspan="5">没有匹配的服务</td></tr>';
  $("count").textContent = shown.length + " 个监听端口";
}

function renderSys(s) {
  const fmtBytes = (b) => b ? ((b / 1073741824 >= 100 ? (b / 1073741824).toFixed(0) : (b / 1073741824).toFixed(1)) + " G") : "—";
  const fmtUp = (sec) => {
    if (!sec) return "—";
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    return d ? `${d} 天 ${h} 小时` : h ? `${h} 小时 ${m} 分` : `${m} 分`;
  };
  const mem = s.mem || {}, disk = s.disk || {};
  const cards = [
    ["负载", (s.loadavg || []).join(" / ") || "—"],
    ["CPU", `${s.cpu_usage}% · ${s.cpu_count} 核`],
    ["内存", `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)} (${mem.percent || 0}%)`],
    ["磁盘 /", `${fmtBytes(disk.used)} / ${fmtBytes(disk.total)} (${disk.percent || 0}%)`],
    ["运行", fmtUp(s.uptime)],
  ];
  $("sysbar").innerHTML = cards.map(([l, v]) =>
    `<div class='stat'><div class='label'>${l}</div><div class='value'>${v}</div></div>`).join("");
}

const TYPE_BADGE = {
  watchdog: ["看门狗", "tbadge wd"],
  reminder: ["提醒", "tbadge rd"],
  scheduled: ["定时", "tbadge sc"],
};
const TASK_COLS = ["name", "schedule", "scope", "command"];

function taskRow(t) {
  const [label, cls] = TYPE_BADGE[t.type] || ["定时", "tbadge sc"];
  const esc = (s) => s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const next = t.next ? new Date(t.next * 1000).toLocaleString() : (t.last ? "上次 " + new Date(t.last * 1000).toLocaleString() : "—");
  return `<tr>
    <td><span class='${cls}'>${label}</span><span class='tname'>${esc(t.name)}</span></td>
    <td class='tsch'>${esc(t.schedule)}</td>
    <td class='tscope'>${t.kind === "timer" ? "systemd" : "cron"} · ${t.scope === "user" ? "用户" : "系统"}</td>
    <td class='tcmd'>${esc(t.command)}</td>
    <td class='tnext'>${next}</td>
  </tr>`;
}

let ompCache = null;
async function loadAgents() {
  if (ompCache) return ompCache;
  try {
    const r = await fetch("/api/omp", { cache: "no-store" });
    const data = await r.json();
    ompCache = { omp: data.omp || [], codex: data.codex || [] };
    $("n-omp").textContent = (ompCache.omp.length + ompCache.codex.length) || "";
  } catch (err) { ompCache = { omp: [], codex: [] }; }
  return ompCache;
}
function renderAgentPanel(agents) {
  const el = $("tasks");
  if (filter !== "omp") { el.hidden = true; return; }
  el.hidden = false; el.className = "watchdog-panel";
  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const labels = {running:"运行中", blocked:"阻塞", idle:"空闲", completed:"已完成"};
  let rows = "";
  // OMP agents
  agents.omp.forEach(x => {
    rows += "<tr><td><span class='tbadge wd'>OMP</span><span class='tname tlink' data-sid='" + esc(x.id) +
      "' data-cwd='" + esc(x.cwd) + "' data-tmux='" + esc(x.tmux) + "' title='点击查看日志 · " + esc(x.goal) + "'>" +
      esc((x.goal || x.cwd).slice(0, 60)) + "</span></td><td>" + (labels[x.health] || esc(x.status)) +
      "</td><td class='tscope'>" + esc(x.tmux) + "<br>" + esc(x.cwd) + "</td><td class='tsch'>" +
      esc(x.last_activity) + "<br>" + x.idle_seconds + "s 前</td><td class='tcmd'>" + esc(x.tool) + "</td></tr>";
  });
  // Codex agents
  agents.codex.forEach(x => {
    rows += "<tr><td><span class='tbadge rd'>Codex</span><span class='tname tlink' data-sid='' data-cwd='" +
      esc(x.cwd) + "' data-tmux='' title='点击查看实时画面 · pid " + esc(x.pid) + "'>" +
      esc(x.cwd) + "</span></td><td>运行中</td><td class='tscope'>—<br>" + esc(x.cwd) + "</td><td class='tsch'>" +
      esc(x.last_activity) + "<br>" + x.idle_seconds + "s 前</td><td class='tcmd'>pid " + esc(x.pid) + "</td></tr>";
  });
  const total = agents.omp.length + agents.codex.length;
  el.innerHTML = "<h2>agent 任务 <span style='color:#666;font-weight:400'>" + total +
    " 项 · 点击标题查看日志</span></h2><table><thead><tr><th>Agent</th><th>状态</th><th>tmux / 目录</th><th>最近活动</th><th>当前工具</th></tr></thead><tbody>" +
    (rows || "<tr><td class='empty' colspan='5'>没有检测到 agent</td></tr>") + "</tbody></table>";
  el.querySelectorAll(".tlink").forEach(a => a.addEventListener("click", () => toggleAgentLog(a)));
}

async function loadAgentLog(a, det) {
  const sid = a.dataset.sid || "";
  const cwd = a.dataset.cwd || "";
  const tmx = a.dataset.tmux || "";
  const cell = det.querySelector("td");
  cell.innerHTML = "<div class='agentlog'>加载中…</div>";
  try {
    const r = await fetch("/api/agentlog?sid=" + encodeURIComponent(sid) + "&cwd=" + encodeURIComponent(cwd) + "&tmux=" + encodeURIComponent(tmx), { cache: "no-store" });
    const d = await r.json();
    const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
    let html = "<div class='agentlog'>";
    if ((d.events || []).length) {
      html += "<div class='aglog-title'>最近活动 <button class='aglog-refresh'>⟳ 刷新</button></div><div class='aglog-list'>" +
        d.events.map(e => "<div class='aglog-row'><span class='aglog-ts'>" + esc(e[0]) + "</span><span class='aglog-txt'>" + esc(e[1]) + "</span></div>").join("") + "</div>";
    }
    if (d.capture && d.capture.length) {
      html += "<div class='aglog-title'>终端画面 <button class='aglog-refresh'>⟳ 刷新</button></div><pre class='termlog'>" +
        d.capture.map(l => esc(l)).join("\\n") + "</pre>";
    }
    if (!d.events.length && !d.capture) html += "<div class='aglog-empty'>没有可用的日志 / 终端画面</div>";
    html += "</div>";
    det.className = "agent-detail";
    cell.innerHTML = html;
    det.querySelectorAll(".aglog-refresh").forEach(b => b.addEventListener("click", () => loadAgentLog(a, det)));
  } catch (err) {
    det.className = "agent-detail";
    cell.innerHTML = "<div class='agentlog aglog-empty'>加载失败: " + esc(err.message) + "</div>";
  }
}

function toggleAgentLog(a) {
  const tr = a.closest("tr");
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("agent-detail")) {
    next.remove();
    return;
  }
  if (next && next.classList.contains("agent-detail-loading")) return;
  const det = document.createElement("tr");
  det.className = "agent-detail-loading";
  det.innerHTML = "<td colspan='5'><div class='agentlog'>加载中…</div></td>";
  tr.after(det);
  loadAgentLog(a, det);
}

let tmuxCache = null;
async function loadTmux() {
  if (tmuxCache) return tmuxCache;
  try {
    const r = await fetch("/api/tmux", { cache: "no-store" });
    const data = await r.json();
    tmuxCache = data.panes || [];
    $("n-tmux").textContent = tmuxCache.length || "";
  } catch (err) { tmuxCache = []; }
  return tmuxCache;
}
function renderTmuxPanel(panes) {
  const el = $("tasks");
  if (filter !== "tmux") { el.hidden = true; return; }
  el.hidden = false; el.className = "watchdog-panel";
  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const rows = panes.map(x => "<tr><td class='tname'>" + esc(x.session) + ":" + esc(x.pane) +
    (x.active ? " <span class='tbadge wd'>当前</span>" : "") + "</td><td>" + esc(x.command) +
    "</td><td class='tscope'>" + esc(x.title) + "</td><td class='tcmd'>" + esc(x.cwd) +
    "</td><td class='tsch'>" + esc(x.size) + "</td></tr>").join("");
  el.innerHTML = "<h2>tmux 状态 <span style='color:#666;font-weight:400'>" + panes.length +
    " 个窗格</span></h2><table><thead><tr><th>窗格</th><th>命令</th><th>标题</th><th>目录</th><th>尺寸</th></tr></thead><tbody>" +
    (rows || "<tr><td class='empty' colspan='5'>tmux 未运行</td></tr>") + "</tbody></table>";
}

let tasksCache = null; // 懒加载缓存

async function loadTasks() {
  if (tasksCache) return tasksCache;
  try {
    const r = await fetch("/api/tasks", { cache: "no-store" });
    const data = await r.json();
    tasksCache = data.tasks || [];
    $("n-watchdog").textContent = tasksCache.length;
  } catch (err) {
    tasksCache = [];
  }
  return tasksCache;
}

function renderWatchdogPanel(tasks) {
  const el = $("tasks");
  if (filter !== "watchdog") { el.hidden = true; return; }
  el.hidden = false;
  el.className = "watchdog-panel";
  const nwd = tasks.filter(t => t.type === "watchdog").length;
  const nrd = tasks.filter(t => t.type === "reminder").length;
  const nsc = tasks.length - nwd - nrd;
  el.innerHTML = `<h2>定时任务 / 看门狗
    <span style='color:#e0a84c'>${nwd} 看门狗</span> ·
    <span style='color:#6ea8dc'>${nrd} 提醒</span> ·
    <span style='color:#9a9a9a'>${nsc} 定时</span> ·
    <span style='color:#666;font-weight:400'>共 ${tasks.length} 项</span></h2>
    <table><thead><tr><th>任务</th><th>周期</th><th>来源</th><th>命令</th><th>最近执行</th></tr></thead>
    <tbody>${tasks.length ? tasks.map(taskRow).join("") : "<tr><td class='empty' colspan='5'>没有定时任务 / 看门狗</td></tr>"}</tbody></table>`;
}

async function load(alsoSys) {
  const btn = $("refresh");
  btn.classList.add("spinning");
  btn.disabled = true;
  try {
    const r = await fetch("/api", { cache: "no-store" });
    const data = await r.json();
    $("updated").textContent = new Date(data.updated * 1000).toLocaleString();
    services = data.services;
    applyFilter();
  } catch (err) {
    console.error("refresh failed", err);
  }
  if (alsoSys) {
    try {
      const r = await fetch("/api/sys", { cache: "no-store" });
      renderSys(await r.json());
    } catch (err) {
      console.error("sys refresh failed", err);
    }
  }
  btn.classList.remove("spinning");
  btn.disabled = false;
}

document.querySelectorAll(".chip").forEach(c =>
  c.addEventListener("click", () => { filter = c.dataset.f; applyFilter(); }));
document.querySelectorAll(".tcol").forEach(b =>
  b.addEventListener("click", () => {
    $("svc").dataset.col = b.dataset.col;
    document.querySelectorAll(".tcol").forEach(x =>
      x.classList.toggle("active", x === b));
  }));
$("refresh").addEventListener("click", () => load(true));
$("auto").addEventListener("change", (ev) => { autoOn = ev.target.checked; if (autoOn) load(false); });
setInterval(() => { if (autoOn) load(false); }, AUTO * 1000);
load(true);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "svc-dashboard/1.0"

    def _host(self):
        return self.headers.get("Host") or f"localhost:{LISTEN_PORT}"

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            entries = gather()
            body = render_html(self._host(), entries, time.time()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api":
            payload = json.dumps(
                {"updated": time.time(), "services": gather()},
                ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif path == "/api/sys":
            payload = json.dumps(sys_info(), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif path == "/api/tasks":
            payload = json.dumps({"tasks": scan_tasks()}, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif path == "/api/omp":
            payload = json.dumps({"updated": time.time(), "omp": scan_omp(),
                                  "codex": scan_codex()}, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif path == "/api/tmux":
            payload = json.dumps({"updated": time.time(), "panes": scan_tmux()},
                                 ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif path.startswith("/api/agentlog"):
            qs = parse_qs(urlparse(self.path).query)
            sid = (qs.get("sid") or [""])[0]
            cwd = (qs.get("cwd") or [""])[0]
            tmx = (qs.get("tmux") or [""])[0]
            if not tmx and cwd:
                tmx = _tmux_by_cwd(cwd)
            body = {"events": scan_agent_log(sid) if sid else [],
                    "capture": _tmux_capture(tmx)}
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))


def main():
    args = sys.argv[1:]
    port = DEFAULT_PORT
    if "--port" in args:
        try:
            port = int(args[args.index("--port") + 1])
        except (ValueError, IndexError):
            print("用法: dashboard.py [--port N] [--scan]")
            return 2
    if "--scan" in args:
        _priv["map"] = _run_sudo_ss()  # 同步预热
        print(json.dumps({"services": gather()}, ensure_ascii=False, indent=2))
        return 0
    if os.geteuid() != 0:
        _priv["map"] = _run_sudo_ss()  # 非 root 时预热;root 直接读 /proc
    httpd = ThreadingHTTPServer((LISTEN_HOST, port), Handler)
    httpd.daemon_threads = True
    print(f"svc-dashboard 已启动: http://0.0.0.0:{port}/  (Ctrl+C 退出)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
