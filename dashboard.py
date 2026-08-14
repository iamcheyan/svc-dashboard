#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
svc-dashboard — 列出本机正在监听(对外提供)的 TCP 服务。

  访问  http://<本机IP>/    服务列表(每次打开都会重新扫描)
       http://<本机IP>/api JSON 数据
  页面右上角: 手动刷新按钮 + 自动刷新开关(默认 10 秒)。

用法:
  python3 dashboard.py                 # 默认监听 80(特权端口,需 root)
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
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DEFAULT_PORT = 80
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
# 用 `sudo -n ss -tlnp` 拿权威信息: 只在用户访问页面时同步扫描一次,
# 无后台线程、无自动刷新 —— 没人访问时 dashboard 完全静默。
# 失败(无 sudo 权限/被禁/ss 超时)时降级为空映射,页面照常显示。
# (本机实测 `ss -H -tlnp` 需 24 分钟才返回,故设 8s 超时 + 杀进程组,不留孤儿。)

_priv = {"lock": threading.Lock(), "map": None}


def _kill_tree(proc):
    """subprocess 超时后,杀整个进程组(含 sudo 的孙进程 ss)。

    实测: 本机 `ss -H -tlnp` 会挂起不返回(exit 124), subprocess.run(timeout=)
    只杀 sudo 自身, ss 孙进程成为孤儿 R 态进程持续累积(曾堆到 240+ 个,
    拖垮 dashboard 主循环)。start_new_session 让子进程自成进程组,超时后
    os.killpg 一网打尽。
    """
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _run_sudo_ss():
    try:
        proc = subprocess.Popen(
            ["sudo", "-n", "ss", "-H", "-tlnp"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        try:
            out, err = proc.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            return {}
        if proc.returncode != 0:
            return {}
        mapping = {}
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            procinfo = parts[5] if len(parts) > 5 else ""
            m = re.search(r'users:\(\("([^"]+)"', procinfo)
            if not m:
                continue
            name = m.group(1)
            pm = re.search(r"pid=(\d+)", procinfo)
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


def priv_scan():
    """同步扫一次 sudo ss,缓存结果供本次 gather() 的多次 priv_lookup 复用。

    只在 gather() 调用时执行(即用户访问页面触发),无后台线程、无自动刷新。
    本机 ss 极慢(24min),_run_sudo_ss 内部 8s 超时 + 杀进程组,不会阻塞页面。
    """
    with _priv["lock"]:
        if _priv["map"] is None:
            _priv["map"] = _run_sudo_ss()
        return _priv["map"]


def priv_lookup(port, ip):
    """返回 sudo 层记录的该端口进程列表;无数据时返回 None(用不到就降级)。"""
    m = priv_scan()
    if not m:
        return None
    return m.get(port)


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


_SELF_UNIT = None


def _self_unit():
    """dashboard 自己所属的 systemd 单元(从 /proc/self/cgroup 读)。
    dashboard spawn 的子进程(如手动服务)同属该 cgroup —— 它们是直接进程,
    不是 systemd 服务,classify 需特判。"""
    global _SELF_UNIT
    if _SELF_UNIT is None:
        _SELF_UNIT = ""
        try:
            with open("/proc/self/cgroup", encoding="utf-8") as f:
                for line in f:
                    path = line.split(":", 2)[-1]
                    m = re.search(r"/([^/]+\.(?:service|scope))$", path)
                    if m:
                        _SELF_UNIT = m.group(1)
                        break
        except OSError:
            pass
    return _SELF_UNIT


def classify(cgroup_text):
    """根据 cgroup 判断: 容器内 / systemd 单元 / 直接进程。
    scope: user=用户自己启动的, system=系统服务, docker=容器。"""
    m = CID_RE.search(cgroup_text)
    if m:
        return {"type": "docker", "container_id": m.group(1)[:12],
                "unit": None, "scope": "docker"}
    self_unit = _self_unit()
    for line in cgroup_text.splitlines():
        path = line.split(":", 2)[-1]
        mm = re.search(r"/([^/]+\.(?:service|scope))$", path)
        if mm:
            unit = mm.group(1)
            # tmux-spawn-*.scope / session-*.scope 是终端会话 scope,不是服务
            if unit.startswith(("user@", "session-", "tmux-spawn-", "app-", "systemd-")):
                continue
            if unit == self_unit:
                # dashboard 自身及它后台拉起的子进程(手动服务): 直接进程
                return {"type": "direct", "unit": None, "container_id": None,
                        "scope": "user"}
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


_docker_ps_cache = {"t": 0.0, "map": {}}


def docker_port_map():
    """docker ps 的端口映射: 宿主机端口 -> (容器名, 容器短ID)。

    访问时即扫(无后台刷新)。2s 内的重复请求复用结果,避免同一页面加载
    的 HTML+API 两次请求各扫一遍。docker ps 本身很快(远快于 ss)。
    """
    now = time.time()
    if now - _docker_ps_cache["t"] < 2:
        return _docker_ps_cache["map"]
    mapping = {}
    try:
        proc = subprocess.Popen(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, start_new_session=True,
        )
        try:
            out, _ = proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            out = ""
    except Exception:
        out = ""
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        cid, name, ports = parts[0], parts[1], parts[2]
        for chunk in ports.split(","):
            m = re.search(r":(\d+)->", chunk.strip())
            if m:
                mapping.setdefault(int(m.group(1)), (name, cid[:12]))
    _docker_ps_cache.update({"t": now, "map": mapping})
    return mapping


def gather():
    """扫描一次,返回服务列表(按端口排序,同端口合并)。

    只在用户访问页面时调用 —— 没有后台自动刷新,没人访问时 dashboard
    完全静默(进程停着但不消耗 CPU/IO)。每次访问都重新扫描,不跨请求缓存。
    """
    # 重置 ss 兜底缓存:每次访问都即时获取最新状态,不用旧数据
    with _priv["lock"]:
        _priv["map"] = None
    socks = listen_sockets()
    inode_pid = inode_to_pid()
    docker_ports = docker_port_map()
    self_pid = os.getpid()

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

    # 受管手动进程服务: 即使端口没监听也保留一行(标 inactive),让用户能点「继续」。
    # 这样暂停的服务不会从服务表消失 —— 用户要求暂停后还能恢复。
    listen_ports = {s["port"] for s in socks}
    for u in MANAGE_UNITS:
        if u["kind"] != "proc" or u["port"] in listen_ports:
            continue
        if any(e["port"] == u["port"] for e in entries):
            continue
        entries.append({
            "ip": "0.0.0.0", "port": u["port"], "pids": [],
            "name": u.get("label", u["id"]) + " (paused)",
            "cmdline": "—", "cwd": None,
            "type": "direct", "unit": None, "container_id": None,
            "scope": "user", "docker_proxy": False, "is_self": False,
            "paused": True,
        })
    entries.sort(key=lambda e: e["port"])
    return entries


# ---------------- 系统信息(负载/CPU/内存/磁盘) ----------------

DEFAULT_LANG = "zh"
LANG_KEYS = ("zh", "en", "ja")

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
    total = available = swap_total = swap_free = 0
    for line in read("/proc/meminfo").splitlines():
        parts = line.split()
        if parts[0] == "MemTotal:":
            total = int(parts[1]) * 1024
        elif parts[0] == "MemAvailable:":
            available = int(parts[1]) * 1024
        elif parts[0] == "SwapTotal:":
            swap_total = int(parts[1]) * 1024
        elif parts[0] == "SwapFree:":
            swap_free = int(parts[1]) * 1024
    used = total - available
    percent = round(100 * used / total, 1) if total else 0.0
    swap_used = swap_total - swap_free
    swap_percent = round(100 * swap_used / swap_total, 1) if swap_total else 0.0
    return {"total": total, "used": used, "available": available,
            "percent": percent,
            "swap_total": swap_total, "swap_used": swap_used,
            "swap_percent": swap_percent}


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
    # 负载水位("还能开几个 goal") + CPU/内存 top5 进程
    load15 = info["loadavg"][2] if info["loadavg"] else None
    zone, n = load_zone(load15)
    try:
        tops = top_procs(5)
    except Exception:
        tops = {"cpu": [], "mem": []}
    info["goalload"] = {"load15": load15, "cores": info["cpu_count"],
                        "zone": zone, "n": n,
                        "cpu_top": tops["cpu"], "mem_top": tops["mem"]}
    return info


def fmt_bytes(n):
    if not n:
        return "—"
    g = n / (1024 ** 3)
    return f"{g:.0f} G" if g >= 100 else f"{g:.1f} G"


def fmt_uptime(sec, lang=DEFAULT_LANG):
    if not sec:
        return "—"
    d, rem = divmod(int(sec), 86400)
    h, m = divmod(rem, 3600)
    m //= 60
    if d:
        return t(lang, "day_hour", d=d, h=h)
    if h:
        return t(lang, "hour_min", h=h, m=m)
    return t(lang, "minute", m=m)


# ---------------- 内联 SVG 图标系统(零依赖, 与前端 JS 共享同一份 path 表) ----------------
# 风格: 16x16 viewBox, stroke=currentColor, stroke-width=1.5, round linecap/join。
# JS 侧经 {{ICONS_JSON}} 注入同一份表, 保证两端图标完全一致。
ICONS = {
    "wait":   '<path d="M8 1.5A6.5 6.5 0 1 1 1.5 8"/>',
    "ok":     '<circle cx="8" cy="8" r="6.5"/><path d="m5.3 8.3 1.9 1.9 3.5-4.2"/>',
    "warn":   '<path d="M8 1.8 15 13.8H1Z"/><path d="M8 6v3.4"/><path d="M8 11.9h.01"/>',
    "err":    '<circle cx="8" cy="8" r="6.5"/><path d="m5.7 5.7 4.6 4.6M10.3 5.7l-4.6 4.6"/>',
    "dot":    '<circle cx="8" cy="8" r="4.5" fill="currentColor" stroke="none"/>',
    "pause":  '<path d="M5.5 3.5v9M10.5 3.5v9"/>',
    "retry":  '<path d="M2.6 8a5.4 5.4 0 0 1 9.3-3.7M13.4 8a5.4 5.4 0 0 1-9.3 3.7"/>'
              '<path d="M12.1 1.7v2.8H9.3M3.9 14.3v-2.8h2.8"/>',
    "up":     '<circle cx="8" cy="8" r="6.5"/><path d="M8 11V5.6M5.7 7.9 8 5.6l2.3 2.3"/>',
    "bell":   '<path d="M8 2.2a3.8 3.8 0 0 0-3.8 3.8c0 3-1.1 4.1-1.7 4.8h11c-.6-.7-1.7-1.8-1.7-4.8A3.8 3.8 0 0 0 8 2.2Z"/>'
              '<path d="M6.6 12.8a1.5 1.5 0 0 0 2.8 0"/>',
    "trash":  '<path d="M2.8 4.2h10.4M6.4 4.2V2.6h3.2v1.6M4.2 4.2l.6 9.2h6.4l.6-9.2M6.7 6.8v4M9.3 6.8v4"/>',
    "box":    '<path d="M8 1.8 13.6 4.6v6.8L8 14.2 2.4 11.4V4.6Z"/><path d="M2.4 4.6 8 7.4l5.6-2.8M8 7.4v6.8"/>',
    "folder": '<path d="M1.8 4.3c0-.6.5-1.1 1.1-1.1h3l1.5 1.7h5.7c.6 0 1.1.5 1.1 1.1v6c0 .6-.5 1.1-1.1 1.1H2.9c-.6 0-1.1-.5-1.1-1.1Z"/>',
    "file":   '<path d="M4 1.8h5.2L12.4 5v9.2H4Z"/><path d="M9 1.8V5h3.4"/>',
    "heart":  '<path d="M8 13.6S1.8 10.2 1.8 6C1.8 4 3.3 2.6 5.1 2.6c1.2 0 2.3.7 2.9 1.7.6-1 1.7-1.7 2.9-1.7 1.8 0 3.3 1.4 3.3 3.4 0 4.2-6.2 7.6-6.2 7.6Z"/>',
    "gauge":  '<path d="M2.4 11.2a5.9 5.9 0 1 1 11.2 0"/><path d="M8 11 10.6 6.8"/><path d="M8 11h.01"/>',
    "clock":  '<circle cx="8" cy="8" r="6.4"/><path d="M8 4.6V8l2.3 1.7"/>',
    "ext":    '<path d="M6.8 3.4H4.2c-1 0-1.8.8-1.8 1.8v6.6c0 1 .8 1.8 1.8 1.8h6.6c1 0 1.8-.8 1.8-1.8V9.2"/>'
              '<path d="M9.4 2.6h4v4M13 3 7.8 8.2"/>',
    "copy":   '<rect x="5.6" y="5.6" width="7.9" height="7.9" rx="1.3"/>'
              '<path d="M10.4 5.6V3.9c0-.7-.6-1.3-1.3-1.3H3.9c-.7 0-1.3.6-1.3 1.3v5.2c0 .7.6 1.3 1.3 1.3h1.7"/>',
    "refresh":'<path d="M13.6 8a5.6 5.6 0 1 1-1.7-4"/><path d="M12.3 1.4v2.8H9.5"/>',
    "lock":   '<rect x="3.4" y="7" width="9.2" height="6.6" rx="1.3"/><path d="M5.6 7V5.2a2.4 2.4 0 0 1 4.8 0V7"/>',
    "close":  '<path d="m4.2 4.2 7.6 7.6M11.8 4.2l-7.6 7.6"/>',
    "chev":   '<path d="m6 4 4.6 4L6 12"/>',
    "down":   '<path d="M8 2.6v9.2M4.6 8.4 8 11.8l3.4-3.4"/>',
    "cpu":    '<rect x="4" y="4" width="8" height="8" rx="1.3"/>'
              '<path d="M6.2 1.6v2M9.8 1.6v2M6.2 12.4v2M9.8 12.4v2M1.6 6.2h2M1.6 9.8h2M12.4 6.2h2M12.4 9.8h2"/>',
    "mem":    '<rect x="2.4" y="4.8" width="11.2" height="7" rx="1.1"/><path d="M5.2 8.2v1.6M8 7v2.8M10.8 8.2v1.6"/>',
    "disk":   '<ellipse cx="8" cy="3.9" rx="5.2" ry="1.9"/>'
              '<path d="M2.8 3.9v8.2c0 1.05 2.33 1.9 5.2 1.9s5.2-.85 5.2-1.9V3.9"/>'
              '<path d="M2.8 8c0 1.05 2.33 1.9 5.2 1.9s5.2-.85 5.2-1.9"/>',
    "load":   '<path d="M1.4 8.6h2.6l2-5.4 3 10 2-4.6h3.6"/>',
    "swap":   '<path d="M3.2 6.2a5.2 5.2 0 0 1 9.4-1.8M12.8 9.8a5.2 5.2 0 0 1-9.4 1.8"/>'
              '<path d="M13 2.2v2.6h-2.6M3 13.8v-2.6h2.6"/>',
    "play":   '<path d="M5.2 3.4 12.4 8l-7.2 4.6Z"/>',
    "stop":   '<rect x="4" y="4" width="8" height="8" rx="1.2"/>',
    "sun":    '<circle cx="8" cy="8" r="3.2"/>'
              '<path d="M8 1.2v1.8M8 13v1.8M1.2 8H3M13 8h1.8M3.2 3.2l1.3 1.3M11.5 11.5l1.3 1.3M12.8 3.2l-1.3 1.3M4.5 11.5l-1.3 1.3"/>',
    "moon":   '<path d="M13.4 10.4A5.8 5.8 0 0 1 5.6 2.6a6 6 0 1 0 7.8 7.8Z"/>',
    "auto":   '<circle cx="8" cy="8" r="6.4"/><path d="M8 1.6a6.4 6.4 0 0 1 0 12.8Z" fill="currentColor" stroke="none"/>',
}

_ICO_PAT = re.compile(r"\{\{ICO:([a-z0-9_]+)(?::(\d+))?\}\}")


def icon(name, size=16, cls="ic"):
    """name -> 内联 SVG 字符串; 未知名字回退为空心圆点。"""
    path = ICONS.get(name) or ICONS["dot"]
    c = f' class="{cls}"' if cls else ""
    return (f'<svg{c} width="{size}" height="{size}" viewBox="0 0 16 16" fill="none" '
            f'stroke="currentColor" stroke-width="1.5" stroke-linecap="round" '
            f'stroke-linejoin="round" aria-hidden="true">{path}</svg>')


# 事件类型 -> (图标, 语义色 class, i18n key)。前端 EV_META 与此同构。
KIND_META = {
    "complete": ("ok", "t-green", "evk_complete"),
    "recover": ("up", "t-green", "evk_recover"),
    "restart": ("retry", "t-red", "evk_restart"),
    "nudge": ("bell", "t-warn", "evk_nudge"),
    "pause": ("pause", "t-warn", "evk_pause"),
    "cleanup": ("trash", "t-green", "evk_cleanup"),
    "commit": ("box", "t-green", "evk_commit"),
}

def render_sysbar(s, lang=DEFAULT_LANG):
    """系统信息卡片条(打开页面时渲染一次,手动刷新才更新)。"""
    loadavg = " / ".join(f"{x:.2f}" for x in s["loadavg"]) if s.get("loadavg") else "—"
    cpu = f'{s["cpu_usage"]}% · {s["cpu_count"]} {t(lang, "unit_core")}'
    mem = s.get("mem") or {}
    mem_txt = f'{fmt_bytes(mem.get("used"))} / {fmt_bytes(mem.get("total"))} ({mem.get("percent", 0)}%)'
    disk = s.get("disk") or {}
    disk_txt = f'{fmt_bytes(disk.get("used"))} / {fmt_bytes(disk.get("total"))} ({disk.get("percent", 0)}%)'
    cards = [
        ("load", t(lang, "sys_load"), loadavg),
        ("cpu", "CPU", cpu),
        ("mem", t(lang, "sys_mem"), mem_txt),
        ("disk", t(lang, "sys_disk"), disk_txt),
        ("up", t(lang, "sys_up"), fmt_uptime(s.get("uptime"), lang)),
    ]
    # data-k: 手机端双击手势定位(负载卡双击→Goal页, 磁盘卡双击→展开top进程)
    k_ico = {"load": "load", "cpu": "cpu", "mem": "mem", "disk": "disk", "up": "clock"}
    return '<div class="sysbar" id="sysbar">' + "".join(
        f'<div class="stat" data-k="{k}"><div class="label">'
        f'<span class="lb-ico">{icon(k_ico.get(k, "dot"), 13)}</span>{lbl}</div>'
        f'<div class="value">{val}</div></div>' for k, lbl, val in cards) + "</div>"


# ---------------- 国际化 ----------------
# 三语(中文 / English / 日本語),按 Accept-Language 自动切换,?lang= 可强制覆盖。

L10N = {
    "zh": {
        "title": "服务一览", "github_repo": "GitHub 仓库",
        "updated": "更新于", "svc_pre": "", "svc_post": " 个监听端口", "auto_refresh": "自动刷新",
        "refresh": "刷新", "ptr_pull": "下拉刷新", "ptr_release": "松开刷新", "ptr_loading": "刷新中…",
        "chip_user": "用户服务", "chip_docker": "Docker", "chip_system": "系统服务",
        "chip_all": "全部", "chip_omp": "agent任务", "chip_watchdog": "定时任务",
        "chip_tmux": "tmux状态", "chip_manage": "服务管理",
        "th_svc": "服务", "th_port": "端口", "th_addr": "监听地址", "th_pid": "PID",
        "th_cmd": "启动命令", "th_cwd": "工作目录",
        "th_ctl": "控制", "ctl_pause": "暂停", "ctl_resume": "继续", "ctl_checking": "…",
        "badge_docker": "容器", "badge_direct": "进程", "badge_self": "本页",
        "badge_paused": "已暂停",
        "badge_proxy": "Docker映射", "detail_cid": "容器ID", "detail_unit": "systemd 单元",
        "loopback": "仅本机", "no_match": "没有匹配的服务",
        "sys_load": "负载", "sys_cpu": "CPU", "sys_mem": "内存", "sys_disk": "磁盘 /",
        "sys_up": "运行", "unit_core": "核",
        "day_hour": "{d} 天 {h} 小时", "hour_min": "{h} 小时 {m} 分", "minute": "{m} 分",
        "tbd_wd": "看门狗", "tbd_rd": "提醒", "tbd_sc": "定时",
        "t_scope_user": "用户", "t_scope_sys": "系统", "t_last": "上次",
        "t_cycle": "周期", "t_source": "来源", "t_cmd": "命令", "t_lastrun": "最近执行",
        "t_task": "任务", "panel_watchdog": "定时任务 / 看门狗", "t_total": "共 {n} 项",
        "t_none": "没有定时任务 / 看门狗",
        "cron_hourly": "每小时", "cron_daily": "每天", "cron_weekly": "每周",
        "cron_monthly": "每月", "cron_daily_twice": "每天 {h1}:{m1} / {h2}:{m2}",
        "cron_daily_at": "每天 {h}:{m}", "cron_daily_raw": "每天 {hm}",
        "cron_every_min": "每 {n} 分钟", "cron_every_hour": "每 {n} 小时",
        "cron_every_sec": "每 {n}", "cron_weekly_at": "每周{days} {h}:00",
        "cron_month_day": "{mon}月{dom}日 {h}:{m}", "cron_by_unit": "按 unit 配置",
        "wd_sun": "日", "wd_mon": "一", "wd_tue": "二", "wd_wed": "三",
        "wd_thu": "四", "wd_fri": "五", "wd_sat": "六",
        "a_running": "运行中", "a_blocked": "阻塞", "a_idle": "空闲", "a_done": "已完成",
        "a_status": "状态", "a_loc": "tmux / 目录", "a_active": "最近活动", "a_tool": "当前工具",
        "a_ago": "{s}s 前", "a_openlog": "点击查看日志 · {g}",
        "a_openterm": "点击查看实时画面 · pid {p}",
        "a_title": "agent 任务", "a_hint": "{n} 项 · 点击标题查看日志",
        "a_none": "没有检测到 agent", "a_th_agent": "Agent",
        "a_loading": "加载中…", "a_recent": "最近活动", "a_term": "终端画面",
        "a_nolog": "没有可用的日志 / 终端画面", "a_fail": "加载失败: {e}",
        "aev_exit": "会话结束: {r}", "aev_goal": "目标: {o}", "aev_comp": "压缩: {s}",
        "tmux_panel": "tmux 状态", "tmux_panes": "{n} 个窗格", "tmux_active": "当前",
        "tmux_th_pane": "窗格", "tmux_th_title": "标题", "tmux_th_size": "尺寸",
        "tmux_none": "tmux 未运行",
        "m_server": "Zircon 服务器 (ServerCore)", "m_server_desc": "Mir3 传奇3 服务器主进程",
        "m_bots": "Zircon 机器人 (BotRunner)", "m_bots_desc": "AI 机器人运行器",
        "m_ts": "Tailscale", "m_ts_desc": "Tailscale 组网服务",
        "m_wilviewer": "WilViewer 图档服务", "m_wilviewer_desc": "Mir3 客户端图档浏览 (8765)",
        "m_mapviewer": "MapViewer 地图服务", "m_mapviewer_desc": "Mir3 地图浏览 (8899)",
        "m_start": "启动", "m_stop": "停止", "m_restart": "重启", "m_pause": "暂停",
        "m_resume": "恢复", "m_enable": "启用",
        "m_state_fail": "状态获取失败", "m_paused": "已暂停 (SIGSTOP)",
        "m_title_stop": "停止服务", "m_title_restart": "重启服务",
        "m_title_resume": "SIGCONT 恢复", "m_title_pause": "SIGSTOP 挂起,不终止进程",
        "m_title_start": "启动服务",
        "m_panel": "服务管理",
        "m_hint": "systemd: 暂停=挂起(SIGSTOP);手动服务: 暂停=停止,启用=重新启动",
        "m_confirm": "确认要{label} {unit} 吗?", "m_doing": "执行中…",
        "m_unknown_unit": "未知受管单元: {id}", "m_show_fail": "systemctl show 失败 (code {c})",
        "m_unknown_action": "未知操作: {a}",
        "m_done_start": "启动已执行", "m_done_stop": "停止已执行",
        "m_done_restart": "重启已执行", "m_done_pause": "暂停已执行",
        "m_done_resume": "恢复已执行", "m_fail": "{a}失败 (code {c})",
        "m_no_self": "不能操作 dashboard 自身(入口)", "m_started_async": "已后台启动(端口未即时就绪)",
        "m_no_touch": "不能操作受保护进程: {name}",
        "m_badreq": "请求体解析失败: {e}",
        "g_panel": "Goal 进度", "g_hint": "实时采集: tmux pane + session 活跃度 + watchdog 台账",
        "g_active": "在跑", "g_paused": "已暂停", "g_retry": "API 重试中",
        "g_done": "已完成", "g_lost": "会话丢失",
        "g_ctx": "上下文", "g_ctx_high": "偏高", "g_ctx_stop": "建议停止",
        "g_last": "最近活动", "g_stalled": "可能 STALLED",
        "g_copy": "复制 resume 命令", "g_copied": "已复制",
        "g_none": "当前没有在跑的 goal",
        "g_done_fold": "已完成 goal（{n}）",
        "ld_title": "建议并发", "ld_ok": "还可开 {n} 个 goal",
        "ld_full": "满载，别再开了", "ld_over": "过载，先别开",
        "ld_load": "load15 {l} / {c}核",
        "ld_cpu": "CPU top5", "ld_mem": "内存 top5",
        "ev_title": "最近事件", "ev_hint": "watchdog 动作 + goal 完成台账",
        "ev_complete": "完成", "ev_restart": "watchdog 重启",
        "ev_nudge": "watchdog 催行", "ev_recover": "已恢复",
        "ev_pause": "目标暂停", "ev_cleanup": "清理",
        "ev_other": "·", "ev_none": "暂无事件",
        "g_ago_s": "{s} 秒前", "g_ago_m": "{m} 分钟前", "g_ago_h": "{h} 小时前",
        "tab_home": "概览", "tab_goal": "Goal", "tab_svc": "服务", "tab_model": "模型", "tab_log": "日志",
        "act_open": "打开", "act_copy_addr": "复制地址", "g_detail": "详情",
        "chart_title": "负载 / CPU 趋势", "chart_win": "窗口 {n} 点",
        "chart_empty": "采样中：刷新几次就有曲线了（双指捏合可调时间窗）",
        "log_pick": "选择 agent 查看日志",
        "st_all_ok": "全部正常", "st_alert": "有告警 {n}",
        "st_stale": "数据过期", "st_loading": "读取中…",
        "m_svc_ok": "正常服务", "m_goal_run": "在跑 Goal", "m_goal_bad": "暂停/异常",
        "m_alerts": "未处理告警",
        "al_title": "需要处理", "al_none": "没有需要处理的告警",
        "al_paused": "Goal 已暂停", "al_stalled": "疑似挂死(STALLED)",
        "al_lost": "会话丢失", "al_done": "已完成,待查看",
        "al_ignore": "忽略", "al_detail": "详情",
        "rc_title": "最近活动", "rc_more": "全部 →",
        "lf_status": "状态", "lf_source": "来源", "lf_time": "时间",
        "lf_all": "全部", "lf_success": "成功", "lf_warn": "告警",
        "lf_fail": "失败", "lf_recover": "恢复",
        "lf_wd": "watchdog", "lf_done": "完成", "lf_commit": "commit",
        "lf_3d": "3天", "lf_7d": "7天",
        "ev_loop": "循环 ×{n}", "ev_empty": "该时间范围内没有事件",
        "ev_commit": "提交",
        "evk_complete": "完成", "evk_restart": "重启(进程死亡)",
        "evk_nudge": "催行", "evk_recover": "已恢复", "evk_pause": "暂停",
        "evk_cleanup": "清理", "evk_commit": "提交", "evk_other": "其他",
        "g_ago_d": "{d} 天前",
        "tab_tools": "ツール",
        "tl_health_title": "健康检查", "tl_health_run": "跑一次检查", "tl_health_loading": "检查中…",
        "tl_h_load": "负载", "tl_h_cpu": "CPU", "tl_h_mem": "内存", "tl_h_swap": "Swap",
        "tl_h_disk": "磁盘 /", "tl_h_temp": "温度", "tl_h_trend": "磁盘趋势",
        "tl_h_trend_base": "已记基线, 明天起算增速", "tl_h_trend_days": "日增 {g} · 预计满盘 {d}",
        "tl_h_procs": "关键进程", "tl_h_ports": "端口心跳", "tl_h_wd": "watchdog 1h 异常",
        "tl_copy_ssh": "ssh 命令", "tl_copy_lan": "局域网 IP", "tl_copy_ts": "Tailscale IP",
        "tl_fs_title": "文件浏览", "tl_fs_filter": "过滤…", "tl_fs_hidden": "隐藏文件",
        "tl_fs_du": "计算大小", "tl_fs_du_run": "计算中…(5s)", "tl_fs_du_none": "非目录",
        "tl_fs_dl": "下载", "tl_fs_empty": "空目录或全部被过滤",
        "tl_clean_title": "垃圾清理", "tl_clean_scan": "扫描", "tl_clean_scanning": "扫描中…",
        "tl_clean_exec": "执行清理", "tl_clean_confirm": "确认清理所选项目？此操作不可撤销",
        "tl_clean_docker": "docker 磁盘占用", "tl_clean_docker_prune": "docker prune",
        "tl_clean_docker_confirm": "确认 docker system prune？将删除所有悬空镜像/停止容器/未用网络",
        "tl_clean_total": "可释放合计", "tl_clean_freed": "实际释放(df)",
        "tl_net_title": "网络速测", "tl_net_run": "测一次", "tl_net_run_ing": "测速中…",
        "tl_net_ext": "外网 HEAD", "tl_net_ts": "Tailscale 对端",
        "tl_usvc_title": "用户服务(重启)", "tl_usvc_unlock": "解锁",
        "tl_usvc_hint": "输入 I-KNOW 解锁重启按钮", "tl_usvc_wrong": "确认字符串不匹配",
        "tl_usvc_restart": "重启", "tl_usvc_loading": "读取中…", "tl_usvc_none": "无用户级服务",
        "tl_cron_title": "计划任务一览", "tl_g1_title": "工具直达",
        "theme_title": "外观", "th_auto": "跟随系统", "th_dark": "深色", "th_light": "浅色",
        "refresh_title": "点击刷新 · 长按锁定/解锁自动刷新",
        "locked_toast": "已锁定：自动刷新暂停", "unlocked_toast": "已解锁：自动刷新恢复",
    },
    "en": {
        "title": "Services", "github_repo": "GitHub repo",
        "updated": "updated", "svc_pre": "", "svc_post": " listening ports", "auto_refresh": "Auto refresh",
        "refresh": "Refresh", "ptr_pull": "Pull to refresh", "ptr_release": "Release to refresh", "ptr_loading": "Refreshing…",
        "chip_user": "User services", "chip_docker": "Docker", "chip_system": "System services",
        "chip_all": "All", "chip_omp": "Agents", "chip_watchdog": "Tasks",
        "chip_tmux": "tmux", "chip_manage": "Manage",
        "th_svc": "Service", "th_port": "Port", "th_addr": "Listen addr", "th_pid": "PID",
        "th_cmd": "Command", "th_cwd": "Work dir",
        "th_ctl": "Control", "ctl_pause": "Pause", "ctl_resume": "Resume", "ctl_checking": "…",
        "badge_docker": "Container", "badge_direct": "Process", "badge_self": "This page",
        "badge_paused": "Paused",
        "badge_proxy": "Docker map", "detail_cid": "Container ID", "detail_unit": "systemd unit",
        "loopback": "local only", "no_match": "No matching services",
        "sys_load": "Load", "sys_cpu": "CPU", "sys_mem": "Memory", "sys_disk": "Disk /",
        "sys_up": "Uptime", "unit_core": "cores",
        "day_hour": "{d}d {h}h", "hour_min": "{h}h {m}m", "minute": "{m}m",
        "tbd_wd": "Watchdog", "tbd_rd": "Reminder", "tbd_sc": "Scheduled",
        "t_scope_user": "user", "t_scope_sys": "system", "t_last": "last ",
        "t_cycle": "Schedule", "t_source": "Source", "t_cmd": "Command", "t_lastrun": "Last run",
        "t_task": "Task", "panel_watchdog": "Tasks / Watchdogs", "t_total": "{n} total",
        "t_none": "No tasks / watchdogs",
        "cron_hourly": "hourly", "cron_daily": "daily", "cron_weekly": "weekly",
        "cron_monthly": "monthly", "cron_daily_twice": "daily {h1}:{m1} / {h2}:{m2}",
        "cron_daily_at": "daily at {h}:{m}", "cron_daily_raw": "daily {hm}",
        "cron_every_min": "every {n} min", "cron_every_hour": "every {n} h",
        "cron_every_sec": "every {n}", "cron_weekly_at": "weekly {days} {h}:00",
        "cron_month_day": "{mon}/{dom} {h}:{m}", "cron_by_unit": "per unit config",
        "wd_sun": "Sun", "wd_mon": "Mon", "wd_tue": "Tue", "wd_wed": "Wed",
        "wd_thu": "Thu", "wd_fri": "Fri", "wd_sat": "Sat",
        "a_running": "Running", "a_blocked": "Blocked", "a_idle": "Idle", "a_done": "Completed",
        "a_status": "Status", "a_loc": "tmux / dir", "a_active": "Last activity",
        "a_tool": "Current tool", "a_ago": "{s}s ago",
        "a_openlog": "Click for log · {g}", "a_openterm": "Click for live view · pid {p}",
        "a_title": "Agent tasks", "a_hint": "{n} items · click title for log",
        "a_none": "No agents detected", "a_th_agent": "Agent",
        "a_loading": "Loading…", "a_recent": "Recent activity", "a_term": "Terminal",
        "a_nolog": "No log / terminal available", "a_fail": "Failed: {e}",
        "aev_exit": "session ended: {r}", "aev_goal": "Goal: {o}", "aev_comp": "Compaction: {s}",
        "tmux_panel": "tmux status", "tmux_panes": "{n} panes", "tmux_active": "active",
        "tmux_th_pane": "Pane", "tmux_th_title": "Title", "tmux_th_size": "Size",
        "tmux_none": "tmux not running",
        "m_server": "Zircon Server (ServerCore)", "m_server_desc": "Mir3 legend3 server main process",
        "m_bots": "Zircon Bots (BotRunner)", "m_bots_desc": "AI bot runner",
        "m_ts": "Tailscale", "m_ts_desc": "Tailscale mesh service",
        "m_wilviewer": "WilViewer Image Service", "m_wilviewer_desc": "Mir3 client image browser (8765)",
        "m_mapviewer": "MapViewer Map Service", "m_mapviewer_desc": "Mir3 map browser (8899)",
        "m_start": "Start", "m_stop": "Stop", "m_restart": "Restart", "m_pause": "Pause",
        "m_resume": "Resume", "m_enable": "Enable",
        "m_state_fail": "Failed to get status", "m_paused": "Paused (SIGSTOP)",
        "m_title_stop": "Stop service", "m_title_restart": "Restart service",
        "m_title_resume": "Resume (SIGCONT)", "m_title_pause": "Suspend (SIGSTOP), keeps process",
        "m_title_start": "Start service",
        "m_panel": "Service control",
        "m_hint": "systemd: pause = SIGSTOP suspend; manual svc: pause = stop, enable = relaunch",
        "m_confirm": "Confirm {label} {unit}?", "m_doing": "Running…",
        "m_unknown_unit": "Unknown unit: {id}", "m_show_fail": "systemctl show failed (code {c})",
        "m_unknown_action": "Unknown action: {a}",
        "m_done_start": "Start executed", "m_done_stop": "Stop executed",
        "m_done_restart": "Restart executed", "m_done_pause": "Pause executed",
        "m_done_resume": "Resume executed", "m_fail": "{a} failed (code {c})",
        "m_no_self": "Cannot manage the dashboard itself (entry point)", "m_started_async": "Launched in background (port not ready yet)",
        "m_no_touch": "Protected process: {name} cannot be managed",
        "m_badreq": "Bad request: {e}",
        "g_panel": "Goal progress", "g_hint": "live: tmux pane + session mtime + watchdog logs",
        "g_active": "running", "g_paused": "paused", "g_retry": "API retrying",
        "g_done": "completed", "g_lost": "session lost",
        "g_ctx": "context", "g_ctx_high": "high", "g_ctx_stop": "consider stopping",
        "g_last": "last activity", "g_stalled": "maybe STALLED",
        "g_copy": "Copy resume cmd", "g_copied": "copied",
        "g_none": "No running goals",
        "g_done_fold": "Completed goals ({n})",
        "ld_title": "Concurrency", "ld_ok": "room for {n} more goal(s)",
        "ld_full": "at capacity, no more goals", "ld_over": "overloaded, hold off",
        "ld_load": "load15 {l} / {c} cores",
        "ld_cpu": "CPU top5", "ld_mem": "Memory top5",
        "ev_title": "Recent events", "ev_hint": "watchdog actions + completions",
        "ev_complete": "complete", "ev_restart": "watchdog restart",
        "ev_nudge": "watchdog nudge", "ev_recover": "recovered",
        "ev_pause": "goal paused", "ev_cleanup": "cleanup",
        "ev_other": "·", "ev_none": "No events yet",
        "g_ago_s": "{s}s ago", "g_ago_m": "{m}m ago", "g_ago_h": "{h}h ago",
        "tab_home": "Overview", "tab_goal": "Goal", "tab_svc": "Services", "tab_model": "Models", "tab_log": "Logs",
        "act_open": "Open", "act_copy_addr": "Copy address", "g_detail": "details",
        "chart_title": "Load / CPU trend", "chart_win": "window {n} pts",
        "chart_empty": "Collecting samples: refresh a few times (pinch to adjust window)",
        "log_pick": "Pick an agent for logs",
        "st_all_ok": "All good", "st_alert": "{n} alert(s)",
        "st_stale": "stale data", "st_loading": "loading…",
        "m_svc_ok": "services OK", "m_goal_run": "running goals", "m_goal_bad": "paused/bad",
        "m_alerts": "open alerts",
        "al_title": "Needs attention", "al_none": "Nothing needs attention",
        "al_paused": "Goal paused", "al_stalled": "possibly stalled",
        "al_lost": "session lost", "al_done": "completed, review pending",
        "al_ignore": "Ignore", "al_detail": "Details",
        "rc_title": "Recent activity", "rc_more": "All →",
        "lf_status": "status", "lf_source": "source", "lf_time": "time",
        "lf_all": "all", "lf_success": "ok", "lf_warn": "warn",
        "lf_fail": "fail", "lf_recover": "recovered",
        "lf_wd": "watchdog", "lf_done": "done", "lf_commit": "commit",
        "lf_3d": "3d", "lf_7d": "7d",
        "ev_loop": "loop ×{n}", "ev_empty": "No events in this range",
        "ev_commit": "commit",
        "evk_complete": "complete", "evk_restart": "relaunch (dead)",
        "evk_nudge": "nudge", "evk_recover": "recovered", "evk_pause": "paused",
        "evk_cleanup": "cleanup", "evk_commit": "commit", "evk_other": "other",
        "g_ago_d": "{d}d ago",
        "tab_tools": "Tools",
        "tl_health_title": "Health check", "tl_health_run": "Run check", "tl_health_loading": "Checking…",
        "tl_h_load": "Load", "tl_h_cpu": "CPU", "tl_h_mem": "Memory", "tl_h_swap": "Swap",
        "tl_h_disk": "Disk /", "tl_h_temp": "Temp", "tl_h_trend": "Disk trend",
        "tl_h_trend_base": "baseline recorded; growth from tomorrow",
        "tl_h_trend_days": "+{g}/day · full at {d}",
        "tl_h_procs": "Key processes", "tl_h_ports": "Port heartbeat", "tl_h_wd": "watchdog 1h anomalies",
        "tl_copy_ssh": "ssh command", "tl_copy_lan": "LAN IP", "tl_copy_ts": "Tailscale IP",
        "tl_fs_title": "Files", "tl_fs_filter": "filter…", "tl_fs_hidden": "hidden files",
        "tl_fs_du": "calc size", "tl_fs_du_run": "calculating…(5s)", "tl_fs_du_none": "not a dir",
        "tl_fs_dl": "download", "tl_fs_empty": "empty or all filtered",
        "tl_clean_title": "Cleanup", "tl_clean_scan": "Scan", "tl_clean_scanning": "Scanning…",
        "tl_clean_exec": "Run cleanup", "tl_clean_confirm": "Clean selected items? Irreversible",
        "tl_clean_docker": "docker disk usage", "tl_clean_docker_prune": "docker prune",
        "tl_clean_docker_confirm": "Run docker system prune? Removes dangling images, stopped containers, unused networks",
        "tl_clean_total": "total reclaimable", "tl_clean_freed": "freed (df)",
        "tl_net_title": "Network test", "tl_net_run": "Run test", "tl_net_run_ing": "Testing…",
        "tl_net_ext": "External HEAD", "tl_net_ts": "Tailscale peer",
        "tl_usvc_title": "User services (restart)", "tl_usvc_unlock": "Unlock",
        "tl_usvc_hint": "type I-KNOW to unlock restart buttons", "tl_usvc_wrong": "wrong confirm string",
        "tl_usvc_restart": "restart", "tl_usvc_loading": "loading…", "tl_usvc_none": "no user services",
        "tl_cron_title": "Scheduled tasks", "tl_g1_title": "Quick links",
        "theme_title": "Appearance", "th_auto": "System", "th_dark": "Dark", "th_light": "Light",
        "refresh_title": "Tap to refresh · long-press to lock/unlock auto refresh",
        "locked_toast": "Locked: auto refresh paused", "unlocked_toast": "Unlocked: auto refresh resumed",
    },
    "ja": {
        "title": "サービス一覧", "github_repo": "GitHub リポジトリ",
        "updated": "更新", "svc_pre": "サービス ", "svc_post": "", "auto_refresh": "自動更新",
        "refresh": "更新", "ptr_pull": "引っ張って更新", "ptr_release": "離して更新", "ptr_loading": "更新中…",
        "chip_user": "ユーザーサービス", "chip_docker": "Docker", "chip_system": "システムサービス",
        "chip_all": "すべて", "chip_omp": "エージェント", "chip_watchdog": "タスク",
        "chip_tmux": "tmux", "chip_manage": "サービス管理",
        "th_svc": "サービス", "th_port": "ポート", "th_addr": "待受アドレス", "th_pid": "PID",
        "th_cmd": "起動コマンド", "th_cwd": "作業ディレクトリ",
        "th_ctl": "操作", "ctl_pause": "一時停止", "ctl_resume": "再開", "ctl_checking": "…",
        "badge_docker": "コンテナ", "badge_direct": "プロセス", "badge_self": "このページ",
        "badge_paused": "一時停止中",
        "badge_proxy": "Dockerマップ", "detail_cid": "コンテナID", "detail_unit": "systemd ユニット",
        "loopback": "ローカルのみ", "no_match": "一致するサービスがありません",
        "sys_load": "負荷", "sys_cpu": "CPU", "sys_mem": "メモリ", "sys_disk": "ディスク /",
        "sys_up": "稼働", "unit_core": "コア",
        "day_hour": "{d}日 {h}時間", "hour_min": "{h}時間 {m}分", "minute": "{m}分",
        "tbd_wd": "ウォッチドッグ", "tbd_rd": "リマインダー", "tbd_sc": "定期",
        "t_scope_user": "ユーザー", "t_scope_sys": "システム", "t_last": "前回 ",
        "t_cycle": "周期", "t_source": "ソース", "t_cmd": "コマンド", "t_lastrun": "最終実行",
        "t_task": "タスク", "panel_watchdog": "タスク / ウォッチドッグ", "t_total": "全 {n} 件",
        "t_none": "タスク / ウォッチドッグはありません",
        "cron_hourly": "毎時", "cron_daily": "毎日", "cron_weekly": "毎週",
        "cron_monthly": "毎月", "cron_daily_twice": "毎日 {h1}:{m1} / {h2}:{m2}",
        "cron_daily_at": "毎日 {h}:{m}", "cron_daily_raw": "毎日 {hm}",
        "cron_every_min": "毎 {n} 分", "cron_every_hour": "毎 {n} 時間",
        "cron_every_sec": "毎 {n}", "cron_weekly_at": "毎週{days} {h}:00",
        "cron_month_day": "{mon}月{dom}日 {h}:{m}", "cron_by_unit": "unit 設定に従う",
        "wd_sun": "日", "wd_mon": "月", "wd_tue": "火", "wd_wed": "水",
        "wd_thu": "木", "wd_fri": "金", "wd_sat": "土",
        "a_running": "実行中", "a_blocked": "ブロック", "a_idle": "待機", "a_done": "完了",
        "a_status": "状態", "a_loc": "tmux / ディレクトリ", "a_active": "最終活動",
        "a_tool": "現在のツール", "a_ago": "{s}秒前",
        "a_openlog": "クリックでログ · {g}", "a_openterm": "クリックでライブ画面 · pid {p}",
        "a_title": "エージェント", "a_hint": "{n} 件 · タイトルをクリックでログ",
        "a_none": "エージェントが検出されません", "a_th_agent": "エージェント",
        "a_loading": "読み込み中…", "a_recent": "最近の活動", "a_term": "ターミナル",
        "a_nolog": "ログ / ターミナルはありません", "a_fail": "失敗: {e}",
        "aev_exit": "セッション終了: {r}", "aev_goal": "目標: {o}", "aev_comp": "圧縮: {s}",
        "tmux_panel": "tmux 状態", "tmux_panes": "{n} ペイン", "tmux_active": "現在",
        "tmux_th_pane": "ペイン", "tmux_th_title": "タイトル", "tmux_th_size": "サイズ",
        "tmux_none": "tmux は起動していません",
        "m_server": "Zircon サーバー (ServerCore)", "m_server_desc": "Mir3 レジェンド3 サーバー本体",
        "m_bots": "Zircon ボット (BotRunner)", "m_bots_desc": "AI ボットランナー",
        "m_ts": "Tailscale", "m_ts_desc": "Tailscale メッシュサービス",
        "m_wilviewer": "WilViewer 画像サービス", "m_wilviewer_desc": "Mir3 クライアント画像ビューア (8765)",
        "m_mapviewer": "MapViewer マップサービス", "m_mapviewer_desc": "Mir3 マップビューア (8899)",
        "m_start": "起動", "m_stop": "停止", "m_restart": "再起動", "m_pause": "一時停止",
        "m_resume": "再開", "m_enable": "有効化",
        "m_state_fail": "状態の取得に失敗", "m_paused": "一時停止中 (SIGSTOP)",
        "m_title_stop": "サービス停止", "m_title_restart": "サービス再起動",
        "m_title_resume": "再開 (SIGCONT)", "m_title_pause": "一時停止 (SIGSTOP),プロセスは維持",
        "m_title_start": "サービス起動",
        "m_panel": "サービス管理",
        "m_hint": "systemd: 一時停止 = SIGSTOP;手動サービス: 一時停止 = 停止,有効化 = 再起動",
        "m_confirm": "{label} {unit} を実行しますか?", "m_doing": "実行中…",
        "m_unknown_unit": "不明なユニット: {id}", "m_show_fail": "systemctl show に失敗 (code {c})",
        "m_unknown_action": "不明な操作: {a}",
        "m_done_start": "起動しました", "m_done_stop": "停止しました",
        "m_done_restart": "再起動しました", "m_done_pause": "一時停止しました",
        "m_done_resume": "再開しました", "m_fail": "{a} に失敗 (code {c})",
        "m_no_self": "ダッシュボード自身は操作できません(入口)", "m_started_async": "バックグラウンド起動しました(ポート未即時)",
        "m_no_touch": "保護プロセス {name} は操作できません",
        "m_badreq": "リクエスト解析失敗: {e}",
        "g_panel": "Goal 進捗", "g_hint": "ライブ取得: tmux pane + session 更新時刻 + watchdog ログ",
        "g_active": "実行中", "g_paused": "一時停止", "g_retry": "API リトライ中",
        "g_done": "完了", "g_lost": "セッション消失",
        "g_ctx": "コンテキスト", "g_ctx_high": "高め", "g_ctx_stop": "停止推奨",
        "g_last": "最終活動", "g_stalled": "STALLED の可能性",
        "ld_ok": "あと {n} 個まで起動可能",
        "g_none": "実行中の goal はありません",
        "g_done_fold": "完了済み goal（{n}）",
        "ld_title": "推奨同時実行",
        "ld_full": "満杯、これ以上は不可", "ld_over": "過負荷、控えて",
        "ld_load": "load15 {l} / {c}コア",
        "ld_cpu": "CPU top5", "ld_mem": "メモリ top5",
        "ev_title": "最近のイベント", "ev_hint": "watchdog 操作 + 完了台帳",
        "ev_complete": "完了", "ev_restart": "watchdog 再起動",
        "ev_nudge": "watchdog 促し", "ev_recover": "復旧",
        "ev_pause": "goal 一時停止", "ev_cleanup": "クリーンアップ",
        "ev_other": "·", "ev_none": "イベントなし",
        "g_ago_s": "{s} 秒前", "g_ago_m": "{m} 分前", "g_ago_h": "{h} 時間前",
        "tab_home": "概要", "tab_goal": "Goal", "tab_svc": "サービス", "tab_model": "モデル", "tab_log": "ログ",
        "act_open": "開く", "act_copy_addr": "アドレスをコピー", "g_detail": "詳細",
        "chart_title": "負荷 / CPU 推移", "chart_win": "ウィンドウ {n} 点",
        "chart_empty": "サンプル収集中：数回更新すると曲線になります（ピンチで調整）",
        "log_pick": "エージェントを選択",
        "st_all_ok": "すべて正常", "st_alert": "要注意 {n} 件",
        "st_stale": "データ期限切れ", "st_loading": "読み込み中…",
        "m_svc_ok": "正常サービス", "m_goal_run": "実行中 Goal", "m_goal_bad": "一時停止・異常",
        "m_alerts": "未対応アラート",
        "al_title": "要対応", "al_none": "対応が必要なアラートはありません",
        "al_paused": "Goal 一時停止中", "al_stalled": "停滞(STALLED)の可能性",
        "al_lost": "セッション消失", "al_done": "完了: 確認待ち",
        "al_ignore": "無視", "al_detail": "詳細",
        "rc_title": "最近の活動", "rc_more": "すべて →",
        "lf_status": "状態", "lf_source": "ソース", "lf_time": "期間",
        "lf_all": "すべて", "lf_success": "成功", "lf_warn": "注意",
        "lf_fail": "失敗", "lf_recover": "復旧",
        "lf_wd": "watchdog", "lf_done": "完了", "lf_commit": "commit",
        "lf_3d": "3日", "lf_7d": "7日",
        "ev_loop": "循環 ×{n}", "ev_empty": "この期間のイベントはありません",
        "ev_commit": "コミット",
        "evk_complete": "完了", "evk_restart": "再始動(プロセス死亡)",
        "evk_nudge": "催促", "evk_recover": "復旧", "evk_pause": "一時停止",
        "evk_cleanup": "クリーンアップ", "evk_commit": "コミット", "evk_other": "その他",
        "g_ago_d": "{d} 日前",
        "tab_tools": "ツール",
        "tl_health_title": "ヘルスチェック", "tl_health_run": "チェック実行", "tl_health_loading": "チェック中…",
        "tl_h_load": "負荷", "tl_h_cpu": "CPU", "tl_h_mem": "メモリ", "tl_h_swap": "Swap",
        "tl_h_disk": "ディスク /", "tl_h_temp": "温度", "tl_h_trend": "ディスク推移",
        "tl_h_trend_base": "ベースライン記録済み（明日から算出）",
        "tl_h_trend_days": "日増 {g} · 満了予測 {d}",
        "tl_h_procs": "重要プロセス", "tl_h_ports": "ポート死活", "tl_h_wd": "watchdog 1h 異常",
        "tl_copy_ssh": "ssh コマンド", "tl_copy_lan": "LAN IP", "tl_copy_ts": "Tailscale IP",
        "tl_fs_title": "ファイル", "tl_fs_filter": "絞り込み…", "tl_fs_hidden": "隠しファイル",
        "tl_fs_du": "サイズ計算", "tl_fs_du_run": "計算中…(5s)", "tl_fs_du_none": "ディレクトリ以外",
        "tl_fs_dl": "ダウンロード", "tl_fs_empty": "空 or 全て除外",
        "tl_clean_title": "クリーンアップ", "tl_clean_scan": "スキャン", "tl_clean_scanning": "スキャン中…",
        "tl_clean_exec": "クリーンアップ実行", "tl_clean_confirm": "選択項目を削除します。取り消せません",
        "tl_clean_docker": "docker ディスク使用", "tl_clean_docker_prune": "docker prune",
        "tl_clean_docker_confirm": "docker system prune を実行？未使用イメージ・停止コンテナ・未使用ネットワークを削除",
        "tl_clean_total": "解放可能合計", "tl_clean_freed": "実解放(df)",
        "tl_net_title": "ネットワーク計測", "tl_net_run": "計測", "tl_net_run_ing": "計測中…",
        "tl_net_ext": "外部 HEAD", "tl_net_ts": "Tailscale 対向",
        "tl_usvc_title": "ユーザーサービス(再起動)", "tl_usvc_unlock": "解除",
        "tl_usvc_hint": "I-KNOW と入力して再起動ボタンを解除", "tl_usvc_wrong": "確認文字列が違います",
        "tl_usvc_restart": "再起動", "tl_usvc_loading": "読み込み中…", "tl_usvc_none": "ユーザーサービスなし",
        "tl_cron_title": "予定タスク一覧", "tl_g1_title": "ツール直行",
        "theme_title": "外観", "th_auto": "システム", "th_dark": "ダーク", "th_light": "ライト",
        "refresh_title": "タップで更新 · 長押しで自動更新のロック切替",
        "locked_toast": "ロック中: 自動更新停止", "unlocked_toast": "ロック解除: 自動更新再開",
    },
}


def t(lang, key, **kw):
    """取语言文本;带 {} 占位符时做格式化,缺键时原样返回 key。"""
    s = L10N.get(lang, L10N[DEFAULT_LANG]).get(key, key)
    if kw:
        try:
            return s.format(**kw)
        except (KeyError, IndexError):
            return s
    return s


_T_PAT = re.compile(r"\{\{T:(\w+)\}\}")


def _apply_t(template, lang):
    """替换模板里的 {{T:key}} 占位符。"""
    return _T_PAT.sub(lambda m: t(lang, m.group(1)), template)


def detect_lang(accept, query=""):
    """Accept-Language 检测 + ?lang= 强制覆盖;zh/en/ja,缺省回退 zh。"""
    for item in (query or "").split("&"):
        if item.startswith("lang="):
            v = item.split("=", 1)[1].lower()
            if v in LANG_KEYS:
                return v
            v = v.split("-")[0]
            if v in LANG_KEYS:
                return v
            break
    if accept:
        for part in accept.split(","):
            tag = part.split(";")[0].strip().lower()
            if tag in LANG_KEYS:
                return tag
            base = tag.split("-")[0]
            if base in LANG_KEYS:
                return base
    return DEFAULT_LANG


# ---------------- 页面 ----------------

BADGE = {
    "docker": "badge-docker",
    "systemd": "badge-systemd",
    "direct": "badge-direct",
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

WEEKDAYS = {
    "zh": {"0": "日", "1": "一", "2": "二", "3": "三", "4": "四", "5": "五", "6": "六", "7": "日"},
    "en": {"0": "Sun", "1": "Mon", "2": "Tue", "3": "Wed", "4": "Thu", "5": "Fri", "6": "Sat", "7": "Sun"},
    "ja": {"0": "日", "1": "月", "2": "火", "3": "水", "4": "木", "5": "金", "6": "土", "7": "日"},
}


def human_cron(fields, lang=DEFAULT_LANG):
    """5 字段 cron 或 systemd OnCalendar 表达式 -> 人类可读文本(按语言)。"""
    if isinstance(fields, str):
        s = fields.strip()
        # systemd OnCalendar 格式
        if s == "hourly":
            return t(lang, "cron_hourly")
        if s == "daily":
            return t(lang, "cron_daily")
        if s == "weekly":
            return t(lang, "cron_weekly")
        if s == "monthly":
            return t(lang, "cron_monthly")
        if s.startswith("*-*-* "):
            hm = s.split(None, 1)[1]
            if hm == "6,18:00":
                return t(lang, "cron_daily_twice", h1="6", m1="00", h2="18", m2="00")
            if ":" in hm:
                h, m = hm.split(":", 1)
                return t(lang, "cron_daily_at", h=h, m=m)
            return t(lang, "cron_daily_raw", hm=hm)
        if s.startswith("*:"):
            # systemd `*:0/5` = 每 5 分钟
            step = s[2:].split("/", 1)
            return t(lang, "cron_every_min", n=step[1] if len(step) == 2 else step[0])
        if s.startswith("*-*-* "):
            return t(lang, "cron_daily_raw", hm=s.replace("*-*-* ", ""))
        return s
    m, h, dom, mon, dow = fields
    wd = WEEKDAYS.get(lang, WEEKDAYS[DEFAULT_LANG])
    star = dom == "*" and mon == "*" and dow == "*"
    if m.startswith("*/") and h == "*" and star:
        return t(lang, "cron_every_min", n=m[2:])
    if m == "0" and h.startswith("*/") and star:
        return t(lang, "cron_every_hour", n=h[2:])
    if m == "0" and h not in "*" and star:
        return t(lang, "cron_daily_at", h=h, m="00")
    if m == "0" and h not in "*" and dom == "*" and mon == "*" and dow not in "*":
        days = "/".join(wd.get(d, d) for d in dow.split(","))
        return t(lang, "cron_weekly_at", days=days, h=h)
    if m not in "*" and h not in "*" and dom not in "*" and mon not in "*" and dow == "*":
        return t(lang, "cron_month_day", mon=mon, dom=dom, h=h, m=f"{int(m):02d}")
    return " ".join(fields)


def classify_task(name, command):
    """按名称/命令启发式分类型: watchdog / reminder / scheduled。"""
    text = f"{name} {command}"
    if WATCHDOG_RE.search(text):
        return "watchdog"
    if REMINDER_RE.search(text):
        return "reminder"
    return "scheduled"


def parse_cron_lines(lines, scope, lang=DEFAULT_LANG):
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
            "schedule": human_cron(fields, lang), "expr": " ".join(fields),
            "next": None, "last": None, "state": "enabled",
            "type": classify_task(name, cmd), "command": cmd,
        })
    return tasks


def _read_cron_file(path, scope, lang, out):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            out.extend(parse_cron_lines(f, scope, lang))
    except OSError:
        pass


def scan_cron(lang=DEFAULT_LANG):
    tasks = []
    for scope, path in CRON_FILES:
        _read_cron_file(path, scope, lang, tasks)
    try:
        for fn in sorted(os.listdir(CRON_D_DIR)):
            if fn.startswith("."):
                continue
            _read_cron_file(os.path.join(CRON_D_DIR, fn), "system", lang, tasks)
    except OSError:
        pass
    return tasks


def _run_timers(scope, lang=DEFAULT_LANG):
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
            cal = t(lang, "cron_every_sec", n=m2.group(1).strip())
        schedule = human_cron(cal, lang) if cal else t(lang, "cron_by_unit")
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
            ["journalctl", "-u", "cron", "-o", "short-iso", "--no-pager",
             "--since", "7 days ago"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, errors="replace", start_new_session=True)
    except Exception:
        return last
    try:
        out, _ = p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_tree(p)
        out = ""
    re_line = re.compile(r"^(\S+T\S+[+-]\d{2}:?\d{2})\s+\S+\s+CRON\[\d+\]:\s+\(\S+\)\s+CMD\s+\((.*)\)\s*$")
    for line in out.splitlines():
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
    return last


def scan_tasks(lang=DEFAULT_LANG):
    """汇总所有定时/看门狗任务(8 秒缓存,按语言分开)。"""
    now = time.time()
    data = _tasks_cache["data"]
    if isinstance(data, dict) and data.get(lang) is not None and now - _tasks_cache["t"] < 8:
        return data[lang]
    tasks = scan_cron(lang) + _run_timers("system", lang) + _run_timers("user", lang)
    last_runs = _cron_last_runs()
    for t in tasks:
        if t["kind"] == "cron":
            t["last"] = last_runs.get(_cmd_key(t["command"]))
    tasks.sort(key=lambda t: (t["type"] != "watchdog", t["name"]))
    d = _tasks_cache["data"]
    if not isinstance(d, dict):
        d = {}
    d[lang] = tasks
    _tasks_cache.update({"t": now, "data": d})
    return tasks


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


def merge_events(wd_events, completed, limit=24):
    """watchdog 事件 + 完成台账合并为一条时间线(时间倒序)。
    每条带 src 标记(watchdog / done),前端日志页按来源筛选。"""
    merged = [{"ts": e["ts"], "time": e["time"], "gid": e["gid"], "name": e["name"],
               "kind": e["kind"], "text": e["text"], "src": "watchdog"}
              for e in wd_events]
    for c in completed:
        merged.append({"ts": c["ts"], "time": c["time"], "gid": c["gid"],
                       "name": c["label"] or c["gid"][:8], "kind": "complete",
                       "text": c["transcript"], "src": "done"})
    merged.sort(key=lambda x: -x["ts"])
    return merged[:limit]


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
                out.append(hit[:72])
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


# 快捷工具入口: 端口存活才显示(chips)
TOOL_LINKS = [("dbeditor", 8810), ("dbviewer", 8800),
              ("wilviewer", 8765), ("mapviewer", 8899)]


# ---------------- 负载水位 + top 进程 ----------------
_proc_cpu_prev = {"t": 0.0, "cpu": {}}


def top_procs(limit=5):
    """CPU / 内存 top 进程(同名聚合)。CPU% 取与上次采样的增量;
    首次采样退化为进程生命周期均值。纯 /proc 解析,无 psutil。"""
    now = time.time()
    hz = os.sysconf("SC_CLK_TCK") or 100
    page = os.sysconf("SC_PAGE_SIZE") or 4096
    try:
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
    except (OSError, ValueError):
        uptime = 0.0
    cur, meta = {}, {}
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return {"cpu": [], "mem": []}
    for pid in pids:
        try:
            with open(f"/proc/{pid}/stat") as f:
                data = f.read()
            lp = data.rfind(")")
            comm = data[data.find("(") + 1:lp]
            rest = data[lp + 2:].split()
            cpu_j = int(rest[11]) + int(rest[12])
            starttime = int(rest[19])
            rss = int(rest[21]) * page
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = [a for a in f.read().decode("utf-8", "replace").split("\0") if a]
        except (OSError, ValueError, IndexError):
            continue
        if not argv:  # 内核线程
            continue
        cur[pid] = cpu_j
        meta[pid] = (nice_name(" ".join(argv)) or comm, rss, starttime)
    prev, dt = _proc_cpu_prev["cpu"], max(0.0, now - _proc_cpu_prev["t"])
    agg = {}
    for pid, (name, rss, starttime) in meta.items():
        j = cur[pid]
        if dt >= 0.5 and pid in prev:
            pct = (j - prev[pid]) / hz / dt * 100
        elif uptime > 0:
            age = uptime - starttime / hz
            pct = j / hz / age * 100 if age > 1 else 0.0
        else:
            pct = 0.0
        a = agg.setdefault(name, [0.0, 0])
        a[0] += pct
        a[1] += rss
    _proc_cpu_prev.update({"t": now, "cpu": cur})
    cpu_top = sorted(((v[0], k) for k, v in agg.items()), reverse=True)[:limit]
    mem_top = sorted(((v[1], k) for k, v in agg.items()), reverse=True)[:limit]
    return {"cpu": [[round(p, 0), k] for p, k in cpu_top],
            "mem": [[round(b / 1024 / 1024, 0), k] for b, k in mem_top]}


def load_zone(load15):
    """load15 -> (水位档, 还可开几个 goal): <6 绿 / 6-10 黄 / >10 红。"""
    if load15 is None:
        return ("none", 0)
    if load15 < 6:
        return ("ok", 2 if load15 < 3 else 1)
    if load15 <= 10:
        return ("full", 0)
    return ("over", 0)


def render_goal_cards(cards, lang=DEFAULT_LANG):
    """Goal 进度卡片 + 已完成折叠区(服务端渲染,打开页面/手动刷新时更新)。"""
    # light -> (icon 名, 语义色 class, 状态文案 i18n key); SVG 图标颜色走 CSS 变量
    light = {"active": ("dot", "t-green", "g_active"), "paused": ("pause", "t-warn", "g_paused"),
             "retry": ("retry", "t-orange", "g_retry"), "done": ("ok", "t-green", "g_done"),
             "lost": ("warn", "t-red", "g_lost")}
    out = []
    for c in cards:
        ico_name, ico_cls, key = light.get(c["light"], ("warn", "t-red", "g_lost"))
        glight = f'<span class="glight {ico_cls}">{icon(ico_name, 13)}</span>'
        # 手机端: 状态灯+名称+最近活动 常显;上下文/API重试/进度 收进 .gextra(点标题展开)
        extra, idle_row = [], ""
        if c["ctx_raw"]:
            cls = {"warn": "gtx warn", "stop": "gtx stop"}.get(c["ctx_level"], "gtx")
            note = {"warn": t(lang, "g_ctx_high"), "stop": t(lang, "g_ctx_stop")}.get(c["ctx_level"], "")
            extra.append(f'<div class="grow"><span>{t(lang, "g_ctx")}</span>'
                         f'<span class="{cls}">{c["ctx_raw"]}{" · " + note if note else ""}</span></div>')
        if c["retry"]:
            extra.append(f'<div class="grow"><span>API</span>'
                         f'<span class="gretry">{t(lang, "g_retrying", n=c["retry"])}</span></div>')
        if c["idle_sec"] is not None:
            ago = fmt_ago(c["idle_sec"], lang)
            stall = f' · {t(lang, "g_stalled")}' if c["stalled"] else ""
            idle_row = (f'<div class="grow"><span>{t(lang, "g_last")}</span>'
                        f'<span class="{"gstalled" if c["stalled"] else "gidle"}">{ago}{stall}</span></div>')
        if c["progress"]:
            prog = "<br>".join(escape(x) for x in c["progress"])
            extra.append(f'<div class="gprog">{prog}</div>')
        more = (f'<span class="gmore" title="{t(lang, "g_detail")}">{icon("chev", 12)}</span>') if extra else ""
        head = (f'<div class="ghead">{glight}'
                f'<span class="gname">{escape(c["name"])}</span>'
                f'<span class="gstate">{t(lang, key)}</span>{more}</div>')
        if c["label"] and c["label"] != c["name"]:
            head += f'<div class="gsub">{escape(c["label"][:60])}</div>'
        elif c["objective"]:
            head += f'<div class="gsub">{escape(c["objective"])}</div>'
        inner = head + idle_row
        if extra:
            inner += f'<div class="gextra">{"".join(extra)}</div>'
        foot = ""
        if c["resume_cmd"]:
            foot = (f'<div class="gfoot"><span class="gcopy" role="button" tabindex="0" '
                    f'data-cmd="{escape(c["resume_cmd"], quote=True)}">{icon("copy", 13)} {t(lang, "g_copy")}</span></div>')
        inner += foot
        # 手机端左滑露「复制 resume」: .swipe-bg 静止在卡片下,.swipe-fg 跟手平移
        back = (f'<div class="swipe-bg"><span class="swipe-act" role="button" tabindex="0" '
                f'data-copy="{escape(c["resume_cmd"], quote=True)}">{icon("copy", 13)} {t(lang, "g_copy")}</span></div>'
                if c["resume_cmd"] else "")
        cls = "gcard swipe-item" if back else "gcard"
        out.append(f'<div class="{cls}" data-light="{c["light"]}">{back}<div class="swipe-fg">{inner}</div></div>')
    body = "".join(out) if out else f'<div class="gempty">{t(lang, "g_none")}</div>'
    completed = parse_completed_goals()
    fold = ""
    if completed:
        items = "".join(
            f'<div class="gdone-row"><span class="evt-ts">{escape(c["time"][5:16])}</span>'
            f'<span class="gdone-name">{escape(c["label"] or c["gid"][:8])}</span>'
            f'<span class="gsub">{escape(c["transcript"][:44])}</span></div>'
            for c in completed)
        fold = (f'<details class="gdone"><summary><span class="t-green">{icon("ok", 13)}</span> '
                f'{t(lang, "g_done_fold", n=len(completed))}</summary>'
                f'{items}</details>')
    return (f'<div class="gpanel" id="goals"><h2>{t(lang, "g_panel")} '
            f'<span class="ghint">{t(lang, "g_hint")}</span></h2>'
            f'<div class="gcards">{body}</div>{fold}</div>')


def render_loadline(s, lang=DEFAULT_LANG):
    """负载水位线: 还可开几个 goal + CPU/内存 top5 进程。"""
    gl = s.get("goalload") or {}
    zone, n = gl.get("zone", "none"), gl.get("n", 0)
    msg = {"ok": t(lang, "ld_ok", n=n), "full": t(lang, "ld_full"),
           "over": t(lang, "ld_over")}.get(zone, "—")
    ico_name, color = {"ok": ("dot", "var(--c-green)"), "full": ("pause", "var(--c-warn)"),
                       "over": ("err", "var(--c-red)")}.get(zone, ("dot", "var(--c-gray)"))
    load15 = gl.get("load15")
    sub = t(lang, "ld_load", l=(f"{load15:.1f}" if load15 is not None else "—"),
            c=gl.get("cores", "?"))

    def top_rows(items, fmt):
        if not items:
            return f'<div class="ld-row" style="color:var(--text-dead)">—</div>'
        return "".join(f'<div class="ld-row"><span class="ld-val">{fmt(v)}</span>'
                       f'<span class="ld-name">{escape(k)}</span></div>' for v, k in items)

    cpu_rows = top_rows(gl.get("cpu_top") or [], lambda v: f"{v:.0f}%")
    mem_rows = top_rows(gl.get("mem_top") or [], lambda v: f"{v / 1024:.1f}G" if v >= 1024 else f"{v:.0f}M")
    return (f'<div class="gpanel loadline" id="loadline">'
            f'<div class="ld-head"><span class="ld-ico" style="color:{color}">{icon(ico_name, 14)}</span>'
            f'<b>{t(lang, "ld_title")}</b>：{msg}'
            f'<span class="ld-sub">（{sub}）</span></div>'
            f'<div class="ld-tops"><div class="ld-top"><div class="ld-t">{t(lang, "ld_cpu")}</div>{cpu_rows}</div>'
            f'<div class="ld-top"><div class="ld-t">{t(lang, "ld_mem")}</div>{mem_rows}</div></div></div>')


def render_toolchips(entries, host_header, lang=DEFAULT_LANG):
    """快捷工具入口 chips: 端口存活才显示,点击直达。"""
    ports = {e["port"] for e in entries}
    hostname = (host_header or "").split(":")[0] or socket.gethostname()
    chips = "".join(
        f'<a class="chip tchip" href="http://{escape(hostname)}:{port}/" target="_blank" rel="noopener">'
        f'{name} :{port} {icon("ext", 11)}</a>'
        for name, port in TOOL_LINKS if port in ports)
    if not chips:
        return ""
    return f'<div class="filters toolchips" id="toolchips">{chips}</div>'


def render_events(events, lang=DEFAULT_LANG):
    """最近事件: watchdog 动作 + 完成台账,合并时间倒序。"""
    rows = []
    today = time.strftime("%Y-%m-%d")
    for e in events:
        try:
            ts_str = e["time"]
            show = ts_str[11:16] if ts_str[:10] == today else ts_str[5:16]
        except Exception:
            show = "—"
        ico_name, ico_cls, key = KIND_META.get(e["kind"], ("", "", "ev_other"))
        ico_html = (f'<span class="evt-ico {ico_cls}">{icon(ico_name, 13)}</span>'
                    if ico_name else "")
        label = t(lang, key)
        rows.append(f'<div class="evt-row"><span class="evt-ts">{escape(show)}</span>'
                    f'<span class="evt-name">[{escape(e["name"])}]</span>'
                    f'{ico_html}'
                    f'<span class="evt-txt">{escape(label)} {escape(e["text"][:110])}</span></div>')
    body = "".join(rows) if rows else f'<div class="gempty">{t(lang, "ev_none")}</div>'
    return (f'<div class="gpanel" id="events"><h2>{t(lang, "ev_title")} '
            f'<span class="ghint">{t(lang, "ev_hint")}</span></h2>{body}</div>')

def render_html(host_header, entries, updated_ts, lang=DEFAULT_LANG, sysdata=None, ts_mode=False):
    if sysdata is None:
        sysdata = sys_info()
    rows = []
    for e in entries:
        ip, port = e["ip"], e["port"]
        is_loopback = ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")
        badge_cls = BADGE.get(e["type"], "badge-direct")
        badge_text = t(lang, "badge_docker") if e["type"] == "docker" else t(lang, "badge_direct")
        detail = ""
        if e.get("is_self"):
            badge_text, badge_cls = t(lang, "badge_self"), "badge-self"
        elif e.get("paused"):
            badge_text, badge_cls = t(lang, "badge_paused"), "badge-paused"
        elif e.get("docker_proxy"):
            badge_text = t(lang, "badge_proxy")
        elif e["type"] == "docker" and e.get("container_id"):
            detail = f'<span class="detail" title="{t(lang, "detail_cid")}">{escape(e["container_id"])}</span>'
        elif e["type"] == "systemd" and e.get("unit"):
            detail = f'<span class="detail" title="{t(lang, "detail_unit")}">{escape(e["unit"])}</span>'
        cmd = escape(e["cmdline"] or "—")
        cwd = escape(e["cwd"] or "—")
        pids = ", ".join(str(p) for p in e.get("pids") or ["?"])
        hostname = host_header.split(":")[0]  # 去掉端口,用访问 dashboard 的主机名
        if is_loopback:
            link = f"http://127.0.0.1:{port}/"
            loop = f'<span class="local">{t(lang, "loopback")}</span>'
        else:
            link = f"http://{hostname}:{port}/"
            loop = ""
        # 可管理的手动进程服务(wilviewer/mapviewer): 行尾渲染 暂停/继续 按钮。
        # 只渲染按钮外壳,当前状态由前端按端口查询 /api/manage 后填充。
        man = next((u for u in MANAGE_UNITS
                    if u["kind"] == "proc" and u["port"] == port), None)
        ctl = ""
        if man:
            ctl = (f'<td class="ctl" data-label="Control">'
                   f'<span class="ctl-btn" data-ctl="{man["id"]}" data-port="{port}" role="button" tabindex="0" aria-disabled="true">…</span></td>')
        rows.append(
            f'<tr>'
            f'<td class="name"><span class="svc">{escape(e["name"])}</span>'
            f'<span class="badge {badge_cls}">{badge_text}</span>{detail}</td>'
            f'<td class="port" data-label="{t(lang, "th_port")}"><a href="{link}" target="_blank" rel="noopener">{port}</a></td>'
            f'<td class="addr" data-label="{t(lang, "th_addr")}">{escape(ip)} {loop}</td>'
            f'<td class="pid" data-label="PID">{pids}</td>'
            f'<td class="cmd" data-label="{t(lang, "th_cmd")}">{cmd}</td>'
            f'<td class="cwd" data-label="{t(lang, "th_cwd")}">{cwd}</td>'
            f'{ctl}'
            f'</tr>')
    table = "\n".join(rows)
    hostname = socket.gethostname()
    body = (PAGE_TEMPLATE
            .replace("{{LANG}}", lang)
            .replace("{{TS_MODE}}", "true" if ts_mode else "false")
            .replace("{{T_JSON}}", json.dumps(L10N.get(lang, L10N[DEFAULT_LANG]), ensure_ascii=False))
            .replace("{{ICONS_JSON}}", json.dumps(ICONS, ensure_ascii=False))
            .replace("{{TL_CONF}}", json.dumps(tools_conf(), ensure_ascii=False))
            .replace("{{HOST}}", escape(host_header))
            .replace("{{HOSTNAME}}", escape(hostname))
            .replace("{{AUTO}}", str(AUTO_REFRESH_SEC))
            .replace("{{SYSBAR}}", render_sysbar(sysdata, lang))
            .replace("{{LOADLINE}}", render_loadline(sysdata, lang))
            .replace("{{TOOLCHIPS}}", render_toolchips(entries, host_header, lang))
            .replace("{{GOALS_PANEL}}", render_goal_cards(scan_goals(), lang))
            .replace("{{EVENTS_PANEL}}", render_events(merge_events(
                parse_watchdog_events(), parse_completed_goals()), lang))
            .replace("{{UPDATED}}", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(updated_ts)))
            .replace("{{COUNT}}", str(len(entries)))
            .replace("<!--TABLE-->", table))
    # 模板里的 {{ICO:name:size}} 占位符 -> 内联 SVG(与 JS icon() 同一份数据)
    body = _ICO_PAT.sub(lambda m: icon(m.group(1), int(m.group(2) or 16)), body)
    return _apply_t(body, lang)


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="{{LANG}}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#0a0a0a">
<script>/* 主题预置: 在 CSS 生效前落 data-theme, 防浅色偏好下闪深色(FOUC) */
try{var _tm=localStorage.getItem("svc-theme");if(_tm==="dark"||_tm==="light")document.documentElement.setAttribute("data-theme",_tm)}catch(e){}</script>
<title>{{T:title}} · {{HOSTNAME}}</title>
<link rel="icon" href="data:,">
<style>
  /* ============ 主题变量: 深色为默认, 浅色经 prefers-color-scheme / [data-theme] 覆盖 ============
     语义色规约: 红=严重 黄=关注 绿=正常 灰=历史 蓝=交互。
     文本档均按 WCAG AA(≥4.5:1)对各自主题底色校准; 终端画面(termlog)双主题保持深色。 */
  :root {
    color-scheme: dark;
    --bg: #0a0a0a; --bg-elev: #141414; --bg-panel: #131313; --bg-deep: #101010;
    --bg-input: #141414; --bg-hover: #1f1f1f; --bg-active: #262626;
    --border: #222; --border-soft: #1f1f1f; --border-faint: #1a1a1a;
    --btn-bg: #262626; --btn-hover: #333; --btn-press: #3a3a3a; --btn-border: #333;
    --btn-soft-bg: #1d1d1d; --btn-soft-border: #2e2e2e; --btn-soft-hover-bd: #555;
    --chip-bg: #161616; --chip-border: #2a2a2a;
    --chip-on-bg: #f2f2f2; --chip-on-tx: #111;
    --text-title: #f2f2f2; --text-hi: #eee; --text: #d6d6d6; --text-mid: #c9c9c9;
    --text-soft: #b0b0b0; --text-dim: #909090; --text-faint: #8a8a8a;
    --text-ghost: #777; --text-dead: #666;
    --header-bg: rgba(10,10,10,.9); --tabbar-bg: rgba(12,12,12,.82);
    --scrim: rgba(0,0,0,.92); --skel: #1a1a1a; --focus: #4a90d9;
    --c-red: #e06c6c; --c-red-bg: #2a1a1a;
    --c-warn: #f0b662; --c-warn-bg: #2a2118; --c-warn-border: #5a4422;
    --c-green: #6ec89a; --c-green-bg: #14261c; --c-green-btn: #2e7d4f;
    --c-orange: #e0884c; --c-gray: #9a9a9a; --c-blue: #8ab4f8;
    --link-blue: #6ea8dc; --dot-off: #555;
    --accent-blue-bg: #1d2733; --accent-blue-bd: #2c3a4d; --accent-blue-tx: #9db8d9;
    --accent-blue-hover: #243445; --detail-bg: #101418;
    --tbadge-wd-bg: #2a2010; --tbadge-wd-tx: #e0a84c; --tbadge-wd-bd: #4a3a18;
    --tbadge-rd-bg: #1e2832; --tbadge-rd-tx: #6ea8dc; --tbadge-rd-bd: #26405a;
    --tbadge-sc-bg: #1c1c1c; --tbadge-sc-tx: #9a9a9a; --tbadge-sc-bd: #2e2e2e;
    --term-bg: #0a0e12; --term-bd: #1c242e; --term-tx: #9fd4a0;
    --ts-dim: #5c7a9a; --evt-ts: #63849f;
    --ch-cpu: #6ea8dc; --ch-load: #6ec89a; --ch-mem: #e0a84c; --ch-swap: #b48ead;
    --ch-grid: #1c1c1c;
  }
  /* 浅色: 同一组变量(跟随系统且未被 [data-theme=dark] 覆盖时生效) */
  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {
      color-scheme: light;
      --bg: #f5f5f5; --bg-elev: #fff; --bg-panel: #fafafa; --bg-deep: #ececec;
      --bg-input: #fff; --bg-hover: #e9e9e9; --bg-active: #e2e2e2;
      --border: #e0e0e0; --border-soft: #e4e4e4; --border-faint: #eaeaea;
      --btn-bg: #e4e4e4; --btn-hover: #d8d8d8; --btn-press: #d0d0d0; --btn-border: #c9c9c9;
      --btn-soft-bg: #fff; --btn-soft-border: #c9c9c9; --btn-soft-hover-bd: #999;
      --chip-bg: #fff; --chip-border: #cfcfcf;
      --chip-on-bg: #1f1f1f; --chip-on-tx: #fff;
      --text-title: #111; --text-hi: #1a1a1a; --text: #242424; --text-mid: #333;
      --text-soft: #464646; --text-dim: #575757; --text-faint: #666;
      --text-ghost: #757575; --text-dead: #8f8f8f;
      --header-bg: rgba(245,245,245,.92); --tabbar-bg: rgba(250,250,250,.86);
      --scrim: rgba(0,0,0,.55); --skel: #e2e2e2; --focus: #2b6cb0;
      --c-red: #b33939; --c-red-bg: #fbeaea;
      --c-warn: #8a5800; --c-warn-bg: #fdf3dd; --c-warn-border: #e3c88f;
      --c-green: #1e7d4f; --c-green-bg: #e6f4ec; --c-green-btn: #1e7d4f;
      --c-orange: #a85413; --c-gray: #5f6368; --c-blue: #2b6cb0;
      --link-blue: #2b6cb0; --dot-off: #b8b8b8;
      --accent-blue-bg: #e8f0fb; --accent-blue-bd: #c4d8f0; --accent-blue-tx: #3a6ea5;
      --accent-blue-hover: #d8e7fa; --detail-bg: #f0f5fa;
      --tbadge-wd-bg: #fdf3dd; --tbadge-wd-tx: #8a5800; --tbadge-wd-bd: #e6cf9e;
      --tbadge-rd-bg: #e8f0fb; --tbadge-rd-tx: #3a6ea5; --tbadge-rd-bd: #c4d8f0;
      --tbadge-sc-bg: #ececec; --tbadge-sc-tx: #5c5c5c; --tbadge-sc-bd: #d5d5d5;
      --ts-dim: #5a7a99; --evt-ts: #51708c;
      --ch-cpu: #3572b0; --ch-load: #1e7d4f; --ch-mem: #a8731a; --ch-swap: #8d6a9e;
      --ch-grid: #e4e4e4;
    }
  }
  /* 浅色手动覆盖(设置里选「浅色」) */
  :root[data-theme="light"] {
    color-scheme: light;
    --bg: #f5f5f5; --bg-elev: #fff; --bg-panel: #fafafa; --bg-deep: #ececec;
    --bg-input: #fff; --bg-hover: #e9e9e9; --bg-active: #e2e2e2;
    --border: #e0e0e0; --border-soft: #e4e4e4; --border-faint: #eaeaea;
    --btn-bg: #e4e4e4; --btn-hover: #d8d8d8; --btn-press: #d0d0d0; --btn-border: #c9c9c9;
    --btn-soft-bg: #fff; --btn-soft-border: #c9c9c9; --btn-soft-hover-bd: #999;
    --chip-bg: #fff; --chip-border: #cfcfcf;
    --chip-on-bg: #1f1f1f; --chip-on-tx: #fff;
    --text-title: #111; --text-hi: #1a1a1a; --text: #242424; --text-mid: #333;
    --text-soft: #464646; --text-dim: #575757; --text-faint: #666;
    --text-ghost: #757575; --text-dead: #8f8f8f;
    --header-bg: rgba(245,245,245,.92); --tabbar-bg: rgba(250,250,250,.86);
    --scrim: rgba(0,0,0,.55); --skel: #e2e2e2; --focus: #2b6cb0;
    --c-red: #b33939; --c-red-bg: #fbeaea;
    --c-warn: #8a5800; --c-warn-bg: #fdf3dd; --c-warn-border: #e3c88f;
    --c-green: #1e7d4f; --c-green-bg: #e6f4ec; --c-green-btn: #1e7d4f;
    --c-orange: #a85413; --c-gray: #5f6368; --c-blue: #2b6cb0;
    --link-blue: #2b6cb0; --dot-off: #b8b8b8;
    --accent-blue-bg: #e8f0fb; --accent-blue-bd: #c4d8f0; --accent-blue-tx: #3a6ea5;
    --accent-blue-hover: #d8e7fa; --detail-bg: #f0f5fa;
    --tbadge-wd-bg: #fdf3dd; --tbadge-wd-tx: #8a5800; --tbadge-wd-bd: #e6cf9e;
    --tbadge-rd-bg: #e8f0fb; --tbadge-rd-tx: #3a6ea5; --tbadge-rd-bd: #c4d8f0;
    --tbadge-sc-bg: #ececec; --tbadge-sc-tx: #5c5c5c; --tbadge-sc-bd: #d5d5d5;
    --ts-dim: #5a7a99; --evt-ts: #51708c;
    --ch-cpu: #3572b0; --ch-load: #1e7d4f; --ch-mem: #a8731a; --ch-swap: #8d6a9e;
    --ch-grid: #e4e4e4;
  }
  /* 深色手动覆盖(系统浅色时选「深色」) */
  :root[data-theme="dark"] {
    color-scheme: dark;
    --bg: #0a0a0a; --bg-elev: #141414; --bg-panel: #131313; --bg-deep: #101010;
    --bg-input: #141414; --bg-hover: #1f1f1f; --bg-active: #262626;
    --border: #222; --border-soft: #1f1f1f; --border-faint: #1a1a1a;
    --btn-bg: #262626; --btn-hover: #333; --btn-press: #3a3a3a; --btn-border: #333;
    --btn-soft-bg: #1d1d1d; --btn-soft-border: #2e2e2e; --btn-soft-hover-bd: #555;
    --chip-bg: #161616; --chip-border: #2a2a2a;
    --chip-on-bg: #f2f2f2; --chip-on-tx: #111;
    --text-title: #f2f2f2; --text-hi: #eee; --text: #d6d6d6; --text-mid: #c9c9c9;
    --text-soft: #b0b0b0; --text-dim: #909090; --text-faint: #8a8a8a;
    --text-ghost: #777; --text-dead: #666;
    --header-bg: rgba(10,10,10,.9); --tabbar-bg: rgba(12,12,12,.82);
    --scrim: rgba(0,0,0,.92); --skel: #1a1a1a; --focus: #4a90d9;
    --c-red: #e06c6c; --c-red-bg: #2a1a1a;
    --c-warn: #f0b662; --c-warn-bg: #2a2118; --c-warn-border: #5a4422;
    --c-green: #6ec89a; --c-green-bg: #14261c; --c-green-btn: #2e7d4f;
    --c-orange: #e0884c; --c-gray: #9a9a9a; --c-blue: #8ab4f8;
    --link-blue: #6ea8dc; --dot-off: #555;
    --accent-blue-bg: #1d2733; --accent-blue-bd: #2c3a4d; --accent-blue-tx: #9db8d9;
    --accent-blue-hover: #243445; --detail-bg: #101418;
    --tbadge-wd-bg: #2a2010; --tbadge-wd-tx: #e0a84c; --tbadge-wd-bd: #4a3a18;
    --tbadge-rd-bg: #1e2832; --tbadge-rd-tx: #6ea8dc; --tbadge-rd-bd: #26405a;
    --tbadge-sc-bg: #1c1c1c; --tbadge-sc-tx: #9a9a9a; --tbadge-sc-bd: #2e2e2e;
    --term-bg: #0a0e12; --term-bd: #1c242e; --term-tx: #9fd4a0;
    --ts-dim: #5c7a9a; --evt-ts: #63849f;
    --ch-cpu: #6ea8dc; --ch-load: #6ec89a; --ch-mem: #e0a84c; --ch-swap: #b48ead;
    --ch-grid: #1c1c1c;
  }

  * { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background: var(--bg); color: var(--text); }
  header { position: sticky; top: 0; z-index: 10; background: var(--header-bg); backdrop-filter: blur(6px);
           border-bottom: 1px solid var(--border-soft); padding: 12px 24px;
           display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  header h1 { font-size: 17px; margin: 0; font-weight: 600; color: var(--text-title);
              display: inline-flex; align-items: center; gap: 8px; }
  header h1 .h-server { width: 7px; height: 7px; border-radius: 50%; background: var(--c-green); flex: none; }
  header .meta { color: var(--text-soft); font-size: 12.5px; }
  header .spacer { flex: 1; }
  /* ---------------- 自绘控件体系 ----------------
     不使用任何系统原生控件: 所有按钮/开关均为自绘元素。
     span[role=button] 语义: 可点击;键盘 Enter/Space 由全局委托触发 click。 */
  .btn, .chip, .tcol, .ctl-btn, .mbtn, .aglog-refresh {
    display: inline-flex; align-items: center; justify-content: center; gap: 6px;
    user-select: none; -webkit-user-select: none; touch-action: manipulation;
    cursor: pointer; transition: background .12s, border-color .12s, color .12s, transform .05s; }
  .btn { background: var(--btn-bg); color: var(--text-hi); border: 1px solid var(--btn-border);
         border-radius: 8px; padding: 7px 14px; font-size: 13px; }
  .btn:hover { background: var(--btn-hover); }
  .btn:active { background: var(--btn-press); transform: translateY(1px); }
  .btn.spinning { opacity: .7; }
  /* topbar 刷新按钮: 点击=立即刷新, 长按=锁定/解锁自动刷新(锁定=琥珀描边+锁形角标) */
  .icon-btn { width: 38px; height: 38px; padding: 0; position: relative; border-radius: 10px; }
  #refresh.locked { border-color: var(--c-warn); color: var(--c-warn); }
  #refresh .ic-badge { position: absolute; top: -5px; right: -5px; width: 15px; height: 15px;
                       border-radius: 50%; background: var(--c-warn); color: var(--bg);
                       display: none; align-items: center; justify-content: center; }
  #refresh.locked .ic-badge { display: inline-flex; }
  /* 移动端下拉刷新指示器；默认完全收起，桌面端不注册事件。 */
  #ptr-indicator { position: fixed; top: 0; left: 50%; z-index: 30;
    width: 132px; height: 48px; margin-left: -66px; margin-top: -48px;
    display: flex; align-items: center; justify-content: center; gap: 8px;
    background: var(--bg-elev); border: 1px solid var(--border-strong, var(--chip-border)); border-top: 0;
    border-radius: 0 0 12px 12px; color: var(--text-soft); font-size: 12px;
    transform: translateY(0); transition: transform .22s ease, color .15s ease; }
  #ptr-indicator .ptr-arrow { display: inline-flex; line-height: 1;
    transform: rotate(0deg); transition: transform .12s linear; }
  #ptr-indicator .ptr-arrow svg { display: block; }
  #ptr-indicator.ready { color: var(--c-blue); }
  #ptr-indicator.loading { color: var(--c-green); }
  #ptr-indicator.loading .ptr-arrow { animation: ptr-spin .8s linear infinite; }
  @keyframes ptr-spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) {
    #ptr-indicator, #ptr-indicator .ptr-arrow { transition: none; }
    #ptr-indicator.loading .ptr-arrow { animation: none; }
  }
  .btn[aria-disabled="true"], .btn.disabled { opacity: .5; cursor: default; pointer-events: none; }
  .btn:focus-visible, .chip:focus-visible, .tcol:focus-visible,
  .ctl-btn:focus-visible, .mbtn:focus-visible, .aglog-refresh:focus-visible {
    outline: 2px solid var(--focus); outline-offset: 2px; }
  /* ---------------- 内联 SVG 图标对齐体系(emoji 全量替换) ---------------- */
  .ic { display: inline-block; vertical-align: -0.15em; line-height: 1; }
  .lb-ico, .glight, .al-ico, .rc-ico, .lv-ico, .ld-ico, .evt-ico, .sc-ico {
    display: inline-flex; align-items: center; flex: none; }
  .lb-ico { color: var(--text-dim); margin-right: 5px; }
  .t-green { color: var(--c-green); } .t-warn { color: var(--c-warn); }
  .t-red { color: var(--c-red); } .t-orange { color: var(--c-orange); }
  .statuscard.ok .sc-ico { color: var(--c-green); }
  .statuscard.warn .sc-ico { color: var(--c-warn); }
  .statuscard.bad .sc-ico { color: var(--c-red); }
  main { padding: 16px 24px 40px; }

  /* ---------------- 移动 App 化基础(桌面端多数隐藏) ----------------
     字号走 rem(html=100%),尊重系统字体大小设置;
     手势元素(滑动露按钮/页签栏/图表/骨架屏)仅手机布局出现。 */
  [hidden] { display: none !important; }  /* 防 class 的 display:flex 盖过 hidden 属性 */
  html { font-size: 100%; -webkit-text-size-adjust: 100%; }
  #pages { display: contents; }          /* 桌面: 透明容器,子元素即 main 内容 */
  #tabbar, #chart-wrap, #logpage, #agents-page,
  .skel, .gmore, .statuscard, .mgrid4, #alerts, #recent,
  #log-filters, .lv { display: none; }
  .gextra { display: block; }            /* 桌面: goal 卡次要信息全展示 */
  .swipe-item { position: relative; overflow: hidden; }
  .swipe-bg { position: absolute; inset: 0; display: flex; align-items: stretch;
              justify-content: flex-end; background: var(--c-green-bg); }
  .swipe-act { display: inline-flex; align-items: center; justify-content: center;
               min-width: 88px; padding: 0 14px; background: var(--c-green-btn); color: #fff;
               font-size: 12.5px; white-space: nowrap; }
  .swipe-fg { position: relative; background: var(--bg-panel); will-change: transform;
              transition: transform .18s ease; }
  .swipe-fg.stick { transition: none; }  /* 跟手阶段禁过渡 */
  .svc-open { display: inline-flex; align-items: center; justify-content: center;
              width: 44px; height: 44px; border-radius: 50%; flex: none;
              background: var(--accent-blue-bg); border: 1px solid var(--accent-blue-bd);
              color: var(--accent-blue-tx); text-decoration: none; }
  .skel { display: none; }
  .skel-line { height: 14px; border-radius: 6px; margin: 10px 0;
               background: var(--skel); animation: skel-pulse 1.1s ease-in-out infinite; }
  @keyframes skel-pulse { 0%, 100% { opacity: .45; } 50% { opacity: 1; } }
  .logbar select { width: 100%; background: var(--bg-input); color: var(--text);
                   border: 1px solid var(--chip-border); border-radius: 8px;
                   padding: 10px 12px; font-size: 13px; min-height: 44px; }
  #chart-wrap canvas { width: 100%; height: 150px; display: block; touch-action: none; }
  #chart-empty { color: var(--text-dead); font-size: 12px; padding: 18px 0; }
  .gmore { display: none; color: var(--text-dim); font-size: 11px; }
  .sysbar { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
  .stat { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 10px;
          padding: 10px 16px; min-width: 130px; }
  .stat .label { color: var(--text-dim); font-size: 11px; margin-bottom: 3px;
                 display: inline-flex; align-items: center; }
  .stat .value { font-size: 14px; font-weight: 600; font-family: ui-monospace, monospace;
                 color: var(--text-hi); white-space: nowrap; }
  .tbadge { display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 10.5px;
            margin-right: 6px; vertical-align: 1px; }
  .tbadge.wd { background: var(--tbadge-wd-bg); color: var(--tbadge-wd-tx); border: 1px solid var(--tbadge-wd-bd); }
  .tbadge.rd { background: var(--tbadge-rd-bg); color: var(--tbadge-rd-tx); border: 1px solid var(--tbadge-rd-bd); }
  .tbadge.sc { background: var(--tbadge-sc-bg); color: var(--tbadge-sc-tx); border: 1px solid var(--tbadge-sc-bd); }
  .filters { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; align-items: center; }
  .filters .spacer { flex: 1; }
  .watchdog-panel { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 10px;
                    padding: 12px 14px; margin-bottom: 14px; }
  .watchdog-panel h2 { margin: 0 0 8px; font-size: 13px; color: var(--text-dim); font-weight: 500; }
  .watchdog-panel table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  .watchdog-panel th { text-align: left; color: var(--text-ghost); font-weight: 400; font-size: 11.5px;
                       padding: 4px 8px; border-bottom: 1px solid var(--border-soft); white-space: nowrap; }
  .watchdog-panel td { padding: 5px 8px; border-bottom: 1px solid var(--border-faint); vertical-align: top; }
  .watchdog-panel tr:last-child td { border-bottom: none; }
  .watchdog-panel .tname { font-family: ui-monospace, monospace; color: var(--text-hi); word-break: break-all; }
  .watchdog-panel .tsch { color: var(--text-soft); white-space: nowrap; }
  .watchdog-panel .tscope { color: var(--text-faint); font-size: 11px; }
  .watchdog-panel .tcmd { color: var(--text-dim); font-family: ui-monospace, monospace; font-size: 11px;
                          word-break: break-all; max-width: 420px; }
  .watchdog-panel .tlink { cursor: pointer; }
  .watchdog-panel .tlink:hover { color: var(--c-blue); text-decoration: underline; }
  .watchdog-panel .agent-detail td { background: var(--detail-bg); padding: 10px 14px; }
  .agentlog { max-height: 380px; overflow-y: auto; }
  .aglog-title { font-size: 12px; color: var(--text-faint); margin: 6px 0 4px; display: flex;
                 align-items: center; gap: 8px; }
  .aglog-refresh { background: var(--accent-blue-bg); border: 1px solid var(--accent-blue-bd);
                   color: var(--accent-blue-tx);
                   padding: 2px 10px; font-size: 11px; border-radius: 6px; cursor: pointer; }
  .aglog-refresh:hover { background: var(--accent-blue-hover); }
  .aglog-list { display: flex; flex-direction: column; gap: 2px; }
  .aglog-row { display: flex; gap: 10px; font-family: ui-monospace, monospace; font-size: 11.5px;
               line-height: 1.55; }
  .aglog-ts { color: var(--ts-dim); white-space: nowrap; flex: none; }
  .aglog-txt { color: var(--text-mid); word-break: break-all; }
  .termlog { background: var(--term-bg); border: 1px solid var(--term-bd); border-radius: 6px; padding: 8px 10px;
             font-family: ui-monospace, monospace; font-size: 11px; line-height: 1.45;
             color: var(--term-tx); overflow-x: auto; white-space: pre; margin: 2px 0 8px; }
  .aglog-empty { color: var(--text-dead); font-size: 12px; padding: 8px 0; }
  .mgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; padding: 4px 0 12px; }
  .mcard { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
  .mcard .mhead { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .mcard .mname { font-weight: 600; color: var(--text-hi); font-size: 14px; }
  .mcard .mdesc { color: var(--text-ghost); font-size: 11px; }
  .mcard .mstate { margin: 8px 0 10px; font-size: 12.5px; color: var(--text-soft); display: flex; align-items: center; gap: 6px; }
  .mcard .mdot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
  .mcard .mbtns { display: flex; gap: 8px; flex-wrap: wrap; }
  .mcard .mbtn { background: var(--btn-soft-bg); border: 1px solid var(--btn-soft-border); color: var(--text);
                  border-radius: 6px; padding: 5px 14px; font-size: 12.5px; cursor: pointer; }
  .mcard .mbtn:hover { border-color: var(--btn-soft-hover-bd); color: var(--text-title); }
  .mcard .mbtn[aria-disabled="true"] { opacity: .5; cursor: default; }
  .mcard .mresult { margin-top: 8px; font-size: 12px; color: var(--c-green); min-height: 15px; word-break: break-all; }
  .chip { background: var(--chip-bg); color: var(--text-soft); border: 1px solid var(--chip-border);
          border-radius: 999px; padding: 5px 14px; font-size: 12.5px; cursor: pointer; }
  .chip:hover { background: var(--bg-hover); }
  .chip.active { background: var(--chip-on-bg); border-color: var(--chip-on-bg); color: var(--chip-on-tx); }
  .chip span { opacity: .6; margin-left: 4px; font-size: 11px; }
  a.chip { text-decoration: none; }
  a.chip:hover { color: var(--text-title); border-color: var(--btn-hover); }
  .toolchips { margin-bottom: 14px; }

  /* ---------------- Goal 进度卡片 / 负载水位 / 事件时间线 ---------------- */
  .gpanel { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 10px;
            padding: 12px 14px; margin-bottom: 14px; }
  .gpanel h2 { margin: 0 0 10px; font-size: 13px; color: var(--text-dim); font-weight: 500; }
  .gpanel .ghint { color: var(--text-faint); font-weight: 400; font-size: 11.5px; }
  .gcards { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 10px; align-items: start; }
  .gcard { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
  .gcard .ghead { display: flex; align-items: baseline; gap: 7px; flex-wrap: wrap; }
  .gcard .glight { font-size: 13px; }
  .gcard .gname { font-weight: 600; color: var(--text-hi); font-size: 14px; word-break: break-all; }
  .gcard .gstate { color: var(--text-faint); font-size: 11.5px; }
  .gcard .gsub { color: var(--text-dim); font-size: 11.5px; margin-top: 2px;
                 word-break: break-all; line-height: 1.45; }
  .gcard .grow { display: flex; justify-content: space-between; gap: 10px;
                 font-size: 12.5px; color: var(--text-soft); padding: 3px 0 0; }
  .gcard .grow > span:first-child { color: var(--text-ghost); flex: none; }
  .gcard .gtx { font-family: ui-monospace, monospace; color: var(--text-mid); }
  .gcard .gtx.warn { color: var(--c-warn); font-weight: 600; }
  .gcard .gtx.stop { color: var(--c-red); font-weight: 600; }
  .gcard .gretry { color: var(--c-orange); font-family: ui-monospace, monospace; }
  .gcard .gidle { font-family: ui-monospace, monospace; }
  .gcard .gstalled, .gcard .gstalled + * { color: var(--text-ghost) !important; }
  .gcard .gprog { font-family: ui-monospace, monospace; font-size: 11.5px;
                  color: var(--text-dim); padding: 4px 0 0 6px; line-height: 1.5;
                  word-break: break-all; }
  .gcard .gfoot { margin-top: 8px; }
  .gcopy { display: inline-flex; align-items: center; gap: 6px; background: var(--btn-soft-bg);
           border: 1px solid var(--btn-soft-border); color: var(--text); border-radius: 6px;
           padding: 6px 14px; font-size: 12.5px; cursor: pointer; user-select: none; }
  .gcopy:hover { border-color: var(--btn-soft-hover-bd); color: var(--text-title); }
  .gempty { color: var(--text-faint); font-size: 12.5px; padding: 10px 0; }
  .gdone { margin-top: 12px; border-top: 1px solid var(--border-soft); padding-top: 8px; }
  .gdone summary { cursor: pointer; color: var(--text-dim); font-size: 12.5px; user-select: none;
                   display: flex; align-items: center; gap: 6px; }
  .gdone summary:hover { color: var(--text); }
  .gdone-row { display: flex; gap: 10px; align-items: baseline; padding: 4px 0;
               font-size: 12px; border-bottom: 1px solid var(--border-faint); flex-wrap: wrap; }
  .gdone-row:last-child { border-bottom: none; }
  .gdone-name { color: var(--text-mid); font-weight: 600; word-break: break-all; }

  .loadline .ld-head { font-size: 13.5px; color: var(--text); display: flex;
                       align-items: baseline; gap: 6px; flex-wrap: wrap; }
  .loadline .ld-ico { font-size: 14px; display: inline-flex; align-items: center; }
  .loadline b { color: var(--text-hi); font-weight: 600; }
  .loadline .ld-sub { color: var(--text-dim); font-size: 12px; font-family: ui-monospace, monospace; }
  .loadline .ld-tops { display: flex; gap: 24px; flex-wrap: wrap; margin-top: 8px; }
  .loadline .ld-top { flex: 1 1 260px; min-width: 0; }
  .loadline .ld-t { color: var(--text-dim); font-size: 11px; margin-bottom: 3px; }
  .loadline .ld-row { display: flex; gap: 8px; font-size: 12px; line-height: 1.6;
                      font-family: ui-monospace, monospace; }
  .loadline .ld-val { color: var(--text-mid); min-width: 52px; text-align: right; flex: none; }
  .loadline .ld-name { color: var(--text-dim); word-break: break-all; }

  .evt-row { display: flex; gap: 8px; font-size: 12px; line-height: 1.7;
             font-family: ui-monospace, monospace; flex-wrap: wrap; align-items: baseline; }
  .evt-ts { color: var(--evt-ts); flex: none; }  /* 4.7:1 on --bg-panel */
  .evt-name { color: var(--c-warn); flex: none; }
  .evt-txt { color: var(--text-soft); word-break: break-all; min-width: 200px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th { text-align: left; color: var(--text-faint); font-weight: 500; font-size: 12px;
             padding: 8px 10px; border-bottom: 1px solid var(--border); position: sticky; top: 52px;
             background: var(--bg); }
  tbody td { padding: 9px 10px; border-bottom: 1px solid var(--border-faint); vertical-align: top; }
  tbody tr:hover { background: var(--bg-panel); }
  .name { white-space: nowrap; }
  .svc { font-weight: 600; color: var(--text-hi); }
  .port a { color: var(--text-hi); font-weight: 600; text-decoration: none; font-family: ui-monospace, monospace; font-size: 14px; }
  .port a:hover { text-decoration: underline; color: var(--text-title); }
  .addr, .pid { color: var(--text-faint); font-family: ui-monospace, monospace; white-space: nowrap; }
  .cmd, .cwd { color: var(--text-soft); white-space: pre-wrap; word-break: break-all;
               font-family: ui-monospace, monospace; min-width: 220px; }
  table[data-col="cmd"] td.cwd { display: none; }
  table[data-col="cwd"] td.cmd { display: none; }
  th.colswitch { min-width: 220px; }
  .tcol { background: transparent; border: 1px solid var(--chip-border); color: var(--text-faint);
          border-radius: 6px; padding: 2px 11px; font-size: 11.5px; cursor: pointer; }
  .tcol:hover { color: var(--text-hi); border-color: var(--btn-hover); }
  .tcol.active { background: var(--btn-bg); color: var(--text-title); border-color: var(--btn-hover); }
  .badge { display: inline-block; margin-left: 8px; padding: 2px 7px; border-radius: 999px;
           font-size: 11px; font-weight: 500; vertical-align: 1px; }
  .badge-docker  { background: var(--tbadge-sc-bg); color: var(--text-mid); border: 1px solid var(--btn-hover); }
  .badge-systemd { background: var(--tbadge-sc-bg); color: var(--text-soft); border: 1px solid var(--tbadge-sc-bd); }
  .badge-direct  { background: var(--chip-bg); color: var(--text-faint); border: 1px solid var(--chip-border); }
  .badge-self    { background: var(--btn-bg); color: var(--text-title); border: 1px solid var(--btn-hover); }
  .badge-paused  { background: var(--c-warn-bg); color: var(--c-warn); border: 1px solid var(--c-warn-border); }
  .detail { display: block; color: var(--text-ghost); font-size: 11px; font-family: ui-monospace, monospace; margin-top: 2px; }
  .local { color: var(--text-dim); font-size: 11px; }
  .ctl { white-space: nowrap; }
  .ctl-btn { background: var(--btn-soft-bg); border: 1px solid var(--btn-soft-border); color: var(--text);
             border-radius: 6px; padding: 5px 14px; font-size: 12.5px; cursor: pointer; }
  .ctl-btn:hover { border-color: var(--btn-soft-hover-bd); color: var(--text-title); }
  .ctl-btn[aria-disabled="true"] { opacity: .5; cursor: default; }
  .empty { color: var(--text-faint); text-align: center; padding: 48px 0; }
  @media (max-width: 900px) { .cmd, .cwd { min-width: 120px; } }

  /* ---------------- 手机端 (<768px): App 化布局 ----------------
     六页横向滑动(概览/日志/Goal/服务/模型/ツール) + 底部页签栏 + safe-area;
     服务表→卡片(左滑复制/圆形打开), goal 卡收起次要信息。
     ≥769px 恢复桌面布局,所有规则只在此断点内生效。 */
  /* ---------------- 概要摘要组件 + 日志时间线(桌面隐藏,手机显示) ----------------
     字号体系: 状态数字 22-24px / 正文 14px / 辅助 12px。 */
  .stale { display: inline-flex; align-items: center; gap: 5px; background: var(--c-warn-bg);
           color: var(--c-warn); border: 1px solid var(--c-warn-border); border-radius: 999px;
           padding: 2px 10px; font-size: 12px; }
  .statuscard { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 12px;
                padding: 14px 16px; }
  .statuscard .sc-head { display: flex; align-items: center; gap: 12px; }
  .statuscard .sc-ico { font-size: 30px; line-height: 1; }
  .statuscard .sc-big { font-size: 24px; font-weight: 700; color: var(--text-title); }
  .statuscard .sc-sub { margin-top: 8px; color: var(--text-dim); font-size: 12px; }
  #gh-link { margin-left: auto; color: var(--text-faint); display: inline-flex; padding: 4px;
             border-radius: 8px; align-self: flex-start; }
  #gh-link:hover { color: var(--text); background: var(--bg-hover); }
  #gh-link svg { display: block; }
  .mgrid4 { grid-template-columns: 1fr 1fr; gap: 8px; align-items: start; }
  .mcell { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 10px;
           padding: 10px 12px; display: flex; flex-direction: column; gap: 3px; }
  .mnum { font-size: 22px; font-weight: 700; color: var(--text-title); font-variant-numeric: tabular-nums; }
  .mnum.alert { color: var(--c-warn); }
  .mlabel { font-size: 12px; color: var(--text-dim); }
  .al-btn { background: var(--btn-soft-bg); border: 1px solid var(--btn-soft-border); color: var(--text);
            border-radius: 6px; padding: 8px 12px; font-size: 12.5px; cursor: pointer; }
  .al-btn:hover { border-color: var(--btn-soft-hover-bd); color: var(--text-title); }
  .al-btn.ignore { color: var(--text-dim); }
  .alert-item { align-items: center; gap: 10px; padding: 10px 2px; border-bottom: 1px solid var(--border-faint); }
  .alert-item:last-child { border-bottom: none; }
  .al-ico { font-size: 17px; }
  .al-main { flex: 1 1 auto; min-width: 0; }
  .al-line { font-size: 14px; color: var(--text-hi); display: flex; gap: 8px; align-items: baseline; min-width: 0; }
  .al-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .al-sub { font-size: 12px; color: var(--text-dim); margin-top: 2px; overflow: hidden;
            text-overflow: ellipsis; white-space: nowrap; }
  .al-act { display: flex; gap: 6px; flex: none; }
  .rc-row { align-items: center; gap: 8px; padding: 9px 2px; border-bottom: 1px solid var(--border-faint);
            font-size: 14px; color: var(--text-mid); }
  .rc-row:last-child { border-bottom: none; }
  .rc-ico { flex: none; }
  .rc-kind { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rc-kind .rc-name { color: var(--text-hi); font-weight: 600; }
  .rc-ago::before { content: "·"; color: var(--text-dead); margin-right: 8px; }
  .rc-name { color: var(--text-dim); font-size: 12px; flex: none; max-width: 38%; overflow: hidden;
             text-overflow: ellipsis; white-space: nowrap; }
  .rc-ago { color: var(--text-dim); font-size: 12px; flex: none; }
  /* 日志时间线: 第一行 图标+类型+相对时间, 第二行一句话摘要, 详情默认折叠 */
  .lv { border-bottom: 1px solid var(--border-faint); padding: 9px 2px; }
  .lv:last-child { border-bottom: none; }
  .lv-line1 { display: flex; align-items: baseline; gap: 8px; font-size: 14px; color: var(--text-hi); min-width: 0; }
  .lv-ico { flex: none; display: inline-flex; align-items: center; }
  .lv-kind { font-weight: 600; flex: none; }
  .lv-loop { color: var(--c-warn); font-size: 12.5px; flex: none; }
  .lv-ago { margin-left: auto; color: var(--text-dim); font-size: 12px; flex: none; }
  .lv-line2 { font-size: 14px; color: var(--text-mid); margin-top: 3px; line-height: 1.5;
              display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
  .lv.open .lv-line2 { display: block; }
  .lv-fold { margin-top: 6px; font-size: 12px; color: var(--c-blue); display: inline-flex;
             align-items: center; gap: 4px; cursor: pointer; }
  .lv-fold::before { content: "▸"; transition: transform .15s; }
  .lv.open .lv-fold::before { transform: rotate(90deg); }
  .lv-meta { display: none; margin-top: 6px; background: var(--bg-deep); border: 1px solid var(--btn-soft-border);
             border-radius: 6px; padding: 8px 10px; font-family: ui-monospace, monospace;
             font-size: 11px; color: var(--text-dim); word-break: break-all; line-height: 1.6; }
  .lv.open .lv-meta { display: block; }
  .lv-children { display: none; margin-top: 6px; border-left: 2px solid var(--border-soft); padding-left: 8px; }
  .lv.open > .lv-children { display: block; }
  .lv-more { font-size: 12px; color: var(--text-dim); padding: 10px 0 2px; }

  @media (max-width: 768px) {
    .meta { display: none !important; }  /* 移动端: 更新时间/端口数与主体状态卡重复,隐藏 */
    -webkit-tap-highlight-color: transparent;
    /* safe-area: 刘海/手势条不遮挡; 标题行+状态摘要合并紧凑化 */
    header { padding: 8px max(12px, env(safe-area-inset-right)) 8px max(12px, env(safe-area-inset-left));
             padding-top: calc(8px + env(safe-area-inset-top)); gap: 8px;
             -webkit-backdrop-filter: blur(6px); }
    header h1 { font-size: 15px; }
    header .spacer { display: none; }
    .btn, .chip, .mbtn, .ctl-btn, .tcol, .aglog-refresh { padding: 9px 14px; font-size: 13px; min-height: 38px; }
    .icon-btn { min-height: 38px; }
    /* 内部滚动: main 自滚, 底部页签栏固定在文档流尾, 不再遮住最后一屏 */
    html, body { height: 100%; }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-thumb { background: var(--chip-border); border-radius: 2px; }
  ::-webkit-scrollbar-track { background: transparent; }
    body { display: flex; flex-direction: column; overflow: hidden;
           overscroll-behavior: none; }
    main { flex: 1 1 auto; min-height: 0; overflow-y: auto;
           -webkit-overflow-scrolling: touch; overscroll-behavior-y: contain;
           padding: 10px max(12px, env(safe-area-inset-right)) 16px
                    max(12px, env(safe-area-inset-left)); }
    /* 每页底部留出 页签栏+safe-area+余量: 滚到内容末尾时最后一条完整露出 */
    #track > .pg { padding-bottom: calc(68px + 24px + env(safe-area-inset-bottom)); }

    /* 底部页签栏(唯一导航): 常规文档流尾部 + 毛玻璃, 不遮内容 */
    #tabbar { display: flex; flex: none; z-index: 40;
              background: var(--tabbar-bg);
              -webkit-backdrop-filter: blur(16px) saturate(1.4);
              backdrop-filter: blur(16px) saturate(1.4);
              border-top: 1px solid var(--border);
              padding: 4px max(8px, env(safe-area-inset-left)) calc(4px + env(safe-area-inset-bottom))
                          max(8px, env(safe-area-inset-right)); }
    #tabbar .tab { flex: 1; position: relative; display: flex; flex-direction: column; align-items: center; gap: 3px;
                   padding: 7px 0 3px; min-height: 50px; color: var(--text-faint); font-size: 10.5px;
                   cursor: pointer; user-select: none; -webkit-user-select: none;
                   -webkit-tap-highlight-color: transparent; }
    #tabbar .tab.active { color: var(--c-blue); }
    #tabbar .tab svg { width: 22px; height: 22px; }
    /* 概要页签未处理告警徽章: 红点+数字 */
    .tbadge-dot { position: absolute; top: 2px; left: calc(50% + 12px); min-width: 17px; height: 17px;
                  padding: 0 4px; border-radius: 999px; background: #c04848; color: #fff;
                  font-size: 10.5px; font-weight: 700; display: flex; align-items: center;
                  justify-content: center; border: 1.5px solid var(--tabbar-bg); }

    /* 两层结构: #pages(裁剪窗口) > #track(600% 轨道) > .pg(各 1/6 = 屏宽) */
    #pages { display: block; width: 100%; overflow: hidden; }
    body { overscroll-behavior-x: none; }  /* 关掉浏览器右滑返回/左滑前进接管 */
    #pages, .swipe-fg { touch-action: pan-y; }  /* 横向留给 JS 手势 */
    .filters { touch-action: pan-x; }  /* 自身横滚的容器除外 */
    #track { display: flex; align-items: flex-start; width: 600%;
             will-change: transform;
             transition: transform .26s cubic-bezier(.22,.61,.36,1),
                         height .26s cubic-bezier(.22,.61,.36,1); }
    #track.stick { transition: none; }
    #track > .pg { flex: 0 0 16.6667%; min-width: 16.6667%; max-width: 16.6667%; }
    .skel { display: block; }
    #chart-wrap, #logpage, #agents-page, #toolspage { display: block; }  /* 移动专用面板 */
    #logpage[hidden], #agents-page[hidden], #toolspage[hidden] { display: none !important; }
    /* 概要摘要组件(状态卡+指标2×2+需要处理+最近活动) */
    .statuscard { display: block; margin-bottom: 10px; }
    .mgrid4 { display: grid; margin-bottom: 12px; }
    #alerts, #recent { display: block; margin-bottom: 12px; }
    #recent h2 { display: flex; justify-content: space-between; align-items: baseline; }
    .rc-more { cursor: pointer; }
    #events { display: none; }  /* 概要页只留 3-5 条摘要(最近活动), 全量事件进日志页 */
    .lv { display: block; }
    #log-filters { display: flex; flex-wrap: nowrap; overflow-x: auto;
                   -webkit-overflow-scrolling: touch; scrollbar-width: none;
                   margin: 0 -12px 10px; padding: 0 12px 4px; }
    #log-filters::-webkit-scrollbar { display: none; }
    #log-filters .chip { flex: none; }

    .sysbar { gap: 8px; margin-bottom: 10px; }
    .stat { min-width: calc(50% - 6px); flex: 1 1 calc(50% - 6px); padding: 8px 12px;
            touch-action: manipulation; } /* 双击手势目标: 消除 300ms 缩放 */
    .stat .value { font-size: 12.5px; }

    /* chips 横向滚动 */
    .filters { flex-wrap: nowrap; overflow-x: auto; -webkit-overflow-scrolling: touch;
               scrollbar-width: none; margin: 0 -12px 10px; padding: 0 12px 4px; }
    .filters::-webkit-scrollbar { display: none; }
    .filters .spacer { display: none; }
    .chip { flex: none; padding: 8px 14px; font-size: 12.5px; }

    /* 服务列表 → 卡片(左滑露「复制地址」, 头行右侧 44px 圆形打开按钮) */
    #svc thead { display: none; }
    #svc tbody tr { display: block; background: var(--bg-panel); border: 1px solid var(--border);
                    border-radius: 10px; margin-bottom: 10px; overflow: hidden; }
    #svc tbody tr:has(> td.empty) { background: none; border: none; }
    #svc tbody td { display: block; border: none; padding: 0; }
    #svc tbody td.empty { text-align: center; padding: 32px 0; }
    .td-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
               padding: 10px 12px 4px; }
    .td-head .svc { flex: 1 1 auto; }
    .td-rows { padding: 4px 12px 10px; }
    .td-rows .kv { display: flex; justify-content: space-between; gap: 12px;
                   align-items: baseline; padding: 3px 0; }
    .td-rows .k { color: var(--text-ghost); font-size: 11px; flex: none; }
    .td-rows .v { text-align: right; word-break: break-all; white-space: normal; min-width: 0; }
    .ctl-btn { min-height: 44px; padding: 10px 16px; font-size: 13px; }
    .colswitch, .tcol { display: none; }
    .empty { padding: 32px 0; }

    /* watchdog / agent / tmux 面板表 → 卡片 */
    .watchdog-panel { padding: 10px 12px; }
    .watchdog-panel thead { display: none; }
    .watchdog-panel tbody tr { display: block; padding: 6px 0; }
    .watchdog-panel td { display: flex; justify-content: space-between; gap: 12px;
                         align-items: baseline; border: none; padding: 3px 0;
                         white-space: normal !important; }
    .watchdog-panel td::before { content: attr(data-label); color: var(--text-ghost); font-size: 11px;
                                 flex: none; }
    .watchdog-panel td:first-child { display: block; padding: 2px 0 4px; }
    .watchdog-panel td:first-child::before { content: none; }
    .watchdog-panel .tcmd { max-width: none; }
    .watchdog-panel .agent-detail td { display: block; padding: 8px 4px; }
    .watchdog-panel .agent-detail td::before { content: none; }
    .aglog-row { flex-wrap: wrap; gap: 2px 8px; padding: 4px 0; }
    .aglog-ts { flex: none; }
    .termlog { font-size: 10.5px; -webkit-overflow-scrolling: touch; }

    /* 日志页: 展开式(不嵌套滚动) */
    #logpage .agentlog { max-height: none; overflow: visible; }
    .logbar { margin-bottom: 10px; }

    /* 服务管理卡片 */
    .mgrid { grid-template-columns: 1fr; gap: 10px; }
    .mcard { padding: 12px; }
    .mcard .mbtns { gap: 6px; }
    .mcard .mbtn { flex: 1 1 auto; min-width: 88px; padding: 11px 8px; font-size: 13.5px; }
    .mcard .mresult { font-size: 12.5px; }

    /* Goal 卡片/负载线/事件: 单列可读 */
    .gcards { grid-template-columns: 1fr; gap: 8px; }
    .gcard .grow { flex-wrap: wrap; }
    .gextra { display: none; }               /* 手机: 次要信息默认收起 */
    .gcard.open .gextra { display: block; }
    .gmore { display: inline-flex; margin-left: auto; transition: transform .15s; }
    .gcard.open .gmore { transform: rotate(90deg); }
    .gpanel { padding: 10px 12px; }
    .loadline .ld-top { flex: 1 1 100%; }
    .loadline .ld-row { font-size: 11.5px; }
    .evt-row { gap: 6px; }
    .evt-txt { min-width: 0; flex: 1 1 100%; padding-left: 14px; }
    .gcopy { min-height: 38px; padding: 9px 16px; font-size: 13px; }
    .gdone-row { font-size: 11.5px; }
  }
  @media (prefers-reduced-motion: reduce) {
    #track, .swipe-fg, .gmore { transition: none !important; }
    .skel-line { animation: none; }
  }
  /* ---------------- ツール页 ---------------- */
  .toolspage .tl-sec + .tl-sec { border-top: 1px solid var(--border); margin-top: 14px; padding-top: 12px; }
  .toolspage .tl-sec h3 { margin: 0 0 8px; font-size: 12.5px; color: var(--text-dim); font-weight: 500;
                          display: flex; align-items: center; gap: 6px; }
  .tl-sechead { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .tl-sechead h3 { margin: 0; flex: 1 1 auto; }
  .tl-run { flex: none; cursor: pointer; user-select: none; }
  .tl-row { display: flex; align-items: center; gap: 8px; padding: 5px 0;
            font-size: 12.5px; border-bottom: 1px dashed var(--border-faint); }
  .tl-row:last-child { border-bottom: none; }
  .tl-dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--c-green); }
  .tl-dot.warn { background: var(--c-warn); }
  .tl-dot.bad { background: var(--c-red); }
  .tl-dot.off { background: var(--dot-off); }
  .tl-name { color: var(--text-mid); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tl-val { margin-left: auto; color: var(--text-faint); font-family: ui-monospace, monospace;
            font-size: 11.5px; white-space: nowrap; }
  .tl-val b { color: var(--text-hi); font-weight: 600; }
  .tl-head-big { font-size: 15px; font-weight: 600; }
  .tl-head-big > span:first-child { display: inline-flex; align-items: center; }
  .tl-copyrow { display: flex; gap: 8px; flex-wrap: wrap; }
  .tl-copyrow .btn { font-size: 12px; padding: 6px 12px; }
  .themechips { margin-bottom: 0; }
  .tl-fsbar { display: flex; flex-direction: column; gap: 8px; margin-bottom: 8px; }
  .tl-crumbs { font-size: 12px; color: var(--text-faint); word-break: break-all; line-height: 1.7; }
  .tl-crumbs a { color: var(--link-blue); text-decoration: none; cursor: pointer; }
  .tl-crumbs a:hover { text-decoration: underline; }
  .tl-crumbs .cur { color: var(--text-hi); }
  .tl-fsctl { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .tl-fsctl input[type="search"] { flex: 1 1 120px; background: var(--bg-input); color: var(--text);
      border: 1px solid var(--chip-border); border-radius: 8px; padding: 8px 10px; font-size: 13px; min-height: 38px; }
  .tl-switch { display: inline-flex; gap: 6px; align-items: center; font-size: 12px;
               color: var(--text-faint); cursor: pointer; min-height: 38px; }
  .tl-fslist { border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .tl-fsrow { display: flex; align-items: center; gap: 8px; padding: 9px 10px; font-size: 13px;
              border-bottom: 1px solid var(--border-faint); cursor: pointer; background: var(--bg-panel); }
  .tl-fsrow:hover { background: var(--bg-hover); }
  .tl-fsrow:last-child { border-bottom: none; }
  .tl-fsrow .ico { flex: none; width: 18px; display: inline-flex; align-items: center; justify-content: center; }
  .tl-fsrow .nm { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis;
                  white-space: nowrap; }
  .tl-fsrow .mt { flex: none; color: var(--text-dead); font-size: 11px; font-family: ui-monospace, monospace; }
  .tl-fsrow .sz { flex: none; color: var(--text-faint); font-size: 11.5px; font-family: ui-monospace, monospace;
                 min-width: 56px; text-align: right; }
  .tl-fsrow .du { color: var(--link-blue); }
  .tl-cleanrow { display: flex; align-items: center; gap: 8px; padding: 7px 0; font-size: 12.5px;
                 border-bottom: 1px dashed var(--border-faint); }
  .tl-cleanrow:last-child { border-bottom: none; }
  .tl-cleanrow input[type="checkbox"] { flex: none; width: 16px; height: 16px; accent-color: var(--c-green-btn); }
  .tl-cleanrow .lbl { flex: 1 1 auto; min-width: 0; }
  .tl-cleanrow .lbl small { display: block; color: var(--text-dead); font-size: 11px; margin-top: 1px;
                            word-break: break-all; }
  .tl-cleanrow .sz { flex: none; color: var(--text-hi); font-family: ui-monospace, monospace; font-size: 12px; }
  .tl-docker-pre { background: var(--bg-deep); border: 1px solid var(--border); border-radius: 8px;
                   padding: 8px 10px; font: 11px ui-monospace, monospace; color: var(--text-dim);
                   overflow-x: auto; white-space: pre; margin: 8px 0; }
  #tl-lightbox, #tl-textview { position: fixed; inset: 0; z-index: 80; background: var(--scrim);
      display: flex; align-items: center; justify-content: center; flex-direction: column; }
  #tl-lightbox img { max-width: 96vw; max-height: 88vh; object-fit: contain; }
  .tl-lb-close { position: absolute; top: calc(10px + env(safe-area-inset-top)); right: 12px;
      width: 40px; height: 40px; display: flex; align-items: center; justify-content: center;
      font-size: 18px; color: var(--text-mid); background: var(--btn-soft-bg);
      border: 1px solid var(--chip-border);
      border-radius: 50%; cursor: pointer; }
  #tl-textview { align-items: stretch; }
  .tl-tv-head { display: flex; align-items: center; justify-content: space-between;
      padding: 10px 14px; font-size: 13px; color: var(--text-dim); position: relative; }
  .tl-tv-head .tl-lb-close { position: static; }
  #tl-tv-pre { flex: 1 1 auto; margin: 0; padding: 0 14px 16px; overflow: auto;
      font: 12px/1.6 ui-monospace, monospace; color: var(--text); white-space: pre-wrap;
      word-break: break-all; }
  .tl-usvc-unlock { display: inline-flex; gap: 6px; align-items: center; }
  .tl-usvc-unlock input { width: 110px; background: var(--bg-input); color: var(--text);
      border: 1px solid var(--chip-border); border-radius: 8px; padding: 7px 10px; font-size: 13px; }
  .tl-netrow { display: flex; gap: 8px; align-items: center; padding: 5px 0; font-size: 12.5px; }
  .tl-netrow .tl-val { margin-left: 0; }
  .tl-netrow .sep { flex: 1 1 auto; border-bottom: 1px dotted var(--btn-hover); }
  .copy-toast { position: fixed; left: 50%; bottom: calc(90px + env(safe-area-inset-bottom));
      transform: translateX(-50%); display: inline-flex; align-items: center; gap: 6px;
      background: var(--c-green-bg); color: var(--c-green); border: 1px solid var(--c-green-btn);
      border-radius: 999px; padding: 8px 18px; font-size: 12.5px; z-index: 60;
      pointer-events: none; transition: opacity .3s; }
</style>
<header>
  <!-- topbar 重设计: 左=服务器名(HOSTNAME), 右=刷新按钮(点击刷新/长按锁定自动刷新)。
       原 meta 行与自动刷新开关已并入按钮; updated/count 保留为隐藏节点供 JS 写入。 -->
  <h1 title="{{T:title}}"><span class="h-server" aria-hidden="true"></span>{{HOSTNAME}}</h1>
  <span class="meta" id="meta-line" hidden>
    <span id="updated">{{UPDATED}}</span> <span id="count">{{COUNT}}</span>
  </span>
  <span class="spacer"></span>
  <span class="btn icon-btn" id="refresh" role="button" tabindex="0"
        title="{{T:refresh_title}}" aria-label="{{T:refresh_title}}" aria-pressed="false">{{ICO:refresh:17}}<span class="ic-badge">{{ICO:lock:9}}</span></span>
</header>
<div id="ptr-indicator" aria-hidden="true"><span class="ptr-arrow">{{ICO:down:20}}</span><span class="ptr-label">{{T:ptr_pull}}</span></div>
<main>
<div id="pages">
<div class="statuscard" id="statuscard" role="button" tabindex="0">
  <div class="sc-head"><span class="sc-ico" id="sc-ico">{{ICO:wait:28}}</span><span class="sc-big" id="sc-text">{{T:st_loading}}</span>
    <a id="gh-link" href="https://github.com/iamcheyan/svc-dashboard" target="_blank" rel="noopener" title="{{T:github_repo}}" aria-label="{{T:github_repo}}">
      <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
    </a></div>
  <div class="sc-sub"><span id="sc-fresh"></span><span class="stale" id="sc-stale" hidden> {{T:st_stale}}</span></div>
</div>
<div class="mgrid4">
  <div class="mcell"><span class="mnum" id="m-svc">—</span><span class="mlabel">{{T:m_svc_ok}}</span></div>
  <div class="mcell"><span class="mnum" id="m-run">—</span><span class="mlabel">{{T:m_goal_run}}</span></div>
  <div class="mcell"><span class="mnum" id="m-bad">—</span><span class="mlabel">{{T:m_goal_bad}}</span></div>
  <div class="mcell"><span class="mnum" id="m-alert">—</span><span class="mlabel">{{T:m_alerts}}</span></div>
</div>
<div class="gpanel" id="alerts">
  <h2>{{T:al_title}}</h2>
  <div id="alert-body" class="alert-body"><div class="gempty">{{T:st_loading}}</div></div>
</div>
<div class="gpanel" id="recent">
  <h2>{{T:rc_title}} <span class="ghint rc-more" role="button" tabindex="0">{{T:rc_more}}</span></h2>
  <div id="recent-body"></div>
</div>
{{SYSBAR}}
{{LOADLINE}}
<div class="gpanel" id="chart-wrap">
  <h2>{{T:chart_title}} <span class="ghint" id="chart-win"></span></h2>
  <canvas id="chart" width="640" height="150"></canvas>
  <div id="chart-empty">{{T:chart_empty}}</div>
</div>
{{TOOLCHIPS}}
{{GOALS_PANEL}}
{{EVENTS_PANEL}}
<div class="filters" id="filters">
  <span class="chip active" data-f="user" role="button" tabindex="0">{{T:chip_user}} <span id="n-user"></span></span>
  <span class="chip" data-f="docker" role="button" tabindex="0">{{T:chip_docker}} <span id="n-docker"></span></span>
  <span class="chip" data-f="system" role="button" tabindex="0">{{T:chip_system}} <span id="n-system"></span></span>
  <span class="chip" data-f="all" role="button" tabindex="0">{{T:chip_all}} <span id="n-all"></span></span>
  <span class="spacer"></span>
  <span class="chip" data-f="omp" role="button" tabindex="0">{{T:chip_omp}} <span id="n-omp"></span></span>
  <span class="chip" data-f="watchdog" role="button" tabindex="0">{{T:chip_watchdog}} <span id="n-watchdog"></span></span>
  <span class="chip" data-f="tmux" role="button" tabindex="0">{{T:chip_tmux}} <span id="n-tmux"></span></span>
  <span class="chip" data-f="manage" role="button" tabindex="0">{{T:chip_manage}} <span id="n-manage"></span></span>
</div>
<div id="tasks" hidden></div>
<table id="svc" data-col="cmd">
  <thead><tr>
    <th>{{T:th_svc}}</th><th>{{T:th_port}}</th><th>{{T:th_addr}}</th><th>{{T:th_pid}}</th>
    <th>{{T:th_ctl}}</th>
    <th class="colswitch">
      <span class="tcol active" data-col="cmd" role="button" tabindex="0">{{T:th_cmd}}</span>
      <span class="tcol" data-col="cwd" role="button" tabindex="0">{{T:th_cwd}}</span>
    </th>
  </tr></thead>
  <tbody>
<!--TABLE-->
  </tbody>
</table>
<div class="gpanel" id="agents-page" hidden>
  <h2>{{T:tab_model}} <span class="ghint">{{T:chip_omp}}</span></h2>
</div>
<div class="gpanel" id="logpage" hidden>
  <h2>{{T:tab_log}}</h2>
  <div class="logbar"><select id="logagent-sel"><option value="">{{T:log_pick}}</option></select></div>
  <div class="filters" id="log-filters">
    <span class="chip active" data-lf="all" role="button" tabindex="0">{{T:lf_all}}</span>
    <span class="chip" data-lf="ok" role="button" tabindex="0">{{T:lf_success}}</span>
    <span class="chip" data-lf="warn" role="button" tabindex="0">{{T:lf_warn}}</span>
    <span class="chip" data-lf="fail" role="button" tabindex="0">{{T:lf_fail}}</span>
    <span class="chip" data-lf="recover" role="button" tabindex="0">{{T:lf_recover}}</span>
    <span class="chip active" data-ls="all" role="button" tabindex="0">{{T:lf_wd}}</span>
    <span class="chip" data-ls="done" role="button" tabindex="0">{{T:lf_done}}</span>
    <span class="chip" data-ls="commit" role="button" tabindex="0">{{T:lf_commit}}</span>
    <span class="chip active" data-lt="24" role="button" tabindex="0">24h</span>
    <span class="chip" data-lt="72" role="button" tabindex="0">{{T:lf_3d}}</span>
    <span class="chip" data-lt="168" role="button" tabindex="0">{{T:lf_7d}}</span>
    <span class="chip" data-lt="0" role="button" tabindex="0">{{T:lf_time}}{{T:lf_all}}</span>
  </div>
  <div id="logbody"></div>
</div>
<div class="gpanel toolspage" id="toolspage" hidden>
  <h2>{{T:tab_tools}}</h2>
  <!-- 主题三选: 跟随系统 / 深色 / 浅色(localStorage 记住, html[data-theme] 生效) -->
  <div class="tl-sec" id="tl-theme">
    <div class="tl-sechead"><h3>{{T:theme_title}}</h3></div>
    <div class="filters themechips" id="theme-chips">
      <span class="chip active" data-thm="auto" role="button" tabindex="0">{{T:th_auto}}</span>
      <span class="chip" data-thm="dark" role="button" tabindex="0">{{T:th_dark}}</span>
      <span class="chip" data-thm="light" role="button" tabindex="0">{{T:th_light}}</span>
    </div>
  </div>

  <!-- F2 健康检查 -->
  <div class="tl-sec" id="tl-health">
    <div class="tl-sechead">
      <h3>{{T:tl_health_title}}</h3>
      <span class="btn tl-run" id="tl-health-run" role="button" tabindex="0">{{T:tl_health_run}}</span>
    </div>
    <div id="tl-health-body"><div class="gempty">{{T:st_loading}}</div></div>
  </div>

  <!-- F4 快速复制组(JS 填充) -->
  <div class="tl-sec" id="tl-copy">
    <div id="tl-copy-body" class="tl-copyrow"></div>
  </div>

  <!-- G1 工具直达 chips(JS 填充) -->
  <div class="tl-sec" id="tl-g1sec">
    <h3>{{T:tl_g1_title}}</h3>
    <div class="filters toolchips" id="tl-g1"></div>
  </div>

  <!-- F1 文件浏览 -->
  <div class="tl-sec" id="tl-fs">
    <div class="tl-sechead">
      <h3>{{T:tl_fs_title}}</h3>
      <span class="btn tl-run" id="tl-fs-du" role="button" tabindex="0">{{T:tl_fs_du}}</span>
    </div>
    <div class="tl-fsbar">
      <div class="tl-crumbs" id="tl-fs-crumbs"></div>
      <div class="tl-fsctl">
        <input type="search" id="tl-fs-filter" placeholder="{{T:tl_fs_filter}}" autocomplete="off">
        <label class="tl-switch"><input type="checkbox" id="tl-fs-hidden"><span>{{T:tl_fs_hidden}}</span></label>
      </div>
    </div>
    <div id="tl-fs-list" class="tl-fslist"></div>
  </div>
  <div id="tl-lightbox" hidden><img id="tl-lightbox-img" alt=""><div class="tl-lb-close" role="button" tabindex="0">{{ICO:close:16}}</div></div>
  <div id="tl-textview" hidden><div class="tl-tv-head"><span id="tl-tv-name"></span><span class="tl-lb-close" role="button" tabindex="0">{{ICO:close:16}}</span></div><pre id="tl-tv-pre"></pre></div>

  <!-- F3 垃圾清理 -->
  <div class="tl-sec" id="tl-clean">
    <div class="tl-sechead">
      <h3>{{T:tl_clean_title}}</h3>
      <span class="btn tl-run" id="tl-clean-scan" role="button" tabindex="0">{{T:tl_clean_scan}}</span>
      <span class="btn tl-run" id="tl-clean-exec" role="button" tabindex="0" hidden>{{T:tl_clean_exec}}</span>
    </div>
    <div id="tl-clean-body"><div class="gempty">{{T:tl_clean_scan}} →</div></div>
  </div>

  <!-- G3 网络速测 -->
  <div class="tl-sec" id="tl-net">
    <div class="tl-sechead">
      <h3>{{T:tl_net_title}}</h3>
      <span class="btn tl-run" id="tl-net-run" role="button" tabindex="0">{{T:tl_net_run}}</span>
    </div>
    <div id="tl-net-body"><div class="gempty">—</div></div>
  </div>

  <!-- G2 用户级服务重启(I-KNOW 护栏, 默认锁) -->
  <div class="tl-sec" id="tl-usvc">
    <div class="tl-sechead">
      <h3>{{T:tl_usvc_title}}</h3>
      <span class="tl-usvc-unlock" id="tl-usvc-unlockwrap" hidden>
        <input type="text" id="tl-usvc-code" placeholder="I-KNOW" autocomplete="off">
        <span class="btn tl-run" id="tl-usvc-unlock" role="button" tabindex="0">{{T:tl_usvc_unlock}}</span>
      </span>
      <span class="btn tl-run" id="tl-usvc-showlock" role="button" tabindex="0" title="{{T:tl_usvc_title}}">{{ICO:lock:14}}</span>
    </div>
    <div id="tl-usvc-body"></div>
  </div>

  <!-- G4 计划任务一览(只读) -->
  <div class="tl-sec" id="tl-cron">
    <h3>{{T:tl_cron_title}}</h3>
    <div id="tl-cron-body"><div class="gempty">{{T:st_loading}}</div></div>
  </div>
</div>
</div>
</main>
<nav id="tabbar" aria-label="{{T:title}}">
  <span class="tab" data-p="0" role="button" tabindex="0" aria-label="{{T:tab_home}}">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M2 8.5 8 3l6 5.5V14H9.5v-4h-5v4H2z"/></svg><span class="tlabel">{{T:tab_home}}</span><span class="tbadge-dot" id="tab-alert-badge" hidden></span></span>
  <span class="tab" data-p="1" role="button" tabindex="0" aria-label="{{T:tab_log}}">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M3.5 3.5h9M3.5 6.5h9M3.5 9.5h6M3.5 12.5h4"/></svg><span class="tlabel">{{T:tab_log}}</span></span>
  <span class="tab" data-p="2" role="button" tabindex="0" aria-label="{{T:tab_goal}}">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="8" cy="8" r="5.5"/><circle cx="8" cy="8" r="2" fill="currentColor" stroke="none"/></svg><span class="tlabel">{{T:tab_goal}}</span></span>
  <span class="tab" data-p="3" role="button" tabindex="0" aria-label="{{T:tab_svc}}">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="2" y="2.5" width="12" height="3.5" rx="1"/><rect x="2" y="9.5" width="12" height="3.5" rx="1"/></svg><span class="tlabel">{{T:tab_svc}}</span></span>
  <span class="tab" data-p="4" role="button" tabindex="0" aria-label="{{T:tab_model}}">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="4" y="4" width="8" height="8" rx="1.5"/><path d="M6 1.5v2M10 1.5v2M6 12.5v2M10 12.5v2M1.5 6h2M1.5 10h2M12.5 6h2M12.5 10h2"/></svg><span class="tlabel">{{T:tab_model}}</span></span>
  <span class="tab" data-p="5" role="button" tabindex="0" aria-label="{{T:tab_tools}}">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M9.5 1.5 3 8l-1.5 5 5-1.5 6.5-6.5a2.1 2.1 0 0 0-3-3z"/><path d="M9.5 1.5 12.5 4.5"/></svg><span class="tlabel">{{T:tab_tools}}</span></span>
</nav>
<script>
const AUTO = {{AUTO}};
const LANG = "{{LANG}}";
const TS_MODE = {{TS_MODE}};
const TS_HOST = "100.76.219.104";
const linkHost = (h) => (TS_MODE && (h === "192.168.3.82")) ? TS_HOST : h;  // 来源为 tailscale(100.64.0.0/10) 时链接主机改用 tailscale IP
const T = {{T_JSON}};
const t = (k, p) => { let s = T[k] ?? k; if (p !== undefined) { for (const [a, b] of Object.entries(p)) s = s.split("{" + a + "}").join(b); } return s; };
// --- 内联 SVG 图标(与 Python 端 ICONS 同一份 path 表, stroke=currentColor) ---
const ICONS = {{ICONS_JSON}};
function icon(name, size = 16, cls = "ic") {
  const p = ICONS[name] || ICONS.dot;
  return `<svg class="${cls}" width="${size}" height="${size}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${p}</svg>`;
}
let autoOn = false;          // 自动刷新总开关(刷新按钮长按锁定时强制 false)
let autoLocked = false;      // 长按锁定: true = 30s 自动刷新完全停止
let filter = "user"; // 默认只显示用户服务, 隐藏系统服务
let services = [];
const $ = (id) => document.getElementById(id);

const FILTERS = {
  user:   (e) => e.scope !== "system",
  docker: (e) => e.scope === "docker",
  system: (e) => e.scope === "system",
  omp:     () => false, // OMP 走独立面板,不混进服务表
  watchdog: () => false, // 看门狗走独立面板,不混进服务表
  manage:  () => false, // 服务管理走独立面板
  all:    () => true,
};

function row(e, mobile) {
  const badge = {docker:[t("badge_docker"),"badge-docker"], systemd:["systemd","badge-systemd"], direct:[t("badge_direct"),"badge-direct"]}[e.type] || [t("badge_direct"),"badge-direct"];
  let text = badge[0], detail = "";
  if (e.is_self) { text = t("badge_self"); badge[1] = "badge-self"; }
  else if (e.paused) { text = t("badge_paused"); badge[1] = "badge-paused"; }
  else if (e.docker_proxy) { text = t("badge_proxy"); }
  else if (e.type === "docker" && e.container_id) detail = `<span class='detail' title='${t("detail_cid")}'>${e.container_id}</span>`;
  else if (e.type === "systemd" && e.unit) detail = `<span class='detail' title='${t("detail_unit")}'>${e.unit}</span>`;
  const ip = e.ip;
  const loopback = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
  const link = loopback ? `http://127.0.0.1:${e.port}/` : `http://${linkHost(location.hostname)}:${e.port}/`;
  const loop = loopback ? ' <span class="local">' + t("loopback") + '</span>' : "";
  const cmd = e.cmdline || "—";
  const cwd = e.cwd || "—";
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  // 可管理的手动进程服务: 行尾渲染 暂停/继续 按钮(状态由 fillCtl 填充)
  const man = MANAGE_PROC_BY_PORT[e.port];
  const ctl = man
    ? `<span class='ctl-btn' data-ctl='${man}' data-port='${e.port}' role='button' tabindex='0' aria-disabled='true'>${t("ctl_checking")}</span>`
    : "";
  if (mobile) {
    // 手机卡片(合法表格结构): td.swipe-item 内 左滑露「复制地址」+ 头行 44px 圆形打开
    const kv = (k, v) => `<div class='kv'><span class='k'>${k}</span><span class='v'>${v}</span></div>`;
    const rows =
      kv(t("th_port"), `<a href='${link}' target='_blank' rel='noopener'>${e.port}</a>`) +
      kv(t("th_addr"), `${esc(ip)}${loop}`) +
      kv("PID", e.pids.join(", ")) +
      kv(t("th_cmd"), esc(cmd)) +
      kv(t("th_cwd"), esc(cwd)) +
      (man ? kv(t("th_ctl"), ctl) : "");
    return `<tr><td class='swipe-item'><div class='swipe-bg'>` +
      `<span class='swipe-act' role='button' tabindex='0' data-copy='${esc(link)}' title='${t("act_copy_addr")}'>${icon("copy", 12)} ${t("act_copy_addr")}</span></div>` +
      `<div class='swipe-fg'><div class='td-head'><span class='svc'>${esc(e.name)}</span>` +
      `<span class='badge ${badge[1]}'>${text}</span>${detail}` +
      `<a class='svc-open' href='${link}' target='_blank' rel='noopener' aria-label='${t("act_open")} ${esc(e.name)}'>${icon("ext", 15)}</a></div>` +
      `<div class='td-rows'>${rows}</div></div></td></tr>`;
  }
  return `<tr>
    <td class='name'><span class='svc'>${esc(e.name)}</span><span class='badge ${badge[1]}'>${text}</span>${detail}</td>
    <td class='port' data-label='${t("th_port")}'><a href='${link}' target='_blank' rel='noopener'>${e.port}</a></td>
    <td class='addr' data-label='${t("th_addr")}'>${esc(ip)}${loop}</td>
    <td class='pid' data-label='PID'>${e.pids.join(", ")}</td>
    <td class='cmd' data-label='${t("th_cmd")}'>${esc(cmd)}</td>
    <td class='cwd' data-label='${t("th_cwd")}'>${esc(cwd)}</td>
    ${ctl ? `<td class='ctl' data-label='${t("th_ctl")}'>${ctl}</td>` : ""}
  </tr>`;
}

function applyFilter() {
  const shown = FILTERS[filter] ? services.filter(FILTERS[filter]) : [];
  ["user", "docker", "system", "all"].forEach(f =>
    $("n-" + f).textContent = services.filter(FILTERS[f]).length);
  document.querySelectorAll("#filters .chip").forEach(c =>
    c.classList.toggle("active", c.dataset.f === filter));
  if (filter === "omp") {
    $("svc").style.display = "none";
    // 先亮面板显示「加载中」,再等数据 —— 冷扫描需数秒,
    // 之前面板一直 hidden,数据回来前用户看到的是一片空白。
    const tasksEl = $("tasks");
    tasksEl.hidden = false; tasksEl.className = "watchdog-panel";
    tasksEl.innerHTML = "<h2>" + t("a_title") + " <span style='color:var(--text-dead);font-weight:400'>" + t("a_loading") + "</span></h2>";
    loadAgents().then(renderAgentPanel);
    $("count").textContent = t("chip_omp");
    return;
  }
  if (filter === "tmux") {
    $("svc").style.display = "none";
    loadTmux().then(renderTmuxPanel);
    $("count").textContent = t("chip_tmux");
    return;
  }
  if (filter === "watchdog") {
    // 看门狗模式:隐藏服务表,显示看门狗面板
    $("svc").style.display = "none";
    loadTasks().then(renderWatchdogPanel);
    $("count").textContent = t("chip_watchdog");
    return;
  }
  if (filter === "manage") {
    $("svc").style.display = "none";
    loadManage();
    $("count").textContent = t("chip_manage");
    return;
  }
  $("svc").style.display = "";
  $("tasks").hidden = true;
  const tbody = $("svc").querySelector("tbody");
  tbody.innerHTML = shown.length ? shown.map(e => row(e, isMobile())).join("") :
    '<tr><td class="empty" colspan="6">' + t("no_match") + '</td></tr>';
  $("count").textContent = shown.length;
  fillCtl(); // 服务表行尾 暂停/继续 按钮状态
}

function renderSys(s) {
  const fmtBytes = (b) => b ? ((b / 1073741824 >= 100 ? (b / 1073741824).toFixed(0) : (b / 1073741824).toFixed(1)) + " G") : "—";
  const fmtUp = (sec) => {
    if (!sec) return "—";
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    if (d) return t("day_hour", { d, h });
    if (h) return t("hour_min", { h, m });
    return t("minute", { m });
  };
  const mem = s.mem || {}, disk = s.disk || {};
  const SYS_ICONS = { load: "load", cpu: "cpu", mem: "mem", disk: "disk", up: "clock" };
  const cards = [
    ["load", t("sys_load"), (s.loadavg || []).join(" / ") || "—"],
    ["cpu", "CPU", `${s.cpu_usage}% · ${s.cpu_count} ${t("unit_core")}`],
    ["mem", t("sys_mem"), `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)} (${mem.percent || 0}%)`],
    ["disk", t("sys_disk"), `${fmtBytes(disk.used)} / ${fmtBytes(disk.total)} (${disk.percent || 0}%)`],
    ["up", t("sys_up"), fmtUp(s.uptime)],
  ];
  $("sysbar").innerHTML = cards.map(([k, l, v]) =>
    `<div class='stat' data-k='${k}'><div class='label'><span class='lb-ico'>${icon(SYS_ICONS[k] || "dot", 13)}</span>${l}</div><div class='value'>${v}</div></div>`).join("");
  renderLoadline(s);
  chartSample(s); // 手机端趋势图采样(桌面 no-op)
}

// 负载水位线 + top 进程(/api/sys 刷新时同步更新;与后端 render_loadline 同构)
function renderLoadline(s) {
  const el = $("loadline");
  if (!el || !s.goalload) return;
  const gl = s.goalload, esc = (x) => String(x ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const zone = gl.zone || "none";
  const msg = zone === "ok" ? t("ld_ok", { n: gl.n }) : zone === "full" ? t("ld_full") : zone === "over" ? t("ld_over") : "—";
  const [ico, color] = zone === "ok" ? ["dot", "var(--c-green)"] : zone === "full" ? ["pause", "var(--c-warn)"] : zone === "over" ? ["err", "var(--c-red)"] : ["dot", "var(--c-gray)"];
  const sub = t("ld_load", { l: gl.load15 != null ? gl.load15.toFixed(1) : "—", c: gl.cores ?? "?" });
  const rows = (items, fmt) => (items || []).length
    ? items.map(([v, k]) => `<div class='ld-row'><span class='ld-val'>${fmt(v)}</span><span class='ld-name'>${esc(k)}</span></div>`).join("")
    : `<div class='ld-row' style='color:var(--text-dead)'>—</div>`;
  el.innerHTML = `<div class='ld-head'><span class='ld-ico' style='color:${color}'>${icon(ico, 14)}</span><b>${t("ld_title")}</b>：${msg}` +
    `<span class='ld-sub'>（${sub}）</span></div><div class='ld-tops'>` +
    `<div class='ld-top'><div class='ld-t'>${t("ld_cpu")}</div>${rows(gl.cpu_top, v => v.toFixed(0) + "%")}</div>` +
    `<div class='ld-top'><div class='ld-t'>${t("ld_mem")}</div>${rows(gl.mem_top, v => v >= 1024 ? (v / 1024).toFixed(1) + "G" : v.toFixed(0) + "M")}</div></div>`;
}

// 快捷工具入口 chips: 端口存活才显示,点击直达(随 /api 刷新)
const TOOL_LINKS = [["dbeditor", 8810], ["dbviewer", 8800], ["wilviewer", 8765], ["mapviewer", 8899]];
function renderToolchips() {
  const el = $("toolchips");
  if (!el) return;
  const ports = new Set(services.map(s => s.port));
  const chips = TOOL_LINKS.filter(([n, p]) => ports.has(p)).map(([n, p]) =>
    `<a class='chip tchip' href='http://${linkHost(location.hostname)}:${p}/' target='_blank' rel='noopener'>${n} :${p} ${icon("ext", 11)}</a>`).join("");
  el.innerHTML = chips;
  el.style.display = chips ? "" : "none";
}

// 复制 resume 命令(http 非安全上下文走 execCommand 降级)
function fallbackCopy(txt, done) {
  const ta = document.createElement("textarea");
  ta.value = txt; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } catch (e) { /* 忽略 */ }
  ta.remove();
}
document.addEventListener("click", (e) => {
  const b = e.target.closest(".gcopy, .swipe-act");
  if (!b) return;
  const txt = b.dataset.cmd || b.dataset.copy || "";
  const done = () => {
    const old = b.innerHTML; b.innerHTML = icon("ok", 12) + " " + t("g_copied");
    haptic(12);
    setTimeout(() => b.innerHTML = old, 1600);
  };
  if (navigator.clipboard && window.isSecureContext)
    navigator.clipboard.writeText(txt).then(done).catch(() => fallbackCopy(txt, done));
  else fallbackCopy(txt, done);
});

const TYPE_BADGE = {
  watchdog: [t("tbd_wd"), "tbadge wd"],
  reminder: [t("tbd_rd"), "tbadge rd"],
  scheduled: [t("tbd_sc"), "tbadge sc"],
};
const TASK_COLS = ["name", "schedule", "scope", "command"];

function taskRow(x) {
  const [label, cls] = TYPE_BADGE[x.type] || [t("tbd_sc"), "tbadge sc"];
  const esc = (s) => s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const next = x.next ? new Date(x.next * 1000).toLocaleString() : (x.last ? t("t_last") + new Date(x.last * 1000).toLocaleString() : "—");
  return `<tr>
    <td><span class='${cls}'>${label}</span><span class='tname'>${esc(x.name)}</span></td>
    <td class='tsch' data-label='${t("t_cycle")}'>${esc(x.schedule)}</td>
    <td class='tscope' data-label='${t("t_source")}'>${x.kind === "timer" ? "systemd" : "cron"} · ${x.scope === "user" ? t("t_scope_user") : t("t_scope_sys")}</td>
    <td class='tcmd' data-label='${t("t_cmd")}'>${esc(x.command)}</td>
    <td class='tnext' data-label='${t("t_lastrun")}'>${esc(next)}</td>
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
  const labels = {running:t("a_running"), blocked:t("a_blocked"), idle:t("a_idle"), completed:t("a_done")};
  let rows = "";
  // OMP agents
  agents.omp.forEach(x => {
    rows += "<tr><td><span class='tbadge wd'>OMP</span><span class='tname tlink' data-sid='" + esc(x.id) +
      "' data-cwd='" + esc(x.cwd) + "' data-tmux='" + esc(x.tmux) + "' title='" + t("a_openlog", { g: esc(x.goal) }) + "'>" +
      esc((x.goal || x.cwd).slice(0, 60)) + "</span></td><td data-label='" + t("a_status") + "'>" + (labels[x.health] || esc(x.status)) +
      "</td><td class='tscope' data-label='" + t("a_loc") + "'>" + esc(x.tmux) + "<br>" + esc(x.cwd) + "</td><td class='tsch' data-label='" + t("a_active") + "'>" +
      esc(x.last_activity) + "<br>" + t("a_ago", { s: x.idle_seconds }) + "</td><td class='tcmd' data-label='" + t("a_tool") + "'>" + esc(x.tool) + "</td></tr>";
  });
  // Codex agents
  agents.codex.forEach(x => {
    rows += "<tr><td><span class='tbadge rd'>Codex</span><span class='tname tlink' data-sid='' data-cwd='" +
      esc(x.cwd) + "' data-tmux='' title='" + t("a_openterm", { p: esc(x.pid) }) + "'>" +
      esc(x.cwd) + "</span></td><td data-label='" + t("a_status") + "'>" + t("a_running") + "</td><td class='tscope' data-label='" + t("a_loc") + "'>—<br>" + esc(x.cwd) + "</td><td class='tsch' data-label='" + t("a_active") + "'>" +
      esc(x.last_activity) + "<br>" + t("a_ago", { s: x.idle_seconds }) + "</td><td class='tcmd' data-label='" + t("a_tool") + "'>pid " + esc(x.pid) + "</td></tr>";
  });
  const total = agents.omp.length + agents.codex.length;
  el.innerHTML = "<h2>" + t("a_title") + " <span style='color:var(--text-dead);font-weight:400'>" + t("a_hint", { n: total }) + "</span></h2><table><thead><tr><th>" + t("a_th_agent") + "</th><th>" + t("a_status") + "</th><th>" + t("a_loc") + "</th><th>" + t("a_active") + "</th><th>" + t("a_tool") + "</th></tr></thead><tbody>" +
    (rows || "<tr><td class='empty' colspan='5'>" + t("a_none") + "</td></tr>") + "</tbody></table>";
  el.querySelectorAll(".tlink").forEach(a => a.addEventListener("click", () => toggleAgentLog(a)));
}

async function fetchAgentLog(sid, cwd, tmx) {
  const r = await fetch("/api/agentlog?sid=" + encodeURIComponent(sid) + "&cwd=" + encodeURIComponent(cwd) + "&tmux=" + encodeURIComponent(tmx) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
  return r.json();
}
function agentLogHtml(d) {
  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  let html = "<div class='agentlog'>";
  if ((d.events || []).length) {
    html += "<div class='aglog-title'>" + t("a_recent") + " <span class='aglog-refresh' role='button' tabindex='0'>" + t("refresh") + "</span></div><div class='aglog-list'>" +
      d.events.map(e => "<div class='aglog-row'><span class='aglog-ts'>" + esc(e[0]) + "</span><span class='aglog-txt'>" + esc(e[1]) + "</span></div>").join("") + "</div>";
  }
  if (d.capture && d.capture.length) {
    html += "<div class='aglog-title'>" + t("a_term") + " <span class='aglog-refresh' role='button' tabindex='0'>" + t("refresh") + "</span></div><pre class='termlog'>" +
      d.capture.map(l => esc(l)).join("\\n") + "</pre>";
  }
  if (!(d.events || []).length && !d.capture) html += "<div class='aglog-empty'>" + t("a_nolog") + "</div>";
  return html + "</div>";
}
async function loadAgentLog(a, det) {
  const cell = det.querySelector("td");
  cell.innerHTML = "<div class='agentlog'>" + t("a_loading") + "</div>";
  try {
    const d = await fetchAgentLog(a.dataset.sid || "", a.dataset.cwd || "", a.dataset.tmux || "");
    det.className = "agent-detail";
    cell.innerHTML = agentLogHtml(d);
    det.querySelectorAll(".aglog-refresh").forEach(b => b.addEventListener("click", () => loadAgentLog(a, det)));
  } catch (err) {
    const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
    det.className = "agent-detail";
    cell.innerHTML = "<div class='agentlog aglog-empty'>" + t("a_fail", { e: esc(err.message) }) + "</div>";
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
  det.innerHTML = "<td colspan='5'><div class='agentlog'>" + t("a_loading") + "</div></td>";
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
    (x.active ? " <span class='tbadge wd'>" + t("tmux_active") + "</span>" : "") + "</td><td data-label='" + t("t_cmd") + "'>" + esc(x.command) +
    "</td><td class='tscope' data-label='" + t("tmux_th_title") + "'>" + esc(x.title) + "</td><td class='tcmd' data-label='" + t("th_cwd") + "'>" + esc(x.cwd) +
    "</td><td class='tsch' data-label='" + t("tmux_th_size") + "'>" + esc(x.size) + "</td></tr>").join("");
  el.innerHTML = "<h2>" + t("tmux_panel") + " <span style='color:var(--text-dead);font-weight:400'>" + t("tmux_panes", { n: panes.length }) +
    "</span></h2><table><thead><tr><th>" + t("tmux_th_pane") + "</th><th>" + t("t_cmd") + "</th><th>" + t("tmux_th_title") + "</th><th>" + t("th_cwd") + "</th><th>" + t("tmux_th_size") + "</th></tr></thead><tbody>" +
    (rows || "<tr><td class='empty' colspan='5'>" + t("tmux_none") + "</td></tr>") + "</tbody></table>";
}

let tasksCache = null; // 懒加载缓存

async function loadTasks() {
  if (tasksCache) return tasksCache;
  try {
    const r = await fetch("/api/tasks?lang=" + encodeURIComponent(LANG), { cache: "no-store" });
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
  el.innerHTML = `<h2>${t("panel_watchdog")}
    <span style='color:var(--ch-mem)'>${nwd} ${t("tbd_wd")}</span> ·
    <span style='color:var(--ch-cpu)'>${nrd} ${t("tbd_rd")}</span> ·
    <span style='color:var(--text-dim)'>${nsc} ${t("tbd_sc")}</span> ·
    <span style='color:var(--text-dead);font-weight:400'>${t("t_total", { n: tasks.length })}</span></h2>
    <table><thead><tr><th>${t("t_task")}</th><th>${t("t_cycle")}</th><th>${t("t_source")}</th><th>${t("t_cmd")}</th><th>${t("t_lastrun")}</th></tr></thead>
    <tbody>${tasks.length ? tasks.map(taskRow).join("") : "<tr><td class='empty' colspan='5'>" + t("t_none") + "</td></tr>"}</tbody></table>`;
}

// ---------------------------------------------------------------- 服务管理
// 管理本机关键 systemd 单元(zircon-server / zircon-bots / tailscaled)与
// 手动进程服务(wilviewer / mapviewer): 启动 / 停止 / 重启 / 暂停 / 恢复。
// systemd 单元: 暂停=SIGSTOP 挂起;手动进程: 暂停=终止进程,启用=重新拉起。
// 所有操作都需确认。dashboard 自身(80)不在列表,不可操作。
const MANAGE_UNITS = [
  { id: "zircon-server", kind: "systemd", label: t("m_server"), desc: t("m_server_desc") },
  { id: "zircon-bots", kind: "systemd", label: t("m_bots"), desc: t("m_bots_desc") },
  { id: "tailscaled", kind: "systemd", label: t("m_ts"), desc: t("m_ts_desc") },
  { id: "wilviewer", kind: "proc", port: 8765, label: t("m_wilviewer"), desc: t("m_wilviewer_desc") },
  { id: "mapviewer", kind: "proc", port: 8899, label: t("m_mapviewer"), desc: t("m_mapviewer_desc") },
];
const MANAGE_LABELS = { start: t("m_start"), stop: t("m_stop"), restart: t("m_restart"), pause: t("m_pause"), resume: t("m_resume") };

// 端口 -> 受管手动进程服务 id(服务表行尾按钮用)
const MANAGE_PROC_BY_PORT = {};
MANAGE_UNITS.filter(u => u.kind === "proc").forEach(u => MANAGE_PROC_BY_PORT[u.port] = u.id);

// 服务表行尾的 暂停/继续 按钮: 查状态填充文案,点击执行动作。
async function fillCtl() {
  const btns = document.querySelectorAll(".ctl-btn");
  await Promise.all([...btns].map(async (b) => {
    const uid = b.dataset.ctl;
    b.setAttribute("aria-disabled", "true");
    try {
      const r = await fetch("/api/manage?unit=" + encodeURIComponent(uid) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
      const st = await r.json();
      const running = st && st.ok && st.active === "active";
      b.textContent = running ? t("ctl_pause") : t("ctl_resume");
      b.dataset.action = running ? "stop" : "start";
      b.setAttribute("aria-disabled", "false");
    } catch (e) {
      b.innerHTML = icon("err", 13);
      b.title = e.message;
    }
  }));
  document.querySelectorAll(".ctl-btn").forEach(b =>
    b.addEventListener("click", () => doCtl(b)));
}

async function doCtl(btn) {
  const uid = btn.dataset.ctl, action = btn.dataset.action;
  if (!confirm(t("m_confirm", { label: MANAGE_LABELS[action] || action, unit: uid }))) return;
  btn.setAttribute("aria-disabled", "true");
  btn.textContent = t("m_doing");
  try {
    const r = await fetch("/api/manage?lang=" + encodeURIComponent(LANG), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ unit: uid, action }),
    });
    const d = await r.json();
    btn.innerHTML = icon(d.ok ? "ok" : "err", 13) + " " + escHtml(d.msg || "");
    btn.title = d.msg || "";
    setTimeout(() => { load(true); fillCtl(); }, 800); // 刷新状态
  } catch (e) {
    btn.innerHTML = icon("err", 13);
    btn.title = e.message;
  }
}

function manageCard(u, st, result) {
  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const ok = st && st.ok;
  const active = ok && st.active === "active";
  const stopped = ok && st.stopped;
  const color = !ok ? "var(--c-gray)" : (stopped ? "var(--c-warn)" : (active ? "var(--c-green)" : "var(--c-red)"));
  const stateTxt = !ok ? (st && st.msg ? st.msg : t("m_state_fail"))
    : (stopped ? t("m_paused") : (active ? st.sub : st.active));
  const pid = ok && st.pid && st.pid !== "0" ? " · PID " + esc(st.pid) : "";
  const isProc = u.kind === "proc";
  let btns = "";
  if (active) {
    // 手动进程: 暂停=终止进程;systemd: 停止/暂停(SIGSTOP)分开
    if (isProc) {
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='stop' role='button' tabindex='0' title='${t("m_title_stop")}'>${icon("pause", 13)} ${t("m_pause")}</span>`;
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='restart' role='button' tabindex='0' title='${t("m_title_restart")}'>${icon("refresh", 13)} ${t("m_restart")}</span>`;
    } else {
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='stop' role='button' tabindex='0' title='${t("m_title_stop")}'>${icon("stop", 13)} ${t("m_stop")}</span>`;
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='restart' role='button' tabindex='0' title='${t("m_title_restart")}'>${icon("refresh", 13)} ${t("m_restart")}</span>`;
      btns += stopped
        ? `<span class='mbtn' data-unit='${u.id}' data-action='resume' role='button' tabindex='0' title='${t("m_title_resume")}'>${icon("play", 13)} ${t("m_resume")}</span>`
        : `<span class='mbtn' data-unit='${u.id}' data-action='pause' role='button' tabindex='0' title='${t("m_title_pause")}'>${icon("pause", 13)} ${t("m_pause")}</span>`;
    }
  } else if (ok) {
    btns += `<span class='mbtn' data-unit='${u.id}' data-action='start' role='button' tabindex='0' title='${t("m_title_start")}'>${icon("play", 13)} ${isProc ? t("m_enable") : t("m_start")}</span>`;
  }
  const res = result ? `<div class='mresult'>${esc(result)}</div>` : "<div class='mresult'></div>";
  return `<div class='mcard' data-unit='${u.id}'>
    <div class='mhead'><span class='mname'>${esc(u.label)}</span><span class='mdesc'>${esc(u.desc)}</span></div>
    <div class='mstate'><span class='mdot' style='background:${color}'></span> ${esc(stateTxt)}${pid}</div>
    <div class='mbtns'>${btns}</div>
    ${res}
  </div>`;
}

async function loadManage() {
  const el = $("tasks");
  if (filter !== "manage") { el.hidden = true; return; }
  el.hidden = false;
  el.className = "watchdog-panel";
  // 记住各卡片的操作结果,面板重建(轮询/动作后刷新)时保留
  const prevResults = {};
  el.querySelectorAll(".mcard").forEach(c => {
    const r = c.querySelector(".mresult");
    if (r && r.textContent) prevResults[c.dataset.unit] = r.textContent;
  });
  const cards = await Promise.all(MANAGE_UNITS.map(async (u) => {
    let st = null;
    try {
      const r = await fetch("/api/manage?unit=" + encodeURIComponent(u.id) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
      st = await r.json();
    } catch (e) { st = null; }
    return manageCard(u, st, prevResults[u.id] || "");
  }));
  el.innerHTML = `<h2>${t("m_panel")} <span style='color:var(--text-dead);font-weight:400'>${t("m_hint")}</span></h2>
    <div class='mgrid'>${cards.join("")}</div>`;
  el.querySelectorAll(".mbtn").forEach(b => b.addEventListener("click", () => doManage(b)));
}

async function doManage(btn) {
  const unit = btn.dataset.unit, action = btn.dataset.action;
  const label = MANAGE_LABELS[action] || action;
  if (!confirm(t("m_confirm", { label, unit }))) return;
  btn.setAttribute("aria-disabled", "true");
  const res = btn.closest(".mcard").querySelector(".mresult");
  res.textContent = t("m_doing");
  try {
    const r = await fetch("/api/manage?lang=" + encodeURIComponent(LANG), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ unit, action }),
    });
    const d = await r.json();
    res.innerHTML = icon(d.ok ? "ok" : "err", 13) + " " + escHtml(d.msg || "");
    res.style.color = d.ok ? "var(--c-green)" : "var(--c-red)";
  } catch (e) {
    res.innerHTML = icon("err", 13) + " " + escHtml(e.message);
    res.style.color = "var(--c-red)";
  }
  btn.setAttribute("aria-disabled", "false");
  setTimeout(() => loadManage(), 600); // 等 systemd 状态落地再刷新
}

async function load(alsoSys) {
  const btn = $("refresh");
  btn.classList.add("spinning");
  btn.setAttribute("aria-disabled", "true");
  ompCache = null; tasksCache = null; tmuxCache = null; // 手动刷新清面板缓存,拿到最新 agent/tmux/任务状态
  try {
    const r = await fetch("/api", { cache: "no-store" });
    const data = await r.json();
    $("updated").textContent = new Date(data.updated * 1000).toLocaleString();
    lastUpdatedTs = data.updated * 1000;
    services = data.services;
    renderToolchips();
    applyFilter();
    renderOverview(data);          // 概要摘要(状态卡/指标/需要处理/最近活动)
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
  btn.setAttribute("aria-disabled", "false");
}

/* ================================================================
   概要摘要 + 告警中心(轻量) + 日志时间线 —— 移动端概要/日志页的数据层。
   桌面端 renderOverview 直接返回,布局零变化。
   /api/goals 15s 缓存,概要与日志页共用。 */
let lastUpdatedTs = Date.now();
let goalsCache = { t: 0, data: null };
const LOG_LIMIT = 60;

async function fetchGoalsData(force) {
  const now = Date.now();
  if (!force && goalsCache.data && now - goalsCache.t < 15000) return goalsCache.data;
  try {
    const r = await fetch("/api/goals?limit=" + LOG_LIMIT + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
    const d = await r.json();
    if (d && d.updated) lastUpdatedTs = Math.max(lastUpdatedTs, d.updated * 1000);
    goalsCache = { t: now, data: d };
  } catch (err) { console.error("goals refresh failed", err); }
  return goalsCache.data;
}

function agoStr(sec) {
  if (sec == null) return "—";
  sec = Math.max(0, sec);
  if (sec < 60) return t("g_ago_s", { s: Math.round(sec) });
  if (sec < 3600) return t("g_ago_m", { m: Math.floor(sec / 60) });
  if (sec < 86400) return t("g_ago_h", { h: Math.floor(sec / 3600) });
  return t("g_ago_d", { d: Math.floor(sec / 86400) });
}
function agoFromTs(ts) { return agoStr((Date.now() - ts * 1000) / 1000); }

// --- 事件类型元数据: 图标(双通道) + 语义组(ok/warn/fail/recover) ---
const EV_META = {
  complete: { ico: "ok", grp: "ok", key: "evk_complete" },
  recover:  { ico: "up", grp: "recover", key: "evk_recover" },
  restart:  { ico: "retry", grp: "fail", key: "evk_restart" },
  nudge:    { ico: "bell", grp: "warn", key: "evk_nudge" },
  pause:    { ico: "⏸", grp: "warn", key: "evk_pause" },
  cleanup:  { ico: "trash", grp: "ok", key: "evk_cleanup" },
  commit:   { ico: "box", grp: "ok", key: "evk_commit" },
  other:    { ico: "·", grp: "ok", key: "evk_other" },
};

// --- 告警(需要处理): 忽略记录存 localStorage(同 goal+类型不再提醒) ---
const IGN_KEY = "svc-ignored-alerts";
function ignoredSet() { try { return new Set(JSON.parse(localStorage.getItem(IGN_KEY) || "[]")); } catch (e) { return new Set(); } }
function addIgnore(key) {
  const s = ignoredSet(); s.add(key);
  try { localStorage.setItem(IGN_KEY, JSON.stringify([...s])); } catch (e) {}
}
function goalAlerts(goals) {
  const out = [];
  (goals || []).forEach(g => {
    const id = g.gid || g.session || g.name;
    const sub = g.idle_sec != null ? t("g_last") + ": " + agoStr(g.idle_sec) : "";
    let a = null;
    if (g.light === "paused") a = { sev: "warn", key: "paused|" + id, icon: ["pause", "t-warn"], msg: t("al_paused") };
    else if (g.light === "lost") a = { sev: "bad", key: "lost|" + id, icon: ["warn", "t-red"], msg: t("al_lost") };
    else if (g.light === "done") a = { sev: "done", key: "done|" + id, icon: ["ok", "t-green"], msg: t("al_done") };
    else if (g.stalled) a = { sev: "warn", key: "stalled|" + id, icon: ["clock", "t-warn"], msg: t("al_stalled") };
    else if (g.light === "retry") a = { sev: "warn", key: "retry|" + id, icon: ["retry", "t-warn"], msg: t("g_retry") };
    if (a) out.push({ sev: a.sev, key: a.key, icon: a.icon, msg: a.msg,
                      name: g.name || g.session || "—", sub: sub, cmd: g.resume_cmd || "" });
  });
  return out;
}
function renderAlerts(alerts) {
  const el = $("alert-body");
  if (!el) return;
  if (!alerts.length) { el.innerHTML = `<div class="gempty">${t("al_none")}</div>`; return; }
  el.innerHTML = alerts.map(a => `
    <div class="alert-item" data-key="${escAttr(a.key)}">
      <span class="al-ico ${a.icon[1]}">${icon(a.icon[0], 15)}</span>
      <div class="al-main">
        <div class="al-line"><span class="al-name">${escHtml(a.name)}</span><span class="al-msg">${escHtml(a.msg)}</span></div>
        ${a.sub ? `<div class="al-sub">${escHtml(a.sub)}</div>` : ""}
      </div>
      <div class="al-act">
        ${a.cmd ? `<span class="al-btn gcopy" data-cmd="${escAttr(a.cmd)}" role="button" tabindex="0" title="${escAttr(a.cmd)}">${icon("copy", 13)}</span>` : ""}
        <span class="al-btn detail" role="button" tabindex="0">${t("al_detail")}</span>
        <span class="al-btn ignore" role="button" tabindex="0">${t("al_ignore")}</span>
      </div>
    </div>`).join("");
}

let lastSvc = { ok: 0, total: 0 };
async function renderOverview(apiData) {
  if (!isMobile()) return;
  if (apiData && apiData.services) {
    lastSvc = { ok: apiData.services.filter(s => !s.paused).length, total: apiData.services.length };
  }
  const d = await fetchGoalsData();
  const goals = (d && d.goals) || [];
  const events = (d && d.events) || [];
  const alerts = goalAlerts(goals).filter(a => !ignoredSet().has(a.key));
  const nRun = goals.filter(g => g.light === "active" || g.light === "retry").length;
  const nBad = goals.filter(g => g.light === "paused" || g.light === "lost" || g.stalled).length;
  const nAlert = alerts.length;
  // 总体状态: 图标+文字双通道; 红=有严重(会话丢失) 黄=有告警 绿=全部正常
  const ok = nAlert === 0;
  const cls = ok ? "ok" : alerts.some(a => a.sev === "bad") ? "bad" : "warn";
  const txt = ok ? t("st_all_ok") : t("st_alert", { n: nAlert });
  const ico = ok ? "ok" : "warn";
  const sc = $("statuscard"), sl = $("statusline"); // sl 可为 null(已移除)
  if (sc) { sc.className = "statuscard " + cls; $("sc-ico").innerHTML = icon(ico, 28); $("sc-text").textContent = txt; }
  if (sl) { sl.className = "statusline " + cls; const si = $("status-ico"); if (si) si.innerHTML = icon(ico, 16); const st = $("status-text"); if (st) st.textContent = txt; }
  $("m-svc").textContent = lastSvc.ok + "/" + lastSvc.total;
  $("m-run").textContent = nRun;
  $("m-bad").textContent = nBad;
  $("m-bad").classList.toggle("alert", nBad > 0);
  $("m-alert").textContent = nAlert;
  $("m-alert").classList.toggle("alert", nAlert > 0);
  renderAlerts(alerts);
  // 最近活动: 3-5 条摘要(一行一条), 点击进日志页
  const recent = events.slice(0, 5);
  $("recent-body").innerHTML = recent.length ? recent.map(e => {
    const m = EV_META[e.kind] || EV_META.other;
    return `<div class="rc-row" role="button" tabindex="0"><span class="rc-ico">${icon(m.ico, 14)}</span>` +
      `<span class="rc-kind">${escHtml(t(m.key))} · <b class="rc-name">${escHtml(e.name)}</b></span>` +
      `<span class="rc-ago">${escHtml(agoFromTs(e.ts))}</span></div>`;
  }).join("") : `<div class="gempty">${t("ev_none")}</div>`;
  updateBadge(nAlert);
  refreshFreshness();
}
function updateBadge(n) {
  const b = $("tab-alert-badge");
  if (!b) return;
  b.hidden = !n;
  b.textContent = n > 99 ? "99+" : String(n);
}
function refreshFreshness() {
  const age = Date.now() - lastUpdatedTs;
  const stale = age > 2 * autoSec * 1000;   // 超过 2× 刷新周期 → 数据过期
  const h = $("stale-badge"), s = $("sc-stale");
const staleHtml = icon("warn", 12) + " " + t("st_stale");
  if (h) { h.hidden = !stale; h.innerHTML = staleHtml; }
  if (s) { s.hidden = !stale; s.innerHTML = staleHtml; }
  const f = $("sc-fresh");
  if (f) f.textContent = t("g_last") + ": " + agoStr(age / 1000);
}
setInterval(() => { if (!document.hidden) refreshFreshness(); }, 20000);

// 概要页交互: 状态卡→Goal页 / 状态栏→回概要 / 最近活动→日志页 / 告警操作
$("statuscard").addEventListener("click", () => setPage(2));
const statuslineEl = $("statusline");   // header 状态栏已移除(85102dc), 此处判空防崩
if (statuslineEl) statuslineEl.addEventListener("click", () => {
  setPage(0);
  const m = document.querySelector("main");
  if (m) m.scrollTo({ top: 0 });
});
const rcMore = document.querySelector(".rc-more");
if (rcMore) rcMore.addEventListener("click", () => setPage(1));
$("recent-body").addEventListener("click", () => setPage(1));
document.addEventListener("click", (e) => {
  const it = e.target.closest(".alert-item");
  if (!it) return;
  if (e.target.closest(".gcopy")) return;            // 复制 resume 命令: 交给全局 gcopy
  if (e.target.closest(".ignore")) {                 // 忽略: localStorage 记住, 同 goal+类型不再提醒
    addIgnore(it.dataset.key);
    haptic(8);
    renderOverview(null);
    return;
  }
  if (e.target.closest(".detail")) setPage(2);
});

// --- 日志页: 全局事件时间线(筛选 chips + 同goal循环折叠 + 详情默认折叠) ---
const logFilter = { st: "all", src: "all", hrs: 24 };
function filterEvents(evs) {
  const now = Date.now() / 1000;
  return (evs || []).filter(e => {
    if (logFilter.hrs && e.ts < now - logFilter.hrs * 3600) return false;
    if (logFilter.src === "commit") { if (e.kind !== "commit") return false; }
    else if (logFilter.src !== "all" && e.src !== logFilter.src) return false;
    if (logFilter.st !== "all" && (EV_META[e.kind] || EV_META.other).grp !== logFilter.st) return false;
    return true;
  });
}
function lvHead(e, extra) {
  const m = EV_META[e.kind] || EV_META.other;
  return `<div class="lv-line1"><span class="lv-ico">${icon(m.ico, 14)}</span>` +
    `<span class="lv-kind">${escHtml(t(m.key))}</span>` +
    `<span class="rc-name">${escHtml(e.name)}</span>${extra || ""}` +
    `<span class="lv-ago">${escHtml(agoFromTs(e.ts))}</span></div>`;
}
function evSummary(e) { return e.src === "done" ? String(e.text).split("/").pop() : e.text; }
async function renderLogTimeline() {
  const body = $("logbody");
  if (!body || !isMobile()) return;
  body.innerHTML = `<div class="gempty">${t("a_loading")}</div>`;
  const d = await fetchGoalsData();
  const evs = filterEvents(d && d.events);
  if (!evs.length) { body.innerHTML = `<div class="gempty">${t("ev_empty")}</div>`; return; }
  // 同 goal 同类事件连续 >=3 条 → 折叠「循环 ×N」(019feb87 类刷屏降噪)
  const groups = [];
  evs.forEach(e => {
    const key = e.gid + "|" + e.kind;
    const g = groups[groups.length - 1];
    if (g && g.key === key) g.items.push(e);
    else groups.push({ key, items: [e] });
  });
  let html = "";
  groups.forEach(g => {
    const head = g.items[0];
    if (g.items.length >= 3) {
      html += `<div class="lv">${lvHead(head, `<span class="lv-loop">${t("ev_loop", { n: g.items.length })}</span>`)}` +
        `<div class="lv-line2">${escHtml(evSummary(head))}</div>` +
        `<span class="lv-fold" role="button" tabindex="0">${t("g_detail")}</span>` +
        `<div class="lv-meta">${g.items.map(x => escHtml(x.time + " · " + x.gid + " · " + x.text)).join("<br>")}</div>` +
        `<div class="lv-children">${g.items.slice(0, 12).map(x =>
          lvHead(x) + `<div class="lv-line2">${escHtml(evSummary(x))}</div>`).join("")}` +
        `${g.items.length > 12 ? `<div class="lv-more">… ${g.items.length - 12}</div>` : ""}</div></div>`;
    } else {
      html += g.items.map(e => `<div class="lv">${lvHead(e)}` +
        `<div class="lv-line2">${escHtml(evSummary(e))}</div>` +
        `<span class="lv-fold" role="button" tabindex="0">${t("g_detail")}</span>` +
        `<div class="lv-meta">${escHtml(e.time)} · ${escHtml(e.gid)} · ${escHtml(e.src)}<br>${escHtml(e.text)}</div></div>`).join("");
    }
  });
  body.innerHTML = html;
}
// 日志条目点按: 展开/收起折叠详情(PID/文件名/原始文本默认折叠)
document.addEventListener("click", (e) => {
  const lv = e.target.closest("#logbody .lv");
  if (lv) lv.classList.toggle("open");
});
// 日志筛选 chips: 状态 / 来源 / 时间(默认 24h)
document.querySelectorAll("#log-filters .chip").forEach(c => c.addEventListener("click", () => {
  const attr = c.dataset.lf !== undefined ? "lf" : c.dataset.ls !== undefined ? "ls" : "lt";
  if (attr === "lf") logFilter.st = c.dataset.lf;
  else if (attr === "ls") logFilter.src = c.dataset.ls;
  else logFilter.hrs = +c.dataset.lt;
  document.querySelectorAll(`#log-filters .chip[data-${attr}]`).forEach(x =>
    x.classList.toggle("active", x === c));
  haptic(6);
  renderLogTimeline();
}));

// 仅触摸设备启用：页面顶端向下拖动时复用现有手动刷新入口 load(true)。
(function setupPullToRefresh() {
  const touchCapable = ("ontouchstart" in window) || navigator.maxTouchPoints > 0;
  if (!touchCapable) return;
  const indicator = $("ptr-indicator");
  const arrow = indicator.querySelector(".ptr-arrow");
  const label = indicator.querySelector(".ptr-label");
  const threshold = 70;
  let startY = 0, pull = 0, rawDistance = 0, tracking = false, refreshing = false;
  const setPull = (distance) => {
    rawDistance = Math.max(0, distance);
    pull = Math.min(110, rawDistance * 0.55);
    indicator.style.transform = `translateY(${pull}px)`;
    arrow.style.transform = `rotate(${Math.min(180, rawDistance / threshold * 180)}deg)`;
    const ready = rawDistance >= threshold;
    indicator.classList.toggle("ready", ready);
    label.textContent = t(ready ? "ptr_release" : "ptr_pull");
  };
  // 内部滚动布局: 判断「页面已滚下」要看 main 滚动容器, 不再是 window
  const mainScroller = document.querySelector("main");
  const pageScrolled = () => (mainScroller && mainScroller.scrollTop > 0) || window.scrollY > 0;
  document.addEventListener("touchstart", (e) => {
    if (refreshing || e.touches.length !== 1 || pageScrolled()) return;
    startY = e.touches[0].clientY;
    tracking = true;
  }, { passive: true });
  document.addEventListener("touchmove", (e) => {
    if (!tracking || refreshing || pageScrolled()) return;
    const distance = e.touches[0].clientY - startY;
    if (distance <= 0) { tracking = false; setPull(0); return; }
    e.preventDefault();
    setPull(distance);
  }, { passive: false });
  document.addEventListener("touchend", async () => {
    if (!tracking) return;
    tracking = false;
    if (rawDistance < threshold) { setPull(0); return; }
    refreshing = true;
    indicator.classList.remove("ready");
    indicator.classList.add("loading");
    indicator.style.transform = "translateY(48px)";
    label.textContent = t("ptr_loading");
    console.log("[svc-dashboard] pull-to-refresh: load(true)");
    try { await load(true); }
    finally {
      refreshing = false;
      indicator.classList.remove("loading");
      setPull(0);
      haptic(10); // 刷新完成触觉反馈
      console.log("[svc-dashboard] pull-to-refresh done, haptic(10)");
    }
  }, { passive: true });
})();

document.querySelectorAll("#filters .chip").forEach(c =>
  c.addEventListener("click", () => { filter = c.dataset.f; applyFilter(); }));
document.querySelectorAll(".tcol").forEach(b =>
  b.addEventListener("click", () => {
    $("svc").dataset.col = b.dataset.col;
    document.querySelectorAll(".tcol").forEach(x =>
      x.classList.toggle("active", x === b));
  }));
$("refresh").addEventListener("click", () => {
  if (refreshHoldDone) return;   // 长按已处理, 吞掉后续 click
  haptic(8);
  load(true);
});
// 长按(500ms)锁定/解锁自动刷新: 锁定时按钮变琥珀描边+锁形角标, 点击仍可手动刷新
let refreshHoldTimer = null, refreshHoldDone = false;
["pointerdown", "touchstart"].forEach(ev => $("refresh").addEventListener(ev, () => {
  refreshHoldDone = false;
  clearTimeout(refreshHoldTimer);
  refreshHoldTimer = setTimeout(() => {
    refreshHoldDone = true;
    autoLocked = !autoLocked;
    $("refresh").classList.toggle("locked", autoLocked);
    $("refresh").setAttribute("aria-pressed", autoLocked);
    haptic(15);
    themeToast(t(autoLocked ? "locked_toast" : "unlocked_toast"));
    console.log("[svc-dashboard] auto refresh " + (autoLocked ? "locked" : "unlocked"));
  }, 500);
}, { passive: true }));
["pointerup", "pointercancel", "touchend", "touchcancel", "pointerleave"].forEach(ev =>
  $("refresh").addEventListener(ev, () => clearTimeout(refreshHoldTimer), { passive: true }));
// 全局键盘委托: 所有 span[role=button] 控件支持 Enter/Space 触发
document.addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  const el = e.target.closest('[role="button"]');
  if (!el) return;
  e.preventDefault();
  el.click();
});

/* ================================================================
   移动 App 层(仅触摸设备): 分页滑动 / 底栏 / 列表手势 / 双击 /
   边缘返回 / 捏合图表 / 触觉反馈 / 轮询暂停。
   桌面端不注册任何触摸事件,行为零变化。 */
const TOUCH = ("ontouchstart" in window) || navigator.maxTouchPoints > 0;
const mqMobile = window.matchMedia("(max-width: 768px)");
const isMobile = () => mqMobile.matches;
const haptic = (ms) => { try { navigator.vibrate && navigator.vibrate(ms); } catch (e) {} };
// 触摸互斥: 一次触摸只属于一个手势(分页/滑动露按钮/边缘返回)
const gesture = { claimed: null };
// 移动端把各分区装进 6 个 .pg 页容器; 桌面端恢复原始 DOM 顺序(display:contents 布局)。
// 记住初始顺序, 窗口跨过 768px 断点时来回重组不丢内容。
const PAGE_GROUPS = [
  ["#statuscard", ".mgrid4", "#alerts", "#recent", "#sysbar", "#loadline", "#chart-wrap", "#toolchips"],
  ["#logpage"],
  ["#goals"],
  ["#filters", "#tasks", "#svc"],
  ["#agents-page"],
  ["#toolspage"],
];
let pagesHomeOrder = null, pgWrappers = null, trackEl = null;
function regroupPages() {
  if (!mqMobile.matches) {
    if (pagesHomeOrder) { // 桌面: 按原顺序放回 #pages, 撤掉轨道
      pagesHomeOrder.forEach(el => pages.appendChild(el));
      if (trackEl) { trackEl.remove(); trackEl = null; }
      pgWrappers = null;
    }
    return;
  }
  if (trackEl) return; // 已分组
  pagesHomeOrder = [...pages.children];
  trackEl = document.createElement("div");
  trackEl.id = "track";
  pgWrappers = PAGE_GROUPS.map((sels, i) => {
    const w = document.createElement("div");
    w.className = "pg";
    w.dataset.p = i;
    sels.forEach(s => { const el = document.querySelector(s); if (el) w.appendChild(el); });
    trackEl.appendChild(w);
    return w;
  });
  pages.appendChild(trackEl);
  // homeOrder 里可能残留未入组的元素(如 toolchips 为空串被后端去掉), 追加回第 1 页防丢
  pagesHomeOrder.forEach(el => { if (!el.isConnected) pgWrappers[0].appendChild(el); });
  // 每页高度跟随自身内容; 轨道高=当前页(scrollHeight 含每页自己的 padding-bottom 预留)
  pgWrappers.forEach(w => { w.style.height = "auto"; });
  applyPagesX(false);
}
mqMobile.addEventListener("change", () => { regroupPages(); drawChart(); });

// --- 分页(概览/日志/Goal/服务/模型/ツール) ---
const pages = $("pages");
const N_PAGES = 6;
const PAGE_W = 100 / N_PAGES;   // 轨道宽 600%, 每页位移 = 轨道的 1/6
var page = 0;   // var: 挂到 window, 便于外部调试/测试读取
function pageLabels() { return [t("tab_home"), t("tab_log"), t("tab_goal"), t("tab_svc"), t("tab_model"), t("tab_tools")]; }
function applyPagesX(withTransition) {
  const tr = trackEl; // 移动端才有轨道
  if (!tr) return;
  // 轨道宽 600%: 每页位移 = 轨道的 1/6
  tr.style.transform = `translate3d(${-page * PAGE_W}%,0,0)`;
  // 每页各自高度: 轨道高度跟随当前页内容(flex 容器默认拉伸到最高页 = 高页拖矮页)
  const cur = tr.children[page];
  if (cur) tr.style.height = cur.scrollHeight + "px";
  if (!withTransition) requestAnimationFrame(() => tr.classList.remove("stick"));
}
function setPage(i, opts) {
  i = Math.max(0, Math.min(N_PAGES - 1, i));
  const first = (opts && opts.first) === true;
  if (!first) {
    haptic(8);
    console.log("[svc-dashboard] page -> " + i + " " + pageLabels()[i]);
  }
  const changed = i !== page || first;
  page = i;
  applyPagesX(true);
  document.querySelectorAll("#tabbar .tab").forEach(b => b.classList.toggle("active", +b.dataset.p === i));
  if (changed) activatePage(i);
  // 页面内容异步变化后(骨架→数据/折叠展开)重测高度
  requestAnimationFrame(() => applyPagesX(false));
}
function activatePage(i) {
  if (i === 1) { initLogPage(); renderLogTimeline(); }  // 日志页: agent 选择器 + 事件时间线
  if (i === 4) initAgentsPage();     // 模型页: 拉取 OMP/Codex 卡片
  if (i === 5) initToolsPage();      // ツール页: 惰性初始化(健康/文件/清理/速测/服务/任务)
  if (i === 3 && isMobile()) {       // 服务页: 骨架 → 渲染
    const tbody = $("svc").querySelector("tbody");
    if (!tbody.children.length) tbody.innerHTML = mobileSkel(4);
    applyFilter();
  }
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("#tabbar .tab");
  if (b) { setPage(+b.dataset.p); return; }
});

// --- 骨架屏 ---
function mobileSkel(n) {
  let h = "";
  for (let i = 0; i < n; i++)
    h += `<tr class='skel'><td><div class='skel-line' style='width:86%'></div><div class='skel-line' style='width:64%'></div><div class='skel-line' style='width:74%'></div></td></tr>`;
  return h;
}
function mobileSkelDiv(n) {
  let h = "";
  for (let i = 0; i < n; i++)
    h += `<div class='skel'><div class='skel-line' style='width:86%'></div><div class='skel-line' style='width:64%'></div></div>`;
  return h;
}

// --- 通用复制(http 非安全上下文走 execCommand 降级) ---
function copyText(txt, btn) {
  const done = () => {
    haptic(12);
    if (btn) { const old = btn.innerHTML; btn.innerHTML = icon("ok", 12) + " " + t("g_copied"); setTimeout(() => btn.innerHTML = old, 1600); }
  };
  if (navigator.clipboard && window.isSecureContext)
    navigator.clipboard.writeText(txt).then(done).catch(() => fallbackCopy(txt, done));
  else fallbackCopy(txt, done);
}

// --- 日志页: agent 选择 + 事件时间线(长按复制) ---
let logAgents = null;
async function initLogPage(force) {
  if (!isMobile()) return;
  const sel = $("logagent-sel"), body = $("logbody");
  $("logpage").hidden = false;   // 移动端进入日志页即显示(桌面保持 hidden)
  if (logAgents && !force) { if (!body.children.length) loadLogView(); return; }
  const agents = await loadAgents();
  logAgents = agents;
  let opts = `<option value="">${t("log_pick")}</option>`;
  agents.omp.forEach(x => { opts += `<option value='${escAttr(x.id)}' data-cwd='${escAttr(x.cwd)}' data-tmux='${escAttr(x.tmux)}'>OMP · ${escHtml((x.goal || x.cwd).slice(0, 48))}</option>`; });
  agents.codex.forEach(x => { opts += `<option value='' data-cwd='${escAttr(x.cwd)}' data-tmux=''>Codex · ${escHtml(x.cwd.slice(-40))}</option>`; });
  sel.innerHTML = opts;
  if (!body.children.length) loadLogView();
}
async function loadLogView() {
  const body = $("logbody");
  const sel = $("logagent-sel");
  const opt = sel.selectedOptions[0];
  const sid = sel.value, cwd = opt ? opt.dataset.cwd || "" : "", tmx = opt ? opt.dataset.tmux || "" : "";
  if (!sid && !cwd) { renderLogTimeline(); return; }  // 未选 agent → 全局事件时间线(默认视图)
  body.innerHTML = `<div class='agentlog'>${t("a_loading")}</div>`;
  try {
    const d = await fetchAgentLog(sid, cwd, tmx);
    body.innerHTML = agentLogHtml(d);
    // 长按复制日志全文
    bindLongPress(body, (el) => {
      const txt = el.innerText.trim();
      copyText(txt, null);
      haptic(15);
      console.log("[svc-dashboard] long-press copy " + txt.length + " chars");
      toastCopied(el);
    });
  } catch (err) {
    body.innerHTML = `<div class='agentlog aglog-empty'>${t("a_fail", { e: escHtml(err.message) })}</div>`;
  }
}
function toastCopied(anchor) {
  const d = document.createElement("div");
  d.className = "copy-toast";
  d.innerHTML = icon("ok", 13) + " " + t("g_copied");
  document.body.appendChild(d);
  setTimeout(() => { d.style.opacity = "0"; setTimeout(() => d.remove(), 350); }, 1400);
}
const escHtml = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const escAttr = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

// --- 模型页: OMP / Codex agent 卡片(状态灯+名称+最近活动+日志入口) ---
let agentsInit = false;
async function initAgentsPage() {
  if (!isMobile()) return;
  $("agents-page").hidden = false;  // 移动端进入模型页即显示(桌面保持 hidden)
  if (agentsInit) return;
  agentsInit = true;
  const el = $("agents-page");
  el.innerHTML = `<h2>${t("a_title")} <span class="ghint">${t("a_hint", { n: "" })}</span></h2>` + mobileSkelDiv(3);
  const agents = await loadAgents();
  const total = agents.omp.length + agents.codex.length;
  const cards = [];
  agents.omp.forEach(x => {
    const [dot, txt] = x.health === "running" ? ["var(--c-green)", t("a_running")]
      : x.health === "blocked" ? ["var(--c-warn)", t("a_blocked")]
      : x.health === "completed" ? ["var(--c-gray)", t("a_done")] : ["var(--text-ghost)", t("a_idle")];
    cards.push(`<div class="gcard" data-sid="${escAttr(x.id)}" data-cwd="${escAttr(x.cwd)}" data-tmux="${escAttr(x.tmux)}" role="button" tabindex="0">
      <div class="ghead"><span class="mdot" style="background:${dot};width:9px;height:9px;border-radius:50%;display:inline-block"></span>
      <span class="gname">OMP</span><span class="gstate">${txt}</span></div>
      <div class="gsub">${escHtml((x.goal || x.cwd).slice(0, 60))}</div>
      <div class="grow"><span>${t("a_active")}</span><span class="gidle">${t("a_ago", { s: x.idle_seconds })}</span></div>
      <div class="grow"><span>${t("a_tool")}</span><span class="gtx">${escHtml(x.tool)}</span></div></div>`);
  });
  agents.codex.forEach(x => {
    cards.push(`<div class="gcard" data-sid="" data-cwd="${escAttr(x.cwd)}" data-tmux="" role="button" tabindex="0">
      <div class="ghead"><span style="background:var(--c-green);width:9px;height:9px;border-radius:50%;display:inline-block"></span>
      <span class="gname">Codex</span><span class="gstate">${t("a_running")}</span></div>
      <div class="gsub">${escHtml(x.cwd)}</div>
      <div class="grow"><span>${t("a_active")}</span><span class="gidle">${t("a_ago", { s: x.idle_seconds })}</span></div></div>`);
  });
  el.innerHTML = `<h2>${t("a_title")} <span class="ghint">${t("a_hint", { n: total })}</span></h2>` +
    `<div class="gcards">${cards.join("") || `<div class="gempty">${t("a_none")}</div>`}</div>`;
  // 点模型卡 → 跳日志页并选中该 agent
  el.querySelectorAll(".gcard").forEach(c =>
    c.addEventListener("click", async () => {
      await initLogPage();
      const sel = $("logagent-sel");
      const opt = [...sel.options].find(o => o.value === c.dataset.sid && o.dataset.cwd === c.dataset.cwd);
      if (opt) { sel.value = opt.value; loadLogView(); }
      setPage(1);
    }));
}

// --- goal 卡片展开(点标题切换 .gextra) ---
document.addEventListener("click", (e) => {
    const g = e.target.closest(".gcard");
    if (!g || !isMobile()) return;
    if (e.target.closest(".gcopy, .swipe-act, .swipe-bg")) return;
    if (g.querySelector(".gextra")) { g.classList.toggle("open"); haptic(6); }
});

// --- 长按(500ms)复制 ---
function bindLongPress(root, onCopy) {
  if (!TOUCH) return;
  root.querySelectorAll(".aglog-row, .termlog").forEach(el => {
    let timer = null, sx = 0, sy = 0, moved = false;
    el.style.touchAction = "pan-x pan-y";
    el.addEventListener("touchstart", (e) => {
      if (e.touches.length !== 1) return;
      sx = e.touches[0].clientX; sy = e.touches[0].clientY; moved = false;
      timer = setTimeout(() => { if (!moved) { timer = null; onCopy(el); } }, 500);
    }, { passive: true });
    el.addEventListener("touchmove", (e) => {
      if (timer && (Math.abs(e.touches[0].clientX - sx) > 8 || Math.abs(e.touches[0].clientY - sy) > 8)) {
        clearTimeout(timer); timer = null; moved = true;
      }
    }, { passive: true });
    el.addEventListener("touchend", () => { if (timer) { clearTimeout(timer); timer = null; } }, { passive: true });
    el.addEventListener("touchcancel", () => { if (timer) { clearTimeout(timer); timer = null; } }, { passive: true });
  });
}

// --- 双击: 概览页 负载卡→Goal页 / 磁盘卡→展开top进程 ---
let lastTap = 0, lastTapEl = null;
if (TOUCH) document.addEventListener("touchend", (e) => {
  const stat = e.target.closest ? e.target.closest("#sysbar .stat") : null;
  if (!stat) return;
  const now = Date.now();
  if (now - lastTap < 300 && stat === lastTapEl) {
    lastTap = 0;
    if (stat.dataset.k === "load") { setPage(2); haptic(10); }
    else if (stat.dataset.k === "disk") {
      haptic(10);
      const tops = document.querySelector("#loadline .ld-tops");
      if (tops) tops.hidden = !tops.hidden;
      console.log("[svc-dashboard] double-tap disk -> toggle top procs");
    }
  } else { lastTap = now; lastTapEl = stat; }
}, { passive: true });

// --- 触摸手势总协调: 分页滑动 / 边缘右滑返回 / 列表左滑 ---
if (TOUCH) (function setupGestures() {
  let g = null; // {kind:"page"|"edge"|"row", id, x0, y0, t0, dx, lastX, base, row, fg, lockX}
  const W = () => window.innerWidth;
  document.addEventListener("touchstart", (e) => {
    if (e.touches.length !== 1 || g) return;
    const t = e.touches[0];
    if (!isMobile()) return;
    // 边缘手势最优先: 起点 x<24px 且非首页(否则按普通分页滑动处理)
    const edge = t.clientX < 24 && page > 0;
    const target = !edge && t.target.closest ? t.target.closest(".swipe-item") : null;
    const swipeItem = target;
    // 横向自身滚动的容器不参与手势; a/ chip 不排除 —— 链接上的横滑仍是列表手势, 点击照常触发
    const scroller = t.target.closest ? t.target.closest(".filters, .aglog, .termlog, select") : null;
    if (swipeItem && !scroller) {
      g = { kind: "row", id: t.identifier, x0: t.clientX, y0: t.clientY, t0: Date.now(),
            fg: swipeItem.querySelector(".swipe-fg"), base: 0, lockX: null };
      gesture.claimed = t.identifier;
      return;
    }
    if (scroller || !pages) return;
    // 边缘手势(上文已判定)返回概览, 否则普通分页滑动
    g = { kind: edge ? "edge" : "page", id: t.identifier, x0: t.clientX, y0: t.clientY,
          t0: Date.now(), lastX: t.clientX, lockX: null, dx: 0 };
    gesture.claimed = t.identifier;
  }, { passive: true });

  document.addEventListener("touchmove", (e) => {
    if (!g) return;
    const t = [...e.touches].find(x => x.identifier === g.id);
    if (!t) return;
    const dx = t.clientX - g.x0, dy = t.clientY - g.y0;
    if (g.lockX === null) {
      if (Math.abs(dx) < 6 && Math.abs(dy) < 6) return; // 未定轴
      g.lockX = Math.abs(dx) > Math.abs(dy);
      if (g.kind === "row" || g.kind === "page" || g.kind === "edge") {
        if (g.lockX) e.preventDefault(); // 横向手势: 阻断浏览器返回/前进导航
      }
    }
    if (!g.lockX) return; // 纵向滚动交给浏览器
    if (g.kind === "row") {
      // 左滑露按钮: 只允许负方向(露出右侧按钮), 已露出时回推
      const w = g.fg.parentElement.querySelector(".swipe-act");
      const open = w ? w.offsetWidth : 96;
      let x = Math.min(0, Math.max(-open - 24, g.base + dx));
      g.fg.classList.add("stick");
      g.fg.style.transform = `translate3d(${x}px,0,0)`;
      g.dx = x;
    } else {
      // 分页/边缘: 跟手(阻尼 0.55), 越界回弹
      let d = (page > 0 || dx > 0) && (page < N_PAGES - 1 || dx < 0) ? dx * 0.55
              : dx > 0 ? (page < N_PAGES - 1 ? 0 : Math.min(64, dx * 0.18))
                       : (page > 0 ? 0 : Math.max(-64, dx * 0.18));
      if (g.kind === "edge" && d < -20) { g.kind = "page"; } // 反向滑: 降级为分页
      const pct = d / W() * 100;
      g.dx = pct;
      if (!trackEl) return;
      trackEl.classList.add("stick");
      trackEl.style.transform = `translate3d(calc(${-page * PAGE_W}% + ${pct}vw),0,0)`;
      g.lastX = t.clientX;
    }
  }, { passive: false });

  document.addEventListener("touchend", (e) => {
    if (!g) return;
    const t = [...e.changedTouches].find(x => x.identifier === g.id);
    const done = () => { gesture.claimed = null; g = null; };
    if (!t) { done(); return; }
    if (g.kind === "row") {
      const open = (g.fg.parentElement.querySelector(".swipe-act") || {}).offsetWidth || 96;
      const x = g.dx <= -open * 0.6 ? -open : 0;
      g.fg.classList.remove("stick");
      g.fg.style.transform = `translate3d(${x}px,0,0)`;
      g.fg.dataset.open = x ? "1" : "";
      if (x) haptic(6);
      done(); return;
    }
    const dx = (g.lockX ? g.lastX - g.x0 : 0);
    const dt = Date.now() - g.t0;
    trackEl && trackEl.classList.remove("stick");
    if (g.kind === "edge" && g.lockX && dx > 56) {
      console.log("[svc-dashboard] edge-swipe back to overview");
      setPage(0); done(); return;
    }
    // 分页吸附: 位移超过 1/4 屏 或 快速轻扫
    const fast = Math.abs(dx) > 40 && dt < 260;
    if (g.lockX && (Math.abs(dx) > W() / 4 || fast)) {
      const dir = dx < 0 ? 1 : -1; // 左滑下一页, 右滑上一页
      if ((dir > 0 && page < N_PAGES - 1) || (dir < 0 && page > 0)) { setPage(page + dir); done(); return; }
    }
    applyPagesX(true); // 未达阈值: 弹回当前页
    done();
  }, { passive: true });
  document.addEventListener("touchcancel", () => {
    if (!g) return;
    trackEl && trackEl.classList.remove("stick");
    applyPagesX(true);
    g = null; gesture.claimed = null;
  }, { passive: true });
  // 点击其他区域收起已露出的滑动按钮
  document.addEventListener("touchstart", (e) => {
    document.querySelectorAll(".swipe-fg[data-open]").forEach(fg => {
      if (!fg.parentElement.contains(e.target)) {
        fg.style.transform = "translate3d(0,0,0)"; fg.removeAttribute("data-open");
      }
    });
  }, { passive: true });
})();

// --- 负载/CPU 折线图(最近 24 采样存 localStorage, 捏合调时间窗) ---
const chart = $("chart");
function chartData() {
  try { return JSON.parse(localStorage.getItem("svc-chart") || "[]"); }
  catch (e) { return []; }
}
function chartSave(arr) { try { localStorage.setItem("svc-chart", JSON.stringify(arr)); } catch (e) {} }
function chartSample(s) {
  if (!chart || !isMobile()) return;
  const arr = chartData();
  const now = Date.now();
  const m = s.mem || {};
  arr.push({ t: now, load: (s.loadavg || [null])[0] ?? (s.loadavg || [])[2] ?? null, cpu: s.cpu_usage,
             mem: m.percent ?? null, swap: m.swap_percent ?? null });
  while (arr.length > 24) arr.shift();
  chartSave(arr);
  drawChart();
}
let chartWin = 24;
function drawChart() {
  if (!chart || !isMobile()) return;
  const ctx = chart.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = chart.clientWidth || 360, h = 150;
  if (chart.width !== w * dpr) { chart.width = w * dpr; chart.height = h * dpr; }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const all = chartData();
  $("chart-empty").style.display = all.length < 2 ? "" : "none";
  $("chart-win").textContent = all.length >= 2 ? t("chart_win", { n: chartWin }) : "";
  if (all.length < 2) return;
  const data = all.slice(-chartWin);
  const maxL = Math.max(2, ...data.map(d => d.load || 0));
  const X = i => 6 + i * ((w - 12) / (data.length - 1));
  // 主题色从 CSS 变量读取(getComputedStyle), 明暗主题切换即跟随
  const cs = getComputedStyle(document.documentElement);
  const cssVar = (n) => cs.getPropertyValue(n).trim();
  const CH = { cpu: cssVar("--ch-cpu"), load: cssVar("--ch-load"),
               mem: cssVar("--ch-mem"), swap: cssVar("--ch-swap"), grid: cssVar("--ch-grid") };
  // 网格线
  ctx.strokeStyle = CH.grid; ctx.lineWidth = 1;
  [0.25, 0.5, 0.75].forEach(f => { ctx.beginPath(); ctx.moveTo(0, h * f); ctx.lineTo(w, h * f); ctx.stroke(); });
  // CPU %: 0-100 映射
  ctx.strokeStyle = CH.cpu; ctx.lineWidth = 1.6; ctx.beginPath();
  data.forEach((d, i) => { const y = h - 6 - (d.cpu || 0) / 100 * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // 内存 %: 0-100 映射(橙)
  ctx.strokeStyle = CH.mem; ctx.lineWidth = 1.6; ctx.beginPath();
  data.forEach((d, i) => { if (d.mem == null) return; const y = h - 6 - (d.mem || 0) / 100 * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // Swap %: 0-100 映射(紫; 无 swap 或 0% 时贴底直线,仍显示以便观察趋势)
  ctx.strokeStyle = CH.swap; ctx.lineWidth = 1.6; ctx.beginPath();
  data.forEach((d, i) => { const y = h - 6 - (d.swap || 0) / 100 * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // 负载: 按各自 max 缩放
  ctx.strokeStyle = CH.load; ctx.lineWidth = 1.8; ctx.beginPath();
  data.forEach((d, i) => { const y = h - 6 - (d.load || 0) / maxL * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // 图例(左上 CPU/mem/swap, 右上 load; 颜色同线)
  ctx.font = "10px ui-monospace, monospace";
  ctx.fillStyle = CH.cpu; ctx.fillText("CPU " + Math.round(data[data.length-1].cpu || 0) + "%", 8, 12);
  ctx.fillStyle = CH.mem; ctx.fillText("mem " + Math.round(data[data.length-1].mem || 0) + "%", 8, 26);
  ctx.fillStyle = CH.swap; ctx.fillText("swap " + Math.round(data[data.length-1].swap || 0) + "%", 8, 40);
  ctx.fillStyle = CH.load; ctx.textAlign = "right"; ctx.fillText("load " + maxL.toFixed(1), w - 8, 12); ctx.textAlign = "left";
}
if (chart) {
  window.addEventListener("resize", drawChart);
  mqMobile.addEventListener("change", drawChart);
  drawChart();
  // 捏合调整时间窗: 两指距离变化 → chartWin 4..24
  let pinch = null;
  chart.addEventListener("touchstart", (e) => {
    if (e.touches.length === 2)
      pinch = { d: Math.hypot(e.touches[0].clientX - e.touches[1].clientX,
                              e.touches[0].clientY - e.touches[1].clientY), win: chartWin };
  }, { passive: true });
  chart.addEventListener("touchmove", (e) => {
    if (!pinch || e.touches.length !== 2) return;
    e.preventDefault();
    const d = Math.hypot(e.touches[0].clientX - e.touches[1].clientX,
                         e.touches[0].clientY - e.touches[1].clientY);
    const win = Math.round(Math.max(4, Math.min(24, pinch.win * pinch.d / d)));
    if (win !== chartWin) { chartWin = win; drawChart(); }
  }, { passive: false });
  chart.addEventListener("touchend", () => { if (pinch) { pinch = null; haptic(8); } }, { passive: true });
}

// --- 轮询暂停: 页面不可见时停一切(visibilitychange 埋点) ---
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    console.log("[svc-dashboard] visibilitychange -> hidden, polling paused");
  } else {
    console.log("[svc-dashboard] visibilitychange -> visible, polling resumed");
    if (autoOn && !autoLocked) load(false); // 回前台立即刷一次(锁定时不刷)
  }
});

// --- 手机端 30s 自动刷新(省电); 桌面保持 AUTO ---
const MOBILE_REFRESH_SEC = 30;
let autoSec = AUTO;
function applyAutoSec() {
  const sec = isMobile() ? MOBILE_REFRESH_SEC : AUTO;
  if (sec !== autoSec) {
    autoSec = sec;
    clearInterval(autoTimer);
    autoTimer = setInterval(autoTick, autoSec * 1000);
    console.log("[svc-dashboard] auto refresh interval -> " + autoSec + "s");
  }
}
mqMobile.addEventListener("change", applyAutoSec);
let autoTimer = setInterval(autoTick, autoSec * 1000);
function autoTick() {
  if (autoOn && !autoLocked && !document.hidden) {  // 长按锁定时 30s 自动刷新完全停止
    console.log("[svc-dashboard] auto refresh tick");
    if (filter === "manage") loadManage();
    else load(false);
  }
}
applyAutoSec();

/* ================================================================
   明暗主题: 跟随系统 / 手动深色 / 手动浅色(localStorage 记住)。
   html[data-theme] 覆盖 prefers-color-scheme; meta theme-color 同步;
   切换后 canvas 图表按新 CSS 变量重绘。 */
const THEME_KEY = "svc-theme";
let themeMQ = window.matchMedia("(prefers-color-scheme: light)");
function currentTheme() {
  return document.documentElement.getAttribute("data-theme") || "auto";
}
function applyThemeMeta() {
  const cs = getComputedStyle(document.documentElement);
  const bg = cs.getPropertyValue("--bg").trim() || "#0a0a0a";
  document.querySelector('meta[name="theme-color"]').setAttribute("content", bg);
}
function setTheme(mode) {
  if (mode === "auto") {
    document.documentElement.removeAttribute("data-theme");
    try { localStorage.removeItem(THEME_KEY); } catch (e) {}
  } else {
    document.documentElement.setAttribute("data-theme", mode);
    try { localStorage.setItem(THEME_KEY, mode); } catch (e) {}
  }
  document.querySelectorAll("#theme-chips .chip").forEach(c =>
    c.classList.toggle("active", c.dataset.thm === mode));
  applyThemeMeta();
  drawChart();          // canvas 色值跟随 CSS 变量重绘
  console.log("[svc-dashboard] theme -> " + mode);
}
// 主题切换 toast(与长按锁定共用)
function themeToast(msg) {
  const d = document.createElement("div");
  d.className = "copy-toast";
  d.innerHTML = icon("auto", 13) + " " + msg;
  document.body.appendChild(d);
  setTimeout(() => { d.style.opacity = "0"; setTimeout(() => d.remove(), 350); }, 1400);
}
document.addEventListener("click", (e) => {
  const c = e.target.closest("#theme-chips .chip");
  if (!c) return;
  haptic(6);
  setTheme(c.dataset.thm);
});
setTheme(currentTheme());   // 初始化(含 localStorage 恢复 + meta 同步)
themeMQ.addEventListener("change", () => { applyThemeMeta(); drawChart(); });  // 跟随系统档: 系统切换即更新

// --- 日志页选择器变化 ---
if ($("logagent-sel")) $("logagent-sel").addEventListener("change", loadLogView);

// ================================================================
// ツール页: 健康检查 / 文件浏览 / 垃圾清理 / 网络速测 / 用户服务 / 计划任务
// ================================================================
const TL_CONF = {{TL_CONF}};
let toolsInited = false;

function fmtB(n) {
  if (n == null) return "—";
  if (n < 1024) return n + " B";
  const u = ["K", "M", "G", "T"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : 1) + " " + u[i];
}

async function tlGet(url) {
  const r = await fetch(url, { cache: "no-store" });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.msg || ("HTTP " + r.status));
  return d;
}
async function tlPost(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body), cache: "no-store" });
  return r.json().catch(() => ({ ok: false, msg: "bad json" }));
}

// --- F2 健康检查 ---
async function runHealth() {
  const btn = $("tl-health-run"), body = $("tl-health-body");
  btn.textContent = t("tl_health_loading");
  try {
    const h = await tlGet("/api/health");
    renderHealth(h);
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
  btn.textContent = t("tl_health_run");
}

function renderHealth(h) {
  const body = $("tl-health-body");
  const big = h.overall === "ok" ? "<span class='t-green'>" + icon("ok", 18) + "</span>"
    : h.overall === "warn" ? "<span class='t-warn'>" + icon("warn", 18) + "</span>"
    : "<span class='t-red'>" + icon("err", 18) + "</span>";
  const rows = [];
  const row = (cls, name, val) =>
    `<div class='tl-row'><span class='tl-dot ${cls}'></span><span class='tl-name'>${escHtml(name)}</span><span class='tl-val'>${val}</span></div>`;
  const s = h.sys || {};
  const la = s.loadavg || [];
  rows.push(row(la[2] > (s.cpu_count || 1) ? "warn" : "", t("tl_h_load"),
    `<b>${la.join(" / ") || "—"}</b> / ${s.cpu_count || "?"}`));
  rows.push(row(s.cpu_usage > 90 ? "warn" : "", t("tl_h_cpu"), `<b>${s.cpu_usage}%</b>`));
  rows.push(row((s.mem || {}).percent >= 90 ? "bad" : (s.mem || {}).percent >= 75 ? "warn" : "",
    t("tl_h_mem"), `<b>${(s.mem || {}).percent}%</b> · ${fmtB((s.mem || {}).used)}/${fmtB((s.mem || {}).total)}`));
  const sw = s.swap || {};
  rows.push(row("", t("tl_h_swap"), sw.total ? `<b>${sw.percent}%</b> · ${fmtB(sw.used)}/${fmtB(sw.total)}` : "—"));
  const dk = s.disk || {};
  rows.push(row(dk.percent >= 90 ? "bad" : dk.percent >= 80 ? "warn" : "", t("tl_h_disk"),
    `<b>${dk.percent}%</b> · ${fmtB(dk.free)} ${t("tl_fs_dl") === "下载" ? "可用" : "free"}`));
  if (h.temp) rows.push(row(h.temp.c >= 80 ? "bad" : h.temp.c >= 65 ? "warn" : "",
    `${t("tl_h_temp")} (${escHtml(h.temp.type)})`, `<b>${h.temp.c}°C</b>`));
  const dt = h.disk_trend || {};
  let trendTxt = t("tl_h_trend_base");
  if (dt.eta_full) trendTxt = t("tl_h_trend_days", { g: fmtB(dt.growth_per_day), d: escHtml(dt.eta_full) });
  else if (dt.days > 1) trendTxt = t("tl_h_trend_base") + ` (${dt.days}d)`;
  rows.push(row(dt.days_left != null && dt.days_left < 30 ? "warn" : "", t("tl_h_trend"), trendTxt));
  (h.procs || []).forEach(p => rows.push(row(p.alive ? "" : "bad", `${t("tl_h_procs")} · ${escHtml(p.name)}`,
    p.alive ? `PID ${p.pid}` : "DOWN")));
  const ports = h.ports || [];
  const up = ports.filter(x => x.up).length;
  rows.push(row(up === ports.length ? "" : "warn", t("tl_h_ports"),
    `<b>${up}/${ports.length}</b> up`));
  rows.push(row((h.watchdog_1h || {}).count > 0 ? "warn" : "", t("tl_h_wd"), `<b>${(h.watchdog_1h || {}).count}</b>`));
  const headTxt = h.overall === "ok" ? t("st_all_ok") : `${t("tl_h_ports")} ${up}/${ports.length} · ${t("tl_h_wd")} ${(h.watchdog_1h || {}).count}`;
  body.innerHTML = `<div class='tl-row tl-head-big'><span>${big}</span><span class='tl-name'>${headTxt}</span></div>` + rows.join("") +
    (ports.length ? `<div class='tl-docker-pre' id='tl-ports-pre'>${ports.map(x =>
      `${x.up ? "●" : "○"} :${x.port} ${escHtml(x.name)}`).join("\\n")}</div>` : "");
}

// --- F4 快速复制组 ---
function renderCopyGroup() {
  const hosts = TL_CONF.hosts || {};
  const sshHost = hosts.tailscale || hosts.lan || hosts.hostname || "host";
  const items = [
    [t("tl_copy_ssh"), `ssh tetsuya@${sshHost}`],
    [t("tl_copy_ts"), hosts.tailscale || "—"],
    [t("tl_copy_lan"), hosts.lan || "—"],
  ];
  $("tl-copy-body").innerHTML = items.map(([lbl, val]) =>
    `<span class='btn gcopy' data-copy='${escAttr(val)}' role='button' tabindex='0'>${escHtml(lbl)}: <b>${escHtml(val)}</b></span>`).join("");
}

async function renderG1() {
  const el = $("tl-g1");
  const host = linkHost(location.hostname);
  try {
    const d = await tlGet("/api/toolports");
    const alive = new Set(d.alive || []);
    el.innerHTML = (TL_CONF.g1 || []).map(([n, p]) => alive.has(p)
      ? `<a class='chip tchip' href='http://${host}:${p}/' target='_blank' rel='noopener'>${n} :${p} ${icon("ext", 11)}</a>`
      : `<span class='chip tchip' style='opacity:.35;cursor:default'>${n} :${p}</span>`).join("");
  } catch (e) {
    el.innerHTML = "";
  }
}

// --- F1 文件浏览 ---
let fsCwd = null;
let fsEntries = [];
let fsDuMap = {};

function fsRootMenu() {
  return (TL_CONF.fs_roots || []).map(r =>
    `<span class='chip' data-root='${escAttr(r)}' role='button' tabindex="0">${escHtml(r)}</span>`).join("");
}

function fsCrumbHtml(path) {
  const roots = TL_CONF.fs_roots || [];
  const root = roots.find(r => path === r || path.startsWith(r + "/")) || "/";
  const parts = path === root ? [] : path.slice(root.length + 1).split("/");
  let h = `<a data-crumb='${escAttr(root)}'>${escHtml(root)}</a>`;
  let acc = root;
  parts.forEach(p => {
    acc += "/" + p;
    h += ` / <a data-crumb='${escAttr(acc)}'>${escHtml(p)}</a>`;
  });
  return h;
}

function fsRender() {
  const list = $("tl-fs-list");
  if (!fsCwd) {
    $("tl-fs-crumbs").innerHTML = "";
    list.innerHTML = `<div class='filters' style='border:none;padding:0'>${fsRootMenu()}</div>`;
    return;
  }
  $("tl-fs-crumbs").innerHTML = fsCrumbHtml(fsCwd);
  const q = ($("tl-fs-filter").value || "").toLowerCase();
  const showHidden = $("tl-fs-hidden").checked;
  const rows = fsEntries
    .filter(e => (showHidden || !e.name.startsWith(".")) && (!q || e.name.toLowerCase().includes(q)))
    .map(e => {
      const isDir = e.type === "dir";
      const du = fsDuMap[e.name];
      const sz = isDir ? (du != null ? `<span class='du'>${fmtB(du)}</span>` : "—")
                       : fmtB(e.size);
      return `<div class='tl-fsrow' data-name='${escAttr(e.name)}' data-type='${e.type}' role='button' tabindex="0">` +
        `<span class='ico'>${icon(isDir ? "folder" : "file", 15)}</span><span class='nm'>${escHtml(e.name)}</span>` +
        `<span class='mt'>${new Date(e.mtime * 1000).toLocaleDateString()}</span><span class='sz'>${sz}</span></div>`;
    }).join("");
  list.innerHTML = rows || `<div class='gempty'>${t("tl_fs_empty")}</div>`;
}

async function fsOpen(path) {
  const list = $("tl-fs-list");
  list.innerHTML = `<div class='gempty'>${t("st_loading")}</div>`;
  try {
    const d = await tlGet("/api/fs/list?path=" + encodeURIComponent(path));
    fsCwd = d.path;
    fsEntries = d.entries || [];
    fsDuMap = {};
    fsRender();
  } catch (e) {
    fsCwd = null; fsEntries = [];
    list.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)} — ${t("tl_fs_title")}</div>`;
    fsRender();
  }
}

async function fsDu() {
  if (!fsCwd) return;
  const btn = $("tl-fs-du");
  btn.textContent = t("tl_fs_du_run");
  try {
    const d = await tlGet("/api/fs/du?path=" + encodeURIComponent(fsCwd));
    if (d.ok) {
      fsDuMap = { "": 0 };
      fsDuMap[""] = null;
      const el = $("tl-fs-crumbs");
      el.innerHTML = fsCrumbHtml(fsCwd) + ` · du: <b>${fmtB(d.size)}</b>`;
    } else {
      $("tl-fs-crumbs").innerHTML = fsCrumbHtml(fsCwd) + ` · du <span class="t-red">${icon("err", 11)}</span> ${escHtml(d.msg || "")}`;
    }
  } catch (e) {
    $("tl-fs-crumbs").innerHTML = fsCrumbHtml(fsCwd) + ` · du <span class="t-red">${icon("err", 11)}</span>`;
  }
  btn.textContent = t("tl_fs_du");
}

function fsUrl(name, mode) {
  return "/api/fs/file?path=" + encodeURIComponent(fsCwd + "/" + name) + "&mode=" + mode;
}

async function fsOpenFile(name) {
  const ext = name.split(".").pop().toLowerCase();
  if (["png", "jpg", "jpeg", "webp", "gif"].includes(ext)) {
    $("tl-lightbox-img").src = fsUrl(name, "view");
    $("tl-lightbox").hidden = false;
    return;
  }
  if (["md", "py", "js", "ts", "json", "log", "txt", "yaml", "yml", "toml", "cs", "rs", "sh", "xml", "html", "css", "ini", "conf", "csv"].includes(ext)) {
    try {
      const d = await tlGet(fsUrl(name, "view"));
      $("tl-tv-name").textContent = `${name} (${fmtB((d.text || "").length)})`;
      $("tl-tv-pre").textContent = d.text || "";
      $("tl-textview").hidden = false;
      return;
    } catch (e) { /* 大文件/失败 → 下载 */ }
  }
  location.href = fsUrl(name, "download");   // 其他 → 下载
}

// --- F3 垃圾清理 ---
const CLEAN_IDS = ["journal", "apt", "tmp_old", "hermes_cache", "omp_jsonl", "binobj"];
let cleanItems = [];

async function cleanScan() {
  const btn = $("tl-clean-scan"), body = $("tl-clean-body");
  btn.textContent = t("tl_clean_scanning");
  body.innerHTML = `<div class='gempty'>${t("tl_clean_scanning")}</div>`;
  try {
    const d = await tlPost("/api/cleanup", { dry_run: true });
    cleanItems = (d.items || []).filter(x => !x.display_only);
    const docker = (d.items || []).find(x => x.display_only);
    let h = cleanItems.map(x => {
      const def = x.safe === false;
      return `<div class='tl-cleanrow'>` +
        `<input type='checkbox' data-clean='${x.id}' ${def ? "" : "checked"}>` +
        `<span class='lbl'>${escHtml(x.detail || x.id)}${x.error ? ` <small style='color:var(--c-red)'>${escHtml(x.error)}</small>` : ""}</span>` +
        `<span class='sz'>${fmtB(x.size)}</span></div>`;
    }).join("");
    h += `<div class='tl-row'><span class='tl-dot off'></span><span class='tl-name'>${t("tl_clean_total")}</span>` +
      `<span class='tl-val'><b>${fmtB(cleanItems.reduce((a, x) => a + (x.size || 0), 0))}</b></span></div>`;
    if (docker && docker.raw) {
      h += `<h3 style='margin-top:12px'>${t("tl_clean_docker")}</h3><div class='tl-docker-pre'>${escHtml(docker.raw)}</div>` +
        `<span class='btn tl-run' id='tl-clean-docker' role='button' tabindex='0'>${t("tl_clean_docker_prune")}</span>`;
    }
    body.innerHTML = h;
    $("tl-clean-exec").hidden = false;
    const dp = $("tl-clean-docker");
    if (dp) dp.addEventListener("click", async () => {
      if (!confirm(t("tl_clean_docker_confirm"))) return;
      dp.textContent = "…";
      const r = await tlPost("/api/cleanup", { action: "docker_prune" });
      dp.innerHTML = icon(r.ok ? "ok" : "err", 13) + " " + t("tl_clean_docker_prune");
      alert(r.msg || "");
    });
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
  btn.textContent = t("tl_clean_scan");
}

async function cleanExec() {
  const ids = [...document.querySelectorAll("input[data-clean]:checked")].map(x => x.dataset.clean);
  if (!ids.length) return;
  if (!confirm(t("tl_clean_confirm"))) return;
  const btn = $("tl-clean-exec"), body = $("tl-clean-body");
  btn.textContent = "…";
  const d = await tlPost("/api/cleanup", { dry_run: false, items: ids });
  const rows = (d.results || []).map(r =>
    `<div class='tl-cleanrow'><span class='tl-dot ${r.ok ? "" : "bad"}'></span>` +
    `<span class='lbl'>${escHtml(r.id)}<small>${escHtml(r.msg || "")}</small></span>` +
    `<span class='sz'>${fmtB(r.freed)}</span></div>`).join("");
  body.innerHTML = rows +
    `<div class='tl-row'><span class='tl-dot off'></span><span class='tl-name'>${t("tl_clean_freed")}</span>` +
    `<span class='tl-val'><b>${fmtB(d.df_freed)}</b></span></div>`;
  btn.textContent = t("tl_clean_exec");
  btn.hidden = true;
}

// --- G3 网络速测 ---
async function netRun() {
  const btn = $("tl-net-run"), body = $("tl-net-body");
  btn.textContent = t("tl_net_run_ing");
  body.innerHTML = `<div class='gempty'>${t("tl_net_run_ing")}</div>`;
  try {
    const d = await tlGet("/api/nettest");
    const ts = d.tailscale || {};
    body.innerHTML =
      `<div class='tl-netrow'><span class='tl-name'>${t("tl_net_ext")} (min ${d.samples.length})</span><span class='sep'></span><span class='tl-val'><b>${d.latency_ms != null ? d.latency_ms + " ms" : icon("err", 12)}</b> ${escHtml(d.error || "")}</span></div>` +
      `<div class='tl-netrow'><span class='tl-name'>${t("tl_net_ts")}${ts.peer ? " · " + escHtml(ts.peer) : ""}</span><span class='sep'></span><span class='tl-val'><b>${ts.rtt_ms != null ? ts.rtt_ms + " ms" : escHtml(ts.msg || "—")}</b></span></div>`;
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
  btn.textContent = t("tl_net_run");
}

// --- G2 用户级服务重启(I-KNOW 护栏) ---
async function usvcLoad() {
  const body = $("tl-usvc-body");
  body.innerHTML = `<div class='gempty'>${t("tl_usvc_loading")}</div>`;
  try {
    const d = await tlGet("/api/uservice");
    const unlocked = localStorage.getItem("svc-usvc") === "I-KNOW";
    body.innerHTML = (d.units || []).length ? (d.units || []).map(u => {
      const act = u.active === "active";
      return `<div class='tl-row'><span class='tl-dot ${act ? "" : "warn"}'></span>` +
        `<span class='tl-name'>${escHtml(u.unit)}<br><small style='color:var(--text-dead)'>${escHtml(u.desc)}</small></span>` +
        (unlocked ? `<span class='btn tl-run' data-usvc='${escAttr(u.unit)}' role='button' tabindex='0'>${t("tl_usvc_restart")}</span>` : "") +
        `</div>`;
    }).join("") : `<div class='gempty'>${t("tl_usvc_none")}</div>`;
    body.querySelectorAll("[data-usvc]").forEach(b => b.addEventListener("click", async () => {
      if (!confirm(`${t("tl_usvc_restart")} ${b.dataset.usvc}?`)) return;
      b.textContent = "…";
      const r = await tlPost("/api/uservice", { unit: b.dataset.usvc, action: "restart" });
      b.innerHTML = icon(r.ok ? "ok" : "err", 13) + " " + t("tl_usvc_restart");
      setTimeout(usvcLoad, 1500);
    }));
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
}

function usvcUnlock() {
  const v = ($("tl-usvc-code").value || "").trim();
  if (v !== "I-KNOW") { alert(t("tl_usvc_wrong")); return; }
  localStorage.setItem("svc-usvc", "I-KNOW");
  $("tl-usvc-unlockwrap").hidden = true;   // 解锁成功: 收起输入行(锁按钮本来就在, 无需翻转)
  usvcLoad();
}

// --- G4 计划任务一览(只读, 复用 /api/tasks 的 cron 枚举) ---
async function cronLoad() {
  const body = $("tl-cron-body");
  try {
    const d = await tlGet("/api/tasks?lang=" + encodeURIComponent(LANG));
    body.innerHTML = (d.tasks || []).length ? (d.tasks || []).map(x =>
      `<div class='tl-row'><span class='tl-dot off'></span>` +
      `<span class='tl-name'>${escHtml(x.name)}</span>` +
      `<span class='tl-val'>${escHtml(x.schedule)}</span></div>`).join("")
      : `<div class='gempty'>—</div>`;
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
}

// --- ツール页初始化(首次进入触发) ---
function initToolsPage() {
  $("toolspage").hidden = false;
  if (!toolsInited) {
    toolsInited = true;
    renderCopyGroup();
    renderG1();
    runHealth();
    cronLoad();
    fsRender();
    if (localStorage.getItem("svc-usvc") === "I-KNOW") usvcLoad();
  }
  // 事件绑定(一次性)
  if (!initToolsPage._bound) {
    initToolsPage._bound = true;
    $("tl-health-run").addEventListener("click", runHealth);
    $("tl-fs-du").addEventListener("click", fsDu);
    $("tl-fs-filter").addEventListener("input", fsRender);
    $("tl-fs-hidden").addEventListener("change", fsRender);
    $("tl-clean-scan").addEventListener("click", cleanScan);
    $("tl-clean-exec").addEventListener("click", cleanExec);
    $("tl-net-run").addEventListener("click", netRun);
    $("tl-usvc-unlock").addEventListener("click", usvcUnlock);
    $("tl-usvc-showlock").addEventListener("click", () => {
      $("tl-usvc-showlock").hidden = true;
      $("tl-usvc-unlockwrap").hidden = false;
    });
    $("tl-fs-list").addEventListener("click", (e) => {
      const root = e.target.closest("[data-root]");
      if (root) { fsOpen(root.dataset.root); return; }
      const crumb = e.target.closest("[data-crumb]");
      if (crumb) { fsOpen(crumb.dataset.crumb); return; }
      const row = e.target.closest(".tl-fsrow");
      if (!row) return;
      if (row.dataset.type === "dir") fsOpen(fsCwd + "/" + row.dataset.name);
      else fsOpenFile(row.dataset.name);
    });
    $("tl-fs-crumbs").addEventListener("click", (e) => {
      const crumb = e.target.closest("[data-crumb]");
      if (crumb) fsOpen(crumb.dataset.crumb);
    });
    const closeViews = () => { $("tl-lightbox").hidden = true; $("tl-textview").hidden = true; };
    $("tl-lightbox").addEventListener("click", closeViews);
    $("tl-textview").querySelector(".tl-lb-close").addEventListener("click", (e) => { e.stopPropagation(); closeViews(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeViews(); });
  }
}

// --- 启动 ---
regroupPages();          // 手机: 分组进 6 页; 桌面: 保持原序
if (isMobile()) {
  setPage(0, { first: true });
  applyAutoSec();
} else {
  $("logpage").hidden = true;
  $("agents-page").hidden = true;
  initToolsPage();   // 桌面无页签: 工具面板直接展开在页面流里(内部会解除 hidden)
}
load(true);
</script>
</body>
</html>
"""


# ================= ツール页: 文件浏览 / 健康检查 / 垃圾清理 / 网络速测 / 用户服务 =================
# 全部纯标准库; 写操作只限下方枚举路径(红线: 用户媒体/System.db/git 历史/.env 永不触碰)。

HOME_DIR = "/home/tetsuya"   # svc-dashboard 以 root 运行(systemd 系统级), 不能用 expanduser

# --- F1 文件浏览 ---
FS_ROOTS = [os.path.join(HOME_DIR, "development"),
            os.path.join(HOME_DIR, "NAS"),
            "/tmp",
            os.path.join(HOME_DIR, ".omp", "logs")]
# 敏感文件名: .env / *key* / *secret* / id_rsa* / *.pem —— 列表隐藏 + 直接访问 404
_FS_SENSITIVE = re.compile(r"\.env$|key|secret|^id_rsa|\.pem$", re.I)
_FS_IMAGE = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
_FS_TEXT = {".md", ".py", ".js", ".ts", ".json", ".log", ".txt", ".yaml", ".yml",
            ".toml", ".cs", ".rs", ".sh", ".xml", ".html", ".css", ".ini", ".conf", ".csv"}
_FS_TEXT_MAX = 1 << 20   # 文本 >1MB 只给下载


def fs_sensitive(name):
    return bool(_FS_SENSITIVE.search(name))


def fs_resolve(path_param):
    """用户路径 -> 白名单根内 realpath; 越界/敏感/非法返回 None。
    os.path.realpath 递归解析全部符号链接后复检前缀, 天然覆盖"跟随一层再复检"。"""
    p = (path_param or "").strip()
    if not p or "\x00" in p:
        return None
    p = os.path.expanduser(p)
    if not p.startswith("/"):
        return None
    real = os.path.realpath(p)
    for root in FS_ROOTS:
        rroot = os.path.realpath(root)
        if real == rroot or real.startswith(rroot + os.sep):
            return None if fs_sensitive(os.path.basename(real)) else real
    return None


def fs_list(path_param):
    """目录列表(名称/大小/mtime/类型), 敏感名直接跳过, 文件夹优先。"""
    real = fs_resolve(path_param)
    if not real or not os.path.isdir(real):
        return {"ok": False, "msg": "not found"}
    out = []
    try:
        with os.scandir(real) as it:
            for e in it:
                try:
                    if fs_sensitive(e.name):
                        continue
                    is_dir = e.is_dir(follow_symlinks=True)
                    if not is_dir and not e.is_file(follow_symlinks=True):
                        continue   # socket/fifo 等跳过
                    st = e.stat(follow_symlinks=True)
                    out.append({"name": e.name, "type": "dir" if is_dir else "file",
                                "size": None if is_dir else st.st_size,
                                "mtime": int(st.st_mtime)})
                except OSError:
                    continue
    except OSError as ex:
        return {"ok": False, "msg": str(ex)}
    out.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
    return {"ok": True, "path": real, "entries": out}


def fs_meta(real):
    """文件预览类型 + MIME: 图片直显 / 小文本渲染 / 其他下载。"""
    ext = os.path.splitext(real)[1].lower()
    size = os.path.getsize(real)
    if ext in _FS_IMAGE:
        return "image", {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                         "webp": "image/webp", "gif": "image/gif"}.get(ext[1:], "application/octet-stream")
    if ext in _FS_TEXT and size <= _FS_TEXT_MAX:
        return "text", "text/plain; charset=utf-8"
    return "binary", "application/octet-stream"


def fs_du(path_param):
    """单目录 du(5s 超时放弃, 负载友好)。"""
    real = fs_resolve(path_param)
    if not real or not os.path.isdir(real):
        return {"ok": False, "msg": "not found"}
    try:
        p = subprocess.run(["du", "-sb", real], capture_output=True, text=True, timeout=5)
        if p.returncode != 0:
            return {"ok": False, "msg": p.stderr.strip()[:120] or "du failed"}
        return {"ok": True, "size": int(p.stdout.split()[0])}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "timeout(5s)"}
    except Exception as ex:
        return {"ok": False, "msg": str(ex)[:120]}


# --- F2 健康检查 ---
HEALTH_PROCS = [   # (显示名, 匹配串) 可配置列表
    ("ServerCore (dotnet)", "ServerCore"),
    ("syncthing", "syncthing"),
    ("tailscaled", "tailscaled"),
    ("immich-server", "immich"),
]
DISK_HISTORY_PATH = "/tmp/svc-disk-history.json"
_WD_BAD = re.compile(r"stalled|error|panic|timeout|fail|kill", re.I)


def _proc_alive(pattern):
    """关键进程存活: comm/cmdline 含 pattern -> pid, 否则 None。"""
    pat = pattern.lower()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm", "rb") as f:
                if pat in f.read().decode("utf-8", "replace").lower():
                    return int(pid)
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if pat in f.read().decode("utf-8", "replace").replace("\x00", " ").lower():
                    return int(pid)
        except OSError:
            continue
    return None


def swap_info():
    total = free = 0
    for line in read("/proc/meminfo").splitlines():
        p = line.split()
        if p[0] == "SwapTotal:":
            total = int(p[1]) * 1024
        elif p[0] == "SwapFree:":
            free = int(p[1]) * 1024
    used = total - free
    return {"total": total, "used": used,
            "percent": round(100 * used / total, 1) if total else 0.0}


def thermal_read():
    """取温度最高 zone(/sys/class/thermal, VM 可能没有 -> None)。"""
    best = None
    try:
        zones = sorted(os.listdir("/sys/class/thermal"))
    except OSError:
        return None
    for z in zones:
        if not z.startswith("thermal_zone"):
            continue
        try:
            with open(f"/sys/class/thermal/{z}/type") as f:
                typ = f.read().strip()
            with open(f"/sys/class/thermal/{z}/temp") as f:
                v = int(f.read().strip())
        except (OSError, ValueError):
            continue
        if v > 0:
            c = round(v / 1000.0, 1)
            if best is None or c > best[1]:
                best = (typ, c)
    return {"type": best[0], "c": best[1]} if best else None


def disk_trend(disk):
    """磁盘用量历史: 每次检查落当天一条(保留 30 天), 线性外推预计满盘日期。"""
    today = time.strftime("%Y-%m-%d")
    hist = []
    try:
        with open(DISK_HISTORY_PATH) as f:
            data = json.load(f)
        if isinstance(data, list):
            hist = [h for h in data if isinstance(h, dict) and "d" in h and "u" in h]
    except (OSError, ValueError):
        hist = []
    hist = [h for h in hist if h.get("d") != today]     # 当天覆盖
    hist.append({"d": today, "u": disk["used"], "t": disk["total"]})
    hist.sort(key=lambda h: h["d"])
    hist = hist[-30:]
    try:
        with open(DISK_HISTORY_PATH + ".tmp", "w") as f:
            json.dump(hist, f)
        os.replace(DISK_HISTORY_PATH + ".tmp", DISK_HISTORY_PATH)
    except OSError:
        pass
    out = {"days": len(hist), "growth_per_day": None, "eta_full": None, "days_left": None}
    if len(hist) >= 2 and disk["total"]:
        first, last = hist[0], hist[-1]
        try:
            span = max(1.0, (datetime.strptime(last["d"], "%Y-%m-%d") -
                             datetime.strptime(first["d"], "%Y-%m-%d")).days)
        except ValueError:
            return out
        growth = (last["u"] - first["u"]) / span
        out["growth_per_day"] = round(growth)
        if growth > 0:
            days_left = max(0.0, (disk["total"] - last["u"]) / growth)
            out["days_left"] = int(days_left)
            out["eta_full"] = (datetime.now() + timedelta(days=days_left)).strftime("%Y-%m-%d")
    return out


def port_heartbeat(entries):
    """已注册服务端口逐个 TCP connect(500ms 超时)标 up/down。"""
    seen, out = set(), []
    for e in entries:
        port = e.get("port")
        if not port or port in seen:
            continue
        seen.add(port)
        up = False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                up = True
        except OSError:
            up = False
        out.append({"port": port, "name": e.get("name") or "?", "up": up})
    out.sort(key=lambda x: x["port"])
    return out


def watchdog_anomalies():
    """最近 1h watchdog 异常计数(只解析 goal-watchdog.log 尾部 256K)。"""
    now = time.time()
    n, sample = 0, []
    try:
        with open(WATCHDOG_LOG, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 256 * 1024))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return {"count": 0, "sample": []}
    for raw in lines:
        m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", raw)
        if not m:
            continue
        try:
            ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
        if now - ts > 3600 or not _WD_BAD.search(raw):
            continue
        n += 1
        if len(sample) < 5:
            sample.append(raw[m.end():].strip()[:120])
    return {"count": n, "sample": sample}


def local_hosts():
    """F4 复制组: 局域网 IP + tailscale IP(UDP connect 探测, 不实际发包)。"""
    lan = ts_ip = None
    for target, out_key in ((("8.8.8.8", 80), "lan"), (("100.100.100.100", 53), "tailscale")):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(target)
            ip = s.getsockname()[0]
            s.close()
        except OSError:
            continue
        if out_key == "lan" and not ip.startswith("127."):
            lan = ip
        elif out_key == "tailscale" and ip.startswith("100."):
            ts_ip = ip
    return {"lan": lan, "tailscale": ts_ip, "hostname": socket.gethostname()}


def health_check():
    """一次性快检: 系统指标 + 磁盘趋势 + 温度 + 关键进程 + 端口心跳 + watchdog 异常。"""
    s = sys_info()
    s["swap"] = swap_info()
    procs = []
    for name, pat in HEALTH_PROCS:
        pid = _proc_alive(pat)
        procs.append({"name": name, "alive": pid is not None, "pid": pid})
    h = {"ok": True, "ts": time.time(), "sys": s, "temp": thermal_read(),
         "procs": procs, "ports": port_heartbeat(gather()),
         "watchdog_1h": watchdog_anomalies(), "hosts": local_hosts()}
    h["disk_trend"] = disk_trend(s["disk"]) if s.get("disk") else {
        "days": 0, "growth_per_day": None, "eta_full": None, "days_left": None}
    disk_p = s["disk"]["percent"] if s.get("disk") else 0
    mem_p = s["mem"]["percent"]
    if disk_p >= 90 or mem_p >= 95 or any(not p["alive"] for p in procs):
        h["overall"] = "bad"
    elif disk_p >= 80 or mem_p >= 85 or h["watchdog_1h"]["count"] > 0:
        h["overall"] = "warn"
    else:
        h["overall"] = "ok"
    return h


# --- F3 垃圾清理(先扫后清, dry_run 默认 true) ---
JOURNAL_KEEP = "200M"
TMP_OLD_DAYS = 7
TMP_EXCLUDE = ("godot-mono", "dbeditor", "map_links")   # in-use 排除
HERMES_OLD_DAYS = 3
OMP_JSONL_OLD_DAYS = 30


def _run(cmd, timeout=10):
    """跑外部命令(免密 sudo 场景), 超时保护, 不抛异常。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not installed"
    except Exception as ex:
        return 1, "", str(ex)[:120]


def _parse_size(s):
    m = re.search(r"([\d.]+)\s*([KMGT]?)", s or "", re.I)
    if not m:
        return 0
    return int(float(m.group(1)) *
               {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2).upper()])


def _dir_size(path, deadline, cap=8000):
    """受截止时间约束的目录大小(超时/超量即停, 单线程)。"""
    total = n = 0
    for root, _dirs, files in os.walk(path):
        if time.time() > deadline:
            break
        for f in files:
            n += 1
            if n > cap:
                return total
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _scan_journal():
    rc, out, err = _run(["sudo", "-n", "journalctl", "--disk-usage"], timeout=10)
    used = _parse_size(out) if rc == 0 else 0
    over = max(0, used - 200 * 1024 ** 2)
    return {"size": over, "count": 1 if over else 0,
            "detail": (out or err).splitlines()[0][:120] if (out or err) else "—"}


def _scan_apt():
    total = n = 0
    d = "/var/cache/apt/archives"
    try:
        for f in os.listdir(d):
            if f.endswith(".deb"):
                try:
                    total += os.path.getsize(os.path.join(d, f))
                    n += 1
                except OSError:
                    pass
    except OSError:
        pass
    return {"size": total, "count": n, "detail": f"/var/cache/apt/archives ({n} .deb)"}


def _tmp_old_paths():
    """/tmp 顶层 >7 天旧项(排除 in-use 名与当天文件)。"""
    deadline = time.time() + 5
    cutoff = time.time() - TMP_OLD_DAYS * 86400
    items = []
    try:
        names = os.listdir("/tmp")
    except OSError:
        return items
    for name in names:
        if time.time() > deadline:
            break
        if any(x in name for x in TMP_EXCLUDE):
            continue
        p = os.path.join("/tmp", name)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if st.st_mtime > cutoff or time.strftime("%Y-%m-%d", time.localtime(st.st_mtime)) == time.strftime("%Y-%m-%d"):
            continue
        if os.path.islink(p) or not os.path.isdir(p):
            items.append((p, st.st_size))
        else:
            items.append((p, _dir_size(p, deadline)))
    return items


def _aged_paths(dirpath, days, suffix=None, recursive=False):
    """目录下(可递归)>N 天的文件。"""
    cutoff = time.time() - days * 86400
    items = []
    if recursive:
        for root, _dirs, files in os.walk(dirpath):
            for f in files:
                p = os.path.join(root, f)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if st.st_mtime <= cutoff and (suffix is None or f.endswith(suffix)):
                    items.append((p, st.st_size))
    else:
        try:
            names = os.listdir(dirpath)
        except OSError:
            return items
        for name in names:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if st.st_mtime <= cutoff:
                items.append((p, st.st_size if not os.path.isdir(p) else _dir_size(p, time.time() + 3)))
    return items


def _binobj_paths():
    """~/development 各仓库 bin/obj 构建产物。"""
    deadline = time.time() + 5
    found = []
    for root, dirs, _files in os.walk(os.path.join(HOME_DIR, "development")):
        if time.time() > deadline:
            break
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv")]
        for d in list(dirs):
            if d in ("bin", "obj"):
                p = os.path.join(root, d)
                found.append((p, _dir_size(p, deadline)))
                dirs.remove(d)
    return found


def _scan_docker():
    rc, out, err = _run(["docker", "system", "df"], timeout=10)
    return {"size": 0, "count": 0, "display_only": True, "raw": (out or err)[:1500],
            "detail": "docker system df(只读, prune 单独按钮)"}


def _wrap_scan(sid, paths_fn, detail_fmt):
    def scan():
        items = paths_fn()
        return {"size": sum(sz for _p, sz in items), "count": len(items),
                "detail": detail_fmt.format(n=len(items))}
    return scan


CLEANUP_SCANS = [
    ("journal", _scan_journal, "journalctl 占用超 200M 的部分"),
    ("apt", _scan_apt, "apt 下载缓存(.deb)"),
    ("tmp_old", _wrap_scan("tmp_old", _tmp_old_paths, "/tmp 超 7 天旧文件({n} 项, 已排除 in-use)"), None),
    ("hermes_cache", _wrap_scan("hermes_cache", lambda: _aged_paths(
        os.path.join(HOME_DIR, ".hermes", "cache", "terminal-output"), HERMES_OLD_DAYS),
        "~/.hermes 终端输出缓存 >3 天({n} 项)"), None),
    ("omp_jsonl", _wrap_scan("omp_jsonl", lambda: _aged_paths(
        os.path.join(HOME_DIR, ".omp", "agent"), OMP_JSONL_OLD_DAYS, suffix=".jsonl", recursive=True),
        "~/.omp 会话 jsonl >30 天({n} 个)"), None),
    ("binobj", _wrap_scan("binobj", _binobj_paths, "仓库构建产物 bin/obj({n} 个, 清后触发重建)"), None),
    ("docker", _scan_docker, "docker 磁盘占用(只读)"),
]


def cleanup_scan():
    items = []
    for sid, scan, _lbl in CLEANUP_SCANS:
        try:
            it = scan()
        except Exception as ex:
            it = {"size": 0, "count": 0, "error": str(ex)[:120]}
        it["id"] = sid
        if sid == "binobj":
            it["safe"] = False   # 默认不勾: 会触发重建
        items.append(it)
    return {"ok": True, "dry_run": True, "items": items,
            "df_free": shutil.disk_usage("/").free}


def _clean_journal():
    before = _scan_journal()["size"]
    rc, out, err = _run(["sudo", "-n", "journalctl", "--vacuum-size", JOURNAL_KEEP], timeout=30)
    freed = max(0, before - _scan_journal()["size"])
    return freed, (out or err or f"rc={rc}")[-160:]


def _clean_apt():
    before = _scan_apt()["size"]
    rc, out, err = _run(["sudo", "-n", "apt-get", "clean"], timeout=30)
    freed = max(0, before - _scan_apt()["size"])
    return freed, (err or out or f"rc={rc}")[-160:]


def _make_path_cleaner(paths_fn):
    def run():
        """执行时服务端重扫(绝不信任客户端路径), 逐路径删除, 单个失败继续。"""
        freed, errs = 0, 0
        for p, sz in paths_fn():
            try:
                if os.path.islink(p) or os.path.isfile(p):
                    os.remove(p)
                elif os.path.isdir(p):
                    shutil.rmtree(p)
                else:
                    continue
                freed += sz
            except OSError:
                errs += 1
        return freed, ("done" if not errs else f"done, {errs} 项失败(权限)")
    return run


CLEANUP_RUNNERS = {
    "journal": _clean_journal,
    "apt": _clean_apt,
    "tmp_old": _make_path_cleaner(_tmp_old_paths),
    "hermes_cache": _make_path_cleaner(lambda: _aged_paths(
        os.path.join(HOME_DIR, ".hermes", "cache", "terminal-output"), HERMES_OLD_DAYS)),
    "omp_jsonl": _make_path_cleaner(lambda: _aged_paths(
        os.path.join(HOME_DIR, ".omp", "agent"), OMP_JSONL_OLD_DAYS, suffix=".jsonl", recursive=True)),
    "binobj": _make_path_cleaner(_binobj_paths),
}


def cleanup_run(ids):
    """逐项真清: 任何一项失败不影响其他项; 附 df 前后对比。"""
    free_before = shutil.disk_usage("/").free
    results = []
    for sid in ids:
        fn = CLEANUP_RUNNERS.get(sid)
        if not fn:
            results.append({"id": sid, "ok": False, "freed": 0, "msg": "unknown item"})
            continue
        try:
            freed, msg = fn()
            results.append({"id": sid, "ok": True, "freed": freed, "msg": msg})
        except Exception as ex:
            results.append({"id": sid, "ok": False, "freed": 0, "msg": str(ex)[:160]})
    free_after = shutil.disk_usage("/").free
    return {"ok": True, "dry_run": False, "results": results,
            "df_freed": max(0, free_after - free_before)}


def docker_prune():
    """docker system prune -f(悬空资源; prune 按钮单独, 前端二次确认)。"""
    rc, out, err = _run(["docker", "system", "prune", "-f"], timeout=120)
    return {"ok": rc == 0, "msg": (out or err or f"rc={rc}")[-400:]}


# --- G3 网络速测 ---
NET_TEST_URL = "https://github.com/git/git/releases/latest"


def _tailscale(cmd, timeout=8):
    rc, out, err = _run(cmd, timeout=timeout)
    if rc != 0 and not out:   # 权限不足 → 免密 sudo 重试
        rc2, out2, _e2 = _run(["sudo", "-n"] + cmd, timeout=timeout)
        if rc2 == 0:
            return 0, out2, ""
    return rc, out, err


def ts_ping():
    """tailscale status 取对端, tailscale ping 测对端延迟。"""
    rc, out, err = _tailscale(["tailscale", "status"])
    if rc != 0:
        return {"ok": False, "peer": None, "rtt_ms": None, "msg": (err or f"rc={rc}")[:120]}
    peer = None
    for line in out.splitlines()[1:]:
        parts = line.split()
        if parts and parts[0].count(".") == 3 and not parts[0].startswith("100.100.100.100"):
            peer = parts[0].split(":")[0]
            break
    if not peer:
        return {"ok": True, "peer": None, "rtt_ms": None, "msg": "no peers"}
    rc, out, err = _tailscale(["tailscale", "ping", "--timeout", "3s", "-c", "1", peer])
    m = re.search(r"in ([\d.]+)\s*(ms|s)\b", out)
    if m:
        return {"ok": True, "peer": peer,
                "rtt_ms": round(float(m.group(1)) * (1000 if m.group(2) == "s" else 1), 1)}
    return {"ok": False, "peer": peer, "rtt_ms": None, "msg": (out or err or f"rc={rc}")[:120]}


def net_test():
    """外网 HEAD 延迟(3 次取最小) + tailscale 对端 ping。"""
    import urllib.request
    lat, err = [], ""
    for _ in range(3):
        t0 = time.time()
        try:
            req = urllib.request.Request(
                NET_TEST_URL, method="HEAD",
                headers={"User-Agent": f"svc-dashboard/{server_ver()}"})
            with urllib.request.urlopen(req, timeout=8):
                pass
            lat.append(round((time.time() - t0) * 1000))
        except Exception as ex:
            err = str(ex)[:120]
            break
    return {"ok": bool(lat), "latency_ms": min(lat) if lat else None,
            "samples": lat, "error": err, "tailscale": ts_ping()}


def server_ver():
    return Handler.server_version.split("/")[1]


# --- G2 用户级服务重启(默认隐藏, 前端 I-KNOW 解锁) ---


def _usvc_cmd(args, timeout):
    return _run(["sudo", "-n", "-u", "tetsuya", "env",
                 "XDG_RUNTIME_DIR=/run/user/1000"] + args, timeout=timeout)


def user_services():
    rc, out, _err = _usvc_cmd(["systemctl", "--user", "list-units", "--type=service",
                               "--all", "--no-legend", "--plain"], timeout=6)
    units = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            if "svc-dashboard" in parts[0]:   # 自身除外(且自身为系统级服务)
                continue
            units.append({"unit": parts[0], "active": parts[2], "sub": parts[3],
                          "desc": parts[4].strip() if len(parts) > 4 else ""})
    return units


def user_service_action(unit, action):
    if action not in ("restart", "start", "stop"):
        return {"ok": False, "msg": "bad action"}
    if not unit.endswith(".service") or "svc-dashboard" in unit:
        return {"ok": False, "msg": "unit not allowed"}
    if unit not in {u["unit"] for u in user_services()}:
        return {"ok": False, "msg": "unknown unit"}
    rc, out, err = _usvc_cmd(["systemctl", "--user", action, unit], timeout=20)
    return {"ok": rc == 0, "msg": (out or err or ("ok" if rc == 0 else f"rc={rc}"))[:200]}



def tool_ports_alive():
    """G1 chips 端口存活(服务端 TCP connect 300ms, 浏览器端零 console 噪声)。"""
    alive = []
    for _name, port in tools_conf()["g1"]:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                alive.append(port)
        except OSError:
            pass
    return {"ok": True, "alive": alive}

def tools_conf():
    """页面内嵌工具配置: 白名单根 + 主机地址 + G1 chips 端口表。"""
    return {"fs_roots": FS_ROOTS,
            "hosts": local_hosts(),
            "g1": [["dbeditor", 8810], ["mapviewer", 8899], ["wilviewer", 8765],
                   ["uieditor", 8820], ["dbviewer", 8800], ["webclient", 8822],
                   ["yomu", 8830], ["fudoki", 8831]]}

class Handler(BaseHTTPRequestHandler):
    server_version = "svc-dashboard/1.0"

    def _host(self):
        return self.headers.get("Host") or f"localhost:{LISTEN_PORT}"

    def _client_ip(self):
        """客户端来源 IP：X-Forwarded-For 优先（反代场景），否则直连地址。"""
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0] if self.client_address else ""

    def _is_tailscale_client(self):
        """来源在 Tailscale CGNAT 段 100.64.0.0/10 内 → 页面链接切到 tailscale 主机名。"""
        try:
            import ipaddress
            return ipaddress.ip_address(self._client_ip()) in ipaddress.ip_network("100.64.0.0/10")
        except ValueError:
            return False

    def _send_json(self, code, obj):
        """发 JSON 响应,自带 no-store。任何异常都不让连接挂起。"""
        try:
            payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        except Exception:
            payload = b'{"ok":false,"msg":"encode error"}'
            code = 500
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception:
            pass  # 连接已断,无能为力

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            self._handle_get(path)
        except Exception as e:
            self._send_json(500, {"ok": False, "msg": f"server error: {e}"})

    def _handle_get(self, path):
        if path in ("/", "/index.html"):
            lang = detect_lang(self.headers.get("Accept-Language", ""),
                               urlparse(self.path).query)
            entries = gather()
            body = render_html(self._host(), entries, time.time(), lang,
                               sysdata=sys_info(),
                               ts_mode=self._is_tailscale_client()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api":
            self._send_json(200, {"updated": time.time(), "services": gather()})
        elif path == "/api/sys":
            self._send_json(200, sys_info())
        elif path == "/api/goals":
            # limit 控制事件条数(手机日志页 24h-7d 时间窗需要更多条目)
            qs = parse_qs(urlparse(self.path).query)
            try:
                lim = max(1, min(200, int((qs.get("limit") or ["24"])[0])))
            except ValueError:
                lim = 24
            self._send_json(200, {"updated": time.time(), "goals": scan_goals(),
                                  "completed": parse_completed_goals(limit=lim),
                                  "events": merge_events(
                                      parse_watchdog_events(limit=min(lim, 80)),
                                      parse_completed_goals(limit=lim), limit=lim)})
        elif path == "/api/tasks":
            lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
            self._send_json(200, {"tasks": scan_tasks(lang)})
        elif path == "/api/omp":
            self._send_json(200, {"updated": time.time(), "omp": scan_omp(),
                                  "codex": scan_codex()})
        elif path == "/api/tmux":
            self._send_json(200, {"updated": time.time(), "panes": scan_tmux()})
        elif path == "/api/manage":
            qs = parse_qs(urlparse(self.path).query)
            uid = (qs.get("unit") or [""])[0]
            lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
            if not uid:
                self._send_json(200, {"units": [{"id": u["id"], "label": u["label"], "desc": u["desc"]}
                               for u in MANAGE_UNITS]})
            else:
                self._send_json(200, manage_status(uid, lang))
        elif path.startswith("/api/agentlog"):
            qs = parse_qs(urlparse(self.path).query)
            sid = (qs.get("sid") or [""])[0]
            cwd = (qs.get("cwd") or [""])[0]
            tmx = (qs.get("tmux") or [""])[0]
            if not tmx and cwd:
                tmx = _tmux_by_cwd(cwd)
            lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
            self._send_json(200, {"events": scan_agent_log(sid, lang) if sid else [],
                    "capture": _tmux_capture(tmx)})
        elif path == "/api/fs/list":
            qs = parse_qs(urlparse(self.path).query)
            p = (qs.get("path") or [""])[0]
            data = fs_list(p)
            if not data.get("ok"):
                self.log_message("fs/list rejected %r -> 404", p[:160])
                self._send_json(404, data)
            else:
                self._send_json(200, data)
        elif path == "/api/fs/file":
            self._fs_file()
        elif path == "/api/fs/du":
            qs = parse_qs(urlparse(self.path).query)
            self._send_json(200, fs_du((qs.get("path") or [""])[0]))
        elif path == "/api/health":
            self._send_json(200, health_check())
        elif path == "/api/nettest":
            self._send_json(200, net_test())
        elif path == "/api/toolports":
            self._send_json(200, tool_ports_alive())
        elif path == "/api/uservice":
            self._send_json(200, {"ok": True, "units": user_services()})
        else:
            self.send_error(404)

    def _fs_file(self):
        """GET /api/fs/file?path=&mode=view|download
        view+text -> JSON; 图片直显; download/二进制 -> attachment 流式。"""
        qs = parse_qs(urlparse(self.path).query)
        p = (qs.get("path") or [""])[0]
        mode = (qs.get("mode") or ["view"])[0]
        real = fs_resolve(p)
        if not real or not os.path.isfile(real):
            self.log_message("fs/file rejected %r mode=%s -> 404", p[:160], mode)
            self.send_error(404)
            return
        kind, mime = fs_meta(real)
        if mode == "view" and kind == "text":
            try:
                with open(real, "rb") as f:
                    text = f.read().decode("utf-8", "replace")
                self._send_json(200, {"ok": True, "name": os.path.basename(real),
                                      "size": len(text), "text": text[:512 * 1024]})
            except OSError as ex:
                self._send_json(500, {"ok": False, "msg": str(ex)})
            return
        try:
            size = os.path.getsize(real)
            self.send_response(200)
            ctype = mime if (mode != "download" and kind == "image") else "application/octet-stream"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            if mode == "download" or kind == "binary":
                fn = os.path.basename(real)
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", fn) or "download"
                from urllib.parse import quote
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{safe}"; filename*=UTF-8\'\'{quote(fn)}')
            self.end_headers()
            with open(real, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (OSError, BrokenPipeError) as ex:
            self.log_message("fs/file stream error: %s", ex)

    def do_POST(self):
        """写端点: /api/manage(服务管理) /api/cleanup(dry_run 默认 true)
        /api/uservice(用户级服务重启, 前端 I-KNOW 护栏)"""
        path = urlparse(self.path).path
        if path not in ("/api/manage", "/api/cleanup", "/api/uservice"):
            self.send_error(404)
            return
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(ln) if ln else b""
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception as e:
            lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
            self._send_json(400, {"ok": False, "msg": t(lang, "m_badreq", e=str(e))})
            return
        lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
        if path == "/api/manage":
            unit = str(body.get("unit") or "")
            action = str(body.get("action") or "")
            self.log_message("manage %s %s", unit, action)
            try:
                self._send_json(200, manage_action(unit, action, lang))
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
        elif path == "/api/cleanup":
            dry = body.get("dry_run", True) is not False   # 默认 dry_run!
            action = str(body.get("action") or "")
            items = [str(x) for x in (body.get("items") or [])][:16] if isinstance(body.get("items"), list) else []
            self.log_message("cleanup action=%s dry_run=%s items=%s", action, dry, items)
            try:
                if action == "docker_prune":
                    self._send_json(200, docker_prune())
                elif dry:
                    self._send_json(200, cleanup_scan())
                else:
                    self._send_json(200, cleanup_run(items))
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
        elif path == "/api/uservice":
            unit = str(body.get("unit") or "")
            action = str(body.get("action") or "")
            self.log_message("uservice %s %s", unit, action)
            try:
                self._send_json(200, user_service_action(unit, action))
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))


def selftest():
    """离线自检: 纯函数单测 + 真实数据源 dry-run,全部通过返回 0。"""
    import unittest

    class T(unittest.TestCase):
        def test_ctx(self):
            self.assertEqual(parse_ctx_k("╭── π ZAI Preview > Goal 45K > ~/x ────╮"), 45.0)
            self.assertEqual(parse_ctx_k("── 554K ──╮"), 554.0)
            self.assertEqual(parse_ctx_k("Goal 1.2M"), 1.2 * 1024)
            self.assertIsNone(parse_ctx_k("no header here"))
            self.assertEqual(ctx_level(45), "ok")
            self.assertEqual(ctx_level(801), "warn")   # >800K 黄
            self.assertEqual(ctx_level(1201), "stop")  # >1.2M 红

        def test_retry_progress(self):
            self.assertEqual(parse_retry("API error. Retrying (3)/10 in 5s"), "3")
            self.assertEqual(parse_retry("Retrying (7/10)…"), "7")
            self.assertIsNone(parse_retry("no retry"))
            self.assertTrue(parse_progress(
                "╭─── Todo 12 tasks ───╮\n│ II. Phase 1  3/3   │\n"
                "│   ├─ Browser E2E: import roundtrip + no-resurrect │\n"
                "╰─────────────────────╯"))

        def test_load_zone(self):
            self.assertEqual(load_zone(2.0), ("ok", 2))
            self.assertEqual(load_zone(5.9), ("ok", 1))
            self.assertEqual(load_zone(6.0), ("full", 0))
            self.assertEqual(load_zone(12.4), ("over", 0))

        def test_wd_parse(self):
            line = ("2026-08-14 08:15:10 [019ffbaf] resumed 019ffbaf-4c8d in %30; "
                    "sent '继续' to drive agent")
            m = _WD_LINE_RE.match(line)
            self.assertTrue(m)
            self.assertEqual(_wd_event_kind("goal paused: pid=1; driving with '继续'"), "nudge")

        def test_completed(self):
            with open(GOAL_COMPLETED_LOG) as f:
                real = f.read()
            # 真实台账能解析出完成项,且字段齐全
            entries = parse_completed_goals()
            if "Zircon全代码文档化" in real:
                self.assertTrue(any("Zircon" in c["label"] for c in entries))
                self.assertTrue(entries[0]["resume_cmd"].startswith(OMP_BIN))

    suite = unittest.TestLoader().loadTestsFromTestCase(T)
    unittest.TextTestRunner(verbosity=2).run(suite)
    # dry-run 真实数据源
    print("\n--- live dry-run ---")
    goals = scan_goals()
    print(f"goal cards: {len(goals)}")
    for g in goals:
        print(f"  {g['name']}: light={g['light']} ctx={g['ctx_raw'] or '—'} "
              f"idle={g['idle_sec']}s retry={g['retry']} prog={len(g['progress'])}")
    s = sys_info()
    gl = s["goalload"]
    print(f"load: {gl['load15']} ({gl['zone']}, n={gl['n']}) cpu_top={gl['cpu_top'][:3]}")
    evts = merge_events(parse_watchdog_events(), parse_completed_goals())
    kinds = {e["kind"] for e in evts}
    print(f"events: {len(evts)} kinds={sorted(kinds)}")
    html = render_html("localhost:8899", gather(), time.time(), "zh", sysdata=s)
    checks = ["Goal 进度", "建议并发", "已完成 goal", "最近事件", "tchip"]
    for c in checks:
        mark = "ok" if c in html else "FAIL"
        print(f"  {mark} html contains {c!r}")
    ok = all(c in html for c in checks)
    return 0 if ok else 1


def main():
    args = sys.argv[1:]
    port = DEFAULT_PORT
    if "--port" in args:
        try:
            port = int(args[args.index("--port") + 1])
        except (ValueError, IndexError):
            print("用法: dashboard.py [--port N] [--scan] [--selftest]")
            return 2
    if "--scan" in args:
        print(json.dumps({"services": gather()}, ensure_ascii=False, indent=2))
        return 0
    if "--selftest" in args:
        return selftest()

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
