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
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

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
        # docker-proxy / rootlesskit 是宿主机进程,但端口属于容器发布
        if e["type"] == "direct" and e["name"] in ("docker-proxy", "rootlesskit", "rootlessport") \
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
        cmd_shown = cmd[:90] + ("…" if len(cmd) > 90 else "")
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
            f'<td class="cmd" title="{cmd}">{cmd_shown}</td>'
            f'<td class="cwd" title="{cwd}">{cwd}</td>'
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
         background: #0f172a; color: #e2e8f0; }
  header { position: sticky; top: 0; z-index: 10; background: #0f172aee; backdrop-filter: blur(6px);
           border-bottom: 1px solid #1e293b; padding: 12px 24px;
           display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  header h1 { font-size: 17px; margin: 0; font-weight: 600; }
  header .meta { color: #94a3b8; font-size: 12.5px; }
  header .spacer { flex: 1; }
  button { background: #2563eb; color: #fff; border: 0; border-radius: 8px; padding: 7px 14px;
           font-size: 13px; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  button.spinning { opacity: .7; }
  label.auto { font-size: 13px; color: #cbd5e1; display: flex; align-items: center; gap: 6px; cursor: pointer; }
  main { padding: 16px 24px 40px; }
  .sysbar { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
  .stat { background: #111c33; border: 1px solid #1e293b; border-radius: 10px;
          padding: 10px 16px; min-width: 130px; }
  .stat .label { color: #64748b; font-size: 11px; margin-bottom: 3px; }
  .stat .value { font-size: 14px; font-weight: 600; font-family: ui-monospace, monospace; color: #e2e8f0; white-space: nowrap; }
  .filters { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .chip { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; border-radius: 999px;
          padding: 5px 14px; font-size: 12.5px; cursor: pointer; }
  .chip:hover { background: #263449; }
  .chip.active { background: #2563eb; border-color: #2563eb; color: #fff; }
  .chip span { opacity: .7; margin-left: 4px; font-size: 11px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th { text-align: left; color: #94a3b8; font-weight: 500; font-size: 12px;
             padding: 8px 10px; border-bottom: 1px solid #1e293b; position: sticky; top: 52px;
             background: #0f172a; }
  tbody td { padding: 9px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; }
  tbody tr:hover { background: #16213d; }
  .name { white-space: nowrap; }
  .svc { font-weight: 600; }
  .port a { color: #38bdf8; font-weight: 600; text-decoration: none; font-family: ui-monospace, monospace; font-size: 14px; }
  .port a:hover { text-decoration: underline; }
  .addr, .pid { color: #94a3b8; font-family: ui-monospace, monospace; white-space: nowrap; }
  .cmd, .cwd { color: #cbd5e1; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, monospace; }
  .badge { display: inline-block; margin-left: 8px; padding: 2px 7px; border-radius: 999px;
           font-size: 11px; font-weight: 500; vertical-align: 1px; }
  .badge-docker  { background: #1e3a8a33; color: #93c5fd; border: 1px solid #1e40af66; }
  .badge-systemd { background: #064e3b33; color: #6ee7b7; border: 1px solid #065f4666; }
  .badge-direct  { background: #33415533; color: #94a3b8; border: 1px solid #47556966; }
  .badge-self    { background: #4c1d9533; color: #c4b5fd; border: 1px solid #5b21b666; }
  .detail { display: block; color: #64748b; font-size: 11px; font-family: ui-monospace, monospace; margin-top: 2px; }
  .local { color: #f59e0b; font-size: 11px; }
  .empty { color: #64748b; text-align: center; padding: 48px 0; }
  @media (max-width: 900px) { .cmd, .cwd { max-width: 140px; } }
</style>
</head>
<body>
<header>
  <h1>🖥 服务一览</h1>
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
</div>
<table id="svc">
  <thead><tr>
    <th>服务</th><th>端口</th><th>监听地址</th><th>PID</th><th>启动命令</th><th>工作目录</th>
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
  all:    () => true,
};

function row(e) {
  const badge = {docker:["容器","badge-docker"], systemd:["systemd","badge-systemd"], direct:["进程","badge-direct"]}[e.type] || ["进程","badge-direct"];
  let text = badge[0], detail = "";
  if (e.is_self) { text = "本页"; badge[1] = "badge-self"; }
  else if (e.docker_proxy) { text = "Docker映射"; }
  else if (e.type === "docker" && e.container_id) detail = `<span class="detail" title="容器ID">${e.container_id}</span>`;
  else if (e.type === "systemd" && e.unit) detail = `<span class="detail" title="systemd 单元">${e.unit}</span>`;
  const ip = e.ip;
  const loopback = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
  const link = loopback ? `http://127.0.0.1:${e.port}/` : `http://${location.hostname}:${e.port}/`;
  const loop = loopback ? ' <span class="local">仅本机</span>' : "";
  const cmd = e.cmdline || "—";
  const cmdShown = cmd.length > 90 ? cmd.slice(0, 90) + "…" : cmd;
  const esc = (s) => s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  return `<tr>
    <td class="name"><span class="svc">${esc(e.name)}</span><span class="badge ${badge[1]}">${text}</span>${detail}</td>
    <td class="port"><a href="${link}" target="_blank" rel="noopener">${e.port}</a></td>
    <td class="addr">${esc(ip)}${loop}</td>
    <td class="pid">${e.pids.join(", ")}</td>
    <td class="cmd" title="${esc(cmd)}">${esc(cmdShown)}</td>
    <td class="cwd" title="${esc(e.cwd || "")}">${esc(e.cwd || "—")}</td>
  </tr>`;
}

function applyFilter() {
  const shown = services.filter(FILTERS[filter]);
  ["user", "docker", "system", "all"].forEach(f =>
    $("n-" + f).textContent = services.filter(FILTERS[f]).length);
  document.querySelectorAll(".chip").forEach(c =>
    c.classList.toggle("active", c.dataset.f === filter));
  const tbody = $("svc").querySelector("tbody");
  tbody.innerHTML = shown.length ? shown.map(row).join("") :
    '<tr><td class="empty" colspan="6">没有匹配的服务</td></tr>';
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
    `<div class="stat"><div class="label">${l}</div><div class="value">${v}</div></div>`).join("");
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
    _priv["map"] = _run_sudo_ss()  # 启动前同步预热,首个请求即有完整数据
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
