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
from datetime import datetime
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
    return '<div class="sysbar" id="sysbar">' + "".join(
        f'<div class="stat" data-k="{k}"><div class="label">{lbl}</div>'
        f'<div class="value">{val}</div></div>' for k, lbl, val in cards) + "</div>"


# ---------------- 国际化 ----------------
# 三语(中文 / English / 日本語),按 Accept-Language 自动切换,?lang= 可强制覆盖。

L10N = {
    "zh": {
        "title": "服务一览", "github_repo": "GitHub 仓库",
        "updated": "更新于", "svc_pre": "", "svc_post": " 个监听端口", "auto_refresh": "自动刷新",
        "refresh": "⟳ 刷新", "ptr_pull": "下拉刷新", "ptr_release": "松开刷新", "ptr_loading": "刷新中…",
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
        "aev_exit": "✕ 会话结束: {r}", "aev_goal": "🔀 目标: {o}", "aev_comp": "↻ 压缩: {s}",
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
        "g_done_fold": "✅ 已完成 goal（{n}）",
        "ld_title": "建议并发", "ld_ok": "还可开 {n} 个 goal",
        "ld_full": "满载，别再开了", "ld_over": "过载，先别开",
        "ld_load": "load15 {l} / {c}核",
        "ld_cpu": "CPU top5", "ld_mem": "内存 top5",
        "ev_title": "最近事件", "ev_hint": "watchdog 动作 + goal 完成台账",
        "ev_complete": "✅ 完成", "ev_restart": "🔄 watchdog 重启",
        "ev_nudge": "🔔 watchdog 催行", "ev_recover": "🟢 已恢复",
        "ev_pause": "⏸ 目标暂停", "ev_cleanup": "🧹 清理",
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
        "ev_commit": "📦 提交",
        "evk_complete": "完成", "evk_restart": "重启(进程死亡)",
        "evk_nudge": "催行", "evk_recover": "已恢复", "evk_pause": "暂停",
        "evk_cleanup": "清理", "evk_commit": "提交", "evk_other": "其他",
        "g_ago_d": "{d} 天前",
    },
    "en": {
        "title": "Services", "github_repo": "GitHub repo",
        "updated": "updated", "svc_pre": "", "svc_post": " listening ports", "auto_refresh": "Auto refresh",
        "refresh": "⟳ Refresh", "ptr_pull": "Pull to refresh", "ptr_release": "Release to refresh", "ptr_loading": "Refreshing…",
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
        "aev_exit": "✕ session ended: {r}", "aev_goal": "🔀 Goal: {o}", "aev_comp": "↻ Compaction: {s}",
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
        "g_done_fold": "✅ Completed goals ({n})",
        "ld_title": "Concurrency", "ld_ok": "room for {n} more goal(s)",
        "ld_full": "at capacity, no more goals", "ld_over": "overloaded, hold off",
        "ld_load": "load15 {l} / {c} cores",
        "ld_cpu": "CPU top5", "ld_mem": "Memory top5",
        "ev_title": "Recent events", "ev_hint": "watchdog actions + completions",
        "ev_complete": "✅ complete", "ev_restart": "🔄 watchdog restart",
        "ev_nudge": "🔔 watchdog nudge", "ev_recover": "🟢 recovered",
        "ev_pause": "⏸ goal paused", "ev_cleanup": "🧹 cleanup",
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
        "ev_commit": "📦 commit",
        "evk_complete": "complete", "evk_restart": "relaunch (dead)",
        "evk_nudge": "nudge", "evk_recover": "recovered", "evk_pause": "paused",
        "evk_cleanup": "cleanup", "evk_commit": "commit", "evk_other": "other",
        "g_ago_d": "{d}d ago",
    },
    "ja": {
        "title": "サービス一覧", "github_repo": "GitHub リポジトリ",
        "updated": "更新", "svc_pre": "サービス ", "svc_post": "", "auto_refresh": "自動更新",
        "refresh": "⟳ 更新", "ptr_pull": "引っ張って更新", "ptr_release": "離して更新", "ptr_loading": "更新中…",
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
        "aev_exit": "✕ セッション終了: {r}", "aev_goal": "🔀 目標: {o}", "aev_comp": "↻ 圧縮: {s}",
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
        "g_done_fold": "✅ 完了済み goal（{n}）",
        "ld_title": "推奨同時実行",
        "ld_full": "満杯、これ以上は不可", "ld_over": "過負荷、控えて",
        "ld_load": "load15 {l} / {c}コア",
        "ld_cpu": "CPU top5", "ld_mem": "メモリ top5",
        "ev_title": "最近のイベント", "ev_hint": "watchdog 操作 + 完了台帳",
        "ev_complete": "✅ 完了", "ev_restart": "🔄 watchdog 再起動",
        "ev_nudge": "🔔 watchdog 促し", "ev_recover": "🟢 復旧",
        "ev_pause": "⏸ goal 一時停止", "ev_cleanup": "🧹 クリーンアップ",
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
        "ev_commit": "📦 コミット",
        "evk_complete": "完了", "evk_restart": "再始動(プロセス死亡)",
        "evk_nudge": "催促", "evk_recover": "復旧", "evk_pause": "一時停止",
        "evk_cleanup": "クリーンアップ", "evk_commit": "コミット", "evk_other": "その他",
        "g_ago_d": "{d} 日前",
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
            return ("tool", f"[{ts}] ⚙ {data.get('toolName', '—')}")
        if "tool_execution_end" in ct:
            return ("tool", f"[{ts}] ✓ {data.get('toolName', '—')}")
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
    light = {"active": ("🟢", "g_active"), "paused": ("🟡", "g_paused"),
             "retry": ("🟠", "g_retry"), "done": ("✅", "g_done"),
             "lost": ("⚠️", "g_lost")}
    out = []
    for c in cards:
        icon, key = light.get(c["light"], ("⚠️", "g_lost"))
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
        more = (f'<span class="gmore" title="{t(lang, "g_detail")}">▸</span>') if extra else ""
        head = (f'<div class="ghead"><span class="glight">{icon}</span>'
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
                    f'data-cmd="{escape(c["resume_cmd"], quote=True)}">⧉ {t(lang, "g_copy")}</span></div>')
        inner += foot
        # 手机端左滑露「复制 resume」: .swipe-bg 静止在卡片下,.swipe-fg 跟手平移
        back = (f'<div class="swipe-bg"><span class="swipe-act" role="button" tabindex="0" '
                f'data-copy="{escape(c["resume_cmd"], quote=True)}">⧉ {t(lang, "g_copy")}</span></div>'
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
        fold = (f'<details class="gdone"><summary>{t(lang, "g_done_fold", n=len(completed))}</summary>'
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
    icon, color = {"ok": ("🟢", "#6ec89a"), "full": ("🟡", "#e0b060"),
                   "over": ("🔴", "#e06c6c")}.get(zone, ("⚪", "#8a8a8a"))
    load15 = gl.get("load15")
    sub = t(lang, "ld_load", l=(f"{load15:.1f}" if load15 is not None else "—"),
            c=gl.get("cores", "?"))

    def top_rows(items, fmt):
        if not items:
            return f'<div class="ld-row" style="color:#666">—</div>'
        return "".join(f'<div class="ld-row"><span class="ld-val">{fmt(v)}</span>'
                       f'<span class="ld-name">{escape(k)}</span></div>' for v, k in items)

    cpu_rows = top_rows(gl.get("cpu_top") or [], lambda v: f"{v:.0f}%")
    mem_rows = top_rows(gl.get("mem_top") or [], lambda v: f"{v / 1024:.1f}G" if v >= 1024 else f"{v:.0f}M")
    return (f'<div class="gpanel loadline" id="loadline">'
            f'<div class="ld-head"><span class="ld-ico" style="color:{color}">{icon}</span>'
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
        f'{name} :{port} ↗</a>'
        for name, port in TOOL_LINKS if port in ports)
    if not chips:
        return ""
    return f'<div class="filters toolchips" id="toolchips">{chips}</div>'


def render_events(events, lang=DEFAULT_LANG):
    """最近事件: watchdog 动作 + 完成台账,合并时间倒序。"""
    kind_key = {"complete": "ev_complete", "restart": "ev_restart",
                "nudge": "ev_nudge", "recover": "ev_recover",
                "pause": "ev_pause", "cleanup": "ev_cleanup", "commit": "ev_commit"}
    rows = []
    today = time.strftime("%Y-%m-%d")
    for e in events:
        try:
            ts_str = e["time"]
            show = ts_str[11:16] if ts_str[:10] == today else ts_str[5:16]
        except Exception:
            show = "—"
        label = t(lang, kind_key.get(e["kind"], "ev_other"))
        rows.append(f'<div class="evt-row"><span class="evt-ts">{escape(show)}</span>'
                    f'<span class="evt-name">[{escape(e["name"])}]</span>'
                    f'<span class="evt-txt">{escape(label)} {escape(e["text"][:110])}</span></div>')
    body = "".join(rows) if rows else f'<div class="gempty">{t(lang, "ev_none")}</div>'
    return (f'<div class="gpanel" id="events"><h2>{t(lang, "ev_title")} '
            f'<span class="ghint">{t(lang, "ev_hint")}</span></h2>{body}</div>')

def render_html(host_header, entries, updated_ts, lang=DEFAULT_LANG, sysdata=None):
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
            .replace("{{T_JSON}}", json.dumps(L10N.get(lang, L10N[DEFAULT_LANG]), ensure_ascii=False))
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
    return _apply_t(body, lang)


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="{{LANG}}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0a0a0a">
<title>{{T:title}} · {{HOSTNAME}}</title>
<link rel="icon" href="data:,">
<style>
  :root { color-scheme: dark;
          /* 语义色规约: 红=严重 黄=关注 绿=正常 灰=历史 蓝=交互。
             文本档均按 WCAG AA(≥4.5:1)对 #101010-#141414 卡片底校准。 */
          --c-red: #e06c6c; --c-red-bg: #2a1a1a;
          --c-warn: #f0b662; --c-warn-bg: #2a2118;
          --c-green: #6ec89a; --c-green-bg: #14261c;
          --c-gray: #9a9a9a; --c-blue: #8ab4f8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background: #0a0a0a; color: #d6d6d6; }
  header { position: sticky; top: 0; z-index: 10; background: rgba(10,10,10,.9); backdrop-filter: blur(6px);
           border-bottom: 1px solid #1f1f1f; padding: 12px 24px;
           display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  header h1 { font-size: 17px; margin: 0; font-weight: 600; color: #f2f2f2; }
  header .meta { color: #a8a8a8; font-size: 12.5px; }  /* 8.3:1 (was #8a8a8a) */
  header .spacer { flex: 1; }
  /* ---------------- 自绘控件体系 ----------------
     不使用任何系统原生控件: 所有按钮/开关均为自绘元素。
     span[role=button] 语义: 可点击;键盘 Enter/Space 由全局委托触发 click。 */
  .btn, .chip, .tcol, .ctl-btn, .mbtn, .aglog-refresh {
    display: inline-flex; align-items: center; justify-content: center; gap: 6px;
    user-select: none; -webkit-user-select: none; touch-action: manipulation;
    cursor: pointer; transition: background .12s, border-color .12s, color .12s, transform .05s; }
  .btn { background: #262626; color: #eee; border: 1px solid #333; border-radius: 8px; padding: 7px 14px;
         font-size: 13px; }
  .btn:hover { background: #333; }
  .btn:active { background: #3a3a3a; transform: translateY(1px); }
  .btn.spinning { opacity: .7; }
  /* 移动端下拉刷新指示器；默认完全收起，桌面端不注册事件。 */
  #ptr-indicator { position: fixed; top: 0; left: 50%; z-index: 30;
    width: 132px; height: 48px; margin-left: -66px; margin-top: -48px;
    display: flex; align-items: center; justify-content: center; gap: 8px;
    background: #141414; border: 1px solid #2c2c2c; border-top: 0;
    border-radius: 0 0 12px 12px; color: #aaa; font-size: 12px;
    transform: translateY(0); transition: transform .22s ease, color .15s ease; }
  #ptr-indicator .ptr-arrow { display: inline-block; font-size: 20px; line-height: 1;
    transform: rotate(0deg); transition: transform .12s linear; }
  #ptr-indicator.ready { color: #8ab4f8; }
  #ptr-indicator.loading { color: #6ec89a; }
  #ptr-indicator.loading .ptr-arrow { animation: ptr-spin .8s linear infinite; }
  @keyframes ptr-spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) {
    #ptr-indicator, #ptr-indicator .ptr-arrow { transition: none; }
    #ptr-indicator.loading .ptr-arrow { animation: none; }
  }
  .btn[aria-disabled="true"], .btn.disabled { opacity: .5; cursor: default; pointer-events: none; }
  .btn:focus-visible, .chip:focus-visible, .tcol:focus-visible,
  .ctl-btn:focus-visible, .mbtn:focus-visible, .aglog-refresh:focus-visible {
    outline: 2px solid #4a90d9; outline-offset: 2px; }
  .auto { font-size: 13px; color: #b0b0b0; display: flex; align-items: center; gap: 8px; cursor: pointer; }
  .sw { position: relative; display: inline-flex; width: 40px; height: 22px; flex: none;
        background: #2e2e2e; border: 1px solid #444; border-radius: 999px; cursor: pointer;
        transition: background .18s, border-color .18s; }
  .sw .sw-thumb { position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%;
                  background: #9a9a9a; transition: transform .18s, background .18s; }
  .sw[aria-checked="true"] { background: #2e7d4f; border-color: #3a9a63; }
  .sw[aria-checked="true"] .sw-thumb { transform: translateX(18px); background: #fff; }
  .sw:focus-visible { outline: 2px solid #4a90d9; outline-offset: 2px; }
  main { padding: 16px 24px 40px; }

  /* ---------------- 移动 App 化基础(桌面端多数隐藏) ----------------
     字号走 rem(html=100%),尊重系统字体大小设置;
     手势元素(滑动露按钮/页签栏/图表/骨架屏)仅手机布局出现。 */
  [hidden] { display: none !important; }  /* 防 class 的 display:flex 盖过 hidden 属性 */
  html { font-size: 100%; -webkit-text-size-adjust: 100%; }
  #pages { display: contents; }          /* 桌面: 透明容器,子元素即 main 内容 */
  #tabbar, #chart-wrap, #logpage, #agents-page,
  .skel, .gmore, .statusline, .statuscard, .mgrid4, #alerts, #recent,
  #log-filters, .lv { display: none; }
  .gextra { display: block; }            /* 桌面: goal 卡次要信息全展示 */
  .swipe-item { position: relative; overflow: hidden; }
  .swipe-bg { position: absolute; inset: 0; display: flex; align-items: stretch;
              justify-content: flex-end; background: #14261c; }
  .swipe-act { display: inline-flex; align-items: center; justify-content: center;
               min-width: 88px; padding: 0 14px; background: #2e7d4f; color: #fff;
               font-size: 12.5px; white-space: nowrap; }
  .swipe-fg { position: relative; background: #131313; will-change: transform;
              transition: transform .18s ease; }
  .swipe-fg.stick { transition: none; }  /* 跟手阶段禁过渡 */
  .svc-open { display: inline-flex; align-items: center; justify-content: center;
              width: 44px; height: 44px; border-radius: 50%; flex: none;
              background: #1d2733; border: 1px solid #2c3a4d; color: #9db8d9;
              font-size: 17px; text-decoration: none; }
  .skel { display: none; }
  .skel-line { height: 14px; border-radius: 6px; margin: 10px 0;
               background: #1a1a1a; animation: skel-pulse 1.1s ease-in-out infinite; }
  @keyframes skel-pulse { 0%, 100% { opacity: .45; } 50% { opacity: 1; } }
  .logbar select { width: 100%; background: #141414; color: #d6d6d6;
                   border: 1px solid #2a2a2a; border-radius: 8px;
                   padding: 10px 12px; font-size: 13px; min-height: 44px; }
  #chart-wrap canvas { width: 100%; height: 150px; display: block; touch-action: none; }
  #chart-empty { color: #666; font-size: 12px; padding: 18px 0; }
  .gmore { display: none; color: #909090; font-size: 11px; }
  .sysbar { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
  .stat { background: #141414; border: 1px solid #222; border-radius: 10px;
          padding: 10px 16px; min-width: 130px; }
  .stat .label { color: #909090; font-size: 11px; margin-bottom: 3px; }
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
  .mgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; padding: 4px 0 12px; }
  .mcard { background: #131313; border: 1px solid #222; border-radius: 8px; padding: 12px 14px; }
  .mcard .mhead { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .mcard .mname { font-weight: 600; color: #eee; font-size: 14px; }
  .mcard .mdesc { color: #777; font-size: 11px; }
  .mcard .mstate { margin: 8px 0 10px; font-size: 12.5px; color: #b0b0b0; display: flex; align-items: center; gap: 6px; }
  .mcard .mdot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
  .mcard .mbtns { display: flex; gap: 8px; flex-wrap: wrap; }
  .mcard .mbtn { background: #1d1d1d; border: 1px solid #2e2e2e; color: #d6d6d6; border-radius: 6px;
                  padding: 5px 14px; font-size: 12.5px; cursor: pointer; }
  .mcard .mbtn:hover { border-color: #555; color: #fff; }
  .mcard .mbtn[aria-disabled="true"] { opacity: .5; cursor: default; }
  .mcard .mresult { margin-top: 8px; font-size: 12px; color: #6ec89a; min-height: 15px; word-break: break-all; }
  .chip { background: #161616; color: #b0b0b0; border: 1px solid #2a2a2a; border-radius: 999px;
          padding: 5px 14px; font-size: 12.5px; cursor: pointer; }
  .chip:hover { background: #1f1f1f; }
  .chip.active { background: #f2f2f2; border-color: #f2f2f2; color: #111; }
  .chip span { opacity: .6; margin-left: 4px; font-size: 11px; }
  a.chip { text-decoration: none; }
  a.chip:hover { color: #f2f2f2; border-color: #3a3a3a; }
  .toolchips { margin-bottom: 14px; }

  /* ---------------- Goal 进度卡片 / 负载水位 / 事件时间线 ---------------- */
  .gpanel { background: #141414; border: 1px solid #222; border-radius: 10px;
            padding: 12px 14px; margin-bottom: 14px; }
  .gpanel h2 { margin: 0 0 10px; font-size: 13px; color: #9a9a9a; font-weight: 500; }
  .gpanel .ghint { color: #8f8f8f; font-weight: 400; font-size: 11.5px; }
  .gcards { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 10px; }
  .gcard { background: #131313; border: 1px solid #222; border-radius: 8px; padding: 10px 12px; }
  .gcard .ghead { display: flex; align-items: baseline; gap: 7px; flex-wrap: wrap; }
  .gcard .glight { font-size: 13px; flex: none; }
  .gcard .gname { font-weight: 600; color: #eee; font-size: 14px; word-break: break-all; }
  .gcard .gstate { color: #8a8a8a; font-size: 11.5px; }
  .gcard .gsub { color: #909090; font-size: 11.5px; margin-top: 2px;
                 word-break: break-all; line-height: 1.45; }
  .gcard .grow { display: flex; justify-content: space-between; gap: 10px;
                 font-size: 12.5px; color: #b0b0b0; padding: 3px 0 0; }
  .gcard .grow > span:first-child { color: #777; flex: none; }
  .gcard .gtx { font-family: ui-monospace, monospace; color: #c9c9c9; }
  .gcard .gtx.warn { color: #e0b060; font-weight: 600; }
  .gcard .gtx.stop { color: #e06c6c; font-weight: 600; }
  .gcard .gretry { color: #e0884c; font-family: ui-monospace, monospace; }
  .gcard .gidle { font-family: ui-monospace, monospace; }
  .gcard .gstalled, .gcard .gstalled + * { color: #777 !important; }
  .gcard .gprog { font-family: ui-monospace, monospace; font-size: 11.5px;
                  color: #9a9a9a; padding: 4px 0 0 6px; line-height: 1.5;
                  word-break: break-all; }
  .gcard .gfoot { margin-top: 8px; }
  .gcopy { display: inline-flex; align-items: center; gap: 6px; background: #1d1d1d;
           border: 1px solid #2e2e2e; color: #d6d6d6; border-radius: 6px;
           padding: 6px 14px; font-size: 12.5px; cursor: pointer; user-select: none; }
  .gcopy:hover { border-color: #555; color: #fff; }
  .gempty { color: #8a8a8a; font-size: 12.5px; padding: 10px 0; }
  .gdone { margin-top: 12px; border-top: 1px solid #1f1f1f; padding-top: 8px; }
  .gdone summary { cursor: pointer; color: #9a9a9a; font-size: 12.5px; user-select: none; }
  .gdone summary:hover { color: #d6d6d6; }
  .gdone-row { display: flex; gap: 10px; align-items: baseline; padding: 4px 0;
               font-size: 12px; border-bottom: 1px solid #171717; flex-wrap: wrap; }
  .gdone-row:last-child { border-bottom: none; }
  .gdone-name { color: #c9c9c9; font-weight: 600; word-break: break-all; }

  .loadline .ld-head { font-size: 13.5px; color: #d6d6d6; display: flex;
                       align-items: baseline; gap: 6px; flex-wrap: wrap; }
  .loadline .ld-ico { font-size: 14px; }
  .loadline b { color: #eee; font-weight: 600; }
  .loadline .ld-sub { color: #909090; font-size: 12px; font-family: ui-monospace, monospace; }
  .loadline .ld-tops { display: flex; gap: 24px; flex-wrap: wrap; margin-top: 8px; }
  .loadline .ld-top { flex: 1 1 260px; min-width: 0; }
  .loadline .ld-t { color: #909090; font-size: 11px; margin-bottom: 3px; }
  .loadline .ld-row { display: flex; gap: 8px; font-size: 12px; line-height: 1.6;
                      font-family: ui-monospace, monospace; }
  .loadline .ld-val { color: #c9c9c9; min-width: 52px; text-align: right; flex: none; }
  .loadline .ld-name { color: #9a9a9a; word-break: break-all; }

  .evt-row { display: flex; gap: 8px; font-size: 12px; line-height: 1.7;
             font-family: ui-monospace, monospace; flex-wrap: wrap; }
  .evt-ts { color: #63849f; flex: none; }  /* 4.7:1 on #131313 (was #5c7a9a 4.4:1) */
  .evt-name { color: #e0a84c; flex: none; }
  .evt-txt { color: #b0b0b0; word-break: break-all; min-width: 200px; }
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
  .badge-paused  { background: #2a2118; color: #e0b060; border: 1px solid #5a4422; }
  .detail { display: block; color: #777; font-size: 11px; font-family: ui-monospace, monospace; margin-top: 2px; }
  .local { color: #999; font-size: 11px; }
  .ctl { white-space: nowrap; }
  .ctl-btn { background: #1d1d1d; border: 1px solid #2e2e2e; color: #d6d6d6; border-radius: 6px;
             padding: 5px 14px; font-size: 12.5px; cursor: pointer; }
  .ctl-btn:hover { border-color: #555; color: #fff; }
  .ctl-btn[aria-disabled="true"] { opacity: .5; cursor: default; }
  .empty { color: #8a8a8a; text-align: center; padding: 48px 0; }
  @media (max-width: 900px) { .cmd, .cwd { min-width: 120px; } }

  /* ---------------- 手机端 (<768px): App 化布局 ----------------
     五页横向滑动(概览/日志/Goal/服务/模型) + 底部页签栏 + safe-area;
     服务表→卡片(左滑复制/圆形打开), goal 卡收起次要信息。
     ≥769px 恢复桌面布局,所有规则只在此断点内生效。 */
  /* ---------------- 概要摘要组件 + 日志时间线(桌面隐藏,手机显示) ----------------
     字号体系: 状态数字 22-24px / 正文 14px / 辅助 12px。 */
  .stale { display: inline-block; background: var(--c-warn-bg); color: var(--c-warn);
           border: 1px solid #5a4422; border-radius: 999px; padding: 2px 10px; font-size: 12px; }
  .statusline { background: #101010; border: 1px solid #222; border-radius: 10px; color: #d6d6d6; }
  .statuscard { background: #141414; border: 1px solid #232323; border-radius: 12px; padding: 14px 16px; }
  .statuscard .sc-head { display: flex; align-items: center; gap: 12px; }
  .statuscard .sc-ico { font-size: 30px; line-height: 1; }
  .statuscard .sc-big { font-size: 24px; font-weight: 700; color: #f2f2f2; }
  .statuscard .sc-sub { margin-top: 8px; color: #909090; font-size: 12px; }
  .mgrid4 { grid-template-columns: 1fr 1fr; gap: 8px; }
  .mcell { background: #141414; border: 1px solid #232323; border-radius: 10px; padding: 10px 12px;
           display: flex; flex-direction: column; gap: 3px; }
  .mnum { font-size: 22px; font-weight: 700; color: #f2f2f2; font-variant-numeric: tabular-nums; }
  .mnum.alert { color: var(--c-warn); }
  .mlabel { font-size: 12px; color: #909090; }
  .al-btn { background: #1d1d1d; border: 1px solid #2e2e2e; color: #d6d6d6; border-radius: 6px;
            padding: 8px 12px; font-size: 12.5px; cursor: pointer; }
  .al-btn:hover { border-color: #555; color: #fff; }
  .al-btn.ignore { color: #909090; }
  .alert-item { align-items: center; gap: 10px; padding: 10px 2px; border-bottom: 1px solid #1a1a1a; }
  .alert-item:last-child { border-bottom: none; }
  .al-ico { flex: none; font-size: 17px; }
  .al-main { flex: 1 1 auto; min-width: 0; }
  .al-line { font-size: 14px; color: #e8e8e8; display: flex; gap: 8px; align-items: baseline; min-width: 0; }
  .al-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .al-sub { font-size: 12px; color: #909090; margin-top: 2px; overflow: hidden;
            text-overflow: ellipsis; white-space: nowrap; }
  .al-act { display: flex; gap: 6px; flex: none; }
  .rc-row { align-items: center; gap: 8px; padding: 9px 2px; border-bottom: 1px solid #1a1a1a;
            font-size: 14px; color: #cfcfcf; }
  .rc-row:last-child { border-bottom: none; }
  .rc-ico { flex: none; }
  .rc-kind { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rc-name { color: #909090; font-size: 12px; flex: none; max-width: 38%; overflow: hidden;
             text-overflow: ellipsis; white-space: nowrap; }
  .rc-ago { color: #909090; font-size: 12px; flex: none; }
  /* 日志时间线: 第一行 图标+类型+相对时间, 第二行一句话摘要, 详情默认折叠 */
  .lv { border-bottom: 1px solid #1a1a1a; padding: 9px 2px; }
  .lv:last-child { border-bottom: none; }
  .lv-line1 { display: flex; align-items: baseline; gap: 8px; font-size: 14px; color: #e8e8e8; min-width: 0; }
  .lv-ico { flex: none; }
  .lv-kind { font-weight: 600; flex: none; }
  .lv-loop { color: var(--c-warn); font-size: 12.5px; flex: none; }
  .lv-ago { margin-left: auto; color: #909090; font-size: 12px; flex: none; }
  .lv-line2 { font-size: 14px; color: #c9c9c9; margin-top: 3px; line-height: 1.5;
              display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
  .lv.open .lv-line2 { display: block; }
  .lv-fold { margin-top: 6px; font-size: 12px; color: var(--c-blue); display: inline-flex;
             align-items: center; gap: 4px; cursor: pointer; }
  .lv-fold::before { content: "▸"; transition: transform .15s; }
  .lv.open .lv-fold::before { transform: rotate(90deg); }
  .lv-meta { display: none; margin-top: 6px; background: #101010; border: 1px solid #1d1d1d;
             border-radius: 6px; padding: 8px 10px; font-family: ui-monospace, monospace;
             font-size: 11px; color: #9a9a9a; word-break: break-all; line-height: 1.6; }
  .lv.open .lv-meta { display: block; }
  .lv-children { display: none; margin-top: 6px; border-left: 2px solid #1f1f1f; padding-left: 8px; }
  .lv.open > .lv-children { display: block; }
  .lv-more { font-size: 12px; color: #909090; padding: 10px 0 2px; }

  @media (max-width: 768px) {
    -webkit-tap-highlight-color: transparent;
    /* safe-area: 刘海/手势条不遮挡; 标题行+状态摘要合并紧凑化 */
    header { padding: 8px max(12px, env(safe-area-inset-right)) 8px max(12px, env(safe-area-inset-left));
             padding-top: calc(8px + env(safe-area-inset-top)); gap: 8px;
             -webkit-backdrop-filter: blur(6px); }
    header h1 { font-size: 15px; }
    header h1 a { display: none; }
    header .meta { width: 100%; order: 3; font-size: 11.5px; line-height: 1.5; }
    header .spacer { display: none; }
    .auto { font-size: 12px; }
    .btn, .chip, .mbtn, .ctl-btn, .tcol, .aglog-refresh { padding: 9px 14px; font-size: 13px; min-height: 38px; }
    /* 内部滚动: main 自滚, 底部页签栏固定在文档流尾, 不再遮住最后一屏 */
    html, body { height: 100%; }
    body { display: flex; flex-direction: column; overflow: hidden;
           overscroll-behavior: none; }
    main { flex: 1 1 auto; min-height: 0; overflow-y: auto;
           -webkit-overflow-scrolling: touch; overscroll-behavior-y: contain;
           padding: 10px max(12px, env(safe-area-inset-right)) 16px
                    max(12px, env(safe-area-inset-left)); }
    /* 每页底部留出 页签栏+safe-area+余量: 滚到内容末尾时最后一条完整露出 */
    #track > .pg { padding-bottom: calc(68px + 24px + env(safe-area-inset-bottom)); }
    /* 顶部状态摘要(图标+文字双通道; 颜色仅辅助) */
    .statusline { display: flex; order: 5; width: 100%; gap: 8px; align-items: center;
                  padding: 9px 12px; font-size: 13.5px; margin-top: 2px; }
    .statusline #status-ico { font-size: 16px; flex: none; }
    .statusline.ok #status-ico { color: var(--c-green); }
    .statusline.warn #status-ico { color: var(--c-warn); }
    .statusline.bad #status-ico { color: var(--c-red); }


    /* 底部页签栏(唯一导航): 常规文档流尾部 + 毛玻璃, 不遮内容 */
    #tabbar { display: flex; flex: none; z-index: 40;
              background: rgba(12,12,12,.82);
              -webkit-backdrop-filter: blur(16px) saturate(1.4);
              backdrop-filter: blur(16px) saturate(1.4);
              border-top: 1px solid #232323;
              padding: 4px max(8px, env(safe-area-inset-left)) calc(4px + env(safe-area-inset-bottom))
                          max(8px, env(safe-area-inset-right)); }
    #tabbar .tab { flex: 1; position: relative; display: flex; flex-direction: column; align-items: center; gap: 3px;
                   padding: 7px 0 3px; min-height: 50px; color: #8a8a8a; font-size: 10.5px;
                   cursor: pointer; user-select: none; -webkit-user-select: none;
                   -webkit-tap-highlight-color: transparent; }
    #tabbar .tab.active { color: var(--c-blue); }
    #tabbar .tab svg { width: 22px; height: 22px; }
    /* 概要页签未处理告警徽章: 红点+数字 */
    .tbadge-dot { position: absolute; top: 2px; left: calc(50% + 12px); min-width: 17px; height: 17px;
                  padding: 0 4px; border-radius: 999px; background: #c04848; color: #fff;
                  font-size: 10.5px; font-weight: 700; display: flex; align-items: center;
                  justify-content: center; border: 1.5px solid #141414; }


    /* 两层结构: #pages(裁剪窗口) > #track(500% 轨道) > .pg(各 20% = 屏宽) */
    #pages { display: block; width: 100%; overflow: hidden; }
    body { overscroll-behavior-x: none; }  /* 关掉浏览器右滑返回/左滑前进接管 */
    #pages, .swipe-fg { touch-action: pan-y; }  /* 横向留给 JS 手势 */
    .filters { touch-action: pan-x; }  /* 自身横滚的容器除外 */
    #track { display: flex; align-items: flex-start; width: 500%;
             will-change: transform;
             transition: transform .26s cubic-bezier(.22,.61,.36,1); }
    #track.stick { transition: none; }
    #track > .pg { flex: 0 0 20%; min-width: 20%; max-width: 20%; }
    .skel { display: block; }
    #chart-wrap, #logpage, #agents-page { display: block; }  /* 移动专用面板 */
    #logpage[hidden], #agents-page[hidden] { display: none !important; }
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
    #svc tbody tr { display: block; background: #131313; border: 1px solid #222;
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
    .td-rows .k { color: #777; font-size: 11px; flex: none; }
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
    .watchdog-panel td::before { content: attr(data-label); color: #777; font-size: 11px;
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
</style>
</head>
<body>
<header>
  <h1>{{T:title}}
    <a href="https://github.com/iamcheyan/svc-dashboard" target="_blank" rel="noopener"
       title="{{T:github_repo}}" style="text-decoration:none; margin-left:8px; vertical-align:-3px;">
      <svg width="18" height="18" viewBox="0 0 16 16" fill="#d6d6d6" aria-hidden="true">
        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
      </svg>
    </a>
  </h1>
  <span class="meta">{{T:updated}} <span id="updated">{{UPDATED}}</span> · {{T:svc_pre}}<span id="count">{{COUNT}}</span>{{T:svc_post}}</span>
  <span class="spacer"></span>
  <span class="auto">
    <span class="sw" id="auto" role="switch" aria-checked="false" tabindex="0"
          title="{{T:auto_refresh}}"><span class="sw-thumb"></span></span>
    {{T:auto_refresh}} (<span id="auto-sec">{{AUTO}}s</span>)
  </span>
  <span class="btn" id="refresh" role="button" tabindex="0">{{T:refresh}}</span>
  <div class="statusline" id="statusline" role="button" tabindex="0">
    <span id="status-ico">⏳</span><b id="status-text">{{T:st_loading}}</b>
    <span class="stale" id="stale-badge" hidden>{{T:st_stale}}</span>
  </div>
</header>
<div id="ptr-indicator" aria-hidden="true"><span class="ptr-arrow">↓</span><span class="ptr-label">{{T:ptr_pull}}</span></div>
<main>
<div id="pages">
<div class="statuscard" id="statuscard" role="button" tabindex="0">
  <div class="sc-head"><span class="sc-ico" id="sc-ico">⏳</span><span class="sc-big" id="sc-text">{{T:st_loading}}</span></div>
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
</nav>
<script>
const AUTO = {{AUTO}};
const LANG = "{{LANG}}";
const T = {{T_JSON}};
const t = (k, p) => { let s = T[k] ?? k; if (p !== undefined) { for (const [a, b] of Object.entries(p)) s = s.split("{" + a + "}").join(b); } return s; };
let autoOn = false;
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
  const link = loopback ? `http://127.0.0.1:${e.port}/` : `http://${location.hostname}:${e.port}/`;
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
      `<span class='swipe-act' role='button' tabindex='0' data-copy='${esc(link)}' title='${t("act_copy_addr")}'>⧉ ${t("act_copy_addr")}</span></div>` +
      `<div class='swipe-fg'><div class='td-head'><span class='svc'>${esc(e.name)}</span>` +
      `<span class='badge ${badge[1]}'>${text}</span>${detail}` +
      `<a class='svc-open' href='${link}' target='_blank' rel='noopener' aria-label='${t("act_open")} ${esc(e.name)}'>↗</a></div>` +
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
    tasksEl.innerHTML = "<h2>" + t("a_title") + " <span style='color:#666;font-weight:400'>" + t("a_loading") + "</span></h2>";
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
  const cards = [
    ["load", t("sys_load"), (s.loadavg || []).join(" / ") || "—"],
    ["cpu", "CPU", `${s.cpu_usage}% · ${s.cpu_count} ${t("unit_core")}`],
    ["mem", t("sys_mem"), `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)} (${mem.percent || 0}%)`],
    ["disk", t("sys_disk"), `${fmtBytes(disk.used)} / ${fmtBytes(disk.total)} (${disk.percent || 0}%)`],
    ["up", t("sys_up"), fmtUp(s.uptime)],
  ];
  $("sysbar").innerHTML = cards.map(([k, l, v]) =>
    `<div class='stat' data-k='${k}'><div class='label'>${l}</div><div class='value'>${v}</div></div>`).join("");
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
  const [ico, color] = zone === "ok" ? ["🟢", "#6ec89a"] : zone === "full" ? ["🟡", "#e0b060"] : zone === "over" ? ["🔴", "#e06c6c"] : ["⚪", "#8a8a8a"];
  const sub = t("ld_load", { l: gl.load15 != null ? gl.load15.toFixed(1) : "—", c: gl.cores ?? "?" });
  const rows = (items, fmt) => (items || []).length
    ? items.map(([v, k]) => `<div class='ld-row'><span class='ld-val'>${fmt(v)}</span><span class='ld-name'>${esc(k)}</span></div>`).join("")
    : `<div class='ld-row' style='color:#666'>—</div>`;
  el.innerHTML = `<div class='ld-head'><span class='ld-ico' style='color:${color}'>${ico}</span><b>${t("ld_title")}</b>：${msg}` +
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
    `<a class='chip tchip' href='http://${location.hostname}:${p}/' target='_blank' rel='noopener'>${n} :${p} ↗</a>`).join("");
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
    const old = b.textContent; b.textContent = "✓ " + t("g_copied");
    haptic(12);
    setTimeout(() => b.textContent = old, 1600);
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
  el.innerHTML = "<h2>" + t("a_title") + " <span style='color:#666;font-weight:400'>" + t("a_hint", { n: total }) + "</span></h2><table><thead><tr><th>" + t("a_th_agent") + "</th><th>" + t("a_status") + "</th><th>" + t("a_loc") + "</th><th>" + t("a_active") + "</th><th>" + t("a_tool") + "</th></tr></thead><tbody>" +
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
  el.innerHTML = "<h2>" + t("tmux_panel") + " <span style='color:#666;font-weight:400'>" + t("tmux_panes", { n: panes.length }) +
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
    <span style='color:#e0a84c'>${nwd} ${t("tbd_wd")}</span> ·
    <span style='color:#6ea8dc'>${nrd} ${t("tbd_rd")}</span> ·
    <span style='color:#9a9a9a'>${nsc} ${t("tbd_sc")}</span> ·
    <span style='color:#666;font-weight:400'>${t("t_total", { n: tasks.length })}</span></h2>
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
      b.textContent = "✗";
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
    btn.textContent = (d.ok ? "✓ " : "✗ ") + (d.msg || "");
    btn.title = d.msg || "";
    setTimeout(() => { load(true); fillCtl(); }, 800); // 刷新状态
  } catch (e) {
    btn.textContent = "✗";
    btn.title = e.message;
  }
}

function manageCard(u, st, result) {
  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const ok = st && st.ok;
  const active = ok && st.active === "active";
  const stopped = ok && st.stopped;
  const color = !ok ? "#8a8a8a" : (stopped ? "#e0a84c" : (active ? "#6ec89a" : "#e06c6c"));
  const stateTxt = !ok ? (st && st.msg ? st.msg : t("m_state_fail"))
    : (stopped ? t("m_paused") : (active ? st.sub : st.active));
  const pid = ok && st.pid && st.pid !== "0" ? " · PID " + esc(st.pid) : "";
  const isProc = u.kind === "proc";
  let btns = "";
  if (active) {
    // 手动进程: 暂停=终止进程;systemd: 停止/暂停(SIGSTOP)分开
    if (isProc) {
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='stop' role='button' tabindex='0' title='${t("m_title_stop")}'>⏸ ${t("m_pause")}</span>`;
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='restart' role='button' tabindex='0' title='${t("m_title_restart")}'>⟳ ${t("m_restart")}</span>`;
    } else {
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='stop' role='button' tabindex='0' title='${t("m_title_stop")}'>■ ${t("m_stop")}</span>`;
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='restart' role='button' tabindex='0' title='${t("m_title_restart")}'>⟳ ${t("m_restart")}</span>`;
      btns += stopped
        ? `<span class='mbtn' data-unit='${u.id}' data-action='resume' role='button' tabindex='0' title='${t("m_title_resume")}'>▶ ${t("m_resume")}</span>`
        : `<span class='mbtn' data-unit='${u.id}' data-action='pause' role='button' tabindex='0' title='${t("m_title_pause")}'>⏸ ${t("m_pause")}</span>`;
    }
  } else if (ok) {
    btns += `<span class='mbtn' data-unit='${u.id}' data-action='start' role='button' tabindex='0' title='${t("m_title_start")}'>▶ ${isProc ? t("m_enable") : t("m_start")}</span>`;
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
  el.innerHTML = `<h2>${t("m_panel")} <span style='color:#666;font-weight:400'>${t("m_hint")}</span></h2>
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
    res.textContent = (d.ok ? "✓ " : "✗ ") + (d.msg || "");
    res.style.color = d.ok ? "#6ec89a" : "#e06c6c";
  } catch (e) {
    res.textContent = "✗ " + e.message;
    res.style.color = "#e06c6c";
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
  complete: { ico: "✅", grp: "ok", key: "evk_complete" },
  recover:  { ico: "🟢", grp: "recover", key: "evk_recover" },
  restart:  { ico: "🔄", grp: "fail", key: "evk_restart" },
  nudge:    { ico: "🔔", grp: "warn", key: "evk_nudge" },
  pause:    { ico: "⏸", grp: "warn", key: "evk_pause" },
  cleanup:  { ico: "🧹", grp: "ok", key: "evk_cleanup" },
  commit:   { ico: "📦", grp: "ok", key: "evk_commit" },
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
    if (g.light === "paused") a = { sev: "warn", key: "paused|" + id, icon: "⏸", msg: t("al_paused") };
    else if (g.light === "lost") a = { sev: "bad", key: "lost|" + id, icon: "⚠️", msg: t("al_lost") };
    else if (g.light === "done") a = { sev: "done", key: "done|" + id, icon: "✅", msg: t("al_done") };
    else if (g.stalled) a = { sev: "warn", key: "stalled|" + id, icon: "🐌", msg: t("al_stalled") };
    else if (g.light === "retry") a = { sev: "warn", key: "retry|" + id, icon: "🔁", msg: t("g_retry") };
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
      <span class="al-ico">${a.icon}</span>
      <div class="al-main">
        <div class="al-line"><span class="al-name">${escHtml(a.name)}</span><span class="al-msg">${escHtml(a.msg)}</span></div>
        ${a.sub ? `<div class="al-sub">${escHtml(a.sub)}</div>` : ""}
      </div>
      <div class="al-act">
        ${a.cmd ? `<span class="al-btn gcopy" data-cmd="${escAttr(a.cmd)}" role="button" tabindex="0" title="${escAttr(a.cmd)}">⧉</span>` : ""}
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
  const ico = ok ? "✅" : "⚠";
  const sc = $("statuscard"), sl = $("statusline");
  if (sc) { sc.className = "statuscard " + cls; $("sc-ico").textContent = ico; $("sc-text").textContent = txt; }
  if (sl) { sl.className = "statusline " + cls; $("status-ico").textContent = ico; $("status-text").textContent = txt; }
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
    return `<div class="rc-row" role="button" tabindex="0"><span class="rc-ico">${m.ico}</span>` +
      `<span class="rc-kind">${escHtml(t(m.key))} · ${escHtml(e.name)}</span>` +
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
  if (h) { h.hidden = !stale; h.textContent = "⚠ " + t("st_stale"); }
  if (s) { s.hidden = !stale; s.textContent = "⚠ " + t("st_stale"); }
  const f = $("sc-fresh");
  if (f) f.textContent = t("g_last") + ": " + agoStr(age / 1000);
}
setInterval(() => { if (!document.hidden) refreshFreshness(); }, 20000);

// 概要页交互: 状态卡→Goal页 / 状态栏→回概要 / 最近活动→日志页 / 告警操作
$("statuscard").addEventListener("click", () => setPage(2));
$("statusline").addEventListener("click", () => {
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
  return `<div class="lv-line1"><span class="lv-ico">${m.ico}</span>` +
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
$("refresh").addEventListener("click", () => load(true));
// 自绘开关: 点击 / Enter / Space 切换
const sw = $("auto");
function toggleAuto() {
  autoOn = !autoOn;
  sw.setAttribute("aria-checked", autoOn);
  if (autoOn) load(false);
}
sw.addEventListener("click", toggleAuto);
sw.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleAuto(); }
});
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
// 移动端把各分区装进 5 个 .pg 页容器; 桌面端恢复原始 DOM 顺序(display:contents 布局)。
// 记住初始顺序, 窗口跨过 768px 断点时来回重组不丢内容。
const PAGE_GROUPS = [
  ["#statuscard", ".mgrid4", "#alerts", "#recent", "#sysbar", "#loadline", "#chart-wrap", "#toolchips"],
  ["#logpage"],
  ["#goals"],
  ["#filters", "#tasks", "#svc"],
  ["#agents-page"],
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
}
mqMobile.addEventListener("change", () => { regroupPages(); drawChart(); });

// --- 分页(概览/日志/Goal/服务/模型) ---
const pages = $("pages");
const N_PAGES = 5;
var page = 0;   // var: 挂到 window, 便于外部调试/测试读取
function pageLabels() { return [t("tab_home"), t("tab_log"), t("tab_goal"), t("tab_svc"), t("tab_model")]; }
function applyPagesX(withTransition) {
  const tr = trackEl; // 移动端才有轨道
  if (!tr) return;
  tr.classList.toggle("stick", !withTransition);
  // 轨道宽 500%: 每页位移 = 轨道的 20%
  tr.style.transform = `translate3d(${-page * 20}%,0,0)`;
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
}
function activatePage(i) {
  if (i === 1) { initLogPage(); renderLogTimeline(); }  // 日志页: agent 选择器 + 事件时间线
  if (i === 4) initAgentsPage();     // 模型页: 拉取 OMP/Codex 卡片
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
    if (btn) { const old = btn.textContent; btn.textContent = "✓ " + t("g_copied"); setTimeout(() => btn.textContent = old, 1600); }
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
  d.textContent = "✓ " + t("g_copied");
  d.style.cssText = "position:fixed;left:50%;bottom:calc(90px + env(safe-area-inset-bottom));transform:translateX(-50%);background:#1c2a20;color:#6ec89a;border:1px solid #2e7d4f;border-radius:999px;padding:8px 18px;font-size:12.5px;z-index:60;pointer-events:none;transition:opacity .3s";
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
    const [dot, txt] = x.health === "running" ? ["#6ec89a", t("a_running")]
      : x.health === "blocked" ? ["#e0b060", t("a_blocked")]
      : x.health === "completed" ? ["#8a8a8a", t("a_done")] : ["#777", t("a_idle")];
    cards.push(`<div class="gcard" data-sid="${escAttr(x.id)}" data-cwd="${escAttr(x.cwd)}" data-tmux="${escAttr(x.tmux)}" role="button" tabindex="0">
      <div class="ghead"><span class="mdot" style="background:${dot};width:9px;height:9px;border-radius:50%;display:inline-block"></span>
      <span class="gname">OMP</span><span class="gstate">${txt}</span></div>
      <div class="gsub">${escHtml((x.goal || x.cwd).slice(0, 60))}</div>
      <div class="grow"><span>${t("a_active")}</span><span class="gidle">${t("a_ago", { s: x.idle_seconds })}</span></div>
      <div class="grow"><span>${t("a_tool")}</span><span class="gtx">${escHtml(x.tool)}</span></div></div>`);
  });
  agents.codex.forEach(x => {
    cards.push(`<div class="gcard" data-sid="" data-cwd="${escAttr(x.cwd)}" data-tmux="" role="button" tabindex="0">
      <div class="ghead"><span style="background:#6ec89a;width:9px;height:9px;border-radius:50%;display:inline-block"></span>
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
      trackEl.style.transform = `translate3d(calc(${-page * 20}% + ${pct}vw),0,0)`;
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
  arr.push({ t: now, load: (s.loadavg || [null])[0] ?? (s.loadavg || [])[2] ?? null, cpu: s.cpu_usage });
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
  // 网格线
  ctx.strokeStyle = "#1c1c1c"; ctx.lineWidth = 1;
  [0.25, 0.5, 0.75].forEach(f => { ctx.beginPath(); ctx.moveTo(0, h * f); ctx.lineTo(w, h * f); ctx.stroke(); });
  // CPU %: 0-100 映射
  ctx.strokeStyle = "#6ea8dc"; ctx.lineWidth = 1.6; ctx.beginPath();
  data.forEach((d, i) => { const y = h - 6 - (d.cpu || 0) / 100 * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // 负载: 按各自 max 缩放
  ctx.strokeStyle = "#6ec89a"; ctx.lineWidth = 1.8; ctx.beginPath();
  data.forEach((d, i) => { const y = h - 6 - (d.load || 0) / maxL * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // 图例
  ctx.font = "10px ui-monospace, monospace";
  ctx.fillStyle = "#6ea8dc"; ctx.fillText("CPU %", 8, 12);
  ctx.fillStyle = "#6ec89a"; ctx.fillText("load " + maxL.toFixed(1), 60, 12);
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
    if (autoOn) load(false); // 回前台立即刷一次
  }
});

// --- 手机端 30s 自动刷新(省电); 桌面保持 AUTO ---
const MOBILE_REFRESH_SEC = 30;
let autoSec = AUTO;
function applyAutoSec() {
  const sec = isMobile() ? MOBILE_REFRESH_SEC : AUTO;
  if (sec !== autoSec) {
    autoSec = sec;
    $("auto-sec").textContent = sec + "s";
    clearInterval(autoTimer);
    autoTimer = setInterval(autoTick, autoSec * 1000);
    console.log("[svc-dashboard] auto refresh interval -> " + autoSec + "s");
  }
}
mqMobile.addEventListener("change", applyAutoSec);
let autoTimer = setInterval(autoTick, autoSec * 1000);
function autoTick() {
  if (autoOn && !document.hidden) {
    console.log("[svc-dashboard] auto refresh tick");
    if (filter === "manage") loadManage();
    else load(false);
  }
}
applyAutoSec();

// --- 日志页选择器变化 ---
if ($("logagent-sel")) $("logagent-sel").addEventListener("change", loadLogView);

// --- 启动 ---
regroupPages();          // 手机: 分组进 5 页; 桌面: 保持原序
if (isMobile()) {
  setPage(0, { first: true });
  applyAutoSec();
} else {
  $("logpage").hidden = true;
  $("agents-page").hidden = true;
}
load(true);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "svc-dashboard/1.0"

    def _host(self):
        return self.headers.get("Host") or f"localhost:{LISTEN_PORT}"

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
                               sysdata=sys_info()).encode("utf-8")
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
        else:
            self.send_error(404)

    def do_POST(self):
        """管理端点: POST /api/manage  body={"unit": id, "action": start|stop|restart|pause|resume}"""
        path = urlparse(self.path).path
        if path != "/api/manage":
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
        unit = str(body.get("unit") or "")
        action = str(body.get("action") or "")
        self.log_message("manage %s %s", unit, action)
        lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
        try:
            self._send_json(200, manage_action(unit, action, lang))
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
        mark = "✓" if c in html else "✗"
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
