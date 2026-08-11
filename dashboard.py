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
        (t(lang, "sys_load"), loadavg),
        ("CPU", cpu),
        (t(lang, "sys_mem"), mem_txt),
        (t(lang, "sys_disk"), disk_txt),
        (t(lang, "sys_up"), fmt_uptime(s.get("uptime"), lang)),
    ]
    return '<div class="sysbar" id="sysbar">' + "".join(
        f'<div class="stat"><div class="label">{lbl}</div>'
        f'<div class="value">{val}</div></div>' for lbl, val in cards) + "</div>"


# ---------------- 国际化 ----------------
# 三语(中文 / English / 日本語),按 Accept-Language 自动切换,?lang= 可强制覆盖。

L10N = {
    "zh": {
        "title": "服务一览", "github_repo": "GitHub 仓库",
        "updated": "更新于", "listen_ports": "个监听端口", "auto_refresh": "自动刷新",
        "refresh": "⟳ 刷新",
        "chip_user": "用户服务", "chip_docker": "Docker", "chip_system": "系统服务",
        "chip_all": "全部", "chip_omp": "agent任务", "chip_watchdog": "定时任务",
        "chip_tmux": "tmux状态", "chip_manage": "服务管理",
        "th_svc": "服务", "th_port": "端口", "th_addr": "监听地址", "th_pid": "PID",
        "th_cmd": "启动命令", "th_cwd": "工作目录",
        "badge_docker": "容器", "badge_direct": "进程", "badge_self": "本页",
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
        "m_start": "启动", "m_stop": "停止", "m_restart": "重启", "m_pause": "暂停",
        "m_resume": "恢复",
        "m_state_fail": "状态获取失败", "m_paused": "已暂停 (SIGSTOP)",
        "m_title_stop": "停止服务", "m_title_restart": "重启服务",
        "m_title_resume": "SIGCONT 恢复", "m_title_pause": "SIGSTOP 挂起,不终止进程",
        "m_title_start": "启动服务",
        "m_panel": "服务管理",
        "m_hint": "zircon / tailscaled · 暂停=挂起进程(SIGSTOP),不终止",
        "m_confirm": "确认要{label} {unit} 吗?", "m_doing": "执行中…",
        "m_unknown_unit": "未知受管单元: {id}", "m_show_fail": "systemctl show 失败 (code {c})",
        "m_unknown_action": "未知操作: {a}",
        "m_done_start": "启动已执行", "m_done_stop": "停止已执行",
        "m_done_restart": "重启已执行", "m_done_pause": "暂停已执行",
        "m_done_resume": "恢复已执行", "m_fail": "{a}失败 (code {c})",
        "m_badreq": "请求体解析失败: {e}",
    },
    "en": {
        "title": "Services", "github_repo": "GitHub repo",
        "updated": "updated", "listen_ports": "listening ports", "auto_refresh": "Auto refresh",
        "refresh": "⟳ Refresh",
        "chip_user": "User services", "chip_docker": "Docker", "chip_system": "System services",
        "chip_all": "All", "chip_omp": "Agents", "chip_watchdog": "Tasks",
        "chip_tmux": "tmux", "chip_manage": "Manage",
        "th_svc": "Service", "th_port": "Port", "th_addr": "Listen addr", "th_pid": "PID",
        "th_cmd": "Command", "th_cwd": "Work dir",
        "badge_docker": "Container", "badge_direct": "Process", "badge_self": "This page",
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
        "m_start": "Start", "m_stop": "Stop", "m_restart": "Restart", "m_pause": "Pause",
        "m_resume": "Resume",
        "m_state_fail": "Failed to get status", "m_paused": "Paused (SIGSTOP)",
        "m_title_stop": "Stop service", "m_title_restart": "Restart service",
        "m_title_resume": "Resume (SIGCONT)", "m_title_pause": "Suspend (SIGSTOP), keeps process",
        "m_title_start": "Start service",
        "m_panel": "Service control",
        "m_hint": "zircon / tailscaled · pause = SIGSTOP suspend, not terminate",
        "m_confirm": "Confirm {label} {unit}?", "m_doing": "Running…",
        "m_unknown_unit": "Unknown unit: {id}", "m_show_fail": "systemctl show failed (code {c})",
        "m_unknown_action": "Unknown action: {a}",
        "m_done_start": "Start executed", "m_done_stop": "Stop executed",
        "m_done_restart": "Restart executed", "m_done_pause": "Pause executed",
        "m_done_resume": "Resume executed", "m_fail": "{a} failed (code {c})",
        "m_badreq": "Bad request: {e}",
    },
    "ja": {
        "title": "サービス一覧", "github_repo": "GitHub リポジトリ",
        "updated": "更新", "listen_ports": "個の待受ポート", "auto_refresh": "自動更新",
        "refresh": "⟳ 更新",
        "chip_user": "ユーザーサービス", "chip_docker": "Docker", "chip_system": "システムサービス",
        "chip_all": "すべて", "chip_omp": "エージェント", "chip_watchdog": "タスク",
        "chip_tmux": "tmux", "chip_manage": "サービス管理",
        "th_svc": "サービス", "th_port": "ポート", "th_addr": "待受アドレス", "th_pid": "PID",
        "th_cmd": "起動コマンド", "th_cwd": "作業ディレクトリ",
        "badge_docker": "コンテナ", "badge_direct": "プロセス", "badge_self": "このページ",
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
        "m_start": "起動", "m_stop": "停止", "m_restart": "再起動", "m_pause": "一時停止",
        "m_resume": "再開",
        "m_state_fail": "状態の取得に失敗", "m_paused": "一時停止中 (SIGSTOP)",
        "m_title_stop": "サービス停止", "m_title_restart": "サービス再起動",
        "m_title_resume": "再開 (SIGCONT)", "m_title_pause": "一時停止 (SIGSTOP),プロセスは維持",
        "m_title_start": "サービス起動",
        "m_panel": "サービス管理",
        "m_hint": "zircon / tailscaled · 一時停止 = SIGSTOP でプロセスを保留,終了しない",
        "m_confirm": "{label} {unit} を実行しますか?", "m_doing": "実行中…",
        "m_unknown_unit": "不明なユニット: {id}", "m_show_fail": "systemctl show に失敗 (code {c})",
        "m_unknown_action": "不明な操作: {a}",
        "m_done_start": "起動しました", "m_done_stop": "停止しました",
        "m_done_restart": "再起動しました", "m_done_pause": "一時停止しました",
        "m_done_resume": "再開しました", "m_fail": "{a} に失敗 (code {c})",
        "m_badreq": "リクエスト解析失敗: {e}",
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


# ---------------- 服务管理 (zircon / tailscaled) ----------------
# 对本机关键 systemd 单元提供 启动 / 停止 / 重启 / 暂停(SIGSTOP)/ 恢复(SIGCONT)。
# 系统服务需要 root: 走与 _run_sudo_ss 相同的免密 sudo 通道执行 systemctl。

MANAGE_UNITS = [
    {"id": "zircon-server", "unit": "zircon-server.service",
     "label": "Zircon 服务器 (ServerCore)", "desc": "Mir3 传奇3 服务器主进程"},
    {"id": "zircon-bots", "unit": "zircon-bots.service",
     "label": "Zircon 机器人 (BotRunner)", "desc": "AI 机器人运行器"},
    {"id": "tailscaled", "unit": "tailscaled.service",
     "label": "Tailscale", "desc": "Tailscale 组网服务"},
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


def manage_status(unit_id, lang=DEFAULT_LANG):
    """查询一个受管单元的状态: ActiveState / SubState / MainPID / 是否被 SIGSTOP 挂起。"""
    cfg = next((u for u in MANAGE_UNITS if u["id"] == unit_id), None)
    if not cfg:
        return {"id": unit_id, "ok": False, "msg": t(lang, "m_unknown_unit", id=unit_id)}
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
    """执行 start / stop / restart / pause(SIGSTOP) / resume(SIGCONT)。"""
    cfg = next((u for u in MANAGE_UNITS if u["id"] == unit_id), None)
    if not cfg:
        return {"ok": False, "msg": t(lang, "m_unknown_unit", id=unit_id)}
    if action not in ACTION_LABELS:
        return {"ok": False, "msg": t(lang, "m_unknown_action", a=action)}
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
def _event_text(event, lang=DEFAULT_LANG):
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
            return ("exit", f"[{ts}] {t(lang, 'aev_exit', r=data.get('reason', '—'))}")
        if "mode_change" in ct:
            goal = data.get("goal") or {}
            obj = " ".join(str(goal.get("objective") or "").split())
            return ("goal", f"[{ts}] {t(lang, 'aev_goal', o=obj[:120])}")
        return ("evt", f"[{ts}] · {ct}")
    if t == "compaction":
        return ("goal", f"[{ts}] {t(lang, 'aev_comp', s=str(event.get('summary', ''))[:120])}")
    return ("evt", f"[{ts}] · {t}") if ts else None


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

def render_html(host_header, entries, updated_ts, lang=DEFAULT_LANG):
    rows = []
    for e in entries:
        ip, port = e["ip"], e["port"]
        is_loopback = ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")
        badge_cls = BADGE.get(e["type"], "badge-direct")
        badge_text = t(lang, "badge_docker") if e["type"] == "docker" else t(lang, "badge_direct")
        detail = ""
        if e.get("is_self"):
            badge_text, badge_cls = t(lang, "badge_self"), "badge-self"
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
        rows.append(
            f'<tr>'
            f'<td class="name"><span class="svc">{escape(e["name"])}</span>'
            f'<span class="badge {badge_cls}">{badge_text}</span>{detail}</td>'
            f'<td class="port" data-label="{t(lang, "th_port")}"><a href="{link}" target="_blank" rel="noopener">{port}</a></td>'
            f'<td class="addr" data-label="{t(lang, "th_addr")}">{escape(ip)} {loop}</td>'
            f'<td class="pid" data-label="PID">{pids}</td>'
            f'<td class="cmd" data-label="{t(lang, "th_cmd")}">{cmd}</td>'
            f'<td class="cwd" data-label="{t(lang, "th_cwd")}">{cwd}</td>'
            f'</tr>')
    table = "\n".join(rows)
    hostname = socket.gethostname()
    body = (PAGE_TEMPLATE
            .replace("{{LANG}}", lang)
            .replace("{{T_JSON}}", json.dumps(L10N.get(lang, L10N[DEFAULT_LANG]), ensure_ascii=False))
            .replace("{{HOST}}", escape(host_header))
            .replace("{{HOSTNAME}}", escape(hostname))
            .replace("{{AUTO}}", str(AUTO_REFRESH_SEC))
            .replace("{{SYSBAR}}", render_sysbar(sys_info(), lang))
            .replace("{{UPDATED}}", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(updated_ts)))
            .replace("{{COUNT}}", str(len(entries)))
            .replace("<!--TABLE-->", table))
    return _apply_t(body, lang)


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="{{LANG}}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{T:title}} · {{HOSTNAME}}</title>
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
  .mcard .mbtn:disabled { opacity: .5; cursor: default; }
  .mcard .mresult { margin-top: 8px; font-size: 12px; color: #6ec89a; min-height: 15px; word-break: break-all; }
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

  /* ---------------- 手机端 (<768px) ----------------
     服务表/面板表 → 卡片化;chips 横滚;按钮触控加大。 */
  @media (max-width: 768px) {
    header { padding: 10px 12px; gap: 8px; }
    header h1 { font-size: 15px; }
    header h1 a { display: none; }
    header .meta { width: 100%; order: 3; font-size: 11.5px; line-height: 1.5; }
    header .spacer { display: none; }
    label.auto { font-size: 12px; }
    button { padding: 9px 14px; font-size: 13px; min-height: 38px; }
    main { padding: 12px 12px 32px; }
    .sysbar { gap: 8px; margin-bottom: 10px; }
    .stat { min-width: calc(50% - 6px); flex: 1 1 calc(50% - 6px); padding: 8px 12px; }
    .stat .value { font-size: 12.5px; }

    /* chips 横向滚动 */
    .filters { flex-wrap: nowrap; overflow-x: auto; -webkit-overflow-scrolling: touch;
               scrollbar-width: none; margin: 0 -12px 10px; padding: 0 12px 4px; }
    .filters::-webkit-scrollbar { display: none; }
    .filters .spacer { display: none; }
    .chip { flex: none; padding: 8px 14px; font-size: 12.5px; }

    /* 服务表 → 卡片 */
    #svc thead { display: none; }
    #svc tbody tr { display: block; background: #131313; border: 1px solid #222;
                    border-radius: 10px; padding: 10px 12px; margin-bottom: 10px; }
    #svc tbody td { display: flex; justify-content: space-between; gap: 12px;
                    align-items: baseline; border: none; padding: 3px 0;
                    white-space: normal !important; }
    #svc tbody td::before { content: attr(data-label); color: #777; font-size: 11px;
                            flex: none; }
    #svc tbody td .detail { margin-top: 0; }
    #svc tbody td.name { display: block; margin-bottom: 4px; }
    #svc tbody td.name::before { content: none; }
    #svc tbody td .cmd, #svc tbody td .cwd { min-width: 0; }
    .colswitch, .tcol { display: none; }
    .empty { padding: 32px 0; }
    #svc tbody tr:has(td.empty) { background: none; border: none; padding: 0; }
    #svc tbody td.empty, .watchdog-panel td.empty {
      display: block !important; text-align: center; justify-content: center; }
    #svc tbody td.empty::before, .watchdog-panel td.empty::before { content: none; }

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
    .aglog-row { flex-wrap: wrap; gap: 2px 8px; }
    .aglog-ts { flex: none; }
    .termlog { font-size: 10.5px; }

    /* 服务管理卡片 */
    .mgrid { grid-template-columns: 1fr; gap: 10px; }
    .mcard { padding: 12px; }
    .mcard .mbtns { gap: 6px; }
    .mcard .mbtn { flex: 1 1 auto; min-width: 88px; padding: 11px 8px; font-size: 13.5px; }
    .mcard .mresult { font-size: 12.5px; }
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
  <span class="meta">{{HOSTNAME}} · {{T:updated}} <span id="updated">{{UPDATED}}</span> · <span id="count">{{COUNT}}</span> {{T:listen_ports}}</span>
  <span class="spacer"></span>
  <label class="auto"><input type="checkbox" id="auto"> {{T:auto_refresh}} ({{AUTO}}s)</label>
  <button id="refresh">{{T:refresh}}</button>
</header>
<main>
{{SYSBAR}}
<div class="filters" id="filters">
  <button class="chip active" data-f="user">{{T:chip_user}} <span id="n-user"></span></button>
  <button class="chip" data-f="docker">{{T:chip_docker}} <span id="n-docker"></span></button>
  <button class="chip" data-f="system">{{T:chip_system}} <span id="n-system"></span></button>
  <button class="chip" data-f="all">{{T:chip_all}} <span id="n-all"></span></button>
  <span class="spacer"></span>
  <button class="chip" data-f="omp">{{T:chip_omp}} <span id="n-omp"></span></button>
  <button class="chip" data-f="watchdog">{{T:chip_watchdog}} <span id="n-watchdog"></span></button>
  <button class="chip" data-f="tmux">{{T:chip_tmux}} <span id="n-tmux"></span></button>
  <button class="chip" data-f="manage">{{T:chip_manage}} <span id="n-manage"></span></button>
</div>
<div id="tasks" hidden></div>
<table id="svc" data-col="cmd">
  <thead><tr>
    <th>{{T:th_svc}}</th><th>{{T:th_port}}</th><th>{{T:th_addr}}</th><th>{{T:th_pid}}</th>
    <th class="colswitch">
      <button class="tcol active" data-col="cmd">{{T:th_cmd}}</button>
      <button class="tcol" data-col="cwd">{{T:th_cwd}}</button>
    </th>
  </tr></thead>
  <tbody>
<!--TABLE-->
  </tbody>
</table>
</main>
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

function row(e) {
  const badge = {docker:[t("badge_docker"),"badge-docker"], systemd:["systemd","badge-systemd"], direct:[t("badge_direct"),"badge-direct"]}[e.type] || [t("badge_direct"),"badge-direct"];
  let text = badge[0], detail = "";
  if (e.is_self) { text = t("badge_self"); badge[1] = "badge-self"; }
  else if (e.docker_proxy) { text = t("badge_proxy"); }
  else if (e.type === "docker" && e.container_id) detail = `<span class='detail' title='${t("detail_cid")}'>${e.container_id}</span>`;
  else if (e.type === "systemd" && e.unit) detail = `<span class='detail' title='${t("detail_unit")}'>${e.unit}</span>`;
  const ip = e.ip;
  const loopback = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
  const link = loopback ? `http://127.0.0.1:${e.port}/` : `http://${location.hostname}:${e.port}/`;
  const loop = loopback ? ' <span class="local">' + t("loopback") + '</span>' : "";
  const cmd = e.cmdline || "—";
  const cwd = e.cwd || "—";
  const esc = (s) => s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  return `<tr>
    <td class='name'><span class='svc'>${esc(e.name)}</span><span class='badge ${badge[1]}'>${text}</span>${detail}</td>
    <td class='port' data-label='${t("th_port")}'><a href='${link}' target='_blank' rel='noopener'>${e.port}</a></td>
    <td class='addr' data-label='${t("th_addr")}'>${esc(ip)}${loop}</td>
    <td class='pid' data-label='PID'>${e.pids.join(", ")}</td>
    <td class='cmd' data-label='${t("th_cmd")}'>${esc(cmd)}</td>
    <td class='cwd' data-label='${t("th_cwd")}'>${esc(cwd)}</td>
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
  tbody.innerHTML = shown.length ? shown.map(row).join("") :
    '<tr><td class="empty" colspan="5">' + t("no_match") + '</td></tr>';
  $("count").textContent = shown.length;
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
    [t("sys_load"), (s.loadavg || []).join(" / ") || "—"],
    ["CPU", `${s.cpu_usage}% · ${s.cpu_count} ${t("unit_core")}`],
    [t("sys_mem"), `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)} (${mem.percent || 0}%)`],
    [t("sys_disk"), `${fmtBytes(disk.used)} / ${fmtBytes(disk.total)} (${disk.percent || 0}%)`],
    [t("sys_up"), fmtUp(s.uptime)],
  ];
  $("sysbar").innerHTML = cards.map(([l, v]) =>
    `<div class='stat'><div class='label'>${l}</div><div class='value'>${v}</div></div>`).join("");
}

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

async function loadAgentLog(a, det) {
  const sid = a.dataset.sid || "";
  const cwd = a.dataset.cwd || "";
  const tmx = a.dataset.tmux || "";
  const cell = det.querySelector("td");
  cell.innerHTML = "<div class='agentlog'>" + t("a_loading") + "</div>";
  try {
    const r = await fetch("/api/agentlog?sid=" + encodeURIComponent(sid) + "&cwd=" + encodeURIComponent(cwd) + "&tmux=" + encodeURIComponent(tmx) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
    const d = await r.json();
    const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
    let html = "<div class='agentlog'>";
    if ((d.events || []).length) {
      html += "<div class='aglog-title'>" + t("a_recent") + " <button class='aglog-refresh'>" + t("refresh") + "</button></div><div class='aglog-list'>" +
        d.events.map(e => "<div class='aglog-row'><span class='aglog-ts'>" + esc(e[0]) + "</span><span class='aglog-txt'>" + esc(e[1]) + "</span></div>").join("") + "</div>";
    }
    if (d.capture && d.capture.length) {
      html += "<div class='aglog-title'>" + t("a_term") + " <button class='aglog-refresh'>" + t("refresh") + "</button></div><pre class='termlog'>" +
        d.capture.map(l => esc(l)).join("\\n") + "</pre>";
    }
    if (!d.events.length && !d.capture) html += "<div class='aglog-empty'>" + t("a_nolog") + "</div>";
    html += "</div>";
    det.className = "agent-detail";
    cell.innerHTML = html;
    det.querySelectorAll(".aglog-refresh").forEach(b => b.addEventListener("click", () => loadAgentLog(a, det)));
  } catch (err) {
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
// 管理本机关键 systemd 单元(zircon-server / zircon-bots / tailscaled):
// 启动 / 停止 / 重启 / 暂停(SIGSTOP)/ 恢复(SIGCONT)。所有操作都需确认。
const MANAGE_UNITS = [
  { id: "zircon-server", label: t("m_server"), desc: t("m_server_desc") },
  { id: "zircon-bots", label: t("m_bots"), desc: t("m_bots_desc") },
  { id: "tailscaled", label: t("m_ts"), desc: t("m_ts_desc") },
];
const MANAGE_LABELS = { start: t("m_start"), stop: t("m_stop"), restart: t("m_restart"), pause: t("m_pause"), resume: t("m_resume") };

function manageCard(u, st, result) {
  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const ok = st && st.ok;
  const active = ok && st.active === "active";
  const stopped = ok && st.stopped;
  const color = !ok ? "#8a8a8a" : (stopped ? "#e0a84c" : (active ? "#6ec89a" : "#e06c6c"));
  const stateTxt = !ok ? (st && st.msg ? st.msg : t("m_state_fail"))
    : (stopped ? t("m_paused") : (active ? st.sub : st.active));
  const pid = ok && st.pid && st.pid !== "0" ? " · PID " + esc(st.pid) : "";
  let btns = "";
  if (active) {
    btns += `<button class='mbtn' data-unit='${u.id}' data-action='stop' title='${t("m_title_stop")}'>■ ${t("m_stop")}</button>`;
    btns += `<button class='mbtn' data-unit='${u.id}' data-action='restart' title='${t("m_title_restart")}'>⟳ ${t("m_restart")}</button>`;
    btns += stopped
      ? `<button class='mbtn' data-unit='${u.id}' data-action='resume' title='${t("m_title_resume")}'>▶ ${t("m_resume")}</button>`
      : `<button class='mbtn' data-unit='${u.id}' data-action='pause' title='${t("m_title_pause")}'>⏸ ${t("m_pause")}</button>`;
  } else if (ok) {
    btns += `<button class='mbtn' data-unit='${u.id}' data-action='start' title='${t("m_title_start")}'>▶ ${t("m_start")}</button>`;
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
  btn.disabled = true;
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
  btn.disabled = false;
  setTimeout(() => loadManage(), 600); // 等 systemd 状态落地再刷新
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
setInterval(() => {
  if (autoOn) {
    if (filter === "manage") loadManage();
    else load(false);
  }
}, AUTO * 1000);
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
            body = render_html(self._host(), entries, time.time(), lang).encode("utf-8")
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
        print(json.dumps({"services": gather()}, ensure_ascii=False, indent=2))
        return 0

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
