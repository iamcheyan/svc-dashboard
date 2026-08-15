import os, shutil, socket, time
from svcdash.i18n import t, DEFAULT_LANG
from svcdash.procscan import read
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
