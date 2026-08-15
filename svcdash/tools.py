import json, os, re, shutil, socket, subprocess, time
import urllib.request
from datetime import datetime, timedelta
from svcdash.config import SERVER_VER
from svcdash.procscan import read, gather
from svcdash.sysinfo import sys_info
from svcdash.goals import WATCHDOG_LOG
# ================= ツール页: 文件浏览 / 健康检查 / 垃圾清理 / 网络速测 / 用户服务 =================
# 全部纯标准库; 写操作只限下方枚举路径(红线: 用户媒体/System.db/git 历史/.env 永不触碰)。

HOME_DIR = "/home/tetsuya"   # svc-dashboard 以 root 运行(systemd 系统级), 不能用 expanduser

# --- F1 文件浏览 ---
# 红线: 根白名单 = home 全树 + /tmp; realpath 越界一律 404; 只读(无上传/删除/改名)。
FS_HOME = HOME_DIR
FS_ROOTS = [HOME_DIR, "/tmp"]
# 敏感文件名: .env* / *key* / *secret* / id_rsa* / *.pem / credentials* / known_hosts / .git
# 列表直接不显示 + 访问 404(与历史实现一致: 隐藏而非仅拦截)。
_FS_SENSITIVE = re.compile(r"\.env|key|secret|^id_rsa|\.pem$|^credentials|known_hosts", re.I)
_FS_IMAGE = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
# 文本预览上限: 超过只服务前 2MB 并标记 truncated(前端提示"仅预览前 2MB")
_FS_TEXT_MAX = 2 << 20


def fs_sensitive(name):
    """.git 按路径组件整目录拒绝(config/hooks 等全部不可见)。"""
    return name == ".git" or bool(_FS_SENSITIVE.search(name))


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
    if any(part == ".git" for part in real.split(os.sep)):
        return None
    for root in FS_ROOTS:
        rroot = os.path.realpath(root)
        if real == rroot or real.startswith(rroot + os.sep):
            return None if fs_sensitive(os.path.basename(real)) else real
    return None


def fs_list(path_param):
    """目录列表(名称/大小/mtime/类型/目录项数), 敏感名直接跳过, 文件夹优先。
    目录项数带 0.4s 总预算, 超时停数(前端显示 —)。parent 供面包屑跳级。"""
    real = fs_resolve(path_param)
    if not real or not os.path.isdir(real):
        return {"ok": False, "msg": "not found"}
    out = []
    deadline = time.monotonic() + 0.4
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
                    ent = {"name": e.name, "type": "dir" if is_dir else "file",
                           "size": None if is_dir else st.st_size,
                           "mtime": int(st.st_mtime)}
                    if is_dir and time.monotonic() < deadline:
                        try:
                            ent["count"] = len(os.listdir(e.path))
                        except OSError:
                            pass
                    out.append(ent)
                except OSError:
                    continue
    except OSError as ex:
        return {"ok": False, "msg": str(ex)}
    out.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
    at_root = any(real == os.path.realpath(r) for r in FS_ROOTS)
    try:
        d_mtime = int(os.stat(real).st_mtime)
    except OSError:
        d_mtime = 0
    return {"ok": True, "path": real, "name": os.path.basename(real) or real,
            "parent": None if at_root else os.path.dirname(real),
            "mtime": d_mtime, "entries": out}


def fs_meta(real):
    """预览类型 + MIME: 图片直显; 其余走文本探测(NUL -> 二进制提示)。"""
    ext = os.path.splitext(real)[1].lower()
    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
            "webp": "image/webp", "gif": "image/gif"}.get(ext[1:], "application/octet-stream")
    return ("image" if ext in _FS_IMAGE else "text"), mime


def fs_read_text(real, enc=""):
    """文本预览读取: 前 2MB 截断 / NUL 前探测二进制 / UTF-8 为主 + GB18030 候选。
    utf-8 严格解码失败而 gb18030 严格通过 -> alt_enc=gb18030(前端给"重开"按钮)。"""
    try:
        st = os.stat(real)
        with open(real, "rb") as f:
            raw = f.read(_FS_TEXT_MAX + 1)
    except OSError as ex:
        return {"ok": False, "msg": str(ex)}
    truncated = len(raw) > _FS_TEXT_MAX
    if truncated:
        raw = raw[:_FS_TEXT_MAX]
    name = os.path.basename(real)
    if b"\x00" in raw[:8192]:
        return {"ok": True, "binary": True, "name": name, "path": real,
                "size": st.st_size, "mtime": int(st.st_mtime)}
    if enc == "gb18030":
        text, used, alt = raw.decode("gb18030", "replace"), "gb18030", None
    else:
        used = "utf-8"
        try:
            text = raw.decode("utf-8")
            alt = None
        except UnicodeDecodeError:
            text = raw.decode("utf-8", "replace")
            try:
                raw.decode("gb18030")
                alt = "gb18030"
            except UnicodeDecodeError:
                alt = None
    return {"ok": True, "binary": False, "name": name, "path": real, "size": st.st_size,
            "mtime": int(st.st_mtime), "text": text, "truncated": truncated,
            "encoding": used, "alt_enc": alt}


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
                headers={"User-Agent": f"svc-dashboard/{SERVER_VER}"})
            with urllib.request.urlopen(req, timeout=8):
                pass
            lat.append(round((time.time() - t0) * 1000))
        except Exception as ex:
            err = str(ex)[:120]
            break
    return {"ok": bool(lat), "latency_ms": min(lat) if lat else None,
            "samples": lat, "error": err, "tailscale": ts_ping()}



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
    """页面内嵌工具配置: 文件浏览起点 + 主机地址 + G1 chips 端口表。"""
    return {"fs_home": FS_HOME,
            "hosts": local_hosts(),
            "g1": [["dbeditor", 8810], ["mapviewer", 8899], ["wilviewer", 8765],
                   ["uieditor", 8820], ["dbviewer", 8800], ["webclient", 8822],
                   ["yomu", 8830], ["fudoki", 8831]]}
