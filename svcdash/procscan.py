import glob, os, re, signal, socket, subprocess, threading, time
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
    """同步扫一次特权 fallback；root dashboard 直接读 /proc，不调用 sudo ss。"""
    if os.geteuid() == 0:
        return {}
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

# ---------------- 每服务资源占用(CPU%/内存/运行时长) ----------------
# CPU 用相邻两次 gather() 的 /proc/<pid>/stat 差分(同 top_procs 思路):
# 首次调用返回 0%(无前值), 前端 10s 轮询下始终有真实值。内存走 statm(单次读)。
_CLK_TCK = os.sysconf("SC_CLK_TCK") or 100
_PAGE = os.sysconf("SC_PAGE_SIZE") or 4096
_BOOT_TIME = 0.0
try:
    with open("/proc/stat", encoding="utf-8") as _f:
        for _line in _f:
            if _line.startswith("btime "):
                _BOOT_TIME = float(_line.split()[1])
                break
except OSError:
    pass
_res_prev = {"pids": {}}   # pid -> (utime+stime jiffies, starttime ticks, 采样时刻)


def _read_proc_stat(pid):
    """(/proc/<pid>/stat) -> (cpu_jiffies, start_ticks) 或 None。
    字段14/15=utime/stime, 22=starttime; comm 可能含空格/括号, 取最后一个 ')' 后切。"""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        tail = raw[raw.rfind(")") + 2:].split()
        return (int(tail[11]) + int(tail[12]), int(tail[19]))
    except (OSError, IndexError, ValueError):
        return None


def _read_proc_rss(pid):
    try:
        with open(f"/proc/{pid}/statm", encoding="utf-8") as f:
            return int(f.read().split()[1]) * _PAGE
    except (OSError, IndexError, ValueError):
        return 0


def service_resources(pids):
    """聚合一组 pid 的 {cpu, mem_mb, up_sec}。

    CPU 差分按"每 pid 各自的上次采样时刻"计算: 同一次 gather() 里 29 个服务
    顺序调用, 若共用一个全局时间戳, 除第一个服务外 elapsed≈0 → 全部 0%。
    快照合并更新: 只覆盖本组 pid, 其他服务的采样保留(替换语义会互相抹掉)。
    """
    now = time.time()
    cur = {}
    for pid in pids:
        st = _read_proc_stat(pid)
        if st:
            cur[pid] = st
    cpu_pct = 0.0
    for pid, (jif, _start) in cur.items():
        prev = _res_prev["pids"].get(pid)
        if not prev:
            continue                       # 首次见到: 无前值, 不计
        elapsed = now - prev[2]
        if elapsed > 0.5:                  # 同请求内重复出现/极短间隔不计
            cpu_pct += max(0, jif - prev[0]) / _CLK_TCK / elapsed * 100.0
    merged = dict(_res_prev["pids"])
    for pid, (jif, start) in cur.items():
        merged[pid] = (jif, start, now)
    for p in list(merged):                 # 淘汰已消失的 pid
        if p not in cur and not os.path.exists(f"/proc/{p}"):
            del merged[p]
    _res_prev["pids"] = merged
    mem = sum(_read_proc_rss(p) for p in cur)
    start2 = min((v[1] for v in cur.values()), default=None)
    up_sec = int(now - (_BOOT_TIME + start2 / _CLK_TCK)) if start2 else 0
    return {"cpu": round(cpu_pct, 1), "mem_mb": round(mem / 1048576.0, 1),
            "up_sec": max(0, up_sec)}
def gather():
    """扫描一次,返回服务列表(按端口排序,同端口合并)。

    只在用户访问页面时调用 —— 没有后台自动刷新,没人访问时 dashboard
    完全静默(进程停着但不消耗 CPU/IO)。每次访问都重新扫描,不跨请求缓存。
    """
    from svcdash.manage import MANAGE_UNITS   # 延迟导入避免 manage↔procscan 循环
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

    # 资源占用 + 通用暂停(svcctl)状态: 台账里有记录的端口标 svcctl_paused;
    # 可操作性(守卫: 自身/22/受保护进程)由 svcctl.can_pause 判定, 前端据此渲染按钮。
    from svcdash import svcctl
    paused_ports = {r.get("port") for r in svcctl.load_state()}
    self_port = int(os.environ.get("SVC_PORT", "80"))
    for e in entries:
        if e.get("pids"):
            e["res"] = service_resources(e["pids"])
        if e["port"] in paused_ports:
            e["svcctl_paused"] = True
        e["manageable"] = e.get("svcctl_paused") or svcctl.can_pause(e, self_port=self_port)

    entries.sort(key=lambda e: e["port"])
    return entries
