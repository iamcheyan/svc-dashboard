import glob, os, re, subprocess, time
from datetime import datetime
from svcdash.i18n import t, DEFAULT_LANG
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
