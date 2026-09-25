"""Agent 运行时总览: 已知 agent 注册表 + 安装/卸载 + 进程 + 活跃任务 + 额度。

只读扫描 + 受控装卸动作(白名单命令, 后台线程 + 台账持久化)。
数据源:
- 注册表: 12 个已知 agent(与 ~/dotfiles/agent/* wrapper 一一对应 + 本机 hermes)
- 二进制: PATH + 固定候选路径; 版本: <bin> --version (10 分钟缓存)
- 进程:   /proc/*/cmdline 按 argv basename 精确匹配(防参数路径误报)
- 任务:   omp → agents.scan_omp() 活会话; grok → active_sessions.json(pid 存活校验);
          codex/claude → 数据目录 24h 内新文件
- 额度:   bash ~/dotfiles/agent/agent-quota.sh --json (codex/agy/grok/kiro/cursor 五家,
          后台线程刷新, 5 分钟缓存; 输出归一化为 buckets)
- 安装:   runuser -u tetsuya bash <wrapper> --version  (wrapper 缺失自动装, --version 装完即退)
- 卸载:   npm uninstall -g <pkg> 或按注册表删 bin
"""
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
import threading
import time

from svcdash import agents

HOME = "/home/tetsuya"
DOTFILES_AGENT = HOME + "/dotfiles/agent"
# 私有 chezmoi 部署的额度查询脚本；公开 dotfiles 路径仅作旧安装回退。
QUOTA_SCRIPT = HOME + "/.config/agent/tools/agent-quota.sh"
if not os.path.isfile(QUOTA_SCRIPT):
    QUOTA_SCRIPT = DOTFILES_AGENT + "/agent-quota.sh"
LEDGER_DIR = HOME + "/.omp/svc-dashboard"
LEDGER_FILE = LEDGER_DIR + "/agentctl.json"
_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_rt_cache = {"t": 0.0, "data": None}
_ver_cache = {}          # bin path -> {"t": float, "v": str}
_quota = {"t": 0.0, "data": None, "running": False, "err": "", "lock": threading.Lock()}
_ctl = {"running": None, "log": []}   # 当前动作 + 最近动作历史(内存)
_ctl_lock = threading.Lock()

# bins: 候选路径(绝对路径优先, 裸名走 PATH); names: /proc argv basename 匹配集;
# extra_re: 额外 cmdline 正则; wrapper: dotfiles 安装脚本(None=不可装);
# rm_bins: 卸载删除路径; npm_pkg: npm 全局包名(卸载用)
REGISTRY = [
    {"id": "omp", "name": "Oh My Pi", "bins": [HOME + "/.bun/bin/omp", HOME + "/.local/bin/omp"],
     "names": {"omp"}, "extra_re": r"__omp_worker|/\.bun/bin/omp",
     "wrapper": DOTFILES_AGENT + "/omp.sh",
     "rm_bins": [HOME + "/.local/bin/omp", HOME + "/.bun/bin/omp"]},
    {"id": "dim", "name": "dim", "bins": ["/usr/bin/dim", HOME + "/.local/bin/dim"],
     "names": {"dim"}, "extra_re": r"/dimcode(?:\s|$)|/bin/dim(?:\s|$)",
     "wrapper": None, "quota": "dim"},
    {"id": "codex", "name": "Codex CLI",
     "bins": ["codex", HOME + "/.fnm/node-versions/*/installation/bin/codex"],
     "names": {"codex"},
     "wrapper": DOTFILES_AGENT + "/codex.sh", "npm_pkg": "@openai/codex",
     "quota": "codex"},
    {"id": "claude", "name": "Claude Code",
     "bins": ["claude", HOME + "/.fnm/node-versions/*/installation/bin/claude"],
     "names": {"claude"},
     "wrapper": DOTFILES_AGENT + "/claude-code.sh", "npm_pkg": "@anthropic-ai/claude-code"},
    {"id": "agy", "name": "Antigravity (Gemini)", "bins": [HOME + "/.local/bin/agy"],
     "names": {"agy", "antigravity"},
     "wrapper": DOTFILES_AGENT + "/antigravity.sh",
     "rm_bins": [HOME + "/.local/bin/agy", HOME + "/.antigravity/bin/agy"],
     "quota": "agy"},
    {"id": "grok", "name": "Grok CLI", "bins": [HOME + "/.grok/bin/grok", HOME + "/.local/bin/grok"],
     "names": {"grok"}, "wrapper": DOTFILES_AGENT + "/grok.sh",
     "rm_bins": [HOME + "/.local/bin/grok", HOME + "/.grok/bin/grok"],
     "quota": "grok"},
    {"id": "cursor-agent", "name": "Cursor Agent",
     "bins": [HOME + "/.local/bin/cursor-agent"], "names": {"cursor-agent"},
     "wrapper": DOTFILES_AGENT + "/cursor.sh",
     "rm_bins": [HOME + "/.local/bin/cursor-agent"],
     "quota": "cursor"},
    {"id": "opencode", "name": "OpenCode",
     "bins": [HOME + "/.opencode/bin/opencode", HOME + "/.local/bin/opencode"],
     "names": {"opencode"}, "wrapper": DOTFILES_AGENT + "/opencode.sh",
     "rm_bins": [HOME + "/.local/bin/opencode", HOME + "/.opencode/bin/opencode"]},
    {"id": "copilot", "name": "GitHub Copilot CLI",
     "bins": [HOME + "/.local/bin/copilot"], "names": {"copilot"},
     "wrapper": DOTFILES_AGENT + "/copilot.sh",
     "rm_bins": [HOME + "/.local/bin/copilot"]},
    {"id": "kiro", "name": "Kiro CLI", "bins": [HOME + "/.local/bin/kiro-cli"],
     "names": {"kiro-cli", "kiro"}, "wrapper": DOTFILES_AGENT + "/kiro.sh",
     "rm_bins": [HOME + "/.local/bin/kiro-cli"],
     "quota": "kiro"},
    {"id": "pi", "name": "Pi", "bins": [HOME + "/.pi/bin/pi", HOME + "/.local/bin/pi"],
     "names": {"pi"}, "wrapper": DOTFILES_AGENT + "/pi.sh",
     "rm_bins": [HOME + "/.local/bin/pi", HOME + "/.pi/bin/pi"]},
    {"id": "mimo", "name": "MiMo Code", "bins": [HOME + "/.local/bin/mimo"],
     "names": {"mimo"}, "wrapper": DOTFILES_AGENT + "/mimo.sh",
     "rm_bins": [HOME + "/.local/bin/mimo"]},
    {"id": "hermes", "name": "Hermes", "bins": [HOME + "/.local/bin/hermes"],
     "names": {"hermes"}, "wrapper": None,
     "extra_re": r"hermes_cli\.main|/hermes-agent/venv/bin"},
]
_PROC_CACHE = {"t": 0.0, "data": None}



def agent_version(binpath):
    now = time.time()
    c = _ver_cache.get(binpath)
    if c and now - c["t"] < 600:
        return c["v"]
    v = ""
    try:
        out = subprocess.run([binpath, "--version"], capture_output=True, text=True,
                             timeout=5)
        line = (out.stdout or out.stderr or "").strip().splitlines()
        v = line[0][:60] if line else ""
    except (OSError, subprocess.SubprocessError):
        v = ""
    _ver_cache[binpath] = {"t": now, "v": v}
    return v


def _proc_stats(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(")", 1)[-1].split()
        utime, stime, starttime = int(parts[11]), int(parts[12]), int(parts[19])
        with open(f"/proc/{pid}/statm") as f:
            rss_pages = int(f.read().split()[1])
        with open("/proc/uptime") as f:
            boot = time.time() - float(f.read().split()[0])
        elapsed = max(1, time.time() - boot - starttime / _CLK_TCK)
        cpu = (utime + stime) / _CLK_TCK / elapsed * 100.0
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            cwd = ""
        return {"pid": int(pid), "cpu_pct": round(cpu, 1),
                "mem_mb": round(rss_pages * os.sysconf("SC_PAGE_SIZE") / 1e6, 1),
                "elapsed_sec": int(elapsed), "cwd": cwd}
    except (OSError, ValueError, IndexError):
        return None


def scan_procs():
    now = time.time()
    if _PROC_CACHE["data"] is not None and now - _PROC_CACHE["t"] < 3:
        return _PROC_CACHE["data"]
    regs = [{"id": r["id"], "names": r["names"],
             "re": re.compile(r.get("extra_re", r"(?!x)x"))} for r in REGISTRY]
    out = {r["id"]: [] for r in REGISTRY}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/cmdline", "rb") as f:
                argv = [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
        except OSError:
            continue
        if not argv:
            continue
        joined = " ".join(argv)
        for r in regs:
            if any(os.path.basename(a) in r["names"] for a in argv) or r["re"].search(joined):
                st = _proc_stats(d)
                if st:
                    st["cmd"] = joined[:120]
                    out[r["id"]].append(st)
                break
    for v in out.values():
        v.sort(key=lambda x: x["pid"])
    _PROC_CACHE.update({"t": now, "data": out})
    return out


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def find_bin(cands):
    """cands 支持绝对路径 / PATH 裸名 / glob(fnm node-versions 版本目录)。"""
    import glob as _glob
    expanded = []
    for c in cands:
        expanded.extend(sorted(_glob.glob(os.path.expanduser(c))) or [c])
    for c in expanded:
        p = os.path.expanduser(c)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
        if "/" not in p:
            for d in os.environ.get("PATH", "").split(":"):
                q = os.path.join(d, p)
                if os.path.isfile(q) and os.access(q, os.X_OK):
                    return q
    return None



def _grok_tasks():
    try:
        with open(HOME + "/.grok/active_sessions.json") as f:
            sess = json.load(f)
        return [{"id": str(s.get("session_id", ""))[:8], "pid": s.get("pid"),
                 "cwd": str(s.get("cwd", "")), "opened_at": str(s.get("opened_at", ""))}
                for s in sess if isinstance(s, dict) and _pid_alive(s.get("pid") or -1)]
    except (OSError, ValueError):
        return []


def _activity_text(value, limit=100):
    """Short, redacted activity label; never put credentials into the dashboard."""
    text = " ".join(str(value or "").split())
    text = re.sub(r"(?:sk-|xai-|AIza|ghp_|github_pat_)[A-Za-z0-9_\-\.]+", "[redacted]", text, flags=re.I)
    return text[:limit] + ("…" if len(text) > limit else "")


def _agy_tasks():
    """Gemini/Antigravity CLI recent conversations from its lightweight history."""
    rows = []
    paths = [HOME + "/.gemini/antigravity-cli/history.jsonl"]
    paths.extend(__import__("glob").glob(HOME + "/.gemini/tmp/*/logs.json"))
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                data = [json.loads(line) for line in f] if path.endswith(".jsonl") else json.load(f)
        except (OSError, ValueError, TypeError):
            continue
        if isinstance(data, dict):
            data = data.get("history") or data.get("entries") or []
        for x in data if isinstance(data, list) else []:
            if not isinstance(x, dict):
                continue
            ts = x.get("timestamp")
            try:
                ts = float(ts) / (1000 if float(ts) > 10**11 else 1)
            except (TypeError, ValueError):
                continue
            age = max(0, int(time.time() - ts))
            if age > 7 * 86400:
                continue
            rows.append({"kind": "session", "id": str(x.get("sessionId") or x.get("conversationId") or ""),
                         "cwd": str(x.get("workspace") or "—"),
                         "title": _activity_text(x.get("display") or x.get("message") or "Gemini activity"),
                         "age_sec": age, "health": "running" if age < 900 else "idle"})
    seen, out = set(), []
    for x in sorted(rows, key=lambda r: r["age_sec"]):
        key = (x["id"], x["cwd"], x["title"])
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out[:8]


def _process_tasks(agent_id, plist):
    return [{"kind": "process", "agent": agent_id, "pid": p["pid"], "cwd": p.get("cwd") or "—",
             "cmd": p.get("cmd") or "—", "age_sec": p.get("elapsed_sec", 0), "health": "running"}
            for p in plist[:4]]


def _recent_files(root, hours=24, limit=3):
    if not root or not os.path.isdir(root):
        return 0, []
    cutoff = time.time() - hours * 3600
    depth0 = root.rstrip("/").count("/")
    hits = []
    for dirpath, dirs, files in os.walk(root):
        if dirpath.count("/") - depth0 >= 4:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
        for fn in files:
            p = os.path.join(dirpath, fn)
            try:
                m = os.path.getmtime(p)
            except OSError:
                continue
            if m >= cutoff:
                hits.append((m, os.path.relpath(p, root)))
    hits.sort(reverse=True)
    return len(hits), [{"file": rel[:80], "age_sec": int(time.time() - m)}
                       for m, rel in hits[:limit]]


# ---------------- 额度: agent-quota.sh --json → 归一化 buckets ----------------

def _iso_cut(s):
    return str(s or "")[:19].replace("T", " ")


def _pct(x):
    try:
        return max(0, min(100, round(float(x))))
    except (TypeError, ValueError):
        return None


def _parse_codex_quota(d):
    """codex app-server 协议 JSON → {account, plan, buckets[]}"""
    acc = (d.get("account") or {}).get("account") or {}
    rl = (d.get("rateLimits") or {}).get("rateLimitsByLimitId")
    if not rl and isinstance((d.get("rateLimits") or {}).get("rateLimits"), dict):
        r = d["rateLimits"]["rateLimits"]
        rl = {r.get("limitId") or "default": r}
    buckets = []
    for key, v in (rl or {}).items():
        name = v.get("limitName") or v.get("limitId") or key
        for tag, field in (("primary", "primary"), ("secondary", "secondary")):
            p = v.get(field) or {}
            used = _pct(p.get("usedPercent"))
            if used is None:
                continue
            buckets.append({"label": f"{name} · {tag}", "remaining_pct": 100 - used,
                            "reset": _iso_cut(p.get("resetsAt")), "detail": ""})
    usage = d.get("usage") or {}
    s = usage.get("summary") or {}
    toks = []
    for label, k in (("7d", "weeklyTokens"), ("lifetime", "lifetimeTokens")):
        v = s.get(k)
        if v is None:
            continue
        try:
            n = int(v)
            toks.append(f"{label} {n/1e6:.1f}M" if n >= 1e6 else f"{label} {n/1e3:.0f}K")
        except (TypeError, ValueError):
            pass
    return {"ok": True, "account": acc.get("email") or "", "plan": acc.get("planType") or "",
            "buckets": buckets, "detail": "; ".join(toks)}

def _iso_cut(s):
    """截断 ISO 时间; 兼容 epoch 秒(codex app-server 返回数字)。"""
    if isinstance(s, (int, float)) or (isinstance(s, str) and s.isdigit()):
        try:
            return time.strftime("%m-%d %H:%M", time.localtime(float(s)))
        except (TypeError, ValueError, OverflowError):
            return ""
    return str(s or "")[:19].replace("T", " ")



def _parse_agy_quota(d):
    """google cloudcode retrieveUserQuotaSummary → gemini/claude+gpt 周额度与5小时额度"""
    buckets = []
    for g in (d.get("quota") or {}).get("groups") or []:
        gname = g.get("displayName") or ""
        for b in g.get("buckets") or []:
            frac = b.get("remainingFraction")
            pct = _pct(float(frac) * 100) if frac is not None else None
            if pct is None:
                continue
            buckets.append({"label": f"{gname} · {b.get('bucketId', '')}",
                            "remaining_pct": pct,
                            "reset": _iso_cut(b.get("resetTime")), "detail": ""})
    emails = [a.get("email") for a in (d.get("accounts") or []) if a.get("email")]
    return {"ok": bool(buckets), "account": ", ".join(emails[:2]), "plan": "",
            "buckets": buckets, "detail": ""}


def _parse_grok_quota(d):
    cfg = ((d.get("billing") or {}).get("config")) or {}
    user = d.get("user") or {}
    buckets = []
    used = _pct(cfg.get("creditUsagePercent"))
    if used is not None:
        buckets.append({"label": "credits", "remaining_pct": 100 - used,
                        "reset": _iso_cut(cfg.get("currentPeriod", {}).get("end")),
                        "detail": ""})
    prepaid = (cfg.get("prepaidBalance") or {}).get("val")
    return {"ok": bool(buckets), "account": user.get("email") or "",
            "plan": user.get("subscriptionTier") or "", "buckets": buckets,
            "detail": f"prepaid {prepaid}" if prepaid is not None else ""}


def _parse_kiro_quota(d):
    buckets = []
    for u in ((d.get("usage") or {}).get("usageBreakdownList")) or []:
        cur, lim = u.get("currentUsage"), u.get("usageLimit")
        pct = _pct((1 - cur / lim) * 100) if lim else None
        if pct is None:
            continue
        buckets.append({"label": u.get("displayName") or u.get("resourceType") or "usage",
                        "remaining_pct": pct,
                        "reset": "", "detail": f"{cur}/{lim} {u.get('unit', '')}"})
    return {"ok": bool(buckets), "account": d.get("email") or "", "plan": "",
            "buckets": buckets, "detail": ""}


def _parse_cursor_quota(d):
    usage = d.get("usage") or {}
    pu = usage.get("planUsage") or {}
    buckets = []
    for label, k in (("included", "totalPercentUsed"), ("auto", "autoPercentUsed"),
                     ("api", "apiPercentUsed")):
        used = _pct(pu.get(k))
        if used is None:
            continue
        buckets.append({"label": label, "remaining_pct": 100 - used, "reset": "",
                        "detail": ""})
    end_ms = usage.get("billingCycleEnd")
    if end_ms:
        try:
            reset = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(end_ms) / 1000))
            for b in buckets:
                b["reset"] = reset
        except (TypeError, ValueError):
            pass
    return {"ok": bool(buckets), "account": "", "plan": "", "buckets": buckets,
            "detail": ""}


def _parse_dim_quota(d):
    """dim usage --json 的 Credits 汇总，转换为 dashboard 通用 bucket。"""
    if not isinstance(d, dict) or not d.get("ok"):
        return {"ok": False, "account": "", "plan": "", "buckets": [],
                "detail": str((d or {}).get("error") or "unavailable")[:120]}
    c = d.get("credits") or {}
    try:
        total = float(c.get("total_units") or 0)
        remaining = float(c.get("remaining_units") or 0)
        used = float(c.get("used_units") or 0)
    except (TypeError, ValueError):
        total = remaining = used = 0
    if total <= 0:
        return {"ok": False, "account": "", "plan": "", "buckets": [],
                "detail": "no Credits bucket"}
    reset = str(d.get("term_end") or "")[:19].replace("T", " ")
    pct = max(0, min(100, round(remaining / total * 100)))
    detail = f"{int(used)}/{int(total)} Credits remaining {int(remaining)}"
    return {"ok": True, "account": "", "plan": "", "buckets": [{
        "label": "Credits", "remaining_pct": pct, "reset": reset, "detail": detail
    }], "detail": detail}


QUOTA_PARSERS = {"codex": _parse_codex_quota, "agy": _parse_agy_quota,
                 "grok": _parse_grok_quota, "kiro": _parse_kiro_quota,
                 "cursor": _parse_cursor_quota, "dim": _parse_dim_quota}


def _runuser_tetsuya(cmd, timeout=300):
    """以 tetsuya 身份跑命令(root 服务降权), 返回 (rc, 输出合并文本)。
    runuser 不加载登录环境, 显式注入用户 PATH(fnm/npm/agent bin)。"""
    env_path = (f'export PATH="{HOME}/.local/bin:{HOME}/.bun/bin:{HOME}/.grok/bin:'
                f'{HOME}/.opencode/bin:{HOME}/.fnm:{HOME}/.local/share/fnm:'
                f'/usr/local/bin:/usr/bin:/bin" && ')
    try:
        out = subprocess.run(["/usr/sbin/runuser", "-u", "tetsuya", "--", "bash", "-c",
                              env_path + cmd],
                             capture_output=True, text=True, timeout=timeout)
        txt = ((out.stdout or "") + (("\n[stderr] " + out.stderr) if out.stderr else "")).strip()
        return out.returncode, txt[-4000:]
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as e:
        return 1, str(e)


def refresh_quota(force=False):
    """后台线程跑 agent-quota.sh --json; 结果缓存 5 分钟。立即返回。"""
    with _quota["lock"]:
        if _quota["running"]:
            return
        if not force and _quota["data"] is not None and time.time() - _quota["t"] < 300:
            return
        _quota["running"] = True
    def _work():
        try:
            out = subprocess.run(
                ["/usr/sbin/runuser", "-u", "tetsuya", "--", "bash",
                 QUOTA_SCRIPT, "--json"],
                capture_output=True, text=True, timeout=120)
            rc, txt = out.returncode, (out.stdout or "").strip()
        except subprocess.TimeoutExpired:
            rc, txt = 124, ""
        except OSError as e:
            rc, txt = 1, ""
        with _quota["lock"]:
            _quota["running"] = False
            _quota["t"] = time.time()
            if rc != 0 or not txt:
                _quota["err"] = txt or f"exit {rc}"
                return
            try:
                raw = json.loads(txt[txt.index("{"):txt.rindex("}") + 1])
            except ValueError:
                _quota["err"] = txt[:200]
                return
            _quota["err"] = ""
            parsed = {}
            for provider, parser in QUOTA_PARSERS.items():
                blk = raw.get(provider)
                if isinstance(blk, dict):
                    try:
                        parsed[provider] = parser(blk)
                    except (TypeError, ValueError, KeyError, AttributeError):
                        parsed[provider] = {"ok": False, "account": "", "plan": "",
                                            "buckets": [], "detail": "parse error"}
            _quota["data"] = parsed
    threading.Thread(target=_work, daemon=True).start()


def quota_snapshot():
    """{"providers": {...}, "updated": ts, "running": bool, "err": str}"""
    with _quota["lock"]:
        return {"providers": _quota["data"] or {}, "updated": _quota["t"],
                "running": _quota["running"], "err": _quota["err"]}


# ---------------- 模型 provider / 模型可用性测试 ----------------
# 数据源: ~/.config/opencode/opencode.json (provider+baseURL+模型表) + ~/.env (密钥存在性)
# + omp 自身: ZAI_API_KEY + ZAI_PREVIEW_MODEL。密钥只读不外传, 响应绝不含 key。
OPENCODE_CONFIG = HOME + "/.config/opencode/opencode.json"
ENV_FILE = HOME + "/.env"
# opencode provider id → ~/.env 密钥变量名
MODEL_ENV_MAP = {
    "DS": "DEEPSEEK_API_KEY", "evomap": "EVOMAP_API_KEY",
    "opencode-go": "OPENCODE_GO_API_KEY", "ollama": "OLLAMA_API_KEY",
    "ollama-BAK": "OLLAMA_BAK_API_KEY", "zai": "ZAI_API_KEY",
}
CHAT_DISABLED = {"evomap"}   # 预充值网关: 只 GET /models 探活, 禁发 chat
ZAI_BASE = "https://api.z.ai/api/palette/v1"
_model_tests = {}            # "provider|model" -> {status, ok, ms, http, detail, t}
_model_lock = threading.Lock()


def _load_env():
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    val = v.strip()
                    if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                        val = val[1:-1]
                    env[k.strip()] = val
    except OSError:
        pass
    return env


def scan_models():
    """provider/模型清单 + 各自密钥状态 + 最近测试结果(不含密钥值)。"""
    env = _load_env()
    providers = []
    try:
        with open(OPENCODE_CONFIG) as f:
            cfg = json.load(f)
        for pid, p in (cfg.get("provider") or {}).items():
            opts = p.get("options") or {}
            base = str(opts.get("baseURL") or "").rstrip("/")
            if not base:
                continue
            env_key = MODEL_ENV_MAP.get(pid, "")
            has_key = bool(env.get(env_key) or opts.get("apiKey"))
            providers.append({
                "id": pid, "name": p.get("name") or pid, "base": base,
                "chat_allowed": pid not in CHAT_DISABLED,
                "has_key": has_key,
                "models": [{"id": m.get("id") or mid, "name": m.get("name") or mid}
                           for mid, m in (p.get("models") or {}).items()],
            })
    except (OSError, ValueError):
        pass
    # omp 自身模型: zai (ZAI_PREVIEW_MODEL)
    zmodel = env.get("ZAI_PREVIEW_MODEL") or ""
    if env.get("ZAI_API_KEY") and zmodel:
        providers.append({"id": "zai", "name": "Z.AI (omp)", "base": ZAI_BASE,
                          "chat_allowed": True, "has_key": True,
                          "models": [{"id": zmodel, "name": zmodel}]})
    out = []
    with _model_lock:
        for p in providers:
            for m in p["models"]:
                r = _model_tests.get(p["id"] + "|" + m["id"])
                if r:
                    m["test"] = {k: r[k] for k in ("status", "ok", "ms", "http", "detail", "t")
                                 if k in r}
        out = providers
    return {"providers": out}


def _http_json(url, key, payload=None, timeout=20):
    """GET/POST JSON; 返回 (ok, ms, http_status, detail)。不发密钥到日志。"""
    req = urllib.request.Request(url, method="GET" if payload is None else "POST")
    req.add_header("Authorization", "Bearer " + key)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(payload).encode()
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(2048)
            return True, int((time.time() - t0) * 1000), resp.status, ""
    except urllib.error.HTTPError as e:
        return False, int((time.time() - t0) * 1000), e.code, (e.read(200) or b"").decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, int((time.time() - t0) * 1000), 0, str(e)[:120]


def model_test_start(provider_id, model_id):
    """后台线程测一个模型: chat_allowed → 1-token chat; 否则 GET /models 探活。"""
    env = _load_env()
    try:
        with open(OPENCODE_CONFIG) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    p = (cfg.get("provider") or {}).get(provider_id)
    base, key = "", ""
    if p:
        base = str((p.get("options") or {}).get("baseURL") or "").rstrip("/")
        key = env.get(MODEL_ENV_MAP.get(provider_id, "")) or str((p.get("options") or {}).get("apiKey") or "")
    if provider_id == "zai":
        base, key = ZAI_BASE, env.get("ZAI_API_KEY") or ""
    if not base or not key:
        return False, "no base url or key"

    def _work():
        with _model_lock:
            _model_tests[provider_id + "|" + model_id] = {"status": "running", "t": time.time()}
        try:
            _run_model_test(provider_id, model_id, base, key)
        except Exception as e:   # 线程内兜底: 异常也要落终态, 不永久卡 running
            with _model_lock:
                _model_tests[provider_id + "|" + model_id] = {
                    "status": "done", "ok": False, "ms": 0, "http": 0,
                    "detail": str(e)[:120], "t": time.time()}

    threading.Thread(target=_work, daemon=True).start()
    return True, "test started"


def _run_model_test(provider_id, model_id, base, key):
        if provider_id in CHAT_DISABLED:
            ok, ms, code, detail = _http_json(base + "/models", key)
            with _model_lock:
                _model_tests[provider_id + "|" + model_id] = {
                    "status": "done", "ok": ok, "ms": ms, "http": code,
                    "detail": ("probe /models " + str(code)) if not ok else "probe /models",
                    "t": time.time()}
        else:
            ok, ms, code, detail = _http_json(
                base + "/chat/completions", key,
                {"model": model_id, "messages": [{"role": "user", "content": "hi"}],
                 "max_tokens": 1, "stream": False})
            with _model_lock:
                _model_tests[provider_id + "|" + model_id] = {
                    "status": "done", "ok": ok, "ms": ms, "http": code,
                    "detail": "" if ok else detail, "t": time.time()}


def model_test_status():
    with _model_lock:
        return {k: dict(v) for k, v in _model_tests.items()}


# ---------------- 安装 / 卸载 (后台线程 + 台账) ----------------

def _ledger_read():
    try:
        with open(LEDGER_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _ledger_append(entry):
    os.makedirs(LEDGER_DIR, exist_ok=True)
    hist = _ledger_read()
    hist.append(entry)
    hist = hist[-50:]
    tmp = LEDGER_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(hist[-50:], f, ensure_ascii=False)
    os.replace(tmp, LEDGER_FILE)


def agentctl_status():
    with _ctl_lock:
        return {"running": dict(_ctl["running"]) if _ctl["running"] else None,
                "history": _ctl["log"][-12:] + _ledger_read()[-12:]}


def agentctl_start(agent_id, action):
    """安装/卸载白名单 agent。同一时刻仅一个动作。返回 (ok, msg)。"""
    if action == "quota":
        refresh_quota(force=True)
        return True, "quota refresh started"
    reg = next((r for r in REGISTRY if r["id"] == agent_id), None)
    if not reg or action not in ("install", "uninstall"):
        return False, "unknown agent or action"
    with _ctl_lock:
        if _ctl["running"]:
            return False, f"busy: {_ctl['running']['agent']} {_ctl['running']['action']}"
        _ctl["running"] = {"agent": agent_id, "action": action, "since": time.time()}


    def _work():
        ok, msg, detail = True, "", ""
        try:
            if action == "install":
                w = reg.get("wrapper")
                if not w or not os.path.isfile(w):
                    ok, msg = False, "no install script"
                else:
                    rc, detail = _runuser_tetsuya(f"bash {w} --version", timeout=600)
                    installed = bool(find_bin(reg["bins"]))
                    ok = installed
                    msg = "installed" if ok else f"install failed (exit {rc})"
            else:
                pkg = reg.get("npm_pkg")
                if pkg:
                    rc, detail = _runuser_tetsuya(
                        f'eval "$(fnm env --shell bash)" 2>/dev/null; fnm use default 2>/dev/null; '
                        f'npm uninstall -g {pkg}', timeout=180)
                    ok = rc == 0
                    detail = detail
                else:
                    detail = []
                    for p in reg.get("rm_bins") or []:
                        try:
                            if os.path.lexists(p):
                                os.remove(p)
                                detail.append("rm " + os.path.basename(p))
                        except OSError as e:
                            detail.append(f"rm {p}: {e}")
                    detail = "; ".join(detail)
                    ok = not find_bin(reg["bins"])
                msg = "uninstalled" if ok else "uninstall incomplete"
        finally:
            with _ctl_lock:
                _ctl["running"] = None
                rec = {"agent": agent_id, "action": action, "ok": ok, "msg": msg,
                       "t": time.strftime("%m-%d %H:%M:%S"), "detail": detail[:500]}
                _ctl["log"].append(rec)
            try:
                _ledger_append(rec)
            except OSError:
                pass
            _ver_cache.clear()
            _rt_cache.update({"t": 0.0, "data": None})
    threading.Thread(target=_work, daemon=True).start()
    return True, f"{action} started: {agent_id}"


# ---------------- 聚合 ----------------

def _meta_for(agent_id):
    meta = {}
    try:
        if agent_id == "codex":
            with open(HOME + "/.codex/auth.json") as f:
                d = json.load(f)
            if d.get("auth_mode"):
                meta["auth"] = str(d["auth_mode"])
        elif agent_id == "grok":
            with open(HOME + "/.grok/auth.json") as f:
                d = json.load(f)
            for v in d.values():
                if isinstance(v, dict) and v.get("email"):
                    meta["account"] = str(v["email"])
                    break
        elif agent_id == "claude":
            with open(HOME + "/.claude.json") as f:
                d = json.load(f)
            acc = d.get("oauthAccount") or {}
            if acc.get("emailAddress"):
                meta["account"] = str(acc["emailAddress"])
    except (OSError, ValueError):
        pass
    return meta


def _system_ai_env():
    """获取本机 AI 开发环境关键组件版本。"""
    versions = {}
    tools = [
        ("bun", ["bun", "--version"]),
        ("node", ["node", "--version"]),
        ("python", ["python3", "--version"]),
        ("git", ["git", "--version"])
    ]
    for name, cmd in tools:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout.strip()
            if out:
                v = out.replace("git version ", "").replace("Python ", "").strip()
                versions[name] = v
        except Exception:
            pass
    return versions


def scan_runtimes():
    now = time.time()
    if _rt_cache["data"] is not None and now - _rt_cache["t"] < 10:
        return _rt_cache["data"]
    procs = scan_procs()
    omp_sessions = agents.scan_omp()
    omp_active = [s for s in omp_sessions if s["health"] in ("running", "blocked")]
    qs = quota_snapshot()
    ctl = agentctl_status()
    result = []
    for a in REGISTRY:
        binpath = find_bin(a["bins"])
        plist = procs.get(a["id"], [])
        entry = {"id": a["id"], "name": a["name"], "installed": bool(binpath),
                 "bin": binpath or "", "version": agent_version(binpath) if binpath else "",
                 "procs": len(plist), "proc_list": plist[:6], "tasks": [],
                 "meta": _meta_for(a["id"]),
                 "installable": bool(a.get("wrapper"))}
        aid = a["id"]
        if aid == "omp":
            entry["tasks"] = [{"kind": "omp", "id": s["id"], "cwd": s["cwd"],
                               "goal": s["goal"], "health": s["health"],
                               "idle_seconds": s["idle_seconds"], "tool": s["tool"],
                               "tmux": s["tmux"]} for s in omp_active[:6]]
            entry["meta"]["sessions_total"] = len(omp_sessions)
        elif aid == "agy":
            entry["tasks"] = _agy_tasks()
        elif aid == "grok":
            entry["tasks"] = [{"kind": "grok", **t} for t in _grok_tasks()]
        elif aid == "codex":
            entry["tasks"] = [{"kind": "codex", "id": s["session_id"], "cwd": s["cwd"],
                               "title": s.get("title") or "Codex session", "health": s["health"],
                               "idle_seconds": s["idle_seconds"], "tool": s.get("last_event") or "—"}
                              for s in agents.scan_codex()[:12]]
            root = HOME + "/.codex/sessions"
            n, recent = _recent_files(root)
            entry["meta"]["sessions_24h"] = n
        elif aid == "claude":
            root = HOME + "/.claude/projects"
            n, recent = _recent_files(root)
            entry["meta"]["sessions_24h"] = n
            entry["tasks"] = [{"kind": "file", "file": r["file"], "age_sec": r["age_sec"]}
                              for r in recent]
        if not entry["tasks"] and plist:
            entry["tasks"] = _process_tasks(aid, plist)
        if a.get("quota"):
            quota = qs["providers"].get(a["quota"])
            # 无法真实查询或没有有效 bucket 的 provider 不进入响应，前端自然隐藏。
            if quota and quota.get("ok") and quota.get("buckets"):
                entry["quota"] = quota
        entry["task_count"] = len(entry["tasks"])
        result.append(entry)
    data = {"updated": now, "agents": result, "models": scan_models(),
            "total_installed": sum(1 for a in REGISTRY if find_bin(a["bins"])),
            "total_running": sum(len(v) for v in procs.values()),
            "env_tools": _system_ai_env(),
            "quota": qs, "ctl": ctl}
    _rt_cache.update({"t": now, "data": data})
    return data


# ---------------- 深度 Agent 详情自省 (Skills / MCP / Gateway / 记忆 / 设定) ----------------

def _extract_skills(base_dir):
    """递归扫描技能目录中的 SKILL.md，提取技能名、分类与描述。"""
    import glob as _glob
    skills = []
    if not base_dir or not os.path.isdir(base_dir):
        return skills
    for p in sorted(_glob.glob(os.path.join(base_dir, "**", "SKILL.md"), recursive=True)):
        dirpath = os.path.dirname(p)
        name = os.path.basename(dirpath)
        rel = os.path.relpath(dirpath, base_dir)
        cat = os.path.dirname(rel) if "/" in rel else ""
        desc = ""
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                head = f.read(1500)
                if head.startswith("---"):
                    parts = head.split("---", 2)
                    if len(parts) >= 3:
                        import yaml as _yaml
                        fm = _yaml.safe_load(parts[1])
                        if isinstance(fm, dict):
                            desc = str(fm.get("description") or "")
        except Exception:
            pass
        skills.append({
            "name": name,
            "category": cat or "general",
            "description": desc[:180] + ("…" if len(desc) > 180 else "")
        })
    return skills


def inspect_agent_detail(agent_id: str, for_public: bool = False) -> dict:
    """深度自省指定 Agent 的配置、运行状态、技能矩阵、MCP、通讯平台与记忆。"""
    reg = next((r for r in REGISTRY if r["id"] == agent_id), None)
    if not reg:
        return {"ok": False, "msg": f"unknown agent: {agent_id}"}

    binpath = find_bin(reg["bins"])
    ver = agent_version(binpath) if binpath else ""
    procs = scan_procs().get(agent_id, [])

    detail = {
        "ok": True,
        "id": agent_id,
        "name": reg["name"],
        "installed": bool(binpath),
        "bin": binpath or "",
        "version": ver,
        "procs": procs,
        "models": {},
        "skills": [],
        "mcp_servers": [],
        "platforms": {},
        "gateway": None,
        "memories": {},
        "cron": [],
        "config_summary": {},
    }

    # 1. Hermes 专项自省
    if agent_id == "hermes":
        hermes_home = HOME + "/.hermes"
        # 1.1 技能
        detail["skills"] = _extract_skills(os.path.join(hermes_home, "skills"))

        # 1.2 Gateway 状态与平台 (Telegram/Discord等)
        gw_path = os.path.join(hermes_home, "gateway_state.json")
        if os.path.isfile(gw_path):
            try:
                with open(gw_path, "r", encoding="utf-8") as f:
                    gw_data = json.load(f)
                    detail["gateway"] = {
                        "state": gw_data.get("gateway_state"),
                        "pid": gw_data.get("pid"),
                        "version": gw_data.get("code_version"),
                        "active_agents": gw_data.get("active_agents", 0),
                        "platforms": gw_data.get("platforms", {}),
                    }
                    detail["platforms"] = gw_data.get("platforms", {})
            except Exception:
                pass

        # 1.3 核心配置 (Model, Fallbacks, Platform toolsets)
        cfg_path = os.path.join(hermes_home, "config.yaml")
        if os.path.isfile(cfg_path):
            try:
                import yaml as _yaml
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = _yaml.safe_load(f) or {}
                m_conf = cfg.get("model") or {}
                if isinstance(m_conf, dict):
                    detail["models"] = {
                        "default": m_conf.get("default", "unknown"),
                        "provider": m_conf.get("provider", "unknown"),
                        "context_length": m_conf.get("context_length"),
                        "fallbacks": [
                            {"provider": fb.get("provider"), "model": fb.get("model")}
                            for fb in (cfg.get("fallback_providers") or []) if isinstance(fb, dict)
                        ]
                    }
                pt = cfg.get("platform_toolsets") or {}
                detail["config_summary"]["platform_toolsets"] = list(pt.keys())
                detail["config_summary"]["reasoning_effort"] = (cfg.get("agent") or {}).get("reasoning_effort")
            except Exception:
                pass

        # 1.4 记忆 (USER.md & MEMORY.md)
        mem_dir = os.path.join(hermes_home, "memories")
        if os.path.isdir(mem_dir):
            for m_file in ["USER.md", "MEMORY.md"]:
                mp = os.path.join(mem_dir, m_file)
                if os.path.isfile(mp):
                    try:
                        with open(mp, "r", encoding="utf-8") as f:
                            content = f.read()
                        lines = [line.strip() for line in content.split("§") if line.strip()]
                        detail["memories"][m_file] = {
                            "count": len(lines),
                            "preview": lines[0][:160] + "…" if lines else "",
                            "topics": [l[:90].replace("\n", " ") for l in lines[:10]]
                        }
                    except Exception:
                        pass

        # 1.5 定时任务 (Cron)
        cron_path = os.path.join(hermes_home, "cron", "jobs.json")
        if os.path.isfile(cron_path):
            try:
                with open(cron_path, "r", encoding="utf-8") as f:
                    cj = json.load(f)
                jobs = cj.get("jobs") or []
                clean_jobs = []
                for j in jobs:
                    clean_jobs.append({
                        "id": j.get("id"),
                        "name": j.get("name"),
                        "schedule": (j.get("schedule") or {}).get("display", "cron"),
                        "state": j.get("state"),
                        "enabled": j.get("enabled"),
                        "last_status": j.get("last_status"),
                        "last_run_at": j.get("last_run_at"),
                        "next_run_at": j.get("next_run_at"),
                        "prompt": j.get("prompt"),
                        "origin": j.get("origin")
                    })
                detail["cron"] = clean_jobs
            except Exception:
                pass

    # 2. Codex 专项自省
    elif agent_id == "codex":
        codex_home = HOME + "/.codex"
        detail["skills"] = _extract_skills(os.path.join(codex_home, "skills"))
        cfg_path = os.path.join(codex_home, "config.toml")
        if os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    txt = f.read()
                m_model = re.search(r'model\s*=\s*"([^"]+)"', txt)
                m_effort = re.search(r'model_reasoning_effort\s*=\s*"([^"]+)"', txt)
                detail["models"] = {
                    "default": m_model.group(1) if m_model else "unknown",
                    "reasoning_effort": m_effort.group(1) if m_effort else "unknown"
                }
                plugins = re.findall(r'\[plugins\."([^"]+)"\]', txt)
                detail["config_summary"]["plugins"] = plugins
            except Exception:
                pass

    # 3. Claude Code 专项自省
    elif agent_id == "claude":
        claude_home = HOME + "/.claude"
        detail["skills"] = _extract_skills(os.path.join(claude_home, "skills"))
        cfg_path = os.path.join(claude_home, "settings.json")
        if os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cdata = json.load(f)
                env = cdata.get("env") or {}
                detail["models"] = {
                    "opus": env.get("OPUS_MODEL", "default"),
                    "sonnet": env.get("SONNET_MODEL", "default")
                }
            except Exception:
                pass

    # 4. Antigravity (Gemini / agy) 专项自省
    elif agent_id == "agy":
        agy_home = HOME + "/.gemini/antigravity-cli"
        detail["skills"] = _extract_skills(os.path.join(agy_home, "builtin", "skills"))

    # 5. Pi 专项自省
    elif agent_id == "pi":
        pi_mcp = HOME + "/.pi/agent/mcp.json"
        if os.path.isfile(pi_mcp):
            try:
                with open(pi_mcp, "r", encoding="utf-8") as f:
                    m = json.load(f)
                servers = m.get("mcpServers") or {}
                detail["mcp_servers"] = [
                    {"name": sname, "command": sval.get("command", "")}
                    for sname, sval in servers.items()
                ]
            except Exception:
                pass

    # 深度脱敏与隐私保护过滤
    from svcdash.privacy import deep_sanitize, sanitize_agent_detail_for_public
    if for_public:
        return sanitize_agent_detail_for_public(detail)
    else:
        # 本地模式脱敏：仍清洗关键凭证，保留完整记忆结构与配置
        return deep_sanitize(detail, mask_ips=False, mask_paths=False)
