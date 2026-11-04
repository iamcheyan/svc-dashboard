"""svcdash/magpie.py — Magpie 网关用量与配额同步模块

从本机 Magpie Web 实例 (http://127.0.0.1:3426) 提取 Token 消耗、费用、模型/智能体统计与配额数据。
支持：
1. 动态探测本地 MAGPIE_WEB_KEY（环境 / systemd user unit / proc）
2. 聚合调用量、费用($)、输入/输出/推理/缓存 Token、TTFT/解码速率、小时趋势
3. 内存缓存（防频刷，today 15s / 7d 60s / 30d 120s）
4. 公网静态导出脱敏（保留模型、Token、费用与宏观趋势，打码账号敏感邮箱）
"""

import json
import os
import re
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from svcdash.privacy import red

MAGPIE_PORT = 3426
MAGPIE_URL = f"http://127.0.0.1:{MAGPIE_PORT}"
HOME = os.environ.get("SUDO_USER_HOME") or "/home/tetsuya"

_cache_lock = threading.Lock()
_usage_cache = {}  # period -> (timestamp, data)
_quotas_cache = (0.0, None)
_routing_cache = (0.0, None)
_providers_cache = (0.0, None)

_cached_key = None
_cached_key_time = 0.0


def _discover_magpie_key():
    """获取访问 Magpie Web API 所需的验证 Key。"""
    global _cached_key, _cached_key_time
    now = time.time()
    if _cached_key and (now - _cached_key_time < 300):
        return _cached_key

    # 1. 环境变量
    k = os.environ.get("MAGPIE_WEB_KEY")
    if k:
        _cached_key = k
        _cached_key_time = now
        return k

    # 2. 从 Magpie 用户服务的运行进程读取。dashboard 以 root 运行，
    # HOME 下的 unit 文件权限为 0600；按精确进程名读取服务环境，避免
    # 读取或输出 unit 内容，也不把密钥复制到 dashboard 配置。
    try:
        out = subprocess.check_output(["pgrep", "-x", "magpie"], timeout=1).decode().strip().split()
        for pid in out:
            env_file = f"/proc/{pid}/environ"
            if os.path.isfile(env_file):
                with open(env_file, "rb") as f:
                    for item in f.read().split(b"\0"):
                        if item.startswith(b"MAGPIE_WEB_KEY="):
                            value = item.split(b"=", 1)[1].decode("utf-8", "ignore").strip()
                            if value:
                                _cached_key = value
                                _cached_key_time = now
                                return value
    except Exception:
        pass

    svc_paths = [
        f"{HOME}/.config/systemd/user/magpie-web.service",
        os.path.expanduser("~/.config/systemd/user/magpie-web.service"),
    ]
    for p in svc_paths:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        m = re.match(r"^Environment=MAGPIE_WEB_KEY=([^\s]+)", line.strip())
                        if m:
                            _cached_key = m.group(1).strip()
                            _cached_key_time = now
                            return _cached_key
            except Exception:
                pass

    return ""


def get_magpie_usage(period="today", force=False):
    """获取指定时间段的 Magpie 流量用量统计数据 (today / 7d / 30d / all)。"""
    if period not in ("today", "7d", "30d", "all"):
        period = "today"

    ttl = 15 if period == "today" else 60 if period == "7d" else 120
    now = time.time()

    with _cache_lock:
        if not force and period in _usage_cache:
            ts, val = _usage_cache[period]
            if now - ts < ttl:
                return val

    key = _discover_magpie_key()
    url = f"{MAGPIE_URL}/api/usage?period={period}"
    headers = {"User-Agent": "svc-dashboard/1.0"}
    if key:
        headers["Cookie"] = f"magpie_web_{MAGPIE_PORT}={key}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
            # 补充状态标记
            data["ok"] = True
            data["fetched_at"] = now
            try:
                data["quotas"] = get_magpie_quotas(force=force)
            except Exception:
                data["quotas"] = []
            with _cache_lock:
                _usage_cache[period] = (now, data)
            return data
    except Exception as e:
        with _cache_lock:
            if period in _usage_cache:
                old_ts, old_data = _usage_cache[period]
                res = dict(old_data)
                res["stale"] = True
                if not res.get("quotas"):
                    try:
                        res["quotas"] = get_magpie_quotas(force=False)
                    except Exception:
                        pass
                return res

        try:
            fallback_quotas = get_magpie_quotas(force=False)
        except Exception:
            fallback_quotas = []

        return {
            "ok": False,
            "period": period,
            "err": str(e),
            "calls": 0,
            "cost": 0,
            "input": 0,
            "output": 0,
            "cache_read": 0,
            "reasoning": 0,
            "agents": [],
            "models": [],
            "series": [],
            "accounts": [],
            "quotas": fallback_quotas,
        }


def _get_local_agent_quotas() -> list:
    """获取本机智能体 (Antigravity, dim 等) 的配额信息，转换为统一配额卡片结构。"""
    try:
        from svcdash import runtimes
        # 触发后台刷新（若缓存过期）
        runtimes.refresh_quota(force=False)
        qs = runtimes.quota_snapshot()
        providers_data = qs.get("providers") or {}
    except Exception:
        providers_data = {}

    local_cards = []

    # 1. Antigravity (Gemini & Claude/GPT)
    agy = providers_data.get("agy")
    if agy and agy.get("ok"):
        user = agy.get("account") or "iamcheyan@gmail.com"
        windows = []
        for b in agy.get("buckets") or []:
            lbl = b.get("label") or ""
            lbl_low = lbl.lower()
            if "gemini-5h" in lbl_low or ("5h" in lbl_low and "gemini" in lbl_low):
                name = "Gemini 5h"
            elif "gemini-weekly" in lbl_low or ("weekly" in lbl_low and "gemini" in lbl_low):
                name = "Gemini Weekly"
            elif "3p-5h" in lbl_low or ("5h" in lbl_low and ("claude" in lbl_low or "3p" in lbl_low)):
                name = "Claude / GPT 5h"
            elif "3p-weekly" in lbl_low or ("weekly" in lbl_low and ("claude" in lbl_low or "3p" in lbl_low)):
                name = "Claude / GPT Weekly"
            else:
                name = lbl.split("·")[-1].strip() if "·" in lbl else lbl

            rem_pct = b.get("remaining_pct")
            used_pct = round(100.0 - float(rem_pct), 1) if rem_pct is not None else 0.0

            w = {
                "name": name,
                "used": used_pct,
            }
            if b.get("reset_ts"):
                try:
                    w["resetsAt"] = datetime.fromtimestamp(b["reset_ts"], timezone.utc).isoformat()
                except Exception:
                    pass
            elif b.get("reset"):
                w["resetsAt"] = b["reset"]

            windows.append(w)

        if windows:
            order_map = {"Gemini 5h": 1, "Gemini Weekly": 2, "Claude / GPT 5h": 3, "Claude / GPT Weekly": 4}
            windows.sort(key=lambda x: order_map.get(x["name"], 99))
            local_cards.append({
                "provider": "antigravity",
                "name": "Antigravity",
                "icon": "antigravity-color",
                "plan": "Google Cloud Code",
                "user": user,
                "windows": windows,
                "readAt": datetime.now(timezone.utc).isoformat()
            })

    # 2. dim (Credits)
    dim = providers_data.get("dim")
    if dim and dim.get("ok"):
        user = dim.get("account") or (agy.get("account") if agy else "") or "iamcheyan@gmail.com"
        windows = []
        for b in dim.get("buckets") or []:
            rem_pct = b.get("remaining_pct")
            used_pct = round(100.0 - float(rem_pct), 1) if rem_pct is not None else 0.0
            detail = b.get("detail") or ""
            
            m = re.search(r"(\d+)/(\d+)", detail)
            used_val = float(m.group(1)) if m else None
            lim_val = float(m.group(2)) if m else None
            rem_val = (lim_val - used_val) if (lim_val and used_val is not None) else None

            w = {
                "name": "Credits",
                "used": used_pct,
            }
            if used_val is not None and lim_val is not None:
                w["display"] = f"{int(used_val):,} / {int(lim_val):,}"
                w["amount"] = used_val
                w["limit"] = lim_val
                w["unit"] = "credits"
            if rem_val is not None:
                w["runsOut"] = rem_val

            if b.get("reset_ts"):
                try:
                    iso_r = datetime.fromtimestamp(b["reset_ts"], timezone.utc).isoformat()
                    w["resetsAt"] = iso_r
                    w["runsOutAt"] = iso_r
                except Exception:
                    pass
            elif b.get("reset"):
                w["resetsAt"] = b["reset"]
                w["runsOutAt"] = b["reset"]

            windows.append(w)

        if windows:
            local_cards.append({
                "provider": "dim",
                "name": "dim",
                "icon": "cpu",
                "plan": "Subscription",
                "user": user,
                "windows": windows,
                "readAt": datetime.now(timezone.utc).isoformat()
            })

    return local_cards


def get_magpie_quotas(force=False):
    """获取 Magpie 实时配额与余额信息，并合并本机智能体配额。"""
    global _quotas_cache
    now = time.time()
    with _cache_lock:
        ts, val = _quotas_cache
        if not force and val is not None and now - ts < 30:
            return val

    key = _discover_magpie_key()
    url = f"{MAGPIE_URL}/api/usage/quotas"
    headers = {"User-Agent": "svc-dashboard/1.0"}
    if key:
        headers["Cookie"] = f"magpie_web_{MAGPIE_PORT}={key}"

    req = urllib.request.Request(url, headers=headers)
    data = []
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception:
        # 回退：读取本地 quotas.json
        qfile = f"{HOME}/.config/magpie/quotas.json"
        if os.path.isfile(qfile):
            try:
                with open(qfile, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = []

    # 合并本机智能体配额 (Antigravity, dim 等置顶)
    local_cards = _get_local_agent_quotas()
    merged = list(local_cards)
    for q in (data or []):
        prov = (q.get("provider") or "").lower()
        if prov not in ("agy", "antigravity", "dim"):
            merged.append(q)

    with _cache_lock:
        _quotas_cache = (now, merged)
    return merged


def _mask_email(s: str) -> str:
    """脱敏邮箱或包含邮箱的字符串。"""
    if not isinstance(s, str):
        return s

    def _sub(m):
        user, domain = m.group(1), m.group(2)
        if len(user) <= 2:
            masked_user = user[0] + "***"
        else:
            masked_user = user[:2] + "***" + user[-1]
        return f"{masked_user}@{domain}"

    return re.sub(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", _sub, s)


def _public_sub_label(sub, lang="zh"):
    """模型 sub 标签形如 'Provider · Account': 保留供应商名, 账号部分整体隐藏。"""
    if not isinstance(sub, str) or not sub:
        return sub
    head, sep, _tail = sub.rpartition("·")
    if not sep:
        return sub  # 纯供应商名 (DeepSeek / WorkBuddy 等), 不含账号标识
    return (head.strip() + " · " + red("account", lang)) if head.strip() else red("account", lang)


def sanitize_magpie_usage_for_public(usage_data: dict, lang: str = "zh") -> dict:
    """对静态公开版中的 Magpie 流量看板进行安全脱敏：
    - 保留总调用量、费用($)、输入/输出/推理/缓存 Token、小时序列、延迟和模型/智能体名称
    - 账号标识(邮箱/显示名/ID)整体替换为语言化占位符, 由前端统一打马赛克
    """
    if not isinstance(usage_data, dict):
        return usage_data

    clean = json.loads(json.dumps(usage_data, ensure_ascii=False))
    acc_red = red("account", lang)

    # 1. 路径隐藏
    if "path" in clean:
        clean["path"] = "~/.config/magpie/usage.jsonl"

    # 2. 账号列表脱敏: 账号标识与显示名整体隐藏(显示名可能是个人名字, 不能部分打码)
    if "accounts" in clean and isinstance(clean["accounts"], list):
        for acc in clean["accounts"]:
            if isinstance(acc, dict):
                acc["account"] = acc_red
                acc["name"] = acc_red
                acc["id"] = acc_red

    # 3. 模型列表脱敏 (models 中的 id / host / sub)
    if "models" in clean and isinstance(clean["models"], list):
        for m in clean["models"]:
            if isinstance(m, dict):
                if m.get("id") and "@" in str(m["id"]):
                    head, _sep, _tail = str(m["id"]).partition("@")
                    m["id"] = (head.strip() + " @ " + acc_red) if head.strip() else acc_red
                if m.get("host"):
                    m["host"] = acc_red
                if m.get("sub"):
                    m["sub"] = _public_sub_label(m["sub"], lang)

    # 4. Caller Keys 脱敏
    if "callerKeys" in clean and isinstance(clean["callerKeys"], list):
        for k in clean["callerKeys"]:
            if isinstance(k, dict):
                cid = k.get("callerKeyId") or k.get("id") or ""
                if len(cid) > 8:
                    k["callerKeyId"] = cid[:4] + "..." + cid[-4:]
                    k["id"] = k["callerKeyId"]

    # 5. Quotas 脱敏: 账号邮箱整体替换为占位符
    if "quotas" in clean and isinstance(clean["quotas"], list):
        for q in clean["quotas"]:
            if isinstance(q, dict):
                if q.get("user"):
                    q["user"] = acc_red
                ci = q.get("checkin")
                if isinstance(ci, dict):
                    for ck in ("user", "by"):
                        if ci.get(ck):
                            ci[ck] = acc_red
                if q.get("accounts") and isinstance(q["accounts"], list):
                    for acc in q["accounts"]:
                        if isinstance(acc, dict) and acc.get("user"):
                            acc["user"] = acc_red

    return clean


_groups_cache = (0, [], [], [], [])
_hist_cache = (0, [])

def get_magpie_routing(force=False):
    """获取 Magpie 实时网关路由决策、统计与最近请求流。"""
    global _routing_cache, _groups_cache, _hist_cache
    now = time.time()
    ts, cached = _routing_cache
    if not force and cached is not None and (now - ts < 8):
        return cached

    key = _discover_magpie_key()
    headers = {"User-Agent": "svc-dashboard/1.0"}
    if key:
        headers["Cookie"] = f"magpie_web_{MAGPIE_PORT}={key}"

    try:
        # 1. 抓取 trace (最近 60 条路由及 totals)
        req_trace = urllib.request.Request(f"{MAGPIE_URL}/api/gateway/trace?after=0", headers=headers)
        with urllib.request.urlopen(req_trace, timeout=4) as resp:
            trace_data = json.loads(resp.read().decode("utf-8", "ignore"))

        # 2. 抓取 history (按日请求量汇总, 60s 缓存)
        g_ts, days_list = _hist_cache
        if force or not days_list or (now - g_ts > 60):
            try:
                req_hist = urllib.request.Request(f"{MAGPIE_URL}/api/gateway/history", headers=headers)
                with urllib.request.urlopen(req_hist, timeout=3) as resp:
                    hdata = json.loads(resp.read().decode("utf-8", "ignore"))
                    days_list = hdata.get("days", [])
                    _hist_cache = (now, days_list)
            except Exception:
                pass

        # 3. 抓取 groups (路由组配置与池, 60s 缓存)
        p_ts, groups_list, pools_list, models_list, deciders_list = _groups_cache
        if force or not groups_list or (now - p_ts > 60):
            try:
                req_groups = urllib.request.Request(f"{MAGPIE_URL}/api/groups", headers=headers)
                with urllib.request.urlopen(req_groups, timeout=3) as resp:
                    gdata = json.loads(resp.read().decode("utf-8", "ignore"))
                    groups_list = gdata.get("groups", [])
                    pools_list = gdata.get("pools", [])
                    models_list = gdata.get("models", [])
                    deciders_list = gdata.get("deciders", [])
                    _groups_cache = (now, groups_list, pools_list, models_list, deciders_list)
            except Exception:
                pass

        res = {
            "ok": True,
            "totals": trace_data.get("totals", {}),
            "now": trace_data.get("now", ""),
            "seq": trace_data.get("seq", 0),
            "routes": trace_data.get("routes", []),
            "days": days_list,
            "groups": groups_list,
            "pools": pools_list,
            "models": models_list,
            "deciders": deciders_list,
            "fetched_at": now
        }
        with _cache_lock:
            _routing_cache = (now, res)
        return res
    except Exception as e:
        if cached is not None:
            c = dict(cached)
            c["stale"] = True
            return c
        return {
            "ok": False,
            "err": str(e),
            "totals": {"requests": 0, "rerouted": 0, "errors": 0},
            "routes": [],
            "days": [],
            "groups": [],
            "pools": []
        }


def get_magpie_providers(force=False):
    """获取 Magpie 供应商列表、预设、多账号及模型清单。"""
    global _providers_cache
    now = time.time()
    ts, cached = _providers_cache
    if not force and cached is not None and (now - ts < 30):
        return cached

    key = _discover_magpie_key()
    headers = {"User-Agent": "svc-dashboard/1.0"}
    if key:
        headers["Cookie"] = f"magpie_web_{MAGPIE_PORT}={key}"

    try:
        req = urllib.request.Request(f"{MAGPIE_URL}/api/providers", headers=headers)
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))

        provs = data.get("providers", [])
        for p in provs:
            models = p.get("models") or []
            active_cnt = len([m for m in models if isinstance(m, dict) and m.get("on")])
            p["active_models_count"] = active_cnt if active_cnt > 0 else len(models)
            p.pop("models", None)
            p.pop("catalog", None)
            p.pop("searchModels", None)
            p.pop("drawIds", None)
            if "agents" in p and isinstance(p["agents"], list):
                p["agents"] = [
                    {"id": a.get("id"), "name": a.get("name"), "icon": a.get("icon"), "current": bool(a.get("current"))}
                    for a in p["agents"] if isinstance(a, dict) and a.get("current")
                ]

        res = {
            "ok": True,
            "providers": provs,
            "presets": {},
            "fetched_at": now
        }
        with _cache_lock:
            _providers_cache = (now, res)
        return res
    except Exception as e:
        if cached is not None:
            c = dict(cached)
            c["stale"] = True
            return c
        return {"ok": False, "err": str(e), "providers": [], "presets": {}}


def sanitize_magpie_routing_for_public(routing_data: dict, lang: str = "zh") -> dict:
    """脱敏公开路由数据：账号标识整体替换为语言化占位符(前端打马赛克)，保留 Token、延迟、耗时树与宏观指标。"""
    if not isinstance(routing_data, dict):
        return routing_data
    clean = json.loads(json.dumps(routing_data, ensure_ascii=False))
    acc_red = red("account", lang)

    # 池成员: who 是账号标识列表(可能是邮箱或个人显示名)
    if isinstance(clean.get("pools"), list):
        for p in clean["pools"]:
            if isinstance(p, dict) and p.get("who"):
                p["who"] = [acc_red for _ in p["who"]]

    routes = clean.get("routes", [])
    if isinstance(routes, list):
        for r in routes:
            if not isinstance(r, dict):
                continue
            if r.get("conv") and len(str(r["conv"])) > 16:
                r["conv"] = r["conv"][:8] + "..." + r["conv"][-4:]
            for coll in ("order", "left", "tries"):
                for o in r.get(coll) or []:
                    if not isinstance(o, dict):
                        continue
                    if o.get("id"):
                        o["id"] = acc_red
                    if o.get("who"):
                        o["who"] = acc_red
                    # 429 冷却记录: key 为 账号邮箱/模型 组合键
                    rest = o.get("rest")
                    if isinstance(rest, dict) and rest.get("key"):
                        rest["key"] = acc_red
            if r.get("prompt") and isinstance(r["prompt"], dict):
                parts = r["prompt"].get("parts") or []
                for p in parts:
                    if isinstance(p, dict) and p.get("items"):
                        for item in p.get("items") or []:
                            if isinstance(item, dict) and item.get("name"):
                                raw_n = str(item["name"])
                                if "/" in raw_n or "\\" in raw_n:
                                    item["name"] = os.path.basename(raw_n) or "file"

    return clean


def sanitize_magpie_providers_for_public(providers_data: dict, lang: str = "zh") -> dict:
    """脱敏公开供应商数据：账号标识整体替换为语言化占位符，保留模型、配额类型与开关状态。"""
    if not isinstance(providers_data, dict):
        return providers_data
    clean = json.loads(json.dumps(providers_data, ensure_ascii=False))
    acc_red = red("account", lang)

    for p in clean.get("providers", []):
        if not isinstance(p, dict):
            continue
        p.pop("proxy", None)
        p.pop("authHeader", None)
        # Magpie's newer provider schema stores a credential identifier (and
        # sometimes its secret) under accessKey; the public UI does not use it.
        p.pop("accessKey", None)
        acc = p.get("account")
        if isinstance(acc, dict):
            if acc.get("user"):
                acc["user"] = acc_red
            for l in acc.get("logins") or []:
                if isinstance(l, dict) and l.get("user"):
                    l["user"] = acc_red
        key_obj = p.get("key")
        if isinstance(key_obj, dict):
            key_obj["masked"] = "••••••"
            if key_obj.get("id"):
                key_obj["id"] = "key"
        for k in p.get("keyList") or []:
            if isinstance(k, dict):
                k["masked"] = "••••••"
                if k.get("id"):
                    k["id"] = "key"

    return clean

