import json, os, re, socket, threading, time
from html import escape
from urllib.parse import quote
from svcdash.i18n import t, L10N, DEFAULT_LANG, _apply_t
from svcdash.icons import ICONS, icon, _ICO_PAT
from svcdash.sysinfo import sys_info, fmt_bytes, fmt_uptime
from svcdash.tools import tools_conf
from svcdash.goals import (scan_goals, merge_events, parse_watchdog_events,
                           parse_completed_goals, TOOL_LINKS, fmt_ago)
from svcdash.repos import parse_repo_commits
from svcdash.procscan import gather
from svcdash.manage import MANAGE_UNITS
from svcdash.config import AUTO_REFRESH_SEC

_STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
# 事件类型 -> (图标, 语义色 class, i18n key)。前端 EV_META 与此同构。
KIND_META = {
    "complete": ("ok", "t-green", "evk_complete"),
    "recover": ("up", "t-green", "evk_recover"),
    "restart": ("retry", "t-red", "evk_restart"),
    "nudge": ("bell", "t-warn", "evk_nudge"),
    "pause": ("pause", "t-warn", "evk_pause"),
    "reclaim": ("trash", "t-green", "evk_reclaim"),
    "cleanup": ("trash", "t-green", "evk_cleanup"),
    "commit": ("branch", "t-green", "evk_commit"),
}
def render_sysbar(s, lang=DEFAULT_LANG):
    """系统信息卡片条(打开页面时渲染一次,手动刷新才更新)。"""
    loadavg = " / ".join(f"{x:.2f}" for x in s["loadavg"]) if s.get("loadavg") else "—"
    cpu = f'{s["cpu_usage"]}% · {s["cpu_count"]} {t(lang, "unit_core")}'
    mem = s.get("mem") or {}
    mem_txt = f'{fmt_bytes(mem.get("used"))} / {fmt_bytes(mem.get("total"))} ({mem.get("percent", 0)}%)'
    disk = s.get("disk") or {}
    disk_txt = f'{fmt_bytes(disk.get("used"))} / {fmt_bytes(disk.get("total"))} ({disk.get("percent", 0)}%)'
    # P1-2: 指标值状态色(>90 红 / ≥75 黄, 与 renderHealth 阈值同风格); load/up 非百分比不上色
    def _zone(pct):
        try:
            pct = float(pct)
        except (TypeError, ValueError):
            return ""
        return " bad" if pct > 90 else " warn" if pct >= 75 else ""

    cards = [
        ("load", t(lang, "sys_load"), loadavg, ""),
        ("cpu", "CPU", cpu, _zone(s.get("cpu_usage"))),
        ("mem", t(lang, "sys_mem"), mem_txt, _zone(mem.get("percent", 0))),
        ("disk", t(lang, "sys_disk"), disk_txt, _zone(disk.get("percent", 0))),
        ("up", t(lang, "sys_up"), fmt_uptime(s.get("uptime"), lang), ""),
    ]
    # data-k: 手机端双击手势定位(负载卡双击→Goal页, 磁盘卡双击→展开top进程)
    k_ico = {"load": "load", "cpu": "cpu", "mem": "mem", "disk": "disk", "up": "clock"}
    return '<div class="sysbar" id="sysbar">' + "".join(
        f'<div class="stat" data-k="{k}"><div class="label">'
        f'<span class="lb-ico">{icon(k_ico.get(k, "dot"), 13)}</span>{lbl}</div>'
        f'<div class="value{cls}">{val}</div></div>' for k, lbl, val, cls in cards) + "</div>"
BADGE = {
    "docker": "badge-docker",
    "systemd": "badge-systemd",
    "direct": "badge-direct",
}
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
        else:
            extra.append(f'<div class="grow"><span>{t(lang, "g_ctx")}</span>'
                         f'<span class="gtx">—</span></div>')
        if c["retry"]:
            extra.append(f'<div class="grow"><span>API</span>'
                         f'<span class="gretry">{t(lang, "g_retrying", n=c["retry"])}</span></div>')
        else:
            extra.append(f'<div class="grow"><span>API</span><span class="gtx">—</span></div>')
        if c["idle_sec"] is not None:
            ago = fmt_ago(c["idle_sec"], lang)
            stall = f' · {t(lang, "g_stalled")}' if c["stalled"] else ""
            idle_row = (f'<div class="grow"><span>{t(lang, "g_last")}</span>'
                        f'<span class="{"gstalled" if c["stalled"] else "gidle"}">{ago}{stall}</span></div>')
        else:
            idle_row = (f'<div class="grow"><span>{t(lang, "g_last")}</span>'
                        f'<span class="gidle">—</span></div>')
        if c["progress"]:
            prog = "<br>".join(escape(x) for x in c["progress"])
            extra.append(f'<div class="gprog">{prog}</div>')
        more = (f'<span class="gmore" title="{t(lang, "g_detail")}">{icon("chev", 12)}</span>') if extra else ""
        detail = (f'<span class="g-detail-btn" role="button" tabindex="0" '
                  f'data-gid="{escape(c["gid"], quote=True)}" '
                  f'data-session="{escape(c["session"], quote=True)}">'
                  f'{icon("doc", 12)} {t(lang, "g_view_detail")}</span>')
        head = (f'<div class="ghead">{glight}'
                f'<span class="gname">{escape(c["name"])}</span>'
                f'<span class="gstate">{t(lang, key)}</span>{more}{detail}</div>')
        if c["label"] and c["label"] != c["name"]:
            head += f'<div class="gsub">{escape(c["label"][:60])}</div>'
        elif c["objective"]:
            head += f'<div class="gsub">{escape(c["objective"])}</div>'
        inner = head + idle_row
        if extra:
            inner += f'<div class="gextra">{"".join(extra)}</div>'
        # 恒定行集: footer 无条件渲染(缺 resume 显 —, 底边 margin-top:auto 对齐);
        # paused/lost 卡额外给"标记忽略"处置(前端接 ignoredSet, key 与 goalAlerts 一致)
        foot = ['<div class="gfoot">']
        if c["resume_cmd"]:
            foot.append(f'<span class="gcopy" role="button" tabindex="0" '
                        f'data-cmd="{escape(c["resume_cmd"], quote=True)}">{icon("copy", 13)} {t(lang, "g_copy")}</span>')
        else:
            foot.append('<span class="gfoot-none">—</span>')
        if c["light"] in ("paused", "lost"):
            ign_key = f'{c["light"]}|{c["gid"] or c["session"] or c["name"]}'
            foot.append(f'<span class="g-ignore-btn" role="button" tabindex="0" '
                        f'data-ign-key="{escape(ign_key, quote=True)}">{t(lang, "g_ignore")}</span>')
        foot.append("</div>")
        inner += "".join(foot)
        # 复制 resume 命令 = 卡片内显式 .gcopy 按钮(无滑扫手势)
        out.append(f'<div class="gcard" data-light="{c["light"]}">{inner}</div>')
    body = "".join(out) if out else (
        f'<div class="empty-state"><span class="es-ico">{icon("gauge", 44)}</span>'
        f'<span class="es-title">{escape(t(lang, "g_none"))}</span>'
        f'<span class="es-sub">{t(lang, "es_sub")}</span></div>')
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
def render_toolchips(entries, host_header, lang=DEFAULT_LANG):
    """快捷工具入口 chips: 端口存活才显示,点击直达。"""
    ports = {e["port"] for e in entries if not e.get("paused")}   # 暂停/冻结的服务不出现在快捷入口
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
_frag_cache = {}                 # (frag, lang) -> (ts, html); 只在锁内读写
PAGE_CACHE_SEC = 5               # fragment 缓存 TTL(原字面量抽常量; 重构时漏定义致 NameError)
_frag_locks = {}                 # (frag, lang) -> per-key Lock: 渲染不占全局锁
_frag_lock = threading.Lock()    # 仅保护上面两个 dict 本身

_SHELL_TPL = None
_SHELL_TPL_LOCK = threading.Lock()
_SHELL_LITE = {}   # lang -> 渲好的 lite 壳(永久缓存, 含 {{BOOT_JSON}} 占位)

def _shell_tpl():
    global _SHELL_TPL
    if _SHELL_TPL is None:
        with _SHELL_TPL_LOCK:
            if _SHELL_TPL is None:
                with open(os.path.join(_STATIC_DIR, "index.html"), encoding="utf-8") as f:
                    _SHELL_TPL = f.read()
    return _SHELL_TPL

def _lite_sysbar(lang):
    return '<div class="sysbar" id="sysbar">' + "".join(
        f'<div class="stat" data-k="{k}"><div class="label">{t(lang, key)}</div><div class="value">—</div></div>'
        for k, key in (("load", "sys_load"), ("cpu", "sys_cpu"), ("mem", "sys_mem"),
                       ("disk", "sys_disk"), ("up", "sys_up"))) + '</div>'

_LITE_GOALS = ('<div class="gpanel" id="goals"><h2>{{T:g_panel}} <span class="ghint">{{T:g_hint}}</span></h2>'
               '<div class="gcards">' + "".join(
                   '<div class="skel"><div class="skel-line" style="width:86%"></div>'
                   '<div class="skel-line" style="width:64%"></div></div>' for _ in range(3))
               + '</div></div>')
_LITE_EVENTS = ('<div class="gpanel" id="events"><h2>{{T:ev_title}} <span class="ghint">{{T:ev_hint}}</span></h2>'
                '<div class="gempty">{{T:a_loading}}</div></div>')


def _svc_rows(entries, lang, host_header):
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
        hostname = host_header.split(":")[0]
        if is_loopback:
            link = f"http://127.0.0.1:{port}/"
            loop = f'<span class="local">{t(lang, "loopback")}</span>'
        else:
            link = f"http://{hostname}:{port}/"
            loop = ""
        man = next((u for u in MANAGE_UNITS
                    if u["kind"] == "proc" and u["port"] == port), None)
        ctl_btn = ""
        if man:
            ctl_btn = (f'<span class="cmd-ctl"><span class="ctl-btn" data-ctl="{man["id"]}" data-port="{port}" '
                       f'role="button" tabindex="0" aria-disabled="true">…</span></span>')
        import json as _json
        det = _json.dumps({"name": e["name"], "port": port, "ip": ip,
                           "cmd": e["cmdline"] or "", "cwd": e["cwd"] or "",
                           "pids": e.get("pids") or []}, ensure_ascii=False)
        det_enc = escape(quote(det, safe=""), quote=True)
        detail_btn = (f'<span class="svc-detail" role="button" tabindex="0" data-detail="{det_enc}" '
                      f'title="{t(lang, "svc_detail")}">{t(lang, "svc_detail")}</span>')
        cmd_cell = f'<div class="cmd-cell"><span class="cmd-text">{cmd}</span>{detail_btn}{ctl_btn}</div>'
        cwd_cell = f'<div class="cmd-cell"><span class="cmd-text">{cwd}</span>{detail_btn}</div>'
        rows.append(
            f'<tr>'
            f'<td class="name"><span class="svc">{escape(e["name"])}</span>'
            f'<span class="badge {badge_cls}">{badge_text}</span>{detail}</td>'
            f'<td class="port" data-label="{t(lang, "th_port")}"><a href="{link}" target="_blank" rel="noopener">{port}</a></td>'
            f'<td class="addr" data-label="{t(lang, "th_addr")}">{escape(ip)} {loop}</td>'
            f'<td class="pid" data-label="PID">{pids}</td>'
            f'<td class="cmd" data-label="{t(lang, "th_cmd")}">{cmd_cell}</td>'
            f'<td class="cwd" data-label="{t(lang, "th_cwd")}">{cwd_cell}</td>'
            f'</tr>')
    return "\n".join(rows)


def _render_shell_core(host_header, entries, updated_ts, lang, sysdata):
    """渲染壳(lite 或 full), 填充除 {{BOOT_JSON}} 外所有占位; lite 按语言永久缓存。"""
    lite = not entries
    if lite:
        cached = _SHELL_LITE.get(lang)
        if cached is not None:
            return cached
    hostname = socket.gethostname()
    if lite:
        sysbar = _lite_sysbar(lang)
        table = ""
        toolchips = ""
        goals_panel = _LITE_GOALS
        events_panel = _LITE_EVENTS
    else:
        if sysdata is None:
            sysdata = sys_info()
        sysbar = render_sysbar(sysdata, lang)
        table = _svc_rows(entries, lang, host_header)
        toolchips = render_toolchips(entries, host_header, lang)
        goals_panel = render_goal_cards(scan_goals(), lang)
        events_panel = render_events(merge_events(
            parse_watchdog_events(), parse_completed_goals(),
            parse_repo_commits()), lang)
    body = (_shell_tpl()
            .replace("{{LANG}}", lang)
            .replace("{{HOSTNAME}}", escape(hostname))
            .replace("{{SYSBAR}}", sysbar)
            .replace("{{TOOLCHIPS}}", toolchips)
            .replace("{{GOALS_PANEL}}", goals_panel)
            .replace("{{EVENTS_PANEL}}", events_panel)
            .replace("{{UPDATED}}", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(updated_ts)))
            .replace("{{COUNT}}", str(len(entries)))
            .replace("<!--TABLE-->", table))
    body = _ICO_PAT.sub(lambda m: icon(m.group(1), int(m.group(2) or 16)), body)
    body = _apply_t(body, lang)
    if lite:
        _SHELL_LITE[lang] = body
    return body


def render_html(host_header, entries, updated_ts, lang=DEFAULT_LANG, sysdata=None, ts_mode=False):
    body = _render_shell_core(host_header, entries, updated_ts, lang, sysdata)
    boot = {"auto": AUTO_REFRESH_SEC, "lang": lang, "tsMode": bool(ts_mode),
            "t": L10N.get(lang, L10N[DEFAULT_LANG]),
            "icons": ICONS,
            "tl": tools_conf()}
    return body.replace("{{BOOT_JSON}}", json.dumps(boot, ensure_ascii=False), 1)


def render_fragment(frag, lang, host_header, ts_mode=False):
    """?p=goals|events|toolchips -> HTML 片段(5s 缓存); 未知返回 None。
    锁策略: 缓存命中只碰全局锁(快); 未命中按 key 取专属锁渲染——重渲染
    (scan_goals/gather 可达秒级)不再阻塞其他 frag/lang 的并发请求。"""
    key = (frag, lang)
    with _frag_lock:
        ent = _frag_cache.get(key)
        klock = _frag_locks.setdefault(key, threading.Lock())
    now = time.time()
    if ent and now - ent[0] < PAGE_CACHE_SEC:
        return ent[1]
    with klock:   # 同 key 并发只渲染一次; 不同 key 完全并行
        with _frag_lock:
            ent = _frag_cache.get(key)
        if ent and time.time() - ent[0] < PAGE_CACHE_SEC:
            return ent[1]
        if frag == "goals":
            html = render_goal_cards(scan_goals(), lang)
        elif frag == "events":
            html = render_events(merge_events(
                parse_watchdog_events(), parse_completed_goals(),
                parse_repo_commits()), lang)
        elif frag == "toolchips":
            html = render_toolchips(gather(), host_header, lang)
        else:
            return None
        with _frag_lock:
            _frag_cache[key] = (time.time(), html)
    return html
