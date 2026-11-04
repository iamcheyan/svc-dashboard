#!/usr/bin/env python3
"""静态仪表盘导出与 GitHub Pages 部署模块。
导出经脱敏、无服务依赖的只读静态面板，可发布至 GitHub Pages 或静态 CDN。
"""
import hashlib, json, os, re, shutil, subprocess, tempfile, time
from svcdash import procscan, sysinfo, goals, repos, tasks, agents
from svcdash.config import STATIC_DIR, DEFAULT_LANG
from svcdash.i18n import L10N, LANG_KEYS
from svcdash.icons import ICONS
from svcdash.render import _render_shell_core, _svc_rows, icon_files
from svcdash.tools import tools_conf


from svcdash.privacy import (  # noqa: F401
    sanitize_services_for_public,
    sanitize_tmux_for_public,
    sanitize_tools_conf_for_public,
    sanitize_public_payload,
    deep_sanitize,
    scan_for_secrets,
    mask_secret,
    sanitize_text,
    redact_marker_re,
)


def _static_chart_history(sysdata, limit=24):
    """为静态快照保留发布器自己的趋势历史，不依赖访客浏览器 localStorage。"""
    now = time.time()
    mem = sysdata.get("mem") or {}
    sample = {
        "t": int(now * 1000),
        "load": ((sysdata.get("loadavg") or [None])[0]),
        "cpu": sysdata.get("cpu_usage"),
        "mem": mem.get("percent"),
        "swap": mem.get("swap_percent"),
    }
    state_dir = os.environ.get(
        "SVC_DASHBOARD_STATIC_STATE",
        os.path.expanduser("~/.cache/svc-dashboard-static"),
    )
    state_path = os.path.join(state_dir, "chart.json")
    history = []
    try:
        with open(state_path, encoding="utf-8") as fp:
            loaded = json.load(fp)
        if isinstance(loaded, list):
            history = [x for x in loaded if isinstance(x, dict)][-limit:]
    except (OSError, ValueError, TypeError):
        pass

    history.append(sample)
    # 首次发布也给前端一个完整窗口，避免只在最右侧显示一个点。
    if len(history) == 1:
        history = [dict(sample, t=sample["t"] - (limit - i - 1) * 600000) for i in range(limit)]
    else:
        history = history[-limit:]
    try:
        os.makedirs(state_dir, exist_ok=True)
        tmp = state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(history, fp, ensure_ascii=False)
        os.replace(tmp, state_path)
    except OSError:
        pass
    return history


def _collect_static_snapshot(lang=DEFAULT_LANG):
    now = time.time()
    raw_services = {lg: procscan.gather(lg) for lg in LANG_KEYS}
    # 脱敏占位符随语言变化: 三语页面共用同一采集快照, 因此按语言各脱敏一份。
    clean_services = {lg: sanitize_services_for_public(raw_services[lg], lg) for lg in LANG_KEYS}
    sysdata = deep_sanitize(sysinfo.sys_info(), mask_ips=True, mask_paths=True)
    chart_data = _static_chart_history(sysdata)

    g_list = goals.scan_goals()
    g_completed = goals.parse_completed_goals(limit=60)
    g_wd = goals.parse_watchdog_events(limit=80)
    commits = repos.parse_repo_commits(per_repo=15, total=100)
    events = goals.merge_events(g_wd, g_completed, commits, limit=100)
    goals_data = deep_sanitize({
        "updated": now,
        "goals": g_list,
        "completed": g_completed,
        "events": events
    }, mask_ips=True, mask_paths=True)

    repos_data = deep_sanitize(repos.repo_stats(), mask_ips=True, mask_paths=True)

    # Tmux 会话全量拓扑脱敏：彻底抹除实际终端输出预览与私有路径
    raw_tmux = agents.scan_tmux_full()
    clean_tmux = {lg: sanitize_tmux_for_public(raw_tmux, lg) for lg in LANG_KEYS}

    # Agent 智能体状态脱敏与详情收集
    clean_agent_details = {}
    try:
        from svcdash.runtimes import (scan_runtimes, REGISTRY, inspect_agent_detail,
                                      refresh_quota, quota_snapshot)
        from svcdash.privacy import sanitize_runtimes_for_public
        # 发布器是独立进程，没有在线 dashboard 的内存缓存；主动采集一次，
        # 否则静态页即使保留 quota 字段也会一直没有额度水位。
        refresh_quota()
        quota_deadline = time.monotonic() + 110
        while quota_snapshot().get("running") and time.monotonic() < quota_deadline:
            time.sleep(0.25)
        _rt_raw = scan_runtimes()
        clean_runtimes = {lg: sanitize_runtimes_for_public(_rt_raw, lg) for lg in LANG_KEYS}
        # 脱敏占位符是语言相关的: 三个语言页面共用同一快照, 因此每个 agent
        # 需要按三种语言各脱敏一份, 供对应语言页面取用。
        for a in REGISTRY:
            aid = a["id"]
            for page_lang in LANG_KEYS:
                clean_agent_details.setdefault(page_lang, {})[aid] = inspect_agent_detail(
                    aid, for_public=True, lang=page_lang)
    except Exception:
        clean_runtimes = {}
        clean_agent_details = {}

    clean_tl = {lg: sanitize_tools_conf_for_public(tools_conf(), lg) for lg in LANG_KEYS}

    # Magpie 网关数据收集 (用量/路由/供应商)
    clean_magpie_usage = {}
    clean_magpie_routing = {}
    clean_magpie_providers = {}
    try:
        from svcdash.magpie import (
            get_magpie_usage, sanitize_magpie_usage_for_public,
            get_magpie_routing, sanitize_magpie_routing_for_public,
            get_magpie_providers, sanitize_magpie_providers_for_public
        )
        raw_mp = get_magpie_usage("today", force=True)
        clean_magpie_usage = {lg: sanitize_magpie_usage_for_public(raw_mp, lg) for lg in LANG_KEYS}
        raw_routing = get_magpie_routing(force=True)
        clean_magpie_routing = {lg: sanitize_magpie_routing_for_public(raw_routing, lg) for lg in LANG_KEYS}
        raw_providers = get_magpie_providers(force=True)
        clean_magpie_providers = {lg: sanitize_magpie_providers_for_public(raw_providers, lg) for lg in LANG_KEYS}
    except Exception as e:
        print(f"[!] 采集 Magpie 数据异常: {e}")
        clean_magpie_usage = {lg: {} for lg in LANG_KEYS}
        clean_magpie_routing = {lg: {} for lg in LANG_KEYS}
        clean_magpie_providers = {lg: {} for lg in LANG_KEYS}

    # PVE 虚拟机数据与详情收集 (Windows11 / DEBIAN 等)
    clean_vms = {}
    clean_vms_detail = {}
    try:
        from svcdash.pve import (
            get_pve_vms, sanitize_pve_vms_for_public,
            get_pve_vm_detail, sanitize_pve_vm_detail_for_public
        )
        raw_vms = get_pve_vms(force=True)
        clean_vms = {lg: sanitize_pve_vms_for_public(raw_vms, lg) for lg in LANG_KEYS}
        for v in (raw_vms.get("vms") or []):
            vid = str(v.get("vmid"))
            dt = get_pve_vm_detail(vid, force=True)
            for lg in LANG_KEYS:
                clean_vms_detail.setdefault(lg, {})[vid] = sanitize_pve_vm_detail_for_public(dt, lg)
    except Exception as e:
        print(f"[!] 采集 PVE 虚拟机数据异常: {e}")
        clean_vms = {lg: {"ok": False, "vms": []} for lg in LANG_KEYS}
        clean_vms_detail = {lg: {} for lg in LANG_KEYS}

    return {
        "now": now, "clean_services": clean_services, "sysdata": sysdata,
        "chart_data": chart_data, "goals_data": goals_data,
        "repos_data": repos_data, "clean_tmux": clean_tmux,
        "clean_runtimes": clean_runtimes, "clean_agent_details": clean_agent_details,
        "clean_tl": clean_tl, "clean_magpie_usage": clean_magpie_usage,
        "clean_magpie_routing": clean_magpie_routing,
        "clean_magpie_providers": clean_magpie_providers,
        "clean_vms": clean_vms,
        "clean_vms_detail": clean_vms_detail,
    }


def _collect_public_tasks():
    """静态快照里的任务列表：只保留 issue 标题与摘要。

    正文、分支、机器、执行日志、编号都不采集——公开页面上出现的就是全部内容，
    不做"发布后模糊"（CSS blur 在开发者工具里一键就能去掉，不能当隐私边界）。
    带 private / secret / no-publish 标签的 issue 直接跳过。
    """
    try:
        from . import taskhub as th_mod
        d = th_mod.issues(mode="open")
        if d.get("ok") is False:
            return {"items": [], "error": d.get("msg") or "taskhub unavailable"}
        items = []
        for it in (d.get("issues") or []):
            labels = [str(l).lower() for l in (it.get("labels") or [])]
            if any(l in {"private", "secret", "no-publish"} for l in labels):
                continue
            title = (it.get("title") or "").strip()
            if not title:
                continue
            items.append({"title": title, "excerpt": (it.get("excerpt") or "").strip()})
        return {"items": items[:40], "count": len(items)}
    except Exception as exc:
        return {"items": [], "error": str(exc)[:120]}


def _public_tasks_payload(lang=DEFAULT_LANG):
    data = _collect_public_tasks()
    items = []
    for it in data.get("items") or []:
        items.append({
            "title": sanitize_text(str(it.get("title") or ""))[:160],
            "excerpt": sanitize_text(str(it.get("excerpt") or ""))[:220],
        })
    return {"items": items, "count": len(items), "error": data.get("error") or ""}


def gather_static_payload(lang=DEFAULT_LANG, snapshot=None):
    """收集并脱敏全量监控与活动数据，生成独立静态 HTML 内容。
    对命令、内部私有 IP、家目录路径、Tmux 终端屏幕输出进行全方位隐私保护脱敏。
    """
    snapshot = snapshot or _collect_static_snapshot(lang)
    now = snapshot["now"]
    clean_services = (snapshot["clean_services"] or {}).get(lang, [])
    sysdata = snapshot["sysdata"]
    chart_data = snapshot["chart_data"]
    goals_data = snapshot["goals_data"]
    repos_data = snapshot["repos_data"]
    clean_tmux = (snapshot["clean_tmux"] or {}).get(lang, {})
    clean_runtimes = (snapshot["clean_runtimes"] or {}).get(lang, {})
    clean_tl = (snapshot["clean_tl"] or {}).get(lang, {})
    tasks_data = deep_sanitize({"tasks": tasks.scan_tasks(lang)}, mask_ips=True, mask_paths=True)

    # 生成预渲染骨架与完整 DOM (传空 entries 触发 lite 模式，避免服务端把内部数据硬编码到 HTML)
    body = _render_shell_core("127.0.0.1", [], now, lang, sysdata)
    # 不让静态站点把服务表留成空骨架。这里使用已经脱敏的快照生成首屏
    # HTML；前端仍会用同一份 BOOT 数据增量刷新，但即使 JS 被拦截/延迟，
    # 访客也能看到可用内容。
    body = re.sub(
        r'(<table id="svc">.*?<tbody>).*?(</tbody>)',
        lambda m: m.group(1) + _svc_rows(clean_services, lang, "127.0.0.1", readonly=True) + m.group(2),
        body,
        count=1,
        flags=re.DOTALL,
    )
    body = sanitize_text(body, mask_ips=True, mask_paths=True)

    # 路径相对化以支持无论是域名根路径还是 /repo-name/ 子路径访问
    body = body.replace('href="/static/', 'href="./static/')
    body = body.replace('src="/static/', 'src="./static/')

    # 标记只读 class
    body = body.replace('<html lang="', '<html class="is-readonly" lang="', 1)
    if '<body class="' in body:
        body = body.replace('<body class="', '<body class="is-readonly ', 1)
    else:
        body = body.replace('<body', '<body class="is-readonly"', 1)

    # 公开仓库活动是用户明确要查看的公开信号：保留提交评论、文件路径和
    # 仓库轨迹；Goal/Agent/Tmux/任务等仍走严格内容脱敏。
    public_goals = sanitize_public_payload(goals_data, lang)
    public_goals["events"] = [
        deep_sanitize(event, mask_ips=True, mask_paths=True)
        if event.get("kind") == "commit"
        else sanitize_public_payload(event, lang)
        for event in goals_data.get("events", [])
    ]

    boot = {
        "static": True,
        "readonly": True,
        "auto": 0,
        "lang": lang,
        "tsMode": False,
        "t": L10N.get(lang, L10N.get(DEFAULT_LANG, {})),
        "icons": ICONS,
        "iconFiles": icon_files(),
        "redactRe": redact_marker_re(lang),
        "tl": clean_tl,
        "apiData": {"updated": now, "services": clean_services},
        "sysData": sysdata,
        "chartData": chart_data,
        "goalsData": public_goals,
        "reposData": deep_sanitize(repos_data, mask_ips=True, mask_paths=True),
        "tasksData": sanitize_public_payload(tasks_data, lang),
        # 任务标题/摘要按字段单独脱敏：只清洗密钥、家目录、内网 IP，
        # 不套用通用 red("content")——那会把标题整条替换成"[内容已脱敏]"，
        # 列表就没法看了。正文/分支/日志在采集阶段就没有进入快照。
        "thTasks": _public_tasks_payload(lang),
        "tmuxData": sanitize_public_payload(clean_tmux, lang),
        # clean_runtimes 已由 sanitize_runtimes_for_public 处理；不要再次套用
        # 通用内容规则，否则 quota.bucket.label 会被误判为私密文本。
        "runtimesData": clean_runtimes,
        "agentDetails": (snapshot.get("clean_agent_details") or {}).get(lang, {}),
        "magpieUsage": (snapshot.get("clean_magpie_usage") or {}).get(lang, {}),
        "magpieRouting": (snapshot.get("clean_magpie_routing") or {}).get(lang, {}),
        "magpieProviders": (snapshot.get("clean_magpie_providers") or {}).get(lang, {}),
        "vmsData": (snapshot.get("clean_vms") or {}).get(lang, {}),
        "vmsDetail": (snapshot.get("clean_vms_detail") or {}).get(lang, {}),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }

    boot_json = json.dumps(boot, ensure_ascii=False)
    # 对完整 JSON 串进行最后的凭据检测与强制消除
    secrets_in_json = scan_for_secrets(boot_json)
    if secrets_in_json:
        print(f"[!] 警告：在导出数据中检测到敏感模式，已自动消除: {secrets_in_json}")
        boot_json = mask_secret(boot_json)

    html = body.replace("{{BOOT_JSON}}", boot_json, 1)

    # 最终全篇安全审计与脱敏
    html = sanitize_text(html, mask_ips=True, mask_paths=True)
    secrets_in_html = scan_for_secrets(html)
    if secrets_in_html:
        html = mask_secret(html)

    return html


def export_static(output_dir, lang=DEFAULT_LANG, cname=None):
    """将只读看板导出到指定目录。"""
    os.makedirs(output_dir, exist_ok=True)
    out_static = os.path.join(output_dir, "static")
    os.makedirs(out_static, exist_ok=True)

    # 复制静态资源 (app.css, app.js, icons/)
    # 需求 #138：app.js/app.css 是原样拷到公开站的，而 app.js 里可能硬编码
    # 内网 IP / Tailscale IP / 真实邮箱。只清洗 HTML 是不够的，这里对拷过去的
    # 文本资源也做一次脱敏，避免源码里的私有信息随 GitHub Pages 发布。
    for fn in ("app.css", "app.js"):
        src = os.path.join(STATIC_DIR, fn)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(out_static, fn)
        shutil.copy2(src, dst)
        try:
            text = open(dst, "r", encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        masked = sanitize_text(mask_secret(text), mask_ips=True, mask_paths=True)
        if masked != text:
            with open(dst, "w", encoding="utf-8") as fp:
                fp.write(masked)
    icons_src = os.path.join(STATIC_DIR, "icons")
    if os.path.isdir(icons_src):
        shutil.copytree(icons_src, os.path.join(out_static, "icons"), dirs_exist_ok=True)

    # 各语言页面共用同一份采集快照，避免语言版本之间数据不一致或重复采样。
    snapshot = _collect_static_snapshot(DEFAULT_LANG)
    # GitHub Pages/CDN 会长时间缓存静态资源；固定版本号会让旧 JS 继续运行，
    # 即使 index.html 已经更新。用本次实际资源内容生成 cache-busting 版本。
    asset_bytes = b"".join(
        open(os.path.join(out_static, fn), "rb").read()
        for fn in ("app.css", "app.js")
        if os.path.isfile(os.path.join(out_static, fn))
    )
    asset_version = hashlib.sha256(asset_bytes).hexdigest()[:12]
    for page_lang in LANG_KEYS:
        html = gather_static_payload(lang=page_lang, snapshot=snapshot)
        html = re.sub(r'(app\.css\?v=)[^"\']+', r'\g<1>' + asset_version, html)
        html = re.sub(r'(app\.js\?v=)[^"\']+', r'\g<1>' + asset_version, html)
        filename = "index.html" if page_lang == DEFAULT_LANG else f"index-{page_lang}.html"
        with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as f:
            f.write(html)

    # 创建 .nojekyll 防止 GitHub Pages 忽略特定文件夹
    with open(os.path.join(output_dir, ".nojekyll"), "w", encoding="utf-8") as f:
        f.write("")

    # 写入自定义域名 CNAME
    if cname:
        with open(os.path.join(output_dir, "CNAME"), "w", encoding="utf-8") as f:
            f.write(cname.strip() + "\n")

    return True


def deploy_gh_pages(cname=None, lang=DEFAULT_LANG):
    """将脱敏静态看板发布到 GitHub Pages (gh-pages 分支)。"""
    # 检查 git remote
    try:
        remote_url = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        print("[!] 无法获取 git 远程 origin 地址，请确认在 git 仓库内。")
        return 1

    print(f"[*] 正在收集监控快照并构建静态站点 (脱敏 + 只读)...")
    with tempfile.TemporaryDirectory(prefix="svc_gh_pages_") as tmpdir:
        export_static(tmpdir, lang=lang, cname=cname)

        # 发布前安全门禁审计
        exported_html_path = os.path.join(tmpdir, "index.html")
        with open(exported_html_path, "r", encoding="utf-8") as fp:
            findings = scan_for_secrets(fp.read())
        if findings:
            print(f"\033[31m[X] 安全门禁拦截：在生成的静态站点中发现疑似凭证，已阻止推送到公网！\033[0m")
            for name, snip in findings:
                print(f"  • {name}: {snip}")
            return 1
        print("[\033[32m✓\033[0m] 静态站点安全审计通过：未包含任何明文 API 密钥或内网 IP。")

        print(f"[*] 准备提交至远程 gh-pages 分支...")
        env = dict(os.environ)
        cmds = [
            ["git", "init"],
            ["git", "checkout", "-b", "gh-pages"],
            ["git", "config", "user.name", "iamcheyan"],
            ["git", "config", "user.email", "iamcheyan@users.noreply.github.com"],
            ["git", "add", "."],
            ["git", "commit", "-m", f"Deploy static snapshot at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} [skip ci]"],
            ["git", "remote", "add", "origin", remote_url],
            ["git", "push", "-f", "origin", "gh-pages"]
        ]

        for cmd in cmds:
            res = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True, env=env)
            if res.returncode != 0 and "push" in cmd:
                print(f"[!] Git push 失败:\n{res.stderr}")
                return 1

        print("[✓] 成功推送到 origin/gh-pages 分支！")

    # 检查并配置 GitHub Pages 设置 (通过 gh CLI)
    try:
        repo_slug = "iamcheyan/svc-dashboard"
        m = re.search(r"[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$", remote_url)
        if m:
            repo_slug = m.group(1)

        print(f"[*] 正在检查并配置 GitHub Pages ({repo_slug})...")
        p_check = subprocess.run(["gh", "api", f"repos/{repo_slug}/pages"],
                                 capture_output=True, text=True)
        if p_check.returncode != 0:
            print("[*] 正在为仓库启用 GitHub Pages (分支: gh-pages, 路径: /)...")
            p_init = subprocess.run(
                ["gh", "api", "-X", "POST", f"repos/{repo_slug}/pages",
                 "-f", "source[branch]=gh-pages", "-f", "source[path]=/"],
                capture_output=True, text=True
            )
            if p_init.returncode == 0:
                print("[✓] GitHub Pages 服务已成功开启！")
            else:
                print(f"[!] GitHub Pages 启用响应: {p_init.stderr.strip() or p_init.stdout.strip()}")
        else:
            print("[✓] GitHub Pages 处于启用状态。")

        if cname:
            print(f"[*] 正在配置自定义域名: {cname}...")
            p_cname = subprocess.run(
                ["gh", "api", "-X", "PUT", f"repos/{repo_slug}/pages",
                 "-f", f"cname={cname.strip()}"],
                capture_output=True, text=True
            )
            if p_cname.returncode == 0:
                print(f"[✓] 自定义域名 {cname} 已成功绑定至 GitHub Pages！")
            else:
                print(f"[!] CNAME 配置返回: {p_cname.stderr.strip() or p_cname.stdout.strip()}")
    except Exception as e:
        print(f"[!] 自动化配置 Pages 遇到小提示: {e}")

    default_url = f"https://{cname}" if cname else f"https://iamcheyan.github.io/svc-dashboard/"
    print(f"\n==========================================")
    print(f" 部署完成！访问地址: {default_url}")
    print(f"==========================================")
    return 0
