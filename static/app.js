const BOOT = window.__BOOT__ || {};
if (BOOT.readonly) {
  document.documentElement.classList.add("is-readonly");
  if (document.body) document.body.classList.add("is-readonly");
  else document.addEventListener("DOMContentLoaded", () => document.body.classList.add("is-readonly"));
}
const AUTO = BOOT.auto;
const LANG = BOOT.lang;
const LOCALE_TAG = { zh: "zh-CN", en: "en-US", ja: "ja-JP" }[LANG] || undefined;
const TS_MODE = BOOT.tsMode;
const TS_HOST = "100.76.219.104";
const LAN_HOST = "127.0.0.1";
const linkHost = (h) => (TS_MODE && (h === "127.0.0.1")) ? TS_HOST : h;  // 来源为 tailscale(100.64.0.0/10) 时链接主机改用 tailscale IP
const getMagpieUrl = () => {
  const isTs = (window.__BOOT__ && window.__BOOT__.tsMode) ||
               (typeof TS_MODE !== "undefined" && TS_MODE) ||
               location.hostname.endsWith(".ts.net") ||
               (typeof TS_HOST !== "undefined" && location.hostname === TS_HOST) ||
               location.hostname.startsWith("100.");
  if (isTs) {
    return "https://debian.tailb4776a.ts.net:8443/";
  }
  if (location.hostname === "127.0.0.1" || location.hostname === "localhost") {
    return "http://127.0.0.1:3426/";
  }
  return "https://debian.tailb4776a.ts.net:8443/";
};
const T = BOOT.t;
const t = (k, p) => { let s = T[k] ?? k; if (p !== undefined) { for (const [a, b] of Object.entries(p)) s = s.split("{" + a + "}").join(b); } return s; };
const DASH_LANGS = ["zh", "en", "ja"];
const baseLang = value => String(value || "").toLowerCase().split("-")[0];
function systemLang() {
  const candidate = baseLang((navigator.languages && navigator.languages[0]) || navigator.language);
  return DASH_LANGS.includes(candidate) ? candidate : "zh";
}
function langDirectory(url) {
  return url.pathname.endsWith("/") ? url.pathname : url.pathname.slice(0, url.pathname.lastIndexOf("/") + 1);
}
function chooseDashboardLanguage(choice) {
  const url = new URL(location.href);
  try { localStorage.setItem("svc-lang", choice); } catch (e) {}
  if (BOOT.static) {
    const selected = choice === "auto" ? systemLang() : choice;
    url.pathname = langDirectory(url) + (selected === "zh" ? "index.html" : `index-${selected}.html`);
    url.searchParams.delete("lang");
    if (choice !== "auto") url.searchParams.set("lang", selected);
  } else if (choice === "auto") {
    url.searchParams.delete("lang");
  } else {
    url.searchParams.set("lang", choice);
  }
  location.assign(url.toString());
}
function initLanguageMenu() {
  const wrap = $("lang-switch"), trigger = $("lang-trigger"), menu = $("lang-menu");
  if (!wrap || !trigger || !menu) return;
  let preference = "auto";
  try {
    const queryLang = baseLang(new URLSearchParams(location.search).get("lang"));
    const stored = localStorage.getItem("svc-lang");
    if (DASH_LANGS.includes(queryLang)) preference = queryLang;
    else if (DASH_LANGS.includes(stored)) preference = stored;
    else if (stored === "auto") preference = "auto";
  } catch (e) {}
  const display = preference === "auto" ? "AUTO" : preference.toUpperCase();
  const current = $("lang-current");
  if (current) current.textContent = display;
  wrap.querySelectorAll("[data-lang-choice]").forEach(option => {
    option.setAttribute("aria-checked", String(option.dataset.langChoice === preference));
  });
  const setOpen = open => {
    menu.hidden = !open;
    trigger.setAttribute("aria-expanded", String(open));
  };
  trigger.addEventListener("click", () => setOpen(menu.hidden));
  menu.addEventListener("click", e => {
    const option = e.target.closest("[data-lang-choice]");
    if (!option) return;
    chooseDashboardLanguage(option.dataset.langChoice);
  });
  document.addEventListener("click", e => { if (!wrap.contains(e.target)) setOpen(false); });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && !menu.hidden) { setOpen(false); trigger.focus(); }
  });
}
// --- POST 令牌: 管理动作需 X-Svc-Token(服务器 /etc/svc-dashboard/token 内容)。
// 页面不内嵌 token(匿名访客拿不到); 首次动作弹输入框, 存 sessionStorage(标签页会话级)。 ---
let svcTok = (typeof BOOT !== "undefined" && BOOT.token) || sessionStorage.getItem("svcTok") || "";
async function apiPost(url, body) {
  const withLang = (u) => u + (u.includes("?") ? "&" : "?") + "lang=" + encodeURIComponent(LANG);
  const send = () => fetch(withLang(url), { method: "POST",
    headers: { "Content-Type": "application/json", "X-Svc-Token": svcTok },
    body: JSON.stringify(body), cache: "no-store" });
  let r = await send();
  if (r.status === 403) {
    const d = await r.clone().json().catch(() => ({}));
    if (d.needToken) {                       // 令牌缺失/失效 → 问一次, 重试一次
      const tok = (window.prompt(t("tok_prompt")) || "").trim();
      if (!tok) return r;
      svcTok = tok; sessionStorage.setItem("svcTok", tok);
      r = await send();
    }
  }
  return r;
}
// --- 内联 SVG 图标(与 Python 端 ICONS 同一份 path 表, stroke=currentColor) ---
const ICONS = BOOT.icons;
function icon(name, size = 16, cls = "ic") {
  const p = ICONS[name] || ICONS.dot;
  return `<svg class="${cls}" width="${size}" height="${size}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${p}</svg>`;
}
// 空状态(iOS 风): 灰色大图标 + 粗体主标题 + 灰色副标题
function esHtml(ico, title) {
  return `<div class="empty-state"><span class="es-ico">${icon(ico, 44)}</span>` +
         `<span class="es-title">${escHtml(title)}</span>` +
         `<span class="es-sub">${t("es_sub")}</span></div>`;
}
let autoOn = true;           // 自动刷新总开关(旧版遗留: false 且无处置 true, 整条轮询链路死代码;
                              // 首页资源磁贴需要活数据 → 默认开。桌面 10s/移动 30s/后台停/长按锁定停)
let autoLocked = false;      // 长按锁定: true = 30s 自动刷新完全停止
// TaskHub 状态容器：必须早于任何 setCat()/init 逻辑声明，否则 TDZ 报错。
const TH = { tab: "events", mode: "open", q: "", issues: null, runs: null,
             hosts: null, health: null, logId: null, timer: null, sheet: null };
let filter = "user"; // 默认只显示用户服务, 隐藏系统服务
let services = [];
const $ = (id) => document.getElementById(id);

const FILTERS = {
  user:   (e) => e.scope !== "system",
  web:    (e) => e.scope !== "system" && !e.paused && !((e.ip || "").startsWith("127.") || e.ip === "::1" || (e.ip || "").startsWith("::ffff:127.")) && ![22000, 5355].includes(+e.port),
  docker: (e) => e.scope === "docker",
  system: (e) => e.scope === "system",
  omp:     () => false, // OMP 走独立面板,不混进服务表
  watchdog: () => false, // 看门狗走独立面板
  tmux:    () => false, // tmux 走独立面板
  tailscale: () => false, // tailscale 走独立面板
  manage:  () => false, // 服务管理走独立面板
  all:    () => true,
};

function row(e, mobile) {
  const badge = {docker:[t("badge_docker"),"badge-docker"], systemd:["systemd","badge-systemd"], direct:[t("badge_direct"),"badge-direct"]}[e.type] || [t("badge_direct"),"badge-direct"];
  let text = badge[0], detail = "";
  const svPaused = e.paused || e.svcctl_paused;
  if (e.is_self) { text = t("badge_self"); badge[1] = "badge-self"; }
  else if (svPaused) { text = t("badge_paused"); badge[1] = "badge-paused"; }
  else if (e.docker_proxy) { text = t("badge_proxy"); }
  else if (e.type === "docker" && e.container_id) detail = `<span class='detail' title='${t("detail_cid")}'>${escHtml(e.container_id)}</span>`;
  else if (e.type === "systemd" && e.unit) detail = `<span class='detail' title='${t("detail_unit")}'>${escHtml(e.unit)}</span>`;
  const ip = e.ip;
  const loopback = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
  const link = (e.port === 3426) ? getMagpieUrl() : (loopback ? `http://127.0.0.1:${e.port}/` : `http://${linkHost(location.hostname)}:${e.port}/`);
  const loop = loopback ? ' <span class="local">' + t("loopback") + '</span>' : "";
  const cmd = e.cmdline || "—", cwd = e.cwd || "—";
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const man = MANAGE_PROC_BY_PORT[e.port];
  const svcUnit = man || (e.type === "systemd" && MANAGE_SVC_BY_UNIT[e.unit]) || null;
  const svcDot = `<span class="svc-dot ${svPaused ? "bad" : svcUnit ? "off" : "on"}"${svcUnit ? ` data-unit="${esc(svcUnit)}"` : ""}></span>`;
  const ctl = man
    ? `<span class='ctl-btn' data-ctl='${man}' data-port='${e.port}' role='button' tabindex='0' aria-disabled='true'>${t("ctl_checking")}</span>`
    : "";
  const svctl = svBtn(e);
  const svBtnNamed = svctl ? svctl.replace("data-svcp=", `data-svcn='${esc(e.name.replace(/ \(docker\)| \(paused\)$/g, ""))}' data-svcp=`) : "";
  const res = fmtRes(e);
  const rres = e.res ? { cpu: Math.round(e.res.cpu), mem_mb: Math.round(e.res.mem_mb),
                         up_sec: Math.floor(e.res.up_sec / 60) * 60 } : null;
  const dpayload = { name: e.name, port: e.port, ip, cmd, cwd, pids: e.pids, res: rres, unit: e.unit || null, cid: e.container_id || null };
  const detailBtn = BOOT.readonly ? "" : `<span class='svc-detail' role='button' tabindex='0' data-detail='${encodeURIComponent(JSON.stringify(dpayload))}' title='${t("svc_detail")}'>${t("svc_detail")}</span>`;
  const actions = `${detailBtn}${ctl}${svBtnNamed}`;
  if (mobile) {
    return `<tr><td><div class='td-head'>${svcDot}<span class='svc'>${esc(e.name)}</span>` +
      `<span class='badge ${badge[1]}'>${text}</span>${detail}` +
      `<span class='svc-act' role='button' tabindex='0' data-copy='${esc(link)}' title='${t("act_copy_addr")}' aria-label='${t("act_copy_addr")}'>${icon("copy", 15)}</span>` +
      `<a class='svc-open' href='${link}' target='_blank' rel='noopener' aria-label='${t("act_open")} ${esc(e.name)}'>${icon("ext", 15)}</a></div>` +
      `<div class='svc-summary'><a class='port' href='${link}' target='_blank' rel='noopener'>:${e.port}</a>` +
      `<span class='svc-summary-res'>${res || "—"}</span><span class='svc-summary-detail'>${actions}</span></div></td></tr>`;
  }
  return `<tr>
    <td class='name'>${svcDot}<span class='svc'>${esc(e.name)}</span><span class='badge ${badge[1]}'>${text}</span>${detail}</td>
    <td class='port' data-label='${t("th_port")}'><a href='${link}' target='_blank' rel='noopener'>${e.port}</a></td>
    <td class='res' data-label='${t("th_res")}'>${res || "—"}</td>
    <td class='svc-actions' data-label='${t("g_detail")}'>${actions}</td>
  </tr>`;
}

// --- 服务表增量渲染: 轮询(桌面10s/移动30s)不再整表 innerHTML 重建 ---
// key=ip:port(一个监听一行), sig=整行 HTML: 内容没变的行 <tr> 节点原地保留,
// 悬停/按钮态/长按上下文不闪; 变化的行单独 replaceWith; 顺序按数据序插入。
const svcRows = new Map();   // key -> {html, node}
function renderSvcRows(tbody, shown, mobile) {
  if (!shown.length) {
    if (!tbody.querySelector("td.empty"))
      tbody.innerHTML = '<tr><td class="empty" colspan="6">' + t("no_match") + '</td></tr>';
    svcRows.clear();
    return;
  }
  const want = new Set();
  let prev = null;
  shown.forEach((e, i) => {
    let key = (e.ip || "?") + ":" + e.port;
    if (want.has(key)) key += "#" + i;        // ip:port 撞车兜底
    want.add(key);
    const html = row(e, mobile);
    let ent = svcRows.get(key);
    if (!ent || ent.html !== html) {
      if (tbody.querySelector("td.empty")) tbody.innerHTML = "";
      const tpl = document.createElement("template");
      tpl.innerHTML = html.trim();
      const node = tpl.content.firstElementChild;
      if (ent) ent.node.replaceWith(node);
      ent = { html, node };
      svcRows.set(key, ent);
    }
    if (ent.node.parentElement !== tbody || ent.node.previousElementSibling !== prev)
      tbody.insertBefore(ent.node, prev ? prev.nextSibling : tbody.firstChild);
    prev = ent.node;
  });
  for (const [k, ent] of svcRows)
    if (!want.has(k)) { ent.node.remove(); svcRows.delete(k); }
}
function hideAllServiceSubviews() {
  const np = $("network-page"); if (np) np.hidden = true;
  const tasks = $("tasks"); if (tasks) tasks.hidden = true;
  const sp = $("svc-panel"); if (sp) sp.style.display = "none";
  const svc = $("svc"); if (svc) svc.style.display = "none";
  const cp = $("cron-panel"); if (cp) { cp.style.display = "none"; cp.hidden = true; }
  const lp = $("logpage"); if (lp) { lp.style.display = "none"; lp.hidden = true; }
}

function applyFilter() {
  const shown = FILTERS[filter] ? services.filter(FILTERS[filter]) : [];
  ["user", "web", "docker", "system", "all"].forEach(f => {
    const el = $("n-" + f);
    if (el) el.textContent = services.filter(FILTERS[f]).length;
  });
  document.querySelectorAll("#filters .chip").forEach(c =>
    c.classList.toggle("active", c.dataset.f === filter));

  // 严格隔离：切换任何分类时，其他所有画面一律彻底隐藏
  hideAllServiceSubviews();

  if (filter === "tailscale") {
    const np = $("network-page");
    if (np) {
      np.hidden = false;
      renderNetworkPage();
    }
    $("count").textContent = "Tailscale";
    return;
  }
  if (filter === "omp") {
    const tasksEl = $("tasks");
    if (tasksEl) {
      tasksEl.hidden = false;
      tasksEl.className = "watchdog-panel";
      tasksEl.innerHTML = `<h2>${t("a_title")} <span style="color:var(--text-dead);font-weight:400">${t("a_loading")}</span></h2>`;
      loadAgents().then(renderAgentPanel);
    }
    $("count").textContent = t("chip_omp");
    return;
  }
  if (filter === "tmux") {
    const tasksEl = $("tasks");
    if (tasksEl) {
      tasksEl.hidden = false;
      tasksEl.className = "watchdog-panel";
      tasksEl.innerHTML = `<h2>${t("tmux_panel")} <span style="color:var(--text-dead);font-weight:400">${t("a_loading")}</span></h2>`;
      loadTmux().then(renderTmuxPanel);
    }
    $("count").textContent = t("chip_tmux");
    return;
  }
  if (filter === "watchdog") {
    const tasksEl = $("tasks");
    if (tasksEl) {
      tasksEl.hidden = false;
      tasksEl.className = "watchdog-panel";
      tasksEl.innerHTML = `<h2>${t("panel_watchdog")} <span style="color:var(--text-dead);font-weight:400">${t("a_loading")}</span></h2>`;
      loadTasks().then(renderWatchdogPanel);
    }
    $("count").textContent = t("chip_watchdog");
    return;
  }
  if (filter === "manage") {
    const tasksEl = $("tasks");
    if (tasksEl) {
      tasksEl.hidden = false;
      tasksEl.className = "watchdog-panel manage-panel";
      tasksEl.innerHTML = `<h2>${t("m_panel")} <span style="color:var(--text-dead);font-weight:400">${t("a_loading")}</span></h2>`;
      loadManage();
    }
    $("count").textContent = t("chip_manage");
    return;
  }

  // 常规服务端口过滤 (user, web, docker, system, all)
  const sp = $("svc-panel"); if (sp) sp.style.display = "";
  const svc = $("svc"); if (svc) svc.style.display = "";
  const cp = $("cron-panel"); if (cp) { cp.style.display = ""; cp.hidden = false; }
  const lp = $("logpage"); if (lp) { lp.style.display = ""; lp.hidden = false; }
  const tbody = $("svc")?.querySelector("tbody");
  if (tbody) renderSvcRows(tbody, shown, isMobile());
  $("count").textContent = shown.length;
  fillCtl(); // 服务表行尾 暂停/继续 按钮状态
  fillSvcDots(); // 行首状态点
  if (typeof fetchTailscaleData === "function") {
    fetchTailscaleData().then(d => {
      const el = $("n-tailscale");
      if (el && d && d.peers) el.textContent = d.peers.length ? String(d.peers.length) : "";
    });
  }
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
  const SYS_ICONS = { load: "load", cpu: "cpu", mem: "mem", disk: "disk", up: "clock" };
  const zone = (p) => (p > 90 ? " bad" : p >= 75 ? " warn" : "");   // P1-2: >90 红 / ≥75 黄
  const cards = [
    ["load", t("sys_load"), (s.loadavg || []).join(" / ") || "—", ""],
    ["cpu", "CPU", `${s.cpu_usage}% · ${s.cpu_count} ${t("unit_core")}`, zone(s.cpu_usage)],
    ["mem", t("sys_mem"), `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)} (${mem.percent || 0}%)`, zone(mem.percent || 0)],
    ["disk", t("sys_disk"), `${fmtBytes(disk.used)} / ${fmtBytes(disk.total)} (${disk.percent || 0}%)`, zone(disk.percent || 0)],
    ["up", t("sys_up"), fmtUp(s.uptime), ""],
  ];
  $("sysbar").innerHTML = cards.map(([k, l, v, cls]) =>
    `<div class='stat' data-k='${k}'><div class='label'><span class='lb-ico'>${icon(SYS_ICONS[k] || "dot", 13)}</span>${l}</div><div class='value${cls}'>${v}</div></div>`).join("");
  chartSample(s); // 趋势图采样并绘制
}

// --- 仓库面板: agent/goal 改动过的仓库(/api/repos; 客户端 60s 缓存) ---
let reposCache = { t: 0, data: null }, reposInflight = false;
async function loadRepos(force) {
  if (BOOT.static && BOOT.reposData) {
    reposCache.data = BOOT.reposData;
    reposCache.t = Date.now();
    renderRepos(reposCache.data);
    return;
  }
  const now = Date.now();
  if (!force && reposCache.data && now - reposCache.t < 60000) return;
  if (reposInflight && !force) return;          // 冷启动 /api/repos 可达 14s, 防重复并发
  const snap = snapGet("repos");
  if (snap && snap.data && !reposCache.data) {  // 首屏先用快照渲染(轨迹条/仓库卡)
    reposCache = { t: 0, data: snap.data };
    renderRepos(snap.data);
  }
  reposInflight = true;
  try {
    const r = await fetch(force ? "/api/repos?refresh=1" : "/api/repos", { cache: "no-store" });
    reposCache.data = await r.json();
    reposCache.t = Date.now();
    renderRepos(reposCache.data);
    snapSet("repos", { data: reposCache.data });
  } catch (err) {
    if (!snap) console.error("repos load failed", err);   // 有快照兜底时不刷屏
  } finally {
    reposInflight = false;
  }
}
function renderRepos(d) {
  const el = $("repos-body");
  if (el) {
    const list = (d && d.repos) || [];
    if (!list.length) { el.innerHTML = `<div class="gempty">${t("rp_empty")}</div>`; return; }
    const fmtB = (n) => {
      if (n == null) return "—";
      const u = ["B", "KB", "MB", "GB", "TB"];
      let i = 0;
      while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
      return (i ? n.toFixed(1) : n) + " " + u[i];
    };
    const stripOf = (traj) => (traj || []).map(trajCell).join("");
    el.innerHTML = list.map(r => {
      const meta = [t("rp_commits", { n: r.commits ?? "—" }), fmtB(r.size), t("rp_files", { n: r.files ?? "—" })];
      if (r.branches > 1) meta.push(t("rp_branches", { n: r.branches }));
      if (r.dirty) meta.push(`<span class="rp-dirty">${t("rp_dirty", { n: r.dirty })}</span>`);
      return `<div class="rp-row" role="button" tabindex="0" data-traj="${escAttr(r.name)}">
        <div class="rp-l1"><span class="rp-name">${escHtml(r.name)}</span><span class="rp-branch">${escHtml(r.branch)}</span>
          <span class="rp-meta">${meta.join(" · ")}</span></div>
        ${r.last ? `<div class="rp-last"><span class="rp-hash">${escHtml(r.last.hash)}</span> ${escHtml(r.last.subject)} <span class="rp-ago">· ${escHtml(agoFromTs(r.last.ts))}</span></div>` : ""}
        ${(r.traj || []).length ? `<div class="rp-traj" title="${escAttr(t("tr_days"))}">${stripOf(r.traj)}</div>` : ""}
      </div>`;
    }).join("");
  }
}
// --- Agent 操作轨迹详情页(全屏浮层): 大号14天双行条 + 图例 + 类别筛选 + 事件流 ---
const TR_KEY = { commit: "tr_commit", warn: "tr_warn", good: "tr_good", done: "tr_done",
                 agent: "tr_agent", error: "tr_error", turn: "tr_turn", say: "tr_say",
                 compact: "tr_compact", exit: "tr_exit", spawn: "tr_spawn",
                 replan: "tr_replan", model: "tr_model" };
const TR_EV_ICON = { commit: "branch", complete: "ok", recover: "up", restart: "retry",
                     nudge: "bell", pause: "pause", cleanup: "trash", other: "dot",
                     tool: "code", compact: "box", error: "err", turn: "user",
                     say: "chat", exit: "power", spawn: "spark", replan: "refresh", model: "cpu" };
// 双行逐日 cell: 上行里程碑色, 下行活动健康色; title 汇总当日全部类别计数
function trajCell(s) {
  const tip = s.n
    ? Object.entries(s.c || {}).map(([k, v]) => `${t(TR_KEY[k] || k)}×${v}`).join(" ")
    : t("tr_idle");
  return `<span class="tr-day" title="${escAttr(s.d + " · " + tip)}">`
    + `<i class="tr-top${s.cls ? " tr-" + s.cls : " tr-idle"}"></i>`
    + `<i class="tr-bot${s.bot ? " tr-" + s.bot : " tr-idle"}"></i></span>`;
}
let trajEvents = [], trajFilter = "";
function renderTrajBody() {
  const list = trajFilter ? trajEvents.filter(e => e.kind === trajFilter) : trajEvents;
  const rows = list.map(e => `<div class="traj-ev tr-ev-${e.cls || "none"}">`
    + `<span class="traj-ev-ico">${icon(TR_EV_ICON[e.kind] || "dot", 14)}</span>`
    + `<span class="traj-ev-kind">${escHtml(t("trk_" + e.kind) || e.kind)}</span>`
    + `<span class="traj-ev-text">${e.name ? `<b>${escHtml(e.name)}</b> · ` : ""}${escHtml(e.text || "")}</span>`
    + `<span class="traj-ev-time">${escHtml(e.time)}</span></div>`).join("");
  $("traj-body").innerHTML = rows || `<div class="gempty">${t("tr_empty")}</div>`;
}
function renderTrajFilter() {
  const el = $("traj-filter");
  if (!el) return;
  const counts = {};
  trajEvents.forEach(e => { counts[e.kind] = (counts[e.kind] || 0) + 1; });
  const kinds = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  el.innerHTML = kinds.map(k =>
    `<span class="trf-chip${trajFilter === k ? " on" : ""}" data-tfk="${escAttr(k)}" role="button" tabindex="0">`
    + `${icon(TR_EV_ICON[k] || "dot", 11)} ${escHtml(t("trk_" + k) || k)} <b>${counts[k]}</b></span>`).join("");
  el.hidden = !kinds.length;
}
function closeTraj() {
  $("traj-view").hidden = true;
  document.documentElement.classList.remove("traj-noscroll");
}
async function openTraj(name) {
  const v = $("traj-view");
  if (!v) return;
  $("traj-name").textContent = name;
  $("traj-sub").textContent = "";
  $("traj-strip").innerHTML = "";
  $("traj-days").innerHTML = "";
  $("traj-legend").innerHTML = "";
  $("traj-filter").innerHTML = "";
  $("traj-filter").hidden = true;
  $("traj-body").innerHTML = `<div class="gempty">${t("a_loading")}</div>`;
  v.hidden = false;
  v.classList.remove("opening"); void v.offsetWidth; v.classList.add("opening");
  document.documentElement.classList.add("traj-noscroll");
  haptic(8);
  try {
    const r = await fetch("/api/trajectory?repo=" + encodeURIComponent(name), { cache: "no-store" });
    const d = await r.json();
    if (!d.ok) { $("traj-body").innerHTML = `<div class="gempty">${escHtml(d.msg || "error")}</div>`; return; }
    $("traj-sub").textContent = d.path || "";
    $("traj-strip").innerHTML = (d.strip || []).map(trajCell).join("");
    $("traj-days").innerHTML = (d.strip || []).map((s, i) => `<b>${i % 2 ? "" : escHtml(s.d)}</b>`).join("");
    $("traj-legend").innerHTML = ["commit", "warn", "good", "done", "agent", "error"]
      .map(k => `<span><i class="tr-${k}"></i>${t("tr_" + k)}</span>`).join("");
    trajEvents = d.events || [];
    trajFilter = "";
    renderTrajFilter();
    renderTrajBody();
  } catch (e) {
    $("traj-body").innerHTML = `<div class="gempty">${escHtml(e.message)}</div>`;
  }
}
document.addEventListener("click", (ev) => {
  const chip = ev.target.closest(".trf-chip");
  if (chip) {                       // 类别筛选: 再点同 chip 取消筛选
    const k = chip.dataset.tfk;
    trajFilter = trajFilter === k ? "" : k;
    renderTrajFilter();
    renderTrajBody();
    haptic(6);
    return;
  }
  const row = ev.target.closest(".rp-row[data-traj]");
  if (row) { openTraj(row.dataset.traj); return; }
  if (ev.target.closest("#traj-back")) closeTraj();
});
// 独立 Esc: 轨迹页可从首页仓库面板打开(此时工具页未初始化, 其 Esc 链未绑定)
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("traj-view").hidden) closeTraj();
});
const rpRefreshBtn = $("rp-refresh");
if (rpRefreshBtn) rpRefreshBtn.addEventListener("click", () => {
  haptic(8);
  rpRefreshBtn.classList.add("spin");
  loadRepos(true).finally(() => rpRefreshBtn.classList.remove("spin"));
});

// 快捷工具入口 chips: 端口存活才显示,点击直达(随 /api 刷新)
const TOOL_LINKS = [["dbeditor", 8810], ["dbviewer", 8800], ["wilviewer", 8765], ["mapviewer", 8899]];
function renderToolchips() {
  const el = $("toolchips");
  if (!el) return;
  const ports = new Set(services.filter(s => !s.paused).map(s => s.port));   // 暂停服务不显示
  let chips = TOOL_LINKS.filter(([n, p]) => ports.has(p)).map(([n, p]) =>
    `<a class='chip tchip' href='http://${linkHost(location.hostname)}:${p}/' target='_blank' rel='noopener'>${n} :${p} ${icon("ext", 11)}</a>`).join("");
  if (!BOOT.static) {
    const remote = "https://debian.tailb4776a.ts.net";
    const vnc = [];
    if (ports.has(6080)) vnc.push(`<a class='chip tchip' href='${remote}/xfce/vnc.html?autoconnect=1&resize=scale' target='_blank' rel='noopener'>XFCE VNC ${icon("ext", 11)}</a>`);
    if (ports.has(6082)) vnc.push(`<a class='chip tchip' href='${remote}:8449/vnc.html?autoconnect=1&resize=scale' target='_blank' rel='noopener'>Hyprland VNC ${icon("ext", 11)}</a>`);
    if (ports.has(3426)) {
      vnc.unshift(`<a class='chip tchip magpie-chip' style='color:#c084fc;border-color:rgba(168,85,247,0.35);background:rgba(168,85,247,0.08);' href='${escAttr(getMagpieUrl())}' target='_blank' rel='noopener'>Magpie ${icon("ext", 11)}</a>`);
    }
    chips = vnc.join("") + chips;
  }
  el.innerHTML = chips;
  el.hidden = !chips;
  el.style.display = chips ? "" : "none";
}

// 显式复制按钮统一处理(.gcopy 胶囊钮 / .svc-act 圆形钮; http 非安全上下文走 execCommand 降级)
function fallbackCopy(txt, done) {
  const ta = document.createElement("textarea");
  ta.value = txt; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } catch (e) { /* 忽略 */ }
  ta.remove();
}
document.addEventListener("click", (e) => {
  const b = e.target.closest(".gcopy, .svc-act");
  if (!b) return;
  const txt = b.dataset.cmd || b.dataset.copy || "";
  const iconOnly = b.classList.contains("svc-act");  // 圆形图标钮: 反馈只换图标不塞文字
  const done = () => {
    const old = b.innerHTML; b.innerHTML = icon("ok", 12) + (iconOnly ? "" : " " + t("g_copied"));
    haptic(12);
    setTimeout(() => b.innerHTML = old, 1600);
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
  const esc = (s) => String(s || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  let lastStr = "—";
  if (x.last) {
    const ago = agoStr(Date.now() / 1000 - x.last);
    lastStr = `<span title="${new Date(x.last * 1000).toLocaleString(LOCALE_TAG)}">${ago || t("ago_just_now")}</span>`;
  }
  let triggerBtn = "";
  if (x.kind === "timer") {
    triggerBtn = `<button type="button" class="btn-ts-mini btn-task-trigger" data-name="${esc(x.name)}" data-kind="${esc(x.kind)}" data-scope="${esc(x.scope)}" title="${t("tac_trigger_title")}">▶ ${t("tac_trigger")}</button>`;
  }
  return `<tr>
    <td><span class='${cls}'>${label}</span><span class='tname'>${esc(x.name)}</span></td>
    <td class='tsch' data-label='${t("t_cycle")}'>${esc(x.schedule)}</td>
    <td class='tscope' data-label='${t("t_source")}'>${x.kind === "timer" ? "systemd" : "cron"} · ${x.scope === "user" ? t("t_scope_user") : t("t_scope_sys")}</td>
    <td class='tcmd' data-label='${t("t_cmd")}'>${esc(x.command)}</td>
    <td class='tnext' data-label='${t("t_lastrun")}'>${lastStr}</td>
    <td class='tact' data-label="${t("th_action")}">${triggerBtn}</td>
  </tr>`;
}

let ompCache = null;
async function loadAgents() {
  if (BOOT.static) return { omp: [], codex: [] };
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

  // 1. 合并 OMP 与 Codex agents
  const all = [
    ...(agents.omp || []).map(x => ({ ...x, kind: "omp", key: x.id, title: x.goal || x.cwd, tmx: x.tmux })),
    ...(agents.codex || []).map(x => ({ ...x, kind: "codex", key: x.session_id, title: x.title || x.session_id, tmx: "" }))
  ];

  // 2. 严格按活跃时间从新到旧排序 (idle_seconds 越小越新)
  all.sort((a, b) => {
    const ta = (a.idle_seconds !== undefined && a.idle_seconds !== null) ? a.idle_seconds : 99999999;
    const tb = (b.idle_seconds !== undefined && b.idle_seconds !== null) ? b.idle_seconds : 99999999;
    return ta - tb;
  });

  const rows = all.map(x => {
    const isOmp = x.kind === "omp";
    const badgeCls = isOmp ? "wd" : "rd";
    const badgeText = isOmp ? "OMP" : "Codex";
    const hCls = x.health || "idle";
    const statusPill = `<span class="st-badge ${hCls}">${labels[hCls] || esc(x.status || x.health)}</span>`;
    const loc = x.tmx ? `tmux: ${esc(x.tmx)}` : esc(x.cwd || "—");

    let wakeBtn = "";
    if (x.tmx && x.tmx !== "—") {
      const sname = x.tmx.split(":")[0];
      wakeBtn = `
        <button type="button" class="btn-ts-mini btn-tmux-wake" data-sname="${esc(sname)}" data-target="${esc(x.tmx)}" title="${t("tac_wake_title")}">
          ${icon("bolt", 11)} <span>${t("tac_wake")}</span>
        </button>
      `;
    }

    const ago = (x.idle_seconds !== undefined && x.idle_seconds !== null) ? agoStr(x.idle_seconds) : "—";
    const fullDate = x.last_activity ? x.last_activity.replace("T", " ") : "";

    return `
      <tr>
        <td>
          <span class="tbadge ${badgeCls}">${badgeText}</span>
          <span class="tname tlink" data-sid="${esc(x.key)}" data-cwd="${esc(x.cwd)}" data-tmux="${esc(x.tmx || "")}" title="${t("a_openlog", { g: esc(x.title) })}">
            ${esc(stripMd(x.title || "").slice(0, 60))}
          </span>
        </td>
        <td data-label="${t("a_status")}">${statusPill}</td>
        <td class="tscope" data-label="${t("a_loc")}">${loc}</td>
        <td class="tsch" data-label="${t("a_active")}">
          <strong>${ago}</strong><br><span class="ghint">${esc(fullDate)}</span>
        </td>
        <td class="tcmd" data-label="${t("a_tool")}">
          <div style="display:flex;align-items:center;gap:6px;">
            ${wakeBtn}
            <span>${esc(x.tool || x.last_event || (x.pid !== "—" ? "pid " + x.pid : "—"))}</span>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  const total = all.length;
  el.innerHTML = `
    <h2>${t("a_title")} <span style="color:var(--text-dead);font-weight:400">${t("a_hint", { n: total })} · ${t("latest_active_first")}</span></h2>
    <table><thead><tr><th>${t("a_th_agent")}</th><th>${t("a_status")}</th><th>${t("a_loc")}</th><th>${t("a_active")}</th><th>${t("a_tool")}</th></tr></thead>
    <tbody>${rows || "<tr><td class='empty' colspan='5'>" + t("a_none") + "</td></tr>"}</tbody></table>
  `;

  el.querySelectorAll(".tlink").forEach(a => a.addEventListener("click", () => toggleAgentLog(a)));
}

async function fetchAgentLog(sid, cwd, tmx) {
  const r = await fetch("/api/agentlog?sid=" + encodeURIComponent(sid) + "&cwd=" + encodeURIComponent(cwd) + "&tmux=" + encodeURIComponent(tmx) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
  return r.json();
}
// --- tmux capture-pane -e 的 ANSI(SGR) → HTML: 真彩/256色/16色 + 粗/暗, 其余 CSI/OSC 丢弃 ---
const ANSI_16 = ["#4c566a","#bf616a","#a3be8c","#ebcb8b","#81a1c1","#b48ead","#88c0d0","#e5e9f0",
                 "#616e88","#d08770","#97b67c","#f0d390","#8ca9c9","#c8a2c8","#9fc6d8","#ffffff"];
function _xterm256(n) {
  if (n < 16) return ANSI_16[n];
  if (n < 232) { const s = [0, 95, 135, 175, 215, 255], c = n - 16;
    return "rgb(" + s[(c / 36) | 0] + "," + s[((c % 36) / 6) | 0] + "," + s[c % 6] + ")"; }
  const v = 8 + (n - 232) * 10; return "rgb(" + v + "," + v + "," + v + ")";
}
function ansiToHtml(s) {
  // 逐行处理(tmux capture 每行 SGR 自含): 收集 {text, st} 段 → 行尾裁掉"无背景色"的尾随空格
  // (TUI 把空格涂满 pane 宽度, 是假宽度) → 同风格相邻段合并为一个 span。
  const re = /\x1b(?:\[[0-9;:<=>?]*[A-Za-z]|\][^\x07]*\x07|\][^\x1b]*\x1b\\)/g;
  const sgr = (seq, st) => {
    const parts = seq.slice(2, -1).split(/[;:]/);
    for (let i = 0; i < parts.length; i++) {
      const c = parseInt(parts[i] || "0", 10) || 0;
      if (c === 0) { st.fg = st.bg = ""; st.bold = st.dim = false; }
      else if (c === 1) st.bold = true;
      else if (c === 2) st.dim = true;
      else if (c === 22) { st.bold = st.dim = false; }
      else if (c >= 30 && c <= 37) st.fg = ANSI_16[c - 30];
      else if (c >= 90 && c <= 97) st.fg = ANSI_16[c - 82];
      else if (c === 39) st.fg = "";
      else if (c >= 40 && c <= 47) st.bg = ANSI_16[c - 40];
      else if (c >= 100 && c <= 107) st.bg = ANSI_16[c - 92];
      else if (c === 49) st.bg = "";
      else if (c === 38 || c === 48) {
        let col = "";
        if (+parts[i + 1] === 2) { col = "rgb(" + (+parts[i + 2] || 0) + "," + (+parts[i + 3] || 0) + "," + (+parts[i + 4] || 0) + ")"; i += 4; }
        else if (+parts[i + 1] === 5) { col = _xterm256(+parts[i + 2] || 0); i += 2; }
        if (c === 38) st.fg = col; else st.bg = col;
      }
    }
  };
  const st2css = (st) => [st.fg && "color:" + st.fg, st.bg && "background:" + st.bg,
                           st.bold && "font-weight:600", st.dim && "opacity:.62"].filter(Boolean).join(";");
  let out = "";
  let open = null;   // 显式声明: 原隐式全局与 window.open 相撞, 首段多 </span> 且跨行着色丢失
  for (const line of String(s).split("\n")) {
    const segs = [];
    const st = { fg: "", bg: "", bold: false, dim: false };
    let last = 0, m;
    re.lastIndex = 0;
    while ((m = re.exec(line))) {
      if (m.index > last) segs.push({ text: line.slice(last, m.index), st: { ...st } });
      if (m[0].charCodeAt(1) === 91 && m[0].endsWith("m")) sgr(m[0], st);
      last = m.index + m[0].length;
    }
    if (last < line.length) segs.push({ text: line.slice(last), st: { ...st } });
    // 行尾裁剪: 尾随空格段直接丢弃(即使带背景——TUI 涂满 pane 宽的死宽度, 是假滚动条元凶),
    // 最末非空白段去掉尾随空格
    for (let i = segs.length - 1; i >= 0; i--) {
      if (/^ *$/.test(segs[i].text)) { segs.splice(i, 1); continue; }
      segs[i].text = segs[i].text.replace(/ +$/, "");
      break;
    }
    for (const sg of segs) {
      if (!sg.text) continue;
      const css = st2css(sg.st);
      if (css !== open) { if (open) out += "</span>"; if (css) out += '<span style="' + css + '">'; open = css || null; }
      out += escHtml(sg.text);
    }
    if (open) { out += "</span>"; open = null; }
    out += "\n";
  }
  return out.replace(/\n$/, "");
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
      ansiToHtml(d.capture.join("\n")) + "</pre>";
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
  if (BOOT.static && BOOT.tmuxData) {
    const panes = BOOT.tmuxData.panes || [];
    tmuxCache = panes;
    return panes;
  }
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

  // 从新到旧排序 (按 activity timestamp 倒序)
  const sorted = [...panes].sort((a, b) => {
    if (a.active !== b.active) return a.active ? -1 : 1;
    return (b.activity || 0) - (a.activity || 0);
  });

  const rows = sorted.map(x => {
    const ago = (x.idle_seconds !== undefined && x.idle_seconds !== null) ? agoStr(x.idle_seconds) : "—";
    return `
      <tr>
        <td class="tname">
          ${esc(x.session)}:${esc(x.pane)}
          ${x.active ? " <span class='tbadge wd'>" + t("tmux_active") + "</span>" : ""}
        </td>
        <td data-label="${t("t_cmd")}"><code>${esc(x.command)}</code> ${x.pid !== "—" ? `<span class="ghint">(${x.pid})</span>` : ""}</td>
        <td class="tscope" data-label="${t("tmux_th_title")}">${esc(x.title)}</td>
        <td class="tcmd" data-label="${t("th_cwd")}">${esc(x.cwd)}</td>
        <td class="tsch" data-label="${t("th_active_time")}">${ago}</td>
        <td data-label="${t("th_action")}">
          <div style="display:flex;align-items:center;gap:6px;">
            <button type="button" class="btn-ts-mini btn-tmux-wake" data-sname="${esc(x.session)}" data-target="${esc(x.session + ':' + x.pane)}" title="${t("tac_wake_title")}">
              ${icon("bolt", 11)} <span>${t("tac_wake")}</span>
            </button>
            <button type="button" class="btn-ts-mini btn-tmux-preview" data-target="${esc(x.session + ':' + x.pane)}" title="${t("tac_preview_title")}">
              ${icon("play", 11)} <span>${t("tac_preview")}</span>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  el.innerHTML = `
    <h2>${t("tmux_panel")} <span style="color:var(--text-dead);font-weight:400">${t("tmux_panes", { n: sorted.length })} · ${t("latest_active_priority")}</span></h2>
    <table><thead><tr><th>${t("tmux_th_pane")}</th><th>${t("t_cmd")}</th><th>${t("tmux_th_title")}</th><th>${t("th_cwd")}</th><th>${t("th_active_time")}</th><th>${t("th_action")}</th></tr></thead>
    <tbody>${rows || "<tr><td class='empty' colspan='6'>" + t("tmux_none") + "</td></tr>"}</tbody></table>
  `;
}

let tasksCache = null; // 懒加载缓存

async function loadTasks() {
  if (BOOT.static && BOOT.tasksData) {
    tasksCache = BOOT.tasksData.tasks || [];
    return tasksCache;
  }
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

  // 严格按最后执行时间从新到旧排序
  const sorted = [...tasks].sort((a, b) => {
    const la = a.last || 0, lb = b.last || 0;
    if (la !== lb) return lb - la;
    const na = a.next || 0, nb = b.next || 0;
    return na - nb;
  });

  const nwd = sorted.filter(t => t.type === "watchdog").length;
  const nrd = sorted.filter(t => t.type === "reminder").length;
  const nsc = sorted.length - nwd - nrd;
  el.innerHTML = `<h2>${t("panel_watchdog")}
    <span style='color:var(--ch-mem)'>${nwd} ${t("tbd_wd")}</span> ·
    <span style='color:var(--ch-cpu)'>${nrd} ${t("tbd_rd")}</span> ·
    <span style='color:var(--text-dim)'>${nsc} ${t("tbd_sc")}</span> ·
    <span style='color:var(--text-dead);font-weight:400'>${t("t_total", { n: sorted.length })} · ${t("recent_exec_first")}</span></h2>
    <table><thead><tr><th>${t("t_task")}</th><th>${t("t_cycle")}</th><th>${t("t_source")}</th><th>${t("t_cmd")}</th><th>${t("t_lastrun")}</th><th>${t("th_action")}</th></tr></thead>
    <tbody>${sorted.length ? sorted.map(taskRow).join("") : "<tr><td class='empty' colspan='6'>" + t("t_none") + "</td></tr>"}</tbody></table>`;
}

// ---------------------------------------------------------------- 服务管理
// 管理本机关键 systemd 单元(zircon-server / zircon-bots / tailscaled)与
// 手动进程服务(wilviewer / mapviewer): 启动 / 停止 / 重启 / 暂停 / 恢复。
const MANAGE_UNITS = [
  { id: "zircon-server", kind: "systemd", label: t("m_server"), desc: t("m_server_desc") },
  { id: "zircon-bots", kind: "systemd", label: t("m_bots"), desc: t("m_bots_desc") },
  { id: "wsgateway", kind: "systemd", label: t("mgr_zircon_ws"), desc: t("mgr_zircon_ws_desc") },
  { id: "tailscaled", kind: "systemd", label: t("m_ts"), desc: t("m_ts_desc") },
  { id: "wilviewer", kind: "proc", port: 8765, label: t("m_wilviewer"), desc: t("m_wilviewer_desc") },
  { id: "mapviewer", kind: "proc", port: 8899, label: t("m_mapviewer"), desc: t("m_mapviewer_desc") },
];
const MANAGE_LABELS = { start: t("m_start"), stop: t("m_stop"), restart: t("m_restart"), pause: t("m_pause"), resume: t("m_resume") };

async function loadManage() {
  const el = $("tasks");
  if (filter !== "manage") { el.hidden = true; return; }
  el.hidden = false;
  el.className = "watchdog-panel manage-panel";
  el.innerHTML = `<h2>${t("m_panel")} <span style="color:var(--text-dead);font-weight:400">${t("a_loading")}</span></h2>`;

  const [unitStatuses, ctlData] = await Promise.all([
    Promise.all(MANAGE_UNITS.map(async (u) => {
      try {
        const r = await fetch("/api/manage?unit=" + encodeURIComponent(u.id) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
        return { ...u, st: await r.json() };
      } catch (e) {
        return { ...u, st: null };
      }
    })),
    fetch("/api/svcctl", { cache: "no-store" }).then(r => r.json()).catch(() => ({ paused: [], history: [] }))
  ]);

  if (filter !== "manage") return;
  renderManagePanel(unitStatuses, ctlData);
}

function renderManagePanel(unitStatuses, ctlData) {
  const el = $("tasks");
  if (filter !== "manage") { el.hidden = true; return; }
  el.hidden = false;

  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

  // 1. 核心受管服务卡片
  const cardsHtml = unitStatuses.map(u => {
    const st = u.st || {};
    const isRunning = st.ok && st.active === "active";
    const isPaused = st.stopped;
    const dotCls = isRunning ? "on" : (isPaused ? "bad" : "off");
    const statusTxt = isRunning ? (t("ts_status_running") + (st.pid ? ` · PID ${st.pid}` : "")) : (isPaused ? t("m_paused") : (st.active || t("ts_status_stopped")));

    let btns = "";
    if (isRunning) {
      btns = `
        <button type="button" class="btn-ts-mini ctl-btn" data-ctl="${esc(u.id)}" data-action="restart">${icon("retry", 11)} ${t("m_restart")}</button>
        <button type="button" class="btn-ts-mini ctl-btn" data-ctl="${esc(u.id)}" data-action="pause">${icon("pause", 11)} ${t("m_pause")}</button>
        <button type="button" class="btn-ts-mini ctl-btn danger" data-ctl="${esc(u.id)}" data-action="stop">${t("m_stop")}</button>
      `;
    } else {
      btns = `
        <button type="button" class="btn-ts-mini ctl-btn primary" data-ctl="${esc(u.id)}" data-action="start">${icon("play", 11)} ${t("m_start")}</button>
      `;
    }

    return `
      <div class="manage-card">
        <div class="manage-card-top">
          <div class="manage-card-title">
            <span class="svc-dot ${dotCls}"></span>
            <strong>${esc(u.label)}</strong>
            <span class="ts-os-badge">${esc(u.kind)}</span>
          </div>
          <span class="ghint">${esc(u.port ? ":" + u.port : "")}</span>
        </div>
        <div class="manage-card-desc">${esc(u.desc)}</div>
        <div class="manage-card-foot">
          <span class="manage-card-status">${statusTxt}</span>
          <div class="manage-card-btns">${btns}</div>
        </div>
      </div>
    `;
  }).join("");

  // 2. 通用服务冻结台账 (Svcctl 暂停清单) - 从新到旧排序
  const pausedList = [...(ctlData.paused || [])].sort((a, b) => (b.ts || 0) - (a.ts || 0));
  let pausedHtml = "";
  if (!pausedList.length) {
    pausedHtml = `<div class="gempty" style="padding:16px 0;">${t("sc_empty")}</div>`;
  } else {
    pausedHtml = `
      <table class="manage-paused-table">
        <thead><tr><th>${t("sc_th_port_svc")}</th><th>PID</th><th>${t("sc_th_frozen_at")}</th><th>${t("sc_th_command")}</th><th>${t("sc_th_action")}</th></tr></thead>
        <tbody>
          ${pausedList.map(p => {
            const ago = p.ts ? agoStr(Date.now() / 1000 - p.ts) : "—";
            return `
              <tr>
                <td><strong>:${p.port}</strong> <span class="tscope">${esc(p.name)}</span></td>
                <td>${(p.pids || []).join(", ") || "—"}</td>
                <td class="tsch">${ago}</td>
                <td class="tcmd" title="${esc(p.cmdline)}">${esc((p.cmdline || "—").slice(0, 60))}</td>
                <td>
                  <button type="button" class="btn-ts-mini svctl-btn" data-svcp="${p.port}" data-svca="resume" data-svcn="${esc(p.name)}">
                    ${icon("play", 11)} <span>${t("ctl_resume")}</span>
                  </button>
                </td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    `;
  }

  // 3. 操作审计历史 (Audit Log) - 从新到旧排序
  const historyList = [...(ctlData.history || [])].reverse().slice(0, 12);
  const historyHtml = historyList.length ? `
    <div class="manage-audit-list">
      ${historyList.map(h => `<div class="manage-audit-item">${esc(h)}</div>`).join("")}
    </div>
  ` : `<div class="gempty" style="padding:10px 0;">${t("sc_no_history")}</div>`;

  el.innerHTML = `
    <h2>${t("m_panel")} <span class="ghint">${t("m_hint")}</span></h2>
    <div class="manage-grid">${cardsHtml}</div>

    <div style="margin-top:20px;">
      <h2>${t("sc_panel_title")} <span class="ghint">${t("sc_panel_hint", { n: pausedList.length })}</span></h2>
      ${pausedHtml}
    </div>

    <div style="margin-top:20px;">
      ${t("sc_history_title")} + ${t("sc_history_hint")}
      ${historyHtml}
    </div>
  `;

  // 绑定按钮事件
  el.querySelectorAll(".ctl-btn").forEach(b => b.addEventListener("click", () => doCtl(b)));
  el.querySelectorAll(".svctl-btn").forEach(b => b.addEventListener("click", () => doSvcCtl(b)));
}

// 端口 -> 受管手动进程服务 id(服务表行尾按钮用)
const MANAGE_PROC_BY_PORT = {};
MANAGE_UNITS.filter(u => u.kind === "proc").forEach(u => MANAGE_PROC_BY_PORT[u.port] = u.id);
// systemd 单元名 -> 受管 id(P0-6 行首状态点; 本列表单元名 = id + ".service")
const MANAGE_SVC_BY_UNIT = {};
MANAGE_UNITS.filter(u => u.kind === "systemd").forEach(u => { MANAGE_SVC_BY_UNIT[u.id + ".service"] = u.id; });

// P0-6: 行首状态点按受管单元状态上色(15s 缓存; fillCtl 的按钮查询保持独立实时不受影响)
const svcDotCache = {};
async function fillSvcDots() {
  if (BOOT.static) return;
  const dots = document.querySelectorAll(".svc-dot[data-unit]");
  const uids = [...new Set([...dots].map(d => d.dataset.unit))];
  const now = Date.now();
  await Promise.all(uids.map(async (uid) => {
    const c = svcDotCache[uid];
    if (c && now - c.t < 15000) return;
    try {
      const r = await fetch("/api/manage?unit=" + encodeURIComponent(uid) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
      svcDotCache[uid] = { t: Date.now(), st: await r.json() };
    } catch (err) {
      svcDotCache[uid] = { t: Date.now(), st: null };   // 查询失败 → 保持灰点
    }
  }));
  dots.forEach(d => {
    const st = (svcDotCache[d.dataset.unit] || {}).st;
    d.classList.remove("off");   // 初始灰态由下面的 toggle 重设, 防止 off/on 并存
    d.classList.toggle("on", !!(st && st.ok && st.active === "active"));
    d.classList.toggle("bad", !!(st && st.ok && st.active !== "active"));
    d.classList.toggle("off", !(st && st.ok));   // 查询失败/未知 → 灰
  });
}

let _fillCtlAt = 0, _fillCtlPromise = null;
async function fillCtl() {
  if (BOOT.static) return;
  const now = Date.now();
  if (_fillCtlPromise) return _fillCtlPromise;
  if (now - _fillCtlAt < 15000) return;
  _fillCtlAt = now;
  const btns = document.querySelectorAll(".ctl-btn");
  _fillCtlPromise = Promise.all([...btns].map(async (b) => {
    const uid = b.dataset.ctl;
    b.setAttribute("aria-disabled", "true");
    try {
      const r = await fetch("/api/manage?unit=" + encodeURIComponent(uid) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
      const st = await r.json();
      const running = st && st.ok && st.active === "active";
      b.textContent = running ? t("ctl_pause") : t("ctl_resume");
      b.dataset.action = running ? "stop" : "start";
      b.setAttribute("aria-disabled", "false");
    } catch (e) { b.innerHTML = icon("err", 13); b.title = e.message; }
  })).finally(() => { _fillCtlPromise = null; });
  return _fillCtlPromise;
}

  document.querySelectorAll(".ctl-btn").forEach(b => b.addEventListener("click", () => doCtl(b)));
function uiConfirm(message) {
  const modal = $("ui-modal"), msg = $("ui-dialog-msg"), ok = $("ui-ok"), cancel = $("ui-cancel");
  if (!modal || !msg || !ok || !cancel) return Promise.resolve(false);
  msg.textContent = message;
  modal.hidden = false;
  document.body.classList.add("modal-open");
  return new Promise(resolve => {
    let done = false;
    const finish = value => { if (done) return; done = true; modal.hidden = true; document.body.classList.remove("modal-open"); cleanup(); resolve(value); };
    const onKey = e => { if (e.key === "Escape") finish(false); if (e.key === "Enter") finish(true); };
    const cleanup = () => { ok.removeEventListener("click", yes); cancel.removeEventListener("click", no); modal.removeEventListener("click", outside); document.removeEventListener("keydown", onKey); };
    const yes = () => finish(true), no = () => finish(false), outside = e => { if (e.target === modal) finish(false); };
    ok.addEventListener("click", yes); cancel.addEventListener("click", no); modal.addEventListener("click", outside); document.addEventListener("keydown", onKey);
    ok.focus();
  });
}
let uiNoticeTimer = null;
function uiNotice(message) {
  const el = $("ui-notice"); if (!el) return;
  el.textContent = message || ""; el.hidden = !message;
  clearTimeout(uiNoticeTimer); if (message) uiNoticeTimer = setTimeout(() => { el.hidden = true; }, 3600);
}

async function doCtl(btn) {
  const uid = btn.dataset.ctl, action = btn.dataset.action;
  if (!await uiConfirm(t("m_confirm", { label: MANAGE_LABELS[action] || action, unit: uid }))) return;
  btn.setAttribute("aria-disabled", "true");
  btn.textContent = t("m_doing");
  try {
    const r = await apiPost("/api/manage?lang=" + encodeURIComponent(LANG),
      { unit: uid, action });
    const d = await r.json();
    btn.innerHTML = icon(d.ok ? "ok" : "err", 13) + " " + escHtml(d.msg || "");
    btn.title = d.msg || "";
    setTimeout(() => { load(true); fillCtl(); }, 800); // 刷新状态
  } catch (e) {
    btn.innerHTML = icon("err", 13);
    btn.title = e.message;
  }
}

// --- 通用服务暂停/恢复 (svcctl): SIGSTOP 冻结(端口保持)/SIGCONT 解冻 ---
function fmtUp(sec) {
  if (!sec || sec < 60) return "—";
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}
function fmtRes(e) {
  const r = e.res;
  if (!r) return "";
  // cpu 取整与 dpayload 同粒度: 轮询间行 HTML 稳定, 增量渲染可复用未变行
  return `<span class='svc-res' title='${t("svc_res_title")}'>${Math.round(r.cpu)}% · ${r.mem_mb >= 1024 ? (r.mem_mb / 1024).toFixed(1) + "G" : Math.round(r.mem_mb) + "M"} · ${fmtUp(r.up_sec)}</span>`;
}
function svBtn(e) {
  if (!e.manageable || e.is_self) return "";
  const paused = !!e.svcctl_paused;
  return `<span class='svctl-btn' data-svcp='${e.port}' data-svca='${paused ? "resume" : "pause"}' role='button' tabindex='0'>${icon(paused ? "play" : "pause", 12)} ${paused ? t("ctl_resume") : t("ctl_pause")}</span>`;
}
// 通用结果 toast(成功/失败反馈, 首页迷你按钮用)
function uiToast(msg, ico) {
  const d = document.createElement("div");
  d.className = "copy-toast";
  d.innerHTML = icon(ico || "ok", 13) + " " + escHtml(msg || "");
  document.body.appendChild(d);
  setTimeout(() => { d.style.opacity = "0"; setTimeout(() => d.remove(), 350); }, 1400);
}
async function doSvcCtl(btn) {
  const mini = btn.dataset.svmini === "1";
  const port = +btn.dataset.svcp, action = btn.dataset.svca;
  const name = btn.dataset.svcn || (":" + port);
  if (action === "pause" && !await uiConfirm(t("sc_confirm_pause", { name, port }))) return;
  btn.setAttribute("aria-disabled", "true");
  if (!mini) btn.textContent = t("m_doing");
  try {
    const r = await apiPost("/api/svcctl", { port, action });
    const d = await r.json();
    if (mini) uiToast(d.msg || (d.ok ? "OK" : "FAIL"), d.ok ? "ok" : "err");
    else { btn.innerHTML = icon(d.ok ? "ok" : "err", 13) + " " + escHtml(d.msg || ""); btn.title = d.msg || ""; }
    setTimeout(() => load(true), 800);
  } catch (e) {
    if (mini) uiToast(e.message, "err"); else { btn.innerHTML = icon("err", 13); btn.title = e.message; }
  }
}
document.addEventListener("click", (ev) => {
  const b = ev.target.closest(".svctl-btn");
  if (!b) return;
  ev.preventDefault(); ev.stopPropagation();   // 迷你按钮嵌在 <a> 磁贴内: 拦截导航
  if (b.getAttribute("aria-disabled") !== "true") doSvcCtl(b);
});

// --- 首屏快照缓存(localStorage): 打开页面先用上次数据秒渲染, 后台再拉新覆盖 ---
// 慢接口(/api/repos 冷启动 ~14s)不再阻塞首屏; 右上刷新钮照常拉最新。
const SNAP_K = "svc-snap1:";
function snapGet(k) {
  try { const raw = localStorage.getItem(SNAP_K + k); return raw ? JSON.parse(raw) : null; }
  catch (e) { return null; }
}
function snapSet(k, v) {
  try { localStorage.setItem(SNAP_K + k, JSON.stringify(v)); } catch (e) { /* 超限/隐私模式: 忽略 */ }
}

function applyFragment(part, selector, html) {
  const box = document.createElement("template");
  box.innerHTML = html.trim();
  const next = box.content.querySelector(selector);
  const old = document.querySelector(selector);
  if (next && old) {
    if (old.classList.contains("cat-off")) next.classList.add("cat-off");
    old.replaceWith(next);
    const i = pagesHomeOrder ? pagesHomeOrder.indexOf(old) : -1;   // P1: replaceWith 后同步引用, 防跨断点回桌面把旧骨架放回
    if (i >= 0) pagesHomeOrder[i] = next;
  }
  else if (part === "toolchips" && next) {
    document.querySelector("#filters")?.before(next);
    if (!isMobile() && curCat !== "home") next.classList.add("cat-off");
  }
  else return false;
  if (part === "toolchips") renderToolchips();
  return true;
}

async function hydrateFragments() {
  if (BOOT.static) return;
  const jobs = [
    ["goals", "#goals"],
    ["events", "#events"],
    ["toolchips", "#toolchips"],
  ];
  await Promise.all(jobs.map(async ([part, selector]) => {
    const snap = snapGet("frag:" + part);          // 先落快照, 骨架屏立即变实数据
    if (snap && snap.html) {
      try { if (applyFragment(part, selector, snap.html)) remeasureTrack(); } catch (e) {}
    }
    try {
      const r = await fetch("/api/fragment?p=" + part + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const html = await r.text();
      if (applyFragment(part, selector, html)) {
        snapSet("frag:" + part, { html });
        remeasureTrack();   // fragment 落地改变当前页高度, 立即重测(RO 兜底其余异步)
      }
    } catch (err) {
      console.error("fragment hydrate failed: " + part, err);
    }
  }));
}

function applyApiData(data) {
  $("updated").textContent = new Date(data.updated * 1000).toLocaleString(LOCALE_TAG);
  lastUpdatedTs = data.updated * 1000;
  services = data.services;
  renderToolchips();
  applyFilter();
  renderOverview(data);          // 概要摘要(指标/需要处理/最近活动)
  loadRepos();                    // 仓库面板(客户端 60s 缓存; 面板内按钮强制重算)
}

let refreshInFlight = null;
async function load(alsoSys) {
  if (refreshInFlight) return refreshInFlight;
  const btns = [$("refresh"), $("fab-refresh")].filter(Boolean);
  btns.forEach(b => { b.classList.add("spinning"); b.setAttribute("aria-disabled", "true"); });

  refreshInFlight = (async () => {
    try {
      if (BOOT.static) {
        if (BOOT.apiData) applyApiData(BOOT.apiData);
        if (alsoSys && BOOT.sysData) renderSys(BOOT.sysData);
        if (BOOT.vmsData) renderVms(BOOT.vmsData);
        return;
      }
      ompCache = null; tasksCache = null; tmuxCache = null; // 手动刷新清面板缓存,拿到最新 agent/tmux/任务状态
      const snap = snapGet("api");
      if (snap && snap.data) {                 // 快照先行: 不等网络
        try { applyApiData(snap.data); } catch (e) { console.error("snapshot render failed", e); }
      }
      try {
        const r = await fetch("/api", { cache: "no-store" });
        const data = await r.json();
        applyApiData(data);
        snapSet("api", { data });
      } catch (err) {
        console.error("refresh failed", err);
      }
      if (alsoSys) {
        const ss = snapGet("sys");
        if (ss && ss.data) { try { renderSys(ss.data); } catch (e) {} }
        loadVms(true);
        try {
          const r = await fetch("/api/sys", { cache: "no-store" });
          const d = await r.json();
          renderSys(d);
          snapSet("sys", { data: d });
        } catch (err) {
          console.error("sys refresh failed", err);
        }
      }
    } finally {
      btns.forEach(b => { b.classList.remove("spinning"); b.setAttribute("aria-disabled", "false"); });
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

// 统一全站刷新调度器：防重入、联动当前页数据刷新，顶栏按钮与下拉刷新共享
async function triggerSharedRefresh(opts = {}) {
  const isPull = !!opts.isPull;
  try {
    await load(true);
    if (typeof page !== "undefined") {
      if (page === 1 && typeof renderActivityPage === "function") {
        await renderActivityPage();
      } else if (page === 2 && typeof renderTmuxPage === "function") {
        await renderTmuxPage();
      } else if (page === 3 && typeof initAgentsPage === "function") {
        await initAgentsPage();
      } else if (page === 4) {
        if (typeof filter !== "undefined" && filter === "tailscale" && typeof renderNetworkPage === "function") {
          await renderNetworkPage(true);
        } else if (typeof filter !== "undefined" && filter === "omp" && typeof loadAgents === "function") {
          await loadAgents().then(renderAgentPanel);
        } else if (typeof filter !== "undefined" && filter === "watchdog" && typeof loadTasks === "function") {
          await loadTasks().then(renderWatchdogPanel);
        } else if (typeof filter !== "undefined" && filter === "tmux" && typeof loadTmux === "function") {
          await loadTmux().then(renderTmuxPanel);
        } else if (typeof filter !== "undefined" && filter === "manage" && typeof loadManage === "function") {
          await loadManage();
        }
      }
    }
  } catch (err) {
    console.error("[svc-dashboard] shared refresh failed:", err);
  }
}

/* ================================================================
   概要摘要 + 告警中心(轻量) + 日志时间线 —— 移动端概要/日志页的数据层。
   桌面端 renderOverview 直接返回,布局零变化。
   /api/goals 15s 缓存,概要与日志页共用。 */
let lastUpdatedTs = Date.now();
let goalsCache = { t: 0, data: null };
const LOG_LIMIT = 200;

async function fetchGoalsData(force) {
  if (BOOT.static && BOOT.goalsData) return BOOT.goalsData;
  const now = Date.now();
  if (!force && goalsCache.data && now - goalsCache.t < 15000) return goalsCache.data;
  const snap = snapGet("goals");
  if (!force && snap && snap.data) {
    goalsCache = { t: now, data: snap.data };
    fetch("/api/goals?limit=" + LOG_LIMIT + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" })
      .then(r => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(d => { goalsCache = { t: Date.now(), data: d }; snapSet("goals", { data: d });
                   if (page === 1) renderActivityPage(); })
      .catch(err => console.error("goals refresh failed", err));
    return snap.data;
  }
  try {
    const r = await fetch("/api/goals?limit=" + LOG_LIMIT + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    if (d && d.updated) lastUpdatedTs = Math.max(lastUpdatedTs, d.updated * 1000);
    goalsCache = { t: now, data: d };
    snapSet("goals", { data: d });
  } catch (err) {
    console.error("goals refresh failed", err);
    if (!force && page === 1) {
      setTimeout(() => { if (page === 1 && !goalsCache.data) renderActivityPage(); }, 3000);
    }
  }
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

// P1-9: agent 卡/表摘要剥离 markdown 记号(标题# 强调*_` 引用> 链接只留文字)
function stripMd(s) {
  return String(s ?? "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[#*_~`>]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// --- 事件类型元数据: 图标(双通道) + 语义组(ok/warn/fail/recover) ---
const EV_META = {
  complete: { ico: "ok", grp: "ok", key: "evk_complete" },
  recover:  { ico: "up", grp: "recover", key: "evk_recover" },
  restart:  { ico: "retry", grp: "fail", key: "evk_restart" },
  nudge:    { ico: "bell", grp: "warn", key: "evk_nudge" },
  pause:    { ico: "⏸", grp: "warn", key: "evk_pause" },
  reclaim: { ico: "trash", grp: "ok", key: "evk_reclaim" },
  cleanup:  { ico: "trash", grp: "ok", key: "evk_cleanup" },
  commit:   { ico: "branch", grp: "ok", key: "evk_commit" },
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
    if (g.light === "paused") a = { sev: "warn", key: "paused|" + id, icon: ["pause", "t-warn"], msg: t("al_paused") };
    else if (g.light === "lost") a = { sev: "bad", key: "lost|" + id, icon: ["warn", "t-red"], msg: t("al_lost") };
    else if (g.light === "done") a = { sev: "done", key: "done|" + id, icon: ["ok", "t-green"], msg: t("al_done") };
    else if (g.stalled) a = { sev: "warn", key: "stalled|" + id, icon: ["clock", "t-warn"], msg: t("al_stalled") };
    else if (g.light === "retry") a = { sev: "warn", key: "retry|" + id, icon: ["retry", "t-warn"], msg: t("g_retry") };
    if (a) out.push({ sev: a.sev, key: a.key, icon: a.icon, msg: a.msg,
                      name: g.name || g.session || "—", sub: sub, cmd: g.resume_cmd || "" });
  });
  return out;
}
function renderAlerts(alerts) {
  const el = $("alert-body"), panel = $("alerts");
  if (!el) return;
  if (panel) panel.hidden = !alerts.length;
  if (!alerts.length) { el.innerHTML = ""; return; }
  el.innerHTML = alerts.map(a => `
    <div class="alert-item" data-key="${escAttr(a.key)}">
      <span class="al-ico ${a.icon[1]}">${icon(a.icon[0], 15)}</span>
      <div class="al-main">
        <div class="al-line"><span class="al-name">${escHtml(a.name)}</span><span class="al-msg">${escHtml(a.msg)}</span></div>
        ${a.sub ? `<div class="al-sub">${escHtml(a.sub)}</div>` : ""}
      </div>
      <div class="al-act">
        ${a.cmd ? `<span class="al-btn gcopy" data-cmd="${escAttr(a.cmd)}" role="button" tabindex="0" title="${escAttr(a.cmd)}">${icon("copy", 13)}</span>` : ""}
        <span class="al-btn detail" role="button" tabindex="0">${t("al_detail")}</span>
        <span class="al-btn ignore" role="button" tabindex="0">${t("al_ignore")}</span>
      </div>
    </div>`).join("");
}

const IMG_EXT_RE = /\.(png|jpe?g|gif|webp|svg|bmp|ico|avif)$/i;

// 自动发布器产生的固定维护提交只折叠历史，始终保留最新一条作为发布状态。
function isStaticPublishCommit(e) {
  if (!e || e.kind !== "commit" || e.repo !== "svc-dashboard") return false;
  const subject = String(e.subject || e.text || "").split("\n", 1)[0].trim();
  return /^Update sanitized static snapshot(?:\s|$)/i.test(subject);
}

function withLatestStaticPublishCommit(events) {
  const list = events || [];
  let latestIndex = -1, latestTs = -Infinity;
  list.forEach((e, i) => {
    if (!isStaticPublishCommit(e)) return;
    const ts = Number(e.ts) || 0;
    if (ts > latestTs) { latestTs = ts; latestIndex = i; }
  });
  return list.filter((e, i) => !isStaticPublishCommit(e) || i === latestIndex);
}

function renderPortalActivity(events) {
  const body = $("hp-body-activity"), badge = $("hp-badge-activity");
  if (!body) return;
  const evts = events || [];
  const commits = withLatestStaticPublishCommit(evts).filter(e => e.kind === "commit");
  if (badge) badge.textContent = commits.length ? t("hp_recent_count", { n: commits.length }) : "";
  const recent = commits.slice(0, 4);
  if (!recent.length) {
    body.innerHTML = `<div class="gempty">${escHtml(t("hp_no_recent_act"))}</div>`;
    return;
  }
  body.innerHTML = recent.map(e => {
    const th = getRepoTheme(e.repo || "repo");
    const hasImg = (e.files || []).some(f => IMG_EXT_RE.test(f.path));
    const imgBadge = hasImg ? `<span title="${escAttr(t("act_image_title"))}" style="color:#f472b6;margin-left:4px;">${icon("img", 11)}</span>` : "";
    const msg = (e.text || "").split("\n")[0].trim() || (e.short_sha || "commit");
    const ago = agoFromTs(e.ts);
    return `<div class="hp-act-row" data-nav="activity">
      <div class="hp-act-topline">
        <span class="hp-act-repo" style="--rc-col:${th.color};--rc-bg:${th.bg};--rc-bd:${th.border};">
          <span class="act-repo-dot"></span>
          <span>${escHtml(e.repo || "git")}</span>
        </span>
        <span class="hp-act-author">${escHtml(e.author ? `by ${e.author}` : "")}</span>
        ${imgBadge}
        <span class="hp-act-time">${escHtml(ago)}</span>
      </div>
      <div class="hp-act-msg">${escHtml(msg)}</div>
    </div>`;
  }).join("");
}

async function renderPortalTmux() {
  const body = $("hp-body-tmux"), badge = $("hp-badge-tmux");
  if (!body) return;
  try {
    const data = await fetchTmuxData();
    const sessions = (data && data.sessions) || [];
    const sum = (data && data.summary) || {};
    if (badge) badge.textContent = t("hp_sessions_count", { n: sum.total || sessions.length });
    if (!sessions.length) {
      body.innerHTML = `<div class="gempty">${escHtml(t("hp_no_tmux"))}</div>`;
      return;
    }
    const recent = sessions.slice(0, 4);
    body.innerHTML = recent.map(s => {
      const winCount = s.windows_count || (s.windows ? s.windows.length : 1);
      const isAgent = s.is_agent;
      const firstWin = (s.windows || [])[0] || {};
      const firstPane = (firstWin.panes || [])[0] || {};
      const cmd = firstPane.command || firstWin.name || "bash";
      return `<div class="hp-tmux-row" data-nav="tmux">
        <div class="hp-tmux-info">
          <div class="hp-tmux-name">
            <span class="agent-status-dot on"></span>
            <b>${escHtml(s.name)}</b>
          </div>
          <div class="hp-tmux-sub">${t("hp_windows_count", { n: winCount })} · ${escHtml(cmd)}</div>
        </div>
        <span class="hp-tmux-badge">${isAgent ? "Agent" : s.attached ? "attached" : "detached"}</span>
      </div>`;
    }).join("");
  } catch (e) {
    body.innerHTML = `<div class="gempty">${escHtml(e.message)}</div>`;
  }
}

function renderPortalSvc(services) {
  const body = $("hp-body-svc"), badge = $("hp-badge-svc");
  if (!body) return;
  const svcs = services || [];
  const web = svcs.filter(e => {
    const ip = e.ip || "";
    const loop = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
    return e.scope !== "system" && !e.paused && !loop && ![22000, 5355].includes(+e.port);
  });
  const seen = new Set(), uniq = [];
  web.forEach(e => { const k = e.port + ":" + (e.name || ""); if (!seen.has(k)) { seen.add(k); uniq.push(e); } });
  const activeCount = svcs.filter(s => !s.paused).length;
  if (badge) badge.textContent = t("hp_services_count", { n: activeCount, total: svcs.length });
  if (!uniq.length) {
    body.innerHTML = `<div class="gempty">${escHtml(t("hp_no_svc"))}</div>`;
    return;
  }
  const topSvcs = uniq.slice(0, 6);
  body.innerHTML = `<div class="hp-svc-grid">` + topSvcs.map(e => {
    const id = svcIdentity(e);
    const link = `http://${linkHost(location.hostname)}:${e.port}/`;
    const r = e.res;
    const resTxt = r ? `${r.cpu.toFixed(0)}% · ${Math.round(r.mem_mb)}M` : (id.sub || "active");
    return `<a class="hp-svc-chip" href="${escAttr(link)}" target="_blank" rel="noopener">
      <div class="hp-svc-head">
        <span class="hp-svc-name">${escHtml(id.main)}</span>
        <span class="hp-svc-port">:${e.port}</span>
      </div>
      <div class="hp-svc-res">${escHtml(resTxt)}</div>
    </a>`;
  }).join("") + `</div>`;
}

function formatQuotaBucketName(label) {
  if (!label) return t("quota_label_default");
  let s = String(label);
  s = s.replace(/^(Gemini Models|Claude and GPT models)\s*·\s*/i, "");
  s = s.replace(/^codex\s*·\s*/i, "");
  s = s.replace(/^gpt-reserve\s*·\s*/i, t("quota_gpt_reserve") + " · ");
  s = s.replace(/\bprimary\b/i, "5h");
  s = s.replace(/\bsecondary\b/i, t("quota_weekly"));
  s = s.replace(/\bgemini-5h\b/i, "Gemini 5h");
  s = s.replace(/\bgemini-weekly\b/i, t("quota_gemini_weekly"));
  s = s.replace(/\b3p-5h\b/i, "Claude/3P 5h");
  s = s.replace(/\b3p-weekly\b/i, t("quota_3p_weekly"));
  return s.trim();
}

async function renderPortalAgent() {
  const body = $("hp-body-agent"), badge = $("hp-badge-agent");
  if (!body) return;
  try {
    const d = await loadRuntimes();
    const agents = (d && d.agents) || [];
    if (badge) badge.textContent = t("hp_installed_running", {
      installed: d.total_installed || 0, running: d.total_running || 0
    });
    // 只显示有额度数据的 agent，没有额度或查不到的一律不显示
    const withQuota = agents.filter(a => {
      const buckets = (a.quota && a.quota.buckets) || [];
      return buckets.length > 0 && buckets.some(b => b.remaining_pct != null);
    }).sort((a, b) => (b.procs || 0) - (a.procs || 0));

    if (!withQuota.length) {
      body.innerHTML = `<div class="gempty">${escHtml(t("hp_no_agent_proc"))}</div>`;
      return;
    }
    body.innerHTML = withQuota.map(a => {
      const buckets = (a.quota && a.quota.buckets) || [];
      // 工作目录摘要
      const cwds = [...new Set((a.proc_list || []).map(p =>
        (p.cwd || "").replace(/\/$/, "").split("/").pop() || "?"
      ))].slice(0, 2);
      const cwdHtml = cwds.map(c => `<span class="hp-ag-cwd">${escHtml(c)}</span>`).join("");

      // 额度分桶进度条
      const bucketsHtml = `<div class="hp-ag-buckets">` + buckets.map(b => {
        const p = b.remaining_pct != null ? Math.round(b.remaining_pct) : null;
        if (p == null) return "";
        const cls = p >= 50 ? "high" : (p >= 15 ? "mid" : "low");
        const shortName = formatQuotaBucketName(b.label);
        let resetTip = "";
        if (b.reset) {
          const m = b.reset.match(/(?:\d{4}-)?(\d{2}-\d{2}\s+\d{2}:\d{2})/);
          resetTip = m ? m[1] : b.reset.slice(-8);
        } else if (b.detail && b.detail.includes("/")) {
          resetTip = b.detail.split(" ")[0];
        }
        return `<div class="hp-bucket-row">
          <div class="hp-bucket-meta">
            <span class="hp-bucket-name" title="${escAttr(b.label)}">${escHtml(shortName)}</span>
            <span class="hp-bucket-right">
              ${resetTip ? `<span class="hp-bucket-reset">${escHtml(resetTip)}</span>` : ""}
              <span class="hp-bucket-val ${cls}">${p}%</span>
            </span>
          </div>
          <div class="hp-bucket-track">
            <div class="hp-bucket-fill ${cls}" style="width:${Math.max(p, 2)}%"></div>
          </div>
        </div>`;
      }).join("") + `</div>`;

      return `<div class="hp-ag-item" role="button" tabindex="0" data-nav="agent" data-agent="${escAttr(a.id)}">
        <div class="hp-ag-item-head">
          <div class="hp-ag-title-wrap">
            <span class="agent-status-dot on"></span>
            <span class="hp-ag-name">${escHtml(a.name)}</span>
            <span class="hp-ag-procs">${a.procs}${escHtml(t("hp_procs_unit"))}</span>
          </div>
          <div class="hp-ag-cwds">${cwdHtml}</div>
        </div>
        ${bucketsHtml}
      </div>`;
    }).join("");
  } catch (e) {
    body.innerHTML = `<div class="gempty">${escHtml(e.message)}</div>`;
  }
}



// --- PVE 虚拟机状态面板 (Windows11 / DEBIAN) ---
let vmsCache = { t: 0, data: null };
async function loadVms(force) {
  if (BOOT.static && BOOT.vmsData) {
    vmsCache.data = BOOT.vmsData;
    vmsCache.t = Date.now();
    renderVms(BOOT.vmsData);
    return BOOT.vmsData;
  }
  const now = Date.now();
  if (!force && vmsCache.data && now - vmsCache.t < 15000) {
    renderVms(vmsCache.data);
    return vmsCache.data;
  }
  const snap = snapGet("vms");
  if (!force && snap && snap.data && !vmsCache.data) {
    vmsCache = { t: now, data: snap.data };
    renderVms(snap.data);
  }
  try {
    const r = await fetch("/api/vms", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    vmsCache = { t: Date.now(), data: d };
    snapSet("vms", { data: d });
    renderVms(d);
    return d;
  } catch (err) {
    if (!snap) console.error("vms load failed", err);
    return vmsCache.data;
  }
}

function fmtGib(b) {
  if (!b || b <= 0) return "0 B";
  const gib = b / 1073741824;
  if (gib >= 1) return gib.toFixed(2) + " GiB";
  const mib = b / 1048576;
  if (mib >= 1) return mib.toFixed(2) + " MiB";
  return b + " B";
}

function fmtUptimeLang(sec) {
  if (!sec || sec <= 0) return "";
  const days = Math.floor(sec / 86400);
  const rem = sec % 86400;
  const hours = String(Math.floor(rem / 3600)).padStart(2, "0");
  const mins = String(Math.floor((rem % 3600) / 60)).padStart(2, "0");
  const secs = String(rem % 60).padStart(2, "0");
  if (days > 0) {
    return t("vm_uptime_days", { d: days, h: hours, m: mins, s: secs });
  }
  return `${hours}:${mins}:${secs}`;
}

function renderVms(d) {
  const el = $("hp-vms-grid");
  if (!el) return;
  const list = (d && d.vms) || [];
  if (!list.length) {
    if (d && d.error) {
      el.innerHTML = `<div class="gempty" style="grid-column:1/-1;">${escHtml(d.error)}</div>`;
    }
    return;
  }

  el.innerHTML = list.map(v => {
    const isRun = v.status === "running";
    const upStr = isRun && v.uptime ? `(${t("vm_uptime_prefix")}: ${fmtUptimeLang(v.uptime)})` : "";
    const cpuPct = Number(v.cpu_usage || 0).toFixed(2);
    const memPct = Number(v.mem_percent || 0).toFixed(2);
    const cpuStr = `${cpuPct}% of ${v.cpus || 1} CPUs`;
    const memStr = t("vm_mem_of", { pct: memPct, total: fmtGib(v.mem_total), used: fmtGib(v.mem_used) });
    const memHostStr = fmtGib(v.mem_host);
    const diskStr = fmtGib(v.boot_disk);
    const haStr = (!v.ha || v.ha === "none") ? t("vm_ha_none") : (v.ha || t("vm_ha_none"));

    // CPU bar & Mem bar
    const memFillCls = v.mem_percent > 90 ? " bad" : v.mem_percent >= 75 ? " warn" : "";

    // IPs
    let ipsHtml = "";
    if (v.ips && v.ips.length) {
      ipsHtml = `<div class="hp-vm-ips-wrap">` + v.ips.map(ip => {
        return `<span class="hp-vm-ip-tag" title="${escAttr(ip)}">${escHtml(ip)}</span>`;
      }).join("") + `</div>`;
    } else {
      ipsHtml = `<span class="hp-vm-v" style="color:var(--text-muted);font-weight:400;">${escHtml(t("vm_no_agent"))}</span>`;
    }

    const pveLink = linkHost(v.pve_url || "https://127.0.0.1:8006");

    return `<div class="gpanel hp-vm-card" id="hp-vm-${escAttr(v.vmid)}" data-vmid="${escAttr(v.vmid)}" role="button" tabindex="0">
      <div class="hp-vm-head">
        <div class="hp-vm-title-wrap">
          <span class="hp-vm-ico ${isRun ? "running" : "stopped"}">${icon("server", 15)}</span>
          <span class="hp-vm-name">${escHtml(v.name)}</span>
          ${upStr ? `<span class="hp-vm-uptime">${escHtml(upStr)}</span>` : ""}
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="hp-vm-status-badge ${isRun ? "running" : "stopped"}">
            ${icon("dot", 8)} ${isRun ? "running" : "stopped"}
          </span>
          <span class="hp-vm-link" data-openvm="${escAttr(v.vmid)}" title="${escAttr(t("vmd_title"))}">
            ${escHtml(t("al_detail"))} ${icon("chev", 11)}
          </span>
        </div>
      </div>
      <div class="hp-vm-rows">
        <div class="hp-vm-row">
          <div class="hp-vm-row-kv">
            <span class="hp-vm-k">${icon("doc", 13)} ${escHtml(t("vm_status"))}</span>
            <span class="hp-vm-v">${isRun ? "running" : "stopped"}</span>
          </div>
        </div>
        <div class="hp-vm-row">
          <div class="hp-vm-row-kv">
            <span class="hp-vm-k">${icon("heart", 13)} ${escHtml(t("vm_ha"))}</span>
            <span class="hp-vm-v">${escHtml(haStr)}</span>
          </div>
        </div>
        <div class="hp-vm-row">
          <div class="hp-vm-row-kv">
            <span class="hp-vm-k">${icon("box", 13)} ${escHtml(t("vm_node"))}</span>
            <span class="hp-vm-v">${escHtml(v.node || "pve")}</span>
          </div>
        </div>
        <div class="hp-vm-row">
          <div class="hp-vm-row-kv">
            <span class="hp-vm-k">${icon("cpu", 13)} ${escHtml(t("vm_cpu"))}</span>
            <span class="hp-vm-v">${escHtml(cpuStr)}</span>
          </div>
          <div class="hp-vm-bar-track">
            <div class="hp-vm-bar-fill cpu" style="width:${Math.min(Math.max(v.cpu_usage || 0, isRun ? 1 : 0), 100)}%;"></div>
          </div>
        </div>
        <div class="hp-vm-row">
          <div class="hp-vm-row-kv">
            <span class="hp-vm-k">${icon("mem", 13)} ${escHtml(t("vm_mem"))}</span>
            <span class="hp-vm-v">${escHtml(memStr)}</span>
          </div>
          <div class="hp-vm-bar-track">
            <div class="hp-vm-bar-fill mem${memFillCls}" style="width:${Math.min(Math.max(v.mem_percent || 0, isRun ? 1 : 0), 100)}%;"></div>
          </div>
        </div>
        <div class="hp-vm-row">
          <div class="hp-vm-row-kv">
            <span class="hp-vm-k">${icon("mem", 13)} ${escHtml(t("vm_host_mem"))}</span>
            <span class="hp-vm-v">${escHtml(memHostStr)}</span>
          </div>
        </div>
        <div class="hp-vm-row">
          <div class="hp-vm-row-kv">
            <span class="hp-vm-k">${icon("disk", 13)} ${escHtml(t("vm_boot_disk"))}</span>
            <span class="hp-vm-v">${escHtml(diskStr)}</span>
          </div>
        </div>
        <div class="hp-vm-row">
          <div class="hp-vm-row-kv" style="align-items:flex-start;">
            <span class="hp-vm-k" style="margin-top:2px;">${icon("network", 13)} ${escHtml(t("vm_ips"))}</span>
            ${ipsHtml}
          </div>
        </div>
      </div>
    </div>`;
  }).join("");
}

// --- PVE 虚拟机详情全屏浮层 (VM Details Sheet) ---
let curVmDetailId = null;
let curVmTab = "summary";
let vmDetailCache = {};

function makeVmAreaChart(points, valKey, color, gradId, maxScale, isBytes) {
  if (!points || !points.length) {
    return `<div class="gempty" style="height:120px;display:flex;align-items:center;justify-content:center;">${escHtml(t("es_sub"))}</div>`;
  }
  const vals = points.map(p => Number(p[valKey]) || 0);
  const maxV = Math.max(...vals, maxScale || 1);
  const W = 500, H = 130, padTop = 15, padBottom = 22, padLeft = 45, padRight = 12;
  const plotW = W - padLeft - padRight;
  const plotH = H - padTop - padBottom;

  const pts = points.map((p, i) => {
    const x = padLeft + (i / Math.max(points.length - 1, 1)) * plotW;
    const v = Number(p[valKey]) || 0;
    const y = padTop + plotH - (maxV > 0 ? (v / maxV) * plotH : 0);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const polylinePts = pts.join(" ");
  const polygonPts = `${padLeft},${H - padBottom} ` + polylinePts + ` ${W - padRight},${H - padBottom}`;

  const fmtTime = (ts) => ts ? new Date(ts * 1000).toTimeString().slice(0, 5) : "";
  const tStart = fmtTime(points[0].time);
  const tMid = fmtTime(points[Math.floor(points.length / 2)].time);
  const tEnd = fmtTime(points[points.length - 1].time);

  const fmtAxis = (v) => {
    if (isBytes) {
      if (v >= 1073741824) return (v / 1073741824).toFixed(1) + "G";
      if (v >= 1048576) return (v / 1048576).toFixed(0) + "M";
      if (v >= 1024) return (v / 1024).toFixed(0) + "K";
      return Math.round(v);
    }
    return Math.round(v) + (maxScale === 100 ? "%" : "");
  };

  return `
    <svg class="vmd-svg-chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <defs>
        <linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="${color}" stop-opacity="0.45"/>
          <stop offset="100%" stop-color="${color}" stop-opacity="0.02"/>
        </linearGradient>
      </defs>
      <line x1="${padLeft}" y1="${padTop}" x2="${W - padRight}" y2="${padTop}" stroke="rgba(255,255,255,0.06)" stroke-width="1" />
      <line x1="${padLeft}" y1="${padTop + plotH / 2}" x2="${W - padRight}" y2="${padTop + plotH / 2}" stroke="rgba(255,255,255,0.06)" stroke-width="1" stroke-dasharray="3,3" />
      <line x1="${padLeft}" y1="${H - padBottom}" x2="${W - padRight}" y2="${H - padBottom}" stroke="rgba(255,255,255,0.12)" stroke-width="1" />

      <text x="${padLeft - 6}" y="${padTop + 4}" font-size="9" fill="rgba(255,255,255,0.4)" text-anchor="end" font-family="monospace">${fmtAxis(maxV)}</text>
      <text x="${padLeft - 6}" y="${H - padBottom}" font-size="9" fill="rgba(255,255,255,0.4)" text-anchor="end" font-family="monospace">0</text>

      <polygon fill="url(#${gradId})" points="${polygonPts}" />
      <polyline fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" points="${polylinePts}" />

      <text x="${padLeft}" y="${H - 6}" font-size="9" fill="rgba(255,255,255,0.45)" font-family="monospace">${tStart}</text>
      <text x="${padLeft + plotW / 2}" y="${H - 6}" font-size="9" fill="rgba(255,255,255,0.45)" text-anchor="middle" font-family="monospace">${tMid}</text>
      <text x="${W - padRight}" y="${H - 6}" font-size="9" fill="rgba(255,255,255,0.45)" text-anchor="end" font-family="monospace">${tEnd}</text>
    </svg>
  `;
}

function renderVmDetailHeader(v) {
  const isRun = v.status === "running";
  const title = $("vm-sheet-title");
  const sub = $("vm-sheet-sub");
  const badge = $("vm-sheet-badge");
  const ico = $("vm-sheet-ico");
  const pveLink = $("vm-sheet-pve-link");

  if (title) title.textContent = v.name || ("VM-" + v.vmid);
  if (sub) sub.textContent = `${v.node || "pve"} · qemu/${v.vmid}` + (isRun && v.uptime ? ` · ${t("vm_uptime_prefix")}: ${fmtUptimeLang(v.uptime)}` : "");
  if (badge) {
    badge.className = "hp-vm-status-badge " + (isRun ? "running" : "stopped");
    badge.innerHTML = `${icon("dot", 8)} ${isRun ? "running" : "stopped"}`;
  }
  if (ico) {
    ico.className = "hp-vm-ico " + (isRun ? "running" : "stopped");
  }
  if (pveLink) {
    pveLink.href = linkHost(v.pve_url || `https://127.0.0.1:8006/#v1:0:=qemu%2F${v.vmid}:4:=notes::::::=notes`);
  }
}

function renderVmDetailTab(d, tab) {
  const body = $("vm-sheet-body");
  if (!body) return;
  const isRun = d.status === "running";
  const hw = d.hardware || {};
  const opt = d.options || {};
  const rrd = d.rrd || [];
  const latestRrd = rrd.length ? rrd[rrd.length - 1] : {};

  if (tab === "summary") {
    const cpuChartSvg = makeVmAreaChart(rrd, "cpu", "#38bdf8", "grad-cpu-vmd", 100, false);
    const memChartSvg = makeVmAreaChart(rrd, "mem", "#22c55e", "grad-mem-vmd", d.mem_total || (hw.memory_mb * 1048576), true);

    const ipsHtml = (d.ips && d.ips.length)
      ? d.ips.map(ip => `<span class="hp-vm-ip-tag" title="${escAttr(ip)}">${escHtml(ip)}</span>`).join(" ")
      : `<span style="color:var(--text-muted);">${escHtml(t("vm_no_agent"))}</span>`;

    body.innerHTML = `
      <div class="vmd-metrics-grid">
        <div class="vmd-kpi">
          <span class="vmd-kpi-lbl">${icon("cpu", 13)} ${escHtml(t("vm_cpu"))}</span>
          <span class="vmd-kpi-val">${Number(d.cpu_usage || 0).toFixed(2)}%</span>
          <span class="vmd-kpi-sub">${d.cpus || hw.cores || 1} Cores · ${escHtml(hw.cpu_type || "kvm64")}</span>
        </div>
        <div class="vmd-kpi">
          <span class="vmd-kpi-lbl">${icon("mem", 13)} ${escHtml(t("vm_mem"))}</span>
          <span class="vmd-kpi-val">${fmtGib(d.mem_used)}</span>
          <span class="vmd-kpi-sub">${fmtGib(d.mem_total)}</span>
        </div>
        <div class="vmd-kpi">
          <span class="vmd-kpi-lbl">${icon("disk", 13)} ${escHtml(t("vm_boot_disk"))}</span>
          <span class="vmd-kpi-val">${fmtGib(d.boot_disk)}</span>
          <span class="vmd-kpi-sub">${escHtml(d.node || "pve")}</span>
        </div>
        <div class="vmd-kpi">
          <span class="vmd-kpi-lbl">${icon("network", 13)} ${escHtml(t("vm_ips"))}</span>
          <div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px;">${ipsHtml}</div>
        </div>
      </div>

      <div class="vmd-charts-grid">
        <div class="vmd-chart-card">
          <div class="vmd-chart-head">
            <span class="vmd-chart-title">${icon("cpu", 14)} ${escHtml(t("vmd_chart_cpu"))}</span>
            <span class="vmd-chart-badge">${Number(d.cpu_usage || 0).toFixed(1)}%</span>
          </div>
          <div class="vmd-chart-box">${cpuChartSvg}</div>
        </div>
        <div class="vmd-chart-card">
          <div class="vmd-chart-head">
            <span class="vmd-chart-title">${icon("mem", 14)} ${escHtml(t("vmd_chart_mem"))}</span>
            <span class="vmd-chart-badge">${fmtGib(d.mem_used)}</span>
          </div>
          <div class="vmd-chart-box">${memChartSvg}</div>
        </div>
      </div>

      <div class="vmd-table-card">
        <h3>${icon("activity", 15)} ${escHtml(t("vmd_chart_io"))}</h3>
        <div class="vmd-kv-list">
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_net_in"))} / ${escHtml(t("vmd_net_out"))}</span>
            <span class="vmd-kv-v">${fmtGib(latestRrd.netin || 0)}/s · ${fmtGib(latestRrd.netout || 0)}/s</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_disk_read"))} / ${escHtml(t("vmd_disk_write"))}</span>
            <span class="vmd-kv-v">${fmtGib(latestRrd.diskread || 0)}/s · ${fmtGib(latestRrd.diskwrite || 0)}/s</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vm_host_mem"))}</span>
            <span class="vmd-kv-v">${fmtGib(d.mem_host)}</span>
          </div>
        </div>
      </div>
    `;
    return;
  }

  if (tab === "hardware") {
    const disksHtml = (hw.disks || []).map(dk => `
      <div class="vmd-kv-item">
        <span class="vmd-kv-k" style="font-family:var(--font-mono);font-weight:600;color:#38bdf8;">${escHtml(dk.key)}</span>
        <span class="vmd-kv-v">${escHtml(dk.value)}</span>
      </div>
    `).join("") || `<div class="gempty">${escHtml(t("es_sub"))}</div>`;

    const nicsHtml = (hw.nics || []).map(nc => `
      <div class="vmd-kv-item">
        <span class="vmd-kv-k" style="font-family:var(--font-mono);font-weight:600;color:#4ade80;">${escHtml(nc.key)}</span>
        <span class="vmd-kv-v">${escHtml(nc.value)}</span>
      </div>
    `).join("") || `<div class="gempty">${escHtml(t("es_sub"))}</div>`;

    body.innerHTML = `
      <div class="vmd-table-card">
        <h3>${icon("cpu", 15)} ${escHtml(t("vmd_hw_processors"))}</h3>
        <div class="vmd-kv-list">
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">Cores</span>
            <span class="vmd-kv-v">${hw.cores || 1}</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">Sockets</span>
            <span class="vmd-kv-v">${hw.sockets || 1}</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">Type</span>
            <span class="vmd-kv-v">${escHtml(hw.cpu_type || "kvm64")}</span>
          </div>
        </div>
      </div>

      <div class="vmd-table-card">
        <h3>${icon("mem", 15)} ${escHtml(t("vmd_hw_memory"))}</h3>
        <div class="vmd-kv-list">
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_hw_memory"))}</span>
            <span class="vmd-kv-v">${hw.memory_mb || 0} MB (${fmtGib(d.mem_total)})</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">Ballooning</span>
            <span class="vmd-kv-v">${hw.balloon ? hw.balloon + " MB" : escHtml(t("vm_ha_none"))}</span>
          </div>
        </div>
      </div>

      <div class="vmd-table-card">
        <h3>${icon("disk", 15)} ${escHtml(t("vmd_hw_disks"))}</h3>
        <div class="vmd-kv-list">${disksHtml}</div>
      </div>

      <div class="vmd-table-card">
        <h3>${icon("network", 15)} ${escHtml(t("vmd_hw_network"))}</h3>
        <div class="vmd-kv-list">${nicsHtml}</div>
      </div>

      <div class="vmd-table-card">
        <h3>${icon("server", 15)} ${escHtml(t("vmd_hw_bios"))} & ${escHtml(t("vmd_hw_machine"))}</h3>
        <div class="vmd-kv-list">
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_hw_bios"))}</span>
            <span class="vmd-kv-v">${escHtml(hw.bios || "seabios")}</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_hw_machine"))}</span>
            <span class="vmd-kv-v">${escHtml(hw.machine || "pc")}</span>
          </div>
        </div>
      </div>
    `;
    return;
  }

  if (tab === "options") {
    body.innerHTML = `
      <div class="vmd-table-card">
        <h3>${icon("tool", 15)} ${escHtml(t("vmd_tab_options"))}</h3>
        <div class="vmd-kv-list">
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_opt_onboot"))}</span>
            <span class="vmd-kv-v">${opt.onboot ? `<span style="color:#4ade80;">${icon("ok", 12)} YES</span>` : escHtml(t("vm_ha_none"))}</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_opt_bootorder"))}</span>
            <span class="vmd-kv-v">${escHtml(opt.boot_order || "—")}</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_opt_ostype"))}</span>
            <span class="vmd-kv-v">${escHtml(opt.ostype || "—")}</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vmd_opt_agent"))}</span>
            <span class="vmd-kv-v">${d.has_guest_agent ? `<span style="color:#4ade80;">${icon("ok", 12)} enabled</span>` : escHtml(t("vm_no_agent"))}</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vm_ha"))}</span>
            <span class="vmd-kv-v">${escHtml(d.ha === "none" ? t("vm_ha_none") : d.ha)}</span>
          </div>
          <div class="vmd-kv-item">
            <span class="vmd-kv-k">${escHtml(t("vm_node"))}</span>
            <span class="vmd-kv-v">${escHtml(d.node || "pve")}</span>
          </div>
        </div>
      </div>
    `;
    return;
  }

  if (tab === "tasks") {
    const snaps = d.snapshots || [];
    const snapsHtml = snaps.length ? snaps.map(s => `
      <div class="vmd-snap-card">
        <div class="vmd-snap-info">
          <span class="vmd-snap-name">${icon("file", 13)} ${escHtml(s.name)}</span>
          ${s.description ? `<span class="vmd-snap-desc">${escHtml(s.description)}</span>` : ""}
        </div>
        <span class="vmd-task-time">${s.snaptime ? escHtml(agoFromTs(s.snaptime)) : "—"}</span>
      </div>
    `).join("") : `<div class="gempty">${escHtml(t("vmd_snaps_none"))}</div>`;

    const tasks = d.tasks || [];
    const tasksHtml = tasks.length ? tasks.map(tk => {
      const isOk = tk.status === "OK";
      return `
        <div class="vmd-task-row">
          <div class="vmd-task-main">
            <span class="vmd-task-badge">${escHtml(tk.type)}</span>
            <span style="color:${isOk ? '#4ade80' : '#ef4444'};font-weight:600;">${escHtml(tk.status)}</span>
            <span style="color:var(--text-dim);font-size:11px;">by ${escHtml(tk.user)}</span>
          </div>
          <span class="vmd-task-time">${tk.starttime ? escHtml(agoFromTs(tk.starttime)) : "—"}</span>
        </div>
      `;
    }).join("") : `<div class="gempty">${escHtml(t("vmd_tasks_none"))}</div>`;

    body.innerHTML = `
      <div class="vmd-table-card">
        <h3>${icon("file", 15)} ${escHtml(t("vmd_snaps_title"))}</h3>
        <div style="display:flex;flex-direction:column;gap:8px;">${snapsHtml}</div>
      </div>

      <div class="vmd-table-card">
        <h3>${icon("clock", 15)} ${escHtml(t("vmd_tasks_title"))}</h3>
        <div style="display:flex;flex-direction:column;gap:6px;">${tasksHtml}</div>
      </div>
    `;
  }
}

let vmDetailInFlight = null;
async function openVmDetail(vmid) {
  const idStr = String(vmid);
  const sheet = $("vm-detail-sheet");
  if (!sheet) return;

  sheet.hidden = false;
  sheet.classList.add("opening");
  document.documentElement.classList.add("traj-noscroll");

  if (location.hash !== "#vm=" + idStr) {
    location.hash = "#vm=" + idStr;
  }

  // Pre-fill from vmsCache if available
  const vmBasics = (vmsCache.data && vmsCache.data.vms || []).find(v => String(v.vmid) === idStr);
  if (vmBasics) {
    renderVmDetailHeader(vmBasics);
  }

  curVmDetailId = idStr;
  if (!curVmTab) curVmTab = "summary";
  document.querySelectorAll("#vm-sheet-nav .chip").forEach(c => {
    c.classList.toggle("active", c.getAttribute("data-vmtab") === curVmTab);
  });

  // Check static / cache
  if (BOOT.static && BOOT.vmsDetail && BOOT.vmsDetail[idStr]) {
    renderVmDetailHeader(BOOT.vmsDetail[idStr]);
    renderVmDetailTab(BOOT.vmsDetail[idStr], curVmTab);
    return;
  }

  if (vmDetailCache[idStr] && (Date.now() - vmDetailCache[idStr].t < 15000)) {
    renderVmDetailHeader(vmDetailCache[idStr].data);
    renderVmDetailTab(vmDetailCache[idStr].data, curVmTab);
    return;
  }

  if (vmDetailInFlight === idStr) return;
  vmDetailInFlight = idStr;

  const body = $("vm-sheet-body");
  if (body) body.innerHTML = `<div class="gempty">${escHtml(t("st_loading"))}</div>`;

  try {
    const r = await fetch(`/api/vms/detail?vmid=${encodeURIComponent(idStr)}`, { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    vmDetailCache[idStr] = { t: Date.now(), data: d };
    if (curVmDetailId === idStr) {
      renderVmDetailHeader(d);
      renderVmDetailTab(d, curVmTab);
    }
  } catch (err) {
    if (body && curVmDetailId === idStr) body.innerHTML = `<div class="gempty">${escHtml(err.message)}</div>`;
  } finally {
    if (vmDetailInFlight === idStr) vmDetailInFlight = null;
  }
}

function closeVmDetail() {
  curVmDetailId = null;
  const sheet = $("vm-detail-sheet");
  if (sheet) sheet.hidden = true;
  document.documentElement.classList.remove("traj-noscroll");
  if (location.hash.startsWith("#vm=")) {
    history.replaceState(null, "", location.pathname + location.search);
  }
}

// 事件监听: VM 卡片点击、详情抽屉关闭与切卡
$("hp-vms-grid")?.addEventListener("click", (e) => {
  const card = e.target.closest("[data-vmid]");
  if (card) {
    const vmid = card.getAttribute("data-vmid");
    if (vmid) openVmDetail(vmid);
  }
});

$("vm-sheet-back")?.addEventListener("click", closeVmDetail);

$("vm-sheet-nav")?.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-vmtab]");
  if (!btn) return;
  const tab = btn.getAttribute("data-vmtab");
  curVmTab = tab;
  document.querySelectorAll("#vm-sheet-nav .chip").forEach(c => c.classList.toggle("active", c === btn));
  let d = null;
  if (BOOT.static && BOOT.vmsDetail && BOOT.vmsDetail[curVmDetailId]) {
    d = BOOT.vmsDetail[curVmDetailId];
  } else if (curVmDetailId && vmDetailCache[curVmDetailId]) {
    d = vmDetailCache[curVmDetailId].data;
  }
  if (d) renderVmDetailTab(d, tab);
});

window.addEventListener("hashchange", () => {
  const m = location.hash.match(/^#vm=(\d+)/);
  if (m) {
    openVmDetail(m[1]);
  } else if (curVmDetailId) {
    closeVmDetail();
  }
});
const initVmM = location.hash.match(/^#vm=(\d+)/);
if (initVmM) {
  openVmDetail(initVmM[1]);
}

let lastSvc = { ok: 0, total: 0 };
async function renderOverview(apiData) {
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

  const mSvc = $("m-svc"), mRun = $("m-run"), mBad = $("m-bad"), mAlert = $("m-alert");
  if (mSvc) mSvc.textContent = lastSvc.ok + "/" + lastSvc.total;
  if (mRun) mRun.textContent = nRun;
  if (mBad) { mBad.textContent = nBad; mBad.classList.toggle("alert", nBad > 0); }
  if (mAlert) { mAlert.textContent = nAlert; mAlert.classList.toggle("alert", nAlert > 0); }

  renderAlerts(alerts);
  updateBadge(nAlert);

  // 渲染首页四大中枢概览卡片与 PVE 虚拟机
  loadVms();
  renderPortalActivity(events);
  renderPortalSvc(apiData && apiData.services);
  await Promise.allSettled([renderPortalTmux(), renderPortalAgent()]);
}
function renderHomeTiles(services) {
  const el = $("hp-tiles");
  if (!el) return;
  const panel = el.closest(".hp-web");
  const svcs = services || [];
  const web = svcs.filter(e => {
    const ip = e.ip || "";
    const loop = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
    return e.scope !== "system" && !e.paused && !loop && ![22000, 5355].includes(+e.port);
  });
  // 同端口去重(docker v4/v6 双行)
  const seen = new Set(), uniq = [];
  web.forEach(e => { const k = e.port + ":" + (e.name || ""); if (!seen.has(k)) { seen.add(k); uniq.push(e); } });
  if (panel) panel.hidden = !uniq.length;
  el.innerHTML = uniq.length ? uniq.map(e => {
    const link = `http://${linkHost(location.hostname)}:${e.port}/`;
    const id = svcIdentity(e);
    const svp = !!e.svcctl_paused;
    const btn = (e.manageable && !e.is_self)
      ? `<span class="svctl-btn hp-sv${svp ? " paused" : ""}" data-svmini="1" data-svcp="${e.port}" data-svca="${svp ? "resume" : "pause"}" data-svcn="${escAttr(id.main)}" role="button" tabindex="-1" title="${svp ? t("ctl_resume") : t("ctl_pause")}">${icon(svp ? "play" : "pause", 11)}</span>` : "";
    // 资源行: 一眼看出大户 —— cpu≥80%/mem≥1G 红, ≥30%/≥300M 橙
    const r = e.res;
    let resLine = "";
    if (r) {
      const hot = r.cpu >= 30 || r.mem_mb >= 300, crit = r.cpu >= 80 || r.mem_mb >= 1024;
      resLine = `<span class="hp-tile-res${crit ? " crit" : hot ? " hot" : ""}">`
        + `${r.cpu.toFixed(1)}% · ${r.mem_mb >= 1024 ? (r.mem_mb / 1024).toFixed(1) + "G" : Math.round(r.mem_mb) + "M"} · ${fmtUp(r.up_sec)}</span>`;
    }
    const tip = [id.tip, r ? `${t("svc_res_title")}: ${r.cpu.toFixed(1)}% · ${Math.round(r.mem_mb)}M · ${fmtUp(r.up_sec)}` : ""].filter(Boolean).join("\n");
    return `<a class="hp-tile${svp ? " sv-paused" : ""}" href="${escAttr(link)}" target="_blank" rel="noopener" title="${escAttr(tip)}">`
      + `<span class="hp-tile-main"><span class="hp-tile-name">${escHtml(id.main)}</span>`
      + `<span class="hp-tile-main-r"><span class="hp-tile-port">:${e.port}</span>${btn}</span></span>`
      + resLine
      + `<span class="hp-tile-sub">${escHtml(id.sub)}</span></a>`;
  }).join("") : "";
}
// Web 磁贴身份识别: 主标签选"最能认出这是啥"的名字, 副行给程序/路径上下文。
// docker → 容器名; systemd 真单元 → 单元名; 否则脚本名(解释器/dashboard 这类泛化名
// 退回 cwd 目录名, 如 python3 -m http.server + cwd=yomu → 主标签 yomu)。
function svcIdentity(e) {
  const interp = new Set(["python", "python3", "python", "node", "bun", "npm", "npx",
    "uv", "dotnet", "java", "ruby", "perl", "php", "sh", "bash", "sudo", "nohup"]);
  const cmdline = (e.cmdline || "").trim();
  const cwd = e.cwd || "";
  const parts = cmdline.split(/\s+/).filter(Boolean);
  let script = "", isModule = false;
  for (const p of parts.slice(1)) {          // 跳过 argv0, 取首个非 flag 参数
    if (p === "-m") { isModule = true; continue; }
    if (p.startsWith("-")) continue;
    script = p; break;
  }
  const scriptBase = script ? script.split("/").pop().replace(/\.(py|js|ts)$/, "") : "";
  const cwdBase = cwd && cwd !== "/" ? cwd.replace(/\/+$/, "").split("/").pop() : "";
  const dockerName = (e.name || "").includes("(docker)") ? e.name.replace(/\s*\(docker\)/, "") : "";
  const unit = e.unit || "";
  const realUnit = unit && !unit.endsWith(".scope") ? unit.replace(/\.service$/, "") : "";
  const cmdShort = (() => {
    const p = cmdline.split(/\s+/).filter(Boolean);
    if (p.length > 1) p[0] = p[0].split("/").pop();
    let s = p.join(" ");
    return s.length > 46 ? s.slice(0, 45) + "…" : s;
  })();
  let main = "", sub = "";
  if (dockerName && e.type === "docker") { main = dockerName; sub = "Docker"; }
  else if (realUnit) { main = realUnit; sub = unit; }
  else {
    const generic = isModule || !scriptBase || interp.has(scriptBase) || scriptBase === "dashboard";
    if (!generic && scriptBase !== cwdBase && cwdBase !== "tetsuya") { main = scriptBase; sub = cwd; }
    else if (cwdBase && cwdBase !== "tetsuya") { main = cwdBase; sub = cmdShort; }
    else { main = (e.name || "?").replace(/\s*\(docker\)/, ""); sub = cmdShort; }
  }
  const tip = [cmdline, cwd ? `cwd: ${cwd}` : "", unit ? `unit: ${unit}` : ""].filter(Boolean).join("\n");
  return { main, sub, tip };
}
function renderHomeGoals(goals, nRun, nBad) {
  const el = $("hp-goal-body");
  if (!el) return;
  const panel = el.closest(".hp-goals");
  if (panel) panel.hidden = !(goals || []).length;
  const act = (goals || []).filter(g => g.light === "active" || g.light === "retry")
    .sort((a, b) => (b.idle_sec || 0) - (a.idle_sec || 0)).slice(0, 4);
  el.innerHTML = `<div class="hp-goal-line"><b>${nRun}</b> ${t("g_active")} · <b class="${nBad ? "t-red" : ""}">${nBad}</b> ${t("g_paused")}</div>`
    + (act.length ? act.map(g => `<div class="hp-goal-row"><span class="glight t-green">${icon("dot", 10)}</span>`
       + `<span class="hp-goal-name">${escHtml(g.name)}</span><span class="hp-goal-ctx">${escHtml(g.ctx_raw || "")}</span>`
       + `<span class="hp-goal-ago">${g.idle_sec != null ? escHtml(agoStr(g.idle_sec)) : ""}</span></div>`).join("")
      : `<div class="gempty">${t("g_none")}</div>`);
}
function updateBadge(n) {
  const b = $("tab-alert-badge");
  if (!b) return;
  b.hidden = !n;
  b.textContent = n > 99 ? "99+" : String(n);
}

// 概要页交互: 四大中枢 Portal 跳转
document.addEventListener("click", (e) => {
  const jump = e.target.closest("[data-nav]");
  if (jump) {
    if (e.target.closest("a[href]") || e.target.closest(".gcopy") || e.target.closest(".svctl-btn")) return;
    const nav = jump.dataset.nav;
    if (nav === "activity") { isMobile() ? setPage(1) : setCat("activity"); }
    else if (nav === "tmux") { isMobile() ? setPage(2) : setCat("tmux"); }
    else if (nav === "agent") { isMobile() ? setPage(3) : setCat("agent"); }
    else if (nav === "svc") { isMobile() ? setPage(4) : setCat("svc"); }
    else if (nav === "network" || nav === "ts") {
      if (isMobile()) setPage(4); else setCat("svc");
      filter = "tailscale"; applyFilter();
    }
    scrollTo({ top: 0, behavior: "smooth" });
  }
});

const statuslineEl = $("statusline");   // header 状态栏已移除(85102dc), 此处判空防崩
if (statuslineEl) statuslineEl.addEventListener("click", () => {
  setPage(0);
  const m = document.querySelector("main");
  if (m) m.scrollTo({ top: 0 });
});
const rcMore = document.querySelector(".rc-more");
if (rcMore) rcMore.addEventListener("click", () => {
  if (typeof mqMobile !== "undefined" && mqMobile.matches) setPage(1);
  else setCat("activity");
});
const hpMore = document.querySelector(".hp-more");
if (hpMore) hpMore.addEventListener("click", () => {
  if (typeof mqMobile !== "undefined" && mqMobile.matches) setPage(2);
  else setCat("tmux");
});
const recentBodyEl = $("recent-body");
if (recentBodyEl) {
  recentBodyEl.addEventListener("click", (evt) => {
    const row = evt.target.closest(".rc-row");
    if (row && row.dataset.url) {
      window.open(row.dataset.url, "_blank", "noopener,noreferrer");
      return;
    }
    if (typeof mqMobile !== "undefined" && mqMobile.matches) setPage(1);
    else setCat("activity");
  });
}
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

// --- 活动流 (Activity Stream: Git 提交 + 远程同步 + Goal/Watchdog) ---
let curActivityFilter = "all";
let showStaticPublishCommits = false;

function formatDiff(raw) {
  return raw.split("\n").map(line => {
    const esc = escHtml(line);
    if (line.startsWith("+++") || line.startsWith("---")) {
      return `<span class="diff-line diff-meta">${esc}</span>`;
    } else if (line.startsWith("+")) {
      return `<span class="diff-line diff-add">${esc}</span>`;
    } else if (line.startsWith("-")) {
      return `<span class="diff-line diff-del">${esc}</span>`;
    } else if (line.startsWith("@@")) {
      return `<span class="diff-line diff-hunk">${esc}</span>`;
    } else if (line.includes(" | ") && (line.includes("+") || line.includes("-"))) {
      return `<span class="diff-line diff-stat">${esc}</span>`;
    }
    return `<span class="diff-line">${esc}</span>`;
  }).join("");
}

function formatBroadDate(ts) {
  const d = new Date(ts * 1000);
  const now = new Date();
  const y = d.getFullYear(), m = d.getMonth() + 1, day = d.getDate();
  const todayStr = `${now.getFullYear()}-${now.getMonth()+1}-${now.getDate()}`;
  const yest = new Date(now.getTime() - 86400000);
  const yestStr = `${yest.getFullYear()}-${yest.getMonth()+1}-${yest.getDate()}`;
  const curStr = `${y}-${m}-${day}`;
  const dt = (LANG === "en")
    ? `${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${day}, ${y}`
    : `${y}-${m}-${day}`;
  const title = (LANG === "en") ? t("act_commits_on", { d: dt }) : dt;
  if (curStr === todayStr) return title + " · " + t("act_date_today");
  if (curStr === yestStr) return title + " · " + t("act_date_yest");
  return title;
}

const GITHUB_NODE_SVG = `<svg class="act-node-svg" width="24" height="18" viewBox="0 0 24 18" fill="none" aria-hidden="true"><path d="M0 9h7M17 9h7" stroke="var(--border-subtle, rgba(128,128,128,.45))" stroke-width="2"/><circle cx="12" cy="9" r="4.5" fill="var(--bg, #0a0a0a)" stroke="var(--border-subtle, rgba(128,128,128,.7))" stroke-width="2"/><circle cx="12" cy="9" r="1.8" fill="currentColor"/></svg>`;

const CURATED_PALETTE = [
  "#a371f7", // 紫色 (Mir3-Research)
  "#388bfd", // 蓝色 (zircon)
  "#3fb950", // 绿色 (svc-dashboard)
  "#f0883e", // 暖橙
  "#22d3ee", // 青蓝
  "#f43f5e", // 玫红
  "#eab308", // 黄金
  "#14b8a6", // 蓝绿
  "#fb7185", // 珊瑚红
  "#818cf8", // 靛蓝
  "#84cc16", // 黄绿
  "#d946ef", // 洋红
  "#0ea5e9", // 天蓝
  "#fb923c", // 杏橙
  "#2dd4bf", // 薄荷
  "#e11d48", // 宝石红
  "#6366f1", // 鸢尾紫
  "#10b981", // 翡翠绿
  "#f97316", // 橘红
  "#06b6d4"  // 深青
];

function hexToRgba(hex, alpha) {
  let c = hex.replace("#", "");
  if (c.length === 3) c = c.split("").map(x => x + x).join("");
  const num = parseInt(c, 16);
  return `rgba(${(num >> 16) & 255}, ${(num >> 8) & 255}, ${num & 255}, ${alpha})`;
}

let repoColorMap = null;
function getRepoColorMap() {
  if (repoColorMap) return repoColorMap;
  try {
    repoColorMap = JSON.parse(localStorage.getItem("svc_repo_colors") || "{}");
  } catch (e) {
    repoColorMap = {};
  }
  if (!repoColorMap["Mir3-Research"]) repoColorMap["Mir3-Research"] = "#a371f7";
  if (!repoColorMap["zircon"]) repoColorMap["zircon"] = "#388bfd";
  if (!repoColorMap["svc-dashboard"]) repoColorMap["svc-dashboard"] = "#3fb950";
  return repoColorMap;
}

function getRepoTheme(repo) {
  if (!repo) repo = "other";
  const map = getRepoColorMap();
  let hex = map[repo];
  if (!hex) {
    const used = new Set(Object.values(map));
    const unused = CURATED_PALETTE.filter(c => !used.has(c));
    let h = 0;
    for (let i = 0; i < repo.length; i++) h = (h * 31 + repo.charCodeAt(i)) >>> 0;
    if (unused.length > 0) {
      hex = unused[h % unused.length];
    } else {
      hex = CURATED_PALETTE[h % CURATED_PALETTE.length];
    }
    map[repo] = hex;
    try { localStorage.setItem("svc_repo_colors", JSON.stringify(map)); } catch (e) {}
  }
  return {
    color: hex,
    bg: hexToRgba(hex, 0.12),
    border: hexToRgba(hex, 0.35)
  };
}

async function renderActivityPage() {
  const ap = $("activity-page");
  if (ap) ap.hidden = false;
  const container = $("activity-body");
  if (!container) return;
  const d = await fetchGoalsData();
  if (!d) {
    container.innerHTML = `<div class="gempty t-red">${escHtml(t("act_load_failed"))}<button class="btn" type="button" id="act-retry">${escHtml(t("refresh"))}</button></div>`;
    $("act-retry")?.addEventListener("click", async () => {
      container.innerHTML = `<div class="gempty">${escHtml(t("a_loading"))}</div>`;
      await fetchGoalsData(true);
      renderActivityPage();
    }, { once: true });
    return;
  }
  const events = (d && d.events) || [];
  const activityEvents = showStaticPublishCommits ? events : withLatestStaticPublishCommit(events);
  if (!activityEvents.length) {
    container.innerHTML = `<div class="gempty">${escHtml(t("act_empty"))}</div>`;
    return;
  }

  // 计数更新
  const nAll = activityEvents.length;
  const nCommit = activityEvents.filter(e => e.kind === "commit").length;
  const nImg = activityEvents.filter(e => e.kind === "commit" && (e.files || []).some(f => IMG_EXT_RE.test(f.path))).length;
  const nBoth = activityEvents.filter(e => e.kind === "commit" && e.origin === "both").length;
  const nLocal = activityEvents.filter(e => e.kind === "commit" && e.origin === "local").length;
  const nDone = activityEvents.filter(e => e.src === "done" || e.kind === "complete").length;
  const nWd = activityEvents.filter(e => e.src === "watchdog").length;

  const setCnt = (id, n) => { const el = $(id); if (el) el.textContent = n ? `(${n})` : ""; };
  setCnt("n-act-all", nAll);
  setCnt("n-act-commit", nCommit);
  setCnt("n-act-img", nImg);
  setCnt("n-act-both", nBoth);
  setCnt("n-act-local", nLocal);
  setCnt("n-act-done", nDone);
  setCnt("n-act-watchdog", nWd);
  const autoToggle = $("act-auto-publish-toggle");
  if (autoToggle) {
    autoToggle.classList.toggle("active", showStaticPublishCommits);
    const hiddenCount = Math.max(0, events.filter(isStaticPublishCommit).length - 1);
    autoToggle.textContent = `${t(showStaticPublishCommits ? "act_hide_auto" : "act_show_auto")}${hiddenCount && !showStaticPublishCommits ? ` (${hiddenCount})` : ""}`;
  }

  // 筛选过滤 (类型筛选)
  const filtered = activityEvents.filter(e => {
    if (curActivityFilter === "commit") { if (e.kind !== "commit") return false; }
    else if (curActivityFilter === "img") { if (e.kind !== "commit" || !(e.files || []).some(f => IMG_EXT_RE.test(f.path))) return false; }
    else if (curActivityFilter === "both") { if (e.kind !== "commit" || e.origin !== "both") return false; }
    else if (curActivityFilter === "local") { if (e.kind !== "commit" || e.origin !== "local") return false; }
    else if (curActivityFilter === "done") { if (e.src !== "done" && e.kind !== "complete") return false; }
    else if (curActivityFilter === "watchdog") { if (e.src !== "watchdog" && e.kind !== "watchdog") return false; }
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="gempty">${escHtml(t("act_empty"))}</div>`;
    return;
  }

  // 保持时间倒序, 按连续相同日期对条目分组(类似 GitHub Commit Timeline)
  const dateGroups = [];
  filtered.forEach(e => {
    const d = new Date(e.ts * 1000);
    const dKey = `${d.getFullYear()}-${d.getMonth()+1}-${d.getDate()}`;
    const last = dateGroups[dateGroups.length - 1];
    if (last && last.key === dKey) {
      last.items.push(e);
    } else {
      dateGroups.push({
        key: dKey,
        title: formatBroadDate(e.ts),
        items: [e]
      });
    }
  });

  const renderCard = (e, pos, theme) => {
    let spineEl = "";
    if (pos === "first") {
      spineEl = `<div class="act-spine spine-bot"></div>`;
    } else if (pos === "mid") {
      spineEl = `<div class="act-spine spine-full"></div>`;
    } else if (pos === "last") {
      spineEl = `<div class="act-spine spine-top"></div>`;
    }
    const nodeEl = `<div class="act-node" data-pos="${pos}"></div>`;

    if (e.kind === "commit") {
      const repo = e.repo || e.name || "git";
      const sha = e.short_sha || e.gid || "";
      const branch = e.branch ? `<span class="act-branch">${icon("branch", 11)} ${escHtml(e.branch)}</span>` : "";
      let originBadge = "";
      if (e.origin === "both") {
        originBadge = `<span class="rc-tag rc-synced">${icon("check", 10)} ${escHtml(t("gh_synced"))}</span>`;
      } else if (e.origin === "local") {
        originBadge = `<span class="rc-tag rc-local">${escHtml(t("gh_local"))}</span>`;
      } else if (e.origin === "github") {
        originBadge = `<span class="rc-tag rc-gh">${icon("git", 10)} GitHub</span>`;
      }

      const files = e.files || [];
      const imgFiles = files.filter(f => IMG_EXT_RE.test(f.path));
      const hasImg = imgFiles.length > 0;
      let imgBadge = "";
      if (hasImg) {
        imgBadge = `<span class="rc-tag rc-img" title="${escAttr(t("act_image_count", { n: imgFiles.length }))}">${icon("img", 11)} ${escHtml(t("act_has_img"))}${imgFiles.length > 1 ? ` (${imgFiles.length})` : ''}</span>`;
      }

      let filesHtml = "";
      if (files.length > 0) {
        const fileRows = files.slice(0, 8).map(f => {
          const st = (f.status || "M").toUpperCase();
          const cls = st === "A" ? "fbadge-a" : (st === "D" ? "fbadge-d" : (st === "R" ? "fbadge-r" : "fbadge-m"));
          const isImgFile = IMG_EXT_RE.test(f.path);
          const imgMark = isImgFile ? ` <span class="act-img-dot" title="${escAttr(t("act_image_title"))}">${icon("img", 10)}</span>` : "";
          return `<div class="act-f-row ${isImgFile ? 'is-img' : ''}"><span class="fbadge ${cls}">${escHtml(st)}</span><span class="act-f-path" title="${escAttr(f.path)}">${escHtml(f.path)}</span>${imgMark}</div>`;
        }).join("");
        const moreTxt = files.length > 8 ? `<div class="act-f-row act-f-more" style="color:var(--text-ghost); font-size:10.5px;">... ${t("act_more")} (${files.length - 8})</div>` : "";
        filesHtml = `<div class="act-files-summary">${icon("diff", 12)} <span>${files.length} ${escHtml(t("act_files_changed"))}</span></div>` +
                    `<div class="act-files-box">${fileRows}${moreTxt}</div>`;
      }

      let ghBtn = "";
      if (e.url) {
        ghBtn = `<a class="btn-act btn-act-gh" href="${escAttr(e.url)}" target="_blank" rel="noopener">${icon("git", 13)} ${escHtml(t("act_diff_gh"))} ↗</a>`;
      } else if (sha) {
        ghBtn = `<a class="btn-act btn-act-gh" href="https://github.com/iamcheyan/${encodeURIComponent(repo)}/commit/${encodeURIComponent(sha)}" target="_blank" rel="noopener">${icon("git", 13)} ${escHtml(t("act_diff_gh"))} ↗</a>`;
      }

      let diffBtn = "";
      if (!BOOT.static && sha && e.origin !== "github") {
        diffBtn = `<button class="btn-act btn-act-diff" data-repo="${escAttr(repo)}" data-sha="${escAttr(sha)}">${icon("diff", 13)} <span class="act-diff-text">${escHtml(t("act_diff_local"))}</span></button>`;
      }

      const subj = e.subject || e.text || "—";
      const timeStr = e.time || (e.ts ? new Date(e.ts * 1000).toLocaleString(LOCALE_TAG) : '');
      const author = e.author || "cheyan";
      const initial = (author.slice(0, 1) || "C").toUpperCase();
      const metaRow = `<div class="act-meta-row">
        <span class="act-author-wrap"><span class="act-avatar-badge">${escHtml(initial)}</span> <span class="act-author">${escHtml(author)}</span></span>
        <span class="act-dot-sep">·</span>
        <span class="act-time-full">${icon("clock", 11)} ${escHtml(timeStr)}</span>
        <span class="act-dot-sep">·</span>
        <span class="act-time-ago">${escHtml(agoFromTs(e.ts))}</span>
      </div>`;

      return `<div class="act-card" data-repo="${escAttr(repo)}" data-sha="${escAttr(sha)}" data-pos="${pos}">
        ${nodeEl}
        ${spineEl}
        <div class="act-top">
          <span class="act-badge-repo" style="color:${theme.color};background:${theme.bg};border:1px solid ${theme.border};">${escHtml(repo)}</span>
          ${branch}
          ${sha ? `<span class="act-sha">${escHtml(sha)}</span>` : ""}
          ${originBadge}
          ${imgBadge}
          <span class="act-time" title="${escAttr(timeStr)}">${escHtml(agoFromTs(e.ts))}</span>
        </div>
        <div class="act-body">
          <div class="act-subj">${escHtml(subj)}</div>
          ${metaRow}
          ${filesHtml}
        </div>
        <div class="act-actions">
          ${ghBtn}
          ${diffBtn}
        </div>
        <div class="act-diff-box" hidden><pre class="act-diff-pre"><code></code></pre></div>
      </div>`;
    } else {
      const m = EV_META[e.kind] || EV_META.other;
      const isDone = e.src === "done" || e.kind === "complete";
      const ico = isDone ? "ok" : (m.ico || "branch");
      const kindLabel = t(m.key);
      const timeStr = e.time || (e.ts ? new Date(e.ts * 1000).toLocaleString(LOCALE_TAG) : '');
      const resumeBtn = e.resume_cmd ? `<button class="btn-act-resume gcopy" data-copy="${escAttr(e.resume_cmd)}" title="${escAttr(t("act_copy_resume"))}">${icon("copy", 11)} <span>${t("g_resume")}</span></button>` : "";
      return `<div class="act-card act-card-event" data-pos="${pos}">
        ${nodeEl}
        ${spineEl}
        <div class="act-top">
          <span class="rc-ico" style="display:inline-flex;align-items:center;">${icon(ico, 14)}</span>
          <span class="act-badge-repo" style="color:${theme.color};background:${theme.bg};border:1px solid ${theme.border};">${escHtml(e.name || e.gid || '')}</span>
          <span class="rc-tag ${isDone ? 'rc-synced' : 'rc-local'}">${escHtml(kindLabel)}</span>
          <span class="act-time" title="${escAttr(timeStr)}">${escHtml(agoFromTs(e.ts))}</span>
        </div>
        <div class="act-body">
          <div class="act-subj" style="font-weight: normal; color: var(--text-soft); font-size: 12.5px;">${escHtml(e.text || '—')}</div>
          <div class="act-meta-row">
            <span class="act-time-full">${icon("clock", 11)} ${escHtml(timeStr)}</span>
            ${resumeBtn}
          </div>
        </div>
      </div>`;
    }
  };

  container.innerHTML = `<div class="act-timeline">` + dateGroups.map(grp => {
    // 连续属于同一仓库/目标的事件聚合成一个 cluster (共享小柱子并归入同一卡片)
    const clusters = [];
    let curCluster = null;
    grp.items.forEach(e => {
      let key = "";
      let name = "";
      if (e.kind === "commit") {
        name = e.repo || e.name || "git";
        key = "repo:" + name;
      } else if (e.src === "done" || e.kind === "complete") {
        name = e.name || e.gid || "goal";
        key = "goal:" + name;
      } else {
        name = e.kind || "event";
        key = "ev:" + name;
      }

      if (!curCluster || curCluster.key !== key) {
        curCluster = { key, name, kind: e.kind, theme: getRepoTheme(name), items: [] };
        clusters.push(curCluster);
      }
      curCluster.items.push(e);
    });

    const clustersHtml = clusters.map(c => {
      const count = c.items.length;
      const cardsHtml = c.items.map((e, idx) => {
        let pos = "single";
        if (count > 1) {
          if (idx === 0) pos = "first";
          else if (idx === count - 1) pos = "last";
          else pos = "mid";
        }
        return renderCard(e, pos, c.theme);
      }).join("");

      return `<div class="act-repo-cluster" style="--rc-col:${c.theme.color};--rc-bg:${c.theme.bg};--rc-bd:${c.theme.border};" data-repo="${escAttr(c.name)}" data-count="${count}">
        <div class="act-group-card">
          ${cardsHtml}
        </div>
      </div>`;
    }).join("");

    const cntTxt = grp.items.length > 1 ? `<span class="act-date-count">(${t("act_changes_cnt", { n: grp.items.length })})</span>` : "";
    return `<div class="act-date-group">
      <div class="act-date-header">
        <span class="act-node-icon">${GITHUB_NODE_SVG}</span>
        <span class="act-date-title">${escHtml(grp.title)} ${cntTxt}</span>
      </div>
      ${clustersHtml}
    </div>`;
  }).join("") + `</div>`;
  if (typeof applyPagesX === "function" && isMobile()) {
    requestAnimationFrame(() => applyPagesX(false));
  }
}

// 委托监听活动页 Diff 按钮与筛选过滤
document.addEventListener("click", async (e) => {
  const chip = e.target.closest("#act-filters .chip");
  if (chip) {
    if (chip.id === "act-auto-publish-toggle") {
      showStaticPublishCommits = !showStaticPublishCommits;
      renderActivityPage();
      return;
    }
    document.querySelectorAll("#act-filters .chip").forEach(c => c.classList.toggle("active", c === chip));
    curActivityFilter = chip.dataset.af;
    renderActivityPage();
    return;
  }
  const diffBtn = e.target.closest(".btn-act-diff");
  if (diffBtn) {
    const card = diffBtn.closest(".act-card");
    if (!card) return;
    const diffBox = card.querySelector(".act-diff-box");
    const textSpan = diffBtn.querySelector(".act-diff-text");
    if (!diffBox) return;

    if (!diffBox.hidden) {
      diffBox.hidden = true;
      diffBtn.classList.remove("active");
      if (textSpan) textSpan.textContent = t("act_diff_local");
      return;
    }

    diffBox.hidden = false;
    diffBtn.classList.add("active");
    if (textSpan) textSpan.textContent = t("act_diff_close");
    const codeEl = diffBox.querySelector("code");
    if (codeEl && !codeEl.textContent) {
      codeEl.textContent = t("act_diff_loading");
      const repo = diffBtn.dataset.repo;
      const sha = diffBtn.dataset.sha;
      try {
        const resp = await fetch(`/api/commitdiff?repo=${encodeURIComponent(repo)}&sha=${encodeURIComponent(sha)}`);
        const data = await resp.json();
        if (data && data.ok && data.diff) {
          codeEl.innerHTML = formatDiff(data.diff);
        } else {
          codeEl.textContent = (data && data.error) || "Failed to load diff";
        }
      } catch (err) {
        codeEl.textContent = "Error fetching diff: " + err.message;
      }
    }
    return;
  }
});

// ==========================================================================
// --- Tmux 会话中枢与全屏/沉浸式终端 ---
// ==========================================================================
let tmuxHubCache = { t: 0, data: null };
let curTmuxFilter = "all";
const tmuxActiveWins = {};  // session -> active window index
const tmuxShowTerm = {};    // session -> boolean (default true)

// 沉浸式终端状态
let curTmuxSheet = {
  sname: "",
  target: "",
  lines: 300,
  live: true,
  timer: null,
  userScrolledUp: false
};

// 极轻量级 ANSI 终端转义序列解析器 (带状态重置与基础 16 色高保真还原)
function parseAnsiToHtml(raw) {
  if (!raw) return "";
  const esc = escHtml(raw);
  const re = /\x1b\[([0-9;]*)m/g;
  let activeClasses = [];
  let out = "";
  let lastIdx = 0;
  let match;

  const codeMap = {
    1: "ansi-bold", 2: "ansi-dim", 3: "ansi-italic", 4: "ansi-underline",
    30: "ansi-fg-black", 31: "ansi-fg-red", 32: "ansi-fg-green", 33: "ansi-fg-yellow",
    34: "ansi-fg-blue", 35: "ansi-fg-magenta", 36: "ansi-fg-cyan", 37: "ansi-fg-white",
    90: "ansi-fg-bright-black", 91: "ansi-fg-bright-red", 92: "ansi-fg-bright-green", 93: "ansi-fg-bright-yellow",
    94: "ansi-fg-bright-blue", 95: "ansi-fg-bright-magenta", 96: "ansi-fg-bright-cyan", 97: "ansi-fg-bright-white",
    40: "ansi-bg-black", 41: "ansi-bg-red", 42: "ansi-bg-green", 43: "ansi-bg-yellow",
    44: "ansi-bg-blue", 45: "ansi-bg-magenta", 46: "ansi-bg-cyan", 47: "ansi-bg-white"
  };

  while ((match = re.exec(esc)) !== null) {
    const textChunk = esc.slice(lastIdx, match.index);
    if (textChunk) {
      if (activeClasses.length > 0) {
        out += `<span class="${activeClasses.join(" ")}">${textChunk}</span>`;
      } else {
        out += textChunk;
      }
    }
    lastIdx = re.lastIndex;

    const codes = match[1] ? match[1].split(";").map(c => parseInt(c, 10)) : [0];
    for (const code of codes) {
      if (code === 0 || isNaN(code)) {
        activeClasses = [];
      } else if (code === 22) {
        activeClasses = activeClasses.filter(c => c !== "ansi-bold" && c !== "ansi-dim");
      } else if (code === 23) {
        activeClasses = activeClasses.filter(c => c !== "ansi-italic");
      } else if (code === 24) {
        activeClasses = activeClasses.filter(c => c !== "ansi-underline");
      } else if (code === 39) {
        activeClasses = activeClasses.filter(c => !c.startsWith("ansi-fg-"));
      } else if (code === 49) {
        activeClasses = activeClasses.filter(c => !c.startsWith("ansi-bg-"));
      } else if (codeMap[code]) {
        if (code >= 30 && code <= 37 || code >= 90 && code <= 97) {
          activeClasses = activeClasses.filter(c => !c.startsWith("ansi-fg-"));
        } else if (code >= 40 && code <= 47) {
          activeClasses = activeClasses.filter(c => !c.startsWith("ansi-bg-"));
        }
        activeClasses.push(codeMap[code]);
      }
    }
  }

  const remaining = esc.slice(lastIdx);
  if (remaining) {
    if (activeClasses.length > 0) {
      out += `<span class="${activeClasses.join(" ")}">${remaining}</span>`;
    } else {
      out += remaining;
    }
  }

  // 清除其他非常见控制序列如光标跳转等
  return out.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
}

async function fetchTmuxPaneCapture(target, lines) {
  if (BOOT.static) {
    return { ok: true, raw: t("static_term_blocked"), total_lines: 1 };
  }
  try {
    const url = `/api/tmux/capture?target=${encodeURIComponent(target)}&lines=${encodeURIComponent(lines || 300)}&ansi=1`;
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.json();
  } catch (err) {
    return { ok: false, msg: err.message };
  }
}

// --- Tailscale 组网与服务中枢 (Tailscale Network & Services Hub) ---
let tsCache = { t: 0, data: null };

async function fetchTailscaleData(force) {
  if (BOOT.static) return { ok: false, static: true };
  const now = Date.now();
  if (!force && tsCache.data && now - tsCache.t < 6000) return tsCache.data;
  try {
    const r = await fetch("/api/tailscale", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    tsCache = { t: now, data: d };
    return d;
  } catch (err) {
    console.error("tailscale fetch failed", err);
    return tsCache.data || { ok: false, error: err.message };
  }
}

function fmtBytes(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
}

async function renderNetworkPage(force) {
  const np = $("network-page");
  if (!np) return;

  const data = await fetchTailscaleData(force);
  if (!data || !data.ok) {
    const list = $("ts-peers-list");
    const msg = (data && data.static)
      ? t("static_ts_blocked")
      : `${t("a_none")}: ${escHtml(data?.error || "Tailscale not running")}`;
    if (list) list.innerHTML = `<div class="gempty">${msg}</div>`;
    return;
  }

  // 1. 本机 Self 卡片
  const selfCard = $("ts-self-card");
  if (selfCard && data.self) {
    const s = data.self;
    const isRunning = data.backend_state === "Running";
    const ipsHtml = (s.ips || []).map(ip =>
      `<span class="ts-ip-chip gcopy" data-copy="${escAttr(ip)}" title="${t("ts_copy_ip")}">
         ${escHtml(ip)} ${icon("copy", 10)}
       </span>`
    ).join("");

    selfCard.innerHTML = `
      <div class="ts-self-top">
        <div class="ts-self-title">
          <span>${icon("home", 15)}</span>
          <span>${escHtml(s.hostname)}</span>
          <span class="ts-os-badge">${escHtml(s.os)}</span>
          <span class="ts-badge ${isRunning ? 'running' : ''}">${isRunning ? icon("ok", 11) + " " + t("ts_status_running") : t("ts_status_stopped")}</span>
        </div>
        ${data.version ? `<span class="ghint">v${escHtml(data.version.split('-')[0])}</span>` : ''}
      </div>
      <div class="ts-self-ips">${ipsHtml}</div>
      ${s.dns_name ? `
        <div class="ts-dns-text">
          <span>${icon("ext", 11)}</span>
          <span class="gcopy" data-copy="https://${escAttr(s.dns_name)}" title="${t("g_copy")}">${escHtml(s.dns_name)}</span>
        </div>` : ''}
    `;
  }

  // 2. Serve 代理服务
  const srvGrid = $("ts-serve-grid");
  const srvCount = $("ts-serve-count");
  const srvServices = data.serve?.services || [];
  if (srvCount) srvCount.textContent = `(${srvServices.length})`;
  if (srvGrid) {
    if (!srvServices.length) {
      srvGrid.innerHTML = `<div class="gempty" style="grid-column: 1/-1;">${t("a_none")}</div>`;
    } else {
      srvGrid.innerHTML = srvServices.map(srv => {
        return `
          <div class="ts-serve-card">
            <div class="ts-serve-info">
              <div class="ts-serve-path" title="${escAttr(srv.url)}">${escHtml(srv.path || "/")}</div>
              <div class="ts-serve-proxy">${t("ts_serve_proxy_to")} <code>${escHtml(srv.target)}</code> (${escHtml(srv.host_port || '')})</div>
            </div>
            <div class="ts-serve-btns">
              <a href="${escAttr(srv.url)}" target="_blank" rel="noopener noreferrer" class="btn-ts-mini">
                ${icon("ext", 11)} <span>${t("ts_open")}</span>
              </a>
              <button type="button" class="btn-ts-mini gcopy" data-copy="${escAttr(srv.url)}" title="${t("g_copy")}">
                ${icon("copy", 11)}
              </button>
            </div>
          </div>
        `;
      }).join("");
    }
  }

  // 3. 已连 Peers 设备列表
  const peersList = $("ts-peers-list");
  const peersCount = $("ts-peers-count");
  const peers = data.peers || [];
  if (peersCount) peersCount.textContent = `(${peers.length})`;
  if (peersList) {
    if (!peers.length) {
      peersList.innerHTML = `<div class="gempty">${t("a_none")}</div>`;
    } else {
      peersList.innerHTML = peers.map(p => {
        const ip = (p.ips && p.ips[0]) || "";
        const online = p.online;
        const direct = p.direct;

        let connBadge = "";
        if (direct && p.cur_addr) {
          connBadge = `<span class="ts-conn-pill direct">${icon("bolt", 10)} ${t("ts_direct")} · ${escHtml(p.cur_addr)}</span>`;
        } else if (p.relay) {
          connBadge = `<span class="ts-conn-pill relay">🌐 ${t("ts_relay")} (${escHtml(p.relay)})</span>`;
        } else if (online) {
          connBadge = `<span class="ts-conn-pill direct">${t("ts_online")}</span>`;
        } else {
          connBadge = `<span class="ts-conn-pill offline">${t("ts_offline")}</span>`;
        }

        const trafficText = (p.tx_bytes || p.rx_bytes) ?
          `↑ ${fmtBytes(p.tx_bytes)} · ↓ ${fmtBytes(p.rx_bytes)}` : "";

        return `
          <div class="ts-peer-card" data-peer-ip="${escAttr(ip)}" data-peer-host="${escAttr(p.hostname)}">
            <div class="ts-peer-header">
              <div class="ts-peer-name">
                <span>${escHtml(p.hostname)}</span>
                <span class="ts-os-badge">${escHtml(p.os)}</span>
              </div>
              <div>${connBadge}</div>
            </div>
            <div class="ts-peer-detail">
              <div class="ts-peer-ip">${escHtml(ip)}</div>
              ${trafficText ? `<div class="ts-peer-traffic">${trafficText}</div>` : ''}
            </div>
            <div class="ts-peer-actions">
              <button type="button" class="btn-ts-mini btn-peer-ping" data-peer="${escAttr(ip || p.hostname)}">
                ${icon("bolt", 11)} <span>${t("ts_ping")}</span>
              </button>
              <span class="ts-ping-res" hidden></span>
              <button type="button" class="btn-ts-mini gcopy" data-copy="${escAttr(ip)}" title="${t("ts_copy_ip")}">
                ${icon("copy", 11)} <span>${t("ts_copy_ip")}</span>
              </button>
              <button type="button" class="btn-ts-mini gcopy" data-copy="ssh tetsuya@${escAttr(ip)}" title="${t("ts_copy_ssh")}">
                ${icon("term", 11)} <span>${t("ts_copy_ssh")}</span>
              </button>
            </div>
          </div>
        `;
      }).join("");
    }
  }
}

// --- Tailscale 事件委托 (Netcheck, Ping, Refresh) ---
document.addEventListener("click", async (e) => {
  // 刷新网络面板
  const refBtn = e.target.closest("#btn-ts-refresh");
  if (refBtn) {
    haptic(8);
    refBtn.disabled = true;
    try { await renderNetworkPage(true); } finally { setTimeout(() => refBtn.disabled = false, 800); }
    return;
  }

  // 运行 Netcheck 网络穿透诊断
  if (e.target.closest("#btn-ts-netcheck")) {
    const card = $("ts-netcheck-card");
    if (!card) return;
    card.hidden = false;
    if (BOOT.static) {
      card.innerHTML = `<div class="gempty">${icon("wait", 14)} ${t("static_ts_blocked")}</div>`;
      return;
    }
    card.innerHTML = `<div class="gempty">${icon("wait", 14)} ${t("ts_diag_loading")}</div>`;
    haptic(8);
    try {
      const r = await tlPost("/api/tailscale/netcheck", {});
      if (r && r.ok) {
        card.innerHTML = `
          <div class="ts-self-title" style="margin-bottom:8px;">
            <span>${icon("activity", 14)}</span> <span>${t("ts_diag_title")}</span>
          </div>
          <div class="ts-diag-grid">
            <div class="ts-diag-item">
              <div class="ts-diag-label">${t("ts_diag_udp")}</div>
              <div class="ts-diag-val ${r.udp ? 'ok' : 'warn'}">${r.udp ? t("ts_diag_ok") : t("ts_diag_limited")}</div>
            </div>
            <div class="ts-diag-item">
              <div class="ts-diag-label">IPv4 / IPv6</div>
              <div class="ts-diag-val ok">${r.ipv4 ? 'v4' : ''} ${r.ipv6 ? '· v6' : ''}</div>
            </div>
            <div class="ts-diag-item">
              <div class="ts-diag-label">${t("ts_diag_upnp")}</div>
              <div class="ts-diag-val ${r.upnp ? 'ok' : ''}">${r.upnp ? t("ts_diag_yes") : t("ts_diag_no")}</div>
            </div>
            <div class="ts-diag-item">
              <div class="ts-diag-label">${t("ts_diag_derp")}</div>
              <div class="ts-diag-val ok">Region ${r.preferred_derp || '-'} (${r.preferred_derp_latency_ms || '-'} ms)</div>
            </div>
          </div>
        `;
      } else {
        card.innerHTML = `<div class="gempty" style="color:var(--c-red);">${t("ts_diag_fail", { e: escHtml(r?.error || "Netcheck error") })}</div>`;
      }
    } catch (err) {
      card.innerHTML = `<div class="gempty" style="color:var(--c-red);">${t("ts_diag_fail", { e: escHtml(err.message) })}</div>`;
    }
    return;
  }

  // Peer 节点 Ping 测速
  const pingBtn = e.target.closest(".btn-peer-ping");
  if (pingBtn) {
    const peer = pingBtn.dataset.peer;
    const card = pingBtn.closest(".ts-peer-card");
    const resEl = card ? card.querySelector(".ts-ping-res") : null;
    if (!peer || !resEl) return;
    pingBtn.disabled = true;
    resEl.hidden = false;
    resEl.className = "ts-ping-res";
    resEl.textContent = t("ts_pinging");
    haptic(6);
    try {
      const r = await tlPost("/api/tailscale/ping", { peer });
      if (r && r.ok && r.rtt_ms !== null) {
        const mode = r.direct ? t("ts_direct") : (r.via || t("ts_relay"));
        resEl.textContent = `${r.rtt_ms} ms (${mode})`;
      } else {
        resEl.className = "ts-ping-res err";
        resEl.textContent = t("ts_ping_timeout");
      }
    } catch (_) {
      resEl.className = "ts-ping-res err";
      resEl.textContent = t("ts_ping_error");
    } finally {
      pingBtn.disabled = false;
    }
    return;
  }
});

async function fetchTmuxData(force) {
  const now = Date.now();
  if (BOOT.static && BOOT.tmuxData) return BOOT.tmuxData;
  if (!force && tmuxHubCache.data && now - tmuxHubCache.t < 4000) return tmuxHubCache.data;
  try {
    const r = await fetch("/api/tmux", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    tmuxHubCache = { t: now, data: d };
    snapSet("tmux", d);
  } catch (err) {
    console.error("tmux refresh failed", err);
    if (!tmuxHubCache.data) tmuxHubCache.data = snapGet("tmux");
  }
  return tmuxHubCache.data;
}

async function renderTmuxPage() {
  const tp = $("tmux-panel");
  if (!tp) return;
  const body = $("tmux-body");
  if (!body) return;

  const data = await fetchTmuxData();
  if (!data || !data.sessions) {
    body.innerHTML = `<div class="gempty">${escHtml(t("tmux_empty"))}</div>`;
    return;
  }

  const { sessions, summary } = data;

  // 1. 顶部汇总卡片
  const statsEl = $("tmux-stats");
  if (statsEl && summary) {
    const totalWins = sessions.reduce((acc, s) => acc + (s.windows_count || (s.windows ? s.windows.length : 1)), 0);
    statsEl.innerHTML = `
      <div class="tmux-stat-card">
        <div class="tmux-stat-val">${summary.total || sessions.length}</div>
        <div class="tmux-stat-lbl">${escHtml(t("tmux_total_sessions"))}</div>
      </div>
      <div class="tmux-stat-card">
        <div class="tmux-stat-val" style="color:#38bdf8;">${totalWins}</div>
        <div class="tmux-stat-lbl">${escHtml(t("tmux_total_windows"))}</div>
      </div>
      <div class="tmux-stat-card">
        <div class="tmux-stat-val" style="color:#a78bfa;">${summary.panes_total || 0}</div>
        <div class="tmux-stat-lbl">${escHtml(t("tmux_total_panes"))}</div>
      </div>
      <div class="tmux-stat-card">
        <div class="tmux-stat-val" style="color:#4ade80;">${summary.attached} <small>/ ${summary.detached}</small></div>
        <div class="tmux-stat-lbl">${escHtml(t("tmux_attached"))} / ${escHtml(t("tmux_detached"))}</div>
      </div>
      <div class="tmux-stat-card">
        <div class="tmux-stat-val" style="color:#fbbf24;">${summary.agents}</div>
        <div class="tmux-stat-lbl">${escHtml(t("tmux_agents"))}</div>
      </div>
    `;
  }

  // 2. 筛选条计数
  const nAll = $("n-tf-all"), nAgent = $("n-tf-agent"), nAtt = $("n-tf-attached"), nDet = $("n-tf-detached");
  if (nAll) nAll.textContent = `(${sessions.length})`;
  if (nAgent) nAgent.textContent = `(${sessions.filter(s => s.is_agent).length})`;
  if (nAtt) nAtt.textContent = `(${sessions.filter(s => s.attached).length})`;
  if (nDet) nDet.textContent = `(${sessions.filter(s => !s.attached).length})`;
  const nRes = $("n-tf-resumable"), nSt = $("n-tf-standalone");
  if (nRes) nRes.textContent = `(${sessions.filter(s => s.goal && s.goal.resume_cmd).length})`;
  if (nSt) nSt.textContent = `(${sessions.filter(s => !s.is_agent).length})`;

  // 3. 过滤 sessions
  const filtered = sessions.filter(s => {
    if (curTmuxFilter === "agent" && !s.is_agent) return false;
    if (curTmuxFilter === "resumable" && !(s.goal && s.goal.resume_cmd)) return false;
    if (curTmuxFilter === "standalone" && s.is_agent) return false;
    if (curTmuxFilter === "attached" && !s.attached) return false;
    if (curTmuxFilter === "detached" && s.attached) return false;
    return true;
  });

  if (!filtered.length) {
    body.innerHTML = `<div class="gempty">${escHtml(t("tmux_empty"))}</div>`;
    return;
  }

  // 4. 渲染会话卡片
  body.innerHTML = filtered.map(s => {
    const isAtt = s.attached;
    const isAgent = s.is_agent;
    const dotClass = isAtt ? "attached" : (isAgent ? "agent" : "detached");
    const attBadge = isAtt ?
      `<span class="tmux-badge tmux-badge-att">${escHtml(t("tmux_attached"))}</span>` :
      `<span class="tmux-badge tmux-badge-det">${escHtml(t("tmux_detached"))}</span>`;
    const agentBadge = isAgent ?
      `<span class="tmux-badge tmux-badge-agent">${icon("bot", 11)} ${escHtml(t("tmux_filter_agent"))}</span>` : "";

    let repoBadge = "";
    if (s.repo && s.repo !== "—") {
      const theme = getRepoTheme(s.repo);
      repoBadge = `<span class="tmux-badge tmux-badge-repo" style="background:${theme.color};">${escHtml(s.repo)}</span>`;
    }

    const wins = s.windows || [];
    let curWinIdx = tmuxActiveWins[s.name];
    if (curWinIdx === undefined) {
      const activeWin = wins.find(w => w.active) || wins[0];
      curWinIdx = activeWin ? activeWin.index : 1;
      tmuxActiveWins[s.name] = curWinIdx;
    }
    const curWin = wins.find(w => w.index === curWinIdx) || wins[0] || { panes: [] };

    const tabsHtml = wins.length > 0 ? `
      <div class="tmux-tabs-bar">
        ${wins.map(w => {
          const isSelected = w.index === curWinIdx;
          const star = w.active ? `<span class="tmux-tab-star" title="${t("tmux_active_win")}">*</span>` : "";
          return `<span class="tmux-tab-chip ${isSelected ? 'active' : ''}" data-sname="${escAttr(s.name)}" data-widx="${w.index}">
            ${w.index}: ${escHtml(w.name)}${star}
          </span>`;
        }).join("")}
      </div>` : "";

    const panes = curWin.panes || [];
    const activePane = panes.find(p => p.active) || panes[0] || {};

    const panesHtml = panes.map(p => {
      const pcmd = (p.command || "term").toLowerCase();
      return `
        <div class="tmux-pane-row">
          <div class="tmux-pane-left">
            <span class="tmux-cmd-badge ${escAttr(pcmd)}">${escHtml(p.command || '—')}</span>
            <span class="tmux-pane-title" title="${escAttr(p.title || '')}">${escHtml(p.title || '—')}</span>
          </div>
          <div class="tmux-pane-meta">
            <span>PID ${escHtml(p.pid || '—')}</span> · <span>${escHtml(p.size || '—')}</span>
          </div>
        </div>
      `;
    }).join("");

    const showTerm = tmuxShowTerm[s.name] !== false;
    const termLines = (activePane.preview || []).slice(-12);
    const termText = termLines.length ? termLines.join("\n") : t("tmux_no_output");
    const termHtml = showTerm ? `
      <div class="tmux-term-preview">
        <div class="tmux-term-topbar">
          <div class="tmux-term-dots"><span></span><span></span><span></span></div>
          <span>${escHtml(s.name)} : ${curWin.index}.${activePane.index || 1} · ${escHtml(activePane.command || '')}</span>
          <span>${escHtml(activePane.size || '')}</span>
        </div>
        <pre class="tmux-term-pre"><code>${escHtml(termText)}</code></pre>
      </div>
    ` : "";

    let goalBanner = "";
    if (s.goal) {
      const g = s.goal;
      goalBanner = `
        <div class="tmux-goal-banner">
          <div class="tmux-goal-banner-left">
            ${icon("target", 13)} <b>${escHtml(t("tmux_linked_goal"))}</b>
            <span class="tmux-goal-banner-obj">${escHtml(g.objective || g.label || g.gid)}</span>
          </div>
          ${g.resume_cmd ? `
            <div class="tmux-goal-banner-acts">
              <button class="btn-tmux-act g-resume-btn" data-resume-cmd="${escAttr(g.resume_cmd)}" title="${t("tmux_resume_bg_title")}">
                ${icon("play", 11)} <span>${escHtml(t("g_resume_run"))}</span>
              </button>
              <button class="btn-tmux-act gcopy" data-copy="${escAttr(g.resume_cmd)}" title="${escAttr(t("g_copy"))}">
                ${icon("copy", 11)} <span>${escHtml(t("g_copy"))}</span>
              </button>
            </div>
          ` : ""}
        </div>
      `;
    }

    const agoTxt = agoStr(s.activity_ago);

    return `
      <article class="tmux-session-card" data-sname="${escAttr(s.name)}">
        <div class="tmux-card-top">
          <div class="tmux-card-title-wrap">
            <span class="tmux-status-dot ${dotClass}" title="${isAtt ? 'Attached' : 'Detached'}"></span>
            <span class="tmux-sname">${escHtml(s.name)}</span>
            ${attBadge}
            ${agentBadge}
            ${repoBadge}
            <span class="tmux-badge tmux-badge-det">${s.windows_count} ${escHtml(t("tmux_total_windows"))}</span>
          </div>
          <div class="tmux-card-actions">
            <button class="btn-tmux-act btn-tmux-wake" data-sname="${escAttr(s.name)}" data-target="${escAttr(activePane.pane ? `${s.name}:${activePane.pane}` : s.name)}" title="${escAttr(t("tmux_wake_title"))}">
              ${icon("bolt", 12)} <span>${escHtml(t("tmux_wake"))}</span>
            </button>
            <button class="btn-tmux-act btn-tmux-fullscreen" data-sname="${escAttr(s.name)}" data-target="${escAttr(activePane.pane ? `${s.name}:${activePane.pane}` : s.name)}" title="${escAttr(t('tmux_fullscreen'))}">
              ${icon("expand", 12)} <span>${escHtml(t("tmux_fullscreen"))}</span>
            </button>
            <button class="btn-tmux-act btn-tmux-term-toggle ${showTerm ? 'active' : ''}" data-sname="${escAttr(s.name)}" title="${escAttr(t('tmux_term_toggle'))}">
              ${icon("term", 12)} <span>${escHtml(showTerm ? t("tmux_term_hide") : t("tmux_term_toggle"))}</span>
            </button>
            <button class="btn-tmux-act btn-tmux-copy-attach gcopy" data-copy="${escAttr(s.attach_cmd)}" title="${escAttr(t('tmux_copy_attach'))}">
              ${icon("copy", 12)} <span>attach</span>
            </button>
            <button class="btn-tmux-act btn-tmux-kill danger" data-sname="${escAttr(s.name)}" title="${escAttr(t('tmux_kill_session'))}">
              ${icon("close", 12)} <span>${escHtml(t("tmux_kill"))}</span>
            </button>
          </div>
        </div>
        <div class="tmux-meta-bar">
          <span class="tmux-meta-item">${icon("clock", 12)} <span>${escHtml(s.created_str)} (${agoTxt})</span></span>
          <span class="tmux-meta-item">${icon("folder", 12)} <code>${escHtml(s.main_cwd)}</code></span>
        </div>
        ${tabsHtml}
        ${panesHtml}
        ${termHtml}
        ${goalBanner}
      </article>
    `;
  }).join("");
}

// 全屏沉浸式终端控制器
async function openTmuxSheet(sname, target) {
  const sheet = $("tmux-term-sheet");
  if (!sheet) return;

  // 优先用已有缓存立即开窗(内容本身由 capture 接口拉取), 无缓存才阻塞请求, 避免并发扫描卡顿
  const data = (tmuxHubCache.data && tmuxHubCache.data.sessions) ? tmuxHubCache.data : await fetchTmuxData();
  const session = (data && data.sessions) ? data.sessions.find(s => s.name === sname) : null;
  const initialTarget = target || (session ? `${session.name}:${session.windows?.[0]?.index || 1}` : sname);

  curTmuxSheet.sname = sname;
  curTmuxSheet.target = initialTarget;
  curTmuxSheet.userScrolledUp = false;

  const titleEl = $("tmux-sheet-title");
  const subEl = $("tmux-sheet-sub");
  const dotEl = $("tmux-sheet-dot");
  const badgeEl = $("tmux-sheet-pane-badge");
  const tabsEl = $("tmux-sheet-tabs");
  const linesSel = $("tmux-sheet-lines");

  if (titleEl) titleEl.textContent = sname;
  if (subEl && session) subEl.textContent = `${session.main_cwd || ''} · ${session.main_command || ''}`;
  if (dotEl) {
    dotEl.className = "tmux-status-dot " + (session?.attached ? "attached" : (session?.is_agent ? "agent" : "detached"));
  }
  if (badgeEl) badgeEl.textContent = initialTarget;
  if (linesSel) linesSel.value = String(curTmuxSheet.lines || 300);

  // 渲染多窗口快速切换 Tabs
  if (tabsEl && session && session.windows && session.windows.length > 0) {
    tabsEl.innerHTML = session.windows.map(w => {
      const wTarget = `${session.name}:${w.index}`;
      const isActive = curTmuxSheet.target.startsWith(wTarget) || (curTmuxSheet.target === session.name && w.index === 1);
      return `<span class="tmux-sheet-tab ${isActive ? 'active' : ''}" data-target="${escAttr(wTarget)}">
        ${icon("term", 11)} <span>${w.index}: ${escHtml(w.name || 'win')}</span>
      </span>`;
    }).join("");
  } else if (tabsEl) {
    tabsEl.innerHTML = "";
  }

  sheet.hidden = false;
  sheet.classList.add("opening");
  document.documentElement.classList.add("traj-noscroll");

  // 初始拉取并启动轮询
  await refreshTmuxSheetOutput();
  startTmuxSheetLive();
}

function closeTmuxSheet() {
  const sheet = $("tmux-term-sheet");
  if (!sheet) return;
  sheet.hidden = true;
  document.documentElement.classList.remove("traj-noscroll");
  stopTmuxSheetLive();
}

async function refreshTmuxSheetOutput() {
  if (!curTmuxSheet.target) return;
  const pre = $("tmux-fullscreen-pre");
  if (!pre) return;
  const codeEl = pre.querySelector("code");

  const res = await fetchTmuxPaneCapture(curTmuxSheet.target, curTmuxSheet.lines);
  if (!res || !res.ok) {
    if (codeEl) codeEl.innerHTML = `<span style="color:#f87171;">${escHtml(res?.msg || "Failed to capture terminal")}</span>`;
    return;
  }

  const html = parseAnsiToHtml(res.raw || "");
  if (codeEl) codeEl.innerHTML = html || `<span style="color:#6e7681;">(no output)</span>`;

  const body = $("tmux-sheet-body");
  if (body && !curTmuxSheet.userScrolledUp) {
    body.scrollTop = body.scrollHeight;
  }
}

function startTmuxSheetLive() {
  stopTmuxSheetLive();
  if (!curTmuxSheet.live) return;
  curTmuxSheet.timer = setInterval(async () => {
    const sheet = $("tmux-term-sheet");
    if (!sheet || sheet.hidden || document.hidden) return;
    await refreshTmuxSheetOutput();
  }, 2500);
}

function stopTmuxSheetLive() {
  if (curTmuxSheet.timer) {
    clearInterval(curTmuxSheet.timer);
    curTmuxSheet.timer = null;
  }
}

// Tmux Hub 事件监听绑定 (一处绑定)
(function initTmuxPageEvents() {
  const tp = $("tmux-panel");
  if (!tp) return;

  const filterWrap = $("tmux-filters");
  if (filterWrap) {
    filterWrap.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip");
      if (!chip || !chip.dataset.tf) return;
      filterWrap.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      curTmuxFilter = chip.dataset.tf;
      renderTmuxPage();
    });
  }

  tp.addEventListener("click", (e) => {
    const fsBtn = e.target.closest(".btn-tmux-fullscreen");
    if (fsBtn && fsBtn.dataset.sname) {
      openTmuxSheet(fsBtn.dataset.sname, fsBtn.dataset.target);
      return;
    }

    const tabChip = e.target.closest(".tmux-tab-chip");
    if (tabChip && tabChip.dataset.sname && tabChip.dataset.widx) {
      tmuxActiveWins[tabChip.dataset.sname] = parseInt(tabChip.dataset.widx, 10);
      renderTmuxPage();
      return;
    }

    const termBtn = e.target.closest(".btn-tmux-term-toggle");
    if (termBtn && termBtn.dataset.sname) {
      const sname = termBtn.dataset.sname;
      tmuxShowTerm[sname] = tmuxShowTerm[sname] === false ? true : false;
      renderTmuxPage();
      return;
    }

    const copyBtn = e.target.closest(".btn-tmux-copy-attach");
    if (copyBtn && copyBtn.dataset.copy) {
      const cmd = copyBtn.dataset.copy;
      copyText(cmd, copyBtn);
      uiNotice(t("tmux_copied", { cmd }));
      return;
    }

    const killBtn = e.target.closest(".btn-tmux-kill");
    if (killBtn && killBtn.dataset.sname) {
      const sname = killBtn.dataset.sname;
      uiConfirm(t("tmux_kill_confirm", { sname })).then(async ok => {
        if (!ok) return;
        try {
          const r = await fetch("/api/tmux/kill", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Svc-Token": BOOT.token || "" },
            body: JSON.stringify({ session: sname })
          });
          const res = await r.json();
          if (res.ok) {
            uiNotice(t("tmux_killed") || "Session terminated");
            await fetchTmuxData(true);
            renderTmuxPage();
          } else {
            uiNotice(res.msg || "Kill failed");
          }
        } catch (err) {
          uiNotice("Error: " + err.message);
        }
      });
      return;
    }
  });

  // 绑定 Tmux 全屏终端交互
  const sheet = $("tmux-term-sheet");
  if (sheet) {
    const backBtn = $("tmux-sheet-back");
    if (backBtn) backBtn.addEventListener("click", closeTmuxSheet);

    const sheetKillBtn = $("btn-tmux-sheet-kill");
    if (sheetKillBtn) {
      sheetKillBtn.addEventListener("click", () => {
        if (!curTmuxSheet.sname) return;
        const sname = curTmuxSheet.sname;
        uiConfirm(t("tmux_kill_confirm", { sname })).then(async ok => {
          if (!ok) return;
          try {
            const r = await fetch("/api/tmux/kill", {
              method: "POST",
              headers: { "Content-Type": "application/json", "X-Svc-Token": BOOT.token || "" },
              body: JSON.stringify({ session: sname })
            });
            const res = await r.json();
            if (res.ok) {
              closeTmuxSheet();
              uiNotice(t("tmux_killed") || "Session terminated");
              await fetchTmuxData(true);
              renderTmuxPage();
            } else {
              uiNotice(res.msg || "Kill failed");
            }
          } catch (err) {
            uiNotice("Error: " + err.message);
          }
        });
      });
    }

    const liveBtn = $("btn-tmux-sheet-live");
    if (liveBtn) {
      liveBtn.addEventListener("click", () => {
        curTmuxSheet.live = !curTmuxSheet.live;
        const dot = liveBtn.querySelector(".tmux-live-dot");
        const txt = $("tmux-live-text");
        if (curTmuxSheet.live) {
          liveBtn.classList.remove("active");
          if (dot) dot.classList.add("on");
          if (txt) txt.textContent = t("tmux_live_on");
          startTmuxSheetLive();
          refreshTmuxSheetOutput();
        } else {
          liveBtn.classList.add("active");
          if (dot) dot.classList.remove("on");
          if (txt) txt.textContent = t("tmux_live_off");
          stopTmuxSheetLive();
        }
      });
    }

    const copyBtn = $("btn-tmux-sheet-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", () => {
        const pre = $("tmux-fullscreen-pre");
        if (pre) {
          copyText(pre.innerText || "", copyBtn);
          uiNotice(t("tmux_output_copied"));
        }
      });
    }

    const linesSel = $("tmux-sheet-lines");
    if (linesSel) {
      linesSel.addEventListener("change", (e) => {
        curTmuxSheet.lines = parseInt(e.target.value, 10) || 300;
        refreshTmuxSheetOutput();
      });
    }

    const tabsEl = $("tmux-sheet-tabs");
    if (tabsEl) {
      tabsEl.addEventListener("click", (e) => {
        const tab = e.target.closest(".tmux-sheet-tab");
        if (!tab || !tab.dataset.target) return;
        tabsEl.querySelectorAll(".tmux-sheet-tab").forEach(t => t.classList.remove("active"));
        tab.classList.add("active");
        curTmuxSheet.target = tab.dataset.target;
        const badgeEl = $("tmux-sheet-pane-badge");
        if (badgeEl) badgeEl.textContent = curTmuxSheet.target;
        refreshTmuxSheetOutput();
      });
    }

    const bodyEl = $("tmux-sheet-body");
    const scrollBtn = $("btn-tmux-sheet-scroll");
    if (bodyEl) {
      bodyEl.addEventListener("scroll", () => {
        const isNearBottom = (bodyEl.scrollHeight - bodyEl.scrollTop - bodyEl.clientHeight) < 60;
        curTmuxSheet.userScrolledUp = !isNearBottom;
        if (scrollBtn) {
          scrollBtn.hidden = isNearBottom;
        }
      });
    }

    if (scrollBtn && bodyEl) {
      scrollBtn.addEventListener("click", () => {
        bodyEl.scrollTop = bodyEl.scrollHeight;
        curTmuxSheet.userScrolledUp = false;
        scrollBtn.hidden = true;
      });
    }

    // 交互式终端输入与快速按键
    const termInput = $("tmux-term-input");
    const termSendBtn = $("btn-tmux-term-send");
    const sendTermInput = async () => {
      if (!termInput || !curTmuxSheet.target) return;
      const text = termInput.value;
      if (!text && text !== "") return;
      termInput.value = "";
      try {
        await fetch("/api/tmux/send", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Svc-Token": BOOT.token || "" },
          body: JSON.stringify({ target: curTmuxSheet.target, text, enter: true })
        });
        await refreshTmuxSheetOutput();
      } catch (err) {
        console.error("send error:", err);
      }
    };

    if (termInput) {
      termInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          sendTermInput();
        }
      });
    }
    if (termSendBtn) {
      termSendBtn.addEventListener("click", sendTermInput);
    }

    const sheetBar = $("tmux-sheet-bar");
    if (sheetBar) {
      sheetBar.addEventListener("click", async (e) => {
        const keyBtn = e.target.closest(".btn-term-key");
        if (!keyBtn || !curTmuxSheet.target) return;
        const key = keyBtn.dataset.key;
        const cmd = keyBtn.dataset.cmd;
        try {
          if (key) {
            await fetch("/api/tmux/send", {
              method: "POST",
              headers: { "Content-Type": "application/json", "X-Svc-Token": BOOT.token || "" },
              body: JSON.stringify({ target: curTmuxSheet.target, key })
            });
          } else if (cmd) {
            await fetch("/api/tmux/send", {
              method: "POST",
              headers: { "Content-Type": "application/json", "X-Svc-Token": BOOT.token || "" },
              body: JSON.stringify({ target: curTmuxSheet.target, text: cmd, enter: true })
            });
          }
          await refreshTmuxSheetOutput();
        } catch (err) {
          console.error("key send error:", err);
        }
      });
    }

    // ESC 关闭
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !sheet.hidden) {
        closeTmuxSheet();
      }
    });
  }

  // 新建任务弹层：左边执行者 / 右边 Issue 正文，创建即派发到 chezmoi 的 Issue
  const newOpenBtn = $("btn-tmux-new-open");
  const newModal = $("tmux-new-modal");
  const newCloseBtn = $("btn-tmux-new-close");
  const newCancelBtn = $("btn-tmux-new-cancel");
  const newSubmitBtn = $("btn-tmux-new-submit");
  const agentGrid = $("tmux-new-agent-grid");
  const hostChips = $("nt-host-chips");
  const titleInput = $("nt-title");
  const bodyInput = $("nt-body");

  let ntAgent = "hermes";
  let ntHost = "";

  async function ntLoadHosts() {
    if (!hostChips) return;
    hostChips.innerHTML = `<span class="chip">…</span>`;
    const d = await thGet("/api/th/hosts").catch(() => ({ ok: false }));
    const hosts = ((d && d.hosts) || []).filter(h => h.online !== false);
    ntHost = ntHost || (d && d.default) || (hosts[0] || {}).id || "";
    hostChips.innerHTML = hosts.map(h =>
      `<span class="chip ${h.id === ntHost ? "active" : ""}" data-host="${escAttr(h.id)}">${escHtml(h.label || h.id)}</span>`
    ).join("") || `<span class="chip">—</span>`;
  }

  const closeNewModal = () => { if (newModal) newModal.hidden = true; };

  if (newOpenBtn && newModal) {
    newOpenBtn.addEventListener("click", () => {
      newModal.hidden = false;
      ntLoadHosts();
      setTimeout(() => titleInput && titleInput.focus(), 60);
    });
  }
  if (newCloseBtn) newCloseBtn.addEventListener("click", closeNewModal);
  if (newCancelBtn) newCancelBtn.addEventListener("click", closeNewModal);
  if (newModal) newModal.addEventListener("click", e => { if (e.target === newModal) closeNewModal(); });

  if (agentGrid) {
    agentGrid.addEventListener("click", e => {
      const card = e.target.closest(".nt-agent");
      if (!card) return;
      agentGrid.querySelectorAll(".nt-agent").forEach(c => c.classList.remove("active"));
      card.classList.add("active");
      ntAgent = card.dataset.agent;
    });
  }
  if (hostChips) {
    hostChips.addEventListener("click", e => {
      const chip = e.target.closest(".chip[data-host]");
      if (!chip) return;
      hostChips.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      ntHost = chip.dataset.host;
    });
  }
  if (bodyInput) {
    bodyInput.addEventListener("keydown", e => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); newSubmitBtn && newSubmitBtn.click(); }
    });
  }

  if (newSubmitBtn) {
    newSubmitBtn.addEventListener("click", async () => {
      const title = (titleInput && titleInput.value.trim()) || "";
      const body = (bodyInput && bodyInput.value.trim()) || "";
      if (!title) { uiNotice(t("nt_need_title") || `请先写标题`); titleInput && titleInput.focus(); return; }
      newSubmitBtn.disabled = true;
      const origText = newSubmitBtn.innerHTML;
      newSubmitBtn.innerHTML = `${icon("wait", 14)} <span>...</span>`;
      try {
        const r = await apiPost("/api/th/new", { title, body, agent: ntAgent, host: ntHost });
        const d = await r.json().catch(() => ({ ok: false, msg: "bad json" }));
        if (!d.ok) { uiNotice(d.msg || `创建失败`); return; }
        closeNewModal();
        if (titleInput) titleInput.value = "";
        if (bodyInput) bodyInput.value = "";
        TH.health = null;
        if (d.needs_repo) uiNotice(`#${d.number} 已创建 · 在 Telegram 里确认仓库后自动开始`);
        else uiNotice(`#${d.number} 已派发 · ${ntAgent} @ ${ntHost || `默认机器`}`);
        await thRenderTasks();
        if (d.number) thOpenTask(d.number, true);
      } catch (err) {
        uiNotice("Error: " + err.message);
      } finally {
        newSubmitBtn.disabled = false;
        newSubmitBtn.innerHTML = origText;
      }
    });
  }
})();

// --- 日志页: 全局事件时间线(筛选 chips + 同goal循环折叠 + 详情默认折叠) ---
const logFilter = { st: "all", src: "all", hrs: 24 };
function filterEvents(evs) {
  const now = Date.now() / 1000;
  return (evs || []).filter(e => {
    if (isStaticPublishCommit(e)) return false;
    if (logFilter.hrs && e.ts < now - logFilter.hrs * 3600) return false;
    if (logFilter.src === "commit") { if (e.kind !== "commit") return false; }
    else if (logFilter.src !== "all" && e.src !== logFilter.src) return false;
    if (logFilter.st !== "all" && (EV_META[e.kind] || EV_META.other).grp !== logFilter.st) return false;
    return true;
  });
}
function lvHead(e, extra) {
  const m = EV_META[e.kind] || EV_META.other;
  return `<div class="lv-line1"><span class="lv-ico">${icon(m.ico, 14)}</span>` +
    `<span class="lv-kind">${escHtml(t(m.key))}</span>` +
    `<span class="rc-name">${escHtml(e.name)}</span>${extra || ""}` +
    `<span class="lv-ago">${escHtml(agoFromTs(e.ts))}</span></div>`;
}
function evSummary(e) { return e.src === "done" ? String(e.text).split("/").pop() : e.text; }
async function renderLogTimeline() {
  const body = $("logbody");
  if (!body) return;
  body.innerHTML = `<div class="gempty">${t("a_loading")}</div>`;
  const d = await fetchGoalsData();
  const evs = filterEvents(d && d.events);
  if (!evs.length) { body.innerHTML = esHtml("clock", t("ev_empty")); return; }
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
      html += `<div class="lv lv-${(EV_META[head.kind] || EV_META.other).grp}">${lvHead(head, `<span class="lv-loop">${t("ev_loop", { n: g.items.length })}</span>`)}` +
        `<div class="lv-line2">${escHtml(evSummary(head))}</div>` +
        `<span class="lv-fold" role="button" tabindex="0">${t("g_detail")}</span>` +
        `<div class="lv-meta">${g.items.map(x => escHtml(x.time + " · " + x.gid + " · " + x.text)).join("<br>")}</div>` +
        `<div class="lv-children">${g.items.slice(0, 12).map(x =>
          lvHead(x) + `<div class="lv-line2">${escHtml(evSummary(x))}</div>`).join("")}` +
        `${g.items.length > 12 ? `<div class="lv-more">… ${g.items.length - 12}</div>` : ""}</div></div>`;
    } else {
      html += g.items.map(e => `<div class="lv lv-${(EV_META[e.kind] || EV_META.other).grp}">${lvHead(e)}` +
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

// --- 原生 App 级移动端下拉刷新控制器 (Pull-to-Refresh Controller) ---
const ptrController = (function setupPullToRefresh() {
  const touchCapable = ("ontouchstart" in window) || navigator.maxTouchPoints > 0;
  const indicator = $("ptr-indicator");
  const ring = indicator ? indicator.querySelector(".ptr-ring circle") : null;
  const core = indicator ? indicator.querySelector(".ptr-core") : null;
  const main = document.querySelector("main");

  if (!indicator || !ring || !core) return null;

  const CIRC = 2 * Math.PI * 16.5; // ~103.67
  const THRESHOLD = 56;
  const MAX_PULL = 78;
  const HOLD_Y = 46;

  // 状态机常量: 0=空闲, 1=判定死区, 2=下拉中, 3=刷新中
  const STATE_IDLE = 0;
  const STATE_PENDING = 1;
  const STATE_PULLING = 2;
  const STATE_REFRESHING = 3;

  let state = STATE_IDLE;
  let startX = 0, startY = 0;
  let pull = 0, rawDistance = 0;
  let hasHaptic = false;
  let resetTimer = null;

  const isAtTop = () => {
    const mainTop = main ? main.scrollTop : 0;
    return mainTop <= 0 && (window.scrollY || document.documentElement.scrollTop || 0) <= 0;
  };

  const isInteractiveTarget = (el) => {
    if (!el || !el.closest) return false;
    return !!el.closest("input, textarea, select, [contenteditable='true'], .ui-modal, .lightbox, pre, code");
  };

  const hasScrollableUpwardAncestor = (el) => {
    let cur = el;
    while (cur && cur !== main && cur !== document.body && cur !== document.documentElement) {
      if (cur.scrollTop > 0) {
        const style = window.getComputedStyle(cur);
        const oy = style.overflowY;
        if (oy === "auto" || oy === "scroll") return true;
      }
      cur = cur.parentElement;
    }
    return false;
  };

  const applyVisuals = (pullY) => {
    pull = pullY;
    const scale = Math.min(1, 0.72 + (pull / MAX_PULL) * 0.28);
    indicator.style.transform = `translate3d(-50%, ${pull}px, 0) scale(${scale})`;
    indicator.classList.toggle("on", pull > 4);

    const isReady = pull >= THRESHOLD;
    indicator.classList.toggle("ready", isReady);

    if (isReady && !hasHaptic) {
      haptic(10);
      hasHaptic = true;
    } else if (!isReady && hasHaptic) {
      hasHaptic = false;
    }

    const prog = Math.min(1, pull / THRESHOLD);
    ring.style.strokeDashoffset = String(CIRC * (1 - prog));
    core.style.transform = `rotate(${prog * 180}deg)`;
  };

  const resetVisuals = (immediate = false) => {
    clearTimeout(resetTimer);
    pull = 0;
    rawDistance = 0;
    hasHaptic = false;
    indicator.classList.remove("on", "pulling", "ready", "loading");

    if (immediate) {
      indicator.style.transition = "none";
      indicator.style.transform = "";
      ring.style.strokeDashoffset = String(CIRC);
      core.style.transform = "";
      state = STATE_IDLE;
    } else {
      indicator.style.transition = "transform .28s cubic-bezier(0.2, 0, 0, 1), opacity .2s ease";
      indicator.style.transform = "translate3d(-50%, -46px, 0) scale(0.72)";
      resetTimer = setTimeout(() => {
        indicator.style.transition = "";
        indicator.style.transform = "";
        ring.style.strokeDashoffset = String(CIRC);
        core.style.transform = "";
        state = STATE_IDLE;
      }, 300);
    }
  };

  const onTouchStart = (e) => {
    // 仅在触屏支持且视口为移动端时启用；桌面端完全放行
    if (!touchCapable || !isMobile()) return;
    if (state === STATE_REFRESHING || e.touches.length !== 1) return;
    if (!isAtTop() || isInteractiveTarget(e.target) || hasScrollableUpwardAncestor(e.target)) return;

    clearTimeout(resetTimer);
    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
    state = STATE_PENDING;
    hasHaptic = false;
  };

  const onTouchMove = (e) => {
    if (state !== STATE_PENDING && state !== STATE_PULLING) return;
    if (e.touches.length !== 1 || !isAtTop()) {
      resetVisuals(true);
      return;
    }

    const curX = e.touches[0].clientX;
    const curY = e.touches[0].clientY;
    const dx = curX - startX;
    const dy = curY - startY;

    if (state === STATE_PENDING) {
      const absX = Math.abs(dx);
      const absY = Math.abs(dy);
      // 判定死区：微小位移不干预
      if (absX < 7 && absY < 7) return;

      // 明确垂直向下判定为下拉刷新；否则放行给横向切卡或原生滚动
      if (dy > 0 && dy > absX * 1.25) {
        state = STATE_PULLING;
        indicator.classList.add("pulling", "on");
      } else {
        state = STATE_IDLE;
        resetVisuals(true);
        return;
      }
    }

    if (state === STATE_PULLING) {
      if (e.cancelable) e.preventDefault();
      rawDistance = Math.max(0, dy - 7);
      // 真实对数阻尼公式
      const pullY = Math.min(MAX_PULL, Math.pow(rawDistance, 0.82) * 1.55);
      applyVisuals(pullY);
    }
  };

  const onTouchEnd = async () => {
    if (state !== STATE_PULLING) {
      if (state === STATE_PENDING) resetVisuals(true);
      return;
    }

    if (pull < THRESHOLD) {
      resetVisuals(false);
      return;
    }

    // 触发刷新
    state = STATE_REFRESHING;
    indicator.classList.remove("pulling", "ready");
    indicator.classList.add("loading");
    indicator.style.transition = "transform .28s cubic-bezier(0.2, 0, 0, 1)";
    indicator.style.transform = `translate3d(-50%, ${HOLD_Y}px, 0) scale(1)`;

    try {
      await triggerSharedRefresh({ isPull: true });
    } catch (_) {
    } finally {
      haptic(12);
      resetVisuals(false);
    }
  };

  const onTouchCancel = () => {
    if (state !== STATE_REFRESHING) {
      resetVisuals(false);
    }
  };

  document.addEventListener("touchstart", onTouchStart, { passive: true });
  document.addEventListener("touchmove", onTouchMove, { passive: false });
  document.addEventListener("touchend", onTouchEnd, { passive: true });
  document.addEventListener("touchcancel", onTouchCancel, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && state !== STATE_REFRESHING) resetVisuals(true);
  });

  return {
    getState: () => state,
    reset: resetVisuals,
    isAtTop,
  };
})();

document.querySelectorAll("#filters .chip").forEach(c =>
  c.addEventListener("click", () => { filter = c.dataset.f; applyFilter(); }));
document.querySelectorAll(".tcol").forEach(b =>
  b.addEventListener("click", () => {
    $("svc").dataset.col = b.dataset.col;
    document.querySelectorAll(".tcol").forEach(x =>
      x.classList.toggle("active", x === b));
  }));
// 刷新控件(topbar 圆钮): 点击=立即刷新, 长按(500ms)=锁定/解锁自动刷新
let refreshHoldTimer = null, refreshHoldDone = false;
function refreshBtns() { return [$("refresh")].filter(Boolean); }
function setAutoLocked(v) {
  autoLocked = v;
  refreshBtns().forEach(b => { b.classList.toggle("locked", v); b.setAttribute("aria-pressed", v); });
}
function bindRefreshCtl(btn) {
  btn.addEventListener("click", () => {
    if (refreshHoldDone) return;
    haptic(8);
    triggerSharedRefresh({ isPull: false });
  });
  ["pointerdown", "touchstart"].forEach(ev => btn.addEventListener(ev, () => {
    refreshHoldDone = false;
    clearTimeout(refreshHoldTimer);
    refreshHoldTimer = setTimeout(() => {
      refreshHoldDone = true;
      setAutoLocked(!autoLocked);
      haptic(15);
      themeToast(t(autoLocked ? "locked_toast" : "unlocked_toast"));
    }, 500);
  }, { passive: true }));
  ["pointerup", "pointercancel", "touchend", "touchcancel", "pointerleave"].forEach(ev =>
    btn.addEventListener(ev, () => clearTimeout(refreshHoldTimer), { passive: true }));
}
refreshBtns().forEach(bindRefreshCtl);
// 全局彻底停用浮动刷新圆钮
(function setupFab() {
  const fab = $("fab-refresh");
  if (fab) fab.hidden = true;
})();
// 全局键盘委托: 所有 span[role=button] 控件支持 Enter/Space 触发
document.addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  const el = e.target.closest('[role="button"]');
  if (!el) return;
  e.preventDefault();
  el.click();
});

/* ================================================================
   移动 App 层(仅触摸设备): 底栏 / 列表手势 / 双击 /
   捏合图表 / 触觉反馈 / 轮询暂停。横向滑动不做切页, 交给原生滚动。
   桌面端不注册任何触摸事件,行为零变化。 */
const TOUCH = ("ontouchstart" in window) || navigator.maxTouchPoints > 0;
const mqMobile = window.matchMedia("(max-width: 768px)");
const isMobile = () => mqMobile.matches;
const haptic = (ms) => {
  try {
    if (navigator.userActivation && !navigator.userActivation.hasBeenActive) return;
    navigator.vibrate && navigator.vibrate(ms);
  } catch (e) {}
};
// 移动端把各分区装进 5 个 .pg 页容器; 桌面端恢复原始 DOM 顺序(display:contents 布局)。
// 记住初始顺序, 窗口跨过 768px 断点时来回重组不丢内容。
const PAGE_GROUPS = [
  ["#sysbar", "#chart-wrap", "#hp-vms-grid", "#hp-portal-grid"],
  ["#activity-page"],
  ["#tmux-panel"],
  ["#agents-page"],
  ["#svc-head", "#svc-subnav", "#filters", "#network-page", "#tasks", "#svc-panel", "#cron-panel", "#logpage"],
];
let pagesHomeOrder = null, pgWrappers = null, trackEl = null, headerHome = null;
function placeHeader(mobile) {
  // 移动端: header 移入 main 顶部 → 随内容滚出视口(不固定); 桌面: 放回 body 原位(同为静态, 随文档滚动)。
  // 移动方向只在断点切换时执行一次, 载入时即按当前视口就位。
  const hdr = document.querySelector("header"), main = document.querySelector("main");
  if (!hdr || !main) return;
  if (mobile && hdr.parentElement !== main) {
    if (!headerHome) headerHome = { parent: hdr.parentElement, next: hdr.nextElementSibling };
    main.insertBefore(hdr, main.firstChild);
  } else if (!mobile && headerHome && hdr.parentElement !== headerHome.parent) {
    headerHome.parent.insertBefore(hdr, headerHome.next);
  }
}
function regroupPages() {
  placeHeader(mqMobile.matches);
  if (!mqMobile.matches) {
    if (pagesHomeOrder) { // 桌面: 按原顺序放回 #pages, 撤掉轨道
      pagesHomeOrder.forEach(el => pages.appendChild(el));
      if (trackEl) { trackEl.remove(); trackEl = null; }
      pgWrappers = null;
      watchPageHeights();   // P0-1: 桌面撤轨道, 解除高度观察
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
  // 每页高度跟随自身内容; 轨道高=当前页(scrollHeight 含每页自己的 padding-bottom 预留)
  pgWrappers.forEach(w => { w.style.height = "auto"; });
  applyPagesX(false);
  watchPageHeights();   // P0-1: 内容尺寸变化自动重测
}
mqMobile.addEventListener("change", () => {
  regroupPages(); drawChart();
  // 桌面分类过滤与移动分页互斥: 切到移动清 .cat-off(分页自身就按页隔离内容)
  if (mqMobile.matches) {
    document.querySelectorAll(".cat-off").forEach(el => el.classList.remove("cat-off"));
  } else setCat(curCat, false);   // 切回桌面: 恢复选中分类的过滤
});
// --- 分页(概览/活动/Tmux/Agent/服务) ---
const pages = $("pages");
const N_PAGES = 5;
const PAGE_W = 100 / N_PAGES;   // 轨道宽 500%, 每页位移 = 轨道的 1/5
var page = 0;   // var: 挂到 window, 便于外部调试/测试读取
function pageLabels() { return [t("tab_home"), t("tab_activity"), t("tab_tmux"), t("tab_agent"), t("tab_svc")]; }
function applyPagesX(withTransition) {
  const tr = trackEl; // 移动端才有轨道
  if (!tr) return;
  // 轨道宽 500%: 每页位移 = 轨道的 1/5
  tr.style.transform = `translate3d(${-page * PAGE_W}%,0,0)`;
  // 每页各自高度: 轨道高度跟随当前页内容(flex 容器默认拉伸到最高页 = 高页拖矮页)
  const cur = tr.children[page];
  // P0-1: rect 含 .pg padding-bottom(底栏预留)且无取整截断, 比 scrollHeight 精确
  if (cur) tr.style.height = Math.ceil(cur.getBoundingClientRect().height) + "px";
  if (!withTransition) requestAnimationFrame(() => tr.classList.remove("stick"));
}

// --- P0-1: 轨道高度重测 ---
// 当前页内容异步变化(骨架→数据/折叠展开/图片字体加载)都会改变 .pg 高度;
// ResizeObserver 盯住每页包裹容器, 一变就按当前页重设 #track 高度,
// 否则 #pages(overflow:hidden) 按旧高度裁掉底部内容(被悬浮底栏遮挡的根因)。
function remeasureTrack() { if (trackEl) applyPagesX(false); }
let trackRO = null;
function watchPageHeights() {
  if (trackRO) { trackRO.disconnect(); trackRO = null; }
  if (!trackEl || !pgWrappers || !("ResizeObserver" in window)) return;
  trackRO = new ResizeObserver(() => remeasureTrack());
  pgWrappers.forEach(w => trackRO.observe(w));
}
// 字体加载完成与整页资源 load 后各补测一次(RO 兜底其余异步时机)
if (document.fonts && document.fonts.ready) document.fonts.ready.then(remeasureTrack);
window.addEventListener("load", remeasureTrack);
function setPage(i, opts) {
  i = Math.max(0, Math.min(N_PAGES - 1, i));
  const first = (opts && opts.first) === true;
  if (!first) {
    haptic(8);
    console.log("[svc-dashboard] page -> " + i + " " + pageLabels()[i]);
  }
  const changed = i !== page || first;
  page = i;
  syncConnbarVisibility();
  applyPagesX(true);
  document.querySelectorAll("#tabbar .tab").forEach(b => b.classList.toggle("active", +b.dataset.p === i));
  const tb = $("tabbar");
  if (tb) tb.classList.remove("tabbar-hidden");
  if (changed) activatePage(i);
  // 页面内容异步变化后(骨架→数据/折叠展开)重测高度
  requestAnimationFrame(() => applyPagesX(false));
}
function activatePage(i) {
  if (i === 0) requestAnimationFrame(drawChart);
  if (i === 1) { const ap = $("activity-page"); if (ap) ap.hidden = false; renderActivityPage(); }
  if (i === 2) {
    const tp = $("tmux-panel");
    if (tp) tp.hidden = false;
    tmuxInitSubnav();          // 任务列表 / 看门狗：桌面经 setCat 进入，手机经分页进入，两边都要初始化
    renderTmuxPage();
  }
  if (i === 3) {
    const ap = $("agents-page");
    if (ap) ap.hidden = false;
    initAgentsPage();
  }
  if (i === 4 && isMobile()) {       // 服务页: 骨架 → 渲染
    const tbody = $("svc").querySelector("tbody");
    if (!tbody.children.length) tbody.innerHTML = mobileSkel(4);
    applyFilter();
  }
  if (i === 4) {                     // 服务页尾部 = 计划任务 + 日志区
    const cp = $("cron-panel");
    if (cp) cp.hidden = false;
    cronLoad();
    initLogPage(); renderLogTimeline();
  }
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("#tabbar .tab");
  if (b) {
    const tb = $("tabbar");
    if (tb) tb.classList.remove("tabbar-hidden");
    setPage(+b.dataset.p);
    return;
  }
});

// --- 手机端导航栏随滚动自动隐藏/显现 (下滑隐藏留出全屏视野，上滑浮现) ---
(function initTabbarAutoScroll() {
  const main = document.querySelector("main");
  const tabbar = document.getElementById("tabbar");
  if (!tabbar) return;
  let lastY = 0;
  let ticking = false;

  const onScroll = (currentY) => {
    const diff = currentY - lastY;
    if (diff > 12 && currentY > 50) {
      tabbar.classList.add("tabbar-hidden");
    } else if (diff < -8 || currentY <= 25) {
      tabbar.classList.remove("tabbar-hidden");
    }
    lastY = Math.max(0, currentY);
    ticking = false;
  };

  if (main) {
    main.addEventListener("scroll", () => {
      if (!ticking) {
        requestAnimationFrame(() => onScroll(main.scrollTop));
        ticking = true;
      }
    }, { passive: true });
  }

  window.addEventListener("scroll", () => {
    if (!ticking) {
      requestAnimationFrame(() => onScroll(window.scrollY || document.documentElement.scrollTop));
      ticking = true;
    }
  }, { passive: true });
})();

// --- 手机端左右滑动切换卡片 (Swipe to Switch Page / Tab) ---
(function initSwipeToChangePage() {
  const touchCapable = ("ontouchstart" in window) || navigator.maxTouchPoints > 0;
  if (!touchCapable) return;

  let startX = 0, startY = 0, startTime = 0;
  let isSwiping = false, directionLocked = false;
  let scrollableParent = null;

  function findHorizontalScrollable(el) {
    while (el && el !== document.body && el !== trackEl && el !== pages) {
      if (el.classList && (el.classList.contains("filters") || el.classList.contains("nodel-code"))) {
        if (el.scrollWidth > el.clientWidth) return el;
      }
      const style = window.getComputedStyle(el);
      const ox = style.overflowX;
      if ((ox === "auto" || ox === "scroll") && el.scrollWidth > el.clientWidth) {
        return el;
      }
      el = el.parentElement;
    }
    return null;
  }

  document.addEventListener("touchstart", (e) => {
    if (!isMobile() || !trackEl || e.touches.length !== 1) return;
    const target = e.target;
    // 忽略输入交互与弹窗
    if (target.closest("input, textarea, select, [contenteditable='true'], .modal-content, .lightbox")) return;

    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
    startTime = Date.now();
    isSwiping = false;
    directionLocked = false;
    scrollableParent = findHorizontalScrollable(target);
  }, { passive: true });

  document.addEventListener("touchmove", (e) => {
    if (!isMobile() || !trackEl || !startX || e.touches.length !== 1) return;
    const curX = e.touches[0].clientX;
    const curY = e.touches[0].clientY;
    const dx = curX - startX;
    const dy = curY - startY;

    if (!directionLocked) {
      const absX = Math.abs(dx);
      const absY = Math.abs(dy);
      if (absX >= 8 || absY >= 8) {
        directionLocked = true;
        if (absX > absY * 1.2) {
          // 判定为水平滑动。若触摸在内部横滚容器上且该容器在滑动方向尚有滚动余量，则让容器自己滚动
          if (scrollableParent) {
            const maxScroll = scrollableParent.scrollWidth - scrollableParent.clientWidth;
            const sl = scrollableParent.scrollLeft;
            if ((dx > 0 && sl > 2) || (dx < 0 && sl < maxScroll - 2)) {
              isSwiping = false;
              return;
            }
          }
          isSwiping = true;
        } else {
          isSwiping = false;
        }
      }
    }

    if (isSwiping) {
      if (e.cancelable) e.preventDefault();
      const vw = window.innerWidth || 360;
      let deltaPercent = (dx / vw) * PAGE_W;

      // 处于第 0 页向右拉或最后一页向左拉时，施加橡皮筋弹性阻尼
      if ((page === 0 && dx > 0) || (page === N_PAGES - 1 && dx < 0)) {
        deltaPercent *= 0.28;
      }

      trackEl.classList.add("stick");
      trackEl.style.transform = `translate3d(${-page * PAGE_W + deltaPercent}%, 0, 0)`;
    }
  }, { passive: false });

  const endSwipe = (e) => {
    if (!startX) return;
    const lastX = (e.changedTouches && e.changedTouches[0]) ? e.changedTouches[0].clientX : startX;
    const dx = lastX - startX;
    const dt = Date.now() - startTime;
    const wasSwiping = isSwiping;

    startX = 0;
    startY = 0;
    startTime = 0;
    isSwiping = false;
    directionLocked = false;
    scrollableParent = null;

    if (wasSwiping && trackEl) {
      trackEl.classList.remove("stick");
      const vw = window.innerWidth || 360;
      const vx = dx / Math.max(1, dt);
      const flick = dt < 350 && Math.abs(dx) > 28 && Math.abs(vx) > 0.22;
      const movedEnough = Math.abs(dx) > Math.min(vw * 0.18, 55);

      let targetPage = page;
      if (flick || movedEnough) {
        if (dx < 0 && page < N_PAGES - 1) {
          targetPage = page + 1;
        } else if (dx > 0 && page > 0) {
          targetPage = page - 1;
        }
      }

      if (targetPage !== page) {
        setPage(targetPage);
      } else {
        applyPagesX(true);
      }
    }
  };

  document.addEventListener("touchend", endSwipe, { passive: true });
  document.addEventListener("touchcancel", endSwipe, { passive: true });
})();

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
    if (btn) { const old = btn.innerHTML; btn.innerHTML = icon("ok", 12) + " " + t("g_copied"); setTimeout(() => btn.innerHTML = old, 1600); }
  };
  if (navigator.clipboard && window.isSecureContext)
    navigator.clipboard.writeText(txt).then(done).catch(() => fallbackCopy(txt, done));
  else fallbackCopy(txt, done);
}

// --- 日志页: agent 选择 + 事件时间线(长按复制) ---
let logAgents = null;
// escHtml/escAttr 必须声明在 syncLogAgentPicker 与下方 IIFE 之前:
// initLogAgentPicker 在模块求值期立即执行, const 放后面会触发 TDZ
// ReferenceError 并杀死整个主脚本(catbar/hash 路由/load 全部不执行)。
const escHtml = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const escAttr = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function syncLogAgentPicker() {
  const sel = $("logagent-sel"), menu = $("logagent-menu"), value = $("logagent-value"), picker = $("logagent-picker");
  if (!sel || !menu || !value || !picker) return;
  menu.innerHTML = [...sel.options].map((o, i) => `<div class="ui-option${i === sel.selectedIndex ? " active" : ""}" data-index="${i}" role="option" tabindex="0">${escHtml(o.textContent)}</div>`).join("");
  value.textContent = sel.options[sel.selectedIndex]?.textContent || t("log_pick");
  menu.querySelectorAll(".ui-option").forEach(o => o.addEventListener("click", () => { sel.selectedIndex = +o.dataset.index; menu.hidden = true; syncLogAgentPicker(); sel.dispatchEvent(new Event("change")); }));
}
function initLogAgentPicker() {
  const picker = $("logagent-picker"), menu = $("logagent-menu");
  if (!picker || !menu) return;
  picker.addEventListener("click", e => { if (!e.target.closest(".ui-option")) menu.hidden = !menu.hidden; });
  document.addEventListener("click", e => { if (!picker.contains(e.target)) menu.hidden = true; });
  syncLogAgentPicker();
}

async function initLogPage(force) {
  const lp = $("logpage");
  if (lp) lp.hidden = false;   // 双端进入日志页即显示(移动页签 / 桌面 cat=log)
  const sel = $("logagent-sel"), body = $("logbody");
  if (!sel || !body) return;
  if (logAgents && !force) { if (!body.children.length) loadLogView(); return; }
  const agents = await loadAgents();
  logAgents = agents;
  let opts = `<option value="">${t("log_pick")}</option>`;
  agents.omp.forEach(x => { opts += `<option value='${escAttr(x.id)}' data-cwd='${escAttr(x.cwd)}' data-tmux='${escAttr(x.tmux)}'>OMP · ${escHtml(stripMd(x.goal || x.cwd).slice(0, 48))}</option>`; });
  agents.codex.forEach(x => { opts += `<option value='' data-cwd='${escAttr(x.cwd)}' data-tmux=''>Codex · ${escHtml(x.cwd.slice(-40))}</option>`; });
  sel.innerHTML = opts;
  syncLogAgentPicker();
  // 默认选中最近活跃的 agent(omp 已按 活跃→闲置 排序), 免得默认空选择
  const first = [...sel.options].find(o => o.value);
  if (first && !sel.selectedOptions[0]?.value) { sel.value = first.value; }
  if (!body.children.length) loadLogView();
}
async function loadLogView() {
  const body = $("logbody");
  const sel = $("logagent-sel");
  if (!body || !sel) return;
  const opt = sel.selectedOptions ? sel.selectedOptions[0] : null;
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
  d.className = "copy-toast";
  d.innerHTML = icon("ok", 13) + " " + t("g_copied");
  document.body.appendChild(d);
  setTimeout(() => { d.style.opacity = "0"; setTimeout(() => d.remove(), 350); }, 1400);
}
// (escHtml/escAttr 已上移到 syncLogAgentPicker 之前, 此处勿重复声明)

// --- Agent 运行时总览: 注册表 + 过滤分组 + 装卸 + 状态/进程/任务/额度 ---
let agentsInit = false, rtCache = null, rtT = 0, rtTimer = null, rtFilter = null, rtModelTimer = null;
async function loadRuntimes(force) {
  if (BOOT.static && BOOT.runtimesData) {
    rtCache = BOOT.runtimesData;
    return rtCache;
  }
  const n = Date.now();
  if (!force && rtCache && n - rtT < 15000) return rtCache;
  rtCache = await tlGet("/api/runtimes");
  rtT = n;
  return rtCache;
}

const rtState = a => !a.installed ? "none" : a.procs > 0 ? "run" : "idle";
const rtHasQuota = a => !!(a.quota && a.quota.ok && a.quota.buckets && a.quota.buckets.length);
const rtHasTasks = a => a.installed && (a.task_count || 0) > 0;
function rtActivityRank(a, nowSec = Date.now() / 1000) {
  const tasks = a.tasks || [];
  const liveTasks = tasks.filter(x => x.health === "running" || x.health === "blocked").length;
  const ages = tasks.map(x => Number(x.idle_seconds ?? x.age_sec))
    .filter(n => Number.isFinite(n) && n >= 0);
  const newestAge = ages.length ? Math.min(...ages) : Infinity;
  const recentTasks = ages.filter(age => age <= 30 * 86400).length;
  const recentSessions = Number((a.meta || {}).sessions_24h) || 0;
  return [
    a.installed ? 1 : 0,
    (a.procs || 0) > 0 || liveTasks > 0 ? 1 : 0,
    liveTasks,
    a.procs || 0,
    recentTasks + recentSessions,
    -newestAge,
  ];
}
function sortAgentsByActivity(agents) {
  return (agents || []).map((agent, index) => ({ agent, index, rank: rtActivityRank(agent) }))
    .sort((a, b) => {
      for (let i = 0; i < a.rank.length; i++) {
        if (a.rank[i] !== b.rank[i]) return b.rank[i] - a.rank[i];
      }
      return a.index - b.index;
    })
    .map(x => x.agent);
}

function rtQuotaHtml(a) {
  const q = a.quota;
  if (!q) return "";
  if (!q.buckets || !q.buckets.length)
    return `<div class="rt-qnone">${t("rt_quotafail")}</div>`;
  return `<div class="agent-quota-box">
    <div class="agent-quota-title">
      <span>${icon("gauge", 12)} ${t("agent_quota_title")}</span>
      ${q.account ? `<span style="font-weight:normal;color:var(--text-ghost)">${escHtml(q.account)}${q.plan ? ' · ' + escHtml(q.plan) : ''}</span>` : ""}
    </div>
    ${q.buckets.map(b => {
      const p = b.remaining_pct;
      if (p == null) return "";
      const cls = p >= 50 ? "high" : p >= 15 ? "mid" : "low";
      const dead = p <= 0;
      return `<div class="agent-bucket-row">
        <div class="agent-bucket-meta">
          <span><b>${escHtml(b.label)}</b>: ${p}%</span>
          <span class="reset-txt">${b.reset ? (dead ? t("rt_exhausted") : t("rt_reset")) + " " + escHtml(b.reset) : (b.detail ? escHtml(b.detail) : "")}</span>
        </div>
        <div class="agent-bar-track">
          <div class="agent-bar-fill ${cls}" style="width:${Math.max(p, 2)}%"></div>
        </div>
      </div>`;
    }).join("")}
  </div>`;
}

function rtTasksHtml(a) {
  const rows = [];
  (a.tasks || []).forEach(x => {
    if (x.kind === "omp" || x.kind === "codex") rows.push(`<div class="rt-task" data-sid="${escAttr(x.id)}" data-cwd="${escAttr(x.cwd)}" data-tmux="${escAttr(x.tmux || "")}" role="button" tabindex="0">
      <span class="rt-dot2 ${x.health === "running" ? "run" : "warn"}"></span>
      <span class="rt-taskgoal">${escHtml(stripMd(x.goal || x.title || x.cwd).slice(0, 70))}</span>
      <span class="rt-taskmeta">${agoStr(x.idle_seconds)} · ${escHtml(x.tool || "session")}</span></div>`);
    else if (x.kind === "grok") rows.push(`<div class="rt-task"><span class="rt-dot2 run"></span>
      <span class="rt-taskgoal">${escHtml(x.cwd)}</span><span class="rt-taskmeta">pid ${escHtml(String(x.pid))}</span></div>`);
    else if (x.kind === "session") rows.push(`<div class="rt-task"><span class="rt-dot2 ${x.health === "running" ? "run" : "dim"}"></span>
      <span class="rt-taskgoal">${escHtml(x.title || x.cwd)}</span><span class="rt-taskmeta">${agoStr(x.age_sec)} · ${escHtml(x.cwd)}</span></div>`);
    else if (x.kind === "process") rows.push(`<div class="rt-task"><span class="rt-dot2 run"></span>
      <span class="rt-taskgoal">${escHtml(x.cwd)}</span><span class="rt-taskmeta">pid ${escHtml(String(x.pid))}</span></div>`);
    else if (x.kind === "file") rows.push(`<div class="rt-task"><span class="rt-dot2 dim"></span>
      <span class="rt-taskgoal">${escHtml(x.file)}</span><span class="rt-taskmeta">${agoStr(x.age_sec)}</span></div>`);
  });
  return rows.join("");
}

function rtCardHtml(a) {
  const st = rtState(a);
  const stDot = st === "run" ? "on" : st === "idle" ? "idle" : "";
  const stText = st === "run" ? `${t("rt_f_run")} (${a.procs})` : (a.installed ? t("rt_sec_idle") : t("rt_f_none"));

  let procsHtml = "";
  if (a.procs > 0 && a.proc_list && a.proc_list.length) {
    procsHtml = `<div class="agent-procs-list">
      ${a.proc_list.map(p => `
        <div class="agent-proc-item">
          <div><span class="agent-proc-pid">PID ${p.pid}</span> <span class="agent-proc-cwd" title="${escAttr(p.cwd || '')}">${escHtml(p.cwd || '—')}</span></div>
          <div class="agent-proc-res"><b>${p.cpu_pct}%</b> CPU · <b>${p.mem_mb}</b> MB</div>
        </div>
      `).join("")}
    </div>`;
  }

  const tasksHtml = rtTasksHtml(a);
  const detailBtn = `<button class="rt-btn ghost btn-agent-detail" data-agent-id="${escAttr(a.id)}">${t("agent_btn_detail")}</button>`;

  return `<article class="agent-card ${st}" data-aname="${escAttr(a.name)}">
    <div class="agent-card-top">
      <div class="agent-card-title-wrap">
        <span class="agent-status-dot ${stDot}"></span>
        <span class="agent-aname">${escHtml(a.name)}</span>
        <span class="agent-pill ${st}">${escHtml(stText)}</span>
        ${a.version ? `<span class="agent-acc-badge">${escHtml(a.version)}</span>` : ""}
      </div>
      <div class="agent-card-actions">
        ${detailBtn}
      </div>
    </div>
    ${procsHtml}
    ${tasksHtml ? `<div class="rt-tasks" style="margin-top:8px;">${tasksHtml}</div>` : ""}
  </article>`;
}

function rtMatch(a, f) {
  const st = rtState(a);
  if (f === "run") return st === "run";
  if (f === "idle") return st === "idle";
  if (f === "tasks") return rtHasTasks(a);
  if (f === "quota") return a.installed && rtHasQuota(a);
  if (f === "none") return st === "none";
  return true;
}

let curAgentTab = "routing";
let curMagpiePeriod = "today";
let curQuotaMode = "remain";
let curAccountMasked = true;
let curMagpieData = null;
let curMagpieRoutingData = null;
let curMagpieProvidersData = null;
let magpieUsageCache = {};
let magpieRoutingCache = null;
let magpieProvidersCache = null;

function fmtTokens(n) {
  if (n == null || isNaN(n)) return "0";
  n = Number(n);
  if (n >= 1e9) return (n / 1e9).toFixed(2) + "B";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
  return String(Math.round(n));
}

function fmtCost(n) {
  if (n == null || isNaN(n)) return "$0.00";
  n = Number(n);
  if (n >= 100) return "$" + n.toFixed(1);
  if (n >= 1) return "$" + n.toFixed(2);
  if (n > 0) return "$" + n.toFixed(3);
  return "$0.00";
}

function fmtSpeed(ms, out) {
  if (!ms || !out) return "—";
  const sec = ms / 1000;
  if (sec <= 0) return "—";
  const spd = out / sec;
  return spd >= 100 ? Math.round(spd) + " t/s" : spd.toFixed(1) + " t/s";
}

function fmtLatency(ms) {
  if (!ms) return "—";
  if (ms >= 1000) return (ms / 1000).toFixed(2) + "s";
  return Math.round(ms) + "ms";
}

function fmtMonthDayTime(isoStr) {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    return `${d.getMonth() + 1}月${d.getDate()}日 ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  } catch (e) {
    return isoStr;
  }
}

function fmtResetDate(isoStr) {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    const now = new Date();
    const isTomorrow = (d.getDate() === now.getDate() + 1 && d.getMonth() === now.getMonth());
    const isToday = (d.getDate() === now.getDate() && d.getMonth() === now.getMonth());
    const timeStr = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    if (isTomorrow) return `明天 ${timeStr}`;
    if (isToday) return `今天 ${timeStr}`;
    return `${d.getMonth() + 1}月${d.getDate()}日 ${timeStr}`;
  } catch (e) {
    return isoStr;
  }
}

function fmtRelTime(isoStr) {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    const diffSec = Math.round((d.getTime() - Date.now()) / 1000);
    if (diffSec <= 0) return t("mp_reset_done");
    if (diffSec < 3600) return `${Math.ceil(diffSec / 60)} 分钟后`;
    if (diffSec < 86400) return `${Math.round(diffSec / 3600)} 小时后`;
    return `${Math.round(diffSec / 86400)} 天后`;
  } catch (e) {
    return "";
  }
}

function renderSparkline(points) {
  if (!points || points.length < 2) {
    return `
      <svg class="mp-sparkline-svg" viewBox="0 0 200 24" preserveAspectRatio="none">
        <line x1="0" y1="18" x2="200" y2="18" stroke="rgba(255,255,255,0.06)" stroke-width="1" />
        <line x1="0" y1="12" x2="200" y2="12" stroke="#38bdf8" stroke-width="1.5" stroke-dasharray="3,3" opacity="0.6" />
      </svg>
    `;
  }
  const values = points.map(p => Number(p.amount) || 0);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = (max - min) || 1;
  const W = 200, H = 24, padY = 3;
  const polyPoints = points.map((p, i) => {
    const x = Math.round((i / (points.length - 1)) * W);
    const y = Math.round(H - padY - ((p.amount - min) / range) * (H - padY * 2));
    return `${x},${y}`;
  }).join(" ");

  return `
    <svg class="mp-sparkline-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <line x1="0" y1="${H-1}" x2="${W}" y2="${H-1}" stroke="rgba(255,255,255,0.06)" stroke-width="1" />
      <polyline fill="none" stroke="#38bdf8" stroke-width="1.8" points="${polyPoints}" />
    </svg>
  `;
}

function renderAccountRow(acc, provider, isSec = false) {
  const isMaskedCls = curAccountMasked ? "is-masked" : "";
  const userDisp = acc.user || (acc.balance ? "" : "API key");
  const planDisp = acc.plan || "";

  let windowsHtml = "";
  if (acc.windows && acc.windows.length > 0) {
    const isMultiWin = acc.windows.length > 1;
    windowsHtml = `
      <div class="mp-win-container" style="${isMultiWin ? '' : 'flex-direction:column;'}">
        ${acc.windows.map(w => {
          const usedPct = Number(w.used) || 0;
          const remainPct = Math.max(0, Math.min(100, 100 - usedPct));
          let valText = "";
          let barPct = 0;

          if (w.name === "Credits" || (w.display && w.display.includes("/"))) {
            const parts = (w.display || "").split("/").map(s => parseFloat(s.trim()));
            const fmtNum = (n) => {
              if (n == null || isNaN(n)) return "0";
              const num = Number(n);
              return Number.isInteger(num) ? num.toLocaleString() : num.toFixed(2);
            };
            const totalLimit = fmtNum(w.limit || parts[1] || 50);
            if (curQuotaMode === "remain") {
              const remRaw = (w.runsOut != null) ? Number(w.runsOut) : ((parts.length === 2 && !isNaN(parts[0]) && !isNaN(parts[1])) ? Math.max(0, parts[1] - parts[0]) : (w.limit && w.amount != null ? Math.max(0, w.limit - w.amount) : null));
              const rem = remRaw != null ? fmtNum(remRaw) : remainPct.toFixed(1);
              valText = `${rem} / ${totalLimit} ${t("mp_credits")} · ${t("mp_view_mode_remain")} ${remainPct.toFixed(1)}%`;
              barPct = remainPct;
            } else {
              valText = `${w.display || `${fmtNum(w.amount || parts[0] || 0)} / ${totalLimit}`} ${t("mp_credits")} · ${t("mp_view_mode_used")} ${usedPct.toFixed(1)}%`;
              barPct = usedPct;
            }
          } else {
            if (curQuotaMode === "remain") {
              valText = `${t("mp_view_mode_remain")} ${remainPct >= 10 ? remainPct.toFixed(0) : remainPct.toFixed(1)}%`;
              barPct = remainPct;
            } else {
              valText = `${t("mp_view_mode_used")} ${usedPct >= 10 ? usedPct.toFixed(0) : usedPct.toFixed(1)}%`;
              barPct = usedPct;
            }
          }

          let metaHtml = "";
          if (w.resetsAt) {
            const dateStr = fmtResetDate(w.resetsAt);
            const relStr = fmtRelTime(w.resetsAt);
            let paceStr = "";
            if (w.holds && w.holds.since) {
              const s = new Date(w.holds.since).getTime();
              const e = new Date(w.resetsAt).getTime();
              const n = Date.now();
              if (e > s && n >= s) {
                const elRatio = (n - s) / (e - s);
                const pace = Math.round((usedPct / 100 - elRatio) * 100);
                paceStr = ` · ${t("mp_pace", { n: (pace >= 0 ? "+" : "") + pace })}`;
              }
            }
            metaHtml += `<span>重置于 ${dateStr} · ${relStr}${paceStr}</span>`;
          }
          if (w.holds && w.holds.tokens) {
            const tokStr = t("mp_window_tokens", { n: fmtTokens(w.holds.tokens) });
            const costStr = w.holds.cost ? ` · ${t("mp_window_cost", { n: w.holds.cost.toFixed(2) })}` : "";
            metaHtml += `<span>${tokStr}${costStr}</span>`;
          }
          if (w.runsOutAt) {
            const daysLeft = Math.max(1, Math.round((new Date(w.runsOutAt).getTime() - Date.now()) / (86400 * 1000)));
            const roStr = (w.runsOut != null) ? (Number.isInteger(Number(w.runsOut)) ? Number(w.runsOut).toLocaleString() : Number(w.runsOut).toFixed(2)) : "";
            metaHtml += `<span>${roStr ? `${roStr} 积分 将于 ` : ""}${fmtMonthDayTime(w.runsOutAt)} 过期 · ${daysLeft} 天后</span>`;
          }

          // 与 Agent 概览额度条(hp-bucket)统一: 健康=绿, 警戒=橙, 危险=红
          const fillCls = (curQuotaMode === "remain")
            ? ((barPct <= 15) ? "low" : (barPct <= 50) ? "warn" : "")
            : ((barPct >= 85) ? "low" : (barPct >= 50) ? "warn" : "");
          const winNameDisp = (w.name === "5 hours" ? t("mp_win_5h") : w.name === "7 days" ? t("mp_win_7d") : w.name === "Credits" ? t("mp_credits") : w.name);

          return `
            <div class="mp-win-col">
              <div class="mp-win-top">
                <span class="mp-win-name">${escHtml(winNameDisp)}</span>
                <span class="mp-win-val ${fillCls}">${escHtml(valText)}</span>
              </div>
              <div class="mp-win-track">
                <div class="mp-win-fill ${fillCls}" style="width:${Math.max(2, Math.min(100, barPct))}%;"></div>
              </div>
              ${metaHtml ? `<div class="mp-win-meta">${metaHtml}</div>` : ""}
            </div>
          `;
        }).join("")}
      </div>
    `;
  }

  let dailyHtml = "";
  if (acc.daily && acc.daily.days && acc.daily.days.length > 0) {
    const dUsed = acc.daily.days[0].used;
    dailyHtml = `
      <div class="mp-daily-burn">
        <span>${t("mp_daily_used", { n: dUsed })}</span>
        <span style="color:var(--text-dim);font-size:10px;">刚刚更新</span>
      </div>
    `;
  }

  let balanceHtml = "";
  if (acc.balance != null) {
    let statHtml = "";
    if (acc.balanceTrend && acc.balanceTrend.runsOut) {
      const daysLeft = Math.max(1, Math.round((new Date(acc.balanceTrend.runsOut).getTime() - Date.now()) / (86400 * 1000)));
      statHtml = `按此速度，预计 ${daysLeft} 天后用完`;
    }
    balanceHtml = `
      <div class="mp-balance-box">
        <span class="mp-balance-lbl">${t("mp_balance")}</span>
        <span class="mp-balance-val">${escHtml(acc.balance)}</span>
      </div>
      <div class="mp-trend-stat">
        <span>${statHtml}</span>
        <span style="color:var(--text-dim);font-size:10.5px;">刚刚更新</span>
      </div>
      ${renderSparkline(acc.balanceTrend ? acc.balanceTrend.points : null)}
      <div class="mp-trend-stat" style="font-size:10.5px;color:var(--text-soft);">
        <span><span class="mp-trend-dot"></span>${t("mp_balance")} ${escHtml(acc.balance)} ${(acc.balanceTrend && acc.balanceTrend.perDay != null && !isNaN(acc.balanceTrend.perDay)) ? `· 约每天 $${Number(acc.balanceTrend.perDay).toFixed(2)}` : ""}</span>
      </div>
    `;
  }

  let resetsHtml = "";
  if (acc.resets && acc.resets.count > 0) {
    const untilStr = acc.resets.until ? fmtMonthDayTime(acc.resets.until) : "";
    resetsHtml = `
      <div class="mp-reset-card-badge">
        ${icon("retry", 12)}
        <span>${t("mp_resets_card", { n: acc.resets.count })} ${untilStr ? `· ${untilStr}前有效` : ""}</span>
      </div>
    `;
  }

  let errorHtml = "";
  if (acc.error) {
    errorHtml = `<div class="mp-acc-error">${escHtml(acc.error)}</div>`;
  }

  return `
    <div class="mp-account-row">
      ${userDisp || planDisp ? `
        <div class="mp-acc-head">
          <span class="mp-acc-email ${isMaskedCls}" title="${escAttr(userDisp)}">${escHtml(userDisp)}</span>
          ${planDisp ? `<span class="mp-acc-plan">${escHtml(planDisp)}</span>` : ""}
        </div>
      ` : ""}
      ${windowsHtml}
      ${balanceHtml}
      ${dailyHtml}
      ${resetsHtml}
      ${errorHtml}
    </div>
  `;
}

function renderMagpieQuotas(quotas, container) {
  if (!container) return;
  if (!quotas || !quotas.length) {
    container.innerHTML = `<div class="gempty" style="grid-column:1/-1;">${escHtml(t("mp_empty"))}</div>`;
    return;
  }
  const groups = {};
  quotas.forEach(q => {
    const p = q.provider || "other";
    if (!groups[p]) {
      groups[p] = {
        provider: p,
        name: q.name || p,
        items: []
      };
    }
    groups[p].items.push(q);
  });

  const PROV_ORDER = ["antigravity", "agy", "dim", "codex", "grok", "kiro", "workbuddy-ai", "our-free-model", "openrouter", "deepseek"];
  const sortedKeys = Object.keys(groups).sort((a, b) => {
    const ia = PROV_ORDER.indexOf(a) !== -1 ? PROV_ORDER.indexOf(a) : 99;
    const ib = PROV_ORDER.indexOf(b) !== -1 ? PROV_ORDER.indexOf(b) : 99;
    return ia - ib;
  });

  const cardsHtml = sortedKeys.map(p => {
    const g = groups[p];
    const primary = g.items[0];
    const secondaries = g.items.slice(1);
    const hasSec = secondaries.length > 0;
    const provIcon = (p === "antigravity" || p === "agy" ? "spark" : p === "dim" ? "cpu" : p === "codex" ? "bolt" : p === "workbuddy-ai" ? "cpu" : p === "deepseek" ? "spark" : p === "kiro" ? "spark" : p === "grok" ? "bolt" : p === "openrouter" ? "network" : "box");
    const provCol = (p === "antigravity" || p === "agy" ? "#c084fc" : p === "dim" ? "#10b981" : p === "codex" ? "#10b981" : p === "workbuddy-ai" ? "#06b6d4" : p === "deepseek" ? "#3b82f6" : p === "kiro" ? "#8b5cf6" : p === "grok" ? "#e2e8f0" : p === "openrouter" ? "#f59e0b" : "#64748b");
    const pDisplayName = (p === "antigravity" || p === "agy" ? "Antigravity (Gemini & Claude)" : p === "dim" ? "dim" : p === "grok" ? "Grok (SuperGrok)" : g.name);

    return `
      <div class="mp-quota-card" data-provider="${escAttr(p)}">
        <div class="mp-quota-head">
          <div class="mp-quota-provider" style="color:${provCol};">
            ${quotaProvIcon(primary.icon, provIcon)} <span>${escHtml(pDisplayName)}</span>
          </div>
          ${hasSec ? `
            <button class="mp-expand-btn" data-target="mp-sec-${escAttr(p)}" type="button">
              ${escHtml(t("mp_expand_accounts", { n: secondaries.length }))}
            </button>
          ` : ""}
        </div>
        <div class="mp-primary-account">
          ${renderAccountRow(primary, p)}
        </div>
        ${hasSec ? `
          <div class="mp-secondary-accounts" id="mp-sec-${escAttr(p)}" hidden>
            ${secondaries.map(sec => renderAccountRow(sec, p, true)).join("")}
          </div>
        ` : ""}
      </div>
    `;
  }).join("");

  container.innerHTML = cardsHtml;
}

async function loadMagpieUsage(period = "today", force = false) {
  if (BOOT.static && BOOT.magpieUsage) {
    if (period === "today") return BOOT.magpieUsage;
    return { ok: false, static: true, calls: 0, cost: 0, agents: [], models: [], series: [] };
  }
  if (!force && magpieUsageCache[period]) {
    return magpieUsageCache[period];
  }
  try {
    const r = await tlGet(`/api/magpie/usage?period=${encodeURIComponent(period)}`);
    if (r) {
      magpieUsageCache[period] = r;
      return r;
    }
  } catch (e) {
    console.warn("loadMagpieUsage error:", e);
  }
  return magpieUsageCache[period] || { ok: false, calls: 0, cost: 0, agents: [], models: [], series: [] };
}

function renderMagpieUsage(d) {
  const el = $("agent-view-usage");
  if (!el || !d) return;
  curMagpieData = d;

  const kpisEl = $("mp-kpis");
  if (kpisEl) {
    const totalCalls = d.calls || 0;
    const estCost = fmtCost(d.cost);
    const totalTokens = (d.input || 0) + (d.output || 0) + (d.reasoning || 0) + (d.cache_read || 0);
    const inTokens = d.input || 0;
    const cacheTokens = d.cache_read || 0;
    const cacheHit = (inTokens + cacheTokens > 0)
      ? ((cacheTokens / (inTokens + cacheTokens)) * 100).toFixed(1) + "%"
      : "—";
    const avgTtft = (d.timed && d.timed > 0)
      ? fmtLatency(d.ttft_ms / d.timed)
      : "—";

    kpisEl.innerHTML = `
      <div class="agent-kpi-card mp-kpi-card">
        <div class="agent-kpi-val mp-kpi-val" style="color:var(--c-blue);">${totalCalls.toLocaleString()}</div>
        <div class="agent-kpi-lbl">${escHtml(t("mp_kpi_calls"))}</div>
        <div class="mp-kpi-sub">${d.errors ? `<span style="color:var(--c-red);">${d.errors} ${escHtml(t("mp_errors"))}</span>` : `<span style="color:var(--c-green);">100% OK</span>`}</div>
      </div>
      <div class="agent-kpi-card mp-kpi-card">
        <div class="agent-kpi-val mp-kpi-val" style="color:var(--c-green);">${estCost}</div>
        <div class="agent-kpi-lbl">${escHtml(t("mp_kpi_cost"))}</div>
        <div class="mp-kpi-sub">${d.unpriced ? `${d.unpriced} unpriced` : "USD"}</div>
      </div>
      <div class="agent-kpi-card mp-kpi-card">
        <div class="agent-kpi-val mp-kpi-val">${fmtTokens(totalTokens)}</div>
        <div class="agent-kpi-lbl">${escHtml(t("mp_kpi_tokens"))}</div>
        <div class="mp-kpi-sub" title="${escAttr(t("mp_tokens_sub", { inp: fmtTokens(d.input), out: fmtTokens(d.output), rea: fmtTokens(d.reasoning), cac: fmtTokens(d.cache_read) }))}">
          ↓${fmtTokens(d.input)} · ↑${fmtTokens(d.output)} · ⚡${fmtTokens(d.reasoning)}
        </div>
      </div>
      <div class="agent-kpi-card mp-kpi-card">
        <div class="agent-kpi-val mp-kpi-val" style="color:var(--c-violet);">${cacheHit}</div>
        <div class="agent-kpi-lbl">${escHtml(t("mp_kpi_cache_hit"))}</div>
        <div class="mp-kpi-sub">Hit ${fmtTokens(cacheTokens)}</div>
      </div>
      <div class="agent-kpi-card mp-kpi-card">
        <div class="agent-kpi-val mp-kpi-val" style="color:var(--c-orange);">${avgTtft}</div>
        <div class="agent-kpi-lbl">${escHtml(t("mp_kpi_ttft"))}</div>
        <div class="mp-kpi-sub">${d.timed || 0} samples</div>
      </div>
    `;
  }

  const quotaGrid = $("mp-quota-grid");
  if (quotaGrid) {
    renderMagpieQuotas(d.quotas || [], quotaGrid);
  }

  const trendTitle = $("mp-trend-title");
  if (trendTitle) {
    trendTitle.textContent = (d.period === "today") ? t("mp_trend_title") : t("mp_trend_title_days");
  }
  const trendSub = $("mp-chart-summary");
  if (trendSub) {
    trendSub.textContent = `${(d.calls || 0).toLocaleString()} reqs · ${fmtCost(d.cost)}`;
  }
  const chartEl = $("mp-timeline-chart");
  if (chartEl) {
    const series = d.series || [];
    if (!series.length) {
      chartEl.innerHTML = `<div class="gempty" style="width:100%;">${escHtml(t("mp_empty"))}</div>`;
    } else {
      const maxCalls = Math.max(1, ...series.map(s => s.calls || 0));
      chartEl.innerHTML = series.map(s => {
        const calls = s.calls || 0;
        const pct = Math.max(calls > 0 ? 6 : 2, Math.round((calls / maxCalls) * 100));
        const tip = `${s.label}: ${calls} calls · ${fmtCost(s.cost)} · ${fmtTokens((s.input||0) + (s.output||0))} tokens`;
        const activeColor = calls > 0 ? "var(--ch-cpu)" : "rgba(128,128,128,.2)";
        return `
          <div class="mp-bar-col" title="${escHtml(tip)}">
            <div class="mp-bar-fill" style="height:${pct}%;background:${activeColor};"></div>
            <span class="mp-bar-label">${escHtml(s.label)}</span>
          </div>
        `;
      }).join("");
    }
  }

  const agentsList = $("mp-agents-list");
  if (agentsList) {
    const agents = (d.agents || []).slice().sort((a, b) => (b.calls || 0) - (a.calls || 0));
    const totalCalls = d.calls || 1;
    if (!agents.length) {
      agentsList.innerHTML = `<div class="gempty">${escHtml(t("mp_empty"))}</div>`;
    } else {
      agentsList.innerHTML = agents.map(a => {
        const pct = Math.min(100, Math.round(((a.calls || 0) / totalCalls) * 100));
        const totalTokens = (a.input || 0) + (a.output || 0) + (a.reasoning || 0) + (a.cache_read || 0);
        return `
          <div class="mp-item">
            <div class="mp-item-header">
              <span class="mp-item-name">${icon(a.icon || "bolt", 14)} <span>${escHtml(a.name || a.id)}</span></span>
              <span class="mp-item-stats">
                <span style="font-weight:600;color:var(--text-title);">${(a.calls || 0).toLocaleString()}</span>
                <span style="color:var(--c-green);">${fmtCost(a.cost)}</span>
              </span>
            </div>
            <div class="mp-track">
              <div class="mp-track-fill" style="width:${pct}%;"></div>
            </div>
            <div class="mp-item-header" style="font-size:11px;color:var(--text-dim);">
              <span>${fmtTokens(totalTokens)} tk (${fmtTokens(a.input)} in / ${fmtTokens(a.output)} out)</span>
              <span>${a.timed ? `TTFT ${fmtLatency(a.ttft_ms / a.timed)}` : ""} ${a.errors ? `· <span style="color:var(--c-red);">${a.errors} err</span>` : ""}</span>
            </div>
          </div>
        `;
      }).join("");
    }
  }

  const modelsList = $("mp-models-list");
  if (modelsList) {
    const models = (d.models || []).slice().sort((a, b) => (b.calls || 0) - (a.calls || 0));
    const totalCalls = d.calls || 1;
    if (!models.length) {
      modelsList.innerHTML = `<div class="gempty">${escHtml(t("mp_empty"))}</div>`;
    } else {
      modelsList.innerHTML = models.slice(0, 15).map(m => {
        const pct = Math.min(100, Math.round(((m.calls || 0) / totalCalls) * 100));
        const totalTokens = (m.input || 0) + (m.output || 0) + (m.reasoning || 0) + (m.cache_read || 0);
        const spd = fmtSpeed(m.decode_ms, m.decode_out);
        return `
          <div class="mp-item">
            <div class="mp-item-header">
              <span class="mp-item-name" title="${escHtml(m.name || m.id)}">${icon("spark", 13)} <span>${escHtml(m.name || m.id)}</span></span>
              <span class="mp-item-stats">
                <span style="font-weight:600;color:var(--text-title);">${(m.calls || 0).toLocaleString()}</span>
                <span style="color:var(--c-green);">${fmtCost(m.cost)}</span>
              </span>
            </div>
            <div class="mp-track">
              <div class="mp-track-fill" style="width:${pct}%;background:var(--c-violet);"></div>
            </div>
            <div class="mp-item-header" style="font-size:11px;color:var(--text-dim);">
              <span>${escHtml(m.sub || m.provider || "")}</span>
              <span>${fmtTokens(totalTokens)} tk · ${spd !== "—" ? spd : `TTFT ${fmtLatency(m.ttft_ms / (m.timed || 1))}`}</span>
            </div>
          </div>
        `;
      }).join("");
    }
  }

  const accountsGrid = $("mp-accounts-grid");
  if (accountsGrid) {
    const accounts = d.accounts || [];
    if (!accounts.length) {
      accountsGrid.innerHTML = `<div class="gempty" style="grid-column:1/-1;">${escHtml(t("mp_empty"))}</div>`;
    } else {
      accountsGrid.innerHTML = accounts.map(acc => {
        const totalTokens = (acc.input || 0) + (acc.output || 0) + (acc.reasoning || 0) + (acc.cache_read || 0);
        return `
          <div class="mp-account-card">
            <div class="mp-account-top">
              <span class="mp-account-name" title="${escHtml(acc.name || acc.account || "")}">${escHtml(acc.name || acc.account || "Account")}</span>
              <span class="mp-account-badge">${escHtml(acc.provider || "gateway")}</span>
            </div>
            <div class="mp-account-meta">
              <span><b>${(acc.calls || 0).toLocaleString()}</b> reqs</span>
              <span><b>${fmtCost(acc.cost)}</b></span>
              <span>${fmtTokens(totalTokens)} tokens</span>
              ${acc.errors ? `<span style="color:var(--c-red);"><b>${acc.errors}</b> err</span>` : ""}
            </div>
          </div>
        `;
      }).join("");
    }
  }

  const freshEl = $("mp-fresh-time");
  if (freshEl && d.fetched_at) {
    const dateStr = new Date(d.fetched_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    freshEl.textContent = `Updated ${dateStr}`;
  }
}

async function refreshMagpieUsage(force = false) {
  const container = $("agent-view-usage");
  if (!container || container.hidden) return;
  const d = await loadMagpieUsage(curMagpiePeriod, force);
  renderMagpieUsage(d);
}

async function loadMagpieRouting(force = false) {
  if (BOOT.static && BOOT.magpieRouting) return BOOT.magpieRouting;
  if (!force && magpieRoutingCache) return magpieRoutingCache;
  try {
    const r = await tlGet("/api/magpie/routing");
    if (r) { magpieRoutingCache = r; return r; }
  } catch (e) { console.warn("loadMagpieRouting error:", e); }
  return magpieRoutingCache || { ok: false, routes: [], totals: {} };
}


let curRoutingPicked = null;
let routingResizeObs = null;
let routingReqTab = "all";
let routingBySession = false;
let routingMaskAccounts = false;
let curRoutingAccountFilter = null;
let curRoutingGroupFilter = null;
let ctxActiveTab = "all";
let ctxShowAll = false;
let curRoutingGroupEdit = null;

const ROUTE_OPTS = [["", "Smart"], ["order", "In order"], ["rotate", "In turn"], ["usage", "Least used"]];
const AFF_OPTS = [["", "Auto"], ["session", "Session"], ["turn", "Within a turn"], ["off", "Off"]];
const AFF_HINT = {
  "": "A conversation stays with the account or key that answered it while what the vendor cached of it is worth keeping — within a turn always, across turns while it's fresh.",
  session: "A conversation stays with the account or key that answered it for the whole session, while it can answer.",
  turn: "A conversation stays put within a turn, while the agent sends tool results back; when you speak again, routing decides afresh.",
  off: "Every request is routed afresh, whoever answered its conversation before.",
};
const GROUP_HINT = {
  "": "Smart, over every member's accounts and keys together: of the subscriptions with quota to spare, the one whose allowance renews soonest goes first; one resting after a failure goes last.",
  order: "In order: the first model until it can't answer, then the next — each over its own accounts or keys as its provider routes them.",
  rotate: "In turn: each conversation's next turn goes to the next member's account or key, spreading the load.",
  usage: "Least used first: the account or key with the most of its allowance left goes first.",
};
const EFFORT_OPTS = ["low", "medium", "high", "xhigh", "max"];

function splitMemberId(id) {
  id = id || "";
  if (id.startsWith("group/")) return [id, ""];
  const m = /^(.+):(none|minimal|low|medium|high|xhigh|max)$/i.exec(id);
  return m ? [m[1], m[2].toLowerCase()] : [id, ""];
}

function ruleSummaryText(r) {
  const bits = [];
  if (r.tokens) bits.push(`≥ ${Number(r.tokens).toLocaleString()} tokens`);
  if (r.images) bits.push("has an image");
  if (r.effort) bits.push(r.effort === "on" ? "reasoning on" : `reasoning ≥ ${r.effort}`);
  if (r.agents && r.agents.length) bits.push(r.agents.join(" / "));
  if (r.intent) bits.push(`asks for “${r.intent}”`);
  return bits.join(" · ") || "default rule";
}

function getRoutingModesMap() {
  return {
    "": [t("rt_mode_smart"), t("rt_mode_smart_desc")],
    order: [t("rt_mode_order"), t("rt_mode_order_desc")],
    rotate: [t("rt_mode_rotate"), t("rt_mode_rotate_desc")],
    usage: [t("rt_mode_usage"), t("rt_mode_usage_desc")]
  };
}

function showRoutingToolsModal(r) {
  if (!r) return;
  const parts = r.prompt?.parts || [];
  const toolsPart = parts.find(p => p.kind === "tools");
  const resultsPart = parts.find(p => p.kind === "results");
  const declaredTools = toolsPart?.items || [];
  const toolResults = resultsPart?.items || [];

  const overlay = document.createElement("div");
  overlay.className = "rt-modal-overlay";
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  let toolsListHtml = "";
  if (declaredTools.length) {
    toolsListHtml = declaredTools.map(item => `
      <div class="rt-tool-item">
        <span class="ic">${renderProviderIcon("tools", "T")}</span>
        <span class="t-name">${escHtml(item.name || "tool")}</span>
        <span class="t-tokens">${fmtTokens(item.tokens || 0)} tokens</span>
      </div>
    `).join("");
  } else {
    toolsListHtml = `<div class="gempty" style="padding:16px;">${t("rt_tools_none")}</div>`;
  }

  let resultsListHtml = "";
  if (toolResults.length) {
    resultsListHtml = toolResults.map(item => `
      <div class="rt-tool-item">
        <span class="ic">${renderProviderIcon("tools", "T")}</span>
        <span class="t-name">${escHtml(item.name || "tool")}</span>
        <span style="font-size:11px;color:var(--accent);margin-left:auto;">${item.n ? t("rt_tools_calls_count", { n: item.n }) : ""}</span>
        <span class="t-tokens">${fmtTokens(item.tokens || 0)} tokens</span>
      </div>
    `).join("");
  }

  overlay.innerHTML = `
    <div class="rt-modal-card">
      <div class="rt-modal-head">
        <div>
          <b>${t("rt_tools_title")}</b>
          <span style="font-size:11px;color:var(--muted);margin-left:8px;">#${escHtml(String(r.seq || r.id || ""))} · ${escHtml(r.agent || "agent")}</span>
        </div>
        <button type="button" class="rt-modal-close-btn" aria-label="${t("rt_modal_close")}">✕</button>
      </div>
      <div class="rt-modal-body">
        <div style="font-size:12px;color:var(--text-soft);">${t("rt_tools_desc")}</div>
        <div>
          <b style="font-size:12px;display:block;margin-bottom:6px;">${t("rt_tools_declared")} (${declaredTools.length})</b>
          <div style="display:grid;gap:6px;">${toolsListHtml}</div>
        </div>
        ${toolResults.length ? `
          <div style="margin-top:8px;">
            <b style="font-size:12px;display:block;margin-bottom:6px;">${t("rt_tools_results")} (${toolResults.length})</b>
            <div style="display:grid;gap:6px;">${resultsListHtml}</div>
          </div>
        ` : ""}
      </div>
    </div>
  `;
  overlay.querySelector(".rt-modal-close-btn").onclick = () => overlay.remove();
  document.body.appendChild(overlay);
}

function showRoutingPolicyModal(curMode) {
  const overlay = document.createElement("div");
  overlay.className = "rt-modal-overlay";
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  const policies = [
    { id: "", key: "smart", title: t("rt_mode_smart"), desc: t("rt_mode_smart_desc") },
    { id: "order", key: "order", title: t("rt_mode_order"), desc: t("rt_mode_order_desc") },
    { id: "rotate", key: "rotate", title: t("rt_mode_rotate"), desc: t("rt_mode_rotate_desc") },
    { id: "usage", key: "usage", title: t("rt_mode_usage"), desc: t("rt_mode_usage_desc") }
  ];

  overlay.innerHTML = `
    <div class="rt-modal-card">
      <div class="rt-modal-head">
        <b>${t("rt_policy_title")}</b>
        <button type="button" class="rt-modal-close-btn" aria-label="${t("rt_modal_close")}">✕</button>
      </div>
      <div class="rt-modal-body">
        <div class="rt-policy-grid">
          ${policies.map(p => {
            const isActive = (p.id === curMode || (!curMode && p.key === "smart"));
            return `
              <div class="rt-policy-item ${isActive ? "active" : ""}">
                <b>${isActive ? "✓ " : ""}${escHtml(p.title)}</b>
                <p>${escHtml(p.desc)}</p>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    </div>
  `;
  overlay.querySelector(".rt-modal-close-btn").onclick = () => overlay.remove();
  document.body.appendChild(overlay);
}

function setGlobalAccountsMask(masked) {
  routingMaskAccounts = masked;
  curAccountMasked = masked;
  document.body.classList.toggle("masking", masked);
  const rtMask = $("rtMask");
  if (rtMask) {
    rtMask.setAttribute("aria-pressed", String(masked));
    const sp = rtMask.querySelector("span");
    if (sp) sp.textContent = masked ? t("mp_show_accounts") : t("mp_hide_accounts");
  }
  const btnMask = $("mp-btn-mask");
  if (btnMask) {
    btnMask.classList.toggle("active", masked);
    const lbl = $("mp-mask-label");
    if (lbl) lbl.textContent = masked ? t("mp_show_accounts") : t("mp_mask_toggle");
  }
  document.querySelectorAll(".mp-acc-email").forEach(el => {
    el.classList.toggle("is-masked", masked);
  });
}

const RTHUES = {
  claude: "#d97757", codex: "#6366f1", gemini: "#0ea5e9", copilot: "#a855f7",
  cursor: "#14b8a6", opencode: "#eab308", crush: "#ec4899", goose: "#84cc16",
  pi: "#10b981", omp: "#f43f5e", dsh: "#06b6d4", commandcode: "#f97316",
  mimocode: "#3b82f6", hermes: "#a855f7"
};
const RTSPARE = ["#8b5cf6", "#22c55e", "#e11d48", "#0891b2", "#ca8a04", "#db2777", "#2563eb", "#65a30d"];

function rtHue(id) {
  if (!id) return "#8b5cf6";
  const k = String(id).toLowerCase();
  if (RTHUES[k]) return RTHUES[k];
  let h = 0;
  for (let i = 0; i < k.length; i++) h = (h * 31 + k.charCodeAt(i)) >>> 0;
  return RTSPARE[h % RTSPARE.length];
}

function rtTook(ms) {
  if (ms === undefined || ms === null) return t("rt_ms", { n: 0 });
  return ms < 1000 ? t("rt_ms", { n: Math.round(ms) }) : t("rt_sec", { n: (ms / 1000).toFixed(ms < 10000 ? 1 : 0) });
}

function rtDur(ms) {
  const s = Math.max(1, Math.round(ms / 1000));
  if (s < 60) return t("rt_sec", { n: s });
  const m = Math.round(s / 60);
  if (m < 60) return t("rt_min", { n: m });
  const h = Math.floor(m / 60), mm = m % 60;
  if (h < 10 && mm) return `${t("rt_hr", { n: h })} ${t("rt_min", { n: mm })}`;
  if (h < 48) return t("rt_hr", { n: Math.round(m / 60) });
  return t("rt_day", { n: Math.round(m / 1440) });
}

function rtClock(isoStr) {
  if (!isoStr) return "";
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
}

function rtTimeFull(isoStr) {
  if (!isoStr) return "";
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
}

function layoutRoutingWires() {
  const stage = document.querySelector("#rt .rt-stage");
  if (!stage) return;
  const wires = stage.querySelector(".rt-wires");
  const hub = stage.querySelector(".rt-hub");
  const srcs = stage.querySelector(".rt-srcs");
  const list = stage.querySelector(".rt-accts");
  if (!wires || !hub || !srcs || !list) return;

  const r = stage.getBoundingClientRect();
  if (!r.width || !r.height) return;

  const b = (e) => {
    const x = e.getBoundingClientRect();
    return {
      l: x.left - r.left,
      r: x.right - r.left,
      t: x.top - r.top,
      b: x.bottom - r.top,
      cx: (x.left + x.right) / 2 - r.left,
      cy: (x.top + x.bottom) / 2 - r.top
    };
  };

  wires.setAttribute("viewBox", `0 0 ${r.width} ${r.height}`);
  const h = b(hub);
  const low = b(srcs).b;

  const agentNodes = stage.querySelectorAll(".rt-src");
  agentNodes.forEach(node => {
    const wire = node.__wire;
    if (!wire) return;
    const s = b(node);
    const mx = (s.r + h.l) / 2;
    if (h.l > s.r) {
      wire.setAttribute("d", `M${s.r} ${s.cy} C${mx} ${s.cy} ${mx} ${h.cy} ${h.l} ${h.cy}`);
    } else {
      wire.setAttribute("d", `M${s.cx} ${s.b} L${h.cx} ${h.t}`);
    }
  });

  const fromHub = (a) => {
    if (a.l > h.r) {
      const mx = (h.r + a.l) / 2;
      return `M${h.r} ${h.cy} C${mx} ${h.cy} ${mx} ${a.cy} ${a.l} ${a.cy}`;
    }
    const x = a.l - 12, y = Math.max(h.b, low - 8);
    return `M${h.cx} ${h.b} L${h.cx} ${y} C${h.cx} ${y + 22} ${x} ${y + 2} ${x} ${y + 24} L${x} ${a.cy - 10} Q${x} ${a.cy} ${a.l} ${a.cy}`;
  };

  const narrow = mqMobile.matches;
  const rowItems = list.querySelectorAll("li:not(.idle)");
  rowItems.forEach(row => {
    const wire = row.__wire;
    if (!wire) return;
    if (narrow) { wire.setAttribute("d", ""); return; }
    wire.setAttribute("d", fromHub(b(row)));
  });
}

function renderGroupRowHtml(g, isCur) {
  const modesMap = getRoutingModesMap();
  const gid = g.id || g.name || "group";
  const sep = g.routing === "order" ? " → " : " · ";
  const membersStr = (g.members || []).map(m => escHtml(m)).join(sep);
  const mLabel = modesMap[g.routing || ""]?.[0] || t("rt_mode_smart");
  const affLabel = g.affinity ? (AFF_OPTS.find(x => x[0] === g.affinity)?.[1] || g.affinity) : "";
  const rulesCount = (g.rules || []).length;
  const rulesTitle = (g.rules || []).map((r, i) => `${i + 1}. ${ruleSummaryText(r)} → ${r.use || ''}`).join("\n");

  return `
    <div class="rt-group ${isCur ? 'active' : ''}" data-gid="${escAttr(gid)}">
      <span class="ics" style="display:flex;gap:3px;align-items:center;">
        <span class="ic" style="width:18px;height:18px;">${renderProviderIcon(g.members?.[0] || 'default', 'G')}</span>
      </span>
      <div class="main">
        <div class="nm">
          <b>${escHtml(g.name || gid)}</b>
          <code class="mdl">group/${escHtml(gid)}</code>
          ${g.auto ? `<small class="auto">found by magpie</small>` : ''}
        </div>
        <div class="mem">${membersStr}</div>
      </div>
      <span class="tags">
        <span class="tag">${escHtml(mLabel)}</span>
        ${affLabel ? `<span class="tag">${escHtml(affLabel)}</span>` : ''}
        ${rulesCount ? `<span class="tag" title="${escAttr(rulesTitle)}">${rulesCount === 1 ? '1 rule' : rulesCount + ' rules'}</span>` : ''}
      </span>
      <button type="button" class="text btn-edit-group" data-gid="${escAttr(gid)}">${t("rt_edit")}</button>
    </div>
  `;
}

function renderGroupEditorHtml(g, d, models, deciders) {
  const modesMap = getRoutingModesMap();
  const isNew = !g;
  const gid = g ? (g.id || g.name) : "";
  const routing = d.routing || "";
  const affinity = d.affinity || "";
  const effort = d.effort || "";
  const rules = d.rules || [];
  const members = d.members || [];
  const hasIntents = rules.some(r => (r.intent || "").trim().length > 0);
  const showClassifier = effort === "auto" || hasIntents;

  const rHint = GROUP_HINT[routing] || GROUP_HINT[""];
  const aHint = AFF_HINT[affinity] || AFF_HINT[""];

  return `
    <div class="editor rt-gedit" data-gid="${escAttr(gid)}">
      <div class="ehead">
        <b>${isNew ? t("rt_new_group") : escHtml(g.name || gid)}</b>
        ${g?.auto ? `<span class="note">found by magpie — saving a change makes it yours</span>` : ''}
      </div>

      <label>Name</label>
      <div>
        <input type="text" class="g-in-name" value="${escAttr(d.name || '')}" placeholder="e.g. Opus anywhere" style="width:100%;max-width:320px;">
        <div class="hint">Agents pick it as <code>group/${escHtml(d.id || d.name || 'group')}</code></div>
      </div>

      ${!isNew ? `
        <label>ID</label>
        <div>
          <input type="text" class="g-in-id" value="${escAttr(d.id || gid)}" style="width:100%;max-width:320px;">
        </div>
      ` : ''}

      <label>Models</label>
      <div>
        <div class="fallback">
          <div class="fbl" id="gedit-members-list">
            ${members.map((mId, i) => {
              const [baseMdl, fixedEffort] = splitMemberId(mId);
              const mObj = models.find(x => x.id === baseMdl || x.id === mId) || { id: mId, providerName: "Provider" };
              const fixedLabel = fixedEffort ? `${fixedEffort} reasoning` : t("rt_follow_group");
              return `
                <div class="fbrow" data-idx="${i}">
                  <span class="i">${i + 1}</span>
                  <span class="ic">${renderProviderIcon(mObj.icon || mId, mId[0])}</span>
                  <span class="n">
                    <b>${escHtml(mObj.name || mId)}</b>
                    <small>${escHtml(mObj.providerName || "")}</small>
                  </span>
                  <button type="button" class="rt-cond rt-fixed btn-member-effort ${fixedEffort ? 'on' : ''}" data-idx="${i}" title="${fixedEffort ? 'Fixed reasoning' : 'Follow group'}">
                    ${escHtml(fixedLabel)}
                  </button>
                  ${i > 0 ? `<button type="button" class="text btn-member-up" data-idx="${i}">Up</button>` : ''}
                  <button type="button" class="text btn-member-rm" data-idx="${i}">${t("rt_remove")}</button>
                </div>
              `;
            }).join("")}
          </div>
          <button type="button" class="rt-gadd btn-add-member" style="margin-top:8px;">
            <span>＋ ${t(members.length ? "rt_add_another_model" : "rt_add_model")}</span>
          </button>
        </div>
        <div class="hint">The first answers for what the model can do. In order, they are tried top first.</div>
      </div>

      <label>${t("rt_routing_lbl")}</label>
      <div>
        <div class="segs gedit-routing-segs">
          ${ROUTE_OPTS.map(([k, lbl]) => `
            <span class="opt ${routing === k ? 'on' : ''}" data-val="${k}">${escHtml(t(modesMap[k]?.[0] || lbl))}</span>
          `).join("")}
        </div>
        <div class="hint" id="gedit-routing-hint">${escHtml(rHint)}</div>
      </div>

      <label>${t("rt_stays_lbl")}</label>
      <div>
        <div class="segs gedit-stays-segs">
          ${AFF_OPTS.map(([k, lbl]) => `
            <span class="opt ${affinity === k ? 'on' : ''}" data-val="${k}">${escHtml(lbl)}</span>
          `).join("")}
        </div>
        <div class="hint" id="gedit-stays-hint">${escHtml(aHint)}</div>
      </div>

      <label>${t("rt_rules_lbl")}</label>
      <div>
        <div class="fallback rt-rules">
          <div class="fbl" id="gedit-rules-list">
            ${rules.map((r, i) => {
              const tokensVal = r.tokens || "";
              const hasImg = !!r.images;
              const effortVal = r.effort || "";
              const agentVal = (r.agents && r.agents.length) ? r.agents.join(", ") : "any agent";
              const intentVal = r.intent || "";
              const targetMdl = r.use || members[0] || "";

              return `
                <div class="rt-rule" data-idx="${i}">
                  <span class="i">${i + 1}</span>
                  <div class="when" style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;">
                    <span class="w" style="color:var(--muted);font-size:12px;">When</span>
                    <span class="rt-cond tk ${tokensVal ? 'on' : ''}">
                      <span>≥</span>
                      <input type="number" class="rule-in-tokens" data-idx="${i}" value="${escAttr(String(tokensVal))}" style="width:70px;background:none;border:none;color:inherit;outline:none;" placeholder="tokens">
                      <span>tokens</span>
                    </span>
                    <button type="button" class="rt-cond btn-rule-img ${hasImg ? 'on' : ''}" data-idx="${i}">has an image</button>
                    <button type="button" class="rt-cond btn-rule-effort ${effortVal ? 'on' : ''}" data-idx="${i}">
                      ${effortVal ? `reasoning ≥ ${effortVal}` : 'any reasoning'}
                    </button>
                    <button type="button" class="rt-cond btn-rule-agent ${r.agents?.length ? 'on' : ''}" data-idx="${i}">
                      ${escHtml(agentVal)}
                    </button>
                    <span class="rt-cond in ${intentVal ? 'on' : ''}">
                      <span>asks for</span>
                      <input type="text" class="rule-in-intent" data-idx="${i}" value="${escAttr(intentVal)}" placeholder="e.g. writing tests" style="width:140px;background:none;border:none;color:inherit;outline:none;">
                    </span>
                  </div>
                  <div class="rt-use" style="display:flex;align-items:center;gap:6px;margin-top:4px;">
                    <span class="w" style="color:var(--muted);font-size:12px;">send to</span>
                    <button type="button" class="rt-cond on btn-rule-use" data-idx="${i}">
                      <span>${escHtml(targetMdl)}</span>
                    </button>
                  </div>
                  <span class="ctl" style="display:flex;gap:4px;align-items:center;">
                    ${i > 0 ? `<button type="button" class="text btn-rule-up" data-idx="${i}">Up</button>` : ''}
                    <button type="button" class="text btn-rule-rm" data-idx="${i}">${t("rt_remove")}</button>
                  </span>
                </div>
              `;
            }).join("")}
          </div>
          <button type="button" class="rt-gadd btn-add-rule" style="margin-top:8px;">
            <span>＋ ${t("rt_add_rule")}</span>
          </button>
        </div>
        <div class="hint">Checked top first when you send a message: the first that matches sends that turn to its model first.</div>
      </div>

      <label>${t("rt_effort_lbl")}</label>
      <div>
        <div class="segs gedit-effort-segs">
          <span class="opt ${!effort ? 'on' : ''}" data-val="">Agent's</span>
          <span class="opt ${effort === 'auto' ? 'on' : ''}" data-val="auto">Picked per turn</span>
        </div>
        <div class="hint">${effort === 'auto' ? "As a turn begins, the classifier rates how hard it is..." : "Each request reasons as much as the agent asked."}</div>
      </div>

      ${showClassifier ? `
        <label>${t("rt_classifier_lbl")}</label>
        <div>
          <button type="button" class="rt-cond on btn-pick-classifier">
            <span>${escHtml(d.classifier || deciders[0]?.id || "opencode-zen/jev-1.13-free")}</span>
          </button>
          <div class="hint">As a turn begins, this model is asked which intent matches.</div>
        </div>
      ` : ''}

      <div class="bar">
        ${!isNew ? `<button type="button" class="text danger btn-del-group">${t("rt_remove")}</button>` : ''}
        <span class="grow"></span>
        <button type="button" class="text btn-cancel-group">${t("rt_cancel")}</button>
        <button type="button" class="text primary btn-save-group">${t("rt_save")}</button>
      </div>
    </div>
  `;
}

function bindGroupEvents(container, gItems, availableModels, availableDeciders) {
  container.querySelectorAll(".rt-group").forEach(el => {
    el.onclick = (e) => {
      if (e.target.closest("button")) return;
      const gid = el.dataset.gid;
      if (curRoutingGroupEdit && curRoutingGroupEdit.id === gid) {
        curRoutingGroupEdit = null;
      } else {
        const targetG = gItems.find(x => (x.id || x.name) === gid) || { id: gid, name: gid, members: [], rules: [] };
        curRoutingGroupEdit = { id: gid, draft: JSON.parse(JSON.stringify(targetG)) };
      }
      renderMagpieRouting(curMagpieRoutingData);
    };
  });

  container.querySelectorAll(".btn-edit-group").forEach(btn => {
    btn.onclick = (e) => {
      e.stopPropagation();
      const gid = btn.dataset.gid;
      if (curRoutingGroupEdit && curRoutingGroupEdit.id === gid) {
        curRoutingGroupEdit = null;
      } else {
        const targetG = gItems.find(x => (x.id || x.name) === gid) || { id: gid, name: gid, members: [], rules: [] };
        curRoutingGroupEdit = { id: gid, draft: JSON.parse(JSON.stringify(targetG)) };
      }
      renderMagpieRouting(curMagpieRoutingData);
    };
  });

  const ed = container.querySelector(".rt-gedit");
  if (!ed || !curRoutingGroupEdit) return;
  const d = curRoutingGroupEdit.draft;

  const inName = ed.querySelector(".g-in-name");
  if (inName) { inName.oninput = () => { d.name = inName.value; }; }
  const inId = ed.querySelector(".g-in-id");
  if (inId) { inId.oninput = () => { d.id = inId.value; }; }

  ed.querySelectorAll(".btn-member-effort").forEach(btn => {
    btn.onclick = () => {
      const idx = parseInt(btn.dataset.idx, 10);
      const mId = d.members[idx];
      if (!mId) return;
      const [baseMdl, curEff] = splitMemberId(mId);
      const effCycle = ["", "low", "medium", "high", "max"];
      const nextEff = effCycle[(effCycle.indexOf(curEff) + 1) % effCycle.length];
      d.members[idx] = nextEff ? `${baseMdl}:${nextEff}` : baseMdl;
      renderMagpieRouting(curMagpieRoutingData);
    };
  });

  ed.querySelectorAll(".btn-member-up").forEach(btn => {
    btn.onclick = () => {
      const idx = parseInt(btn.dataset.idx, 10);
      if (idx > 0) {
        const tmp = d.members[idx];
        d.members[idx] = d.members[idx - 1];
        d.members[idx - 1] = tmp;
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  });

  ed.querySelectorAll(".btn-member-rm").forEach(btn => {
    btn.onclick = () => {
      const idx = parseInt(btn.dataset.idx, 10);
      d.members.splice(idx, 1);
      renderMagpieRouting(curMagpieRoutingData);
    };
  });

  const btnAddMember = ed.querySelector(".btn-add-member");
  if (btnAddMember) {
    btnAddMember.onclick = () => {
      const candidate = availableModels.find(m => !d.members.some(x => x.startsWith(m.id))) || availableModels[0];
      if (candidate) {
        d.members.push(candidate.id);
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  }

  ed.querySelectorAll(".gedit-routing-segs .opt").forEach(opt => {
    opt.onclick = () => {
      d.routing = opt.dataset.val;
      renderMagpieRouting(curMagpieRoutingData);
    };
  });

  ed.querySelectorAll(".gedit-stays-segs .opt").forEach(opt => {
    opt.onclick = () => {
      d.affinity = opt.dataset.val;
      renderMagpieRouting(curMagpieRoutingData);
    };
  });

  ed.querySelectorAll(".rule-in-tokens").forEach(inp => {
    inp.oninput = () => {
      const idx = parseInt(inp.dataset.idx, 10);
      if (d.rules[idx]) {
        d.rules[idx].tokens = parseInt(inp.value, 10) || 0;
        inp.closest(".rt-cond")?.classList.toggle("on", !!d.rules[idx].tokens);
      }
    };
  });

  ed.querySelectorAll(".btn-rule-img").forEach(btn => {
    btn.onclick = () => {
      const idx = parseInt(btn.dataset.idx, 10);
      if (d.rules[idx]) {
        d.rules[idx].images = !d.rules[idx].images;
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  });

  ed.querySelectorAll(".btn-rule-effort").forEach(btn => {
    btn.onclick = () => {
      const idx = parseInt(btn.dataset.idx, 10);
      if (d.rules[idx]) {
        const cycle = ["", "on", "low", "medium", "high", "max"];
        const cur = d.rules[idx].effort || "";
        d.rules[idx].effort = cycle[(cycle.indexOf(cur) + 1) % cycle.length];
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  });

  ed.querySelectorAll(".rule-in-intent").forEach(inp => {
    inp.oninput = () => {
      const idx = parseInt(inp.dataset.idx, 10);
      if (d.rules[idx]) {
        d.rules[idx].intent = inp.value;
        inp.closest(".rt-cond")?.classList.toggle("on", !!inp.value.trim());
      }
    };
  });

  ed.querySelectorAll(".btn-rule-use").forEach(btn => {
    btn.onclick = () => {
      const idx = parseInt(btn.dataset.idx, 10);
      if (d.rules[idx] && d.members.length) {
        const curUse = d.rules[idx].use || d.members[0];
        const nextIdx = (d.members.indexOf(curUse) + 1) % d.members.length;
        d.rules[idx].use = d.members[nextIdx];
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  });

  ed.querySelectorAll(".btn-rule-up").forEach(btn => {
    btn.onclick = () => {
      const idx = parseInt(btn.dataset.idx, 10);
      if (idx > 0 && d.rules[idx]) {
        const tmp = d.rules[idx];
        d.rules[idx] = d.rules[idx - 1];
        d.rules[idx - 1] = tmp;
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  });

  ed.querySelectorAll(".btn-rule-rm").forEach(btn => {
    btn.onclick = () => {
      const idx = parseInt(btn.dataset.idx, 10);
      if (d.rules[idx]) {
        d.rules.splice(idx, 1);
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  });

  const btnAddRule = ed.querySelector(".btn-add-rule");
  if (btnAddRule) {
    btnAddRule.onclick = () => {
      d.rules.push({ use: d.members[d.members.length - 1] || d.members[0] || "", tokens: 0, images: false, effort: "", agents: [], intent: "" });
      renderMagpieRouting(curMagpieRoutingData);
    };
  }

  ed.querySelectorAll(".gedit-effort-segs .opt").forEach(opt => {
    opt.onclick = () => {
      d.effort = opt.dataset.val;
      if (d.effort === "auto" && !d.classifier && availableDeciders.length) {
        d.classifier = availableDeciders[0].id;
      }
      renderMagpieRouting(curMagpieRoutingData);
    };
  });

  const btnPickClassifier = ed.querySelector(".btn-pick-classifier");
  if (btnPickClassifier) {
    btnPickClassifier.onclick = () => {
      const cycle = availableDeciders.map(x => x.id);
      if (cycle.length) {
        const next = cycle[(cycle.indexOf(d.classifier) + 1) % cycle.length];
        d.classifier = next;
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  }

  const btnCancel = ed.querySelector(".btn-cancel-group");
  if (btnCancel) {
    btnCancel.onclick = () => {
      curRoutingGroupEdit = null;
      renderMagpieRouting(curMagpieRoutingData);
    };
  }

  const btnDel = ed.querySelector(".btn-del-group");
  if (btnDel) {
    btnDel.onclick = () => {
      if (BOOT.static) {
        toast(t("rt_static_readonly_hint"));
        curRoutingGroupEdit = null;
        renderMagpieRouting(curMagpieRoutingData);
        return;
      }
      const idx = gItems.findIndex(x => (x.id || x.name) === curRoutingGroupEdit.id);
      if (idx >= 0) gItems.splice(idx, 1);
      curRoutingGroupEdit = null;
      renderMagpieRouting(curMagpieRoutingData);
    };
  }

  const btnSave = ed.querySelector(".btn-save-group");
  if (btnSave) {
    btnSave.onclick = () => {
      if (BOOT.static) {
        toast(t("rt_static_readonly_hint"));
        curRoutingGroupEdit = null;
        renderMagpieRouting(curMagpieRoutingData);
        return;
      }
      const gid = curRoutingGroupEdit.id;
      if (!gid) {
        gItems.unshift({ ...d, id: d.id || d.name || "new-group" });
      } else {
        const item = gItems.find(x => (x.id || x.name) === gid);
        if (item) Object.assign(item, d);
      }
      toast(t("rt_save") + " ✓");
      curRoutingGroupEdit = null;
      renderMagpieRouting(curMagpieRoutingData);
    };
  }
}

function renderMagpieRouting(data) {
  const el = $("agent-view-routing");
  if (!el || !data) return;
  curMagpieRoutingData = data;

  const box = $("rt");
  const more = $("rtMore");
  const maskBtn = $("rtMask");
  if (!box) return;

  if (maskBtn && !maskBtn.dataset.bound) {
    maskBtn.dataset.bound = "1";
    maskBtn.setAttribute("aria-pressed", String(routingMaskAccounts));
    maskBtn.onclick = () => {
      setGlobalAccountsMask(!routingMaskAccounts);
    };
  }

  const routes = data.routes || [];
  const totals = data.totals || {};
  const groups = data.groups || [];

  if (!routes.length) {
    box.innerHTML = `<div class="gempty" style="padding:48px 16px;">${escHtml(t("mp_empty"))}</div>`;
    if (more) more.innerHTML = "";
    return;
  }

  const curRoute = curRoutingPicked || routes[0];
  const group = (curRoutingGroupFilter && (data.groups || []).find(g => g.name === curRoutingGroupFilter)) || curRoute.group || { id: "default", name: "default", routing: "" };
  const routingMode = group.routing || "";
  const modesMap = getRoutingModesMap();
  const modeInfo = modesMap[routingMode] || modesMap[""];

  // Agents active on stage
  const recentAgents = [];
  const seenAgs = new Set();
  const activeRoutes = routes.slice(0, 10);
  for (const r of activeRoutes) {
    const ag = r.agent || "pi";
    if (!seenAgs.has(ag)) {
      seenAgs.add(ag);
      recentAgents.push({ id: ag, name: ag, model: r.model || "group/default" });
      if (recentAgents.length >= 3) break;
    }
  }
  if (!recentAgents.length) recentAgents.push({ id: "pi", name: "Pi", model: curRoute.model || "group/default" });

  box.innerHTML = "";

  const totalMs = curRoute.ms || 0;
  const ttftMs = curRoute.ttft || 0;
  const outTokens = curRoute.out || (curRoute.tokens?.output || 0) || 1200;
  const inTokens = curRoute.tokens?.input || curRoute.tokens || 0;
  const speed = (ttftMs && totalMs > ttftMs) ? Math.round(outTokens / ((totalMs - ttftMs) / 1000)) : 311;
  const targetProv = curRoute.provider || "DeepSeek";
  const targetMdl = curRoute.served || curRoute.model || "deepseek-flash";
  const winnerWho = curRoute.who || curRoute.id || curRoute.provider || "account";

  // 移动端专用清晰流水线卡片 (PC 宽屏保持原有 3 列连线并在 CSS 中隐藏此卡)
  const pipelineEl = document.createElement("div");
  pipelineEl.className = "rt-pipeline-m";

  const isAnswering = (curRoute.tries || []).some(tr => !tr.done);
  const statusBadge = isAnswering ? `🟢 ${t("rt_answering")}` : `🟢 200 OK (${rtTook(totalMs)})`;

  const recentChipsHtml = routes.slice(0, 8).map((r, i) => {
    const isPick = curRoute.id === r.id;
    const ag = r.agent || "pi";
    const prov = r.provider || "API";
    const timeStr = rtClock(r.time) || "";
    return `
      <button type="button" class="rt-m-req-chip ${isPick ? 'active' : ''}" data-idx="${i}">
        <span class="dot ${isPick ? 'live' : ''}"></span>
        <b>${escHtml(ag)}</b>
        <span style="opacity:0.4;">›</span>
        <em>${escHtml(prov)}</em>
        <small>${escHtml(timeStr)}</small>
      </button>
    `;
  }).join("");

  pipelineEl.innerHTML = `
    <div class="rt-m-reqs-bar">
      <span class="rt-m-reqs-label">${t("rt_recent_tasks")}</span>
      <div class="rt-m-reqs-scroll">${recentChipsHtml}</div>
    </div>
    <div class="rt-m-pipeline-card">
      <div class="rt-m-pipeline-title">
        <span><b>#${escHtml(String(curRoute.seq || curRoute.id || ""))}</b> · ${rtClock(curRoute.time) || ""}</span>
        <span>group/${escHtml(group.name || "default")}</span>
      </div>
      <div class="rt-m-flow">
        <!-- 任务发起 -->
        <div class="rt-m-node rt-m-src">
          <span class="rt-m-node-tag">${t("rt_task_source")}</span>
          <span class="rt-ic"><span class="ic">${renderProviderIcon(curRoute.agent || "pi", (curRoute.agent || "P")[0])}</span></span>
          <b>${escHtml(curRoute.agent || "pi")}</b>
          <code class="mdl">${escHtml(curRoute.model || "default")}</code>
        </div>
        <!-- 箭头 -->
        <div class="rt-m-arrow">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 5l7 7-7 7"/></svg>
        </div>
        <!-- 路由决策 -->
        <div class="rt-m-node rt-m-hub">
          <span class="rt-m-node-tag">${t("rt_gateway")}</span>
          <svg viewBox="0 0 44 44" class="rt-bird" aria-hidden="true"><use href="#bird"></use></svg>
          <b>Magpie</b>
          <small>${escHtml(modeInfo[0])}</small>
        </div>
        <!-- 箭头 -->
        <div class="rt-m-arrow">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 5l7 7-7 7"/></svg>
        </div>
        <!-- 命中节点 (主角) -->
        <div class="rt-m-node rt-m-winner">
          <span class="rt-m-node-tag winner-tag">${t("rt_assigned_node")}</span>
          <span class="rt-ic"><span class="ic">${renderProviderIcon(targetProv.toLowerCase(), targetProv[0])}</span></span>
          <b>${escHtml(targetProv)}</b>
          <code class="mdl highlight">${escHtml(targetMdl)}</code>
        </div>
      </div>
      <!-- 命中节点执行详情 -->
      <div class="rt-m-winner-summary">
        <div class="rt-m-winner-row1">
          <b>
            <span class="ic">${renderProviderIcon(targetProv.toLowerCase(), targetProv[0])}</span>
            <span class="pii">${escHtml(winnerWho)}</span>
            <code class="mdl">${escHtml(targetMdl)}</code>
          </b>
          <span class="rt-m-winner-status">${statusBadge}</span>
        </div>
        <div class="rt-m-winner-row2">
          <span>${t("rt_completed_in", { ms: rtTook(totalMs) })}</span>
          <span>TTFT <b>${rtTook(ttftMs)}</b></span>
          <span>${t("rt_speed_tok_s", { n: speed })}</span>
          <span>Token <b>${fmtTokens(inTokens)}</b> in / <b>${fmtTokens(outTokens)}</b> out</span>
        </div>
      </div>
    </div>
  `;

  pipelineEl.querySelectorAll(".rt-m-req-chip").forEach(btn => {
    btn.onclick = () => {
      const idx = Number(btn.dataset.idx);
      if (routes[idx]) {
        curRoutingPicked = routes[idx];
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  });
  box.appendChild(pipelineEl);

  // Top info (PC 端显示)
  const topEl = document.createElement("div");
  topEl.className = "rt-top";
  const orderList = curRoute.order || [];
  // 座位键与原版 magpie routing.js 一致(id+model), 精确匹配不到时回退 id:
  // 旧写法用 tr.who === w.who 兜底, 而 tries 根本没有 who 字段, 于是
  // undefined === undefined 把所有无 who 的座位都判成命中(实测 13/55 行全绿)
  const seatKey = (x) => (x.id || "") + "\u0000" + (x.model || "");
  const tryState = { trying: new Set(), answered: new Set() };
  for (const tr of (curRoute.tries || [])) {
    const hit = orderList.find(x => seatKey(x) === seatKey(tr)) || orderList.find(x => x.id && x.id === tr.id);
    const k = hit ? seatKey(hit) : seatKey(tr);
    if (!tr.done) tryState.trying.add(k);                            // 正在问它: 亮
    else if ((tr.status || 0) < 400) tryState.answered.add(k);       // 它答了: 亮
  }                                                                  // 报错转交/休息的座位不亮
  const enabledCount = orderList.filter(x => !x.fallback).length || orderList.length || 30;
  topEl.innerHTML = `
    <div class="rt-what" style="display:flex;align-items:center;flex-wrap:wrap;gap:6px;">
      <b>${escHtml(group.name || curRoute.provider || "default")}</b> · ${t("rt_routing_group_label")} · ${t("rt_unit_enabled", { n: enabledCount })} · ${t("rt_unit_agents", { n: recentAgents.length })}
      ${curRoutingPicked ? `
        <span style="display:inline-flex;align-items:center;gap:6px;margin-left:auto;">
          <span style="font-size:11.5px;color:var(--amber);background:rgba(255,159,10,0.1);padding:1px 7px;border-radius:4px;border:1px solid rgba(255,159,10,0.3);">
            #${escHtml(String(curRoute.seq || curRoute.id || ""))} · ${escHtml(rtClock(curRoute.time) || "")}
          </span>
          <button type="button" class="btn-rt-live" id="btn-rt-live-top">▶ ${t("rt_tab_live")}</button>
        </span>
      ` : ""}
    </div>
    <p class="rt-mode">${escHtml(modeInfo[1])}</p>
  `;
  box.appendChild(topEl);
  const btnLiveTop = topEl.querySelector("#btn-rt-live-top");
  if (btnLiveTop) {
    btnLiveTop.onclick = () => {
      curRoutingPicked = null;
      renderMagpieRouting(curMagpieRoutingData);
    };
  }

  // Stage
  const stageEl = document.createElement("div");
  stageEl.className = "rt-stage";
  const NS = "http://www.w3.org/2000/svg";
  const wiresSvg = document.createElementNS(NS, "svg");
  wiresSvg.setAttribute("class", "rt-wires");
  wiresSvg.setAttribute("aria-hidden", "true");

  // Sources (agents)
  const srcsEl = document.createElement("div");
  srcsEl.className = "rt-srcs" + (recentAgents.length > 1 ? " many" : "");

  recentAgents.forEach(a => {
    const node = document.createElement("div");
    node.className = "rt-node rt-src";
    const hue = rtHue(a.id);
    node.style.setProperty("--agent", hue);
    node.title = `${a.name} · ${t("rt_tools_title")}`;
    node.onclick = () => showRoutingToolsModal(curRoute);
    node.innerHTML = `
      <span class="rt-ic"><span class="ic">${renderProviderIcon(a.id, a.id[0])}</span></span>
      <b>${escHtml(a.name)}</b>
      <small>${escHtml(a.model)}</small>
    `;
    const wirePath = document.createElementNS(NS, "path");
    wirePath.style.setProperty("--agent", hue);
    if (curRoute.agent === a.id) {
      wirePath.classList.add("live");
    }
    wiresSvg.appendChild(wirePath);
    node.__wire = wirePath;
    srcsEl.appendChild(node);
  });

  // Hub (magpie)
  const hubEl = document.createElement("div");
  hubEl.className = "rt-node rt-hub";
  hubEl.innerHTML = `
    <svg viewBox="0 0 44 44" class="rt-bird" aria-hidden="true"><use href="#bird"></use></svg>
    <b>magpie</b>
    <small>127.0.0.1:3426</small>
    <i class="rt-go" title="${escAttr(t("rt_policy_title"))}">${escHtml(modeInfo[0])}</i>
  `;
  const hubGo = hubEl.querySelector("i.rt-go");
  if (hubGo) {
    hubGo.onclick = () => showRoutingPolicyModal(group.routing || "");
  }

  // Accounts & candidate seats list
  const acctsEl = document.createElement("ol");
  acctsEl.className = "rt-accts";

  orderList.forEach(w => {
    const rowLi = document.createElement("li");
    const rkey = seatKey(w);
    const isTrying = tryState.trying.has(rkey);
    const isAnswered = tryState.answered.has(rkey);
    const isWinner = isTrying || isAnswered;
    const isResting = !!w.rest;

    if (isWinner) rowLi.classList.add("on");
    if (isResting) rowLi.classList.add("rest");

    let stText = "";
    if (isTrying) stText = t("rt_answering");
    else if (isAnswered) stText = t("rt_answered");
    else if (isResting) stText = t("rt_resting");
    else if (w.known && w.used !== undefined) {
      const remain = Math.max(0, 100 - Math.round(w.used));
      stText = `${t("rt_remain_pct", { n: remain })} · ${t("rt_renews_days", { n: 15 })}`;
    } else if (w.credits) {
      stText = `${Number(w.credits).toLocaleString()} · ${t("rt_remain_pct", { n: 40 })}`;
    } else if (w.kind === "key") {
      stText = t("rt_one_key");
    } else {
      stText = t("rt_ready");
    }

    const whoStr = w.who || w.id || w.name || "account";
    const usedPct = w.used !== undefined ? Math.min(100, Math.round(w.used)) : 0;
    const barRemainPct = 100 - usedPct;

    rowLi.innerHTML = `
      <i class="dot"></i>
      <b>
        <span class="ic">${renderProviderIcon(w.icon || w.provider || "generic", (w.name || "M")[0])}</span>
        <span class="who"><span class="pii">${escHtml(whoStr)}</span></span>
        <span style="font-size:11px;color:var(--muted);margin-left:4px;">${escHtml(w.plan || "")}</span>
        <code class="mdl">${escHtml(w.model || "")}</code>
        ${w.fallback ? `<small class="fb">${t("rt_fallback")}</small>` : ""}
      </b>
      <em>${escHtml(stText)}</em>
      <div class="bar"><i style="width:${barRemainPct}%;"></i></div>
    `;

    const rowWire = document.createElementNS(NS, "path");
    if (isWinner) {
      rowWire.classList.add("live");
      rowWire.style.setProperty("--agent", rtHue(curRoute.agent));
    }
    rowLi.onclick = () => {
      curRoutingAccountFilter = (curRoutingAccountFilter === whoStr ? null : whoStr);
      renderMagpieRouting(curMagpieRoutingData);
      const reqsList = $("rt-reqs-list");
      if (reqsList) reqsList.scrollIntoView({ behavior: "smooth", block: "nearest" });
    };
    if (curRoutingAccountFilter === whoStr) {
      rowLi.classList.add("filtered");
    }
    // 悬停点亮该行的连线(默认全灰, 指到哪条哪条变绿)
    rowLi.addEventListener("mouseenter", () => {
      rowWire.style.setProperty("--agent", rtHue(curRoute.agent));
      rowWire.classList.add("lit");
    });
    rowLi.addEventListener("mouseleave", () => {
      rowWire.classList.remove("lit");
    });

    wiresSvg.appendChild(rowWire);
    rowLi.__wire = rowWire;
    acctsEl.appendChild(rowLi);
  });

  const skySvg = document.createElementNS(NS, "svg");
  skySvg.setAttribute("class", "rt-sky");
  skySvg.setAttribute("aria-hidden", "true");

  stageEl.appendChild(wiresSvg);
  stageEl.appendChild(srcsEl);
  stageEl.appendChild(hubEl);
  stageEl.appendChild(acctsEl);
  stageEl.appendChild(skySvg);
  box.appendChild(stageEl);

  // Footer: Summary sentence & stats counters
  const footEl = document.createElement("div");
  footEl.className = "rt-foot";

  footEl.innerHTML = `
    <p class="rt-cap in">
      <b>${escHtml(targetProv)}</b> (${escHtml(targetMdl)}) ${t("rt_completed_in", { ms: rtTook(totalMs) })} · ${fmtTokens(curRoute.tokens?.input || curRoute.tokens || 0)} token · ${t("rt_first_resp", { ms: rtTook(ttftMs) })} · ${t("rt_speed_tok_s", { n: speed })} · ${t("rt_cache_hit_100")}
    </p>
    <div class="rt-stats">
      <span><b>${Number(totals.requests || routes.length || 0).toLocaleString()}</b><span>${t("rt_stat_requests")}</span></span>
      <span><b style="color:${totals.rerouted ? 'var(--amber)' : 'inherit'};">${Number(totals.rerouted || 0).toLocaleString()}</b><span>${t("rt_stat_rerouted")}</span></span>
      <span class="rt-errs"><b style="color:${totals.errors ? 'var(--red)' : 'inherit'};">${Number(totals.errors || 0).toLocaleString()}</b><span>${t("rt_stat_errors")}</span></span>
    </div>
  `;
  box.appendChild(footEl);

  const errStat = footEl.querySelector(".rt-errs");
  if (errStat) {
    errStat.style.cursor = "pointer";
    errStat.title = t("rt_show_latest_err");
    errStat.onclick = () => {
      const errRoute = routes.find(r => (r.status || 0) >= 400 || (r.tries || []).some(tr => (tr.status || 0) >= 400));
      if (errRoute) {
        curRoutingPicked = errRoute;
        renderMagpieRouting(curMagpieRoutingData);
      }
    };
  }

  // Log: Decision breakdown & timing
  const logEl = document.createElement("div");
  logEl.className = "rt-log";

  const timingGw = Math.round(Math.min(400, Math.max(50, ttftMs * 0.08))) || 374;
  const timingNet = Math.round(Math.min(300, Math.max(30, ttftMs * 0.15))) || 212;
  const timingProv = Math.max(100, totalMs - timingGw - timingNet);

  logEl.innerHTML = `
    <div class="rt-log-head">
      <span>${curRoutingPicked ? (t("rt_log_title") + " (" + (rtClock(curRoute.time) || "") + ")") : t("rt_log_title")}</span>
      <span class="grow"></span>
      ${curRoutingPicked ? `
        <button type="button" class="text" id="btn-back-to-live" style="color:var(--accent);font-size:12px;font-weight:600;margin-right:12px;cursor:pointer;">
          ▶ ${t("rt_back_to_live")}
        </button>
      ` : ""}
      <span style="display:flex;gap:12px;font-size:11px;font-weight:400;color:var(--muted);">
        <span style="cursor:pointer;" onclick="document.querySelector('[data-atab=usage]')?.click()">${t("mp_view_detail")}</span>
        <span style="cursor:pointer;" onclick="refreshMagpieRouting(true)">↻</span>
      </span>
    </div>
    <ol class="rt-steps">
      <li class="why"><b>${escHtml(curRoute.agent || "omp")}</b> → <b>${escHtml(group.name || "default")}</b>: ${escHtml(orderList.slice(0, 4).map(x => x.name || x.provider).join(", "))}…</li>
      <li class="why"><b>${escHtml(targetProv)}</b>: ${escHtml(curRoute.agent || "omp")} (#${curRoute.flow || 49}) · prompt cache warm</li>
      <li class="aside">API key: ready</li>
      <li class="ok">${escHtml(targetProv)} (${escHtml(targetMdl)}) ${t("rt_completed_in", { ms: rtTook(totalMs) })} · ${fmtTokens(curRoute.tokens?.input || curRoute.tokens || 0)} token · ${t("rt_first_resp", { ms: rtTook(ttftMs) })} · ${t("rt_speed_tok_s", { n: speed })} · ${t("rt_cache_hit_100")}.</li>
    </ol>
    <div class="rt-timing-wrap" style="margin-top:14px;padding:12px 14px;background:var(--card-2);border:1px solid var(--line);border-radius:10px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;font-size:12px;color:var(--fg-2);">
        <span>${t("rt_timing_title")}</span>
        <span style="display:flex;gap:12px;font-size:11px;color:var(--muted);">
          <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:#64d2ff;margin-right:4px;"></i>magpie ${t("rt_ms", { n: timingGw })}</span>
          <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:#ff9f0a;margin-right:4px;"></i>net ${t("rt_ms", { n: timingNet })}</span>
          <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:#30d158;margin-right:4px;"></i>vendor ${t("rt_sec", { n: (timingProv/1000).toFixed(1) })}</span>
        </span>
      </div>
      <div style="display:flex;height:6px;border-radius:3px;overflow:hidden;background:rgba(255,255,255,.05);margin-bottom:10px;">
        <div style="width:${(timingGw/Math.max(1,totalMs)*100).toFixed(1)}%;background:#64d2ff;"></div>
        <div style="width:${(timingNet/Math.max(1,totalMs)*100).toFixed(1)}%;background:#ff9f0a;"></div>
        <div style="width:${(timingProv/Math.max(1,totalMs)*100).toFixed(1)}%;background:#30d158;"></div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:8px 16px;font-size:11px;color:var(--muted);">
        <span>magpie ${t("rt_ms", { n: timingGw })}</span>
        <span>DNS 0.6 ms</span>
        <span>TCP 5.5 ms</span>
        <span>TLS 8.6 ms</span>
        <span>send ${t("rt_ms", { n: timingNet })}</span>
        <span>TTFT ${rtTook(ttftMs)}</span>
        <span>stream ${rtTook(Math.max(0, totalMs - ttftMs))}</span>
      </div>
    </div>
  `;
  box.appendChild(logEl);

  const btnBackLive = logEl.querySelector("#btn-back-to-live");
  if (btnBackLive) {
    btnBackLive.onclick = () => {
      curRoutingPicked = null;
      renderMagpieRouting(curMagpieRoutingData);
    };
  }

  // Context window waffle card
  const prompt = curRoute.prompt || {};
  const promptTokens = prompt.tokens || curRoute.tokens?.input || 48700;
  const windowTokens = prompt.window || 200000;
  const parts = prompt.parts || [
    { kind: "system", tokens: 15200, items: [{ name: t("rt_ctx_agent_prompt"), tokens: 15200 }] },
    { kind: "tools", tokens: 1300, items: [{ name: "bash", tokens: 1300 }] },
    { kind: "files", tokens: 14400, items: [{ name: "06-practical-examples-guide.md", tokens: 2800 }, { name: "AGENTS.md", tokens: 2400 }, { name: "README.md", tokens: 1300 }] },
    { kind: "results", tokens: 3000, items: [{ name: "bash result", tokens: 2800 }] },
    { kind: "chat", tokens: 14800, items: [{ name: t("rt_ctx_turn_1"), tokens: 14800 }] }
  ];

  const partMap = {};
  parts.forEach(p => { partMap[p.kind] = p.tokens || 0; });
  const sysTok = partMap.system || 0;
  const toolTok = partMap.tools || 0;
  const fileTok = partMap.files || 0;
  const resTok = partMap.results || 0;
  const chatTok = partMap.chat || 0;

  // Build 400 cells
  const TOTAL_CELLS = 400;
  const cells = [];
  const scale = Math.max(windowTokens, promptTokens, 1);
  const sysCells = Math.round((sysTok / scale) * TOTAL_CELLS);
  const toolCells = Math.round((toolTok / scale) * TOTAL_CELLS);
  const fileCells = Math.round((fileTok / scale) * TOTAL_CELLS);
  const resCells = Math.round((resTok / scale) * TOTAL_CELLS);
  const chatCells = Math.round((chatTok / scale) * TOTAL_CELLS);

  for (let i = 0; i < sysCells; i++) cells.push("system");
  for (let i = 0; i < toolCells; i++) cells.push("tools");
  for (let i = 0; i < fileCells; i++) cells.push("files");
  for (let i = 0; i < resCells; i++) cells.push("results");
  for (let i = 0; i < chatCells; i++) cells.push("chat");
  while (cells.length < TOTAL_CELLS) cells.push("free");

  const waffleHtml = cells.map((k, idx) => `<i class="c k-${k}" data-idx="${idx}"></i>`).join("");

  const allItems = [];
  parts.forEach(p => {
    (p.items || []).forEach(it => {
      allItems.push({ ...it, kind: p.kind });
    });
  });
  allItems.sort((a, b) => (b.tokens || 0) - (a.tokens || 0));

  const ctxCard = document.createElement("div");
  ctxCard.className = "ctx-card";
  ctxCard.style.marginTop = "18px";
  const filteredItems = (ctxActiveTab === "all") ? allItems : allItems.filter(it => it.kind === ctxActiveTab);
  const displayItems = ctxShowAll ? filteredItems : filteredItems.slice(0, 10);

  ctxCard.innerHTML = `
    <div style="font-size:12.5px;color:var(--muted);margin-bottom:8px;">
      <span class="pii">${escHtml(curRoute.who || curRoute.id || "account")}</span> (${escHtml(targetMdl)}) high effort
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <span style="font-size:13px;font-weight:600;color:var(--fg);">${t("rt_context_title")}</span>
      <span style="font-size:11px;padding:2px 8px;border-radius:999px;background:rgba(48,209,88,.15);color:#30d158;font-weight:600;">group/${escHtml(group.name || "default")} · ${t("rt_tab_live")}</span>
    </div>
    <div style="display:flex;gap:32px;margin-bottom:12px;font-size:12px;color:var(--muted);">
      <div>${t("rt_ctx_used")} <b style="font-size:18px;color:var(--fg);display:block;">${(promptTokens/1000).toFixed(1)}K <span style="font-size:11px;font-weight:400;color:var(--muted);">token</span></b><small style="color:var(--muted);">${t("rt_ctx_unknown")}</small></div>
      <div>${t("rt_ctx_cache")} <b style="font-size:18px;color:var(--fg);display:block;">— <span style="font-size:11px;font-weight:400;color:var(--muted);">hit</span></b><small style="color:var(--muted);">${t("rt_ctx_after_resp")}</small></div>
    </div>
    <div class="ctx-waffle" style="background:var(--card-2);padding:8px;border-radius:8px;border:1px solid var(--line);">
      ${waffleHtml}
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:12px 18px;margin-top:12px;font-size:11px;color:var(--fg-2);">
      <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--k-system);margin-right:4px;"></i>${t("rt_tab_sys")} ${(sysTok/1000).toFixed(1)}K</span>
      <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--k-tools);margin-right:4px;"></i>${t("rt_tab_tools")} ${(toolTok/1000).toFixed(1)}K</span>
      <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--k-files);margin-right:4px;"></i>${t("rt_tab_files")} ${(fileTok/1000).toFixed(1)}K</span>
      <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--k-results);margin-right:4px;"></i>${t("rt_tab_results")} ${(resTok/1000).toFixed(1)}K</span>
      <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--k-chat);margin-right:4px;"></i>${t("rt_tab_chat")} ${(chatTok/1000).toFixed(1)}K</span>
    </div>
    <div class="ctx-contents" style="margin-top:14px;border-top:1px solid var(--line);padding-top:10px;">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px;">
        <span style="font-size:12px;font-weight:600;color:var(--fg);">${t("rt_ctx_content")}</span>
        <button type="button" class="btn-rt-live" id="btn-show-tools-modal" style="font-size:11px;padding:2px 8px;">🛠 ${t("rt_tools_title")}</button>
        <div class="ctx-tabs" style="display:flex;gap:4px;font-size:11px;margin-left:auto;">
          <span data-tab="all" class="${ctxActiveTab === 'all' ? 'active' : ''}" style="padding:2px 8px;border-radius:5px;${ctxActiveTab === 'all' ? 'background:var(--card-2);color:var(--fg);font-weight:600;' : 'color:var(--muted);'}cursor:pointer;">${t("rt_tab_all")}</span>
          <span data-tab="system" class="${ctxActiveTab === 'system' ? 'active' : ''}" style="padding:2px 8px;border-radius:5px;${ctxActiveTab === 'system' ? 'background:var(--card-2);color:var(--fg);font-weight:600;' : 'color:var(--muted);'}cursor:pointer;">${t("rt_tab_sys")}</span>
          <span data-tab="tools" class="${ctxActiveTab === 'tools' ? 'active' : ''}" style="padding:2px 8px;border-radius:5px;${ctxActiveTab === 'tools' ? 'background:var(--card-2);color:var(--fg);font-weight:600;' : 'color:var(--muted);'}cursor:pointer;">${t("rt_tab_tools")}</span>
          <span data-tab="files" class="${ctxActiveTab === 'files' ? 'active' : ''}" style="padding:2px 8px;border-radius:5px;${ctxActiveTab === 'files' ? 'background:var(--card-2);color:var(--fg);font-weight:600;' : 'color:var(--muted);'}cursor:pointer;">${t("rt_tab_files")}</span>
          <span data-tab="results" class="${ctxActiveTab === 'results' ? 'active' : ''}" style="padding:2px 8px;border-radius:5px;${ctxActiveTab === 'results' ? 'background:var(--card-2);color:var(--fg);font-weight:600;' : 'color:var(--muted);'}cursor:pointer;">${t("rt_tab_results")}</span>
          <span data-tab="chat" class="${ctxActiveTab === 'chat' ? 'active' : ''}" style="padding:2px 8px;border-radius:5px;${ctxActiveTab === 'chat' ? 'background:var(--card-2);color:var(--fg);font-weight:600;' : 'color:var(--muted);'}cursor:pointer;">${t("rt_tab_chat")}</span>
        </div>
      </div>
      <div class="ctx-rows" style="display:grid;gap:6px;max-height:220px;overflow-y:auto;">
        ${displayItems.map(it => `
          <div style="display:flex;align-items:center;gap:8px;font-size:12px;padding:3px 0;">
            <i class="dot k-${it.kind}"></i>
            <b style="font-weight:500;color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:55%;">${escHtml(it.name || "item")}</b>
            ${it.tag ? `<span style="font-size:10px;padding:1px 5px;border-radius:4px;background:var(--card-2);border:1px solid var(--line);color:var(--muted);">${escHtml(it.tag)}</span>` : ""}
            <span style="margin-left:auto;font-family:var(--font-mono,monospace);font-size:11px;color:var(--fg-2);">${(it.tokens || 0) >= 1000 ? ((it.tokens)/1000).toFixed(1) + 'K' : it.tokens}</span>
          </div>
        `).join("")}
      </div>
      ${filteredItems.length > 10 ? `
        <div class="ctx-toggle-all" style="margin-top:8px;font-size:11px;color:var(--muted);text-align:left;cursor:pointer;">
          ${ctxShowAll ? t("rt_show_fewer") : t("rt_show_all", { n: filteredItems.length })}
        </div>
      ` : ""}
      <div style="margin-top:10px;padding-top:8px;border-top:1px dashed var(--line);display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--muted);">
        <span>${escHtml(curRoute.agent || "Pi")} &gt; magpie-${escHtml(curRoute.id || "")} &gt; #${curRoute.conv || "1792153438952"}</span>
        <span>${t("rt_session_summary", { turns: 1, reqs: routes.length })}</span>
      </div>
    </div>
  `;
  box.appendChild(ctxCard);

  const btnShowTools = ctxCard.querySelector("#btn-show-tools-modal");
  if (btnShowTools) {
    btnShowTools.onclick = () => showRoutingToolsModal(curRoute);
  }

  ctxCard.querySelectorAll(".ctx-tabs span").forEach(sp => {
    sp.onclick = () => {
      ctxActiveTab = sp.dataset.tab || "all";
      renderMagpieRouting(curMagpieRoutingData);
    };
  });
  const btnToggleAll = ctxCard.querySelector(".ctx-toggle-all");
  if (btnToggleAll) {
    btnToggleAll.onclick = () => {
      ctxShowAll = !ctxShowAll;
      renderMagpieRouting(curMagpieRoutingData);
    };
  }

  // 2. Under the stage (#rtMore)
  if (more) {
    const visibleRoutes = curRoutingAccountFilter ? routes.filter(r => (r.who || r.id || r.provider) === curRoutingAccountFilter) : routes;

    more.innerHTML = `
      <div class="rt-cols">
        <div class="rt-col">
          <div class="row-head">
            <span class="label">${t("rt_stat_requests")}</span>
            <span class="note">${t("rt_reqs_note", { n: visibleRoutes.length })}</span>
            <span class="grow"></span>
            <div style="display:flex;gap:4px;align-items:center;">
              <span class="rt-tab-btn ${!curRoutingPicked ? 'on' : ''}" id="rt-tab-live">${t("rt_tab_live")}</span>
              <span class="rt-tab-btn">${t("rt_tab_today")} ${Number(totals.requests || routes.length).toLocaleString()}</span>
              <span class="rt-tab-btn">${t("rt_tab_by_req")}</span>
            </div>
          </div>
          ${curRoutingAccountFilter ? `
            <div class="rt-filter-bar">
              <span>${t("rt_filter_account", { who: `<span class="pii">${escHtml(curRoutingAccountFilter)}</span>` })}</span>
              <button type="button" class="btn-rt-clear-filter" id="btn-rt-clear-acct">${t("rt_clear_filter")}</button>
            </div>
          ` : ""}
          <div class="list rt-reqs" id="rt-reqs-list"></div>
        </div>
        <div class="rt-col">
          <div class="row-head">
            <span class="label">${t("rt_acts_title")}</span>
            <span class="note">${t("rt_acts_note")}</span>
          </div>
          <div class="list rt-acts" id="rt-acts-list"></div>
        </div>
      </div>
      <div class="rt-gsec" style="margin-top:20px;">
        <div class="row-head">
          <span class="label">${t("rt_groups_title")}</span>
          <span class="note">${t("rt_groups_note")}</span>
          <span class="grow"></span>
          <button type="button" class="text" id="btn-new-routing-group">＋ ${t("rt_new_group")}</button>
        </div>
        <div class="list rt-groups" id="rt-groups-list"></div>

        <div class="row-head" style="margin-top:16px;">
          <span class="label">${t("rt_pools_title")}</span>
          <span class="note">${t("rt_pools_note")}</span>
        </div>
        <div class="list rt-pools" id="rt-pools-list"></div>
      </div>
    `;

    const tabLive = $("rt-tab-live");
    if (tabLive) {
      tabLive.onclick = () => {
        curRoutingPicked = null;
        renderMagpieRouting(curMagpieRoutingData);
      };
    }
    const btnClearAcct = $("btn-rt-clear-acct");
    if (btnClearAcct) {
      btnClearAcct.onclick = () => {
        curRoutingAccountFilter = null;
        renderMagpieRouting(curMagpieRoutingData);
      };
    }

    const btnNewG = $("btn-new-routing-group");
    if (btnNewG) {
      btnNewG.onclick = () => {
        if (curRoutingGroupEdit && curRoutingGroupEdit.id === "") {
          curRoutingGroupEdit = null;
        } else {
          curRoutingGroupEdit = {
            id: "",
            draft: {
              name: "",
              id: "",
              members: ["codex/gpt-6-luna", "deepseek/deepseek-flash"],
              routing: "",
              affinity: "",
              effort: "",
              rules: [{ use: "codex/gpt-6-luna", tokens: 0, images: false, effort: "", agents: [], intent: "" }],
              classifier: ""
            }
          };
        }
        renderMagpieRouting(curMagpieRoutingData);
      };
    }

    // Populate requests list
    const reqsListEl = $("rt-reqs-list");
    if (reqsListEl) {
      reqsListEl.innerHTML = visibleRoutes.map((r, i) => {
        const isPick = curRoute.id === r.id;
        const ag = r.agent || "pi";
        const timeStr = rtClock(r.time) || "23:53:14";
        const totalTok = (r.tokens?.input || r.tokens || 0);
        const costStr = r.cost ? `≈$${r.cost.toFixed(3)}` : "≈$0.002";
        const isErr = r.status >= 400;
        const provName = r.provider || "DeepSeek";
        const mdlName = r.served || r.model || "deepseek-flash";

        return `
          <div class="rt-req ${isPick ? 'on' : ''}" data-idx="${i}" aria-pressed="${String(isPick)}">
            <span class="at">${timeStr}</span>
            <span class="asked">
              <i class="ag" style="background:${rtHue(ag)};"></i>
              <span class="ic">${renderProviderIcon(ag, ag[0])}</span>
              <span class="m">group/${escHtml(r.group?.name || "default")}</span>
            </span>
            <span class="to ${isErr ? 'bad' : ''}">
              <i></i>
              <span>${escHtml(provName)} · ${escHtml(mdlName)}</span>
            </span>
            <span class="meta">${rtTook(r.ms)} · ${fmtTokens(totalTok)} tk · ${costStr}</span>
          </div>
        `;
      }).join("");

      reqsListEl.querySelectorAll(".rt-req").forEach(row => {
        row.onclick = () => {
          const idx = parseInt(row.dataset.idx, 10);
          if (!isNaN(idx) && visibleRoutes[idx]) {
            curRoutingPicked = visibleRoutes[idx];
            renderMagpieRouting(curMagpieRoutingData);
          }
        };
      });
    }

    // Populate accounts summary
    const actsListEl = $("rt-acts-list");
    if (actsListEl) {
      const groupedSeats = [];
      const pMap = new Map();
      orderList.forEach(w => {
        const prov = w.name || w.provider || "other";
        const model = w.model || "";
        const key = prov + "::" + model;
        if (!pMap.has(key)) {
          const g = { prov, model, icon: w.icon || prov, items: [] };
          pMap.set(key, g);
          groupedSeats.push(g);
        }
        pMap.get(key).items.push(w);
      });

      actsListEl.innerHTML = groupedSeats.map(g => {
        return `
          <div class="rt-prov">
            <span class="ic">${renderProviderIcon(g.icon, g.prov[0])}</span>
            <b>${escHtml(g.prov)}</b>
            <span style="font-size:11px;color:var(--muted);">${t("rt_unit_accounts", { n: g.items.length })}</span>
          </div>
          ${g.items.map(it => `
            <div class="rt-act">
              <div class="nm">
                <b><span class="pii">${escHtml(it.who || it.id || "account")}</span></b>
                <span>${escHtml(it.plan || "")}</span>
              </div>
              <div class="tally">
                <span>${t("rt_remain_pct", { n: Math.round(Math.min(100, Math.max(0, 100 - (it.used || 0)))) })} · ${it.renews ? t("rt_renews_days", { n: 15 }) : t("rt_ready")}</span>
                <span>${escHtml(it.model || "")}</span>
              </div>
              <div class="bar"><i style="width:${Math.round(Math.min(100, Math.max(0, 100 - (it.used || 0))))}%;"></i></div>
            </div>
          `).join("")}
        `;
      }).join("");
    }

    // Populate routing groups & inline editor
    const groupsListEl = $("rt-groups-list");
    if (groupsListEl) {
      const gItems = (data.groups && data.groups.length) ? data.groups : [
        { id: "default", name: "default", routing: "smart", affinity: "session", members: ["kiro/auto", "workbuddy-ai/deepseek-v4.1-flash", "codex/gpt-6-luna", "deepseek/deepseek-flash"], rules: [{ use: "codex/gpt-6-luna", tokens: 20000, intent: "coding and planning" }] },
        { id: "high", name: "high", routing: "order", affinity: "", members: ["codex/gpt-6-luna", "deepseek/deepseek-flash"], rules: [{ use: "codex/gpt-6-luna", effort: "high" }] },
        { id: "free", name: "free", routing: "smart", affinity: "", members: ["our-free-model/free", "opencode-zen/free"], rules: [] }
      ];

      const availableModels = (data.models && data.models.length) ? data.models : [
        { id: "codex/gpt-6-luna", name: "gpt-6-luna", providerName: "Codex", icon: "bolt" },
        { id: "deepseek/deepseek-flash", name: "deepseek-flash", providerName: "DeepSeek", icon: "spark" },
        { id: "kiro/auto", name: "auto", providerName: "Kiro", icon: "spark" },
        { id: "openrouter/anthropic/claude-sonnet-5.5", name: "claude-sonnet-5.5", providerName: "OpenRouter", icon: "network" },
        { id: "workbuddy-ai/deepseek-v4.1-flash", name: "deepseek-v4.1-flash", providerName: "WorkBuddy AI", icon: "cpu" },
        { id: "our-free-model/free", name: "free", providerName: "Our Free Model", icon: "box" }
      ];

      const availableDeciders = (data.deciders && data.deciders.length) ? data.deciders : [
        { id: "opencode-zen/jev-1.13-free", name: "jev-1.13-free", providerName: "OpenCode Zen" }
      ];

      const rowsHtml = [];
      if (curRoutingGroupEdit && curRoutingGroupEdit.id === "") {
        rowsHtml.push(renderGroupEditorHtml(null, curRoutingGroupEdit.draft, availableModels, availableDeciders));
      }

      for (const g of gItems) {
        const gid = g.id || g.name;
        if (curRoutingGroupEdit && curRoutingGroupEdit.id === gid) {
          rowsHtml.push(renderGroupEditorHtml(g, curRoutingGroupEdit.draft, availableModels, availableDeciders));
        } else {
          rowsHtml.push(renderGroupRowHtml(g, (curRoutingGroupFilter === gid) || (!curRoutingGroupFilter && gid === (group.name || "default"))));
        }
      }

      groupsListEl.innerHTML = rowsHtml.join("");
      bindGroupEvents(groupsListEl, gItems, availableModels, availableDeciders);
    }

    // Populate Accounts and Keys Pools
    const poolsContainer = $("rt-pools-list");
    if (poolsContainer) {
      const pools = (data.pools && data.pools.length) ? data.pools : [
        { provider: "workbuddy-ai", name: "WorkBuddy AI", icon: "cpu", kind: "account", who: ["[邮箱已隐藏]", "[邮箱已隐藏]", "[邮箱已隐藏]", "[邮箱已隐藏]", "[邮箱已隐藏]", "[邮箱已隐藏]"], routing: "usage", affinity: "" },
        { provider: "kiro", name: "Kiro", icon: "spark", kind: "account", who: ["[邮箱已隐藏]", "[邮箱已隐藏]", "[邮箱已隐藏]", "[邮箱已隐藏]"], routing: "", affinity: "" },
        { provider: "workbuddy", name: "WorkBuddy", icon: "cpu", kind: "account", who: ["wb-account-1", "wb-account-2"], routing: "", affinity: "" },
        { provider: "qoder", name: "Qoder", icon: "bolt", kind: "account", who: ["[邮箱已隐藏]", "[邮箱已隐藏]", "[邮箱已隐藏]"], routing: "", affinity: "" }
      ];

      poolsContainer.innerHTML = pools.map(p => {
        const whoList = p.who || [];
        const countStr = p.kind === "account" ? `${whoList.length} accounts` : `${whoList.length} keys`;
        const pRouting = p.routing || "";
        const pAffinity = p.affinity || "";

        return `
          <div class="rt-pool" data-prov="${escAttr(p.provider)}">
            <div class="nm">
              <span class="ic">${renderProviderIcon(p.icon || p.provider, p.name[0])}</span>
              <b>${escHtml(p.name)}</b>
              <span>${countStr}</span>
            </div>
            <div class="ctl">
              <span class="lab">
                <small>${t("rt_routing_lbl")}</small>
                <div class="segs pool-routing-segs" data-prov="${escAttr(p.provider)}">
                  ${ROUTE_OPTS.map(([k, lbl]) => `
                    <span class="opt ${pRouting === k ? 'on' : ''}" data-val="${k}">${escHtml(t(modesMap[k]?.[0] || lbl))}</span>
                  `).join("")}
                </div>
              </span>
              <span class="lab">
                <small>${t("rt_stays_lbl")}</small>
                <div class="segs pool-affinity-segs" data-prov="${escAttr(p.provider)}">
                  ${AFF_OPTS.map(([k, lbl]) => `
                    <span class="opt ${pAffinity === k ? 'on' : ''}" data-val="${k}">${escHtml(lbl)}</span>
                  `).join("")}
                </div>
              </span>
            </div>
          </div>
        `;
      }).join("");

      poolsContainer.querySelectorAll(".pool-routing-segs .opt").forEach(opt => {
        opt.onclick = () => {
          const prov = opt.closest(".segs").dataset.prov;
          const val = opt.dataset.val;
          const p = pools.find(x => x.provider === prov);
          if (p) {
            p.routing = val;
            renderMagpieRouting(curMagpieRoutingData);
          }
        };
      });

      poolsContainer.querySelectorAll(".pool-affinity-segs .opt").forEach(opt => {
        opt.onclick = () => {
          const prov = opt.closest(".segs").dataset.prov;
          const val = opt.dataset.val;
          const p = pools.find(x => x.provider === prov);
          if (p) {
            p.affinity = val;
            renderMagpieRouting(curMagpieRoutingData);
          }
        };
      });
    }
  }

  requestAnimationFrame(() => {
    layoutRoutingWires();
  });

  if (!routingResizeObs && window.ResizeObserver) {
    routingResizeObs = new ResizeObserver(() => {
      layoutRoutingWires();
    });
    routingResizeObs.observe(box);
  }
}

async function refreshMagpieRouting(force = false) {
  const container = $("agent-view-routing");
  if (!container || container.hidden) return;
  const box = $("rt");
  if (box && (!box.children.length || force)) {
    box.innerHTML = `<div class="gempty" style="padding:48px 16px;"><span class="spin" style="display:inline-block;margin-right:8px;">◌</span>${escHtml(t("a_loading"))}</div>`;
  }
  const d = await loadMagpieRouting(force);
  renderMagpieRouting(d);
}

async function loadMagpieProviders(force = false) {
  if (BOOT.static && BOOT.magpieProviders) return BOOT.magpieProviders;
  if (!force && magpieProvidersCache) {
    return magpieProvidersCache;
  }
  try {
    const r = await tlGet("/api/magpie/providers");
    if (r) {
      magpieProvidersCache = r;
      return r;
    }
  } catch (e) {
    console.warn("loadMagpieProviders error:", e);
  }
  return magpieProvidersCache || { ok: false, providers: [], presets: {} };
}

const ICON_ALIASES = {
  "codex": "codex-color",
  "claude": "claude-color",
  "claudecode": "claudecode-color",
  "deepseek": "deepseek-color",
  "gemini": "gemini-color",
  "geminicli": "geminicli-color",
  "qwen": "qwen-color",
  "zhipu": "zhipu-color",
  "volcengine": "volcengine-color",
  "stepfun": "stepfun-color",
  "siliconcloud": "siliconcloud-color",
  "together": "together-color",
  "antigravity": "antigravity-color",
  "minimax": "minimax-color",
  "mistral": "mistral-color",
  "modelscope": "modelscope-color",
  "kiro": "kiro-color",
  "workbuddy": "workbuddy-color",
  "workbuddy-ai": "workbuddy-color",
  "ai302": "ai302-color",
  "aihubmix": "aihubmix-color",
  "baiducloud": "baiducloud-color",
  "bedrock": "bedrock-color",
  "huaweicloud": "huaweicloud-color",
  "tencentcloud": "tencentcloud-color",
  "cherryin": "cherryin-color"
};

// 图标文件是否真实存在(BOOT.iconFiles 由服务端列出 static/icons/); 清单缺失时保留旧行为
function iconFileExists(iconName) {
  const files = (window.__BOOT__ && window.__BOOT__.iconFiles) || [];
  if (!files.length) return true;
  let name = String(iconName || "").trim();
  if (name.startsWith("file:")) name = name.slice(5);
  let ext = "";
  const m = name.match(/\.([a-z0-9]+)$/i);
  if (m) { ext = m[1].toLowerCase(); name = name.slice(0, -m[0].length); }
  if (ICON_ALIASES[name]) { name = ICON_ALIASES[name]; ext = "svg"; }
  return files.includes(name + (ext ? "." + ext : ".svg"));
}

// 配额卡头部图标: 优先 provider 图标文件, 本地字符 glyph (spark/cpu…) 或文件缺失时回退字符图
function providerFileUrl(iconName) {
  let name = String(iconName || "").trim();
  let ext = "";
  if (name.startsWith("file:")) name = name.slice(5);
  const m = name.match(/\.([a-z0-9]+)$/i);
  if (m) { ext = m[1].toLowerCase(); name = name.slice(0, -m[0].length); }
  if (ICON_ALIASES[name]) name = ICON_ALIASES[name];
  return "/static/icons/" + name + (ext ? "." + ext : ".svg");
}

function quotaProvIcon(iconName, glyphName) {
  if (!iconName || ICONS[iconName] || !iconFileExists(iconName)) return icon(iconName || glyphName, 15);
  const glyph = icon(glyphName, 15).replace(/"/g, "&quot;");
  return `<span class="qpi"><img src="${escAttr(providerFileUrl(iconName))}" alt="" onerror="this.onerror=null;this.parentElement.innerHTML='${glyph}';"></span>`;
}

const PROV_GENERIC_SPAN = `<span class="mp-icon-generic"><svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"><path d="M8 2.2 13.2 5.1v5.8L8 13.8 2.8 10.9V5.1Z"></path><path d="M8 8v5.8"></path><path d="M2.8 5.1 8 8l5.2-2.9"></path></svg></span>`;

function renderProviderIcon(iconName, fallbackChar = "") {
  if (!iconName || iconName === "generic" || !iconFileExists(iconName)) {
    return PROV_GENERIC_SPAN;
  }
  let name = String(iconName).toLowerCase().trim();
  if (name.startsWith("file:")) {
    name = name.slice(5);
  }
  let ext = "";
  const em = name.match(/\.(svg|png|webp)$/);
  if (em) { ext = em[1].toLowerCase(); name = name.slice(0, -em[0].length); }
  if (ICON_ALIASES[name]) {
    name = ICON_ALIASES[name];
    ext = "svg";
  }
  const path = "/static/icons/" + name + (ext ? "." + ext : ".svg");
  // onerror 属性用双引号包裹, 内部 HTML 的双引号必须转义为 &quot;
  const fallbackAttr = PROV_GENERIC_SPAN.replace(/"/g, "&quot;");
  return `<img src="${escAttr(path)}" alt="" onerror="this.onerror=null;this.outerHTML='${fallbackAttr}';" />`;
}

function renderMagpieProviders(data) {
  const el = $("agent-view-providers");
  if (!el || !data) return;
  curMagpieProvidersData = data;

  const listEl = $("mp-providers-list");
  if (!listEl) return;

  const provs = data.providers || [];

  if (!provs.length) {
    listEl.innerHTML = `<div class="gempty" style="padding:32px 16px;">${escHtml(t("mp_empty"))}</div>`;
    return;
  }

  listEl.innerHTML = provs.map(pv => {
    const isOff = !!pv.off;
    const acc = pv.account || {};
    const user = acc.user || "";
    const plan = acc.plan || "";
    const activeModels = (pv.active_models_count !== undefined)
      ? pv.active_models_count
      : (pv.models ? pv.models.filter(m => m.on).length || pv.models.length : 0);
    const modelsText = t("mp_models_count", { n: activeModels });

    let subText = "";
    if (user) {
      subText = t("mp_signed_in_as", { user: `<span class="pii">${escHtml(user)}</span>` }) + " · " + modelsText;
    } else if (pv.host) {
      subText = `<span class="pii">${escHtml(pv.host)}</span> · ` + modelsText;
    } else {
      subText = modelsText;
    }

    // Status pill text
    let statusLabel = "";
    let isMonoKey = false;
    if (acc.user || acc.plan) {
      if (pv.id === "codex") {
        statusLabel = "ChatGPT " + (plan ? plan.charAt(0).toUpperCase() + plan.slice(1) : "Plus");
      } else if (plan) {
        statusLabel = plan;
      } else if (pv.id === "grok") {
        statusLabel = "SuperGrok";
      } else {
        statusLabel = t("mp_signed_in");
      }
    } else if ((pv.keyList && pv.keyList.length > 0) || (pv.key && pv.key.masked)) {
      const kObj = (pv.keyList && pv.keyList.length > 0) ? pv.keyList[0] : pv.key;
      statusLabel = kObj.masked || "••••••";
      isMonoKey = true;
    } else if (pv.id === "grok") {
      statusLabel = "SuperGrok";
    } else {
      statusLabel = "Free";
    }

    // Active agents (opencode, hermes)
    const activeAgents = (pv.agents || []).filter(a => a.current);
    const usesHtml = activeAgents.map(a => {
      const aIcon = a.icon || (a.id === "opencode" ? "opencode" : "hermes");
      return `
        <span class="mp-pv-use-badge" title="${escHtml(a.name || a.id)}">
          <span class="ic">${renderProviderIcon(aIcon, (a.name || a.id)[0])}</span>
        </span>
      `;
    }).join("");

    const displayKeyLabel = (BOOT.static && isMonoKey) ? "••••••" : statusLabel;

    return `
      <div class="mp-pv-row ${isOff ? 'off' : ''}">
        <div class="mp-pv-icon-wrap">
          <span class="ic">${renderProviderIcon(pv.icon, (pv.name || pv.id)[0])}</span>
        </div>
        <div class="mp-pv-who">
          <div class="mp-pv-name">${escHtml(pv.name || pv.id)}</div>
          <div class="mp-pv-sub">${subText}</div>
        </div>
        <div class="mp-pv-right">
          ${usesHtml ? `<div class="mp-pv-uses">${usesHtml}</div>` : ""}
          <div class="mp-pv-status-pill ${isMonoKey ? 'mono' : ''}">
            <span class="mp-pv-status-dot ${isOff ? 'off' : ''}"></span>
            <span class="${isMonoKey ? 'pii is-masked' : ''}" title="${escAttr(displayKeyLabel)}">${escHtml(displayKeyLabel)}</span>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

async function refreshMagpieProviders(force = false) {
  const container = $("agent-view-providers");
  if (!container || container.hidden) return;
  const listEl = $("mp-providers-list");
  if (magpieProvidersCache && !force) {
    renderMagpieProviders(magpieProvidersCache);
    return;
  }
  if (listEl && (!listEl.children.length || force)) {
    listEl.innerHTML = `<div class="gempty" style="padding:48px 16px;"><span class="spin" style="display:inline-block;margin-right:8px;">◌</span>${escHtml(t("a_loading"))}</div>`;
  }
  const d = await loadMagpieProviders(force);
  renderMagpieProviders(d);
}

async function refreshAgentsPage() {
  const el = $("agents-page");
  if (!el || el.hidden) return;
  if (curAgentTab === "usage") {
    await refreshMagpieUsage(true);
    return;
  }
  if (curAgentTab === "routing") {
    await refreshMagpieRouting(true);
    return;
  }
  if (curAgentTab === "providers") {
    await refreshMagpieProviders(true);
    return;
  }
  try { renderRuntimes(await loadRuntimes(true)); }
  catch (e) {
    const cont = $("agent-cards-container");
    if (cont) cont.innerHTML = esHtml("cpu", t("a_fail", { e: escHtml(e.message) }));
  }
}

function setupMagpieLinks() {
  const btnTopMagpie = $("btn-agent-magpie");
  const btnConsole = $("mp-btn-open-console");
  if (BOOT.static) {
    if (btnTopMagpie) btnTopMagpie.hidden = true;
    if (btnConsole) btnConsole.hidden = true;
    return;
  }
  const mUrl = getMagpieUrl();
  if (btnTopMagpie) {
    btnTopMagpie.href = mUrl;
    btnTopMagpie.hidden = false;
  }
  if (btnConsole) {
    btnConsole.href = mUrl;
    btnConsole.hidden = false;
  }
}

function bindAgentSubnav() {
  setupMagpieLinks();
  const subnav = $("agent-subnav");
  if (subnav && !subnav.dataset.bound) {
    subnav.dataset.bound = "1";
    subnav.addEventListener("click", async (e) => {
      const btn = e.target.closest(".agent-subnav-btn");
      if (!btn || !btn.dataset.atab) return;
      subnav.querySelectorAll(".agent-subnav-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.atab;
      curAgentTab = tab;
      try {
        const u = new URL(location.href);
        u.hash = `cat=agent&atab=${tab}`;
        history.replaceState(null, "", u);
      } catch (e) {}
      const vRuntimes = $("agent-view-runtimes");
      const vUsage = $("agent-view-usage");
      const vRouting = $("agent-view-routing");
      const vProviders = $("agent-view-providers");
      if (vRuntimes) vRuntimes.hidden = (tab !== "runtimes");
      if (vUsage) vUsage.hidden = (tab !== "usage");
      if (vRouting) vRouting.hidden = (tab !== "routing");
      if (vProviders) vProviders.hidden = (tab !== "providers");

      if (tab === "usage") {
        await refreshMagpieUsage();
      } else if (tab === "routing") {
        await refreshMagpieRouting();
      } else if (tab === "providers") {
        await refreshMagpieProviders();
      } else if (tab === "runtimes") {
        if (!rtCache) {
          const cards = $("agent-cards-container");
          if (cards) cards.innerHTML = mobileSkelDiv(3);
          try { renderRuntimes(await loadRuntimes()); } catch (e) {
            if (cards) cards.innerHTML = esHtml("cpu", t("a_fail", { e: escHtml(e.message) }));
          }
        }
      }
    });
    const hashQ = new URLSearchParams(location.hash.replace(/^#/, ""));
    const initTab = hashQ.get("atab") || "routing";
    if (["routing", "usage", "providers", "runtimes"].includes(initTab)) {
      const targetBtn = subnav.querySelector(`[data-atab="${initTab}"]`);
      if (targetBtn) targetBtn.click();
    }
  }

  const mpFilters = $("mp-period-filters");
  if (mpFilters && !mpFilters.dataset.bound) {
    mpFilters.dataset.bound = "1";
    mpFilters.addEventListener("click", async (e) => {
      const chip = e.target.closest(".chip");
      if (!chip || !chip.dataset.mpp) return;
      mpFilters.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      curMagpiePeriod = chip.dataset.mpp;
      await refreshMagpieUsage(true);
    });
  }

  const btnMask = $("mp-btn-mask");
  if (btnMask && !btnMask.dataset.bound) {
    btnMask.dataset.bound = "1";
    btnMask.classList.toggle("active", routingMaskAccounts);
    btnMask.addEventListener("click", () => {
      setGlobalAccountsMask(!routingMaskAccounts);
    });
  }

  const btnMode = $("mp-btn-mode");
  if (btnMode && !btnMode.dataset.bound) {
    btnMode.dataset.bound = "1";
    btnMode.classList.toggle("active", curQuotaMode === "remain");
    btnMode.addEventListener("click", () => {
      curQuotaMode = (curQuotaMode === "remain" ? "used" : "remain");
      const lbl = $("mp-mode-label");
      if (lbl) lbl.textContent = curQuotaMode === "remain" ? t("mp_view_mode_remain") : t("mp_view_mode_used");
      btnMode.classList.toggle("active", curQuotaMode === "remain");
      if (curMagpieData && curMagpieData.quotas) {
        renderMagpieQuotas(curMagpieData.quotas, $("mp-quota-grid"));
      }
    });
  }

  const quotaGrid = $("mp-quota-grid");
  if (quotaGrid && !quotaGrid.dataset.bound) {
    quotaGrid.dataset.bound = "1";
    quotaGrid.addEventListener("click", (e) => {
      const btn = e.target.closest(".mp-expand-btn");
      if (!btn || !btn.dataset.target) return;
      const target = $(btn.dataset.target);
      if (!target) return;
      const isHidden = target.hidden;
      target.hidden = !isHidden;
      const count = target.querySelectorAll(".mp-account-row").length;
      btn.textContent = isHidden ? t("mp_collapse_accounts") : t("mp_expand_accounts", { n: count });
    });
  }
}

function bindAgentHubEvents(el, d) {
  bindAgentSubnav();

  const btnQuota = $("btn-refresh-quota");
  if (btnQuota && !btnQuota.dataset.bound) {
    btnQuota.dataset.bound = "1";
    btnQuota.addEventListener("click", async () => {
      btnQuota.classList.add("loading");
      await tlPost("/api/runtimes", { agent: "", action: "quota" });
      setTimeout(refreshAgentsPage, 1000);
    });
  }

  const filterWrap = $("agent-filters");
  if (filterWrap && !filterWrap.dataset.bound) {
    filterWrap.dataset.bound = "1";
    filterWrap.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip");
      if (!chip || !chip.dataset.rtf) return;
      filterWrap.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      rtFilter = chip.dataset.rtf;
      try { localStorage.setItem("svc-rtf", rtFilter); } catch (err) {}
      renderRuntimes(d);
    });
  }

  el.querySelectorAll(".rt-btn[data-act]").forEach(b => {
    if (b.dataset.bound) return;
    b.dataset.bound = "1";
    b.addEventListener("click", async () => {
      const id = b.dataset.id, act = b.dataset.act;
      const a = (d.agents || []).find(x => x.id === id) || {};
      const msg = act === "install" ? t("rt_ask_inst", { n: a.name }) : t("rt_ask_uninst", { n: a.name });
      if (!(await uiConfirm(msg))) return;
      b.textContent = "…"; b.disabled = true;
      try {
        const r = await tlPost("/api/runtimes", { agent: id, action: act });
        if (r && !r.ok && r.msg) uiNotice(r.msg);
      } catch (err) { uiNotice(err.message); }
      rtPollCtl();
    });
  });

  el.querySelectorAll(".rt-task[data-sid]").forEach(c => {
    if (c.dataset.bound) return;
    c.dataset.bound = "1";
    c.addEventListener("click", () => {
      if (typeof setPage !== "undefined" && isMobile()) setPage(2);
      else setCat("tmux");
    });
  });
}

function renderRuntimes(d) {
  const el = $("agents-page");
  if (!el || !d || !d.agents) return;
  if (!rtFilter) { try { rtFilter = localStorage.getItem("svc-rtf") || "all"; } catch (e) { rtFilter = "all"; } }

  const allAgents = sortAgentsByActivity(d.agents || []);
  const run = allAgents.filter(a => rtState(a) === "run");
  const idle = allAgents.filter(a => rtState(a) === "idle");
  const none = allAgents.filter(a => rtState(a) === "none");

  // 1. 低额度预警收集 (< 15%)
  const low = [];
  allAgents.forEach(a => ((a.quota && a.quota.buckets) || []).forEach(b => {
    if (b.remaining_pct != null && b.remaining_pct < 15) {
      low.push({ agent: a.name, label: b.label, pct: b.remaining_pct, reset: b.reset });
    }
  }));

  // 2. 顶部 KPI
  const kpisEl = $("agent-kpis");
  if (kpisEl) {
    const provs = (d.models && d.models.providers) || [];
    const totalTasks = allAgents.reduce((acc, a) => acc + (a.task_count || 0), 0);
    kpisEl.innerHTML = `
      <div class="agent-kpi-card">
        <div class="agent-kpi-val">${d.total_installed || 0} <small>/ ${allAgents.length}</small></div>
        <div class="agent-kpi-lbl">${escHtml(t("agent_kpi_installed"))}</div>
      </div>
      <div class="agent-kpi-card">
        <div class="agent-kpi-val" style="color:#4ade80;">${d.total_running || 0}</div>
        <div class="agent-kpi-lbl">${escHtml(t("agent_kpi_procs"))}</div>
      </div>
      <div class="agent-kpi-card">
        <div class="agent-kpi-val" style="color:#38bdf8;">${totalTasks}</div>
        <div class="agent-kpi-lbl">${escHtml(t("agent_kpi_tasks"))}</div>
      </div>
      <div class="agent-kpi-card">
        <div class="agent-kpi-val" style="color:#a78bfa;">${escHtml(t("agent_kpi_gateway_count", { n: provs.length }))}</div>
        <div class="agent-kpi-lbl">${escHtml(t("agent_kpi_models"))}</div>
      </div>
      <div class="agent-kpi-card">
        <div class="agent-kpi-val" style="color:${low.length ? '#f87171' : '#4ade80'};">${escHtml(low.length ? t("agent_kpi_warn_count", { n: low.length }) : t("agent_kpi_quota_ok"))}</div>
        <div class="agent-kpi-lbl">${escHtml(t("agent_kpi_quota_warn"))}</div>
      </div>
    `;
  }

  // 3. 低额度横幅
  const lowWrap = $("agent-low-quota-wrap");
  if (lowWrap) {
    if (low.length > 0) {
      lowWrap.hidden = false;
      lowWrap.innerHTML = `
        <div class="agent-low-quota-banner">
          <div class="agent-low-quota-head">${icon("warn", 14)} <span>${escHtml(t("agent_low_quota_banner"))}</span></div>
          <div class="agent-low-quota-list">
            ${low.map(x => `
              <div class="agent-low-quota-item">
                <span><b>${escHtml(x.agent)}</b> · ${escHtml(x.label)}</span>
                <span>${escHtml(t("agent_quota_remaining", { n: x.pct }))} ${x.reset ? `<small style="color:var(--text-ghost)">(${escHtml(x.reset)})</small>` : ''}</span>
              </div>
            `).join("")}
          </div>
        </div>
      `;
    } else {
      lowWrap.hidden = true;
      lowWrap.innerHTML = "";
    }
  }

  // 4. 筛选计数
  const nAll = $("n-rtf-all"), nRun = $("n-rtf-run"), nTasks = $("n-rtf-tasks"), nQuota = $("n-rtf-quota"), nNone = $("n-rtf-none");
  if (nAll) nAll.textContent = `(${allAgents.length})`;
  if (nRun) nRun.textContent = `(${run.length})`;
  if (nTasks) nTasks.textContent = `(${allAgents.filter(rtHasTasks).length})`;
  if (nQuota) nQuota.textContent = `(${allAgents.filter(a => a.installed && rtHasQuota(a)).length})`;
  if (nNone) nNone.textContent = `(${none.length})`;

  // 5. 过滤
  const filtered = allAgents.filter(a => rtMatch(a, rtFilter));

  // 6. 渲染卡片
  const cardsContainer = $("agent-cards-container");
  if (cardsContainer) {
    if (!filtered.length) {
      cardsContainer.innerHTML = `<div class="gempty">${escHtml(t("agent_empty"))}</div>`;
    } else {
      cardsContainer.innerHTML = filtered.map(rtCardHtml).join("");
    }
  }

  // 7. 模型网关探活区
  const modelsContainer = $("agent-models-section");
  if (modelsContainer) {
    modelsContainer.innerHTML = rtModelsSection(d);
    rtBindModels(modelsContainer, d);
  }

  // 8. 智能体运行环境区
  const envContainer = $("agent-env-section");
  if (envContainer) {
    const tools = d.env_tools || {};
    envContainer.innerHTML = `
      <div class="agent-env-section">
        <div class="agent-env-head">${icon("cpu", 14)} <span>${escHtml(t("agent_env_title"))}</span></div>
        <div class="agent-env-grid">
          ${Object.entries(tools).map(([name, ver]) => `
            <div class="agent-env-chip"><b>${escHtml(name)}</b> <span>${escHtml(ver)}</span></div>
          `).join("")}
        </div>
      </div>
    `;
  }

  // 9. 动作与事件监听
  bindAgentHubEvents(el, d);

  if ((d.models && d.models.providers || []).some(p => p.models.some(m => m.test && m.test.status === "running"))) rtPollModels();
  if (d.ctl && d.ctl.running) rtPollCtl();
  else if (d.quota && d.quota.running && !rtTimer) rtPollQuota();
}
function rtModelTestHtml(m) {
  if (BOOT.readonly) return `<span class="rt-mst readonly">${t("st_readonly")}</span>`;
  const r = m.test;
  if (!r) return `<button class="rt-btn ghost" data-mtest="1">${t("rt_m_test")}</button>`;
  if (r.status === "running") return `<span class="rt-mst testing">${t("rt_m_testing")}</span>`;
  return r.ok
    ? `<span class="rt-mst ok">✓ ${r.ms}ms</span><button class="rt-btn ghost" data-mtest="1">${t("rt_m_test")}</button>`
    : `<span class="rt-mst err" title="${escAttr(r.detail || "")}">✗ ${r.http || ""}</span><button class="rt-btn ghost" data-mtest="1">${t("rt_m_test")}</button>`;
}
function rtModelsSection(d) {
  const provs = (d.models && d.models.providers) || [];
  if (!provs.length) return "";
  const anyRunning = provs.some(p => p.models.some(m => m.test && m.test.status === "running"));
  const cards = provs.map(p => {
    const rows = p.models.map(m => `<div class="rt-mrow" data-prov="${escAttr(p.id)}" data-model="${escAttr(m.id)}">
      <span class="rt-mid">${escHtml(m.id)}</span><span class="rt-macts">${rtModelTestHtml(m)}</span></div>`).join("");
    const badge = p.chat_allowed ? "" : `<em class="rt-mprobe" title="${escAttr(t("rt_m_probehint"))}">${t("rt_m_probeonly")}</em>`;
    return `<div class="rt-mcard">
      <div class="rt-mhead"><span class="rt-mkey ${p.has_key ? "ok" : ""}" title="${escAttr(t("rt_m_key"))}"></span>
        <b>${escHtml(p.name)}</b>${badge}<span class="rt-mhost">${escHtml((p.base || "").replace(/^https?:\/\//, "").split("/")[0])}</span></div>
      ${rows}</div>`;
  }).join("");
  const hint = BOOT.readonly ? t("rt_static_hint") : t("rt_m_hint");
  return `<section class="rt-sec"><h3 class="rt-sechead"><span class="rt-sq model"></span>${t("rt_m_title")} <em>${provs.length}</em></h3>
    <div class="rt-mhint">${hint}</div>
    <div class="rt-mgrid">${cards}</div></section>`;
}
function rtBindModels(el, d) {
  el.querySelectorAll("[data-mtest]").forEach(b => b.addEventListener("click", async e => {
    e.stopPropagation();
    const row = b.closest(".rt-mrow");
    const prov = row.dataset.prov, model = row.dataset.model;
    b.outerHTML = `<span class="rt-mst testing">${t("rt_m_testing")}</span>`;
    try { await tlPost("/api/models", { provider: prov, model }); } catch (err) {}
    rtPollModels();
  }));
}
function rtPollModels() {   // 有测试在跑: 2.5s 轮询直到全部完成再整页重渲染
  rtModelTimer = setInterval(async () => {
    if (document.hidden) return;
    try {
      const m = await tlGet("/api/models");
      const running = (m.providers || []).some(p => p.models.some(x => x.test && x.test.status === "running"));
      const el = $("agents-page");
      if (el && !el.hidden) {
        const d = rtCache || await loadRuntimes(true);
        if (d.models) { d.models = m; renderRuntimes(d); }
      }
      if (!running) { clearInterval(rtModelTimer); rtModelTimer = null; }
    } catch (e) { clearInterval(rtModelTimer); rtModelTimer = null; }
  }, 2500);
}
function rtPollQuota() {   // 额度后台刷新中: 6s 后重查重渲染(仍在刷新则继续链式等待)
  setTimeout(async () => {
    try {
      rtT = 0;
      const d = await loadRuntimes(true);
      if ($("agents-page") && !$("agents-page").hidden) renderRuntimes(d);
    } catch (e) { return; }
  }, 6000);
}
function rtPollCtl() {
  if (rtTimer) return;
  rtTimer = setInterval(async () => {
    if (document.hidden) return;
    try {
      const s = await tlGet("/api/agentctl");
      if (!s || !s.running) { clearInterval(rtTimer); rtTimer = null; refreshAgentsPage(); }
    } catch (e) { clearInterval(rtTimer); rtTimer = null; }
  }, 2000);
}
async function initAgentsPage() {
  const el = $("agents-page");
  if (!el) return;
  el.hidden = false;  // 双端进入 agent 页即显示(移动页签 / 桌面 cat=agent)
  bindAgentSubnav();
  if (BOOT.static && BOOT.magpieUsage) {
    try { renderMagpieUsage(BOOT.magpieUsage); } catch (e) {}
  }
  if (BOOT.static && BOOT.magpieRouting) {
    try { renderMagpieRouting(BOOT.magpieRouting); } catch (e) {}
  }
  if (BOOT.static && BOOT.magpieProviders) {
    try { renderMagpieProviders(BOOT.magpieProviders); } catch (e) {}
  }
  if (!BOOT.static) {
    loadMagpieProviders().catch(() => {});
  }
  if (agentsInit) { refreshAgentsPage(); return; }
  agentsInit = true;
  if (curAgentTab === "routing") {
    refreshMagpieRouting().catch(() => {});
  } else if (curAgentTab === "usage") {
    refreshMagpieUsage().catch(() => {});
  } else if (curAgentTab === "providers") {
    refreshMagpieProviders().catch(() => {});
  } else {
    const cards = $("agent-cards-container");
    if (cards) cards.innerHTML = mobileSkelDiv(3);
    try { renderRuntimes(await loadRuntimes()); }
    catch (e) {
      if (cards) cards.innerHTML = esHtml("cpu", t("a_fail", { e: escHtml(e.message) }));
    }
  }
}
let curAgentDetail = null;
let curAgentDetailTab = "basic";

function renderAgentDetailContent(data, tab) {
  if (!data) return `<div class="gempty">${escHtml(t("a_fail", { e: "No data" }))}</div>`;

  if (tab === "basic") {
    const models = data.models || {};
    const procs = data.procs || [];
    const cfg = data.config_summary || {};
    let modelRows = "";
    if (models.default) {
      modelRows += `<div class="ad-info-card">
        <span class="ad-info-label">Default Model</span>
        <span class="ad-info-val">${escHtml(models.default)}</span>
        ${models.provider ? `<span class="ad-skill-cat" style="margin-top:4px;">Provider: ${escHtml(models.provider)}</span>` : ""}
      </div>`;
    }
    if (models.opus || models.sonnet) {
      if (models.opus) {
        modelRows += `<div class="ad-info-card">
          <span class="ad-info-label">Opus Model</span>
          <span class="ad-info-val">${escHtml(models.opus)}</span>
        </div>`;
      }
      if (models.sonnet) {
        modelRows += `<div class="ad-info-card">
          <span class="ad-info-label">Sonnet Model</span>
          <span class="ad-info-val">${escHtml(models.sonnet)}</span>
        </div>`;
      }
    }
    if (models.reasoning_effort) {
      modelRows += `<div class="ad-info-card">
        <span class="ad-info-label">Reasoning Effort</span>
        <span class="ad-info-val">${escHtml(models.reasoning_effort)}</span>
      </div>`;
    }
    if (models.context_length) {
      modelRows += `<div class="ad-info-card">
        <span class="ad-info-label">Context Length</span>
        <span class="ad-info-val">${(models.context_length / 1024).toFixed(0)}k tokens</span>
      </div>`;
    }

    let fallbackHtml = "";
    if (models.fallbacks && models.fallbacks.length) {
      fallbackHtml = `<div class="ad-section">
        <div class="ad-sec-title">${icon("bolt", 13)} Fallback Providers</div>
        <div class="ad-fallback-list">
          ${models.fallbacks.map(fb => `<span class="ad-fallback-chip">${escHtml(fb.provider || "")}: <b>${escHtml(fb.model || "")}</b></span>`).join("")}
        </div>
      </div>`;
    }

    let procsHtml = "";
    if (procs.length) {
      procsHtml = `<div class="ad-section">
        <div class="ad-sec-title">${icon("terminal", 13)} ${t("agent_sec_procs")} (${procs.length})</div>
        <div class="ad-card-grid">
          ${procs.map(p => `<div class="ad-info-card">
            <span class="ad-info-label">PID ${escHtml(p.pid)} · Up ${escHtml(fmtUp(p.up_sec))}</span>
            <span class="ad-info-val">${escHtml(p.cmd || "")}</span>
            <span class="ad-info-label" style="margin-top:2px;">CPU: ${escHtml(p.cpu_pct)}% · Mem: ${escHtml(p.mem_mb)} MB</span>
          </div>`).join("")}
        </div>
      </div>`;
    }

    return `<div class="ad-section">
      <div class="ad-sec-title">${icon("cpu", 13)} ${t("agent_sec_models")}</div>
      <div class="ad-card-grid">
        <div class="ad-info-card">
          <span class="ad-info-label">Version</span>
          <span class="ad-info-val">${escHtml(data.version || "—")}</span>
        </div>
        <div class="ad-info-card">
          <span class="ad-info-label">Binary Path</span>
          <span class="ad-info-val" style="font-family:var(--mono);font-size:11px;">${escHtml(data.bin || "—")}</span>
        </div>
        ${modelRows}
      </div>
      ${fallbackHtml}
      ${procsHtml}
    </div>`;
  }

  if (tab === "skills") {
    const skills = data.skills || [];
    if (!skills.length) {
      return `<div class="gempty">${escHtml(t("agent_no_skills"))}</div>`;
    }
    return `<div class="ad-section">
      <div class="ad-sec-title">${icon("bolt", 13)} ${t("agent_sec_skills")} (${skills.length})</div>
      <div class="ad-skills-grid">
        ${skills.map(s => `<div class="ad-skill-card">
          <div class="ad-skill-top">
            <span class="ad-skill-name">${escHtml(s.name)}</span>
            <span class="ad-skill-cat">${escHtml(s.category)}</span>
          </div>
          ${s.description ? `<div class="ad-skill-desc">${escHtml(s.description)}</div>` : ""}
        </div>`).join("")}
      </div>
    </div>`;
  }

  if (tab === "platforms") {
    const gw = data.gateway || {};
    const plats = data.platforms || {};
    const pKeys = Object.keys(plats);
    const mcp = data.mcp_servers || [];
    const cfg = data.config_summary || {};
    const toolsets = cfg.platform_toolsets || [];

    let platHtml = "";
    if (pKeys.length) {
      platHtml = `<div class="ad-section">
        <div class="ad-sec-title">${icon("share", 13)} Communication Platforms (Gateway)</div>
        <div style="display:flex;flex-direction:column;gap:8px;">
          ${pKeys.map(k => {
            const p = plats[k] || {};
            const st = p.state || "unknown";
            return `<div class="ad-platform-row">
              <div class="ad-platform-name">${icon("message", 15)} ${escHtml(k.toUpperCase())}</div>
              <div style="display:flex;align-items:center;gap:8px;">
                ${p.updated_at ? `<span class="ad-info-label">${escHtml(p.updated_at.slice(0, 19).replace("T", " "))}</span>` : ""}
                <span class="ad-platform-badge ${st === "connected" ? "connected" : ""}">${escHtml(st)}</span>
              </div>
            </div>`;
          }).join("")}
        </div>
      </div>`;
    }

    let toolsetsHtml = "";
    if (toolsets.length) {
      toolsetsHtml = `<div class="ad-section">
        <div class="ad-sec-title">${icon("tool", 13)} Platform Toolsets</div>
        <div class="ad-fallback-list">
          ${toolsets.map(ts => `<span class="ad-fallback-chip">${escHtml(ts)}</span>`).join("")}
        </div>
      </div>`;
    }

    let mcpHtml = "";
    if (mcp.length) {
      mcpHtml = `<div class="ad-section">
        <div class="ad-sec-title">${icon("gauge", 13)} MCP Servers (${mcp.length})</div>
        <div class="ad-card-grid">
          ${mcp.map(m => `<div class="ad-info-card">
            <span class="ad-info-label">MCP Server</span>
            <span class="ad-info-val">${escHtml(m.name)}</span>
            <span class="ad-info-label" style="font-family:var(--mono);margin-top:2px;">${escHtml(m.command)}</span>
          </div>`).join("")}
        </div>
      </div>`;
    }

    return `<div style="display:flex;flex-direction:column;gap:16px;">
      ${platHtml || `<div class="gempty">${t("agent_no_platforms")}</div>`}
      ${toolsetsHtml}
      ${mcpHtml}
    </div>`;
  }

  if (tab === "memories") {
    const mems = data.memories || {};
    const mKeys = Object.keys(mems);
    if (!mKeys.length) {
      return `<div class="gempty">${escHtml(t("agent_no_memories"))}</div>`;
    }
    return `<div class="ad-section">
      <div class="ad-sec-title">${icon("book", 13)} ${t("agent_sec_memories")}</div>
      <div style="display:flex;flex-direction:column;gap:12px;">
        ${mKeys.map(k => {
          const m = mems[k] || {};
          const topics = m.topics || [];
          return `<div class="ad-memory-box">
            <div class="ad-memory-head">
              <span class="ad-memory-title">${escHtml(k)}</span>
              <span class="ad-memory-count">t("agent_mem_count", { n: m.count || 0 })</span>
            </div>
            ${m.preview ? `<div class="ad-skill-desc" style="color:var(--text-title);">${escHtml(m.preview)}</div>` : ""}
            <div class="ad-memory-items">
              ${topics.map(tText => `<div class="ad-memory-item">${escHtml(tText)}</div>`).join("")}
            </div>
          </div>`;
        }).join("")}
      </div>
    </div>`;
  }

  if (tab === "cron") {
    const cron = data.cron || [];
    if (!cron.length) {
      return `<div class="gempty">${escHtml(t("agent_no_cron"))}</div>`;
    }
    return `<div class="ad-section">
      <div class="ad-sec-title">${icon("clock", 13)} ${t("agent_sec_cron")} (${cron.length})</div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        ${cron.map(j => `<div class="ad-cron-card">
          <div class="ad-cron-top">
            <span class="ad-cron-name">${escHtml(j.name || j.id)}</span>
            <span class="ad-cron-sched">${escHtml(j.schedule || "")}</span>
          </div>
          ${j.prompt ? `<div class="ad-cron-prompt">${escHtml(j.prompt)}</div>` : ""}
          <div class="ad-cron-meta">
            <span>Status: <b style="color:${j.last_status === 'ok' ? '#4ade80' : '#f87171'}">${escHtml(j.last_status || 'never')}</b></span>
            ${j.last_run_at ? `<span>Last: ${escHtml(j.last_run_at.slice(0, 19).replace('T', ' '))}</span>` : ""}
            ${j.next_run_at ? `<span>Next: ${escHtml(j.next_run_at.slice(0, 19).replace('T', ' '))}</span>` : ""}
            ${j.origin && j.origin.platform ? `<span>Deliver: <b>${escHtml(j.origin.platform)}</b></span>` : ""}
          </div>
        </div>`).join("")}
      </div>
    </div>`;
  }

  return "";
}

function closeAgentDetail() {
  const sheet = $("agent-detail-sheet");
  if (!sheet) return;
  sheet.hidden = true;
  document.documentElement.classList.remove("traj-noscroll");
}

// 把正文顶边对准页签底边。高度交给 top/bottom，不再写 height。
function revealAgentSheetBody() {
  const sheet = $("agent-detail-sheet");
  const nav = $("agent-sheet-nav");
  const body = $("agent-sheet-body");
  if (!sheet || !body || sheet.hidden) return;
  const apply = () => {
    if (sheet.hidden) return;
    const sheetTop = sheet.getBoundingClientRect().top;
    const navBottom = nav ? nav.getBoundingClientRect().bottom : sheetTop + 132;
    const top = Math.max(0, Math.round(navBottom - sheetTop));
    body.style.top = top + "px";
    body.style.height = "";
    body.style.minHeight = "";
  };
  apply();
  requestAnimationFrame(apply);
  setTimeout(apply, 60);
}
if (!window._agentSheetRevealBound) {
  window._agentSheetRevealBound = true;
  window.addEventListener("resize", revealAgentSheetBody);
  if (window.visualViewport) window.visualViewport.addEventListener("resize", revealAgentSheetBody);
}

async function openAgentDetail(agentId) {
  const sheet = $("agent-detail-sheet");
  const title = $("agent-sheet-title");
  const sub = $("agent-sheet-sub");
  const dot = $("agent-sheet-dot");
  const pill = $("agent-sheet-pill");
  const body = $("agent-sheet-body");
  const backBtn = $("agent-sheet-back");
  const nav = $("agent-sheet-nav");
  if (!sheet || !body) return;

  curAgentDetailTab = "basic";
  sheet.hidden = false;
  sheet.classList.remove("opening"); void sheet.offsetWidth; sheet.classList.add("opening");
  document.documentElement.classList.add("traj-noscroll");
  haptic(8);
  body.innerHTML = `<div class="gempty">${escHtml(t("st_loading"))}</div>`;

  if (backBtn && !backBtn.dataset.bound) {
    backBtn.dataset.bound = "1";
    backBtn.addEventListener("click", closeAgentDetail);
  }

  // 绑定 tab 切换
  if (nav && !nav.dataset.bound) {
    nav.dataset.bound = "1";
    nav.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip");
      if (!chip || !chip.dataset.adtab) return;
      nav.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      curAgentDetailTab = chip.dataset.adtab;
      body.innerHTML = renderAgentDetailContent(curAgentDetail, curAgentDetailTab);
      revealAgentSheetBody();
    });
  }

  // 重置 tab 激活态
  nav?.querySelectorAll(".chip")?.forEach(c => {
    if (c.dataset.adtab === "basic") c.classList.add("active");
    else c.classList.remove("active");
  });

  try {
    let d = null;
    // 静态公网优先使用 BOOT.agentDetails
    if (BOOT && BOOT.agentDetails && BOOT.agentDetails[agentId]) {
      d = BOOT.agentDetails[agentId];
    } else {
      const r = await fetch("/api/agentdetail?agent=" + encodeURIComponent(agentId), { cache: "no-store" });
      d = await r.json();
    }
    if (!d || !d.ok) throw new Error((d && d.msg) || "failed to load");
    curAgentDetail = d;

    if (title) title.textContent = t("agent_detail_title", { name: d.name });
    if (sub) sub.textContent = d.bin || "";
    if (dot) {
      dot.className = "agent-status-dot " + (d.procs && d.procs.length ? "on" : (d.installed ? "idle" : ""));
    }
    if (pill) {
      pill.className = "agent-pill " + (d.procs && d.procs.length ? "run" : (d.installed ? "idle" : "none"));
      pill.textContent = d.procs && d.procs.length ? `${t("rt_f_run")} (${d.procs.length})` : (d.installed ? t("rt_sec_idle") : t("rt_f_none"));
    }

    const sCnt = $("ad-skills-count");
    if (sCnt) sCnt.textContent = (d.skills && d.skills.length) ? `(${d.skills.length})` : "";
    const cCnt = $("ad-cron-count");
    if (cCnt) cCnt.textContent = (d.cron && d.cron.length) ? `(${d.cron.length})` : "";

    body.innerHTML = renderAgentDetailContent(d, curAgentDetailTab);
    revealAgentSheetBody();
  } catch (err) {
    body.innerHTML = `<div class="gempty">${escHtml(t("a_fail", { e: err.message }))}</div>`;
    revealAgentSheetBody();
  }
}

document.addEventListener("click", e => {
  const b = e.target.closest(".btn-agent-detail");
  if (b) {
    e.preventDefault();
    e.stopPropagation();
    openAgentDetail(b.dataset.agentId);
    return;
  }
  if (e.target.closest("#agent-sheet-back")) {
    closeAgentDetail();
    return;
  }
});

// --- Goal 详情: 双栏 KV + ANSI 彩色终端 + 活动/事件; 宽弹层 ---
function goalDetailHtml(d) {
  const esc = escHtml;
  const g = d.goal || {}, w = d.watchdog || {}, p = d.pane || {};
  const kv = (k, v) => `<span class="k">${esc(k)}</span><span class="v">${esc(v || "—")}</span>`;
  const nAct = (d.activities || []).length, nEvt = (d.events || []).length;
  const activity = (d.activities || []).map(x => `<div class="g-detail-event"><span class="kind">${esc(x.kind)}</span>${esc(x.text)}</div>`).join("");
  const events = (d.events || []).map(x => `<div class="g-detail-event"><span class="time">${esc(x.time || "")}</span><span class="kind">${esc(x.kind || "event")}</span>${esc(x.text || "")}</div>`).join("");
  const capture = (d.capture || []).join("\n");
  return `<div class="g-detail-body">
    <div class="g-detail-grid">
    <section class="g-detail-section"><h3>${t("g_status_detail")}</h3><div class="g-detail-kv">` +
      kv(t("g_field_status"), g.light) + kv(t("g_field_idle"), g.idle_sec == null ? "—" : t("g_seconds", { n: g.idle_sec })) +
      kv("Context", g.ctx_raw) + kv("Retry", g.retry) + kv(t("gd_progress"), (g.progress || []).join("\n")) + `</div></section>` +
    `<section class="g-detail-section"><h3>${t("g_runtime_detail")}</h3><div class="g-detail-kv">` +
      kv("Goal ID", g.gid || w.gid) + kv("Session", w.session) + kv("PID / Pane", `${p.pid || "—"} / ${p.pane || "—"}`) + kv(t("gd_workdir"), w.workdir) + kv("JSONL", w.jsonl) + `</div></section>
    </div>` +
    (capture ? `<section class="g-detail-section"><h3>${t("g_terminal_detail")}</h3><pre class="g-detail-log">${ansiToHtml(capture)}</pre></section>` : "") +
    `<div class="g-detail-grid">
    <section class="g-detail-section"><h3>${t("g_activity_detail")} (${nAct})</h3><div class="g-detail-events">${activity || `<div>${t("g_no_activity")}</div>`}</div></section>` +
    `<section class="g-detail-section"><h3>${t("g_watchdog_detail")} (${nEvt})</h3><div class="g-detail-events">${events || `<div>${t("g_no_activity")}</div>`}</div></section>
    </div>
  </div>`;
}
async function openGoalDetail(btn) {
  const modal = $("ui-modal"), title = $("ui-dialog-title"), msg = $("ui-dialog-msg"), ok = $("ui-ok"), cancel = $("ui-cancel");
  if (!modal || !title || !msg || !cancel) return;
  title.innerHTML = icon("doc", 17) + " <span>" + escHtml(btn.closest(".gcard")?.querySelector(".gname")?.textContent?.trim() || t("g_view_detail")) + "</span>";
  msg.innerHTML = `<div class="g-detail-body">${t("a_loading")}</div>`;
  if (ok) ok.hidden = true;
  cancel.textContent = t("m_close"); modal.hidden = false; document.body.classList.add("modal-open");
  modal.classList.add("detail-wide");
  const close = () => { modal.hidden = true; document.body.classList.remove("modal-open"); modal.classList.remove("detail-wide"); if (ok) ok.hidden = false; cancel.textContent = t("m_cancel"); cancel.removeEventListener("click", close); modal.removeEventListener("click", outside); document.removeEventListener("keydown", key); };
  const outside = e => { if (e.target === modal) close(); };
  const key = e => { if (e.key === "Escape") close(); };
  cancel.addEventListener("click", close); modal.addEventListener("click", outside); document.addEventListener("keydown", key);
  try {
    const q = "gid=" + encodeURIComponent(btn.dataset.gid || "") + "&session=" + encodeURIComponent(btn.dataset.session || "");
    const r = await fetch("/api/goaldetail?" + q, { cache: "no-store" });
    const d = await r.json();
    if (!r.ok || !d.ok) throw new Error(d.msg || "HTTP " + r.status);
    msg.innerHTML = goalDetailHtml(d);
  } catch (e) { msg.innerHTML = `<div class="g-detail-log">${escHtml(e.message)}</div>`; }
  cancel.focus();
}
document.addEventListener("click", e => {
  const b = e.target.closest(".g-detail-btn");
  if (!b) return;
  e.preventDefault(); e.stopPropagation(); openGoalDetail(b);
});

// --- goal 卡"标记忽略"(P1-8): 接概要页 ignoredSet, 同 goal+类型不再提醒 ---
document.addEventListener("click", (e) => {
  const b = e.target.closest(".g-ignore-btn");
  if (!b || b.classList.contains("ignored")) return;
  addIgnore(b.dataset.ignKey || "");
  b.classList.add("ignored");
  b.textContent = t("g_ignored");
  haptic(8);
  renderOverview(null);   // 概要"需要处理"同步去掉对应告警
});

// --- 移动服务卡长命令折叠/展开(P1-6): 点命令行本身切换 2 行截断 ---
document.addEventListener("click", (e) => {
  const m = e.target.closest(".mclamp");
  if (!m) return;
  m.classList.toggle("open");
  m.setAttribute("aria-expanded", m.classList.contains("open") ? "true" : "false");
});

// --- goal 卡「▶ 恢复运行」按钮: POST /api/goalresume ---
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".g-resume-btn");
  if (!btn) return;
  e.preventDefault(); e.stopPropagation();
  const cmd = btn.dataset.resumeCmd || "";
  if (!cmd) return;
  btn.disabled = true;
  const origHtml = btn.innerHTML;
  btn.textContent = "…";
  haptic(10);
  try {
    const r = await tlPost("/api/goalresume", { resume_cmd: cmd });
    if (r && r.ok) {
      btn.innerHTML = icon("ok", 12) + " " + escHtml(t("g_resumed"));
      btn.classList.add("ok");
      // 唤醒成功后，2.5 秒自动刷新 Tmux 会话列表，使新会话即时出现
      setTimeout(async () => {
        try {
          await fetchTmuxData(true);
          await fetchGoalsData(true);
          renderTmuxPage();
        } catch (_) {}
      }, 2500);
    } else {
      btn.textContent = "✗ " + escHtml((r && r.msg) || "error");
    }
  } catch (err) {
    btn.textContent = "✗ err";
  }
  setTimeout(() => {
    btn.disabled = false;
    btn.classList.remove("ok");
    btn.innerHTML = origHtml;
  }, 4000);
});

// --- Tmux 会话「⚡ 唤醒推进」按钮: 调用 Hermes 自动判断并推进任务 ---
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".btn-tmux-wake");
  if (!btn) return;
  e.preventDefault(); e.stopPropagation();
  const sname = btn.dataset.sname;
  if (!sname) return;
  btn.disabled = true;
  const origHtml = btn.innerHTML;
  btn.innerHTML = `${icon("bolt", 12)} <span>⚡ ${t("tac_wake_running")}</span>`;
  btn.classList.add("working");
  haptic(10);
  try {
    const r = await tlPost("/api/tmux/wake", { session: sname, pane: (btn.dataset.target || "").split(":")[1] || "" });
    if (r && r.ok) {
      btn.innerHTML = `${icon("ok", 12)} <span>${escHtml(r.msg || t("tac_wake_done"))}</span>`;
      btn.classList.remove("working");
      btn.classList.add("success");
      haptic(15);
      // 推进成功后，延迟 1.5 秒刷新当前会话终端画面
      setTimeout(async () => {
        try {
          await fetchTmuxData(true);
          renderTmuxPage();
        } catch (_) {}
      }, 1500);
    } else {
      btn.innerHTML = `<span>✗ ${escHtml((r && r.msg) || t("tac_wake_fail"))}</span>`;
    }
  } catch (err) {
    btn.innerHTML = `<span>✗ ${escHtml(err.message)}</span>`;
  }
  setTimeout(() => {
    btn.disabled = false;
    btn.classList.remove("working", "success");
    btn.innerHTML = origHtml;
  }, 4500);
});

// --- 定时任务「▶ 触发」按钮: POST /api/tasks/run ---
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".btn-task-trigger");
  if (!btn) return;
  e.preventDefault(); e.stopPropagation();
  const name = btn.dataset.name, kind = btn.dataset.kind, scope = btn.dataset.scope;
  if (!name) return;
  btn.disabled = true;
  const origText = btn.innerHTML;
  btn.textContent = "…";
  haptic(10);
  try {
    const r = await tlPost("/api/tasks/run", { name, kind, scope });
    if (r && r.ok) {
      btn.innerHTML = `${icon("ok", 11)} <span>${t("tac_triggered")}</span>`;
      btn.classList.add("ok");
      setTimeout(() => { tasksCache = null; loadTasks().then(renderWatchdogPanel); }, 1500);
    } else {
      btn.textContent = "✗ " + ((r && r.msg) || t("tac_fail"));
    }
  } catch (err) {
    btn.textContent = "✗ " + t("tac_error");
  }
  setTimeout(() => {
    btn.disabled = false;
    btn.classList.remove("ok");
    btn.innerHTML = origText;
  }, 3500);
});

// --- Tmux 窗格「▶ 预览」终端输出 ---
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".btn-tmux-preview");
  if (!btn) return;
  e.preventDefault(); e.stopPropagation();
  const target = btn.dataset.target;
  if (!target) return;
  const tr = btn.closest("tr");
  if (!tr) return;
  let nextRow = tr.nextElementSibling;
  if (nextRow && nextRow.classList.contains("tmux-preview-row")) {
    nextRow.remove();
    btn.classList.remove("active");
    return;
  }
  btn.classList.add("active");
  const newRow = document.createElement("tr");
  newRow.className = "tmux-preview-row";
  newRow.innerHTML = `<td colspan="6" style="padding:10px;background:rgba(0,0,0,.35);"><div class="termlog" style="max-height:220px;overflow-y:auto;font-family:ui-monospace,monospace;font-size:11px;line-height:1.35;white-space:pre-wrap;">${t("a_loading")}</div></td>`;
  tr.after(newRow);
  try {
    const r = await fetch(`/api/tmux/capture?target=${encodeURIComponent(target)}&lines=40&ansi=1`, { cache: "no-store" });
    const d = await r.json();
    const box = newRow.querySelector(".termlog");
    if (box) {
      if (d.ok && d.capture) box.innerHTML = ansiToHtml(d.capture);
      else box.textContent = t("tmux_capture_fail", { e: d.msg || t("tmux_capture_unknown") });
    }
  } catch (err) {
    const box = newRow.querySelector(".termlog");
    if (box) box.textContent = t("tmux_capture_err", { e: err.message });
  }
});

document.addEventListener("click", (e) => {
    const g = e.target.closest(".gcard");
    if (!g || !isMobile()) return;
    if (e.target.closest(".gcopy")) return;           // 复制 resume 命令: 交给全局 gcopy
    if (e.target.closest(".g-detail-btn")) return;    // 查看详情: 交给 goal 详情弹层
    if (e.target.closest(".g-ignore-btn")) return;    // 标记忽略: 交给上方忽略委托
    if (e.target.closest(".g-resume-btn")) return;    // 恢复运行: 交给上方委托
    if (g.querySelector(".gextra")) { g.classList.toggle("open"); haptic(6); }
});


// --- 服务行"详情"按钮: 弹层看完整启动命令/工作目录 (复用主题化 ui-modal) ---
document.addEventListener("click", async (e) => {
  const b = e.target.closest(".svc-detail");
  if (!b) return;
  let d = {};
  try { d = JSON.parse(decodeURIComponent(b.dataset.detail || "")); } catch (err) { return; }
  const modal = $("ui-modal"), title = $("ui-dialog-title"), msg = $("ui-dialog-msg"), cancel = $("ui-cancel");
  if (!modal || !msg || !title || !cancel) return;
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  title.innerHTML = icon("doc", 17) + " <span>" + esc(d.name || "") + "</span>";
  const r = d.res || {};
  const resRows = (r.cpu === undefined ? "" :
      `<span class="k">${t("sys_cpu")}</span><span class="v">${r.cpu.toFixed(1)}%</span>`
      + `<span class="k">${t("sys_mem")}</span><span class="v">${r.mem_mb >= 1024 ? (r.mem_mb / 1024).toFixed(1) + " GB" : Math.round(r.mem_mb) + " MB"}</span>`
      + `<span class="k">${t("res_up")}</span><span class="v">${fmtUp(r.up_sec)}</span>`)
    + (d.unit ? `<span class="k">unit</span><span class="v">${esc(d.unit)}</span>` : "")
    + (d.cid ? `<span class="k">${t("detail_cid")}</span><span class="v">${esc(d.cid)}</span>` : "");
  msg.innerHTML = `<div class="svc-detail-kv">`
    + `<span class="k">${t("th_port")}</span><span class="v">${esc(d.port || "—")}</span>`
    + `<span class="k">${t("th_addr")}</span><span class="v">${esc(d.ip || "—")}</span>`
    + `<span class="k">PID</span><span class="v">${esc((d.pids || []).join(", ") || "—")}</span>`
    + resRows
    + `<span class="k">${t("th_cmd")}</span><span class="v">${esc(d.cmd || "—")}</span>`
    + `<span class="k">${t("th_cwd")}</span><span class="v">${esc(d.cwd || "—")}</span></div>`;
  cancel.textContent = t("m_close");
  modal.hidden = false;
  const onClose = () => { cancel.textContent = t("m_cancel"); };
  cancel.addEventListener("click", onClose, { once: true });
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
  } else { lastTap = now; lastTapEl = stat; }
}, { passive: true });

// --- 触摸手势: 横向滑动不再用于切页(改由底部页签按钮切换),
//     横向手势交给原生滚动, 让 .act-repos-scroll / .filters 等横向容器可滑动查看被裁剪的内容 ---

// --- 负载/CPU 折线图(最近 24 采样存 localStorage, 捏合调时间窗) ---
const chart = $("chart");
function chartData() {
  if (BOOT.static && Array.isArray(BOOT.chartData)) return BOOT.chartData;
  try { return JSON.parse(localStorage.getItem("svc-chart") || "[]"); }
  catch (e) { return []; }
}
function chartSave(arr) { try { localStorage.setItem("svc-chart", JSON.stringify(arr)); } catch (e) {} }
function chartSample(s) {
  if (!chart) return;
  if (BOOT.static) { drawChart(); return; }
  const arr = chartData();
  const now = Date.now();
  const m = s.mem || {};
  arr.push({ t: now, load: (s.loadavg || [null])[0] ?? (s.loadavg || [])[2] ?? null, cpu: s.cpu_usage,
             mem: m.percent ?? null, swap: m.swap_percent ?? null });
  while (arr.length > 24) arr.shift();
  chartSave(arr);
  drawChart();
}
let chartWin = 24;
function drawChart() {
  if (!chart) return;
  const rect = chart.getBoundingClientRect();
  const w = Math.round(rect.width || chart.clientWidth);
  const h = Math.round(rect.height || chart.clientHeight || 150);
  if (w <= 0 || h <= 0) {
    requestAnimationFrame(() => { if (chart.clientWidth > 0) drawChart(); });
    return;
  }
  const dpr = window.devicePixelRatio || 1;
  const targetW = Math.round(w * dpr);
  const targetH = Math.round(h * dpr);
  if (chart.width !== targetW || chart.height !== targetH) {
    chart.width = targetW;
    chart.height = targetH;
  }
  const ctx = chart.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const all = chartData();
  const emptyEl = $("chart-empty");
  const winEl = $("chart-win");
  if (!all.length) {
    if (emptyEl) emptyEl.style.display = "";
    if (winEl) winEl.textContent = "";
    return;
  }
  if (emptyEl) emptyEl.style.display = "none";
  if (winEl) winEl.textContent = t("chart_win", { n: Math.min(chartWin, all.length) });

  const data = all.length === 1 ? [all[0], all[0]] : all.slice(-chartWin);
  const maxL = Math.max(2, ...data.map(d => d.load || 0));
  // 采样点不足时从右侧向前排布，防止少量点生硬拉伸横跨整屏
  const step = (w - 24) / Math.max(chartWin - 1, 1);
  const X = i => (w - 12) - (data.length - 1 - i) * step;
  // 主题色从 CSS 变量读取(getComputedStyle), 明暗主题切换即跟随
  const cs = getComputedStyle(document.documentElement);
  const cssVar = (n) => cs.getPropertyValue(n).trim();
  const CH = { cpu: cssVar("--ch-cpu") || "#0a84ff", load: cssVar("--ch-load") || "#30d158",
               mem: cssVar("--ch-mem") || "#ff9f0a", swap: cssVar("--ch-swap") || "#bf5af2",
               grid: cssVar("--ch-grid") || "rgba(255,255,255,.08)" };
  // 网格线
  ctx.strokeStyle = CH.grid; ctx.lineWidth = 1;
  [0.25, 0.5, 0.75].forEach(f => { ctx.beginPath(); ctx.moveTo(0, h * f); ctx.lineTo(w, h * f); ctx.stroke(); });

  const drawLine = (color, width, getY) => {
    ctx.strokeStyle = color; ctx.lineWidth = width; ctx.beginPath();
    data.forEach((d, i) => { const y = getY(d); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
    ctx.stroke();
    if (data.length <= 8) {
      ctx.fillStyle = color;
      data.forEach((d, i) => {
        const y = getY(d);
        ctx.beginPath(); ctx.arc(X(i), y, 2.5, 0, Math.PI * 2); ctx.fill();
      });
    }
  };

  // CPU %: 0-100 映射
  drawLine(CH.cpu, 1.6, d => h - 6 - (d.cpu || 0) / 100 * (h - 18));
  // 内存 %: 0-100 映射(橙)
  drawLine(CH.mem, 1.6, d => h - 6 - (d.mem || 0) / 100 * (h - 18));
  // Swap %: 0-100 映射(紫)
  drawLine(CH.swap, 1.6, d => h - 6 - (d.swap || 0) / 100 * (h - 18));
  // 负载: 按各自 max 缩放
  drawLine(CH.load, 1.8, d => h - 6 - (d.load || 0) / maxL * (h - 18));

  // 图例(现代无衬线体防宽体字畸变)
  ctx.font = "600 11px system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'SF Pro Text', sans-serif";
  const lastD = data[data.length - 1];
  ctx.fillStyle = CH.cpu; ctx.fillText("CPU " + Math.round(lastD.cpu || 0) + "%", 8, 16);
  ctx.fillStyle = CH.mem; ctx.fillText("mem " + Math.round(lastD.mem || 0) + "%", 8, 32);
  ctx.fillStyle = CH.swap; ctx.fillText("swap " + Math.round(lastD.swap || 0) + "%", 8, 48);
  // load 标签也放左侧第四行: 放右上角会压在采样点不足时靠右聚拢的负载点上
  ctx.fillStyle = CH.load; ctx.fillText("load " + maxL.toFixed(1), 8, 64);
}
if (chart) {
  window.addEventListener("resize", () => requestAnimationFrame(drawChart));
  mqMobile.addEventListener("change", () => requestAnimationFrame(drawChart));
  if (window.ResizeObserver) {
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.width > 0) drawChart();
      }
    });
    ro.observe(chart);
    const wrap = $("chart-wrap");
    if (wrap) ro.observe(wrap);
  }
  requestAnimationFrame(drawChart);
  setTimeout(drawChart, 150);
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
    if (!BOOT.static && autoOn && !autoLocked) load(false); // 回前台立即刷一次(锁定时不刷)
  }
});

// --- 手机端 30s 自动刷新(省电); 桌面保持 AUTO ---
const MOBILE_REFRESH_SEC = 30;
let autoSec = AUTO;
function applyAutoSec() {
  const sec = isMobile() ? MOBILE_REFRESH_SEC : AUTO;
  if (sec !== autoSec) {
    autoSec = sec;
    clearInterval(autoTimer);
    autoTimer = setInterval(autoTick, autoSec * 1000);
    console.log("[svc-dashboard] auto refresh interval -> " + autoSec + "s");
  }
}
mqMobile.addEventListener("change", applyAutoSec);
let autoTimer = setInterval(autoTick, autoSec * 1000);
function autoTick() {
  if (BOOT.static) return;
  if (autoOn && !autoLocked && !document.hidden) {  // 长按锁定时 30s 自动刷新完全停止
    console.log("[svc-dashboard] auto refresh tick");
    if (filter === "manage") loadManage();
    else load(true);
  }
}
applyAutoSec();

/* ================================================================
   明暗主题: 跟随系统 / 手动深色 / 手动浅色(localStorage 记住)。
   html[data-theme] 覆盖 prefers-color-scheme; meta theme-color 同步;
   切换后 canvas 图表按新 CSS 变量重绘。 */
const THEME_KEY = "svc-theme";
let themeMQ = window.matchMedia("(prefers-color-scheme: light)");
function currentTheme() {
  return document.documentElement.getAttribute("data-theme") || "auto";
}
function applyThemeMeta() {
  const cs = getComputedStyle(document.documentElement);
  const bg = cs.getPropertyValue("--bg").trim() || "#0a0a0a";
  document.querySelector('meta[name="theme-color"]').setAttribute("content", bg);
}
function setTheme(mode) {
  if (mode === "auto") {
    document.documentElement.removeAttribute("data-theme");
    try { localStorage.removeItem(THEME_KEY); } catch (e) {}
  } else {
    document.documentElement.setAttribute("data-theme", mode);
    try { localStorage.setItem(THEME_KEY, mode); } catch (e) {}
  }
  document.querySelectorAll("#theme-chips .chip").forEach(c =>
    c.classList.toggle("active", c.dataset.thm === mode));
  applyThemeMeta();
  drawChart();          // canvas 色值跟随 CSS 变量重绘
  console.log("[svc-dashboard] theme -> " + mode);
}
// 主题切换 toast(与长按锁定共用)
function themeToast(msg) {
  const d = document.createElement("div");
  d.className = "copy-toast";
  d.innerHTML = icon("auto", 13) + " " + msg;
  document.body.appendChild(d);
  setTimeout(() => { d.style.opacity = "0"; setTimeout(() => d.remove(), 350); }, 1400);
}
document.addEventListener("click", (e) => {
  const c = e.target.closest("#theme-chips .chip");
  if (!c) return;
  haptic(6);
  setTheme(c.dataset.thm);
});
setTheme(currentTheme());   // 初始化(含 localStorage 恢复 + meta 同步)
themeMQ.addEventListener("change", () => { applyThemeMeta(); drawChart(); });  // 跟随系统档: 系统切换即更新

// --- 日志页选择器变化 ---
if ($("logagent-sel")) $("logagent-sel").addEventListener("change", loadLogView);

// ================================================================
// 工具页: 健康检查 / 垃圾清理 / 网络速测 / 用户服务 / 计划任务
// ================================================================
const TL_CONF = BOOT.tl;
let toolsInited = false;

function fmtB(n) {
  if (n == null) return "—";
  if (n < 1024) return n + " B";
  const u = ["K", "M", "G", "T"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : 1) + " " + u[i];
}

async function tlGet(url) {
  const withLang = (u) => u + (u.includes("?") ? "&" : "?") + "lang=" + encodeURIComponent(LANG);
  const r = await fetch(withLang(url), { cache: "no-store" });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.msg || ("HTTP " + r.status));
  return d;
}
async function tlPost(url, body) {
  const r = await apiPost(url, body);
  return r.json().catch(() => ({ ok: false, msg: "bad json" }));
}

// --- F2 健康检查 ---
async function runHealth() {
  const btn = $("tl-health-run"), body = $("tl-health-body");
  btn.textContent = t("tl_health_loading");
  try {
    const h = await tlGet("/api/health");
    renderHealth(h);
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
  btn.textContent = t("tl_health_run");
}

function renderHealth(h) {
  const body = $("tl-health-body");
  const big = h.overall === "ok" ? "<span class='t-green'>" + icon("ok", 18) + "</span>"
    : h.overall === "warn" ? "<span class='t-warn'>" + icon("warn", 18) + "</span>"
    : "<span class='t-red'>" + icon("err", 18) + "</span>";
  const rows = [];
  const row = (cls, name, val) =>
    `<div class='tl-row'><span class='tl-dot ${cls}'></span><span class='tl-name'>${escHtml(name)}</span><span class='tl-val'>${val}</span></div>`;
  const s = h.sys || {};
  const la = s.loadavg || [];
  rows.push(row(la[2] > (s.cpu_count || 1) ? "warn" : "", t("tl_h_load"),
    `<b>${la.join(" / ") || "—"}</b> / ${s.cpu_count || "?"}`));
  rows.push(row(s.cpu_usage > 90 ? "warn" : "", t("tl_h_cpu"), `<b>${s.cpu_usage}%</b>`));
  rows.push(row((s.mem || {}).percent >= 90 ? "bad" : (s.mem || {}).percent >= 75 ? "warn" : "",
    t("tl_h_mem"), `<b>${(s.mem || {}).percent}%</b> · ${fmtB((s.mem || {}).used)}/${fmtB((s.mem || {}).total)}`));
  const sw = s.swap || {};
  rows.push(row(sw.percent >= 90 ? "bad" : sw.percent >= 50 ? "warn" : "", t("tl_h_swap"), sw.total ? `<b>${sw.percent}%</b> · ${fmtB(sw.used)}/${fmtB(sw.total)}` : "—"));
  const dk = s.disk || {};
  rows.push(row(dk.percent >= 90 ? "bad" : dk.percent >= 80 ? "warn" : "", t("tl_h_disk"),
    `<b>${dk.percent}%</b> · ${fmtB(dk.free)} ${t("tl_h_free")}`));
  if (h.temp) rows.push(row(h.temp.c >= 80 ? "bad" : h.temp.c >= 65 ? "warn" : "",
    `${t("tl_h_temp")} (${escHtml(h.temp.type)})`, `<b>${h.temp.c}°C</b>`));
  const dt = h.disk_trend || {};
  let trendTxt = t("tl_h_trend_base");
  if (dt.eta_full) trendTxt = t("tl_h_trend_days", { g: fmtB(dt.growth_per_day), d: escHtml(dt.eta_full) });
  else if (dt.days > 1) trendTxt = t("tl_h_trend_base") + ` (${dt.days}d)`;
  rows.push(row(dt.days_left != null && dt.days_left < 30 ? "warn" : "", t("tl_h_trend"), trendTxt));
  (h.procs || []).forEach(p => rows.push(row(p.alive ? "" : "bad", `${t("tl_h_procs")} · ${escHtml(p.name)}`,
    p.alive ? `PID ${p.pid}` : "DOWN")));
  const ports = h.ports || [];
  const up = ports.filter(x => x.up).length;
  // P1-12 去重: 端口/WD 摘要只保留大字告警头(3 秒判断), 删下方两行重复; 端口明细预览保留
  const wdCnt = (h.watchdog_1h || {}).count;
  const headTxt = `${h.overall === "ok" ? t("st_all_ok") : t("st_alert", { n: (ports.length - up) + wdCnt })}`
    + ` · ${t("tl_h_ports")} ${up}/${ports.length} · ${t("tl_h_wd")} ${wdCnt}`;
  body.innerHTML = `<div class='tl-row tl-head-big'><span>${big}</span><span class='tl-name'>${headTxt}</span></div>` + rows.join("") +
    (ports.length ? `<div class='tl-docker-pre' id='tl-ports-pre'>${ports.map(x =>
      `${x.up ? "●" : "○"} :${x.port} ${escHtml(x.name)}`).join("\n")}</div>` : "");
}

// --- 连接信息(IP 复制 chip): ssh/LAN 点击复制, 数据来自 TL_CONF(不写死) ---
function renderConnbar() {
  const grid = $("conn-grid");
  if (!grid) return;
  const hosts = TL_CONF.hosts || {};
  const ts = hosts.tailscale || "", lan = hosts.lan || "";
  const user = (hosts.ssh_user || "tetsuya");
  let h = "";
  if (BOOT.readonly) {
    const currentHost = String(location.hostname || "");
    const onlineHost = /^192\.168\./.test(currentHost) ? currentHost
      : (/^100\.(?:6[4-9]|[7-9]\d|1\d\d)\./.test(currentHost) ? currentHost : TS_HOST);
    const onlineUrl = `http://${onlineHost}/`;
    h += `<a class="h-badge-ro h-online-link" href="${escAttr(onlineUrl)}" title="${escAttr(t("st_online_hint"))}" aria-label="${escAttr(t("st_online"))}">${icon("lock", 12)} ${escHtml(t("st_readonly"))} <span class="h-ro-arrow">↗ ${escHtml(t("st_online"))}</span></a>`;
  }
  if (!BOOT.readonly) {
    if (ts) h += `<span class="gcopy h-live-conn" data-copy="ssh ${user}@${ts}" role="button" tabindex="0" title="ssh ${escAttr(user + '@' + ts)}"><b>${escHtml(ts)}</b></span>`;
    if (lan) h += `<span class="gcopy h-live-conn" data-copy="${escAttr(lan)}" role="button" tabindex="0" title="LAN ${escAttr(lan)}"><b>${escHtml(lan)}</b></span>`;
  }
  grid.innerHTML = h;
  syncConnbarVisibility();
}

function syncConnbarVisibility() {
  const grid = $("conn-grid");
  const home = isMobile() ? page === 0 : curCat === "home";
  // SSH/IP 提示只属于首页；只读快照的“在线版”入口不受影响。
  if (grid) grid.querySelectorAll(".h-live-conn").forEach(el => { el.hidden = !home; });
}

// --- F3 垃圾清理 ---
const CLEAN_IDS = ["journal", "apt", "tmp_old", "hermes_cache", "omp_jsonl", "binobj"];
let cleanItems = [];

async function cleanScan() {
  const btn = $("tl-clean-scan"), body = $("tl-clean-body");
  btn.textContent = t("tl_clean_scanning");
  body.innerHTML = `<div class='gempty'>${t("tl_clean_scanning")}</div>`;
  try {
    const d = await tlPost("/api/cleanup", { dry_run: true });
    cleanItems = (d.items || []).filter(x => !x.display_only);
    const docker = (d.items || []).find(x => x.display_only);
    let h = cleanItems.map(x => {
      const selected = x.safe !== false;
      return `<div class='tl-cleanrow'>` +
        `<span class='clean-toggle${selected ? " selected" : ""}' data-clean='${x.id}' role='button' tabindex='0' aria-pressed='${selected}'>${icon(selected ? "ok" : "dot", 14)}</span>` +
        `<span class='lbl'>${escHtml(x.detail || x.id)}${x.error ? ` <small style='color:var(--c-red)'>${escHtml(x.error)}</small>` : ""}</span>` +
        `<span class='sz'>${fmtB(x.size)}</span></div>`;
    }).join("");
    h += `<div class='tl-row'><span class='tl-dot off'></span><span class='tl-name'>${t("tl_clean_total")}</span>` +
      `<span class='tl-val'><b>${fmtB(cleanItems.reduce((a, x) => a + (x.size || 0), 0))}</b></span></div>`;
    if (docker && docker.raw) {
      h += `<h3 style='margin-top:12px'>${t("tl_clean_docker")}</h3><div class='tl-docker-pre'>${escHtml(docker.raw)}</div>` +
        `<span class='btn tl-run' id='tl-clean-docker' role='button' tabindex='0'>${t("tl_clean_docker_prune")}</span>`;
    }
    body.innerHTML = h;
    body.querySelectorAll(".clean-toggle").forEach(toggle => toggle.addEventListener("click", () => {
      const selected = !toggle.classList.toggle("selected");
      toggle.setAttribute("aria-pressed", selected);
      toggle.innerHTML = icon(selected ? "ok" : "dot", 14);
    }));
    $("tl-clean-exec").hidden = false;
    const dp = $("tl-clean-docker");
    if (dp) dp.addEventListener("click", async () => {
      if (!await uiConfirm(t("tl_clean_docker_confirm"))) return;
      dp.textContent = "…";
      const r = await tlPost("/api/cleanup", { action: "docker_prune" });
      dp.innerHTML = icon(r.ok ? "ok" : "err", 13) + " " + t("tl_clean_docker_prune");
      uiNotice(r.msg || "");
    });
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
  btn.textContent = t("tl_clean_scan");
}

async function cleanExec() {
  const ids = [...document.querySelectorAll(".clean-toggle.selected")].map(x => x.dataset.clean);
  if (!ids.length) return;
  if (!await uiConfirm(t("tl_clean_confirm"))) return;
  const btn = $("tl-clean-exec"), body = $("tl-clean-body");
  btn.textContent = "…";
  const d = await tlPost("/api/cleanup", { dry_run: false, items: ids });
  const rows = (d.results || []).map(r =>
    `<div class='tl-cleanrow'><span class='tl-dot ${r.ok ? "" : "bad"}'></span>` +
    `<span class='lbl'>${escHtml(r.id)}<small>${escHtml(r.msg || "")}</small></span>` +
    `<span class='sz'>${fmtB(r.freed)}</span></div>`).join("");
  body.innerHTML = rows +
    `<div class='tl-row'><span class='tl-dot off'></span><span class='tl-name'>${t("tl_clean_freed")}</span>` +
    `<span class='tl-val'><b>${fmtB(d.df_freed)}</b></span></div>`;
  btn.textContent = t("tl_clean_exec");
  btn.hidden = true;
}

// --- F3b AI 一键清理 (首页面板 + 全屏日志弹层) ---
let _aiTimer = null;
const _aiPoll = async () => {
  try { return await tlGet("/api/aicleanup"); } catch (e) { return { status: "unknown", log_tail: "" }; }
};
async function aiOpenModal() {
  const modal = $("aiclean-modal");
  modal.hidden = false;
  document.body.classList.add("modal-open");
  aiRefresh();          // 立即拉一次并进入轮询
}
function aiCloseModal() {
  $("aiclean-modal").hidden = true;
  document.body.classList.remove("modal-open");
  clearTimeout(_aiTimer);
  aiStatusChip();       // 首页 chip 同步一次
}
async function aiRefresh() {
  const st = await _aiPoll();
  const log = $("aiclean-modal-log"), chip = $("aiclean-modal-st");
  // 展示最近一次运行的完整日志 (从 ===== 分隔符起), 无则提示
  const tail = st.log_tail || "";
  const lastRun = tail.lastIndexOf("===== aiclean start");
  log.textContent = lastRun >= 0 ? tail.slice(lastRun) : (tail || t("tl_aiclean_running"));
  log.scrollTop = log.scrollHeight;
  chip.textContent = st.status === "running" ? `${t("tl_aiclean_running")} ${st.elapsed_s ?? 0}s`
                  : st.status === "error" ? "✗ error" : "✓ done";
  chip.className = "aiclean-st " + st.status;
  const rerun = $("aiclean-modal-rerun");
  clearTimeout(_aiTimer);
  if (st.status === "running") _aiTimer = setTimeout(aiRefresh, document.hidden ? 5000 : 2000);   // 后台标签降频
  else aiStatusChip();
}
async function aiStatusChip() {   // 首页面板按钮/状态行
  const el = $("hp-aiclean-status"); if (!el) return;
  const st = await _aiPoll();
  el.textContent = st.status === "running" ? `${t("tl_aiclean_running")} ${st.elapsed_s ?? 0}s`
                : st.status === "error" ? "✗ " + t("tl_aiclean_lasterr") : "✓ " + t("tl_aiclean_idle");
  el.className = "hp-aiclean-st " + st.status;
  const btn = $("hp-aiclean-run");
  if (btn) btn.textContent = st.status === "running" ? t("tl_aiclean_running") : t("tl_aiclean_run");
}
async function aiRerun() {
  if (!await uiConfirm(t("tl_aiclean_confirm"))) return;
  const r = await tlPost("/api/aicleanup", {});
  if (!r.ok) { uiNotice(r.msg || "failed"); return; }
  aiRefresh();
}
async function aiCleanHome() {
  const st = await _aiPoll();
  if (st.status === "running") { aiOpenModal(); return; }        // 在跑: 直接看实时日志
  // 空闲: 每次点击都发起一轮新清理(确认弹窗防误触)——不再"只带你看上次报告",
  // 旧报告仍在弹层日志里, 看报告→弹层底部"发起一轮新清理"重跑也保留
  if (!await uiConfirm(t("tl_aiclean_confirm"))) return;
  const btn = $("hp-aiclean-run");
  if (btn) btn.textContent = "…";
  const r = await tlPost("/api/aicleanup", {});
  if (!r.ok) { uiNotice(r.msg || "failed"); if (btn) btn.textContent = t("tl_aiclean_run"); return; }
  aiOpenModal();
}

// --- G3 网络速测 ---
async function netRun() {
  const btn = $("tl-net-run"), body = $("tl-net-body");
  btn.textContent = t("tl_net_run_ing");
  body.innerHTML = `<div class='gempty'>${t("tl_net_run_ing")}</div>`;
  try {
    const d = await tlGet("/api/nettest");
    const ts = d.tailscale || {};
    body.innerHTML =
      `<div class='tl-netrow'><span class='tl-name'>${t("tl_net_ext")} (min ${d.samples.length})</span><span class='sep'></span><span class='tl-val'><b>${d.latency_ms != null ? d.latency_ms + " ms" : icon("err", 12)}</b> ${escHtml(d.error || "")}</span></div>` +
      `<div class='tl-netrow'><span class='tl-name'>${t("tl_net_ts")}${ts.peer ? " · " + escHtml(ts.peer) : ""}</span><span class='sep'></span><span class='tl-val'><b>${ts.rtt_ms != null ? ts.rtt_ms + " ms" : escHtml(ts.msg || "—")}</b></span></div>`;
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
  btn.textContent = t("tl_net_run");
}

// --- G2 用户级服务重启(I-KNOW 护栏) ---
async function usvcLoad() {
  const body = $("tl-usvc-body");
  body.innerHTML = `<div class='gempty'>${t("tl_usvc_loading")}</div>`;
  try {
    const d = await tlGet("/api/uservice");
    const unlocked = localStorage.getItem("svc-usvc") === "I-KNOW";
    body.innerHTML = (d.units || []).length ? (d.units || []).map(u => {
      const act = u.active === "active";
      return `<div class='tl-row'><span class='tl-dot ${act ? "" : "warn"}'></span>` +
        `<span class='tl-name'>${escHtml(u.unit)}<br><small style='color:var(--text-dead)'>${escHtml(u.desc)}</small></span>` +
        (unlocked ? `<span class='btn tl-run' data-usvc='${escAttr(u.unit)}' role='button' tabindex='0'>${t("tl_usvc_restart")}</span>` : "") +
        `</div>`;
    }).join("") : `<div class='gempty'>${t("tl_usvc_none")}</div>`;
    body.querySelectorAll("[data-usvc]").forEach(b => b.addEventListener("click", async () => {
      if (!await uiConfirm(`${t("tl_usvc_restart")} ${b.dataset.usvc}?`)) return;
      b.textContent = "…";
      const r = await tlPost("/api/uservice", { unit: b.dataset.usvc, action: "restart" });
      b.innerHTML = icon(r.ok ? "ok" : "err", 13) + " " + t("tl_usvc_restart");
      setTimeout(usvcLoad, 1500);
    }));
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
}

function usvcUnlock() {
  const v = ($("tl-usvc-code").value || "").trim();
  if (v !== "I-KNOW") { uiNotice(t("tl_usvc_wrong")); return; }
  localStorage.setItem("svc-usvc", "I-KNOW");
  $("tl-usvc-unlockwrap").hidden = true;   // 解锁成功: 收起输入行(锁按钮本来就在, 无需翻转)
  usvcLoad();
}

// --- 计划任务(只读, 复用 /api/tasks 的 cron/timer 枚举; 服务页表格样式) ---
async function cronLoad() {
  const body = $("tl-cron-body");
  if (!body) return;
  try {
    const d = await tlGet("/api/tasks?lang=" + encodeURIComponent(LANG));
    const ts = d.tasks || [];
    const cnt = $("cron-count");
    if (cnt) cnt.textContent = ts.length ? t("t_total", { n: ts.length }) : "";
    body.innerHTML = ts.length ? ts.map(x =>
      `<tr><td class='name'>${escHtml(x.name)}</td>` +
      `<td class='cron-sch'>${escHtml(x.schedule)}</td>` +
      `<td class='cron-src'><span class='tbadge ${x.type === "watchdog" ? "wd" : x.type === "reminder" ? "rd" : "sc"}'>${escHtml(x.type)}</span>` +
      `<span class='cron-scope'>${escHtml(x.scope)}</span></td></tr>`).join("")
      : `<tr><td class='empty' colspan='3'>—</td></tr>`;
  } catch (e) {
    body.innerHTML = `<tr><td class='empty t-red' colspan='3'>${icon("err", 13)} ${escHtml(e.message)}</td></tr>`;
  }
}

// --- ツール页初始化(首次进入触发) ---
function initToolsPage() {
  const tp = $("toolspage");
  if (!tp) return;
  tp.hidden = false;
  if (!toolsInited) {
    toolsInited = true;
    renderConnbar();
    runHealth();
    cronLoad();
    if (localStorage.getItem("svc-usvc") === "I-KNOW") usvcLoad();
  }
  // 事件绑定(一次性)
  if (!initToolsPage._bound) {
    initToolsPage._bound = true;
    $("tl-health-run")?.addEventListener("click", runHealth);
    $("tl-clean-scan")?.addEventListener("click", cleanScan);
    $("tl-clean-exec")?.addEventListener("click", cleanExec);
    $("tl-aiclean-run")?.addEventListener("click", aiCleanHome);
    $("tl-net-run")?.addEventListener("click", netRun);
    $("tl-usvc-unlock")?.addEventListener("click", usvcUnlock);
    $("tl-usvc-showlock")?.addEventListener("click", () => {
      const sl = $("tl-usvc-showlock"); if (sl) sl.hidden = true;
      const uw = $("tl-usvc-unlockwrap"); if (uw) uw.hidden = false;
    });
  }
}

// --- 桌面端分类条(右上角 #catbar): 概览/活动/Tmux/Agent/服务; 移动端隐藏(底部页签) ---
const CATS = [
  ["home", "tab_home"], ["activity", "tab_activity"], ["tmux", "nav_tasks"],
  ["agent", "tab_agent"], ["svc", "tab_svc"],
];
const CAT_SELS = {
  home: ["#sysbar", "#chart-wrap", "#hp-vms-grid", "#hp-portal-grid", "#toolchips"],
  activity: ["#activity-page"],
  tmux: ["#tmux-panel"],
  goal: ["#tmux-panel"],
  agent: ["#agents-page"],
  manage: ["#agents-page"],
  svc: ["#svc-head", "#svc-subnav", "#filters", "#network-page", "#tasks", "#svc-panel", "#cron-panel", "#logpage"],
  network: ["#svc-head", "#svc-subnav", "#filters", "#network-page", "#tasks", "#svc-panel", "#cron-panel", "#logpage"],
};
var curCat = "all";
function setCat(c, save) {
  if (c === "network") {
    filter = "tailscale";
    c = "svc";
  }
  curCat = c;
  syncConnbarVisibility();
  document.querySelectorAll("#catbar .cat").forEach(b => b.classList.toggle("active", b.dataset.cat === c));
  const keep = new Set((CAT_SELS[c] || []).map(s => document.querySelector(s)).filter(Boolean));
  document.querySelectorAll("#pages > *").forEach(el => el.classList.toggle("cat-off", !keep.has(el)));
  if (c === "home") requestAnimationFrame(drawChart);
  if (c === "activity") {
    const ap = $("activity-page");
    if (ap) ap.hidden = false;
    renderActivityPage();
  }
  if (c === "tmux" || c === "goal") {
    const tp = $("tmux-panel");
    if (tp) tp.hidden = false;
    tmuxInitSubnav();
    renderTmuxPage();
  }
  if (c === "svc") {
    const lp = $("logpage"), cp = $("cron-panel");
    if (lp) lp.hidden = false;
    if (cp) cp.hidden = false;
    applyFilter();
    initLogPage(); renderLogTimeline(); cronLoad();
  }
  if (c === "agent" || c === "manage") {
    const ap = $("agents-page");
    if (ap) ap.hidden = false;
    initAgentsPage();
  }
  if (save !== false) {
    try { localStorage.setItem("svc-cat", c); } catch (e) {}
    try {
      const u = new URL(location.href);
      if (c === "home") u.hash = ""; else u.hash = "cat=" + c;
      history.replaceState(null, "", u);
    } catch (e) {}
  }
}
function catFromHash() {
  const m = location.hash.match(/^#cat=([a-z]+)/);
  let c = m && m[1] ? m[1] : null;
  if (c === "all") c = "home";
  if (c === "goal") c = "tmux";
  if (c === "log") c = "svc";   // 旧 #cat=log 现落在服务页(日志迁入)
  if (c === "network") { filter = "tailscale"; c = "svc"; }
  if (c === "manage" || c === "tools") c = "agent";
  return CATS.some(x => x[0] === c) ? c : null;
}
window.addEventListener("hashchange", () => {   // 手改 hash/后退也跟随
  const c = catFromHash();
  if (c && c !== curCat) setCat(c, false);
});
(function buildCatbar() {
  const bar = $("catbar");
  if (!bar) return;
  bar.innerHTML = CATS.map(([id, key]) => `<button class="cat" type="button" data-cat="${id}">${t(key)}</button>`).join("");
  bar.addEventListener("click", (e) => {
    const b = e.target.closest(".cat");
    if (!b || b.dataset.cat === curCat) return;
    setCat(b.dataset.cat);
    scrollTo(0, 0);
  });
})();

// 横滚 chips 容器渐隐(.filters): 溢出才加 hf-ov, 滚动位置决定左/右缘渐隐;
// 桌面 .filters 是 wrap 布局永不溢出 → 天然不触发(一处逻辑全站生效)
(function setupFiltersFade() {
  const upd = (el) => {
    const max = el.scrollWidth - el.clientWidth;
    el.classList.toggle("hf-ov", max > 1);
    el.classList.toggle("hf-l", el.scrollLeft > 1);
    el.classList.toggle("hf-r", el.scrollLeft < max - 1);
  };
  document.querySelectorAll(".filters, .agent-subnav").forEach(el => {
    upd(el);
    el.addEventListener("scroll", () => upd(el), { passive: true });
    if (window.ResizeObserver) {
      const ro = new ResizeObserver(() => upd(el));
      ro.observe(el);
      [...el.children].forEach(ch => ro.observe(ch));   // chips 计数/文案变化也重算
    }
    window.addEventListener("resize", () => upd(el));
  });
})();

// --- 静态快照: 所有脱敏占位符打马赛克(只读, 不可取消) ---
// BOOT.redactRe 由服务端按语言生成(privacy.redact_marker_re), 覆盖全部占位文案
// BOOT.redactRe 由服务端按语言生成, 覆盖全部脱敏占位符; 兜底正则兜住发布器后处理产生的标记
const FALLBACK_REDACT_RE = "\\[[^\\[\\n]{0,60}?(?:\\u5df2\\u8131\\u654f|\\u5df2\\u9690\\u85cf|\\u5df2\\u5c4f\\u853d|\\u975e\\u516c\\u958b|redacted|hidden)\\]|\\b[A-Za-z0-9]{1,4}\\*{3}[A-Za-z0-9]{0,3}|\\*{3}REDACTED\\*{3}";
let _redactRe = null;
if (BOOT.static && BOOT.redactRe) {
  try { _redactRe = new RegExp(BOOT.redactRe, "g"); } catch (e) { _redactRe = null; }
}
if (!_redactRe) _redactRe = new RegExp(FALLBACK_REDACT_RE, "g");
// Tmux 页豁免前端马赛克: 该页数据层已整体脱敏(会话匿名/预览屏蔽/字段占位),
// 占位文本保持可读以便分辨会话与窗口; 其余页面照常打码
const REDACT_EXEMPT_SELS = ["#tmux-panel"];
function redactExemptEl() {
  for (const sel of REDACT_EXEMPT_SELS) {
    const el = document.querySelector(sel);
    if (el) return el;
  }
  return null;
}
function applyStaticRedaction(root) {
  if (!_redactRe || !root) return;
  const exempt = redactExemptEl();
  if (exempt) {
    // 还原 Tmux 页上已套的马赛克 span, 让占位文本可见
    exempt.querySelectorAll(".redact-mosaic").forEach(sp => sp.replaceWith(document.createTextNode(sp.textContent || "")));
  }
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      const p = n.parentNode;
      if (p && p.nodeType === 1 && p.classList.contains("redact-mosaic")) return NodeFilter.FILTER_REJECT;
      if (exempt && exempt.contains(n)) return NodeFilter.FILTER_REJECT;
      _redactRe.lastIndex = 0;
      return (n.nodeValue && _redactRe.test(n.nodeValue)) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    }
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach(n => {
    const text = n.nodeValue;
    _redactRe.lastIndex = 0;
    let m;
    const frag = document.createDocumentFragment();
    let last = 0;
    while ((m = _redactRe.exec(text)) !== null) {
      if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
      const span = document.createElement("span");
      span.className = "redact-mosaic";
      span.textContent = m[0];
      span.title = m[0];
      frag.appendChild(span);
      last = m.index + m[0].length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    n.parentNode.replaceChild(frag, n);
  });
}
let _redactTimer = null;
function schedStaticRedaction() {
  clearTimeout(_redactTimer);
  _redactTimer = setTimeout(() => applyStaticRedaction(document.body), 150);
}
if (BOOT.static) {
  document.body.classList.add("is-static", "masking");
  $("rtMask")?.remove();
  $("mp-btn-mask")?.remove();
  if (_redactRe) {
    schedStaticRedaction();
    new MutationObserver(schedStaticRedaction).observe(document.body, {
      childList: true, subtree: true, characterData: true
    });
  }
}

// --- 启动 ---
regroupPages();          // 手机: 分组进 6 页; 桌面: 保持原序
if (isMobile()) {
  // 移动端也解析 #cat= 深链(书签/分享链接直达指定页; 无 hash 保持首页)
  const mCat = catFromHash();
  const mIdx = mCat ? CATS.findIndex(x => x[0] === mCat) : 0;
  setPage(mIdx >= 0 ? mIdx : 0, { first: true });
  applyAutoSec();
} else {
  // 日志/agent 页不再硬锁 hidden: 初始由 HTML hidden 属性遮蔽, 首次 setCat 进入时解除
  let savedCat = catFromHash();
  if (!savedCat) { try { savedCat = localStorage.getItem("svc-cat"); } catch (e) {} }
  if (savedCat === "all") savedCat = "home";
  if (savedCat === "manage") savedCat = "agent";
  setCat(CATS.some(c => c[0] === savedCat) ? savedCat : "home", false);  // URL 优先，随后本地恢复
}
initLogAgentPicker();   // 延后到这里: escHtml 等 const 已初始化(避免 TDZ 崩整页)
initLanguageMenu();
setupMagpieLinks();
load(true);
loadVms();
renderConnbar();   // 顶栏连接信息(ssh/IP)随首屏渲染, 不等进工具页
// AI 清理: 首页面板按钮 + 弹层关闭(独立于工具页惰性初始化, 首页直达)
$("hp-aiclean-run")?.addEventListener("click", aiCleanHome);
$("aiclean-modal-close")?.addEventListener("click", aiCloseModal);
$("aiclean-modal")?.addEventListener("click", e => { if (e.target.id === "aiclean-modal") aiCloseModal(); });
$("aiclean-modal-rerun")?.addEventListener("click", aiRerun);
aiStatusChip();
hydrateFragments();

// ================= TaskHub：任务（Issue）/ 执行日志 =================
// 数据来自本机 TaskHub 引擎(经 svc-dashboard 后端 /api/th/* 转发)；界面完全复用
// 仪表盘的样式与组件，任务只是"活动"里的一个小 tab。


async function thGet(path) {
  try {
    const r = await fetch(path, { cache: "no-store" });
    return await r.json();
  } catch (e) {
    return { ok: false, msg: String(e) };
  }
}

function thAgo(iso) {
  if (!iso) return "—";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!isFinite(s)) return "—";
  if (s < 60) return `刚刚`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}

function thStateLabel(state) {
  const map = { queued: `排队`, starting: `启动中`, running: `运行中`, waiting_user: `运行中`,
                succeeded: `完成`, failed: `失败`, cancelled: `已停止`, lost: `已丢失` };
  return map[state] || state || "—";
}

function thHostChip(run) {
  if (!run) return "";
  const hosts = (TH.hosts && TH.hosts.hosts) || [];
  const h = hosts.find(x => x.id === (run.host || "")) || {};
  const on = h.online !== false;
  return `<span class="chip th-chip th-host ${on ? "th-on" : "th-off"}" title="${on ? escHtml(t("th_online")) : escHtml(t("th_offline"))}">
    ${icon("host", 12)}${escHtml(h.label || run.host || t("th_local"))}</span>`;
}

function thStateChip(run) {
  if (!run) return "";
  return `<span class="chip th-chip th-st th-${escHtml(run.state || "")}">${escHtml(thStateLabel(run.state))}</span>`;
}

function tmuxSetTab() { thRenderTasks(); }

function tmuxInitSubnav() {
  const bar = $("tmux-subnav");
  if (bar && !bar.dataset.wired) {
    bar.dataset.wired = "1";
    bar.addEventListener("click", ev => {
      const btn = ev.target.closest(".page-subnav-btn");
      if (!btn || !btn.dataset.ttab) return;
      const tab = btn.dataset.ttab;
      bar.querySelectorAll(".page-subnav-btn").forEach(b => b.classList.toggle("active", b === btn));
      const vTasks = $("tmux-view-tasks");
      const vSessions = $("tmux-view-sessions");
      if (tab === "tasks") {
        if (vTasks) { vTasks.hidden = false; vTasks.style.display = ""; }
        if (vSessions) { vSessions.hidden = true; vSessions.style.display = "none"; }
        thRenderTasks();
      } else {
        if (vTasks) { vTasks.hidden = true; vTasks.style.display = "none"; }
        if (vSessions) { vSessions.hidden = false; vSessions.style.display = ""; }
        if (typeof renderTmuxPage === "function") renderTmuxPage();
      }
    });
  }

  // 绑定新建任务主按钮
  const btnNew = $("btn-th-new-task") || $("btn-tmux-new-open");
  if (btnNew && !btnNew.dataset.wired) {
    btnNew.dataset.wired = "1";
    btnNew.addEventListener("click", () => thNewTaskModal());
  }

  // 绑定全量刷新按钮
  const btnRefresh = $("btn-th-refresh-all");
  if (btnRefresh && !btnRefresh.dataset.wired) {
    btnRefresh.dataset.wired = "1";
    btnRefresh.addEventListener("click", () => {
      const vTasks = $("tmux-view-tasks");
      if (vTasks && !vTasks.hidden) {
        TH.health = null;
        thRenderTasks();
      } else if (typeof renderTmuxPage === "function") {
        renderTmuxPage();
      }
    });
  }

  thEnsureBase();
  thRenderTasks();
  thStartWatcher();
  thUpdateTmuxBadge();
}

async function thUpdateTmuxBadge() {
  const b = $("n-ttab-sessions");
  if (!b) return;
  const d = await thGet("/api/tmux").catch(() => null);
  if (d && d.sessions) {
    b.textContent = String(d.sessions.length);
  }
}

/* GitHub 没有 webhook 到内网，所以列表靠轮询保持新鲜：
   45s 一次 gh issue list，只有数量/状态/run 发生变化才重绘，避免打扰正在看的详情。 */
function thStartWatcher() {
  if (TH.watch || BOOT.static) return;
  TH.watch = setInterval(async () => {
    if (document.hidden || TH.busy) return;
    const pane = $("tmux-view-tasks");
    if (!pane || pane.offsetParent === null) return;
    TH.busy = true;
    try {
      const d = await thGet("/api/th/issues?mode=all");
      if (d.ok === false) return;
      const sig = (d.issues || [])
        .map(i => `${i.number}:${i.state}:${i.updatedAt}:${i.run ? i.run.state + i.run.id : ""}`)
        .join(",");
      if (sig && sig !== TH.sig) { TH.sig = sig; thRenderTasks(true); }
    } finally { TH.busy = false; }
  }, 45000);
}

function thEnsureBase() {
  return Promise.all([
    TH.hosts ? Promise.resolve(TH.hosts) : thGet("/api/th/hosts").then(d => (TH.hosts = d)),
    TH.health ? Promise.resolve(TH.health) : thGet("/api/th/health").then(d => (TH.health = d)),
  ]);
}

/* 桌面左右两列各自滚动：容器高度 = 视口 - 面板顶部，窗口尺寸变化时重算 */
function thFitSplit() {
  const split = document.querySelector("#tmux-panel .th-split");
  if (!split) return;
  if (!window.matchMedia("(min-width: 701px)").matches) {
    split.style.removeProperty("--th-split-h");
    return;
  }
  let top = 0, el = split;
  while (el) { top += el.offsetTop; el = el.offsetParent; }
  const apply = extra => split.style.setProperty(
    "--th-split-h", Math.max(320, Math.round(window.innerHeight - top - 18 - extra)) + "px");
  apply(0);
  requestAnimationFrame(() => {
    const over = document.scrollingElement.scrollHeight - window.innerHeight;
    if (over > 0) apply(over);
  });
}
window.addEventListener("resize", () => {
  clearTimeout(TH.fitT);
  TH.fitT = setTimeout(thFitSplit, 120);
});

const TH_ACTIVE = new Set(["queued", "starting", "running", "waiting_user"]);
const TH_DISPATCH_KEY = "svc-th-dispatch";   // 上次派发选的执行者 / 机器
const TH_STAGE_ORDER = ["analyze", "plan", "implement", "test", "commit", "pr", "done"];

function thHostName(run) {
  if (!run) return "";
  const hosts = (TH.hosts && TH.hosts.hosts) || [];
  const h = hosts.find(x => x.id === run.host) || {};
  return h.label || run.host || t("th_local");
}

function thCardMeta(parts) {
  return `<div class="th-meta">${parts.filter(Boolean).map(x => `<span>${x}</span>`).join('<i class="th-dot"></i>')}</div>`;
}

function thPercent(run) {
  if (!run) return 0;
  if (typeof run.progress === "number" && run.progress > 0) return Math.min(100, run.progress);
  const idx = TH_STAGE_ORDER.indexOf(run.stage || "");
  return idx < 0 ? 0 : Math.round(((idx + 1) / TH_STAGE_ORDER.length) * 100);
}

function thFormatDuration(sec) {
  if (!sec || sec < 0) return "";
  const s = Math.round(sec);
  if (s < 60) return `${s}秒`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return rem ? `${m}分${rem}秒` : `${m}分钟`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `${h}小时${rm}分`;
}

/* ---------------- 任务列表：支持状态过滤与精简卡片 ---------------- */
async function thRenderTasks(silent) {
  const box = $("th-tasks"); if (!box) return;
  if (BOOT.static) {
    const items = (BOOT.thTasks && BOOT.thTasks.items) || [];
    box.innerHTML = items.length ? `
      <div class="th-group">
        <div class="th-group-head"><span class="th-group-title">${escHtml(t("th_open"))}</span>
          <span class="th-group-n">${items.length}</span></div>
        <div class="th-cards">${items.map((it, i) => `
          <div class="th-card th-row th-static-row" data-th-static="${i}" role="button" tabindex="0">
            <div class="th-title">${escHtml(it.title)}</div>
            ${it.excerpt ? `<div class="th-excerpt">${escHtml(it.excerpt)}</div>` : ""}
          </div>`).join("")}</div>
      </div>` : `<div class="gempty">${escHtml(t("th_empty"))}</div>`;
    box.querySelectorAll("[data-th-static]").forEach(el => el.addEventListener("click", () => {
      box.querySelectorAll(".th-row").forEach(x => x.classList.toggle("selected", x === el));
      thStaticDetail(items[Number(el.dataset.thStatic)] || {});
    }));
    if (items.length && window.matchMedia("(min-width: 701px)").matches) {
      box.querySelector(".th-row")?.classList.add("selected");
      thStaticDetail(items[0]);
    }
    return;
  }

  const keep = silent ? TH.taskView : null;
  const wide = window.matchMedia("(min-width: 701px)").matches;
  box.hidden = false;
  const det = $("th-detail");
  if (det && !wide && !TH.taskView) det.hidden = true;
  if (!TH.taskView) TH.taskView = null;
  if (!TH.filter) TH.filter = "active";

  box.innerHTML = `<div class="th-skeleton"><i></i><i></i><i></i></div>`;
  const d = await thGet("/api/th/issues?mode=all");
  if (d.ok === false) { box.innerHTML = `<div class="gempty t-red">${escHtml(d.msg || `无法读取任务`)}</div>`; return; }
  const items = d.issues || [];
  const running = items.filter(i => i.run && TH_ACTIVE.has(i.run.state));
  const pending = items.filter(i => !i.run && i.state === "open");
  const done = items.filter(i => !running.includes(i) && !pending.includes(i));

  // 更新子导航角标
  const badgeEl = $("n-ttab-tasks");
  if (badgeEl) {
    badgeEl.textContent = running.length ? `⚡${running.length}` : String(running.length + pending.length);
  }

  // 顶部筛选 Chips
  const curF = TH.filter;
  const filterBarHtml = `
    <div class="th-filter-bar">
      <span class="th-filter-chip${curF === 'active' ? ' active' : ''}" data-tf="active">
        活跃任务 <span class="th-filter-count">${running.length + pending.length}</span>
      </span>
      <span class="th-filter-chip${curF === 'running' ? ' active' : ''}" data-tf="running">
        ⚡ 运行中 <span class="th-filter-count">${running.length}</span>
      </span>
      <span class="th-filter-chip${curF === 'pending' ? ' active' : ''}" data-tf="pending">
        待派发 <span class="th-filter-count">${pending.length}</span>
      </span>
      <span class="th-filter-chip${curF === 'done' ? ' active' : ''}" data-tf="done">
        已完成 <span class="th-filter-count">${done.length}</span>
      </span>
      <span class="th-filter-chip${curF === 'all' ? ' active' : ''}" data-tf="all">
        全部 <span class="th-filter-count">${items.length}</span>
      </span>
    </div>`;

  const group = (key, title, list, open) => {
    if (!list.length) return "";
    return `
      <section class="th-group">
        <button class="th-group-head" type="button" data-th-group="${key}">
          <span class="th-group-title">${escHtml(title)}</span>
          <span class="th-group-n">${list.length}</span>
          <span class="th-group-caret">${open ? `收起` : `展开`}</span>
        </button>
        <div class="th-cards" ${open ? "" : "hidden"}>${list.map(i => thTaskCard(i, key)).join("")}</div>
      </section>`;
  };

  let groupsHtml = "";
  if (curF === "active") {
    groupsHtml += group("running", `正在跑`, running, true);
    groupsHtml += group("pending", `待派发`, pending, true);
    if (!running.length && !pending.length) {
      groupsHtml += `<div class="gempty">暂无活跃任务 · 点上方「下发新任务」开始</div>`;
    }
  } else if (curF === "running") {
    groupsHtml += group("running", `正在跑`, running, true);
    if (!running.length) groupsHtml += `<div class="gempty">暂无正在运行的任务</div>`;
  } else if (curF === "pending") {
    groupsHtml += group("pending", `待派发`, pending, true);
    if (!pending.length) groupsHtml += `<div class="gempty">暂无待派发任务</div>`;
  } else if (curF === "done") {
    groupsHtml += group("done", `已完成`, done, true);
    if (!done.length) groupsHtml += `<div class="gempty">暂无已完成任务</div>`;
  } else {
    groupsHtml += group("running", `正在跑`, running, true);
    groupsHtml += group("pending", `待派发`, pending, true);
    groupsHtml += group("done", `已完成`, done, false);
  }

  box.innerHTML = filterBarHtml + groupsHtml;

  // 绑定过滤器点击
  box.querySelectorAll("[data-tf]").forEach(el => el.addEventListener("click", () => {
    TH.filter = el.dataset.tf;
    thRenderTasks();
  }));

  // 展开折叠
  box.querySelectorAll("[data-th-group]").forEach(h => h.addEventListener("click", () => {
    const cards = h.nextElementSibling; if (!cards) return;
    cards.hidden = !cards.hidden;
    h.querySelector(".th-group-caret").textContent = cards.hidden ? `展开` : `收起`;
  }));

  // 点击任务行
  box.querySelectorAll("[data-th-open]").forEach(el => el.addEventListener("click", ev => {
    ev.stopPropagation(); thOpenTask(Number(el.dataset.thOpen));
  }));

  if (wide && !TH.taskView) {
    const first = running[0] || pending[0] || done[0];
    if (first) thOpenTask(first.number, true);
  } else if (keep && box.querySelector(`[data-th-open="${keep}"]`)) {
    box.querySelectorAll(".th-row").forEach(el => el.classList.toggle("selected", Number(el.dataset.thOpen) === keep));
  }

  box.querySelectorAll("[data-th-act]").forEach(el => {
    el.addEventListener("click", ev => {
      ev.stopPropagation();
      const n = Number(el.dataset.num), kind = el.dataset.thAct;
      if (kind === "dispatch") thDispatchModal(n, { title: el.dataset.title || "" });
      if (kind === "restore") thSetState(n, "open");
      if (kind === "cancel") thCancel(el.dataset.run);
      if (kind === "resume") thReply(el.dataset.run, n);
    });
  });

  thFitSplit();
}

function thStaticDetail(it) {
  const det = $("th-detail"); if (!det) return;
  const line = w => `<div class="th-mask-line" style="width:${w}%"></div>`;
  det.innerHTML = `
    <header class="th-head">
      <div class="th-head-line"><span class="th-badge">快照</span></div>
      <h3 class="th-head-title">${escHtml(it.title || "")}</h3>
    </header>
    <div class="th-detail-body">
      <div class="th-static-tag">${escHtml(t("th_static_note"))}</div>
      <section class="th-sec">${line(34)}${line(68)}${line(52)}</section>
      <section class="th-sec">
        <div class="th-sec-head"><span class="th-sec-title">${escHtml(t("th_timeline"))}</span></div>
        ${line(44)}${line(60)}${line(38)}
      </section>
      <section class="th-sec">
        <div class="th-sec-head"><span class="th-sec-title">${escHtml(t("th_issue_body"))}</span></div>
        ${line(92)}${line(86)}${line(74)}${line(90)}${line(58)}
      </section>
    </div>`;
}

function thTaskCard(it, kind) {
  const run = it.run || null;
  const state = run ? thStateLabel(run.state) : (it.state === "closed" ? `已完成` : `待派发`);
  const pct = thPercent(run);
  const excerpt = it.excerpt ? `<div class="th-excerpt" title="${escAttr(it.excerpt)}">${escHtml(it.excerpt)}</div>` : "";
  const selected = TH.taskView === it.number ? " selected" : "";
  const dotState = run ? (run.state || "") : (it.state === "closed" ? "done" : "pending");

  const metaParts = [
    `<b>#${it.number}</b>`,
    run ? escHtml(thHostName(run)) : "",
    run && run.stage ? escHtml(run.stage) : "",
  ].filter(Boolean).join('<i class="th-dot"></i>');

  const progress = (kind === "running" || (run && TH_ACTIVE.has(run.state)))
    ? `<div class="th-progress"><i style="width:${Math.max(12, pct)}%"></i></div>` : "";

  let actions = "";
  if (kind === "running" && run) {
    actions = `<div class="th-row-actions"><button class="th-btn th-btn-sm th-btn-danger" type="button" data-th-act="cancel" data-run="${escAttr(run.id)}">停止</button></div>`;
  } else if (kind === "pending") {
    actions = `<div class="th-row-actions"><button class="th-btn th-btn-sm th-btn-primary" type="button" data-th-act="dispatch" data-num="${it.number}" data-title="${escAttr(it.title || "")}">派发</button></div>`;
  }

  return `<div class="th-card th-row${selected}" data-th-open="${it.number}" role="button" tabindex="0">
    <div class="th-row-head">
      <span class="th-state"><i class="th-led th-led-${escHtml(dotState)}"></i>${escHtml(state)}</span>
      <span class="th-row-id">${metaParts}</span>
      <span class="th-row-time">${escHtml(thAgo(it.updatedAt))}</span>
    </div>
    <div class="th-title" title="${escAttr(it.title || "")}">${escHtml(it.title || "")}</div>
    ${excerpt}
    ${progress}
    ${actions}
  </div>`;
}

/* ---------------- 任务详情：全生命周期流水线 + 实时控制台 + 交互式回复 ---------------- */
async function thOpenTask(number, keepScroll) {
  const box = $("th-tasks"), det = $("th-detail");
  if (!box || !det) return;
  TH.taskView = number;
  if (TH.timer) { clearInterval(TH.timer); TH.timer = null; }
  const wide = window.matchMedia("(min-width: 701px)").matches;
  box.hidden = !wide;
  det.hidden = false;
  if (!wide && !keepScroll) det.scrollIntoView({ block: "start" });
  document.querySelectorAll("#th-tasks .th-row").forEach(el => el.classList.toggle("selected", Number(el.dataset.thOpen) === number));
  det.innerHTML = `<div class="th-skeleton"><i></i><i></i></div>`;

  const d = await thGet(`/api/th/task?number=${encodeURIComponent(number)}`);
  if (d.ok === false) { det.innerHTML = `<div class="gempty t-red">${escHtml(d.msg || `无法读取任务`)}</div>`; return; }

  const issue = d.issue || {}, runs = d.runs || [], latest = d.latest || null, events = d.events || [];
  const activeRun = latest && TH_ACTIVE.has(latest.state);
  const isPending = !activeRun && issue.state !== "closed";
  const isClosed = issue.state === "closed" || (latest && !activeRun);
  const stateKey = latest ? (latest.state || "") : (issue.state === "closed" ? "succeeded" : "pending");
  const stateText = latest ? thStateLabel(latest.state) : (issue.state === "closed" ? `已完成` : `待派发`);

  // 阶段流水线（仅在运行中或有实际执行时计算展示）
  const steps = [
    { key: "dispatch", label: `1. 调度派发` },
    { key: "analyze",  label: `2. 需求分析` },
    { key: "develop",  label: `3. 代码编写` },
    { key: "test",     label: `4. 验证测试` },
    { key: "done",     label: `5. 交付完成` }
  ];

  let curStepIdx = 0;
  if (latest) {
    if (latest.state === "succeeded") {
      curStepIdx = 4;
    } else if (latest.state === "failed" || latest.state === "cancelled" || latest.state === "lost") {
      curStepIdx = Math.max(1, TH_STAGE_ORDER.indexOf(latest.stage || ""));
      if (curStepIdx > 3) curStepIdx = 3;
    } else {
      const stg = latest.stage || "";
      if (stg === "analyze" || stg === "plan") curStepIdx = 1;
      else if (stg === "implement" || stg === "commit") curStepIdx = 2;
      else if (stg === "test" || stg === "pr") curStepIdx = 3;
      else if (stg === "done") curStepIdx = 4;
      else curStepIdx = 2;
    }
  }

  const stepperHtml = activeRun ? `
    <div class="th-stepper">
      ${steps.map((s, idx) => {
        const isDone = (latest && latest.state === "succeeded") || idx < curStepIdx;
        const isCurrent = activeRun && idx === curStepIdx;
        const cls = isDone ? "is-done" : (isCurrent ? "is-current" : "");
        const iconTxt = isDone ? "✓" : String(idx + 1);
        return `
          <div class="th-step-item ${cls}">
            <div class="th-step-dot">${iconTxt}</div>
            <div class="th-step-label">${escHtml(s.label)}</div>
          </div>`;
      }).join("")}
    </div>` : "";

  // 状态横幅
  let statusBannerHtml = "";
  if (activeRun) {
    const durationTxt = latest && latest.duration ? thFormatDuration(latest.duration) : "";
    const runMsg = (latest && latest.message) ? latest.message : `智能体正在运行中…`;
    const isWaiting = latest && latest.state === "waiting_user";
    statusBannerHtml = `
      <div class="th-status-banner${isWaiting ? ' is-warn' : ''}">
        <div class="th-status-msg">
          ${isWaiting ? `⚠️ <b>等待反馈</b>：` : '⚡ '}
          <span>${escHtml(runMsg)}</span>
        </div>
        <div class="th-status-meta">
          ${latest && latest.agent ? `<span class="chip th-chip" style="margin-right:6px;">${escHtml(latest.agent)}</span>` : ''}
          ${durationTxt ? `<span>⏱ ${durationTxt}</span>` : ''}
        </div>
      </div>`;
  }

  // 内联人机交互区（针对 waiting_user 或 运行中随时干预）
  let inlineReplyHtml = "";
  if (activeRun) {
    const isWaiting = latest && latest.state === "waiting_user";
    const phTxt = isWaiting ? `请输入回复内容...` : `例如：检查 models.py 并重新测试...`;
    inlineReplyHtml = `
      <div class="th-inline-reply">
        <div class="th-inline-reply-head">
          <span>${isWaiting ? `💬 智能体等待你的回复：` : `💬 向运行中的智能体追加指令：`}</span>
          <span style="font-size:10.5px;color:var(--text-ghost);">按回车直接发送</span>
        </div>
        <div class="th-inline-reply-box">
          <input type="text" class="th-reply-input" id="th-inline-input" placeholder="${phTxt}" />
          <button class="th-btn th-btn-primary" type="button" id="th-inline-send">发送</button>
        </div>
      </div>`;
  }

  // 待派发场景下的「内置快捷派发面板」
  let quickDispatchHtml = "";
  if (isPending) {
    const hosts = ((TH.hosts && TH.hosts.hosts) || []).filter(h => h.online !== false);
    const defHost = (TH.hosts && TH.hosts.default) || (hosts[0] || {}).id || "";
    const repos = (TH.health && TH.health.repos) || ["iamcheyan/svc-dashboard", "iamcheyan/chezmoi", "iamcheyan/taskhub"];
    quickDispatchHtml = `
      <div class="th-quick-dispatch">
        <div class="th-qd-head">
          <span class="th-qd-title">🚀 准备派发该任务</span>
          <span class="th-qd-hint">默认分派给 Hermes 并创建专属 Telegram 话题实时汇报</span>
        </div>
        <div class="th-qd-row">
          <span class="th-qd-label">智能体</span>
          <div class="th-qd-opts" id="th-qd-agents">
            <button class="th-qd-opt is-on" type="button" data-qd-agent="hermes">⚡ hermes (推荐·全流程 & TG话题)</button>
            <button class="th-qd-opt" type="button" data-qd-agent="pi">pi (敏捷修改)</button>
            <button class="th-qd-opt" type="button" data-qd-agent="omp">omp (通用开发)</button>
          </div>
        </div>
        <div class="th-qd-row">
          <span class="th-qd-label">代码仓库</span>
          <div class="th-qd-opts" id="th-qd-repos">
            <button class="th-qd-opt is-on" type="button" data-qd-repo="">自动推断</button>
            ${repos.map(r => `
              <button class="th-qd-opt" type="button" data-qd-repo="${escAttr(r)}">
                <span>${escHtml(r.split("/").pop())}</span>
              </button>`).join("")}
          </div>
        </div>
        <div class="th-qd-row">
          <span class="th-qd-label">机器</span>
          <div class="th-qd-opts" id="th-qd-hosts">
            ${hosts.map((h, i) => `
              <button class="th-qd-opt${h.id === defHost || (!defHost && i === 0) ? ' is-on' : ''}" type="button" data-qd-host="${escAttr(h.id)}">
                <i class="th-opt-dot"></i> <span>${escHtml(h.label || h.id)}</span>
              </button>`).join("") || `<span class="th-field-none">本地</span>`}
          </div>
        </div>
        <div class="th-qd-foot">
          <button class="th-btn th-btn-primary th-qd-launch" type="button" id="btn-qd-launch">⚡ 开始执行任务</button>
        </div>
      </div>`;
  }

  // 顶部操作动作组
  const actions = [
    activeRun
      ? `<button class="th-btn th-btn-accent" type="button" data-th-act="wake" data-sess="${escAttr(latest ? latest.tmux_session : "")}">⚡ 唤醒推进</button>` : "",
    activeRun
      ? `<button class="th-btn th-btn-danger" type="button" data-th-act="cancel" data-run="${escAttr(latest ? latest.id : "")}" data-num="${issue.number}">停止</button>` : "",
    isClosed
      ? `<button class="th-btn th-btn-primary" type="button" data-th-act="dispatch" data-num="${issue.number}" data-title="${escAttr(issue.title || "")}">重新派发</button>` : "",
    issue.state === "closed"
      ? `<button class="th-btn" type="button" data-th-act="restore" data-num="${issue.number}">恢复打开</button>`
      : `<button class="th-btn" type="button" data-th-act="close" data-num="${issue.number}">关闭任务</button>`,
  ].filter(Boolean).join("");

  const metaBits = [
    (latest && latest.target_repo) || d.repo || "",
    latest ? thHostName(latest) : "",
    latest && latest.branch ? latest.branch : "",
    latest && latest.notify_thread ? `TG话题 #${latest.notify_thread}` : ""
  ].filter(Boolean).map(x => `<span>${escHtml(x)}</span>`).join('<i class="th-head-sep"></i>');

  // 多 Tab 控制区（自适应默认值）
  if (!TH.detailTab || isPending) {
    TH.detailTab = isPending ? "issue" : "console";
  }
  const curDTab = TH.detailTab;

  det.innerHTML = `
    <div class="th-head">
      <div class="th-head-line">
        <button class="th-icon-btn th-back" type="button" data-th-back="1" aria-label="Back">←</button>
        <span class="th-badge is-${escAttr(stateKey)}">${escHtml(stateText)}</span>
        <span class="th-head-num">#${escHtml(String(issue.number || ""))}</span>
        ${metaBits ? `<span class="th-head-meta"><i class="th-head-sep"></i>${metaBits}</span>` : ""}
        <a class="th-icon-btn th-head-link" href="${escAttr(issue.url || "#")}" target="_blank" rel="noopener" title="GitHub" aria-label="GitHub">↗</a>
      </div>
      <h3 class="th-head-title">${escHtml(issue.title || "")}</h3>
      <div class="th-head-actions">${actions}</div>
    </div>
    <div class="th-detail-body">
      ${stepperHtml}
      ${statusBannerHtml}
      ${inlineReplyHtml}
      ${quickDispatchHtml}

      <div class="th-detail-tabs">
        ${activeRun || (latest && latest.tmux_session) ? `
          <button class="th-dtab-btn${curDTab === 'console' ? ' active' : ''}" type="button" data-dtab="console">💻 实时终端控制台</button>` : ''}
        <button class="th-dtab-btn${curDTab === 'issue' ? ' active' : ''}" type="button" data-dtab="issue">📝 任务内容说明</button>
        <button class="th-dtab-btn${curDTab === 'timeline' ? ' active' : ''}" type="button" data-dtab="timeline">📋 执行时间线 (${events.length})</button>
        ${runs.length > 1 ? `<button class="th-dtab-btn${curDTab === 'runs' ? ' active' : ''}" type="button" data-dtab="runs">📜 历史执行 (${runs.length})</button>` : ''}
      </div>

      ${activeRun || (latest && latest.tmux_session) ? `
      <div id="th-tab-console-pane" ${curDTab === 'console' ? '' : 'hidden'}>
        <div class="th-term-window">
          <div class="th-term-header">
            <span id="th-term-title">会话：${escHtml(latest && latest.tmux_session ? latest.tmux_session : "none")}</span>
            <div class="th-term-actions">
              <button class="th-term-btn" type="button" id="btn-term-autoscroll" title="Auto Scroll">滚屏: 开</button>
              <button class="th-term-btn" type="button" id="btn-term-ctrl-c" title="Ctrl+C">Ctrl+C</button>
              <button class="th-term-btn" type="button" id="btn-term-enter" title="Enter">Enter ↵</button>
              <button class="th-term-btn" type="button" id="btn-term-wake" title="Wake">⚡ 唤醒</button>
              <button class="th-term-btn" type="button" id="btn-term-copy" title="Copy">复制</button>
            </div>
          </div>
          <pre class="th-term-content" id="th-term-output">${escHtml(t("th_loading"))}</pre>
        </div>
      </div>` : ''}

      <div id="th-tab-issue-pane" ${curDTab === 'issue' ? '' : 'hidden'}>
        <div class="th-prose">${escHtml(issue.body || `（无正文）`)}</div>
      </div>

      <div id="th-tab-timeline-pane" ${curDTab === 'timeline' ? '' : 'hidden'}>
        <ol class="th-timeline">
          ${events.length ? events.map(e => `
            <li class="th-ev th-ev-${escHtml(e.kind || "")}">
              <span class="th-ev-time">${new Date((e.at || 0) * 1000).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
              <span class="th-ev-kind">${escHtml(e.kind || "")}</span>
              <span class="th-ev-msg">${escHtml((e.message || "").slice(0, 300))}</span>
            </li>`).join("") : `<li class="th-ev th-ev-empty">暂无事件记录</li>`}
        </ol>
      </div>

      ${runs.length > 1 ? `
      <div id="th-tab-runs-pane" ${curDTab === 'runs' ? '' : 'hidden'}>
        <div class="th-runs">${runs.map(r => `
          <div class="th-run-row" data-th-runlog="${escAttr(r.id)}" role="button" tabindex="0">
            <span class="th-run-agent">${escHtml(r.agent)}</span>
            <span class="th-run-state">${escHtml(thStateLabel(r.state))}</span>
            <span class="th-run-stage">${escHtml(r.stage || "—")}</span>
            <span class="th-run-time">${escHtml(thAgo(new Date((r.started_at || r.created_at) * 1000).toISOString()))}</span>
            <span class="th-run-log-link">查看日志</span>
          </div>`).join("")}</div>
      </div>` : ''}

      <div id="th-runlog" class="th-runlog" hidden></div>
    </div>`;

  // 待派发场景下，绑定内置快捷派发面板交互
  if (isPending) {
    let selAgent = "hermes";
    let selRepo = "";
    const hosts = ((TH.hosts && TH.hosts.hosts) || []).filter(h => h.online !== false);
    let selHost = (TH.hosts && TH.hosts.default) || (hosts[0] || {}).id || "";

    det.querySelectorAll("[data-qd-agent]").forEach(btn => {
      btn.addEventListener("click", () => {
        selAgent = btn.dataset.qdAgent;
        det.querySelectorAll("[data-qd-agent]").forEach(b => b.classList.toggle("is-on", b === btn));
      });
    });

    det.querySelectorAll("[data-qd-repo]").forEach(btn => {
      btn.addEventListener("click", () => {
        selRepo = btn.dataset.qdRepo || "";
        det.querySelectorAll("[data-qd-repo]").forEach(b => b.classList.toggle("is-on", b === btn));
      });
    });

    det.querySelectorAll("[data-qd-host]").forEach(btn => {
      btn.addEventListener("click", () => {
        selHost = btn.dataset.qdHost;
        det.querySelectorAll("[data-qd-host]").forEach(b => b.classList.toggle("is-on", b === btn));
      });
    });

    const launchBtn = det.querySelector("#btn-qd-launch");
    if (launchBtn) {
      launchBtn.addEventListener("click", async () => {
        launchBtn.disabled = true;
        launchBtn.textContent = `正在调度…`;
        try {
          const r = await apiPost("/api/th/dispatch", { number: Number(issue.number), agent: selAgent, host: selHost, target_repo: selRepo });
          const d = await r.json().catch(() => ({ ok: false, msg: "bad json" }));
          TH.health = null;
          if (!d.ok) {
            uiNotice(d.msg || `派发失败`);
            launchBtn.disabled = false;
            launchBtn.textContent = `⚡ 开始执行任务`;
            return;
          }
          uiNotice(`任务 #${issue.number} 已分派给 ${selAgent}`);
          thOpenTask(issue.number);
        } catch (e) {
          uiNotice("Error: " + e.message);
          launchBtn.disabled = false;
          launchBtn.textContent = `⚡ 开始执行任务`;
        }
      });
    }
  }

  // Tab 切换逻辑
  det.querySelectorAll("[data-dtab]").forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.dtab;
      TH.detailTab = tab;
      det.querySelectorAll("[data-dtab]").forEach(b => b.classList.toggle("active", b === btn));
      const pConsole = $("th-tab-console-pane");
      const pTimeline = $("th-tab-timeline-pane");
      const pIssue = $("th-tab-issue-pane");
      const pRuns = $("th-tab-runs-pane");
      if (pConsole) pConsole.hidden = (tab !== "console");
      if (pTimeline) pTimeline.hidden = (tab !== "timeline");
      if (pIssue) pIssue.hidden = (tab !== "issue");
      if (pRuns) pRuns.hidden = (tab !== "runs");
    });
  });

  // 返回按钮
  det.querySelector("[data-th-back]")?.addEventListener("click", () => {
    TH.taskView = null; det.hidden = true; thRenderTasks();
  });

  // 操作按钮
  det.querySelectorAll("[data-th-act]").forEach(el => {
    if (el.tagName === "A") return;
    el.addEventListener("click", ev => {
      ev.stopPropagation();
      const n = Number(el.dataset.num || issue.number), kind = el.dataset.thAct;
      if (kind === "dispatch") thDispatchModal(n, { title: el.dataset.title || "", after: () => thOpenTask(n) });
      if (kind === "restore") thSetState(n, "open");
      if (kind === "close") thSetState(n, "closed");
      if (kind === "cancel" && el.dataset.run) thCancel(el.dataset.run, () => thOpenTask(n));
      if (kind === "wake" && latest && latest.tmux_session) {
        apiPost("/api/tmux/wake", { session: latest.tmux_session, pane: "" }).then(r => r.json()).then(res => {
          uiNotice(res.ok ? `已触发唤醒推进` : (res.msg || `唤醒失败`));
        });
      }
    });
  });

  // 内嵌回复回车与发送
  const replyInput = $("th-inline-input");
  const replySendBtn = $("th-inline-send");
  if (replyInput && replySendBtn && latest) {
    const doSend = async () => {
      const val = replyInput.value.trim();
      if (!val) return;
      replySendBtn.disabled = true;
      replySendBtn.textContent = "…";
      const r = await apiPost("/api/th/resume", { id: latest.id, text: val });
      const res = await r.json().catch(() => ({ ok: false }));
      replySendBtn.disabled = false;
      replySendBtn.textContent = `发送`;
      if (!res.ok) {
        uiNotice(res.msg || `发送失败`);
      } else {
        replyInput.value = "";
        uiNotice(`指令已送达智能体`);
        thOpenTask(number, true);
      }
    };
    replySendBtn.addEventListener("click", doSend);
    replyInput.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); doSend(); } });
  }

  // 历史运行点击
  det.querySelectorAll("[data-th-runlog]").forEach(el => el.addEventListener("click", () => thShowLog(el.dataset.thRunlog)));

  // 实时终端捕获与控制
  let autoScroll = true;
  const btnScroll = $("btn-term-autoscroll");
  if (btnScroll) {
    btnScroll.addEventListener("click", () => {
      autoScroll = !autoScroll;
      btnScroll.textContent = autoScroll ? `滚屏: 开` : `滚屏: 关`;
      btnScroll.classList.toggle("is-active", autoScroll);
    });
  }

  const btnCtrlC = $("btn-term-ctrl-c");
  if (btnCtrlC && latest && latest.tmux_session) {
    btnCtrlC.addEventListener("click", async () => {
      const r = await apiPost("/api/tmux/send", { session: latest.tmux_session, key: "C-c" });
      const res = await r.json().catch(() => ({ ok: false }));
      uiNotice(res.ok ? `已发送 Ctrl+C` : `发送失败`);
    });
  }

  const btnEnter = $("btn-term-enter");
  if (btnEnter && latest && latest.tmux_session) {
    btnEnter.addEventListener("click", async () => {
      const r = await apiPost("/api/tmux/send", { session: latest.tmux_session, text: "", enter: true });
      const res = await r.json().catch(() => ({ ok: false }));
      uiNotice(res.ok ? `已发送 Enter` : `发送失败`);
    });
  }

  const btnWake = $("btn-term-wake");
  if (btnWake && latest && latest.tmux_session) {
    btnWake.addEventListener("click", async () => {
      const r = await apiPost("/api/tmux/wake", { session: latest.tmux_session, pane: "" });
      const res = await r.json().catch(() => ({ ok: false }));
      uiNotice(res.ok ? `已发送唤醒` : `唤醒失败`);
    });
  }

  const btnCopy = $("btn-term-copy");
  if (btnCopy) {
    btnCopy.addEventListener("click", () => {
      const pre = $("th-term-output");
      if (pre && navigator.clipboard) {
        navigator.clipboard.writeText(pre.textContent || "");
        uiNotice(`已复制终端文本`);
      }
    });
  }

  const pullTerminal = async () => {
    const pre = $("th-term-output");
    if (!pre) { if (TH.timer) clearInterval(TH.timer); return; }

    if (latest && latest.tmux_session) {
      // 优先从 Tmux 窗格实时捕获
      const cap = await thGet(`/api/tmux/capture?target=${encodeURIComponent(latest.tmux_session)}&ansi=1&lines=180`);
      if (cap && cap.ok && cap.capture) {
        pre.innerHTML = ansiToHtml(Array.isArray(cap.capture) ? cap.capture.join("\n") : String(cap.capture));
        if (autoScroll) pre.scrollTop = pre.scrollHeight;
        return;
      }
    }

    // 备用：从 TaskHub Run 日志拉取
    if (latest && latest.id) {
      const r = await thGet(`/api/th/log?id=${encodeURIComponent(latest.id)}&lines=150`);
      if (r && r.ok && r.log) {
        pre.textContent = r.log;
        if (autoScroll) pre.scrollTop = pre.scrollHeight;
        return;
      }
    }

    if (!latest) {
      pre.textContent = `尚未派发智能体会话。`;
    } else {
      pre.textContent = `会话正在准备启动或等待捕获…`;
    }
  };

  pullTerminal();
  if (TH.timer) { clearInterval(TH.timer); TH.timer = null; }
  if (activeRun) {
    TH.timer = setInterval(() => {
      const pre = $("th-term-output");
      if (!pre || TH.busy) { if (!pre) { clearInterval(TH.timer); TH.timer = null; } return; }
      TH.busy = true; pullTerminal().finally(() => { TH.busy = false; });
    }, 3500);
  }
}

function thShowLog(runId) {
  const box = $("th-runlog"); if (!box) return;
  if (!box.hidden && TH.logId === runId) { box.hidden = true; TH.logId = null; return; }
  TH.logId = runId;
  box.hidden = false;
  box.innerHTML = `<div class="th-runlog-head"><span>原始输出 · ${escHtml(runId)}</span>
    <span class="chip" data-th-logclose="1" role="button" tabindex="0">收起</span></div>
    <pre class="th-log" id="th-log-pre">${escHtml(t("th_loading"))}</pre>`;
  box.querySelector("[data-th-logclose]")?.addEventListener("click", () => { box.hidden = true; TH.logId = null; });
  const pull = async () => {
    if (TH.logId !== runId) return;
    const d = await thGet(`/api/th/log?id=${encodeURIComponent(runId)}&lines=400`);
    const pre = $("th-log-pre"); if (!pre) return;
    pre.textContent = d.ok === false ? (d.msg || t("th_no_log")) : (d.log || t("th_no_log"));
    pre.scrollTop = pre.scrollHeight;
  };
  pull();
  if (TH.timer) clearInterval(TH.timer);
  TH.timer = setInterval(() => {
    if (TH.logId !== runId || !box || box.hidden) { clearInterval(TH.timer); TH.timer = null; return; }
    if (TH.busy) return;
    TH.busy = true; pull().finally(() => { TH.busy = false; });
  }, 3000);
}

/* ---------------- 全新「下发新任务」控制台模态框 ---------------- */
async function thNewTaskModal() {
  if (!TH.health || !TH.hosts) await thEnsureBase().catch(() => {});
  document.querySelectorAll(".th-new-modal").forEach(el => el.remove());

  const rawAgents = (TH.health && TH.health.agents) || ["hermes", "pi", "omp"];
  const agents = ["hermes", ...rawAgents.filter(a => a !== "hermes")];
  const agentMeta = {
    hermes: { name: "hermes", desc: `主力执行 & 创建专属 Telegram 话题汇报` },
    pi: { name: "pi", desc: `敏捷代码修改 · 直接交付` },
    omp: { name: "omp", desc: `通用研发智能体 · 会话交互` }
  };
  const repos = (TH.health && TH.health.repos) || ["iamcheyan/svc-dashboard", "iamcheyan/chezmoi", "iamcheyan/taskhub"];
  const hosts = ((TH.hosts && TH.hosts.hosts) || []).filter(h => h.online !== false);

  let curAgent = "hermes";
  let curRepo = "";
  let curHost = (TH.hosts && TH.hosts.default) || (hosts[0] || {}).id || "";

  const modal = document.createElement("div");
  modal.className = "ui-modal th-new-modal";
  modal.innerHTML = `
    <div class="th-dlg" role="dialog" aria-modal="true" aria-labelledby="th-new-title" tabindex="-1">
      <div class="th-dlg-head">
        <div class="th-dlg-head-main">
          <span class="th-dlg-kicker">智能体任务调度</span>
          <h3 class="th-dlg-title" id="th-new-title">下发新任务</h3>
        </div>
        <button class="th-dlg-x" type="button" data-close="1" aria-label="Close">✕</button>
      </div>
      <div class="th-dlg-body">
        <div class="th-field">
          <span class="th-field-label">任务标题</span>
          <div class="th-tags-row">
            <button class="th-tag-btn" type="button" data-tag="[Bug]">修复 Bug</button>
            <button class="th-tag-btn" type="button" data-tag="[Feature]">新功能</button>
            <button class="th-tag-btn" type="button" data-tag="[Refactor]">代码重构</button>
            <button class="th-tag-btn" type="button" data-tag="[Test]">测试验证</button>
          </div>
          <input type="text" class="th-input-text" id="th-new-input-title" placeholder="${escAttr(t("nt_ph_title"))}" maxlength="160" autocomplete="off" />
        </div>

        <div class="th-field">
          <span class="th-field-label">任务需求 / Prompt 描述</span>
          <textarea class="th-textarea" id="th-new-input-body" placeholder="${escAttr(t("nt_ph_body"))}"></textarea>
        </div>

        <div class="th-field">
          <span class="th-field-label">目标代码仓库</span>
          <div class="th-opts">
            <button class="th-opt is-on" type="button" data-sel-repo="">
              <i class="th-opt-dot"></i><span>自动判断</span>
            </button>
            ${repos.map(r => `
              <button class="th-opt" type="button" data-sel-repo="${escAttr(r)}">
                <i class="th-opt-dot"></i><span>${escHtml(r.split("/").pop())}</span>
              </button>`).join("")}
          </div>
        </div>

        <div class="th-field">
          <span class="th-field-label">执行智能体</span>
          <div class="th-opts" style="display:flex;gap:8px;">
            ${agents.map(a => {
              const meta = agentMeta[a] || { name: a, desc: a };
              return `
                <div class="th-agent-card${a === curAgent ? ' is-on' : ''}" data-sel-agent="${escAttr(a)}">
                  <div class="th-agent-card-title">
                    <span>${escHtml(meta.name)}</span>
                    <i class="th-opt-dot"></i>
                  </div>
                  <div class="th-agent-card-desc">${escHtml(meta.desc)}</div>
                </div>`;
            }).join("")}
          </div>
        </div>

        <div class="th-field">
          <span class="th-field-label">执行主机</span>
          <div class="th-opts">
            ${hosts.map(h => `
              <button class="th-opt${h.id === curHost ? ' is-on' : ''}" type="button" data-sel-host="${escAttr(h.id)}">
                <i class="th-opt-dot"></i><span>${escHtml(h.label || h.id)}</span>
              </button>`).join("") || `<span class="th-field-none">本地</span>`}
          </div>
        </div>
      </div>
      <div class="th-dlg-foot">
        <button class="th-btn" type="button" data-close="1">取消</button>
        <button class="th-btn th-btn-primary" type="button" id="btn-th-new-submit">立即下发任务 ⚡</button>
      </div>
    </div>`;

  document.body.appendChild(modal);
  const dlg = modal.querySelector(".th-dlg");

  const close = () => {
    document.removeEventListener("keydown", onKey);
    modal.remove();
  };
  const onKey = ev => { if (ev.key === "Escape") { ev.stopPropagation(); close(); } };
  document.addEventListener("keydown", onKey);
  modal.addEventListener("click", ev => { if (ev.target === modal) close(); });
  modal.querySelectorAll("[data-close]").forEach(el => el.addEventListener("click", close));

  // 快捷标签添加前缀
  const titleInput = modal.querySelector("#th-new-input-title");
  modal.querySelectorAll("[data-tag]").forEach(btn => {
    btn.addEventListener("click", () => {
      const tag = btn.dataset.tag;
      if (!titleInput.value.startsWith(tag)) {
        titleInput.value = `${tag} ${titleInput.value.replace(/^\[[^\]]+\]\s*/, "")}`;
      }
      titleInput.focus();
    });
  });

  // 仓库选择
  modal.querySelectorAll("[data-sel-repo]").forEach(opt => {
    opt.addEventListener("click", () => {
      curRepo = opt.dataset.selRepo || "";
      modal.querySelectorAll("[data-sel-repo]").forEach(o => o.classList.toggle("is-on", o === opt));
    });
  });

  // 智能体选择
  modal.querySelectorAll("[data-sel-agent]").forEach(card => {
    card.addEventListener("click", () => {
      curAgent = card.dataset.selAgent;
      modal.querySelectorAll("[data-sel-agent]").forEach(c => c.classList.toggle("is-on", c === card));
    });
  });

  // 主机选择
  modal.querySelectorAll("[data-sel-host]").forEach(opt => {
    opt.addEventListener("click", () => {
      curHost = opt.dataset.selHost;
      modal.querySelectorAll("[data-sel-host]").forEach(o => o.classList.toggle("is-on", o === opt));
    });
  });

  // 提交
  const submitBtn = modal.querySelector("#btn-th-new-submit");
  submitBtn.addEventListener("click", async () => {
    const title = titleInput.value.trim();
    const body = modal.querySelector("#th-new-input-body").value.trim();
    if (!title) {
      uiNotice(`请输入任务标题`);
      titleInput.focus();
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = `正在调度下发…`;

    try {
      const r = await apiPost("/api/th/new", { title, body, agent: curAgent, host: curHost, target_repo: curRepo });
      const res = await r.json().catch(() => ({ ok: false, msg: `网络错误` }));
      if (!res.ok) {
        uiNotice(res.msg || `下发任务失败`);
        submitBtn.disabled = false;
        submitBtn.textContent = `立即下发任务 ⚡`;
        return;
      }

      close();
      uiNotice(`任务 #${res.number || ""} 已分派给 ${curAgent}`);

      // 切到任务 Tab 并刷新打开该任务
      const vTasks = $("tmux-view-tasks");
      const vSessions = $("tmux-view-sessions");
      if (vTasks) { vTasks.hidden = false; vTasks.style.display = ""; }
      if (vSessions) { vSessions.hidden = true; vSessions.style.display = "none"; }
      $("tmux-subnav")?.querySelectorAll(".page-subnav-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.ttab === "tasks");
      });

      await thRenderTasks();
      if (res.number) thOpenTask(Number(res.number));
    } catch (e) {
      uiNotice(`创建失败: ` + e.message);
      submitBtn.disabled = false;
      submitBtn.textContent = `立即下发任务 ⚡`;
    }
  });

  setTimeout(() => titleInput.focus(), 50);
}

/* 派遣弹窗：执行者 / 机器 → 确认。挂在 body 上，手机为底部滑层。 */
async function thDispatchModal(number, opts = {}) {
  const after = typeof opts === "function" ? opts : (opts.after || null);
  const title = (opts && opts.title) || "";
  if (!TH.health || !TH.hosts) await thEnsureBase().catch(() => {});
  document.querySelectorAll(".th-dispatch-modal").forEach(el => el.remove());
  const rawAgents = (TH.health && TH.health.agents) || ["hermes", "pi", "omp"];
  const agents = ["hermes", ...rawAgents.filter(a => a !== "hermes")];
  const labels = (TH.health && TH.health.agent_labels) || {};
  const repos = (TH.health && TH.health.repos) || ["iamcheyan/svc-dashboard", "iamcheyan/chezmoi", "iamcheyan/taskhub"];
  const hosts = ((TH.hosts && TH.hosts.hosts) || []).filter(h => h.online !== false);
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(TH_DISPATCH_KEY) || "{}") || {}; } catch (e) { saved = {}; }
  const defAgent = "hermes";
  const defHost = hosts.some(h => h.id === saved.host) ? saved.host
    : ((TH.hosts && TH.hosts.default) || (hosts[0] || {}).id || "");
  let agent = defAgent, hostId = defHost, targetRepo = "";
  const optBtn = (field, val, text, on) => `
    <button class="th-opt${on ? " is-on" : ""}" type="button" data-th-field="${field}"
      data-val="${escAttr(val)}" aria-pressed="${on ? "true" : "false"}">
      <i class="th-opt-dot"></i><span>${escHtml(text)}</span></button>`;
  const modal = document.createElement("div");
  modal.className = "ui-modal th-dispatch-modal";
  modal.innerHTML = `
    <div class="th-dlg" role="dialog" aria-modal="true" aria-labelledby="th-dlg-title" tabindex="-1">
      <div class="th-dlg-head">
        <div class="th-dlg-head-main">
          <span class="th-dlg-kicker">${escHtml(t("th_dispatch"))}</span>
          <h3 class="th-dlg-title" id="th-dlg-title"><span class="th-dlg-num">#${escHtml(String(number))}</span><span>${escHtml(title)}</span></h3>
        </div>
        <button class="th-dlg-x" type="button" data-th-dlg-close="1" aria-label="${escAttr(t("m_close"))}">✕</button>
      </div>
      <div class="th-dlg-body">
        <div class="th-field">
          <span class="th-field-label">${escHtml(t("th_agent"))}</span>
          <div class="th-opts">${agents.map(a => optBtn("agent", a, labels[a] || a, a === defAgent)).join("") || `<span class="th-field-none">—</span>`}</div>
        </div>
        <div class="th-field">
          <span class="th-field-label">代码仓库</span>
          <div class="th-opts">
            ${optBtn("repo", "", `自动推断`, true)}
            ${repos.map(r => optBtn("repo", r, r.split("/").pop(), false)).join("")}
          </div>
        </div>
        <div class="th-field">
          <span class="th-field-label">${escHtml(t("th_host"))}</span>
          <div class="th-opts">${hosts.map(h => optBtn("host", h.id, h.label || h.id, h.id === defHost)).join("") || `<span class="th-field-none">—</span>`}</div>
        </div>
      </div>
      <div class="th-dlg-foot">
        <button class="th-btn" type="button" data-th-dlg-close="1">${escHtml(t("m_cancel"))}</button>
        <button class="th-btn th-btn-primary" type="button" data-th-dlg-go="1">${escHtml(t("th_dispatch"))}</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  const dlg = modal.querySelector(".th-dlg");
  const onKey = ev => { if (ev.key === "Escape") { ev.stopPropagation(); close(); } };
  const close = () => { document.removeEventListener("keydown", onKey); modal.remove(); };
  document.addEventListener("keydown", onKey);
  modal.addEventListener("click", ev => { if (ev.target === modal) close(); });
  modal.querySelectorAll("[data-th-dlg-close]").forEach(el => el.addEventListener("click", close));
  modal.querySelectorAll(".th-opt").forEach(el => el.addEventListener("click", () => {
    const field = el.dataset.thField;
    if (field === "agent") agent = el.dataset.val;
    else if (field === "repo") targetRepo = el.dataset.val;
    else hostId = el.dataset.val;
    modal.querySelectorAll(`.th-opt[data-th-field="${field}"]`).forEach(x => {
      const on = x === el;
      x.classList.toggle("is-on", on);
      x.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }));
  const go = modal.querySelector("[data-th-dlg-go]");
  go.addEventListener("click", async () => {
    if (go.disabled) return;
    const label = go.textContent;
    go.disabled = true;
    go.textContent = "…";
    try {
      const r = await apiPost("/api/th/dispatch", { number: Number(number), agent, host: hostId, target_repo: targetRepo });
      const d = await r.json().catch(() => ({ ok: false, msg: "bad json" }));
      TH.health = null;
      if (!d.ok) { uiNotice(d.msg || `派发失败`); go.disabled = false; go.textContent = label; return; }
      try { localStorage.setItem(TH_DISPATCH_KEY, JSON.stringify({ agent, host: hostId })); } catch (e) {}
      close();
      if (d.needs_repo) uiNotice(`已发到 Telegram，等你确认代码仓库`);
      if (after) after(); else thRenderTasks();
    } catch (err) {
      uiNotice("Error: " + err.message);
      go.disabled = false;
      go.textContent = label;
    }
  });
  setTimeout(() => dlg.focus({ preventScroll: true }), 30);
  return modal;
}

async function thSetState(number, state) {
  const r = await apiPost("/api/th/state", { number: Number(number), state });
  const d = await r.json().catch(() => ({ ok: false, msg: "bad json" }));
  if (!d.ok) { uiNotice(d.msg || `操作失败`); return; }
  TH.taskView ? thOpenTask(TH.taskView) : thRenderTasks();
}

async function thCancel(runId, after) {
  const r = await apiPost("/api/th/cancel", { id: runId });
  const d = await r.json().catch(() => ({ ok: false }));
  if (!d.ok) { uiNotice(d.msg || `取消失败`); return; }
  after ? after() : (TH.taskView ? thOpenTask(TH.taskView) : thRenderTasks());
}

async function thReply(runId, number) {
  const text = window.prompt(`给 agent 的指令`);
  if (!text) return;
  const r = await apiPost("/api/th/resume", { id: runId, text });
  const d = await r.json().catch(() => ({ ok: false }));
  if (!d.ok) { alert(d.msg || `发送失败`); return; }
  TH.taskView ? thOpenTask(number) : thRenderTasks();
}

// 服务页：服务 / 定时 / 日志 三个小 tab（与活动页同一套 subnav）
function initSvcSubnav() {
  const bar = $("svc-subnav");
  if (!bar || bar.dataset.wired) return;
  bar.dataset.wired = "1";
  const panes = { svc: ["svc-panel", "filters"], cron: ["cron-panel"] };
  const all = new Set(Object.values(panes).flat());
  bar.addEventListener("click", e => {
    const btn = e.target.closest(".page-subnav-btn");
    if (!btn || !btn.dataset.sv) return;
    const want = btn.dataset.sv;
    bar.querySelectorAll(".page-subnav-btn").forEach(b => b.classList.toggle("active", b === btn));
    all.forEach(id => {
      const el = $(id);
      if (!el) return;
      const show = (panes[want] || []).includes(id);
      el.hidden = !show;
      el.style.display = show ? "" : "none";
    });
    if (want === "cron" && typeof cronLoad === "function") cronLoad();
  });
}
document.addEventListener("DOMContentLoaded", initSvcSubnav);
setTimeout(initSvcSubnav, 800);
