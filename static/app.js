const BOOT = window.__BOOT__ || {};
if (BOOT.readonly) {
  document.documentElement.classList.add("is-readonly");
  if (document.body) document.body.classList.add("is-readonly");
  else document.addEventListener("DOMContentLoaded", () => document.body.classList.add("is-readonly"));
}
const AUTO = BOOT.auto;
const LANG = BOOT.lang;
const TS_MODE = BOOT.tsMode;
const TS_HOST = "100.76.219.104";
const LAN_HOST = "192.168.3.82";
const linkHost = (h) => (TS_MODE && (h === "192.168.3.82")) ? TS_HOST : h;  // 来源为 tailscale(100.64.0.0/10) 时链接主机改用 tailscale IP
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
let svcTok = sessionStorage.getItem("svcTok") || "";
async function apiPost(url, body) {
  const send = () => fetch(url, { method: "POST",
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
  const link = loopback ? `http://127.0.0.1:${e.port}/` : `http://${linkHost(location.hostname)}:${e.port}/`;
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
function applyFilter() {
  const shown = FILTERS[filter] ? services.filter(FILTERS[filter]) : [];
  ["user", "web", "docker", "system", "all"].forEach(f =>
    $("n-" + f).textContent = services.filter(FILTERS[f]).length);
  document.querySelectorAll("#filters .chip").forEach(c =>
    c.classList.toggle("active", c.dataset.f === filter));
  if (filter === "omp") {
    $("svc").style.display = "none";
    // 先亮面板显示「加载中」,再等数据 —— 冷扫描需数秒,
    // 之前面板一直 hidden,数据回来前用户看到的是一片空白。
    const tasksEl = $("tasks");
    tasksEl.hidden = false; tasksEl.className = "watchdog-panel";
    tasksEl.innerHTML = "<h2>" + t("a_title") + " <span style='color:var(--text-dead);font-weight:400'>" + t("a_loading") + "</span></h2>";
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
  renderSvcRows(tbody, shown, isMobile());
  $("count").textContent = shown.length;
  fillCtl(); // 服务表行尾 暂停/继续 按钮状态
  fillSvcDots(); // P0-6: 行首状态点按受管单元状态上色
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
      if (r.dirty) meta.push(`<span class="rp-dirty">${t("rp_dirty", { n: r.dirty })}</span>`);
      return `<div class="rp-row" role="button" tabindex="0" data-traj="${escAttr(r.name)}">
        <div class="rp-l1"><span class="rp-name">${escHtml(r.name)}</span><span class="rp-branch">${escHtml(r.branch)}</span>
          <span class="rp-meta">${meta.join(" · ")}</span></div>
        ${r.last ? `<div class="rp-last"><span class="rp-hash">${escHtml(r.last.hash)}</span> ${escHtml(r.last.subject)} <span class="rp-ago">· ${escHtml(agoFromTs(r.last.ts))}</span></div>` : ""}
        ${(r.traj || []).length ? `<div class="rp-traj" title="${escAttr(t("tr_days"))}">${stripOf(r.traj)}</div>` : ""}
      </div>`;
    }).join("");
  }
  if ($("act-repos-bar")) {
    renderActivityPage();
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
  const chips = TOOL_LINKS.filter(([n, p]) => ports.has(p)).map(([n, p]) =>
    `<a class='chip tchip' href='http://${linkHost(location.hostname)}:${p}/' target='_blank' rel='noopener'>${n} :${p} ${icon("ext", 11)}</a>`).join("");
  el.innerHTML = chips;
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
  let rows = "";
  // OMP agents
  agents.omp.forEach(x => {
    rows += "<tr><td><span class='tbadge wd'>OMP</span><span class='tname tlink' data-sid='" + esc(x.id) +
      "' data-cwd='" + esc(x.cwd) + "' data-tmux='" + esc(x.tmux) + "' title='" + t("a_openlog", { g: esc(x.goal) }) + "'>" +
      esc(stripMd(x.goal || x.cwd).slice(0, 60)) + "</span></td><td data-label='" + t("a_status") + "'>" + (labels[x.health] || esc(x.status)) +
      "</td><td class='tscope' data-label='" + t("a_loc") + "'>" + esc(x.tmux) + "<br>" + esc(x.cwd) + "</td><td class='tsch' data-label='" + t("a_active") + "'>" +
      esc(x.last_activity) + "<br>" + agoStr(x.idle_seconds) + "</td><td class='tcmd' data-label='" + t("a_tool") + "'>" + esc(x.tool) + "</td></tr>";
  });
  // Codex agents
  agents.codex.forEach(x => {
    rows += "<tr><td><span class='tbadge rd'>Codex</span><span class='tname tlink' data-sid='" + esc(x.session_id) + "' data-cwd='" +
      esc(x.cwd) + "' data-tmux='' title='" + t("a_openlog", { g: esc(x.title) }) + "'>" +
      esc(x.title || x.session_id) + "</span></td><td data-label='" + t("a_status") + "'>" + (labels[x.health] || esc(x.health)) + "</td><td class='tscope' data-label='" + t("a_loc") + "'>session " + esc(x.session_id) + "<br>" + esc(x.cwd) + "</td><td class='tsch' data-label='" + t("a_active") + "'>" +
      esc(x.last_activity) + "<br>" + agoStr(x.idle_seconds) + "</td><td class='tcmd' data-label='" + t("a_tool") + "'>" + esc(x.last_event || (x.pid !== "—" ? "pid " + x.pid : "—")) + "</td></tr>";
  });
  const total = agents.omp.length + agents.codex.length;
  el.innerHTML = "<h2>" + t("a_title") + " <span style='color:var(--text-dead);font-weight:400'>" + t("a_hint", { n: total }) + "</span></h2><table><thead><tr><th>" + t("a_th_agent") + "</th><th>" + t("a_status") + "</th><th>" + t("a_loc") + "</th><th>" + t("a_active") + "</th><th>" + t("a_tool") + "</th></tr></thead><tbody>" +
    (rows || "<tr><td class='empty' colspan='5'>" + t("a_none") + "</td></tr>") + "</tbody></table>";
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
  const rows = panes.map(x => "<tr><td class='tname'>" + esc(x.session) + ":" + esc(x.pane) +
    (x.active ? " <span class='tbadge wd'>" + t("tmux_active") + "</span>" : "") + "</td><td data-label='" + t("t_cmd") + "'>" + esc(x.command) +
    "</td><td class='tscope' data-label='" + t("tmux_th_title") + "'>" + esc(x.title) + "</td><td class='tcmd' data-label='" + t("th_cwd") + "'>" + esc(x.cwd) +
    "</td><td class='tsch' data-label='" + t("tmux_th_size") + "'>" + esc(x.size) + "</td></tr>").join("");
  el.innerHTML = "<h2>" + t("tmux_panel") + " <span style='color:var(--text-dead);font-weight:400'>" + t("tmux_panes", { n: panes.length }) +
    "</span></h2><table><thead><tr><th>" + t("tmux_th_pane") + "</th><th>" + t("t_cmd") + "</th><th>" + t("tmux_th_title") + "</th><th>" + t("th_cwd") + "</th><th>" + t("tmux_th_size") + "</th></tr></thead><tbody>" +
    (rows || "<tr><td class='empty' colspan='5'>" + t("tmux_none") + "</td></tr>") + "</tbody></table>";
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
  const nwd = tasks.filter(t => t.type === "watchdog").length;
  const nrd = tasks.filter(t => t.type === "reminder").length;
  const nsc = tasks.length - nwd - nrd;
  el.innerHTML = `<h2>${t("panel_watchdog")}
    <span style='color:var(--ch-mem)'>${nwd} ${t("tbd_wd")}</span> ·
    <span style='color:var(--ch-cpu)'>${nrd} ${t("tbd_rd")}</span> ·
    <span style='color:var(--text-dim)'>${nsc} ${t("tbd_sc")}</span> ·
    <span style='color:var(--text-dead);font-weight:400'>${t("t_total", { n: tasks.length })}</span></h2>
    <table><thead><tr><th>${t("t_task")}</th><th>${t("t_cycle")}</th><th>${t("t_source")}</th><th>${t("t_cmd")}</th><th>${t("t_lastrun")}</th></tr></thead>
    <tbody>${tasks.length ? tasks.map(taskRow).join("") : "<tr><td class='empty' colspan='5'>" + t("t_none") + "</td></tr>"}</tbody></table>`;
}

// ---------------------------------------------------------------- 服务管理
// 管理本机关键 systemd 单元(zircon-server / zircon-bots / tailscaled)与
// 手动进程服务(wilviewer / mapviewer): 启动 / 停止 / 重启 / 暂停 / 恢复。
// systemd 单元: 暂停=SIGSTOP 挂起;手动进程: 暂停=终止进程,启用=重新拉起。
// 所有操作都需确认。dashboard 自身(80)不在列表,不可操作。
const MANAGE_UNITS = [
  { id: "zircon-server", kind: "systemd", label: t("m_server"), desc: t("m_server_desc") },
  { id: "zircon-bots", kind: "systemd", label: t("m_bots"), desc: t("m_bots_desc") },
  { id: "tailscaled", kind: "systemd", label: t("m_ts"), desc: t("m_ts_desc") },
  { id: "wilviewer", kind: "proc", port: 8765, label: t("m_wilviewer"), desc: t("m_wilviewer_desc") },
  { id: "mapviewer", kind: "proc", port: 8899, label: t("m_mapviewer"), desc: t("m_mapviewer_desc") },
];
const MANAGE_LABELS = { start: t("m_start"), stop: t("m_stop"), restart: t("m_restart"), pause: t("m_pause"), resume: t("m_resume") };

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

function manageCard(u, st, result) {
  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const ok = st && st.ok;
  const active = ok && st.active === "active";
  const stopped = ok && st.stopped;
  const color = !ok ? "var(--c-gray)" : (stopped ? "var(--c-warn)" : (active ? "var(--c-green)" : "var(--c-red)"));
  const stateTxt = !ok ? (st && st.msg ? st.msg : t("m_state_fail"))
    : (stopped ? t("m_paused") : (active ? st.sub : st.active));
  const pid = ok && st.pid && st.pid !== "0" ? " · PID " + esc(st.pid) : "";
  const isProc = u.kind === "proc";
  let btns = "";
  if (active) {
    // 手动进程: 暂停=终止进程;systemd: 停止/暂停(SIGSTOP)分开
    if (isProc) {
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='stop' role='button' tabindex='0' title='${t("m_title_stop")}'>${icon("pause", 13)} ${t("m_pause")}</span>`;
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='restart' role='button' tabindex='0' title='${t("m_title_restart")}'>${icon("refresh", 13)} ${t("m_restart")}</span>`;
    } else {
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='stop' role='button' tabindex='0' title='${t("m_title_stop")}'>${icon("stop", 13)} ${t("m_stop")}</span>`;
      btns += `<span class='mbtn' data-unit='${u.id}' data-action='restart' role='button' tabindex='0' title='${t("m_title_restart")}'>${icon("refresh", 13)} ${t("m_restart")}</span>`;
      btns += stopped
        ? `<span class='mbtn' data-unit='${u.id}' data-action='resume' role='button' tabindex='0' title='${t("m_title_resume")}'>${icon("play", 13)} ${t("m_resume")}</span>`
        : `<span class='mbtn' data-unit='${u.id}' data-action='pause' role='button' tabindex='0' title='${t("m_title_pause")}'>${icon("pause", 13)} ${t("m_pause")}</span>`;
    }
  } else if (ok) {
    btns += `<span class='mbtn' data-unit='${u.id}' data-action='start' role='button' tabindex='0' title='${t("m_title_start")}'>${icon("play", 13)} ${isProc ? t("m_enable") : t("m_start")}</span>`;
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
  el.innerHTML = `<h2>${t("m_panel")} <span style='color:var(--text-dead);font-weight:400'>${t("m_hint")}</span></h2>
    <div class='mgrid'>${cards.join("")}</div>`;
  el.querySelectorAll(".mbtn").forEach(b => b.addEventListener("click", () => doManage(b)));
}

async function doManage(btn) {
  const unit = btn.dataset.unit, action = btn.dataset.action;
  const label = MANAGE_LABELS[action] || action;
  if (!await uiConfirm(t("m_confirm", { label, unit }))) return;
  btn.setAttribute("aria-disabled", "true");
  const res = btn.closest(".mcard").querySelector(".mresult");
  res.textContent = t("m_doing");
  try {
    const r = await apiPost("/api/manage?lang=" + encodeURIComponent(LANG),
      { unit, action });
    const d = await r.json();
    res.innerHTML = icon(d.ok ? "ok" : "err", 13) + " " + escHtml(d.msg || "");
    res.style.color = d.ok ? "var(--c-green)" : "var(--c-red)";
  } catch (e) {
    res.innerHTML = icon("err", 13) + " " + escHtml(e.message);
    res.style.color = "var(--c-red)";
  }
  btn.setAttribute("aria-disabled", "false");
  setTimeout(() => loadManage(), 600); // 等 systemd 状态落地再刷新
}

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
  $("updated").textContent = new Date(data.updated * 1000).toLocaleString();
  lastUpdatedTs = data.updated * 1000;
  services = data.services;
  renderToolchips();
  applyFilter();
  renderOverview(data);          // 概要摘要(状态卡/指标/需要处理/最近活动)
  loadRepos();                    // 仓库面板(客户端 60s 缓存; 面板内按钮强制重算)
}

async function load(alsoSys) {
  const btns = [$("refresh"), $("fab-refresh")].filter(Boolean);
  btns.forEach(b => { b.classList.add("spinning"); b.setAttribute("aria-disabled", "true"); });
  if (BOOT.static) {
    if (BOOT.apiData) applyApiData(BOOT.apiData);
    if (alsoSys && BOOT.sysData) renderSys(BOOT.sysData);
    btns.forEach(b => { b.classList.remove("spinning"); b.setAttribute("aria-disabled", "false"); });
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
    try {
      const r = await fetch("/api/sys", { cache: "no-store" });
      const d = await r.json();
      renderSys(d);
      snapSet("sys", { data: d });
    } catch (err) {
      console.error("sys refresh failed", err);
    }
  }
  btns.forEach(b => { b.classList.remove("spinning"); b.setAttribute("aria-disabled", "false"); });
}

/* ================================================================
   概要摘要 + 告警中心(轻量) + 日志时间线 —— 移动端概要/日志页的数据层。
   桌面端 renderOverview 直接返回,布局零变化。
   /api/goals 15s 缓存,概要与日志页共用。 */
let lastUpdatedTs = Date.now();
let goalsCache = { t: 0, data: null };
const LOG_LIMIT = 120;

async function fetchGoalsData(force) {
  if (BOOT.static && BOOT.goalsData) return BOOT.goalsData;
  const now = Date.now();
  if (!force && goalsCache.data && now - goalsCache.t < 15000) return goalsCache.data;
  try {
    const r = await fetch("/api/goals?limit=" + LOG_LIMIT + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
    const d = await r.json();
    if (d && d.updated) lastUpdatedTs = Math.max(lastUpdatedTs, d.updated * 1000);
    goalsCache = { t: now, data: d };
  } catch (err) { console.error("goals refresh failed", err); }
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

async function renderPortalAgent() {
  const body = $("hp-body-agent"), badge = $("hp-badge-agent");
  if (!body) return;
  try {
    const d = await loadRuntimes();
    const agents = (d && d.agents) || [];
    const low = [];
    agents.forEach(a => ((a.quota && a.quota.buckets) || []).forEach(b => {
      if (b.remaining_pct != null && b.remaining_pct < 15) {
        low.push({ agent: a.name, label: b.label, pct: b.remaining_pct });
      }
    }));
    if (badge) badge.textContent = t("hp_installed_running", { installed: d.total_installed || 0, running: d.total_running || 0 });

    const runningAgents = agents.filter(a => (a.procs || 0) > 0);
    const procsList = [];
    runningAgents.forEach(a => {
      (a.proc_list || []).forEach(p => {
        procsList.push({ name: a.name, pid: p.pid, mem: p.mem_mb, cpu: p.cpu });
      });
    });

    let lowHtml = "";
    if (low.length > 0) {
      lowHtml = `<div class="hp-agent-pill warn">${icon("warn", 12)} <span>${escHtml(t("hp_quota_warn", { n: low.length }))}</span></div>`;
    } else {
      lowHtml = `<div class="hp-agent-pill green"><span>✓ ${escHtml(t("hp_quota_ok"))}</span></div>`;
    }

    body.innerHTML = `
      <div class="hp-agent-summary" data-nav="agent" role="button" tabindex="0">
        <div class="hp-agent-kpis">
          <div class="hp-agent-pill"><b>${d.total_installed || 0}</b> <span>${escHtml(t("hp_installed"))}</span></div>
          <div class="hp-agent-pill ${d.total_running ? 'green' : ''}"><b>${d.total_running || 0}</b> <span>${escHtml(t("hp_running"))}</span></div>
          ${lowHtml}
        </div>
        <div class="hp-agent-procs">
          ${procsList.length ? procsList.slice(0, 3).map(p => `
            <div class="hp-agent-proc-row">
              <span class="hp-agent-proc-name">${escHtml(p.name)}</span>
              <span class="hp-agent-proc-detail">PID ${p.pid} · ${Math.round(p.mem)}MB · ${p.cpu}%</span>
            </div>
          `).join("") : `<div class="gempty" style="padding:10px 0;">${escHtml(t("hp_no_agent_proc"))}</div>`}
        </div>
      </div>
    `;
  } catch (e) {
    body.innerHTML = `<div class="gempty">${escHtml(e.message)}</div>`;
  }
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
  // 总体状态: 图标+文字双通道; 红=有严重(会话丢失) 黄=有告警 绿=全部正常
  const ok = nAlert === 0;
  const cls = ok ? "ok" : alerts.some(a => a.sev === "bad") ? "bad" : "warn";
  const txt = ok ? t("st_all_ok") : t("st_alert", { n: nAlert });
  const ico = ok ? "ok" : "warn";
  const sc = $("statuscard"), sl = $("statusline");
  if (sc) { sc.className = "statuscard " + cls; $("sc-ico").innerHTML = icon(ico, 28); $("sc-text").textContent = txt; }
  if (sl) { sl.className = "statusline " + cls; const si = $("status-ico"); if (si) si.innerHTML = icon(ico, 16); const st = $("status-text"); if (st) st.textContent = txt; }

  const mSvc = $("m-svc"), mRun = $("m-run"), mBad = $("m-bad"), mAlert = $("m-alert");
  if (mSvc) mSvc.textContent = lastSvc.ok + "/" + lastSvc.total;
  if (mRun) mRun.textContent = nRun;
  if (mBad) { mBad.textContent = nBad; mBad.classList.toggle("alert", nBad > 0); }
  if (mAlert) { mAlert.textContent = nAlert; mAlert.classList.toggle("alert", nAlert > 0); }

  renderAlerts(alerts);
  updateBadge(nAlert);
  refreshFreshness();

  // 渲染首页四大中枢概览卡片
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
function refreshFreshness() {
  const age = Date.now() - lastUpdatedTs;
  const stale = age > 2 * autoSec * 1000;   // 超过 2× 刷新周期 → 数据过期
  const h = $("stale-badge"), s = $("sc-stale");
const staleHtml = icon("warn", 12) + " " + t("st_stale");
  if (h) { h.hidden = !stale; h.innerHTML = staleHtml; }
  if (s) { s.hidden = !stale; s.innerHTML = staleHtml; }
  const f = $("sc-fresh");
  if (f) f.textContent = t("g_last") + ": " + agoStr(age / 1000);
}
setInterval(() => { if (!document.hidden) refreshFreshness(); }, 20000);

// 概要页交互: 状态卡 / 四大中枢 Portal 跳转
$("statuscard")?.addEventListener("click", (e) => {
  if (e.target.closest(".gcopy") || e.target.closest("a")) return;
  if (typeof mqMobile !== "undefined" && mqMobile.matches) setPage(2);
  else setCat("svc");
});

document.addEventListener("click", (e) => {
  const jump = e.target.closest("[data-nav]");
  if (jump) {
    if (e.target.closest("a[href]") || e.target.closest(".gcopy") || e.target.closest(".svctl-btn")) return;
    const nav = jump.dataset.nav;
    if (nav === "activity") { isMobile() ? setPage(1) : setCat("activity"); }
    else if (nav === "svc") { isMobile() ? setPage(2) : setCat("svc"); }
    else if (nav === "tmux") { isMobile() ? setPage(3) : setCat("tmux"); }
    else if (nav === "agent") { isMobile() ? setPage(4) : setCat("agent"); }
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
  if (typeof mqMobile !== "undefined" && mqMobile.matches) setPage(3);
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
  if (e.target.closest(".detail")) setPage(3);
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

  if (LANG === "en") {
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const mStr = months[d.getMonth()];
    const dt = `${mStr} ${day}, ${y}`;
    if (curStr === todayStr) return `Commits on ${dt} (Today)`;
    if (curStr === yestStr) return `Commits on ${dt} (Yesterday)`;
    return `Commits on ${dt}`;
  } else if (LANG === "ja") {
    const dt = `${y}年${m}月${day}日`;
    if (curStr === todayStr) return `${dt} (今日)`;
    if (curStr === yestStr) return `${dt} (昨日)`;
    return dt;
  } else {
    // zh
    const dt = `${y}年${m}月${day}日`;
    if (curStr === todayStr) return `${dt} · 今天`;
    if (curStr === yestStr) return `${dt} · 昨天`;
    return dt;
  }
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

let curActivityRepo = "all";

async function renderActivityPage() {
  const ap = $("activity-page");
  if (ap) ap.hidden = false;
  const container = $("activity-body");
  if (!container) return;
  const d = await fetchGoalsData();
  const events = (d && d.events) || [];
  const activityEvents = showStaticPublishCommits ? events : withLatestStaticPublishCommit(events);
  if (!activityEvents.length) {
    container.innerHTML = `<div class="gempty">${escHtml(t("act_empty"))}</div>`;
    return;
  }

  // 渲染顶部仓库胶囊条 (含未提交修改状态与一键筛选)
  const reposBar = $("act-repos-bar");
  if (reposBar) {
    const repoStats = new Map();
    const reposList = ((reposCache.data && reposCache.data.repos) || []).filter(r => {
      if (showStaticPublishCommits || r.name !== "svc-dashboard") return true;
      return activityEvents.some(e => e.kind === "commit" && e.repo === r.name);
    });
    reposList.forEach(r => {
      repoStats.set(r.name, { name: r.name, commits: r.commits || 0, dirty: r.dirty || 0 });
    });
    activityEvents.forEach(e => {
      if (e.kind === "commit" && e.repo && !repoStats.has(e.repo)) {
        repoStats.set(e.repo, { name: e.repo, commits: 0, dirty: 0 });
      }
    });

    const sortedRepos = [...repoStats.values()].sort((a, b) => {
      if ((b.dirty > 0) !== (a.dirty > 0)) return (b.dirty > 0) ? 1 : -1;
      return (b.commits || 0) - (a.commits || 0);
    });

    let chipsHtml = `<span class="act-repo-chip ${curActivityRepo === 'all' ? 'active' : ''}" data-act-repo="all">
      <span class="act-repo-dot" style="--rc-col:var(--text-soft)"></span>
      <span>${t("chip_all")}</span>
    </span>`;

    chipsHtml += sortedRepos.map(r => {
      const th = getRepoTheme(r.name);
      const isAct = curActivityRepo === r.name;
      const dirtyHtml = r.dirty ? `<span class="act-repo-dirty" title="${escAttr(t("act_dirty_count", { n: r.dirty }))}">${escHtml(t("act_dirty_count", { n: r.dirty }))}</span>` : "";
      const commitTxt = r.commits ? `<span class="act-repo-cnt">${r.commits}</span>` : "";
      return `<span class="act-repo-chip ${isAct ? 'active' : ''}" style="--rc-col:${th.color};--rc-bg:${th.bg};--rc-bd:${th.border};" data-act-repo="${escAttr(r.name)}">
        <span class="act-repo-dot"></span>
        <span class="act-repo-name">${escHtml(r.name)}</span>
        ${commitTxt}
        ${dirtyHtml}
        <span class="act-repo-traj-btn" data-traj="${escAttr(r.name)}" role="button" tabindex="0" title="${escAttr(t("act_repo_traj"))}">${icon("chart", 11)}</span>
      </span>`;
    }).join("");

    reposBar.innerHTML = `<button class="act-repos-nav prev" type="button" aria-label="${escAttr(t("act_repo_prev"))}" hidden>‹</button>`
      + `<div class="act-repos-scroll">${chipsHtml}</div>`
      + `<button class="act-repos-nav next" type="button" aria-label="${escAttr(t("act_repo_next"))}" hidden>›</button>`;
    const repoScroll = reposBar.querySelector(".act-repos-scroll");
    const updateRepoNav = () => {
      if (!repoScroll) return;
      const overflowing = repoScroll.scrollWidth > repoScroll.clientWidth + 2;
      reposBar.classList.toggle("has-overflow", overflowing);
      const prev = reposBar.querySelector(".act-repos-nav.prev");
      const next = reposBar.querySelector(".act-repos-nav.next");
      if (prev) { prev.hidden = !overflowing || repoScroll.scrollLeft <= 2; }
      if (next) { next.hidden = !overflowing || repoScroll.scrollLeft + repoScroll.clientWidth >= repoScroll.scrollWidth - 2; }
    };
    if (repoScroll) {
      repoScroll.addEventListener("scroll", updateRepoNav, { passive: true });
      requestAnimationFrame(updateRepoNav);
    }
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

  // 筛选过滤 (类型筛选 + 仓库筛选)
  const filtered = activityEvents.filter(e => {
    if (curActivityFilter === "commit") { if (e.kind !== "commit") return false; }
    else if (curActivityFilter === "img") { if (e.kind !== "commit" || !(e.files || []).some(f => IMG_EXT_RE.test(f.path))) return false; }
    else if (curActivityFilter === "both") { if (e.kind !== "commit" || e.origin !== "both") return false; }
    else if (curActivityFilter === "local") { if (e.kind !== "commit" || e.origin !== "local") return false; }
    else if (curActivityFilter === "done") { if (e.src !== "done" && e.kind !== "complete") return false; }
    else if (curActivityFilter === "watchdog") { if (e.src !== "watchdog" && e.kind !== "watchdog") return false; }

    if (curActivityRepo !== "all") {
      if (e.kind === "commit") {
        if (e.repo !== curActivityRepo) return false;
      } else {
        if (!((e.name || "") + " " + (e.gid || "")).includes(curActivityRepo)) return false;
      }
    }
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
      const timeStr = e.time || (e.ts ? new Date(e.ts * 1000).toLocaleString() : '');
      const author = e.author || "cheyan";
      const metaRow = `<div class="act-meta-row">
        <span class="act-time-full">${icon("clock", 11)} ${escHtml(timeStr)}</span>
        <span class="act-dot-sep">·</span>
        <span class="act-author">by ${escHtml(author)}</span>
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
      const timeStr = e.time || (e.ts ? new Date(e.ts * 1000).toLocaleString() : '');
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
  const repoNav = e.target.closest("#act-repos-bar .act-repos-nav");
  if (repoNav) {
    const scroller = document.querySelector("#act-repos-bar .act-repos-scroll");
    if (scroller) scroller.scrollBy({ left: (repoNav.classList.contains("prev") ? -1 : 1) * Math.max(220, scroller.clientWidth * .72), behavior: "smooth" });
    return;
  }
  const repoChip = e.target.closest("#act-repos-bar .act-repo-chip");
  if (repoChip) {
    if (e.target.closest(".act-repo-traj-btn")) return;
    const r = repoChip.dataset.actRepo;
    curActivityRepo = (curActivityRepo === r && r !== "all") ? "all" : r;
    renderActivityPage();
    return;
  }
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
// --- Tmux 会话中枢 ---
// ==========================================================================
let tmuxHubCache = { t: 0, data: null };
let curTmuxFilter = "all";
let curTmuxSearch = "";
const tmuxActiveWins = {};  // session -> active window index
const tmuxShowTerm = {};    // session -> boolean (default true)

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
        <div class="tmux-stat-val">${summary.total}</div>
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

  // 3. 过滤 sessions
  const q = curTmuxSearch.toLowerCase().trim();
  const filtered = sessions.filter(s => {
    if (curTmuxFilter === "agent" && !s.is_agent) return false;
    if (curTmuxFilter === "attached" && !s.attached) return false;
    if (curTmuxFilter === "detached" && s.attached) return false;
    if (q) {
      const matchName = (s.name || "").toLowerCase().includes(q);
      const matchRepo = (s.repo || "").toLowerCase().includes(q);
      const matchCmd = (s.main_command || "").toLowerCase().includes(q);
      const matchCwd = (s.main_cwd || "").toLowerCase().includes(q);
      const matchWins = (s.windows || []).some(w =>
        (w.name || "").toLowerCase().includes(q) ||
        (w.panes || []).some(p =>
          (p.command || "").toLowerCase().includes(q) ||
          (p.title || "").toLowerCase().includes(q) ||
          (p.cwd || "").toLowerCase().includes(q)
        )
      );
      if (!matchName && !matchRepo && !matchCmd && !matchCwd && !matchWins) return false;
    }
    return true;
  });

  if (!filtered.length) {
    body.innerHTML = `<div class="gempty">${escHtml(q ? t("tmux_no_match") : t("tmux_empty"))}</div>`;
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

    // 仓库颜色胶囊
    let repoBadge = "";
    if (s.repo && s.repo !== "—") {
      const theme = getRepoTheme(s.repo);
      repoBadge = `<span class="tmux-badge tmux-badge-repo" style="background:${theme.color};">${escHtml(s.repo)}</span>`;
    }

    // 活跃窗口选择
    const wins = s.windows || [];
    let curWinIdx = tmuxActiveWins[s.name];
    if (curWinIdx === undefined) {
      const activeWin = wins.find(w => w.active) || wins[0];
      curWinIdx = activeWin ? activeWin.index : 1;
      tmuxActiveWins[s.name] = curWinIdx;
    }
    const curWin = wins.find(w => w.index === curWinIdx) || wins[0] || { panes: [] };

    // 窗口 Tabs
    const tabsHtml = wins.length > 0 ? `
      <div class="tmux-tabs-bar">
        ${wins.map(w => {
          const isSelected = w.index === curWinIdx;
          const star = w.active ? `<span class="tmux-tab-star" title="活跃窗口">*</span>` : "";
          return `<span class="tmux-tab-chip ${isSelected ? 'active' : ''}" data-sname="${escAttr(s.name)}" data-widx="${w.index}">
            ${w.index}: ${escHtml(w.name)}${star}
          </span>`;
        }).join("")}
      </div>` : "";

    // 窗格详情
    const panes = curWin.panes || [];
    const activePane = panes.find(p => p.active) || panes[0] || {};

    // 窗格行
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

    // 终端预览开关与内容
    const showTerm = tmuxShowTerm[s.name] !== false; // 默认展开
    const termLines = (activePane.preview || []).slice(-12);
    const termText = termLines.length ? termLines.join("\n") : "(no terminal output captured)";
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

    // 关联 Goal 提示
    let goalBanner = "";
    if (s.goal) {
      const g = s.goal;
      goalBanner = `
        <div class="tmux-goal-banner">
          <div class="tmux-goal-banner-left">
            ${icon("target", 13)} <b>${escHtml(t("tmux_linked_goal"))}</b>
            <span class="tmux-goal-banner-obj">${escHtml(g.objective || g.label || g.gid)}</span>
          </div>
          ${g.resume_cmd ? `<button class="btn-tmux-act gcopy" data-copy="${escAttr(g.resume_cmd)}">${icon("copy", 11)} <span>Resume</span></button>` : ""}
        </div>
      `;
    }

    const agoStr = s.activity_ago < 60 ? `${s.activity_ago}s ago` : `${Math.floor(s.activity_ago / 60)}m ago`;

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
            <button class="btn-tmux-act btn-tmux-term-toggle ${showTerm ? 'active' : ''}" data-sname="${escAttr(s.name)}" title="${escAttr(t('tmux_term_toggle'))}">
              ${icon("term", 12)} <span>${escHtml(showTerm ? t("tmux_term_hide") : t("tmux_term_toggle"))}</span>
            </button>
            <button class="btn-tmux-act btn-tmux-copy-attach gcopy" data-copy="${escAttr(s.attach_cmd)}" title="${escAttr(t('tmux_copy_attach'))}">
              ${icon("copy", 12)} <span>attach</span>
            </button>
          </div>
        </div>
        <div class="tmux-meta-bar">
          <span class="tmux-meta-item">${icon("clock", 12)} <span>${escHtml(s.created_str)} (${agoStr})</span></span>
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

// Tmux Hub 事件监听绑定 (一处绑定)
(function initTmuxPageEvents() {
  const tp = $("tmux-panel");
  if (!tp) return;

  const searchInput = $("tmux-search");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      curTmuxSearch = e.target.value;
      renderTmuxPage();
    });
  }

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
  });
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

// 仅触摸设备启用：页面顶端向下拖动时复用现有手动刷新入口 load(true)。
(function setupPullToRefresh() {
  const touchCapable = ("ontouchstart" in window) || navigator.maxTouchPoints > 0;
  if (!touchCapable) return;
  const indicator = $("ptr-indicator");
  const ring = indicator.querySelector(".ptr-ring circle");
  const CIRC = 2 * Math.PI * 16.5;   // 圆环周长(r=16.5)
  const threshold = 70;
  let startY = 0, pull = 0, rawDistance = 0, tracking = false, refreshing = false;
  const setPull = (distance) => {
    rawDistance = Math.max(0, distance);
    pull = Math.min(110, rawDistance * 0.55);
    indicator.style.transform = `translateY(${pull}px)`;
    const prog = Math.min(1, rawDistance / threshold);
    if (ring) ring.style.strokeDashoffset = String(CIRC * (1 - prog));
    indicator.classList.toggle("on", rawDistance > 4);
    indicator.classList.toggle("ready", rawDistance >= threshold);
  };
  // 内部滚动布局: 判断「页面已滚下」要看 main 滚动容器, 不再是 window
  const mainScroller = document.querySelector("main");
  const pageScrolled = () => (mainScroller && mainScroller.scrollTop > 0) || window.scrollY > 0;
  document.addEventListener("touchstart", (e) => {
    if (refreshing || e.touches.length !== 1 || pageScrolled()) return;
    startY = e.touches[0].clientY;
    tracking = true;
  }, { passive: true });
  document.addEventListener("touchmove", (e) => {
    if (!tracking || refreshing || pageScrolled()) return;
    const distance = e.touches[0].clientY - startY;
    if (distance <= 0) { tracking = false; setPull(0); return; }
    e.preventDefault();
    setPull(distance);
  }, { passive: false });
  document.addEventListener("touchend", async () => {
    if (!tracking) return;
    tracking = false;
    if (rawDistance < threshold) { setPull(0); return; }
    refreshing = true;
    indicator.classList.remove("ready");
    indicator.classList.add("loading");
    indicator.style.transform = "translateY(48px)";
    // 圆环满格进入 loading 旋转态(ptr-core 旋转动画由 .loading CSS 驱动)
    console.log("[svc-dashboard] pull-to-refresh: load(true)");
    try { await load(true); }
    finally {
      refreshing = false;
      indicator.classList.remove("loading");
      setPull(0);
      haptic(10); // 刷新完成触觉反馈
      console.log("[svc-dashboard] pull-to-refresh done, haptic(10)");
    }
  }, { passive: true });
})();

document.querySelectorAll("#filters .chip").forEach(c =>
  c.addEventListener("click", () => { filter = c.dataset.f; applyFilter(); }));
document.querySelectorAll(".tcol").forEach(b =>
  b.addEventListener("click", () => {
    $("svc").dataset.col = b.dataset.col;
    document.querySelectorAll(".tcol").forEach(x =>
      x.classList.toggle("active", x === b));
  }));
// 刷新控件(topbar 圆钮 + 浮动圆钮共用): 点击=立即刷新, 长按(500ms)=锁定/解锁自动刷新
// 锁定态=琥珀描边+锁形角标, 两个按钮视觉同步。
let refreshHoldTimer = null, refreshHoldDone = false;
function refreshBtns() { return [$("refresh"), $("fab-refresh")].filter(Boolean); }
function setAutoLocked(v) {
  autoLocked = v;
  refreshBtns().forEach(b => { b.classList.toggle("locked", v); b.setAttribute("aria-pressed", v); });
}
function bindRefreshCtl(btn) {
  btn.addEventListener("click", () => {
    if (refreshHoldDone) return;   // 长按已处理, 吞掉后续 click
    haptic(8);
    console.log("[svc-dashboard] manual refresh via " + btn.id);
    load(true);
  });
  ["pointerdown", "touchstart"].forEach(ev => btn.addEventListener(ev, () => {
    refreshHoldDone = false;
    clearTimeout(refreshHoldTimer);
    refreshHoldTimer = setTimeout(() => {
      refreshHoldDone = true;
      setAutoLocked(!autoLocked);
      haptic(15);
      themeToast(t(autoLocked ? "locked_toast" : "unlocked_toast"));
      console.log("[svc-dashboard] auto refresh " + (autoLocked ? "locked" : "unlocked") + " via " + btn.id);
    }, 500);
  }, { passive: true }));
  ["pointerup", "pointercancel", "touchend", "touchcancel", "pointerleave"].forEach(ev =>
    btn.addEventListener(ev, () => clearTimeout(refreshHoldTimer), { passive: true }));
}
refreshBtns().forEach(bindRefreshCtl);
// 浮动刷新圆钮显隐: topbar(header)滚出视口 → 显示; 回到顶部 → 隐藏。
// IntersectionObserver 以视口为 root: 移动端 header 在 main 内随内容滚走, 桌面端随文档滚走。
(function setupFab() {
  const fab = $("fab-refresh"), hdr = document.querySelector("header");
  if (!fab || !hdr || !("IntersectionObserver" in window)) return;
  const io = new IntersectionObserver((entries) => {
    for (const en of entries) {
      const show = !en.isIntersecting;
      fab.hidden = !show;
      console.log("[svc-dashboard] fab " + (show ? "visible (topbar scrolled out)" : "hidden"));
    }
  }, { threshold: 0 });
  io.observe(hdr);
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
   移动 App 层(仅触摸设备): 分页滑动 / 底栏 / 列表手势 / 双击 /
   边缘返回 / 捏合图表 / 触觉反馈 / 轮询暂停。
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
// 触摸互斥: 一次触摸只属于一个手势(分页/滑动露按钮/边缘返回)
const gesture = { claimed: null };
// 移动端把各分区装进 5 个 .pg 页容器; 桌面端恢复原始 DOM 顺序(display:contents 布局)。
// 记住初始顺序, 窗口跨过 768px 断点时来回重组不丢内容。
const PAGE_GROUPS = [
  ["#statuscard", "#sysbar", "#chart-wrap", "#hp-portal-grid"],
  ["#activity-page"],
  ["#filters", "#tasks", "#svc-panel", "#cron-panel", "#logpage"],
  ["#tmux-panel"],
  ["#agents-page"],
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
// --- 分页(概览/活动/服务/Tmux/Agent) ---
const pages = $("pages");
const N_PAGES = 5;
const PAGE_W = 100 / N_PAGES;   // 轨道宽 500%, 每页位移 = 轨道的 1/5
var page = 0;   // var: 挂到 window, 便于外部调试/测试读取
function pageLabels() { return [t("tab_home"), t("tab_activity"), t("tab_svc"), t("tab_tmux"), t("tab_agent")]; }
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
  if (changed) activatePage(i);
  // 页面内容异步变化后(骨架→数据/折叠展开)重测高度
  requestAnimationFrame(() => applyPagesX(false));
}
function activatePage(i) {
  if (i === 0) requestAnimationFrame(drawChart);
  if (i === 1) { const ap = $("activity-page"); if (ap) ap.hidden = false; renderActivityPage(); }
  if (i === 2 && isMobile()) {       // 服务页: 骨架 → 渲染
    const tbody = $("svc").querySelector("tbody");
    if (!tbody.children.length) tbody.innerHTML = mobileSkel(4);
    applyFilter();
  }
  if (i === 2) {                     // 服务页尾部 = 计划任务 + 日志区(原管理页迁入)
    const cp = $("cron-panel");
    if (cp) cp.hidden = false;
    cronLoad();
    initLogPage(); renderLogTimeline();
  }
  if (i === 3) {
    const tp = $("tmux-panel");
    if (tp) tp.hidden = false;
    renderTmuxPage();
  }
  if (i === 4) {
    const ap = $("agents-page");
    if (ap) ap.hidden = false;
    initAgentsPage();
  }
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("#tabbar .tab");
  if (b) { setPage(+b.dataset.p); return; }
});

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
  const sel = $("logagent-sel"), body = $("logbody");
  $("logpage").hidden = false;   // 双端进入日志页即显示(移动页签 / 桌面 cat=log)
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
  if (first && !sel.selectedOptions[0].value) { sel.value = first.value; }
  if (!body.children.length) loadLogView();
}
async function loadLogView() {
  const body = $("logbody");
  const sel = $("logagent-sel");
  const opt = sel.selectedOptions[0];
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
let curAgentSearch = "";

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
  const quotaHtml = rtQuotaHtml(a);
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
    ${quotaHtml}
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

async function refreshAgentsPage() {
  const el = $("agents-page");
  if (!el || el.hidden) return;
  try { renderRuntimes(await loadRuntimes(true)); }
  catch (e) {
    const cont = $("agent-cards-container");
    if (cont) cont.innerHTML = esHtml("cpu", t("a_fail", { e: escHtml(e.message) }));
  }
}

function bindAgentHubEvents(el, d) {
  const searchInput = $("agent-search");
  if (searchInput && !searchInput.dataset.bound) {
    searchInput.dataset.bound = "1";
    searchInput.addEventListener("input", (e) => {
      curAgentSearch = e.target.value;
      renderRuntimes(d);
    });
  }

  const btnQuota = $("btn-refresh-quota");
  if (btnQuota && !btnQuota.dataset.bound) {
    btnQuota.dataset.bound = "1";
    btnQuota.addEventListener("click", async () => {
      btnQuota.classList.add("loading");
      await tlPost("/api/runtimes", { agent: "", action: "quota" });
      setTimeout(refreshAgentsPage, 1000);
    });
  }

  const btnProbeAll = $("btn-probe-all");
  if (btnProbeAll && !btnProbeAll.dataset.bound) {
    btnProbeAll.dataset.bound = "1";
    btnProbeAll.addEventListener("click", async () => {
      const testBtns = el.querySelectorAll("[data-mtest]");
      if (!testBtns.length) return;
      btnProbeAll.classList.add("loading");
      for (const b of testBtns) {
        b.click();
        await new Promise(r => setTimeout(r, 120));
      }
      setTimeout(() => btnProbeAll.classList.remove("loading"), 1000);
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
      if (typeof setPage !== "undefined" && isMobile()) setPage(3);
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

  // 5. 过滤与搜索
  const q = curAgentSearch.toLowerCase().trim();
  const filtered = allAgents.filter(a => {
    if (!rtMatch(a, rtFilter)) return false;
    if (q) {
      const matchName = (a.name || "").toLowerCase().includes(q);
      const matchBin = (a.bin || "").toLowerCase().includes(q);
      const matchAcc = (a.quota && a.quota.account ? a.quota.account.toLowerCase() : "").includes(q);
      const matchProcs = (a.proc_list || []).some(p => (p.cwd || "").toLowerCase().includes(q) || (p.cmd || "").toLowerCase().includes(q) || String(p.pid).includes(q));
      const matchTasks = (a.tasks || []).some(t => (t.cwd || "").toLowerCase().includes(q) || (t.goal || t.title || "").toLowerCase().includes(q));
      if (!matchName && !matchBin && !matchAcc && !matchProcs && !matchTasks) return false;
    }
    return true;
  });

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
  if (agentsInit) { refreshAgentsPage(); return; }
  agentsInit = true;
  const cards = $("agent-cards-container");
  if (cards) cards.innerHTML = mobileSkelDiv(3);
  try { renderRuntimes(await loadRuntimes()); }
  catch (e) {
    if (cards) cards.innerHTML = esHtml("cpu", t("a_fail", { e: escHtml(e.message) }));
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
      ${platHtml || `<div class="gempty">暂无外部接入平台</div>`}
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
              <span class="ad-memory-count">${m.count || 0} 条设定</span>
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

// --- goal 卡片展开(点标题切换 .gextra) ---
document.addEventListener("click", (e) => {
    const g = e.target.closest(".gcard");
    if (!g || !isMobile()) return;
    if (e.target.closest(".gcopy")) return;           // 复制 resume 命令: 交给全局 gcopy
    if (e.target.closest(".g-detail-btn")) return;    // 查看详情: 交给 goal 详情弹层
    if (e.target.closest(".g-ignore-btn")) return;    // 标记忽略: 交给上方忽略委托
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
    if (stat.dataset.k === "load") { setPage(3); haptic(10); }
  } else { lastTap = now; lastTapEl = stat; }
}, { passive: true });

// --- 触摸手势总协调: 分页滑动 / 边缘右滑返回 ---
if (TOUCH) (function setupGestures() {
  let g = null; // {kind:"page"|"edge", id, x0, y0, t0, dx, lastX, lockX}
  const W = () => window.innerWidth;
  document.addEventListener("touchstart", (e) => {
    if (e.touches.length !== 1 || g) return;
    const t = e.touches[0];
    if (!isMobile()) return;
    // 边缘手势最优先: 起点 x<24px 且非首页(否则按普通分页滑动处理)
    const edge = t.clientX < 24 && page > 0;
    // 横向自身滚动的容器不参与手势
    const scroller = t.target.closest ? t.target.closest(".filters, .aglog, .termlog, select") : null;
    if (scroller || !pages) return;
    // 边缘手势(上文已判定)返回概览, 否则普通分页滑动
    g = { kind: edge ? "edge" : "page", id: t.identifier, x0: t.clientX, y0: t.clientY,
          t0: Date.now(), lastX: t.clientX, lockX: null, dx: 0 };
    gesture.claimed = t.identifier;
  }, { passive: true });

  document.addEventListener("touchmove", (e) => {
    if (!g) return;
    const t = [...e.touches].find(x => x.identifier === g.id);
    if (!t) return;
    const dx = t.clientX - g.x0, dy = t.clientY - g.y0;
    if (g.lockX === null) {
      if (Math.abs(dx) < 6 && Math.abs(dy) < 6) return; // 未定轴
      g.lockX = Math.abs(dx) > Math.abs(dy);
      if (g.lockX) e.preventDefault(); // 横向手势: 阻断浏览器返回/前进导航
    }
    if (!g.lockX) return; // 纵向滚动交给浏览器
    // 分页/边缘: 跟手(阻尼 0.55), 越界回弹
    let d = (page > 0 || dx > 0) && (page < N_PAGES - 1 || dx < 0) ? dx * 0.55
            : dx > 0 ? (page < N_PAGES - 1 ? 0 : Math.min(64, dx * 0.18))
                     : (page > 0 ? 0 : Math.max(-64, dx * 0.18));
    if (g.kind === "edge" && d < -20) { g.kind = "page"; } // 反向滑: 降级为分页
    const pct = d / W() * 100;
    g.dx = pct;
    if (!trackEl) return;
    trackEl.classList.add("stick");
    trackEl.style.transform = `translate3d(calc(${-page * PAGE_W}% + ${pct}vw),0,0)`;
    g.lastX = t.clientX;
  }, { passive: false });

  document.addEventListener("touchend", (e) => {
    if (!g) return;
    const t = [...e.changedTouches].find(x => x.identifier === g.id);
    const done = () => { gesture.claimed = null; g = null; };
    if (!t) { done(); return; }
    const dx = (g.lockX ? g.lastX - g.x0 : 0);
    const dt = Date.now() - g.t0;
    trackEl && trackEl.classList.remove("stick");
    if (g.kind === "edge" && g.lockX && dx > 56) {
      console.log("[svc-dashboard] edge-swipe back to overview");
      setPage(0); done(); return;
    }
    // 分页吸附: 位移超过 1/4 屏 或 快速轻扫
    const fast = Math.abs(dx) > 40 && dt < 260;
    if (g.lockX && (Math.abs(dx) > W() / 4 || fast)) {
      const dir = dx < 0 ? 1 : -1; // 左滑下一页, 右滑上一页
      if ((dir > 0 && page < N_PAGES - 1) || (dir < 0 && page > 0)) { setPage(page + dir); done(); return; }
    }
    applyPagesX(true); // 未达阈值: 弹回当前页
    done();
  }, { passive: true });
  document.addEventListener("touchcancel", () => {
    if (!g) return;
    trackEl && trackEl.classList.remove("stick");
    applyPagesX(true);
    g = null; gesture.claimed = null;
  }, { passive: true });
})();

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
  ctx.fillStyle = CH.load; ctx.textAlign = "right"; ctx.fillText("load " + maxL.toFixed(1), w - 8, 16); ctx.textAlign = "left";
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
  const r = await fetch(url, { cache: "no-store" });
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

// --- 连接信息(状态卡 sc-sub 行内的 IP 复制 chip): ssh/LAN 点击复制, 数据来自 TL_CONF(不写死) ---
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
  // 状态卡和 SSH/IP 提示都只属于首页；只读快照的“在线版”入口不受影响。
  const status = $("statuscard");
  if (status) status.hidden = !home;
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

// --- 桌面端分类条(右上角 #catbar): 概览/活动/服务/Tmux/Agent; 移动端隐藏(底部页签) ---
const CATS = [
  ["home", "tab_home"], ["activity", "tab_activity"], ["svc", "tab_svc"], ["tmux", "tab_tmux"], ["agent", "tab_agent"],
];
const CAT_SELS = {
  home: ["#statuscard", "#sysbar", "#chart-wrap", "#hp-portal-grid"],
  activity: ["#activity-page"],
  svc: ["#filters", "#tasks", "#svc-panel", "#cron-panel", "#logpage"],
  tmux: ["#tmux-panel"],
  goal: ["#tmux-panel"],
  agent: ["#agents-page"],
  manage: ["#agents-page"],
};
var curCat = "all";
function setCat(c, save) {
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
    renderTmuxPage();
  }
  if (c === "svc") {
    const lp = $("logpage"), cp = $("cron-panel");
    if (lp) lp.hidden = false;
    if (cp) cp.hidden = false;
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
  document.querySelectorAll(".filters").forEach(el => {
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

// --- 启动 ---
regroupPages();          // 手机: 分组进 6 页; 桌面: 保持原序
if (isMobile()) {
  setPage(0, { first: true });
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
load(true);
renderConnbar();   // 顶栏连接信息(ssh/IP)随首屏渲染, 不等进工具页
// AI 清理: 首页面板按钮 + 弹层关闭(独立于工具页惰性初始化, 首页直达)
$("hp-aiclean-run")?.addEventListener("click", aiCleanHome);
$("aiclean-modal-close")?.addEventListener("click", aiCloseModal);
$("aiclean-modal")?.addEventListener("click", e => { if (e.target.id === "aiclean-modal") aiCloseModal(); });
$("aiclean-modal-rerun")?.addEventListener("click", aiRerun);
aiStatusChip();
hydrateFragments();
