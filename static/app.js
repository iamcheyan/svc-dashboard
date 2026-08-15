const BOOT = window.__BOOT__ || {};
const AUTO = BOOT.auto;
const LANG = BOOT.lang;
const TS_MODE = BOOT.tsMode;
const TS_HOST = "100.76.219.104";
const linkHost = (h) => (TS_MODE && (h === "192.168.3.82")) ? TS_HOST : h;  // 来源为 tailscale(100.64.0.0/10) 时链接主机改用 tailscale IP
const T = BOOT.t;
const t = (k, p) => { let s = T[k] ?? k; if (p !== undefined) { for (const [a, b] of Object.entries(p)) s = s.split("{" + a + "}").join(b); } return s; };
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
  else if (e.type === "docker" && e.container_id) detail = `<span class='detail' title='${t("detail_cid")}'>${e.container_id}</span>`;
  else if (e.type === "systemd" && e.unit) detail = `<span class='detail' title='${t("detail_unit")}'>${e.unit}</span>`;
  const ip = e.ip;
  const loopback = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
  const link = loopback ? `http://127.0.0.1:${e.port}/` : `http://${linkHost(location.hostname)}:${e.port}/`;
  const loop = loopback ? ' <span class="local">' + t("loopback") + '</span>' : "";
  const cmd = e.cmdline || "—";
  const cwd = e.cwd || "—";
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  // 可管理的手动进程服务: 行尾渲染 暂停/继续 按钮(状态由 fillCtl 填充)
  const man = MANAGE_PROC_BY_PORT[e.port];
  // P0-6: 行首运行状态点(红=paused/异常 绿=正常 灰=受管单元状态未知); 受管单元由 fillSvcDots 异步上色
  const svcUnit = man || (e.type === "systemd" && MANAGE_SVC_BY_UNIT[e.unit]) || null;
  const svcDot = `<span class="svc-dot ${svPaused ? "bad" : svcUnit ? "off" : "on"}"${svcUnit ? ` data-unit="${esc(svcUnit)}"` : ""}></span>`;
  const ctl = man
    ? `<span class='ctl-btn' data-ctl='${man}' data-port='${e.port}' role='button' tabindex='0' aria-disabled='true'>${t("ctl_checking")}</span>`
    : "";
  // 通用暂停/恢复(svcctl) + 资源行: 详情弹层 payload 带上 res
  const svctl = svBtn(e);
  const svBtnNamed = svctl ? svctl.replace("data-svcp=", `data-svcn='${esc(e.name.replace(/ \(docker\)| \(paused\)$/g, ""))}' data-svcp=`) : "";
  const res = fmtRes(e);
  const detailBtn = (payload) => `<span class='svc-detail' role='button' tabindex='0' data-detail='${encodeURIComponent(JSON.stringify(payload))}' title='${t("svc_detail")}'>${t("svc_detail")}</span>`;
  const dpayload = { name: e.name, port: e.port, ip, cmd, cwd, pids: e.pids, res: e.res || null, unit: e.unit || null, cid: e.container_id || null };
  if (mobile) {
    // 手机卡片(合法表格结构): 头行右侧显式 44px 圆形 复制/打开 按钮(无滑扫手势)
    const kv = (k, v) => `<div class='kv'><span class='k'>${k}</span><span class='v'>${v}</span></div>`;
    const rows =
      kv(t("th_port"), `<a href='${link}' target='_blank' rel='noopener'>${e.port}</a>`) +
      kv(t("th_addr"), `${esc(ip)}${loop}`) +
      kv("PID", e.pids.join(", ")) +
      (res ? kv(t("th_res"), res) : "") +
      kv(t("th_cmd"), `<span class='mclamp' role='button' tabindex='0' aria-expanded='false'>${esc(cmd)}</span>`) +
      kv(t("th_cwd"), esc(cwd)) +
      (man || svBtnNamed ? kv(t("th_ctl"), ctl + svBtnNamed) : "");
    return `<tr><td>` +
      `<div class='td-head'>${svcDot}<span class='svc'>${esc(e.name)}</span>` +
      `<span class='badge ${badge[1]}'>${text}</span>${detail}` +
      `<span class='svc-act' role='button' tabindex='0' data-copy='${esc(link)}' title='${t("act_copy_addr")}' aria-label='${t("act_copy_addr")}'>${icon("copy", 15)}</span>` +
      `<a class='svc-open' href='${link}' target='_blank' rel='noopener' aria-label='${t("act_open")} ${esc(e.name)}'>${icon("ext", 15)}</a></div>` +
      `<div class='td-rows'>${rows}</div></td></tr>`;
  }
  return `<tr>
    <td class='name'>${svcDot}<span class='svc'>${esc(e.name)}</span><span class='badge ${badge[1]}'>${text}</span>${detail}</td>
    <td class='port' data-label='${t("th_port")}'><a href='${link}' target='_blank' rel='noopener'>${e.port}</a></td>
    <td class='addr' data-label='${t("th_addr")}'>${esc(ip)}${loop}</td>
    <td class='pid' data-label='PID'>${e.pids.join(", ")}${res ? `<div class='pid-res'>${res}</div>` : ""}${svBtnNamed ? `<div class='pid-svctl'>${svBtnNamed}</div>` : ""}</td>
    <td class='cmd' data-label='${t("th_cmd")}'>
      <div class='cmd-cell'><span class='cmd-text'>${esc(cmd)}</span>${detailBtn(dpayload)}${ctl ? `<span class='cmd-ctl'>${ctl}</span>` : ""}</div></td>
    <td class='cwd' data-label='${t("th_cwd")}'>
      <div class='cmd-cell'><span class='cmd-text'>${esc(cwd)}</span>${detailBtn(dpayload)}</div></td>
  </tr>`;
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
  tbody.innerHTML = shown.length ? shown.map(e => row(e, isMobile())).join("") :
    '<tr><td class="empty" colspan="6">' + t("no_match") + '</td></tr>';
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
  chartSample(s); // 手机端趋势图采样(桌面 no-op)
}

// --- 仓库面板: agent/goal 改动过的仓库(/api/repos; 客户端 60s 缓存) ---
let reposCache = { t: 0, data: null }, reposInflight = false;
async function loadRepos(force) {
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
  if (!el) return;
  const list = (d && d.repos) || [];
  if (!list.length) { el.innerHTML = `<div class="gempty">${t("rp_empty")}</div>`; return; }
  const fmtB = (n) => {
    if (n == null) return "—";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  };
  // Agent 操作轨迹条: 近14天逐日双行色块(上行=里程碑: 完成/提交/干预/恢复,
  // 下行=活动健康: 工具调用紫 / 失败高发红); 点击整卡进详情
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
  document.documentElement.classList.remove("fs-noscroll");
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
  document.documentElement.classList.add("fs-noscroll");
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
    rows += "<tr><td><span class='tbadge rd'>Codex</span><span class='tname tlink' data-sid='' data-cwd='" +
      esc(x.cwd) + "' data-tmux='' title='" + t("a_openterm", { p: esc(x.pid) }) + "'>" +
      esc(x.cwd) + "</span></td><td data-label='" + t("a_status") + "'>" + t("a_running") + "</td><td class='tscope' data-label='" + t("a_loc") + "'>—<br>" + esc(x.cwd) + "</td><td class='tsch' data-label='" + t("a_active") + "'>" +
      esc(x.last_activity) + "<br>" + agoStr(x.idle_seconds) + "</td><td class='tcmd' data-label='" + t("a_tool") + "'>pid " + esc(x.pid) + "</td></tr>";
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
function agentLogHtml(d) {
  const esc = (x) => String(x || "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  let html = "<div class='agentlog'>";
  if ((d.events || []).length) {
    html += "<div class='aglog-title'>" + t("a_recent") + " <span class='aglog-refresh' role='button' tabindex='0'>" + t("refresh") + "</span></div><div class='aglog-list'>" +
      d.events.map(e => "<div class='aglog-row'><span class='aglog-ts'>" + esc(e[0]) + "</span><span class='aglog-txt'>" + esc(e[1]) + "</span></div>").join("") + "</div>";
  }
  if (d.capture && d.capture.length) {
    html += "<div class='aglog-title'>" + t("a_term") + " <span class='aglog-refresh' role='button' tabindex='0'>" + t("refresh") + "</span></div><pre class='termlog'>" +
      d.capture.map(l => esc(l)).join("\n") + "</pre>";
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

// 服务表行尾的 暂停/继续 按钮: 查状态填充文案,点击执行动作。
async function fillCtl() {
  const btns = document.querySelectorAll(".ctl-btn");
  await Promise.all([...btns].map(async (b) => {
    const uid = b.dataset.ctl;
    b.setAttribute("aria-disabled", "true");
    try {
      const r = await fetch("/api/manage?unit=" + encodeURIComponent(uid) + "&lang=" + encodeURIComponent(LANG), { cache: "no-store" });
      const st = await r.json();
      const running = st && st.ok && st.active === "active";
      b.textContent = running ? t("ctl_pause") : t("ctl_resume");
      b.dataset.action = running ? "stop" : "start";
      b.setAttribute("aria-disabled", "false");
    } catch (e) {
      b.innerHTML = icon("err", 13);
      b.title = e.message;
    }
  }));
  document.querySelectorAll(".ctl-btn").forEach(b =>
    b.addEventListener("click", () => doCtl(b)));
}

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
    const r = await fetch("/api/manage?lang=" + encodeURIComponent(LANG), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ unit: uid, action }),
    });
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
  return `<span class='svc-res' title='${t("svc_res_title")}'>${r.cpu.toFixed(1)}% · ${r.mem_mb >= 1024 ? (r.mem_mb / 1024).toFixed(1) + "G" : Math.round(r.mem_mb) + "M"} · ${fmtUp(r.up_sec)}</span>`;
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
    const r = await fetch("/api/svcctl", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ port, action }),
    });
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
    const r = await fetch("/api/manage?lang=" + encodeURIComponent(LANG), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ unit, action }),
    });
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
  if (next && old) old.replaceWith(next);
  else if (part === "toolchips" && next) document.querySelector("#filters")?.before(next);
  else return false;
  return true;
}

async function hydrateFragments() {
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
const LOG_LIMIT = 60;

async function fetchGoalsData(force) {
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
  const el = $("alert-body");
  if (!el) return;
  if (!alerts.length) { el.innerHTML = esHtml("bell", t("al_none")); return; }
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
  const sc = $("statuscard"), sl = $("statusline"); // sl 可为 null(已移除)
  if (sc) { sc.className = "statuscard " + cls; $("sc-ico").innerHTML = icon(ico, 28); $("sc-text").textContent = txt; }
  if (sl) { sl.className = "statusline " + cls; const si = $("status-ico"); if (si) si.innerHTML = icon(ico, 16); const st = $("status-text"); if (st) st.textContent = txt; }
  $("m-svc").textContent = lastSvc.ok + "/" + lastSvc.total;
  $("m-run").textContent = nRun;
  $("m-bad").textContent = nBad;
  $("m-bad").classList.toggle("alert", nBad > 0);
  $("m-alert").textContent = nAlert;
  $("m-alert").classList.toggle("alert", nAlert > 0);
  renderAlerts(alerts);
  // 最近活动: 只显示 agent 仓库的提交(由新到旧), 点击进日志页
  const recent = events.filter(e => e.kind === "commit").slice(0, 5);
  $("recent-body").innerHTML = recent.length ? recent.map(e => {
    const m = EV_META[e.kind] || EV_META.other;
    return `<div class="rc-row" role="button" tabindex="0"><span class="rc-ico">${icon(m.ico, 14)}</span>` +
      `<span class="rc-kind">${escHtml(t(m.key))} · <b class="rc-name">${escHtml(e.name)}</b>` +
      `<span class="rc-sub">${escHtml(e.text)}</span></span>` +
      `<span class="rc-ago">${escHtml(agoFromTs(e.ts))}</span></div>`;
  }).join("") : `<div class="gempty">${t("ev_none")}</div>`;
  // Web磁贴 + Goal 摘要: 双端都渲染(移动端 #hp-grid 同样显示, 修复永久"loading…")
  renderHomeTiles(apiData && apiData.services);
  renderHomeGoals(goals, nRun, nBad);
  updateBadge(nAlert);
  refreshFreshness();
}
function renderHomeTiles(services) {
  const el = $("hp-tiles");
  if (!el) return;
  const svcs = services || [];
  const web = svcs.filter(e => {
    const ip = e.ip || "";
    const loop = ip.startsWith("127.") || ip === "::1" || ip.startsWith("::ffff:127.");
    return e.scope !== "system" && !e.paused && !loop && ![22000, 5355].includes(+e.port);
  });
  // 同端口去重(docker v4/v6 双行)
  const seen = new Set(), uniq = [];
  web.forEach(e => { const k = e.port + ":" + (e.name || ""); if (!seen.has(k)) { seen.add(k); uniq.push(e); } });
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
  }).join("") : `<div class="gempty">${t("ev_none")}</div>`;
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

// 概要页交互: 状态卡→Goal页 / 状态栏→回概要 / 最近活动→日志页 / 告警操作
$("statuscard").addEventListener("click", (e) => { if (!e.target.closest(".gcopy")) setPage(2); });
const statuslineEl = $("statusline");   // header 状态栏已移除(85102dc), 此处判空防崩
if (statuslineEl) statuslineEl.addEventListener("click", () => {
  setPage(0);
  const m = document.querySelector("main");
  if (m) m.scrollTo({ top: 0 });
});
const rcMore = document.querySelector(".rc-more");
if (rcMore) rcMore.addEventListener("click", () => setPage(1));
$("recent-body").addEventListener("click", () => setPage(1));
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

// --- 日志页: 全局事件时间线(筛选 chips + 同goal循环折叠 + 详情默认折叠) ---
const logFilter = { st: "all", src: "all", hrs: 24 };
function filterEvents(evs) {
  const now = Date.now() / 1000;
  return (evs || []).filter(e => {
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
const haptic = (ms) => { try { navigator.vibrate && navigator.vibrate(ms); } catch (e) {} };
// 触摸互斥: 一次触摸只属于一个手势(分页/滑动露按钮/边缘返回)
const gesture = { claimed: null };
// 移动端把各分区装进 6 个 .pg 页容器; 桌面端恢复原始 DOM 顺序(display:contents 布局)。
// 记住初始顺序, 窗口跨过 768px 断点时来回重组不丢内容。
const PAGE_GROUPS = [
  ["#statuscard", ".mgrid4", "#alerts", "#hp-grid", "#sysbar", "#repos", "#chart-wrap", "#toolchips"],
  ["#logpage"],
  ["#goals"],
  ["#filters", "#tasks", "#svc-panel"],
  ["#agents-page"],
  ["#toolspage"],
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
// --- 分页(概览/日志/Goal/模型/ツール) ---
const pages = $("pages");
const N_PAGES = 6;
const PAGE_W = 100 / N_PAGES;   // 轨道宽 600%, 每页位移 = 轨道的 1/6
var page = 0;   // var: 挂到 window, 便于外部调试/测试读取
function pageLabels() { return [t("tab_home"), t("tab_log"), t("tab_goal"), t("tab_svc"), t("tab_agent"), t("tab_tools")]; }
function applyPagesX(withTransition) {
  const tr = trackEl; // 移动端才有轨道
  if (!tr) return;
  // 轨道宽 600%: 每页位移 = 轨道的 1/6
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
  applyPagesX(true);
  document.querySelectorAll("#tabbar .tab").forEach(b => b.classList.toggle("active", +b.dataset.p === i));
  if (changed) activatePage(i);
  // 页面内容异步变化后(骨架→数据/折叠展开)重测高度
  requestAnimationFrame(() => applyPagesX(false));
}
function activatePage(i) {
  if (i === 1) { initLogPage(); renderLogTimeline(); }  // 日志页: agent 选择器 + 事件时间线
  if (i === 4) initAgentsPage();     // 模型页: 拉取 OMP/Codex 卡片
  if (i === 5) initToolsPage();      // ツール页: 惰性初始化(健康/文件/清理/速测/服务/任务)
  if (i === 3 && isMobile()) {       // 服务页: 骨架 → 渲染
    const tbody = $("svc").querySelector("tbody");
    if (!tbody.children.length) tbody.innerHTML = mobileSkel(4);
    applyFilter();
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
  const n = Date.now();
  if (!force && rtCache && n - rtT < 15000) return rtCache;
  rtCache = await tlGet("/api/runtimes");
  rtT = n;
  return rtCache;
}
const rtState = a => !a.installed ? "none" : a.procs > 0 ? "run" : "idle";
const rtHasQuota = a => !!(a.quota && a.quota.ok && a.quota.buckets && a.quota.buckets.length);
const rtHasTasks = a => a.installed && (a.task_count || 0) > 0;
function rtQuotaHtml(a) {
  const q = a.quota;
  if (!q) return "";
  if (!q.buckets || !q.buckets.length)
    return `<div class="rt-qnone">${t("rt_quotafail")}</div>`;
  return q.buckets.slice(0, 3).map(b => {
    const p = b.remaining_pct;
    if (p == null) return "";
    const cls = p >= 50 ? "green" : p >= 20 ? "warn" : "red";
    const dead = p <= 0;
    return `<div class="rt-q ${cls}">
      <div class="rt-q-top"><span>${escHtml(b.label)}</span><b>${p}%</b></div>
      <div class="rt-q-track"><i style="width:${Math.max(p, 1.5)}%"></i></div>
      ${b.reset ? `<div class="rt-q-sub">${dead ? t("rt_exhausted") : t("rt_reset")} ${escHtml(b.reset)}</div>` : ""}
    </div>`;
  }).join("");
}
function rtTasksHtml(a) {
  const rows = [];
  (a.tasks || []).forEach(x => {
    if (x.kind === "omp") rows.push(`<div class="rt-task" data-sid="${escAttr(x.id)}" data-cwd="${escAttr(x.cwd)}" data-tmux="${escAttr(x.tmux)}" role="button" tabindex="0">
      <span class="rt-dot2 ${x.health === "running" ? "run" : "warn"}"></span>
      <span class="rt-taskgoal">${escHtml(stripMd(x.goal || x.cwd).slice(0, 70))}</span>
      <span class="rt-taskmeta">${agoStr(x.idle_seconds)} · ${escHtml(x.tool)}</span></div>`);
    else if (x.kind === "grok") rows.push(`<div class="rt-task"><span class="rt-dot2 run"></span>
      <span class="rt-taskgoal">${escHtml(x.cwd)}</span><span class="rt-taskmeta">pid ${escHtml(String(x.pid))}</span></div>`);
    else if (x.kind === "file") rows.push(`<div class="rt-task"><span class="rt-dot2 dim"></span>
      <span class="rt-taskgoal">${escHtml(x.file)}</span><span class="rt-taskmeta">${agoStr(x.age_sec)}</span></div>`);
  });
  return rows.join("");
}
function rtCardHtml(a) {
  const meta = [];
  if (a.quota && a.quota.account) meta.push(escHtml(a.quota.account));
  if (a.quota && a.quota.plan) meta.push(escHtml(a.quota.plan));
  if (a.meta && a.meta.sessions_24h != null && a.meta.sessions_24h > 0) meta.push(t("rt_sess24", { n: a.meta.sessions_24h }));
  if (a.meta && a.meta.sessions_total != null) meta.push(t("rt_sessall", { n: a.meta.sessions_total }));
  let procs = "";
  if (a.procs > 0 && a.proc_list && a.proc_list[0]) {
    const p0 = a.proc_list[0];
    procs = `<div class="rt-procline"><b>${a.procs}</b> ${t("rt_procs")} · <b>${p0.cpu_pct}%</b> CPU · <b>${p0.mem_mb}</b> MB</div>`;
  }
  const tasks = rtTasksHtml(a);
  const quota = rtQuotaHtml(a);
  const btn = a.installable
    ? `<button class="rt-btn ghost danger" data-act="uninstall" data-id="${escAttr(a.id)}">${t("rt_uninstbtn")}</button>` : "";
  return `<div class="rt-card ${rtState(a)}">
    <div class="rt-head"><b>${escHtml(a.name)}</b><span class="rt-ver">${escHtml(a.version || "")}</span></div>
    ${meta.length ? `<div class="rt-sub">${meta.join(" · ")}</div>` : ""}
    ${procs}${quota}
    ${tasks ? `<div class="rt-tasks">${tasks}</div>` : ""}
    ${btn ? `<div class="rt-actions">${btn}</div>` : ""}
  </div>`;
}
function rtMatch(a, f) {
  const st = rtState(a);
  if (f === "run") return st === "run";
  if (f === "idle") return st === "idle";
  if (f === "tasks") return rtHasTasks(a);
  if (f === "quota") return a.installed && rtHasQuota(a);
  if (f === "none") return st === "none";
  return true;   // all
}
async function refreshAgentsPage() {
  const el = $("agents-page");
  if (!el || el.hidden) return;
  el.innerHTML = `<h2>${t("rt_title")}</h2>` + mobileSkelDiv(3);
  try { renderRuntimes(await loadRuntimes(true)); }
  catch (e) { el.innerHTML = esHtml("cpu", t("a_fail", { e: escHtml(e.message) })); }
}
function renderRuntimes(d) {
  const el = $("agents-page");
  if (!el || !d || !d.agents) return;
  if (!rtFilter) { try { rtFilter = localStorage.getItem("svc-rtf") || "all"; } catch (e) { rtFilter = "all"; } }
  const all = d.agents;
  const run = all.filter(a => rtState(a) === "run");
  const idle = all.filter(a => rtState(a) === "idle");
  const none = all.filter(a => rtState(a) === "none");
  const low = [];
  all.forEach(a => ((a.quota && a.quota.buckets) || []).forEach(b => {
    // 横幅只报即将耗尽(>0 且 <10%); 已耗尽(0%)卡片里红色可见, 不再重复横幅
    if (b.remaining_pct != null && b.remaining_pct > 0 && b.remaining_pct < 10) low.push(a.name);
  }));
  const counts = { all: all.length, run: run.length, tasks: all.filter(rtHasTasks).length,
    quota: all.filter(a => a.installed && rtHasQuota(a)).length, none: none.length };
  const FILTERS = [["all", "rt_f_all"], ["run", "rt_f_run"], ["tasks", "rt_f_tasks"],
    ["quota", "rt_f_quota"], ["none", "rt_f_none"]];
  const hist = ((d.ctl && d.ctl.history) || []).slice(-3).reverse();
  const secCards = (key, arr, cls) => {
    const list = arr.filter(a => rtMatch(a, rtFilter));
    if (!list.length) return "";
    return `<section class="rt-sec"><h3 class="rt-sechead"><span class="rt-sq ${cls}"></span>${t(key)} <em>${list.length}</em></h3>
      <div class="rt-grid">${list.map(rtCardHtml).join("")}</div></section>`;
  };
  const secNone = () => {
    const list = none.filter(a => rtMatch(a, rtFilter));
    if (!list.length) return "";
    return `<section class="rt-sec"><h3 class="rt-sechead"><span class="rt-sq none"></span>${t("rt_f_none")} <em>${list.length}</em></h3>
      <div class="rt-none-list">${list.map(a => `<div class="rt-none-row"><b>${escHtml(a.name)}</b>
        ${a.installable ? `<button class="rt-btn" data-act="install" data-id="${escAttr(a.id)}">${t("rt_instbtn")}</button>` : ""}</div>`).join("")}</div></section>`;
  };
  const any = all.some(a => rtMatch(a, rtFilter));
  el.innerHTML = `<h2>${t("rt_title")} <span class="ghint">${t("rt_summary", { i: d.total_installed, n: all.length, p: d.total_running })}</span></h2>` +
    `${low.length ? `<div class="rt-low">${t("rt_low", { n: [...new Set(low)].join(" / ") })}</div>` : ""}` +
    `${d.quota && d.quota.running ? `<div class="rt-qrefresh">${t("rt_refreshing")}</div>` : ""}` +
    `<div class="rt-toolbar"><div class="rt-filters">${FILTERS.map(([id, key]) =>
      `<button class="rt-f${rtFilter === id ? " on" : ""}" data-f="${id}">${t(key)}<em>${counts[id]}</em></button>`).join("")}</div>` +
    `<button class="rt-btn ghost" id="rt-quota-btn">${t("rt_refresh")}</button></div>` +
    (any ? secCards("rt_f_run", run, "run") + secCards("rt_sec_idle", idle, "idle") + secNone()
      : `<div class="rt-empty">${t("rt_empty")}</div>`) +
    rtModelsSection(d) +
    `${hist.length ? `<div class="rt-hist">${hist.map(h =>
      `<div>${escHtml(h.t || "")} ${escHtml(h.agent)} ${escHtml(h.action)} ${h.ok ? "✓" : "✗"} ${escHtml(h.msg || "")}</div>`).join("")}</div>` : ""}`;
  el.querySelectorAll(".rt-f").forEach(b => b.addEventListener("click", () => {
    if (rtFilter === b.dataset.f) return;
    rtFilter = b.dataset.f;
    try { localStorage.setItem("svc-rtf", rtFilter); } catch (e) {}
    renderRuntimes(d);   // 纯前端过滤, 用缓存数据重渲染
  }));
  const qb = $("rt-quota-btn");
  if (qb) qb.addEventListener("click", async () => {
    qb.textContent = "…";
    await tlPost("/api/runtimes", { agent: "", action: "quota" });
    setTimeout(refreshAgentsPage, 800);
  });
  el.querySelectorAll(".rt-btn[data-act]").forEach(b => b.addEventListener("click", async () => {
    const id = b.dataset.id, act = b.dataset.act;
    const a = d.agents.find(x => x.id === id) || {};
    const msg = act === "install" ? t("rt_ask_inst", { n: a.name }) : t("rt_ask_uninst", { n: a.name });
    if (!(await uiConfirm(msg))) return;
    b.textContent = "…"; b.disabled = true;
    try {
      const r = await tlPost("/api/runtimes", { agent: id, action: act });
      if (r && !r.ok && r.msg) uiNotice(r.msg);
    } catch (e) { uiNotice(e.message); }
    rtPollCtl();
  }));
  // omp 任务行 → 跳日志页并选中该 agent(手机切页签, 桌面切分类)
  el.querySelectorAll(".rt-task[data-sid]").forEach(c =>
    c.addEventListener("click", async () => {
      await initLogPage();
      const sel = $("logagent-sel");
      const opt = sel && [...sel.options].find(o => o.value === c.dataset.sid && o.dataset.cwd === c.dataset.cwd);
      if (opt) { sel.value = opt.value; loadLogView(); }
      if (isMobile()) setPage(1);
      else { setCat("log"); scrollTo(0, 0); }
    }));
  rtBindModels(el, d);
  if ((d.models && d.models.providers || []).some(p => p.models.some(m => m.test && m.test.status === "running"))) rtPollModels();
  if (d.ctl && d.ctl.running) rtPollCtl();
  else if (d.quota && d.quota.running && !rtTimer) rtPollQuota();
}
function rtModelTestHtml(m) {
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
  return `<section class="rt-sec"><h3 class="rt-sechead"><span class="rt-sq model"></span>${t("rt_m_title")} <em>${provs.length}</em></h3>
    <div class="rt-mhint">${t("rt_m_hint")}</div>
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
  if (rtModelTimer) return;
  rtModelTimer = setInterval(async () => {
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
  el.innerHTML = `<h2>${t("rt_title")}</h2>` + mobileSkelDiv(3);
  try { renderRuntimes(await loadRuntimes()); }
  catch (e) { el.innerHTML = esHtml("cpu", t("a_fail", { e: escHtml(e.message) })); }
}

// --- Goal 详情: 状态 + watchdog 配置 + tmux 画面 + JSONL 活动 + watchdog 事件 ---
function goalDetailHtml(d) {
  const esc = escHtml;
  const g = d.goal || {}, w = d.watchdog || {}, p = d.pane || {};
  const kv = (k, v) => `<span class="k">${esc(k)}</span><span class="v">${esc(v || "—")}</span>`;
  const activity = (d.activities || []).map(x => `<div class="g-detail-event"><span class="kind">${esc(x.kind)}</span>${esc(x.text)}</div>`).join("");
  const events = (d.events || []).map(x => `<div class="g-detail-event"><span class="time">${esc(x.time || "")}</span><span class="kind">${esc(x.kind || "event")}</span>${esc(x.text || "")}</div>`).join("");
  const capture = (d.capture || []).join("\n");
  return `<div class="g-detail-body">
    <section class="g-detail-section"><h3>${t("g_status_detail")}</h3><div class="g-detail-kv">` +
      kv(t("g_field_status"), g.light) + kv(t("g_field_idle"), g.idle_sec == null ? "—" : t("g_seconds", { n: g.idle_sec })) +
      kv("Context", g.ctx_raw) + kv("Retry", g.retry) + kv("进度", (g.progress || []).join("\n")) + `</div></section>` +
    `<section class="g-detail-section"><h3>${t("g_runtime_detail")}</h3><div class="g-detail-kv">` +
      kv("Goal ID", g.gid || w.gid) + kv("Session", w.session) + kv("PID / Pane", `${p.pid || "—"} / ${p.pane || "—"}`) + kv("工作目录", w.workdir) + kv("JSONL", w.jsonl) + `</div></section>` +
    (capture ? `<section class="g-detail-section"><h3>${t("g_terminal_detail")}</h3><pre class="g-detail-log">${esc(capture)}</pre></section>` : "") +
    `<section class="g-detail-section"><h3>${t("g_activity_detail")} (${(d.activities || []).length})</h3><div class="g-detail-events">${activity || `<div>${t("g_no_activity")}</div>`}</div></section>` +
    `<section class="g-detail-section"><h3>${t("g_watchdog_detail")} (${(d.events || []).length})</h3><div class="g-detail-events">${events || `<div>${t("g_no_activity")}</div>`}</div></section>
  </div>`;
}
async function openGoalDetail(btn) {
  const modal = $("ui-modal"), title = $("ui-dialog-title"), msg = $("ui-dialog-msg"), ok = $("ui-ok"), cancel = $("ui-cancel");
  if (!modal || !title || !msg || !cancel) return;
  title.innerHTML = icon("doc", 17) + " <span>" + t("g_view_detail") + "</span>";
  msg.innerHTML = `<div class="g-detail-body">${t("a_loading")}</div>`;
  if (ok) ok.hidden = true;
  cancel.textContent = t("m_close"); modal.hidden = false; document.body.classList.add("modal-open");
  const close = () => { modal.hidden = true; document.body.classList.remove("modal-open"); if (ok) ok.hidden = false; cancel.textContent = t("m_cancel"); cancel.removeEventListener("click", close); modal.removeEventListener("click", outside); document.removeEventListener("keydown", key); };
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
    if (stat.dataset.k === "load") { setPage(2); haptic(10); }
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
  try { return JSON.parse(localStorage.getItem("svc-chart") || "[]"); }
  catch (e) { return []; }
}
function chartSave(arr) { try { localStorage.setItem("svc-chart", JSON.stringify(arr)); } catch (e) {} }
function chartSample(s) {
  if (!chart || !isMobile()) return;
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
  if (!chart || !isMobile()) return;
  const ctx = chart.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = chart.clientWidth || 360, h = 150;
  if (chart.width !== w * dpr) { chart.width = w * dpr; chart.height = h * dpr; }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const all = chartData();
  $("chart-empty").style.display = all.length < 2 ? "" : "none";
  $("chart-win").textContent = all.length >= 2 ? t("chart_win", { n: chartWin }) : "";
  if (all.length < 2) return;
  const data = all.slice(-chartWin);
  const maxL = Math.max(2, ...data.map(d => d.load || 0));
  const X = i => 6 + i * ((w - 12) / (data.length - 1));
  // 主题色从 CSS 变量读取(getComputedStyle), 明暗主题切换即跟随
  const cs = getComputedStyle(document.documentElement);
  const cssVar = (n) => cs.getPropertyValue(n).trim();
  const CH = { cpu: cssVar("--ch-cpu"), load: cssVar("--ch-load"),
               mem: cssVar("--ch-mem"), swap: cssVar("--ch-swap"), grid: cssVar("--ch-grid") };
  // 网格线
  ctx.strokeStyle = CH.grid; ctx.lineWidth = 1;
  [0.25, 0.5, 0.75].forEach(f => { ctx.beginPath(); ctx.moveTo(0, h * f); ctx.lineTo(w, h * f); ctx.stroke(); });
  // CPU %: 0-100 映射
  ctx.strokeStyle = CH.cpu; ctx.lineWidth = 1.6; ctx.beginPath();
  data.forEach((d, i) => { const y = h - 6 - (d.cpu || 0) / 100 * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // 内存 %: 0-100 映射(橙)
  ctx.strokeStyle = CH.mem; ctx.lineWidth = 1.6; ctx.beginPath();
  data.forEach((d, i) => { if (d.mem == null) return; const y = h - 6 - (d.mem || 0) / 100 * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // Swap %: 0-100 映射(紫; 无 swap 或 0% 时贴底直线,仍显示以便观察趋势)
  ctx.strokeStyle = CH.swap; ctx.lineWidth = 1.6; ctx.beginPath();
  data.forEach((d, i) => { const y = h - 6 - (d.swap || 0) / 100 * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // 负载: 按各自 max 缩放
  ctx.strokeStyle = CH.load; ctx.lineWidth = 1.8; ctx.beginPath();
  data.forEach((d, i) => { const y = h - 6 - (d.load || 0) / maxL * (h - 18); i ? ctx.lineTo(X(i), y) : ctx.moveTo(X(i), y); });
  ctx.stroke();
  // 图例(左上 CPU/mem/swap, 右上 load; 颜色同线)
  ctx.font = "10px ui-monospace, monospace";
  ctx.fillStyle = CH.cpu; ctx.fillText("CPU " + Math.round(data[data.length-1].cpu || 0) + "%", 8, 12);
  ctx.fillStyle = CH.mem; ctx.fillText("mem " + Math.round(data[data.length-1].mem || 0) + "%", 8, 26);
  ctx.fillStyle = CH.swap; ctx.fillText("swap " + Math.round(data[data.length-1].swap || 0) + "%", 8, 40);
  ctx.fillStyle = CH.load; ctx.textAlign = "right"; ctx.fillText("load " + maxL.toFixed(1), w - 8, 12); ctx.textAlign = "left";
}
if (chart) {
  window.addEventListener("resize", drawChart);
  mqMobile.addEventListener("change", drawChart);
  drawChart();
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
    if (autoOn && !autoLocked) load(false); // 回前台立即刷一次(锁定时不刷)
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
  if (autoOn && !autoLocked && !document.hidden) {  // 长按锁定时 30s 自动刷新完全停止
    console.log("[svc-dashboard] auto refresh tick");
    if (filter === "manage") loadManage();
    else load(false);
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
// ツール页: 健康检查 / 文件浏览 / 垃圾清理 / 网络速测 / 用户服务 / 计划任务
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
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body), cache: "no-store" });
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
    `<b>${dk.percent}%</b> · ${fmtB(dk.free)} ${t("tl_fs_dl") === "下载" ? "可用" : "free"}`));
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
  grid.innerHTML =
    (ts ? `<span class="gcopy" data-copy="ssh ${user}@${ts}" role="button" tabindex="0" title="ssh ${escAttr(user + '@' + ts)}"><b>${escHtml(ts)}</b></span>` : "") +
    (lan ? `<span class="gcopy" data-copy="${escAttr(lan)}" role="button" tabindex="0" title="LAN ${escAttr(lan)}"><b>${escHtml(lan)}</b></span>` : "");
}

// --- F1 文件浏览: 独立全屏页(home 起点), 移动单栏 / 桌面≥1024 双栏 ---
const FS_HOME = TL_CONF.fs_home || "/home/tetsuya";
const fsState = { cwd: null, parent: null, name: "", entries: [], err: "",
  sort: localStorage.getItem("svc-fs-sort") || "name",
  hidden: localStorage.getItem("svc-fs-hidden") === "1",
  seq: 0 };
const FS_SORTS = [["name", "fs_sort_name"], ["time", "fs_sort_time"],
                  ["size", "fs_sort_size"], ["type", "fs_sort_type"]];
const FS_ICONS = [["dir", "folder", "fs-ico-dir"], ["img", "img", "fs-ico-img"],
  ["zip", "zip", "fs-ico-zip"], ["code", "code", "fs-ico-code"],
  ["txt", "doc", "fs-ico-txt"], ["bin", "file", "fs-ico-bin"]];

function fsExt(name) { const i = name.lastIndexOf("."); return i > 0 ? name.slice(i + 1).toLowerCase() : ""; }
function fsKind(e) {
  if (e.type === "dir") return "dir";
  const ext = fsExt(e.name);
  if (["png", "jpg", "jpeg", "webp", "gif", "bmp", "svg", "ico"].includes(ext)) return "img";
  if (["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "zst"].includes(ext)) return "zip";
  if (["py", "js", "ts", "cs", "rs", "go", "c", "h", "cpp", "java", "sh", "css", "html", "htm", "xml", "sql", "lua", "rb", "php"].includes(ext)) return "code";
  return "txt";
}

function fsRelTime(ts) {
  const d = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (d < 50) return t("fs_rel_now");
  if (d < 3600) return t("fs_rel_m", { n: Math.round(d / 60) });
  if (d < 86400) return t("fs_rel_h", { n: Math.round(d / 3600) });
  if (d < 172800) return t("fs_rel_y");
  const dt = new Date(ts * 1000);
  const sameYear = dt.getFullYear() === new Date().getFullYear();
  const opt = { month: "short", day: "numeric" };
  if (!sameYear) opt.year = "numeric";
  return dt.toLocaleDateString(LANG === "zh" ? "zh-CN" : LANG === "ja" ? "ja-JP" : "en-US", opt);
}

function fsCrumbsHtml(path) {
  const parts = path.split("/").filter(Boolean);
  let h = `<a data-crumb='/'><svg width='13' height='13' viewBox='0 0 16 16' fill='none' stroke='currentColor' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round">`
    + (ICONS["home"] || "") + `</svg></a>`;
  let acc = "";
  parts.forEach((p, i) => {
    acc += "/" + p;
    h += `<span class='csep'>/</span>`;
    h += i === parts.length - 1 ? `<span class='cur'>${escHtml(p)}</span>`
                                : `<a data-crumb='${escAttr(acc)}'>${escHtml(p)}</a>`;
  });
  return h;
}

function fsApplySort(list) {
  const s = fsState.sort;
  const key = { name: e => e.name.toLowerCase(), time: e => e.mtime,
                size: e => (e.size == null ? -1 : e.size), type: e => fsKind(e) + e.name.toLowerCase() }[s];
  return [...list].sort((a, b) => (a.type === b.type ? 0 : a.type === "dir" ? -1 : 1)
    || (s === "time" || s === "size" ? key(b) - key(a) : (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0)));
}

function fsRender() {
  const list = $("fs-list");
  const q = ($("fs-filter").value || "").trim().toLowerCase();
  $("fs-dirname").textContent = fsState.name || FS_HOME;
  $("fs-crumbs").innerHTML = fsCrumbsHtml(fsState.cwd || FS_HOME);
  $("fs-crumbs").parentElement.scrollLeft = 1e4;
  const rows = fsApplySort(fsState.entries)
    .filter(e => (fsState.hidden || !e.name.startsWith(".")) && (!q || e.name.toLowerCase().includes(q)));
  const html = rows.map(e => {
    const kind = fsKind(e), ico = FS_ICONS.find(x => x[0] === kind);
    const sub = e.type === "dir"
      ? `${e.count != null ? t("fs_items", { n: e.count }) : "—"}</span>`
      : `${fmtB(e.size)}</span>`;
    const acts = `<span class='fs-acts'>` +
      `<span class='fs-hact' data-ha='copy' role='button' tabindex='0' title='${t("fs_copy_path")}' aria-label='${t("fs_copy_path")}'>${icon("copy", 15)}</span>` +
      (e.type === "dir" ? "" :
        `<span class='fs-hact' data-ha='dl' role='button' tabindex='0' title='${t("tl_fs_dl")}' aria-label='${t("tl_fs_dl")}'>${icon("down", 15)}</span>`) +
      `</span>`;
    return `<div class='fs-row' data-kind='${kind}' data-type='${e.type}' data-name='${escAttr(e.name)}'>` +
      `<span class='fs-fico ${ico[2]}'>${icon(ico[1], 19)}</span>` +
      `<span class='fs-main'><span class='fs-nm'>${escHtml(e.name)}</span>` +
      `<span class='fs-meta'><span>${sub}<span class='dot'> · </span>${fsRelTime(e.mtime)}</span></span></span>` +
      acts +
      (e.type === "dir" ? `<span class='fs-earr' style='color:var(--text-dead)'>${icon("chev", 15)}</span>` : "") +
      `</div>`;
  }).join("");
  list.innerHTML = html
    || (fsState.err ? `<div class='fs-errcard'>${icon("err", 16)}<span>${escHtml(fsState.err)}</span>` +
        `<span class='btn fs-retry' role='button' tabindex='0'>${t("fs_retry")}</span></div>`
       : `<div class='fs-note'>${icon("folder", 44)}<span>${q ? t("tl_fs_empty") : t("fs_empty_dir")}</span></div>`);
}

async function fsOpen(path, dir) {
  const seq = ++fsState.seq;
  if (fsState.cwd) {
    const list = $("fs-list");
    list.classList.remove("push", "pop");
    void list.offsetWidth;
    list.classList.add(dir === "up" ? "pop" : "push");
  }
  $("fs-list").innerHTML = Array.from({ length: 7 }, () =>
    "<div class='fs-skrow'><div class='skel-line' style='width:70%'></div><div class='skel-line' style='width:42%;margin-bottom:0'></div></div>").join("");
  try {
    const d = await tlGet("/api/fs/list?path=" + encodeURIComponent(path));
    if (seq !== fsState.seq) return;
    fsState.cwd = d.path; fsState.parent = d.parent || null; fsState.name = d.name;
    fsState.entries = d.entries || []; fsState.err = "";
  } catch (e) {
    if (seq !== fsState.seq) return;
    fsState.err = e.message || String(e);
    if (!fsState.cwd) fsState.cwd = FS_HOME;
  }
  fsRender();
}

function fsFileUrl(path, mode, enc) {
  let u = "/api/fs/file?path=" + encodeURIComponent(path) + "&mode=" + mode;
  if (enc) u += "&enc=" + enc;
  return u;
}

function fsOpenFile(name) {
  const path = (fsState.cwd || FS_HOME) + "/" + name;
  const kind = fsKind({ name, type: "file" });
  haptic(8);
  if (kind === "img") {          // 图片: 复用现有 lightbox
    $("tl-lightbox-img").src = fsFileUrl(path, "view");
    $("tl-lightbox").hidden = false;
    return;
  }
  fsvOpen(path, name);           // 其余全部走文本预览(含二进制提示)
}

function fsPopupMenu(items, anchor) {
  fsCloseMenu();
  const m = document.createElement("div");
  m.className = "fs-menu"; m.id = "fs-menu";
  m.innerHTML = items.map((x, i) => x === "-" ? "<hr>"
    : `<div class='mi ${x.on ? "on" : ""}' data-mi='${i}' role='button' tabindex='0'>${x.ico ? icon(x.ico, 15) : ""}` +
      `<span>${escHtml(x.label)}</span><span class='chk'>${icon("ok", 14)}</span></div>`).join("");
  document.body.appendChild(m);
  const r = anchor.getBoundingClientRect();
  m.style.top = Math.min(r.bottom + 6, innerHeight - m.offsetHeight - 10) + "px";
  m.style.left = Math.max(8, Math.min(r.left, innerWidth - m.offsetWidth - 8)) + "px";
  m.addEventListener("click", (e) => {
    const mi = e.target.closest("[data-mi]");
    if (mi) { fsCloseMenu(); items[+mi.dataset.mi].act(); }
  });
}
function fsCloseMenu() { const m = $("fs-menu"); if (m) m.remove(); }

function fsOpenBrowser() {
  $("fs-app").hidden = false;
  document.documentElement.classList.add("fs-noscroll");
  if (!fsState.cwd) fsOpen(FS_HOME);
  else fsRender();
}
function fsCloseBrowser() {
  $("fs-app").hidden = true; $("fs-view").hidden = true;
  document.documentElement.classList.remove("fs-noscroll");
}

// --- F1b 文本预览: 语法高亮(自写零依赖)/行号/搜索/换行/字号/GB18030 重开 ---
const fsvState = { path: null, name: "", enc: "utf-8", altEnc: null, data: null,
  wrap: localStorage.getItem("svc-fsv-wrap") !== "0",
  lineNo: localStorage.getItem("svc-fsv-num") !== "0",
  font: clampFont(+(localStorage.getItem("svc-fsv-font") || 13)),
  lines: [], marks: [], cur: 0 };
function clampFont(px) { return Math.max(10, Math.min(22, px)); }

/* 轻量高亮: 输入必须是 escHtml 后的文本(已无 < > &), 只产出 <span class=tk-*>。
   够用即可: json/yaml/toml 值色, md 结构色, 代码类 关键字/字符串/注释 三色。 */
const FSV_MD_HEAD = /^#{1,6} .*$|^={3,}$|^-{3,}$/;
function hlLine(line, lang) {
  let out = line;
  const wrap = (re, cls) => { out = out.replace(re, (m) => `\u0001${cls}\u0002${m}\u0003`); };
  if (lang === "md") {
    if (FSV_MD_HEAD.test(line)) wrap(/^.*$/, "h");
    else {
      wrap(/`[^`]+`/g, "s");
      wrap(/\*\*[^*]+\*\*/g, "b");
      wrap(/\[[^\]]*\]\([^)]*\)/g, "l");
      wrap(/^ *([-*+]|\d+\.) /, "p");
    }
  } else if (lang === "json") {
    if (!line.startsWith("//")) {
      wrap(/"(?:[^"\\]|\\)*"(?= *:)/g, "k");
      wrap(/"(?:[^"\\]|\\)*"/g, "s");
      wrap(/\b(?:true|false|null)\b/g, "k");
      wrap(/-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g, "n");
    }
  } else if (lang === "yaml" || lang === "toml" || lang === "ini") {
    wrap(/^[^:=#]+?(?= *[:=])/g, "k");
    wrap(/(["']).*?\1/g, "s");
    wrap(/\b\d+(?:\.\d+)?\b/g, "n");
  } else if (lang === "code") {
    wrap(/(#.*$|\/\/.*$)/g, "c");
    wrap(/(["']).*?(?:\1|$)/g, "s");
    wrap(/\b(0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\b/g, "n");
    wrap(/\b(?:def|class|return|if|elif|else|for|while|in|not|and|or|is|None|True|False|import|from|as|with|try|except|finally|raise|lambda|yield|pass|break|continue|global|async|await|const|let|var|function|new|typeof|instanceof|this|self|super|static|public|private|protected|void|int|float|double|string|bool|char|struct|enum|match|fn|impl|trait|pub|mut|use|where|select|insert|update|delete|create|table|case|switch|do|throw|catch|namespace|using|template|virtual|override)\b/g, "k");
  } else if (lang === "log") {
    wrap(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b/g, "n");
    wrap(/\b(?:ERROR|FATAL|WARN|WARNING)\b/g, "k");
  }
  out = out.replace(/\u0001([A-Za-z0-9_-]+)\u0002((?:[^\u0001\u0003])*)\u0003/g,
    (m0, cls, body) => `<span class='tk-${cls}'>${body}</span>`);
  return out;
}
function hlLang(name, kind) {
  if (kind === "img") return "";
  const ext = fsExt(name);
  if (ext === "md" || ext === "markdown") return "md";
  if (ext === "json") return "json";
  if (["yaml", "yml", "toml", "ini", "conf", "env", "properties"].includes(ext)) return ext === "yml" ? "yaml" : ext;
  if (kind === "code") return "code";
  if (ext === "log") return "log";
  return "plain";
}

const FSV_MAX_LINES = 5000;   // 行数上限: 超出提示截断(大文件保护第二道)
function fsvRender() {
  const d = fsvState.data;
  const body = $("fsv-body");
  $("fs-view").classList.toggle("wrap", fsvState.wrap);
  $("fs-view").classList.toggle("nonum", !fsvState.lineNo);
  $("fs-view").style.setProperty("--fsv-fs", fsvState.font + "px");
  $("fsv-t-wrap").classList.toggle("on", fsvState.wrap);
  $("fsv-t-num").classList.toggle("on", fsvState.lineNo);
  if (!d || d.binary) { body.innerHTML = ""; return; }
  const lang = hlLang(fsvState.name, fsKind({ name: fsvState.name, type: "file" }));
  const lines = fsvState.lines;
  const capped = lines.length > FSV_MAX_LINES;
  const shown = capped ? lines.slice(0, FSV_MAX_LINES) : lines;
  let h = "<pre class='fsv-code'>";
  for (let i = 0; i < shown.length; i++)
    h += `<div class='fsl' data-ln='${i}'><span class='fsln'>${i + 1}</span><span class='fst'>${hlLine(escHtml(shown[i]), lang) || ""}</span></div>`;
  h += "</pre>";
  if (capped) h += `<div class='fs-note' style='padding:18px'>${icon("warn", 20)}<span>${t("fsv_lines_cap", { n: FSV_MAX_LINES.toLocaleString() })}</span></div>`;
  body.innerHTML = h;
  body.scrollTop = 0;
}

function fsvBanner() {
  const d = fsvState.data, el = $("fsv-banner");
  if (!d || d.binary) { el.innerHTML = ""; return; }
  let h = "";
  if (d.truncated) h += `<div>${icon("warn", 14)}<span>${t("fsv_big")}</span>` +
    `<a class='btn' href='${fsFileUrl(fsvState.path, "download")}' download>${t("tl_fs_dl")}</a></div>`;
  if (fsvState.altEnc) h += `<div>${icon("warn", 14)}<span>${t("fsv_gb_hint")}</span>` +
    `<span class='btn' id='fsv-reenc' role='button' tabindex='0'>${t(fsvState.enc === "gb18030" ? "fsv_utf8" : "fsv_gb")}</span></div>`;
  el.innerHTML = h;
  const rb = $("fsv-reenc");
  if (rb) rb.addEventListener("click", () => fsvLoad(fsvState.path, fsvState.name, fsvState.enc === "gb18030" ? "" : fsvState.altEnc));
}

async function fsvLoad(path, name, enc) {
  $("fsv-name").textContent = name;
  $("fsv-sub").textContent = "…";
  $("fsv-banner").innerHTML = "";
  $("fsv-body").innerHTML = "<div class='fs-note'><div class='skel-line' style='width:60%'></div><div class='skel-line' style='width:80%'></div><div class='skel-line' style='width:48%'></div></div>";
  try {
    const d = await tlGet(fsFileUrl(path, "view", enc));
    fsvState.path = path; fsvState.name = name;
    fsvState.enc = d.encoding || "utf-8";
    fsvState.altEnc = d.alt_enc || null;
    fsvState.data = d;
    fsvState.lines = d.binary ? [] : (d.text || "").split("\n");
    fsvState.marks = []; fsvState.cur = 0;
    if (d.binary) {
      $("fsv-body").innerHTML = `<div class='fs-note'>${icon("box", 44)}<span>${t("fsv_binary")}</span>` +
        `<a class='btn' href='${fsFileUrl(path, "download")}' download>${icon("down", 13)} ${t("tl_fs_dl")}</a></div>`;
      $("fsv-sub").textContent = fmtB(d.size);
      $("fsv-status").innerHTML = `${fmtB(d.size)}<span class='dot'>·</span>${new Date(d.mtime * 1000).toLocaleString()}`;
    } else {
      fsvRender(); fsvBanner(); fsvStatus();
      fsvSearch(($("fsv-find").value || "").trim());
    }
  } catch (e) {
    $("fsv-body").innerHTML = `<div class='fs-errcard'>${icon("err", 16)}<span>${escHtml(e.message)}</span>` +
      `<a class='btn' href='${fsFileUrl(path, "download")}' download>${t("tl_fs_dl")}</a></div>`;
  }
}

function fsvStatus() {
  const d = fsvState.data;
  $("fsv-sub").textContent = `${fmtB(d.size)} · ${d.encoding || "?"}`;
  $("fsv-status").innerHTML =
    `${fsvState.lines.length.toLocaleString()} 行<span class='dot'>·</span>${fmtB(d.size)}` +
    `<span class='dot'>·</span>${escHtml(d.encoding || "?")}` +
    `${d.alt_enc ? ` <span class='btn' id='fsv-reenc2' role='button' tabindex='0' style='min-height:22px;padding:2px 8px;font-size:11px'>${t("fsv_gb")}</span>` : ""}` +
    `<span class='dot'>·</span>${new Date(d.mtime * 1000).toLocaleString()}`;
  const b = $("fsv-reenc2");
  if (b) b.addEventListener("click", () => fsvLoad(fsvState.path, fsvState.name, fsvState.altEnc));
}

function fsvOpen(path, name) {
  const v = $("fs-view");
  v.hidden = false;
  v.classList.remove("opening"); void v.offsetWidth; v.classList.add("opening");
  $("fsv-find").value = ""; $("fsv-count").textContent = "";
  fsvLoad(path, name, "");
}

function fsvClose() { $("fs-view").hidden = true; }

function fsvSearch(q, step) {
  const d = fsvState.data;
  if (!d || d.binary) return;
  const cnt = $("fsv-count");
  if (!q) {   // 清除高亮: 恢复原始高亮行
    cnt.textContent = "";
    fsvRender();
    return;
  }
  const ql = q.toLowerCase();
  if (!fsvState.marks.length || fsvState.lastQ !== q) {
    const lines = fsvState.lines, marks = [];
    for (let i = 0; i < lines.length; i++)
      if (lines[i].toLowerCase().includes(ql)) marks.push(i);
    fsvState.marks = marks; fsvState.lastQ = q; fsvState.cur = 0;
    const lang = hlLang(fsvState.name, fsKind({ name: fsvState.name, type: "file" }));
    const body = $("fsv-body");
    body.querySelectorAll(".fsl").forEach((el) => {
      const ln = +el.dataset.ln;
      if (fsvState.lines[ln].toLowerCase().includes(ql)) {
        const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
        el.querySelector(".fst").innerHTML = escHtml(fsvState.lines[ln]).replace(re, (m) => `<mark class='fsv-mark'>${m}</mark>`);
      } else if (el.querySelector(".fst").innerHTML.includes("fsv-mark")) {
        el.querySelector(".fst").innerHTML = hlLine(fsvState.lines[ln], lang) || "";
      }
    });
  }
  fsvState.cur = step ? (fsvState.cur + step + fsvState.marks.length) % fsvState.marks.length : 0;
  const ln = fsvState.marks[fsvState.cur];
  cnt.textContent = `${fsvState.cur + 1}/${fsvState.marks.length}`;
  const body2 = $("fsv-body");
  body2.querySelectorAll(".fsl.cur").forEach((e) => e.classList.remove("cur"));
  const row = body2.querySelector(`.fsl[data-ln='${ln}']`);
  if (row) { row.classList.add("cur"); row.scrollIntoView({ block: "center" }); }
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
      const def = x.safe === false;
      return `<div class='tl-cleanrow'>` +
        `<input type='checkbox' data-clean='${x.id}' ${def ? "" : "checked"}>` +
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
  const ids = [...document.querySelectorAll("input[data-clean]:checked")].map(x => x.dataset.clean);
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

// --- G4 计划任务一览(只读, 复用 /api/tasks 的 cron 枚举) ---
async function cronLoad() {
  const body = $("tl-cron-body");
  try {
    const d = await tlGet("/api/tasks?lang=" + encodeURIComponent(LANG));
    body.innerHTML = (d.tasks || []).length ? (d.tasks || []).map(x =>
      `<div class='tl-row'><span class='tl-dot off'></span>` +
      `<span class='tl-name'>${escHtml(x.name)}</span>` +
      `<span class='tl-val'>${escHtml(x.schedule)}</span></div>`).join("")
      : `<div class='gempty'>—</div>`;
  } catch (e) {
    body.innerHTML = `<div class='gempty t-red'>${icon("err", 13)} ${escHtml(e.message)}</div>`;
  }
}

// --- ツール页初始化(首次进入触发) ---
function initToolsPage() {
  $("toolspage").hidden = false;
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
    $("tl-health-run").addEventListener("click", runHealth);
    $("tl-clean-scan").addEventListener("click", cleanScan);
    $("tl-clean-exec").addEventListener("click", cleanExec);
    $("tl-net-run").addEventListener("click", netRun);
    $("tl-usvc-unlock").addEventListener("click", usvcUnlock);
    $("tl-usvc-showlock").addEventListener("click", () => {
      $("tl-usvc-showlock").hidden = true;
      $("tl-usvc-unlockwrap").hidden = false;
    });
    // 文件浏览独立页(惰性: 首次打开才请求)
    $("fs-entry").addEventListener("click", fsOpenBrowser);
    $("fs-back").addEventListener("click", () => { haptic(6); fsCloseBrowser(); });
    $("fs-home").addEventListener("click", () => { haptic(6); fsOpen(FS_HOME); });
    $("fs-filter").addEventListener("input", fsRender);
    $("fs-list").addEventListener("click", (e) => {
      const crumb = e.target.closest("[data-crumb]");
      if (crumb) { fsOpen(crumb.dataset.crumb, crumb.dataset.crumb === fsState.parent ? "up" : "down"); return; }
      const ha = e.target.closest("[data-ha]");
      if (ha) {   // 行内显式操作钮(复制/下载)
        const row = ha.closest(".fs-row");
        const path = fsState.cwd + "/" + row.dataset.name;
        if (ha.dataset.ha === "copy") copyText(path, ha);
        else location.href = fsFileUrl(path, "download");
        return;
      }
      const retry = e.target.closest(".fs-retry");
      if (retry) { fsOpen(fsState.cwd || FS_HOME); return; }
      const row = e.target.closest(".fs-row");
      if (!row) return;
      if (row.dataset.type === "dir") { haptic(6); fsOpen(fsState.cwd + "/" + row.dataset.name); }
      else fsOpenFile(row.dataset.name);
    });
    $("fs-crumbs").addEventListener("click", (e) => {
      const crumb = e.target.closest("[data-crumb]");
      if (crumb) { haptic(6); fsOpen(crumb.dataset.crumb, crumb.dataset.crumb === fsState.parent ? "up" : "down"); }
    });
    $("fs-sortbtn").addEventListener("click", (e) => {
      e.stopPropagation();   // 不冒泡: 防触发 document 级"菜单外点击收起"
      fsPopupMenu(FS_SORTS.map(([k, lbl]) => ({ label: t(lbl), on: fsState.sort === k, act: () => {
        fsState.sort = k; localStorage.setItem("svc-fs-sort", k); fsRender();
      } })), e.currentTarget);
    });
    $("fs-more").addEventListener("click", (e) => {
      e.stopPropagation();
      fsPopupMenu([
        { label: t("tl_fs_hidden"), ico: "folder", on: fsState.hidden, act: () => {
          fsState.hidden = !fsState.hidden;
          fsRender();
        } },
        "-",
        { label: t("fs_home_btn"), ico: "home", act: () => fsOpen(FS_HOME) },
      ], e.currentTarget);
    });
    // 文本预览
    $("fsv-back").addEventListener("click", () => { haptic(6); fsvClose(); });
    $("fsv-t-wrap").addEventListener("click", () => {
      fsvState.wrap = !fsvState.wrap;
      localStorage.setItem("svc-fsv-wrap", fsvState.wrap ? "1" : "0");
      fsvRender(); fsvSearch(($("fsv-find").value || "").trim());
    });
    $("fsv-t-num").addEventListener("click", () => {
      fsvState.lineNo = !fsvState.lineNo;
      localStorage.setItem("svc-fsv-num", fsvState.lineNo ? "1" : "0");
      fsvRender(); fsvSearch(($("fsv-find").value || "").trim());
    });
    $("fsv-t-minus").addEventListener("click", () => {
      fsvState.font = clampFont(fsvState.font - 1);
      localStorage.setItem("svc-fsv-font", fsvState.font); fsvRender();
    });
    $("fsv-t-plus").addEventListener("click", () => {
      fsvState.font = clampFont(fsvState.font + 1);
      localStorage.setItem("svc-fsv-font", fsvState.font); fsvRender();
    });
    let fsvSearchTimer = null;
    $("fsv-find").addEventListener("input", (e) => {
      clearTimeout(fsvSearchTimer);
      fsvSearchTimer = setTimeout(() => fsvSearch(e.target.value.trim()), 220);
    });
    $("fsv-find").addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); fsvSearch(e.target.value.trim(), e.shiftKey ? -1 : 1); }
    });
    $("fsv-prev").addEventListener("click", () => fsvSearch(($("fsv-find").value || "").trim(), -1));
    $("fsv-next").addEventListener("click", () => fsvSearch(($("fsv-find").value || "").trim(), 1));
    $("fsv-more").addEventListener("click", (e) => {
      e.stopPropagation();
      fsPopupMenu([
        { label: t("fsv_copy_all"), ico: "copy", act: () => copyText(fsvState.data.text || "", e.currentTarget) },
        { label: t("fs_copy_path"), ico: "copy", act: () => copyText(fsvState.path || "", e.currentTarget) },
        "-",
        { label: t("fsv_copy_url"), ico: "ext", act: () => copyText(location.origin + fsFileUrl(fsvState.path, "view"), e.currentTarget) },
        { label: t("tl_fs_dl"), ico: "down", act: () => { location.href = fsFileUrl(fsvState.path, "download"); } },
      ], e.currentTarget);
    });
    // 全局: 菜单外点收起 / Esc 层级退出 / lightbox 复用
    document.addEventListener("click", (e) => { if (!e.target.closest(".fs-menu")) fsCloseMenu(); });
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if ($("fs-menu")) { fsCloseMenu(); return; }
      if (!$("tl-lightbox").hidden) { $("tl-lightbox").hidden = true; return; }
      if (!$("traj-view").hidden) { closeTraj(); return; }
      if (!$("fs-view").hidden) { fsvClose(); return; }
      if (!$("fs-app").hidden) fsCloseBrowser();
    });
    $("tl-lightbox").addEventListener("click", () => { $("tl-lightbox").hidden = true; });
  }
}

// --- 桌面端分类条(右上角 #catbar): 过滤 #pages 各分区; 移动端隐藏(底部页签), 断点切换时清过滤 ---
const CATS = [   // [id, i18n key]; 顺序 = 展示顺序, 与移动端 6 页签一致 ("全部"已删: 无信息架构,首页即导航面板)
  ["home", "tab_home"], ["log", "tab_log"], ["goal", "tab_goal"],
  ["svc", "tab_svc"], ["agent", "tab_agent"], ["tools", "tab_tools"],
];
const CAT_SELS = {   // 桌面可见分区 → 分类(与移动端 PAGE_GROUPS 一一对应)
  home: ["#hp-grid", "#sysbar", "#repos", "#chart-wrap", "#toolchips"],
  log: ["#logpage"],
  goal: ["#goals"],
  svc: ["#filters", "#tasks", "#svc-panel"],
  agent: ["#agents-page"],
  tools: ["#toolspage"],
};
var curCat = "all";
function setCat(c, save) {
  curCat = c;
  document.querySelectorAll("#catbar .cat").forEach(b => b.classList.toggle("active", b.dataset.cat === c));
  const keep = new Set((CAT_SELS[c] || []).map(s => document.querySelector(s)).filter(Boolean));
  document.querySelectorAll("#pages > *").forEach(el => el.classList.toggle("cat-off", !keep.has(el)));
  // 日志/agent 页桌面首入: 解除 hidden + 惰性初始化(与移动端 activatePage 同一套函数)
  if (c === "log") { const lp = $("logpage"); if (lp) lp.hidden = false; initLogPage(); renderLogTimeline(); }
  if (c === "agent") { const ap = $("agents-page"); if (ap) ap.hidden = false; initAgentsPage(); }
  if (save !== false) {
    try { localStorage.setItem("svc-cat", c); } catch (e) {}
    try {                                   // URL hash 同步: #cat=goal 可直达分类
      const u = new URL(location.href);
      if (c === "home") u.hash = ""; else u.hash = "cat=" + c;
      history.replaceState(null, "", u);
    } catch (e) {}
  }
}
function catFromHash() {
  const m = location.hash.match(/^#cat=([a-z]+)/);
  let c = m && CATS.some(x => x[0] === m[1]) ? m[1] : null;
  if (c === "all") c = "home";   // 旧链接兼容
  return c;
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
  initToolsPage();   // 桌面无页签: 工具面板直接展开在页面流里(内部会解除 hidden)
  // 日志/agent 页不再硬锁 hidden: 初始由 HTML hidden 属性遮蔽, 首次 setCat 进入时解除
  let savedCat = catFromHash();
  if (!savedCat) { try { savedCat = localStorage.getItem("svc-cat"); } catch (e) {} }
  if (savedCat === "all") savedCat = "home";
  setCat(CATS.some(c => c[0] === savedCat) ? savedCat : "home", false);  // URL 优先，随后本地恢复
}
initLogAgentPicker();   // 延后到这里: escHtml 等 const 已初始化(避免 TDZ 崩整页)
load(true);
renderConnbar();   // 顶栏连接信息(ssh/IP)随首屏渲染, 不等进工具页
hydrateFragments();
