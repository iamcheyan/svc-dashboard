// Settings › Observability's code (the otel plugin's page): run after app.js,
// whose helpers it shares (el, segs, input, savePrefs), and before start.js
// draws Settings. The connection is either any OTLP collector, set by its
// address and headers, or Langfuse, set by what only the user knows: where it
// is and the project's two keys. Langfuse's address, its Basic sign-in and
// its ingestion header are made from those, into the same endpoint and
// headers settings, so the secret is kept where it always was.

const LANGFUSE_PATH = "/api/public/otel";
const LANGFUSE_HOSTS = [["https://cloud.langfuse.com", "Cloud EU"], ["https://us.cloud.langfuse.com", "Cloud US"]];
// otelKind is the user's pick while the page is open ("otlp" or "langfuse"),
// null for what the saved endpoint says; lfDraft holds keys typed but not yet
// saved, so a redraw doesn't drop them
let otelKind = null, lfDraft = null;
// the rows whose control takes a line of its own under their words
const OTEL_STACKED = ["otelEndpointRow", "otelHeadersRow", "otelBodiesRow", "otelLangfuseHostRow", "otelLangfuseKeysRow"];

// langfuseOf: the host and keys a saved config has, or null for an endpoint
// that isn't Langfuse's OTLP one
function langfuseOf(config) {
  const endpoint = (config.endpoint || "").replace(/\/+$/, "");
  if (!endpoint.endsWith(LANGFUSE_PATH)) return null;
  let pk = "", sk = "";
  const auth = Object.entries(config.headers || {}).find(([k]) => k.toLowerCase() === "authorization")?.[1] || "";
  const basic = /^Basic\s+(\S+)$/i.exec(auth.trim());
  if (basic) {
    try {
      const pair = atob(basic[1]), i = pair.indexOf(":");
      if (i > 0) { pk = pair.slice(0, i); sk = pair.slice(i + 1); }
    } catch {}
  }
  return { host: endpoint.slice(0, -LANGFUSE_PATH.length), pk, sk };
}

// langfuseHost: a typed host as a base URL (scheme added, Langfuse's OTLP
// path taken off if pasted), "" for one that isn't an http(s) address
function langfuseHost(v) {
  let h = v.trim().replace(/\/+$/, "");
  if (h.endsWith(LANGFUSE_PATH)) h = h.slice(0, -LANGFUSE_PATH.length);
  if (h && !/^[a-z][a-z0-9+.-]*:\/\//i.test(h)) h = "https://" + h;
  try {
    const u = new URL(h);
    return /^https?:$/.test(u.protocol) && u.hostname && !u.search && !u.hash && !u.username ? h : "";
  } catch { return ""; }
}

function renderOTel(s, keep) {
  const page = $("#otelList");
  page.replaceChildren();
  let config = { ...(s.otel || {}) };
  const saved = langfuseOf(config);
  const kind = otelKind || (saved ? "langfuse" : "otlp");
  // a heading over a card of its own, as on every other Settings tab
  let box;
  const section = (name) => {
    const head = el("div", "row-head");
    head.append(el("span", "label", t(name)));
    box = el("div", "list prefs");
    page.append(head, box);
  };
  const row = (id, name, sub, control) => {
    const r = el("div", "row pref");
    r.id = id;
    const who = el("div", "who");
    who.append(el("div", "name", t(name)), el("div", "sub", sub));
    const val = el("div", "val");
    val.append(control);
    r.append(who, val);
    if (OTEL_STACKED.includes(id)) r.classList.add("otel-stacked");
    box.append(r);
    return r;
  };
  const save = (change) => {
    otelKind = kind; // what the user is editing stays on screen as they save
    config = { ...config, ...change };
    savePrefs({ ...keep, otel: { ...config } });
  };
  const field = (value, placeholder, type, label) => {
    const f = input(value, placeholder, type);
    f.className = "words";
    f.setAttribute("aria-label", t(label));
    f.autocomplete = "off";
    f.onkeydown = (e) => { e.stopPropagation(); if (e.key === "Enter") f.blur(); };
    return f;
  };
  section("Collector connection");
  row("otelExportRow", "OTLP export", t("Send traces to your collector. Choose what to include below; account credentials stay local"),
    segs([["off", t("Off")], ["on", t("On")]], config.enabled ? "on" : "off", (v) => save({ enabled: v === "on" })));
  row("otelKindRow", "Collector", t("Langfuse needs only its host and your project's keys; any other OTLP/HTTP collector takes its address and headers"),
    segs([["otlp", "OTLP"], ["langfuse", "Langfuse"]], kind, (v) => { otelKind = v; renderOTel(s, keep); }));
  if (kind === "langfuse") renderLangfuse(saved, config, save, row, field);
  else {
    const endpoint = field(config.endpoint || "", "http://localhost:4318", "url", "OTLP endpoint");
    endpoint.onchange = () => save({ endpoint: endpoint.value.trim().replace(/\/+$/, "") });
    row("otelEndpointRow", "OTLP endpoint", t("Base URL of your collector, or Langfuse's /api/public/otel endpoint"), endpoint);
    const headers = field(Object.entries(config.headers || {}).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join(","), "Authorization=Bearer%20token", "password", "OTLP headers");
    headers.onchange = () => {
      const values = {};
      try {
        for (const part of headers.value.split(",").filter((p) => p.trim())) {
          const i = part.indexOf("=");
          if (i < 1) throw new Error(t("Use comma-separated name=value headers"));
          values[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
        }
        save({ headers: values });
      } catch (e) { toast(e.message, true); }
    };
    row("otelHeadersRow", "OTLP headers", t("Comma-separated name=value pairs; percent-encode spaces and commas in values"), headers);
  }
  section("Export scope");
  row("otelMetricsRow", "Export metrics", t("Also send duration and token histograms. Leave off for a traces-only service such as Langfuse"),
    segs([["off", t("Off")], ["on", t("On")]], config.metrics ? "on" : "off", (v) => save({ metrics: v === "on" })));
  row("otelSessionsRow", "Trace agent conversations", t("Reads all local sessions from Codex, Pi, Oh My Pi, Claude Code, Cowork, OpenCode and Gemini CLI, including calls not routed through Magpie. When content is included below, exports prompts, replies, tool arguments and tool output (including file contents and command output), with secrets masked"),
    segs([["off", t("Off")], ["on", t("On")]], config.sessions ? "on" : "off", (v) => save({ sessions: v === "on" })));
  section("Trace content");
  const mode = !config.bodies ? "metadata" : config.bodiesWhole ? "full" : "limited";
  const content = segs([["metadata", t("Metadata only")], ["limited", t("Up to 256 KB")], ["full", t("Full content")]], mode,
    (v) => {
      for (const button of content.querySelectorAll("button")) button.setAttribute("aria-pressed", String(button.classList.contains("on")));
      save({ bodies: v !== "metadata", bodiesWhole: v === "full" });
    });
  content.setAttribute("role", "group");
  content.setAttribute("aria-label", t("Request and response content"));
  for (const [i, button] of [...content.querySelectorAll("button")].entries()) {
    button.setAttribute("aria-pressed", String(["metadata", "limited", "full"][i] === mode));
  }
  const descriptions = {
    metadata: "Send model, token, status and timing metadata only. Prompts, replies and tool content stay local",
    limited: "Include requests and replies as trace input and output, with secrets masked. Each body is limited to 256 KB",
    full: "Include complete requests and replies, with secrets masked. Large content may be refused by your collector",
  };
  row("otelBodiesRow", "Request and response content", t(descriptions[mode]), content);
  if (s.otelEnv) box.append(el("div", "sub otel-env", t("Environment variables override these saved OTLP preferences")));
}

// renderLangfuse: Langfuse's host and keys. Nothing is saved until both keys
// are there; then the endpoint and the Basic header are made from them, and
// a first setup also adds the ingestion header (Langfuse's docs: without it
// OTLP data can show up to 10 minutes late), turns metrics off (Langfuse
// takes traces only) and export on. Every other header, and an ingestion
// header the user set themselves, is kept as it was.
function renderLangfuse(saved, config, save, row, field) {
  if (lfDraft && saved && lfDraft.pk === saved.pk && lfDraft.sk === saved.sk && lfDraft.host === saved.host) lfDraft = null;
  const d = lfDraft || { host: saved?.host || LANGFUSE_HOSTS[0][0], pk: saved?.pk || "", sk: saved?.sk || "" };
  const preset = LANGFUSE_HOSTS.some(([h]) => h === d.host) ? d.host : "other";
  const commit = () => {
    d.pk = d.pk.trim(); d.sk = d.sk.trim();
    lfDraft = { ...d };
    const host = langfuseHost(d.host);
    if (!host) return void toast(t("Enter your Langfuse address, such as https://langfuse.example.com"), true);
    lfDraft.host = d.host = host;
    if (!d.pk || !d.sk) return;
    // a first setup: no Langfuse endpoint saved yet, or one with no sign-in.
    // Another collector's headers are its own, never sent to Langfuse
    const first = !saved || !Object.keys(config.headers || {}).some((k) => k.toLowerCase() === "authorization");
    const headers = {};
    let version = false;
    for (const [k, v] of Object.entries(saved ? config.headers || {} : {})) {
      if (k.toLowerCase() === "authorization") continue;
      if (k.toLowerCase() === "x-langfuse-ingestion-version") version = true;
      headers[k] = v;
    }
    headers.Authorization = "Basic " + btoa(unescape(encodeURIComponent(d.pk + ":" + d.sk)));
    if (!version && first) headers["x-langfuse-ingestion-version"] = "4";
    save({ endpoint: host + LANGFUSE_PATH, headers, ...(first ? { metrics: false, enabled: true } : {}) });
  };
  const other = field(preset === "other" ? d.host : "", "https://langfuse.example.com", "url", "Langfuse host");
  other.onchange = () => { d.host = other.value; commit(); };
  other.hidden = preset !== "other";
  const where = el("div", "otel-host");
  where.append(segs([...LANGFUSE_HOSTS.map(([h, name]) => [h, t(name)]), ["other", t("Self-hosted")]], preset, (v) => {
    other.hidden = v !== "other";
    d.host = v === "other" ? other.value : v;
    lfDraft = { ...d };
    if (v === "other") return void other.focus({ preventScroll: true });
    commit();
  }), other);
  row("otelLangfuseHostRow", "Langfuse host", t("Langfuse Cloud's region, or the address of your own Langfuse"), where);
  const pk = field(d.pk, "pk-lf-…", "text", "Public key");
  pk.oninput = () => { d.pk = pk.value; lfDraft = { ...d }; };
  pk.onchange = commit;
  const sk = field(d.sk, "sk-lf-…", "password", "Secret key");
  sk.oninput = () => { d.sk = sk.value; lfDraft = { ...d }; };
  sk.onchange = commit;
  const keys = el("div", "otel-keys");
  keys.append(pk, sk);
  const host = langfuseHost(d.host);
  row("otelLangfuseKeysRow", "API keys", t("From your Langfuse project's Settings › API Keys. Traces go to {url}", { url: (host || "…") + LANGFUSE_PATH }), keys);
}
