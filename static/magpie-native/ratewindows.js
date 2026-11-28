// A provider's rate windows (#2463) in its editor: the hours it bills at
// its own rate, a peak at 2x or a discount off peak. app.js imports this
// when an editor draws the field (rateWindowsField), so it weighs nothing
// on the core. Each window is its days (none ticked: every day), a span
// that may cross midnight, and the rate the price is times inside it, on
// top of the price rate; the first window holding a call wins.

// rateWindowsPaint draws d's windows into box, and Add a window under
// them while there is room for one more.
window.rateWindowsPaint = function paint(box, d) {
  box.replaceChildren();
  if (!box.nextElementSibling) {
    const help = el("div", "hint", t("Inside a window a call costs the official price times its rate, on top of the price rate; outside every window the price rate alone counts. The first window that holds a call wins. Times are on the clock of the computer magpie runs on, and 22:00–6:00 crosses midnight. No day ticked is every day. A price you set for a model is scaled by the window too. Changing the windows prices the calls already counted again, as a changed price rate does."));
    // a list price with the vendor's own peak has it already (#2463,
    // the author): a window over the same hours would double it again
    help.append(el("div", "", t("DeepSeek's own API, Command Code, OpenCode Go and Ollama Cloud already count their DeepSeek models' peak hours at double: don't add those hours as a window, or they count twice.")));
    help.id = "rate-windows-help";
    box.after(help);
    box.setAttribute("role", "group");
    box.setAttribute("aria-describedby", help.id);
  }
  for (const w of d.rateWindows || []) box.append(rateWindowRow(w, d, () => paint(box, d)));
  if ((d.rateWindows || []).length < 8) {
    const add = el("button", "text", t("Add a window"));
    add.type = "button";
    add.onclick = () => { (d.rateWindows ??= []).push({ days: [], start: "", end: "", rate: "" }); paint(box, d); };
    box.append(add);
  }
};

// rateWindowRow is one window of the editor, its draft w kept as typed.
function rateWindowRow(w, d, repaint) {
  const row = el("div", "rate-win"), chips = el("div", "day-chips");
  const names = [t("Sun"), t("Mon"), t("Tue"), t("Wed"), t("Thu"), t("Fri"), t("Sat")];
  for (let i = 0; i < 7; i++) {
    // a new array each press: the draft's window is a shallow copy of the
    // saved one, which keeps its own days
    const mark = () => {
      const on = (w.days || []).includes(i);
      b.classList.toggle("on", on);
      b.setAttribute("aria-pressed", String(on));
    };
    const b = el("button", "day-chip", names[i]);
    b.type = "button";
    mark();
    b.onclick = () => {
      const days = (w.days || []).filter((x) => x !== i);
      w.days = days.length < (w.days || []).length ? days : [...days, i].sort((a, z) => a - z);
      mark();
    };
    chips.append(b);
  }
  const rate = input(w.rate, "3");
  rate.classList.add("rate-rate");
  rate.inputMode = "decimal";
  rate.setAttribute("aria-label", t("Rate in this window"));
  rate.oninput = () => { w.rate = rate.value; };
  const del = el("button", "text rate-win-del", "×");
  del.type = "button";
  del.title = t("Remove this window");
  del.setAttribute("aria-label", del.title);
  del.onclick = () => {
    const at = (d.rateWindows || []).indexOf(w);
    if (at >= 0) d.rateWindows.splice(at, 1);
    repaint();
  };
  row.append(chips, timePick(w, "start", t("Window starts at")), el("span", "rate-dash", "–"),
    timePick(w, "end", t("Window ends at")), rate, del);
  return row;
}

// timePick is a window's start or end as the app's own menu of half
// hours, not typed; only an end may be 24:00.
function timePick(w, key, label) {
  const b = el("button", "sess-pick rate-time");
  b.type = "button";
  b.setAttribute("aria-haspopup", "menu");
  b.setAttribute("aria-expanded", "false");
  b.setAttribute("aria-label", label);
  const paint = () => {
    b.dataset.value = w[key] || "";
    b.replaceChildren(el("span", "", w[key] || "--:--"), svg(CHEV, 11, 1.6));
  };
  b.onclick = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (b.classList.contains("open")) return closeProtoMenu();
    const times = [];
    for (let m = 0; m < 1440; m += 30) times.push(String(Math.floor(m / 60)).padStart(2, "0") + ":" + String(m % 60).padStart(2, "0"));
    if (key === "end") times.push("24:00");
    openProtoMenu(b, times.map((v) => ({ v, name: v, note: "", literalName: true })), w[key], (v) => { w[key] = v; paint(); }, label, "sess-menu");
  };
  paint();
  return b;
}

// clockOf reads "H:MM" or "HH:MM", 24:00 included; null for what isn't one.
function clockOf(v) {
  const m = String(v ?? "").trim().match(/^(\d{1,2}):(\d{2})$/);
  if (!m) return null;
  const min = +m[1] * 60 + +m[2];
  return +m[1] > 24 || +m[2] > 59 || min > 1440 ? null : min;
}

// rateWindowsOfDraft is the draft's windows as saved, null for none, or
// false when one is typed wrong (provider.CheckRateWindows' rules). Not
// loaded yet, the save leaves them out, which keeps them as they are.
window.rateWindowsOfDraft = function () {
  const out = [];
  for (const w of draft.rateWindows || []) {
    const start = clockOf(w.start), end = clockOf(w.end);
    if (start === null || start === 1440 || end === null || start === end) return false;
    const n = decimalOf(String(w.rate ?? "").trim());
    if (!(n > 0 && n <= 1000) || Math.abs(n * 1000 - Math.round(n * 1000)) > 1e-6) return false;
    out.push({ days: [...(w.days || [])], start: String(w.start).trim(), end: String(w.end).trim(), rate: n });
  }
  return out.length ? out : null;
};

window.rateWindowsError = function (ed) {
  shown(ed.querySelector(".rate-windows input"))?.focus({ preventScroll: true });
  return editorError(t("Rate windows: every window is days, a time like 09:00, another time for it to end, and a rate from 0 to 1000 with at most three decimals"), "warn");
};
