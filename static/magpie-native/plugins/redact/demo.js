// Insights › Masking's demo (client.js has its row): 小鹊 takes one request
// through masking. The letter comes to her before it leaves this computer,
// she tears the password and the email out into her notebook and sticks
// placeholders in their place, the provider answers with placeholders, and
// she puts the values back before the browser on this computer signs in.
//
// She is a video, one take per theme, drawn on the card's own colour; the
// sheets, the notebook and the boxes are the page's, moved over her. The
// video is fetched when the row is first opened, never before. It plays
// while the row is open and on screen, once through, and rests on its last
// step; with reduced motion it starts there. Folded, or with the page left,
// the video lets its source go, so a folded demo holds no decoder or
// buffered video. Where the app's webview would crash on a video
// (bootPrefs.noVideo: Linux without gst-plugins-good), she is her poster.

const XQD_END = 27.5;
const XQD_STEPS = [
  [0, "You send a request", "You ask the agent to sign in to github.com with a password. The letter goes to Little Magpie first and hasn't left your computer yet."],
  [5.4, "She reads it through", "Little Magpie opens the letter and reads it line by line for what shouldn't be sent: emails, passwords."],
  [7.8, "Tearing out what's private", "The real values are torn out and written in her notebook. The notebook stays on your computer."],
  [10.6, "Sticking on placeholders", "Placeholders fill the gaps. A value always gets the same one, so the model still understands."],
  [12.8, "Off to the provider", "The letter is sealed and sent. The provider gets only placeholders."],
  [15.6, "The answer calls the browser", "The model decides to call browser.login, and its arguments are placeholders too."],
  [18.8, "Putting the values back", "When the answer comes, Little Magpie opens her notebook and turns each placeholder back into its value."],
  [22.2, "Signing in on your computer", "The tool signs in with the real password on your computer. The password never left it."],
];
const XQD_MAIL = "yetone@example.com", XQD_PASS = "hunter2-prod";
const XQD_PM = "{{EMAIL_r3tvb2ce}}", XQD_PP = "{{PASSWORD_k7q2m4xa}}";

let xqd = null;   // the demo, once its row has been opened

document.addEventListener("click", (e) => {
  if (e.target.closest?.("#mdRow")) maskDemoToggle();
});

function maskDemoToggle() {
  const row = $("#mdRow"), body = $("#mdBody");
  if (!row || !body) return;
  const open = row.getAttribute("aria-expanded") !== "true";
  row.setAttribute("aria-expanded", String(open));
  body.hidden = !open;
  // the kernel can draw the page again, and an old demo goes with it
  if (open && !xqd?.root.isConnected) xqd = maskDemoBuild(body);
  xqd?.wake();
}

// What a label says: data-t, so a change of language says it again.
const xqdSay = (cls, text) => { const s = el("span", cls, t(text)); s.dataset.t = ""; s.dataset.en = text; return s; };
const xqdIcon = {
  you: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/></svg>',
  book: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z"/><path d="M5 17a3 3 0 0 1 3-3h11"/></svg>',
  lock: '<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  check: (n) => `<svg width="${n}" height="${n}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>`,
  server: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="7" rx="2"/><rect x="4" y="13" width="16" height="7" rx="2"/><path d="M8 7.5h.01M8 16.5h.01"/></svg>',
  env: (seal) => `<svg class="xq-env xq-mv" viewBox="-2 -1 82 58" aria-hidden="true"><rect x="1.5" y="4" width="76" height="50" rx="6" fill="var(--xq-env-shadow)"/><rect x="1" y="1" width="76" height="50" rx="5" fill="var(--xq-paper)" stroke="var(--faint)" stroke-width="1.2"/><path d="M2 3l37 26L76 3" fill="none" stroke="var(--faint)" stroke-width="1.2"/><circle cx="39" cy="28" r="8" fill="${seal}"/><circle cx="39" cy="28" r="4.5" fill="none" stroke="#fff" stroke-opacity=".5" stroke-width="1.3"/></svg>`,
  pause: '<svg width="12" height="12" viewBox="0 0 12 12"><rect x="2" y="1.5" width="2.6" height="9" rx="1" fill="currentColor"/><rect x="7.4" y="1.5" width="2.6" height="9" rx="1" fill="currentColor"/></svg>',
  play: '<svg width="12" height="12" viewBox="0 0 12 12"><path d="M3 1.8v8.4a.6.6 0 0 0 .9.5l7-4.2a.6.6 0 0 0 0-1L3.9 1.3a.6.6 0 0 0-.9.5z" fill="currentColor"/></svg>',
};

// The stage is drawn at 1000×420 and scaled to the card's width.
function maskDemoStage() {
  const stage = el("div", "xq-stage");
  const at = (node, k) => { node.dataset.k = k; return node; };
  const box = (k, icon, title, sub) => {
    const b = at(el("div", "xq-box"), k), h = el("div", "xq-bh"), ic = el("div", "xq-ic" + (icon === "book" ? " xq-acc" : ""));
    ic.innerHTML = xqdIcon[icon];
    const words = el("div");
    words.append(xqdSay("xq-h", title));
    if (sub) words.append(xqdSay("xq-sub", sub));
    h.append(ic, words);
    b.append(h);
    return b;
  };
  const lane = (x, far, text) => { const l = el("div", "xq-lane"); l.style.left = x + "px"; l.append(el("span", "xq-dot" + (far ? " far" : "")), xqdSay("", text)); return l; };
  const divider = el("div", "xq-divider");
  divider.append(xqdSay("", "Over the network"));

  const req = box("req", "you", "You tell the agent");
  req.append(at(el("div", "xq-msg"), "reqmsg"));

  const ledger = box("ledger", "book", "Little Magpie's notebook", "Kept on your computer only");
  ledger.append(at(xqdSay("xq-lempty", "Nothing in it yet"), "lempty"));
  // the entries follow the header, so a taller font moves them down with it
  const entries = el("div", "xq-llist");
  [[XQD_PM, XQD_MAIL], [XQD_PP, XQD_PASS]].forEach(([code, real], i) => {
    const r = at(el("div", "xq-lrow xq-mv"), "row" + i);
    r.append(el("span", "xq-lc xq-pillc", code), el("span", "xq-lv", real));
    entries.append(r);
  });
  ledger.append(entries);

  const browser = at(el("div", "xq-box"), "browser"), bar = el("div", "xq-bbar");
  bar.innerHTML = `<i></i><i></i><i></i><div class="xq-url">${xqdIcon.lock}github.com/login</div>`;
  const form = el("div", "xq-bform"), fu = at(el("div", "xq-field"), "fu"), fp = at(el("div", "xq-field"), "fp"), btn = el("div", "xq-bbtn");
  btn.append(xqdSay("", "Sign in"));
  form.append(fu, fp, btn);
  const ok = at(el("div", "xq-bok xq-mv"), "bok"), chk = el("div", "xq-chk");
  chk.innerHTML = xqdIcon.check(16);
  ok.append(chk, xqdSay("", "Signed in to github.com"), xqdSay("xq-sub", "The tool runs on your computer"));
  browser.append(bar, form, ok);

  const xq = at(el("div", "xq-her"), "her");
  xq.setAttribute("aria-hidden", "true");
  const vid = el("video");
  vid.muted = true; vid.playsInline = true; vid.preload = "auto";
  vid.setAttribute("muted", ""); vid.setAttribute("playsinline", "");
  xq.append(vid);

  const slot = (k, real, code, hole, ok) => {
    const s = at(el("span", "xq-slot"), k);
    if (hole) s.append(el("span", "xq-hole"));
    s.append(el("span", "xq-real xq-mv" + (ok ? " ok" : ""), real), el("span", "xq-code xq-mv", code));
    return s;
  };
  const line = (label, ...rest) => { const l = el("div", "xq-ln"); if (label) l.append(xqdSay("xq-k", label)); l.append(...rest); return l; };
  const paper = (k, head, side) => { const p = at(el("div", "xq-paper xq-mv"), k), ph = el("div", "xq-ph"); ph.append(xqdSay("", head), xqdSay("", side)); p.append(ph); return p; };
  const letter = paper("letter", "Letter to the provider", "Agent → model");
  letter.append(line("The job", xqdSay("", "Sign in to github.com")), line("Account", slot("s0", XQD_MAIL, XQD_PM, true)), line("Password", slot("s1", XQD_PASS, XQD_PP, true)));
  const reply = paper("reply", "The provider's answer", "Calls a tool"), fn = el("div", "xq-ln");
  fn.append(el("span", "xq-fn", "browser.login"), el("span", "xq-arg", "url: github.com"));
  reply.append(fn, line("", el("span", "xq-k", "username"), slot("r0", XQD_MAIL, XQD_PM, false, true)), line("", el("span", "xq-k", "password"), slot("r1", XQD_PASS, XQD_PP, false, true)));

  const prov = box("prov", "server", "Model service", "Remote, not on your computer");
  const pin = at(el("div", "xq-psec xq-mv"), "pin");
  const pline = (...n) => { const p = el("div", "xq-pline"); p.append(...n); return p; };
  pin.append(xqdSay("xq-cap", "Letter it got"), pline(xqdSay("", "Sign in to github.com")), pline(xqdSay("", "Account"), el("span", "xq-pillc", XQD_PM)), pline(xqdSay("", "Password"), el("span", "xq-pillc", XQD_PP)));
  const pout = at(el("div", "xq-psec xq-mv"), "pout"), think = at(el("div", "xq-think"), "think");
  think.append(el("i", "xq-mv"), el("i", "xq-mv"), el("i", "xq-mv"));
  const pcode = at(el("div", "xq-pcode xq-mv"), "pcode");
  pcode.append("browser.login(", el("div", "xq-ind", "username:"), el("span", "xq-pillc", XQD_PM), el("div", "xq-ind", "password:"), el("span", "xq-pillc", XQD_PP), el("div", "", ")"));
  pout.append(xqdSay("xq-cap", "Reply it wrote"), think, pcode);
  const pnote = at(el("div", "xq-pnote xq-mv"), "pnote");
  pnote.innerHTML = xqdIcon.check(12);
  pnote.append(xqdSay("", "It saw only placeholders, never your password or email."));
  prov.append(pin, pout, pnote);

  stage.append(lane(18, false, "Your computer"), lane(802, true, "Provider"), divider, req, ledger, browser, xq, letter, reply, prov);
  stage.insertAdjacentHTML("beforeend", xqdIcon.env("#3c63d8") + xqdIcon.env("#d6a03c"));
  const [envA, envB] = stage.querySelectorAll(".xq-env");
  at(envA, "envA"); at(envB, "envB");
  const fly = (k, cls, text) => { const f = at(el("span", "xq-flyer xq-mv"), k); f.append(el("span", "xq-code " + cls, text)); return f; };
  stage.append(fly("f0", "torn", XQD_MAIL), fly("f1", "torn", XQD_PASS), fly("g0", "back", XQD_MAIL), fly("g1", "back", XQD_PASS));
  for (let i = 0; i < 6; i++) stage.append(at(el("i", "xq-trail xq-mv"), "t" + i));
  return stage;
}

function maskDemoBuild(body) {
  const root = el("div", "xqd"), vp = el("div", "xq-vp"), stage = maskDemoStage();
  vp.append(stage);
  const foot = el("div", "xq-foot"), capT = el("div", "xq-cap-t"), capB = el("div", "xq-cap-b");
  foot.append(capT, capB);
  const ctrl = el("div", "xq-ctrl"), play = el("button", "xq-play"), scrub = el("input", "xq-scrub");
  play.type = "button";
  scrub.type = "range"; scrub.min = "0"; scrub.max = "1000"; scrub.value = "0";
  ctrl.append(play, scrub);
  const steps = el("div", "xq-steps");
  root.append(vp, foot, ctrl, steps);
  body.append(root);

  const q = (k) => stage.querySelector(`[data-k="${k}"]`);
  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
  const seg = (t, a, b) => clamp((t - a) / (b - a));
  const lerp = (a, b, k) => a + (b - a) * k;
  const eo = (k) => 1 - Math.pow(1 - k, 3);
  const eio = (k) => k < .5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
  const f2 = (v) => Math.round(v * 100) / 100;
  // style writes are skipped when the value is the same, so a frame
  // touches only what moved, and nothing per frame reads layout
  const css = (e, prop, v) => { const c = e._c || (e._c = {}); if (c[prop] === v) return; c[prop] = v; e.style[prop] = v; };
  const cls = (e, name, on) => { const c = e._c || (e._c = {}), k = "c:" + name; if (c[k] === on) return; c[k] = on; e.classList.toggle(name, on); };
  const op = (e, v) => css(e, "opacity", String(f2(v)));

  // her hands rest on the desk here in the video: sheets are handed to and
  // taken from these points
  const DESK = { L: [478, 262], R: [542, 262] };
  const held = (side, tilt) => [DESK[side][0], DESK[side][1], tilt];
  const ENV = .82, REQ = [126, 96], PROV = [893, 110], PROV_OUT = [860, 250], BROWSER = [126, 340], LC = [510, 333];
  const OPEN = [510, 256, 0], SEND = held("R", -14), CATCH2 = held("R", -16);

  const slots = {};
  for (const k of ["s0", "s1", "r0", "r1"]) {
    const s = q(k);
    slots[k] = { el: s, real: s.querySelector(".xq-real"), code: s.querySelector(".xq-code"), hole: s.querySelector(".xq-hole") };
  }
  const flyers = ["f0", "f1", "g0", "g1"].map(q), rows = [q("row0"), q("row1")], rowCodes = rows.map((r) => r.querySelector(".xq-lc"));
  const trails = [0, 1, 2, 3, 4, 5].map((i) => q("t" + i)), thinkDots = [...q("think").children];
  const e = {};
  for (const k of ["envA", "envB", "letter", "reply", "reqmsg", "lempty", "pin", "pout", "think", "pcode", "pnote", "fu", "fp", "bok"]) e[k] = q(k);

  // stage-space box from offsets, which ignore transforms, so a sheet is
  // measured where it lies on the desk whatever frame it is drawn in
  const at = (n0) => { let x = 0, y = 0, n = n0; while (n && n !== stage) { x += n.offsetLeft; y += n.offsetTop; n = n.offsetParent; } return { x, y, w: n0.offsetWidth, h: n0.offsetHeight }; };
  const LV = [];
  const measure = () => {
    for (const s of Object.values(slots)) {
      s.rw = s.real.offsetWidth; s.cw = s.code.offsetWidth;
      const b = at(s.el); s.x = b.x; s.y = b.y + b.h / 2;
      if (s.el._c) delete s.el._c.width;
    }
    flyers.forEach((f) => { f._w = f.offsetWidth; f._h = f.offsetHeight; if (f._c) delete f._c.transform; });
    rows.forEach((r, i) => { const b = at(r.querySelector(".xq-lv")); LV[i] = [b.x + Math.min(b.w, 130) / 2 + 6, b.y + b.h / 2]; });
  };

  const bez = (p0, p1, lift, k) => {
    const c = [(p0[0] + p1[0]) / 2, Math.min(p0[1], p1[1]) - lift], u = 1 - k;
    return [u * u * p0[0] + 2 * u * k * c[0] + k * k * p1[0], u * u * p0[1] + 2 * u * k * c[1] + k * k * p1[1]];
  };
  const place = (n, x, y, rot, sc, o) => { css(n, "transform", `translate(${f2(x)}px,${f2(y)}px) rotate(${f2(rot)}deg) scale(${f2(sc)})`); op(n, o); };
  const placeC = (n, x, y, o) => { css(n, "transform", `translate(${f2(x - n._w / 2)}px,${f2(y - n._h / 2)}px)`); op(n, o); };
  const drawTrail = (path, colour) => trails.forEach((d, i) => {
    const kk = path ? path[3] - (i + 1) * .045 : 0;
    if (!path || kk <= 0 || path[3] >= 1) return op(d, 0);
    const [x, y] = bez(path[0], path[1], path[2], kk);
    css(d, "transform", `translate(${f2(x)}px,${f2(y)}px)`);
    css(d, "background", colour);
    op(d, (1 - i / 6) * .45);
  });
  // a sheet between a hand (k = 0) and its place on the desk (k = 1)
  const onDesk = (n, from, k, o) => place(n, lerp(from[0] - LC[0], 0, k), lerp(from[1] - LC[1], 0, k), lerp(from[2], 0, k), lerp(.22, 1, k), o);
  const slotW = (s, w) => css(s.el, "width", Math.round(w) + "px");

  // the request types itself, in the reader's language
  let said = "", lastN = -1, lastSi = -1;
  const reqText = () => t("Sign in to github.com for me with the password {pw}, the account is {email}.", { pw: XQD_PASS, email: XQD_MAIL });
  const typed = (n) => {
    const text = reqText(), shown = text.slice(0, n);
    const frag = document.createDocumentFragment();
    let i = 0;
    for (const m of shown.matchAll(new RegExp(`${XQD_PASS}|${XQD_MAIL.replace(".", "\\.")}`, "g"))) {
      frag.append(shown.slice(i, m.index), el("b", "", m[0]));
      i = m.index + m[0].length;
    }
    frag.append(shown.slice(i));
    return frag;
  };

  const stepBtns = XQD_STEPS.map(([at0, title]) => {
    const b = el("button", "", t(title));
    b.type = "button"; b.dataset.t = ""; b.dataset.en = title;
    b.onclick = () => { seek(at0 + .01); render(T); sync(); };
    steps.append(b);
    return b;
  });

  function render(t0) {
    const lang = document.documentElement.lang;
    const len = reqText().length;
    const n = Math.round(seg(t0, .2, 1.4) * len) * 2 + (t0 < 1.8 ? 1 : 0);
    if (n !== lastN || lang !== said) {
      lastN = n;
      e.reqmsg.replaceChildren(typed(n >> 1));
      if (n & 1) e.reqmsg.append(el("span", "xq-caret"));
    }

    // the envelope flies into her left hand, she brings it to her chest and
    // opens it; later the sealed letter goes from her right hand to the provider
    let path = null, colour = "#3c63d8";
    if (t0 >= 1.6 && t0 < 3.0) {
      const k = eio(seg(t0, 1.75, 3.0)), to = held("L", 18), [x, y] = bez(REQ, to, 60, k);
      place(e.envA, x, y, lerp(-6, to[2], k), lerp(.5, ENV, eo(seg(t0, 1.6, 1.9))), seg(t0, 1.6, 1.75));
      path = [REQ, to, 60, k];
    } else if (t0 >= 3.0 && t0 < 4.95) {
      const k = eio(seg(t0, 3.3, 3.9)), a = held("L", 18), b = OPEN;
      place(e.envA, lerp(a[0], b[0], k), lerp(a[1], b[1], k), lerp(a[2], 0, k), ENV * (1 - .25 * seg(t0, 4.6, 4.95)), 1 - seg(t0, 4.7, 4.95));
    } else if (t0 >= 12.9 && t0 < 13.65) {
      const h = held("R", -14);
      place(e.envA, h[0], h[1], h[2], ENV, seg(t0, 12.9, 13.05));
    } else if (t0 >= 13.65 && t0 < 15.0) {
      const k = eio(seg(t0, 13.65, 14.75)), [x, y] = bez(SEND, PROV, 50, k);
      place(e.envA, x, y, lerp(SEND[2], 0, k), ENV * (1 - .4 * seg(t0, 14.75, 14.95)), 1 - seg(t0, 14.75, 14.95));
      path = [SEND, PROV, 50, k];
    } else op(e.envA, 0);

    if (t0 >= 17.0 && t0 < 18.3) {
      const k = eio(seg(t0, 17.1, 18.3)), to = held("R", -16), [x, y] = bez(PROV_OUT, to, 45, k);
      place(e.envB, x, y, lerp(0, to[2], k), lerp(.5, ENV, eo(seg(t0, 17, 17.3))), seg(t0, 17, 17.15));
      path = [PROV_OUT, to, 45, k]; colour = "#d6a03c";
    } else if (t0 >= 18.3 && t0 < 18.9) {
      const h = held("R", -16);
      place(e.envB, h[0], h[1], h[2], ENV * (1 - .25 * seg(t0, 18.6, 18.9)), 1 - seg(t0, 18.65, 18.9));
    } else op(e.envB, 0);
    drawTrail(path, colour);

    // the letter comes out of the envelope at her chest and lies on the desk
    let lvis = false;
    if (t0 >= 4.6 && t0 < 12.6) { lvis = true; onDesk(e.letter, OPEN, eo(seg(t0, 4.6, 5.4)), seg(t0, 4.6, 4.8)); }
    else if (t0 >= 12.6 && t0 < 13.15) { lvis = true; onDesk(e.letter, SEND, 1 - eio(seg(t0, 12.6, 13.05)), 1 - seg(t0, 12.95, 13.15)); }
    css(e.letter, "visibility", lvis ? "visible" : "hidden");

    // read, tear into the notebook, stick the placeholders on
    const READ = [6.0, 6.8], TEAR = [8.2, 9.2], STICK = [11.0, 11.7];
    ["s0", "s1"].forEach((k, i) => {
      const s = slots[k], torn = seg(t0, TEAR[i], TEAR[i] + .25), stuck = eo(seg(t0, STICK[i], STICK[i] + .35));
      cls(s.real, "hl", t0 >= READ[i]);
      op(s.real, 1 - torn);
      css(s.real, "transform", `translateY(${f2(-6 * torn)}px)`);
      op(s.hole, torn * (1 - stuck));
      op(s.code, stuck);
      css(s.code, "transform", `scale(${f2(lerp(1.25, 1, stuck))})`);
      slotW(s, lerp(s.rw, s.cw, eio(seg(t0, STICK[i], STICK[i] + .35))));
      const fk = seg(t0, TEAR[i] + .05, TEAR[i] + .95);
      if (fk > 0 && fk < 1 && lvis) {
        const [x, y] = bez([s.x + s.rw / 2, s.y], LV[i], 50, eio(fk));
        placeC(flyers[i], x, y, seg(fk, 0, .1) * (1 - seg(fk, .92, 1)));
      } else op(flyers[i], 0);
      op(rows[i], seg(t0, TEAR[i] + .9, TEAR[i] + 1.05));
      op(rowCodes[i], seg(t0, STICK[i], STICK[i] + .3));
    });
    op(e.lempty, 1 - seg(t0, TEAR[0] + .7, TEAR[0] + .9));

    // the provider reads placeholders and answers with placeholders
    op(e.pin, seg(t0, 14.8, 15.2));
    op(e.pout, seg(t0, 15.6, 15.9));
    css(e.think, "display", t0 < 16.4 ? "flex" : "none");
    if (t0 < 16.4 && t0 > 15.5) thinkDots.forEach((d, i) => op(d, .35 + .65 * Math.max(0, Math.sin(t0 * 7 - i * .9))));
    op(e.pcode, seg(t0, 16.4, 16.9));
    op(e.pnote, seg(t0, 17.6, 18.0));

    // the answer comes out of her hands onto the desk, placeholders turn
    // back, then it goes to the browser
    let rvis = false;
    if (t0 >= 18.6 && t0 < 22.4) { rvis = true; onDesk(e.reply, CATCH2, eo(seg(t0, 18.6, 19.4)), seg(t0, 18.6, 18.8)); }
    else if (t0 >= 22.4 && t0 < 23.25) {
      rvis = true; const k = eio(seg(t0, 22.4, 23.2));
      place(e.reply, lerp(0, BROWSER[0] - LC[0], k), lerp(0, BROWSER[1] - LC[1], k), 0, lerp(1, .3, k), 1 - seg(t0, 23.0, 23.25));
    }
    css(e.reply, "visibility", rvis ? "visible" : "hidden");
    const RESTORE = [20.2, 21.1];
    ["r0", "r1"].forEach((k, i) => {
      const s = slots[k], back = eo(seg(t0, RESTORE[i] + .55, RESTORE[i] + .85));
      op(s.code, 1 - back);
      css(s.code, "transform", `translateY(${f2(-5 * back)}px)`);
      op(s.real, back);
      slotW(s, lerp(s.cw, s.rw, back));
      cls(rows[i], "hot", t0 >= RESTORE[i] - .3 && t0 < RESTORE[i] + 1.2);
      const gk = seg(t0, RESTORE[i], RESTORE[i] + .65);
      if (gk > 0 && gk < 1 && rvis) {
        const [x, y] = bez(LV[i], [s.x + s.rw / 2, s.y], 40, eio(gk));
        placeC(flyers[2 + i], x, y, seg(gk, 0, .1) * (1 - seg(gk, .85, 1)));
      } else op(flyers[2 + i], 0);
    });

    // the browser on this computer fills in and signs in
    const tu = XQD_MAIL.slice(0, Math.round(seg(t0, 23.4, 24.1) * XQD_MAIL.length)), tp = "•".repeat(Math.round(seg(t0, 24.1, 24.6) * 12));
    if (e.fu._t !== tu) e.fu.textContent = e.fu._t = tu;
    if (e.fp._t !== tp) e.fp.textContent = e.fp._t = tp;
    cls(e.fu, "on", t0 >= 23.4 && t0 < 24.1);
    cls(e.fp, "on", t0 >= 24.1 && t0 < 24.7);
    const ok = eo(seg(t0, 25.0, 25.4));
    op(e.bok, ok);
    css(e.bok, "transform", `scale(${f2(lerp(.97, 1, ok))})`);

    let si = 0;
    XQD_STEPS.forEach(([s], i) => { if (t0 >= s) si = i; });
    if (si !== lastSi || lang !== said) {
      lastSi = si;
      const n = el("span", "n", `${si + 1}/${XQD_STEPS.length}`);
      capT.replaceChildren(n, t(XQD_STEPS[si][1]));
      capB.textContent = t(XQD_STEPS[si][2]);
      stepBtns.forEach((b, i) => { b.classList.toggle("on", i === si); b.classList.toggle("done", i < si); });
    }
    said = lang;
  }

  // T, the frame clock, moves the sheets every display frame; while the
  // video plays T leans toward its time, so she and the sheets keep step.
  // Without the video (it can't load or play) the frame clock alone runs.
  const vid = stage.querySelector("video");
  let T = 0, playing = !calm(), open = false, seen = false, raf = 0, last = 0, fixed = 0, theme = "", take = "";
  const dark = matchMedia("(prefers-color-scheme: dark)");
  // boot.js says it before the page draws: /api/state's settings don't
  // carry it, so a demo opened before Settings was never told (avk458 on X)
  const noVideo = !!window.bootPrefs?.noVideo;
  const pickVid = () => {
    const th = document.documentElement.dataset.theme || (dark.matches ? "dark" : "light");
    if (th === theme) return;
    theme = th;
    vid.poster = `plugins/redact/xq_${th}.jpg`;
    take = noVideo ? "" : `plugins/redact/xq_${th}.webm`;
    // a new source starts paused: it goes on where the old one was
    seek(T);
    wake();
  };
  // the take is the video's source only while the row is open on the page
  // shown; let go, the video frees its decoder and what it buffered
  const hold = () => {
    if (take && open && vp.getClientRects().length) {
      if (vid.getAttribute("src") !== take) vid.src = take;
    } else if (vid.hasAttribute("src")) {
      vid.removeAttribute("src");
      vid.load();
    }
  };
  const seek = (t0) => { T = t0; if (vid.readyState >= 1) vid.currentTime = Math.min(t0, vid.duration - .02); };
  vid.addEventListener("loadedmetadata", () => seek(T));
  let lastScrub = -1;
  const sync = () => { const v = Math.round(T / XQD_END * 200) * 5; if (v !== lastScrub) { lastScrub = v; scrub.value = v; } };
  const live = () => open && seen && !document.hidden && root.isConnected && !$("#maskDemo")?.hidden;
  const setPlaying = (p) => {
    playing = p;
    play.innerHTML = p ? xqdIcon.pause : xqdIcon.play;
    words();
    if (p && T >= XQD_END - .05) seek(0);
    wake();
  };
  // the controls' names, said again when the language changes
  const words = () => {
    play.title = t(playing ? "Pause the demo" : "Play the demo");
    play.setAttribute("aria-label", play.title);
    scrub.setAttribute("aria-label", t("Where the demo is"));
  };
  play.onclick = () => setPlaying(!playing);
  scrub.oninput = () => { setPlaying(false); seek(scrub.value / 1000 * XQD_END); render(T); };

  function frame(now) {
    raf = 0;
    if (!live() || !playing) return;
    T += Math.min(.05, (now - (last || now)) / 1000);
    last = now;
    if (!vid.paused && !vid.seeking && vid.readyState >= 2) {
      // a video that went elsewhere (a seek it couldn't make, a stall) is
      // sent back to T, at most once a second; T never jumps to it
      const err = vid.currentTime - T;
      if (Math.abs(err) <= .25) T += err * .1;
      else if (now - fixed > 1000) { fixed = now; vid.currentTime = Math.min(T, vid.duration - .02); }
    }
    // once through, then it rests on the last step
    if (T >= XQD_END || vid.ended) { T = XQD_END; render(T); sync(); return setPlaying(false); }
    render(T); sync();
    raf = requestAnimationFrame(frame);
  }
  // wake starts or stops it as the row, the page and the window say
  function wake() {
    open = $("#mdRow")?.getAttribute("aria-expanded") === "true";
    hold();
    if (live() && playing) {
      seek(T);
      vid.play().catch(() => {});
      if (!raf) { last = 0; raf = requestAnimationFrame(frame); }
    } else {
      vid.pause();
      if (raf) cancelAnimationFrame(raf), (raf = 0);
    }
  }
  new IntersectionObserver((es) => { seen = es[es.length - 1].isIntersecting; wake(); }).observe(vp);
  document.addEventListener("visibilitychange", wake);
  new ResizeObserver(() => { stage.style.transform = `scale(${vp.clientWidth / 1000})`; }).observe(vp);
  new MutationObserver(pickVid).observe(document.documentElement, { attributeFilter: ["data-theme"] });
  dark.addEventListener("change", pickVid);
  // a change of language redraws the words the frame writes itself
  new MutationObserver(() => { render(T); words(); }).observe(document.documentElement, { attributeFilter: ["lang"] });

  pickVid();
  measure();
  document.fonts?.ready.then(() => { measure(); render(T); });
  if (!playing) seek(25.6);
  render(T); sync();
  setPlaying(playing);
  root.__state = () => ({ T, ct: vid.currentTime, paused: vid.paused, rs: vid.readyState, src: vid.getAttribute("src") ? vid.currentSrc.split("/").pop() : "", playing, raf: !!raf });
  return { wake, root };
}
