// A masking rule open to change in its place. app.js imports this on a
// rule's Edit, so it weighs nothing on the core.

// editRedactRule: the rule at n, open to change in its place (nf1qaz2w on
// Discord: rules could only be removed) — its name, prefix or regex and
// what to match, laid out as the row that adds one. Save sends it alone,
// checked as an added rule is: one magpie can't use is said in the row,
// what was typed kept and every rule as it was. Cancel (or Escape) leaves
// the rule as it was.
window.editRedactRule = function (r, n, row) {
  const d = ruleEdit;
  const kind = input(d.kind, "API_KEY");
  const match = input(d.match, d.by === "prefix" ? "oc_sk_" : "oc_sk_[A-Za-z0-9]{20,}");
  kind.className = "words rule-kind editing";
  match.className = "words rule-match editing";
  kind.setAttribute("aria-label", t("Name"));
  match.setAttribute("aria-label", d.by === "prefix" ? t("Prefix") : t("Regex"));
  const by = segs([["prefix", t("Prefix")], ["regex", t("Regex")]], d.by, (v) => {
    d.by = v;
    match.placeholder = v === "prefix" ? "oc_sk_" : "oc_sk_[A-Za-z0-9]{20,}";
    match.setAttribute("aria-label", v === "prefix" ? t("Prefix") : t("Regex"));
  });
  const save = el("button", "text rule-save", t("Save"));
  const cancel = el("button", "text rule-cancel", t("Cancel"));
  cancel.onclick = () => { ruleEdit = null; renderSettings(); };
  save.onclick = () => {
    d.kind = kind.value; d.match = match.value.trim();
    if (!d.match) return match.focus(NO_SCROLL);
    const rule = { kind: d.kind.trim(), [d.by === "prefix" ? "prefix" : "regex"]: d.match };
    save.disabled = true;
    writingPrefs(api("settings/redact-rule", { at: n, was: d.was, rule }))
      .then((ns) => { prefs = ns; ruleEdit = null; renderSettings(); status(t("Saved"), "ok", 1500); })
      .catch((e) => { if (ruleEdit === d) d.err = t(e.message); statusTErr(e); renderSettings(); });
  };
  for (const i of [kind, match]) {
    i.oninput = () => { d.kind = kind.value; d.match = match.value; };
    i.onkeydown = (e) => {
      e.stopPropagation();
      if (e.key === "Enter") save.onclick();
      else if (e.key === "Escape") cancel.onclick();
    };
  }
  // the match with Save and Cancel, kept together: a narrow window moves
  // them as one under the name and Prefix or Regex
  const tail = el("div", "rule-tail");
  tail.append(match, save, cancel);
  row(r.kind, d.err || (r.prefix ? t("Starts with {p}", { p: r.prefix }) : t("Matches {re}", { re: r.regex })), kind, by, tail);
  // laid out as the row that adds a rule: its words, the fields under them
  const head = $("#redactList").lastElementChild;
  head.classList.add("rule-row", "rule-editing");
  head.querySelector(".val").classList.add("rule-add");
  if (d.err) head.querySelector(".sub").classList.add("err");
};
