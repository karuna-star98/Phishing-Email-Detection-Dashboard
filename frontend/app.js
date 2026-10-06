// Dashboard logic. SECURITY: all dynamic text is inserted with textContent (via h()), never innerHTML,
// so email content cannot inject HTML/JS (XSS). Raw email HTML is never rendered.
"use strict";
const $ = (s) => document.querySelector(s);
const CLS = {"LOW RISK": "c-low", "MODERATE RISK": "c-mod", "SUSPICIOUS": "c-sus", "HIGH RISK / LIKELY PHISHING": "c-high"};
const COLORS = {"LOW RISK": "#22c55e", "MODERATE RISK": "#eab308", "SUSPICIOUS": "#f97316", "HIGH RISK / LIKELY PHISHING": "#ef4444"};

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}
const clear = (e) => { while (e.firstChild) e.removeChild(e.firstChild); return e; };
async function api(path, opts = {}) {
  const r = await fetch(path, {headers: {"Content-Type": "application/json"}, credentials: "same-origin", ...opts});
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}
const badge = (c) => h("span", {class: "badge " + (CLS[c] || "")}, c);

// ---------------- tabs ----------------
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("#tabs button,.tab").forEach((x) => x.classList.remove("active"));
  b.classList.add("active"); $("#tab-" + b.dataset.tab).classList.add("active");
  if (b.dataset.tab === "dashboard") loadDashboard();
  if (b.dataset.tab === "history") loadHistory();
}));

// ---------------- samples (fictional) ----------------
const SAMPLES = {
  legit: {sender: "Cyber Club <training@example.org>", subject: "Cybersecurity Workshop Reminder",
    body: "Hi everyone,\n\nA reminder that our cybersecurity workshop is on Friday at 3 PM in Room 12. Bring your laptop. The agenda is attached.\n\nSee you there,\nCyber Club", attachment: "agenda.pdf"},
  phish: {sender: "security-alert@account-check.invalid.test", subject: "URGENT: Verify Your Account Immediately",
    body: "Dear customer,\n\nWe detected unusual activity. Your account will be suspended within 24 hours unless you verify your password and confirm your identity here:\nhttp://198.51.100.10/verify-account\n\nSecurity Team", attachment: "verification.pdf.exe"},
};
function loadSample(s) { for (const k of ["sender", "subject", "body", "attachment"]) $("#" + k).value = s[k]; }
$("#s-legit").onclick = () => loadSample(SAMPLES.legit);
$("#s-phish").onclick = () => loadSample(SAMPLES.phish);
$("#file").addEventListener("change", async (ev) => {
  const f = ev.target.files[0]; if (!f) return;
  try {
    const p = await api("/api/parse-eml", {method: "POST", body: JSON.stringify({filename: f.name, content: await f.text()})});
    loadSample({sender: p.sender, subject: p.subject, body: p.body, attachment: p.attachment_name});
    $("#analyze-msg").textContent = "Sample loaded - nothing was executed or opened.";
  } catch (e) { $("#analyze-msg").textContent = e.message; }
  ev.target.value = "";
});

// ---------------- analyzer ----------------
$("#analyze").onclick = async () => {
  $("#analyze-msg").textContent = "Analyzing...";
  try {
    const r = await api("/api/analyze", {method: "POST", body: JSON.stringify({
      sender: $("#sender").value, subject: $("#subject").value, body: $("#body").value, attachment_name: $("#attachment").value})});
    $("#analyze-msg").textContent = "";
    renderResult(clear($("#result")), r);
  } catch (e) { $("#analyze-msg").textContent = e.message; }
};

function sevList(items) {
  return h("ul", {class: "plain"}, items.map((f) => h("li", {class: "sev-" + f.severity}, f.description)));
}
function renderResult(box, r, title = "Result") {
  const cls = r.classification;
  box.append(h("h2", {}, title),
    h("div", {class: "row between"}, h("div", {}, h("div", {class: "muted"}, "PHISHING RISK SCORE"), h("div", {class: "score"}, `${Math.round(r.risk_score)}/100`)), badge(cls)),
    h("div", {class: "meter"}, Object.assign(h("i", {}), {style: `width:${r.risk_score}%;background:${COLORS[cls]}`})),
    h("div", {class: "muted"}, r.ml_probability == null
      ? `Rule-based score ${r.rule_score}/100 (ML not active).`
      : `Rule score ${r.rule_score}/100 + ML probability ${(r.ml_probability * 100).toFixed(0)}% → hybrid ${r.risk_score}/100. A probability is not certainty.`),
    h("h3", {style: "margin-top:14px"}, "WHY?"),
    r.why.length ? h("ul", {class: "why"}, r.why.map((w) => h("li", {}, w))) : h("p", {class: "muted"}, "No phishing rules triggered."),
    h("h3", {}, "Recommended actions"), h("ul", {class: "plain"}, r.recommended_actions.map((a) => h("li", {}, a))));
  const s = r.sender_analysis;
  box.append(h("details", {open: true}, h("summary", {}, `Sender analysis - risk ${s.sender_risk_score}/100`),
    h("p", {class: "mono"}, `${s.display_name ? s.display_name + " " : ""}<${s.sender_address || "?"}>`),
    s.sender_findings.length ? sevList(s.sender_findings) : h("p", {class: "muted"}, "No sender concerns found.")));
  box.append(h("details", {open: true}, h("summary", {}, `URL analysis (${r.url_analyses.length})`),
    r.url_analyses.length ? r.url_analyses.map((u) => h("div", {}, h("p", {class: "mono"}, u.safe_representation, " - risk ", u.url_risk_score, "/100"), sevList(u.findings))) : h("p", {class: "muted"}, "No URLs found. URLs are analyzed as text only and never visited.")));
  if (r.attachment_analyses.length) box.append(h("details", {open: true}, h("summary", {}, "Attachment analysis (filename only)"),
    r.attachment_analyses.map((a) => h("div", {}, h("p", {class: "mono"}, a.filename, " - risk ", a.attachment_risk_score, "/100"), sevList(a.findings)))));
  const cf = r.content_analysis.findings;
  box.append(h("details", {}, h("summary", {}, "Content findings"), cf.length ? sevList(cf) : h("p", {class: "muted"}, "No manipulation language found.")));
  box.append(h("details", {}, h("summary", {}, "Score breakdown"), h("ul", {class: "plain"}, r.contributions.map((c) => h("li", {}, `+${c.points}  ${c.label}`)))));
  box.append(h("p", {class: "note"}, r.note));
  if (r.analysis_id) box.append(h("p", {class: "note"}, `Saved to history as #${r.analysis_id} (metadata only - the email body is not stored).`));
}

// ---------------- charts (plain DOM/SVG, no external libraries) ----------------
function hbars(el, items, empty = "No data yet") {
  clear(el); if (!items.length) return el.append(h("p", {class: "muted"}, empty));
  const max = Math.max(...items.map((i) => i.value), 1);
  items.forEach((i) => el.append(h("div", {class: "bar"}, h("span", {class: "l", title: i.label}, i.label),
    h("span", {class: "t"}, Object.assign(h("i", {}), {style: `width:${(i.value / max) * 100}%;background:${i.color || ""}`})), h("span", {class: "n"}, i.value))));
}
function vbars(el, items) {
  clear(el); const max = Math.max(...items.map((i) => i.value), 1);
  el.append(h("div", {class: "vbars"}, items.map((i) => h("div", {title: `${i.label}: ${i.value}`}, Object.assign(h("i", {}), {style: `height:${(i.value / max) * 120}px`}), i.label.split("-")[0]))));
}
function donut(el, items) {
  clear(el); const total = items.reduce((a, i) => a + i.value, 0);
  if (!total) return el.append(h("p", {class: "muted"}, "No data yet"));
  const ns = "http://www.w3.org/2000/svg", svg = document.createElementNS(ns, "svg"); svg.setAttribute("viewBox", "-60 -60 120 120"); svg.setAttribute("width", "170");
  let a0 = -Math.PI / 2;
  items.filter((i) => i.value).forEach((i) => {
    const a1 = a0 + (i.value / total) * 2 * Math.PI - 0.0001, big = a1 - a0 > Math.PI ? 1 : 0, p = document.createElementNS(ns, "path");
    const pt = (a, r) => `${r * Math.cos(a)},${r * Math.sin(a)}`;
    p.setAttribute("d", `M${pt(a0, 50)} A50,50 0 ${big} 1 ${pt(a1, 50)} L${pt(a1, 30)} A30,30 0 ${big} 0 ${pt(a0, 30)} Z`);
    p.setAttribute("fill", i.color); svg.append(p); a0 = a1 + 0.0001;
  });
  el.append(svg, h("div", {class: "legend"}, items.map((i) => h("span", {}, h("b", {style: `background:${i.color}`}), `${i.label}: ${i.value}`))));
}
function lines(el, days, series) {
  clear(el); if (!days.length) return el.append(h("p", {class: "muted"}, "No data yet"));
  const ns = "http://www.w3.org/2000/svg", W = 320, H = 150, svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H + 20}`); svg.setAttribute("width", "100%");
  const max = Math.max(...series.flatMap((s) => s.values), 1), x = (i) => 10 + (days.length === 1 ? 150 : (i * (W - 20)) / (days.length - 1));
  series.forEach((s) => {
    const pl = document.createElementNS(ns, "polyline"); pl.setAttribute("fill", "none"); pl.setAttribute("stroke", s.color); pl.setAttribute("stroke-width", "2");
    pl.setAttribute("points", s.values.map((v, i) => `${x(i)},${H - (v / max) * (H - 10)}`).join(" ")); svg.append(pl);
    s.values.forEach((v, i) => { const c = document.createElementNS(ns, "circle"); c.setAttribute("cx", x(i)); c.setAttribute("cy", H - (v / max) * (H - 10)); c.setAttribute("r", 2.5); c.setAttribute("fill", s.color); svg.append(c); });
  });
  el.append(svg, h("div", {class: "legend"}, series.map((s) => h("span", {}, h("b", {style: `background:${s.color}`}), s.name)), h("span", {}, `${days[0]} → ${days[days.length - 1]}`)));
}

// ---------------- dashboard ----------------
async function loadDashboard() {
  const days = $("#range").value;
  try {
    const [s, ind] = await Promise.all([api(`/api/dashboard/stats?days=${days}`), api(`/api/dashboard/indicators?days=${days}`)]);
    clear($("#cards")).append(...[["Total emails analyzed", s.total], ["Likely phishing", s.likely_phishing], ["Suspicious", s.suspicious], ["Moderate risk", s.moderate], ["Low risk", s.low_risk], ["Average risk score", s.average_risk]]
      .map(([l, v]) => h("div", {class: "kpi"}, h("b", {}, v), h("span", {}, l))));
    hbars($("#c-class"), Object.keys(COLORS).map((k) => ({label: k, value: s.by_classification[k] || 0, color: COLORS[k]})));
    donut($("#c-flag"), [{label: "Flagged (score ≥ 41)", value: s.flagged, color: "#ef4444"}, {label: "Not flagged", value: s.not_flagged, color: "#22c55e"}]);
    vbars($("#c-hist"), s.risk_histogram.map((b) => ({label: b.range, value: b.count})));
    hbars($("#c-ind"), ind.top_indicators.map((i) => ({label: i.type.replaceAll("_", " "), value: i.count})));
    lines($("#c-trend"), ind.trend.map((t) => t.day), [{name: "Analyzed", color: "#38bdf8", values: ind.trend.map((t) => t.total)}, {name: "Flagged", color: "#ef4444", values: ind.trend.map((t) => t.flagged || 0)}]);
    hbars($("#c-kw"), ind.top_keywords.map((k) => ({label: k.keyword, value: k.count})));
  } catch (e) { clear($("#cards")).append(h("p", {class: "muted"}, e.message)); }
  loadMl();
}
$("#range").onchange = loadDashboard;
async function loadMl() {
  const box = clear($("#ml"));
  try {
    const m = await api("/api/ml/metrics");
    box.append(h("p", {class: "muted"}, `Selected model: ${m.selected_model}. Split: ${m.split.train} train / ${m.split.validation} validation / ${m.split.test} test. ${m.notes.join(" ")}`),
      h("div", {class: "tablewrap"}, h("table", {}, h("thead", {}, h("tr", {}, ["Detector", "Accuracy", "Precision", "Recall", "F1", "FP", "FN"].map((c) => h("th", {}, c)))),
        h("tbody", {}, Object.entries(m.test_metrics).map(([n, v]) => h("tr", {}, [n, v.accuracy, v.precision, v.recall, v.f1, v.fp, v.fn].map((c) => h("td", {}, c))))))),
      h("img", {src: "/reports/confusion_matrices.png", alt: "Confusion matrices"}));
  } catch (e) { box.append(h("p", {class: "muted"}, e.message)); }
}

// ---------------- history ----------------
async function loadHistory() {
  const [sort, order] = $("#h-sort").value.split(":");
  const qs = new URLSearchParams({sort, order, q: $("#h-q").value, classification: $("#h-class").value}); [...qs].forEach(([k, v]) => !v && qs.delete(k));
  const tb = clear($("#h-table tbody"));
  try {
    const d = await api("/api/analyses?" + qs);
    d.items.forEach((a) => tb.append(h("tr", {onclick: () => showDetail(a.analysis_id)}, h("td", {}, a.analysis_id), h("td", {}, a.created_at.replace("T", " ")), h("td", {}, a.sender_domain), h("td", {}, a.subject), h("td", {}, Math.round(a.risk_score)), h("td", {}, badge(a.classification)))));
    $("#h-count").textContent = `${d.total} analyses`;
  } catch (e) { $("#h-count").textContent = e.message; }
}
["#h-q", "#h-class", "#h-sort"].forEach((s) => $(s).addEventListener("input", loadHistory));
async function showDetail(id) {
  const box = clear($("#h-detail")); box.hidden = false;
  try {
    const a = await api("/api/analyses/" + id); renderResult(box, a.result, `Analysis #${id}`);
    box.append(h("button", {class: "ghost danger", onclick: async () => {
      if (!confirm("Delete this analysis?")) return;
      try { await api("/api/analyses/" + id, {method: "DELETE"}); box.hidden = true; loadHistory(); } catch (e) { alert(e.message); }
    }}, "Delete (login required)"));
    box.scrollIntoView({behavior: "smooth"});
  } catch (e) { box.append(h("p", {}, e.message)); }
}

// ---------------- account (optional login) ----------------
async function renderAccount() {
  const box = clear($("#account")), me = await api("/api/me").catch(() => ({authenticated: false}));
  if (me.authenticated) return box.append(h("span", {class: "muted"}, me.username + " "), h("button", {class: "ghost", onclick: async () => { await api("/api/logout", {method: "POST", body: "{}"}); renderAccount(); }}, "Logout"));
  const u = h("input", {placeholder: "username", style: "width:110px"}), p = h("input", {type: "password", placeholder: "password (10+)", style: "width:130px"});
  const go = (path) => async () => { try { await api(path, {method: "POST", body: JSON.stringify({username: u.value, password: p.value})}); if (path.includes("register")) await api("/api/login", {method: "POST", body: JSON.stringify({username: u.value, password: p.value})}); renderAccount(); } catch (e) { alert(e.message); } };
  box.append(h("div", {class: "row"}, u, p, h("button", {class: "ghost", onclick: go("/api/login")}, "Login"), h("button", {class: "ghost", onclick: go("/api/register")}, "Register")));
}
renderAccount();

// ---------------- awareness ----------------
const TIPS = [
  ["Check the sender address", "Look at the real address, not just the display name. Does the domain match the organisation?"],
  ["Check domain spelling", "Look for swapped characters (rn vs m, 1 vs l), extra words, or odd endings."],
  ["Beware unexpected urgency", "'Act now' and 'within 24 hours' are designed to stop you thinking."],
  ["Inspect links before clicking", "Hover to see the destination. Raw IP addresses and shorteners deserve extra suspicion. HTTPS does not mean safe."],
  ["Never share credentials by email", "Real services do not ask you to email or type your password from a message link."],
  ["Be careful with attachments", "Unexpected files - especially .exe, .js, .zip, or names like invoice.pdf.exe - should not be opened."],
  ["Notice generic greetings", "'Dear customer' from a company that knows your name is a warning sign."],
  ["Question unusual payment requests", "Gift cards, new bank details, or rushed transfers - confirm by phone using a known number."],
  ["Notice threatening language", "Threats of suspension or legal action are pressure tactics."],
  ["Consider the context", "Were you expecting this? If not, verify through another channel and report it."],
];
$("#tips").append(...TIPS.map(([t, d]) => h("li", {}, h("b", {}, t), ": ", d)));
const CHECK = ["I recognise the sender and the address looks right", "The domain is spelled correctly", "I was expecting this message", "Nothing pressures me to act immediately", "The link destination matches what it claims", "It does not ask for my password or personal data", "Any attachment is expected and has a normal file type", "If unsure, I will verify through an official channel and report it"];
$("#checklist").append(...CHECK.map((c) => h("li", {}, h("label", {}, h("input", {type: "checkbox", onchange: () => { const n = document.querySelectorAll("#checklist input:checked").length; $("#check-msg").textContent = n === CHECK.length ? "All checks passed - proceed with normal caution." : `${n}/${CHECK.length} checks confirmed. If any is unchecked, pause and verify.`; }}), c))));
