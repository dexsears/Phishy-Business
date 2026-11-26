/* Phishy Business dashboard. Hash routes and two roles (user, admin).
   RESULTS (results.js) = statistics from the full dataset.
   SAMPLE  (sample.js)  = seeded random sample behind the filters and the admin table.
   Roles are front-end only. They hide pages, they do not protect data (see README). */
(() => {
"use strict";
const AI_URL = "";   // paste your Cloudflare Worker address here (see README)
const ADMIN_PASSCODE = "interns";   // change it here. Anyone can read it in the page source.
const $ = id => document.getElementById(id);
const R = window.RESULTS, S = window.SAMPLE;
const fail = m => { $("error").textContent = m; $("error").hidden = false; };
if (!R || !S) return fail("Data files are missing. Run analysis.py to create results.js and sample.js, then refresh.");
if (typeof Chart === "undefined") return fail("The chart library did not load. Check your internet connection and refresh.");

const PH = "#ff6a3d", LG = "#2bb5a0", GRID = "#223044";
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
Chart.defaults.color = "#93a1b5"; Chart.defaults.borderColor = GRID;
Chart.defaults.font.family = '"IBM Plex Sans","Segoe UI",Arial,sans-serif';
const fmt = n => n.toLocaleString("en-US");
const pc = (a, b) => b ? (a / b * 100).toFixed(1) : "0";
const mean = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;
const median = a => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const show = x => x == null ? "-" : +x.toFixed(1);
const pText = p => p < 0.001 ? "less than 0.001" : p.toFixed(3);
const T = R.test, L = R.numeric.url_length, hy = R.numeric.hyphens, CAP = R.length_cap, BINS = 20, W = CAP / BINS;
const rows = S.label.map((l, i) => ({ph: l === S.meta.phishing_label, len: S.url_length[i], dots: S.dots[i],
  hy: S.hyphens[i], https: !!S.https[i], at: !!S.at_symbol[i], tld: S.tld[i]}));
if (R.demo || S.meta.demo) $("demo").hidden = false;

// ---- text built from results.js
const keep = `Legitimate URLs here are much alike (length standard deviation ${L.legit.sd} vs ${L.phish.sd} for phishing, and ${R.binary.https.legit_pct}% use HTTPS), so the findings apply in this dataset. HTTPS alone does not make a site safe, because ${R.binary.https.phish_pct}% of phishing sites use it.`;
const reco = T.significant
  ? `Treat a very long link with extra care${hy.phish.mean > hy.legit.mean ? ", especially one with several hyphens" : ""}. Do not trust a link only because it starts with https, since ${R.binary.https.phish_pct}% of phishing sites in this data use it. Awareness teams can teach students to check link length and the web address ending before they click.`
  : `URL length alone did not separate the two groups, so training should not rely on it. Look at hyphens and HTTPS for other warning signs. Check these findings on a larger and more varied dataset.`;
const cite = `Prasad &amp; Chandra (2024), PhiUSIIL Phishing URL Dataset, UCI Machine Learning Repository, CC BY 4.0, <a href="https://doi.org/10.1016/j.cose.2023.103545">doi.org/10.1016/j.cose.2023.103545</a>`;
$("foot").innerHTML = `Data ${cite}. Group Unpaid Interns.`;

// ---- session and roles
let mem = null;
const role = {
  get: () => { try { return sessionStorage.getItem("pb-role") || mem; } catch { return mem; } },
  set: v => { mem = v; try { v ? sessionStorage.setItem("pb-role", v) : sessionStorage.removeItem("pb-role"); } catch {} }};

// ---- explore state and chart views
const st = {view: "length", type: "all", https: "all", min: 0, max: CAP, tld: "all"};
const pass = (r, f, skipType, skipTld) =>
  (skipType || f.type === "all" || (f.type === "phish") === r.ph) &&
  (f.https === "all" || (f.https === "yes") === r.https) && r.len >= f.min && (f.max >= CAP || r.len <= f.max) &&
  (skipTld || f.tld === "all" || r.tld === f.tld);
const two = (a, b) => [{label: "Phishing", data: a, backgroundColor: PH}, {label: "Legitimate", data: b, backgroundColor: LG}];
const bin = a => { const c = Array(BINS).fill(0); a.forEach(r => c[Math.min(BINS - 1, Math.floor(r.len / W))]++); return c; };
const avg = (a, k) => { const m = mean(a.map(r => r[k])); return m == null ? null : +m.toFixed(2); };
const share = (a, k) => a.length ? +(a.filter(r => r[k]).length / a.length * 100).toFixed(1) : null;
const VIEWS = {
  length: {tab: "URL length", title: "How long are the URLs?", cap: "Each bar counts sites with a URL of that length. Orange bars further right mean longer phishing links.",
    build: (a, p, l) => ({labels: Array.from({length: BINS}, (_, i) => i === BINS - 1 ? `${CAP}+` : `${Math.round(i * W)}-${Math.round((i + 1) * W)}`),
      sets: two(bin(p), bin(l)), x: "URL length (characters)", y: "Number of sites"})},
  chars: {tab: "Dots and hyphens", title: "Do phishing URLs use more dots and hyphens?", cap: "Average count per URL in each group. A taller bar means that character shows up more often.",
    build: (a, p, l) => ({labels: ["Dots", "Hyphens"], sets: two([avg(p, "dots"), avg(p, "hy")], [avg(l, "dots"), avg(l, "hy")]), x: "Character counted", y: "Average per URL"})},
  flags: {tab: "HTTPS and @", title: "How many sites use HTTPS or an @ symbol?", cap: "Share of sites in each group with the feature. Many phishing sites use HTTPS too.",
    build: (a, p, l) => ({labels: ["Uses HTTPS", "Has an @ symbol"], sets: two([share(p, "https"), share(p, "at")], [share(l, "https"), share(l, "at")]), x: "Feature", y: "Share of sites (%)", ymax: 100})},
  ends: {tab: "Address endings", title: "Which address endings are most often phishing?", cap: "Among the 10 most common endings (TLDs), the share of sites that are phishing. This view ignores the site type filter.",
    build: () => {
      const by = {}; rows.filter(r => pass(r, st, true, true)).forEach(r => { const o = by[r.tld] ||= {n: 0, p: 0}; o.n++; o.p += r.ph; });
      const t = Object.entries(by).sort((a, b) => b[1].n - a[1].n).slice(0, 10).map(([k, o]) => ({k, n: o.n, s: +(o.p / o.n * 100).toFixed(1)})).sort((a, b) => b.s - a.s);
      return {labels: t.map(o => `.${o.k} (${fmt(o.n)} sites)`), sets: [{data: t.map(o => o.s), backgroundColor: t.map(o => o.k === st.tld ? "#e7ecf3" : PH)}],
        x: "Phishing share (% of sites with that ending)", y: "Address ending (TLD)", h: true, nolegend: true};}}
};
const mkOpts = c => ({responsive: true, maintainAspectRatio: false, animation: reduce ? false : {duration: 500}, indexAxis: c.h ? "y" : "x",
  plugins: {legend: {display: !c.nolegend, position: "bottom", labels: {boxWidth: 12}}},
  scales: {x: {beginAtZero: true, max: c.h ? 100 : undefined, title: {display: true, text: c.x}, grid: {display: !!c.h, color: GRID}},
           y: {beginAtZero: true, max: c.h ? undefined : c.ymax, title: {display: true, text: c.y}, grid: {color: GRID}}}});
const topTld = Object.entries(rows.reduce((m, r) => (m[r.tld] = (m[r.tld] || 0) + 1, m), {})).sort((a, b) => b[1] - a[1]).slice(0, 10);
let chart = null;

function upd() {
  const all = rows.filter(r => pass(r, st)), ph = all.filter(r => r.ph), lg = all.filter(r => !r.ph), V = VIEWS[st.view];
  $("oMin").textContent = st.min; $("oMax").textContent = st.max >= CAP ? `${CAP} or more` : st.max;
  document.querySelectorAll(".seg button").forEach(b => b.setAttribute("aria-pressed", b.dataset.v === st.view));
  $("read").innerHTML = [["Sites in view", fmt(all.length)], ["Phishing share", all.length ? pc(ph.length, all.length) + "%" : "-"],
    ["Median URL length", `${show(median(ph.map(r => r.len)))} vs ${show(median(lg.map(r => r.len)))}`]]
    .map(([k, v]) => `<div class="panel"><span>${k}</span><b>${v}</b></div>`).join("");
  $("vTitle").textContent = V.title; $("vCap").textContent = V.cap; $("cv").setAttribute("aria-label", V.title);
  $("chartBox").classList.toggle("is-empty", !all.length);
  const c = V.build(all, ph, lg);
  chart.data.labels = c.labels; chart.data.datasets = c.sets; chart.options = mkOpts(c); chart.update();
}

// ---- admin table
const COLS = [["ph", "Type"], ["len", "URL length"], ["dots", "Dots"], ["hy", "Hyphens"], ["https", "HTTPS"], ["at", "@ symbol"], ["tld", "TLD"]];
const cell = (r, k) => k === "ph" ? (r.ph ? "Phishing" : "Legitimate") : (k === "https" || k === "at") ? (r[k] ? "Yes" : "No") : r[k];
const d = {q: "", type: "all", key: "len", dir: -1, page: 0}, PS = 20;
let listNow = [];
function drawTable() {
  const q = d.q.trim().toLowerCase();
  listNow = rows.filter(r => (d.type === "all" || (d.type === "phish") === r.ph) && (!q || r.tld.includes(q)))
    .sort((a, b) => d.dir * (a[d.key] > b[d.key] ? 1 : a[d.key] < b[d.key] ? -1 : 0));
  const pages = Math.max(1, Math.ceil(listNow.length / PS)); d.page = Math.min(d.page, pages - 1);
  const slice = listNow.slice(d.page * PS, (d.page + 1) * PS);
  $("tbl").innerHTML = `<table class="tbl"><thead><tr>${COLS.map(([k, l]) => `<th scope="col" aria-sort="${d.key === k ? (d.dir > 0 ? "ascending" : "descending") : "none"}"><button data-k="${k}">${l}</button></th>`).join("")}</tr></thead>
    <tbody>${slice.map(r => `<tr>${COLS.map(([k]) => `<td>${cell(r, k)}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="7">Nothing suspicious here. Yet. No records match.</td></tr>`}</tbody></table>`;
  $("pg").textContent = listNow.length ? `${d.page * PS + 1}-${d.page * PS + slice.length} of ${fmt(listNow.length)}` : "0 records";
  $("prev").disabled = d.page === 0; $("next").disabled = d.page >= pages - 1;
}

// ---- pages
const pages = {}, mount = {};
pages.login = () => `<section class="login"><h1 data-enter>Phishy Business</h1>
  <p class="lead" data-enter style="--d:.1s">Because some links are looking kinda suspicious. Choose how you want to enter.</p>
  <div class="roles" data-enter style="--d:.2s">
    <div class="panel"><h2>User</h2><p>Browse the overview, explore the charts and read the findings.</p><p><button id="asUser" class="btn" type="button">Enter as user</button></p></div>
    <form id="adminForm" class="panel"><h2>Admin</h2><p>Everything a user sees, plus the data table and pipeline details.</p>
      <p><label for="pass">Passcode</label><input id="pass" type="password" autocomplete="off"></p><p id="passErr" class="err" role="alert"></p>
      <button class="btn" type="submit">Sign in as admin</button></form></div></section>`;
mount.login = () => {
  const go = r => { role.set(r); location.hash = "#/overview"; route(); };
  $("asUser").onclick = () => go("user");
  $("adminForm").onsubmit = e => { e.preventDefault(); $("pass").value === ADMIN_PASSCODE ? go("admin") : ($("passErr").textContent = "That passcode does not match. Try again."); };
};
pages.locked = () => `<h1>Admin only</h1><p class="lead">This page is for admins. Sign out, then sign in with the admin passcode.</p><a class="btn" href="#/overview">Back to overview</a>`;
pages.overview = () => `<section class="hero">
  <h1 data-enter style="--d:.05s">Do phishing links look different from real ones?</h1>
  <p class="lead" data-enter style="--d:.2s">We compared the web addresses of ${fmt(R.n)} websites to see which features give a fake link away.</p>
  <p class="url" data-enter style="--d:.35s" role="img" aria-label="Example of a suspicious web address with no HTTPS, extra hyphens and an @ symbol"><mark style="--d:1.2s">http</mark>://secure<mark style="--d:1.6s">-</mark>login<mark style="--d:1.8s">-</mark>bank.verify<mark style="--d:2s">-</mark>account.example.com/<mark style="--d:2.4s">@</mark>signin</p>
  <p class="flagged">Flagged above. No HTTPS, extra hyphens and an @ symbol.</p>
  <div class="read">
    <div class="panel"><span>Median URL length, in characters</span><b><i class="dot" style="background:${PH}"></i><i data-count="${L.phish.median}">${L.phish.median}</i> <i class="dot" style="background:${LG}"></i><i data-count="${L.legit.median}">${L.legit.median}</i></b><small>Phishing, then legitimate. Full dataset.</small></div>
    <div class="panel"><span>Phishing sites that use HTTPS</span><b><i data-count="${R.binary.https.phish_pct}" data-sfx="%">${R.binary.https.phish_pct}%</i></b><small>Legitimate sites ${R.binary.https.legit_pct}%. Full dataset.</small></div>
    <div class="panel"><span>Is the length gap real?</span><b class="badge">${T.significant ? "Significant" : "Not significant"}</b><small>p ${T.p < 0.001 ? "less than 0.001" : "= " + pText(T.p)}, ${T.effect_name} ${T.effect} (${T.effect_label}).</small></div>
  </div>
  <div class="actions"><a class="btn" href="#/explore">Explore the data</a><a class="btn ghost" href="#/findings">Read the findings</a></div>
  <h2 class="sec">What is in the data</h2>
  <div class="panel">
    <div class="split" role="img" aria-label="${pc(R.n_phish, R.n)}% of sites are phishing and ${pc(R.n_legit, R.n)}% are legitimate"><span style="--w:${pc(R.n_phish, R.n)}%;background:${PH}"></span><span style="--w:${pc(R.n_legit, R.n)}%;background:${LG}"></span></div>
    <p class="legend"><span><i class="dot" style="background:${PH}"></i>Phishing ${fmt(R.n_phish)} (${pc(R.n_phish, R.n)}%)</span><span><i class="dot" style="background:${LG}"></i>Legitimate ${fmt(R.n_legit)} (${pc(R.n_legit, R.n)}%)</span></p>
    <p>Each site is one web address, marked as phishing or legitimate. We count its length, dots, hyphens, HTTPS and @ symbol straight from the address text.</p>
  </div>
  <h2 class="sec">What we checked</h2>
  <div class="cards">
    <a class="panel link" href="#/explore" data-go="length"><h2>URL length</h2><b>${L.phish.median} vs ${L.legit.median}</b><p>Median characters, phishing vs legitimate.</p><small>See the chart</small></a>
    <a class="panel link" href="#/explore" data-go="chars"><h2>Dots and hyphens</h2><b>${hy.phish.mean} vs ${hy.legit.mean}</b><p>Hyphens per URL on average.</p><small>See the chart</small></a>
    <a class="panel link" href="#/explore" data-go="flags"><h2>HTTPS and @</h2><b>${R.binary.https.phish_pct}% vs ${R.binary.https.legit_pct}%</b><p>Sites that use HTTPS.</p><small>See the chart</small></a>
    <a class="panel link" href="#/explore" data-go="ends"><h2>Address endings</h2><b>Top 10</b><p>The most common endings and how often each is phishing.</p><small>See the chart</small></a>
  </div></section>`;
mount.overview = () => document.querySelectorAll("[data-go]").forEach(a => a.addEventListener("click", () => { st.view = a.dataset.go; }));
pages.explore = () => `<h1>Explore the data</h1><p class="lead">Pick a view, then narrow it with the filters. Charts use a random sample of ${fmt(S.meta.size)} sites.</p>
  <div class="seg" role="group" aria-label="Chart views">${Object.entries(VIEWS).map(([k, v]) => `<button type="button" data-v="${k}" aria-pressed="false">${v.tab}</button>`).join("")}</div>
  <div class="filters" role="group" aria-label="Filters">
    <div><label for="fType">Site type</label><select id="fType"><option value="all">All sites</option><option value="phish">Phishing</option><option value="legit">Legitimate</option></select></div>
    <div><label for="fHttps">Uses HTTPS</label><select id="fHttps"><option value="all">All</option><option value="yes">Yes</option><option value="no">No</option></select></div>
    <div><label for="fTld">Address ending</label><select id="fTld"><option value="all">All endings</option>${topTld.map(([t, n]) => `<option value="${t}">.${t} (${fmt(n)})</option>`).join("")}</select></div>
    <div><label for="fMin">Shortest URL<output id="oMin"></output></label><input id="fMin" type="range" min="0" max="${CAP}" step="1"></div>
    <div><label for="fMax">Longest URL<output id="oMax"></output></label><input id="fMax" type="range" min="0" max="${CAP}" step="1"></div>
    <div><button id="reset" class="btn ghost" type="button">Reset filters</button></div></div>
  <div class="read" id="read"></div>
  <section class="panel"><h2 id="vTitle"></h2><div class="chart" id="chartBox"><canvas id="cv" role="img"></canvas><p class="empty">Nothing suspicious here. Yet. No sites match these filters.</p></div><p class="cap" id="vCap"></p></section>`;
mount.explore = () => {
  const sync = () => { $("fType").value = st.type; $("fHttps").value = st.https; $("fTld").value = st.tld; $("fMin").value = st.min; $("fMax").value = st.max; };
  sync();
  chart = new Chart($("cv"), {type: "bar", data: {labels: [], datasets: []}, options: {}});
  document.querySelectorAll(".seg button").forEach(b => b.onclick = () => { st.view = b.dataset.v; upd(); });
  const read = () => { Object.assign(st, {type: $("fType").value, https: $("fHttps").value, tld: $("fTld").value, min: +$("fMin").value, max: +$("fMax").value}); upd(); };
  ["fType", "fHttps", "fTld"].forEach(id => $(id).addEventListener("change", read));
  $("fMin").addEventListener("input", () => { if (+$("fMin").value > +$("fMax").value) $("fMax").value = $("fMin").value; read(); });
  $("fMax").addEventListener("input", () => { if (+$("fMax").value < +$("fMin").value) $("fMin").value = $("fMax").value; read(); });
  $("reset").onclick = () => { Object.assign(st, {type: "all", https: "all", tld: "all", min: 0, max: CAP}); sync(); upd(); };
  upd();
};
pages.findings = () => `<h1 data-enter>${T.conclusion}</h1>
  <ol class="steps"><li><b>The question.</b> Are phishing URLs longer than legitimate URLs? We start by assuming both groups have the same length, and drop that idea only if p is below ${T.alpha}.</li>
    <li><b>The test.</b> ${T.name}. ${T.reason}</li>
    <li><b>The result.</b> p is ${pText(T.p)}. The effect size is ${T.effect_name} ${T.effect}, which is ${T.effect_label}. This uses all ${fmt(R.n)} sites.</li></ol>
  <div class="panel"><h2>What we recommend</h2><p>${reco}</p></div>
  <div class="panel" style="margin-top:14px"><h2>Keep in mind</h2><p>${keep}</p></div>`;
pages.about = () => `<div class="prose"><h1>About and methods</h1>
  <h2>Question</h2><p>Are phishing URLs longer than legitimate URLs?</p>
  <h2>Data source</h2><p>PhiUSIIL Phishing URL dataset (UCI, id 967), ${fmt(R.n)} sites, ${fmt(R.n_phish)} phishing and ${fmt(R.n_legit)} legitimate. ${cite}.</p>
  <h2>How the numbers work</h2><p>The test result and every "full dataset" line use all sites. The Explore charts and filters use a random sample of ${fmt(S.meta.size)} sites (seed ${S.meta.seed}) with the same phishing and legitimate mix. Length, dots, hyphens, HTTPS and @ are counted from the URL text.</p>
  <h2>Limits</h2><ul><li>${keep}</li><li>This is an offline study of one dataset. It does not check live websites.</li><li>A difference in length does not show that length causes phishing.</li></ul></div>`;
pages.data = () => `<h1>Data</h1><p class="lead">Admin view of the pipeline and the sample records behind the charts.</p>
  <div class="kv"><div><span>Data mode</span><b>${R.demo ? "Demo (simulated)" : "Real dataset"}</b></div><div><span>Source file</span><b>${R.source}</b></div>
    <div><span>Sites in full dataset</span><b>${fmt(R.n)}</b></div><div><span>Sites in sample</span><b>${fmt(S.meta.size)}</b></div>
    <div><span>Sample seed</span><b>${S.meta.seed}</b></div><div><span>Test used</span><b>${T.name}</b></div></div>
  <div class="row"><div><label for="dq">Search address ending</label><input id="dq" placeholder="com"></div>
    <div><label for="dt">Site type</label><select id="dt"><option value="all">All sites</option><option value="phish">Phishing</option><option value="legit">Legitimate</option></select></div>
    <div><button id="csv" class="btn" type="button">Export CSV</button></div></div>
  <div class="tw" id="tbl"></div>
  <div class="pager"><button id="prev" class="btn ghost" type="button">Previous</button><span id="pg" role="status"></span><button id="next" class="btn ghost" type="button">Next</button></div>`;
mount.data = () => {
  drawTable();
  $("dq").oninput = e => { d.q = e.target.value; d.page = 0; drawTable(); };
  $("dt").onchange = e => { d.type = e.target.value; d.page = 0; drawTable(); };
  $("prev").onclick = () => { d.page--; drawTable(); }; $("next").onclick = () => { d.page++; drawTable(); };
  $("tbl").onclick = e => { const k = e.target.dataset.k; if (!k) return; d.dir = d.key === k ? -d.dir : 1; d.key = k; drawTable(); $("tbl").querySelector(`[data-k="${k}"]`).focus(); };
  $("csv").onclick = () => {
    const csv = "type,url_length,dots,hyphens,https,at_symbol,tld\n" + listNow.map(r => [r.ph ? "phishing" : "legitimate", r.len, r.dots, r.hy, +r.https, +r.at, r.tld].join(",")).join("\n");
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], {type: "text/csv"})); a.download = "phishy-business-sample.csv"; a.click(); URL.revokeObjectURL(a.href);
  };
};

// ---- AI assistant (talks to the Cloudflare Worker, never to Groq directly)
const intro = {role: "assistant", local: true, content: "Hi. I can explain the findings, walk you through the chart you are on, or look at a link you paste. I cannot open links, so I judge them only from how they look."};
let chat = [intro], busy = false;
const fab = Object.assign(document.createElement("button"), {id: "askBtn", type: "button", className: "btn fab", textContent: "Ask AI", hidden: true});
fab.setAttribute("aria-expanded", "false"); fab.setAttribute("aria-controls", "chat");
const box = document.createElement("section"); box.id = "chat"; box.hidden = true; box.setAttribute("aria-label", "AI assistant");
box.innerHTML = `<header><h2>Ask AI</h2><button id="chatClose" class="btn ghost" type="button">Close</button></header>
  <div id="msgs" aria-live="polite"></div>
  <div id="chips"><button type="button">Explain this page</button><button type="button">What should I look out for?</button><button type="button" data-fill="Check this link ">Check a link</button></div>
  <form id="chatForm"><label for="chatIn" class="vh">Your question</label><textarea id="chatIn" rows="2" maxlength="1500" placeholder="Ask about the findings or paste a link"></textarea><button class="btn" type="submit">Send</button></form>
  <p class="fine">AI can be wrong. It only sees the dashboard numbers and links you paste, and it cannot open websites.</p>`;
document.body.append(fab, box);
function paint() {
  $("msgs").innerHTML = "";
  chat.forEach(m => { const d = document.createElement("div"); d.className = `msg ${m.role}${m.content ? "" : " pending"}`; d.textContent = m.content || "Inspecting the evidence..."; $("msgs").append(d); });
  $("msgs").scrollTop = 1e9;
}
function resetChat() { chat = [intro]; busy = false; paint(); }
function setChat(open) { box.hidden = !open; fab.setAttribute("aria-expanded", open); if (open) { paint(); $("chatIn").focus(); } else fab.focus(); }
function ctx(text) {   // facts sent with each question. Every number comes from results.js or the sample.
  const d = R.numeric.dots, b = R.binary;
  let c = `${R.demo ? "These numbers are simulated demo data. " : ""}Full dataset ${fmt(R.n)} sites (${fmt(R.n_phish)} phishing, ${fmt(R.n_legit)} legitimate). Median URL length ${L.phish.median} phishing vs ${L.legit.median} legitimate. Mean hyphens ${hy.phish.mean} vs ${hy.legit.mean}. Mean dots ${d.phish.mean} vs ${d.legit.mean}. HTTPS ${b.https.phish_pct}% vs ${b.https.legit_pct}%. @ symbol ${b.at_symbol.phish_pct}% vs ${b.at_symbol.legit_pct}%. Test ${T.name}, p ${pText(T.p)}, ${T.effect_name} ${T.effect} (${T.effect_label}). ${T.conclusion} ${keep} Recommendation. ${reco} The user is on the ${prev} page.`;
  if (prev === "explore") {
    const a = rows.filter(r => pass(r, st)), p = a.filter(r => r.ph), l = a.filter(r => !r.ph);
    c += ` Chart shown. ${VIEWS[st.view].title} Filters site type ${st.type}, HTTPS ${st.https}, ending ${st.tld}, length ${st.min} to ${st.max >= CAP ? "any" : st.max}. In view ${a.length} sample sites, ${pc(p.length, a.length)}% phishing, median length ${show(median(p.map(r => r.len)))} vs ${show(median(l.map(r => r.len)))}.`;
  }
  const m = text.match(/(https?:\/\/|www\.)\S+/i);
  if (m) {
    const u = m[0]; let tld = ""; try { tld = new URL(/^https?:/i.test(u) ? u : "http://" + u).hostname.split(".").pop(); } catch {}
    c += ` LINK FEATURES for the pasted link. Length ${u.length}, dots ${(u.match(/\./g) || []).length}, hyphens ${(u.match(/-/g) || []).length}, @ symbol ${u.includes("@") ? "yes" : "no"}, HTTPS ${/^https:/i.test(u) ? "yes" : /^http:/i.test(u) ? "no" : "not shown"}, ending .${tld}.`;
  }
  return c;
}
async function send(text) {
  text = text.trim().slice(0, 1500); if (!text || busy) return;
  if (!AI_URL) { chat.push({role: "user", content: text, local: true}, {role: "assistant", local: true, content: "The AI is not set up yet. Deploy worker.js to Cloudflare and paste its address into AI_URL at the top of app.js. The README has the steps."}); paint(); return; }
  busy = true; chat.push({role: "user", content: text});
  const hist = chat.filter(m => !m.local).slice(-10), a = {role: "assistant", content: ""}; chat.push(a); paint();
  try {
    const res = await fetch(AI_URL, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({messages: hist.map(m => ({role: m.role, content: m.content})), context: ctx(text)})});
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `status ${res.status}`);
    const rd = res.body.getReader(), dec = new TextDecoder(); let buf = "";
    for (;;) {
      const {done, value} = await rd.read(); if (done) break;
      buf += dec.decode(value, {stream: true}); const lines = buf.split("\n"); buf = lines.pop();
      for (const l of lines) { if (!l.startsWith("data: ") || l.includes("[DONE]")) continue;
        try { const t = JSON.parse(l.slice(6)).choices[0].delta.content; if (t) { a.content += t; paint(); } } catch {} }
    }
  } catch (e) { a.content = a.content || `Sorry, I could not reach the assistant (${e.message}). Try again.`; }
  busy = false; paint();
}
fab.onclick = () => setChat(box.hidden);
$("chatClose").onclick = () => setChat(false);
box.addEventListener("keydown", e => { if (e.key === "Escape") setChat(false); });
$("chatForm").onsubmit = e => { e.preventDefault(); const t = $("chatIn").value; $("chatIn").value = ""; send(t); };
$("chatIn").addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("chatForm").requestSubmit(); } });
$("chips").onclick = e => { const b = e.target.closest("button"); if (!b) return;
  if (b.dataset.fill) { $("chatIn").value = b.dataset.fill; $("chatIn").focus(); } else send(b.textContent === "Explain this page" ? "Explain what I am looking at on this page in plain words." : b.textContent); };

// ---- router
const NAV = [["overview", "Overview"], ["explore", "Explore"], ["findings", "Findings"], ["about", "About"], ["data", "Data", "admin"]];
let prev = null;
function countUp(root) {
  root.querySelectorAll("[data-count]").forEach(el => {
    if (reduce) return;
    const to = +el.dataset.count, dec = (el.dataset.count.split(".")[1] || "").length, sfx = el.dataset.sfx || "", t0 = performance.now();
    const step = t => { const k = Math.min(1, (t - t0) / 900), e = 1 - Math.pow(1 - k, 3); el.textContent = (to * e).toFixed(dec) + sfx; if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  });
}
function route() {
  const r = role.get(), name = location.hash.replace(/^#\/?/, "") || "overview", v = $("view");
  let page = !r ? "login" : NAV.some(n => n[0] === name) ? name : "overview";
  if (page === "data" && r !== "admin") page = "locked";
  if (chart) { chart.destroy(); chart = null; }
  document.querySelector(".shell").classList.toggle("out", !r);
  v.innerHTML = pages[page]();
  v.classList.remove("enter"); void v.offsetWidth; v.classList.add("enter");
  $("links").innerHTML = NAV.filter(n => !n[2] || n[2] === r).map(n => `<a href="#/${n[0]}"${n[0] === page ? ' aria-current="page"' : ""}>${n[1]}</a>`).join("");
  $("who").textContent = r ? `Signed in as ${r}` : "";
  $("out").hidden = !r;
  fab.hidden = !r; if (!r) { box.hidden = true; fab.setAttribute("aria-expanded", "false"); resetChat(); }
  document.title = (page === "login" ? "Sign in" : (NAV.find(n => n[0] === page) || [0, "Admin only"])[1]) + " | Phishy Business";
  countUp(v); (mount[page] || (() => {}))();
  window.scrollTo(0, 0);
  if (prev && prev !== page) v.focus({preventScroll: true});
  prev = page;
}
$("out").onclick = () => { role.set(null); location.hash = "#/login"; route(); };
window.addEventListener("hashchange", route);
route();
})();
