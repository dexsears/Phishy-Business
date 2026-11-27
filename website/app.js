/* Phishy Business dashboard. Hash routes and two roles (user, admin).
   RESULTS (results.js) = statistics from the full dataset.
   SAMPLE  (sample.js)  = seeded random sample behind the filters and the admin table.
   Roles are front-end only. They hide pages, they do not protect data (see README). */
(() => {
"use strict";
const AI_URL = "https://phishician.dsbucane.workers.dev/";   // paste your Cloudflare Worker address here (see README)
const AI_NAME = "Phishician";   // name shown on the chat button
const ADMIN_PASSCODE = "interns";   // change it here. Anyone can read it in the page source.
const $ = id => document.getElementById(id);
const R = window.RESULTS, S = window.SAMPLE;
const fail = m => { $("error").textContent = m; $("error").hidden = false; };
if (!R || !S) return fail("Data files are missing. Run analysis.py to create results.js and sample.js, then refresh.");
if (typeof Chart === "undefined") return fail("The chart library did not load. Check your internet connection and refresh.");

const PH = "#ff6a3d", LG = "#2bb5a0", GRID = "#1b2b42";
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
// Pause motion button. The "calm" class on <html> stops every animation (see styles.css).
const htmlEl = document.documentElement;
try { if (sessionStorage.getItem("pb-calm") === "1") htmlEl.classList.add("calm"); } catch {}
const calm = () => reduce || htmlEl.classList.contains("calm");
Chart.defaults.color = "#93a4bb"; Chart.defaults.borderColor = GRID;
Chart.defaults.elements.bar.borderRadius = 4;   // softer bars
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Object.assign(Chart.defaults.plugins.tooltip, {backgroundColor: "#0a1424", borderColor: "#2c4260", borderWidth: 1, padding: 10, cornerRadius: 6, titleColor: "#eaf0f8", bodyColor: "#c5d0df"});
Chart.defaults.font.family = '"IBM Plex Sans","Segoe UI",Arial,sans-serif'; Chart.defaults.font.size = 11;
const fmt = n => n.toLocaleString("en-US");
const num = n => `<span data-count="${n}">${fmt(n)}</span>`;   // number that counts up when it appears
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
$("foot").innerHTML = `Data ${cite}. <span class="team-sm"><svg class="badge-ic" viewBox="0 0 32 32" width="16" height="16" aria-hidden="true" focusable="false"><path d="M12 1v7M20 1v7" stroke="#e0b862" stroke-width="1.4" stroke-linecap="round" fill="none"/><rect x="13" y="5" width="6" height="4" rx="1.2" fill="#e0b862"/><rect x="5" y="8" width="22" height="22" rx="3.5" fill="#14243a" stroke="#e0b862" stroke-width="1.4"/><circle cx="16" cy="16.5" r="3.2" fill="#e0b862"/><path d="M9.8 26c0-3.6 2.8-5.4 6.2-5.4s6.2 1.8 6.2 5.4Z" fill="#e0b862"/></svg>Group Unpaid Interns</span>.`;

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
    build: (a, p, l, f = st) => {
      const by = {}; rows.filter(r => pass(r, f, true, true)).forEach(r => { const o = by[r.tld] ||= {n: 0, p: 0}; o.n++; o.p += r.ph; });
      const t = Object.entries(by).sort((a, b) => b[1].n - a[1].n).slice(0, 10).map(([k, o]) => ({k, n: o.n, s: +(o.p / o.n * 100).toFixed(1)})).sort((a, b) => b.s - a.s);
      return {labels: t.map(o => `.${o.k} (${fmt(o.n)} sites)`), sets: [{data: t.map(o => o.s), backgroundColor: t.map(o => o.k === f.tld ? "#e7ecf3" : PH)}],
        x: "Phishing share (% of sites with that ending)", y: "Address ending (TLD)", h: true, nolegend: true};}}
};
// base = wait before the chart starts (ms). slow = long staggered draw (first draw) or quick update (filters).
const mkOpts = (c, base = 0, slow = true) => ({responsive: true, maintainAspectRatio: false, indexAxis: c.h ? "y" : "x",
  animation: calm() ? false : {duration: slow ? 1700 : 600, easing: "easeOutQuart",
    delay: x => slow && x.type === "data" && x.mode === "default" ? base + x.dataIndex * 55 + x.datasetIndex * 160 : 0},
  plugins: {legend: {display: !c.nolegend, position: "top", align: "end", labels: {boxWidth: 10}}},
  scales: {x: {beginAtZero: true, max: c.h ? 100 : undefined, title: {display: true, text: c.x}, grid: {display: !!c.h, color: GRID}},
           y: {beginAtZero: true, max: c.h ? undefined : c.ymax, title: {display: true, text: c.y}, grid: {color: GRID}}}});
const topTld = Object.entries(rows.reduce((m, r) => (m[r.tld] = (m[r.tld] || 0) + 1, m), {})).sort((a, b) => b[1] - a[1]).slice(0, 10);
let chart = null, charts = [], firstDraw = true;

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
  chart.data.labels = c.labels; chart.data.datasets = c.sets; const slow = firstDraw; firstDraw = false; chart.options = mkOpts(c, 500, slow); chart.update();
}

// ---- admin table
const COLS = [["ph", "Type"], ["len", "URL length"], ["dots", "Dots"], ["hy", "Hyphens"], ["https", "HTTPS"], ["at", "@ symbol"], ["tld", "TLD"]];
const cell = (r, k) => k === "ph" ? (r.ph ? "Phishing" : "Legitimate") : (k === "https" || k === "at") ? (r[k] ? "Yes" : "No") : r[k];
const d = {q: "", type: "all", key: "len", dir: -1, page: 0}, PS = 20;
let listNow = [];
function drawTable(anim) {
  const q = d.q.trim().toLowerCase();
  listNow = rows.filter(r => (d.type === "all" || (d.type === "phish") === r.ph) && (!q || r.tld.includes(q)))
    .sort((a, b) => d.dir * (a[d.key] > b[d.key] ? 1 : a[d.key] < b[d.key] ? -1 : 0));
  const pages = Math.max(1, Math.ceil(listNow.length / PS)); d.page = Math.min(d.page, pages - 1);
  const slice = listNow.slice(d.page * PS, (d.page + 1) * PS);
  $("tbl").innerHTML = `<table class="tbl"><thead><tr>${COLS.map(([k, l]) => `<th scope="col" aria-sort="${d.key === k ? (d.dir > 0 ? "ascending" : "descending") : "none"}"><button data-k="${k}">${l}</button></th>`).join("")}</tr></thead>
    <tbody>${slice.map((r, i) => `<tr${anim ? ` class="in" style="--i:${i}"` : ""}>${COLS.map(([k]) => `<td>${cell(r, k)}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="7">Nothing suspicious here. Yet. No records match.</td></tr>`}</tbody></table>`;
  $("pg").textContent = listNow.length ? `${d.page * PS + 1}-${d.page * PS + slice.length} of ${fmt(listNow.length)}` : "0 records";
  $("prev").disabled = d.page === 0; $("next").disabled = d.page >= pages - 1;
}

// ---- pages
const pages = {}, mount = {};
pages.login = () => `<div class="auth">
  <section class="brand" aria-label="About Phishy Business">
    <a class="logo" href="#/login"><svg class="fish" viewBox="0 0 32 32" width="26" height="26" aria-hidden="true" focusable="false"><path d="M9.5 1.5v7.2" fill="none" stroke="#e0b862" stroke-width="1.4" stroke-linecap="round"/><path d="M9.5 8.7c0 3-2.9 2.6-2.9.6" fill="none" stroke="#e0b862" stroke-width="1.4" stroke-linecap="round"/><g class="tail"><path d="M20 17.5L29.5 10.5Q27.2 17.5 29.5 24.5Z" fill="#2bb5a0"/></g><path d="M2.5 17.5C5.5 11 13 9.6 19 13l2.2 2.3v4.4L19 22c-6 3.4-13.5 2.2-16.5-4.5Z" fill="#ff6a3d"/><path d="M12.5 14.3Q14.7 17.5 12.5 20.7" fill="none" stroke="#08101c" stroke-opacity=".35" stroke-width="1.2" stroke-linecap="round"/><circle cx="7.8" cy="16.3" r="1.6" fill="#08101c"/><circle cx="8.3" cy="15.8" r=".5" fill="#fff"/></svg>Phishy Business</a>
    <div>
      <h1 data-enter>Do phishing links look different from real ones?</h1>
      <p data-enter style="--d:.1s">A research platform that compares the web addresses of phishing and legitimate sites, so awareness teams know which signs to teach.</p>
      <p class="url" data-enter style="--d:.2s" role="img" aria-label="Example of a suspicious address with no HTTPS, extra hyphens and an @ symbol"><mark style="--d:1.4s">http</mark>://secure<mark style="--d:2s">-</mark>login<mark style="--d:2.4s">-</mark>bank.verify.example.com/<mark style="--d:3s">@</mark>signin</p>
      <div class="facts" data-enter style="--d:.3s"><div><b>${num(R.n)}</b><span>web addresses studied</span></div><div><b>${num(L.phish.median)} vs ${num(L.legit.median)}</b><span>median length, phishing vs legitimate</span></div></div>
    </div>
    <div class="team" data-enter style="--d:.5s"><svg class="badge-ic" viewBox="0 0 32 32" width="30" height="30" aria-hidden="true" focusable="false"><path d="M12 1v7M20 1v7" stroke="#e0b862" stroke-width="1.4" stroke-linecap="round" fill="none"/><rect x="13" y="5" width="6" height="4" rx="1.2" fill="#e0b862"/><rect x="5" y="8" width="22" height="22" rx="3.5" fill="#14243a" stroke="#e0b862" stroke-width="1.4"/><circle cx="16" cy="16.5" r="3.2" fill="#e0b862"/><path d="M9.8 26c0-3.6 2.8-5.4 6.2-5.4s6.2 1.8 6.2 5.4Z" fill="#e0b862"/></svg><span><b>by the Unpaid Interns</b><small>Because some links are looking kinda suspicious.</small></span></div>
  </section>
  <section class="authbox"><form id="authForm" novalidate>
    <h2 data-enter>Welcome</h2><p class="mutp" data-enter style="--d:.1s">Choose an access level to open the dashboard.</p>
    <fieldset class="lv" data-enter style="--d:.25s"><legend class="vh">Access level</legend>
      <label><input type="radio" name="level" value="user" checked><span>User<small>Overview, Explore, Findings and About</small></span></label>
      <label><input type="radio" name="level" value="admin"><span>Admin<small>Everything above, plus the Data workspace</small></span></label></fieldset>
    <div id="passBox" hidden><label for="pass" class="lbl">Admin passcode</label>
      <div class="pw"><input id="pass" type="password" autocomplete="off" aria-describedby="passErr"><button id="showPass" class="btn ghost" type="button" aria-pressed="false">Show</button></div></div>
    <p id="passErr" class="err" role="alert"></p>
    <button id="go" class="btn block" type="submit" data-enter style="--d:.4s">Continue as user</button>
    <p class="fine">Access is checked in your browser only. It controls which pages you see and does not protect the data.</p>
  </form></section></div>`;
mount.login = () => {
  const f = $("authForm"), pass = $("pass"), err = $("passErr");
  const lvl = () => f.querySelector("[name=level]:checked").value;
  const sync = () => { const a = lvl() === "admin"; $("passBox").hidden = !a; $("go").textContent = a ? "Sign in as admin" : "Continue as user"; err.textContent = ""; pass.removeAttribute("aria-invalid"); };
  f.querySelectorAll("[name=level]").forEach(r => r.addEventListener("change", sync));
  $("showPass").onclick = e => { const show = pass.type === "password"; pass.type = show ? "text" : "password"; e.currentTarget.textContent = show ? "Hide" : "Show"; e.currentTarget.setAttribute("aria-pressed", show); };
  f.onsubmit = e => {
    e.preventDefault(); const admin = lvl() === "admin";
    if (admin && pass.value !== ADMIN_PASSCODE) { err.textContent = pass.value ? "That passcode does not match. Try again." : "Enter the admin passcode."; pass.setAttribute("aria-invalid", "true"); pass.focus(); return; }
    role.set(admin ? "admin" : "user"); location.hash = "#/overview"; route();
  };
};
pages.locked = () => `<h1>Admin only</h1><p class="lead">This page is for admins. Sign out, then sign in with the admin passcode.</p><a class="btn" href="#/overview">Back to overview</a>`;
const tag = full => `<span class="src${full ? " full" : ""}">${full ? "Full dataset" : "Sample"}</span>`;
const kpi = (cls, lbl, val, sub) => `<div class="kpi ${cls}"><span class="lbl">${lbl}</span><div class="v">${val}</div><small>${sub}</small></div>`;
const card = (id, title, full, cap, cls = "") => `<article class="panel ${cls}"><header><h2>${title}</h2>${tag(full)}</header><div class="chart ${cls ? "tall" : ""}"><canvas id="${id}" role="img" aria-label="${title}. ${cap}"></canvas></div><p class="cap">${cap}</p></article>`;
pages.overview = () => {
  const dif = +(L.phish.median - L.legit.median).toFixed(1), pp = pc(R.n_phish, R.n), lp = pc(R.n_legit, R.n);
  return `<div class="pagehead"><div><h1>Overview</h1><p>Are phishing URLs longer than legitimate URLs?</p></div>
    <div class="meta">${tag(true)} key numbers and findings, ${fmt(R.n)} sites ${tag(false)} distribution and endings, ${fmt(S.meta.size)} sites</div></div>
  <section class="kpis" aria-label="Key numbers from the full dataset">
    ${kpi("", "Records", num(R.n), `<div class="split" role="img" aria-label="${pp}% phishing, ${lp}% legitimate"><span style="--w:${pp}%;background:var(--ph)"></span><span style="--w:${lp}%;background:var(--lg)"></span></div>`)}
    ${kpi("ph", "Phishing", num(R.n_phish), `${pp}% of records`)}
    ${kpi("lg", "Legitimate", num(R.n_legit), `${lp}% of records`)}
    ${kpi("", "Median URL length", `${num(L.phish.median)} vs ${num(L.legit.median)}`, dif === 0 ? "No gap in medians" : `Phishing is ${Math.abs(dif)} characters ${dif > 0 ? "longer" : "shorter"}`)}
    ${kpi("", "Length test", `<span class="badge${T.significant ? " live" : ""}">${T.significant ? "Significant" : "Not significant"}</span>`, `${T.effect_name} ${T.effect}, ${T.effect_label} effect`)}
  </section>
  <section class="dash">
    ${card("o-len", "URL length distribution", false, `Sites by URL length. The last bar holds every URL of ${CAP} characters or more.`, "span2")}
    <article class="panel"><header><h2>Main finding</h2>${tag(true)}</header><p class="big">${T.conclusion}</p>
      <dl class="stats"><div><dt>Test</dt><dd>${T.name}</dd></div><div><dt>p-value</dt><dd>${pText(T.p)}</dd></div><div><dt>Threshold</dt><dd>${T.alpha}</dd></div><div><dt>Effect size</dt><dd>${T.effect_name} ${T.effect}</dd></div></dl>
      <span class="badge">${T.significant ? "Statistically significant" : "Not significant"}</span> <span class="badge mut">${T.effect_label} effect</span>
      <p class="note">${keep}</p></article>
  </section>
  <section class="dash">
    ${card("o-flag", "HTTPS and @ symbol", true, "Share of each group with the feature, from all sites.")}
    ${card("o-char", "Dots and hyphens", true, "Average dots and hyphens per URL, from all sites.")}
    ${card("o-tld", "Phishing share by ending", false, "Phishing share among the 10 most common address endings (TLDs).")}
  </section>`;
};
mount.overview = () => {
  const ph = rows.filter(r => r.ph), lg = rows.filter(r => !r.ph), b = R.binary, d = R.numeric.dots;
  let n = 0;   // each chart draws when its card scrolls into view, one after another
  const add = (id, c) => { const base = 200 + n++ * 150; whenSeen($(id), () => charts.push(new Chart($(id), {type: "bar", data: {labels: c.labels, datasets: c.sets}, options: mkOpts(c, base)}))); };
  add("o-len", VIEWS.length.build(rows, ph, lg));
  add("o-flag", {labels: ["Uses HTTPS", "Has an @ symbol"], sets: two([b.https.phish_pct, b.at_symbol.phish_pct], [b.https.legit_pct, b.at_symbol.legit_pct]), x: "Feature", y: "Share of sites (%)", ymax: 100});
  add("o-char", {labels: ["Dots", "Hyphens"], sets: two([d.phish.mean, hy.phish.mean], [d.legit.mean, hy.legit.mean]), x: "Character counted", y: "Average per URL"});
  add("o-tld", VIEWS.ends.build(null, null, null, {type: "all", https: "all", min: 0, max: CAP, tld: "all"}));
};
pages.explore = () => `<h1 class="mid">Explore the data</h1><p class="lead mid">Pick a view, then narrow it with the filters. Charts use a random sample of ${fmt(S.meta.size)} sites.</p>
  <div class="seg mid" role="group" aria-label="Chart views">${Object.entries(VIEWS).map(([k, v]) => `<button type="button" data-v="${k}" aria-pressed="false">${v.tab}</button>`).join("")}</div>
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
  drawTable(true);
  $("dq").oninput = e => { d.q = e.target.value; d.page = 0; drawTable(); };
  $("dt").onchange = e => { d.type = e.target.value; d.page = 0; drawTable(); };
  $("prev").onclick = () => { d.page--; drawTable(true); }; $("next").onclick = () => { d.page++; drawTable(true); };
  $("tbl").onclick = e => { const k = e.target.dataset.k; if (!k) return; d.dir = d.key === k ? -d.dir : 1; d.key = k; drawTable(true); $("tbl").querySelector(`[data-k="${k}"]`).focus(); };
  $("csv").onclick = () => {
    const csv = "type,url_length,dots,hyphens,https,at_symbol,tld\n" + listNow.map(r => [r.ph ? "phishing" : "legitimate", r.len, r.dots, r.hy, +r.https, +r.at, r.tld].join(",")).join("\n");
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], {type: "text/csv"})); a.download = "phishy-business-sample.csv"; a.click(); URL.revokeObjectURL(a.href);
  };
};

// ---- AI assistant (talks to the Cloudflare Worker, never to Groq directly)
const intro = {role: "assistant", local: true, content: `Hi, I am ${AI_NAME}. I can explain the findings, walk you through the chart you are on, or look at a link you paste. I cannot open links, so I judge them only from how they look.`};
let chat = [intro], busy = false;
const fab = Object.assign(document.createElement("button"), {id: "askBtn", type: "button", className: "btn fab", textContent: "Ask " + AI_NAME, hidden: true});
fab.setAttribute("aria-expanded", "false"); fab.setAttribute("aria-controls", "chat");
const box = document.createElement("section"); box.id = "chat"; box.hidden = true; box.setAttribute("aria-label", "AI assistant");
box.innerHTML = `<header><h2>${AI_NAME}</h2><button id="chatClose" class="btn ghost" type="button">Close</button></header>
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
let closing = null;
function setChat(open) {   // closing plays a short exit animation before the panel is hidden
  clearTimeout(closing); box.classList.remove("closing"); fab.setAttribute("aria-expanded", open);
  if (open) { box.hidden = false; paint(); $("chatIn").focus(); return; }
  fab.focus();
  if (calm() || box.hidden) { box.hidden = true; return; }
  box.classList.add("closing"); closing = setTimeout(() => { box.hidden = true; box.classList.remove("closing"); }, 450);
}
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
fab.onclick = () => setChat(box.hidden || box.classList.contains("closing"));
$("chatClose").onclick = () => setChat(false);
box.addEventListener("keydown", e => { if (e.key === "Escape") setChat(false); });
$("chatForm").onsubmit = e => { e.preventDefault(); const t = $("chatIn").value; $("chatIn").value = ""; send(t); };
$("chatIn").addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("chatForm").requestSubmit(); } });
$("chips").onclick = e => { const b = e.target.closest("button"); if (!b) return;
  if (b.dataset.fill) { $("chatIn").value = b.dataset.fill; $("chatIn").focus(); } else send(b.textContent === "Explain this page" ? "Explain what I am looking at on this page in plain words." : b.textContent); };

// ---- router
const NAV = [["overview", "Overview"], ["explore", "Explore"], ["findings", "Findings"], ["about", "About"], ["data", "Data", "admin"]];
let prev = null;
let obs = [];   // observers for the current page, cleared on every route change
// Run fn the first time el is on screen (so charts draw when you can see them).
function whenSeen(el, fn) {
  if (!el) return;
  if (calm() || !("IntersectionObserver" in window)) return fn();
  const o = new IntersectionObserver(es => { if (es.some(e => e.isIntersecting)) { o.disconnect(); fn(); } }, {threshold: .3});
  o.observe(el); obs.push(o);
}
// Numbers with data-count rise from 0 to the real value from results.js.
function countUp(root, delay = 0) {
  root.querySelectorAll("[data-count]").forEach(el => {
    if (calm() || el.dataset.done) return;
    const raw = el.dataset.count, to = +raw, dec = (raw.split(".")[1] || "").length;
    const out = n => dec ? n.toFixed(dec) : Math.round(n).toLocaleString("en-US");
    el.dataset.done = "1"; el.textContent = out(0);
    setTimeout(() => {
      const t0 = performance.now();
      const step = t => { const k = Math.min(1, (t - t0) / 1900), e = k === 1 ? 1 : 1 - Math.pow(2, -10 * k); el.textContent = out(to * e); if (k < 1) requestAnimationFrame(step); };
      requestAnimationFrame(step);
    }, delay);
  });
}
// Blocks rise in one after another as they come into view. Classes are removed afterwards so hover effects stay fast.
function reveal(root) {
  if (calm() || !("IntersectionObserver" in window)) return;
  const sel = ".pagehead, #view > h1, #view > .lead, .kpis > *, .dash > *, .steps li, .seg, .filters, .read, #view > .panel, .kv > *, .row, .tw, .pager, .prose > *, #view > .btn";
  const items = [...new Set(root.querySelectorAll(sel))];
  const io = new IntersectionObserver(es => {
    es.filter(e => e.isIntersecting).forEach((e, i) => {
      const el = e.target, wait = i * 120; io.unobserve(el);
      el.style.setProperty("--td", wait + "ms"); el.classList.add("in"); countUp(el, wait + 300);
      setTimeout(() => { el.classList.remove("rv", "in"); el.style.removeProperty("--td"); }, wait + 1400);
    });
  }, {threshold: .12});
  items.forEach(el => { el.classList.add("rv"); io.observe(el); });
  obs.push(io);
}
function route() {
  const r = role.get(), name = location.hash.replace(/^#\/?/, "") || "overview", v = $("view");
  let page = !r ? "login" : NAV.some(n => n[0] === name) ? name : "overview";
  if (page === "data" && r !== "admin") page = "locked";
  obs.forEach(o => o.disconnect()); obs = []; firstDraw = true;
  if (chart) { chart.destroy(); chart = null; }
  charts.forEach(c => c.destroy()); charts = [];
  document.querySelector(".shell").classList.toggle("out", !r);
  document.body.classList.toggle("is-out", !r);   // login page moves the motion button to the right
  v.innerHTML = pages[page]();
  v.classList.remove("enter"); void v.offsetWidth; v.classList.add("enter");
  $("links").innerHTML = NAV.filter(n => !n[2] || n[2] === r).map(n => `<a href="#/${n[0]}"${n[0] === page ? ' aria-current="page"' : ""}>${n[1]}</a>`).join("");
  $("who").textContent = r ? `${r === "admin" ? "Admin" : "User"} role` : "";
  $("out").hidden = !r;
  fab.hidden = !r; if (!r) { box.hidden = true; fab.setAttribute("aria-expanded", "false"); resetChat(); }
  document.title = (page === "login" ? "Sign in" : (NAV.find(n => n[0] === page) || [0, "Admin only"])[1]) + " | Phishy Business";
  if (page === "login") countUp(v, 900); else reveal(v);
  (mount[page] || (() => {}))();
  window.scrollTo(0, 0);
  if (prev && prev !== page) v.focus({preventScroll: true});
  prev = page;
}
$("out").onclick = () => { role.set(null); location.hash = "#/login"; route(); };
window.addEventListener("hashchange", route);
// motion button, top bar shadow on scroll, soft light that follows the pointer over cards
const mo = $("mo"), syncMo = () => { mo.textContent = htmlEl.classList.contains("calm") ? "Play motion" : "Pause motion"; };
mo.hidden = reduce; syncMo();
mo.onclick = () => { htmlEl.classList.toggle("calm"); try { sessionStorage.setItem("pb-calm", htmlEl.classList.contains("calm") ? "1" : "0"); } catch {} syncMo(); };
const bar = document.querySelector(".top");
addEventListener("scroll", () => bar.classList.toggle("lifted", scrollY > 4), {passive: true});
$("view").addEventListener("pointermove", e => {
  const c = e.target.closest(".panel, .kpi"); if (!c) return; const r = c.getBoundingClientRect();
  c.style.setProperty("--mx", e.clientX - r.left + "px"); c.style.setProperty("--my", e.clientY - r.top + "px");
});
route();
})();
