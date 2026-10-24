const $ = (id) => document.getElementById(id);
const fmt = (n) => Math.round(n).toLocaleString("en-US");
const pct = (x, d = 1) => `${(100 * x).toFixed(d)}%`;
const exact = (x) => (x === 1 ? "100%" : 100 * x >= 99.95 ? `${(100 * x).toFixed(3)}%` : pct(x)); // never round 99.998% up
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const short = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(0)}k` : fmt(n));
const PORTS = { 53: "DNS", 123: "NTP", 389: "CLDAP", 1900: "SSDP", 11211: "Memcached" };

Chart.defaults.color = css("--muted");
Chart.defaults.font.family = "Inter, system-ui, sans-serif";
Chart.defaults.borderColor = css("--line");

/* ---------------- tabs + tooltips ---------------- */
function showTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
  if (name === "results") loadResults();
  try { history.replaceState(null, "", `#${name}`); } catch (e) { /* ignore */ }
}
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

const tooltip = $("tooltip");
document.addEventListener("mouseover", (e) => {
  const t = e.target.closest(".tip");
  if (!t) return tooltip.classList.remove("show");
  tooltip.textContent = t.dataset.tip;
  const r = t.getBoundingClientRect();
  tooltip.style.left = `${Math.min(r.left, window.innerWidth - 280)}px`;
  tooltip.style.top = `${r.bottom + 8}px`;
  tooltip.classList.add("show");
});

/* ---------------- live charts ---------------- */
const trafficChart = new Chart($("traffic"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "Arriving (incl. attack)", data: [], borderColor: css("--bad"), backgroundColor: "rgba(229,83,75,0.12)", fill: true, tension: 0.25, pointRadius: 0, borderWidth: 2 },
    { label: "Reaching the game server", data: [], borderColor: css("--ok"), tension: 0.25, pointRadius: 0, borderWidth: 2 },
    { label: "Normal level (learned)", data: [], borderColor: css("--muted"), borderDash: [5, 5], pointRadius: 0, borderWidth: 1 },
  ] },
  options: {
    animation: false, maintainAspectRatio: false, interaction: { mode: "index", intersect: false },
    scales: {
      x: { ticks: { maxTicksLimit: 8, callback: function (v) { return this.getLabelForValue(v) + "s"; } }, grid: { display: false } },
      y: { type: "logarithmic", min: 500, title: { display: true, text: "packets / second" },
           ticks: { callback: (v) => (Number.isInteger(Math.log10(v)) ? short(v) : "") } },
    },
    plugins: { legend: { labels: { boxWidth: 12 } }, tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${fmt(c.raw)} pps` } } },
  },
});

const servedChart = new Chart($("served"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "Real players getting through (%)", data: [], borderColor: css("--accent"),
    backgroundColor: "rgba(90,169,230,0.12)", fill: true, tension: 0.25, pointRadius: 0, borderWidth: 2 }] },
  options: {
    animation: false, maintainAspectRatio: false,
    scales: { x: { ticks: { maxTicksLimit: 8 }, grid: { display: false } }, y: { min: 0, max: 100, ticks: { callback: (v) => `${v}%` } } },
    plugins: { legend: { display: false } },
  },
});

/* ---------------- plain-English helpers ---------------- */
function plainRule(rule) {
  let m = rule.match(/^DROP (\w+) src port (\d+)/);
  if (m) return `Dropping ${m[1]} traffic coming from port ${m[2]}${PORTS[m[2]] ? ` (${PORTS[m[2]]} replies)` : ""}`;
  m = rule.match(/^RATE-LIMIT TCP SYN only from unknown sources to ([\d,]+) pps/);
  if (m) return `Slowing new connections from unknown senders to ${m[1]} per second (known players pass)`;
  m = rule.match(/^RATE-LIMIT UDP from unknown sources to ([\d,]+) pps/);
  if (m) return `Slowing UDP from unknown senders to ${m[1]} per second (known players pass)`;
  return rule;
}

const EVENT = {
  scenario: ["▶", "info", (d) => {
    const m = d.match(/'(\w+)'/);
    return d.includes("stopped") ? "All test traffic stopped" : `Test traffic started: ${(m ? m[1] : d).replace("_", " ")}`;
  }],
  alert: ["!", "bad", (d) => {
    const m = d.match(/confirmed: (.+?) \(.*votes=(\d)\/3/);
    return m ? `Alarms agree (${m[2]} of 3): ${m[1]}` : d;
  }],
  classified: ["?", "warn", (d) => d.replace("re-classified as", "Identified as")],
  rule_added: ["■", "warn", (d) => `Blocking started: ${plainRule(d)}`],
  rule_expired: ["✓", "ok", (d) => `Rule removed after the attack: ${plainRule(d)}`],
  escalated: ["↑", "info", () => "Flood bigger than the internet link: asked the provider to filter it (BGP FlowSpec)"],
  withdrawn: ["✓", "ok", () => "Provider filter removed, attack is over"],
  resolved: ["✓", "ok", (d) => {
    const m = d.match(/over after (\d+)s; ([\d.]+)%/);
    return m ? `Incident over after ${m[1]} s. ${m[2]}% of real player traffic got through` : d;
  }],
  rebaselined: ["≈", "info", (d) => d.replace("sustained legitimate surge:", "Busy for a while with real players:")],
  observe: ["i", "info", (d) => d],
};

function list(el, items, render, empty) {
  el.innerHTML = items.length ? items.map(render).join("") : `<li class="empty">${empty}</li>`;
}

function banner(state, icon, title, text) {
  $("banner").className = `banner ${state}`;
  $("banner-icon").textContent = icon;
  $("banner-title").textContent = title;
  $("banner-text").textContent = text;
}

function setSteps(done, now, notes = {}) {
  document.querySelectorAll("#steps li").forEach((li) => {
    const k = li.dataset.step;
    li.className = done.includes(k) ? "done" : k === now ? "now" : "";
    const small = li.querySelector("small");
    small.dataset.orig ??= small.textContent;
    small.textContent = notes[k] || small.dataset.orig;
  });
}

/* ---------------- live render ---------------- */
let lastState = null;

function render(s) {
  lastState = s;
  const h = s.history;
  const last = h[h.length - 1] || {};
  const labels = h.map((p) => p.t);
  trafficChart.data.labels = labels;
  trafficChart.data.datasets[0].data = h.map((p) => Math.max(p.pps, 1));
  trafficChart.data.datasets[1].data = h.map((p) => Math.max(p.passed_pps, 1));
  trafficChart.data.datasets[2].data = h.map((p) => Math.max(p.baseline, 1));
  trafficChart.update();
  servedChart.data.labels = labels;
  servedChart.data.datasets[0].data = h.map((p) => p.served_pct);
  servedChart.update();

  const f = s.features || {};
  const served = last.served_pct ?? 100;
  $("k-pps").textContent = fmt(last.pps || 0);
  $("k-passed").textContent = fmt(last.passed_pps || 0);
  $("k-served").textContent = served.toFixed(0);
  $("k-src").textContent = fmt(f.unique_sources || 0);

  // banner + steps
  const inc = s.incident;
  const blocking = s.rules.filter((r) => r.mode === "enforce");
  const ratio = last.baseline ? last.pps / last.baseline : 1;
  if (s.t < 12) {
    banner("watch", "…", "Learning what normal looks like", "ShieldWall watches the first seconds of traffic to learn this server's normal level.");
    setSteps([], "watch");
  } else if (s.anomalous && s.malicious) {
    const name = s.classification;
    if (blocking.length) {
      banner("attack", "!", `Under attack: ${name}`,
        `ShieldWall is blocking it. ${served.toFixed(0)}% of real player traffic is getting through` +
        (inc && inc.mitigate_s ? `, blocked ${inc.mitigate_s} s after it started.` : "."));
      setSteps(["watch", "detect", "identify", "block"], "explain", { explain: s.explanation ? "summary ready" : "writing summary" });
      if (s.explanation) setSteps(["watch", "detect", "identify", "block", "explain"], null);
    } else {
      banner("attack", "!", `Attack detected: ${name}`, "Writing a blocking rule into the kernel now.");
      setSteps(["watch", "detect", "identify"], "block");
    }
  } else if (s.anomalous) {
    if (s.kind === "legit_surge") {
      banner("watch", "≈", "Busy, but it's real players",
        `Traffic is about ${ratio.toFixed(1)}× normal, but connections complete normally and the mix looks like players, so nobody is blocked.`);
      setSteps(["watch", "detect", "identify"], null, { identify: "real players, not an attack", block: "not needed" });
    } else {
      banner("watch", "?", "Something unusual, watching closely",
        "Traffic is higher than normal but does not match a known attack, so nothing is blocked yet.");
      setSteps(["watch", "detect"], "identify");
    }
  } else if (s.upstream.length) {
    banner("blocked", "↑", "Attack filtered by your internet provider",
      "The flood was bigger than your connection, so ShieldWall asked the provider upstream to filter it. Players are getting through.");
    setSteps(["watch", "detect", "identify", "block", "explain"], null, { block: "filtered upstream" });
  } else if (s.rules.length) {
    const left = Math.max(...s.rules.map((r) => r.expires_in));
    banner("blocked", "✓", "Attack over",
      `Traffic is back to normal. The blocking rules remove themselves in about ${left} s.`);
    setSteps(["watch", "detect", "identify", "block", "explain"], null);
  } else {
    banner("", "✓", "Your server is safe",
      `Traffic looks normal: about ${fmt(last.pps || 0)} packets per second from ${fmt(f.unique_sources || 0)} senders. Nothing is blocked.`);
    setSteps([], "watch");
  }

  const status = $("status");
  status.className = "status" + (s.anomalous && s.malicious ? " alert" : s.anomalous ? " watch" : "");
  $("status-text").textContent = s.anomalous && s.malicious ? "Under attack" : s.anomalous ? "Watching" : "All clear";

  // alarms
  $("d-z").textContent = `(${(last.zscore ?? 0).toFixed(0)})`;
  $("d-c").textContent = `(${(last.cusum ?? 0).toFixed(0)})`;
  $("d-e").textContent = `(${(last.entropy ?? 0).toFixed(1)} bits)`;
  for (const k of ["zscore", "cusum", "entropy"]) $("v-" + k).classList.toggle("on", !!s.votes[k]);

  // AI
  if (s.explanation) $("explain").textContent = s.explanation;
  if (s.llm) $("llm-label").textContent = `${s.llm} · explains, never blocks`;

  list($("rules"), s.rules, (r) => `<li>${esc(plainRule(r.rule))}<small>${r.mode === "enforce" ? "active" : "dry-run (logging only)"} · removes itself in ${r.expires_in}s · ${fmt(r.hits)} packets dropped</small></li>`
    + "", s.upstream.length ? "" : "Nothing is blocked. Traffic flows freely.");
  if (s.upstream.length) $("rules").insertAdjacentHTML("beforeend", s.upstream.map((r) => `<li>Internet provider is filtering: ${esc(plainRule(r.rule))}<small>BGP FlowSpec · ${r.expires_in}s left</small></li>`).join(""));
  list($("talkers"), f.top_talkers || [], ([ip, n]) => `<li><span>${esc(ip)}</span><span>${fmt(n)} pkts/s</span></li>`, "-");

  const ev = s.events.filter((e) => EVENT[e.kind]);
  $("events").innerHTML = ev.length ? ev.map((e) => {
    const [icon, tone, txt] = EVENT[e.kind];
    return `<li><span class="ic ${tone}">${icon}</span><div>${esc(txt(e.detail))}<small>t = ${e.t}s</small></div></li>`;
  }).join("") : `<li class="empty">Nothing has happened yet.</li>`;

  // how it works: live values
  const votes = Object.values(s.votes || {}).filter(Boolean).length;
  $("how-count").textContent = `${fmt(last.pps || 0)} packets/s counted`;
  $("how-detect").textContent = votes ? `${votes} of 3 alarms on` : "all 3 alarms quiet";
  $("how-identify").textContent = s.classification || "nothing to identify";
  $("how-block").textContent = s.rules.length ? `${s.rules.length} rule${s.rules.length > 1 ? "s" : ""} active` : "nothing blocked";
  $("how-explain").textContent = s.llm || "-";
  $("m-z").textContent = (last.zscore ?? 0).toFixed(1);
  $("m-base").textContent = fmt(last.baseline || 0);
  $("m-c").textContent = (last.cusum ?? 0).toFixed(1);
  $("m-e").textContent = (last.entropy ?? 0).toFixed(2);
  $("m-src").textContent = fmt(f.unique_sources || 0);
  $("m-new").textContent = pct(f.new_source_share || 0, 0);
  $("m-cls").textContent = s.classification || "nothing unusual";
  $("m-rules").textContent = s.rules.length ? s.rules.map((r) => plainRule(r.rule)).join("; ") : "no rules";
  $("m-llm").textContent = s.llm || "LLM";
}

async function poll() {
  try { render(await (await fetch("/api/state")).json()); } catch (e) { /* server restarting */ }
  setTimeout(poll, 1000);
}

document.querySelectorAll("[data-preset]").forEach((b) =>
  b.addEventListener("click", () => fetch("/api/launch", { method: "POST", body: JSON.stringify({ preset: b.dataset.preset }) })));
$("stop").addEventListener("click", () => fetch("/api/stop", { method: "POST", body: "{}" }));

async function ask(q) {
  const chat = $("chat");
  chat.insertAdjacentHTML("beforeend", `<div class="q">${esc(q)}</div>`);
  chat.insertAdjacentHTML("beforeend", `<div class="a" id="pending">thinking…</div>`);
  chat.scrollTop = chat.scrollHeight;
  const { answer } = await (await fetch("/api/chat", { method: "POST", body: JSON.stringify({ question: q }) })).json();
  $("pending").outerHTML = `<div class="a">${esc(answer)}</div>`;
  chat.scrollTop = chat.scrollHeight;
}
$("ask").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const q = $("question").value.trim();
  if (q) { $("question").value = ""; ask(q); }
});
document.querySelectorAll(".chips button").forEach((b) => b.addEventListener("click", () => ask(b.dataset.q)));

function mdToHtml(md) {
  const out = [];
  let list = false;
  for (const raw of md.split("\n")) {
    const line = esc(raw).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>");
    if (raw.startsWith("- ")) {
      if (!list) { out.push("<ul>"); list = true; }
      const cls = raw.startsWith("- ✓") ? "ok" : raw.startsWith("- ✗") ? "no" : "";
      out.push(`<li class="${cls}">${line.slice(2)}</li>`);
      continue;
    }
    if (list) { out.push("</ul>"); list = false; }
    if (raw.startsWith("## ")) out.push(`<h4>${line.slice(3)}</h4>`);
    else if (raw.trim()) out.push(`<p>${line}</p>`);
  }
  if (list) out.push("</ul>");
  return out.join("");
}

$("report-btn").addEventListener("click", async () => {
  const btn = $("report-btn");
  btn.disabled = true;
  btn.textContent = "Writing report…";
  try {
    const r = await (await fetch("/api/report", { method: "POST", body: "{}" })).json();
    $("report").innerHTML = mdToHtml(r.markdown || "No report.") + (r.backend ? `<p class="hint">written by ${esc(r.backend)}</p>` : "");
  } finally {
    btn.disabled = false;
    btn.textContent = "Write incident report + suggest rules";
  }
});

/* ---------------- results tab ---------------- */
let results = null;
let perTypeChart = null;
let scenarioChart = null;
const LEVEL_HINT = {
  window: "Every 1-second window across all trials: was an attack happening, and did ShieldWall say so?",
  packet: "Every packet: was each dropped packet really attack traffic, and how much attack traffic was dropped?",
  incident: "Each trial as a whole: was the attack caught at all, and was any non-attack ever blocked?",
};
const NICE = { cldap: "CLDAP amplification", dns: "DNS amplification", ntp: "NTP amplification", syn: "SYN flood",
  udp: "UDP flood", flash_crowd: "Flash crowd", none: "Quiet traffic" };

function showLevel(level) {
  const m = results.metrics.levels[level];
  document.querySelectorAll("#level-seg button").forEach((b) => b.classList.toggle("active", b.dataset.level === level));
  $("level-hint").textContent = LEVEL_HINT[level];
  $("r-acc").textContent = exact(m.accuracy);
  $("r-prec").textContent = exact(m.precision);
  $("r-rec").textContent = exact(m.recall);
  $("r-f1").textContent = m.f1.toFixed(3);
  $("cm-tp").textContent = short(m.tp);
  $("cm-fp").textContent = short(m.fp);
  $("cm-fn").textContent = short(m.fn);
  $("cm-tn").textContent = short(m.tn);
}
document.querySelectorAll("#level-seg button").forEach((b) => b.addEventListener("click", () => showLevel(b.dataset.level)));

async function loadResults() {
  if (results) return;
  try { results = await (await fetch("/api/results")).json(); } catch (e) { return; }
  const M = results.metrics;
  const S = results.results || [];
  const K = results.kernel_test;
  const L = results.llm_eval;
  const R = [...(results.replay || []), ...(results.replay_cic || [])];
  if (R.length) {
    $("real-table").innerHTML = "<tr><th>Attack data</th><th>Inside</th><th>Identified as</th><th>Detected</th><th>Blocked</th><th>Attack dropped once blocking</th><th>Real traffic dropped</th><th>Players served (without → with)</th></tr>" +
      R.map((r) => {
        const c = r.capture, w = r.with;
        const src = c.file.includes("archive.zip") ? "CIC-DDoS2019 " + c.file.split(":")[1] : "StopDDoS " + c.file;
        return `<tr><td>${esc(src)}</td><td class="num">${fmt(c.native_pps)} pps · ${fmt(c.unique_sources)} source${c.unique_sources === 1 ? "" : "s"}${c.fragment_share ? ` · ${(100 * c.fragment_share).toFixed(0)}% fragments` : ""}</td>` +
          `<td>${esc(r.label)}</td><td class="num">${w.detect_s ?? "-"} s</td><td class="num">${w.mitigate_s ?? "-"} s</td>` +
          `<td class="num good-txt">${w.attack_dropped_after_block_pct.toFixed(1)}%</td><td class="num">${w.legit_dropped_pct.toFixed(3)}%</td>` +
          `<td class="num">${r.without.served_pct.toFixed(1)}% → <span class="good-txt">${w.served_pct.toFixed(1)}%</span></td></tr>`;
      }).join("");
    $("real-findings").innerHTML = [
      ["Fragments", "Real amplification floods are 14-24% IP fragments with no ports. A port rule alone let them through, so ShieldWall now adds a fragment rule (verified on the Linux kernel)."],
      ["Multi-vector", "The real memcached capture mixes Memcached, NTP and DNS at once. ShieldWall now writes a rule for every vector instead of only the biggest."],
      ["Single host", "CIC-DDoS2019's attacks all come from one machine. Fingerprints missed two of them, so the Count-Min Sketch heavy hitter now blocks that address."],
    ].map(([b, t]) => `<div><b>${b}</b>${t}</div>`).join("");
  } else {
    $("real-table").innerHTML = `<tr><td class="hint">Run <code>shieldwall replay capture.pcap</code> to fill this in.</td></tr>`;
  }

  if (M) {
    $("res-intro").textContent = `Three kinds of evidence: real attack data (public captures and CIC-DDoS2019) replayed through the engine, ${M.trials} randomized trials in the simulated lab (${M.attacks} attacks, ${M.negatives} non-attacks), and the XDP program tested on a real Linux kernel. Plus an evaluation of the AI assistant.`;
    showLevel("window");
    $("extra-facts").innerHTML = [
      [pct(M.type_accuracy, 0), "of caught attacks were given the right name"],
      [`${M.median_detect_s} s`, "median time from attack start to detection"],
      [`${M.legit_dropped_pct.toFixed(3)}%`, "of real player traffic wrongly dropped"],
      [`${M.levels.incident.tp}/${M.attacks}`, "attacks caught (the misses were the weakest ones)"],
    ].map(([b, t]) => `<div class="fact"><b>${b}</b><span>${t}</span></div>`).join("");

    const rows = M.per_type;
    perTypeChart?.destroy();
    perTypeChart = new Chart($("per-type"), {
      type: "bar",
      data: {
        labels: rows.map((r) => NICE[r.kind] || r.kind),
        datasets: [
          { label: "Handled correctly", data: rows.map((r) => (r.attack ? r.detected : r.trials - r.detected)), backgroundColor: css("--ok") },
          { label: "Wrong", data: rows.map((r) => (r.attack ? r.trials - r.detected : r.detected)), backgroundColor: css("--bad") },
        ],
      },
      options: {
        indexAxis: "y", maintainAspectRatio: false, animation: false,
        scales: { x: { stacked: true, title: { display: true, text: "trials" }, ticks: { precision: 0 } }, y: { stacked: true, grid: { display: false } } },
        plugins: { legend: { labels: { boxWidth: 12 } }, tooltip: { callbacks: { footer: (items) => {
          const r = rows[items[0].dataIndex];
          return r.attack ? `detected ${r.detected}/${r.trials}, named correctly ${r.type_ok}/${r.trials}` : `wrongly blocked ${r.detected}/${r.trials}`;
        } } } },
      },
    });
  }

  if (S.length) {
    const short_names = { S1: "Clean attack", S2a: "SYN flood + players", S2b: "UDP flood + players", S3: "Flash crowd", S4: "Bigger than link" };
    scenarioChart?.destroy();
    scenarioChart = new Chart($("scenarios"), {
      type: "bar",
      data: {
        labels: S.map((r) => short_names[r.key] || r.key),
        datasets: [
          { label: "Without ShieldWall", data: S.map((r) => r.served_without), backgroundColor: "rgba(229,83,75,0.75)" },
          { label: "With ShieldWall", data: S.map((r) => r.served_with), backgroundColor: css("--ok") },
        ],
      },
      options: {
        maintainAspectRatio: false, animation: false,
        scales: { y: { min: 0, max: 100, title: { display: true, text: "% of real player traffic served" }, ticks: { callback: (v) => `${v}%` } }, x: { grid: { display: false } } },
        plugins: { legend: { labels: { boxWidth: 12 } }, tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${c.raw.toFixed(1)}%` } } },
      },
    });
    $("scenario-table").innerHTML = "<tr><th>Scenario</th><th>Identified as</th><th>Without</th><th>With</th><th>Detected after</th><th>Blocked after</th></tr>" +
      S.map((r) => `<tr><td>${esc(r.name)}</td><td>${esc(r.label)}</td><td class="num ${r.served_without < 95 ? "bad-txt" : ""}">${r.served_without.toFixed(1)}%</td>` +
        `<td class="num good-txt">${r.served_with.toFixed(1)}%</td><td class="num">${r.detect_s ?? "-"} s</td>` +
        `<td class="num">${r.malicious ? `${r.mitigate_s ?? "-"} s${r.escalated ? " (via provider)" : ""}` : "nothing to block"}</td></tr>`).join("");
  }

  if (K) {
    $("kernel").innerHTML = `<div class="kv">
      <div><b>${fmt(K.attack_dropped)} / ${fmt(K.attack_sent)}</b><span>attack packets dropped by the kernel</span></div>
      <div><b>${fmt(K.player_passed)} / ${fmt(K.player_sent)}</b><span>player packets let through</span></div>
      <div><b>${fmt(K.sources_estimated)}</b><span>senders estimated (truth: ${fmt(K.sources_true)})</span></div>
      <div><b>${fmt(K.dry_run_dropped)}</b><span>packets dropped in dry-run mode (should be 0)</span></div>
      ${K.fragments_sent ? `<div><b>${fmt(K.fragments_dropped)} / ${fmt(K.fragments_sent)}</b><span>IP fragments (no ports) dropped by the fragment rule</span></div>
      <div><b>${fmt(K.heavy_hitter_dropped)} / ${fmt(K.heavy_hitter_sent)}</b><span>packets from one flooding host dropped by the blocklist, ${fmt(K.others_passed)} others passed</span></div>` : ""}
    </div>
    <p class="hint">Real packets sent with scapy through the XDP program on Linux ${esc(K.kernel)}. Identified as: <b>${esc(K.classified_as)}</b>.</p>
    <span class="pass">Kernel test passed</span>`;
  } else {
    $("kernel").innerHTML = `<p class="hint">Run <code>sudo bash tests/xdp_kernel_test.sh</code> on Linux to fill this in.</p>`;
  }

  if (L) {
    const x = L.summary;
    $("llm-model-hint").textContent = `${x.model} · ${x.explanations} explanations + ${L.chat.length} questions`;
    $("m-llm-ground").textContent = pct(x.numeric_grounding, 0);
    const ex = L.explanations[0];
    const qa = L.chat[0];
    $("llm-eval").innerHTML = `<div class="kv">
      <div><b>${pct(x.numeric_grounding, 0)}</b><span>of numbers it wrote match the real facts (${x.numbers_checked - x.hallucinated_numbers}/${x.numbers_checked}, no made-up numbers)</span></div>
      <div><b>${pct(x.label_accuracy, 0)}</b><span>named the right attack, or called a surge real players</span></div>
      <div><b>${pct(x.chat_accuracy, 0)}</b><span>chat answers correct</span></div>
      <div><b>${x.latency_median_s.toFixed(1)} s</b><span>median reply time (runs in the background)</span></div>
      <div><b>$${x.cost_per_explanation_usd.toFixed(5)}</b><span>cost per explanation</span></div>
      <div><b>$${x.total_cost_usd.toFixed(4)}</b><span>cost of this whole evaluation</span></div>
      ${x.claims_checked ? `<div><b>${pct(x.claims_supported, 0)}</b><span>of claims judged supported with the right meaning (LLM-as-judge, ${x.claims_checked} claims)</span></div>
      <div><b>${x.suggestions_accepted}/${x.suggestions}</b><span>suggested rules accepted by the controller (in dry-run); the rest were rejected as unsafe or useless</span></div>` : ""}
    </div>
    ${results.llm_eval_prompt_v1 ? (() => { const v = results.llm_eval_prompt_v1.summary; return `<div class="quote"><small>Prompt v1 → v2 (fixed after the evaluation found over-claiming and useless suggestions)</small>
      Claims judged faithful ${pct(v.claims_supported, 0)} → <b>${pct(x.claims_supported, 0)}</b> · perfect explanations ${pct(v.fully_faithful, 0)} → <b>${pct(x.fully_faithful, 0)}</b> · suggestions accepted ${v.suggestions_accepted}/${v.suggestions} → <b>${x.suggestions_accepted}/${x.suggestions}</b></div>`; })() : ""}
    <div class="quote"><small>Example explanation (${esc(ex.case)})</small>${esc(ex.text)}</div>
    <div class="quote"><small>Q: ${esc(qa.question)}</small>${esc(qa.answer)}</div>`;
  } else {
    $("llm-eval").innerHTML = `<p class="hint">Run <code>shieldwall llm-eval</code> with an OPENAI_API_KEY to fill this in.</p>`;
  }
}

/* ---------------- start ---------------- */
const initial = (location.hash || "#live").slice(1);
showTab(["live", "how", "results"].includes(initial) ? initial : "live");
loadResults();
poll();
