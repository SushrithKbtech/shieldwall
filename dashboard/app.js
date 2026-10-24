const $ = (id) => document.getElementById(id);
const fmt = (n) => Math.round(n).toLocaleString();
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

Chart.defaults.color = css("--muted");
Chart.defaults.font.family = "Inter, system-ui, sans-serif";
Chart.defaults.borderColor = css("--line");

const trafficChart = new Chart($("traffic"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "Arriving", data: [], borderColor: css("--bad"), backgroundColor: "rgba(229,83,75,0.12)", fill: true, tension: 0.25, pointRadius: 0, borderWidth: 2 },
    { label: "Passed to server", data: [], borderColor: css("--ok"), tension: 0.25, pointRadius: 0, borderWidth: 2 },
    { label: "Learned baseline", data: [], borderColor: css("--muted"), borderDash: [5, 5], pointRadius: 0, borderWidth: 1 },
  ] },
  options: {
    animation: false, maintainAspectRatio: false, interaction: { mode: "index", intersect: false },
    scales: {
      x: { ticks: { maxTicksLimit: 8, callback: function (v) { return this.getLabelForValue(v) + "s"; } }, grid: { display: false } },
      y: { type: "logarithmic", min: 500, ticks: { callback: (v) => (Number.isInteger(Math.log10(v)) ? fmt(v) : "") } },
    },
    plugins: { legend: { labels: { boxWidth: 12 } }, tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${fmt(c.raw)} pps` } } },
  },
});

const servedChart = new Chart($("served"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "Real player traffic served (%)", data: [], borderColor: css("--accent"), backgroundColor: "rgba(90,169,230,0.12)", fill: true, tension: 0.25, pointRadius: 0, borderWidth: 2 },
  ] },
  options: {
    animation: false, maintainAspectRatio: false,
    scales: { x: { ticks: { maxTicksLimit: 8 }, grid: { display: false } }, y: { min: 0, max: 100 } },
    plugins: { legend: { display: false } },
  },
});

function list(el, items, render, empty) {
  el.innerHTML = items.length ? items.map(render).join("") : `<li class="empty">${empty}</li>`;
}

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

function render(s) {
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

  $("k-pps").textContent = fmt(last.pps || 0);
  $("k-gbps").textContent = (last.gbps || 0).toFixed(2);
  $("k-served").textContent = (last.served_pct ?? 100).toFixed(0);
  $("k-src").textContent = fmt(s.features?.unique_sources || 0);
  $("k-stage").textContent = s.stage.replace("_", "-");

  const status = $("status");
  const malicious = s.rules.length || s.upstream.length;
  status.className = "status" + (s.anomalous && malicious ? " alert" : s.anomalous ? " watch" : "");
  $("status-text").textContent = s.anomalous ? (malicious ? "Under attack · mitigating" : "Anomaly · observing")
    : s.upstream.length ? "Filtered upstream · FlowSpec active" : (malicious ? "Recovered · rules expiring" : "All clear");

  $("d-z").textContent = (last.zscore ?? 0).toFixed(1);
  $("d-c").textContent = (last.cusum ?? 0).toFixed(0);
  $("d-e").textContent = (last.entropy ?? 0).toFixed(2);
  for (const k of ["zscore", "cusum", "entropy"]) $("v-" + k).classList.toggle("on", !!s.votes[k]);

  const cls = $("classification");
  if (s.classification) {
    const benign = /legitimate|unclassified/.test(s.classification);
    cls.textContent = (benign ? "Observing: " : "Detected: ") + s.classification;
    cls.className = "classification " + (benign ? "ok" : "bad");
  } else {
    cls.textContent = "No anomaly.";
    cls.className = "classification";
  }

  if (s.explanation) $("explain").textContent = s.explanation;

  list($("rules"), s.rules, (r) => `<li>${esc(r.rule)}<small>${r.mode} · expires in ${r.expires_in}s · ${fmt(r.hits)} pkts dropped</small></li>`, "No rules. Traffic flows freely.");
  list($("upstream"), s.upstream, (r) => `<li>${esc(r.rule)}<small>announced to ISP · ${r.expires_in}s left</small></li>`, "Not needed.");
  list($("talkers"), s.features?.top_talkers || [], ([ip, n]) => `<li><span>${esc(ip)}</span><span>${fmt(n)}</span></li>`, "-");
  list($("events"), s.events, (e) => `<li><span class="tag ${esc(e.kind)}">${esc(e.kind.replace("_", " "))}</span>t=${e.t}s ${esc(e.detail)}</li>`, "No events yet.");
}

async function poll() {
  try {
    const res = await fetch("/api/state");
    render(await res.json());
  } catch (e) { /* server restarting */ }
  setTimeout(poll, 1000);
}

document.querySelectorAll("[data-preset]").forEach((b) =>
  b.addEventListener("click", () => fetch("/api/launch", { method: "POST", body: JSON.stringify({ preset: b.dataset.preset }) })));
$("stop").addEventListener("click", () => fetch("/api/stop", { method: "POST", body: "{}" }));

$("ask").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const q = $("question").value.trim();
  if (!q) return;
  $("question").value = "";
  const chat = $("chat");
  chat.insertAdjacentHTML("beforeend", `<div class="q">${esc(q)}</div>`);
  const res = await fetch("/api/chat", { method: "POST", body: JSON.stringify({ question: q }) });
  const { answer } = await res.json();
  chat.insertAdjacentHTML("beforeend", `<div class="a">${esc(answer)}</div>`);
  chat.scrollTop = chat.scrollHeight;
});

poll();
