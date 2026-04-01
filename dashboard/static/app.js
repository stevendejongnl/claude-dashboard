// ============================================================
// State
// ============================================================
const MAX_LIVE_ROWS = 200;
const MAX_EVT_ROWS  = 500;
const MAX_LEAK_ROWS = 500;

let flowCount   = 0;
let leakCount   = 0;
let allFlows    = [];
let allEvents   = [];
let allLeaks    = [];
let statsChart  = null;

// ============================================================
// WebSocket
// ============================================================
function connectWS() {
  const base = (document.querySelector('base')?.getAttribute('href') || '/').replace(/\/$/, '');
  const wsUrl = `ws://${location.host}${base}/ws`;
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    document.getElementById('ws-dot').style.background = 'var(--green)';
    document.getElementById('ws-status').textContent = 'live';
  };

  ws.onclose = () => {
    document.getElementById('ws-dot').style.background = 'var(--red)';
    document.getElementById('ws-status').textContent = 'reconnecting...';
    setTimeout(connectWS, 3000);
  };

  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === 'flow')  handleNewFlow(msg.data);
    if (msg.type === 'event') handleNewEvent(msg.data);
    if (msg.type === 'leak')  handleNewLeak(msg.data);
  };
}

// ============================================================
// Live Wire panel
// ============================================================
function categoryClass(cat) {
  return `cat-${cat}`;
}

function handleNewFlow(flow) {
  allFlows.unshift(flow);
  if (allFlows.length > MAX_LIVE_ROWS) allFlows.pop();
  flowCount++;
  document.getElementById('flow-count').textContent = `${flowCount} flows`;
  renderFlows();
}

function renderFlows() {
  const container = document.getElementById('live-wire-body');
  const html = allFlows.slice(0, MAX_LIVE_ROWS).map(f => {
    const ts = f.ts ? f.ts.substring(11, 19) : '??:??:??';
    const statusCls = (f.status >= 200 && f.status < 300) ? 'status-ok' : 'status-err';
    const path = f.path.length > 40 ? f.path.substring(0, 40) + '…' : f.path;
    const leakBadge = f.leak_count ? `<span style="color:var(--red);font-weight:600">⚠${f.leak_count}</span>` : '';
    return `<div class="flow-row" onclick="showDetail(${f.id})" data-id="${f.id}">
      <span class="${categoryClass(f.category)}">${f.category}</span>
      <span>${ts}</span>
      <span title="${f.path}">${path}</span>
      <span class="${statusCls}">${f.status ?? '—'}</span>
      ${leakBadge}
    </div>`;
  }).join('');
  container.innerHTML = html;
}

// ============================================================
// Telemetry Events panel
// ============================================================
const evtColorMap = {
  tengu_api_success:  'var(--green)',
  tengu_api_error:    'var(--red)',
  tengu_exit:         'var(--yellow)',
  tengu_init:         'var(--accent)',
  tengu_tool_use_success: 'var(--purple)',
};

function handleNewEvent(evt) {
  allEvents.unshift(evt);
  if (allEvents.length > MAX_EVT_ROWS) allEvents.pop();
  renderEvents();
}

function renderEvents() {
  const filter = document.getElementById('evt-filter').value.toLowerCase();
  const container = document.getElementById('evt-panel');
  const visible = allEvents.filter(e =>
    !filter || e.event_name.toLowerCase().includes(filter)
  ).slice(0, 200);

  const html = visible.map(e => {
    const ts = e.client_ts ? e.client_ts.substring(11, 19) : '—';
    const color = evtColorMap[e.event_name] || 'var(--text)';
    let meta = '';
    try {
      const am = JSON.parse(e.additional_meta || '{}');
      if (am.costUSD !== undefined)    meta = `$${am.costUSD?.toFixed(4)}`;
      else if (am.inputTokens)         meta = `${am.inputTokens}↓/${am.outputTokens}↑`;
      else if (am.durationMs)          meta = `${am.durationMs}ms`;
    } catch {}
    return `<div class="evt-row">
      <span class="evt-ts">${ts}</span>
      <span class="evt-name" style="color:${color}">${e.event_name}</span>
      <span style="color:var(--muted);font-size:10px">${meta}</span>
    </div>`;
  }).join('');
  container.innerHTML = html;
}

document.getElementById('evt-filter').addEventListener('input', renderEvents);

// ============================================================
// Leaks panel
// ============================================================
function handleNewLeak(leak) {
  allLeaks.unshift(leak);
  if (allLeaks.length > MAX_LEAK_ROWS) allLeaks.pop();
  leakCount++;
  updateLeakBadge();
  renderLeaks();
}

function updateLeakBadge() {
  const badge = document.getElementById('leak-badge');
  const count = document.getElementById('leak-count');
  if (leakCount > 0) {
    badge.classList.remove('hidden');
    count.textContent = leakCount;
  }
}

function renderLeaks() {
  const container = document.getElementById('leaks-panel');
  const lc = document.getElementById('leaks-count');
  lc.textContent = leakCount;

  if (allLeaks.length === 0) {
    container.innerHTML = '<div class="leak-empty">✓ No secrets detected</div>';
    return;
  }

  const html = allLeaks.slice(0, MAX_LEAK_ROWS).map(l => {
    const sev = (l.severity || 'MEDIUM').toLowerCase();
    return `<div class="leak-row" title="${l.description}">
      <span class="leak-badge ${sev}">${l.severity}</span>
      <span class="leak-desc">${l.description}</span>
      <span class="leak-redacted">${l.redacted_match}</span>
      <span style="color:var(--muted);font-size:10px">${l.entropy?.toFixed(2) ?? '—'}</span>
    </div>`;
  }).join('');
  container.innerHTML = html;
}

// ============================================================
// API Stats chart (Chart.js)
// ============================================================
async function loadStats() {
  const resp = await fetch('api/stats/cost');
  const data = await resp.json();

  const days = [...new Set(data.map(r => r.day))].sort();
  const costByDay = days.map(d =>
    data.filter(r => r.day === d).reduce((s, r) => s + (r.total_cost || 0), 0)
  );
  const inputByDay = days.map(d =>
    data.filter(r => r.day === d).reduce((s, r) => s + (r.input_tokens || 0), 0)
  );
  const outputByDay = days.map(d =>
    data.filter(r => r.day === d).reduce((s, r) => s + (r.output_tokens || 0), 0)
  );

  const ctx = document.getElementById('stats-chart').getContext('2d');
  if (statsChart) statsChart.destroy();

  const mode = document.getElementById('chart-mode').value;
  const isCost = mode === 'cost';

  statsChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: days,
      datasets: isCost
        ? [{ label: 'Cost USD', data: costByDay, backgroundColor: 'rgba(88,166,255,0.6)', borderColor: 'var(--accent)', borderWidth: 1 }]
        : [
            { label: 'Input Tokens',  data: inputByDay,  backgroundColor: 'rgba(63,185,80,0.6)', borderColor: 'var(--green)', borderWidth: 1 },
            { label: 'Output Tokens', data: outputByDay, backgroundColor: 'rgba(210,153,34,0.6)', borderColor: 'var(--yellow)', borderWidth: 1 },
          ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#8b949e', font: { family: 'monospace', size: 11 } } }
      },
      scales: {
        x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } }
      }
    }
  });
}

document.getElementById('chart-mode').addEventListener('change', loadStats);

// ============================================================
// Sessions panel
// ============================================================
async function loadSessions() {
  const resp = await fetch('api/sessions');
  const data = await resp.json();

  const totalCost = data.reduce((s, r) => s + (r.cost_usd || 0), 0);
  document.getElementById('total-cost').textContent =
    `$${totalCost.toFixed(4)} total`;

  const tbody = document.getElementById('sessions-body');
  tbody.innerHTML = data.map(s => `
    <tr>
      <td style="color:var(--muted);font-size:10px">${s.session_id?.substring(0, 8)}…</td>
      <td style="color:var(--muted);font-size:10px">${s.end_ts?.substring(0, 10) ?? '—'}</td>
      <td style="color:var(--yellow)">$${(s.cost_usd || 0).toFixed(4)}</td>
      <td>${(s.input_tokens || 0).toLocaleString()}</td>
      <td>${(s.output_tokens || 0).toLocaleString()}</td>
      <td style="color:var(--green)">+${s.lines_added ?? 0}</td>
      <td style="color:var(--red)">-${s.lines_removed ?? 0}</td>
    </tr>
  `).join('');
}

// ============================================================
// Detail overlay (click a flow to see req/resp body)
// ============================================================
function showDetail(flowId) {
  const flow = allFlows.find(f => f.id === flowId);
  if (!flow) return;

  let content = `Category: ${flow.category}\nHost: ${flow.host}\nPath: ${flow.path}\n`;
  content += `Status: ${flow.status}  Duration: ${flow.duration_ms}ms\n`;
  content += `Request Size: ${flow.req_size}B  Response Size: ${flow.resp_size}B\n\n`;

  if (flow.req_body) {
    try {
      content += '--- REQUEST BODY ---\n';
      content += JSON.stringify(JSON.parse(flow.req_body), null, 2);
      content += '\n\n';
    } catch { content += flow.req_body + '\n\n'; }
  }
  if (flow.resp_body) {
    try {
      content += '--- RESPONSE BODY ---\n';
      content += JSON.stringify(JSON.parse(flow.resp_body), null, 2);
    } catch { content += flow.resp_body; }
  }

  document.getElementById('detail-content').textContent = content;
  document.getElementById('detail-overlay').classList.add('open');
}

document.getElementById('detail-close').onclick = () =>
  document.getElementById('detail-overlay').classList.remove('open');

document.getElementById('detail-overlay').onclick = (e) => {
  if (e.target === document.getElementById('detail-overlay'))
    document.getElementById('detail-overlay').classList.remove('open');
};

// ============================================================
// Initial data load
// ============================================================
async function initialLoad() {
  const [flows, events, leaks] = await Promise.all([
    fetch('api/flows').then(r => r.json()),
    fetch('api/events').then(r => r.json()),
    fetch('api/leaks').then(r => r.json()),
  ]);

  allFlows = flows;
  flowCount = flows.length;
  document.getElementById('flow-count').textContent = `${flowCount} flows`;
  renderFlows();

  allEvents = events;
  renderEvents();

  allLeaks = leaks;
  leakCount = leaks.length;
  updateLeakBadge();
  renderLeaks();

  await loadStats();
  await loadSessions();
}

// ============================================================
// Bootstrap
// ============================================================
initialLoad();
connectWS();

// Refresh sessions and stats every 30s to pick up new data
setInterval(async () => {
  await loadSessions();
  await loadStats();
}, 30000);
