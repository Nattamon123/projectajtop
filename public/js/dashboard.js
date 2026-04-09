import { nwSocket } from './api.js';

/**
 * NetWatch Dashboard — Main Client Script
 */

// ── Auth Guard ────────────────────────────────────────────────────────────────
const token = sessionStorage.getItem('nw_token');
const user  = JSON.parse(sessionStorage.getItem('nw_user') || 'null');
if (!token || !user) { window.location.href = '/'; }

// ── User Info ─────────────────────────────────────────────────────────────────
document.getElementById('userNameDisplay').textContent = user.username;
document.getElementById('userAvatar').textContent = user.username[0].toUpperCase();
if (user.role === 'admin') {
  document.getElementById('captureControls').style.display = 'block';
  document.getElementById('navUsers').style.display = 'inline-flex';
}
document.getElementById('logoutBtn').addEventListener('click', () => {
  sessionStorage.clear();
  window.location.href = '/';
});

// ── Toast Helper ──────────────────────────────────────────────────────────────
function toast(msg, type = 'info', duration = 3000) {
  const tc  = document.getElementById('toastContainer');
  
  // Anti-flood: max 5 toasts visible at a time
  while (tc.children.length >= 5) {
    tc.removeChild(tc.firstChild);
  }

  const el  = document.createElement('div');
  
  const baseClasses = "px-4 py-3 text-sm font-semibold border bg-sys-surface shadow-xl flex items-center gap-3 animate-[slideIn_0.3s_ease-out]";
  let typeClasses = "";
  if (type === 'success') typeClasses = "border-sys-green text-sys-green";
  else if (type === 'error') typeClasses = "border-sys-red text-sys-red";
  else typeClasses = "border-sys-cyan text-sys-cyan";
  
  el.className = `${baseClasses} ${typeClasses}`;
  el.innerHTML = `<span class="w-1.5 h-1.5 inline-block ${type === 'error' ? 'bg-sys-red' : (type === 'success' ? 'bg-sys-green' : 'bg-sys-cyan')}"></span> ${msg}`;
  
  tc.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

// ── Chart.js Global Defaults ──────────────────────────────────────────────────
Chart.defaults.color          = '#a1a1aa'; // text-sys-text-muted
Chart.defaults.borderColor    = '#27272a'; // border-sys-border
Chart.defaults.font.family    = "'Inter', sans-serif";
Chart.defaults.font.size      = 11;

const COLORS = {
  cyan:   '#06b6d4',
  purple: '#8b5cf6',
  green:  '#10b981',
  red:    '#ef4444',
  orange: '#f97316',
  yellow: '#eab308',
  blue:   '#3b82f6',
  pink:   '#ec4899',
};

const PROTOCOL_COLORS = {
  HTTPS:      COLORS.cyan,
  HTTP:       COLORS.orange,
  SSH:        COLORS.green,
  DNS:        COLORS.yellow,
  SMTP:       COLORS.blue,
  SMTPS:      COLORS.purple,
  IMAPS:      COLORS.pink,
  POP3S:      '#e040fb',
  MySQL:      '#ff8f00',
  ICMP:       COLORS.red,
  NTP:        '#80cbc4',
  'HTTP-Alt': '#ffab40',
  Unknown:    '#546e7a',
};

function protocolColor(name) { return PROTOCOL_COLORS[name] || '#546e7a'; }

const TLS_COLORS = {
  'TLS 1.3': COLORS.green,
  'TLS 1.2': COLORS.cyan,
  'TLS 1.1': COLORS.yellow,
  'TLS 1.0': COLORS.orange,
  'SSL 3.0': COLORS.red,
  'SSH-2.0': COLORS.purple,
};

// ── Chart: Packets per Second (Line) ─────────────────────────────────────────
const ctxPps = document.getElementById('chartPps').getContext('2d');
const ppsData = {
  labels:   [],
  datasets: [{
    label: 'Packets/sec',
    data: [],
    borderColor: COLORS.cyan,
    backgroundColor: 'rgba(0,245,255,0.06)',
    borderWidth: 2,
    fill: true,
    tension: 0.4,
    pointRadius: 0,
    pointHoverRadius: 4,
  }],
};
const chartPps = new Chart(ctxPps, {
  type: 'line',
  data: ppsData,
  options: {
    animation: false,
    responsive: true,
    maintainAspectRatio: false,
    interaction: { intersect: false, mode: 'index' },
    plugins: { legend: { display: false } },
    scales: {
      x: {
        grid: { color: 'rgba(0,245,255,0.05)' },
        ticks: { maxTicksLimit: 10, maxRotation: 0 },
      },
      y: {
        grid: { color: 'rgba(0,245,255,0.05)' },
        min: 0,
        ticks: { callback: (v) => v >= 1000 ? (v/1000).toFixed(1)+'k' : v },
      },
    },
  },
});

// ── Chart: Protocol Distribution (Doughnut) ───────────────────────────────────
const ctxProto = document.getElementById('chartProtocol').getContext('2d');
const chartProtocol = new Chart(ctxProto, {
  type: 'doughnut',
  data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: 'rgba(5,8,22,0.8)', borderWidth: 2, hoverOffset: 6 }] },
  options: {
    animation: { duration: 400 },
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'right', labels: { boxWidth: 10, padding: 10, font: { size: 11 } } },
      tooltip: { callbacks: {
        label: (ctx) => ` ${ctx.label}: ${ctx.parsed.toLocaleString()} pkts`,
      }},
    },
    cutout: '65%',
  },
});

// ── Chart: Encryption Status (Horizontal Bar) ─────────────────────────────────
const ctxEnc = document.getElementById('chartEncryption').getContext('2d');
const chartEncryption = new Chart(ctxEnc, {
  type: 'bar',
  data: {
    labels: ['Encrypted', 'Unencrypted'],
    datasets: [{
      data: [0, 0],
      backgroundColor: [COLORS.green, COLORS.red],
      borderColor:     ['rgba(0,255,136,0.5)', 'rgba(255,71,87,0.5)'],
      borderWidth: 1,
      borderRadius: 4,
    }],
  },
  options: {
    animation: false,
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: 'rgba(0,245,255,0.05)' }, ticks: { callback: (v) => v >= 1000 ? (v/1000).toFixed(0)+'k' : v } },
      y: { grid: { display: false } },
    },
  },
});

// ── Chart: TLS Versions (Bar) ──────────────────────────────────────────────────
const ctxTLS = document.getElementById('chartTLS').getContext('2d');
const chartTLS = new Chart(ctxTLS, {
  type: 'bar',
  data: { labels: [], datasets: [{ label: 'Packets', data: [], backgroundColor: [], borderRadius: 4 }] },
  options: {
    animation: false,
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { display: false } },
      y: { grid: { color: 'rgba(0,245,255,0.05)' }, ticks: { callback: (v) => v >= 1000 ? (v/1000).toFixed(0)+'k' : v } },
    },
  },
});

// ── Chart: Top Source IPs (Bar) ─────────────────────────────────────────────────
const ctxTop = document.getElementById('chartTopIPs').getContext('2d');
const chartTopIPs = new Chart(ctxTop, {
  type: 'bar',
  data: { labels: [], datasets: [{ label: 'Packets', data: [], backgroundColor: 'rgba(123,47,255,0.6)', borderColor: COLORS.purple, borderWidth: 1, borderRadius: 4 }] },
  options: {
    animation: false,
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: 'rgba(0,245,255,0.05)' }, ticks: { callback: (v) => v >= 1000 ? (v/1000).toFixed(0)+'k' : v } },
      y: { grid: { display: false }, ticks: { font: { family: "'JetBrains Mono'" }, color: '#7986cb' } },
    },
  },
});

// ── Chart: Packet Size Distribution (Bar) ────────────────────────────────────
const ctxSize = document.getElementById('chartSize').getContext('2d');
const chartSize = new Chart(ctxSize, {
  type: 'bar',
  data: {
    labels: ['0–64 B', '65–256 B', '257–512 B', '513–1024 B', '1025+ B'],
    datasets: [{
      label: 'Bytes',
      data: [0, 0, 0, 0, 0],
      backgroundColor: [
        'rgba(0,245,255,0.5)', 'rgba(0,255,136,0.5)',
        'rgba(123,47,255,0.5)', 'rgba(255,107,53,0.5)', 'rgba(255,71,87,0.5)',
      ],
      borderRadius: 4,
    }],
  },
  options: {
    animation: false,
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { display: false } },
      y: { grid: { color: 'rgba(0,245,255,0.05)' }, ticks: { callback: (v) => v >= 1000 ? (v/1000).toFixed(0)+'k' : v } },
    },
  },
});

// ── Stats Update ──────────────────────────────────────────────────────────────
function updateKPIs(s) {
  const total = s.totalPackets;
  animateNum('kpiTotal', total);
  animateNum('kpiPps', s.currentPps);
  document.getElementById('kpiEncPct').textContent  = s.encryptedPct + '%';
  document.getElementById('kpiEncAbs').textContent  = `${s.encryptedPackets.toLocaleString()} / ${total.toLocaleString()} packets`;
  const plainPct = 100 - s.encryptedPct;
  document.getElementById('kpiPlainPct').textContent  = plainPct + '%';
  document.getElementById('kpiPlainAbs').textContent  = `${s.unencryptedPackets.toLocaleString()} packets exposed`;
  document.getElementById('livePps').textContent = `${s.currentPps.toLocaleString()} pps`;
}

function updatePpsChart(history) {
  const labels = history.map((p) => new Date(p.t).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }));
  const data   = history.map((p) => p.pps);
  ppsData.labels            = labels;
  ppsData.datasets[0].data  = data;
  chartPps.update('none');
}

function updateProtocolChart(protocols) {
  const entries = Object.entries(protocols).sort(([, a], [, b]) => b - a);
  chartProtocol.data.labels                        = entries.map(([k]) => k);
  chartProtocol.data.datasets[0].data              = entries.map(([, v]) => v);
  chartProtocol.data.datasets[0].backgroundColor   = entries.map(([k]) => protocolColor(k));
  chartProtocol.update('none');
}

function updateEncryptionChart(s) {
  chartEncryption.data.datasets[0].data = [s.encryptedPackets, s.unencryptedPackets];
  chartEncryption.update('none');
}

function updateTLSChart(tlsVersions) {
  // TLS version severity order
  const ORDER = ['TLS 1.3', 'TLS 1.2', 'SSH-2.0', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0'];
  const sorted = ORDER.filter((k) => tlsVersions[k]);
  chartTLS.data.labels                      = sorted;
  chartTLS.data.datasets[0].data            = sorted.map((k) => tlsVersions[k] || 0);
  chartTLS.data.datasets[0].backgroundColor = sorted.map((k) => TLS_COLORS[k] || '#546e7a');
  chartTLS.update('none');
}

function updateTopIPsChart(topIps) {
  chartTopIPs.data.labels            = topIps.slice(0,8).map((x) => x.ip);
  chartTopIPs.data.datasets[0].data  = topIps.slice(0,8).map((x) => x.count);
  chartTopIPs.update('none');
}

function updateSizeChart(buckets) {
  const keys = ['0-64', '65-256', '257-512', '513-1024', '1025+'];
  chartSize.data.datasets[0].data = keys.map((k) => buckets[k] || 0);
  chartSize.update('none');
}

function handleStats(s) {
  updateKPIs(s);
  updatePpsChart(s.ppsHistory || []);
  updateProtocolChart(s.protocols || {});
  updateEncryptionChart(s);
  updateTLSChart(s.tlsVersions || {});
  updateTopIPsChart(s.topSrcIps || []);
  updateSizeChart(s.sizeBuckets || {});
}

// ── Number counter animation ──────────────────────────────────────────────────
function animateNum(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  const prev = parseInt(el.textContent.replace(/,/g, '') || '0');
  if (prev === val) return;
  el.textContent = val.toLocaleString();
  el.classList.remove('brightness-200');
  void el.offsetWidth; // reflow
  el.classList.add('brightness-200', 'transition-all', 'duration-300');
  setTimeout(() => el.classList.remove('brightness-200'), 300);
}

// ── Live Packet Feed ──────────────────────────────────────────────────────────
let feedCount    = 0;
const MAX_ROWS   = 120;
const tbody      = document.getElementById('packetTbody');
let isStreamPaused = false;

document.getElementById('btnPauseStream').addEventListener('click', (e) => {
  isStreamPaused = !isStreamPaused;
  const dot = document.getElementById('pauseDot');
  const label = document.getElementById('pauseLabel');
  if (isStreamPaused) {
    dot.className = "w-1.5 h-1.5 bg-sys-yellow inline-block";
    label.textContent = "Paused";
    label.classList.add("text-sys-yellow");
  } else {
    dot.className = "w-1.5 h-1.5 bg-sys-green inline-block animate-pulse";
    label.textContent = "Live";
    label.classList.remove("text-sys-yellow");
  }
});

function encBadge(pkt) {
  const base = "px-1.5 py-0.5 border text-[0.65rem] uppercase tracking-wider font-bold inline-flex items-center gap-1";
  if (!pkt.encrypted) return `<span class="${base} border-sys-red text-sys-red bg-sys-red-faint"><span class="w-1 h-1 bg-sys-red block"></span> Plain</span>`;
  if (!pkt.tlsVersion) return `<span class="${base} border-sys-green text-sys-green bg-sys-green-faint"><span class="w-1 h-1 bg-sys-green block"></span> Encrypted</span>`;
  
  // Warn on legacy TLS
  if (['SSL 3.0','TLS 1.0','TLS 1.1'].includes(pkt.tlsVersion))
    return `<span class="${base} border-sys-yellow text-sys-yellow bg-sys-yellow-faint"><span class="w-1 h-1 bg-sys-yellow block"></span> ${pkt.tlsVersion}</span>`;
    
  return `<span class="${base} border-sys-green text-sys-green bg-sys-green-faint"><span class="w-1 h-1 bg-sys-green block"></span> ${pkt.tlsVersion}</span>`;
}

function rowClass(pkt) {
  if (!pkt.encrypted) return 'border-l-2 border-sys-red';
  if (['SSL 3.0','TLS 1.0','TLS 1.1'].includes(pkt.tlsVersion)) return 'border-l-2 border-sys-yellow';
  return 'border-l-2 border-sys-green';
}

function appendPackets(packets) {
  if (isStreamPaused) return; // Drop DOM updates if paused

  // Clear placeholder row
  if (tbody.children.length === 1 && tbody.children[0].children.length === 1) {
    tbody.innerHTML = '';
  }

  const frag = document.createDocumentFragment();
  for (const p of packets) {
    feedCount++;
    const tr = document.createElement('tr');
    tr.className = rowClass(p);
    const t = new Date(p.timestamp).toLocaleTimeString([], { hour12: false });
    tr.innerHTML = `
      <td class="px-5 py-2 text-sys-text-muted">${t}</td>
      <td class="px-5 py-2">${p.srcIp}</td>
      <td class="px-5 py-2">${p.dstIp}</td>
      <td class="px-5 py-2 text-sys-cyan">${p.protocol}</td>
      <td class="px-5 py-2" style="color:${protocolColor(p.appProtocol)}">${p.appProtocol}</td>
      <td class="px-5 py-2 text-sys-text-muted">${p.dstPort}</td>
      <td class="px-5 py-2">${p.size} B</td>
      <td class="px-5 py-2">${encBadge(p)}</td>`;
    frag.prepend(tr);
  }
  tbody.prepend(frag);

  // Keep MAX_ROWS rows
  while (tbody.children.length > MAX_ROWS) tbody.removeChild(tbody.lastChild);
  document.getElementById('feedCount').textContent = `${feedCount.toLocaleString()} pkt`;
}

// ── Socket.IO ─────────────────────────────────────────────────────────────────
let socket;

function connectSocket() {
  socket = io({ auth: { token }, reconnectionAttempts: 10, reconnectionDelay: 1500 });

  socket.on('connect', () => {
    toast('Connected to NetWatch server', 'success');
    updateCaptureStatus({ running: false });
  });

  socket.on('disconnect', (reason) => {
    toast(`Disconnected: ${reason}`, 'error', 5000);
    updateCaptureStatus({ running: false });
  });

  socket.on('connect_error', (err) => {
    toast(`Connection error: ${err.message}`, 'error');
  });

  socket.on('stats:update', handleStats);
  socket.on('stats:reset',  () => {
    feedCount = 0;
    document.getElementById('feedCount').textContent = '0 packets';
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:2rem;">Stats reset. Waiting…</td></tr>';
    toast('Stats reset', 'info');
  });

  socket.on('security_alert', (alert) => {
    toast(`[${alert.severity}] ${alert.message}`, alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'error' : 'info', 8000);
  });

  socket.on('packet:batch', appendPackets);
  socket.on('capture:status', updateCaptureStatus);
  socket.on('error:auth', (e) => toast(e.message, 'error'));
}

// ── Capture Controls ──────────────────────────────────────────────────────────
function updateCaptureStatus(s) {
  const dot      = document.getElementById('captureDot');
  const status   = document.getElementById('captureStatus');
  const btnStart = document.getElementById('btnStart');
  const btnStop  = document.getElementById('btnStop');

  if (s.running) {
    dot.className = "w-2 h-2 bg-sys-green inline-block shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse";
    status.textContent = `Running — ${s.interface}`;
    status.className = "text-sys-green";
  } else {
    dot.className = "w-2 h-2 bg-sys-red inline-block";
    status.textContent = "Stopped";
    status.className = "text-sys-text-muted";
  }

  if (btnStart) {
    btnStart.disabled = s.running;
    btnStop.disabled  = !s.running;
    if(s.running) {
      btnStart.classList.add('opacity-50', 'pointer-events-none');
      btnStop.classList.remove('opacity-50', 'pointer-events-none');
    } else {
      btnStart.classList.remove('opacity-50', 'pointer-events-none');
      btnStop.classList.add('opacity-50', 'pointer-events-none');
    }
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
connectSocket();

if (user.role === 'admin') {
  const ifaceSelect = document.getElementById('ifaceSelect');
  const ppsRange    = document.getElementById('ppsRange');
  const ppsLabel    = document.getElementById('ppsLabel');
  const btnStart    = document.getElementById('btnStart');
  const btnStop     = document.getElementById('btnStop');
  const btnReset    = document.getElementById('btnResetStats');

  // Wait for socket, then fetch interfaces
  async function loadInterfaces() {
    const { interfaces } = await nwSocket.getInterfaces(socket);
    ifaceSelect.innerHTML = interfaces.map((i) =>
      `<option value="${i.name}">${i.name} — ${i.desc}</option>`
    ).join('');
  }

  socket.on('connect', loadInterfaces);

  ppsRange.addEventListener('input', () => {
    ppsLabel.textContent = parseInt(ppsRange.value).toLocaleString();
  });

  btnStart.addEventListener('click', () => {
    const iface = ifaceSelect.value;
    const pps   = parseInt(ppsRange.value);
    if (!iface) { toast('Please select an interface', 'error'); return; }
    nwSocket.startCapture(socket, iface, pps);
    toast(`Starting capture on ${iface} @ ${pps.toLocaleString()} pps`, 'success');
  });

  btnStop.addEventListener('click', () => {
    nwSocket.stopCapture(socket);
    toast('Capture stopped', 'info');
  });

  btnReset.addEventListener('click', () => {
    if (confirm('Reset all statistics?')) nwSocket.resetStats(socket);
  });
}
