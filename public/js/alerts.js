import { nwApi } from './api.js';

/**
 * NetWatch — Alerts Forensic Logic
 */

// ── Auth Guard
const token = sessionStorage.getItem('nw_token');
const user  = JSON.parse(sessionStorage.getItem('nw_user') || 'null');
if (!token || !user) { window.location.href = '/'; }

// ── UI Setup
document.getElementById('userNameDisplay').textContent = user.username;
document.getElementById('userAvatar').textContent = user.username[0].toUpperCase();
if (user.role === 'admin') {
  document.getElementById('navUsers').style.display = 'inline-flex';
}
document.getElementById('logoutBtn').addEventListener('click', () => {
  sessionStorage.clear();
  window.location.href = '/';
});

// ── Toast Helper
function toast(msg, type = 'info', duration = 3000) {
  const tc  = document.getElementById('toastContainer');
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

// ── Constants & State
let currentPage = 1;
const limit = 50;
let totalPages = 1;

// ── DOM Elements
const tbody = document.getElementById('alertsTbody');
const btnPrev = document.getElementById('btnPrev');
const btnNext = document.getElementById('btnNext');
const pageCurrent = document.getElementById('pageCurrent');
const pageTotal = document.getElementById('pageTotal');
const resultsCount = document.getElementById('resultsCount');
const filterSeverity = document.getElementById('filterSeverity');

function severityBadge(sev) {
  const base = "px-1.5 py-0.5 border text-[0.65rem] uppercase tracking-wider font-bold inline-flex items-center gap-1";
  if (sev === 'CRITICAL') return `<span class="${base} border-sys-red text-sys-red bg-sys-red-faint"><span class="w-1.5 h-1.5 bg-sys-red block"></span> ${sev}</span>`;
  if (sev === 'HIGH') return `<span class="${base} border-sys-orange text-sys-orange bg-sys-orange-faint"><span class="w-1.5 h-1.5 bg-sys-orange block"></span> ${sev}</span>`;
  if (sev === 'MEDIUM') return `<span class="${base} border-sys-yellow text-sys-yellow bg-sys-yellow-faint"><span class="w-1.5 h-1.5 bg-sys-yellow block"></span> ${sev}</span>`;
  return `<span class="${base} border-sys-cyan text-sys-cyan bg-sys-cyan-faint"><span class="w-1.5 h-1.5 bg-sys-cyan block"></span> ${sev}</span>`;
}

async function loadPage(page) {
  try {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-sys-text-muted p-12 font-sans text-sm"><span class="animate-pulse">Accessing security vaults...</span></td></tr>`;
    
    // Severity Filter logic (if "HIGH & ABOVE")
    let sevValue = filterSeverity.value;
    
    const data = await nwApi.getAlerts({
      page,
      limit,
      severity: sevValue
    });

    renderTable(data);
  } catch (err) {
    toast(err.message, 'error');
  }
}

function renderTable(data) {
  if (!data.alerts || data.alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-sys-text-muted p-12 font-sans text-sm">No security incidents found for the given criteria.</td></tr>`;
    return;
  }

  const frag = document.createDocumentFragment();
  data.alerts.forEach(a => {
    const tr = document.createElement('tr');
    tr.className = `hover:bg-sys-border/20 transition-colors border-l-2 ${a.severity === 'CRITICAL' ? 'border-sys-red bg-sys-red-faint/10' : (a.severity === 'HIGH' ? 'border-sys-orange' : 'border-sys-yellow')}`;
    const t = new Date(a.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium', hour12: false });
    
    tr.innerHTML = `
      <td class="px-5 py-3 text-sys-text-muted">${t}</td>
      <td class="px-5 py-3">${severityBadge(a.severity)}</td>
      <td class="px-5 py-3 font-bold text-sys-text">${a.type}</td>
      <td class="px-5 py-3 text-sys-text-muted italic">"${a.message}"</td>
      <td class="px-5 py-3 font-mono">${a.metadata?.srcIp || 'N/A'}</td>
      <td class="px-5 py-3 font-mono text-sys-text-muted">${a.metadata?.dstIp || 'N/A'}:${a.metadata?.dstPort || ''}</td>`;
    frag.appendChild(tr);
  });

  tbody.innerHTML = '';
  tbody.appendChild(frag);

  // Update Pagination State
  currentPage = data.page;
  totalPages = Math.ceil(data.total / limit) || 1;
  pageCurrent.textContent = currentPage;
  pageTotal.textContent = totalPages;
  resultsCount.textContent = `Total: ${data.total.toLocaleString()}`;

  btnPrev.disabled = currentPage <= 1;
  btnNext.disabled = currentPage >= totalPages;
}

// ── Event Listeners
document.getElementById('btnApply').addEventListener('click', () => loadPage(1));
document.getElementById('btnClear').addEventListener('click', () => {
  filterSeverity.value = "";
  loadPage(1);
});

btnPrev.addEventListener('click', () => { if (currentPage > 1) loadPage(currentPage - 1); });
btnNext.addEventListener('click', () => { if (currentPage < totalPages) loadPage(currentPage + 1); });

// ── Init
loadPage(1);
