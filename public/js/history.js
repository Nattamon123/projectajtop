import { nwApi } from './api.js';

/**
 * NetWatch — History Logic
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
const COLORS = {
  cyan: '#06b6d4', orange: '#f97316', green: '#10b981', yellow: '#eab308',
  blue: '#3b82f6', purple: '#8b5cf6', pink: '#ec4899', red: '#ef4444'
};
const PROTOCOL_COLORS = {
  HTTPS: COLORS.cyan, HTTP: COLORS.orange, SSH: COLORS.green, DNS: COLORS.yellow,
  SMTP: COLORS.blue, SMTPS: COLORS.purple, ICMP: COLORS.red, Unknown: '#546e7a',
};
function protocolColor(name) { return PROTOCOL_COLORS[name] || '#546e7a'; }

let currentPage = 1;
const limit = 100;
let totalPages = 1;

// ── DOM Elements
const tbody = document.getElementById('historyTbody');
const btnPrev = document.getElementById('btnPrev');
const btnNext = document.getElementById('btnNext');
const pageCurrent = document.getElementById('pageCurrent');
const pageTotal = document.getElementById('pageTotal');
const resultsCount = document.getElementById('resultsCount');

const filterProtocol = document.getElementById('filterProtocol');
const filterAppProtocol = document.getElementById('filterAppProtocol');
const filterEncrypted = document.getElementById('filterEncrypted');

// ดึงตัวแปรช่องค้นหาขั้นสูงมาเก็บไว้
const filterSrcIp = document.getElementById('filterSrcIp');
const filterDstIp = document.getElementById('filterDstIp');
const filterDstPort = document.getElementById('filterDstPort');

// ── Data Fetching
async function fetchHistory(page = 1, isExport = false) {
  return nwApi.getHistory({
    page,
    limit: isExport ? 5000 : limit,
    protocol: filterProtocol.value,
    appProtocol: filterAppProtocol.value,
    encrypted: filterEncrypted.value,
    // ส่งค่าไปยัง Backend ถ้ามีการพิมพ์
    srcIp: filterSrcIp.value.trim(),
    dstIp: filterDstIp.value.trim(),
    dstPort: filterDstPort.value.trim()
  });
}

function encBadge(pkt) {
  const base = "px-1.5 py-0.5 border text-[0.65rem] uppercase tracking-wider font-bold inline-flex items-center gap-1";
  if (!pkt.encrypted) return `<span class="${base} border-sys-red text-sys-red bg-sys-red-faint"><span class="w-1 h-1 bg-sys-red block"></span> Plain</span>`;
  if (!pkt.tlsVersion) return `<span class="${base} border-sys-green text-sys-green bg-sys-green-faint"><span class="w-1 h-1 bg-sys-green block"></span> Encrypted</span>`;
  if (['SSL 3.0','TLS 1.0','TLS 1.1'].includes(pkt.tlsVersion))
    return `<span class="${base} border-sys-yellow text-sys-yellow bg-sys-yellow-faint"><span class="w-1 h-1 bg-sys-yellow block"></span> ${pkt.tlsVersion}</span>`;
  return `<span class="${base} border-sys-green text-sys-green bg-sys-green-faint"><span class="w-1 h-1 bg-sys-green block"></span> ${pkt.tlsVersion}</span>`;
}

function renderTable(data) {
  if (!data.packets || data.packets.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-sys-text-muted p-12 font-sans text-sm">No packets found for the given criteria.</td></tr>`;
    return;
  }

  const frag = document.createDocumentFragment();
  data.packets.forEach(p => {
    const tr = document.createElement('tr');
    tr.className = `hover:bg-sys-border/20 transition-colors ${!p.encrypted ? 'border-l-2 border-sys-red' : (['SSL 3.0','TLS 1.0','TLS 1.1'].includes(p.tlsVersion) ? 'border-l-2 border-sys-yellow' : 'border-l-2 border-sys-green')}`;
    const t = new Date(p.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium', hour12: false });
    
    tr.innerHTML = `
      <td class="px-5 py-2 text-sys-text-muted">${t}</td>
      <td class="px-5 py-2">${p.srcIp}</td>
      <td class="px-5 py-2">${p.dstIp}</td>
      <td class="px-5 py-2 text-sys-cyan">${p.protocol}</td>
      <td class="px-5 py-2" style="color:${protocolColor(p.appProtocol)}">${p.appProtocol}</td>
      <td class="px-5 py-2 text-sys-text-muted">${p.dstPort}</td>
      <td class="px-5 py-2">${p.size} B</td>
      <td class="px-5 py-2">${encBadge(p)}</td>`;
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

async function loadPage(page) {
  try {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-sys-text-muted p-12 font-sans text-sm"><span class="animate-pulse">Loading databanks...</span></td></tr>`;
    const data = await fetchHistory(page);
    renderTable(data);
  } catch (err) {
    toast(err.message, 'error');
  }
}

// ── Event Listeners
document.getElementById('btnApply').addEventListener('click', () => loadPage(1));
document.getElementById('btnClear').addEventListener('click', () => {
  // ล้างค่าทั้งหมดในทุกช่องค้นหา
  filterProtocol.value = "";
  filterAppProtocol.value = "";
  filterEncrypted.value = "";
  filterSrcIp.value = "";
  filterDstIp.value = "";
  filterDstPort.value = "";
  // โหลดข้อมูลใหม่ทั้งหมดกลับมาที่หน้า 1
  loadPage(1);
});

btnPrev.addEventListener('click', () => { if (currentPage > 1) loadPage(currentPage - 1); });
btnNext.addEventListener('click', () => { if (currentPage < totalPages) loadPage(currentPage + 1); });

// ── Export Functions
function triggerDownload(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

document.getElementById('btnExportJSON').addEventListener('click', async () => {
  try {
    toast('Preparing JSON export (up to 5000 rows)...', 'info');
    const data = await fetchHistory(1, true);
    triggerDownload(JSON.stringify(data.packets, null, 2), `netwatch_export_${Date.now()}.json`, 'application/json');
    toast('JSON Export Complete', 'success');
  } catch (err) {
    toast('Export Failed: ' + err.message, 'error');
  }
});

document.getElementById('btnExportCSV').addEventListener('click', async () => {
  try {
    toast('Preparing CSV export (up to 5000 rows)...', 'info');
    const data = await fetchHistory(1, true);
    if (!data.packets.length) {
      toast('No data to export', 'error');
      return;
    }
    
    // Create CSV Header
    const fields = ['timestamp', 'srcIp', 'dstIp', 'srcPort', 'dstPort', 'protocol', 'appProtocol', 'size', 'encrypted', 'tlsVersion'];
    let csv = fields.join(',') + '\n';
    
    // Append Rows
    for (const p of data.packets) {
      const row = fields.map(f => {
        let val = p[f];
        if (val === null || val === undefined) val = '';
        val = val.toString().replace(/"/g, '""'); // escape quotes
        return `"${val}"`;
      });
      csv += row.join(',') + '\n';
    }

    triggerDownload(csv, `netwatch_export_${Date.now()}.csv`, 'text/csv');
    toast('CSV Export Complete', 'success');
  } catch (err) {
    toast('Export Failed: ' + err.message, 'error');
  }
});

document.getElementById('btnExportPDF').addEventListener('click', async () => {
  try {
    const { jsPDF } = window.jspdf;
    if (!jsPDF) throw new Error('PDF library not loaded');

    toast('Preparing PDF Report (up to 5000 rows)...', 'info');
    const data = await fetchHistory(1, true);
    if (!data.packets || data.packets.length === 0) {
      toast('No data to export', 'error');
      return;
    }

    const doc = new jsPDF('l', 'mm', 'a4'); // Landscape A4
    const now = new Date();

    // ── PDF Header ──
    doc.setFontSize(22);
    doc.setTextColor(6, 182, 212); // sys-cyan
    doc.text('NetWatch — Forensic Traffic Report', 14, 20);
    
    doc.setFontSize(10);
    doc.setTextColor(161, 161, 170); // sys-text-muted
    doc.text(`Generated on: ${now.toLocaleString()}`, 14, 28);
    doc.text(`Total Records: ${data.total.toLocaleString()}`, 14, 33);

    // ── Table Setup ──
    const head = [['Timestamp', 'Source IP', 'Destination IP', 'Proto', 'App', 'Port', 'Size', 'Encryption']];
    const body = data.packets.map(p => [
      new Date(p.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium', hour12: false }),
      p.srcIp,
      p.dstIp,
      p.protocol,
      p.appProtocol,
      p.dstPort,
      `${p.size} B`,
      p.encrypted ? (p.tlsVersion || 'Encrypted') : 'Plain'
    ]);

    doc.autoTable({
      head,
      body,
      startY: 40,
      theme: 'grid',
      styles: {
        fontSize: 8,
        font: 'courier',
        cellPadding: 2,
        overflow: 'linebreak',
        halign: 'left'
      },
      headStyles: {
        fillColor: [39, 39, 42], // sys-border
        textColor: [255, 255, 255],
        fontStyle: 'bold'
      },
      alternateRowStyles: {
        fillColor: [244, 244, 245]
      },
      columnStyles: {
        0: { cellWidth: 35 }, // Timestamp
        6: { halign: 'right' } // Size
      },
      margin: { top: 40 }
    });

    doc.save(`netwatch_report_${Date.now()}.pdf`);
    toast('PDF Report Generated', 'success');
  } catch (err) {
    console.error(err);
    toast('PDF Export Failed: ' + err.message, 'error');
  }
});

// ── Init
loadPage(1);
