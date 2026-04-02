const socket   = io();
const list     = document.getElementById('alerts-list');
const empty    = document.getElementById('empty-state');
const dot      = document.getElementById('status-dot');
const statusTx = document.getElementById('status-text');
const lastSeen = document.getElementById('last-seen');
const stats    = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
const statEls  = Object.fromEntries(Object.keys(stats).map(k => [k, document.getElementById('stat-' + k)]));
let activeFilter = 'all';

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

let uptimeInterval = null;
let connectedAt    = null;

function formatUptime(seconds) {
  const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
  const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
  const s = String(seconds % 60).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

socket.on('connect', () => {
  dot.className = 'dot live';
  statusTx.textContent = 'LIVE';
  connectedAt = Date.now();
  clearInterval(uptimeInterval);
  uptimeInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - connectedAt) / 1000);
    lastSeen.textContent = 'UP ' + formatUptime(elapsed);
  }, 1000);
});

socket.on('disconnect', () => {
  dot.className = 'dot dead';
  statusTx.textContent = 'DISCONNECTED';
  clearInterval(uptimeInterval);
  lastSeen.textContent = '--';
});

socket.on('alert', (data) => {
  empty.style.display = 'none';
  addAlert(data);
});

// Add a new alert to the alert list
function addAlert(a) {
  const sev = a.severity_label || 'low';
  stats.total++;
  if (sev in stats) stats[sev]++;
  updateStats();

  const row = document.createElement('div');
  row.className = `alert-row ${sev}`;
  if (activeFilter !== 'all' && activeFilter !== sev) row.classList.add('hidden');

  row.innerHTML = `
    <div class="col-time">${esc(a.timestamp_display)}</div>
    <div class="col-sev"><span class="sev-badge ${sev}">${sev}</span></div>
    <div class="col-src">${esc(a.src_ip)}:${esc(a.src_port)}</div>
    <div class="col-dst">${esc(a.dst_ip)}:${esc(a.dst_port)}</div>
    <div class="col-sig">${esc(a.signature)}</div>
    <div class="col-cat">${esc(a.category)}</div>
  `;

  list.insertBefore(row, list.firstChild);
  if (list.children.length > 200) list.removeChild(list.lastChild);
}

function updateStats() {
  for (const key of Object.keys(stats))
    statEls[key].textContent = stats[key];
}

// Filter alert list to selected severity level
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    activeFilter = btn.dataset.filter;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.alert-row').forEach(row => {
      row.classList.toggle('hidden', activeFilter !== 'all' && !row.classList.contains(activeFilter));
    });
  });
});

// On page load: fetch the last 200 alerts already in the server buffer
fetch('/api/alerts/recent?n=200')
  .then(r => r.json())
  .then(data => {
    data.alerts.forEach(a => addAlert(a));
  });

// Clear button: wipe the server buffer then clear the page
document.getElementById('clear-btn').addEventListener('click', () => {
  fetch('/api/alerts/clear', { method: 'POST' }).then(() => {
    list.innerHTML = '';
    Object.keys(stats).forEach(k => stats[k] = 0);
    updateStats();
    empty.style.display = 'block';
  });
});

// Analyse button: open the analysis endpoint as raw JSON in a new tab
document.getElementById('analyse-btn').addEventListener('click', () => {
  window.open('/api/analyse', '_blank');
});
