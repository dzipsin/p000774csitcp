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

socket.on('connect',    () => { dot.className = 'dot live'; statusTx.textContent = 'LIVE'; });
socket.on('disconnect', () => { dot.className = 'dot dead'; statusTx.textContent = 'DISCONNECTED'; });

socket.on('alert', (data) => {
  empty.style.display = 'none';
  addAlert(data);
});

function addAlert(a) {
  const sev = a.severity || 'low';
  stats.total++;
  if (sev in stats) stats[sev]++;
  updateStats();

  const row = document.createElement('div');
  row.className = `alert-row ${sev}`;
  if (activeFilter !== 'all' && activeFilter !== sev) row.classList.add('hidden');

  row.innerHTML = `
    <div class="col-time">${esc(a.timestamp)}</div>
    <div class="col-sev"><span class="sev-badge ${sev}">${sev}</span></div>
    <div class="col-src">${esc(a.src_ip)}:${esc(a.src_port)}</div>
    <div class="col-dst">${esc(a.dst_ip)}:${esc(a.dst_port)}</div>
    <div class="col-sig">${esc(a.signature)}</div>
    <div class="col-cat">${esc(a.category)}</div>
  `;

  list.insertBefore(row, list.firstChild);
  lastSeen.textContent = 'LAST: ' + a.timestamp;
  if (list.children.length > 200) list.removeChild(list.lastChild);
}

function updateStats() {
  for (const key of Object.keys(stats))
    statEls[key].textContent = stats[key];
}

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

document.getElementById('clear-btn').addEventListener('click', () => {
  list.innerHTML = '';
  Object.keys(stats).forEach(k => stats[k] = 0);
  updateStats();
  empty.style.display = 'block';
});
