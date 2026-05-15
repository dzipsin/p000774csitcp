// ============================================================================
// app.js — dashboard frontend
// ============================================================================

const socket = io();

// ---- Elements ----
const dot      = document.getElementById('status-dot');
const statusTx = document.getElementById('status-text');
const lastSeen = document.getElementById('last-seen');

// Alerts elements
const alertsList    = document.getElementById('alerts-list');
const emptyAlerts   = document.getElementById('empty-state-alerts');

// Incidents elements
const incidentsList = document.getElementById('incidents-list');
const emptyInc      = document.getElementById('empty-state-incidents');

// Tab counters
const tabCountAlerts    = document.getElementById('tab-count-alerts');
const tabCountIncidents = document.getElementById('tab-count-incidents');

// Alert stats
const alertStats   = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
const alertStatEls = Object.fromEntries(
  Object.keys(alertStats).map(k => [k, document.getElementById('stat-' + k)])
);

// Incident stats
const incStatEls = {
  total:  document.getElementById('inc-total'),
  open:   document.getElementById('inc-open'),
  closed: document.getElementById('inc-closed'),
  tp:     document.getElementById('inc-tp'),
  fp:     document.getElementById('inc-fp'),
};

// ---- State ----
let activeTab          = 'alerts';
let activeAlertFilter  = 'all';
let activeIncFilter    = 'all';

// In-memory incident cache: incident_id -> report object
const incidentCache = new Map();
// Track which incident cards the user has expanded (so updates don't collapse them)
const expandedIncidents = new Set();

// ---- Utilities ----

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatUptime(seconds) {
  const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
  const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
  const s = String(seconds % 60).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function formatTimeAgo(iso) {
  if (!iso) return '—';
  try {
    const then = new Date(iso).getTime();
    const diff = Math.floor((Date.now() - then) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
    return `${Math.floor(diff/3600)}h ago`;
  } catch { return iso; }
}

// ---- Connection status ----

let uptimeInterval = null;
let connectedAt    = null;

socket.on('connect', () => {
  dot.className = 'dot live';
  statusTx.textContent = 'LIVE';
  connectedAt = Date.now();
  clearInterval(uptimeInterval);
  uptimeInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - connectedAt) / 1000);
    lastSeen.textContent = 'UP ' + formatUptime(elapsed);
  }, 1000);

  // Refetch state on reconnect (covers edge case 17)
  fetchInitialState();
});

socket.on('disconnect', () => {
  dot.className = 'dot dead';
  statusTx.textContent = 'DISCONNECTED';
  clearInterval(uptimeInterval);
  lastSeen.textContent = '--';
});

// ----------------------------------------------------------------------------
// Tabs
// ----------------------------------------------------------------------------

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.tab;
    activeTab = target;

    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById('tab-' + target).classList.add('active');
  });
});

// ----------------------------------------------------------------------------
// Alerts handling (existing behaviour preserved)
// ----------------------------------------------------------------------------

socket.on('alert', (data) => {
  emptyAlerts.style.display = 'none';
  addAlert(data);
});

socket.on('clear', () => {
  alertsList.innerHTML = '';
  Object.keys(alertStats).forEach(k => alertStats[k] = 0);
  updateAlertStats();
  emptyAlerts.style.display = 'block';
});

function addAlert(a) {
  const sev = (a.severity_label || 'low').toLowerCase();
  alertStats.total++;
  if (sev in alertStats) alertStats[sev]++;
  updateAlertStats();

  const row = document.createElement('div');
  row.className = `alert-row ${sev}`;
  if (activeAlertFilter !== 'all' && activeAlertFilter !== sev) row.classList.add('hidden');

  row.innerHTML = `
    <div class="col-time">${esc(a.timestamp_display)}</div>
    <div class="col-sev"><span class="sev-badge ${sev}">${esc(sev)}</span></div>
    <div class="col-src">${esc(a.src_ip)}:${esc(a.src_port)}</div>
    <div class="col-dst">${esc(a.dst_ip)}:${esc(a.dst_port)}</div>
    <div class="col-sig">${esc(a.signature)}</div>
    <div class="col-cat">${esc(a.category)}</div>
  `;

  alertsList.insertBefore(row, alertsList.firstChild);
  if (alertsList.children.length > 200) alertsList.removeChild(alertsList.lastChild);
}

function updateAlertStats() {
  for (const key of Object.keys(alertStats)) {
    alertStatEls[key].textContent = alertStats[key];
  }
  tabCountAlerts.textContent = alertStats.total;
}

// Filter alert list by severity
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    activeAlertFilter = btn.dataset.filter;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.alert-row').forEach(row => {
      row.classList.toggle(
        'hidden',
        activeAlertFilter !== 'all' && !row.classList.contains(activeAlertFilter)
      );
    });
  });
});

// Clear alerts button
document.getElementById('clear-btn').addEventListener('click', () => {
  fetch('/api/alerts/clear', { method: 'POST' });
});

// Legacy batch "Analyse" button — opens raw JSON (kept for backward compat)
document.getElementById('analyse-btn').addEventListener('click', () => {
  window.open('/api/analyse', '_blank');
});

// ----------------------------------------------------------------------------
// Incidents handling
// ----------------------------------------------------------------------------

socket.on('incident_updated', (report) => {
  if (!report || !report.incident_summary) return;
  const id = report.incident_summary.incident_id;
  incidentCache.set(id, report);
  renderAllIncidents();
});

socket.on('incidents_cleared', () => {
  incidentCache.clear();
  expandedIncidents.clear();
  renderAllIncidents();
});

// Incident filter buttons
document.querySelectorAll('.inc-filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    activeIncFilter = btn.dataset.incFilter;
    document.querySelectorAll('.inc-filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderAllIncidents();
  });
});

// Force-regenerate button
document.getElementById('regen-btn').addEventListener('click', async () => {
  const btn = document.getElementById('regen-btn');
  btn.disabled = true;
  btn.textContent = 'Regenerating...';
  try {
    const res = await fetch('/api/incidents/regenerate', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      alert('Regenerate failed: ' + (data.error || res.status));
    }
  } catch (e) {
    alert('Regenerate error: ' + e.message);
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = 'Force Regenerate';
    }, 500);
  }
});

// Clear incidents button
document.getElementById('clear-incidents-btn').addEventListener('click', async () => {
  if (!confirm('Clear all incident reports? (Memory and disk)')) return;
  try {
    await fetch('/api/incidents/clear', { method: 'POST' });
    // Server will emit incidents_cleared; that handles UI reset
  } catch (e) {
    alert('Clear error: ' + e.message);
  }
});

// -- Rendering ---------------------------------------------------------------

function renderAllIncidents() {
  const all = Array.from(incidentCache.values());

  // Sort newest first by generated_at
  all.sort((a, b) => {
    const ta = a.incident_summary?.generated_at || '';
    const tb = b.incident_summary?.generated_at || '';
    return tb.localeCompare(ta);
  });

  // Compute stats across the full set (not filtered)
  let open = 0, closed = 0, tpTotal = 0, fpTotal = 0;
  for (const r of all) {
    const s = r.incident_summary || {};
    if (s.incident_status === 'open') open++;
    else if (s.incident_status === 'closed') closed++;
    const cc = s.classification_counts || {};
    tpTotal += Number(cc.true_positive || 0);
    fpTotal += Number(cc.false_positive || 0);
  }
  incStatEls.total.textContent  = all.length;
  incStatEls.open.textContent   = open;
  incStatEls.closed.textContent = closed;
  incStatEls.tp.textContent     = tpTotal;
  incStatEls.fp.textContent     = fpTotal;
  tabCountIncidents.textContent = all.length;

  // Apply filter
  const filtered = all.filter(r => {
    if (activeIncFilter === 'all') return true;
    return r.incident_summary?.incident_status === activeIncFilter;
  });

  // Empty state visibility
  emptyInc.style.display = filtered.length === 0 ? 'block' : 'none';

  // Replace DOM
  incidentsList.innerHTML = '';
  for (const report of filtered) {
    incidentsList.appendChild(buildIncidentCard(report));
  }
}

function buildIncidentCard(report) {
  const sum = report.incident_summary || {};
  const id  = sum.incident_id || 'unknown';
  const shortId = id.slice(0, 8);

  const card = document.createElement('div');
  const status = sum.incident_status || 'open';
  const severity = sum.overall_severity || 'Low';
  const genStatus = report.generation_status || 'complete';

  card.className = `incident-card status-${status} severity-${severity}`;
  if (genStatus === 'error') card.classList.add('status-error');
  if (expandedIncidents.has(id)) card.classList.add('expanded');
  card.dataset.incidentId = id;

  // --- Header ---
  const header = document.createElement('div');
  header.className = 'incident-header';
  header.innerHTML = `
    <span class="incident-id">${esc(shortId)}</span>
    <span class="incident-status ${esc(status)}">${esc(status)}</span>
    <span class="incident-src">${esc(sum.source_ip || '?')}</span>
    ${sum.repeat_offender ? '<span class="repeat-badge">Repeat Offender</span>' : ''}
    <div class="incident-meta">
      <span><strong>${esc(sum.total_alerts ?? 0)}</strong> alerts</span>
      <span>Severity: <strong>${esc(severity)}</strong></span>
      <span>CVSS: <strong>${esc(sum.overall_cvss_estimate ?? '—')}</strong></span>
      <span>${esc(formatTimeAgo(sum.last_updated_at))}</span>
      <span class="incident-version">${esc(sum.report_version || '')}</span>
    </div>
  `;
  card.appendChild(header);

  // --- Attacks row ---
  const attacks = sum.detected_attacks || [];
  if (attacks.length) {
    const ar = document.createElement('div');
    ar.className = 'attacks-row';
    ar.innerHTML = attacks
      .map(a => `<span class="attack-chip">${esc(a)}</span>`)
      .join('');
    card.appendChild(ar);
  }

  // --- Generation status banner (for partial/error states) ---
  if (genStatus === 'partial') {
    const bar = document.createElement('div');
    bar.className = 'gen-status-bar partial';
    bar.textContent = '⚠ Partial report — some fields fell back to template';
    card.appendChild(bar);
  } else if (genStatus === 'error') {
    const bar = document.createElement('div');
    bar.className = 'gen-status-bar error';
    bar.textContent = `✕ Generation error: ${esc(report.generation_error || 'unknown')}`;
    card.appendChild(bar);
  }

  // --- Toggle button + detail section ---
  const toggle = document.createElement('button');
  toggle.className = 'incident-toggle';
  toggle.textContent = 'Show details';
  toggle.addEventListener('click', (ev) => {
    ev.stopPropagation();
    const isExpanded = card.classList.toggle('expanded');
    if (isExpanded) {
      expandedIncidents.add(id);
      toggle.textContent = 'Hide details';
    } else {
      expandedIncidents.delete(id);
      toggle.textContent = 'Show details';
    }
  });
  if (expandedIncidents.has(id)) toggle.textContent = 'Hide details';
  card.appendChild(toggle);

  const detail = buildIncidentDetail(report);
  card.appendChild(detail);

  // Clicking header toggles too
  header.addEventListener('click', () => toggle.click());

  return card;
}

function buildIncidentDetail(report) {
  const sum  = report.incident_summary || {};
  const desc = report.incident_summary_description || {};
  const expo = report.information_exposure || {};
  const expoDesc = report.information_exposure_description || {};
  const analyses = report.alert_analyses || [];
  const alerts = report.alerts || [];

  const detail = document.createElement('div');
  detail.className = 'incident-detail';

  // Overview
  if (desc.overview) {
    detail.appendChild(_section('Overview', `<p class="detail-prose">${esc(desc.overview)}</p>`));
  }

  // Classification counts + attack stage + vectors (grid)
  const cc = sum.classification_counts || {};
  let metaHTML = '<dl class="detail-grid">';
  metaHTML += `<dt>Attack stage</dt><dd>${esc(desc.overall_attack_stage || '—')}</dd>`;
  metaHTML += `<dt>Vectors</dt><dd>${esc((desc.attack_vectors || []).join(', ') || '—')}</dd>`;
  metaHTML += `<dt>True positives</dt><dd>${esc(cc.true_positive ?? 0)}</dd>`;
  metaHTML += `<dt>False positives</dt><dd>${esc(cc.false_positive ?? 0)}</dd>`;
  if (cc.error) metaHTML += `<dt>Errors</dt><dd>${esc(cc.error)}</dd>`;
  metaHTML += `<dt>First seen</dt><dd>${esc(sum.first_seen || '—')}</dd>`;
  metaHTML += `<dt>Last seen</dt><dd>${esc(sum.last_seen || '—')}</dd>`;
  metaHTML += `<dt>Data sensitivity</dt><dd>${esc(expo.data_sensitive_rating || '—')}</dd>`;
  metaHTML += '</dl>';
  detail.appendChild(_section('Summary', metaHTML));

  // Recommendations
  const suggestions = desc.ai_suggestions || [];
  if (suggestions.length) {
    const items = suggestions.map(s => `<li>${esc(s)}</li>`).join('');
    detail.appendChild(_section('AI Suggestions', `<ul class="detail-list">${items}</ul>`));
  }

  // Exposure
  if (expoDesc.exposure_summary || expoDesc.impact_assessment) {
    let html = '';
    if (expoDesc.exposure_summary) html += `<p class="detail-prose"><strong>Exposure:</strong> ${esc(expoDesc.exposure_summary)}</p>`;
    if (expoDesc.impact_assessment) html += `<p class="detail-prose" style="margin-top:6px"><strong>Impact:</strong> ${esc(expoDesc.impact_assessment)}</p>`;
    const types = expo.exposure_types || [];
    const systems = expo.affected_systems || [];
    if (types.length)   html += `<p class="detail-prose" style="margin-top:6px"><strong>Types:</strong> ${esc(types.join(', '))}</p>`;
    if (systems.length) html += `<p class="detail-prose"><strong>Systems:</strong> ${esc(systems.join(', '))}</p>`;
    detail.appendChild(_section('Information Exposure', html));
  }

  // Per-alert analyses (cap to 5, show "N more" if truncated)
  if (analyses.length) {
    const shown = analyses.slice(0, 5);
    const rows = shown.map(a => `
      <div class="alert-mini-row">
        <div class="alert-mini-type">${esc(a.attack_type_classified || '-')}</div>
        <div>${esc(a.payload_classification || '-')}</div>
        <div style="color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.likely_intent || '-')}</div>
        <div style="color:var(--muted);text-align:right">conf ${esc(a.confidence_score ?? '-')}</div>
      </div>
    `).join('');
    let html = `<div class="alert-mini-table">${rows}</div>`;
    if (analyses.length > 5) {
      html += `<div style="margin-top:6px;color:var(--muted);font-size:0.7rem">… ${analyses.length - 5} more</div>`;
    }
    detail.appendChild(_section(`Alert Analyses (${analyses.length})`, html));
  }

  // Indicators of compromise
  const iocs = expo.indicators_of_compromise || [];
  if (iocs.length) {
    const chips = iocs.slice(0, 20).map(i =>
      `<span class="ioc-item"><span class="ioc-type">${esc(i.type)}</span>${esc(i.value)}</span>`
    ).join('');
    let html = `<div class="ioc-list">${chips}</div>`;
    if (iocs.length > 20) {
      html += `<div style="margin-top:6px;color:var(--muted);font-size:0.7rem">… ${iocs.length - 20} more</div>`;
    }
    detail.appendChild(_section('Indicators of Compromise', html));
  }

  // Metadata footer
  const meta = `<div style="color:var(--muted);font-size:0.7rem">
      Model: ${esc(report.model_used || '—')} &nbsp;·&nbsp;
      Provider: ${esc(report.provider_type || '—')} &nbsp;·&nbsp;
      Report ID: ${esc(sum.report_id || '—').slice(0, 8)}
    </div>`;
  detail.appendChild(_section('', meta));

  return detail;
}

function _section(title, innerHTML) {
  const wrap = document.createElement('div');
  wrap.className = 'detail-section';
  if (title) {
    const t = document.createElement('div');
    t.className = 'detail-section-title';
    t.textContent = title;
    wrap.appendChild(t);
  }
  const body = document.createElement('div');
  body.innerHTML = innerHTML;
  wrap.appendChild(body);
  return wrap;
}

// ----------------------------------------------------------------------------
// Initial state fetch
// ----------------------------------------------------------------------------

async function fetchInitialState() {
  // Alerts
  try {
    const r = await fetch('/api/alerts/recent?n=200');
    const data = await r.json();
    // Reset state and re-populate (avoids double-counting after reconnect)
    alertsList.innerHTML = '';
    Object.keys(alertStats).forEach(k => alertStats[k] = 0);
    (data.alerts || []).forEach(a => addAlert(a));
    if (data.alerts && data.alerts.length) emptyAlerts.style.display = 'none';
  } catch (e) {
    console.error('Failed to fetch alerts:', e);
  }

  // Incidents
  try {
    const r = await fetch('/api/incidents');
    const data = await r.json();
    incidentCache.clear();
    for (const inc of data.incidents || []) {
      if (inc && inc.incident_summary) {
        incidentCache.set(inc.incident_summary.incident_id, inc);
      }
    }
    renderAllIncidents();
  } catch (e) {
    console.error('Failed to fetch incidents:', e);
  }
}

// Periodically refresh the "time ago" labels
setInterval(() => {
  if (activeTab === 'incidents' && incidentCache.size > 0) {
    // Cheap update: re-render. Only happens when tab is active.
    renderAllIncidents();
  }
}, 30000);

// Kick off initial load (also runs again on reconnect)
fetchInitialState();