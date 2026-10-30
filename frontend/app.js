/** Browser workflows; credentials remain in HTTP-only session cookies. */
const ROOT_API = window.location.protocol === 'file:' ? 'http://localhost:8000' : '';
const API_BASE = `${ROOT_API}/api/v1`;
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled', 'timed_out']);
const FINDING_STATUSES = new Set(['open', 'in_progress', 'fixed', 'accepted_risk', 'false_positive']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const COLLECTIONS = ['scans', 'findings', 'assets', 'authorizations', 'reports'];
const PAGE_SIZE = 100;
const MAX_SCAN_TARGETS = 50;
const AUTO_REFRESH_MS = 20000;
const STREAM_POLL_MS = 15000;
const FALLBACK_POLL_MS = 3000;
const STREAM_ERROR_LIMIT = 3;
const STREAM_EVENTS = ['stage_started', 'tool_started', 'tool_finished', 'scan_completed', 'scan_failed', 'scan_cancelled', 'scan_timed_out', 'done'];
const ROLE_TITLES = { admin: 'Requires administrator role', analyst: 'Requires analyst role' };
const state = {
  user: null, organizations: [], activeOrgId: localStorage.getItem('vulnscanner_active_org') || null,
  orgVersion: 0, sessionVersion: 0, profiles: [], profilesRequest: null, profilesError: null,
  scans: [], findings: [], assets: [], authorizations: [], reports: [],
  selectedFinding: null, evidenceStatus: 'loading', activeScanEventSource: null, liveScanId: null, liveScanOrgId: null,
  liveScanStartTime: null, timerInterval: null, pollInterval: null, autoRefreshInterval: null, autoRefreshing: false, monitorReloadOrg: null,
  refreshPromise: null, revoking: new Set(), modalFocus: new Map(), loading: new Set(), errors: new Map(),
};
localStorage.removeItem('vulnscanner_jwt');
const el = id => document.getElementById(id);
function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
function parseDate(value) {
  const text = /^\d{4}-\d{2}-\d{2}T/.test(value) && !/(Z|[+-]\d\d:\d\d)$/.test(value) ? `${value}Z` : value;
  return new Date(text);
}
function timestampOf(value) {
  if (!value) return null;
  const time = parseDate(value).getTime();
  return Number.isFinite(time) ? time : null;
}
function formatDate(value) {
  if (!value) return '-';
  const date = parseDate(value);
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function formatDuration(milliseconds) {
  const total = Math.max(0, Math.floor(milliseconds / 1000)), hours = Math.floor(total / 3600);
  const pad = value => String(value).padStart(2, '0');
  const minutes = Math.floor((total % 3600) / 60), seconds = total % 60;
  return hours ? `${hours}:${pad(minutes)}:${pad(seconds)}` : `${pad(minutes)}:${pad(seconds)}`;
}
function localDate() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
}
function pageVisible() { return document.visibilityState === undefined || document.visibilityState === 'visible'; }
function getStatusBadgeClass(status) {
  return ({ completed: 'badge-success', running: 'badge-low', failed: 'badge-critical', timed_out: 'badge-critical', cancelled: 'badge-info', cancel_requested: 'badge-medium' })[status] || 'badge-info';
}
function statusBadge(status) {
  return `<span class="badge ${getStatusBadgeClass(status)}">${escapeHTML(String(status || 'unknown').replaceAll('_', ' '))}</span>`;
}
function severityBadge(severity) {
  return `<span class="badge badge-${SEVERITIES.has(severity) ? severity : 'info'}">${escapeHTML(severity || 'unknown')}</span>`;
}
function showToast(message, type = 'info') {
  const kind = ['info', 'error', 'success'].includes(type) ? type : 'info';
  const toast = document.createElement('div');
  toast.className = `toast toast-${kind}`;
  toast.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  const text = document.createElement('span');
  text.className = 'toast-message'; text.textContent = message; toast.appendChild(text);
  const container = el('toast-container');
  if (kind === 'error') {
    // Errors stay until dismissed so they can be read at any pace.
    const close = document.createElement('button');
    close.type = 'button'; close.className = 'toast-close'; close.dataset.action = 'dismiss-toast';
    close.setAttribute('aria-label', 'Dismiss notification'); close.textContent = '×';
    toast.appendChild(close);
  } else setTimeout(() => toast.remove(), 5000);
  container.appendChild(toast);
  const visible = [...container.children].filter(item => !item.removed);
  if (visible.length > 5) visible[0].remove();
}
function apiErrorMessage(data, status) {
  if (Array.isArray(data.detail)) return data.detail.map(issue => {
    const field = (issue.loc || []).filter(part => part !== 'body').join('.');
    return `${field ? `${field}: ` : ''}${issue.msg || 'Invalid value'}`;
  }).join('; ');
  return typeof data.detail === 'string' ? data.detail : data.message || `Request failed (${status})`;
}
async function apiRequest(endpoint, options = {}, retry = true) {
  const { timeoutMs = 20000, ...requestOptions } = options;
  const headers = { ...(options.headers || {}) };
  if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const publicPath = ['/health', '/scan-profiles', '/system/'].some(prefix => endpoint.startsWith(prefix));
  const url = `${endpoint.startsWith('/api/') || publicPath ? ROOT_API : API_BASE}${endpoint}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, { ...requestOptions, headers, credentials: 'include', signal: options.signal || controller.signal });
  } catch (error) {
    throw new Error(error.name === 'AbortError' ? 'The request took too long. Please try again.' : 'Cannot reach the server. Check your connection and try again.');
  } finally { clearTimeout(timeout); }
  if (response.status === 401 && !['/auth/login', '/auth/register', '/auth/refresh', '/auth/logout'].includes(endpoint)) {
    if (retry) {
      if (!state.refreshPromise) state.refreshPromise = apiRequest('/auth/refresh', { method: 'POST' }, false).finally(() => { state.refreshPromise = null; });
      try { await state.refreshPromise; }
      catch (error) { if (!error.authFailure) throw error; }
      // Retry even when this tab's refresh was refused: refresh tokens are single
      // use, and another tab sharing the cookies may already have rotated them.
      // A second 401 ends the session (retry=false).
      return apiRequest(endpoint, options, false);
    }
    handleAuthRequired();
    const error = new Error('Your session has expired. Please sign in again.');
    error.authFailure = true;
    throw error;
  }
  if (response.status === 204) return null;
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error(apiErrorMessage(data || {}, response.status));
    error.authFailure = response.status === 401;
    throw error;
  }
  if (data === null) throw new Error('The server returned an unexpected response. Please try again.');
  return data;
}
function setBusy(id, busy, label) {
  const button = el(id);
  if (!button) return;
  button.disabled = busy;
  button.setAttribute('aria-busy', String(busy));
  button.querySelector('.spinner')?.classList.toggle('hidden', !busy);
  const text = button.querySelector('.btn-text');
  if (text && label) text.textContent = label;
}
function switchAuthTab(tab) {
  ['login', 'register'].forEach(name => {
    el(`tab-${name}-btn`).classList.toggle('active', name === tab);
    el(`tab-${name}-btn`).setAttribute('aria-pressed', String(name === tab));
    el(`${name}-form`).classList.toggle('hidden', name !== tab);
  });
  el(tab === 'login' ? 'login-email' : 'reg-fullname').focus();
}
function handleAuthRequired() {
  closeLiveMonitor();
  stopAutoRefresh();
  state.user = null;
  state.activeOrgId = null;
  state.orgVersion += 1;
  state.sessionVersion += 1;
  state.organizations = [];
  clearOrgData();
  localStorage.removeItem('vulnscanner_active_org');
  document.querySelectorAll('.modal-backdrop:not(#auth-modal)').forEach(modal => modal.classList.add('hidden'));
  el('app-shell').classList.add('hidden');
  el('session-check')?.classList.add('hidden');
  openModal('auth-modal');
}
async function handleLogin(event) {
  event.preventDefault(); setBusy('login-submit-btn', true, 'Signing in…');
  try {
    await apiRequest('/auth/login', { method: 'POST', body: JSON.stringify({ email: el('login-email').value.trim(), password: el('login-password').value }) });
    el('login-password').value = '';
    await initApplication();
    if (state.user) showToast('Signed in', 'success');
  } catch (error) { showToast(error.message, 'error'); }
  finally { setBusy('login-submit-btn', false, 'Sign in'); }
}
async function handleRegister(event) {
  event.preventDefault(); setBusy('reg-submit-btn', true, 'Creating account…');
  const email = el('reg-email').value.trim(), password = el('reg-password').value;
  try {
    await apiRequest('/auth/register', { method: 'POST', body: JSON.stringify({ email, password, full_name: el('reg-fullname').value.trim() }) });
    switchAuthTab('login'); el('login-email').value = email; el('reg-password').value = '';
    showToast('Account created', 'success');
    await apiRequest('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    await initApplication();
  } catch (error) { showToast(error.message, 'error'); }
  finally { setBusy('reg-submit-btn', false, 'Create account'); }
}
async function handleLogout() {
  try { await apiRequest('/auth/logout', { method: 'POST' }); handleAuthRequired(); showToast('Signed out'); }
  catch (error) { showToast(`Could not sign out: ${error.message}`, 'error'); }
}
async function initApplication() {
  const sessionVersion = ++state.sessionVersion;
  try {
    const user = await apiRequest('/auth/me');
    if (sessionVersion !== state.sessionVersion) return;
    state.user = user;
    closeModal('auth-modal'); el('session-check')?.classList.add('hidden'); el('app-shell').classList.remove('hidden');
    const name = state.user.full_name || state.user.email;
    el('user-display-name').textContent = name; el('user-avatar-initials').textContent = name.charAt(0).toUpperCase();
    navigate('dashboard');
    await Promise.allSettled([loadToolStatus(), loadProfiles(), loadOrganizations()]);
  } catch (error) {
    if (sessionVersion !== state.sessionVersion) return;
    handleAuthRequired(); if (!error.authFailure) showToast(error.message, 'error');
  }
}
function activeRole() {
  return state.user?.is_superuser ? 'admin' : state.user?.memberships?.find(m => m.organization_id === state.activeOrgId)?.role || 'viewer';
}
function mayAnalyze() { return !!state.user && ['admin', 'analyst'].includes(activeRole()); }
function mayAdmin() { return !!state.user && activeRole() === 'admin'; }
function setControlTitle(control, title) {
  if (title) control.setAttribute('title', title); else control.removeAttribute('title');
}
function gateControl(control, minRole) {
  const allowed = minRole === 'admin' ? mayAdmin() : mayAnalyze();
  control.disabled = !state.activeOrgId || !allowed;
  setControlTitle(control, !state.activeOrgId ? 'Select or create an organization first' : allowed ? '' : ROLE_TITLES[minRole]);
}
function applyPermissions() {
  el('user-role-badge').textContent = activeRole();
  gateControl(el('quick-scan-btn'), 'analyst');
  document.querySelectorAll('[data-min-role]').forEach(button => gateControl(button, button.dataset.minRole === 'admin' ? 'admin' : 'analyst'));
  ['fetch-ai-fix-btn', 'update-finding-status-select', 'save-finding-status-btn'].forEach(id => {
    const control = el(id); if (!control) return;
    control.disabled = !mayAnalyze(); setControlTitle(control, mayAnalyze() ? '' : ROLE_TITLES.analyst);
  });
  renderProfileOptions();
}
async function loadToolStatus() {
  try {
    const data = await apiRequest('/system/scanner-status'); let ready = 0;
    for (const [name, info] of Object.entries(data.tools || {})) {
      const tag = el(`tool-${name}`); if (!tag) continue;
      ready += info.available ? 1 : 0; tag.classList.toggle('active', !!info.available);
      tag.querySelector('.tag-status').textContent = info.available ? 'Ready' : 'Unavailable';
    }
    el('scanner-health-dot').classList.toggle('online', ready > 0);
    el('scanner-health-dot').setAttribute('aria-label', ready > 0 ? 'At least one scanner available' : 'No scanners available');
  } catch (error) { el('scanner-health-dot').classList.remove('online'); showToast(`Could not check scanners: ${error.message}`, 'error'); }
}
// Platform profiles do not change per organization, so they are fetched once per session.
function loadProfiles() {
  const sessionVersion = state.sessionVersion;
  if (state.profilesRequest?.session === sessionVersion) return state.profilesRequest.promise;
  const promise = (async () => {
    try {
      const profiles = await apiRequest('/scan-profiles');
      if (sessionVersion !== state.sessionVersion) return;
      if (!Array.isArray(profiles)) throw new Error('The server returned an unexpected list.');
      state.profiles = profiles; state.profilesError = null; renderProfileOptions();
    } catch (error) {
      if (sessionVersion !== state.sessionVersion) return;
      state.profilesError = error.message; state.profilesRequest = null;
      showToast(`Could not load profiles: ${error.message}`, 'error');
    }
  })();
  state.profilesRequest = { session: sessionVersion, promise };
  return promise;
}
function fetchProfiles() { return loadProfiles(); }
function renderProfileOptions() {
  const select = el('scan-profile-select'); if (!select) return;
  const previous = select.value;
  select.innerHTML = '<option value="">Select scanner profile…</option>';
  state.profiles.forEach(profile => {
    if (profile.organization_id && profile.organization_id !== state.activeOrgId) return;
    const option = document.createElement('option'); option.value = profile.id;
    option.textContent = `${profile.display_name}${profile.is_intrusive ? ' · Intrusive' : ''}`;
    option.dataset.intrusive = String(profile.is_intrusive); option.dataset.desc = profile.description || '';
    option.disabled = profile.is_intrusive && !mayAdmin(); select.appendChild(option);
  });
  select.value = previous;
  if (select.value !== previous) handleProfileSelect(select);
}
async function loadOrganizations() {
  const sessionVersion = state.sessionVersion;
  try {
    const organizations = await apiRequest('/organizations');
    if (sessionVersion !== state.sessionVersion) return;
    state.organizations = organizations;
    const select = el('active-org-select'); select.innerHTML = '';
    if (!state.organizations.length) {
      state.activeOrgId = null;
      const option = document.createElement('option'); option.value = ''; option.textContent = 'Create your first organization'; select.appendChild(option);
      clearOrgData(); renderAll(); applyPermissions(); openNewOrgModal(); return;
    }
    state.organizations.forEach(org => { const option = document.createElement('option'); option.value = org.id; option.textContent = org.name; select.appendChild(option); });
    await handleOrgChange(state.organizations.some(org => org.id === state.activeOrgId) ? state.activeOrgId : state.organizations[0].id);
  } catch (error) { showToast(`Could not load organizations: ${error.message}`, 'error'); }
}
function clearOrgData() {
  stopAutoRefresh();
  for (const name of COLLECTIONS) state[name] = [];
  state.loading.clear(); state.errors.clear(); state.selectedFinding = null; state.revoking.clear();
}
async function handleOrgChange(orgId) {
  if (!orgId || !state.organizations.some(org => org.id === orgId)) return;
  closeLiveMonitor();
  ['finding-detail-modal', 'new-auth-modal', 'new-scan-modal', 'new-report-modal'].forEach(closeModal);
  ['new-auth-form', 'new-scan-form', 'new-report-form'].forEach(id => el(id).reset());
  state.activeOrgId = orgId; state.orgVersion += 1;
  localStorage.setItem('vulnscanner_active_org', orgId); el('active-org-select').value = orgId;
  // applyPermissions also re-renders the cached profile options for the new role.
  clearOrgData(); applyPermissions(); renderAll();
  await refreshActiveOrgData();
}
// Pages until a short page, or until a page adds nothing new (a server ignoring limit/offset).
async function fetchCollection(path, paginate, isCurrent = () => true) {
  if (!paginate) return await apiRequest(path);
  const result = [], seen = new Set();
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const rows = await apiRequest(`${path}?limit=${PAGE_SIZE}&offset=${offset}`);
    if (!isCurrent()) return null;
    if (!Array.isArray(rows)) throw new Error('The server returned an unexpected list.');
    let added = 0;
    for (const row of rows) {
      const id = row?.id;
      if (id !== undefined && id !== null) {
        if (seen.has(id)) continue;
        seen.add(id); added += 1;
      }
      result.push(row);
    }
    if (rows.length < PAGE_SIZE || added === 0) return result;
  }
}
async function loadCollection(name, paginate = true) {
  const orgId = state.activeOrgId, version = state.orgVersion;
  if (!orgId) return;
  const isCurrent = () => orgId === state.activeOrgId && version === state.orgVersion;
  state.loading.add(name); state.errors.delete(name); renderCollection(name); renderDashboard();
  try {
    const rows = await fetchCollection(`/organizations/${orgId}/${name}`, paginate, isCurrent);
    if (isCurrent()) state[name] = rows;
  } catch (error) {
    if (isCurrent()) state.errors.set(name, error.message);
  } finally {
    if (isCurrent()) {
      state.loading.delete(name); renderCollection(name); renderDashboard();
      if (name === 'assets') { filterFindings(); if (state.selectedFinding) renderFindingDetails(state.selectedFinding); }
      if (name === 'scans') scheduleAutoRefresh();
    }
  }
}
function loadScans() { return loadCollection('scans'); }
function loadFindings() { return loadCollection('findings'); }
function loadAssets() { return loadCollection('assets'); }
function loadReports() { return loadCollection('reports'); }
function loadAuthorizations() {
  if (activeRole() === 'viewer') { state.authorizations = []; renderAuthorizations(); return Promise.resolve(); }
  return loadCollection('authorizations');
}
async function refreshActiveOrgData() { await Promise.allSettled([loadScans(), loadFindings(), loadAssets(), loadAuthorizations(), loadReports()]); }
async function refreshData() {
  const button = el('refresh-data-btn');
  button?.setAttribute('aria-busy', 'true');
  try {
    if (state.profilesError) loadProfiles();
    await refreshActiveOrgData();
  } finally { button?.setAttribute('aria-busy', 'false'); }
}
function retryCollection(name) {
  ({ scans: loadScans, findings: loadFindings, assets: loadAssets, authorizations: loadAuthorizations, reports: loadReports })[name]?.();
}
function loadDashboard() { renderDashboard(); return Promise.resolve(); }
// Auto-refresh runs only while a scan is still in progress and the page is visible.
function stopAutoRefresh() {
  if (state.autoRefreshInterval !== null) clearInterval(state.autoRefreshInterval);
  state.autoRefreshInterval = null;
}
function scheduleAutoRefresh() {
  const needed = !!state.activeOrgId && state.scans.some(scan => !TERMINAL_STATUSES.has(scan.status));
  if (needed && state.autoRefreshInterval === null) state.autoRefreshInterval = setInterval(autoRefresh, AUTO_REFRESH_MS);
  else if (!needed) stopAutoRefresh();
}
async function autoRefresh() {
  if (!pageVisible() || state.autoRefreshing || !state.activeOrgId) return;
  const active = new Set(state.scans.filter(scan => !TERMINAL_STATUSES.has(scan.status)).map(scan => scan.id));
  if (!active.size) { stopAutoRefresh(); return; }
  const orgId = state.activeOrgId, version = state.orgVersion;
  state.autoRefreshing = true;
  try { await loadScans(); } finally { state.autoRefreshing = false; }
  if (orgId !== state.activeOrgId || version !== state.orgVersion) return;
  if (state.scans.some(scan => active.has(scan.id) && TERMINAL_STATUSES.has(scan.status))) await Promise.allSettled([loadFindings(), loadAssets()]);
}
function collectionMessage(name, empty) {
  if (!state.activeOrgId) return 'Create or select an organization to get started.';
  if (state.loading.has(name) && !state[name].length) return 'Loading…';
  return state.errors.has(name) ? `Could not load this list. ${state.errors.get(name)}` : empty;
}
function emptyRow(name, columns, message) {
  return `<tr><td colspan="${columns}" class="empty-state${state.errors.has(name) ? ' error-state' : ''}">${escapeHTML(collectionMessage(name, message))}${state.errors.has(name) ? ` <button type="button" class="btn btn-xs btn-ghost" data-action="retry" data-collection="${name}">Try again</button>` : ''}</td></tr>`;
}
function hasRows(name) { return !state.errors.has(name) && state[name].length > 0; }
// Rows stay visible during a reload; assistive technology is told the region is updating.
function updateBusyState() {
  const busy = name => state.loading.has(name) && state[name].length > 0;
  COLLECTIONS.forEach(name => el(`view-${name}`)?.setAttribute('aria-busy', String(busy(name))));
  el('view-dashboard')?.setAttribute('aria-busy', String(['scans', 'findings', 'assets', 'authorizations'].some(busy)));
}
function profileName(scan) { return state.profiles.find(profile => profile.id === scan.profile_id)?.display_name || 'Scan profile'; }
function targetNames(targets) { return (targets || []).map(target => typeof target === 'string' ? target : target.target_value || target.value || '').filter(Boolean).join(', '); }
let locationIndex = { source: null, assets: new Map(), services: new Map() };
function assetLocationIndex() {
  if (locationIndex.source !== state.assets) {
    const assets = new Map(), services = new Map();
    for (const asset of state.assets || []) {
      assets.set(asset.id, asset);
      for (const service of asset.services || []) services.set(service.id, service);
    }
    locationIndex = { source: state.assets, assets, services };
  }
  return locationIndex;
}
function findingLocation(finding) {
  const index = assetLocationIndex(), asset = index.assets.get(finding.asset_id);
  const service = asset ? index.services.get(finding.service_id) : undefined;
  return { address: asset?.ip_address || asset?.hostname || asset?.domain || '-', port: service?.port ?? null, protocol: service?.protocol || '' };
}
function topFindings(findings, limit = 5) {
  const top = [];
  for (const finding of findings) {
    if (['fixed', 'false_positive'].includes(finding.status)) continue;
    const score = finding.priority_score || 0;
    let position = top.length;
    while (position > 0 && (top[position - 1].priority_score || 0) < score) position -= 1;
    if (position >= limit) continue;
    top.splice(position, 0, finding);
    if (top.length > limit) top.pop();
  }
  return top;
}
function renderDashboard() {
  const count = (name, value) => state.errors.has(name) ? '-' : state.loading.has(name) && !state[name].length ? '…' : value;
  const activeScans = state.scans.filter(scan => !TERMINAL_STATUSES.has(scan.status)).length;
  el('stat-scans-count').textContent = count('scans', `${activeScans} / ${state.scans.length}`);
  el('stat-critical-count').textContent = count('findings', state.findings.filter(f => ['critical', 'high'].includes(f.severity) && !['fixed', 'false_positive'].includes(f.status)).length);
  el('stat-assets-count').textContent = count('assets', state.assets.length);
  el('stat-auth-count').textContent = activeRole() === 'viewer' ? '-' : count('authorizations', state.authorizations.filter(a => a.is_valid).length);
  const scans = el('dashboard-recent-scans');
  scans.innerHTML = !hasRows('scans')
    ? `<div class="empty-state">${escapeHTML(collectionMessage('scans', 'No scans yet. Authorize your targets, then start an assessment.'))}</div>`
    : `<table class="data-table"><thead><tr><th>Profile</th><th>Status</th><th>Targets</th><th>Queued</th></tr></thead><tbody>${state.scans.slice(0, 5).map(scan => `<tr><td>${escapeHTML(profileName(scan))}</td><td>${statusBadge(scan.status)}</td><td><code>${escapeHTML(targetNames(scan.targets))}</code></td><td>${escapeHTML(formatDate(scan.queued_at))}</td></tr>`).join('')}</tbody></table>`;
  const findings = el('dashboard-top-findings');
  findings.innerHTML = !hasRows('findings')
    ? `<div class="empty-state">${escapeHTML(collectionMessage('findings', 'No findings recorded. A completed assessment is needed to evaluate your targets.'))}</div>`
    : topFindings(state.findings).map(f => `<div class="finding-summary glass-panel-subtle"><div>${severityBadge(f.severity)} <strong>${escapeHTML(f.title)}</strong><p class="text-muted">${escapeHTML(findingLocation(f).address)} · Priority ${escapeHTML(f.priority_score ?? '-')}</p></div><button type="button" class="btn btn-xs btn-ghost" data-action="finding" data-id="${escapeHTML(f.id)}" aria-label="Inspect details for ${escapeHTML(f.title)}">Inspect</button></div>`).join('') || '<div class="empty-state">No open findings in this organization.</div>';
  updateBusyState();
}
function scanActionLabel(scan) {
  const id = String(scan.id).slice(0, 8);
  return TERMINAL_STATUSES.has(scan.status) ? ['View events', `View events for scan ${id}`] : ['Monitor', `Monitor scan ${id}`];
}
function renderScans() {
  el('scans-tbody').innerHTML = !hasRows('scans')
    ? emptyRow('scans', 7, 'No scans yet. Start an assessment after authorizing your targets.')
    : state.scans.map(scan => {
      const [label, accessibleName] = scanActionLabel(scan);
      return `<tr><td><code>${escapeHTML(String(scan.id).slice(0, 8))}</code></td><td>${escapeHTML(profileName(scan))}</td><td><code>${escapeHTML(targetNames(scan.targets))}</code></td><td>${statusBadge(scan.status)}${scan.error_message ? `<small class="scan-error">${escapeHTML(scan.error_message)}</small>` : ''}</td><td>${escapeHTML(scan.findings_count)}</td><td>${escapeHTML(formatDate(scan.queued_at))}</td><td><button type="button" class="btn btn-xs btn-ghost" data-action="monitor" data-id="${escapeHTML(scan.id)}" aria-label="${escapeHTML(accessibleName)}">${label}</button></td></tr>`;
    }).join('');
  updateBusyState();
}
function renderFindings(findings) {
  el('findings-tbody').innerHTML = state.errors.has('findings') || !findings.length
    ? emptyRow('findings', 7, 'No findings match these filters.')
    : findings.map(f => {
      const location = findingLocation(f);
      return `<tr><td>${severityBadge(f.severity)}</td><td><strong>${escapeHTML(f.title)}</strong></td><td><code>${escapeHTML(location.address)}</code></td><td>${escapeHTML(location.port === null ? '-' : `${location.port}/${location.protocol}`)}</td><td><span class="tool-tag">${escapeHTML(f.source_tool)}</span></td><td>${statusBadge(f.status)}</td><td><button type="button" class="btn btn-xs btn-primary" data-action="finding" data-id="${escapeHTML(f.id)}" aria-label="Details for ${escapeHTML(f.title)}">Details & guidance</button></td></tr>`;
    }).join('');
  updateBusyState();
}
function filterFindings() {
  const severity = el('findings-severity-filter').value, status = el('findings-status-filter').value;
  renderFindings(state.findings.filter(f => (!severity || f.severity === severity) && (!status || f.status === status)));
}
function renderAssets() {
  el('assets-tbody').innerHTML = !hasRows('assets')
    ? emptyRow('assets', 6, 'No assets discovered yet. Run an authorized discovery scan.')
    : state.assets.map(a => `<tr><td>${escapeHTML(a.asset_type)}</td><td><code>${escapeHTML(a.ip_address || '-')}</code></td><td>${escapeHTML(a.hostname || a.domain || '-')}</td><td>${escapeHTML([a.os_name, a.os_version].filter(Boolean).join(' ') || 'Unknown')}</td><td>${(a.services || []).map(s => `<span class="badge badge-low">${escapeHTML(`${s.port}/${s.protocol} ${s.service_name || ''}`)}</span>`).join(' ') || '-'}</td><td>${escapeHTML(formatDate(a.first_seen))}</td></tr>`).join('');
  updateBusyState();
}
function authorizationActions(auth) {
  if (!mayAdmin() || auth.is_revoked) return '<span class="text-muted">-</span>';
  return `<button type="button" class="btn btn-xs btn-danger" data-action="revoke-auth" data-id="${escapeHTML(auth.id)}" aria-label="Revoke authorization ${escapeHTML(auth.title)}"${state.revoking.has(auth.id) ? ' disabled' : ''}>Revoke</button>`;
}
function renderAuthorizations() {
  const select = el('scan-auth-select'), previous = select.value;
  select.innerHTML = '<option value="">Select approved scope authorization…</option>';
  state.authorizations.filter(auth => auth.is_valid).forEach(auth => { const option = document.createElement('option'); option.value = auth.id; option.textContent = `${auth.title} · ${auth.signer_name}`; select.appendChild(option); });
  select.value = previous;
  renderApprovedTargets();
  const message = activeRole() === 'viewer' ? 'Authorization details require an analyst or administrator role.' : 'No authorizations yet. Add written approval and target boundaries before scanning.';
  el('authorizations-tbody').innerHTML = !hasRows('authorizations')
    ? emptyRow('authorizations', 6, message)
    : state.authorizations.map(a => `<tr><td><strong>${escapeHTML(a.title)}</strong><br>${escapeHTML(a.signer_name)}<br><small>${escapeHTML(a.signer_email)}</small></td><td><code>${escapeHTML(targetNames(a.authorized_targets))}</code></td><td><span class="badge ${a.is_valid ? 'badge-success' : 'badge-info'}">${a.is_revoked ? 'Revoked' : a.is_valid ? 'Valid' : 'Expired'}</span></td><td>${escapeHTML(a.authorization_date)}</td><td>${escapeHTML(a.expiration_date || 'No expiry')}</td><td>${authorizationActions(a)}</td></tr>`).join('');
  updateBusyState();
}
function reportUrl(report, orgId = state.activeOrgId) {
  return `${ROOT_API}/api/v1/organizations/${encodeURIComponent(orgId)}/reports/${encodeURIComponent(report.id)}/html`;
}
// The HTML route is cookie-authenticated, and a plain navigation never passes through
// apiRequest's 401 -> /auth/refresh path, so an idle console (access cookie older than its
// lifetime) would open a raw 401 page. A primary click therefore opens the tab inside the
// user gesture (popup blockers allow it), makes a cheap authenticated GET that renews the
// cookie when needed, and only then points the tab at the report. Modified/middle clicks
// keep the browser's default behaviour on the real href.
async function openReport(reportId) {
  const orgId = state.activeOrgId;
  if (!orgId || !reportId) return;
  const url = reportUrl({ id: reportId }, orgId);
  const tab = window.open('', '_blank');
  if (tab) { try { tab.opener = null; } catch { /* some browsers make opener read-only */ } }
  try {
    await apiRequest(`/organizations/${orgId}/reports/${reportId}`);
  } catch (error) {
    try { tab?.close?.(); } catch { /* already closed */ }
    showToast(error.authFailure ? 'Sign in again to open the report.' : error.message, 'error');
    return;
  }
  if (tab && !tab.closed) { tab.location = url; return; }
  if (!window.open(url, '_blank', 'noopener')) showToast('Allow pop-ups for this console, or middle-click View HTML to open the report.', 'info');
}
function renderReports() {
  el('reports-tbody').innerHTML = !hasRows('reports')
    ? emptyRow('reports', 5, 'No reports yet. Create an executive or technical assessment report.')
    : state.reports.map(r => `<tr><td>${escapeHTML(r.title)}</td><td>${escapeHTML(r.report_type)}</td><td><code>${escapeHTML(r.scan_id?.slice(0, 8) || 'Organization overview')}</code></td><td>${escapeHTML(formatDate(r.generated_at))}</td><td><a class="btn btn-xs btn-primary" href="${escapeHTML(reportUrl(r))}" data-action="open-report" data-id="${escapeHTML(r.id)}" target="_blank" rel="noopener noreferrer" aria-label="View report ${escapeHTML(r.title)} (HTML, opens in a new tab)">View HTML</a></td></tr>`).join('');
  updateBusyState();
}
function renderCollection(name) { ({ scans: renderScans, findings: filterFindings, assets: renderAssets, authorizations: renderAuthorizations, reports: renderReports })[name]?.(); }
function renderAll() { COLLECTIONS.forEach(renderCollection); renderDashboard(); }
function navigate(view, focusTitle = false) {
  const titles = { dashboard: ['Dashboard', 'Assessment coverage and findings at a glance'], scans: ['Scans & audits', 'Run authorized assessments and review progress'], findings: ['Findings & remediation', 'Prioritize findings and review guidance'], assets: ['Asset inventory', 'Discovered hosts and services'], authorizations: ['Scope authorizations', 'Written approval and approved target boundaries'], reports: ['Reports', 'Executive and technical assessment reports'] };
  if (!titles[view]) return;
  document.querySelectorAll('.nav-item').forEach(item => { item.classList.toggle('active', item.dataset.view === view); item.setAttribute('aria-current', item.dataset.view === view ? 'page' : 'false'); });
  document.querySelectorAll('.view-panel').forEach(panel => panel.classList.toggle('active', panel.id === `view-${view}`));
  el('page-title').textContent = titles[view][0]; el('page-subtitle').textContent = titles[view][1];
  if (focusTitle) el('page-title').focus();
}
function openModal(id) {
  const modal = el(id);
  if (modal.classList.contains('hidden')) state.modalFocus.set(id, document.activeElement);
  modal.classList.remove('hidden');
  el('app-shell').inert = true;
  modal.querySelector('input:not([type="hidden"]), select, textarea, button')?.focus();
}
function closeModal(id) {
  const modal = el(id); if (!modal || modal.classList.contains('hidden')) return;
  modal.classList.add('hidden');
  el('app-shell').inert = document.querySelectorAll('.modal-backdrop:not(.hidden)').length > 0;
  const previous = state.modalFocus.get(id); if (previous?.isConnected) previous.focus();
  state.modalFocus.delete(id);
}
function openDialog(id) {
  if (id === 'new-org-modal') openNewOrgModal();
  else if (id === 'new-scan-modal') openNewScanModal();
  else if (id === 'new-auth-modal') openNewAuthModal();
  else if (id === 'new-report-modal') openNewReportModal();
}
function requireOrganization(role) {
  if (!state.activeOrgId) { showToast('Create an organization first.'); openNewOrgModal(); return false; }
  const allowed = role === 'admin' ? mayAdmin() : mayAnalyze();
  if (!allowed) showToast(`This action requires an ${role === 'admin' ? 'administrator' : 'analyst or administrator'} role.`, 'error');
  return allowed;
}
function openNewOrgModal() { openModal('new-org-modal'); }
function openNewAuthModal() {
  if (!requireOrganization('admin')) return;
  if (!el('auth-date').value) el('auth-date').value = localDate();
  openModal('new-auth-modal');
}
function openNewScanModal() {
  if (!requireOrganization('analyst')) return;
  const valid = state.authorizations.filter(auth => auth.is_valid);
  if (!valid.length) {
    showToast('A valid scope authorization is required before scanning.');
    if (mayAdmin()) openNewAuthModal(); return;
  }
  if (state.profilesError) loadProfiles();
  const select = el('scan-auth-select');
  if (valid.length === 1 && !select.value) select.value = valid[0].id;
  renderApprovedTargets();
  openModal('new-scan-modal');
}
function openNewReportModal() {
  if (!requireOrganization('analyst')) return;
  const select = el('report-scan-select'); select.innerHTML = '<option value="">Organization overview</option>';
  state.scans.forEach(scan => { const option = document.createElement('option'); option.value = scan.id; option.textContent = `${profileName(scan)} · ${formatDate(scan.queued_at)} · ${scan.status}`; select.appendChild(option); });
  openModal('new-report-modal');
}
async function handleCreateOrg(event) {
  event.preventDefault();
  const name = el('org-name-input').value.trim(), supplied = el('org-slug-input')?.value.trim();
  const generated = name.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 94).replace(/-$/g, '');
  const slug = supplied || (generated.length >= 3 ? generated : `${generated || 'org'}-team`);
  const sessionVersion = state.sessionVersion;
  setBusy('create-org-submit-btn', true);
  try {
    const org = await apiRequest('/organizations', { method: 'POST', body: JSON.stringify({ name, slug }) });
    if (sessionVersion !== state.sessionVersion) return;
    const user = await apiRequest('/auth/me');
    if (sessionVersion !== state.sessionVersion) return;
    state.user = user; state.activeOrgId = org.id;
    closeModal('new-org-modal'); await loadOrganizations();
    showToast(`Organization “${org.name}” created`, 'success');
  } catch (error) { showToast(error.message, 'error'); }
  finally { setBusy('create-org-submit-btn', false); }
}
function handleProfileSelect(select) {
  const profile = state.profiles.find(item => item.id === select.value);
  el('profile-description').textContent = profile?.description || '';
  el('profile-description').classList.toggle('hidden', !profile);
  el('intrusive-warning').classList.toggle('hidden', !profile?.is_intrusive); el('intrusive-checkbox').checked = false;
}
function selectedAuthorization() {
  const id = el('scan-auth-select').value;
  return id ? state.authorizations.find(auth => auth.id === id && auth.is_valid) : undefined;
}
function approvedTargetValues(auth) {
  return (auth?.authorized_targets || []).map(target => typeof target === 'string' ? target : target.value || target.target_value || '').filter(Boolean);
}
function renderApprovedTargets() {
  const values = approvedTargetValues(selectedAuthorization()), shown = values.slice(0, 12);
  el('scan-approved-targets').classList.toggle('hidden', !values.length);
  el('scan-approved-targets-list').innerHTML = shown.map(value => `<li><code>${escapeHTML(value)}</code></li>`).join('')
    + (values.length > shown.length ? `<li class="text-muted">+${values.length - shown.length} more</li>` : '');
}
function useApprovedTargets() {
  const values = approvedTargetValues(selectedAuthorization());
  if (!values.length) return;
  el('scan-targets-input').value = values.join('\n');
  if (values.length > MAX_SCAN_TARGETS) showToast(`This authorization lists ${values.length} targets, but a scan accepts at most ${MAX_SCAN_TARGETS}. Remove some before launching.`, 'error');
}
async function handleCreateAuth(event) {
  event.preventDefault(); if (!requireOrganization('admin')) return;
  const targets = el('auth-targets').value.trim().split(/[\s,]+/).filter(Boolean).map(value => ({ value }));
  if (!targets.length) { showToast('Add at least one approved target.', 'error'); return; }
  const payload = { title: el('auth-signer-title').value.trim(), signer_name: el('auth-signer-name').value.trim(), signer_email: el('auth-signer-email').value.trim(), authorization_date: el('auth-date').value, expiration_date: el('auth-expiration').value || null, notes: el('auth-notes').value.trim() || null, targets };
  if (payload.expiration_date && payload.expiration_date < payload.authorization_date) { showToast('Expiration cannot be earlier than authorization date.', 'error'); return; }
  const orgId = state.activeOrgId; setBusy('create-auth-submit-btn', true);
  try {
    await apiRequest(`/organizations/${orgId}/authorizations`, { method: 'POST', body: JSON.stringify(payload) });
    if (orgId !== state.activeOrgId) return;
    closeModal('new-auth-modal'); el('new-auth-form').reset(); await loadAuthorizations(); showToast('Scope authorization recorded', 'success');
  } catch (error) { showToast(error.message, 'error'); }
  finally { setBusy('create-auth-submit-btn', false); }
}
async function revokeAuthorization(authId) {
  if (!requireOrganization('admin')) return;
  const auth = state.authorizations.find(item => item.id === authId);
  if (!auth || auth.is_revoked || state.revoking.has(authId)) return;
  if (!window.confirm(`Revoke the authorization “${auth.title}”? New scans under it will be blocked and its running scans will be cancelled.`)) return;
  const orgId = state.activeOrgId;
  state.revoking.add(authId); renderAuthorizations();
  try {
    await apiRequest(`/organizations/${orgId}/authorizations/${encodeURIComponent(authId)}`, { method: 'DELETE' });
    if (orgId !== state.activeOrgId) return;
    await Promise.allSettled([loadAuthorizations(), loadScans()]);
    showToast(`Authorization “${auth.title}” revoked`, 'success');
  } catch (error) { if (orgId === state.activeOrgId) showToast(error.message, 'error'); }
  finally { state.revoking.delete(authId); if (orgId === state.activeOrgId) renderAuthorizations(); }
}
async function handleLaunchScan(event) {
  event.preventDefault(); if (!requireOrganization('analyst')) return;
  const profile = state.profiles.find(item => item.id === el('scan-profile-select').value), acknowledged = el('intrusive-checkbox').checked;
  if (!profile) { showToast('Select a scan profile.', 'error'); return; }
  if (profile.is_intrusive && (!mayAdmin() || !acknowledged)) { showToast('Intrusive scans require administrator approval and explicit acknowledgement.', 'error'); return; }
  const targets = el('scan-targets-input').value.trim().split(/[\s,]+/).filter(Boolean);
  if (!targets.length) { showToast('Specify at least one target.', 'error'); return; }
  const orgId = state.activeOrgId; setBusy('start-scan-submit-btn', true);
  try {
    const scan = await apiRequest(`/organizations/${orgId}/scans`, { method: 'POST', body: JSON.stringify({ authorization_id: el('scan-auth-select').value, profile_id: profile.id, targets, intrusive_acknowledged: acknowledged }) });
    if (orgId !== state.activeOrgId) return;
    closeModal('new-scan-modal'); el('new-scan-form').reset(); handleProfileSelect(el('scan-profile-select')); renderApprovedTargets(); navigate('scans');
    await loadScans();
    if (orgId !== state.activeOrgId) return;
    monitorScan(scan.id, targetNames(scan.targets)); showToast('Scan submitted. Follow its status in the monitor.', 'success');
  } catch (error) { showToast(error.message, 'error'); }
  finally { setBusy('start-scan-submit-btn', false); }
}
async function handleGenerateReport(event) {
  event.preventDefault(); if (!requireOrganization('analyst')) return;
  const orgId = state.activeOrgId, reportType = el('report-type-select').value; setBusy('create-report-submit-btn', true);
  try {
    await apiRequest(`/organizations/${orgId}/reports`, { method: 'POST', body: JSON.stringify({ scan_id: el('report-scan-select').value || null, report_type: reportType, title: el('report-title-input').value.trim() || `${reportType === 'technical' ? 'Technical' : 'Executive'} assessment report` }) });
    if (orgId !== state.activeOrgId) return;
    closeModal('new-report-modal'); el('new-report-form').reset(); navigate('reports'); await loadReports(); showToast('Report requested. Use “View HTML” when it is ready.', 'success');
  } catch (error) { showToast(error.message, 'error'); }
  finally { setBusy('create-report-submit-btn', false); }
}
function appendScanLog(message, timestamp) {
  const box = el('live-scan-console');
  box.textContent = (box.textContent + `[${timestamp ? formatDate(timestamp) : new Date().toLocaleTimeString()}] ${message}\n`).slice(-50000);
  box.scrollTop = box.scrollHeight;
}
function updateMonitor(status, progress) {
  if (status) {
    el('live-scan-status-badge').textContent = status.replaceAll('_', ' '); el('live-scan-status-badge').className = `badge ${getStatusBadgeClass(status)}`;
    el('cancel-scan-btn').disabled = !mayAnalyze() || TERMINAL_STATUSES.has(status) || status === 'cancel_requested';
  }
  if (progress !== undefined && progress !== null && Number.isFinite(Number(progress))) {
    const pct = Math.max(0, Math.min(100, Number(progress))); el('live-scan-progress-bar').style.width = `${pct}%`; el('live-scan-progress-bar').setAttribute('aria-valuenow', String(pct));
  }
}
// Finished scans show their recorded duration once; queued scans wait for started_at.
function startScanTimer(scan) {
  if (state.timerInterval !== null) clearInterval(state.timerInterval);
  state.timerInterval = null;
  const timer = el('live-scan-timer'), started = timestampOf(scan?.started_at);
  state.liveScanStartTime = started;
  if (TERMINAL_STATUSES.has(scan?.status)) {
    const endedAt = timestampOf(scan.completed_at) ?? timestampOf(scan.cancelled_at) ?? timestampOf(scan.timed_out_at);
    // Failed scans record no end time, so their duration is unknown.
    timer.textContent = started !== null && endedAt !== null ? formatDuration(endedAt - started) : scan.status === 'failed' ? 'Failed' : '--:--';
    return;
  }
  if (started === null) { timer.textContent = 'Queued'; return; }
  const tick = () => { timer.textContent = formatDuration(Date.now() - state.liveScanStartTime); };
  tick(); state.timerInterval = setInterval(tick, 1000);
}
function mergeScan(scan) {
  const index = state.scans.findIndex(item => item.id === scan.id);
  if (index === -1) state.scans = [scan, ...state.scans];
  else state.scans[index] = { ...state.scans[index], ...scan };
  renderScans(); renderDashboard();
}
function stopMonitorConnections() {
  state.activeScanEventSource?.close(); state.activeScanEventSource = null;
  if (state.timerInterval !== null) clearInterval(state.timerInterval);
  if (state.pollInterval !== null) clearInterval(state.pollInterval);
  state.timerInterval = null; state.pollInterval = null;
}
// A monitor poll can merge a scan's terminal status into state.scans before the
// monitor's finish() runs, which hides the transition from autoRefresh. If the
// monitor is then closed or replaced, findings and assets are reloaded here.
function flushMonitorReload() {
  const pendingOrg = state.monitorReloadOrg; state.monitorReloadOrg = null;
  if (pendingOrg && pendingOrg === state.activeOrgId) Promise.allSettled([loadFindings(), loadAssets()]);
}
function closeLiveMonitor(reloadPending = false) {
  if (reloadPending) flushMonitorReload(); else state.monitorReloadOrg = null;
  stopMonitorConnections(); state.liveScanId = null; state.liveScanOrgId = null; el('live-scan-container').classList.add('hidden');
}
function monitorScan(scanId, targets) {
  if (!state.activeOrgId) return;
  flushMonitorReload();
  stopMonitorConnections(); state.liveScanId = scanId; state.liveScanOrgId = state.activeOrgId;
  const orgId = state.liveScanOrgId;
  let scan = state.scans.find(item => item.id === scanId);
  el('live-scan-container').classList.remove('hidden'); el('live-scan-target').textContent = targets || targetNames(scan?.targets) || `Scan ${scanId.slice(0, 8)}`;
  el('live-scan-console').textContent = '';
  updateMonitor(scan?.status || 'queued', scan?.progress_pct || 0); startScanTimer(scan); appendScanLog('Connecting to scan events…');
  // A scan that had already ended needs no data refresh; its events are replayed by the stream.
  const startedTerminal = TERMINAL_STATUSES.has(scan?.status);
  const seen = new Set();
  let ended = false, polling = false, streamOpen = false, terminalPolls = 0, streamErrors = 0, reopenAfterPoll = false, reopened = false;
  const isCurrent = () => !ended && orgId === state.activeOrgId && state.liveScanId === scanId;
  const schedulePolls = delay => {
    if (state.pollInterval !== null) clearInterval(state.pollInterval);
    state.pollInterval = setInterval(poll, delay);
  };
  const finish = status => {
    if (!isCurrent() || !TERMINAL_STATUSES.has(status)) return;
    ended = true; stopMonitorConnections(); updateMonitor(status, status === 'completed' ? 100 : undefined);
    if (TERMINAL_STATUSES.has(scan?.status)) startScanTimer(scan);
    appendScanLog(`Scan ${status.replaceAll('_', ' ')}.`);
    if (startedTerminal) return;
    state.monitorReloadOrg = null; // this reload covers it
    Promise.allSettled([loadScans(), loadFindings(), loadAssets()]).then(() => {
      // The stream can report the end before a poll refreshed `scan`; settle the
      // timer from the reloaded row so it does not stay frozen at its last tick.
      const refreshed = state.scans.find(item => item.id === scanId);
      if (state.liveScanId === scanId && orgId === state.activeOrgId && TERMINAL_STATUSES.has(refreshed?.status)) startScanTimer(refreshed);
    });
  };
  const poll = async () => {
    if (polling || !isCurrent() || document.hidden) return; polling = true;
    try {
      const current = await apiRequest(`/organizations/${orgId}/scans/${scanId}`);
      if (!isCurrent() || !current || typeof current !== 'object' || current.id !== scanId) return;
      scan = current; mergeScan(current); updateMonitor(current.status, current.progress_pct);
      if (!startedTerminal && TERMINAL_STATUSES.has(current.status)) state.monitorReloadOrg = orgId;
      if (state.liveScanStartTime === null && (current.started_at || TERMINAL_STATUSES.has(current.status))) startScanTimer(current);
      // While the stream is open it replays the remaining events and closes itself; finishing
      // here first would drop them. Polling takes over if the stream fails or stalls.
      if (TERMINAL_STATUSES.has(current.status) && (!streamOpen || ++terminalPolls >= 2)) finish(current.status);
      else if (reopenAfterPoll) { reopenAfterPoll = false; openStream(); schedulePolls(STREAM_POLL_MS); }
    } catch (error) {
      if (state.liveScanId === scanId && orgId === state.activeOrgId) appendScanLog(error.message);
      if (error.authFailure) stopMonitorConnections();
    } finally { polling = false; }
  };
  const receive = event => {
    if (!isCurrent()) return;
    streamErrors = 0;
    try {
      const data = JSON.parse(event.data); if (data.id && seen.has(data.id)) return; if (data.id) seen.add(data.id);
      const payload = data.payload || data, type = data.event_type || event.type;
      appendScanLog(payload.message || payload.error || [type.replaceAll('_', ' '), payload.tool || payload.stage].filter(Boolean).join(' · '), data.created_at);
      const terminal = ({ scan_completed: 'completed', scan_failed: 'failed', scan_cancelled: 'cancelled', scan_timed_out: 'timed_out' })[type];
      if (terminal) finish(terminal);
      else if (type === 'stream_closed' || event.type === 'done') finish(data.final_status);
      else {
        updateMonitor(payload.stage === 'validating' ? 'validating' : payload.stage === 'parsing' ? 'parsing' : payload.stage === 'normalizing' ? 'normalizing' : payload.tool ? 'running' : undefined, payload.progress_pct);
        // A queued scan has started: fetch started_at for the timer rather than waiting for the next poll.
        if (state.liveScanStartTime === null && !TERMINAL_STATUSES.has(scan?.status)) poll();
      }
    } catch { appendScanLog('An event could not be read. Status polling will continue.'); }
  };
  const openStream = () => {
    const source = new EventSource(`${ROOT_API}/api/v1/organizations/${orgId}/scans/${scanId}/events`, { withCredentials: true });
    state.activeScanEventSource = source; streamOpen = true; streamErrors = 0; terminalPolls = 0;
    STREAM_EVENTS.forEach(type => source.addEventListener(type, receive));
    source.onopen = () => { streamErrors = 0; };
    source.onerror = () => {
      if (!isCurrent() || state.activeScanEventSource !== source) return;
      streamErrors += 1;
      const closed = source.readyState === EventSource.CLOSED;
      // The browser retries a CONNECTING stream itself; the backend replays missed events.
      if (!closed && streamErrors < STREAM_ERROR_LIMIT) { appendScanLog('Reconnecting…'); return; }
      source.close(); state.activeScanEventSource = null; streamOpen = false;
      appendScanLog('Event connection interrupted. Checking scan status periodically.');
      // A closed stream (for example an expired session) is reopened once after a poll succeeds.
      if (closed && !reopened) { reopened = true; reopenAfterPoll = true; }
      schedulePolls(FALLBACK_POLL_MS); poll();
    };
  };
  openStream(); schedulePolls(STREAM_POLL_MS); poll();
}
async function cancelCurrentScan() {
  if (!state.liveScanId || state.liveScanOrgId !== state.activeOrgId || !mayAnalyze()) return;
  const orgId = state.liveScanOrgId, scanId = state.liveScanId; setBusy('cancel-scan-btn', true);
  try {
    const scan = await apiRequest(`/organizations/${orgId}/scans/${scanId}/cancel`, { method: 'POST' });
    if (orgId !== state.activeOrgId || scanId !== state.liveScanId) return;
    updateMonitor(scan.status, scan.progress_pct); appendScanLog('Cancellation requested. Waiting for the scanner to stop.');
  } catch (error) { showToast(error.message, 'error'); setBusy('cancel-scan-btn', false); }
  finally { el('cancel-scan-btn').setAttribute('aria-busy', 'false'); }
}
function renderFindingDetails(finding) {
  const location = findingLocation(finding);
  el('finding-modal-title').textContent = finding.title;
  const badge = el('finding-modal-severity'); badge.textContent = finding.severity; badge.className = `badge badge-${SEVERITIES.has(finding.severity) ? finding.severity : 'info'}`;
  el('finding-modal-target').textContent = location.address; el('finding-modal-cvss').textContent = finding.cvss_score ?? 'Not scored';
  el('finding-modal-tool').textContent = finding.source_tool; el('finding-modal-port').textContent = location.port === null ? 'No service recorded' : `${location.port}/${location.protocol}`;
  el('finding-modal-desc').textContent = finding.description || 'No description provided.';
  // List rows are summaries without evidence; the detail request fills it in.
  el('finding-modal-evidence').textContent = Array.isArray(finding.evidence)
    ? finding.evidence.map(item => `${item.evidence_type}\n${item.content}`).join('\n\n') || 'No evidence recorded.'
    : state.evidenceStatus === 'error' ? 'Evidence could not be loaded.' : 'Loading evidence…';
}
async function openFindingModal(findingId) {
  const finding = state.findings.find(item => item.id === findingId); if (!finding) return;
  const orgId = state.activeOrgId;
  state.selectedFinding = finding; state.evidenceStatus = 'loading'; renderFindingDetails(finding);
  el('update-finding-status-select').value = finding.status; el('status-reason-input').value = finding.accepted_risk_reason || '';
  handleFindingStatusSelect(finding.status);
  el('ai-remediation-body').innerHTML = finding.llm_remediation ? renderRemediation(finding.llm_remediation) : '<p class="placeholder-text">Request guidance for this finding, then review it before making changes.</p>';
  applyPermissions(); openModal('finding-detail-modal');
  const stillSelected = () => state.selectedFinding?.id === findingId && orgId === state.activeOrgId;
  try {
    const detail = await apiRequest(`/organizations/${orgId}/findings/${findingId}`);
    if (!stillSelected()) return;
    if (!detail || typeof detail !== 'object' || Array.isArray(detail) || detail.id !== findingId) throw new Error('Unexpected finding response');
    const current = state.selectedFinding;
    // Keep edits made while the request was in flight (status change, generated guidance).
    const merged = current === finding ? { ...detail } : { ...detail, ...current, evidence: detail.evidence, remediation_notes: detail.remediation_notes };
    if (!merged.llm_remediation && current.llm_remediation) merged.llm_remediation = current.llm_remediation;
    const index = state.findings.findIndex(item => item.id === findingId); if (index !== -1) state.findings[index] = merged;
    state.selectedFinding = merged; state.evidenceStatus = 'loaded'; renderFindingDetails(merged);
    // Do not overwrite the panel while new guidance is being generated.
    if (merged.llm_remediation && el('fetch-ai-fix-btn').getAttribute('aria-busy') !== 'true') el('ai-remediation-body').innerHTML = renderRemediation(merged.llm_remediation);
  } catch {
    if (!stillSelected()) return;
    state.evidenceStatus = 'error';
    if (!Array.isArray(state.selectedFinding.evidence)) el('finding-modal-evidence').textContent = 'Evidence could not be loaded.';
  }
}
function renderRemediation(data) {
  const generated = data.source === 'llm';
  const list = values => `<ul>${(values || []).map(value => `<li>${escapeHTML(value)}</li>`).join('')}</ul>`;
  const references = (data.references || []).map(reference => {
    try {
      const url = new URL(reference);
      if (!['https:', 'http:'].includes(url.protocol)) return `<li>${escapeHTML(reference)}</li>`;
      return `<li><a href="${escapeHTML(url.href)}" target="_blank" rel="noopener noreferrer">${escapeHTML(reference)}</a></li>`;
    } catch { return `<li>${escapeHTML(reference)}</li>`; }
  }).join('');
  return `<span class="badge ${generated ? 'badge-low' : 'badge-info'}">${generated ? 'AI-generated guidance' : 'Generic or unverified guidance'}</span><p class="guidance-note">${escapeHTML(data.fallback_reason || (generated ? 'Review these steps against the affected system before applying them.' : 'Confirm this advice applies to the affected system.'))}</p><h4>Summary</h4><p>${escapeHTML(data.summary)}</p><h4>Root cause</h4><p>${escapeHTML(data.root_cause)}</p><h4>Business impact</h4><p>${escapeHTML(data.business_impact)}</p>${data.prerequisites?.length ? `<h4>Before you start</h4>${list(data.prerequisites)}` : ''}<h4>Remediation steps</h4><ol>${(data.remediation_steps || []).map(step => `<li><strong>${escapeHTML(step.title)}</strong><p>${escapeHTML(step.description)}</p>${step.commands_or_code ? `<pre><code>${escapeHTML(step.commands_or_code)}</code></pre>` : ''}<p><strong>Verify:</strong> ${escapeHTML(step.verification)}</p></li>`).join('')}</ol>${data.verification_steps?.length ? `<h4>Verification</h4>${list(data.verification_steps)}` : ''}${references ? `<h4>References</h4><ul>${references}</ul>` : ''}`;
}
async function generateAiRemediation() {
  if (!state.selectedFinding || !requireOrganization('analyst')) return;
  const findingId = state.selectedFinding.id, orgId = state.activeOrgId; setBusy('fetch-ai-fix-btn', true);
  try {
    const data = await apiRequest(`/organizations/${orgId}/findings/${findingId}/remediation`, { method: 'POST', timeoutMs: 150000 });
    if (state.selectedFinding?.id !== findingId || orgId !== state.activeOrgId) return;
    state.selectedFinding.llm_remediation = data; el('ai-remediation-body').innerHTML = renderRemediation(data);
    showToast(data.source === 'llm' ? 'Guidance generated. Review it before applying changes.' : 'Generic guidance is available. Review the source notice.');
  } catch (error) { if (state.selectedFinding?.id === findingId && orgId === state.activeOrgId) el('ai-remediation-body').textContent = `Could not generate guidance: ${error.message}`; }
  finally { setBusy('fetch-ai-fix-btn', false); applyPermissions(); }
}
function handleFindingStatusSelect(status) {
  el('finding-status-reason-group').classList.toggle('hidden', status !== 'accepted_risk'); el('status-reason-input').required = status === 'accepted_risk';
}
function saveFindingStatus() { return updateFindingStatus(el('update-finding-status-select').value); }
async function updateFindingStatus(status) {
  if (!state.selectedFinding || !requireOrganization('analyst')) return;
  if (!FINDING_STATUSES.has(status)) { showToast('Choose a valid finding status.', 'error'); return; }
  const reason = el('status-reason-input').value.trim();
  if (status === 'accepted_risk' && !reason) { showToast('Explain why this risk is being accepted.', 'error'); el('status-reason-input').focus(); return; }
  const findingId = state.selectedFinding.id, orgId = state.activeOrgId; setBusy('save-finding-status-btn', true);
  try {
    const finding = await apiRequest(`/organizations/${orgId}/findings/${findingId}`, { method: 'PATCH', body: JSON.stringify({ status, accepted_risk_reason: status === 'accepted_risk' ? reason : null }) });
    if (orgId !== state.activeOrgId) return;
    const index = state.findings.findIndex(item => item.id === findingId); if (index !== -1) state.findings[index] = finding;
    if (state.selectedFinding?.id === findingId) state.selectedFinding = finding;
    filterFindings(); renderDashboard(); showToast('Finding status updated', 'success');
  } catch (error) { showToast(error.message, 'error'); if (state.selectedFinding?.id === findingId) el('update-finding-status-select').value = state.selectedFinding.status; }
  finally { setBusy('save-finding-status-btn', false); applyPermissions(); }
}
// All interaction is delegated from document so the page needs no inline handlers (CSP
// script-src 'self'). Rows carry data attributes; untrusted values never become handlers.
document.addEventListener('click', event => {
  const button = event.target?.closest?.('[data-action]'); if (!button) return;
  const { action, id } = button.dataset;
  switch (action) {
    case 'navigate': return navigate(button.dataset.view, true);
    case 'switch-auth-tab': return switchAuthTab(button.dataset.tab);
    case 'open-modal': return openDialog(button.dataset.modal);
    case 'close-modal': return closeModal(button.dataset.modal);
    case 'logout': return handleLogout();
    case 'refresh': return refreshData();
    case 'cancel-scan': return cancelCurrentScan();
    case 'close-monitor': return closeLiveMonitor(true);
    case 'generate-remediation': return generateAiRemediation();
    case 'save-finding-status': return saveFindingStatus();
    case 'use-approved-targets': return useApprovedTargets();
    case 'revoke-auth': return revokeAuthorization(id);
    case 'open-report':
      if (event.button > 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return undefined;
      event.preventDefault?.();
      return openReport(id);
    case 'dismiss-toast': return button.parentElement?.remove();
    case 'finding': return openFindingModal(id);
    case 'monitor': navigate('scans'); return monitorScan(id);
    case 'retry': return retryCollection(button.dataset.collection);
    default: return undefined;
  }
});
document.addEventListener('submit', event => {
  switch (event.target?.id) {
    case 'login-form': return handleLogin(event);
    case 'register-form': return handleRegister(event);
    case 'new-scan-form': return handleLaunchScan(event);
    case 'new-auth-form': return handleCreateAuth(event);
    case 'new-report-form': return handleGenerateReport(event);
    case 'new-org-form': return handleCreateOrg(event);
    default: return undefined;
  }
});
document.addEventListener('change', event => {
  const target = event.target; if (!target) return undefined;
  switch (target.id) {
    case 'active-org-select': return handleOrgChange(target.value);
    case 'findings-severity-filter':
    case 'findings-status-filter': return filterFindings();
    case 'scan-profile-select': return handleProfileSelect(target);
    case 'update-finding-status-select': return handleFindingStatusSelect(target.value);
    case 'scan-auth-select': return renderApprovedTargets();
    default: return undefined;
  }
});
document.addEventListener('visibilitychange', () => { if (pageVisible() && state.autoRefreshInterval !== null) autoRefresh(); });
document.addEventListener('keydown', event => {
  const modals = [...document.querySelectorAll('.modal-backdrop:not(.hidden)')], modal = modals[modals.length - 1]; if (!modal) return;
  if (event.key === 'Escape' && modal.id !== 'auth-modal') { closeModal(modal.id); event.preventDefault(); return; }
  if (event.key !== 'Tab') return;
  const focusable = [...modal.querySelectorAll('button, input, select, textarea, a[href], [tabindex="0"]')].filter(item => !item.disabled && item.getClientRects().length);
  if (!focusable.length) return;
  const first = focusable[0], last = focusable[focusable.length - 1];
  if (!modal.contains(document.activeElement)) { first.focus(); event.preventDefault(); return; }
  if (event.shiftKey && document.activeElement === first) { last.focus(); event.preventDefault(); }
  else if (!event.shiftKey && document.activeElement === last) { first.focus(); event.preventDefault(); }
});
document.addEventListener('DOMContentLoaded', initApplication);
