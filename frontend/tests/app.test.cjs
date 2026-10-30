const assert = require('node:assert/strict');
const test = require('node:test');
const { createHarness, ElementStub } = require('./harness.cjs');
const fixtures = require('./fixtures/contracts.json');

const clone = value => structuredClone(value);
const orgId = fixtures.organization.id;
const scanId = fixtures.scan.id;
const findingId = fixtures.finding.id;
const base = `/api/v1/organizations/${orgId}`;
const submitEvent = () => ({ preventDefault() {} });
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const payloadOf = call => JSON.parse(call.body);
const activeInlineHandlers = html => {
  const handlers = [];
  for (const tag of html.match(/<[a-z][a-z0-9-]*(?:[^>"']|"[^"]*"|'[^']*')*>/gi) ?? []) {
    const attributes = tag.replace(/^<[a-z][a-z0-9-]*/i, '').replace(/>$/, '');
    for (const attribute of attributes.matchAll(/([^\s=]+)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?/g)) {
      if (/^on[a-z]+$/i.test(attribute[1])) handlers.push(attribute[1]);
    }
  }
  return handlers;
};
const onlyCall = (h, suffix, method) => {
  const matches = h.calls.filter(call => call.url.endsWith(suffix) && call.method === method);
  assert.equal(matches.length, 1, `${method} ${suffix} must be called once`);
  return matches[0];
};

function setup(options = {}) {
  const h = createHarness(options);
  Object.assign(h.state, {
    activeOrgId: orgId,
    user: clone(fixtures.user),
    organizations: [clone(fixtures.organization)],
    profiles: [clone(fixtures.profile)],
    scans: [clone(fixtures.scan)],
    assets: [clone(fixtures.asset)],
    findings: [clone(fixtures.finding)],
    authorizations: [clone(fixtures.authorization)],
  });
  return h;
}

function fillScope(h) {
  h.el('auth-signer-name').value = 'Lab Owner';
  h.el('auth-signer-email').value = 'owner@example.com';
  const title = h.elements.get('auth-title') ?? h.elements.get('auth-signer-title');
  assert.ok(title, 'Scope form needs a title field');
  title.value = 'Local lab scope';
  h.el('auth-date').value = '2026-10-02';
  h.el('auth-expiration').value = '2026-10-31';
  h.el('auth-notes').value = 'Controlled lab hosts only';
  h.el('auth-targets').value = '127.0.0.1, localhost\n127.0.0.1';
}

test('authorization submission includes required dates/title and structured targets', async () => {
  const h = setup({ respond: () => ({ body: fixtures.authorization }) });
  h.state.user.memberships[0].role = 'admin';
  h.disableRefresh();
  fillScope(h);
  await h.invoke('handleCreateAuth', submitEvent());
  const call = onlyCall(h, `${base}/authorizations`, 'POST');
  const payload = payloadOf(call);
  assert.equal(payload.title, 'Local lab scope');
  assert.equal(payload.signer_name, 'Lab Owner');
  assert.equal(payload.signer_email, 'owner@example.com');
  assert.equal(payload.authorization_date, '2026-10-02');
  assert.equal(payload.expiration_date, '2026-10-31');
  assert.equal(payload.notes, 'Controlled lab hosts only');
  assert.ok(Array.isArray(payload.targets));
  assert.deepEqual([...new Set(payload.targets.map(target => target.value))], ['127.0.0.1', 'localhost']);
  for (const target of payload.targets) assert.equal(typeof target.value, 'string');
  for (const unsupported of ['signer_title', 'authorized_targets', 'max_targets_per_scan', 'allow_private_ips', 'authorized_at']) {
    assert.equal(Object.hasOwn(payload, unsupported), false, `Do not submit unsupported field ${unsupported}`);
  }
});

test('intrusive scan requires acknowledgement before any request', async () => {
  const h = setup();
  h.state.user.memberships[0].role = 'admin';
  h.el('scan-auth-select').value = fixtures.authorization.id;
  h.el('scan-profile-select').value = fixtures.profile.id;
  const option = new ElementStub('option');
  Object.assign(option, { value: fixtures.profile.id, dataset: { intrusive: 'true' } });
  h.el('scan-profile-select').selectedOptions = [option];
  h.state.profiles[0].is_intrusive = true;
  h.el('scan-targets-input').value = '127.0.0.1';
  h.el('intrusive-checkbox').checked = false;
  await h.invoke('handleLaunchScan', submitEvent());
  assert.equal(h.calls.length, 0);
});

test('scan creation submits normalized target strings and organization scope', async () => {
  const h = setup({ respond: call => ({ body: call.method === 'POST' ? fixtures.scan : [] }) });
  h.disableRefresh();
  h.context.monitorScan = () => {};
  h.el('scan-auth-select').value = fixtures.authorization.id;
  h.el('scan-profile-select').value = fixtures.profile.id;
  h.el('scan-profile-select').selectedOptions = [Object.assign(new ElementStub('option'), { value: fixtures.profile.id, dataset: { intrusive: 'false' } })];
  h.el('scan-targets-input').value = '127.0.0.1, localhost\n';
  await h.invoke('handleLaunchScan', submitEvent());
  assert.deepEqual(payloadOf(onlyCall(h, `${base}/scans`, 'POST')), {
    authorization_id: fixtures.authorization.id, profile_id: fixtures.profile.id,
    targets: ['127.0.0.1', 'localhost'], intrusive_acknowledged: false,
  });
});

test('cancel request remains in the organization that owns the monitored scan', async () => {
  const h = setup({ respond: () => ({ body: { ...fixtures.scan, status: 'cancel_requested' } }) });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId, '127.0.0.1');
  await h.settle();
  await h.invoke('cancelCurrentScan');
  const call = onlyCall(h, `${base}/scans/${scanId}/cancel`, 'POST');
  assert.equal(call.credentials, 'include');
});

test('monitor subscribes to named SSE events and reads nested event payloads', async () => {
  const h = setup({ respond: () => ({ body: fixtures.scan }) });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId, '127.0.0.1');
  await h.settle();
  const es = h.eventSources.at(-1);
  assert.equal(es.url, `${base}/scans/${scanId}/events`);
  assert.equal(es.options.withCredentials, true);
  for (const event of ['stage_started', 'tool_started', 'tool_finished', 'scan_completed', 'scan_failed', 'scan_cancelled', 'scan_timed_out', 'done']) {
    assert.ok(es.handlers.has(event), `Must listen for named ${event} event`);
  }
  await es.emit('tool_finished', {
    id: 'event-1', event_type: 'tool_finished', created_at: '2026-10-02T08:00:05Z',
    payload: { tool: 'nmap', exit_code: 1, error: 'Local fixture scanner error', assets_found: 1, findings_found: 1 },
  });
  assert.match(h.el('live-scan-console').textContent, /Local fixture scanner error/);
  await h.invoke('closeLiveMonitor');
  assert.equal(es.closed, true);
  assert.equal(h.intervals.size, 0);
});

for (const status of ['completed', 'failed', 'cancelled', 'timed_out']) {
  test(`named terminal ${status} event closes monitor and accurately shows completion`, async () => {
    const h = setup({ respond: () => ({ body: fixtures.scan }) });
    h.disableRefresh();
    await h.invoke('monitorScan', scanId, '127.0.0.1');
    await h.settle();
    const es = h.eventSources.at(-1);
    h.el('live-scan-progress-bar').style.width = '35%';
    await es.emit(`scan_${status}`, {
      id: 'terminal-event', event_type: `scan_${status}`, created_at: '2026-10-02T08:01:00Z',
      payload: { message: `Scan ${status}; partial results retained`, findings_count: 1 },
    });
    assert.equal(es.closed, true);
    assert.equal(h.intervals.size, 0);
    assert.match(h.el('live-scan-status-badge').textContent.toLowerCase().replaceAll(' ', '_'), new RegExp(status));
    if (status === 'completed') assert.equal(h.el('live-scan-progress-bar').style.width, '100%');
    else assert.notEqual(h.el('live-scan-progress-bar').style.width, '100%', 'Incomplete scans must not look fully completed');
  });
}

test('done event uses final_status even without a terminal scan event', async () => {
  const h = setup({ respond: () => ({ body: fixtures.scan }) });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId, '127.0.0.1');
  await h.settle();
  const es = h.eventSources.at(-1);
  await es.emit('done', { event_type: 'stream_closed', final_status: 'cancelled' });
  assert.equal(es.closed, true);
  assert.equal(h.intervals.size, 0);
  assert.match(h.el('live-scan-status-badge').textContent.toLowerCase(), /cancelled/);
});

test('finding details derive the address and service from backend relationship IDs', async () => {
  const h = setup();
  await h.invoke('openFindingModal', findingId);
  assert.match(h.el('finding-modal-target').textContent, /127\.0\.0\.1/);
  assert.match(h.el('finding-modal-port').textContent, /443\/tcp/);
  assert.match(h.el('finding-modal-evidence').textContent, /TLS 1\.0 accepted/);
  assert.equal(h.el('update-finding-status-select').value, 'open');
});

test('remediation POST renders structured guidance and clearly identifies generic fallback', async () => {
  const h = setup({ respond: () => ({ body: fixtures.remediation }) });
  h.state.selectedFinding = h.state.findings[0];
  await h.invoke('generateAiRemediation');
  onlyCall(h, `${base}/findings/${findingId}/remediation`, 'POST');
  const text = h.el('ai-remediation-body').textContent;
  for (const expected of [fixtures.remediation.summary, fixtures.remediation.root_cause, fixtures.remediation.business_impact,
    ...fixtures.remediation.prerequisites, fixtures.remediation.remediation_steps[0].title,
    fixtures.remediation.remediation_steps[0].commands_or_code,
    fixtures.remediation.remediation_steps[0].verification, ...fixtures.remediation.verification_steps]) {
    assert.ok(text.includes(expected), `Missing guidance: ${expected}`);
  }
  assert.match(text, /fallback|generic/i);
  assert.ok(text.includes(fixtures.remediation.fallback_reason));
});

test('finding status PATCH uses actual endpoint and lowercase enum', async () => {
  const h = setup({ respond: () => ({ body: { ...fixtures.finding, status: 'in_progress' } }) });
  h.disableRefresh();
  h.state.selectedFinding = h.state.findings[0];
  await h.invoke('updateFindingStatus', 'in_progress');
  assert.equal(payloadOf(onlyCall(h, `${base}/findings/${findingId}`, 'PATCH')).status, 'in_progress');
  assert.equal(h.state.selectedFinding.status, 'in_progress');
});

test('finding filters use API severity and status values', async () => {
  const h = setup();
  h.state.findings.push({ ...clone(fixtures.finding), id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', title: 'Another lower severity finding', severity: 'low', status: 'fixed' });
  h.el('findings-severity-filter').value = 'high';
  h.el('findings-status-filter').value = 'open';
  await h.invoke('filterFindings');
  assert.match(h.el('findings-tbody').textContent, /Legacy TLS enabled/);
  assert.doesNotMatch(h.el('findings-tbody').textContent, /Another lower severity/);
});

test('scan and authorization rendering reads target objects rather than invented fields', async () => {
  const h = setup({ respond: call => ({ body: call.url.includes('/authorizations?') ? [fixtures.authorization] : [fixtures.scan] }) });
  await h.invoke('loadScans');
  await h.invoke('loadAuthorizations');
  for (const id of ['scans-tbody', 'authorizations-tbody']) {
    assert.match(h.el(id).textContent, /127\.0\.0\.1/);
    assert.doesNotMatch(h.el(id).textContent, /\[object Object\]|undefined|Invalid Date/);
  }
  assert.match(h.el('scans-tbody').textContent, /Local discovery/);
});

test('dashboard counts lowercase critical/high severities', async () => {
  const h = setup({ respond: call => ({ body: call.url.endsWith('/findings') ? [fixtures.finding, { ...fixtures.finding, severity: 'critical' }] : [] }) });
  h.state.findings = [clone(fixtures.finding), { ...clone(fixtures.finding), severity: 'critical' }];
  h.state.scans = ['queued', 'running', 'cancel_requested', 'completed', 'failed', 'cancelled', 'timed_out'].map(status => ({ ...clone(fixtures.scan), status }));
  await h.invoke('loadDashboard');
  assert.equal(h.el('stat-critical-count').textContent, '2');
  assert.equal(h.el('stat-scans-count').textContent, '3 / 7');
});

test('scan elapsed time treats backend timestamps without offsets as UTC', async () => {
  const h = setup({ respond: () => ({ body: fixtures.scan }) });
  h.state.scans = [{ ...clone(fixtures.scan), status: 'running', started_at: '2026-10-02T11:00:00' }];
  await h.invoke('monitorScan', fixtures.scan.id);
  assert.equal(h.state.liveScanStartTime, Date.parse('2026-10-02T11:00:00Z'));
});

test('untrusted finding titles, identifiers, descriptions and evidence remain inert text', async () => {
  const h = setup();
  const hostile = '<img src=x onerror=alert(1)>'; // No script is executed by this offline harness.
  const finding = { ...clone(fixtures.finding), id: "bad' onclick='alert(2)", title: hostile, description: hostile, source_tool: hostile,
    evidence: [{ ...fixtures.finding.evidence[0], content: hostile }] };
  h.state.findings = [finding];
  await h.invoke('renderFindings', h.state.findings);
  assert.ok(h.el('findings-tbody').textContent.includes(hostile), 'Original evidence text should remain visible');
  assert.doesNotMatch(h.el('findings-tbody').innerHTML, /<img\b/i, 'Scanner fields must not create HTML');
  assert.deepEqual(activeInlineHandlers(h.el('findings-tbody').innerHTML), [], 'Scanner fields must not create executable handlers');
  await h.invoke('openFindingModal', finding.id);
  for (const id of ['finding-modal-title', 'finding-modal-desc', 'finding-modal-evidence']) {
    assert.ok(h.el(id).textContent.includes(hostile));
    assert.doesNotMatch(h.el(id).innerHTML, /<img\b/i);
  }
});

test('untrusted remediation code, text, and error messages remain inert', async () => {
  const hostile = '<svg onload=alert(1)>unsafe scanner detail</svg>';
  const remediation = { ...clone(fixtures.remediation), summary: hostile,
    remediation_steps: [{ ...fixtures.remediation.remediation_steps[0], commands_or_code: hostile }],
    references: ['javascript:alert(1)', 'https://www.rfc-editor.org/rfc/rfc8996'] };
  const h = setup({ respond: () => ({ body: remediation }) });
  h.state.selectedFinding = h.state.findings[0];
  await h.invoke('generateAiRemediation');
  assert.ok(h.el('ai-remediation-body').textContent.includes(hostile));
  assert.doesNotMatch(h.el('ai-remediation-body').innerHTML, /<svg\b|href=["']javascript:/i);
  const failed = setup({ respond: () => ({ status: 503, body: { detail: hostile } }) });
  failed.state.selectedFinding = failed.state.findings[0];
  await failed.invoke('generateAiRemediation');
  assert.doesNotMatch(failed.el('ai-remediation-body').innerHTML, /<svg\b/i);
});

test('login and subsequent API requests use cookies without reading or storing JWTs', async () => {
  const h = setup({ storage: { vulnscanner_jwt: 'legacy-sensitive-token' }, respond: () => ({ body: { access_token: 'new-sensitive-token' } }) });
  h.context.initApplication = async () => {};
  h.el('login-email').value = 'analyst@example.com';
  h.el('login-password').value = 'Password123!';
  await h.invoke('handleLogin', submitEvent());
  await h.invoke('apiRequest', '/organizations');
  assert.equal(h.storage.has('vulnscanner_jwt'), false, 'Remove old JWT storage');
  assert.equal(h.storageCalls.some(([action, key]) => ['get', 'set'].includes(action) && key === 'vulnscanner_jwt'), false, 'JWT must not be read or persisted');
  for (const call of h.calls) {
    assert.equal(call.credentials, 'include');
    const headers = new Headers(call.headers);
    assert.equal(headers.has('authorization'), false, 'Cookie requests must not expose a bearer token to JS storage');
  }
});

test('expired cookie refreshes once and replays the original request', async () => {
  let attempts = 0;
  const h = setup({ respond: call => {
    if (call.url.endsWith('/auth/refresh')) return { body: { access_token: 'ignored-token' } };
    attempts += 1;
    return attempts === 1 ? { status: 401, body: { detail: 'Expired access session' } } : { body: [fixtures.organization] };
  } });
  const result = await h.invoke('apiRequest', '/organizations');
  assert.equal(result[0].id, orgId);
  assert.deepEqual(h.calls.map(call => [call.method, call.url]), [
    ['GET', '/api/v1/organizations'], ['POST', '/api/v1/auth/refresh'], ['GET', '/api/v1/organizations'],
  ]);
  assert.equal(h.storageCalls.some(([action, key]) => action === 'set' && key === 'vulnscanner_jwt'), false);
});

test('failed refresh ends the session with no retry loop', async () => {
  const h = setup({ respond: () => ({ status: 401, body: { detail: 'Session expired' } }) });
  await assert.rejects(() => h.invoke('apiRequest', '/organizations'));
  assert.equal(h.calls.filter(call => call.url.endsWith('/auth/refresh')).length, 1);
  // original request, refresh, one replay (another tab may have rotated the cookies)
  assert.equal(h.calls.length, 3);
  assert.equal(h.el('auth-modal').classList.contains('hidden'), false);
  assert.equal(h.el('app-shell').classList.contains('hidden'), true);
});

test('a refresh lost to another tab still replays the request with the rotated cookies', async () => {
  let attempts = 0;
  const h = setup({ respond: call => {
    if (call.url.endsWith('/auth/refresh')) return { status: 401, body: { detail: 'Refresh token has already been used' } };
    attempts += 1;
    return attempts === 1 ? { status: 401, body: { detail: 'Expired access session' } } : { body: [fixtures.organization] };
  } });
  const result = await h.invoke('apiRequest', '/organizations');
  assert.equal(result[0].id, orgId);
  assert.equal(h.el('auth-modal').classList.contains('hidden'), true, 'The other tab renewed the session; no sign-in prompt');
});

test('concurrent expired protected requests share one refresh, including the user profile', async () => {
  const attempts = new Map();
  let completeRefresh;
  const refresh = new Promise(resolve => { completeRefresh = resolve; });
  const h = setup({ respond: call => {
    if (call.url.endsWith('/auth/refresh')) return refresh;
    const count = (attempts.get(call.url) ?? 0) + 1;
    attempts.set(call.url, count);
    if (count === 1) return { status: 401, body: { detail: 'Expired access cookie' } };
    return { body: call.url.endsWith('/auth/me') ? fixtures.user : [fixtures.organization] };
  } });
  const organizations = h.invoke('apiRequest', '/organizations');
  const profile = h.invoke('apiRequest', '/auth/me');
  await h.settle();
  assert.equal(h.calls.filter(call => call.url.endsWith('/auth/refresh')).length, 1);
  completeRefresh({ body: { access_token: 'ignored-token' } });
  const [orgs, user] = await Promise.all([organizations, profile]);
  assert.equal(orgs[0].id, orgId);
  assert.equal(user.id, fixtures.user.id);
  assert.equal(h.calls.filter(call => call.url.endsWith('/auth/refresh')).length, 1);
});

test('validation error details are readable rather than object coercion', async () => {
  const h = setup({ respond: () => ({ status: 422, body: { detail: [{ loc: ['body', 'title'], msg: 'Field required', type: 'missing' }] } }) });
  await assert.rejects(() => h.invoke('apiRequest', '/organizations'), error => {
    assert.match(error.message, /title|Field required/i);
    assert.doesNotMatch(error.message, /\[object Object\]/);
    return true;
  });
});

test('accepting risk requires a reason and submits it with the status', async () => {
  const h = setup({ respond: () => ({ body: { ...fixtures.finding, status: 'accepted_risk', accepted_risk_reason: 'Compensating controls approved until next review' } }) });
  h.disableRefresh();
  h.state.selectedFinding = h.state.findings[0];
  h.el('status-reason-input').value = '';
  await h.invoke('updateFindingStatus', 'accepted_risk');
  assert.equal(h.calls.length, 0, 'Empty justification must be rejected before submission');
  h.el('status-reason-input').value = 'Compensating controls approved until next review';
  await h.invoke('updateFindingStatus', 'accepted_risk');
  const payload = payloadOf(onlyCall(h, `${base}/findings/${findingId}`, 'PATCH'));
  assert.equal(payload.status, 'accepted_risk');
  assert.equal(payload.accepted_risk_reason, 'Compensating controls approved until next review');
});

test('reports submit the actual type enum and link to session-authenticated downloads', async () => {
  const h = setup({ respond: call => ({ body: call.method === 'POST' ? fixtures.report : [fixtures.report] }) });
  h.el('report-scan-select').value = scanId;
  h.el('report-type-select').value = 'technical';
  h.el('report-title-input').value = 'Local lab technical assessment';
  await h.invoke('handleGenerateReport', submitEvent());
  assert.deepEqual(payloadOf(onlyCall(h, `${base}/reports`, 'POST')), {
    scan_id: scanId, report_type: 'technical', title: fixtures.report.title,
  });
  await h.invoke('loadReports');
  const html = h.el('reports-tbody').innerHTML;
  assert.ok(html.includes(`href="${base}/reports/${fixtures.report.id}/html"`), 'View HTML must use the cookie-authenticated organization route');
  assert.doesNotMatch(html, /local-report-fixture-token|\/reports\/download\//, 'The console must not expose bearer-style token URLs');
  assert.match(html, /target="_blank" rel="noopener noreferrer"/);
  assert.match(html, /aria-label="View report Local lab technical assessment/);
  assert.doesNotMatch(h.el('reports-tbody').textContent, /undefined|Invalid Date/);
  assert.ok(h.calls.some(call => call.method === 'GET' && call.url === `${base}/reports?limit=100&offset=0`), 'Reports are paginated');
});

test('late responses from an old organization do not replace the selected organization data', async () => {
  let resolveOld;
  const oldResponse = new Promise(resolve => { resolveOld = resolve; });
  const h = setup({ respond: () => oldResponse });
  const load = h.invoke('loadScans');
  await h.settle();
  h.state.activeOrgId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  h.state.scans = [];
  h.el('scans-tbody').textContent = 'Selected organization has no scans';
  resolveOld({ body: [fixtures.scan] });
  await load;
  assert.equal(h.state.scans.length, 0);
  assert.equal(h.el('scans-tbody').textContent, 'Selected organization has no scans');
});

test('changing organizations closes old scan monitoring before another action', async () => {
  const h = setup({ respond: call => ({ body: call.url.endsWith('/scan-profiles') ? [fixtures.profile] : fixtures.scan }) });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId, '127.0.0.1');
  await h.settle();
  const source = h.eventSources.at(-1);
  const nextOrg = { ...clone(fixtures.organization), id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', name: 'Second lab' };
  h.state.organizations.push(nextOrg);
  await h.invoke('handleOrgChange', nextOrg.id);
  await h.invoke('cancelCurrentScan');
  assert.equal(source.closed, true);
  assert.equal(h.intervals.size, 0);
  assert.equal(h.state.liveScanId, null);
  assert.equal(h.calls.some(call => call.url.endsWith('/cancel')), false);
});

test('logout closes scan monitoring and hides organization data', async () => {
  const h = setup({ respond: call => call.url.endsWith('/auth/logout') ? { status: 204 } : { body: fixtures.scan } });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId, '127.0.0.1');
  await h.settle();
  const source = h.eventSources.at(-1);
  await h.invoke('handleLogout');
  onlyCall(h, '/api/v1/auth/logout', 'POST');
  assert.equal(source.closed, true);
  assert.equal(h.intervals.size, 0);
  assert.equal(h.state.user, null);
  assert.equal(h.el('app-shell').classList.contains('hidden'), true);
});

for (const invalidate of ['handleAuthRequired', 'handleLogout']) {
  test(`stale initial user profile cannot reopen the app after ${invalidate}`, async () => {
    const profile = deferred();
    const h = setup({ respond: call => call.url.endsWith('/auth/me') ? profile.promise
      : call.url.endsWith('/auth/logout') ? { status: 204 }
      : { body: [] } });
    h.disableRefresh();
    h.state.user = null;
    const initialization = h.invoke('initApplication');
    await h.settle();
    await h.invoke(invalidate);
    profile.resolve({ body: fixtures.user });
    await initialization;
    assert.equal(h.state.user, null);
    assert.equal(h.state.organizations.length, 0);
    assert.equal(h.el('app-shell').classList.contains('hidden'), true);
    assert.equal(h.el('auth-modal').classList.contains('hidden'), false);
    assert.equal(h.calls.some(call => call.url.includes('/system/scanner-status')), false, 'An obsolete initialization must not continue loading');
  });
}

test('pending organization list cannot repopulate account state after logout', async () => {
  const organizations = deferred();
  const h = setup({ respond: call => call.url.endsWith('/organizations') ? organizations.promise
    : call.url.endsWith('/auth/logout') ? { status: 204 }
    : { body: [] } });
  h.disableRefresh();
  const loading = h.invoke('loadOrganizations');
  await h.settle();
  await h.invoke('handleLogout');
  organizations.resolve({ body: [fixtures.organization] });
  await loading;
  assert.equal(h.state.organizations.length, 0);
  assert.equal(h.state.activeOrgId, null);
  assert.equal(h.state.user, null);
  assert.equal(h.el('app-shell').classList.contains('hidden'), true);
});

test('organization change during the post-launch list refresh cannot monitor the previous scan', async () => {
  const scans = deferred();
  const h = setup({ respond: call => call.method === 'POST' && call.url.endsWith('/scans') ? { body: fixtures.scan }
    : call.url.includes(`/organizations/${orgId}/scans?`) ? scans.promise
    : { body: [] } });
  h.el('scan-auth-select').value = fixtures.authorization.id;
  h.el('scan-profile-select').value = fixtures.profile.id;
  h.el('scan-targets-input').value = '127.0.0.1';
  const launching = h.invoke('handleLaunchScan', submitEvent());
  await h.settle();
  assert.ok(h.calls.some(call => call.url.includes(`/organizations/${orgId}/scans?`)), 'Wait until the post-launch list request is in flight');
  const nextOrg = { ...clone(fixtures.organization), id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', name: 'Second lab' };
  h.state.organizations.push(nextOrg);
  await h.invoke('handleOrgChange', nextOrg.id);
  scans.resolve({ body: [fixtures.scan] });
  await launching;
  assert.equal(h.state.activeOrgId, nextOrg.id);
  assert.equal(h.state.liveScanId, null);
  assert.equal(h.eventSources.length, 0, 'The original scan must not open an event stream in the newly selected organization');
  assert.equal(h.calls.some(call => call.url === `/api/v1/organizations/${nextOrg.id}/scans/${scanId}`), false);
});

for (const shiftKey of [false, true]) {
  test(`modal traps ${shiftKey ? 'Shift+Tab' : 'Tab'} when focus starts outside the dialog`, async () => {
    const h = setup();
    const modal = h.el('new-org-modal');
    modal.classList.remove('hidden');
    const first = h.el('org-name-input');
    const last = h.el('create-org-submit-btn');
    modal.appendChild(first); modal.appendChild(last);
    modal.querySelectorAll = () => [first, last];
    h.document.querySelectorAll = selector => selector === '.modal-backdrop:not(.hidden)' ? [modal] : [];
    h.document.activeElement = h.el('quick-scan-btn');
    let prevented = false;
    await h.dispatchDocumentEvent('keydown', { key: 'Tab', shiftKey, preventDefault() { prevented = true; } });
    assert.equal(prevented, true);
    assert.equal(modal.contains(h.document.activeElement), true, 'Focus must redirect into the open dialog');
  });

  test(`modal wraps ${shiftKey ? 'Shift+Tab from its first control' : 'Tab from its last control'}`, async () => {
    const h = setup();
    const modal = h.el('new-org-modal');
    modal.classList.remove('hidden');
    const first = h.el('org-name-input'), last = h.el('create-org-submit-btn');
    modal.appendChild(first); modal.appendChild(last);
    modal.querySelectorAll = () => [first, last];
    h.document.querySelectorAll = selector => selector === '.modal-backdrop:not(.hidden)' ? [modal] : [];
    h.document.activeElement = shiftKey ? first : last;
    let prevented = false;
    await h.dispatchDocumentEvent('keydown', { key: 'Tab', shiftKey, preventDefault() { prevented = true; } });
    assert.equal(prevented, true);
    assert.equal(h.document.activeElement, shiftKey ? last : first);
  });
}

// --- CSP compliance and delegated events -------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const appSource = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
const stylesSource = fs.readFileSync(path.join(__dirname, '..', 'styles.css'), 'utf8');
const otherFindingId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const summaryOf = finding => { const row = clone(finding); delete row.evidence; delete row.remediation_notes; return row; };
const actionTarget = dataset => {
  // The click lands on an inner element; the delegated listener must walk up with closest().
  const button = Object.assign(new ElementStub('button'), { dataset });
  const icon = new ElementStub('svg');
  button.appendChild(icon);
  return icon;
};
const longIntervals = h => [...h.intervals.values()].filter(interval => interval.delay >= 10000);

test('console markup works under a strict CSP: no inline handlers, styles or external resources', () => {
  assert.deepEqual(activeInlineHandlers(indexHtml), []);
  assert.doesNotMatch(indexHtml, /\sstyle\s*=/i, 'style attributes are blocked by style-src self');
  assert.doesNotMatch(indexHtml, /<(?:link|script)\b[^>]*\b(?:href|src)\s*=\s*["']?(?:https?:)?\/\//i, 'Load scripts and styles from the console origin only');
  assert.doesNotMatch(appSource, /\sstyle=|\son[a-z]+=["']/i, 'Templates must not create inline styles or handlers');
  assert.ok(/\.progress-bar\s*\{[^}]*width:\s*0/.test(stylesSource), 'The progress bar starts empty from the stylesheet');
  assert.ok(/--font-sans:[^;]*system-ui/.test(stylesSource), 'Fonts fall back to system faces');
  assert.equal(/fonts\.(googleapis|gstatic)\.com|@import|url\(\s*["']?https?:/i.test(stylesSource), false, 'No external font or style downloads');
  assert.doesNotMatch(indexHtml, /id="toast-container"[^>]*aria-live/, 'Each toast announces itself through its own role');
  assert.match(indexHtml, /id="reg-password"[^>]*minlength="12"/);
  assert.match(indexHtml, /Password \(12\+ characters\)/);
  assert.match(indexHtml, /id="page-title"[^>]*tabindex="-1"/);
});

test('the sign-in dialog starts hidden behind a session check', () => {
  const h = createHarness();
  assert.equal(h.el('auth-modal').classList.contains('hidden'), true);
  assert.equal(h.el('session-check').classList.contains('hidden'), false);
  h.invoke('handleAuthRequired');
  assert.equal(h.el('auth-modal').classList.contains('hidden'), false);
  assert.equal(h.el('session-check').classList.contains('hidden'), true);
});

test('delegated submit listener maps each form to its handler', async () => {
  const h = setup();
  const seen = [];
  for (const name of ['handleLogin', 'handleRegister', 'handleLaunchScan', 'handleCreateAuth', 'handleGenerateReport', 'handleCreateOrg']) {
    h.context[name] = event => { seen.push(name); event.preventDefault(); };
  }
  let prevented = 0;
  for (const form of ['login-form', 'register-form', 'new-scan-form', 'new-auth-form', 'new-report-form', 'new-org-form']) {
    await h.dispatchDocumentEvent('submit', { target: h.el(form), preventDefault() { prevented += 1; } });
  }
  assert.deepEqual(seen, ['handleLogin', 'handleRegister', 'handleLaunchScan', 'handleCreateAuth', 'handleGenerateReport', 'handleCreateOrg']);
  assert.equal(prevented, 6);
});

test('delegated change listener drives selects without inline handlers', async () => {
  const h = setup();
  const seen = [];
  for (const name of ['handleOrgChange', 'filterFindings', 'handleProfileSelect', 'handleFindingStatusSelect', 'renderApprovedTargets']) {
    h.context[name] = (...args) => { seen.push([name, ...args]); };
  }
  h.el('active-org-select').value = orgId;
  h.el('update-finding-status-select').value = 'fixed';
  for (const id of ['active-org-select', 'findings-severity-filter', 'findings-status-filter', 'scan-profile-select', 'update-finding-status-select', 'scan-auth-select']) {
    await h.dispatchDocumentEvent('change', { target: h.el(id) });
  }
  assert.deepEqual(seen, [
    ['handleOrgChange', orgId], ['filterFindings'], ['filterFindings'],
    ['handleProfileSelect', h.el('scan-profile-select')], ['handleFindingStatusSelect', 'fixed'], ['renderApprovedTargets'],
  ]);
});

test('delegated click listener routes data-action buttons from markup and rows', async () => {
  const h = setup();
  const seen = [];
  for (const name of ['openNewScanModal', 'openNewOrgModal', 'openNewAuthModal', 'openNewReportModal', 'closeModal', 'handleLogout', 'cancelCurrentScan', 'closeLiveMonitor',
    'generateAiRemediation', 'saveFindingStatus', 'refreshActiveOrgData', 'switchAuthTab', 'openFindingModal', 'monitorScan']) {
    h.context[name] = (...args) => { seen.push([name, ...args]); };
  }
  for (const dataset of [
    { action: 'open-modal', modal: 'new-scan-modal' }, { action: 'open-modal', modal: 'new-org-modal' },
    { action: 'open-modal', modal: 'new-auth-modal' }, { action: 'open-modal', modal: 'new-report-modal' },
    { action: 'close-modal', modal: 'new-scan-modal' }, { action: 'logout' }, { action: 'cancel-scan' }, { action: 'close-monitor' },
    { action: 'generate-remediation' }, { action: 'save-finding-status' }, { action: 'refresh' }, { action: 'switch-auth-tab', tab: 'register' },
    { action: 'finding', id: findingId }, { action: 'monitor', id: scanId },
  ]) await h.dispatchDocumentEvent('click', { target: actionTarget(dataset) });
  assert.deepEqual(seen.map(([name]) => name), ['openNewScanModal', 'openNewOrgModal', 'openNewAuthModal', 'openNewReportModal', 'closeModal', 'handleLogout',
    'cancelCurrentScan', 'closeLiveMonitor', 'generateAiRemediation', 'saveFindingStatus', 'refreshActiveOrgData', 'switchAuthTab', 'openFindingModal', 'monitorScan']);
  assert.deepEqual(seen[4], ['closeModal', 'new-scan-modal']);
  assert.deepEqual(seen.at(-2), ['openFindingModal', findingId]);
  assert.equal(h.el('page-title').textContent, 'Scans & audits', 'Monitoring a scan opens the scans view');
  // Markup carries the wiring the delegated listener reads.
  assert.equal(h.el('quick-scan-btn').dataset.action, 'open-modal');
  assert.equal(h.el('cancel-scan-btn').dataset.action, 'cancel-scan');
  assert.equal(h.el('save-finding-status-btn').dataset.action, 'save-finding-status');
});

test('user navigation moves focus to the page heading, the initial view does not', async () => {
  const h = setup();
  h.invoke('navigate', 'dashboard');
  assert.notEqual(h.el('page-title').focused, true);
  await h.dispatchDocumentEvent('click', { target: actionTarget({ action: 'navigate', view: 'findings' }) });
  assert.equal(h.el('page-title').textContent, 'Findings & remediation');
  assert.equal(h.el('page-title').focused, true);
});

// --- Finding detail ---------------------------------------------------------------------------

test('finding modal shows the summary row at once, then evidence from one detail GET', async () => {
  const detail = { ...clone(fixtures.finding), llm_remediation: clone(fixtures.remediation) };
  const h = setup({ respond: call => ({ body: call.url.endsWith(`/findings/${findingId}`) ? detail : [] }) });
  h.state.findings = [summaryOf(fixtures.finding)];
  const opening = h.invoke('openFindingModal', findingId);
  assert.equal(h.el('finding-modal-title').textContent, fixtures.finding.title);
  assert.equal(h.el('finding-modal-evidence').textContent, 'Loading evidence…');
  await opening;
  onlyCall(h, `${base}/findings/${findingId}`, 'GET');
  assert.match(h.el('finding-modal-evidence').textContent, /TLS 1\.0 accepted/);
  assert.equal(h.state.findings[0].evidence.length, 1);
  assert.equal(h.state.selectedFinding.evidence.length, 1);
  assert.ok(h.el('ai-remediation-body').textContent.includes(fixtures.remediation.summary), 'Cached guidance from the detail is shown');
});

test('a late finding detail for a previously selected finding is ignored', async () => {
  const first = deferred();
  const other = { ...summaryOf(fixtures.finding), id: otherFindingId, title: 'Other finding' };
  const otherDetail = { ...clone(fixtures.finding), id: otherFindingId, title: 'Other finding',
    evidence: [{ ...fixtures.finding.evidence[0], id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', finding_id: otherFindingId, content: 'Other evidence' }] };
  const h = setup({ respond: call => call.url.endsWith(`/findings/${findingId}`) ? first.promise : { body: otherDetail } });
  h.state.findings = [summaryOf(fixtures.finding), other];
  const opening = h.invoke('openFindingModal', findingId);
  await h.settle();
  await h.invoke('openFindingModal', otherFindingId);
  first.resolve({ body: clone(fixtures.finding) });
  await opening;
  assert.equal(h.state.selectedFinding.id, otherFindingId);
  assert.equal(h.el('finding-modal-title').textContent, 'Other finding');
  assert.match(h.el('finding-modal-evidence').textContent, /Other evidence/);
  assert.doesNotMatch(h.el('finding-modal-evidence').textContent, /TLS 1\.0/);
});

test('a failed finding detail keeps the row and says evidence could not be loaded', async () => {
  const h = setup({ respond: () => ({ status: 503, body: { detail: 'Unavailable' } }) });
  h.state.findings = [summaryOf(fixtures.finding)];
  await h.invoke('openFindingModal', findingId);
  assert.equal(h.el('finding-modal-title').textContent, fixtures.finding.title);
  assert.match(h.el('finding-modal-evidence').textContent, /Evidence could not be loaded/);
  assert.equal(h.state.findings[0].title, fixtures.finding.title);
});

// --- Data loading ------------------------------------------------------------------------------

const scanPage = (from, count) => Array.from({ length: count }, (_, index) => ({ ...clone(fixtures.scan), id: `scan-${from + index}` }));

test('collection paging stops after an organization switch', async () => {
  const firstPage = deferred();
  const h = setup({ respond: call => call.url.includes('offset=0') ? firstPage.promise : { body: scanPage(100, 5) } });
  const loading = h.invoke('loadScans');
  await h.settle();
  h.state.activeOrgId = otherFindingId; h.state.orgVersion += 1;
  firstPage.resolve({ body: scanPage(0, 100) });
  await loading;
  assert.equal(h.calls.filter(call => call.url.includes('/scans?')).length, 1, 'No further pages for the old organization');
  assert.equal(h.state.scans.length, 1, 'The old organization rows are not applied');
});

test('duplicate ids across pages collapse and a server ignoring limit cannot loop forever', async () => {
  const h = setup({ respond: call => ({ body: call.url.includes('offset=0') ? scanPage(0, 100) : scanPage(95, 10) }) });
  await h.invoke('loadScans');
  assert.equal(h.state.scans.length, 105);
  assert.equal(new Set(h.state.scans.map(scan => scan.id)).size, 105);
  const ignoring = setup({ respond: () => ({ body: scanPage(0, 100) }) });
  await ignoring.invoke('loadScans');
  assert.equal(ignoring.calls.length, 2, 'A page that adds no new ids ends paging');
  assert.equal(ignoring.state.scans.length, 100);
});

test('authorizations and reports are paginated', async () => {
  const h = setup();
  await h.invoke('loadAuthorizations');
  await h.invoke('loadReports');
  assert.ok(h.calls.some(call => call.url === `${base}/authorizations?limit=100&offset=0`));
  assert.ok(h.calls.some(call => call.url === `${base}/reports?limit=100&offset=0`));
});

test('initialization fetches scan profiles exactly once, and organization changes reuse them', async () => {
  const secondOrg = { ...clone(fixtures.organization), id: otherFindingId, name: 'Second lab' };
  const h = setup({ respond: call => {
    if (call.url.endsWith('/auth/me')) return { body: fixtures.user };
    if (call.url.endsWith('/api/v1/organizations')) return { body: [fixtures.organization, secondOrg] };
    if (call.url.endsWith('/scan-profiles')) return { body: [fixtures.profile] };
    if (call.url.includes('/system/scanner-status')) return { body: { tools: {} } };
    return { body: [] };
  } });
  Object.assign(h.state, { user: null, activeOrgId: null, organizations: [], profiles: [] });
  await h.invoke('initApplication');
  await h.settle();
  assert.equal(h.state.activeOrgId, orgId);
  assert.equal(h.calls.filter(call => call.url.endsWith('/scan-profiles')).length, 1);
  assert.equal(h.state.profiles.length, 1);
  assert.equal(h.el('session-check').classList.contains('hidden'), true);
  assert.equal(h.el('app-shell').classList.contains('hidden'), false);
  assert.equal(h.el('page-title').focused, undefined, 'The initial view does not steal focus');
  await h.invoke('handleOrgChange', secondOrg.id);
  assert.equal(h.calls.filter(call => call.url.endsWith('/scan-profiles')).length, 1);
});

test('rows stay visible while a collection reloads', async () => {
  const reload = deferred();
  const h = setup({ respond: () => reload.promise });
  const loading = h.invoke('loadScans');
  await h.settle();
  assert.match(h.el('scans-tbody').textContent, /Local discovery/);
  assert.doesNotMatch(h.el('scans-tbody').textContent, /Loading/);
  assert.equal(h.el('view-scans').getAttribute('aria-busy'), 'true');
  assert.equal(h.el('stat-scans-count').textContent, '1 / 1');
  reload.resolve({ body: [fixtures.scan] });
  await loading;
  assert.equal(h.el('view-scans').getAttribute('aria-busy'), 'false');
  const empty = setup({ respond: () => deferred().promise });
  empty.state.scans = [];
  empty.invoke('loadScans');
  await empty.settle();
  assert.match(empty.el('scans-tbody').textContent, /Loading…/);
  assert.equal(empty.el('stat-scans-count').textContent, '…');
});

test('auto-refresh does nothing while every scan is terminal', async () => {
  const h = setup({ respond: () => ({ body: [{ ...clone(fixtures.scan), status: 'completed' }] }) });
  await h.invoke('loadScans');
  assert.equal([...h.intervals.values()].some(interval => interval.delay === 20000), false);
});

test('auto-refresh reloads scans while one runs and reloads findings when it finishes', async () => {
  let status = 'running';
  const h = setup({ respond: call => ({ body: call.url.includes('/scans?') ? [{ ...clone(fixtures.scan), status }] : [] }) });
  await h.invoke('loadScans');
  const refresh = [...h.intervals.values()].find(interval => interval.delay === 20000);
  assert.ok(refresh, 'An in-progress scan schedules one 20 s refresh');
  h.document.visibilityState = 'hidden';
  await refresh.callback();
  assert.equal(h.calls.length, 1, 'No refresh while the page is hidden');
  h.document.visibilityState = 'visible';
  status = 'completed';
  await refresh.callback();
  assert.equal(h.calls.filter(call => call.url.includes('/findings?')).length, 1);
  assert.equal(h.calls.filter(call => call.url.includes('/assets?')).length, 1);
  assert.equal([...h.intervals.values()].some(interval => interval.delay === 20000), false, 'Refresh stops once nothing is running');
  h.invoke('clearOrgData');
  assert.equal(h.state.autoRefreshInterval, null);
});

test('error toasts persist with a close button; other toasts expire', async () => {
  const h = setup();
  h.invoke('showToast', 'Broken', 'error');
  assert.equal(h.timeouts.some(timeout => timeout.delay <= 5000), false, 'Error toasts are not removed after 5 s');
  const toast = h.el('toast-container').children[0];
  assert.equal(toast.getAttribute('role'), 'alert');
  const close = toast.children.find(child => child.dataset.action === 'dismiss-toast');
  assert.ok(close, 'Error toasts can be dismissed');
  assert.match(close.getAttribute('aria-label'), /Dismiss/);
  await h.dispatchDocumentEvent('click', { target: close });
  assert.equal(toast.removed, true);
  h.invoke('showToast', 'Saved', 'success');
  assert.ok(h.timeouts.some(timeout => timeout.delay === 5000));
});

// --- Scan monitor ------------------------------------------------------------------------------

test('only one long poll interval runs while the event stream is open', async () => {
  const h = setup({ respond: () => ({ body: fixtures.scan }) });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId);
  await h.settle();
  const delays = [...h.intervals.values()].map(interval => interval.delay);
  assert.equal(longIntervals(h).length, 1);
  assert.equal(delays.includes(3000), false, 'Fast polling is only a fallback');
  await h.eventSources.at(-1).emit('stage_started', { id: 'event-a', event_type: 'stage_started', payload: { stage: 'scanning' } });
  assert.equal(h.calls.length, 1, 'Stream events do not trigger extra polls');
});

test('a CONNECTING stream error lets the browser retry, then falls back after three', async () => {
  const h = setup({ respond: () => ({ body: fixtures.scan }) });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId);
  await h.settle();
  const es = h.eventSources.at(-1);
  await es.fail(0);
  assert.equal(es.closed, false);
  assert.match(h.el('live-scan-console').textContent, /Reconnecting…/);
  await es.fail(0);
  assert.equal(es.closed, false);
  await es.fail(0);
  assert.equal(es.closed, true);
  assert.ok([...h.intervals.values()].some(interval => interval.delay === 3000));
  assert.equal(h.eventSources.length, 1, 'A stream the browser gave up on is not reopened');
});

test('a CLOSED stream falls back to polling and reopens once after a successful poll', async () => {
  const h = setup({ respond: () => ({ body: fixtures.scan }) });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId);
  await h.settle();
  const es = h.eventSources.at(-1);
  await es.fail(2);
  await h.settle();
  assert.equal(es.closed, true);
  assert.equal(h.eventSources.length, 2, 'The stream is reopened after the poll succeeds');
  assert.equal(longIntervals(h).length, 1);
  assert.equal([...h.intervals.values()].some(interval => interval.delay === 3000), false);
  await h.eventSources.at(-1).fail(2);
  await h.settle();
  assert.equal(h.eventSources.length, 2, 'Only one reopen per monitor');
});

test('a polled status is merged into the scans table and dashboard', async () => {
  const h = setup({ respond: () => ({ body: { ...clone(fixtures.scan), status: 'cancel_requested', progress_pct: 60 } }) });
  h.disableRefresh();
  await h.invoke('monitorScan', scanId);
  await h.settle();
  assert.match(h.el('scans-tbody').textContent, /cancel requested/);
  assert.equal(h.state.scans[0].progress_pct, 60);
  assert.equal(h.state.scans.length, 1);
});

test('a finished stream reloads only scans, findings and assets', async () => {
  const h = setup({ respond: () => ({ body: fixtures.scan }) });
  await h.invoke('monitorScan', scanId);
  await h.settle();
  const before = h.calls.length;
  await h.eventSources.at(-1).emit('scan_completed', { id: 'done-1', event_type: 'scan_completed', payload: {} });
  await h.settle();
  const reloaded = h.calls.slice(before).map(call => call.url.split('?')[0].split('/').at(-1)).sort();
  assert.deepEqual(reloaded, ['assets', 'findings', 'scans']);
});

test('a completed scan shows its recorded duration once without a timer', async () => {
  const completed = { ...clone(fixtures.scan), status: 'completed', progress_pct: 100, started_at: '2026-10-02T11:00:00Z', completed_at: '2026-10-02T11:05:30Z' };
  const h = setup({ respond: () => ({ body: completed }) });
  h.disableRefresh();
  h.state.scans = [completed];
  await h.invoke('monitorScan', scanId);
  await h.settle();
  assert.equal(h.el('live-scan-timer').textContent, '05:30');
  assert.equal([...h.intervals.values()].some(interval => interval.delay === 1000), false);
  assert.equal(h.invoke('formatDuration', 3723000), '1:02:03');
});

test('closing the monitor after a poll saw the scan end still reloads findings and assets', async () => {
  const running = { ...clone(fixtures.scan), status: 'running', started_at: '2026-10-02T11:00:00Z' };
  const h = setup({ respond: call => ({ body: call.url.split('?')[0].endsWith(`/scans/${scanId}`) ? { ...running, status: 'completed', completed_at: '2026-10-02T11:01:00Z' } : [] }) });
  h.state.scans = [running];
  await h.invoke('monitorScan', scanId);
  await h.settle();
  assert.equal(h.state.scans[0].status, 'completed', 'The poll merged the terminal status while the stream is still open');
  const before = h.calls.length;
  await h.dispatchDocumentEvent('click', { target: actionTarget({ action: 'close-monitor' }), button: 0, preventDefault() {} });
  await h.settle();
  const reloaded = h.calls.slice(before).map(call => call.url.split('?')[0].split('/').at(-1)).sort();
  assert.deepEqual(reloaded, ['assets', 'findings']);
});

test('a failed scan without an end time says Failed instead of a blank duration', async () => {
  const failed = { ...clone(fixtures.scan), status: 'failed', started_at: '2026-10-02T11:00:00Z', completed_at: null, cancelled_at: null, timed_out_at: null };
  const h = setup({ respond: () => ({ body: failed }) });
  h.disableRefresh();
  h.state.scans = [failed];
  await h.invoke('monitorScan', scanId);
  await h.settle();
  assert.equal(h.el('live-scan-timer').textContent, 'Failed');
});

test('a stream that ends before any poll settles the timer from the reloaded scan', async () => {
  const running = { ...clone(fixtures.scan), status: 'running', started_at: '2026-10-02T11:00:00Z' };
  const completed = { ...running, status: 'completed', progress_pct: 100, completed_at: '2026-10-02T11:02:05Z' };
  let finished = false;
  const h = setup({ respond: call => {
    const path = call.url.split('?')[0];
    if (path.endsWith('/scans')) return { body: finished ? [completed] : [running] };
    if (path.endsWith(`/scans/${scanId}`)) return { body: finished ? completed : running };
    return { body: [] };
  } });
  h.state.scans = [running];
  await h.invoke('monitorScan', scanId);
  await h.settle();
  finished = true;
  await h.eventSources.at(-1).emit('scan_completed', { id: 'done-1', event_type: 'scan_completed', payload: {} });
  await h.settle();
  assert.equal(h.el('live-scan-timer').textContent, '02:05');
  assert.equal([...h.intervals.values()].some(interval => interval.delay === 1000), false);
});

test('a queued scan shows Queued until a poll reports started_at', async () => {
  const queued = { ...clone(fixtures.scan), status: 'queued', started_at: null, progress_pct: 0 };
  const h = setup({ respond: () => ({ body: { ...queued, status: 'running', started_at: '2026-10-02T11:00:00Z' } }) });
  h.disableRefresh();
  h.state.scans = [queued];
  h.invoke('monitorScan', scanId);
  assert.equal(h.el('live-scan-timer').textContent, 'Queued');
  assert.equal(h.state.liveScanStartTime, null);
  await h.settle();
  assert.equal(h.state.liveScanStartTime, Date.parse('2026-10-02T11:00:00Z'));
  assert.ok([...h.intervals.values()].some(interval => interval.delay === 1000));
});

// --- Authorizations ----------------------------------------------------------------------------

test('an administrator revokes an authorization after confirming', async () => {
  const authId = fixtures.authorization.id;
  const h = setup({ respond: call => ({ body: call.method === 'DELETE' ? { ...fixtures.authorization, is_revoked: true, is_valid: false } : [] }) });
  h.state.user.memberships[0].role = 'admin';
  h.invoke('renderAuthorizations');
  const html = h.el('authorizations-tbody').innerHTML;
  assert.match(html, new RegExp(`data-action="revoke-auth" data-id="${authId}" aria-label="Revoke authorization Local lab scope"`));
  await h.dispatchDocumentEvent('click', { target: actionTarget({ action: 'revoke-auth', id: authId }) });
  assert.equal(h.confirmations.length, 1);
  assert.match(h.confirmations[0], /Local lab scope/);
  assert.match(h.confirmations[0], /blocked/);
  assert.match(h.confirmations[0], /cancelled/);
  onlyCall(h, `${base}/authorizations/${authId}`, 'DELETE');
  assert.ok(h.calls.some(call => call.method === 'GET' && call.url.startsWith(`${base}/authorizations?`)), 'Authorizations reload');
  assert.ok(h.calls.some(call => call.method === 'GET' && call.url.startsWith(`${base}/scans?`)), 'Scans reload');
});

test('revocation is not sent when the confirmation is declined', async () => {
  const h = setup({ confirm: () => false });
  h.state.user.memberships[0].role = 'admin';
  await h.invoke('revokeAuthorization', fixtures.authorization.id);
  assert.equal(h.confirmations.length, 1);
  assert.equal(h.calls.length, 0);
});

for (const role of ['viewer', 'analyst']) {
  test(`${role}s see no revoke button`, () => {
    const h = setup();
    h.state.user.memberships[0].role = role;
    h.invoke('renderAuthorizations');
    assert.doesNotMatch(h.el('authorizations-tbody').innerHTML, /revoke-auth/);
  });
}

test('the scan dialog lists approved targets and can fill them in', async () => {
  const h = setup();
  h.invoke('renderAuthorizations');
  assert.equal(h.el('scan-approved-targets').classList.contains('hidden'), true);
  h.el('scan-auth-select').value = fixtures.authorization.id;
  await h.dispatchDocumentEvent('change', { target: h.el('scan-auth-select') });
  assert.equal(h.el('scan-approved-targets').classList.contains('hidden'), false);
  assert.match(h.el('scan-approved-targets-list').textContent, /127\.0\.0\.1/);
  await h.dispatchDocumentEvent('click', { target: h.el('use-approved-targets-btn') });
  assert.equal(h.el('scan-targets-input').value, '127.0.0.1');
  assert.match(indexHtml, /50 targets per scan/);
});

test('a single valid authorization is preselected in the scan dialog', () => {
  const h = setup();
  h.invoke('renderAuthorizations');
  h.invoke('openNewScanModal');
  assert.equal(h.el('new-scan-modal').classList.contains('hidden'), false);
  assert.equal(h.el('scan-auth-select').value, fixtures.authorization.id);
  assert.match(h.el('scan-approved-targets-list').textContent, /127\.0\.0\.1/);
});

// --- Accessibility -----------------------------------------------------------------------------

test('row buttons name the item they act on', () => {
  const h = setup();
  h.state.reports = [clone(fixtures.report)];
  h.invoke('renderAll');
  assert.match(h.el('findings-tbody').innerHTML, /aria-label="Details for Legacy TLS enabled"/);
  assert.match(h.el('dashboard-top-findings').innerHTML, /aria-label="Inspect details for Legacy TLS enabled"/);
  assert.match(h.el('scans-tbody').innerHTML, /aria-label="Monitor scan 66666666"/);
  assert.match(h.el('reports-tbody').innerHTML, /aria-label="View report Local lab technical assessment/);
});

test('role-disabled controls explain the role they need', () => {
  const h = setup();
  h.state.user.memberships[0].role = 'viewer';
  h.invoke('applyPermissions');
  assert.equal(h.el('quick-scan-btn').disabled, true);
  assert.equal(h.el('quick-scan-btn').getAttribute('title'), 'Requires analyst role');
  assert.equal(h.el('fetch-ai-fix-btn').getAttribute('title'), 'Requires analyst role');
  h.state.user.memberships[0].role = 'analyst';
  h.invoke('applyPermissions');
  assert.equal(h.el('quick-scan-btn').disabled, false);
  assert.equal(h.el('quick-scan-btn').getAttribute('title'), null);
});

test('View HTML renews an expired access cookie before the report tab navigates', async () => {
  const reportPath = `${base}/reports/${fixtures.report.id}`;
  let reportGets = 0;
  const h = setup({
    respond: call => {
      if (call.url.endsWith('/auth/refresh')) return { body: { ok: true } };
      if (call.url === reportPath && call.method === 'GET') return ++reportGets === 1 ? { status: 401, body: { detail: 'expired' } } : { body: fixtures.report };
      return { body: [] };
    },
  });
  h.state.reports = [clone(fixtures.report)];
  h.invoke('renderReports');
  assert.match(h.el('reports-tbody').innerHTML, new RegExp(`data-action="open-report" data-id="${fixtures.report.id}"`));
  let prevented = false;
  await h.dispatchDocumentEvent('click', { target: actionTarget({ action: 'open-report', id: fixtures.report.id }), button: 0, preventDefault() { prevented = true; } });
  await h.settle();
  assert.ok(prevented, 'A primary click is handled by the console, not the bare href');
  assert.deepEqual(h.calls.map(call => `${call.method} ${call.url}`), [`GET ${reportPath}`, 'POST /api/v1/auth/refresh', `GET ${reportPath}`]);
  assert.equal(h.opened.length, 1, 'The tab is opened once, inside the click');
  assert.deepEqual(h.opened[0].args, ['', '_blank']);
  assert.equal(h.opened[0].tab.opener, null, 'The report tab cannot script the console');
  assert.equal(h.opened[0].tab.location, `${reportPath}/html`, 'The tab navigates only after the session is fresh');
  assert.equal(h.opened[0].tab.closed, false);
});

test('View HTML closes the pending tab when the session cannot be renewed', async () => {
  const h = setup({ respond: call => call.url.endsWith('/auth/refresh') || call.url.includes('/reports/') ? { status: 401, body: { detail: 'expired' } } : { body: [] } });
  await h.dispatchDocumentEvent('click', { target: actionTarget({ action: 'open-report', id: fixtures.report.id }), button: 0, preventDefault() {} });
  await h.settle();
  assert.equal(h.opened.length, 1);
  assert.equal(h.opened[0].tab.closed, true, 'No tab is left showing a raw 401 page');
  assert.equal(h.opened[0].tab.location, undefined);
  assert.equal(h.el('auth-modal').classList.contains('hidden'), false, 'The user is asked to sign in again');
});

test('View HTML falls back to a noopener window when the pre-opened tab was blocked, and leaves modified clicks alone', async () => {
  const h = setup({ respond: call => call.url.endsWith(`/reports/${fixtures.report.id}`) ? { body: fixtures.report } : { body: [] }, open: () => null });
  let prevented = false;
  await h.dispatchDocumentEvent('click', { target: actionTarget({ action: 'open-report', id: fixtures.report.id }), button: 1, preventDefault() { prevented = true; } });
  await h.dispatchDocumentEvent('click', { target: actionTarget({ action: 'open-report', id: fixtures.report.id }), button: 0, ctrlKey: true, preventDefault() { prevented = true; } });
  assert.equal(prevented, false, 'Middle and modified clicks use the browser default on the real href');
  assert.equal(h.calls.length, 0);
  await h.dispatchDocumentEvent('click', { target: actionTarget({ action: 'open-report', id: fixtures.report.id }), button: 0, preventDefault() {} });
  await h.settle();
  assert.deepEqual(h.opened.map(entry => entry.args), [['', '_blank'], [`${base}/reports/${fixtures.report.id}/html`, '_blank', 'noopener']]);
});
