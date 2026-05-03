// CSP web client — talks to /api on the same origin (proxied by nginx).

const API = '/api';
const TOKEN_KEY = 'csp_token';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function token() { return localStorage.getItem(TOKEN_KEY); }
function setToken(t) { localStorage.setItem(TOKEN_KEY, t); }
function clearToken() { localStorage.removeItem(TOKEN_KEY); }

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token() ? { authorization: 'Bearer ' + token() } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    clearToken();
    showLogin();
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    const j = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(j.error || 'request failed');
  }
  return res.json();
}

function showLogin() {
  $('#loginView').classList.remove('hidden');
  $('#appView').classList.add('hidden');
  $('#userBadge').classList.add('hidden');
}
function showApp(user) {
  $('#loginView').classList.add('hidden');
  $('#appView').classList.remove('hidden');
  $('#userBadge').classList.remove('hidden');
  $('#userBadge').innerHTML = `${user.username} <span class="muted">(${user.role})</span> <button id="logoutBtn">logout</button>`;
  $('#logoutBtn').onclick = () => { clearToken(); showLogin(); };
  refreshLibrary();
}

async function bootstrap() {
  if (!token()) return showLogin();
  try {
    const me = await api('/auth/me');
    showApp(me.user);
  } catch {
    showLogin();
  }
}

// --- Login ---
$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#loginError').textContent = '';
  const fd = new FormData(e.target);
  try {
    const res = await api('/auth/login', {
      method: 'POST',
      body: { username: fd.get('username'), password: fd.get('password') },
    });
    setToken(res.token);
    showApp(res.user);
  } catch (err) {
    $('#loginError').textContent = err.message;
  }
});

// --- Tabs ---
$$('.tab').forEach(t => {
  t.onclick = () => {
    $$('.tab').forEach(x => x.classList.remove('active'));
    $$('.tab-panel').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $(`.tab-panel[data-panel="${t.dataset.tab}"]`).classList.add('active');
    if (t.dataset.tab === 'mutate' || t.dataset.tab === 'library') refreshLibrary();
    if (t.dataset.tab === 'attack') { loadCatalog(); refreshRuns(); }
    if (t.dataset.tab === 'agents') { refreshAgents(); refreshAgentTasks(); ensureCatalogLoadedForAgents(); }
  };
});

// --- Generate ---
$('#generateForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  $('#generateResult').textContent = '...';
  try {
    const res = await api('/files/generate', {
      method: 'POST',
      body: { file_type: fd.get('file_type'), note: fd.get('note') || null },
    });
    $('#generateResult').textContent = JSON.stringify(res, null, 2);
    refreshLibrary();
  } catch (err) {
    $('#generateResult').textContent = 'ERR: ' + err.message;
  }
});

// --- Mutate ---
async function refreshArtifactSelect() {
  try {
    const res = await api('/files/');
    const sel = $('#mutateArtifact');
    sel.innerHTML = '';
    for (const a of res.artifacts) {
      const o = document.createElement('option');
      o.value = a.id;
      o.textContent = `${a.file_type} ${a.size}B ${a.sha256.slice(0, 12)} (${a.source_op})`;
      sel.appendChild(o);
    }
  } catch (err) {
    console.error(err);
  }
}

$('#mutateForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const id = fd.get('artifact_id');
  if (!id) { $('#mutateResult').textContent = 'pick an artifact'; return; }
  $('#mutateResult').textContent = '...';
  const body = { operation: fd.get('operation'), algo: fd.get('algo') };
  if (body.operation === 'append_random') body.n = Number(fd.get('n')) || 32;
  if (body.operation === 'pad') body.target_length = Number(fd.get('target_length'));
  if (body.operation === 'until_prefix') body.target_prefix = fd.get('target_prefix');
  try {
    const res = await api(`/files/${id}/mutate`, { method: 'POST', body });
    $('#mutateResult').textContent = JSON.stringify(res, null, 2);
    refreshLibrary();
  } catch (err) {
    $('#mutateResult').textContent = 'ERR: ' + err.message;
  }
});

// --- Convert ---
$('#convertForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  $('#convertResult').textContent = '...';
  try {
    const res = await api('/files/convert', {
      method: 'POST',
      body: {
        target: fd.get('target'),
        mode: fd.get('mode'),
        pdf_text: fd.get('pdf_text') || null,
      },
    });
    $('#convertResult').textContent = JSON.stringify(res, null, 2);
    refreshLibrary();
  } catch (err) {
    $('#convertResult').textContent = 'ERR: ' + err.message;
  }
});

// --- Library ---
$('#refreshLibrary').addEventListener('click', refreshLibrary);

async function refreshLibrary() {
  try {
    const res = await api('/files/');
    const tbody = $('#libraryTable tbody');
    tbody.innerHTML = '';
    for (const a of res.artifacts) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${a.created_at}</td>
        <td>${a.file_type}</td>
        <td>${a.source_op}</td>
        <td>${a.size}</td>
        <td><code>${a.sha256.slice(0, 24)}…</code></td>
        <td><a href="${API}/files/${a.id}/download?_t=${token()}" target="_blank" data-id="${a.id}">download</a></td>
      `;
      tbody.appendChild(tr);
    }
    // Add auth header to download links via fetch+blob
    $$('a[data-id]', tbody).forEach(a => {
      a.removeAttribute('href');
      a.style.cursor = 'pointer';
      a.onclick = (e) => { e.preventDefault(); downloadArtifact(a.dataset.id); };
    });
    refreshArtifactSelect();
  } catch (err) {
    console.error(err);
  }
}

// --- ATT&CK ---
let CATALOG = [];
let SELECTED_TECH = null;

async function loadCatalog() {
  if (CATALOG.length) { renderCatalog(); return; }
  try {
    const data = await api('/techniques/');
    CATALOG = data.techniques || [];
    renderCatalog();
  } catch (err) {
    $('#attackTechniques').innerHTML = `<li>error: ${err.message}</li>`;
  }
}

function renderCatalog() {
  const filter = ($('#attackFilter').value || '').toLowerCase();
  const ul = $('#attackTechniques');
  ul.innerHTML = '';
  for (const t of CATALOG) {
    const blob = (t.id + ' ' + t.name + ' ' + t.tactic).toLowerCase();
    if (filter && !blob.includes(filter)) continue;
    const li = document.createElement('li');
    if (SELECTED_TECH && SELECTED_TECH.id === t.id) li.classList.add('active');
    li.innerHTML = `<span class="tid">${t.id}</span>${t.name}<span class="tac">${t.tactic}</span>`;
    li.onclick = () => { SELECTED_TECH = t; renderCatalog(); renderDetail(t); };
    ul.appendChild(li);
  }
}

function renderDetail(t) {
  const d = $('#attackDetail');
  d.innerHTML = `
    <h4>${t.id} — ${t.name}</h4>
    <div class="muted">${t.tactic} · ${t.platforms.join(', ')}</div>
    <p>${t.description}</p>
    ${t.tests.map(tt => `
      <div class="test" data-test="${encodeURIComponent(tt.name)}">
        <div class="test-head">
          <span class="test-name">${tt.name}</span>
          <span>
            <span class="badge">${tt.executor}</span>
            <span class="badge">${tt.platforms.join(',')}</span>
            ${tt.runnable_here ? '<span class="badge runnable">runnable here</span>' : ''}
          </span>
        </div>
        <div class="muted">${tt.description}</div>
        <code>${escapeHtml(tt.command)}</code>
        <div class="muted">Expected signals:</div>
        <ul class="muted">${tt.expected_signals.map(s => `<li>${escapeHtml(s)}</li>`).join('') || '<li>(none)</li>'}</ul>
        <div class="actions">
          ${tt.runnable_here ? `<button data-action="run" data-tech="${t.id}" data-test="${tt.name}">Run on worker</button>` : ''}
          <button class="secondary" data-action="script" data-tech="${t.id}" data-test="${tt.name}">Download script</button>
        </div>
      </div>
    `).join('')}
  `;
  d.querySelectorAll('button[data-action]').forEach(b => {
    b.onclick = () => {
      const action = b.dataset.action;
      if (action === 'run') runTechnique(b.dataset.tech, b.dataset.test);
      else if (action === 'script') downloadScript(b.dataset.tech, b.dataset.test);
    };
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function runTechnique(techId, testName) {
  $('#attackResult').textContent = `running ${techId} / ${testName} ...`;
  try {
    const res = await api(`/techniques/${encodeURIComponent(techId)}/run`, {
      method: 'POST', body: { test_name: testName },
    });
    $('#attackResult').textContent = JSON.stringify({
      run_id: res.run_id,
      exit_code: res.exit_code,
      duration_ms: res.duration_ms,
      command: res.command,
      stdout: res.stdout,
      stderr: res.stderr,
    }, null, 2);
    refreshRuns();
  } catch (err) {
    $('#attackResult').textContent = 'ERR: ' + err.message;
  }
}

async function downloadScript(techId, testName) {
  try {
    const res = await api(`/techniques/${encodeURIComponent(techId)}/script`, {
      method: 'POST', body: { test_name: testName },
    });
    const bin = Uint8Array.from(atob(res.data_b64), c => c.charCodeAt(0));
    const blob = new Blob([bin], { type: res.mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = res.filename; a.click();
    URL.revokeObjectURL(url);
    $('#attackResult').textContent = `downloaded ${res.filename} (${res.size} bytes)`;
  } catch (err) {
    $('#attackResult').textContent = 'ERR: ' + err.message;
  }
}

async function refreshRuns() {
  try {
    const res = await api('/runs/');
    const tbody = $('#runsTable tbody');
    tbody.innerHTML = '';
    for (const r of res.runs) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${r.created_at}</td>
        <td>${r.technique_id}</td>
        <td>${r.test_name}</td>
        <td>${r.exit_code}</td>
        <td>${r.duration_ms}</td>
        <td><button data-id="${r.id}">view</button></td>
      `;
      tr.querySelector('button').onclick = () => viewRun(r.id);
      tbody.appendChild(tr);
    }
  } catch (err) {
    console.error(err);
  }
}

async function viewRun(id) {
  try {
    const r = await api(`/runs/${id}`);
    $('#attackResult').textContent = JSON.stringify(r, null, 2);
  } catch (err) {
    $('#attackResult').textContent = 'ERR: ' + err.message;
  }
}

document.addEventListener('input', (e) => {
  if (e.target && e.target.id === 'attackFilter') renderCatalog();
});

// --- Agents ---
async function refreshAgents() {
  try {
    const data = await api('/agents/');
    const tbody = $('#agentsTable tbody');
    const sel = $('#taskAgentSelect');
    tbody.innerHTML = '';
    sel.innerHTML = '';
    for (const a of data.agents) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${a.created_at}</td>
        <td><code>${a.id}</code></td>
        <td>${a.hostname || '-'}</td>
        <td>${a.platform}</td>
        <td>${a.last_seen || '-'}</td>
        <td>${a.beacon_count}</td>
        <td>${a.status}</td>
        <td>${a.status === 'active' ? `<button data-kill="${a.id}">kill</button>` : ''}</td>
      `;
      const killBtn = tr.querySelector('button[data-kill]');
      if (killBtn) killBtn.onclick = () => killAgent(a.id);
      tbody.appendChild(tr);

      if (a.status === 'active') {
        const o = document.createElement('option');
        o.value = a.id;
        o.textContent = `${a.hostname || a.id} · ${a.platform}`;
        o.dataset.platform = a.platform;
        sel.appendChild(o);
      }
    }
    repopulateTaskTechSelect();
  } catch (err) { console.error(err); }
}

async function killAgent(id) {
  if (!confirm(`kill agent ${id}?`)) return;
  try {
    await api(`/agents/${id}/kill`, { method: 'POST' });
    refreshAgents();
  } catch (err) {
    alert('kill failed: ' + err.message);
  }
}

$('#newEnrollToken').addEventListener('click', async () => {
  try {
    const res = await api('/agents/enroll-token', { method: 'POST', body: { label: 'web-ui' } });
    $('#enrollTokenView').textContent =
      `${res.token}  (expires ${res.expires_at} UTC)`;
  } catch (err) {
    $('#enrollTokenView').textContent = 'ERR: ' + err.message;
  }
});

async function ensureCatalogLoadedForAgents() {
  if (!CATALOG.length) {
    await loadCatalog();
  }
  repopulateTaskTechSelect();
}

function repopulateTaskTechSelect() {
  const sel = $('#taskTechSelect');
  const opt = $('#taskAgentSelect').selectedOptions[0];
  const platform = opt ? opt.dataset.platform : null;
  sel.innerHTML = '';
  for (const t of CATALOG) {
    if (platform && !t.platforms.includes(platform)) continue;
    const o = document.createElement('option');
    o.value = t.id;
    o.textContent = `${t.id} ${t.name}`;
    sel.appendChild(o);
  }
  repopulateTaskTestSelect();
}

function repopulateTaskTestSelect() {
  const techId = $('#taskTechSelect').value;
  const tech = CATALOG.find(t => t.id === techId);
  const sel = $('#taskTestSelect');
  const opt = $('#taskAgentSelect').selectedOptions[0];
  const platform = opt ? opt.dataset.platform : null;
  sel.innerHTML = '';
  if (!tech) return;
  for (const tt of tech.tests) {
    if (platform && !tt.platforms.includes(platform)) continue;
    const o = document.createElement('option');
    o.value = tt.name;
    o.textContent = `${tt.name} (${tt.executor})`;
    sel.appendChild(o);
  }
}

document.addEventListener('change', (e) => {
  if (e.target && e.target.id === 'taskAgentSelect') repopulateTaskTechSelect();
  if (e.target && e.target.id === 'taskTechSelect')  repopulateTaskTestSelect();
});

$('#queueTaskForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const agentId = fd.get('agent_id');
  if (!agentId) { $('#agentResult').textContent = 'pick an agent'; return; }
  try {
    const res = await api(`/agents/${agentId}/tasks`, {
      method: 'POST',
      body: {
        technique_id: fd.get('technique_id'),
        test_name: fd.get('test_name'),
        timeout_sec: Number(fd.get('timeout_sec')) || 15,
      },
    });
    $('#agentResult').textContent = JSON.stringify(res, null, 2);
    refreshAgentTasks();
  } catch (err) {
    $('#agentResult').textContent = 'ERR: ' + err.message;
  }
});

async function refreshAgentTasks() {
  try {
    const data = await api('/agents/');
    const tbody = $('#agentTasksTable tbody');
    tbody.innerHTML = '';
    for (const a of data.agents) {
      const tasks = await api(`/agents/${a.id}/tasks`);
      for (const t of tasks.tasks.slice(0, 10)) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${t.created_at}</td>
          <td><code>${a.hostname || a.id}</code></td>
          <td>${t.technique_id}</td>
          <td>${t.test_name}</td>
          <td>${t.status}</td>
          <td>${t.exit_code ?? ''}</td>
          <td>${t.duration_ms ?? ''}</td>
          <td><button data-task="${t.id}">view</button></td>
        `;
        tr.querySelector('button').onclick = () => viewAgentTask(t.id);
        tbody.appendChild(tr);
      }
    }
  } catch (err) { console.error(err); }
}

async function viewAgentTask(id) {
  try {
    const t = await api(`/agents/tasks/${id}`);
    $('#agentResult').textContent = JSON.stringify(t, null, 2);
  } catch (err) {
    $('#agentResult').textContent = 'ERR: ' + err.message;
  }
}

const AGENT_SOURCE_PATHS = {
  python: '/agent/python/csp_agent.py',
  powershell: '/agent/powershell/csp-agent.ps1',
  csharp: '/agent/csharp/CspAgent.cs',
};
$$('a[data-agent-src]').forEach(a => {
  a.onclick = (e) => {
    e.preventDefault();
    alert(`Agent source path in the repo:\n${AGENT_SOURCE_PATHS[a.dataset.agentSrc]}\n\nClone the repo or copy the file to your test endpoint, then run with the enroll token shown above.`);
  };
});

async function downloadArtifact(id) {
  const res = await fetch(`${API}/files/${id}/download`, {
    headers: { authorization: 'Bearer ' + token() },
  });
  if (!res.ok) { alert('download failed'); return; }
  const blob = await res.blob();
  const cd = res.headers.get('content-disposition') || '';
  const m = cd.match(/filename="(.+)"/);
  const name = m ? m[1] : `${id}.bin`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

bootstrap();
