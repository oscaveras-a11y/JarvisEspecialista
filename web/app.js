// CYBER CORE — protótipo de interface (frontend-only).
// Nenhuma chamada de rede, nenhuma execução real do CORE. Estado fica em
// localStorage, só neste navegador. Isso é intencional: ver o banner no
// index.html para o porquê.
'use strict';

const STORE_KEY = 'cybercore.ui.v1';

const DEFAULT_STATE = { cases: [], tasks: [], audit: [], activeCase: null };

function loadState() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return structuredClone(DEFAULT_STATE);
    const parsed = JSON.parse(raw);
    return { ...structuredClone(DEFAULT_STATE), ...parsed };
  } catch {
    return structuredClone(DEFAULT_STATE);
  }
}

function saveState() {
  localStorage.setItem(STORE_KEY, JSON.stringify(state));
}

let state = loadState();

function uid() {
  return crypto.getRandomValues(new Uint32Array(4)).join('').slice(0, 32);
}

function nowIso() {
  return new Date().toISOString();
}

// ---------- hash-chained audit trail (same principle as memory.audit()) ----------
async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function appendAudit(caseId, event, data) {
  const chain = state.audit.filter(e => e.case_id === caseId);
  const previous = chain.length ? chain[chain.length - 1].digest : '0'.repeat(64);
  const created = nowIso();
  const payload = JSON.stringify(data ?? {});
  const digest = await sha256Hex(JSON.stringify([caseId, event, payload, created, previous]));
  state.audit.push({ id: uid(), case_id: caseId, event, data: payload, created, previous, digest });
  saveState();
}

async function verifyChain(caseId) {
  const chain = state.audit.filter(e => e.case_id === caseId).sort((a, b) => a.created.localeCompare(b.created));
  let previous = '0'.repeat(64);
  for (const entry of chain) {
    const expected = await sha256Hex(JSON.stringify([entry.case_id, entry.event, entry.data, entry.created, previous]));
    if (expected !== entry.digest) return false;
    previous = entry.digest;
  }
  return true;
}

// ---------- toasts ----------
function toast(message, kind = 'info') {
  const stack = document.getElementById('toast-stack');
  const el = document.createElement('div');
  el.className = 'toast' + (kind === 'danger' ? ' toast-danger' : '');
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ---------- navigation ----------
const VIEWS = ['dashboard', 'new', 'investigations', 'tasks', 'logs', 'reports'];
const VIEW_TITLES = {
  dashboard: 'Painel', new: 'Nova investigação', investigations: 'Investigações',
  tasks: 'Tarefas & progresso', logs: 'Logs & hipóteses', reports: 'Relatórios',
};

function showView(view) {
  for (const v of VIEWS) {
    document.getElementById('view-' + v).hidden = v !== view;
  }
  for (const btn of document.querySelectorAll('.nav-item')) {
    btn.classList.toggle('is-active', btn.dataset.view === view);
  }
  document.getElementById('view-title').textContent = VIEW_TITLES[view];
  render();
}

// ---------- case helpers ----------
function getCase(id) {
  return state.cases.find(c => c.id === id) || null;
}

function eventDotClass(event) {
  if (event.includes('cancel')) return 'is-danger';
  if (event.includes('pause')) return 'is-warn';
  if (event.includes('resume') || event.includes('created')) return 'is-ok';
  return 'is-accent';
}

function stateBadge(c) {
  if (c.state === 'CANCELADO') return '<span class="badge badge-cancelled">cancelado</span>';
  if (c.paused) return '<span class="badge badge-paused">pausado</span>';
  return '<span class="badge badge-active">em investigação</span>';
}

// ---------- rendering ----------
function populateCaseSelect() {
  const select = document.getElementById('case-select');
  const current = select.value;
  select.innerHTML = '<option value="">Nenhuma investigação selecionada</option>' +
    state.cases.map(c => `<option value="${c.id}">${escapeHtml(c.project)} — ${c.id.slice(0, 8)}</option>`).join('');
  select.value = state.activeCase && getCase(state.activeCase) ? state.activeCase : (current || '');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

function renderDashboard() {
  document.getElementById('stat-total').textContent = state.cases.length;
  document.getElementById('stat-active').textContent = state.cases.filter(c => c.state !== 'CANCELADO' && !c.paused).length;
  document.getElementById('stat-paused').textContent = state.cases.filter(c => c.paused && c.state !== 'CANCELADO').length;
  document.getElementById('stat-cancelled').textContent = state.cases.filter(c => c.state === 'CANCELADO').length;

  const recent = document.getElementById('dashboard-recent');
  const items = [...state.cases].sort((a, b) => b.created.localeCompare(a.created)).slice(0, 5);
  recent.innerHTML = items.length ? items.map(c => `
    <div class="item">
      <div class="item-main">
        <div class="item-title">${escapeHtml(c.project)}</div>
        <div class="item-sub">${c.id.slice(0, 8)} · criado ${new Date(c.created).toLocaleString('pt-BR')}</div>
      </div>
      ${stateBadge(c)}
    </div>`).join('') : '<div class="empty">Nenhuma investigação ainda — crie a primeira.</div>';

  const activity = document.getElementById('dashboard-activity');
  const events = [...state.audit].sort((a, b) => b.created.localeCompare(a.created)).slice(0, 5);
  activity.innerHTML = events.length ? events.map(e => `
    <div class="item">
      <div class="item-main">
        <span class="feed-dot ${eventDotClass(e.event)}"></span>
        <div>
          <div class="item-title">${escapeHtml(e.event)}</div>
          <div class="item-sub">${new Date(e.created).toLocaleString('pt-BR')}</div>
        </div>
      </div>
    </div>`).join('') : '<div class="empty">Sem atividade registrada ainda.</div>';
}

function renderInvestigations() {
  const el = document.getElementById('investigations-table');
  if (!state.cases.length) {
    el.innerHTML = '<div class="empty">Nenhuma investigação criada ainda.</div>';
    return;
  }
  const rows = [...state.cases].sort((a, b) => b.created.localeCompare(a.created)).map(c => `
    <tr data-id="${c.id}">
      <td><strong>${escapeHtml(c.project)}</strong><br><span class="item-sub">${c.id.slice(0, 8)}</span></td>
      <td>${stateBadge(c)}</td>
      <td>${escapeHtml(c.owner)}</td>
      <td>${new Date(c.created).toLocaleString('pt-BR')}</td>
      <td class="actions">
        <button class="btn btn-sm" data-act="select">selecionar</button>
        ${c.state !== 'CANCELADO' ? (c.paused
          ? '<button class="btn btn-sm" data-act="resume">retomar</button>'
          : '<button class="btn btn-sm" data-act="pause">pausar</button>') : ''}
        ${c.state !== 'CANCELADO' ? '<button class="btn btn-sm btn-danger" data-act="cancel">cancelar</button>' : ''}
      </td>
    </tr>`).join('');
  el.innerHTML = `<table>
    <thead><tr><th>Projeto</th><th>Estado</th><th>Responsável</th><th>Criado</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderTasks() {
  const list = document.getElementById('tasks-list');
  const caseId = state.activeCase;
  if (!caseId) {
    list.innerHTML = '<div class="empty">Selecione uma investigação no topo da página.</div>';
    return;
  }
  const items = state.tasks.filter(t => t.case_id === caseId).sort((a, b) => b.created.localeCompare(a.created));
  list.innerHTML = items.length ? items.map(t => `
    <div class="item">
      <div class="item-main">
        <div class="item-title">${escapeHtml(t.tool)} <span class="item-sub">${escapeHtml(t.path)}</span></div>
        <div class="item-sub">enfileirada ${new Date(t.created).toLocaleString('pt-BR')}</div>
      </div>
      <span class="badge badge-pending">${t.status}</span>
    </div>`).join('') : '<div class="empty">Nenhuma tarefa enfileirada para esta investigação.</div>';
}

async function renderLogs() {
  const caseId = state.activeCase;
  const listEl = document.getElementById('logs-list');
  const statusEl = document.getElementById('chain-status');
  if (!caseId) {
    listEl.innerHTML = '<div class="empty">Selecione uma investigação no topo da página.</div>';
    statusEl.textContent = '';
    statusEl.className = 'chain-status';
    return;
  }
  const chain = state.audit.filter(e => e.case_id === caseId).sort((a, b) => a.created.localeCompare(b.created));
  listEl.innerHTML = chain.length ? chain.slice().reverse().map(e => `
    <div class="item">
      <div class="item-main">
        <span class="feed-dot ${eventDotClass(e.event)}"></span>
        <div>
          <div class="item-title">${escapeHtml(e.event)}</div>
          <div class="item-sub">${new Date(e.created).toLocaleString('pt-BR')} · digest ${e.digest.slice(0, 16)}…</div>
        </div>
      </div>
    </div>`).join('') : '<div class="empty">Sem eventos registrados ainda.</div>';

  const valid = chain.length ? await verifyChain(caseId) : null;
  if (valid === null) {
    statusEl.textContent = '';
    statusEl.className = 'chain-status';
  } else {
    statusEl.textContent = valid ? '✓ cadeia de hash íntegra' : '✗ cadeia de hash quebrada — algo foi alterado';
    statusEl.className = 'chain-status ' + (valid ? 'ok' : 'bad');
  }
}

function renderReports() {
  const caseId = state.activeCase;
  const el = document.getElementById('report-preview');
  const c = caseId ? getCase(caseId) : null;
  if (!c) {
    el.textContent = 'Selecione uma investigação no topo da página para pré-visualizar o relatório.';
    return;
  }
  el.textContent = buildReportMarkdown(c);
}

function buildReportMarkdown(c) {
  const tasks = state.tasks.filter(t => t.case_id === c.id);
  const audit = state.audit.filter(e => e.case_id === c.id);
  const lines = [
    `# Relatório — ${c.project}`,
    '',
    `- **ID da investigação:** ${c.id}`,
    `- **Responsável:** ${c.owner}`,
    `- **Autorização:** ${c.authorization}`,
    `- **Escopo:** ${c.scope}`,
    `- **Estado:** ${c.state}${c.paused ? ' (pausada)' : ''}`,
    `- **Criado em:** ${c.created}`,
    '',
    '## Objetivo',
    c.objective,
    '',
    '## Tarefas enfileiradas',
    tasks.length ? tasks.map(t => `- \`${t.tool}\` → ${t.path} (${t.status})`).join('\n') : '_nenhuma tarefa enfileirada_',
    '',
    '## Trilha de auditoria',
    audit.length ? audit.map(e => `- ${e.created} — ${e.event}`).join('\n') : '_sem eventos_',
    '',
    '---',
    '_Gerado pelo protótipo de interface do CYBER CORE — dados locais de demonstração,',
    'não substituem o relatório real emitido por `cyber report`._',
  ];
  return lines.join('\n');
}

function render() {
  populateCaseSelect();
  renderDashboard();
  renderInvestigations();
  renderTasks();
  renderLogs();
  renderReports();
}

// ---------- actions ----------
async function createCase(fields) {
  const c = {
    id: uid(),
    project: fields.project,
    objective: fields.objective,
    scope: fields.scope,
    owner: fields.owner,
    authorization: fields.authorization,
    validHours: fields.validHours,
    allowRecovery: fields.allowRecovery,
    state: 'EM INVESTIGACAO',
    paused: false,
    created: nowIso(),
  };
  state.cases.push(c);
  state.activeCase = c.id;
  saveState();
  await appendAudit(c.id, 'investigation_created', { project: c.project, owner: c.owner });
  return c;
}

async function pauseCase(id) {
  const c = getCase(id);
  if (!c) return;
  c.paused = true;
  saveState();
  await appendAudit(id, 'investigation_paused', {});
}

async function resumeCase(id) {
  const c = getCase(id);
  if (!c) return;
  c.paused = false;
  saveState();
  await appendAudit(id, 'investigation_resumed', {});
}

async function cancelCase(id, reason) {
  const c = getCase(id);
  if (!c) return;
  c.state = 'CANCELADO';
  c.paused = true;
  saveState();
  await appendAudit(id, 'investigation_cancelled', { reason });
}

async function enqueueTask(caseId, tool, path) {
  const t = { id: uid(), case_id: caseId, tool, path, status: 'pending', created: nowIso() };
  state.tasks.push(t);
  saveState();
  await appendAudit(caseId, 'task_enqueued', { tool, path });
  return t;
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------- wiring ----------
document.addEventListener('DOMContentLoaded', () => {
  for (const btn of document.querySelectorAll('.nav-item')) {
    btn.addEventListener('click', () => showView(btn.dataset.view));
  }
  for (const btn of document.querySelectorAll('[data-nav]')) {
    btn.addEventListener('click', () => showView(btn.dataset.nav));
  }

  document.getElementById('banner-close').addEventListener('click', () => {
    document.getElementById('proto-banner').classList.add('is-hidden');
  });

  document.getElementById('case-select').addEventListener('change', (e) => {
    state.activeCase = e.target.value || null;
    saveState();
    render();
  });

  document.getElementById('form-new-case').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fields = {
      project: document.getElementById('f-project').value.trim(),
      objective: document.getElementById('f-objective').value.trim(),
      scope: document.getElementById('f-scope').value.trim(),
      owner: document.getElementById('f-owner').value.trim(),
      authorization: document.getElementById('f-authorization').value.trim(),
      validHours: Number(document.getElementById('f-valid-hours').value) || 72,
      allowRecovery: document.getElementById('f-recovery').checked,
    };
    const c = await createCase(fields);
    e.target.reset();
    document.getElementById('f-valid-hours').value = 72;
    toast(`Investigação "${c.project}" criada.`);
    showView('investigations');
  });

  document.getElementById('investigations-table').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const id = btn.closest('tr').dataset.id;
    const act = btn.dataset.act;
    if (act === 'select') {
      state.activeCase = id;
      saveState();
      toast('Investigação selecionada.');
      render();
    } else if (act === 'pause') {
      await pauseCase(id);
      toast('Investigação pausada.');
      render();
    } else if (act === 'resume') {
      await resumeCase(id);
      toast('Investigação retomada.');
      render();
    } else if (act === 'cancel') {
      const reason = prompt('Motivo do cancelamento (obrigatório):');
      if (!reason || !reason.trim()) { toast('Cancelamento requer um motivo.', 'danger'); return; }
      if (!confirm('Cancelar esta investigação? Essa ação não pode ser desfeita.')) return;
      await cancelCase(id, reason.trim());
      toast('Investigação cancelada.', 'danger');
      render();
    }
  });

  document.getElementById('form-new-task').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.activeCase) { toast('Selecione uma investigação primeiro.', 'danger'); return; }
    const tool = document.getElementById('task-tool').value;
    const path = document.getElementById('task-path').value.trim();
    if (!path) return;
    await enqueueTask(state.activeCase, tool, path);
    document.getElementById('task-path').value = '';
    toast('Tarefa enfileirada.');
    render();
  });

  document.getElementById('verify-chain').addEventListener('click', async () => {
    if (!state.activeCase) { toast('Selecione uma investigação primeiro.', 'danger'); return; }
    await renderLogs();
    toast('Cadeia de hash verificada.');
  });

  document.getElementById('gen-report').addEventListener('click', () => {
    const c = state.activeCase ? getCase(state.activeCase) : null;
    if (!c) { toast('Selecione uma investigação primeiro.', 'danger'); return; }
    const md = buildReportMarkdown(c);
    downloadText(`relatorio-${c.id.slice(0, 8)}.md`, md);
    toast('Relatório baixado.');
  });

  render();
});
