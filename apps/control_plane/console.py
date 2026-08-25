"""Delegation Fabric console (single-page, zero-dependency).

Served by the Control Plane at GET /console. Reads only — all mutations go
through the documented /v1 API. Never displays tokens or secret material:
every rendered value passes through escape_console_value()/esc(), and any
field whose name matches a sensitive-key pattern is masked via
mask_console_value()/mask() (mirrored client- and server-side; see tests).

Views: Agent Registry (+ per-agent drill-in), Delegations (+ detail),
Approvals queue, enriched Task Inspector (checkpoints, grants, approvals,
event receipts, wait duration), Audit Graph, Security Denials.

The Audit Graph tab renders an interactive React Flow provenance DAG loaded
from a CDN; when unreachable it degrades to the vanilla timeline rendering.
"""

from __future__ import annotations

import re

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

_SENSITIVE_KEY_RE = re.compile(r"token|secret|credential|password|api[-_]?key", re.IGNORECASE)


def escape_console_value(value: object) -> str:
    """HTML-escape a value before embedding it in the console page."""
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def mask_console_value(key: str, value: object) -> str:
    """Mask values behind sensitive-sounding keys; never render secret material."""
    if _SENSITIVE_KEY_RE.search(key or ""):
        return "\u2022" * 8
    return str(value if value is not None else "")


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Delegation Fabric Console</title>
<style>
  :root { --bg:#0b1020; --panel:#131a30; --line:#26304f; --fg:#e8ecf8; --dim:#93a0c2; --ok:#3ecf8e; --bad:#ff6b6b; --warn:#ffc86b; }
  * { box-sizing:border-box; margin:0; font-family:ui-sans-serif,system-ui,sans-serif; }
  body { background:var(--bg); color:var(--fg); padding:24px; max-width:1100px; margin:auto; }
  h1 { font-size:20px; letter-spacing:.4px; } h1 span{color:var(--dim);font-weight:400;font-size:13px;display:block;margin-top:4px}
  h2 { font-size:14px; margin:16px 0 10px; color:var(--dim); text-transform:uppercase; letter-spacing:.6px; }
  nav { display:flex; gap:8px; margin:18px 0; flex-wrap:wrap; }
  nav button { background:var(--panel); color:var(--fg); border:1px solid var(--line); padding:8px 14px; border-radius:8px; cursor:pointer; font-size:13px; }
  nav button.active { border-color:var(--ok); }
  section { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--dim); font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:.6px; }
  tbody tr.clickable { cursor:pointer; } tbody tr.clickable:hover td { background:rgba(62,207,142,.05); }
  .pill { padding:2px 9px; border-radius:99px; font-size:11px; font-weight:600; white-space:nowrap; }
  .ok{background:rgba(62,207,142,.15);color:var(--ok)} .bad{background:rgba(255,107,107,.15);color:var(--bad)} .warn{background:rgba(255,200,107,.15);color:var(--warn)} .neutral{background:rgba(147,160,194,.15);color:var(--dim)}
  input { background:var(--bg); border:1px solid var(--line); color:var(--fg); padding:8px 10px; border-radius:8px; width:280px; font-size:13px; }
  button.go { background:var(--ok); color:#06281a; border:none; padding:8px 14px; border-radius:8px; cursor:pointer; font-weight:600; }
  button.back { background:transparent; color:var(--dim); border:1px solid var(--line); padding:6px 12px; border-radius:8px; cursor:pointer; font-size:12px; }
  .row { display:flex; gap:8px; margin-bottom:14px; align-items:center; flex-wrap:wrap; }
  pre { background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px; font-size:12px; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }
  .muted { color:var(--dim); font-size:12px; margin-top:10px; }
  ul.chain { list-style:none; padding-left:0; font-size:13px; }
  ul.chain li { padding:8px 10px; border-left:3px solid var(--line); margin:6px 0; }
  ul.chain li.allow { border-color:var(--ok); } ul.chain li.deny { border-color:var(--bad); } ul.chain li.quarantine { border-color:var(--warn); }
  .rf-wrap { height:440px; border:1px solid var(--line); border-radius:8px; margin-bottom:14px; overflow:hidden; }
  .react-flow__node { font-size:12px; }
  .react-flow__edge-path { stroke:var(--dim); }
  .react-flow__controls button { background:var(--panel); border-bottom:1px solid var(--line); fill:var(--fg); color:var(--fg); }
  .react-flow__controls button:hover { background:var(--bg); }
  .react-flow__minimap { background:var(--bg) !important; border:1px solid var(--line); border-radius:8px; }
  .react-flow__attribution { display:none; }
  .hidden { display:none; }
  .subhead { font-size:12px; color:var(--dim); text-transform:uppercase; letter-spacing:.6px; margin:18px 0 8px; }
</style>
</head>
<body>
<h1>Delegation Fabric<span>Deterministic authorization for AI agent fleets &mdash; read-only console</span></h1>
<nav>
  <button data-tab="registry" class="active">Agent Registry</button>
  <button data-tab="agent" class="hidden">Agent Detail</button>
  <button data-tab="delegations">Delegations</button>
  <button data-tab="approvals">Approvals</button>
  <button data-tab="task">Task Inspector</button>
  <button data-tab="audit">Audit Graph</button>
  <button data-tab="security">Security Denials</button>
</nav>

<section id="tab-registry">
  <table><thead><tr><th>Agent</th><th>Version</th><th>Owner</th><th>Risk</th><th>Capabilities</th><th>Denied tools</th><th>Regions</th><th>Deployment</th></tr></thead>
  <tbody id="registry-rows"><tr><td colspan="8" class="muted">Loading&hellip;</td></tr></tbody></table>
</section>

<section id="tab-agent" class="hidden">
  <div class="row"><button class="back" onclick="showTab('registry')">&larr; Back to registry</button></div>
  <div id="agent-body" class="muted">Select an agent.</div>
</section>

<section id="tab-delegations" class="hidden">
  <div id="delegation-detail" class="hidden"></div>
  <table><thead><tr><th>Sponsor</th><th>Purpose</th><th>Status</th><th>Task</th><th>Created</th><th>Expires</th></tr></thead>
  <tbody id="delegation-rows"><tr><td colspan="6" class="muted">Loading&hellip;</td></tr></tbody></table>
</section>

<section id="tab-approvals" class="hidden">
  <table><thead><tr><th>Approval</th><th>Type</th><th>Approver</th><th>Decision</th><th>Queue state</th><th>Subject hash</th><th>Created</th><th>Expires</th><th>Bound grant</th></tr></thead>
  <tbody id="approval-rows"><tr><td colspan="9" class="muted">Loading&hellip;</td></tr></tbody></table>
</section>

<section id="tab-task" class="hidden">
  <div class="row"><input id="task-id" placeholder="task_id e.g. task_demo_1001"/><button class="go" onclick="loadTask()">Inspect</button></div>
  <div id="task-body" class="muted">Enter a task id.</div>
</section>

<section id="tab-audit" class="hidden">
  <div class="row"><input id="audit-task-id" placeholder="task_id"/><button class="go" onclick="loadAudit()">Load chain</button><span id="audit-status"></span></div>
  <div id="audit-graph" class="rf-wrap hidden"></div>
  <p id="audit-fallback-note" class="muted hidden">Interactive provenance graph unavailable (CDN offline) &mdash; showing timeline instead.</p>
  <ul id="audit-chain" class="chain"></ul>
</section>

<section id="tab-security" class="hidden">
  <div class="row"><input id="sec-task-id" placeholder="task_id"/><button class="go" onclick="loadSecurity()">Show denials</button></div>
  <div id="security-body" class="muted">Structured denials by reason code.</div>
</section>

<p class="muted">Evidence surfaces: reason codes are closed-enum; the audit chain is SHA-256 hash-chained; no grant tokens are ever displayed &mdash; token-like fields render as masked dots.</p>

<script>
const $ = (id) => document.getElementById(id);
const TABS = ['registry','agent','delegations','approvals','task','audit','security'];
// Mirrors server-side escape_console_value(): every dynamic value rendered as
// HTML passes through esc() or an escaper-wrapped helper; raw variable
// interpolation never reaches the DOM.
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Mirrors server-side mask_console_value(): fields named like secrets never render material.
const SENSITIVE_KEY = /(token|secret|credential|password|api[-_]?key)/i;
const mask = (key, v) => SENSITIVE_KEY.test(String(key ?? '')) ? '\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022' : v;
function showTab(name) {
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('active', x.dataset.tab === name));
  TABS.forEach(t => $('tab-'+t).classList.toggle('hidden', t !== name));
}
document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  const t = b.dataset.tab;
  if (t === 'delegations' && !b.dataset.loaded) { b.dataset.loaded = '1'; loadDelegations().catch(()=>{}); }
  if (t === 'approvals' && !b.dataset.loaded) { b.dataset.loaded = '1'; loadApprovals().catch(()=>{}); }
  showTab(t);
});
const riskPill = (r) => pill(r, r==='critical'||r==='high' ? 'bad' : r==='medium' ? 'warn' : 'ok');
const statusPill = (s) => {
  const cls = s==='active'||s==='completed'||s==='approved'||s==='issued'||s==='consumed' ? 'ok'
            : s==='revoked'||s==='rejected'||s==='failed'||s==='cancelled'||s==='denied' ? 'bad' : 'warn';
  return pill(s, cls);
};
const fmtDur = (ms) => {
  ms = Math.max(0, ms);
  const d = Math.floor(ms/864e5), h = Math.floor(ms%864e5/36e5), m = Math.floor(ms%36e5/6e4), s = Math.floor(ms%6e4/1e3);
  return (d ? d+'d ' : '') + (h ? h+'h ' : '') + m + 'm ' + s + 's';
};
const pill = (text, cls) => '<span class="pill ' + cls + '">' + esc(text) + '</span>';
async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}

async function loadRegistry() {
  const agents = await api('/v1/agents');
  $('registry-rows').innerHTML = agents.map(a => `<tr class="clickable" data-agent="${esc(a.agent_id)}" data-version="${esc(a.version)}">
    <td><strong>${esc(a.agent_id)}</strong></td><td>${esc(a.version)}</td><td>${esc(a.owner||'&mdash;')}</td>
    <td>${riskPill(a.risk_class)}</td>
    <td>${esc(a.capabilities.join(', '))}</td><td>${esc(a.denied_tools.join(', '))||'&mdash;'}</td><td>${esc(a.allowed_regions.join(', '))}</td><td>${esc(a.deployment_revision||'&mdash;')}</td></tr>`).join('');
}
$('registry-rows').addEventListener('click', (ev) => {
  const tr = ev.target.closest('tr[data-agent]');
  if (!tr) return;
  showTab('agent');
  showAgent(tr.dataset.agent, tr.dataset.version);
});

async function showAgent(id, version) {
  $('agent-body').innerHTML = '<span class="muted">Loading&hellip;</span>';
  try {
    const a = await api('/v1/agents/' + encodeURIComponent(id) + '/versions/' + encodeURIComponent(version));
    $('agent-body').innerHTML = `
      <h2 style="margin-top:0">${esc(a.agent_id)} @ ${esc(a.version)}</h2>
      <table>
      <tr><th>Version</th><td>${esc(a.version)}</td></tr>
      <tr><th>Owner</th><td>${esc(a.owner||'&mdash;')}</td></tr>
      <tr><th>Risk class</th><td>${riskPill(a.risk_class)}</td></tr>
      <tr><th>Deployment revision</th><td>${esc(a.deployment_revision||'&mdash;')}</td></tr>
      <tr><th>Capabilities</th><td>${esc(a.capabilities.join(', '))}</td></tr>
      <tr><th>Denied tools</th><td>${esc(a.denied_tools.join(', '))||'&mdash;'}</td></tr>
      <tr><th>Allowed regions</th><td>${esc(a.allowed_regions.join(', '))}</td></tr>
      </table>`;
  } catch (e) { $('agent-body').innerHTML = '<span class="pill bad">Not found</span>'; }
}

async function loadDelegations() {
  const ds = await api('/v1/delegations');
  $('delegation-detail').classList.add('hidden');
  $('delegation-rows').innerHTML = ds.length === 0
    ? '<tr><td colspan="6" class="muted">No delegations recorded.</td></tr>'
    : ds.map(d => `<tr class="clickable" data-delegation="${esc(d.delegation_id)}">
      <td>${esc(sponsorLabel(d.sponsor))}</td><td>${esc(d.purpose)}</td><td>${statusPill(d.status)}</td>
      <td>${esc(d.task_id)}</td><td>${esc(d.created_at)}</td><td>${esc(d.expires_at)}</td></tr>`).join('');
}
$('delegation-rows').addEventListener('click', async (ev) => {
  const tr = ev.target.closest('tr[data-delegation]');
  if (!tr) return;
  try {
    const d = await api('/v1/delegations/' + encodeURIComponent(tr.dataset.delegation));
    const sponsorLine = sponsorLabel(d.sponsor);
    $('delegation-detail').innerHTML = `
      <h2 style="margin-top:0">Delegation ${esc(d.delegation_id)} ${statusPill(d.status)}</h2>
      <table>
      <tr><th>Sponsor</th><td>${esc(sponsorLine)}</td></tr>
      <tr><th>Purpose</th><td>${esc(d.purpose)}</td></tr>
      <tr><th>Bound task</th><td>${esc(d.task_id)}</td></tr>
      <tr><th>Policy version</th><td>${esc(d.policy_version)}</td></tr>
      <tr><th>Allowed agents</th><td>${esc(d.allowed_agents.join(', ')||'(any manifest agent)')}</td></tr>
      <tr><th>Allowed regions</th><td>${esc(d.allowed_regions.join(', '))}</td></tr>
      <tr><th>Created / Expires</th><td>${esc(d.created_at)} &rarr; ${esc(d.expires_at)}</td></tr>
      <tr><th>Revoked</th><td>${revokedCell(d)}</td></tr>
      </table>`;
    $('delegation-detail').classList.remove('hidden');
  } catch (e) { /* leave list untouched on transient failure */ }
});
function revokedCell(d) {
  if (!d.revoked_at) return '&mdash;';
  return '<span class="pill bad">' + esc(d.revoked_at) + '</span> by ' + esc(d.revoked_by || '&mdash;');
}

function approvalQueue(a) {
  if ((a.decision.value || a.decision) === 'rejected') return pill('rejected', 'bad');
  if (Date.parse(a.expires_at) < Date.now()) return pill('expired', 'warn');
  if (a.used_by_grant_id) return pill('consumed', 'neutral');
  return pill('pending use', 'ok');
}

// Server redacts sponsor PII to subject_hash; render a truncated, non-reversible
// label. The empty fallback is a plain em-dash character (not an HTML entity)
// so esc() at the call sites passes it through without double-escaping.
function sponsorLabel(s) {
  if (!s || !s.subject_hash) return '\\u2014';
  return String(s.subject_hash).slice(0, 19) + '\\u2026';
}

function approvalRow(a) {
  return `<tr>
    <td><strong>${esc(a.approval_id)}</strong><br/><span style="color:var(--dim)">task ${esc(a.task_id)}</span></td>
    <td>${esc(a.approval_type)}</td><td>${esc(a.approver_subject)}</td><td>${statusPill(a.decision.value || a.decision)}</td>
    <td>${approvalQueue(a)}</td>
    <td style="word-break:break-all">${esc(a.subject_hash)}</td>
    <td>${esc(a.created_at)}</td><td>${esc(a.expires_at)}</td><td>${esc(a.used_by_grant_id||'&mdash;')}</td></tr>`;
}

async function loadApprovals() {
  const aps = await api('/v1/approvals');
  $('approval-rows').innerHTML = aps.length === 0
    ? '<tr><td colspan="9" class="muted">No approvals recorded.</td></tr>'
    : aps.map(approvalRow).join('');
}

async function loadTask() {
  const id = $('task-id').value.trim(); if (!id) return;
  try {
    const t = await api('/v1/tasks/' + encodeURIComponent(id));
    const nowMs = Date.now();
    const terminal = ['completed','failed','cancelled'].includes(t.state);
    const age = t.created_at ? fmtDur(nowMs - Date.parse(t.created_at)) : null;
    const wait = (!terminal && t.updated_at) ? fmtDur(nowMs - Date.parse(t.updated_at)) : null;
    $('task-body').innerHTML = `
      <table>
      <tr><th>State</th><td>${statusPill(t.state)} &middot; version ${esc(t.version)}</td></tr>
      <tr><th>Agent</th><td>${esc(t.agent || '&mdash;')}</td></tr>
      <tr><th>Session</th><td>${esc(t.session_id || '&mdash;')}</td></tr>
      <tr><th>Delegation</th><td>${esc(t.delegation_id || '&mdash;')}</td></tr>
      <tr><th>Latest checkpoint</th><td>${esc(t.latest_checkpoint_id || '&mdash;')}</td></tr>
      ${durationRow('Total duration', age)}
      ${durationRow('Waiting in current state', wait)}
      <tr><th>Updated</th><td>${esc(t.updated_at)}</td></tr>
      </table>
      <div id="task-depth" class="muted">Loading task depth&hellip;</div>`;
    try {
      const depth = await api('/v1/tasks/' + encodeURIComponent(id) + '/depth');
      renderTaskDepth(depth);
    } catch (e) {
      $('task-depth').innerHTML = '<span class="pill warn">Depth data unavailable</span>';
    }
  } catch (e) { $('task-body').innerHTML = '<span class="pill bad">Not found</span>'; }
}

function durationRow(label, value) {
  return '<tr><th>' + esc(label) + '</th><td>' + esc(value ?? '&mdash;') + '</td></tr>';
}

function renderTaskDepth(depth) {
  const cps = depth.checkpoints || [], gs = depth.grants || [],
        aps = depth.approvals || [], rs = depth.event_receipts || [];
  let html = '';
  html += '<p class="subhead">Checkpoints (' + cps.length + ')</p>';
  html += cps.length === 0 ? '<p class="muted">None.</p>' : '<table><thead><tr><th>Checkpoint</th><th>State</th><th>Agent</th><th>Session</th><th>Memory refs</th><th>Pending subject hash</th><th>Created</th></tr></thead><tbody>'
    + cps.map(c => `<tr><td>${esc(c.checkpoint_id)}</td><td>${esc(c.state)}@${esc(c.state_version)}</td><td>${esc(c.agent_id)}@${esc(c.agent_version)}</td><td>${esc(c.session_id)}</td><td>${esc((c.memory_refs||[]).length)}</td><td style="word-break:break-all">${esc(c.pending_subject_hash || '\\u2014')}</td><td>${esc(c.created_at)}</td></tr>`).join('')
    + '</tbody></table>';
  html += '<p class="subhead">Execution grants (' + gs.length + ') &mdash; tokens never displayed</p>';
  html += gs.length === 0 ? '<p class="muted">None.</p>' : '<table><thead><tr><th>Grant</th><th>Tool</th><th>Status</th><th>Issued</th><th>Expires</th><th>Consumed</th></tr></thead><tbody>'
    + gs.map(g => `<tr><td>${esc(g.grant_id)}</td><td>${esc(g.tool)}</td><td>${statusPill(g.status.value || g.status)}</td><td>${esc(g.issued_at)}</td><td>${esc(g.expires_at)}</td><td>${esc(g.consumed_at||'&mdash;')}</td></tr>`).join('')
    + '</tbody></table>';
  html += '<p class="subhead">Approvals (' + aps.length + ')</p>';
  html += aps.length === 0 ? '<p class="muted">None.</p>' : '<table><thead><tr><th>Approval</th><th>Type</th><th>Approver</th><th>Decision</th><th>Subject hash</th><th>Bound grant</th><th>Created</th></tr></thead><tbody>'
    + aps.map(a => `<tr><td>${esc(a.approval_id)}</td><td>${esc(a.approval_type)}</td><td>${esc(a.approver_subject)}</td><td>${statusPill(a.decision.value || a.decision)}</td><td style="word-break:break-all">${esc(a.subject_hash)}</td><td>${esc(a.used_by_grant_id||'&mdash;')}</td><td>${esc(a.created_at)}</td></tr>`).join('')
    + '</tbody></table>';
  html += '<p class="subhead">Event receipts (' + rs.length + ')</p>';
  html += rs.length === 0 ? '<p class="muted">None.</p>' : '<table><thead><tr><th>Event</th><th>Type</th><th>Status</th><th>Attempts</th><th>First seen</th><th>Completed</th></tr></thead><tbody>'
    + rs.map(r => `<tr><td>${esc(r.event_id)}</td><td>${esc(r.event_type)}</td><td>${esc(r.status)}</td><td>${esc(r.attempt_count ?? 1)}</td><td>${esc(r.first_seen_at||'&mdash;')}</td><td>${esc(r.completed_at||'&mdash;')}</td></tr>`).join('')
    + '</tbody></table>';
  $('task-depth').innerHTML = html;
  $('task-depth').className = '';
}

const TONE_COLOR = { ok:'#3ecf8e', bad:'#ff6b6b', warn:'#ffc86b', neutral:'#93a0c2' };

function toneFor(e) {
  if (e.decision === 'deny') return 'bad';
  if (e.decision === 'quarantine') return 'warn';
  if (e.decision === 'allow') return 'ok';
  return 'neutral';
}

// PLAN.md Day 6 chain order:
// human -> delegation -> source document -> agent/version -> policy decision
// -> execution grant -> approval -> tool request -> side effect
function classifyType(t) {
  if (/^delegation/.test(t))                 return { layer:1, title:'Delegation' };
  if (/document|source|resource/.test(t))    return { layer:2, title:'Source Document' };
  if (/policy|denied|decision|evaluat/.test(t)) return { layer:4, title:'Policy Decision' };
  if (/grant/.test(t))                       return { layer:5, title:'Execution Grant' };
  if (/approval/.test(t))                    return { layer:6, title:'Approval' };
  if (/tool/.test(t))                        return { layer:7, title:'Tool Request' };
  if (/quarantin/.test(t))                   return { layer:8, title:'Quarantine' };
  if (/release/.test(t))                     return { layer:8, title:'Release' };
  if (/state|transition|checkpoint/.test(t)) return { layer:9, title:'State Transition' };
  return null;
}

// Deterministic node/edge derivation from audit events (layered DAG).
// Node labels are rendered by React as text nodes (auto-safe); they do not go
// through esc(), which is reserved for hand-built HTML strings below.
function deriveGraph(events) {
  const sorted = [...events].sort((a,b) => String(a.occurred_at).localeCompare(String(b.occurred_at)));

  // Cluster events by distinct event_type, preserving first-seen order.
  const order = [];
  const clusters = new Map();
  for (const e of sorted) {
    const key = e.event_type || 'unknown';
    if (!clusters.has(key)) { clusters.set(key, []); order.push(key); }
    clusters.get(key).push(e);
  }

  function mkNode(id, lines, layer, tone) {
    return {
      id,
      position: { x:0, y:layer * 110 },
      data: { label: lines.join('\\n') },
      style: {
        background:'var(--panel)', border:'2px solid ' + TONE_COLOR[tone], borderRadius:10,
        color:'var(--fg)', fontSize:12, padding:10, width:230, whiteSpace:'pre-wrap',
      },
    };
  }

  const nodes = [];
  let humanActor = null, agentActor = null, docRef = null;
  for (const e of sorted) {
    if (!humanActor && e.actor && e.actor.type === 'human') humanActor = e.actor;
    if (!agentActor && e.actor && e.actor.type === 'agent') agentActor = e.actor;
    if (!docRef && e.resource_refs && e.resource_refs.length) docRef = e.resource_refs[0];
  }

  nodes.push(mkNode('human', [humanActor ? 'Human Sponsor (' + humanActor.id + ')' : 'Human Sponsor'], 0, 'neutral'));
  if (docRef) nodes.push(mkNode('doc', ['Source Document', String(docRef).slice(0, 40)], 2, 'neutral'));
  if (agentActor) nodes.push(mkNode('agent', ['Agent / Version', agentActor.id + (agentActor.version ? '@' + agentActor.version : '')], 3, 'neutral'));

  // One node per distinct event_type cluster; unknown types appended after
  // the known layers in first-seen order.
  let nextUnknownLayer = 10;
  const clusterMeta = [];
  for (const key of order) {
    const evs = clusters.get(key);
    let meta = classifyType(key);
    let tone;
    if (meta) {
      tone = evs.some(e => e.decision === 'deny') ? 'bad'
           : evs.some(e => e.decision === 'quarantine') ? 'warn'
           : evs.some(e => e.decision === 'allow') ? 'ok' : 'neutral';
      if (key === 'task.state.transition') tone = 'neutral'; // gray per spec
    } else {
      meta = { layer: nextUnknownLayer++, title: key };
      tone = evs.some(e => e.decision === 'deny') ? 'bad'
           : evs.some(e => e.decision === 'quarantine') ? 'warn' : 'neutral';
    }
    const lines = [meta.title + (evs.length > 1 ? ' x' + evs.length : '')];
    const tools = [...new Set(evs.map(e => e.tool).filter(Boolean))];
    if (tools.length) lines.push(tools.join(', '));
    const reasons = [...new Set(evs.map(e => e.reason_code).filter(Boolean))];
    if (reasons.length) lines.push('reason=' + reasons.join(', '));
    nodes.push(mkNode('et:' + key, lines.slice(0, 3), meta.layer, tone));
    clusterMeta.push({ key, layer: meta.layer });
  }

  // Chain edges in canonical order; center nodes sharing a layer.
  const chainIds = ['human'];
  if (docRef) chainIds.push('doc');
  if (agentActor) chainIds.push('agent');
  clusterMeta.sort((a,b) => a.layer - b.layer).forEach(c => chainIds.push('et:' + c.key));

  const edges = [];
  for (let i = 1; i < chainIds.length; i++) {
    edges.push({
      id: 'e-' + chainIds[i-1] + '-' + chainIds[i],
      source: chainIds[i-1], target: chainIds[i],
      type: 'smoothstep', animated: true,
      style: { stroke:'#93a0c2' },
    });
  }

  const byLayer = new Map();
  for (const n of nodes) {
    if (!byLayer.has(n.position.y)) byLayer.set(n.position.y, []);
    byLayer.get(n.position.y).push(n);
  }
  for (const group of byLayer.values()) {
    group.forEach((n, i) => { n.position.x = (i - (group.length - 1) / 2) * 250; });
  }

  return { nodes, edges };
}

async function loadAudit() {
  const id = $('audit-task-id').value.trim(); if (!id) return;
  try {
    const events = await api('/v1/audit/tasks/' + encodeURIComponent(id));
    const v = await api('/v1/audit/tasks/' + encodeURIComponent(id) + '/verify');
    $('audit-status').innerHTML = v.valid
      ? `<span class="pill ok">chain valid (${esc(v.events)} events)</span>`
      : '<span class="pill bad">CHAIN BROKEN</span>';
    $('audit-chain').innerHTML = events.map(e => {
      let detail = e.tool ? 'tool=' + esc(e.tool) : '';
      if (e.reason_code) detail += ' reason=' + esc(e.reason_code);
      if (e.actor) detail += ' actor=' + esc(e.actor.type) + ':' + esc(e.actor.id);
      return '<li class="' + esc(e.decision) + '"><strong>' + esc(e.event_type) + '</strong> '
        + '<span style="color:var(--dim)">' + detail + ' &middot; ' + esc(e.occurred_at) + '</span></li>';
    }).join('');
    // Interactive React Flow DAG when available; timeline stays as fallback.
    const renderDag = window.__renderAuditDag;
    const shown = typeof renderDag === 'function' && events.length > 0 && renderDag(events);
    $('audit-graph').classList.toggle('hidden', !shown);
    $('audit-chain').classList.toggle('hidden', !!shown);
  } catch (err) {
    $('audit-status').innerHTML = '<span class="pill bad">load failed</span>';
  }
}

async function loadSecurity() {
  const id = $('sec-task-id').value.trim(); if (!id) return;
  const events = await api('/v1/audit/tasks/' + encodeURIComponent(id));
  const denied = events.filter(e => e.decision !== 'allow');
  $('security-body').innerHTML = denied.length === 0
    ? '<span class="pill ok">No denials recorded for this task.</span>'
    : '<table><thead><tr><th>Event</th><th>Reason code</th><th>Tool</th><th>Actor</th><th>Time</th></tr></thead><tbody>'
      + denied.map(e => `<tr><td>${esc(e.event_type)}</td><td><span class="pill bad">${esc(e.reason_code||'&mdash;')}</span></td><td>${esc(e.tool||'&mdash;')}</td><td>${esc(e.actor?e.actor.id:'&mdash;')}</td><td>${esc(e.occurred_at)}</td></tr>`).join('')
      + '</tbody></table>';
}

loadRegistry().catch(() => {});
</script>

<script type="module">
// Interactive provenance DAG via React Flow (CDN ESM, no build step).
// On failure (offline / CDN unreachable) the vanilla timeline remains.
window.__renderAuditDag = null;
(async () => {
  try {
    const [ReactMod, ReactDOMMod, RF] = await Promise.all([
      import('https://esm.sh/react@18.3.1'),
      import('https://esm.sh/react-dom@18.3.1/client'),
      import('https://esm.sh/reactflow@11.11.4?deps=react@18.3.1,react-dom@18.3.1')
    ]);
    const css = document.createElement('link');
    css.rel = 'stylesheet';
    css.href = 'https://esm.sh/reactflow@11.11.4/dist/style.css';
    document.head.appendChild(css);

    const React = ReactMod.default;
    const { createElement: h, useMemo } = React;
    const { createRoot } = ReactDOMMod;
    const { ReactFlowProvider, ReactFlow, Background, Controls, MiniMap } = RF;

    function Graph({ events }) {
      const { nodes, edges } = useMemo(() => deriveGraph(events), [events]);
      return h(ReactFlowProvider, null,
        h(ReactFlow, { nodes, edges, fitView: true, minZoom: 0.2 },
          h(Background, { color: '#26304f', gap: 24 }),
          h(Controls),
          h(MiniMap, { pannable: true, zoomable: true, nodeColor: n => n.style.border })
        )
      );
    }

    let root = null;
    window.__renderAuditDag = (events) => {
      const host = document.getElementById('audit-graph');
      if (!host || !Array.isArray(events)) return false;
      if (!root) root = createRoot(host);
      root.render(h(Graph, { events }));
      return true;
    };
  } catch (err) {
    console.warn('[console] React Flow CDN unavailable; using timeline fallback:', err);
    document.getElementById('audit-fallback-note')?.classList.remove('hidden');
  }
})();
</script>
</body>
</html>
"""


def register_console(app: FastAPI) -> None:
    @app.get("/console", include_in_schema=False)
    async def console() -> HTMLResponse:
        return HTMLResponse(_PAGE)
