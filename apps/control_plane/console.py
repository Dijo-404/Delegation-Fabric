"""Delegation Fabric console (single-page, zero-dependency).

Served by the Control Plane at GET /console. Reads only — all mutations go
through the documented /v1 API. Never displays tokens or secret material.

The Audit Graph tab renders an interactive React Flow provenance DAG loaded
from a CDN; when unreachable it degrades to the vanilla timeline rendering.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

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
  nav { display:flex; gap:8px; margin:18px 0; flex-wrap:wrap; }
  nav button { background:var(--panel); color:var(--fg); border:1px solid var(--line); padding:8px 14px; border-radius:8px; cursor:pointer; font-size:13px; }
  nav button.active { border-color:var(--ok); }
  section { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); }
  th { color:var(--dim); font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:.6px; }
  .pill { padding:2px 9px; border-radius:99px; font-size:11px; font-weight:600; }
  .ok{background:rgba(62,207,142,.15);color:var(--ok)} .bad{background:rgba(255,107,107,.15);color:var(--bad)} .warn{background:rgba(255,200,107,.15);color:var(--warn)}
  input { background:var(--bg); border:1px solid var(--line); color:var(--fg); padding:8px 10px; border-radius:8px; width:280px; font-size:13px; }
  button.go { background:var(--ok); color:#06281a; border:none; padding:8px 14px; border-radius:8px; cursor:pointer; font-weight:600; }
  .row { display:flex; gap:8px; margin-bottom:14px; align-items:center; }
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
</style>
</head>
<body>
<h1>Delegation Fabric<span>Deterministic authorization for AI agent fleets &mdash; read-only console</span></h1>
<nav>
  <button data-tab="registry" class="active">Agent Registry</button>
  <button data-tab="task">Task Inspector</button>
  <button data-tab="audit">Audit Graph</button>
  <button data-tab="security">Security Denials</button>
</nav>

<section id="tab-registry">
  <table><thead><tr><th>Agent</th><th>Version</th><th>Risk</th><th>Capabilities</th><th>Denied tools</th><th>Regions</th></tr></thead>
  <tbody id="registry-rows"><tr><td colspan="6" class="muted">Loading&hellip;</td></tr></tbody></table>
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

<p class="muted">Evidence surfaces: reason codes are closed-enum; the audit chain is SHA-256 hash-chained; no grant tokens are ever displayed.</p>

<script>
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  ['registry','task','audit','security'].forEach(t => $('tab-'+t).classList.toggle('hidden', t !== b.dataset.tab));
});

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}

async function loadRegistry() {
  const agents = await api('/v1/agents');
  $('registry-rows').innerHTML = agents.map(a => `<tr>
    <td><strong>${esc(a.agent_id)}</strong></td><td>${esc(a.version)}</td>
    <td><span class="pill ${a.risk_class==='critical'?'bad':a.risk_class==='high'?'warn':'ok'}">${esc(a.risk_class)}</span></td>
    <td>${esc(a.capabilities.join(', '))}</td><td>${esc(a.denied_tools.join(', '))||'&mdash;'}</td><td>${esc(a.allowed_regions.join(', '))}</td></tr>`).join('');
}

async function loadTask() {
  const id = $('task-id').value.trim(); if (!id) return;
  try {
    const t = await api('/v1/tasks/' + encodeURIComponent(id));
    const grants = t.grant_ids || [];
    $('task-body').innerHTML = `<table>
      <tr><th>State</th><td><span class="pill ${t.state==='quarantined'?'warn':t.state==='completed'?'ok':t.state==='failed'||t.state==='cancelled'?'bad':''}">${esc(t.state)}</span></td></tr>
      <tr><th>Version</th><td>${esc(t.version)}</td></tr>
      <tr><th>Session</th><td>${esc(t.session_id || '&mdash;')}</td></tr>
      <tr><th>Agent</th><td>${esc(t.agent || '&mdash;')}</td></tr>
      <tr><th>Checkpoint</th><td>${esc(t.latest_checkpoint_id || '&mdash;')}</td></tr>
      <tr><th>Updated</th><td>${esc(t.updated_at)}</td></tr></table>`;
  } catch (e) { $('task-body').innerHTML = '<span class="pill bad">Not found</span>'; }
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
    $('audit-status').innerHTML = v.valid ? '<span class="pill ok">chain valid ('+v.events+' events)</span>' : '<span class="pill bad">CHAIN BROKEN</span>';
    $('audit-chain').innerHTML = events.map(e => {
      let detail = e.tool ? `tool=${e.tool}` : '';
      if (e.reason_code) detail += ` reason=${e.reason_code}`;
      if (e.actor) detail += ` actor=${e.actor.type}:${e.actor.id}`;
      return `<li class="${e.decision}"><strong>${e.event_type}</strong> <span style="color:var(--dim)">${detail} &middot; ${e.occurred_at}</span></li>`;
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
