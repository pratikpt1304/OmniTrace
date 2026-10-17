/**
 * OmniTrace Threat Cockpit — Frontend Architecture & State Engine
 * FalkorDB Graph Hacks (Track 01: Agents That Act on Connected Data)
 */

// State Container
const state = {
  network: null,
  rawNodes: [],
  rawEdges: [],
  nodesDataSet: null,
  edgesDataSet: null,
  physicsEnabled: true,
  activeDossier: null,
  frozenAccounts: new Set(),
  focusedThreatId: null,
  isInvestigating: false,
  isDemoRunning: false,
  apiConnected: false,
};

// ============================================================================
// 1. INITIALIZATION & NETWORK SETUP
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initVisNetwork();
  setupEventListeners();
  checkApiHealth();
  refreshGraphData();

  // Periodic health check
  setInterval(checkApiHealth, 15000);
});

function initVisNetwork() {
  const container = document.getElementById('vis-network-canvas');
  state.nodesDataSet = new vis.DataSet([]);
  state.edgesDataSet = new vis.DataSet([]);

  const data = {
    nodes: state.nodesDataSet,
    edges: state.edgesDataSet,
  };

  const options = {
    nodes: {
      font: {
        face: 'JetBrains Mono, monospace',
        color: '#f8fafc',
        size: 11,
      },
      borderWidth: 2,
      shadow: {
        enabled: true,
        color: 'rgba(0, 0, 0, 0.6)',
        size: 10,
        x: 0,
        y: 4,
      },
    },
    edges: {
      arrows: {
        to: { enabled: true, scaleFactor: 0.75 },
      },
      font: {
        face: 'JetBrains Mono, monospace',
        size: 9,
        color: '#94a3b8',
        align: 'middle',
        background: 'rgba(9, 12, 21, 0.75)',
        strokeWidth: 0,
      },
      smooth: {
        type: 'cubicBezier',
        forceDirection: 'none',
        roundness: 0.25,
      },
    },
    physics: {
      enabled: true,
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {
        gravitationalConstant: -70,
        centralGravity: 0.015,
        springLength: 130,
        springConstant: 0.08,
        damping: 0.85,
        avoidOverlap: 0.6,
      },
      stabilization: {
        enabled: true,
        iterations: 120,
        updateInterval: 25,
      },
    },
    interaction: {
      hover: true,
      tooltipDelay: 150,
      zoomView: true,
      dragView: true,
      selectConnectedEdges: true,
    },
  };

  state.network = new vis.Network(container, data, options);

  // Network Event Listeners
  state.network.on('click', (params) => {
    if (params.nodes.length > 0) {
      const selectedId = params.nodes[0];
      inspectNode(selectedId);
    } else {
      closeNodeDrawer();
    }
  });

  state.network.on('hoverNode', () => {
    container.style.cursor = 'pointer';
  });
  state.network.on('blurNode', () => {
    container.style.cursor = 'default';
  });
}

// ============================================================================
// 2. API CALLS & DATA REFRESH
// ============================================================================
async function checkApiHealth() {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  try {
    const res = await fetch('/api/graph/state');
    if (res.ok) {
      state.apiConnected = true;
      dot.className = 'status-dot';
      text.textContent = 'API CONNECTED';
    } else {
      throw new Error('API degraded');
    }
  } catch (err) {
    state.apiConnected = false;
    dot.className = 'status-dot disconnected';
    text.textContent = 'DISCONNECTED';
  }
}

async function refreshGraphData() {
  try {
    const res = await fetch('/api/graph/state');
    const data = await res.json();

    state.rawNodes = data.nodes || [];
    state.rawEdges = data.edges || [];

    // Parse frozen accounts and enrich nodes
    state.frozenAccounts.clear();
    const styledNodes = state.rawNodes.map((n) => {
      const isSanction = n.group === 'SanctionedEntity';
      const isDevice = n.group === 'Device';
      const isIP = n.group === 'IPAddress';
      const isFrozen = n.color && (n.color.background === '#ff3300' || n.label.includes('FROZEN'));

      if (isFrozen) {
        state.frozenAccounts.add(n.id);
      }

      let shape = 'dot';
      let size = 20;
      let label = n.label || n.id;
      let color = n.color;

      if (isSanction) {
        shape = 'hexagon';
        size = 28;
        color = {
          background: '#ff2d55',
          border: '#ffffff',
          highlight: { background: '#ff436b', border: '#ffffff' },
        };
      } else if (isDevice) {
        shape = 'square';
        size = 18;
        color = { background: '#b026ff', border: '#d27aff' };
      } else if (isIP) {
        shape = 'diamond';
        size = 18;
        color = { background: '#8b5cf6', border: '#a78bfa' };
      } else if (isFrozen) {
        label = `🔒 ${n.id}\n[FROZEN]`;
        color = {
          background: '#ef4444',
          border: '#ffffff',
          highlight: { background: '#dc2626', border: '#ffffff' },
        };
      }

      // Generate rich hover HTML tooltip
      const tooltip = `
        <div style="background:#0b1120; border:1px solid rgba(255,255,255,0.15); padding:8px 12px; border-radius:6px; font-family:'JetBrains Mono', monospace; font-size:11px; color:#fff;">
          <div style="font-weight:700; color:#00f0ff; margin-bottom:4px;">${n.id}</div>
          <div>Type: <span style="color:#94a3b8;">${n.group || 'Account'}</span></div>
          <div>Status: <span style="color:${isFrozen ? '#ff2d55' : '#00e676'}; font-weight:700;">${isFrozen ? 'FROZEN' : 'ACTIVE'}</span></div>
        </div>
      `;

      return {
        ...n,
        shape,
        size,
        label,
        color,
        title: tooltip,
        borderWidth: isFrozen || isSanction ? 3 : 1.5,
      };
    });

    state.nodesDataSet.clear();
    state.nodesDataSet.add(styledNodes);

    state.edgesDataSet.clear();
    state.edgesDataSet.add(state.rawEdges);

    updateTelemetryHeader();
    updateMetricsTab();
    updateFreezeRegistry();
    updateSearchAutocomplete();

    // Toggle empty state message if 0 nodes
    const emptyState = document.getElementById('empty-feed-placeholder');
    if (emptyState && state.rawNodes.length > 0 && !state.activeDossier) {
      emptyState.innerHTML = `
        <div class="empty-state-icon">⚡</div>
        <div style="font-weight:700; color:#fff; font-size:0.9rem;">Graph Loaded (${state.rawNodes.length} Nodes)</div>
        <div class="empty-state-text">Ready for autonomous threat detection. Click <strong>Run Investigation</strong> to begin.</div>
      `;
    }
  } catch (err) {
    showToast('Graph Sync Error', err.message, 'error');
  }
}

// ============================================================================
// 3. AGENT INVESTIGATION ENGINE & TIMELINE
// ============================================================================
async function runInvestigation() {
  if (state.isInvestigating) return;
  state.isInvestigating = true;

  const runBtn = document.getElementById('btn-run-investigation');
  runBtn.disabled = true;
  runBtn.innerHTML = `
    <svg style="animation:spin 1s infinite linear; width:16px; height:16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
      <path d="M12 2a10 10 0 0 1 10 10"></path>
    </svg>
    Investigating Graph...
  `;

  // Render animated step-by-step investigation timeline in Left Panel
  const feed = document.getElementById('threats-feed');
  feed.innerHTML = `
    <div class="investigation-timeline" id="investigation-timeline">
      <div class="timeline-title">
        <span class="status-dot"></span> Autonomous Investigation Loop
      </div>
      <div class="timeline-step active" id="step-1">
        <div class="step-icon">1</div>
        <span>Scanning FalkorDB graph topology...</span>
      </div>
      <div class="timeline-step" id="step-2">
        <div class="step-icon">2</div>
        <span>Tracing multi-hop shortest paths to sanctions...</span>
      </div>
      <div class="timeline-step" id="step-3">
        <div class="step-icon">3</div>
        <span>Detecting circular structuring rings...</span>
      </div>
      <div class="timeline-step" id="step-4">
        <div class="step-icon">4</div>
        <span>Checking device & IP collision clusters...</span>
      </div>
      <div class="timeline-step" id="step-5">
        <div class="step-icon">5</div>
        <span>Executing atomic graph account freezes...</span>
      </div>
    </div>
  `;

  // Animate timeline steps
  const steps = ['step-1', 'step-2', 'step-3', 'step-4', 'step-5'];
  for (let i = 0; i < steps.length - 1; i++) {
    await sleep(220);
    const curr = document.getElementById(steps[i]);
    const next = document.getElementById(steps[i + 1]);
    if (curr) {
      curr.className = 'timeline-step done';
      curr.querySelector('.step-icon').textContent = '✓';
    }
    if (next) {
      next.className = 'timeline-step active';
    }
  }

  try {
    const t0 = performance.now();
    const res = await fetch('/api/investigate', { method: 'POST' });
    const dossier = await res.json();
    const latency = Math.round(performance.now() - t0);

    // Finalize last timeline step
    const step5 = document.getElementById('step-5');
    if (step5) {
      step5.className = 'timeline-step done';
      step5.querySelector('.step-icon').textContent = '✓';
    }

    await sleep(250);
    state.activeDossier = dossier;

    renderThreatCards(dossier);
    await refreshGraphData();

    showToast('Investigation Complete', `Found ${dossier.findings.length} threat topologies in ${latency}ms`, 'success');
  } catch (err) {
    showToast('Investigation Failed', err.message, 'error');
  } finally {
    state.isInvestigating = false;
    runBtn.disabled = false;
    runBtn.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
      Run Investigation
    `;
  }
}

function renderThreatCards(dossier) {
  const feed = document.getElementById('threats-feed');
  const countBadge = document.getElementById('threat-count-badge');
  countBadge.textContent = `${dossier.findings.length} THREATS`;

  let html = `
    <div style="font-size:0.72rem; font-family:'JetBrains Mono'; color:#00f0ff; margin-bottom:4px; display:flex; justify-content:space-between; align-items:center;">
      <span>AGENT DOSSIER: ${dossier.investigation_id || 'COMPLETED'}</span>
      <span style="color:#00e676;">${dossier.enforcement_actions.length} FROZEN</span>
    </div>
  `;

  dossier.findings.forEach((finding, idx) => {
    const isCritical = finding.severity === 'CRITICAL';
    const cardClass = isCritical ? 'threat-card critical' : 'threat-card high';
    const severityBadgeClass = isCritical ? 'severity-badge critical' : 'severity-badge high';

    // Parse path nodes for interactive chips
    let pathChips = [];
    if (finding.path_trail) {
      pathChips = finding.path_trail.split(' -> ').map((s) => s.trim());
    } else if (finding.cycle_path) {
      pathChips = finding.cycle_path.split(' -> ').map((s) => s.trim());
    } else if (finding.accounts_sharing) {
      pathChips = [...finding.accounts_sharing];
      if (finding.device_fingerprint) pathChips.push(finding.device_fingerprint);
    }

    const chipsHtml = pathChips
      .map((chip, cIdx) => {
        const isSanction = chip.includes('SANCTION');
        const chipClass = isSanction ? 'path-chip sanction' : 'path-chip';
        return `
        <span class="${chipClass}" onclick="event.stopPropagation(); focusSingleNode('${chip}')">${chip}</span>
        ${cIdx < pathChips.length - 1 ? '<span class="path-arrow">→</span>' : ''}
      `;
      })
      .join('');

    html += `
      <div class="${cardClass}" id="card-threat-${idx}" onclick="focusThreatTrail(${idx})">
        <div class="card-top">
          <span class="${severityBadgeClass}">${finding.severity}</span>
          <span class="card-latency">${finding.latency_ms ? finding.latency_ms + 'ms' : '< 1ms'}</span>
        </div>
        <div class="card-title">${formatThreatTitle(finding.type)}</div>
        <div class="card-reasoning">${finding.reasoning}</div>
        ${pathChips.length > 0 ? `<div class="path-trail-container">${chipsHtml}</div>` : ''}
      </div>
    `;
  });

  feed.innerHTML = html;
}

function formatThreatTitle(type) {
  switch (type) {
    case 'OFAC_SANCTIONS_EXPOSURE':
      return 'OFAC Sanctions Exposure';
    case 'CIRCULAR_STRUCTURING_RING':
      return 'Circular Structuring Loop';
    case 'SYBIL_DEVICE_FINGERPRINT_COLLISION':
      return 'Sybil Hardware Farm Collision';
    default:
      return type.replace(/_/g, ' ');
  }
}

// ============================================================================
// 4. GRAPH FOCUS, HIGHLIGHT & DIMMING ENGINE
// ============================================================================
function focusThreatTrail(threatIdx) {
  if (!state.activeDossier || !state.activeDossier.findings[threatIdx]) return;
  const finding = state.activeDossier.findings[threatIdx];
  state.focusedThreatId = threatIdx;

  // Highlight card in left feed
  document.querySelectorAll('.threat-card').forEach((c, idx) => {
    if (idx === threatIdx) {
      c.classList.add('focused');
      c.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } else {
      c.classList.remove('focused');
    }
  });

  // Extract all involved node IDs
  let targetNodeIds = [];
  if (finding.path_trail) {
    targetNodeIds = finding.path_trail.split(' -> ').map((s) => s.trim());
  } else if (finding.cycle_path) {
    targetNodeIds = finding.cycle_path.split(' -> ').map((s) => s.trim());
  } else if (finding.accounts_sharing) {
    targetNodeIds = [...finding.accounts_sharing];
    if (finding.device_fingerprint) targetNodeIds.push(finding.device_fingerprint);
  }

  if (targetNodeIds.length === 0) return;

  const targetSet = new Set(targetNodeIds);

  // Dim non-target nodes and highlight target nodes
  const updateNodes = [];
  state.nodesDataSet.forEach((node) => {
    const isTarget = targetSet.has(node.id);
    updateNodes.push({
      id: node.id,
      opacity: isTarget ? 1.0 : 0.12,
      font: { color: isTarget ? '#ffffff' : 'rgba(255,255,255,0.2)' },
      shadow: isTarget
        ? { enabled: true, color: '#00f0ff', size: 20, x: 0, y: 0 }
        : { enabled: false },
    });
  });
  state.nodesDataSet.update(updateNodes);

  // Dim edges
  const updateEdges = [];
  state.edgesDataSet.forEach((edge) => {
    const isTargetEdge = targetSet.has(edge.from) && targetSet.has(edge.to);
    updateEdges.push({
      id: edge.id,
      color: isTargetEdge
        ? { color: '#ff2d55', opacity: 1.0 }
        : { color: 'rgba(255,255,255,0.05)', opacity: 0.05 },
      width: isTargetEdge ? 3.5 : 1,
    });
  });
  state.edgesDataSet.update(updateEdges);

  // Smooth camera zoom & fit
  state.network.fit({
    nodes: targetNodeIds,
    animation: {
      duration: 700,
      easingFunction: 'easeInOutQuad',
    },
  });

  // Show Reset Focus banner
  const banner = document.getElementById('focus-banner');
  const bannerText = document.getElementById('focus-banner-text');
  bannerText.textContent = `Isolated Threat: ${formatThreatTitle(finding.type)} (${targetNodeIds.length} nodes)`;
  banner.style.display = 'flex';
}

function resetGraphFocus() {
  state.focusedThreatId = null;

  // Restore all nodes
  const restoreNodes = [];
  state.nodesDataSet.forEach((node) => {
    restoreNodes.push({
      id: node.id,
      opacity: 1.0,
      font: { color: '#ffffff' },
      shadow: { enabled: true, color: 'rgba(0,0,0,0.6)', size: 10, x: 0, y: 4 },
    });
  });
  state.nodesDataSet.update(restoreNodes);

  // Restore edges
  const restoreEdges = [];
  state.edgesDataSet.forEach((edge) => {
    restoreEdges.push({
      id: edge.id,
      color: { color: edge.color.color || 'rgba(255,255,255,0.25)', opacity: 1.0 },
      width: 1.5,
    });
  });
  state.edgesDataSet.update(restoreEdges);

  // Reset card focus
  document.querySelectorAll('.threat-card').forEach((c) => c.classList.remove('focused'));

  // Hide banner
  document.getElementById('focus-banner').style.display = 'none';

  // Fit all nodes
  state.network.fit({
    animation: { duration: 600, easingFunction: 'easeInOutQuad' },
  });
}

function focusSingleNode(nodeId) {
  if (!nodeId || !state.network) return;
  state.network.focus(nodeId, {
    scale: 1.4,
    animation: { duration: 600, easingFunction: 'easeInOutQuad' },
  });
  inspectNode(nodeId);
}

// ============================================================================
// 5. NODE INSPECTOR DRAWER
// ============================================================================
function inspectNode(nodeId) {
  const node = state.nodesDataSet.get(nodeId);
  if (!node) return;

  const drawer = document.getElementById('node-drawer');
  document.getElementById('drawer-node-id').textContent = node.id;
  document.getElementById('drawer-node-type').textContent = node.group || 'Account';

  const isFrozen = state.frozenAccounts.has(node.id);
  const statusEl = document.getElementById('drawer-node-status');
  statusEl.textContent = isFrozen ? 'FROZEN' : 'ACTIVE';
  statusEl.style.color = isFrozen ? 'var(--red)' : 'var(--green)';

  const riskEl = document.getElementById('drawer-node-risk');
  riskEl.textContent = isFrozen ? '100 / 100 (CRITICAL)' : '15 / 100 (LOW)';
  riskEl.style.color = isFrozen ? 'var(--red)' : 'var(--cyan)';

  const actionsContainer = document.getElementById('drawer-actions');
  if (isFrozen) {
    actionsContainer.innerHTML = `
      <button class="btn btn-unfreeze" style="width:100%; justify-content:center; padding:9px 14px;" onclick="unfreezeAccount('${node.id}')">
        ✓ Unfreeze Account & Restore Status
      </button>
    `;
  } else {
    actionsContainer.innerHTML = `
      <button class="btn btn-secondary" style="width:100%; justify-content:center; font-size:0.75rem;" onclick="focusSingleNode('${node.id}')">
        Center Camera on Entity
      </button>
    `;
  }

  drawer.classList.add('open');
}

function closeNodeDrawer() {
  const drawer = document.getElementById('node-drawer');
  if (drawer) drawer.classList.remove('open');
}

async function unfreezeAccount(accId) {
  try {
    const res = await fetch('/api/account/unfreeze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_id: accId }),
    });
    const data = await res.json();
    if (data.ok) {
      showToast('Account Unfrozen', `Restored ${accId} to ACTIVE state in FalkorDB`, 'success');
      state.frozenAccounts.delete(accId);
      await refreshGraphData();
      inspectNode(accId);
    } else {
      showToast('Unfreeze Failed', data.error || 'Server error', 'error');
    }
  } catch (err) {
    showToast('Unfreeze Error', err.message, 'error');
  }
}

// ============================================================================
// 6. RIGHT PANEL TABS (METRICS, FREEZE REGISTRY, CYPHER STUDIO)
// ============================================================================
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-pane').forEach((pane) => {
    pane.classList.toggle('active', pane.id === `tab-pane-${tabId}`);
  });
}

function updateTelemetryHeader() {
  const nodesCount = state.rawNodes.length;
  const edgesCount = state.rawEdges.length;
  document.getElementById('header-node-count').textContent = nodesCount;
  document.getElementById('header-edge-count').textContent = edgesCount;
}

function updateMetricsTab() {
  const nodeCount = state.rawNodes.length;
  const edgeCount = state.rawEdges.length;
  const threatsCount = state.activeDossier ? state.activeDossier.findings.length : 3;
  const frozenCount = state.frozenAccounts.size;

  animateNumber('stat-nodes', nodeCount);
  animateNumber('stat-edges', edgeCount);
  animateNumber('stat-threats', threatsCount);
  animateNumber('stat-frozen', frozenCount);
}

function animateNumber(elementId, target) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const current = parseInt(el.textContent, 10) || 0;
  if (current === target) return;

  const duration = 600;
  const stepTime = 30;
  const steps = duration / stepTime;
  const increment = (target - current) / steps;
  let val = current;

  const timer = setInterval(() => {
    val += increment;
    if ((increment > 0 && val >= target) || (increment < 0 && val <= target)) {
      el.textContent = target;
      clearInterval(timer);
    } else {
      el.textContent = Math.round(val);
    }
  }, stepTime);
}

function updateFreezeRegistry() {
  const container = document.getElementById('freeze-registry-list');
  const countBadge = document.getElementById('freeze-registry-count');
  countBadge.textContent = `${state.frozenAccounts.size} FROZEN`;

  if (state.frozenAccounts.size === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🛡️</div>
        <div style="font-weight:700; color:#fff;">No Frozen Accounts</div>
        <div class="empty-state-text">No active graph lockouts. Accounts are frozen automatically during autonomous investigations.</div>
      </div>
    `;
    return;
  }

  let html = '';
  state.frozenAccounts.forEach((accId) => {
    html += `
      <div class="freeze-card" onclick="focusSingleNode('${accId}')">
        <div class="freeze-card-top">
          <div class="freeze-id">
            <span style="color:#ef4444;">🔒</span> ${accId}
          </div>
          <span class="freeze-badge">MUTATION AUDITED</span>
        </div>
        <div class="freeze-desc">
          High-risk financial anomaly detected. Account status set to FROZEN and linked to EnforcementAction in FalkorDB.
        </div>
        <div style="margin-top:4px;">
          <button class="btn-unfreeze" onclick="event.stopPropagation(); unfreezeAccount('${accId}')">
            ✓ Unfreeze Account
          </button>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

// ============================================================================
// 7. CYPHER STUDIO
// ============================================================================
const CYPHER_PRESETS = {
  shortest_path: `MATCH (src:Account {id: 'ACC_MULE_ALPHA'}),
      (target:SanctionedEntity),
      p = (src)-[:TRANSFERRED*1..5]->(target)
RETURN p, length(p) AS hops, target.name AS target_name
LIMIT 5;`,

  cycle_detection: `MATCH (a:Account)-[:TRANSFERRED]->(b:Account)-[:TRANSFERRED]->(c:Account)-[:TRANSFERRED]->(a:Account)
RETURN a.id AS acc_a, b.id AS acc_b, c.id AS acc_c
LIMIT 5;`,

  sybil_collisions: `MATCH (a1:Account)-[:USED_DEVICE]->(d:Device)<-[:USED_DEVICE]-(a2:Account)
WHERE a1.id < a2.id
RETURN a1.id AS acc_1, a2.id AS acc_2, d.fingerprint AS shared_hwid
LIMIT 5;`,

  frozen_registry: `MATCH (a:Account {status: 'FROZEN'})
RETURN a.id AS account, a.holder AS holder, a.status AS status, a.risk_score AS risk
ORDER BY a.risk_score DESC;`,
};

function loadCypherPreset(presetKey) {
  const query = CYPHER_PRESETS[presetKey];
  if (!query) return;
  document.getElementById('cypher-editor').value = query.trim();
  executeCypherQuery();
}

async function executeCypherQuery() {
  const query = document.getElementById('cypher-editor').value.trim();
  if (!query) {
    showToast('Empty Query', 'Enter openCypher query or click a preset pill', 'info');
    return;
  }

  const runBtn = document.getElementById('btn-run-cypher');
  const tableContainer = document.getElementById('cypher-results-table');
  const telemetryEl = document.getElementById('cypher-telemetry');

  runBtn.disabled = true;
  telemetryEl.textContent = 'Executing on FalkorDB...';
  tableContainer.innerHTML = `
    <div style="padding:20px; text-align:center; color:#00f0ff; font-family:'JetBrains Mono'; font-size:11px;">
      Running openCypher linear algebra query...
    </div>
  `;

  try {
    const t0 = performance.now();
    const res = await fetch('/api/graph/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query }),
    });
    const data = await res.json();
    const clientLatency = Math.round(performance.now() - t0);

    if (!data.ok) {
      telemetryEl.textContent = 'Error';
      telemetryEl.style.color = 'var(--red)';
      tableContainer.innerHTML = `
        <div style="padding:15px; color:#ff2d55; font-family:'JetBrains Mono'; font-size:11px;">
          ✕ Cypher Error: ${data.error}
        </div>
      `;
      return;
    }

    const execTime = data.execution_time_ms ? `${data.execution_time_ms}ms` : `${clientLatency}ms`;
    telemetryEl.textContent = `✓ ${data.row_count} rows in ${execTime}`;
    telemetryEl.style.color = 'var(--green)';

    if (!data.rows || data.rows.length === 0) {
      tableContainer.innerHTML = `
        <div style="padding:20px; text-align:center; color:#64748b; font-family:'JetBrains Mono'; font-size:11px;">
          (0 rows returned in ${execTime})
        </div>
      `;
      return;
    }

    let tableHtml = `<table class="data-table"><thead><tr>`;
    data.columns.forEach((col) => {
      tableHtml += `<th>${col}</th>`;
    });
    tableHtml += `</tr></thead><tbody>`;

    data.rows.forEach((row) => {
      tableHtml += `<tr>`;
      row.forEach((cell) => {
        const display = typeof cell === 'object' ? JSON.stringify(cell) : cell;
        tableHtml += `<td title="${display}">${display}</td>`;
      });
      tableHtml += `</tr>`;
    });
    tableHtml += `</tbody></table>`;

    tableContainer.innerHTML = tableHtml;
  } catch (err) {
    telemetryEl.textContent = 'Network Error';
    telemetryEl.style.color = 'var(--red)';
    tableContainer.innerHTML = `<div style="padding:15px; color:#ff2d55;">${err.message}</div>`;
  } finally {
    runBtn.disabled = false;
  }
}

// ============================================================================
// 8. SEED DATA WORKFLOW
// ============================================================================
async function seedGraphData() {
  const btn = document.getElementById('btn-seed-data');
  btn.disabled = true;
  btn.textContent = 'Seeding Graph...';

  try {
    const res = await fetch('/api/seed', { method: 'POST' });
    await res.json();

    state.activeDossier = null;
    state.focusedThreatId = null;
    resetGraphFocus();
    await refreshGraphData();

    // Reset left panel
    document.getElementById('threat-count-badge').textContent = '0 THREATS';
    document.getElementById('threats-feed').innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon" style="color:#00e676; border-color:rgba(0,230,118,0.3);">✓</div>
        <div style="font-weight:700; color:#fff;">Financial Network Seeded</div>
        <div class="empty-state-text">FalkorDB initialized with synthetic banking mesh, sanctions list, and fraud clusters. Ready to investigate!</div>
      </div>
    `;

    showToast('Synthetic Graph Seeded', 'Generated baseline accounts, smurfing paths, and rings in FalkorDB', 'success');
  } catch (err) {
    showToast('Seed Failed', err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path>
        <path d="M3 3v5h5"></path>
        <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"></path>
        <path d="M16 21h5v-5"></path>
      </svg>
      Seed Data
    `;
  }
}

// ============================================================================
// 9. AUTOMATED DEMO MODE (2-MINUTE WALKTHROUGH)
// ============================================================================
async function startDemoMode() {
  if (state.isDemoRunning) return;
  state.isDemoRunning = true;

  const banner = document.getElementById('demo-banner');
  const bannerText = document.getElementById('demo-narration-text');
  banner.style.display = 'flex';

  const setNarration = (text) => {
    bannerText.innerHTML = text;
  };

  try {
    // Step 1: Seed Graph
    setNarration('<strong>Step 1/5:</strong> Seeding financial banking graph in FalkorDB Cloud...');
    await seedGraphData();
    await sleep(2000);

    // Step 2: Overview of topology
    setNarration('<strong>Step 2/5:</strong> FalkorDB graph ready. Sub-millisecond openCypher engine active.');
    state.network.fit({ animation: { duration: 800, easingFunction: 'easeInOutQuad' } });
    await sleep(2200);

    // Step 3: Run autonomous AI agent
    setNarration('<strong>Step 3/5:</strong> Launching Autonomous Threat Investigator Agent...');
    await runInvestigation();
    await sleep(2400);

    // Step 4: Highlight Threat 1 (Sanctions Smurfing)
    if (state.activeDossier && state.activeDossier.findings.length > 0) {
      setNarration('<strong>Step 4/5:</strong> Detected 4-Hop OFAC Sanctions Smurfing Path. Freezing mules!');
      focusThreatTrail(0);
      switchTab('registry');
      await sleep(3500);

      // Highlight Threat 2 (Circular Ring)
      if (state.activeDossier.findings.length > 1) {
        setNarration('<strong>Structuring Detection:</strong> Identified circular money cycling ring (A → B → C → A).');
        focusThreatTrail(1);
        await sleep(3500);
      }

      // Highlight Threat 3 (Sybil Collisions)
      if (state.activeDossier.findings.length > 2) {
        setNarration('<strong>Sybil Hardware Farm:</strong> Multiple accounts sharing identical device fingerprint.');
        focusThreatTrail(2);
        await sleep(3500);
      }
    }

    // Step 5: Switch to Cypher Studio
    setNarration('<strong>Step 5/5:</strong> openCypher Studio — Live sub-millisecond graph query telemetry.');
    switchTab('cypher');
    loadCypherPreset('shortest_path');
    await sleep(3000);

    setNarration('✓ <strong>Demo Complete:</strong> All threats detected and neutralized on FalkorDB.');
    await sleep(3000);
  } catch (err) {
    showToast('Demo Interrupted', err.message, 'error');
  } finally {
    state.isDemoRunning = false;
    banner.style.display = 'none';
  }
}

// ============================================================================
// 10. SEARCH & AUTOCOMPLETE
// ============================================================================
function updateSearchAutocomplete() {
  const input = document.getElementById('node-search-input');
  const dropdown = document.getElementById('search-dropdown');

  input.oninput = (e) => {
    const q = e.target.value.trim().toLowerCase();
    if (!q) {
      dropdown.style.display = 'none';
      return;
    }

    const matches = state.rawNodes.filter(
      (n) => n.id.toLowerCase().includes(q) || (n.label && n.label.toLowerCase().includes(q))
    );

    if (matches.length === 0) {
      dropdown.innerHTML = `<div style="padding:10px; color:#64748b; font-size:11px;">No entities found</div>`;
      dropdown.style.display = 'block';
      return;
    }

    dropdown.innerHTML = matches
      .slice(0, 7)
      .map(
        (m) => `
        <div class="search-item" onclick="focusSingleNode('${m.id}'); document.getElementById('search-dropdown').style.display='none';">
          <span>${m.id}</span>
          <span style="color:#00f0ff; font-size:10px;">${m.group || 'Node'}</span>
        </div>
      `
      )
      .join('');
    dropdown.style.display = 'block';
  };

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.search-box')) {
      dropdown.style.display = 'none';
    }
  });
}

// ============================================================================
// 11. EVENT LISTENERS & HELPERS
// ============================================================================
function setupEventListeners() {
  // Top Buttons
  document.getElementById('btn-seed-data').addEventListener('click', seedGraphData);
  document.getElementById('btn-run-investigation').addEventListener('click', runInvestigation);
  document.getElementById('btn-demo-mode').addEventListener('click', startDemoMode);

  // Graph HUD Controls
  document.getElementById('btn-fit-screen').addEventListener('click', () => {
    state.network.fit({ animation: { duration: 600, easingFunction: 'easeInOutQuad' } });
  });

  document.getElementById('btn-toggle-physics').addEventListener('click', (e) => {
    state.physicsEnabled = !state.physicsEnabled;
    state.network.setOptions({ physics: { enabled: state.physicsEnabled } });
    e.currentTarget.classList.toggle('active', state.physicsEnabled);
    showToast('Physics Engine', state.physicsEnabled ? 'Simulation Enabled' : 'Simulation Frozen', 'info');
  });

  // Focus Reset Banner
  document.getElementById('btn-reset-focus').addEventListener('click', resetGraphFocus);

  // Drawer Close
  document.getElementById('btn-close-drawer').addEventListener('click', closeNodeDrawer);

  // Tabs
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Cypher Presets
  document.querySelectorAll('.preset-pill').forEach((pill) => {
    pill.addEventListener('click', () => loadCypherPreset(pill.dataset.preset));
  });

  // Cypher Run Button & Shortcut
  document.getElementById('btn-run-cypher').addEventListener('click', executeCypherQuery);
  document.getElementById('cypher-editor').addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      executeCypherQuery();
    }
  });
}

function showToast(title, message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
  toast.innerHTML = `
    <span style="font-weight:700; color:${type === 'success' ? 'var(--green)' : type === 'error' ? 'var(--red)' : 'var(--cyan)'};">${icon}</span>
    <div>
      <div style="font-weight:700; font-size:12px;">${title}</div>
      <div style="font-size:11px; color:#94a3b8;">${message}</div>
    </div>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
