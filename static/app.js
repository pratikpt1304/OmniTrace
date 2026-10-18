/**
 * OmniTrace Threat Cockpit — Enterprise Light Theme Engine
 * FalkorDB Graph Hacks (Track 01: Agents That Act on Connected Data)
 * Real-time SSE Agent Investigator, Vis-Network Canvas & GraphRAG Studio
 */

// Global State
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
  isStreaming: false,
  activeStream: null,
  liveFindings: [],
  liveActions: [],
  apiConnected: false,
  lastEngineMs: null,
  lastRoundtripMs: null,
  displayedCounts: { nodes: 0, edges: 0, threats: 0, frozen: 0 },
};

// ============================================================================
// 1. INITIALIZATION & NETWORK SETUP
// ============================================================================
document.addEventListener('DOMContentLoaded', async () => {
  initVisNetwork();
  setupEventListeners();
  checkApiHealth();
  await refreshGraphData();
  await checkAndLoadLatestDossier();

  // Periodic health check
  setInterval(checkApiHealth, 15000);
});

async function checkAndLoadLatestDossier() {
  try {
    const res = await fetch('/api/dossiers');
    const data = await res.json();
    if (data && data.dossiers && data.dossiers.length > 0) {
      const latest = data.dossiers[0];
      const invId = latest.investigation_id;
      if (invId) {
        const dRes = await fetch(`/api/dossiers/${encodeURIComponent(invId)}`);
        const dossier = await dRes.json();
        if (dossier && dossier.findings) {
          state.activeDossier = dossier;
          state.liveFindings = [];
          state.liveActions = dossier.proposed_actions || [];

          const liveContainer = document.getElementById('live-stream-container');
          if (liveContainer) liveContainer.style.display = 'flex';
          const placeholder = document.getElementById('empty-feed-placeholder');
          if (placeholder) placeholder.style.display = 'none';

          const findingsList = document.getElementById('live-findings-list');
          if (findingsList) findingsList.innerHTML = '';
          (dossier.findings || []).forEach((f) => addFindingDeduplicated(f));

          const streamLabel = document.getElementById('live-stream-label');
          if (streamLabel) {
            streamLabel.textContent = `DOSSIER LOADED (${invId})`;
            streamLabel.style.color = 'var(--text-primary)';
          }
          updateMetricsTab();
        }
      }
    }
  } catch (e) {
    // Graceful no-op if dossiers unavailable
  }
}

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
        face: 'Inter, -apple-system, sans-serif',
        color: '#0B0F14',
        size: 11,
        strokeWidth: 2,
        strokeColor: '#FFFFFF',
      },
      borderWidth: 2,
      shadow: {
        enabled: true,
        color: 'rgba(11, 15, 20, 0.08)',
        size: 8,
        x: 0,
        y: 2,
      },
    },
    edges: {
      arrows: {
        to: { enabled: true, scaleFactor: 0.65 },
      },
      color: {
        color: '#CBD5E1',
        highlight: '#0284C7',
        hover: '#0284C7',
      },
      font: {
        face: 'JetBrains Mono, monospace',
        size: 9,
        color: '#64748B',
        align: 'middle',
        background: 'transparent',
        strokeWidth: 2,
        strokeColor: '#FFFFFF',
      },
      smooth: {
        type: 'cubicBezier',
        forceDirection: 'none',
        roundness: 0.25,
      },
      width: 1.2,
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
      tooltipDelay: 120,
      hideEdgesOnDrag: false,
      keyboard: false,
    },
  };

  state.network = new vis.Network(container, data, options);

  // Network Event Handlers
  state.network.on('click', (params) => {
    if (params.nodes.length > 0) {
      inspectNode(params.nodes[0]);
    } else {
      closeNodeDrawer();
    }
  });

  state.network.on('doubleClick', (params) => {
    if (params.nodes.length > 0) {
      focusSingleNode(params.nodes[0]);
    }
  });
}

// ============================================================================
// 2. DATA SYNCHRONIZATION & HEALTH TELEMETRY
// ============================================================================
async function checkApiHealth() {
  const coldStartBanner = document.getElementById('cold-start-banner');
  // If health check takes > 1.5s, show cold start warmup notice
  const coldStartTimer = setTimeout(() => {
    if (!state.apiConnected && coldStartBanner) {
      coldStartBanner.style.display = 'flex';
    }
  }, 1500);

  try {
    const res = await fetch('/api/health');
    clearTimeout(coldStartTimer);
    if (coldStartBanner) coldStartBanner.style.display = 'none';

    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    const modeBadge = document.getElementById('ai-mode-badge');
    const demoBanner = document.getElementById('public-demo-banner');

    if (res.ok) {
      const data = await res.json();
      state.apiConnected = true;
      if (dot) dot.className = 'status-dot';
      if (text) text.textContent = 'FalkorDB Online';

      if (demoBanner) {
        demoBanner.style.display = 'none';
      }

      const aiModePill = document.getElementById('ai-mode-pill');
      if (aiModePill) aiModePill.style.display = 'none';
      if (modeBadge) {
        modeBadge.textContent = '';
      }
    } else {
      throw new Error('Health check non-200');
    }
  } catch (err) {
    clearTimeout(coldStartTimer);
    state.apiConnected = false;
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    if (dot) dot.className = 'status-dot disconnected';
    if (text) text.textContent = 'Disconnected';
  }
}

async function refreshGraphData() {
  try {
    const res = await fetch('/api/graph/state');
    const data = await res.json();

    state.rawNodes = data.nodes || [];
    state.rawEdges = data.edges || [];

    // Parse frozen accounts & style nodes for light theme
    state.frozenAccounts.clear();
    const styledNodes = state.rawNodes.map((n) => {
      const isSanction = n.group === 'SanctionedEntity';
      const isDevice = n.group === 'Device';
      const isIP = n.group === 'IPAddress';
      const isFrozen = (n.color && n.color.background === '#ff3300') || (n.label && n.label.includes('FROZEN'));

      if (isFrozen) {
        state.frozenAccounts.add(n.id);
      }

      let shape = 'dot';
      let size = 18;
      let label = n.label || n.id;
      let color = {
        background: '#0284C7', // Sky Blue for standard accounts
        border: '#0369A1',
        highlight: { background: '#0284C7', border: '#0C4A6E' },
      };

      if (isSanction) {
        shape = 'hexagon';
        size = 26;
        color = {
          background: '#C8102E', // Cherry red
          border: '#991B1B',
          highlight: { background: '#A00C24', border: '#7F1D1D' },
        };
      } else if (isFrozen) {
        label = `🔒 ${n.id}\n[FROZEN]`;
        color = {
          background: '#C8102E',
          border: '#991B1B',
          highlight: { background: '#A00C24', border: '#7F1D1D' },
        };
      } else if (isDevice) {
        shape = 'square';
        size = 16;
        color = {
          background: '#475569', // Slate
          border: '#334155',
          highlight: { background: '#1E293B', border: '#0F172A' },
        };
      } else if (isIP) {
        shape = 'diamond';
        size = 16;
        color = {
          background: '#4F46E5', // Indigo
          border: '#4338CA',
          highlight: { background: '#3730A3', border: '#312E81' },
        };
      } else if (n.group === 'FlaggedAccount') {
        color = {
          background: '#D97706', // Amber
          border: '#B45309',
          highlight: { background: '#B45309', border: '#78350F' },
        };
      }

      // Rich enterprise light tooltip
      const tooltip = `
        <div style="background:#FFFFFF; border:1px solid #E2E8F0; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1); padding:8px 12px; border-radius:6px; font-family:'JetBrains Mono', monospace; font-size:11px; color:#0B0F14;">
          <div style="font-weight:700; color:#0284C7; margin-bottom:4px;">${escapeHtml(n.id)}</div>
          <div style="color:#475569;">Type: <span style="color:#0B0F14; font-weight:600;">${escapeHtml(n.group || 'Account')}</span></div>
          <div style="color:#475569;">Status: <span style="color:${isFrozen ? '#C8102E' : '#15803D'}; font-weight:700;">${isFrozen ? 'FROZEN' : 'ACTIVE'}</span></div>
        </div>
      `;

      return {
        ...n,
        shape,
        size,
        label,
        color,
        title: tooltip,
        borderWidth: isFrozen || isSanction ? 2.5 : 1.5,
      };
    });

    state.nodesDataSet.clear();
    state.nodesDataSet.add(styledNodes);

    // Style edges: threat edges cherry red, normal edges light grey
    const styledEdges = state.rawEdges.map((e) => {
      const isThreat = e.color && (e.color.color === '#ff0055' || e.color === '#ff0055');
      return {
        ...e,
        color: isThreat ? { color: '#C8102E' } : { color: '#CBD5E1' },
        width: isThreat ? 2.2 : 1.2,
      };
    });

    state.edgesDataSet.clear();
    state.edgesDataSet.add(styledEdges);

    updateTelemetryHeader();
    updateMetricsTab();
    updateFreezeRegistry();
    updateSearchAutocomplete();

    // Toggle empty state placeholder in feed
    const emptyState = document.getElementById('empty-feed-placeholder');
    if (emptyState && state.rawNodes.length > 0 && !state.activeDossier && !state.isStreaming) {
      emptyState.innerHTML = `
        <div class="empty-state-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
          </svg>
        </div>
        <div class="empty-state-title">Graph Loaded (${state.rawNodes.length} Nodes)</div>
        <div class="empty-state-text">FalkorDB in-memory mesh active. Click <strong>Run Investigation</strong> to begin autonomous multi-hop threat analysis.</div>
      `;
    }
  } catch (err) {
    showToast('Graph Sync Error', err.message, 'error');
  }
}

function updateTelemetryHeader() {
  const nodeCountEl = document.getElementById('header-node-count');
  const edgeCountEl = document.getElementById('header-edge-count');
  if (nodeCountEl) nodeCountEl.textContent = state.rawNodes.length;
  if (edgeCountEl) edgeCountEl.textContent = state.rawEdges.length;

  // Only display measured latencies
  const enginePill = document.getElementById('pill-engine-latency');
  const engineVal = document.getElementById('header-engine-latency');
  if (enginePill && engineVal) {
    if (state.lastEngineMs != null) {
      engineVal.textContent = `${state.lastEngineMs}ms`;
      enginePill.style.display = 'inline-flex';
    } else {
      enginePill.style.display = 'none';
    }
  }

  const roundtripPill = document.getElementById('pill-roundtrip-latency');
  const roundtripVal = document.getElementById('header-roundtrip-latency');
  if (roundtripPill && roundtripVal) {
    if (state.lastRoundtripMs != null) {
      roundtripVal.textContent = `${state.lastRoundtripMs}ms`;
      roundtripPill.style.display = 'inline-flex';
    } else {
      roundtripPill.style.display = 'none';
    }
  }
}

function updateHeaderLatency(engineMs, roundtripMs) {
  if (engineMs != null && !isNaN(engineMs)) {
    state.lastEngineMs = parseFloat(engineMs);
  }
  if (roundtripMs != null && !isNaN(roundtripMs)) {
    state.lastRoundtripMs = parseFloat(roundtripMs);
  }
  updateTelemetryHeader();
}

// ============================================================================
// 3. INVESTIGATION: REAL-TIME SSE STREAM & FALLBACK RUNNER
// ============================================================================
function startLiveInvestigation() {
  if (state.isStreaming) return;
  state.isStreaming = true;

  const liveBtn = document.getElementById('btn-live-stream');
  const cancelBtn = document.getElementById('btn-cancel-stream');

  if (liveBtn) {
    liveBtn.disabled = true;
    liveBtn.innerHTML = `
      <svg style="animation:spin 1s infinite linear;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
        <path d="M12 2a10 10 0 0 1 10 10"></path>
      </svg>
      Investigating...
    `;
  }
  if (cancelBtn) {
    cancelBtn.style.display = 'inline-flex';
  }

  // Initialize live feed
  const feed = document.getElementById('threats-feed');
  feed.innerHTML = `
    <div id="live-stream-header" class="live-stream-status">
      <span style="display:flex; align-items:center; gap:6px;">
        <span class="live-pulse-dot"></span>
        <span id="live-stream-label">AUTONOMOUS INVESTIGATION IN PROGRESS</span>
      </span>
      <span id="live-step-counter" style="color:var(--sky-primary); font-weight:700;">STEP 0/12</span>
    </div>
    <div id="live-thinking-box" style="display:none;"></div>
    <div id="live-tool-steps" style="display:flex; flex-direction:column; gap:6px;"></div>
    <div id="live-findings-list" style="display:flex; flex-direction:column; gap:10px;"></div>
  `;

  state.activeDossier = {
    investigation_id: 'inv_live_' + Date.now(),
    findings: [],
    proposed_actions: [],
    enforcement_actions: [],
  };
  state.liveFindings = [];
  state.liveActions = [];
  updateThreatCountBadge();

  // Connect to SSE stream
  try {
    const evtSource = new EventSource('/api/investigate/stream?auto_freeze=false');
    state.activeStream = evtSource;

    evtSource.addEventListener('thinking', (e) => {
      try {
        const data = JSON.parse(e.data);
        const thinkingBox = document.getElementById('live-thinking-box');
        if (thinkingBox) {
          thinkingBox.style.display = 'block';
          thinkingBox.className = 'thinking-card';
          thinkingBox.innerHTML = `
            <div class="thinking-header">Agent Reasoning (Step ${data.step || 1})</div>
            <div class="thinking-text">${escapeHtml(data.text)}</div>
          `;
        }
        const stepCounter = document.getElementById('live-step-counter');
        if (stepCounter && data.step) {
          stepCounter.textContent = `STEP ${data.step}/12`;
        }
      } catch (err) {
        console.error('Error handling thinking event', err);
      }
    });

    evtSource.addEventListener('tool_call', (e) => {
      try {
        const data = JSON.parse(e.data);
        const toolSteps = document.getElementById('live-tool-steps');
        if (toolSteps) {
          const cardId = `tool-call-${data.step}-${data.tool}`;
          if (!document.getElementById(cardId)) {
            const argsStr = Object.entries(data.args || {})
              .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
              .join(', ');
            const card = document.createElement('div');
            card.id = cardId;
            card.className = 'tool-step-card';
            card.innerHTML = `
              <div class="tool-step-top">
                <span class="tool-name-badge">${escapeHtml(data.tool)}</span>
                <span class="tool-timing-badge" id="timing-${data.step}-${data.tool}">Running...</span>
              </div>
              <div style="color:#64748B; font-size:10px;">Args: (${escapeHtml(argsStr)})</div>
              <div class="tool-result-summary" id="result-${data.step}-${data.tool}">Executing openCypher query...</div>
            `;
            toolSteps.appendChild(card);
            card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        }
        const stepCounter = document.getElementById('live-step-counter');
        if (stepCounter && data.step) {
          stepCounter.textContent = `STEP ${data.step}/12`;
        }
      } catch (err) {
        console.error('Error handling tool_call event', err);
      }
    });

    evtSource.addEventListener('tool_result', (e) => {
      try {
        const data = JSON.parse(e.data);
        const resEl = document.getElementById(`result-${data.step}-${data.tool}`);
        const timingEl = document.getElementById(`timing-${data.step}-${data.tool}`);

        if (resEl) {
          resEl.textContent = data.summary || 'Query finished';
        }
        if (timingEl) {
          timingEl.textContent = `${data.engine_ms != null ? data.engine_ms + 'ms engine • ' : ''}${data.latency_ms || 0}ms`;
        }
        updateHeaderLatency(data.engine_ms, data.latency_ms);
      } catch (err) {
        console.error('Error handling tool_result event', err);
      }
    });

    evtSource.addEventListener('finding', (e) => {
      try {
        const finding = JSON.parse(e.data);
        addFindingDeduplicated(finding);
      } catch (err) {
        console.error('Error handling finding event', err);
      }
    });

    evtSource.addEventListener('proposed_action', (e) => {
      try {
        const action = JSON.parse(e.data);
        state.liveActions.push(action);
        if (state.activeDossier) {
          state.activeDossier.proposed_actions.push(action);
        }
        const findingsList = document.getElementById('live-findings-list');
        if (findingsList) {
          const actionHtml = renderProposedActionCard(action, state.liveActions.length - 1);
          findingsList.insertAdjacentHTML('beforeend', actionHtml);
        }
      } catch (err) {
        console.error('Error handling proposed_action event', err);
      }
    });

    evtSource.addEventListener('done', (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.dossier) {
          state.activeDossier = data.dossier;
        }
        const streamLabel = document.getElementById('live-stream-label');
        if (streamLabel) {
          streamLabel.textContent = 'INVESTIGATION COMPLETED';
          streamLabel.style.color = 'var(--green-success)';
        }
        refreshGraphData();
        showToast('Investigation Complete', `Identified ${state.liveFindings.length} distinct threats.`, 'success');
      } catch (err) {
        console.error('Error handling done event', err);
      } finally {
        cleanupStream();
      }
    });

    evtSource.onerror = (e) => {
      // If SSE fails or disconnected, notify user and fallback to direct POST /api/investigate
      cleanupStream();
      if (state.liveFindings.length === 0) {
        showToast('Stream Interrupted', 'Live stream disconnected; falling back to direct investigation...', 'info');
        runDirectInvestigationFallback();
      } else {
        showToast('Stream Completed', 'Investigation stream closed. You can review findings or click Run Investigation to retry.', 'info');
        refreshGraphData();
      }
    };
  } catch (err) {
    cleanupStream();
    showToast('Stream Error', `${err.message}. Retrying via direct API fallback...`, 'error');
    runDirectInvestigationFallback();
  }
}

async function runDirectInvestigationFallback() {
  try {
    showToast('Direct Investigation', 'Connecting to API investigator...', 'info');
    const res = await fetch('/api/investigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auto_freeze: false }),
    });
    const dossier = await res.json();
    state.activeDossier = dossier;
    state.liveFindings = [];
    state.liveActions = dossier.proposed_actions || [];

    const findingsList = document.getElementById('live-findings-list');
    if (findingsList) findingsList.innerHTML = '';

    (dossier.findings || []).forEach((f) => addFindingDeduplicated(f));

    const streamLabel = document.getElementById('live-stream-label');
    if (streamLabel) {
      streamLabel.textContent = 'INVESTIGATION COMPLETED';
      streamLabel.style.color = 'var(--green-success)';
    }
    refreshGraphData();
    showToast('Investigation Complete', `Dossier compiled with ${state.liveFindings.length} threats`, 'success');
  } catch (err) {
    showToast('Investigation Failed', err.message, 'error');
  } finally {
    cleanupStream();
  }
}

function cleanupStream() {
  if (state.activeStream) {
    state.activeStream.close();
    state.activeStream = null;
  }
  state.isStreaming = false;

  const liveBtn = document.getElementById('btn-live-stream');
  const cancelBtn = document.getElementById('btn-cancel-stream');

  if (liveBtn) {
    liveBtn.disabled = false;
    liveBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polygon points="5 3 19 12 5 21 5 3"></polygon>
      </svg>
      Run Investigation
    `;
  }
  if (cancelBtn) {
    cancelBtn.style.display = 'none';
  }
}

function cancelInvestigation() {
  if (state.isStreaming) {
    cleanupStream();
    showToast('Investigation Cancelled', 'Operation halted by user.', 'info');
    const streamLabel = document.getElementById('live-stream-label');
    if (streamLabel) {
      streamLabel.textContent = 'INVESTIGATION CANCELLED';
      streamLabel.style.color = 'var(--amber-warning)';
    }
  }
}

// ============================================================================
// 4. FINDINGS DEDUPLICATION & CARD RENDERING
// ============================================================================
function isDuplicateFinding(newF, existingF) {
  if (newF.type !== existingF.type) return false;

  if (newF.type === 'CIRCULAR_STRUCTURING_RING') {
    const r1 = [...(newF.ring_members || [])].sort().join(',');
    const r2 = [...(existingF.ring_members || [])].sort().join(',');
    return r1 && r2 && r1 === r2;
  }

  if (newF.type === 'SYBIL_DEVICE_FINGERPRINT_COLLISION') {
    if (newF.device_fingerprint && existingF.device_fingerprint) {
      return newF.device_fingerprint === existingF.device_fingerprint;
    }
    const a1 = [...(newF.accounts_sharing || [])].sort().join(',');
    const a2 = [...(existingF.accounts_sharing || [])].sort().join(',');
    return a1 && a2 && a1 === a2;
  }

  if (newF.type === 'OFAC_SANCTIONS_EXPOSURE') {
    return newF.source_account === existingF.source_account && newF.sanctioned_entity === existingF.sanctioned_entity;
  }

  return false;
}

function addFindingDeduplicated(finding) {
  // Check if identical finding already recorded
  const exists = state.liveFindings.some((existing) => isDuplicateFinding(finding, existing));
  if (exists) return;

  state.liveFindings.push(finding);
  if (state.activeDossier && !state.activeDossier.findings.includes(finding)) {
    state.activeDossier.findings.push(finding);
  }

  updateThreatCountBadge();

  const findingsList = document.getElementById('live-findings-list');
  if (findingsList) {
    const idx = state.liveFindings.length - 1;
    const cardHtml = renderSingleThreatCard(finding, idx);
    findingsList.insertAdjacentHTML('beforeend', cardHtml);
  }

  // Isolate finding on canvas
  focusFindingNodes(finding);
  updateHeaderLatency(finding.engine_ms, finding.roundtrip_ms || finding.latency_ms);
  showToast('Threat Identified', `${formatThreatTitle(finding.type, finding)} caught on graph`, 'error');
}

function updateThreatCountBadge() {
  const badge = document.getElementById('threat-count-badge');
  if (badge) {
    const count = state.liveFindings.length;
    badge.textContent = `${count} ${count === 1 ? 'Threat' : 'Threats'}`;
    badge.classList.toggle('active', count > 0);
  }
}

function formatThreatTitle(type, finding) {
  switch (type) {
    case 'OFAC_SANCTIONS_EXPOSURE': {
      const hops = finding?.hop_count || (finding?.path_trail ? finding.path_trail.split(' -> ').length - 1 : 3);
      return `OFAC Sanctions Exposure (${hops} Hops)`;
    }
    case 'CIRCULAR_STRUCTURING_RING': {
      const nodeCount = finding?.ring_members?.length || (finding?.cycle_path ? finding.cycle_path.split(' -> ').length - 1 : 3);
      return `Circular Structuring Loop (${nodeCount} Nodes)`;
    }
    case 'SYBIL_DEVICE_FINGERPRINT_COLLISION': {
      const memberCount = finding?.member_count || finding?.accounts_sharing?.length || 2;
      return `Sybil Hardware Cluster (${memberCount} Accounts)`;
    }
    default:
      return (type || 'THREAT').replace(/_/g, ' ');
  }
}

function renderSingleThreatCard(finding, idx) {
  const isCritical = finding.severity === 'CRITICAL';
  const cardClass = isCritical ? 'threat-card critical' : 'threat-card high';
  const severityBadgeClass = isCritical ? 'severity-badge critical' : 'severity-badge high';

  let pathChips = [];
  if (finding.path_trail) {
    pathChips = finding.path_trail.split(' -> ').map((s) => s.trim());
  } else if (finding.cycle_path) {
    pathChips = finding.cycle_path.split(' -> ').map((s) => s.trim());
  } else if (finding.accounts_sharing) {
    pathChips = [...finding.accounts_sharing];
    if (finding.device_fingerprint) pathChips.push(finding.device_fingerprint);
  } else if (finding.ring_members) {
    pathChips = [...finding.ring_members];
  }

  const chipsHtml = pathChips
    .map((chip, cIdx) => {
      const isSanction = chip.includes('SANCTION');
      const chipClass = isSanction ? 'path-chip sanction' : 'path-chip';
      return `
        <span class="${chipClass}" onclick="event.stopPropagation(); focusSingleNode('${escapeHtml(chip)}')">${escapeHtml(chip)}</span>
        ${cIdx < pathChips.length - 1 ? '<span class="path-arrow">→</span>' : ''}
      `;
    })
    .join('');

  // Confidence badge
  const confidenceBadge = finding.confidence
    ? `<span style="font-size:10px; color:#64748B; font-family:'JetBrains Mono';">${Math.round(finding.confidence * 100)}% Conf.</span>`
    : '';

  // Only display latency if measured from API
  let latencyHtml = '';
  if (finding.engine_ms != null) {
    latencyHtml = `<span class="card-latency">${finding.engine_ms}ms engine</span>`;
  } else if (finding.latency_ms != null) {
    latencyHtml = `<span class="card-latency">${finding.latency_ms}ms</span>`;
  }

  const evidenceDetails = `
    <details class="threat-evidence-details" style="margin-top:6px; font-size:11px; color:#475569; cursor:pointer;" onclick="event.stopPropagation();">
      <summary style="color:#0284C7; font-family:'JetBrains Mono'; font-weight:600; outline:none; user-select:none;">Evidence & Cypher Telemetry</summary>
      <div style="margin-top:6px; padding:8px 10px; background:#F8FAFC; border:1px solid #E2E8F0; border-radius:6px; font-family:'JetBrains Mono'; font-size:10px; line-height:1.45;">
        ${finding.cypher_query ? `<div style="margin-bottom:4px;"><span style="color:#64748B;">QUERY:</span> <code style="color:#0369A1;">${escapeHtml(finding.cypher_query)}</code></div>` : ''}
        ${finding.amounts && finding.amounts.length ? `<div style="margin-bottom:4px;"><span style="color:#64748B;">AMOUNTS:</span> <span style="color:#15803D;">$${finding.amounts.join(' → $')}</span></div>` : ''}
        ${finding.cycle_path ? `<div style="margin-bottom:4px;"><span style="color:#64748B;">CYCLE:</span> ${escapeHtml(finding.cycle_path)}</div>` : ''}
        ${finding.device_fingerprint ? `<div style="margin-bottom:4px;"><span style="color:#64748B;">DEVICE ID:</span> <span style="color:#4F46E5;">${escapeHtml(finding.device_fingerprint)}</span></div>` : ''}
        ${finding.evidence ? `<div><span style="color:#64748B;">EVIDENCE:</span> ${escapeHtml(typeof finding.evidence === 'object' ? JSON.stringify(finding.evidence) : finding.evidence)}</div>` : ''}
      </div>
    </details>
  `;

  return `
    <div class="${cardClass}" id="card-threat-${idx}" onclick="focusThreatTrail(${idx})">
      <div class="card-top">
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="${severityBadgeClass}">${escapeHtml(finding.severity)}</span>
          ${confidenceBadge}
        </div>
        ${latencyHtml}
      </div>
      <div class="card-title">${formatThreatTitle(finding.type, finding)}</div>
      <div class="card-reasoning">${escapeHtml(finding.reasoning)}</div>
      ${pathChips.length > 0 ? `<div class="path-trail-container">${chipsHtml}</div>` : ''}
      ${evidenceDetails}
    </div>
  `;
}

function renderProposedActionCard(action, idx) {
  const accId = escapeHtml(action.account_id || '');
  const reason = escapeHtml(action.reason || 'Containment proposed by threat policy');
  const conf = action.confidence ? `${Math.round(action.confidence * 100)}% Conf.` : '';

  return `
    <div class="proposed-action-card" id="card-action-${idx}">
      <div class="action-top">
        <span class="action-badge">PROPOSED ACTION</span>
        <span style="font-size:10px; color:#64748B; font-family:'JetBrains Mono';">${conf}</span>
      </div>
      <div class="action-account">Lockout ${accId}</div>
      <div class="action-reason">${reason}</div>
      <div class="action-btn-row">
        <button class="btn-approve" onclick="approveAction('${accId}', '${reason}', this)">
          Approve Freeze
        </button>
        <button class="btn-reject" onclick="rejectAction('${accId}', this)">
          Reject
        </button>
      </div>
    </div>
  `;
}

async function approveAction(accountId, reason, btnEl) {
  try {
    btnEl.disabled = true;
    btnEl.textContent = 'Freezing...';

    const res = await fetch('/api/actions/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_id: accountId, reason: reason }),
    });
    const data = await res.json();
    if (data.ok) {
      btnEl.className = 'btn-approve approved';
      btnEl.innerHTML = '✓ Frozen & Enforced';

      const parent = btnEl.closest('.action-btn-row');
      if (parent) {
        const rejBtn = parent.querySelector('.btn-reject');
        if (rejBtn) rejBtn.style.display = 'none';
      }

      showToast('Enforcement Complete', `Account ${accountId} locked in FalkorDB`, 'success');
      await refreshGraphData();
    } else {
      throw new Error(data.error || 'Approval failed');
    }
  } catch (err) {
    btnEl.disabled = false;
    btnEl.textContent = 'Retry Approve';
    showToast('Enforcement Error', err.message, 'error');
  }
}

async function rejectAction(accountId, btnEl) {
  try {
    btnEl.disabled = true;
    btnEl.textContent = 'Rejecting...';

    const res = await fetch('/api/actions/reject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_id: accountId, reason: 'Operator rejected containment freeze' }),
    });
    const data = await res.json();
    if (data.ok) {
      btnEl.textContent = '✕ Dismissed by Operator';
      btnEl.style.color = 'var(--text-muted)';
      btnEl.style.borderColor = 'var(--border-light)';

      const parent = btnEl.closest('.action-btn-row');
      if (parent) {
        const appBtn = parent.querySelector('.btn-approve');
        if (appBtn) appBtn.style.display = 'none';
      }
      showToast('Action Dismissed', `Proposed freeze on ${accountId} rejected`, 'info');
    } else {
      throw new Error(data.error || 'Failed to reject action');
    }
  } catch (err) {
    btnEl.disabled = false;
    btnEl.textContent = 'Reject';
    showToast('Reject Error', err.message, 'error');
  }
}

// ============================================================================
// 5. GRAPH FOCUS, HIGHLIGHT & DIMMING ENGINE
// ============================================================================
function focusThreatTrail(threatIdx) {
  const finding = state.liveFindings[threatIdx] || (state.activeDossier && state.activeDossier.findings[threatIdx]);
  if (!finding) return;
  state.focusedThreatId = threatIdx;

  document.querySelectorAll('.threat-card').forEach((c, idx) => {
    if (idx === threatIdx) {
      c.classList.add('focused');
      c.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } else {
      c.classList.remove('focused');
    }
  });

  focusFindingNodes(finding);
}

function focusFindingNodes(finding) {
  let targetNodeIds = [];
  if (finding.path_trail) {
    targetNodeIds = finding.path_trail.split(' -> ').map((s) => s.trim());
  } else if (finding.cycle_path) {
    targetNodeIds = finding.cycle_path.split(' -> ').map((s) => s.trim());
  } else if (finding.accounts_sharing) {
    targetNodeIds = [...finding.accounts_sharing];
    if (finding.device_fingerprint) targetNodeIds.push(finding.device_fingerprint);
  } else if (finding.ring_members) {
    targetNodeIds = [...finding.ring_members];
  } else if (finding.path_nodes) {
    targetNodeIds = finding.path_nodes.map((n) => (typeof n === 'object' ? n.id : n));
  }

  if (targetNodeIds.length === 0) return;
  highlightNodeSet(targetNodeIds, formatThreatTitle(finding.type, finding));
}

function highlightNodeSet(targetNodeIds, title) {
  const targetSet = new Set(targetNodeIds);

  const updateNodes = [];
  state.nodesDataSet.forEach((node) => {
    const isTarget = targetSet.has(node.id);
    updateNodes.push({
      id: node.id,
      opacity: isTarget ? 1.0 : 0.15,
      font: {
        color: isTarget ? '#0B0F14' : 'rgba(11, 15, 20, 0.25)',
      },
      shadow: isTarget
        ? { enabled: true, color: 'rgba(2, 132, 199, 0.35)', size: 14, x: 0, y: 3 }
        : { enabled: false },
    });
  });
  state.nodesDataSet.update(updateNodes);

  // Dim edges not in threat path
  const updateEdges = [];
  state.edgesDataSet.forEach((edge) => {
    const isBetween = targetSet.has(edge.from) && targetSet.has(edge.to);
    updateEdges.push({
      id: edge.id,
      color: isBetween ? { color: '#C8102E' } : { color: '#E2E8F0' },
      width: isBetween ? 2.5 : 1,
    });
  });
  state.edgesDataSet.update(updateEdges);

  // Show focus banner
  const banner = document.getElementById('focus-banner');
  const bannerText = document.getElementById('focus-banner-text');
  if (banner && bannerText) {
    bannerText.textContent = `Isolated: ${title} (${targetNodeIds.length} Nodes)`;
    banner.style.display = 'flex';
  }

  // Smooth camera zoom
  state.network.fit({
    nodes: targetNodeIds,
    animation: { duration: 500, easingFunction: 'easeInOutQuad' },
  });
}

function focusSingleNode(nodeId) {
  if (!state.network) return;
  state.network.focus(nodeId, {
    scale: 1.3,
    animation: { duration: 500, easingFunction: 'easeInOutQuad' },
  });
  inspectNode(nodeId);
}

function resetGraphFocus() {
  state.focusedThreatId = null;
  document.querySelectorAll('.threat-card').forEach((c) => c.classList.remove('focused'));

  const resetNodes = [];
  state.nodesDataSet.forEach((node) => {
    resetNodes.push({
      id: node.id,
      opacity: 1.0,
      font: { color: '#0B0F14' },
      shadow: { enabled: true, color: 'rgba(11, 15, 20, 0.08)', size: 8, x: 0, y: 2 },
    });
  });
  state.nodesDataSet.update(resetNodes);

  const resetEdges = [];
  state.edgesDataSet.forEach((edge) => {
    resetEdges.push({
      id: edge.id,
      color: null,
      width: 1.2,
    });
  });
  state.edgesDataSet.update(resetEdges);

  const banner = document.getElementById('focus-banner');
  if (banner) banner.style.display = 'none';

  state.network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
}

// ============================================================================
// 6. NODE INSPECTION DRAWER
// ============================================================================
function inspectNode(nodeId) {
  const node = state.rawNodes.find((n) => n.id === nodeId);
  if (!node) return;

  const drawer = document.getElementById('node-drawer');
  const typeEl = document.getElementById('drawer-node-type');
  const idEl = document.getElementById('drawer-node-id');
  const statusEl = document.getElementById('drawer-node-status');
  const riskEl = document.getElementById('drawer-node-risk');
  const actionsEl = document.getElementById('drawer-actions');

  const isFrozen = state.frozenAccounts.has(nodeId);
  const isSanction = node.group === 'SanctionedEntity';

  typeEl.textContent = node.group || 'Account Entity';
  idEl.textContent = nodeId;

  statusEl.textContent = isFrozen ? 'FROZEN (LOCKED)' : isSanction ? 'SANCTIONED (OFAC TARGET)' : 'ACTIVE';
  statusEl.style.color = isFrozen || isSanction ? 'var(--cherry-danger)' : 'var(--green-success)';

  const riskScore = node.risk_score != null ? node.risk_score : isSanction ? 100 : isFrozen ? 95 : 15;
  riskEl.textContent = `${riskScore} / 100`;

  let actionHtml = '';
  if (node.group === 'Account' || !node.group) {
    if (isFrozen) {
      actionHtml = `
        <button class="btn btn-secondary" style="width:100%; border-color:var(--green-border); color:var(--green-success);" onclick="unfreezeAccount('${escapeHtml(nodeId)}')">
          ✓ Unfreeze Account
        </button>
      `;
    } else {
      actionHtml = `
        <button class="btn btn-danger" style="width:100%;" onclick="freezeAccountDirect('${escapeHtml(nodeId)}')">
          Lockout Account
        </button>
      `;
    }
  }

  actionsEl.innerHTML = actionHtml;
  drawer.classList.add('open');
}

function closeNodeDrawer() {
  const drawer = document.getElementById('node-drawer');
  if (drawer) drawer.classList.remove('open');
}

async function freezeAccountDirect(accountId) {
  try {
    const res = await fetch('/api/freeze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_id: accountId, reason: 'Operator manual lockout' }),
    });
    const data = await res.json();
    if (data.success || data.ok) {
      showToast('Account Frozen', `Account ${accountId} locked in FalkorDB`, 'error');
      await refreshGraphData();
      inspectNode(accountId);
    } else {
      throw new Error(data.error || 'Failed to freeze account');
    }
  } catch (err) {
    showToast('Freeze Failed', err.message, 'error');
  }
}

async function unfreezeAccount(accountId) {
  try {
    const res = await fetch('/api/account/unfreeze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_id: accountId, actor: 'human_operator' }),
    });
    const data = await res.json();
    if (data.ok) {
      showToast('Account Restored', `Account ${accountId} is now active`, 'success');
      await refreshGraphData();
      inspectNode(accountId);
    } else {
      throw new Error(data.error || 'Failed to unfreeze account');
    }
  } catch (err) {
    showToast('Unfreeze Failed', err.message, 'error');
  }
}

// ============================================================================
// 7. TABS, METRICS & COUNT-UP ANIMATION
// ============================================================================
function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === tabName);
  });
  document.querySelectorAll('.tab-pane').forEach((p) => {
    p.classList.toggle('active', p.id === `tab-pane-${tabName}`);
  });
  if (tabName === 'history') {
    loadInvestigationsHistory();
  }
}

function animateCountUp(el, start, end, duration = 350) {
  if (!el) return;
  if (typeof start !== 'number' || isNaN(start)) start = 0;
  if (typeof end !== 'number' || isNaN(end)) end = 0;
  if (start === end || duration <= 0) {
    el.textContent = end;
    return;
  }
  const startTime = performance.now();
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easeOutQuad = 1 - (1 - progress) * (1 - progress);
    const current = Math.round(start + (end - start) * easeOutQuad);
    el.textContent = Math.max(0, current);
    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      el.textContent = end;
    }
  }
  requestAnimationFrame(update);
}

function updateMetricsTab() {
  const statNodes = document.getElementById('stat-nodes');
  const statEdges = document.getElementById('stat-edges');
  const statThreats = document.getElementById('stat-threats');
  const statFrozen = document.getElementById('stat-frozen');

  const targetNodes = state.rawNodes.length;
  const targetEdges = state.rawEdges.length;
  const targetThreats = state.liveFindings.length || (state.activeDossier ? state.activeDossier.findings.length : 0);
  const targetFrozen = state.frozenAccounts.size;

  animateCountUp(statNodes, state.displayedCounts.nodes, targetNodes);
  animateCountUp(statEdges, state.displayedCounts.edges, targetEdges);
  animateCountUp(statThreats, state.displayedCounts.threats, targetThreats);
  animateCountUp(statFrozen, state.displayedCounts.frozen, targetFrozen);

  state.displayedCounts = {
    nodes: targetNodes,
    edges: targetEdges,
    threats: targetThreats,
    frozen: targetFrozen,
  };
}

function updateFreezeRegistry() {
  const listEl = document.getElementById('freeze-registry-list');
  const countEl = document.getElementById('freeze-registry-count');
  if (!listEl) return;

  const frozenArray = Array.from(state.frozenAccounts);
  if (countEl) countEl.textContent = `${frozenArray.length} ${frozenArray.length === 1 ? 'Frozen' : 'Frozen'}`;

  if (frozenArray.length === 0) {
    listEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </div>
        <div class="empty-state-title">No Frozen Accounts</div>
        <div class="empty-state-text">No accounts currently locked. Run the autonomous investigation to detect and contain compromised mules.</div>
      </div>
    `;
    return;
  }

  let html = '';
  frozenArray.forEach((accId) => {
    html += `
      <div class="freeze-item">
        <div>
          <div class="freeze-item-id">🔒 ${escapeHtml(accId)}</div>
          <div class="freeze-item-reason">Containment lockout active</div>
        </div>
        <button class="btn-unfreeze" onclick="unfreezeAccount('${escapeHtml(accId)}')">Unfreeze</button>
      </div>
    `;
  });

  listEl.innerHTML = html;
}

// Audit Chain Verification
async function verifyAuditChain() {
  const resultEl = document.getElementById('audit-verification-result');
  const btn = document.getElementById('btn-verify-audit');
  if (resultEl) resultEl.textContent = 'Verifying SHA-256 blockchain...';
  if (btn) btn.disabled = true;

  try {
    const res = await fetch('/api/audit/verify');
    const data = await res.json();
    if (data.valid) {
      if (resultEl) {
        resultEl.style.color = 'var(--green-success)';
        resultEl.textContent = `✓ Passed: ${data.verified_count} blocks verified without tampering.`;
      }
      showToast('Audit Verified', `${data.verified_count} blocks cryptographically verified`, 'success');
    } else {
      if (resultEl) {
        resultEl.style.color = 'var(--cherry-danger)';
        resultEl.textContent = `✕ Tamper detected: ${data.message}`;
      }
      showToast('Audit Tamper', data.message, 'error');
    }
  } catch (err) {
    if (resultEl) {
      resultEl.style.color = 'var(--cherry-danger)';
      resultEl.textContent = `Error: ${err.message}`;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ============================================================================
// 8. OPENCYPHER STUDIO
// ============================================================================
const CYPHER_PRESETS = {
  shortest_path: `MATCH (a:Account {id: 'ACC_MULE_ALPHA'}), (target:SanctionedEntity)
RETURN shortestPath((a)-[:TRANSFERRED*1..5]->(target)) AS path, a.id AS origin_account, target.name AS target_name;`,

  cycle_detection: `MATCH (a:Account)-[r1:TRANSFERRED]->(b:Account)-[r2:TRANSFERRED]->(c:Account)-[r3:TRANSFERRED]->(a:Account)
WHERE a.id < b.id AND a.id < c.id AND b.id <> c.id
RETURN a.id, b.id, c.id, r1.amount, r2.amount, r3.amount;`,

  sybil_collisions: `MATCH (a:Account)-[:OPERATED_FROM]->(d:Device)
WITH d.fingerprint AS device, count(a) AS account_count, collect(a.id) AS accounts
WHERE account_count >= 2
RETURN device, account_count, accounts;`,

  frozen_registry: `MATCH (a:Account {status: 'frozen'})
RETURN a.id AS account_id, a.risk_score AS risk, a.frozen_at AS locked_at;`,
};

function loadCypherPreset(presetKey) {
  const editor = document.getElementById('cypher-editor');
  if (editor && CYPHER_PRESETS[presetKey]) {
    editor.value = CYPHER_PRESETS[presetKey];
    executeCypherQuery();
  }
}

async function executeCypherQuery() {
  const editor = document.getElementById('cypher-editor');
  const telemetryEl = document.getElementById('cypher-telemetry');
  const tableContainer = document.getElementById('cypher-results-table');
  const runBtn = document.getElementById('btn-run-cypher');

  const query = editor.value.trim();
  if (!query) return;

  runBtn.disabled = true;
  telemetryEl.textContent = 'Executing query...';
  telemetryEl.style.color = 'var(--sky-primary)';

  try {
    const res = await fetch('/api/graph/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query }),
    });
    const data = await res.json();

    if (!data.ok) {
      telemetryEl.textContent = 'Query Error';
      telemetryEl.style.color = 'var(--cherry-danger)';
      tableContainer.innerHTML = `<div style="padding:15px; color:var(--cherry-danger);">${escapeHtml(data.error)}</div>`;
      return;
    }

    telemetryEl.textContent = `${data.row_count} rows • ${data.execution_time_ms}ms execution`;
    telemetryEl.style.color = 'var(--green-success)';

    if (data.rows.length === 0) {
      tableContainer.innerHTML = `<div style="padding:20px; color:#64748B; text-align:center;">Query succeeded: 0 rows returned.</div>`;
      return;
    }

    let tableHtml = `<table class="data-table"><thead><tr>`;
    data.columns.forEach((col) => {
      tableHtml += `<th>${escapeHtml(col)}</th>`;
    });
    tableHtml += `</tr></thead><tbody>`;

    data.rows.forEach((row) => {
      tableHtml += `<tr>`;
      row.forEach((cell) => {
        const display = typeof cell === 'object' ? JSON.stringify(cell) : String(cell);
        tableHtml += `<td title="${escapeHtml(display)}">${escapeHtml(display)}</td>`;
      });
      tableHtml += `</tr>`;
    });
    tableHtml += `</tbody></table>`;

    tableContainer.innerHTML = tableHtml;
  } catch (err) {
    telemetryEl.textContent = 'Network Error';
    telemetryEl.style.color = 'var(--cherry-danger)';
    tableContainer.innerHTML = `<div style="padding:15px; color:var(--cherry-danger);">${escapeHtml(err.message)}</div>`;
  } finally {
    runBtn.disabled = false;
  }
}

// ============================================================================
// 9. SEED DATA WORKFLOW
// ============================================================================
async function seedGraphData() {
  const btn = document.getElementById('btn-seed-data');
  btn.disabled = true;
  btn.textContent = 'Seeding Graph...';

  try {
    const res = await fetch('/api/seed', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true }),
    });
    await res.json();

    state.activeDossier = null;
    state.liveFindings = [];
    state.liveActions = [];
    state.focusedThreatId = null;
    resetGraphFocus();
    await refreshGraphData();

    updateThreatCountBadge();
    document.getElementById('threats-feed').innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon" style="color:var(--green-success); background:var(--green-light); border-color:var(--green-border);">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        </div>
        <div class="empty-state-title">Financial Graph Initialized</div>
        <div class="empty-state-text">FalkorDB initialized with synthetic banking mesh, OFAC sanctions list, and fraud clusters. Ready to investigate!</div>
      </div>
    `;

    showToast('Synthetic Graph Seeded', 'Generated baseline accounts, smurfing paths, and rings in FalkorDB', 'success');
  } catch (err) {
    showToast('Seed Failed', err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
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
// 10. SEARCH & AUTOCOMPLETE
// ============================================================================
function updateSearchAutocomplete() {
  const input = document.getElementById('node-search-input');
  const dropdown = document.getElementById('search-dropdown');
  if (!input || !dropdown) return;

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
      dropdown.innerHTML = `<div style="padding:10px; color:#64748B; font-size:11px;">No entities found</div>`;
      dropdown.style.display = 'block';
      return;
    }

    dropdown.innerHTML = matches
      .slice(0, 7)
      .map(
        (m) => `
        <div class="search-item" onclick="focusSingleNode('${escapeHtml(m.id)}'); document.getElementById('search-dropdown').style.display='none';">
          <span>${escapeHtml(m.id)}</span>
          <span style="color:#0284C7; font-size:10px; font-weight:600;">${escapeHtml(m.group || 'Node')}</span>
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
// 11. GRAPHRAG (NATURAL LANGUAGE QUERY OVER FALKORDB)
// ============================================================================
function setRagQuestion(q) {
  const input = document.getElementById('rag-question-input');
  if (input) {
    input.value = q;
    submitRagQuestion();
  }
}

async function submitRagQuestion() {
  const input = document.getElementById('rag-question-input');
  const btn = document.getElementById('btn-submit-rag');
  const container = document.getElementById('rag-response-container');
  const summaryEl = document.getElementById('rag-summary-text');
  const timingEl = document.getElementById('rag-timing-badge');
  const cypherEl = document.getElementById('rag-cypher-code');
  const tableEl = document.getElementById('rag-results-table');

  const question = input ? input.value.trim() : '';
  if (!question) return;

  if (btn) btn.disabled = true;
  if (container) container.style.display = 'flex';
  if (summaryEl) summaryEl.textContent = 'Synthesizing verified openCypher query...';
  if (cypherEl) cypherEl.textContent = '-- Introspecting FalkorDB schema...';
  if (tableEl) tableEl.innerHTML = '';

  try {
    const res = await fetch('/api/graph/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    });
    const data = await res.json();
    if (!data.ok) {
      if (summaryEl) summaryEl.textContent = `Error: ${data.error || 'Query failed'}`;
      if (timingEl) timingEl.textContent = 'Failed';
      return;
    }

    if (summaryEl) summaryEl.textContent = data.summary || 'Query executed successfully.';
    if (timingEl) timingEl.textContent = `${data.execution_time_ms || 0}ms engine`;
    if (cypherEl) cypherEl.textContent = data.cypher || '--';

    // Highlight returned nodes on canvas
    if (data.highlight_nodes && data.highlight_nodes.length > 0) {
      highlightNodeSet(data.highlight_nodes, `Ask Graph: "${question}"`);
    }

    // Render results table
    if (data.rows && data.rows.length > 0) {
      let ths = (data.columns || []).map((c) => `<th>${escapeHtml(c)}</th>`).join('');
      let trs = data.rows
        .map((row) => {
          let tds = row
            .map((v) => {
              const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
              return `<td title="${escapeHtml(valStr)}">${escapeHtml(valStr)}</td>`;
            })
            .join('');
          return `<tr>${tds}</tr>`;
        })
        .join('');
      tableEl.innerHTML = `<table class="data-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
    } else {
      tableEl.innerHTML = `<div style="padding:10px; color:#64748B; font-size:11px;">0 rows returned</div>`;
    }
  } catch (err) {
    if (summaryEl) summaryEl.textContent = `Network error: ${err.message}`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ============================================================================
// 12. GRAPH MEMORY (INVESTIGATION HISTORY)
// ============================================================================
async function loadInvestigationsHistory() {
  const container = document.getElementById('investigations-history-list');
  if (!container) return;
  container.innerHTML = `<div style="padding:15px; text-align:center; color:#64748B; font-size:11px;">Loading past investigations from FalkorDB...</div>`;

  try {
    const res = await fetch('/api/investigations/history');
    const data = await res.json();
    const historyList = data.investigations || data.history || [];

    if (!data.ok || historyList.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
          </div>
          <div class="empty-state-title">No Past Investigations</div>
          <div class="empty-state-text">Run an investigation to store (:Investigation) memory nodes in FalkorDB.</div>
        </div>
      `;
      return;
    }

    let html = '';
    historyList.forEach((inv) => {
      const invId = inv.id || inv.investigation_id || 'INV-RECORD';
      const dateStr = inv.timestamp ? new Date(inv.timestamp).toLocaleTimeString() : 'Recent';
      html += `
        <div class="threat-card" style="cursor:default; border-left:3px solid var(--sky-primary);">
          <div class="card-top">
            <span style="font-family:'JetBrains Mono'; font-size:11px; color:#0284C7; font-weight:700;">${escapeHtml(invId)}</span>
            <span class="card-latency">${inv.threat_count || 0} threats</span>
          </div>
          <div style="font-size:11px; color:#0B0F14; margin-top:3px;">Agent: ${escapeHtml(inv.agent_id || 'OmniTrace-v1')} • Mode: ${escapeHtml(inv.mode || 'rules')}</div>
          <div style="font-size:10px; color:#64748B; margin-top:2px;">Audited: ${escapeHtml(inv.summary || 'Investigation')} • At: ${dateStr}</div>
          <div style="margin-top:6px; display:flex; gap:6px;">
            <button class="btn-xs" onclick="exportInvestigationReport('${escapeHtml(invId)}', 'html')">Report</button>
            <button class="btn-xs" onclick="exportInvestigationReport('${escapeHtml(invId)}', 'json')">JSON</button>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div style="padding:10px; color:var(--cherry-danger); font-size:11px;">Error loading history: ${escapeHtml(err.message)}</div>`;
  }
}

function exportInvestigationReport(invId, format) {
  const url = `/api/dossiers/${encodeURIComponent(invId)}/export?format=${format}`;
  if (format === 'html') {
    window.open(url, '_blank');
  } else {
    window.location.href = url;
  }
}

// ============================================================================
// 13. GUIDED DEMO ENGINE (100% REAL ACTIONS ON SYNTHETIC DATA)
// ============================================================================
const demoState = {
  active: false,
  paused: false,
  stepIndex: 0,
  stepTimeout: null,
};

async function startGuidedDemo() {
  if (demoState.active) return;

  // Confirmation dialog before seeding wipes graph
  const proceed = window.confirm('This resets the demo data. Continue?');
  if (!proceed) return;

  demoState.active = true;
  demoState.paused = false;
  demoState.stepIndex = 1;

  const banner = document.getElementById('guided-demo-banner');
  const captionEl = document.getElementById('guided-demo-caption');
  const pauseResumeBtn = document.getElementById('btn-demo-pause-resume');
  const demoBtn = document.getElementById('btn-guided-demo');

  if (banner) banner.style.display = 'flex';
  if (pauseResumeBtn) pauseResumeBtn.textContent = 'Pause';
  if (demoBtn) demoBtn.disabled = true;

  try {
    // STEP 1: REAL SEED
    setDemoCaption('Step 1 of 4: Resetting and seeding synthetic fraud topology in FalkorDB...');
    await waitWhilePaused(800);
    if (!demoState.active) return;

    const seedRes = await fetch('/api/seed', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true }),
    });
    if (!seedRes.ok) {
      const errData = await seedRes.json().catch(() => ({}));
      throw new Error(errData.error || `Seeding failed with HTTP ${seedRes.status}`);
    }
    await refreshGraphData();
    showToast('Demo Step 1', `Seeded synthetic graph (${state.rawNodes.length} nodes, ${state.rawEdges.length} edges)`, 'success');

    // STEP 2: REAL INVESTIGATION STREAM
    await waitWhilePaused(1800);
    if (!demoState.active) return;
    demoState.stepIndex = 2;
    setDemoCaption('Step 2 of 4: The agent searches the graph for sanctions exposure, circular rings, and Sybil farms...');

    // Run real live investigation and wait until findings are loaded
    await executeDemoInvestigation();
    if (!demoState.active) return;

    // STEP 3: HIGHLIGHT FIRST FINDING ON GRAPH
    await waitWhilePaused(1500);
    if (!demoState.active) return;
    demoState.stepIndex = 3;

    if (state.liveFindings && state.liveFindings.length > 0) {
      const firstFinding = state.liveFindings[0];
      const title = formatThreatTitle(firstFinding.type, firstFinding);
      setDemoCaption(`Step 3 of 4: Visualizing threat path on graph: ${title}...`);
      focusThreatTrail(0);
      showToast('Demo Step 3', `Highlighted ${title}`, 'info');
    } else {
      setDemoCaption('Step 3 of 4: No threats returned by investigator.');
    }

    // STEP 4: SHOW APPROVE / FREEZE ACTION FLOW
    await waitWhilePaused(2000);
    if (!demoState.active) return;
    demoState.stepIndex = 4;
    setDemoCaption('Step 4 of 4: Compliance cockpit proposes containment action for operator review...');

    const firstApproveBtn = document.querySelector('.btn-approve');
    if (firstApproveBtn) {
      firstApproveBtn.scrollIntoView({ behavior: 'smooth', block: 'center' });
      firstApproveBtn.style.outline = '2px solid var(--sky-primary)';
      firstApproveBtn.style.outlineOffset = '2px';
      setTimeout(() => {
        if (firstApproveBtn) firstApproveBtn.style.outline = 'none';
      }, 3000);
    }

    await waitWhilePaused(2500);
    if (!demoState.active) return;
    setDemoCaption('Guided demo completed: All actions were executed on live FalkorDB endpoints.');
    showToast('Guided Demo Finished', 'Completed 4/4 real steps on synthetic data.', 'success');

    setTimeout(() => {
      stopGuidedDemo();
    }, 4500);
  } catch (err) {
    stopGuidedDemo();
    showToast('Guided Demo Error', err.message, 'error');
  }
}

function setDemoCaption(text) {
  const captionEl = document.getElementById('guided-demo-caption');
  if (captionEl) captionEl.textContent = text;
}

function toggleDemoPause() {
  if (!demoState.active) return;
  demoState.paused = !demoState.paused;
  const btn = document.getElementById('btn-demo-pause-resume');
  if (btn) btn.textContent = demoState.paused ? 'Resume' : 'Pause';
  if (demoState.paused) {
    showToast('Guided Demo', 'Demo paused by operator', 'info');
  } else {
    showToast('Guided Demo', 'Demo resumed', 'info');
  }
}

function stopGuidedDemo() {
  demoState.active = false;
  demoState.paused = false;
  const banner = document.getElementById('guided-demo-banner');
  const demoBtn = document.getElementById('btn-guided-demo');
  if (banner) banner.style.display = 'none';
  if (demoBtn) demoBtn.disabled = false;
  if (state.isStreaming) {
    cancelInvestigation();
  }
}

async function waitWhilePaused(ms) {
  let elapsed = 0;
  const interval = 100;
  while (elapsed < ms) {
    if (!demoState.active) return;
    if (!demoState.paused) {
      elapsed += interval;
    }
    await new Promise((r) => setTimeout(r, interval));
  }
}

function executeDemoInvestigation() {
  return new Promise((resolve, reject) => {
    // If EventSource is supported, stream real live investigation
    if (!window.EventSource) {
      runDirectInvestigationFallback().then(resolve).catch(reject);
      return;
    }

    startLiveInvestigation();

    // Poll until investigation stream finishes or fails
    const checkInterval = setInterval(() => {
      if (!demoState.active) {
        clearInterval(checkInterval);
        resolve();
        return;
      }
      if (!state.isStreaming) {
        clearInterval(checkInterval);
        if (state.liveFindings && state.liveFindings.length > 0) {
          resolve();
        } else {
          // If SSE didn't return findings, fall back to direct POST
          runDirectInvestigationFallback().then(resolve).catch(reject);
        }
      }
    }, 500);

    // Timeout safety cap at 25 seconds
    setTimeout(() => {
      clearInterval(checkInterval);
      resolve();
    }, 25000);
  });
}

// 14. EVENT LISTENERS & HELPERS
// ============================================================================
function setupEventListeners() {
  // Navigation Actions
  document.getElementById('btn-seed-data').addEventListener('click', seedGraphData);
  document.getElementById('btn-live-stream').addEventListener('click', startLiveInvestigation);
  document.getElementById('btn-cancel-stream').addEventListener('click', cancelInvestigation);

  const guidedDemoBtn = document.getElementById('btn-guided-demo');
  if (guidedDemoBtn) guidedDemoBtn.addEventListener('click', startGuidedDemo);
  const pauseDemoBtn = document.getElementById('btn-demo-pause-resume');
  if (pauseDemoBtn) pauseDemoBtn.addEventListener('click', toggleDemoPause);
  const stopDemoBtn = document.getElementById('btn-demo-stop');
  if (stopDemoBtn) stopDemoBtn.addEventListener('click', stopGuidedDemo);

  // Graph HUD Controls
  document.getElementById('btn-fit-screen').addEventListener('click', () => {
    state.network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
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
    if (pill.dataset.preset) {
      pill.addEventListener('click', () => loadCypherPreset(pill.dataset.preset));
    }
  });

  // Cypher Run Button & Shortcut
  document.getElementById('btn-run-cypher').addEventListener('click', executeCypherQuery);
  document.getElementById('cypher-editor').addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      executeCypherQuery();
    }
  });

  // GraphRAG (Ask Graph)
  const ragSubmitBtn = document.getElementById('btn-submit-rag');
  if (ragSubmitBtn) ragSubmitBtn.addEventListener('click', submitRagQuestion);
  const ragInput = document.getElementById('rag-question-input');
  if (ragInput) {
    ragInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        submitRagQuestion();
      }
    });
  }

  // Memory History Refresh
  const histRefreshBtn = document.getElementById('btn-refresh-history');
  if (histRefreshBtn) histRefreshBtn.addEventListener('click', loadInvestigationsHistory);

  // Audit Blockchain Verification
  const auditVerifyBtn = document.getElementById('btn-verify-audit');
  if (auditVerifyBtn) auditVerifyBtn.addEventListener('click', verifyAuditChain);

  // Compliance Dossier Exports
  const expHtmlBtn = document.getElementById('btn-export-html');
  if (expHtmlBtn) {
    expHtmlBtn.addEventListener('click', () => {
      const invId = state.activeDossier ? state.activeDossier.investigation_id : 'latest';
      exportInvestigationReport(invId, 'html');
    });
  }
  const expJsonBtn = document.getElementById('btn-export-json');
  if (expJsonBtn) {
    expJsonBtn.addEventListener('click', () => {
      const invId = state.activeDossier ? state.activeDossier.investigation_id : 'latest';
      exportInvestigationReport(invId, 'json');
    });
  }
}

// Enterprise Light Toast System (Replaces browser popups)
function showToast(title, message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const iconSvg =
    type === 'success'
      ? `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="#15803D" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`
      : type === 'error'
      ? `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="#C8102E" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`
      : `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;

  toast.innerHTML = `
    ${iconSvg}
    <div>
      <div class="toast-title">${escapeHtml(title)}</div>
      <div class="toast-message">${escapeHtml(message)}</div>
    </div>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => toast.remove(), 250);
  }, 4000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
