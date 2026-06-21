/* DNS Looking Glass — app.js
   Vanilla JS, no external dependencies. */

'use strict';

// ── State ────────────────────────────────────────────────────────────────────
let config = null;

// ── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadConfig().then(() => {
    restoreFromURL();
    wireFormBehaviours();
  });
  loadVersion();

  document.getElementById('query-form').addEventListener('submit', onSubmit);
});

// ── Config loading ────────────────────────────────────────────────────────────
async function loadConfig() {
  try {
    const resp = await fetch('api/config.php');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    config = await resp.json();
    populateQTypes(config.qtypes || []);
    populateNodes(config.nameservers || []);
    if (config.client_ip) {
      const ecsAddr = document.getElementById('ecs-address');
      if (ecsAddr && !ecsAddr.value) {
        ecsAddr.value = config.client_ip;
        // Auto-select IPv6 family if client IP is v6.
        if (config.client_ip.includes(':')) {
          document.getElementById('ecs-family').value = '2';
          document.getElementById('ecs-source').value = '48';
        }
      }
    }
  } catch (e) {
    document.getElementById('nodes-container').innerHTML =
      `<p class="loading-hint" style="color:var(--color-error)">Failed to load config: ${e.message}</p>`;
  }
}

async function loadVersion() {
  try {
    const resp = await fetch('version.json');
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.version) {
      const el = document.getElementById('app-version');
      if (el) el.textContent = ` — ${data.version}`;
    }
  } catch (_) { /* version.json absent; degrade silently */ }
}

function populateQTypes(qtypes) {
  const sel = document.getElementById('qtype');
  sel.innerHTML = '';
  qtypes.forEach(t => {
    const opt = document.createElement('option');
    opt.value = t;
    opt.textContent = t;
    sel.appendChild(opt);
  });
  const defaultQtype = config.defaults?.qtype || 'A';
  sel.value = defaultQtype;
}

function populateNodes(groups) {
  const container = document.getElementById('nodes-container');
  container.innerHTML = '';

  if (groups.length === 0) {
    container.innerHTML = '<p class="loading-hint">No nodes available for your IP address.</p>';
    return;
  }

  const defaultTag = config.defaults?.nameserver || '';
  let firstTag = null;

  groups.forEach(group => {
    const items = group.items || {};
    const tags = Object.keys(items).sort((a, b) =>
      items[a].name.localeCompare(items[b].name));
    if (tags.length === 0) return;

    const groupEl = document.createElement('div');
    groupEl.className = 'node-group';

    const nameEl = document.createElement('div');
    nameEl.className = 'node-group-name';

    const nameText = document.createElement('span');
    nameText.textContent = group.name;
    nameEl.appendChild(nameText);

    const ctrlsEl = document.createElement('span');
    ctrlsEl.className = 'node-group-controls';
    const allBtn = document.createElement('button');
    allBtn.type = 'button';
    allBtn.className = 'node-select-link';
    allBtn.textContent = 'all';
    const noneBtn = document.createElement('button');
    noneBtn.type = 'button';
    noneBtn.className = 'node-select-link';
    noneBtn.textContent = 'none';
    ctrlsEl.appendChild(allBtn);
    ctrlsEl.appendChild(document.createTextNode(' / '));
    ctrlsEl.appendChild(noneBtn);
    nameEl.appendChild(ctrlsEl);

    groupEl.appendChild(nameEl);

    const itemsEl = document.createElement('div');
    itemsEl.className = 'node-items';

    tags.forEach(tag => {
      const item = items[tag];
      if (!firstTag) firstTag = tag;

      const label = document.createElement('label');
      label.className = 'check-label';

      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.name = 'node';
      cb.value = tag;
      cb.dataset.nodeName = item.name;

      const isDefault = tag === defaultTag || (!defaultTag && tag === firstTag);
      if (isDefault) cb.checked = true;

      const span = document.createElement('span');
      span.textContent = item.name;

      label.appendChild(cb);
      label.appendChild(span);
      itemsEl.appendChild(label);
    });

    allBtn.addEventListener('click', () => {
      itemsEl.querySelectorAll('input[type=checkbox]').forEach(cb => { cb.checked = true; });
    });
    noneBtn.addEventListener('click', () => {
      itemsEl.querySelectorAll('input[type=checkbox]').forEach(cb => { cb.checked = false; });
    });

    groupEl.appendChild(itemsEl);
    container.appendChild(groupEl);
  });

  // Ensure at least the first node is selected if none match defaults.
  const checked = container.querySelectorAll('input[type=checkbox]:checked');
  if (checked.length === 0 && firstTag) {
    const first = container.querySelector(`input[value="${firstTag}"]`);
    if (first) first.checked = true;
  }
}

// ── Form behaviour wiring ─────────────────────────────────────────────────────
function wireFormBehaviours() {
  // Mode radio — show/hide target IP fields; grey out RD in recursive mode.
  document.querySelectorAll('input[name="mode"]').forEach(radio => {
    radio.addEventListener('change', onModeChange);
  });

  // EDNS size toggle.
  document.getElementById('edns-size-enable').addEventListener('change', function () {
    document.getElementById('edns-size-fields').classList.toggle('hidden', !this.checked);
  });

  // NSID has no sub-fields.

  // ECS toggle.
  document.getElementById('edns-ecs-enable').addEventListener('change', function () {
    document.getElementById('edns-ecs-fields').classList.toggle('hidden', !this.checked);
  });

  // ECS family change — update source prefix default.
  document.getElementById('ecs-family').addEventListener('change', function () {
    const src = document.getElementById('ecs-source');
    src.value = this.value === '2' ? '48' : '24';
  });

  // DO flag — auto-enable EDNS when DO is checked; keep Validate in sync.
  document.getElementById('flag-do').addEventListener('change', function () {
    if (this.checked) {
      document.getElementById('edns-size-enable').checked = true;
      document.getElementById('edns-size-fields').classList.remove('hidden');
    }
    updateValidateState();
  });

  // Validate checkbox — show/hide anchor mode selector.
  document.getElementById('flag-validate').addEventListener('change', updateValidateState);

  // DS override — add row when button clicked.
  document.getElementById('add-ds-override').addEventListener('click', addDSOverride);

  // TCP — disable EDNS UDP size when TCP is selected.
  document.querySelectorAll('input[name="use_tcp"]').forEach(r => {
    r.addEventListener('change', onProtocolChange);
  });
}

function onModeChange() {
  const mode = document.querySelector('input[name="mode"]:checked')?.value;
  const targetFields = document.getElementById('target-fields');
  const rdLabel = document.getElementById('flag-rd').closest('.check-label');

  targetFields.classList.toggle('hidden', mode !== 'target');

  if (mode === 'recursive') {
    rdLabel.setAttribute('aria-disabled', 'true');
    rdLabel.classList.add('disabled');
    rdLabel.title = 'Recursion Desired is not used in full recursive mode';
  } else {
    rdLabel.removeAttribute('aria-disabled');
    rdLabel.classList.remove('disabled');
    rdLabel.title = 'Recursion Desired — ask the server to recurse on your behalf';
  }

  updateValidateState();
}

// ── DS override helpers ───────────────────────────────────────────────────────

// Parse a DS record from either full zone-file format or bare RDATA.
// Accepts: "12345 13 2 ABCD..." or "zone. TTL IN DS 12345 13 2 ABCD..."
// Digest hex may contain whitespace (multi-line zone-file continuation).
function parseDSRecord(text) {
  const m = text.trim().match(/(?:.*?\s+IN\s+DS\s+)?(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-F][0-9a-fA-F\s]*)/i);
  if (!m) return null;
  return {
    key_tag:     +m[1],
    algorithm:   +m[2],
    digest_type: +m[3],
    digest:      m[4].replace(/\s+/g, '').toUpperCase(),
  };
}

function addDSOverride() {
  const list = document.getElementById('ds-override-list');
  const row = document.createElement('div');
  row.className = 'ds-override-row';
  row.innerHTML =
    '<input type="text" class="ds-zone" placeholder="example.com." spellcheck="false" autocapitalize="off" autocomplete="off">' +
    '<textarea class="ds-text" rows="2" placeholder="12345 13 2 ABCDEF…&#10;(paste DS RDATA or full DS record line)" spellcheck="false"></textarea>' +
    '<select class="ds-mode">' +
      '<option value="add">Add alongside parent DS</option>' +
      '<option value="replace">Replace parent DS entirely</option>' +
    '</select>' +
    '<button type="button" class="ds-remove" aria-label="Remove DS override">×</button>';
  row.querySelector('.ds-remove').addEventListener('click', () => row.remove());
  list.appendChild(row);
  row.querySelector('.ds-zone').focus();
}

function updateValidateState() {
  const mode = document.querySelector('input[name="mode"]:checked')?.value;
  const doChecked = document.getElementById('flag-do').checked;
  const cb = document.getElementById('flag-validate');
  const label = document.getElementById('label-validate');
  const anchorFields = document.getElementById('anchor-mode-fields');
  const active = mode === 'recursive' && doChecked;

  cb.disabled = !active;
  label.classList.toggle('disabled', !active);
  label.setAttribute('aria-disabled', active ? 'false' : 'true');
  if (!active) cb.checked = false;

  const validateChecked = active && cb.checked;
  anchorFields.classList.toggle('hidden', !validateChecked);
}

function onProtocolChange() {
  const isTCP = document.querySelector('input[name="use_tcp"]:checked')?.value === 'tcp';
  const sizeCheck = document.getElementById('edns-size-enable');
  const sizeLabel = sizeCheck.closest('.check-label');
  const sizeFields = document.getElementById('edns-size-fields');
  if (isTCP) {
    sizeLabel.classList.add('disabled');
    sizeLabel.setAttribute('aria-disabled', 'true');
    sizeFields.classList.add('hidden');
  } else {
    sizeLabel.classList.remove('disabled');
    sizeLabel.removeAttribute('aria-disabled');
    if (sizeCheck.checked) sizeFields.classList.remove('hidden');
  }
}

// ── Form submission ───────────────────────────────────────────────────────────
async function onSubmit(e) {
  e.preventDefault();

  const qname = document.getElementById('qname').value.trim();
  if (!qname) {
    document.getElementById('qname').classList.add('error');
    setStatus('QNAME is required', true);
    return;
  }
  document.getElementById('qname').classList.remove('error');

  const mode = document.querySelector('input[name="mode"]:checked')?.value;
  const nsInput = document.getElementById('nameserver');
  if (mode === 'target' && !nsInput.value.trim()) {
    nsInput.classList.add('error');
    setStatus('Nameserver IP or hostname is required in Specify IP mode', true);
    return;
  }
  nsInput.classList.remove('error');

  const selectedNodes = [...document.querySelectorAll('input[name="node"]:checked')];
  if (selectedNodes.length === 0) {
    setStatus('Select at least one node', true);
    return;
  }

  const payload = buildPayload(qname);
  const resultsEl = document.getElementById('results');
  resultsEl.innerHTML = '';
  resultsEl.classList.remove('hidden');

  const btn = document.getElementById('submit-btn');
  btn.disabled = true;
  setStatus(`Querying ${selectedNodes.length} node${selectedNodes.length > 1 ? 's' : ''}…`);

  updateURL(qname, payload, selectedNodes.map(n => n.value));

  // Fire one request per node in parallel; render results as they arrive.
  const promises = selectedNodes.map(node => queryNode(node.value, node.dataset.nodeName, payload));

  const multi = selectedNodes.length > 1;
  const panels = {};

  // Pre-create skeleton accordion panels in document order so results slot in correctly.
  if (multi) {
    selectedNodes.forEach(node => {
      const panel = createSkeletonPanel(node.value, nodeLabel(node.dataset.nodeName, payload));
      resultsEl.appendChild(panel);
      panels[node.value] = panel;
    });
  }

  const settled = promises.map((p, i) => {
    const tag = selectedNodes[i].value;
    const name = nodeLabel(selectedNodes[i].dataset.nodeName, payload);
    return p.then(result => {
      if (multi) {
        fillPanel(panels[tag], name, result, true, payload.mode);
      } else {
        const panel = buildResultPanel(name, result, false, payload.mode);
        resultsEl.appendChild(panel);
      }
    });
  });

  await Promise.allSettled(settled);
  btn.disabled = false;
  setStatus('');
}

function buildPayload(qname) {
  const mode = document.querySelector('input[name="mode"]:checked')?.value || 'localhost';
  const isTCP = document.querySelector('input[name="use_tcp"]:checked')?.value === 'tcp';
  const ednsOptions = [];

  if (document.getElementById('edns-nsid').checked) {
    ednsOptions.push({ code: 3 });
  }
  if (document.getElementById('edns-ecs-enable').checked) {
    ednsOptions.push({
      code: 8,
      family: parseInt(document.getElementById('ecs-family').value, 10),
      address: document.getElementById('ecs-address').value.trim() || '0.0.0.0',
      source_prefix: parseInt(document.getElementById('ecs-source').value, 10),
      scope_prefix: parseInt(document.getElementById('ecs-scope').value, 10),
    });
  }

  const sizeEnabled = document.getElementById('edns-size-enable').checked;
  const doEnabled = document.getElementById('flag-do').checked;

  const validateChecked = document.getElementById('flag-validate').checked;
  const anchorMode = document.querySelector('input[name="anchor_mode"]:checked')?.value || 'iana';

  return {
    qname,
    qtype:      document.getElementById('qtype').value,
    mode,
    nameserver: document.getElementById('nameserver').value.trim(),
    port:       parseInt(document.getElementById('dns-port').value, 10) || 53,
    use_tcp:    isTCP,
    flags: {
      rd:       document.getElementById('flag-rd').checked,
      ad:       document.getElementById('flag-ad').checked,
      cd:       document.getElementById('flag-cd').checked,
      do:       doEnabled,
      validate: validateChecked,
    },
    edns: {
      udp_size: (sizeEnabled || doEnabled)
        ? (parseInt(document.getElementById('edns-udp-size').value, 10) || 1232)
        : 0,
      options: ednsOptions,
    },
    trust_anchor_mode:  anchorMode,
    trust_anchors:      (validateChecked && anchorMode === 'iana') ? (config?.trust_anchors || []) : [],
    zone_trust_anchors: collectDSOverrides(validateChecked),
  };
}

function collectDSOverrides(validateActive) {
  if (!validateActive) return [];
  const overrides = [];
  document.querySelectorAll('.ds-override-row').forEach(row => {
    const zone = row.querySelector('.ds-zone').value.trim();
    const override = row.querySelector('.ds-mode').value === 'replace';
    const ds = [];
    row.querySelector('.ds-text').value.split('\n').forEach(line => {
      if (line.trim()) {
        const parsed = parseDSRecord(line);
        if (parsed) ds.push(parsed);
      }
    });
    if (zone && ds.length > 0) {
      overrides.push({ zone, ds, override });
    }
  });
  return overrides;
}

async function queryNode(tag, nodeName, payload) {
  const body = JSON.stringify({ ...payload, tag });
  try {
    const resp = await fetch('api/query.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    const data = await resp.json();
    return data;
  } catch (e) {
    return { error: e.message };
  }
}

// Returns a display label for a node, appending target IP and protocol in target mode.
function nodeLabel(name, payload) {
  if (payload.mode !== 'target') return name;
  const ns = (payload.nameserver || '').trim();
  if (!ns) return name;
  const port = payload.port && payload.port !== 53 ? `:${payload.port}` : '';
  const proto = payload.use_tcp ? 'TCP' : 'UDP';
  return `${name} · ${ns}${port} via ${proto}`;
}

// ── Result panel building ─────────────────────────────────────────────────────
function createSkeletonPanel(tag, name) {
  const panel = document.createElement('div');
  panel.className = 'result-panel';
  panel.dataset.tag = tag;
  panel.innerHTML = `
    <div class="result-panel-header">
      <span class="result-node-name">${esc(name)}</span>
      <span class="result-timing">Waiting…</span>
      <span class="accordion-toggle">▼</span>
    </div>
    <div class="result-panel-body"><p class="loading-hint">Loading…</p></div>`;
  wireAccordion(panel);
  return panel;
}

function fillPanel(panel, name, data, accordion, mode) {
  const header = panel.querySelector('.result-panel-header');
  const body = panel.querySelector('.result-panel-body');
  header.querySelector('.result-timing').innerHTML = timingHTML(data);
  body.innerHTML = '';
  appendResultContent(body, data, mode);
  if (!panel.querySelector('.accordion-toggle')) {
    const tog = document.createElement('span');
    tog.className = 'accordion-toggle';
    tog.textContent = '▼';
    header.appendChild(tog);
  }
}

function buildResultPanel(name, data, accordion, mode) {
  const panel = document.createElement('div');
  panel.className = 'result-panel';
  const showToggle = accordion;

  panel.innerHTML = `
    <div class="result-panel-header"${accordion ? '' : ' style="cursor:default"'}>
      <span class="result-node-name">${esc(name)}</span>
      <span class="result-timing">${timingHTML(data)}</span>
      ${showToggle ? '<span class="accordion-toggle">▼</span>' : ''}
    </div>
    <div class="result-panel-body"></div>`;

  appendResultContent(panel.querySelector('.result-panel-body'), data, mode);
  if (accordion) wireAccordion(panel);
  return panel;
}

function timingHTML(data) {
  if (data.error && !data.api_ms) return '';
  const dns = data.dns_query_ms != null ? data.dns_query_ms.toFixed(1) : null;
  const api = data.api_ms != null ? data.api_ms.toFixed(1) : null;
  if (!api) return dns ? `<span class="dns-time">${dns}ms DNS</span>` : '';
  const overhead = api && dns ? (parseFloat(api) - parseFloat(dns)).toFixed(1) : null;
  return `Round-trip: <span class="dns-time">${api}ms</span>`
    + (dns ? ` &nbsp;(DNS: ${dns}ms / overhead: ${overhead}ms)` : '');
}

function appendResultContent(body, data, mode) {
  if (data.error) {
    const errEl = document.createElement('div');
    errEl.className = 'result-error';
    errEl.textContent = data.error;
    body.appendChild(errEl);
    return;
  }

  // DNSSEC badge (recursive mode).
  if (data.dnssec_valid !== null && data.dnssec_valid !== undefined) {
    const badge = document.createElement('span');
    badge.className = 'dnssec-badge';
    if (data.dnssec_valid === true)                    { badge.classList.add('secure');        badge.textContent = 'DNSSEC: Secure'; }
    else if (data.dnssec_valid === false)              { badge.classList.add('bogus');         badge.textContent = 'DNSSEC: Bogus'; }
    else if (data.dnssec_valid === 'insecure')         { badge.classList.add('insecure');      badge.textContent = 'DNSSEC: Insecure'; }
    else                                               { badge.classList.add('indeterminate'); badge.textContent = 'DNSSEC: Indeterminate'; }
    body.appendChild(badge);
  }

  // NSID.
  if (data.nsid) {
    const nsidEl = document.createElement('div');
    nsidEl.className = 'response-text-block';
    nsidEl.style.fontSize = '0.75rem';
    nsidEl.textContent = `NSID: ${data.nsid}`;
    body.appendChild(nsidEl);
  }

  // Response text.
  if (data.response_text) {
    const pre = document.createElement('div');
    pre.className = 'response-text-block';
    pre.textContent = data.response_text;
    body.appendChild(pre);
  }

  // Resolution chain (recursive mode).
  if (data.resolution_chain && data.resolution_chain.length > 0) {
    body.appendChild(buildChainSection(data.resolution_chain));
  }

  // Packet visualiser (query + response). Collapsed by default in localhost/target mode.
  if (data.query_bytes_hex || data.response_bytes_hex) {
    body.appendChild(buildPacketSection(data, mode !== 'recursive'));
  }
}

function buildChainSection(chain) {
  const resSteps = chain.filter(s => !s.validation_step);
  const valSteps = chain.filter(s => s.validation_step);

  const sec = document.createElement('div');
  sec.className = 'chain-section';

  appendStepGroup(sec, `Resolution chain (${resSteps.length} step${resSteps.length !== 1 ? 's' : ''})`, resSteps, 'chain-title');
  if (valSteps.length > 0) {
    appendStepGroup(sec, `DNSSEC validation (${valSteps.length} step${valSteps.length !== 1 ? 's' : ''})`, valSteps, 'chain-title chain-title-validation');
  }
  return sec;
}

function appendStepGroup(container, title, steps, titleClass) {
  const titleEl = document.createElement('div');
  titleEl.className = titleClass;
  titleEl.textContent = title;
  container.appendChild(titleEl);

  steps.forEach((step, i) => {
    const stepEl = document.createElement('div');
    stepEl.className = 'chain-step';
    if (i === steps.length - 1) stepEl.classList.add('open');

    const hdr = document.createElement('div');
    hdr.className = 'chain-step-header';
    const nsLabel = step.nameserver_name
      ? `${esc(step.nameserver_name)} (${esc(step.nameserver)})`
      : esc(step.nameserver);
    const noteHtml = step.step_note
      ? ` <span class="chain-step-note">${esc(step.step_note)}</span>`
      : '';
    hdr.innerHTML = `<span>${i + 1}. ${nsLabel} → ${esc(step.qname)} ${esc(step.qtype)}${noteHtml}</span>`
      + `<span>${step.dns_query_ms.toFixed(1)}ms</span>`;
    hdr.addEventListener('click', () => stepEl.classList.toggle('open'));

    const bodyEl = document.createElement('div');
    bodyEl.className = 'chain-step-body';
    if (step.nsid) {
      const nsidEl = document.createElement('div');
      nsidEl.className = 'response-text-block';
      nsidEl.style.fontSize = '0.75rem';
      nsidEl.textContent = `NSID: ${step.nsid}`;
      bodyEl.appendChild(nsidEl);
    }
    if (step.response_text) {
      const pre = document.createElement('div');
      pre.className = 'response-text-block';
      pre.textContent = step.response_text;
      bodyEl.appendChild(pre);
    }
    if (step.query_bytes_hex || step.response_bytes_hex) {
      bodyEl.appendChild(buildPacketSection(step));
    }

    stepEl.appendChild(hdr);
    stepEl.appendChild(bodyEl);
    container.appendChild(stepEl);
  });
}

// ── Accordion ─────────────────────────────────────────────────────────────────
function wireAccordion(panel) {
  panel.querySelector('.result-panel-header').addEventListener('click', () => {
    panel.classList.toggle('collapsed');
  });
}

// ── Status ────────────────────────────────────────────────────────────────────
function setStatus(msg, isError) {
  const el = document.getElementById('query-status');
  el.textContent = msg;
  el.className = 'query-status' + (isError ? ' error' : '');
}

// ── URL state ─────────────────────────────────────────────────────────────────
function updateURL(qname, payload, tags) {
  const p = new URLSearchParams();
  p.set('qname', qname);
  p.set('qtype', payload.qtype);
  p.set('mode', payload.mode);
  if (tags.length) p.set('nodes', tags.join(','));
  history.replaceState(null, '', '?' + p.toString());
}

function restoreFromURL() {
  const p = new URLSearchParams(location.search);
  if (p.has('qname')) document.getElementById('qname').value = p.get('qname');
  if (p.has('qtype') && document.getElementById('qtype').querySelector(`option[value="${p.get('qtype')}"]`)) {
    document.getElementById('qtype').value = p.get('qtype');
  }
  if (p.has('mode')) {
    const radio = document.querySelector(`input[name="mode"][value="${p.get('mode')}"]`);
    if (radio) { radio.checked = true; onModeChange(); }
  }
  if (p.has('nodes')) {
    const tags = p.get('nodes').split(',');
    document.querySelectorAll('input[name="node"]').forEach(cb => {
      cb.checked = tags.includes(cb.value);
    });
  }
}

// ── Packet visualiser ─────────────────────────────────────────────────────────
function buildPacketSection(data, collapsed = false) {
  const sec = document.createElement('div');
  sec.className = 'packet-section';

  const title = document.createElement('div');
  title.className = 'packet-title packet-title-toggle';
  const arrow = document.createElement('span');
  arrow.className = 'packet-collapse-arrow';
  arrow.textContent = collapsed ? '▸' : '▾';
  title.appendChild(arrow);
  title.appendChild(document.createTextNode(' Packet View'));
  sec.appendChild(title);

  const inner = document.createElement('div');
  inner.className = 'packet-inner';
  if (collapsed) inner.classList.add('hidden');
  sec.appendChild(inner);

  title.addEventListener('click', () => {
    const nowCollapsed = inner.classList.toggle('hidden');
    arrow.textContent = nowCollapsed ? '▸' : '▾';
  });

  // Sub-tabs: Query / Response.
  const subBar = document.createElement('div');
  subBar.className = 'packet-sub-tabs';

  const hasBoth = data.query_bytes_hex && data.response_bytes_hex;

  const panes = {};

  if (data.query_bytes_hex) {
    const btn = makeSubBtn('Query', true);
    subBar.appendChild(btn);
    panes.query = { hex: data.query_bytes_hex, btn };
  }
  if (data.response_bytes_hex) {
    const btn = makeSubBtn('Response', !data.query_bytes_hex);
    subBar.appendChild(btn);
    panes.response = { hex: data.response_bytes_hex, btn };
  }

  if (hasBoth) inner.appendChild(subBar);

  // Wireshark / Hex dump tabs.
  const tabsBar = document.createElement('div');
  tabsBar.className = 'packet-tabs-bar';
  const wsBtn = makeTabBtn('Packet Detail', true);
  const hexBtn = makeTabBtn('Hex Dump', false);
  tabsBar.appendChild(wsBtn);
  tabsBar.appendChild(hexBtn);
  inner.appendChild(tabsBar);

  // Content area.
  const content = document.createElement('div');
  inner.appendChild(content);

  function render(hexStr) {
    content.innerHTML = '';
    const bytes = hexToBytes(hexStr);
    const parsed = DNSParser.parse(bytes);

    // Wireshark view.
    const wsView = document.createElement('div');
    wsView.className = 'tree-view' + (wsBtn.classList.contains('active') ? '' : ' hidden');

    // Hex dump view.
    const hexView = document.createElement('div');
    hexView.className = 'hex-view' + (hexBtn.classList.contains('active') ? '' : ' hidden');

    buildTreeView(wsView, parsed, bytes);
    buildHexView(hexView, bytes, parsed.annotations);

    // Cross-highlight wiring.
    wireHighlight(wsView, hexView, parsed.annotations);

    content.appendChild(wsView);
    content.appendChild(hexView);

    wsBtn.onclick = () => { wsBtn.classList.add('active'); hexBtn.classList.remove('active'); wsView.classList.remove('hidden'); hexView.classList.add('hidden'); };
    hexBtn.onclick = () => { hexBtn.classList.add('active'); wsBtn.classList.remove('active'); hexView.classList.remove('hidden'); wsView.classList.add('hidden'); };
  }

  // Activate first available pane.
  let activeHex = data.query_bytes_hex || data.response_bytes_hex;
  render(activeHex);

  // Sub-tab switching.
  Object.entries(panes).forEach(([key, pane]) => {
    pane.btn.addEventListener('click', () => {
      Object.values(panes).forEach(p => p.btn.classList.remove('active'));
      pane.btn.classList.add('active');
      render(pane.hex);
    });
  });

  return sec;
}

function makeTabBtn(label, active) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'packet-tab-btn' + (active ? ' active' : '');
  btn.textContent = label;
  return btn;
}

function makeSubBtn(label, active) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'packet-sub-btn' + (active ? ' active' : '');
  btn.textContent = label;
  return btn;
}

// ── Cross-highlight ───────────────────────────────────────────────────────────
function wireHighlight(wsView, hexView, annotations) {
  // Tree rows carry data-start and data-end byte offsets.
  wsView.querySelectorAll('[data-start]').forEach(row => {
    const start = parseInt(row.dataset.start, 10);
    const end   = parseInt(row.dataset.end, 10);
    const events = { mouseenter: () => hlHex(hexView, start, end, true),
                     mouseleave: () => hlHex(hexView, start, end, false) };
    row.addEventListener('mouseenter', events.mouseenter);
    row.addEventListener('mouseleave', events.mouseleave);
  });

  // Hex bytes carry data-offset.
  hexView.querySelectorAll('[data-offset]').forEach(el => {
    const off = parseInt(el.dataset.offset, 10);
    const ann = annotations.find(a => off >= a.start && off < a.end);
    if (!ann) return;
    el.addEventListener('mouseenter', () => {
      hlHex(hexView, ann.start, ann.end, true);
      hlTree(wsView, ann.start, ann.end, true);
    });
    el.addEventListener('mouseleave', () => {
      hlHex(hexView, ann.start, ann.end, false);
      hlTree(wsView, ann.start, ann.end, false);
    });
  });
}

function hlHex(hexView, start, end, on) {
  hexView.querySelectorAll('[data-offset]').forEach(el => {
    const off = parseInt(el.dataset.offset, 10);
    if (off >= start && off < end) el.classList.toggle('highlighted', on);
  });
}

function hlTree(wsView, start, end, on) {
  wsView.querySelectorAll('[data-start]').forEach(row => {
    if (parseInt(row.dataset.start, 10) === start) row.classList.toggle('highlighted', on);
  });
}

// ── Tree view builder ─────────────────────────────────────────────────────────
function buildTreeView(container, parsed, bytes) {
  const root = document.createElement('div');
  root.className = 'tree-node tree-node-root';

  appendSection(root, 'DNS Header', parsed.header);
  appendSection(root, 'Question Section', parsed.question);
  if (parsed.answer.length)     appendSection(root, `Answer Section (${parsed.answer.length})`, parsed.answer);
  if (parsed.authority.length)  appendSection(root, `Authority Section (${parsed.authority.length})`, parsed.authority);
  if (parsed.additional.length) appendSection(root, `Additional Section (${parsed.additional.length})`, parsed.additional);

  container.appendChild(root);
}

function appendSection(parent, title, items) {
  const wrapper = document.createElement('div');
  wrapper.className = 'tree-node';

  const hdr = document.createElement('div');
  hdr.className = 'tree-row tree-section-header';
  if (Array.isArray(items) && items.length > 0 && items[0].start != null) {
    hdr.dataset.start = items[0].start;
    hdr.dataset.end   = items[items.length - 1].end ?? items[0].end;
  } else if (items && items.start != null) {
    hdr.dataset.start = items.start;
    hdr.dataset.end   = items.end;
  }

  const tog = document.createElement('span');
  tog.className = 'tree-toggle';
  tog.textContent = '▾';

  const label = document.createElement('span');
  label.textContent = title;

  hdr.appendChild(tog);
  hdr.appendChild(label);
  wrapper.appendChild(hdr);

  const children = document.createElement('div');
  children.className = 'tree-children';

  const appendRows = (nodes) => {
    (Array.isArray(nodes) ? nodes : [nodes]).forEach(node => {
      if (node.children) {
        appendSection(children, node.label || '', node.children);
      } else {
        const row = document.createElement('div');
        row.className = 'tree-row';
        if (node.start != null) { row.dataset.start = node.start; row.dataset.end = node.end; }
        if (node.bits) {
          row.innerHTML = `<span class="tree-bits">${esc(node.bits)}</span> <span class="tree-field">${esc(node.field)}</span><span class="tree-desc">: ${esc(node.desc)}</span>`;
        } else {
          row.innerHTML = `<span class="tree-toggle"></span><span class="tree-field">${esc(node.field)}</span><span class="tree-desc">: </span><span class="tree-value">${esc(String(node.value ?? ''))}</span>`;
        }
        children.appendChild(row);
      }
    });
  };

  appendRows(items);
  wrapper.appendChild(children);

  tog.addEventListener('click', (e) => {
    e.stopPropagation();
    const collapsed = children.classList.toggle('collapsed');
    tog.textContent = collapsed ? '▸' : '▾';
  });

  parent.appendChild(wrapper);
}

// ── Hex dump builder ──────────────────────────────────────────────────────────
function buildHexView(container, bytes, annotations) {
  const ROW = 16;
  for (let i = 0; i < bytes.length; i += ROW) {
    const row = document.createElement('div');
    row.className = 'hex-row';

    const off = document.createElement('span');
    off.className = 'hex-offset';
    off.textContent = i.toString(16).padStart(4, '0');
    row.appendChild(off);

    const bytesEl = document.createElement('span');
    bytesEl.className = 'hex-bytes';

    const asciiEl = document.createElement('span');
    asciiEl.className = 'hex-ascii';

    for (let j = 0; j < ROW; j++) {
      if (j === 8) {
        const sep = document.createElement('span');
        sep.className = 'hex-group';
        bytesEl.appendChild(sep);
      }
      const idx = i + j;
      if (idx < bytes.length) {
        const byteEl = document.createElement('span');
        byteEl.className = 'hex-byte';
        byteEl.dataset.offset = idx;
        byteEl.textContent = bytes[idx].toString(16).padStart(2, '0');
        bytesEl.appendChild(byteEl);

        const asciiChar = document.createElement('span');
        asciiChar.className = 'ascii-char';
        asciiChar.dataset.offset = idx;
        const c = bytes[idx];
        asciiChar.textContent = (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
        asciiEl.appendChild(asciiChar);
      } else {
        bytesEl.appendChild(Object.assign(document.createElement('span'), { className: 'hex-byte', textContent: '  ' }));
        asciiEl.appendChild(Object.assign(document.createElement('span'), { className: 'ascii-char', textContent: ' ' }));
      }
    }

    row.appendChild(bytesEl);
    row.appendChild(asciiEl);
    container.appendChild(row);
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return arr;
}

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
