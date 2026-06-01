import { useState, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import Icon from './Icon.jsx';
import { api } from '../api.js';

const CATEGORIES = {
  cred_reuse:      { label: 'Credential reuse',       color: '#e8cc42', style: 'lateral', icon: '🔑' },
  domain_admin:    { label: 'DA propagation',          color: '#cc2233', style: 'exploit', icon: '👑' },
  hash_reuse:      { label: 'Pass-the-Hash',           color: '#f09a3a', style: 'lateral', icon: '🔓' },
  password_reuse:  { label: 'Password reuse',          color: '#f09a3a', style: 'lateral', icon: '🔐' },
  service_reach:   { label: 'Service reachability',   color: '#5b8af5', style: 'normal',  icon: '🌐' },
  delegation:      { label: 'Delegation paths',        color: '#c07af0', style: 'lateral', icon: '🎫' },
};

function getNodeForHost(host, nodes) {
  if (!host) return null;
  for (const n of nodes) {
    const fallbackIps = n.ip ? [n.ip] : [];
    const ips = n.ips?.length > 0 ? n.ips : fallbackIps;
    if (ips.includes(host.ip)) return n;
    if (host.hostname && n.label && n.label.toLowerCase() === host.hostname.toLowerCase()) return n;
  }
  return null;
}

function makeAdder(seen, vectors) {
  return (v) => {
    const key = `${v.category}:${[v.from, v.to].sort((a, b) => a.localeCompare(b)).join('~')}:${v.label}`;
    if (!seen.has(key) && v.from !== v.to) { seen.add(key); vectors.push({ ...v, _key: key }); }
  };
}

function credReuseLabel(isDA, isLA) {
  if (isDA) return 'DA';
  if (isLA) return 'LA reuse';
  return 'cred reuse';
}

function credReuseReason(username, isDA, isLA) {
  const laRole = isLA ? 'Local Admin' : 'confirmed';
  const role = isDA ? 'Domain Admin' : laRole;
  return `${username} has ${role} access on both hosts`;
}

function addCredReusePair(a, b, cred, add) {
  const isDA = a.access.includes('domain_admin') || b.access.includes('domain_admin');
  const isLA = a.access.includes('local_admin') || b.access.includes('local_admin');
  add({
    category: 'cred_reuse',
    from: a.node.id, to: b.node.id,
    fromLabel: a.node.label, toLabel: b.node.label,
    label: credReuseLabel(isDA, isLA),
    style: isDA ? 'exploit' : 'lateral',
    reason: credReuseReason(cred.username, isDA, isLA),
    cred: cred.username,
  });
}

function buildCredReuseForCred(arr, cred, hostById, nodes, add) {
  const entries = arr
    .filter(c => c.access?.length > 0)
    .map(c => ({ host: hostById[c.host_id], access: c.access }))
    .filter(c => c.host);
  const mapped = entries
    .map(({ host, access }) => ({ node: getNodeForHost(host, nodes), access, host }))
    .filter(x => x.node);
  for (let i = 0; i < mapped.length; i++) {
    for (let j = i + 1; j < mapped.length; j++) {
      addCredReusePair(mapped[i], mapped[j], cred, add);
    }
  }
}

function buildCredReuse(chnByCred, credById, hostById, nodes, add) {
  for (const [credId, arr] of Object.entries(chnByCred)) {
    const cred = credById[credId];
    if (!cred) continue;
    buildCredReuseForCred(arr, cred, hostById, nodes, add);
  }
}

function getNodeIps(n) {
  const fallback = n.ip ? [n.ip] : [];
  return n.ips?.length > 0 ? n.ips : fallback;
}

function addDomainAdminEdges(da, cred, srcHost, srcNode, hosts, nodes, add) {
  for (const n of nodes) {
    if (n.id === srcNode.id) continue;
    const ips = getNodeIps(n);
    const h = hosts.find(h2 => ips.includes(h2.ip));
    if (!h?.domain?.trim()) continue;
    add({
      category: 'domain_admin',
      from: srcNode.id, to: n.id,
      fromLabel: srcNode.label, toLabel: n.label,
      label: 'DA',
      style: 'exploit',
      reason: `${cred.username} (DA) owned on ${srcHost.ip || srcHost.hostname} → lateral to ${h.domain}`,
      cred: cred.username,
    });
  }
}

function buildDomainAdmin(chnList, credById, hostById, hosts, nodes, add) {
  const daEntries = chnList.filter(c => c.access?.includes('domain_admin'));
  for (const da of daEntries) {
    const cred = credById[da.cred_id];
    const srcHost = hostById[da.host_id];
    if (!cred || !srcHost) continue;
    const srcNode = getNodeForHost(srcHost, nodes);
    if (!srcNode) continue;
    addDomainAdminEdges(da, cred, srcHost, srcNode, hosts, nodes, add);
  }
}

function buildHashReuse(creds, hosts, nodes, add) {
  const byHash = {};
  for (const c of creds) {
    if (c.secret && /^[a-fA-F0-9]{32}$/.test(c.secret)) {
      const k = c.secret.toLowerCase();
      if (!byHash[k]) byHash[k] = [];
      byHash[k].push(c);
    }
  }
  for (const [, hcreds] of Object.entries(byHash)) {
    if (hcreds.length < 2) continue;
    const mapped = hcreds.map(c => {
      const h = hosts.find(h2 => h2.ip === c.host || h2.hostname === c.host || (c.host_ids || []).includes(h2.id));
      return h ? { node: getNodeForHost(h, nodes), host: h, cred: c } : null;
    }).filter(x => x?.node);
    for (let i = 0; i < mapped.length; i++) {
      for (let j = i + 1; j < mapped.length; j++) {
        add({
          category: 'hash_reuse',
          from: mapped[i].node.id, to: mapped[j].node.id,
          fromLabel: mapped[i].node.label, toLabel: mapped[j].node.label,
          label: 'PTH',
          style: 'lateral',
          reason: `Same NTLM hash: ${mapped[i].cred.username} / ${mapped[j].cred.username}`,
          cred: mapped[i].cred.username,
        });
      }
    }
  }
}

function groupByPassword(creds) {
  const byPwd = {};
  for (const c of creds) {
    if (c.secret && c.secret.length >= 4 && !/^[a-fA-F0-9]{32}$/.test(c.secret)) {
      if (!byPwd[c.secret]) byPwd[c.secret] = [];
      byPwd[c.secret].push(c);
    }
  }
  return byPwd;
}

function addPasswordReusePairs(pwd, mapped, add) {
  for (let i = 0; i < mapped.length; i++) {
    for (let j = i + 1; j < mapped.length; j++) {
      if (mapped[i].cred.id === mapped[j].cred.id) continue;
      add({
        category: 'password_reuse',
        from: mapped[i].node.id, to: mapped[j].node.id,
        fromLabel: mapped[i].node.label, toLabel: mapped[j].node.label,
        label: 'pwd reuse',
        style: 'lateral',
        reason: `Password "${pwd.slice(0, 4)}…" reused: ${mapped[i].cred.username} / ${mapped[j].cred.username}`,
        cred: mapped[i].cred.username,
      });
    }
  }
}

function buildPasswordReuse(creds, hosts, nodes, add) {
  const byPwd = groupByPassword(creds);
  for (const [pwd, pcreds] of Object.entries(byPwd)) {
    if (pcreds.length < 2) continue;
    const mapped = pcreds.map(c => {
      const h = hosts.find(h2 => h2.ip === c.host || h2.hostname === c.host);
      return h ? { node: getNodeForHost(h, nodes), host: h, cred: c } : null;
    }).filter(x => x?.node);
    addPasswordReusePairs(pwd, mapped, add);
  }
}

const SERVICE_CHECKS = [
  { ports: ['80','443','8080','8443'], label: 'HTTP(S)', reason: 'Open web port' },
  { ports: ['22'],                     label: 'SSH',     reason: 'Open SSH' },
  { ports: ['445','139'],              label: 'SMB',     reason: 'Open SMB' },
  { ports: ['3389'],                   label: 'RDP',     reason: 'Open RDP' },
  { ports: ['5985','5986'],            label: 'WinRM',   reason: 'Open WinRM' },
  { ports: ['1433'],                   label: 'MSSQL',   reason: 'Open MSSQL' },
  { ports: ['3306'],                   label: 'MySQL',   reason: 'Open MySQL' },
];

function buildServiceReach(nodes, add) {
  const attacker = nodes.find(n => n.type === 'attacker');
  if (!attacker) return;
  for (const n of nodes) {
    if (n.id === attacker.id) continue;
    const ports = new Set((n.ports || []).map(String));
    for (const { ports: ps, label, reason } of SERVICE_CHECKS) {
      if (ps.some(p => ports.has(p))) {
        add({
          category: 'service_reach',
          from: attacker.id, to: n.id,
          fromLabel: attacker.label, toLabel: n.label,
          label, style: 'normal',
          reason: `${reason} on ${n.label}`,
          cred: null,
        });
      }
    }
  }
}

function isDelegationCred(c) {
  if (!c.notes) return false;
  const lc = c.notes.toLowerCase();
  return lc.includes('constrained delegation') || lc.includes('delegation target');
}

function findTargetNode(target, hosts, nodes) {
  const shortTarget = target.toLowerCase().split('/')[0].split('.')[0];
  const targetHost = hosts.find(h =>
    h.hostname?.toLowerCase().includes(shortTarget) || h.ip === target
  );
  return targetHost ? getNodeForHost(targetHost, nodes) : null;
}

function addDelegationTargets(line, c, srcNode, hosts, nodes, add) {
  if (!line.toLowerCase().includes('delegation target')) return;
  const targets = line.replace(/^.*?:/, '').split(',').map(s => s.trim()).filter(Boolean);
  for (const target of targets) {
    const targetNode = findTargetNode(target, hosts, nodes);
    if (!targetNode) continue;
    add({
      category: 'delegation',
      from: srcNode.id, to: targetNode.id,
      fromLabel: srcNode.label, toLabel: targetNode.label,
      label: 'deleg',
      style: 'lateral',
      reason: `${c.username} has constrained delegation to ${target}`,
      cred: c.username,
    });
  }
}

function buildDelegationForCred(c, hosts, nodes, add) {
  const srcHost = hosts.find(h => h.ip === c.host || h.hostname === c.host);
  const srcNode = srcHost ? getNodeForHost(srcHost, nodes) : null;
  if (!srcNode) return;
  for (const line of c.notes.split('\n')) {
    addDelegationTargets(line, c, srcNode, hosts, nodes, add);
  }
}

function buildDelegation(creds, hosts, nodes, add) {
  for (const c of creds) {
    if (!isDelegationCred(c)) continue;
    buildDelegationForCred(c, hosts, nodes, add);
  }
}

function analyzeVectors(hosts, creds, chnList, nodes) {
  const vectors = [];
  const hostById  = Object.fromEntries(hosts.map(h => [h.id, h]));
  const credById  = Object.fromEntries(creds.map(c => [c.id, c]));

  const seen = new Set();
  const add = makeAdder(seen, vectors);

  const chnByCred = {};
  for (const c of chnList) {
    if (!chnByCred[c.cred_id]) chnByCred[c.cred_id] = [];
    chnByCred[c.cred_id].push(c);
  }

  buildCredReuse(chnByCred, credById, hostById, nodes, add);
  buildDomainAdmin(chnList, credById, hostById, hosts, nodes, add);
  buildHashReuse(creds, hosts, nodes, add);
  buildPasswordReuse(creds, hosts, nodes, add);
  buildServiceReach(nodes, add);
  buildDelegation(creds, hosts, nodes, add);

  return vectors;
}

function renderLoading(accent) {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12, padding: 40 }}>
      <div style={{ width: 32, height: 32, border: `3px solid ${accent}33`, borderTop: `3px solid ${accent}`, borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
      <div style={{ fontSize: 12, color: '#606570', fontFamily: 'JetBrains Mono' }}>Analyzing attack paths…</div>
    </div>
  );
}

function renderEmpty() {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, padding: 40 }}>
      <div style={{ fontSize: 32 }}>✓</div>
      <div style={{ fontSize: 13, color: '#39d353', fontFamily: 'Space Grotesk', fontWeight: 600 }}>No new attack paths found</div>
      <div style={{ fontSize: 11, color: '#404550', fontFamily: 'JetBrains Mono', textAlign: 'center', maxWidth: 400 }}>
        Either all detected vectors are already on the map, or not enough data is available.
        Add more creds with confirmed access roles (LA/DA) to enable path analysis.
      </div>
    </div>
  );
}

function renderCategoryTabs(activeTab, setActiveTab, grouped, newVectors, accent) {
  return (
    <div style={{ display: 'flex', borderBottom: '1px solid #1e2029', background: '#0a0c10', overflowX: 'auto', flexShrink: 0 }}>
      <button onClick={() => setActiveTab(null)} style={{ padding: '8px 14px', background: 'none', border: 'none', borderBottom: activeTab === null ? `2px solid ${accent}` : '2px solid transparent', cursor: 'pointer', color: activeTab === null ? '#e0e4ec' : '#505560', fontSize: 10, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', flexShrink: 0 }}>
        All <span style={{ color: accent, marginLeft: 4 }}>{newVectors.length}</span>
      </button>
      {Object.entries(CATEGORIES).map(([key, cat]) => {
        const count = grouped[key]?.length || 0;
        if (!count) return null;
        return (
          <button key={key} onClick={() => setActiveTab(key)} style={{ padding: '8px 14px', background: 'none', border: 'none', borderBottom: activeTab === key ? `2px solid ${cat.color}` : '2px solid transparent', cursor: 'pointer', color: activeTab === key ? cat.color : '#505560', fontSize: 10, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 5 }}>
            <span>{cat.icon}</span> {cat.label} <span style={{ color: cat.color, opacity: .8 }}>{count}</span>
          </button>
        );
      })}
    </div>
  );
}

function renderVectorRow(v, selected, toggleV) {
  const cat = CATEGORIES[v.category];
  const isSel = selected.has(v._key);
  return (
    <button type="button" key={v._key} onClick={() => toggleV(v._key)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 14px', borderBottom: '1px solid #14161b', cursor: 'pointer', background: isSel ? `${cat.color}0a` : 'transparent', borderLeft: isSel ? `2px solid ${cat.color}88` : '2px solid transparent', transition: 'background .1s', width: '100%', textAlign: 'left' }}>
      <input type="checkbox" checked={isSel} onChange={() => toggleV(v._key)} onClick={e => e.stopPropagation()} style={{ width: 13, height: 13, cursor: 'pointer', accentColor: cat.color, flexShrink: 0 }} />

      <div style={{ width: 28, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <span style={{ fontSize: 8, color: cat.color, background: cat.color + '18', border: `1px solid ${cat.color}44`, borderRadius: 3, padding: '2px 5px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>{v.label}</span>
      </div>

      <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
        <span style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }}>{v.fromLabel}</span>
        <span style={{ color: cat.color, fontSize: 14, flexShrink: 0 }}>→</span>
        <span style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }}>{v.toLabel}</span>
      </div>

      <span style={{ fontSize: 8, color: cat.color, background: cat.color + '15', border: `1px solid ${cat.color}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', flexShrink: 0 }}>{cat.icon} {cat.label}</span>

      <span title={v.reason} style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }}>{v.reason}</span>
    </button>
  );
}

function buildExistingKeys(existingEdges) {
  const s = new Set();
  for (const e of existingEdges) {
    s.add(`${e.from}~${e.to}:${e.label}`);
    s.add(`${e.to}~${e.from}:${e.label}`);
  }
  return s;
}

function isNewVector(v, existingKeys) {
  return !existingKeys.has(`${v.from}~${v.to}:${v.label}`) && !existingKeys.has(`${v.to}~${v.from}:${v.label}`);
}

function groupVectors(vectors) {
  const g = {};
  for (const v of vectors) {
    if (!g[v.category]) g[v.category] = [];
    g[v.category].push(v);
  }
  return g;
}

function toggleSetKey(prev, key) {
  const next = new Set(prev);
  if (next.has(key)) { next.delete(key); } else { next.add(key); }
  return next;
}

function applyToggleAll(prev, keys, allSel) {
  const next = new Set(prev);
  for (const k of keys) {
    if (allSel) { next.delete(k); } else { next.add(k); }
  }
  return next;
}

function buildEdgesToAdd(newVectors, selected) {
  return newVectors
    .filter(v => selected.has(v._key))
    .map(v => ({
      id: `av_${crypto.randomUUID()}`,
      from: v.from, to: v.to, label: v.label, style: v.style,
    }));
}

function _computeAllVectors(chnList, hosts, creds, nodes) {
  if (!chnList) return [];
  return analyzeVectors(hosts, creds, chnList, nodes);
}

function _loadChnList(projectId, setChnList, setLoading) {
  api.getCredHostNotes({ pid: projectId })
    .then(list => { setChnList(list); setLoading(false); })
    .catch(() => { setChnList([]); setLoading(false); });
}

function _allVisibleSelected(visibleVectors, selected) {
  return visibleVectors.length > 0 && visibleVectors.every(v => selected.has(v._key));
}

function _applyVectorSelection(newVectors, selected, onApply, onClose) {
  const toAdd = buildEdgesToAdd(newVectors, selected);
  if (toAdd.length > 0) onApply(toAdd);
  onClose();
}

function AVAFooter({ totalSelected, accent, onClose, onApply }) {
  const hasSelected = totalSelected > 0;
  const edgePlural = totalSelected === 1 ? '' : 's';
  const summary = hasSelected
    ? `Will add ${totalSelected} edge${edgePlural} to the map`
    : 'Select paths to add to the network map';
  return (
    <div style={{ padding: '12px 18px', borderTop: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, background: '#090b0f', flexShrink: 0 }}>
      <div style={{ flex: 1, fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>{summary}</div>
      <button onClick={onClose} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '6px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
      <button onClick={onApply} disabled={!hasSelected} style={{ background: hasSelected ? accent : '#1a1c22', border: 'none', borderRadius: 5, padding: '6px 16px', cursor: hasSelected ? 'pointer' : 'default', color: hasSelected ? '#fff' : '#404550', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', opacity: hasSelected ? 1 : .5 }}>
        Add {hasSelected ? `(${totalSelected})` : ''} to map
      </button>
    </div>
  );
}
AVAFooter.propTypes = { totalSelected: PropTypes.any, accent: PropTypes.any, onClose: PropTypes.any, onApply: PropTypes.any };

export default function AttackVectorAnalyzer({ projectId, hosts, creds, nodes, existingEdges, accent, onApply, onClose }) {
  const [chnList, setChnList]   = useState(null);
  const [loading, setLoading]   = useState(true);
  const [selected, setSelected] = useState(new Set());
  const [activeTab, setActiveTab] = useState(null);

  useEffect(() => { _loadChnList(projectId, setChnList, setLoading); }, [projectId]);

  const allVectors = useMemo(() => _computeAllVectors(chnList, hosts, creds, nodes), [chnList, hosts, creds, nodes]);
  const existingKeys = useMemo(() => buildExistingKeys(existingEdges), [existingEdges]);
  const newVectors = useMemo(() => allVectors.filter(v => isNewVector(v, existingKeys)), [allVectors, existingKeys]);
  const grouped = useMemo(() => groupVectors(newVectors), [newVectors]);
  const visibleVectors = activeTab ? (grouped[activeTab] || []) : newVectors;
  const totalSelected = newVectors.filter(v => selected.has(v._key)).length;

  const toggleV = (key) => setSelected(prev => toggleSetKey(prev, key));
  const toggleAll = () => {
    const keys = visibleVectors.map(v => v._key);
    const allSel = keys.every(k => selected.has(k));
    setSelected(prev => applyToggleAll(prev, keys, allSel));
  };
  const applySelected = () => _applyVectorSelection(newVectors, selected, onApply, onClose);
  const vectorCountLabel = `${newVectors.length} new vector${newVectors.length === 1 ? '' : 's'} detected`;

  const showLoading = loading;
  const showEmpty = !loading && newVectors.length === 0;
  const showResults = !loading && newVectors.length > 0;

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#00000099', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ width: 740, maxHeight: '88vh', background: '#0c0e13', border: '1px solid #2a2d35', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 24px 64px #000000cc' }}>

        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 14, fontWeight: 700, color: '#e0e4ec', fontFamily: 'Space Grotesk', flex: 1 }}>Attack Vector Analyzer</span>
          {!loading && <span style={{ fontSize: 11, color: newVectors.length > 0 ? accent : '#404550', fontFamily: 'JetBrains Mono' }}>{vectorCountLabel}</span>}
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={13} color="#606570" /></button>
        </div>

        {showLoading && renderLoading(accent)}
        {showEmpty && renderEmpty()}
        {showResults && (
          <>
            {renderCategoryTabs(activeTab, setActiveTab, grouped, newVectors, accent)}

            <div style={{ padding: '7px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8, background: '#0a0c10', flexShrink: 0 }}>
              <input type="checkbox"
                checked={_allVisibleSelected(visibleVectors, selected)}
                onChange={toggleAll}
                style={{ width: 13, height: 13, cursor: 'pointer', accentColor: accent }}
              />
              <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', flex: 1 }}>
                {visibleVectors.length} path{visibleVectors.length === 1 ? '' : 's'} shown
              </span>
              {totalSelected > 0 && (
                <span style={{ fontSize: 10, color: accent, fontFamily: 'JetBrains Mono' }}>
                  {totalSelected} selected
                </span>
              )}
            </div>

            <div style={{ flex: 1, overflowY: 'auto' }}>
              {visibleVectors.map((v) => renderVectorRow(v, selected, toggleV))}
            </div>

            <AVAFooter totalSelected={totalSelected} accent={accent} onClose={onClose} onApply={applySelected} />
          </>
        )}
      </div>
    </div>
  );
}
AttackVectorAnalyzer.propTypes = { projectId: PropTypes.any, hosts: PropTypes.any, creds: PropTypes.any, nodes: PropTypes.any, existingEdges: PropTypes.any, accent: PropTypes.any, onApply: PropTypes.any, onClose: PropTypes.any };
