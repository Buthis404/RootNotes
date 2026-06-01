import React, { useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import TopologyBuilderModal from '../components/TopologyBuilderModal.jsx';
import { NETWORK_BACKGROUNDS } from './network-map/constants.js';
import { computeOverlayThreats, computeOverlaySessions, computeOverlayAccess, computeOverlayPivots, computeOverlayRoles } from './network-map/GraphAlgorithms.jsx';

const NetworkCanvas = React.lazy(() => import('./network-map/NetworkCanvas.jsx'));

// ── AddPivotModal ────────────────────────────────────────────────────

function AddPivotModal({ projectId, hosts, accent, onClose, onCreated, initialPivotHostId = '' }) {
  const [form, setForm] = useState({ pivot_host_id: initialPivotHostId, source_host_id: '', tool: 'chisel', pivot_type: 'socks5', route_cidr: '', bind_address: '', status: 'active', notes: '' });
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState('');

  const save = async () => {
    if (!form.pivot_host_id) { setErr('Select pivot host'); return; }
    setSaving(true); setErr('');
    try { await api.createPivot(projectId, { ...form, pid: projectId }); onCreated(); onClose(); }
    catch (e) { setErr(e?.message || 'Failed to create pivot'); } finally { setSaving(false); }
  };

  const inp = { background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', width: '100%', boxSizing: 'border-box' };
  const lbl = { fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2000 }}>
      <button type="button" aria-label="Close add pivot modal" onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
      <div style={{ background: '#0c0e13', border: '1px solid #2a2d35', borderRadius: 8, padding: 24, width: 400, boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 20 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: '#e0e4ec', fontFamily: 'Space Grotesk', flex: 1 }}>Add Pivot</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 16, padding: 0 }}>×</button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div><div style={lbl}>Pivot Host *</div><select value={form.pivot_host_id} onChange={e => setForm(s => ({ ...s, pivot_host_id: e.target.value }))} style={inp}><option value="">Select host…</option>{hosts.map(h => <option key={h.id} value={h.id}>{h.hostname || h.ip}{h.ip && h.hostname ? ` (${h.ip})` : ''}</option>)}</select></div>
          <div><div style={lbl}>Source Host (optional)</div><select value={form.source_host_id} onChange={e => setForm(s => ({ ...s, source_host_id: e.target.value }))} style={inp}><option value="">— attacker default —</option>{hosts.filter(h => h.is_attacker).map(h => <option key={h.id} value={h.id}>{h.hostname || h.ip} (attacker)</option>)}{hosts.filter(h => !h.is_attacker).map(h => <option key={h.id} value={h.id}>{h.hostname || h.ip}</option>)}</select></div>
          <div style={{ display: 'flex', gap: 10 }}>
            <div style={{ flex: 1 }}><div style={lbl}>Tool</div><select value={form.tool} onChange={e => setForm(s => ({ ...s, tool: e.target.value }))} style={inp}>{['chisel', 'ligolo', 'ligolo-ng', 'metasploit', 'ssh', 'other'].map(t => <option key={t} value={t}>{t}</option>)}</select></div>
            <div style={{ flex: 1 }}><div style={lbl}>Type</div><select value={form.pivot_type} onChange={e => setForm(s => ({ ...s, pivot_type: e.target.value }))} style={inp}>{['socks5', 'socks4', 'route', 'portfwd', 'reverse'].map(t => <option key={t} value={t}>{t}</option>)}</select></div>
          </div>
          <div><div style={lbl}>Route CIDR</div><input value={form.route_cidr} onChange={e => setForm(s => ({ ...s, route_cidr: e.target.value }))} placeholder="x.x.x.x/24" style={inp} /></div>
          <div><div style={lbl}>Bind Address</div><input value={form.bind_address} onChange={e => setForm(s => ({ ...s, bind_address: e.target.value }))} placeholder="127.0.0.1:1080" style={inp} /></div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div style={lbl}>Status:</div>
            {[['active', '#39d353'], ['inactive', '#808590']].map(([s, c]) => (
              <button key={s} onClick={() => setForm(f => ({ ...f, status: s }))} style={{ background: form.status === s ? c + '22' : 'transparent', border: `1px solid ${form.status === s ? c + '66' : '#2a2d35'}`, borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: form.status === s ? c : '#505560', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{s}</button>
            ))}
          </div>
          {err && <div style={{ fontSize: 10, color: '#cc2233' }}>{err}</div>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
            <button onClick={onClose} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
            <button onClick={save} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 16px', cursor: saving ? 'default' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', opacity: saving ? 0.7 : 1 }}>{saving ? 'Saving…' : 'Add Pivot'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

AddPivotModal.propTypes = {
  projectId: PropTypes.any,
  hosts: PropTypes.array,
  accent: PropTypes.string,
  onClose: PropTypes.func,
  onCreated: PropTypes.func,
  initialPivotHostId: PropTypes.string,
};

// ── Toast / toolbar helpers ──────────────────────────────────────────

const OVERLAY_MODES = [
  { key: 'none', label: 'No overlay', color: '#404550' },
  { key: 'threats', label: '⚑ Threats', color: '#e8574a' },
  { key: 'sessions', label: '⊙ Sessions', color: '#39d353' },
  { key: 'access', label: '✓ Access', color: '#f09a3a' },
  { key: 'pivots', label: '⇄ Pivots', color: '#e8cc42' },
  { key: 'roles', label: '◈ Roles', color: '#6fc8f0' },
];

function SmartBuildSummaryToast({ summary }) {
  if (!summary) return null;
  return (
    <div style={{ position: 'absolute', top: 84, right: 18, zIndex: 60, background: '#0a0c10', border: '1px solid #39d35344', borderRadius: 6, padding: '10px 14px', boxShadow: '0 6px 20px #000a', fontFamily: 'JetBrains Mono', fontSize: 10, color: '#c8cdd6', minWidth: 230 }}>
      <div style={{ color: '#39d353', fontWeight: 600, marginBottom: 6 }}>Smart Build complete</div>
      <div>+{summary.edges_added} edges · +{summary.nodes_added} nodes · +{summary.regions_added} regions</div>
      {summary.edges_stale > 0 && <div style={{ color: '#9098a8', marginTop: 4 }}>{summary.edges_stale} stale (decayed)</div>}
      {Object.keys(summary.by_source).length > 0 && <div style={{ marginTop: 8, paddingTop: 6, borderTop: '1px solid #1a1c22', color: '#808890' }}>{Object.entries(summary.by_source).map(([k, v]) => <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}><span>{k}</span><span style={{ color: '#c8cdd6' }}>{v}</span></div>)}</div>}
      {summary.ts && <div style={{ marginTop: 6, color: '#505560', fontSize: 9 }}>{new Date(summary.ts).toLocaleTimeString()}</div>}
    </div>
  );
}

SmartBuildSummaryToast.propTypes = {
  summary: PropTypes.object,
};

function OverlayModeSelector({ overlayMode, setOverlayMode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', borderRight: '1px solid #1a1c22' }}>
      {OVERLAY_MODES.map(m => <button key={m.key} onClick={() => setOverlayMode(m.key)} title={`Overlay: ${m.label}`} style={{ background: overlayMode === m.key ? m.color + '18' : 'transparent', border: 'none', padding: '7px 11px', cursor: 'pointer', color: overlayMode === m.key ? m.color : '#404550', fontSize: 10, fontFamily: 'JetBrains Mono', transition: 'color .15s', flexShrink: 0 }}>{m.label}</button>)}
    </div>
  );
}

OverlayModeSelector.propTypes = {
  overlayMode: PropTypes.string,
  setOverlayMode: PropTypes.func,
};

function NetworkTabBar({ networks, activeNetId, setActiveNetId, editingName, nameVal, setNameVal, commitRename, setEditingName, startRename, accent, onDeleteNetwork, onCreateNetwork, onUpdateNetwork, activeNet, projectId }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', background: '#0a0b0f', borderBottom: '1px solid #1a1c22', flexShrink: 0, paddingLeft: 4 }}>
      <div style={{ display: 'flex', flex: 1, overflowX: 'auto' }}>
        {networks.map(net => {
          const isActive = net.id === activeNetId;
          return (
            <div key={net.id} style={{ display: 'flex', alignItems: 'center', borderRight: '1px solid #1a1c22', flexShrink: 0 }}>
              <span style={{ width: 8, alignSelf: 'stretch', background: net.background || '#07080b' }} />
              {editingName === net.id
                ? <input autoFocus value={nameVal} onChange={e => setNameVal(e.target.value)} onBlur={() => commitRename(net.id)} onKeyDown={e => { if (e.key === 'Enter') { commitRename(net.id); } if (e.key === 'Escape') { setEditingName(null); } }} style={{ background: '#0e1016', border: '1px solid ' + accent, outline: 'none', color: '#f0f2f6', fontSize: 11, fontFamily: 'JetBrains Mono', padding: '6px 10px', width: 140 }} />
                : <button onClick={() => setActiveNetId(net.id)} onDoubleClick={() => startRename(net)} style={{ background: isActive ? '#12141a' : 'transparent', border: 'none', borderBottom: isActive ? `2px solid ${accent}` : '2px solid transparent', padding: '9px 14px', cursor: 'pointer', color: isActive ? '#f0f2f6' : '#606570', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: isActive ? 600 : 400 }}>{net.name}<span style={{ fontSize: 9, color: isActive ? accent + '99' : '#404550', marginLeft: 6 }}>{net.nodes?.length || 0}</span></button>
              }
              {isActive && networks.length > 1 && <button onClick={() => onDeleteNetwork(net.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', padding: '0 6px', display: 'flex' }}><Icon name="close" size={10} color="currentColor" /></button>}
            </div>
          );
        })}
      </div>
      {activeNet && <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingRight: 10 }}>{NETWORK_BACKGROUNDS.map(bg => <button key={bg} onClick={() => onUpdateNetwork(activeNet.id, { background: bg })} style={{ width: 14, height: 14, borderRadius: 3, background: bg, border: `1px solid ${(activeNet.background || '#07080b') === bg ? accent : '#2a2d35'}`, cursor: 'pointer' }} />)}</div>}
      <button onClick={() => onCreateNetwork({ pid: projectId, name: `Network ${networks.length + 1}`, background: NETWORK_BACKGROUNDS[networks.length % NETWORK_BACKGROUNDS.length] })} style={{ background: 'transparent', border: 'none', borderLeft: '1px solid #1a1c22', padding: '9px 14px', cursor: 'pointer', color: '#404550', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono' }}><Icon name="plus" size={11} color="currentColor" /> Network</button>
    </div>
  );
}

NetworkTabBar.propTypes = {
  networks: PropTypes.array,
  activeNetId: PropTypes.string,
  setActiveNetId: PropTypes.func,
  editingName: PropTypes.string,
  nameVal: PropTypes.string,
  setNameVal: PropTypes.func,
  commitRename: PropTypes.func,
  setEditingName: PropTypes.func,
  startRename: PropTypes.func,
  accent: PropTypes.string,
  onDeleteNetwork: PropTypes.func,
  onCreateNetwork: PropTypes.func,
  onUpdateNetwork: PropTypes.func,
  activeNet: PropTypes.object,
  projectId: PropTypes.any,
};

// ── Async helpers ────────────────────────────────────────────────────

async function _doSmartBuild(projectId, setSmartBuilding, setSmartBuildSummary, onRefreshNetworks) {
  setSmartBuilding(true);
  try {
    const res = await api.topologySmartBuild(projectId, { keep_manual_positions: true, include_access_edges: true, include_domain_edges: true, include_subnet_edges: true, include_regions: true, include_internet_facing: true });
    if (res && typeof res === 'object') {
      setSmartBuildSummary({ edges_added: res.edges_added ?? 0, nodes_added: res.nodes_added ?? 0, edges_stale: res.edges_stale ?? 0, regions_added: res.regions_added ?? 0, by_source: res.edges_by_source || {}, ts: res.last_smart_build || '' });
      setTimeout(() => setSmartBuildSummary(null), 9000);
    }
    await onRefreshNetworks?.();
  } catch (e) { console.error('Smart-build failed:', e); } finally { setSmartBuilding(false); }
}

async function _doCollectPivots(projectId, setPivots, onRefreshNetworks) {
  try {
    await api.collectPivots(projectId, {});
    const data = await api.listPivots(projectId);
    setPivots(data?.items || []);
    await onRefreshNetworks?.();
  } catch (e) { console.error('Pivot collection failed:', e); }
}

async function _doDeletePivot(projectId, pivotId, setPivots) {
  try { await api.deletePivot(projectId, pivotId); setPivots(prev => prev.filter(p => p.id !== pivotId)); } catch (e) { console.error('Delete pivot failed:', e); }
}

async function _doUpdatePivot(projectId, pivotId, data, setPivots) {
  try { const updated = await api.updatePivot(projectId, pivotId, data); setPivots(prev => prev.map(p => p.id === pivotId ? updated : p)); } catch (e) { console.error('Update pivot failed:', e); }
}

function _computeOverlayData(overlayMode, { creds, objectives, findings, attackSteps, projectHosts, allActivities, pivots, networks, activeNetId }) {
  if (overlayMode === 'none') return null;
  const map = new Map();
  if (overlayMode === 'threats') computeOverlayThreats(map, creds, objectives, findings, attackSteps, projectHosts);
  if (overlayMode === 'sessions') computeOverlaySessions(map, allActivities);
  if (overlayMode === 'access') computeOverlayAccess(map, creds, projectHosts, networks, activeNetId);
  if (overlayMode === 'pivots') computeOverlayPivots(map, pivots);
  if (overlayMode === 'roles') computeOverlayRoles(map, projectHosts);
  return map.size > 0 ? map : null;
}

function useNetworkActiveId(projectId, networks, activeNetId, setActiveNetId) {
  useEffect(() => {
    if (networks.length > 0) { if (!activeNetId || !networks.some(n => n.id === activeNetId)) setActiveNetId(networks[0].id); } else { setActiveNetId(null); }
  }, [projectId, networks, activeNetId]); // eslint-disable-line react-hooks/exhaustive-deps
}

function useTopologyEnabled(projectId, setTopologyEnabled) {
  useEffect(() => {
    let cancelled = false;
    api.listModules().then(({ modules }) => { if (cancelled) { return; } const topology = (modules || []).find(mod => mod.name === 'topology'); setTopologyEnabled(topology ? topology.enabled !== false : true); }).catch(() => { if (!cancelled) { setTopologyEnabled(true); } });
    return () => { cancelled = true; };
  }, [projectId]); // eslint-disable-line react-hooks/exhaustive-deps
}

async function _loadPivots(projectId, setPivots) {
  if (!projectId) return;
  try { const data = await api.listPivots(projectId); setPivots(data?.items || []); } catch { setPivots([]); }
}

async function _loadActivities(overlayMode, projectId, activitiesLen, setAllActivities) {
  if (overlayMode !== 'sessions' || !projectId) return;
  if (activitiesLen > 0) return;
  try { const data = await api.getHostActivities(projectId); setAllActivities(data || []); } catch {}
}

async function _handlePivotCreated(projectId, setPivots, setAddPivotPrefilledHostId) {
  const data = await api.listPivots(projectId).catch(() => ({ items: [] }));
  setPivots(data?.items || []); setAddPivotPrefilledHostId(null);
}

function _shouldShowBanner(topologyEnabled, activeNet, projectHosts) {
  return topologyEnabled && !!activeNet && (activeNet.nodes || []).length === 0 && projectHosts.length > 0;
}

// ── Toolbar / Banner / EmptyState ───────────────────────────────────

function NetworkToolbar({ topologyEnabled, projectHosts, smartBuilding, activeNet, accessOverlay, setAccessOverlay, handleSmartBuild, handleCollectPivots, setShowAddPivot, setShowTopologyBuilder, overlayMode, setOverlayMode }) {
  if (!topologyEnabled) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', background: '#0a0b0f', borderBottom: '1px solid #1a1c22', flexShrink: 0, overflowX: 'auto' }}>
      {projectHosts.length > 0 && <button onClick={handleSmartBuild} disabled={smartBuilding} title="Smart Build" style={{ background: smartBuilding ? 'transparent' : '#39d35310', border: 'none', borderRight: '1px solid #1a1c22', padding: '7px 14px', cursor: smartBuilding ? 'default' : 'pointer', color: smartBuilding ? '#404550' : '#39d353', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono', opacity: smartBuilding ? 0.6 : 1, flexShrink: 0 }}><Icon name="target" size={11} color="currentColor" />{smartBuilding ? 'Building…' : 'Smart Build'}</button>}
      {(activeNet?.edges?.length ?? (activeNet?.edges_json?.length ?? 0)) > 0 && <button onClick={() => setAccessOverlay(v => !v)} title="Access Graph" style={{ background: accessOverlay ? '#39d35312' : 'transparent', border: 'none', borderRight: '1px solid #1a1c22', padding: '7px 14px', cursor: 'pointer', color: accessOverlay ? '#39d353' : '#404550', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}><Icon name="link" size={11} color="currentColor" />Access Graph</button>}
      <OverlayModeSelector overlayMode={overlayMode} setOverlayMode={setOverlayMode} />
      <button onClick={() => setShowAddPivot(true)} title="Add Pivot" style={{ background: 'transparent', border: 'none', borderRight: '1px solid #1a1c22', padding: '7px 14px', cursor: 'pointer', color: '#c07af0', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}><Icon name="plus" size={11} color="currentColor" />Add Pivot</button>
      <button onClick={handleCollectPivots} title="Collect Pivots" style={{ background: 'transparent', border: 'none', borderRight: '1px solid #1a1c22', padding: '7px 14px', cursor: 'pointer', color: '#e8cc42', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}><Icon name="link" size={11} color="currentColor" />Collect Pivots</button>
      <button onClick={() => setShowTopologyBuilder(true)} title="Build topology from scan" style={{ background: 'transparent', border: 'none', borderRight: '1px solid #1a1c22', padding: '7px 14px', cursor: 'pointer', color: '#5b8af5', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}><Icon name="target" size={11} color="currentColor" /> Topology</button>
    </div>
  );
}

NetworkToolbar.propTypes = {
  topologyEnabled: PropTypes.bool,
  projectHosts: PropTypes.array,
  smartBuilding: PropTypes.bool,
  activeNet: PropTypes.object,
  accessOverlay: PropTypes.bool,
  setAccessOverlay: PropTypes.func,
  handleSmartBuild: PropTypes.func,
  handleCollectPivots: PropTypes.func,
  setShowAddPivot: PropTypes.func,
  setShowTopologyBuilder: PropTypes.func,
  overlayMode: PropTypes.string,
  setOverlayMode: PropTypes.func,
};

function NetworkBanner({ smartBuilding, projectHosts, handleSmartBuild }) {
  return (
    <div style={{ padding: '10px 16px', background: '#0c0e13', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f09a3a', flexShrink: 0 }} />
      <span style={{ fontSize: 10, color: '#707580', fontFamily: 'JetBrains Mono', flex: 1 }}>{projectHosts.length} project hosts are not on this map</span>
      <button onClick={handleSmartBuild} disabled={smartBuilding} style={{ background: '#39d353', border: 'none', borderRadius: 5, padding: '6px 14px', cursor: smartBuilding ? 'default' : 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, opacity: smartBuilding ? 0.7 : 1 }}><Icon name="target" size={11} color="#fff" />{smartBuilding ? 'Building…' : 'Smart Build'}</button>
    </div>
  );
}

NetworkBanner.propTypes = {
  smartBuilding: PropTypes.bool,
  projectHosts: PropTypes.array,
  handleSmartBuild: PropTypes.func,
};

function NetworkEmptyState({ topologyEnabled, projectHosts, smartBuilding, accent, projectId, onCreateNetwork, handleSmartBuild }) {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 14, color: '#303540' }}>
      <Icon name="network" size={40} color="#2a2d35" />
      <div style={{ fontSize: 13, color: '#404550' }}>No network maps</div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={() => onCreateNetwork({ pid: projectId, name: 'Main network', background: '#07080b' })} style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7 }}><Icon name="plus" size={12} color="currentColor" /> Create empty map</button>
        {topologyEnabled && projectHosts.length > 0 && <button onClick={handleSmartBuild} disabled={smartBuilding} style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 18px', cursor: smartBuilding ? 'default' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7, opacity: smartBuilding ? 0.7 : 1 }}><Icon name="target" size={12} color="#fff" />{smartBuilding ? 'Building…' : 'Smart Build'}</button>}
      </div>
    </div>
  );
}

NetworkEmptyState.propTypes = {
  topologyEnabled: PropTypes.bool,
  projectHosts: PropTypes.array,
  smartBuilding: PropTypes.bool,
  accent: PropTypes.string,
  projectId: PropTypes.any,
  onCreateNetwork: PropTypes.func,
  handleSmartBuild: PropTypes.func,
};

// ── Body ─────────────────────────────────────────────────────────────

function NetworkViewBody({ projectId, accent, accentGreen, networks, onCreateNetwork, onUpdateNetwork, onDeleteNetwork, onCreateHost, onUpdateHost, onSyncHostByIp, hosts: projectHosts, onAddActivity, onUpdateActivity, onDeleteActivity, onRefreshHosts, onRefreshNetworks, markLocalOp, animateLinks, smartBuildSummary, topologyEnabled, showTopologyBuilder, setShowTopologyBuilder, showAddPivot, setShowAddPivot, addPivotPrefilledHostId, setAddPivotPrefilledHostId, activeNetId, setActiveNetId, editingName, setEditingName, nameVal, setNameVal, smartBuilding, accessOverlay, setAccessOverlay, overlayMode, setOverlayMode, activeNet, overlayData, pivots, handleSmartBuild, handleCollectPivots, handleDeletePivot, handleUpdatePivot, handleAddPivotForHost, handlePivotCreated, startRename, commitRename }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>
      <SmartBuildSummaryToast summary={smartBuildSummary} />
      <NetworkTabBar networks={networks} activeNetId={activeNetId} setActiveNetId={setActiveNetId} editingName={editingName} nameVal={nameVal} setNameVal={setNameVal} commitRename={commitRename} setEditingName={setEditingName} startRename={startRename} accent={accent} onDeleteNetwork={onDeleteNetwork} onCreateNetwork={onCreateNetwork} onUpdateNetwork={onUpdateNetwork} activeNet={activeNet} projectId={projectId} />
      <NetworkToolbar topologyEnabled={topologyEnabled} projectHosts={projectHosts} smartBuilding={smartBuilding} activeNet={activeNet} accessOverlay={accessOverlay} setAccessOverlay={setAccessOverlay} handleSmartBuild={handleSmartBuild} handleCollectPivots={handleCollectPivots} setShowAddPivot={setShowAddPivot} setShowTopologyBuilder={setShowTopologyBuilder} overlayMode={overlayMode} setOverlayMode={setOverlayMode} />
      {topologyEnabled && showTopologyBuilder && <TopologyBuilderModal projectId={projectId} accent={accent} onClose={() => setShowTopologyBuilder(false)} onApplied={() => { setShowTopologyBuilder(false); onRefreshHosts?.(); onRefreshNetworks?.(); }} />}
      {_shouldShowBanner(topologyEnabled, activeNet, projectHosts) && <NetworkBanner smartBuilding={smartBuilding} projectHosts={projectHosts} handleSmartBuild={handleSmartBuild} />}
      {activeNet
        ? <React.Suspense fallback={<div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#404550' }}>Loading canvas…</div>}><NetworkCanvas key={activeNet.id} projectId={projectId} net={activeNet} onUpdate={(data) => onUpdateNetwork(activeNet.id, data)} onCreateHost={onCreateHost} onUpdateHost={onUpdateHost} onSyncHostByIp={onSyncHostByIp} accent={accent} accentGreen={accentGreen} hosts={projectHosts} onAddActivity={onAddActivity} onUpdateActivity={onUpdateActivity} onDeleteActivity={onDeleteActivity} markLocalOp={markLocalOp} animateLinks={animateLinks} overlayData={overlayData} accessOverlay={accessOverlay} overlayMode={overlayMode} pivots={pivots} projectHosts={projectHosts} onDeletePivot={handleDeletePivot} onUpdatePivot={handleUpdatePivot} onAddPivotForHost={handleAddPivotForHost} /></React.Suspense>
        : <NetworkEmptyState topologyEnabled={topologyEnabled} projectHosts={projectHosts} smartBuilding={smartBuilding} accent={accent} projectId={projectId} onCreateNetwork={onCreateNetwork} handleSmartBuild={handleSmartBuild} />
      }
      {showAddPivot && <AddPivotModal projectId={projectId} hosts={projectHosts} accent={accent} initialPivotHostId={addPivotPrefilledHostId || ''} onClose={() => { setShowAddPivot(false); setAddPivotPrefilledHostId(null); }} onCreated={handlePivotCreated} />}
    </div>
  );
}

NetworkViewBody.propTypes = {
  projectId: PropTypes.any,
  accent: PropTypes.string,
  accentGreen: PropTypes.string,
  networks: PropTypes.array,
  onCreateNetwork: PropTypes.func,
  onUpdateNetwork: PropTypes.func,
  onDeleteNetwork: PropTypes.func,
  onCreateHost: PropTypes.func,
  onUpdateHost: PropTypes.func,
  onSyncHostByIp: PropTypes.func,
  hosts: PropTypes.array,
  onAddActivity: PropTypes.func,
  onUpdateActivity: PropTypes.func,
  onDeleteActivity: PropTypes.func,
  onRefreshHosts: PropTypes.func,
  onRefreshNetworks: PropTypes.func,
  markLocalOp: PropTypes.func,
  animateLinks: PropTypes.bool,
  smartBuildSummary: PropTypes.object,
  topologyEnabled: PropTypes.bool,
  showTopologyBuilder: PropTypes.bool,
  setShowTopologyBuilder: PropTypes.func,
  showAddPivot: PropTypes.bool,
  setShowAddPivot: PropTypes.func,
  addPivotPrefilledHostId: PropTypes.string,
  setAddPivotPrefilledHostId: PropTypes.func,
  activeNetId: PropTypes.string,
  setActiveNetId: PropTypes.func,
  editingName: PropTypes.string,
  setEditingName: PropTypes.func,
  nameVal: PropTypes.string,
  setNameVal: PropTypes.func,
  smartBuilding: PropTypes.bool,
  accessOverlay: PropTypes.bool,
  setAccessOverlay: PropTypes.func,
  overlayMode: PropTypes.string,
  setOverlayMode: PropTypes.func,
  activeNet: PropTypes.object,
  overlayData: PropTypes.object,
  pivots: PropTypes.array,
  handleSmartBuild: PropTypes.func,
  handleCollectPivots: PropTypes.func,
  handleDeletePivot: PropTypes.func,
  handleUpdatePivot: PropTypes.func,
  handleAddPivotForHost: PropTypes.func,
  handlePivotCreated: PropTypes.func,
  startRename: PropTypes.func,
  commitRename: PropTypes.func,
};

// ── Root ─────────────────────────────────────────────────────────────

export default function NetworkView({ projectId, accent, accentGreen, networks, onCreateNetwork, onUpdateNetwork, onDeleteNetwork, onCreateHost, onUpdateHost, onSyncHostByIp, hosts, onAddActivity, onUpdateActivity, onDeleteActivity, onRefreshHosts, onRefreshNetworks, markLocalOp, animateLinks = true, findings = [], objectives = [], creds = [], attackSteps = [] }) {
  const [activeNetId, setActiveNetId] = useState(null);
  const [editingName, setEditingName] = useState(null);
  const [nameVal, setNameVal] = useState('');
  const [showTopologyBuilder, setShowTopologyBuilder] = useState(false);
  const [smartBuilding, setSmartBuilding] = useState(false);
  const [smartBuildSummary, setSmartBuildSummary] = useState(null);
  const [topologyEnabled, setTopologyEnabled] = useState(true);
  const [accessOverlay, setAccessOverlay] = useState(false);
  const [overlayMode, setOverlayMode] = useState('none');
  const [allActivities, setAllActivities] = useState([]);
  const [pivots, setPivots] = useState([]);
  const [showAddPivot, setShowAddPivot] = useState(false);
  const [addPivotPrefilledHostId, setAddPivotPrefilledHostId] = useState(null);

  useNetworkActiveId(projectId, networks, activeNetId, setActiveNetId);
  useTopologyEnabled(projectId, setTopologyEnabled);

  useEffect(() => { _loadPivots(projectId, setPivots); }, [projectId, networks]); // eslint-disable-line react-hooks/exhaustive-deps

  const activeNet = networks.find(n => n.id === activeNetId);
  const projectHosts = hosts;

  useEffect(() => { _loadActivities(overlayMode, projectId, allActivities.length, setAllActivities); }, [overlayMode, projectId]); // eslint-disable-line react-hooks/exhaustive-deps

  const overlayData = useMemo(
    () => _computeOverlayData(overlayMode, { creds, objectives, findings, attackSteps, projectHosts, allActivities, pivots, networks, activeNetId }),
    [overlayMode, creds, objectives, findings, attackSteps, projectHosts, allActivities, pivots, networks, activeNetId],
  );

  const handleSmartBuild = () => _doSmartBuild(projectId, setSmartBuilding, setSmartBuildSummary, onRefreshNetworks);
  const handleCollectPivots = () => _doCollectPivots(projectId, setPivots, onRefreshNetworks);
  const handleDeletePivot = (pivotId) => _doDeletePivot(projectId, pivotId, setPivots);
  const handleUpdatePivot = (pivotId, data) => _doUpdatePivot(projectId, pivotId, data, setPivots);
  const handleAddPivotForHost = (hostId) => { setAddPivotPrefilledHostId(hostId); setShowAddPivot(true); };
  const startRename = (net) => { setEditingName(net.id); setNameVal(net.name); };
  const commitRename = (id) => { if (nameVal.trim()) { onUpdateNetwork(id, { name: nameVal.trim() }); } setEditingName(null); };
  const handlePivotCreated = () => _handlePivotCreated(projectId, setPivots, setAddPivotPrefilledHostId);

  return <NetworkViewBody projectId={projectId} accent={accent} accentGreen={accentGreen} networks={networks} onCreateNetwork={onCreateNetwork} onUpdateNetwork={onUpdateNetwork} onDeleteNetwork={onDeleteNetwork} onCreateHost={onCreateHost} onUpdateHost={onUpdateHost} onSyncHostByIp={onSyncHostByIp} hosts={projectHosts} onAddActivity={onAddActivity} onUpdateActivity={onUpdateActivity} onDeleteActivity={onDeleteActivity} onRefreshHosts={onRefreshHosts} onRefreshNetworks={onRefreshNetworks} markLocalOp={markLocalOp} animateLinks={animateLinks} smartBuildSummary={smartBuildSummary} topologyEnabled={topologyEnabled} showTopologyBuilder={showTopologyBuilder} setShowTopologyBuilder={setShowTopologyBuilder} showAddPivot={showAddPivot} setShowAddPivot={setShowAddPivot} addPivotPrefilledHostId={addPivotPrefilledHostId} setAddPivotPrefilledHostId={setAddPivotPrefilledHostId} activeNetId={activeNetId} setActiveNetId={setActiveNetId} editingName={editingName} setEditingName={setEditingName} nameVal={nameVal} setNameVal={setNameVal} smartBuilding={smartBuilding} accessOverlay={accessOverlay} setAccessOverlay={setAccessOverlay} overlayMode={overlayMode} setOverlayMode={setOverlayMode} activeNet={activeNet} overlayData={overlayData} pivots={pivots} handleSmartBuild={handleSmartBuild} handleCollectPivots={handleCollectPivots} handleDeletePivot={handleDeletePivot} handleUpdatePivot={handleUpdatePivot} handleAddPivotForHost={handleAddPivotForHost} handlePivotCreated={handlePivotCreated} startRename={startRename} commitRename={commitRename} />;
}

NetworkView.propTypes = {
  projectId: PropTypes.any,
  accent: PropTypes.string,
  accentGreen: PropTypes.string,
  networks: PropTypes.array,
  onCreateNetwork: PropTypes.func,
  onUpdateNetwork: PropTypes.func,
  onDeleteNetwork: PropTypes.func,
  onCreateHost: PropTypes.func,
  onUpdateHost: PropTypes.func,
  onSyncHostByIp: PropTypes.func,
  hosts: PropTypes.array,
  onAddActivity: PropTypes.func,
  onUpdateActivity: PropTypes.func,
  onDeleteActivity: PropTypes.func,
  onRefreshHosts: PropTypes.func,
  onRefreshNetworks: PropTypes.func,
  markLocalOp: PropTypes.func,
  animateLinks: PropTypes.bool,
  findings: PropTypes.array,
  objectives: PropTypes.array,
  creds: PropTypes.array,
  attackSteps: PropTypes.array,
};
