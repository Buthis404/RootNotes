import { useState, useRef } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import Icon from './Icon.jsx';

const CONF_COLOR = (c) => {
  if (c >= 0.85) return '#39d353';
  if (c >= 0.65) return '#f09a3a';
  return '#cc2233';
};

function ConfBadge({ value }) {
  const pct = Math.round(value * 100);
  return (
    <span style={{ fontSize: 9, fontFamily: 'JetBrains Mono', color: CONF_COLOR(value),
      background: `${CONF_COLOR(value)}18`, border: `1px solid ${CONF_COLOR(value)}44`,
      borderRadius: 3, padding: '1px 5px', flexShrink: 0 }}>
      {pct}%
    </span>
  );
}

function ItemRow({ checked, onToggle, children }) {
  return (
    <button type="button" onClick={onToggle}
      style={{ display: 'flex', alignItems: 'flex-start', gap: 8, background: '#0a0c10',
        border: `1px solid ${checked ? '#2a2d35' : '#1a1c22'}`, borderRadius: 4,
        padding: '6px 10px', marginBottom: 4, cursor: 'pointer',
        opacity: checked ? 1 : 0.45, userSelect: 'none', width: '100%', textAlign: 'left' }}>
      <span style={{ fontSize: 10, color: checked ? '#39d353' : '#353840', flexShrink: 0, marginTop: 1 }}>
        {checked ? '☑' : '☐'}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>{children}</div>
    </button>
  );
}

function SectionHeader({ color, label, count, allChecked, onToggleAll }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
      <span style={{ fontSize: 10, color, fontWeight: 600, flex: 1 }}>{label} ({count})</span>
      <button onClick={onToggleAll}
        style={{ background: 'transparent', border: 'none', cursor: 'pointer',
          color: '#505560', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '2px 6px' }}>
        {allChecked ? 'deselect all' : 'select all'}
      </button>
    </div>
  );
}

export default function TopologyBuilderModal({ projectId, accent, onClose, onApplied }) {
  const [step, setStep] = useState('select');
  const [sourceType, setSourceType] = useState('nmap');
  const [file, setFile] = useState(null);
  const [keepManual, setKeepManual] = useState(true);
  const [createLinks, setCreateLinks] = useState(true);
  const [updateExisting, setUpdateExisting] = useState(true);
  const [confidenceThreshold, setConfidenceThreshold] = useState(0.5);
  const [preview, setPreview] = useState(null);
  const [selectedNewHosts, setSelectedNewHosts] = useState(new Set());
  const [selectedUpdatedHosts, setSelectedUpdatedHosts] = useState(new Set());
  const [selectedLinks, setSelectedLinks] = useState(new Set());
  const [error, setError] = useState('');
  const [applying, setApplying] = useState(false);
  const fileRef = useRef();

  const handleFileChange = (e) => { setFile(e.target.files?.[0] || null); setError(''); };

  const handlePreview = async () => {
    if (!file) { setError('Select a scan file first'); return; }
    setError('');
    setStep('preview');
    try {
      const form = new FormData();
      form.append('file', file);
      form.append('source_type', sourceType);
      form.append('keep_manual_positions', keepManual ? 'true' : 'false');
      form.append('create_links', createLinks ? 'true' : 'false');
      form.append('update_existing_hosts', updateExisting ? 'true' : 'false');
      form.append('confidence_threshold', String(confidenceThreshold));
      const result = await api.topologyPreview(projectId, form);
      setPreview(result);
      setSelectedNewHosts(new Set(result.new_hosts.map(h => h.ip)));
      setSelectedUpdatedHosts(new Set(result.updated_hosts.map(h => h.ip)));
      setSelectedLinks(new Set(result.new_links.map((_, i) => i)));
    } catch (e) {
      setError(e.message);
      setStep('select');
    }
  };

  const handleApply = async () => {
    if (!preview) return;
    setApplying(true);
    setError('');
    try {
      const filteredPreview = {
        ...preview,
        new_hosts: preview.new_hosts.filter(h => selectedNewHosts.has(h.ip)),
        updated_hosts: preview.updated_hosts.filter(h => selectedUpdatedHosts.has(h.ip)),
        new_links: preview.new_links.filter((_, i) => selectedLinks.has(i)),
      };
      await api.topologyApply(projectId, {
        preview: filteredPreview,
        options: {
          keep_manual_positions: keepManual,
          create_missing_networks: true,
          create_links: createLinks,
          update_existing_hosts: updateExisting,
          confidence_threshold: confidenceThreshold,
          source_type: sourceType,
        },
      });
      setStep('done');
      setTimeout(() => onApplied?.(), 800);
    } catch (e) {
      setError(e.message);
    } finally {
      setApplying(false);
    }
  };

  const handleRebuildLayout = async () => {
    try {
      await api.topologyRebuildLayout(projectId, { keep_manual_positions: keepManual });
      onApplied?.();
    } catch (e) {
      setError(e.message);
    }
  };

  const toggleSet = (set, setter, key) => {
    setter(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const inputStyle = { background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none', width: '100%' };
  const btnStyle = (color) => ({ background: color, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 });
  const ghostBtn = { background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' };
  const checkRow = { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, cursor: 'pointer', fontSize: 11, color: '#808590' };

  const selectedCount = (preview
    ? selectedNewHosts.size + selectedUpdatedHosts.size
    : 0);

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 500, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <button type="button" aria-label="Close topology builder" onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
      <div style={{ background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 10, width: 600, maxHeight: '85vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 64px #00000099' }}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid #1e2029' }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Topology Builder</div>
            <div style={{ fontSize: 10, color: '#505560', marginTop: 2 }}>Build network topology from scan data</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#505560' }}><Icon name="close" size={14} color="currentColor" /></button>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>

          {/* Step: Select */}
          {step === 'select' && (
            <div>
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Source Type</div>
                <select value={sourceType} onChange={e => setSourceType(e.target.value)} style={{ ...inputStyle, width: 'auto' }}>
                  <option value="nmap">Nmap XML (-oX)</option>
                </select>
              </div>

              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Scan File</div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input ref={fileRef} type="file" accept=".xml" onChange={handleFileChange} style={{ display: 'none' }} />
                  <button onClick={() => fileRef.current?.click()} style={{ ...ghostBtn }}>
                    {file ? file.name : 'Choose file…'}
                  </button>
                  {file && <span style={{ fontSize: 10, color: '#39d353' }}>✓ {(file.size / 1024).toFixed(1)} KB</span>}
                </div>
              </div>

              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.1em' }}>Options</div>
                {[
                  [keepManual, setKeepManual, 'Keep manual node positions'],
                  [createLinks, setCreateLinks, 'Auto-create subnet links'],
                  [updateExisting, setUpdateExisting, 'Update existing hosts with new data'],
                ].map(([val, setter, label]) => (
                  <label key={label} style={checkRow}>
                    <input type="checkbox" checked={val} onChange={e => setter(e.target.checked)} style={{ accentColor: accent }} />
                    {label}
                  </label>
                ))}

                {createLinks && (
                  <div style={{ marginTop: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: '#606570' }}>Min confidence</span>
                      <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: CONF_COLOR(confidenceThreshold) }}>
                        {Math.round(confidenceThreshold * 100)}%
                      </span>
                    </div>
                    <input type="range" min="0" max="1" step="0.05" value={confidenceThreshold}
                      onChange={e => setConfidenceThreshold(Number.parseFloat(e.target.value))}
                      style={{ width: '100%', accentColor: accent }} />
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>
                      <span>0% (all)</span><span>50%</span><span>100% (certain only)</span>
                    </div>
                  </div>
                )}
              </div>

              {error && <div style={{ color: '#cc2233', fontSize: 11, marginBottom: 12 }}>{error}</div>}

              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={handlePreview} disabled={!file} style={{ ...btnStyle(accent), opacity: file ? 1 : 0.5 }}>
                  <Icon name="target" size={12} color="#fff" /> Preview Changes
                </button>
                <button onClick={handleRebuildLayout} style={ghostBtn} title="Recompute positions for all nodes">
                  Rebuild Layout
                </button>
                <button onClick={onClose} style={ghostBtn}>Cancel</button>
              </div>
            </div>
          )}

          {/* Step: Preview */}
          {step === 'preview' && preview && (
            <div>
              <div style={{ background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '10px 14px', marginBottom: 16, fontSize: 11, color: '#808590' }}>
                {preview.summary}
                {selectedCount > 0 && (
                  <span style={{ marginLeft: 12, color: accent }}>
                    → {selectedNewHosts.size} new + {selectedUpdatedHosts.size} updated selected
                  </span>
                )}
              </div>

              {/* New hosts */}
              {preview.new_hosts.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <SectionHeader color="#39d353" label="New hosts" count={preview.new_hosts.length}
                    allChecked={selectedNewHosts.size === preview.new_hosts.length}
                    onToggleAll={() => setSelectedNewHosts(
                      selectedNewHosts.size === preview.new_hosts.length
                        ? new Set()
                        : new Set(preview.new_hosts.map(h => h.ip))
                    )} />
                  {preview.new_hosts.map((h) => (
                    <ItemRow key={h.ip} checked={selectedNewHosts.has(h.ip)}
                      onToggle={() => toggleSet(selectedNewHosts, setSelectedNewHosts, h.ip)}>
                      <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#c8cdd6' }}>
                        <span style={{ color: '#39d353' }}>{h.ip}</span>
                        {h.hostname && <span style={{ color: '#505560' }}> · {h.hostname}</span>}
                        {h.os && h.os !== 'Unknown' && <span style={{ color: '#404550' }}> · {h.os}</span>}
                        {h.ports.length > 0 && <span style={{ color: '#404550' }}> · {h.ports.length} ports</span>}
                      </div>
                    </ItemRow>
                  ))}
                </div>
              )}

              {/* Updated hosts */}
              {preview.updated_hosts.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <SectionHeader color="#f09a3a" label="Updated hosts" count={preview.updated_hosts.length}
                    allChecked={selectedUpdatedHosts.size === preview.updated_hosts.length}
                    onToggleAll={() => setSelectedUpdatedHosts(
                      selectedUpdatedHosts.size === preview.updated_hosts.length
                        ? new Set()
                        : new Set(preview.updated_hosts.map(h => h.ip))
                    )} />
                  {preview.updated_hosts.map((h) => (
                    <ItemRow key={h.ip} checked={selectedUpdatedHosts.has(h.ip)}
                      onToggle={() => toggleSet(selectedUpdatedHosts, setSelectedUpdatedHosts, h.ip)}>
                      <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#c8cdd6' }}>
                        <span style={{ color: '#f09a3a' }}>{h.ip}</span>
                        {Object.keys(h.changes).map(k => (
                          <span key={k} style={{ color: '#606570', marginLeft: 8 }}>+{k}</span>
                        ))}
                      </div>
                    </ItemRow>
                  ))}
                </div>
              )}

              {/* Links */}
              {preview.new_links.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <SectionHeader color="#5b8af5" label="Inferred links" count={preview.new_links.length}
                    allChecked={selectedLinks.size === preview.new_links.length}
                    onToggleAll={() => setSelectedLinks(
                      selectedLinks.size === preview.new_links.length
                        ? new Set()
                        : new Set(preview.new_links.map((_, i) => i))
                    )} />
                  {preview.new_links.map((l, i) => (
                    <ItemRow key={`${l.source_ip}-${l.target_ip}`} checked={selectedLinks.has(i)}
                      onToggle={() => toggleSet(selectedLinks, setSelectedLinks, i)}>
                      <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: l.reason ? 3 : 0 }}>
                          <span style={{ color: '#c8cdd6' }}>{l.source_ip}</span>
                          <span style={{ color: '#404550' }}>↔</span>
                          <span style={{ color: '#c8cdd6' }}>{l.target_ip}</span>
                          <span style={{ color: '#354060', background: '#1a1e2a', border: '1px solid #2a2d40', borderRadius: 3, padding: '1px 5px', fontSize: 9 }}>{l.link_type}</span>
                          <ConfBadge value={l.confidence} />
                        </div>
                        {l.reason && (
                          <div style={{ color: '#404550', fontSize: 9, paddingLeft: 2 }}>
                            {l.reason}
                          </div>
                        )}
                      </div>
                    </ItemRow>
                  ))}
                </div>
              )}

              {preview.new_hosts.length === 0 && preview.updated_hosts.length === 0 && (
                <div style={{ color: '#505560', fontSize: 11, marginBottom: 16 }}>No changes detected.</div>
              )}

              {error && <div style={{ color: '#cc2233', fontSize: 11, marginBottom: 12 }}>{error}</div>}

              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={handleApply}
                  disabled={applying || selectedCount === 0}
                  style={{ ...btnStyle('#39d353'), opacity: (applying || selectedCount === 0) ? 0.5 : 1 }}>
                  {applying ? 'Applying…' : `✓ Apply selected (${selectedCount} hosts, ${selectedLinks.size} links)`}
                </button>
                <button onClick={() => setStep('select')} style={ghostBtn}>← Back</button>
                <button onClick={onClose} style={ghostBtn}>Cancel</button>
              </div>
            </div>
          )}

          {/* Step: Done */}
          {step === 'done' && (
            <div style={{ textAlign: 'center', padding: '20px 0', color: '#39d353', fontSize: 14 }}>
              ✓ Topology applied successfully
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

ConfBadge.propTypes = {
  value: PropTypes.number,
};

ItemRow.propTypes = {
  checked: PropTypes.bool,
  onToggle: PropTypes.func,
  children: PropTypes.node,
};

SectionHeader.propTypes = {
  color: PropTypes.string,
  label: PropTypes.string,
  count: PropTypes.number,
  allChecked: PropTypes.bool,
  onToggleAll: PropTypes.func,
};

TopologyBuilderModal.propTypes = {
  projectId: PropTypes.any,
  accent: PropTypes.string,
  onClose: PropTypes.func,
  onApplied: PropTypes.func,
};
