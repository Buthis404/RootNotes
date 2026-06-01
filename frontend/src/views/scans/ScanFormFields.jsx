/**
 * Shared form primitives for scan panels (Nmap, Nuclei, CME, DonPAPI).
 */

import PropTypes from 'prop-types';

export const FieldRow = ({ label, children }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 12 }}>
    <label style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</label>
    {children}
  </div>
);
FieldRow.propTypes = { label: PropTypes.any, children: PropTypes.any };

export const Input = ({ value, onChange, placeholder, monospace, multiline, rows = 3 }) => {
  const base = {
    background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5,
    padding: '7px 10px', color: '#c8cdd6', fontSize: 12,
    fontFamily: monospace ? 'JetBrains Mono' : 'inherit',
    outline: 'none', width: '100%', boxSizing: 'border-box',
  };
  return multiline
    ? <textarea value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} rows={rows} style={{ ...base, resize: 'vertical' }} />
    : <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={base} />;
};
Input.propTypes = { value: PropTypes.any, onChange: PropTypes.any, placeholder: PropTypes.any, monospace: PropTypes.any, multiline: PropTypes.any, rows: PropTypes.any };

export const ResultBox = ({ result, error }) => {
  if (!result && !error) return null;
  if (error) return (
    <div style={{ background: '#1a0508', border: '1px solid #cc223344', borderRadius: 6, padding: 12, marginTop: 12, fontSize: 12, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>
      {error}
    </div>
  );
  return (
    <div style={{ background: '#0a1208', border: '1px solid #39d35344', borderRadius: 6, padding: 12, marginTop: 12, fontSize: 11, fontFamily: 'JetBrains Mono', color: '#c8cdd6', whiteSpace: 'pre-wrap', overflowX: 'auto', maxHeight: 300, overflowY: 'auto' }}>
      {typeof result === 'string' ? result : JSON.stringify(result, null, 2)}
    </div>
  );
};
ResultBox.propTypes = { result: PropTypes.any, error: PropTypes.any };

export function ExecutionSourceRow({ executionSource, setExecutionSource, pivotObservationId, setPivotObservationId, pivotOptions = [], loading = false }) {
  return (
    <>
      <FieldRow label="Execution source">
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {[
            { id: 'attacker', label: 'Attacker host', color: '#5b8af5' },
            { id: 'pivot_listener', label: 'Pivot listener', color: '#e8cc42' },
          ].map(opt => (
            <button key={opt.id} onClick={() => setExecutionSource(opt.id)}
              style={{ background: executionSource === opt.id ? `${opt.color}22` : '#1a1c22', border: `1px solid ${executionSource === opt.id ? opt.color : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: executionSource === opt.id ? opt.color : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {opt.label}
            </button>
          ))}
        </div>
      </FieldRow>
      {executionSource === 'pivot_listener' && (
        <FieldRow label="Pivot listener">
          <select value={pivotObservationId} onChange={e => setPivotObservationId(e.target.value)} style={{ background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, fontFamily: 'JetBrains Mono', outline: 'none', width: '100%', boxSizing: 'border-box' }}>
            <option value="">{loading ? 'Loading listeners...' : 'Select pivot listener...'}</option>
            {pivotOptions.map(item => (
              <option key={item.id} value={item.id}>{item.label}</option>
            ))}
          </select>
        </FieldRow>
      )}
    </>
  );
}
ExecutionSourceRow.propTypes = {
  executionSource: PropTypes.any,
  setExecutionSource: PropTypes.any,
  pivotObservationId: PropTypes.any,
  setPivotObservationId: PropTypes.any,
  pivotOptions: PropTypes.any,
  loading: PropTypes.any,
};

export function isSocksPivot(item) {
  if (!item.bind_address) return false;
  const pt = String(item.pivot_type || '').toLowerCase();
  return pt.includes('socks4') || pt.includes('socks5');
}
