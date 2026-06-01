import { useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../../components/Icon.jsx';

export default function AddFromProjectPanel({ hosts, accent, onAdd, onClose }) {
  const [sel, setSel] = useState(new Set());
  const [searchQuery, setSearchQuery] = useState('');

  const toggle = (ip) => setSel(prev => {
    const next = new Set(prev);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    return next;
  });

  const filteredHosts = searchQuery.trim()
    ? hosts.filter(h => (h.ip?.toLowerCase().includes(searchQuery.toLowerCase())) || (h.hostname?.toLowerCase().includes(searchQuery.toLowerCase())))
    : hosts;

  const selectAll = () => setSel(new Set(filteredHosts.map(h => h.ip)));

  return (
    <div style={{ background: '#0c0e13', borderBottom: '1px solid #2a2d35', flexShrink: 0, maxHeight: 280, display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '8px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', flex: 1 }}>Add hosts from project</span>
        <button onClick={selectAll} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>All{searchQuery && ` (${filteredHosts.length})`}</button>
        <button onClick={() => sel.size > 0 && onAdd(sel)} style={{ background: sel.size ? accent : '#1a1c22', border: 'none', borderRadius: 3, padding: '3px 12px', cursor: sel.size ? 'pointer' : 'default', color: '#fff', fontSize: 9, fontWeight: 600, fontFamily: 'JetBrains Mono', opacity: sel.size ? 1 : 0.4 }}>Add {sel.size ? `(${sel.size})` : ''}</button>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button>
      </div>
      <div style={{ padding: '6px 14px', borderBottom: '1px solid #1e2029' }}>
        <input type="text" placeholder="Search by IP or hostname..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} style={{ width: '100%', background: '#12141a', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 10px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono', outline: 'none' }} />
      </div>
      <div style={{ overflowY: 'auto', flex: 1 }}>
        {filteredHosts.length === 0 ? (
          <div style={{ padding: '20px', textAlign: 'center', color: '#404550', fontSize: 10 }}>No results</div>
        ) : (
          filteredHosts.map(h => <button type="button" key={h.ip} onClick={() => toggle(h.ip)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 14px', cursor: 'pointer', background: sel.has(h.ip) ? `${accent}10` : 'transparent', borderLeft: sel.has(h.ip) ? `2px solid ${accent}` : '2px solid transparent', width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', borderBottom: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}><div style={{ width: 12, height: 12, borderRadius: 2, border: `1px solid ${sel.has(h.ip) ? accent : '#404550'}`, background: sel.has(h.ip) ? accent : 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{sel.has(h.ip) && <Icon name="check" size={9} color="#fff" />}</div><span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#9098a8', width: 120 }}>{h.ip}</span><span style={{ fontSize: 10, color: '#c8cdd6', width: 110, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.hostname || '-'}</span></button>)
        )}
      </div>
    </div>
  );
}

AddFromProjectPanel.propTypes = {
  hosts: PropTypes.array,
  accent: PropTypes.string,
  onAdd: PropTypes.func,
  onClose: PropTypes.func,
};