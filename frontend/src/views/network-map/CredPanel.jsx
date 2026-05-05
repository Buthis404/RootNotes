import { useEffect, useState } from 'react';
import Icon from '../../components/Icon.jsx';
import { api } from '../../api.js';
import { ACCESS_ROLES } from './constants.js';

export default function CredPanel({ cred, host, accent, pid, linkType }) {
  const [open, setOpen] = useState(false);
  const [chn, setChn] = useState(null);
  const [notes, setNotes] = useState('');
  const [, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    api.getCredHostNotes({ cred_id: cred.id, host_id: host.id }).then(list => {
      const found = list[0] || null;
      setChn(found);
      setNotes(found?.notes || '');
    }).catch(() => {});
  }, [open, cred.id, host.id]);

  const saveNote = async (newNotes, newAccess) => {
    setSaving(true);
    try {
      const body = { cred_id: cred.id, host_id: host.id, pid, notes: newNotes, access: newAccess ?? chn?.access ?? [] };
      const result = chn
        ? await api.updateCredHostNote(chn.id, { notes: newNotes, access: newAccess ?? chn.access })
        : await api.upsertCredHostNote(body);
      setChn(result);
      setNotes(result.notes);
    } catch {}
    setSaving(false);
  };

  const toggleAccess = async (roleId) => {
    const current = chn?.access || [];
    const next = current.includes(roleId) ? current.filter(r => r !== roleId) : [...current, roleId];
    await saveNote(notes, next);
  };

  const linkColors = { ip: '#5b8af5', domain: '#c07af0', 'domain?': '#f09a3a', linked: '#39d353' };
  const linkLabels = { ip: 'IP', domain: 'domain', 'domain?': 'domain?', linked: 'linked' };
  const linkTitles = { ip: 'Linked by IP', domain: 'Domain credential (host is domain-joined)', 'domain?': 'Domain credential - set host domain to confirm', linked: 'Linked via host_ids' };

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, marginBottom: 6 }}>
      <div onClick={() => setOpen(v => !v)} style={{ padding: '6px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ fontSize: 11, color: '#e0e4ec', fontFamily: 'JetBrains Mono', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.username}</span>
            <div style={{ display: 'flex', gap: 3, flexShrink: 0, alignItems: 'center' }}>
              <span title={linkTitles[linkType]} style={{ fontSize: 8, color: linkColors[linkType], background: linkColors[linkType] + '22', border: `1px solid ${linkColors[linkType]}44`, borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>{linkLabels[linkType]}</span>
              {cred.is_domain && <span style={{ fontSize: 8, color: '#f09a3a', background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>AD</span>}
              {(chn?.access || []).slice(0, 2).map(r => {
                const role = ACCESS_ROLES.find(a => a.id === r);
                return role ? <span key={r} style={{ fontSize: 8, color: accent, background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>{role.label}</span> : null;
              })}
            </div>
          </div>
          <div style={{ fontSize: 9, color: '#606570', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.service || '-'} · {cred.type}{cred.cracked ? ' · cracked' : ''}</div>
        </div>
        <Icon name="chevron" size={10} color="#606570" style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform .12s', flexShrink: 0 }} />
      </div>
      {open && (
        <div style={{ padding: '8px', borderTop: '1px solid #1e2029' }}>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 4 }}>Secret</div>
          <div style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', wordBreak: 'break-all', marginBottom: 8 }}>{cred.secret || '(empty)'}</div>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 4 }}>Access on this host</div>
          <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginBottom: 8 }}>
            {ACCESS_ROLES.map(role => {
              const active = (chn?.access || []).includes(role.id);
              return (
                <button key={role.id} onClick={() => toggleAccess(role.id)} title={role.title} style={{ background: active ? accent + '22' : '#0e1016', border: `1px solid ${active ? accent + '66' : '#2a2d35'}`, borderRadius: 3, padding: '3px 7px', cursor: 'pointer', color: active ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
                  {role.label}
                </button>
              );
            })}
          </div>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 4 }}>Notes on this host</div>
          <textarea value={notes} onChange={e => setNotes(e.target.value)} onBlur={() => saveNote(notes)} placeholder="e.g. can't RDP, needs relay, password expired..." style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono', lineHeight: 1.5, resize: 'vertical', outline: 'none', minHeight: 54, boxSizing: 'border-box' }} />
          {cred.notes && <div style={{ fontSize: 9, color: '#606570', marginTop: 6, lineHeight: 1.5 }}>Cred notes: {cred.notes}</div>}
        </div>
      )}
    </div>
  );
}
