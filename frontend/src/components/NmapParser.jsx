import { useState } from 'react';
import Icon from './Icon.jsx';
import { PORT_SERVICES } from '../constants.js';

// Извлечь домен из FQDN hostname: dc01.acme.local -> acme.local
function domainFromHostname(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  if (parts.length >= 3) return parts.slice(1).join('.');
  if (parts.length === 2) return hostname; // уже домен типа acme.local
  return '';
}

// ── Nmap XML ─────────────────────────────────────────────────────────
function parseNmapXML(text) {
  try {
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    const hosts = [];
    for (const hostEl of doc.querySelectorAll('host')) {
      if (hostEl.querySelector('status')?.getAttribute('state') !== 'up') continue;
      const ip = hostEl.querySelector('address[addrtype="ipv4"]')?.getAttribute('addr') || '';
      if (!ip) continue;
      const hostname = hostEl.querySelector('hostname')?.getAttribute('name') || '';
      const osEl = hostEl.querySelector('osmatch');
      let os = osEl?.getAttribute('name') || '';
      if (os.toLowerCase().includes('windows')) os = 'Windows';
      else if (os.toLowerCase().includes('linux')) os = 'Linux';

      // Домен из скриптов
      let domain = '';
      for (const scriptEl of hostEl.querySelectorAll('script')) {
        const sid = scriptEl.getAttribute('id') || '';
        if (sid === 'smb-os-discovery' || sid === 'smb2-security-mode' || sid === 'nbstat') {
          const out = scriptEl.getAttribute('output') || '';
          const dm = out.match(/Domain:\s*([^\s,]+)/i) || out.match(/domain:\s*([^\s,]+)/i);
          if (dm && dm[1] !== 'WORKGROUP') { domain = dm[1].replace(/\\\x00?/g, ''); break; }
          // smb-os-discovery element
          const domEl = scriptEl.querySelector('elem[key="domain"]') || scriptEl.querySelector('elem[key="Forest name"]');
          if (domEl && domEl.textContent && domEl.textContent !== 'WORKGROUP') { domain = domEl.textContent; break; }
        }
      }
      if (!domain) domain = domainFromHostname(hostname);

      const ports = [], services = [];
      for (const portEl of hostEl.querySelectorAll('port')) {
        if (portEl.querySelector('state')?.getAttribute('state') !== 'open') continue;
        const pid = portEl.getAttribute('portid');
        const svc = portEl.querySelector('service');
        const name = svc?.getAttribute('name') || svc?.getAttribute('product') || PORT_SERVICES[parseInt(pid)] || '';
        ports.push(pid);
        services.push(name);
      }
      hosts.push({ ip, hostname, os: os || 'Unknown', ports, services, status: 'scanned', domain });
    }
    return hosts;
  } catch { return []; }
}

// ── Nmap Grepable (-oG) ───────────────────────────────────────────────
function parseNmapGrepable(text) {
  const hosts = [];
  for (const line of text.split('\n')) {
    if (line.startsWith('#') || !line.trim()) continue;
    const m = line.match(/Host:\s+(\S+)\s+\(([^)]*)\)/);
    if (!m) continue;
    const ip = m[1], hostname = m[2] || '';
    const ports = [], services = [];
    const pm = line.match(/Ports:\s+(.+?)(?:\t|$)/);
    if (pm) {
      for (const p of pm[1].split(',')) {
        const parts = p.trim().split('/');
        if (parts[1] === 'open') {
          ports.push(parts[0]);
          services.push(parts[4] || PORT_SERVICES[parseInt(parts[0])] || '');
        }
      }
    }
    hosts.push({ ip, hostname, os: 'Unknown', ports, services, status: 'scanned', domain: domainFromHostname(hostname) });
  }
  return hosts;
}

// ── Nmap Text (-oN) ───────────────────────────────────────────────────
function parseNmapText(text) {
  const hosts = [];
  let cur = null;
  for (const line of text.split('\n')) {
    const rep = line.match(/Nmap scan report for (.+)/);
    if (rep) {
      if (cur) hosts.push(cur);
      const target = rep[1].trim();
      const ipM = target.match(/\((\d+\.\d+\.\d+\.\d+)\)/);
      const ip = ipM ? ipM[1] : target;
      const hostname = ipM ? target.replace(/ \(.*\)/, '').trim() : '';
      cur = { ip, hostname, os: 'Unknown', ports: [], services: [], status: 'scanned', domain: domainFromHostname(hostname) };
    }
    if (cur) {
      const pm = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)/);
      if (pm) {
        cur.ports.push(pm[1]);
        cur.services.push(pm[3] !== 'unknown' ? pm[3] : (PORT_SERVICES[parseInt(pm[1])] || pm[3]));
      }
      const osM = line.match(/OS details:\s+(.+)/);
      if (osM) {
        const raw = osM[1].split(',')[0].trim();
        cur.os = raw.toLowerCase().includes('windows') ? 'Windows' : raw.toLowerCase().includes('linux') ? 'Linux' : raw;
      }
      // smb-os-discovery в тексте
      const domM = line.match(/Domain:\s*([^\s\\,]+)/i);
      if (domM && domM[1] !== 'WORKGROUP' && !cur.domain) cur.domain = domM[1];
      // FQDN из nbstat
      const fqdnM = line.match(/FQDN:\s*(\S+)/i);
      if (fqdnM && !cur.domain) cur.domain = domainFromHostname(fqdnM[1]);
    }
  }
  if (cur) hosts.push(cur);
  return hosts;
}

// ── NetExec / CrackMapExec ────────────────────────────────────────────
// SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 x64 (name:DC01) (domain:acme.local) (signing:True) (SMBv1:False)
function parseNetExec(text) {
  const hosts = [];
  const seen = new Set();
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*(SMB|LDAP|WINRM|SSH|RDP|MSSQL|FTP)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+\[\*\]\s*(.*)/i);
    if (!m) continue;
    const proto = m[1].toUpperCase();
    const ip = m[2];
    const port = m[3];
    const netbios = m[4];
    const rest = m[5];
    if (seen.has(ip + ':' + port)) continue;
    seen.add(ip + ':' + port);

    // Парсим метаданные из скобок
    const nameM = rest.match(/name:([^)]+)/i);
    const domainM = rest.match(/domain:([^)]+)/i);
    const osM = rest.match(/^([^(]+)/);

    const hostname = nameM ? nameM[1].trim() : netbios;
    const domain = domainM ? domainM[1].trim() : '';
    const osRaw = osM ? osM[1].trim() : '';
    const os = osRaw.toLowerCase().includes('windows') ? 'Windows' : osRaw.toLowerCase().includes('linux') ? 'Linux' : (osRaw || 'Unknown');

    const portName = PORT_SERVICES[parseInt(port)] || proto.toLowerCase();
    const existing = hosts.find(h => h.ip === ip);
    if (existing) {
      if (!existing.ports.includes(port)) { existing.ports.push(port); existing.services.push(portName); }
      if (!existing.domain && domain) existing.domain = domain;
    } else {
      hosts.push({ ip, hostname, os, ports: [port], services: [portName], status: 'scanned', domain });
    }
  }
  return hosts;
}

// ── Advanced Port Scanner XML ─────────────────────────────────────────
// <report><hosts><host name="DC01" ip="10.10.10.5"><ports><port protocol="TCP" number="445" status="Open" description="Microsoft-DS"/></ports></host></hosts></report>
function parseAdvancedPortScanner(text) {
  try {
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    const hosts = [];
    for (const hostEl of doc.querySelectorAll('host')) {
      const ip = hostEl.getAttribute('ip') || '';
      if (!ip) continue;
      const hostname = hostEl.getAttribute('name') || '';
      const ports = [], services = [];
      for (const portEl of hostEl.querySelectorAll('port')) {
        if ((portEl.getAttribute('status') || '').toLowerCase() !== 'open') continue;
        const num = portEl.getAttribute('number') || '';
        const desc = portEl.getAttribute('description') || PORT_SERVICES[parseInt(num)] || '';
        ports.push(num);
        services.push(desc);
      }
      hosts.push({ ip, hostname, os: 'Unknown', ports, services, status: 'scanned', domain: domainFromHostname(hostname) });
    }
    return hosts;
  } catch { return []; }
}

// ── Авто-определение формата ─────────────────────────────────────────
function detectFormat(text) {
  const t = text.trim();
  if (t.startsWith('<?xml') || t.startsWith('<nmaprun')) return 'nmap-xml';
  if (t.startsWith('<?xml') && t.includes('<report>') && t.includes('<host ') && t.includes('number=')) return 'aps';
  if (t.includes('<report>') && t.includes('<host ') && t.includes('number=')) return 'aps';
  if (t.includes('Host:') && t.includes('Ports:')) return 'nmap-grep';
  // NetExec: строка начинается с протокола + IP
  if (/^\s*(SMB|LDAP|WINRM|SSH|RDP|MSSQL|FTP)\s+\d+\.\d+/im.test(t)) return 'netexec';
  return 'nmap-text';
}

function FORMAT_LABEL(f) {
  return { 'nmap-xml': 'Nmap XML', 'nmap-grep': 'Nmap -oG', 'nmap-text': 'Nmap -oN', 'netexec': 'NetExec/CME', 'aps': 'Advanced Port Scanner' }[f] || f;
}

function parseScan(text) {
  const fmt = detectFormat(text);
  switch (fmt) {
    case 'nmap-xml':   return { hosts: parseNmapXML(text), fmt };
    case 'nmap-grep':  return { hosts: parseNmapGrepable(text), fmt };
    case 'netexec':    return { hosts: parseNetExec(text), fmt };
    case 'aps':        return { hosts: parseAdvancedPortScanner(text), fmt };
    default:           return { hosts: parseNmapText(text), fmt };
  }
}

export default function NmapParser({ pid, onImport, onClose, accent }) {
  const [raw, setRaw] = useState('');
  const [parsed, setParsed] = useState(null);
  const [fmt, setFmt] = useState('');
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState(null);

  const doParse = () => {
    const { hosts, fmt: f } = parseScan(raw);
    setParsed(hosts);
    setFmt(f);
    setResult(null);
  };

  const doImport = async () => {
    if (!parsed?.length) return;
    setImporting(true);
    try {
      const res = await onImport(parsed);
      setResult(res);
    } catch (e) {
      setResult({ error: e.message });
    }
    setImporting(false);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, width: 760, maxHeight: '85vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 64px #00000099' }}>
        {/* Header */}
        <div style={{ padding: '18px 24px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <Icon name="terminal" size={16} color={accent} />
          <span style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', flex: 1 }}>Scan Parser</span>
          <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>Nmap · NetExec · Advanced Port Scanner</span>
          {fmt && <span style={{ fontSize: 9, color: accent, background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 3, padding: '2px 7px', fontFamily: 'JetBrains Mono' }}>{FORMAT_LABEL(fmt)}</span>}
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '18px 24px' }}>
          {!parsed ? (
            <>
              <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>
                Paste scanner output — format is detected automatically
              </div>
              <textarea value={raw} onChange={e => setRaw(e.target.value)}
                placeholder={`# Nmap XML / Grepable / Text\nnmap -sV -sC -T4 192.168.1.0/24 -oX out.xml\n\n# NetExec / CrackMapExec\nnxc smb 10.10.10.0/24\n\n# Advanced Port Scanner\nFile → Save as XML`}
                style={{ width: '100%', height: 280, background: '#07080b', border: '1px solid #2a2d35', borderRadius: 6, padding: '14px 16px', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', lineHeight: 1.6, resize: 'vertical', outline: 'none' }} />
            </>
          ) : (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                <span style={{ fontSize: 12, color: parsed.length > 0 ? '#39d353' : '#cc2233', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                  {parsed.length > 0 ? `Hosts found: ${parsed.length}` : 'No hosts found'}
                </span>
                <button onClick={() => { setParsed(null); setResult(null); setFmt(''); }}
                  style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                  Edit
                </button>
              </div>
              {result && (
                <div style={{ padding: '10px 14px', background: result.error ? '#cc223318' : '#39d35318', border: `1px solid ${result.error ? '#cc2233' : '#39d353'}44`, borderRadius: 6, marginBottom: 14, fontSize: 12, color: result.error ? '#cc2233' : '#39d353', fontFamily: 'JetBrains Mono' }}>
                  {result.error ? `Error: ${result.error}` : `Imported: ${result.hosts_added} new hosts`}
                </div>
              )}
              <div style={{ maxHeight: 340, overflowY: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                  <thead>
                    <tr style={{ background: '#0d0f14' }}>
                      {['IP', 'Hostname', 'OS', 'Domain', 'Ports'].map(h => (
                        <th key={h} style={{ padding: '6px 10px', textAlign: 'left', color: '#505560', fontFamily: 'JetBrains Mono', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid #1e2029' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {parsed.map((h, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #14161b' }}
                        onMouseEnter={e => e.currentTarget.style.background = '#ffffff04'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                        <td style={{ padding: '7px 10px', color: '#5b8af5', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{h.ip}</td>
                        <td style={{ padding: '7px 10px', color: '#9098a8', fontFamily: 'JetBrains Mono' }}>{h.hostname || '—'}</td>
                        <td style={{ padding: '7px 10px', color: '#9098a8' }}>{h.os}</td>
                        <td style={{ padding: '7px 10px' }}>
                          {h.domain
                            ? <span style={{ fontSize: 9, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af044', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{h.domain}</span>
                            : <span style={{ color: '#303540' }}>—</span>}
                        </td>
                        <td style={{ padding: '7px 10px' }}>
                          <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                            {h.ports.slice(0, 8).map((p, pi) => (
                              <span key={p} style={{ fontSize: 9, color: '#6fc8f0', background: '#6fc8f018', border: '1px solid #6fc8f033', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>
                                {p}{h.services[pi] ? `/${h.services[pi]}` : ''}
                              </span>
                            ))}
                            {h.ports.length > 8 && <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{h.ports.length - 8}</span>}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '14px 24px', borderTop: '1px solid #1e2029', display: 'flex', justifyContent: 'flex-end', gap: 8, flexShrink: 0 }}>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Close</button>
          {!parsed ? (
            <button onClick={doParse} disabled={!raw.trim()}
              style={{ background: raw.trim() ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: raw.trim() ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
              Parse
            </button>
          ) : (
            <button onClick={doImport} disabled={!parsed.length || importing || !!result}
              style={{ background: parsed.length && !result ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: (parsed.length && !result) ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
              {importing ? 'Importing...' : result ? 'Imported ✓' : `Import ${parsed.length} hosts`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
