import { useState } from 'react';
import PropTypes from 'prop-types';
import Icon from './Icon.jsx';
import { PORT_SERVICES } from '../constants.js';

function domainFromHostname(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  if (parts.length >= 3) return parts.slice(1).join('.');
  if (parts.length === 2) return hostname;
  return '';
}

function osFromString(raw) {
  const l = raw.toLowerCase();
  if (l.includes('windows')) return 'Windows';
  if (l.includes('linux')) return 'Linux';
  return raw;
}

function extractDomainFromScripts(hostEl) {
  for (const scriptEl of hostEl.querySelectorAll('script')) {
    const sid = scriptEl.getAttribute('id') || '';
    if (sid !== 'smb-os-discovery' && sid !== 'smb2-security-mode' && sid !== 'nbstat') continue;
    const out = scriptEl.getAttribute('output') || '';
    const dm = out.match(/Domain:\s*([^\s,]+)/i) || out.match(/domain:\s*([^\s,]+)/i);
    if (dm && dm[1] !== 'WORKGROUP') return dm[1].replaceAll('\\', '').replaceAll('\u0000', '');
    const domEl = scriptEl.querySelector('elem[key="domain"]') || scriptEl.querySelector('elem[key="Forest name"]');
    if (domEl?.textContent && domEl.textContent !== 'WORKGROUP') return domEl.textContent;
  }
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
      const osRaw = osEl?.getAttribute('name') || '';
      const os = osRaw ? osFromString(osRaw) : 'Unknown';

      let domain = extractDomainFromScripts(hostEl);
      if (!domain) domain = domainFromHostname(hostname);

      const ports = [], services = [];
      for (const portEl of hostEl.querySelectorAll('port')) {
        if (portEl.querySelector('state')?.getAttribute('state') !== 'open') continue;
        const pid = portEl.getAttribute('portid');
        const svc = portEl.querySelector('service');
        const name = svc?.getAttribute('name') || svc?.getAttribute('product') || PORT_SERVICES[Number.parseInt(pid)] || '';
        ports.push(pid);
        services.push(name);
      }
      hosts.push({ ip, hostname, os, ports, services, status: 'scanned', domain });
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
    const portsPart = line.split('Ports: ')[1]?.split('\t')[0] || '';
    if (portsPart) {
      for (const p of portsPart.split(',')) {
        const parts = p.trim().split('/');
        if (parts[1] === 'open') {
          ports.push(parts[0]);
          services.push(parts[4] || PORT_SERVICES[Number.parseInt(parts[0])] || '');
        }
      }
    }
    hosts.push({ ip, hostname, os: 'Unknown', ports, services, status: 'scanned', domain: domainFromHostname(hostname) });
  }
  return hosts;
}

function applyNmapTextLineParsing(line, cur) {
  const pm = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)/);
  if (pm) {
    cur.ports.push(pm[1]);
    cur.services.push(pm[3] === 'unknown' ? (PORT_SERVICES[Number.parseInt(pm[1])] || pm[3]) : pm[3]);
  }
  const osM = line.match(/OS details:\s+(.+)/);
  if (osM) {
    const raw = osM[1].split(',')[0].trim();
    cur.os = osFromString(raw) || raw;
  }
  const domM = line.match(/Domain:\s*([^\s\\,]+)/i);
  if (domM && domM[1] !== 'WORKGROUP' && !cur.domain) cur.domain = domM[1];
  const fqdnM = line.match(/FQDN:\s*(\S+)/i);
  if (fqdnM && !cur.domain) cur.domain = domainFromHostname(fqdnM[1]);
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
    if (cur) applyNmapTextLineParsing(line, cur);
  }
  if (cur) hosts.push(cur);
  return hosts;
}

function buildNetExecHostEntry(ip, hostname, domain, osRaw, port, portName) {
  const os = osRaw ? osFromString(osRaw) : 'Unknown';
  return { ip, hostname, os, ports: [port], services: [portName], status: 'scanned', domain };
}

function parseNetExecLineFields(m) {
  const proto = m[1].toUpperCase();
  const rest = m[5];
  const nameM = rest.match(/name:([^)]+)/i);
  const domainM = rest.match(/domain:([^)]+)/i);
  const osM = rest.match(/^([^(]+)/);
  return {
    proto,
    ip: m[2],
    port: m[3],
    hostname: nameM ? nameM[1].trim() : m[4],
    domain: domainM ? domainM[1].trim() : '',
    osRaw: osM ? osM[1].trim() : '',
  };
}

// ── NetExec / CrackMapExec ────────────────────────────────────────────
function parseNetExec(text) {
  const hosts = [];
  const seen = new Set();
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*(SMB|LDAP|WINRM|SSH|RDP|MSSQL|FTP)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+\[\*\]\s*(.*)/i);
    if (!m) continue;
    const { proto, ip, port, hostname, domain, osRaw } = parseNetExecLineFields(m);
    if (seen.has(ip + ':' + port)) continue;
    seen.add(ip + ':' + port);

    const portName = PORT_SERVICES[Number.parseInt(port)] || proto.toLowerCase();
    const existing = hosts.find(h => h.ip === ip);
    if (existing) {
      if (!existing.ports.includes(port)) { existing.ports.push(port); existing.services.push(portName); }
      if (!existing.domain && domain) existing.domain = domain;
    } else {
      hosts.push(buildNetExecHostEntry(ip, hostname, domain, osRaw, port, portName));
    }
  }
  return hosts;
}

// ── Advanced Port Scanner XML ─────────────────────────────────────────
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
        const desc = portEl.getAttribute('description') || PORT_SERVICES[Number.parseInt(num)] || '';
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
  if (t.split(/\r?\n/).some(line => /^(SMB|LDAP|WINRM|SSH|RDP|MSSQL|FTP)\s+\d+\./i.test(line.trim()))) return 'netexec';
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

function HostTableRow({ h }) {
  const [hovered, setHovered] = useState(false);
  return (
    <tr style={{ borderBottom: '1px solid #14161b', background: hovered ? '#ffffff04' : 'transparent' }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}>
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
  );
}
HostTableRow.propTypes = { h: PropTypes.any };

function ParsedView({ parsed, result, onEdit, onImport, importing, accent }) {
  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <span style={{ fontSize: 12, color: parsed.length > 0 ? '#39d353' : '#cc2233', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
          {parsed.length > 0 ? `Hosts found: ${parsed.length}` : 'No hosts found'}
        </span>
        <button onClick={onEdit}
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
            {parsed.map((h) => <HostTableRow key={h.ip} h={h} />)}
          </tbody>
        </table>
      </div>
    </>
  );
}
ParsedView.propTypes = { parsed: PropTypes.any, result: PropTypes.any, onEdit: PropTypes.any, onImport: PropTypes.any, importing: PropTypes.any, accent: PropTypes.any };

function ParserHeader({ fmt, accent, onClose }) {
  return (
    <div style={{ padding: '18px 24px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
      <Icon name="terminal" size={16} color={accent} />
      <span style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', flex: 1 }}>Scan Parser</span>
      <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>Nmap · NetExec · Advanced Port Scanner</span>
      {fmt && <span style={{ fontSize: 9, color: accent, background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 3, padding: '2px 7px', fontFamily: 'JetBrains Mono' }}>{FORMAT_LABEL(fmt)}</span>}
      <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
        <Icon name="close" size={14} color="#606570" />
      </button>
    </div>
  );
}
ParserHeader.propTypes = { fmt: PropTypes.any, accent: PropTypes.any, onClose: PropTypes.any };

function ParserFooter({ parsed, raw, importing, result, onClose, onParse, onImport, accent }) {
  const canParse = raw.trim();
  const canImport = parsed?.length && !result;
  const resultLabel = result ? 'Imported ✓' : `Import ${parsed?.length || 0} hosts`;
  const importLabel = importing ? 'Importing...' : resultLabel;
  return (
    <div style={{ padding: '14px 24px', borderTop: '1px solid #1e2029', display: 'flex', justifyContent: 'flex-end', gap: 8, flexShrink: 0 }}>
      <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Close</button>
      {parsed ? (
        <button onClick={onImport} disabled={!parsed.length || importing || !!result}
          style={{ background: canImport ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: canImport ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
          {importLabel}
        </button>
      ) : (
        <button onClick={onParse} disabled={!canParse}
          style={{ background: canParse ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: canParse ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
          Parse
        </button>
      )}
    </div>
  );
}
ParserFooter.propTypes = { parsed: PropTypes.any, raw: PropTypes.any, importing: PropTypes.any, result: PropTypes.any, onClose: PropTypes.any, onParse: PropTypes.any, onImport: PropTypes.any, accent: PropTypes.any };

function RawInputView({ raw, setRaw }) {
  return (
    <>
      <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>
        Paste scanner output — format is detected automatically
      </div>
      <textarea value={raw} onChange={e => setRaw(e.target.value)}
        placeholder={`# Nmap XML / Grepable / Text\nnmap -sV -sC -T4 192.168.1.0/24 -oX out.xml\n\n# NetExec / CrackMapExec\nnxc smb 10.10.10.0/24\n\n# Advanced Port Scanner\nFile → Save as XML`}
        style={{ width: '100%', height: 280, background: '#07080b', border: '1px solid #2a2d35', borderRadius: 6, padding: '14px 16px', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', lineHeight: 1.6, resize: 'vertical', outline: 'none' }} />
    </>
  );
}
RawInputView.propTypes = { raw: PropTypes.any, setRaw: PropTypes.any };

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

  const handleEdit = () => { setParsed(null); setResult(null); setFmt(''); };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, width: 760, maxHeight: '85vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 64px #00000099' }}>
        <ParserHeader fmt={fmt} accent={accent} onClose={onClose} />
        <div style={{ flex: 1, overflow: 'auto', padding: '18px 24px' }}>
          {parsed ? (
            <ParsedView parsed={parsed} result={result} onEdit={handleEdit} onImport={doImport} importing={importing} accent={accent} />
          ) : (
            <RawInputView raw={raw} setRaw={setRaw} />
          )}
        </div>
        <ParserFooter parsed={parsed} raw={raw} importing={importing} result={result} onClose={onClose} onParse={doParse} onImport={doImport} accent={accent} />
      </div>
    </div>
  );
}
NmapParser.propTypes = { pid: PropTypes.any, onImport: PropTypes.any, onClose: PropTypes.any, accent: PropTypes.any };
