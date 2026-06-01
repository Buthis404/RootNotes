// ── Nmap XML parser ───────────────────────────────────────────────────

function detectOsFromName(osName) {
  if (/windows/i.test(osName)) return 'Windows';
  if (/linux/i.test(osName)) return 'Linux';
  if (/mac\s*os|darwin/i.test(osName)) return 'macOS';
  if (/freebsd|openbsd|netbsd/i.test(osName)) return 'Linux';
  return null;
}

function detectOsFromCpes(hostEl) {
  const cpes = Array.from(hostEl.querySelectorAll('cpe')).map(c => c.textContent).join(' ');
  if (/windows/i.test(cpes)) return 'Windows';
  if (/linux/i.test(cpes)) return 'Linux';
  return null;
}

function resolveHostOs(hostEl) {
  const osMatch = hostEl.querySelector('osmatch');
  const osClass = hostEl.querySelector('osclass');
  const osName = (osMatch?.getAttribute('name') || osClass?.getAttribute('osfamily') || '').toLowerCase();
  return detectOsFromName(osName) || detectOsFromCpes(hostEl) || 'Unknown';
}

function extractServiceTags(fullSvc, svcName) {
  const tags = [];
  if (/apache/i.test(fullSvc)) tags.push('apache');
  if (/nginx/i.test(fullSvc)) tags.push('nginx');
  if (/iis/i.test(fullSvc)) tags.push('iis');
  if (/openssh/i.test(fullSvc)) tags.push('ssh');
  if (/mysql/i.test(fullSvc)) tags.push('mysql');
  if (/postgresql|postgres/i.test(fullSvc)) tags.push('postgres');
  if (/mssql|microsoft sql/i.test(fullSvc)) tags.push('mssql');
  if (/smb|samba/i.test(fullSvc)) tags.push('smb');
  if (/rdp|ms-wbt/i.test(svcName)) tags.push('rdp');
  if (/ldap/i.test(svcName)) tags.push('ldap');
  if (/kerberos/i.test(svcName)) tags.push('kerberos');
  if (/tomcat/i.test(fullSvc)) tags.push('tomcat');
  return tags;
}

function processNmapPort(portEl, ports, services, tags) {
  const portState = portEl.querySelector('state')?.getAttribute('state');
  if (portState !== 'open') return;

  const portId = portEl.getAttribute('portid');
  ports.push(portId);

  const svcEl = portEl.querySelector('service');
  if (!svcEl) return;

  const svcName = svcEl.getAttribute('name') || '';
  const product = svcEl.getAttribute('product') || '';
  const version = svcEl.getAttribute('version') || '';
  if (svcName) services.push(svcName);
  if (product) tags.push(product.split(' ')[0].toLowerCase());

  const fullSvc = `${product} ${version}`.trim();
  for (const tag of extractServiceTags(fullSvc, svcName)) {
    tags.push(tag);
  }
}

export function parseNmapXml(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, 'application/xml');
  const parseError = doc.querySelector('parsererror');
  if (parseError) throw new Error('Invalid XML: ' + parseError.textContent.slice(0, 120));

  const hosts = [];
  doc.querySelectorAll('host').forEach(hostEl => {
    const state = hostEl.querySelector('status')?.getAttribute('state');
    if (state && state !== 'up') return;

    const ip = hostEl.querySelector('address[addrtype="ipv4"]')?.getAttribute('addr')
      || hostEl.querySelector('address[addrtype="ipv6"]')?.getAttribute('addr')
      || '';
    if (!ip) return;

    const hostname = hostEl.querySelector('hostname')?.getAttribute('name') || '';
    const os = resolveHostOs(hostEl);

    const ports = [];
    const services = [];
    const tags = [];

    hostEl.querySelectorAll('port').forEach(portEl => {
      processNmapPort(portEl, ports, services, tags);
    });

    const scriptNotes = [];
    hostEl.querySelectorAll('script').forEach(s => {
      const id = s.getAttribute('id') || '';
      const output = s.getAttribute('output') || '';
      if (output && id) scriptNotes.push(`[${id}] ${output.slice(0, 200)}`);
    });

    const status = ports.length > 0 ? 'scanned' : 'alive';

    hosts.push({
      ip,
      hostname,
      os,
      status,
      ports: [...new Set(ports)],
      services: [...new Set(services)],
      tags: [...new Set(tags)],
      notes: scriptNotes.slice(0, 3).join('\n').slice(0, 500),
    });
  });

  return { hosts, creds: [] };
}


// ── Advanced Port Scanner HTML parser ────────────────────────────────

function detectApsTableColumns(rows) {
  let ipIdx = -1, hostIdx = -1, portIdx = -1, statusIdx = -1, startRow = 0;
  for (let j = 0; j < Math.min(rows.length, 5); j++) {
    const contents = Array.from(rows[j].querySelectorAll('th,td')).map(c => c.textContent.trim().toLowerCase());
    ipIdx = contents.findIndex(h => h.includes('ip') || h.includes('адрес') || h.includes('address'));
    hostIdx = contents.findIndex(h => h.includes('host') || h.includes('имя') || h.includes('name'));
    portIdx = contents.findIndex(h => h.includes('port') || h.includes('порт'));
    statusIdx = contents.findIndex(h => h.includes('status') || h.includes('статус') || h.includes('state'));
    if (ipIdx !== -1 || hostIdx !== -1) {
      startRow = j + 1;
      break;
    }
  }
  return { ipIdx, hostIdx, portIdx, statusIdx, startRow };
}

function extractIpFromRaw(ipRaw) {
  if (!ipRaw) return '';
  const m = ipRaw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/) || ipRaw.match(/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/);
  return m ? m[0] : '';
}

function isDeadStatus(statusRaw) {
  if (!statusRaw) return false;
  return statusRaw.includes('dead') || statusRaw.includes('offline') || statusRaw.includes('не в сети') || statusRaw === 'выключен' || statusRaw === 'отключен';
}

function extractPortsFromText(portRaw) {
  return portRaw.split(/[\s,;|]+/).map(p => p.replace(/[/()\s].*/, '').trim()).filter(p => /^\d+$/.test(p));
}

function extractApsServiceTags(fullText, currentHost) {
  if (fullText.includes('apache')) currentHost.tags.push('apache');
  if (fullText.includes('nginx')) currentHost.tags.push('nginx');
  if (fullText.includes('iis')) currentHost.tags.push('iis');
  if (fullText.includes('mysql')) currentHost.tags.push('mysql');
  if (fullText.includes('postgresql') || fullText.includes('postgres')) currentHost.tags.push('postgres');
  if (fullText.includes('mssql') || fullText.includes('microsoft sql')) currentHost.tags.push('mssql');
  if (fullText.includes('ftp')) currentHost.tags.push('ftp');
  if (fullText.includes('ssh')) currentHost.tags.push('ssh');
  if (fullText.includes('vsftpd')) currentHost.tags.push('ftp');
}

function processApsRhead(rh, currentHost) {
  const title = rh.textContent.trim().replace(/:$/, '');
  const titleLower = title.toLowerCase();
  const nextRes = [];
  let sibling = rh.nextElementSibling;
  while (sibling?.classList?.contains('res')) {
    nextRes.push(sibling.textContent.trim());
    sibling = sibling.nextElementSibling;
  }

  if (titleLower.includes('порт') || titleLower.includes('port')) {
    nextRes.forEach(r => {
      const parenIdx = r.indexOf('(');
      const port = parenIdx >= 0 ? r.slice(0, parenIdx).trim() : '';
      if (port) {
        if (/^\d+$/.test(port)) currentHost.ports.push(port);
      } else {
        const p = r.replace(/[/(\s:].*/, '').trim();
        if (/^\d+$/.test(p)) currentHost.ports.push(p);
      }
    });
    return;
  }

  if (titleLower.includes('radmin')) return;

  const info = nextRes.join(' ').trim();
  if (!info) {
    currentHost.services.push(title);
    return;
  }

  const openIdx = info.indexOf('(');
  const closeIdx = openIdx >= 0 ? info.indexOf(')', openIdx + 1) : -1;
  const serviceVersion = openIdx >= 0 && closeIdx > openIdx ? info.slice(openIdx + 1, closeIdx) : '';
  const serviceEntry = serviceVersion ? `${title} (${serviceVersion})` : title;
  currentHost.services.push(serviceEntry);

  const fullText = `${title} ${info}`.toLowerCase();
  extractApsServiceTags(fullText, currentHost);

  if (currentHost.notes.length < 500) {
    const noteEntry = serviceVersion ? `${title}: ${serviceVersion}` : `${title}: ${info.slice(0, 100)}`;
    currentHost.notes = (currentHost.notes ? currentHost.notes + '\n' : '') + noteEntry;
  }
}

function processApsDetailRow(row, currentHost) {
  const detailCell = row.querySelector('[colspan]') || Array.from(row.querySelectorAll('td')).slice(-1)[0];
  if (!detailCell) return;

  const rheads = Array.from(detailCell.querySelectorAll('.rhead'));
  if (rheads.length > 0) {
    rheads.forEach(rh => processApsRhead(rh, currentHost));
    return;
  }

  const text = detailCell.textContent.trim();
  if (text.toLowerCase().includes('port') || text.toLowerCase().includes('порт')) {
    const pList = extractPortsFromText(text);
    currentHost.ports.push(...pList);
  }
}

function applyApsPortTags(h) {
  if (h.ports.includes('445') || h.ports.includes('139')) h.tags.push('smb');
  if (h.ports.includes('3389')) h.tags.push('rdp');
  if (h.ports.includes('22')) h.tags.push('ssh');
  if (h.ports.includes('80') || h.ports.includes('443') || h.ports.includes('8080')) h.tags.push('web');
}

function createApsHostEntry(ip, hostname) {
  return { ip: ip || hostname, hostname: ip && hostname !== ip ? hostname : '', os: 'Unknown', status: 'alive', ports: [], services: [], tags: [], notes: '' };
}

function processApsMainRow(cells, ipIdx, hostIdx, portIdx, statusIdx, hosts) {
  let ipRaw = ipIdx >= 0 ? cells[ipIdx]?.textContent.trim() : '';
  let ip = extractIpFromRaw(ipRaw);
  ip = extractIpFromRaw(ip) || ip;
  const hostname = hostIdx >= 0 ? cells[hostIdx]?.textContent.trim() : '';
  const statusRaw = statusIdx >= 0 ? cells[statusIdx]?.textContent.trim().toLowerCase() : '';
  if (isDeadStatus(statusRaw)) return null;
  if (!ip && !hostname) return null;
  const host = createApsHostEntry(ip, hostname);
  hosts.push(host);
  if (portIdx >= 0) {
    const portRaw = cells[portIdx]?.textContent.trim();
    if (portRaw) host.ports.push(...extractPortsFromText(portRaw));
  }
  return host;
}

function processApsTable(table, hosts) {
  const rows = Array.from(table.querySelectorAll('tr'));
  if (rows.length < 2) return false;

  const { ipIdx, hostIdx, portIdx, statusIdx, startRow } = detectApsTableColumns(rows);
  if (ipIdx === -1 && hostIdx === -1) return false;

  let currentHost = null;

  for (let i = startRow; i < rows.length; i++) {
    const row = rows[i];
    const cells = Array.from(row.querySelectorAll('td'));
    if (cells.length === 0) continue;

    const ipRaw = ipIdx >= 0 ? cells[ipIdx]?.textContent.trim() : '';
    const ip = extractIpFromRaw(ipRaw);
    const isSubRow = (cells.length < Math.max(ipIdx, hostIdx) + 1) || (!ip && cells.length > 0 && row.querySelector('[colspan]'));

    if (!isSubRow && ip) {
      currentHost = processApsMainRow(cells, ipIdx, hostIdx, portIdx, statusIdx, hosts);
    } else if (isSubRow && currentHost) {
      processApsDetailRow(row, currentHost);
    }
  }

  return hosts.length > 0;
}

function apsFallbackTextScan(doc, htmlText) {
  const text = doc.body?.textContent || htmlText;
  const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
  const seen = new Set();
  const hosts = [];
  let m;
  while ((m = ipRe.exec(text)) !== null) {
    const ip = m[0];
    if (seen.has(ip)) continue;
    seen.add(ip);
    hosts.push({ ip, hostname: '', os: 'Unknown', status: 'alive', ports: [], services: [], tags: [], notes: '' });
  }
  return hosts;
}

export function parseApsHtml(htmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(htmlText, 'text/html');

  let hosts = [];

  for (const table of doc.querySelectorAll('table')) {
    if (processApsTable(table, hosts)) break;
  }

  if (hosts.length === 0) {
    hosts = apsFallbackTextScan(doc, htmlText);
  }

  hosts.forEach(h => {
    h.ports = [...new Set(h.ports)];
    h.services = [...new Set(h.services)];
    h.tags = [...new Set(h.tags)];
    if (h.ports.length > 0) h.status = 'scanned';
    applyApsPortTags(h);
    h.tags = [...new Set(h.tags)];
  });

  return { hosts, creds: [] };
}


// ── NetExec / CrackMapExec text parser ───────────────────────────────

const NETEXEC_SERVICE_MAP = {
  'SMB':   { service: 'SMB',   port: '445',  tag: 'smb'   },
  'WINRM': { service: 'WinRM', port: '5985', tag: 'winrm' },
  'SSH':   { service: 'SSH',   port: '22',   tag: 'ssh'   },
  'LDAP':  { service: 'LDAP',  port: '389',  tag: 'ldap'  },
  'MSSQL': { service: 'MSSQL', port: '1433', tag: 'mssql' },
  'RDP':   { service: 'RDP',   port: '3389', tag: 'rdp'   },
  'FTP':   { service: 'FTP',   port: '21',   tag: 'ftp'   },
  'HTTP':  { service: 'HTTP',  port: '80',   tag: 'web'   },
  'HTTPS': { service: 'HTTPS', port: '443',  tag: 'web'   },
  'VNC':   { service: 'VNC',   port: '5900', tag: 'vnc'   },
  'WMI':   { service: 'WMI',   port: '135',  tag: 'wmi'   },
};

function updateNetexecHostOs(host, message) {
  const osRe = /Windows\s+([\d.]+)\s+Build/i;
  const linuxRe = /Linux|Ubuntu|Debian|CentOS|RHEL|Fedora/i;
  if (message.match(osRe) && host.os === 'Unknown') host.os = 'Windows';
  if (linuxRe.test(message) && host.os === 'Unknown') host.os = 'Linux';
}

function appendNetexecNote(host, message) {
  if (message.includes('signing') || message.includes('domain') || message.includes('Domain')) {
    const note = message.trim().slice(0, 200);
    if (!host.notes.includes(note)) host.notes = (host.notes ? host.notes + '\n' : '') + note;
  }
}

function processNetexecCred(host, message, svcInfo, protoUp, ip, hostname, creds) {
  const credSuccessRe = /\[(\+|-|SUCCESS|Pwn3d!)\]\s+(?:([^\\/\s]+)[\\/])?([^:\s]+):([^\s()]+)/i;
  const pwnedRe = /\(Pwn3d!\)|\[Pwn3d!\]/i;
  const credM = message.match(credSuccessRe);
  if (!credM) return;

  const [, sign, domain, username, password] = credM;
  const isPwned = pwnedRe.test(message);
  const sUp = sign.toUpperCase();
  const isSuccess = sUp === '+' || sUp === 'SUCCESS' || sUp === 'PWN3D!';

  if (!isSuccess) return;

  if (isPwned) {
    host.status = 'pwned';
    host._pwned = true;
    if (!host.tags.includes('pwned')) host.tags.push('pwned');
  } else if (host.status !== 'pwned') {
    host.status = 'access';
  }

  const fullUser = domain ? `${domain}\\${username}` : username;
  creds.push({
    username: fullUser,
    secret: password,
    type: 'plain',
    service: svcInfo.service,
    host: ip,
    cracked: true,
    notes: `${protoUp} — ${isPwned ? 'Admin/Pwned' : 'Valid'} • ${hostname}`,
  });
}

function ensureNetexecHost(hostsMap, ip, hostname) {
  if (!hostsMap[ip]) {
    hostsMap[ip] = { ip, hostname, os: 'Unknown', status: 'alive', ports: [], services: [], tags: [], notes: '', _pwned: false };
  }
  const host = hostsMap[ip];
  if (hostname && !host.hostname) host.hostname = hostname;
  return host;
}

function applyNetexecSvcToHost(host, port, svcInfo) {
  if (port && !host.ports.includes(port)) host.ports.push(port);
  if (!host.services.includes(svcInfo.service)) host.services.push(svcInfo.service);
  if (!host.tags.includes(svcInfo.tag)) host.tags.push(svcInfo.tag);
  if (host.status === 'alive') host.status = 'scanned';
}

export function parseNetexecText(text) {
  const cleanText = text.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
  const lines = cleanText.split('\n');
  const hostsMap = {};
  const creds = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    const proto = (parts[0] || '').replace(/^\[/, '').replace(/\]$/, '');
    const ip = parts[1] || '';
    let idx = 2;
    const port1 = /^\d+$/.test(parts[idx] || '') ? parts[idx++] : '';
    const port2 = /^\d+$/.test(parts[idx] || '') ? parts[idx++] : '';
    const rawHostname = parts[idx++] || '-';
    const message = parts.slice(idx).join(' ');
    if (!proto || !ip || !message) continue;
    const protoUp = proto.toUpperCase();
    const port = port1 || port2 || (protoUp === 'SMB' ? '445' : '');
    const hostname = rawHostname === '-' ? '' : rawHostname;
    const svcInfo = NETEXEC_SERVICE_MAP[protoUp] || { service: proto, port, tag: proto.toLowerCase() };

    const host = ensureNetexecHost(hostsMap, ip, hostname);
    applyNetexecSvcToHost(host, port, svcInfo);
    updateNetexecHostOs(host, message);
    appendNetexecNote(host, message);
    processNetexecCred(host, message, svcInfo, protoUp, ip, hostname, creds);
  }

  const hosts = Object.values(hostsMap).map(({ _pwned, ...h }) => h);
  return { hosts, creds };
}
