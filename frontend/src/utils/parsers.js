// ── Nmap XML parser ───────────────────────────────────────────────────
export function parseNmapXml(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, 'application/xml');
  const parseError = doc.querySelector('parsererror');
  if (parseError) throw new Error('Invalid XML: ' + parseError.textContent.slice(0, 120));

  const hosts = [];
  doc.querySelectorAll('host').forEach(hostEl => {
    // skip down hosts
    const state = hostEl.querySelector('status')?.getAttribute('state');
    if (state && state !== 'up') return;

    const ip = hostEl.querySelector('address[addrtype="ipv4"]')?.getAttribute('addr')
      || hostEl.querySelector('address[addrtype="ipv6"]')?.getAttribute('addr')
      || '';
    if (!ip) return;

    const hostname = hostEl.querySelector('hostname')?.getAttribute('name') || '';

    // OS detection
    let os = 'Unknown';
    const osMatch = hostEl.querySelector('osmatch');
    const osClass = hostEl.querySelector('osclass');
    const osName = (osMatch?.getAttribute('name') || osClass?.getAttribute('osfamily') || '').toLowerCase();

    if (/windows/i.test(osName)) os = 'Windows';
    else if (/linux/i.test(osName)) os = 'Linux';
    else if (/mac\s*os|darwin/i.test(osName)) os = 'macOS';
    else if (/freebsd|openbsd|netbsd/i.test(osName)) os = 'Linux'; // close enough for tags

    // Fallback: CPE
    if (os === 'Unknown') {
      const cpes = Array.from(hostEl.querySelectorAll('cpe')).map(c => c.textContent).join(' ');
      if (/windows/i.test(cpes)) os = 'Windows';
      else if (/linux/i.test(cpes)) os = 'Linux';
    }

    const ports = [];
    const services = [];
    const tags = [];

    hostEl.querySelectorAll('port').forEach(portEl => {
      const portState = portEl.querySelector('state')?.getAttribute('state');
      if (portState !== 'open') return;

      const portId = portEl.getAttribute('portid');
      const proto = portEl.getAttribute('protocol') || 'tcp';
      ports.push(portId);

      const svcEl = portEl.querySelector('service');
      if (svcEl) {
        const svcName = svcEl.getAttribute('name') || '';
        const product = svcEl.getAttribute('product') || '';
        const version = svcEl.getAttribute('version') || '';
        if (svcName) services.push(svcName);
        if (product) tags.push(product.split(' ')[0].toLowerCase());

        // extract useful version tags
        const fullSvc = `${product} ${version}`.trim();
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
      }
    });

    // Script output notes
    const scriptNotes = [];
    hostEl.querySelectorAll('script').forEach(s => {
      const id = s.getAttribute('id') || '';
      const output = s.getAttribute('output') || '';
      if (output && id) scriptNotes.push(`[${id}] ${output.slice(0, 200)}`);
    });

    // status based on open ports found
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
export function parseApsHtml(htmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(htmlText, 'text/html');

  const hosts = [];
  let currentHost = null;

  const tables = doc.querySelectorAll('table');

  for (const table of tables) {
    const rows = Array.from(table.querySelectorAll('tr'));
    if (rows.length < 2) continue;

    // Detect header row and column indices
    let ipIdx = -1, hostIdx = -1, portIdx = -1, statusIdx = -1;
    let startRow = 0;

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

    if (ipIdx === -1 && hostIdx === -1) continue;

    for (let i = startRow; i < rows.length; i++) {
      const row = rows[i];
      const cells = Array.from(row.querySelectorAll('td'));
      if (cells.length === 0) continue;

      let ipRaw = ipIdx >= 0 ? cells[ipIdx]?.textContent.trim() : '';
      let ip = '';
      if (ipRaw) {
        const ipMatch = ipRaw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/) || ipRaw.match(/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/);
        if (ipMatch) ip = ipMatch[0];
      }

      const isSubRow = (cells.length < Math.max(ipIdx, hostIdx) + 1) || (!ip && cells.length > 0 && row.querySelector('[colspan]'));

      if (!isSubRow && ip) {
        // This is a new host row
        const hostname = hostIdx >= 0 ? cells[hostIdx]?.textContent.trim() : '';
        const statusRaw = statusIdx >= 0 ? cells[statusIdx]?.textContent.trim().toLowerCase() : '';

        if (statusRaw && (statusRaw.includes('dead') || statusRaw.includes('offline') || statusRaw.includes('не в сети') || statusRaw === 'выключен' || statusRaw === 'отключен')) {
          currentHost = null;
          continue;
        }

        if (ip) {
          const ipMatch = ip.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/) || ip.match(/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/);
          if (ipMatch) ip = ipMatch[0];
        }

        if (!ip && !hostname) continue;

        currentHost = {
          ip: ip || hostname,
          hostname: ip && hostname !== ip ? hostname : '',
          os: 'Unknown',
          status: 'alive',
          ports: [],
          services: [],
          tags: [],
          notes: '',
        };
        hosts.push(currentHost);

        // If ports are in the same row
        if (portIdx >= 0) {
          const portRaw = cells[portIdx]?.textContent.trim();
          if (portRaw) {
            const pList = portRaw.split(/[\s,;|]+/).map(p => p.replace(/[\/\(\s].*/, '').trim()).filter(p => /^\d+$/.test(p));
            currentHost.ports.push(...pList);
          }
        }
      } else if (isSubRow && currentHost) {
        // This is a details row for the current host
        const detailCell = row.querySelector('[colspan]') || cells[cells.length - 1];
        if (!detailCell) continue;

        const rheads = Array.from(detailCell.querySelectorAll('.rhead'));
        if (rheads.length > 0) {
          rheads.forEach(rh => {
            const title = rh.textContent.trim().replace(/:$/, '');
            const titleLower = title.toLowerCase();
            const nextRes = [];
            let sibling = rh.nextElementSibling;
            while (sibling && sibling.classList.contains('res')) {
              nextRes.push(sibling.textContent.trim());
              sibling = sibling.nextElementSibling;
            }

            if (titleLower.includes('порт') || titleLower.includes('port')) {
              // Parse ports
              nextRes.forEach(r => {
                const portMatch = r.match(/(\d+)\s*\(([A-Z]+)\)/i);
                if (portMatch) {
                  const [, port, proto] = portMatch;
                  if (port && /^\d+$/.test(port)) {
                    currentHost.ports.push(port);
                  }
                } else {
                  const p = r.replace(/[\/\(\s:].*/, '').trim();
                  if (/^\d+$/.test(p)) currentHost.ports.push(p);
                }
              });
            } else if (!titleLower.includes('radmin')) {
              // Parse service information
              const info = nextRes.join(' ').trim();
              
              // Extract service name and version from different formats
              // Format 1: "Service name (software version)"
              // Format 2: "Page title (software version)"
              let serviceName = title;
              let serviceVersion = '';
              
              if (info) {
                // Try to extract version info in parentheses
                const versionMatch = info.match(/\(([^)]+)\)/);
                if (versionMatch) {
                  serviceVersion = versionMatch[1];
                }
                
                // Store as service with version
                const serviceEntry = serviceVersion ? `${serviceName} (${serviceVersion})` : serviceName;
                currentHost.services.push(serviceEntry);
                
                // Extract tags from service info
                const fullText = `${title} ${info}`.toLowerCase();
                if (fullText.includes('apache')) currentHost.tags.push('apache');
                if (fullText.includes('nginx')) currentHost.tags.push('nginx');
                if (fullText.includes('iis')) currentHost.tags.push('iis');
                if (fullText.includes('mysql')) currentHost.tags.push('mysql');
                if (fullText.includes('postgresql') || fullText.includes('postgres')) currentHost.tags.push('postgres');
                if (fullText.includes('mssql') || fullText.includes('microsoft sql')) currentHost.tags.push('mssql');
                if (fullText.includes('ftp')) currentHost.tags.push('ftp');
                if (fullText.includes('ssh')) currentHost.tags.push('ssh');
                if (fullText.includes('vsftpd')) currentHost.tags.push('ftp');
                
                // Add to notes with cleaner format
                if (currentHost.notes.length < 500) {
                  const noteEntry = serviceVersion ? `${serviceName}: ${serviceVersion}` : `${serviceName}: ${info.slice(0, 100)}`;
                  currentHost.notes = (currentHost.notes ? currentHost.notes + '\n' : '') + noteEntry;
                }
              } else {
                currentHost.services.push(serviceName);
              }
            }
          });
        } else {
          // Fallback for detail rows without .rhead (just text)
          const text = detailCell.textContent.trim();
          if (text.toLowerCase().includes('port') || text.toLowerCase().includes('порт')) {
            const pList = text.split(/[\s,;|]+/).map(p => p.replace(/[\/\(\s].*/, '').trim()).filter(p => /^\d+$/.test(p));
            currentHost.ports.push(...pList);
          }
        }
      }
    }

    if (hosts.length > 0) break;
  }

  // Fallback: scan all text for IP addresses if no table found
  if (hosts.length === 0) {
    const text = doc.body?.textContent || htmlText;
    const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
    const seen = new Set();
    let m;
    while ((m = ipRe.exec(text)) !== null) {
      const ip = m[0];
      if (seen.has(ip)) continue;
      seen.add(ip);
      hosts.push({ ip, hostname: '', os: 'Unknown', status: 'alive', ports: [], services: [], tags: [], notes: '' });
    }
  }

  // Final cleanup for each host
  hosts.forEach(h => {
    h.ports = [...new Set(h.ports)];
    h.services = [...new Set(h.services)];
    h.tags = [...new Set(h.tags)];
    if (h.ports.length > 0) h.status = 'scanned';
    
    // Auto tags based on ports
    if (h.ports.includes('445') || h.ports.includes('139')) h.tags.push('smb');
    if (h.ports.includes('3389')) h.tags.push('rdp');
    if (h.ports.includes('22')) h.tags.push('ssh');
    if (h.ports.includes('80') || h.ports.includes('443') || h.ports.includes('8080')) h.tags.push('web');
    h.tags = [...new Set(h.tags)];
  });

  return { hosts, creds: [] };
}


// ── NetExec / CrackMapExec text parser ───────────────────────────────
export function parseNetexecText(text) {
  // Strip ANSI escape codes
  const cleanText = text.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
  const lines = cleanText.split('\n');
  const hostsMap = {};   // ip -> host obj
  const creds = [];

  // Regex patterns
  const mainRe = /^\s*(?:\[)?([\w\(\)-]+)(?:\])?\s+([0-9a-fA-F\.:]+)(?::(\d+))?\s+(\d+)?\s*(\S+)\s+(.*)/;
  const credSuccessRe = /\[(\+|-|SUCCESS|Pwn3d!)\]\s+(?:([^\\\/\s]+)[\\\/])?([^:\s]+):([^\s\(\)]+)/i;
  const pwnedRe = /\(Pwn3d!\)|\[Pwn3d!\]/i;
  const osRe = /Windows\s+([\d.]+)\s+Build/i;
  const linuxRe = /Linux|Ubuntu|Debian|CentOS|RHEL|Fedora/i;

  const serviceMap = {
    'SMB': { service: 'SMB', port: '445', tag: 'smb' },
    'WINRM': { service: 'WinRM', port: '5985', tag: 'winrm' },
    'SSH': { service: 'SSH', port: '22', tag: 'ssh' },
    'LDAP': { service: 'LDAP', port: '389', tag: 'ldap' },
    'MSSQL': { service: 'MSSQL', port: '1433', tag: 'mssql' },
    'RDP': { service: 'RDP', port: '3389', tag: 'rdp' },
    'FTP': { service: 'FTP', port: '21', tag: 'ftp' },
    'HTTP': { service: 'HTTP', port: '80', tag: 'web' },
    'HTTPS': { service: 'HTTPS', port: '443', tag: 'web' },
    'VNC': { service: 'VNC', port: '5900', tag: 'vnc' },
    'WMI': { service: 'WMI', port: '135', tag: 'wmi' },
  };

  for (const line of lines) {
    const m = line.match(mainRe);
    if (!m) continue;

    const [, proto, ip, port1, port2, rawHostname, message] = m;
    const protoUp = proto.toUpperCase();
    const port = port1 || port2 || (protoUp === 'SMB' ? '445' : '');
    const hostname = rawHostname === '-' ? '' : rawHostname;
    const svcInfo = serviceMap[protoUp] || { service: proto, port, tag: proto.toLowerCase() };

    if (!hostsMap[ip]) {
      hostsMap[ip] = {
        ip,
        hostname,
        os: 'Unknown',
        status: 'alive',
        ports: [],
        services: [],
        tags: [],
        notes: '',
        _pwned: false,
      };
    }
    const host = hostsMap[ip];
    if (hostname && !host.hostname) host.hostname = hostname;

    if (port && !host.ports.includes(port)) host.ports.push(port);
    if (!host.services.includes(svcInfo.service)) host.services.push(svcInfo.service);
    if (!host.tags.includes(svcInfo.tag)) host.tags.push(svcInfo.tag);

    if (host.status === 'alive') host.status = 'scanned';

    const osM = message.match(osRe);
    if (osM && host.os === 'Unknown') host.os = 'Windows';
    if (linuxRe.test(message) && host.os === 'Unknown') host.os = 'Linux';
    if (message.includes('signing') || message.includes('domain') || message.includes('Domain')) {
      const note = message.trim().slice(0, 200);
      if (!host.notes.includes(note)) host.notes = (host.notes ? host.notes + '\n' : '') + note;
    }

    const credM = message.match(credSuccessRe);
    if (credM) {
      const [, sign, domain, username, password] = credM;
      const isPwned = pwnedRe.test(message);
      const sUp = sign.toUpperCase();
      const isSuccess = sUp === '+' || sUp === 'SUCCESS' || sUp === 'PWN3D!';

      if (isSuccess) {
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
    }
  }

  const hosts = Object.values(hostsMap).map(({ _pwned, ...h }) => h);
  return { hosts, creds };
}
