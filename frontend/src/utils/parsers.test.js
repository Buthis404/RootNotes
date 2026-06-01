import { describe, it, expect } from 'vitest';
import { parseNmapXml, parseApsHtml, parseNetexecText } from './parsers.js';

describe('parseNmapXml', () => {
  const xml = `<?xml version="1.0"?>
  <nmaprun>
    <host>
      <status state="up"/>
      <address addr="10.0.0.5" addrtype="ipv4"/>
      <hostname name="dc01.corp.local"/>
      <os><osmatch name="Microsoft Windows Server 2019"/></os>
      <ports>
        <port portid="445"><state state="open"/><service name="microsoft-ds" product="Samba smbd" version="4.0"/></port>
        <port portid="88"><state state="open"/><service name="kerberos-sec"/></port>
        <port portid="9999"><state state="closed"/><service name="zzz"/></port>
      </ports>
      <hostscript><script id="smb-os" output="Windows Server 2019 build 17763"/></hostscript>
    </host>
    <host>
      <status state="down"/>
      <address addr="10.0.0.6" addrtype="ipv4"/>
    </host>
    <host>
      <status state="up"/>
      <hostname name="no-ip.local"/>
    </host>
  </nmaprun>`;

  it('parses up-hosts with an ipv4 address and skips down / ip-less hosts', () => {
    const { hosts, creds } = parseNmapXml(xml);
    expect(creds).toEqual([]);
    expect(hosts).toHaveLength(1);
    expect(hosts[0].ip).toBe('10.0.0.5');
    expect(hosts[0].hostname).toBe('dc01.corp.local');
  });

  it('detects OS, open ports, services and tags', () => {
    const h = parseNmapXml(xml).hosts[0];
    expect(h.os).toBe('Windows');
    expect(h.ports).toContain('445');
    expect(h.ports).toContain('88');
    expect(h.ports).not.toContain('9999');
    expect(h.services).toContain('microsoft-ds');
    expect(h.tags).toContain('smb');
    expect(h.tags).toContain('kerberos');
    expect(h.status).toBe('scanned');
  });

  it('captures script notes', () => {
    const h = parseNmapXml(xml).hosts[0];
    expect(h.notes).toContain('[smb-os]');
  });

  it('marks a host with no open ports as alive', () => {
    const xmlNoPorts = `<nmaprun><host><status state="up"/>
      <address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>`;
    const h = parseNmapXml(xmlNoPorts).hosts[0];
    expect(h.status).toBe('alive');
    expect(h.os).toBe('Unknown');
  });

  it('throws on malformed XML', () => {
    expect(() => parseNmapXml('<nmaprun><host>')).toThrow(/Invalid XML/);
  });
});

describe('parseApsHtml', () => {
  it('parses a table with IP / host / port columns', () => {
    const html = `<table>
      <tr><th>IP</th><th>Host</th><th>Port</th><th>Status</th></tr>
      <tr><td>192.168.1.10</td><td>web01</td><td>80, 443</td><td>online</td></tr>
      <tr><td>192.168.1.11</td><td>db01</td><td>3389</td><td>dead</td></tr>
    </table>`;
    const { hosts } = parseApsHtml(html);
    const ips = hosts.map(h => h.ip);
    expect(ips).toContain('192.168.1.10');
    // dead host is skipped
    expect(ips).not.toContain('192.168.1.11');
    const web = hosts.find(h => h.ip === '192.168.1.10');
    expect(web.ports).toEqual(expect.arrayContaining(['80', '443']));
    expect(web.tags).toContain('web');
    expect(web.status).toBe('scanned');
  });

  it('applies port-derived tags (smb/rdp/ssh)', () => {
    const html = `<table>
      <tr><th>address</th><th>port</th></tr>
      <tr><td>10.1.1.1</td><td>445 139 22</td></tr>
    </table>`;
    const h = parseApsHtml(html).hosts[0];
    expect(h.tags).toEqual(expect.arrayContaining(['smb', 'ssh']));
  });

  it('falls back to a raw IP text scan when no usable table exists', () => {
    const html = `<div>scan log 172.16.5.5 and 172.16.5.6 found, 172.16.5.5 dup</div>`;
    const { hosts } = parseApsHtml(html);
    const ips = hosts.map(h => h.ip);
    expect(ips).toEqual(['172.16.5.5', '172.16.5.6']);
  });
});

describe('parseNetexecText', () => {
  it('parses hosts, services and OS from netexec output', () => {
    const out = [
      'SMB         10.0.0.20    445    DC01    [*] Windows 10.0 Build 17763 (name:DC01) (domain:corp.local) (signing:True)',
      'SMB         10.0.0.20    445    DC01    [+] corp.local\\administrator:Passw0rd! (Pwn3d!)',
    ].join('\n');
    const { hosts, creds } = parseNetexecText(out);
    expect(hosts).toHaveLength(1);
    const h = hosts[0];
    expect(h.ip).toBe('10.0.0.20');
    expect(h.os).toBe('Windows');
    expect(h.ports).toContain('445');
    expect(h.services).toContain('SMB');
    expect(h.status).toBe('pwned');
    // _pwned internal flag is stripped from output
    expect(h).not.toHaveProperty('_pwned');

    expect(creds).toHaveLength(1);
    expect(creds[0]).toMatchObject({
      username: 'corp.local\\administrator',
      secret: 'Passw0rd!',
      cracked: true,
      host: '10.0.0.20',
    });
    expect(creds[0].notes).toContain('Admin/Pwned');
  });

  it('records valid (non-pwned) creds and sets access status', () => {
    const out = 'SMB  10.0.0.21  445  WS01  [+] corp\\user:Spring2024';
    const { hosts, creds } = parseNetexecText(out);
    expect(creds[0].username).toBe('corp\\user');
    expect(creds[0].notes).toContain('Valid');
    expect(hosts[0].status).toBe('access');
  });

  it('strips ANSI colour codes and ignores short lines', () => {
    const out = '\x1b[32mSMB\x1b[0m 10.0.0.22 445 SRV [*] signing enabled\nshort line';
    const { hosts } = parseNetexecText(out);
    expect(hosts).toHaveLength(1);
    expect(hosts[0].ip).toBe('10.0.0.22');
  });

  it('does not emit creds for failed auth attempts', () => {
    const out = 'SMB  10.0.0.23  445  SRV  [-] corp\\user:wrongpass STATUS_LOGON_FAILURE';
    const { creds } = parseNetexecText(out);
    expect(creds).toHaveLength(0);
  });
});
