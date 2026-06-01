import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import NmapParser from './NmapParser.jsx';

function renderParser(extra = {}) {
  const onImport = extra.onImport || vi.fn().mockResolvedValue({ hosts_added: 1 });
  const onClose = vi.fn();
  render(<NmapParser pid="p1" onImport={onImport} onClose={onClose} accent="#cc2233" />);
  return { onImport, onClose };
}

function parse(text) {
  fireEvent.change(screen.getByRole('textbox'), { target: { value: text } });
  fireEvent.click(screen.getByRole('button', { name: 'Parse' }));
}

const NMAP_XML = `<?xml version="1.0"?><nmaprun>
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <hostname name="dc01.corp.local"/>
    <os><osmatch name="Microsoft Windows Server 2019"/></os>
    <ports><port portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports>
  </host></nmaprun>`;

describe('NmapParser', () => {
  it('parses Nmap XML and renders the host table', async () => {
    renderParser();
    parse(NMAP_XML);
    expect(await screen.findByText('Hosts found: 1')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument();
    expect(screen.getByText('dc01.corp.local')).toBeInTheDocument();
    // format badge
    expect(screen.getByText('Nmap XML')).toBeInTheDocument();
  });

  it('parses Nmap grepable output', async () => {
    renderParser();
    parse('Host: 192.168.1.10 (web01)\tPorts: 80/open/tcp//http//,443/open/tcp//https//\n');
    expect(await screen.findByText('Hosts found: 1')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    expect(screen.getByText('Nmap -oG')).toBeInTheDocument();
  });

  it('detects NetExec output', async () => {
    renderParser();
    parse('SMB  10.0.0.20  445  DC01  [*] Windows 10.0 (name:DC01) (domain:corp.local)\n');
    expect(await screen.findByText('Hosts found: 1')).toBeInTheDocument();
    expect(screen.getByText('NetExec/CME')).toBeInTheDocument();
  });

  it('shows "No hosts found" for unparseable input', async () => {
    renderParser();
    parse('just some random text with no hosts');
    expect(await screen.findByText('No hosts found')).toBeInTheDocument();
  });

  it('calls onImport and shows the import result', async () => {
    const onImport = vi.fn().mockResolvedValue({ hosts_added: 1 });
    renderParser({ onImport });
    parse(NMAP_XML);
    await screen.findByText('Hosts found: 1');
    fireEvent.click(screen.getByRole('button', { name: /Import 1 hosts/ }));
    await waitFor(() => expect(onImport).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Imported: 1 new hosts/)).toBeInTheDocument();
  });
});
