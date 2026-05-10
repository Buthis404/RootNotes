"""
Auto-enrichment: detect tool from command, parse output, return structured host data.

Supported tools:
  nmap      — text output ("Nmap scan report for ...") or XML ("-oX -")
  netexec   — CME/nxc/netexec SMB/WinRM/LDAP/RDP output
  secretsdump — impacket secretsdump NTLM hashes
  hydra     — hydra/medusa/crowbar found credentials
"""
import re
import xml.etree.ElementTree as ET
from typing import Optional


# ── Tool detection ────────────────────────────────────────────────────

_TOOL_PATTERNS = [
    ("nmap",        re.compile(r"\bnmap\b", re.I)),
    ("netexec",     re.compile(r"\b(netexec|nxc|crackmapexec|cme)\b", re.I)),
    ("secretsdump", re.compile(r"\bsecretsdump\b|\bimpacket-secretsdump\b", re.I)),
    ("hydra",       re.compile(r"\b(hydra|medusa|crowbar)\b", re.I)),
]


def detect_tool(command: str) -> Optional[str]:
    for name, pat in _TOOL_PATTERNS:
        if pat.search(command):
            return name
    return None


# ── Nmap parsers ──────────────────────────────────────────────────────

def _parse_nmap_xml(xml_text: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        if state_el is None or state_el.get("state") != "up":
            continue
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue
        hostname = ""
        for hn in host_el.findall(".//hostname"):
            if hn.get("type") in ("user", "PTR", None):
                hostname = hn.get("name", "")
                break
        os_guess = ""
        os_el = host_el.find(".//osmatch")
        if os_el is not None:
            os_guess = os_el.get("name", "")
        ports, services = [], []
        for port_el in host_el.findall(".//port"):
            st = port_el.find("state")
            if st is None or st.get("state") != "open":
                continue
            portid = port_el.get("portid", "")
            proto  = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            svc_name    = svc_el.get("name", "")    if svc_el is not None else ""
            svc_product = svc_el.get("product", "") if svc_el is not None else ""
            ports.append(f"{portid}/{proto}")
            if svc_name:
                label = f"{portid}/{svc_name}" + (f" ({svc_product})" if svc_product else "")
                services.append(label)
        hosts.append({"ip": ip, "hostname": hostname, "os": os_guess,
                      "ports": ports, "services": services})
    return hosts


def _parse_nmap_text(text: str) -> list[dict]:
    hosts = []
    current: dict | None = None
    for line in text.splitlines():
        line = line.strip()
        # New host block
        m = re.match(r"Nmap scan report for (?:(\S+)\s+\((\d[\d.]+)\)|(\d[\d.]+))", line)
        if m:
            if current:
                hosts.append(current)
            if m.group(3):
                current = {"ip": m.group(3), "hostname": "", "os": "", "ports": [], "services": []}
            else:
                current = {"ip": m.group(2), "hostname": m.group(1), "os": "", "ports": [], "services": []}
            continue
        if current is None:
            continue
        # OS guess
        m = re.match(r"OS details?: (.+)", line, re.I)
        if m and not current["os"]:
            current["os"] = m.group(1).strip()
            continue
        # Aggressive OS guess
        m = re.match(r"Aggressive OS guesses?: (.+?) \(\d", line, re.I)
        if m and not current["os"]:
            current["os"] = m.group(1).strip()
            continue
        # Open port line: 22/tcp   open  ssh
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S*)(.*)", line, re.I)
        if m:
            port, proto, svc, rest = m.groups()
            port_str = f"{port}/{proto}"
            if port_str not in current["ports"]:
                current["ports"].append(port_str)
            svc = svc.strip()
            version = rest.strip()
            if svc:
                label = f"{port}/{svc}" + (f" ({version})" if version else "")
                current["services"].append(label)
    if current:
        hosts.append(current)
    return hosts


def parse_nmap(output: str) -> list[dict]:
    # Try XML first (if command used -oX -)
    if output.lstrip().startswith("<?xml") or output.lstrip().startswith("<nmaprun"):
        return _parse_nmap_xml(output)
    return _parse_nmap_text(output)


# ── NetExec / CME parser ──────────────────────────────────────────────

_NXC_HOST_RE    = re.compile(r"^(?:SMB|WINRM|LDAP|RDP|FTP|SSH|MSSQL)\s+([\d.]+)\s+(\d+)\s+(\S+)\s+\[", re.I)
_NXC_OS_RE      = re.compile(r"\(name:([^)]+)\).*\(domain:([^)]+)\).*\(signing:(True|False)\).*\(SMBv1:(True|False)\)", re.I)
_NXC_WIN_OS_RE  = re.compile(r"(Windows\s+\S+(?:\s+\S+)?)", re.I)
_NXC_DOMAIN_RE  = re.compile(r"\(domain:([^)]+)\)", re.I)
_NXC_AUTH_RE    = re.compile(r"\[\+\].*?(?:([\w.]+)\\)?([\w.@-]+):(.*?)\s", re.I)
_NXC_PWNED_RE   = re.compile(r"\(Pwn3d!\)", re.I)
_NXC_HASH_RE    = re.compile(r"^[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}$")


def parse_netexec(output: str) -> dict:
    hosts: dict[str, dict] = {}
    found_creds: list[dict] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _NXC_HOST_RE.match(line)
        if m:
            ip, port, name = m.group(1), m.group(2), m.group(3)
            if ip not in hosts:
                hosts[ip] = {"ip": ip, "hostname": name, "domain": "",
                             "ports": [], "services": [], "os": "", "smb_signing": None}
            h = hosts[ip]
            port_str = f"{port}/tcp"
            if port_str not in h["ports"]:
                h["ports"].append(port_str)
            dm = _NXC_DOMAIN_RE.search(line)
            if dm:
                domain = dm.group(1).strip()
                if domain.lower() != name.lower():
                    h["domain"] = domain
            om = _NXC_WIN_OS_RE.search(line)
            if om and not h["os"]:
                h["os"] = om.group(1).strip()
            sm = re.search(r"\(signing:(True|False)\)", line, re.I)
            if sm:
                h["smb_signing"] = sm.group(1).lower() == "true"
            continue

        # Successful auth line: [+] DOMAIN\user:pass
        if "[+]" in line:
            am = _NXC_AUTH_RE.search(line)
            if am:
                domain_part = (am.group(1) or "").strip()
                username    = (am.group(2) or "").strip()
                secret      = (am.group(3) or "").strip()
                if username and secret and secret not in ("<empty>", ""):
                    ctype = "hash" if _NXC_HASH_RE.match(secret) else "plain"
                    pwned = bool(_NXC_PWNED_RE.search(line))
                    found_creds.append({
                        "domain":   domain_part,
                        "username": username,
                        "secret":   secret,
                        "type":     ctype,
                        "service":  "smb",
                        "pwned":    pwned,
                    })

    return {"hosts": list(hosts.values()), "creds": found_creds}


# ── Secretsdump parser ────────────────────────────────────────────────

_HASH_LINE_RE = re.compile(
    r"^(?:([\w.-]+)\\)?([\w.$@-]+):\d+:([A-Fa-f0-9]{32}):([A-Fa-f0-9]{32}):::",
)
_PLAIN_LINE_RE = re.compile(r"^(?:([\w.-]+)\\)?([\w.$@-]+):.*?:(.+)$")


def parse_secretsdump(output: str) -> dict:
    creds = []
    for line in output.splitlines():
        line = line.strip()
        m = _HASH_LINE_RE.match(line)
        if m:
            domain, username, lm, nt = m.groups()
            creds.append({
                "domain":   domain or "",
                "username": username,
                "secret":   f"{lm}:{nt}",
                "type":     "ntlm",
                "service":  "smb",
            })
    return {"creds": creds}


# ── Hydra / Medusa parser ─────────────────────────────────────────────

_HYDRA_RE  = re.compile(r"\[(\d+)\]\[(\w+)\] host: ([\d.]+).*?login: (\S+).*?password: (\S+)", re.I)
_MEDUSA_RE = re.compile(r"ACCOUNT FOUND.*?Host:\s*([\d.]+).*?User:\s*(\S+).*?Password:\s*(\S+)", re.I)


def parse_hydra(output: str) -> dict:
    creds = []
    for line in output.splitlines():
        m = _HYDRA_RE.search(line)
        if m:
            port, service, ip, username, secret = m.groups()
            creds.append({
                "host": ip, "username": username, "secret": secret,
                "type": "plain", "service": service,
            })
        m = _MEDUSA_RE.search(line)
        if m:
            ip, username, secret = m.groups()
            creds.append({
                "host": ip, "username": username, "secret": secret,
                "type": "plain", "service": "unknown",
            })
    return {"creds": creds}


# ── Main entry ────────────────────────────────────────────────────────

def parse_output(command: str, output: str) -> dict:
    """Detect tool from command and parse output.

    Returns:
        {
          "tool": str | None,
          "hosts": [{"ip", "hostname", "os", "domain", "ports", "services", ...}],
          "creds": [{"domain", "username", "secret", "type", "service", ...}],
        }
    """
    tool = detect_tool(command)
    if not tool or not output:
        return {"tool": tool, "hosts": [], "creds": []}

    if tool == "nmap":
        hosts = parse_nmap(output)
        return {"tool": "nmap", "hosts": hosts, "creds": []}

    if tool == "netexec":
        r = parse_netexec(output)
        return {"tool": "netexec", "hosts": r["hosts"], "creds": r["creds"]}

    if tool == "secretsdump":
        r = parse_secretsdump(output)
        return {"tool": "secretsdump", "hosts": [], "creds": r["creds"]}

    if tool == "hydra":
        r = parse_hydra(output)
        return {"tool": "hydra", "hosts": [], "creds": r["creds"]}

    return {"tool": tool, "hosts": [], "creds": []}
