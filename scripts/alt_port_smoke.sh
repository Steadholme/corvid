#!/usr/bin/env bash
# Alt-port smoke for Corvid — NEVER binds :25.
#
# Builds holdfast/corvid:dev, runs it on ALT ports (2525/2587/8800) with CORVID_STORE=postgres
# (throwaway Postgres) + the REAL DKIM key, then:
#   1. SMTP-injects a message to w33d@w33d.xyz on 2525,
#   2. confirms the webmail inbox (GET /, X-Auth-Subject: w33d) shows it,
#   3. composes + sends a message, and verifies the queued OUTBOUND message carries a VALID
#      DKIM signature (checked against the published default.txt public key, in-container).
# Cleans up all throwaway containers/network on exit.
set -euo pipefail

IMG=holdfast/corvid:dev
NET=corvid-smoke-net
PG=corvid-smoke-pg
APP=corvid-smoke-app
PGPW=smokepw
DKIM_DIR=/etc/opendkim/keys/w33d.xyz

cleanup() {
  docker rm -f "$APP" >/dev/null 2>&1 || true
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "== build image =="
docker build -t "$IMG" "$(dirname "$0")/.." >/dev/null

echo "== network + throwaway postgres =="
docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_PASSWORD="$PGPW" -e POSTGRES_DB=corvid postgres:18-alpine >/dev/null
for i in $(seq 1 30); do
  docker exec "$PG" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

echo "== run corvid on alt ports (2525/2587/8800), real DKIM key, postgres store =="
docker run -d --name "$APP" --network "$NET" --user 0:0 \
  -e CORVID_STORE=postgres \
  -e DATABASE_URL="postgres://postgres:${PGPW}@${PG}:5432/corvid" \
  -e MAIL_DOMAIN=w33d.xyz \
  -e DKIM_KEY_PATH=/run/dkim/default.private \
  -e SMTP_ADDR=0.0.0.0:2525 -e SUBMISSION_ADDR=0.0.0.0:2587 -e WEBMAIL_ADDR=0.0.0.0:8800 \
  -v "${DKIM_DIR}:/run/dkim:ro" \
  -p 127.0.0.1:2525:2525 -p 127.0.0.1:2587:2587 -p 127.0.0.1:8800:8800 \
  "$IMG" >/dev/null

echo "== wait for webmail healthz =="
for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8800/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:8800/healthz >/dev/null

echo "== 1) SMTP inject -> w33d@w33d.xyz on :2525 =="
python3 - <<'PY'
import socket, sys
def expect(sock, prefix):
    data = sock.recv(4096).decode(errors="replace")
    if not data.startswith(prefix):
        sys.exit(f"SMTP: expected {prefix}, got {data!r}")
    return data
s = socket.create_connection(("127.0.0.1", 2525), timeout=10)
expect(s, "220")
s.sendall(b"EHLO smoke.local\r\n");      expect(s, "250")
s.sendall(b"MAIL FROM:<alice@example.com>\r\n"); expect(s, "250")
s.sendall(b"RCPT TO:<w33d@w33d.xyz>\r\n");        expect(s, "250")
s.sendall(b"DATA\r\n");                  expect(s, "354")
msg = (b"From: Alice <alice@example.com>\r\n"
       b"To: w33d@w33d.xyz\r\n"
       b"Subject: Corvid Smoke Inbound\r\n"
       b"\r\n"
       b"Hello from the alt-port smoke test.\r\n"
       b".\r\n")
s.sendall(msg);                          expect(s, "250")
s.sendall(b"QUIT\r\n");                  expect(s, "221")
s.close()
print("   injected OK")
PY

echo "== 2) webmail inbox shows it + 3) compose/send =="
python3 - <<'PY'
import urllib.request, urllib.error, urllib.parse, sys, re
BASE = "http://127.0.0.1:8800"
def get(path, headers=None):
    req = urllib.request.Request(BASE+path, headers=headers or {})
    return urllib.request.urlopen(req, timeout=10)

# 2) inbox lists the injected message
r = get("/", {"X-Auth-Subject": "w33d", "X-Auth-Email": "w33d@steadholme.local"})
body = r.read().decode(errors="replace")
assert r.status == 200, r.status
assert "Corvid Smoke Inbound" in body, "injected subject missing from inbox"
print("   inbox shows injected message OK")

# 3) compose -> capture CSRF cookie+token
r = get("/compose", {"X-Auth-Subject": "w33d"})
cookie = r.headers.get("Set-Cookie", "")
m = re.search(r"__Host-csrf=([0-9a-f]+)", cookie)
assert m, f"no CSRF cookie: {cookie!r}"
token = m.group(1)

# POST /send
data = urllib.parse.urlencode({
    "csrf": token, "to": "relay-test@example.net",
    "subject": "Corvid Smoke Outbound", "body": "Outbound body for DKIM check.",
}).encode()
req = urllib.request.Request(BASE+"/send", data=data, method="POST", headers={
    "X-Auth-Subject": "w33d",
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": f"__Host-csrf={token}",
})
try:
    r = urllib.request.urlopen(req, timeout=10)
    code = r.status
except urllib.error.HTTPError as e:
    code = e.code
# urllib follows the 303 -> lands on 200 inbox; either is success.
assert code in (200, 303), f"send failed: {code}"
print("   compose/send accepted OK")
PY

echo "== verify the OUTBOUND message carries a VALID DKIM signature =="
RAW_B64=$(docker exec "$PG" psql -U postgres -d corvid -t -A \
  -c "SELECT encode(convert_to(raw,'UTF8'),'base64') FROM outbound_queue ORDER BY id LIMIT 1" | tr -d '[:space:]')
test -n "$RAW_B64" || { echo "no outbound row found"; exit 1; }
RESULT=$(printf '%s' "$RAW_B64" | base64 -d | docker exec -i "$APP" corvid dkim-verify /run/dkim/default.txt)
echo "   dkim-verify: $RESULT"
[ "$RESULT" = "DKIM VALID" ] || { echo "DKIM verification FAILED"; exit 1; }

echo
echo "ALT-PORT SMOKE OK: inject->store->webmail render + compose/send + VALID DKIM (vs published default.txt)"
