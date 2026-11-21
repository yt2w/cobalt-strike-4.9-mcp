#!/usr/bin/env bash
# reconnect.sh - bring the cs-mcp-4.9 MCP server back up inside a running
# opencode daemon.
#
# Why this exists
# ---------------
# opencode spawns the MCP server as a child process and talks to it over
# stdio.  If that child ever goes away, opencode does NOT respawn it:
# the entry turns into a permanent "failed" badge and the tools vanish
# from the catalog, even though the server itself is perfectly healthy.
#
# opencode does expose a runtime route for exactly this:
#
#     POST /api/experimental/mcp/<name>/connect
#
# The daemon's API uses HTTP Basic auth with the user name "opencode"
# and the password from ~/.config/opencode/service.json.
#
#   ./reconnect.sh              reconnect every configured MCP server
#   ./reconnect.sh cobalt-strike
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SERVICE_JSON="${OPENCODE_SERVICE_JSON:-$HOME/.config/opencode/service.json}"

if [ ! -f "$SERVICE_JSON" ]; then
    echo "[!] no $SERVICE_JSON" >&2
    exit 1
fi

PASSWORD="$(python3 -c '
import json,sys
print(json.load(open(sys.argv[1])).get("password",""))' "$SERVICE_JSON")"
if [ -z "$PASSWORD" ]; then
    echo "[!] no password in $SERVICE_JSON" >&2
    exit 1
fi

AUTH="Authorization: Basic $(printf 'opencode:%s' "$PASSWORD" | base64 -w0)"

# find the daemon: the process running "opencode serve"
SERVE_PID="$(pgrep -f 'opencode serve' | head -1)"
if [ -z "$SERVE_PID" ]; then
    echo "[!] no 'opencode serve' daemon found" >&2
    exit 1
fi

PORT="$(ss -ltnp 2>/dev/null | grep "pid=$SERVE_PID," | grep -oE "127\.0\.0\.1:[0-9]+" | head -1 | cut -d: -f2)"
if [ -z "$PORT" ]; then
    PORT="$(ss -ltnp 2>/dev/null | grep -oE "127\.0\.0\.1:[0-9]+" | head -1 | cut -d: -f2)"
fi
if [ -z "$PORT" ]; then
    echo "[!] could not determine the daemon port" >&2
    exit 1
fi
BASE="http://127.0.0.1:$PORT"

# which servers are configured?
SERVERS="$*"
if [ -z "$SERVERS" ]; then
    SERVERS="$(curl -s -H "$AUTH" "$BASE/api/mcp" \
        | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
for s in d.get("data",[]) or []:
    print(s.get("name",""))' 2>/dev/null)"
fi

if [ -z "$SERVERS" ]; then
    echo "[!] no MCP servers to reconnect" >&2
    exit 1
fi

rc=0
for name in $SERVERS; do
    echo "[*] reconnecting '$name' via $BASE ..."
    code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" \
            "$BASE/api/experimental/mcp/$name/connect")"
    if [ "$code" = "204" ] || [ "$code" = "200" ]; then
        echo "[+] '$name' reconnect requested (HTTP $code)"
    else
        echo "[!] '$name' reconnect failed (HTTP $code)" >&2
        rc=1
    fi
done

sleep 2
echo
echo "== status =="
curl -s -H "$AUTH" "$BASE/api/mcp" > "${TMPDIR:-/tmp}/cs-mcp-4.9/.mcp-status.json" 2>/dev/null
python3 - <<'PY'
import json
try:
    with open(os.environ.get("TMPDIR", "/tmp") + "/cs-mcp-4.9/.mcp-status.json") as fh:
        d = json.load(fh)
except Exception as exc:
    print("  could not read the status:", exc)
    raise SystemExit(0)
for s in d.get("data", []) or []:
    st = s.get("status", {}) or {}
    name = s.get("name", "")
    print(f"  {name:16} {st.get('status', '?'):10} tools={len(s.get('tools', []) or [])}")
    if st.get("error"):
        print("      error:", str(st["error"])[:300])
PY
exit $rc
