#!/usr/bin/env bash
# cs-mcp-4.9 installer: spool dirs + MCP client registration.
#
#   ./install.sh              install and register with opencode
#   ./install.sh --no-register  only prepare the spool
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPOOL="${CS_MCP_DIR:-/tmp/cs-mcp-4.9}"
STATE="${CS_MCP_STATE_DIR:-$HOME/.cs-mcp-4.9}"
CORPUS="${CS_MCP_CORPUS:-$HOME/Abofs}"
OC_CONFIG="${OPENCODE_CONFIG:-$HOME/.config/opencode/opencode.json}"

echo "[+] spool dir     : $SPOOL"
echo "[+] state dir     : $STATE"
echo "[+] corpus        : $CORPUS"

mkdir -p "$SPOOL/inbox" "$SPOOL/outbox" "$STATE"
chmod 0770 "$SPOOL" "$SPOOL/inbox" "$SPOOL/outbox" 2>/dev/null || true
chmod 0700 "$STATE" 2>/dev/null || true

# the agent writes its token here on first load; make it readable by the operator
if [ ! -f "$SPOOL/agent.token" ]; then
  python3 - "$SPOOL" <<'PY'
import sys, uuid, os
spool = sys.argv[1]
tok = uuid.uuid4().hex + uuid.uuid4().hex
p = os.path.join(spool, "agent.token")
with open(p, "w") as fh:
    fh.write(tok)
os.chmod(p, 0o644)
print("[+] pre-seeded agent token")
PY
fi

# keep the python side importable regardless of cwd
if [ ! -e "$HERE/server/mcp.pth" ]; then
  :
fi

if [ "${1:-}" = "--no-register" ]; then
  echo "[+] done (registration skipped)"
  exit 0
fi

python3 - "$OC_CONFIG" "$HERE" <<'PY'
import json, os, sys

cfg_path, here = sys.argv[1], sys.argv[2]
cfg = {}
if os.path.exists(cfg_path):
    with open(cfg_path, encoding="utf-8") as fh:
        cfg = json.load(fh)

mcp = cfg.setdefault("mcp", {})
# drop the previous bridge (it needed a socket listener inside the CS client)
for dead in ("cobalt-strike", "cobalt-strike-legacy"):
    mcp.pop(dead, None)

mcp["cobalt-strike"] = {
    "type": "local",
    "command": ["/usr/bin/python3", os.path.join(here, "server", "cs_mcp_server.py")],
    "environment": {
        "CS_MCP_DIR": os.environ.get("CS_MCP_DIR", "/tmp/cs-mcp-4.9"),
        "CS_MCP_STATE_DIR": os.environ.get("CS_MCP_STATE_DIR", os.path.expanduser("~/.cs-mcp-4.9")),
        "CS_MCP_CORPUS": os.environ.get("CS_MCP_CORPUS", os.path.expanduser("~/Abofs")),
        "CS_TS_LOG_DIR": os.environ.get(
            "CS_TS_LOG_DIR", os.environ.get(
                "CS_TS_LOG_DIR", os.path.expanduser("~/cobaltstrike/cobaltstrike/Server/logs")
            )
        ),
        "CS_MCP_EDR_KIT": os.environ.get(
            "CS_MCP_EDR_KIT", os.environ.get(
                "CS_MCP_EDR_KIT", os.path.expanduser("~/Abofs/CS-EDR-Enumeration/edr-enum.cna")
            )
        ),
        "CS_MCP_POSTFLIGHT_SECONDS": os.environ.get("CS_MCP_POSTFLIGHT_SECONDS", "25"),
        "PYTHONPATH": os.path.join(here, "server"),
    },
    "enabled": True,
}

tmp = cfg_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
os.replace(tmp, cfg_path)
print(f"[+] registered 'cobalt-strike' MCP in {cfg_path}")
PY

cat <<EOF

[+] Next: load the agent into the Cobalt Strike client.

    Cobalt Strike -> Script Manager -> Load -> $HERE/agent/cs_agent.cna

    It prints its spool dir + token and writes $SPOOL/agent.status.
    Verify with:

    python3 $HERE/tools/selftest.py

[+] Or make it load by itself on every client start:

    $HERE/tools/patch_client_jar.sh

    (it patches scripts/default.cna inside the client jar, backs the jar
     up first, and can be reverted with --revert)

[+] Offline checks, no client and no beacon needed:

    python3 $HERE/tools/dryrun.py       # the Sleep agent, in isolation
    python3 $HERE/tools/testsuite.py    # the whole python stack
    python3 $HERE/tools/mcp_probe.py    # real MCP handshake
EOF
