#!/usr/bin/env bash
# patch_client_jar.sh - make the cs-mcp-4.9 agent load automatically every time
# the Cobalt Strike client starts.
#
# Cobalt Strike runs scripts/default.cna at startup.  This script adds a
# single line to that file:
#
#     include("<repo>/agent/cs_agent.cna");
#
# so the spool agent is always present and the operator never has to use
# the Script Manager again.
#
#   ./patch_client_jar.sh              patch the jar (backs it up first)
#   ./patch_client_jar.sh --check      report whether it is patched
#   ./patch_client_jar.sh --revert     restore from the backup
#   ./patch_client_jar.sh --jar PATH   use a different jar
#
# The patch only takes effect on the NEXT client start.  The running
# client is not disturbed: it has already read default.cna into memory.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

CLIENT_DIR="${CS_CLIENT_DIR:-$HOME/cobaltstrike/cobaltstrike/Client}"
AGENT="${CS_MCP_AGENT:-$ROOT/agent/cs_agent.cna}"
JAR=""
MODE="patch"

MARK_BEGIN="# >>> cs-mcp-4.9 agent autoload >>>"
MARK_END="# <<< cs-mcp-4.9 agent autoload <<<"

usage() {
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --jar) JAR="$2"; shift 2 ;;
        --agent) AGENT="$2"; shift 2 ;;
        --check) MODE="check"; shift ;;
        --revert) MODE="revert"; shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

# ---------------------------------------------------------------------------
# locate the jar
# ---------------------------------------------------------------------------
if [ -z "$JAR" ]; then
    # prefer the jar the running client actually uses
    running="$(ps -eo args 2>/dev/null | grep -oE '[A-Za-z0-9._-]+\.jar' | grep -i cobaltstrike | head -1 || true)"
    if [ -n "$running" ] && [ -f "$CLIENT_DIR/$running" ]; then
        JAR="$CLIENT_DIR/$running"
    elif [ -f "$CLIENT_DIR/cobaltstrike-client*.jar" ]; then
        JAR="$CLIENT_DIR/cobaltstrike-client*.jar"
    elif [ -f "$CLIENT_DIR/cobaltstrike-client.jar" ]; then
        JAR="$CLIENT_DIR/cobaltstrike-client.jar"
    else
        echo "[!] no Cobalt Strike client jar found in $CLIENT_DIR" >&2
        exit 1
    fi
fi

if [ ! -f "$JAR" ]; then
    echo "[!] jar not found: $JAR" >&2
    exit 1
fi

BACKUP="$JAR.pre-cs-mcp-4.9.bak"

is_patched() {
    unzip -p "$JAR" scripts/default.cna 2>/dev/null | grep -qF "$MARK_BEGIN"
}

case "$MODE" in
check)
    if is_patched; then
        echo "[+] PATCHED   $JAR"
        unzip -p "$JAR" scripts/default.cna 2>/dev/null | grep -F "include(" | sed 's/^/      /'
    else
        echo "[-] NOT PATCHED   $JAR"
    fi
    exit 0
    ;;

revert)
    if [ ! -f "$BACKUP" ]; then
        echo "[!] no backup at $BACKUP" >&2
        exit 1
    fi
    cp -p "$BACKUP" "$JAR"
    echo "[+] restored $JAR from $BACKUP"
    exit 0
    ;;
esac

if is_patched; then
    echo "[+] already patched: $JAR"
    exit 0
fi

if [ ! -f "$AGENT" ]; then
    echo "[!] agent not found: $AGENT" >&2
    exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/cs-mcp-4.9/jarpatch.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

echo "[+] jar   : $JAR"
echo "[+] agent : $AGENT"

# ---------------------------------------------------------------------------
# extract and patch scripts/default.cna
# ---------------------------------------------------------------------------
mkdir -p "$TMP/work"
if ! unzip -o -q "$JAR" scripts/default.cna -d "$TMP/work"; then
    echo "[!] scripts/default.cna is not in the jar" >&2
    exit 1
fi

CNA="$TMP/work/scripts/default.cna"
cp -p "$CNA" "$TMP/default.cna.orig"

python3 - "$CNA" "$AGENT" "$MARK_BEGIN" "$MARK_END" <<'PY'
import re
import sys

path, agent, begin, end = sys.argv[1:5]
with open(path, "r", encoding="utf-8", errors="replace") as fh:
    src = fh.read()

block = (
    f'\t{begin}\n'
    f'\t# auto load the cs-mcp-4.9 spool agent so it survives client restarts\n'
    f'\tinclude("{agent}");\n'
    f'\t{end}\n'
)

# insert into the existing "on ready" handler
m = re.search(r"^on\s+ready\s*\{", src, re.M)
if m:
    src = src[: m.end()] + "\n" + block + src[m.end():]
else:
    src = src.rstrip() + "\n\non ready {\n" + block + "}\n"

with open(path, "w", encoding="utf-8") as fh:
    fh.write(src)
print(f"[+] patched scripts/default.cna (inserted at offset {m.end() if m else 'EOF'})")
PY

echo "[+] patched default.cna:"
sed -n "/$(echo "$MARK_BEGIN" | sed 's/\//\\\//g')/,/$(echo "$MARK_END" | sed 's/\//\\\//g')/p" "$CNA" | sed 's/^/      /'

# ---------------------------------------------------------------------------
# rebuild the jar
# ---------------------------------------------------------------------------
# The rebuilt jar is staged NEXT TO the original so that the final move
# is an atomic rename on the same filesystem.  The running client keeps
# its open file descriptor on the old inode, so replacing the jar cannot
# corrupt the instance that is already up.
TMPJAR="$JAR.new.$$"
cp -p "$JAR" "$TMPJAR"

# zip -X updates a single entry and leaves every other entry byte for byte
# alone.  jar uf would rewrite the manifest.
( cd "$TMP/work" && zip -X -q "$TMPJAR" scripts/default.cna )

echo "[+] validating the rebuilt jar ..."
if ! unzip -t -q "$TMPJAR" >/dev/null 2>&1; then
    echo "[!] the rebuilt jar is corrupt - the original has NOT been touched" >&2
    rm -f "$TMPJAR"
    exit 1
fi

# the entry must still be there and must contain the include
if ! unzip -p "$TMPJAR" scripts/default.cna 2>/dev/null | grep -qF "include(\"$AGENT\")"; then
    echo "[!] the rebuilt jar does not contain the include line" >&2
    rm -f "$TMPJAR"
    exit 1
fi

# the rest of the archive must be untouched
before="$(unzip -l "$JAR" | tail -1 | awk '{print $2}')"
after="$(unzip -l "$TMPJAR" | tail -1 | awk '{print $2}')"
echo "[+] archive size: $before -> $after"

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
if [ ! -f "$BACKUP" ]; then
    cp -p "$JAR" "$BACKUP"
    echo "[+] backup: $BACKUP"
fi

chmod --reference="$JAR" "$TMPJAR" 2>/dev/null || chmod 644 "$TMPJAR"
chown --reference="$JAR" "$TMPJAR" 2>/dev/null || true

mv -f "$TMPJAR" "$JAR"
echo "[+] installed: $JAR"

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
if is_patched; then
    echo "[+] verified: the jar is patched"
else
    echo "[!] the jar does not look patched after the install" >&2
    exit 1
fi

cat <<EOF

Next client start will load the agent automatically.  The change does not
affect the client that is running right now.

  client dir : $(dirname "$JAR")
  agent      : $AGENT

Check the console on the next start for:

  [cs-agent] cs-mcp-4.9 agent 4.9 READY (fork pump)

Revert with:

  $0 --revert
EOF
