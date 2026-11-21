#!/usr/bin/env python3
"""Wait for the next Cobalt Strike session to appear.

Read-only: it asks the Aggressor agent for the live session table, which
is a CLIENT side call.  No task is ever sent to a beacon, so nothing
shows up in the target's telemetry.

    python3 tools/watch_beacons.py                  # wait forever
    python3 tools/watch_beacons.py --timeout 3600   # give up after an hour
    python3 tools/watch_beacons.py --once           # single check

It writes every new session to /tmp/cs-mcp-4.9/watch.log and drops a JSON
file per new session in /tmp/cs-mcp-4.9/new_sessions/.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))

from csagent import AgentClient, AgentError  # noqa: E402

SPOOL = Path(os.environ.get("CS_MCP_DIR", "/tmp/cs-mcp-4.9"))
LOG = SPOOL / "watch.log"
OUT = SPOOL / "new_sessions"


def log(msg: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {msg}"
    print(line, flush=True)
    try:
        SPOOL.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=0, help="seconds to wait (0 = forever)")
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    client = AgentClient()
    client.ensure_dirs()

    seen: set[str] = set()
    first = True
    t0 = time.time()

    log("watching for sessions (read only, nothing is tasked) ...")

    while True:
        try:
            resp = client.call("beacons", timeout=20)
            rows = resp.rows if resp.ok else []
        except AgentError as exc:
            log(f"agent not reachable: {exc}")
            rows = []

        ids = []
        for row in rows:
            bid = row[0] if row else ""
            if not bid:
                continue
            ids.append(bid)
            if bid not in seen:
                seen.add(bid)
                rec = {
                    "bid": bid,
                    "note": row[1] if len(row) > 1 else "",
                    "computer": row[4] if len(row) > 4 else "",
                    "user": row[5] if len(row) > 5 else "",
                    "os": row[6] if len(row) > 6 else "",
                    "arch": row[7] if len(row) > 7 else "",
                    "pid": row[8] if len(row) > 8 else "",
                    "process": row[9] if len(row) > 9 else "",
                    "last": row[10] if len(row) > 10 else "",
                    "sleep": row[11] if len(row) > 11 else "",
                    "is_admin": row[12] if len(row) > 12 else "",
                    "seen_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                try:
                    (OUT / f"{bid}.json").write_text(json.dumps(rec, indent=2))
                except OSError:
                    pass
                log(f"NEW SESSION bid={bid} {rec['process']} {rec['user']} "
                    f"{rec['computer']} ({rec['os']} {rec['arch']})")

        if first:
            log(f"current sessions: {len(ids)} {ids}")
            first = False

        if args.once:
            return 0

        elapsed = time.time() - t0
        if args.timeout and elapsed > args.timeout:
            log(f"timed out after {elapsed:.0f}s with sessions {ids}")
            return 1

        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
