#!/usr/bin/env python3
"""Determine WHY the cs-mcp-4.9 server process exits under opencode.

The opencode log shows:

    mcp connected  server=cobalt-strike tools=26
    ... 34 minutes of normal traffic ...
    mcp transport error  MCP server process exited

with NO traceback in the captured stderr.  A clean exit means the MCP
SDK's stdio loop hit EOF on stdin, i.e. the CLIENT closed the pipe.

This harness reproduces the opencode side exactly: same command, same
environment, same request sequence (initialize, tools/list,
resources/list, resources/templates/list), and then it just SITS THERE
with stdin held open.  If the server exits on its own, the bug is
server side.  If it stays alive, opencode is the one closing it.

    python3 tools/mcp_lifetime.py --idle 420
"""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server" / "cs_mcp_server.py"

ENV = {
    "PYTHONPATH": str(ROOT / "server"),
    "CS_MCP_DIR": "/tmp/cs-mcp-4.9",
    "CS_MCP_STATE_DIR": str(Path.home() / ".cs-mcp-4.9"),
    "CS_MCP_CORPUS": str(Path.home()/"Abofs"),
    "CS_TS_LOG_DIR": str(Path.home()/"cobaltstrike"/"cobaltstrike"/"Server"/"logs"),
    "CS_MCP_EDR_KIT": str(Path.home()/"Abofs"/"CS-EDR-Enumeration"/"edr-enum.cna"),
    "CS_MCP_POSTFLIGHT_SECONDS": "25",
}


def send(proc: subprocess.Popen, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8") + b"\n"
    proc.stdin.write(body)
    proc.stdin.flush()


def read_reply(proc: subprocess.Popen, timeout: float) -> dict | None:
    """Read one JSON-RPC message from stdout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--idle", type=int, default=420, help="seconds to idle with stdin open")
    ap.add_argument("--stderr", default=str(Path(tempfile.gettempdir())/"cs-mcp-4.9"/"mcp_lifetime.stderr"))
    args = ap.parse_args()

    env = dict(os.environ)
    env.update(ENV)

    errf = open(args.stderr, "wb")
    proc = subprocess.Popen(
        ["/usr/bin/python3", str(SERVER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=errf,
        env=env,
        bufsize=0,
    )
    print(f"[*] spawned pid {proc.pid}, stderr -> {args.stderr}")

    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "lifetime-probe", "version": "1.0"},
        },
    }
    send(proc, init)
    reply = read_reply(proc, 30)
    if not reply:
        print("[FAIL] no initialize reply")
        return 1
    print("[*] initialize ok")

    send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    for rid, method in (
        (2, "tools/list"),
        (3, "resources/list"),
        (4, "resources/templates/list"),
        (5, "prompts/list"),
    ):
        send(proc, {"jsonrpc": "2.0", "id": rid, "method": method, "params": {}})
        r = read_reply(proc, 60)
        if r is None:
            print(f"[!] no reply to {method}")
            break
        if "error" in r:
            print(f"[!] {method} -> error {r['error']}")
        else:
            result = r.get("result", {})
            n = len(result.get("tools", result.get("resources", result.get("prompts", []))))
            print(f"[*] {method} ok ({n} items)")

    print(f"[*] idling {args.idle}s with stdin held open ...")
    t0 = time.time()
    while time.time() - t0 < args.idle:
        if proc.poll() is not None:
            print(f"[!] SERVER EXITED on its own after {time.time() - t0:.1f}s "
                  f"(returncode={proc.returncode})")
            errf.flush()
            print("--- stderr tail ---")
            print(Path(args.stderr).read_text(errors="replace")[-3000:])
            return 2
        time.sleep(2)

    print(f"[*] still alive after {args.idle}s (returncode={proc.poll()})")
    print("[*] closing stdin (simulating the client going away) ...")
    proc.stdin.close()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        print("[!] did NOT exit after stdin close")
        proc.kill()
        return 3
    print(f"[*] exited cleanly after stdin close, returncode={proc.returncode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
