#!/usr/bin/env python3
"""Verify the cs-mcp-4.9 server really speaks MCP over stdio.

Starts the server as a subprocess, performs the MCP handshake, lists the
tools and calls one harmless read-only tool.  This is the check that
catches a server that starts but dies on the first request - which is
exactly what an "error" in the MCP client looks like.

    python3 tools/mcp_probe.py
    python3 tools/mcp_probe.py --call cs_status
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server" / "cs_mcp_server.py"

sys.path.insert(0, str(ROOT / "server"))

ENV = {
    "PYTHONPATH": str(ROOT / "server"),
    "CS_MCP_DIR": os.environ.get("CS_MCP_DIR", "/tmp/cs-mcp-4.9"),
    "CS_MCP_STATE_DIR": os.environ.get("CS_MCP_STATE_DIR", str(Path.home() / ".cs-mcp-4.9")),
    "CS_MCP_CORPUS": os.environ.get("CS_MCP_CORPUS", os.path.expanduser("~/Abofs")),
    "CS_TS_LOG_DIR": os.environ.get(
        "CS_TS_LOG_DIR", os.path.expanduser("~/cobaltstrike/cobaltstrike/Server/logs")
    ),
    "CS_MCP_EDR_KIT": os.environ.get(
        "CS_MCP_EDR_KIT", os.path.expanduser("~/Abofs/CS-EDR-Enumeration/edr-enum.cna")
    ),
    "CS_MCP_POSTFLIGHT_SECONDS": os.environ.get("CS_MCP_POSTFLIGHT_SECONDS", "25"),
}


async def probe(call: str) -> int:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = dict(os.environ)
    env.update(ENV)

    params = StdioServerParameters(command="/usr/bin/python3", args=[str(SERVER)], env=env)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(f"[*] handshake ok: {init.serverInfo.name} v{init.serverInfo.version}")

            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"[*] {len(names)} tools registered")
            for n in names:
                print(f"      {n}")

            if call:
                tool = next((t for t in tools.tools if t.name == call), None)
                if tool is None:
                    print(f"[FAIL] tool '{call}' not found")
                    return 1
                args = {}
                for p in (tool.inputSchema.get("properties") or {}):
                    if p == "bid":
                        args[p] = "12345"
                result = await session.call_tool(call, args)
                text = "\n".join(
                    c.text for c in result.content if getattr(c, "type", "") == "text"
                )
                print(f"\n[*] call {call} -> isError={result.isError}")
                print(text[:3000])
                if result.isError:
                    return 1

    print("\nMCP PROBE PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--call", default="cs_status", help="tool to call after the handshake")
    args = ap.parse_args()
    try:
        return asyncio.run(probe(args.call))
    except Exception as exc:  # noqa: BLE001
        print(f"MCP PROBE FAIL: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
