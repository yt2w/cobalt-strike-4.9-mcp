#!/usr/bin/env python3
"""
End-to-end self-test for the cs-mcp-4.9 stack.

    python3 tools/selftest.py            run the full check
    python3 tools/selftest.py --quick    only the transport check

Checks, in order:
  1. spool dirs exist and are writable
  2. the agent answers a ping (is cs_agent.cna loaded in the CS client?)
  3. the agent reports a transport mode and a heartbeat
  4. sessions can be listed
  5. the python policy layer refuses the built-ins that kill beacons
  6. the BOF inventory builds and classifies
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "server"))

from csagent import AgentClient, AgentError  # noqa: E402
from policy import check_raw_command  # noqa: E402
from registry import Registry  # noqa: E402

PASS, FAIL = "  [PASS]", "  [FAIL]"
failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    if ok:
        print(f"{PASS} {label}" + (f" - {detail}" if detail else ""))
    else:
        failures += 1
        print(f"{FAIL} {label}" + (f" - {detail}" if detail else ""))


def main() -> int:
    quick = "--quick" in sys.argv
    agent = AgentClient()

    print("== transport ==")
    agent.ensure_dirs()
    check("spool dirs present", agent.inbox.is_dir() and agent.outbox.is_dir(), str(agent.base))

    token_file = agent.base / "agent.token"
    check("agent token present", token_file.exists(), str(token_file))

    try:
        resp = agent.call("ping", timeout=10)
        check("agent answers ping", resp.ok, f"version={resp.get('agent_version')}")
    except AgentError as exc:
        check("agent answers ping", False, str(exc))
        print()
        print("The CS-side agent is not answering. Load it in Cobalt Strike:")
        print("  Script Manager -> Load -> agent/cs_agent.cna")
        return 1
    except Exception as exc:  # noqa: BLE001
        check("agent answers ping", False, f"{type(exc).__name__}: {exc}")
        return 1

    if quick:
        return 0 if failures == 0 else 1

    print()
    print("== agent state ==")
    st = agent.agent_status()
    check("status file written", bool(st), ", ".join(f"{k}={v}" for k, v in list(st.items())[:6]))
    check("transport mode known", st.get("mode", "") in ("fork", "event"), st.get("mode", "?"))
    check("agent selftest passed", st.get("selftest") == "pass", st.get("selftest", "no selftest record"))
    #  the heartbeat file carries its timestamp under the key "time"
    hb = st.get("time", "") or st.get("heartbeat", "")
    if hb.isdigit():
        age = (time.time() * 1000 - int(hb)) / 1000
        check("heartbeat fresh", age < 60, f"{age:.1f}s old")
    else:
        check("heartbeat fresh", False, "no heartbeat timestamp")

    print()
    print("== sessions ==")
    try:
        resp = agent.call("beacons")
        check("list beacons", resp.ok, f"{resp.get('count', '?')} sessions")
        if resp.ok and resp.rows:
            first = resp.rows[0]
            check("beacon fields present", len(first) >= 10, f"id={first[0]} user={first[6] if len(first) > 6 else '?'}")
    except Exception as exc:  # noqa: BLE001
        check("list beacons", False, str(exc))

    print()
    print("== policy ==")
    d = check_raw_command("shell whoami")
    check("blocks 'shell'", not d.allowed, d.reason[:60])
    d = check_raw_command("powershell Get-Process")
    check("blocks 'powershell'", not d.allowed, d.reason[:60])
    d = check_raw_command("upload /tmp/x")
    check("blocks 'upload'", not d.allowed, d.reason[:60])
    d = check_raw_command("edr_check")
    check("allows unknown plugin command", d.allowed and d.requires_ack, d.reason[:60])
    d = check_raw_command("ps")
    check("allows in-beacon 'ps'", d.allowed and not d.requires_ack, d.reason[:60])

    print()
    print("== inventory ==")
    reg = Registry()
    t0 = time.time()
    bofs = reg.build_inventory()
    dt = time.time() - t0
    check("BOF inventory built", len(bofs) > 0, f"{len(bofs)} objects in {dt:.1f}s")
    bands: dict[str, int] = {}
    for b in bofs:
        bands[str(b.get("risk"))] = bands.get(str(b.get("risk")), 0) + 1
    check("risk bands assigned", any(k != "unknown" for k in bands), json.dumps(bands))
    kits = reg.build_kits()
    check("kit inventory built", len(kits) > 0, f"{len(kits)} .cna kits")

    print()
    if failures:
        print(f"RESULT: {failures} check(s) failed")
        return 1
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
