#!/usr/bin/env python3
"""
cs-mcp-4.9: a Cobalt Strike 4.9 MCP server built around CUSTOM plugins and
CUSTOM BOFs.

Why not the built-ins
---------------------
`shell`, `powershell`, `execute-assembly`, `upload`, `download`,
`screenshot` and `portscan` create exactly the child-process and
file-write telemetry that endpoint security is tuned to catch.  On an
engagement where the beacon is the only foothold, they are how sessions
die.  This server therefore refuses them by default (in two independent
layers: here, and inside cs_agent.cna in the client) and drives the
beacon through the operator's own .cna plugins and .o BOFs instead.

What it adds over a dumb tasking bridge
---------------------------------------
  * a static risk classification for every BOF in the corpus
  * a quarantine list and a live "this killed a beacon" learning loop
  * beacon output capture, so results come back instead of scrolling by
  * a full audit trail for the engagement debrief

Transport: cs_agent.cna (in the CS client) over a spool directory.
"""

#  NOTE: do NOT add "from __future__ import annotations" to this file.
#  FastMCP 1.12 inspects the raw annotations of every @mcp.tool() function
#  and calls issubclass(param.annotation, Context).  With PEP 563 the
#  annotations are STRINGS, so issubclass() raises
#  "TypeError: issubclass() arg 1 must be a class" and the server dies
#  at import time.  Python 3.10+ understands the X | Y syntax natively,
#  so the future import is not needed.

import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

#  The MCP SDK logs one INFO line per request ("Processing request of
#  type ...") to stderr.  opencode captures the child's stderr and
#  REPLAYS IT VERBATIM in the MCP error badge, so an idle-but-healthy
#  server that later dies shows up as a wall of scary-looking log lines
#  instead of the real cause.  Keep stderr for real problems only.
logging.getLogger("mcp").setLevel(logging.WARNING)
logging.getLogger("mcp.server").setLevel(logging.WARNING)
logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.WARNING)
logging.getLogger("mcp.server.session").setLevel(logging.WARNING)
logging.getLogger("mcp.client").setLevel(logging.WARNING)

from mcp.server.fastmcp import FastMCP

from csagent import AgentClient, AgentError
from edr import (
    EDRSpecDB,
    TargetProfiles,
    detect_vendors,
    parse_edr_enum_output,
)
from policy import (
    ALLOWED_BUILTINS,
    DENIED_BUILTINS,
    Decision,
    check_raw_command,
    evaluate_bof,
    parse_noise,
    policy_summary,
)
from registry import Registry
from tslog import TSLogReader

STATE_DIR = Path(os.environ.get("CS_MCP_STATE_DIR", Path.home() / ".cs-mcp-4.9"))
AUDIT_PATH = STATE_DIR / "audit.log"
ALLOW_DENIED = os.environ.get("CS_MCP_ALLOW_DENIED", "0") in ("1", "true", "yes")
POSTFLIGHT_SECONDS = float(os.environ.get("CS_MCP_POSTFLIGHT_SECONDS", "25"))
EDR_KIT_PATH = os.environ.get(
    "CS_MCP_EDR_KIT", os.path.expanduser("~/Abofs/CS-EDR-Enumeration/edr-enum.cna")
)

mcp = FastMCP("cobalt-strike")
agent = AgentClient()
registry = Registry()
tslog_reader = TSLogReader()
targets = TargetProfiles()
_edr_db = EDRSpecDB(EDR_KIT_PATH)
_seen_sessions: set[str] = set()


# ---------------------------------------------------------------------------
# audit trail
# ---------------------------------------------------------------------------
def audit(tool: str, outcome: str, detail: dict[str, Any] | None = None) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        rec = {
            "ts": int(time.time() * 1000),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tool": tool,
            "outcome": outcome,
            "detail": detail or {},
        }
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def _err(msg: str) -> str:
    return json.dumps({"ok": False, "error": msg}, indent=2)


def _agent_error(exc: Exception) -> str:
    return _err(f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
BEACON_FIELDS = [
    "id", "note", "internal", "external", "computer", "user",
    "os", "arch", "pid", "process", "last", "sleep", "is_admin",
]


def _beacon_rows() -> list[dict[str, Any]]:
    resp = agent.call("beacons")
    if not resp.ok:
        raise AgentError(resp.message or "beacons failed")
    out: list[dict[str, Any]] = []
    for row in resp.rows:
        rec = {BEACON_FIELDS[i]: row[i] for i in range(min(len(row), len(BEACON_FIELDS)))}
        out.append(rec)
    return out


def _session_alive(bid: str) -> bool:
    try:
        return any(str(b.get("id")) == str(bid) for b in _beacon_rows())
    except Exception:
        return False


def _risk_for(path: str, target_edr: list[str] | None = None, force: bool = False) -> tuple[dict[str, Any] | None, Decision]:
    entry = registry.bof_by_path(path)
    if entry is None:
        return None, Decision(False, f"BOF not found in inventory: {path}", risk="unknown", blocked_by="not-found")
    decision = evaluate_bof(
        entry,
        quarantined=registry.is_quarantined(path),
        quarantine_reason=registry.quarantine_reason(path),
        observed_kills=registry.kill_count(path),
        target_edr=target_edr or [],
        force=force,
    )
    return entry, decision


def _postflight_watch(bid: str, bof_path: str, started: float) -> None:
    """After a BOF run, check whether the beacon survived.  If it did not,
    the BOF is quarantined so the next operator never repeats the mistake."""

    def worker() -> None:
        time.sleep(POSTFLIGHT_SECONDS)
        try:
            alive = _session_alive(bid)
        except Exception:
            return
        if alive:
            audit("postflight", "alive", {"bid": bid, "bof": bof_path})
            return
        count = registry.record_kill(bof_path, f"beacon {bid} died within {POSTFLIGHT_SECONDS}s of the run")
        audit("postflight", "beacon-death", {"bid": bid, "bof": bof_path, "kills": count})

    threading.Thread(target=worker, daemon=True).start()


# ---------------------------------------------------------------------------
# awareness
# ---------------------------------------------------------------------------
@mcp.tool()
def cs_status() -> str:
    """Health of the Cobalt Strike link: agent version, transport mode, session and
    listener counts.  Call this first - if the agent is not loaded it says so."""
    try:
        st = agent.agent_status()
        resp = agent.call("status")
        payload = {
            "ok": resp.ok,
            "agent": st,
            "beacons": resp.get("beacons", "0"),
            "listeners": resp.get("listeners", "0"),
            "mode": resp.get("mode", st.get("mode", "unknown")),
            "spool_dir": str(agent.base),
            "audit_log": str(AUDIT_PATH),
        }
        audit("cs_status", "ok")
        return json.dumps(payload, indent=2)
    except Exception as exc:
        audit("cs_status", "error", {"error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def list_beacons() -> str:
    """List every live Cobalt Strike session (beacon) with identity, host, and timing."""
    try:
        rows = _beacon_rows()
        audit("list_beacons", "ok", {"count": len(rows)})
        return json.dumps({"ok": True, "count": len(rows), "beacons": rows}, indent=2)
    except Exception as exc:
        audit("list_beacons", "error", {"error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def get_beacon(bid: str) -> str:
    """Full metadata for one session id."""
    try:
        resp = agent.call("beacon_info", {"bid": str(bid)})
        if not resp.ok:
            return _err(resp.message)
        audit("get_beacon", "ok", {"bid": bid})
        return json.dumps({"ok": True, "beacon": resp.data}, indent=2)
    except Exception as exc:
        audit("get_beacon", "error", {"bid": bid, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def list_hosts() -> str:
    """Hosts Cobalt Strike knows about, with address and OS."""
    try:
        resp = agent.call("hosts")
        if not resp.ok:
            return _err(resp.message)
        hosts = [{"host": r[0], "address": r[1] if len(r) > 1 else "", "os": r[2] if len(r) > 2 else ""} for r in resp.rows]
        audit("list_hosts", "ok", {"count": len(hosts)})
        return json.dumps({"ok": True, "count": len(hosts), "hosts": hosts}, indent=2)
    except Exception as exc:
        audit("list_hosts", "error", {"error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def list_listeners() -> str:
    """Configured Cobalt Strike listeners."""
    try:
        resp = agent.call("listeners")
        if not resp.ok:
            return _err(resp.message)
        out = []
        for row in resp.rows:
            rec = {"name": row[0] if row else "", "settings": {}}
            for field in row[1:]:
                if "=" in field:
                    k, _, v = field.partition("=")
                    rec["settings"][k] = v
            out.append(rec)
        audit("list_listeners", "ok", {"count": len(out)})
        return json.dumps({"ok": True, "count": len(out), "listeners": out}, indent=2)
    except Exception as exc:
        audit("list_listeners", "error", {"error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def recent_events() -> str:
    """Sessions that have appeared since this tool was last called.  Poll it to detect
    new footholds without re-reading the whole list."""
    try:
        rows = _beacon_rows()
        new = [r for r in rows if str(r.get("id")) not in _seen_sessions]
        for r in rows:
            _seen_sessions.add(str(r.get("id")))
        audit("recent_events", "ok", {"new": len(new)})
        return json.dumps({"ok": True, "total": len(rows), "new_sessions": new}, indent=2)
    except Exception as exc:
        audit("recent_events", "error", {"error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def beacon_output(bid: str = "", limit: int = 20, kind: str = "output") -> str:
    """Captured output from beacon commands and BOFs, newest last.

    This is how you read results: the Team Server writes a full transcript
    of every session, so a BOF's output comes back here instead of
    scrolling past in the Cobalt Strike console.

    kind='output' returns only command output.  kind='transcript' returns
    the whole session log (metadata, input, task, output, check-ins).

    Cobalt Strike 4.9 has no 'beacon_output' event, so the transcript on
    the Team Server is the capture channel."""
    try:
        n = max(1, int(limit))
        if bid:
            if kind == "transcript":
                events = tslog_reader.transcript(bid, limit=n)
            else:
                events = tslog_reader.read_output(bid)
                events = events[-n:]
            source = "team-server-log"
        else:
            # no session given: every session the Team Server knows about
            events = []
            for row in tslog_reader.session_map():
                if not row.get("bid"):
                    continue
                events.extend(tslog_reader.read_output(row["bid"])[-n:])
            events = events[-n:]
            source = "team-server-log"
        audit("beacon_output", "ok", {"bid": bid, "kind": kind, "events": len(events)})
        return json.dumps(
            {
                "ok": True,
                "source": source,
                "count": len(events),
                "kind": kind,
                "output": events,
            },
            indent=2,
        )
    except Exception as exc:
        audit("beacon_output", "error", {"error": str(exc)})
        return _agent_error(exc)


# ---------------------------------------------------------------------------
# custom plugin control
# ---------------------------------------------------------------------------
@mcp.tool()
def list_plugin_commands() -> str:
    """Beacon commands registered by the custom .cna plugins currently loaded in
    Cobalt Strike, with their descriptions.  These are the safe, operator-authored
    commands - prefer them over built-ins."""
    try:
        resp = agent.call("plugin_commands")
        if not resp.ok:
            return _err(resp.message)
        cmds = []
        for row in resp.rows:
            name = row[0] if row else ""
            desc = row[1] if len(row) > 1 else ""
            detail = row[2] if len(row) > 2 else ""
            built_in = name.lower() in DENIED_BUILTINS or name.lower() in ALLOWED_BUILTINS
            noise = parse_noise(detail + "\n" + desc)
            cmds.append(
                {
                    "command": name,
                    "description": desc,
                    "usage": detail[:800],
                    "source": "builtin" if built_in else "custom-plugin",
                    "noise_level": noise.get("level", 0),
                    "noise_label": noise.get("label", ""),
                    "noise_stars": "*" * int(noise.get("level", 0)),
                    "noise_note": noise.get("note", ""),
                    "blocked": name.lower() in DENIED_BUILTINS and not ALLOW_DENIED,
                }
            )
        audit("list_plugin_commands", "ok", {"count": len(cmds)})
        return json.dumps({"ok": True, "count": len(cmds), "commands": cmds}, indent=2)
    except Exception as exc:
        audit("list_plugin_commands", "error", {"error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def list_kits(query: str = "", limit: int = 60) -> str:
    """Inventory of custom .cna plugin kits on this machine and the beacon commands
    each one registers.  Use it to find the plugin you need before loading it."""
    try:
        kits = registry.build_kits()
        if query:
            q = query.lower()
            kits = [
                k
                for k in kits
                if q in k["path"].lower()
                or q in k["kit"].lower()
                or any(q in c.lower() for c in k["commands"])
            ]
        kits = sorted(kits, key=lambda k: k["mtime"], reverse=True)[: max(1, int(limit))]
        audit("list_kits", "ok", {"count": len(kits)})
        return json.dumps({"ok": True, "count": len(kits), "kits": kits}, indent=2)
    except Exception as exc:
        audit("list_kits", "error", {"error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def load_plugin(path: str) -> str:
    """Load a custom .cna plugin into the running Cobalt Strike client.

    Only load kits from this machine's own corpus - a plugin runs with full
    Aggressor privileges inside the client."""
    try:
        p = str(path)
        kit = registry.kit_by_path(p)
        if kit is None:
            return _err(
                f"'{p}' is not a known kit in the corpus. Use list_kits to find the right path."
            )
        resp = agent.call("load_script", {"path": p})
        if not resp.ok:
            audit("load_plugin", "error", {"path": p, "error": resp.message})
            return _err(resp.message)
        audit("load_plugin", "ok", {"path": p})
        return json.dumps(
            {"ok": True, "loaded": p, "commands": kit["commands"], "aliases": kit["aliases"]},
            indent=2,
        )
    except Exception as exc:
        audit("load_plugin", "error", {"path": path, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def run_plugin_command(bid: str, command: str, args: str = "", acknowledge_risk: bool = False) -> str:
    """Run a command on a session: a custom .cna plugin command or a safe built-in.

    The client-side agent routes plugin commands through the client's alias
    dispatcher and known built-ins (e.g. blockdlls) through their real
    Aggressor bridge.  It no longer mistakes them for a program to spawn.
    The built-in commands that get beacons killed are refused.  Anything that is
    not a known built-in is treated as a plugin command and must be acknowledged
    once, because the server cannot see what the plugin does on the target."""
    full = f"{command} {args}".strip()
    decision = check_raw_command(full, allow_denied=ALLOW_DENIED)
    if not decision.allowed:
        audit("run_plugin_command", "blocked", {"bid": bid, "command": command, "reason": decision.reason})
        return json.dumps({"ok": False, "blocked": True, "decision": decision.as_dict()}, indent=2)
    if decision.requires_ack and not acknowledge_risk:
        audit("run_plugin_command", "needs-ack", {"bid": bid, "command": command})
        return json.dumps(
            {
                "ok": False,
                "blocked": True,
                "needs_acknowledgement": True,
                "decision": decision.as_dict(),
                "hint": "re-call with acknowledge_risk=true to accept this risk",
            },
            indent=2,
        )
    try:
        resp = agent.call("task", {"bid": str(bid), "cmd": full})
        if not resp.ok:
            audit("run_plugin_command", "error", {"bid": bid, "command": command, "error": resp.message})
            return _err(resp.message)
        audit("run_plugin_command", "ok", {"bid": bid, "command": command, "risk": decision.risk})
        return json.dumps(
            {
                "ok": True,
                "tasked": resp.get("tasked", "1"),
                "bid": str(bid),
                "command": full,
                "risk": decision.risk,
                "note": "output will appear in beacon_output()",
            },
            indent=2,
        )
    except Exception as exc:
        audit("run_plugin_command", "error", {"bid": bid, "command": command, "error": str(exc)})
        return _agent_error(exc)


# ---------------------------------------------------------------------------
# custom BOF control
# ---------------------------------------------------------------------------
@mcp.tool()
def list_bofs(kit: str = "", risk: str = "", query: str = "", limit: int = 50) -> str:
    """Inventory of custom BOFs (compiled .o objects) with their static risk rating.

    Filter by kit, risk band (low/medium/high/critical) or a name query."""
    try:
        entries = registry.build_inventory()
        if kit:
            entries = [e for e in entries if kit.lower() in str(e.get("kit", "")).lower()]
        if risk:
            entries = [e for e in entries if str(e.get("risk", "")).lower() == risk.lower()]
        if query:
            q = query.lower()
            entries = [
                e
                for e in entries
                if q in str(e.get("name", "")).lower()
                or q in str(e.get("path", "")).lower()
                or any(q in str(c).lower() for c in e.get("categories", []))
            ]
        entries = sorted(entries, key=lambda e: (-int(e.get("score", 0)), str(e.get("name", ""))))
        total = len(entries)
        entries = entries[: max(1, int(limit))]
        audit("list_bofs", "ok", {"total": total, "returned": len(entries)})
        return json.dumps({"ok": True, "total": total, "returned": len(entries), "bofs": entries}, indent=2)
    except Exception as exc:
        audit("list_bofs", "error", {"error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def bof_info(path: str) -> str:
    """Full detail and risk assessment for one BOF, including quarantine and
    observed-beacon-death history."""
    try:
        entry, decision = _risk_for(str(path))
        if entry is None:
            return _err(f"BOF not found: {path}")
        audit("bof_info", "ok", {"path": path, "risk": entry.get("risk")})
        return json.dumps(
            {
                "ok": True,
                "bof": entry,
                "decision": decision.as_dict(),
                "quarantined": registry.is_quarantined(str(path)),
                "quarantine_reason": registry.quarantine_reason(str(path)),
                "observed_kills": registry.kill_count(str(path)),
            },
            indent=2,
        )
    except Exception as exc:
        audit("bof_info", "error", {"path": path, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def run_bof(
    bid: str,
    path: str,
    args: str = "",
    fmt: str = "",
    value: str = "",
    acknowledge_risk: bool = False,
    target_edr: str = "",
    force: bool = False,
) -> str:
    """Run a CUSTOM BOF on a session - the primary control path of this server.

    The BOF is statically classified before it runs, and the decision is
    made against what is known to be defending THAT session:

      * medium-and-above risk BOFs need acknowledge_risk=true
      * a BOF that performs injection, evasion, execution, credential or
        privilege work on a host with endpoint security needs an explicit
        acknowledgement as well
      * critical BOFs, and any BOF that has already been observed killing
        a beacon, are refused outright
      * force=true overrides only the EDR interaction block, never a
        quarantine or an observed death

    The session is checked for liveness before and after the run, and a BOF
    that kills the beacon is quarantined automatically.

    target_edr is optional: the profile recorded for the session is used
    automatically.  Pass it to add to what is already known."""
    try:
        p = str(path)
        edr = [e.strip() for e in str(target_edr).split(",") if e.strip()]
        known = targets.vendors(str(bid))
        merged = list(dict.fromkeys(known + edr))
        if edr:
            targets.set(str(bid), vendors=edr, source="operator")

        entry, decision = _risk_for(p, target_edr=merged, force=force)
        if entry is None:
            return _err(f"BOF not found in the inventory: {p}. Use list_bofs to find it.")

        if not decision.allowed:
            audit(
                "run_bof",
                "blocked",
                {"bid": bid, "bof": p, "reason": decision.reason, "by": decision.blocked_by},
            )
            return json.dumps(
                {
                    "ok": False,
                    "blocked": True,
                    "decision": decision.as_dict(),
                    "hint": (
                        "A different, narrower technique is usually the answer. If this one is "
                        "validated against this specific product, re-run with force=true."
                        if decision.blocked_by == "edr-critical"
                        else "Use list_bofs to find a lower risk alternative."
                    ),
                },
                indent=2,
            )

        if decision.requires_ack and not acknowledge_risk:
            audit("run_bof", "needs-ack", {"bid": bid, "bof": p, "risk": decision.risk})
            return json.dumps(
                {
                    "ok": False,
                    "blocked": True,
                    "needs_acknowledgement": True,
                    "decision": decision.as_dict(),
                    "target_edr": merged,
                    "hint": "re-call with acknowledge_risk=true to accept this risk",
                },
                indent=2,
            )

        if not _session_alive(str(bid)):
            audit("run_bof", "error", {"bid": bid, "bof": p, "error": "session not alive"})
            return _err(f"session {bid} is not alive - refusing to task it")

        payload: dict[str, Any] = {"bid": str(bid), "path": p}
        if args:
            payload["arg"] = args
        if fmt and value:
            payload["fmt"] = fmt
            payload["value"] = value

        resp = agent.call("inline_execute", payload)
        if not resp.ok:
            audit("run_bof", "error", {"bid": bid, "bof": p, "error": resp.message})
            return _err(resp.message)

        _postflight_watch(str(bid), p, time.time())
        audit("run_bof", "ok", {"bid": bid, "bof": p, "risk": decision.risk, "edr": merged})
        return json.dumps(
            {
                "ok": True,
                "bof": p,
                "bid": str(bid),
                "risk": decision.risk,
                "decision": decision.as_dict(),
                "target_edr": merged,
                "liveness_check_in_seconds": POSTFLIGHT_SECONDS,
                "note": "output will appear in beacon_output()",
            },
            indent=2,
        )
    except Exception as exc:
        audit("run_bof", "error", {"bid": bid, "bof": path, "error": str(exc)})
        return _agent_error(exc)


# ---------------------------------------------------------------------------
# target awareness - what is defending this host
# ---------------------------------------------------------------------------
@mcp.tool()
def target_profile(bid: str) -> str:
    """What is known about the endpoint security on a session.

    The profile drives the risk decision: a process hollowing BOF is
    ordinary on an undefended host and a beacon kill on a host running
    Falcon or SentinelOne.  It is built from the operator's own
    CS-EDR-Enumeration kit and persisted in ~/.cs-mcp-4.9/targets.json."""
    try:
        prof = targets.get(str(bid))
        prof["edr_signature_db"] = _edr_db.summary()
        audit("target_profile", "ok", {"bid": bid, "vendors": prof.get("vendors", [])})
        return json.dumps({"ok": True, "bid": str(bid), "profile": prof}, indent=2)
    except Exception as exc:
        audit("target_profile", "error", {"bid": bid, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def set_target_edr(bid: str, vendors: str, notes: str = "") -> str:
    """Record the endpoint security products defending a session.

    Use this when you already know what is on the host, or to correct the
    automatic detection.  Vendors are comma separated.  This changes only
    the server's risk decisions - it does not touch the beacon."""
    try:
        names = [v.strip() for v in str(vendors).split(",") if v.strip()]
        if not names:
            return _err("no vendors given")
        prof = targets.set(str(bid), vendors=names, source="operator", notes=notes)
        audit("set_target_edr", "ok", {"bid": bid, "vendors": names})
        return json.dumps({"ok": True, "bid": str(bid), "profile": prof}, indent=2)
    except Exception as exc:
        audit("set_target_edr", "error", {"bid": bid, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def detect_target_edr(bid: str, lookback: int = 400) -> str:
    """Scan a session's existing transcript for endpoint security products.

    READ ONLY - this does not task the beacon.  It reads the Team Server
    log the session already has and looks for known security products
    (198 process, 114 service and 132 driver signatures across 48
    vendors, read straight out of the operator's EDR kit), so a product
    that showed up in an earlier task is not missed."""
    try:
        events = tslog_reader.transcript(str(bid), limit=max(1, int(lookback)))
        blob = "\n".join(
            "\n".join([e.get("body", "")] + list(e.get("lines", []))) for e in events
        )
        hits = detect_vendors(blob)
        parsed = parse_edr_enum_output(blob)
        for h in parsed["hits"]:
            if not any(x["vendor"].lower() == h["vendor"].lower() for x in hits):
                hits.append(
                    {
                        "vendor": h["vendor"],
                        "product": h["product"],
                        "category": h["category"],
                        "matched": h["matched"],
                    }
                )
        if hits:
            targets.set(
                str(bid),
                vendors=sorted({h["vendor"] for h in hits}),
                products=hits,
                source="transcript-scan",
            )
        prof = targets.get(str(bid))
        audit("detect_target_edr", "ok", {"bid": bid, "hits": len(hits)})
        return json.dumps(
            {
                "ok": True,
                "bid": str(bid),
                "detected": hits,
                "count": len(hits),
                "profile": prof,
                "note": "read only - the beacon was not tasked",
            },
            indent=2,
        )
    except Exception as exc:
        audit("detect_target_edr", "error", {"bid": bid, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def enumerate_target_edr(bid: str, mode: str = "check", acknowledge_risk: bool = False) -> str:
    """Ask the TARGET what security software it is running, using the operator's
    CS-EDR-Enumeration kit, and store the answer in the session profile.

    This DOES task the beacon.  Modes and their telemetry cost:
      check          - process list only, in process, no child process, no artifacts
      services_bof   - services and kernel drivers via an in process BOF, no artifacts
      services_cmd   - cmd.exe + 'sc query', one child process
      services_pick  - unmanaged CLR hosting, no powershell.exe process
      full           - powershell + WMI, highest telemetry

    The cheapest mode that answers the question is the right one on a
    defended host: check and services_bof create no artifacts at all."""
    try:
        cmd_map = {
            "check": ("edr_check", 1),
            "services_bof": ("edr_services_bof", 1),
            "services_cmd": ("edr_services_cmd", 3),
            "services_pick": ("edr_services_pick", 2),
            "full": ("edr_enum", 4),
        }
        m = str(mode).lower()
        if m not in cmd_map:
            return _err(f"unknown mode '{mode}'. Use one of: {', '.join(cmd_map)}")
        command, noise = cmd_map[m]

        if noise >= 3 and not acknowledge_risk:
            audit("enumerate_target_edr", "needs-ack", {"bid": bid, "mode": m})
            return json.dumps(
                {
                    "ok": False,
                    "blocked": True,
                    "needs_acknowledgement": True,
                    "noise_level": noise,
                    "hint": (
                        f"'{command}' creates {'*' * noise} telemetry. Prefer mode='check' or "
                        "mode='services_bof', which are artifact free. Re-call with "
                        "acknowledge_risk=true if you really want this one."
                    ),
                },
                indent=2,
            )

        # make sure the kit is loaded, otherwise the command does not exist
        loaded = False
        try:
            resp = agent.call("plugin_commands")
            loaded = any((r[0] if r else "") == command for r in resp.rows)
        except Exception:
            pass
        if not loaded:
            kit = EDR_KIT_PATH
            if not Path(kit).exists():
                return _err(
                    f"EDR kit not found at {kit} and '{command}' is not registered in the client"
                )
            lr = agent.call("load_script", {"path": kit})
            if not lr.ok:
                return _err(f"could not load the EDR kit: {lr.message}")
            audit("enumerate_target_edr", "kit-loaded", {"kit": kit})

        before = len(tslog_reader.read_output(str(bid)))
        tr = agent.call("task", {"bid": str(bid), "cmd": command})
        if not tr.ok:
            audit("enumerate_target_edr", "error", {"bid": bid, "error": tr.message})
            return _err(tr.message)

        # wait for the session to print the result
        deadline = time.time() + 45
        text = ""
        while time.time() < deadline:
            time.sleep(2)
            events = tslog_reader.read_output(str(bid))
            if len(events) > before:
                text = events[-1].get("text", "")
                break
        parsed = parse_edr_enum_output(text)
        hits = parsed["hits"] or detect_vendors(text)
        if hits:
            targets.set(
                str(bid),
                vendors=sorted({h["vendor"] for h in hits}),
                products=hits,
                source=f"edr-enum:{command}",
            )
        prof = targets.get(str(bid))
        audit(
            "enumerate_target_edr",
            "ok",
            {"bid": bid, "mode": m, "command": command, "hits": len(hits)},
        )
        return json.dumps(
            {
                "ok": True,
                "bid": str(bid),
                "command": command,
                "noise_level": noise,
                "detected": hits,
                "count": len(hits),
                "profile": prof,
                "raw": text[:4000],
            },
            indent=2,
        )
    except Exception as exc:
        audit("enumerate_target_edr", "error", {"bid": bid, "error": str(exc)})
        return _agent_error(exc)


# ---------------------------------------------------------------------------
# session hygiene (safe, stays inside the beacon)
# ---------------------------------------------------------------------------
@mcp.tool()
def set_beacon_note(bid: str, note: str) -> str:
    """Label a session in Cobalt Strike.  Use it: an untagged beacon is an
    unattributed incident."""
    try:
        resp = agent.call("note", {"bid": str(bid), "note": note})
        if not resp.ok:
            return _err(resp.message)
        audit("set_beacon_note", "ok", {"bid": bid, "note": note})
        return json.dumps({"ok": True, "bid": str(bid), "note": note}, indent=2)
    except Exception as exc:
        audit("set_beacon_note", "error", {"bid": bid, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def set_beacon_sleep(bid: str, seconds: int, jitter: int = 0) -> str:
    """Change how often a session checks in.  Raising it lowers the chance of a
    noisy command being caught in the act."""
    try:
        resp = agent.call("set_sleep", {"bid": str(bid), "sleep": int(seconds), "jitter": int(jitter)})
        if not resp.ok:
            return _err(resp.message)
        audit("set_beacon_sleep", "ok", {"bid": bid, "seconds": seconds})
        return json.dumps({"ok": True, "bid": str(bid), "sleep": seconds, "jitter": jitter}, indent=2)
    except Exception as exc:
        audit("set_beacon_sleep", "error", {"bid": bid, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def beacon_liveness(bid: str) -> str:
    """Is this session still alive?  Also reports its last check-in time."""
    try:
        rows = _beacon_rows()
        rec = next((r for r in rows if str(r.get("id")) == str(bid)), None)
        audit("beacon_liveness", "ok", {"bid": bid, "alive": rec is not None})
        return json.dumps({"ok": True, "bid": str(bid), "alive": rec is not None, "beacon": rec}, indent=2)
    except Exception as exc:
        audit("beacon_liveness", "error", {"bid": bid, "error": str(exc)})
        return _agent_error(exc)


# ---------------------------------------------------------------------------
# policy management
# ---------------------------------------------------------------------------
@mcp.tool()
def policy_status() -> str:
    """Show the active policy: which built-ins are blocked, which are safe, and
    what the acknowledgement and block thresholds are."""
    audit("policy_status", "ok")
    return json.dumps(policy_summary(allow_denied=ALLOW_DENIED), indent=2)


@mcp.tool()
def quarantine_bof(path: str, reason: str) -> str:
    """Block a BOF from being run.  Use this for the old kits that are known to
    kill sessions."""
    try:
        rec = registry.quarantine(str(path), reason)
        audit("quarantine_bof", "ok", {"path": path, "reason": reason})
        return json.dumps({"ok": True, "quarantined": str(path), "record": rec}, indent=2)
    except Exception as exc:
        audit("quarantine_bof", "error", {"path": path, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def unquarantine_bof(path: str) -> str:
    """Allow a previously quarantined BOF again."""
    try:
        ok = registry.unquarantine(str(path))
        audit("unquarantine_bof", "ok" if ok else "not-found", {"path": path})
        return json.dumps({"ok": ok, "path": str(path)}, indent=2)
    except Exception as exc:
        audit("unquarantine_bof", "error", {"path": path, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def annotate_bof(path: str, risk: str, note: str) -> str:
    """Record the operator's own risk judgement for a BOF.  The annotation is
    shown by list_bofs and bof_info and survives restarts."""
    try:
        rec = registry.annotate(str(path), risk, note)
        audit("annotate_bof", "ok", {"path": path, "risk": risk})
        return json.dumps({"ok": True, "path": str(path), "annotation": rec}, indent=2)
    except Exception as exc:
        audit("annotate_bof", "error", {"path": path, "error": str(exc)})
        return _agent_error(exc)


@mcp.tool()
def audit_log(limit: int = 25) -> str:
    """Recent operator actions - the evidence trail for the engagement debrief."""
    try:
        if not AUDIT_PATH.exists():
            return json.dumps({"ok": True, "entries": []}, indent=2)
        lines = AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        tail = lines[-max(1, int(limit)) :]
        out = []
        for line in tail:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        audit("audit_log", "ok", {"entries": len(out)})
        return json.dumps({"ok": True, "count": len(out), "entries": out}, indent=2)
    except Exception as exc:
        return _agent_error(exc)


if __name__ == "__main__":
    #  opencode owns this process.  When it goes away it closes the
    #  stdio pipe, the MCP SDK's read loop hits EOF and mcp.run()
    #  returns.  That is a normal disconnect, not a failure: exit 0
    #  quietly so the client can respawn us cleanly.
    #
    #  Any unexpected exception is reported as ONE short line on
    #  stderr instead of a traceback, because whatever lands on
    #  stderr is exactly what the client shows in its error badge.
    try:
        mcp.run()
    except (EOFError, BrokenPipeError, ConnectionResetError):
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        print(f"cs-mcp-4.9 fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
