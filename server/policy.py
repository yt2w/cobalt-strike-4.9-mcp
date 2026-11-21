"""
Policy engine for the Cobalt Strike MCP server.

Two layers of protection, deliberately:

  1. This module (python side) decides what an MCP client is allowed to
     ask for.  The default posture is "custom plugins and custom BOFs
     only" - the built-ins that reliably get a beacon killed by EDR/AV
     are refused rather than merely discouraged.

  2. cs_agent.cna carries the same deny list inside the Cobalt Strike
     client, so a misconfigured or hostile MCP client still cannot drive
     them.  That layer can be relaxed deliberately with
     -Dcs.mcp.allow_denied=1 on the CS client.

The risk model is intentionally conservative: a tool is only allowed
without acknowledgement when its static analysis and operator history
agree that it is low risk.  Anything with a history of killing a beacon
is refused outright, not warned about.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# hard denied built-ins
# ---------------------------------------------------------------------------
# These spawn a child process, drop a file on disk, pull bytes over the
# wire, or otherwise produce the telemetry that endpoint security is
# tuned to catch.  In an engagement where the beacon is the only foothold,
# running them is how sessions die.
DENIED_BUILTINS: dict[str, str] = {
    "shell": "spawns cmd.exe - highest signal child process on the host",
    "powershell": "spawns powershell.exe - classic EDR detection trigger",
    "execute-assembly": "loads and executes .NET in memory, leaves no drop but is widely hooked",
    "upload": "writes a file to disk on the target",
    "download": "reads a file and exfiltrates it over the C2 channel",
    "screenshot": "captures the desktop - often blocked by EDR policy and noisy",
    "portscan": "raw connect() sweep - noisy and often blocked by host firewall",
    "kill": "terminates a process on the target",
    "rm": "deletes a file on the target",
    "runas": "starts a new process under another account",
    "getuid": "spawns a helper process",
    "inline-execute": "loads a full PE in memory - equivalent to execute-assembly",
}

# Commands that are fine because they stay inside the beacon process.
ALLOWED_BUILTINS: dict[str, str] = {
    "ps": "process list, handled inside the beacon",
    "jobs": "job list, handled inside the beacon",
    "make_token": "token manipulation inside the beacon",
    "steal_token": "token manipulation inside the beacon",
    "rev2self": "reverts the beacon token",
    "getprivs": "privilege check inside the beacon",
    "sleep": "changes check-in interval",
    "note": "changes the session note",
    "whoami": "identity query",
    "blockdlls": "sets the child-process DLL mitigation flag inside the beacon, no child process",
}

RISK_ORDER = ["low", "medium", "high", "critical"]


def risk_at_least(risk: str, floor: str) -> bool:
    try:
        return RISK_ORDER.index(risk) >= RISK_ORDER.index(floor)
    except ValueError:
        return True


@dataclass
class Decision:
    allowed: bool
    reason: str
    risk: str = "low"
    requires_ack: bool = False
    blocked_by: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "risk": self.risk,
            "requires_acknowledgement": self.requires_ack,
            "blocked_by": self.blocked_by,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# raw command policy
# ---------------------------------------------------------------------------
def command_verb(command: str) -> str:
    cmd = (command or "").strip()
    if not cmd:
        return ""
    m = re.match(r"^([A-Za-z0-9_\-]+)", cmd)
    return m.group(1).lower() if m else ""


def check_raw_command(command: str, allow_denied: bool = False) -> Decision:
    """Decide whether a raw beacon command may be sent."""
    verb = command_verb(command)
    if not verb:
        return Decision(False, "empty command", blocked_by="empty")

    if verb in DENIED_BUILTINS:
        if allow_denied:
            return Decision(
                True,
                f"'{verb}' is normally blocked ({DENIED_BUILTINS[verb]}) but the operator "
                "has explicitly allowed denied built-ins",
                risk="high",
                requires_ack=True,
                blocked_by="denied-builtin",
            )
        return Decision(
            False,
            f"'{verb}' is blocked: {DENIED_BUILTINS[verb]}. "
            "Use a custom plugin command or a custom BOF instead.",
            risk="high",
            blocked_by="denied-builtin",
        )

    if verb in ALLOWED_BUILTINS:
        return Decision(True, f"'{verb}' runs inside the beacon process", risk="low")

    # Unknown verbs are assumed to be custom plugin commands, which is the
    # point of this server, but they are still acknowledged as medium risk
    # because we cannot see what the plugin does.
    return Decision(
        True,
        f"'{verb}' is not a known built-in - treated as a custom plugin command",
        risk="medium",
        requires_ack=True,
        blocked_by="",
    )


# ---------------------------------------------------------------------------
# BOF risk policy
# ---------------------------------------------------------------------------
# Category names come from the static scanner (server/bof_scanner.py).  The
# older names are kept as aliases so a fallback scan still lines up.
#
# These are the categories that endpoint security instruments directly.
# A BOF that touches them on a defended host is the classic beacon kill,
# so their presence is what raises the floor on an EDR protected target.
HIGH_SIGNAL_CATEGORIES = {
    "process_hollowing",
    "defense_evasion",
    "execution",
    "credential_access",
    "privilege",
    "SLEEP_MASK",
    "EXEC_LOADER",
    # aliases used by the fallback scanner
    "process_injection",
    "process_execution",
    "privilege_escalation",
}

MEDIUM_SIGNAL_CATEGORIES = {
    "persistence",
    "anti_forensics",
    "artifact_on_disk",
    "network",
    "discovery_noise",
    "discovery",
}

# Risk floor above which the operator must explicitly acknowledge.
ACK_REQUIRED_AT = "medium"
BLOCK_AT = "critical"

# ---------------------------------------------------------------------------
# noise model
# ---------------------------------------------------------------------------
# Borrowed from the operator's own CS-EDR-Enumeration kit, which rates
# every one of its commands by how much telemetry it creates.  The same
# scale is used for the corpus at large: what matters is not "is this
# dangerous in the abstract" but "how much does it look like".
NOISE_LEVELS = {
    1: "minimal",       # in-process, no child process, no artifacts
    2: "low",           # unusual but not spawns a process
    3: "moderate",      # child process, low anomaly score
    4: "high",          # full PowerShell/WMI telemetry
}
NOISE_STARS = {1: "*", 2: "**", 3: "***", 4: "****"}


def parse_noise(text: str) -> dict[str, Any]:
    """Pull a NOISE rating out of a plugin command's help text.

    The EDR kit writes 'NOISE: * Minimal - Beacon-native, in-process'.
    """
    detail = {"level": 0, "label": "", "raw": ""}
    if not text:
        return detail
    m = re.search(
        r"NOISE:\s*(?P<stars>\*+)\s*(?P<label>[A-Za-z]+)?(?:\s*-\s*(?P<rest>[^\n]*))?",
        text,
    )
    if not m:
        return detail
    stars = m.group("stars") or ""
    level = min(4, max(1, len(stars)))
    label = (m.group("label") or "").strip()
    if not label:
        label = NOISE_LEVELS.get(level, "")
    detail["level"] = level
    detail["label"] = label.lower()
    detail["raw"] = m.group(0).strip()
    detail["note"] = (m.group("rest") or "").strip()
    return detail


def noise_risk(level: int) -> str:
    return {0: "low", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(level, "medium")


def evaluate_bof(
    entry: dict[str, Any],
    quarantined: bool = False,
    quarantine_reason: str = "",
    observed_kills: int = 0,
    target_edr: list[str] | None = None,
    force: bool = False,
) -> Decision:
    """
    Decide whether a BOF may be run against a beacon.

    entry: the inventory record (risk, score, categories, reasons).
    target_edr: security products known to be on the target.
    force: operator override for the EDR interaction block only.  It can
           never override a quarantine or an observed beacon death.
    """
    risk = str(entry.get("risk", "unknown")).lower()
    if risk not in RISK_ORDER:
        risk = "medium"
    categories = {str(c).lower() for c in entry.get("categories", [])}
    reasons = list(entry.get("reasons", []))
    name = entry.get("name") or entry.get("path", "bof")

    detail: dict[str, Any] = {
        "bof": name,
        "static_risk": risk,
        "static_score": entry.get("score", 0),
        "categories": sorted(categories),
        "reasons": reasons[:8],
    }

    # 1. history of killing a beacon is decisive, and force never applies
    if observed_kills > 0:
        return Decision(
            False,
            f"'{name}' has previously killed a beacon on this engagement "
            f"({observed_kills} observed death(s)). It is blocked until an operator "
            "explicitly overrides the quarantine.",
            risk="critical",
            blocked_by="observed-beacon-death",
            detail=detail,
        )

    # 2. explicit quarantine is decisive, and force never applies
    if quarantined:
        return Decision(
            False,
            f"'{name}' is quarantined: {quarantine_reason or 'no reason recorded'}",
            risk=risk,
            blocked_by="quarantine",
            detail=detail,
        )

    # 3. endpoint security raises the floor
    edr = [e for e in (target_edr or []) if e]
    if edr:
        detail["target_edr"] = edr
        hot = sorted(categories & HIGH_SIGNAL_CATEGORIES)
        detail["edr_intersection"] = hot
        if hot:
            # a defended target plus a high signal technique is the
            # beacon kill.  It is refused outright at critical risk,
            # and needs an explicit acknowledgement at high risk.
            if risk == "critical" and not force:
                return Decision(
                    False,
                    f"'{name}' performs {', '.join(hot)} and endpoint security is "
                    f"present on the target ({', '.join(edr)}). On a defended host this "
                    "combination is the classic beacon kill. If you have validated the "
                    "technique against this specific product, re-run with force=true.",
                    risk="critical",
                    blocked_by="edr-critical",
                    detail=detail,
                )
            if risk == "critical" and force:
                return Decision(
                    True,
                    f"'{name}' is critical and endpoint security is present "
                    f"({', '.join(edr)}) - forced by the operator.",
                    risk="critical",
                    requires_ack=True,
                    blocked_by="edr-critical-forced",
                    detail=detail,
                )
            return Decision(
                True,
                f"'{name}' performs {', '.join(hot)} and endpoint security is present "
                f"on the target ({', '.join(edr)}). Confirm you accept the beacon-loss "
                "risk before running.",
                risk="high" if risk == "low" else risk,
                requires_ack=True,
                blocked_by="edr-interaction",
                detail=detail,
            )

    # 4. static risk floor
    if risk == BLOCK_AT:
        return Decision(
            False,
            f"'{name}' scores {entry.get('score', '?')} and is classified critical "
            f"({', '.join(sorted(categories)) or 'no category'}). Running it is very "
            "likely to end the session. Use a narrower custom BOF instead.",
            risk="critical",
            blocked_by="static-risk",
            detail=detail,
        )

    # 5. otherwise acknowledge above the floor
    if risk_at_least(risk, ACK_REQUIRED_AT):
        return Decision(
            True,
            f"'{name}' is {risk} risk ({', '.join(sorted(categories))}). "
            "Confirm you accept the beacon-loss risk before running.",
            risk=risk,
            requires_ack=True,
            detail=detail,
        )

    return Decision(True, f"'{name}' is low risk", risk=risk, detail=detail)


def policy_summary(allow_denied: bool = False) -> dict[str, Any]:
    return {
        "posture": "custom plugins + custom BOFs only",
        "denied_builtins": {k: v for k, v in DENIED_BUILTINS.items()},
        "allowed_builtins": {k: v for k, v in ALLOWED_BUILTINS.items()},
        "acknowledgement_floor": ACK_REQUIRED_AT,
        "block_floor": BLOCK_AT,
        "allow_denied_overridden": allow_denied,
        "notes": [
            "The same deny list is enforced inside the Cobalt Strike client by cs_agent.cna.",
            "A BOF that has been observed killing a beacon is blocked outright.",
            "Quarantine and risk annotations persist in ~/.cs-mcp-4.9/registry.json.",
        ],
    }
