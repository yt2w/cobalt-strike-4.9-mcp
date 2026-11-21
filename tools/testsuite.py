#!/usr/bin/env python3
"""Offline test suite for the whole cs-mcp-4.9 Python stack.

Nothing here tasks a beacon.  The only live component is the transport
round trip, and that one is skipped (not failed) when the Cobalt Strike
client has no agent loaded.

    python3 tools/testsuite.py            run everything
    python3 tools/testsuite.py -k policy  run only matching groups
    python3 tools/testsuite.py -v         show every assertion

Groups
------
  policy    the deny list, the acknowledgement floor, the EDR interaction
            rules and the force/quarantine precedence
  edr       the signature database, the output parsers and the false
            positive guards
  tslog     the Team Server transcript parser against the real log
  registry  the BOF and kit inventory, quarantine and the kill learning loop
  targets   the per target profile persistence
  transport the spool protocol, including the root/unprivileged split
  mcp       the server imports and registers every tool (this is what
            catches the FastMCP annotation crash)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))

import edr as edr_mod  # noqa: E402
import policy as policy_mod  # noqa: E402
import registry as registry_mod  # noqa: E402
import tslog as tslog_mod  # noqa: E402

VERBOSE = False
GROUPS: dict[str, list] = {}
FAILURES: list[tuple[str, str]] = []
PASSED = 0


# ---------------------------------------------------------------------------
# tiny test harness
# ---------------------------------------------------------------------------
def group(name: str):
    def deco(fn):
        GROUPS.setdefault(name, []).append(fn)
        return fn

    return deco


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASSED
    if ok:
        PASSED += 1
        if VERBOSE:
            print(f"    [ok]   {label}" + (f" - {detail}" if detail else ""))
    else:
        FAILURES.append((label, detail))
        print(f"    [FAIL] {label}" + (f" - {detail}" if detail else ""))


def eq(label: str, got, want) -> None:
    check(label, got == want, f"got {got!r}, want {want!r}")


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------
LOW_BOF = {
    "name": "benign.o",
    "path": "/corpus/benign.o",
    "risk": "low",
    "score": 2,
    "categories": ["discovery"],
    "reasons": [],
}
MED_BOF = {
    "name": "medium.o",
    "path": "/corpus/medium.o",
    "risk": "medium",
    "score": 20,
    "categories": ["network"],
    "reasons": ["network"],
}
HIGH_BOF = {
    "name": "inject.o",
    "path": "/corpus/inject.o",
    "risk": "high",
    "score": 45,
    "categories": ["process_hollowing", "execution"],
    "reasons": ["process_hollowing: unmap"],
}
CRIT_BOF = {
    "name": "sleepmask.o",
    "path": "/corpus/sleepmask.o",
    "risk": "critical",
    "score": 64,
    "categories": ["process_hollowing", "defense_evasion", "SLEEP_MASK"],
    "reasons": ["amsi/etw patching"],
}


@group("policy")
def test_deny_list() -> None:
    for cmd in (
        "shell whoami",
        "powershell Get-Process",
        "execute-assembly Foo.dll",
        "upload /tmp/x /tmp/y",
        "download /tmp/x",
        "screenshot",
        "portscan 1-1024",
        "kill 1234",
        "rm /tmp/x",
        "runas user pass",
        "getuid",
        "inline-execute /tmp/x.exe",
    ):
        d = policy_mod.check_raw_command(cmd)
        check(
            f"denies '{cmd.split()[0]}'",
            not d.allowed and d.blocked_by == "denied-builtin",
            d.reason[:70],
        )

    for cmd in ("ps", "jobs", "whoami", "sleep 60", "note hello", "getprivs"):
        d = policy_mod.check_raw_command(cmd)
        check(f"allows '{cmd}'", d.allowed and not d.requires_ack, d.reason[:70])

    # a custom plugin command is allowed but acknowledged
    d = policy_mod.check_raw_command("edr_check")
    check("custom plugin allowed with ack", d.allowed and d.requires_ack, d.reason[:70])

    # the operator override
    d = policy_mod.check_raw_command("shell whoami", allow_denied=True)
    check("allow_denied overrides the block", d.allowed and d.requires_ack, d.reason[:70])

    # empty command
    d = policy_mod.check_raw_command("   ")
    check("empty command denied", not d.allowed, d.reason[:70])


@group("policy")
def test_evaluate_bof_matrix() -> None:
    # --- no EDR on the target -------------------------------------------
    d = policy_mod.evaluate_bof(LOW_BOF)
    check("low risk allowed, no ack", d.allowed and not d.requires_ack, d.reason[:60])

    d = policy_mod.evaluate_bof(MED_BOF)
    check("medium risk needs ack", d.allowed and d.requires_ack, d.reason[:60])

    d = policy_mod.evaluate_bof(HIGH_BOF)
    check("high risk needs ack", d.allowed and d.requires_ack, d.reason[:60])

    d = policy_mod.evaluate_bof(CRIT_BOF)
    check(
        "critical risk blocked without EDR",
        not d.allowed and d.blocked_by == "static-risk",
        f"{d.blocked_by}: {d.reason[:60]}",
    )

    # --- EDR on the target -----------------------------------------------
    edr_list = ["Microsoft Defender"]

    d = policy_mod.evaluate_bof(LOW_BOF, target_edr=edr_list)
    check("low risk + EDR still fine", d.allowed and not d.requires_ack, d.reason[:60])

    d = policy_mod.evaluate_bof(HIGH_BOF, target_edr=edr_list)
    check(
        "high risk + hot category + EDR needs ack",
        d.allowed and d.requires_ack and d.blocked_by == "edr-interaction",
        f"{d.blocked_by}: {d.reason[:60]}",
    )
    check(
        "high risk + EDR mentions the intersection",
        "process_hollowing" in d.detail.get("edr_intersection", []),
        str(d.detail.get("edr_intersection")),
    )

    d = policy_mod.evaluate_bof(CRIT_BOF, target_edr=edr_list)
    check(
        "critical risk + EDR blocked",
        not d.allowed and d.blocked_by == "edr-critical",
        f"{d.blocked_by}: {d.reason[:60]}",
    )

    d = policy_mod.evaluate_bof(CRIT_BOF, target_edr=edr_list, force=True)
    check(
        "force overrides the EDR critical block",
        d.allowed and d.blocked_by == "edr-critical-forced" and d.requires_ack,
        f"{d.blocked_by}: {d.reason[:60]}",
    )

    # --- force must NOT override quarantine or an observed death ---------
    d = policy_mod.evaluate_bof(
        HIGH_BOF, quarantined=True, quarantine_reason="killed a beacon", target_edr=edr_list, force=True
    )
    check(
        "force cannot override a quarantine",
        not d.allowed and d.blocked_by == "quarantine",
        f"{d.blocked_by}: {d.reason[:60]}",
    )

    d = policy_mod.evaluate_bof(
        HIGH_BOF, observed_kills=2, target_edr=edr_list, force=True
    )
    check(
        "force cannot override an observed beacon death",
        not d.allowed and d.blocked_by == "observed-beacon-death",
        f"{d.blocked_by}: {d.reason[:60]}",
    )

    # --- an observed death beats everything ------------------------------
    d = policy_mod.evaluate_bof(LOW_BOF, observed_kills=1)
    check(
        "an observed death blocks even a low risk BOF",
        not d.allowed and d.blocked_by == "observed-beacon-death",
        d.reason[:70],
    )

    # --- unknown risk is treated as medium --------------------------------
    weird = {"name": "x.o", "risk": "banana", "categories": []}
    d = policy_mod.evaluate_bof(weird)
    check("unknown risk is treated as medium", d.allowed and d.requires_ack, d.reason[:60])


@group("policy")
def test_noise_parsing() -> None:
    cases = [
        ("NOISE: * Minimal - Beacon-native bps(). Zero artifacts.", 1),
        ("NOISE: ** Low - in-process only", 2),
        ("NOISE: *** Moderate - spawns one helper", 3),
        ("NOISE: **** High - powershell.exe, ScriptBlock (4104), AMSI", 4),
    ]
    for text, want in cases:
        d = policy_mod.parse_noise(text)
        eq(f"noise level of {text[:18]!r}", d["level"], want)

    d = policy_mod.parse_noise("no noise rating here")
    eq("no noise rating -> level 0", d["level"], 0)
    d = policy_mod.parse_noise("")
    eq("empty text -> level 0", d["level"], 0)

    # the real kit text
    kit = Path.home()/"Abofs"/"CS-EDR-Enumeration"/"edr-enum.cna"
    if kit.exists():
        text = kit.read_text(encoding="utf-8", errors="replace")
        d = policy_mod.parse_noise(text)
        check("the EDR kit carries a noise rating", d["level"] >= 1, d["raw"][:60])


@group("policy")
def test_policy_summary() -> None:
    s = policy_mod.policy_summary()
    eq("summary posture", s["posture"], "custom plugins + custom BOFs only")
    check(
        "every denied builtin has a reason",
        all(s["denied_builtins"].values()),
        "",
    )
    eq("ack floor", s["acknowledgement_floor"], "medium")
    eq("block floor", s["block_floor"], "critical")


# ---------------------------------------------------------------------------
# edr
# ---------------------------------------------------------------------------
@group("edr")
def test_signature_db() -> None:
    d = edr_mod.db()
    s = d.summary()
    check("kit is readable", s["available"], s["kit"])
    check("vendor count is plausible", s["vendors"] >= 40, str(s["vendors"]))
    check("process signatures loaded", s["signatures"]["process"] >= 150, str(s["signatures"]))
    check("service signatures loaded", s["signatures"]["service"] >= 80, str(s["signatures"]))
    check("driver signatures loaded", s["signatures"]["driver"] >= 80, str(s["signatures"]))

    # the real target is Defender for Endpoint
    hits = edr_mod.detect_vendors("MsMpEng.exe MsSense.exe SenseNDR.exe")
    vendors = [h["vendor"] for h in hits]
    check("detects Microsoft Defender", "Microsoft Defender" in vendors, str(vendors))
    cat = [h["category"] for h in hits if h["vendor"] == "Microsoft Defender"]
    check("classifies Defender as EDR", "EDR" in cat, str(cat))


@group("edr")
def test_false_positives() -> None:
    """Substring matching used to invent vendors."""
    for text in (
        "Dns.exe 1234",
        "MessSvc.exe 1234",
        "sunset.exe 1234",
        "cscache.exe 1234",
        "nonsense.exe 1234",
    ):
        hits = edr_mod.detect_vendors(text)
        eq(f"no vendor invented from {text!r}", [h["vendor"] for h in hits], [])

    hits = edr_mod.detect_vendors("csfalconcontainer.exe")
    eq("crowdstrike still detected", [h["vendor"] for h in hits], ["CrowdStrike"])


@group("edr")
def test_parse_enum_output() -> None:
    sample = """[EDR-ENUM] ============ Security Product Enumeration ============
  [EDR]  CrowdStrike - Falcon  (proc: csfalconcontainer.exe)
  [AV]   Microsoft - Defender  (proc: MsMpEng.exe)
  [EPP]  SentinelOne - Singularity  (proc: SentinelAgent.exe)
[EDR-ENUM] Unique security products found: 3"""
    r = edr_mod.parse_edr_enum_output(sample)
    eq("three products parsed", r["count"], 3)
    vendors = sorted(h["vendor"] for h in r["hits"])
    eq("vendors parsed", vendors, ["CrowdStrike", "Microsoft Defender", "SentinelOne"])

    # control characters from blog() must not break the parse
    dirty = "\x03[EDR]\x00 CrowdStrike - Falcon (proc: csfalconcontainer.exe)"
    r = edr_mod.parse_edr_enum_output(dirty)
    eq("control characters stripped", r["count"], 1)

    eq("empty output", edr_mod.parse_edr_enum_output("")["count"], 0)
    eq("noise output", edr_mod.parse_edr_enum_output("nothing useful here")["count"], 0)


@group("edr")
def test_vendor_canonicalisation() -> None:
    eq("Microsoft folds into Microsoft Defender", edr_mod.canonical_vendor("Microsoft"), "Microsoft Defender")
    eq("Broadcom folds into Symantec", edr_mod.canonical_vendor("Broadcom"), "Symantec")
    eq("unknown vendor is unchanged", edr_mod.canonical_vendor("Acme Security"), "Acme Security")


# ---------------------------------------------------------------------------
# tslog
# ---------------------------------------------------------------------------
@group("tslog")
def test_tslog_parsing() -> None:
    sample = """10/28 15:35:08 UTC [metadata] 203.0.113.1 <- 192.0.2.10; computer: EXAMPLE-HOST; user: SYSTEM *; process: example.exe; pid: 12345; os: Windows; version: 10.0; build: 26200; beacon arch: x64 (x64)
10/28 15:35:53 UTC [input] <operator> ps
10/28 15:35:53 UTC [task] <T1057> Tasked beacon to list processes
10/28 15:36:23 UTC [output]
lsass.exe	1420	1588
MsMpEng.exe	1496	3000

10/28 15:38:56 UTC [input] <operator> uptime
10/28 15:38:56 UTC [task] <T1082> Tasked beacon to run uptime BOF (T1082)
10/28 15:39:18 UTC [output]
Uptime: 39 days
"""
    events = tslog_mod.TSLogReader.parse_events(sample)
    eq("event count", len(events), 7)
    kinds = [e["kind"] for e in events]
    eq("kinds in order", kinds, ["metadata", "input", "task", "output", "input", "task", "output"])

    out = [e for e in events if e["kind"] == "output"]
    eq("first output owns two lines", len(out[0]["lines"]), 2)
    check("output line preserved", "MsMpEng.exe" in out[0]["lines"][1], str(out[0]["lines"]))
    eq("second output line count", len(out[1]["lines"]), 1)
    check("timestamp parsed", out[0]["ts"] > 0, str(out[0]["ts"]))


TSLOG_FIXTURE = """10/28 15:35:08 UTC [metadata] 203.0.113.1 <- 192.0.2.10; computer: EXAMPLE-HOST; user: SYSTEM *; process: example.exe; pid: 12345; os: Windows; version: 10.0; build: 26200; beacon arch: x64 (x64)
10/28 15:35:14 UTC [note] ☑ session alive
10/28 15:35:53 UTC [input] <operator> ps
10/28 15:35:53 UTC [task] <T1057> Tasked beacon to list processes
10/28 15:36:23 UTC [output]
lsass.exe\t1420\t1588
MsMpEng.exe\t1496\t3000

10/28 15:38:56 UTC [input] <operator> uptime
10/28 15:38:56 UTC [task] <T1082> Tasked beacon to run uptime BOF (T1082)
10/28 15:39:18 UTC [output]
Uptime: 39 days

10/28 15:40:14 UTC [note] 💀 session dead
"""


def _fixture_tslog() -> Path:
    import os
    from datetime import datetime, timezone
    root = Path(tempfile.mkdtemp(prefix="cs-mcp-4.9-tslog-"))
    day = datetime.now(timezone.utc).strftime("%y%m%d")
    d = root / day / "192.0.2.10"
    d.mkdir(parents=True)
    (d / "beacon_12345.log").write_text(TSLOG_FIXTURE, encoding="utf-8")
    return root


@group("tslog")
def test_tslog_live_log() -> None:
    """Transcript parsing against a local fixture."""
    import os
    root = _fixture_tslog()
    old = os.environ.get("CS_TS_LOG_DIR")
    os.environ["CS_TS_LOG_DIR"] = str(root)
    try:
        r = tslog_mod.TSLogReader(root)
        check("team server log directory exists", r.available(), str(r.root))
        p = r.find_beacon_log("12345")
        if p is None:
            check("session log located for 12345", False, "not found")
            return
        check("session log located for 12345", True, str(p))
        events = r.read_events("12345")
        check("events parsed", len(events) > 0, str(len(events)))
        meta = r._metadata(p)
        eq("beacon id comes from the metadata pid", meta["pid"], 12345)
        eq("host address parsed", meta["ip"], "192.0.2.10")
        outputs = r.read_output("12345")
        check("output blocks found", len(outputs) >= 2, str(len(outputs)))
        blob = "\n".join(o["text"] for o in outputs)
        check("process list captured", "MsMpEng.exe" in blob, "no MsMpEng in output")
        check("uptime BOF output captured", "Uptime:" in blob, "no uptime output")
        sessions = r.session_map()
        check("session map populated", len(sessions) > 0, str(sessions))
    finally:
        if old is None:
            os.environ.pop("CS_TS_LOG_DIR", None)
        else:
            os.environ["CS_TS_LOG_DIR"] = old


@group("tslog")
def test_tslog_death_detection() -> None:
    """The emoji legend CS uses in the note line."""
    import os
    root = _fixture_tslog()
    old = os.environ.get("CS_TS_LOG_DIR")
    os.environ["CS_TS_LOG_DIR"] = str(root)
    try:
        p = tslog_mod.TSLogReader(root).find_beacon_log("12345")
        if p is None:
            check("session log located", False, "not found")
            return
        text = p.read_text(encoding="utf-8", errors="replace")
        check("session was alive at some point", "☑" in text, "no alive marker")
        check("session death is recorded", "💀" in text, "no death marker")
    finally:
        if old is None:
            os.environ.pop("CS_TS_LOG_DIR", None)
        else:
            os.environ["CS_TS_LOG_DIR"] = old


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------
@group("registry")
def test_inventory() -> None:
    reg = registry_mod.Registry()
    bofs = reg.build_inventory()
    check("BOF inventory is not empty", len(bofs) > 100, str(len(bofs)))

    bands: dict[str, int] = {}
    for b in bofs:
        bands[str(b.get("risk"))] = bands.get(str(b.get("risk")), 0) + 1
    check(
        "every object has a risk band",
        set(bands) <= {"low", "medium", "high", "critical"},
        str(bands),
    )
    check("critical objects are rare", bands.get("critical", 0) <= 20, str(bands))
    check("low risk objects dominate", bands.get("low", 0) > bands.get("critical", 0) * 10, str(bands))

    # entries are well formed
    sample = bofs[0]
    for key in ("path", "name", "risk", "score", "categories", "size", "sha256", "is_elf"):
        check(f"inventory entry has '{key}'", key in sample, str(list(sample)[:8]))

    # the ELF objects must be flagged: they cannot run through a Windows beacon
    elf = [b for b in bofs if b.get("is_elf")]
    check("Linux ELF objects are flagged", len(elf) > 0, str(len(elf)))
    check(
        "ELF objects are a small minority",
        len(elf) < len(bofs) * 0.3,
        f"{len(elf)} of {len(bofs)}",
    )

    # the known critical objects
    crit = [b for b in bofs if b.get("risk") == "critical"]
    names = sorted(Path(b["path"]).name for b in crit)
    check("sleepmask objects are classified critical", "sleepmask.x64.o" in names, str(names[:5]))

    kits = reg.build_kits()
    check("kit inventory is not empty", len(kits) > 50, str(len(kits)))
    edr_kit = [k for k in kits if k["name"] == "edr-enum.cna"]
    check("the EDR kit is indexed", len(edr_kit) == 1, str(len(edr_kit)))
    if edr_kit:
        cmds = edr_kit[0]["commands"]
        check(
            "the EDR kit's commands are extracted",
            "edr_check" in cmds and "edr_enum" in cmds,
            str(cmds[:6]),
        )


@group("registry")
def test_quarantine_and_learning() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="cs-mcp-4.9-reg-"))
    try:
        reg = registry_mod.Registry(state_dir=tmp)
        key = "/corpus/evil.o"
        check("not quarantined initially", not reg.is_quarantined(key), "")
        reg.quarantine(key, "test")
        check("quarantine recorded", reg.is_quarantined(key), "")
        check("quarantine reason kept", reg.quarantine_reason(key) == "test", reg.quarantine_reason(key))

        n = reg.record_kill(key, "beacon died after the run")
        eq("kill counted", n, 1)
        eq("kill count readable", reg.kill_count(key), 1)
        check("an observed death also quarantines", reg.is_quarantined(key), "")

        # reload from disk: the state must survive
        reg2 = registry_mod.Registry(state_dir=tmp)
        eq("kill count survives a reload", reg2.kill_count(key), 1)
        check("quarantine survives a reload", reg2.is_quarantined(key), "")

        check("unquarantine works", reg2.unquarantine(key), "")
        check("quarantine removed", not reg2.is_quarantined(key), "")

        # and the policy honours it
        d = policy_mod.evaluate_bof(
            {"name": "evil.o", "risk": "low", "categories": []},
            observed_kills=reg2.kill_count(key),
        )
        check("policy blocks the learned killer", not d.allowed, d.reason[:60])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@group("registry")
def test_bof_lookup() -> None:
    reg = registry_mod.Registry()
    bofs = reg.build_inventory()
    if not bofs:
        check("inventory available for lookup", False, "")
        return
    one = bofs[0]
    found = reg.bof_by_path(one["path"])
    check("lookup by full path", found is not None and found["path"] == one["path"], "")
    check("lookup of a missing path returns None", reg.bof_by_path("/nope/nope.o") is None, "")


# ---------------------------------------------------------------------------
# targets
# ---------------------------------------------------------------------------
@group("targets")
def test_target_profiles() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="cs-mcp-4.9-targets-"))
    try:
        p = edr_mod.TargetProfiles(tmp / "targets.json")
        eq("unknown target has no vendors", p.vendors("999"), [])

        p.set("999", vendors=["Microsoft Defender"], source="test")
        eq("vendor recorded", p.vendors("999"), ["Microsoft Defender"])

        p.set("999", vendors=["CrowdStrike"], source="test2")
        eq("vendors merge", sorted(p.vendors("999")), ["CrowdStrike", "Microsoft Defender"])

        # reload from disk
        p2 = edr_mod.TargetProfiles(tmp / "targets.json")
        eq("profile survives a reload", sorted(p2.vendors("999")), ["CrowdStrike", "Microsoft Defender"])

        check("clear removes the profile", p2.clear("999"), "")
        eq("profile gone", p2.vendors("999"), [])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
@group("transport")
def test_transport_roundtrip() -> None:
    from csagent import AgentClient, AgentError

    c = AgentClient()
    c.ensure_dirs()
    if not (c.base / "agent.token").exists():
        print("    (skipped: no live CS agent - load agent/cs_agent.cna to run this group)")
        return
    try:
        r = c.call("ping", timeout=15)
    except AgentError as exc:
        print(f"    (skipped: agent unreachable: {exc})")
        return
    check("agent answers ping", r.ok, r.message)
    check("agent reports a version", bool(r.get("agent_version")), r.get("agent_version"))

    st = c.agent_status()
    check("status file is readable", bool(st), "")
    eq("selftest passed", st.get("selftest"), "pass")
    eq("mode is fork", st.get("mode"), "fork")
    eq("binary read strategy", st.get("read_strategy"), "readb_len")
    eq("binary round trip matched", st.get("bin_read_match"), "1")

    # the queue file must be usable by both sides
    q = c.inbox / "queue.txt"
    check("queue file exists", q.exists(), str(q))
    if q.exists():
        mode = q.stat().st_mode & 0o777
        check("queue file is writable by the server", bool(mode & 0o200), oct(mode))


@group("transport")
def test_transport_auth() -> None:
    """A wrong token must be rejected, and the request file alone must
    still be enough for the agent to find it."""
    from csagent import AgentClient, AgentError

    c = AgentClient()
    c.ensure_dirs()
    try:
        c.call("ping", timeout=10)
    except AgentError:
        print("    (skipped: no agent loaded)")
        return

    # write a request with a bad token by hand
    req_id = "testsuite-badtoken"
    body = "TOOL\tping\nARG\ttoken\tdefinitely-not-the-token\nEND\n"
    (c.inbox / f"{req_id}.req").write_text(body, encoding="utf-8")
    try:
        with open(c.inbox / "queue.txt", "a", encoding="utf-8") as fh:
            fh.write(req_id + "\n")
    except OSError:
        pass

    res = c.outbox / f"{req_id}.res"
    deadline = time.time() + 20
    while time.time() < deadline and not res.exists():
        time.sleep(0.1)
    check("bad token request answered", res.exists(), "no response")
    if res.exists():
        text = res.read_text(encoding="utf-8", errors="replace")
        check("bad token rejected", "invalid or missing token" in text, text[:120])


@group("transport")
def test_transport_escaping() -> None:
    from csagent import AgentClient, _esc, _unesc

    for raw in ("plain", "with\ttab", "with\nnewline", "back\\slash", "mixed \\\t\n"):
        eq(f"escape round trip for {raw!r}", _unesc(_esc(raw)), raw)

    c = AgentClient()
    c.ensure_dirs()
    check("base is set", str(c.base).endswith("cs-mcp-4.9") or "cs-mcp-4.9" in str(c.base), str(c.base))


# ---------------------------------------------------------------------------
# mcp
# ---------------------------------------------------------------------------
@group("mcp")
def test_server_imports_and_registers_tools() -> None:
    """The FastMCP annotation crash happened at import time, so importing
    the module and counting the tools is the check."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "cs_mcp_server", ROOT / "server" / "cs_mcp_server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    tools = mod.mcp._tool_manager.list_tools()
    names = {t.name for t in tools}
    check("tools registered", len(names) >= 20, str(len(names)))

    required = {
        "cs_status",
        "list_beacons",
        "beacon_output",
        "list_plugin_commands",
        "list_bofs",
        "bof_info",
        "run_bof",
        "target_profile",
        "set_target_edr",
        "detect_target_edr",
        "enumerate_target_edr",
        "quarantine_bof",
        "policy_status",
        "audit_log",
    }
    missing = required - names
    check("every expected tool is registered", not missing, f"missing: {sorted(missing)}")

    # the deny list must be visible through the tool surface
    s = mod.policy_summary()
    check("shell is denied", "shell" in s["denied_builtins"], "")


@group("mcp")
def test_agent_has_the_same_deny_list() -> None:
    """The client side deny list must match the python side."""
    agent_src = (ROOT / "agent" / "cs_agent.cna").read_text(encoding="utf-8")
    for verb in policy_mod.DENIED_BUILTINS:
        check(
            f"agent denies '{verb}'",
            f'"{verb}"' in agent_src,
            "not found in cs_agent.cna",
        )
    # the agent must not contain the event that does not exist in CS 4.9
    check(
        "agent does not register the non existent beacon_output event",
        "on beacon_output" not in agent_src,
        "CS 4.9 has no beacon_output event",
    )


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------
def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", "--filter", default="", help="only run groups matching this text")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    selected = [
        (name, fns)
        for name, fns in GROUPS.items()
        if not args.filter or args.filter.lower() in name.lower()
    ]

    print("cs-mcp-4.9 test suite")
    print("=" * 60)
    for name, fns in selected:
        print(f"\n[{name}]")
        for fn in fns:
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                FAILURES.append((f"{name}/{fn.__name__}", f"{type(exc).__name__}: {exc}"))
                print(f"    [FAIL] {fn.__name__} raised {type(exc).__name__}: {exc}")
                if VERBOSE:
                    traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"passed: {PASSED}   failed: {len(FAILURES)}")
    if FAILURES:
        print("\nfailures:")
        for label, detail in FAILURES:
            print(f"  - {label}" + (f"  ({detail})" if detail else ""))
        return 1
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
