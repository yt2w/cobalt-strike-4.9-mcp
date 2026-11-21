#!/usr/bin/env python3
"""Offline dry-run harness for agent/cs_agent.cna.

Runs the agent's Sleep source inside the standalone Sleep engine that
ships inside the Cobalt Strike 4.9 client jar, with the Aggressor API
replaced by stubs.  Nothing is sent to a beacon and nothing touches the
live Cobalt Strike client.

What it proves
--------------
1. The script PARSES.  Aggressor's `on`/`command` blocks are stripped
   (they are Aggressor keywords, not Sleep), everything else is kept, so
   a syntax error is caught here instead of burning a reload cycle.
2. The file spool transport works end to end: a request written by
   Python is picked up by the pump and answered in the outbox.
3. The hard deny list actually blocks a dangerous command.
4. A real .o file is loaded byte-exactly.  The stub for
   beacon_inline_execute writes the bytes it received through
   ISO-8859-1 so Python can diff them against the original object.

Usage:  python3 tools/dryrun.py [--object /path/to/file.o]
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent" / "cs_agent.cna"
JAR = Path(os.environ.get("CS_JAR", ""))
if not str(JAR):
    _cands = sorted((Path.home() / "cobaltstrike").rglob("cobaltstrike-client*.jar"))
    JAR = _cands[0] if _cands else Path("cobaltstrike-client.jar")
SANDBOX = Path(os.environ.get("CS_MCP_DIR", "/tmp/cs-mcp-4.9"))/"dryrun"

# ----------------------------------------------------------------- stubs --

PRELUDE = r"""
# =====================================================================
#  DRY RUN STUBS - the Aggressor API replaced by no-ops so the agent
#  can be exercised outside Cobalt Strike.  Nothing here touches a
#  beacon; every task call is recorded to a file instead.
# =====================================================================

#  NOTE: no script globals are used by the stubs.  A forked thread does
#  not inherit the parent script's globals, so every path is baked in
#  as a literal.

sub dry_note {
    ($m) = @_;
    # NOTE: no globals here.  A forked thread does not inherit the
    # parent script's globals, so anything a stub needs must be baked
    # into the literal path.
    $fh = openf(">>__DRY_DIR__/tasks.log");
    writeb($fh, $m . "\n");
    closef($fh);
}

sub beacons { return @("12345"); }

sub beacon_info {
    ($bid, $key) = @_;
    return "dryrun-" . $key;
}

sub listeners { return @("http"); }

sub listener_info {
    ($name) = @_;
    %h = %("port" => "8080", "proto" => "http");
    return %h;
}

sub hosts { return @("192.0.2.10"); }

sub host_info {
    ($host, $key) = @_;
    return "dryrun-" . $key;
}

sub beacon_commands { return @("drycmd", "drycmd2"); }

sub beacon_command_describe {
    ($name) = @_;
    return "dry description of " . $name;
}

sub beacon_command_detail {
    ($name) = @_;
    return "dry detail of " . $name;
}
sub binput {
    ($bid, $cmd) = @_;
    dry_note("binput " . $bid . " " . $cmd);
}

sub bexecute {
    ($bid, $cmd) = @_;
    dry_note("bexecute " . $bid . " " . $cmd);
}

sub bnote { dry_note("bnote"); }
sub bsleep { dry_note("bsleep"); }
sub bps { dry_note("bps"); }
sub bjobs { dry_note("bjobs"); }
sub bsteal_token { dry_note("bsteal_token"); }
sub bmake_token { dry_note("bmake_token"); }
sub brev2self { dry_note("brev2self"); }
sub bgetprivs { dry_note("bgetprivs"); }
sub bexit { dry_note("bexit"); }

# Built-in bridges used by builtin_task().  These must be called instead
# of bexecute() for built-in Beacon commands.
sub bblockdlls { ($bid, $on) = @_; dry_note("bblockdlls " . $bid . " " . $on); }
sub bloginuser { ($bid, $dom, $usr, $pw) = @_; dry_note("bloginuser " . $bid . " " . $dom . " " . $usr); }
sub bcd { ($bid, $path) = @_; dry_note("bcd " . $bid . " " . $path); }
sub bpwd { dry_note("bpwd"); }
sub bshell { ($bid, $cmd) = @_; dry_note("bshell " . $bid . " " . $cmd); }
sub brun { ($bid, $cmd) = @_; dry_note("brun " . $bid . " " . $cmd); }

# Stand-ins for the live client's AliasManager.  "drycmd" is a custom
# .cna plugin command; everything else is a built-in.  Sleep keeps the
# FIRST definition of a sub, so main() strips these two subs from the
# agent source before appending the driver.
sub is_plugin_alias {
    ($name) = @_;
    if ($name eq "drycmd") { return 1; }
    return 0;
}

sub fire_plugin_alias {
    ($bid, $verb, $args) = @_;
    dry_note("fireAlias " . $bid . " " . $verb . " " . $args);
    return 1;
}


sub bof_pack {
    ($bid, $fmt, $val) = @_;
    return "PACKED:" . $fmt . ":" . $val;
}

#  Records exactly what would have been handed to Cobalt Strike.  The
#  bytes are dumped through ISO-8859-1 so every char code 0-255 maps to
#  the identical byte, which lets Python diff against the source .o.
sub beacon_inline_execute {
    ($bid, $data, $entry, $args) = @_;
    $isnull = 0;
    if ($data eq $null) { $isnull = 1; }
    println("STUB inline: bid=[" . $bid . "] dataNull=" . $isnull . " entry=[" . $entry . "]");
    $meta = "bid=" . $bid . "\nentry=" . $entry . "\nargs=" . $args . "\nlen=" . strlen($data) . "\n";
    $fh = openf(">__DRY_DIR__/inline_meta.txt");
    writeb($fh, $meta);
    closef($fh);
    #  writeb is byte preserving for char codes 0-255 (verified), so the
    #  dump can be compared byte for byte with the original .o file.
    $fh = openf(">__DRY_DIR__/inline_rx.bin");
    writeb($fh, $data);
    closef($fh);
    dry_note("beacon_inline_execute " . $bid . " " . $entry . " len=" . strlen($data));
}

#  Multi column rows must survive the trip.  "(@f) = @_;" captures only
#  the FIRST argument in Sleep, so a broken resp_row silently returns one
#  empty column instead of three.
sub beacon_info {
    ($bid, $key) = @_;
    if ($key eq "note") { return "test-note"; }
    if ($key eq "computer") { return "TESTHOST"; }
    return "dryrun-" . $key;
}

sub include { dry_note("include"); }

#  NOTE: fork() is deliberately NOT stubbed here.  Sleep ships its own
#  fork (sleep/bridges/BasicIO$fork) which runs a closure on a
#  background thread; defining a sub named fork shadows the built in
#  and the pump dies silently.
"""

# The driver runs after the agent's boot code.  It exercises the
# transport and the deny list through the real queue files.
#
# NOTE: request bodies are built as plain strings.  A Sleep hash literal
# keeps the quotes on string keys (%("token" => x) iterates with the key
# "token" INCLUDING the quotes), which silently breaks key lookup.
DRIVER = r"""
# ------------------------------ driver --------------------------------
sub dry_req {
    ($tool, $extra) = @_;
    $dir = agent_dir();
    $id = "dry" . now_ms() . rand(1000);
    $body = "TOOL\t" . $tool . "\n" . $extra . "END\n";
    write_text($dir . "/inbox/" . $id . ".req", $body);
    append_text($dir . "/inbox/queue.txt", $id . "\n");
    $waited = 0;
    while ($waited < 100) {
        if (file_exists($dir . "/outbox/" . $id . ".res") == 1) {
            return @($id, read_text($dir . "/outbox/" . $id . ".res"));
        }
        sleep_ms(50);
        $waited = $waited + 1;
    }
    return @($id, "TIMEOUT");
}

$TOK = agent_token();

println("=== DRYRUN: status request ===");
($s1, $r1) = dry_req("status", "ARG\ttoken\t" . esc($TOK) . "\n");
println($r1);

println("=== DRYRUN: denied command ===");
($s2, $r2) = dry_req("task", "ARG\ttoken\t" . esc($TOK) . "\nARG\tbid\t12345\nARG\tcmd\tshell whoami\n");
println($r2);

println("=== DRYRUN: built-in blockdlls (must use bblockdlls, not bexecute) ===");
($s3, $r3) = dry_req("task", "ARG\ttoken\t" . esc($TOK) . "\nARG\tbid\t12345\nARG\tcmd\tblockdlls\n");
println($r3);

println("=== DRYRUN: plugin alias (must use fireAlias) ===");
($s3a, $r3a) = dry_req("task", "ARG\ttoken\t" . esc($TOK) . "\nARG\tbid\t12345\nARG\tcmd\tdrycmd hello world\n");
println($r3a);

println("=== DRYRUN: unsupported command (must be refused) ===");
($s3b, $r3b) = dry_req("task", "ARG\ttoken\t" . esc($TOK) . "\nARG\tbid\t12345\nARG\tcmd\tboguscmd\n");
println($r3b);

println("=== DRYRUN: bad token ===");
($s4, $r4) = dry_req("ping", "ARG\ttoken\twrong-token\n");
println($r4);

println("=== DRYRUN: inline_execute ===");
($s5, $r5) = dry_req("inline_execute", "ARG\ttoken\t" . esc($TOK) . "\nARG\tbid\t12345\nARG\tpath\t__OBJECT__\nARG\tentry\tgo\n");
println($r5);

#  A multi column row.  The response must carry every field, not one
#  empty field.
println("=== DRYRUN: multi column row ===");
($s6, $r6) = dry_req("beacons", "ARG\ttoken\t" . esc($TOK) . "\n");
println($r6);

#  A row with SEVERAL arguments.  "(@f) = @_;" would make @f a scalar
#  and foreach over it would silently iterate zero times, producing one
#  empty field and a warning per row.
println("=== DRYRUN: multi argument row ===");
($s7, $r7) = dry_req("plugin_commands", "ARG\ttoken\t" . esc($TOK) . "\n");
println($r7);

#  The queue file is a HINT, not the delivery mechanism: the agent also
#  scans the inbox for request files.  This request is deliberately NOT
#  added to queue.txt, so it only arrives if the scan works.
println("=== DRYRUN: inbox scan (no queue entry) ===");
$dir = agent_dir();
$sid = "scan" . now_ms() . rand(1000);
$sbody = "TOOL\tping\nARG\ttoken\t" . esc($TOK) . "\nEND\n";
write_text($dir . "/inbox/" . $sid . ".req", $sbody);
$swaited = 0;
$sfound = 0;
while ($swaited < 100) {
    if (file_exists($dir . "/outbox/" . $sid . ".res") == 1) {
        println(read_text($dir . "/outbox/" . $sid . ".res"));
        $sfound = 1;
        break;
    }
    sleep_ms(50);
    $swaited = $swaited + 1;
}
if ($sfound == 0) { println("SCAN TIMEOUT - the request was never picked up"); }

println("=== DRYRUN: tasks seen ===");
println(read_text("__DRY_DIR__/tasks.log"));

[java.lang.System exit: 0];
"""


# ------------------------------------------------------------- utilities --

def strip_aggressor_blocks(src: str) -> str:
    """Remove `on <event> { ... }` and `command <name> { ... }` blocks.

    Those are Aggressor keywords, not Sleep, so the standalone engine
    cannot parse them.  Brace matching is done by counting, which is
    safe because the agent's blocks contain no braces inside strings
    other than the obvious ones.
    """
    out = src
    for header in ("on beacon_initial", "command csagent"):
        while True:
            m = re.search(rf"^[ \t]*{re.escape(header)}\b", out, re.M)
            if not m:
                break
            start = m.start()
            brace = out.find("{", m.end())
            if brace == -1:
                out = out[:start] + f"# stripped: {header}\n" + out[m.end():]
                continue
            depth = 0
            end = None
            for i in range(brace, len(out)):
                if out[i] == "{":
                    depth += 1
                elif out[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            if end is None:
                out = out[:start] + f"# UNTERMINATED: {header}\n"
                break
            out = out[:start] + f"# stripped: {header}\n" + out[end:]
    return out


def strip_alias_wrappers(src: str) -> str:
    """Drop the agent's two AliasManager wrappers.

    Sleep keeps the first definition of a sub, so the prelude's stand-ins
    would never take effect if the real wrappers were present.
    """
    for name in ("is_plugin_alias", "fire_plugin_alias"):
        src = re.sub(
            rf"(?m)^sub {name} \{{[^}}]*\}}\n?",
            "",
            src,
        )
    return src


def parse_status(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("DATA\t"):
            parts = line.split("\t", 2)
            if len(parts) == 3:
                out[parts[1]] = parts[2]
    return out


def unesc(s: str) -> str:
    return (
        s.replace("\\t", "\t")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\\\", "\\")
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--object", default=None, help="a .o file to load through inline_execute")
    ap.add_argument("--agent", default=None, help="an alternative agent script to test")
    ap.add_argument("--keep", action="store_true", help="keep the sandbox")
    args = ap.parse_args()

    agent_path = Path(args.agent) if args.agent else AGENT
    if not JAR.exists():
        print(f"FAIL: CS jar not found at {JAR}")
        return 2
    if not agent_path.exists():
        print(f"FAIL: agent not found at {agent_path}")
        return 2

    obj = args.object
    if obj is None:
        cand = Path(os.environ.get("CS_MCP_CORPUS", "."))/"wsl"/"BusyBOF"/"pwd.o"
        for p in sorted(Path(os.environ.get("CS_MCP_CORPUS", ".")).rglob("pwd.o")):
            cand = p
            break
        obj = str(cand)
    if not Path(obj).exists():
        print(f"FAIL: object not found: {obj}")
        return 2

    if SANDBOX.exists():
        shutil.rmtree(SANDBOX)
    (SANDBOX / "inbox").mkdir(parents=True)
    (SANDBOX / "outbox").mkdir(parents=True)

    src = agent_path.read_text(encoding="utf-8")
    src = strip_aggressor_blocks(src)
    src = strip_alias_wrappers(src)
    prelude = PRELUDE.replace("__DRY_DIR__", str(SANDBOX))
    driver = DRIVER.replace("__OBJECT__", obj).replace("__DRY_DIR__", str(SANDBOX))
    script = prelude + "\n" + src + "\n" + driver

    script_path = SANDBOX / "agent_dry.cna"
    script_path.write_text(script, encoding="utf-8")

    print(f"[*] script: {script_path} ({len(script)} bytes)")
    print(f"[*] object: {obj} ({Path(obj).stat().st_size} bytes)")
    print("[*] running standalone Sleep engine ...\n")

    env = dict(os.environ)
    env["CLASSPATH"] = str(JAR)
    proc = subprocess.run(
        ["java", f"-Dcs.mcp.dir={SANDBOX}", "-cp", str(JAR), "sleep.console.TextConsole", str(script_path)],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    out = proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr.strip() else "")
    print(out[:12000])
    print(f"[*] engine exit code: {proc.returncode}")

    print("\n=== RESULTS ===")
    ok = True

    # 1. parse / boot
    status = parse_status(SANDBOX / "agent.status")
    for key in (
        "agent_version",
        "read_strategy",
        "probe_read_match",
        "bin_read_len",
        "bin_read_match",
        "exists_missing",
        "hash_pairs",
        "aggressor_ok",
        "beacon_count",
        "bof_pack_ok",
        "selftest",
        "mode",
    ):
        print(f"  {key:22} = {status.get(key, '<missing>')}")

    if status.get("selftest") != "pass":
        print("  !! agent selftest did not pass")
        ok = False
    if status.get("probe_read_match") != "1":
        print("  !! text read round trip failed")
        ok = False
    if status.get("aggressor_ok") != "1":
        print("  !! aggressor probe failed")
        ok = False

    # 2. deny list
    if "blocked by agent hard-deny policy" not in out:
        print("  !! hard deny list did not block 'shell whoami'")
        ok = False
    else:
        print("  hard deny list      : OK (shell blocked)")

    # 3. built-in and plugin commands reached the RIGHT stubs
    tasks_path = SANDBOX / "tasks.log"
    tasks = tasks_path.read_text(encoding="utf-8", errors="replace") if tasks_path.exists() else ""
    if "bexecute" in tasks:
        print("  !! a command was sent through bexecute() (program spawn)")
        ok = False
    elif "bblockdlls 12345 1" not in tasks:
        print("  !! blockdlls did not reach the built-in bridge")
        print(f"     tasks.log = {tasks!r}")
        ok = False
    elif "fireAlias 12345 drycmd hello world" not in tasks:
        print("  !! plugin command did not reach fireAlias()")
        print(f"     tasks.log = {tasks!r}")
        ok = False
    else:
        print("  routing              : OK (blockdlls -> bridge, plugin -> fireAlias)")

    # 4. auth
    if "invalid or missing token" not in out:
        print("  !! bad token was not rejected")
        ok = False
    else:
        print("  token auth          : OK (bad token rejected)")

    # 4b. inbox scan: a request with no queue entry must still be found
    scan_block = ""
    if "=== DRYRUN: inbox scan (no queue entry) ===" in out:
        scan_block = out.split("=== DRYRUN: inbox scan (no queue entry) ===", 1)[1]
        scan_block = scan_block.split("=== DRYRUN: tasks seen ===", 1)[0]
    if "SCAN TIMEOUT" in scan_block:
        print("  !! inbox scan did not pick up a request without a queue entry")
        ok = False
    elif "STATUS\tok" in scan_block:
        print("  inbox scan          : OK (request found without a queue entry)")
    else:
        print("  !! inbox scan produced no answer")
        ok = False

    # 4c. multi column rows must keep every field
    row_block = ""
    if "=== DRYRUN: multi column row ===" in out:
        row_block = out.split("=== DRYRUN: multi column row ===", 1)[1]
        row_block = row_block.split("=== DRYRUN:", 1)[0]
    row_lines = [ln for ln in row_block.splitlines() if ln.startswith("ROW\t")]
    if not row_lines:
        print("  !! no ROW line in the beacons response")
        ok = False
    else:
        fields = row_lines[0].split("\t")[1:]
        if len(fields) < 10 or not fields[0].strip() or not fields[4].strip():
            print(f"  !! row has {len(fields)} field(s), first={fields[:2]!r} - columns were lost")
            ok = False
        else:
            print(f"  multi column row    : OK ({len(fields)} fields, id={fields[0]})")

    # 4d. a row built from SEVERAL arguments must keep all of them
    arg_block = ""
    if "=== DRYRUN: multi argument row ===" in out:
        arg_block = out.split("=== DRYRUN: multi argument row ===", 1)[1]
        arg_block = arg_block.split("=== DRYRUN:", 1)[0]
    arg_rows = [ln for ln in arg_block.splitlines() if ln.startswith("ROW\t")]
    if not arg_rows:
        print("  !! no ROW line in the plugin_commands response")
        ok = False
    else:
        fields = arg_rows[0].split("\t")[1:]
        if len(fields) < 3 or not fields[0].strip() or not fields[1].strip():
            print(f"  !! argument row has {len(fields)} field(s), {fields[:3]!r} - arguments were lost")
            ok = False
        else:
            print(f"  multi argument row  : OK ({len(fields)} fields, name={fields[0]})")

    # 4e. no foreach warnings anywhere
    if "Attempted to use foreach on non-array" in out:
        print("  !! the engine reported a foreach on a non-array")
        for ln in out.splitlines():
            if "foreach on non-array" in ln:
                print(f"     {ln.strip()[:120]}")
                break
        ok = False
    else:
        print("  no foreach warnings : OK")

    # 5. byte exact object load
    rx = SANDBOX / "inline_rx.bin"
    if not rx.exists():
        print("  !! inline_execute never delivered bytes to the stub")
        ok = False
    else:
        got = rx.read_bytes()
        want = Path(obj).read_bytes()
        if got == want:
            print(f"  byte exact .o load  : OK ({len(got)} bytes identical)")
        else:
            print(f"  !! .o load differs: got {len(got)} bytes, want {len(want)}")
            for i, (a, b) in enumerate(zip(got, want)):
                if a != b:
                    print(f"     first difference at offset {i}: {a} != {b}")
                    break
            ok = False

    meta = SANDBOX / "inline_meta.txt"
    if meta.exists():
        print("  inline metadata     :")
        for line in meta.read_text().splitlines():
            print(f"      {line}")

    if not args.keep and ok:
        shutil.rmtree(SANDBOX, ignore_errors=True)

    print("\n" + ("DRY RUN PASS" if ok else "DRY RUN FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
