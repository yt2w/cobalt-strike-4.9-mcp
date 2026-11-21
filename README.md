# cs-mcp-4.9

MCP server for Cobalt Strike 4.9. It drives beacons through the operator's own
`.cna` plugins and `.o` BOFs, and refuses the built-ins that reliably kill
sessions on defended hosts.

## Architecture

```
MCP client  ──stdio──>  server/cs_mcp_server.py
                         policy, risk, EDR, JSON
                              │
                              ▼  spool: inbox/<id>.req, outbox/<id>.res
                         agent/cs_agent.cna
                              │  inside the Cobalt Strike client
                              ▼
                         beacon_inline_execute()
```

Transport is a tab-separated line protocol over a shared spool directory.
Sleep has no JSON parser and no usable sockets. Requests are delivered twice:
via `inbox/queue.txt` and by scanning `inbox/*.req` for files with no `.claim`
marker. The scan is the real mechanism; the queue is a hint, because the CS
client usually runs as root and makes the queue unappendable to the operator.

## Denied built-ins

Refused in two independent layers: `server/policy.py` and a hard deny list in
`agent/cs_agent.cna` (relaxable only with `-Dcs.mcp.allow_denied=1`).

| built-in | telemetry |
|---|---|
| `shell`, `runas` | child process from a signed SYSTEM service |
| `powershell`, `execute-assembly`, `inline-execute` | AMSI, CLR load, 4104 |
| `upload`, `download` | file write/read by the service binary |
| `screenshot` | GDI capture from session 0 |
| `portscan` | connect() sweep |
| `kill`, `rm`, `getuid` | process/file/new-process |

## Risk model

`policy.evaluate_bof()` applies rules in order, first match wins:

1. BOF previously killed a beacon → blocked (`observed-beacon-death`)
2. BOF quarantined → blocked (`quarantine`)
3. EDR present + hot category + critical risk → blocked (`edr-critical`)
4. same, lower risk → allowed, requires acknowledgement
5. static risk critical → blocked (`static-risk`)
6. static risk medium/high → allowed, requires acknowledgement
7. otherwise → allowed

`force=true` overrides rule 3 only. It cannot override quarantine or an
observed beacon death.

Hot categories: `process_hollowing`, `defense_evasion`, `execution`,
`credential_access`, `privilege`, `SLEEP_MASK`, `EXEC_LOADER`.

## Output capture

CS 4.9 has no `beacon_output` event. Output is read from the Team Server
transcript at `<ts logs>/<yymmdd>/<ip>/beacon_<session id>.log`.

The Team Server session id is not the CS beacon id. They are linked via the
`[metadata]` line, whose `pid:` field is the CS beacon id. `server/tslog.py`
does the mapping and parses `[input]`, `[task]` and `[output]` blocks.

Post-flight is 25 seconds. Defender telemetry is batched and correlated, so a
death may surface much later. BOFs correlated with a death are quarantined
permanently.

## EDR awareness

`server/edr.py` parses the signature database out of `edr-enum.cna` (48
vendors, 198 process, 114 service, 132 driver signatures) so the server and
the kit cannot drift.

- `detect_target_edr(bid)` — read only, scans the existing transcript
- `set_target_edr(bid, vendors)` — record known products
- `enumerate_target_edr(bid, mode)` — tasks the beacon

| mode | command | noise | artifacts |
|---|---|---|---|
| `check` | `edr_check` | `*` | none, in-process process list |
| `services_bof` | `edr_services_bof` | `*` | none, in-process BOF |
| `services_pick` | `edr_services_pick` | `**` | no `powershell.exe` |
| `services_cmd` | `edr_services_cmd` | `***` | one `cmd.exe` |
| `full` | `edr_enum` | `****` | PowerShell + WMI, 4104, AMSI |

Use `check` or `services_bof` on defended hosts.

## Configuration

All paths are overridable by environment variable:

| variable | default |
|---|---|
| `CS_MCP_DIR` | `/tmp/cs-mcp-4.9` |
| `CS_MCP_STATE_DIR` | `~/.cs-mcp-4.9` |
| `CS_MCP_CORPUS` | `~/Abofs` |
| `CS_TS_LOG_DIR` | `~/cobaltstrike/cobaltstrike/Server/logs` |
| `CS_MCP_EDR_KIT` | `~/Abofs/CS-EDR-Enumeration/edr-enum.cna` |
| `CS_MCP_POSTFLIGHT_SECONDS` | `25` |
| `CS_JAR` | first `cobaltstrike-client*.jar` under `~/cobaltstrike` |

## Install

```bash
./install.sh                 # spool dirs + register MCP server
./install.sh --no-register   # spool dirs only
```

Load `agent/cs_agent.cna` in the CS client via Script Manager. To autoload it
on every client start, use `tools/patch_client_jar.sh --check` and then apply.

## Tests

```bash
python3 tools/testsuite.py   # offline assertions over the Python stack
python3 tools/dryrun.py      # agent under the real Sleep engine, stubbed API
python3 tools/selftest.py    # live stack check
python3 tools/mcp_probe.py   # MCP handshake + tool list
```

## Tools

`cs_status`, `list_beacons`, `get_beacon`, `beacon_output`,
`list_plugin_commands`, `list_kits`, `load_plugin`, `run_plugin_command`,
`list_bofs`, `bof_info`, `run_bof`, `target_profile`, `set_target_edr`,
`detect_target_edr`, `enumerate_target_edr`, `quarantine_bof`,
`unquarantine_bof`, `annotate_bof`, `policy_status`, `audit_log`.
