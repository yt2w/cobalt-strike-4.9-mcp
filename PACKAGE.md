# cs-mcp-4.9 — GitHub package

Clean source copy of the Cobalt Strike 4.9 MCP bridge.

## Included
- README.md, install.sh
- agent/cs_agent.cna (Sleep/Aggressor agent, 4.9)
- server/*.py (MCP server, policy, transport, BOF scanner, registry, EDR, tslog)
- tools/*.py, tools/*.sh (selftest, dryrun, testsuite, probe, lifetime, reconnect, watchers, patch script)
- .gitignore

## Excluded (deliberately)
- ~/.cs-mcp-4.9/ engagement state: audit.log, inventory.json, targets.json
- spool state: tokens, inbox/outbox, logs, probe files, .env, keys/certs
- all __pycache__ / *.pyc

The agent reads its shared token from a Java property or generates it on first
load; no live token or credential is stored in this package.

## Quick start
1. Copy this directory to your WSL/CS host.
2. Run `./install.sh` (configure paths/listener as needed).
3. Load `agent/cs_agent.cna` in the Cobalt Strike client (Script Manager), or
   use `tools/patch_client_jar.sh` to autoload it on client start.
4. Point your MCP client (e.g. OpenCode) at `server/cs_mcp_server.py` via stdio.
