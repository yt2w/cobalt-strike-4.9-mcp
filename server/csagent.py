"""
Transport to the Cobalt Strike side agent (cs_agent.cna).

The agent runs inside the Cobalt Strike client JVM and speaks a dumb
line protocol over a spool directory.  All of the smart stuff (JSON,
policy, risk scoring) lives here in Python where it is testable.

Wire format (tab separated, values escaped with \\t \\n \\r \\\\):

    request  inbox/<id>.req      TOOL<TAB>name / ARG<TAB>key<TAB>value / END
    response outbox/<id>.res     STATUS<TAB>ok|error / MSG / DATA / ROW / END
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.environ.get("CS_MCP_DIR", "/tmp/cs-mcp-4.9"))
DEFAULT_TIMEOUT = float(os.environ.get("CS_MCP_TIMEOUT", "45"))


def _esc(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _unesc(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "t":
                out.append("\t")
            elif nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt == "\\":
                out.append("\\")
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


@dataclass
class AgentResponse:
    ok: bool
    message: str = ""
    data: dict[str, str] = field(default_factory=dict)
    rows: list[list[str]] = field(default_factory=list)

    def get(self, key: str, default: str = "") -> str:
        return self.data.get(key, default)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "message": self.message,
            "data": self.data,
            "rows": self.rows,
        }


class AgentError(RuntimeError):
    """Raised when the agent is unreachable or returns an error envelope."""


class AgentClient:
    """Client for the spool-based CS side agent."""

    def __init__(self, base_dir: Path | str | None = None, timeout: float | None = None):
        self.base = Path(base_dir or DEFAULT_DIR)
        self.inbox = self.base / "inbox"
        self.outbox = self.base / "outbox"
        self.timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        self._token: str | None = None
        self.last_queue_error: str = ""

    # ------------------------------------------------------------------
    # setup
    # ------------------------------------------------------------------
    def ensure_dirs(self) -> None:
        """Create the spool dirs.  Called by the installer, harmless to repeat.

        The Cobalt Strike client runs as root and this server does not, so
        the two shared directories have to be writable by BOTH.  The base
        directory only needs to be readable (the token and the status files
        live there), but inbox and outbox must be world writable.
        """
        for d in (self.base, self.inbox, self.outbox):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        for d, mode in ((self.base, 0o755), (self.inbox, 0o777), (self.outbox, 0o777)):
            try:
                os.chmod(d, mode)
            except OSError:
                # not ours (the client created it as root) - the agent
                # relaxes those permissions on its side
                pass

    @property
    def token(self) -> str:
        # re-read every time: the agent regenerates its token on load, and a
        # stale cached token shows up as a confusing 401
        p = self.base / "agent.token"
        if not p.exists():
            raise AgentError(
                f"no agent token at {p} - the CS agent has not been loaded into the "
                "Cobalt Strike client yet (Script Manager -> Load -> agent/cs_agent.cna)"
            )
        token = p.read_text(encoding="utf-8", errors="replace").strip()
        if not token:
            raise AgentError(f"agent token at {p} is empty - the agent is still loading or failed")
        self._token = token
        return token

    def agent_status(self) -> dict[str, str]:
        """Parsed agent status.

        agent.status is append-only (one DATA line per fact, last value
        wins) so the forked pump thread and the main script can both write
        to it without fighting over a buffer.  agent.heartbeat is
        overwritten on every pump pass.
        """
        out: dict[str, str] = {}
        for name in ("agent.status", "agent.heartbeat"):
            p = self.base / name
            if not p.exists():
                continue
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("DATA\t"):
                    parts = line.split("\t", 2)
                    if len(parts) == 3:
                        out[parts[1]] = _unesc(parts[2])
        return out

    # ------------------------------------------------------------------
    # request / response
    # ------------------------------------------------------------------
    def _repair_queue(self) -> bool:
        """Replace a queue file we cannot append to.

        The Cobalt Strike client runs as root, so it may have created
        inbox/queue.txt as root:root 0644.  This process cannot append to
        that, but it CAN replace it: rename/unlink only needs write
        permission on the DIRECTORY, which belongs to the operator.
        The content is preserved so no queued request id is lost.
        """
        queue = self.inbox / "queue.txt"
        try:
            content = queue.read_text(encoding="utf-8", errors="replace") if queue.exists() else ""
        except OSError:
            content = ""
        tmp = self.inbox / f".queue.repair.{os.getpid()}"
        try:
            tmp.write_text(content, encoding="utf-8")
            os.chmod(tmp, 0o666)
            os.replace(tmp, queue)
            return True
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    def call(self, tool: str, args: dict[str, Any] | None = None, timeout: float | None = None) -> AgentResponse:
        args = dict(args or {})
        args["token"] = self.token

        req_id = uuid.uuid4().hex
        body = [f"TOOL\t{tool}"]
        for k, v in args.items():
            body.append(f"ARG\t{k}\t{_esc(v)}")
        body.append("END")

        req_path = self.inbox / f"{req_id}.req"
        res_path = self.outbox / f"{req_id}.res"
        tmp_path = self.inbox / f".{req_id}.tmp"
        tmp_path.write_text("\n".join(body) + "\n", encoding="utf-8")
        os.replace(tmp_path, req_path)  # atomic: the agent never sees a partial file

        # Publish the id in the queue.  This is a HINT, not the delivery
        # mechanism: the agent also scans the inbox for request files, so
        # a queue file that the CS client created as root (and therefore
        # made unappendable for this process) does not break the
        # transport.  If the append fails, the request is still picked up.
        queue = self.inbox / "queue.txt"
        try:
            with open(queue, "a", encoding="utf-8") as qf:
                qf.write(req_id + "\n")
                qf.flush()
                os.fsync(qf.fileno())
        except OSError as exc:
            self.last_queue_error = str(exc)
            # Try once to take the queue file back, then retry the append.
            # Even if that fails the request is still delivered: the agent
            # scans the inbox for request files.
            if self._repair_queue():
                try:
                    with open(queue, "a", encoding="utf-8") as qf:
                        qf.write(req_id + "\n")
                        qf.flush()
                        os.fsync(qf.fileno())
                    self.last_queue_error = ""
                except OSError as exc2:
                    self.last_queue_error = str(exc2)

        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while time.time() < deadline:
            if res_path.exists():
                # the agent writes the file directly, so wait for the END marker
                text = res_path.read_text(encoding="utf-8", errors="replace")
                if "END\n" in text or text.rstrip().endswith("END"):
                    resp = self._parse(text)
                    try:
                        req_path.unlink(missing_ok=True)
                        res_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    return resp
            time.sleep(0.05)

        raise AgentError(
            f"agent did not answer '{tool}' within {timeout or self.timeout:.0f}s. "
            f"Is the CS client running with agent/cs_agent.cna loaded? "
            f"(status file: {self.base / 'agent.status'})"
        )

    @staticmethod
    def _parse(text: str) -> AgentResponse:
        ok = False
        message = ""
        data: dict[str, str] = {}
        rows: list[list[str]] = []
        for line in text.splitlines():
            if not line:
                continue
            parts = line.split("\t")
            kind = parts[0]
            if kind == "STATUS" and len(parts) >= 2:
                ok = parts[1] == "ok"
            elif kind == "MSG" and len(parts) >= 2:
                message = _unesc(parts[1])
            elif kind == "DATA" and len(parts) >= 3:
                data[parts[1]] = _unesc(parts[2])
            elif kind == "ROW" and len(parts) >= 2:
                rows.append([_unesc(p) for p in parts[1:]])
        return AgentResponse(ok=ok, message=message, data=data, rows=rows)

    # ------------------------------------------------------------------
    # beacon output capture
    # ------------------------------------------------------------------
    def read_output(self, bid: str | None = None, since_ms: int = 0) -> list[dict[str, Any]]:
        """Beacon output captured by the agent's on beacon_output handler."""
        p = self.base / "output.log"
        if not p.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line:
                continue
            head, _, body = line.partition("\x1f")
            parts = line.split("\x1f", 2)
            if len(parts) < 2:
                continue
            ts, ev_bid = parts[0], parts[1]
            text = parts[2] if len(parts) > 2 else ""
            try:
                ts_i = int(ts)
            except ValueError:
                ts_i = 0
            if ts_i < since_ms:
                continue
            if bid and ev_bid != str(bid):
                continue
            events.append({"ts": ts_i, "bid": ev_bid, "text": text})
        return events

    def output_size(self) -> int:
        p = self.base / "output.log"
        try:
            return p.stat().st_size
        except OSError:
            return 0


if __name__ == "__main__":  # tiny manual probe
    import json
    import sys

    c = AgentClient()
    try:
        print(json.dumps(c.call("ping").as_dict(), indent=2))
        print(json.dumps(c.call("status").as_dict(), indent=2))
    except AgentError as e:
        print(f"agent unreachable: {e}", file=sys.stderr)
        sys.exit(1)
