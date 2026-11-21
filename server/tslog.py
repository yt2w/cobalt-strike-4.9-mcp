"""
Team Server log reader - the output capture channel for CS 4.9.

Cobalt Strike 4.9 has NO "beacon_output" Aggressor event (the string
does not exist anywhere in the client jar; the only beacon event is
"beacon_initial"), so task output cannot be captured from inside the
client.  It CAN be captured from the Team Server side: the server
writes a full transcript of every session to

    <ts logs>/<yymmdd>/<ip>/beacon_<session id>.log

with one timestamped line per event:

    10/28 15:35:08 UTC [metadata] 203.0.113.1 <- 192.0.2.10; ... pid: 12345; ...
    10/28 15:35:20 UTC [input] <operator> whoami
    10/28 15:35:21 UTC [task] <T1033> Tasked beacon to run: whoami
    10/28 15:35:25 UTC [output]
    example\\user\\host

The [output] marker is followed by the raw output lines until the next
timestamped line.

The Team Server's internal session id (the beacon_<id>.log file name)
is NOT the Cobalt Strike beacon id the operator sees.  They are linked
through the [metadata] line, whose "pid:" field IS the CS beacon id,
because a CS beacon id is the pid of the process it is running in.

This module is read only.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DEFAULT_TS_LOG_DIR = Path(
    os.environ.get(
        "CS_TS_LOG_DIR", os.path.expanduser("~/cobaltstrike/cobaltstrike/Server/logs")
    )
)

# 10/28 15:35:08 UTC [output] rest of the line
_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\s+\w+)?)\s+\[(?P<kind>[a-z_]+)\]\s?(?P<body>.*)$"
)
_PID_RE = re.compile(r"\bpid:\s*(\d+)\b")
_IP_RE = re.compile(r"<-\s*(\d{1,3}(?:\.\d{1,3}){3})")


def _parse_ts(text: str, now: datetime | None = None) -> int:
    """MM/DD HH:MM:SS UTC -> epoch millis.  Returns 0 when unparsable.

    The Team Server does not write the year, so the current year is
    assumed.  A log line that would land in the future is therefore
    last year (the log folders are named yymmdd, and a session that
    straddles New Year keeps writing into the old folder).
    """
    text = text.strip()
    reference = now or datetime.now(timezone.utc)
    for fmt in ("%m/%d %H:%M:%S %Z", "%m/%d %H:%M:%S"):
        try:
            naive = datetime.strptime(text, fmt)
        except ValueError:
            continue
        candidate = naive.replace(year=reference.year, tzinfo=timezone.utc)
        if candidate > reference + timedelta(days=1):
            candidate = candidate.replace(year=reference.year - 1)
        return int(candidate.timestamp() * 1000)
    return 0


class TSLogReader:
    """Read-only access to the Team Server session transcripts."""

    def __init__(self, root: Path | str | None = None):
        self.root = Path(root or DEFAULT_TS_LOG_DIR)
        self._index_cache: dict[str, Any] = {}
        self._index_time = 0.0

    # ------------------------------------------------------------------
    # locating logs
    # ------------------------------------------------------------------
    def day_dirs(self, lookback_days: int = 3) -> list[Path]:
        """Session log directories for the last N days, newest first."""
        if not self.root.exists():
            return []
        out: list[Path] = []
        today = datetime.now(timezone.utc)
        for i in range(lookback_days):
            day = today.fromtimestamp(today.timestamp() - i * 86400, tz=timezone.utc)
            # the server names the folder yymmdd, but it can roll over
            # local midnight, so also look at the previous day
            for stamp in (day, day.fromtimestamp(day.timestamp() - 86400, tz=timezone.utc)):
                name = stamp.strftime("%y%m%d")
                p = self.root / name
                if p.exists() and p.is_dir() and p not in out:
                    out.append(p)
        # also include any folder that exists but is not in the window
        return out

    def beacon_logs(self, lookback_days: int = 3) -> list[Path]:
        logs: list[Path] = []
        for d in self.day_dirs(lookback_days):
            for p in d.rglob("beacon_*.log"):
                try:
                    if p.is_file():
                        logs.append(p)
                except OSError:
                    continue
        logs.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        return logs

    def _metadata(self, path: Path) -> dict[str, Any]:
        """First [metadata] line of a session log."""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for _ in range(40):
                    line = fh.readline()
                    if not line:
                        break
                    if "[metadata]" in line:
                        body = line.split("[metadata]", 1)[1].strip()
                        pid = _PID_RE.search(body)
                        ip = _IP_RE.search(body)
                        return {
                            "pid": int(pid.group(1)) if pid else 0,
                            "ip": ip.group(1) if ip else "",
                            "raw": body,
                        }
        except OSError:
            pass
        return {"pid": 0, "ip": "", "raw": ""}

    def find_beacon_log(self, bid: str | int) -> Path | None:
        """Locate the session log whose metadata pid matches the CS beacon id."""
        try:
            want = int(str(bid).strip())
        except (TypeError, ValueError):
            return None
        # cache for a few seconds: the mapping is stable
        now = time.time()
        if self._index_time and now - self._index_time < 15:
            hit = self._index_cache.get(str(want))
            if hit:
                p = Path(hit)
                return p if p.exists() else None
        for p in self.beacon_logs():
            meta = self._metadata(p)
            if meta["pid"] == want:
                self._index_cache[str(want)] = str(p)
                self._index_time = now
                return p
        self._index_time = now
        return None

    # ------------------------------------------------------------------
    # parsing
    # ------------------------------------------------------------------
    @staticmethod
    def parse_events(text: str) -> list[dict[str, Any]]:
        """Split a session log into events.

        An [output] marker owns the following un-timestamped lines; they
        are attached to it as "lines".
        """
        events: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        for raw in text.splitlines():
            m = _LINE_RE.match(raw)
            if m:
                current = {
                    "ts": _parse_ts(m.group("ts")),
                    "ts_text": m.group("ts"),
                    "kind": m.group("kind"),
                    "body": m.group("body"),
                    "lines": [],
                }
                events.append(current)
                continue
            if current is not None and current["kind"] == "output" and raw.strip():
                current["lines"].append(raw)
        return events

    def read_events(self, bid: str | int) -> list[dict[str, Any]]:
        path = self.find_beacon_log(bid)
        if path is None:
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return self.parse_events(text)

    def read_output(self, bid: str | int, since_ms: int = 0) -> list[dict[str, Any]]:
        """Output blocks for a beacon, newest last."""
        out: list[dict[str, Any]] = []
        for ev in self.read_events(bid):
            if ev["kind"] != "output":
                continue
            if since_ms and ev["ts"] and ev["ts"] < since_ms:
                continue
            body = "\n".join(ev["lines"]).strip()
            if not body and ev["body"]:
                body = ev["body"].strip()
            out.append({"ts": ev["ts"], "bid": str(bid), "text": body})
        return out

    def transcript(self, bid: str | int, limit: int = 200) -> list[dict[str, Any]]:
        """Recent activity for a beacon, whatever the event kind."""
        events = self.read_events(bid)
        return events[-limit:]

    def session_map(self) -> list[dict[str, Any]]:
        """Every session log found, with its CS beacon id when known."""
        rows: list[dict[str, Any]] = []
        for p in self.beacon_logs():
            meta = self._metadata(p)
            try:
                mtime = int(p.stat().st_mtime)
            except OSError:
                mtime = 0
            rows.append(
                {
                    "path": str(p),
                    "bid": str(meta["pid"]) if meta["pid"] else "",
                    "ip": meta["ip"],
                    "metadata": meta["raw"],
                    "mtime": mtime,
                }
            )
        return rows

    def available(self) -> bool:
        return self.root.exists()
