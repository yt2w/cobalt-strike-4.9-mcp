"""
Registry for the Cobalt Strike MCP server.

Holds three things:

  * the BOF inventory  - what custom BOFs exist on this box, with a
    static risk classification for each one
  * the kit inventory  - what custom .cna plugins exist and which beacon
    commands each of them registers
  * operator state     - quarantine, risk annotations and observed
    beacon deaths, persisted so the server learns across sessions

State file: ~/.cs-mcp-4.9/registry.json
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

STATE_DIR = Path(os.environ.get("CS_MCP_STATE_DIR", Path.home() / ".cs-mcp-4.9"))
CORPUS_ROOT = Path(os.environ.get("CS_MCP_CORPUS", os.path.expanduser("~/Abofs")))

# fallback signatures used when the full scanner module is not installed
_FALLBACK_SIGNATURES: dict[str, tuple[str, str]] = {
    "process_injection": (r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection", "high"),
    "defense_evasion": (r"AmsiScanBuffer|EtwEventWrite|UnhookDll|NtTraceEvent", "high"),
    "process_execution": (r"CreateProcess|WinExec|ShellExecute|powershell|cmd\.exe", "high"),
    "credential_access": (r"lsass|sekurlsa|wdigest|MiniDumpWriteDump|OpenProcess", "medium"),
    "privilege_escalation": (r"AdjustTokenPrivileges|SeDebugPrivilege|DuplicateToken", "medium"),
    "persistence": (r"RegSetValueEx|CreateService|schtasks", "medium"),
    "anti_forensics": (r"SetFileTime|ClearEventLog|wevtutil", "medium"),
    "artifact_on_disk": (r"CreateFile|WriteFile|fopen|ofstream", "low"),
    "network": (r"WSAStartup|InternetOpen|WinHttpOpen", "low"),
    "discovery": (r"CreateToolhelp32Snapshot|GetAdaptersInfo|NetUserEnum", "low"),
}

_CMD_RE = re.compile(r"""beacon_command_register\s*\(\s*["']([^"']+)["']""")
_ALIAS_RE = re.compile(r"""^\s*alias\s+([A-Za-z0-9_\-]+)\s*\{""", re.M)
_SUB_RE = re.compile(r"""^\s*sub\s+([A-Za-z0-9_\-]+)\s*\{""", re.M)


def _is_elf(path: Path) -> bool:
    """True for Linux ELF objects.

    81 of the corpus objects are Linux relocatables (the wsl, Kit and
    Bypass-Protection0x00 kits).  They cannot be run through a Windows
    beacon's inline_execute, so they must not be offered as runnable
    Windows BOFs.
    """
    try:
        with path.open("rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _sha256(path: Path) -> str:
    try:
        import hashlib

        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


class Registry:
    def __init__(self, corpus_root: Path | str | None = None, state_dir: Path | str | None = None):
        self.corpus = Path(corpus_root or CORPUS_ROOT)
        self.state_dir = Path(state_dir or STATE_DIR)
        self.state_path = self.state_dir / "registry.json"
        self.inventory_path = self.state_dir / "inventory.json"
        self.state: dict[str, Any] = {
            "quarantine": {},
            "annotations": {},
            "observed_kills": {},
            "seen_sessions": [],
        }
        self._bofs: list[dict[str, Any]] | None = None
        self._kits: list[dict[str, Any]] | None = None
        self._scanner: Any = None
        self.load()

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def load(self) -> None:
        try:
            if self.state_path.exists():
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self.state.update(data)
        except (OSError, ValueError):
            pass
        for key in ("quarantine", "annotations", "observed_kills"):
            if not isinstance(self.state.get(key), dict):
                self.state[key] = {}
        if not isinstance(self.state.get("seen_sessions"), list):
            self.state["seen_sessions"] = []

    def save(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.state_path)

    # ------------------------------------------------------------------
    # operator state
    # ------------------------------------------------------------------
    def is_quarantined(self, key: str) -> bool:
        return key in self.state["quarantine"]

    def quarantine_reason(self, key: str) -> str:
        return str(self.state["quarantine"].get(key, {}).get("reason", ""))

    def quarantine(self, key: str, reason: str) -> dict[str, Any]:
        self.state["quarantine"][key] = {"reason": reason, "ts": int(time.time() * 1000)}
        self.save()
        return self.state["quarantine"][key]

    def unquarantine(self, key: str) -> bool:
        if key in self.state["quarantine"]:
            del self.state["quarantine"][key]
            self.save()
            return True
        return False

    def annotate(self, key: str, risk: str, note: str) -> dict[str, Any]:
        self.state["annotations"][key] = {"risk": risk, "note": note, "ts": int(time.time() * 1000)}
        self.save()
        return self.state["annotations"][key]

    def record_kill(self, key: str, detail: str = "") -> int:
        rec = self.state["observed_kills"].setdefault(key, {"count": 0, "events": []})
        rec["count"] = int(rec.get("count", 0)) + 1
        rec.setdefault("events", []).append({"ts": int(time.time() * 1000), "detail": detail})
        # an observed death is a quarantine, full stop
        self.state["quarantine"][key] = {
            "reason": f"observed beacon death: {detail}" if detail else "observed beacon death",
            "ts": int(time.time() * 1000),
        }
        self.save()
        return int(rec["count"])

    def kill_count(self, key: str) -> int:
        return int(self.state["observed_kills"].get(key, {}).get("count", 0))

    # ------------------------------------------------------------------
    # BOF inventory
    # ------------------------------------------------------------------
    def _load_scanner(self) -> Any:
        if self._scanner is not None:
            return self._scanner
        try:
            import importlib.util

            cand = Path(__file__).with_name("bof_scanner.py")
            if cand.exists():
                spec = importlib.util.spec_from_file_location("bof_scanner", cand)
                mod = importlib.util.module_from_spec(spec)
                assert spec.loader is not None
                spec.loader.exec_module(mod)
                self._scanner = mod
        except Exception:
            self._scanner = False
        return self._scanner

    def _fallback_scan(self, path: Path) -> dict[str, Any]:
        try:
            data = path.read_bytes()
        except OSError:
            return {"path": str(path), "risk": "unknown", "score": 0, "categories": [], "reasons": []}
        try:
            text = data.decode("latin-1", errors="ignore")
        except Exception:
            text = ""
        cats: list[str] = []
        reasons: list[str] = []
        score = 0
        for cat, (pattern, sev) in _FALLBACK_SIGNATURES.items():
            if re.search(pattern, text, re.IGNORECASE):
                cats.append(cat)
                reasons.append(f"{cat}: matched {pattern}")
                score += {"high": 40, "medium": 20, "low": 5}[sev]
        if score >= 80:
            risk = "critical"
        elif score >= 40:
            risk = "high"
        elif score >= 15:
            risk = "medium"
        else:
            risk = "low"
        return {
            "path": str(path),
            "name": path.name,
            "risk": risk,
            "score": score,
            "categories": cats,
            "reasons": reasons,
        }

    def build_inventory(self, refresh: bool = False) -> list[dict[str, Any]]:
        """Scan the corpus for BOF objects and classify them.

        The scanner prefers a source sibling over the compiled object, but
        keeps findings that only the object reveals (many kits spread their
        implementation over several files, so a single source file
        under-reports what the object actually does).
        """
        if self._bofs is not None and not refresh:
            return self._bofs

        cached: list[dict[str, Any]] = []
        if self.inventory_path.exists() and not refresh:
            try:
                cached = json.loads(self.inventory_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                cached = []

        if cached:
            self._bofs = cached
            return self._bofs

        scanner = self._load_scanner()
        entries: list[dict[str, Any]] = []
        objs = sorted(self.corpus.rglob("*.o")) if self.corpus.exists() else []
        for obj in objs:
            try:
                size = obj.stat().st_size
            except OSError:
                size = 0
            if scanner and scanner is not False:
                try:
                    res = scanner.scan_bof(str(obj), str(self.corpus))
                    cls = res.get("classification", {})
                    entry = {
                        "path": str(obj),
                        "name": obj.name,
                        "kit": obj.parent.name,
                        "size": size,
                        "risk": cls.get("risk", "medium"),
                        "score": cls.get("score", 0),
                        "categories": cls.get("categories", []),
                        "reasons": cls.get("reasons", []),
                        "has_source": bool(res.get("source_path")),
                        "source_path": res.get("source_path"),
                        "scan_kind": res.get("kind", "object"),
                        "object_only_rules": res.get("object_only_rules", []),
                        "is_elf": _is_elf(obj),
                        "sha256": _sha256(obj),
                    }
                except Exception:
                    entry = self._fallback_scan(obj)
                    entry.update(
                        {"name": obj.name, "kit": obj.parent.name, "size": size, "is_elf": _is_elf(obj)}
                    )
            else:
                entry = self._fallback_scan(obj)
                entry.update(
                    {"name": obj.name, "kit": obj.parent.name, "size": size, "is_elf": _is_elf(obj)}
                )
            entries.append(entry)

        self._bofs = entries
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            self.inventory_path.write_text(json.dumps(entries, indent=1), encoding="utf-8")
        except OSError:
            pass
        return self._bofs

    def bof_by_path(self, path: str) -> dict[str, Any] | None:
        for b in self.build_inventory():
            if b.get("path") == path:
                return b
        # allow matching by basename
        base = os.path.basename(path)
        matches = [b for b in self.build_inventory() if b.get("name") == base]
        return matches[0] if len(matches) == 1 else None

    # ------------------------------------------------------------------
    # kit inventory (.cna plugins)
    # ------------------------------------------------------------------
    def build_kits(self, refresh: bool = False) -> list[dict[str, Any]]:
        if self._kits is not None and not refresh:
            return self._kits
        kits: list[dict[str, Any]] = []
        if self.corpus.exists():
            for cna in sorted(self.corpus.rglob("*.cna")):
                try:
                    text = cna.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                cmds = sorted(set(_CMD_RE.findall(text)))
                aliases = sorted(set(_ALIAS_RE.findall(text)))
                subs = sorted(set(_SUB_RE.findall(text)))
                kits.append(
                    {
                        "path": str(cna),
                        "name": cna.name,
                        "kit": cna.parent.name,
                        "size": cna.stat().st_size,
                        "commands": cmds,
                        "aliases": aliases,
                        "functions": subs,
                        "mtime": int(cna.stat().st_mtime),
                    }
                )
        self._kits = kits
        return kits

    def kit_by_path(self, path: str) -> dict[str, Any] | None:
        for k in self.build_kits():
            if k["path"] == path:
                return k
        return None
