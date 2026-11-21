"""
Target-aware endpoint security modelling.

The whole point of this server is that the SAME BOF is safe on one host
and lethal on another.  A process hollowing BOF on a bare Windows box
may be fine; the same BOF on a machine with CrowdStrike Falcon or
SentinelOne is the classic beacon kill.  So the risk decision has to
know what is defending the target.

Two sources of truth:

  1. The operator's own kit, CS-EDR-Enumeration/edr-enum.cna, carries a
     signature database (199 process, 115 service and 132 driver
     signatures across 48 vendors) and a NOISE rating for each of its
     own commands.  This module reads that database straight out of the
     kit so the server and the kit never drift apart.

  2. The per-target profile, persisted in ~/.cs-mcp-4.9/targets.json, says
     what has been observed (or declared by the operator) for a given
     beacon id.

Everything here is read only with respect to the beacon.  Detecting the
EDR does not task the target; running the enumeration kit does, and that
is a separate, explicit decision made by the operator.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

STATE_DIR = Path(os.environ.get("CS_MCP_STATE_DIR", Path.home() / ".cs-mcp-4.9"))
EDR_KIT = Path(
    os.environ.get(
        "CS_MCP_EDR_KIT", os.path.expanduser("~/Abofs/CS-EDR-Enumeration/edr-enum.cna")
    )
)
TARGETS_PATH = STATE_DIR / "targets.json"

#  Signature tables in the kit:  %edr_process_signatures["key"] = "Vendor | Product | CAT";
_SIG_RE = re.compile(
    r'%edr_(?P<table>process|service|driver)_signatures\["(?P<key>[^"]+)"\]\s*=\s*'
    r'"(?P<value>[^"]+)"'
)

#  A line of EDR-ENUM output:  "  [EDR]  CrowdStrike - Falcon  (proc: csfalconcontainer.exe)"
_HIT_RE = re.compile(
    r"\[\s*(?P<cat>EDR|AV|EPP|TEL|OTH)\s*\]\s*(?P<vendor>[^-]+?)\s+-\s+(?P<product>.+?)"
    r"(?:\s+\((?:proc|svc|drv):\s*(?P<key>[^)]+)\))?\s*$"
)

#  Vendor names worth spotting in ANY beacon output, not just EDR-ENUM.
#  Deliberately fuzzy: the agent often prints a service or driver name.
_VENDOR_HINTS: dict[str, list[str]] = {
    "CrowdStrike": ["csfalcon", "falconhost", "csagent", "crowdstrike"],
    "SentinelOne": ["sentinelone", "sentinelagent", "singularity"],
    "Microsoft Defender": ["msmpeng", "sensecnc", "mdeclient", "windows defender"],
    "Carbon Black": ["cbdefense", "carbon black", "repmon"],
    "Tanium": ["tanium", "taniumclient"],
    "Palo Alto Cortex": ["cortex xdr", "panw cortex"],
    "Symantec": ["ccsvchst", "symantec", "sep64bg"],
    "Trend Micro": ["trendmicro", "ntrtscan", "pccntmon"],
    "Kaspersky": ["kaspersky", "avp.exe", "klif"],
    "ESET": ["ekrn", "eset"],
    "Sophos": ["sophos", "savservice"],
    "Cylance": ["cylance", "cyagent"],
    "Fortinet": ["forticlient", "fortiagent", "fortinet"],
    "Check Point": ["checkpoint", "cpview"],
    "Cybereason": ["cybereason", "crs_sensor"],
    "Trellix": ["trellix", "mfemms"],
    "Bitdefender": ["bitdefender", "bdagent"],
    "Malwarebytes": ["malwarebytes", "mbam"],
    "Avast": ["avast", "asw"],
    "Rapid7": ["rapid7", "insight"],
    "Velociraptor": ["velociraptor"],
    "LimaCharlie": ["limacharlie"],
    "Elastic": ["elastic", "winlogbeat"],
    "Splunk": ["splunk"],
    "HarfangLab": ["harfanglab"],
    "Deep Instinct": ["deep instinct"],
    "Huntress": ["huntress"],
    "BlackBerry": ["blackberry", "cysense"],
    "Secureworks": ["secureworks", "ironsight"],
    "Broadcom": ["broadcom"],
    "Endgame": ["endgame", "egrep"],
    "Comodo": ["comodo", "cmdagent"],
    "AhnLab": ["ahnlab"],
    "Avira": ["avira"],
    "G Data": ["g data", "gdata"],
    "Webroot": ["webroot"],
    "Norton": ["norton"],
    "CyberArk": ["cyberark"],
    "Nexthink": ["nexthink"],
    "Cisco Secure Endpoint": ["cisco secure endpoint", "ampagent"],
    "Ivanti": ["ivanti"],
    "Proofpoint": ["proofpoint"],
}

#  How much a vendor raises the floor.  EDR and EPP are endpoint
#  telemetry engines; AV alone is weaker but still hooked.
_VENDOR_WEIGHT = {
    "EDR": "high",
    "EPP": "high",
    "SIEM-EDR": "high",
    "DFIR": "medium",
    "AV": "medium",
    "Telemetry": "low",
}


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def _contains_token(haystack: str, needle: str) -> bool:
    """True when `needle` occurs at a word boundary.

    A plain substring test is useless for security product names: "ns.exe"
    appears inside "Dns.exe" (which would look like Norton) and "essvc"
    inside "MessSvc.exe" (which would look like ESET).  Requiring the
    needle to START at a non alphanumeric boundary removes those, while
    still matching "msmpeng" inside "MsMpEng.exe".
    """
    if not needle:
        return False
    return re.search(r"(?<![a-z0-9._-])" + re.escape(needle.lower()), haystack.lower()) is not None


#  Several names in the kit and in the hint list refer to the same
#  product family.  They are folded together so the profile does not
#  list "Microsoft", "Microsoft Defender" and "Defender for Endpoint" as
#  three separate vendors.
_VENDOR_ALIASES = {
    "microsoft": "Microsoft Defender",
    "microsoft defender": "Microsoft Defender",
    "microsoft defender for endpoint": "Microsoft Defender",
    "defender for endpoint": "Microsoft Defender",
    "windows defender": "Microsoft Defender",
    "broadcom": "Symantec",
    "carbon black": "Carbon Black",
    "vmware carbon black": "Carbon Black",
    "falcon": "CrowdStrike",
    "crowdstrike falcon": "CrowdStrike",
    "sentinel": "SentinelOne",
    "sophos": "Sophos",
    "eset": "ESET",
    "avast": "Avast",
    "avg": "AVG",
    "palo alto cortex": "Palo Alto Cortex",
}


def canonical_vendor(name: str) -> str:
    key = (name or "").strip().lower()
    return _VENDOR_ALIASES.get(key, (name or "").strip())


class EDRSpecDB:
    """The signature database read out of the operator's EDR kit."""

    def __init__(self, kit_path: Path | str | None = None):
        self.kit = Path(kit_path or EDR_KIT)
        self._loaded = False
        self.signatures: dict[str, dict[str, str]] = {
            "process": {},
            "service": {},
            "driver": {},
        }
        self._vendors: set[str] = set()
        self.categories: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            text = self.kit.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        for m in _SIG_RE.finditer(text):
            table = m.group("table")
            key = m.group("key").lower()
            raw = m.group("value")
            parts = [p.strip() for p in raw.split("|")]
            vendor = parts[0] if parts else "Unknown"
            product = parts[1] if len(parts) > 1 else "Unknown"
            cat = parts[2] if len(parts) > 2 else "Unknown"
            self.signatures[table][key] = {
                "vendor": vendor,
                "product": product,
                "category": cat,
                "key": m.group("key"),
            }
            self._vendors.add(vendor)
            self.categories[vendor] = cat

    def vendors(self) -> list[str]:
        return sorted(self._vendors)

    def match(self, text: str) -> list[dict[str, Any]]:
        """Find known security products mentioned in a blob of text."""
        if not text:
            return []
        low = text.lower()
        hits: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for table, sigs in self.signatures.items():
            for key, info in sigs.items():
                if key and _contains_token(low, key):
                    ident = (info["vendor"], info["product"])
                    if ident in seen:
                        continue
                    seen.add(ident)
                    hits.append(
                        {
                            "vendor": info["vendor"],
                            "product": info["product"],
                            "category": info["category"],
                            "matched": info["key"],
                            "source": table,
                        }
                    )
        return hits

    def summary(self) -> dict[str, Any]:
        return {
            "kit": str(self.kit),
            "available": self.kit.exists(),
            "vendors": len(self._vendors),
            "signatures": {k: len(v) for k, v in self.signatures.items()},
        }


_DB: EDRSpecDB | None = None


def db() -> EDRSpecDB:
    global _DB
    if _DB is None:
        _DB = EDRSpecDB()
    return _DB


# ---------------------------------------------------------------------------
# output parsing
# ---------------------------------------------------------------------------
def parse_edr_enum_output(text: str) -> dict[str, Any]:
    """Parse the output of the EDR-ENUM kit into a vendor list."""
    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        line = line.replace("\x03", "").replace("\x04", "").replace("\x0b", "")
        line = re.sub(r"[\x00-\x1f]", "", line).strip()
        if not line:
            continue
        m = _HIT_RE.search(line)
        if not m:
            continue
        vendor = m.group("vendor").strip()
        product = m.group("product").strip()
        cat = m.group("cat")
        if not vendor or vendor.startswith("=="):
            continue
        ident = (canonical_vendor(vendor).lower(), product.lower())
        if ident in seen:
            continue
        seen.add(ident)
        hits.append(
            {
                "vendor": canonical_vendor(vendor),
                "product": product,
                "category": {"TEL": "Telemetry", "OTH": "Other"}.get(cat, cat),
                "matched": (m.group("key") or "").strip(),
            }
        )
    return {"hits": hits, "count": len(hits)}


def detect_vendors(text: str) -> list[dict[str, Any]]:
    """Fuzzy EDR detection over arbitrary beacon output.

    Matching is boundary aware, so a process called "Dns.exe" does not
    look like Norton and "MessSvc.exe" does not look like ESET.

    Hits from the same vendor family are MERGED rather than dropped:
    MsMpEng.exe (antimalware engine) and MsSense.exe (the Defender for
    Endpoint sensor) are two products of one vendor, and the sensor is
    the one that actually kills sessions.
    """
    low = (text or "").lower()
    if not low:
        return []

    #  vendor -> merged record
    merged: dict[str, dict[str, Any]] = {}

    def _add(vendor: str, product: str, category: str, matched: str, source: str) -> None:
        canon = canonical_vendor(vendor)
        key = canon.lower()
        rec = merged.get(key)
        if rec is None:
            rec = {
                "vendor": canon,
                "category": category,
                "products": [],
                "matched": [],
                "sources": [],
            }
            merged[key] = rec
        if product and product not in rec["products"]:
            rec["products"].append(product)
        if matched and matched not in rec["matched"]:
            rec["matched"].append(matched)
        if source and source not in rec["sources"]:
            rec["sources"].append(source)
        # keep the strongest category: EDR beats AV beats Telemetry
        rank = {"EDR": 4, "EPP": 4, "SIEM-EDR": 4, "DFIR": 3, "AV": 2, "Telemetry": 1}
        if rank.get(category, 0) > rank.get(rec["category"], 0):
            rec["category"] = category

    for vendor, needles in _VENDOR_HINTS.items():
        for needle in needles:
            if _contains_token(low, needle):
                _add(vendor, "", "EDR", needle, "hint")
                break

    for hit in db().match(text):
        _add(hit["vendor"], hit["product"], hit["category"], hit["matched"], hit["source"])

    out: list[dict[str, Any]] = []
    for rec in merged.values():
        out.append(
            {
                "vendor": rec["vendor"],
                "category": rec["category"],
                "products": rec["products"],
                "matched": rec["matched"],
                "sources": rec["sources"],
            }
        )
    # strongest first: the EDR that kills sessions matters more than an AV engine
    order = {"EDR": 4, "EPP": 4, "SIEM-EDR": 4, "DFIR": 3, "AV": 2, "Telemetry": 1}
    out.sort(key=lambda r: -order.get(r["category"], 0))
    return out


# ---------------------------------------------------------------------------
# per target profiles
# ---------------------------------------------------------------------------
class TargetProfiles:
    """Per beacon endpoint security profile, persisted across sessions."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path or TARGETS_PATH)
        self.data: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.data = raw
        except (OSError, ValueError):
            self.data = {}

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass

    def get(self, bid: str) -> dict[str, Any]:
        return dict(self.data.get(str(bid), {}))

    def vendors(self, bid: str) -> list[str]:
        prof = self.get(bid)
        return [str(v) for v in prof.get("vendors", [])]

    def set(
        self,
        bid: str,
        vendors: list[str] | None = None,
        products: list[dict[str, Any]] | None = None,
        source: str = "manual",
        notes: str = "",
    ) -> dict[str, Any]:
        bid = str(bid)
        prof = self.data.setdefault(bid, {"vendors": [], "products": [], "events": []})
        if vendors:
            merged = list(prof.get("vendors", []))
            for v in vendors:
                if v and v not in merged:
                    merged.append(v)
            prof["vendors"] = merged
        if products:
            existing = {(p.get("vendor"), p.get("product")) for p in prof.get("products", [])}
            for p in products:
                key = (p.get("vendor"), p.get("product"))
                if key not in existing:
                    existing.add(key)
                    prof.setdefault("products", []).append(p)
        prof["source"] = source
        prof["notes"] = notes or prof.get("notes", "")
        prof["updated"] = int(time.time() * 1000)
        prof.setdefault("events", []).append(
            {"ts": prof["updated"], "source": source, "vendors": vendors or []}
        )
        self.save()
        return prof

    def clear(self, bid: str) -> bool:
        if str(bid) in self.data:
            del self.data[str(bid)]
            self.save()
            return True
        return False

    def all(self) -> dict[str, Any]:
        return dict(self.data)
