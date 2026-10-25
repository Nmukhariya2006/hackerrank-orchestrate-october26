import csv, json, re, sqlite3
from datetime import datetime

RID = re.compile(r"\b(?:account|search|support|analytics|export|backup|data_flow|audit_record|"
                 r"tombstone|marketing|cache|object|legal_hold)_\d+\b")

def _ts(s): return datetime.fromisoformat(s.replace("Z", "+00:00"))

def _walk(o, key=""):
    out = []
    if isinstance(o, dict):
        sc = {k: v for k, v in o.items() if not isinstance(v, (dict, list))}
        if sc: out.append(key + " " + json.dumps(sc, ensure_ascii=False))
        for k, v in o.items(): out += _walk(v, k)
    elif isinstance(o, list):
        for v in o: out += _walk(v, key)
    return out

def read_units(path, ocr=False):
    p = path.lower()
    try:
        if p.endswith(".sql"):
            con = sqlite3.connect(":memory:")
            con.executescript(open(path, encoding="utf-8", errors="ignore").read())
            units = []
            for (t,) in con.execute("select name from sqlite_master where type='table'").fetchall():
                cols = [c[1] for c in con.execute(f"pragma table_info({t})")]
                for row in con.execute(f"select * from {t}"):
                    units.append(t + " " + json.dumps(dict(zip(cols, row)), default=str, ensure_ascii=False))
            if units: return units
        elif p.endswith(".json"):
            return _walk(json.load(open(path, encoding="utf-8")))
        elif p.endswith(".pdf"):
            from pypdf import PdfReader
            return [l for pg in PdfReader(path).pages for l in (pg.extract_text() or "").splitlines()]
        elif p.endswith((".png", ".jpg", ".jpeg")):
            if not ocr: return []
            import pytesseract; from PIL import Image
            return pytesseract.image_to_string(Image.open(path)).splitlines()
    except Exception as e:
        print("warn:", path, e)
    return open(path, encoding="utf-8", errors="ignore").read().splitlines()

def classify(rid, texts, ids):
    """returns (treatment, compliant). TUNE THIS after inspecting real evidence."""
    kind = rid.rsplit("_", 1)[0]
    t = " ".join(texts).lower()
    direct = ids.direct_in(t)
    if kind in ("audit_record", "legal_hold"):
        return "RETAIN", True
    if kind == "data_flow":
        active = bool(re.search(r"\b(enabled|active|running)\b", t)) and \
                 not re.search(r"\b(disabled|paused|stopped)\b", t)
        return "FLOW", not active
    if kind == "backup":
        blocked = bool(re.search(r"(restore[_ ]?blocked|\bblocked\b|restorable\W+false)", t))
        return "RESTORE", blocked
    gone = bool(re.search(r"\b(deleted|absent|not[_ ]found|purged)\b", t)) and not direct
    if kind == "support":
        kind = "support_att" if "attachment" in t else "support_msg"
    if kind in ("account", "search", "export", "marketing", "cache", "object", "support_att"):
        return "DELETE", gone
    if kind in ("support_msg", "tombstone"):
        return "REDACT", not direct
    if kind == "analytics":
        return "ANONYMIZE", not direct
    return "RETAIN", True

class Evidence:
    def __init__(self, ds, ocr=False):
        self.ds, self.ocr, self.cache = ds, ocr, {}
        self.files = sorted(csv.DictReader(open(f"{ds}/evidence_files.csv", encoding="utf-8")),
                            key=lambda r: r["captured_at"], reverse=True)
        self.activity = list(csv.DictReader(
            open(f"{ds}/system_activity.csv", encoding="utf-8")
        ))

    def units(self, f):
        file_id = f["file_id"]
        if file_id not in self.cache:
            base = __import__("pathlib").Path(self.ds)
            path = __import__("pathlib").Path(f["file_path"])
            if not path.is_absolute():
            # Try the path relative to the dataset directory first.
                candidate = base / path

            # If the manifest already includes the dataset folder,
            # try the path relative to the project root too.
                if not candidate.exists():
                    candidate = base.parent / path
                path = candidate
                
            if not path.is_file():
                print(f"WARNING: Evidence file not found: {path}")
                self.cache[file_id] = []
            else:
                self.cache[file_id] = read_units(str(path), self.ocr)

        return self.cache[file_id]
                
                
    
    def find(self, ids, audit_at, submitted_at=None):
        cutoff = _ts(audit_at)

        # First, use the existing identity-based evidence search.
        for f in self.files:
            if _ts(f["captured_at"]) > cutoff:
                continue

            found = {}
            for unit in self.units(f):
                if ids.direct_in(unit) or ids.weak_in(unit):
                    for rid in RID.findall(unit):
                        found.setdefault(rid, []).append(unit)

            if found:
                return f["file_id"], {
                    rid: classify(rid, units, ids)
                    for rid, units in found.items()
                }

        # Fallback: connect a recent successful deletion event
        # to a snapshot captured after that event.
        if not submitted_at:
            return None, {}

        submitted = _ts(submitted_at)
        actions = {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"}

        events = []
        for event in self.activity:
            try:
                event_time = _ts(event["timestamp"])
            except (KeyError, ValueError, TypeError):
                continue

            if (
                event.get("action") in actions
                and event.get("status", "").upper() == "SUCCESS"
                and abs((event_time - submitted).total_seconds()) <= 300
                and event_time <= cutoff
            ):
                rid = event.get("resource_id", "").strip()
                if RID.fullmatch(rid):
                    events.append((event_time, rid, event))

        for event_time, rid, event in sorted(events, reverse=True):
            snapshots = [
                f for f in self.files
                if event_time <= _ts(f["captured_at"]) <= cutoff
            ]

            for f in snapshots:
                units = self.units(f)
                resource_units = [
                    unit for unit in units
                    if rid in unit
                ]

                if event.get("action") == "DELETE_RECORD":
                    if not resource_units:
                        return f["file_id"], {rid: ("DELETE", True)}

                    return f["file_id"], {rid: ("DELETE", False)}

                # Redaction/anonymization needs actual evidence
                # of the resulting state; don't assume success.
                if resource_units:
                    treatment, compliant = classify(rid, resource_units, ids)
                    return f["file_id"], {rid: (treatment, compliant)}

        return None, {}
