import argparse
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

import pandas as pd

from ghost_audit.identity import IdentityResolver, norm_digits, norm_uid
from ghost_audit.loaders import evidence_path, load_dataset, read_csv

INDEX_PATH = Path(".cache/evidence_index.json")

PREFIX_SYSTEM = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "cache": "cache_service",
    "marketing": "marketing_platform",
    "backup": "backup_service",
    "data_flow": "integration_service",
    "audit_record": "security_service",
    "email_delivery": "email_delivery_service",
    "legal_hold": "legal_service",
    "identity": "identity_service",
    "tombstone": "identity_service",
    "object": "object_storage",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b", re.I)
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
RES_RE = re.compile(r"\b((?:%s)_\d+)\b" % "|".join(sorted(PREFIX_SYSTEM, key=len, reverse=True)))
PHONE_RE = re.compile(r"\+\d[\d\s().\-]{7,}\d")
RETAIN_RE = re.compile(r"retain until\s+(\d{1,2}\s+\w{3}\s+\d{4})", re.I)
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(.*)$")
SYSLOG_RE = re.compile(r"^<\d+>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(.*)$")
KV_RE = re.compile(r'([A-Za-z_][\w.]*)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')

NULLS = {"", "null", "none"}
NAME_KEYS = {"full_name", "display_name", "requester_name", "name", "customer_name"}
EMAIL_KEYS = {"email", "requester_email", "owner_email", "customer_email", "matched_value"}
REF_KEYS = {"user_id", "customer_reference", "subject_reference", "subject_ref", "customer_ref"}
STATE_KEYS = {"enabled", "restore_allowed", "download_available"}
RETAIN_KEYS = {"retention_until", "retain_until"}
OWN_TS_KEYS = ("observed_at", "recorded_at", "captured_at")


@dataclass
class Obs:
    file_id: str
    kind: str
    ts: str
    row_ts: str
    system: str
    resource_id: str
    store: str
    record_type: str
    present: bool
    inferred: bool
    enabled: object
    restore_allowed: object
    download_available: object
    keys: list
    pii: dict
    retain_until: str
    linked: list


def prefix_of(resource_id):
    return resource_id.rsplit("_", 1)[0] if "_" in resource_id else resource_id


def to_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("true", "1", "yes", "enabled"):
        return True
    if text in ("false", "0", "no", "disabled"):
        return False
    return None


def mine(text):
    keys = {"e:" + match.lower() for match in EMAIL_RE.findall(text)}
    keys |= {"u:" + norm_uid(match.lower()) for match in USER_RE.findall(text)}
    keys |= {"h:" + match.lower() for match in HASH_RE.findall(text)}
    return keys


def flatten(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                yield from flatten(value)
            else:
                yield str(key), value
    elif isinstance(node, list):
        for item in node:
            yield from flatten(item)


def digest(items):
    keys = set()
    pii = {"name": False, "email": False, "phone": False, "hash": False, "ref": False}
    state = {}
    retain = ""
    for key, value in items:
        if value is None:
            continue
        key = str(key).lower()
        text = str(value).strip()
        if text.lower() in NULLS:
            continue
        if key in STATE_KEYS:
            state[key] = to_bool(value)
        if key in RETAIN_KEYS:
            retain = text
        mined = mine(text)
        keys |= mined
        if key in NAME_KEYS:
            pii["name"] = True
        if key in EMAIL_KEYS or (key in REF_KEYS and any(item.startswith("e:") for item in mined)):
            pii["email"] = True
        if key == "email_hash":
            pii["hash"] = True
        if key in REF_KEYS and any(item.startswith("u:") for item in mined):
            pii["ref"] = True
        if key.endswith("phone"):
            digits = norm_digits(text)
            if len(digits) >= 8:
                keys.add("p:" + digits)
                pii["phone"] = True
    return sorted(keys), pii, state, retain


def presence(leaf, event=""):
    rows = leaf.get("rows")
    if rows is not None:
        try:
            return int(str(rows)) > 0
        except ValueError:
            pass
    code = leaf.get("http_status", leaf.get("status_code"))
    if code is not None:
        try:
            code = int(str(code))
            if code == 200:
                return True
            if code == 404:
                return False
        except ValueError:
            pass
    if "cache" not in event:
        result = str(leaf.get("result", "")).strip().upper()
        if result in ("FOUND", "HIT"):
            return True
        if result in ("NOT_FOUND", "MISS"):
            return False
    return None


def make_obs(file_id, kind, ts, rid, system, store, record_type, items, present, state_items=None, row_ts=""):
    keys, pii, _, _ = digest(items)
    _, _, state, retain = digest(state_items if state_items is not None else items)
    linked = sorted({match for _, value in items if isinstance(value, str) for match in RES_RE.findall(value)} - {rid})
    inferred = present is None
    return Obs(
        file_id=file_id,
        kind=kind,
        ts=ts or "",
        row_ts=row_ts,
        system=system or PREFIX_SYSTEM.get(prefix_of(rid), ""),
        resource_id=rid,
        store=store,
        record_type=record_type,
        present=True if inferred else bool(present),
        inferred=inferred,
        enabled=state.get("enabled"),
        restore_allowed=state.get("restore_allowed"),
        download_available=state.get("download_available"),
        keys=keys,
        pii=pii,
        retain_until=retain,
        linked=linked,
    )


def sql_obs(path, file_id, captured):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
    tables = [row[0] for row in connection.execute("select name from sqlite_master where type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        scope = {row[0]: row[1] for row in connection.execute("select origin_system, captured_at from snapshot_scope")}
    out = []
    for table in tables:
        if table == "snapshot_scope":
            continue
        for row in connection.execute(f'select * from "{table}"'):
            rec = dict(row)
            rid = str(rec.get("resource_id") or "")
            row_ts = str(rec.get("updated_at") or rec.get("indexed_at") or "")
            if "record_json" in rec:
                items = list(flatten(json.loads(rec["record_json"])))
                system = rec.get("origin_system") or PREFIX_SYSTEM.get(prefix_of(rid), "")
                record_type = rec.get("collection_name") or ""
            else:
                items = list(rec.items())
                system = PREFIX_SYSTEM.get(prefix_of(rid), "")
                record_type = table
            ts = scope.get(system) or captured or row_ts
            out.append(make_obs(file_id, "sql", ts, rid, system, table, record_type, items, True, row_ts=row_ts))
    return out, scope


def parse_kv(text):
    out = {}
    for match in KV_RE.finditer(text):
        key = match.group(1)
        if match.group(2) is not None:
            value = match.group(2).replace('\\"', '"')
        else:
            value = match.group(3)
        out[key] = value
        if key == "message" and "=" in value:
            for inner_key, inner_value in parse_kv(value).items():
                out.setdefault(inner_key, inner_value)
    return out


def parse_log_line(line):
    match = TS_RE.match(line.strip())
    if not match:
        return None
    ts, rest = match.groups()
    rest = rest.strip()
    if rest.startswith("{"):
        try:
            return ts, {str(key): value for key, value in json.loads(rest).items()}
        except ValueError:
            return None
    if rest.startswith("|"):
        parts = [part.strip() for part in rest.lstrip("| ").split(" | ")]
        kv = parse_kv(parts[4]) if len(parts) > 4 else {}
        if len(parts) >= 4:
            kv.update({"level": parts[0], "service": parts[1], "trace_id": parts[2], "event": parts[3]})
        return ts, kv
    syslog = SYSLOG_RE.match(rest)
    if syslog:
        _, service, trace, tail = syslog.groups()
        kv = parse_kv(tail)
        kv.update({"service": service, "trace_id": trace})
        return ts, kv
    return ts, parse_kv(rest)


def group_name(path):
    return re.sub(r"_\d{6,8}(_\d{6})?$", "", path.stem)


def log_obs(path, file_id, captured):
    groups = {}
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ts, kv = parsed
        trace = str(kv.get("trace_id") or kv.get("requestId") or f"line{number}")
        groups.setdefault(trace, []).append((ts, kv))
    out = []
    store = group_name(path)
    for lines in groups.values():
        shared = [pair for _, kv in lines for pair in kv.items()]
        resources = {}
        for ts, kv in lines:
            rid = str(kv.get("resource_id") or "")
            if rid.lower() in NULLS:
                lookup = str(kv.get("lookup_key") or "")
                rid = lookup if RES_RE.fullmatch(lookup) else ""
            if rid:
                resources.setdefault(rid, []).append((ts, kv))
        for rid, own in resources.items():
            present = None
            for _, kv in own:
                value = presence(kv, str(kv.get("event", "")))
                if value is not None:
                    present = value
            own_items = [pair for _, kv in own for pair in kv.items()]
            last = own[-1][1]
            system = PREFIX_SYSTEM.get(prefix_of(rid)) or str(last.get("system") or last.get("service") or "")
            ts = max(item[0] for item in own)
            out.append(make_obs(file_id, "log", ts, rid, system, store, str(last.get("record_type") or ""), shared, present, own_items))
    return out


def json_obs(payload, file_id, captured):
    out = []

    def emit(node, local):
        rid = node["resource_id"]
        items = list(flatten(node))
        system = node.get("system") if isinstance(node.get("system"), str) else local.get("system", "")
        ts = next((node[key] for key in OWN_TS_KEYS if isinstance(node.get(key), str)), "") or local.get("ts") or captured
        record_type = node.get("record_type") if isinstance(node.get("record_type"), str) else ""
        store = node.get("collection") if isinstance(node.get("collection"), str) else local.get("store", "")
        out.append(make_obs(file_id, "json", ts, rid, system, store, record_type, items, presence(dict(items))))

    def walk(node, ctx):
        if isinstance(node, list):
            for item in node:
                walk(item, ctx)
            return
        if not isinstance(node, dict):
            return
        local = dict(ctx)
        for key in ("captured_at", "exported_at"):
            if isinstance(node.get(key), str):
                local["ts"] = node[key]
        for key in ("data_store", "origin_system"):
            if isinstance(node.get(key), str):
                local["system"] = node[key]
        if isinstance(node.get("collection"), str):
            local["store"] = node["collection"]
        if isinstance(node.get("resource_id"), str):
            emit(node, local)
            return
        for key, value in node.items():
            child = dict(local)
            if str(key).endswith(("_service", "_platform")):
                child["system"] = str(key)
            elif isinstance(value, list):
                child["store"] = str(key)
            walk(value, child)

    walk(payload, {})
    return out


def txt_obs(path, file_id, captured):
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("- ") or " | " not in line:
            continue
        parts = [part.strip() for part in line[2:].split(" | ")]
        if len(parts) < 6:
            continue
        ts, system, rid, record_type, result, subject = parts[:6]
        out.append(make_obs(file_id, "txt", ts, rid, system, "handover", record_type, [("subject_reference", subject)], presence({"result": result})))
    return out


def pdf_obs(path, file_id, captured):
    import pymupdf

    with pymupdf.open(path) as document:
        text = "\n".join(page.get_text() for page in document)
    items = [("text", text)]
    retain = ""
    match = RETAIN_RE.search(text)
    if match:
        retain = pd.to_datetime(match.group(1), utc=True, errors="coerce").isoformat()
    phones = [norm_digits(value) for value in PHONE_RE.findall(text)]
    resources = sorted(set(RES_RE.findall(text))) or [""]
    out = []
    for rid in resources:
        obs = make_obs(file_id, "pdf", captured, rid, "", path.stem, "DOCUMENT", items, True)
        obs.keys = sorted(set(obs.keys) | {"p:" + digits for digits in phones if len(digits) >= 8})
        obs.pii["email"] = any(key.startswith("e:") for key in obs.keys)
        obs.pii["ref"] = any(key.startswith("u:") for key in obs.keys)
        obs.pii["phone"] = bool(phones)
        obs.retain_until = retain
        out.append(obs)
    return out


def image_obs(path, file_id, captured):
    from ghost_audit import vision

    found = vision.to_obs(file_id, captured, path.stem)
    return found or [make_obs(file_id, "image", captured, "", "", path.stem, "NEEDS_VISION", [], True)]

def build_index(rebuild=False):
    if INDEX_PATH.exists() and not rebuild:
        payload = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
        return [Obs(**row) for row in payload["obs"]], payload["meta"]
    manifest = read_csv("evidence_files.csv")
    observations, meta = [], {}
    for _, row in manifest.iterrows():
        file_id = row["file_id"]
        captured = row["captured_at"]
        entry = {"file_path": row["file_path"], "origin": row["origin"], "captured_at": captured}
        meta[file_id] = entry
        try:
            path = evidence_path(row["file_path"])
            ext = path.suffix.lower()
            entry["kind"] = ext.lstrip(".")
            if ext == ".sql":
                found, scope = sql_obs(path, file_id, captured)
                entry["scope"] = scope
            elif ext == ".log":
                found = log_obs(path, file_id, captured)
            elif ext == ".json":
                found = json_obs(json.loads(path.read_text(encoding="utf-8", errors="replace")), file_id, captured)
            elif ext == ".txt":
                found = txt_obs(path, file_id, captured)
            elif ext == ".pdf":
                found = pdf_obs(path, file_id, captured)
            elif ext in (".png", ".jpg", ".jpeg"):
                found = image_obs(path, file_id, captured)
            else:
                found = []
            entry["observations"] = len(found)
            observations.extend(found)
        except Exception as error:
            entry["error"] = f"{type(error).__name__}: {error}"
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    INDEX_PATH.write_text(json.dumps({"meta": meta, "obs": [asdict(item) for item in observations]}), encoding="utf-8")
    return observations, meta


def identity_keys(identity):
    keys = {"u:" + norm_uid(identity.user_id.lower())}
    keys |= {"e:" + email.strip().lower() for email in identity.emails}
    keys |= {"h:" + digest_value.strip().lower() for digest_value in identity.hashes}
    for phone in identity.phones:
        digits = norm_digits(phone)
        if len(digits) >= 8:
            keys.add("p:" + digits)
    return keys


def stats():
    observations, meta = build_index()
    print("files:", len(meta), "observations:", len(observations))
    print("errors:", {fid: info["error"] for fid, info in meta.items() if "error" in info})
    print("by kind:", dict(Counter(item.kind for item in observations)))
    print("present:", dict(Counter(item.present for item in observations)), "inferred:", sum(item.inferred for item in observations))
    print("no identity keys:", sum(1 for item in observations if not item.keys and item.resource_id))
    print("\nobservations per file (lowest):")
    for fid, info in sorted(meta.items(), key=lambda pair: pair[1].get("observations", 0))[:10]:
        print(" ", fid, info.get("file_path"), info.get("observations", 0))
    census = defaultdict(Counter)
    for item in observations:
        census[prefix_of(item.resource_id)][item.system] += 1
    print("\nresource prefix -> systems:")
    for prefix, counter in sorted(census.items()):
        print(" ", repr(prefix), dict(counter))
    print("\nrecord types:", dict(Counter(item.record_type for item in observations if item.record_type).most_common(25)))
    print("\nstores:", dict(Counter(item.store for item in observations).most_common(25)))


def calibrate(limit):
    data = load_dataset()
    observations, _ = build_index()
    resolver = IdentityResolver(data.identities, data.audit_log)
    by_key = defaultdict(list)
    for item in observations:
        if item.resource_id:
            for key in item.keys:
                by_key[key].append(item)
    expected = {}
    for _, row in data.sample_output.iterrows():
        steps = json.loads(row["steps_json"])
        expected[row["case_id"]] = {
            "status": row["deletion_status"],
            "resources": {step["resource_id"] for step in steps if step["resource_id"]},
            "evidence": {(step["resource_id"], step["evidence_id"]) for step in steps if step["evidence_id"]},
        }
    totals = Counter()
    for _, row in data.sample_requests.head(limit).iterrows():
        identity = resolver.resolve(row["email"], at=row["requested_at"])
        hits, reach = {}, set()
        for key in identity_keys(identity):
            for item in by_key.get(key, []):
                hits.setdefault(item.resource_id, set()).add(item.file_id)
                reach.update(item.linked)
        want = expected[row["case_id"]]
        direct = want["resources"] & set(hits)
        via_link = (want["resources"] - direct) & reach
        missing = sorted(want["resources"] - direct - via_link)
        evidence_ok = {pair for pair in want["evidence"] if pair[1] in hits.get(pair[0], set())}
        totals["expected"] += len(want["resources"])
        totals["direct"] += len(direct)
        totals["via_link"] += len(via_link)
        totals["evidence_expected"] += len(want["evidence"])
        totals["evidence_ok"] += len(evidence_ok)
        print(
            f"{row['case_id']} {want['status']:<10} res {len(direct)}+{len(via_link)}link/{len(want['resources'])} "
            f"ev {len(evidence_ok)}/{len(want['evidence'])} extra={len(set(hits) - want['resources'])} missing={missing}"
        )
    print("\ntotals:", dict(totals))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["build", "stats", "calibrate"])
    parser.add_argument("--limit", type=int, default=32)
    args = parser.parse_args()
    if args.mode == "build":
        build_index(rebuild=True)
        stats()
    elif args.mode == "stats":
        stats()
    else:
        calibrate(args.limit)


if __name__ == "__main__":
    main()