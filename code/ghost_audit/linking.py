import argparse
import json
import sqlite3
import sys
from collections import Counter, defaultdict
import re

from ghost_audit import activity
from ghost_audit.evidence import PREFIX_SYSTEM, build_index, identity_keys
from ghost_audit.identity import IdentityResolver
from ghost_audit.loaders import evidence_path, load_dataset


class LinkIndex:
    def __init__(self, observations):
        self.obs = defaultdict(list)
        self.keys = defaultdict(set)
        self.edges = defaultdict(set)
        for item in observations:
            if not item.resource_id:
                continue
            self.obs[item.resource_id].append(item)
            self.keys[item.resource_id].update(item.keys)
            for other in item.linked:
                self.edges[item.resource_id].add(other)
                self.edges[other].add(item.resource_id)
        for link in activity.identity_links():
            tokens = {"e:" + email for email in link["emails"]} | {"u:" + user for user in link["users"]}
            for rid in link["resource_ids"]:
                self.keys[rid].update(tokens)
        self.by_key = defaultdict(set)
        for rid, keys in self.keys.items():
            for key in keys:
                self.by_key[key].add(rid)
                
    def resources_for(self, keys):
        direct = set()
        for key in keys:
            direct |= self.by_key.get(key, set())
        linked = set()
        for rid in direct:
            linked |= self.edges.get(rid, set())
        def keep(rid):
            return rid.rsplit("_", 1)[0] in PREFIX_SYSTEM
        direct = {rid for rid in direct if keep(rid)}
        linked = {rid for rid in linked - direct if keep(rid)}
        return direct, linked

def expected_for(data):
    out = {}
    for _, row in data.sample_output.iterrows():
        steps = json.loads(row["steps_json"])
        out[row["case_id"]] = {
            "status": row["deletion_status"],
            "resources": {step["resource_id"] for step in steps if step["resource_id"]},
            "evidence": {(step["resource_id"], step["evidence_id"]) for step in steps if step["evidence_id"]},
        }
    return out


def summarize(item):
    flag = "*" if item.inferred else ""
    extra = ""
    if item.enabled is not None or item.restore_allowed is not None:
        extra = f" enabled={item.enabled} restore={item.restore_allowed}"
    return f"{item.file_id} {item.kind} ts={item.ts} present={item.present}{flag} keys={len(item.keys)} store={item.store}{extra}"


def describe(index, rid, meta, expected_ev="", limit=6):
    items = index.obs.get(rid, [])
    print(f"  [{rid}] obs={len(items)} owner_keys={len(index.keys.get(rid, []))} edges={sorted(index.edges.get(rid, []))[:5]}")
    for item in sorted(items, key=lambda entry: entry.ts)[:limit]:
        print("     OBS", summarize(item))
    for _, row in activity.rows_for(rid).head(limit).iterrows():
        print("     ACT", row["activity_id"], row["event_time"], row["event_type"], row["source_system"], "->", row["target_system"], row["reported_result"], "|", row["details"][:110])
    if expected_ev:
        info = meta.get(expected_ev, {})
        seen = [item for item in items if item.file_id == expected_ev]
        print(f"     EXPECTED {expected_ev} {info.get('file_path')} captured={info.get('captured_at')} observes_resource={len(seen)}")


def calibrate(limit, explain):
    data = load_dataset()
    observations, meta = build_index()
    index = LinkIndex(observations)
    resolver = IdentityResolver(data.identities, data.audit_log)
    expected = expected_for(data)
    totals = Counter()
    for _, row in data.sample_requests.head(limit).iterrows():
        identity = resolver.resolve(row["email"], at=row["requested_at"])
        direct, linked = index.resources_for(identity_keys(identity))
        owned = direct | linked
        want = expected[row["case_id"]]
        missing = sorted(want["resources"] - owned)
        extra = sorted(owned - want["resources"])
        evidence_ok = {pair for pair in want["evidence"] if pair[1] in {item.file_id for item in index.obs.get(pair[0], [])}}
        totals["expected"] += len(want["resources"])
        totals["found"] += len(want["resources"] & owned)
        totals["owned"] += len(owned)
        totals["evidence_expected"] += len(want["evidence"])
        totals["evidence_ok"] += len(evidence_ok)
        print(
            f"{row['case_id']} {want['status']:<10} found {len(want['resources'] & owned)}/{len(want['resources'])} "
            f"ev {len(evidence_ok)}/{len(want['evidence'])} owned={len(owned)} extra={len(extra)} missing={missing}"
        )
        if explain:
            for rid in missing:
                describe(index, rid, meta, next((ev for res, ev in want["evidence"] if res == rid), ""))
            if extra:
                print("     EXTRA sample:", extra[:8])
    print("\ntotals:", dict(totals))


def probe_file(file_id, observations, meta):
    info = meta[file_id]
    print(file_id, {key: value for key, value in info.items() if key != "scope"}, "scope=", info.get("scope"))
    items = [item for item in observations if item.file_id == file_id]
    print("observations:", len(items), dict(Counter(item.system for item in items)))
    for item in items[:12]:
        print("  ", item.resource_id, item.system, item.store, item.present, item.inferred, len(item.keys), item.record_type, item.ts)
    path = evidence_path(info["file_path"])
    if path.suffix.lower() == ".sql":
        connection = sqlite3.connect(":memory:")
        connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
        for (name,) in connection.execute("select name from sqlite_master where type='table'").fetchall():
            count = connection.execute(f'select count(*) from "{name}"').fetchone()[0]
            print("   table", name, count)

def grep(tokens):
    from ghost_audit.loaders import list_evidence

    patterns = [re.compile(re.escape(token) + r"(?!\d)") for token in tokens]
    for path in list_evidence():
        if path.suffix.lower() not in (".sql", ".log", ".json", ".txt"):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if any(pattern.search(line) for pattern in patterns):
                print(f"{path.name}:{number}: {line[:320]}")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["calibrate", "where", "file", "grep"])
    parser.add_argument("ids", nargs="*")
    parser.add_argument("--limit", type=int, default=32)
    parser.add_argument("--explain", action="store_true")
    args = parser.parse_args()
    if args.mode == "calibrate":
        calibrate(args.limit, args.explain)
        return
    if args.mode == "grep":
        grep(args.ids)
        return
    observations, meta = build_index()
    if args.mode == "file":
        for file_id in args.ids:
            probe_file(file_id, observations, meta)
        return
    index = LinkIndex(observations)
    for rid in args.ids:
        describe(index, rid, meta)

if __name__ == "__main__":
    main()