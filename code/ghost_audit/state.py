import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass, field

import pandas as pd

from ghost_audit.evidence import PREFIX_SYSTEM, build_index, prefix_of

FLOOR = pd.Timestamp("1970-01-01", tz="UTC")
FLAGS = ("name", "email", "phone", "hash", "ref")


def to_ts(value):
    ts = pd.to_datetime(value, utc=True, errors="coerce")
    return None if pd.isna(ts) else ts


def store_key(item):
    if "replica" in (item.store or "").lower():
        return ("replica", item.store)
    return ("primary", item.system)


@dataclass
class ResState:
    resource_id: str
    system: str
    present: object = None
    pii: dict = field(default_factory=lambda: {flag: False for flag in FLAGS})
    enabled: object = None
    restore_allowed: object = None
    record_type: str = ""
    store_text: str = ""
    retain_until: str = ""
    cite_present: str = ""
    cite_absent: str = ""
    observed: bool = False


class StateIndex:
    def __init__(self, observations, meta):
        self.meta = meta
        self.avail = {fid: to_ts(info.get("captured_at")) for fid, info in meta.items()}
        self.by_res = defaultdict(list)
        members = defaultdict(lambda: defaultdict(set))
        for item in observations:
            file_ts = self.avail.get(item.file_id)
            if item.resource_id:
                self.by_res[item.resource_id].append((item, to_ts(item.ts) or file_ts, file_ts))
                if meta.get(item.file_id, {}).get("listing"):
                    members[item.file_id][store_key(item)].add(item.resource_id)
        self.listings = []
        for fid, info in meta.items():
            if not info.get("listing"):
                continue
            keys = {key: found for key, found in members.get(fid, {}).items() if found}
            if keys:
                self.listings.append((self.avail[fid], fid, keys))
        self.listings.sort(key=lambda row: (row[0] or FLOOR, row[1]))

    def at(self, rid, when):
        system = PREFIX_SYSTEM.get(prefix_of(rid), "")
        seen = {("primary", system)} if system else set()
        events = []
        for item, ts, file_ts in self.by_res.get(rid, []):
            if file_ts is not None and file_ts > when:
                continue
            if ts is not None and ts > when:
                continue
            key = store_key(item)
            seen.add(key)
            events.append((ts or file_ts or FLOOR, file_ts or FLOOR, item.file_id, key, item.present, True, item))
        for file_ts, fid, keys in self.listings:
            if file_ts is None or file_ts > when:
                continue
            for key, found in keys.items():
                if key in seen and rid not in found:
                    events.append((file_ts, file_ts, fid, key, False, False, None))
        if not events:
            return ResState(rid, system)
        events.sort(key=lambda event: (event[0], event[1]))
        latest = {}
        for event in events:
            latest[event[3]] = event
        direct = [event for event in events if event[5]]
        live = [event for event in latest.values() if event[5] and event[4]]
        flagged_enabled = [event for event in direct if event[6].enabled is not None]
        flagged_restore = [event for event in direct if event[6].restore_allowed is not None]
        present_direct = [event for event in direct if event[4]]
        absent_direct = [event for event in direct if not event[4]]
        absent_listing = [event for event in events if not event[5]]
        retained = [event for event in direct if event[6].retain_until]
        texts = {f"{event[6].store} {event[6].record_type}".lower() for event in present_direct}
        return ResState(
            resource_id=rid,
            system=system or (direct[-1][6].system if direct else ""),
            present=any(event[4] for event in latest.values()),
            pii={flag: any(event[6].pii.get(flag) for event in live) for flag in FLAGS},
            enabled=flagged_enabled[-1][6].enabled if flagged_enabled else None,
            restore_allowed=flagged_restore[-1][6].restore_allowed if flagged_restore else None,
            record_type=present_direct[-1][6].record_type if present_direct else "",
            store_text=" ".join(sorted(texts)),
            retain_until=retained[-1][6].retain_until if retained else "",
            cite_present=present_direct[-1][2] if present_direct else "",
            cite_absent=(absent_direct[-1][2] if absent_direct else (absent_listing[-1][2] if absent_listing else "")),
            observed=bool(direct),
        )


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("ids", nargs="+")
    parser.add_argument("--at", required=True)
    args = parser.parse_args()
    observations, meta = build_index()
    index = StateIndex(observations, meta)
    when = to_ts(args.at)
    for rid in args.ids:
        print(index.at(rid, when))


if __name__ == "__main__":
    main()