import re
from collections import defaultdict

from ghost_audit import activity

ACCOUNT_WINDOW = (-95.0, 15.0)
ANALYTICS_WINDOW = (-30.5, -26.5)
SPECIAL = "Target resource:"
SPECIAL_WINDOW = (-10.0, 10.0)


def case_number(case_id):
    match = re.search(r"\d+", str(case_id))
    return int(match.group()) if match else 0


def pool(kind):
    frame = activity.load()
    if kind == "account":
        mask = (frame["event_type"] == "DELETE_RECORD") & (frame["target_system"] == "account_service")
    else:
        mask = (
            (frame["event_type"] == "ANONYMIZE_RECORD")
            & (frame["target_system"] == "analytics_platform")
            & ~frame["details"].str.contains("received the final result")
        )
    return frame[mask]


def in_window(gap, details, window):
    if SPECIAL in details:
        return SPECIAL_WINDOW[0] <= gap <= SPECIAL_WINDOW[1]
    return window[0] <= gap <= window[1]


def assign(cases, key_owned, kinds, corroborate):
    claimed = {rid for owned in key_owned.values() for rid in owned}
    result = defaultdict(list)
    taken = set()
    for kind in kinds:
        window = ACCOUNT_WINDOW if kind == "account" else ANALYTICS_WINDOW
        rows = pool(kind)
        rows = rows[~rows["resource_id"].isin(claimed)]
        data = list(zip(rows["ts"], rows["resource_id"], rows["details"]))
        slots = defaultdict(list)
        for _, case in cases.iterrows():
            owned = key_owned.get(case["case_id"], [])
            if kind == "account" and any(rid.startswith("account_") for rid in owned):
                continue
            slots[case["reported_at"]].append(case)
        for reported_at in sorted(slots):
            group = sorted(slots[reported_at], key=lambda case: case_number(case["case_id"]))
            found = []
            for ts, rid, details in data:
                if rid in taken:
                    continue
                gap = (ts - reported_at).total_seconds() / 60.0
                if not in_window(gap, details, window):
                    continue
                if kind == "analytics" and not any(corroborate(rid, case) for case in group):
                    continue
                found.append((ts, rid))
            found.sort()
            if found and len(found) == len(group):
                for case, (_, rid) in zip(group, found):
                    result[case["case_id"]].append(rid)
                    taken.add(rid)
    return result