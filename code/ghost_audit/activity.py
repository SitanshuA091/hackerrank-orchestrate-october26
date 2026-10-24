import argparse
import re
import sys
from collections import Counter, defaultdict
from functools import lru_cache

import pandas as pd

from ghost_audit.evidence import EMAIL_RE, RES_RE, USER_RE
from ghost_audit.identity import norm_uid
from ghost_audit.loaders import read_csv


@lru_cache(maxsize=1)
def load():
    frame = read_csv("system_activity.csv")
    frame["ts"] = pd.to_datetime(frame["event_time"], utc=True, errors="coerce")
    text = frame["details"].fillna("")
    frame["emails"] = text.map(lambda value: sorted({match.lower() for match in EMAIL_RE.findall(value)}))
    frame["users"] = text.map(lambda value: sorted({norm_uid(match.lower()) for match in USER_RE.findall(value)}))
    frame["mentions"] = text.map(lambda value: sorted(set(RES_RE.findall(value))))
    return frame.sort_values(["ts", "activity_id"], kind="stable").reset_index(drop=True)


@lru_cache(maxsize=1)
def by_resource():
    index = defaultdict(list)
    frame = load()
    for position, (rid, mentions) in enumerate(zip(frame["resource_id"], frame["mentions"])):
        index[rid].append(position)
        for mention in mentions:
            if mention != rid:
                index[mention].append(position)
    return dict(index)


def rows_for(resource_id, at=None):
    frame = load()
    rows = frame.loc[by_resource().get(resource_id, [])]
    if at is not None:
        rows = rows[rows["ts"] <= pd.Timestamp(at)]
    return rows


def non_deletion_resources():
    frame = load()
    mask = (frame["event_type"] == "CLASSIFY_REQUEST") & frame["details"].str.contains("non-deletion", case=False)
    return set(frame.loc[mask, "resource_id"])


def identity_links():
    frame = load()
    out = []
    for _, row in frame[frame["event_type"] == "LINK_RESOURCE_IDENTITY"].iterrows():
        out.append(
            {
                "resource_ids": sorted({row["resource_id"], *row["mentions"]}),
                "emails": row["emails"],
                "users": row["users"],
                "ts": row["ts"],
            }
        )
    return out


def restore_repopulations():
    frame = load()
    rows = frame[frame["event_type"] == "RESTORE_BACKUP"]
    return [
        {"backup": row["resource_id"], "ts": row["ts"], "downstream": [item for item in row["mentions"] if item != row["resource_id"]]}
        for _, row in rows.iterrows()
    ]


def template(text):
    text = EMAIL_RE.sub("<EMAIL>", text)
    text = USER_RE.sub("<USER>", text)
    return re.sub(r"\b[a-z_]+_\d+\b", "<ID>", text)


def show():
    frame = load()
    print("rows:", len(frame), "range:", frame["ts"].min(), frame["ts"].max())
    print("\n=== event_type, source -> target ===")
    routes = Counter(zip(frame["event_type"], frame["source_system"], frame["target_system"]))
    for (event, source, target), count in sorted(routes.items()):
        print(count, event, source, "->", target)
    print("\n=== templates ===")
    templates = Counter(zip(frame["event_type"], frame["reported_result"], frame["details"].map(template)))
    for (event, result, text), count in sorted(templates.items()):
        print(count, event, result, "|", text)
    print("\nnon-deletion resources:", sorted(non_deletion_resources()))
    print("identity links:", identity_links())
    print("restores:", restore_repopulations())


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["show", "resource"])
    parser.add_argument("ids", nargs="*")
    args = parser.parse_args()
    if args.mode == "show":
        show()
        return
    pd.set_option("display.width", 250)
    pd.set_option("display.max_colwidth", 120)
    for rid in args.ids:
        print(f"\n=== {rid} ===")
        print(rows_for(rid)[["activity_id", "event_time", "event_type", "source_system", "target_system", "reported_result", "details"]].to_string(index=False))


if __name__ == "__main__":
    main()