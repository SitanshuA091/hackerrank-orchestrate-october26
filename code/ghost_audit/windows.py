import argparse
import json
import sys
from statistics import median
from collections import Counter
import pandas as pd

from ghost_audit import activity
from ghost_audit.loaders import load_dataset

WORKER_EVENTS = {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "RETAIN_RECORD"}
SWEEP = (15, 30, 60, 120, 240, 720, 1440)


def expected_resources(data):
    out = {}
    for _, row in data.sample_output.iterrows():
        steps = json.loads(row["steps_json"])
        out[row["case_id"]] = {step["resource_id"] for step in steps if step["resource_id"]}
    return out


def worker_rows():
    frame = activity.load()
    mask = (frame["source_system"] == "deletion_worker") & frame["event_type"].isin(WORKER_EVENTS)
    return frame[mask]


def minutes(delta):
    return delta.total_seconds() / 60.0


def deltas(data, expected):
    worker = worker_rows()
    pooled = []
    for _, case in data.sample_requests.iterrows():
        for rid in sorted(expected[case["case_id"]]):
            rows = worker[worker["resource_id"] == rid]
            if rows.empty:
                print(f"{case['case_id']} {rid:<20} no worker rows")
                continue
            gaps = (rows["ts"] - case["reported_at"]).map(minutes)
            best = gaps.abs().idxmin()
            row = rows.loc[best]
            gap = gaps.loc[best]
            pooled.append(abs(gap))
            print(
                f"{case['case_id']} {rid:<20} {row['event_type']:<17} {row['reported_result']:<8} "
                f"vs_reported={gap:9.1f}m vs_requested={minutes(row['ts'] - case['requested_at']):9.1f}m "
                f"vs_audit={minutes(row['ts'] - case['audit_at']):9.1f}m"
            )
    if pooled:
        ordered = sorted(pooled)
        print("\n|vs_reported| minutes: median", round(median(ordered), 1), "p90", round(ordered[int(len(ordered) * 0.9)], 1), "max", round(ordered[-1], 1))


def sweep(data, expected):
    worker = worker_rows()
    for width in SWEEP:
        hit = want = got = 0
        counts = []
        for _, case in data.sample_requests.iterrows():
            gaps = (worker["ts"] - case["reported_at"]).map(minutes).abs()
            pool = set(worker.loc[gaps <= width, "resource_id"])
            truth = expected[case["case_id"]] & set(worker["resource_id"])
            hit += len(pool & truth)
            want += len(truth)
            got += len(pool)
            counts.append(len(pool))
        print(f"window=+-{width:>5}m recall={hit}/{want} precision={hit}/{got} avg_candidates={sum(counts) / len(counts):.1f}")


def candidates(data, expected, lo, hi):
    from ghost_audit.evidence import build_index
    from ghost_audit.linking import LinkIndex

    observations, _ = build_index()
    index = LinkIndex(observations)
    worker = worker_rows()
    scoped = worker["resource_id"].str.startswith(("account_", "analytics_"))
    keyless = ~worker["resource_id"].map(lambda rid: bool(index.keys.get(rid)))
    pool = worker[scoped & keyless]
    totals = Counter()
    for _, case in data.sample_requests.iterrows():
        target = {
            rid
            for rid in expected[case["case_id"]]
            if rid.startswith(("account_", "analytics_")) and not index.keys.get(rid)
        }
        gaps = (pool["ts"] - case["reported_at"]).map(minutes)
        rows = pool[(gaps >= lo) & (gaps <= hi)]
        got = set(rows["resource_id"])
        totals["target"] += len(target)
        totals["hit"] += len(target & got)
        totals["candidates"] += len(got)
        print(f"\n{case['case_id']} reported={case['reported_at']} target={sorted(target)} hit={len(target & got)}/{len(target)} candidates={len(got)}")
        for _, row in rows.iterrows():
            gap = minutes(row["ts"] - case["reported_at"])
            flag = "*" if row["resource_id"] in target else " "
            print(f"  {flag} {row['resource_id']:<16} {row['event_type']:<16} {row['reported_result']:<8} {gap:8.1f}m {row['activity_id']}")
    print("\ntotals:", dict(totals))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["deltas", "sweep", "candidates"])
    parser.add_argument("--lo", type=float, default=-90)
    parser.add_argument("--hi", type=float, default=130)
    args = parser.parse_args()
    data = load_dataset()
    expected = expected_resources(data)
    if args.mode == "deltas":
        deltas(data, expected)
    elif args.mode == "sweep":
        sweep(data, expected)
    else:
        candidates(data, expected, args.lo, args.hi)


if __name__ == "__main__":
    main()