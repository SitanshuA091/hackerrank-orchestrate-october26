import argparse
import json
import sys

import pandas as pd

from ghost_audit import activity, attribution, scoring
from ghost_audit.evidence import PREFIX_SYSTEM, build_index, identity_keys, prefix_of
from ghost_audit.identity import IdentityResolver
from ghost_audit.linking import LinkIndex
from ghost_audit.loaders import load_dataset
from ghost_audit.planner import Entry, plan
from ghost_audit.rules import categorize, noncompliant
from ghost_audit.state import StateIndex

RELEVANT_PREFIXES = {"account", "analytics", "search", "support", "export", "tombstone"}
RELEVANCE_MINUTES = 180
KINDS = {"none": (), "account": ("account",), "all": ("account", "analytics")}


class World:
    def __init__(self, attr="all", relevance=True):
        self.relevance = relevance
        self.data = load_dataset()
        observations, meta = build_index()
        self.links = LinkIndex(observations)
        self.states = StateIndex(observations, meta)
        self.resolver = IdentityResolver(self.data.identities, self.data.audit_log)
        self.non_deletion = activity.non_deletion_resources()
        self.cases = pd.concat([self.data.sample_requests, self.data.requests], ignore_index=True)
        self.key_owned = {row["case_id"]: self.keys_for(row) for _, row in self.cases.iterrows()}
        self.attributed = attribution.assign(self.cases, self.key_owned, KINDS[attr], self.has_obs)

    def relevant(self, rid, reported_at):
        if not self.relevance or prefix_of(rid) not in RELEVANT_PREFIXES:
            return True
        ops = activity.policy_ops(rid, worker_only=True)
        if not ops:
            return True
        return any(abs((op[0] - reported_at).total_seconds()) <= RELEVANCE_MINUTES * 60 for op in ops)

    def has_obs(self, rid, case):
        for _, _, file_ts in self.states.by_res.get(rid, []):
            if file_ts is not None and file_ts <= case["audit_at"]:
                return True
        return False

    def keys_for(self, row):
        identity = self.resolver.resolve(row["email"], at=row["requested_at"])
        if identity is None:
            return []
        direct, linked = self.links.resources_for(identity_keys(identity))
        found = [rid for rid in direct | linked if prefix_of(rid) in PREFIX_SYSTEM]
        return sorted(rid for rid in found if self.relevant(rid, row["reported_at"]))

    def owned(self, case_id):
        return sorted(set(self.key_owned.get(case_id, [])) | set(self.attributed.get(case_id, [])))


def audit_case(world, row, owned=None):
    resources = world.owned(row["case_id"]) if owned is None else owned
    if set(resources) & world.non_deletion:
        return "NOT_APPLICABLE", []
    entries = []
    when = row["audit_at"]
    for rid in resources:
        state = world.states.at(rid, when)
        category, action = categorize(state, when)
        system = state.system or PREFIX_SYSTEM.get(prefix_of(rid), "")
        entries.append(Entry(rid, system, category, action, noncompliant(action, state, when), state))
    complete = not any(entry.bad for entry in entries)
    return ("COMPLETE" if complete else "INCOMPLETE"), plan(entries, complete)


def expected_map(frame):
    return {row["case_id"]: (row["deletion_status"], json.loads(row["steps_json"])) for _, row in frame.iterrows()}


def run_sample(world, oracle, show):
    expected = expected_map(world.data.sample_output)
    pred = {}
    hit = got = want = 0
    for _, row in world.data.sample_requests.iterrows():
        case_id = row["case_id"]
        truth = {step["resource_id"] for step in expected[case_id][1] if step["resource_id"]}
        mine = set(world.attributed.get(case_id, []))
        hit += len(mine & truth)
        got += len(mine)
        want += len(truth - set(world.key_owned.get(case_id, [])))
        owned = sorted(truth) if oracle else None
        pred[case_id] = audit_case(world, row, owned)
    print(f"attribution: correct={hit} assigned={got} keyless_expected={want}")
    return scoring.evaluate(pred, expected, show)


def run_full(world, path):
    rows = []
    for _, row in world.data.requests.iterrows():
        status, steps = audit_case(world, row)
        rows.append({"case_id": row["case_id"], "deletion_status": status, "steps_json": json.dumps(steps, separators=(",", ":"))})
    frame = pd.DataFrame(rows).sort_values("case_id")
    frame.to_csv(path, index=False)
    print(frame["deletion_status"].value_counts().to_string())
    print("rows:", len(frame), "| NOT_APPLICABLE expected: 10")


def explain(world, case_id, oracle):
    case = world.cases[world.cases["case_id"] == case_id].iloc[0]
    expected = expected_map(world.data.sample_output).get(case_id)
    exp_steps = expected[1] if expected else []
    exp_res = sorted({step["resource_id"] for step in exp_steps if step["resource_id"]})
    mine = world.owned(case_id)
    print(case_id, case["email"], case["reported_status"], "reported", case["reported_at"], "audit", case["audit_at"])
    print("expected status:", expected[0] if expected else "?", "| owned:", mine, "| expected resources:", exp_res)
    when = case["audit_at"]
    for rid in sorted(set(mine) | set(exp_res)):
        state = world.states.at(rid, when)
        category, action = categorize(state, when)
        bad = noncompliant(action, state, when)
        tag = ("OK" if rid in exp_res else "EXTRA") if rid in mine else "MISSED"
        flags = {key: value for key, value in state.pii.items() if value}
        print(
            f"\n[{tag}] {rid} action={action} bad={bad} present={state.present} enabled={state.enabled} "
            f"restore={state.restore_allowed} pii={flags} cite_present={state.cite_present} cite_absent={state.cite_absent}"
        )
        for item, _, _ in world.states.by_res.get(rid, [])[:8]:
            print("   OBS", item.file_id, item.kind, item.ts, "present=", item.present, "inferred=", item.inferred, "store=", item.store, "type=", item.record_type, "enabled=", item.enabled, "restore=", item.restore_allowed)
        for ts, act, result, source in activity.policy_ops(rid)[:5]:
            print("   OP ", ts, act, result, source)
        for step in exp_steps:
            if step["resource_id"] == rid:
                print("   EXP", step["phase"], step["operation"], step["evidence_id"] or "-")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["sample", "full", "explain"])
    parser.add_argument("--case", nargs="*", default=[])
    parser.add_argument("--oracle", action="store_true")
    parser.add_argument("--show", type=int, default=8)
    parser.add_argument("--attr", choices=list(KINDS), default="all")
    parser.add_argument("--no-relevance", action="store_true")
    parser.add_argument("--output", default="output.csv")
    args = parser.parse_args()
    world = World(attr=args.attr, relevance=not args.no_relevance)
    if args.mode == "sample":
        run_sample(world, args.oracle, args.show)
    elif args.mode == "full":
        run_full(world, args.output)
    else:
        for case_id in args.case:
            explain(world, case_id, args.oracle)
            print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()