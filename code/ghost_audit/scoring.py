from collections import Counter


def keyed(steps):
    return [(s["phase"], s["operation"], s["system_id"], s["resource_id"], s["state"]) for s in steps]


def evaluate(pred, expected, show=8):
    totals = Counter()
    shown = 0
    for case_id in sorted(expected):
        exp_status, exp_steps = expected[case_id]
        got_status, got_steps = pred.get(case_id, ("", []))
        exp_keys, got_keys = keyed(exp_steps), keyed(got_steps)
        common = Counter(exp_keys) & Counter(got_keys)
        exp_evidence = {key: step["evidence_id"] for key, step in zip(exp_keys, exp_steps)}
        evidence_bad = []
        for key, step in zip(got_keys, got_steps):
            if key in exp_evidence:
                totals["evidence_total"] += 1
                if step["evidence_id"] == exp_evidence[key]:
                    totals["evidence_ok"] += 1
                else:
                    evidence_bad.append((key, exp_evidence[key], step["evidence_id"]))
        status_ok = exp_status == got_status
        sequence_ok = exp_keys == got_keys
        order_ok = [key for key in got_keys if key in common] == [key for key in exp_keys if key in common]
        totals["cases"] += 1
        totals["status_ok"] += status_ok
        totals["sequence_ok"] += sequence_ok
        totals["order_ok"] += order_ok
        totals["exp_steps"] += len(exp_keys)
        totals["got_steps"] += len(got_keys)
        totals["hit_steps"] += sum(common.values())
        if status_ok and sequence_ok and not evidence_bad:
            totals["perfect"] += 1
            continue
        if shown < show:
            shown += 1
            print(f"\n{case_id} exp={exp_status} got={got_status} sequence_ok={sequence_ok}")
            for key in (Counter(exp_keys) - Counter(got_keys)).elements():
                print("   MISSING", key)
            for key in (Counter(got_keys) - Counter(exp_keys)).elements():
                print("   EXTRA  ", key)
            for key, want, have in evidence_bad:
                print("   EVIDENCE", key, "expected", want, "got", have)
    cases = max(totals["cases"], 1)
    print("\nstatus accuracy      :", f"{totals['status_ok']}/{cases}")
    print("step recall          :", f"{totals['hit_steps']}/{totals['exp_steps']}")
    print("step precision       :", f"{totals['hit_steps']}/{totals['got_steps']}")
    print("evidence on matched  :", f"{totals['evidence_ok']}/{totals['evidence_total']}")
    print("order ok (common)    :", f"{totals['order_ok']}/{cases}")
    print("exact sequence       :", f"{totals['sequence_ok']}/{cases}")
    print("perfect cases        :", f"{totals['perfect']}/{cases}")
    return dict(totals)