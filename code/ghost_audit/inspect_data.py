import argparse
import json
import re
import sqlite3
import sys
from collections import Counter

import pandas as pd

from ghost_audit.loaders import EVIDENCE_DIR, list_evidence, load_dataset


def clip(text, limit):
    text = str(text)
    return text if len(text) <= limit else text[:limit] + f"...[+{len(text) - limit} chars]"


def group_name(path):
    return re.sub(r"_\d{6,8}$", "", path.stem)


def show_data():
    data = load_dataset()
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", None)
    pd.set_option("display.max_colwidth", 140)
    print("=== deletion_rules ===")
    print(data.rules.to_string(index=False))
    for column in ("event_type", "source_system", "target_system", "reported_result"):
        print(f"\n=== activity.{column} ===")
        print(data.activity[column].value_counts().to_string())
    print("\n=== one activity row per event_type ===")
    print(data.activity.groupby("event_type").head(1).to_string(index=False))
    print("\n=== audit_log.field_name ===")
    print(data.audit_log["field_name"].value_counts().to_string())
    output = data.sample_output
    print("\n=== sample status counts ===")
    print(output["deletion_status"].value_counts().to_string())
    merged = data.sample_requests.merge(output, on="case_id")
    print("\n=== NOT_APPLICABLE sample texts ===")
    for _, row in merged[merged["deletion_status"] == "NOT_APPLICABLE"].head(6).iterrows():
        print(row["case_id"], "|", row["reported_status"], "|", row["request_text"])
    print("\n=== INCOMPLETE sample cases ===")
    for _, row in merged[merged["deletion_status"] == "INCOMPLETE"].head(2).iterrows():
        print(row["case_id"], row["email"], row["reported_status"], row["requested_at"], row["audit_at"])
        print(row["request_text"])
        for step in json.loads(row["steps_json"]):
            print("  ", json.dumps(step, sort_keys=True))
    combos = Counter()
    for raw in output["steps_json"]:
        for step in json.loads(raw):
            combos[(step["phase"], step["operation"], step["system_id"])] += 1
    print("\n=== step combos in samples ===")
    for key, count in sorted(combos.items()):
        print(count, key)


def preview_sql(path, chars):
    text = path.read_text(encoding="utf-8", errors="replace")
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(text)
    except Exception as error:
        return f"SQL load error: {error}\n" + clip(text, chars)
    lines = []
    tables = connection.execute("select name, sql from sqlite_master where type='table'").fetchall()
    for name, sql in tables:
        count = connection.execute(f'select count(*) from "{name}"').fetchone()[0]
        rows = connection.execute(f'select * from "{name}" limit 2').fetchall()
        lines.append(f"{sql}\n  rows={count} sample={rows}")
    return clip("\n".join(lines), chars * 3)


def preview(path, ext, chars):
    try:
        if ext == ".sql":
            return preview_sql(path, chars)
        if ext in (".log", ".txt"):
            return clip(path.read_text(encoding="utf-8", errors="replace"), chars)
        if ext == ".json":
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            return clip(json.dumps(payload, default=str), chars * 2)
        if ext == ".pdf":
            import fitz

            with fitz.open(path) as document:
                return f"pages={len(document)}\n" + clip(document[0].get_text(), chars)
        if ext in (".png", ".jpg", ".jpeg"):
            from PIL import Image

            with Image.open(path) as image:
                return f"size={image.size} mode={image.mode}"
        return "unsupported"
    except Exception as error:
        return f"ERROR {error}"


def show_evidence(ext_filter, chars):
    groups = {}
    for path in list_evidence():
        ext = path.suffix.lower()
        if ext_filter and ext != ext_filter:
            continue
        groups.setdefault((ext, group_name(path)), []).append(path)
    for (ext, name), paths in sorted(groups.items()):
        print(f"\n##### {ext} | {name} | {len(paths)} files | e.g. {paths[0].relative_to(EVIDENCE_DIR)}")
        print(preview(paths[0], ext, chars))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["data", "evidence"])
    parser.add_argument("--ext", default="")
    parser.add_argument("--chars", type=int, default=900)
    args = parser.parse_args()
    if args.mode == "data":
        show_data()
    else:
        show_evidence(args.ext.lower(), args.chars)


if __name__ == "__main__":
    main()