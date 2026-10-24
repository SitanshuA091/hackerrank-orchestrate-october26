import os
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _find_dataset_dir():
    candidates = []
    override = os.getenv("DATASET_DIR")
    if override:
        candidates.append(Path(override))
    candidates.append(PROJECT_ROOT.parent / "dataset")
    candidates.append(PROJECT_ROOT / "dataset")
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    raise FileNotFoundError("dataset directory not found; set DATASET_DIR")


DATASET_DIR = _find_dataset_dir()
EVIDENCE_DIR = DATASET_DIR / "evidence"
TIMESTAMP_COLUMNS = ("requested_at", "reported_at", "audit_at")


def read_csv(name):
    frame = pd.read_csv(DATASET_DIR / name, dtype=str, keep_default_na=False)
    frame.columns = [column.strip() for column in frame.columns]
    for column in frame.columns:
        frame[column] = frame[column].str.strip()
    return frame


def parse_timestamps(frame, columns=TIMESTAMP_COLUMNS):
    for column in columns:
        if column in frame.columns:
            frame[column] = pd.to_datetime(frame[column], utc=True, errors="coerce")
    return frame


def evidence_path(relative):
    relative = str(relative).strip().lstrip("/\\")
    for base in (EVIDENCE_DIR, DATASET_DIR):
        candidate = base / relative
        if candidate.exists():
            return candidate
    matches = list(EVIDENCE_DIR.rglob(Path(relative).name))
    if matches:
        return matches[0]
    raise FileNotFoundError(relative)


def list_evidence():
    return sorted(path for path in EVIDENCE_DIR.rglob("*") if path.is_file())


@dataclass
class Dataset:
    requests: pd.DataFrame
    sample_requests: pd.DataFrame
    sample_output: pd.DataFrame
    identities: pd.DataFrame
    audit_log: pd.DataFrame
    activity: pd.DataFrame
    rules: pd.DataFrame
    evidence_manifest: pd.DataFrame


def load_dataset():
    return Dataset(
        requests=parse_timestamps(read_csv("deletion_requests.csv")),
        sample_requests=parse_timestamps(read_csv("sample_deletion_requests.csv")),
        sample_output=read_csv("sample_output.csv"),
        identities=read_csv("user_identities.csv"),
        audit_log=read_csv("user_audit_log.csv"),
        activity=read_csv("system_activity.csv"),
        rules=read_csv("deletion_rules.csv"),
        evidence_manifest=read_csv("evidence_files.csv"),
    )


def describe(rows=3):
    names = (
        "deletion_requests.csv",
        "sample_deletion_requests.csv",
        "sample_output.csv",
        "user_identities.csv",
        "user_audit_log.csv",
        "system_activity.csv",
        "deletion_rules.csv",
        "evidence_files.csv",
    )
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", None)
    pd.set_option("display.max_colwidth", 80)
    for name in names:
        frame = read_csv(name)
        print(f"\n=== {name} {frame.shape} ===")
        print(frame.head(rows).to_string(index=False))
    counts = {}
    for path in list_evidence():
        counts[path.suffix.lower()] = counts.get(path.suffix.lower(), 0) + 1
    print("\n=== evidence by extension ===")
    print(counts)
    print([str(path.relative_to(EVIDENCE_DIR)) for path in list_evidence()[:15]])


if __name__ == "__main__":
    describe()