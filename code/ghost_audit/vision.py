import argparse
import json
import sys
import time
from pathlib import Path

from ghost_audit.evidence import PREFIX_SYSTEM, make_obs, prefix_of
from ghost_audit.llm import LLMRouter
from ghost_audit.loaders import evidence_path, read_csv

CACHE_FILE = Path(".cache/vision.json")
IMAGE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}

PROMPT = (
    "You transcribe screenshots of internal admin consoles for a data-deletion audit. "
    "Return JSON only with this shape: "
    '{"console": string, "captured_at": string|null, "records": [{"system_id": string|null, '
    '"resource_id": string|null, "record_type": string|null, "name": string|null, "email": string|null, '
    '"phone": string|null, "email_hash": string|null, "user_id": string|null, "status": string|null, '
    '"enabled": boolean|null, "restore_allowed": boolean|null, "exists": boolean|null, "notes": string|null}], '
    '"other_text": [string]}. '
    "Transcribe every visible row verbatim. Use null for empty, masked, or absent values. "
    "Set exists to true when the row is shown as an existing record and false when the console shows not found, "
    "deleted, or no results for it. Preserve resource ids such as account_123 or search_45 exactly. "
    "Never infer or invent values."
)


def load_cache():
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    return {}


def save_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=1), encoding="utf-8")


def transcribe(force=False, pause=4.0):
    router = LLMRouter(primary="gemini")
    cache = load_cache()
    manifest = read_csv("evidence_files.csv")
    for _, row in manifest.iterrows():
        path = evidence_path(row["file_path"])
        suffix = path.suffix.lower()
        if suffix not in IMAGE_TYPES:
            continue
        file_id = row["file_id"]
        if file_id in cache and not force:
            continue
        try:
            result = router.complete_json(
                PROMPT,
                "Transcribe this screenshot.",
                images=[(path.read_bytes(), IMAGE_TYPES[suffix])],
                purpose="vision",
            )
        except Exception as error:
            print(file_id, path.name, "FAILED", error)
            continue
        cache[file_id] = result
        save_cache(cache)
        records = result.get("records", []) if isinstance(result, dict) else result
        print(file_id, path.name, len(records), "records")
        time.sleep(pause)


def to_obs(file_id, captured, stem):
    entry = load_cache().get(file_id)
    if not entry:
        return []
    records = entry.get("records", []) if isinstance(entry, dict) else entry
    out = []
    for record in records:
        rid = str(record.get("resource_id") or "").strip()
        if not rid:
            continue
        items = [
            ("full_name", record.get("name")),
            ("email", record.get("email")),
            ("phone", record.get("phone")),
            ("email_hash", record.get("email_hash")),
            ("user_id", record.get("user_id")),
        ]
        state = [("enabled", record.get("enabled")), ("restore_allowed", record.get("restore_allowed"))]
        system = str(record.get("system_id") or PREFIX_SYSTEM.get(prefix_of(rid), ""))
        out.append(
            make_obs(file_id, "image", captured, rid, system, stem, str(record.get("record_type") or ""), items, record.get("exists"), state)
        )
    return out


def show():
    for file_id, entry in load_cache().items():
        records = entry.get("records", []) if isinstance(entry, dict) else entry
        print(f"\n{file_id}: {entry.get('console') if isinstance(entry, dict) else ''} captured={entry.get('captured_at') if isinstance(entry, dict) else ''}")
        for record in records:
            print("  ", json.dumps(record, ensure_ascii=False))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["run", "show"])
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.mode == "run":
        transcribe(force=args.force)
    else:
        show()


if __name__ == "__main__":
    main()