import hashlib
import re
from dataclasses import dataclass, field

import pandas as pd

CORE_FIELDS = ("name", "email", "phone", "email_hash")


def norm_email(value):
    return str(value).strip().lower()


def norm_digits(value):
    return re.sub(r"\D", "", str(value))


def norm_uid(value):
    value = str(value).strip()
    match = re.fullmatch(r"(\D*?)0*(\d+)", value)
    return f"{match.group(1)}{match.group(2)}" if match else value


def sha256_hex(value):
    return hashlib.sha256(norm_email(value).encode("utf-8")).hexdigest()


@dataclass
class UserIdentity:
    user_id: str
    values: dict
    matched_via: str
    ambiguous_with: list = field(default_factory=list)

    @property
    def names(self):
        return self.values.get("name", [])

    @property
    def emails(self):
        return self.values.get("email", [])

    @property
    def phones(self):
        return self.values.get("phone", [])

    @property
    def hashes(self):
        return self.values.get("email_hash", [])

    def find_in_text(self, text):
        lowered = text.lower()
        compact = norm_digits(text)
        found = {"email": [], "email_hash": [], "phone": [], "name": []}
        for email in self.emails:
            if norm_email(email) in lowered:
                found["email"].append(email)
        for digest in self.hashes:
            if digest.lower() in lowered:
                found["email_hash"].append(digest)
        for phone in self.phones:
            digits = norm_digits(phone)
            if phone in text or (len(digits) >= 8 and digits in compact):
                found["phone"].append(phone)
        for name in self.names:
            if name.lower() in lowered:
                found["name"].append(name)
        return {key: value for key, value in found.items() if value}


class IdentityResolver:
    def __init__(self, identities, audit_log):
        frame = identities.copy()
        frame["uid"] = frame["user_id"].map(norm_uid)
        self.current = frame.drop_duplicates("uid", keep="last").set_index("uid", drop=False)
        audit = audit_log.copy()
        audit["event_time"] = pd.to_datetime(audit["event_time"], utc=True, errors="coerce")
        audit["field"] = audit["field_name"].str.strip().str.lower()
        audit["uid"] = audit["user_id"].map(norm_uid)
        self.audit = audit
        self.events = {uid: group.sort_values("event_time") for uid, group in audit.groupby("uid")}
        self.hash_rate = self._hash_rate()
        self.derive_hashes = self.hash_rate > 0.99

    def _hash_rate(self):
        if self.current.empty:
            return 0.0
        expected = self.current["email"].map(sha256_hex)
        return float((expected == self.current["email_hash"].str.lower()).mean())

    def _candidates(self, email):
        key = norm_email(email)
        current_mask = self.current["email"].map(norm_email) == key
        current = set(self.current.loc[current_mask, "uid"])
        history_mask = (self.audit["field"] == "email") & (
            (self.audit["old_value"].map(norm_email) == key)
            | (self.audit["new_value"].map(norm_email) == key)
        )
        historical = set(self.audit.loc[history_mask, "uid"])
        return current, historical

    def _value_at(self, uid, field_name, at):
        base = ""
        if uid in self.current.index and field_name in self.current.columns:
            base = self.current.at[uid, field_name]
        events = self.events.get(uid)
        if at is None or events is None:
            return base
        rows = events[events["field"] == field_name]
        if rows.empty:
            return base
        before = rows[rows["event_time"] <= at]
        if before.empty:
            return rows.iloc[0]["old_value"]
        return before.iloc[-1]["new_value"]

    def _build(self, uid, via, others, as_of):
        values = {name: [] for name in CORE_FIELDS}

        def add(key, value):
            value = str(value).strip()
            if value and value not in values.setdefault(key, []):
                values[key].append(value)

        original = uid
        if uid in self.current.index:
            row = self.current.loc[uid]
            original = row["user_id"]
            for key in CORE_FIELDS:
                add(key, row.get(key, ""))
        events = self.events.get(uid)
        if events is not None:
            if as_of is not None:
                events = events[events["event_time"] <= as_of]
            for _, event in events.iterrows():
                add(event["field"], event["new_value"])
                add(event["field"], event["old_value"])
        if self.derive_hashes:
            for email in list(values["email"]):
                add("email_hash", sha256_hex(email))
        ambiguous = [self.current.at[other, "user_id"] if other in self.current.index else other for other in others]
        return UserIdentity(user_id=original, values=values, matched_via=via, ambiguous_with=ambiguous)

    def resolve(self, email, at=None, as_of=None):
        current, historical = self._candidates(email)
        pool = current | historical
        via = "current_email" if current else "email_history"
        if not pool:
            digest = sha256_hex(email)
            mask = self.current["email_hash"].str.lower() == digest
            pool = set(self.current.loc[mask, "uid"])
            via = "email_hash"
        if not pool:
            return None
        ordered = sorted(current) + sorted(pool - current)
        if len(pool) > 1 and at is not None:
            owners = [uid for uid in pool if norm_email(self._value_at(uid, "email", at)) == norm_email(email)]
            if owners:
                ordered = sorted(owners) + sorted(pool - set(owners))
        return self._build(ordered[0], via, ordered[1:], as_of)

    def resolve_all(self, requests):
        results = {}
        for _, row in requests.iterrows():
            results[row["case_id"]] = self.resolve(row["email"], at=row.get("requested_at"))
        return results


if __name__ == "__main__":
    from collections import Counter

    from ghost_audit.loaders import load_dataset

    data = load_dataset()
    resolver = IdentityResolver(data.identities, data.audit_log)
    print("email_hash == sha256(email) rate:", resolver.hash_rate)
    for label, frame in (("requests", data.requests), ("samples", data.sample_requests)):
        results = resolver.resolve_all(frame)
        via = Counter(identity.matched_via if identity else "UNRESOLVED" for identity in results.values())
        ambiguous = [case for case, identity in results.items() if identity and identity.ambiguous_with]
        unresolved = [case for case, identity in results.items() if identity is None]
        print(f"\n{label}: {dict(via)}")
        print("ambiguous:", ambiguous[:15])
        print("unresolved:", unresolved[:15])
    sample = resolver.resolve_all(data.sample_requests)
    widest = max((i for i in sample.values() if i), key=lambda i: sum(len(v) for v in i.values.values()))
    print("\nwidest identity:", widest)