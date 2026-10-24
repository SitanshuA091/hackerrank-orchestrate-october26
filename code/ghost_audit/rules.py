from ghost_audit import activity

OPS = {
    "DELETE": ("REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED"),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "PRESENT", "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"),
    "RETAIN": (None, None, None, None, "VERIFY_RECORD_PRESENT"),
    "DISABLE": ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED"),
    "BLOCK": ("REPORT_RESTORE_RISK", "ACTIVE", "BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED"),
}

VERIFY_STATE = {
    "DELETE": "ABSENT",
    "REDACT": "REDACTED",
    "ANONYMIZE": "ANONYMIZED",
    "RETAIN": "PRESENT",
    "DISABLE": "DISABLED",
    "BLOCK": "BLOCKED",
}

TABLE = {
    "account": ("USER_PROFILE", "DELETE"),
    "search": ("SEARCH_INDEX_ENTRY", "DELETE"),
    "cache": ("CACHE_ENTRY", "DELETE"),
    "export": ("USER_EXPORT", "DELETE"),
    "marketing": ("MARKETING_PROFILE", "DELETE"),
    "identity": ("SECONDARY_IDENTIFIER", "DELETE"),
    "tombstone": ("ACCOUNT_TOMBSTONE", "REDACT"),
    "email_delivery": ("EMAIL_DELIVERY_LOG", "REDACT"),
    "audit_record": ("SECURITY_AUDIT_LOG", "RETAIN"),
    "legal_hold": ("LEGAL_HOLD_RECORD", "RETAIN"),
    "backup": ("BACKUP_ARCHIVE", "BLOCK"),
    "data_flow": ("ACTIVE_DATA_FLOW", "DISABLE"),
}

DIRECT_IDENTIFIERS = ("name", "email", "phone", "hash")


def worker_ops(resource_id, when):
    return [op for op in activity.policy_ops(resource_id, worker_only=True) if op[0] <= when]


def last_worker_action(resource_id, when):
    ops = worker_ops(resource_id, when)
    if not ops:
        return None
    return max(ops, key=lambda op: op[0])[1]


def worker_success(resource_id, action, when):
    return any(op[1] == action and op[2] == "SUCCESS" for op in worker_ops(resource_id, when))


def categorize(state, when):
    prefix = state.resource_id.rsplit("_", 1)[0]
    text = state.store_text
    if prefix == "support":
        base = ("SUPPORT_ATTACHMENT", "DELETE") if "attach" in text else ("SUPPORT_MESSAGE", "REDACT")
    elif prefix == "analytics":
        profile_copy = "customer_profiles" in text or "user_profile" in text or state.pii["name"]
        base = ("USER_PROFILE", "DELETE") if profile_copy else ("ANALYTICS_PROFILE", "ANONYMIZE")
    else:
        base = TABLE.get(prefix, ("UNKNOWN", "RETAIN"))
    action = last_worker_action(state.resource_id, when)
    if action in OPS:
        return base[0], action
    return base


def noncompliant(action, state, when):
    if action == "DELETE":
        return state.present is True
    if action == "REDACT":
        return state.present is True and any(state.pii[flag] for flag in DIRECT_IDENTIFIERS)
    if action == "ANONYMIZE":
        return state.present is True and any(state.pii.values())
    if action == "DISABLE":
        if state.enabled is not None:
            return bool(state.enabled)
        return not worker_success(state.resource_id, "DISABLE", when)
    if action == "BLOCK":
        if state.restore_allowed is not None:
            return bool(state.restore_allowed)
        return not worker_success(state.resource_id, "BLOCK", when)
    return False