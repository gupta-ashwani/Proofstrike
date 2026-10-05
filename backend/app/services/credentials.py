"""
Credential masking for target auth configs.

Test-account passwords are needed by the crawler but must never be sent back
out through the API. Responses carry a placeholder instead, and when a client
sends that placeholder back on update (e.g. the edit form round-trips the
config), the stored password is kept.
"""

import copy

PASSWORD_MASK = "********"
SECRET_KEYS = ("password",)


def mask_auth_config(auth_config: dict | None) -> dict | None:
    """Copy of auth_config with every password (top-level and in "users") masked."""
    if not auth_config:
        return auth_config
    masked = copy.deepcopy(auth_config)
    for entry in [masked, *(u for u in masked.get("users") or [] if isinstance(u, dict))]:
        for key in SECRET_KEYS:
            if entry.get(key):
                entry[key] = PASSWORD_MASK
    return masked


def merge_masked_secrets(incoming: dict | None, existing: dict | None) -> dict | None:
    """
    Replace masked placeholders in an incoming auth_config with the stored values.

    Top-level secrets come from the existing top level; entries in "users" are
    matched by username.
    """
    if not incoming or not existing:
        return incoming
    merged = copy.deepcopy(incoming)

    for key in SECRET_KEYS:
        if merged.get(key) == PASSWORD_MASK:
            merged[key] = existing.get(key)

    existing_users = {
        u.get("username"): u for u in existing.get("users") or [] if isinstance(u, dict)
    }
    for user in merged.get("users") or []:
        if not isinstance(user, dict):
            continue
        stored = existing_users.get(user.get("username"), {})
        for key in SECRET_KEYS:
            if user.get(key) == PASSWORD_MASK:
                user[key] = stored.get(key)

    return merged
