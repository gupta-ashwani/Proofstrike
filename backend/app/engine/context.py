"""
ScanContext — shared state threaded through every pipeline stage.

The pipeline builds one ScanContext (parsed config, rate limiter, URL excluder,
resolved auth) and hands it to each stage in turn. Stages read what they need and
write their results back onto it:

  - crawl stage fills `storage_state` (the authenticated browser session) so later
    stages can reuse the login without persisting cookies to the database, and
    adds its metrics to `stats`.
  - detect / verify stages (Phase 4 / 5) read endpoints from the DB and the
    session from `storage_state`.

The authenticated session lives only in memory for the duration of the scan.
"""

import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.engine.throttle import RateLimiter
from app.engine.crawler.auth import AuthConfig
from app.engine.crawler.spider import UrlExcluder
from app.engine.crawler.scope import DomainScope

logger = logging.getLogger("proofstrike.engine.context")

# Defaults when the scan config does not specify them
DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_PAGES = 100
DEFAULT_REQUEST_DELAY = 0.0      # seconds between requests (0 = no artificial gap)
DEFAULT_MAX_CONCURRENCY = 1
DEFAULT_DETECTORS = ["xss", "sqli"]


def _int(config: dict, keys: tuple[str, ...], default: int, minimum: int) -> int:
    """First present key in config as an int clamped to `minimum` (explicit 0 respected)."""
    for key in keys:
        value = config.get(key)
        if value is not None:
            try:
                return max(minimum, int(value))
            except (TypeError, ValueError):
                logger.warning("Ignoring invalid scan config %s=%r", key, value)
    return default


def _float(config: dict, key: str, default: float, minimum: float) -> float:
    value = config.get(key)
    if value is None:
        return default
    try:
        return max(minimum, float(value))
    except (TypeError, ValueError):
        logger.warning("Ignoring invalid scan config %s=%r", key, value)
        return default


@dataclass
class ScanContext:
    scan_id: str
    session_factory: async_sessionmaker[AsyncSession]
    base_url: str
    base_domain: str
    headless: bool
    max_depth: int
    max_pages: int
    detectors: list[str]
    auth_config: dict | None          # resolved (absolute login_url), or None
    secret_values: set[str]           # credential values that must never be stored
    limiter: RateLimiter
    excluder: UrlExcluder
    scope: DomainScope
    use_sitemap: bool
    verify_post: bool
    stats: dict = field(default_factory=dict)
    storage_state: dict | None = None  # authenticated Playwright session (in memory only)

    @property
    def authenticated(self) -> bool:
        return bool(self.stats.get("auth_success"))

    @classmethod
    def build(cls, scan_id, session_factory, target, scan_config: dict | None) -> "ScanContext":
        """Parse a target + scan config into a ready-to-run context."""
        config = scan_config or {}
        base_url = target.base_url.rstrip("/")

        auth_config = target.auth_config
        if AuthConfig.is_configured(auth_config):
            # Allow a login_url relative to the target ("/login")
            auth_config = {
                **auth_config,
                "login_url": urljoin(target.base_url, auth_config["login_url"]),
            }
        else:
            auth_config = None

        secret_values = set()
        if auth_config:
            secret_values.add(str(auth_config.get("password", "")))
            for user in auth_config.get("users") or []:
                if isinstance(user, dict) and user.get("password"):
                    secret_values.add(str(user["password"]))
            secret_values.discard("")

        detectors = config.get("detectors")
        if not isinstance(detectors, list):
            detectors = list(DEFAULT_DETECTORS)

        extra_hosts = config.get("scope_hosts")
        if not isinstance(extra_hosts, list):
            extra_hosts = []

        return cls(
            scan_id=scan_id,
            session_factory=session_factory,
            base_url=base_url,
            base_domain=urlparse(base_url).netloc,
            headless=bool(config.get("headless", True)),
            max_depth=_int(config, ("max_depth", "crawl_depth"), DEFAULT_MAX_DEPTH, minimum=0),
            max_pages=_int(config, ("max_pages", "request_budget"), DEFAULT_MAX_PAGES, minimum=1),
            detectors=[str(d).lower() for d in detectors],
            auth_config=auth_config,
            secret_values=secret_values,
            limiter=RateLimiter(
                delay=_float(config, "request_delay", DEFAULT_REQUEST_DELAY, minimum=0.0),
                max_concurrency=_int(config, ("max_concurrency",), DEFAULT_MAX_CONCURRENCY, minimum=1),
            ),
            excluder=UrlExcluder(config.get("exclude_patterns")),
            scope=DomainScope(base_url, [str(h) for h in extra_hosts]),
            use_sitemap=bool(config.get("use_sitemap", True)),
            verify_post=bool(config.get("verify_post", True)),
        )
