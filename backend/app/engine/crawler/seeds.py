"""
Seed discovery — find URLs the link-crawl might not reach on its own.

Reads robots.txt (its Sitemap: directives and Allow/Disallow path hints) and
sitemap.xml (including sitemap-index files, one level of nesting), and returns
in-scope, crawlable candidate URLs to seed the spider with. This surfaces
"orphan" pages that nothing links to.

Bounded on purpose: capped URL count, capped sitemap fetches, fetches paced by
the shared limiter. Fetched through the authenticated request context so gated
sitemaps are reachable.
"""

import logging
import re
from urllib.parse import urljoin

from app.engine.crawler.scope import DomainScope
from app.engine.crawler.spider import UrlExcluder, is_crawlable_url

logger = logging.getLogger("proofstrike.crawler.seeds")

MAX_SEED_URLS = 500       # stop collecting candidates past this
MAX_SITEMAP_FETCHES = 20  # stop fetching sitemap documents past this
MAX_BODY_BYTES = 5_000_000

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


async def _fetch(request_context, url: str, limiter) -> str | None:
    try:
        async with limiter:
            resp = await request_context.get(url, max_redirects=3, timeout=10_000)
        try:
            if resp.status != 200:
                return None
            body = await resp.text()
            return body[:MAX_BODY_BYTES]
        finally:
            await resp.dispose()
    except Exception as e:
        logger.debug("Seed fetch failed for %s: %s", url, e)
        return None


async def discover_seeds(
    request_context,
    base_url: str,
    scope: DomainScope,
    excluder: UrlExcluder,
    limiter,
) -> list[str]:
    """Return in-scope, crawlable seed URLs from robots.txt + sitemap(s)."""
    base = base_url.rstrip("/") + "/"
    seeds: list[str] = []
    seen: set[str] = set()

    def add(candidate: str):
        absolute = urljoin(base, candidate)
        if (
            absolute not in seen
            and scope.contains(absolute)
            and is_crawlable_url(absolute)
            and not excluder.is_excluded(absolute)
        ):
            seen.add(absolute)
            seeds.append(absolute)

    # ── robots.txt ──
    sitemap_urls: list[str] = []
    robots = await _fetch(request_context, urljoin(base, "robots.txt"), limiter)
    if robots:
        for line in robots.splitlines():
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key == "sitemap" and value:
                sitemap_urls.append(value)
            elif key in ("allow", "disallow") and value and value != "/" and "*" not in value:
                add(value)

    # Fall back to the conventional location if robots named no sitemap
    if not sitemap_urls:
        sitemap_urls.append(urljoin(base, "sitemap.xml"))

    # ── sitemap(s), with one level of sitemap-index nesting ──
    queue = list(dict.fromkeys(sitemap_urls))
    fetches = 0
    while queue and fetches < MAX_SITEMAP_FETCHES and len(seeds) < MAX_SEED_URLS:
        sitemap = queue.pop(0)
        if not scope.contains(sitemap):
            continue
        fetches += 1
        xml = await _fetch(request_context, sitemap, limiter)
        if not xml:
            continue
        is_index = "<sitemapindex" in xml.lower()
        for loc in _LOC_RE.findall(xml):
            if is_index:
                if loc not in queue and fetches + len(queue) < MAX_SITEMAP_FETCHES:
                    queue.append(loc)
            else:
                add(loc)
                if len(seeds) >= MAX_SEED_URLS:
                    break

    if seeds:
        logger.info("Seed discovery: %d URLs from robots.txt/sitemap", len(seeds))
    return seeds[:MAX_SEED_URLS]
