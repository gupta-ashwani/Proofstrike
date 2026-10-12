"""
Spider — BFS page explorer that discovers all navigable pages.

Handles:
  - BFS traversal starting from the base URL
  - Extracting links from <a href>, onclick handlers, etc.
  - URL canonicalization to avoid duplicate visits
  - Domain boundary enforcement
  - Skipping logout / destructive URLs (session-killing or state-changing GETs)
  - Depth and page budget limits
  - Waiting for network idle after each navigation
  - Re-authenticating when a page bounces to the login screen (via session_guard)
"""

import asyncio
import logging
import re
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode

from playwright.async_api import Page, TimeoutError as PlaywrightTimeout

logger = logging.getLogger("proofstrike.crawler.spider")

# URL keywords that indicate the link ends the session or changes/destroys data.
# A keyword must start a path/query segment ("/logout", "?action=delete",
# "/user-remove"), so words merely containing it ("/undeleted") are not skipped.
DEFAULT_EXCLUDE_KEYWORDS = [
    "logout", "log-out", "log_out", "signout", "sign-out", "sign_out", "logoff", "log-off",
    "delete", "remove", "destroy", "drop", "purge", "truncate", "reset",
    "unsubscribe", "deactivate", "revoke", "disable",
]
DEFAULT_EXCLUDE_PATTERN = (
    r"(?:^|[/?&=_.\-])(?:" + "|".join(re.escape(k) for k in DEFAULT_EXCLUDE_KEYWORDS) + r")"
)


class UrlExcluder:
    """
    Decides whether a URL must never be navigated to by the crawler.

    Matches the default logout/destructive keywords plus any user-supplied
    regexes (scan config "exclude_patterns") against the URL's path + query.
    """

    def __init__(self, extra_patterns: list[str] | None = None):
        self.patterns = [re.compile(DEFAULT_EXCLUDE_PATTERN, re.IGNORECASE)]
        for pattern in extra_patterns or []:
            try:
                self.patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.warning("Ignoring invalid exclude pattern %r: %s", pattern, e)

    def is_excluded(self, url: str) -> bool:
        parsed = urlparse(url)
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        return any(p.search(target) for p in self.patterns)


@dataclass
class CrawlResult:
    """Result of crawling a single page."""
    url: str
    final_url: str  # After redirects
    status: int | None = None
    title: str = ""
    links_found: list[str] = field(default_factory=list)
    error: str | None = None


def canonicalize_url(url: str) -> str:
    """
    Normalize a URL for deduplication.
    - Strips fragments (#...)
    - Strips trailing slashes from path
    - Sorts query parameters
    - Lowercases scheme and host
    """
    parsed = urlparse(url)

    # Lowercase scheme and host
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Remove trailing slash from path (unless it's just "/")
    path = parsed.path.rstrip("/") or "/"

    # Sort query parameters for consistent comparison
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    sorted_query = urlencode(sorted(query_params.items()), doseq=True)

    # Reconstruct without fragment
    return urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))


def is_same_domain(url: str, base_domain: str) -> bool:
    """Check if a URL belongs to the same domain as the base."""
    try:
        parsed = urlparse(url)
        url_domain = parsed.netloc.lower().split(":")[0]  # Strip port
        base = base_domain.lower().split(":")[0]
        return url_domain == base or url_domain.endswith("." + base)
    except Exception:
        return False


def is_crawlable_url(url: str) -> bool:
    """Filter out non-HTTP URLs and static asset URLs."""
    parsed = urlparse(url)

    # Only HTTP/HTTPS
    if parsed.scheme not in ("http", "https"):
        return False

    # Skip common static asset extensions
    skip_extensions = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".avi",
        ".mov", ".wmv", ".doc", ".docx", ".xls", ".xlsx",
    }
    path_lower = parsed.path.lower()
    for ext in skip_extensions:
        if path_lower.endswith(ext):
            return False

    return True


# Called after each navigation with (requested_url, landed_url). Returns True if it
# restored a lost session, in which case the page is loaded again.
SessionGuard = Callable[[str, str], Awaitable[bool]]


class Spider:
    """
    BFS spider that discovers all navigable pages within a target domain.

    Usage:
        spider = Spider(page, base_url="https://example.com", max_depth=3, max_pages=50)
        async for result in spider.crawl():
            print(result.url, len(result.links_found))
    """

    def __init__(
        self,
        page: Page,
        base_url: str,
        max_depth: int = 5,
        max_pages: int = 100,
        wait_after_navigation: int = 2_000,
        excluder: UrlExcluder | None = None,
        session_guard: SessionGuard | None = None,
        limiter=None,
        scope=None,
        extra_seeds: list[str] | None = None,
    ):
        self.page = page
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.wait_after_navigation = wait_after_navigation
        self.excluder = excluder or UrlExcluder()
        self.session_guard = session_guard
        self.limiter = limiter
        self.extra_seeds = extra_seeds or []

        # In-scope domain(s). Default to the base URL's own host + subdomains.
        from app.engine.crawler.scope import DomainScope
        self.scope = scope or DomainScope(self.base_url)
        self.base_domain = urlparse(self.base_url).netloc.lower()

        # BFS state
        self.visited: set[str] = set()
        self.queue: deque[tuple[str, int]] = deque()  # (url, depth)
        self.pages_crawled: int = 0
        self.excluded_urls: list[str] = []  # canonical URLs skipped as unsafe

        # Cancellation flag
        self._cancelled = False

    def cancel(self):
        """Signal the spider to stop crawling."""
        self._cancelled = True

    async def crawl(self):
        """
        BFS crawl generator — yields CrawlResult for each page visited.
        """
        # Seed the queue with the base URL
        canonical_base = canonicalize_url(self.base_url)
        self.queue.append((self.base_url, 0))
        self.visited.add(canonical_base)

        # Seed extra URLs (e.g. from sitemap/robots), filtered like discovered links
        for seed in self.extra_seeds:
            canonical = canonicalize_url(seed)
            if (
                canonical not in self.visited
                and self.scope.contains(seed)
                and is_crawlable_url(seed)
                and not self.excluder.is_excluded(seed)
            ):
                self.visited.add(canonical)
                self.queue.append((seed, 0))

        while self.queue and not self._cancelled:
            # Budget check
            if self.pages_crawled >= self.max_pages:
                logger.info("Page budget reached (%d pages)", self.max_pages)
                break

            url, depth = self.queue.popleft()

            # Depth check
            if depth > self.max_depth:
                continue

            logger.info(
                "[%d/%d] Crawling depth=%d: %s",
                self.pages_crawled + 1, self.max_pages, depth, url,
            )

            result = await self._visit_page(url)
            self.pages_crawled += 1

            # Enqueue discovered links
            for link in result.links_found:
                canonical = canonicalize_url(link)
                if (
                    canonical not in self.visited
                    and self.scope.contains(link)
                    and is_crawlable_url(link)
                ):
                    self.visited.add(canonical)
                    if self.excluder.is_excluded(link):
                        logger.info("Skipping unsafe URL: %s", link)
                        self.excluded_urls.append(canonical)
                        continue
                    self.queue.append((link, depth + 1))

            yield result

        if self._cancelled:
            logger.info("Spider cancelled after %d pages", self.pages_crawled)

    async def _navigate(self, url: str, result: CrawlResult):
        """Load url and wait for it to settle, recording status and final URL."""
        if self.limiter is not None:
            async with self.limiter:
                response = await self.page.goto(url, wait_until="domcontentloaded")
        else:
            response = await self.page.goto(url, wait_until="domcontentloaded")

        if response:
            result.status = response.status
            result.final_url = self.page.url

        # Wait for any dynamic content to load
        try:
            await self.page.wait_for_load_state("networkidle", timeout=self.wait_after_navigation)
        except PlaywrightTimeout:
            logger.debug("Network idle timeout for %s — proceeding", url)

        # Small extra wait for SPA rendering
        await asyncio.sleep(0.5)

    async def _visit_page(self, url: str) -> CrawlResult:
        """Navigate to a page and extract all links from it."""
        result = CrawlResult(url=url, final_url=url)

        try:
            await self._navigate(url, result)

            # Bounced to the login page? Restore the session and load the page again.
            if self.session_guard and await self.session_guard(url, self.page.url):
                await self._navigate(url, result)

            # Extract page title
            result.title = await self.page.title() or ""

            # Extract all links from the page
            result.links_found = await self._extract_links()

            logger.debug(
                "Page %s: status=%s, title='%s', links=%d",
                url, result.status, result.title[:50], len(result.links_found),
            )

        except PlaywrightTimeout:
            result.error = "Navigation timeout"
            logger.warning("Timeout navigating to %s", url)
        except Exception as e:
            result.error = str(e)
            logger.warning("Error crawling %s: %s", url, e)

        return result

    async def _extract_links(self) -> list[str]:
        """Extract all navigable links from the current page."""
        links = set()
        current_url = self.page.url

        # 1. <a href="..."> links
        try:
            anchors = await self.page.eval_on_selector_all(
                "a[href]",
                """elements => elements.map(el => ({
                    href: el.href,
                    target: el.target || '',
                }))""",
            )
            for anchor in anchors:
                href = anchor.get("href", "")
                if href and not href.startswith("javascript:") and not href.startswith("mailto:"):
                    absolute = urljoin(current_url, href)
                    links.add(absolute)
        except Exception as e:
            logger.debug("Error extracting anchor links: %s", e)

        # 2. <form action="..."> — extract form targets
        try:
            forms = await self.page.eval_on_selector_all(
                "form[action]",
                "elements => elements.map(el => el.action)",
            )
            for action in forms:
                if action:
                    absolute = urljoin(current_url, action)
                    links.add(absolute)
        except Exception as e:
            logger.debug("Error extracting form actions: %s", e)

        # 3. <link> and <meta> with URLs (for API discovery)
        try:
            meta_urls = await self.page.eval_on_selector_all(
                'link[href], meta[content]',
                """elements => elements.map(el => {
                    if (el.tagName === 'LINK') return el.href;
                    const content = el.content || '';
                    if (content.startsWith('http')) return content;
                    return null;
                }).filter(Boolean)""",
            )
            for u in meta_urls:
                if u:
                    links.add(u)
        except Exception as e:
            logger.debug("Error extracting meta URLs: %s", e)

        # Filter to same domain only
        same_domain_links = [
            link for link in links
            if self.scope.contains(link)
        ]

        return same_domain_links
