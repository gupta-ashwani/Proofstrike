"""
DomainScope — decides which URLs are in-scope for a crawl.

By default the scope is the target's own host (and its subdomains). A scan can
widen it via config "scope_hosts" to include, e.g., a separate API subdomain or
a second environment. Anything outside the scope is never crawled or recorded.
"""

from urllib.parse import urlparse


def _host_of(url_or_host: str) -> str:
    """Hostname (no port) from a URL or a bare host string."""
    text = url_or_host.strip()
    if "://" not in text:
        text = "//" + text  # let urlparse treat it as netloc, not path
    return urlparse(text).netloc.lower().split("@")[-1].split(":")[0]


class DomainScope:
    def __init__(self, base_url: str, extra_hosts: list[str] | None = None):
        self.domains: set[str] = set()
        for entry in [base_url, *(extra_hosts or [])]:
            host = _host_of(entry)
            if host:
                self.domains.add(host)

    def contains(self, url: str) -> bool:
        """True if url's host equals or is a subdomain of any in-scope domain."""
        try:
            host = _host_of(url)
        except Exception:
            return False
        if not host:
            return False
        return any(host == d or host.endswith("." + d) for d in self.domains)

    def __repr__(self) -> str:
        return f"<DomainScope {sorted(self.domains)}>"
