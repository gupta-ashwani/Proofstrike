"""
Endpoint Extractor — discover API endpoints, forms, and parameters.

Two extraction sources:
  1. DOM-based: forms, input fields, links with query params
  2. Network-based: intercepted XHR/fetch requests from the browser

All discovered endpoints are deduplicated by (url_path, method) pair.
"""

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urljoin

from playwright.async_api import Page

from app.engine.crawler.browser import CapturedRequest

logger = logging.getLogger("proofstrike.crawler.extractor")


@dataclass
class DiscoveredEndpoint:
    """A discovered API endpoint or form action."""
    url: str
    method: str = "GET"
    params: dict | None = None       # query params or form fields
    source: str = "link"             # link, form, xhr, fetch, script
    auth_required: bool = False
    post_data: str | None = None     # raw POST body for XHR/fetch


def _parse_query_params(url: str) -> dict | None:
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Flatten single-value lists for cleaner storage
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    return None


def _strip_query(url: str) -> str:
    """Return URL without query string (for dedup key)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


class EndpointExtractor:
    """
    Extracts endpoints from both the DOM and intercepted network traffic.

    Usage:
        extractor = EndpointExtractor(page, base_domain="example.com")
        dom_endpoints = await extractor.extract_from_dom()
        net_endpoints = extractor.extract_from_network(captured_requests)
        all_endpoints = extractor.merge(dom_endpoints + net_endpoints)
    """

    def __init__(self, page: Page, base_domain: str):
        self.page = page
        self.base_domain = base_domain.lower()

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to target domain."""
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower().split(":")[0]
            base = self.base_domain.split(":")[0]
            return host == base or host.endswith("." + base)
        except Exception:
            return False

    async def extract_from_dom(self) -> list[DiscoveredEndpoint]:
        """
        Extract endpoints from the current page's DOM.

        Discovers:
          - Forms with their action URLs, methods, and input fields
          - Links with query parameters
          - Buttons with data attributes or onclick handlers
        """
        endpoints = []
        current_url = self.page.url

        # ── 1. Extract forms ──
        try:
            forms = await self.page.eval_on_selector_all(
                "form",
                """forms => forms.map(form => ({
                    action: form.action || '',
                    method: (form.method || 'GET').toUpperCase(),
                    inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(inp => ({
                        name: inp.name || '',
                        type: inp.type || 'text',
                        value: inp.value || '',
                        required: inp.required || false,
                    })).filter(inp => inp.name),
                }))""",
            )

            for form_data in forms:
                action = form_data.get("action", "") or current_url
                method = form_data.get("method", "GET")
                inputs = form_data.get("inputs", [])

                # Resolve relative URLs
                absolute_url = urljoin(current_url, action)

                if not self._is_same_domain(absolute_url):
                    continue

                # Build params from form inputs
                params = {}
                for inp in inputs:
                    name = inp.get("name", "")
                    if name:
                        params[name] = {
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                            "required": inp.get("required", False),
                        }

                endpoints.append(DiscoveredEndpoint(
                    url=_strip_query(absolute_url),
                    method=method,
                    params=params if params else None,
                    source="form",
                ))

            logger.debug("Extracted %d form endpoints", len(forms))

        except Exception as e:
            logger.debug("Error extracting forms: %s", e)

        # ── 2. Extract links with query params ──
        try:
            links = await self.page.eval_on_selector_all(
                "a[href]",
                "elements => elements.map(el => el.href).filter(Boolean)",
            )

            for href in links:
                absolute_url = urljoin(current_url, href)
                if not self._is_same_domain(absolute_url):
                    continue

                params = _parse_query_params(absolute_url)
                if params:
                    endpoints.append(DiscoveredEndpoint(
                        url=_strip_query(absolute_url),
                        method="GET",
                        params=params,
                        source="link",
                    ))

        except Exception as e:
            logger.debug("Error extracting link params: %s", e)

        # ── 3. Extract script-embedded API endpoints ──
        try:
            script_urls = await self.page.eval_on_selector_all(
                "script",
                """scripts => {
                    const urls = [];
                    const patterns = [
                        /['"](\\/api\\/[^'"\\s]+)['"]/g,
                        /['"](\\/v[0-9]+\\/[^'"\\s]+)['"]/g,
                        /fetch\\(['"]([^'"]+)['"]/g,
                        /axios\\.[a-z]+\\(['"]([^'"]+)['"]/g,
                        /\\.(?:get|post|put|delete|patch)\\(['"]([^'"]+)['"]/g,
                    ];
                    scripts.forEach(script => {
                        const text = script.textContent || '';
                        patterns.forEach(pattern => {
                            let match;
                            const re = new RegExp(pattern.source, pattern.flags);
                            while ((match = re.exec(text)) !== null) {
                                if (match[1]) urls.push(match[1]);
                            }
                        });
                    });
                    return [...new Set(urls)];
                }""",
            )

            for url_path in script_urls:
                absolute_url = urljoin(current_url, url_path)
                if self._is_same_domain(absolute_url) or url_path.startswith("/"):
                    if url_path.startswith("/"):
                        parsed_base = urlparse(current_url)
                        absolute_url = f"{parsed_base.scheme}://{parsed_base.netloc}{url_path}"

                    params = _parse_query_params(absolute_url)
                    endpoints.append(DiscoveredEndpoint(
                        url=_strip_query(absolute_url),
                        method="GET",
                        params=params,
                        source="script",
                    ))

            logger.debug("Extracted %d script-embedded API endpoints", len(script_urls))

        except Exception as e:
            logger.debug("Error extracting script URLs: %s", e)

        return endpoints

    def extract_from_network(
        self, captured_requests: list[CapturedRequest]
    ) -> list[DiscoveredEndpoint]:
        """
        Convert intercepted network requests into DiscoveredEndpoint objects.

        This captures the actual XHR/fetch calls the application makes.
        """
        endpoints = []

        for req in captured_requests:
            if not self._is_same_domain(req.url):
                continue

            # Determine source type
            source = "xhr"
            if req.resource_type == "fetch":
                source = "fetch"
            elif req.resource_type == "document":
                source = "navigation"
            elif req.resource_type == "form":
                source = "form"

            params = _parse_query_params(req.url)

            # Parse POST data as additional params
            post_params = None
            if req.post_data:
                try:
                    # Try URL-encoded form data
                    post_params = parse_qs(req.post_data, keep_blank_values=True)
                    post_params = {
                        k: v[0] if len(v) == 1 else v
                        for k, v in post_params.items()
                    }
                except Exception:
                    pass

            # Merge query params and post params
            all_params = {}
            if params:
                all_params.update(params)
            if post_params:
                all_params.update(post_params)

            endpoints.append(DiscoveredEndpoint(
                url=_strip_query(req.url),
                method=req.method,
                params=all_params if all_params else None,
                source=source,
                post_data=req.post_data,
            ))

        logger.debug("Extracted %d network endpoints", len(endpoints))
        return endpoints

    @staticmethod
    def deduplicate(endpoints: list[DiscoveredEndpoint]) -> list[DiscoveredEndpoint]:
        """
        Deduplicate endpoints by (url_base, method) pair.
        Keeps the first occurrence, but merges params from duplicates.
        """
        seen: dict[tuple[str, str], DiscoveredEndpoint] = {}

        for ep in endpoints:
            # Normalize the URL for dedup
            key = (_strip_query(ep.url).rstrip("/"), ep.method.upper())

            if key not in seen:
                seen[key] = ep
            else:
                # Merge params from duplicate
                existing = seen[key]
                if ep.params and existing.params:
                    existing.params.update(ep.params)
                elif ep.params:
                    existing.params = ep.params

                # Prefer more specific source (xhr/fetch > form > link)
                source_priority = {"xhr": 4, "fetch": 4, "form": 3, "script": 2, "link": 1, "navigation": 0}
                if source_priority.get(ep.source, 0) > source_priority.get(existing.source, 0):
                    existing.source = ep.source

        deduped = list(seen.values())
        logger.info(
            "Deduplication: %d → %d endpoints", len(endpoints), len(deduped)
        )
        return deduped
