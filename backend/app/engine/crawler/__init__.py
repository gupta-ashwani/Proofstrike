"""
ProofStrike Crawler Engine — Playwright-based web application discovery.

Exports the crawl stage used by the scan pipeline.
"""

from app.engine.crawler.engine import CrawlStage

__all__ = ["CrawlStage"]
