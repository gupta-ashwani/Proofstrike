"""
ProofStrike Crawler Engine — Playwright-based web application discovery.

Exports the main CrawlerEngine class for use by the scan orchestrator.
"""

from app.engine.crawler.engine import CrawlerEngine

__all__ = ["CrawlerEngine"]
