"""
Authentication Handler — perform login flows via Playwright.

Handles:
  - Reading auth_config from the Target model
  - Filling login forms (username/password)
  - Clicking submit and waiting for navigation
  - Detecting login success or failure
  - Persisting session cookies for authenticated crawling
"""

import logging
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout

logger = logging.getLogger("proofstrike.crawler.auth")


class AuthConfig:
    """
    Parsed authentication configuration.

    Expected format from Target.auth_config:
    {
        "login_url": "https://example.com/login",
        "username_selector": "#username",
        "password_selector": "#password",
        "submit_selector": "#login-btn",
        "username": "admin",
        "password": "password123",
        "success_indicator": {
            "type": "url_contains",    # or "element_visible" or "url_changed"
            "value": "/dashboard"       # URL substring or CSS selector
        }
    }
    """

    def __init__(self, config: dict):
        self.login_url: str = config["login_url"]
        self.username_selector: str = config["username_selector"]
        self.password_selector: str = config["password_selector"]
        self.submit_selector: str = config["submit_selector"]
        self.username: str = config["username"]
        self.password: str = config["password"]
        self.success_indicator: dict = config.get(
            "success_indicator", {"type": "url_changed", "value": ""}
        )

    @staticmethod
    def is_configured(auth_config: dict | None) -> bool:
        """Check if auth_config has all required fields for login."""
        if not auth_config:
            return False
        required = [
            "login_url",
            "username_selector",
            "password_selector",
            "submit_selector",
            "username",
            "password",
        ]
        return all(k in auth_config for k in required)


class AuthHandler:
    """
    Performs automated login and validates success.

    Usage:
        handler = AuthHandler(page)
        success = await handler.login(auth_config)
    """

    def __init__(self, page: Page):
        self.page = page
        self._authenticated = False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    async def login(self, auth_config: dict) -> bool:
        """
        Perform the full login flow.

        Returns True if login succeeded, False otherwise.
        """
        config = AuthConfig(auth_config)
        logger.info("Attempting login at %s", config.login_url)

        try:
            # Navigate to login page
            await self.page.goto(config.login_url, wait_until="networkidle")
            logger.debug("Login page loaded")

            # Store the URL before login for comparison
            pre_login_url = self.page.url

            # Fill credentials
            await self.page.fill(config.username_selector, config.username)
            await self.page.fill(config.password_selector, config.password)
            logger.debug("Credentials filled")

            # Click submit and wait for navigation
            await self.page.click(config.submit_selector)

            # Wait for navigation or network idle after form submission
            try:
                await self.page.wait_for_load_state("networkidle", timeout=10_000)
            except PlaywrightTimeout:
                # Some SPAs don't trigger a full navigation
                logger.debug("Network idle timeout — checking success indicator anyway")

            # Validate login success
            success = await self._check_success(config, pre_login_url)

            if success:
                logger.info("Login successful")
                self._authenticated = True
            else:
                logger.warning("Login failed — success indicator not met")
                self._authenticated = False

            return self._authenticated

        except PlaywrightTimeout:
            logger.error("Login timed out — could not complete login flow")
            self._authenticated = False
            return False
        except Exception as e:
            logger.error("Login error: %s", str(e))
            self._authenticated = False
            return False

    async def _check_success(self, config: AuthConfig, pre_login_url: str) -> bool:
        """
        Check if the login succeeded based on the configured success indicator.
        """
        indicator = config.success_indicator
        indicator_type = indicator.get("type", "url_changed")
        indicator_value = indicator.get("value", "")

        current_url = self.page.url

        if indicator_type == "url_contains":
            # URL should contain a specific substring after login
            return indicator_value in current_url

        elif indicator_type == "url_changed":
            # URL should be different from the login page
            return current_url != pre_login_url

        elif indicator_type == "element_visible":
            # A specific element should be visible after login
            try:
                await self.page.wait_for_selector(
                    indicator_value, state="visible", timeout=5_000
                )
                return True
            except PlaywrightTimeout:
                return False

        elif indicator_type == "element_absent":
            # A login-specific element (e.g., login form) should be gone
            try:
                await self.page.wait_for_selector(
                    indicator_value, state="hidden", timeout=5_000
                )
                return True
            except PlaywrightTimeout:
                return False

        else:
            # Default: assume success if URL changed
            logger.warning("Unknown success indicator type: %s", indicator_type)
            return current_url != pre_login_url
