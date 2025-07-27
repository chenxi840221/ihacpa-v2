"""
Playwright Manager

High-level browser automation manager with intelligent features.
"""

import asyncio
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
import random
import json

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright


class PlaywrightManager:
    """
    Advanced Playwright manager with anti-detection and performance features.
    
    Features:
    - Multiple browser contexts for isolation
    - User agent rotation
    - Proxy support
    - Automatic retry with exponential backoff
    - Screenshot and content capture
    - Performance monitoring
    - Anti-detection measures
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.browser_type = self.config.get("browser", "chromium")  # chromium, firefox, webkit
        self.headless = self.config.get("headless", True)
        self.timeout = self.config.get("timeout", 30000)  # milliseconds
        self.viewport = self.config.get("viewport", {"width": 1920, "height": 1080})
        
        # Anti-detection settings
        self.rotate_user_agents = self.config.get("rotate_user_agents", True)
        self.random_delays = self.config.get("random_delays", True)
        self.stealth_mode = self.config.get("stealth_mode", True)
        
        # Performance settings
        self.max_concurrent_pages = self.config.get("max_concurrent_pages", 5)
        self.page_pool_size = self.config.get("page_pool_size", 3)
        
        # Internal state
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.contexts: Dict[str, BrowserContext] = {}
        self.page_pool: List[Page] = []
        self.active_pages: int = 0
        
        # User agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        
        self.stats = {
            "pages_created": 0,
            "requests_made": 0,
            "errors_encountered": 0,
            "total_wait_time": 0.0,
            "start_time": datetime.utcnow()
        }
    
    async def initialize(self):
        """Initialize Playwright and browser"""
        try:
            self.playwright = await async_playwright().start()
            
            # Select browser type
            if self.browser_type == "firefox":
                browser_launcher = self.playwright.firefox
            elif self.browser_type == "webkit":
                browser_launcher = self.playwright.webkit
            else:
                browser_launcher = self.playwright.chromium
            
            # Launch browser with optimized settings
            launch_options = {
                "headless": self.headless,
                "args": [
                    "--no-first-run",
                    "--disable-dev-shm-usage",
                    "--disable-background-timer-throttling",
                    "--disable-backgrounding-occluded-windows",
                    "--disable-renderer-backgrounding",
                ]
            }
            
            if self.stealth_mode:
                launch_options["args"].extend([
                    "--disable-blink-features=AutomationControlled",
                    "--disable-features=VizDisplayCompositor",
                ])
            
            self.browser = await browser_launcher.launch(**launch_options)
            
            # Pre-create page pool
            await self._populate_page_pool()
            
            print(f"✅ Playwright initialized with {self.browser_type}")
            
        except Exception as e:
            print(f"❌ Failed to initialize Playwright: {e}")
            raise
    
    async def _populate_page_pool(self):
        """Pre-create pages for better performance"""
        for _ in range(self.page_pool_size):
            context = await self._create_context()
            page = await context.new_page()
            await self._configure_page(page)
            self.page_pool.append(page)
            self.stats["pages_created"] += 1
    
    async def _create_context(self, **kwargs) -> BrowserContext:
        """Create a new browser context with random settings"""
        context_options = {
            "viewport": self.viewport,
            "ignore_https_errors": True,
            "java_script_enabled": True,
        }
        
        # Add user agent rotation
        if self.rotate_user_agents:
            context_options["user_agent"] = random.choice(self.user_agents)
        
        # Add any custom options
        context_options.update(kwargs)
        
        context = await self.browser.new_context(**context_options)
        
        # Set default timeouts
        context.set_default_timeout(self.timeout)
        context.set_default_navigation_timeout(self.timeout)
        
        return context
    
    async def _configure_page(self, page: Page):
        """Configure page with stealth and performance settings"""
        if self.stealth_mode:
            # Remove webdriver property
            await page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
            """)
            
            # Randomize screen resolution
            await page.add_init_script(f"""
                Object.defineProperty(screen, 'width', {{
                    get: () => {random.randint(1366, 1920)},
                }});
                Object.defineProperty(screen, 'height', {{
                    get: () => {random.randint(768, 1080)},
                }});
            """)
        
        # Block unnecessary resources for performance
        await page.route("**/*.{png,jpg,jpeg,gif,svg,woff,woff2}", lambda route: route.abort())
        
        # Add request tracking
        page.on("request", self._track_request)
        page.on("response", self._track_response)
    
    def _track_request(self, request):
        """Track requests for monitoring"""
        self.stats["requests_made"] += 1
    
    def _track_response(self, response):
        """Track responses for monitoring"""
        if not response.ok:
            self.stats["errors_encountered"] += 1
    
    async def get_page(self, context_id: Optional[str] = None) -> Page:
        """
        Get a page from the pool or create a new one.
        
        Args:
            context_id: Optional context identifier for isolation
            
        Returns:
            Page instance ready for use
        """
        # Check if we have available pages in pool
        if self.page_pool and self.active_pages < self.max_concurrent_pages:
            page = self.page_pool.pop(0)
            self.active_pages += 1
            return page
        
        # Create new page if under limit
        if self.active_pages < self.max_concurrent_pages:
            if context_id and context_id in self.contexts:
                context = self.contexts[context_id]
            else:
                context = await self._create_context()
                if context_id:
                    self.contexts[context_id] = context
            
            page = await context.new_page()
            await self._configure_page(page)
            self.active_pages += 1
            self.stats["pages_created"] += 1
            return page
        
        # Wait for a page to become available
        while self.active_pages >= self.max_concurrent_pages:
            await asyncio.sleep(0.1)
        
        return await self.get_page(context_id)
    
    async def return_page(self, page: Page):
        """Return a page to the pool for reuse"""
        try:
            # Clear the page state
            await page.goto("about:blank")
            await page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
            
            # Return to pool if not full
            if len(self.page_pool) < self.page_pool_size:
                self.page_pool.append(page)
            else:
                await page.close()
            
            self.active_pages = max(0, self.active_pages - 1)
            
        except Exception as e:
            print(f"⚠️  Error returning page: {e}")
            self.active_pages = max(0, self.active_pages - 1)
    
    async def navigate_with_retry(
        self, 
        page: Page, 
        url: str, 
        max_retries: int = 3,
        wait_for: Optional[str] = None
    ) -> bool:
        """
        Navigate to URL with intelligent retry logic.
        
        Args:
            page: Page instance
            url: URL to navigate to
            max_retries: Maximum retry attempts
            wait_for: Selector to wait for after navigation
            
        Returns:
            True if navigation succeeded
        """
        for attempt in range(max_retries):
            try:
                # Random delay for anti-detection
                if self.random_delays and attempt > 0:
                    delay = random.uniform(1.0, 3.0)
                    await asyncio.sleep(delay)
                    self.stats["total_wait_time"] += delay
                
                # Navigate to URL
                response = await page.goto(url, wait_until="domcontentloaded")
                
                if response and response.ok:
                    # Wait for specific element if requested
                    if wait_for:
                        await page.wait_for_selector(wait_for, timeout=10000)
                    
                    return True
                
            except Exception as e:
                print(f"⚠️  Navigation attempt {attempt + 1} failed for {url}: {e}")
                if attempt == max_retries - 1:
                    self.stats["errors_encountered"] += 1
                    return False
        
        return False
    
    async def extract_text(self, page: Page, selector: str) -> Optional[str]:
        """
        Extract text from page using selector.
        
        Args:
            page: Page instance
            selector: CSS selector
            
        Returns:
            Extracted text or None
        """
        try:
            element = await page.wait_for_selector(selector, timeout=5000)
            if element:
                return await element.text_content()
        except Exception as e:
            print(f"⚠️  Text extraction failed for selector '{selector}': {e}")
        
        return None
    
    async def extract_multiple_texts(self, page: Page, selector: str) -> List[str]:
        """
        Extract text from multiple elements.
        
        Args:
            page: Page instance
            selector: CSS selector
            
        Returns:
            List of extracted texts
        """
        try:
            elements = await page.query_selector_all(selector)
            texts = []
            
            for element in elements:
                text = await element.text_content()
                if text and text.strip():
                    texts.append(text.strip())
            
            return texts
            
        except Exception as e:
            print(f"⚠️  Multiple text extraction failed for selector '{selector}': {e}")
            return []
    
    async def click_and_wait(
        self, 
        page: Page, 
        selector: str, 
        wait_for: Optional[str] = None,
        timeout: int = 10000
    ) -> bool:
        """
        Click element and wait for response.
        
        Args:
            page: Page instance
            selector: Selector to click
            wait_for: Selector to wait for after click
            timeout: Timeout in milliseconds
            
        Returns:
            True if click and wait succeeded
        """
        try:
            # Add random delay before click
            if self.random_delays:
                await asyncio.sleep(random.uniform(0.5, 1.5))
            
            await page.click(selector)
            
            if wait_for:
                await page.wait_for_selector(wait_for, timeout=timeout)
            else:
                # Wait for network idle
                await page.wait_for_load_state("networkidle")
            
            return True
            
        except Exception as e:
            print(f"⚠️  Click and wait failed for selector '{selector}': {e}")
            return False
    
    async def take_screenshot(self, page: Page, filename: Optional[str] = None) -> Optional[str]:
        """
        Take screenshot of current page.
        
        Args:
            page: Page instance
            filename: Optional filename (auto-generated if not provided)
            
        Returns:
            Screenshot filename if successful
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"screenshot_{timestamp}.png"
            
            await page.screenshot(path=filename, full_page=True)
            return filename
            
        except Exception as e:
            print(f"⚠️  Screenshot failed: {e}")
            return None
    
    async def smart_scroll(self, page: Page, direction: str = "down", distance: int = 500) -> bool:
        """
        Smart scrolling with human-like behavior.
        
        Args:
            page: Page instance
            direction: Scroll direction (up, down)
            distance: Scroll distance in pixels
            
        Returns:
            True if scroll succeeded
        """
        try:
            if self.random_delays:
                await asyncio.sleep(random.uniform(0.2, 0.8))
            
            if direction == "down":
                await page.evaluate(f"window.scrollBy(0, {distance})")
            else:
                await page.evaluate(f"window.scrollBy(0, -{distance})")
            
            # Wait for content to load
            await asyncio.sleep(random.uniform(0.5, 1.0))
            return True
            
        except Exception as e:
            print(f"⚠️  Smart scroll failed: {e}")
            return False
    
    async def fill_form_field(self, page: Page, selector: str, value: str, clear_first: bool = True) -> bool:
        """
        Fill form field with human-like typing.
        
        Args:
            page: Page instance
            selector: Field selector
            value: Value to enter
            clear_first: Whether to clear field first
            
        Returns:
            True if fill succeeded
        """
        try:
            element = await page.wait_for_selector(selector, timeout=5000)
            if not element:
                return False
            
            # Click to focus
            await element.click()
            
            if clear_first:
                await element.fill("")
            
            # Type with human-like delays
            for char in value:
                await element.type(char, delay=random.randint(50, 150))
                
            return True
            
        except Exception as e:
            print(f"⚠️  Form fill failed for selector '{selector}': {e}")
            return False
    
    async def wait_for_multiple_selectors(self, page: Page, selectors: List[str], timeout: int = 10000) -> Optional[str]:
        """
        Wait for any of multiple selectors to appear.
        
        Args:
            page: Page instance
            selectors: List of selectors to wait for
            timeout: Timeout in milliseconds
            
        Returns:
            The selector that was found first, or None
        """
        try:
            tasks = []
            for selector in selectors:
                task = asyncio.create_task(page.wait_for_selector(selector, timeout=timeout))
                tasks.append((selector, task))
            
            done, pending = await asyncio.wait(
                [task for _, task in tasks],
                return_when=asyncio.FIRST_COMPLETED,
                timeout=timeout / 1000
            )
            
            # Cancel pending tasks
            for task in pending:
                task.cancel()
            
            # Find which selector completed
            for selector, task in tasks:
                if task in done:
                    return selector
            
        except Exception as e:
            print(f"⚠️  Multiple selector wait failed: {e}")
        
        return None
    
    async def extract_table_data(self, page: Page, table_selector: str) -> List[Dict[str, str]]:
        """
        Extract data from HTML table.
        
        Args:
            page: Page instance
            table_selector: Table selector
            
        Returns:
            List of dictionaries representing table rows
        """
        try:
            # Wait for table to load
            await page.wait_for_selector(table_selector, timeout=10000)
            
            # Extract table data using JavaScript
            table_data = await page.evaluate(f"""
                () => {{
                    const table = document.querySelector('{table_selector}');
                    if (!table) return [];
                    
                    const rows = Array.from(table.querySelectorAll('tr'));
                    if (rows.length === 0) return [];
                    
                    // Get headers
                    const headerRow = rows[0];
                    const headers = Array.from(headerRow.querySelectorAll('th, td'))
                        .map(cell => cell.textContent?.trim() || '');
                    
                    // Get data rows
                    const dataRows = rows.slice(1);
                    const data = [];
                    
                    for (const row of dataRows) {{
                        const cells = Array.from(row.querySelectorAll('td'));
                        const rowData = {{}};
                        
                        cells.forEach((cell, index) => {{
                            const header = headers[index] || `column_${{index}}`;
                            rowData[header] = cell.textContent?.trim() || '';
                        }});
                        
                        data.push(rowData);
                    }}
                    
                    return data;
                }}
            """)
            
            return table_data
            
        except Exception as e:
            print(f"⚠️  Table extraction failed for selector '{table_selector}': {e}")
            return []
    
    async def handle_popup(self, page: Page, action: str = "accept") -> bool:
        """
        Handle JavaScript popups (alert, confirm, prompt).
        
        Args:
            page: Page instance
            action: Action to take (accept, dismiss)
            
        Returns:
            True if popup was handled
        """
        try:
            popup_handled = False
            
            def handle_dialog(dialog):
                nonlocal popup_handled
                if action == "accept":
                    dialog.accept()
                else:
                    dialog.dismiss()
                popup_handled = True
            
            page.on("dialog", handle_dialog)
            
            # Wait a bit to see if popup appears
            await asyncio.sleep(1.0)
            
            return popup_handled
            
        except Exception as e:
            print(f"⚠️  Popup handling failed: {e}")
            return False
    
    async def get_page_performance(self, page: Page) -> Dict[str, Any]:
        """
        Get page performance metrics.
        
        Args:
            page: Page instance
            
        Returns:
            Performance metrics dictionary
        """
        try:
            metrics = await page.evaluate("""
                () => {
                    const navigation = performance.getEntriesByType('navigation')[0];
                    const paint = performance.getEntriesByType('paint');
                    
                    return {
                        loadTime: navigation ? navigation.loadEventEnd - navigation.loadEventStart : 0,
                        domContentLoaded: navigation ? navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart : 0,
                        firstPaint: paint.find(p => p.name === 'first-paint')?.startTime || 0,
                        firstContentfulPaint: paint.find(p => p.name === 'first-contentful-paint')?.startTime || 0,
                        resourceCount: performance.getEntriesByType('resource').length,
                        memoryUsage: performance.memory ? {
                            used: performance.memory.usedJSHeapSize,
                            total: performance.memory.totalJSHeapSize,
                            limit: performance.memory.jsHeapSizeLimit
                        } : null
                    };
                }
            """)
            
            return metrics
            
        except Exception as e:
            print(f"⚠️  Performance metrics extraction failed: {e}")
            return {}
    
    async def save_page_content(self, page: Page, filename: Optional[str] = None, format: str = "html") -> Optional[str]:
        """
        Save page content to file.
        
        Args:
            page: Page instance
            filename: Optional filename
            format: Content format (html, pdf)
            
        Returns:
            Saved filename if successful
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                ext = "pdf" if format == "pdf" else "html"
                filename = f"page_content_{timestamp}.{ext}"
            
            if format == "pdf":
                await page.pdf(path=filename, format="A4")
            else:
                content = await page.content()
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            return filename
            
        except Exception as e:
            print(f"⚠️  Page content save failed: {e}")
            return None

    async def close_page(self, page: Page):
        """
        Close a specific page and remove it from tracking.
        
        Args:
            page: Page instance to close
        """
        try:
            if page in self.page_pool:
                self.page_pool.remove(page)
            
            await page.close()
            self.active_pages = max(0, self.active_pages - 1)
            
        except Exception as e:
            print(f"⚠️  Error closing page: {e}")

    async def get_stats(self) -> Dict[str, Any]:
        """Get performance and usage statistics"""
        uptime = (datetime.utcnow() - self.stats["start_time"]).total_seconds()
        
        return {
            **self.stats,
            "uptime_seconds": uptime,
            "active_pages": self.active_pages,
            "page_pool_size": len(self.page_pool),
            "contexts": len(self.contexts),
            "requests_per_second": self.stats["requests_made"] / uptime if uptime > 0 else 0,
            "error_rate": self.stats["errors_encountered"] / max(1, self.stats["requests_made"]),
            "average_wait_time": self.stats["total_wait_time"] / max(1, self.stats["requests_made"])
        }
    
    async def cleanup(self):
        """Clean up all resources"""
        try:
            # Close all pages in pool
            for page in self.page_pool:
                await page.close()
            self.page_pool.clear()
            
            # Close all contexts
            for context in self.contexts.values():
                await context.close()
            self.contexts.clear()
            
            # Close browser
            if self.browser:
                await self.browser.close()
            
            # Stop playwright
            if self.playwright:
                await self.playwright.stop()
            
            print("✅ Playwright cleanup completed")
            
        except Exception as e:
            print(f"⚠️  Playwright cleanup error: {e}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()