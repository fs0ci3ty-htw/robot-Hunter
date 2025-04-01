import random
import asyncio
import re
from typing import Set, Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import jsbeautifier
from playwright.async_api import async_playwright
from datetime import datetime
import time

# Import refactored/new components
from console_manager import ConsoleManager
from smart_detector import SmartDetector
from attack_engine import AttackEngine
from advanced_js_analyzer import AdvancedJSAnalyzer
from js_analyzer import JSAnalyzer # Static analyzer
from traffic_analyzer import TrafficAnalyzer
from report_generator import ReportGenerator # Needed to add findings

class SmartCrawler:
    def __init__(self, console_manager: ConsoleManager, report_generator: ReportGenerator, max_depth: int = 2, rate_limit: int = 10, interactsh_url: str = None, timeout: int = 30):
        self.console = console_manager
        self.report_generator = report_generator
        self.max_depth = max_depth
        self.rate_limit = rate_limit
        self.interactsh_url = interactsh_url
        self.timeout = timeout
        self.attack_engine = AttackEngine(console_manager=self.console, interactsh_url=self.interactsh_url)

    async def start_crawl(self, target_url: str):
        """Starts the crawling process."""
        # Ensure the URL has a protocol, try https first
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme:
            https_url = "https://" + target_url
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch()
                    context = await browser.new_context()
                    page = await context.new_page()
                    response = await page.goto(https_url, timeout=self.timeout * 1000)
                    await browser.close()
                    if response and response.status != 400:
                        target_url = https_url
                    else:
                        target_url = "http://" + target_url  # Fallback to http
            except:
                target_url = "http://" + target_url  # Fallback to http

        self.console.print_info(f"Starting crawl on {target_url} with depth {self.max_depth}")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                context = await browser.new_context()
                page = await context.new_page()

                await self._crawl(page, target_url, depth=0)

                await browser.close()

        except Exception as e:
            self.console.print_error(f"Error during crawling: {e}")

    async def _crawl(self, page, url: str, depth: int):
        """Recursive function to crawl the website."""
        if depth > self.max_depth:
            self.console.print_debug(f"Reached max depth of {self.max_depth} at {url}")
            return

        try:
            self.console.print_debug(f"Crawling {url} at depth {depth}")
            response = await page.goto(url, timeout=self.timeout * 1000) # Convert to milliseconds

            if response and response.status == 200:
                self.console.print_success(f"Successfully accessed {url} (Status: {response.status})")

                # Extract links from the page
                links = await page.locator("a").evaluate_all("links => links.map(link => link.href)")
                unique_links = list(set(links)) # Remove duplicates

                for link in unique_links:
                    # Basic check to avoid crawling external domains
                    if link.startswith(url) or url in link:
                        await self._crawl(page, link, depth + 1)
                    else:
                        self.console.print_debug(f"Skipping external link: {link}")
            else:
                self.console.print_warning(f"Failed to access {url} (Status: {response.status if response else 'Unknown'})")

        except Exception as e:
            self.console.print_error(f"Error while crawling {url}: {e}")