from typing import List, Dict
import jsbeautifier
import re

class JSAnalyzer:
    def __init__(self):
        pass

    async def extract_js_from_page(self, page) -> List[str]:
        """Extracts JavaScript code from a Playwright page."""
        js_content = await self.extract_js_content(page)
        return js_content

    async def extract_js_content(self, page):
        """Extracts both inline and external script content from a page."""
        js_codes = []

        # Extract inline scripts
        inline_scripts = await page.evaluate("""
            () => {
                const scripts = Array.from(document.querySelectorAll('script:not([src])'));
                return scripts.map(script => script.textContent);
            }
        """)
        js_codes.extend(inline_scripts)

        # Extract external scripts
        external_script_urls = await page.evaluate("""
            () => {
                const scripts = Array.from(document.querySelectorAll('script[src]'));
                return scripts.map(script => script.src);
            }
        """)

        for url in external_script_urls:
            try:
                response = await page.request.get(url)
                if response.status == 200:
                    js_codes.append(await response.text())
                else:
                    print(f"Failed to fetch script from {url}: Status {response.status}")
            except Exception as e:
                print(f"Error fetching script from {url}: {e}")

        return js_codes

    def deobfuscate_js(self, js_code: str) -> str:
        """Deobfuscates JavaScript code using jsbeautifier."""
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.space_in_empty_paren = True
        return jsbeautifier.beautify(js_code, opts)

    def find_suspicious_patterns(self, js_code: str) -> List[Dict]:
        """Finds suspicious patterns in JavaScript code."""
        patterns = [
            {"name": "eval", "pattern": r"\beval\s*\(", "severity": "high"},
            {"name": "document.write", "pattern": r"document\.write", "severity": "medium"},
            {"name": "Base64", "pattern": r"atob\(|btoa\(", "severity": "medium"},
            {"name": "String.fromCharCode", "pattern": r"String\.fromCharCode", "severity": "low"},
        ]
        findings = []
        for pattern in patterns:
            matches = re.findall(pattern["pattern"], js_code)
            if matches:
                findings.append({
                    "name": pattern["name"],
                    "matches": matches,
                    "severity": pattern["severity"]
                })
        return findings

    async def analyze_webpack(self, page) -> Dict:
        """Analyzes webpack bundles (placeholder)."""
        return {}

    def analyze_source_maps(self, source_map_content: str) -> Dict:
        """Analyzes source maps (placeholder)."""
        return {}

    async def extract_and_analyze_js(self, page):
        """Extracts and analyzes JavaScript (placeholder)."""
        pass
