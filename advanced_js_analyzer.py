import asyncio
import os
import stat
from pathlib import Path
import random
import re
import json
import base64
import jsbeautifier
from typing import List, Dict, Any
import time  # For timestamps if needed

# Import ConsoleManager
from console_manager import ConsoleManager
from playwright.async_api import Page, Error as PlaywrightError


class AdvancedJSAnalyzer:
    def __init__(self, console_manager: ConsoleManager):
        self.console = console_manager
        # Use internal findings list, which will be returned by run_full_analysis
        self._internal_findings: List[Dict[str, Any]] = []

        self.console.print_debug("Initializing AdvancedJSAnalyzer...")

        # Payload list (Consider moving to central payloads.py if shared)
        self.cmd_injection_payloads = [
            "; id", "& dir", "| cat /etc/passwd", "$(id)", "`id`", "&& whoami", "|| hostname"
        ]

        # Setup working directory (keep existing logic)
        self.working_dir = Path('/tmp/robot-hunter')
        try:
            self.working_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.working_dir, stat.S_IRWXU)  # Owner Read/Write/Execute
            self.console.print_debug(f"AdvancedJSAnalyzer working directory: {self.working_dir}")
        except PermissionError as e:
            self.console.print_warning(f"Permission error creating {self.working_dir}: {e}. Using fallback.")
            try:
                self.working_dir = Path.home() / '.robot-hunter-advjs'
                self.working_dir.mkdir(parents=True, exist_ok=True)
                self.console.print_debug(f"AdvancedJSAnalyzer fallback directory: {self.working_dir}")
            except Exception as fallback_e:
                self.console.print_error(f"Failed to create fallback directory {self.working_dir}: {fallback_e}")
                # Decide how to handle this - maybe disable features needing disk?

        self.console.print_debug("AdvancedJSAnalyzer initialization complete")

    def _add_finding(self, type: str, severity: str, details: dict, url: str = ""):
        """Adds a finding to the internal list."""
        finding = {
            "type": f"js_dynamic_{type}",  # Prefix to distinguish from static
            "severity": severity,
            "url": url,  # Add URL context if available
            "details": details,
            "timestamp": time.time()
        }
        self._internal_findings.append(finding)

    # --- Error Handlers (Using ConsoleManager) ---
    async def _handle_permission_error(self, error, context=None):
        self.console.print_error(f"Permission Error during JS analysis: {error}")
        pass

    async def _handle_timeout_error(self, error, context=None):
        self.console.print_error(f"Timeout Error during JS analysis: {error}")
        pass

    async def _handle_network_error(self, error, context=None):
        self.console.print_error(f"Network Error during JS analysis: {error}")
        pass

    # --- Safe Operations (Example logging change) ---
    async def _safe_file_access(self, path):
        try:
            temp_path = self.working_dir / Path(path).name
            self.console.print_debug(f"Attempting safe file access to: {temp_path}")
            return temp_path
        except Exception as e:
            self.console.print_error(f"Error in safe file access '{path}': {e}")
            return None

    async def run_analysis_with_retry(self, page: Page, max_retries: int = 2) -> Dict[str, List[Dict[str, Any]]]:
        """Runs the full analysis with retries, returning findings."""
        for attempt in range(max_retries):
            self._internal_findings = []
            try:
                self.console.print_info(f"Starting advanced JS analysis (Attempt {attempt + 1}/{max_retries}) on {page.url}")
                await self.run_full_analysis(page)
                self.console.print_success(f"Advanced JS analysis completed (Attempt {attempt + 1}). Found {len(self._internal_findings)} potential findings.")
                return {"findings": self._internal_findings}
            except PermissionError as e:
                self.console.print_warning(f"JS Analysis Permission Error (Attempt {attempt + 1}): {e}")
                await self._handle_permission_error(e, {'operation': 'analysis'})
                if attempt == max_retries - 1:
                    self.console.print_error("Max retries reached for JS analysis due to permission errors.")
                    return {"findings": self._internal_findings}
            except PlaywrightError as pe:
                self.console.print_error(f"Playwright error during JS analysis (Attempt {attempt + 1}): {pe}")
                if attempt == max_retries - 1:
                    self.console.print_error("Max retries reached for JS analysis due to Playwright errors.")
                    return {"findings": self._internal_findings}
                await asyncio.sleep(1.5 ** attempt)
            except Exception as e:
                self.console.print_error(f"General error during JS analysis (Attempt {attempt + 1}): {e}")
                self.console.console.print_exception(show_locals=self.console.verbose)
                if attempt == max_retries - 1:
                    self.console.print_error("Max retries reached for JS analysis due to general errors.")
                    return {"findings": self._internal_findings}
                await asyncio.sleep(1.5 ** attempt)

        return {"findings": self._internal_findings}

    # --- JS Debugger/Instrumentation Setup ---
    async def setup_debugger(self, page: Page):
        """Configures the JS environment for analysis."""
        self.console.print_debug("Setting up JS debugger hooks...")
        try:
            await page.evaluate("""
            (() => {
                if (window.__debugData) return;

                window.__debugData = { /* ... existing structure ... */ };
                document.body.setAttribute('data-robot-hunter-ignore', 'true');
                setTimeout(() => {
                    if (document.body.hasAttribute('data-robot-hunter-ignore')) {
                        document.body.removeAttribute('data-robot-hunter-ignore');
                    }
                }, 100);

                console.log('[RH_AdvJS] Debugger hooks activated.');
            })();
            """)
            self.console.print_debug("JS debugger hooks injected successfully.")
        except PlaywrightError as e:
            self.console.print_error(f"Failed to setup JS debugger: {e}")
        except Exception as e:
            self.console.print_error(f"Unexpected error setting up JS debugger: {e}")

    # --- Analysis Methods (Using _add_finding) ---
    async def analyze_variables(self, page: Page):
        """Analyzes and potentially manipulates variables."""
        self.console.print_debug("Analyzing JS variables...")
        page_url = page.url
        try:
            single_char_vars = await page.evaluate("() => window.__debugData ? window.__debugData.singleCharVars : {}")

            tested_vars = 0
            max_vars_to_test = 3
            for var_name, info in single_char_vars.items():
                if tested_vars >= max_vars_to_test:
                    break
                if info and info.get('type') in ['object', 'function'] and info.get('usageCount', 0) > 0:
                    await self._modify_and_test_variable(page, var_name, info)
                    tested_vars += 1
                    await asyncio.sleep(0.2)

            final_data = await page.evaluate("""
                () => window.__debugData ? {
                    singleCharVars: window.__debugData.singleCharVars || {},
                    modifiedVars: window.__debugData.modifiedVars || {},
                    callGraph: window.__debugData.callGraph || {},
                    errors: window.__debugData.errors || []
                } : {}
            """)

            for var_name, info in final_data.get('singleCharVars', {}).items():
                if info.get('usageCount', 0) > 0:
                    self._add_finding("active_single_char_var", "MEDIUM", {
                        "name": var_name,
                        "var_type": info.get('type'),
                        "usage_count": info.get('usageCount'),
                        "method_calls_count": len(info.get('methodCalls', [])),
                    }, page_url)

            for var_name, mod_info in final_data.get('modifiedVars', {}).items():
                if mod_info.get('error'):
                    self._add_finding("var_modification_error", "HIGH", {
                        "name": var_name,
                        "error": mod_info['error'],
                        "details": "Error occurred attempting to modify variable; indicates potential sensitivity or protection mechanism.",
                    }, page_url)
                elif mod_info.get('modified'):
                    self.console.print_debug(f"Variable '{var_name}' modified for testing ({mod_info.get('property','?')}).")

            for caller, callees in final_data.get('callGraph', {}).items():
                suspicious_keywords = ['ajax', 'fetch', 'http', 'post', 'send', 'submit', 'request', 'query', 'param', 'token', 'auth', 'key', 'secret']
                if any(keyword in caller.lower() for keyword in suspicious_keywords):
                    callee_str = ', '.join(callees)
                    if any(keyword in callee_str.lower() for keyword in suspicious_keywords):
                        self._add_finding("suspicious_call_chain", "MEDIUM", {
                            "caller": caller[:200],
                            "callees": callees,
                            "details": "Potentially sensitive function call chain detected."
                        }, page_url)

        except PlaywrightError as e:
            self.console.print_error(f"Error during variable analysis: {e}")
        except Exception as e:
            self.console.print_error(f"Unexpected error during variable analysis: {e}")

    async def _modify_and_test_variable(self, page: Page, var_name: str, info: Dict):
        """Attempts to modify a variable and checks for errors."""
        page_url = page.url
        self.console.print_debug(f"Attempting modification test for var '{var_name}' (Type: {info.get('type')})")
        modification_successful = False

        test_payloads = [
            "'", '"', "`",
            "<script>alert('rh_mod_xss')</script>",
            "' OR 1=1 --",
            "{{7*7}}", "${7*7}",
            random.choice(self.cmd_injection_payloads),
            "file:///etc/passwd",
            "javascript:alert('rh_mod_jsuri')",
            {"key": "value", "nested": {"$ne": 1}},
            "<h1>RH_MOD</h1>",
            None, True, False, 0, 1, -1, [], {},
        ]
        payload_to_use = random.choice(test_payloads)
        payload_str = str(payload_to_use)

        try:
            result = await page.evaluate("""
                async (varName, payload) => {
                    const debugData = window.__debugData || {};
                    if (!debugData.modifiedVars) debugData.modifiedVars = {};
                    const modInfo = { modified: false, error: null, stack: null };
                    debugData.modifiedVars[varName] = modInfo;

                    try {
                        const target = window[varName];
                        if (target === undefined || target === null) {
                            modInfo.error = "Variable is undefined or null"; return modInfo;
                        }

                        const originalType = typeof target;
                        let modified = false;

                        if (originalType === 'object' && target !== null) {
                            const props = Object.keys(target);
                            const propToModify = props.length > 0 ? props[0] : 'rh_test_prop';
                            const originalValue = target[propToModify];
                            try {
                                target[propToModify] = payload;
                                modInfo.property = propToModify;
                                modInfo.originalValue = originalValue;
                                modInfo.newValue = payload;
                                modified = true;
                            } catch (propErr) { modInfo.error = `Error setting property ${propToModify}: ${propErr.toString()}`; }

                        } else if (originalType === 'function') {
                            try {
                                target(payload);
                                modInfo.action = 'called function';
                                modified = true;
                            } catch (callErr) { modInfo.error = `Error calling function: ${callErr.toString()}`; }

                        } else {
                            try {
                                modInfo.error = "Direct reassignment of primitives via evaluate is unreliable.";
                            } catch(assignErr) { modInfo.error = `Error reassigning primitive: ${assignErr.toString()}`; }
                        }

                        modInfo.modified = modified;
                        if (modified) console.log(`[RH_AdvJS] Modification test applied to ${varName}`);

                    } catch (e) {
                        modInfo.error = `General modification error: ${e.toString()}`;
                        modInfo.stack = e.stack;
                        console.error(`[RH_AdvJS] Error modifying ${varName}:`, e);
                    }
                    return modInfo;
                }
            """, var_name, payload_to_use)

            modification_successful = result.get('modified', False)
            if result.get('error'):
                self._add_finding("var_modification_error", "HIGH", {
                    "name": var_name, "error": result['error'], "payload_type": type(payload_to_use).__name__,
                    "details": f"Error during controlled modification attempt with payload: {payload_str[:50]}..."
                }, page_url)

            if modification_successful:
                await asyncio.sleep(1.0)
                new_errors = await page.evaluate("""
                    (startTime) => {
                        const debugData = window.__debugData || {};
                        return (debugData.errors || []).filter(e => e.timestamp > startTime);
                    }
                """, result.get('timestamp', time.time() * 1000))

                for error in new_errors:
                    self._add_finding("var_modification_side_effect", "HIGH", {
                        "variable": var_name,
                        "payload_type": type(payload_to_use).__name__,
                        "payload_preview": payload_str[:50] + '...',
                        "error_type": error.get('type'),
                        "error_message": error.get('message') or error.get('reason'),
                        "details": "Error occurred shortly after variable modification, potentially indicating vulnerability."
                    }, page_url)

        except PlaywrightError as e:
            self.console.print_error(f"Playwright error during variable modification test for '{var_name}': {e}")
        except Exception as e:
            self.console.print_error(f"Unexpected error during variable modification test for '{var_name}': {e}")

    async def trace_function_execution(self, page: Page, selector_to_click: str):
        """Analyzes changes caused by clicking an element."""
        self.console.print_debug(f"Tracing execution after click on: {selector_to_click}")
        page_url = page.url
        try:
            before_state = await page.evaluate("() => window.__debugData ? { networkCount: window.__debugData.networkRequests.length, errorCount: window.__debugData.errors.length, serviceConnectionsCount: window.__debugData.serviceConnections.length, dbOperationsCount: window.__debugData.dbOperations.length } : {}")
            start_time = time.time() * 1000

            element = await page.query_selector(selector_to_click)
            if not element:
                self.console.print_warning(f"Cannot trace click, element not found: {selector_to_click}")
                return

            if not await element.is_visible():
                self.console.print_warning(f"Cannot trace click, element not visible: {selector_to_click}")
                return

            self.console.print_debug(f"Clicking element for tracing: {selector_to_click}")
            async with page.expect_navigation(wait_until="load", timeout=self.console.timeout // 2):
                await element.click(timeout=5000)
            self.console.print_debug(f"Navigation completed after click on {selector_to_click}")
            await asyncio.sleep(0.5)

            after_state = await page.evaluate("""
                (beforeCounts, startTime) => {
                    const debugData = window.__debugData || {};
                    const network = debugData.networkRequests || [];
                    const errors = debugData.errors || [];
                    const services = debugData.serviceConnections || [];
                    const dbOps = debugData.dbOperations || [];

                    return {
                        newNetwork: network.slice(beforeCounts.networkCount || 0),
                        newErrors: errors.filter(e => e.timestamp > startTime),
                        newServices: services.slice(beforeCounts.serviceConnectionsCount || 0),
                        newDbOps: dbOps.slice(beforeCounts.dbOperationsCount || 0)
                    };
                }
            """, before_state, start_time)

            if after_state.get('newNetwork'):
                self.console.print_debug(f"Found {len(after_state['newNetwork'])} new network requests after click.")
                for req in after_state['newNetwork']:
                    if any(p in req.get('url','').lower() for p in ['api','graphql','query','data']):
                        self._add_finding("network_request_on_click", "INFO", {
                            "element_selector": selector_to_click,
                            "request_url": req.get('url'),
                            "request_method": req.get('method', req.get('options',{}).get('method','GET')),
                            "details": "API-like network request triggered by element click."
                        }, page_url)

            if after_state.get('newErrors'):
                self.console.print_warning(f"Found {len(after_state['newErrors'])} new JS errors after click on {selector_to_click}")
                for err in after_state['newErrors']:
                    self._add_finding("js_error_on_click", "LOW", {
                        "element_selector": selector_to_click,
                        "error_type": err.get('type'),
                        "error_message": err.get('message') or err.get('reason'),
                        "details": "JavaScript error occurred after element interaction."
                    }, page_url)

            if after_state.get('newServices'):
                self.console.print_info(f"Found {len(after_state['newServices'])} new service connections after click on {selector_to_click}")
                for svc in after_state['newServices']:
                    self._add_finding("service_connection_on_click", "MEDIUM", {
                        "element_selector": selector_to_click,
                        "service_url": svc.get('url'),
                        "service_type": svc.get('type', 'api_endpoint'),
                        "details": "Potential backend service connection triggered by element click."
                    }, page_url)

            if after_state.get('newDbOps'):
                self.console.print_info(f"Found {len(after_state['newDbOps'])} new DB operations after click on {selector_to_click}")
                for op in after_state['newDbOps']:
                    self._add_finding("db_operation_on_click", "HIGH", {
                        "element_selector": selector_to_click,
                        "db_name": op.get('name'),
                        "operation_type": op.get('type'),
                        "details": f"Potential DB operation ({op.get('type')}) triggered by element click.",
                        "data_preview": str(op.get('data'))[:100]+"..." if op.get('data') else None
                    }, page_url)

        except PlaywrightError as e:
            if "navigation" in str(e).lower() and "timeout" in str(e).lower():
                self.console.print_debug(f"Click on {selector_to_click} did not cause navigation within timeout.")
            else:
                self.console.print_warning(f"Playwright error during trace execution for {selector_to_click}: {e}")
        except Exception as e:
            self.console.print_error(f"Unexpected error during trace execution for {selector_to_click}: {e}")

    async def analyze_db_connections(self, page: Page):
        """Retrieves DB connection info from JS context."""
        self.console.print_debug("Analyzing potential DB connections from JS context...")
        page_url = page.url
        try:
            db_operations = await page.evaluate("() => window.__debugData ? window.__debugData.dbOperations : []")
            for operation in db_operations:
                self._add_finding("database_operation", "HIGH", {
                    "db_name": operation.get('name', 'unknown'),
                    "operation_type": operation.get('type', 'unknown'),
                    "details": f"DB operation/connection detected in JS context: {json.dumps(operation)[:150]}...",
                    "data_preview": str(operation.get('data'))[:100]+"..." if operation.get('data') else None
                }, page_url)
        except PlaywrightError as e:
            self.console.print_error(f"Error analyzing DB connections: {e}")
        except Exception as e:
            self.console.print_error(f"Unexpected error analyzing DB connections: {e}")

    async def run_full_analysis(self, page: Page):
        """Orchestrates the advanced JS analysis steps."""
        self.console.print_info(f"Running full advanced JS analysis on {page.url}")

        await self.setup_debugger(page)
        await self.analyze_variables(page)
        await asyncio.sleep(0.5)
        await self.analyze_db_connections(page)
        await asyncio.sleep(0.2)

        self.console.print_debug(f"Finished advanced JS analysis for {page.url}")