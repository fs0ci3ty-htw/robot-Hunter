from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs
import json
import base64
import re
import time

# Import ConsoleManager
from console_manager import ConsoleManager
from playwright.async_api import BrowserContext, Request, Response, Error as PlaywrightError

class TrafficAnalyzer:
    def __init__(self, console_manager: ConsoleManager):
        self.console = console_manager
        self.requests: List[Dict[str, Any]] = []
        self.responses: List[Dict[str, Any]] = []
        # self.websocket_messages = [] # Optional: Add websocket handling if needed
        self.console.print_debug("Traffic Analyzer Initialized")

    async def capture_traffic(self, browser_context: BrowserContext):
        """Captures traffic by attaching handlers to the BrowserContext."""
        self.console.print_debug("Attaching traffic capture handlers to browser context...")

        # Use weak=True maybe? To avoid potential memory leaks if handlers aren't removed? Needs testing.
        browser_context.on("request", self._handle_request)
        browser_context.on("response", self._handle_response)
        browser_context.on("requestfailed", self._handle_request_failed)
        # browser_context.on("websocket", self._handle_websocket) # Optional

        self.console.print_debug("Traffic capture handlers attached.")

    def _handle_request(self, request: Request):
        """Callback for 'request' event."""
        try:
             req_data = {
                "url": request.url,
                "method": request.method,
                "headers": request.headers,
                "post_data": request.post_data, # Can be None
                "resource_type": request.resource_type,
                "is_navigation": request.is_navigation_request(),
                "timestamp": time.time()
             }
             self.requests.append(req_data)
             # Log less verbosely by default, maybe only non-GET or navigation requests?
             if request.method != "GET" or request.is_navigation_request():
                  self.console.print_debug(f"Request: {request.method} {request.url} (Type: {request.resource_type})")
        except Exception as e:
             self.console.print_warning(f"Error handling request event for {request.url}: {e}")


    async def _handle_response(self, response: Response):
        """Callback for 'response' event."""
        body = None
        body_base64 = None
        error_msg = None
        try:
            # Attempt to get body, handle potential errors (e.g., for redirects, no content)
            try:
                 # Check content type to decide if getting text is feasible/useful
                 content_type = response.headers.get('content-type', '').lower()
                 # Heuristic for text-based content
                 is_text_based = any(ct in content_type for ct in ['html', 'text', 'json', 'xml', 'javascript', 'css'])

                 if response.ok and is_text_based:
                     body_bytes = await response.body()
                     # Try decoding, fallback if fails
                     try:
                         body = body_bytes.decode('utf-8', errors='replace')
                     except UnicodeDecodeError:
                          body = body_bytes.decode('latin-1', errors='replace') # Fallback encoding
                          error_msg = "Decoding error, used fallback."
                 elif response.ok: # Non-text binary data, maybe encode?
                      # body_bytes = await response.body() # Get raw bytes
                      # body_base64 = base64.b64encode(body_bytes).decode() # Optional: Store large binary as b64
                      pass # Or just ignore body for binary
                 else: # Error status code, might still have a useful body
                     try:
                          body_bytes = await response.body()
                          body = body_bytes.decode('utf-8', errors='replace')
                     except Exception:
                          error_msg = "Could not read error response body."

            except PlaywrightError as pe: # Catch errors like 'response body is unavailable'
                 error_msg = f"Could not get response body: {pe}"
            except Exception as e:
                 error_msg = f"Unexpected error getting response body: {e}"


            resp_data = {
                "url": response.url,
                "status": response.status,
                "ok": response.ok,
                "headers": response.headers,
                "body": body, # Might be None
                "body_base64": body_base64, # Optional
                "resource_type": response.request.resource_type,
                "from_service_worker": response.from_service_worker(),
                "error_message": error_msg, # Record issues getting body
                "timestamp": time.time()
            }
            self.responses.append(resp_data)

            # Log responses, maybe only errors or specific types?
            log_body_preview = ""
            if body and len(body) > 0:
                 log_body_preview = f"(Body: {body[:50].replace(chr(10), '').replace(chr(13), '')}...)"
            elif body_base64:
                 log_body_preview = "(Body: Base64 Encoded)"
            elif error_msg:
                 log_body_preview = f"({error_msg})"

            if not response.ok:
                 self.console.print_warning(f"Response: {response.status} {response.url} {log_body_preview}")
            else:
                 self.console.print_debug(f"Response: {response.status} {response.url} {log_body_preview}")

        except Exception as e:
             self.console.print_warning(f"Error handling response event for {response.url}: {e}")

    def _handle_request_failed(self, request: Request):
        """Callback for 'requestfailed' event."""
        try:
             failure_text = request.failure()
             self.console.print_warning(f"Request Failed: {request.method} {request.url} - Error: {failure_text}")
             # Optionally add to a separate list of failed requests
        except Exception as e:
             self.console.print_warning(f"Error handling requestfailed event for {request.url}: {e}")


    def analyze_traffic(self) -> List[Dict[str, Any]]:
        """Analyzes captured traffic (requests/responses) and returns findings."""
        self.console.print_info("Analyzing captured traffic...")
        findings = []
        processed_urls = set() # Avoid duplicate findings for the same URL/issue type

        # --- Analysis Logic ---

        # 1. Sensitive Info in URLs (GET Requests)
        sensitive_keywords_url = ['password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'auth', 'sessionid', 'jsessionid']
        for req in self.requests:
             if req['method'] == 'GET':
                 url = req['url']
                 key = f"url_sens_{url}"
                 if key in processed_urls: continue
                 parsed_url = urlparse(url)
                 params = parse_qs(parsed_url.query)
                 for param_name in params.keys():
                      if any(keyword in param_name.lower() for keyword in sensitive_keywords_url):
                           findings.append({
                               "type": "sensitive_info_in_url",
                               "severity": "MEDIUM",
                               "url": url,
                               "details": f"Parameter '{param_name}' might contain sensitive data."
                           })
                           processed_urls.add(key)
                           break # Only report once per URL for this type

        # 2. Sensitive Info in POST Data
        sensitive_keywords_post = ['password', 'passwd', 'pwd', 'secret', 'creditcard', 'cvv', 'ssn']
        for req in self.requests:
             if req['method'] == 'POST' and req['post_data']:
                 url = req['url']
                 key = f"post_sens_{url}"
                 if key in processed_urls: continue
                 try:
                      # Attempt to parse common formats (form-urlencoded, json)
                      post_data_str = req['post_data']
                      found_sensitive = False
                      params = {}
                      content_type = req['headers'].get('content-type', '').lower()

                      if 'application/x-www-form-urlencoded' in content_type:
                           params = parse_qs(post_data_str)
                      elif 'application/json' in content_type:
                           try: params = json.loads(post_data_str)
                           except json.JSONDecodeError: pass # Ignore if not valid JSON

                      # Check parameter names/keys
                      if isinstance(params, dict):
                           for param_name in params.keys():
                               if any(keyword in param_name.lower() for keyword in sensitive_keywords_post):
                                    found_sensitive = True; break
                      # Also check raw string for keywords (less reliable)
                      elif isinstance(post_data_str, str):
                           if any(keyword in post_data_str.lower() for keyword in sensitive_keywords_post):
                                found_sensitive = True

                      if found_sensitive:
                           findings.append({
                               "type": "sensitive_info_in_post",
                               "severity": "MEDIUM",
                               "url": url,
                               "details": f"POST data to {url} might contain sensitive information."
                           })
                           processed_urls.add(key)

                 except Exception as e:
                      self.console.print_warning(f"Error parsing POST data for {url}: {e}")

        # 3. Sensitive Info/Tokens in Headers (Request & Response)
        sensitive_headers = ['authorization', 'x-api-key', 'x-auth-token', 'proxy-authorization', 'cookie']
        sensitive_cookie_names = ['sessionid', 'userid', 'admin', 'token', 'jwt']
        for req in self.requests: # Check request headers
             url = req['url']; key = f"req_hdr_sens_{url}"
             if key in processed_urls: continue
             for h_name, h_value in req['headers'].items():
                  h_lower = h_name.lower()
                  if any(keyword in h_lower for keyword in sensitive_headers):
                       # Special check for Cookie header contents
                       is_sensitive = True
                       details = f"Request header '{h_name}' detected."
                       if h_lower == 'cookie':
                            is_sensitive = False # Reset, check individual cookies
                            try:
                                 cookies = dict(item.strip().split('=', 1) for item in h_value.split(';') if '=' in item)
                                 sensitive_found = []
                                 for c_name in cookies.keys():
                                      if any(sens_c in c_name.lower() for sens_c in sensitive_cookie_names):
                                           sensitive_found.append(c_name)
                                 if sensitive_found:
                                      is_sensitive = True
                                      details = f"Sensitive cookie(s) found in request: {', '.join(sensitive_found)}"
                            except Exception: pass # Ignore cookie parsing errors

                       if is_sensitive:
                           findings.append({
                               "type": "sensitive_info_in_request_header",
                               "severity": "MEDIUM", "url": url, "details": details
                           })
                           processed_urls.add(key); break # Once per request

        for resp in self.responses: # Check response headers
             url = resp['url']; key = f"resp_hdr_sens_{url}"
             if key in processed_urls: continue
             for h_name, h_value in resp['headers'].items():
                  h_lower = h_name.lower()
                  # Look for Set-Cookie with sensitive names, or custom headers leaking info
                  if h_lower == 'set-cookie':
                       try:
                           cookie_parts = h_value.split(';')[0] # Get "name=value" part
                           if '=' in cookie_parts:
                                c_name = cookie_parts.split('=', 1)[0].strip()
                                if any(sens_c in c_name.lower() for sens_c in sensitive_cookie_names):
                                     findings.append({
                                         "type": "sensitive_info_in_response_header",
                                         "severity": "MEDIUM", "url": url,
                                         "details": f"Sensitive cookie potentially set: '{c_name}'"
                                     })
                                     processed_urls.add(key); break
                       except Exception: pass
                  elif any(keyword in h_lower for keyword in sensitive_headers) or 'secret' in h_lower or 'token' in h_lower:
                        findings.append({
                            "type": "sensitive_info_in_response_header",
                            "severity": "MEDIUM", "url": url,
                            "details": f"Potentially sensitive response header '{h_name}' detected."
                        })
                        processed_urls.add(key); break

        # 4. Information Disclosure in Response Bodies (Error messages, versions, etc.)
        info_disclosure_patterns = [
             re.compile(r'error|exception|traceback|stack trace', re.IGNORECASE),
             re.compile(r'php/?([\d\.]+)', re.IGNORECASE), # PHP Version
             re.compile(r'apache/?([\d\.]+)', re.IGNORECASE), # Apache Version
             re.compile(r'nginx/?([\d\.]+)', re.IGNORECASE), # Nginx Version
             re.compile(r'jboss|tomcat|jetty', re.IGNORECASE), # App Servers
             re.compile(r'ORA-\d{5}', re.IGNORECASE), # Oracle Errors
             re.compile(r'SQLSTATE\[\d+\]', re.IGNORECASE), # SQL Errors
             re.compile(r'Microsoft .* Error', re.IGNORECASE), # ASP errors
             re.compile(r'Internal Server Error', re.IGNORECASE), # Generic but potentially revealing
             re.compile(r'debug mode', re.IGNORECASE), # Debug flags
        ]
        for resp in self.responses:
             if resp['body'] and isinstance(resp['body'], str):
                 url = resp['url']; key = f"info_disc_{url}"
                 if key in processed_urls: continue
                 body_sample = resp['body'][:5000] # Analyze start of body
                 for pattern in info_disclosure_patterns:
                      if pattern.search(body_sample):
                           match_text = pattern.search(body_sample).group(0)
                           findings.append({
                               "type": "information_disclosure",
                               "severity": "LOW",
                               "url": url,
                               "details": f"Potential info disclosure detected: '{match_text[:50]}...'"
                           })
                           processed_urls.add(key)
                           break # Report first pattern found for this URL

        # 5. Insecure HTTP Usage (if target is HTTPS)
        # This requires knowing the initial target scheme, maybe pass it to init?
        # initial_scheme = urlparse(self.target_url).scheme # Assuming target_url is stored
        # if initial_scheme == 'https':
        #    for req in self.requests:
        #        if req['url'].startswith('http://') and self._is_in_scope(req['url']):
        #             # Report finding about insecure HTTP request within HTTPS site
        #             pass

        self.console.print_info(f"Traffic analysis complete. Found {len(findings)} potential findings.")
        return findings

    def get_endpoints(self) -> List[str]:
        """Extracts unique URLs (potentially endpoints) from captured requests."""
        # Simple extraction, could be enhanced to parse paths, filter file extensions etc.
        endpoints = set()
        for request in self.requests:
            try:
                 url = request.get("url")
                 if url:
                      # Basic filtering: ignore common static files if desired
                      parsed = urlparse(url)
                      if not re.search(r'\.(js|css|png|jpg|jpeg|gif|woff|woff2|svg|ico)$', parsed.path, re.IGNORECASE):
                           endpoints.add(url)
            except Exception: continue # Ignore errors processing URLs
        self.console.print_debug(f"Extracted {len(endpoints)} unique URLs from traffic.")
        return sorted(list(endpoints))

    def _is_in_scope(self, url: str) -> bool:
        """Helper to check if URL is in the initially defined scope (needs scope domain)."""
        # This assumes TrafficAnalyzer somehow knows the scope_domain, e.g., from SiteCrawler
        # Or needs to be passed during initialization. Placeholder logic:
        # return urlparse(url).netloc.lower() == self.scope_domain if hasattr(self, 'scope_domain') else True
        return True # Assume in scope if not implemented properly yet
