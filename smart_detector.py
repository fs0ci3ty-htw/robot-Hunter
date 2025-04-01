import logging
import random
import time
import base64
import html
import urllib.parse
from typing import List, Dict, Any, Optional
import re

# Import ConsoleManager
from console_manager import ConsoleManager

class SmartDetector:
    def __init__(self, console_manager: ConsoleManager, interactsh_url: Optional[str] = None):
        # Use ConsoleManager for user output
        self.console = console_manager
        # Use standard logging for internal debug messages if necessary
        self.logger = logging.getLogger('SmartDetector')
        self.interactsh_url = interactsh_url

        # --- User Agents ---
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.82",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", # Common bot
        ]

        # --- WAF Evasion Headers Pool ---
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
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Forwarded-Proto": "https"},
            {"Via": f"1.1 google"},
        ]

        # --- Interactive Element Detection Cues (Used in JS Evaluation) ---
        self.interactive_attributes = {
             "visual_cues": [
                "style.cursor === 'pointer'",
                "(el.offsetWidth > 10 && el.offsetHeight > 10)",
                "(style.backgroundColor !== 'transparent' || style.backgroundImage !== 'none')",
                "(style.borderWidth !== '0px' && style.borderStyle !== 'none')",
                "style.visibility !== 'hidden' && style.display !== 'none' && style.opacity !== '0'",
             ],
             "behavior_cues": [
                "el.onclick !== null",
                "el.onmouseover !== null",
                "el.onfocus !== null",
                "el.hasAttribute('onclick')",
                "el.hasAttribute('onmouseover')",
                "el.hasAttribute('onfocus')",
                "el.hasAttribute('ng-click')",
                "el.hasAttribute('v-on:click')",
                "el.hasAttribute('@click')",
                "el.matches('[data-action], [js-action], [data-onclick]')",
             ],
             "semantic_cues": [
                "['BUTTON', 'A', 'INPUT', 'TEXTAREA', 'SELECT', 'DETAILS'].includes(el.tagName)",
                "(el.tagName === 'INPUT' && ['submit', 'button', 'reset', 'image'].includes(el.type))",
                "el.getAttribute('role') === 'button' || el.getAttribute('role') === 'link' || el.getAttribute('role') === 'menuitem' || el.getAttribute('role') === 'tab'",
                "el.matches('[class*=\"btn\"], [class*=\"button\"], [class*=\"link\"], [class*=\"nav\"], [class*=\"menu\"], [class*=\"action\"]')",
                "el.isContentEditable"
             ],
             "text_cues": [
                "el.textContent && ['submit', 'send', 'login', 'register', 'buy', 'add', 'search', 'go', 'continue', 'next', 'more', 'click', 'view', 'update', 'save', 'delete', 'apply', 'confirm', 'accept'].some(t => el.textContent.trim().toLowerCase().includes(t))"
             ]
        }

        # --- Error Codes ---
        self.error_codes = {
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
            405: "Method Not Allowed", 429: "Too Many Requests", 500: "Internal Server Error",
            501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"
        }

        # --- Payload Counters ---
        self.identity_rotation_counter = 0
        self.payload_obfuscation_counter = 0 # Can track obfuscation usage if needed

        self.console.print_debug("SmartDetector initialized.")

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
            # Avoid reserved ranges for potentially 'external' looking IPs
            while first_octet in [0, 127] or (first_octet == 169 and random.randint(0,255) == 254) or first_octet >= 224:
                first_octet = random.randint(1, 223)
            return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    async def get_next_user_agent_and_headers(self) -> Dict[str, str]:
        """Gets a random User-Agent and a selection of WAF evasion headers."""
        user_agent = random.choice(self.user_agents)
        num_headers = random.randint(2, 5)
        # Ensure we don't select more headers than available
        num_to_select = min(num_headers, len(self.waf_evasion_headers_pool))
        selected_header_dicts = random.sample(self.waf_evasion_headers_pool, num_to_select)

        final_headers: Dict[str, str] = {"User-Agent": user_agent}
        header_keys_added: set[str] = set(["user-agent"])

        for header_dict in selected_header_dicts:
            try:
                key = list(header_dict.keys())[0]
                value = header_dict[key]
                # Ensure value is a string
                value_str = str(value)
                # Normalize key for checking duplicates
                norm_key = key.lower()
                if norm_key not in header_keys_added:
                    final_headers[key] = value_str
                    header_keys_added.add(norm_key)
            except (IndexError, KeyError, TypeError) as e:
                self.console.print_warning(f"Error processing evasion header {header_dict}: {e}")
                continue # Skip malformed header dicts

        self.console.print_debug(f"Rotated Identity: UA={user_agent[:20]}..., Headers={list(final_headers.keys())}")
        return final_headers

    async def should_rotate_identity(self) -> bool:
        """Determines if it's time to rotate identity headers."""
        self.identity_rotation_counter += 1
        # Rotate more frequently initially, then less often
        rotate_threshold = random.randint(3, 8) if self.identity_rotation_counter < 50 else random.randint(10, 20)
        should = self.identity_rotation_counter % rotate_threshold == 0
        if should:
             self.console.print_debug("Rotating identity...")
        return should

    async def detect_interactive_elements(self, page) -> List[Dict]:
        """Detects interactive elements using a scoring system based on JS evaluation."""
        self.console.print_info("Detecting interactive elements...")

        # Combine cues into a JS function for evaluation
        visual_check = ' || '.join(f"({c})" for c in self.interactive_attributes['visual_cues'])
        behavior_check = ' || '.join(f"({c})" for c in self.interactive_attributes['behavior_cues'])
        semantic_check = ' || '.join(f"({c})" for c in self.interactive_attributes['semantic_cues'])
        text_check = ' || '.join(f"({c})" for c in self.interactive_attributes['text_cues'])

        js_code = f"""
            () => {{
                const elementsData = [];
                // Query only within body to avoid head elements etc. Limit scope slightly.
                const allElements = document.querySelectorAll('body *:not(script):not(style):not(meta):not(link):not(title)');

                allElements.forEach(el => {{
                    try {{
                        // Avoid analyzing the analyzer's own elements if any were added
                        if (el.closest('[data-robot-hunter-ignore]')) return;

                        const style = window.getComputedStyle(el);
                        let score = 0;
                        const reasons = [];

                        // Check visibility first - skip if not visible
                        const rect = el.getBoundingClientRect();
                        if (!(rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none' && style.opacity !== '0')) {{
                           return;
                        }}

                        if ({visual_check}) {{ score += 1; reasons.push('visual'); }}
                        if ({behavior_check}) {{ score += 3; reasons.push('behavior'); }}
                        if ({semantic_check}) {{ score += 2; reasons.push('semantic'); }}
                        if ({text_check}) {{ score += 1; reasons.push('text'); }}

                        // Minimum score threshold & filter redundant parent/child clicks (basic)
                        if (score >= 2 && !el.querySelector('[data-rh-interactive="true"]')) {{
                            el.setAttribute('data-rh-interactive', 'true'); // Mark to avoid children
                            elementsData.push({{
                                selector: generateCssSelector(el),
                                score: score,
                                reasons: reasons,
                                text: el.textContent?.trim()?.substring(0, 50) || el.value?.substring(0,50) || el.name || el.id || '',
                                tag: el.tagName,
                                attributes: Array.from(el.attributes).reduce((acc, attr) => {{ acc[attr.name] = attr.value; return acc; }}, {{}}),
                                is_visible: true,
                                bounding_box: {{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }}
                            }});
                        }}
                    }} catch (e) {{
                        // console.error("Error processing element:", el, e); // Enable for deep debug
                    }}
                }});

                // Cleanup markers
                document.querySelectorAll('[data-rh-interactive]').forEach(el => el.removeAttribute('data-rh-interactive'));

                // Helper to generate a CSS selector
                function generateCssSelector(el) {{
                    if (!(el instanceof Element)) return;
                    const path = [];
                    while (el && el.nodeType === Node.ELEMENT_NODE) {{
                        let selector = el.nodeName.toLowerCase();
                        if (el.id) {{
                            // Escape special characters in ID
                            let escapedId = el.id.replace(/([!"#$%&'()*+,./:;<=>?@[\]^`{{|}}~])/g, '\\\\$1');
                            selector += '#' + escapedId;
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
                     // Ensure the path starts from html or body if possible
                    if (path.length > 0 && !path[0].startsWith('html') && !path[0].startsWith('body')) {{
                         if (el && document.documentElement.contains(el)) {{ 
                              // Check if documentElement selector works better
                              path.unshift('html');
                         }}
                    }}
                    return path.join(" > ");
                }}

                // Sort by score
                return elementsData.sort((a, b) => b.score - a.score);
            }}
        """
        try:
            elements_data = await page.evaluate(js_code)
            self.console.print_info(f"Found {len(elements_data)} potentially interactive elements.")
            for element in elements_data[:5]: # Log top 5
                self.console.print_debug(f"  -> Tag: {element['tag']}, Score: {element['score']}, Text: '{element['text']}', Selector: {element.get('selector','N/A')[:60]}...")
            return elements_data # Return serializable data
        except Exception as e:
            self.console.print_error(f"Error detecting interactive elements via JS: {e}")
            # self.console.print_debug(f"Failing JS Code:\n{js_code}") # Uncomment for deep debug
            return []


    async def detect_forms(self, page) -> List[Dict]:
        """Detects standard forms and pseudo-forms using JS evaluation."""
        self.console.print_info("Detecting forms...")
        try:
            # This JS needs to be robust to return selectors reliably
            forms_data = await page.evaluate("""
                () => {
                    const results = [];
                    const formElements = new Set(); // Track elements already part of a standard form

                    // Helper to generate CSS Selector (same as in detect_interactive_elements)
                    function generateCssSelector(el) {
                         if (!(el instanceof Element)) return null;
                         const path = [];
                         while (el && el.nodeType === Node.ELEMENT_NODE) {
                             let selector = el.nodeName.toLowerCase();
                             if (el.id) {
                                 let escapedId = el.id.replace(/([!"#$%&'()*+,./:;<=>?@[\]^`{{|}}~])/g, '\\\\$1');
                                 selector += '#' + escapedId;
                                 path.unshift(selector);
                                 break;
                             } else {
                                 let sib = el, nth = 1;
                                 while (sib = sib.previousElementSibling) {
                                     if (sib.nodeName.toLowerCase() == selector) nth++;
                                 }
                                 if (nth != 1) selector += ":nth-of-type("+nth+")";
                             }
                             path.unshift(selector);
                             el = el.parentNode;
                         }
                         return path.join(" > ");
                     }

                    // 1. Standard Forms
                    document.querySelectorAll('form').forEach(form => {
                        const formSelector = generateCssSelector(form);
                        if (!formSelector) return;

                        const inputs = Array.from(form.querySelectorAll('input, select, textarea'));
                        inputs.forEach(inp => formElements.add(inp)); // Mark inputs as belonging to a form

                        const submitButton = form.querySelector('button[type="submit"], input[type="submit"], button:not([type]), input[type="button"][value*="submit" i]'); // Try harder to find submit
                        results.push({
                            type: 'standard_form',
                            selector: formSelector,
                            action: form.action,
                            method: form.method || 'get', // Default to GET if not specified
                            inputs: inputs.map(el => ({
                                selector: generateCssSelector(el),
                                type: el.type || el.tagName.toLowerCase(),
                                name: el.name || el.id || '', // Use ID as fallback name
                                id: el.id,
                                value: el.type === 'password' ? null : el.value // Don't leak PW default val
                            })).filter(inp => inp.selector), // Only include inputs we can select
                            submit_selector: submitButton ? generateCssSelector(submitButton) : null
                        });
                    });

                    // 2. Pseudo-Forms (Inputs not in a standard form)
                    // Group orphaned inputs by visual proximity or common ancestor
                    const orphanedInputs = Array.from(document.querySelectorAll('input, select, textarea')).filter(el => !formElements.has(el));
                    const groupedOrphans = {}; // Group by a common ancestor selector

                    orphanedInputs.forEach(input => {
                         // Find a reasonable ancestor (e.g., div, fieldset, section) but not body/html
                         let ancestor = input.parentElement;
                         while (ancestor && !['DIV', 'FIELDSET', 'SECTION', 'LI', 'P'].includes(ancestor.tagName) && ancestor.tagName !== 'BODY') {
                              ancestor = ancestor.parentElement;
                         }
                         if (!ancestor || ancestor.tagName === 'BODY') ancestor = input.parentElement; // Fallback to direct parent

                         const ancestorSelector = generateCssSelector(ancestor);
                         if (!ancestorSelector) return;

                         if (!groupedOrphans[ancestorSelector]) {
                              groupedOrphans[ancestorSelector] = { element: ancestor, inputs: [] };
                         }
                         groupedOrphans[ancestorSelector].inputs.push(input);
                     });

                    Object.entries(groupedOrphans).forEach(([ancestorSelector, group]) => {
                         if (group.inputs.length >= 1) { // Consider even single orphaned inputs if they have a button nearby
                             // Look for a button-like element within or immediately after the ancestor
                             const submitButton = group.element.querySelector('button, [role="button"], input[type="button"], a[href="#"]') ||
                                                  group.element.nextElementSibling?.matches('button, [role="button"], input[type="button"]') ? group.element.nextElementSibling : null;

                             // Only add if it looks like a form (e.g., multiple inputs or one input + button)
                             if (group.inputs.length > 1 || (group.inputs.length === 1 && submitButton)) {
                                  results.push({
                                      type: 'pseudo_form',
                                      selector: ancestorSelector, // Selector of the common ancestor
                                      action: null, // Action unknown
                                      method: 'post', // Assume POST
                                      inputs: group.inputs.map(el => ({
                                          selector: generateCssSelector(el),
                                          type: el.type || el.tagName.toLowerCase(),
                                          name: el.name || el.id || '',
                                          id: el.id,
                                          value: el.type === 'password' ? null : el.value
                                      })).filter(inp => inp.selector),
                                      submit_selector: submitButton ? generateCssSelector(submitButton) : null
                                  });
                             }
                         }
                     });

                    return results;
                }
            """)
            standard_forms = len([f for f in forms_data if f.get('type') == 'standard_form'])
            pseudo_forms = len([f for f in forms_data if f.get('type') == 'pseudo_form'])
            self.console.print_info(f"Detected Forms: {len(forms_data)} (Standard: {standard_forms}, Pseudo: {pseudo_forms})")
            # Debug print form details if verbose
            for form in forms_data:
                 self.console.print_debug(f"  -> Form Type: {form.get('type')}, Inputs: {len(form.get('inputs',[]))}, Action: {form.get('action','N/A')}, Selector: {form.get('selector','N/A')[:60]}...")
            return forms_data
        except Exception as e:
            self.console.print_error(f"Error detecting forms via JS: {e}")
            return []

    def obfuscate_payload(self, payload: str, level: int = 1) -> str:
        """Applies WAF evasion techniques to payloads. (Keep implementation from previous response)"""
        if level <= 0: return payload
        original_payload = payload
        techniques_applied = []

        replacements = {
            " ": ["/**/", "%09", "%20", "+"],
            "=": ["= ", "%3d"], "'": ["%27", "`"], "\"": ["%22", "`"],
            "(": ["%28"], ")": ["%29"], "<": ["%3c"], ">": ["%3e"],
            ";": ["%3b"], "|": ["%7c"], "&": ["%26"],
        }
        keywords_sql = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
        keywords_script = ["SCRIPT", "ALERT", "ONERROR", "IMG", "SVG", "EVAL", "ONLOAD", "IFRAME", "PROMPT"]
        keywords_cmd = ["SLEEP", "CAT", "WHOAMI", "SYSTEMINFO", "TYPE", "DIR", "ID", "PING", "NSLOOKUP"]

        # Level 1: Simple space/char replacement, case variation, basic comments
        if level >= 1:
            if ' ' in payload and random.random() < 0.7: # Higher chance for space replacement
                 payload = payload.replace(' ', random.choice(replacements[' ']), random.randint(1, 3)) # Replace multiple spaces
                 techniques_applied.append("space_replace")
            if random.random() < 0.5:
                 char_to_replace = random.choice(list(replacements.keys()))
                 if char_to_replace != ' ' and char_to_replace in payload:
                     payload = payload.replace(char_to_replace, random.choice(replacements[char_to_replace]), 1)
                     techniques_applied.append("char_replace")
            if random.random() < 0.6:
                 all_keywords = keywords_sql + keywords_script + keywords_cmd
                 kw_to_vary = random.choice(all_keywords)
                 if re.search(kw_to_vary, payload, re.IGNORECASE):
                     payload = re.sub(f"({kw_to_vary})", lambda m: ''.join(random.choice([c.upper(), c.lower()]) for c in m.group(1)), payload, count=1, flags=re.IGNORECASE)
                     techniques_applied.append("case_vary")

        # Level 2: More encoding, versioned comments, URL encoding, newline chars
        if level >= 2:
            if any(kw in original_payload.upper() for kw in keywords_sql) and random.random() < 0.4:
                parts = re.split(r'(\s+)', payload) # Split while keeping delimiters
                if len(parts) > 1:
                    try:
                         # Find a keyword to wrap
                         keyword_indices = [i for i, p in enumerate(parts) if p.upper() in keywords_sql]
                         if keyword_indices:
                              idx = random.choice(keyword_indices)
                              # Check if it's not already commented
                              if not parts[idx].startswith('/*!'):
                                   parts[idx] = f"/*!50000{parts[idx]}*/"
                                   payload = "".join(parts)
                                   techniques_applied.append("mysql_comment")
                    except IndexError: pass # Ignore if logic fails

            if random.random() < 0.5:
                 char_to_encode = random.choice("=()<>;&|'")
                 if char_to_encode in payload:
                     payload = payload.replace(char_to_encode, urllib.parse.quote(char_to_encode), 1)
                     techniques_applied.append("partial_urlencode")

            if random.random() < 0.3: # Add newline/tab chars sometimes
                 payload = payload.replace(' ', random.choice(['%0a', '%0d', '%09']), 1)
                 techniques_applied.append("newline_char")

        # Level 3: Full URL encoding, Base64 (context specific!), HTML Entities
        if level >= 3:
            if random.random() < 0.3:
                 payload = urllib.parse.quote(payload)
                 techniques_applied.append("full_urlencode")
            elif 'alert' in original_payload and '<' not in original_payload and random.random() < 0.5: # Context: Maybe JS string?
                 payload = ''.join(f"\\u{ord(c):04x}" for c in payload)
                 techniques_applied.append("js_unicode_escape")
            elif any(k in original_payload for k in ['<', '>']) and random.random() < 0.6: # Likely HTML context
                 payload = ''.join(f"&#x{ord(c):x};" for c in payload)
                 techniques_applied.append("html_entity")


        self.console.print_debug(f"Payload Obfuscation (Level {level}): {original_payload[:30]}... -> {payload[:40]}... | Techniques: {techniques_applied or 'None'}")
        return payload


    async def log_response_status(self, response, context: str = "") -> Dict[str, Any]:
        """Logs detailed info about HTTP responses, using ConsoleManager if applicable."""
        status = -1
        url = "N/A"
        content_type = "N/A"
        content_length = 0
        details = ""
        category = "info"
        is_error = False

        if response:
            status = response.status_code
            url = str(response.url)
            content_type = response.headers.get("content-type", "N/A")
            content_length = len(response.content)

        log_entry: Dict[str, Any] = {
            "timestamp": time.time(),
            "status": status,
            "url": url,
            "content_type": content_type,
            "content_length": content_length,
            "context": context
        }

        if status >= 400:
            is_error = True
            error_type = self.error_codes.get(status, "Unknown Error")
            log_entry["error"] = True
            log_entry["error_type"] = error_type
            if 400 <= status < 500:
                category = "client_error"
            elif status >= 500:
                category = "server_error"

            if status == 403: details = "Access Forbidden - Potential WAF or Access Control"
            elif status == 429: details = "Rate Limited - Reduce request frequency"
            elif status >= 500: details = "Server Error - Potential vulnerability or misconfiguration"
            log_entry["details"] = details

        # Log to console (optional, maybe only for errors or verbose mode)
        if is_error or self.console.verbose:
             log_msg = f"Response Status: {status} ({self.error_codes.get(status, 'Unknown')}) for {url} [{context}] {details}"
             if is_error:
                 self.console.print_warning(log_msg) if status < 500 else self.console.print_error(log_msg)
             else:
                 self.console.print_debug(log_msg)

        return log_entry