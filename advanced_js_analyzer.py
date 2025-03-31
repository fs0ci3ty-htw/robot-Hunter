import logging
import asyncio
import os
import stat
from pathlib import Path
from curses import window
from dataclasses import field
from math import prod
import random
import re
import json
import base64
from aiohttp import Payload
import jsbeautifier
from typing import List, Dict, Any

class AdvancedJSAnalyzer:
    def __init__(self, console_manager):
        # Initialize logging
        self.logger = logging.getLogger('AdvancedJSAnalyzer')
        self.logger.setLevel(logging.INFO)
        
        # Create handler if none exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            
        self.console = console_manager  # Add console manager
        self.logger.info("Initializing AdvancedJSAnalyzer...")
        
        # Existing initialization code
        self.findings = []
        self.traced_functions = {}
        self.modified_variables = {}
        self.cmd_injection_payloads = [
            "; ls -la", 
            "& dir", 
            "| cat /etc/passwd", 
            "$(whoami)", 
            "`id`", 
            "$(cat /etc/shadow)", 
            "'; ls -la; '", 
            "&& netstat -an"
        ]
        
        # Verificar y configurar permisos
        self.working_dir = Path('/tmp/robot-hunter')
        try:
            # Crear directorio temporal con permisos seguros
            self.working_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.working_dir, stat.S_IRWXU)
            
            self.logger.info(f"Directorio de trabajo creado: {self.working_dir}")
        except PermissionError as e:
            self.logger.error(f"Error de permisos al crear directorio: {e}")
            # Intentar usar directorio alternativo
            self.working_dir = Path.home() / '.robot-hunter'
            self.working_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Usando directorio alternativo: {self.working_dir}")
        
        # Configurar manejo de errores mejorado
        self.error_handlers = {
            'PermissionError': self._handle_permission_error,
            'TimeoutError': self._handle_timeout_error,
            'NetworkError': self._handle_network_error
        }
        
        self.logger.debug("Initialization complete")
        
    async def _handle_permission_error(self, error, context=None):
        """Maneja errores de permisos"""
        self.logger.error(f"Error de permisos: {error}")
        self.logger.info("Intentando ejecutar con privilegios reducidos...")
        
        if context and 'operation' in context:
            try:
                # Intentar operación alternativa con menos privilegios
                if context['operation'] == 'file_access':
                    return await self._safe_file_access(context['path'])
                elif context['operation'] == 'network_access':
                    return await self._safe_network_access(context['url'])
            except Exception as e:
                self.logger.error(f"Error en operación alternativa: {e}")
                return None

    async def _handle_timeout_error(self, error, context=None):
        """Maneja errores de timeout"""
        self.logger.error(f"Error de timeout: {error}")
        self.console.print(f"[red]Timeout Error: {error}[/red]")  # Use console manager
        self.logger.info("Intentando operación con timeout extendido...")
        
        if context and 'operation' in context:
            try:
                # Reintentar con timeout extendido
                if context.get('retry_count', 0) < 3:
                    context['retry_count'] = context.get('retry_count', 0) + 1
                    context['timeout'] = context.get('timeout', 30) * 2
                    
                    self.logger.info(f"Reintento {context['retry_count']} con timeout de {context['timeout']}s")
                    
                    if context['operation'] == 'page_load':
                        return await self._safe_page_load(context['url'], context['timeout'])
                    elif context['operation'] == 'script_execution':
                        return await self._safe_script_execution(context['script'], context['timeout'])
                    
                return None
            except Exception as e:
                self.logger.error(f"Error en reintento con timeout extendido: {e}")
                self.console.print(f"[red]Error in retry with extended timeout: {e}[/red]")  # Use console manager
                return None

    async def _handle_network_error(self, error, context=None):
        """Maneja errores de red"""
        self.logger.error(f"Error de red: {error}")
        self.console.print(f"[red]Network Error: {error}[/red]")  # Use console manager
        self.logger.info("Intentando operación alternativa de red...")
        
        if context and 'operation' in context:
            try:
                # Intentar operación alternativa
                if context['operation'] == 'fetch':
                    return await self._safe_network_access(context['url'])
                elif context['operation'] == 'websocket':
                    return await self._safe_websocket_connection(context['url'])
            except Exception as e:
                self.logger.error(f"Error en operación alternativa de red: {e}")
                self.console.print(f"[red]Error in alternative network operation: {e}[/red]")  # Use console manager
                return None

    async def _safe_file_access(self, path):
        """Intenta acceder a archivos de forma segura"""
        try:
            temp_path = self.working_dir / Path(path).name
            self.logger.debug(f"Intentando acceso seguro a: {temp_path}")
            return temp_path
        except Exception as e:
            self.logger.error(f"Error en acceso seguro a archivo: {e}")
            return None

    async def _safe_network_access(self, url):
        """Intenta acceso a red con privilegios reducidos"""
        try:
            self.logger.debug(f"Intentando acceso a red seguro para: {url}")
            # Implementar lógica de acceso a red con privilegios reducidos
            return True
        except Exception as e:
            self.logger.error(f"Error en acceso seguro a red: {e}")
            return None

    async def _safe_page_load(self, url: str, timeout: int):
        """Carga segura de página con timeout extendido"""
        self.logger.debug(f"Intentando cargar {url} con timeout de {timeout}s")
        try:
            # Implementar lógica de carga segura
            self.console.print(f"[yellow]Loading page: {url}[/yellow]")  # Use console manager
            return True
        except Exception as e:
            self.logger.error(f"Error en carga segura de página: {e}")
            self.console.print(f"[red]Error in safe page load: {e}[/red]")  # Use console manager
            return None

    async def _safe_script_execution(self, script: str, timeout: int):
        """Ejecución segura de script con timeout extendido"""
        self.logger.debug(f"Intentando ejecutar script con timeout de {timeout}s")
        try:
            # Implementar lógica de ejecución segura
            self.console.print(f"[yellow]Executing script with timeout: {timeout}s[/yellow]")  # Use console manager
            return True
        except Exception as e:
            self.logger.error(f"Error en ejecución segura de script: {e}")
            self.console.print(f"[red]Error in safe script execution: {e}[/red]")  # Use console manager
            return None

    async def run_analysis_with_retry(self, page, max_retries=3):
        """Ejecuta análisis con reintentos y manejo de errores"""
        for attempt in range(max_retries):
            try:
                self.logger.info(f"Intento de análisis {attempt + 1}/{max_retries}")
                self.console.print(f"[blue]Analysis attempt {attempt + 1}/{max_retries}[/blue]")  # Use console manager
                findings = await self.run_full_analysis(page)  # Capture findings
                return {"findings": findings}  # Return structured findings
            except PermissionError as e:
                self.logger.warning(f"Error de permisos en intento {attempt + 1}: {e}")
                self.console.print(f"[yellow]Permission Error: {e}[/yellow]")  # Use console manager
                await self._handle_permission_error(e, {'operation': 'analysis'})
                if attempt == max_retries - 1:
                    raise
            except Exception as e:
                self.logger.error(f"Error general en intento {attempt + 1}: {e}")
                self.console.print(f"[red]General Error: {e}[/red]")  # Use console manager
                if attempt == max_retries - 1:
                    raise
            await asyncio.sleep(1)

    async def setup_debugger(self, page):
        """Configurar el debugger y los hooks de instrumentación"""
        await page.evaluate("""
        (() => {
            // Almacenamiento global para resultados
            window.__debugData = {
                functionCalls: [],
                singleCharVars: {},
                networkRequests: [],
                errors: [],
                modifiedVars: {},
                callGraph: {},
                serviceConnections: [],
                dbOperations: []
            };
            
            // Interceptar todas las llamadas a fetch y XHR
            const originalFetch = window.fetch;
            window.fetch = async function(resource, options) {
                try {
                    const callStack = new Error().stack;
                    const requestData = {
                        type: 'fetch',
                        url: resource.toString(),
                        options: options || {},
                        timestamp: Date.now(),
                        stack: callStack
                    };
                    
                    window.__debugData.networkRequests.push(requestData);
                    
                    // Analizar si parece conexión a DB o servicio
                    const url = resource.toString();
                    if (url.match(/api|service|db|data|query|graphql|firebase|aws/i)) {
                        window.__debugData.serviceConnections.push({
                            type: 'api_endpoint',
                            url: url,
                            timestamp: Date.now(),
                            caller: callStack.split('\\n')[1]
                        });
                    }
                    
                    // Ejecutar el fetch original
                    const response = await originalFetch.apply(this, arguments);
                    
                    // Capturar el resultado si es posible
                    const clone = response.clone();
                    try {
                        const contentType = clone.headers.get('content-type');
                        if (contentType && contentType.includes('application/json')) {
                            const jsonData = await clone.json();
                            requestData.response = {
                                status: clone.status,
                                contentType: contentType,
                                data: jsonData
                            };
                            
                            // Detectar posibles datos de DB
                            if (JSON.stringify(jsonData).match(/id|user|pass|admin|account|key|token/i)) {
                                window.__debugData.dbOperations.push({
                                    type: 'db_data',
                                    operation: 'read',
                                    data: jsonData,
                                    url: url
                                });
                            }
                        }
                    } catch(e) {
                        // Error al parsear la respuesta
                    }
                    
                    return response;
                } catch(error) {
                    window.__debugData.errors.push({
                        type: 'fetch_error',
                        error: error.toString(),
                        url: resource.toString(),
                        timestamp: Date.now()
                    });
                    throw error;
                }
            };
            
            // Interceptar XHR
            const originalXHROpen = XMLHttpRequest.prototype.open;
            const originalXHRSend = XMLHttpRequest.prototype.send;
            
            XMLHttpRequest.prototype.open = function(method, url) {
                this._debugData = {
                    method: method,
                    url: url,
                    timestamp: Date.now(),
                    stack: new Error().stack
                };
                return originalXHROpen.apply(this, arguments);
            };
            
            XMLHttpRequest.prototype.send = function(data) {
                if (this._debugData) {
                    this._debugData.data = data;
                    window.__debugData.networkRequests.push(this._debugData);
                    
                    // Analizar si parece conexión a DB o servicio
                    const url = this._debugData.url;
                    if (url.match(/api|service|db|data|query|graphql|firebase|aws/i)) {
                        window.__debugData.serviceConnections.push({
                            type: 'api_endpoint',
                            url: url,
                            method: this._debugData.method,
                            timestamp: Date.now(),
                            caller: this._debugData.stack.split('\\n')[1]
                        });
                    }
                }
                
                // Interceptar la respuesta
                this.addEventListener('load', function() {
                    if (this._debugData) {
                        this._debugData.response = {
                            status: this.status,
                            responseText: this.responseText
                        };
                        
                        // Detectar posibles datos de DB
                        if (this.responseText.match(/id|user|pass|admin|account|key|token/i)) {
                            window.__debugData.dbOperations.push({
                                type: 'db_data',
                                operation: 'read',
                                data: this.responseText.substring(0, 1000), // Limitar tamaño
                                url: this._debugData.url
                            });
                        }
                    }
                });
                
                return originalXHRSend.apply(this, arguments);
            };
            
            // Encontrar y rastrear variables de una sola letra
            for (let key in window) {
                if (key.length === 1 || key.match(/^[a-z]\\d*$/)) {
                    const value = window[key];
                    
                    // Guardar estado original
                    window.__debugData.singleCharVars[key] = {
                        type: typeof value,
                        originalValue: value,
                        properties: typeof value === 'object' ? Object.keys(value || {}) : [],
                        usageCount: 0,
                        methodCalls: []
                    };
                    
                    // Si es un objeto, rastrear sus métodos
                    if (typeof value === 'object' && value !== null) {
                        for (let prop in value) {
                            if (typeof value[prop] === 'function') {
                                const originalMethod = value[prop];
                                value[prop] = function() {
                                    window.__debugData.singleCharVars[key].usageCount++;
                                    window.__debugData.singleCharVars[key].methodCalls.push({
                                        method: prop,
                                        args: Array.from(arguments),
                                        timestamp: Date.now(),
                                        stack: new Error().stack
                                    });
                                    
                                    // Rastrear en el grafo de llamadas
                                    const caller = new Error().stack.split('\\n')[2]?.trim() || 'unknown';
                                    const callee = key + '.' + prop;
                                    
                                    if (!window.__debugData.callGraph[caller]) {
                                        window.__debugData.callGraph[caller] = [];
                                    }
                                    window.__debugData.callGraph[caller].push(callee);
                                    
                                    return originalMethod.apply(this, arguments);
                                };
                            }
                        }
                    }
                }
            }
            
            // Interceptar errores globales
            window.addEventListener('error', function(event) {
                window.__debugData.errors.push({
                    type: 'global_error',
                    message: event.message,
                    filename: event.filename,
                    lineno: event.lineno,
                    colno: event.colno,
                    timestamp: Date.now(),
                    stack: event.error?.stack
                });
            });
            
            // Interceptar promesas rechazadas
            window.addEventListener('unhandledrejection', function(event) {
                window.__debugData.errors.push({
                    type: 'promise_rejection',
                    reason: event.reason?.toString(),
                    timestamp: Date.now(),
                    stack: event.reason?.stack
                });
            });
            
            // Activar debugger para funciones sospechosas
            ['eval', 'Function', 'setTimeout', 'setInterval'].forEach(funcName => {
                if (typeof window[funcName] === 'function') {
                    const original = window[funcName];
                    window[funcName] = function() {
                        window.__debugData.functionCalls.push({
                            name: funcName,
                            args: Array.from(arguments),
                            timestamp: Date.now(),
                            stack: new Error().stack
                        });
                        // Activar debugger solo en versión de desarrollo
                        // debugger;
                        return original.apply(this, arguments);
                    };
                }
            });
            
            // Detectar conexiones a bases de datos
            ['indexedDB', 'openDatabase', 'firebase', 'firestore'].forEach(dbName => {
                if (window[dbName]) {
                    window.__debugData.dbOperations.push({
                        type: 'db_connection',
                        name: dbName,
                        available: true,
                        timestamp: Date.now()
                    });
                }
            });
            
            console.log('[AdvancedJSAnalyzer] Debugger activado');
        })();
        """)
        
        print("Debugger configurado con éxito")
    
    async def analyze_variables(self, page):
        """Analizar y manipular variables de una sola letra"""
        single_char_vars = await page.evaluate("""
        () => {
            if (!window.__debugData || !window.__debugData.singleCharVars) {
                return {};
            }
            return window.__debugData.singleCharVars;
        }
        """)
        
        # Probar cada variable modificándola
        for var_name, info in single_char_vars.items():
            if info['type'] in ['object', 'function'] and info['usageCount'] > 0:
                # La variable se usa, intentar modificarla
                await self._modify_and_test_variable(page, var_name, info)
        
        # Capturar los resultados finales
        updated_data = await page.evaluate("""
        () => {
            if (!window.__debugData) {
                return {
                    singleCharVars: {},
                    modifiedVars: {},
                    callGraph: {},
                    errors: []
                };
            }
            return {
                singleCharVars: window.__debugData.singleCharVars,
                modifiedVars: window.__debugData.modifiedVars || {},
                callGraph: window.__debugData.callGraph,
                errors: window.__debugData.errors
            };
        }
        """)
        
        # Registrar hallazgos
        for var_name, info in updated_data['singleCharVars'].items():
            if info['usageCount'] > 0:
                self.findings.append({
                    "type": "active_single_char_var",
                    "name": var_name,
                    "usage_count": info['usageCount'],
                    "method_calls": info['methodCalls'],
                    "severity": "MEDIUM"
                })
            
            if var_name in updated_data.get('modifiedVars', {}):
                mod_info = updated_data['modifiedVars'][var_name]
                if mod_info.get('error'):
                    self.findings.append({
                        "type": "var_modification_error",
                        "name": var_name,
                        "error": mod_info['error'],
                        "severity": "HIGH",
                        "details": "Error al modificar variable, posible punto de entrada para ataque"
                    })
        
        # Buscar patrones sospechosos en el grafo de llamadas
        for caller, callees in updated_data.get('callGraph', {}).items():
            suspicious_patterns = ['ajax', 'fetch', 'getJSON', 'post', 'request', 'send', 'submit']
            if any(pattern in caller.lower() for pattern in suspicious_patterns):
                self.findings.append({
                    "type": "suspicious_call_chain",
                    "caller": caller,
                    "callees": callees,
                    "severity": "MEDIUM",
                    "details": "Cadena de llamadas sospechosa, potencial punto de inyección"
                })
        
        return updated_data
    
    async def _modify_and_test_variable(self, page, var_name, info):
        """Modifica una variable y observa el comportamiento"""
        # Probar diferentes tipos de modificaciones según el tipo
        if info['type'] == 'object':
            # Intentar inyección SQL en una propiedad
            sql_payload = "' OR '1'='1"
            await page.evaluate(f"""
            (varName, payload) => {{
                try {{
                    // Guardar valor original
                    const original = window[varName];
                    
                    // Buscar propiedad modificable
                    const props = Object.keys(original || {{}});
                    if (props.length > 0) {{
                        const propToModify = props[0];
                        const originalValue = original[propToModify];
                        
                        // Modificar propiedad
                        original[propToModify] = payload;
                        
                        if (!window.__debugData) window.__debugData = {{}};
                        if (!window.__debugData.modifiedVars) window.__debugData.modifiedVars = {{}};
                        window.__debugData.modifiedVars[varName] = {{
                            modified: true,
                            property: propToModify,
                            originalValue: originalValue,
                            newValue: payload
                        }};
                        
                        console.log(`Modified ${{varName}}.${{propToModify}} to "${{payload}}"`);
                    }}
                }} catch(e) {{
                    if (!window.__debugData) window.__debugData = {{}};
                    if (!window.__debugData.modifiedVars) window.__debugData.modifiedVars = {{}};
                    window.__debugData.modifiedVars[varName] = {{
                        error: e.toString(),
                        stack: e.stack
                    }};
                    console.error(`Error modifying ${{varName}}:`, e);
                }}
            }}
            """, var_name, sql_payload)
            
            # Esperar a que se procese la modificación
            await asyncio.sleep(1)
            
            # Verificar si ha provocado errores
            errors = await page.evaluate("""
            () => {
                if (!window.__debugData || !window.__debugData.errors) {
                    return [];
                }
                return window.__debugData.errors;
            }
            """)
            
            # Registrar errores nuevos
            recent_errors = [e for e in errors if e['timestamp'] > (info.get('timestamp', 0) or 0)]
            for error in recent_errors:
                self.findings.append({
                    "type": "var_modification_error",
                    "variable": var_name,
                    "error": error,
                    "severity": "HIGH",
                    "details": "Error provocado por modificación, posible vulnerabilidad"
                })
        
        # Intentar inyección de comandos
        if info['type'] == 'object' and info['usageCount'] > 2:
            cmd_payload = random.choice(self.cmd_injection_payloads)
            await page.evaluate(f"""
            (varName, payload) => {{
                try {{
                    // Buscar métodos que acepten cadenas
                    const obj = window[varName];
                    for (let prop in obj) {{
                        if (typeof obj[prop] === 'function') {{
                            try {{
                                // Intentar llamar con payload
                                obj[prop](payload);
                                console.log(`Called ${window[var_name]}.${prod}(${Payload})`);
                            }} catch(e) {{
                                // Ignorar errores en las llamadas individuales
                            }}
                        }}
                    }}
                }} catch(e) {{
                    console.error(`Error in command injection test:`, e);
                }}
            }}
            """, var_name, cmd_payload)
            
            await asyncio.sleep(1)
    
    async def trace_function_execution(self, page, selector_to_click):
        """Coloca breakpoints y sigue la ejecución al hacer clic en un elemento"""
        # Primero capturar estado antes de hacer clic
        before_state = await page.evaluate("""
        () => {
            if (!window.__debugData) {
                return {
                    networkCount: 0,
                    errorCount: 0,
                    serviceConnections: []
                };
            }
            return {
                networkCount: window.__debugData.networkRequests.length,
                errorCount: window.__debugData.errors.length,
                serviceConnections: [...window.__debugData.serviceConnections]
            };
        }
        """)
        
        # Intentar hacer clic en el elemento
        try:
            await page.click(selector_to_click)
            # Esperar a que se completen las peticiones de red
            await page.wait_for_load_state("networkidle")
        except Exception as e:
            print(f"Error al hacer clic en {selector_to_click}: {e}")
        
        # Capturar estado después del clic
        after_state = await page.evaluate(f"""
        () => {{
            if (!window.__debugData) {{
                return {{
                    networkRequests: [],
                    errors: [],
                    serviceConnections: []
                }};
            }}
            return {{
                networkRequests: window.__debugData.networkRequests.slice({before_state['networkCount']}),
                errors: window.__debugData.errors.slice({before_state['errorCount']}),
                serviceConnections: window.__debugData.serviceConnections.slice({len(before_state['serviceConnections'])})
            }};
        }}
        """)
        
        # Analizar los resultados
        results = {
            "clicked_element": selector_to_click,
            "new_network_requests": len(after_state.get('networkRequests', [])),
            "new_errors": len(after_state.get('errors', [])),
            "new_service_connections": len(after_state.get('serviceConnections', []))
        }
        
        # Identificar endpoints interesantes
        interesting_endpoints = []
        for req in after_state.get('networkRequests', []):
            url = req.get('url', '')
            if any(pattern in url for pattern in ['api', 'data', 'query', 'graphql', 'json']):
                interesting_endpoints.append({
                    "url": url,
                    "method": req.get('method', 'GET'),
                    "has_data": bool(req.get('data', False))
                })
        
        results["interesting_endpoints"] = interesting_endpoints
        
        # Registrar hallazgos si hay conexiones a servicios
        for conn in after_state.get('serviceConnections', []):
            self.findings.append({
                "type": "service_connection",
                "url": conn.get('url'),
                "triggered_by": selector_to_click,
                "severity": "MEDIUM",
                "details": f"Conexión a servicio detectada al hacer clic en {selector_to_click}"
            })
        
        return results
    
    async def inject_payloads_in_form(self, page, form_selector):
        """Inyecta payloads en un formulario y observa la respuesta"""
        try:
            self.logger.info(f"Iniciando inyección de payloads en formulario: {form_selector}")
            
            # Identificar todos los campos del formulario
            form_fields = await page.evaluate(f"""
            (formSelector) => {{
                const form = document.querySelector(formSelector);
                if (!form) return null;
                
                const fields = Array.from(form.querySelectorAll('input, select, textarea'));
                return fields.map(field => {{
                    return {{
                        name: field.name || field.id || '',
                        type: field.type || field.tagName.toLowerCase(),
                        value: field.value || '',
                        selector: `${form_selector} ${field.tagName.toLowerCase()}` + 
                                 (field.id ? `#${field.id}` : '') + 
                                 (field.name ? `[name="${field.name}"]` : '')
                    }};
                }});
            }}
            """, form_selector)

            if not form_fields:
                self.logger.warning(f"No se encontraron campos en el formulario: {form_selector}")
                return {"error": f"No se encontró el formulario: {form_selector}"}

            # Preparar payloads para diferentes tipos de campos
            payloads = {
                "text": ["' OR 1=1--", "<script>alert(1)</script>", "; ls -la"],
                "password": ["admin' --", "' UNION SELECT 1,2,3--"],
                "email": ["admin'@example.com", "test+<script>alert(1)</script>@example.com"],
                "number": ["1 OR 1=1", "999999", "-1' OR 1=1"]
            }

            results = {"attempts": []}
            
            # Para cada campo, intentar diferentes payloads
            for current_field in form_fields:
                field_type = current_field.get('type', 'text')
                field_selector = current_field.get('selector')
                field_name = current_field.get('name', 'unknown')

                if not field_selector:
                    self.logger.warning(f"Campo sin selector válido: {field_name}")
                    continue

                self.logger.info(f"Probando campo: {field_name} ({field_type})")
                
                # Seleccionar payloads apropiados
                field_payloads = payloads.get(field_type, payloads['text'])
                
                for payload in field_payloads:
                    try:
                        self.logger.debug(f"Intentando payload: {payload}")
                        
                        # Llenar el campo
                        await page.fill(field_selector, payload)
                        
                        # Buscar y hacer clic en el botón de envío
                        submit_button = await page.query_selector(f"{form_selector} button[type=submit], {form_selector} input[type=submit]")
                        if submit_button:
                            await submit_button.click()
                            await page.wait_for_load_state("networkidle")
                            
                            attempt_result = {
                                "field": field_name,
                                "payload": payload,
                                "success": True,
                                "error": None
                            }
                            
                        else:
                            attempt_result = {
                                "field": field_name,
                                "payload": payload,
                                "success": False,
                                "error": "No se encontró botón de envío"
                            }
                        
                        results["attempts"].append(attempt_result)
                        
                    except Exception as e:
                        self.logger.error(f"Error al probar payload '{payload}' en campo '{field_name}': {str(e)}")
                        results["attempts"].append({
                            "field": field_name,
                            "payload": payload,
                            "success": False,
                            "error": str(e)
                        })
                        
                    # Esperar un poco entre intentos
                    await asyncio.sleep(0.5)
                    
                # Restaurar el formulario para el siguiente campo
                try:
                    await page.goto(page.url)
                    await page.wait_for_load_state("networkidle")
                except Exception as e:
                    self.logger.error(f"Error al restaurar página: {str(e)}")

            return results
            
        except Exception as e:
            self.logger.error(f"Error general en inject_payloads_in_form: {str(e)}")
            return {"error": str(e)}
    
    async def analyze_db_connections(self, page):
        """Analiza posibles conexiones a bases de datos"""
        db_operations = await page.evaluate("""
        () => {
            if (!window.__debugData || !window.__debugData.dbOperations) {
                return [];
            }
            return window.__debugData.dbOperations;
        }
        """)
        
        for operation in db_operations:
            self.findings.append({
                "type": "database_operation",
                "database": operation.get('name', 'unknown'),
                "operation_type": operation.get('operation', 'unknown'),
                "severity": "HIGH",
                "details": f"Operación de base de datos detectada: {json.dumps(operation)[:100]}..."
            })
        
        return db_operations
    
    async def run_full_analysis(self, page):
        """Ejecuta el análisis completo y devuelve los hallazgos"""
        self.console.print("[green]Running full analysis...[/green]")
        findings = []
        # Implement the full analysis logic here, adding findings to the list
        # Example:
        # findings.append({"type": "example", "data": "example data"})
        return findings