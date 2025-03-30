import asyncio
import random
import re
import json
import base64
import jsbeautifier
from typing import List, Dict, Any

class AdvancedJSAnalyzer:
    def __init__(self):
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
                                console.log(`Called ${varName}.${prop}(${payload})`);
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
        # Identificar todos los campos del formulario
        form_fields = await page.evaluate(f"""
        (formSelector) => {{
            const form = document.querySelector(formSelector);
            if (!form) return null;
            
            return Array.from(form.querySelectorAll('input, select, textarea')).map(field => {{
                const id = field.id ? `#${field.id}` : '';
                const name = field.name ? `[name="${field.name}"]` : '';
                return {{
                    name: field.name || field.id,
                    type: field.type || field.tagName.toLowerCase(),
                    value: field.value,
                    selector: field.tagName.toLowerCase() + id + name
                }};
            }});
        }}
        """, form_selector)
        
        if not form_fields:
            return {"error": f"No se encontró el formulario: {form_selector}"}
        
        # Preparar payloads para diferentes tipos de campos
        payloads = {
            "text": ["' OR 1=1--", "<script>alert(1)</script>", "; ls -la"],
            "password": ["admin' --", "' UNION SELECT 1,2,3--", "password' OR '1'='1"],
            "email": ["admin'@example.com", "user@example.com' OR '1'='1", "test+<script>alert(1)</script>@example.com"],
            "number": ["1 OR 1=1", "999999", "-1' OR 1=1"]
        }
        
        results = {"attempts": []}
        
        # Para cada campo, intentar diferentes payloads
        for field in form_fields:
            field_type = field['type']
            field_selector = field['selector']
            
            # Seleccionar payloads apropiados
            field_payloads = payloads.get(field_type, payloads['text'])
            
            for payload in field_payloads:
                # Capturar estado antes de enviar
                before_state = await page.evaluate("""
                () => {{
                    if (!window.__debugData) {{
                        return {{
                            networkCount: 0,
                            errorCount: 0
                        }};
                    }}
                    return {{
                        networkCount: window.__debugData.networkRequests.length,
                        errorCount: window.__debugData.errors.length
                    }};
                }}
                """)
                
                try:
                    # Llenar el campo
                    await page.fill(field_selector, payload)
                    
                    # Buscar y hacer clic en el botón de envío
                    submit_button = await page.query_selector(f"{form_selector} button[type=submit], {form_selector} input[type=submit]")
                    if submit_button:
                        await submit_button.click()
                        await page.wait_for_load_state("networkidle")
                    
                    # Capturar estado después del envío
                    after_state = await page.evaluate(f"""
                    () => {{
                        if (!window.__debugData) {{
                            return {{
                                networkRequests: [],
                                errors: [],
                                currentUrl: window.location.href
                            }};
                        }}
                        return {{
                            networkRequests: window.__debugData.networkRequests.slice({before_state['networkCount']}),
                            errors: window.__debugData.errors.slice({before_state['errorCount']}),
                            currentUrl: window.location.href
                        }};
                    }}
                    """)
                    
                    # Analizar respuesta
                    success = len(after_state.get('errors', [])) == 0
                    redirect = after_state.get('currentUrl') != page.url
                    
                    # Buscar respuestas de error en la página
                    error_messages = await page.evaluate("""
                    () => {
                        const errors = [];
                        // Buscar elementos que parezcan mensajes de error
                        document.querySelectorAll('.error, .alert, [role="alert"], [class*="error"]').forEach(el => {
                            errors.push(el.textContent.trim());
                        });
                        return errors;
                    }
                    """)
                    
                    attempt_result = {
                        "field": field['name'],
                        "payload": payload,
                        "success": success,
                        "redirect": redirect,
                        "error_messages": error_messages,
                        "triggered_errors": len(after_state.get('errors', [])) > 0
                    }
                    
                    results["attempts"].append(attempt_result)
                    
                    # Si provocó un error en el servidor, registrar como potencial vulnerabilidad
                    if attempt_result["triggered_errors"] and not error_messages:
                        self.findings.append({
                            "type": "form_injection_vulnerability",
                            "field": field['name'],
                            "payload": payload,
                            "severity": "HIGH",
                            "details": f"El payload '{payload}' en el campo '{field['name']}' provocó errores pero no mostró mensaje de error al usuario"
                        })
                    
                    # Restaurar el formulario para el siguiente intento
                    await page.goto(page.url)
                    await page.wait_for_load_state("networkidle")
                    
                except Exception as e:
                    print(f"Error al probar payload '{payload}' en campo '{field['name']}': {e}")
        
        return results
    
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
        """Ejecuta análisis completo de JS y registra vulnerabilidades"""
        # 1. Configurar debugger
        await self.setup_debugger(page)
        
        # 2. Analizar variables
        var_analysis = await self.analyze_variables(page)
        
        # 3. Buscar botones y enlaces para hacer clic
        interactive_elements = await page.evaluate("""
        () => {
            return Array.from(document.querySelectorAll('button, a, [role="button"], [class*="btn"]'))
                .filter(el => el.offsetWidth > 0 && el.offsetHeight > 0)
                .map(el => ({
                    text: el.textContent.trim(),
                    tag: el.tagName,
                    selector: el.tagName.toLowerCase() + 
                        (el.id ? `#${el.id}` : '') + 
                        (el.className ? `.${el.className.split(' ')[0]}` : '')
                }));
        }
        """)
        
        # 4. Hacer clic en elementos y rastrear ejecución
        for element in interactive_elements[:5]:  # Limitar para evitar bucles infinitos
            await self.trace_function_execution(page, element['selector'])
            await asyncio.sleep(1)  # Esperar entre clics
        
        # 5. Buscar formularios
        forms = await page.evaluate("""
        () => {
            return Array.from(document.querySelectorAll('form')).map(form => ({
                id: form.id,
                action: form.action,
                method: form.method,
                selector: form.tagName.toLowerCase() + 
                    (form.id ? `#${form.id}` : '') + 
                    (form.className ? `.${form.className.split(' ')[0]}` : '')
            }));
        }
        """)
        
        # 6. Probar payloads en formularios
        for form in forms:
            await self.inject_payloads_in_form(page, form['selector'])
        
        # 7. Analizar conexiones a DB
        await self.analyze_db_connections(page)
        
        # 8. Generar informe final
        return {
            "var_analysis": var_analysis,
            "interactive_elements": interactive_elements,
            "forms": forms,
            "findings": self.findings
        } 