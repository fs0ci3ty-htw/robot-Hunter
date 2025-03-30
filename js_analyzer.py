import jsbeautifier
import re
from typing import List, Dict

class JSAnalyzer:
    def __init__(self):
        # Patrones para buscar en el código
        self.patterns = {
            # Credenciales y claves
            "api_keys": r'(?i)(api[_-]?key|apikey|key|token|secret)["\']?\s*(?::|=)\s*["\']([^"\']+)["\']',
            "passwords": r'(?i)(password|passwd|pwd|pass)["\']?\s*(?::|=)\s*["\']([^"\']+)["\']',
            "credentials": r'(?i)(username|user|login|email)["\']?\s*(?::|=)\s*["\']([^"\']+)["\']',
            
            # Endpoints y URLs
            "endpoints": r'(?i)(url|endpoint|api|path)["\']?\s*(?::|=)\s*["\']([^"\']+)["\']',
            "internal_urls": r'(?i)(https?:)?//(?:localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|internal)\S+',
            
            # Parámetros potencialmente explotables
            "sql_params": r'(?i)(select|insert|update|delete|where|from)\s+.*?\?',
            "file_ops": r'(?i)(readFile|writeFile|appendFile|unlink|rmdir|mkdir)\s*\([^)]*\)',
            "dom_manipulation": r'(?i)(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)\s*\([^)]*\)',
            
            # Comentarios con información sensible
            "sensitive_comments": r'(?i)//.*?(todo|fixme|hack|note|password|key|token|bug)',
            
            # Variables y funciones sospechosas
            "debug_vars": r'(?i)(debug|test|dev|staging)["\']?\s*(?::|=)\s*(true|false)',
            "admin_routes": r'(?i)(admin|dashboard|manage|control)["\']?\s*(?::|=)\s*["\']([^"\']+)["\']',
            
            # Patrones para variables cortas y ofuscadas
            "short_vars": r'(?:var|let|const)\s+([a-z])\s*=',
            "single_char_methods": r'([a-z])\s*\.\s*([a-zA-Z_$][a-zA-Z0-9_$]*)',
            
            # Patrones para funciones y sus parámetros
            "function_params": r'function\s*(?:\w+)?\s*\((.*?)\)',
            "arrow_functions": r'=>\s*{([^}]*)}',
            
            # Patrones para bases de datos y almacenamiento
            "db_connections": r'(?i)(mongodb|mysql|postgresql|firebase|dynamodb|redis).*?["\']([^"\']+)["\']',
            "cloud_storage": r'(?i)(s3|blob|storage|bucket).*?["\']([^"\']+)["\']',
            
            # Patrones para APIs y endpoints
            "api_endpoints": r'(?i)(get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']',
            
            # Patrones para variables de entorno y configuración
            "env_vars": r'(?i)(process\.env|config|settings)\.[A-Z_]+',
        }

    async def extract_js_from_page(self, page) -> List[str]:
        # Extraer información de Webpack y otros empaquetadores
        webpack_modules = await page.evaluate("""
            () => {
                const results = {
                    webpack_modules: [],
                    source_maps: [],
                    chunk_info: []
                };
                
                // Buscar módulos de Webpack
                if (window.webpackJsonp) {
                    results.webpack_modules = Object.keys(window.webpackJsonp);
                }
                
                // Buscar source maps
                document.querySelectorAll('script').forEach(script => {
                    const sourceMap = script.getAttribute('sourceMappingURL');
                    if (sourceMap) {
                        results.source_maps.push({
                            url: sourceMap,
                            script: script.src || 'inline'
                        });
                    }
                });
                
                // Intentar extraer información de chunks
                if (window.webpackChunk) {
                    results.chunk_info = window.webpackChunk.map(chunk => ({
                        id: chunk.id,
                        files: chunk.files
                    }));
                }
                
                // Buscar variables globales comunes de empaquetadores
                const bundlerVars = [
                    '__webpack_require__',
                    '__webpack_modules__',
                    'webpackJsonp',
                    'require',
                    'define',
                    'module',
                    'exports'
                ].filter(v => window[v]);
                
                return {
                    ...results,
                    bundler_vars: bundlerVars,
                    global_vars: Object.keys(window).filter(k => 
                        k.includes('webpack') || 
                        k.includes('chunk') || 
                        k.includes('module') ||
                        k.includes('bundle')
                    )
                };
            }
        """)

        # Analizar console.logs y errores
        await page.evaluate("""
            (() => {
                const originalLog = console.log;
                const originalError = console.error;
                const logs = [];
                
                console.log = function(...args) {
                    logs.push({type: 'log', args: args});
                    originalLog.apply(console, args);
                };
                
                console.error = function(...args) {
                    logs.push({type: 'error', args: args});
                    originalError.apply(console, args);
                };
                
                window._interceptedLogs = logs;
            })()
        """)

        # Extraer información de módulos dinámicos
        dynamic_imports = await page.evaluate("""
            () => {
                const imports = [];
                const originalImport = window.import;
                
                window.import = function(module) {
                    imports.push(module);
                    return originalImport.apply(window, arguments);
                };
                
                return imports;
            }
        """)

        # Extraer scripts inline
        inline_scripts = await page.evaluate("""
            () => {
                const scripts = [];
                // Scripts normales
                document.querySelectorAll('script:not([src])').forEach(s => scripts.push(s.innerHTML));
                
                // Eventos inline
                document.querySelectorAll('*').forEach(el => {
                    for (let attr of el.attributes) {
                        if (attr.name.startsWith('on')) {
                            scripts.push(attr.value);
                        }
                    }
                });
                
                // Data attributes con JavaScript
                document.querySelectorAll('[data-js]').forEach(el => scripts.push(el.dataset.js));
                
                return scripts;
            }
        """)

        # Extraer scripts externos
        external_scripts = await page.evaluate("""
            () => {
                const scripts = [];
                // Scripts externos
                document.querySelectorAll('script[src]').forEach(s => scripts.push(s.src));
                
                // Links a JavaScript
                document.querySelectorAll('link[rel="javascript"]').forEach(l => scripts.push(l.href));
                
                return scripts;
            }
        """)

        # Extraer JavaScript de atributos HTML
        html_js = await page.evaluate("""
            () => {
                const results = [];
                // Buscar en atributos href="javascript:"
                document.querySelectorAll('[href^="javascript:"]').forEach(el => 
                    results.push(el.getAttribute('href')));
                
                // Buscar en otros atributos que puedan contener JS
                ['onclick', 'onload', 'onsubmit', 'onerror'].forEach(attr => {
                    document.querySelectorAll(`[${attr}]`).forEach(el => 
                        results.push(el.getAttribute(attr)));
                });
                
                return results;
            }
        """)

        return list(set(inline_scripts + external_scripts + html_js))

    def deobfuscate_js(self, js_code: str) -> str:
        try:
            # Desofuscación básica
            beautified = jsbeautifier.beautify(js_code)
            
            # Reemplazar nombres de variables ofuscados
            beautified = re.sub(r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)', 
                              lambda m: f"var {m.group(2)} = {m.group(2)}", beautified)
            
            # Descomponer arrays de strings
            beautified = re.sub(r'\[(.*?)\].join\(["\']\1["\']\)', 
                              lambda m: f'"{m.group(1)}"', beautified)
            
            return beautified
        except Exception as e:
            return f"Error en desofuscación: {str(e)}\nCódigo original: {js_code}"

    def find_suspicious_patterns(self, js_code: str) -> List[Dict]:
        findings = []
        
        # Buscar todos los patrones definidos
        for pattern_name, pattern in self.patterns.items():
            matches = re.finditer(pattern, js_code, re.MULTILINE)
            for match in matches:
                finding = {
                    "type": pattern_name,
                    "line": js_code[:match.start()].count('\n') + 1,
                    "match": match.group(0),
                    "context": js_code[max(0, match.start()-50):min(len(js_code), match.end()+50)].strip()
                }
                
                # Si hay grupos capturados, añadirlos al hallazgo
                if len(match.groups()) > 0:
                    finding["captured_values"] = match.groups()
                
                findings.append(finding)

        # Análisis adicional de funciones y variables
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*{'
        for match in re.finditer(function_pattern, js_code):
            func_name = match.group(1)
            if any(keyword in func_name.lower() for keyword in ['admin', 'token', 'key', 'password', 'auth', 'secret']):
                findings.append({
                    "type": "suspicious_function",
                    "line": js_code[:match.start()].count('\n') + 1,
                    "function_name": func_name,
                    "context": js_code[max(0, match.start()-50):min(len(js_code), match.end()+50)].strip()
                })

        return findings

    async def analyze_webpack(self, page) -> Dict:
        """Analizar específicamente módulos de Webpack"""
        return await page.evaluate("""
            () => {
                const analysis = {
                    entries: [],
                    chunks: [],
                    modules: [],
                    dependencies: []
                };
                
                // Buscar puntos de entrada
                if (window.webpackJsonp) {
                    analysis.entries = Object.keys(window.webpackJsonp);
                }
                
                // Analizar chunks cargados
                if (window.webpackChunk) {
                    analysis.chunks = window.webpackChunk.map(chunk => ({
                        id: chunk.id,
                        files: chunk.files,
                        loaded: true
                    }));
                }
                
                // Buscar módulos y dependencias
                if (window.__webpack_require__) {
                    const modules = window.__webpack_require__.m;
                    if (modules) {
                        analysis.modules = Object.keys(modules).map(id => ({
                            id,
                            source: modules[id].toString()
                        }));
                    }
                    
                    const cache = window.__webpack_require__.c;
                    if (cache) {
                        analysis.dependencies = Object.keys(cache).map(id => ({
                            id,
                            exports: Object.keys(cache[id].exports || {})
                        }));
                    }
                }
                
                return analysis;
            }
        """)

    def analyze_source_maps(self, source_map_content: str) -> Dict:
        """Analizar source maps para obtener información original"""
        try:
            import json
            data = json.loads(source_map_content)
            return {
                "sources": data.get("sources", []),
                "names": data.get("names", []),
                "mappings_sample": data.get("mappings", "")[:100],
                "file": data.get("file", ""),
                "source_root": data.get("sourceRoot", "")
            }
        except Exception as e:
            return {"error": str(e)}

    async def extract_and_analyze_js(self, page):
        # Configurar interceptación de debugger
        await page.evaluate("""
            (() => {
                // Interceptar todas las funciones cortas
                window.__functionCalls = [];
                window.__originalFunctions = {};
                
                // Función para interceptar llamadas
                function interceptFunction(obj, prop) {
                    if (typeof obj[prop] === 'function') {
                        const original = obj[prop];
                        window.__originalFunctions[prop] = original;
                        
                        obj[prop] = function(...args) {
                            window.__functionCalls.push({
                                name: prop,
                                args: args,
                                stack: new Error().stack,
                                timestamp: Date.now()
                            });
                            
                            try {
                                const result = original.apply(this, args);
                                if (result instanceof Promise) {
                                    return result.then(r => {
                                        window.__functionCalls[window.__functionCalls.length - 1].result = r;
                                        return r;
                                    });
                                }
                                window.__functionCalls[window.__functionCalls.length - 1].result = result;
                                return result;
                            } catch (error) {
                                window.__functionCalls[window.__functionCalls.length - 1].error = error.toString();
                                throw error;
                            }
                        };
                    }
                }
                
                // Interceptar variables cortas
                const shortVars = {};
                Object.defineProperty(window, '__shortVars', {
                    get: () => shortVars,
                    set: () => {}
                });
                
                // Observar cambios en el DOM
                const observer = new MutationObserver(mutations => {
                    mutations.forEach(mutation => {
                        if (mutation.type === 'childList') {
                            mutation.addedNodes.forEach(node => {
                                if (node.nodeType === 1) { // ELEMENT_NODE
                                    // Buscar scripts nuevos
                                    if (node.tagName === 'SCRIPT') {
                                        window.__functionCalls.push({
                                            type: 'script_added',
                                            content: node.textContent,
                                            src: node.src,
                                            timestamp: Date.now()
                                        });
                                    }
                                }
                            });
                        }
                    });
                });
                
                observer.observe(document.documentElement, {
                    childList: true,
                    subtree: true
                });
                
                // Interceptar eval y new Function
                const originalEval = window.eval;
                window.eval = function(code) {
                    window.__functionCalls.push({
                        type: 'eval',
                        code: code,
                        timestamp: Date.now()
                    });
                    return originalEval.call(this, code);
                };
                
                const originalFunction = window.Function;
                window.Function = function(...args) {
                    window.__functionCalls.push({
                        type: 'new_function',
                        args: args,
                        timestamp: Date.now()
                    });
                    return originalFunction.apply(this, args);
                };
                
                // Interceptar storage
                ['localStorage', 'sessionStorage'].forEach(storage => {
                    const original = window[storage];
                    ['setItem', 'getItem', 'removeItem'].forEach(method => {
                        const originalMethod = original[method];
                        original[method] = function(...args) {
                            window.__functionCalls.push({
                                type: 'storage',
                                storage: storage,
                                method: method,
                                args: args,
                                timestamp: Date.now()
                            });
                            return originalMethod.apply(this, args);
                        };
                    });
                });
            })();
        """)

        # Analizar el código JavaScript
        js_analysis = await page.evaluate("""
            () => {
                const analysis = {
                    shortVars: {},
                    functionCalls: window.__functionCalls,
                    originalFunctions: window.__originalFunctions,
                    storage: {},
                    apis: [],
                    dbConnections: []
                };
                
                // Analizar variables cortas
                for (let key in window) {
                    if (key.length === 1) {
                        analysis.shortVars[key] = {
                            type: typeof window[key],
                            value: window[key],
                            properties: Object.keys(window[key] || {})
                        };
                    }
                }
                
                // Buscar APIs y endpoints
                const urlPattern = /https?:\/\/[^\s/$.?#].[^\s]*/gi;
                document.documentElement.innerHTML.match(urlPattern)?.forEach(url => {
                    analysis.apis.push(url);
                });
                
                // Buscar conexiones a bases de datos
                const dbPattern = /(mongodb|mysql|postgresql|firebase|dynamodb):\/\/[^\s]+/gi;
                document.documentElement.innerHTML.match(dbPattern)?.forEach(db => {
                    analysis.dbConnections.push(db);
                });
                
                return analysis;
            }
        """)

        # Establecer breakpoints en funciones sospechosas
        await page.evaluate("""
            (() => {
                // Funciones que queremos debuggear
                const suspiciousPatterns = [
                    'eval', 'Function', 'fetch', 'XMLHttpRequest',
                    'WebSocket', 'localStorage', 'sessionStorage'
                ];
                
                suspiciousPatterns.forEach(pattern => {
                    if (window[pattern]) {
                        debugger;
                    }
                });
            })();
        """)

        return js_analysis

    def analyze_findings(self, js_analysis):
        findings = []
        
        # Analizar variables cortas
        for var_name, info in js_analysis.get("shortVars", {}).items():
            findings.append({
                "type": "short_variable",
                "name": var_name,
                "info": info,
                "risk": "high" if info["type"] in ["function", "object"] else "medium"
            })

        # Analizar llamadas a funciones
        for call in js_analysis.get("functionCalls", []):
            if call.get("type") == "eval" or call.get("type") == "new_function":
                findings.append({
                    "type": "dangerous_function",
                    "name": call["type"],
                    "args": call.get("args", []),
                    "risk": "critical"
                })

        # Analizar conexiones a bases de datos
        for db in js_analysis.get("dbConnections", []):
            findings.append({
                "type": "database_connection",
                "url": db,
                "risk": "high"
            })

        return findings
