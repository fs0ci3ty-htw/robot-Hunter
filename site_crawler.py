import random
import asyncio
from typing import Set, Dict, List
from urllib.parse import urljoin, urlparse
import playwright.async_api as pw
from js_analyzer import JSAnalyzer
from attack_engine import AttackEngine
from datetime import datetime
from urllib.parse import parse_qs
from smart_detector import SmartDetector

class SmartCrawler:
    def __init__(self):
        self.visited_urls: Set[str] = set()
        self.visited_endpoints: Set[str] = set()
        self.search_terms = {
            "electronics": [
                "smartphone", "laptop", "headphones", "tablet", "smartwatch",
                "camera", "bluetooth speaker", "wireless earbuds"
            ],
            "fashion": [
                "shoes", "jacket", "dress", "jeans", "shirt",
                "backpack", "sunglasses", "watch"
            ],
            "sports": [
                "running shoes", "yoga mat", "gym bag", "fitness band",
                "sports bottle", "bicycle", "tennis racket"
            ],
            "home": [
                "chair", "lamp", "coffee maker", "pillow", "blanket",
                "desk", "mirror", "curtains"
            ],
            "general": [
                "book", "gift", "sale", "new", "popular",
                "recommended", "best seller"
            ]
        }
        self.max_depth = 3
        self.requests_per_minute = 20
        self.js_analyzer = JSAnalyzer()
        self.attack_engine = AttackEngine()
        
        # Rastrear estados para evitar bucles
        self.button_clicks: Dict[str, int] = {}
        self.form_submissions: Dict[str, int] = {}
        
        # Control de búsquedas para evitar repeticiones
        self.used_terms: Set[str] = set()
        self.searches_per_page = 2  # Límite de búsquedas por página
        
        self.findings = []
        self.current_analysis = {
            'clicks': [],
            'forms': [],
            'endpoints': [],
            'js_vars': [],
            'network_requests': [],
            'dom_changes': []
        }
        
        # Patrones comunes de elementos interactivos
        self.interactive_patterns = {
            'buy_buttons': [
                # Textos comunes
                '[text*="comprar" i]',
                '[text*="buy" i]',
                '[text*="add to cart" i]',
                '[text*="agregar al carrito" i]',
                '[text*="checkout" i]',
                # Clases comunes
                '[class*="buy" i]',
                '[class*="add-to-cart" i]',
                '[class*="purchase" i]',
                '[class*="comprar" i]',
                # IDs comunes
                '[id*="buy" i]',
                '[id*="cart" i]',
                '[id*="checkout" i]',
                # Atributos aria
                '[aria-label*="comprar" i]',
                '[aria-label*="buy" i]',
                '[role="button"]'
            ],
            'product_cards': [
                '[class*="product" i]',
                '[class*="item" i]',
                '[class*="card" i]',
                '[class*="producto" i]',
                '[data-type="product"]',
                'article',
                '.product-container',
                '.item-container'
            ],
            'navigation': [
                'nav a',
                '[class*="menu-item" i]',
                '[class*="nav-link" i]',
                '.pagination a'
            ]
        }
        
        self.detector = SmartDetector()
        
    async def start_crawl(self, initial_url: str):
        async with pw.async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            
            # Interceptar peticiones de red
            await context.route("**/*", self.handle_route)
            
            page = await context.new_page()
            await self.crawl_page(page, initial_url, depth=0)
            await browser.close()

    async def handle_route(self, route: pw.Route):
        request = route.request
        
        # Registrar endpoint
        if request.method != "GET":
            self.visited_endpoints.add(f"{request.method} {request.url}")
            
        # Continuar con la petición
        await route.continue_()
        
        # Analizar respuesta para detectar vulnerabilidades
        response = await route.request.response()
        if response:
            await self.analyze_response(response)

    async def crawl_page(self, page: pw.Page, url: str, depth: int):
        if depth >= self.max_depth or url in self.visited_urls:
            return
            
        print(f"Explorando: {url} (profundidad: {depth})")
        self.visited_urls.add(url)
        
        try:
            # Configurar interceptación de red
            await page.route("**/*", self.analyze_network_request)
            
            # Navegar a la página
            await page.goto(url, wait_until="networkidle", timeout=60000)
            
            # Analizar JavaScript inicial
            await self.analyze_js_variables(page)
            
            # Simular scroll natural
            await self.natural_scroll(page)
            
            # Utilizar el detector inteligente
            interactive_elements = await self.detector.detect_interactive_elements(page)
            print(f"Detectados {len(interactive_elements)} elementos interactivos")
            
            for element in interactive_elements[:10]:  # Limitar a 10 por página
                try:
                    print(f"Interactuando con: {element['tag']} - {element['text']}")
                    
                    # Estado antes de la interacción
                    pre_state = await self.capture_page_state(page)
                    
                    # Interactuar con el elemento
                    element_handle = element['element']
                    await element_handle.click()
                    
                    # Esperar a que se cargue la página
                    await page.wait_for_load_state("networkidle")
                    
                    # Estado después de la interacción
                    post_state = await self.capture_page_state(page)
                    
                    # Analizar cambios y registrar
                    changes = self.analyze_state_changes(pre_state, post_state)
                    if changes:
                        await self.record_finding(
                            'interactive_element',
                            'INFO',
                            {
                                'element': f"{element['tag']} - {element['text']}",
                                'changes': changes
                            }
                        )
                except Exception as e:
                    print(f"Error interactuando con elemento: {str(e)}")
            
            # Detectar formularios incluso sin etiqueta form
            forms = await self.detector.detect_forms(page)
            print(f"Detectados {len(forms)} formularios/grupos de entrada")
            
            for form in forms:
                try:
                    print(f"Probando formulario: {form['type']}")
                    await self.handle_form_submission(page, form)
                except Exception as e:
                    print(f"Error en formulario: {str(e)}")
            
            # Realizar búsquedas naturales
            await self.handle_search_forms(page)
            
            # Recopilar y analizar nuevos enlaces
            new_urls = await self.gather_links(page, url)
            
            # Generar reporte parcial
            await self.generate_security_report()
            
            # Explorar nuevos enlaces
            for new_url in new_urls:
                if new_url not in self.visited_urls:
                    await self.crawl_page(page, new_url, depth + 1)
            
        except Exception as e:
            print(f"Error explorando {url}: {str(e)}")

    async def handle_search_forms(self, page: pw.Page):
        # Encontrar campos de búsqueda
        search_inputs = await page.query_selector_all('''
            input[type="search"],
            input[type="text"][id*="search" i],
            input[type="text"][name*="search" i],
            input[type="text"][placeholder*="search" i],
            input[type="text"][class*="search" i]
        ''')
        
        searches_done = 0
        
        for input in search_inputs:
            try:
                if searches_done >= self.searches_per_page:
                    break
                    
                # Verificar si el input es visible y utilizable
                if await input.is_visible():
                    # Obtener un término de búsqueda natural
                    search_term = await self.get_next_search_term()
                    
                    print(f"Realizando búsqueda con término: {search_term}")
                    
                    # Simular comportamiento humano
                    await input.click()
                    await asyncio.sleep(0.5)  # Pequeña pausa antes de escribir
                    await input.fill("")
                    await input.type(search_term, delay=random.randint(100, 200))
                    
                    # Esperar un momento antes de enviar (como haría un humano)
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    
                    # Buscar y usar el botón de búsqueda
                    form = await input.evaluate('el => el.closest("form")')
                    if form:
                        submit_button = await page.query_selector('button[type="submit"], input[type="submit"]')
                        if submit_button:
                            await submit_button.click()
                            await page.wait_for_load_state("networkidle")
                            
                            # Analizar resultados
                            await self.js_analyzer.extract_and_analyze_js(page)
                            
                            # Esperar entre búsquedas
                            await asyncio.sleep(random.uniform(2, 4))
                            
                            searches_done += 1
                            
            except Exception as e:
                print(f"Error en búsqueda: {str(e)}")
                continue

    async def analyze_search_results(self, page: pw.Page):
        """
        Analiza los resultados de búsqueda para comportamiento más natural
        """
        try:
            # Buscar elementos de producto/resultado
            results = await page.query_selector_all(
                '[class*="product" i], [class*="result" i], [class*="item" i]'
            )
            
            if results:
                # Seleccionar un resultado aleatorio para simular interés
                result = random.choice(results)
                if await result.is_visible():
                    # Scroll hasta el elemento
                    await result.scroll_into_view_if_needed()
                    await asyncio.sleep(random.uniform(1, 2))
                    
                    # Probabilidad de hacer clic (70%)
                    if random.random() < 0.7:
                        await result.click()
                        await page.wait_for_load_state("networkidle")
                        await self.js_analyzer.extract_and_analyze_js(page)
                        
                        # Regresar después de ver el detalle
                        await page.go_back()
                        await page.wait_for_load_state("networkidle")
        
        except Exception as e:
            print(f"Error analizando resultados: {str(e)}")

    async def click_buttons(self, page: pw.Page):
        buttons = await page.query_selector_all("button, a.btn, input[type='button']")
        
        for button in buttons:
            try:
                # Obtener identificador único para el botón
                button_id = await self.get_element_identifier(button)
                
                # Evitar clics repetitivos
                if self.button_clicks.get(button_id, 0) >= 2:
                    continue
                
                if await button.is_visible():
                    # Registrar clic
                    self.button_clicks[button_id] = self.button_clicks.get(button_id, 0) + 1
                    
                    # Hacer clic y esperar cambios
                    await button.click()
                    await page.wait_for_load_state("networkidle")
                    
                    # Analizar nueva página/estado
                    await self.js_analyzer.extract_and_analyze_js(page)
                    
            except Exception as e:
                print(f"Error al hacer clic en botón: {str(e)}")

    async def analyze_auth_forms(self, page: pw.Page):
        # Detectar formularios de login/registro
        auth_forms = await page.query_selector_all('form:has(input[type="password"])')
        
        for form in auth_forms:
            try:
                # Obtener endpoint del formulario
                action = await form.get_attribute('action')
                if action:
                    full_url = urljoin(page.url, action)
                    print(f"Detectado endpoint de autenticación: {full_url}")
                    
                    # Intentar ataques básicos
                    await self.attack_engine.test_sql_injection(full_url)
                    await self.attack_engine.test_nosql_injection(full_url)
                    
            except Exception as e:
                print(f"Error analizando formulario de autenticación: {str(e)}")

    async def gather_links(self, page: pw.Page, base_url: str) -> List[str]:
        base_domain = urlparse(base_url).netloc
        links = []
        
        # Encontrar todos los enlaces en la página
        elements = await page.query_selector_all('a[href]')
        
        for element in elements:
            try:
                href = await element.get_attribute('href')
                if href:
                    full_url = urljoin(base_url, href)
                    parsed_url = urlparse(full_url)
                    
                    # Solo incluir URLs del mismo dominio
                    if parsed_url.netloc == base_domain:
                        links.append(full_url)
            except Exception:
                continue
                
        return list(set(links))  # Eliminar duplicados

    async def get_element_identifier(self, element) -> str:
        """Genera un identificador único para un elemento."""
        props = ['id', 'name', 'class', 'type']
        identifier_parts = []
        
        for prop in props:
            value = await element.get_attribute(prop)
            if value:
                identifier_parts.append(f"{prop}={value}")
                
        text = await element.text_content()
        if text:
            identifier_parts.append(f"text={text.strip()}")
            
        return "|".join(identifier_parts) or "unknown"

    async def analyze_response(self, response: pw.Response):
        try:
            # Analizar headers
            headers = response.headers
            
            # Analizar body si es JSON
            if "application/json" in response.headers.get("content-type", ""):
                body = await response.json()
                # Aquí podrías buscar patrones interesantes en la respuesta
                
            # Registrar códigos de estado no comunes
            if response.status not in [200, 301, 302, 304]:
                print(f"Código de estado inusual: {response.status} en {response.url}")
                
        except Exception as e:
            print(f"Error analizando respuesta: {str(e)}") 

    async def get_next_search_term(self) -> str:
        """
        Obtiene un término de búsqueda aleatorio pero natural,
        evitando repeticiones hasta que se hayan usado todos
        """
        # Aplanar todas las categorías si no hay términos disponibles
        if len(self.used_terms) >= sum(len(terms) for terms in self.search_terms.values()):
            self.used_terms.clear()

        while True:
            # Seleccionar categoría aleatoria
            category = random.choice(list(self.search_terms.keys()))
            # Seleccionar término aleatorio de esa categoría
            term = random.choice(self.search_terms[category])
            
            if term not in self.used_terms:
                self.used_terms.add(term)
                return term

    async def natural_scroll(self, page: pw.Page):
        """
        Simula un comportamiento de scroll más natural
        """
        try:
            # Obtener altura de la página
            height = await page.evaluate('document.documentElement.scrollHeight')
            
            # Realizar scroll gradual
            current = 0
            while current < height:
                scroll_amount = random.randint(100, 300)
                await page.evaluate(f'window.scrollBy(0, {scroll_amount})')
                current += scroll_amount
                await asyncio.sleep(random.uniform(0.5, 1.5))
                
            # Probabilidad de scroll hacia arriba
            if random.random() < 0.3:
                await page.evaluate('window.scrollTo(0, 0)')
                await asyncio.sleep(random.uniform(1, 2))
                
        except Exception as e:
            print(f"Error en scroll natural: {str(e)}") 

    async def record_finding(self, finding_type: str, severity: str, details: dict):
        self.findings.append({
            'type': finding_type,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'details': details
        })

    async def analyze_element_behavior(self, page: pw.Page, element, context: str):
        """Analiza el comportamiento de un elemento antes y después de interactuar"""
        try:
            # Capturar estado inicial
            initial_state = await self.capture_page_state(page)
            
            # Interactuar con el elemento
            await element.click()
            await page.wait_for_load_state("networkidle")
            
            # Capturar estado después de la interacción
            final_state = await self.capture_page_state(page)
            
            # Analizar cambios
            changes = await self.analyze_state_changes(initial_state, final_state)
            
            if changes:
                await self.record_finding(
                    'element_interaction',
                    'INFO',
                    {
                        'context': context,
                        'changes': changes,
                        'element': await self.get_element_identifier(element)
                    }
                )
                
        except Exception as e:
            print(f"Error analyzing element behavior: {str(e)}")

    async def capture_page_state(self, page: pw.Page):
        """Captura el estado actual de la página"""
        return await page.evaluate("""
            () => {
                return {
                    url: window.location.href,
                    localStorage: {...localStorage},
                    sessionStorage: {...sessionStorage},
                    cookies: document.cookie,
                    forms: Array.from(document.forms).map(f => ({
                        action: f.action,
                        method: f.method,
                        inputs: Array.from(f.elements).map(e => ({
                            name: e.name,
                            type: e.type,
                            value: e.type === 'password' ? null : e.value
                        }))
                    })),
                    networkRequests: window.performance.getEntriesByType('resource'),
                    globals: Object.keys(window),
                    domSnapshot: document.documentElement.outerHTML
                }
            }
        """)

    async def analyze_network_request(self, request: pw.Request):
        """Analiza cada petición de red"""
        try:
            url = request.url
            method = request.method
            headers = request.headers
            post_data = request.post_data
            
            # Analizar parámetros de URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            if query_params:
                await self.record_finding(
                    'url_parameters',
                    'INFO',
                    {
                        'url': url,
                        'params': query_params
                    }
                )
            
            # Analizar datos POST
            if method == "POST" and post_data:
                await self.record_finding(
                    'post_data',
                    'INFO',
                    {
                        'url': url,
                        'data': post_data
                    }
                )
                
            # Analizar headers interesantes
            sensitive_headers = ['authorization', 'x-api-key', 'token']
            for header in sensitive_headers:
                if header in headers:
                    await self.record_finding(
                        'sensitive_header',
                        'MEDIUM',
                        {
                            'url': url,
                            'header': header
                        }
                    )
                    
        except Exception as e:
            print(f"Error analyzing network request: {str(e)}")

    async def analyze_js_variables(self, page: pw.Page):
        """Analiza variables y funciones JavaScript"""
        js_analysis = await page.evaluate("""
            () => {
                const analysis = {
                    shortVars: {},
                    functions: {},
                    eventListeners: [],
                    globals: {}
                };
                
                // Analizar variables globales
                for (let key in window) {
                    const value = window[key];
                    if (key.length === 1) {
                        analysis.shortVars[key] = {
                            type: typeof value,
                            properties: Object.keys(value || {})
                        };
                    }
                    
                    if (typeof value === 'function') {
                        analysis.functions[key] = {
                            args: value.toString().match(/\\((.*?)\\)/)[1].split(','),
                            body: value.toString()
                        };
                    }
                }
                
                // Capturar event listeners
                const elements = document.querySelectorAll('*');
                elements.forEach(el => {
                    const listeners = getEventListeners(el);
                    if (Object.keys(listeners).length > 0) {
                        analysis.eventListeners.push({
                            element: el.tagName,
                            id: el.id,
                            class: el.className,
                            listeners: listeners
                        });
                    }
                });
                
                return analysis;
            }
        """)
        
        # Registrar hallazgos del análisis JS
        if js_analysis['shortVars']:
            await self.record_finding(
                'js_short_vars',
                'INFO',
                {'variables': js_analysis['shortVars']}
            )
            
        if js_analysis['functions']:
            await self.record_finding(
                'js_functions',
                'INFO',
                {'functions': js_analysis['functions']}
            )
            
        if js_analysis['eventListeners']:
            await self.record_finding(
                'event_listeners',
                'INFO',
                {'listeners': js_analysis['eventListeners']}
            )

    async def handle_form_submission(self, page: pw.Page, form):
        """Analiza y prueba formularios"""
        try:
            # Identificar tipo de formulario
            form_type = await self.identify_form_type(form)
            
            # Capturar campos y valores originales
            original_values = await self.capture_form_values(form)
            
            # Probar diferentes inputs basados en el tipo
            test_cases = self.get_test_cases(form_type)
            
            for test_case in test_cases:
                # Restaurar valores originales
                await self.restore_form_values(form, original_values)
                
                # Aplicar caso de prueba
                await self.fill_form_test_case(form, test_case)
                
                # Capturar y analizar respuesta
                response = await self.submit_and_analyze(page, form)
                
                if response:
                    await self.record_finding(
                        'form_test',
                        'INFO',
                        {
                            'form_type': form_type,
                            'test_case': test_case,
                            'response': response
                        }
                    )
                    
        except Exception as e:
            print(f"Error handling form submission: {str(e)}")

    async def generate_security_report(self):
        """Genera el reporte de seguridad con todos los hallazgos"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'findings_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0
            },
            'findings_by_type': {},
            'detailed_findings': self.findings
        }
        
        # Contar hallazgos por severidad y tipo
        for finding in self.findings:
            report['findings_by_severity'][finding['severity']] += 1
            
            finding_type = finding['type']
            if finding_type not in report['findings_by_type']:
                report['findings_by_type'][finding_type] = 0
            report['findings_by_type'][finding_type] += 1
        
        return report 

    async def find_interactive_elements(self, page: pw.Page):
        """Encuentra elementos interactivos usando múltiples estrategias"""
        elements = []
        
        # 1. Búsqueda por selectores específicos
        for category, patterns in self.interactive_patterns.items():
            for pattern in patterns:
                elements.extend(await page.query_selector_all(pattern))

        # 2. Búsqueda por comportamiento
        clickable_elements = await page.evaluate("""
            () => {
                const elements = [];
                document.querySelectorAll('*').forEach(el => {
                    const style = window.getComputedStyle(el);
                    if (
                        (style.cursor === 'pointer' || 
                         el.onclick || 
                         el.addEventListener || 
                         el.hasAttribute('click')) &&
                        style.display !== 'none' &&
                        style.visibility !== 'hidden'
                    ) {
                        elements.push(el);
                    }
                });
                return elements;
            }
        """)
        elements.extend(clickable_elements)

        # 3. Análisis visual para detectar elementos que parecen botones
        visual_elements = await page.evaluate("""
            () => {
                return Array.from(document.querySelectorAll('*')).filter(el => {
                    const style = window.getComputedStyle(el);
                    return (
                        style.backgroundColor !== 'transparent' &&
                        style.border !== 'none' &&
                        style.padding !== '0px' &&
                        el.offsetWidth > 20 &&
                        el.offsetHeight > 20 &&
                        el.textContent.trim().length > 0
                    );
                });
            }
        """)
        elements.extend(visual_elements)

        return list(set(elements))  # Eliminar duplicados

    async def analyze_product_page(self, page: pw.Page):
        """Análisis específico para páginas de productos"""
        try:
            # Detectar precio
            price_patterns = [
                '[class*="price" i]',
                '[class*="precio" i]',
                '[itemprop="price"]',
                r'span:has-text(/[$€]\s*\d+/)'
            ]
            
            # Detectar botones de compra
            buy_buttons = await page.query_selector_all(
                ', '.join(self.interactive_patterns['buy_buttons'])
            )
            
            for button in buy_buttons:
                if await button.is_visible():
                    # Analizar estado antes de clic
                    pre_click_state = await self.capture_page_state(page)
                    
                    # Clic en el botón
                    await button.click()
                    await page.wait_for_load_state("networkidle")
                    
                    # Analizar cambios
                    post_click_state = await self.capture_page_state(page)
                    changes = await self.analyze_state_changes(pre_click_state, post_click_state)
                    
                    await self.record_finding(
                        'buy_button_interaction',
                        'INFO',
                        {
                            'button_text': await button.text_content(),
                            'changes': changes,
                            'url': page.url
                        }
                    )
                    
        except Exception as e:
            print(f"Error analyzing product page: {str(e)}")

    async def analyze_product_listing(self, page: pw.Page):
        """Análisis de listados de productos"""
        try:
            products = await page.query_selector_all(
                ', '.join(self.interactive_patterns['product_cards'])
            )
            
            for product in products:
                if await product.is_visible():
                    # Extraer información del producto
                    product_info = await self.extract_product_info(product)
                    
                    # Buscar elementos interactivos dentro del producto
                    interactive_elements = await product.query_selector_all(
                        'a, button, [role="button"], [class*="btn"]'
                    )
                    
                    for element in interactive_elements:
                        await self.analyze_element_behavior(page, element, 'product_interaction')
                        
        except Exception as e:
            print(f"Error analyzing product listing: {str(e)}") 