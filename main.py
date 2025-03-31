import asyncio
import sys
import os
import subprocess
import signal
from typing import Optional
from playwright.async_api import async_playwright, Browser, Page
from traffic_analyzer import TrafficAnalyzer
from js_analyzer import JSAnalyzer
from attack_engine import AttackEngine
from report_generator import ReportGenerator
from network_analyzer import NetworkAnalyzer
from advanced_js_analyzer import AdvancedJSAnalyzer
from site_crawler import SmartCrawler
import shutil

class BugBountyScanner:
    def __init__(self, url: str):
        self.url = url
        self.traffic_analyzer = TrafficAnalyzer()
        self.js_analyzer = JSAnalyzer()
        self.advanced_js_analyzer = AdvancedJSAnalyzer()
        self.attack_engine = AttackEngine()
        self.report_generator = ReportGenerator()
        self.mitm_process: Optional[subprocess.Popen] = None
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        self.playwright = None
        self.proxy_port = 8082
        self.network_analyzer = NetworkAnalyzer()
        self.crawler = SmartCrawler()

    async def setup(self):
        """Inicializar el entorno de escaneo"""
        try:
            # Verificar herramientas
            await self.setup_tools()
            
            # Usar mitmdump con configuración más permisiva
            print("Iniciando mitmdump...")
            self.mitm_process = subprocess.Popen(
                ["mitmdump", 
                 "--listen-port", str(self.proxy_port),
                 "--mode", "regular",
                 "--ssl-insecure",  # Ignorar errores SSL
                 "--set", "block_global=false",  # Permitir todas las conexiones
                 "--set", "connection_strategy=eager",  # Estrategia de conexión más agresiva
                 "--quiet",
                 "-s", "mitm_script.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Dar más tiempo a que mitmdump inicie completamente
            print(f"Esperando que mitmdump inicie en puerto {self.proxy_port}...")
            await asyncio.sleep(10)
            
            # Verificar que mitmdump está ejecutándose
            if self.mitm_process.poll() is not None:
                stderr = self.mitm_process.stderr.read().decode()
                raise Exception(f"No se pudo iniciar mitmdump. Error: {stderr}")
            
            print("Iniciando navegador...")
            self.playwright = await async_playwright().start()
            
            # Configuración más permisiva del navegador
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                proxy={
                    "server": f"http://127.0.0.1:{self.proxy_port}",
                    "bypass": "localhost,127.0.0.1"
                },
                args=[
                    '--ignore-certificate-errors',
                    '--disable-web-security',
                    '--allow-insecure-localhost',
                    '--disable-gpu',
                    '--no-sandbox'
                ]
            )
            
            # Configurar el contexto con más opciones de seguridad
            context = await self.browser.new_context(
                ignore_https_errors=True,
                bypass_csp=True,  # Bypass Content Security Policy
                java_script_enabled=True
            )
            
            self.page = await context.new_page()
            
            # Aumentar timeouts
            self.page.set_default_navigation_timeout(60000)  # 60 segundos
            self.page.set_default_timeout(60000)
            
            # Mejorar el logging de errores
            self.page.on("pageerror", lambda err: print(f"Error en página: {err}"))
            self.page.on("console", lambda msg: print(f"Consola: {msg.text}"))
            self.page.on("request", lambda req: print(f"Petición: {req.method} {req.url}"))
            self.page.on("response", lambda res: print(f"Respuesta: {res.status} {res.url}"))
            
            print("Configuración completada exitosamente")
            
        except Exception as e:
            print(f"Error detallado durante la inicialización: {str(e)}")
            if self.mitm_process:
                stderr = self.mitm_process.stderr.read().decode()
                print(f"Error de mitmdump: {stderr}")
            await self.cleanup()
            raise

    async def setup_tools(self):
        """Configurar y verificar herramientas necesarias"""
        tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Tools")
        
        # Crear directorio de Tools si no existe
        if not os.path.exists(tools_dir):
            os.makedirs(tools_dir)
            print(f"Creado directorio Tools en: {tools_dir}")
        
        # Lista de herramientas requeridas
        required_tools = [
            "mitmdump",
            "nomore403"
        ]
        
        # Verificar cada herramienta
        missing_tools = []
        for tool in required_tools:
            global_path = shutil.which(tool)
            local_path = os.path.join(tools_dir, tool)
            
            if global_path:
                print(f"✅ {tool} encontrado globalmente: {global_path}")
            elif os.path.isfile(local_path) and os.access(local_path, os.X_OK):
                print(f"✅ {tool} encontrado en Tools/: {local_path}")
            else:
                print(f"❌ {tool} no encontrado")
                missing_tools.append(tool)
        
        # Sugerir instalación para herramientas faltantes
        if missing_tools:
            print("\nAlgunas herramientas necesarias no están disponibles:")
            for tool in missing_tools:
                if tool == "mitmdump":
                    print("  - mitmdump: Instalar con 'pip install mitmproxy'")
                elif tool == "nomore403":
                    print("  - nomore403: Instalar con:")
                    print("    mkdir -p Tools && cd Tools")
                    print("    git clone https://github.com/devploit/nomore403")
                    print("    cd nomore403")
                    print("    go build")

    async def scan(self):
        """Ejecutar el escaneo completo"""
        try:
            print(f"Iniciando escaneo de {self.url}")
            
            # 1️⃣ Cargar página y capturar tráfico
            print("1. Cargando página y capturando tráfico...")
            await self.page.goto(self.url)
            await self.traffic_analyzer.capture_traffic(self.page)
            
            # 2️⃣ Configurar y ejecutar el analizador avanzado de JS
            print("2. Ejecutando análisis avanzado de JavaScript...")
            await self.advanced_js_analyzer.setup_debugger(self.page)
            analyzer = AdvancedJSAnalyzer()
            results = await analyzer.run_analysis_with_retry(self.page)
            self.report_generator.add_findings("Advanced JS Analysis", results["findings"])
            
            # 3️⃣ Extraer y analizar JavaScript tradicional
            print("3. Analizando JavaScript...")
            js_files = await self.js_analyzer.extract_js_from_page(self.page)
            for js_file in js_files:
                clean_code = self.js_analyzer.deobfuscate_js(js_file)
                suspicious_patterns = self.js_analyzer.find_suspicious_patterns(clean_code)
                self.report_generator.add_findings("JS Analysis", suspicious_patterns)
            
            # 4️⃣ Analizar tráfico
            print("4. Analizando tráfico de red...")
            traffic_findings = self.traffic_analyzer.analyze_traffic()
            self.report_generator.add_findings("Traffic Analysis", traffic_findings)
            
            # 5️⃣ Ejecutar el crawler inteligente para explorar el sitio
            print("5. Ejecutando exploración del sitio...")
            await self.crawler.start_crawl(self.url)
            crawler_findings = self.crawler.findings
            self.report_generator.add_findings("Site Exploration", crawler_findings)
            
            # 6️⃣ Ejecutar ataques de prueba
            print("6. Ejecutando pruebas de seguridad...")
            endpoints = self.traffic_analyzer.get_endpoints()
            attack_results = await self.attack_engine.run_attacks(self.page, endpoints)
            self.report_generator.add_findings("Security Tests", attack_results)
            
            # 7️⃣ Analizar red con Scapy
            print("7. Analizando red con Scapy...")
            await self.network_analyzer.setup(self.url)
            self.network_analyzer.start_capture(timeout=30)  # Captura durante 30 segundos
            network_findings = self.network_analyzer.get_findings()
            self.report_generator.add_findings("Network Analysis", network_findings)
            
            # 8️⃣ Generar reporte
            print("8. Generando reporte...")
            self.report_generator.generate_report("security_report")
            
            print("Escaneo completado exitosamente!")
            
        except Exception as e:
            print(f"Error durante el escaneo: {str(e)}")
            raise
        finally:
            await self.cleanup()

    async def cleanup(self):
        """Limpiar recursos"""
        try:
            if self.page:
                await self.page.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            if self.mitm_process:
                self.mitm_process.terminate()
                try:
                    self.mitm_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.mitm_process.kill()
        except Exception as e:
            print(f"Error durante la limpieza: {str(e)}")

def signal_handler(signum, frame):
    """Manejar señales de terminación"""
    print("\nRecibida señal de terminación. Limpiando...")
    sys.exit(0)

async def main(url: str):
    # Validar y corregir la URL
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    # Verificación más estricta de la URL
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if not parsed.netloc or '.' not in parsed.netloc:
            raise ValueError("URL inválida")
    except Exception as e:
        print(f"Error: URL inválida ({str(e)})")
        print("Ejemplo de formato correcto: example.com o https://example.com")
        sys.exit(1)
    
    # Registrar manejador de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    scanner = BugBountyScanner(url)
    try:
        print(f"Iniciando escaneo de {url}")
        await scanner.setup()
        await scanner.setup_tools()
        await scanner.scan()
    except Exception as e:
        print(f"Error fatal: {str(e)}")
        await scanner.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 main.py <URL>")
        print("Ejemplo: python3 main.py example.com")
        print("        python3 main.py https://example.com")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(main(url))
