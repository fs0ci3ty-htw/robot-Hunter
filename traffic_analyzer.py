class TrafficAnalyzer:
    def __init__(self):
        self.requests = []
        self.responses = []
        self.websocket_messages = []

    async def capture_traffic(self, page):
        def handle_request(request):
            self.requests.append({
                "url": request.url,
                "method": request.method,
                "headers": request.headers,
                "post_data": request.post_data
            })

        def handle_response(response):
            try:
                self.responses.append({
                    "url": response.url,
                    "status": response.status,
                    "headers": response.headers,
                    "body": ""  # Se llenará después
                })
            except Exception as e:
                print(f"Error capturando respuesta: {e}")

        def handle_request_failed(request):
            self.requests.append({
                "url": request.url,
                "error": str(request.failure) if request.failure else "Unknown error"
            })

        # Registrar los manejadores de eventos
        page.on("request", handle_request)
        page.on("response", handle_response)
        page.on("requestfailed", handle_request_failed)

    def analyze_traffic(self):
        findings = []
        
        # Analizar datos sensibles en respuestas
        sensitive_keywords = ["API_KEY", "password", "TOKEN", "SECRET", "jwt", "auth"]
        for response in self.responses:
            if isinstance(response, dict):
                body = response.get("body", "")
                headers = response.get("headers", {})
                
                if isinstance(body, str):
                    for keyword in sensitive_keywords:
                        if keyword.lower() in body.lower():
                            findings.append(f"Dato sensible encontrado en {response['url']}: {keyword}")
                
                for header, value in headers.items():
                    if any(keyword.lower() in header.lower() for keyword in sensitive_keywords):
                        findings.append(f"Header sensible encontrado en {response['url']}: {header}")

        # Analizar endpoints internos
        internal_patterns = ["/api/", "/internal/", "/admin/", "/v1/", "/v2/"]
        for request in self.requests:
            if isinstance(request, dict):
                url = request.get("url", "")
                if isinstance(url, str):
                    if any(pattern in url.lower() for pattern in internal_patterns):
                        findings.append(f"Endpoint interno detectado: {url}")

        return findings

    def get_endpoints(self):
        endpoints = []
        for request in self.requests:
            if isinstance(request, dict):
                url = request.get("url", "")
                if isinstance(url, str):
                    if any(pattern in url.lower() for pattern in ["/api/", "/internal/", "/admin/", "/v1/", "/v2/"]):
                        endpoints.append(url)
        return endpoints
