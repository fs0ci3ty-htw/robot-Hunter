from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Modificar tráfico en tiempo real (ejemplo)
    if "api" in flow.request.url:
        flow.request.query["test"] = "modified"

def is_text_content(response):
    """Verificar si el contenido es texto legible"""
    content_type = response.headers.get("content-type", "")
    return any(text_type in content_type.lower() for text_type in [
        "text/",
        "application/json",
        "application/javascript",
        "application/xml",
        "application/x-www-form-urlencoded"
    ])

def response(flow: http.HTTPFlow) -> None:
    # Registrar respuestas solo si son texto
    if is_text_content(flow.response):
        with open("traffic_log.txt", "a", encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"URL: {flow.request.url}\n")
            f.write(f"Content-Type: {flow.response.headers.get('content-type', 'N/A')}\n")
            try:
                # Intentar decodificar como UTF-8
                text = flow.response.get_text()
                # Limitar la longitud del texto para evitar archivos muy grandes
                if len(text) > 1000:
                    text = text[:1000] + "...[truncado]"
                f.write(f"Response:\n{text}\n")
            except:
                f.write("Response: [Contenido no legible como texto]\n")
    else:
        # Para contenido no textual, solo registrar la metadata
        with open("traffic_log.txt", "a", encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"URL: {flow.request.url}\n")
            f.write(f"Content-Type: {flow.response.headers.get('content-type', 'N/A')}\n")
            f.write("Response: [Contenido binario]\n")
