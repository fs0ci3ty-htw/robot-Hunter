from scapy.all import *
from scapy.layers.http import *
from scapy.layers.dns import DNS
from typing import Dict, List, Optional
from urllib.parse import urlparse
import asyncio

class TrafficAnalyzer:
    def __init__(self, console_manager):
        self.console = console_manager
        self.requests = []
        self.responses = []
        self.websocket_messages = []
        self.console.log("Traffic Analyzer Initialized")

    async def setup(self, target_url: str):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)

    def start_capture(self, interface: str = None, timeout: int = 30):
        self.interface = interface
        self.timeout = timeout
        self.console.log(f"Starting capture on interface: {interface} for {timeout} seconds")

    def packet_callback(self, packet):
        if HTTPRequest in packet:
            self.analyze_http_packet(packet)
        elif TCP in packet:
            self.analyze_tcp_packet(packet)

    def analyze_http_packet(self, packet):
        http_layer = packet.getlayer(HTTPRequest)
        if http_layer:
            url = self.target_url + http_layer.fields['Path'].decode()
            method = http_layer.fields['Method'].decode()
            self.console.log(f"HTTP Request: {method} {url}")

    def analyze_tcp_packet(self, packet):
        # Basic TCP analysis
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        self.console.log(f"TCP Packet: Source Port {src_port}, Destination Port {dst_port}")

    async def capture_traffic(self, browser_context):
        """Captures traffic by attaching to the BrowserContext."""
        self.console.log("Capturing traffic from browser context...")

        def handle_request(request):
            self.requests.append({
                "url": request.url,
                "method": request.method,
                "headers": request.headers
            })
            self.console.log(f"Request: {request.method} {request.url}")

        def handle_response(response):
            self.responses.append({
                "url": response.url,
                "status": response.status,
                "headers": response.headers
            })
            self.console.log(f"Response: {response.status} {response.url}")

        def handle_request_failed(request):
            self.console.log(f"Request Failed: {request.url}")

        # Attach the handlers to the browser context
        browser_context.on("request", handle_request)
        browser_context.on("response", handle_response)
        browser_context.on("requestfailed", handle_request_failed)

        self.console.log("Traffic capture started.")

    def analyze_traffic(self):
        """Analyzes captured traffic and returns findings."""
        self.console.log("Analyzing captured traffic...")
        findings = []

        # Example analysis: Check for sensitive data in requests
        for request in self.requests:
            if "password" in request["url"].lower() or "api_key" in request["url"].lower():
                findings.append({
                    "type": "Sensitive Data in URL",
                    "url": request["url"],
                    "method": request["method"]
                })
                self.console.log(f"Sensitive data found in URL: {request['url']}")

        # Example analysis: Check for large responses
        for response in self.responses:
            if response["status"] >= 400:
                findings.append({
                    "type": "Error Response",
                    "url": response["url"],
                    "status": response["status"]
                })
                self.console.log(f"Error response: {response['status']} {response['url']}")

        self.console.log("Traffic analysis complete.")
        return findings

    def get_endpoints(self):
        """Extracts unique endpoints from captured traffic."""
        endpoints = set()
        for request in self.requests:
            endpoints.add(request["url"])
        return list(endpoints)
