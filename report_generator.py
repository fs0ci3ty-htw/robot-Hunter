from typing import Dict, List, Any
import json
from datetime import datetime
import threading
import subprocess
import os

class ReportGenerator:
    def __init__(self):
        self.findings = {}
        self.metadata = {
            "scan_date": datetime.now().isoformat(),
            "version": "1.0.0",
            "scan_name": "Security Scan",
            "scan_target": "",
            "scan_duration": 0,
            "scan_status": "initiated"
        }
        self.lock = threading.Lock()

    def add_findings(self, section: str, findings: List[Dict[str, Any]]) -> None:
        if findings:
            with self.lock:
                self.findings[section] = findings

    def set_scan_target(self, target: str) -> None:
        self.metadata["scan_target"] = target
    
    def set_scan_duration(self, duration: int) -> None:
        self.metadata["scan_duration"] = duration
        
    def set_scan_status(self, status: str) -> None:
        self.metadata["scan_status"] = status

    def generate_report(self, filename: str) -> None:
        report = {
            "metadata": self.metadata,
            "findings": self.findings,
            "summary": self._generate_summary()
        }

        # Generar reporte en formato JSON
        with open(f"{filename}.json", "w") as f:
            json.dump(report, f, indent=2)

        # Generar reporte en formato texto legible
        with open(filename, "w") as f:
            f.write(self._generate_text_report(report))

        print(f"Reporte generado en {filename} y {filename}.json")

    def _generate_summary(self) -> Dict[str, int]:
        summary = {
            "total_findings": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "by_type": {},
            "vulnerable_endpoints": [],
            "db_connections": [],
            "service_connections": []
        }

        for section, findings in self.findings.items():
            for finding in findings:
                summary["total_findings"] += 1
                
                # Contar por tipo
                finding_type = finding.get("type", "unknown")
                summary["by_type"][finding_type] = summary["by_type"].get(finding_type, 0) + 1
                
                # Contar por severidad
                severity = self._determine_severity(finding)
                summary["by_severity"][severity] += 1
                
                # Registrar endpoints vulnerables
                if "url" in finding or "endpoint" in finding:
                    endpoint = finding.get("url", finding.get("endpoint", ""))
                    if endpoint and endpoint not in summary["vulnerable_endpoints"]:
                        summary["vulnerable_endpoints"].append(endpoint)
                
                # Registrar conexiones a bases de datos
                if finding_type == "database_operation" or finding_type == "db_connection":
                    db_info = finding.get("database", "") or finding.get("name", "")
                    if db_info and db_info not in summary["db_connections"]:
                        summary["db_connections"].append(db_info)
                
                # Registrar conexiones a servicios
                if finding_type == "service_connection" and "url" in finding:
                    if finding["url"] not in summary["service_connections"]:
                        summary["service_connections"].append(finding["url"])

        return summary

    def _determine_severity(self, finding: Dict[str, Any]) -> str:
        # Priorizar la severidad explícitamente definida
        if "severity" in finding:
            severity = finding["severity"].lower()
            if severity in ["critical", "high", "medium", "low", "info"]:
                return severity
        
        # Tipos de vulnerabilidades críticas
        critical_types = [
            "sql_injection_vulnerability", 
            "command_injection_vulnerability",
            "form_injection_vulnerability",
            "var_modification_error"
        ]
        
        # Tipos de vulnerabilidades altas
        high_types = [
            "xss_vulnerability", 
            "path_traversal_vulnerability",
            "database_operation",
            "active_single_char_var",
            "db_connection"
        ]
        
        # Tipos de vulnerabilidades medias
        medium_types = [
            "sensitive_data", 
            "error_message",
            "service_connection",
            "suspicious_call_chain"
        ]
        
        finding_type = finding.get("type", "")
        
        if finding_type in critical_types:
            return "critical"
        elif finding_type in high_types:
            return "high"
        elif finding_type in medium_types:
            return "medium"
        elif finding_type.endswith("_error"):
            return "low"
        else:
            return "info"

    def _generate_text_report(self, report: Dict[str, Any]) -> str:
        text = []
        
        # Encabezado
        text.append("=" * 80)
        text.append("REPORTE DE VULNERABILIDADES")
        text.append("=" * 80)
        text.append(f"Fecha: {report['metadata']['scan_date']}")
        text.append(f"Versión: {report['metadata']['version']}")
        text.append("=" * 80)
        
        # Resumen
        text.append("\nRESUMEN")
        text.append("-" * 80)
        summary = report["summary"]
        text.append(f"Total de hallazgos: {summary['total_findings']}")
        text.append("\nPor severidad:")
        for severity, count in summary["by_severity"].items():
            text.append(f"- {severity.upper()}: {count}")
        text.append("\nPor tipo:")
        for finding_type, count in summary["by_type"].items():
            text.append(f"- {finding_type}: {count}")
        
        # Endpoints vulnerables
        if summary.get("vulnerable_endpoints"):
            text.append("\nEndpoints vulnerables:")
            for endpoint in summary["vulnerable_endpoints"]:
                text.append(f"- {endpoint}")
        
        # Conexiones a bases de datos
        if summary.get("db_connections"):
            text.append("\nConexiones a bases de datos:")
            for db in summary["db_connections"]:
                text.append(f"- {db}")
        
        # Conexiones a servicios
        if summary.get("service_connections"):
            text.append("\nConexiones a servicios:")
            for service in summary["service_connections"]:
                text.append(f"- {service}")
        
        # Hallazgos detallados, priorizando vulnerabilidades reales
        text.append("\nHALLAZGOS DETALLADOS")
        text.append("=" * 80)
        
        # Ordenar secciones para mostrar primero las más importantes
        priority_order = [
            "Advanced JS Analysis",
            "Security Tests", 
            "Site Exploration", 
            "Network Analysis", 
            "Traffic Analysis", 
            "JS Analysis"
        ]
        
        # Ordenar secciones según prioridad
        ordered_sections = sorted(
            report["findings"].keys(),
            key=lambda x: priority_order.index(x) if x in priority_order else 999
        )
        
        for section in ordered_sections:
            text.append(f"\n{section}")
            text.append("-" * 80)
            
            # Filtrar y ordenar hallazgos por severidad
            findings = report["findings"][section]
            findings_by_severity = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            }
            
            for finding in findings:
                severity = self._determine_severity(finding)
                findings_by_severity[severity].append(finding)
            
            # Mostrar hallazgos por severidad (de más alta a más baja)
            for severity in ["critical", "high", "medium", "low", "info"]:
                for finding in findings_by_severity[severity]:
                    if severity in ["info", "low"] and section in ["JS Analysis", "Traffic Analysis"]:
                        # Omitir hallazgos de baja severidad en análisis básicos para reducir ruido
                        continue
                    
                    text.append(f"\nTipo: {finding.get('type', 'N/A')}")
                    text.append(f"Severidad: {severity.upper()}")
                    
                    # Mostrar detalles específicos según el tipo de hallazgo
                    if "details" in finding:
                        text.append(f"Detalles: {finding['details']}")
                    
                    if "url" in finding:
                        text.append(f"URL: {finding['url']}")
                    elif "endpoint" in finding:
                        text.append(f"Endpoint: {finding['endpoint']}")
                    
                    if "method" in finding:
                        text.append(f"Método: {finding['method']}")
                    
                    if "payload" in finding:
                        text.append(f"Payload: {finding['payload']}")
                    
                    if "name" in finding:
                        text.append(f"Nombre: {finding['name']}")
                    
                    if "triggered_by" in finding:
                        text.append(f"Activado por: {finding['triggered_by']}")
                    
                    if "database" in finding:
                        text.append(f"Base de datos: {finding['database']}")
                    
                    if "error" in finding:
                        text.append(f"Error: {finding['error']}")
                    
                    if "context" in finding:
                        # Limitar el contexto para evitar sobrecarga de información
                        context = finding['context']
                        if isinstance(context, str) and len(context) > 100:
                            context = context[:100] + "..."
                        text.append(f"Contexto: {context}")
                    
                    text.append("-" * 40)
        
        return "\n".join(text)

    def handle_forbidden(self, url: str, threads: int = 5) -> Dict[str, Any]:
        """
        Maneja un código 403 iniciando un ataque con nomore403 en un hilo separado.
        
        Args:
            url: URL que devolvió el código 403
            threads: Número de hilos a utilizar para el ataque
            
        Returns:
            Diccionario con los resultados del ataque
        """
        result = {"status": "initiated", "url": url, "findings": []}
        
        def run_nomore403():
            try:
                # Construir el comando para nomore403
                cmd = [
                    "nomore403",
                    "-u", url,
                    "-m", str(threads),
                    "--random-agent",
                    "-v",
                    "-r",  # Seguir redirecciones
                    "-k", "headers,path-case,endpaths",  # Técnicas que pueden alarmar menos al WAF
                    "--timeout", "10000",
                    "--unique"
                ]
                
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
                                
                                # Añadir al reporte principal
                                if "Security Tests" not in self.findings:
                                    self.findings["Security Tests"] = []
                                self.findings["Security Tests"].append(finding)
                    else:
                        result["status"] = "failed"
                        result["error"] = stderr
            
            except Exception as e:
                with self.lock:
                    result["status"] = "error"
                    result["error"] = str(e)
        
        # Iniciar el proceso en un hilo separado
        thread = threading.Thread(target=run_nomore403)
        thread.daemon = True  # El hilo se cerrará cuando el programa principal termine
        thread.start()
        
        return result

    def handle_response_status(self, url: str, status_code: int) -> Dict[str, Any]:
        """
        Analiza el código de estado HTTP y toma acciones apropiadas
        
        Args:
            url: URL de la solicitud
            status_code: Código de estado HTTP recibido
            
        Returns:
            Diccionario con información sobre la acción tomada
        """
        result = {
            "url": url,
            "status_code": status_code,
            "action_taken": "none"
        }
        
        # Manejar código 403 (Forbidden)
        if status_code == 403:
            bypass_result = self.handle_forbidden(url)
            result["action_taken"] = "bypass_attempt"
            result["bypass_info"] = bypass_result
            
            # Registrar el intento en el reporte
            finding = {
                "type": "forbidden_access",
                "url": url,
                "details": "Se detectó acceso prohibido. Iniciando bypass automático.",
                "bypass_status": bypass_result["status"]
            }
            
            if "Security Tests" not in self.findings:
                self.findings["Security Tests"] = []
            self.findings["Security Tests"].append(finding)
        
        return result
