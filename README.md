# Robot Hunter - Bug Bounty Scanner

Una herramienta automatizada para Bug Bounty que utiliza Playwright y mitmproxy para realizar análisis de seguridad en aplicaciones web.

## 🚀 Características

- Análisis automático de tráfico HTTP/HTTPS
- Desofuscación y análisis de JavaScript
- Detección de patrones sospechosos
- Pruebas de seguridad automatizadas
- Generación de reportes detallados

## 📋 Requisitos

- Python 3.8 o superior
- Linux (probado en Kali Linux)
- Certificado de mitmproxy instalado en el sistema

## 🛠️ Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/tu-usuario/robot-hunter.git
cd robot-hunter
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Instalar navegadores necesarios para Playwright:
```bash
playwright install
```

4. Instalar el certificado de mitmproxy:
```bash
mitmproxy
```
Sigue las instrucciones en pantalla para instalar el certificado en tu sistema.

## 🔧 Uso

Ejecutar el scanner con una URL objetivo:

```bash
python3 main.py https://ejemplo.com
```

El scanner realizará las siguientes tareas:
1. Cargar la página y capturar tráfico
2. Analizar JavaScript
3. Analizar tráfico de red
4. Ejecutar pruebas de seguridad
5. Generar reporte

## 📊 Reportes

El scanner genera dos tipos de reportes:
- `security_report.txt`: Reporte legible en formato texto
- `security_report.json`: Reporte detallado en formato JSON

Los reportes incluyen:
- Resumen de hallazgos por severidad
- Detalles de vulnerabilidades encontradas
- Contexto y evidencia de cada hallazgo

## 🔒 Seguridad

- Usa esta herramienta solo en sitios web que tengas permiso para probar
- No realices pruebas en producción sin autorización
- Mantén las credenciales y datos sensibles seguros

## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor:
1. Haz fork del repositorio
2. Crea una rama para tu feature
3. Haz commit de tus cambios
4. Push a la rama
5. Crea un Pull Request

## 📝 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## ⚠️ Descargo de Responsabilidad

Esta herramienta es solo para fines educativos y de investigación. El uso de esta herramienta para atacar sistemas sin autorización previa es ilegal. El autor no se hace responsable del uso indebido de esta herramienta. 