# ForenseCTL - Framework de Análisis Forense Digital

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Status](https://img.shields.io/badge/status-Production%20Ready-green.svg)](https://github.com/ismaiars/ForenseCTL)

## 🔍 Descripción

ForenseCTL es un framework completo de análisis forense digital diseñado para profesionales de ciberseguridad, equipos DFIR y analistas forenses. Proporciona un ciclo completo de investigación: **recopilación → análisis → reporte → cadena de custodia**.

## ✨ Características Principales

- 📁 **Gestión Completa de Casos**: Creación, administración y seguimiento de casos forenses
- 🔍 **Recopilación Automática**: Extracción de artefactos del sistema (procesos, archivos, registro, red)
- ⚙️ **Análisis Forense Avanzado**: Análisis de memoria, disco, timeline y detección de amenazas
- 📄 **Reportes Multi-formato**: Generación de reportes en HTML, PDF y DOCX con lenguaje técnico-casual
- 🔗 **Cadena de Custodia**: Registro completo y automático de todas las acciones realizadas
- 📊 **Exportación de Datos**: Múltiples formatos de exportación (JSON, CSV) para análisis posterior
- 🛠️ **Herramientas Integradas**: Verificación de integridad, limpieza y estadísticas del sistema
- 🖥️ **Interfaz Interactiva**: Demo completo con menús intuitivos y navegación fácil
- 🔒 **Seguridad**: Manejo seguro de evidencia con verificación de integridad
- 📈 **Monitoreo**: Estado del sistema en tiempo real y estadísticas detalladas

## 🚀 Instalación

### Requisitos del Sistema
- **Sistema Operativo**: Windows 10/11 (Probado y optimizado)
- **Python**: 3.8 o superior
- **RAM**: Mínimo 8GB (recomendado 16GB para análisis complejos)
- **Espacio en Disco**: Mínimo 10GB libres
- **Permisos**: Administrador para recopilación completa de evidencia

### Instalación Paso a Paso

```bash
# 1. Clonar el repositorio
git clone https://github.com/ismaiars/ForenseCTL.git
cd ForenseCTL

# 2. Crear entorno virtual (recomendado)
python -m venv venv
venv\Scripts\activate  # En Windows

# 3. Instalar dependencias básicas
pip install psutil platform-info datetime pathlib json

# 4. Instalar dependencias para reportes (se instalan automáticamente)
# reportlab, python-docx, beautifulsoup4, markdown
```

### Dependencias Automáticas

El sistema instala automáticamente las siguientes dependencias según sea necesario:

- **Reportes PDF**: `reportlab`
- **Reportes DOCX**: `python-docx`
- **Procesamiento HTML**: `beautifulsoup4`, `markdown`
- **Análisis del Sistema**: `psutil`, `platform`
- **Gestión de Archivos**: `pathlib`, `json`, `datetime`

### Verificación de Instalación

```bash
# Ejecutar demo interactivo completo
python demo_completo_interactivo.py

# Ejecutar demo específico de reportes PDF/DOCX
python demo_pdf_docx_alternativo.py

# Verificar componentes del sistema
python -c "import forensectl; print('ForenseCTL instalado correctamente')"
```

## 🚀 Quick Start

### Demo Rápido

```bash
# Ejecutar demo interactivo completo
python demo_completo_interactivo.py

# El demo incluye:
# 1. Gestión de casos forenses
# 2. Recopilación de evidencia del sistema
# 3. Análisis forense avanzado
# 4. Generación de reportes (HTML, PDF, DOCX)
# 5. Cadena de custodia
# 6. Exportación de datos
# 7. Herramientas de administración
```

## 🎯 Funcionalidades Principales

### 📁 Gestión de Casos
- Crear nuevos casos forenses
- Listar y seleccionar casos existentes
- Ver información detallada de casos
- Actualizar metadatos de casos
- Eliminar casos obsoletos

### 🔍 Recopilación de Evidencia
- **Información del Sistema**: Hardware, OS, usuarios
- **Procesos Activos**: Lista completa de procesos en ejecución
- **Conexiones de Red**: Conexiones TCP/UDP activas
- **Programas Instalados**: Software instalado en el sistema
- **Archivos del Sistema**: Archivos críticos y logs
- **Registro de Windows**: Claves importantes del registro

### ⚙️ Análisis Forense
- **Análisis de Memoria**: Extracción y análisis de volcados de memoria
- **Análisis de Disco**: Examen de sistemas de archivos y particiones
- **Timeline Forense**: Construcción de líneas de tiempo de eventos
- **Detección YARA**: Búsqueda de patrones maliciosos
- **Análisis de Artefactos**: Extracción de artefactos específicos

### 📄 Generación de Reportes
- **Reportes Técnicos**: Análisis detallado para especialistas
- **Reportes Ejecutivos**: Resúmenes para directivos
- **Múltiples Formatos**: HTML, PDF, DOCX
- **Lenguaje Técnico-Casual**: Accesible pero profesional
- **Plantillas Personalizables**: Adaptables a diferentes necesidades

### 🔗 Cadena de Custodia
- Registro automático de todas las acciones
- Historial completo de manipulación de evidencia
- Búsqueda por evidencia específica
- Estadísticas de custodia
- Exportación de registros

### 📊 Exportación y Herramientas
- **Exportación de Datos**: JSON, CSV para análisis posterior
- **Verificación de Integridad**: Validación de archivos
- **Limpieza del Sistema**: Eliminación de archivos temporales
- **Estadísticas Detalladas**: Métricas del caso y sistema
- **Monitoreo en Tiempo Real**: Estado del sistema y componentes

## 🔧 Solución de Problemas

### Problemas Comunes de Instalación

#### Error: "No module named 'forensectl'"
```bash
# Solución: Instalar el proyecto en modo desarrollo
pip install -e .
```

#### Error: "No module named 'rich'" o dependencias faltantes
```bash
# Solución: Instalar dependencias básicas
pip install click rich typer pydantic jinja2 pyyaml requests psutil pandas numpy cryptography sqlalchemy
```

#### Error: "forensectl command not found"
```bash
# Solución: Usar la ruta completa al CLI
python forensectl/cli.py --help
```

#### Error en pyproject.toml (Poetry)
```bash
# Solución: Usar setup.py en su lugar
mv pyproject.toml pyproject.toml.bak
pip install -e .
```

#### Error: "CaseManager.create_case() got an unexpected keyword argument 'timezone'"
```bash
# Este error ya está corregido en la versión actual
# Si persiste, verificar que el archivo cli.py esté actualizado
```

### Verificación de Instalación

```bash
# Verificar que el CLI funciona
python forensectl/cli.py --help

# Crear un caso de prueba
python forensectl/cli.py case init -c TEST-$(date +%Y%m%d)-ORG-DEMO -e "Test User" -o "Test Org" -d "Prueba de instalación"

# Verificar estado del caso
python forensectl/cli.py case status -c TEST-$(date +%Y%m%d)-ORG-DEMO
```

## 🏗️ Arquitectura del Proyecto

```
ForenseCTL/
├── forensectl/                    # Framework principal
│   ├── core/                      # Núcleo del sistema
│   │   ├── case_manager.py        # Gestión de casos forenses
│   │   ├── evidence_collector.py  # Recopilación de evidencia
│   │   ├── chain_custody.py       # Cadena de custodia
│   │   └── system_analyzer.py     # Análisis del sistema
│   ├── analysis/                  # Módulos de análisis
│   │   ├── memory_analyzer.py     # Análisis de memoria
│   │   ├── disk_analyzer.py       # Análisis de disco
│   │   ├── network_analyzer.py    # Análisis de red
│   │   └── timeline_builder.py    # Constructor de timeline
│   ├── reports/                   # Sistema de reportes
│   │   ├── report_generator.py    # Generador principal
│   │   ├── pdf_generator.py       # Generación PDF
│   │   ├── docx_generator.py      # Generación DOCX
│   │   └── html_generator.py      # Generación HTML
│   ├── cli/                       # Interfaz CLI
│   │   └── commands.py            # Comandos disponibles
│   └── interactive_menu.py        # Menú interactivo
├── templates/                     # Plantillas de reportes
│   ├── executive_report_*.html    # Reportes ejecutivos
│   └── technical_report_*.html    # Reportes técnicos
├── cases/                         # Casos forenses (generados)
├── analysis/                      # Análisis guardados
├── reports/                       # Reportes generados
├── demo_completo_interactivo.py   # Demo principal
├── demo_pdf_docx_alternativo.py   # Demo de reportes
└── README.md                      # Documentación
```

## 📚 Documentación

- [Guía de Instalación](docs/installation.md)
- [Arquitectura del Sistema](docs/architecture.md)
- [SOPs y Playbooks](docs/playbooks/)
- [Guías Legales](docs/legal/)
- [API Reference](docs/api/)
- [Cómo Presentar en Portafolio](docs/portfolio-guide.md)

## 🔒 Seguridad y Compliance

- ✅ **Cadena de Custodia**: Firmas digitales opcionales (minisign/age)
- ✅ **Mínimos Privilegios**: No root containers, RBAC
- ✅ **Evidencia Read-Only**: Montajes RO, write blockers
- ✅ **Cifrado**: TLS en tránsito, cifrado opcional en reposo
- ✅ **PII Protection**: Enmascarado en reportes públicos
- ✅ **Security Scanning**: Trivy, pip-audit, gitleaks

## 🧪 Testing

```bash
# Ejecutar todas las pruebas
make test

# Pruebas específicas
poetry run pytest tests/unit/
poetry run pytest tests/integration/
poetry run pytest tests/e2e/

# Verificación de integridad
make verify-integrity
```

## 🤝 Contribución

¡Las contribuciones son bienvenidas! Para contribuir al proyecto:

1. **Fork** el repositorio
2. **Crea** una rama para tu funcionalidad (`git checkout -b feature/nueva-funcionalidad`)
3. **Desarrolla** tu código siguiendo las convenciones existentes
4. **Prueba** tu código con los demos disponibles
5. **Commit** tus cambios (`git commit -m 'Añadir nueva funcionalidad'`)
6. **Push** a tu rama (`git push origin feature/nueva-funcionalidad`)
7. **Abre** un Pull Request

### Áreas de Contribución

- **Nuevos Analizadores**: Módulos de análisis específicos
- **Plantillas de Reportes**: Nuevos formatos y estilos
- **Recopiladores de Evidencia**: Nuevas fuentes de datos
- **Mejoras de UI**: Interfaz más intuitiva
- **Documentación**: Guías y tutoriales
- **Testing**: Casos de prueba y validación

## ⚖️ Consideraciones Legales

**⚠️ IMPORTANTE**: Esta herramienta está diseñada exclusivamente para:

- Análisis forense autorizado en entornos controlados
- Respuesta a incidentes en infraestructura propia
- Investigaciones con autorización legal explícita
- Entornos de laboratorio y educación

**El uso no autorizado de estas herramientas puede violar leyes locales e internacionales. Los usuarios son responsables de cumplir con todas las regulaciones aplicables.**

## 📄 Licencia

Este proyecto está licenciado bajo la **Licencia MIT** - consulta el archivo [LICENSE](LICENSE) para más detalles.

### Resumen de la Licencia
- ✅ Uso comercial permitido
- ✅ Modificación permitida
- ✅ Distribución permitida
- ✅ Uso privado permitido
- ❌ Sin garantía
- ❌ Sin responsabilidad del autor

## 🙏 Agradecimientos

- **Python Community** - Por las excelentes librerías utilizadas
- **ReportLab** - Generación de PDFs de alta calidad
- **python-docx** - Creación de documentos DOCX
- **psutil** - Información detallada del sistema
- **BeautifulSoup** - Procesamiento HTML robusto
- **Comunidad Forense Digital** - Por compartir conocimiento y mejores prácticas

---

**ForenseCTL** - Framework de Análisis Forense Digital desarrollado para profesionales de ciberseguridad y equipos de respuesta a incidentes.

---

**Desarrollado con ❤️ para la comunidad de Blue Team y DFIR**