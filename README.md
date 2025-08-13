# ForenseCTL - Herramienta de Análisis Forense Automatizado

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-green.svg)](https://github.com/features/actions)

## 🔍 Descripción

ForenseCTL es una herramienta profesional de análisis forense digital que automatiza el ciclo completo de investigación: **adquisición → preservación → análisis → timeline → reporte**. Diseñada para Blue Teams, equipos DFIR y MSSPs que requieren respuesta a incidentes reproducible y con cadena de custodia documentada.

## ✨ Características Principales

- 🔒 **Integridad Garantizada**: SHA-256/SHA-512, cadena de custodia y evidencia inmutable
- 🖥️ **Multi-Plataforma**: Windows, Linux y macOS (opcional)
- 🧠 **Análisis de Memoria**: Volatility3 con perfiles preconfigurados
- 💾 **Análisis de Disco**: The Sleuth Kit, Autopsy headless, carving
- 📊 **Timeline Forense**: plaso/log2timeline con correlación automática
- 🔍 **Detección de Malware**: YARA rules sobre memoria/disco/artefactos
- ☁️ **Cloud Forensics**: AWS CloudTrail, GCP Audit, Azure Activity Logs
- 📄 **Reportes Profesionales**: Plantillas técnicas y ejecutivas (PDF/HTML)
- 🐳 **Containerizado**: Docker + docker-compose para reproducibilidad
- 🔄 **CI/CD Completo**: GitHub Actions con security scanning

## 🚀 Quick Start

### Prerrequisitos

- Python 3.12+ con Poetry
- Docker y docker-compose
- 16GB RAM (recomendado para análisis grandes)
- Make (opcional, para comandos simplificados)

### Instalación

```bash
# Clonar repositorio
git clone https://github.com/ismaiars/ForenseCTL.git
cd ForenseCTL

# Setup automático
make setup
# O manualmente:
poetry install
docker compose build
```

### Demo Rápido

```bash
# Inicializar caso de demostración
poetry run forensectl init-case --case CASE-20250812-DEMO

# Levantar laboratorio
docker compose up -d

# Análisis de memoria (ejemplo)
poetry run forensectl analyze memory --inputs data/samples/memdump.raw

# Generar timeline
poetry run forensectl timeline build --inputs data/samples/artefactos --format jsonl

# Crear reporte ejecutivo
poetry run forensectl report build --case CASE-20250812-DEMO --template ejecutivo
```

## 📋 Comandos CLI Principales

```bash
# Gestión de casos
forensectl init-case --case CASE-YYYYMMDD-ORG-INCIDENT
forensectl chain add-entry --case <id> --note "Evidencia recibida"

# Adquisición
forensectl acquire --profile windows --scope live --target hostname
forensectl acquire --profile linux --scope image --target /dev/sdb

# Verificación de integridad
forensectl verify --path evidence/disk.dd

# Análisis
forensectl analyze memory --profile win10 --inputs memory.raw
forensectl analyze disk --inputs disk.dd
forensectl analyze artefactos --profile windows --inputs registry/

# Timeline y correlación
forensectl timeline build --inputs logs/ --format jsonl
forensectl timeline export --case <id> --format csv

# Detección
forensectl yara scan --rules rules/yara --inputs evidence/

# Reportes
forensectl report build --case <id> --template tecnico
forensectl report build --case <id> --template ejecutivo

# Retención
forensectl retention archive --case <id>
forensectl retention purge --case <id>
```

## 🏗️ Arquitectura

```
forense-automatizado-blueteam/
├── forensectl/           # CLI principal (Python)
├── modules/              # Módulos especializados
│   ├── adquisicion/      # Colectores y verificación
│   ├── preservacion/     # Cadena de custodia
│   ├── analisis_memoria/ # Volatility3 wrappers
│   ├── analisis_disco/   # TSK/Autopsy wrappers
│   ├── artefactos_endpoint/ # Parsers Windows/Linux/macOS
│   ├── timeline/         # plaso/psort pipeline
│   ├── yara_scanner/     # Detección de malware
│   ├── cloud_forensics/  # Logs cloud (AWS/GCP/Azure)
│   ├── reportes/         # Plantillas y generación
│   └── retencion/        # Archivado y borrado seguro
├── rules/yara/           # Reglas YARA
├── data/samples/         # Datasets sintéticos
├── docker/               # Contenedores
├── docs/                 # Documentación y SOPs
└── tests/                # Pruebas automatizadas
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

Ver [CONTRIBUTING.md](CONTRIBUTING.md) para guías de contribución, [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) para normas de conducta y [SECURITY.md](SECURITY.md) para reportes de seguridad.

## ⚖️ Consideraciones Legales

**⚠️ IMPORTANTE**: Esta herramienta está diseñada exclusivamente para:

- Análisis forense autorizado en entornos controlados
- Respuesta a incidentes en infraestructura propia
- Investigaciones con autorización legal explícita
- Entornos de laboratorio y educación

**El uso no autorizado de estas herramientas puede violar leyes locales e internacionales. Los usuarios son responsables de cumplir con todas las regulaciones aplicables.**

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

## 🏆 Reconocimientos

- [Volatility Foundation](https://www.volatilityfoundation.org/) - Análisis de memoria
- [The Sleuth Kit](https://www.sleuthkit.org/) - Análisis de sistemas de archivos
- [plaso](https://github.com/log2timeline/plaso) - Timeline forense
- [YARA](https://virustotal.github.io/yara/) - Detección de patrones

---

**Desarrollado con ❤️ para la comunidad de Blue Team y DFIR**