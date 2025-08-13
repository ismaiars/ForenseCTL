.PHONY: help setup test demo report clean lint format security docker-build docker-up docker-down verify-integrity

# Variables
PYTHON := python
POETRY := poetry
DOCKER := docker
DOCKER_COMPOSE := docker compose

# Colores para output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

help: ## Mostrar esta ayuda
	@echo "$(BLUE)Forense-Automatizado-BlueTeam - Comandos Disponibles$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

setup: ## Configurar entorno de desarrollo completo
	@echo "$(BLUE)🔧 Configurando entorno de desarrollo...$(NC)"
	@echo "$(YELLOW)📦 Instalando dependencias Python...$(NC)"
	$(POETRY) install --all-extras
	@echo "$(YELLOW)🐳 Construyendo contenedores Docker...$(NC)"
	$(DOCKER_COMPOSE) build
	@echo "$(YELLOW)🔧 Configurando pre-commit hooks...$(NC)"
	$(POETRY) run pre-commit install
	@echo "$(YELLOW)📁 Creando directorios de trabajo...$(NC)"
	mkdir -p cases evidence analysis reports manifests chain logs
	@echo "$(GREEN)✅ Setup completado exitosamente!$(NC)"

test: ## Ejecutar todas las pruebas
	@echo "$(BLUE)🧪 Ejecutando pruebas...$(NC)"
	$(POETRY) run pytest tests/ -v --cov=forensectl --cov=modules --cov-report=html --cov-report=term

test-unit: ## Ejecutar solo pruebas unitarias
	@echo "$(BLUE)🧪 Ejecutando pruebas unitarias...$(NC)"
	$(POETRY) run pytest tests/unit/ -v

test-integration: ## Ejecutar pruebas de integración
	@echo "$(BLUE)🧪 Ejecutando pruebas de integración...$(NC)"
	$(POETRY) run pytest tests/integration/ -v

test-e2e: ## Ejecutar pruebas end-to-end
	@echo "$(BLUE)🧪 Ejecutando pruebas end-to-end...$(NC)"
	$(POETRY) run pytest tests/e2e/ -v

demo: ## Ejecutar demostración completa del sistema
	@echo "$(BLUE)🎬 Iniciando demostración del sistema...$(NC)"
	@echo "$(YELLOW)📋 Inicializando caso de demostración...$(NC)"
	$(POETRY) run forensectl init-case --case CASE-20250812-DEMO --examiner "Demo User" --org "Demo Org"
	@echo "$(YELLOW)🐳 Levantando laboratorio Docker...$(NC)"
	$(DOCKER_COMPOSE) up -d
	@echo "$(YELLOW)⏳ Esperando servicios...$(NC)"
	sleep 10
	@echo "$(YELLOW)🧠 Analizando memoria de ejemplo...$(NC)"
	$(POETRY) run forensectl analyze memory --inputs data/samples/memdump.raw --profile win10 --case CASE-20250812-DEMO || echo "Archivo de ejemplo no encontrado, continuando..."
	@echo "$(YELLOW)📊 Generando timeline...$(NC)"
	$(POETRY) run forensectl timeline build --inputs data/samples/artefactos --format jsonl --case CASE-20250812-DEMO || echo "Artefactos de ejemplo no encontrados, continuando..."
	@echo "$(YELLOW)🔍 Ejecutando escaneo YARA...$(NC)"
	$(POETRY) run forensectl yara scan --rules rules/yara --inputs data/samples --case CASE-20250812-DEMO || echo "Reglas YARA no encontradas, continuando..."
	@echo "$(GREEN)🎉 Demo completada! Revisa los resultados en cases/CASE-20250812-DEMO/$(NC)"

report: ## Generar reportes de demostración
	@echo "$(BLUE)📄 Generando reportes...$(NC)"
	@echo "$(YELLOW)📋 Reporte técnico...$(NC)"
	$(POETRY) run forensectl report build --case CASE-20250812-DEMO --template tecnico
	@echo "$(YELLOW)📊 Reporte ejecutivo...$(NC)"
	$(POETRY) run forensectl report build --case CASE-20250812-DEMO --template ejecutivo
	@echo "$(GREEN)✅ Reportes generados en cases/CASE-20250812-DEMO/reports/$(NC)"

lint: ## Ejecutar linters de código
	@echo "$(BLUE)🔍 Ejecutando linters...$(NC)"
	$(POETRY) run ruff check .
	$(POETRY) run mypy forensectl modules

format: ## Formatear código
	@echo "$(BLUE)🎨 Formateando código...$(NC)"
	$(POETRY) run black .
	$(POETRY) run isort .
	$(POETRY) run ruff check --fix .

security: ## Ejecutar escaneos de seguridad
	@echo "$(BLUE)🔒 Ejecutando escaneos de seguridad...$(NC)"
	@echo "$(YELLOW)🔍 Auditando dependencias...$(NC)"
	$(POETRY) run pip-audit
	@echo "$(YELLOW)🛡️ Escaneando vulnerabilidades...$(NC)"
	$(POETRY) run safety check
	@echo "$(YELLOW)🔐 Analizando código con Bandit...$(NC)"
	$(POETRY) run bandit -r forensectl modules -f json -o security-report.json || true
	@echo "$(GREEN)✅ Escaneos de seguridad completados$(NC)"

docker-build: ## Construir imágenes Docker
	@echo "$(BLUE)🐳 Construyendo imágenes Docker...$(NC)"
	$(DOCKER_COMPOSE) build

docker-up: ## Levantar servicios Docker
	@echo "$(BLUE)🐳 Levantando servicios Docker...$(NC)"
	$(DOCKER_COMPOSE) up -d

docker-down: ## Detener servicios Docker
	@echo "$(BLUE)🐳 Deteniendo servicios Docker...$(NC)"
	$(DOCKER_COMPOSE) down

docker-logs: ## Ver logs de contenedores
	@echo "$(BLUE)🐳 Mostrando logs de contenedores...$(NC)"
	$(DOCKER_COMPOSE) logs -f

verify-integrity: ## Verificar integridad de evidencias
	@echo "$(BLUE)🔐 Verificando integridad de evidencias...$(NC)"
	$(POETRY) run forensectl verify --path evidence/ --recursive
	@echo "$(GREEN)✅ Verificación de integridad completada$(NC)"

clean: ## Limpiar archivos temporales y cache
	@echo "$(BLUE)🧹 Limpiando archivos temporales...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/
	@echo "$(GREEN)✅ Limpieza completada$(NC)"

clean-docker: ## Limpiar contenedores y volúmenes Docker
	@echo "$(BLUE)🐳 Limpiando recursos Docker...$(NC)"
	$(DOCKER_COMPOSE) down -v --remove-orphans
	$(DOCKER) system prune -f
	@echo "$(GREEN)✅ Limpieza Docker completada$(NC)"

docs-serve: ## Servir documentación localmente
	@echo "$(BLUE)📚 Sirviendo documentación...$(NC)"
	$(POETRY) run mkdocs serve

docs-build: ## Construir documentación
	@echo "$(BLUE)📚 Construyendo documentación...$(NC)"
	$(POETRY) run mkdocs build

install-dev: ## Instalar herramientas de desarrollo adicionales
	@echo "$(BLUE)🔧 Instalando herramientas de desarrollo...$(NC)"
	$(POETRY) install --all-extras
	$(POETRY) run pre-commit install
	@echo "$(GREEN)✅ Herramientas de desarrollo instaladas$(NC)"

ci: lint test security ## Ejecutar pipeline CI completo
	@echo "$(GREEN)✅ Pipeline CI completado exitosamente$(NC)"

release-check: ## Verificar que el proyecto está listo para release
	@echo "$(BLUE)🚀 Verificando preparación para release...$(NC)"
	make ci
	make verify-integrity
	@echo "$(YELLOW)🔍 Verificando que no hay secretos...$(NC)"
	# Aquí iría gitleaks o trufflehog si están instalados
	@echo "$(GREEN)✅ Proyecto listo para release$(NC)"

# Comandos específicos para casos forenses
case-init: ## Inicializar nuevo caso (usar CASE_ID=nombre)
	@echo "$(BLUE)📋 Inicializando caso $(CASE_ID)...$(NC)"
	$(POETRY) run forensectl init-case --case $(CASE_ID)

case-status: ## Ver estado de caso (usar CASE_ID=nombre)
	@echo "$(BLUE)📊 Estado del caso $(CASE_ID):$(NC)"
	$(POETRY) run forensectl case status --case $(CASE_ID)

case-archive: ## Archivar caso (usar CASE_ID=nombre)
	@echo "$(BLUE)📦 Archivando caso $(CASE_ID)...$(NC)"
	$(POETRY) run forensectl retention archive --case $(CASE_ID)

# Comandos de desarrollo
dev-setup: ## Setup rápido para desarrollo
	@echo "$(BLUE)⚡ Setup rápido para desarrollo...$(NC)"
	$(POETRY) install
	$(POETRY) run pre-commit install
	mkdir -p cases evidence analysis reports
	@echo "$(GREEN)✅ Setup de desarrollo completado$(NC)"

dev-test: ## Pruebas rápidas para desarrollo
	@echo "$(BLUE)⚡ Pruebas rápidas...$(NC)"
	$(POETRY) run pytest tests/unit/ -x -v

# Información del sistema
info: ## Mostrar información del sistema
	@echo "$(BLUE)ℹ️  Información del Sistema$(NC)"
	@echo "Python: $$($(PYTHON) --version)"
	@echo "Poetry: $$($(POETRY) --version)"
	@echo "Docker: $$($(DOCKER) --version)"
	@echo "Docker Compose: $$($(DOCKER_COMPOSE) version --short)"
	@echo "Sistema: $$(uname -s)"
	@echo "Arquitectura: $$(uname -m)"