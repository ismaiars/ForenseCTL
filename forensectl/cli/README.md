# ForenseCTL CLI

Interfaz de línea de comandos para ForenseCTL - Herramienta profesional de análisis forense digital.

## Instalación

```bash
pip install forensectl
```

## Configuración

### Inicialización

```bash
# Inicializar ForenseCTL en el directorio actual
forensectl init

# Inicializar en un directorio específico
forensectl init --work-dir /path/to/forensics
```

### Configuración

```bash
# Ver configuración actual
forensectl config --show

# Editar configuración
forensectl config --edit

# Restablecer configuración por defecto
forensectl config --reset
```

## Comandos Principales

### 📁 Gestión de Casos

```bash
# Crear un nuevo caso
forensectl case create --name "Investigación Malware" --examiner "John Doe"

# Listar casos
forensectl case list

# Ver detalles de un caso
forensectl case show --case CASE-001

# Actualizar caso
forensectl case update --case CASE-001 --status active

# Cerrar caso
forensectl case close --case CASE-001

# Archivar caso
forensectl case archive --case CASE-001

# Eliminar caso
forensectl case delete --case CASE-001
```

### 🗂️ Gestión de Evidencias

```bash
# Agregar evidencia
forensectl evidence add --case CASE-001 --path /path/to/evidence --type disk

# Listar evidencias
forensectl evidence list --case CASE-001

# Ver detalles de evidencia
forensectl evidence show --case CASE-001 --evidence EV-001

# Actualizar evidencia
forensectl evidence update --case CASE-001 --evidence EV-001 --description "Nueva descripción"

# Verificar integridad
forensectl evidence verify --case CASE-001 --evidence EV-001

# Eliminar evidencia
forensectl evidence remove --case CASE-001 --evidence EV-001
```

### 🔬 Análisis Forense

```bash
# Análisis de memoria
forensectl analyze memory --case CASE-001 --evidence EV-001 --profile Win10x64

# Análisis de disco
forensectl analyze disk --case CASE-001 --evidence EV-001 --type full

# Extracción de artefactos
forensectl analyze extract-artifacts --case CASE-001 --evidence EV-001 --os windows

# Análisis completo
forensectl analyze all --case CASE-001 --evidence EV-001 --profile comprehensive

# Ver estado de análisis
forensectl analyze status --case CASE-001
```

### 📅 Gestión de Timelines

```bash
# Construir timeline
forensectl timeline build --case CASE-001 --evidence EV-001 --output timeline.csv

# Analizar timeline
forensectl timeline analyze --case CASE-001 --timeline timeline.csv

# Filtrar timeline
forensectl timeline filter --case CASE-001 --timeline timeline.csv --start-date 2024-01-01

# Exportar timeline
forensectl timeline export --case CASE-001 --timeline timeline.csv --format xlsx

# Listar timelines
forensectl timeline list --case CASE-001
```

### 🛡️ Detección con YARA

```bash
# Escanear con YARA
forensectl yara scan --case CASE-001 --evidence EV-001 --rules malware

# Compilar reglas
forensectl yara compile --rules /path/to/rules --output compiled.yar

# Actualizar reglas
forensectl yara update --source github --ruleset malware

# Listar reglas
forensectl yara list-rules --details

# Ver resultados
forensectl yara results --case CASE-001 --scan-id SCAN-001
```

### 📄 Generación de Reportes

```bash
# Generar reporte
forensectl report generate --case CASE-001 --template standard --format pdf

# Listar plantillas
forensectl report templates --details

# Convertir reporte
forensectl report convert --input report.pdf --output report.docx

# Validar reporte
forensectl report validate --report report.pdf

# Listar reportes
forensectl report list --case CASE-001
```

### 🔗 Cadena de Custodia

```bash
# Agregar entrada
forensectl chain add-entry --case CASE-001 --evidence EV-001 --action "Análisis iniciado"

# Listar entradas
forensectl chain list --case CASE-001 --evidence EV-001

# Verificar cadena
forensectl chain verify --case CASE-001 --evidence EV-001

# Exportar cadena
forensectl chain export --case CASE-001 --evidence EV-001 --format pdf

# Firmar entrada
forensectl chain sign --case CASE-001 --evidence EV-001 --entry ENTRY-001
```

### ✅ Verificación de Integridad

```bash
# Verificar evidencia
forensectl verify evidence --case CASE-001 --evidence EV-001

# Verificar caso completo
forensectl verify case --case CASE-001

# Verificar hash específico
forensectl verify hash --file /path/to/file --expected-hash abc123

# Ver resultados de verificación
forensectl verify results --case CASE-001
```

### 📦 Gestión de Retención

```bash
# Crear política de retención
forensectl retention policy create --name "Política Estándar" --period 2555

# Ver estado de retención
forensectl retention status --case CASE-001

# Limpiar datos vencidos
forensectl retention cleanup --dry-run

# Aplicar retención legal
forensectl retention policy update --case CASE-001 --legal-hold
```

### 🔄 Flujos de Trabajo

```bash
# Crear workflow
forensectl workflow create --name "Análisis Malware" --template comprehensive

# Listar workflows
forensectl workflow list --category malware

# Ejecutar workflow
forensectl workflow run --workflow WF-001 --case CASE-001

# Ver estado de workflow
forensectl workflow status --workflow WF-001

# Listar plantillas
forensectl workflow templates --details
```

## Comandos de Sistema

```bash
# Ver versión
forensectl version

# Ver estado general
forensectl status

# Mostrar ayuda
forensectl --help
forensectl COMMAND --help
```

## Opciones Globales

```bash
# Modo verbose
forensectl --verbose COMMAND

# Modo silencioso
forensectl --quiet COMMAND

# Archivo de configuración personalizado
forensectl --config /path/to/config.yaml COMMAND

# Directorio de trabajo específico
forensectl COMMAND --work-dir /path/to/workspace
```

## Ejemplos de Flujos Completos

### Investigación Básica

```bash
# 1. Inicializar workspace
forensectl init

# 2. Crear caso
forensectl case create --name "Incident-2024-001" --examiner "Jane Smith"

# 3. Agregar evidencia
forensectl evidence add --case CASE-001 --path /evidence/disk.dd --type disk

# 4. Ejecutar análisis
forensectl analyze all --case CASE-001 --evidence EV-001 --profile standard

# 5. Construir timeline
forensectl timeline build --case CASE-001 --evidence EV-001

# 6. Escanear con YARA
forensectl yara scan --case CASE-001 --evidence EV-001 --rules malware

# 7. Generar reporte
forensectl report generate --case CASE-001 --template comprehensive

# 8. Cerrar caso
forensectl case close --case CASE-001
```

### Análisis de Malware

```bash
# 1. Crear caso específico para malware
forensectl case create --name "Malware Analysis" --type malware --priority high

# 2. Agregar muestra de malware
forensectl evidence add --case CASE-001 --path /samples/malware.exe --type file

# 3. Ejecutar workflow de malware
forensectl workflow run --workflow malware-analysis --case CASE-001

# 4. Ver resultados
forensectl analyze status --case CASE-001
forensectl yara results --case CASE-001

# 5. Generar reporte especializado
forensectl report generate --case CASE-001 --template malware-analysis
```

### Respuesta a Incidentes

```bash
# 1. Crear caso de incidente
forensectl case create --name "Security Incident" --type incident --priority critical

# 2. Agregar múltiples evidencias
forensectl evidence add --case CASE-001 --path /evidence/memory.dmp --type memory
forensectl evidence add --case CASE-001 --path /evidence/disk.e01 --type disk
forensectl evidence add --case CASE-001 --path /evidence/network.pcap --type network

# 3. Ejecutar análisis en paralelo
forensectl workflow run --workflow incident-response --case CASE-001 --parallel

# 4. Construir timeline completo
forensectl timeline build --case CASE-001 --all-evidence --include-network

# 5. Generar reporte ejecutivo
forensectl report generate --case CASE-001 --template executive-summary
```

## Configuración Avanzada

### Archivo de Configuración

Copia `config_example.yaml` como `config.yaml` y personaliza:

```yaml
general:
  work_directory: "/forensics"
  log_level: "INFO"
  max_parallel_jobs: 8

analysis:
  volatility:
    executable_path: "/opt/volatility3/vol.py"
  sleuthkit:
    installation_directory: "/usr/local/bin"

yara:
  rules_directory: "/opt/yara-rules"
  max_file_size_mb: 500
  scan_threads: 8

reports:
  default_template: "corporate"
  digital_signature: true
  signature:
    certificate_path: "/certs/forensics.crt"
    private_key_path: "/certs/forensics.key"
```

### Variables de Entorno

```bash
# Directorio de trabajo por defecto
export FORENSECTL_WORK_DIR="/forensics"

# Nivel de logging
export FORENSECTL_LOG_LEVEL="DEBUG"

# Archivo de configuración
export FORENSECTL_CONFIG="/etc/forensectl/config.yaml"

# Número de trabajos paralelos
export FORENSECTL_MAX_JOBS="8"
```

## Integración con Herramientas

### Volatility

```bash
# Configurar ruta de Volatility
forensectl config set analysis.volatility.executable_path "/opt/volatility3/vol.py"

# Descargar símbolos
forensectl analyze memory --case CASE-001 --evidence EV-001 --download-symbols
```

### The Sleuth Kit

```bash
# Configurar TSK
forensectl config set analysis.sleuthkit.installation_directory "/usr/local/bin"

# Análisis completo de disco
forensectl analyze disk --case CASE-001 --evidence EV-001 --include-deleted --analyze-slack
```

### YARA

```bash
# Actualizar reglas desde GitHub
forensectl yara update --source github --ruleset yara-rules/rules

# Compilar reglas personalizadas
forensectl yara compile --rules /custom/rules --output /opt/yara/compiled.yar
```

## Solución de Problemas

### Problemas Comunes

1. **Error de permisos**:
   ```bash
   sudo chown -R $USER:$USER /forensics
   chmod -R 755 /forensics
   ```

2. **Dependencias faltantes**:
   ```bash
   pip install --upgrade forensectl[all]
   ```

3. **Espacio insuficiente**:
   ```bash
   forensectl status  # Ver uso de disco
   forensectl retention cleanup --dry-run  # Ver qué se puede limpiar
   ```

### Logs y Debug

```bash
# Habilitar modo debug
forensectl --verbose COMMAND

# Ver logs
tail -f logs/forensectl.log

# Verificar configuración
forensectl config --show
```

### Rendimiento

```bash
# Ajustar trabajos paralelos
forensectl config set general.max_parallel_jobs 16

# Usar SSD para directorio temporal
forensectl config set general.temp_directory "/ssd/temp"

# Optimizar análisis de memoria
forensectl analyze memory --case CASE-001 --evidence EV-001 --fast-scan
```

## Contribuir

1. Fork del repositorio
2. Crear rama de feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit de cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## Licencia

MIT License - ver archivo LICENSE para detalles.

## Soporte

- 📧 Email: support@forensectl.com
- 🐛 Issues: https://github.com/forensectl/forensectl/issues
- 📖 Documentación: https://docs.forensectl.com
- 💬 Discord: https://discord.gg/forensectl