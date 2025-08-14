# 🔍 ForenseCTL - Sistema de Análisis Forense Digital Multiplataforma

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/platform-Windows-0078D4?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)](https://www.linux.org/)
[![Status](https://img.shields.io/badge/status-Production%20Ready-00C851?logo=checkmarx&logoColor=white)](https://github.com/ismaiars/ForenseCTL)
[![Windows Executable](https://img.shields.io/badge/Windows%20EXE-8.44MB-FF6900?logo=windows&logoColor=white)](ForenseCTL_Distribution/)
[![Linux Script](https://img.shields.io/badge/Linux%20Script-Ready-FCC624?logo=linux&logoColor=black)](ForenseCTL_Linux_Distribution/)

</div>

## 🎯 Descripción

**ForenseCTL** es un sistema completo de análisis forense digital **multiplataforma** 🚀. Disponible como **ejecutable standalone para Windows (8.44MB)** y **script Python para Linux**. Diseñado para profesionales de ciberseguridad, equipos DFIR y analistas forenses, proporciona un ciclo completo de investigación forense: **recopilación → análisis → reporte → cadena de custodia**.

### 🌟 **¿Por qué ForenseCTL?**

✅ **Multiplataforma**: Windows (ejecutable) y Linux (script Python)  
✅ **Sin Instalaciones Complejas**: Ejecutable único o script directo  
✅ **Análisis Completo**: Recopilación automática de evidencia del sistema  
✅ **Reportes Profesionales**: HTML y JSON con diseño técnico-profesional  
✅ **Cadena de Custodia**: Registro automático de todas las acciones  
✅ **Interfaz Intuitiva**: Menú interactivo fácil de usar  
✅ **Portable**: Funciona desde cualquier ubicación sin dependencias complejas

## ✨ Funcionalidades Completas del Sistema Multiplataforma

### 🎯 **Núcleo del Sistema**
- 📁 **Gestión Completa de Casos**: Creación, administración y seguimiento de casos forenses
- 🔍 **Recopilación Automática**: Extracción de artefactos del sistema Windows y Linux en tiempo real
- ⚙️ **Análisis Forense Integral**: Análisis completo del sistema, procesos y red multiplataforma
- 📄 **Reportes Profesionales**: Generación automática en HTML y JSON adaptados por plataforma
- 🔗 **Cadena de Custodia**: Registro automático y completo de todas las acciones
- 🌐 **Soporte Multiplataforma**: Windows (ejecutable) y Linux (script Python)

### 🖥️ **Recopilación de Evidencia Multiplataforma**
#### 🌐 **Común (Windows & Linux)**
- 💻 **Información del Sistema**: Hardware, OS, arquitectura, usuarios activos
- 🔄 **Procesos en Ejecución**: Lista completa con PID, memoria, CPU y rutas
- 🌐 **Conexiones de Red**: TCP/UDP activas, puertos locales y remotos
- 📦 **Software Instalado**: Programas, versiones y ubicaciones de instalación
- 📂 **Archivos del Sistema**: Logs críticos, archivos temporales y de configuración

#### 🖥️ **Específico Windows**
- 🗃️ **Registro de Windows**: Claves importantes del sistema y aplicaciones
- 🔧 **Servicios de Windows**: Servicios activos, inactivos y configuraciones
- 📋 **Event Logs**: Registros de eventos del sistema y aplicaciones

#### 🐧 **Específico Linux**
- 📦 **Gestión de Paquetes**: Paquetes instalados (apt, yum, pacman, etc.)
- 🔧 **Servicios systemd**: Servicios activos, inactivos y configuraciones
- 📁 **Configuraciones del Sistema**: Archivos críticos de configuración
- 📝 **Logs del Sistema**: Syslog, auth.log, kern.log y otros logs críticos

### 📊 **Análisis y Reportes**
- 📈 **Análisis Estadístico**: Métricas detalladas del sistema y evidencia
- 🎨 **Reportes HTML**: Diseño profesional con gráficos y tablas interactivas
- 📋 **Exportación JSON**: Datos estructurados para análisis posterior
- 🔍 **Búsqueda Avanzada**: Filtros por tipo de evidencia y criterios específicos
- 📝 **Documentación Automática**: Generación de informes técnicos completos

### 🛠️ **Herramientas Integradas**
- ✅ **Verificación de Integridad**: Validación de archivos y evidencia
- 🧹 **Limpieza del Sistema**: Eliminación segura de archivos temporales
- 📈 **Monitoreo en Tiempo Real**: Estado del sistema y recursos
- 🔒 **Seguridad**: Manejo seguro de evidencia con verificación de integridad
- 🖥️ **Interfaz Intuitiva**: Menú interactivo con navegación fácil y clara

## 🚀 Instalación y Uso Multiplataforma

### 🖥️ **Windows - Ejecutable Standalone (Recomendado)**

**¡La forma más fácil de usar ForenseCTL en Windows!** 🎯

1. **📥 Descargar**: Navega a la carpeta `ForenseCTL_Distribution/`
2. **▶️ Ejecutar**: Doble clic en `ForenseCTL.exe` o desde terminal:
   ```cmd
   cd ForenseCTL_Distribution
   ForenseCTL.exe
   ```
3. **🎉 ¡Listo!**: El sistema se iniciará automáticamente

### 🐧 **Linux - Script Python**

**¡ForenseCTL ahora disponible para Linux!** 🚀

1. **📥 Descargar**: Navega a la carpeta `ForenseCTL_Linux_Distribution/`
2. **🔧 Instalación Automática**:
   ```bash
   cd ForenseCTL_Linux_Distribution
   chmod +x install_linux.sh
   sudo ./install_linux.sh
   forensectl
   ```
3. **⚡ Ejecución Directa**:
   ```bash
   python3 forensectl_linux.py
   ```

### 🖥️ **Requisitos del Sistema**

#### Windows
| Componente | Mínimo | Recomendado |
|------------|--------|-------------|
| 🖥️ **OS** | Windows 10 | Windows 11 |
| 💾 **RAM** | 4GB | 8GB+ |
| 💿 **Disco** | 1GB libre | 5GB+ |
| 👤 **Permisos** | Usuario | Administrador* |

#### Linux
| Componente | Mínimo | Recomendado |
|------------|--------|-------------|
| 🐧 **OS** | Linux Kernel 3.0+ | Linux Kernel 5.0+ |
| 🐍 **Python** | 3.6+ | 3.8+ |
| 💾 **RAM** | 2GB | 4GB+ |
| 💿 **Disco** | 500MB libre | 2GB+ |
| 👤 **Permisos** | Usuario | Root/sudo* |

*_Permisos elevados requeridos para recopilación completa de evidencia_

### ⚡ **Inicio Rápido**

#### Windows
```cmd
# Método 1: Ejecutar directamente
ForenseCTL_Distribution\ForenseCTL.exe

# Método 2: Desde PowerShell
cd ForenseCTL_Distribution
.\ForenseCTL.exe

# Método 3: Usar install.bat (instalación automática)
ForenseCTL_Distribution\install.bat
```

#### Linux
```bash
# Método 1: Instalación global
sudo ./install_linux.sh
forensectl

# Método 2: Ejecución directa
python3 forensectl_linux.py

# Método 3: Inicio rápido
./quick_start.sh
```

## 📦 **Distribuciones Disponibles**

### 🖥️ **Windows Distribution**
- **Ubicación**: `ForenseCTL_Distribution/`
- **Archivo Principal**: `ForenseCTL.exe` (8.44MB)
- **Instalador**: `install.bat`
- **Documentación**: `README.md`

### 🐧 **Linux Distribution**
- **Ubicación**: `ForenseCTL_Linux_Distribution/`
- **Archivo Principal**: `forensectl_linux.py`
- **Instalador**: `install_linux.sh`
- **Inicio Rápido**: `quick_start.sh`
- **Documentación**: `README.md`, `docs/QUICK_INSTALL.md`
- **Ejemplos**: `examples/system_check.py`

### 🔧 **Instalación desde Código Fuente (Desarrolladores)**

#### Windows
<details>
<summary>📋 Instrucciones para desarrolladores Windows</summary>

```bash
# 1. Clonar repositorio
git clone https://github.com/ismaiars/ForenseCTL.git
cd ForenseCTL

# 2. Instalar dependencias
pip install psutil platform-info datetime pathlib json

# 3. Ejecutar desde código
python forensectl_standalone.py
```

**Dependencias incluidas automáticamente:**
- `psutil` - Información del sistema
- `platform` - Detalles de la plataforma
- `json`, `datetime`, `pathlib` - Utilidades estándar

</details>

#### Linux
<details>
<summary>📋 Instrucciones para desarrolladores Linux</summary>

```bash
# 1. Clonar repositorio
git clone https://github.com/ismaiars/ForenseCTL.git
cd ForenseCTL

# 2. Instalar dependencias
pip3 install psutil

# 3. Ejecutar versión Linux
python3 forensectl_linux.py
```

**Dependencias requeridas:**
- `psutil` - Información del sistema Linux
- `platform` - Detalles de la plataforma (incluido en Python)
- `json`, `datetime`, `pathlib` - Utilidades estándar

</details>

## 🚀 Guía de Uso Rápido

### 🎯 **Primer Uso del Ejecutable**

1. **🚀 Iniciar ForenseCTL**:
   ```cmd
   cd ForenseCTL_Distribution
   ForenseCTL.exe
   ```

2. **📋 Menú Principal** - Verás estas opciones:
   ```
   ╔══════════════════════════════════════════════════════════════╗
   ║              FORENSECTL STANDALONE                           ║
   ║           ANÁLISIS FORENSE DIGITAL                          ║
   ╚══════════════════════════════════════════════════════════════╝
   
   [1] 📁 Gestión de Casos
   [2] 🔍 Análisis Forense
   [3] 📄 Generación de Reportes
   [4] 🔗 Cadena de Custodia
   [5] ⚙️  Configuración
   [6] ❓ Ayuda
   [0] 🚪 Salir
   ```

3. **🔥 Flujo de Trabajo Recomendado**:
   - **Paso 1**: Crear nuevo caso (Opción 1)
   - **Paso 2**: Ejecutar análisis forense (Opción 2)
   - **Paso 3**: Generar reporte (Opción 3)
   - **Paso 4**: Revisar cadena de custodia (Opción 4)

### 📊 **Funcionalidades Principales**

| Opción | Funcionalidad | Descripción |
|--------|---------------|-------------|
| 📁 **[1]** | **Gestión de Casos** | Crear, listar y administrar casos forenses |
| 🔍 **[2]** | **Análisis Forense** | Recopilación automática de evidencia del sistema |
| 📄 **[3]** | **Reportes** | Generación de informes HTML y JSON profesionales |
| 🔗 **[4]** | **Cadena de Custodia** | Registro automático de todas las acciones |
| ⚙️ **[5]** | **Configuración** | Ajustes del sistema y preferencias |
| ❓ **[6]** | **Ayuda** | Documentación y guías de uso |

## 🎯 Detalles de Funcionalidades

### 📁 **[1] Gestión de Casos**
```
🔹 Crear Nuevo Caso
🔹 Listar Casos Existentes  
🔹 Seleccionar Caso Activo
🔹 Ver Información del Caso
🔹 Eliminar Casos
```
**Características:**
- ✅ Metadatos completos (ID, investigador, organización, descripción)
- ✅ Estructura de directorios automática
- ✅ Validación de datos de entrada
- ✅ Gestión de casos múltiples

### 🔍 **[2] Análisis Forense**
```
🔹 Recopilar Información del Sistema
🔹 Analizar Procesos en Ejecución
🔹 Examinar Conexiones de Red
🔹 Inventariar Software Instalado
🔹 Extraer Archivos del Sistema
🔹 Analizar Registro de Windows
```
**Datos Recopilados:**
- 💻 **Sistema**: CPU, RAM, OS, arquitectura, usuarios
- 🔄 **Procesos**: PID, nombre, memoria, CPU, ruta ejecutable
- 🌐 **Red**: Conexiones TCP/UDP, puertos, IPs locales/remotas
- 📦 **Software**: Programas instalados, versiones, ubicaciones
- 📂 **Archivos**: Logs del sistema, archivos temporales, configuraciones
- 🗃️ **Registro**: Claves críticas del sistema y aplicaciones

### 📄 **[3] Generación de Reportes**
```
🔹 Reporte HTML Interactivo
🔹 Exportación JSON Estructurada
🔹 Resumen Ejecutivo
🔹 Detalles Técnicos
```
**Características de Reportes:**
- 🎨 **HTML**: Diseño profesional con CSS, tablas interactivas
- 📋 **JSON**: Datos estructurados para análisis posterior
- 📊 **Estadísticas**: Métricas detalladas del sistema
- 🔍 **Búsqueda**: Filtros por tipo de evidencia

### 🔗 **[4] Cadena de Custodia**
```
🔹 Registro Automático de Acciones
🔹 Historial Completo
🔹 Búsqueda por Evidencia
🔹 Estadísticas de Custodia
🔹 Exportación de Registros
```
**Trazabilidad Completa:**
- ⏰ **Timestamp**: Fecha y hora exacta de cada acción
- 👤 **Usuario**: Identificación del investigador
- 📝 **Descripción**: Detalle de la acción realizada
- 🔒 **Integridad**: Hash de verificación de evidencia

### ⚙️ **[5] Configuración y Herramientas**
```
🔹 Configuración del Sistema
🔹 Verificación de Integridad
🔹 Limpieza de Archivos Temporales
🔹 Estadísticas del Sistema
🔹 Monitoreo en Tiempo Real
```

## 🔧 Solución de Problemas

### 🚨 **Problemas Comunes del Ejecutable**

#### ❌ **"El ejecutable no inicia"**
```cmd
# Verificar permisos de administrador
# Clic derecho en ForenseCTL.exe → "Ejecutar como administrador"

# O desde PowerShell como administrador:
cd ForenseCTL_Distribution
.\ForenseCTL.exe
```

#### ❌ **"Error de acceso denegado"**
```cmd
# Solución: Ejecutar como administrador
# Necesario para recopilación completa de evidencia del sistema
```

#### ❌ **"No se pueden crear archivos"**
```cmd
# Verificar espacio en disco (mínimo 1GB)
# Verificar permisos de escritura en la carpeta
```

#### ❌ **"El análisis no recopila datos"**
```cmd
# Verificar que Windows Defender no bloquee el ejecutable
# Agregar excepción en el antivirus si es necesario
```

### ✅ **Verificación de Funcionamiento**

```cmd
# 1. Verificar que el ejecutable funciona
ForenseCTL_Distribution\ForenseCTL.exe

# 2. Crear caso de prueba
# Usar opción [1] en el menú → "Crear Nuevo Caso"

# 3. Ejecutar análisis básico
# Usar opción [2] en el menú → "Recopilar Información del Sistema"

# 4. Generar reporte de prueba
# Usar opción [3] en el menú → "Generar Reporte HTML"
```

### 🛠️ **Solución de Problemas Avanzados**

<details>
<summary>🔍 Problemas de desarrollo (código fuente)</summary>

#### Error: "No module named 'forensectl'"
```bash
# Solución: Instalar dependencias
pip install psutil platform-info
```

#### Error: "forensectl_standalone.py not found"
```bash
# El archivo fue eliminado después de la compilación
# Recrear desde el repositorio si necesitas modificar el código
```

</details>

## 🏗️ Arquitectura del Sistema

### 📁 **Estructura Actual (Optimizada)**

```
ForenseCTL/
├── 📄 LICENSE                     # Licencia MIT
├── 📖 README.md                   # Documentación principal
└── 📦 ForenseCTL_Distribution/    # 🎯 EJECUTABLE STANDALONE
    ├── 🚀 ForenseCTL.exe          # Ejecutable principal (8.44MB)
    ├── 📋 README.md               # Guía de uso del ejecutable
    ├── ⚙️ install.bat             # Script de instalación automática
    └── 📂 forensics_workspace/    # Espacio de trabajo
        ├── 📁 cases/              # Casos forenses creados
        ├── 🔍 evidence/           # Evidencia recopilada
        ├── 📄 reports/            # Reportes generados
        └── 🎨 templates/          # Plantillas de reportes
```

### 🔧 **Arquitectura Interna del Ejecutable**

```
ForenseCTL.exe (Standalone)
├── 🎯 Core System
│   ├── CaseManager           # Gestión de casos forenses
│   ├── RealSystemAnalyzer    # Análisis del sistema Windows
│   ├── ChainOfCustody        # Cadena de custodia automática
│   └── ReportGenerator       # Generación de reportes
├── 🔍 Evidence Collection
│   ├── System Information    # Hardware, OS, usuarios
│   ├── Process Analysis      # Procesos en ejecución
│   ├── Network Connections   # Conexiones TCP/UDP
│   ├── Installed Software    # Programas instalados
│   ├── System Files         # Archivos críticos y logs
│   └── Windows Registry     # Claves del registro
├── 📊 Report Generation
│   ├── HTML Reports         # Reportes interactivos
│   ├── JSON Export          # Datos estructurados
│   ├── Executive Summary    # Resumen ejecutivo
│   └── Technical Details    # Detalles técnicos
└── 🖥️ Interactive Interface
    ├── Main Menu            # Menú principal
    ├── Case Management      # Gestión de casos
    ├── Analysis Tools       # Herramientas de análisis
    └── Configuration        # Configuración del sistema
```

### 🎯 **Ventajas de la Arquitectura Standalone**

| Característica | Beneficio |
|----------------|----------|
| 🚀 **Ejecutable Único** | Sin dependencias externas, fácil distribución |
| 📦 **Todo Incluido** | Todas las funcionalidades en un solo archivo |
| 🔒 **Seguro** | Sin instalación, sin modificación del sistema |
| 💾 **Ligero** | Solo 8.44MB, optimizado para rendimiento |
| 🖥️ **Portable** | Funciona desde cualquier ubicación |
| ⚡ **Rápido** | Inicio inmediato, sin tiempo de carga |

### 🔄 **Flujo de Datos**

```
[Sistema Windows] → [Recopilación] → [Análisis] → [Reportes] → [Cadena de Custodia]
       ↓                ↓              ↓           ↓              ↓
   Hardware/SW    →  Evidencia   →  Procesado  →  HTML/JSON  →  Registro
   Procesos/Red   →  Temporal    →  Validado   →  Exportado  →  Automático
   Registro/Logs  →  Estructurado → Analizado  →  Formateado →  Trazable
```

## 📚 Documentación y Recursos

### 📖 **Documentación Incluida**
- 📋 **README.md Principal**: Guía completa del sistema
- 📄 **README.md del Ejecutable**: Instrucciones específicas de uso
- ❓ **Ayuda Integrada**: Opción [6] en el menú principal
- 🔧 **Solución de Problemas**: Sección completa en este documento

### 🎓 **Recursos de Aprendizaje**
- 🖥️ **Interfaz Intuitiva**: Menú autoexplicativo con navegación guiada
- 🔍 **Análisis Paso a Paso**: Flujo de trabajo estructurado
- 📊 **Reportes de Ejemplo**: Generación automática para aprendizaje
- 🔗 **Cadena de Custodia**: Registro automático para comprensión del proceso

## 🔒 Seguridad y Compliance

### 🛡️ **Características de Seguridad**
- ✅ **Cadena de Custodia Automática**: Registro completo de todas las acciones
- ✅ **Verificación de Integridad**: Hash de archivos y evidencia
- ✅ **Acceso Controlado**: Requiere permisos de administrador para análisis completo
- ✅ **Evidencia Read-Only**: No modifica archivos del sistema original
- ✅ **Registro Detallado**: Timestamp y trazabilidad completa
- ✅ **Exportación Segura**: Formatos estándar (HTML, JSON) sin ejecutables

### 🔐 **Compliance Forense**
- 📋 **Estándares**: Cumple con mejores prácticas de análisis forense digital
- 🔍 **Trazabilidad**: Registro completo de la cadena de custodia
- 📝 **Documentación**: Reportes detallados para uso legal
- ⚖️ **Integridad**: Verificación de hash para validación de evidencia

## 🧪 Verificación y Testing

### ✅ **Verificación del Ejecutable**

```cmd
# 1. Verificar funcionamiento básico
ForenseCTL_Distribution\ForenseCTL.exe

# 2. Crear caso de prueba
# Menú [1] → Crear Nuevo Caso → Datos de prueba

# 3. Ejecutar análisis de prueba
# Menú [2] → Recopilar Información del Sistema

# 4. Generar reporte de prueba
# Menú [3] → Generar Reporte HTML

# 5. Verificar cadena de custodia
# Menú [4] → Ver Historial de Acciones
```

### 🔍 **Validación de Resultados**
- 📊 **Reportes HTML**: Verificar que se generan correctamente
- 📋 **Datos JSON**: Validar estructura y contenido
- 🔗 **Cadena de Custodia**: Confirmar registro de acciones
- 📁 **Estructura de Archivos**: Verificar organización de casos

## 🤝 Contribución y Desarrollo

### 🚀 **¿Quieres Contribuir?**

¡Las contribuciones son bienvenidas! El sistema está diseñado para ser fácilmente extensible:

1. **🍴 Fork** el repositorio
2. **🌿 Crea** una rama para tu funcionalidad (`git checkout -b feature/nueva-funcionalidad`)
3. **💻 Desarrolla** siguiendo las convenciones del código existente
4. **🧪 Prueba** tu código con el ejecutable
5. **📝 Commit** tus cambios (`git commit -m 'Añadir nueva funcionalidad'`)
6. **📤 Push** a tu rama (`git push origin feature/nueva-funcionalidad`)
7. **🔄 Abre** un Pull Request

### 🎯 **Áreas de Contribución**

| Área | Descripción | Dificultad |
|------|-------------|------------|
| 🔍 **Nuevos Analizadores** | Módulos de análisis específicos | 🟡 Media |
| 🎨 **Plantillas de Reportes** | Nuevos formatos y estilos | 🟢 Fácil |
| 📊 **Recopiladores de Evidencia** | Nuevas fuentes de datos | 🟡 Media |
| 🖥️ **Mejoras de UI** | Interfaz más intuitiva | 🟢 Fácil |
| 📚 **Documentación** | Guías y tutoriales | 🟢 Fácil |
| 🧪 **Testing** | Casos de prueba y validación | 🟡 Media |
| 🔧 **Optimización** | Mejoras de rendimiento | 🔴 Difícil |

### 💡 **Ideas para Nuevas Funcionalidades**
- 🌐 **Análisis de Red Avanzado**: Captura de tráfico, análisis de protocolos
- 🔐 **Análisis de Malware**: Detección de patrones maliciosos
- 📱 **Soporte Multi-plataforma**: Linux, macOS
- 🎨 **Interfaz Gráfica**: GUI con Qt o Tkinter
- ☁️ **Integración Cloud**: Análisis en la nube
- 🤖 **IA/ML**: Detección automática de anomalías

## ⚖️ Consideraciones Legales

### ⚠️ **USO RESPONSABLE**

**Esta herramienta está diseñada EXCLUSIVAMENTE para:**

✅ **Usos Autorizados:**
- 🏢 Análisis forense autorizado en entornos corporativos
- 🚨 Respuesta a incidentes en infraestructura propia
- 🔍 Investigaciones con autorización legal explícita
- 🎓 Entornos de laboratorio y educación
- 🛡️ Auditorías de seguridad autorizadas

❌ **Usos Prohibidos:**
- 🚫 Análisis no autorizado de sistemas ajenos
- 🚫 Violación de privacidad
- 🚫 Actividades ilegales o maliciosas
- 🚫 Uso sin consentimiento del propietario

### 📋 **Responsabilidad del Usuario**

**⚠️ IMPORTANTE**: El uso no autorizado de estas herramientas puede violar leyes locales e internacionales. Los usuarios son completamente responsables de:

- ✅ Obtener autorización legal antes del uso
- ✅ Cumplir con todas las regulaciones aplicables
- ✅ Respetar la privacidad y derechos de terceros
- ✅ Usar la herramienta de manera ética y legal

## 📁 **Estructura del Proyecto**

```
ForenseCTL/
├── 📁 ForenseCTL_Distribution/          # 🖥️ Distribución Windows
│   ├── ForenseCTL.exe                   # Ejecutable principal (8.44MB)
│   ├── install.bat                      # Instalador Windows
│   ├── README.md                        # Documentación Windows
│   └── forensics_workspace/             # Espacio de trabajo
├── 📁 ForenseCTL_Linux_Distribution/    # 🐧 Distribución Linux
│   ├── forensectl_linux.py              # Script principal Linux
│   ├── install_linux.sh                 # Instalador Linux
│   ├── quick_start.sh                   # Inicio rápido
│   ├── requirements.txt                 # Dependencias Python
│   ├── docs/                            # Documentación adicional
│   ├── examples/                        # Scripts de ejemplo
│   └── README.md                        # Documentación Linux
├── 📄 README.md                         # Documentación principal
├── 📄 LICENSE                           # Licencia MIT
└── 📦 ForenseCTL_Linux_v1.0_YYYYMMDD.zip # Paquete distribución Linux
```

## 🆕 **Novedades de la Versión**

### ✨ **v1.0 - Soporte Multiplataforma**
- 🐧 **Nuevo**: Soporte completo para Linux
- 🖥️ **Mejorado**: Optimización del ejecutable Windows
- 📦 **Nuevo**: Gestión de paquetes Linux (apt, yum, pacman)
- 🔧 **Nuevo**: Análisis de servicios systemd
- 📁 **Nuevo**: Análisis de configuraciones Linux
- 🚀 **Nuevo**: Scripts de instalación automática
- 📚 **Mejorado**: Documentación multiplataforma

## 📄 Licencia

### 📜 **Licencia MIT**

Este proyecto está licenciado bajo la **Licencia MIT** - consulta el archivo [LICENSE](LICENSE) para más detalles.

| Permisos | Limitaciones | Condiciones |
|----------|--------------|-------------|
| ✅ Uso comercial | ❌ Sin garantía | 📋 Incluir licencia |
| ✅ Modificación | ❌ Sin responsabilidad | 📋 Incluir copyright |
| ✅ Distribución | | |
| ✅ Uso privado | | |

## 🙏 Agradecimientos

### 🛠️ **Tecnologías Utilizadas**
- 🐍 **Python Community** - Por el excelente ecosistema de desarrollo
- 📊 **psutil** - Información detallada del sistema Windows
- 🖥️ **platform** - Detalles de la plataforma y arquitectura
- 📦 **PyInstaller** - Compilación a ejecutable standalone
- 🎨 **HTML/CSS** - Reportes profesionales y atractivos

### 🌟 **Comunidad**
- 🛡️ **Comunidad DFIR** - Por compartir conocimiento y mejores prácticas
- 🔵 **Blue Team Community** - Por la inspiración y feedback
- 🎓 **Comunidad Académica** - Por los fundamentos teóricos
- 💻 **Desarrolladores Open Source** - Por las herramientas y librerías

---

## 📞 Soporte y Contacto

### 🐛 **Reportar Problemas**
- **GitHub Issues**: [Crear nuevo issue](https://github.com/ismaiars/ForenseCTL/issues)
- **Email**: iarsfate@gmail.com
- **Documentación**: Wiki del proyecto

### 🤝 **Contribuciones**
¡Las contribuciones son bienvenidas! Por favor:
1. Fork el repositorio
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

---

<div align="center">

## 🎯 **ForenseCTL Multiplataforma**

**Sistema Completo de Análisis Forense Digital**  
*Desarrollado para profesionales de ciberseguridad y equipos DFIR*

### 🚀 **Windows: 8.44MB • Linux: Script Python • Portable • Sin Dependencias**

---

**Desarrollado con ❤️ para la comunidad de Blue Team y DFIR**

[![⭐ Star en GitHub](https://img.shields.io/badge/⭐-Star%20en%20GitHub-yellow?style=for-the-badge)](https://github.com/ismaiars/ForenseCTL)
[![📥 Windows](https://img.shields.io/badge/📥-Windows%20EXE-0078D4?style=for-the-badge&logo=windows)](ForenseCTL_Distribution/ForenseCTL.exe)
[![📥 Linux](https://img.shields.io/badge/📥-Linux%20Script-FCC624?style=for-the-badge&logo=linux)](ForenseCTL_Linux_Distribution/)
[![📖 Documentación](https://img.shields.io/badge/📖-Documentación-blue?style=for-the-badge)](README.md)

</div>