# 🐧 ForenseCTL Linux - Sistema de Análisis Forense Digital

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)](https://www.linux.org/)
[![Status](https://img.shields.io/badge/status-Production%20Ready-00C851?logo=checkmarx&logoColor=white)](https://github.com/ismaiars/ForenseCTL)
[![Portable](https://img.shields.io/badge/Portable-Ready-FF6900?logo=files&logoColor=white)](forensectl_linux.py)

</div>

## 🎯 Descripción

**ForenseCTL Linux** es la versión multiplataforma del sistema de análisis forense digital, específicamente adaptada para distribuciones Linux 🐧. Diseñado para profesionales de ciberseguridad, equipos DFIR y analistas forenses que trabajan en entornos Linux, proporciona un ciclo completo de investigación forense: **recopilación → análisis → reportes → cadena de custodia**.

### 🌟 **¿Por qué ForenseCTL Linux?**

✅ **Multiplataforma**: Compatible con las principales distribuciones Linux  
✅ **Script Único**: Sin compilación, ejecutable directamente con Python  
✅ **Análisis Completo**: Recopilación automática de evidencia del sistema Linux  
✅ **Reportes Profesionales**: HTML y JSON con diseño técnico-profesional  
✅ **Cadena de Custodia**: Registro automático de todas las acciones  
✅ **Interfaz Intuitiva**: Menú interactivo fácil de usar  
✅ **Código Abierto**: Totalmente modificable y auditable

## 🐧 Distribuciones Linux Soportadas

| Distribución | Gestor de Paquetes | Estado | Notas |
|--------------|-------------------|--------|-------|
| 🟢 **Ubuntu** | apt/dpkg | ✅ Completo | Totalmente soportado |
| 🟢 **Debian** | apt/dpkg | ✅ Completo | Totalmente soportado |
| 🟢 **CentOS** | yum/rpm | ✅ Completo | Versiones 7, 8, 9 |
| 🟢 **RHEL** | yum/dnf/rpm | ✅ Completo | Red Hat Enterprise |
| 🟢 **Fedora** | dnf/rpm | ✅ Completo | Versiones recientes |
| 🟢 **Arch Linux** | pacman | ✅ Completo | Rolling release |
| 🟢 **Manjaro** | pacman | ✅ Completo | Basado en Arch |
| 🟢 **openSUSE** | zypper/rpm | ✅ Completo | Leap y Tumbleweed |
| 🟡 **Otras** | Varios | ⚠️ Básico | Funcionalidad limitada |

## ✨ Funcionalidades Específicas para Linux

### 🎯 **Núcleo del Sistema**
- 📁 **Gestión Completa de Casos**: Creación, administración y seguimiento de casos forenses
- 🔍 **Recopilación Automática**: Extracción de artefactos del sistema Linux en tiempo real
- ⚙️ **Análisis Forense Integral**: Análisis completo del sistema, procesos y red
- 📄 **Reportes Profesionales**: Generación automática en HTML y JSON
- 🔗 **Cadena de Custodia**: Registro automático y completo de todas las acciones

### 🖥️ **Recopilación de Evidencia Linux**
- 💻 **Información del Sistema**: Hardware, distribución, kernel, arquitectura, usuarios activos
- 🔄 **Procesos en Ejecución**: Lista completa con PID, memoria, CPU, rutas y líneas de comando
- 🌐 **Conexiones de Red**: TCP/UDP activas, puertos locales y remotos
- 📦 **Paquetes Instalados**: Software instalado via apt/yum/pacman/zypper
- 📂 **Archivos Críticos**: Logs del sistema, configuraciones, historiales de bash
- 👥 **Usuarios del Sistema**: Información de /etc/passwd, usuarios activos, sesiones
- 🔐 **Archivos de Seguridad**: /etc/shadow, /etc/group, configuraciones SSH

### 📊 **Análisis y Reportes**
- 📈 **Análisis Estadístico**: Métricas detalladas del sistema y evidencia
- 🎨 **Reportes HTML**: Diseño profesional con gráficos y tablas interactivas
- 📋 **Exportación JSON**: Datos estructurados para análisis posterior
- 🔍 **Búsqueda Avanzada**: Filtros por tipo de evidencia y criterios específicos
- 📝 **Documentación Automática**: Generación de informes técnicos completos
- 🔒 **Verificación de Integridad**: Hashes SHA256 de archivos críticos

### 🛠️ **Herramientas Integradas**
- ✅ **Detección Automática**: Identificación de distribución y gestor de paquetes
- 🧹 **Análisis de Logs**: Extracción de información de /var/log/
- 📈 **Monitoreo en Tiempo Real**: Estado del sistema y recursos
- 🔒 **Seguridad**: Manejo seguro de evidencia con verificación de integridad
- 🖥️ **Interfaz Intuitiva**: Menú interactivo con navegación fácil y clara

## 🚀 Instalación y Configuración

### 📦 **Instalación Automática (Recomendada)**

**¡La forma más fácil de instalar ForenseCTL Linux!** 🎯

```bash
# 1. Descargar ForenseCTL Linux
wget https://github.com/ismaiars/ForenseCTL/archive/main.zip
unzip main.zip
cd ForenseCTL-main

# 2. Ejecutar instalador automático
chmod +x install_linux.sh
sudo ./install_linux.sh

# 3. ¡Listo! Ejecutar ForenseCTL
forensectl
```

### 🔧 **Instalación Manual**

```bash
# 1. Verificar Python 3.6+
python3 --version

# 2. Instalar dependencias
pip3 install psutil

# 3. Descargar ForenseCTL Linux
wget https://raw.githubusercontent.com/ismaiars/ForenseCTL/main/forensectl_linux.py
chmod +x forensectl_linux.py

# 4. Ejecutar
python3 forensectl_linux.py
```

### 🖥️ **Requisitos del Sistema**

| Componente | Mínimo | Recomendado |
|------------|--------|-------------|
| 🐧 **OS** | Linux Kernel 3.0+ | Linux Kernel 5.0+ |
| 🐍 **Python** | 3.6+ | 3.8+ |
| 💾 **RAM** | 2GB | 4GB+ |
| 💿 **Disco** | 500MB libre | 2GB+ |
| 👤 **Permisos** | Usuario | Root/sudo* |

*_Root requerido para recopilación completa de evidencia_

### ⚡ **Inicio Rápido**

```bash
# Método 1: Instalación global
sudo ./install_linux.sh
forensectl

# Método 2: Ejecución directa
python3 forensectl_linux.py

# Método 3: Como root para análisis completo
sudo python3 forensectl_linux.py
```

### 📋 **Dependencias**

**Dependencias Python requeridas:**
```bash
psutil>=5.8.0    # Información del sistema
```

**Módulos estándar incluidos:**
- `platform` - Información de la plataforma
- `json`, `datetime`, `pathlib` - Utilidades estándar
- `os`, `sys`, `subprocess` - Interacción con el sistema
- `hashlib` - Verificación de integridad

## 🚀 Guía de Uso

### 🎯 **Primer Uso**

1. **🚀 Iniciar ForenseCTL Linux**:
   ```bash
   # Como usuario normal
   python3 forensectl_linux.py
   
   # Como root (recomendado para análisis completo)
   sudo python3 forensectl_linux.py
   ```

2. **📋 Menú Principal** - Verás estas opciones:
   ```
   ╔══════════════════════════════════════════════════════════════╗
   ║                    FORENSECTL LINUX                         ║
   ║              ANÁLISIS FORENSE DIGITAL                       ║
   ║                   Versión Linux 1.0                         ║
   ╚══════════════════════════════════════════════════════════════╝
   
   [1] 📁 Gestión de Casos
   [2] 🔍 Análisis Forense del Sistema
   [3] 📄 Generación de Reportes
   [4] 🔗 Cadena de Custodia
   [5] ⚙️  Configuración y Herramientas
   [6] ❓ Ayuda
   [0] 🚪 Salir
   ```

### 🔄 **Flujo de Trabajo Recomendado**

1. **📁 Crear Caso** → Opción [1] → "Crear nuevo caso"
2. **🔍 Análisis** → Opción [2] → "Análisis completo del sistema"
3. **📄 Reporte** → Opción [3] → "Generar ambos reportes"
4. **🔗 Verificar** → Opción [4] → "Ver cadena de custodia"

### 📊 **Funcionalidades Principales**

| Opción | Funcionalidad | Descripción |
|--------|---------------|-------------|
| **[1]** | 📁 Gestión de Casos | Crear, listar y seleccionar casos forenses |
| **[2]** | 🔍 Análisis Forense | Recopilación completa de evidencia del sistema |
| **[3]** | 📄 Reportes | Generación de reportes HTML y JSON |
| **[4]** | 🔗 Cadena de Custodia | Registro y verificación de acciones |
| **[5]** | ⚙️ Configuración | Herramientas y configuración del sistema |

## 🔧 Detalles de Funcionalidades

### 📁 **[1] Gestión de Casos**
```
🔹 Crear Nuevo Caso Forense
🔹 Listar Casos Existentes
🔹 Seleccionar Caso Activo
🔹 Información del Investigador
🔹 Descripción del Caso
```

**Datos recopilados:**
- ID único del caso con timestamp
- Nombre del caso y descripción
- Investigador responsable
- Fecha y hora de creación
- Estado del caso (activo/cerrado)

### 🔍 **[2] Análisis Forense del Sistema**
```
🔹 Análisis Completo del Sistema Linux
🔹 Recopilación de Procesos en Ejecución
🔹 Análisis de Conexiones de Red
🔹 Inventario de Paquetes Instalados
🔹 Análisis de Archivos Críticos
```

**Datos recopilados:**
- **Sistema**: Hostname, distribución, kernel, arquitectura, hardware
- **Procesos**: PID, nombre, usuario, estado, memoria, CPU, línea de comando
- **Red**: Conexiones TCP/UDP, puertos, direcciones IP, estado
- **Paquetes**: Software instalado con versiones (apt/yum/pacman/zypper)
- **Archivos**: Logs críticos, configuraciones, historiales, hashes SHA256
- **Usuarios**: Información de /etc/passwd, sesiones activas, permisos

### 📄 **[3] Generación de Reportes**
```
🔹 Reporte HTML Profesional
🔹 Exportación de Datos JSON
🔹 Resumen Ejecutivo
🔹 Detalles Técnicos Completos
🔹 Gráficos y Tablas Interactivas
```

**Características de los reportes:**
- **HTML**: Diseño profesional, tablas interactivas, gráficos
- **JSON**: Datos estructurados para análisis posterior
- **Integridad**: Verificación SHA256 de archivos
- **Timestamp**: Marca de tiempo de generación
- **Metadatos**: Información del caso y sistema

### 🔗 **[4] Cadena de Custodia**
```
🔹 Registro Automático de Acciones
🔹 Timestamp de Todas las Operaciones
🔹 Verificación de Integridad
🔹 Trazabilidad Completa
🔹 Historial de Modificaciones
```

**Información registrada:**
- 🕐 **Timestamp**: Fecha y hora exacta de cada acción
- 👤 **Usuario**: Quién realizó la acción
- 🔧 **Acción**: Tipo de operación realizada
- 📝 **Descripción**: Detalle de la acción realizada
- 🔒 **Integridad**: Hash de verificación de evidencia

### ⚙️ **[5] Configuración y Herramientas**
```
🔹 Verificación de Dependencias
🔹 Información del Sistema
🔹 Limpieza de Archivos Temporales
🔹 Estadísticas del Sistema
🔹 Configuración de Parámetros
```

## 🔧 Solución de Problemas

### 🚨 **Problemas Comunes**

#### ❌ **"Python 3 no encontrado"**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install python3 python3-pip

# CentOS/RHEL/Fedora
sudo dnf install python3 python3-pip
# o para versiones antiguas:
sudo yum install python3 python3-pip

# Arch Linux
sudo pacman -S python python-pip
```

#### ❌ **"No module named 'psutil'"**
```bash
# Instalación global
sudo pip3 install psutil

# Instalación local
pip3 install --user psutil

# Desde repositorios del sistema
# Ubuntu/Debian:
sudo apt install python3-psutil
# CentOS/RHEL/Fedora:
sudo dnf install python3-psutil
```

#### ❌ **"Permission denied" al acceder a archivos**
```bash
# Ejecutar como root para análisis completo
sudo python3 forensectl_linux.py

# O cambiar permisos específicos (no recomendado)
sudo chmod +r /etc/shadow
```

#### ❌ **"No se pueden crear archivos"**
```bash
# Verificar espacio en disco
df -h

# Verificar permisos de escritura
ls -la ./forensics_workspace/

# Crear directorios manualmente si es necesario
mkdir -p ./forensics_workspace/{cases,evidence,reports,templates}
```

### ✅ **Verificación de Funcionamiento**

```bash
# 1. Verificar Python y dependencias
python3 -c "import psutil, json, datetime, platform; print('✅ Dependencias OK')"

# 2. Verificar permisos
whoami
id

# 3. Ejecutar test básico
python3 forensectl_linux.py
# Crear caso de prueba → Análisis básico → Generar reporte

# 4. Verificar archivos generados
ls -la ./forensics_workspace/
ls -la ./forensics_workspace/cases/
ls -la ./forensics_workspace/evidence/
ls -la ./forensics_workspace/reports/
```

### 🛠️ **Solución de Problemas por Distribución**

<details>
<summary>🟢 Ubuntu/Debian</summary>

```bash
# Actualizar repositorios
sudo apt update

# Instalar dependencias completas
sudo apt install python3 python3-pip python3-dev python3-psutil

# Si hay problemas con pip
sudo apt install python3-setuptools

# Verificar instalación
python3 --version
pip3 --version
```

</details>

<details>
<summary>🟢 CentOS/RHEL/Fedora</summary>

```bash
# Para CentOS/RHEL 8+
sudo dnf install python3 python3-pip python3-devel python3-psutil

# Para CentOS/RHEL 7
sudo yum install python3 python3-pip python3-devel
sudo pip3 install psutil

# Habilitar EPEL si es necesario
sudo yum install epel-release
```

</details>

<details>
<summary>🟢 Arch Linux/Manjaro</summary>

```bash
# Instalar dependencias
sudo pacman -S python python-pip python-psutil

# Actualizar sistema si hay problemas
sudo pacman -Syu

# Verificar instalación
python --version
pip --version
```

</details>

## 🏗️ Arquitectura del Sistema

### 📁 **Estructura del Proyecto**

```
ForenseCTL-Linux/
├── 📄 forensectl_linux.py         # Script principal
├── 📄 install_linux.sh            # Instalador automático
├── 📖 README_Linux.md             # Documentación Linux
├── 📄 LICENSE                     # Licencia MIT
└── 📂 forensics_workspace/        # Espacio de trabajo
    ├── 📁 cases/                  # Casos forenses creados
    ├── 🔍 evidence/               # Evidencia recopilada
    ├── 📄 reports/                # Reportes generados
    └── 🎨 templates/              # Plantillas de reportes
```

### 🔧 **Arquitectura Interna**

```
forensectl_linux.py
├── 🎯 LinuxSystemAnalyzer
│   ├── get_system_information()    # Info del sistema Linux
│   ├── get_running_processes()     # Procesos en ejecución
│   ├── get_network_connections()   # Conexiones de red
│   ├── get_installed_packages()    # Paquetes instalados
│   ├── get_system_files()          # Archivos críticos
│   ├── get_users_info()            # Información de usuarios
│   └── collect_all_evidence()      # Recopilación completa
├── 📁 CaseManager
│   ├── create_case()               # Crear nuevo caso
│   ├── list_cases()                # Listar casos
│   └── workspace management        # Gestión del workspace
├── 📊 ReportGenerator
│   ├── generate_html_report()      # Reportes HTML
│   ├── generate_json_report()      # Reportes JSON
│   └── template management         # Gestión de plantillas
└── 🖥️ Interactive Interface
    ├── show_banner()               # Banner del sistema
    ├── show_menu()                 # Menú principal
    ├── main()                      # Función principal
    └── error handling              # Manejo de errores
```

### 🎯 **Ventajas de la Arquitectura**

| Característica | Beneficio |
|----------------|----------|
| 🐍 **Python Puro** | Sin compilación, fácil modificación |
| 📦 **Modular** | Componentes independientes y reutilizables |
| 🔧 **Extensible** | Fácil añadir nuevas funcionalidades |
| 🐧 **Multiplataforma** | Compatible con múltiples distribuciones |
| 🔒 **Seguro** | Verificación de integridad y logs |
| 📊 **Escalable** | Manejo eficiente de grandes volúmenes |

### 🔄 **Flujo de Datos**

```
[Sistema Linux] → [Recopilación] → [Análisis] → [Almacenamiento] → [Reportes]
       ↓              ↓             ↓             ↓              ↓
   Procesos      psutil API    Procesamiento   JSON Files    HTML/JSON
   Archivos      subprocess    Verificación    Evidence      Reports
   Red           /proc         Integridad      Cases         Chain
   Paquetes      /etc          Timestamp       Workspace     Custody
```

## 🔒 Seguridad y Compliance

### 🛡️ **Características de Seguridad**
- ✅ **Cadena de Custodia Automática**: Registro completo de todas las acciones
- ✅ **Verificación de Integridad**: Hash SHA256 de archivos críticos
- ✅ **Acceso Controlado**: Requiere permisos de root para análisis completo
- ✅ **Evidencia Read-Only**: No modifica archivos del sistema original
- ✅ **Registro Detallado**: Timestamp y trazabilidad completa
- ✅ **Exportación Segura**: Formatos estándar sin ejecutables
- ✅ **Almacenamiento Local**: Todos los datos permanecen en el sistema local

### 🔐 **Compliance Forense**
- 📋 **Estándares**: Cumple con mejores prácticas de análisis forense digital
- 🔍 **Trazabilidad**: Registro completo de la cadena de custodia
- 📝 **Documentación**: Reportes detallados para uso legal
- ⚖️ **Integridad**: Verificación de hash para validación de evidencia
- 🔒 **Privacidad**: Sin conexiones externas no autorizadas

### 🛡️ **Consideraciones de Seguridad Linux**
- 🔐 **Permisos**: Respeta el modelo de permisos de Linux
- 📂 **Acceso a Archivos**: Solo lee archivos accesibles según permisos
- 👤 **Usuarios**: Análisis de usuarios y grupos del sistema
- 🔍 **Logs**: Extracción segura de logs del sistema
- 🌐 **Red**: Análisis de conexiones sin interceptación

## 🧪 Verificación y Testing

### ✅ **Test de Instalación**

```bash
# 1. Test de dependencias
python3 -c "import psutil, json, datetime, platform, pathlib, os, sys, subprocess, hashlib; print('✅ Todas las dependencias OK')"

# 2. Test de permisos
whoami
groups
id

# 3. Test de funcionalidad básica
python3 forensectl_linux.py
# Crear caso → Análisis → Reporte → Verificar archivos
```

### 🔍 **Test de Funcionalidades**

```bash
# 1. Test de recopilación de sistema
python3 -c "from forensectl_linux import LinuxSystemAnalyzer; a=LinuxSystemAnalyzer(); a.get_system_information(); print('✅ Sistema OK')"

# 2. Test de procesos
python3 -c "import psutil; print(f'✅ Procesos: {len(list(psutil.process_iter()))}')"

# 3. Test de red
python3 -c "import psutil; print(f'✅ Conexiones: {len(psutil.net_connections())}')"

# 4. Test de archivos
ls -la /etc/passwd /etc/hosts /var/log/ 2>/dev/null | wc -l
```

### 📊 **Validación de Resultados**
- 📄 **Reportes HTML**: Verificar que se generan correctamente
- 📋 **Datos JSON**: Validar estructura y contenido
- 🔒 **Hashes**: Verificar integridad de archivos
- 📁 **Casos**: Confirmar creación y gestión
- 🔗 **Cadena de Custodia**: Validar registro de acciones

## 🤝 Contribución y Desarrollo

### 🛠️ **Cómo Contribuir**

ForenseCTL Linux es un proyecto de código abierto que acepta contribuciones de la comunidad:

1. **🍴 Fork** del repositorio
2. **🌿 Crear** una rama para tu funcionalidad
3. **💻 Desarrollar** y probar los cambios
4. **📝 Documentar** las modificaciones
5. **🔄 Pull Request** con descripción detallada

### 📋 **Áreas de Contribución**

| Área | Dificultad | Descripción |
|------|------------|-------------|
| 🐛 **Bug Fixes** | 🟢 Fácil | Corrección de errores reportados |
| 📖 **Documentación** | 🟢 Fácil | Mejoras en README y comentarios |
| 🔧 **Nuevas Funcionalidades** | 🟡 Medio | Análisis adicionales, nuevos formatos |
| 🎨 **Interfaz** | 🟡 Medio | Mejoras en la interfaz de usuario |
| 🏗️ **Arquitectura** | 🔴 Difícil | Optimizaciones de rendimiento |
| 🔒 **Seguridad** | 🔴 Difícil | Auditorías y mejoras de seguridad |

### 💡 **Ideas para Nuevas Funcionalidades**
- 🔐 **Análisis de Malware**: Detección de patrones maliciosos
- 📱 **Soporte para Contenedores**: Análisis de Docker/Podman
- 🎨 **Interfaz Gráfica**: GUI con Qt o Tkinter
- ☁️ **Integración Cloud**: Análisis en la nube
- 🤖 **IA/ML**: Detección automática de anomalías
- 📊 **Visualizaciones**: Gráficos avanzados y dashboards

### 🔧 **Configuración de Desarrollo**

```bash
# 1. Clonar repositorio
git clone https://github.com/ismaiars/ForenseCTL.git
cd ForenseCTL

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias de desarrollo
pip install psutil pytest black flake8

# 4. Ejecutar tests
python -m pytest tests/

# 5. Formatear código
black forensectl_linux.py
flake8 forensectl_linux.py
```

## ⚖️ Consideraciones Legales

### ⚠️ **USO RESPONSABLE**

**Esta herramienta está diseñada EXCLUSIVAMENTE para:**

✅ **Usos Autorizados:**
- 🏢 Análisis forense autorizado en entornos corporativos
- 🚨 Respuesta a incidentes en infraestructura propia
- 🔍 Investigaciones con autorización legal explícita
- 🎓 Entornos de laboratorio y educación
- 🛡️ Auditorías de seguridad autorizadas
- 🐧 Administración de sistemas Linux propios

❌ **Usos Prohibidos:**
- 🚫 Análisis no autorizado de sistemas ajenos
- 🚫 Violación de privacidad
- 🚫 Actividades ilegales o maliciosas
- 🚫 Uso sin consentimiento del propietario
- 🚫 Bypass de medidas de seguridad

### 📋 **Responsabilidad del Usuario**

**⚠️ IMPORTANTE**: El uso no autorizado de estas herramientas puede violar leyes locales e internacionales. Los usuarios son completamente responsables de:

- ✅ Obtener autorización legal antes del uso
- ✅ Cumplir con todas las regulaciones aplicables
- ✅ Respetar la privacidad y derechos de terceros
- ✅ Usar la herramienta de manera ética y legal
- ✅ Mantener la confidencialidad de la evidencia

### 🌍 **Consideraciones Específicas para Linux**
- 🔐 **Permisos de Root**: Usar responsablemente los privilegios elevados
- 📂 **Acceso a Archivos**: Respetar permisos y propiedad de archivos
- 👥 **Privacidad de Usuarios**: Proteger información personal de usuarios
- 🔍 **Logs del Sistema**: Manejar logs de forma confidencial

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
- 📊 **psutil** - Información detallada del sistema multiplataforma
- 🖥️ **platform** - Detalles de la plataforma y arquitectura
- 🐧 **Linux Community** - Por el sistema operativo y herramientas
- 🎨 **HTML/CSS** - Reportes profesionales y atractivos

### 🌟 **Comunidad Linux**
- 🐧 **Linux Foundation** - Por el desarrollo y mantenimiento de Linux
- 📦 **Distribuciones Linux** - Ubuntu, Debian, CentOS, Fedora, Arch, etc.
- 🛡️ **Comunidad DFIR** - Por compartir conocimiento y mejores prácticas
- 🔵 **Blue Team Community** - Por la inspiración y feedback
- 🎓 **Comunidad Académica** - Por los fundamentos teóricos
- 💻 **Desarrolladores Open Source** - Por las herramientas y librerías

---

<div align="center">

## 🐧 **ForenseCTL Linux**

**Sistema Completo de Análisis Forense Digital para Linux**  
*Desarrollado para profesionales de ciberseguridad y equipos DFIR*

### 🚀 **Multiplataforma • Código Abierto • Sin Dependencias Complejas • Listo para Usar**

---

**Desarrollado con ❤️ para la comunidad de Blue Team, DFIR y Linux**

[![⭐ Star en GitHub](https://img.shields.io/badge/⭐-Star%20en%20GitHub-yellow?style=for-the-badge)](https://github.com/ismaiars/ForenseCTL)
[![📥 Descargar](https://img.shields.io/badge/📥-Descargar%20Linux-green?style=for-the-badge)](forensectl_linux.py)
[![📖 Documentación](https://img.shields.io/badge/📖-Documentación-blue?style=for-the-badge)](README_Linux.md)

</div>