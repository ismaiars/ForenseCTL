#!/bin/bash

# ForenseCTL Linux - Script de Instalación
# Sistema de Análisis Forense Digital para Linux
# Licencia: MIT

set -e  # Salir si hay algún error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes con colores
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner de instalación
show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 FORENSECTL LINUX INSTALLER                  ║"
    echo "║              Sistema de Análisis Forense Digital            ║"
    echo "║                      Versión 1.0                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    print_info "🐧 Instalador para distribuciones Linux"
    print_info "🔍 Configuración automática de dependencias"
    print_info "📦 Instalación de ForenseCTL Linux"
    echo
}

# Detectar distribución Linux
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
    
    print_info "Distribución detectada: $DISTRO $VERSION"
}

# Verificar si se ejecuta como root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Ejecutándose como root - se instalarán dependencias del sistema"
        IS_ROOT=true
    else
        print_info "Ejecutándose como usuario normal - instalación local"
        IS_ROOT=false
    fi
}

# Verificar Python 3
check_python() {
    print_info "Verificando Python 3..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python 3 encontrado: $PYTHON_VERSION"
        
        # Verificar versión mínima (3.6+)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 6 ]; then
            print_success "Versión de Python compatible"
        else
            print_error "Se requiere Python 3.6 o superior"
            exit 1
        fi
    else
        print_error "Python 3 no encontrado"
        
        if [ "$IS_ROOT" = true ]; then
            print_info "Intentando instalar Python 3..."
            install_python
        else
            print_error "Por favor instala Python 3 manualmente o ejecuta como root"
            exit 1
        fi
    fi
}

# Instalar Python según la distribución
install_python() {
    case $DISTRO in
        ubuntu|debian)
            apt update
            apt install -y python3 python3-pip python3-venv
            ;;
        fedora)
            dnf install -y python3 python3-pip
            ;;
        centos|rhel)
            if [ "$VERSION" = "8" ] || [ "$VERSION" = "9" ]; then
                dnf install -y python3 python3-pip
            else
                yum install -y python3 python3-pip
            fi
            ;;
        arch|manjaro)
            pacman -S --noconfirm python python-pip
            ;;
        opensuse*)
            zypper install -y python3 python3-pip
            ;;
        *)
            print_error "Distribución no soportada para instalación automática"
            print_info "Por favor instala Python 3 manualmente"
            exit 1
            ;;
    esac
}

# Verificar pip
check_pip() {
    print_info "Verificando pip..."
    
    if command -v pip3 &> /dev/null; then
        print_success "pip3 encontrado"
        PIP_CMD="pip3"
    elif command -v pip &> /dev/null; then
        # Verificar que pip corresponde a Python 3
        PIP_PYTHON_VERSION=$(pip --version | grep -o 'python [0-9]\.[0-9]' | cut -d' ' -f2 | cut -d'.' -f1)
        if [ "$PIP_PYTHON_VERSION" = "3" ]; then
            print_success "pip encontrado (Python 3)"
            PIP_CMD="pip"
        else
            print_error "pip encontrado pero corresponde a Python 2"
            PIP_CMD="pip3"
        fi
    else
        print_error "pip no encontrado"
        
        if [ "$IS_ROOT" = true ]; then
            print_info "Intentando instalar pip..."
            install_pip
        else
            print_error "Por favor instala pip manualmente o ejecuta como root"
            exit 1
        fi
    fi
}

# Instalar pip según la distribución
install_pip() {
    case $DISTRO in
        ubuntu|debian)
            apt install -y python3-pip
            ;;
        fedora|centos|rhel)
            if command -v dnf &> /dev/null; then
                dnf install -y python3-pip
            else
                yum install -y python3-pip
            fi
            ;;
        arch|manjaro)
            pacman -S --noconfirm python-pip
            ;;
        opensuse*)
            zypper install -y python3-pip
            ;;
        *)
            print_error "No se pudo instalar pip automáticamente"
            exit 1
            ;;
    esac
    
    PIP_CMD="pip3"
}

# Instalar dependencias Python
install_dependencies() {
    print_info "Instalando dependencias de Python..."
    
    # Lista de dependencias requeridas
    DEPENDENCIES=(
        "psutil>=5.8.0"
        "pathlib2; python_version<'3.4'"
    )
    
    for dep in "${DEPENDENCIES[@]}"; do
        print_info "Instalando $dep..."
        if [ "$IS_ROOT" = true ]; then
            $PIP_CMD install "$dep"
        else
            $PIP_CMD install --user "$dep"
        fi
    done
    
    print_success "Dependencias instaladas correctamente"
}

# Verificar dependencias instaladas
verify_dependencies() {
    print_info "Verificando dependencias..."
    
    # Verificar psutil
    if python3 -c "import psutil; print(f'psutil {psutil.__version__}')" 2>/dev/null; then
        PSUTIL_VERSION=$(python3 -c "import psutil; print(psutil.__version__)")
        print_success "psutil $PSUTIL_VERSION - OK"
    else
        print_error "psutil no está disponible"
        return 1
    fi
    
    # Verificar módulos estándar
    STANDARD_MODULES=("json" "datetime" "platform" "pathlib" "os" "sys" "subprocess" "hashlib")
    
    for module in "${STANDARD_MODULES[@]}"; do
        if python3 -c "import $module" 2>/dev/null; then
            print_success "$module - OK"
        else
            print_error "$module no está disponible"
            return 1
        fi
    done
    
    print_success "Todas las dependencias verificadas correctamente"
}

# Crear estructura de directorios
create_directories() {
    print_info "Creando estructura de directorios..."
    
    INSTALL_DIR="$HOME/ForenseCTL"
    
    if [ "$IS_ROOT" = true ]; then
        INSTALL_DIR="/opt/ForenseCTL"
    fi
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/forensics_workspace/cases"
    mkdir -p "$INSTALL_DIR/forensics_workspace/evidence"
    mkdir -p "$INSTALL_DIR/forensics_workspace/reports"
    mkdir -p "$INSTALL_DIR/forensics_workspace/templates"
    
    print_success "Directorios creados en: $INSTALL_DIR"
}

# Copiar archivos de ForenseCTL
install_forensectl() {
    print_info "Instalando ForenseCTL Linux..."
    
    # Verificar que el archivo forensectl_linux.py existe
    if [ ! -f "forensectl_linux.py" ]; then
        print_error "Archivo forensectl_linux.py no encontrado"
        print_info "Asegúrate de ejecutar este script desde el directorio de ForenseCTL"
        exit 1
    fi
    
    # Copiar archivo principal
    cp "forensectl_linux.py" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/forensectl_linux.py"
    
    # Crear script de ejecución
    cat > "$INSTALL_DIR/forensectl" << 'EOF'
#!/bin/bash
# ForenseCTL Linux - Script de ejecución

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Verificar permisos
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  ADVERTENCIA: No se está ejecutando como root."
    echo "   Algunas funciones pueden estar limitadas."
    echo "   Para análisis completo, ejecuta: sudo $0"
    echo
fi

# Ejecutar ForenseCTL
python3 forensectl_linux.py "$@"
EOF
    
    chmod +x "$INSTALL_DIR/forensectl"
    
    print_success "ForenseCTL Linux instalado en: $INSTALL_DIR"
}

# Crear enlace simbólico global
create_symlink() {
    if [ "$IS_ROOT" = true ]; then
        print_info "Creando enlace simbólico global..."
        
        ln -sf "$INSTALL_DIR/forensectl" "/usr/local/bin/forensectl"
        
        print_success "ForenseCTL disponible globalmente como 'forensectl'"
    else
        print_info "Para usar ForenseCTL globalmente, añade esto a tu ~/.bashrc:"
        echo "export PATH=\"$INSTALL_DIR:\$PATH\""
        echo
        print_info "O ejecuta directamente: $INSTALL_DIR/forensectl"
    fi
}

# Crear archivo de configuración
create_config() {
    print_info "Creando archivo de configuración..."
    
    cat > "$INSTALL_DIR/config.json" << EOF
{
    "version": "1.0",
    "install_date": "$(date -Iseconds)",
    "install_dir": "$INSTALL_DIR",
    "python_version": "$(python3 --version | cut -d' ' -f2)",
    "distro": "$DISTRO",
    "user": "$(whoami)",
    "workspace_dir": "$INSTALL_DIR/forensics_workspace",
    "auto_backup": true,
    "max_evidence_files": 100,
    "report_format": "both"
}
EOF
    
    print_success "Archivo de configuración creado"
}

# Ejecutar test básico
run_test() {
    print_info "Ejecutando test básico..."
    
    cd "$INSTALL_DIR"
    
    # Test de importación
    if python3 -c "import sys; sys.path.insert(0, '.'); import forensectl_linux; print('✅ Importación exitosa')" 2>/dev/null; then
        print_success "Test de importación - OK"
    else
        print_error "Test de importación - FALLO"
        return 1
    fi
    
    # Test de dependencias
    if python3 -c "import psutil, json, datetime, platform, pathlib, os, sys, subprocess, hashlib; print('✅ Dependencias OK')" 2>/dev/null; then
        print_success "Test de dependencias - OK"
    else
        print_error "Test de dependencias - FALLO"
        return 1
    fi
    
    print_success "Todos los tests pasaron correctamente"
}

# Mostrar información de instalación completada
show_completion() {
    echo
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 INSTALACIÓN COMPLETADA                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    print_success "ForenseCTL Linux instalado correctamente"
    echo
    print_info "📍 Ubicación: $INSTALL_DIR"
    print_info "🐍 Python: $(python3 --version)"
    print_info "📦 Dependencias: Instaladas"
    print_info "🔧 Configuración: Creada"
    echo
    print_info "🚀 CÓMO USAR:"
    
    if [ "$IS_ROOT" = true ]; then
        echo "   • Ejecutar globalmente: forensectl"
        echo "   • O directamente: $INSTALL_DIR/forensectl"
    else
        echo "   • Ejecutar: $INSTALL_DIR/forensectl"
        echo "   • Para uso global, añadir a PATH: export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
    
    echo
    print_info "⚠️  IMPORTANTE:"
    echo "   • Para análisis completo, ejecutar como root: sudo forensectl"
    echo "   • Los datos se guardan en: $INSTALL_DIR/forensics_workspace"
    echo "   • Consulta la documentación para más información"
    echo
    print_info "🔒 SEGURIDAD:"
    echo "   • Esta herramienta es para uso autorizado únicamente"
    echo "   • Cumple con las leyes locales e internacionales"
    echo "   • Mantén la evidencia de forma segura"
    echo
}

# Función principal
main() {
    show_banner
    
    # Verificaciones previas
    detect_distro
    check_root
    check_python
    check_pip
    
    # Instalación
    install_dependencies
    verify_dependencies
    create_directories
    install_forensectl
    create_symlink
    create_config
    
    # Verificación final
    run_test
    
    # Información de finalización
    show_completion
}

# Manejo de errores
trap 'print_error "Instalación interrumpida"; exit 1' INT TERM

# Ejecutar instalación
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi