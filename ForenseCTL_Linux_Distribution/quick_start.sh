#!/bin/bash

# ForenseCTL Linux - Inicio Rápido
# Este script verifica dependencias e inicia ForenseCTL

set -e

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
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

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                 FORENSECTL LINUX                            ║"
echo "║                 INICIO RÁPIDO                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar Python 3
print_status "Verificando Python 3..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 no está instalado"
    print_status "Instalar con:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  CentOS/RHEL:   sudo dnf install python3 python3-pip"
    echo "  Arch Linux:    sudo pacman -S python python-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | cut -d" " -f2 | cut -d"." -f1,2)
print_success "Python $PYTHON_VERSION encontrado"

# Verificar psutil
print_status "Verificando dependencia psutil..."
if ! python3 -c "import psutil" &> /dev/null; then
    print_warning "psutil no está instalado"
    print_status "Instalando psutil..."
    
    if command -v pip3 &> /dev/null; then
        pip3 install --user psutil
    else
        print_error "pip3 no está disponible"
        print_status "Instalar con el gestor de paquetes:"
        echo "  Ubuntu/Debian: sudo apt install python3-psutil"
        echo "  CentOS/RHEL:   sudo dnf install python3-psutil"
        echo "  Arch Linux:    sudo pacman -S python-psutil"
        exit 1
    fi
fi

print_success "psutil disponible"

# Verificar archivo principal
if [[ ! -f "forensectl_linux.py" ]]; then
    print_error "forensectl_linux.py no encontrado en el directorio actual"
    exit 1
fi

# Mostrar información del usuario
print_status "Usuario actual: $(whoami)"
if [[ $EUID -eq 0 ]]; then
    print_success "Ejecutando como root - Análisis completo disponible"
else
    print_warning "Ejecutando como usuario normal - Algunas funciones pueden estar limitadas"
    print_status "Para análisis completo, ejecutar: sudo python3 forensectl_linux.py"
fi

print_status "Iniciando ForenseCTL Linux..."
echo ""

# Ejecutar ForenseCTL
python3 forensectl_linux.py