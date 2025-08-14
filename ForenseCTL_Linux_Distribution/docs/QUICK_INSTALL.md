# 🚀 Guía de Instalación Rápida - ForenseCTL Linux

## Método 1: Instalación Automática (Recomendado)

```bash
# 1. Hacer ejecutable el instalador
chmod +x install_linux.sh

# 2. Ejecutar instalador
sudo ./install_linux.sh

# 3. Ejecutar ForenseCTL
forensectl
```

## Método 2: Ejecución Directa

```bash
# 1. Verificar sistema
python3 examples/system_check.py

# 2. Inicio rápido
./quick_start.sh

# 3. O ejecutar directamente
python3 forensectl_linux.py
```

## Método 3: Instalación Manual

```bash
# 1. Instalar Python y dependencias
sudo apt install python3 python3-pip  # Ubuntu/Debian
sudo dnf install python3 python3-pip  # CentOS/RHEL/Fedora
sudo pacman -S python python-pip      # Arch Linux

# 2. Instalar psutil
pip3 install psutil

# 3. Ejecutar ForenseCTL
python3 forensectl_linux.py
```

## Verificación

```bash
# Verificar instalación
python3 examples/system_check.py

# Test básico
python3 -c "import psutil; print('✅ OK')"
```

## Solución de Problemas

- **Python no encontrado**: Instalar Python 3.6+
- **psutil no encontrado**: `pip3 install psutil`
- **Permisos**: Ejecutar como root para análisis completo
- **Espacio**: Verificar al menos 500MB libres

Para más detalles, consultar `README.md`