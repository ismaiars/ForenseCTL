#!/usr/bin/env python3
"""
ForenseCTL Linux - Verificación del Sistema
Este script verifica que el sistema cumple con los requisitos
"""

import sys
import platform
import subprocess
import os

def print_header():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              FORENSECTL LINUX - VERIFICACIÓN                ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

def check_python():
    print("🐍 Verificando Python...")
    version = sys.version_info
    print(f"   Versión: {version.major}.{version.minor}.{version.micro}")
    
    if version.major >= 3 and version.minor >= 6:
        print("   ✅ Python OK")
        return True
    else:
        print("   ❌ Python 3.6+ requerido")
        return False

def check_psutil():
    print("\n📊 Verificando psutil...")
    try:
        import psutil
        print(f"   Versión: {psutil.__version__}")
        print("   ✅ psutil OK")
        return True
    except ImportError:
        print("   ❌ psutil no instalado")
        print("   Instalar con: pip3 install psutil")
        return False

def check_system():
    print("\n🐧 Información del Sistema...")
    print(f"   OS: {platform.system()}")
    print(f"   Distribución: {platform.platform()}")
    print(f"   Arquitectura: {platform.machine()}")
    print(f"   Kernel: {platform.release()}")
    
    if platform.system() == "Linux":
        print("   ✅ Sistema Linux OK")
        return True
    else:
        print("   ⚠️  No es un sistema Linux")
        return False

def check_permissions():
    print("\n👤 Verificando Permisos...")
    user = os.getenv('USER', 'unknown')
    uid = os.getuid() if hasattr(os, 'getuid') else 'unknown'
    
    print(f"   Usuario: {user}")
    print(f"   UID: {uid}")
    
    if uid == 0:
        print("   ✅ Ejecutando como root - Análisis completo disponible")
    else:
        print("   ⚠️  Usuario normal - Algunas funciones limitadas")
        print("   Sugerencia: sudo python3 forensectl_linux.py")
    
    return True

def check_disk_space():
    print("\n💾 Verificando Espacio en Disco...")
    try:
        import shutil
        total, used, free = shutil.disk_usage('.')
        
        free_gb = free // (1024**3)
        print(f"   Espacio libre: {free_gb} GB")
        
        if free_gb >= 2:
            print("   ✅ Espacio suficiente")
            return True
        elif free_gb >= 0.5:
            print("   ⚠️  Espacio limitado pero suficiente")
            return True
        else:
            print("   ❌ Espacio insuficiente (mínimo 500MB)")
            return False
    except Exception as e:
        print(f"   ⚠️  No se pudo verificar espacio: {e}")
        return True

def main():
    print_header()
    
    checks = [
        check_python(),
        check_psutil(),
        check_system(),
        check_permissions(),
        check_disk_space()
    ]
    
    print("\n" + "="*60)
    
    passed = sum(checks)
    total = len(checks)
    
    if passed == total:
        print(f"✅ VERIFICACIÓN COMPLETA: {passed}/{total} checks pasados")
        print("🚀 Sistema listo para ejecutar ForenseCTL Linux")
        print("\nEjecutar con: python3 forensectl_linux.py")
    else:
        print(f"⚠️  VERIFICACIÓN PARCIAL: {passed}/{total} checks pasados")
        print("🔧 Revisar los elementos marcados arriba")
    
    print("\n📖 Para más información, consultar README.md")

if __name__ == "__main__":
    main()