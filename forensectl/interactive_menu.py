#!/usr/bin/env python3
"""Menú interactivo para ForenseCTL."""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

from forensectl import logger
from forensectl.core.case_manager import CaseManager
from forensectl.analysis.disk_analyzer import DiskAnalyzer
from forensectl.analysis.memory_analyzer import MemoryAnalyzer
from forensectl.analysis.timeline_builder import TimelineBuilder
from forensectl.analysis.artifact_extractor import ArtifactExtractor
try:
    from forensectl.analysis.yara_scanner import YaraScanner
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class ForenseCTLMenu:
    """Menú interactivo principal de ForenseCTL."""
    
    def __init__(self):
        """Inicializar el menú."""
        self.case_manager = CaseManager()
        self.current_case = None
        self.running = True
        
    def clear_screen(self):
        """Limpiar la pantalla."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def show_banner(self):
        """Mostrar banner de ForenseCTL."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                        ForenseCTL v0.1.0                    ║
║              Framework de Análisis Forense Digital          ║
║                                                              ║
║  🔍 Análisis de Discos  📱 Análisis de Memoria             ║
║  ⏰ Líneas de Tiempo    🔎 Escáner YARA                    ║
║  📊 Reportes           🗂️  Gestión de Casos                ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)
        if self.current_case:
            print(f"📁 Caso Actual: {self.current_case}")
        print()
        
    def show_main_menu(self):
        """Mostrar menú principal."""
        print("═══════════════ MENÚ PRINCIPAL ═══════════════")
        print("1️⃣  Gestión de Casos")
        print("2️⃣  Análisis de Discos")
        print("3️⃣  Análisis de Memoria")
        print("4️⃣  Construcción de Timeline")
        print("5️⃣  Extracción de Artefactos")
        if YARA_AVAILABLE:
            print("6️⃣  Escáner YARA")
        else:
            print("6️⃣  Escáner YARA (No disponible - instalar yara-python)")
        print("7️⃣  Reportes y Exportación")
        print("8️⃣  Verificación de Integridad")
        print("9️⃣  Configuración")
        print("0️⃣  Salir")
        print("═" * 50)
        
    def show_case_menu(self):
        """Mostrar menú de gestión de casos."""
        print("\n═══════════════ GESTIÓN DE CASOS ═══════════════")
        print("1. Crear nuevo caso")
        print("2. Abrir caso existente")
        print("3. Listar casos")
        print("4. Información del caso actual")
        print("5. Cerrar caso actual")
        print("0. Volver al menú principal")
        print("═" * 50)
        
    def show_disk_analysis_menu(self):
        """Mostrar menú de análisis de discos."""
        print("\n═══════════════ ANÁLISIS DE DISCOS ═══════════════")
        print("1. Analizar imagen de disco")
        print("2. Extraer información de particiones")
        print("3. Generar timeline de partición")
        print("4. Buscar archivos eliminados")
        print("5. Análisis de sistema de archivos")
        print("0. Volver al menú principal")
        print("═" * 50)
        
    def show_memory_analysis_menu(self):
        """Mostrar menú de análisis de memoria."""
        print("\n═══════════════ ANÁLISIS DE MEMORIA ═══════════════")
        print("1. Analizar dump de memoria")
        print("2. Extraer procesos")
        print("3. Analizar conexiones de red")
        print("4. Extraer artefactos de memoria")
        print("5. Buscar patrones específicos")
        print("0. Volver al menú principal")
        print("═" * 50)
        
    def get_user_input(self, prompt: str = "Seleccione una opción: ") -> str:
        """Obtener entrada del usuario."""
        try:
            return input(prompt).strip()
        except KeyboardInterrupt:
            print("\n\n👋 Saliendo de ForenseCTL...")
            sys.exit(0)
            
    def pause(self):
        """Pausar hasta que el usuario presione Enter."""
        input("\n📎 Presione Enter para continuar...")
        
    def handle_case_management(self):
        """Manejar gestión de casos."""
        while True:
            self.clear_screen()
            self.show_banner()
            self.show_case_menu()
            
            choice = self.get_user_input()
            
            if choice in ['0', 'volver', 'back']:
                break
            elif choice in ['1', 'crear', 'nuevo']:
                self.create_new_case()
            elif choice in ['2', 'abrir', 'open']:
                self.open_existing_case()
            elif choice in ['3', 'listar', 'list']:
                self.list_cases()
            elif choice in ['4', 'info', 'información']:
                self.show_case_info()
            elif choice in ['5', 'cerrar', 'close']:
                self.close_current_case()
            else:
                print("❌ Opción no válida. Intente nuevamente.")
                self.pause()
                
    def create_new_case(self):
        """Crear un nuevo caso."""
        print("\n📁 CREAR NUEVO CASO")
        print("═" * 30)
        
        case_id = self.get_user_input("ID del caso: ")
        if not case_id:
            print("❌ ID del caso requerido.")
            self.pause()
            return
            
        investigator = self.get_user_input("Investigador: ")
        description = self.get_user_input("Descripción: ")
        
        try:
            case_info = self.case_manager.create_case(
                case_id=case_id,
                investigator=investigator,
                description=description
            )
            self.current_case = case_id
            print(f"✅ Caso '{case_id}' creado exitosamente.")
            print(f"📂 Directorio: {case_info['case_directory']}")
        except Exception as e:
            print(f"❌ Error al crear caso: {e}")
            
        self.pause()
        
    def open_existing_case(self):
        """Abrir un caso existente."""
        print("\n📂 ABRIR CASO EXISTENTE")
        print("═" * 30)
        
        # Mostrar casos disponibles
        cases = self.case_manager.list_cases()
        if not cases:
            print("❌ No hay casos disponibles.")
            self.pause()
            return
            
        print("Casos disponibles:")
        for i, case in enumerate(cases, 1):
            print(f"{i}. {case['case_id']} - {case.get('description', 'Sin descripción')}")
            
        choice = self.get_user_input("\nSeleccione un caso (número o ID): ")
        
        try:
            if choice.isdigit():
                case_index = int(choice) - 1
                if 0 <= case_index < len(cases):
                    case_id = cases[case_index]['case_id']
                else:
                    print("❌ Número de caso inválido.")
                    self.pause()
                    return
            else:
                case_id = choice
                
            case_info = self.case_manager.load_case(case_id)
            self.current_case = case_id
            print(f"✅ Caso '{case_id}' abierto exitosamente.")
            
        except Exception as e:
            print(f"❌ Error al abrir caso: {e}")
            
        self.pause()
        
    def list_cases(self):
        """Listar todos los casos."""
        print("\n📋 LISTA DE CASOS")
        print("═" * 30)
        
        try:
            cases = self.case_manager.list_cases()
            if not cases:
                print("❌ No hay casos disponibles.")
            else:
                for case in cases:
                    status = "🟢 ACTIVO" if case['case_id'] == self.current_case else "⚪ INACTIVO"
                    print(f"\n📁 {case['case_id']} {status}")
                    print(f"   👤 Investigador: {case.get('investigator', 'N/A')}")
                    print(f"   📝 Descripción: {case.get('description', 'Sin descripción')}")
                    print(f"   📅 Creado: {case.get('created_at', 'N/A')}")
                    
        except Exception as e:
            print(f"❌ Error al listar casos: {e}")
            
        self.pause()
        
    def show_case_info(self):
        """Mostrar información del caso actual."""
        if not self.current_case:
            print("❌ No hay caso activo.")
            self.pause()
            return
            
        print(f"\n📊 INFORMACIÓN DEL CASO: {self.current_case}")
        print("═" * 50)
        
        try:
            case_info = self.case_manager.get_case_info(self.current_case)
            print(f"📁 ID: {case_info['case_id']}")
            print(f"👤 Investigador: {case_info.get('investigator', 'N/A')}")
            print(f"📝 Descripción: {case_info.get('description', 'Sin descripción')}")
            print(f"📅 Creado: {case_info.get('created_at', 'N/A')}")
            print(f"📂 Directorio: {case_info.get('case_directory', 'N/A')}")
            
        except Exception as e:
            print(f"❌ Error al obtener información: {e}")
            
        self.pause()
        
    def close_current_case(self):
        """Cerrar el caso actual."""
        if not self.current_case:
            print("❌ No hay caso activo.")
        else:
            print(f"✅ Caso '{self.current_case}' cerrado.")
            self.current_case = None
            
        self.pause()
        
    def handle_disk_analysis(self):
        """Manejar análisis de discos."""
        if not self.current_case:
            print("❌ Debe abrir un caso antes de realizar análisis.")
            self.pause()
            return
            
        while True:
            self.clear_screen()
            self.show_banner()
            self.show_disk_analysis_menu()
            
            choice = self.get_user_input()
            
            if choice in ['0', 'volver', 'back']:
                break
            elif choice in ['1', 'analizar', 'analyze']:
                self.analyze_disk_image()
            elif choice in ['2', 'particiones', 'partitions']:
                self.extract_partition_info()
            elif choice in ['3', 'timeline']:
                self.generate_partition_timeline()
            elif choice in ['4', 'eliminados', 'deleted']:
                self.find_deleted_files()
            elif choice in ['5', 'filesystem', 'fs']:
                self.analyze_filesystem()
            else:
                print("❌ Opción no válida. Intente nuevamente.")
                self.pause()
                
    def analyze_disk_image(self):
        """Analizar imagen de disco."""
        print("\n💽 ANÁLISIS DE IMAGEN DE DISCO")
        print("═" * 40)
        
        image_path = self.get_user_input("Ruta de la imagen de disco: ")
        if not image_path or not Path(image_path).exists():
            print("❌ Archivo de imagen no encontrado.")
            self.pause()
            return
            
        try:
            analyzer = DiskAnalyzer(self.current_case)
            print("🔄 Analizando imagen de disco...")
            result = analyzer.analyze_disk_image(Path(image_path))
            
            print("\n✅ Análisis completado:")
            print(f"📊 Particiones encontradas: {len(result.get('partitions', []))}")
            print(f"💾 Tamaño total: {result.get('total_size', 'N/A')}")
            print(f"🔧 Tipo de imagen: {result.get('image_type', 'N/A')}")
            
        except Exception as e:
            print(f"❌ Error en el análisis: {e}")
            
        self.pause()
        
    def extract_partition_info(self):
        """Extraer información de particiones."""
        print("\n🗂️  INFORMACIÓN DE PARTICIONES")
        print("═" * 40)
        
        image_path = self.get_user_input("Ruta de la imagen de disco: ")
        if not image_path or not Path(image_path).exists():
            print("❌ Archivo de imagen no encontrado.")
            self.pause()
            return
            
        try:
            analyzer = DiskAnalyzer(self.current_case)
            print("🔄 Extrayendo información de particiones...")
            result = analyzer.extract_partition_info(Path(image_path))
            
            print("\n✅ Información extraída:")
            for i, partition in enumerate(result.get('partitions', []), 1):
                print(f"\n📁 Partición {i}:")
                print(f"   🏷️  Tipo: {partition.get('type', 'N/A')}")
                print(f"   📏 Tamaño: {partition.get('size', 'N/A')}")
                print(f"   📍 Offset: {partition.get('offset', 'N/A')}")
                
        except Exception as e:
            print(f"❌ Error al extraer información: {e}")
            
        self.pause()
        
    def run(self):
        """Ejecutar el menú principal."""
        while self.running:
            self.clear_screen()
            self.show_banner()
            self.show_main_menu()
            
            choice = self.get_user_input()
            
            if choice in ['0', 'salir', 'exit', 'quit']:
                self.running = False
                print("\n👋 ¡Gracias por usar ForenseCTL!")
            elif choice in ['1', 'casos', 'cases']:
                self.handle_case_management()
            elif choice in ['2', 'disco', 'disk']:
                self.handle_disk_analysis()
            elif choice in ['3', 'memoria', 'memory']:
                print("🚧 Análisis de memoria - En desarrollo")
                self.pause()
            elif choice in ['4', 'timeline']:
                print("🚧 Timeline - En desarrollo")
                self.pause()
            elif choice in ['5', 'artefactos', 'artifacts']:
                print("🚧 Extracción de artefactos - En desarrollo")
                self.pause()
            elif choice in ['6', 'yara']:
                if YARA_AVAILABLE:
                    print("🚧 Escáner YARA - En desarrollo")
                else:
                    print("❌ YARA no disponible. Instale yara-python.")
                self.pause()
            elif choice in ['7', 'reportes', 'reports']:
                print("🚧 Reportes - En desarrollo")
                self.pause()
            elif choice in ['8', 'verificación', 'verify']:
                print("🚧 Verificación - En desarrollo")
                self.pause()
            elif choice in ['9', 'config', 'configuración']:
                print("🚧 Configuración - En desarrollo")
                self.pause()
            else:
                print("❌ Opción no válida. Intente nuevamente.")
                self.pause()


def main():
    """Función principal."""
    try:
        menu = ForenseCTLMenu()
        menu.run()
    except KeyboardInterrupt:
        print("\n\n👋 Saliendo de ForenseCTL...")
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        logger.error(f"Error en menú interactivo: {e}")


if __name__ == "__main__":
    main()