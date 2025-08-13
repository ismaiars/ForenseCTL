#!/usr/bin/env python3
"""
Script de prueba para el análisis forense completo del sistema.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Agregar el directorio del proyecto al path
sys.path.insert(0, str(Path(__file__).parent))

from real_system_analyzer import RealSystemAnalyzer

def test_analisis_completo():
    """Probar el análisis forense completo del sistema."""
    print("🔬 PRUEBA DE ANÁLISIS FORENSE COMPLETO")
    print("=" * 50)
    
    try:
        print("🔍 Iniciando análisis forense completo...")
        analyzer = RealSystemAnalyzer()
        
        print("📊 Recopilando todos los datos del sistema...")
        comprehensive_data = analyzer.get_comprehensive_analysis()
        
        # Crear directorio para guardar el análisis
        analysis_dir = Path("test_analisis_completo")
        analysis_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        analysis_file = analysis_dir / f"analisis_completo_test_{timestamp}.json"
        
        # Guardar análisis completo
        with open(analysis_file, 'w', encoding='utf-8') as f:
            json.dump(comprehensive_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Análisis completo guardado en: {analysis_file}")
        
        # Mostrar estadísticas detalladas
        print("\n📊 ESTADÍSTICAS COMPLETAS DEL ANÁLISIS:")
        print("=" * 50)
        
        # Información del sistema
        system_info = comprehensive_data['analysis_info']['system_info']
        print(f"🖥️ Sistema Operativo: {system_info['system']} {system_info['release']}")
        print(f"💻 Hostname: {system_info['hostname']}")
        print(f"👤 Usuario Actual: {system_info['username']}")
        print(f"🏗️ Arquitectura: {system_info['machine']}")
        print(f"⚙️ Procesador: {system_info['processor']}")
        
        # Timeline events
        timeline_count = len(comprehensive_data['timeline_events'])
        print(f"\n⏱️ Eventos de Timeline: {timeline_count}")
        
        # Artefactos del sistema
        artifacts = comprehensive_data['system_artifacts']
        registry_count = len(artifacts.get('registry_keys', []))
        browser_count = len(artifacts.get('browser_artifacts', []))
        system_artifacts_count = len(artifacts.get('system_artifacts', []))
        processes_count = len(artifacts.get('running_processes', []))
        network_count = len(artifacts.get('network_info', []))
        disk_count = len(artifacts.get('disk_info', []))
        
        print(f"\n🔍 ARTEFACTOS DEL SISTEMA:")
        print(f"   🔑 Claves de registro: {registry_count}")
        print(f"   🌐 Artefactos de navegador: {browser_count}")
        print(f"   📁 Artefactos del sistema: {system_artifacts_count}")
        print(f"   ⚙️ Procesos en ejecución: {processes_count}")
        print(f"   🌐 Información de red: {network_count}")
        print(f"   💾 Información de disco: {disk_count}")
        
        # Análisis de seguridad
        security = comprehensive_data['security_analysis']
        print(f"\n🛡️ ANÁLISIS DE SEGURIDAD:")
        print(f"   📊 Nivel de riesgo: {security['risk_level']}")
        print(f"   🎯 Puntuación de seguridad: {security['security_score']}/100")
        print(f"   ⚠️ Vulnerabilidades detectadas: {len(security['vulnerabilities'])}")
        print(f"   🔍 Amenazas detectadas: {len(security['threats_detected'])}")
        print(f"   💡 Recomendaciones: {len(security['recommendations'])}")
        
        # Nuevas categorías de datos
        event_logs_count = len(comprehensive_data['event_logs'])
        prefetch_count = len(comprehensive_data['prefetch_files'])
        browser_history_count = len(comprehensive_data['browser_history_metadata'])
        usb_count = len(comprehensive_data['usb_device_history'])
        startup_count = len(comprehensive_data['startup_programs'])
        software_count = len(comprehensive_data['installed_software'])
        
        print(f"\n📋 DATOS FORENSES ADICIONALES:")
        print(f"   📋 Logs de eventos de Windows: {event_logs_count}")
        print(f"   🚀 Archivos Prefetch: {prefetch_count}")
        print(f"   🌐 Bases de datos de navegador: {browser_history_count}")
        print(f"   💾 Dispositivos USB detectados: {usb_count}")
        print(f"   🚀 Programas de inicio: {startup_count}")
        print(f"   📦 Software instalado: {software_count}")
        
        # Mostrar algunos ejemplos de datos
        print(f"\n🎯 EJEMPLOS DE DATOS RECOPILADOS:")
        print("=" * 40)
        
        # Mostrar algunos procesos
        if artifacts.get('running_processes'):
            print("⚙️ PROCESOS EN EJECUCIÓN (Top 5):")
            for i, process in enumerate(artifacts['running_processes'][:5], 1):
                print(f"   {i}. {process['name']} (PID: {process['pid']}, CPU: {process['cpu_percent']}%)")
        
        # Mostrar algunas claves de registro
        if artifacts.get('registry_keys'):
            print("\n🔑 CLAVES DE REGISTRO (Ejemplos):")
            for i, key in enumerate(artifacts['registry_keys'][:3], 1):
                print(f"   {i}. {key['key']} = {key['value'][:50]}..." if len(key['value']) > 50 else f"   {i}. {key['key']} = {key['value']}")
        
        # Mostrar algunos logs de eventos
        if comprehensive_data['event_logs'] and 'error' not in comprehensive_data['event_logs'][0]:
            print("\n📋 LOGS DE EVENTOS (Ejemplos):")
            for i, log in enumerate(comprehensive_data['event_logs'][:3], 1):
                if 'error' not in log:
                    print(f"   {i}. {log['name']} ({log['size_bytes']:,} bytes)")
        
        # Mostrar software instalado
        if comprehensive_data['installed_software']:
            print("\n📦 SOFTWARE INSTALADO (Ejemplos):")
            for i, software in enumerate(comprehensive_data['installed_software'][:5], 1):
                print(f"   {i}. {software['name']} v{software['version']} ({software['publisher']})")
        
        # Mostrar vulnerabilidades si las hay
        if security['vulnerabilities']:
            print("\n⚠️ VULNERABILIDADES DETECTADAS:")
            for i, vuln in enumerate(security['vulnerabilities'], 1):
                print(f"   {i}. {vuln}")
        
        # Mostrar recomendaciones
        if security['recommendations']:
            print("\n💡 RECOMENDACIONES DE SEGURIDAD:")
            for i, rec in enumerate(security['recommendations'][:5], 1):
                print(f"   {i}. {rec}")
        
        print(f"\n📁 ARCHIVO GENERADO:")
        print(f"   📄 {analysis_file}")
        print(f"   📊 Tamaño del archivo: {analysis_file.stat().st_size:,} bytes")
        
        print("\n✅ ANÁLISIS FORENSE COMPLETO FINALIZADO EXITOSAMENTE")
        print("🎯 Todos los datos del sistema han sido recopilados y analizados")
        
    except Exception as e:
        print(f"❌ Error durante el análisis: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_analisis_completo()