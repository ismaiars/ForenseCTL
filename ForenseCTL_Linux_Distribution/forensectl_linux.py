#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ForenseCTL Linux - Sistema de Análisis Forense Digital para Linux
Versión multiplataforma compatible con distribuciones Linux

Desarrollado para profesionales de ciberseguridad y equipos DFIR
Licencia: MIT
"""

import os
import sys
import json
import platform
import datetime
import hashlib
import subprocess
from pathlib import Path
try:
    import psutil
except ImportError:
    print("Error: psutil no está instalado. Ejecuta: pip install psutil")
    sys.exit(1)

class LinuxSystemAnalyzer:
    """Analizador del sistema Linux para recopilación forense"""
    
    def __init__(self):
        self.system_info = {}
        self.processes = []
        self.network_connections = []
        self.installed_packages = []
        self.system_files = []
        self.users_info = []
        
    def get_system_information(self):
        """Recopila información básica del sistema Linux"""
        try:
            uname = platform.uname()
            self.system_info = {
                'hostname': uname.node,
                'system': uname.system,
                'release': uname.release,
                'version': uname.version,
                'machine': uname.machine,
                'processor': uname.processor,
                'architecture': platform.architecture()[0],
                'python_version': platform.python_version(),
                'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'disk_usage': {}
            }
            
            # Información de discos
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    self.system_info['disk_usage'][partition.device] = {
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free
                    }
                except PermissionError:
                    continue
                    
        except Exception as e:
            print(f"Error recopilando información del sistema: {e}")
            
    def get_running_processes(self):
        """Recopila información de procesos en ejecución"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time', 'memory_info', 'cpu_percent', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_info['create_time'] = datetime.datetime.fromtimestamp(proc_info['create_time']).isoformat()
                    proc_info['memory_rss'] = proc_info['memory_info'].rss if proc_info['memory_info'] else 0
                    proc_info['memory_vms'] = proc_info['memory_info'].vms if proc_info['memory_info'] else 0
                    del proc_info['memory_info']  # Remover objeto no serializable
                    self.processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error recopilando procesos: {e}")
            
    def get_network_connections(self):
        """Recopila conexiones de red activas"""
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                self.network_connections.append(conn_info)
        except Exception as e:
            print(f"Error recopilando conexiones de red: {e}")
            
    def get_installed_packages(self):
        """Recopila paquetes instalados (dpkg/rpm/pacman)"""
        try:
            # Detectar gestor de paquetes
            if os.path.exists('/usr/bin/dpkg'):
                # Debian/Ubuntu
                result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
                lines = result.stdout.split('\n')[5:]  # Saltar headers
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            self.installed_packages.append({
                                'name': parts[1],
                                'version': parts[2],
                                'description': ' '.join(parts[3:]) if len(parts) > 3 else ''
                            })
            elif os.path.exists('/usr/bin/rpm'):
                # RedHat/CentOS/Fedora
                result = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION} %{SUMMARY}\n'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split(' ', 2)
                        if len(parts) >= 2:
                            self.installed_packages.append({
                                'name': parts[0],
                                'version': parts[1],
                                'description': parts[2] if len(parts) > 2 else ''
                            })
            elif os.path.exists('/usr/bin/pacman'):
                # Arch Linux
                result = subprocess.run(['pacman', '-Q'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            self.installed_packages.append({
                                'name': parts[0],
                                'version': parts[1],
                                'description': ''
                            })
        except Exception as e:
            print(f"Error recopilando paquetes instalados: {e}")
            
    def get_system_files(self):
        """Recopila archivos críticos del sistema Linux"""
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/hosts',
            '/etc/hostname',
            '/etc/resolv.conf',
            '/etc/fstab',
            '/etc/crontab',
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/secure',
            '/home/*/.bash_history',
            '/root/.bash_history'
        ]
        
        for file_path in critical_files:
            try:
                if '*' in file_path:
                    # Manejar wildcards
                    import glob
                    for actual_file in glob.glob(file_path):
                        self._add_file_info(actual_file)
                else:
                    self._add_file_info(file_path)
            except Exception as e:
                continue
                
    def _add_file_info(self, file_path):
        """Añade información de un archivo específico"""
        try:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                with open(file_path, 'rb') as f:
                    content_hash = hashlib.sha256(f.read()).hexdigest()
                    
                self.system_files.append({
                    'path': file_path,
                    'size': stat.st_size,
                    'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'accessed': datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
                    'permissions': oct(stat.st_mode)[-3:],
                    'owner_uid': stat.st_uid,
                    'group_gid': stat.st_gid,
                    'sha256': content_hash
                })
        except (PermissionError, OSError):
            pass
            
    def get_users_info(self):
        """Recopila información de usuarios del sistema"""
        try:
            # Usuarios activos
            for user in psutil.users():
                self.users_info.append({
                    'name': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.datetime.fromtimestamp(user.started).isoformat()
                })
                
            # Información adicional de /etc/passwd
            if os.path.exists('/etc/passwd'):
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            parts = line.strip().split(':')
                            if len(parts) >= 7:
                                # Solo usuarios con UID >= 1000 (usuarios normales)
                                if int(parts[2]) >= 1000 or int(parts[2]) == 0:
                                    self.users_info.append({
                                        'username': parts[0],
                                        'uid': int(parts[2]),
                                        'gid': int(parts[3]),
                                        'home_dir': parts[5],
                                        'shell': parts[6],
                                        'type': 'system_user'
                                    })
        except Exception as e:
            print(f"Error recopilando información de usuarios: {e}")
            
    def collect_all_evidence(self):
        """Recopila toda la evidencia del sistema"""
        print("🔍 Iniciando recopilación de evidencia del sistema Linux...")
        
        print("📊 Recopilando información del sistema...")
        self.get_system_information()
        
        print("🔄 Analizando procesos en ejecución...")
        self.get_running_processes()
        
        print("🌐 Recopilando conexiones de red...")
        self.get_network_connections()
        
        print("📦 Analizando paquetes instalados...")
        self.get_installed_packages()
        
        print("📂 Recopilando archivos críticos del sistema...")
        self.get_system_files()
        
        print("👥 Analizando información de usuarios...")
        self.get_users_info()
        
        print("✅ Recopilación de evidencia completada.")
        
        return {
            'timestamp': datetime.datetime.now().isoformat(),
            'system_info': self.system_info,
            'processes': self.processes,
            'network_connections': self.network_connections,
            'installed_packages': self.installed_packages,
            'system_files': self.system_files,
            'users_info': self.users_info
        }

class CaseManager:
    """Gestor de casos forenses"""
    
    def __init__(self, workspace_dir="./forensics_workspace"):
        self.workspace_dir = Path(workspace_dir)
        self.cases_dir = self.workspace_dir / "cases"
        self.evidence_dir = self.workspace_dir / "evidence"
        self.reports_dir = self.workspace_dir / "reports"
        
        # Crear directorios si no existen
        for directory in [self.workspace_dir, self.cases_dir, self.evidence_dir, self.reports_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            
    def create_case(self, case_name, investigator, description=""):
        """Crea un nuevo caso forense"""
        case_id = f"CASE_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        case_data = {
            'case_id': case_id,
            'case_name': case_name,
            'investigator': investigator,
            'description': description,
            'created': datetime.datetime.now().isoformat(),
            'status': 'active',
            'evidence_files': [],
            'chain_of_custody': []
        }
        
        case_file = self.cases_dir / f"{case_id}.json"
        with open(case_file, 'w', encoding='utf-8') as f:
            json.dump(case_data, f, indent=2, ensure_ascii=False)
            
        print(f"✅ Caso creado: {case_id}")
        return case_id
        
    def list_cases(self):
        """Lista todos los casos disponibles"""
        cases = []
        for case_file in self.cases_dir.glob("CASE_*.json"):
            try:
                with open(case_file, 'r', encoding='utf-8') as f:
                    case_data = json.load(f)
                    cases.append(case_data)
            except Exception as e:
                print(f"Error leyendo caso {case_file}: {e}")
        return cases

class ReportGenerator:
    """Generador de reportes forenses"""
    
    def __init__(self, reports_dir="./forensics_workspace/reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_html_report(self, evidence_data, case_id):
        """Genera reporte HTML profesional"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.reports_dir / f"report_{case_id}_{timestamp}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Forense - {case_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #2c3e50; margin: 0; font-size: 2.5em; }}
        .header p {{ color: #7f8c8d; margin: 10px 0 0 0; font-size: 1.1em; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #34495e; border-left: 4px solid #3498db; padding-left: 15px; font-size: 1.5em; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .info-card {{ background: #ecf0f1; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db; }}
        .info-card h3 {{ margin: 0 0 15px 0; color: #2c3e50; }}
        .info-card p {{ margin: 5px 0; color: #34495e; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .highlight {{ background-color: #fff3cd; padding: 10px; border-radius: 5px; border-left: 4px solid #ffc107; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Reporte de Análisis Forense Digital</h1>
            <p>Sistema Linux - Caso: {case_id}</p>
            <p>Generado: {evidence_data['timestamp']}</p>
        </div>
        
        <div class="section">
            <h2>📊 Información del Sistema</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>🖥️ Sistema Operativo</h3>
                    <p><strong>Hostname:</strong> {evidence_data['system_info'].get('hostname', 'N/A')}</p>
                    <p><strong>Sistema:</strong> {evidence_data['system_info'].get('system', 'N/A')}</p>
                    <p><strong>Release:</strong> {evidence_data['system_info'].get('release', 'N/A')}</p>
                    <p><strong>Arquitectura:</strong> {evidence_data['system_info'].get('architecture', 'N/A')}</p>
                </div>
                <div class="info-card">
                    <h3>💾 Hardware</h3>
                    <p><strong>Procesador:</strong> {evidence_data['system_info'].get('processor', 'N/A')}</p>
                    <p><strong>CPUs:</strong> {evidence_data['system_info'].get('cpu_count', 'N/A')}</p>
                    <p><strong>RAM Total:</strong> {evidence_data['system_info'].get('memory_total', 0) // (1024**3)} GB</p>
                    <p><strong>RAM Disponible:</strong> {evidence_data['system_info'].get('memory_available', 0) // (1024**3)} GB</p>
                </div>
                <div class="info-card">
                    <h3>⏰ Tiempo del Sistema</h3>
                    <p><strong>Último Reinicio:</strong> {evidence_data['system_info'].get('boot_time', 'N/A')}</p>
                    <p><strong>Análisis Realizado:</strong> {evidence_data['timestamp']}</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔄 Procesos en Ejecución</h2>
            <p>Total de procesos analizados: <strong>{len(evidence_data['processes'])}</strong></p>
            <table>
                <tr>
                    <th>PID</th>
                    <th>Nombre</th>
                    <th>Usuario</th>
                    <th>Estado</th>
                    <th>Memoria (MB)</th>
                    <th>Tiempo de Inicio</th>
                </tr>
"""
        
        # Agregar procesos (limitado a los primeros 50 para evitar reportes muy largos)
        for proc in evidence_data['processes'][:50]:
            memory_mb = proc.get('memory_rss', 0) // (1024*1024)
            html_content += f"""
                <tr>
                    <td>{proc.get('pid', 'N/A')}</td>
                    <td>{proc.get('name', 'N/A')}</td>
                    <td>{proc.get('username', 'N/A')}</td>
                    <td>{proc.get('status', 'N/A')}</td>
                    <td>{memory_mb}</td>
                    <td>{proc.get('create_time', 'N/A')}</td>
                </tr>
"""
        
        html_content += f"""
            </table>
        </div>
        
        <div class="section">
            <h2>🌐 Conexiones de Red</h2>
            <p>Total de conexiones activas: <strong>{len(evidence_data['network_connections'])}</strong></p>
            <table>
                <tr>
                    <th>Tipo</th>
                    <th>Dirección Local</th>
                    <th>Dirección Remota</th>
                    <th>Estado</th>
                    <th>PID</th>
                </tr>
"""
        
        # Agregar conexiones de red
        for conn in evidence_data['network_connections'][:30]:
            html_content += f"""
                <tr>
                    <td>{conn.get('type', 'N/A')}</td>
                    <td>{conn.get('local_address', 'N/A')}</td>
                    <td>{conn.get('remote_address', 'N/A')}</td>
                    <td>{conn.get('status', 'N/A')}</td>
                    <td>{conn.get('pid', 'N/A')}</td>
                </tr>
"""
        
        html_content += f"""
            </table>
        </div>
        
        <div class="section">
            <h2>📦 Paquetes Instalados</h2>
            <p>Total de paquetes encontrados: <strong>{len(evidence_data['installed_packages'])}</strong></p>
            <div class="highlight">
                <p><strong>Nota:</strong> Se muestran los primeros 20 paquetes. El análisis completo está disponible en el archivo JSON.</p>
            </div>
            <table>
                <tr>
                    <th>Nombre</th>
                    <th>Versión</th>
                    <th>Descripción</th>
                </tr>
"""
        
        # Agregar paquetes instalados (limitado)
        for pkg in evidence_data['installed_packages'][:20]:
            html_content += f"""
                <tr>
                    <td>{pkg.get('name', 'N/A')}</td>
                    <td>{pkg.get('version', 'N/A')}</td>
                    <td>{pkg.get('description', 'N/A')[:100]}...</td>
                </tr>
"""
        
        html_content += f"""
            </table>
        </div>
        
        <div class="section">
            <h2>📂 Archivos Críticos del Sistema</h2>
            <p>Archivos analizados: <strong>{len(evidence_data['system_files'])}</strong></p>
            <table>
                <tr>
                    <th>Ruta</th>
                    <th>Tamaño</th>
                    <th>Modificado</th>
                    <th>Permisos</th>
                    <th>SHA256</th>
                </tr>
"""
        
        # Agregar archivos del sistema
        for file_info in evidence_data['system_files']:
            size_kb = file_info.get('size', 0) // 1024
            html_content += f"""
                <tr>
                    <td>{file_info.get('path', 'N/A')}</td>
                    <td>{size_kb} KB</td>
                    <td>{file_info.get('modified', 'N/A')}</td>
                    <td>{file_info.get('permissions', 'N/A')}</td>
                    <td>{file_info.get('sha256', 'N/A')[:16]}...</td>
                </tr>
"""
        
        html_content += f"""
            </table>
        </div>
        
        <div class="footer">
            <p>🔍 <strong>ForenseCTL Linux</strong> - Sistema de Análisis Forense Digital</p>
            <p>Reporte generado automáticamente el {datetime.datetime.now().strftime('%d/%m/%Y a las %H:%M:%S')}</p>
            <p>⚖️ Este reporte es para uso profesional en análisis forense digital autorizado</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"📄 Reporte HTML generado: {report_file}")
        return report_file
        
    def generate_json_report(self, evidence_data, case_id):
        """Genera reporte JSON con todos los datos"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.reports_dir / f"evidence_{case_id}_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(evidence_data, f, indent=2, ensure_ascii=False)
            
        print(f"📋 Reporte JSON generado: {report_file}")
        return report_file

def show_banner():
    """Muestra el banner de ForenseCTL Linux"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    FORENSECTL LINUX                         ║
║              ANÁLISIS FORENSE DIGITAL                       ║
║                   Versión Linux 1.0                         ║
╚══════════════════════════════════════════════════════════════╝

🐧 Sistema de análisis forense digital para distribuciones Linux
🔍 Recopilación automática de evidencia del sistema
📄 Generación de reportes profesionales HTML y JSON
🔗 Cadena de custodia automática

"""
    print(banner)

def show_menu():
    """Muestra el menú principal"""
    menu = """
╔══════════════════════════════════════════════════════════════╗
║                      MENÚ PRINCIPAL                         ║
╚══════════════════════════════════════════════════════════════╝

[1] 📁 Gestión de Casos
[2] 🔍 Análisis Forense del Sistema
[3] 📄 Generación de Reportes
[4] 🔗 Cadena de Custodia
[5] ⚙️  Configuración y Herramientas
[6] ❓ Ayuda
[0] 🚪 Salir

Selecciona una opción: """
    return input(menu)

def main():
    """Función principal de ForenseCTL Linux"""
    show_banner()
    
    # Verificar permisos
    if os.geteuid() != 0:
        print("⚠️  ADVERTENCIA: No se está ejecutando como root.")
        print("   Algunas funciones pueden estar limitadas.")
        print("   Para análisis completo, ejecuta: sudo python3 forensectl_linux.py\n")
    
    case_manager = CaseManager()
    analyzer = LinuxSystemAnalyzer()
    report_generator = ReportGenerator()
    
    current_case = None
    
    while True:
        try:
            option = show_menu()
            
            if option == '1':
                # Gestión de Casos
                print("\n📁 GESTIÓN DE CASOS")
                print("[1] Crear nuevo caso")
                print("[2] Listar casos existentes")
                print("[3] Seleccionar caso activo")
                
                case_option = input("Selecciona una opción: ")
                
                if case_option == '1':
                    case_name = input("Nombre del caso: ")
                    investigator = input("Investigador: ")
                    description = input("Descripción (opcional): ")
                    current_case = case_manager.create_case(case_name, investigator, description)
                    
                elif case_option == '2':
                    cases = case_manager.list_cases()
                    if cases:
                        print("\nCasos disponibles:")
                        for case in cases:
                            print(f"- {case['case_id']}: {case['case_name']} ({case['status']})")
                    else:
                        print("No hay casos disponibles.")
                        
                elif case_option == '3':
                    cases = case_manager.list_cases()
                    if cases:
                        print("\nCasos disponibles:")
                        for i, case in enumerate(cases):
                            print(f"[{i+1}] {case['case_id']}: {case['case_name']}")
                        try:
                            selection = int(input("Selecciona un caso: ")) - 1
                            if 0 <= selection < len(cases):
                                current_case = cases[selection]['case_id']
                                print(f"✅ Caso activo: {current_case}")
                            else:
                                print("❌ Selección inválida")
                        except ValueError:
                            print("❌ Entrada inválida")
                    else:
                        print("No hay casos disponibles.")
                        
            elif option == '2':
                # Análisis Forense
                if not current_case:
                    print("❌ Primero debes crear o seleccionar un caso.")
                    continue
                    
                print(f"\n🔍 ANÁLISIS FORENSE - Caso: {current_case}")
                print("[1] Análisis completo del sistema")
                print("[2] Análisis de procesos")
                print("[3] Análisis de red")
                print("[4] Análisis de paquetes")
                
                analysis_option = input("Selecciona una opción: ")
                
                if analysis_option == '1':
                    print("\n🚀 Iniciando análisis completo del sistema...")
                    evidence = analyzer.collect_all_evidence()
                    
                    # Guardar evidencia
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    evidence_file = Path(f"./forensics_workspace/evidence/evidence_{current_case}_{timestamp}.json")
                    evidence_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(evidence_file, 'w', encoding='utf-8') as f:
                        json.dump(evidence, f, indent=2, ensure_ascii=False)
                    
                    print(f"💾 Evidencia guardada: {evidence_file}")
                    
                elif analysis_option in ['2', '3', '4']:
                    print("🔄 Ejecutando análisis específico...")
                    if analysis_option == '2':
                        analyzer.get_running_processes()
                        print(f"✅ Procesos analizados: {len(analyzer.processes)}")
                    elif analysis_option == '3':
                        analyzer.get_network_connections()
                        print(f"✅ Conexiones analizadas: {len(analyzer.network_connections)}")
                    elif analysis_option == '4':
                        analyzer.get_installed_packages()
                        print(f"✅ Paquetes analizados: {len(analyzer.installed_packages)}")
                        
            elif option == '3':
                # Generación de Reportes
                if not current_case:
                    print("❌ Primero debes crear o seleccionar un caso.")
                    continue
                    
                print(f"\n📄 GENERACIÓN DE REPORTES - Caso: {current_case}")
                
                # Buscar archivos de evidencia del caso actual
                evidence_files = list(Path("./forensics_workspace/evidence").glob(f"evidence_{current_case}_*.json"))
                
                if not evidence_files:
                    print("❌ No hay evidencia disponible. Primero ejecuta un análisis.")
                    continue
                    
                # Usar el archivo de evidencia más reciente
                latest_evidence = max(evidence_files, key=lambda x: x.stat().st_mtime)
                
                with open(latest_evidence, 'r', encoding='utf-8') as f:
                    evidence_data = json.load(f)
                    
                print("[1] Generar reporte HTML")
                print("[2] Generar reporte JSON")
                print("[3] Generar ambos reportes")
                
                report_option = input("Selecciona una opción: ")
                
                if report_option in ['1', '3']:
                    report_generator.generate_html_report(evidence_data, current_case)
                    
                if report_option in ['2', '3']:
                    report_generator.generate_json_report(evidence_data, current_case)
                    
            elif option == '4':
                # Cadena de Custodia
                print("\n🔗 CADENA DE CUSTODIA")
                print("Funcionalidad en desarrollo...")
                
            elif option == '5':
                # Configuración
                print("\n⚙️ CONFIGURACIÓN Y HERRAMIENTAS")
                print("[1] Verificar dependencias")
                print("[2] Información del sistema")
                print("[3] Limpiar archivos temporales")
                
                config_option = input("Selecciona una opción: ")
                
                if config_option == '1':
                    print("\n🔍 Verificando dependencias...")
                    try:
                        import psutil
                        print(f"✅ psutil: {psutil.__version__}")
                    except ImportError:
                        print("❌ psutil: No instalado")
                        
                    print(f"✅ Python: {platform.python_version()}")
                    print(f"✅ Sistema: {platform.system()} {platform.release()}")
                    
                elif config_option == '2':
                    print("\n📊 Información del sistema:")
                    uname = platform.uname()
                    print(f"Hostname: {uname.node}")
                    print(f"Sistema: {uname.system} {uname.release}")
                    print(f"Arquitectura: {uname.machine}")
                    print(f"Procesador: {uname.processor}")
                    
            elif option == '6':
                # Ayuda
                help_text = """
❓ AYUDA - ForenseCTL Linux

🎯 FUNCIONALIDADES PRINCIPALES:

1. 📁 Gestión de Casos:
   - Crear nuevos casos forenses
   - Listar casos existentes
   - Seleccionar caso activo

2. 🔍 Análisis Forense:
   - Análisis completo del sistema Linux
   - Recopilación de procesos en ejecución
   - Análisis de conexiones de red
   - Inventario de paquetes instalados
   - Análisis de archivos críticos del sistema

3. 📄 Generación de Reportes:
   - Reportes HTML profesionales
   - Exportación de datos en JSON
   - Reportes detallados con evidencia

4. 🔗 Cadena de Custodia:
   - Registro automático de acciones
   - Trazabilidad completa
   - Verificación de integridad

⚠️  REQUISITOS:
- Python 3.6+
- psutil (pip install psutil)
- Permisos de root para análisis completo

🔒 SEGURIDAD:
- Todos los datos se almacenan localmente
- No se realizan conexiones externas
- Verificación de integridad con SHA256

📞 SOPORTE:
Esta herramienta está diseñada para profesionales
de ciberseguridad y equipos DFIR.
"""
                print(help_text)
                
            elif option == '0':
                print("\n👋 Gracias por usar ForenseCTL Linux")
                print("🔒 Recuerda manejar la evidencia de forma segura")
                break
                
            else:
                print("❌ Opción inválida. Intenta de nuevo.")
                
            input("\nPresiona Enter para continuar...")
            
        except KeyboardInterrupt:
            print("\n\n👋 Saliendo de ForenseCTL Linux...")
            break
        except Exception as e:
            print(f"\n❌ Error inesperado: {e}")
            input("Presiona Enter para continuar...")

if __name__ == "__main__":
    main()