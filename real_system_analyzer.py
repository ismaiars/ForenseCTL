"""Analizador de sistema real para recopilar datos forenses del sistema actual."""

import json
import os
import platform
import psutil
import subprocess
import winreg
import sqlite3
import glob
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


class RealSystemAnalyzer:
    """Analizador que recopila datos reales del sistema Windows actual."""
    
    def __init__(self):
        self.system_info = self._get_system_info()
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Obtener información básica del sistema."""
        return {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "hostname": platform.node(),
            "username": os.getenv('USERNAME', 'Unknown'),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_real_timeline_events(self) -> List[Dict[str, Any]]:
        """Generar timeline con eventos reales del sistema."""
        events = []
        
        # Evento de inicio del análisis
        events.append({
            "timestamp": datetime.now().isoformat(),
            "event_type": "analysis_start",
            "description": f"Análisis forense iniciado en {self.system_info['hostname']}",
            "source": "ForenseCTL Real Analyzer",
            "details": {
                "system": self.system_info['system'],
                "release": self.system_info['release'],
                "username": self.system_info['username']
            }
        })
        
        # Procesos en ejecución
        try:
            running_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'username']):
                try:
                    proc_info = proc.info
                    if proc_info['create_time']:
                        create_time = datetime.fromtimestamp(proc_info['create_time'])
                        running_processes.append({
                            "timestamp": create_time.isoformat(),
                            "event_type": "process_start",
                            "description": f"Proceso iniciado: {proc_info['name']} (PID: {proc_info['pid']})",
                            "source": "System Process Monitor",
                            "details": {
                                "pid": proc_info['pid'],
                                "name": proc_info['name'],
                                "username": proc_info.get('username', 'N/A')
                            }
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Agregar solo los 10 procesos más recientes
            running_processes.sort(key=lambda x: x['timestamp'], reverse=True)
            events.extend(running_processes[:10])
            
        except Exception as e:
            events.append({
                "timestamp": datetime.now().isoformat(),
                "event_type": "error",
                "description": f"Error obteniendo procesos: {str(e)}",
                "source": "System Process Monitor"
            })
        
        # Información de red
        try:
            network_connections = psutil.net_connections(kind='inet')
            active_connections = [conn for conn in network_connections if conn.status == 'ESTABLISHED']
            
            if active_connections:
                events.append({
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "network_analysis",
                    "description": f"Conexiones de red activas detectadas: {len(active_connections)}",
                    "source": "Network Monitor",
                    "details": {
                        "total_connections": len(active_connections),
                        "sample_connections": [
                            f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip if conn.raddr else 'N/A'}:{conn.raddr.port if conn.raddr else 'N/A'}"
                            for conn in active_connections[:5]
                        ]
                    }
                })
        except Exception as e:
            events.append({
                "timestamp": datetime.now().isoformat(),
                "event_type": "error",
                "description": f"Error obteniendo conexiones de red: {str(e)}",
                "source": "Network Monitor"
            })
        
        return events
    
    def get_real_artifacts(self) -> Dict[str, Any]:
        """Extraer artefactos reales del sistema."""
        artifacts = {
            "registry_keys": [],
            "browser_artifacts": [],
            "system_artifacts": [],
            "running_processes": [],
            "network_info": {},
            "disk_info": {},
            "timestamp": datetime.now().isoformat()
        }
        
        # Claves de registro reales
        try:
            registry_keys = []
            
            # Programas de inicio
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            registry_keys.append({
                                "key": f"HKLM\\Run\\{name}",
                                "value": str(value),
                                "type": "startup_program"
                            })
                            i += 1
                        except WindowsError:
                            break
            except Exception:
                pass
            
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            registry_keys.append({
                                "key": f"HKCU\\Run\\{name}",
                                "value": str(value),
                                "type": "startup_program"
                            })
                            i += 1
                        except WindowsError:
                            break
            except Exception:
                pass
            
            artifacts["registry_keys"] = registry_keys
            
        except Exception as e:
            artifacts["registry_keys"] = [f"Error accediendo al registro: {str(e)}"]
        
        # Artefactos de navegador
        try:
            browser_artifacts = []
            user_profile = os.getenv('USERPROFILE', '')
            
            # Chrome
            chrome_history = Path(user_profile) / "AppData/Local/Google/Chrome/User Data/Default/History"
            if chrome_history.exists():
                browser_artifacts.append(f"Chrome History encontrado: {chrome_history}")
            
            # Firefox
            firefox_profiles = Path(user_profile) / "AppData/Roaming/Mozilla/Firefox/Profiles"
            if firefox_profiles.exists():
                profiles = list(firefox_profiles.glob("*.default*"))
                if profiles:
                    browser_artifacts.append(f"Firefox Profile encontrado: {profiles[0]}")
            
            # Edge
            edge_data = Path(user_profile) / "AppData/Local/Microsoft/Edge/User Data/Default"
            if edge_data.exists():
                browser_artifacts.append(f"Edge Data encontrado: {edge_data}")
            
            artifacts["browser_artifacts"] = browser_artifacts if browser_artifacts else ["No se encontraron artefactos de navegador"]
            
        except Exception as e:
            artifacts["browser_artifacts"] = [f"Error buscando artefactos de navegador: {str(e)}"]
        
        # Artefactos del sistema
        try:
            system_artifacts = []
            
            # Event Logs
            event_logs_dir = Path("C:/Windows/System32/winevt/Logs")
            if event_logs_dir.exists():
                evtx_files = list(event_logs_dir.glob("*.evtx"))
                system_artifacts.append(f"Event Logs encontrados: {len(evtx_files)} archivos .evtx")
            
            # Prefetch
            prefetch_dir = Path("C:/Windows/Prefetch")
            if prefetch_dir.exists():
                pf_files = list(prefetch_dir.glob("*.pf"))
                system_artifacts.append(f"Prefetch Files encontrados: {len(pf_files)} archivos .pf")
            
            # Recent Documents
            recent_dir = Path(user_profile) / "AppData/Roaming/Microsoft/Windows/Recent"
            if recent_dir.exists():
                recent_files = list(recent_dir.glob("*.lnk"))
                system_artifacts.append(f"Recent Documents: {len(recent_files)} archivos .lnk")
            
            artifacts["system_artifacts"] = system_artifacts if system_artifacts else ["No se encontraron artefactos del sistema"]
            
        except Exception as e:
            artifacts["system_artifacts"] = [f"Error buscando artefactos del sistema: {str(e)}"]
        
        # Procesos en ejecución
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "cpu_percent": proc_info.get('cpu_percent', 0),
                        "memory_percent": proc_info.get('memory_percent', 0)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Top 10 procesos por uso de CPU
            processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
            artifacts["running_processes"] = processes[:10]
            
        except Exception as e:
            artifacts["running_processes"] = [{"error": f"Error obteniendo procesos: {str(e)}"}]
        
        # Información de red
        try:
            network_info = {
                "interfaces": [],
                "connections": 0
            }
            
            # Interfaces de red
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family.name == 'AF_INET':
                        network_info["interfaces"].append({
                            "interface": interface,
                            "ip": addr.address,
                            "netmask": addr.netmask
                        })
            
            # Conexiones activas
            connections = psutil.net_connections(kind='inet')
            network_info["connections"] = len([c for c in connections if c.status == 'ESTABLISHED'])
            
            artifacts["network_info"] = network_info
            
        except Exception as e:
            artifacts["network_info"] = {"error": f"Error obteniendo información de red: {str(e)}"}
        
        # Información de disco
        try:
            disk_info = {
                "partitions": [],
                "usage": {}
            }
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info["partitions"].append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total_gb": round(usage.total / (1024**3), 2),
                        "used_gb": round(usage.used / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2),
                        "percent_used": round((usage.used / usage.total) * 100, 2)
                    })
                except PermissionError:
                    continue
            
            artifacts["disk_info"] = disk_info
            
        except Exception as e:
            artifacts["disk_info"] = {"error": f"Error obteniendo información de disco: {str(e)}"}
        
        return artifacts
    
    def get_real_security_analysis(self) -> Dict[str, Any]:
        """Realizar análisis de seguridad real del sistema."""
        security_analysis = {
            "threats_detected": [],
            "vulnerabilities": [],
            "risk_level": "UNKNOWN",
            "recommendations": [],
            "security_score": 0,
            "system_info": self.system_info,
            "timestamp": datetime.now().isoformat()
        }
        
        risk_factors = 0
        total_checks = 0
        
        # Verificar procesos sospechosos
        try:
            suspicious_processes = []
            suspicious_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['name'].lower() in suspicious_names:
                        if proc_info.get('cpu_percent', 0) > 50:
                            suspicious_processes.append(f"Proceso con alto CPU: {proc_info['name']} (PID: {proc_info['pid']})")
                            risk_factors += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if suspicious_processes:
                security_analysis["threats_detected"].extend(suspicious_processes)
            
            total_checks += 1
            
        except Exception as e:
            security_analysis["vulnerabilities"].append(f"Error verificando procesos: {str(e)}")
        
        # Verificar conexiones de red sospechosas
        try:
            suspicious_connections = []
            connections = psutil.net_connections(kind='inet')
            external_connections = 0
            
            for conn in connections:
                if conn.raddr and conn.status == 'ESTABLISHED':
                    external_connections += 1
                    # Verificar conexiones a puertos comúnmente maliciosos
                    if conn.raddr.port in [4444, 5555, 6666, 8080, 9999]:
                        suspicious_connections.append(f"Conexión sospechosa a puerto {conn.raddr.port}: {conn.raddr.ip}")
                        risk_factors += 2
            
            if external_connections > 20:
                security_analysis["vulnerabilities"].append(f"Alto número de conexiones externas: {external_connections}")
                risk_factors += 1
            
            if suspicious_connections:
                security_analysis["threats_detected"].extend(suspicious_connections)
            
            total_checks += 1
            
        except Exception as e:
            security_analysis["vulnerabilities"].append(f"Error verificando conexiones: {str(e)}")
        
        # Verificar uso de recursos
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk_usage = psutil.disk_usage('C:\\')
            
            if cpu_percent > 80:
                security_analysis["vulnerabilities"].append(f"Alto uso de CPU: {cpu_percent}%")
                risk_factors += 1
            
            if memory.percent > 85:
                security_analysis["vulnerabilities"].append(f"Alto uso de memoria: {memory.percent}%")
                risk_factors += 1
            
            if (disk_usage.used / disk_usage.total) > 0.9:
                security_analysis["vulnerabilities"].append(f"Disco casi lleno: {round((disk_usage.used / disk_usage.total) * 100, 1)}%")
                risk_factors += 1
            
            total_checks += 3
            
        except Exception as e:
            security_analysis["vulnerabilities"].append(f"Error verificando recursos: {str(e)}")
        
        # Calcular nivel de riesgo y puntuación
        if total_checks > 0:
            risk_percentage = (risk_factors / (total_checks * 2)) * 100  # Máximo 2 puntos de riesgo por check
            
            if risk_percentage < 20:
                security_analysis["risk_level"] = "LOW"
                security_analysis["security_score"] = max(80, 100 - risk_percentage)
            elif risk_percentage < 50:
                security_analysis["risk_level"] = "MEDIUM"
                security_analysis["security_score"] = max(50, 80 - risk_percentage)
            else:
                security_analysis["risk_level"] = "HIGH"
                security_analysis["security_score"] = max(20, 50 - risk_percentage)
        else:
            security_analysis["security_score"] = 50
        
        # Generar recomendaciones basadas en hallazgos
        recommendations = [
            "Mantener el sistema operativo actualizado",
            "Usar software antivirus actualizado",
            "Revisar procesos en ejecución regularmente",
            "Monitorear conexiones de red activas"
        ]
        
        if risk_factors > 0:
            recommendations.extend([
                "Investigar procesos con alto uso de recursos",
                "Verificar conexiones de red sospechosas",
                "Realizar escaneo completo de malware"
            ])
        
        if security_analysis["risk_level"] == "HIGH":
            recommendations.extend([
                "Considerar desconectar el sistema de la red",
                "Realizar análisis forense completo",
                "Contactar al equipo de seguridad"
            ])
        
        security_analysis["recommendations"] = recommendations
        
        return security_analysis
    
    def get_event_logs_info(self) -> List[Dict[str, Any]]:
        """Obtener información de logs de eventos de Windows."""
        event_logs = []
        
        try:
            # Buscar archivos .evtx en el directorio de logs
            logs_path = "C:\\Windows\\System32\\winevt\\Logs"
            if os.path.exists(logs_path):
                for log_file in glob.glob(os.path.join(logs_path, "*.evtx")):
                    try:
                        stat = os.stat(log_file)
                        event_logs.append({
                            "name": os.path.basename(log_file),
                            "path": log_file,
                            "size_bytes": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            "type": "Windows Event Log"
                        })
                    except Exception as e:
                        continue
        except Exception as e:
            event_logs.append({
                "error": f"No se pudieron acceder a los logs de eventos: {str(e)}",
                "type": "error"
            })
        
        return event_logs
    
    def get_prefetch_files(self) -> List[Dict[str, Any]]:
        """Obtener información de archivos Prefetch."""
        prefetch_files = []
        
        try:
            prefetch_path = "C:\\Windows\\Prefetch"
            if os.path.exists(prefetch_path):
                for pf_file in glob.glob(os.path.join(prefetch_path, "*.pf")):
                    try:
                        stat = os.stat(pf_file)
                        prefetch_files.append({
                            "name": os.path.basename(pf_file),
                            "path": pf_file,
                            "size_bytes": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            "type": "Prefetch File"
                        })
                    except Exception as e:
                        continue
        except Exception as e:
            prefetch_files.append({
                "error": f"No se pudieron acceder a los archivos Prefetch: {str(e)}",
                "type": "error"
            })
        
        return prefetch_files
    
    def get_browser_history(self) -> List[Dict[str, Any]]:
        """Obtener historial de navegadores (solo metadatos por privacidad)."""
        browser_data = []
        username = os.getenv('USERNAME', 'Unknown')
        
        # Rutas de navegadores comunes
        browser_paths = {
            "Chrome": f"C:\\Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
            "Edge": f"C:\\Users\\{username}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History",
            "Firefox": f"C:\\Users\\{username}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
        }
        
        for browser, path in browser_paths.items():
            try:
                if browser == "Firefox":
                    # Firefox tiene múltiples perfiles
                    if os.path.exists(path):
                        for profile_dir in os.listdir(path):
                            profile_path = os.path.join(path, profile_dir)
                            if os.path.isdir(profile_path):
                                places_db = os.path.join(profile_path, "places.sqlite")
                                if os.path.exists(places_db):
                                    stat = os.stat(places_db)
                                    browser_data.append({
                                        "browser": f"{browser} ({profile_dir})",
                                        "database_path": places_db,
                                        "size_bytes": stat.st_size,
                                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                        "type": "Browser History Database"
                                    })
                else:
                    # Chrome y Edge
                    if os.path.exists(path):
                        stat = os.stat(path)
                        browser_data.append({
                            "browser": browser,
                            "database_path": path,
                            "size_bytes": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "type": "Browser History Database"
                        })
            except Exception as e:
                continue
        
        return browser_data
    
    def get_usb_device_history(self) -> List[Dict[str, Any]]:
        """Obtener historial de dispositivos USB conectados."""
        usb_devices = []
        
        try:
            # Acceder al registro para obtener información de dispositivos USB
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                              "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR") as key:
                i = 0
                while True:
                    try:
                        device_key = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, device_key) as device:
                            j = 0
                            while True:
                                try:
                                    instance_key = winreg.EnumKey(device, j)
                                    with winreg.OpenKey(device, instance_key) as instance:
                                        try:
                                            friendly_name = winreg.QueryValueEx(instance, "FriendlyName")[0]
                                        except:
                                            friendly_name = device_key
                                        
                                        usb_devices.append({
                                            "device_id": device_key,
                                            "instance_id": instance_key,
                                            "friendly_name": friendly_name,
                                            "type": "USB Storage Device"
                                        })
                                    j += 1
                                except OSError:
                                    break
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            usb_devices.append({
                "error": f"No se pudo acceder al historial USB: {str(e)}",
                "type": "error"
            })
        
        return usb_devices
    
    def get_startup_programs(self) -> List[Dict[str, Any]]:
        """Obtener programas de inicio del sistema."""
        startup_programs = []
        
        # Ubicaciones de registro para programas de inicio
        startup_keys = [
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
        ]
        
        for hive, key_path in startup_keys:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, reg_type = winreg.EnumValue(key, i)
                            startup_programs.append({
                                "name": name,
                                "command": value,
                                "registry_hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                                "registry_key": key_path,
                                "type": "Startup Program"
                            })
                            i += 1
                        except OSError:
                            break
            except Exception as e:
                continue
        
        return startup_programs
    
    def get_installed_software(self) -> List[Dict[str, Any]]:
        """Obtener lista de software instalado."""
        installed_software = []
        
        # Ubicaciones de registro para software instalado
        software_keys = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        ]
        
        for key_path in software_keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    try:
                                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                    except:
                                        version = "Unknown"
                                    try:
                                        publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                                    except:
                                        publisher = "Unknown"
                                    try:
                                        install_date = winreg.QueryValueEx(subkey, "InstallDate")[0]
                                    except:
                                        install_date = "Unknown"
                                    
                                    installed_software.append({
                                        "name": display_name,
                                        "version": version,
                                        "publisher": publisher,
                                        "install_date": install_date,
                                        "registry_key": subkey_name,
                                        "type": "Installed Software"
                                    })
                                except:
                                    pass
                            i += 1
                        except OSError:
                            break
            except Exception as e:
                continue
        
        return installed_software
    
    def get_comprehensive_analysis(self) -> Dict[str, Any]:
        """Obtener análisis forense completo del sistema."""
        comprehensive_data = {
            "analysis_info": {
                "timestamp": datetime.now().isoformat(),
                "analyzer": "ForenseCTL Real System Analyzer",
                "system_info": self.system_info
            },
            "timeline_events": self.get_real_timeline_events(),
            "system_artifacts": self.get_real_artifacts(),
            "security_analysis": self.get_real_security_analysis(),
            "event_logs": self.get_event_logs_info(),
            "prefetch_files": self.get_prefetch_files(),
            "browser_history_metadata": self.get_browser_history(),
            "usb_device_history": self.get_usb_device_history(),
            "startup_programs": self.get_startup_programs(),
            "installed_software": self.get_installed_software()
        }
        
        return comprehensive_data