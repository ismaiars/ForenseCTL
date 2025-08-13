"""Analizador de memoria usando Volatility3."""

import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from forensectl import config, logger
from forensectl.core.chain_of_custody import ChainOfCustody
from forensectl.core.manifest import Manifest


class MemoryAnalyzer:
    """Analizador de dumps de memoria usando Volatility3."""
    
    def __init__(self, case_id: str, examiner: str = "") -> None:
        """Inicializar analizador de memoria.
        
        Args:
            case_id: ID del caso
            examiner: Examinador responsable
        """
        self.case_id = case_id
        self.examiner = examiner
        
        # Directorios del caso
        self.case_dir = config.CASES_DIR / case_id
        self.analysis_dir = self.case_dir / "analysis" / "memory"
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        
        # Herramientas auxiliares
        self.chain_of_custody = ChainOfCustody(case_id)
        self.manifest = Manifest(case_id)
        
        # Configuración de Volatility3
        self.volatility_cmd = "vol"
        self.supported_profiles = [
            "windows.info",
            "windows.pslist",
            "windows.psscan",
            "windows.pstree",
            "windows.cmdline",
            "windows.filescan",
            "windows.dlllist",
            "windows.handles",
            "windows.malfind",
            "windows.netscan",
            "windows.registry.hivelist",
            "windows.registry.printkey",
            "windows.vadinfo",
            "windows.memmap",
            "linux.pslist",
            "linux.pstree",
            "linux.lsmod",
            "linux.bash",
            "mac.pslist",
            "mac.pstree",
            "mac.lsmod"
        ]
    
    def analyze_memory_dump(
        self,
        dump_path: Union[str, Path],
        profile: Optional[str] = None,
        plugins: Optional[List[str]] = None,
        output_format: str = "json",
        custom_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Analizar dump de memoria completo.
        
        Args:
            dump_path: Ruta del dump de memoria
            profile: Perfil específico (auto-detectar si None)
            plugins: Lista de plugins a ejecutar (todos si None)
            output_format: Formato de salida ('json', 'csv', 'text')
            custom_options: Opciones personalizadas
            
        Returns:
            Diccionario con resultados del análisis
        """
        dump_path = Path(dump_path)
        if not dump_path.exists():
            raise ValueError(f"Dump de memoria no encontrado: {dump_path}")
        
        analysis_id = str(uuid.uuid4())
        analysis_start = datetime.now(timezone.utc)
        
        logger.info(f"Iniciando análisis de memoria {analysis_id} para dump: {dump_path}")
        
        # Crear directorio de análisis
        analysis_output_dir = self.analysis_dir / analysis_id
        analysis_output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Auto-detectar perfil si no se especifica
            if not profile:
                profile = self._detect_profile(dump_path)
                logger.info(f"Perfil auto-detectado: {profile}")
            
            # Usar plugins por defecto si no se especifican
            if not plugins:
                plugins = self._get_default_plugins(profile)
            
            # Ejecutar análisis
            results = {}
            for plugin in plugins:
                try:
                    plugin_result = self._run_plugin(
                        dump_path, plugin, analysis_output_dir, output_format, custom_options
                    )
                    results[plugin] = plugin_result
                    logger.info(f"Plugin {plugin} ejecutado exitosamente")
                except Exception as e:
                    logger.error(f"Error ejecutando plugin {plugin}: {e}")
                    results[plugin] = {"error": str(e), "status": "failed"}
            
            analysis_end = datetime.now(timezone.utc)
            
            # Crear resumen del análisis
            analysis_summary = {
                "analysis_id": analysis_id,
                "case_id": self.case_id,
                "analysis_type": "memory_analysis",
                "dump_path": str(dump_path),
                "profile": profile,
                "plugins_executed": plugins,
                "output_directory": str(analysis_output_dir),
                "output_format": output_format,
                "started_at": analysis_start.isoformat(),
                "completed_at": analysis_end.isoformat(),
                "duration_seconds": (analysis_end - analysis_start).total_seconds(),
                "examiner": self.examiner,
                "tool_info": {
                    "name": "Volatility3",
                    "version": self._get_volatility_version(),
                    "command": self.volatility_cmd
                },
                "results_summary": self._generate_results_summary(results),
                "custom_options": custom_options or {}
            }
            
            # Guardar resumen
            summary_file = analysis_output_dir / "analysis_summary.json"
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(analysis_summary, f, indent=2, ensure_ascii=False)
            
            # Registrar en manifiesto
            self.manifest.register_analysis(
                analysis_id=analysis_id,
                analysis_type="memory_analysis",
                evidence_id="",  # Se puede vincular después
                tool_name="Volatility3",
                tool_version=self._get_volatility_version(),
                output_path=str(analysis_output_dir),
                examiner=self.examiner,
                description=f"Análisis de memoria con perfil {profile}",
                parameters={
                    "dump_path": str(dump_path),
                    "profile": profile,
                    "plugins": plugins,
                    "output_format": output_format
                },
                results_summary=analysis_summary["results_summary"]
            )
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="memory_analysis_completed",
                description=f"Análisis de memoria completado con {len(plugins)} plugins",
                examiner=self.examiner,
                evidence_path=str(dump_path),
                metadata={
                    "analysis_id": analysis_id,
                    "profile": profile,
                    "plugins_count": len(plugins),
                    "duration_seconds": analysis_summary["duration_seconds"]
                }
            )
            
            logger.info(f"Análisis de memoria {analysis_id} completado exitosamente")
            return analysis_summary
            
        except Exception as e:
            logger.error(f"Error durante análisis de memoria {analysis_id}: {e}")
            
            # Agregar error a cadena de custodia
            self.chain_of_custody.add_entry(
                action="memory_analysis_failed",
                description=f"Fallo en análisis de memoria: {str(e)}",
                examiner=self.examiner,
                evidence_path=str(dump_path),
                metadata={"analysis_id": analysis_id, "error": str(e)}
            )
            
            raise
    
    def run_single_plugin(
        self,
        dump_path: Union[str, Path],
        plugin: str,
        output_format: str = "json",
        custom_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Ejecutar un plugin específico de Volatility3.
        
        Args:
            dump_path: Ruta del dump de memoria
            plugin: Nombre del plugin
            output_format: Formato de salida
            custom_options: Opciones personalizadas
            
        Returns:
            Resultado del plugin
        """
        dump_path = Path(dump_path)
        if not dump_path.exists():
            raise ValueError(f"Dump de memoria no encontrado: {dump_path}")
        
        if plugin not in self.supported_plugins:
            logger.warning(f"Plugin {plugin} no está en la lista de plugins soportados")
        
        analysis_id = f"single_{plugin}_{uuid.uuid4().hex[:8]}"
        output_dir = self.analysis_dir / analysis_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Ejecutando plugin {plugin} en dump: {dump_path}")
        
        try:
            result = self._run_plugin(dump_path, plugin, output_dir, output_format, custom_options)
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="memory_plugin_executed",
                description=f"Plugin {plugin} ejecutado",
                examiner=self.examiner,
                evidence_path=str(dump_path),
                metadata={
                    "plugin": plugin,
                    "output_format": output_format,
                    "output_directory": str(output_dir)
                }
            )
            
            logger.info(f"Plugin {plugin} ejecutado exitosamente")
            return result
            
        except Exception as e:
            logger.error(f"Error ejecutando plugin {plugin}: {e}")
            raise
    
    def extract_processes(self, dump_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Extraer lista de procesos del dump de memoria.
        
        Args:
            dump_path: Ruta del dump de memoria
            
        Returns:
            Lista de procesos encontrados
        """
        profile = self._detect_profile(dump_path)
        
        if profile.startswith("windows"):
            plugin = "windows.pslist"
        elif profile.startswith("linux"):
            plugin = "linux.pslist"
        elif profile.startswith("mac"):
            plugin = "mac.pslist"
        else:
            raise ValueError(f"Perfil no soportado para extracción de procesos: {profile}")
        
        result = self.run_single_plugin(dump_path, plugin, "json")
        
        # Parsear resultados específicos de procesos
        processes = []
        if "output_data" in result:
            for process_data in result["output_data"]:
                processes.append({
                    "pid": process_data.get("PID"),
                    "ppid": process_data.get("PPID"),
                    "name": process_data.get("ImageFileName"),
                    "offset": process_data.get("Offset"),
                    "threads": process_data.get("Threads"),
                    "handles": process_data.get("Handles"),
                    "session_id": process_data.get("SessionId"),
                    "wow64": process_data.get("Wow64"),
                    "create_time": process_data.get("CreateTime"),
                    "exit_time": process_data.get("ExitTime")
                })
        
        return processes
    
    def extract_network_connections(self, dump_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Extraer conexiones de red del dump de memoria.
        
        Args:
            dump_path: Ruta del dump de memoria
            
        Returns:
            Lista de conexiones de red
        """
        profile = self._detect_profile(dump_path)
        
        if not profile.startswith("windows"):
            raise ValueError(f"Extracción de red solo soportada para Windows, perfil: {profile}")
        
        result = self.run_single_plugin(dump_path, "windows.netscan", "json")
        
        # Parsear resultados de conexiones de red
        connections = []
        if "output_data" in result:
            for conn_data in result["output_data"]:
                connections.append({
                    "offset": conn_data.get("Offset"),
                    "protocol": conn_data.get("Proto"),
                    "local_address": conn_data.get("LocalAddr"),
                    "local_port": conn_data.get("LocalPort"),
                    "foreign_address": conn_data.get("ForeignAddr"),
                    "foreign_port": conn_data.get("ForeignPort"),
                    "state": conn_data.get("State"),
                    "pid": conn_data.get("PID"),
                    "owner": conn_data.get("Owner"),
                    "created": conn_data.get("Created")
                })
        
        return connections
    
    def detect_malware_indicators(self, dump_path: Union[str, Path]) -> Dict[str, Any]:
        """Detectar indicadores de malware en el dump de memoria.
        
        Args:
            dump_path: Ruta del dump de memoria
            
        Returns:
            Diccionario con indicadores de malware
        """
        profile = self._detect_profile(dump_path)
        
        if not profile.startswith("windows"):
            raise ValueError(f"Detección de malware solo soportada para Windows, perfil: {profile}")
        
        # Ejecutar plugin malfind
        malfind_result = self.run_single_plugin(dump_path, "windows.malfind", "json")
        
        # Analizar resultados
        indicators = {
            "suspicious_processes": [],
            "injected_code": [],
            "suspicious_network": [],
            "hidden_processes": [],
            "summary": {
                "total_indicators": 0,
                "risk_level": "low"
            }
        }
        
        # Procesar resultados de malfind
        if "output_data" in malfind_result:
            for finding in malfind_result["output_data"]:
                indicators["injected_code"].append({
                    "pid": finding.get("PID"),
                    "process": finding.get("Process"),
                    "address": finding.get("Address"),
                    "protection": finding.get("Protection"),
                    "hexdump": finding.get("Hexdump"),
                    "disasm": finding.get("Disasm")
                })
        
        # Comparar pslist vs psscan para procesos ocultos
        try:
            pslist_result = self.run_single_plugin(dump_path, "windows.pslist", "json")
            psscan_result = self.run_single_plugin(dump_path, "windows.psscan", "json")
            
            pslist_pids = set()
            psscan_pids = set()
            
            if "output_data" in pslist_result:
                pslist_pids = {p.get("PID") for p in pslist_result["output_data"]}
            
            if "output_data" in psscan_result:
                psscan_pids = {p.get("PID") for p in psscan_result["output_data"]}
            
            hidden_pids = psscan_pids - pslist_pids
            for pid in hidden_pids:
                if pid:  # Filtrar None
                    indicators["hidden_processes"].append({"pid": pid})
                    
        except Exception as e:
            logger.warning(f"Error comparando procesos ocultos: {e}")
        
        # Calcular resumen
        total_indicators = (
            len(indicators["injected_code"]) +
            len(indicators["hidden_processes"]) +
            len(indicators["suspicious_network"])
        )
        
        indicators["summary"]["total_indicators"] = total_indicators
        
        if total_indicators == 0:
            indicators["summary"]["risk_level"] = "low"
        elif total_indicators <= 5:
            indicators["summary"]["risk_level"] = "medium"
        else:
            indicators["summary"]["risk_level"] = "high"
        
        return indicators
    
    def _detect_profile(self, dump_path: Path) -> str:
        """Auto-detectar perfil del dump de memoria.
        
        Args:
            dump_path: Ruta del dump
            
        Returns:
            Perfil detectado
        """
        try:
            # Intentar con windows.info primero
            cmd = [self.volatility_cmd, "-f", str(dump_path), "windows.info"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return "windows"
            
            # Intentar con linux si Windows falla
            cmd = [self.volatility_cmd, "-f", str(dump_path), "linux.pslist"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return "linux"
            
            # Intentar con mac si Linux falla
            cmd = [self.volatility_cmd, "-f", str(dump_path), "mac.pslist"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return "mac"
            
            # Por defecto, asumir Windows
            logger.warning("No se pudo auto-detectar perfil, asumiendo Windows")
            return "windows"
            
        except Exception as e:
            logger.error(f"Error auto-detectando perfil: {e}")
            return "windows"
    
    def _get_default_plugins(self, profile: str) -> List[str]:
        """Obtener plugins por defecto según el perfil.
        
        Args:
            profile: Perfil del sistema
            
        Returns:
            Lista de plugins por defecto
        """
        if profile.startswith("windows"):
            return [
                "windows.info",
                "windows.pslist",
                "windows.pstree",
                "windows.cmdline",
                "windows.filescan",
                "windows.netscan",
                "windows.malfind",
                "windows.handles"
            ]
        elif profile.startswith("linux"):
            return [
                "linux.pslist",
                "linux.pstree",
                "linux.lsmod",
                "linux.bash"
            ]
        elif profile.startswith("mac"):
            return [
                "mac.pslist",
                "mac.pstree",
                "mac.lsmod"
            ]
        else:
            return ["windows.info", "windows.pslist"]
    
    def _run_plugin(
        self,
        dump_path: Path,
        plugin: str,
        output_dir: Path,
        output_format: str,
        custom_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Ejecutar plugin específico de Volatility3.
        
        Args:
            dump_path: Ruta del dump
            plugin: Nombre del plugin
            output_dir: Directorio de salida
            output_format: Formato de salida
            custom_options: Opciones personalizadas
            
        Returns:
            Resultado del plugin
        """
        # Construir comando
        cmd = [self.volatility_cmd, "-f", str(dump_path), plugin]
        
        # Agregar opciones personalizadas
        if custom_options:
            for key, value in custom_options.items():
                cmd.extend([f"--{key}", str(value)])
        
        # Configurar salida
        output_file = output_dir / f"{plugin}.{output_format}"
        
        if output_format == "json":
            cmd.extend(["--output", "json"])
        elif output_format == "csv":
            cmd.extend(["--output", "csv"])
        
        start_time = datetime.now(timezone.utc)
        
        try:
            # Ejecutar comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutos timeout
                cwd=output_dir
            )
            
            end_time = datetime.now(timezone.utc)
            
            # Guardar salida
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            
            # Guardar errores si existen
            if result.stderr:
                error_file = output_dir / f"{plugin}_errors.txt"
                with open(error_file, "w", encoding="utf-8") as f:
                    f.write(result.stderr)
            
            # Parsear salida JSON si es aplicable
            output_data = None
            if output_format == "json" and result.stdout.strip():
                try:
                    output_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    logger.warning(f"No se pudo parsear salida JSON del plugin {plugin}")
            
            return {
                "plugin": plugin,
                "status": "success" if result.returncode == 0 else "error",
                "return_code": result.returncode,
                "output_file": str(output_file),
                "output_data": output_data,
                "execution_time": (end_time - start_time).total_seconds(),
                "command": " ".join(cmd),
                "stdout_length": len(result.stdout),
                "stderr_length": len(result.stderr)
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout ejecutando plugin {plugin}")
            return {
                "plugin": plugin,
                "status": "timeout",
                "error": "Plugin execution timed out",
                "command": " ".join(cmd)
            }
        except Exception as e:
            logger.error(f"Error ejecutando plugin {plugin}: {e}")
            return {
                "plugin": plugin,
                "status": "error",
                "error": str(e),
                "command": " ".join(cmd)
            }
    
    def _get_volatility_version(self) -> str:
        """Obtener versión de Volatility3.
        
        Returns:
            Versión de Volatility3
        """
        try:
            result = subprocess.run(
                [self.volatility_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return "unknown"
                
        except Exception:
            return "unknown"
    
    def extract_registry_data(self, dump_path: Union[str, Path]) -> Dict[str, Any]:
        """Extraer datos del registro de Windows del dump de memoria.
        
        Args:
            dump_path: Ruta del dump de memoria
            
        Returns:
            Datos del registro extraídos
        """
        profile = self._detect_profile(dump_path)
        
        if not profile.startswith("windows"):
            raise ValueError(f"Extracción de registro solo soportada para Windows, perfil: {profile}")
        
        registry_data = {
            "hives": [],
            "keys": [],
            "values": [],
            "summary": {
                "total_hives": 0,
                "total_keys": 0,
                "total_values": 0
            }
        }
        
        try:
            # Listar hives del registro
            hivelist_result = self.run_single_plugin(dump_path, "windows.registry.hivelist", "json")
            
            if "output_data" in hivelist_result:
                for hive in hivelist_result["output_data"]:
                    registry_data["hives"].append({
                        "offset": hive.get("Offset"),
                        "name": hive.get("Name"),
                        "file_full_path": hive.get("FileFullPath")
                    })
                
                registry_data["summary"]["total_hives"] = len(registry_data["hives"])
            
            # Extraer claves importantes del registro
            important_keys = [
                "windows.registry.printkey --key \"Microsoft\\Windows\\CurrentVersion\\Run\"",
                "windows.registry.printkey --key \"Microsoft\\Windows\\CurrentVersion\\RunOnce\"",
                "windows.registry.printkey --key \"Microsoft\\Windows NT\\CurrentVersion\""
            ]
            
            for key_cmd in important_keys:
                try:
                    key_result = self.run_single_plugin(dump_path, key_cmd.split()[0], "json")
                    if "output_data" in key_result:
                        registry_data["keys"].extend(key_result["output_data"])
                except Exception as e:
                    logger.warning(f"Error extrayendo clave del registro: {e}")
            
            registry_data["summary"]["total_keys"] = len(registry_data["keys"])
            
        except Exception as e:
            logger.error(f"Error extrayendo datos del registro: {e}")
            registry_data["error"] = str(e)
        
        return registry_data
    
    def extract_files_from_memory(self, dump_path: Union[str, Path], output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Extraer archivos del dump de memoria.
        
        Args:
            dump_path: Ruta del dump de memoria
            output_dir: Directorio de salida para archivos extraídos
            
        Returns:
            Información sobre archivos extraídos
        """
        if output_dir is None:
            output_dir = self.analysis_dir / f"extracted_files_{uuid.uuid4().hex[:8]}"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        profile = self._detect_profile(dump_path)
        
        if not profile.startswith("windows"):
            raise ValueError(f"Extracción de archivos solo soportada para Windows, perfil: {profile}")
        
        extraction_data = {
            "files_found": [],
            "files_extracted": [],
            "extraction_errors": [],
            "summary": {
                "total_files_found": 0,
                "total_files_extracted": 0,
                "total_errors": 0,
                "extraction_directory": str(output_dir)
            }
        }
        
        try:
            # Escanear archivos en memoria
            filescan_result = self.run_single_plugin(dump_path, "windows.filescan", "json")
            
            if "output_data" in filescan_result:
                for file_info in filescan_result["output_data"]:
                    file_data = {
                        "offset": file_info.get("Offset"),
                        "name": file_info.get("Name"),
                        "size": file_info.get("Size")
                    }
                    extraction_data["files_found"].append(file_data)
                
                extraction_data["summary"]["total_files_found"] = len(extraction_data["files_found"])
                
                # Extraer archivos específicos (limitado a archivos pequeños por rendimiento)
                interesting_extensions = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"]
                
                for file_info in extraction_data["files_found"][:50]:  # Limitar a 50 archivos
                    file_name = file_info.get("name", "")
                    file_size = file_info.get("size", 0)
                    
                    # Solo extraer archivos pequeños e interesantes
                    if (any(file_name.lower().endswith(ext) for ext in interesting_extensions) and 
                        file_size and file_size < 1024 * 1024):  # < 1MB
                        
                        try:
                            offset = file_info.get("offset")
                            if offset:
                                # Usar dumpfiles para extraer
                                extract_result = self._extract_file_by_offset(dump_path, offset, output_dir)
                                if extract_result["success"]:
                                    extraction_data["files_extracted"].append({
                                        "original_name": file_name,
                                        "extracted_path": extract_result["extracted_path"],
                                        "offset": offset,
                                        "size": file_size
                                    })
                                else:
                                    extraction_data["extraction_errors"].append({
                                        "file_name": file_name,
                                        "offset": offset,
                                        "error": extract_result["error"]
                                    })
                        except Exception as e:
                            extraction_data["extraction_errors"].append({
                                "file_name": file_name,
                                "error": str(e)
                            })
                
                extraction_data["summary"]["total_files_extracted"] = len(extraction_data["files_extracted"])
                extraction_data["summary"]["total_errors"] = len(extraction_data["extraction_errors"])
            
        except Exception as e:
            logger.error(f"Error extrayendo archivos de memoria: {e}")
            extraction_data["error"] = str(e)
        
        return extraction_data
    
    def analyze_process_memory(self, dump_path: Union[str, Path], pid: int) -> Dict[str, Any]:
        """Analizar memoria específica de un proceso.
        
        Args:
            dump_path: Ruta del dump de memoria
            pid: ID del proceso a analizar
            
        Returns:
            Análisis detallado del proceso
        """
        profile = self._detect_profile(dump_path)
        
        if not profile.startswith("windows"):
            raise ValueError(f"Análisis de proceso solo soportado para Windows, perfil: {profile}")
        
        process_analysis = {
            "pid": pid,
            "process_info": {},
            "memory_sections": [],
            "handles": [],
            "dlls": [],
            "command_line": "",
            "environment_variables": [],
            "suspicious_indicators": [],
            "summary": {
                "total_memory_sections": 0,
                "total_handles": 0,
                "total_dlls": 0,
                "risk_level": "low"
            }
        }
        
        try:
            # Información básica del proceso
            pslist_result = self.run_single_plugin(dump_path, "windows.pslist", "json")
            
            if "output_data" in pslist_result:
                for process in pslist_result["output_data"]:
                    if process.get("PID") == pid:
                        process_analysis["process_info"] = {
                            "name": process.get("ImageFileName"),
                            "ppid": process.get("PPID"),
                            "threads": process.get("Threads"),
                            "handles": process.get("Handles"),
                            "session_id": process.get("SessionId"),
                            "wow64": process.get("Wow64"),
                            "create_time": process.get("CreateTime"),
                            "exit_time": process.get("ExitTime")
                        }
                        break
            
            # Línea de comandos
            try:
                cmdline_result = self.run_single_plugin(dump_path, "windows.cmdline", "json")
                if "output_data" in cmdline_result:
                    for cmd_info in cmdline_result["output_data"]:
                        if cmd_info.get("PID") == pid:
                            process_analysis["command_line"] = cmd_info.get("Args", "")
                            break
            except Exception as e:
                logger.warning(f"Error obteniendo línea de comandos para PID {pid}: {e}")
            
            # Variables de entorno
            try:
                envars_result = self.run_single_plugin(dump_path, "windows.envars", "json")
                if "output_data" in envars_result:
                    for env_info in envars_result["output_data"]:
                        if env_info.get("PID") == pid:
                            process_analysis["environment_variables"].append({
                                "variable": env_info.get("Variable"),
                                "value": env_info.get("Value")
                            })
            except Exception as e:
                logger.warning(f"Error obteniendo variables de entorno para PID {pid}: {e}")
            
            # DLLs cargadas
            try:
                dlllist_result = self.run_single_plugin(dump_path, "windows.dlllist", "json")
                if "output_data" in dlllist_result:
                    for dll_info in dlllist_result["output_data"]:
                        if dll_info.get("PID") == pid:
                            process_analysis["dlls"].append({
                                "base": dll_info.get("Base"),
                                "size": dll_info.get("Size"),
                                "name": dll_info.get("Name"),
                                "path": dll_info.get("Path")
                            })
                
                process_analysis["summary"]["total_dlls"] = len(process_analysis["dlls"])
            except Exception as e:
                logger.warning(f"Error obteniendo DLLs para PID {pid}: {e}")
            
            # Handles
            try:
                handles_result = self.run_single_plugin(dump_path, "windows.handles", "json")
                if "output_data" in handles_result:
                    for handle_info in handles_result["output_data"]:
                        if handle_info.get("PID") == pid:
                            process_analysis["handles"].append({
                                "offset": handle_info.get("Offset"),
                                "handle_value": handle_info.get("HandleValue"),
                                "granted_access": handle_info.get("GrantedAccess"),
                                "type": handle_info.get("Type"),
                                "details": handle_info.get("Details")
                            })
                
                process_analysis["summary"]["total_handles"] = len(process_analysis["handles"])
            except Exception as e:
                logger.warning(f"Error obteniendo handles para PID {pid}: {e}")
            
            # Análisis de indicadores sospechosos
            suspicious_count = 0
            
            # Verificar si el proceso tiene DLLs sospechosas
            suspicious_dlls = ["injected", "unknown", "temp", "appdata"]
            for dll in process_analysis["dlls"]:
                dll_path = dll.get("path", "").lower()
                if any(susp in dll_path for susp in suspicious_dlls):
                    process_analysis["suspicious_indicators"].append({
                        "type": "suspicious_dll",
                        "description": f"DLL sospechosa: {dll.get('name')}",
                        "details": dll
                    })
                    suspicious_count += 1
            
            # Verificar handles sospechosos
            suspicious_handles = ["mutant", "event", "section"]
            for handle in process_analysis["handles"]:
                handle_type = handle.get("type", "").lower()
                if handle_type in suspicious_handles:
                    process_analysis["suspicious_indicators"].append({
                        "type": "suspicious_handle",
                        "description": f"Handle sospechoso: {handle_type}",
                        "details": handle
                    })
                    suspicious_count += 1
            
            # Calcular nivel de riesgo
            if suspicious_count == 0:
                process_analysis["summary"]["risk_level"] = "low"
            elif suspicious_count <= 3:
                process_analysis["summary"]["risk_level"] = "medium"
            else:
                process_analysis["summary"]["risk_level"] = "high"
            
        except Exception as e:
            logger.error(f"Error analizando proceso {pid}: {e}")
            process_analysis["error"] = str(e)
        
        return process_analysis
    
    def _extract_file_by_offset(self, dump_path: Path, offset: str, output_dir: Path) -> Dict[str, Any]:
        """Extraer archivo por offset usando dumpfiles.
        
        Args:
            dump_path: Ruta del dump
            offset: Offset del archivo
            output_dir: Directorio de salida
            
        Returns:
            Resultado de la extracción
        """
        try:
            cmd = [self.volatility_cmd, "-f", str(dump_path), "windows.dumpfiles", "--virtaddr", offset]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=output_dir
            )
            
            if result.returncode == 0:
                # Buscar archivo extraído
                extracted_files = list(output_dir.glob(f"*{offset}*"))
                if extracted_files:
                    return {
                        "success": True,
                        "extracted_path": str(extracted_files[0]),
                        "offset": offset
                    }
            
            return {
                "success": False,
                "error": f"No se pudo extraer archivo en offset {offset}",
                "stderr": result.stderr
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "offset": offset
            }
    
    def _generate_results_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generar resumen de resultados.
        
        Args:
            results: Resultados de plugins
            
        Returns:
            Resumen de resultados
        """
        summary = {
            "total_plugins": len(results),
            "successful_plugins": 0,
            "failed_plugins": 0,
            "plugins_with_data": 0,
            "total_execution_time": 0,
            "plugin_status": {}
        }
        
        for plugin, result in results.items():
            status = result.get("status", "unknown")
            summary["plugin_status"][plugin] = status
            
            if status == "success":
                summary["successful_plugins"] += 1
                if result.get("output_data"):
                    summary["plugins_with_data"] += 1
            else:
                summary["failed_plugins"] += 1
            
            execution_time = result.get("execution_time", 0)
            summary["total_execution_time"] += execution_time
        
        return summary