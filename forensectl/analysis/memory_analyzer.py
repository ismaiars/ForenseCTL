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