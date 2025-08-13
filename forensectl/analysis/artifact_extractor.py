"""Extractor de artefactos forenses específicos del sistema operativo."""

import json
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from forensectl import config, logger
from forensectl.core.chain_of_custody import ChainOfCustody
from forensectl.core.manifest import Manifest


class ArtifactExtractor:
    """Extractor de artefactos forenses específicos del sistema operativo."""
    
    def __init__(self, case_id: str, examiner: str = "") -> None:
        """Inicializar extractor de artefactos.
        
        Args:
            case_id: ID del caso
            examiner: Examinador responsable
        """
        self.case_id = case_id
        self.examiner = examiner
        
        # Directorios del caso
        self.case_dir = config.CASES_DIR / case_id
        self.artifacts_dir = self.case_dir / "analysis" / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        
        # Herramientas auxiliares
        self.chain_of_custody = ChainOfCustody(case_id)
        self.manifest = Manifest(case_id)
        
        # Definición de artefactos por sistema operativo
        self.artifact_definitions = {
            "windows": {
                "registry": {
                    "description": "Archivos de registro de Windows",
                    "priority": "critical",
                    "paths": [
                        "Windows/System32/config/SYSTEM",
                        "Windows/System32/config/SOFTWARE",
                        "Windows/System32/config/SECURITY",
                        "Windows/System32/config/SAM",
                        "Windows/System32/config/DEFAULT",
                        "Users/*/NTUSER.DAT",
                        "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat"
                    ],
                    "extensions": [".dat", ".log", ".log1", ".log2"]
                },
                "event_logs": {
                    "description": "Logs de eventos de Windows",
                    "priority": "high",
                    "paths": [
                        "Windows/System32/winevt/Logs/*.evtx",
                        "Windows/System32/config/*.evt"
                    ],
                    "extensions": [".evtx", ".evt"]
                },
                "prefetch": {
                    "description": "Archivos Prefetch de Windows",
                    "priority": "high",
                    "paths": [
                        "Windows/Prefetch/*.pf"
                    ],
                    "extensions": [".pf"]
                },
                "recent_files": {
                    "description": "Archivos recientes y accesos directos",
                    "priority": "medium",
                    "paths": [
                        "Users/*/AppData/Roaming/Microsoft/Windows/Recent/*",
                        "Users/*/AppData/Roaming/Microsoft/Office/Recent/*"
                    ],
                    "extensions": [".lnk", ".automaticDestinations-ms", ".customDestinations-ms"]
                },
                "browser_artifacts": {
                    "description": "Artefactos de navegadores web",
                    "priority": "medium",
                    "paths": [
                        "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
                        "Users/*/AppData/Local/Google/Chrome/User Data/Default/Cookies",
                        "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History",
                        "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
                        "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/cookies.sqlite"
                    ],
                    "extensions": [".sqlite", ".db"]
                },
                "usb_artifacts": {
                    "description": "Artefactos de dispositivos USB",
                    "priority": "medium",
                    "paths": [
                        "Windows/inf/setupapi.dev.log",
                        "Windows/System32/config/SYSTEM"
                    ],
                    "registry_keys": [
                        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"
                    ]
                },
                "network_artifacts": {
                    "description": "Artefactos de red y conectividad",
                    "priority": "medium",
                    "paths": [
                        "Windows/System32/drivers/etc/hosts",
                        "Windows/System32/config/SOFTWARE"
                    ],
                    "registry_keys": [
                        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList"
                    ]
                }
            },
            "linux": {
                "system_logs": {
                    "description": "Logs del sistema Linux",
                    "priority": "critical",
                    "paths": [
                        "var/log/syslog*",
                        "var/log/auth.log*",
                        "var/log/kern.log*",
                        "var/log/messages*",
                        "var/log/secure*"
                    ],
                    "extensions": [".log", ".gz"]
                },
                "user_artifacts": {
                    "description": "Artefactos de usuario Linux",
                    "priority": "high",
                    "paths": [
                        "home/*/.bash_history",
                        "home/*/.zsh_history",
                        "home/*/.ssh/known_hosts",
                        "home/*/.ssh/authorized_keys",
                        "root/.bash_history"
                    ],
                    "extensions": []
                },
                "network_config": {
                    "description": "Configuración de red Linux",
                    "priority": "medium",
                    "paths": [
                        "etc/hosts",
                        "etc/resolv.conf",
                        "etc/network/interfaces",
                        "etc/NetworkManager/system-connections/*"
                    ],
                    "extensions": [".conf"]
                },
                "cron_jobs": {
                    "description": "Tareas programadas (cron)",
                    "priority": "medium",
                    "paths": [
                        "etc/crontab",
                        "etc/cron.d/*",
                        "var/spool/cron/crontabs/*"
                    ],
                    "extensions": []
                }
            },
            "macos": {
                "system_logs": {
                    "description": "Logs del sistema macOS",
                    "priority": "critical",
                    "paths": [
                        "var/log/system.log*",
                        "var/log/install.log*",
                        "private/var/log/asl/*.asl"
                    ],
                    "extensions": [".log", ".asl"]
                },
                "user_artifacts": {
                    "description": "Artefactos de usuario macOS",
                    "priority": "high",
                    "paths": [
                        "Users/*/.bash_history",
                        "Users/*/.zsh_history",
                        "Users/*/Library/Preferences/*",
                        "Users/*/Library/Application Support/*/"
                    ],
                    "extensions": [".plist"]
                },
                "browser_artifacts": {
                    "description": "Artefactos de navegadores macOS",
                    "priority": "medium",
                    "paths": [
                        "Users/*/Library/Safari/History.db",
                        "Users/*/Library/Application Support/Google/Chrome/Default/History",
                        "Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite"
                    ],
                    "extensions": [".db", ".sqlite"]
                }
            }
        }
    
    def extract_artifacts(
        self,
        source_path: Union[str, Path],
        os_type: str,
        artifact_categories: Optional[List[str]] = None,
        custom_paths: Optional[List[str]] = None,
        preserve_timestamps: bool = True,
        create_hashes: bool = True
    ) -> Dict[str, Any]:
        """Extraer artefactos forenses del sistema.
        
        Args:
            source_path: Ruta de la fuente (imagen montada o directorio)
            os_type: Tipo de sistema operativo (windows, linux, macos)
            artifact_categories: Categorías específicas de artefactos
            custom_paths: Rutas personalizadas adicionales
            preserve_timestamps: Preservar timestamps originales
            create_hashes: Crear hashes de los artefactos
            
        Returns:
            Resultados de la extracción de artefactos
        """
        source_path = Path(source_path)
        if not source_path.exists():
            raise ValueError(f"Fuente no encontrada: {source_path}")
        
        if os_type not in self.artifact_definitions:
            raise ValueError(f"Tipo de OS no soportado: {os_type}")
        
        extraction_id = str(uuid.uuid4())
        extraction_start = datetime.now(timezone.utc)
        
        logger.info(f"Iniciando extracción de artefactos {extraction_id} para {os_type}: {source_path}")
        
        # Crear directorio de extracción
        extraction_output_dir = self.artifacts_dir / extraction_id
        extraction_output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Obtener definiciones de artefactos
            os_artifacts = self.artifact_definitions[os_type]
            
            # Filtrar categorías si se especifican
            if artifact_categories:
                os_artifacts = {
                    k: v for k, v in os_artifacts.items() 
                    if k in artifact_categories
                }
            
            extracted_artifacts = []
            extraction_stats = {
                "total_categories": len(os_artifacts),
                "successful_extractions": 0,
                "failed_extractions": 0,
                "total_files_extracted": 0,
                "total_size_bytes": 0
            }
            
            # Extraer artefactos por categoría
            for category, definition in os_artifacts.items():
                logger.info(f"Extrayendo categoría: {category}")
                
                category_result = self._extract_artifact_category(
                    source_path, category, definition, extraction_output_dir,
                    preserve_timestamps, create_hashes
                )
                
                extracted_artifacts.append(category_result)
                
                if category_result["status"] == "success":
                    extraction_stats["successful_extractions"] += 1
                    extraction_stats["total_files_extracted"] += category_result["files_extracted"]
                    extraction_stats["total_size_bytes"] += category_result["total_size"]
                else:
                    extraction_stats["failed_extractions"] += 1
            
            # Extraer rutas personalizadas si se especifican
            if custom_paths:
                custom_result = self._extract_custom_paths(
                    source_path, custom_paths, extraction_output_dir,
                    preserve_timestamps, create_hashes
                )
                extracted_artifacts.append(custom_result)
            
            extraction_end = datetime.now(timezone.utc)
            
            # Crear resumen de la extracción
            extraction_summary = {
                "extraction_id": extraction_id,
                "case_id": self.case_id,
                "source_path": str(source_path),
                "os_type": os_type,
                "extracted_artifacts": extracted_artifacts,
                "statistics": extraction_stats,
                "output_directory": str(extraction_output_dir),
                "started_at": extraction_start.isoformat(),
                "completed_at": extraction_end.isoformat(),
                "duration_seconds": (extraction_end - extraction_start).total_seconds(),
                "examiner": self.examiner,
                "extraction_parameters": {
                    "artifact_categories": artifact_categories or list(os_artifacts.keys()),
                    "custom_paths": custom_paths or [],
                    "preserve_timestamps": preserve_timestamps,
                    "create_hashes": create_hashes
                }
            }
            
            # Guardar resumen
            summary_file = extraction_output_dir / "extraction_summary.json"
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(extraction_summary, f, indent=2, ensure_ascii=False)
            
            # Generar índice de artefactos
            self._generate_artifact_index(extraction_summary, extraction_output_dir)
            
            # Registrar en manifiesto
            self.manifest.register_analysis(
                analysis_id=extraction_id,
                analysis_type="artifact_extraction",
                evidence_id="",  # Se puede vincular después
                tool_name="ArtifactExtractor",
                tool_version="1.0.0",
                output_path=str(extraction_output_dir),
                examiner=self.examiner,
                description=f"Extracción de artefactos {os_type} con {extraction_stats['total_files_extracted']} archivos",
                parameters={
                    "source_path": str(source_path),
                    "os_type": os_type,
                    "categories": artifact_categories,
                    "preserve_timestamps": preserve_timestamps
                },
                results_summary={
                    "categories_processed": extraction_stats["total_categories"],
                    "files_extracted": extraction_stats["total_files_extracted"],
                    "total_size_mb": extraction_stats["total_size_bytes"] // (1024 * 1024)
                }
            )
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="artifact_extraction_completed",
                description=f"Extracción de artefactos {os_type} completada con {extraction_stats['total_files_extracted']} archivos",
                examiner=self.examiner,
                evidence_path=str(source_path),
                metadata={
                    "extraction_id": extraction_id,
                    "os_type": os_type,
                    "files_extracted": extraction_stats["total_files_extracted"],
                    "duration_seconds": extraction_summary["duration_seconds"]
                }
            )
            
            logger.info(f"Extracción de artefactos {extraction_id} completada: {extraction_stats['total_files_extracted']} archivos")
            return extraction_summary
            
        except Exception as e:
            logger.error(f"Error durante extracción de artefactos {extraction_id}: {e}")
            
            # Agregar error a cadena de custodia
            self.chain_of_custody.add_entry(
                action="artifact_extraction_failed",
                description=f"Fallo en extracción de artefactos: {str(e)}",
                examiner=self.examiner,
                evidence_path=str(source_path),
                metadata={"extraction_id": extraction_id, "error": str(e)}
            )
            
            raise
    
    def extract_registry_artifacts(
        self,
        source_path: Union[str, Path],
        registry_hives: Optional[List[str]] = None,
        export_format: str = "json"
    ) -> Dict[str, Any]:
        """Extraer artefactos específicos del registro de Windows.
        
        Args:
            source_path: Ruta de la fuente
            registry_hives: Hives específicos del registro
            export_format: Formato de exportación (json, csv, reg)
            
        Returns:
            Resultados de la extracción del registro
        """
        source_path = Path(source_path)
        
        # Hives por defecto
        if not registry_hives:
            registry_hives = ["SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"]
        
        extraction_id = str(uuid.uuid4())
        logger.info(f"Extrayendo artefactos del registro {extraction_id}")
        
        # Crear directorio de extracción
        registry_output_dir = self.artifacts_dir / f"registry_{extraction_id}"
        registry_output_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_hives = []
        
        for hive_name in registry_hives:
            try:
                hive_result = self._extract_registry_hive(
                    source_path, hive_name, registry_output_dir, export_format
                )
                extracted_hives.append(hive_result)
                
            except Exception as e:
                logger.warning(f"Error extrayendo hive {hive_name}: {e}")
                extracted_hives.append({
                    "hive_name": hive_name,
                    "status": "error",
                    "error": str(e)
                })
        
        registry_summary = {
            "extraction_id": extraction_id,
            "case_id": self.case_id,
            "source_path": str(source_path),
            "extraction_type": "registry_artifacts",
            "extracted_hives": extracted_hives,
            "output_directory": str(registry_output_dir),
            "export_format": export_format,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "examiner": self.examiner
        }
        
        # Guardar resumen
        summary_file = registry_output_dir / "registry_extraction_summary.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(registry_summary, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Extracción de registro {extraction_id} completada")
        return registry_summary
    
    def extract_browser_artifacts(
        self,
        source_path: Union[str, Path],
        browsers: Optional[List[str]] = None,
        artifact_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Extraer artefactos específicos de navegadores.
        
        Args:
            source_path: Ruta de la fuente
            browsers: Navegadores específicos (chrome, firefox, edge, safari)
            artifact_types: Tipos de artefactos (history, cookies, downloads, bookmarks)
            
        Returns:
            Resultados de la extracción de navegadores
        """
        source_path = Path(source_path)
        
        # Navegadores por defecto
        if not browsers:
            browsers = ["chrome", "firefox", "edge", "safari"]
        
        # Tipos de artefactos por defecto
        if not artifact_types:
            artifact_types = ["history", "cookies", "downloads", "bookmarks"]
        
        extraction_id = str(uuid.uuid4())
        logger.info(f"Extrayendo artefactos de navegadores {extraction_id}")
        
        # Crear directorio de extracción
        browser_output_dir = self.artifacts_dir / f"browsers_{extraction_id}"
        browser_output_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_browsers = []
        
        for browser in browsers:
            try:
                browser_result = self._extract_browser_data(
                    source_path, browser, artifact_types, browser_output_dir
                )
                extracted_browsers.append(browser_result)
                
            except Exception as e:
                logger.warning(f"Error extrayendo datos de {browser}: {e}")
                extracted_browsers.append({
                    "browser": browser,
                    "status": "error",
                    "error": str(e)
                })
        
        browser_summary = {
            "extraction_id": extraction_id,
            "case_id": self.case_id,
            "source_path": str(source_path),
            "extraction_type": "browser_artifacts",
            "extracted_browsers": extracted_browsers,
            "output_directory": str(browser_output_dir),
            "browsers_requested": browsers,
            "artifact_types_requested": artifact_types,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "examiner": self.examiner
        }
        
        # Guardar resumen
        summary_file = browser_output_dir / "browser_extraction_summary.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(browser_summary, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Extracción de navegadores {extraction_id} completada")
        return browser_summary
    
    def _extract_artifact_category(
        self,
        source_path: Path,
        category: str,
        definition: Dict[str, Any],
        output_dir: Path,
        preserve_timestamps: bool,
        create_hashes: bool
    ) -> Dict[str, Any]:
        """Extraer categoría específica de artefactos.
        
        Args:
            source_path: Ruta de la fuente
            category: Nombre de la categoría
            definition: Definición de la categoría
            output_dir: Directorio de salida
            preserve_timestamps: Preservar timestamps
            create_hashes: Crear hashes
            
        Returns:
            Resultado de la extracción de la categoría
        """
        category_dir = output_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_files = []
        total_size = 0
        
        try:
            # Procesar rutas definidas
            for path_pattern in definition.get("paths", []):
                matching_files = self._find_matching_files(source_path, path_pattern)
                
                for file_path in matching_files:
                    try:
                        # Copiar archivo
                        relative_path = file_path.relative_to(source_path)
                        dest_path = category_dir / relative_path
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        shutil.copy2(file_path, dest_path)
                        
                        # Preservar timestamps si se solicita
                        if preserve_timestamps:
                            shutil.copystat(file_path, dest_path)
                        
                        file_size = dest_path.stat().st_size
                        total_size += file_size
                        
                        file_info = {
                            "original_path": str(file_path),
                            "extracted_path": str(dest_path),
                            "relative_path": str(relative_path),
                            "size_bytes": file_size,
                            "extracted_at": datetime.now(timezone.utc).isoformat()
                        }
                        
                        # Crear hash si se solicita
                        if create_hashes:
                            file_info["sha256"] = self._calculate_file_hash(dest_path)
                        
                        extracted_files.append(file_info)
                        
                    except Exception as e:
                        logger.warning(f"Error extrayendo {file_path}: {e}")
            
            return {
                "category": category,
                "status": "success",
                "description": definition.get("description", ""),
                "priority": definition.get("priority", "medium"),
                "files_extracted": len(extracted_files),
                "total_size": total_size,
                "output_directory": str(category_dir),
                "extracted_files": extracted_files
            }
            
        except Exception as e:
            logger.error(f"Error extrayendo categoría {category}: {e}")
            return {
                "category": category,
                "status": "error",
                "error": str(e),
                "files_extracted": len(extracted_files),
                "total_size": total_size
            }
    
    def _extract_custom_paths(
        self,
        source_path: Path,
        custom_paths: List[str],
        output_dir: Path,
        preserve_timestamps: bool,
        create_hashes: bool
    ) -> Dict[str, Any]:
        """Extraer rutas personalizadas.
        
        Args:
            source_path: Ruta de la fuente
            custom_paths: Lista de rutas personalizadas
            output_dir: Directorio de salida
            preserve_timestamps: Preservar timestamps
            create_hashes: Crear hashes
            
        Returns:
            Resultado de la extracción personalizada
        """
        custom_dir = output_dir / "custom"
        custom_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_files = []
        total_size = 0
        
        for path_pattern in custom_paths:
            try:
                matching_files = self._find_matching_files(source_path, path_pattern)
                
                for file_path in matching_files:
                    try:
                        relative_path = file_path.relative_to(source_path)
                        dest_path = custom_dir / relative_path
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        shutil.copy2(file_path, dest_path)
                        
                        if preserve_timestamps:
                            shutil.copystat(file_path, dest_path)
                        
                        file_size = dest_path.stat().st_size
                        total_size += file_size
                        
                        file_info = {
                            "original_path": str(file_path),
                            "extracted_path": str(dest_path),
                            "relative_path": str(relative_path),
                            "size_bytes": file_size,
                            "pattern_matched": path_pattern,
                            "extracted_at": datetime.now(timezone.utc).isoformat()
                        }
                        
                        if create_hashes:
                            file_info["sha256"] = self._calculate_file_hash(dest_path)
                        
                        extracted_files.append(file_info)
                        
                    except Exception as e:
                        logger.warning(f"Error extrayendo {file_path}: {e}")
                        
            except Exception as e:
                logger.warning(f"Error procesando patrón {path_pattern}: {e}")
        
        return {
            "category": "custom",
            "status": "success",
            "description": "Rutas personalizadas especificadas por el usuario",
            "priority": "user_defined",
            "files_extracted": len(extracted_files),
            "total_size": total_size,
            "output_directory": str(custom_dir),
            "extracted_files": extracted_files,
            "custom_patterns": custom_paths
        }
    
    def _extract_registry_hive(
        self,
        source_path: Path,
        hive_name: str,
        output_dir: Path,
        export_format: str
    ) -> Dict[str, Any]:
        """Extraer hive específico del registro.
        
        Args:
            source_path: Ruta de la fuente
            hive_name: Nombre del hive
            output_dir: Directorio de salida
            export_format: Formato de exportación
            
        Returns:
            Resultado de la extracción del hive
        """
        # Buscar archivo del hive
        hive_patterns = [
            f"Windows/System32/config/{hive_name}",
            f"Windows/System32/config/{hive_name.upper()}",
            f"Windows/System32/config/{hive_name.lower()}"
        ]
        
        hive_file = None
        for pattern in hive_patterns:
            potential_path = source_path / pattern
            if potential_path.exists():
                hive_file = potential_path
                break
        
        if not hive_file:
            return {
                "hive_name": hive_name,
                "status": "not_found",
                "error": f"Hive {hive_name} no encontrado"
            }
        
        # Copiar hive
        dest_hive = output_dir / f"{hive_name}.hive"
        shutil.copy2(hive_file, dest_hive)
        
        # TODO: Implementar parseo del registro según el formato
        # Por ahora, solo copiar el archivo
        
        return {
            "hive_name": hive_name,
            "status": "success",
            "original_path": str(hive_file),
            "extracted_path": str(dest_hive),
            "size_bytes": dest_hive.stat().st_size,
            "export_format": export_format
        }
    
    def _extract_browser_data(
        self,
        source_path: Path,
        browser: str,
        artifact_types: List[str],
        output_dir: Path
    ) -> Dict[str, Any]:
        """Extraer datos específicos de un navegador.
        
        Args:
            source_path: Ruta de la fuente
            browser: Nombre del navegador
            artifact_types: Tipos de artefactos
            output_dir: Directorio de salida
            
        Returns:
            Resultado de la extracción del navegador
        """
        browser_dir = output_dir / browser
        browser_dir.mkdir(parents=True, exist_ok=True)
        
        # Definir rutas por navegador
        browser_paths = {
            "chrome": {
                "history": "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
                "cookies": "Users/*/AppData/Local/Google/Chrome/User Data/Default/Cookies",
                "downloads": "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
                "bookmarks": "Users/*/AppData/Local/Google/Chrome/User Data/Default/Bookmarks"
            },
            "firefox": {
                "history": "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
                "cookies": "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/cookies.sqlite",
                "downloads": "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
                "bookmarks": "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite"
            },
            "edge": {
                "history": "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History",
                "cookies": "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/Cookies",
                "downloads": "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History",
                "bookmarks": "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/Bookmarks"
            }
        }
        
        if browser not in browser_paths:
            return {
                "browser": browser,
                "status": "not_supported",
                "error": f"Navegador {browser} no soportado"
            }
        
        extracted_artifacts = []
        
        for artifact_type in artifact_types:
            if artifact_type in browser_paths[browser]:
                path_pattern = browser_paths[browser][artifact_type]
                matching_files = self._find_matching_files(source_path, path_pattern)
                
                for file_path in matching_files:
                    try:
                        dest_path = browser_dir / f"{artifact_type}_{file_path.name}"
                        shutil.copy2(file_path, dest_path)
                        
                        extracted_artifacts.append({
                            "artifact_type": artifact_type,
                            "original_path": str(file_path),
                            "extracted_path": str(dest_path),
                            "size_bytes": dest_path.stat().st_size
                        })
                        
                    except Exception as e:
                        logger.warning(f"Error extrayendo {artifact_type} de {browser}: {e}")
        
        return {
            "browser": browser,
            "status": "success",
            "extracted_artifacts": extracted_artifacts,
            "artifacts_count": len(extracted_artifacts),
            "output_directory": str(browser_dir)
        }
    
    def _find_matching_files(
        self,
        source_path: Path,
        pattern: str
    ) -> List[Path]:
        """Encontrar archivos que coincidan con un patrón.
        
        Args:
            source_path: Ruta base de búsqueda
            pattern: Patrón de búsqueda
            
        Returns:
            Lista de archivos coincidentes
        """
        try:
            # Convertir patrón a ruta relativa
            pattern_path = source_path / pattern
            
            # Usar glob para encontrar coincidencias
            if "*" in pattern:
                matching_files = list(source_path.glob(pattern))
            else:
                # Ruta específica
                if pattern_path.exists():
                    matching_files = [pattern_path]
                else:
                    matching_files = []
            
            # Filtrar solo archivos (no directorios)
            return [f for f in matching_files if f.is_file()]
            
        except Exception as e:
            logger.warning(f"Error buscando patrón {pattern}: {e}")
            return []
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calcular hash SHA256 de un archivo.
        
        Args:
            file_path: Ruta del archivo
            
        Returns:
            Hash SHA256 del archivo
        """
        import hashlib
        
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.warning(f"Error calculando hash de {file_path}: {e}")
            return "error_calculating_hash"
    
    def _generate_artifact_index(
        self,
        extraction_summary: Dict[str, Any],
        output_dir: Path
    ) -> None:
        """Generar índice de artefactos extraídos.
        
        Args:
            extraction_summary: Resumen de la extracción
            output_dir: Directorio de salida
        """
        index_file = output_dir / "artifact_index.txt"
        
        with open(index_file, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ÍNDICE DE ARTEFACTOS EXTRAÍDOS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"ID de Extracción: {extraction_summary['extraction_id']}\n")
            f.write(f"Caso: {extraction_summary['case_id']}\n")
            f.write(f"Fuente: {extraction_summary['source_path']}\n")
            f.write(f"Sistema Operativo: {extraction_summary['os_type']}\n")
            f.write(f"Fecha: {extraction_summary['started_at']}\n")
            f.write(f"Examinador: {extraction_summary['examiner']}\n\n")
            
            stats = extraction_summary['statistics']
            f.write("ESTADÍSTICAS:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Categorías procesadas: {stats['total_categories']}\n")
            f.write(f"Extracciones exitosas: {stats['successful_extractions']}\n")
            f.write(f"Extracciones fallidas: {stats['failed_extractions']}\n")
            f.write(f"Total de archivos: {stats['total_files_extracted']}\n")
            f.write(f"Tamaño total: {stats['total_size_bytes'] // (1024*1024)} MB\n\n")
            
            f.write("ARTEFACTOS POR CATEGORÍA:\n")
            f.write("-" * 40 + "\n")
            
            for artifact in extraction_summary['extracted_artifacts']:
                if artifact['status'] == 'success':
                    f.write(f"\n[{artifact['category'].upper()}]\n")
                    f.write(f"Descripción: {artifact.get('description', 'N/A')}\n")
                    f.write(f"Prioridad: {artifact.get('priority', 'N/A')}\n")
                    f.write(f"Archivos extraídos: {artifact['files_extracted']}\n")
                    f.write(f"Tamaño: {artifact['total_size'] // 1024} KB\n")
                    f.write(f"Directorio: {artifact['output_directory']}\n")
                else:
                    f.write(f"\n[{artifact['category'].upper()}] - ERROR\n")
                    f.write(f"Error: {artifact.get('error', 'Desconocido')}\n")
        
        logger.info(f"Índice de artefactos generado: {index_file}")