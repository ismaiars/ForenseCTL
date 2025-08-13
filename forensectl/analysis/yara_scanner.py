"""Escáner YARA para detección de malware y artefactos sospechosos."""

import json
import subprocess
import uuid
import yara
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from forensectl import config, logger
from forensectl.core.chain_of_custody import ChainOfCustody
from forensectl.core.manifest import Manifest


class YaraScanner:
    """Escáner YARA para detección de malware y artefactos sospechosos."""
    
    def __init__(self, case_id: str, examiner: str = "") -> None:
        """Inicializar escáner YARA.
        
        Args:
            case_id: ID del caso
            examiner: Examinador responsable
        """
        self.case_id = case_id
        self.examiner = examiner
        
        # Directorios del caso
        self.case_dir = config.CASES_DIR / case_id
        self.yara_dir = self.case_dir / "analysis" / "yara"
        self.yara_dir.mkdir(parents=True, exist_ok=True)
        
        # Directorio de reglas YARA
        self.rules_dir = config.BASE_DIR / "rules" / "yara"
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Herramientas auxiliares
        self.chain_of_custody = ChainOfCustody(case_id)
        self.manifest = Manifest(case_id)
        
        # Categorías de reglas predefinidas
        self.rule_categories = {
            "malware": {
                "description": "Reglas de detección de malware general",
                "priority": "high",
                "rules": []
            },
            "apt": {
                "description": "Reglas de detección de APT (Advanced Persistent Threats)",
                "priority": "critical",
                "rules": []
            },
            "ransomware": {
                "description": "Reglas de detección de ransomware",
                "priority": "critical",
                "rules": []
            },
            "trojan": {
                "description": "Reglas de detección de troyanos",
                "priority": "high",
                "rules": []
            },
            "rootkit": {
                "description": "Reglas de detección de rootkits",
                "priority": "high",
                "rules": []
            },
            "webshell": {
                "description": "Reglas de detección de webshells",
                "priority": "medium",
                "rules": []
            },
            "packer": {
                "description": "Reglas de detección de packers y ofuscadores",
                "priority": "medium",
                "rules": []
            },
            "exploit": {
                "description": "Reglas de detección de exploits",
                "priority": "high",
                "rules": []
            },
            "suspicious": {
                "description": "Reglas de detección de comportamiento sospechoso",
                "priority": "low",
                "rules": []
            }
        }
        
        # Extensiones de archivo a escanear por defecto
        self.default_extensions = [
            ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".jar", ".war", ".ear", ".zip", ".rar", ".7z",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
            ".php", ".asp", ".aspx", ".jsp", ".py", ".pl", ".rb"
        ]
        
        # Inicializar reglas por defecto
        self._initialize_default_rules()
    
    def scan_target(
        self,
        target_path: Union[str, Path],
        rule_categories: Optional[List[str]] = None,
        custom_rules: Optional[List[Union[str, Path]]] = None,
        scan_archives: bool = True,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        timeout_per_file: int = 30,
        extensions_filter: Optional[List[str]] = None,
        recursive: bool = True
    ) -> Dict[str, Any]:
        """Escanear objetivo con reglas YARA.
        
        Args:
            target_path: Ruta del objetivo (archivo o directorio)
            rule_categories: Categorías de reglas a usar
            custom_rules: Reglas personalizadas adicionales
            scan_archives: Escanear dentro de archivos comprimidos
            max_file_size: Tamaño máximo de archivo a escanear
            timeout_per_file: Timeout por archivo en segundos
            extensions_filter: Filtro de extensiones específicas
            recursive: Escaneo recursivo en directorios
            
        Returns:
            Resultados del escaneo YARA
        """
        target_path = Path(target_path)
        if not target_path.exists():
            raise ValueError(f"Objetivo no encontrado: {target_path}")
        
        scan_id = str(uuid.uuid4())
        scan_start = datetime.now(timezone.utc)
        
        logger.info(f"Iniciando escaneo YARA {scan_id} para: {target_path}")
        
        # Crear directorio de escaneo
        scan_output_dir = self.yara_dir / scan_id
        scan_output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Compilar reglas
            compiled_rules = self._compile_rules(rule_categories, custom_rules)
            
            if not compiled_rules:
                raise ValueError("No se pudieron compilar las reglas YARA")
            
            # Obtener lista de archivos a escanear
            files_to_scan = self._get_files_to_scan(
                target_path, extensions_filter, max_file_size, recursive
            )
            
            logger.info(f"Escaneando {len(files_to_scan)} archivos")
            
            # Realizar escaneo
            scan_results = []
            scanned_files = 0
            matched_files = 0
            
            for file_path in files_to_scan:
                try:
                    file_results = self._scan_file(
                        file_path, compiled_rules, timeout_per_file
                    )
                    
                    if file_results["matches"]:
                        scan_results.append(file_results)
                        matched_files += 1
                    
                    scanned_files += 1
                    
                    # Log progreso cada 100 archivos
                    if scanned_files % 100 == 0:
                        logger.info(f"Progreso: {scanned_files}/{len(files_to_scan)} archivos escaneados")
                        
                except Exception as e:
                    logger.warning(f"Error escaneando {file_path}: {e}")
                    scan_results.append({
                        "file_path": str(file_path),
                        "error": str(e),
                        "matches": []
                    })
            
            scan_end = datetime.now(timezone.utc)
            
            # Crear resumen del escaneo
            scan_summary = {
                "scan_id": scan_id,
                "case_id": self.case_id,
                "target_path": str(target_path),
                "scan_type": "yara_malware_detection",
                "results": scan_results,
                "statistics": {
                    "total_files_found": len(files_to_scan),
                    "files_scanned": scanned_files,
                    "files_with_matches": matched_files,
                    "total_matches": sum(len(r["matches"]) for r in scan_results if "matches" in r),
                    "scan_coverage": (scanned_files / len(files_to_scan)) * 100 if files_to_scan else 0
                },
                "output_directory": str(scan_output_dir),
                "started_at": scan_start.isoformat(),
                "completed_at": scan_end.isoformat(),
                "duration_seconds": (scan_end - scan_start).total_seconds(),
                "examiner": self.examiner,
                "tool_info": {
                    "name": "YARA",
                    "version": self._get_yara_version(),
                    "python_yara_version": yara.__version__ if hasattr(yara, '__version__') else "unknown"
                },
                "scan_parameters": {
                    "rule_categories": rule_categories or [],
                    "custom_rules": [str(r) for r in (custom_rules or [])],
                    "scan_archives": scan_archives,
                    "max_file_size": max_file_size,
                    "timeout_per_file": timeout_per_file,
                    "extensions_filter": extensions_filter,
                    "recursive": recursive
                }
            }
            
            # Guardar resultados
            results_file = scan_output_dir / "yara_scan_results.json"
            with open(results_file, "w", encoding="utf-8") as f:
                json.dump(scan_summary, f, indent=2, ensure_ascii=False)
            
            # Generar reporte de detecciones
            if matched_files > 0:
                self._generate_detection_report(scan_summary, scan_output_dir)
            
            # Registrar en manifiesto
            self.manifest.register_analysis(
                analysis_id=scan_id,
                analysis_type="yara_scan",
                evidence_id="",  # Se puede vincular después
                tool_name="YARA",
                tool_version=self._get_yara_version(),
                output_path=str(scan_output_dir),
                examiner=self.examiner,
                description=f"Escaneo YARA de {target_path.name} con {matched_files} detecciones",
                parameters={
                    "target_path": str(target_path),
                    "rule_categories": rule_categories,
                    "files_scanned": scanned_files,
                    "max_file_size": max_file_size
                },
                results_summary={
                    "files_with_matches": matched_files,
                    "total_matches": scan_summary["statistics"]["total_matches"],
                    "threat_level": self._assess_threat_level(scan_results)
                }
            )
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="yara_scan_completed",
                description=f"Escaneo YARA completado con {matched_files} detecciones en {scanned_files} archivos",
                examiner=self.examiner,
                evidence_path=str(target_path),
                metadata={
                    "scan_id": scan_id,
                    "files_scanned": scanned_files,
                    "detections": matched_files,
                    "duration_seconds": scan_summary["duration_seconds"]
                }
            )
            
            logger.info(f"Escaneo YARA {scan_id} completado: {matched_files} detecciones en {scanned_files} archivos")
            return scan_summary
            
        except Exception as e:
            logger.error(f"Error durante escaneo YARA {scan_id}: {e}")
            
            # Agregar error a cadena de custodia
            self.chain_of_custody.add_entry(
                action="yara_scan_failed",
                description=f"Fallo en escaneo YARA: {str(e)}",
                examiner=self.examiner,
                evidence_path=str(target_path),
                metadata={"scan_id": scan_id, "error": str(e)}
            )
            
            raise
    
    def scan_memory_dump(
        self,
        memory_dump_path: Union[str, Path],
        rule_categories: Optional[List[str]] = None,
        custom_rules: Optional[List[Union[str, Path]]] = None,
        chunk_size: int = 1024 * 1024  # 1MB chunks
    ) -> Dict[str, Any]:
        """Escanear dump de memoria con reglas YARA.
        
        Args:
            memory_dump_path: Ruta del dump de memoria
            rule_categories: Categorías de reglas a usar
            custom_rules: Reglas personalizadas adicionales
            chunk_size: Tamaño de chunk para lectura de memoria
            
        Returns:
            Resultados del escaneo de memoria
        """
        memory_dump_path = Path(memory_dump_path)
        if not memory_dump_path.exists():
            raise ValueError(f"Dump de memoria no encontrado: {memory_dump_path}")
        
        scan_id = str(uuid.uuid4())
        scan_start = datetime.now(timezone.utc)
        
        logger.info(f"Iniciando escaneo YARA de memoria {scan_id} para: {memory_dump_path}")
        
        # Crear directorio de escaneo
        scan_output_dir = self.yara_dir / f"memory_{scan_id}"
        scan_output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Compilar reglas
            compiled_rules = self._compile_rules(rule_categories, custom_rules)
            
            if not compiled_rules:
                raise ValueError("No se pudieron compilar las reglas YARA")
            
            # Escanear dump de memoria
            matches = []
            
            with open(memory_dump_path, "rb") as f:
                offset = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    try:
                        chunk_matches = compiled_rules.match(data=chunk)
                        
                        for match in chunk_matches:
                            match_info = {
                                "rule_name": match.rule,
                                "namespace": match.namespace,
                                "tags": list(match.tags),
                                "meta": dict(match.meta),
                                "strings": [],
                                "offset_in_dump": offset
                            }
                            
                            # Agregar información de strings coincidentes
                            for string in match.strings:
                                match_info["strings"].append({
                                    "identifier": string.identifier,
                                    "instances": [
                                        {
                                            "offset": instance.offset + offset,
                                            "matched_data": instance.matched_data.hex() if len(instance.matched_data) <= 100 else instance.matched_data[:100].hex() + "...",
                                            "matched_length": instance.matched_length
                                        }
                                        for instance in string.instances
                                    ]
                                })
                            
                            matches.append(match_info)
                    
                    except Exception as e:
                        logger.warning(f"Error escaneando chunk en offset {offset}: {e}")
                    
                    offset += len(chunk)
                    
                    # Log progreso cada 100MB
                    if offset % (100 * 1024 * 1024) == 0:
                        logger.info(f"Progreso escaneo memoria: {offset // (1024 * 1024)} MB procesados")
            
            scan_end = datetime.now(timezone.utc)
            
            # Crear resumen del escaneo de memoria
            memory_scan_summary = {
                "scan_id": scan_id,
                "case_id": self.case_id,
                "memory_dump_path": str(memory_dump_path),
                "scan_type": "yara_memory_scan",
                "matches": matches,
                "statistics": {
                    "dump_size_bytes": memory_dump_path.stat().st_size,
                    "total_matches": len(matches),
                    "unique_rules_matched": len(set(m["rule_name"] for m in matches)),
                    "chunks_processed": offset // chunk_size + (1 if offset % chunk_size else 0)
                },
                "output_directory": str(scan_output_dir),
                "started_at": scan_start.isoformat(),
                "completed_at": scan_end.isoformat(),
                "duration_seconds": (scan_end - scan_start).total_seconds(),
                "examiner": self.examiner,
                "tool_info": {
                    "name": "YARA",
                    "version": self._get_yara_version(),
                    "python_yara_version": yara.__version__ if hasattr(yara, '__version__') else "unknown"
                },
                "scan_parameters": {
                    "rule_categories": rule_categories or [],
                    "custom_rules": [str(r) for r in (custom_rules or [])],
                    "chunk_size": chunk_size
                }
            }
            
            # Guardar resultados
            results_file = scan_output_dir / "memory_scan_results.json"
            with open(results_file, "w", encoding="utf-8") as f:
                json.dump(memory_scan_summary, f, indent=2, ensure_ascii=False)
            
            # Generar reporte de detecciones en memoria
            if matches:
                self._generate_memory_detection_report(memory_scan_summary, scan_output_dir)
            
            # Registrar en manifiesto
            self.manifest.register_analysis(
                analysis_id=scan_id,
                analysis_type="yara_memory_scan",
                evidence_id="",
                tool_name="YARA",
                tool_version=self._get_yara_version(),
                output_path=str(scan_output_dir),
                examiner=self.examiner,
                description=f"Escaneo YARA de memoria con {len(matches)} detecciones",
                parameters={
                    "memory_dump_path": str(memory_dump_path),
                    "rule_categories": rule_categories,
                    "chunk_size": chunk_size
                },
                results_summary={
                    "total_matches": len(matches),
                    "unique_rules": len(set(m["rule_name"] for m in matches)),
                    "threat_level": self._assess_threat_level_memory(matches)
                }
            )
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="yara_memory_scan_completed",
                description=f"Escaneo YARA de memoria completado con {len(matches)} detecciones",
                examiner=self.examiner,
                evidence_path=str(memory_dump_path),
                metadata={
                    "scan_id": scan_id,
                    "matches": len(matches),
                    "dump_size_mb": memory_dump_path.stat().st_size // (1024 * 1024),
                    "duration_seconds": memory_scan_summary["duration_seconds"]
                }
            )
            
            logger.info(f"Escaneo YARA de memoria {scan_id} completado: {len(matches)} detecciones")
            return memory_scan_summary
            
        except Exception as e:
            logger.error(f"Error durante escaneo YARA de memoria {scan_id}: {e}")
            
            # Agregar error a cadena de custodia
            self.chain_of_custody.add_entry(
                action="yara_memory_scan_failed",
                description=f"Fallo en escaneo YARA de memoria: {str(e)}",
                examiner=self.examiner,
                evidence_path=str(memory_dump_path),
                metadata={"scan_id": scan_id, "error": str(e)}
            )
            
            raise
    
    def add_custom_rule(
        self,
        rule_content: str,
        rule_name: str,
        category: str = "custom",
        description: str = "",
        priority: str = "medium"
    ) -> Dict[str, Any]:
        """Agregar regla YARA personalizada.
        
        Args:
            rule_content: Contenido de la regla YARA
            rule_name: Nombre de la regla
            category: Categoría de la regla
            description: Descripción de la regla
            priority: Prioridad de la regla
            
        Returns:
            Información de la regla agregada
        """
        # Validar regla YARA
        try:
            yara.compile(source=rule_content)
        except Exception as e:
            raise ValueError(f"Regla YARA inválida: {e}")
        
        # Crear directorio de categoría si no existe
        category_dir = self.rules_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)
        
        # Guardar regla
        rule_file = category_dir / f"{rule_name}.yar"
        with open(rule_file, "w", encoding="utf-8") as f:
            f.write(rule_content)
        
        # Actualizar categoría
        if category not in self.rule_categories:
            self.rule_categories[category] = {
                "description": description or f"Reglas personalizadas de {category}",
                "priority": priority,
                "rules": []
            }
        
        self.rule_categories[category]["rules"].append(str(rule_file))
        
        # Agregar a cadena de custodia
        self.chain_of_custody.add_entry(
            action="yara_rule_added",
            description=f"Regla YARA personalizada agregada: {rule_name}",
            examiner=self.examiner,
            evidence_path="",
            metadata={
                "rule_name": rule_name,
                "category": category,
                "rule_file": str(rule_file),
                "priority": priority
            }
        )
        
        logger.info(f"Regla YARA {rule_name} agregada en categoría {category}")
        
        return {
            "rule_name": rule_name,
            "category": category,
            "rule_file": str(rule_file),
            "priority": priority,
            "description": description
        }
    
    def update_rules_from_repository(
        self,
        repository_url: str = "https://github.com/Yara-Rules/rules.git",
        categories_to_update: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Actualizar reglas desde repositorio externo.
        
        Args:
            repository_url: URL del repositorio de reglas
            categories_to_update: Categorías específicas a actualizar
            
        Returns:
            Información de la actualización
        """
        # TODO: Implementar descarga y actualización de reglas
        # Por ahora, retornar placeholder
        
        logger.info(f"Actualización de reglas desde {repository_url} (no implementado)")
        
        return {
            "status": "not_implemented",
            "repository_url": repository_url,
            "categories_requested": categories_to_update or [],
            "note": "Rule repository update pending implementation"
        }
    
    def _compile_rules(
        self,
        rule_categories: Optional[List[str]],
        custom_rules: Optional[List[Union[str, Path]]]
    ) -> Optional[yara.Rules]:
        """Compilar reglas YARA.
        
        Args:
            rule_categories: Categorías de reglas a compilar
            custom_rules: Reglas personalizadas adicionales
            
        Returns:
            Reglas YARA compiladas
        """
        rule_sources = {}
        
        # Agregar reglas de categorías
        if rule_categories:
            for category in rule_categories:
                if category in self.rule_categories:
                    for rule_file in self.rule_categories[category]["rules"]:
                        rule_path = Path(rule_file)
                        if rule_path.exists():
                            rule_sources[f"{category}_{rule_path.stem}"] = str(rule_path)
        
        # Agregar reglas personalizadas
        if custom_rules:
            for i, rule in enumerate(custom_rules):
                rule_path = Path(rule)
                if rule_path.exists():
                    rule_sources[f"custom_{i}_{rule_path.stem}"] = str(rule_path)
                else:
                    # Asumir que es contenido de regla directamente
                    rule_sources[f"custom_{i}"] = str(rule)
        
        # Si no hay reglas específicas, usar reglas por defecto
        if not rule_sources:
            for category, info in self.rule_categories.items():
                if info["priority"] in ["high", "critical"]:
                    for rule_file in info["rules"]:
                        rule_path = Path(rule_file)
                        if rule_path.exists():
                            rule_sources[f"{category}_{rule_path.stem}"] = str(rule_path)
        
        if not rule_sources:
            logger.warning("No se encontraron reglas YARA para compilar")
            return None
        
        try:
            logger.info(f"Compilando {len(rule_sources)} reglas YARA")
            return yara.compile(filepaths=rule_sources)
        except Exception as e:
            logger.error(f"Error compilando reglas YARA: {e}")
            return None
    
    def _get_files_to_scan(
        self,
        target_path: Path,
        extensions_filter: Optional[List[str]],
        max_file_size: int,
        recursive: bool
    ) -> List[Path]:
        """Obtener lista de archivos a escanear.
        
        Args:
            target_path: Ruta objetivo
            extensions_filter: Filtro de extensiones
            max_file_size: Tamaño máximo de archivo
            recursive: Escaneo recursivo
            
        Returns:
            Lista de archivos a escanear
        """
        files_to_scan = []
        
        # Usar extensiones por defecto si no se especifican
        extensions = extensions_filter or self.default_extensions
        extensions = [ext.lower() for ext in extensions]
        
        if target_path.is_file():
            # Escanear archivo único
            if target_path.stat().st_size <= max_file_size:
                files_to_scan.append(target_path)
        else:
            # Escanear directorio
            pattern = "**/*" if recursive else "*"
            
            for file_path in target_path.glob(pattern):
                if file_path.is_file():
                    # Verificar extensión
                    if any(file_path.suffix.lower() == ext for ext in extensions):
                        # Verificar tamaño
                        try:
                            if file_path.stat().st_size <= max_file_size:
                                files_to_scan.append(file_path)
                        except OSError:
                            # Archivo inaccesible
                            continue
        
        return files_to_scan
    
    def _scan_file(
        self,
        file_path: Path,
        compiled_rules: yara.Rules,
        timeout: int
    ) -> Dict[str, Any]:
        """Escanear archivo individual.
        
        Args:
            file_path: Ruta del archivo
            compiled_rules: Reglas compiladas
            timeout: Timeout en segundos
            
        Returns:
            Resultados del escaneo del archivo
        """
        try:
            matches = compiled_rules.match(
                filepath=str(file_path),
                timeout=timeout
            )
            
            match_results = []
            
            for match in matches:
                match_info = {
                    "rule_name": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": []
                }
                
                # Agregar información de strings coincidentes
                for string in match.strings:
                    match_info["strings"].append({
                        "identifier": string.identifier,
                        "instances": [
                            {
                                "offset": instance.offset,
                                "matched_data": instance.matched_data.hex() if len(instance.matched_data) <= 100 else instance.matched_data[:100].hex() + "...",
                                "matched_length": instance.matched_length
                            }
                            for instance in string.instances
                        ]
                    })
                
                match_results.append(match_info)
            
            return {
                "file_path": str(file_path),
                "file_size": file_path.stat().st_size,
                "matches": match_results,
                "scan_timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            return {
                "file_path": str(file_path),
                "error": str(e),
                "matches": []
            }
    
    def _generate_detection_report(
        self,
        scan_summary: Dict[str, Any],
        output_dir: Path
    ) -> None:
        """Generar reporte de detecciones.
        
        Args:
            scan_summary: Resumen del escaneo
            output_dir: Directorio de salida
        """
        report_file = output_dir / "detection_report.txt"
        
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("REPORTE DE DETECCIONES YARA\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"ID de Escaneo: {scan_summary['scan_id']}\n")
            f.write(f"Caso: {scan_summary['case_id']}\n")
            f.write(f"Objetivo: {scan_summary['target_path']}\n")
            f.write(f"Fecha: {scan_summary['started_at']}\n")
            f.write(f"Examinador: {scan_summary['examiner']}\n\n")
            
            stats = scan_summary['statistics']
            f.write("ESTADÍSTICAS:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Archivos encontrados: {stats['total_files_found']}\n")
            f.write(f"Archivos escaneados: {stats['files_scanned']}\n")
            f.write(f"Archivos con detecciones: {stats['files_with_matches']}\n")
            f.write(f"Total de detecciones: {stats['total_matches']}\n")
            f.write(f"Cobertura de escaneo: {stats['scan_coverage']:.1f}%\n\n")
            
            f.write("DETECCIONES:\n")
            f.write("-" * 40 + "\n")
            
            for result in scan_summary['results']:
                if result.get('matches'):
                    f.write(f"\nArchivo: {result['file_path']}\n")
                    f.write(f"Tamaño: {result.get('file_size', 0)} bytes\n")
                    
                    for match in result['matches']:
                        f.write(f"  Regla: {match['rule_name']}\n")
                        f.write(f"  Tags: {', '.join(match['tags'])}\n")
                        
                        if match['meta']:
                            f.write(f"  Metadatos: {match['meta']}\n")
                        
                        f.write("\n")
    
    def _generate_memory_detection_report(
        self,
        scan_summary: Dict[str, Any],
        output_dir: Path
    ) -> None:
        """Generar reporte de detecciones en memoria.
        
        Args:
            scan_summary: Resumen del escaneo de memoria
            output_dir: Directorio de salida
        """
        report_file = output_dir / "memory_detection_report.txt"
        
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("REPORTE DE DETECCIONES YARA EN MEMORIA\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"ID de Escaneo: {scan_summary['scan_id']}\n")
            f.write(f"Caso: {scan_summary['case_id']}\n")
            f.write(f"Dump de Memoria: {scan_summary['memory_dump_path']}\n")
            f.write(f"Fecha: {scan_summary['started_at']}\n")
            f.write(f"Examinador: {scan_summary['examiner']}\n\n")
            
            stats = scan_summary['statistics']
            f.write("ESTADÍSTICAS:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Tamaño del dump: {stats['dump_size_bytes'] // (1024*1024)} MB\n")
            f.write(f"Total de detecciones: {stats['total_matches']}\n")
            f.write(f"Reglas únicas detectadas: {stats['unique_rules_matched']}\n")
            f.write(f"Chunks procesados: {stats['chunks_processed']}\n\n")
            
            f.write("DETECCIONES EN MEMORIA:\n")
            f.write("-" * 40 + "\n")
            
            for match in scan_summary['matches']:
                f.write(f"\nRegla: {match['rule_name']}\n")
                f.write(f"Offset en dump: 0x{match['offset_in_dump']:08x}\n")
                f.write(f"Tags: {', '.join(match['tags'])}\n")
                
                if match['meta']:
                    f.write(f"Metadatos: {match['meta']}\n")
                
                for string_match in match['strings']:
                    f.write(f"  String: {string_match['identifier']}\n")
                    for instance in string_match['instances'][:3]:  # Limitar a 3 instancias
                        f.write(f"    Offset: 0x{instance['offset']:08x}\n")
                        f.write(f"    Datos: {instance['matched_data']}\n")
                
                f.write("\n")
    
    def _assess_threat_level(self, scan_results: List[Dict[str, Any]]) -> str:
        """Evaluar nivel de amenaza basado en detecciones.
        
        Args:
            scan_results: Resultados del escaneo
            
        Returns:
            Nivel de amenaza (low, medium, high, critical)
        """
        if not scan_results:
            return "none"
        
        critical_indicators = ["apt", "ransomware", "trojan", "rootkit"]
        high_indicators = ["malware", "exploit", "backdoor"]
        
        has_critical = False
        has_high = False
        
        for result in scan_results:
            for match in result.get("matches", []):
                tags = [tag.lower() for tag in match.get("tags", [])]
                rule_name = match.get("rule_name", "").lower()
                
                if any(indicator in rule_name or indicator in " ".join(tags) for indicator in critical_indicators):
                    has_critical = True
                elif any(indicator in rule_name or indicator in " ".join(tags) for indicator in high_indicators):
                    has_high = True
        
        if has_critical:
            return "critical"
        elif has_high:
            return "high"
        elif len(scan_results) > 10:
            return "medium"
        else:
            return "low"
    
    def _assess_threat_level_memory(self, matches: List[Dict[str, Any]]) -> str:
        """Evaluar nivel de amenaza en memoria.
        
        Args:
            matches: Detecciones en memoria
            
        Returns:
            Nivel de amenaza
        """
        if not matches:
            return "none"
        
        # Detecciones en memoria son generalmente más críticas
        if len(matches) > 5:
            return "critical"
        elif len(matches) > 2:
            return "high"
        else:
            return "medium"
    
    def _initialize_default_rules(self) -> None:
        """Inicializar reglas YARA por defecto."""
        # Crear reglas básicas de ejemplo
        default_rules = {
            "malware": [
                {
                    "name": "suspicious_strings",
                    "content": '''rule suspicious_strings {
    meta:
        description = "Detecta strings sospechosos comunes"
        author = "ForenseCTL"
        date = "2024-01-01"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "rundll32" nocase
        $s4 = "regsvr32" nocase
    condition:
        any of them
}'''
                }
            ],
            "suspicious": [
                {
                    "name": "base64_encoded",
                    "content": '''rule base64_encoded {
    meta:
        description = "Detecta contenido codificado en base64"
        author = "ForenseCTL"
    strings:
        $base64 = /[A-Za-z0-9+\/]{20,}={0,2}/
    condition:
        $base64
}'''
                }
            ]
        }
        
        # Crear reglas por defecto si no existen
        for category, rules in default_rules.items():
            category_dir = self.rules_dir / category
            category_dir.mkdir(parents=True, exist_ok=True)
            
            for rule_info in rules:
                rule_file = category_dir / f"{rule_info['name']}.yar"
                
                if not rule_file.exists():
                    with open(rule_file, "w", encoding="utf-8") as f:
                        f.write(rule_info["content"])
                    
                    self.rule_categories[category]["rules"].append(str(rule_file))
    
    def _get_yara_version(self) -> str:
        """Obtener versión de YARA.
        
        Returns:
            Versión de YARA
        """
        try:
            result = subprocess.run(
                ["yara", "--version"],
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