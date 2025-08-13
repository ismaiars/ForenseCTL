"""Constructor de timelines forenses usando plaso."""

import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from forensectl import config, logger
from forensectl.core.chain_of_custody import ChainOfCustody
from forensectl.core.manifest import Manifest


class TimelineBuilder:
    """Constructor de timelines forenses usando plaso."""
    
    def __init__(self, case_id: str, examiner: str = "") -> None:
        """Inicializar constructor de timeline.
        
        Args:
            case_id: ID del caso
            examiner: Examinador responsable
        """
        self.case_id = case_id
        self.examiner = examiner
        
        # Directorios del caso
        self.case_dir = config.CASES_DIR / case_id
        self.timeline_dir = self.case_dir / "analysis" / "timeline"
        self.timeline_dir.mkdir(parents=True, exist_ok=True)
        
        # Herramientas auxiliares
        self.chain_of_custody = ChainOfCustody(case_id)
        self.manifest = Manifest(case_id)
        
        # Comandos de plaso
        self.plaso_commands = {
            "log2timeline": "log2timeline.py",
            "psort": "psort.py",
            "pinfo": "pinfo.py",
            "psteal": "psteal.py",
            "image_export": "image_export.py"
        }
        
        # Parsers disponibles en plaso
        self.available_parsers = [
            "win7_bootres", "winevt", "winevtx", "winreg", "prefetch",
            "chrome_history", "firefox_history", "safari_history",
            "ntfs", "fat", "ext4", "hfs", "apfs",
            "syslog", "apache_access", "iis", "nginx_access",
            "sqlite", "esedb", "olecf", "lnk", "recycler",
            "usnjrnl", "mft", "filestat", "pe", "bencode"
        ]
        
        # Filtros de tiempo comunes
        self.time_filters = {
            "last_24h": "--date-filters 'date >= \"2024-01-01 00:00:00\" AND date <= \"2024-01-02 00:00:00\"'",
            "last_week": "--date-filters 'date >= \"2024-01-01 00:00:00\" AND date <= \"2024-01-08 00:00:00\"'",
            "last_month": "--date-filters 'date >= \"2024-01-01 00:00:00\" AND date <= \"2024-02-01 00:00:00\"'"
        }
    
    def build_timeline(
        self,
        source_path: Union[str, Path],
        source_type: str = "auto",
        parsers: Optional[List[str]] = None,
        time_zone: str = "UTC",
        output_format: str = "csv",
        date_filter: Optional[str] = None,
        keyword_filter: Optional[str] = None,
        custom_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Construir timeline forense completo.
        
        Args:
            source_path: Ruta de la fuente (imagen, directorio, archivo)
            source_type: Tipo de fuente (image, directory, file, auto)
            parsers: Lista de parsers específicos a usar
            time_zone: Zona horaria para el timeline
            output_format: Formato de salida (csv, json, xlsx, l2tcsv)
            date_filter: Filtro de fechas
            keyword_filter: Filtro de palabras clave
            custom_options: Opciones personalizadas
            
        Returns:
            Diccionario con información del timeline generado
        """
        source_path = Path(source_path)
        if not source_path.exists():
            raise ValueError(f"Fuente no encontrada: {source_path}")
        
        timeline_id = str(uuid.uuid4())
        timeline_start = datetime.now(timezone.utc)
        
        logger.info(f"Iniciando construcción de timeline {timeline_id} para: {source_path}")
        
        # Crear directorio de timeline
        timeline_output_dir = self.timeline_dir / timeline_id
        timeline_output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Fase 1: Extracción con log2timeline
            plaso_file = timeline_output_dir / f"{timeline_id}.plaso"
            extraction_result = self._extract_timeline_data(
                source_path, plaso_file, source_type, parsers, time_zone, custom_options
            )
            
            if not extraction_result["success"]:
                raise RuntimeError(f"Error en extracción: {extraction_result['error']}")
            
            # Fase 2: Procesamiento con psort
            timeline_file = timeline_output_dir / f"timeline.{output_format}"
            processing_result = self._process_timeline_data(
                plaso_file, timeline_file, output_format, date_filter, keyword_filter
            )
            
            if not processing_result["success"]:
                raise RuntimeError(f"Error en procesamiento: {processing_result['error']}")
            
            # Fase 3: Análisis estadístico
            stats_result = self._analyze_timeline_statistics(plaso_file, timeline_output_dir)
            
            timeline_end = datetime.now(timezone.utc)
            
            # Crear resumen del timeline
            timeline_summary = {
                "timeline_id": timeline_id,
                "case_id": self.case_id,
                "source_path": str(source_path),
                "source_type": source_type,
                "plaso_file": str(plaso_file),
                "timeline_file": str(timeline_file),
                "output_directory": str(timeline_output_dir),
                "output_format": output_format,
                "time_zone": time_zone,
                "parsers_used": parsers or [],
                "extraction_stats": extraction_result.get("stats", {}),
                "processing_stats": processing_result.get("stats", {}),
                "timeline_stats": stats_result.get("stats", {}),
                "started_at": timeline_start.isoformat(),
                "completed_at": timeline_end.isoformat(),
                "duration_seconds": (timeline_end - timeline_start).total_seconds(),
                "examiner": self.examiner,
                "tool_info": {
                    "name": "plaso",
                    "version": self._get_plaso_version(),
                    "commands_used": ["log2timeline.py", "psort.py", "pinfo.py"]
                },
                "filters": {
                    "date_filter": date_filter,
                    "keyword_filter": keyword_filter
                },
                "options": custom_options or {}
            }
            
            # Guardar resumen
            summary_file = timeline_output_dir / "timeline_summary.json"
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(timeline_summary, f, indent=2, ensure_ascii=False)
            
            # Registrar en manifiesto
            self.manifest.register_analysis(
                analysis_id=timeline_id,
                analysis_type="timeline_construction",
                evidence_id="",  # Se puede vincular después
                tool_name="plaso",
                tool_version=self._get_plaso_version(),
                output_path=str(timeline_output_dir),
                examiner=self.examiner,
                description=f"Timeline forense de {source_type}: {source_path.name}",
                parameters={
                    "source_path": str(source_path),
                    "source_type": source_type,
                    "parsers": parsers,
                    "time_zone": time_zone,
                    "output_format": output_format,
                    "date_filter": date_filter,
                    "keyword_filter": keyword_filter
                },
                results_summary={
                    "total_events": timeline_summary.get("timeline_stats", {}).get("total_events", 0),
                    "unique_sources": timeline_summary.get("timeline_stats", {}).get("unique_sources", 0),
                    "date_range": timeline_summary.get("timeline_stats", {}).get("date_range", {})
                }
            )
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="timeline_constructed",
                description=f"Timeline forense construido con {timeline_summary.get('timeline_stats', {}).get('total_events', 0)} eventos",
                examiner=self.examiner,
                evidence_path=str(source_path),
                metadata={
                    "timeline_id": timeline_id,
                    "total_events": timeline_summary.get("timeline_stats", {}).get("total_events", 0),
                    "duration_seconds": timeline_summary["duration_seconds"]
                }
            )
            
            logger.info(f"Timeline {timeline_id} construido exitosamente")
            return timeline_summary
            
        except Exception as e:
            logger.error(f"Error durante construcción de timeline {timeline_id}: {e}")
            
            # Agregar error a cadena de custodia
            self.chain_of_custody.add_entry(
                action="timeline_construction_failed",
                description=f"Fallo en construcción de timeline: {str(e)}",
                examiner=self.examiner,
                evidence_path=str(source_path),
                metadata={"timeline_id": timeline_id, "error": str(e)}
            )
            
            raise
    
    def filter_timeline(
        self,
        plaso_file: Union[str, Path],
        output_file: Union[str, Path],
        date_filter: Optional[str] = None,
        keyword_filter: Optional[str] = None,
        source_filter: Optional[str] = None,
        output_format: str = "csv"
    ) -> Dict[str, Any]:
        """Filtrar timeline existente.
        
        Args:
            plaso_file: Archivo plaso de entrada
            output_file: Archivo de salida filtrado
            date_filter: Filtro de fechas
            keyword_filter: Filtro de palabras clave
            source_filter: Filtro de fuentes
            output_format: Formato de salida
            
        Returns:
            Información del filtrado
        """
        plaso_file = Path(plaso_file)
        output_file = Path(output_file)
        
        if not plaso_file.exists():
            raise ValueError(f"Archivo plaso no encontrado: {plaso_file}")
        
        # Crear directorio de salida
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Construir comando psort con filtros
        cmd = [self.plaso_commands["psort"]]
        
        # Agregar filtros
        if date_filter:
            cmd.extend(["--date-filters", date_filter])
        
        if keyword_filter:
            cmd.extend(["--slice", keyword_filter])
        
        if source_filter:
            cmd.extend(["--source-filter", source_filter])
        
        # Formato de salida
        cmd.extend(["-o", output_format])
        
        # Archivos
        cmd.extend(["-w", str(output_file), str(plaso_file)])
        
        logger.info(f"Filtrando timeline: {plaso_file} -> {output_file}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutos
            )
            
            if result.returncode == 0:
                # Obtener estadísticas del archivo filtrado
                file_size = output_file.stat().st_size if output_file.exists() else 0
                
                # Agregar a cadena de custodia
                self.chain_of_custody.add_entry(
                    action="timeline_filtered",
                    description=f"Timeline filtrado con criterios específicos",
                    examiner=self.examiner,
                    evidence_path=str(plaso_file),
                    metadata={
                        "output_file": str(output_file),
                        "date_filter": date_filter,
                        "keyword_filter": keyword_filter,
                        "source_filter": source_filter,
                        "output_size": file_size
                    }
                )
                
                logger.info(f"Timeline filtrado exitosamente: {output_file}")
                
                return {
                    "status": "success",
                    "input_file": str(plaso_file),
                    "output_file": str(output_file),
                    "output_size": file_size,
                    "filters_applied": {
                        "date_filter": date_filter,
                        "keyword_filter": keyword_filter,
                        "source_filter": source_filter
                    },
                    "command": " ".join(cmd)
                }
            else:
                error_msg = result.stderr if result.stderr else "Error desconocido"
                logger.error(f"Error filtrando timeline: {error_msg}")
                
                return {
                    "status": "error",
                    "error": error_msg,
                    "command": " ".join(cmd)
                }
                
        except Exception as e:
            logger.error(f"Excepción filtrando timeline: {e}")
            return {
                "status": "error",
                "error": str(e),
                "command": " ".join(cmd)
            }
    
    def get_timeline_info(
        self,
        plaso_file: Union[str, Path]
    ) -> Dict[str, Any]:
        """Obtener información de un archivo plaso.
        
        Args:
            plaso_file: Archivo plaso
            
        Returns:
            Información del timeline
        """
        plaso_file = Path(plaso_file)
        
        if not plaso_file.exists():
            raise ValueError(f"Archivo plaso no encontrado: {plaso_file}")
        
        # Construir comando pinfo
        cmd = [self.plaso_commands["pinfo"], str(plaso_file)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                info = self._parse_pinfo_output(result.stdout)
                
                logger.info(f"Información obtenida para timeline: {plaso_file}")
                
                return {
                    "status": "success",
                    "plaso_file": str(plaso_file),
                    "info": info,
                    "raw_output": result.stdout,
                    "command": " ".join(cmd)
                }
            else:
                error_msg = result.stderr if result.stderr else "Error desconocido"
                logger.error(f"Error obteniendo información del timeline: {error_msg}")
                
                return {
                    "status": "error",
                    "error": error_msg,
                    "command": " ".join(cmd)
                }
                
        except Exception as e:
            logger.error(f"Excepción obteniendo información del timeline: {e}")
            return {
                "status": "error",
                "error": str(e),
                "command": " ".join(cmd)
            }
    
    def export_timeline_subset(
        self,
        plaso_file: Union[str, Path],
        output_dir: Union[str, Path],
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        sources: Optional[List[str]] = None,
        formats: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Exportar subconjunto del timeline en múltiples formatos.
        
        Args:
            plaso_file: Archivo plaso de entrada
            output_dir: Directorio de salida
            start_date: Fecha de inicio (YYYY-MM-DD HH:MM:SS)
            end_date: Fecha de fin (YYYY-MM-DD HH:MM:SS)
            sources: Lista de fuentes específicas
            formats: Lista de formatos de salida
            
        Returns:
            Información de la exportación
        """
        plaso_file = Path(plaso_file)
        output_dir = Path(output_dir)
        
        if not plaso_file.exists():
            raise ValueError(f"Archivo plaso no encontrado: {plaso_file}")
        
        # Crear directorio de salida
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Formatos por defecto
        if not formats:
            formats = ["csv", "json", "xlsx"]
        
        exported_files = []
        
        for output_format in formats:
            try:
                # Construir filtro de fechas
                date_filter = None
                if start_date and end_date:
                    date_filter = f'date >= "{start_date}" AND date <= "{end_date}"'
                elif start_date:
                    date_filter = f'date >= "{start_date}"'
                elif end_date:
                    date_filter = f'date <= "{end_date}"'
                
                # Construir filtro de fuentes
                source_filter = None
                if sources:
                    source_filter = ",".join(sources)
                
                # Archivo de salida
                output_file = output_dir / f"timeline_subset.{output_format}"
                
                # Filtrar y exportar
                filter_result = self.filter_timeline(
                    plaso_file, output_file, date_filter, None, source_filter, output_format
                )
                
                if filter_result["status"] == "success":
                    exported_files.append({
                        "format": output_format,
                        "file": str(output_file),
                        "size": filter_result.get("output_size", 0)
                    })
                    
            except Exception as e:
                logger.warning(f"Error exportando formato {output_format}: {e}")
        
        logger.info(f"Exportados {len(exported_files)} archivos de timeline")
        
        return {
            "status": "success",
            "exported_files": exported_files,
            "filters_applied": {
                "start_date": start_date,
                "end_date": end_date,
                "sources": sources
            }
        }
    
    def _extract_timeline_data(
        self,
        source_path: Path,
        plaso_file: Path,
        source_type: str,
        parsers: Optional[List[str]],
        time_zone: str,
        custom_options: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Extraer datos de timeline con log2timeline.
        
        Args:
            source_path: Ruta de la fuente
            plaso_file: Archivo plaso de salida
            source_type: Tipo de fuente
            parsers: Parsers específicos
            time_zone: Zona horaria
            custom_options: Opciones personalizadas
            
        Returns:
            Resultado de la extracción
        """
        # Construir comando log2timeline
        cmd = [self.plaso_commands["log2timeline"]]
        
        # Opciones básicas
        cmd.extend(["--timezone", time_zone])
        cmd.extend(["--storage-file", str(plaso_file)])
        
        # Parsers específicos
        if parsers:
            cmd.extend(["--parsers", ",".join(parsers)])
        
        # Opciones personalizadas
        if custom_options:
            for key, value in custom_options.items():
                if value is not None:
                    cmd.extend([f"--{key}", str(value)])
        
        # Fuente
        cmd.append(str(source_path))
        
        logger.info(f"Ejecutando extracción de timeline: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hora
            )
            
            if result.returncode == 0:
                # Obtener estadísticas del archivo plaso
                plaso_size = plaso_file.stat().st_size if plaso_file.exists() else 0
                
                logger.info(f"Extracción completada: {plaso_file} ({plaso_size} bytes)")
                
                return {
                    "success": True,
                    "plaso_file": str(plaso_file),
                    "plaso_size": plaso_size,
                    "stats": self._parse_log2timeline_stats(result.stderr),
                    "command": " ".join(cmd)
                }
            else:
                error_msg = result.stderr if result.stderr else "Error desconocido"
                logger.error(f"Error en extracción de timeline: {error_msg}")
                
                return {
                    "success": False,
                    "error": error_msg,
                    "command": " ".join(cmd)
                }
                
        except Exception as e:
            logger.error(f"Excepción en extracción de timeline: {e}")
            return {
                "success": False,
                "error": str(e),
                "command": " ".join(cmd)
            }
    
    def _process_timeline_data(
        self,
        plaso_file: Path,
        timeline_file: Path,
        output_format: str,
        date_filter: Optional[str],
        keyword_filter: Optional[str]
    ) -> Dict[str, Any]:
        """Procesar datos de timeline con psort.
        
        Args:
            plaso_file: Archivo plaso de entrada
            timeline_file: Archivo de timeline de salida
            output_format: Formato de salida
            date_filter: Filtro de fechas
            keyword_filter: Filtro de palabras clave
            
        Returns:
            Resultado del procesamiento
        """
        # Construir comando psort
        cmd = [self.plaso_commands["psort"]]
        
        # Filtros
        if date_filter:
            cmd.extend(["--date-filters", date_filter])
        
        if keyword_filter:
            cmd.extend(["--slice", keyword_filter])
        
        # Formato de salida
        cmd.extend(["-o", output_format])
        
        # Archivos
        cmd.extend(["-w", str(timeline_file), str(plaso_file)])
        
        logger.info(f"Ejecutando procesamiento de timeline: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutos
            )
            
            if result.returncode == 0:
                # Obtener estadísticas del archivo de timeline
                timeline_size = timeline_file.stat().st_size if timeline_file.exists() else 0
                
                logger.info(f"Procesamiento completado: {timeline_file} ({timeline_size} bytes)")
                
                return {
                    "success": True,
                    "timeline_file": str(timeline_file),
                    "timeline_size": timeline_size,
                    "stats": self._parse_psort_stats(result.stderr),
                    "command": " ".join(cmd)
                }
            else:
                error_msg = result.stderr if result.stderr else "Error desconocido"
                logger.error(f"Error en procesamiento de timeline: {error_msg}")
                
                return {
                    "success": False,
                    "error": error_msg,
                    "command": " ".join(cmd)
                }
                
        except Exception as e:
            logger.error(f"Excepción en procesamiento de timeline: {e}")
            return {
                "success": False,
                "error": str(e),
                "command": " ".join(cmd)
            }
    
    def _analyze_timeline_statistics(
        self,
        plaso_file: Path,
        output_dir: Path
    ) -> Dict[str, Any]:
        """Analizar estadísticas del timeline.
        
        Args:
            plaso_file: Archivo plaso
            output_dir: Directorio de salida
            
        Returns:
            Estadísticas del timeline
        """
        stats = {
            "total_events": 0,
            "unique_sources": 0,
            "date_range": {},
            "event_types": {},
            "source_breakdown": {},
            "hourly_distribution": {},
            "daily_distribution": {},
            "file_size": 0
        }
        
        try:
            # Obtener información básica del archivo plaso
            if plaso_file.exists():
                stats["file_size"] = plaso_file.stat().st_size
            
            # Usar pinfo para obtener estadísticas
            info_result = self.get_timeline_info(plaso_file)
            
            if info_result["status"] == "success":
                info_data = info_result.get("info", {})
                
                # Extraer estadísticas básicas
                if "storage_information" in info_data:
                    storage_info = info_data["storage_information"]
                    stats["total_events"] = int(storage_info.get("number_of_events", 0))
                
                # Extraer información de fuentes
                if "sources" in info_data:
                    sources_info = info_data["sources"]
                    stats["unique_sources"] = len(sources_info)
                    
                    # Contar eventos por fuente
                    for source, source_data in sources_info.items():
                        if isinstance(source_data, dict) and "events" in source_data:
                            stats["source_breakdown"][source] = int(source_data["events"])
                
                # Extraer rango de fechas
                if "timeline_information" in info_data:
                    timeline_info = info_data["timeline_information"]
                    stats["date_range"] = {
                        "start_date": timeline_info.get("first_event_timestamp"),
                        "end_date": timeline_info.get("last_event_timestamp")
                    }
            
            # Generar estadísticas adicionales si tenemos un timeline CSV
            csv_timeline = output_dir / "timeline.csv"
            if csv_timeline.exists():
                additional_stats = self._analyze_csv_timeline(csv_timeline)
                stats.update(additional_stats)
            
            # Guardar estadísticas
            stats_file = output_dir / "timeline_statistics.json"
            with open(stats_file, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Estadísticas de timeline generadas: {stats['total_events']} eventos")
            
            return {
                "success": True,
                "stats": stats,
                "stats_file": str(stats_file)
            }
            
        except Exception as e:
            logger.error(f"Error analizando estadísticas del timeline: {e}")
            return {
                "success": False,
                "error": str(e),
                "stats": stats
            }
    
    def _parse_log2timeline_stats(self, stderr_output: str) -> Dict[str, Any]:
        """Parsear estadísticas de log2timeline.
        
        Args:
            stderr_output: Salida de error del comando
            
        Returns:
            Estadísticas parseadas
        """
        stats = {"raw_output": stderr_output}
        
        # Buscar patrones comunes en la salida
        for line in stderr_output.split("\n"):
            line = line.strip()
            
            if "Processing completed" in line:
                stats["status"] = "completed"
            elif "events extracted" in line:
                # Extraer número de eventos
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.isdigit() and i + 1 < len(parts) and "events" in parts[i + 1]:
                        stats["events_extracted"] = int(part)
                        break
            elif "parsers" in line.lower() and "used" in line.lower():
                # Extraer parsers utilizados
                if ":" in line:
                    parsers_part = line.split(":", 1)[1].strip()
                    stats["parsers_used"] = [p.strip() for p in parsers_part.split(",")]
        
        return stats
    
    def _parse_psort_stats(self, stderr_output: str) -> Dict[str, Any]:
        """Parsear estadísticas de psort.
        
        Args:
            stderr_output: Salida de error del comando
            
        Returns:
            Estadísticas parseadas
        """
        stats = {"raw_output": stderr_output}
        
        # Buscar patrones comunes en la salida
        for line in stderr_output.split("\n"):
            line = line.strip()
            
            if "Processing completed" in line:
                stats["status"] = "completed"
            elif "events processed" in line:
                # Extraer número de eventos procesados
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.isdigit() and i + 1 < len(parts) and "events" in parts[i + 1]:
                        stats["events_processed"] = int(part)
                        break
        
        return stats
    
    def _parse_pinfo_output(self, output: str) -> Dict[str, Any]:
        """Parsear salida de pinfo.
        
        Args:
            output: Salida del comando
            
        Returns:
            Información parseada
        """
        info = {"raw_output": output}
        
        current_section = None
        
        for line in output.split("\n"):
            line = line.strip()
            
            if line.endswith(":"):
                current_section = line[:-1].lower().replace(" ", "_")
                info[current_section] = {}
            elif ":" in line and current_section:
                key, value = line.split(":", 1)
                info[current_section][key.strip().lower().replace(" ", "_")] = value.strip()
            elif ":" in line:
                key, value = line.split(":", 1)
                info[key.strip().lower().replace(" ", "_")] = value.strip()
        
        return info
    
    def _analyze_csv_timeline(self, csv_file: Path) -> Dict[str, Any]:
        """Analizar timeline CSV para estadísticas adicionales.
        
        Args:
            csv_file: Archivo CSV del timeline
            
        Returns:
            Estadísticas adicionales
        """
        additional_stats = {
            "hourly_distribution": {},
            "daily_distribution": {},
            "event_types": {},
            "top_sources": []
        }
        
        try:
            import csv
            from collections import Counter
            
            event_types = Counter()
            hourly_dist = Counter()
            daily_dist = Counter()
            sources = Counter()
            
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    # Analizar tipos de eventos
                    if 'message_type' in row:
                        event_types[row['message_type']] += 1
                    
                    # Analizar distribución temporal
                    if 'datetime' in row:
                        try:
                            dt_str = row['datetime']
                            # Extraer hora y día
                            if ' ' in dt_str:
                                date_part, time_part = dt_str.split(' ', 1)
                                if ':' in time_part:
                                    hour = time_part.split(':')[0]
                                    hourly_dist[hour] += 1
                                daily_dist[date_part] += 1
                        except:
                            pass
                    
                    # Analizar fuentes
                    if 'source' in row:
                        sources[row['source']] += 1
            
            # Convertir a diccionarios
            additional_stats["event_types"] = dict(event_types.most_common(20))
            additional_stats["hourly_distribution"] = dict(hourly_dist)
            additional_stats["daily_distribution"] = dict(daily_dist)
            additional_stats["top_sources"] = list(sources.most_common(10))
            
        except Exception as e:
            logger.warning(f"Error analizando CSV timeline: {e}")
        
        return additional_stats
    
    def _get_plaso_version(self) -> str:
        """Obtener versión de plaso.
        
        Returns:
            Versión de plaso
        """
        try:
            result = subprocess.run(
                ["log2timeline.py", "--version"],
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