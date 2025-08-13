"""Generador de reportes forenses técnicos y ejecutivos."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from forensectl import config, logger
from forensectl.core.case_manager import CaseManager
from forensectl.core.manifest import Manifest
from forensectl.core.chain_of_custody import ChainOfCustody
from .template_manager import TemplateManager
from .export_manager import ExportManager


class ReportGenerator:
    """Generador de reportes forenses completos."""
    
    def __init__(self, case_id: str, examiner: str = "") -> None:
        """Inicializar generador de reportes.
        
        Args:
            case_id: ID del caso
            examiner: Examinador responsable
        """
        self.case_id = case_id
        self.examiner = examiner
        
        # Directorios del caso
        self.case_dir = config.CASES_DIR / case_id
        self.reports_dir = self.case_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Herramientas auxiliares
        self.case_manager = CaseManager()
        self.manifest = Manifest(case_id)
        self.chain_of_custody = ChainOfCustody(case_id)
        self.template_manager = TemplateManager()
        self.export_manager = ExportManager()
        
        # Configuración de reportes
        self.report_config = {
            "technical": {
                "sections": [
                    "executive_summary",
                    "case_information",
                    "evidence_summary",
                    "analysis_methodology",
                    "technical_findings",
                    "timeline_analysis",
                    "artifact_analysis",
                    "malware_analysis",
                    "network_analysis",
                    "conclusions",
                    "recommendations",
                    "appendices"
                ],
                "detail_level": "high",
                "include_technical_details": True,
                "include_raw_data": True,
                "include_screenshots": True
            },
            "executive": {
                "sections": [
                    "executive_summary",
                    "case_overview",
                    "key_findings",
                    "business_impact",
                    "recommendations",
                    "next_steps"
                ],
                "detail_level": "low",
                "include_technical_details": False,
                "include_raw_data": False,
                "include_screenshots": False
            }
        }
    
    def generate_report(
        self,
        report_type: str = "technical",
        output_format: str = "pdf",
        template_name: Optional[str] = None,
        custom_sections: Optional[List[str]] = None,
        include_attachments: bool = True,
        language: str = "es"
    ) -> Dict[str, Any]:
        """Generar reporte forense completo.
        
        Args:
            report_type: Tipo de reporte (technical, executive)
            output_format: Formato de salida (pdf, html, markdown, docx)
            template_name: Nombre de plantilla personalizada
            custom_sections: Secciones personalizadas
            include_attachments: Incluir archivos adjuntos
            language: Idioma del reporte
            
        Returns:
            Información del reporte generado
        """
        if report_type not in self.report_config:
            raise ValueError(f"Tipo de reporte no soportado: {report_type}")
        
        report_id = str(uuid.uuid4())
        generation_start = datetime.now(timezone.utc)
        
        logger.info(f"Iniciando generación de reporte {report_id} tipo {report_type}")
        
        try:
            # Obtener información del caso
            case_info = self.case_manager.get_case(self.case_id)
            if not case_info:
                raise ValueError(f"Caso no encontrado: {self.case_id}")
            
            # Recopilar datos para el reporte
            report_data = self._collect_report_data(case_info, report_type)
            
            # Configurar secciones
            config = self.report_config[report_type].copy()
            if custom_sections:
                config["sections"] = custom_sections
            
            # Generar contenido del reporte
            report_content = self._generate_report_content(
                report_data, config, language
            )
            
            # Crear directorio de salida
            report_output_dir = self.reports_dir / report_id
            report_output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generar reporte en el formato solicitado
            output_file = self._generate_output_file(
                report_content, report_output_dir, output_format,
                template_name, report_type, language
            )
            
            # Incluir archivos adjuntos si se solicita
            attachments = []
            if include_attachments:
                attachments = self._include_attachments(
                    report_data, report_output_dir
                )
            
            generation_end = datetime.now(timezone.utc)
            
            # Crear metadatos del reporte
            report_metadata = {
                "report_id": report_id,
                "case_id": self.case_id,
                "report_type": report_type,
                "output_format": output_format,
                "template_name": template_name,
                "language": language,
                "output_file": str(output_file),
                "output_directory": str(report_output_dir),
                "attachments": attachments,
                "sections_included": config["sections"],
                "generated_at": generation_start.isoformat(),
                "completed_at": generation_end.isoformat(),
                "generation_time_seconds": (generation_end - generation_start).total_seconds(),
                "examiner": self.examiner,
                "file_size_bytes": output_file.stat().st_size if output_file.exists() else 0,
                "page_count": self._estimate_page_count(output_file, output_format),
                "generation_parameters": {
                    "include_attachments": include_attachments,
                    "detail_level": config["detail_level"],
                    "include_technical_details": config["include_technical_details"]
                }
            }
            
            # Guardar metadatos
            metadata_file = report_output_dir / "report_metadata.json"
            with open(metadata_file, "w", encoding="utf-8") as f:
                json.dump(report_metadata, f, indent=2, ensure_ascii=False)
            
            # Registrar en manifiesto
            self.manifest.register_report(
                report_id=report_id,
                report_type=report_type,
                output_format=output_format,
                output_path=str(output_file),
                examiner=self.examiner,
                description=f"Reporte {report_type} en formato {output_format}",
                metadata={
                    "sections_count": len(config["sections"]),
                    "attachments_count": len(attachments),
                    "language": language,
                    "template_used": template_name or "default"
                }
            )
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="report_generated",
                description=f"Reporte {report_type} generado en formato {output_format}",
                examiner=self.examiner,
                evidence_path=str(output_file),
                metadata={
                    "report_id": report_id,
                    "report_type": report_type,
                    "output_format": output_format,
                    "file_size_bytes": report_metadata["file_size_bytes"]
                }
            )
            
            logger.info(f"Reporte {report_id} generado exitosamente: {output_file}")
            return report_metadata
            
        except Exception as e:
            logger.error(f"Error generando reporte {report_id}: {e}")
            
            # Agregar error a cadena de custodia
            self.chain_of_custody.add_entry(
                action="report_generation_failed",
                description=f"Fallo en generación de reporte: {str(e)}",
                examiner=self.examiner,
                metadata={"report_id": report_id, "error": str(e)}
            )
            
            raise
    
    def generate_timeline_report(
        self,
        timeline_file: Union[str, Path],
        output_format: str = "html",
        time_range: Optional[Dict[str, str]] = None,
        event_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Generar reporte específico de timeline.
        
        Args:
            timeline_file: Archivo de timeline a procesar
            output_format: Formato de salida
            time_range: Rango de tiempo a incluir
            event_types: Tipos de eventos a filtrar
            
        Returns:
            Información del reporte de timeline generado
        """
        timeline_file = Path(timeline_file)
        if not timeline_file.exists():
            raise ValueError(f"Archivo de timeline no encontrado: {timeline_file}")
        
        report_id = str(uuid.uuid4())
        logger.info(f"Generando reporte de timeline {report_id}")
        
        # Crear directorio de salida
        timeline_report_dir = self.reports_dir / f"timeline_{report_id}"
        timeline_report_dir.mkdir(parents=True, exist_ok=True)
        
        # Procesar timeline
        timeline_data = self._process_timeline_file(timeline_file, time_range, event_types)
        
        # Generar visualización
        output_file = self._generate_timeline_visualization(
            timeline_data, timeline_report_dir, output_format
        )
        
        timeline_metadata = {
            "report_id": report_id,
            "case_id": self.case_id,
            "report_type": "timeline",
            "source_timeline": str(timeline_file),
            "output_file": str(output_file),
            "output_format": output_format,
            "events_processed": len(timeline_data.get("events", [])),
            "time_range": time_range,
            "event_types_filtered": event_types,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "examiner": self.examiner
        }
        
        # Guardar metadatos
        metadata_file = timeline_report_dir / "timeline_report_metadata.json"
        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(timeline_metadata, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Reporte de timeline {report_id} generado: {output_file}")
        return timeline_metadata
    
    def generate_comparison_report(
        self,
        baseline_case_id: str,
        comparison_type: str = "evidence",
        output_format: str = "pdf"
    ) -> Dict[str, Any]:
        """Generar reporte de comparación entre casos.
        
        Args:
            baseline_case_id: ID del caso base para comparación
            comparison_type: Tipo de comparación (evidence, analysis, timeline)
            output_format: Formato de salida
            
        Returns:
            Información del reporte de comparación
        """
        report_id = str(uuid.uuid4())
        logger.info(f"Generando reporte de comparación {report_id}")
        
        # Obtener datos de ambos casos
        current_case = self.case_manager.get_case(self.case_id)
        baseline_case = self.case_manager.get_case(baseline_case_id)
        
        if not current_case or not baseline_case:
            raise ValueError("Uno o ambos casos no encontrados")
        
        # Crear directorio de salida
        comparison_report_dir = self.reports_dir / f"comparison_{report_id}"
        comparison_report_dir.mkdir(parents=True, exist_ok=True)
        
        # Realizar comparación
        comparison_data = self._perform_case_comparison(
            current_case, baseline_case, comparison_type
        )
        
        # Generar reporte de comparación
        output_file = self._generate_comparison_output(
            comparison_data, comparison_report_dir, output_format
        )
        
        comparison_metadata = {
            "report_id": report_id,
            "current_case_id": self.case_id,
            "baseline_case_id": baseline_case_id,
            "comparison_type": comparison_type,
            "output_file": str(output_file),
            "output_format": output_format,
            "differences_found": comparison_data.get("differences_count", 0),
            "similarities_found": comparison_data.get("similarities_count", 0),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "examiner": self.examiner
        }
        
        # Guardar metadatos
        metadata_file = comparison_report_dir / "comparison_report_metadata.json"
        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(comparison_metadata, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Reporte de comparación {report_id} generado: {output_file}")
        return comparison_metadata
    
    def _collect_report_data(
        self,
        case_info: Dict[str, Any],
        report_type: str
    ) -> Dict[str, Any]:
        """Recopilar datos necesarios para el reporte.
        
        Args:
            case_info: Información del caso
            report_type: Tipo de reporte
            
        Returns:
            Datos compilados para el reporte
        """
        logger.info("Recopilando datos para el reporte")
        
        # Datos básicos del caso
        report_data = {
            "case_info": case_info,
            "generation_timestamp": datetime.now(timezone.utc).isoformat(),
            "examiner": self.examiner
        }
        
        # Obtener resumen del manifiesto
        manifest_summary = self.manifest.get_case_summary()
        report_data["manifest_summary"] = manifest_summary
        
        # Obtener evidencias
        evidences = self.manifest.get_evidences()
        report_data["evidences"] = evidences
        
        # Obtener análisis realizados
        analyses = self.manifest.get_analyses()
        report_data["analyses"] = analyses
        
        # Obtener cadena de custodia
        chain_entries = self.chain_of_custody.get_entries()
        report_data["chain_of_custody"] = chain_entries
        
        # Obtener verificaciones de integridad
        integrity_checks = self.manifest.get_integrity_verifications()
        report_data["integrity_checks"] = integrity_checks
        
        # Datos específicos según el tipo de reporte
        if report_type == "technical":
            # Incluir datos técnicos detallados
            report_data.update(self._collect_technical_data())
        elif report_type == "executive":
            # Incluir resúmenes ejecutivos
            report_data.update(self._collect_executive_data())
        
        return report_data
    
    def _collect_technical_data(self) -> Dict[str, Any]:
        """Recopilar datos técnicos detallados.
        
        Returns:
            Datos técnicos para el reporte
        """
        technical_data = {}
        
        # Buscar archivos de análisis específicos
        analysis_dir = self.case_dir / "analysis"
        
        if analysis_dir.exists():
            # Análisis de memoria
            memory_dir = analysis_dir / "memory"
            if memory_dir.exists():
                technical_data["memory_analysis"] = self._collect_memory_analysis_data(memory_dir)
            
            # Análisis de disco
            disk_dir = analysis_dir / "disk"
            if disk_dir.exists():
                technical_data["disk_analysis"] = self._collect_disk_analysis_data(disk_dir)
            
            # Timelines
            timeline_dir = analysis_dir / "timeline"
            if timeline_dir.exists():
                technical_data["timeline_analysis"] = self._collect_timeline_data(timeline_dir)
            
            # Análisis YARA
            yara_dir = analysis_dir / "yara"
            if yara_dir.exists():
                technical_data["yara_analysis"] = self._collect_yara_data(yara_dir)
            
            # Artefactos
            artifacts_dir = analysis_dir / "artifacts"
            if artifacts_dir.exists():
                technical_data["artifacts_analysis"] = self._collect_artifacts_data(artifacts_dir)
        
        return technical_data
    
    def _collect_executive_data(self) -> Dict[str, Any]:
        """Recopilar datos para reporte ejecutivo.
        
        Returns:
            Datos ejecutivos para el reporte
        """
        executive_data = {
            "key_findings": self._extract_key_findings(),
            "risk_assessment": self._assess_risks(),
            "business_impact": self._assess_business_impact(),
            "recommendations": self._generate_recommendations()
        }
        
        return executive_data
    
    def _generate_report_content(
        self,
        report_data: Dict[str, Any],
        config: Dict[str, Any],
        language: str
    ) -> Dict[str, Any]:
        """Generar contenido estructurado del reporte.
        
        Args:
            report_data: Datos del reporte
            config: Configuración del reporte
            language: Idioma del reporte
            
        Returns:
            Contenido estructurado del reporte
        """
        logger.info("Generando contenido del reporte")
        
        content = {
            "metadata": {
                "title": self._get_report_title(report_data, language),
                "case_id": self.case_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "examiner": self.examiner,
                "language": language,
                "detail_level": config["detail_level"]
            },
            "sections": {}
        }
        
        # Generar cada sección
        for section_name in config["sections"]:
            try:
                section_content = self._generate_section_content(
                    section_name, report_data, config, language
                )
                content["sections"][section_name] = section_content
            except Exception as e:
                logger.warning(f"Error generando sección {section_name}: {e}")
                content["sections"][section_name] = {
                    "title": section_name.replace("_", " ").title(),
                    "content": f"Error generando contenido: {str(e)}",
                    "error": True
                }
        
        return content
    
    def _generate_output_file(
        self,
        report_content: Dict[str, Any],
        output_dir: Path,
        output_format: str,
        template_name: Optional[str],
        report_type: str,
        language: str
    ) -> Path:
        """Generar archivo de salida en el formato especificado.
        
        Args:
            report_content: Contenido del reporte
            output_dir: Directorio de salida
            output_format: Formato de salida
            template_name: Nombre de plantilla
            report_type: Tipo de reporte
            language: Idioma
            
        Returns:
            Ruta del archivo generado
        """
        logger.info(f"Generando archivo de salida en formato {output_format}")
        
        # Obtener plantilla
        template = self.template_manager.get_template(
            template_name or f"default_{report_type}",
            output_format,
            language
        )
        
        # Generar contenido usando la plantilla
        rendered_content = self.template_manager.render_template(
            template, report_content
        )
        
        # Exportar en el formato solicitado
        output_file = self.export_manager.export_report(
            rendered_content, output_dir, output_format, report_content["metadata"]
        )
        
        return output_file
    
    def _include_attachments(
        self,
        report_data: Dict[str, Any],
        output_dir: Path
    ) -> List[Dict[str, str]]:
        """Incluir archivos adjuntos relevantes.
        
        Args:
            report_data: Datos del reporte
            output_dir: Directorio de salida
            
        Returns:
            Lista de archivos adjuntos incluidos
        """
        attachments = []
        attachments_dir = output_dir / "attachments"
        attachments_dir.mkdir(exist_ok=True)
        
        # TODO: Implementar lógica para incluir archivos relevantes
        # Por ejemplo: logs importantes, capturas de pantalla, etc.
        
        return attachments
    
    def _estimate_page_count(self, file_path: Path, format_type: str) -> int:
        """Estimar número de páginas del reporte.
        
        Args:
            file_path: Ruta del archivo
            format_type: Tipo de formato
            
        Returns:
            Estimación del número de páginas
        """
        if not file_path.exists():
            return 0
        
        # Estimación básica basada en el tamaño del archivo
        file_size = file_path.stat().st_size
        
        if format_type == "pdf":
            # Aproximadamente 50KB por página para PDF
            return max(1, file_size // 51200)
        elif format_type in ["html", "markdown"]:
            # Aproximadamente 5KB por página para texto
            return max(1, file_size // 5120)
        else:
            return 1
    
    # Métodos auxiliares para recopilación de datos específicos
    def _collect_memory_analysis_data(self, memory_dir: Path) -> Dict[str, Any]:
        """Recopilar datos de análisis de memoria."""
        # TODO: Implementar recopilación de datos de memoria
        return {"status": "not_implemented"}
    
    def _collect_disk_analysis_data(self, disk_dir: Path) -> Dict[str, Any]:
        """Recopilar datos de análisis de disco."""
        # TODO: Implementar recopilación de datos de disco
        return {"status": "not_implemented"}
    
    def _collect_timeline_data(self, timeline_dir: Path) -> Dict[str, Any]:
        """Recopilar datos de timeline."""
        # TODO: Implementar recopilación de datos de timeline
        return {"status": "not_implemented"}
    
    def _collect_yara_data(self, yara_dir: Path) -> Dict[str, Any]:
        """Recopilar datos de análisis YARA."""
        # TODO: Implementar recopilación de datos YARA
        return {"status": "not_implemented"}
    
    def _collect_artifacts_data(self, artifacts_dir: Path) -> Dict[str, Any]:
        """Recopilar datos de artefactos."""
        # TODO: Implementar recopilación de datos de artefactos
        return {"status": "not_implemented"}
    
    def _extract_key_findings(self) -> List[Dict[str, Any]]:
        """Extraer hallazgos clave para reporte ejecutivo."""
        # TODO: Implementar extracción de hallazgos clave
        return []
    
    def _assess_risks(self) -> Dict[str, Any]:
        """Evaluar riesgos identificados."""
        # TODO: Implementar evaluación de riesgos
        return {"status": "not_implemented"}
    
    def _assess_business_impact(self) -> Dict[str, Any]:
        """Evaluar impacto en el negocio."""
        # TODO: Implementar evaluación de impacto
        return {"status": "not_implemented"}
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generar recomendaciones."""
        # TODO: Implementar generación de recomendaciones
        return []
    
    def _get_report_title(self, report_data: Dict[str, Any], language: str) -> str:
        """Obtener título del reporte."""
        case_info = report_data.get("case_info", {})
        case_id = case_info.get("case_id", self.case_id)
        
        if language == "es":
            return f"Reporte de Análisis Forense - Caso {case_id}"
        else:
            return f"Forensic Analysis Report - Case {case_id}"
    
    def _generate_section_content(
        self,
        section_name: str,
        report_data: Dict[str, Any],
        config: Dict[str, Any],
        language: str
    ) -> Dict[str, Any]:
        """Generar contenido de una sección específica."""
        # TODO: Implementar generación de contenido por sección
        return {
            "title": section_name.replace("_", " ").title(),
            "content": f"Contenido de {section_name} - Por implementar",
            "generated": True
        }
    
    def _process_timeline_file(
        self,
        timeline_file: Path,
        time_range: Optional[Dict[str, str]],
        event_types: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Procesar archivo de timeline."""
        # TODO: Implementar procesamiento de timeline
        return {"events": [], "status": "not_implemented"}
    
    def _generate_timeline_visualization(
        self,
        timeline_data: Dict[str, Any],
        output_dir: Path,
        output_format: str
    ) -> Path:
        """Generar visualización de timeline."""
        # TODO: Implementar visualización de timeline
        output_file = output_dir / f"timeline.{output_format}"
        output_file.write_text("Timeline visualization - Not implemented")
        return output_file
    
    def _perform_case_comparison(
        self,
        current_case: Dict[str, Any],
        baseline_case: Dict[str, Any],
        comparison_type: str
    ) -> Dict[str, Any]:
        """Realizar comparación entre casos."""
        # TODO: Implementar comparación de casos
        return {
            "differences_count": 0,
            "similarities_count": 0,
            "status": "not_implemented"
        }
    
    def _generate_comparison_output(
        self,
        comparison_data: Dict[str, Any],
        output_dir: Path,
        output_format: str
    ) -> Path:
        """Generar salida de comparación."""
        # TODO: Implementar generación de comparación
        output_file = output_dir / f"comparison.{output_format}"
        output_file.write_text("Comparison report - Not implemented")
        return output_file