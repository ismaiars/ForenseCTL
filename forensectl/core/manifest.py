"""Gestión de manifiestos forenses para casos y evidencias."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from forensectl import config, logger


class Manifest:
    """Gestor de manifiestos forenses para casos y evidencias."""
    
    def __init__(self, case_id: str, manifest_type: str = "case") -> None:
        """Inicializar gestor de manifiestos.
        
        Args:
            case_id: Identificador del caso
            manifest_type: Tipo de manifiesto ('case', 'evidence', 'analysis')
        """
        self.case_id = case_id
        self.manifest_type = manifest_type
        self.case_dir = config.CASES_DIR / case_id
        self.manifests_dir = self.case_dir / "manifests"
        
        # Crear directorio si no existe
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        
        # Archivo de manifiesto principal del caso
        self.case_manifest_file = self.manifests_dir / "case_manifest.json"
        
        # Inicializar manifiesto del caso si no existe
        if manifest_type == "case" and not self.case_manifest_file.exists():
            self._initialize_case_manifest()
    
    def _initialize_case_manifest(self) -> None:
        """Inicializar manifiesto principal del caso."""
        manifest_data = {
            "manifest_id": str(uuid.uuid4()),
            "case_id": self.case_id,
            "manifest_type": "case",
            "version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "forensectl_version": "0.1.0",
            "case_info": {
                "status": "active",
                "evidence_count": 0,
                "analysis_count": 0,
                "report_count": 0
            },
            "evidence_registry": [],
            "analysis_registry": [],
            "report_registry": [],
            "integrity_checks": [],
            "metadata": {}
        }
        
        self._save_manifest(self.case_manifest_file, manifest_data)
        logger.info(f"Manifiesto del caso {self.case_id} inicializado")
    
    def register_evidence(
        self,
        evidence_id: str,
        evidence_type: str,
        source_path: str,
        storage_path: str,
        hash_value: str,
        hash_algorithm: str = "sha256",
        file_size: int = 0,
        examiner: str = "",
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Registrar evidencia en el manifiesto del caso.
        
        Args:
            evidence_id: ID único de la evidencia
            evidence_type: Tipo de evidencia
            source_path: Ruta original
            storage_path: Ruta de almacenamiento
            hash_value: Hash de la evidencia
            hash_algorithm: Algoritmo de hash usado
            file_size: Tamaño del archivo
            examiner: Examinador responsable
            description: Descripción de la evidencia
            metadata: Metadatos adicionales
        """
        case_manifest = self._load_manifest(self.case_manifest_file)
        
        evidence_entry = {
            "evidence_id": evidence_id,
            "evidence_type": evidence_type,
            "source_path": source_path,
            "storage_path": storage_path,
            "hash_value": hash_value,
            "hash_algorithm": hash_algorithm,
            "file_size": file_size,
            "examiner": examiner,
            "description": description,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "status": "acquired",
            "metadata": metadata or {}
        }
        
        # Verificar si ya existe
        existing_index = None
        for i, entry in enumerate(case_manifest["evidence_registry"]):
            if entry["evidence_id"] == evidence_id:
                existing_index = i
                break
        
        if existing_index is not None:
            # Actualizar entrada existente
            case_manifest["evidence_registry"][existing_index] = evidence_entry
            logger.info(f"Evidencia {evidence_id} actualizada en manifiesto")
        else:
            # Agregar nueva entrada
            case_manifest["evidence_registry"].append(evidence_entry)
            case_manifest["case_info"]["evidence_count"] += 1
            logger.info(f"Evidencia {evidence_id} registrada en manifiesto")
        
        # Actualizar timestamp
        case_manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        self._save_manifest(self.case_manifest_file, case_manifest)
    
    def register_analysis(
        self,
        analysis_id: str,
        analysis_type: str,
        evidence_id: str,
        tool_name: str,
        tool_version: str,
        output_path: str,
        examiner: str = "",
        description: str = "",
        parameters: Optional[Dict[str, Any]] = None,
        results_summary: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Registrar análisis en el manifiesto del caso.
        
        Args:
            analysis_id: ID único del análisis
            analysis_type: Tipo de análisis
            evidence_id: ID de la evidencia analizada
            tool_name: Nombre de la herramienta
            tool_version: Versión de la herramienta
            output_path: Ruta de salida del análisis
            examiner: Examinador responsable
            description: Descripción del análisis
            parameters: Parámetros usados
            results_summary: Resumen de resultados
            metadata: Metadatos adicionales
        """
        case_manifest = self._load_manifest(self.case_manifest_file)
        
        analysis_entry = {
            "analysis_id": analysis_id,
            "analysis_type": analysis_type,
            "evidence_id": evidence_id,
            "tool_name": tool_name,
            "tool_version": tool_version,
            "output_path": output_path,
            "examiner": examiner,
            "description": description,
            "parameters": parameters or {},
            "results_summary": results_summary or {},
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "metadata": metadata or {}
        }
        
        # Verificar si ya existe
        existing_index = None
        for i, entry in enumerate(case_manifest["analysis_registry"]):
            if entry["analysis_id"] == analysis_id:
                existing_index = i
                break
        
        if existing_index is not None:
            # Actualizar entrada existente
            case_manifest["analysis_registry"][existing_index] = analysis_entry
            logger.info(f"Análisis {analysis_id} actualizado en manifiesto")
        else:
            # Agregar nueva entrada
            case_manifest["analysis_registry"].append(analysis_entry)
            case_manifest["case_info"]["analysis_count"] += 1
            logger.info(f"Análisis {analysis_id} registrado en manifiesto")
        
        # Actualizar timestamp
        case_manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        self._save_manifest(self.case_manifest_file, case_manifest)
    
    def register_report(
        self,
        report_id: str,
        report_type: str,
        report_format: str,
        output_path: str,
        examiner: str = "",
        description: str = "",
        evidence_ids: Optional[List[str]] = None,
        analysis_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Registrar reporte en el manifiesto del caso.
        
        Args:
            report_id: ID único del reporte
            report_type: Tipo de reporte
            report_format: Formato del reporte
            output_path: Ruta de salida del reporte
            examiner: Examinador responsable
            description: Descripción del reporte
            evidence_ids: IDs de evidencias incluidas
            analysis_ids: IDs de análisis incluidos
            metadata: Metadatos adicionales
        """
        case_manifest = self._load_manifest(self.case_manifest_file)
        
        report_entry = {
            "report_id": report_id,
            "report_type": report_type,
            "report_format": report_format,
            "output_path": output_path,
            "examiner": examiner,
            "description": description,
            "evidence_ids": evidence_ids or [],
            "analysis_ids": analysis_ids or [],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "generated",
            "metadata": metadata or {}
        }
        
        # Verificar si ya existe
        existing_index = None
        for i, entry in enumerate(case_manifest["report_registry"]):
            if entry["report_id"] == report_id:
                existing_index = i
                break
        
        if existing_index is not None:
            # Actualizar entrada existente
            case_manifest["report_registry"][existing_index] = report_entry
            logger.info(f"Reporte {report_id} actualizado en manifiesto")
        else:
            # Agregar nueva entrada
            case_manifest["report_registry"].append(report_entry)
            case_manifest["case_info"]["report_count"] += 1
            logger.info(f"Reporte {report_id} registrado en manifiesto")
        
        # Actualizar timestamp
        case_manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        self._save_manifest(self.case_manifest_file, case_manifest)
    
    def add_integrity_check(
        self,
        target_path: str,
        target_type: str,
        hash_value: str,
        hash_algorithm: str = "sha256",
        verification_result: bool = True,
        examiner: str = "",
        notes: Optional[str] = None
    ) -> None:
        """Agregar verificación de integridad al manifiesto.
        
        Args:
            target_path: Ruta del objetivo verificado
            target_type: Tipo de objetivo ('evidence', 'analysis', 'report')
            hash_value: Hash calculado
            hash_algorithm: Algoritmo de hash
            verification_result: Resultado de la verificación
            examiner: Examinador responsable
            notes: Notas adicionales
        """
        case_manifest = self._load_manifest(self.case_manifest_file)
        
        integrity_entry = {
            "check_id": str(uuid.uuid4()),
            "target_path": target_path,
            "target_type": target_type,
            "hash_value": hash_value,
            "hash_algorithm": hash_algorithm,
            "verification_result": verification_result,
            "examiner": examiner,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "notes": notes
        }
        
        case_manifest["integrity_checks"].append(integrity_entry)
        case_manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        self._save_manifest(self.case_manifest_file, case_manifest)
        
        status = "VÁLIDA" if verification_result else "INVÁLIDA"
        logger.info(f"Verificación de integridad registrada: {target_path} - {status}")
    
    def get_case_summary(self) -> Dict[str, Any]:
        """Obtener resumen del caso desde el manifiesto.
        
        Returns:
            Diccionario con resumen del caso
        """
        if not self.case_manifest_file.exists():
            return {
                "case_id": self.case_id,
                "status": "not_initialized",
                "error": "Manifiesto del caso no encontrado"
            }
        
        case_manifest = self._load_manifest(self.case_manifest_file)
        
        # Calcular estadísticas adicionales
        evidence_types = {}
        analysis_types = {}
        report_types = {}
        
        for evidence in case_manifest.get("evidence_registry", []):
            evidence_type = evidence.get("evidence_type", "unknown")
            evidence_types[evidence_type] = evidence_types.get(evidence_type, 0) + 1
        
        for analysis in case_manifest.get("analysis_registry", []):
            analysis_type = analysis.get("analysis_type", "unknown")
            analysis_types[analysis_type] = analysis_types.get(analysis_type, 0) + 1
        
        for report in case_manifest.get("report_registry", []):
            report_type = report.get("report_type", "unknown")
            report_types[report_type] = report_types.get(report_type, 0) + 1
        
        # Verificaciones de integridad
        integrity_stats = {
            "total_checks": len(case_manifest.get("integrity_checks", [])),
            "passed_checks": sum(1 for check in case_manifest.get("integrity_checks", []) 
                                if check.get("verification_result", False)),
            "failed_checks": sum(1 for check in case_manifest.get("integrity_checks", []) 
                                if not check.get("verification_result", True))
        }
        
        return {
            "case_id": self.case_id,
            "manifest_id": case_manifest.get("manifest_id"),
            "version": case_manifest.get("version"),
            "created_at": case_manifest.get("created_at"),
            "last_updated": case_manifest.get("last_updated"),
            "case_info": case_manifest.get("case_info", {}),
            "statistics": {
                "evidence_types": evidence_types,
                "analysis_types": analysis_types,
                "report_types": report_types,
                "integrity_checks": integrity_stats
            },
            "metadata": case_manifest.get("metadata", {})
        }
    
    def get_evidence_list(self) -> List[Dict[str, Any]]:
        """Obtener lista de evidencias registradas.
        
        Returns:
            Lista de evidencias
        """
        if not self.case_manifest_file.exists():
            return []
        
        case_manifest = self._load_manifest(self.case_manifest_file)
        return case_manifest.get("evidence_registry", [])
    
    def get_analysis_list(self) -> List[Dict[str, Any]]:
        """Obtener lista de análisis registrados.
        
        Returns:
            Lista de análisis
        """
        if not self.case_manifest_file.exists():
            return []
        
        case_manifest = self._load_manifest(self.case_manifest_file)
        return case_manifest.get("analysis_registry", [])
    
    def get_report_list(self) -> List[Dict[str, Any]]:
        """Obtener lista de reportes registrados.
        
        Returns:
            Lista de reportes
        """
        if not self.case_manifest_file.exists():
            return []
        
        case_manifest = self._load_manifest(self.case_manifest_file)
        return case_manifest.get("report_registry", [])
    
    def get_integrity_checks(self) -> List[Dict[str, Any]]:
        """Obtener lista de verificaciones de integridad.
        
        Returns:
            Lista de verificaciones
        """
        if not self.case_manifest_file.exists():
            return []
        
        case_manifest = self._load_manifest(self.case_manifest_file)
        return case_manifest.get("integrity_checks", [])
    
    def update_case_metadata(self, metadata: Dict[str, Any]) -> None:
        """Actualizar metadatos del caso.
        
        Args:
            metadata: Nuevos metadatos
        """
        case_manifest = self._load_manifest(self.case_manifest_file)
        
        # Fusionar metadatos existentes con nuevos
        current_metadata = case_manifest.get("metadata", {})
        current_metadata.update(metadata)
        
        case_manifest["metadata"] = current_metadata
        case_manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        self._save_manifest(self.case_manifest_file, case_manifest)
        logger.info(f"Metadatos del caso {self.case_id} actualizados")
    
    def update_case_status(self, status: str) -> None:
        """Actualizar estado del caso.
        
        Args:
            status: Nuevo estado ('active', 'closed', 'archived')
        """
        case_manifest = self._load_manifest(self.case_manifest_file)
        
        case_manifest["case_info"]["status"] = status
        case_manifest["case_info"]["status_updated_at"] = datetime.now(timezone.utc).isoformat()
        case_manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        self._save_manifest(self.case_manifest_file, case_manifest)
        logger.info(f"Estado del caso {self.case_id} actualizado a: {status}")
    
    def export_manifest(
        self,
        output_path: Path,
        format: str = "json",
        include_integrity: bool = True
    ) -> None:
        """Exportar manifiesto del caso.
        
        Args:
            output_path: Ruta de salida
            format: Formato de exportación ('json', 'csv')
            include_integrity: Incluir verificaciones de integridad
        """
        case_manifest = self._load_manifest(self.case_manifest_file)
        
        if not include_integrity:
            case_manifest.pop("integrity_checks", None)
        
        if format.lower() == "json":
            self._export_json(case_manifest, output_path)
        elif format.lower() == "csv":
            self._export_csv(case_manifest, output_path)
        else:
            raise ValueError(f"Formato de exportación no soportado: {format}")
        
        logger.info(f"Manifiesto del caso exportado a {output_path}")
    
    def validate_manifest(self) -> Dict[str, Any]:
        """Validar integridad del manifiesto.
        
        Returns:
            Resultado de validación
        """
        try:
            if not self.case_manifest_file.exists():
                return {
                    "valid": False,
                    "errors": ["Archivo de manifiesto no encontrado"],
                    "warnings": []
                }
            
            case_manifest = self._load_manifest(self.case_manifest_file)
            
            validation_result = {
                "valid": True,
                "errors": [],
                "warnings": []
            }
            
            # Verificar campos requeridos
            required_fields = ["manifest_id", "case_id", "version", "created_at"]
            for field in required_fields:
                if field not in case_manifest:
                    validation_result["errors"].append(f"Campo requerido faltante: {field}")
                    validation_result["valid"] = False
            
            # Verificar estructura de registros
            for evidence in case_manifest.get("evidence_registry", []):
                if "evidence_id" not in evidence:
                    validation_result["errors"].append("Evidencia sin ID encontrada")
                    validation_result["valid"] = False
            
            for analysis in case_manifest.get("analysis_registry", []):
                if "analysis_id" not in analysis:
                    validation_result["errors"].append("Análisis sin ID encontrado")
                    validation_result["valid"] = False
            
            for report in case_manifest.get("report_registry", []):
                if "report_id" not in report:
                    validation_result["errors"].append("Reporte sin ID encontrado")
                    validation_result["valid"] = False
            
            # Verificar consistencia de contadores
            case_info = case_manifest.get("case_info", {})
            actual_evidence_count = len(case_manifest.get("evidence_registry", []))
            actual_analysis_count = len(case_manifest.get("analysis_registry", []))
            actual_report_count = len(case_manifest.get("report_registry", []))
            
            if case_info.get("evidence_count", 0) != actual_evidence_count:
                validation_result["warnings"].append(
                    f"Contador de evidencias inconsistente: {case_info.get('evidence_count')} vs {actual_evidence_count}"
                )
            
            if case_info.get("analysis_count", 0) != actual_analysis_count:
                validation_result["warnings"].append(
                    f"Contador de análisis inconsistente: {case_info.get('analysis_count')} vs {actual_analysis_count}"
                )
            
            if case_info.get("report_count", 0) != actual_report_count:
                validation_result["warnings"].append(
                    f"Contador de reportes inconsistente: {case_info.get('report_count')} vs {actual_report_count}"
                )
            
            logger.info(f"Validación de manifiesto completada: {validation_result['valid']}")
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validando manifiesto: {e}")
            return {
                "valid": False,
                "errors": [f"Error de validación: {e}"],
                "warnings": []
            }
    
    def _save_manifest(self, file_path: Path, manifest_data: Dict[str, Any]) -> None:
        """Guardar datos de manifiesto.
        
        Args:
            file_path: Ruta del archivo
            manifest_data: Datos del manifiesto
        """
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2, ensure_ascii=False)
        except IOError as e:
            logger.error(f"Error guardando manifiesto: {e}")
            raise
    
    def _load_manifest(self, file_path: Path) -> Dict[str, Any]:
        """Cargar datos de manifiesto.
        
        Args:
            file_path: Ruta del archivo
            
        Returns:
            Datos del manifiesto
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error cargando manifiesto: {e}")
            raise
    
    def _export_json(self, manifest_data: Dict[str, Any], output_path: Path) -> None:
        """Exportar manifiesto en formato JSON.
        
        Args:
            manifest_data: Datos del manifiesto
            output_path: Ruta de salida
        """
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2, ensure_ascii=False)
    
    def _export_csv(self, manifest_data: Dict[str, Any], output_path: Path) -> None:
        """Exportar manifiesto en formato CSV.
        
        Args:
            manifest_data: Datos del manifiesto
            output_path: Ruta de salida
        """
        import csv
        
        # Crear archivo CSV con múltiples hojas (archivos separados)
        base_path = output_path.with_suffix("")
        
        # Exportar evidencias
        evidence_file = base_path.with_name(f"{base_path.name}_evidence.csv")
        with open(evidence_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Evidence ID", "Type", "Source Path", "Storage Path", "Hash", "Size", "Examiner", "Registered At"])
            
            for evidence in manifest_data.get("evidence_registry", []):
                writer.writerow([
                    evidence.get("evidence_id", ""),
                    evidence.get("evidence_type", ""),
                    evidence.get("source_path", ""),
                    evidence.get("storage_path", ""),
                    evidence.get("hash_value", ""),
                    evidence.get("file_size", ""),
                    evidence.get("examiner", ""),
                    evidence.get("registered_at", "")
                ])
        
        # Exportar análisis
        analysis_file = base_path.with_name(f"{base_path.name}_analysis.csv")
        with open(analysis_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Analysis ID", "Type", "Evidence ID", "Tool", "Version", "Output Path", "Examiner", "Started At"])
            
            for analysis in manifest_data.get("analysis_registry", []):
                writer.writerow([
                    analysis.get("analysis_id", ""),
                    analysis.get("analysis_type", ""),
                    analysis.get("evidence_id", ""),
                    analysis.get("tool_name", ""),
                    analysis.get("tool_version", ""),
                    analysis.get("output_path", ""),
                    analysis.get("examiner", ""),
                    analysis.get("started_at", "")
                ])
        
        # Exportar reportes
        reports_file = base_path.with_name(f"{base_path.name}_reports.csv")
        with open(reports_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Report ID", "Type", "Format", "Output Path", "Examiner", "Generated At"])
            
            for report in manifest_data.get("report_registry", []):
                writer.writerow([
                    report.get("report_id", ""),
                    report.get("report_type", ""),
                    report.get("report_format", ""),
                    report.get("output_path", ""),
                    report.get("examiner", ""),
                    report.get("generated_at", "")
                ])