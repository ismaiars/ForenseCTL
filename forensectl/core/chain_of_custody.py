"""Gestor de cadena de custodia para evidencias forenses."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from forensectl import config, logger


class ChainOfCustody:
    """Gestor de cadena de custodia para evidencias forenses."""
    
    def __init__(self, case_id: str) -> None:
        """Inicializar gestor de cadena de custodia.
        
        Args:
            case_id: Identificador del caso
        """
        self.case_id = case_id
        self.case_dir = config.CASES_DIR / case_id
        self.chain_dir = self.case_dir / "chain"
        self.chain_file = self.chain_dir / "chain_of_custody.json"
        
        # Crear directorio si no existe
        self.chain_dir.mkdir(parents=True, exist_ok=True)
        
        # Inicializar archivo de cadena si no existe
        if not self.chain_file.exists():
            self._initialize_chain()
    
    def _initialize_chain(self) -> None:
        """Inicializar archivo de cadena de custodia."""
        initial_chain = {
            "case_id": self.case_id,
            "chain_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "entries": [],
            "metadata": {
                "forensectl_version": "0.1.0",
                "chain_format": "forensectl-v1",
                "last_modified": datetime.now(timezone.utc).isoformat()
            }
        }
        
        with open(self.chain_file, "w", encoding="utf-8") as f:
            json.dump(initial_chain, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Cadena de custodia inicializada para caso {self.case_id}")
    
    def add_entry(
        self,
        action: str,
        description: str,
        examiner: str,
        evidence_path: Optional[str] = None,
        evidence_hash: Optional[str] = None,
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Agregar entrada a la cadena de custodia.
        
        Args:
            action: Acción realizada (ej: 'evidence_acquired', 'analysis_started')
            description: Descripción de la acción
            examiner: Nombre del examinador
            evidence_path: Ruta de la evidencia (opcional)
            evidence_hash: Hash de la evidencia (opcional)
            notes: Notas adicionales (opcional)
            metadata: Metadatos adicionales (opcional)
            
        Returns:
            ID único de la entrada
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        entry = {
            "entry_id": entry_id,
            "timestamp": timestamp,
            "action": action,
            "description": description,
            "examiner": examiner,
            "evidence_path": evidence_path,
            "evidence_hash": evidence_hash,
            "notes": notes,
            "metadata": metadata or {},
            "system_info": self._get_system_info()
        }
        
        # Cargar cadena actual
        chain_data = self._load_chain()
        
        # Agregar nueva entrada
        chain_data["entries"].append(entry)
        chain_data["metadata"]["last_modified"] = timestamp
        chain_data["metadata"]["total_entries"] = len(chain_data["entries"])
        
        # Guardar cadena actualizada
        self._save_chain(chain_data)
        
        logger.info(f"Entrada agregada a cadena de custodia: {action} por {examiner}")
        return entry_id
    
    def get_entries(
        self, 
        action_filter: Optional[str] = None,
        examiner_filter: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Obtener entradas de la cadena de custodia.
        
        Args:
            action_filter: Filtrar por tipo de acción
            examiner_filter: Filtrar por examinador
            limit: Límite de entradas a retornar
            
        Returns:
            Lista de entradas filtradas
        """
        chain_data = self._load_chain()
        entries = chain_data["entries"]
        
        # Aplicar filtros
        if action_filter:
            entries = [e for e in entries if e["action"] == action_filter]
        
        if examiner_filter:
            entries = [e for e in entries if e["examiner"] == examiner_filter]
        
        # Ordenar por timestamp (más recientes primero)
        entries.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Aplicar límite
        if limit:
            entries = entries[:limit]
        
        return entries
    
    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Obtener entrada específica por ID.
        
        Args:
            entry_id: ID de la entrada
            
        Returns:
            Entrada o None si no se encuentra
        """
        chain_data = self._load_chain()
        
        for entry in chain_data["entries"]:
            if entry["entry_id"] == entry_id:
                return entry
        
        return None
    
    def update_entry(
        self, 
        entry_id: str, 
        updates: Dict[str, Any],
        examiner: str
    ) -> bool:
        """Actualizar entrada existente.
        
        Args:
            entry_id: ID de la entrada
            updates: Campos a actualizar
            examiner: Examinador que realiza la actualización
            
        Returns:
            True si se actualizó exitosamente
        """
        chain_data = self._load_chain()
        
        for entry in chain_data["entries"]:
            if entry["entry_id"] == entry_id:
                # Crear entrada de auditoría
                audit_entry = {
                    "original_entry_id": entry_id,
                    "updated_by": examiner,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "changes": updates,
                    "original_values": {k: entry.get(k) for k in updates.keys()}
                }
                
                # Actualizar entrada
                entry.update(updates)
                entry["last_modified"] = datetime.now(timezone.utc).isoformat()
                entry["modified_by"] = examiner
                
                # Agregar auditoría
                if "audit_trail" not in entry:
                    entry["audit_trail"] = []
                entry["audit_trail"].append(audit_entry)
                
                # Guardar cambios
                chain_data["metadata"]["last_modified"] = datetime.now(timezone.utc).isoformat()
                self._save_chain(chain_data)
                
                logger.info(f"Entrada {entry_id} actualizada por {examiner}")
                return True
        
        logger.warning(f"Entrada {entry_id} no encontrada para actualización")
        return False
    
    def sign_entry(self, entry_id: str, signature: str, signer: str) -> bool:
        """Firmar entrada de cadena de custodia.
        
        Args:
            entry_id: ID de la entrada
            signature: Firma digital
            signer: Firmante
            
        Returns:
            True si se firmó exitosamente
        """
        chain_data = self._load_chain()
        
        for entry in chain_data["entries"]:
            if entry["entry_id"] == entry_id:
                if "signatures" not in entry:
                    entry["signatures"] = []
                
                signature_entry = {
                    "signature": signature,
                    "signer": signer,
                    "signed_at": datetime.now(timezone.utc).isoformat(),
                    "algorithm": "digital_signature"  # Placeholder
                }
                
                entry["signatures"].append(signature_entry)
                
                # Guardar cambios
                chain_data["metadata"]["last_modified"] = datetime.now(timezone.utc).isoformat()
                self._save_chain(chain_data)
                
                logger.info(f"Entrada {entry_id} firmada por {signer}")
                return True
        
        logger.warning(f"Entrada {entry_id} no encontrada para firma")
        return False
    
    def export_chain(
        self, 
        output_path: Path, 
        format: str = "json",
        include_signatures: bool = True
    ) -> None:
        """Exportar cadena de custodia.
        
        Args:
            output_path: Ruta de salida
            format: Formato de exportación ('json', 'csv', 'pdf')
            include_signatures: Incluir firmas en la exportación
        """
        chain_data = self._load_chain()
        
        if not include_signatures:
            # Remover firmas para exportación pública
            for entry in chain_data["entries"]:
                entry.pop("signatures", None)
        
        if format.lower() == "json":
            self._export_json(chain_data, output_path)
        elif format.lower() == "csv":
            self._export_csv(chain_data, output_path)
        elif format.lower() == "pdf":
            self._export_pdf(chain_data, output_path)
        else:
            raise ValueError(f"Formato de exportación no soportado: {format}")
        
        logger.info(f"Cadena de custodia exportada a {output_path}")
    
    def validate_chain(self) -> Dict[str, Any]:
        """Validar integridad de la cadena de custodia.
        
        Returns:
            Diccionario con resultado de validación
        """
        try:
            chain_data = self._load_chain()
            
            validation_result = {
                "valid": True,
                "errors": [],
                "warnings": [],
                "statistics": {
                    "total_entries": len(chain_data["entries"]),
                    "signed_entries": 0,
                    "examiners": set(),
                    "date_range": None
                }
            }
            
            entries = chain_data["entries"]
            
            if not entries:
                validation_result["warnings"].append("Cadena de custodia vacía")
                return validation_result
            
            # Validar estructura de entradas
            required_fields = ["entry_id", "timestamp", "action", "description", "examiner"]
            
            for i, entry in enumerate(entries):
                # Verificar campos requeridos
                for field in required_fields:
                    if field not in entry or not entry[field]:
                        validation_result["errors"].append(
                            f"Entrada {i}: Campo requerido '{field}' faltante o vacío"
                        )
                        validation_result["valid"] = False
                
                # Verificar formato de timestamp
                try:
                    datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
                except (ValueError, KeyError):
                    validation_result["errors"].append(
                        f"Entrada {i}: Timestamp inválido"
                    )
                    validation_result["valid"] = False
                
                # Estadísticas
                if "signatures" in entry and entry["signatures"]:
                    validation_result["statistics"]["signed_entries"] += 1
                
                if "examiner" in entry:
                    validation_result["statistics"]["examiners"].add(entry["examiner"])
            
            # Calcular rango de fechas
            timestamps = [e["timestamp"] for e in entries if "timestamp" in e]
            if timestamps:
                validation_result["statistics"]["date_range"] = {
                    "start": min(timestamps),
                    "end": max(timestamps)
                }
            
            # Convertir set a lista para serialización JSON
            validation_result["statistics"]["examiners"] = list(
                validation_result["statistics"]["examiners"]
            )
            
            logger.info(f"Validación de cadena completada: {validation_result['valid']}")
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validando cadena de custodia: {e}")
            return {
                "valid": False,
                "errors": [f"Error de validación: {e}"],
                "warnings": [],
                "statistics": {}
            }
    
    def _load_chain(self) -> Dict[str, Any]:
        """Cargar datos de cadena de custodia."""
        try:
            with open(self.chain_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error cargando cadena de custodia: {e}")
            raise
    
    def _save_chain(self, chain_data: Dict[str, Any]) -> None:
        """Guardar datos de cadena de custodia."""
        try:
            with open(self.chain_file, "w", encoding="utf-8") as f:
                json.dump(chain_data, f, indent=2, ensure_ascii=False)
        except IOError as e:
            logger.error(f"Error guardando cadena de custodia: {e}")
            raise
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Obtener información del sistema."""
        import platform
        import getpass
        
        return {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "user": getpass.getuser(),
            "python_version": platform.python_version(),
            "forensectl_version": "0.1.0"
        }
    
    def _export_json(self, chain_data: Dict[str, Any], output_path: Path) -> None:
        """Exportar cadena en formato JSON."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(chain_data, f, indent=2, ensure_ascii=False)
    
    def _export_csv(self, chain_data: Dict[str, Any], output_path: Path) -> None:
        """Exportar cadena en formato CSV."""
        import csv
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            
            # Encabezados
            headers = [
                "Entry ID", "Timestamp", "Action", "Description", 
                "Examiner", "Evidence Path", "Evidence Hash", "Notes"
            ]
            writer.writerow(headers)
            
            # Datos
            for entry in chain_data["entries"]:
                row = [
                    entry.get("entry_id", ""),
                    entry.get("timestamp", ""),
                    entry.get("action", ""),
                    entry.get("description", ""),
                    entry.get("examiner", ""),
                    entry.get("evidence_path", ""),
                    entry.get("evidence_hash", ""),
                    entry.get("notes", "")
                ]
                writer.writerow(row)
    
    def _export_pdf(self, chain_data: Dict[str, Any], output_path: Path) -> None:
        """Exportar cadena en formato PDF."""
        # TODO: Implementar exportación PDF
        # Requiere reportlab o similar
        logger.warning("Exportación PDF no implementada aún")
        raise NotImplementedError("Exportación PDF pendiente de implementación")