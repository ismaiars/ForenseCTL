"""Gestión de evidencias forenses digitales."""

import hashlib
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from forensectl import config, logger
from .integrity import IntegrityVerifier
from .chain_of_custody import ChainOfCustody


class Evidence:
    """Clase para gestionar evidencias forenses digitales."""
    
    def __init__(
        self,
        case_id: str,
        evidence_id: Optional[str] = None,
        source_path: Optional[Union[str, Path]] = None,
        evidence_type: str = "unknown",
        description: str = "",
        examiner: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Inicializar evidencia.
        
        Args:
            case_id: ID del caso
            evidence_id: ID único de la evidencia (se genera si no se proporciona)
            source_path: Ruta del archivo/directorio de evidencia
            evidence_type: Tipo de evidencia (disk_image, memory_dump, file, etc.)
            description: Descripción de la evidencia
            examiner: Examinador responsable
            metadata: Metadatos adicionales
        """
        self.case_id = case_id
        self.evidence_id = evidence_id or str(uuid.uuid4())
        self.source_path = Path(source_path) if source_path else None
        self.evidence_type = evidence_type
        self.description = description
        self.examiner = examiner
        self.metadata = metadata or {}
        
        # Directorios del caso
        self.case_dir = config.CASES_DIR / case_id
        self.evidence_dir = self.case_dir / "evidence"
        self.manifests_dir = self.case_dir / "manifests"
        
        # Archivos específicos de esta evidencia
        self.evidence_manifest = self.manifests_dir / f"{self.evidence_id}_manifest.json"
        self.evidence_storage = self.evidence_dir / self.evidence_id
        
        # Crear directorios necesarios
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        
        # Inicializar herramientas
        self.integrity_verifier = IntegrityVerifier()
        self.chain_of_custody = ChainOfCustody(case_id)
        
        # Timestamps
        self.created_at = datetime.now(timezone.utc)
        self.last_accessed = None
        self.last_modified = None
    
    def acquire(
        self,
        preserve_original: bool = True,
        compression: bool = False,
        encryption: bool = False,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Adquirir evidencia desde la fuente.
        
        Args:
            preserve_original: Mantener archivo original
            compression: Comprimir evidencia
            encryption: Encriptar evidencia
            notes: Notas de adquisición
            
        Returns:
            Diccionario con información de adquisición
        """
        if not self.source_path or not self.source_path.exists():
            raise ValueError(f"Ruta de evidencia no válida: {self.source_path}")
        
        logger.info(f"Iniciando adquisición de evidencia {self.evidence_id}")
        
        # Crear directorio de almacenamiento
        self.evidence_storage.mkdir(parents=True, exist_ok=True)
        
        # Calcular hash original
        original_hash = self._calculate_hash(self.source_path)
        
        # Determinar ruta de destino
        if self.source_path.is_file():
            dest_path = self.evidence_storage / self.source_path.name
        else:
            dest_path = self.evidence_storage / "evidence_data"
        
        # Copiar evidencia
        acquisition_start = datetime.now(timezone.utc)
        
        try:
            if self.source_path.is_file():
                shutil.copy2(self.source_path, dest_path)
            else:
                shutil.copytree(self.source_path, dest_path, dirs_exist_ok=True)
            
            acquisition_end = datetime.now(timezone.utc)
            
            # Verificar integridad después de la copia
            copied_hash = self._calculate_hash(dest_path)
            
            if original_hash != copied_hash:
                raise ValueError("Fallo en verificación de integridad durante adquisición")
            
            # Aplicar compresión si se solicita
            if compression:
                dest_path = self._compress_evidence(dest_path)
            
            # Aplicar encriptación si se solicita
            if encryption:
                dest_path = self._encrypt_evidence(dest_path)
            
            # Crear manifiesto de evidencia
            manifest_data = self._create_manifest(
                dest_path, original_hash, acquisition_start, acquisition_end, notes
            )
            
            # Guardar manifiesto
            self._save_manifest(manifest_data)
            
            # Agregar entrada a cadena de custodia
            self.chain_of_custody.add_entry(
                action="evidence_acquired",
                description=f"Evidencia {self.evidence_type} adquirida: {self.description}",
                examiner=self.examiner,
                evidence_path=str(dest_path),
                evidence_hash=original_hash,
                notes=notes,
                metadata={
                    "evidence_id": self.evidence_id,
                    "source_path": str(self.source_path),
                    "acquisition_method": "file_copy",
                    "compression": compression,
                    "encryption": encryption
                }
            )
            
            # Remover original si no se debe preservar
            if not preserve_original and self.source_path != dest_path:
                if self.source_path.is_file():
                    self.source_path.unlink()
                else:
                    shutil.rmtree(self.source_path)
            
            logger.info(f"Evidencia {self.evidence_id} adquirida exitosamente")
            
            return {
                "evidence_id": self.evidence_id,
                "status": "acquired",
                "storage_path": str(dest_path),
                "original_hash": original_hash,
                "copied_hash": copied_hash,
                "acquisition_time": (acquisition_end - acquisition_start).total_seconds(),
                "manifest_path": str(self.evidence_manifest)
            }
            
        except Exception as e:
            logger.error(f"Error durante adquisición de evidencia {self.evidence_id}: {e}")
            
            # Limpiar en caso de error
            if self.evidence_storage.exists():
                shutil.rmtree(self.evidence_storage)
            
            raise
    
    def verify_integrity(self) -> Dict[str, Any]:
        """Verificar integridad de la evidencia.
        
        Returns:
            Resultado de verificación de integridad
        """
        if not self.evidence_manifest.exists():
            raise ValueError(f"Manifiesto de evidencia no encontrado: {self.evidence_manifest}")
        
        manifest_data = self._load_manifest()
        stored_evidence_path = Path(manifest_data["storage_path"])
        
        if not stored_evidence_path.exists():
            return {
                "valid": False,
                "error": f"Archivo de evidencia no encontrado: {stored_evidence_path}"
            }
        
        # Calcular hash actual
        current_hash = self._calculate_hash(stored_evidence_path)
        original_hash = manifest_data["original_hash"]
        
        # Verificar integridad
        integrity_valid = current_hash == original_hash
        
        verification_result = {
            "evidence_id": self.evidence_id,
            "valid": integrity_valid,
            "original_hash": original_hash,
            "current_hash": current_hash,
            "algorithm": manifest_data.get("hash_algorithm", "sha256"),
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "storage_path": str(stored_evidence_path)
        }
        
        # Agregar entrada a cadena de custodia
        self.chain_of_custody.add_entry(
            action="integrity_verified",
            description=f"Verificación de integridad: {'VÁLIDA' if integrity_valid else 'INVÁLIDA'}",
            examiner=self.examiner,
            evidence_path=str(stored_evidence_path),
            evidence_hash=current_hash,
            metadata={
                "evidence_id": self.evidence_id,
                "verification_result": integrity_valid,
                "hash_algorithm": manifest_data.get("hash_algorithm", "sha256")
            }
        )
        
        if integrity_valid:
            logger.info(f"Integridad de evidencia {self.evidence_id} verificada exitosamente")
        else:
            logger.error(f"Fallo en verificación de integridad para evidencia {self.evidence_id}")
        
        return verification_result
    
    def get_metadata(self) -> Dict[str, Any]:
        """Obtener metadatos completos de la evidencia.
        
        Returns:
            Diccionario con metadatos de la evidencia
        """
        if not self.evidence_manifest.exists():
            return {
                "evidence_id": self.evidence_id,
                "case_id": self.case_id,
                "evidence_type": self.evidence_type,
                "description": self.description,
                "examiner": self.examiner,
                "status": "not_acquired",
                "metadata": self.metadata
            }
        
        manifest_data = self._load_manifest()
        
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "examiner": self.examiner,
            "status": "acquired",
            "source_path": manifest_data.get("source_path"),
            "storage_path": manifest_data.get("storage_path"),
            "original_hash": manifest_data.get("original_hash"),
            "hash_algorithm": manifest_data.get("hash_algorithm"),
            "file_size": manifest_data.get("file_size"),
            "acquired_at": manifest_data.get("acquired_at"),
            "acquisition_duration": manifest_data.get("acquisition_duration"),
            "compression": manifest_data.get("compression", False),
            "encryption": manifest_data.get("encryption", False),
            "metadata": {**self.metadata, **manifest_data.get("metadata", {})}
        }
    
    def export_evidence(
        self,
        export_path: Path,
        include_manifest: bool = True,
        include_chain: bool = True
    ) -> Dict[str, Any]:
        """Exportar evidencia para transferencia.
        
        Args:
            export_path: Ruta de exportación
            include_manifest: Incluir manifiesto
            include_chain: Incluir cadena de custodia
            
        Returns:
            Información de exportación
        """
        if not self.evidence_storage.exists():
            raise ValueError(f"Evidencia no encontrada: {self.evidence_storage}")
        
        export_path = Path(export_path)
        export_path.mkdir(parents=True, exist_ok=True)
        
        # Copiar evidencia
        evidence_export = export_path / f"{self.evidence_id}_evidence"
        if self.evidence_storage.is_file():
            shutil.copy2(self.evidence_storage, evidence_export)
        else:
            shutil.copytree(self.evidence_storage, evidence_export, dirs_exist_ok=True)
        
        exported_files = [str(evidence_export)]
        
        # Incluir manifiesto
        if include_manifest and self.evidence_manifest.exists():
            manifest_export = export_path / f"{self.evidence_id}_manifest.json"
            shutil.copy2(self.evidence_manifest, manifest_export)
            exported_files.append(str(manifest_export))
        
        # Incluir cadena de custodia
        if include_chain:
            chain_export = export_path / f"{self.evidence_id}_chain.json"
            self.chain_of_custody.export_chain(chain_export, format="json")
            exported_files.append(str(chain_export))
        
        # Agregar entrada a cadena de custodia
        self.chain_of_custody.add_entry(
            action="evidence_exported",
            description=f"Evidencia exportada a {export_path}",
            examiner=self.examiner,
            evidence_path=str(evidence_export),
            metadata={
                "evidence_id": self.evidence_id,
                "export_path": str(export_path),
                "exported_files": exported_files,
                "include_manifest": include_manifest,
                "include_chain": include_chain
            }
        )
        
        logger.info(f"Evidencia {self.evidence_id} exportada a {export_path}")
        
        return {
            "evidence_id": self.evidence_id,
            "export_path": str(export_path),
            "exported_files": exported_files,
            "export_timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def delete_evidence(self, confirm: bool = False) -> bool:
        """Eliminar evidencia (requiere confirmación).
        
        Args:
            confirm: Confirmación de eliminación
            
        Returns:
            True si se eliminó exitosamente
        """
        if not confirm:
            logger.warning(f"Eliminación de evidencia {self.evidence_id} cancelada (falta confirmación)")
            return False
        
        try:
            # Agregar entrada a cadena de custodia antes de eliminar
            self.chain_of_custody.add_entry(
                action="evidence_deleted",
                description=f"Evidencia {self.evidence_id} eliminada",
                examiner=self.examiner,
                evidence_path=str(self.evidence_storage) if self.evidence_storage.exists() else "N/A",
                metadata={
                    "evidence_id": self.evidence_id,
                    "deletion_reason": "manual_deletion"
                }
            )
            
            # Eliminar archivos
            if self.evidence_storage.exists():
                if self.evidence_storage.is_file():
                    self.evidence_storage.unlink()
                else:
                    shutil.rmtree(self.evidence_storage)
            
            if self.evidence_manifest.exists():
                self.evidence_manifest.unlink()
            
            logger.info(f"Evidencia {self.evidence_id} eliminada exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"Error eliminando evidencia {self.evidence_id}: {e}")
            return False
    
    def _calculate_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Calcular hash de archivo o directorio.
        
        Args:
            file_path: Ruta del archivo/directorio
            algorithm: Algoritmo de hash
            
        Returns:
            Hash hexadecimal
        """
        if file_path.is_file():
            return self.integrity_verifier.calculate_hash(file_path, algorithm)
        else:
            # Para directorios, calcular hash combinado
            hasher = hashlib.new(algorithm)
            
            for file in sorted(file_path.rglob("*")):
                if file.is_file():
                    file_hash = self.integrity_verifier.calculate_hash(file, algorithm)
                    hasher.update(f"{file.relative_to(file_path)}:{file_hash}".encode())
            
            return hasher.hexdigest()
    
    def _compress_evidence(self, evidence_path: Path) -> Path:
        """Comprimir evidencia.
        
        Args:
            evidence_path: Ruta de la evidencia
            
        Returns:
            Ruta del archivo comprimido
        """
        import tarfile
        
        compressed_path = evidence_path.with_suffix(".tar.gz")
        
        with tarfile.open(compressed_path, "w:gz") as tar:
            tar.add(evidence_path, arcname=evidence_path.name)
        
        # Eliminar original no comprimido
        if evidence_path.is_file():
            evidence_path.unlink()
        else:
            shutil.rmtree(evidence_path)
        
        logger.info(f"Evidencia comprimida: {compressed_path}")
        return compressed_path
    
    def _encrypt_evidence(self, evidence_path: Path) -> Path:
        """Encriptar evidencia.
        
        Args:
            evidence_path: Ruta de la evidencia
            
        Returns:
            Ruta del archivo encriptado
        """
        # TODO: Implementar encriptación real
        # Por ahora, solo simular el proceso
        encrypted_path = evidence_path.with_suffix(evidence_path.suffix + ".enc")
        shutil.move(evidence_path, encrypted_path)
        
        logger.warning(f"Encriptación simulada: {encrypted_path} (implementar encriptación real)")
        return encrypted_path
    
    def _create_manifest(
        self,
        storage_path: Path,
        original_hash: str,
        acquisition_start: datetime,
        acquisition_end: datetime,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Crear manifiesto de evidencia.
        
        Args:
            storage_path: Ruta de almacenamiento
            original_hash: Hash original
            acquisition_start: Inicio de adquisición
            acquisition_end: Fin de adquisición
            notes: Notas adicionales
            
        Returns:
            Datos del manifiesto
        """
        file_size = 0
        if storage_path.is_file():
            file_size = storage_path.stat().st_size
        else:
            file_size = sum(f.stat().st_size for f in storage_path.rglob("*") if f.is_file())
        
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "examiner": self.examiner,
            "source_path": str(self.source_path),
            "storage_path": str(storage_path),
            "original_hash": original_hash,
            "hash_algorithm": "sha256",
            "file_size": file_size,
            "acquired_at": acquisition_start.isoformat(),
            "acquisition_duration": (acquisition_end - acquisition_start).total_seconds(),
            "notes": notes,
            "metadata": self.metadata,
            "forensectl_version": "0.1.0",
            "manifest_version": "1.0"
        }
    
    def _save_manifest(self, manifest_data: Dict[str, Any]) -> None:
        """Guardar manifiesto de evidencia.
        
        Args:
            manifest_data: Datos del manifiesto
        """
        with open(self.evidence_manifest, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2, ensure_ascii=False)
    
    def _load_manifest(self) -> Dict[str, Any]:
        """Cargar manifiesto de evidencia.
        
        Returns:
            Datos del manifiesto
        """
        with open(self.evidence_manifest, "r", encoding="utf-8") as f:
            return json.load(f)
    
    @classmethod
    def load_from_manifest(cls, case_id: str, evidence_id: str) -> "Evidence":
        """Cargar evidencia desde manifiesto existente.
        
        Args:
            case_id: ID del caso
            evidence_id: ID de la evidencia
            
        Returns:
            Instancia de Evidence
        """
        manifests_dir = config.CASES_DIR / case_id / "manifests"
        manifest_file = manifests_dir / f"{evidence_id}_manifest.json"
        
        if not manifest_file.exists():
            raise ValueError(f"Manifiesto no encontrado: {manifest_file}")
        
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
        
        evidence = cls(
            case_id=case_id,
            evidence_id=evidence_id,
            source_path=manifest_data.get("source_path"),
            evidence_type=manifest_data.get("evidence_type", "unknown"),
            description=manifest_data.get("description", ""),
            examiner=manifest_data.get("examiner", ""),
            metadata=manifest_data.get("metadata", {})
        )
        
        return evidence
    
    @classmethod
    def list_case_evidence(cls, case_id: str) -> List[Dict[str, Any]]:
        """Listar todas las evidencias de un caso.
        
        Args:
            case_id: ID del caso
            
        Returns:
            Lista de metadatos de evidencias
        """
        manifests_dir = config.CASES_DIR / case_id / "manifests"
        
        if not manifests_dir.exists():
            return []
        
        evidence_list = []
        
        for manifest_file in manifests_dir.glob("*_manifest.json"):
            try:
                evidence_id = manifest_file.stem.replace("_manifest", "")
                evidence = cls.load_from_manifest(case_id, evidence_id)
                evidence_list.append(evidence.get_metadata())
            except Exception as e:
                logger.error(f"Error cargando evidencia desde {manifest_file}: {e}")
        
        return evidence_list