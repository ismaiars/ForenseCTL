"""Verificador de integridad para evidencias forenses."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from forensectl import config, logger


class IntegrityVerifier:
    """Verificador de integridad de evidencias digitales."""
    
    def __init__(self) -> None:
        """Inicializar el verificador de integridad."""
        self.hash_algorithms = config.HASH_ALGORITHMS
    
    def calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calcular hashes de un archivo.
        
        Args:
            file_path: Ruta del archivo
            
        Returns:
            Diccionario con hashes calculados
            
        Raises:
            IOError: Si no se puede leer el archivo
        """
        if not file_path.exists() or not file_path.is_file():
            raise IOError(f"Archivo no encontrado o no es un archivo: {file_path}")
        
        hashes = {}
        hash_objects = {}
        
        # Inicializar objetos hash
        for algorithm in self.hash_algorithms:
            hash_objects[algorithm] = hashlib.new(algorithm)
        
        # Leer archivo en chunks para archivos grandes
        chunk_size = 8192 * 1024  # 8MB chunks
        
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
            
            # Obtener hashes finales
            for algorithm, hash_obj in hash_objects.items():
                hashes[algorithm] = hash_obj.hexdigest()
            
            logger.debug(f"Hashes calculados para {file_path}: {hashes}")
            return hashes
            
        except IOError as e:
            logger.error(f"Error calculando hashes para {file_path}: {e}")
            raise
    
    def create_manifest(self, file_path: Path, case_id: Optional[str] = None) -> Dict[str, Any]:
        """Crear manifiesto de integridad para un archivo.
        
        Args:
            file_path: Ruta del archivo
            case_id: ID del caso (opcional)
            
        Returns:
            Diccionario con manifiesto de integridad
        """
        if not file_path.exists():
            raise IOError(f"Archivo no encontrado: {file_path}")
        
        stat = file_path.stat()
        hashes = self.calculate_hashes(file_path)
        
        manifest = {
            "file_info": {
                "path": str(file_path.absolute()),
                "name": file_path.name,
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime, timezone.utc).isoformat(),
            },
            "hashes": hashes,
            "verification": {
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "verified_by": "forensectl",
                "version": "0.1.0",
                "case_id": case_id,
                "algorithms": self.hash_algorithms
            },
            "metadata": {
                "manifest_version": "1.0",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        }
        
        logger.info(f"Manifiesto creado para {file_path}")
        return manifest
    
    def save_manifest(self, manifest: Dict[str, Any], output_path: Path) -> None:
        """Guardar manifiesto en archivo.
        
        Args:
            manifest: Manifiesto de integridad
            output_path: Ruta de salida
        """
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Manifiesto guardado en {output_path}")
            
        except IOError as e:
            logger.error(f"Error guardando manifiesto en {output_path}: {e}")
            raise
    
    def verify_file(self, file_path: Path, manifest_path: Optional[Path] = None) -> Dict[str, Any]:
        """Verificar integridad de un archivo.
        
        Args:
            file_path: Ruta del archivo a verificar
            manifest_path: Ruta del manifiesto (opcional, se busca automáticamente)
            
        Returns:
            Diccionario con resultado de verificación
        """
        if not file_path.exists():
            return {
                "valid": False,
                "error": f"Archivo no encontrado: {file_path}",
                "file_path": str(file_path)
            }
        
        # Buscar manifiesto si no se proporciona
        if manifest_path is None:
            manifest_path = self._find_manifest(file_path)
        
        if manifest_path is None or not manifest_path.exists():
            return {
                "valid": False,
                "error": f"Manifiesto no encontrado para {file_path}",
                "file_path": str(file_path)
            }
        
        try:
            # Cargar manifiesto
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            
            # Calcular hashes actuales
            current_hashes = self.calculate_hashes(file_path)
            original_hashes = manifest["hashes"]
            
            # Verificar cada hash
            hash_results = {}
            all_valid = True
            
            for algorithm in self.hash_algorithms:
                if algorithm in original_hashes and algorithm in current_hashes:
                    is_valid = original_hashes[algorithm] == current_hashes[algorithm]
                    hash_results[algorithm] = {
                        "valid": is_valid,
                        "original": original_hashes[algorithm],
                        "current": current_hashes[algorithm]
                    }
                    if not is_valid:
                        all_valid = False
                else:
                    hash_results[algorithm] = {
                        "valid": False,
                        "error": f"Hash {algorithm} no disponible"
                    }
                    all_valid = False
            
            # Verificar metadatos básicos
            stat = file_path.stat()
            size_valid = manifest["file_info"]["size"] == stat.st_size
            
            if not size_valid:
                all_valid = False
            
            result = {
                "valid": all_valid,
                "file_path": str(file_path),
                "manifest_path": str(manifest_path),
                "hash_results": hash_results,
                "size_valid": size_valid,
                "original_size": manifest["file_info"]["size"],
                "current_size": stat.st_size,
                "verified_at": datetime.now(timezone.utc).isoformat()
            }
            
            if all_valid:
                logger.info(f"Verificación exitosa para {file_path}")
            else:
                logger.warning(f"Verificación fallida para {file_path}")
            
            return result
            
        except (json.JSONDecodeError, KeyError, IOError) as e:
            logger.error(f"Error verificando {file_path}: {e}")
            return {
                "valid": False,
                "error": f"Error procesando manifiesto: {e}",
                "file_path": str(file_path),
                "manifest_path": str(manifest_path) if manifest_path else None
            }
    
    def verify_path(self, path: Path, recursive: bool = False) -> Dict[str, Any]:
        """Verificar integridad de archivos en una ruta.
        
        Args:
            path: Ruta a verificar (archivo o directorio)
            recursive: Si verificar recursivamente
            
        Returns:
            Diccionario con resultados de verificación
        """
        results = {
            "valid": True,
            "files_checked": 0,
            "files_valid": 0,
            "files_invalid": 0,
            "errors": [],
            "details": []
        }
        
        if path.is_file():
            # Verificar archivo único
            result = self.verify_file(path)
            results["files_checked"] = 1
            
            if result["valid"]:
                results["files_valid"] = 1
            else:
                results["files_invalid"] = 1
                results["valid"] = False
                if "error" in result:
                    results["errors"].append(result["error"])
            
            results["details"].append(result)
            
        elif path.is_dir():
            # Verificar directorio
            pattern = "**/*" if recursive else "*"
            
            for file_path in path.glob(pattern):
                if file_path.is_file() and not file_path.name.startswith("."):
                    result = self.verify_file(file_path)
                    results["files_checked"] += 1
                    
                    if result["valid"]:
                        results["files_valid"] += 1
                    else:
                        results["files_invalid"] += 1
                        results["valid"] = False
                        if "error" in result:
                            results["errors"].append(result["error"])
                    
                    results["details"].append(result)
        
        else:
            results["valid"] = False
            results["errors"].append(f"Ruta no válida: {path}")
        
        logger.info(
            f"Verificación completada: {results['files_checked']} archivos, "
            f"{results['files_valid']} válidos, {results['files_invalid']} inválidos"
        )
        
        return results
    
    def create_batch_manifest(self, paths: List[Path], output_dir: Path, case_id: Optional[str] = None) -> List[Path]:
        """Crear manifiestos para múltiples archivos.
        
        Args:
            paths: Lista de rutas de archivos
            output_dir: Directorio de salida para manifiestos
            case_id: ID del caso
            
        Returns:
            Lista de rutas de manifiestos creados
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_paths = []
        
        for file_path in paths:
            if file_path.is_file():
                try:
                    manifest = self.create_manifest(file_path, case_id)
                    manifest_filename = f"{file_path.name}.manifest.json"
                    manifest_path = output_dir / manifest_filename
                    
                    self.save_manifest(manifest, manifest_path)
                    manifest_paths.append(manifest_path)
                    
                except Exception as e:
                    logger.error(f"Error creando manifiesto para {file_path}: {e}")
        
        logger.info(f"Creados {len(manifest_paths)} manifiestos en {output_dir}")
        return manifest_paths
    
    def _find_manifest(self, file_path: Path) -> Optional[Path]:
        """Buscar manifiesto para un archivo.
        
        Args:
            file_path: Ruta del archivo
            
        Returns:
            Ruta del manifiesto o None si no se encuentra
        """
        # Buscar en el mismo directorio
        manifest_name = f"{file_path.name}.manifest.json"
        manifest_path = file_path.parent / manifest_name
        
        if manifest_path.exists():
            return manifest_path
        
        # Buscar en directorio manifests del caso
        case_manifests_dir = file_path.parent.parent / "manifests"
        if case_manifests_dir.exists():
            manifest_path = case_manifests_dir / manifest_name
            if manifest_path.exists():
                return manifest_path
        
        # Buscar en directorio global de manifests
        global_manifests_dir = config.BASE_DIR / "manifests"
        if global_manifests_dir.exists():
            manifest_path = global_manifests_dir / manifest_name
            if manifest_path.exists():
                return manifest_path
        
        return None
    
    def generate_integrity_report(self, verification_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generar reporte de integridad.
        
        Args:
            verification_results: Lista de resultados de verificación
            
        Returns:
            Diccionario con reporte de integridad
        """
        total_files = len(verification_results)
        valid_files = sum(1 for r in verification_results if r["valid"])
        invalid_files = total_files - valid_files
        
        # Agrupar errores
        errors_by_type = {}
        for result in verification_results:
            if not result["valid"] and "error" in result:
                error_type = type(result["error"]).__name__
                if error_type not in errors_by_type:
                    errors_by_type[error_type] = []
                errors_by_type[error_type].append(result["file_path"])
        
        report = {
            "summary": {
                "total_files": total_files,
                "valid_files": valid_files,
                "invalid_files": invalid_files,
                "success_rate": (valid_files / total_files * 100) if total_files > 0 else 0
            },
            "errors_by_type": errors_by_type,
            "details": verification_results,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generated_by": "forensectl-integrity-verifier"
        }
        
        return report