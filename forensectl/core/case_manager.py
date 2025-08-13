"""Gestor de casos forenses."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Any

from forensectl import config, logger


class CaseManager:
    """Gestor para crear y administrar casos forenses."""
    
    def __init__(self) -> None:
        """Inicializar el gestor de casos."""
        self.cases_dir = config.CASES_DIR
        self.cases_dir.mkdir(parents=True, exist_ok=True)
    
    def create_case(
        self,
        case_id: str,
        examiner: str,
        organization: str,
        description: str,
        timezone_str: str = "UTC"
    ) -> Dict[str, Any]:
        """Crear un nuevo caso forense.
        
        Args:
            case_id: Identificador único del caso (ej: CASE-20250812-ORG-INCIDENT)
            examiner: Nombre del examinador forense
            organization: Organización responsable
            description: Descripción del caso
            timezone_str: Zona horaria del caso
            
        Returns:
            Diccionario con información del caso creado
            
        Raises:
            ValueError: Si el caso ya existe o el ID es inválido
        """
        # Validar formato del case_id
        if not self._validate_case_id(case_id):
            raise ValueError(
                f"ID de caso inválido: {case_id}. "
                "Formatos aceptados: CASO-XXX (ej: CASO-001) o CASE-YYYYMMDD-ORG-INCIDENT"
            )
        
        case_dir = self.cases_dir / case_id
        
        # Verificar que el caso no exista
        if case_dir.exists():
            raise ValueError(f"El caso {case_id} ya existe")
        
        # Crear información del caso
        case_info = {
            "case_id": case_id,
            "uuid": str(uuid.uuid4()),
            "examiner": examiner,
            "organization": organization,
            "description": description,
            "timezone": timezone_str,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "active",
            "version": "1.0",
            "metadata": {
                "forensectl_version": "0.1.0",
                "created_by": examiner,
                "last_modified": datetime.now(timezone.utc).isoformat()
            }
        }
        
        # Crear directorio del caso
        case_dir.mkdir(parents=True, exist_ok=True)
        
        # Guardar información del caso
        case_info_file = case_dir / "case_info.json"
        with open(case_info_file, "w", encoding="utf-8") as f:
            json.dump(case_info, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Caso {case_id} creado exitosamente")
        return case_info
    
    def setup_case_structure(self, case_id: str) -> None:
        """Crear estructura de directorios para el caso.
        
        Args:
            case_id: Identificador del caso
        """
        case_dir = self.cases_dir / case_id
        
        # Directorios estándar del caso
        directories = [
            "evidence",      # Evidencias digitales
            "analysis",      # Resultados de análisis
            "reports",       # Reportes generados
            "manifests",     # Manifiestos de integridad
            "chain",         # Cadena de custodia
            "logs",          # Logs de procesamiento
            "temp",          # Archivos temporales
            "exports"        # Exportaciones y extracciones
        ]
        
        for directory in directories:
            dir_path = case_dir / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            
            # Crear archivo README en cada directorio
            readme_file = dir_path / "README.md"
            readme_content = self._get_directory_readme(directory)
            with open(readme_file, "w", encoding="utf-8") as f:
                f.write(readme_content)
        
        # Crear archivo .gitkeep para preservar estructura en git
        for directory in directories:
            gitkeep_file = case_dir / directory / ".gitkeep"
            gitkeep_file.touch()
        
        logger.info(f"Estructura de directorios creada para caso {case_id}")
    
    def get_case_info(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Obtener información de un caso.
        
        Args:
            case_id: Identificador del caso
            
        Returns:
            Diccionario con información del caso o None si no existe
        """
        case_dir = self.cases_dir / case_id
        case_info_file = case_dir / "case_info.json"
        
        if not case_info_file.exists():
            return None
        
        try:
            with open(case_info_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error leyendo información del caso {case_id}: {e}")
            return None
    
    def update_case_info(self, case_id: str, updates: Dict[str, Any]) -> bool:
        """Actualizar información de un caso.
        
        Args:
            case_id: Identificador del caso
            updates: Diccionario con campos a actualizar
            
        Returns:
            True si se actualizó exitosamente, False en caso contrario
        """
        case_info = self.get_case_info(case_id)
        if not case_info:
            return False
        
        # Actualizar campos
        case_info.update(updates)
        case_info["metadata"]["last_modified"] = datetime.now(timezone.utc).isoformat()
        
        # Guardar cambios
        case_dir = self.cases_dir / case_id
        case_info_file = case_dir / "case_info.json"
        
        try:
            with open(case_info_file, "w", encoding="utf-8") as f:
                json.dump(case_info, f, indent=2, ensure_ascii=False)
            logger.info(f"Información del caso {case_id} actualizada")
            return True
        except IOError as e:
            logger.error(f"Error actualizando caso {case_id}: {e}")
            return False
    
    def list_cases(self) -> list[Dict[str, Any]]:
        """Listar todos los casos.
        
        Returns:
            Lista de diccionarios con información de casos
        """
        cases = []
        
        for case_dir in self.cases_dir.iterdir():
            if case_dir.is_dir():
                case_info = self.get_case_info(case_dir.name)
                if case_info:
                    cases.append(case_info)
        
        # Ordenar por fecha de creación (más recientes primero)
        cases.sort(key=lambda x: x["created_at"], reverse=True)
        return cases
    
    def archive_case(self, case_id: str) -> bool:
        """Marcar un caso como archivado.
        
        Args:
            case_id: Identificador del caso
            
        Returns:
            True si se archivó exitosamente, False en caso contrario
        """
        updates = {
            "status": "archived",
            "archived_at": datetime.now(timezone.utc).isoformat()
        }
        return self.update_case_info(case_id, updates)
    
    def delete_case(self, case_id: str, confirm: bool = False) -> bool:
        """Eliminar un caso completamente.
        
        Args:
            case_id: Identificador del caso
            confirm: Confirmación explícita para eliminar
            
        Returns:
            True si se eliminó exitosamente, False en caso contrario
        """
        if not confirm:
            logger.warning(f"Eliminación de caso {case_id} requiere confirmación explícita")
            return False
        
        case_dir = self.cases_dir / case_id
        
        if not case_dir.exists():
            logger.warning(f"Caso {case_id} no existe")
            return False
        
        try:
            import shutil
            shutil.rmtree(case_dir)
            logger.info(f"Caso {case_id} eliminado completamente")
            return True
        except OSError as e:
            logger.error(f"Error eliminando caso {case_id}: {e}")
            return False
    
    def _validate_case_id(self, case_id: str) -> bool:
        """Validar formato del ID de caso.
        
        Args:
            case_id: ID a validar
            
        Returns:
            True si el formato es válido
        """
        import re
        
        # Formato nuevo simple: CASO-XXX (donde XXX son 3 dígitos)
        simple_pattern = r"^CASO-\d{3}$"
        
        # Formato antiguo: CASE-YYYYMMDD-ORG-INCIDENT
        legacy_pattern = r"^CASE-\d{8}-[A-Z0-9]+-[A-Z0-9-]+$"
        
        case_id_upper = case_id.upper()
        return bool(re.match(simple_pattern, case_id_upper) or re.match(legacy_pattern, case_id_upper))
    
    def _get_directory_readme(self, directory: str) -> str:
        """Generar contenido README para directorios del caso.
        
        Args:
            directory: Nombre del directorio
            
        Returns:
            Contenido del README
        """
        readme_content = {
            "evidence": (
                "# Evidencias Digitales\n\n"
                "Este directorio contiene las evidencias digitales originales del caso.\n\n"
                "## Estructura:\n"
                "- `memory/` - Dumps de memoria\n"
                "- `disk/` - Imágenes de disco\n"
                "- `network/` - Capturas de red\n"
                "- `logs/` - Logs del sistema\n"
                "- `artifacts/` - Artefactos específicos\n\n"
                "⚠️ **IMPORTANTE**: Todas las evidencias deben tener manifiestos de integridad."
            ),
            "analysis": (
                "# Resultados de Análisis\n\n"
                "Este directorio contiene los resultados de análisis forense.\n\n"
                "## Estructura:\n"
                "- `memory/` - Análisis de memoria (Volatility3)\n"
                "- `disk/` - Análisis de disco (TSK/Autopsy)\n"
                "- `timeline/` - Timelines generados (plaso)\n"
                "- `yara/` - Resultados de escaneo YARA\n"
                "- `artifacts/` - Análisis de artefactos específicos"
            ),
            "reports": (
                "# Reportes Forenses\n\n"
                "Este directorio contiene los reportes generados del caso.\n\n"
                "## Tipos de Reporte:\n"
                "- `tecnico/` - Reportes técnicos detallados\n"
                "- `ejecutivo/` - Resúmenes ejecutivos\n"
                "- `anexos/` - Anexos y evidencia visual\n"
                "- `exports/` - Exportaciones en diferentes formatos"
            ),
            "manifests": (
                "# Manifiestos de Integridad\n\n"
                "Este directorio contiene los manifiestos de integridad de evidencias.\n\n"
                "## Contenido:\n"
                "- Hashes SHA-256 y SHA-512\n"
                "- Metadatos de archivos\n"
                "- Firmas digitales (opcional)\n"
                "- Timestamps de verificación"
            ),
            "chain": (
                "# Cadena de Custodia\n\n"
                "Este directorio contiene la documentación de cadena de custodia.\n\n"
                "## Contenido:\n"
                "- Entradas de cadena de custodia\n"
                "- Transferencias de evidencia\n"
                "- Firmas y autorizaciones\n"
                "- Logs de acceso"
            ),
            "logs": (
                "# Logs de Procesamiento\n\n"
                "Este directorio contiene logs del procesamiento forense.\n\n"
                "## Contenido:\n"
                "- Logs de herramientas\n"
                "- Errores y advertencias\n"
                "- Tiempos de ejecución\n"
                "- Comandos ejecutados"
            ),
            "temp": (
                "# Archivos Temporales\n\n"
                "Este directorio contiene archivos temporales de procesamiento.\n\n"
                "⚠️ **NOTA**: Los archivos en este directorio pueden ser eliminados "
                "automáticamente después del procesamiento."
            ),
            "exports": (
                "# Exportaciones\n\n"
                "Este directorio contiene exportaciones y extracciones del caso.\n\n"
                "## Contenido:\n"
                "- Archivos extraídos\n"
                "- Datos exportados\n"
                "- Conversiones de formato\n"
                "- Subconjuntos de evidencia"
            )
        }
        
        return readme_content.get(directory, f"# {directory.title()}\n\nDirectorio del caso forense.")