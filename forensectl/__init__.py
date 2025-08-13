"""Forense-Automatizado-BlueTeam - CLI para análisis forense digital automatizado.

Este paquete proporciona herramientas profesionales para:
- Adquisición y preservación de evidencias digitales
- Análisis de memoria, disco y artefactos de endpoint
- Generación de timelines forenses
- Detección de malware con YARA
- Reportes técnicos y ejecutivos
- Cadena de custodia documentada
"""

__version__ = "0.1.0"
__author__ = "Forense-Automatizado-BlueTeam Contributors"
__email__ = "contact@forense-automatizado-blueteam.org"
__license__ = "MIT"

# Configuración de logging
import logging
import sys
from pathlib import Path
from typing import Optional

# Configurar logging estructurado
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("forensectl.log", mode="a"),
    ],
)

# Logger principal
logger = logging.getLogger("forensectl")

# Configuración global
class Config:
    """Configuración global de forensectl."""
    
    # Directorios base
    BASE_DIR: Path = Path.cwd()
    CASES_DIR: Path = BASE_DIR / "cases"
    EVIDENCE_DIR: Path = BASE_DIR / "evidence"
    ANALYSIS_DIR: Path = BASE_DIR / "analysis"
    REPORTS_DIR: Path = BASE_DIR / "reports"
    RULES_DIR: Path = BASE_DIR / "rules"
    
    # Configuración de logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Configuración de integridad
    HASH_ALGORITHMS: list[str] = ["sha256", "sha512"]
    
    # Configuración de análisis
    MAX_WORKERS: int = 4
    MEMORY_LIMIT_GB: int = 16
    
    # Configuración de reportes
    REPORT_TEMPLATES_DIR: Path = BASE_DIR / "modules" / "reportes" / "templates"
    
    @classmethod
    def from_env(cls) -> "Config":
        """Cargar configuración desde variables de entorno."""
        import os
        
        config = cls()
        
        # Directorios
        if cases_dir := os.getenv("FORENSECTL_CASES_DIR"):
            config.CASES_DIR = Path(cases_dir)
        if evidence_dir := os.getenv("FORENSECTL_EVIDENCE_DIR"):
            config.EVIDENCE_DIR = Path(evidence_dir)
        if analysis_dir := os.getenv("FORENSECTL_ANALYSIS_DIR"):
            config.ANALYSIS_DIR = Path(analysis_dir)
        if reports_dir := os.getenv("FORENSECTL_REPORTS_DIR"):
            config.REPORTS_DIR = Path(reports_dir)
            
        # Logging
        if log_level := os.getenv("FORENSECTL_LOG_LEVEL"):
            config.LOG_LEVEL = log_level
            
        # Análisis
        if max_workers := os.getenv("FORENSECTL_MAX_WORKERS"):
            config.MAX_WORKERS = int(max_workers)
        if memory_limit := os.getenv("FORENSECTL_MEMORY_LIMIT_GB"):
            config.MEMORY_LIMIT_GB = int(memory_limit)
            
        return config
    
    def ensure_directories(self) -> None:
        """Crear directorios necesarios si no existen."""
        for directory in [
            self.CASES_DIR,
            self.EVIDENCE_DIR,
            self.ANALYSIS_DIR,
            self.REPORTS_DIR,
        ]:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Directorio asegurado: {directory}")

# Instancia global de configuración
config = Config.from_env()

# Asegurar directorios al importar
config.ensure_directories()

# Exportar elementos principales
__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "config",
    "logger",
    "Config",
]