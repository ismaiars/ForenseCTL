"""Analizador de imágenes de disco usando The Sleuth Kit."""

import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from forensectl import config, logger
from forensectl.core.chain_of_custody import ChainOfCustody
from forensectl.core.manifest import Manifest


class DiskAnalyzer:
    """Analizador de imágenes de disco usando The Sleuth Kit (TSK)."""
    
    def __init__(self, case_id: str, examiner: str = "") -> None:
        """Inicializar analizador de disco.
        
        Args:
            case_id: ID del caso
            examiner: Examinador responsable
        """
        self.case_id = case_id
        self.examiner = examiner
        
        # Directorios del caso
        self.case_dir = config.CASES_DIR / case_id
        self.analysis_dir = self.case_dir / "analysis" / "disk"
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        
        # Herramientas auxiliares
        self.chain_of_custody = ChainOfCustody(case_id)
        self.manifest = Manifest(case_id)
        
        # Comandos de TSK
        self.tsk_commands = {
            "mmls": "mmls",      # Listar particiones
            "fsstat": "fsstat",  # Información del sistema de archivos
            "fls": "fls",        # Listar archivos
            "istat": "istat",    # Información de inodo
            "icat": "icat",      # Extraer contenido de archivo
            "blkstat": "blkstat", # Información de bloque
            "blkcat": "blkcat",  # Extraer contenido de bloque
            "img_stat": "img_stat", # Información de imagen
            "mactime": "mactime", # Timeline
            "fiwalk": "fiwalk"   # Análisis forense
        }
        
        # Tipos de sistemas de archivos soportados
        self.supported_filesystems = [
            "ntfs", "fat32", "fat16", "fat12", "ext4", "ext3", "ext2",
            "hfs+", "hfs", "iso9660", "ufs", "raw"
        ]
    
    def analyze_disk_image(
        self,
        image_path: Union[str, Path],
        partition_offset: Optional[int] = None,
        filesystem_type: Optional[str] = None,
        extract_files: bool = True,
        generate_timeline: bool = True,
        custom_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Analizar imagen de disco completa.
        
        Args:
            image_path: Ruta de la imagen de disco
            partition_offset: Offset de partición específica
            filesystem_type: Tipo de sistema de archivos
            extract_files: Extraer archivos importantes
            generate_timeline: Generar timeline
            custom_options: Opciones personalizadas
            
        Returns:
            Diccionario con resultados del análisis
        """
        image_path = Path(image_path)
        if not image_path.exists():
            raise ValueError(f"Imagen de disco no encontrada: {image_path}")
        
        analysis_id = str(uuid.uuid4())
        analysis_start = datetime.now(timezone.utc)
        
        logger.info(f"Iniciando análisis de disco {analysis_id} para imagen: {image_path}")
        
        # Crear directorio de análisis
        analysis_output_dir = self.analysis_dir / analysis_id
        analysis_output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Obtener información básica de la imagen
            image_info = self._get_image_info(image_path, analysis_output_dir)
            
            # Listar particiones
            partitions = self._list_partitions(image_path, analysis_output_dir)
            
            # Analizar cada partición o la especificada
            partition_results = {}
            
            if partition_offset is not None:
                # Analizar partición específica
                partition_results[partition_offset] = self._analyze_partition(
                    image_path, partition_offset, filesystem_type, 
                    analysis_output_dir, extract_files, generate_timeline
                )
            else:
                # Analizar todas las particiones detectadas
                for partition in partitions:
                    offset = partition.get("start_sector", 0) * 512  # Convertir a bytes
                    if offset > 0:  # Ignorar particiones sin offset válido
                        try:
                            partition_results[offset] = self._analyze_partition(
                                image_path, offset, filesystem_type,
                                analysis_output_dir, extract_files, generate_timeline
                            )
                        except Exception as e:
                            logger.error(f"Error analizando partición en offset {offset}: {e}")
                            partition_results[offset] = {"error": str(e)}
            
            analysis_end = datetime.now(timezone.utc)
            
            # Crear resumen del análisis
            analysis_summary = {
                "analysis_id": analysis_id,
                "case_id": self.case_id,
                "analysis_type": "disk_analysis",
                "image_path": str(image_path),
                "image_info": image_info,
                "partitions": partitions,
                "partition_results": partition_results,
                "output_directory": str(analysis_output_dir),
                "started_at": analysis_start.isoformat(),
                "completed_at": analysis_end.isoformat(),
                "duration_seconds": (analysis_end - analysis_start).total_seconds(),
                "examiner": self.examiner,
                "tool_info": {
                    "name": "The Sleuth Kit",
                    "version": self._get_tsk_version(),
                    "commands_used": list(self.tsk_commands.keys())
                },
                "options": {
                    "partition_offset": partition_offset,
                    "filesystem_type": filesystem_type,
                    "extract_files": extract_files,
                    "generate_timeline": generate_timeline,
                    "custom_options": custom_options or {}
                }
            }
            
            # Guardar resumen
            summary_file = analysis_output_dir / "analysis_summary.json"
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(analysis_summary, f, indent=2, ensure_ascii=False)
            
            # Registrar en manifiesto
            self.manifest.register_analysis(
                analysis_id=analysis_id,
                analysis_type="disk_analysis",
                evidence_id="",  # Se puede vincular después
                tool_name="The Sleuth Kit",
                tool_version=self._get_tsk_version(),
                output_path=str(analysis_output_dir),
                examiner=self.examiner,
                description=f"Análisis de imagen de disco con {len(partition_results)} particiones",
                parameters={
                    "image_path": str(image_path),
                    "partition_offset": partition_offset,
                    "filesystem_type": filesystem_type,
                    "extract_files": extract_files,
                    "generate_timeline": generate_timeline
                },
                results_summary={
                    "partitions_analyzed": len(partition_results),
                    "total_files_found": sum(
                        len(result.get("files", [])) for result in partition_results.values()
                        if isinstance(result, dict) and "files" in result
                    )
                }
            )
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="disk_analysis_completed",
                description=f"Análisis de disco completado con {len(partition_results)} particiones",
                examiner=self.examiner,
                evidence_path=str(image_path),
                metadata={
                    "analysis_id": analysis_id,
                    "partitions_count": len(partition_results),
                    "duration_seconds": analysis_summary["duration_seconds"]
                }
            )
            
            logger.info(f"Análisis de disco {analysis_id} completado exitosamente")
            return analysis_summary
            
        except Exception as e:
            logger.error(f"Error durante análisis de disco {analysis_id}: {e}")
            
            # Agregar error a cadena de custodia
            self.chain_of_custody.add_entry(
                action="disk_analysis_failed",
                description=f"Fallo en análisis de disco: {str(e)}",
                examiner=self.examiner,
                evidence_path=str(image_path),
                metadata={"analysis_id": analysis_id, "error": str(e)}
            )
            
            raise
    
    def extract_file_by_inode(
        self,
        image_path: Union[str, Path],
        inode: int,
        output_path: Union[str, Path],
        partition_offset: Optional[int] = None,
        filesystem_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Extraer archivo específico por número de inodo.
        
        Args:
            image_path: Ruta de la imagen de disco
            inode: Número de inodo del archivo
            output_path: Ruta de salida para el archivo extraído
            partition_offset: Offset de la partición
            filesystem_type: Tipo de sistema de archivos
            
        Returns:
            Información de la extracción
        """
        image_path = Path(image_path)
        output_path = Path(output_path)
        
        if not image_path.exists():
            raise ValueError(f"Imagen de disco no encontrada: {image_path}")
        
        # Crear directorio de salida
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Construir comando icat
        cmd = [self.tsk_commands["icat"]]
        
        if partition_offset:
            cmd.extend(["-o", str(partition_offset // 512)])  # Convertir a sectores
        
        if filesystem_type:
            cmd.extend(["-f", filesystem_type])
        
        cmd.extend([str(image_path), str(inode)])
        
        logger.info(f"Extrayendo archivo con inodo {inode} desde {image_path}")
        
        try:
            # Ejecutar comando
            with open(output_path, "wb") as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    timeout=300
                )
            
            if result.returncode == 0:
                file_size = output_path.stat().st_size
                
                # Agregar a cadena de custodia
                self.chain_of_custody.add_entry(
                    action="file_extracted",
                    description=f"Archivo extraído por inodo {inode}",
                    examiner=self.examiner,
                    evidence_path=str(image_path),
                    metadata={
                        "inode": inode,
                        "output_path": str(output_path),
                        "file_size": file_size,
                        "partition_offset": partition_offset
                    }
                )
                
                logger.info(f"Archivo extraído exitosamente: {output_path} ({file_size} bytes)")
                
                return {
                    "status": "success",
                    "inode": inode,
                    "output_path": str(output_path),
                    "file_size": file_size,
                    "command": " ".join(cmd)
                }
            else:
                error_msg = result.stderr.decode() if result.stderr else "Error desconocido"
                logger.error(f"Error extrayendo archivo con inodo {inode}: {error_msg}")
                
                return {
                    "status": "error",
                    "inode": inode,
                    "error": error_msg,
                    "command": " ".join(cmd)
                }
                
        except Exception as e:
            logger.error(f"Excepción extrayendo archivo con inodo {inode}: {e}")
            return {
                "status": "error",
                "inode": inode,
                "error": str(e),
                "command": " ".join(cmd)
            }
    
    def search_files_by_name(
        self,
        image_path: Union[str, Path],
        filename_pattern: str,
        partition_offset: Optional[int] = None,
        filesystem_type: Optional[str] = None,
        case_sensitive: bool = False
    ) -> List[Dict[str, Any]]:
        """Buscar archivos por nombre o patrón.
        
        Args:
            image_path: Ruta de la imagen de disco
            filename_pattern: Patrón de nombre de archivo
            partition_offset: Offset de la partición
            filesystem_type: Tipo de sistema de archivos
            case_sensitive: Búsqueda sensible a mayúsculas
            
        Returns:
            Lista de archivos encontrados
        """
        # Obtener lista completa de archivos
        files = self._list_files(image_path, partition_offset, filesystem_type)
        
        # Filtrar por patrón
        matching_files = []
        
        for file_info in files:
            filename = file_info.get("name", "")
            
            if case_sensitive:
                match = filename_pattern in filename
            else:
                match = filename_pattern.lower() in filename.lower()
            
            if match:
                matching_files.append(file_info)
        
        logger.info(f"Encontrados {len(matching_files)} archivos que coinciden con '{filename_pattern}'")
        
        return matching_files
    
    def get_filesystem_info(
        self,
        image_path: Union[str, Path],
        partition_offset: Optional[int] = None,
        filesystem_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Obtener información detallada del sistema de archivos.
        
        Args:
            image_path: Ruta de la imagen de disco
            partition_offset: Offset de la partición
            filesystem_type: Tipo de sistema de archivos
            
        Returns:
            Información del sistema de archivos
        """
        image_path = Path(image_path)
        
        # Construir comando fsstat
        cmd = [self.tsk_commands["fsstat"]]
        
        if partition_offset:
            cmd.extend(["-o", str(partition_offset // 512)])
        
        if filesystem_type:
            cmd.extend(["-f", filesystem_type])
        
        cmd.append(str(image_path))
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Parsear salida de fsstat
                fs_info = self._parse_fsstat_output(result.stdout)
                
                logger.info(f"Información del sistema de archivos obtenida para {image_path}")
                
                return {
                    "status": "success",
                    "filesystem_info": fs_info,
                    "raw_output": result.stdout,
                    "command": " ".join(cmd)
                }
            else:
                error_msg = result.stderr if result.stderr else "Error desconocido"
                logger.error(f"Error obteniendo información del sistema de archivos: {error_msg}")
                
                return {
                    "status": "error",
                    "error": error_msg,
                    "command": " ".join(cmd)
                }
                
        except Exception as e:
            logger.error(f"Excepción obteniendo información del sistema de archivos: {e}")
            return {
                "status": "error",
                "error": str(e),
                "command": " ".join(cmd)
            }
    
    def _get_image_info(self, image_path: Path, output_dir: Path) -> Dict[str, Any]:
        """Obtener información básica de la imagen.
        
        Args:
            image_path: Ruta de la imagen
            output_dir: Directorio de salida
            
        Returns:
            Información de la imagen
        """
        cmd = [self.tsk_commands["img_stat"], str(image_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Guardar salida
            output_file = output_dir / "image_info.txt"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            
            if result.returncode == 0:
                return self._parse_img_stat_output(result.stdout)
            else:
                return {"error": result.stderr, "status": "failed"}
                
        except Exception as e:
            logger.error(f"Error obteniendo información de imagen: {e}")
            return {"error": str(e), "status": "failed"}
    
    def _list_partitions(self, image_path: Path, output_dir: Path) -> List[Dict[str, Any]]:
        """Listar particiones de la imagen.
        
        Args:
            image_path: Ruta de la imagen
            output_dir: Directorio de salida
            
        Returns:
            Lista de particiones
        """
        cmd = [self.tsk_commands["mmls"], str(image_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Guardar salida
            output_file = output_dir / "partitions.txt"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            
            if result.returncode == 0:
                return self._parse_mmls_output(result.stdout)
            else:
                logger.warning(f"No se pudieron listar particiones: {result.stderr}")
                return []
                
        except Exception as e:
            logger.error(f"Error listando particiones: {e}")
            return []
    
    def _analyze_partition(
        self,
        image_path: Path,
        offset: int,
        filesystem_type: Optional[str],
        output_dir: Path,
        extract_files: bool,
        generate_timeline: bool
    ) -> Dict[str, Any]:
        """Analizar partición específica.
        
        Args:
            image_path: Ruta de la imagen
            offset: Offset de la partición
            filesystem_type: Tipo de sistema de archivos
            output_dir: Directorio de salida
            extract_files: Extraer archivos
            generate_timeline: Generar timeline
            
        Returns:
            Resultados del análisis de la partición
        """
        partition_dir = output_dir / f"partition_{offset}"
        partition_dir.mkdir(parents=True, exist_ok=True)
        
        results = {
            "offset": offset,
            "filesystem_type": filesystem_type,
            "analysis_directory": str(partition_dir)
        }
        
        # Obtener información del sistema de archivos
        fs_info = self.get_filesystem_info(image_path, offset, filesystem_type)
        results["filesystem_info"] = fs_info
        
        # Listar archivos
        files = self._list_files(image_path, offset, filesystem_type)
        results["files"] = files
        results["file_count"] = len(files)
        
        # Guardar lista de archivos
        files_output = partition_dir / "files_list.json"
        with open(files_output, "w", encoding="utf-8") as f:
            json.dump(files, f, indent=2, ensure_ascii=False)
        
        # Extraer archivos importantes si se solicita
        if extract_files:
            extracted_files = self._extract_important_files(
                image_path, files, partition_dir, offset, filesystem_type
            )
            results["extracted_files"] = extracted_files
        
        # Generar timeline si se solicita
        if generate_timeline:
            timeline = self._generate_partition_timeline(
                image_path, partition_dir, offset, filesystem_type
            )
            results["timeline"] = timeline
        
        return results
    
    def _list_files(
        self,
        image_path: Path,
        offset: Optional[int] = None,
        filesystem_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Listar archivos en la partición.
        
        Args:
            image_path: Ruta de la imagen
            offset: Offset de la partición
            filesystem_type: Tipo de sistema de archivos
            
        Returns:
            Lista de archivos
        """
        cmd = [self.tsk_commands["fls"], "-r", "-l"]  # Recursivo y formato largo
        
        if offset:
            cmd.extend(["-o", str(offset // 512)])
        
        if filesystem_type:
            cmd.extend(["-f", filesystem_type])
        
        cmd.append(str(image_path))
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return self._parse_fls_output(result.stdout)
            else:
                logger.warning(f"Error listando archivos: {result.stderr}")
                return []
                
        except Exception as e:
            logger.error(f"Excepción listando archivos: {e}")
            return []
    
    def _extract_important_files(
        self,
        image_path: Path,
        files: List[Dict[str, Any]],
        output_dir: Path,
        offset: int,
        filesystem_type: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Extraer archivos importantes.
        
        Args:
            image_path: Ruta de la imagen
            files: Lista de archivos
            output_dir: Directorio de salida
            offset: Offset de la partición
            filesystem_type: Tipo de sistema de archivos
            
        Returns:
            Lista de archivos extraídos
        """
        # Patrones de archivos importantes
        important_patterns = [
            ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1",
            ".doc", ".docx", ".pdf", ".txt", ".log",
            "registry", "ntuser", "sam", "system", "security",
            ".evtx", ".evt", "prefetch"
        ]
        
        extracted_files = []
        extract_dir = output_dir / "extracted_files"
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        for file_info in files[:100]:  # Limitar a 100 archivos
            filename = file_info.get("name", "").lower()
            inode = file_info.get("inode")
            
            if not inode or filename in ["..", "."]:
                continue
            
            # Verificar si es un archivo importante
            is_important = any(pattern in filename for pattern in important_patterns)
            
            if is_important:
                try:
                    output_file = extract_dir / f"inode_{inode}_{Path(filename).name}"
                    extraction_result = self.extract_file_by_inode(
                        image_path, inode, output_file, offset, filesystem_type
                    )
                    
                    if extraction_result["status"] == "success":
                        extracted_files.append({
                            "original_path": file_info.get("path", ""),
                            "extracted_path": str(output_file),
                            "inode": inode,
                            "size": extraction_result.get("file_size", 0)
                        })
                        
                except Exception as e:
                    logger.warning(f"Error extrayendo archivo {filename}: {e}")
        
        logger.info(f"Extraídos {len(extracted_files)} archivos importantes")
        return extracted_files
    
    def _generate_partition_timeline(
        self,
        image_path: Path,
        output_dir: Path,
        offset: int,
        filesystem_type: Optional[str]
    ) -> Dict[str, Any]:
        """Generar timeline de la partición.
        
        Args:
            image_path: Ruta de la imagen
            output_dir: Directorio de salida
            offset: Offset de la partición
            filesystem_type: Tipo de sistema de archivos
            
        Returns:
            Información del timeline
        """
        # TODO: Implementar generación de timeline con fls + mactime
        # Por ahora, retornar placeholder
        timeline_file = output_dir / "timeline.csv"
        
        timeline_info = {
            "timeline_file": str(timeline_file),
            "status": "not_implemented",
            "note": "Timeline generation pending implementation"
        }
        
        return timeline_info
    
    def _parse_img_stat_output(self, output: str) -> Dict[str, Any]:
        """Parsear salida de img_stat.
        
        Args:
            output: Salida del comando
            
        Returns:
            Información parseada
        """
        info = {"raw_output": output}
        
        for line in output.split("\n"):
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip().lower().replace(" ", "_")] = value.strip()
        
        return info
    
    def _parse_mmls_output(self, output: str) -> List[Dict[str, Any]]:
        """Parsear salida de mmls.
        
        Args:
            output: Salida del comando
            
        Returns:
            Lista de particiones
        """
        partitions = []
        
        for line in output.split("\n"):
            line = line.strip()
            if line and not line.startswith(("DOS", "Units", "Slot", "---")):
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        partitions.append({
                            "slot": parts[0],
                            "start_sector": int(parts[1]),
                            "end_sector": int(parts[2]),
                            "length": int(parts[3]),
                            "type": parts[4],
                            "description": " ".join(parts[5:])
                        })
                    except ValueError:
                        continue
        
        return partitions
    
    def _parse_fls_output(self, output: str) -> List[Dict[str, Any]]:
        """Parsear salida de fls.
        
        Args:
            output: Salida del comando
            
        Returns:
            Lista de archivos
        """
        files = []
        
        for line in output.split("\n"):
            line = line.strip()
            if line and not line.startswith("d/d"):
                # Formato típico: r/r * 123: filename
                parts = line.split(":", 1)
                if len(parts) == 2:
                    meta_part = parts[0].strip()
                    filename = parts[1].strip()
                    
                    # Extraer número de inodo
                    inode = None
                    if "*" in meta_part:
                        inode_part = meta_part.split("*")[-1].strip()
                        try:
                            inode = int(inode_part)
                        except ValueError:
                            pass
                    
                    files.append({
                        "name": filename,
                        "inode": inode,
                        "meta_info": meta_part,
                        "path": filename  # Simplificado
                    })
        
        return files
    
    def _parse_fsstat_output(self, output: str) -> Dict[str, Any]:
        """Parsear salida de fsstat.
        
        Args:
            output: Salida del comando
            
        Returns:
            Información del sistema de archivos
        """
        fs_info = {"raw_output": output}
        
        current_section = None
        
        for line in output.split("\n"):
            line = line.strip()
            
            if line.endswith(":"):
                current_section = line[:-1].lower().replace(" ", "_")
                fs_info[current_section] = {}
            elif ":" in line and current_section:
                key, value = line.split(":", 1)
                fs_info[current_section][key.strip().lower().replace(" ", "_")] = value.strip()
            elif ":" in line:
                key, value = line.split(":", 1)
                fs_info[key.strip().lower().replace(" ", "_")] = value.strip()
        
        return fs_info
    
    def _get_tsk_version(self) -> str:
        """Obtener versión de The Sleuth Kit.
        
        Returns:
            Versión de TSK
        """
        try:
            result = subprocess.run(
                ["fls", "-V"],
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