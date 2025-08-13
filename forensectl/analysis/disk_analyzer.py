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
        """Obtener información básica de la imagen de disco.
        
        Args:
            image_path: Ruta de la imagen
            output_dir: Directorio de salida
            
        Returns:
            Información de la imagen
        """
        try:
            # Ejecutar img_stat para obtener información de la imagen
            cmd = [self.tsk_commands["img_stat"], str(image_path)]
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True
            )
            
            # Parsear salida de img_stat
            info = {
                "path": str(image_path),
                "size": image_path.stat().st_size,
                "type": "raw",
                "sector_size": 512,
                "raw_output": result.stdout
            }
            
            # Extraer información específica de la salida
            lines = result.stdout.split('\n')
            for line in lines:
                if "Image Type:" in line:
                    info["type"] = line.split(":")[1].strip()
                elif "Sector Size:" in line:
                    try:
                        info["sector_size"] = int(line.split(":")[1].strip())
                    except ValueError:
                        pass
            
            # Guardar información completa
            info_file = output_dir / "image_info.txt"
            with open(info_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            
            logger.info(f"Información de imagen obtenida: {info['type']}, {info['size']} bytes")
            return info
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"Error ejecutando img_stat: {e}")
            # Fallback a información básica
            return {
                "path": str(image_path),
                "size": image_path.stat().st_size,
                "type": "unknown",
                "sector_size": 512,
                "error": str(e)
            }
        except FileNotFoundError:
            logger.warning("img_stat no encontrado, usando información básica")
            return {
                "path": str(image_path),
                "size": image_path.stat().st_size,
                "type": "raw",
                "sector_size": 512,
                "tsk_available": False
            }
    
    def _list_partitions(self, image_path: Path, output_dir: Path) -> List[Dict[str, Any]]:
        """Listar particiones de la imagen.
        
        Args:
            image_path: Ruta de la imagen
            output_dir: Directorio de salida
            
        Returns:
            Lista de particiones encontradas
        """
        try:
            cmd = [self.tsk_commands["mmls"], str(image_path)]
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True
            )
            
            # Guardar salida completa
            output_file = output_dir / "partitions.txt"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            
            # Parsear salida de mmls
            partitions = []
            lines = result.stdout.split('\n')
            
            # Buscar líneas de particiones (formato: slot:start-end(length) description)
            for line in lines:
                line = line.strip()
                if not line or line.startswith('DOS') or line.startswith('Units') or ':' not in line:
                    continue
                
                try:
                    # Parsear línea de partición
                    parts = line.split()
                    if len(parts) >= 4:
                        slot = parts[0].rstrip(':')
                        start_sector = int(parts[1])
                        end_sector = int(parts[2])
                        length = int(parts[3])
                        description = ' '.join(parts[4:]) if len(parts) > 4 else 'Unknown'
                        
                        partition = {
                            'slot': slot,
                            'start_sector': start_sector,
                            'end_sector': end_sector,
                            'length_sectors': length,
                            'start_byte': start_sector * 512,
                            'size_bytes': length * 512,
                            'description': description,
                            'type': self._detect_partition_type(description)
                        }
                        
                        partitions.append(partition)
                        
                except (ValueError, IndexError) as e:
                    logger.debug(f"Error parseando línea de partición '{line}': {e}")
                    continue
            
            logger.info(f"Encontradas {len(partitions)} particiones")
            return partitions
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"Error ejecutando mmls: {e}")
            return []
        except FileNotFoundError:
            logger.warning("mmls no encontrado, no se pueden listar particiones")
            return []
        except Exception as e:
            logger.error(f"Error inesperado listando particiones: {e}")
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
            offset: Offset de la partición en bytes
            filesystem_type: Tipo de sistema de archivos
            output_dir: Directorio de salida
            extract_files: Extraer archivos importantes
            generate_timeline: Generar timeline
            
        Returns:
            Resultados del análisis de la partición
        """
        partition_dir = output_dir / f"partition_{offset}"
        partition_dir.mkdir(parents=True, exist_ok=True)
        
        sector_offset = offset // 512  # Convertir bytes a sectores
        
        results = {
            "offset": offset,
            "sector_offset": sector_offset,
            "filesystem_type": filesystem_type,
            "analysis_directory": str(partition_dir),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            logger.info(f"Analizando partición en offset {offset} (sector {sector_offset})")
            
            # Obtener información del sistema de archivos
            fs_info = self.get_filesystem_info(image_path, offset, filesystem_type)
            results["filesystem_info"] = fs_info
            
            # Auto-detectar tipo de sistema de archivos si no se especificó
            if not filesystem_type and fs_info.get("filesystem_info", {}).get("file_system_type"):
                filesystem_type = fs_info["filesystem_info"]["file_system_type"]
                results["filesystem_type"] = filesystem_type
            
            # Listar archivos y directorios
            files = self._list_files(image_path, offset, filesystem_type)
            results["files"] = files
            results["file_count"] = len(files)
            
            # Guardar lista de archivos
            files_output = partition_dir / "files_list.json"
            with open(files_output, "w", encoding="utf-8") as f:
                json.dump(files, f, indent=2, ensure_ascii=False)
            
            # Buscar archivos eliminados
            deleted_files = self._find_deleted_files(image_path, offset, filesystem_type)
            results["deleted_files"] = deleted_files
            results["deleted_files_count"] = len(deleted_files)
            
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
            
            # Análisis de seguridad básico
            security_analysis = self._perform_security_analysis(files, deleted_files)
            results["security_analysis"] = security_analysis
            
            logger.info(f"Análisis de partición completado: {len(files)} archivos encontrados")
            
        except Exception as e:
            logger.error(f"Error analizando partición {offset}: {e}")
            results["error"] = str(e)
            results["status"] = "failed"
        else:
            results["status"] = "completed"
        
        # Guardar resumen de la partición
        summary_file = partition_dir / "partition_summary.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
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
        cmd = [self.tsk_commands["fls"], "-r", "-l", "-p"]  # Recursivo, formato largo, con path completo
        
        if offset:
            cmd.extend(["-o", str(offset // 512)])
        
        if filesystem_type:
            cmd.extend(["-f", filesystem_type])
        
        cmd.append(str(image_path))
        
        try:
            logger.info(f"Listando archivos en offset {offset}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                files = self._parse_fls_output(result.stdout)
                logger.info(f"Encontrados {len(files)} archivos")
                return files
            else:
                logger.warning(f"Error listando archivos: {result.stderr}")
                return []
                
        except FileNotFoundError:
            logger.error("fls no encontrado. Instale The Sleuth Kit.")
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
    
    def _generate_timeline(
        self,
        image_path: Path,
        output_dir: Path,
        offset: Optional[int] = None,
        filesystem_type: Optional[str] = None
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
        timeline_file = output_dir / "timeline.csv"
        bodyfile = output_dir / "bodyfile.txt"
        
        try:
            # Paso 1: Generar bodyfile con fls
            logger.info("Generando bodyfile con fls...")
            
            fls_cmd = [self.tsk_commands["fls"], "-r", "-m", "/", "-z", "UTC"]
            
            if offset:
                fls_cmd.extend(["-o", str(offset // 512)])
            
            if filesystem_type:
                fls_cmd.extend(["-f", filesystem_type])
            
            fls_cmd.append(str(image_path))
            
            # Ejecutar fls y guardar bodyfile
            result = subprocess.run(
                fls_cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hora timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Error ejecutando fls: {result.stderr}")
                return {
                    "timeline_file": str(timeline_file),
                    "status": "error",
                    "error": f"fls failed: {result.stderr}"
                }
            
            # Guardar bodyfile
            with open(bodyfile, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            
            logger.info(f"Bodyfile generado: {bodyfile}")
            
            # Paso 2: Convertir bodyfile a timeline con mactime
            logger.info("Generando timeline con mactime...")
            
            mactime_cmd = [self.tsk_commands["mactime"], "-d", "-b", str(bodyfile)]
            
            result = subprocess.run(
                mactime_cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutos timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Error ejecutando mactime: {result.stderr}")
                return {
                    "timeline_file": str(timeline_file),
                    "status": "error",
                    "error": f"mactime failed: {result.stderr}"
                }
            
            # Guardar timeline
            with open(timeline_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            
            # Analizar estadísticas del timeline
            stats = self._analyze_timeline_stats(timeline_file)
            
            logger.info(f"Timeline generado: {timeline_file}")
            
            timeline_info = {
                "timeline_file": str(timeline_file),
                "bodyfile": str(bodyfile),
                "status": "success",
                "stats": stats,
                "file_size": timeline_file.stat().st_size if timeline_file.exists() else 0
            }
            
            # Agregar a cadena de custodia
            self.chain_of_custody.add_entry(
                action="timeline_generation",
                details={
                    "tool": "fls + mactime",
                    "image": str(image_path),
                    "offset": offset,
                    "filesystem": filesystem_type,
                    "timeline_file": str(timeline_file),
                    "events_count": stats.get("total_events", 0)
                }
            )
            
            return timeline_info
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout generando timeline")
            return {
                "timeline_file": str(timeline_file),
                "status": "error",
                "error": "Timeline generation timeout"
            }
        except Exception as e:
            logger.error(f"Error generando timeline: {e}")
            return {
                "timeline_file": str(timeline_file),
                "status": "error",
                "error": str(e)
            }
    
    def _analyze_timeline_stats(self, timeline_file: Path) -> Dict[str, Any]:
        """Analizar estadísticas del timeline generado.
        
        Args:
            timeline_file: Archivo de timeline
            
        Returns:
            Estadísticas del timeline
        """
        stats = {
            "total_events": 0,
            "date_range": {},
            "file_types": {},
            "activity_by_hour": {},
            "top_directories": []
        }
        
        try:
            if not timeline_file.exists():
                return stats
            
            from collections import Counter
            import re
            
            file_types = Counter()
            hours = Counter()
            directories = Counter()
            dates = []
            
            with open(timeline_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip() and not line.startswith('#'):
                        stats["total_events"] += 1
                        
                        # Parsear línea de mactime
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            # Fecha y hora (primer campo)
                            datetime_str = parts[0].strip()
                            if datetime_str:
                                try:
                                    # Extraer hora
                                    if ' ' in datetime_str:
                                        time_part = datetime_str.split(' ')[1]
                                        if ':' in time_part:
                                            hour = time_part.split(':')[0]
                                            hours[hour] += 1
                                    
                                    # Guardar fecha para rango
                                    dates.append(datetime_str)
                                except:
                                    pass
                            
                            # Nombre de archivo (último campo)
                            if len(parts) > 2:
                                filename = parts[-1].strip()
                                if filename:
                                    # Tipo de archivo
                                    if '.' in filename:
                                        ext = filename.split('.')[-1].lower()
                                        file_types[ext] += 1
                                    
                                    # Directorio
                                    if '/' in filename:
                                        directory = '/'.join(filename.split('/')[:-1])
                                        if directory:
                                            directories[directory] += 1
            
            # Procesar estadísticas
            stats["file_types"] = dict(file_types.most_common(10))
            stats["activity_by_hour"] = dict(hours)
            stats["top_directories"] = list(directories.most_common(10))
            
            # Rango de fechas
            if dates:
                stats["date_range"] = {
                    "start": min(dates),
                    "end": max(dates)
                }
            
        except Exception as e:
            logger.warning(f"Error analizando estadísticas del timeline: {e}")
        
        return stats
    
    def _find_deleted_files(
        self,
        image_path: Path,
        offset: Optional[int] = None,
        filesystem_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Buscar archivos eliminados en la partición.
        
        Args:
            image_path: Ruta de la imagen
            offset: Offset de la partición
            filesystem_type: Tipo de sistema de archivos
            
        Returns:
            Lista de archivos eliminados
        """
        cmd = [self.tsk_commands["fls"], "-r", "-d"]  # Recursivo y solo eliminados
        
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
                deleted_files = self._parse_fls_output(result.stdout)
                logger.info(f"Encontrados {len(deleted_files)} archivos eliminados")
                return deleted_files
            else:
                logger.warning(f"Error buscando archivos eliminados: {result.stderr}")
                return []
                
        except Exception as e:
            logger.error(f"Excepción buscando archivos eliminados: {e}")
            return []
    
    def _perform_security_analysis(
        self,
        files: List[Dict[str, Any]],
        deleted_files: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Realizar análisis de seguridad básico.
        
        Args:
            files: Lista de archivos activos
            deleted_files: Lista de archivos eliminados
            
        Returns:
            Resultados del análisis de seguridad
        """
        # Patrones sospechosos
        suspicious_patterns = [
            ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr",
            "temp", "tmp", "cache", "recent", "prefetch"
        ]
        
        malware_indicators = [
            "trojan", "virus", "malware", "backdoor", "keylog",
            "rootkit", "spyware", "adware", "ransomware"
        ]
        
        # Análisis de archivos activos
        suspicious_files = []
        executable_files = []
        system_files = []
        
        for file_info in files:
            filename = file_info.get("name", "").lower()
            
            # Archivos ejecutables
            if any(filename.endswith(ext) for ext in [".exe", ".dll", ".sys", ".bat", ".cmd"]):
                executable_files.append(file_info)
            
            # Archivos del sistema
            if any(pattern in filename for pattern in ["system32", "windows", "program files"]):
                system_files.append(file_info)
            
            # Archivos sospechosos
            if any(pattern in filename for pattern in suspicious_patterns + malware_indicators):
                suspicious_files.append(file_info)
        
        # Análisis de archivos eliminados
        deleted_suspicious = []
        for file_info in deleted_files:
            filename = file_info.get("name", "").lower()
            if any(pattern in filename for pattern in suspicious_patterns + malware_indicators):
                deleted_suspicious.append(file_info)
        
        return {
            "total_files": len(files),
            "total_deleted_files": len(deleted_files),
            "executable_files_count": len(executable_files),
            "system_files_count": len(system_files),
            "suspicious_files_count": len(suspicious_files),
            "deleted_suspicious_count": len(deleted_suspicious),
            "suspicious_files": suspicious_files[:10],  # Limitar a 10
            "deleted_suspicious": deleted_suspicious[:10],  # Limitar a 10
            "risk_level": self._calculate_risk_level(
                len(suspicious_files), len(deleted_suspicious), len(executable_files)
            )
        }
    
    def _calculate_risk_level(
        self,
        suspicious_count: int,
        deleted_suspicious_count: int,
        executable_count: int
    ) -> str:
        """Calcular nivel de riesgo basado en hallazgos.
        
        Args:
            suspicious_count: Número de archivos sospechosos
            deleted_suspicious_count: Número de archivos eliminados sospechosos
            executable_count: Número de archivos ejecutables
            
        Returns:
            Nivel de riesgo (low, medium, high, critical)
        """
        score = 0
        
        # Puntuación basada en archivos sospechosos
        score += suspicious_count * 2
        score += deleted_suspicious_count * 3  # Los eliminados son más sospechosos
        score += min(executable_count // 10, 5)  # Muchos ejecutables pueden ser sospechosos
        
        if score >= 20:
            return "critical"
        elif score >= 10:
            return "high"
        elif score >= 5:
            return "medium"
        else:
            return "low"
    
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
        """Parsear salida de mmls (método legacy, ahora integrado en _list_partitions).
        
        Args:
            output: Salida del comando mmls
            
        Returns:
            Lista de particiones parseadas
        """
        # Este método se mantiene por compatibilidad pero la lógica
        # se ha movido a _list_partitions para mejor manejo de errores
        partitions = []
        lines = output.split("\n")
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith("DOS") or line.startswith("Units") or ":" not in line:
                continue
            
            try:
                # Parsear línea de partición
                parts = line.split()
                if len(parts) >= 4:
                    slot = parts[0].rstrip(":")
                    start_sector = int(parts[1])
                    end_sector = int(parts[2])
                    length = int(parts[3])
                    description = " ".join(parts[4:]) if len(parts) > 4 else "Unknown"
                    
                    partition = {
                        "slot": slot,
                        "start_sector": start_sector,
                        "end_sector": end_sector,
                        "length_sectors": length,
                        "start_byte": start_sector * 512,
                        "size_bytes": length * 512,
                        "description": description,
                        "type": self._detect_partition_type(description)
                    }
                    
                    partitions.append(partition)
                    
            except (ValueError, IndexError) as e:
                logger.debug(f"Error parseando línea mmls '{line}': {e}")
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
            if not line or line.startswith("d/d"):
                continue
            
            try:
                # Formato con -l: r/r * 123: filename
                # Formato extendido puede incluir: permisos tamaño fecha filename
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                
                meta_part = parts[0].strip()
                filename_part = parts[1].strip()
                
                # Extraer información del meta_part
                file_info = {
                    "name": filename_part,
                    "meta_info": meta_part,
                    "path": filename_part,
                    "inode": None,
                    "type": "unknown",
                    "size": None,
                    "allocated": True,
                    "deleted": False
                }
                
                # Determinar tipo de archivo
                if meta_part.startswith("d/d"):
                    file_info["type"] = "directory"
                elif meta_part.startswith("r/r"):
                    file_info["type"] = "regular_file"
                elif meta_part.startswith("l/l"):
                    file_info["type"] = "symbolic_link"
                elif meta_part.startswith("-/-"):
                    file_info["type"] = "unknown"
                    file_info["deleted"] = True
                    file_info["allocated"] = False
                
                # Extraer número de inodo
                if "*" in meta_part:
                    try:
                        inode_part = meta_part.split("*")[-1].strip()
                        file_info["inode"] = int(inode_part)
                    except (ValueError, IndexError):
                        pass
                
                # Detectar archivos eliminados
                if "*" in meta_part and not file_info["deleted"]:
                    file_info["deleted"] = True
                    file_info["allocated"] = False
                
                # Extraer extensión
                if "." in filename_part:
                    file_info["extension"] = filename_part.split(".")[-1].lower()
                else:
                    file_info["extension"] = None
                
                # Categorizar archivo
                file_info["category"] = self._categorize_file(filename_part, file_info["extension"])
                
                # Detectar archivos del sistema
                file_info["is_system_file"] = self._is_system_file(filename_part)
                
                # Detectar archivos sospechosos
                file_info["is_suspicious"] = self._is_suspicious_file(filename_part)
                
                files.append(file_info)
                
            except Exception as e:
                logger.debug(f"Error parseando línea fls '{line}': {e}")
                continue
        
        return files
    
    def _parse_fsstat_output(self, output: str) -> Dict[str, Any]:
        """Parsear salida de fsstat.
        
        Args:
            output: Salida del comando fsstat
            
        Returns:
            Información parseada del sistema de archivos
        """
        fs_info = {
            "file_system_type": "unknown",
            "volume_label": None,
            "sector_size": None,
            "cluster_size": None,
            "total_sectors": None,
            "total_clusters": None,
            "free_clusters": None,
            "used_clusters": None,
            "root_directory_entries": None,
            "fat_entries": None,
            "serial_number": None,
            "creation_time": None,
            "last_mount_time": None,
            "features": [],
            "errors": [],
            "raw_output": output
        }
        
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Detectar tipo de sistema de archivos
            if "File System Type:" in line:
                fs_info["file_system_type"] = line.split(":", 1)[1].strip()
            elif "FILE SYSTEM INFORMATION" in line:
                if "NTFS" in line:
                    fs_info["file_system_type"] = "NTFS"
                elif "FAT" in line:
                    fs_info["file_system_type"] = "FAT"
                elif "EXT" in line:
                    fs_info["file_system_type"] = "EXT"
                elif "HFS" in line:
                    fs_info["file_system_type"] = "HFS+"
            
            # Información general
            elif "Volume Label:" in line or "Volume Name:" in line:
                fs_info["volume_label"] = line.split(":", 1)[1].strip()
            elif "Sector Size:" in line:
                try:
                    fs_info["sector_size"] = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif "Cluster Size:" in line or "Block Size:" in line:
                try:
                    fs_info["cluster_size"] = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif "Total Sectors:" in line:
                try:
                    fs_info["total_sectors"] = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif "Total Clusters:" in line or "Total Blocks:" in line:
                try:
                    fs_info["total_clusters"] = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif "Free Clusters:" in line or "Free Blocks:" in line:
                try:
                    fs_info["free_clusters"] = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif "Used Clusters:" in line or "Used Blocks:" in line:
                try:
                    fs_info["used_clusters"] = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif "Serial Number:" in line or "Volume Serial Number:" in line:
                fs_info["serial_number"] = line.split(":", 1)[1].strip()
            elif "Created:" in line or "Creation Time:" in line:
                fs_info["creation_time"] = line.split(":", 1)[1].strip()
            elif "Last Mount:" in line or "Last Mounted:" in line:
                fs_info["last_mount_time"] = line.split(":", 1)[1].strip()
            
            # Características específicas de NTFS
            elif "MFT Entry Size:" in line:
                try:
                    fs_info["mft_entry_size"] = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif "Index Entry Size:" in line:
                try:
                    fs_info["index_entry_size"] = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            
            # Características específicas de FAT
            elif "Root Directory Entries:" in line:
                try:
                    fs_info["root_directory_entries"] = int(line.split(":", 1)[1].strip())
                except (ValueError, IndexError):
                    pass
            elif "FAT Entries:" in line:
                try:
                    fs_info["fat_entries"] = int(line.split(":", 1)[1].strip())
                except (ValueError, IndexError):
                    pass
            
            # Detectar errores o inconsistencias
            elif any(keyword in line.lower() for keyword in ["error", "corrupt", "damaged", "inconsistent"]):
                fs_info["errors"].append(line)
            
            # Detectar características especiales
            elif any(keyword in line.lower() for keyword in ["journal", "encryption", "compression", "sparse"]):
                fs_info["features"].append(line)
            
            # Mantener compatibilidad con el parsing original
            elif line.endswith(":"):
                current_section = line[:-1].lower().replace(" ", "_")
                fs_info[current_section] = {}
            elif ":" in line and current_section:
                key, value = line.split(":", 1)
                fs_info[current_section][key.strip().lower().replace(" ", "_")] = value.strip()
            elif ":" in line:
                key, value = line.split(":", 1)
                fs_info[key.strip().lower().replace(" ", "_")] = value.strip()
        
        # Calcular estadísticas adicionales
        if fs_info["total_clusters"] and fs_info["free_clusters"]:
            fs_info["used_clusters"] = fs_info["total_clusters"] - fs_info["free_clusters"]
            fs_info["usage_percentage"] = round(
                (fs_info["used_clusters"] / fs_info["total_clusters"]) * 100, 2
            )
        
        if fs_info["cluster_size"] and fs_info["total_clusters"]:
            fs_info["total_size_bytes"] = fs_info["cluster_size"] * fs_info["total_clusters"]
            fs_info["total_size_mb"] = round(fs_info["total_size_bytes"] / (1024 * 1024), 2)
            fs_info["total_size_gb"] = round(fs_info["total_size_bytes"] / (1024 * 1024 * 1024), 2)
        
        if fs_info["cluster_size"] and fs_info["free_clusters"]:
            fs_info["free_size_bytes"] = fs_info["cluster_size"] * fs_info["free_clusters"]
            fs_info["free_size_mb"] = round(fs_info["free_size_bytes"] / (1024 * 1024), 2)
            fs_info["free_size_gb"] = round(fs_info["free_size_bytes"] / (1024 * 1024 * 1024), 2)
        
        # Detectar tipo automáticamente si no se encontró
        if fs_info["file_system_type"] == "unknown":
            if fs_info.get("mft_entry_size"):
                fs_info["file_system_type"] = "NTFS"
            elif fs_info.get("fat_entries"):
                fs_info["file_system_type"] = "FAT"
        
        return fs_info
    
    def _detect_partition_type(self, description: str) -> str:
        """Detectar tipo de partición basado en descripción.
        
        Args:
            description: Descripción de la partición
            
        Returns:
            Tipo de partición detectado
        """
        description_lower = description.lower()
        
        # Mapeo de descripciones comunes a tipos de sistema de archivos
        type_mappings = {
            'ntfs': 'ntfs',
            'fat32': 'fat32',
            'fat16': 'fat16', 
            'fat12': 'fat12',
            'ext4': 'ext4',
            'ext3': 'ext3',
            'ext2': 'ext2',
            'linux': 'ext4',  # Asumir ext4 para particiones Linux genéricas
            'swap': 'swap',
            'extended': 'extended',
            'hfs+': 'hfs+',
            'hfs': 'hfs',
            'apfs': 'apfs',
            'ufs': 'ufs',
            'dos': 'fat16',
            'win95': 'fat32',
            'microsoft': 'ntfs'
        }
        
        for keyword, fs_type in type_mappings.items():
            if keyword in description_lower:
                return fs_type
        
        return "unknown"
    
    def _get_filesystem_info(
        self,
        image_path: Path,
        partition_offset: int,
        filesystem_type: Optional[str],
        output_dir: Path
    ) -> Dict[str, Any]:
        """Obtener información del sistema de archivos.
        
        Args:
            image_path: Ruta de la imagen
            partition_offset: Offset de la partición en sectores
            filesystem_type: Tipo de sistema de archivos
            output_dir: Directorio de salida
            
        Returns:
            Información del sistema de archivos
        """
        cmd = [self.tsk_commands["fsstat"]]
        
        if partition_offset:
            cmd.extend(["-o", str(partition_offset)])
        
        if filesystem_type:
            cmd.extend(["-f", filesystem_type])
        
        cmd.append(str(image_path))
        
        try:
            logger.info(f"Ejecutando fsstat en offset {partition_offset}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Guardar salida raw
            fsstat_output = output_dir / "fsstat_output.txt"
            with open(fsstat_output, "w", encoding="utf-8") as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n\n=== STDERR ===\n")
                    f.write(result.stderr)
            
            if result.returncode == 0:
                fs_info = self._parse_fsstat_output(result.stdout)
                fs_info["raw_output_file"] = str(fsstat_output)
                fs_info["status"] = "success"
                logger.info(f"Información del sistema de archivos obtenida: {fs_info.get('file_system_type', 'unknown')}")
                return fs_info
            else:
                logger.warning(f"fsstat falló: {result.stderr}")
                return {
                    "filesystem_type": filesystem_type or "unknown",
                    "status": "failed",
                    "error": result.stderr,
                    "raw_output_file": str(fsstat_output)
                }
                
        except FileNotFoundError:
            logger.error("fsstat no encontrado. Instale The Sleuth Kit.")
            return {
                "filesystem_type": filesystem_type or "unknown",
                "status": "tool_not_found",
                "error": "fsstat executable not found"
            }
        except Exception as e:
            logger.error(f"Error ejecutando fsstat: {e}")
            return {
                "filesystem_type": filesystem_type or "unknown",
                "status": "error",
                "error": str(e)
            }
    
    def _categorize_file(self, filename: str, extension: Optional[str]) -> str:
        """Categorizar archivo por tipo.
        
        Args:
            filename: Nombre del archivo
            extension: Extensión del archivo
            
        Returns:
            Categoría del archivo
        """
        if not extension:
            if filename.lower() in ["..", "."]:
                return "directory_entry"
            return "no_extension"
        
        # Categorías de archivos
        categories = {
            "executable": ["exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "scr", "msi"],
            "document": ["doc", "docx", "pdf", "txt", "rtf", "odt", "xls", "xlsx", "ppt", "pptx"],
            "image": ["jpg", "jpeg", "png", "gif", "bmp", "tiff", "ico", "svg"],
            "video": ["mp4", "avi", "mkv", "mov", "wmv", "flv", "webm"],
            "audio": ["mp3", "wav", "flac", "aac", "ogg", "wma"],
            "archive": ["zip", "rar", "7z", "tar", "gz", "bz2", "xz"],
            "web": ["html", "htm", "css", "js", "php", "asp", "jsp"],
            "database": ["db", "sqlite", "mdb", "accdb", "dbf"],
            "log": ["log", "evt", "evtx"],
            "registry": ["reg", "dat"],
            "system": ["ini", "cfg", "conf", "config"]
        }
        
        for category, extensions in categories.items():
            if extension in extensions:
                return category
        
        return "other"
    
    def _is_system_file(self, filename: str) -> bool:
        """Detectar si es un archivo del sistema.
        
        Args:
            filename: Nombre del archivo
            
        Returns:
            True si es archivo del sistema
        """
        filename_lower = filename.lower()
        
        system_patterns = [
            "windows", "system32", "syswow64", "program files",
            "ntuser", "sam", "system", "security", "software",
            "bootmgr", "ntldr", "pagefile", "hiberfil",
            "$mft", "$logfile", "$volume", "$bitmap"
        ]
        
        return any(pattern in filename_lower for pattern in system_patterns)
    
    def _is_suspicious_file(self, filename: str) -> bool:
        """Detectar si es un archivo sospechoso.
        
        Args:
            filename: Nombre del archivo
            
        Returns:
            True si es archivo sospechoso
        """
        filename_lower = filename.lower()
        
        suspicious_patterns = [
            "temp", "tmp", "cache", "recent", "prefetch",
            "trojan", "virus", "malware", "backdoor", "keylog",
            "rootkit", "spyware", "adware", "ransomware",
            "crack", "keygen", "patch", "loader"
        ]
        
        suspicious_extensions = [
            "tmp", "temp", "bak", "old", "~"
        ]
        
        # Verificar patrones sospechosos
        if any(pattern in filename_lower for pattern in suspicious_patterns):
            return True
        
        # Verificar extensiones sospechosas
        if "." in filename:
            extension = filename.split(".")[-1].lower()
            if extension in suspicious_extensions:
                return True
        
        return False
    
    def _calculate_file_statistics(self, files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calcular estadísticas de archivos.
        
        Args:
            files: Lista de archivos
            
        Returns:
            Estadísticas calculadas
        """
        stats = {
            "total_files": len(files),
            "by_type": {},
            "by_category": {},
            "by_extension": {},
            "deleted_files": 0,
            "system_files": 0,
            "suspicious_files": 0,
            "largest_files": [],
            "most_common_extensions": []
        }
        
        # Contadores
        type_counts = {}
        category_counts = {}
        extension_counts = {}
        
        for file_info in files:
            # Por tipo
            file_type = file_info.get("type", "unknown")
            type_counts[file_type] = type_counts.get(file_type, 0) + 1
            
            # Por categoría
            category = file_info.get("category", "other")
            category_counts[category] = category_counts.get(category, 0) + 1
            
            # Por extensión
            extension = file_info.get("extension")
            if extension:
                extension_counts[extension] = extension_counts.get(extension, 0) + 1
            
            # Contadores especiales
            if file_info.get("deleted", False):
                stats["deleted_files"] += 1
            
            if file_info.get("is_system_file", False):
                stats["system_files"] += 1
            
            if file_info.get("is_suspicious", False):
                stats["suspicious_files"] += 1
        
        # Ordenar y limitar resultados
        stats["by_type"] = dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True))
        stats["by_category"] = dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True))
        stats["by_extension"] = dict(sorted(extension_counts.items(), key=lambda x: x[1], reverse=True))
        
        # Top 10 extensiones más comunes
        stats["most_common_extensions"] = list(stats["by_extension"].items())[:10]
        
        return stats
    
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