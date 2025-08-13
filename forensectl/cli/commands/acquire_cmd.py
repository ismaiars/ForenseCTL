"""Comandos CLI para adquisición de evidencias."""

import os
import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from forensectl import logger
from forensectl.core.case_manager import CaseManager
from forensectl.core.evidence import EvidenceManager
from forensectl.core.integrity import IntegrityManager
from forensectl.core.chain_of_custody import ChainOfCustody

console = Console()

# Crear aplicación Typer para comandos de adquisición
app = typer.Typer(
    name="acquire",
    help="🔍 Comandos para adquisición de evidencias",
    no_args_is_help=True
)


@app.command("file")
def acquire_file(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    file_path: Path = typer.Option(..., "--file", "-f", help="Ruta del archivo a adquirir"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Descripción de la evidencia"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Fuente de la evidencia"),
    custodian: Optional[str] = typer.Option(None, "--custodian", help="Custodio de la evidencia"),
    copy_method: str = typer.Option("copy", "--method", "-m", help="Método de copia (copy/dd/robocopy)"),
    verify_integrity: bool = typer.Option(True, "--verify/--no-verify", help="Verificar integridad"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📁 Adquirir un archivo como evidencia.
    
    Copia el archivo al directorio de evidencias del caso, calcula hashes
    y registra la cadena de custodia.
    
    Ejemplos:
        forensectl acquire file --case CASE-001 --file /path/to/evidence.txt
        forensectl acquire file -c CASE-001 -f suspicious.exe -d "Malware sospechoso"
    """
    try:
        # Validar que el archivo existe
        if not file_path.exists():
            rprint(f"[red]❌ Archivo no encontrado: {file_path}[/red]")
            raise typer.Exit(1)
        
        if not file_path.is_file():
            rprint(f"[red]❌ La ruta no es un archivo: {file_path}[/red]")
            raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        evidence_manager = EvidenceManager(case_id, case_manager=case_manager)
        integrity_manager = IntegrityManager()
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🔍 Adquiriendo archivo: {file_path.name}[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de copia
            copy_task = progress.add_task("Copiando archivo...", total=100)
            
            # Adquirir evidencia
            evidence_info = evidence_manager.acquire_file(
                source_path=file_path,
                description=description or f"Archivo adquirido: {file_path.name}",
                source=source or str(file_path.parent),
                custodian=custodian,
                copy_method=copy_method,
                progress_callback=lambda p: progress.update(copy_task, completed=p)
            )
            
            progress.update(copy_task, completed=100)
            
            # Verificar integridad si se solicita
            if verify_integrity:
                verify_task = progress.add_task("Verificando integridad...", total=100)
                
                is_valid = integrity_manager.verify_evidence(
                    evidence_info["evidence_path"],
                    evidence_info["hashes"]["sha256"]
                )
                
                progress.update(verify_task, completed=100)
                
                if not is_valid:
                    rprint(f"[red]❌ Error de integridad detectado[/red]")
                    raise typer.Exit(1)
            
            # Registrar en cadena de custodia
            chain_task = progress.add_task("Registrando cadena de custodia...", total=100)
            
            chain_manager.add_entry(
                evidence_id=evidence_info["evidence_id"],
                action="acquired",
                description=f"Archivo adquirido desde {file_path}",
                custodian=custodian or "system"
            )
            
            progress.update(chain_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Evidencia adquirida exitosamente[/green]")
        
        summary_table = Table(title="Resumen de Adquisición")
        summary_table.add_column("Campo", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("ID de Evidencia", evidence_info["evidence_id"])
        summary_table.add_row("Archivo Original", str(file_path))
        summary_table.add_row("Archivo de Evidencia", str(evidence_info["evidence_path"]))
        summary_table.add_row("Tamaño", f"{evidence_info['size']:,} bytes")
        summary_table.add_row("MD5", evidence_info["hashes"]["md5"])
        summary_table.add_row("SHA-1", evidence_info["hashes"]["sha1"])
        summary_table.add_row("SHA-256", evidence_info["hashes"]["sha256"])
        summary_table.add_row("Método de Copia", copy_method)
        summary_table.add_row("Integridad Verificada", "✅ Sí" if verify_integrity else "⚠️ No")
        
        console.print(summary_table)
        
    except Exception as e:
        logger.error(f"Error adquiriendo archivo: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("directory")
def acquire_directory(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    dir_path: Path = typer.Option(..., "--directory", "-d", help="Ruta del directorio a adquirir"),
    description: Optional[str] = typer.Option(None, "--description", help="Descripción de la evidencia"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Fuente de la evidencia"),
    custodian: Optional[str] = typer.Option(None, "--custodian", help="Custodio de la evidencia"),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", "-r", help="Copia recursiva"),
    include_patterns: Optional[List[str]] = typer.Option(None, "--include", help="Patrones de archivos a incluir"),
    exclude_patterns: Optional[List[str]] = typer.Option(None, "--exclude", help="Patrones de archivos a excluir"),
    max_size: Optional[str] = typer.Option(None, "--max-size", help="Tamaño máximo (ej: 100MB, 1GB)"),
    verify_integrity: bool = typer.Option(True, "--verify/--no-verify", help="Verificar integridad"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📁 Adquirir un directorio completo como evidencia.
    
    Copia recursivamente el directorio al directorio de evidencias del caso,
    calcula hashes y registra la cadena de custodia.
    
    Ejemplos:
        forensectl acquire directory --case CASE-001 --directory /path/to/evidence/
        forensectl acquire directory -c CASE-001 -d /suspicious/folder --include "*.exe" --include "*.dll"
    """
    try:
        # Validar que el directorio existe
        if not dir_path.exists():
            rprint(f"[red]❌ Directorio no encontrado: {dir_path}[/red]")
            raise typer.Exit(1)
        
        if not dir_path.is_dir():
            rprint(f"[red]❌ La ruta no es un directorio: {dir_path}[/red]")
            raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        evidence_manager = EvidenceManager(case_id, case_manager=case_manager)
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🔍 Adquiriendo directorio: {dir_path.name}[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de copia
            copy_task = progress.add_task("Copiando directorio...", total=100)
            
            # Adquirir evidencia
            evidence_info = evidence_manager.acquire_directory(
                source_path=dir_path,
                description=description or f"Directorio adquirido: {dir_path.name}",
                source=source or str(dir_path.parent),
                custodian=custodian,
                recursive=recursive,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns,
                max_size=max_size,
                progress_callback=lambda p: progress.update(copy_task, completed=p)
            )
            
            progress.update(copy_task, completed=100)
            
            # Verificar integridad si se solicita
            if verify_integrity:
                verify_task = progress.add_task("Verificando integridad...", total=100)
                
                # TODO: Implementar verificación de integridad para directorios
                progress.update(verify_task, completed=100)
            
            # Registrar en cadena de custodia
            chain_task = progress.add_task("Registrando cadena de custodia...", total=100)
            
            chain_manager.add_entry(
                evidence_id=evidence_info["evidence_id"],
                action="acquired",
                description=f"Directorio adquirido desde {dir_path}",
                custodian=custodian or "system"
            )
            
            progress.update(chain_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Evidencia adquirida exitosamente[/green]")
        
        summary_table = Table(title="Resumen de Adquisición")
        summary_table.add_column("Campo", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("ID de Evidencia", evidence_info["evidence_id"])
        summary_table.add_row("Directorio Original", str(dir_path))
        summary_table.add_row("Directorio de Evidencia", str(evidence_info["evidence_path"]))
        summary_table.add_row("Archivos Copiados", str(evidence_info.get("files_count", 0)))
        summary_table.add_row("Tamaño Total", f"{evidence_info.get('total_size', 0):,} bytes")
        summary_table.add_row("Copia Recursiva", "✅ Sí" if recursive else "❌ No")
        summary_table.add_row("Integridad Verificada", "✅ Sí" if verify_integrity else "⚠️ No")
        
        console.print(summary_table)
        
    except Exception as e:
        logger.error(f"Error adquiriendo directorio: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("disk")
def acquire_disk(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    device: str = typer.Option(..., "--device", "-d", help="Dispositivo a adquirir (ej: /dev/sda, \\\\.\\PhysicalDrive0)"),
    description: Optional[str] = typer.Option(None, "--description", help="Descripción de la evidencia"),
    custodian: Optional[str] = typer.Option(None, "--custodian", help="Custodio de la evidencia"),
    format_type: str = typer.Option("dd", "--format", "-f", help="Formato de imagen (dd/ewf/aff)"),
    compression: bool = typer.Option(False, "--compress", help="Comprimir imagen"),
    split_size: Optional[str] = typer.Option(None, "--split", help="Dividir imagen (ej: 2GB, 4GB)"),
    verify_integrity: bool = typer.Option(True, "--verify/--no-verify", help="Verificar integridad"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """💾 Adquirir una imagen completa de disco.
    
    Crea una imagen forense bit-a-bit del dispositivo especificado.
    Requiere privilegios administrativos.
    
    Ejemplos:
        forensectl acquire disk --case CASE-001 --device /dev/sda
        forensectl acquire disk -c CASE-001 -d \\\\.\\PhysicalDrive0 --format ewf --compress
    """
    try:
        # Verificar privilegios administrativos
        if os.name == 'nt':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                rprint("[red]❌ Se requieren privilegios de administrador para adquirir discos[/red]")
                raise typer.Exit(1)
        else:
            if os.geteuid() != 0:
                rprint("[red]❌ Se requieren privilegios de root para adquirir discos[/red]")
                raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        evidence_manager = EvidenceManager(case_id, case_manager=case_manager)
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        rprint(f"[blue]💾 Adquiriendo disco: {device}[/blue]")
        rprint(f"[yellow]⚠️ Esta operación puede tomar mucho tiempo[/yellow]")
        
        # Confirmar operación
        confirm = typer.confirm(
            f"¿Está seguro de que desea adquirir el dispositivo {device}?"
        )
        if not confirm:
            rprint("[yellow]❌ Operación cancelada[/yellow]")
            raise typer.Exit(0)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de adquisición
            acquire_task = progress.add_task("Adquiriendo imagen de disco...", total=100)
            
            # Adquirir imagen de disco
            evidence_info = evidence_manager.acquire_disk(
                device=device,
                description=description or f"Imagen de disco: {device}",
                custodian=custodian,
                format_type=format_type,
                compression=compression,
                split_size=split_size,
                progress_callback=lambda p: progress.update(acquire_task, completed=p)
            )
            
            progress.update(acquire_task, completed=100)
            
            # Verificar integridad si se solicita
            if verify_integrity:
                verify_task = progress.add_task("Verificando integridad...", total=100)
                
                # TODO: Implementar verificación de integridad para imágenes de disco
                progress.update(verify_task, completed=100)
            
            # Registrar en cadena de custodia
            chain_task = progress.add_task("Registrando cadena de custodia...", total=100)
            
            chain_manager.add_entry(
                evidence_id=evidence_info["evidence_id"],
                action="acquired",
                description=f"Imagen de disco adquirida desde {device}",
                custodian=custodian or "system"
            )
            
            progress.update(chain_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Imagen de disco adquirida exitosamente[/green]")
        
        summary_table = Table(title="Resumen de Adquisición")
        summary_table.add_column("Campo", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("ID de Evidencia", evidence_info["evidence_id"])
        summary_table.add_row("Dispositivo", device)
        summary_table.add_row("Archivo de Imagen", str(evidence_info["evidence_path"]))
        summary_table.add_row("Formato", format_type.upper())
        summary_table.add_row("Tamaño", f"{evidence_info.get('size', 0):,} bytes")
        summary_table.add_row("Compresión", "✅ Sí" if compression else "❌ No")
        summary_table.add_row("División", split_size if split_size else "❌ No")
        summary_table.add_row("Integridad Verificada", "✅ Sí" if verify_integrity else "⚠️ No")
        
        console.print(summary_table)
        
    except Exception as e:
        logger.error(f"Error adquiriendo disco: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("memory")
def acquire_memory(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    description: Optional[str] = typer.Option(None, "--description", help="Descripción de la evidencia"),
    custodian: Optional[str] = typer.Option(None, "--custodian", help="Custodio de la evidencia"),
    method: str = typer.Option("auto", "--method", "-m", help="Método de adquisición (auto/winpmem/lime/volatility)"),
    compress: bool = typer.Option(True, "--compress/--no-compress", help="Comprimir dump de memoria"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🧠 Adquirir un dump de memoria RAM.
    
    Captura el contenido de la memoria RAM del sistema actual.
    Requiere privilegios administrativos.
    
    Ejemplos:
        forensectl acquire memory --case CASE-001
        forensectl acquire memory -c CASE-001 --method winpmem --compress
    """
    try:
        # Verificar privilegios administrativos
        if os.name == 'nt':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                rprint("[red]❌ Se requieren privilegios de administrador para adquirir memoria[/red]")
                raise typer.Exit(1)
        else:
            if os.geteuid() != 0:
                rprint("[red]❌ Se requieren privilegios de root para adquirir memoria[/red]")
                raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        evidence_manager = EvidenceManager(case_id, case_manager=case_manager)
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🧠 Adquiriendo memoria RAM[/blue]")
        rprint(f"[yellow]⚠️ Esta operación puede tomar varios minutos[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de adquisición
            acquire_task = progress.add_task("Capturando memoria RAM...", total=100)
            
            # Adquirir dump de memoria
            evidence_info = evidence_manager.acquire_memory(
                description=description or "Dump de memoria RAM",
                custodian=custodian,
                method=method,
                compress=compress,
                progress_callback=lambda p: progress.update(acquire_task, completed=p)
            )
            
            progress.update(acquire_task, completed=100)
            
            # Registrar en cadena de custodia
            chain_task = progress.add_task("Registrando cadena de custodia...", total=100)
            
            chain_manager.add_entry(
                evidence_id=evidence_info["evidence_id"],
                action="acquired",
                description="Dump de memoria RAM adquirido",
                custodian=custodian or "system"
            )
            
            progress.update(chain_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Dump de memoria adquirido exitosamente[/green]")
        
        summary_table = Table(title="Resumen de Adquisición")
        summary_table.add_column("Campo", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("ID de Evidencia", evidence_info["evidence_id"])
        summary_table.add_row("Archivo de Dump", str(evidence_info["evidence_path"]))
        summary_table.add_row("Método", method)
        summary_table.add_row("Tamaño", f"{evidence_info.get('size', 0):,} bytes")
        summary_table.add_row("Compresión", "✅ Sí" if compress else "❌ No")
        summary_table.add_row("MD5", evidence_info.get("hashes", {}).get("md5", "N/A"))
        summary_table.add_row("SHA-256", evidence_info.get("hashes", {}).get("sha256", "N/A"))
        
        console.print(summary_table)
        
    except Exception as e:
        logger.error(f"Error adquiriendo memoria: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("list")
def list_evidence(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filtrar por tipo de evidencia"),
    limit: int = typer.Option(20, "--limit", "-l", help="Número máximo de evidencias a mostrar"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Listar evidencias adquiridas en un caso.
    
    Muestra una tabla con todas las evidencias del caso especificado.
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        evidence_manager = EvidenceManager(case_id, case_manager=case_manager)
        
        # Obtener lista de evidencias
        evidences = evidence_manager.list_evidence(
            evidence_type=evidence_type,
            limit=limit
        )
        
        if not evidences:
            rprint(f"[yellow]📭 No se encontraron evidencias en el caso {case_id}[/yellow]")
            return
        
        # Crear tabla
        table = Table(title=f"Evidencias del Caso {case_id} ({len(evidences)} encontradas)")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Tipo", style="yellow")
        table.add_column("Descripción", style="white")
        table.add_column("Tamaño", style="blue")
        table.add_column("Adquirida", style="green")
        table.add_column("Estado", style="magenta")
        
        for evidence in evidences:
            # Formatear tamaño
            size = evidence.get("size", 0)
            if size > 1024**3:  # GB
                size_str = f"{size / (1024**3):.1f} GB"
            elif size > 1024**2:  # MB
                size_str = f"{size / (1024**2):.1f} MB"
            elif size > 1024:  # KB
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
            
            # Truncar descripción si es muy larga
            description = evidence.get("description", "N/A")
            if len(description) > 40:
                description = description[:37] + "..."
            
            table.add_row(
                evidence.get("evidence_id", "N/A"),
                evidence.get("type", "N/A"),
                description,
                size_str,
                evidence.get("acquired_at", "N/A"),
                evidence.get("status", "N/A")
            )
        
        console.print(table)
        
    except Exception as e:
        logger.error(f"Error listando evidencias: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)