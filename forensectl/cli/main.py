"""CLI principal de ForenseCTL."""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from forensectl import __version__, logger
from forensectl.core.case_manager import CaseManager
from forensectl.core.config import get_settings
from forensectl.analysis import MemoryAnalyzer, DiskAnalyzer, TimelineBuilder, YaraScanner, ArtifactExtractor
from forensectl.reports import ReportGenerator
from forensectl.cli.commands import (
    case_cmd,
    evidence_cmd,
    acquire_cmd,
    analyze_cmd,
    timeline_cmd,
    yara_cmd,
    report_cmd,
    chain_cmd,
    verify_cmd,
    retention_cmd,
    workflow_cmd
)

# Configurar consola Rich
console = Console()

# Crear aplicación Typer principal
app = typer.Typer(
    name="forensectl",
    help="🔍 ForenseCTL - Herramienta de Análisis Forense Automatizado",
    epilog="Para más información: https://github.com/tu-org/forensectl",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=True
)

# Registrar subcomandos
app.add_typer(case_cmd.app, name="case", help="📁 Gestión de casos forenses")
app.add_typer(evidence_cmd.app, name="evidence", help="🗂️ Gestión de evidencias")
app.add_typer(acquire_cmd.app, name="acquire", help="🔍 Adquisición de evidencias")
app.add_typer(analyze_cmd.app, name="analyze", help="🧠 Análisis forense")
app.add_typer(timeline_cmd.app, name="timeline", help="⏱️ Construcción de timeline")
app.add_typer(yara_cmd.app, name="yara", help="🦠 Detección con YARA")
app.add_typer(report_cmd.app, name="report", help="📊 Generación de reportes")
app.add_typer(chain_cmd.app, name="chain", help="🔗 Cadena de custodia")
app.add_typer(verify_cmd.app, name="verify", help="✅ Verificación de integridad")
app.add_typer(retention_cmd.app, name="retention", help="🗑️ Gestión de retención")
app.add_typer(workflow_cmd.app, name="workflow", help="🔄 Workflows automatizados")


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", "-v", help="Mostrar versión"),
    verbose: bool = typer.Option(False, "--verbose", help="Modo verbose"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Modo silencioso"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Archivo de configuración")
) -> None:
    """ForenseCTL - Herramienta de Análisis Forense Automatizado.
    
    Una plataforma profesional que automatiza el ciclo completo de investigación forense:
    adquisición → preservación → análisis → timeline → reporte.
    """
    if version:
        rprint(f"[bold blue]ForenseCTL[/bold blue] versión [green]{__version__}[/green]")
        raise typer.Exit()
    
    # Configurar logging según opciones
    if verbose:
        logger.setLevel("DEBUG")
    elif quiet:
        logger.setLevel("ERROR")
    
    # Cargar configuración personalizada si se especifica
    if config_file:
        if not config_file.exists():
            rprint(f"[red]❌ Archivo de configuración no encontrado: {config_file}[/red]")
            raise typer.Exit(1)
        # TODO: Implementar carga de configuración personalizada
        logger.info(f"Cargando configuración desde: {config_file}")


@app.command("init-case")
def init_case(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso (ej: CASE-20250812-ORG-INCIDENT)"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Nombre del examinador"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Descripción del caso"),
    organization: Optional[str] = typer.Option(None, "--organization", "-o", help="Organización"),
    incident_type: Optional[str] = typer.Option(None, "--type", "-t", help="Tipo de incidente"),
    priority: str = typer.Option("medium", "--priority", "-p", help="Prioridad (low/medium/high/critical)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🆕 Inicializar un nuevo caso forense.
    
    Crea la estructura de directorios, manifiestos iniciales y cadena de custodia.
    
    Ejemplos:
        forensectl init-case --case CASE-20250812-ACME-MALWARE --examiner "John Doe"
        forensectl init-case -c CASE-001 -e "Jane Smith" -d "Análisis de ransomware"
    """
    try:
        settings = get_settings()
        
        # Usar directorio de trabajo personalizado o por defecto
        if work_dir:
            case_manager = CaseManager(work_dir=work_dir)
        else:
            case_manager = CaseManager()
        
        # Validar formato de case_id
        if not case_manager.validate_case_id(case_id):
            rprint(f"[red]❌ Formato de case_id inválido: {case_id}[/red]")
            rprint("[yellow]Formato esperado: CASE-YYYYMMDD-ORG-INCIDENT[/yellow]")
            raise typer.Exit(1)
        
        # Verificar si el caso ya existe
        if case_manager.case_exists(case_id):
            rprint(f"[red]❌ El caso {case_id} ya existe[/red]")
            raise typer.Exit(1)
        
        # Crear caso
        case_info = {
            "case_id": case_id,
            "examiner": examiner,
            "description": description or f"Caso forense {case_id}",
            "organization": organization or settings.organization,
            "incident_type": incident_type or "unknown",
            "priority": priority
        }
        
        case_path = case_manager.create_case(**case_info)
        
        # Mostrar información del caso creado
        rprint(f"[green]✅ Caso {case_id} creado exitosamente[/green]")
        rprint(f"[blue]📁 Directorio: {case_path}[/blue]")
        
        # Mostrar estructura creada
        table = Table(title="Estructura del Caso")
        table.add_column("Directorio", style="cyan")
        table.add_column("Propósito", style="white")
        
        table.add_row("evidence/", "Evidencias originales")
        table.add_row("analysis/", "Resultados de análisis")
        table.add_row("reports/", "Reportes generados")
        table.add_row("manifests/", "Manifiestos y metadatos")
        table.add_row("chain/", "Cadena de custodia")
        table.add_row("temp/", "Archivos temporales")
        
        console.print(table)
        
        rprint("\n[yellow]💡 Próximos pasos:[/yellow]")
        rprint(f"  1. Adquirir evidencias: [cyan]forensectl acquire --case {case_id}[/cyan]")
        rprint(f"  2. Analizar evidencias: [cyan]forensectl analyze --case {case_id}[/cyan]")
        rprint(f"  3. Generar reporte: [cyan]forensectl report build --case {case_id}[/cyan]")
        
    except Exception as e:
        logger.error(f"Error inicializando caso: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("list-cases")
def list_cases(
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filtrar por estado"),
    examiner: Optional[str] = typer.Option(None, "--examiner", "-e", help="Filtrar por examinador"),
    limit: int = typer.Option(20, "--limit", "-l", help="Número máximo de casos a mostrar"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Listar casos existentes.
    
    Muestra una tabla con información básica de los casos.
    """
    try:
        if work_dir:
            case_manager = CaseManager(work_dir=work_dir)
        else:
            case_manager = CaseManager()
        
        cases = case_manager.list_cases(status=status, examiner=examiner, limit=limit)
        
        if not cases:
            rprint("[yellow]📭 No se encontraron casos[/yellow]")
            return
        
        # Crear tabla
        table = Table(title=f"Casos Forenses ({len(cases)} encontrados)")
        table.add_column("Case ID", style="cyan", no_wrap=True)
        table.add_column("Examinador", style="green")
        table.add_column("Estado", style="yellow")
        table.add_column("Creado", style="blue")
        table.add_column("Descripción", style="white")
        
        for case in cases:
            table.add_row(
                case.get("case_id", "N/A"),
                case.get("examiner", "N/A"),
                case.get("status", "N/A"),
                case.get("created_at", "N/A"),
                case.get("description", "N/A")[:50] + "..." if len(case.get("description", "")) > 50 else case.get("description", "N/A")
            )
        
        console.print(table)
        
    except Exception as e:
        logger.error(f"Error listando casos: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("case-info")
def case_info(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """ℹ️ Mostrar información detallada de un caso.
    
    Incluye metadatos, evidencias, análisis realizados y estado de la cadena de custodia.
    """
    try:
        if work_dir:
            case_manager = CaseManager(work_dir=work_dir)
        else:
            case_manager = CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        case_info = case_manager.get_case_info(case_id)
        
        # Información básica
        rprint(f"[bold blue]📋 Información del Caso: {case_id}[/bold blue]\n")
        
        basic_table = Table(title="Información Básica")
        basic_table.add_column("Campo", style="cyan")
        basic_table.add_column("Valor", style="white")
        
        for key, value in case_info.get("basic", {}).items():
            basic_table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(basic_table)
        
        # Evidencias
        evidences = case_info.get("evidences", [])
        if evidences:
            rprint("\n[bold green]📁 Evidencias:[/bold green]")
            evidence_table = Table()
            evidence_table.add_column("Archivo", style="cyan")
            evidence_table.add_column("Tipo", style="yellow")
            evidence_table.add_column("Tamaño", style="blue")
            evidence_table.add_column("Hash SHA-256", style="green")
            
            for evidence in evidences:
                evidence_table.add_row(
                    evidence.get("filename", "N/A"),
                    evidence.get("type", "N/A"),
                    evidence.get("size", "N/A"),
                    evidence.get("sha256", "N/A")[:16] + "..." if evidence.get("sha256") else "N/A"
                )
            
            console.print(evidence_table)
        
        # Análisis realizados
        analyses = case_info.get("analyses", [])
        if analyses:
            rprint("\n[bold yellow]🧠 Análisis Realizados:[/bold yellow]")
            analysis_table = Table()
            analysis_table.add_column("Tipo", style="cyan")
            analysis_table.add_column("Estado", style="yellow")
            analysis_table.add_column("Fecha", style="blue")
            analysis_table.add_column("Resultados", style="green")
            
            for analysis in analyses:
                analysis_table.add_row(
                    analysis.get("type", "N/A"),
                    analysis.get("status", "N/A"),
                    analysis.get("timestamp", "N/A"),
                    str(analysis.get("results_count", 0)) + " archivos"
                )
            
            console.print(analysis_table)
        
        # Estadísticas
        stats = case_info.get("statistics", {})
        if stats:
            rprint("\n[bold magenta]📊 Estadísticas:[/bold magenta]")
            stats_table = Table()
            stats_table.add_column("Métrica", style="cyan")
            stats_table.add_column("Valor", style="white")
            
            for key, value in stats.items():
                stats_table.add_row(key.replace("_", " ").title(), str(value))
            
            console.print(stats_table)
        
    except Exception as e:
        logger.error(f"Error obteniendo información del caso: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("status")
def status(
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="ID del caso específico"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📊 Mostrar estado general del sistema.
    
    Incluye información sobre casos activos, recursos del sistema y servicios.
    """
    try:
        settings = get_settings()
        
        rprint("[bold blue]🔍 Estado del Sistema ForenseCTL[/bold blue]\n")
        
        # Información del sistema
        system_table = Table(title="Información del Sistema")
        system_table.add_column("Componente", style="cyan")
        system_table.add_column("Estado", style="green")
        system_table.add_column("Información", style="white")
        
        system_table.add_row("ForenseCTL", "✅ Activo", f"v{__version__}")
        system_table.add_row("Python", "✅ Activo", f"{sys.version.split()[0]}")
        system_table.add_row("Directorio de Trabajo", "✅ Configurado", str(settings.work_dir))
        system_table.add_row("Organización", "✅ Configurado", settings.organization)
        
        console.print(system_table)
        
        # Casos activos
        if work_dir:
            case_manager = CaseManager(work_dir=work_dir)
        else:
            case_manager = CaseManager()
        
        if case_id:
            # Estado de caso específico
            if case_manager.case_exists(case_id):
                rprint(f"\n[bold green]📋 Estado del Caso: {case_id}[/bold green]")
                # TODO: Implementar estado detallado del caso
                rprint(f"[green]✅ Caso {case_id} encontrado y accesible[/green]")
            else:
                rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
        else:
            # Resumen de todos los casos
            cases = case_manager.list_cases(limit=5)
            if cases:
                rprint(f"\n[bold yellow]📋 Casos Recientes ({len(cases)} de últimos 5):[/bold yellow]")
                for case in cases:
                    status_icon = "🟢" if case.get("status") == "active" else "🟡"
                    rprint(f"  {status_icon} {case.get('case_id')} - {case.get('examiner')}")
            else:
                rprint("\n[yellow]📭 No hay casos activos[/yellow]")
        
        # TODO: Agregar estado de servicios (Docker, bases de datos, etc.)
        
    except Exception as e:
        logger.error(f"Error obteniendo estado: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("self-check")
def self_check() -> None:
    """🔧 Verificar configuración y dependencias del sistema.
    
    Ejecuta una serie de verificaciones para asegurar que ForenseCTL
    está correctamente configurado y todas las dependencias están disponibles.
    """
    try:
        rprint("[bold blue]🔧 Verificación del Sistema ForenseCTL[/bold blue]\n")
        
        checks = []
        
        # Verificar configuración
        try:
            settings = get_settings()
            checks.append(("Configuración", True, "Cargada correctamente"))
        except Exception as e:
            checks.append(("Configuración", False, f"Error: {e}"))
        
        # Verificar directorio de trabajo
        try:
            work_dir = Path(settings.work_dir)
            if work_dir.exists() and work_dir.is_dir():
                checks.append(("Directorio de Trabajo", True, str(work_dir)))
            else:
                checks.append(("Directorio de Trabajo", False, f"No existe: {work_dir}"))
        except Exception as e:
            checks.append(("Directorio de Trabajo", False, f"Error: {e}"))
        
        # Verificar herramientas forenses
        tools = [
            ("Volatility3", "vol"),
            ("The Sleuth Kit", "fls"),
            ("plaso", "log2timeline.py"),
            ("YARA", "yara")
        ]
        
        for tool_name, command in tools:
            try:
                import subprocess
                result = subprocess.run([command, "--version"], 
                                      capture_output=True, timeout=10)
                if result.returncode == 0:
                    checks.append((tool_name, True, "Disponible"))
                else:
                    checks.append((tool_name, False, "No responde"))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                checks.append((tool_name, False, "No encontrado"))
            except Exception as e:
                checks.append((tool_name, False, f"Error: {e}"))
        
        # Mostrar resultados
        check_table = Table(title="Resultados de Verificación")
        check_table.add_column("Componente", style="cyan")
        check_table.add_column("Estado", style="white")
        check_table.add_column("Detalles", style="white")
        
        all_passed = True
        for component, passed, details in checks:
            status = "✅ OK" if passed else "❌ FALLO"
            status_style = "green" if passed else "red"
            check_table.add_row(component, f"[{status_style}]{status}[/{status_style}]", details)
            if not passed:
                all_passed = False
        
        console.print(check_table)
        
        if all_passed:
            rprint("\n[bold green]✅ Todas las verificaciones pasaron correctamente[/bold green]")
            rprint("[green]🚀 ForenseCTL está listo para usar[/green]")
        else:
            rprint("\n[bold red]❌ Algunas verificaciones fallaron[/bold red]")
            rprint("[yellow]💡 Revisar la documentación de instalación[/yellow]")
            raise typer.Exit(1)
        
    except Exception as e:
        logger.error(f"Error en verificación del sistema: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()