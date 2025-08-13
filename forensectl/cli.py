"""CLI principal de forensectl - Herramienta de análisis forense digital automatizado."""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm

from forensectl import __version__, config, logger
from forensectl.core.case_manager import CaseManager
from forensectl.core.integrity import IntegrityVerifier
from forensectl.core.chain_of_custody import ChainOfCustody

# Console para output rico
console = Console()

# Configuración global de Click
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=__version__, prog_name="forensectl")
@click.option(
    "--verbose", "-v", 
    is_flag=True, 
    help="Habilitar logging detallado"
)
@click.option(
    "--config-file", 
    type=click.Path(exists=True), 
    help="Archivo de configuración personalizado"
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config_file: Optional[str]) -> None:
    """🔍 Forense-Automatizado-BlueTeam - Análisis forense digital profesional.
    
    Automatiza el ciclo completo: adquisición → preservación → análisis → timeline → reporte.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config_file"] = config_file
    
    if verbose:
        import logging
        logging.getLogger("forensectl").setLevel(logging.DEBUG)
        logger.debug("Modo verbose habilitado")
    
    # Mostrar banner
    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(
            "[bold blue]🔍 Forense-Automatizado-BlueTeam[/bold blue]\n"
            f"[dim]Versión {__version__}[/dim]\n\n"
            "[green]Análisis forense digital profesional[/green]\n"
            "[yellow]Usa --help para ver comandos disponibles[/yellow]",
            title="Forensectl",
            border_style="blue"
        ))


@cli.group()
def case() -> None:
    """Gestión de casos forenses."""
    pass


@case.command("init")
@click.option(
    "--case", "-c", 
    required=True, 
    help="ID del caso (formato: CASE-YYYYMMDD-ORG-INCIDENT)"
)
@click.option(
    "--examiner", "-e", 
    required=True, 
    help="Nombre del examinador forense"
)
@click.option(
    "--org", "-o", 
    required=True, 
    help="Organización"
)
@click.option(
    "--description", "-d", 
    help="Descripción del caso"
)
@click.option(
    "--timezone", "-tz", 
    default="UTC", 
    help="Zona horaria del caso"
)
def init_case(
    case: str, 
    examiner: str, 
    org: str, 
    description: Optional[str], 
    timezone: str
) -> None:
    """Inicializar un nuevo caso forense."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Inicializando caso...", total=None)
            
            case_manager = CaseManager()
            case_info = case_manager.create_case(
                case_id=case,
                examiner=examiner,
                organization=org,
                description=description or f"Caso forense {case}",
                timezone=timezone
            )
            
            progress.update(task, description="Creando estructura de directorios...")
            case_manager.setup_case_structure(case)
            
            progress.update(task, description="Inicializando cadena de custodia...")
            chain = ChainOfCustody(case)
            chain.add_entry(
                action="case_created",
                description=f"Caso inicializado por {examiner}",
                examiner=examiner
            )
        
        console.print(f"\n[green]✅ Caso {case} inicializado exitosamente[/green]")
        console.print(f"[dim]Directorio: {config.CASES_DIR / case}[/dim]")
        
        # Mostrar estructura creada
        table = Table(title="Estructura del Caso")
        table.add_column("Directorio", style="cyan")
        table.add_column("Propósito", style="white")
        
        directories = [
            ("evidence/", "Evidencias digitales"),
            ("analysis/", "Resultados de análisis"),
            ("reports/", "Reportes generados"),
            ("manifests/", "Manifiestos de integridad"),
            ("chain/", "Cadena de custodia"),
            ("logs/", "Logs de procesamiento")
        ]
        
        for directory, purpose in directories:
            table.add_row(directory, purpose)
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]❌ Error inicializando caso: {e}[/red]")
        logger.error(f"Error en init_case: {e}")
        sys.exit(1)


@case.command("status")
@click.option(
    "--case", "-c", 
    required=True, 
    help="ID del caso"
)
def case_status(case: str) -> None:
    """Mostrar estado del caso."""
    try:
        case_manager = CaseManager()
        case_info = case_manager.get_case_info(case)
        
        if not case_info:
            console.print(f"[red]❌ Caso {case} no encontrado[/red]")
            sys.exit(1)
        
        # Panel principal con información del caso
        info_text = (
            f"[bold]ID:[/bold] {case_info['case_id']}\n"
            f"[bold]Examinador:[/bold] {case_info['examiner']}\n"
            f"[bold]Organización:[/bold] {case_info['organization']}\n"
            f"[bold]Creado:[/bold] {case_info['created_at']}\n"
            f"[bold]Zona Horaria:[/bold] {case_info['timezone']}\n"
            f"[bold]Descripción:[/bold] {case_info['description']}"
        )
        
        console.print(Panel(
            info_text,
            title=f"[bold blue]Caso {case}[/bold blue]",
            border_style="blue"
        ))
        
        # Estadísticas de evidencias
        case_dir = config.CASES_DIR / case
        evidence_dir = case_dir / "evidence"
        analysis_dir = case_dir / "analysis"
        reports_dir = case_dir / "reports"
        
        stats_table = Table(title="Estadísticas")
        stats_table.add_column("Categoría", style="cyan")
        stats_table.add_column("Cantidad", style="green")
        stats_table.add_column("Tamaño", style="yellow")
        
        # Contar archivos y calcular tamaños
        def get_dir_stats(directory: Path) -> tuple[int, int]:
            if not directory.exists():
                return 0, 0
            files = list(directory.rglob("*"))
            file_count = len([f for f in files if f.is_file()])
            total_size = sum(f.stat().st_size for f in files if f.is_file())
            return file_count, total_size
        
        def format_size(size_bytes: int) -> str:
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.1f} PB"
        
        evidence_count, evidence_size = get_dir_stats(evidence_dir)
        analysis_count, analysis_size = get_dir_stats(analysis_dir)
        reports_count, reports_size = get_dir_stats(reports_dir)
        
        stats_table.add_row("Evidencias", str(evidence_count), format_size(evidence_size))
        stats_table.add_row("Análisis", str(analysis_count), format_size(analysis_size))
        stats_table.add_row("Reportes", str(reports_count), format_size(reports_size))
        
        console.print(stats_table)
        
    except Exception as e:
        console.print(f"[red]❌ Error obteniendo estado del caso: {e}[/red]")
        logger.error(f"Error en case_status: {e}")
        sys.exit(1)


@cli.command()
@click.option(
    "--profile", "-p", 
    type=click.Choice(["windows", "linux", "mac"]), 
    required=True,
    help="Perfil de adquisición"
)
@click.option(
    "--scope", "-s", 
    type=click.Choice(["live", "image"]), 
    required=True,
    help="Tipo de adquisición"
)
@click.option(
    "--target", "-t", 
    required=True,
    help="Objetivo (hostname, device, imagen)"
)
@click.option(
    "--case", "-c", 
    required=True,
    help="ID del caso"
)
@click.option(
    "--output", "-o", 
    help="Directorio de salida personalizado"
)
def acquire(
    profile: str, 
    scope: str, 
    target: str, 
    case: str, 
    output: Optional[str]
) -> None:
    """Adquirir evidencias digitales."""
    try:
        console.print(f"[blue]🔍 Iniciando adquisición {scope} para perfil {profile}[/blue]")
        console.print(f"[dim]Objetivo: {target}[/dim]")
        console.print(f"[dim]Caso: {case}[/dim]")
        
        # TODO: Implementar módulos de adquisición
        console.print("[yellow]⚠️  Módulo de adquisición en desarrollo[/yellow]")
        console.print("[dim]Próximamente: adquisición automática con validación de integridad[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error en adquisición: {e}[/red]")
        logger.error(f"Error en acquire: {e}")
        sys.exit(1)


@cli.command()
@click.option(
    "--path", "-p", 
    required=True,
    type=click.Path(exists=True),
    help="Ruta del archivo o directorio a verificar"
)
@click.option(
    "--recursive", "-r", 
    is_flag=True,
    help="Verificación recursiva"
)
def verify(path: str, recursive: bool) -> None:
    """Verificar integridad de evidencias."""
    try:
        console.print(f"[blue]🔐 Verificando integridad: {path}[/blue]")
        
        verifier = IntegrityVerifier()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Verificando...", total=None)
            
            result = verifier.verify_path(Path(path), recursive=recursive)
            
        if result["valid"]:
            console.print(f"[green]✅ Verificación exitosa[/green]")
            console.print(f"[dim]Archivos verificados: {result['files_checked']}[/dim]")
        else:
            console.print(f"[red]❌ Verificación fallida[/red]")
            console.print(f"[red]Errores: {result['errors']}[/red]")
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]❌ Error en verificación: {e}[/red]")
        logger.error(f"Error en verify: {e}")
        sys.exit(1)


@cli.group()
def analyze() -> None:
    """Análisis de evidencias digitales."""
    pass


@analyze.command("memory")
@click.option(
    "--inputs", "-i", 
    required=True,
    help="Archivos de memoria a analizar"
)
@click.option(
    "--profile", "-p", 
    help="Perfil de Volatility3"
)
@click.option(
    "--case", "-c", 
    required=True,
    help="ID del caso"
)
def analyze_memory(inputs: str, profile: Optional[str], case: str) -> None:
    """Analizar dumps de memoria con Volatility3."""
    try:
        console.print(f"[blue]🧠 Analizando memoria: {inputs}[/blue]")
        console.print(f"[dim]Caso: {case}[/dim]")
        
        # TODO: Implementar análisis de memoria
        console.print("[yellow]⚠️  Módulo de análisis de memoria en desarrollo[/yellow]")
        console.print("[dim]Próximamente: Volatility3 con plugins preconfigurados[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error en análisis de memoria: {e}[/red]")
        logger.error(f"Error en analyze_memory: {e}")
        sys.exit(1)


@analyze.command("disk")
@click.option(
    "--inputs", "-i", 
    required=True,
    help="Imágenes de disco a analizar"
)
@click.option(
    "--case", "-c", 
    required=True,
    help="ID del caso"
)
def analyze_disk(inputs: str, case: str) -> None:
    """Analizar imágenes de disco con The Sleuth Kit."""
    try:
        console.print(f"[blue]💾 Analizando disco: {inputs}[/blue]")
        console.print(f"[dim]Caso: {case}[/dim]")
        
        # TODO: Implementar análisis de disco
        console.print("[yellow]⚠️  Módulo de análisis de disco en desarrollo[/yellow]")
        console.print("[dim]Próximamente: TSK/Autopsy con extracción automática[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error en análisis de disco: {e}[/red]")
        logger.error(f"Error en analyze_disk: {e}")
        sys.exit(1)


@cli.group()
def timeline() -> None:
    """Generación y análisis de timelines forenses."""
    pass


@timeline.command("build")
@click.option(
    "--inputs", "-i", 
    required=True,
    help="Artefactos o logs de entrada"
)
@click.option(
    "--format", "-f", 
    type=click.Choice(["csv", "jsonl"]), 
    default="jsonl",
    help="Formato de salida"
)
@click.option(
    "--case", "-c", 
    required=True,
    help="ID del caso"
)
def timeline_build(inputs: str, format: str, case: str) -> None:
    """Construir timeline forense con plaso."""
    try:
        console.print(f"[blue]📊 Construyendo timeline: {inputs}[/blue]")
        console.print(f"[dim]Formato: {format}[/dim]")
        console.print(f"[dim]Caso: {case}[/dim]")
        
        # TODO: Implementar pipeline de timeline
        console.print("[yellow]⚠️  Módulo de timeline en desarrollo[/yellow]")
        console.print("[dim]Próximamente: plaso/log2timeline con correlación automática[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error construyendo timeline: {e}[/red]")
        logger.error(f"Error en timeline_build: {e}")
        sys.exit(1)


@cli.group()
def yara() -> None:
    """Detección de malware con YARA."""
    pass


@yara.command("scan")
@click.option(
    "--rules", "-r", 
    required=True,
    help="Directorio de reglas YARA"
)
@click.option(
    "--inputs", "-i", 
    required=True,
    help="Archivos o directorios a escanear"
)
@click.option(
    "--case", "-c", 
    required=True,
    help="ID del caso"
)
def yara_scan(rules: str, inputs: str, case: str) -> None:
    """Escanear con reglas YARA."""
    try:
        console.print(f"[blue]🔍 Escaneando con YARA: {inputs}[/blue]")
        console.print(f"[dim]Reglas: {rules}[/dim]")
        console.print(f"[dim]Caso: {case}[/dim]")
        
        # TODO: Implementar scanner YARA
        console.print("[yellow]⚠️  Módulo YARA en desarrollo[/yellow]")
        console.print("[dim]Próximamente: escaneo automático con reglas preconfiguradas[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error en escaneo YARA: {e}[/red]")
        logger.error(f"Error en yara_scan: {e}")
        sys.exit(1)


@cli.group()
def report() -> None:
    """Generación de reportes forenses."""
    pass


@report.command("build")
@click.option(
    "--case", "-c", 
    required=True,
    help="ID del caso"
)
@click.option(
    "--template", "-t", 
    type=click.Choice(["tecnico", "ejecutivo"]), 
    required=True,
    help="Plantilla de reporte"
)
@click.option(
    "--format", "-f", 
    type=click.Choice(["pdf", "html", "markdown"]), 
    default="pdf",
    help="Formato de salida"
)
def report_build(case: str, template: str, format: str) -> None:
    """Generar reporte forense."""
    try:
        console.print(f"[blue]📄 Generando reporte {template} para caso {case}[/blue]")
        console.print(f"[dim]Formato: {format}[/dim]")
        
        # TODO: Implementar generador de reportes
        console.print("[yellow]⚠️  Módulo de reportes en desarrollo[/yellow]")
        console.print("[dim]Próximamente: plantillas Jinja2 → Markdown → PDF/HTML[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error generando reporte: {e}[/red]")
        logger.error(f"Error en report_build: {e}")
        sys.exit(1)


@cli.group()
def retention() -> None:
    """Gestión de retención y archivado."""
    pass


@retention.command("archive")
@click.option(
    "--case", "-c", 
    required=True,
    help="ID del caso"
)
def retention_archive(case: str) -> None:
    """Archivar caso."""
    try:
        console.print(f"[blue]📦 Archivando caso {case}[/blue]")
        
        # TODO: Implementar archivado
        console.print("[yellow]⚠️  Módulo de archivado en desarrollo[/yellow]")
        console.print("[dim]Próximamente: archivado seguro con cifrado[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error archivando caso: {e}[/red]")
        logger.error(f"Error en retention_archive: {e}")
        sys.exit(1)


@cli.group()
def chain() -> None:
    """Gestión de cadena de custodia."""
    pass


@chain.command("add-entry")
@click.option(
    "--case", "-c", 
    required=True,
    help="ID del caso"
)
@click.option(
    "--note", "-n", 
    required=True,
    help="Nota de la entrada"
)
@click.option(
    "--examiner", "-e", 
    help="Examinador (por defecto: usuario actual)"
)
def chain_add_entry(case: str, note: str, examiner: Optional[str]) -> None:
    """Agregar entrada a la cadena de custodia."""
    try:
        import getpass
        examiner = examiner or getpass.getuser()
        
        console.print(f"[blue]📝 Agregando entrada a cadena de custodia[/blue]")
        console.print(f"[dim]Caso: {case}[/dim]")
        console.print(f"[dim]Examinador: {examiner}[/dim]")
        
        chain_manager = ChainOfCustody(case)
        chain_manager.add_entry(
            action="manual_entry",
            description=note,
            examiner=examiner
        )
        
        console.print(f"[green]✅ Entrada agregada exitosamente[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Error agregando entrada: {e}[/red]")
        logger.error(f"Error en chain_add_entry: {e}")
        sys.exit(1)


def main() -> None:
    """Punto de entrada principal."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Operación cancelada por el usuario[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Error inesperado: {e}[/red]")
        logger.exception("Error inesperado en CLI")
        sys.exit(1)


if __name__ == "__main__":
    main()