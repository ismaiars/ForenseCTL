"""Comandos CLI para análisis forense."""

from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from forensectl import logger
from forensectl.core.case_manager import CaseManager
from forensectl.analysis import MemoryAnalyzer, DiskAnalyzer, ArtifactExtractor

console = Console()

# Crear aplicación Typer para comandos de análisis
app = typer.Typer(
    name="analyze",
    help="🧠 Comandos para análisis forense",
    no_args_is_help=True
)


@app.command("memory")
def analyze_memory(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_id: Optional[str] = typer.Option(None, "--evidence", "-e", help="ID de evidencia específica"),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Perfil de Volatility (auto-detectar si no se especifica)"),
    plugins: Optional[List[str]] = typer.Option(None, "--plugin", help="Plugins específicos a ejecutar"),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato de salida (json/csv/text)"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar resultados en el caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🧠 Analizar dumps de memoria con Volatility.
    
    Ejecuta análisis de memoria usando Volatility3 sobre dumps de memoria
    adquiridos previamente.
    
    Ejemplos:
        forensectl analyze memory --case CASE-001
        forensectl analyze memory -c CASE-001 -e EVIDENCE-001 --plugin pslist --plugin netstat
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        memory_analyzer = MemoryAnalyzer(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🧠 Analizando memoria para caso: {case_id}[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de análisis
            analysis_task = progress.add_task("Ejecutando análisis de memoria...", total=100)
            
            # Ejecutar análisis
            results = memory_analyzer.analyze(
                evidence_id=evidence_id,
                profile=profile,
                plugins=plugins,
                output_format=output_format,
                progress_callback=lambda p: progress.update(analysis_task, completed=p)
            )
            
            progress.update(analysis_task, completed=100)
            
            # Guardar resultados si se solicita
            if save_results:
                save_task = progress.add_task("Guardando resultados...", total=100)
                
                memory_analyzer.save_results(results)
                
                progress.update(save_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Análisis de memoria completado[/green]")
        
        summary_table = Table(title="Resumen de Análisis de Memoria")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Evidencias Analizadas", str(len(results.get("evidences", []))))
        summary_table.add_row("Plugins Ejecutados", str(len(results.get("plugins", []))))
        summary_table.add_row("Procesos Encontrados", str(results.get("process_count", 0)))
        summary_table.add_row("Conexiones de Red", str(results.get("network_connections", 0)))
        summary_table.add_row("Archivos Abiertos", str(results.get("open_files", 0)))
        summary_table.add_row("Módulos Cargados", str(results.get("loaded_modules", 0)))
        summary_table.add_row("Formato de Salida", output_format.upper())
        summary_table.add_row("Resultados Guardados", "✅ Sí" if save_results else "❌ No")
        
        console.print(summary_table)
        
        # Mostrar hallazgos importantes
        if results.get("suspicious_processes"):
            rprint("\n[bold red]🚨 Procesos Sospechosos Detectados:[/bold red]")
            for process in results["suspicious_processes"][:5]:  # Mostrar solo los primeros 5
                rprint(f"  • PID {process['pid']}: {process['name']} - {process['reason']}")
        
        if results.get("malware_indicators"):
            rprint("\n[bold yellow]⚠️ Indicadores de Malware:[/bold yellow]")
            for indicator in results["malware_indicators"][:5]:
                rprint(f"  • {indicator['type']}: {indicator['value']}")
        
    except Exception as e:
        logger.error(f"Error analizando memoria: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("disk")
def analyze_disk(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_id: Optional[str] = typer.Option(None, "--evidence", "-e", help="ID de evidencia específica"),
    analysis_type: str = typer.Option("full", "--type", "-t", help="Tipo de análisis (full/quick/custom)"),
    file_systems: Optional[List[str]] = typer.Option(None, "--filesystem", help="Sistemas de archivos específicos"),
    include_deleted: bool = typer.Option(True, "--deleted/--no-deleted", help="Incluir archivos eliminados"),
    include_slack: bool = typer.Option(False, "--slack/--no-slack", help="Incluir análisis de slack space"),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato de salida (json/csv/text)"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar resultados en el caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """💾 Analizar imágenes de disco con The Sleuth Kit.
    
    Ejecuta análisis forense de sistemas de archivos sobre imágenes de disco
    adquiridas previamente.
    
    Ejemplos:
        forensectl analyze disk --case CASE-001
        forensectl analyze disk -c CASE-001 -e EVIDENCE-001 --type quick
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        disk_analyzer = DiskAnalyzer(case_id, case_manager=case_manager)
        
        rprint(f"[blue]💾 Analizando disco para caso: {case_id}[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de análisis
            analysis_task = progress.add_task("Ejecutando análisis de disco...", total=100)
            
            # Ejecutar análisis
            results = disk_analyzer.analyze(
                evidence_id=evidence_id,
                analysis_type=analysis_type,
                file_systems=file_systems,
                include_deleted=include_deleted,
                include_slack=include_slack,
                output_format=output_format,
                progress_callback=lambda p: progress.update(analysis_task, completed=p)
            )
            
            progress.update(analysis_task, completed=100)
            
            # Guardar resultados si se solicita
            if save_results:
                save_task = progress.add_task("Guardando resultados...", total=100)
                
                disk_analyzer.save_results(results)
                
                progress.update(save_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Análisis de disco completado[/green]")
        
        summary_table = Table(title="Resumen de Análisis de Disco")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Evidencias Analizadas", str(len(results.get("evidences", []))))
        summary_table.add_row("Sistemas de Archivos", str(len(results.get("filesystems", []))))
        summary_table.add_row("Archivos Encontrados", str(results.get("files_count", 0)))
        summary_table.add_row("Archivos Eliminados", str(results.get("deleted_files", 0)))
        summary_table.add_row("Directorios", str(results.get("directories_count", 0)))
        summary_table.add_row("Tamaño Total", f"{results.get('total_size', 0):,} bytes")
        summary_table.add_row("Tipo de Análisis", analysis_type.title())
        summary_table.add_row("Formato de Salida", output_format.upper())
        summary_table.add_row("Resultados Guardados", "✅ Sí" if save_results else "❌ No")
        
        console.print(summary_table)
        
        # Mostrar hallazgos importantes
        if results.get("suspicious_files"):
            rprint("\n[bold red]🚨 Archivos Sospechosos Detectados:[/bold red]")
            for file_info in results["suspicious_files"][:5]:
                rprint(f"  • {file_info['path']} - {file_info['reason']}")
        
        if results.get("hidden_files"):
            rprint("\n[bold yellow]👁️ Archivos Ocultos Encontrados:[/bold yellow]")
            for file_info in results["hidden_files"][:5]:
                rprint(f"  • {file_info['path']} ({file_info['size']} bytes)")
        
    except Exception as e:
        logger.error(f"Error analizando disco: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("artifacts")
def extract_artifacts(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_id: Optional[str] = typer.Option(None, "--evidence", "-e", help="ID de evidencia específica"),
    artifact_types: Optional[List[str]] = typer.Option(None, "--type", help="Tipos de artefactos específicos"),
    os_type: Optional[str] = typer.Option(None, "--os", help="Tipo de SO (windows/linux/macos)"),
    include_registry: bool = typer.Option(True, "--registry/--no-registry", help="Incluir análisis de registro (Windows)"),
    include_logs: bool = typer.Option(True, "--logs/--no-logs", help="Incluir logs del sistema"),
    include_browser: bool = typer.Option(True, "--browser/--no-browser", help="Incluir artefactos de navegador"),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato de salida (json/csv/text)"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar resultados en el caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔍 Extraer artefactos forenses específicos.
    
    Extrae y analiza artefactos forenses como registros, logs, historial de navegador,
    archivos de configuración, etc.
    
    Ejemplos:
        forensectl analyze artifacts --case CASE-001
        forensectl analyze artifacts -c CASE-001 --type registry --type browser
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        artifact_extractor = ArtifactExtractor(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🔍 Extrayendo artefactos para caso: {case_id}[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de extracción
            extract_task = progress.add_task("Extrayendo artefactos...", total=100)
            
            # Ejecutar extracción
            results = artifact_extractor.extract(
                evidence_id=evidence_id,
                artifact_types=artifact_types,
                os_type=os_type,
                include_registry=include_registry,
                include_logs=include_logs,
                include_browser=include_browser,
                output_format=output_format,
                progress_callback=lambda p: progress.update(extract_task, completed=p)
            )
            
            progress.update(extract_task, completed=100)
            
            # Guardar resultados si se solicita
            if save_results:
                save_task = progress.add_task("Guardando resultados...", total=100)
                
                artifact_extractor.save_results(results)
                
                progress.update(save_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Extracción de artefactos completada[/green]")
        
        summary_table = Table(title="Resumen de Extracción de Artefactos")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Evidencias Procesadas", str(len(results.get("evidences", []))))
        summary_table.add_row("Tipos de Artefactos", str(len(results.get("artifact_types", []))))
        summary_table.add_row("Artefactos Extraídos", str(results.get("artifacts_count", 0)))
        summary_table.add_row("Entradas de Registro", str(results.get("registry_entries", 0)))
        summary_table.add_row("Logs del Sistema", str(results.get("system_logs", 0)))
        summary_table.add_row("Historial de Navegador", str(results.get("browser_history", 0)))
        summary_table.add_row("Archivos de Configuración", str(results.get("config_files", 0)))
        summary_table.add_row("Formato de Salida", output_format.upper())
        summary_table.add_row("Resultados Guardados", "✅ Sí" if save_results else "❌ No")
        
        console.print(summary_table)
        
        # Mostrar hallazgos importantes
        if results.get("suspicious_artifacts"):
            rprint("\n[bold red]🚨 Artefactos Sospechosos:[/bold red]")
            for artifact in results["suspicious_artifacts"][:5]:
                rprint(f"  • {artifact['type']}: {artifact['description']}")
        
        if results.get("user_activity"):
            rprint("\n[bold blue]👤 Actividad de Usuario Detectada:[/bold blue]")
            for activity in results["user_activity"][:5]:
                rprint(f"  • {activity['timestamp']}: {activity['action']}")
        
    except Exception as e:
        logger.error(f"Error extrayendo artefactos: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("all")
def analyze_all(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_id: Optional[str] = typer.Option(None, "--evidence", "-e", help="ID de evidencia específica"),
    analysis_profile: str = typer.Option("standard", "--profile", "-p", help="Perfil de análisis (quick/standard/comprehensive)"),
    parallel: bool = typer.Option(True, "--parallel/--sequential", help="Ejecutar análisis en paralelo"),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato de salida (json/csv/text)"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar resultados en el caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔄 Ejecutar análisis completo automatizado.
    
    Ejecuta todos los tipos de análisis disponibles según el perfil seleccionado:
    - quick: Análisis básico y rápido
    - standard: Análisis estándar completo
    - comprehensive: Análisis exhaustivo (puede tomar horas)
    
    Ejemplos:
        forensectl analyze all --case CASE-001
        forensectl analyze all -c CASE-001 --profile comprehensive --parallel
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        rprint(f"[blue]🔄 Ejecutando análisis completo para caso: {case_id}[/blue]")
        rprint(f"[yellow]📋 Perfil de análisis: {analysis_profile}[/yellow]")
        rprint(f"[yellow]⚡ Modo: {'Paralelo' if parallel else 'Secuencial'}[/yellow]")
        
        # Definir análisis según el perfil
        analysis_steps = {
            "quick": [
                ("memory", "Análisis básico de memoria"),
                ("disk", "Análisis rápido de disco"),
                ("artifacts", "Extracción de artefactos básicos")
            ],
            "standard": [
                ("memory", "Análisis completo de memoria"),
                ("disk", "Análisis completo de disco"),
                ("artifacts", "Extracción completa de artefactos")
            ],
            "comprehensive": [
                ("memory", "Análisis exhaustivo de memoria"),
                ("disk", "Análisis exhaustivo de disco"),
                ("artifacts", "Extracción exhaustiva de artefactos")
            ]
        }
        
        steps = analysis_steps.get(analysis_profile, analysis_steps["standard"])
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            all_results = {}
            
            for i, (analysis_type, description) in enumerate(steps):
                task = progress.add_task(f"[{i+1}/{len(steps)}] {description}...", total=100)
                
                try:
                    if analysis_type == "memory":
                        analyzer = MemoryAnalyzer(case_id, case_manager=case_manager)
                        results = analyzer.analyze(
                            evidence_id=evidence_id,
                            profile=None,  # Auto-detect
                            plugins=None,  # Use profile defaults
                            output_format=output_format,
                            progress_callback=lambda p: progress.update(task, completed=p)
                        )
                    
                    elif analysis_type == "disk":
                        analyzer = DiskAnalyzer(case_id, case_manager=case_manager)
                        results = analyzer.analyze(
                            evidence_id=evidence_id,
                            analysis_type=analysis_profile,
                            progress_callback=lambda p: progress.update(task, completed=p)
                        )
                    
                    elif analysis_type == "artifacts":
                        extractor = ArtifactExtractor(case_id, case_manager=case_manager)
                        results = extractor.extract(
                            evidence_id=evidence_id,
                            progress_callback=lambda p: progress.update(task, completed=p)
                        )
                    
                    all_results[analysis_type] = results
                    progress.update(task, completed=100)
                    
                except Exception as e:
                    logger.error(f"Error en análisis {analysis_type}: {e}")
                    progress.update(task, completed=100, description=f"❌ Error en {description}")
                    all_results[analysis_type] = {"error": str(e)}
            
            # Guardar resultados consolidados
            if save_results:
                save_task = progress.add_task("Consolidando y guardando resultados...", total=100)
                
                # TODO: Implementar guardado consolidado de resultados
                
                progress.update(save_task, completed=100)
        
        # Mostrar resumen consolidado
        rprint(f"[green]✅ Análisis completo finalizado[/green]")
        
        summary_table = Table(title="Resumen de Análisis Completo")
        summary_table.add_column("Análisis", style="cyan")
        summary_table.add_column("Estado", style="white")
        summary_table.add_column("Resultados", style="green")
        
        for analysis_type, results in all_results.items():
            if "error" in results:
                status = "❌ Error"
                result_count = "N/A"
            else:
                status = "✅ Completado"
                result_count = str(results.get("total_items", 0))
            
            summary_table.add_row(
                analysis_type.title(),
                status,
                result_count
            )
        
        console.print(summary_table)
        
        # Mostrar hallazgos críticos consolidados
        critical_findings = []
        for analysis_type, results in all_results.items():
            if "error" not in results:
                critical_findings.extend(results.get("critical_findings", []))
        
        if critical_findings:
            rprint("\n[bold red]🚨 Hallazgos Críticos Consolidados:[/bold red]")
            for finding in critical_findings[:10]:  # Mostrar solo los primeros 10
                rprint(f"  • {finding.get('severity', 'HIGH')}: {finding.get('description', 'N/A')}")
        
    except Exception as e:
        logger.error(f"Error en análisis completo: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("status")
def analysis_status(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📊 Mostrar estado de análisis del caso.
    
    Muestra el progreso y resultados de todos los análisis ejecutados.
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        # TODO: Implementar obtención de estado de análisis
        analysis_status = case_manager.get_analysis_status(case_id)
        
        rprint(f"[blue]📊 Estado de Análisis - Caso: {case_id}[/blue]")
        
        # Tabla de estado general
        status_table = Table(title="Estado General")
        status_table.add_column("Tipo de Análisis", style="cyan")
        status_table.add_column("Estado", style="white")
        status_table.add_column("Última Ejecución", style="blue")
        status_table.add_column("Resultados", style="green")
        
        for analysis in analysis_status.get("analyses", []):
            status_icon = {
                "completed": "✅",
                "running": "🔄",
                "failed": "❌",
                "pending": "⏳"
            }.get(analysis.get("status"), "❓")
            
            status_table.add_row(
                analysis.get("type", "N/A").title(),
                f"{status_icon} {analysis.get('status', 'N/A').title()}",
                analysis.get("last_run", "N/A"),
                str(analysis.get("result_count", 0))
            )
        
        console.print(status_table)
        
        # Estadísticas generales
        stats = analysis_status.get("statistics", {})
        if stats:
            rprint("\n[bold yellow]📈 Estadísticas:[/bold yellow]")
            rprint(f"  • Total de análisis ejecutados: {stats.get('total_analyses', 0)}")
            rprint(f"  • Análisis completados: {stats.get('completed_analyses', 0)}")
            rprint(f"  • Análisis fallidos: {stats.get('failed_analyses', 0)}")
            rprint(f"  • Tiempo total de análisis: {stats.get('total_time', 'N/A')}")
        
    except Exception as e:
        logger.error(f"Error obteniendo estado de análisis: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)