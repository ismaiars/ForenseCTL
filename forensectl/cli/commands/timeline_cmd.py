"""Comandos CLI para construcción de timeline."""

from pathlib import Path
from typing import Optional, List
from datetime import datetime, timedelta

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from forensectl import logger
from forensectl.core.case_manager import CaseManager
from forensectl.analysis.timeline_builder import TimelineBuilder

console = Console()

# Crear aplicación Typer para comandos de timeline
app = typer.Typer(
    name="timeline",
    help="⏱️ Comandos para construcción de timeline",
    no_args_is_help=True
)


@app.command("build")
def build_timeline(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_ids: Optional[List[str]] = typer.Option(None, "--evidence", "-e", help="IDs de evidencias específicas"),
    start_date: Optional[str] = typer.Option(None, "--start", "-s", help="Fecha de inicio (YYYY-MM-DD HH:MM:SS)"),
    end_date: Optional[str] = typer.Option(None, "--end", help="Fecha de fin (YYYY-MM-DD HH:MM:SS)"),
    timezone: str = typer.Option("UTC", "--timezone", "-tz", help="Zona horaria"),
    sources: Optional[List[str]] = typer.Option(None, "--source", help="Fuentes específicas (filesystem/registry/logs/memory)"),
    output_format: str = typer.Option("csv", "--format", "-f", help="Formato de salida (csv/json/xlsx/html)"),
    include_hashes: bool = typer.Option(True, "--hashes/--no-hashes", help="Incluir hashes de archivos"),
    include_content: bool = typer.Option(False, "--content/--no-content", help="Incluir contenido de archivos pequeños"),
    filter_noise: bool = typer.Option(True, "--filter/--no-filter", help="Filtrar eventos de ruido"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar timeline en el caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """⏱️ Construir timeline forense completo.
    
    Utiliza plaso para extraer eventos temporales de todas las evidencias
    y crear un timeline unificado.
    
    Ejemplos:
        forensectl timeline build --case CASE-001
        forensectl timeline build -c CASE-001 --start "2024-01-01 00:00:00" --end "2024-01-31 23:59:59"
        forensectl timeline build -c CASE-001 --source filesystem --source registry --format xlsx
    """
    try:
        # Validar fechas si se proporcionan
        start_dt = None
        end_dt = None
        
        if start_date:
            try:
                start_dt = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
                except ValueError:
                    rprint(f"[red]❌ Formato de fecha de inicio inválido: {start_date}[/red]")
                    rprint("[yellow]Formato esperado: YYYY-MM-DD HH:MM:SS o YYYY-MM-DD[/yellow]")
                    raise typer.Exit(1)
        
        if end_date:
            try:
                end_dt = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
                    end_dt = end_dt.replace(hour=23, minute=59, second=59)
                except ValueError:
                    rprint(f"[red]❌ Formato de fecha de fin inválido: {end_date}[/red]")
                    rprint("[yellow]Formato esperado: YYYY-MM-DD HH:MM:SS o YYYY-MM-DD[/yellow]")
                    raise typer.Exit(1)
        
        # Validar que la fecha de inicio sea anterior a la de fin
        if start_dt and end_dt and start_dt >= end_dt:
            rprint("[red]❌ La fecha de inicio debe ser anterior a la fecha de fin[/red]")
            raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        timeline_builder = TimelineBuilder(case_id, case_manager=case_manager)
        
        rprint(f"[blue]⏱️ Construyendo timeline para caso: {case_id}[/blue]")
        if start_dt or end_dt:
            rprint(f"[yellow]📅 Rango temporal: {start_dt or 'Inicio'} → {end_dt or 'Fin'}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de construcción
            build_task = progress.add_task("Extrayendo eventos temporales...", total=100)
            
            # Construir timeline
            timeline_results = timeline_builder.build_timeline(
                evidence_ids=evidence_ids,
                start_date=start_dt,
                end_date=end_dt,
                timezone=timezone,
                sources=sources,
                output_format=output_format,
                include_hashes=include_hashes,
                include_content=include_content,
                filter_noise=filter_noise,
                progress_callback=lambda p: progress.update(build_task, completed=p)
            )
            
            progress.update(build_task, completed=100)
            
            # Guardar resultados si se solicita
            if save_results:
                save_task = progress.add_task("Guardando timeline...", total=100)
                
                timeline_builder.save_timeline(timeline_results)
                
                progress.update(save_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Timeline construido exitosamente[/green]")
        
        summary_table = Table(title="Resumen de Timeline")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Evidencias Procesadas", str(len(timeline_results.get("evidences", []))))
        summary_table.add_row("Eventos Extraídos", str(timeline_results.get("total_events", 0)))
        summary_table.add_row("Eventos Filtrados", str(timeline_results.get("filtered_events", 0)))
        summary_table.add_row("Fuentes de Datos", str(len(timeline_results.get("sources", []))))
        summary_table.add_row("Rango Temporal", f"{timeline_results.get('date_range', {}).get('start', 'N/A')} → {timeline_results.get('date_range', {}).get('end', 'N/A')}")
        summary_table.add_row("Zona Horaria", timezone)
        summary_table.add_row("Formato de Salida", output_format.upper())
        summary_table.add_row("Archivo de Timeline", str(timeline_results.get("output_file", "N/A")))
        summary_table.add_row("Timeline Guardado", "✅ Sí" if save_results else "❌ No")
        
        console.print(summary_table)
        
        # Mostrar eventos más relevantes
        if timeline_results.get("significant_events"):
            rprint("\n[bold yellow]🎯 Eventos Significativos:[/bold yellow]")
            for event in timeline_results["significant_events"][:5]:
                rprint(f"  • {event['timestamp']}: {event['description']} ({event['source']})")
        
        # Mostrar estadísticas por fuente
        if timeline_results.get("source_statistics"):
            rprint("\n[bold blue]📊 Estadísticas por Fuente:[/bold blue]")
            for source, count in timeline_results["source_statistics"].items():
                rprint(f"  • {source}: {count:,} eventos")
        
    except Exception as e:
        logger.error(f"Error construyendo timeline: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("analyze")
def analyze_timeline(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    timeline_file: Optional[Path] = typer.Option(None, "--timeline", "-t", help="Archivo de timeline específico"),
    analysis_type: str = typer.Option("patterns", "--type", help="Tipo de análisis (patterns/anomalies/correlations/all)"),
    time_window: int = typer.Option(60, "--window", "-w", help="Ventana de tiempo en minutos para correlaciones"),
    min_frequency: int = typer.Option(5, "--min-freq", help="Frecuencia mínima para detectar patrones"),
    include_visualizations: bool = typer.Option(True, "--viz/--no-viz", help="Generar visualizaciones"),
    output_format: str = typer.Option("html", "--format", "-f", help="Formato de salida (html/json/pdf)"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar análisis en el caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔍 Analizar timeline para detectar patrones y anomalías.
    
    Ejecuta análisis avanzado sobre el timeline construido para identificar:
    - Patrones de comportamiento
    - Anomalías temporales
    - Correlaciones entre eventos
    - Actividad sospechosa
    
    Ejemplos:
        forensectl timeline analyze --case CASE-001
        forensectl timeline analyze -c CASE-001 --type anomalies --window 30
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        timeline_builder = TimelineBuilder(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🔍 Analizando timeline para caso: {case_id}[/blue]")
        rprint(f"[yellow]📊 Tipo de análisis: {analysis_type}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de análisis
            analysis_task = progress.add_task("Analizando timeline...", total=100)
            
            # Ejecutar análisis
            analysis_results = timeline_builder.analyze_timeline(
                timeline_file=timeline_file,
                analysis_type=analysis_type,
                time_window=time_window,
                min_frequency=min_frequency,
                include_visualizations=include_visualizations,
                output_format=output_format,
                progress_callback=lambda p: progress.update(analysis_task, completed=p)
            )
            
            progress.update(analysis_task, completed=100)
            
            # Guardar resultados si se solicita
            if save_results:
                save_task = progress.add_task("Guardando análisis...", total=100)
                
                timeline_builder.save_analysis(analysis_results)
                
                progress.update(save_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Análisis de timeline completado[/green]")
        
        summary_table = Table(title="Resumen de Análisis de Timeline")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Eventos Analizados", str(analysis_results.get("total_events", 0)))
        summary_table.add_row("Patrones Detectados", str(len(analysis_results.get("patterns", []))))
        summary_table.add_row("Anomalías Encontradas", str(len(analysis_results.get("anomalies", []))))
        summary_table.add_row("Correlaciones", str(len(analysis_results.get("correlations", []))))
        summary_table.add_row("Ventana de Tiempo", f"{time_window} minutos")
        summary_table.add_row("Visualizaciones", "✅ Sí" if include_visualizations else "❌ No")
        summary_table.add_row("Formato de Salida", output_format.upper())
        summary_table.add_row("Archivo de Análisis", str(analysis_results.get("output_file", "N/A")))
        
        console.print(summary_table)
        
        # Mostrar hallazgos críticos
        if analysis_results.get("critical_findings"):
            rprint("\n[bold red]🚨 Hallazgos Críticos:[/bold red]")
            for finding in analysis_results["critical_findings"][:5]:
                rprint(f"  • {finding['timestamp']}: {finding['description']} (Severidad: {finding['severity']})")
        
        # Mostrar patrones más frecuentes
        if analysis_results.get("top_patterns"):
            rprint("\n[bold blue]📈 Patrones Más Frecuentes:[/bold blue]")
            for pattern in analysis_results["top_patterns"][:5]:
                rprint(f"  • {pattern['description']}: {pattern['frequency']} ocurrencias")
        
    except Exception as e:
        logger.error(f"Error analizando timeline: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("filter")
def filter_timeline(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    timeline_file: Optional[Path] = typer.Option(None, "--timeline", "-t", help="Archivo de timeline específico"),
    start_date: Optional[str] = typer.Option(None, "--start", "-s", help="Fecha de inicio (YYYY-MM-DD HH:MM:SS)"),
    end_date: Optional[str] = typer.Option(None, "--end", help="Fecha de fin (YYYY-MM-DD HH:MM:SS)"),
    event_types: Optional[List[str]] = typer.Option(None, "--type", help="Tipos de eventos a incluir"),
    sources: Optional[List[str]] = typer.Option(None, "--source", help="Fuentes específicas"),
    keywords: Optional[List[str]] = typer.Option(None, "--keyword", "-k", help="Palabras clave en descripción"),
    exclude_keywords: Optional[List[str]] = typer.Option(None, "--exclude", help="Palabras clave a excluir"),
    min_size: Optional[int] = typer.Option(None, "--min-size", help="Tamaño mínimo de archivo (bytes)"),
    max_size: Optional[int] = typer.Option(None, "--max-size", help="Tamaño máximo de archivo (bytes)"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Archivo de salida"),
    output_format: str = typer.Option("csv", "--format", "-f", help="Formato de salida (csv/json/xlsx)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔍 Filtrar timeline por criterios específicos.
    
    Aplica filtros avanzados al timeline para extraer eventos específicos
    según criterios temporales, tipos, fuentes o contenido.
    
    Ejemplos:
        forensectl timeline filter --case CASE-001 --start "2024-01-15 09:00:00" --end "2024-01-15 17:00:00"
        forensectl timeline filter -c CASE-001 --keyword "malware" --keyword "suspicious" --type "file_creation"
    """
    try:
        # Validar fechas si se proporcionan
        start_dt = None
        end_dt = None
        
        if start_date:
            try:
                start_dt = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
                except ValueError:
                    rprint(f"[red]❌ Formato de fecha de inicio inválido: {start_date}[/red]")
                    raise typer.Exit(1)
        
        if end_date:
            try:
                end_dt = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
                    end_dt = end_dt.replace(hour=23, minute=59, second=59)
                except ValueError:
                    rprint(f"[red]❌ Formato de fecha de fin inválido: {end_date}[/red]")
                    raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        timeline_builder = TimelineBuilder(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🔍 Filtrando timeline para caso: {case_id}[/blue]")
        
        # Mostrar criterios de filtrado
        if start_dt or end_dt:
            rprint(f"[yellow]📅 Rango temporal: {start_dt or 'Inicio'} → {end_dt or 'Fin'}[/yellow]")
        if keywords:
            rprint(f"[yellow]🔍 Palabras clave: {', '.join(keywords)}[/yellow]")
        if event_types:
            rprint(f"[yellow]📋 Tipos de eventos: {', '.join(event_types)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de filtrado
            filter_task = progress.add_task("Aplicando filtros...", total=100)
            
            # Aplicar filtros
            filtered_results = timeline_builder.filter_timeline(
                timeline_file=timeline_file,
                start_date=start_dt,
                end_date=end_dt,
                event_types=event_types,
                sources=sources,
                keywords=keywords,
                exclude_keywords=exclude_keywords,
                min_size=min_size,
                max_size=max_size,
                output_file=output_file,
                output_format=output_format,
                progress_callback=lambda p: progress.update(filter_task, completed=p)
            )
            
            progress.update(filter_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Timeline filtrado exitosamente[/green]")
        
        summary_table = Table(title="Resumen de Filtrado")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Eventos Originales", str(filtered_results.get("original_count", 0)))
        summary_table.add_row("Eventos Filtrados", str(filtered_results.get("filtered_count", 0)))
        summary_table.add_row("Eventos Resultantes", str(filtered_results.get("result_count", 0)))
        summary_table.add_row("Porcentaje Retenido", f"{filtered_results.get('retention_percentage', 0):.1f}%")
        summary_table.add_row("Criterios Aplicados", str(len(filtered_results.get("applied_filters", []))))
        summary_table.add_row("Formato de Salida", output_format.upper())
        summary_table.add_row("Archivo de Salida", str(filtered_results.get("output_file", "N/A")))
        
        console.print(summary_table)
        
        # Mostrar muestra de eventos filtrados
        if filtered_results.get("sample_events"):
            rprint("\n[bold blue]📋 Muestra de Eventos Filtrados:[/bold blue]")
            for event in filtered_results["sample_events"][:5]:
                rprint(f"  • {event['timestamp']}: {event['description']} ({event['source']})")
        
    except Exception as e:
        logger.error(f"Error filtrando timeline: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("export")
def export_timeline(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    timeline_file: Optional[Path] = typer.Option(None, "--timeline", "-t", help="Archivo de timeline específico"),
    output_format: str = typer.Option("xlsx", "--format", "-f", help="Formato de exportación (xlsx/csv/json/html/pdf)"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Archivo de salida"),
    include_metadata: bool = typer.Option(True, "--metadata/--no-metadata", help="Incluir metadatos"),
    include_statistics: bool = typer.Option(True, "--stats/--no-stats", help="Incluir estadísticas"),
    include_visualizations: bool = typer.Option(True, "--viz/--no-viz", help="Incluir visualizaciones"),
    template: Optional[str] = typer.Option(None, "--template", help="Plantilla personalizada"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📤 Exportar timeline en diferentes formatos.
    
    Exporta el timeline construido a formatos profesionales para análisis
    o presentación, incluyendo metadatos y visualizaciones.
    
    Ejemplos:
        forensectl timeline export --case CASE-001 --format xlsx
        forensectl timeline export -c CASE-001 --format pdf --output timeline_report.pdf
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        timeline_builder = TimelineBuilder(case_id, case_manager=case_manager)
        
        rprint(f"[blue]📤 Exportando timeline para caso: {case_id}[/blue]")
        rprint(f"[yellow]📋 Formato: {output_format.upper()}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de exportación
            export_task = progress.add_task("Exportando timeline...", total=100)
            
            # Exportar timeline
            export_results = timeline_builder.export_timeline(
                timeline_file=timeline_file,
                output_format=output_format,
                output_file=output_file,
                include_metadata=include_metadata,
                include_statistics=include_statistics,
                include_visualizations=include_visualizations,
                template=template,
                progress_callback=lambda p: progress.update(export_task, completed=p)
            )
            
            progress.update(export_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Timeline exportado exitosamente[/green]")
        
        summary_table = Table(title="Resumen de Exportación")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Eventos Exportados", str(export_results.get("events_count", 0)))
        summary_table.add_row("Formato", output_format.upper())
        summary_table.add_row("Archivo de Salida", str(export_results.get("output_file", "N/A")))
        summary_table.add_row("Tamaño del Archivo", f"{export_results.get('file_size', 0):,} bytes")
        summary_table.add_row("Metadatos Incluidos", "✅ Sí" if include_metadata else "❌ No")
        summary_table.add_row("Estadísticas Incluidas", "✅ Sí" if include_statistics else "❌ No")
        summary_table.add_row("Visualizaciones", "✅ Sí" if include_visualizations else "❌ No")
        summary_table.add_row("Plantilla", template or "Por defecto")
        
        console.print(summary_table)
        
        rprint(f"\n[bold green]📁 Archivo exportado: {export_results.get('output_file')}[/bold green]")
        
    except Exception as e:
        logger.error(f"Error exportando timeline: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("list")
def list_timelines(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Listar timelines disponibles en un caso.
    
    Muestra todos los timelines construidos para el caso especificado.
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        timeline_builder = TimelineBuilder(case_id, case_manager=case_manager)
        
        # Obtener lista de timelines
        timelines = timeline_builder.list_timelines()
        
        if not timelines:
            rprint(f"[yellow]📭 No se encontraron timelines en el caso {case_id}[/yellow]")
            return
        
        # Crear tabla
        table = Table(title=f"Timelines del Caso {case_id} ({len(timelines)} encontrados)")
        table.add_column("Archivo", style="cyan")
        table.add_column("Formato", style="yellow")
        table.add_column("Eventos", style="blue")
        table.add_column("Rango Temporal", style="green")
        table.add_column("Creado", style="white")
        table.add_column("Tamaño", style="magenta")
        
        for timeline in timelines:
            # Formatear tamaño
            size = timeline.get("size", 0)
            if size > 1024**2:  # MB
                size_str = f"{size / (1024**2):.1f} MB"
            elif size > 1024:  # KB
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
            
            table.add_row(
                timeline.get("filename", "N/A"),
                timeline.get("format", "N/A").upper(),
                str(timeline.get("events_count", 0)),
                f"{timeline.get('start_date', 'N/A')} → {timeline.get('end_date', 'N/A')}",
                timeline.get("created_at", "N/A"),
                size_str
            )
        
        console.print(table)
        
    except Exception as e:
        logger.error(f"Error listando timelines: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)