"""Comandos CLI para generación de reportes."""

from pathlib import Path
from typing import Optional, List
from datetime import datetime

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from forensectl import logger
from forensectl.core.case_manager import CaseManager
from forensectl.reporting.report_generator import ReportGenerator

console = Console()

# Crear aplicación Typer para comandos de reportes
app = typer.Typer(
    name="report",
    help="📄 Comandos para generación de reportes",
    no_args_is_help=True
)


@app.command("generate")
def generate_report(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    template: str = typer.Option("standard", "--template", "-t", help="Plantilla de reporte (standard/executive/technical/legal)"),
    output_format: str = typer.Option("pdf", "--format", "-f", help="Formato de salida (pdf/docx/html/markdown)"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Archivo de salida"),
    include_sections: Optional[List[str]] = typer.Option(None, "--include", help="Secciones a incluir"),
    exclude_sections: Optional[List[str]] = typer.Option(None, "--exclude", help="Secciones a excluir"),
    include_evidence: bool = typer.Option(True, "--evidence/--no-evidence", help="Incluir evidencias"),
    include_timeline: bool = typer.Option(True, "--timeline/--no-timeline", help="Incluir timeline"),
    include_analysis: bool = typer.Option(True, "--analysis/--no-analysis", help="Incluir análisis"),
    include_artifacts: bool = typer.Option(True, "--artifacts/--no-artifacts", help="Incluir artefactos"),
    include_yara: bool = typer.Option(True, "--yara/--no-yara", help="Incluir resultados YARA"),
    include_chain: bool = typer.Option(True, "--chain/--no-chain", help="Incluir cadena de custodia"),
    include_metadata: bool = typer.Option(True, "--metadata/--no-metadata", help="Incluir metadatos"),
    include_attachments: bool = typer.Option(False, "--attachments/--no-attachments", help="Incluir archivos adjuntos"),
    compress_output: bool = typer.Option(False, "--compress", help="Comprimir salida"),
    sign_report: bool = typer.Option(False, "--sign", help="Firmar digitalmente el reporte"),
    watermark: Optional[str] = typer.Option(None, "--watermark", help="Texto de marca de agua"),
    language: str = typer.Option("es", "--language", "-l", help="Idioma del reporte (es/en)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📄 Generar reporte forense completo.
    
    Genera un reporte forense profesional con todos los hallazgos,
    análisis y evidencias del caso.
    
    Ejemplos:
        forensectl report generate --case CASE-001
        forensectl report generate -c CASE-001 --template executive --format docx
        forensectl report generate -c CASE-001 --exclude timeline --no-attachments
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        report_generator = ReportGenerator(case_id, case_manager=case_manager)
        
        # Generar nombre de archivo si no se especifica
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = Path(f"reporte_{case_id}_{template}_{timestamp}.{output_format}")
        
        rprint(f"[blue]📄 Generando reporte para caso: {case_id}[/blue]")
        rprint(f"[yellow]📋 Plantilla: {template} | Formato: {output_format.upper()}[/yellow]")
        rprint(f"[yellow]🌐 Idioma: {language.upper()} | Salida: {output_file}[/yellow]")
        
        # Mostrar configuración de secciones
        sections_config = {
            "evidencias": include_evidence,
            "timeline": include_timeline,
            "análisis": include_analysis,
            "artefactos": include_artifacts,
            "YARA": include_yara,
            "cadena de custodia": include_chain,
            "metadatos": include_metadata,
            "adjuntos": include_attachments
        }
        
        enabled_sections = [name for name, enabled in sections_config.items() if enabled]
        rprint(f"[yellow]📑 Secciones incluidas: {', '.join(enabled_sections)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de generación
            generate_task = progress.add_task("Generando reporte...", total=100)
            
            # Generar reporte
            report_result = report_generator.generate(
                template=template,
                output_format=output_format,
                output_file=output_file,
                include_sections=include_sections,
                exclude_sections=exclude_sections,
                include_evidence=include_evidence,
                include_timeline=include_timeline,
                include_analysis=include_analysis,
                include_artifacts=include_artifacts,
                include_yara=include_yara,
                include_chain=include_chain,
                include_metadata=include_metadata,
                include_attachments=include_attachments,
                compress_output=compress_output,
                sign_report=sign_report,
                watermark=watermark,
                language=language,
                progress_callback=lambda p: progress.update(generate_task, completed=p)
            )
            
            progress.update(generate_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Reporte generado exitosamente[/green]")
        
        summary_table = Table(title="Resumen de Generación")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Archivo de Salida", str(output_file))
        summary_table.add_row("Plantilla", template.title())
        summary_table.add_row("Formato", output_format.upper())
        summary_table.add_row("Idioma", language.upper())
        summary_table.add_row("Páginas", str(report_result.get("pages", "N/A")))
        summary_table.add_row("Tamaño", f"{report_result.get('file_size', 0):,} bytes")
        summary_table.add_row("Secciones", str(report_result.get("sections_count", 0)))
        summary_table.add_row("Evidencias", str(report_result.get("evidence_count", 0)))
        summary_table.add_row("Tiempo de Generación", f"{report_result.get('generation_time', 0):.2f} segundos")
        summary_table.add_row("Comprimido", "✅ Sí" if compress_output else "❌ No")
        summary_table.add_row("Firmado", "✅ Sí" if sign_report else "❌ No")
        
        console.print(summary_table)
        
        # Mostrar estadísticas del contenido
        if report_result.get("content_stats"):
            stats = report_result["content_stats"]
            rprint("\n[bold blue]📊 Estadísticas del Contenido:[/bold blue]")
            rprint(f"  • Evidencias procesadas: {stats.get('evidence_processed', 0)}")
            rprint(f"  • Eventos de timeline: {stats.get('timeline_events', 0)}")
            rprint(f"  • Análisis incluidos: {stats.get('analysis_included', 0)}")
            rprint(f"  • Artefactos extraídos: {stats.get('artifacts_extracted', 0)}")
            rprint(f"  • Coincidencias YARA: {stats.get('yara_matches', 0)}")
            rprint(f"  • Entradas de cadena: {stats.get('chain_entries', 0)}")
        
        # Mostrar información de archivos adicionales
        if report_result.get("additional_files"):
            rprint("\n[bold green]📁 Archivos Adicionales:[/bold green]")
            for file_info in report_result["additional_files"]:
                rprint(f"  • {file_info['type']}: {file_info['path']}")
        
        rprint(f"\n[bold green]📄 Reporte disponible en: {output_file}[/bold green]")
        
    except Exception as e:
        logger.error(f"Error generando reporte: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("templates")
def list_templates(
    show_details: bool = typer.Option(False, "--details", "-d", help="Mostrar detalles de plantillas"),
    template_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filtrar por tipo"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Listar plantillas de reporte disponibles.
    
    Muestra las plantillas de reporte disponibles en el sistema
    con información sobre sus características.
    
    Ejemplos:
        forensectl report templates
        forensectl report templates --details --type executive
    """
    try:
        report_generator = ReportGenerator()
        
        # Obtener lista de plantillas
        templates = report_generator.list_templates(
            template_type=template_type,
            include_details=show_details
        )
        
        if not templates:
            rprint("[yellow]📭 No se encontraron plantillas[/yellow]")
            return
        
        rprint(f"[blue]📋 Plantillas de Reporte Disponibles ({len(templates)} encontradas)[/blue]")
        
        if output_format == "table":
            # Mostrar como tabla
            table = Table(title="Plantillas de Reporte")
            table.add_column("Nombre", style="cyan")
            table.add_column("Tipo", style="yellow")
            table.add_column("Formatos", style="blue")
            table.add_column("Idiomas", style="green")
            
            if show_details:
                table.add_column("Descripción", style="white")
                table.add_column("Secciones", style="magenta")
            
            for template in templates:
                # Formatear listas
                formats = ", ".join(template.get("supported_formats", []))
                languages = ", ".join(template.get("supported_languages", []))
                
                row_data = [
                    template.get("name", "N/A"),
                    template.get("type", "N/A"),
                    formats,
                    languages
                ]
                
                if show_details:
                    description = template.get("description", "N/A")
                    if len(description) > 50:
                        description = description[:47] + "..."
                    
                    sections = ", ".join(template.get("sections", []))
                    if len(sections) > 40:
                        sections = sections[:37] + "..."
                    
                    row_data.extend([description, sections])
                
                table.add_row(*row_data)
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(templates, indent=2))
        
        # Mostrar estadísticas
        template_types = {}
        for template in templates:
            t_type = template.get("type", "unknown")
            template_types[t_type] = template_types.get(t_type, 0) + 1
        
        rprint("\n[bold blue]📊 Estadísticas:[/bold blue]")
        rprint(f"  • Total de plantillas: {len(templates)}")
        rprint("  • Por tipo:")
        for t_type, count in template_types.items():
            rprint(f"    - {t_type}: {count}")
        
    except Exception as e:
        logger.error(f"Error listando plantillas: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("convert")
def convert_report(
    input_file: Path = typer.Option(..., "--input", "-i", help="Archivo de reporte de entrada"),
    output_format: str = typer.Option(..., "--format", "-f", help="Formato de salida (pdf/docx/html/markdown)"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Archivo de salida"),
    template: Optional[str] = typer.Option(None, "--template", "-t", help="Aplicar nueva plantilla"),
    preserve_formatting: bool = typer.Option(True, "--preserve/--no-preserve", help="Preservar formato original"),
    include_metadata: bool = typer.Option(True, "--metadata/--no-metadata", help="Incluir metadatos"),
    compress_output: bool = typer.Option(False, "--compress", help="Comprimir salida"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔄 Convertir reporte entre formatos.
    
    Convierte un reporte existente a un formato diferente,
    opcionalmente aplicando una nueva plantilla.
    
    Ejemplos:
        forensectl report convert --input reporte.pdf --format docx
        forensectl report convert -i reporte.html -f pdf --template executive
    """
    try:
        # Validar archivo de entrada
        if not input_file.exists():
            rprint(f"[red]❌ Archivo de entrada no encontrado: {input_file}[/red]")
            raise typer.Exit(1)
        
        report_generator = ReportGenerator()
        
        # Generar nombre de archivo si no se especifica
        if not output_file:
            output_file = input_file.with_suffix(f".{output_format}")
        
        rprint(f"[blue]🔄 Convirtiendo reporte[/blue]")
        rprint(f"[yellow]📄 Entrada: {input_file} → Salida: {output_file}[/yellow]")
        rprint(f"[yellow]🎯 Formato: {output_format.upper()}[/yellow]")
        
        if template:
            rprint(f"[yellow]📋 Nueva plantilla: {template}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de conversión
            convert_task = progress.add_task("Convirtiendo reporte...", total=100)
            
            # Convertir reporte
            convert_result = report_generator.convert(
                input_file=input_file,
                output_format=output_format,
                output_file=output_file,
                template=template,
                preserve_formatting=preserve_formatting,
                include_metadata=include_metadata,
                compress_output=compress_output,
                progress_callback=lambda p: progress.update(convert_task, completed=p)
            )
            
            progress.update(convert_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Conversión completada[/green]")
        
        summary_table = Table(title="Resumen de Conversión")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Archivo Original", str(input_file))
        summary_table.add_row("Archivo Convertido", str(output_file))
        summary_table.add_row("Formato Original", convert_result.get("original_format", "N/A").upper())
        summary_table.add_row("Formato Nuevo", output_format.upper())
        summary_table.add_row("Plantilla Aplicada", template or "N/A")
        summary_table.add_row("Tamaño Original", f"{convert_result.get('original_size', 0):,} bytes")
        summary_table.add_row("Tamaño Nuevo", f"{convert_result.get('new_size', 0):,} bytes")
        summary_table.add_row("Tiempo de Conversión", f"{convert_result.get('conversion_time', 0):.2f} segundos")
        summary_table.add_row("Formato Preservado", "✅ Sí" if preserve_formatting else "❌ No")
        summary_table.add_row("Comprimido", "✅ Sí" if compress_output else "❌ No")
        
        console.print(summary_table)
        
        rprint(f"\n[bold green]📄 Reporte convertido disponible en: {output_file}[/bold green]")
        
    except Exception as e:
        logger.error(f"Error convirtiendo reporte: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("validate")
def validate_report(
    report_file: Path = typer.Option(..., "--file", "-f", help="Archivo de reporte a validar"),
    check_integrity: bool = typer.Option(True, "--integrity/--no-integrity", help="Verificar integridad"),
    check_signatures: bool = typer.Option(True, "--signatures/--no-signatures", help="Verificar firmas digitales"),
    check_metadata: bool = typer.Option(True, "--metadata/--no-metadata", help="Verificar metadatos"),
    check_content: bool = typer.Option(True, "--content/--no-content", help="Verificar contenido"),
    detailed_output: bool = typer.Option(False, "--detailed", "-d", help="Salida detallada"),
    output_format: str = typer.Option("table", "--format", help="Formato de salida (table/json)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """✅ Validar integridad y autenticidad de reporte.
    
    Verifica la integridad, firmas digitales y metadatos de un reporte
    forense para asegurar su autenticidad.
    
    Ejemplos:
        forensectl report validate --file reporte.pdf
        forensectl report validate -f reporte.pdf --detailed --no-signatures
    """
    try:
        # Validar archivo
        if not report_file.exists():
            rprint(f"[red]❌ Archivo de reporte no encontrado: {report_file}[/red]")
            raise typer.Exit(1)
        
        report_generator = ReportGenerator()
        
        rprint(f"[blue]✅ Validando reporte: {report_file}[/blue]")
        
        # Mostrar configuración de validación
        checks = []
        if check_integrity: checks.append("integridad")
        if check_signatures: checks.append("firmas")
        if check_metadata: checks.append("metadatos")
        if check_content: checks.append("contenido")
        
        rprint(f"[yellow]🔍 Verificaciones: {', '.join(checks)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de validación
            validate_task = progress.add_task("Validando reporte...", total=100)
            
            # Validar reporte
            validation_result = report_generator.validate(
                report_file=report_file,
                check_integrity=check_integrity,
                check_signatures=check_signatures,
                check_metadata=check_metadata,
                check_content=check_content,
                detailed_output=detailed_output,
                progress_callback=lambda p: progress.update(validate_task, completed=p)
            )
            
            progress.update(validate_task, completed=100)
        
        # Determinar estado general
        overall_status = validation_result.get("overall_status", "unknown")
        status_color = {
            "valid": "green",
            "warning": "yellow",
            "invalid": "red",
            "unknown": "white"
        }.get(overall_status, "white")
        
        rprint(f"[{status_color}]{'✅' if overall_status == 'valid' else '⚠️' if overall_status == 'warning' else '❌'} Estado general: {overall_status.upper()}[/{status_color}]")
        
        if output_format == "table":
            # Mostrar resultados como tabla
            table = Table(title="Resultados de Validación")
            table.add_column("Verificación", style="cyan")
            table.add_column("Estado", style="white")
            table.add_column("Detalles", style="yellow")
            
            checks_results = validation_result.get("checks", {})
            
            for check_name, check_result in checks_results.items():
                status = check_result.get("status", "unknown")
                status_icon = {
                    "passed": "✅",
                    "warning": "⚠️",
                    "failed": "❌",
                    "skipped": "⏭️"
                }.get(status, "❓")
                
                details = check_result.get("message", "N/A")
                if len(details) > 60:
                    details = details[:57] + "..."
                
                table.add_row(
                    check_name.replace("_", " ").title(),
                    f"{status_icon} {status.upper()}",
                    details
                )
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(validation_result, indent=2))
        
        # Mostrar información del archivo
        file_info = validation_result.get("file_info", {})
        if file_info:
            rprint("\n[bold blue]📄 Información del Archivo:[/bold blue]")
            rprint(f"  • Tamaño: {file_info.get('size', 0):,} bytes")
            rprint(f"  • Formato: {file_info.get('format', 'N/A')}")
            rprint(f"  • Creado: {file_info.get('created', 'N/A')}")
            rprint(f"  • Modificado: {file_info.get('modified', 'N/A')}")
            rprint(f"  • Hash SHA256: {file_info.get('sha256', 'N/A')}")
        
        # Mostrar advertencias y errores
        if validation_result.get("warnings"):
            rprint("\n[bold yellow]⚠️ Advertencias:[/bold yellow]")
            for warning in validation_result["warnings"][:5]:
                rprint(f"  • {warning}")
        
        if validation_result.get("errors"):
            rprint("\n[bold red]❌ Errores:[/bold red]")
            for error in validation_result["errors"][:5]:
                rprint(f"  • {error}")
        
        # Mostrar recomendaciones
        if validation_result.get("recommendations"):
            rprint("\n[bold blue]💡 Recomendaciones:[/bold blue]")
            for recommendation in validation_result["recommendations"][:3]:
                rprint(f"  • {recommendation}")
        
    except Exception as e:
        logger.error(f"Error validando reporte: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("list")
def list_reports(
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Filtrar por caso específico"),
    template: Optional[str] = typer.Option(None, "--template", "-t", help="Filtrar por plantilla"),
    format_filter: Optional[str] = typer.Option(None, "--format", "-f", help="Filtrar por formato"),
    date_from: Optional[str] = typer.Option(None, "--from", help="Fecha desde (YYYY-MM-DD)"),
    date_to: Optional[str] = typer.Option(None, "--to", help="Fecha hasta (YYYY-MM-DD)"),
    show_details: bool = typer.Option(False, "--details", "-d", help="Mostrar detalles"),
    output_format: str = typer.Option("table", "--output", "-o", help="Formato de salida (table/json/csv)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Listar reportes generados.
    
    Muestra una lista de reportes generados con opciones de filtrado
    y información detallada.
    
    Ejemplos:
        forensectl report list
        forensectl report list --case CASE-001 --details
        forensectl report list --template executive --format pdf
    """
    try:
        report_generator = ReportGenerator()
        
        # Obtener lista de reportes
        reports = report_generator.list_reports(
            case_id=case_id,
            template=template,
            format_filter=format_filter,
            date_from=date_from,
            date_to=date_to,
            include_details=show_details
        )
        
        if not reports:
            rprint("[yellow]📭 No se encontraron reportes[/yellow]")
            return
        
        rprint(f"[blue]📋 Reportes Encontrados ({len(reports)} reportes)[/blue]")
        
        if output_format == "table":
            # Mostrar como tabla
            table = Table(title="Reportes Generados")
            table.add_column("Archivo", style="cyan")
            table.add_column("Caso", style="yellow")
            table.add_column("Plantilla", style="blue")
            table.add_column("Formato", style="green")
            table.add_column("Tamaño", style="white")
            table.add_column("Creado", style="magenta")
            
            if show_details:
                table.add_column("Estado", style="red")
                table.add_column("Páginas", style="blue")
            
            for report in reports:
                # Formatear tamaño
                size = report.get("size", 0)
                if size > 1024 * 1024:
                    size_str = f"{size / (1024 * 1024):.1f} MB"
                elif size > 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size} B"
                
                row_data = [
                    report.get("filename", "N/A"),
                    report.get("case_id", "N/A"),
                    report.get("template", "N/A"),
                    report.get("format", "N/A").upper(),
                    size_str,
                    report.get("created", "N/A")
                ]
                
                if show_details:
                    status = report.get("status", "unknown")
                    status_icon = {
                        "valid": "✅",
                        "warning": "⚠️",
                        "invalid": "❌",
                        "unknown": "❓"
                    }.get(status, "❓")
                    
                    row_data.extend([
                        f"{status_icon} {status}",
                        str(report.get("pages", "N/A"))
                    ])
                
                table.add_row(*row_data)
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(reports, indent=2))
        
        elif output_format == "csv":
            # TODO: Implementar salida CSV
            rprint("[yellow]⚠️ Formato CSV no implementado aún[/yellow]")
        
        # Mostrar estadísticas
        total_size = sum(report.get("size", 0) for report in reports)
        formats = {}
        templates = {}
        
        for report in reports:
            fmt = report.get("format", "unknown")
            formats[fmt] = formats.get(fmt, 0) + 1
            
            tmpl = report.get("template", "unknown")
            templates[tmpl] = templates.get(tmpl, 0) + 1
        
        rprint("\n[bold blue]📊 Estadísticas:[/bold blue]")
        rprint(f"  • Total de reportes: {len(reports)}")
        rprint(f"  • Tamaño total: {total_size:,} bytes")
        rprint("  • Por formato:")
        for fmt, count in formats.items():
            rprint(f"    - {fmt.upper()}: {count}")
        rprint("  • Por plantilla:")
        for tmpl, count in templates.items():
            rprint(f"    - {tmpl}: {count}")
        
    except Exception as e:
        logger.error(f"Error listando reportes: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)