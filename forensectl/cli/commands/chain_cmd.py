"""Comandos CLI para gestión de cadena de custodia."""

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
from forensectl.core.chain_of_custody import ChainOfCustody

console = Console()

# Crear aplicación Typer para comandos de cadena de custodia
app = typer.Typer(
    name="chain",
    help="🔗 Comandos para gestión de cadena de custodia",
    no_args_is_help=True
)


@app.command("add-entry")
def add_entry(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_id: str = typer.Option(..., "--evidence", "-e", help="ID de la evidencia"),
    action: str = typer.Option(..., "--action", "-a", help="Acción realizada"),
    person: str = typer.Option(..., "--person", "-p", help="Persona responsable"),
    location: str = typer.Option(..., "--location", "-l", help="Ubicación"),
    reason: str = typer.Option(..., "--reason", "-r", help="Razón de la acción"),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="Notas adicionales"),
    timestamp: Optional[str] = typer.Option(None, "--timestamp", "-t", help="Timestamp (ISO format)"),
    witness: Optional[str] = typer.Option(None, "--witness", "-w", help="Testigo"),
    organization: Optional[str] = typer.Option(None, "--org", help="Organización"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", help="Directorio de trabajo")
) -> None:
    """🔗 Agregar entrada a la cadena de custodia.
    
    Registra una nueva acción en la cadena de custodia de una evidencia,
    documentando quién, qué, cuándo, dónde y por qué.
    
    Ejemplos:
        forensectl chain add-entry --case CASE-001 --evidence EV-001 --action "Adquisición" --person "Juan Pérez" --location "Oficina" --reason "Inicio de investigación"
        forensectl chain add-entry -c CASE-001 -e EV-001 -a "Análisis" -p "Ana García" -l "Laboratorio" -r "Análisis forense" --witness "Carlos López"
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        # Parsear timestamp si se proporciona
        entry_timestamp = None
        if timestamp:
            try:
                entry_timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                rprint(f"[red]❌ Formato de timestamp inválido: {timestamp}[/red]")
                rprint("[yellow]💡 Use formato ISO: YYYY-MM-DDTHH:MM:SS[/yellow]")
                raise typer.Exit(1)
        
        rprint(f"[blue]🔗 Agregando entrada a cadena de custodia[/blue]")
        rprint(f"[yellow]📋 Caso: {case_id} | Evidencia: {evidence_id}[/yellow]")
        rprint(f"[yellow]👤 Persona: {person} | Acción: {action}[/yellow]")
        
        # Agregar entrada
        entry_id = chain_manager.add_entry(
            evidence_id=evidence_id,
            action=action,
            person=person,
            location=location,
            reason=reason,
            notes=notes,
            timestamp=entry_timestamp,
            witness=witness,
            organization=organization
        )
        
        rprint(f"[green]✅ Entrada agregada exitosamente[/green]")
        rprint(f"[green]🆔 ID de entrada: {entry_id}[/green]")
        
        # Mostrar resumen de la entrada
        summary_table = Table(title="Entrada de Cadena de Custodia")
        summary_table.add_column("Campo", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("ID de Entrada", entry_id)
        summary_table.add_row("Caso", case_id)
        summary_table.add_row("Evidencia", evidence_id)
        summary_table.add_row("Acción", action)
        summary_table.add_row("Persona", person)
        summary_table.add_row("Ubicación", location)
        summary_table.add_row("Razón", reason)
        summary_table.add_row("Timestamp", entry_timestamp.isoformat() if entry_timestamp else "Automático")
        summary_table.add_row("Testigo", witness or "N/A")
        summary_table.add_row("Organización", organization or "N/A")
        summary_table.add_row("Notas", notes or "N/A")
        
        console.print(summary_table)
        
    except Exception as e:
        logger.error(f"Error agregando entrada a cadena de custodia: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("list")
def list_entries(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_id: Optional[str] = typer.Option(None, "--evidence", "-e", help="Filtrar por evidencia específica"),
    person: Optional[str] = typer.Option(None, "--person", "-p", help="Filtrar por persona"),
    action: Optional[str] = typer.Option(None, "--action", "-a", help="Filtrar por acción"),
    date_from: Optional[str] = typer.Option(None, "--from", help="Fecha desde (YYYY-MM-DD)"),
    date_to: Optional[str] = typer.Option(None, "--to", help="Fecha hasta (YYYY-MM-DD)"),
    limit: int = typer.Option(50, "--limit", "-l", help="Número máximo de entradas"),
    show_details: bool = typer.Option(False, "--details", "-d", help="Mostrar detalles completos"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json/csv)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", help="Directorio de trabajo")
) -> None:
    """📋 Listar entradas de cadena de custodia.
    
    Muestra las entradas de la cadena de custodia con opciones de filtrado
    y formato de salida.
    
    Ejemplos:
        forensectl chain list --case CASE-001
        forensectl chain list -c CASE-001 --evidence EV-001 --details
        forensectl chain list -c CASE-001 --person "Juan Pérez" --from 2024-01-01
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        # Parsear fechas si se proporcionan
        parsed_date_from = None
        parsed_date_to = None
        
        if date_from:
            try:
                parsed_date_from = datetime.fromisoformat(date_from)
            except ValueError:
                rprint(f"[red]❌ Formato de fecha inválido: {date_from}[/red]")
                raise typer.Exit(1)
        
        if date_to:
            try:
                parsed_date_to = datetime.fromisoformat(date_to)
            except ValueError:
                rprint(f"[red]❌ Formato de fecha inválido: {date_to}[/red]")
                raise typer.Exit(1)
        
        rprint(f"[blue]📋 Listando cadena de custodia - Caso: {case_id}[/blue]")
        
        # Mostrar filtros aplicados
        filters = []
        if evidence_id: filters.append(f"evidencia: {evidence_id}")
        if person: filters.append(f"persona: {person}")
        if action: filters.append(f"acción: {action}")
        if date_from: filters.append(f"desde: {date_from}")
        if date_to: filters.append(f"hasta: {date_to}")
        
        if filters:
            rprint(f"[yellow]🔍 Filtros: {', '.join(filters)}[/yellow]")
        
        # Obtener entradas
        entries = chain_manager.list_entries(
            evidence_id=evidence_id,
            person=person,
            action=action,
            date_from=parsed_date_from,
            date_to=parsed_date_to,
            limit=limit,
            include_details=show_details
        )
        
        if not entries:
            rprint("[yellow]📭 No se encontraron entradas de cadena de custodia[/yellow]")
            return
        
        rprint(f"[green]📊 {len(entries)} entradas encontradas[/green]")
        
        if output_format == "table":
            # Mostrar como tabla
            if show_details:
                # Tabla detallada
                for i, entry in enumerate(entries, 1):
                    rprint(f"\n[bold blue]📋 Entrada {i}/{len(entries)}[/bold blue]")
                    
                    detail_table = Table(title=f"Entrada {entry.get('id', 'N/A')}")
                    detail_table.add_column("Campo", style="cyan")
                    detail_table.add_column("Valor", style="white")
                    
                    detail_table.add_row("ID", entry.get("id", "N/A"))
                    detail_table.add_row("Evidencia", entry.get("evidence_id", "N/A"))
                    detail_table.add_row("Acción", entry.get("action", "N/A"))
                    detail_table.add_row("Persona", entry.get("person", "N/A"))
                    detail_table.add_row("Ubicación", entry.get("location", "N/A"))
                    detail_table.add_row("Razón", entry.get("reason", "N/A"))
                    detail_table.add_row("Timestamp", entry.get("timestamp", "N/A"))
                    detail_table.add_row("Testigo", entry.get("witness", "N/A"))
                    detail_table.add_row("Organización", entry.get("organization", "N/A"))
                    detail_table.add_row("Notas", entry.get("notes", "N/A"))
                    
                    console.print(detail_table)
            else:
                # Tabla resumida
                table = Table(title="Cadena de Custodia")
                table.add_column("ID", style="cyan")
                table.add_column("Evidencia", style="yellow")
                table.add_column("Acción", style="blue")
                table.add_column("Persona", style="green")
                table.add_column("Ubicación", style="white")
                table.add_column("Timestamp", style="magenta")
                
                for entry in entries:
                    # Truncar campos largos
                    action = entry.get("action", "N/A")
                    if len(action) > 20:
                        action = action[:17] + "..."
                    
                    person = entry.get("person", "N/A")
                    if len(person) > 15:
                        person = person[:12] + "..."
                    
                    location = entry.get("location", "N/A")
                    if len(location) > 15:
                        location = location[:12] + "..."
                    
                    table.add_row(
                        entry.get("id", "N/A"),
                        entry.get("evidence_id", "N/A"),
                        action,
                        person,
                        location,
                        entry.get("timestamp", "N/A")
                    )
                
                console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(entries, indent=2, default=str))
        
        elif output_format == "csv":
            # TODO: Implementar salida CSV
            rprint("[yellow]⚠️ Formato CSV no implementado aún[/yellow]")
        
        # Mostrar estadísticas
        if len(entries) > 1:
            actions = {}
            people = {}
            
            for entry in entries:
                action = entry.get("action", "unknown")
                actions[action] = actions.get(action, 0) + 1
                
                person = entry.get("person", "unknown")
                people[person] = people.get(person, 0) + 1
            
            rprint("\n[bold blue]📊 Estadísticas:[/bold blue]")
            rprint(f"  • Total de entradas: {len(entries)}")
            rprint("  • Acciones más frecuentes:")
            for action, count in sorted(actions.items(), key=lambda x: x[1], reverse=True)[:3]:
                rprint(f"    - {action}: {count}")
            rprint("  • Personas más activas:")
            for person, count in sorted(people.items(), key=lambda x: x[1], reverse=True)[:3]:
                rprint(f"    - {person}: {count}")
        
    except Exception as e:
        logger.error(f"Error listando cadena de custodia: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("verify")
def verify_chain(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_id: Optional[str] = typer.Option(None, "--evidence", "-e", help="Verificar evidencia específica"),
    check_integrity: bool = typer.Option(True, "--integrity/--no-integrity", help="Verificar integridad"),
    check_continuity: bool = typer.Option(True, "--continuity/--no-continuity", help="Verificar continuidad"),
    check_timestamps: bool = typer.Option(True, "--timestamps/--no-timestamps", help="Verificar timestamps"),
    check_signatures: bool = typer.Option(True, "--signatures/--no-signatures", help="Verificar firmas"),
    detailed_report: bool = typer.Option(False, "--detailed", "-d", help="Reporte detallado"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", help="Directorio de trabajo")
) -> None:
    """✅ Verificar integridad de la cadena de custodia.
    
    Verifica la integridad, continuidad y validez de la cadena de custodia
    para asegurar que no ha sido comprometida.
    
    Ejemplos:
        forensectl chain verify --case CASE-001
        forensectl chain verify -c CASE-001 --evidence EV-001 --detailed
        forensectl chain verify -c CASE-001 --no-signatures --format json
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        rprint(f"[blue]✅ Verificando cadena de custodia - Caso: {case_id}[/blue]")
        
        if evidence_id:
            rprint(f"[yellow]🔍 Evidencia específica: {evidence_id}[/yellow]")
        
        # Mostrar verificaciones a realizar
        checks = []
        if check_integrity: checks.append("integridad")
        if check_continuity: checks.append("continuidad")
        if check_timestamps: checks.append("timestamps")
        if check_signatures: checks.append("firmas")
        
        rprint(f"[yellow]🔍 Verificaciones: {', '.join(checks)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de verificación
            verify_task = progress.add_task("Verificando cadena de custodia...", total=100)
            
            # Verificar cadena
            verification_result = chain_manager.verify_chain(
                evidence_id=evidence_id,
                check_integrity=check_integrity,
                check_continuity=check_continuity,
                check_timestamps=check_timestamps,
                check_signatures=check_signatures,
                detailed_report=detailed_report,
                progress_callback=lambda p: progress.update(verify_task, completed=p)
            )
            
            progress.update(verify_task, completed=100)
        
        # Determinar estado general
        overall_status = verification_result.get("overall_status", "unknown")
        status_color = {
            "valid": "green",
            "warning": "yellow",
            "invalid": "red",
            "unknown": "white"
        }.get(overall_status, "white")
        
        status_icon = {
            "valid": "✅",
            "warning": "⚠️",
            "invalid": "❌",
            "unknown": "❓"
        }.get(overall_status, "❓")
        
        rprint(f"\n[{status_color}]{status_icon} Estado general: {overall_status.upper()}[/{status_color}]")
        
        if output_format == "table":
            # Mostrar resultados como tabla
            table = Table(title="Resultados de Verificación")
            table.add_column("Verificación", style="cyan")
            table.add_column("Estado", style="white")
            table.add_column("Detalles", style="yellow")
            
            checks_results = verification_result.get("checks", {})
            
            for check_name, check_result in checks_results.items():
                status = check_result.get("status", "unknown")
                check_icon = {
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
                    f"{check_icon} {status.upper()}",
                    details
                )
            
            console.print(table)
            
            # Mostrar estadísticas de verificación
            stats = verification_result.get("statistics", {})
            if stats:
                rprint("\n[bold blue]📊 Estadísticas de Verificación:[/bold blue]")
                rprint(f"  • Entradas verificadas: {stats.get('entries_checked', 0)}")
                rprint(f"  • Evidencias verificadas: {stats.get('evidences_checked', 0)}")
                rprint(f"  • Verificaciones exitosas: {stats.get('checks_passed', 0)}")
                rprint(f"  • Advertencias: {stats.get('warnings', 0)}")
                rprint(f"  • Errores: {stats.get('errors', 0)}")
                rprint(f"  • Tiempo de verificación: {stats.get('verification_time', 0):.2f} segundos")
        
        elif output_format == "json":
            import json
            rprint(json.dumps(verification_result, indent=2, default=str))
        
        # Mostrar problemas encontrados
        if verification_result.get("issues"):
            rprint("\n[bold red]⚠️ Problemas Encontrados:[/bold red]")
            for issue in verification_result["issues"][:5]:
                severity = issue.get("severity", "unknown")
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                    "info": "🔵"
                }.get(severity, "⚪")
                
                rprint(f"  {severity_icon} [{severity.upper()}] {issue.get('description', 'N/A')}")
                if issue.get("evidence_id"):
                    rprint(f"    📋 Evidencia: {issue['evidence_id']}")
                if issue.get("entry_id"):
                    rprint(f"    🔗 Entrada: {issue['entry_id']}")
        
        # Mostrar recomendaciones
        if verification_result.get("recommendations"):
            rprint("\n[bold blue]💡 Recomendaciones:[/bold blue]")
            for recommendation in verification_result["recommendations"][:3]:
                rprint(f"  • {recommendation}")
        
    except Exception as e:
        logger.error(f"Error verificando cadena de custodia: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("export")
def export_chain(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_id: Optional[str] = typer.Option(None, "--evidence", "-e", help="Exportar evidencia específica"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Archivo de salida"),
    output_format: str = typer.Option("pdf", "--format", "-f", help="Formato de salida (pdf/xlsx/csv/json)"),
    include_signatures: bool = typer.Option(True, "--signatures/--no-signatures", help="Incluir firmas digitales"),
    include_metadata: bool = typer.Option(True, "--metadata/--no-metadata", help="Incluir metadatos"),
    include_verification: bool = typer.Option(True, "--verification/--no-verification", help="Incluir verificación"),
    template: str = typer.Option("standard", "--template", "-t", help="Plantilla de exportación"),
    language: str = typer.Option("es", "--language", "-l", help="Idioma (es/en)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", help="Directorio de trabajo")
) -> None:
    """📤 Exportar cadena de custodia.
    
    Exporta la cadena de custodia en diferentes formatos para
    presentación legal o archivo.
    
    Ejemplos:
        forensectl chain export --case CASE-001
        forensectl chain export -c CASE-001 --evidence EV-001 --format xlsx
        forensectl chain export -c CASE-001 --template legal --language en
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        # Generar nombre de archivo si no se especifica
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_suffix = f"_{evidence_id}" if evidence_id else ""
            output_file = Path(f"cadena_custodia_{case_id}{evidence_suffix}_{timestamp}.{output_format}")
        
        rprint(f"[blue]📤 Exportando cadena de custodia - Caso: {case_id}[/blue]")
        rprint(f"[yellow]📄 Formato: {output_format.upper()} | Plantilla: {template}[/yellow]")
        rprint(f"[yellow]🌐 Idioma: {language.upper()} | Salida: {output_file}[/yellow]")
        
        if evidence_id:
            rprint(f"[yellow]🔍 Evidencia específica: {evidence_id}[/yellow]")
        
        # Mostrar configuración de exportación
        options = []
        if include_signatures: options.append("firmas")
        if include_metadata: options.append("metadatos")
        if include_verification: options.append("verificación")
        
        rprint(f"[yellow]⚙️ Opciones: {', '.join(options)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de exportación
            export_task = progress.add_task("Exportando cadena de custodia...", total=100)
            
            # Exportar cadena
            export_result = chain_manager.export(
                evidence_id=evidence_id,
                output_file=output_file,
                output_format=output_format,
                include_signatures=include_signatures,
                include_metadata=include_metadata,
                include_verification=include_verification,
                template=template,
                language=language,
                progress_callback=lambda p: progress.update(export_task, completed=p)
            )
            
            progress.update(export_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Exportación completada[/green]")
        
        summary_table = Table(title="Resumen de Exportación")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Archivo de Salida", str(output_file))
        summary_table.add_row("Formato", output_format.upper())
        summary_table.add_row("Plantilla", template.title())
        summary_table.add_row("Idioma", language.upper())
        summary_table.add_row("Entradas Exportadas", str(export_result.get("entries_exported", 0)))
        summary_table.add_row("Evidencias Incluidas", str(export_result.get("evidences_included", 0)))
        summary_table.add_row("Tamaño del Archivo", f"{export_result.get('file_size', 0):,} bytes")
        summary_table.add_row("Tiempo de Exportación", f"{export_result.get('export_time', 0):.2f} segundos")
        summary_table.add_row("Firmas Incluidas", "✅ Sí" if include_signatures else "❌ No")
        summary_table.add_row("Verificación Incluida", "✅ Sí" if include_verification else "❌ No")
        
        console.print(summary_table)
        
        # Mostrar información adicional
        if export_result.get("metadata"):
            metadata = export_result["metadata"]
            rprint("\n[bold blue]📋 Información del Documento:[/bold blue]")
            rprint(f"  • Páginas: {metadata.get('pages', 'N/A')}")
            rprint(f"  • Fecha de generación: {metadata.get('generated_at', 'N/A')}")
            rprint(f"  • Versión: {metadata.get('version', 'N/A')}")
            rprint(f"  • Hash del documento: {metadata.get('document_hash', 'N/A')}")
        
        rprint(f"\n[bold green]📄 Cadena de custodia exportada: {output_file}[/bold green]")
        
    except Exception as e:
        logger.error(f"Error exportando cadena de custodia: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("sign")
def sign_entry(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    entry_id: str = typer.Option(..., "--entry", "-e", help="ID de la entrada"),
    certificate_file: Optional[Path] = typer.Option(None, "--cert", help="Archivo de certificado"),
    private_key_file: Optional[Path] = typer.Option(None, "--key", help="Archivo de clave privada"),
    signature_reason: str = typer.Option("Validación de cadena de custodia", "--reason", "-r", help="Razón de la firma"),
    signature_location: Optional[str] = typer.Option(None, "--location", "-l", help="Ubicación de la firma"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", help="Directorio de trabajo")
) -> None:
    """✍️ Firmar digitalmente una entrada de cadena de custodia.
    
    Aplica una firma digital a una entrada específica de la cadena de custodia
    para garantizar su autenticidad e integridad.
    
    Ejemplos:
        forensectl chain sign --case CASE-001 --entry ENTRY-001
        forensectl chain sign -c CASE-001 -e ENTRY-001 --cert cert.pem --key key.pem
    """
    try:
        # Validar archivos de certificado y clave si se proporcionan
        if certificate_file and not certificate_file.exists():
            rprint(f"[red]❌ Archivo de certificado no encontrado: {certificate_file}[/red]")
            raise typer.Exit(1)
        
        if private_key_file and not private_key_file.exists():
            rprint(f"[red]❌ Archivo de clave privada no encontrado: {private_key_file}[/red]")
            raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        chain_manager = ChainOfCustody(case_id, case_manager=case_manager)
        
        rprint(f"[blue]✍️ Firmando entrada de cadena de custodia[/blue]")
        rprint(f"[yellow]📋 Caso: {case_id} | Entrada: {entry_id}[/yellow]")
        rprint(f"[yellow]📝 Razón: {signature_reason}[/yellow]")
        
        if signature_location:
            rprint(f"[yellow]📍 Ubicación: {signature_location}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de firma
            sign_task = progress.add_task("Firmando entrada...", total=100)
            
            # Firmar entrada
            signature_result = chain_manager.sign_entry(
                entry_id=entry_id,
                certificate_file=certificate_file,
                private_key_file=private_key_file,
                signature_reason=signature_reason,
                signature_location=signature_location,
                progress_callback=lambda p: progress.update(sign_task, completed=p)
            )
            
            progress.update(sign_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Entrada firmada exitosamente[/green]")
        
        summary_table = Table(title="Información de Firma Digital")
        summary_table.add_column("Campo", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("ID de Entrada", entry_id)
        summary_table.add_row("ID de Firma", signature_result.get("signature_id", "N/A"))
        summary_table.add_row("Algoritmo", signature_result.get("algorithm", "N/A"))
        summary_table.add_row("Timestamp", signature_result.get("timestamp", "N/A"))
        summary_table.add_row("Certificado", signature_result.get("certificate_info", "N/A"))
        summary_table.add_row("Razón", signature_reason)
        summary_table.add_row("Ubicación", signature_location or "N/A")
        summary_table.add_row("Hash de Firma", signature_result.get("signature_hash", "N/A"))
        
        console.print(summary_table)
        
        # Mostrar información del certificado
        if signature_result.get("certificate_details"):
            cert_details = signature_result["certificate_details"]
            rprint("\n[bold blue]📜 Detalles del Certificado:[/bold blue]")
            rprint(f"  • Emisor: {cert_details.get('issuer', 'N/A')}")
            rprint(f"  • Sujeto: {cert_details.get('subject', 'N/A')}")
            rprint(f"  • Válido desde: {cert_details.get('valid_from', 'N/A')}")
            rprint(f"  • Válido hasta: {cert_details.get('valid_to', 'N/A')}")
            rprint(f"  • Número de serie: {cert_details.get('serial_number', 'N/A')}")
        
    except Exception as e:
        logger.error(f"Error firmando entrada: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)