"""Comandos CLI para verificación de integridad."""

from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from forensectl import logger
from forensectl.core.case_manager import CaseManager
from forensectl.core.integrity_manager import IntegrityManager

console = Console()

# Crear aplicación Typer para comandos de verificación
app = typer.Typer(
    name="verify",
    help="🔍 Comandos para verificación de integridad",
    no_args_is_help=True
)


@app.command("evidence")
def verify_evidence(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_ids: Optional[List[str]] = typer.Option(None, "--evidence", "-e", help="IDs de evidencias específicas"),
    hash_algorithms: Optional[List[str]] = typer.Option(None, "--hash", "-h", help="Algoritmos de hash (md5/sha1/sha256/sha512)"),
    check_signatures: bool = typer.Option(True, "--signatures/--no-signatures", help="Verificar firmas digitales"),
    check_timestamps: bool = typer.Option(True, "--timestamps/--no-timestamps", help="Verificar timestamps"),
    check_metadata: bool = typer.Option(True, "--metadata/--no-metadata", help="Verificar metadatos"),
    deep_scan: bool = typer.Option(False, "--deep", help="Verificación profunda"),
    parallel_jobs: int = typer.Option(4, "--jobs", "-j", help="Número de trabajos paralelos"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json/csv)"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar resultados"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔍 Verificar integridad de evidencias.
    
    Verifica la integridad de las evidencias mediante hashes criptográficos,
    firmas digitales y validación de metadatos.
    
    Ejemplos:
        forensectl verify evidence --case CASE-001
        forensectl verify evidence -c CASE-001 --evidence EV-001 --deep
        forensectl verify evidence -c CASE-001 --hash sha256 --hash sha512 --no-signatures
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        integrity_manager = IntegrityManager(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🔍 Verificando integridad de evidencias - Caso: {case_id}[/blue]")
        
        # Mostrar configuración
        if evidence_ids:
            rprint(f"[yellow]📋 Evidencias específicas: {', '.join(evidence_ids)}[/yellow]")
        if hash_algorithms:
            rprint(f"[yellow]🔐 Algoritmos de hash: {', '.join(hash_algorithms)}[/yellow]")
        
        # Mostrar verificaciones habilitadas
        checks = []
        if check_signatures: checks.append("firmas")
        if check_timestamps: checks.append("timestamps")
        if check_metadata: checks.append("metadatos")
        if deep_scan: checks.append("verificación profunda")
        
        rprint(f"[yellow]✅ Verificaciones: {', '.join(checks)}[/yellow]")
        rprint(f"[yellow]⚡ Trabajos paralelos: {parallel_jobs}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de verificación
            verify_task = progress.add_task("Verificando evidencias...", total=100)
            
            # Verificar evidencias
            verification_results = integrity_manager.verify_evidence(
                evidence_ids=evidence_ids,
                hash_algorithms=hash_algorithms,
                check_signatures=check_signatures,
                check_timestamps=check_timestamps,
                check_metadata=check_metadata,
                deep_scan=deep_scan,
                parallel_jobs=parallel_jobs,
                progress_callback=lambda p: progress.update(verify_task, completed=p)
            )
            
            progress.update(verify_task, completed=100)
            
            # Guardar resultados si se solicita
            if save_results:
                save_task = progress.add_task("Guardando resultados...", total=100)
                
                integrity_manager.save_verification_results(verification_results)
                
                progress.update(save_task, completed=100)
        
        # Determinar estado general
        overall_status = verification_results.get("overall_status", "unknown")
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
            table = Table(title="Resultados de Verificación de Evidencias")
            table.add_column("Evidencia", style="cyan")
            table.add_column("Estado", style="white")
            table.add_column("Hash", style="yellow")
            table.add_column("Firmas", style="blue")
            table.add_column("Timestamps", style="green")
            table.add_column("Metadatos", style="magenta")
            
            evidence_results = verification_results.get("evidences", [])
            
            for evidence in evidence_results:
                evidence_id = evidence.get("evidence_id", "N/A")
                
                # Estado general de la evidencia
                evidence_status = evidence.get("status", "unknown")
                evidence_icon = {
                    "valid": "✅",
                    "warning": "⚠️",
                    "invalid": "❌",
                    "unknown": "❓"
                }.get(evidence_status, "❓")
                
                # Estados de verificaciones individuales
                hash_status = evidence.get("hash_verification", {}).get("status", "unknown")
                hash_icon = {
                    "passed": "✅",
                    "failed": "❌",
                    "warning": "⚠️",
                    "skipped": "⏭️"
                }.get(hash_status, "❓")
                
                signature_status = evidence.get("signature_verification", {}).get("status", "unknown")
                signature_icon = {
                    "passed": "✅",
                    "failed": "❌",
                    "warning": "⚠️",
                    "skipped": "⏭️"
                }.get(signature_status, "❓")
                
                timestamp_status = evidence.get("timestamp_verification", {}).get("status", "unknown")
                timestamp_icon = {
                    "passed": "✅",
                    "failed": "❌",
                    "warning": "⚠️",
                    "skipped": "⏭️"
                }.get(timestamp_status, "❓")
                
                metadata_status = evidence.get("metadata_verification", {}).get("status", "unknown")
                metadata_icon = {
                    "passed": "✅",
                    "failed": "❌",
                    "warning": "⚠️",
                    "skipped": "⏭️"
                }.get(metadata_status, "❓")
                
                table.add_row(
                    evidence_id,
                    f"{evidence_icon} {evidence_status}",
                    f"{hash_icon} {hash_status}",
                    f"{signature_icon} {signature_status}",
                    f"{timestamp_icon} {timestamp_status}",
                    f"{metadata_icon} {metadata_status}"
                )
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(verification_results, indent=2, default=str))
        
        elif output_format == "csv":
            # TODO: Implementar salida CSV
            rprint("[yellow]⚠️ Formato CSV no implementado aún[/yellow]")
        
        # Mostrar estadísticas
        stats = verification_results.get("statistics", {})
        if stats:
            rprint("\n[bold blue]📊 Estadísticas de Verificación:[/bold blue]")
            rprint(f"  • Evidencias verificadas: {stats.get('evidences_verified', 0)}")
            rprint(f"  • Verificaciones exitosas: {stats.get('verifications_passed', 0)}")
            rprint(f"  • Advertencias: {stats.get('warnings', 0)}")
            rprint(f"  • Errores: {stats.get('errors', 0)}")
            rprint(f"  • Tiempo total: {stats.get('total_time', 0):.2f} segundos")
            rprint(f"  • Algoritmos utilizados: {', '.join(stats.get('algorithms_used', []))}")
        
        # Mostrar problemas encontrados
        if verification_results.get("issues"):
            rprint("\n[bold red]⚠️ Problemas Encontrados:[/bold red]")
            for issue in verification_results["issues"][:5]:
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
        
        # Mostrar recomendaciones
        if verification_results.get("recommendations"):
            rprint("\n[bold blue]💡 Recomendaciones:[/bold blue]")
            for recommendation in verification_results["recommendations"][:3]:
                rprint(f"  • {recommendation}")
        
    except Exception as e:
        logger.error(f"Error verificando evidencias: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("case")
def verify_case(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    check_structure: bool = typer.Option(True, "--structure/--no-structure", help="Verificar estructura del caso"),
    check_metadata: bool = typer.Option(True, "--metadata/--no-metadata", help="Verificar metadatos"),
    check_chain: bool = typer.Option(True, "--chain/--no-chain", help="Verificar cadena de custodia"),
    check_evidences: bool = typer.Option(True, "--evidences/--no-evidences", help="Verificar evidencias"),
    check_reports: bool = typer.Option(True, "--reports/--no-reports", help="Verificar reportes"),
    detailed_report: bool = typer.Option(False, "--detailed", "-d", help="Reporte detallado"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json)"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar resultados"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔍 Verificar integridad completa del caso.
    
    Realiza una verificación integral del caso incluyendo estructura,
    metadatos, cadena de custodia, evidencias y reportes.
    
    Ejemplos:
        forensectl verify case --case CASE-001
        forensectl verify case -c CASE-001 --detailed --no-reports
        forensectl verify case -c CASE-001 --format json
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        integrity_manager = IntegrityManager(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🔍 Verificando integridad completa del caso: {case_id}[/blue]")
        
        # Mostrar verificaciones a realizar
        checks = []
        if check_structure: checks.append("estructura")
        if check_metadata: checks.append("metadatos")
        if check_chain: checks.append("cadena de custodia")
        if check_evidences: checks.append("evidencias")
        if check_reports: checks.append("reportes")
        
        rprint(f"[yellow]✅ Verificaciones: {', '.join(checks)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de verificación
            verify_task = progress.add_task("Verificando caso completo...", total=100)
            
            # Verificar caso
            verification_results = integrity_manager.verify_case(
                check_structure=check_structure,
                check_metadata=check_metadata,
                check_chain=check_chain,
                check_evidences=check_evidences,
                check_reports=check_reports,
                detailed_report=detailed_report,
                progress_callback=lambda p: progress.update(verify_task, completed=p)
            )
            
            progress.update(verify_task, completed=100)
            
            # Guardar resultados si se solicita
            if save_results:
                save_task = progress.add_task("Guardando resultados...", total=100)
                
                integrity_manager.save_case_verification_results(verification_results)
                
                progress.update(save_task, completed=100)
        
        # Determinar estado general
        overall_status = verification_results.get("overall_status", "unknown")
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
        
        rprint(f"\n[{status_color}]{status_icon} Estado general del caso: {overall_status.upper()}[/{status_color}]")
        
        if output_format == "table":
            # Mostrar resultados como tabla
            table = Table(title="Resultados de Verificación del Caso")
            table.add_column("Componente", style="cyan")
            table.add_column("Estado", style="white")
            table.add_column("Detalles", style="yellow")
            table.add_column("Tiempo", style="blue")
            
            components = verification_results.get("components", {})
            
            for component_name, component_result in components.items():
                status = component_result.get("status", "unknown")
                component_icon = {
                    "passed": "✅",
                    "warning": "⚠️",
                    "failed": "❌",
                    "skipped": "⏭️"
                }.get(status, "❓")
                
                details = component_result.get("summary", "N/A")
                if len(details) > 50:
                    details = details[:47] + "..."
                
                verification_time = component_result.get("verification_time", 0)
                
                table.add_row(
                    component_name.replace("_", " ").title(),
                    f"{component_icon} {status.upper()}",
                    details,
                    f"{verification_time:.2f}s"
                )
            
            console.print(table)
            
            # Mostrar detalles si se solicita
            if detailed_report:
                for component_name, component_result in components.items():
                    if component_result.get("details"):
                        rprint(f"\n[bold blue]📋 Detalles de {component_name.replace('_', ' ').title()}:[/bold blue]")
                        for detail in component_result["details"][:3]:
                            rprint(f"  • {detail}")
        
        elif output_format == "json":
            import json
            rprint(json.dumps(verification_results, indent=2, default=str))
        
        # Mostrar estadísticas generales
        stats = verification_results.get("statistics", {})
        if stats:
            rprint("\n[bold blue]📊 Estadísticas Generales:[/bold blue]")
            rprint(f"  • Componentes verificados: {stats.get('components_verified', 0)}")
            rprint(f"  • Verificaciones exitosas: {stats.get('verifications_passed', 0)}")
            rprint(f"  • Advertencias: {stats.get('warnings', 0)}")
            rprint(f"  • Errores críticos: {stats.get('critical_errors', 0)}")
            rprint(f"  • Tiempo total: {stats.get('total_verification_time', 0):.2f} segundos")
            rprint(f"  • Puntuación de integridad: {stats.get('integrity_score', 0):.1f}%")
        
        # Mostrar problemas críticos
        if verification_results.get("critical_issues"):
            rprint("\n[bold red]🚨 Problemas Críticos:[/bold red]")
            for issue in verification_results["critical_issues"][:5]:
                rprint(f"  🔴 {issue.get('description', 'N/A')}")
                if issue.get("component"):
                    rprint(f"    📋 Componente: {issue['component']}")
                if issue.get("recommendation"):
                    rprint(f"    💡 Recomendación: {issue['recommendation']}")
        
        # Mostrar recomendaciones generales
        if verification_results.get("recommendations"):
            rprint("\n[bold blue]💡 Recomendaciones Generales:[/bold blue]")
            for recommendation in verification_results["recommendations"][:3]:
                rprint(f"  • {recommendation}")
        
    except Exception as e:
        logger.error(f"Error verificando caso: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("hash")
def verify_hash(
    file_path: Path = typer.Option(..., "--file", "-f", help="Archivo a verificar"),
    expected_hash: str = typer.Option(..., "--hash", "-h", help="Hash esperado"),
    algorithm: str = typer.Option("sha256", "--algorithm", "-a", help="Algoritmo de hash (md5/sha1/sha256/sha512)"),
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="ID del caso (opcional)"),
    save_result: bool = typer.Option(False, "--save", help="Guardar resultado en el caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔐 Verificar hash de un archivo específico.
    
    Calcula y compara el hash de un archivo con el valor esperado
    para verificar su integridad.
    
    Ejemplos:
        forensectl verify hash --file evidence.img --hash abc123... --algorithm sha256
        forensectl verify hash -f document.pdf -h def456... -a md5 --case CASE-001
    """
    try:
        # Validar archivo
        if not file_path.exists():
            rprint(f"[red]❌ Archivo no encontrado: {file_path}[/red]")
            raise typer.Exit(1)
        
        # Validar algoritmo
        supported_algorithms = ["md5", "sha1", "sha256", "sha512"]
        if algorithm.lower() not in supported_algorithms:
            rprint(f"[red]❌ Algoritmo no soportado: {algorithm}[/red]")
            rprint(f"[yellow]💡 Algoritmos soportados: {', '.join(supported_algorithms)}[/yellow]")
            raise typer.Exit(1)
        
        # Inicializar manager si se proporciona caso
        integrity_manager = None
        if case_id:
            case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
            if not case_manager.case_exists(case_id):
                rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
                raise typer.Exit(1)
            integrity_manager = IntegrityManager(case_id, case_manager=case_manager)
        else:
            integrity_manager = IntegrityManager()
        
        rprint(f"[blue]🔐 Verificando hash del archivo: {file_path}[/blue]")
        rprint(f"[yellow]🔍 Algoritmo: {algorithm.upper()}[/yellow]")
        rprint(f"[yellow]📋 Hash esperado: {expected_hash}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de verificación
            verify_task = progress.add_task("Calculando hash...", total=100)
            
            # Verificar hash
            verification_result = integrity_manager.verify_file_hash(
                file_path=file_path,
                expected_hash=expected_hash,
                algorithm=algorithm,
                progress_callback=lambda p: progress.update(verify_task, completed=p)
            )
            
            progress.update(verify_task, completed=100)
            
            # Guardar resultado si se solicita
            if save_result and case_id:
                save_task = progress.add_task("Guardando resultado...", total=100)
                
                integrity_manager.save_hash_verification_result(verification_result)
                
                progress.update(save_task, completed=100)
        
        # Determinar resultado
        is_valid = verification_result.get("is_valid", False)
        calculated_hash = verification_result.get("calculated_hash", "N/A")
        
        if is_valid:
            rprint(f"[green]✅ Hash verificado correctamente[/green]")
        else:
            rprint(f"[red]❌ Hash no coincide[/red]")
        
        # Mostrar detalles
        summary_table = Table(title="Verificación de Hash")
        summary_table.add_column("Campo", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Archivo", str(file_path))
        summary_table.add_row("Algoritmo", algorithm.upper())
        summary_table.add_row("Hash Esperado", expected_hash)
        summary_table.add_row("Hash Calculado", calculated_hash)
        summary_table.add_row("Estado", "✅ VÁLIDO" if is_valid else "❌ INVÁLIDO")
        summary_table.add_row("Tamaño del Archivo", f"{verification_result.get('file_size', 0):,} bytes")
        summary_table.add_row("Tiempo de Cálculo", f"{verification_result.get('calculation_time', 0):.2f} segundos")
        summary_table.add_row("Timestamp", verification_result.get("timestamp", "N/A"))
        
        if case_id:
            summary_table.add_row("Caso", case_id)
            summary_table.add_row("Resultado Guardado", "✅ Sí" if save_result else "❌ No")
        
        console.print(summary_table)
        
        # Mostrar información adicional del archivo
        file_info = verification_result.get("file_info", {})
        if file_info:
            rprint("\n[bold blue]📄 Información del Archivo:[/bold blue]")
            rprint(f"  • Tamaño: {file_info.get('size', 0):,} bytes")
            rprint(f"  • Creado: {file_info.get('created', 'N/A')}")
            rprint(f"  • Modificado: {file_info.get('modified', 'N/A')}")
            rprint(f"  • Permisos: {file_info.get('permissions', 'N/A')}")
        
        # Mostrar advertencias si las hay
        if verification_result.get("warnings"):
            rprint("\n[bold yellow]⚠️ Advertencias:[/bold yellow]")
            for warning in verification_result["warnings"]:
                rprint(f"  • {warning}")
        
        # Salir con código de error si la verificación falla
        if not is_valid:
            raise typer.Exit(1)
        
    except Exception as e:
        logger.error(f"Error verificando hash: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("results")
def show_verification_results(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    verification_type: Optional[str] = typer.Option(None, "--type", "-t", help="Tipo de verificación (evidence/case/hash)"),
    date_from: Optional[str] = typer.Option(None, "--from", help="Fecha desde (YYYY-MM-DD)"),
    date_to: Optional[str] = typer.Option(None, "--to", help="Fecha hasta (YYYY-MM-DD)"),
    status_filter: Optional[str] = typer.Option(None, "--status", help="Filtrar por estado (valid/warning/invalid)"),
    limit: int = typer.Option(50, "--limit", "-l", help="Número máximo de resultados"),
    show_details: bool = typer.Option(False, "--details", "-d", help="Mostrar detalles"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json/csv)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📊 Mostrar resultados de verificaciones anteriores.
    
    Muestra los resultados de verificaciones de integridad ejecutadas
    previamente con opciones de filtrado.
    
    Ejemplos:
        forensectl verify results --case CASE-001
        forensectl verify results -c CASE-001 --type evidence --status invalid
        forensectl verify results -c CASE-001 --from 2024-01-01 --details
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        integrity_manager = IntegrityManager(case_id, case_manager=case_manager)
        
        # Parsear fechas si se proporcionan
        parsed_date_from = None
        parsed_date_to = None
        
        if date_from:
            try:
                from datetime import datetime
                parsed_date_from = datetime.fromisoformat(date_from)
            except ValueError:
                rprint(f"[red]❌ Formato de fecha inválido: {date_from}[/red]")
                raise typer.Exit(1)
        
        if date_to:
            try:
                from datetime import datetime
                parsed_date_to = datetime.fromisoformat(date_to)
            except ValueError:
                rprint(f"[red]❌ Formato de fecha inválido: {date_to}[/red]")
                raise typer.Exit(1)
        
        rprint(f"[blue]📊 Resultados de verificación - Caso: {case_id}[/blue]")
        
        # Mostrar filtros aplicados
        filters = []
        if verification_type: filters.append(f"tipo: {verification_type}")
        if status_filter: filters.append(f"estado: {status_filter}")
        if date_from: filters.append(f"desde: {date_from}")
        if date_to: filters.append(f"hasta: {date_to}")
        
        if filters:
            rprint(f"[yellow]🔍 Filtros: {', '.join(filters)}[/yellow]")
        
        # Obtener resultados
        results = integrity_manager.get_verification_results(
            verification_type=verification_type,
            date_from=parsed_date_from,
            date_to=parsed_date_to,
            status_filter=status_filter,
            limit=limit,
            include_details=show_details
        )
        
        if not results.get("verifications"):
            rprint(f"[yellow]📭 No se encontraron resultados de verificación[/yellow]")
            return
        
        verifications = results["verifications"]
        rprint(f"[green]📊 {len(verifications)} verificaciones encontradas[/green]")
        
        if output_format == "table":
            # Mostrar como tabla
            table = Table(title="Resultados de Verificación")
            table.add_column("ID", style="cyan")
            table.add_column("Tipo", style="yellow")
            table.add_column("Estado", style="white")
            table.add_column("Objetivo", style="blue")
            table.add_column("Fecha", style="green")
            
            if show_details:
                table.add_column("Detalles", style="magenta")
            
            for verification in verifications:
                verification_id = verification.get("id", "N/A")
                v_type = verification.get("type", "N/A")
                status = verification.get("status", "unknown")
                target = verification.get("target", "N/A")
                timestamp = verification.get("timestamp", "N/A")
                
                # Icono de estado
                status_icon = {
                    "valid": "✅",
                    "warning": "⚠️",
                    "invalid": "❌",
                    "unknown": "❓"
                }.get(status, "❓")
                
                # Truncar objetivo si es muy largo
                if len(target) > 30:
                    target = target[:27] + "..."
                
                row_data = [
                    verification_id,
                    v_type.title(),
                    f"{status_icon} {status.upper()}",
                    target,
                    timestamp
                ]
                
                if show_details:
                    details = verification.get("summary", "N/A")
                    if len(details) > 40:
                        details = details[:37] + "..."
                    row_data.append(details)
                
                table.add_row(*row_data)
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(results, indent=2, default=str))
        
        elif output_format == "csv":
            # TODO: Implementar salida CSV
            rprint("[yellow]⚠️ Formato CSV no implementado aún[/yellow]")
        
        # Mostrar estadísticas
        stats = results.get("statistics", {})
        if stats:
            rprint("\n[bold blue]📊 Estadísticas:[/bold blue]")
            rprint(f"  • Total de verificaciones: {stats.get('total_verifications', 0)}")
            rprint(f"  • Verificaciones válidas: {stats.get('valid_verifications', 0)}")
            rprint(f"  • Advertencias: {stats.get('warning_verifications', 0)}")
            rprint(f"  • Verificaciones inválidas: {stats.get('invalid_verifications', 0)}")
            
            # Distribución por tipo
            if stats.get("type_distribution"):
                rprint("  • Por tipo:")
                for v_type, count in stats["type_distribution"].items():
                    rprint(f"    - {v_type}: {count}")
        
        # Mostrar tendencias recientes
        if results.get("trends"):
            trends = results["trends"]
            rprint("\n[bold blue]📈 Tendencias Recientes:[/bold blue]")
            if trends.get("improving"):
                rprint(f"  ✅ Mejorando: {trends['improving']}")
            if trends.get("degrading"):
                rprint(f"  ⚠️ Empeorando: {trends['degrading']}")
            if trends.get("stable"):
                rprint(f"  🔄 Estable: {trends['stable']}")
        
    except Exception as e:
        logger.error(f"Error mostrando resultados de verificación: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)