"""Comandos CLI para detección con YARA."""

from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from forensectl import logger
from forensectl.core.case_manager import CaseManager
from forensectl.analysis.yara_scanner import YaraScanner

console = Console()

# Crear aplicación Typer para comandos de YARA
app = typer.Typer(
    name="yara",
    help="🦠 Comandos para detección con YARA",
    no_args_is_help=True
)


@app.command("scan")
def scan_evidence(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_ids: Optional[List[str]] = typer.Option(None, "--evidence", "-e", help="IDs de evidencias específicas"),
    rule_files: Optional[List[Path]] = typer.Option(None, "--rules", "-r", help="Archivos de reglas YARA específicos"),
    rule_sets: Optional[List[str]] = typer.Option(None, "--ruleset", help="Conjuntos de reglas predefinidos (malware/apt/crypto/etc)"),
    target_types: Optional[List[str]] = typer.Option(None, "--target", "-t", help="Tipos de archivos objetivo (exe/dll/pdf/doc/etc)"),
    scan_mode: str = typer.Option("fast", "--mode", "-m", help="Modo de escaneo (fast/thorough/deep)"),
    max_file_size: Optional[str] = typer.Option(None, "--max-size", help="Tamaño máximo de archivo (ej: 100MB)"),
    include_archives: bool = typer.Option(True, "--archives/--no-archives", help="Escanear dentro de archivos comprimidos"),
    include_memory: bool = typer.Option(False, "--memory/--no-memory", help="Escanear dumps de memoria"),
    parallel_jobs: int = typer.Option(4, "--jobs", "-j", help="Número de trabajos paralelos"),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato de salida (json/csv/xml/text)"),
    save_results: bool = typer.Option(True, "--save/--no-save", help="Guardar resultados en el caso"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🦠 Escanear evidencias con reglas YARA.
    
    Ejecuta detección de malware y patrones sospechosos usando reglas YARA
    sobre las evidencias del caso.
    
    Ejemplos:
        forensectl yara scan --case CASE-001
        forensectl yara scan -c CASE-001 --ruleset malware --ruleset apt --mode thorough
        forensectl yara scan -c CASE-001 --rules custom.yar --target exe --target dll
    """
    try:
        # Validar archivos de reglas si se especifican
        if rule_files:
            for rule_file in rule_files:
                if not rule_file.exists():
                    rprint(f"[red]❌ Archivo de reglas no encontrado: {rule_file}[/red]")
                    raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        yara_scanner = YaraScanner(case_id, case_manager=case_manager)
        
        rprint(f"[blue]🦠 Escaneando con YARA para caso: {case_id}[/blue]")
        rprint(f"[yellow]⚡ Modo: {scan_mode} | Trabajos paralelos: {parallel_jobs}[/yellow]")
        
        # Mostrar configuración del escaneo
        if rule_sets:
            rprint(f"[yellow]📋 Conjuntos de reglas: {', '.join(rule_sets)}[/yellow]")
        if rule_files:
            rprint(f"[yellow]📄 Archivos de reglas: {', '.join([str(f) for f in rule_files])}[/yellow]")
        if target_types:
            rprint(f"[yellow]🎯 Tipos objetivo: {', '.join(target_types)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de escaneo
            scan_task = progress.add_task("Ejecutando escaneo YARA...", total=100)
            
            # Ejecutar escaneo
            scan_results = yara_scanner.scan(
                evidence_ids=evidence_ids,
                rule_files=rule_files,
                rule_sets=rule_sets,
                target_types=target_types,
                scan_mode=scan_mode,
                max_file_size=max_file_size,
                include_archives=include_archives,
                include_memory=include_memory,
                parallel_jobs=parallel_jobs,
                output_format=output_format,
                progress_callback=lambda p: progress.update(scan_task, completed=p)
            )
            
            progress.update(scan_task, completed=100)
            
            # Guardar resultados si se solicita
            if save_results:
                save_task = progress.add_task("Guardando resultados...", total=100)
                
                yara_scanner.save_results(scan_results)
                
                progress.update(save_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Escaneo YARA completado[/green]")
        
        summary_table = Table(title="Resumen de Escaneo YARA")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Evidencias Escaneadas", str(len(scan_results.get("evidences", []))))
        summary_table.add_row("Archivos Procesados", str(scan_results.get("files_scanned", 0)))
        summary_table.add_row("Reglas Cargadas", str(scan_results.get("rules_loaded", 0)))
        summary_table.add_row("Coincidencias Totales", str(scan_results.get("total_matches", 0)))
        summary_table.add_row("Archivos con Coincidencias", str(scan_results.get("infected_files", 0)))
        summary_table.add_row("Tiempo de Escaneo", f"{scan_results.get('scan_time', 0):.2f} segundos")
        summary_table.add_row("Modo de Escaneo", scan_mode.title())
        summary_table.add_row("Formato de Salida", output_format.upper())
        summary_table.add_row("Resultados Guardados", "✅ Sí" if save_results else "❌ No")
        
        console.print(summary_table)
        
        # Mostrar coincidencias críticas
        if scan_results.get("critical_matches"):
            rprint("\n[bold red]🚨 Coincidencias Críticas:[/bold red]")
            for match in scan_results["critical_matches"][:5]:
                rprint(f"  • {match['file']}: {match['rule']} - {match['description']}")
        
        # Mostrar familias de malware detectadas
        if scan_results.get("malware_families"):
            rprint("\n[bold yellow]🦠 Familias de Malware Detectadas:[/bold yellow]")
            for family, count in scan_results["malware_families"].items():
                rprint(f"  • {family}: {count} coincidencias")
        
        # Mostrar estadísticas por tipo de archivo
        if scan_results.get("file_type_stats"):
            rprint("\n[bold blue]📊 Estadísticas por Tipo de Archivo:[/bold blue]")
            for file_type, stats in scan_results["file_type_stats"].items():
                rprint(f"  • {file_type}: {stats['scanned']} escaneados, {stats['matches']} coincidencias")
        
    except Exception as e:
        logger.error(f"Error ejecutando escaneo YARA: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("compile")
def compile_rules(
    rule_files: List[Path] = typer.Option(..., "--rules", "-r", help="Archivos de reglas YARA a compilar"),
    output_file: Path = typer.Option(..., "--output", "-o", help="Archivo de reglas compiladas"),
    include_dirs: Optional[List[Path]] = typer.Option(None, "--include", "-I", help="Directorios de inclusión"),
    validate_only: bool = typer.Option(False, "--validate", "-v", help="Solo validar sintaxis"),
    optimize: bool = typer.Option(True, "--optimize/--no-optimize", help="Optimizar reglas compiladas"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """⚙️ Compilar reglas YARA para uso optimizado.
    
    Compila múltiples archivos de reglas YARA en un archivo binario optimizado
    para escaneos más rápidos.
    
    Ejemplos:
        forensectl yara compile --rules malware.yar --rules apt.yar --output compiled.yarc
        forensectl yara compile -r *.yar -o all_rules.yarc --optimize
    """
    try:
        # Validar archivos de reglas
        for rule_file in rule_files:
            if not rule_file.exists():
                rprint(f"[red]❌ Archivo de reglas no encontrado: {rule_file}[/red]")
                raise typer.Exit(1)
        
        # Validar directorios de inclusión
        if include_dirs:
            for include_dir in include_dirs:
                if not include_dir.exists() or not include_dir.is_dir():
                    rprint(f"[red]❌ Directorio de inclusión no válido: {include_dir}[/red]")
                    raise typer.Exit(1)
        
        yara_scanner = YaraScanner()
        
        rprint(f"[blue]⚙️ Compilando reglas YARA[/blue]")
        rprint(f"[yellow]📄 Archivos de entrada: {len(rule_files)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            if validate_only:
                # Solo validar
                validate_task = progress.add_task("Validando reglas...", total=100)
                
                validation_results = yara_scanner.validate_rules(
                    rule_files=rule_files,
                    include_dirs=include_dirs,
                    progress_callback=lambda p: progress.update(validate_task, completed=p)
                )
                
                progress.update(validate_task, completed=100)
                
                # Mostrar resultados de validación
                if validation_results["valid"]:
                    rprint(f"[green]✅ Todas las reglas son válidas[/green]")
                else:
                    rprint(f"[red]❌ Se encontraron errores en las reglas[/red]")
                    for error in validation_results["errors"]:
                        rprint(f"  • {error['file']}: {error['message']}")
                    raise typer.Exit(1)
            
            else:
                # Compilar reglas
                compile_task = progress.add_task("Compilando reglas...", total=100)
                
                compile_results = yara_scanner.compile_rules(
                    rule_files=rule_files,
                    output_file=output_file,
                    include_dirs=include_dirs,
                    optimize=optimize,
                    progress_callback=lambda p: progress.update(compile_task, completed=p)
                )
                
                progress.update(compile_task, completed=100)
        
        if not validate_only:
            # Mostrar resumen de compilación
            rprint(f"[green]✅ Reglas compiladas exitosamente[/green]")
            
            summary_table = Table(title="Resumen de Compilación")
            summary_table.add_column("Métrica", style="cyan")
            summary_table.add_column("Valor", style="white")
            
            summary_table.add_row("Archivos de Entrada", str(len(rule_files)))
            summary_table.add_row("Reglas Compiladas", str(compile_results.get("rules_count", 0)))
            summary_table.add_row("Archivo de Salida", str(output_file))
            summary_table.add_row("Tamaño del Archivo", f"{compile_results.get('output_size', 0):,} bytes")
            summary_table.add_row("Optimización", "✅ Sí" if optimize else "❌ No")
            summary_table.add_row("Tiempo de Compilación", f"{compile_results.get('compile_time', 0):.2f} segundos")
            
            console.print(summary_table)
            
            rprint(f"\n[bold green]📁 Archivo compilado: {output_file}[/bold green]")
        
    except Exception as e:
        logger.error(f"Error compilando reglas YARA: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("update")
def update_rules(
    rule_sources: Optional[List[str]] = typer.Option(None, "--source", "-s", help="Fuentes de reglas (github/malware-bazaar/etc)"),
    rule_sets: Optional[List[str]] = typer.Option(None, "--ruleset", help="Conjuntos específicos a actualizar"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Directorio de salida"),
    force_update: bool = typer.Option(False, "--force", "-f", help="Forzar actualización"),
    verify_signatures: bool = typer.Option(True, "--verify/--no-verify", help="Verificar firmas digitales"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🔄 Actualizar reglas YARA desde fuentes remotas.
    
    Descarga y actualiza reglas YARA desde repositorios públicos y fuentes
    de inteligencia de amenazas.
    
    Ejemplos:
        forensectl yara update
        forensectl yara update --source github --ruleset malware --force
    """
    try:
        yara_scanner = YaraScanner()
        
        rprint(f"[blue]🔄 Actualizando reglas YARA[/blue]")
        
        # Mostrar configuración
        if rule_sources:
            rprint(f"[yellow]📡 Fuentes: {', '.join(rule_sources)}[/yellow]")
        if rule_sets:
            rprint(f"[yellow]📋 Conjuntos: {', '.join(rule_sets)}[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarea de actualización
            update_task = progress.add_task("Descargando actualizaciones...", total=100)
            
            # Actualizar reglas
            update_results = yara_scanner.update_rules(
                rule_sources=rule_sources,
                rule_sets=rule_sets,
                output_dir=output_dir,
                force_update=force_update,
                verify_signatures=verify_signatures,
                progress_callback=lambda p: progress.update(update_task, completed=p)
            )
            
            progress.update(update_task, completed=100)
        
        # Mostrar resumen
        rprint(f"[green]✅ Actualización completada[/green]")
        
        summary_table = Table(title="Resumen de Actualización")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Fuentes Consultadas", str(len(update_results.get("sources", []))))
        summary_table.add_row("Reglas Descargadas", str(update_results.get("downloaded_rules", 0)))
        summary_table.add_row("Reglas Actualizadas", str(update_results.get("updated_rules", 0)))
        summary_table.add_row("Reglas Nuevas", str(update_results.get("new_rules", 0)))
        summary_table.add_row("Errores", str(len(update_results.get("errors", []))))
        summary_table.add_row("Verificación de Firmas", "✅ Sí" if verify_signatures else "❌ No")
        summary_table.add_row("Directorio de Salida", str(update_results.get("output_dir", "N/A")))
        
        console.print(summary_table)
        
        # Mostrar nuevas reglas importantes
        if update_results.get("important_updates"):
            rprint("\n[bold yellow]🆕 Actualizaciones Importantes:[/bold yellow]")
            for update in update_results["important_updates"][:5]:
                rprint(f"  • {update['ruleset']}: {update['description']}")
        
        # Mostrar errores si los hay
        if update_results.get("errors"):
            rprint("\n[bold red]❌ Errores Durante la Actualización:[/bold red]")
            for error in update_results["errors"][:5]:
                rprint(f"  • {error['source']}: {error['message']}")
        
    except Exception as e:
        logger.error(f"Error actualizando reglas YARA: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("list-rules")
def list_rules(
    rule_dir: Optional[Path] = typer.Option(None, "--directory", "-d", help="Directorio de reglas"),
    rule_sets: Optional[List[str]] = typer.Option(None, "--ruleset", help="Filtrar por conjuntos específicos"),
    show_details: bool = typer.Option(False, "--details", help="Mostrar detalles de las reglas"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json/csv)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Listar reglas YARA disponibles.
    
    Muestra información sobre las reglas YARA disponibles en el sistema.
    
    Ejemplos:
        forensectl yara list-rules
        forensectl yara list-rules --directory /path/to/rules --details
    """
    try:
        yara_scanner = YaraScanner()
        
        # Obtener lista de reglas
        rules_info = yara_scanner.list_rules(
            rule_dir=rule_dir,
            rule_sets=rule_sets,
            include_details=show_details
        )
        
        if not rules_info.get("rules"):
            rprint("[yellow]📭 No se encontraron reglas YARA[/yellow]")
            return
        
        rprint(f"[blue]📋 Reglas YARA Disponibles ({len(rules_info['rules'])} encontradas)[/blue]")
        
        if output_format == "table":
            # Mostrar como tabla
            table = Table(title="Reglas YARA")
            table.add_column("Archivo", style="cyan")
            table.add_column("Conjunto", style="yellow")
            table.add_column("Reglas", style="blue")
            table.add_column("Tamaño", style="green")
            table.add_column("Modificado", style="white")
            
            if show_details:
                table.add_column("Descripción", style="magenta")
            
            for rule in rules_info["rules"]:
                # Formatear tamaño
                size = rule.get("size", 0)
                if size > 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size} B"
                
                row_data = [
                    rule.get("filename", "N/A"),
                    rule.get("ruleset", "N/A"),
                    str(rule.get("rule_count", 0)),
                    size_str,
                    rule.get("modified", "N/A")
                ]
                
                if show_details:
                    description = rule.get("description", "N/A")
                    if len(description) > 50:
                        description = description[:47] + "..."
                    row_data.append(description)
                
                table.add_row(*row_data)
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(rules_info, indent=2))
        
        elif output_format == "csv":
            # TODO: Implementar salida CSV
            rprint("[yellow]⚠️ Formato CSV no implementado aún[/yellow]")
        
        # Mostrar estadísticas
        stats = rules_info.get("statistics", {})
        if stats:
            rprint("\n[bold blue]📊 Estadísticas:[/bold blue]")
            rprint(f"  • Total de archivos: {stats.get('total_files', 0)}")
            rprint(f"  • Total de reglas: {stats.get('total_rules', 0)}")
            rprint(f"  • Conjuntos únicos: {stats.get('unique_rulesets', 0)}")
            rprint(f"  • Tamaño total: {stats.get('total_size', 0):,} bytes")
        
    except Exception as e:
        logger.error(f"Error listando reglas YARA: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("results")
def show_results(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    scan_id: Optional[str] = typer.Option(None, "--scan", "-s", help="ID de escaneo específico"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filtrar por severidad (low/medium/high/critical)"),
    rule_name: Optional[str] = typer.Option(None, "--rule", "-r", help="Filtrar por nombre de regla"),
    file_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filtrar por tipo de archivo"),
    limit: int = typer.Option(50, "--limit", "-l", help="Número máximo de resultados"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json/csv)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📊 Mostrar resultados de escaneos YARA.
    
    Muestra los resultados de escaneos YARA ejecutados previamente,
    con opciones de filtrado y formato.
    
    Ejemplos:
        forensectl yara results --case CASE-001
        forensectl yara results -c CASE-001 --severity high --limit 20
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        yara_scanner = YaraScanner(case_id, case_manager=case_manager)
        
        # Obtener resultados
        results = yara_scanner.get_results(
            scan_id=scan_id,
            severity=severity,
            rule_name=rule_name,
            file_type=file_type,
            limit=limit
        )
        
        if not results.get("matches"):
            rprint(f"[yellow]📭 No se encontraron resultados para el caso {case_id}[/yellow]")
            return
        
        rprint(f"[blue]📊 Resultados YARA - Caso: {case_id}[/blue]")
        rprint(f"[yellow]🔍 {len(results['matches'])} coincidencias encontradas[/yellow]")
        
        if output_format == "table":
            # Mostrar como tabla
            table = Table(title="Coincidencias YARA")
            table.add_column("Archivo", style="cyan")
            table.add_column("Regla", style="yellow")
            table.add_column("Severidad", style="red")
            table.add_column("Descripción", style="white")
            table.add_column("Fecha", style="blue")
            
            for match in results["matches"]:
                # Formatear severidad con colores
                severity_val = match.get("severity", "unknown").lower()
                severity_color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "green",
                    "unknown": "white"
                }.get(severity_val, "white")
                
                # Truncar descripción si es muy larga
                description = match.get("description", "N/A")
                if len(description) > 60:
                    description = description[:57] + "..."
                
                table.add_row(
                    match.get("file_path", "N/A"),
                    match.get("rule_name", "N/A"),
                    f"[{severity_color}]{severity_val.upper()}[/{severity_color}]",
                    description,
                    match.get("timestamp", "N/A")
                )
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(results, indent=2))
        
        elif output_format == "csv":
            # TODO: Implementar salida CSV
            rprint("[yellow]⚠️ Formato CSV no implementado aún[/yellow]")
        
        # Mostrar estadísticas
        stats = results.get("statistics", {})
        if stats:
            rprint("\n[bold blue]📊 Estadísticas de Resultados:[/bold blue]")
            rprint(f"  • Total de coincidencias: {stats.get('total_matches', 0)}")
            rprint(f"  • Archivos afectados: {stats.get('affected_files', 0)}")
            rprint(f"  • Reglas activadas: {stats.get('triggered_rules', 0)}")
            
            # Distribución por severidad
            if stats.get("severity_distribution"):
                rprint("  • Distribución por severidad:")
                for sev, count in stats["severity_distribution"].items():
                    rprint(f"    - {sev}: {count}")
        
    except Exception as e:
        logger.error(f"Error mostrando resultados YARA: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)