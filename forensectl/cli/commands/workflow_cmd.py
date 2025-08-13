"""Comandos CLI para gestión de flujos de trabajo forenses."""

from pathlib import Path
from typing import Optional, List, Dict, Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.tree import Tree
from rich import print as rprint

from forensectl import logger
from forensectl.core.case_manager import CaseManager
from forensectl.core.workflow_manager import WorkflowManager

console = Console()

# Crear aplicación Typer para comandos de workflow
app = typer.Typer(
    name="workflow",
    help="🔄 Comandos para gestión de flujos de trabajo forenses",
    no_args_is_help=True
)


@app.command("create")
def create_workflow(
    name: str = typer.Option(..., "--name", "-n", help="Nombre del flujo de trabajo"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Descripción del flujo"),
    template: Optional[str] = typer.Option(None, "--template", "-t", help="Plantilla base (standard/comprehensive/custom)"),
    steps_file: Optional[Path] = typer.Option(None, "--steps", "-s", help="Archivo JSON con definición de pasos"),
    category: str = typer.Option("general", "--category", "-c", help="Categoría del flujo (general/malware/incident/compliance)"),
    priority: str = typer.Option("medium", "--priority", "-p", help="Prioridad (low/medium/high/critical)"),
    auto_execute: bool = typer.Option(False, "--auto-execute", help="Ejecución automática de pasos"),
    parallel_execution: bool = typer.Option(False, "--parallel", help="Permitir ejecución paralela"),
    timeout_minutes: int = typer.Option(60, "--timeout", help="Timeout en minutos"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🆕 Crear un nuevo flujo de trabajo forense.
    
    Crea un flujo de trabajo personalizado con pasos definidos
    para automatizar procesos forenses comunes.
    
    Ejemplos:
        forensectl workflow create --name "Análisis Malware" --template comprehensive
        forensectl workflow create -n "Incident Response" --steps incident_steps.json
        forensectl workflow create -n "Quick Scan" --auto-execute --parallel
    """
    try:
        # Inicializar manager
        workflow_manager = WorkflowManager(work_dir=work_dir) if work_dir else WorkflowManager()
        
        rprint(f"[blue]🆕 Creando flujo de trabajo: {name}[/blue]")
        
        # Preparar configuración del workflow
        workflow_config = {
            "name": name,
            "description": description or f"Flujo de trabajo forense: {name}",
            "category": category,
            "priority": priority,
            "auto_execute": auto_execute,
            "parallel_execution": parallel_execution,
            "timeout_minutes": timeout_minutes,
            "created_by": "forensectl-cli"
        }
        
        # Cargar pasos desde archivo si se proporciona
        steps_definition = None
        if steps_file:
            if not steps_file.exists():
                rprint(f"[red]❌ Archivo de pasos no encontrado: {steps_file}[/red]")
                raise typer.Exit(1)
            
            try:
                import json
                with open(steps_file, 'r', encoding='utf-8') as f:
                    steps_definition = json.load(f)
                rprint(f"[green]✅ Pasos cargados desde: {steps_file}[/green]")
            except Exception as e:
                rprint(f"[red]❌ Error cargando archivo de pasos: {e}[/red]")
                raise typer.Exit(1)
        
        # Crear workflow
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            create_task = progress.add_task("Creando flujo de trabajo...", total=100)
            
            workflow = workflow_manager.create_workflow(
                config=workflow_config,
                template=template,
                steps_definition=steps_definition
            )
            
            progress.update(create_task, completed=100)
        
        workflow_id = workflow.get("workflow_id")
        rprint(f"[green]✅ Flujo de trabajo creado exitosamente[/green]")
        rprint(f"[yellow]🆔 ID del flujo: {workflow_id}[/yellow]")
        
        # Mostrar información del workflow creado
        info_table = Table(title="Información del Flujo de Trabajo")
        info_table.add_column("Campo", style="cyan")
        info_table.add_column("Valor", style="white")
        
        info_table.add_row("ID", workflow_id)
        info_table.add_row("Nombre", workflow.get("name", "N/A"))
        info_table.add_row("Descripción", workflow.get("description", "N/A"))
        info_table.add_row("Categoría", workflow.get("category", "N/A").title())
        info_table.add_row("Prioridad", workflow.get("priority", "N/A").title())
        info_table.add_row("Ejecución Automática", "✅ Sí" if workflow.get("auto_execute") else "❌ No")
        info_table.add_row("Ejecución Paralela", "✅ Sí" if workflow.get("parallel_execution") else "❌ No")
        info_table.add_row("Timeout", f"{workflow.get('timeout_minutes', 0)} minutos")
        info_table.add_row("Total de Pasos", str(len(workflow.get("steps", []))))
        info_table.add_row("Fecha de Creación", workflow.get("created_at", "N/A"))
        
        console.print(info_table)
        
        # Mostrar pasos del workflow
        steps = workflow.get("steps", [])
        if steps:
            rprint("\n[bold blue]📋 Pasos del Flujo de Trabajo:[/bold blue]")
            
            steps_tree = Tree("🔄 Flujo de Trabajo")
            
            for i, step in enumerate(steps, 1):
                step_name = step.get("name", f"Paso {i}")
                step_type = step.get("type", "unknown")
                step_description = step.get("description", "Sin descripción")
                
                step_icon = {
                    "acquire": "📥",
                    "analyze": "🔍",
                    "timeline": "📅",
                    "yara": "🛡️",
                    "report": "📄",
                    "verify": "✅",
                    "custom": "⚙️"
                }.get(step_type, "📋")
                
                step_node = steps_tree.add(f"{step_icon} {step_name} ({step_type})")
                step_node.add(f"📝 {step_description}")
                
                # Mostrar dependencias si las hay
                dependencies = step.get("dependencies", [])
                if dependencies:
                    deps_str = ", ".join(dependencies)
                    step_node.add(f"🔗 Dependencias: {deps_str}")
            
            console.print(steps_tree)
        
        # Mostrar comandos útiles
        rprint("\n[bold blue]💡 Comandos Útiles:[/bold blue]")
        rprint(f"  • Ejecutar: [cyan]forensectl workflow run --workflow {workflow_id} --case CASE-ID[/cyan]")
        rprint(f"  • Ver estado: [cyan]forensectl workflow status --workflow {workflow_id}[/cyan]")
        rprint(f"  • Editar: [cyan]forensectl workflow edit --workflow {workflow_id}[/cyan]")
        
    except Exception as e:
        logger.error(f"Error creando flujo de trabajo: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("list")
def list_workflows(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filtrar por categoría"),
    priority: Optional[str] = typer.Option(None, "--priority", "-p", help="Filtrar por prioridad"),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filtrar por estado"),
    show_details: bool = typer.Option(False, "--details", "-d", help="Mostrar detalles"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Listar flujos de trabajo disponibles.
    
    Muestra todos los flujos de trabajo creados con opciones
    de filtrado y formato.
    
    Ejemplos:
        forensectl workflow list
        forensectl workflow list --category malware --details
        forensectl workflow list --priority high --format json
    """
    try:
        # Inicializar manager
        workflow_manager = WorkflowManager(work_dir=work_dir) if work_dir else WorkflowManager()
        
        rprint(f"[blue]📋 Listando flujos de trabajo[/blue]")
        
        # Aplicar filtros
        filters = {}
        if category: filters["category"] = category
        if priority: filters["priority"] = priority
        if status: filters["status"] = status
        
        if filters:
            filter_str = ", ".join([f"{k}: {v}" for k, v in filters.items()])
            rprint(f"[yellow]🔍 Filtros aplicados: {filter_str}[/yellow]")
        
        # Obtener workflows
        workflows = workflow_manager.list_workflows(
            filters=filters,
            include_details=show_details
        )
        
        if not workflows:
            rprint(f"[yellow]📭 No se encontraron flujos de trabajo[/yellow]")
            return
        
        rprint(f"[green]📊 {len(workflows)} flujos de trabajo encontrados[/green]")
        
        if output_format == "table":
            # Mostrar como tabla
            table = Table(title="Flujos de Trabajo")
            table.add_column("ID", style="cyan")
            table.add_column("Nombre", style="white")
            table.add_column("Categoría", style="yellow")
            table.add_column("Prioridad", style="blue")
            table.add_column("Pasos", style="green")
            table.add_column("Estado", style="magenta")
            table.add_column("Creado", style="white")
            
            if show_details:
                table.add_column("Descripción", style="white")
            
            for workflow in workflows:
                workflow_id = workflow.get("workflow_id", "N/A")
                name = workflow.get("name", "N/A")
                category_display = workflow.get("category", "N/A").title()
                priority_display = workflow.get("priority", "N/A").title()
                steps_count = len(workflow.get("steps", []))
                status_display = workflow.get("status", "inactive").title()
                created_at = workflow.get("created_at", "N/A")
                
                # Iconos de prioridad
                priority_icon = {
                    "Critical": "🔴",
                    "High": "🟠",
                    "Medium": "🟡",
                    "Low": "🟢"
                }.get(priority_display, "⚪")
                
                # Iconos de estado
                status_icon = {
                    "Active": "✅",
                    "Running": "🔄",
                    "Completed": "✅",
                    "Failed": "❌",
                    "Paused": "⏸️",
                    "Inactive": "⏹️"
                }.get(status_display, "❓")
                
                # Truncar fecha
                if created_at != "N/A":
                    try:
                        from datetime import datetime
                        created_date = datetime.fromisoformat(created_at)
                        created_at = created_date.strftime("%Y-%m-%d")
                    except:
                        pass
                
                row_data = [
                    workflow_id,
                    name,
                    category_display,
                    f"{priority_icon} {priority_display}",
                    str(steps_count),
                    f"{status_icon} {status_display}",
                    created_at
                ]
                
                if show_details:
                    description = workflow.get("description", "N/A")
                    if len(description) > 50:
                        description = description[:47] + "..."
                    row_data.append(description)
                
                table.add_row(*row_data)
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(workflows, indent=2, default=str))
        
        # Mostrar estadísticas
        if len(workflows) > 1:
            categories = {}
            priorities = {}
            statuses = {}
            
            for workflow in workflows:
                cat = workflow.get("category", "unknown")
                pri = workflow.get("priority", "unknown")
                stat = workflow.get("status", "unknown")
                
                categories[cat] = categories.get(cat, 0) + 1
                priorities[pri] = priorities.get(pri, 0) + 1
                statuses[stat] = statuses.get(stat, 0) + 1
            
            rprint("\n[bold blue]📊 Estadísticas:[/bold blue]")
            
            if categories:
                rprint("  • Por categoría:")
                for cat, count in categories.items():
                    rprint(f"    - {cat.title()}: {count}")
            
            if priorities:
                rprint("  • Por prioridad:")
                for pri, count in priorities.items():
                    rprint(f"    - {pri.title()}: {count}")
            
            if statuses:
                rprint("  • Por estado:")
                for stat, count in statuses.items():
                    rprint(f"    - {stat.title()}: {count}")
        
    except Exception as e:
        logger.error(f"Error listando flujos de trabajo: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("run")
def run_workflow(
    workflow_id: str = typer.Option(..., "--workflow", "-w", help="ID del flujo de trabajo"),
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    evidence_ids: Optional[List[str]] = typer.Option(None, "--evidence", "-e", help="IDs de evidencias específicas"),
    parameters: Optional[List[str]] = typer.Option(None, "--param", "-p", help="Parámetros adicionales (key=value)"),
    skip_steps: Optional[List[str]] = typer.Option(None, "--skip", help="Pasos a omitir"),
    start_from_step: Optional[str] = typer.Option(None, "--start-from", help="Iniciar desde paso específico"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulación sin ejecutar"),
    parallel: bool = typer.Option(False, "--parallel", help="Ejecución paralela cuando sea posible"),
    continue_on_error: bool = typer.Option(False, "--continue-on-error", help="Continuar si hay errores"),
    save_intermediate: bool = typer.Option(True, "--save-intermediate/--no-save", help="Guardar resultados intermedios"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """▶️ Ejecutar un flujo de trabajo forense.
    
    Ejecuta un flujo de trabajo específico en un caso,
    con opciones de personalización y control.
    
    Ejemplos:
        forensectl workflow run --workflow WF-001 --case CASE-001
        forensectl workflow run -w WF-001 -c CASE-001 --evidence EV-001 --parallel
        forensectl workflow run -w WF-001 -c CASE-001 --param timeout=120 --dry-run
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        workflow_manager = WorkflowManager(work_dir=work_dir) if work_dir else WorkflowManager()
        
        # Verificar caso
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        # Verificar workflow
        workflow = workflow_manager.get_workflow(workflow_id)
        if not workflow:
            rprint(f"[red]❌ Flujo de trabajo {workflow_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        rprint(f"[blue]▶️ Ejecutando flujo de trabajo: {workflow.get('name', workflow_id)}[/blue]")
        rprint(f"[yellow]📋 Caso: {case_id}[/yellow]")
        
        if dry_run:
            rprint(f"[yellow]🔍 Modo simulación (dry-run)[/yellow]")
        
        # Parsear parámetros adicionales
        parsed_parameters = {}
        if parameters:
            for param in parameters:
                if "=" in param:
                    key, value = param.split("=", 1)
                    parsed_parameters[key.strip()] = value.strip()
                else:
                    rprint(f"[yellow]⚠️ Parámetro inválido ignorado: {param}[/yellow]")
        
        # Mostrar configuración de ejecución
        config_table = Table(title="Configuración de Ejecución")
        config_table.add_column("Opción", style="cyan")
        config_table.add_column("Valor", style="white")
        
        config_table.add_row("Flujo de Trabajo", f"{workflow_id} ({workflow.get('name', 'N/A')})")
        config_table.add_row("Caso", case_id)
        config_table.add_row("Evidencias", ", ".join(evidence_ids) if evidence_ids else "Todas")
        config_table.add_row("Ejecución Paralela", "✅ Sí" if parallel else "❌ No")
        config_table.add_row("Continuar en Error", "✅ Sí" if continue_on_error else "❌ No")
        config_table.add_row("Guardar Intermedios", "✅ Sí" if save_intermediate else "❌ No")
        
        if skip_steps:
            config_table.add_row("Pasos Omitidos", ", ".join(skip_steps))
        
        if start_from_step:
            config_table.add_row("Iniciar Desde", start_from_step)
        
        if parsed_parameters:
            params_str = ", ".join([f"{k}={v}" for k, v in parsed_parameters.items()])
            config_table.add_row("Parámetros", params_str)
        
        console.print(config_table)
        
        # Preparar configuración de ejecución
        execution_config = {
            "case_id": case_id,
            "evidence_ids": evidence_ids,
            "parameters": parsed_parameters,
            "skip_steps": skip_steps or [],
            "start_from_step": start_from_step,
            "dry_run": dry_run,
            "parallel_execution": parallel,
            "continue_on_error": continue_on_error,
            "save_intermediate_results": save_intermediate
        }
        
        # Ejecutar workflow
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            execution_task = progress.add_task("Ejecutando flujo de trabajo...", total=100)
            
            execution_result = workflow_manager.execute_workflow(
                workflow_id=workflow_id,
                execution_config=execution_config,
                progress_callback=lambda p, desc: progress.update(
                    execution_task, 
                    completed=p, 
                    description=desc or "Ejecutando flujo de trabajo..."
                )
            )
            
            progress.update(execution_task, completed=100)
        
        # Mostrar resultados
        execution_id = execution_result.get("execution_id")
        status = execution_result.get("status", "unknown")
        
        status_color = {
            "completed": "green",
            "failed": "red",
            "partial": "yellow",
            "cancelled": "blue"
        }.get(status, "white")
        
        status_icon = {
            "completed": "✅",
            "failed": "❌",
            "partial": "⚠️",
            "cancelled": "⏹️"
        }.get(status, "❓")
        
        rprint(f"\n[{status_color}]{status_icon} Ejecución {status.upper()}[/{status_color}]")
        rprint(f"[yellow]🆔 ID de ejecución: {execution_id}[/yellow]")
        
        # Tabla de resultados
        results_table = Table(title="Resultados de Ejecución")
        results_table.add_column("Campo", style="cyan")
        results_table.add_column("Valor", style="white")
        
        results_table.add_row("ID de Ejecución", execution_id)
        results_table.add_row("Estado", f"{status_icon} {status.upper()}")
        results_table.add_row("Pasos Ejecutados", str(execution_result.get("steps_executed", 0)))
        results_table.add_row("Pasos Exitosos", str(execution_result.get("steps_successful", 0)))
        results_table.add_row("Pasos Fallidos", str(execution_result.get("steps_failed", 0)))
        results_table.add_row("Pasos Omitidos", str(execution_result.get("steps_skipped", 0)))
        results_table.add_row("Tiempo Total", f"{execution_result.get('total_time_seconds', 0):.2f} segundos")
        results_table.add_row("Inicio", execution_result.get("start_time", "N/A"))
        results_table.add_row("Fin", execution_result.get("end_time", "N/A"))
        
        console.print(results_table)
        
        # Mostrar detalles de pasos
        step_results = execution_result.get("step_results", [])
        if step_results:
            rprint("\n[bold blue]📋 Detalles de Pasos:[/bold blue]")
            
            steps_table = Table()
            steps_table.add_column("Paso", style="cyan")
            steps_table.add_column("Estado", style="white")
            steps_table.add_column("Tiempo", style="yellow")
            steps_table.add_column("Resultado", style="green")
            
            for step_result in step_results:
                step_name = step_result.get("step_name", "N/A")
                step_status = step_result.get("status", "unknown")
                step_time = step_result.get("execution_time_seconds", 0)
                step_output = step_result.get("output_summary", "N/A")
                
                step_icon = {
                    "completed": "✅",
                    "failed": "❌",
                    "skipped": "⏭️",
                    "running": "🔄"
                }.get(step_status, "❓")
                
                # Truncar resultado si es muy largo
                if len(step_output) > 40:
                    step_output = step_output[:37] + "..."
                
                steps_table.add_row(
                    step_name,
                    f"{step_icon} {step_status.upper()}",
                    f"{step_time:.2f}s",
                    step_output
                )
            
            console.print(steps_table)
        
        # Mostrar errores si los hay
        errors = execution_result.get("errors", [])
        if errors:
            rprint("\n[bold red]❌ Errores Encontrados:[/bold red]")
            for error in errors[:5]:
                step_name = error.get("step_name", "N/A")
                error_message = error.get("message", "N/A")
                rprint(f"  • [{step_name}] {error_message}")
        
        # Mostrar archivos generados
        generated_files = execution_result.get("generated_files", [])
        if generated_files:
            rprint("\n[bold blue]📄 Archivos Generados:[/bold blue]")
            for file_info in generated_files[:10]:
                file_path = file_info.get("path", "N/A")
                file_type = file_info.get("type", "N/A")
                file_size = file_info.get("size_bytes", 0)
                
                # Formatear tamaño
                if file_size > 1024**2:  # MB
                    size_display = f"{file_size / (1024**2):.2f} MB"
                elif file_size > 1024:  # KB
                    size_display = f"{file_size / 1024:.2f} KB"
                else:
                    size_display = f"{file_size} bytes"
                
                rprint(f"  • [{file_type}] {file_path} ({size_display})")
        
        # Comandos útiles
        rprint("\n[bold blue]💡 Comandos Útiles:[/bold blue]")
        rprint(f"  • Ver detalles: [cyan]forensectl workflow status --execution {execution_id}[/cyan]")
        rprint(f"  • Ver logs: [cyan]forensectl workflow logs --execution {execution_id}[/cyan]")
        
        if status == "failed":
            rprint(f"  • Reintentar: [cyan]forensectl workflow run --workflow {workflow_id} --case {case_id}[/cyan]")
        
        # Salir con código de error si falló
        if status == "failed" and not continue_on_error:
            raise typer.Exit(1)
        
    except Exception as e:
        logger.error(f"Error ejecutando flujo de trabajo: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("status")
def workflow_status(
    workflow_id: Optional[str] = typer.Option(None, "--workflow", "-w", help="ID del flujo de trabajo"),
    execution_id: Optional[str] = typer.Option(None, "--execution", "-e", help="ID de ejecución específica"),
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Filtrar por caso"),
    show_logs: bool = typer.Option(False, "--logs", "-l", help="Mostrar logs"),
    show_details: bool = typer.Option(False, "--details", "-d", help="Mostrar detalles"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📊 Verificar estado de flujos de trabajo y ejecuciones.
    
    Muestra el estado actual de flujos de trabajo y sus ejecuciones,
    con opciones de filtrado y detalle.
    
    Ejemplos:
        forensectl workflow status --workflow WF-001
        forensectl workflow status --execution EX-001 --logs
        forensectl workflow status --case CASE-001 --details
    """
    try:
        # Inicializar manager
        workflow_manager = WorkflowManager(work_dir=work_dir) if work_dir else WorkflowManager()
        
        if execution_id:
            # Mostrar estado de ejecución específica
            rprint(f"[blue]📊 Estado de ejecución: {execution_id}[/blue]")
            
            execution_status = workflow_manager.get_execution_status(execution_id)
            
            if not execution_status:
                rprint(f"[red]❌ Ejecución {execution_id} no encontrada[/red]")
                raise typer.Exit(1)
            
            _display_execution_status(execution_status, show_logs, show_details, console)
        
        elif workflow_id:
            # Mostrar estado de workflow específico
            rprint(f"[blue]📊 Estado del flujo de trabajo: {workflow_id}[/blue]")
            
            workflow_status_data = workflow_manager.get_workflow_status(workflow_id)
            
            if not workflow_status_data:
                rprint(f"[red]❌ Flujo de trabajo {workflow_id} no encontrado[/red]")
                raise typer.Exit(1)
            
            _display_workflow_status(workflow_status_data, show_details, console)
        
        else:
            # Mostrar estado general de todos los workflows
            rprint(f"[blue]📊 Estado general de flujos de trabajo[/blue]")
            
            if case_id:
                rprint(f"[yellow]🔍 Filtrado por caso: {case_id}[/yellow]")
            
            general_status = workflow_manager.get_general_status(
                case_filter=case_id,
                include_details=show_details
            )
            
            _display_general_status(general_status, output_format, console)
        
    except Exception as e:
        logger.error(f"Error obteniendo estado de workflow: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("templates")
def list_templates(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filtrar por categoría"),
    show_details: bool = typer.Option(False, "--details", "-d", help="Mostrar detalles"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Listar plantillas de flujos de trabajo disponibles.
    
    Muestra las plantillas predefinidas que pueden usarse
    como base para crear nuevos flujos de trabajo.
    
    Ejemplos:
        forensectl workflow templates
        forensectl workflow templates --category malware --details
        forensectl workflow templates --format json
    """
    try:
        # Inicializar manager
        workflow_manager = WorkflowManager(work_dir=work_dir) if work_dir else WorkflowManager()
        
        rprint(f"[blue]📋 Plantillas de flujos de trabajo[/blue]")
        
        # Obtener plantillas
        templates = workflow_manager.get_workflow_templates(
            category_filter=category,
            include_details=show_details
        )
        
        if not templates:
            rprint(f"[yellow]📭 No se encontraron plantillas[/yellow]")
            return
        
        rprint(f"[green]📊 {len(templates)} plantillas encontradas[/green]")
        
        if output_format == "table":
            # Mostrar como tabla
            table = Table(title="Plantillas de Flujos de Trabajo")
            table.add_column("Nombre", style="cyan")
            table.add_column("Categoría", style="yellow")
            table.add_column("Pasos", style="green")
            table.add_column("Descripción", style="white")
            
            if show_details:
                table.add_column("Autor", style="blue")
                table.add_column("Versión", style="magenta")
            
            for template in templates:
                template_name = template.get("name", "N/A")
                template_category = template.get("category", "N/A").title()
                steps_count = len(template.get("steps", []))
                description = template.get("description", "N/A")
                
                # Truncar descripción
                if len(description) > 50:
                    description = description[:47] + "..."
                
                row_data = [
                    template_name,
                    template_category,
                    str(steps_count),
                    description
                ]
                
                if show_details:
                    author = template.get("author", "N/A")
                    version = template.get("version", "N/A")
                    row_data.extend([author, version])
                
                table.add_row(*row_data)
            
            console.print(table)
        
        elif output_format == "json":
            import json
            rprint(json.dumps(templates, indent=2, default=str))
        
        # Mostrar estadísticas por categoría
        if len(templates) > 1:
            categories = {}
            for template in templates:
                cat = template.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1
            
            rprint("\n[bold blue]📊 Por Categoría:[/bold blue]")
            for cat, count in categories.items():
                rprint(f"  • {cat.title()}: {count}")
        
        # Mostrar comandos útiles
        rprint("\n[bold blue]💡 Comandos Útiles:[/bold blue]")
        rprint("  • Crear desde plantilla: [cyan]forensectl workflow create --template TEMPLATE_NAME[/cyan]")
        rprint("  • Ver detalles: [cyan]forensectl workflow templates --details[/cyan]")
        
    except Exception as e:
        logger.error(f"Error listando plantillas: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


def _display_execution_status(execution_status: Dict[str, Any], show_logs: bool, show_details: bool, console: Console) -> None:
    """Mostrar estado de una ejecución específica."""
    # Información básica
    status_table = Table(title="Estado de Ejecución")
    status_table.add_column("Campo", style="cyan")
    status_table.add_column("Valor", style="white")
    
    execution_id = execution_status.get("execution_id", "N/A")
    workflow_id = execution_status.get("workflow_id", "N/A")
    case_id = execution_status.get("case_id", "N/A")
    status = execution_status.get("status", "unknown")
    
    status_icon = {
        "running": "🔄",
        "completed": "✅",
        "failed": "❌",
        "paused": "⏸️",
        "cancelled": "⏹️"
    }.get(status, "❓")
    
    status_table.add_row("ID de Ejecución", execution_id)
    status_table.add_row("Flujo de Trabajo", workflow_id)
    status_table.add_row("Caso", case_id)
    status_table.add_row("Estado", f"{status_icon} {status.upper()}")
    status_table.add_row("Progreso", f"{execution_status.get('progress_percentage', 0):.1f}%")
    status_table.add_row("Paso Actual", execution_status.get("current_step", "N/A"))
    status_table.add_row("Inicio", execution_status.get("start_time", "N/A"))
    
    if execution_status.get("end_time"):
        status_table.add_row("Fin", execution_status.get("end_time", "N/A"))
    
    status_table.add_row("Tiempo Transcurrido", f"{execution_status.get('elapsed_time_seconds', 0):.2f} segundos")
    
    console.print(status_table)
    
    # Mostrar logs si se solicita
    if show_logs:
        logs = execution_status.get("logs", [])
        if logs:
            rprint("\n[bold blue]📋 Logs de Ejecución:[/bold blue]")
            for log_entry in logs[-10:]:  # Últimos 10 logs
                timestamp = log_entry.get("timestamp", "N/A")
                level = log_entry.get("level", "INFO")
                message = log_entry.get("message", "N/A")
                
                level_color = {
                    "ERROR": "red",
                    "WARNING": "yellow",
                    "INFO": "blue",
                    "DEBUG": "white"
                }.get(level, "white")
                
                rprint(f"  [{level_color}][{timestamp}] {level}: {message}[/{level_color}]")


def _display_workflow_status(workflow_status: Dict[str, Any], show_details: bool, console: Console) -> None:
    """Mostrar estado de un workflow específico."""
    # Información del workflow
    workflow_table = Table(title="Estado del Flujo de Trabajo")
    workflow_table.add_column("Campo", style="cyan")
    workflow_table.add_column("Valor", style="white")
    
    workflow_id = workflow_status.get("workflow_id", "N/A")
    name = workflow_status.get("name", "N/A")
    status = workflow_status.get("status", "inactive")
    
    workflow_table.add_row("ID", workflow_id)
    workflow_table.add_row("Nombre", name)
    workflow_table.add_row("Estado", status.title())
    workflow_table.add_row("Total de Ejecuciones", str(workflow_status.get("total_executions", 0)))
    workflow_table.add_row("Ejecuciones Exitosas", str(workflow_status.get("successful_executions", 0)))
    workflow_table.add_row("Ejecuciones Fallidas", str(workflow_status.get("failed_executions", 0)))
    workflow_table.add_row("Última Ejecución", workflow_status.get("last_execution_time", "N/A"))
    
    console.print(workflow_table)
    
    # Mostrar ejecuciones recientes
    recent_executions = workflow_status.get("recent_executions", [])
    if recent_executions:
        rprint("\n[bold blue]📋 Ejecuciones Recientes:[/bold blue]")
        
        executions_table = Table()
        executions_table.add_column("ID", style="cyan")
        executions_table.add_column("Caso", style="yellow")
        executions_table.add_column("Estado", style="white")
        executions_table.add_column("Inicio", style="green")
        executions_table.add_column("Duración", style="blue")
        
        for execution in recent_executions[:5]:
            exec_id = execution.get("execution_id", "N/A")
            case_id = execution.get("case_id", "N/A")
            exec_status = execution.get("status", "unknown")
            start_time = execution.get("start_time", "N/A")
            duration = execution.get("duration_seconds", 0)
            
            exec_icon = {
                "completed": "✅",
                "failed": "❌",
                "running": "🔄",
                "cancelled": "⏹️"
            }.get(exec_status, "❓")
            
            executions_table.add_row(
                exec_id,
                case_id,
                f"{exec_icon} {exec_status.upper()}",
                start_time,
                f"{duration:.2f}s"
            )
        
        console.print(executions_table)


def _display_general_status(general_status: Dict[str, Any], output_format: str, console: Console) -> None:
    """Mostrar estado general de todos los workflows."""
    if output_format == "json":
        import json
        rprint(json.dumps(general_status, indent=2, default=str))
        return
    
    # Estadísticas generales
    stats = general_status.get("statistics", {})
    
    stats_table = Table(title="Estadísticas Generales")
    stats_table.add_column("Métrica", style="cyan")
    stats_table.add_column("Valor", style="white")
    
    stats_table.add_row("Total de Workflows", str(stats.get("total_workflows", 0)))
    stats_table.add_row("Workflows Activos", str(stats.get("active_workflows", 0)))
    stats_table.add_row("Total de Ejecuciones", str(stats.get("total_executions", 0)))
    stats_table.add_row("Ejecuciones en Curso", str(stats.get("running_executions", 0)))
    stats_table.add_row("Ejecuciones Exitosas", str(stats.get("successful_executions", 0)))
    stats_table.add_row("Ejecuciones Fallidas", str(stats.get("failed_executions", 0)))
    
    console.print(stats_table)
    
    # Workflows más utilizados
    popular_workflows = general_status.get("popular_workflows", [])
    if popular_workflows:
        rprint("\n[bold blue]🔥 Workflows Más Utilizados:[/bold blue]")
        
        popular_table = Table()
        popular_table.add_column("Workflow", style="cyan")
        popular_table.add_column("Ejecuciones", style="yellow")
        popular_table.add_column("Tasa de Éxito", style="green")
        
        for workflow in popular_workflows[:5]:
            name = workflow.get("name", "N/A")
            executions = workflow.get("execution_count", 0)
            success_rate = workflow.get("success_rate", 0)
            
            popular_table.add_row(
                name,
                str(executions),
                f"{success_rate:.1f}%"
            )
        
        console.print(popular_table)