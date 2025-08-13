"""Comandos CLI para gestión de retención de datos."""

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
from forensectl.core.retention_manager import RetentionManager

console = Console()

# Crear aplicación Typer para comandos de retención
app = typer.Typer(
    name="retention",
    help="📅 Comandos para gestión de retención de datos",
    no_args_is_help=True
)


@app.command("policy")
def manage_retention_policy(
    case_id: str = typer.Option(..., "--case", "-c", help="ID del caso"),
    action: str = typer.Option(..., "--action", "-a", help="Acción (create/update/view/delete)"),
    retention_period: Optional[int] = typer.Option(None, "--period", "-p", help="Período de retención en días"),
    policy_type: Optional[str] = typer.Option(None, "--type", "-t", help="Tipo de política (legal/regulatory/business)"),
    auto_delete: bool = typer.Option(False, "--auto-delete", help="Eliminación automática al vencer"),
    notification_days: Optional[List[int]] = typer.Option(None, "--notify", help="Días antes del vencimiento para notificar"),
    exceptions: Optional[List[str]] = typer.Option(None, "--exceptions", help="Excepciones a la política"),
    legal_hold: bool = typer.Option(False, "--legal-hold", help="Retención legal (suspende eliminación)"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Descripción de la política"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📋 Gestionar políticas de retención de datos.
    
    Permite crear, actualizar, ver o eliminar políticas de retención
    para casos forenses específicos.
    
    Ejemplos:
        forensectl retention policy --case CASE-001 --action create --period 2555 --type legal
        forensectl retention policy -c CASE-001 -a update --auto-delete --notify 30 --notify 7
        forensectl retention policy -c CASE-001 -a view
    """
    try:
        # Validar acción
        valid_actions = ["create", "update", "view", "delete"]
        if action not in valid_actions:
            rprint(f"[red]❌ Acción inválida: {action}[/red]")
            rprint(f"[yellow]💡 Acciones válidas: {', '.join(valid_actions)}[/yellow]")
            raise typer.Exit(1)
        
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if not case_manager.case_exists(case_id):
            rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
            raise typer.Exit(1)
        
        retention_manager = RetentionManager(case_id, case_manager=case_manager)
        
        if action == "create":
            # Validar parámetros requeridos para crear
            if not retention_period:
                rprint(f"[red]❌ Período de retención requerido para crear política[/red]")
                raise typer.Exit(1)
            
            if not policy_type:
                policy_type = "business"
            
            rprint(f"[blue]📋 Creando política de retención - Caso: {case_id}[/blue]")
            
            # Crear política
            policy_data = {
                "retention_period_days": retention_period,
                "policy_type": policy_type,
                "auto_delete_enabled": auto_delete,
                "notification_days": notification_days or [30, 7, 1],
                "exceptions": exceptions or [],
                "legal_hold": legal_hold,
                "description": description or f"Política de retención para caso {case_id}",
                "created_by": "forensectl-cli",
                "created_at": datetime.now().isoformat()
            }
            
            policy = retention_manager.create_retention_policy(policy_data)
            
            rprint(f"[green]✅ Política de retención creada exitosamente[/green]")
            rprint(f"[yellow]📋 ID de política: {policy.get('policy_id', 'N/A')}[/yellow]")
            
            # Calcular fecha de vencimiento
            expiration_date = datetime.now() + timedelta(days=retention_period)
            rprint(f"[yellow]📅 Fecha de vencimiento: {expiration_date.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
        
        elif action == "update":
            rprint(f"[blue]📝 Actualizando política de retención - Caso: {case_id}[/blue]")
            
            # Preparar datos de actualización
            update_data = {}
            if retention_period is not None:
                update_data["retention_period_days"] = retention_period
            if policy_type is not None:
                update_data["policy_type"] = policy_type
            if auto_delete is not None:
                update_data["auto_delete_enabled"] = auto_delete
            if notification_days is not None:
                update_data["notification_days"] = notification_days
            if exceptions is not None:
                update_data["exceptions"] = exceptions
            if legal_hold is not None:
                update_data["legal_hold"] = legal_hold
            if description is not None:
                update_data["description"] = description
            
            update_data["updated_by"] = "forensectl-cli"
            update_data["updated_at"] = datetime.now().isoformat()
            
            if not update_data:
                rprint(f"[yellow]⚠️ No se especificaron cambios para actualizar[/yellow]")
                return
            
            policy = retention_manager.update_retention_policy(update_data)
            
            rprint(f"[green]✅ Política de retención actualizada exitosamente[/green]")
        
        elif action == "view":
            rprint(f"[blue]👁️ Consultando política de retención - Caso: {case_id}[/blue]")
            
            policy = retention_manager.get_retention_policy()
            
            if not policy:
                rprint(f"[yellow]📭 No se encontró política de retención para el caso {case_id}[/yellow]")
                return
        
        elif action == "delete":
            rprint(f"[blue]🗑️ Eliminando política de retención - Caso: {case_id}[/blue]")
            
            # Confirmar eliminación
            confirm = typer.confirm("¿Está seguro de que desea eliminar la política de retención?")
            if not confirm:
                rprint(f"[yellow]❌ Operación cancelada[/yellow]")
                return
            
            retention_manager.delete_retention_policy()
            
            rprint(f"[green]✅ Política de retención eliminada exitosamente[/green]")
            return
        
        # Mostrar información de la política (para create, update, view)
        if action in ["create", "update", "view"]:
            policy = retention_manager.get_retention_policy()
            
            if policy:
                # Tabla de información de la política
                policy_table = Table(title="Política de Retención")
                policy_table.add_column("Campo", style="cyan")
                policy_table.add_column("Valor", style="white")
                
                policy_table.add_row("ID de Política", policy.get("policy_id", "N/A"))
                policy_table.add_row("Caso", case_id)
                policy_table.add_row("Período de Retención", f"{policy.get('retention_period_days', 0)} días")
                policy_table.add_row("Tipo de Política", policy.get("policy_type", "N/A").title())
                policy_table.add_row("Eliminación Automática", "✅ Habilitada" if policy.get("auto_delete_enabled") else "❌ Deshabilitada")
                policy_table.add_row("Retención Legal", "🔒 Activa" if policy.get("legal_hold") else "🔓 Inactiva")
                
                # Notificaciones
                notification_days = policy.get("notification_days", [])
                if notification_days:
                    notifications_str = ", ".join([f"{days} días" for days in notification_days])
                    policy_table.add_row("Notificaciones", notifications_str)
                else:
                    policy_table.add_row("Notificaciones", "❌ Ninguna")
                
                # Excepciones
                exceptions = policy.get("exceptions", [])
                if exceptions:
                    exceptions_str = ", ".join(exceptions[:3])
                    if len(exceptions) > 3:
                        exceptions_str += f" (+{len(exceptions) - 3} más)"
                    policy_table.add_row("Excepciones", exceptions_str)
                else:
                    policy_table.add_row("Excepciones", "❌ Ninguna")
                
                policy_table.add_row("Descripción", policy.get("description", "N/A"))
                policy_table.add_row("Creada", policy.get("created_at", "N/A"))
                policy_table.add_row("Creada por", policy.get("created_by", "N/A"))
                
                if policy.get("updated_at"):
                    policy_table.add_row("Última Actualización", policy.get("updated_at", "N/A"))
                    policy_table.add_row("Actualizada por", policy.get("updated_by", "N/A"))
                
                console.print(policy_table)
                
                # Calcular y mostrar fechas importantes
                if policy.get("retention_period_days"):
                    created_date = datetime.fromisoformat(policy.get("created_at", datetime.now().isoformat()))
                    expiration_date = created_date + timedelta(days=policy["retention_period_days"])
                    days_remaining = (expiration_date - datetime.now()).days
                    
                    rprint("\n[bold blue]📅 Fechas Importantes:[/bold blue]")
                    rprint(f"  • Fecha de vencimiento: {expiration_date.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if days_remaining > 0:
                        rprint(f"  • Días restantes: {days_remaining}")
                        
                        # Verificar si hay notificaciones próximas
                        for notify_days in notification_days:
                            if days_remaining <= notify_days:
                                rprint(f"  ⚠️ Notificación: Vence en {days_remaining} días")
                                break
                    else:
                        rprint(f"  🚨 VENCIDA: Hace {abs(days_remaining)} días")
                        if not policy.get("legal_hold"):
                            rprint(f"  ⚠️ Elegible para eliminación automática")
                
                # Mostrar estado de retención legal
                if policy.get("legal_hold"):
                    rprint("\n[bold red]🔒 RETENCIÓN LEGAL ACTIVA[/bold red]")
                    rprint("  • Los datos no pueden ser eliminados automáticamente")
                    rprint("  • Se requiere autorización legal para eliminar")
        
    except Exception as e:
        logger.error(f"Error gestionando política de retención: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("status")
def check_retention_status(
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="ID del caso específico"),
    show_expired: bool = typer.Option(True, "--expired/--no-expired", help="Mostrar casos vencidos"),
    show_expiring: bool = typer.Option(True, "--expiring/--no-expiring", help="Mostrar casos próximos a vencer"),
    expiring_days: int = typer.Option(30, "--expiring-days", help="Días para considerar 'próximo a vencer'"),
    show_legal_hold: bool = typer.Option(True, "--legal-hold/--no-legal-hold", help="Mostrar casos con retención legal"),
    output_format: str = typer.Option("table", "--format", "-f", help="Formato de salida (table/json/csv)"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """📊 Verificar estado de retención de casos.
    
    Muestra el estado de retención de uno o todos los casos,
    incluyendo vencimientos y retenciones legales.
    
    Ejemplos:
        forensectl retention status
        forensectl retention status --case CASE-001
        forensectl retention status --expiring-days 7 --no-expired
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if case_id:
            # Verificar caso específico
            if not case_manager.case_exists(case_id):
                rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
                raise typer.Exit(1)
            
            retention_manager = RetentionManager(case_id, case_manager=case_manager)
            
            rprint(f"[blue]📊 Estado de retención - Caso: {case_id}[/blue]")
            
            # Obtener estado del caso
            status = retention_manager.get_retention_status()
            
            if not status:
                rprint(f"[yellow]📭 No se encontró política de retención para el caso {case_id}[/yellow]")
                return
            
            # Mostrar estado individual
            _display_case_status(case_id, status, console)
        
        else:
            # Verificar todos los casos
            rprint(f"[blue]📊 Estado de retención de todos los casos[/blue]")
            
            # Obtener lista de casos
            cases = case_manager.list_cases()
            
            if not cases:
                rprint(f"[yellow]📭 No se encontraron casos[/yellow]")
                return
            
            # Recopilar estados de retención
            retention_statuses = []
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                console=console
            ) as progress:
                
                status_task = progress.add_task("Verificando estados de retención...", total=len(cases))
                
                for case_info in cases:
                    case_id_current = case_info.get("case_id")
                    if case_id_current:
                        try:
                            retention_manager = RetentionManager(case_id_current, case_manager=case_manager)
                            status = retention_manager.get_retention_status()
                            
                            if status:
                                status["case_id"] = case_id_current
                                retention_statuses.append(status)
                        
                        except Exception as e:
                            logger.warning(f"Error obteniendo estado de retención para caso {case_id_current}: {e}")
                    
                    progress.advance(status_task)
            
            # Filtrar resultados según opciones
            filtered_statuses = []
            
            for status in retention_statuses:
                include_case = False
                
                if status.get("is_expired") and show_expired:
                    include_case = True
                elif status.get("is_expiring", {}).get(f"within_{expiring_days}_days") and show_expiring:
                    include_case = True
                elif status.get("legal_hold") and show_legal_hold:
                    include_case = True
                elif not (status.get("is_expired") or status.get("is_expiring", {}).get(f"within_{expiring_days}_days")):
                    # Casos normales (no vencidos ni próximos a vencer)
                    include_case = True
                
                if include_case:
                    filtered_statuses.append(status)
            
            if not filtered_statuses:
                rprint(f"[yellow]📭 No se encontraron casos que coincidan con los filtros[/yellow]")
                return
            
            rprint(f"[green]📊 {len(filtered_statuses)} casos encontrados[/green]")
            
            if output_format == "table":
                # Mostrar como tabla
                table = Table(title="Estado de Retención de Casos")
                table.add_column("Caso", style="cyan")
                table.add_column("Estado", style="white")
                table.add_column("Días Restantes", style="yellow")
                table.add_column("Fecha Vencimiento", style="blue")
                table.add_column("Retención Legal", style="red")
                table.add_column("Tipo", style="green")
                
                for status in filtered_statuses:
                    case_id_display = status.get("case_id", "N/A")
                    
                    # Determinar estado y color
                    if status.get("is_expired"):
                        status_display = "🚨 VENCIDO"
                    elif status.get("is_expiring", {}).get(f"within_{expiring_days}_days"):
                        status_display = "⚠️ PRÓXIMO A VENCER"
                    elif status.get("legal_hold"):
                        status_display = "🔒 RETENCIÓN LEGAL"
                    else:
                        status_display = "✅ ACTIVO"
                    
                    days_remaining = status.get("days_remaining", 0)
                    if days_remaining < 0:
                        days_display = f"Vencido hace {abs(days_remaining)} días"
                    else:
                        days_display = str(days_remaining)
                    
                    expiration_date = status.get("expiration_date", "N/A")
                    if expiration_date != "N/A":
                        try:
                            exp_date = datetime.fromisoformat(expiration_date)
                            expiration_date = exp_date.strftime("%Y-%m-%d")
                        except:
                            pass
                    
                    legal_hold_display = "🔒 Sí" if status.get("legal_hold") else "🔓 No"
                    policy_type = status.get("policy_type", "N/A").title()
                    
                    table.add_row(
                        case_id_display,
                        status_display,
                        days_display,
                        expiration_date,
                        legal_hold_display,
                        policy_type
                    )
                
                console.print(table)
            
            elif output_format == "json":
                import json
                rprint(json.dumps(filtered_statuses, indent=2, default=str))
            
            elif output_format == "csv":
                # TODO: Implementar salida CSV
                rprint("[yellow]⚠️ Formato CSV no implementado aún[/yellow]")
            
            # Mostrar estadísticas generales
            total_cases = len(filtered_statuses)
            expired_cases = len([s for s in filtered_statuses if s.get("is_expired")])
            expiring_cases = len([s for s in filtered_statuses if s.get("is_expiring", {}).get(f"within_{expiring_days}_days")])
            legal_hold_cases = len([s for s in filtered_statuses if s.get("legal_hold")])
            active_cases = total_cases - expired_cases - expiring_cases
            
            rprint("\n[bold blue]📊 Resumen:[/bold blue]")
            rprint(f"  • Total de casos: {total_cases}")
            rprint(f"  • Casos activos: {active_cases}")
            rprint(f"  • Casos vencidos: {expired_cases}")
            rprint(f"  • Casos próximos a vencer: {expiring_cases}")
            rprint(f"  • Casos con retención legal: {legal_hold_cases}")
            
            # Alertas importantes
            if expired_cases > 0:
                rprint(f"\n[bold red]🚨 ATENCIÓN: {expired_cases} casos han vencido[/bold red]")
            
            if expiring_cases > 0:
                rprint(f"\n[bold yellow]⚠️ ADVERTENCIA: {expiring_cases} casos vencen en {expiring_days} días[/bold yellow]")
        
    except Exception as e:
        logger.error(f"Error verificando estado de retención: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("cleanup")
def cleanup_expired_data(
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="ID del caso específico"),
    dry_run: bool = typer.Option(True, "--dry-run/--execute", help="Simulación sin eliminar datos"),
    force: bool = typer.Option(False, "--force", help="Forzar eliminación (omitir confirmaciones)"),
    skip_legal_hold: bool = typer.Option(True, "--skip-legal-hold/--include-legal-hold", help="Omitir casos con retención legal"),
    backup_before_delete: bool = typer.Option(True, "--backup/--no-backup", help="Crear respaldo antes de eliminar"),
    backup_location: Optional[Path] = typer.Option(None, "--backup-location", help="Ubicación del respaldo"),
    parallel_jobs: int = typer.Option(2, "--jobs", "-j", help="Trabajos paralelos para eliminación"),
    work_dir: Optional[Path] = typer.Option(None, "--work-dir", "-w", help="Directorio de trabajo")
) -> None:
    """🗑️ Limpiar datos vencidos según políticas de retención.
    
    Elimina automáticamente casos y evidencias que han superado
    su período de retención, respetando retenciones legales.
    
    Ejemplos:
        forensectl retention cleanup --dry-run
        forensectl retention cleanup --case CASE-001 --execute --force
        forensectl retention cleanup --execute --backup-location /backup
    """
    try:
        # Inicializar managers
        case_manager = CaseManager(work_dir=work_dir) if work_dir else CaseManager()
        
        if case_id:
            # Limpiar caso específico
            if not case_manager.case_exists(case_id):
                rprint(f"[red]❌ Caso {case_id} no encontrado[/red]")
                raise typer.Exit(1)
            
            cases_to_process = [case_id]
        else:
            # Obtener todos los casos
            cases = case_manager.list_cases()
            cases_to_process = [case["case_id"] for case in cases if case.get("case_id")]
        
        if not cases_to_process:
            rprint(f"[yellow]📭 No se encontraron casos para procesar[/yellow]")
            return
        
        rprint(f"[blue]🗑️ Iniciando limpieza de datos vencidos[/blue]")
        rprint(f"[yellow]📋 Casos a procesar: {len(cases_to_process)}[/yellow]")
        rprint(f"[yellow]🔄 Modo: {'Simulación (dry-run)' if dry_run else 'Ejecución real'}[/yellow]")
        
        # Recopilar casos elegibles para eliminación
        eligible_cases = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            
            scan_task = progress.add_task("Escaneando casos...", total=len(cases_to_process))
            
            for case_id_current in cases_to_process:
                try:
                    retention_manager = RetentionManager(case_id_current, case_manager=case_manager)
                    status = retention_manager.get_retention_status()
                    
                    if status and status.get("is_expired"):
                        # Verificar retención legal
                        if status.get("legal_hold") and skip_legal_hold:
                            rprint(f"[yellow]⏭️ Omitiendo {case_id_current}: Retención legal activa[/yellow]")
                        else:
                            eligible_cases.append({
                                "case_id": case_id_current,
                                "status": status,
                                "retention_manager": retention_manager
                            })
                
                except Exception as e:
                    logger.warning(f"Error evaluando caso {case_id_current}: {e}")
                
                progress.advance(scan_task)
        
        if not eligible_cases:
            rprint(f"[green]✅ No se encontraron casos vencidos elegibles para eliminación[/green]")
            return
        
        rprint(f"[yellow]🎯 Casos elegibles para eliminación: {len(eligible_cases)}[/yellow]")
        
        # Mostrar casos que serán eliminados
        if eligible_cases:
            table = Table(title="Casos Elegibles para Eliminación")
            table.add_column("Caso", style="cyan")
            table.add_column("Días Vencido", style="red")
            table.add_column("Tamaño", style="yellow")
            table.add_column("Retención Legal", style="magenta")
            
            total_size = 0
            
            for case_info in eligible_cases:
                case_id_display = case_info["case_id"]
                status = case_info["status"]
                
                days_expired = abs(status.get("days_remaining", 0))
                case_size = status.get("total_size_bytes", 0)
                total_size += case_size
                
                legal_hold_display = "🔒 Sí" if status.get("legal_hold") else "🔓 No"
                
                # Formatear tamaño
                if case_size > 1024**3:  # GB
                    size_display = f"{case_size / (1024**3):.2f} GB"
                elif case_size > 1024**2:  # MB
                    size_display = f"{case_size / (1024**2):.2f} MB"
                else:
                    size_display = f"{case_size / 1024:.2f} KB"
                
                table.add_row(
                    case_id_display,
                    f"{days_expired} días",
                    size_display,
                    legal_hold_display
                )
            
            console.print(table)
            
            # Mostrar tamaño total
            if total_size > 1024**3:  # GB
                total_size_display = f"{total_size / (1024**3):.2f} GB"
            elif total_size > 1024**2:  # MB
                total_size_display = f"{total_size / (1024**2):.2f} MB"
            else:
                total_size_display = f"{total_size / 1024:.2f} KB"
            
            rprint(f"\n[bold blue]📊 Espacio total a liberar: {total_size_display}[/bold blue]")
        
        # Confirmar eliminación si no es dry-run
        if not dry_run:
            if not force:
                rprint(f"\n[bold red]⚠️ ADVERTENCIA: Esta operación eliminará permanentemente {len(eligible_cases)} casos[/bold red]")
                confirm = typer.confirm("¿Está seguro de que desea continuar?")
                if not confirm:
                    rprint(f"[yellow]❌ Operación cancelada[/yellow]")
                    return
            
            # Crear respaldos si se solicita
            if backup_before_delete:
                rprint(f"[blue]💾 Creando respaldos antes de eliminar...[/blue]")
                
                backup_dir = backup_location or Path.cwd() / "retention_backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    console=console
                ) as progress:
                    
                    backup_task = progress.add_task("Creando respaldos...", total=len(eligible_cases))
                    
                    for case_info in eligible_cases:
                        case_id_backup = case_info["case_id"]
                        retention_manager = case_info["retention_manager"]
                        
                        try:
                            backup_path = retention_manager.create_backup_before_deletion(
                                backup_directory=backup_dir
                            )
                            rprint(f"[green]✅ Respaldo creado: {backup_path}[/green]")
                        
                        except Exception as e:
                            rprint(f"[red]❌ Error creando respaldo para {case_id_backup}: {e}[/red]")
                        
                        progress.advance(backup_task)
            
            # Proceder con eliminación
            rprint(f"[blue]🗑️ Eliminando casos vencidos...[/blue]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                console=console
            ) as progress:
                
                delete_task = progress.add_task("Eliminando casos...", total=len(eligible_cases))
                
                deleted_count = 0
                errors_count = 0
                
                for case_info in eligible_cases:
                    case_id_delete = case_info["case_id"]
                    retention_manager = case_info["retention_manager"]
                    
                    try:
                        deletion_result = retention_manager.delete_expired_case()
                        
                        if deletion_result.get("success"):
                            rprint(f"[green]✅ Caso {case_id_delete} eliminado exitosamente[/green]")
                            deleted_count += 1
                        else:
                            rprint(f"[red]❌ Error eliminando caso {case_id_delete}: {deletion_result.get('error', 'Error desconocido')}[/red]")
                            errors_count += 1
                    
                    except Exception as e:
                        rprint(f"[red]❌ Error eliminando caso {case_id_delete}: {e}[/red]")
                        errors_count += 1
                    
                    progress.advance(delete_task)
                
                # Resumen de eliminación
                rprint(f"\n[bold blue]📊 Resumen de Eliminación:[/bold blue]")
                rprint(f"  • Casos eliminados exitosamente: {deleted_count}")
                rprint(f"  • Errores durante eliminación: {errors_count}")
                rprint(f"  • Total procesados: {len(eligible_cases)}")
                
                if deleted_count > 0:
                    rprint(f"[green]✅ Limpieza completada exitosamente[/green]")
                
                if errors_count > 0:
                    rprint(f"[yellow]⚠️ Se encontraron {errors_count} errores durante la limpieza[/yellow]")
        
        else:
            # Modo dry-run
            rprint(f"\n[bold blue]🔍 SIMULACIÓN COMPLETADA[/bold blue]")
            rprint(f"  • Casos que serían eliminados: {len(eligible_cases)}")
            rprint(f"  • Espacio que se liberaría: {total_size_display}")
            rprint(f"[yellow]💡 Para ejecutar la eliminación real, use --execute[/yellow]")
        
    except Exception as e:
        logger.error(f"Error durante limpieza de datos: {e}")
        rprint(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


def _display_case_status(case_id: str, status: dict, console: Console) -> None:
    """Mostrar estado de retención de un caso individual."""
    # Tabla de estado
    status_table = Table(title=f"Estado de Retención - {case_id}")
    status_table.add_column("Campo", style="cyan")
    status_table.add_column("Valor", style="white")
    
    # Estado general
    if status.get("is_expired"):
        status_display = "🚨 VENCIDO"
        status_color = "red"
    elif status.get("is_expiring", {}).get("within_30_days"):
        status_display = "⚠️ PRÓXIMO A VENCER"
        status_color = "yellow"
    elif status.get("legal_hold"):
        status_display = "🔒 RETENCIÓN LEGAL"
        status_color = "blue"
    else:
        status_display = "✅ ACTIVO"
        status_color = "green"
    
    status_table.add_row("Estado", f"[{status_color}]{status_display}[/{status_color}]")
    
    # Días restantes
    days_remaining = status.get("days_remaining", 0)
    if days_remaining < 0:
        days_display = f"Vencido hace {abs(days_remaining)} días"
    else:
        days_display = f"{days_remaining} días"
    
    status_table.add_row("Días Restantes", days_display)
    
    # Fechas
    if status.get("creation_date"):
        status_table.add_row("Fecha de Creación", status["creation_date"])
    
    if status.get("expiration_date"):
        status_table.add_row("Fecha de Vencimiento", status["expiration_date"])
    
    # Política
    status_table.add_row("Tipo de Política", status.get("policy_type", "N/A").title())
    status_table.add_row("Período de Retención", f"{status.get('retention_period_days', 0)} días")
    
    # Retención legal
    legal_hold_display = "🔒 Activa" if status.get("legal_hold") else "🔓 Inactiva"
    status_table.add_row("Retención Legal", legal_hold_display)
    
    # Eliminación automática
    auto_delete_display = "✅ Habilitada" if status.get("auto_delete_enabled") else "❌ Deshabilitada"
    status_table.add_row("Eliminación Automática", auto_delete_display)
    
    # Tamaño
    total_size = status.get("total_size_bytes", 0)
    if total_size > 1024**3:  # GB
        size_display = f"{total_size / (1024**3):.2f} GB"
    elif total_size > 1024**2:  # MB
        size_display = f"{total_size / (1024**2):.2f} MB"
    else:
        size_display = f"{total_size / 1024:.2f} KB"
    
    status_table.add_row("Tamaño Total", size_display)
    
    console.print(status_table)
    
    # Mostrar alertas específicas
    if status.get("is_expired") and not status.get("legal_hold"):
        console.print("\n[bold red]🚨 ALERTA: Este caso ha vencido y es elegible para eliminación automática[/bold red]")
    
    if status.get("legal_hold"):
        console.print("\n[bold blue]🔒 RETENCIÓN LEGAL: Los datos no pueden ser eliminados automáticamente[/bold blue]")
    
    # Mostrar próximas notificaciones
    notifications = status.get("upcoming_notifications", [])
    if notifications:
        console.print("\n[bold yellow]📅 Próximas Notificaciones:[/bold yellow]")
        for notification in notifications[:3]:
            console.print(f"  • {notification}")