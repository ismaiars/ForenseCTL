"""Gestor de plantillas para reportes forenses."""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from jinja2 import Environment, FileSystemLoader, Template, select_autoescape

from forensectl import config, logger


class TemplateManager:
    """Gestor de plantillas para generación de reportes."""
    
    def __init__(self) -> None:
        """Inicializar gestor de plantillas."""
        # Directorio de plantillas
        self.templates_dir = config.BASE_DIR / "templates"
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurar entorno Jinja2
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Registrar filtros personalizados
        self._register_custom_filters()
        
        # Inicializar plantillas por defecto
        self._initialize_default_templates()
        
        # Catálogo de plantillas disponibles
        self.template_catalog = {
            "technical": {
                "pdf": {
                    "es": "technical_report_es.html",
                    "en": "technical_report_en.html"
                },
                "html": {
                    "es": "technical_report_es.html",
                    "en": "technical_report_en.html"
                },
                "markdown": {
                    "es": "technical_report_es.md",
                    "en": "technical_report_en.md"
                }
            },
            "executive": {
                "pdf": {
                    "es": "executive_report_es.html",
                    "en": "executive_report_en.html"
                },
                "html": {
                    "es": "executive_report_es.html",
                    "en": "executive_report_en.html"
                },
                "markdown": {
                    "es": "executive_report_es.md",
                    "en": "executive_report_en.md"
                }
            },
            "timeline": {
                "html": {
                    "es": "timeline_report_es.html",
                    "en": "timeline_report_en.html"
                }
            },
            "comparison": {
                "html": {
                    "es": "comparison_report_es.html",
                    "en": "comparison_report_en.html"
                }
            }
        }
    
    def get_template(
        self,
        template_name: str,
        output_format: str = "html",
        language: str = "es"
    ) -> Template:
        """Obtener plantilla específica.
        
        Args:
            template_name: Nombre de la plantilla
            output_format: Formato de salida
            language: Idioma de la plantilla
            
        Returns:
            Objeto Template de Jinja2
        """
        # Buscar en catálogo
        template_file = self._resolve_template_file(
            template_name, output_format, language
        )
        
        if not template_file:
            # Usar plantilla por defecto
            template_file = self._get_default_template(output_format, language)
        
        try:
            template = self.jinja_env.get_template(template_file)
            logger.info(f"Plantilla cargada: {template_file}")
            return template
        except Exception as e:
            logger.error(f"Error cargando plantilla {template_file}: {e}")
            # Fallback a plantilla básica
            return self._get_fallback_template(output_format)
    
    def render_template(
        self,
        template: Template,
        data: Dict[str, Any]
    ) -> str:
        """Renderizar plantilla con datos.
        
        Args:
            template: Plantilla a renderizar
            data: Datos para la plantilla
            
        Returns:
            Contenido renderizado
        """
        try:
            # Agregar funciones auxiliares al contexto
            render_context = data.copy()
            render_context.update(self._get_template_context())
            
            rendered_content = template.render(**render_context)
            logger.info("Plantilla renderizada exitosamente")
            return rendered_content
            
        except Exception as e:
            logger.error(f"Error renderizando plantilla: {e}")
            raise
    
    def create_custom_template(
        self,
        template_name: str,
        template_content: str,
        output_format: str = "html",
        language: str = "es",
        description: str = ""
    ) -> bool:
        """Crear plantilla personalizada.
        
        Args:
            template_name: Nombre de la plantilla
            template_content: Contenido de la plantilla
            output_format: Formato de salida
            language: Idioma
            description: Descripción de la plantilla
            
        Returns:
            True si se creó exitosamente
        """
        try:
            # Crear directorio para plantillas personalizadas
            custom_dir = self.templates_dir / "custom"
            custom_dir.mkdir(exist_ok=True)
            
            # Generar nombre de archivo
            template_filename = f"{template_name}_{language}.{self._get_template_extension(output_format)}"
            template_file = custom_dir / template_filename
            
            # Guardar plantilla
            with open(template_file, "w", encoding="utf-8") as f:
                f.write(template_content)
            
            # Guardar metadatos
            metadata = {
                "name": template_name,
                "filename": template_filename,
                "output_format": output_format,
                "language": language,
                "description": description,
                "created_at": "2024-01-01T00:00:00Z",  # Placeholder
                "custom": True
            }
            
            metadata_file = custom_dir / f"{template_filename}.meta.json"
            with open(metadata_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Plantilla personalizada creada: {template_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error creando plantilla personalizada: {e}")
            return False
    
    def list_templates(
        self,
        output_format: Optional[str] = None,
        language: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Listar plantillas disponibles.
        
        Args:
            output_format: Filtrar por formato
            language: Filtrar por idioma
            
        Returns:
            Lista de plantillas disponibles
        """
        templates = []
        
        # Plantillas del catálogo
        for template_type, formats in self.template_catalog.items():
            for fmt, languages in formats.items():
                if output_format and fmt != output_format:
                    continue
                    
                for lang, filename in languages.items():
                    if language and lang != language:
                        continue
                    
                    templates.append({
                        "name": f"default_{template_type}",
                        "type": template_type,
                        "filename": filename,
                        "output_format": fmt,
                        "language": lang,
                        "custom": False,
                        "description": f"Plantilla por defecto para reportes {template_type}"
                    })
        
        # Plantillas personalizadas
        custom_dir = self.templates_dir / "custom"
        if custom_dir.exists():
            for meta_file in custom_dir.glob("*.meta.json"):
                try:
                    with open(meta_file, "r", encoding="utf-8") as f:
                        metadata = json.load(f)
                    
                    if output_format and metadata.get("output_format") != output_format:
                        continue
                    if language and metadata.get("language") != language:
                        continue
                    
                    templates.append(metadata)
                    
                except Exception as e:
                    logger.warning(f"Error leyendo metadatos de plantilla {meta_file}: {e}")
        
        return templates
    
    def validate_template(
        self,
        template_content: str,
        output_format: str = "html"
    ) -> Dict[str, Any]:
        """Validar sintaxis de plantilla.
        
        Args:
            template_content: Contenido de la plantilla
            output_format: Formato de salida
            
        Returns:
            Resultado de la validación
        """
        validation_result = {
            "valid": False,
            "errors": [],
            "warnings": []
        }
        
        try:
            # Validar sintaxis Jinja2
            template = self.jinja_env.from_string(template_content)
            
            # Intentar renderizar con datos de prueba
            test_data = self._get_test_data()
            template.render(**test_data)
            
            validation_result["valid"] = True
            logger.info("Plantilla validada exitosamente")
            
        except Exception as e:
            validation_result["errors"].append(str(e))
            logger.error(f"Error validando plantilla: {e}")
        
        # Validaciones específicas por formato
        if output_format == "html":
            validation_result["warnings"].extend(
                self._validate_html_template(template_content)
            )
        elif output_format == "markdown":
            validation_result["warnings"].extend(
                self._validate_markdown_template(template_content)
            )
        
        return validation_result
    
    def _register_custom_filters(self) -> None:
        """Registrar filtros personalizados para Jinja2."""
        
        def format_datetime(value, format_str="%Y-%m-%d %H:%M:%S"):
            """Formatear fecha y hora."""
            if isinstance(value, str):
                from datetime import datetime
                try:
                    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    return dt.strftime(format_str)
                except:
                    return value
            return value
        
        def format_filesize(value):
            """Formatear tamaño de archivo."""
            try:
                size = int(value)
                for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                    if size < 1024.0:
                        return f"{size:.1f} {unit}"
                    size /= 1024.0
                return f"{size:.1f} PB"
            except:
                return value
        
        def format_duration(value):
            """Formatear duración en segundos."""
            try:
                seconds = float(value)
                hours = int(seconds // 3600)
                minutes = int((seconds % 3600) // 60)
                secs = int(seconds % 60)
                
                if hours > 0:
                    return f"{hours}h {minutes}m {secs}s"
                elif minutes > 0:
                    return f"{minutes}m {secs}s"
                else:
                    return f"{secs}s"
            except:
                return value
        
        def truncate_text(value, length=100):
            """Truncar texto."""
            if len(str(value)) > length:
                return str(value)[:length] + "..."
            return str(value)
        
        # Registrar filtros
        self.jinja_env.filters['format_datetime'] = format_datetime
        self.jinja_env.filters['format_filesize'] = format_filesize
        self.jinja_env.filters['format_duration'] = format_duration
        self.jinja_env.filters['truncate_text'] = truncate_text
    
    def _initialize_default_templates(self) -> None:
        """Inicializar plantillas por defecto."""
        # Crear plantillas básicas si no existen
        default_templates = {
            "technical_report_es.html": self._get_technical_html_template_es(),
            "technical_report_en.html": self._get_technical_html_template_en(),
            "executive_report_es.html": self._get_executive_html_template_es(),
            "executive_report_en.html": self._get_executive_html_template_en(),
            "technical_report_es.md": self._get_technical_markdown_template_es(),
            "technical_report_en.md": self._get_technical_markdown_template_en()
        }
        
        for filename, content in default_templates.items():
            template_file = self.templates_dir / filename
            if not template_file.exists():
                try:
                    with open(template_file, "w", encoding="utf-8") as f:
                        f.write(content)
                    logger.info(f"Plantilla por defecto creada: {filename}")
                except Exception as e:
                    logger.error(f"Error creando plantilla {filename}: {e}")
    
    def _resolve_template_file(
        self,
        template_name: str,
        output_format: str,
        language: str
    ) -> Optional[str]:
        """Resolver archivo de plantilla."""
        # Buscar en catálogo
        if template_name.startswith("default_"):
            template_type = template_name.replace("default_", "")
            if template_type in self.template_catalog:
                formats = self.template_catalog[template_type]
                if output_format in formats:
                    languages = formats[output_format]
                    if language in languages:
                        return languages[language]
        
        # Buscar plantilla personalizada
        custom_dir = self.templates_dir / "custom"
        if custom_dir.exists():
            extension = self._get_template_extension(output_format)
            custom_file = f"{template_name}_{language}.{extension}"
            if (custom_dir / custom_file).exists():
                return f"custom/{custom_file}"
        
        return None
    
    def _get_default_template(
        self,
        output_format: str,
        language: str
    ) -> str:
        """Obtener plantilla por defecto."""
        if output_format == "html":
            return f"technical_report_{language}.html"
        elif output_format == "markdown":
            return f"technical_report_{language}.md"
        else:
            return f"technical_report_{language}.html"
    
    def _get_fallback_template(self, output_format: str) -> Template:
        """Obtener plantilla de respaldo."""
        if output_format == "html":
            content = "<html><body><h1>{{ metadata.title }}</h1><p>Reporte generado</p></body></html>"
        else:
            content = "# {{ metadata.title }}\n\nReporte generado"
        
        return self.jinja_env.from_string(content)
    
    def _get_template_extension(self, output_format: str) -> str:
        """Obtener extensión de plantilla."""
        extensions = {
            "html": "html",
            "pdf": "html",  # PDF usa plantilla HTML
            "markdown": "md",
            "docx": "html"  # DOCX usa plantilla HTML
        }
        return extensions.get(output_format, "html")
    
    def _get_template_context(self) -> Dict[str, Any]:
        """Obtener contexto adicional para plantillas."""
        return {
            "current_date": "2024-01-01",  # Placeholder
            "forensectl_version": "1.0.0",
            "organization": "Organización Forense"
        }
    
    def _get_test_data(self) -> Dict[str, Any]:
        """Obtener datos de prueba para validación."""
        return {
            "metadata": {
                "title": "Reporte de Prueba",
                "case_id": "TEST-001",
                "generated_at": "2024-01-01T00:00:00Z",
                "examiner": "Examinador de Prueba"
            },
            "case_info": {
                "case_id": "TEST-001",
                "description": "Caso de prueba"
            },
            "sections": {
                "executive_summary": {
                    "title": "Resumen Ejecutivo",
                    "content": "Contenido de prueba"
                }
            }
        }
    
    def _validate_html_template(self, content: str) -> List[str]:
        """Validar plantilla HTML."""
        warnings = []
        
        # Verificar etiquetas básicas
        if "<html>" not in content:
            warnings.append("Plantilla HTML no contiene etiqueta <html>")
        if "<head>" not in content:
            warnings.append("Plantilla HTML no contiene etiqueta <head>")
        if "<body>" not in content:
            warnings.append("Plantilla HTML no contiene etiqueta <body>")
        
        return warnings
    
    def _validate_markdown_template(self, content: str) -> List[str]:
        """Validar plantilla Markdown."""
        warnings = []
        
        # Verificar estructura básica
        if not content.strip().startswith("#"):
            warnings.append("Plantilla Markdown no comienza con un encabezado")
        
        return warnings
    
    # Plantillas por defecto
    def _get_technical_html_template_es(self) -> str:
        """Plantilla HTML técnica en español."""
        return '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        .metadata { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        .evidence-list { list-style-type: none; padding: 0; }
        .evidence-item { background: #f9f9f9; margin: 10px 0; padding: 15px; border-left: 4px solid #007acc; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <div class="metadata">
            <p><strong>Caso:</strong> {{ case_info.case_id }}</p>
            <p><strong>Examinador:</strong> {{ metadata.examiner }}</p>
            <p><strong>Fecha de Generación:</strong> {{ metadata.generated_at | format_datetime }}</p>
        </div>
    </div>

    {% for section_name, section in sections.items() %}
    <div class="section">
        <h2>{{ section.title }}</h2>
        <div>{{ section.content }}</div>
    </div>
    {% endfor %}

    <div class="section">
        <h2>Información del Caso</h2>
        <table>
            <tr><th>Campo</th><th>Valor</th></tr>
            <tr><td>ID del Caso</td><td>{{ case_info.case_id }}</td></tr>
            <tr><td>Descripción</td><td>{{ case_info.description | default("N/A") }}</td></tr>
            <tr><td>Examinador</td><td>{{ case_info.examiner | default("N/A") }}</td></tr>
            <tr><td>Organización</td><td>{{ case_info.organization | default("N/A") }}</td></tr>
        </table>
    </div>

    {% if evidences %}
    <div class="section">
        <h2>Evidencias Analizadas</h2>
        <ul class="evidence-list">
        {% for evidence in evidences %}
            <li class="evidence-item">
                <strong>{{ evidence.evidence_id }}</strong><br>
                Tipo: {{ evidence.evidence_type }}<br>
                Descripción: {{ evidence.description | default("N/A") }}<br>
                Tamaño: {{ evidence.file_size | format_filesize }}
            </li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}

    <div class="section">
        <h2>Información de Generación</h2>
        <p>Este reporte fue generado automáticamente por ForenseCTL v{{ forensectl_version }}.</p>
        <p>Fecha y hora de generación: {{ metadata.generated_at | format_datetime }}</p>
    </div>
</body>
</html>'''
    
    def _get_technical_html_template_en(self) -> str:
        """Plantilla HTML técnica en inglés."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        .metadata { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        .evidence-list { list-style-type: none; padding: 0; }
        .evidence-item { background: #f9f9f9; margin: 10px 0; padding: 15px; border-left: 4px solid #007acc; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <div class="metadata">
            <p><strong>Case:</strong> {{ case_info.case_id }}</p>
            <p><strong>Examiner:</strong> {{ metadata.examiner }}</p>
            <p><strong>Generation Date:</strong> {{ metadata.generated_at | format_datetime }}</p>
        </div>
    </div>

    {% for section_name, section in sections.items() %}
    <div class="section">
        <h2>{{ section.title }}</h2>
        <div>{{ section.content }}</div>
    </div>
    {% endfor %}

    <div class="section">
        <h2>Case Information</h2>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Case ID</td><td>{{ case_info.case_id }}</td></tr>
            <tr><td>Description</td><td>{{ case_info.description | default("N/A") }}</td></tr>
            <tr><td>Examiner</td><td>{{ case_info.examiner | default("N/A") }}</td></tr>
            <tr><td>Organization</td><td>{{ case_info.organization | default("N/A") }}</td></tr>
        </table>
    </div>

    {% if evidences %}
    <div class="section">
        <h2>Analyzed Evidence</h2>
        <ul class="evidence-list">
        {% for evidence in evidences %}
            <li class="evidence-item">
                <strong>{{ evidence.evidence_id }}</strong><br>
                Type: {{ evidence.evidence_type }}<br>
                Description: {{ evidence.description | default("N/A") }}<br>
                Size: {{ evidence.file_size | format_filesize }}
            </li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}

    <div class="section">
        <h2>Generation Information</h2>
        <p>This report was automatically generated by ForenseCTL v{{ forensectl_version }}.</p>
        <p>Generation date and time: {{ metadata.generated_at | format_datetime }}</p>
    </div>
</body>
</html>'''
    
    def _get_executive_html_template_es(self) -> str:
        """Plantilla HTML ejecutiva en español."""
        return '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }
        .header { text-align: center; border-bottom: 3px solid #007acc; padding-bottom: 20px; margin-bottom: 40px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #007acc; font-size: 1.5em; margin-bottom: 15px; }
        .executive-summary { background: #f0f8ff; padding: 20px; border-radius: 8px; border-left: 5px solid #007acc; }
        .key-findings { background: #fff5f5; padding: 20px; border-radius: 8px; border-left: 5px solid #ff6b6b; }
        .recommendations { background: #f0fff0; padding: 20px; border-radius: 8px; border-left: 5px solid #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <p><strong>Caso:</strong> {{ case_info.case_id }} | <strong>Fecha:</strong> {{ metadata.generated_at | format_datetime }}</p>
    </div>

    {% for section_name, section in sections.items() %}
    <div class="section {% if section_name == 'executive_summary' %}executive-summary{% elif section_name == 'key_findings' %}key-findings{% elif section_name == 'recommendations' %}recommendations{% endif %}">
        <h2>{{ section.title }}</h2>
        <div>{{ section.content }}</div>
    </div>
    {% endfor %}

    <div class="section">
        <h2>Resumen del Análisis</h2>
        <p>Este reporte ejecutivo presenta los hallazgos principales del análisis forense realizado.</p>
        <p><strong>Examinador:</strong> {{ metadata.examiner }}</p>
        <p><strong>Organización:</strong> {{ organization }}</p>
    </div>
</body>
</html>'''
    
    def _get_executive_html_template_en(self) -> str:
        """Plantilla HTML ejecutiva en inglés."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }
        .header { text-align: center; border-bottom: 3px solid #007acc; padding-bottom: 20px; margin-bottom: 40px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #007acc; font-size: 1.5em; margin-bottom: 15px; }
        .executive-summary { background: #f0f8ff; padding: 20px; border-radius: 8px; border-left: 5px solid #007acc; }
        .key-findings { background: #fff5f5; padding: 20px; border-radius: 8px; border-left: 5px solid #ff6b6b; }
        .recommendations { background: #f0fff0; padding: 20px; border-radius: 8px; border-left: 5px solid #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <p><strong>Case:</strong> {{ case_info.case_id }} | <strong>Date:</strong> {{ metadata.generated_at | format_datetime }}</p>
    </div>

    {% for section_name, section in sections.items() %}
    <div class="section {% if section_name == 'executive_summary' %}executive-summary{% elif section_name == 'key_findings' %}key-findings{% elif section_name == 'recommendations' %}recommendations{% endif %}">
        <h2>{{ section.title }}</h2>
        <div>{{ section.content }}</div>
    </div>
    {% endfor %}

    <div class="section">
        <h2>Analysis Summary</h2>
        <p>This executive report presents the main findings of the forensic analysis performed.</p>
        <p><strong>Examiner:</strong> {{ metadata.examiner }}</p>
        <p><strong>Organization:</strong> {{ organization }}</p>
    </div>
</body>
</html>'''
    
    def _get_technical_markdown_template_es(self) -> str:
        """Plantilla Markdown técnica en español."""
        return '''# {{ metadata.title }}

**Caso:** {{ case_info.case_id }}  
**Examinador:** {{ metadata.examiner }}  
**Fecha de Generación:** {{ metadata.generated_at | format_datetime }}

---

{% for section_name, section in sections.items() %}
## {{ section.title }}

{{ section.content }}

{% endfor %}

## Información del Caso

| Campo | Valor |
|-------|-------|
| ID del Caso | {{ case_info.case_id }} |
| Descripción | {{ case_info.description | default("N/A") }} |
| Examinador | {{ case_info.examiner | default("N/A") }} |
| Organización | {{ case_info.organization | default("N/A") }} |

{% if evidences %}
## Evidencias Analizadas

{% for evidence in evidences %}
### {{ evidence.evidence_id }}

- **Tipo:** {{ evidence.evidence_type }}
- **Descripción:** {{ evidence.description | default("N/A") }}
- **Tamaño:** {{ evidence.file_size | format_filesize }}

{% endfor %}
{% endif %}

---

*Este reporte fue generado automáticamente por ForenseCTL v{{ forensectl_version }}.*
'''
    
    def _get_technical_markdown_template_en(self) -> str:
        """Plantilla Markdown técnica en inglés."""
        return '''# {{ metadata.title }}

**Case:** {{ case_info.case_id }}  
**Examiner:** {{ metadata.examiner }}  
**Generation Date:** {{ metadata.generated_at | format_datetime }}

---

{% for section_name, section in sections.items() %}
## {{ section.title }}

{{ section.content }}

{% endfor %}

## Case Information

| Field | Value |
|-------|-------|
| Case ID | {{ case_info.case_id }} |
| Description | {{ case_info.description | default("N/A") }} |
| Examiner | {{ case_info.examiner | default("N/A") }} |
| Organization | {{ case_info.organization | default("N/A") }} |

{% if evidences %}
## Analyzed Evidence

{% for evidence in evidences %}
### {{ evidence.evidence_id }}

- **Type:** {{ evidence.evidence_type }}
- **Description:** {{ evidence.description | default("N/A") }}
- **Size:** {{ evidence.file_size | format_filesize }}

{% endfor %}
{% endif %}

---

*This report was automatically generated by ForenseCTL v{{ forensectl_version }}.*
'''