# {{ metadata.title }}

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
