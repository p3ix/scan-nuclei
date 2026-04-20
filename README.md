# scan-nuclei

Plantillas Nuclei enfocadas en auditoria de Java, Tomcat y Apache HTTPD.

## Estructura

El arbol principal vive en `templates/` y separa los hallazgos por tipo:

- `cves/`
- `vulnerabilities/`
- `misconfiguration/`
- `exposures/`
- `technologies/`
- `default-logins/`
- `workflows/`

## Criterio de severidad para exposures

- `high`: fugas con datos sensibles o de configuracion explotable.
- `medium`: consolas o metadata operativa que amplian superficie de ataque.
- `info`: descubrimiento o documentacion expuesta sin impacto directo.

## Quick Start

```bash
# validar sintaxis de templates
nuclei -validate -t templates/

# ejecutar contra un objetivo
nuclei -t templates/ -u https://objetivo
```

## Convencion de nombres

- CVEs: `CVE-YYYY-NNNNN-<producto>-<slug-corto>.yaml`
- Resto: `<producto>-<hallazgo>-<contexto>.yaml`

## Interpretacion de resultados

- `info`: fingerprinting o evidencia de superficie (requiere correlacion con otros hallazgos).
- `low`: hardening/posture mejorable sin evidencia directa de explotacion.
- `medium`: exposicion o misconfiguracion con impacto operativo claro.
- `high`/`critical`: riesgo explotable alto (credenciales, admin surface, leaks sensibles).

## Convencion `-exposed` vs `-potential`

- `*-exposed.yaml`: confirma exposicion observable (endpoint, archivo, consola, metadata).
- `*-potential.yaml`: indica **riesgo potencial** por superficie/version; requiere validacion manual adicional antes de concluir vulnerabilidad.

## Triage recomendado (evitar duplicados)

- Contar una sola vez por tipo de evidencia:
  - OpenAPI/WADL docs (`docs.json`, `v2/v3/api-docs`, `application.wadl`)
  - Swagger assets/source maps (`swagger-ui*.js`, `*.map`)
  - Fingerprints de tecnologia (`technologies/*`)
- Priorizar para remediacion en este orden:
  1) `default-logins`, `misconfiguration` de admin panels
  2) `exposures` de secretos/configuracion
  3) `cves/*-potential` (tras confirmacion manual)
  4) `technologies` y `posture` (`low/info`)

## Baseline de calidad antes de commit

- Parse YAML correcto de todas las plantillas.
- Campos obligatorios presentes (`id`, `info`, `http/requests`, `matchers-condition`, `matchers`).
- Revisar solapamientos de paths para reducir hallazgos duplicados.

Para detalle de clasificacion, ver `templates/README.md`.
