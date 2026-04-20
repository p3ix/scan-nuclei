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

Para detalle de clasificacion, ver `templates/README.md`.
