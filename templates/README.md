# Templates internals

Este README documenta el arbol interno de `templates/`.
La documentacion principal para GitHub esta en el `README.md` de la raiz.

## Uso rapido

```bash
nuclei -validate -t templates/
nuclei -t templates/ -u https://objetivo
```

## Clasificacion

- `cves/`: detecciones ligadas a CVEs concretos.
- `vulnerabilities/`: fallos sin CVE unico.
- `misconfiguration/`: configuraciones inseguras.
- `exposures/`: endpoints o archivos sensibles expuestos.
- `technologies/`: fingerprinting (`severity: info`).
- `default-logins/`: credenciales por defecto.
- `workflows/`: encadenado de templates.

## Nota de nomenclatura

- `*-exposed`: evidencia confirmada de exposicion.
- `*-potential`: superficie/version compatible que requiere validacion manual.

## Nota de triage rapido

- Evitar doble conteo entre templates de docs (`openapi/wadl`) y templates de assets (`swagger-ui/*.map`).
- Tratar `technologies/*` como contexto de priorizacion, no como finding explotable por si solo.
- Para stacktraces:
  - si hay paquetes/clases internas y lineas de codigo, priorizar remediacion;
  - si solo hay error generico, tratar como hardening de manejo de errores.
- Para cabeceras:
  - `misconfiguration/*headers*`: postura/hardening (`low`).
  - `vulnerabilities/*headers*` y `cors-*`: riesgo de impacto en navegador/API (`medium`/`high`).
  - `technologies/*disclosure*`: contexto de reconocimiento (`info`).

Las carpetas vacias mantienen `.gitkeep`.
