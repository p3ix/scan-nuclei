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
- En WildFly, agrupar `wildfly-*-management-unauth` como evidencia de una misma causa raiz cuando el problema sea lectura no autenticada del management model.
- Para stacktraces:
  - si hay paquetes/clases internas y lineas de codigo, priorizar remediacion;
  - si solo hay error generico, tratar como hardening de manejo de errores.
- Para cabeceras:
  - `misconfiguration/*headers*`: postura/hardening (`low`).
  - `vulnerabilities/*headers*` y `cors-*`: riesgo de impacto en navegador/API (`medium`/`high`).
  - `technologies/*disclosure*`: contexto de reconocimiento (`info`).

## Nota de workflows WildFly

- `workflows/wildfly/wildfly-modern-admin-surface-workflow.yaml`:
  - orientado a WildFly reciente, Undertow, management API, health/metrics y configuracion expuesta.
- `workflows/wildfly/jboss-legacy-migration-debt-workflow.yaml`:
  - orientado a deuda de migracion y superficies legacy de JBoss.

## Nota de workflows Tomcat

- `workflows/tomcat/tomcat-version-priority-workflow.yaml`:
  - orientado a superficie admin, defaults, archivos sensibles y CVEs `potential`.
- `workflows/tomcat/tomcat-fingerprint-to-java-exposure-workflow.yaml`:
  - orientado a exposiciones Java tipicas sobre aplicaciones servidas por Tomcat.
- `workflows/tomcat/tomcat-hardening-workflow.yaml`:
  - orientado a posture review, headers, cookies, TRACE, errores verbosos y surface admin.

## Nota de workflows Apache

- `workflows/apache/apache-misconfig-from-fingerprint-workflow.yaml`:
  - orientado a misconfiguracion general y exposicion de configuracion/modulos.
- `workflows/apache/apache-proxy-admin-surface-workflow.yaml`:
  - orientado a proxy/admin surface y CVEs `potential` asociados a proxy.
- `workflows/apache/apache-hardening-workflow.yaml`:
  - orientado a posture review, headers, metodos inseguros, listing y configuracion expuesta.

Las carpetas vacias mantienen `.gitkeep`.
