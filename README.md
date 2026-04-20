# scan-nuclei

Plantillas Nuclei enfocadas en auditoria de Java, Tomcat, WildFly/JBoss y Apache HTTPD.

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

## Workflows recomendados

Para objetivos WildFly/JBoss, separa el uso segun contexto para evitar ruido y duplicados:

- `templates/workflows/wildfly/wildfly-modern-admin-surface-workflow.yaml`
  - para WildFly moderno y superficie Undertow, management, health, metrics y hardening.
- `templates/workflows/wildfly/jboss-legacy-migration-debt-workflow.yaml`
  - para detectar deuda de migracion y superficies legacy de JBoss en nodos antiguos o mixtos.

Ejemplos:

```bash
# WildFly moderno
nuclei -w templates/workflows/wildfly/wildfly-modern-admin-surface-workflow.yaml -u https://objetivo

# JBoss legacy / migracion
nuclei -w templates/workflows/wildfly/jboss-legacy-migration-debt-workflow.yaml -u https://objetivo
```

## Cobertura WildFly moderna

La linea de `WildFly` moderno esta pensada principalmente para:

- superficie de administracion (`/management`, consola, Hawtio, Jolokia)
- endpoints operativos (`health`, `metrics`, `openapi`)
- hardening HTTP/servlet
- exposicion de ficheros de configuracion y metadata de despliegue
- lecturas no autenticadas del management model

Las plantillas `wildfly-*-management-unauth` indican un riesgo especialmente alto porque no solo detectan que existe la interfaz de gestion, sino que confirman lectura de informacion sensible sin autenticacion.

Triage rapido recomendado para estos hallazgos:

1. `wildfly-management-read-operations-unauth` y `wildfly-management-model-unauth`
2. `wildfly-datasources-management-unauth`, `wildfly-elytron-management-unauth`, `wildfly-mail-management-unauth`, `wildfly-mod-cluster-management-unauth`
3. `wildfly-management-endpoint-exposed`, `wildfly-console-exposed`, `wildfly-hawtio-console-exposed`
4. exposiciones de ficheros (`standalone.xml`, `domain.xml`, `host.xml`, `mgmt-users.properties`, `jboss-web.xml`, `persistence.xml`)
5. postura/hardening (`headers`, `cookies`, `CORS`, `verbose error disclosure`)

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
  - management reads de WildFly (`wildfly-*-management-unauth`) cuando varias plantillas devuelven la misma causa raiz de exposicion
- Priorizar para remediacion en este orden:
  1) `default-logins`, `misconfiguration` de admin panels
  2) `exposures` de secretos/configuracion
  3) `exposures/error-pages` con stacktraces (si revelan clases, rutas o datos internos)
  4) `cves/*-potential` (tras confirmacion manual)
  5) `technologies` y `posture` (`low/info`)

## Triage de stacktraces

- `stacktrace` con paquetes internos (`org.*`, `com.*`), clases de framework o line numbers:
  - priorizar como fuga de informacion util para encadenar ataques.
- `stacktrace` sin datos sensibles aparentes:
  - tratar como hallazgo de hardening y mejorar manejo de errores en produccion.
- Si aparece por input malformado (`?f=[`, comillas, expresiones):
  - revisar validacion/sanitizacion de parametros y respuestas de excepcion globales.

## Triage de cabeceras

- `low`:
  - cabeceras de hardening ausentes (postura), sin evidencia directa de explotacion.
- `medium`:
  - cabeceras presentes pero debiles (`unsafe-inline`, HSTS flojo, XFO/XCTO invalidos),
  - cookies de sesion sin flags recomendados.
- `high`:
  - combinaciones CORS peligrosas (`Allow-Credentials: true` + Origin reflejado arbitrario).
- En disclosure (`Server`, `X-Powered-By`, version headers), tratar como `info` para priorizacion de superficie.

## Baseline de calidad antes de commit

- Parse YAML correcto de todas las plantillas.
- Campos obligatorios presentes (`id`, `info`, `http/requests`, `matchers-condition`, `matchers`).
- Revisar solapamientos de paths para reducir hallazgos duplicados.
- En workflows WildFly, mantener separadas las familias `modern-admin-surface` y `legacy-migration-debt`.

Para detalle de clasificacion, ver `templates/README.md`.
