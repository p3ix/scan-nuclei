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

## Flujo recomendado en un comando

Hay un script para dejar un chequeo repetible (version, update opcional, validacion y scan):

```bash
# dar permisos de ejecucion (solo la primera vez)
chmod +x scripts/check-nuclei.sh

# validar + scan rapido
scripts/check-nuclei.sh --target https://objetivo

# un solo workflow, limite de tasa, o argumentos extra a nuclei (despues de --)
scripts/check-nuclei.sh --target https://objetivo -w templates/workflows/apache/apache-hardening-workflow.yaml
scripts/check-nuclei.sh --target https://objetivo --rate-limit 5
scripts/check-nuclei.sh --target https://objetivo -- -c 10 -timeout 15s

# validar + scan + actualizar templates
scripts/check-nuclei.sh --target https://objetivo --update-templates

# actualizar nuclei + templates y luego validar + scan
scripts/check-nuclei.sh --target https://objetivo --update-nuclei --update-templates
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

Para objetivos Tomcat, separa el uso segun el tipo de revision:

- `templates/workflows/tomcat/tomcat-version-priority-workflow.yaml`
  - para superficie admin, archivos sensibles, defaults y CVEs `potential`.
- `templates/workflows/tomcat/tomcat-fingerprint-to-java-exposure-workflow.yaml`
  - para exposiciones Java tipicas desplegadas sobre Tomcat.
- `templates/workflows/tomcat/tomcat-hardening-workflow.yaml`
  - para revisar hardening, headers, cookies, TRACE, errores verbosos y surface admin.

Ejemplos:

```bash
# Tomcat admin surface + ficheros sensibles + CVEs potenciales
nuclei -w templates/workflows/tomcat/tomcat-version-priority-workflow.yaml -u https://objetivo

# Tomcat + exposiciones Java
nuclei -w templates/workflows/tomcat/tomcat-fingerprint-to-java-exposure-workflow.yaml -u https://objetivo

# Tomcat hardening
nuclei -w templates/workflows/tomcat/tomcat-hardening-workflow.yaml -u https://objetivo
```

Para objetivos Apache, separa el uso segun el tipo de revision:

- `templates/workflows/apache/apache-misconfig-from-fingerprint-workflow.yaml`
  - para misconfiguracion general, `server-status`, `server-info`, listados, `.ht*` y configuracion expuesta.
- `templates/workflows/apache/apache-proxy-admin-surface-workflow.yaml`
  - para proxy/admin surface, `balancer-manager`, `mod_cluster`, `jk-status`, `workers.properties`, `uriworkermap.properties`, AJP config leaks, forward/open proxy y CVEs `potential` de proxy.
- `templates/workflows/apache/apache-hardening-workflow.yaml`
  - para posture review de Apache, headers, metodos inseguros, directory listing y configuracion expuesta.
- `templates/workflows/apache/apache-fronting-tomcat-workflow.yaml`
  - para Apache actuando como frontend de Tomcat.
- `templates/workflows/apache/apache-fronting-wildfly-workflow.yaml`
  - para Apache actuando como frontend de WildFly/Undertow.

Ejemplos:

```bash
# Apache misconfiguration general
nuclei -w templates/workflows/apache/apache-misconfig-from-fingerprint-workflow.yaml -u https://objetivo

# Apache proxy/admin surface
nuclei -w templates/workflows/apache/apache-proxy-admin-surface-workflow.yaml -u https://objetivo

# Apache hardening
nuclei -w templates/workflows/apache/apache-hardening-workflow.yaml -u https://objetivo

# Apache fronting Tomcat
nuclei -w templates/workflows/apache/apache-fronting-tomcat-workflow.yaml -u https://objetivo

# Apache fronting WildFly
nuclei -w templates/workflows/apache/apache-fronting-wildfly-workflow.yaml -u https://objetivo
```

## Workflow Spring (apps Java)

Para aplicaciones Spring sobre servlet containers o stacks Java genericos, el workflow encadena fingerprint Spring con riesgos tipicos (perfiles, actuators, superficie web):

- `templates/workflows/spring/spring-fingerprint-to-risk-workflow.yaml`

Ejemplo:

```bash
nuclei -w templates/workflows/spring/spring-fingerprint-to-risk-workflow.yaml -u https://objetivo
```

## Workflow Java (Quarkus / Micronaut)

Para stacks reactivos o ligeros con señales distintas a Spring Boot, el workflow encadena fingerprint **Quarkus** (`/q/health` con check `io.quarkus`) y **Micronaut** (cabecera `Server: ...micronaut...`) con comprobaciones de riesgo acotadas (Dev UI Quarkus, fugas de env para Micronaut).

- `templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml`

Ejemplo:

```bash
nuclei -w templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml -u https://objetivo
# o con el script: scripts/check-nuclei.sh --target https://objetivo -w templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml
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
  - manager/help/text/status de Tomcat cuando varias rutas describen la misma superficie administrativa
  - `server-status`/`server-info`/`status-json` de Apache cuando describen la misma superficie de administracion
  - `apache-server-status-request-metadata-exposed` como detalle mas sensible de `mod_status` cuando hay `Client`, `VHost` y `Request`; si sale junto a `server-status`, contarlo como profundidad adicional de la misma exposicion
  - `apache-balancer-manager-backend-details-exposed` como detalle operativo de `balancer-manager` cuando revela miembros, rutas o backends; si sale junto a `apache-balancer-manager-exposed`, contarlo como profundidad adicional del mismo panel
  - `apache-mod-cluster-manager-backend-details-exposed` como detalle operativo de `mod_cluster` cuando revela nodos, `LBGroup`, `Balancer`, `JVMRoute` o `Contexts`; si sale junto a `apache-mod-cluster-manager-exposed`, contarlo como profundidad adicional del mismo panel
  - `apache-jk-status-backend-details-exposed` como detalle operativo de `mod_jk` cuando revela workers, `route`, `host`, `port` o endpoints AJP; si sale junto a `apache-jk-status-exposed`, contarlo como profundidad adicional del mismo panel
  - señal `proxy_wstunnel` en `apache-proxy-wstunnel-module-signal-potential` como contexto de modulo cuando ya cuentas `server-info` como exposicion de `mod_info`
  - `apache-proxy-wstunnel-routing-signal-exposed` como evidencia mas accionable de reglas o routing WebSocket; si sale junto a `server-info`, contarlo como detalle de la misma exposicion de `mod_info`, no como panel distinto
  - `apache-proxy-backend-routing-disclosure-exposed` como correlacion concreta de `frontend path`, esquema y backend interno (`localhost`, RFC1918 o dominios internos); si sale junto a `server-info`, contarlo como detalle de la misma exposicion de `mod_info`
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

## Licencia

[MIT](LICENSE) (repositorio de plantillas comunitario).

## Baseline de calidad antes de commit

- La validacion `nuclei -validate -t templates/` corre en CI (`.github/workflows/nuclei-validate.yml`) con una **version fija de Nuclei** (reproducible); se recomienda revisar la actualizacion al menos **trimestral** o al necesitar nuevas capacidades de motor.
- CI en push y PR hacia `main`/`master`.
- Parse YAML correcto de todas las plantillas.
- Campos obligatorios presentes (`id`, `info`, `http/requests`, `matchers-condition`, `matchers`).
- Revisar solapamientos de paths para reducir hallazgos duplicados.
- En workflows WildFly, mantener separadas las familias `modern-admin-surface` y `legacy-migration-debt`.
- En workflows Tomcat, separar `version-priority`, `java-exposure` y `hardening` segun el objetivo del scan.
- En workflows Apache, separar `misconfig`, `proxy-admin-surface` y `hardening` segun el objetivo del scan.

Para detalle de clasificacion, ver `templates/README.md`. Falsos positivos frecuentes: `KNOWN-FP.md`.
