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

# chequeo estructural del repo (ids, severities, referencias internas)
scripts/check-repo.sh

# regresion minima con fixtures HTTP locales
python3 scripts/run-http-regression.py

# ejecutar contra un objetivo
nuclei -t templates/ -u https://objetivo
```

Para detalles de testing y regresion minima, ver [TESTING.md](TESTING.md).

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

# salida agregada (1 hallazgo por template+host, con paths consolidados)
scripts/check-nuclei.sh --target https://objetivo --aggregate-output

# validar + scan + actualizar templates
scripts/check-nuclei.sh --target https://objetivo --update-templates

# actualizar nuclei + templates y luego validar + scan
scripts/check-nuclei.sh --target https://objetivo --update-nuclei --update-templates
```

### Salida agregada (menos ruido)

Cuando varias rutas de la misma plantilla hacen match (por ejemplo WADL en
`/rest/application.wadl`, `?detail=true` y `xsd0.xsd`), `nuclei` las imprime por
separado. Para agruparlas en una sola entrada por `host + template`, usa:

```bash
scripts/check-nuclei.sh --target https://objetivo --aggregate-output
```

Tradeoff:

- salida normal: detalle raw por cada request/path coincidente;
- salida agregada: una linea por plantilla/host y lista de paths evidenciados.

## Workflows recomendados

## Que workflow usar segun escenario

Guia rapida para no tener que elegir a ciegas:

| Escenario | Workflow recomendado | Objetivo principal | Ruido esperado |
| --- | --- | --- | --- |
| Apache solo | `templates/workflows/apache/apache-misconfig-from-fingerprint-workflow.yaml` | misconfiguracion general, `server-status`, `server-info`, listados y config expuesta | medio |
| Apache solo (posture review) | `templates/workflows/apache/apache-hardening-workflow.yaml` | headers, cookies, TRACE, metodos inseguros y postura de frontend | bajo-medio |
| Apache con foco proxy/admin | `templates/workflows/apache/apache-proxy-admin-surface-workflow.yaml` | `balancer-manager`, `mod_cluster`, `jk-status`, `workers.properties`, `uriworkermap.properties`, `proxy_ajp.conf`, `server-status`/`server-info` y CVEs `potential` de proxy | medio-alto |
| Apache fronting Tomcat | `templates/workflows/apache/apache-fronting-tomcat-workflow.yaml` | correlacion frontend Apache con superficie y señales tipicas de Tomcat | medio |
| Apache fronting WildFly | `templates/workflows/apache/apache-fronting-wildfly-workflow.yaml` | correlacion frontend Apache con superficie y señales tipicas de WildFly/Undertow | medio |
| Tomcat solo | `templates/workflows/tomcat/tomcat-version-priority-workflow.yaml` | manager/admin surface, defaults, archivos sensibles y CVEs `potential` | medio-alto |
| Tomcat solo (hardening) | `templates/workflows/tomcat/tomcat-hardening-workflow.yaml` | hardening HTTP, cookies, TRACE, verbose errors y postura | bajo-medio |
| Tomcat con apps Java | `templates/workflows/tomcat/tomcat-fingerprint-to-java-exposure-workflow.yaml` | exposiciones Java tipicas desplegadas sobre Tomcat | medio |
| WildFly moderno | `templates/workflows/wildfly/wildfly-modern-admin-surface-workflow.yaml` | management, consola, Hawtio, Jolokia, health/metrics, `domain mode`, Elytron/TLS y config sensible | medio-alto |
| JBoss legacy / migracion | `templates/workflows/wildfly/jboss-legacy-migration-debt-workflow.yaml` | deuda de migracion, superficies legacy y artefactos historicos | medio |
| Spring sobre stack Java | `templates/workflows/spring/spring-fingerprint-to-risk-workflow.yaml` | actuators, perfiles, docs y superficie web Spring | medio |
| Quarkus / Micronaut | `templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml` | snapshot acotado de superficie moderna Java | bajo-medio |

Regla practica:

- si buscas **amplitud con coste razonable**, empieza por el workflow del escenario
- si buscas **posture review**, usa los workflows de `hardening`
- si buscas **superficie admin/proxy**, usa los workflows mas profundos aunque metan mas ruido
- si el objetivo responde por multiples stacks o frontends, usa `--aggregate-output` para reducir duplicados

Ejemplos rapidos:

```bash
# Apache solo
scripts/check-nuclei.sh --target https://objetivo -w templates/workflows/apache/apache-misconfig-from-fingerprint-workflow.yaml --aggregate-output

# Apache fronting Tomcat
scripts/check-nuclei.sh --target https://objetivo -w templates/workflows/apache/apache-fronting-tomcat-workflow.yaml --aggregate-output

# Tomcat solo
scripts/check-nuclei.sh --target https://objetivo -w templates/workflows/tomcat/tomcat-version-priority-workflow.yaml --aggregate-output

# WildFly moderno
scripts/check-nuclei.sh --target https://objetivo -w templates/workflows/wildfly/wildfly-modern-admin-surface-workflow.yaml --aggregate-output
```

Para objetivos WildFly/JBoss, separa el uso segun contexto para evitar ruido y duplicados:

- `templates/workflows/wildfly/wildfly-modern-admin-surface-workflow.yaml`
  - para WildFly moderno y superficie Undertow, management, health, metrics, `domain mode`, Elytron/TLS, listeners HTTPS y correlacion con `application-users/roles` y `keystore/truststore`.
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
  - para superficie admin, archivos sensibles, defaults, descriptores `Catalina/localhost/`, recursos `JNDI`, `GlobalNamingResources`, `server.xml`, `tomcat-users.xml`, `web.xml` y CVEs `potential`.
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

Triage practico para Tomcat:

- contar `manager/html`, `help`, `text`, `status` y `host-manager` como una
  misma superficie admin cuando dependen del mismo conector
- agrupar `context.xml`, `ROOT.xml`, `Catalina/localhost/*.xml`,
  `JNDI/resources`, `GlobalNamingResources` y backups relacionados como una
  misma familia de fuga de configuracion, destacando aparte solo la evidencia
  mas sensible
- agrupar `WAR/JAR` y residuos `.bak/.old/.orig/.save/.tmp/~/.swp` por
  aplicacion o raiz de despliegue, no como findings independientes por fichero

Para objetivos Apache, separa el uso segun el tipo de revision:

- `templates/workflows/apache/apache-misconfig-from-fingerprint-workflow.yaml`
  - para misconfiguracion general, `server-status`, `server-info`, listados, `.ht*` y configuracion expuesta.
- `templates/workflows/apache/apache-proxy-admin-surface-workflow.yaml`
  - para proxy/admin surface, `balancer-manager`, `mod_cluster`, `jk-status`, `workers.properties`, `uriworkermap.properties`, `proxy_ajp.conf`, `server-status?auto`, `status-json`, AJP config leaks, forward/open proxy, correlacion `mod_info` (`ProxyPass`, `ProxyPassMatch`, `RewriteRule [P]`, `ws://` / `wss://`) y CVEs `potential` de proxy.
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

## Workflow Java (diagnostics generic)

Para aplicaciones Java servlet-based donde aun no sabes si detras hay Spring,
Tomcat customizado u otra app Java clasica, hay un workflow corto centrado en
diagnostics y configuracion expuesta:

- `templates/workflows/java/java-diagnostics-exposure-workflow.yaml`

Encadena fingerprints genericos (`JSESSIONID`, firmas servlet en errores) con
checks reutilizables de:

- `env`
- `logfile`
- `threaddump`
- `heapdump`
- `loggers`
- `scheduledtasks`

Ejemplo:

```bash
nuclei -w templates/workflows/java/java-diagnostics-exposure-workflow.yaml -u https://objetivo
```

Para stacks reactivos o ligeros con señales distintas a Spring Boot, el workflow encadena fingerprint **Quarkus** (`/q/health` con check `io.quarkus`) y **Micronaut** (cabecera `Server: ...micronaut...`) con comprobaciones de riesgo acotadas (Dev UI Quarkus, fugas de env para Micronaut).

- `templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml`

Ejemplo:

```bash
nuclei -w templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml -u https://objetivo
# o con el script: scripts/check-nuclei.sh --target https://objetivo -w templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml
```

Notas de interpretacion:

- `Quarkus`:
  - el fingerprint actual busca `/q/health` y exige señal `io.quarkus` en el cuerpo para reducir ruido frente a otros runtimes con `MicroProfile Health`
  - si `/q/health` esta deshabilitado, protegido, remapeado o filtrado por proxy/WAF, la ausencia de match no descarta `Quarkus`
  - `quarkus-openapi-surface-exposed` y `quarkus-metrics-endpoint-exposed` deben leerse como exposicion operativa/documental, no como confirmacion de una vulnerabilidad explotable por si sola
- `Micronaut`:
  - el fingerprint actual depende de `Server: ...micronaut...` y es deliberadamente conservador

## Cobertura actual de regresion

La regresion HTTP local cubre ya no solo validacion basica de templates, sino tambien profundidad de workflows y familias con mas riesgo de ruido:

- `Apache`: `mod_status`, `server-info`, `balancer-manager`, `mod_cluster`, `jk-status`, `workers.properties`, `uriworkermap.properties`, `proxy_ajp.conf` y disclosure de backends/routing.
- `Tomcat`: superficie manager/host-manager, `Catalina/localhost/*.xml`, `JNDI/resources`, `GlobalNamingResources`, `server.xml`, `tomcat-users.xml`, `web.xml` y artefactos temporales/backups.
- `WildFly`: `domain mode`, Elytron, TLS, Undertow HTTPS listeners, `application-users/roles` y correlacion con `keystore/truststore`.

Para el detalle exacto de la suite y como ampliar fixtures, ver [TESTING.md](TESTING.md).
  - en produccion es comun que Apache, Nginx, balanceadores o gateways sobrescriban el header `Server`, por lo que la ausencia de match no descarta `Micronaut`
  - los checks de `env`, `management`, `loggers` y `refresh` describen superficie expuesta o potencialmente escribible; requieren correlacion con contexto operativo antes de priorizar como riesgo alto

Estado recomendado de esta familia:

- tratarla como **inicial pero fiable**
- usarla como snapshot acotado de superficie moderna Java
- ampliar cobertura solo tras validar ruido en objetivos reales autorizados

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

La guia operativa completa de triage y deduplicacion esta en [TRIAGE.md](TRIAGE.md).

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
- El chequeo estructural `scripts/check-repo.sh` revisa ids duplicados, severidades, convenciones de nombre y referencias internas de workflows/templates.
- La regresion minima `python3 scripts/run-http-regression.py` ejecuta escenarios locales controlados para `Quarkus`, `Micronaut`, `Apache`, `Tomcat`, `WildFly` y `Spring`, y muestra resumen por familia al final.
- CI en push y PR hacia `main`/`master`.
- Parse YAML correcto de todas las plantillas.
- Campos obligatorios presentes (`id`, `info`, `http/requests`, `matchers-condition`, `matchers`).
- Revisar solapamientos de paths para reducir hallazgos duplicados.
- En workflows WildFly, mantener separadas las familias `modern-admin-surface` y `legacy-migration-debt`.
- En workflows Tomcat, separar `version-priority`, `java-exposure` y `hardening` segun el objetivo del scan.
- En workflows Apache, separar `misconfig`, `proxy-admin-surface` y `hardening` segun el objetivo del scan.

Para detalle de clasificacion, ver `templates/README.md`. Falsos positivos frecuentes: `KNOWN-FP.md`.
