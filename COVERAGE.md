# Coverage Matrix

Este documento resume la cobertura actual del repositorio y el backlog
priorizado para seguir ampliando el set de plantillas sin crecer a ciegas.

## Cobertura actual

### Apache

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `apache-httpd-server-header`, default page, reverse proxy, server version, fronting `Tomcat` y `WildFly`. |
| Admin surface | Fuerte | `server-status`, `status?auto`, `status-json`, `server-info`, `balancer-manager`, `jk-status`, detalle de `request metadata` en `mod_status`, detalle de backends/rutas en `balancer-manager`, detalle de topologia en `mod_cluster` y detalle operativo de workers en `mod_jk`, todo ya cubierto tambien en regresion HTTP. |
| Proxy surface | Fuerte | `open-proxy`, `forward-proxy`, trust bypass por `X-Forwarded-*`, fronting `Tomcat`/`WildFly`, señal de routing `proxy_wstunnel`, correlacion backend/path via `mod_info` incluyendo `ProxyPass`, `ProxyPassMatch`, `ProxyPassReverse`, `RewriteRule` hacia backends internos y reglas WebSocket, CVEs `mod_proxy`. |
| Config leaks | Fuerte | `httpd.conf`, `apache2.conf`, `vhosts`, `ssl.conf`, backups, `.ht*`, alias/script mappings frecuentes, `workers.properties`, `uriworkermap.properties` y `proxy_ajp.conf`. |
| Hardening | Fuerte | missing headers, TRACE, unsafe methods, directory listing, redirect HTTP->HTTPS, HSTS, cookies de frontend, redirects inseguros, auth surface y disclosure de backend en `Location`. |
| CVE potential | Bueno | `CVE-2021-40438`, `CVE-2021-41773`, `CVE-2021-42013`, `CVE-2023-25690`. |
| Workflows | Fuerte | `misconfig`, `proxy-admin-surface`, `hardening`, `fronting-tomcat`, `fronting-wildfly`. |

### Tomcat

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `server header`, `catalina signatures`, default error, version hint, manager realm. |
| Admin surface | Fuerte | `manager`, `host-manager`, `jmxproxy`, `text/*`, `status`, default logins. |
| Config leaks | Fuerte | `server.xml`, `context.xml`, `tomcat-users.xml`, `web.xml`, `catalina.policy`, `logging.properties`, ROOT context, backups, variantes `Catalina/localhost/*.xml`, `GlobalNamingResources`, `WEB-INF/web.xml` y nombres de app no-default con residuos editor-temp comunes. |
| Defaults / sample apps | Fuerte | ROOT page, docs/examples, artifacts, deployed-artifact listing y residuos de archivos de despliegue para nombres de app tipicos y corporativos no-default. |
| Hardening | Bueno | hardening workflow, headers summary, TRACE, verbose errors, cookies, stacktrace. |
| CVE potential | Bueno | `CVE-2017-12617`, `CVE-2019-0232`, `CVE-2020-1938`, `CVE-2020-9484`. |
| Workflows | Fuerte | `version-priority`, `java-exposure`, `hardening`. |
| Ficheros conf | Fuerte | `catalina.properties`, `catalina.policy`, `server.xml`, `context.xml`, `tomcat-users.xml`, `web.xml` y variantes frecuentes de backup/editor-temp (`.bak`, `.old`, `.orig`, `.save`, `.tmp`, `~`, `.swp`). |

### Quarkus / Micronaut (señal Java)

| Familia | Estado | Notas |
| --- | --- | --- |
| Fingerprinting | Inicial | Quarkus: `quarkus-stack-fingerprint` ( `/q/health` + `io.quarkus` en checks). Micronaut: `micronaut-signal-fingerprint` (header `Server` con `micronaut`). |
| Riesgo encadenado | Inicial | `quarkus-dev-ui-surface-exposed`; Micronaut encadena `java-env-files-exposed` en el workflow. |
| Workflows | Nuevo | `workflows/java/java-modern-stacks-snapshot-workflow.yaml`. |

### WildFly / JBoss / Undertow

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `wildfly server header`, version hint, welcome page, management realm, `undertow` default/error/version. |
| Admin surface | Fuerte | `management`, console, Hawtio, Jolokia, legacy JBoss consoles/invokers. |
| Management unauth reads | Fuerte | root/model + `datasources`, `mail`, `elytron`, `elytron TLS`, `http/sasl-authentication-factory`, `mod_cluster`, `undertow https-listener`, `domain topology` y detalle de despliegues/overlays en `domain mode`. |
| Config leaks | Fuerte | `standalone.xml`, `domain.xml`, `host.xml`, `mgmt-users/groups`, `elytron` properties, `application-users/roles`, logging, `jboss-web.xml`, `jboss-app.xml`, `jboss-client.xml`, `jboss-deployment-structure.xml`, `ironjacamar.xml`, `persistence.xml`, `*-ds.xml`, `keystore/truststore` Java. |
| Defaults / sample apps | Bueno | welcome content, sample apps, health, metrics, OpenAPI. |
| Hardening | Fuerte | headers, cookies, CORS, verbose errors, stacktraces, TLS/SSL topology via Elytron y Undertow management reads, mas correlacion con `keystore/truststore` expuestos. |
| CVE potential | Medio-Bueno | Undertow/WildFly modernas + JBoss legacy. |
| Workflows | Fuerte | `wildfly-modern-admin-surface`, `jboss-legacy-migration-debt`, `apache-fronting-wildfly`. |

## Fortalezas del repo

- Buena separacion entre `technologies`, `misconfiguration`, `exposures`, `cves` y `workflows`.
- Workflows operativos para `Apache`, `Tomcat` y `WildFly`.
- Cobertura fuerte de superficie administrativa y ficheros sensibles.
- Buen uso de `*-potential` para separar riesgo potencial de evidencia confirmada.
- Documentacion y triage ya suficientemente claros para uso real.

## Huecos principales

### Apache

- correlacion aun mas fina de `mod_info` cuando el frontend usa reglas complejas, condiciones o layouts poco comunes fuera de `ProxyPass*`, `RewriteRule` y `BalancerMember`.
- TLS posture adicional:
  - redirects canonicos de host/scheme/port
  - politicas de cookies de frontend mas finas
  - disclosures de certificados o cadenas TLS si aparecen en respuestas o errores

### Tomcat

- variantes aun menos comunes de nombres de despliegue y editor-temp bajo `Catalina/localhost/` si aparecen en validacion real.
- JNDI/resource exposure mas fina:
  - referencias indirectas o menos comunes en descriptores por app y combinaciones de `context.xml.*` fuera de las familias ya cubiertas.

### WildFly

- lecturas de Elytron/TLS aun mas especificas si aparecen `trust-store`, `key-store`, `ssl-context` o factories con nombres no-default en entornos reales.
- correlacion mas fina entre `Undertow`, `Elytron` y artefactos TLS cuando la topologia use nombres o rutas no-estandar.

### Transversal

- Exposicion **GraphQL** (introspeccion sin autenticacion) en `exposures/apis/`.
- Matriz de validacion en entornos corporativos autorizados (staging, preproduccion o piloto) que cubra:
  - Apache solo
  - Apache fronting Tomcat
  - Apache fronting WildFly
  - Tomcat solo
  - WildFly solo
- Falsos positivos conocidos: [KNOWN-FP.md](KNOWN-FP.md) (hoja viva, ampliar con cada familia nueva).
- Criterios de deduplicacion mas formales por familia.

## Backlog priorizado

### Prioridad 1

1. Apache reverse-proxy Java profundo
   - cadenas frontend->backend mas finas
   - correlacion de paths/backend sobre `proxy_wstunnel`
   - trust/disclosure adicional en despliegues complejos

2. Apache TLS / frontend posture adicional
   - redirects canonicos
   - cookies de frontend mas finas
   - disclosures TLS en errores o respuestas

3. Tomcat coverage residual
   - variantes menos comunes de despliegue/config no-default
   - validacion real de nombres adicionales antes de seguir ampliando volumen

4. WildFly correlation residual
   - layouts no-default de Elytron/TLS
   - mas detalle solo si aparece necesidad real en validacion autorizada

### Prioridad 2

1. Apache mod_status profundo
   - diferenciar `ExtendedStatus` con `Client` / `VHost` / `Request`
   - extraer mejor request metadata y contexto operativo sin duplicar el panel base

2. Apache balancer/mod_cluster profundo
   - extraer mejor miembros, rutas, estados y topologia desde `balancer-manager` y `mod_cluster`
   - evitar contar panel y detalle operativo como dos hallazgos separados

3. Apache mod_jk profundo
   - extraer workers, `route`, `host`, `port` y endpoints AJP desde `jk-status`
   - evitar contar panel y detalle operativo como dos hallazgos separados

### Prioridad 3

1. Validacion reproducible en entornos reales autorizados (sin depender de contenedores locales)
2. Falsos positivos conocidos
3. Tabla de deduplicacion por familia

## Pilar de implementacion actual

**Elegido:** el bloque inicial de Prioridad 1 ya esta mayoritariamente cerrado en **Tomcat** (artefactos/descriptores), **WildFly** (`domain mode`, `Elytron/TLS`, `Undertow HTTPS listener`) y **Apache** (`mod_info`, `mod_status`, `balancer/mod_cluster/mod_jk`, `workers.properties`, `uriworkermap.properties`, `proxy_ajp.conf`).

**Rationale:** El repo ya no esta en fase de "abrir lineas grandes", sino en fase de consolidar lo abierto y mover el backlog hacia validacion real, triage y refinamiento de ruido.

## Recomendacion operativa

Antes de seguir añadiendo volumen, usar el backlog con este orden:

1. Añadir una subfamilia concreta
2. Validarla en un objetivo o entorno corporativo real autorizado
3. Ajustar ruido
4. Documentar triage
5. Repetir

Esto mantiene el repo util para auditoria real y evita crecer con plantillas
que luego generan mas ruido que señal.
