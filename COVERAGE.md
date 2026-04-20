# Coverage Matrix

Este documento resume la cobertura actual del repositorio y el backlog
priorizado para seguir ampliando el set de plantillas sin crecer a ciegas.

## Cobertura actual

### Apache

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `apache-httpd-server-header`, default page, reverse proxy, server version, fronting `Tomcat` y `WildFly`. |
| Admin surface | Fuerte | `server-status`, `status?auto`, `status-json`, `server-info`, `balancer-manager`, `jk-status`. |
| Proxy surface | Fuerte | `open-proxy`, `forward-proxy`, trust bypass por `X-Forwarded-*`, fronting `Tomcat`/`WildFly`, CVEs `mod_proxy`. |
| Config leaks | Fuerte | `httpd.conf`, `apache2.conf`, `vhosts`, `ssl.conf`, backups, `.ht*`, alias/script mappings frecuentes. |
| Hardening | Fuerte | missing headers, TRACE, unsafe methods, directory listing, redirect HTTP->HTTPS, HSTS, cookies de frontend, redirects inseguros, auth surface y disclosure de backend en `Location`. |
| CVE potential | Bueno | `CVE-2021-40438`, `CVE-2021-41773`, `CVE-2021-42013`, `CVE-2023-25690`. |
| Workflows | Fuerte | `misconfig`, `proxy-admin-surface`, `hardening`, `fronting-tomcat`, `fronting-wildfly`. |

### Tomcat

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `server header`, `catalina signatures`, default error, version hint, manager realm. |
| Admin surface | Fuerte | `manager`, `host-manager`, `jmxproxy`, `text/*`, `status`, default logins. |
| Config leaks | Fuerte | `server.xml`, `context.xml`, `tomcat-users.xml`, `web.xml`, `catalina.policy`, `logging.properties`, ROOT context, backups. |
| Defaults / sample apps | Fuerte | ROOT page, docs/examples, artifacts, deployed-artifact listing. |
| Hardening | Bueno | hardening workflow, headers summary, TRACE, verbose errors, cookies, stacktrace. |
| CVE potential | Bueno | `CVE-2017-12617`, `CVE-2019-0232`, `CVE-2020-1938`, `CVE-2020-9484`. |
| Workflows | Fuerte | `version-priority`, `java-exposure`, `hardening`. |

### WildFly / JBoss / Undertow

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `wildfly server header`, version hint, welcome page, management realm, `undertow` default/error/version. |
| Admin surface | Fuerte | `management`, console, Hawtio, Jolokia, legacy JBoss consoles/invokers. |
| Management unauth reads | Fuerte | root/model + `datasources`, `mail`, `elytron`, `elytron TLS`, `mod_cluster`, `undertow https-listener`. |
| Config leaks | Fuerte | `standalone.xml`, `domain.xml`, `host.xml`, `mgmt-users/groups`, `elytron` properties, logging, `jboss-web.xml`, `jboss-app.xml`, `jboss-client.xml`, `jboss-deployment-structure.xml`, `ironjacamar.xml`, `persistence.xml`, `*-ds.xml`. |
| Defaults / sample apps | Bueno | welcome content, sample apps, health, metrics, OpenAPI. |
| Hardening | Fuerte | headers, cookies, CORS, verbose errors, stacktraces, TLS/SSL topology via Elytron y Undertow management reads. |
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

- `mod_cluster` / `proxy_ajp` / `proxy_wstunnel` / `mod_status` mas finos cuando el frontend encadena backends Java complejos.
- `proxy_wstunnel` y cadenas WebSocket backend mas finas.
- TLS posture adicional:
  - redirects canonicos de host/scheme/port
  - politicas de cookies de frontend mas finas
  - disclosures de certificados o cadenas TLS si aparecen en respuestas o errores

### Tomcat

- Descriptores y configs legacy adicionales:
  - `catalina.policy` ya existe, pero faltan `catalina.properties` backups y algunas variantes de `Catalina/localhost/*.xml` menos comunes.
- Artefactos de despliegue:
  - WAR/JAR/backups concretos fuera de directory listing.
- JNDI/resource exposure mas fina:
  - referencias indirectas o menos comunes en descriptores por app y combinaciones de `context.xml.*`.

### WildFly

- TLS / Elytron mas fino:
  - ficheros referenciados de keystore/truststore y rutas concretas desde descriptores o propiedades
  - surface de realms/factories mas detallada por tipo de auth factory
- Domain mode / host-controller:
  - lecturas y artefactos mas especificos de topologia y despliegue distribuido.

### Transversal

- Suite reproducible de laboratorio para validar:
  - Apache limpio
  - Apache fronting Tomcat
  - Apache fronting WildFly
  - Tomcat limpio
  - WildFly limpio
- Catalogo de falsos positivos conocidos por plantilla.
- Criterios de deduplicacion mas formales por familia.

## Backlog priorizado

### Prioridad 1

1. Tomcat deploy artifacts concretos
   - WAR/JAR/backup files sin depender solo de directory listing
   - `Catalina/localhost/*.xml` adicionales menos comunes
   - variantes legacy y copias editor-temp de despliegues

2. WildFly domain mode / host-controller profundo
   - lecturas y artefactos mas especificos de topologia distribuida
   - hosts, server-groups y deployment overlays

3. Apache reverse-proxy Java profundo
   - `proxy_wstunnel`
   - cadenas frontend->backend mas finas
   - trust/disclosure adicional en despliegues complejos

### Prioridad 2

1. WildFly TLS / Elytron hardening profundo
   - referencias a keystore/truststore
   - auth factories y realms mas finos
   - topologia TLS de Undertow mas detallada

2. Apache TLS / frontend posture adicional
3. Tomcat JNDI / resource descriptor coverage adicional

### Prioridad 3

1. Laboratorio reproducible
2. Falsos positivos conocidos
3. Tabla de deduplicacion por familia

## Recomendacion operativa

Antes de seguir añadiendo volumen, usar el backlog con este orden:

1. Añadir una subfamilia concreta
2. Validarla en un objetivo o laboratorio real
3. Ajustar ruido
4. Documentar triage
5. Repetir

Esto mantiene el repo util para auditoria real y evita crecer con plantillas
que luego generan mas ruido que señal.
