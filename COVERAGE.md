# Coverage Matrix

Este documento resume la cobertura actual del repositorio y el backlog
priorizado para seguir ampliando el set de plantillas sin crecer a ciegas.

## Cobertura actual

### Apache

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `apache-httpd-server-header`, default page, reverse proxy, server version, fronting `Tomcat` y `WildFly`. |
| Admin surface | Fuerte | `server-status`, `status?auto`, `status-json`, `server-info`, `balancer-manager`, `jk-status`, detalle de `request metadata` en `mod_status`, detalle de backends/rutas en `balancer-manager`, detalle de topologia en `mod_cluster` y detalle operativo de workers en `mod_jk`. |
| Proxy surface | Fuerte | `open-proxy`, `forward-proxy`, trust bypass por `X-Forwarded-*`, fronting `Tomcat`/`WildFly`, señal de routing `proxy_wstunnel`, correlacion backend/path via `mod_info`, CVEs `mod_proxy`. |
| Config leaks | Fuerte | `httpd.conf`, `apache2.conf`, `vhosts`, `ssl.conf`, backups, `.ht*`, alias/script mappings frecuentes. |
| Hardening | Fuerte | missing headers, TRACE, unsafe methods, directory listing, redirect HTTP->HTTPS, HSTS, cookies de frontend, redirects inseguros, auth surface y disclosure de backend en `Location`. |
| CVE potential | Bueno | `CVE-2021-40438`, `CVE-2021-41773`, `CVE-2021-42013`, `CVE-2023-25690`. |
| Workflows | Fuerte | `misconfig`, `proxy-admin-surface`, `hardening`, `fronting-tomcat`, `fronting-wildfly`. |

### Tomcat

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `server header`, `catalina signatures`, default error, version hint, manager realm. |
| Admin surface | Fuerte | `manager`, `host-manager`, `jmxproxy`, `text/*`, `status`, default logins. |
| Config leaks | Fuerte | `server.xml`, `context.xml`, `tomcat-users.xml`, `web.xml`, `catalina.policy`, `logging.properties`, ROOT context, backups, y variantes `Catalina/localhost/*.xml`. |
| Defaults / sample apps | Fuerte | ROOT page, docs/examples, artifacts, deployed-artifact listing. |
| Hardening | Bueno | hardening workflow, headers summary, TRACE, verbose errors, cookies, stacktrace. |
| CVE potential | Bueno | `CVE-2017-12617`, `CVE-2019-0232`, `CVE-2020-1938`, `CVE-2020-9484`. |
| Workflows | Fuerte | `version-priority`, `java-exposure`, `hardening`. |
| Ficheros conf | Complemento | `catalina.properties` y variantes de copia/backup frecuentes (`.bak`, `~`, `.old`, `.save`) en `sensitive-paths`. |

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
| Management unauth reads | Fuerte | root/model + `datasources`, `mail`, `elytron`, `elytron TLS`, `mod_cluster`, `undertow https-listener`, `domain topology`. |
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

- `mod_cluster` / `proxy_ajp` mas finos cuando el frontend encadena backends Java complejos.
- `proxy_wstunnel` y cadenas WebSocket backend aun mas finas, idealmente con mas correlacion de paths o backends concretos.
- TLS posture adicional:
  - redirects canonicos de host/scheme/port
  - politicas de cookies de frontend mas finas
  - disclosures de certificados o cadenas TLS si aparecen en respuestas o errores

### Tomcat

- Descriptores y configs legacy adicionales:
  - `catalina.properties`: rutas de backup frecuentes añadidas; siguen faltando variantes editor-temp y nombres de app no-default bajo `Catalina/localhost/`.
  - `catalina.policy`: variantes y apps no-default bajo `Catalina/localhost/`.
- Artefactos de despliegue:
  - ampliar a JAR/backups concretos fuera de directory listing y nombres de app menos tipicos.
- JNDI/resource exposure mas fina:
  - referencias indirectas o menos comunes en descriptores por app y combinaciones de `context.xml.*`.

### WildFly

- TLS / Elytron mas fino:
  - ficheros referenciados de keystore/truststore y rutas concretas desde descriptores o propiedades
  - surface de realms/factories mas detallada por tipo de auth factory
- Domain mode / host-controller:
  - ampliar mas alla de hosts, `server-groups` y overlays hacia artefactos y lecturas mas especificas de despliegue distribuido.

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

1. Tomcat deploy artifacts concretos
   - JAR/backup files sin depender solo de directory listing
   - `Catalina/localhost/*.xml` adicionales para nombres de app menos comunes
   - variantes legacy y copias editor-temp de despliegues

2. WildFly domain mode / host-controller profundo
   - lecturas y artefactos mas especificos de topologia distribuida
   - profundizar en `host=*`, `server-group=*` y `deployment-overlay=*`

3. Apache reverse-proxy Java profundo
   - cadenas frontend->backend mas finas
   - correlacion de paths/backend sobre `proxy_wstunnel`
   - trust/disclosure adicional en despliegues complejos

4. Apache mod_status profundo
   - diferenciar `ExtendedStatus` con `Client` / `VHost` / `Request`
   - extraer mejor request metadata y contexto operativo sin duplicar el panel base

5. Apache balancer/mod_cluster profundo
   - extraer mejor miembros, rutas, estados y topologia desde `balancer-manager` y `mod_cluster`
   - evitar contar panel y detalle operativo como dos hallazgos separados

6. Apache mod_jk profundo
   - extraer workers, `route`, `host`, `port` y endpoints AJP desde `jk-status`
   - evitar contar panel y detalle operativo como dos hallazgos separados

### Prioridad 2

1. WildFly TLS / Elytron hardening profundo
   - referencias a keystore/truststore
   - auth factories y realms mas finos
   - topologia TLS de Undertow mas detallada

2. Apache TLS / frontend posture adicional
3. Tomcat JNDI / resource descriptor coverage adicional

### Prioridad 3

1. Validacion reproducible en entornos reales autorizados (sin depender de contenedores locales)
2. Falsos positivos conocidos
3. Tabla de deduplicacion por familia

## Pilar de implementacion actual

**Elegido:** Prioridad 1 con foco en **Tomcat: artefactos de despliegue (WAR) y descriptores bajo `conf/Catalina/localhost/`**, **WildFly: lecturas de topologia en `domain mode`** y **Apache: correlacion de routing proxy hacia backends internos a partir de `mod_info`**.

**Rationale:** Los artefactos y context XML suelen dar el mayor valor por hallazgo en auditorias de aplicaciones servidas por Tomcat, y las lecturas de topologia en WildFly `domain mode` mejoran mucho el entendimiento de despliegues distribuidos con poca complejidad adicional. En Apache, la combinacion de señal `proxy_wstunnel` y correlacion `frontend path -> backend interno` mejora el triage sin duplicar el hallazgo generico de `server-info`.

## Recomendacion operativa

Antes de seguir añadiendo volumen, usar el backlog con este orden:

1. Añadir una subfamilia concreta
2. Validarla en un objetivo o entorno corporativo real autorizado
3. Ajustar ruido
4. Documentar triage
5. Repetir

Esto mantiene el repo util para auditoria real y evita crecer con plantillas
que luego generan mas ruido que señal.
