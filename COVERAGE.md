# Coverage Matrix

Este documento resume la cobertura actual del repositorio y el backlog
priorizado para seguir ampliando el set de plantillas sin crecer a ciegas.

## Cobertura actual

### Apache

| Familia | Estado | Notas |
|---|---|---|
| Fingerprinting | Fuerte | `apache-httpd-server-header`, default page, reverse proxy, server version, fronting `Tomcat` y `WildFly`. |
| Admin surface | Fuerte | `server-status`, `status?auto`, `status-json`, `server-info`, `balancer-manager`, `jk-status`. |
| Proxy surface | Fuerte | `open-proxy`, `forward-proxy`, trust bypass por `X-Forwarded-*`, CVEs `mod_proxy`. |
| Config leaks | Bueno | `httpd.conf`, `apache2.conf`, `vhosts`, `ssl.conf`, backups, `.ht*`. |
| Hardening | Bueno | missing headers, TRACE, unsafe methods, directory listing. |
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
| Management unauth reads | Fuerte | root/model + `datasources`, `mail`, `elytron`, `mod_cluster`. |
| Config leaks | Fuerte | `standalone.xml`, `domain.xml`, `host.xml`, `mgmt-users/groups`, logging, `jboss-web.xml`, `jboss-deployment-structure.xml`, `persistence.xml`. |
| Defaults / sample apps | Bueno | welcome content, sample apps, health, metrics, OpenAPI. |
| Hardening | Bueno | headers, cookies, CORS, verbose errors, stacktraces. |
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

- TLS posture mas fino:
  - redireccion HTTP -> HTTPS
  - HSTS consistente en frontend
  - posibles disclosures de certificados/rutas si aparecen en respuestas
- `mod_cluster` / `proxy_ajp` / `proxy_wstunnel` / `mod_status` mas finos cuando el frontend encadena backends Java complejos.
- Configuracion legacy de auth (`auth_basic`, `auth_digest`) y alias/script mappings expuestos.

### Tomcat

- Descriptores y configs legacy adicionales:
  - `catalina.policy` ya existe, pero faltan `catalina.properties` backups y algunas variantes de `Catalina/localhost/*.xml` no ROOT.
- Artefactos de despliegue:
  - WAR/JAR/backups concretos fuera de directory listing.
- JNDI/resource exposure mas fina:
  - descriptores de recursos por app y combinaciones de `context.xml.default`, `context.xml.*`.

### WildFly

- Descriptores legacy/EE adicionales:
  - `*-ds.xml`
  - `jboss-app.xml`
  - `jboss-client.xml`
  - `ironjacamar.xml`
- TLS / Elytron mas fino:
  - ficheros referenciados de keystore/truststore
  - surface de realms/factories mas detallada
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

1. Apache TLS / frontend hardening
   - redirects a HTTPS
   - HSTS efectivo
   - cabeceras frontend de seguridad

2. WildFly datasource / EE descriptors
   - `*-ds.xml`
   - `jboss-app.xml`
   - `jboss-client.xml`
   - `ironjacamar.xml`

3. Tomcat deploy artifacts concretos
   - WAR/JAR/backup files sin depender solo de directory listing
   - `Catalina/localhost/*.xml` adicionales

### Prioridad 2

1. Apache auth / alias / script mappings
2. WildFly TLS / Elytron hardening profundo
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
