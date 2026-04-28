# Falsos positivos conocidos

Registro breve de plantillas que requieren contexto adicional o correlacion para no sobre-priorizar un hallazgo. Ampliar segun entornos reales.

| Plantilla | Nota |
| --- | --- |
| `templates/exposures/apis/graphql-introspection-unauth.yaml` | Algunas APIs publicas documentan el esquema de forma intencionada. Verificar politica de producto y entorno (interno vs publico) antes de tratar como vulnerabilidad. |
| `templates/technologies/micronaut/micronaut-signal-fingerprint.yaml` | Depende de la cabecera `Server: ...micronaut...`; en produccion muchas instalaciones usan un reverse proxy que oculta u homogeneiza el header, por lo que no implica ausencia de Micronaut. |
| `templates/technologies/quarkus/quarkus-stack-fingerprint.yaml` | Pide cuerpo con `io.quarkus` en `/q/health`; otras plataformas con MicroProfile Health bajo el mismo path sin esa firma no emitiran match (por diseno, para reducir ruido frente a WildFly). |
| `templates/misconfiguration/java-apps/quarkus-dev-ui-surface-exposed.yaml` | Cadenas "Dev UI" pueden aparecer en otras UIs. El match exige "quarkus" y patrones de dev; revisar cuerpo y contexto. |
| `templates/misconfiguration/quarkus/quarkus-openapi-surface-exposed.yaml` | Puede coincidir con documentacion intencionalmente publicada bajo `/q/openapi` o `/q/swagger-ui`; tratar como exposicion operativa/documental salvo que el contexto exija ocultarla. |
| `templates/misconfiguration/quarkus/quarkus-metrics-endpoint-exposed.yaml` | `metrics` puede estar expuesto de forma deliberada para observabilidad; revisar si el endpoint es publico, interno o protegido aguas arriba antes de escalar prioridad. |
| `templates/misconfiguration/micronaut/micronaut-management-endpoints-exposed.yaml` | Agrega varias rutas (`/env`, `/routes`, `/beans`, `/loggers`) que pueden representar la misma superficie de management; deduplicar por causa raiz y no por path individual. |
| `templates/misconfiguration/micronaut/micronaut-loggers-write-surface-exposed.yaml` | Un `400` o `415` con semantica JSON puede indicar parser activo o ruta existente, no necesariamente cambio de log level confirmado; revisar respuesta y control de acceso antes de concluir write surface real. |
| `templates/misconfiguration/micronaut/micronaut-refresh-write-surface-exposed.yaml` | Igual que en `loggers`, respuestas `200/202/204/400/415` indican superficie potencialmente alcanzable, pero no siempre accion de refresh efectiva sin autenticacion. |
| `templates/exposures/sensitive-paths/tomcat-manager-help-exposed.yaml` | Puede salir junto a `tomcat-manager-html-exposed`, `text` y `status` sobre la misma causa raiz de superficie admin; no contarlo como hallazgo separado salvo que revele una capacidad distinta y util para explotacion. |
| `templates/exposures/sensitive-paths/tomcat-jndi-resources-exposed.yaml` | Puede solaparse con `context.xml`, `ROOT.xml`, `GlobalNamingResources` o backups del mismo descriptor; priorizar la evidencia mas sensible y evitar multiplicar findings por cada ruta equivalente. |
| `templates/exposures/sensitive-paths/tomcat-context-resource-backups-exposed.yaml` | Variantes `.bak/.old/.orig/.save/.tmp/~` suelen describir la misma fuga de configuracion que el descriptor base; tratarlas como profundidad adicional salvo que el backup revele mas secretos que el fichero activo. |
| `templates/exposures/sensitive-paths/tomcat-app-archive-temp-artifacts-exposed.yaml` | WAR/JAR de nombres comunes (`app`, `api`, `admin`, `portal`, `service`) pueden ser intencionalmente accesibles en algun entorno de distribucion interna; validar si realmente son artefactos de despliegue no previstos antes de escalar. |
| `templates/exposures/sensitive-paths/tomcat-catalina-localhost-app-xml-temp-variants-exposed.yaml` | Variantes de `Catalina/localhost/*.xml` para nombres no-default (`auth`, `gateway`, `internal`, `backoffice`, etc.) suelen representar la misma familia de fuga que `ROOT.xml` o `context.xml`; agrupar por aplicacion o descriptor, no por sufijo o backup. |
| `templates/exposures/sensitive-paths/tomcat-users-xml-exposed.yaml` | Puede coexistir con `server.xml`, `UserDatabaseRealm` o `MemoryUserDatabase`; priorizarlo como hallazgo principal cuando expone usuarios/roles reales y tratar el resto como evidencia de soporte. |
| `templates/exposures/sensitive-paths/tomcat-web-xml-exposed.yaml` | `web.xml` y `WEB-INF/web.xml` pueden duplicar la misma exposicion de servlets, filtros y `security-constraint`; deduplicar por aplicacion o contexto salvo que uno de ellos revele parametros o roles mas sensibles. |
| `templates/misconfiguration/apache/apache-server-status-request-metadata-exposed.yaml` | Si aparece junto a `apache-server-status-exposed`, tratarlo como profundidad adicional de `mod_status`, no como finding independiente, salvo que revele `Client`, `VHost` o `Request` con informacion especialmente sensible. |
| `templates/misconfiguration/apache/apache-server-status-auto-exposed.yaml` | `server-status?auto` suele ser la variante machine-readable de la misma causa raiz que `server-status`; deduplicar por superficie `mod_status` y destacar aparte solo si facilita scraping o inventario automatizado. |
| `templates/misconfiguration/apache/apache-status-json-exposed.yaml` | Igual que `server-status?auto`, suele representar la misma exposicion de `mod_status`; priorizarlo mas solo si la salida JSON contiene datos operativos mas explotables que la vista HTML. |
| `templates/misconfiguration/apache/apache-balancer-manager-backend-details-exposed.yaml` | Si ya existe `apache-balancer-manager-exposed`, contarlo como detalle del mismo panel. Separarlo solo cuando el backend detail revele hosts, rutas o estados internos de alto valor. |
| `templates/misconfiguration/apache/apache-mod-cluster-manager-backend-details-exposed.yaml` | Suele ser profundidad del mismo panel `mod_cluster_manager`; no multiplicar findings por cada vista o listado si la causa raiz es la misma. |
| `templates/misconfiguration/apache/apache-jk-status-backend-details-exposed.yaml` | Igual que `jk-status`, suele ampliar evidencia del mismo panel de administracion; deduplicar y destacar aparte solo si expone mappings o workers internos especialmente sensibles. |
| `templates/exposures/sensitive-paths/apache-workers-properties-exposed.yaml` | Puede solaparse con `uriworkermap.properties`, `proxy_ajp.conf` o `mod_info` cuando todo describe el mismo routing `mod_jk/AJP`; agrupar por stack de proxy/routing y no por fichero individual. |
| `templates/exposures/sensitive-paths/apache-uriworkermap-properties-exposed.yaml` | Igual que `workers.properties`, suele ser evidencia de la misma configuracion `mod_jk`; priorizarlo mas solo si revela rutas sensibles o segmentacion interna no visible en otros artefactos. |
| `templates/exposures/sensitive-paths/apache-proxy-ajp-config-exposed.yaml` | Puede representar la misma fuga que `workers.properties`, `server-info` o `ProxyPass ajp://`; tratarlo como correlacion adicional de AJP/routing, no como finding separado por defecto. |
| `templates/misconfiguration/apache/apache-proxy-backend-routing-disclosure-exposed.yaml` | `ProxyPass`, `ProxyPassMatch` y `RewriteRule [P]` pueden aparecer tambien en `server-info` o ficheros expuestos; consolidar por backend/routing interno y no por cada mecanismo de proxy detectado. |
| `templates/misconfiguration/apache/apache-internal-backend-location-disclosure.yaml` | Si coincide con otros templates de routing/proxy, suele describir el mismo backend interno o topologia; mantenerlo como hallazgo independiente solo si la localizacion interna es la evidencia principal. |
| `templates/exposures/sensitive-paths/wildfly-elytron-properties-exposed.yaml` | `application-users.properties`, `application-roles.properties`, `mgmt-users.properties` y variantes de dominio/standalone pueden ser la misma causa raiz de exposicion de credenciales o roles; deduplicar por dominio de autenticacion y destacar el fichero mas sensible. |
| `templates/exposures/sensitive-paths/java-keystore-truststore-exposed.yaml` | Puede aparecer como correlacion de `ssl-context`, `key-store` o `trust-manager` leidos por Elytron/TLS; priorizarlo mas cuando el artefacto binario es realmente descargable y no solo inferido desde configuracion. |
| `templates/exposures/javascript-sourcemap-exposed.yaml` | Cualquier respuesta 200 con JSON con forma de source map (incl. mensajes o rutas falsa similitud) puede requerir revision manual del payload. |

Para triage generico y reglas de deduplicacion por familia, seguir
[TRIAGE.md](TRIAGE.md).

## Regla de deduplicacion agregada (salida JSONL resumida)

Cuando uses `scripts/check-nuclei.sh --aggregate-output`, aplicar esta regla:

- misma combinacion `host + template-id` => **un solo hallazgo** con multiples evidencias (`paths`).

Esto aplica especialmente a familias con alta repeticion por rutas:

- API docs (`wadl`, `openapi`, `swagger-assets`)
- `sensitive-paths`
- management endpoints

Si aparecen varios `matcher-name` dentro del mismo `template-id`, tratalos como profundidad
de evidencia del mismo hallazgo, no como vulnerabilidades independientes.
