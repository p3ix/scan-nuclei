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
