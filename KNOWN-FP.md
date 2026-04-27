# Falsos positivos conocidos

Registro breve de plantillas que requieren contexto adicional o correlacion para no sobre-priorizar un hallazgo. Ampliar segun entornos reales.

| Plantilla | Nota |
| --- | --- |
| `templates/exposures/apis/graphql-introspection-unauth.yaml` | Algunas APIs publicas documentan el esquema de forma intencionada. Verificar politica de producto y entorno (interno vs publico) antes de tratar como vulnerabilidad. |
| `templates/technologies/micronaut/micronaut-signal-fingerprint.yaml` | Depende de la cabecera `Server: ...micronaut...`; en produccion muchas instalaciones usan un reverse proxy que oculta u homogeneiza el header, por lo que no implica ausencia de Micronaut. |
| `templates/technologies/quarkus/quarkus-stack-fingerprint.yaml` | Pide cuerpo con `io.quarkus` en `/q/health`; otras plataformas con MicroProfile Health bajo el mismo path sin esa firma no emitiran match (por diseno, para reducir ruido frente a WildFly). |
| `templates/misconfiguration/java-apps/quarkus-dev-ui-surface-exposed.yaml` | Cadenas "Dev UI" pueden aparecer en otras UIs. El match exige "quarkus" y patrones de dev; revisar cuerpo y contexto. |
| `templates/exposures/javascript-sourcemap-exposed.yaml` | Cualquier respuesta 200 con JSON con forma de source map (incl. mensajes o rutas falsa similitud) puede requerir revision manual del payload. |

Para triage generico, seguir [README.md](README.md#triage-recomendado-evitar-duplicados).

## Regla de deduplicacion agregada (salida JSONL resumida)

Cuando uses `scripts/check-nuclei.sh --aggregate-output`, aplicar esta regla:

- misma combinacion `host + template-id` => **un solo hallazgo** con multiples evidencias (`paths`).

Esto aplica especialmente a familias con alta repeticion por rutas:

- API docs (`wadl`, `openapi`, `swagger-assets`)
- `sensitive-paths`
- management endpoints

Si aparecen varios `matcher-name` dentro del mismo `template-id`, tratalos como profundidad
de evidencia del mismo hallazgo, no como vulnerabilidades independientes.
