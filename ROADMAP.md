# Roadmap

Plan corto y accionable para consolidar `scan-nuclei` como repositorio util,
mantenible y menos dependiente de validacion manual.

## Estado actual

El repositorio ya tiene una base fuerte:

- cobertura amplia en `Apache`, `Tomcat` y `WildFly/JBoss`
- linea inicial para `Quarkus` y `Micronaut`
- `workflows` reutilizables para escenarios reales
- criterio de triage y severidad documentado
- validacion automatica en CI con `nuclei -validate -t templates/`
- chequeo estructural del repo
- regresion HTTP local con fixtures por familia

El principal siguiente salto no es solo "mas templates", sino "mas confianza":

- reducir falsos positivos
- controlar duplicados
- detectar regresiones funcionales
- estabilizar familias nuevas antes de expandir mas

## Estado del roadmap corto

El bloque corto original esta practicamente cumplido.

Hoy el repo ya tiene:

- checks estructurales mas alla de `nuclei -validate`
- criterio de deduplicacion y triage por familia
- linea `Quarkus/Micronaut` estable en su alcance actual
- guia de uso por escenario en `README.md`
- regresion HTTP con `58` casos distribuidos entre `Apache`, `Tomcat`,
  `WildFly`, `Spring`, `Quarkus` y `Micronaut`

## Prioridades actuales

1. Validacion real autorizada y ajuste de ruido
2. Triage y deduplicacion reutilizable para informes
3. Cobertura residual selectiva
4. Mantenimiento de regresion

## Lo ya cerrado

- `scripts/check-repo.sh` y CI integrados
- `TRIAGE.md` con reglas operativas por familia
- `README.md` con workflows y escenarios de uso
- `TESTING.md` con runner de regresion
- consolidacion fuerte de:
  - `Apache` proxy/admin (`mod_info`, `mod_status`, `balancer`, `mod_cluster`,
    `mod_jk`, `workers.properties`, `uriworkermap.properties`, `proxy_ajp.conf`)
  - `Tomcat` despliegue/config (`Catalina/localhost`, `server.xml`,
    `tomcat-users.xml`, `web.xml`, `WAR/JAR`, `JNDI`)
  - `WildFly` `domain mode`, `Elytron/TLS`, `Undertow HTTPS listener`,
    `application-users/roles`, `keystore/truststore`

## Riesgos a vigilar

- crecer en numero de templates mas rapido que en validacion real
- mezclar fingerprinting con hallazgos accionables en el mismo nivel de triage
- duplicar exposiciones de panel y detalle como si fueran dos vulnerabilidades
- dejar que el backlog documental quede por detras del estado real del repo

## Decisiones recomendadas

- no abrir nuevas lineas grandes de cobertura sin validacion real
- priorizar calidad sobre volumen
- usar validacion en entornos reales autorizados antes de dar por buena una
  subfamilia nueva

## Backlog inmediato despues de estas 2 semanas

Cuando este bloque quede cerrado, el siguiente paso natural seria:

1. matriz de validacion reproducible en entornos corporativos autorizados
2. backlog residual y selectivo por familia segun evidencia real
3. tabla de deduplicacion mas formal y reusable para informes
4. mantenimiento de la regresion a medida que crezcan los workflows

## Resumen ejecutivo

La prioridad correcta sigue siendo "confiar mas en lo que ya hay". El siguiente
salto de valor ya no pasa tanto por abrir mas volumen, sino por validar mejor,
documentar mejor y crecer solo donde haya necesidad real.
