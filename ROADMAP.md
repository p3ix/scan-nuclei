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

El principal siguiente salto no es solo "mas templates", sino "mas confianza":

- reducir falsos positivos
- controlar duplicados
- detectar regresiones funcionales
- estabilizar familias nuevas antes de expandir mas

## Objetivo de las proximas 2 semanas

Subir el nivel de calidad del repo sin frenar la evolucion funcional.

Resultado esperado al final del ciclo:

- base minima de checks estructurales mas alla de `nuclei -validate`
- criterio de deduplicacion mas formal por familia
- linea `Quarkus/Micronaut` mas estable y mejor documentada
- guia de uso mas directa para escenarios tipicos de auditoria

## Prioridades

1. Calidad y regresion
2. Deduplicacion y triage
3. Consolidacion de Quarkus/Micronaut
4. Experiencia de uso

## Semana 1

### 1. Blindar calidad minima

Objetivo:
Tener controles basicos que detecten problemas que hoy pasan aunque el YAML sea
valido.

Tareas:

- crear un script local de checks estructurales en `scripts/`
- comprobar `id` duplicados
- comprobar nombres de archivo fuera de convencion
- detectar severidades vacias o poco consistentes
- detectar referencias a workflows o templates que no existan
- dejar documentado como ejecutar estos checks antes de commit

Definicion de hecho:

- existe script ejecutable y documentado
- el script falla con codigo distinto de cero cuando detecta problemas
- el script se puede integrar despues en CI sin rehacerlo

Entregables sugeridos:

- `scripts/check-repo.sh`
- seccion breve en `README.md`

### 2. Cerrar criterio de deduplicacion

Objetivo:
Que el repo exprese mejor que es un hallazgo base, que es profundidad
adicional, y que no debe contarse dos veces.

Tareas:

- convertir el criterio narrativo actual en reglas operativas por familia
- definir para `Apache`:
  - `server-status` vs `request-metadata`
  - `balancer-manager` vs detalle de backends
  - `mod_cluster` vs detalle topologico
  - `jk-status` vs detalle operativo
- definir para `Tomcat`:
  - `manager`/`help`/`text`/`status` como misma superficie cuando aplique
- definir para `WildFly`:
  - lecturas `management-unauth` como misma causa raiz cuando proceda
- reflejar el criterio en `KNOWN-FP.md` o en una tabla nueva dedicada

Definicion de hecho:

- hay una tabla o seccion clara por familia
- una persona nueva puede interpretar resultados sin depender del autor

Entregables sugeridos:

- ampliar `KNOWN-FP.md`
- o crear `TRIAGE.md`

## Semana 2

### 3. Consolidar Quarkus y Micronaut

Objetivo:
Evitar que esta familia crezca mas rapido de lo que madura.

Tareas:

- revisar las plantillas actuales de `Quarkus` y `Micronaut`
- documentar explicitamente:
  - que señal usa cada fingerprint
  - que limitaciones tiene
  - cuando puede haber falsos negativos por reverse proxy
  - como debe correlacionarse con otros hallazgos
- añadir plantillas nuevas solo si salen de necesidad real o validacion util
- ampliar `KNOWN-FP.md` con notas especificas de esta familia

Definicion de hecho:

- la familia queda marcada como "inicial pero fiable"
- el workflow `java-modern-stacks-snapshot` tiene expectativas claras de uso

Entregables sugeridos:

- mejora en `README.md`
- mejora en `KNOWN-FP.md`
- ajuste fino de plantillas si hace falta

### 4. Mejorar experiencia de uso

Objetivo:
Reducir friccion para ejecutar el repo en escenarios comunes.

Tareas:

- añadir una seccion de uso por escenario en `README.md`
- cubrir al menos estos casos:
  - Apache solo
  - Apache fronting Tomcat
  - Apache fronting WildFly
  - Tomcat solo
  - WildFly solo
- indicar workflow recomendado y expectativa de ruido
- enlazar con el modo `--aggregate-output`

Definicion de hecho:

- alguien nuevo puede elegir workflow sin leer todo el repo
- la recomendacion de uso queda alineada con el triage real

## Riesgos a vigilar

- crecer en numero de templates mas rapido que en validacion real
- mezclar fingerprinting con hallazgos accionables en el mismo nivel de triage
- duplicar exposiciones de panel y detalle como si fueran dos vulnerabilidades
- abrir mas familias nuevas antes de estabilizar `Quarkus/Micronaut`

## Decisiones recomendadas

- no abrir nuevas lineas grandes de cobertura esta quincena
- priorizar calidad sobre volumen
- usar validacion en entornos reales autorizados antes de dar por buena una
  subfamilia nueva

## Backlog inmediato despues de estas 2 semanas

Cuando este bloque quede cerrado, el siguiente paso natural seria:

1. pruebas de regresion con fixtures o casos controlados por familia
2. ampliacion profunda de `Tomcat`, `WildFly domain mode` y `Apache proxy`
3. matriz de validacion reproducible en entornos corporativos autorizados
4. tabla de deduplicacion mas formal y reusable para informes

## Resumen ejecutivo

La prioridad correcta ahora no es "tener mas templates", sino "confiar mas en
los que ya tenemos". Si este roadmap se cumple, el repo deberia quedar mejor
preparado para crecer sin aumentar ruido ni deuda operativa.
