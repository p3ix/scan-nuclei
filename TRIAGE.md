# Triage Guide

Guia operativa para interpretar resultados, evitar doble conteo y priorizar
hallazgos de `scan-nuclei`.

Este documento separa tres cosas:

- falsos positivos o matices conocidos: [KNOWN-FP.md](KNOWN-FP.md)
- cobertura y backlog: [COVERAGE.md](COVERAGE.md)
- uso y workflows: [README.md](README.md)

## Reglas generales

- contar una sola vez la misma causa raiz
- usar `technologies/*` como contexto, no como vulnerabilidad explotable
- tratar `*-potential` como riesgo a confirmar, no como explotacion demostrada
- si varias rutas pertenecen al mismo `template-id`, contar un solo hallazgo con
  multiples evidencias
- si una plantilla de "detalle" depende de un panel base o de una exposicion
  base, contarla como profundidad adicional, no como finding separado

## Prioridad de remediacion

Orden recomendado de atencion:

1. `default-logins` y paneles/superficies de administracion
2. `exposures` de secretos, configuracion o artefactos sensibles
3. `management-unauth` y lecturas sensibles no autenticadas
4. stacktraces y errores verbosos con clases, rutas o line numbers
5. `cves/*-potential` tras confirmacion manual
6. hardening y posture (`low`)
7. fingerprinting y disclosures (`info`)

## Reglas agregadas

Cuando uses `scripts/check-nuclei.sh --aggregate-output`:

- misma combinacion `host + template-id` => un solo hallazgo
- multiples `paths` => multiples evidencias del mismo hallazgo
- multiples `matcher-name` dentro del mismo `template-id` => profundidad de
  evidencia, no vulnerabilidades independientes

Esto aplica especialmente a:

- `openapi`, `wadl`, `swagger-assets`
- `sensitive-paths`
- management endpoints

## Apache

### Hallazgo base

Contar como hallazgo base:

- `apache-server-status-exposed`
- `apache-server-status-auto-exposed`
- `apache-status-json-exposed`
- `apache-server-info-exposed`
- `apache-balancer-manager-exposed`
- `apache-mod-cluster-manager-exposed`
- `apache-jk-status-exposed`

### Profundidad adicional

No contar aparte si ya existe el panel o exposicion base:

- `apache-server-status-request-metadata-exposed`
  - tratar como profundidad de `mod_status` si revela `Client`, `VHost` o
    `Request`
- `apache-balancer-manager-backend-details-exposed`
  - tratar como detalle operativo de `balancer-manager`
- `apache-mod-cluster-manager-backend-details-exposed`
  - tratar como detalle operativo de `mod_cluster`
- `apache-jk-status-backend-details-exposed`
  - tratar como detalle operativo de `mod_jk`
- `apache-info-module-signature-exposed`
  - tratar como evidencia parcial o asociada a `server-info`
- `apache-proxy-wstunnel-module-signal-potential`
  - tratar como señal de modulo, no como hallazgo principal
- `apache-proxy-wstunnel-routing-signal-exposed`
  - si coincide junto a `server-info`, tratarlo como detalle accionable de la
    exposicion de `mod_info`
- `apache-proxy-backend-routing-disclosure-exposed`
  - si coincide junto a `server-info`, tratarlo como correlacion mas concreta
    de la misma fuga
- `apache-proxy-backend-routing-disclosure-exposed` con `ProxyPassMatch` o
  `RewriteRule` hacia backends internos
  - tratarlo igual que `ProxyPass` directo: misma fuga de `mod_info`, pero con
    mas contexto sobre path matching o reglas de rewrite

### Deduplicacion recomendada

- `server-status`, `status?auto` y `status-json` suelen describir la misma
  superficie operativa
- `server-info` y detalles extraidos desde `mod_info` suelen describir la misma
  causa raiz
- panel y detalle topologico no deben contarse como dos vulnerabilidades
  separadas

## Tomcat

### Hallazgo base

Contar como hallazgo base:

- `tomcat-manager-html-exposed`
- `tomcat-host-manager-html-exposed`
- `tomcat-manager-jmxproxy-exposed`
- `tomcat-manager-script-endpoint-exposed`
- `tomcat-manager-text-deploy-surface-exposed`

### Profundidad adicional

No contar aparte si describen la misma superficie administrativa:

- `tomcat-manager-help-exposed`
- `tomcat-manager-text-endpoints-exposed`
- `tomcat-manager-status-endpoint-exposed`
- `tomcat-host-manager-help-exposed`
- `tomcat-host-manager-text-endpoints-exposed`

### Deduplicacion recomendada

- `manager`, `help`, `text`, `status` y endpoints auxiliares pueden ser la
  misma superficie admin con distintas rutas
- artefactos WAR, backups y descriptores bajo `Catalina/localhost/` pueden
  apuntar al mismo problema de exposicion de despliegue; agrupar por evidencia
  funcional al informar
- artefactos de app no-default (`app`, `api`, `admin`, `portal`, `service`) y
  sus residuos `.bak/.old/.orig/.save/.tmp/~/.swp` suelen describir la misma
  causa raiz de gestion insegura de despliegues; no contarlos como hallazgos
  independientes por cada nombre de archivo
- recursos `JNDI`, `ResourceLink`, `Environment`, `GlobalNamingResources`,
  `context.xml`, `ROOT.xml` y backups relacionados pueden apuntar a la misma
  exposicion de configuracion de recursos; separarlos por impacto solo cuando
  cambie claramente la evidencia sensible
- defaults, docs y ejemplos de Tomcat suelen contarse como exposicion base de
  contenido por defecto, no como varias vulnerabilidades separadas si revelan la
  misma instalacion

### Orden practico de triage

Priorizar en este orden cuando salgan varias familias Tomcat a la vez:

1. `default-logins` y paneles de administracion
2. `manager-script`, `jmxproxy` y `text-deploy-surface`
3. `tomcat-users.xml`, `server.xml`, `context.xml`, `GlobalNamingResources`,
   `JNDI/resources`
4. descriptores `Catalina/localhost/*.xml` y sus backups/temp variants
5. artefactos `WAR/JAR` y residuos de despliegue
6. defaults/docs/examples/listings
7. `CVE-*-potential` tras confirmacion manual

### Regla practica para informes

- si el riesgo principal es “superficie administrativa Tomcat expuesta”,
  agrupar `manager/html`, `help`, `text`, `status` y `host-manager` como una
  misma exposicion con profundidad adicional
- si el riesgo principal es “fuga de configuracion/despliegue”, agrupar
  `context.xml`, `ROOT.xml`, `Catalina/localhost/*.xml`, `JNDI/resources` y
  backups como una misma familia de exposicion, destacando por separado solo los
  ficheros con credenciales o recursos concretos
- si el riesgo principal es “artefactos descargables”, agrupar `WAR/JAR` y sus
  residuos por aplicacion o por raiz de despliegue, no por cada extension

## WildFly / JBoss

### Hallazgo base

Contar como hallazgo base:

- `wildfly-management-endpoint-exposed`
- `wildfly-console-exposed`
- `wildfly-hawtio-console-exposed`
- `wildfly-management-model-unauth`
- `wildfly-management-read-operations-unauth`

### Profundidad adicional

No contar aparte si ya se confirmo lectura no autenticada del management model:

- `wildfly-datasources-management-unauth`
- `wildfly-mail-management-unauth`
- `wildfly-elytron-management-unauth`
- `wildfly-elytron-tls-management-unauth`
- `wildfly-mod-cluster-management-unauth`
- `wildfly-undertow-https-listener-management-unauth`
- `wildfly-domain-topology-management-unauth`
- `wildfly-management-whoami-unauth`

### Deduplicacion recomendada

- si varias `wildfly-*-management-unauth` derivan de la misma ausencia de
  autenticacion en `/management`, contarlas como una misma causa raiz con
  multiples pruebas
- `wildfly-domain-topology-management-unauth` y
  `wildfly-domain-deployment-details-management-unauth` suelen describir la
  misma exposicion de `domain mode`; tratar la segunda como profundidad
  adicional cuando solo amplie detalle de `server-group`, `deployment`,
  `deployment-overlay` o `server-config`
- separar WildFly moderno de JBoss legacy cuando el hallazgo cambia la
  interpretacion o la prioridad de remediacion
- ficheros expuestos como `standalone.xml`, `domain.xml` o `mgmt-users` pueden
  reforzar el mismo problema operativo, pero deben seguir informandose como
  evidencia sensible concreta

## OpenAPI / WADL / Swagger

### Hallazgo base

Contar como hallazgo base:

- `openapi-json-exposed`
- `openapi-yaml-exposed`
- `wadl-exposed`
- `swagger-ui-exposed`

### Profundidad adicional

No contar aparte si solo amplian la misma documentacion:

- `swagger-assets-sourcemap-exposed`
- `swagger-contextpath-artifacts-exposed`
- `swagger-contextpath-artifacts-exposed-pro`
- `wsdl-xsd-exposed`

### Deduplicacion recomendada

- si varias rutas exponen el mismo spec o la misma UI, informarlo como una sola
  exposicion de documentacion
- si hay assets, source maps o artefactos de una misma UI, tratarlos como
  profundidad adicional salvo que revelen algo distinto y mas sensible

## Quarkus / Micronaut

### Quarkus

- `quarkus-stack-fingerprint` es una señal fuerte pero no exhaustiva
- ausencia de match no descarta `Quarkus` si `/q/health` esta deshabilitado,
  protegido, remapeado o escondido por proxy
- `quarkus-dev-ui-surface-exposed` debe priorizarse alto porque expone una
  superficie propia de desarrollo
- `quarkus-openapi-surface-exposed` y `quarkus-metrics-endpoint-exposed`
  suelen ser exposicion operativa/documental; separarlas del fingerprint y
  no tratarlas como vulnerabilidad critica por defecto

### Micronaut

- `micronaut-signal-fingerprint` es conservador y depende del header `Server`
- ausencia de match no descarta `Micronaut` si hay reverse proxy, gateway o
  hardening de headers
- `micronaut-management-endpoints-exposed` puede devolver varias rutas de la
  misma causa raiz; deduplicar por superficie de management
- `micronaut-loggers-write-surface-exposed` y
  `micronaut-refresh-write-surface-exposed` deben interpretarse como
  write surface potencial o semiconfirmada, no como cambio de estado probado

### Regla practica

- usar esta familia como snapshot de superficie moderna Java
- si hay match, aporta señal util
- si no hay match, no asumir ausencia de stack

## Stacktraces

Priorizar mas alto cuando aparezcan:

- paquetes internos
- clases de aplicacion
- line numbers
- rutas locales
- nombres de componentes o frameworks utiles para encadenar ataque

Tratar como hardening cuando:

- el error es generico
- no hay detalle sensible
- no se revela contexto interno util

## Cabeceras

- `low`
  - ausencia de cabeceras de hardening o postura mejorable
- `medium`
  - HSTS flojo, flags de cookie incompletos, valores invalidos o politicas web
    debiles
- `high`
  - CORS peligroso, especialmente `Allow-Credentials: true` con origen reflejado
- `info`
  - disclosures como `Server`, `X-Powered-By` o version hints

## Cuando separar hallazgos

Mantener hallazgos separados cuando:

- cambian la causa raiz
- cambian la remediacion
- cambian claramente el impacto
- pasan de "panel base" a "lectura sensible confirmada"
- pasan de "documentacion expuesta" a "secreto o config sensible expuesta"

## Regla practica final

Si dudas entre contar 2 hallazgos o 1:

- contar 1 cuando una evidencia explica o profundiza otra
- contar 2 cuando el equipo tendria que aplicar dos remediaciones distintas
