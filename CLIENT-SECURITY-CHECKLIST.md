# Checklist de seguridad antes de entregar al cliente

Esta checklist sirve para revisar un objetivo antes de sacar resultados al
cliente usando este repositorio de templates Nuclei. La idea es separar:

- lo que los scripts/templates pueden detectar con evidencia HTTP
- lo que hay que confirmar manualmente
- lo que debe quedar claro en el informe para evitar sobrecontar, exagerar o
  dejar riesgos importantes fuera

## 1. Antes de escanear

- [ ] Confirmar alcance autorizado: dominios, subdominios, IPs, puertos,
      entornos y ventanas horarias.
- [ ] Confirmar si se permite escaneo autenticado o solo externo anonimo.
- [ ] Confirmar limites de tasa, concurrencia, user-agent y ventanas de bajo
      impacto.
- [ ] Identificar activos criticos: produccion, preproduccion, admin panels,
      APIs internas publicadas, balanceadores, WAF/CDN y proxies.
- [ ] Resolver redirects y canonical host: HTTP -> HTTPS, `www`, context paths,
      puertos alternativos y virtual hosts.
- [ ] Guardar version de Nuclei y fecha/hora de ejecucion.
- [ ] Validar templates antes del scan:

```bash
scripts/check-repo.sh
nuclei -validate -t templates/
```

- [ ] Si se usan todos los templates, preferir salida agregada para reducir
      ruido:

```bash
scripts/full-scan.sh --target https://objetivo
```

- [ ] Si el stack esta claro, usar workflow especifico en vez de barrido total.
- [ ] No ejecutar payloads destructivos ni pruebas de escritura reales fuera de
      autorizacion explicita. Los templates `*-write-surface-potential` solo
      buscan comportamiento de endpoint con entradas invalidas.

## 2. Que cubre este repo

Este repo esta especialmente orientado a:

- Apache HTTPD: hardening, `server-status`, `server-info`, proxy/admin surface,
  `mod_jk`, `mod_cluster`, AJP/proxy leaks, TRACE, headers y configuracion
  expuesta.
- Tomcat: Manager/Host Manager, endpoints `text`, `jmxproxy`, deploy surface,
  defaults, docs, examples, `server.xml`, `tomcat-users.xml`, `context.xml`,
  `Catalina/localhost`, artefactos WAR/JAR y backups.
- Java web generico: `JSESSIONID`, errores servlet, stacktraces, descriptors
  `WEB-INF`, `META-INF`, logs, heapdump, threaddump, env, OpenAPI/WADL/Swagger,
  JSF/Jakarta Faces y PrimeFaces.
- Spring Boot / Spring Cloud: Actuator, health/env/metrics/loggers, write
  surfaces potenciales, gateway, config server, Eureka, Spring Boot Admin,
  Zipkin y perfiles/configuracion expuesta.
- WildFly/JBoss/Undertow: management API, consola, domain mode, datasources,
  Elytron/TLS, mod_cluster, health/metrics, OpenAPI, Hawtio/Jolokia y ficheros
  sensibles.
- Jetty: fingerprints, configuracion, realms, directory listing, test webapp y
  dump servlet.
- Quarkus y Micronaut: health, metrics, management endpoints, env, loggers,
  refresh/stop surfaces y OpenAPI.
- Nginx: autoindex, stub status, version disclosure y VTS status.
- Observability e infraestructura: Prometheus, Alertmanager, Grafana signup,
  cAdvisor, etcd metrics, Kubernetes API/Dashboard, Docker Registry, Consul,
  Vault, Elasticsearch, Kibana, RabbitMQ, Jenkins, Flink y Spark.
- CVEs seleccionadas: detecciones `potential` para priorizacion, no prueba
  definitiva de explotabilidad.
- Default credentials seleccionadas: Tomcat Manager / Apache Tomcat.

## 3. Que NO cubre o no demuestra por si solo

- [ ] No sustituye una auditoria autenticada de aplicacion.
- [ ] No prueba logica de negocio, autorizacion horizontal/vertical, IDOR,
      fraude, abuso de workflow ni controles de rol.
- [ ] No cubre fuzzing profundo de parametros, inyecciones complejas, SSRF
      personalizada, deserializacion custom o explotacion manual.
- [ ] No confirma explotabilidad real de todos los `CVE-*-potential`; requiere
      version exacta, configuracion, parcheado y, si esta autorizado, PoC
      controlada.
- [ ] No valida hardening de sistema operativo, red interna, reglas cloud,
      IAM, secretos fuera de HTTP ni segmentacion.
- [ ] No garantiza ausencia de exposicion si hay WAF, rutas remapeadas,
      autenticacion condicional, virtual hosts no incluidos o context paths no
      descubiertos.
- [ ] No demuestra impacto de endpoints de escritura si solo hay respuesta
      compatible; los `*-write-surface-potential` se deben confirmar aparte.
- [ ] No analiza codigo fuente ni dependencias con SAST/SCA.
- [ ] No cubre TLS en profundidad: ciphers, certificados, HSTS preload, mTLS,
      OCSP, downgrade, renegociacion o configuraciones avanzadas.

## 4. Checklist de ejecucion

- [ ] Ejecutar fingerprinting o workflow adecuado para identificar stack.
- [ ] Ejecutar workflow especifico si aplica:
      - Full coverage: `templates/workflows/global/full-coverage-workflow.yaml`
      - Apache solo: `templates/workflows/apache/apache-misconfig-from-fingerprint-workflow.yaml`
      - Apache hardening: `templates/workflows/apache/apache-hardening-workflow.yaml`
      - Apache proxy/admin: `templates/workflows/apache/apache-proxy-admin-surface-workflow.yaml`
      - Apache fronting Tomcat: `templates/workflows/apache/apache-fronting-tomcat-workflow.yaml`
      - Apache fronting WildFly: `templates/workflows/apache/apache-fronting-wildfly-workflow.yaml`
      - Tomcat admin/config/CVEs: `templates/workflows/tomcat/tomcat-version-priority-workflow.yaml`
      - Tomcat hardening: `templates/workflows/tomcat/tomcat-hardening-workflow.yaml`
      - Tomcat con apps Java: `templates/workflows/tomcat/tomcat-fingerprint-to-java-exposure-workflow.yaml`
      - WildFly moderno: `templates/workflows/wildfly/wildfly-modern-admin-surface-workflow.yaml`
      - JBoss legacy: `templates/workflows/wildfly/jboss-legacy-migration-debt-workflow.yaml`
      - Spring: `templates/workflows/spring/spring-fingerprint-to-risk-workflow.yaml`
      - Java diagnostico generico: `templates/workflows/java/java-diagnostics-exposure-workflow.yaml`
      - Jetty: `templates/workflows/java/jetty-fingerprint-to-java-exposure-workflow.yaml`
      - JSF/Jakarta Faces: `templates/workflows/java/jsf-jakarta-faces-workflow.yaml`
      - Nginx: `templates/workflows/nginx/nginx-hardening-workflow.yaml`
      - Observability: `templates/workflows/observability/observability-exposure-workflow.yaml`
      - Infraestructura: `templates/workflows/infrastructure/infrastructure-admin-surface-workflow.yaml`
      - CI/CD: `templates/workflows/cicd/cicd-exposure-workflow.yaml`
      - Search stack: `templates/workflows/search/search-stack-exposure-workflow.yaml`
      - Messaging: `templates/workflows/messaging/messaging-admin-surface-workflow.yaml`
      - Java platform admin: `templates/workflows/java/java-platform-admin-surface-workflow.yaml`
- [ ] Si el objetivo tiene muchos paths o context roots, probar tambien con
      rutas base relevantes: `/`, `/app`, `/api`, `/admin`, `/manager`,
      `/services`, `/actuator`, `/management`.
- [ ] Repetir contra puertos no estandar si estan en alcance: 8080, 8081, 8443,
      8009, 9990, 9000, 9090, 9093, 9200, 5601, 15672, 10250.
- [ ] Guardar output raw y output agregado.
- [ ] Revisar errores de conexion, timeouts, 403/401, redirects y bloqueos WAF.
- [ ] Comparar resultados con tecnologia detectada; un fingerprint `info` no es
      una vulnerabilidad.

## 5. Checklist de triage antes del informe

- [ ] Agrupar por causa raiz, no por cada path.
- [ ] No contar dos veces el mismo panel admin detectado por varias rutas.
- [ ] Tratar `technologies/*` como contexto.
- [ ] Tratar `*-potential` como riesgo a confirmar.
- [ ] Confirmar si el hallazgo es publico desde Internet o solo desde red
      corporativa/VPN.
- [ ] Revisar si hay autenticacion real aunque el template detecte el producto.
- [ ] Confirmar si la respuesta pertenece al cliente y no a un proxy, CDN,
      proveedor compartido o pagina generica.
- [ ] Revisar evidencias sensibles antes de pegarlas en informe: secretos,
      tokens, usuarios, rutas internas, nombres de host y datos personales.
- [ ] Recortar evidencias al minimo necesario.
- [ ] Marcar claramente falsos positivos, imposibilidad de confirmacion o
      hallazgos dependientes de contexto.
- [ ] Priorizar por impacto real: admin publico, secretos/config, lectura no
      autenticada, dumps/logs, write surfaces, documentacion API, hardening.

## 6. Apache HTTPD

Comprobar con Nuclei:

- [ ] `server-status`, `server-status?auto`, `server-status?json`.
- [ ] `server-info` y fuga de modulos/configuracion.
- [ ] `balancer-manager`, `mod_cluster-manager`, `jk-status`.
- [ ] `workers.properties`, `uriworkermap.properties`, `proxy_ajp.conf`.
- [ ] `ProxyPass`, `ProxyPassMatch`, `RewriteRule [P]`, rutas `ws://`/`wss://`.
- [ ] Directory listing y `.ht*` expuestos.
- [ ] TRACE/metodos inseguros.
- [ ] Headers de seguridad y cookies.
- [ ] HSTS ausente/debil en HTTPS.
- [ ] Version disclosure.
- [ ] Posible open proxy / forward proxy.

Comprobar manualmente:

- [ ] Si `server-status` revela clientes, hosts internos o rutas sensibles.
- [ ] Si `server-info` muestra backends internos explotables.
- [ ] Si Apache solo sirve como proxy delante de Tomcat/WildFly/Java.
- [ ] Si headers faltantes tienen impacto real en la aplicacion.
- [ ] Si redirects dependen de `Host`, `X-Forwarded-*` o cabeceras de proxy.
- [ ] Si hay rutas admin protegidas por IP pero expuestas desde ubicacion del
      cliente.

## 7. Tomcat

Comprobar con Nuclei:

- [ ] `/manager/html`, `/host-manager/html`.
- [ ] `/manager/text/*`, deploy surface, script endpoint y JMX proxy.
- [ ] Default credentials.
- [ ] `/manager/status`, help pages y endpoints auxiliares.
- [ ] `tomcat-users.xml`, `server.xml`, `context.xml`, `web.xml`.
- [ ] `Catalina/localhost/*.xml`, backups y variantes temporales.
- [ ] `GlobalNamingResources`, JNDI resources, datasource config.
- [ ] WAR/JAR descargables, backups y restos de despliegue.
- [ ] Examples, docs, default root, directory listings.
- [ ] TRACE, cookies `JSESSIONID`, SameSite/Secure/HttpOnly.
- [ ] Stacktraces y errores verbosos.
- [ ] CVEs `potential` segun version/superficie.

Comprobar manualmente:

- [ ] Si Manager permite login real o solo muestra realm.
- [ ] Si credenciales default han sido probadas con autorizacion.
- [ ] Si `text/deploy` o `jmxproxy` son alcanzables tras autenticacion.
- [ ] Si ficheros XML contienen credenciales, JNDI, JDBC URLs o secretos.
- [ ] Si WAR/JAR descargados contienen codigo, configs o dependencias sensibles.
- [ ] Si CVEs Tomcat aplican a version exacta, Java, conector y configuracion.

## 8. Java / Spring / APIs

Comprobar con Nuclei:

- [ ] Actuator root, health, env, configprops, beans, mappings, metrics,
      prometheus, loggers, scheduledtasks, sessions, auditevents, flyway,
      liquibase, quartz, caches, startup, heapdump, threaddump y logfile.
- [ ] Write surfaces potenciales: shutdown, restart, refresh, busrefresh,
      busenv, gateway refresh, gateway routes, env y config monitor.
- [ ] Spring Cloud Config Server, Eureka, Spring Boot Admin, Zipkin.
- [ ] OpenAPI/Swagger/WADL/WSDL/GraphQL UI/introspection.
- [ ] H2 console, Jolokia, Hawtio.
- [ ] Log files, env files, application properties/yaml y perfiles.
- [ ] `WEB-INF`, `META-INF`, descriptors Jakarta EE/JSF.
- [ ] JSF ViewState, PrimeFaces resources y stacktraces.
- [ ] Security headers, CORS, CSP, XFO, XCTO.

Comprobar manualmente:

- [ ] Si endpoints Actuator estan autenticados en otros context paths.
- [ ] Si `env`, `heapdump`, `logfile` o `threaddump` contienen secretos o datos
      personales.
- [ ] Si write surfaces realmente modifican estado; no asumir explotacion por
      una respuesta 400/405/415 compatible.
- [ ] Si OpenAPI/Swagger revela endpoints internos, metodos peligrosos,
      modelos sensibles o rutas admin.
- [ ] Si CORS permite credenciales con origen reflejado y endpoints con datos.
- [ ] Si errores verbosos exponen clases internas, rutas de fichero, SQL o
      lineas de codigo.
- [ ] Si hay autenticacion SSO, comprobar que no hay bypass por path alternativo
      o cabeceras de proxy.

## 9. WildFly / JBoss / Undertow

Comprobar con Nuclei:

- [ ] `/management`, consola, whoami, read-resource/read-operation.
- [ ] Datasources, mail, Elytron, TLS, Undertow HTTPS listener.
- [ ] Domain topology, deployments, server groups.
- [ ] mod_cluster management.
- [ ] Health, metrics, OpenAPI.
- [ ] Hawtio/Jolokia.
- [ ] `standalone.xml`, `domain.xml`, `host.xml`, Elytron properties,
      management users/groups, keystores/truststores.
- [ ] JBoss legacy: JMX Console, Web Console, invoker servlet.
- [ ] CVEs `potential` de JBoss/WildFly/Undertow.

Comprobar manualmente:

- [ ] Si management model permite lectura real sin autenticacion.
- [ ] Si endpoints devuelven secretos o solo estructura.
- [ ] Si domain mode expone topologia interna accionable.
- [ ] Si ficheros de usuarios/grupos o keystores son material sensible real.
- [ ] Si componentes legacy siguen desplegados o solo devuelven paginas de error.

## 10. Jetty / Quarkus / Micronaut

Comprobar con Nuclei:

- [ ] Jetty headers, errores, default pages, config files, realm properties.
- [ ] Jetty directory listing, dump servlet y test webapp.
- [ ] Quarkus `/q/health`, `/q/metrics`, `/q/openapi`, Swagger UI y Dev UI.
- [ ] Micronaut env, routes, beans, loggers, metrics, threaddump, refresh y stop.

Comprobar manualmente:

- [ ] Si endpoints Quarkus/Micronaut estan remapeados.
- [ ] Si health/metrics revelan dependencias internas.
- [ ] Si Dev UI o refresh/stop estan disponibles en entorno productivo.
- [ ] Si Jetty test/dump pertenece al servidor real o a una app de ejemplo.

## 11. Nginx

Comprobar con Nuclei:

- [ ] Autoindex/directory listing.
- [ ] Stub status.
- [ ] VTS status dashboard/API.
- [ ] Version disclosure.

Comprobar manualmente:

- [ ] Si Nginx esta delante de Apache/Tomcat/WildFly y oculta rutas internas.
- [ ] Si `stub_status`/VTS revelan backends o trafico sensible.
- [ ] Si hay rutas admin protegidas por allowlist mal aplicada.
- [ ] Si redirects y cabeceras confian en `Host` o `X-Forwarded-*`.

## 12. Infraestructura y observabilidad

Comprobar con Nuclei:

- [ ] Kubernetes API y Dashboard.
- [ ] Docker Registry catalog.
- [ ] Consul HTTP API.
- [ ] Vault health/seal status.
- [ ] Prometheus targets/config/admin API surface.
- [ ] Alertmanager UI/API.
- [ ] Grafana public signup.
- [ ] cAdvisor y etcd metrics.
- [ ] Elasticsearch API y Kibana status/UI.
- [ ] RabbitMQ Management.
- [ ] Jenkins dashboard/API y Script Console.
- [ ] Apache Flink y Spark UI.

Comprobar manualmente:

- [ ] Si las APIs estan realmente sin autenticacion o solo devuelven login/401.
- [ ] Si hay datos de produccion: targets, pods, namespaces, repos, indices,
      queues, jobs, pipelines o dashboards.
- [ ] Si hay acciones administrativas posibles: Jenkins script, Prometheus
      admin, RabbitMQ operations, Kubernetes API, Docker Registry push/delete.
- [ ] Si endpoints de estado aparentemente inocuos revelan version, cluster,
      datacenter, nodos, rutas internas o nombres de servicio.

## 13. Severidad orientativa antes de entregar

- [ ] Critical: ejecucion remota/admin real, Jenkins Script Console accesible,
      Kubernetes API sin autenticacion con recursos accesibles, default login
      valido en panel critico.
- [ ] High: panel admin expuesto, secretos/config descargables, heapdump/logfile
      sensible, JMX/Jolokia potente, Manager Tomcat, Elasticsearch sin auth,
      RabbitMQ/Kibana/Solr/Nacos/Flink expuestos con datos.
- [ ] Medium: health/metrics/docs/API docs con detalle interno, dashboards de
      observabilidad, directory listing no sensible, version disclosure con
      correlacion util, headers/cookies relevantes.
- [ ] Low/Info: fingerprinting, banners, headers de postura sin impacto probado,
      defaults visuales sin datos ni accion.

## 14. Evidencia minima por hallazgo

- [ ] URL exacta y metodo.
- [ ] Status code.
- [ ] Template id.
- [ ] Fecha/hora y origen del scan.
- [ ] Fragmento de evidencia minimizado.
- [ ] Impacto concreto para el cliente.
- [ ] Recomendacion accionable.
- [ ] Nota de confianza: confirmado, potencial, requiere autenticacion, requiere
      validacion manual.
- [ ] Agrupacion/deduplicacion aplicada.

## 15. Remediacion que conviene sugerir

- [ ] Cerrar exposicion publica de paneles y APIs administrativas.
- [ ] Requerir autenticacion fuerte y MFA donde aplique.
- [ ] Aplicar allowlist de IP/VPN/mTLS para management.
- [ ] Deshabilitar endpoints no necesarios en produccion.
- [ ] Eliminar defaults, ejemplos, docs internas y artefactos residuales.
- [ ] Rotar secretos si se expusieron ficheros, logs, dumps o configs.
- [ ] Revisar permisos de despliegue y limpieza de backups.
- [ ] Desactivar version disclosure cuando sea viable.
- [ ] Endurecer headers/cookies/TLS segun criticidad de la app.
- [ ] Revisar configuracion de proxies y cabeceras `X-Forwarded-*`.
- [ ] Monitorizar accesos a endpoints expuestos y buscar abuso historico.

## 16. Control final antes de enviar

- [ ] El informe separa hallazgos confirmados de `potential`.
- [ ] No hay secretos completos pegados en evidencias.
- [ ] No hay doble conteo de la misma causa raiz.
- [ ] Las severidades estan justificadas por impacto y contexto.
- [ ] Los hallazgos de hardening no tapan riesgos de mayor impacto.
- [ ] Se explican limites del escaneo y zonas no cubiertas.
- [ ] Se incluyen comandos/workflows usados o metodologia reproducible.
- [ ] Se indica que Nuclei es una fuente de evidencia, no una prueba de ausencia
      de vulnerabilidades.
- [ ] Se proponen siguientes pasos manuales para lo no cubierto.
