# Matriz de cobertura

Este documento resume que contemplan las plantillas del repositorio cuando se ejecutan con:

```bash
nuclei -t ./templates -u https://objetivo
```

El objetivo de la matriz es explicar el alcance de seguridad de forma practica: que tecnologia o superficie se revisa, que tipo de riesgo se busca y por que le importa a la empresa.

## Resumen ejecutivo

| Area | Que contempla | Riesgo principal | Prioridad habitual |
| --- | --- | --- | --- |
| CVEs conocidas | Apache HTTPD, Java/JBoss/WildFly/Spring/Struts, Tomcat | Versiones o superficies compatibles con vulnerabilidades publicas | Alta, validar manualmente los `*-potential` |
| Credenciales por defecto | Tomcat Manager y Apache Tomcat | Acceso administrativo por credenciales debiles o por defecto | Critica/alta |
| Ficheros sensibles | `.git`, configs Java/Spring/Tomcat/WildFly, keystores, logs, backups, WAR/JAR | Fuga de secretos, rutas internas, credenciales, configuracion y artefactos | Alta |
| APIs y documentacion | GraphQL, OpenAPI, Swagger, WADL, WSDL/XSD | Enumeracion de endpoints, modelos de datos y operaciones internas | Media/alta |
| Diagnostico y debug | Heapdump, threaddump, logfile, Actuator, Jolokia, env, loggers | Exposicion de memoria, variables, tokens, trazas y operacion interna | Alta |
| Consolas administrativas | Jenkins, Kubernetes, Docker Registry, Consul, Vault, RabbitMQ, ActiveMQ, Solr, Nacos, Druid, Flink, Spark, Hawtio, Karaf/Felix, Camunda, Flowable, GlassFish/Payara, WebLogic, WebSphere | Superficie de administracion expuesta o sin autenticacion | Alta |
| DevOps y supply chain | GitLab, Nexus, Artifactory, SonarQube, Argo CD, Harbor | Fuga de codigo, artefactos, imagenes, pipelines y despliegues | Media/alta |
| IAM | Keycloak | Superficie de identidad expuesta, riesgo de ataques a SSO/admin | Media/alta |
| Servidores web/proxy | Apache HTTPD, Nginx, Tomcat, Jetty, WildFly/Undertow | Headers debiles, directory listing, WebDAV, TRACE, proxy exposure, status/admin pages | Media/alta |
| Frameworks Java | Spring Boot, Quarkus, Micronaut, JSF/Jakarta Faces, Struts, Axis2, CXF, Vaadin | Actuators, endpoints de gestion, stacktraces, CORS, cookies, dev/debug, listados de servicios | Media/alta |
| Observabilidad | Prometheus, Alertmanager, Grafana signup, cAdvisor, etcd, Zipkin | Fuga de metricas, targets internos, topologia y datos operativos | Media/alta |
| Fingerprinting | Apache, Tomcat, WildFly, Jetty, Spring, Quarkus, Micronaut, Java Web | Identificacion de tecnologia y version para priorizar hallazgos | Informativa |

## Matriz detallada por carpeta

| Ruta | Plantillas | Contempla | Ejemplos de deteccion | Valor para la empresa |
| --- | ---: | --- | --- | --- |
| `templates/cves/apache/` | 4 | CVEs de Apache HTTPD y mod_proxy | Path traversal/RCE CVE-2021-41773/42013, SSRF CVE-2021-40438, request smuggling CVE-2023-25690 | Prioriza servidores Apache con exposicion compatible con CVEs conocidas |
| `templates/cves/java/` | 13 | CVEs en ecosistema Java/JBoss/Spring/Struts/Undertow/Jolokia | Log4Shell, Spring4Shell, Struts RCE, JBoss invoker, H2 console, RESTEasy, Undertow | Ayuda a detectar deuda tecnica y stacks Java historicamente explotados |
| `templates/cves/tomcat/` | 4 | CVEs de Apache Tomcat | Ghostcat, JSP upload, CGI RCE, session deserialization | Localiza Tomcat con riesgos conocidos o superficies compatibles |
| `templates/default-logins/apache-tomcat/` | 1 | Credenciales por defecto de Tomcat | Usuario/password por defecto en paneles Tomcat | Detecta accesos administrativos triviales |
| `templates/default-logins/tomcat-manager/` | 1 | Credenciales por defecto de Tomcat Manager | Login en `/manager` | Previene compromiso directo de despliegues Java |
| `templates/exposures/` | 10 | Documentacion/API y artefactos genericos | OpenAPI JSON/YAML, Swagger UI/config/assets, WADL, WSDL/XSD, sourcemaps | Reduce fuga de contratos API, rutas internas y logica cliente |
| `templates/exposures/apis/` | 2 | GraphQL | Introspection y GraphQL UI | Evita enumeracion completa de schema, queries y mutations |
| `templates/exposures/debug-probes/` | 3 | Endpoints de diagnostico Java | Heapdump, logfile, threaddump | Puede revelar secretos en memoria, trazas, rutas y datos sensibles |
| `templates/exposures/error-pages/` | 3 | Stacktraces y errores verbosos | Tomcat, WildFly/Undertow, Jakarta Faces | Reduce informacion tecnica util para ataques dirigidos |
| `templates/exposures/sensitive-paths/` | 102 | Ficheros sensibles y rutas comunes en Java/Tomcat/WildFly/Spring | `.git/config`, `application.yml`, `server.xml`, `tomcat-users.xml`, `standalone.xml`, JMX remote, templates server-side, keystores, logs, WAR/JAR, `WEB-INF/web.xml`, `SESSIONS.ser`, JSP compilados, logs WildFly/JBoss | Es la cobertura mas fuerte contra fugas de configuracion, secretos y artefactos internos |
| `templates/misconfiguration/apache/` | 53 | Misconfiguracion Apache HTTPD y proxy | `server-status`, `server-info`, directory listing, `.ht*`, `.svn`, envvars, logs, WebDAV, manual expuesto, ModSecurity, PHP-FPM proxy, TRACE, headers, open proxy, balancer-manager, mod_cluster, jk-status, config leaks | Cubre hardening, exposicion admin/proxy, WAF y fugas de backend |
| `templates/misconfiguration/cicd/` | 2 | Jenkins | Dashboard/API y Script Console | Detecta riesgo critico en CI/CD y posible ejecucion remota si hay mala configuracion |
| `templates/misconfiguration/devops/` | 6 | Herramientas DevOps y supply chain | GitLab, Nexus, Artifactory, SonarQube, Argo CD, Harbor | Localiza superficies que pueden revelar codigo, artefactos, imagenes, pipelines y despliegues |
| `templates/misconfiguration/iam/` | 1 | Identidad y SSO | Keycloak admin console | Identifica superficie sensible de autenticacion/autorizacion |
| `templates/misconfiguration/infrastructure/` | 5 | Infraestructura expuesta | Kubernetes API, Kubernetes Dashboard, Docker Registry catalog, Consul API, Vault health | Detecta planos de control y servicios internos publicados por error |
| `templates/misconfiguration/java-apps/` | 41 | Consolas, endpoints y hardening de apps Java | Spring Actuator write surfaces, Axis2, CXF, Karaf/Felix, Camunda, Flowable, Vaadin debug, GlassFish/Payara, WebLogic, WebSphere, Druid, Nacos, Solr, Flink, Spark, Eureka, Hawtio, Jolokia, Zipkin, H2, headers | Cubre exposiciones comunes en plataformas Java empresariales |
| `templates/misconfiguration/jetty/` | 3 | Jetty | Directory listing, dump servlet, test webapp | Detecta apps de prueba/debug y listados inseguros |
| `templates/misconfiguration/messaging/` | 2 | Mensajeria | RabbitMQ Management, ActiveMQ Web Console | Identifica paneles de broker expuestos |
| `templates/misconfiguration/micronaut/` | 7 | Micronaut management | Env, threaddump, metrics, management endpoints, loggers/refresh/stop | Reduce exposicion de operacion y endpoints potencialmente peligrosos |
| `templates/misconfiguration/nginx/` | 4 | Nginx | Autoindex, stub_status, VTS, version disclosure | Cubre hardening y exposicion de estado |
| `templates/misconfiguration/observability/` | 6 | Observabilidad | Prometheus targets/admin API, Alertmanager, Grafana signup, cAdvisor, etcd metrics | Evita fuga de topologia, targets, servicios y datos operativos |
| `templates/misconfiguration/quarkus/` | 3 | Quarkus | Health, metrics, OpenAPI | Detecta endpoints operativos/documentales expuestos |
| `templates/misconfiguration/search/` | 2 | Buscadores y analitica | Elasticsearch API sin autenticacion, Kibana status | Reduce riesgo de fuga de indices, cluster info y paneles |
| `templates/misconfiguration/tomcat/` | 10 | Tomcat Manager/Host Manager | Manager HTML, script, text deploy, JMX proxy, diagnostico, sesiones, WebDAV, host-manager, restriccion localhost | Detecta superficie admin, despliegue remoto y metodos inseguros |
| `templates/misconfiguration/wildfly/` | 27 | WildFly/JBoss moderno | Consola, management model/read ops, datasources, Elytron/TLS, mail, messaging-activemq, deployment-scanner, system properties, batch-jberet, remoting, Infinispan, transactions, EE subsystem, legacy security realms, IO workers, mod_cluster, health, metrics, OpenAPI, domain topology | Muy valioso para detectar administracion WildFly expuesta o lectura no autenticada |
| `templates/technologies/apache/` | 6 | Fingerprinting Apache | Server header, default page, version disclosure, reverse proxy/fronting Tomcat/WildFly | Ayuda a entender arquitectura y priorizar checks |
| `templates/technologies/java-web/` | 6 | Fingerprinting Java Web | JSESSIONID, servlet errors, JSF/Jakarta Faces, PrimeFaces, `X-Powered-By`, framework headers | Identifica tecnologia y frameworks antes de triage |
| `templates/technologies/jetty/` | 2 | Fingerprinting Jetty | Server header y error page | Contexto tecnologico |
| `templates/technologies/micronaut/` | 1 | Fingerprinting Micronaut | Senales de Micronaut | Contexto tecnologico |
| `templates/technologies/quarkus/` | 1 | Fingerprinting Quarkus | Senales de Quarkus | Contexto tecnologico |
| `templates/technologies/spring-boot/` | 1 | Fingerprinting Spring Boot | Whitelabel/error page | Contexto tecnologico para actuators y riesgos Spring |
| `templates/technologies/tomcat/` | 5 | Fingerprinting Tomcat | Server header, default error page, Catalina signatures, manager realm, version hints | Contexto para priorizar Tomcat |
| `templates/technologies/wildfly/` | 7 | Fingerprinting WildFly/Undertow | Server header, welcome page, management realm, default pages, version hints | Contexto para priorizar WildFly/JBoss |
| `templates/vulnerabilities/generic-servlets/` | 10 | Riesgos genericos servlet/HTTP | CORS con credenciales, TRACE echo, verbose errors, directory listing, cookies JSESSIONID, HSTS/XFO/XCTO debiles | Hardening reutilizable para apps Java |
| `templates/vulnerabilities/micronaut/` | 3 | Micronaut sensible | Beans, env sensitive keys, routes | Detecta metadata sensible y rutas internas |
| `templates/vulnerabilities/spring/` | 21 | Spring/Spring Boot | Actuator beans/env/configprops/mappings/metrics/sessions/health details, CORS, CSP, cookies, trace, gateway routes | Cubre una de las superficies Java mas frecuentes en empresa |
| `templates/vulnerabilities/struts/` | 2 | Apache Struts | Devmode/debug y showcase endpoints | Detecta despliegues de ejemplo o debug peligrosos |

## Lectura por tipo de hallazgo

| Tipo | Que significa | Ejemplos | Accion recomendada |
| --- | --- | --- | --- |
| `exposed` | Hay evidencia observable de una superficie, fichero, panel o endpoint accesible | `swagger-ui-exposed`, `tomcat-users-xml-exposed`, `wildfly-console-exposed` | Revisar acceso, restringir por red/autenticacion y retirar artefactos |
| `unauth` | El endpoint parece responder sin autenticacion efectiva | `kubernetes-api-unauthenticated`, `spring-actuator-*-unauth`, `wildfly-*-management-unauth` | Tratar como prioridad alta; confirmar impacto y cerrar exposicion |
| `potential` | La condicion observada es compatible con riesgo o CVE, pero necesita validacion manual | `CVE-2022-22965-spring4shell-potential`, `apache-open-proxy-potential` | Confirmar version/configuracion antes de reportar como explotable |
| `fingerprint` | Identifica tecnologia, version, framework o producto | `tomcat-server-header-fingerprint`, `quarkus-stack-fingerprint` | Usar como contexto para priorizar y agrupar hallazgos |
| `default-login` | Prueba credenciales por defecto conocidas | Tomcat/Manager | Cambiar credenciales, revisar cuentas y auditar accesos |
| `hardening` | Postura defensiva mejorable | HSTS, cookies, CORS, X-Frame-Options, X-Content-Type-Options, TRACE | Corregir por configuracion base o middleware |

## Priorizacion sugerida

| Prioridad | Familias | Motivo |
| --- | --- | --- |
| 1 | `default-logins`, `*-management-unauth`, `script-console`, `heapdump`, `env`, ficheros con secretos | Pueden dar acceso directo, secretos o ejecucion |
| 2 | Consolas admin, CI/CD, DevOps, IAM, Kubernetes, Docker Registry, Consul, Vault, RabbitMQ | Superficies de alto impacto aunque requieran login |
| 3 | CVEs `potential`, version disclosure y fingerprints con tecnologia antigua | Requieren validacion, pero orientan remediacion |
| 4 | Documentacion API, Swagger/OpenAPI/WSDL/WADL, GraphQL introspection | Facilitan enumeracion y ataques contra API |
| 5 | Headers, cookies, CORS, TRACE, errores verbosos, directory listing | Hardening y reduccion de superficie |

## Limites de cobertura

- No sustituye un pentest manual ni una revision autenticada.
- No verifica parches internos ni configuraciones que no sean observables por HTTP.
- Los hallazgos `*-potential` deben validarse antes de tratarlos como vulnerabilidad confirmada.
- Los fingerprints `info` no son vulnerabilidades por si solos; sirven para priorizar.
- El resultado depende de rutas, proxies, autenticacion, WAF, cabeceras y configuracion del objetivo.
