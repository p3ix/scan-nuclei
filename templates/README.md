# Templates

Arbol de plantillas listo para ejecutar directamente con Nuclei:

```bash
nuclei -t ./templates -u https://objetivo
```

Actualmente contiene 393 plantillas organizadas por tipo de hallazgo y tecnologia.

## Carpetas Principales

| Carpeta | Plantillas | Proposito |
| --- | ---: | --- |
| `cves/` | 21 | CVEs concretos y checks no intrusivos de exposicion potencial |
| `default-logins/` | 2 | Credenciales por defecto |
| `exposures/` | 121 | Ficheros, endpoints, dumps, logs, APIs y artefactos sensibles expuestos |
| `misconfiguration/` | 184 | Consolas, administracion expuesta, hardening, proxies y configuracion insegura |
| `technologies/` | 29 | Fingerprinting y version disclosure |
| `vulnerabilities/` | 36 | Riesgos sin CVE unica o genericos de frameworks |

## Subfamilias Destacadas

| Ruta | Enfoque |
| --- | --- |
| `misconfiguration/apache/` | Apache HTTPD, proxying, WebDAV, ModSecurity, logs, status/info y hardening |
| `misconfiguration/tomcat/` | Tomcat Manager, Host Manager, JMXProxy, diagnostico, sesiones y WebDAV |
| `misconfiguration/wildfly/` | WildFly/JBoss management, datasources, Elytron, remoting, Infinispan, Undertow y dominio |
| `misconfiguration/java-apps/` | Spring, Dubbo, Camunda, Flowable, Vaadin, XXL-JOB, Apollo, Druid, Nacos, Solr, Spark, Flink y mas |
| `exposures/sensitive-paths/` | Configs Java/Spring/Tomcat/WildFly, keystores, logs, WAR/JAR, `WEB-INF`, JMX y artefactos runtime |
| `exposures/apis/` | GraphQL introspection y UI |
| `exposures/debug-probes/` | Heapdump, threaddump y logfile |

La matriz completa de cobertura vive en [`../COVERAGE-MATRIX.md`](../COVERAGE-MATRIX.md).

## Nomenclatura

- `*-exposed`: evidencia observable de exposicion.
- `*-unauth`: acceso sin autenticacion efectiva.
- `*-potential`: indicio compatible con riesgo o CVE; requiere validacion manual.
- `*-fingerprint`: contexto tecnologico para priorizar hallazgos.
- `*-default-credentials`: prueba de credenciales por defecto o debiles conocidas.

## Validacion

```bash
nuclei -validate -t ./templates
```

Si la salida incluye `All templates validated successfully`, el arbol esta listo para uso.
