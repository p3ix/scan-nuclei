# scan-nuclei

Plantillas Nuclei enfocadas en auditorias HTTP de aplicaciones y plataformas Java: Apache HTTPD, Tomcat, WildFly/JBoss, Spring, Quarkus, Micronaut, Jetty y superficies habituales de infraestructura expuesta.

Este repo esta pensado para uso directo con Nuclei:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/
```

Validacion opcional de sintaxis:

```bash
nuclei -validate -t ./templates
```

## Estructura

- `templates/cves/`: detecciones asociadas a CVEs concretos.
- `templates/vulnerabilities/`: vulnerabilidades o exposiciones explotables sin CVE unico.
- `templates/misconfiguration/`: configuraciones inseguras, consolas y endpoints administrativos expuestos.
- `templates/exposures/`: ficheros sensibles, endpoints de diagnostico, OpenAPI/WSDL/Swagger, sourcemaps y artefactos publicados.
- `templates/technologies/`: fingerprinting y version disclosure.
- `templates/default-logins/`: comprobaciones de credenciales por defecto.

## Uso recomendado

Para tu caso, ejecuta todo el arbol:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/
```

Si el objetivo usa un certificado interno o autofirmado y Nuclei falla por TLS, usa:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/ -tls-sni 192.168.0.18
```

Si quieres reducir ruido en una primera pasada, puedes filtrar por severidad:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/ -severity critical,high,medium
```

## Criterio rapido de lectura

- `critical` / `high`: revisar y corregir primero; normalmente implican exposicion sensible, acceso no autenticado o riesgo explotable.
- `medium`: superficie util para ataque o fuga operativa que conviene cerrar.
- `low`: hardening o postura defensiva.
- `info`: fingerprinting; sirve para priorizar, no es por si solo una vulnerabilidad.

Los templates con sufijo `-potential` indican una condicion compatible con una vulnerabilidad o mala configuracion, pero requieren validacion manual antes de reportarlos como confirmados.
