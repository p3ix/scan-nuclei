# Templates

Arbol de plantillas para ejecutar directamente con Nuclei:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/
```

## Carpetas

- `cves/`: CVEs concretos.
- `vulnerabilities/`: fallos sin CVE unico.
- `misconfiguration/`: configuraciones inseguras.
- `exposures/`: endpoints, ficheros o artefactos sensibles expuestos.
- `technologies/`: fingerprinting y version disclosure.
- `default-logins/`: credenciales por defecto.

## Nomenclatura

- `*-exposed`: evidencia confirmada de exposicion.
- `*-potential`: indicio que requiere validacion manual.
- `*-fingerprint`: contexto tecnologico para priorizar hallazgos.
