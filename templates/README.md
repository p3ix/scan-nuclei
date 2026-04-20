# Templates internals

Este README documenta el arbol interno de `templates/`.
La documentacion principal para GitHub esta en el `README.md` de la raiz.

## Uso rapido

```bash
nuclei -validate -t templates/
nuclei -t templates/ -u https://objetivo
```

## Clasificacion

- `cves/`: detecciones ligadas a CVEs concretos.
- `vulnerabilities/`: fallos sin CVE unico.
- `misconfiguration/`: configuraciones inseguras.
- `exposures/`: endpoints o archivos sensibles expuestos.
- `technologies/`: fingerprinting (`severity: info`).
- `default-logins/`: credenciales por defecto.
- `workflows/`: encadenado de templates.

Las carpetas vacias mantienen `.gitkeep`.
