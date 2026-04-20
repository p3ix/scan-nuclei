# Plantillas Nuclei (Java / Tomcat / Apache)

## Criterio de clasificación

| Directorio | Cuándo usarlo |
|------------|----------------|
| `cves/` | Comprobaciones ligadas a un **CVE** concreto (matchers alineados al advisory; evitar basarse solo en banner). |
| `vulnerabilities/` | Clases de fallo o cadenas de explotación **sin un CVE único** (lógica de app, patrones genéricos). |
| `misconfiguration/` | Configuración **insegura pero “válida”**: interfaces admin expuestas, verbos/módulos peligrosos, headers de debug, etc. |
| `exposures/` | **Filtración o superficie sensible** vía HTTP: rutas (`/WEB-INF/`, backups), páginas de error ruidosas, probes de debug. |
| `technologies/` | **Huella** (`severity: info`): detección de stack sin afirmar explotabilidad. |
| `default-logins/` | Formularios o basic auth con **credenciales por defecto** conocidas. |
| `workflows/` | Flujos **multi-request** (p. ej. fingerprint → chequeo acotado). |
| `file/` | Plantillas `protocol: file` para artefactos en disco (CI, imágenes). |
| `helpers/` | Payloads o datos reutilizables entre plantillas (si aplica). |

## Nombres de fichero

- CVEs: `CVE-YYYY-NNNNN-<producto>-<slug-corto>.yaml`.
- Resto: `<producto>-<hallazgo>-<opcional-contexto>.yaml` en minúsculas y guiones.

## Uso

```bash
nuclei -t templates/ -u https://objetivo
```

Las carpetas vacías usan `.gitkeep` para mantener el árbol en Git.
