#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "[ERR] No se encontro el comando requerido: $bin" >&2
    exit 1
  fi
}

require_bin python3

python3 - "$ROOT_DIR" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
TEMPLATES_DIR = ROOT / "templates"
ALLOWED_TOP_LEVEL = {
    "cves",
    "default-logins",
    "exposures",
    "misconfiguration",
    "technologies",
    "vulnerabilities",
    "workflows",
}
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
LOWERCASE_STEM_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
CVE_STEM_RE = re.compile(r"^CVE-\d{4}-\d{4,}-[a-z0-9][a-z0-9-]*$")
ID_RE = re.compile(r"^id:\s*([^\s#]+)\s*$")
SEVERITY_RE = re.compile(r"^\s{2}severity:\s*([^\s#]+)\s*$")
AUTHOR_RE = re.compile(r"^\s{2}author:\s*(.+?)\s*$")
TEMPLATE_REF_RE = re.compile(r"^\s*-\s*template:\s*(templates/[^\s#]+)\s*$")

errors = []
warnings = []
id_to_files = {}
yaml_files = sorted(TEMPLATES_DIR.rglob("*.yaml"))

if not yaml_files:
    errors.append("No se encontraron templates .yaml bajo templates/")

for path in yaml_files:
    rel = path.relative_to(ROOT)
    parts = rel.parts
    if len(parts) < 3:
        errors.append(f"{rel}: ruta demasiado corta; se espera templates/<familia>/...")
        continue

    top_level = parts[1]
    if top_level not in ALLOWED_TOP_LEVEL:
        errors.append(
            f"{rel}: categoria superior no reconocida '{top_level}'"
        )

    stem = path.stem
    if stem.startswith("CVE-"):
        if not CVE_STEM_RE.fullmatch(stem):
            errors.append(
                f"{rel}: nombre CVE fuera de convencion (esperado CVE-YYYY-NNNN[-N]-slug)"
            )
    elif not LOWERCASE_STEM_RE.fullmatch(stem):
        errors.append(
            f"{rel}: nombre de archivo fuera de convencion; usar minusculas, digitos y guiones"
        )

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        errors.append(f"{rel}: no se pudo leer como UTF-8")
        continue

    template_id = None
    severity = None
    author = None
    template_refs = []

    for line in lines:
        if template_id is None:
            match = ID_RE.match(line)
            if match:
                template_id = match.group(1).strip()
                continue

        if severity is None:
            match = SEVERITY_RE.match(line)
            if match:
                severity = match.group(1).strip().strip("'\"")
                continue

        if author is None:
            match = AUTHOR_RE.match(line)
            if match:
                author = match.group(1).strip().strip("'\"")
                continue

        match = TEMPLATE_REF_RE.match(line)
        if match:
            template_refs.append(match.group(1).strip())

    if not template_id:
        errors.append(f"{rel}: falta campo top-level 'id'")
    else:
        id_to_files.setdefault(template_id, []).append(rel)
        if template_id != stem:
            errors.append(
                f"{rel}: id '{template_id}' no coincide con el nombre de archivo '{stem}'"
            )

    if top_level == "workflows":
        if severity is not None:
            warnings.append(
                f"{rel}: workflow con severity declarada; revisar si es intencional"
            )
    else:
        if severity is None:
            errors.append(f"{rel}: falta info.severity")
        elif severity not in ALLOWED_SEVERITIES:
            errors.append(
                f"{rel}: severity '{severity}' no permitida; usar una de {sorted(ALLOWED_SEVERITIES)}"
            )

    if not author:
        errors.append(f"{rel}: falta info.author")

    for ref in template_refs:
        target = ROOT / ref
        if not target.is_file():
            errors.append(f"{rel}: referencia rota a template '{ref}'")

for template_id, files in sorted(id_to_files.items()):
    if len(files) > 1:
        joined = ", ".join(str(f) for f in files)
        errors.append(f"id duplicado '{template_id}' en: {joined}")

print(f"[INF] Templates revisados: {len(yaml_files)}")
print(f"[INF] Workflows/referencias revisadas: {sum(1 for p in yaml_files if 'workflows' in p.parts)}")

if warnings:
    print(f"[WAR] Advertencias: {len(warnings)}")
    for warning in warnings:
        print(f"[WAR] {warning}")

if errors:
    print(f"[ERR] Problemas detectados: {len(errors)}")
    for error in errors:
        print(f"[ERR] {error}")
    raise SystemExit(1)

print("[OK] Chequeo estructural completado sin errores.")
PY
