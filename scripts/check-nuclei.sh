#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATES_DIR="${ROOT_DIR}/templates"

TARGET=""
UPDATE_NUCLEI=0
UPDATE_TEMPLATES=0
SKIP_VALIDATE=0

usage() {
  cat <<'EOF'
Uso:
  scripts/check-nuclei.sh --target https://objetivo

Opciones:
  -t, --target URL         URL objetivo para el scan rapido.
      --update-nuclei      Ejecuta "nuclei -update" antes de validar/scanear.
      --update-templates   Ejecuta "nuclei -update-templates" antes de validar/scanear.
      --skip-validate      Omite "nuclei -validate -t templates/".
  -h, --help               Muestra esta ayuda.

Ejemplos:
  scripts/check-nuclei.sh --target https://cliente.dgh.es:8143/vesismin-ws
  scripts/check-nuclei.sh --target https://objetivo --update-templates
  scripts/check-nuclei.sh --target https://objetivo --update-nuclei --update-templates
EOF
}

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "[ERR] No se encontro el comando requerido: $bin" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)
      TARGET="${2:-}"
      shift 2
      ;;
    --update-nuclei)
      UPDATE_NUCLEI=1
      shift
      ;;
    --update-templates)
      UPDATE_TEMPLATES=1
      shift
      ;;
    --skip-validate)
      SKIP_VALIDATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERR] Opcion no reconocida: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[ERR] Debes indicar --target." >&2
  usage
  exit 1
fi

require_bin nuclei

echo "[INF] Nuclei version actual:"
nuclei -version

if [[ "$UPDATE_NUCLEI" -eq 1 ]]; then
  echo "[INF] Actualizando binario nuclei..."
  nuclei -update
fi

if [[ "$UPDATE_TEMPLATES" -eq 1 ]]; then
  echo "[INF] Actualizando templates..."
  nuclei -update-templates
fi

if [[ "$SKIP_VALIDATE" -eq 0 ]]; then
  echo "[INF] Validando templates en ${TEMPLATES_DIR}..."
  nuclei -validate -t "${TEMPLATES_DIR}/"
else
  echo "[INF] Validacion omitida por --skip-validate"
fi

echo "[INF] Ejecutando scan rapido contra ${TARGET}..."
nuclei -t "${TEMPLATES_DIR}/" -u "${TARGET}" -nc

echo "[OK] Flujo completado."
