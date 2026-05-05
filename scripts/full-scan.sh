#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Uso:
  scripts/full-scan.sh --target https://objetivo

Ejecuta el barrido completo recomendado:
  - valida templates
  - usa todos los templates HTTP bajo templates/
  - agrega salida por host+template para reducir ruido

Opciones:
  -t, --target URL       URL objetivo.
  -rl, --rate-limit N   Limite de peticiones por segundo para nuclei.
      --raw-output      No agrupa resultados; imprime salida nuclei normal.
      --skip-validate   Omite validacion previa.
  -h, --help            Muestra esta ayuda.
  --                    Fin de opciones; el resto se pasa a nuclei.

Ejemplos:
  scripts/full-scan.sh --target https://objetivo
  scripts/full-scan.sh --target https://objetivo --rate-limit 5
  scripts/full-scan.sh --target https://objetivo -- --follow-redirects -c 10 -timeout 15s
EOF
}

TARGET=""
RATE_LIMIT=""
RAW_OUTPUT=0
SKIP_VALIDATE=0
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --)
      shift
      EXTRA=("$@")
      break
      ;;
    -t|--target)
      TARGET="${2:-}"
      shift 2
      ;;
    -rl|--rate-limit)
      RATE_LIMIT="${2:-}"
      shift 2
      ;;
    --raw-output)
      RAW_OUTPUT=1
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

CMD=("${ROOT_DIR}/scripts/check-nuclei.sh" --target "$TARGET")

if [[ "$SKIP_VALIDATE" -eq 1 ]]; then
  CMD+=(--skip-validate)
fi

if [[ -n "$RATE_LIMIT" ]]; then
  CMD+=(--rate-limit "$RATE_LIMIT")
fi

if [[ "$RAW_OUTPUT" -eq 0 ]]; then
  CMD+=(--aggregate-output)
fi

if [[ "${#EXTRA[@]}" -gt 0 ]]; then
  CMD+=(-- "${EXTRA[@]}")
fi

echo "[INF] Full scan: todos los templates bajo templates/"
"${CMD[@]}"
