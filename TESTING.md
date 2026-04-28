# Testing Guide

Guia corta para entender y ampliar los checks de calidad del repositorio.

## Capas actuales

El repo tiene tres capas de verificacion:

1. `nuclei -validate -t templates/`
   - valida sintaxis y estructura de templates

2. `scripts/check-repo.sh`
   - valida consistencia interna del repo
   - revisa `id` duplicados, severidades, nombres y referencias de workflows

3. `python3 scripts/run-http-regression.py`
   - ejecuta regresion minima de comportamiento contra fixtures HTTP locales
   - comprueba matches esperados y no esperados
   - soporta tambien fixtures binarios via `body_base64` para cubrir casos como
     `keystore/truststore`

## Que cubre hoy la regresion HTTP

La suite actual cubre escenarios pequenos y controlados para:

- `Quarkus`
- `Micronaut`
- `Apache`
- `Tomcat`
- `WildFly`
- `Spring`

La meta no es simular servidores completos, sino dar una red minima que detecte:

- regresiones obvias de fingerprint
- plantillas que dejan de hacer match en casos esperados
- plantillas que empiezan a hacer match en casos negativos sencillos
- cambios en workflows que rompen encadenados basicos

## Como ejecutar

```bash
# sintaxis de templates
nuclei -validate -t templates/

# consistencia del repo
scripts/check-repo.sh

# regresion minima de comportamiento
python3 scripts/run-http-regression.py
```

Nota:

- `scripts/run-http-regression.py` levanta un servidor HTTP local temporal en
  `127.0.0.1`
- en entornos muy restringidos puede requerir permiso para abrir ese puerto local

## Donde vive cada pieza

- fixtures HTTP: [tests/fixtures/http-regression-fixtures.json](/home/asier/scan-nuclei/tests/fixtures/http-regression-fixtures.json)
- runner: [scripts/run-http-regression.py](/home/asier/scan-nuclei/scripts/run-http-regression.py)
- chequeo estructural: [scripts/check-repo.sh](/home/asier/scan-nuclei/scripts/check-repo.sh)
- CI: [.github/workflows/nuclei-validate.yml](/home/asier/scan-nuclei/.github/workflows/nuclei-validate.yml)

## Como anadir un caso nuevo

1. crear o ampliar un escenario en `tests/fixtures/http-regression-fixtures.json`
2. añadir un `Case(...)` en `scripts/run-http-regression.py`
3. definir:
   - `family`
   - `scenario`
   - `scan_mode`: `template` o `workflow`
   - `target`
   - `expected`
   - `unexpected`
4. ejecutar `python3 scripts/run-http-regression.py`
5. si el caso representa ruido conocido, anotar el matiz en `KNOWN-FP.md`

## Criterios para elegir nuevos casos

Priorizar:

- fingerprints importantes y estables
- hallazgos accionables de alto valor
- workflows que encadenan varias plantillas
- falsos positivos conocidos o limites de deteccion importantes

Evitar al principio:

- fixtures demasiado grandes o realistas
- depender de detalles fragiles del servidor de pruebas
- convertir la suite en una copia completa del comportamiento real del producto

## Limitaciones actuales

- no todos los fingerprints basados en orden exacto de headers son faciles de
  reproducir con un servidor HTTP minimo
- algunos workflows profundos pueden disparar hallazgos adicionales validos; por
  eso las expectativas deben centrarse en ids clave, no en listar todo el ruido
- la suite actual busca estabilidad y cobertura minima, no exhaustividad
- algunos clientes pueden cerrar conexiones antes de consumir toda la respuesta;
  el runner ya trata esos cierres tempranos como benignos

## Recomendacion practica

Cuando añadas una plantilla nueva:

1. valida sintaxis
2. pasa `scripts/check-repo.sh`
3. si la plantilla toca una familia ya cubierta, intenta añadir al menos un caso
   positivo o negativo al runner
4. documenta matices de triage o falsos positivos si aparecen
