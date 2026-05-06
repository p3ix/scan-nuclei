# scan-nuclei

Plantillas Nuclei enfocadas en auditorias HTTP de aplicaciones y plataformas Java: Apache HTTPD, Tomcat, WildFly/JBoss, Spring, Quarkus, Micronaut, Jetty y superficies habituales de infraestructura expuesta.

Este repo esta pensado para uso directo con Nuclei:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/
```

## Instalacion rapida

### 1. Instalar dependencias basicas

Necesitas `git` para descargar el repositorio y `nuclei` para ejecutar las plantillas.

En Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y git curl unzip
```

En macOS con Homebrew:

```bash
brew install git
```

En Windows, instala Git desde <https://git-scm.com/download/win> y ejecuta los comandos desde PowerShell o Git Bash.

### 2. Instalar Nuclei

Opcion recomendada en Linux/macOS si tienes Go instalado:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Asegurate de tener el binario de Go en el `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Comprueba la instalacion:

```bash
nuclei -version
```

Alternativa manual:

1. Descarga la version para tu sistema desde <https://github.com/projectdiscovery/nuclei/releases>.
2. Descomprime el fichero.
3. Copia el binario `nuclei` a una carpeta incluida en el `PATH`, por ejemplo `/usr/local/bin` en Linux.

### 3. Descargar este repositorio

```bash
git clone https://github.com/p3ix/scan-nuclei.git
cd scan-nuclei
```

Si ya tienes el repo descargado:

```bash
cd scan-nuclei
git pull
```

### 4. Validar que todo funciona

Valida la sintaxis de las plantillas:

```bash
nuclei -validate -t ./templates
```

Si ves `All templates validated successfully`, el entorno esta listo.

### 5. Ejecutar el primer escaneo

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/
```

Para escanear otro objetivo, cambia la URL:

```bash
nuclei -t ./templates -u https://objetivo
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

Guardar resultados en fichero:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/ -o resultados.txt
```

Guardar resultados en JSONL para procesarlos despues:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/ -jsonl -o resultados.jsonl
```

Actualizar Nuclei cuando quieras tener la ultima version del motor:

```bash
nuclei -update
```

## Criterio rapido de lectura

- `critical` / `high`: revisar y corregir primero; normalmente implican exposicion sensible, acceso no autenticado o riesgo explotable.
- `medium`: superficie util para ataque o fuga operativa que conviene cerrar.
- `low`: hardening o postura defensiva.
- `info`: fingerprinting; sirve para priorizar, no es por si solo una vulnerabilidad.

Los templates con sufijo `-potential` indican una condicion compatible con una vulnerabilidad o mala configuracion, pero requieren validacion manual antes de reportarlos como confirmados.
