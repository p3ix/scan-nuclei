# scan-nuclei

Plantillas Nuclei enfocadas en auditorias HTTP de aplicaciones y plataformas Java: Apache HTTPD, Tomcat, WildFly/JBoss, Spring, Quarkus, Micronaut, Jetty, herramientas DevOps/IAM y superficies habituales de infraestructura expuesta.

Este repo esta pensado para uso directo con Nuclei:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/
```

## Instalacion en Linux

### 1. Instalar dependencias basicas

En Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y git curl unzip
```

### 2. Instalar Go

Comprueba primero si Go ya esta instalado:

```bash
go version
```

Si el comando no existe, instala Go. Opcion sencilla desde paquetes del sistema:

```bash
sudo apt update
sudo apt install -y golang-go
```

Si necesitas la version oficial mas reciente, descargala desde <https://go.dev/dl/> y sigue la guia oficial de Linux. Despues anade Go al `PATH`:

```bash
export PATH="$PATH:/usr/local/go/bin"
```

Para dejarlo permanente en Bash:

```bash
echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

Comprueba que funciona:

```bash
go version
```

### 3. Instalar Nuclei

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Anade los binarios de Go al `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Para dejarlo permanente en Bash:

```bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc
```

Comprueba la instalacion:

```bash
nuclei -version
```

### 4. Descargar este repositorio

```bash
git clone https://github.com/p3ix/scan-nuclei.git
cd scan-nuclei
```

Si ya tienes el repo descargado:

```bash
cd scan-nuclei
git pull
```

### 5. Validar las plantillas

```bash
nuclei -validate -t ./templates
```

Si ves `All templates validated successfully`, el entorno esta listo.

### 6. Ejecutar el primer escaneo

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/
```

## Instalacion en Windows

### 1. Instalar Git

1. Descarga Git desde <https://git-scm.com/download/win>.
2. Ejecuta el instalador.
3. Cierra y vuelve a abrir PowerShell.
4. Comprueba la instalacion:

```powershell
git --version
```

### 2. Instalar Go

1. Descarga el instalador `.msi` desde <https://go.dev/dl/>.
2. Ejecuta el instalador y deja las opciones por defecto.
3. Cierra y vuelve a abrir PowerShell para recargar el `PATH`.
4. Comprueba que funciona:

```powershell
go version
```

### 3. Instalar Nuclei

```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Anade la carpeta de binarios de Go al `PATH` de usuario:

```powershell
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$env:USERPROFILE\go\bin", "User")
```

Cierra y vuelve a abrir PowerShell. Comprueba la instalacion:

```powershell
nuclei -version
```

### 4. Descargar este repositorio

```powershell
git clone https://github.com/p3ix/scan-nuclei.git
cd scan-nuclei
```

Si ya tienes el repo descargado:

```powershell
cd scan-nuclei
git pull
```

### 5. Validar las plantillas

```powershell
nuclei -validate -t .\templates
```

Si ves `All templates validated successfully`, el entorno esta listo.

### 6. Ejecutar el primer escaneo

```powershell
nuclei -t .\templates -u https://192.168.0.18:8443/
```

Para escanear otro objetivo en Linux, cambia la URL:

```bash
nuclei -t ./templates -u https://objetivo
```

En Windows:

```powershell
nuclei -t .\templates -u https://objetivo
```

## Estructura

- `templates/cves/`: detecciones asociadas a CVEs concretos.
- `templates/vulnerabilities/`: vulnerabilidades o exposiciones explotables sin CVE unico.
- `templates/misconfiguration/`: configuraciones inseguras, consolas y endpoints administrativos expuestos.
- `templates/exposures/`: ficheros sensibles, endpoints de diagnostico, OpenAPI/WSDL/Swagger, sourcemaps y artefactos publicados.
- `templates/technologies/`: fingerprinting y version disclosure.
- `templates/default-logins/`: comprobaciones de credenciales por defecto.

Subfamilias utiles para empresa:

- `templates/misconfiguration/devops/`: GitLab, Nexus, Artifactory, SonarQube, Argo CD y Harbor.
- `templates/misconfiguration/iam/`: Keycloak y otras superficies de identidad.

## Uso recomendado

Para tu caso, ejecuta todo el arbol.

Linux:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/
```

Windows:

```powershell
nuclei -t .\templates -u https://192.168.0.18:8443/
```

Si el objetivo usa un certificado interno o autofirmado y Nuclei falla por TLS, usa:

Linux:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/ -tls-sni 192.168.0.18
```

Windows:

```powershell
nuclei -t .\templates -u https://192.168.0.18:8443/ -tls-sni 192.168.0.18
```

Si quieres reducir ruido en una primera pasada, puedes filtrar por severidad:

Linux:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/ -severity critical,high,medium
```

Windows:

```powershell
nuclei -t .\templates -u https://192.168.0.18:8443/ -severity critical,high,medium
```

Guardar resultados en fichero:

Linux:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/ -o resultados.txt
```

Windows:

```powershell
nuclei -t .\templates -u https://192.168.0.18:8443/ -o resultados.txt
```

Guardar resultados en JSONL para procesarlos despues:

Linux:

```bash
nuclei -t ./templates -u https://192.168.0.18:8443/ -jsonl -o resultados.jsonl
```

Windows:

```powershell
nuclei -t .\templates -u https://192.168.0.18:8443/ -jsonl -o resultados.jsonl
```

Actualizar Nuclei cuando quieras tener la ultima version del motor:

Linux y Windows:

```bash
nuclei -update
```

## Criterio rapido de lectura

- `critical` / `high`: revisar y corregir primero; normalmente implican exposicion sensible, acceso no autenticado o riesgo explotable.
- `medium`: superficie util para ataque o fuga operativa que conviene cerrar.
- `low`: hardening o postura defensiva.
- `info`: fingerprinting; sirve para priorizar, no es por si solo una vulnerabilidad.

Los templates con sufijo `-potential` indican una condicion compatible con una vulnerabilidad o mala configuracion, pero requieren validacion manual antes de reportarlos como confirmados.
