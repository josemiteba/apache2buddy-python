# Apache2Buddy en Kubernetes

Este proyecto es un fork de [richardforth/apache2buddy](https://github.com/richardforth/apache2buddy) (implementación original en Perl), convertido y adaptado a Python.

Este README explica cómo ejecutar apache2buddy.py en pods de Kubernetes para analizar el rendimiento de Apache.

## 📋 Requisitos Previos
- **Root access (OBLIGATORIO)**: El script debe ejecutarse como usuario root para poder inspeccionar procesos, memoria y ficheros de Apache adecuadamente.

### Ejecutar como root en Kubernetes
- Si el contenedor no permite `kubectl exec` con root, puedes usar kpexec para obtener privilegios elevados sin SSH. Instálalo según su guía y ejecuta el comando dentro del pod objetivo.
  - Proyecto: [ssup2/kpexec](https://github.com/ssup2/kpexec)
  - Ejemplos:
    ```bash
    # Abrir una shell con herramientas dentro del mismo contenedor con privilegios altos
    kpexec -it -T -n <namespace> <pod> -- bash

    # Ejecutar el script directamente con herramientas (tools mode)
    kpexec -it -T -n <namespace> <pod> -- python3 /path/apache2buddy.py --skip-os-version-check -p 8080
    ```

### Dependencias del Sistema
Apache2buddy.py requiere las siguientes herramientas del sistema:

```bash
# Herramientas básicas
- python3 (3.5+)
- procps (ps, pmap)
- net-tools (netstat) o iproute2 (ss)
- curl
- grep, awk, sed
- hostname
- findutils

# Para análisis completo
- php (opcional, para análisis de PHP)
```
## 🚀 Ejecución

```bash
# Conectar al pod
kubectl exec -it <pod-name> -- bash

# Instalar dependencias
apt-get update
apt-get install -y python3 procps net-tools curl grep hostname findutils util-linux psmisc apache2-utils

# Copiar y ejecutar script
python3 apache2buddy.py --skip-os-version-check -p 8080
```

### Opciones de ejecución recomendadas
- `-p, --port`: Puerto donde escucha Apache (ej. `-p 8080`).
- `-v, --verbose`: Salida detallada para diagnóstico.
- `-O, --skip-os-version-check`: Omite validación estricta de versión de SO (útil en contenedores).
- `--skip-maxclients`: Omite chequeo de “MaxClients/MaxRequestWorkers hits” en logs.
- `--skip-php-fatal`: Omite escaneo de errores fatales de PHP en logs.
- `--noheader --noinfo --nowarn --no-ok`: Modos silenciosos útiles para CI.

Ejemplos:
```bash
# Modo estándar en contenedor (recomendado)
python3 apache2buddy.py -p 8080 -v -O --skip-php-fatal

# Modo más rápido evitando escaneos de logs
python3 apache2buddy.py -p 8080 -O --skip-maxclients --skip-php-fatal

# Modo reporte (silencioso)
python3 apache2buddy.py --report -p 8080 -O
```