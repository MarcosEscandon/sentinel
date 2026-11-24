# Sentinel

Motor de escaneo de malware modular para Windows, escrito en Python. Cubre la
parte central de un producto tipo Malwarebytes: **firmas SHA-256**, reglas de
nombre y contenido, **heurística** (entropía, doble extensión, imports PE),
**análisis de macros VBA** (MS-OVBA), **YARA opcional**, **cuarentena
reversible**, **historial SQLite**, **informes JSON**, **protección en tiempo
real**, **servicio de Windows**, **GUI**, **auditoría de seguridad** y
**anti-tamper** de manifiestos.

> No es un reemplazo de un antivirus comercial. La base incluida contiene un
> **IOC real e inofensivo** (EICAR), diez hashes reales de campañas públicas
> (Dark Caracal, Sofacy y Tick, curados de `Neo23x0/signature-base`) y
> marcadores sintéticos para probar el flujo completo sin manipular malware.

## Probar con un IOC real

EICAR es el fichero de prueba estándar de la industria: cualquier antivirus
debe detectarlo y es completamente inofensivo.

```powershell
sentinel scan sentinel\data\iocs\eicar.com
```

Debe aparecer `EICAR-HASH` y `EICAR-CONTENT`. El mismo indicador está en
`sentinel/data/iocs/eicar.csv`, listo para el convertidor de feeds. En
`sentinel/data/iocs/curated.csv` están los hashes reales con su campaña de
origen; ambos se pueden importar con `sentinel feeds import`.

## Instalación

```powershell
cd C:\Users\marco\Mine\sentinel
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev,signing,hardening,realtime]"  # tests, Ed25519, regex, watchdog
pip install -e ".[yara]"                           # opcional: reglas YARA
pip install -e ".[service]"                        # opcional: servicio de Windows
```

`signing` y `hardening` son obligatorios para actualizar firmas de forma segura.
Sin `regex`, las reglas de contenido funcionan pero no tienen límite de tiempo.
Sin `watchdog`, la monitorización usa el backend nativo de Windows
(`ReadDirectoryChangesW` vía `ctypes`) y, si ese tampoco está disponible,
sondeo (`polling`) sin dependencias.

## Uso rápido

```powershell
# Verificar que los detectores funcionan
sentinel selftest

# Escanear una carpeta (informe legible + guardado en JSON)
sentinel scan C:\Users\marco\Downloads --json informe.json

# Escaneo paralelo sin descomprimir contenedores
sentinel scan D:\datos --jobs 8 --no-containers

# Solo los archivos sospechosos van a cuarentena, sin preguntar
sentinel scan C:\Users\marco\Descargas --quarantine-found --yes

# Allowlist adicional (los archivos propios se excluyen solos)
sentinel scan C:\Users\marco\Downloads --allowlist allowlist.json

# Gestionar cuarentena (verify detecta manipulaciones)
sentinel quarantine list
sentinel quarantine verify
sentinel quarantine restore <id>
sentinel quarantine delete <id>

# Historial y firmas
sentinel history --limit 10
sentinel signatures info
sentinel signatures validate

# Autoevaluación de seguridad y cadena de suministro
sentinel audit                          # 10 checks; 0 OK, 2 si hay fallos
sentinel integrity build . --output docs/manifest.json
sentinel integrity verify . --manifest docs/manifest.json --public-key public.pem

# Análisis de macros (además de OFFICE-MACRO, reglas VBA-* sobre el código)
sentinel scan C:\Descargas\informe.docm
```

### Actualización firmada

```powershell
# 1. Generar claves una sola vez (la privada NO se distribuye)
sentinel keys generate --private C:\seguro\private.pem --public public.pem

# 2. Firmar el paquete de firmas publicado
sentinel signatures --signatures signatures.json sign --key C:\seguro\private.pem --output signatures.json.sig

# 3. En cada cliente: descarga, verifica firma, valida esquema y rechaza rollback
sentinel signatures update --url https://ejemplo.local/signatures.json --public-key public.pem
```

La opción `--sha256` es adicional; la firma Ed25519 y la clave pública son
obligatorias. El cliente rechaza cualquier revisión menor o igual a la
instalada. El JSON debe incluir `"revision": <entero>`.

### Contenedores, feeds y auditoría

```powershell
# ZIP/TAR/GZ/BZ2/XZ se descomprimen con límites anti-bomba (3 niveles por defecto)
# Office/OOXML (docx, xlsx, ...) y OLE2 (doc, xls, ppt, msi, msg) también se analizan
sentinel scan C:\Descargas

# Un proyecto VBA incrustado se reporta como OFFICE-MACRO (MEDIUM); el código
# descomprimido se analiza con reglas VBA-* (AutoOpen, Shell, PowerShell, etc.)
sentinel scan C:\Descargas\informe.docm

# Importar IOCs de un CSV, JSON, MISP o lista de hashes
sentinel --signatures C:\ProgramData\sentinel\signatures.json feeds import C:\feeds\proveedor.csv --source proveedor
sentinel --signatures C:\ProgramData\sentinel\signatures.json feeds import C:\feeds\misp.json --format misp --dry-run

# Registro de auditoría en JSONL (por defecto <home>/audit.jsonl)
sentinel --log-file C:\logs\sentinel.jsonl scan C:\Descargas
sentinel --no-log scan C:\Descargas
```

El importador incrementa `revision` y hace una copia `.bak` de la base
anterior. La firma Ed25519 debe regenerarse después de importar IOCs.

### Protección en tiempo real e interfaz gráfica

```powershell
# Monitor en primer plano: prioriza native (Windows), después watchdog, después polling
sentinel monitor C:\Descargas --poll-interval 2 --grace-period 0.5

# Avisos de escritorio: auto (toast si hay winotify, si no cuadro nativo), none para servicio
sentinel monitor C:\Descargas --notify auto

# Interfaz gráfica (tkinter, incluido en Python para Windows)
sentinel gui
# o: sentinel-gui
```

Los eventos `realtime.detection`, `realtime.quarantine` y `realtime.error` se
escriben en el JSONL de auditoría. La acción de un hallazgo puede ser
`quarantined`, `detected` o `error` (`clean` si no hay hallazgos). El monitor
acepta `--backend native|watchdog|polling` para forzar el mecanismo de vigilancia
(si no se especifica, se elige automáticamente). El backend nativo no SIGUE
reparse points y solo vigila directorios: los archivos sueltos se ignoran.
Las notificaciones se lanzan en un hilo daemon para no bloquear el escaneo;
`--notify none` es la opción recomendada al ejecutar como servicio.

Para instalar el servicio de Windows (requiere administrador):

```powershell
sentinel --home C:\ProgramData\sentinel service install --paths C:\Descargas --startup auto
sentinel service status
sentinel service start
sentinel service stop
sentinel service remove
```

La configuración del servicio se guarda en `<home>/service.json` y el home
elegido se persiste en `%ProgramData%\sentinel\service_home.txt` para que
`LocalSystem` pueda leerlo. El directorio vigilado **no debe estar dentro del
home**, porque la auto-exclusión lo ignoraría. Para depurar sin instalar nada:
`sentinel service run`.

Códigos de salida: `0` limpio, `1` hay hallazgos, `2` error operativo. Útil
para integrar en scripts o tareas programadas. Las opciones globales
(`--home`, `--signatures`, `--config-file`, `--log-file`, `--no-log`) se
aceptan antes o después del subcomando.

Para ajustar umbrales y exclusiones, copia `config.example.json` y pásalo con
`--config-file`.

## Estructura

```
sentinel/
├── sentinel/
│   ├── cli.py               # subcomandos y presentación
│   ├── config.py            # ScanConfig
│   ├── crypto.py            # claves Ed25519 y verificación
│   ├── feeds.py             # conversor de IOCs (CSV/JSON/MISP/hashes)
│   ├── realtime.py          # monitor native/watchdog/polling
│   ├── notify.py            # avisos toast/cuadro nativo
│   ├── audit.py             # autoevaluación de seguridad (10 checks)
│   ├── integrity.py         # manifiestos SHA-256 y firma de paquetes
│   ├── service.py           # servicio de Windows
│   ├── gui.py               # interfaz tkinter
│   ├── updates.py           # descarga verificada y atómica de firmas
│   ├── data/
│   │   ├── signatures.json
│   │   ├── signatures.json.sig   # firma Ed25519 de la base
│   │   ├── signatures.json.pub   # clave pública de distribución
│   │   ├── yara/sample.yar
│   │   └── iocs/                 # eicar.{com,csv} y curated.csv
│   ├── core/
│   │   ├── allowlist.py     # exclusiones y auto-exclusión
│   │   ├── logging.py       # auditoría JSONL
│   │   ├── models.py        # Finding, ScanResult, RuleHit, Severity
│   │   ├── quarantine.py    # cuarentena con hash + MAC
│   │   └── database.py      # historial en SQLite
│   └── engine/
│       ├── signatures.py    # validación y matching de firmas
│       ├── heuristics.py    # entropía, doble extensión, parser PE
│       ├── containers.py    # ZIP/TAR/GZ/BZ2/XZ/OOXML con límites
│       ├── ole.py           # parser CFB/OLE2 para doc/xls/ppt/msi/msg
│       ├── vba.py           # descompresión MS-OVBA y reglas VBA-*
│       ├── scanner.py       # recorrido, hashing, paralelo y orquestación
│       └── yara.py          # integración opcional con yara-python
├── packaging/               # spec de PyInstaller, build.ps1 y get-signtool.ps1
├── tools/benchmark.py       # benchmarks de archivos/s y MB/s con --jobs
├── docs/                    # THREAT_MODEL.md, PERFORMANCE.md y resultados
└── tests/
```

## Ampliar las firmas

`signatures.json` admite tres bloques:

```json
{
  "schema": 1,
  "version": "2026-11-21",
  "revision": 3,
  "hashes": {
    "<sha256>": {"id": "IOC-0001", "severity": "high", "description": "..."}
  },
  "filenames": [
    {"id": "FN-0001", "pattern": "\\.js\\.vbs$", "severity": "medium", "description": "..."}
  ],
  "content": [
    {"id": "CT-0001", "pattern": "marcador", "severity": "low", "description": "...", "max_size": 1048576}
  ]
}
```

Los patrones de `filenames` y `content` son expresiones regulares sobre bytes y
se compilan con `IGNORECASE`. `max_size` evita evaluar archivos grandes. Con
`hardening` instalado, cada regla tiene un límite de 100 ms; una regla que lo
supere se omite y se reporta como `RULE-TIMEOUT`.

## Puntos de extensión

* **Nuevos detectores**: añade un módulo en `engine/` que devuelva `RuleHit` y
  llámalo desde `Scanner._detect`.
* **Otras fuentes de IOC**: añade un parser en `feeds.py` y regístralo en
  `PARSERS`. Copia `allowlist.example.json` para excluir binaries conocidos
  como buenos.
* **Interfaz gráfica**: `sentinel gui` usa `SentinelGUI`; también es integrable
  desde código con `SentinelGUI(headless=True)` para usar `scan_path()`,
  `format_summary()` y `refresh_quarantine()` sin ventana.
* **Protección en tiempo real**: `RealtimeMonitor` expone `process_path()` y
  `on_finding`; el servicio de Windows reutiliza esa misma implementación.
  Antes de desplegarlo, prueba bien las exclusiones en un entorno aislado.

## Seguridad y límites

* La heurística **prioriza**, no condena: un `HEUR-*` debe revisarse antes de
  borrar nada. Las firmas exactas son la única señal determinista.
* `--quarantine-found` mueve archivos; la ruta original queda registrada y se
  puede restaurar con `sentinel quarantine restore <id>`.
* No se analizan reparse points/junctions por defecto para evitar bucles.
* Tamaño máximo por archivo: 128 MiB (configurable con `--max-size`).
* La cuarentena guarda el SHA-256 real y un HMAC del índice con una clave fuera
  del directorio de cuarentena; `restore` rechaza entradas manipuladas.
* Para producción: usa actualizaciones firmadas con `--public-key`, firma también
  el paquete de IOCs importados, ejecuta con un usuario sin privilegios y revisa
  la allowlist antes de desplegar.
* La firma Authenticode del ejecutable (ver `packaging/README.md`) **no**
  sustituye a la verificación Ed25519 de las firmas.
* La base incluye EICAR y diez hashes reales de fuentes públicas; no es una
  base de firmas comercial. Amplía con fuentes fiables y firma cada revisión.
* El análisis de Office/MSI extrae streams, detecta proyectos VBA y descomprime
  el código MS-OVBA para aplicar reglas `VBA-*`. No evalúa código ni desofusca
  estrategias arbitrarias: los hallazgos son señales de revisión.
* Todavía queda fuera de alcance el filtro de sistema de archivos a nivel de
  kernel: el monitor actual es de usuario y puede perder eventos si el buffer
  de 64 KiB se desborda (se registra `realtime.error`).

## Auditoría, anti-tamper y rendimiento

`sentinel audit` ejecuta 10 comprobaciones reales (firma y rollback de bases,
integridad de cuarentena, logging, allowlist, backend de tiempo real, límites de
configuración, ubicación de `home` e IOCs mínimos). Devuelve `0` si todo pasa y
`2` si hay fallos; con la base incluida, firmada y con su clave pública, el
resultado es **100/100**. El detalle y las remediations están en
`docs/THREAT_MODEL.md`.

`sentinel integrity build/verify` genera y comprueba un manifiesto SHA-256.
`verify` distingue `missing`, `modified` y `added`, y con `--public-key`
valida también la firma Ed25519 del manifiesto. El análisis estático con
`python -m bandit -r sentinel -x tests` terminó con **0 avisos** (6026 líneas
analizadas; detalle en `docs/bandit-results.json`) y el análisis de
dependencias con `pip-audit` sobre los extras declarados encontró **0
vulnerabilidades** en 24 paquetes (`docs/pip-audit-results.json`). El build de PyInstaller genera
y empaqueta `manifest.json` (y su firma si se define `SENTINEL_PRIVATE_KEY`)
dentro de `sentinel/data`; se puede verificar con:

```powershell
sentinel integrity verify _internal\sentinel\data --manifest _internal\sentinel\data\manifest.json --public-key _internal\sentinel\data\signatures.json.pub
```

Rendimiento medido en este equipo (Python 3.10.11, Windows 10, 2000 archivos,
63 MiB, `python tools/benchmark.py --files 2000`):

| `--jobs` | Tiempo (s) | MB/s | Archivos/s |
| -------: | ---------: | ---: | ---------: |
|        1 |      2,386 | 26,4 |        838 |
|        2 |      2,243 | 28,1 |        892 |
|        4 |      2,204 | 28,6 |        908 |
|        8 |      2,215 | 28,5 |        903 |

El óptimo medido es **4 hilos**; a 8 hilos el GIL anula la ganancia. Los 1948
hallazgos son falsos positivos de heurística sobre datos aleatorios, no malware;
el paralelismo no cambia el resultado. Datos completos en
`docs/PERFORMANCE.md` y `docs/benchmark-results.json`.

## Estado de producción

Es un **prototipo funcional, empaquetado y validado localmente**, no un producto
production-ready completo. Quedan fuera de alcance o requieren infraestructura
externa:

* Filtro de sistema de archivos a nivel kernel: el monitor es de modo usuario y
  puede perder eventos si se desborda el buffer de 64 KiB.
* Auditoría externa independiente: `sentinel audit` es una autoevaluación.
* Certificado Authenticode EV/OV: aquí solo se usó un certificado autofirmado
  para validar el proceso. Confiándolo temporalmente solo al usuario se consiguió
  `signtool verify /pa` con 0 errores; se retiró inmediatamente después. Sin esa
  confianza el estado es `UnknownError` y SmartScreen requiere reputación. En
  este equipo, además, **Device Guard bloqueó el exe recién compilado** por no
  provenir de una CA de confianza; el build y su smoke test interno pasaron, pero
  la validación final se hizo con la CLI de Python. Un certificado EV/OV real
  debería resolver este bloqueo.
* Instalación del servicio de Windows: necesita administrador (abre UAC). Se
  validó `service run` en primer plano y, ya corregidos el home persistido y el
  `StopEvent` de pywin32 312, que el servicio instalado llega a `Running`.
* Base de firmas: EICAR, 10 hashes públicos y marcadores sintéticos; no sustituye
  a una base comercial actualizada.

## Compilación (Windows x64)

```powershell
pip install -e ".[packaging]"
.\packaging\get-signtool.ps1          # opcional: signtool portable, sin admin
.\packaging\build.ps1 -Console        # dist\sentinel.exe
.\packaging\build.ps1 -Sign           # firma con signtool + timestamp
```

Con `SENTINEL_PRIVATE_KEY=<ruta.pem>` el build también firma el manifiesto de
datos con Ed25519. Consulta `packaging/README.md` para certificados, opciones
onedir/onefile y smoke tests. Herramientas de diagnóstico: `python -m pytest`,
`python -m ruff check .`, `python -m bandit -r sentinel -x tests`,
`sentinel selftest`, `sentinel audit` y `python tools/benchmark.py`.
