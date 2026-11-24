# Empaquetado de Sentinel (Windows 10/11 x64)

Este directorio contiene la receta de compilación de Sentinel como ejecutable
de Windows. No modifica el código fuente: el spec genera en `build/` un launcher
y un *runtime hook* (ambos archivos de texto) que replican el entry point
`sentinel.cli:main` y corrigen la salida estándar en modo sin consola.

Archivos:

* `sentinel.spec` — especificación de PyInstaller >= 6.
* `build.ps1` — script de compilación, verificación y firma opcional.
* `get-signtool.ps1` — descarga un `signtool.exe` portable desde NuGet.

## Requisitos

* Windows 10 u 11 de 64 bits.
* Python 3.10 o superior de 64 bits (el mismo entorno donde se instaló el
  proyecto).
* PyInstaller >= 6. `build.ps1` lo instala con `pip` si no está disponible.
* Solo para `-Sign`: `signtool.exe` (del Windows SDK o descargado con
  `.\packaging\get-signtool.ps1`) y un certificado de firma de código **EV u OV**
  instalado en el almacén `CurrentUser\My` de Windows (en token/HSM para EV).
  `get-signtool.ps1` no necesita administrador: extrae el binario del paquete
  NuGet oficial en `packaging\tools\signtool.exe`.

## 1. Instalar dependencias

Desde la raíz del proyecto (`C:\Users\marco\Mine\sentinel`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev,signing,hardening,service,realtime]"
```

`dev`, `signing` y `hardening` cubren pruebas, Ed25519 y `regex` con límite de
tiempo. `service` y `realtime` añaden la gestión del servicio de Windows y
`watchdog`; el monitor también funciona sin ellos usando sondeo o el backend
nativo de `ReadDirectoryChangesW` en Windows.

## 2. Compilar

```powershell
.\packaging\build.ps1
```

o, de forma explícita:

```powershell
.\packaging\build.ps1 -Configuration Release -OneFile
```

Si PowerShell bloquea scripts locales:

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\build.ps1
```

El resultado por defecto es `dist\sentinel.exe` (un único archivo). El script
limpia `build/` y `dist/`, genera `build/manifest.json` con los hashes SHA-256
de `sentinel/data`, ejecuta PyInstaller con `packaging/sentinel.spec`, comprueba
que el exe existe y lanza `dist\sentinel.exe --version` como smoke test.
Cualquier fallo termina con `throw` y código de salida distinto de cero.

El manifiesto (y su firma si se configura `SENTINEL_PRIVATE_KEY`) se empaqueta
dentro de `sentinel/data`. En modo `-OneFile:$false` se puede verificar con:

```powershell
sentinel integrity verify _internal\sentinel\data `
  --manifest _internal\sentinel\data\manifest.json `
  --public-key _internal\sentinel\data\signatures.json.pub
```

| Parámetro | Efecto |
| --- | --- |
| `-Configuration Release` (por defecto) | Compilación normal (`--log-level INFO`). |
| `-Configuration Debug` | Añade `--debug` y `--log-level DEBUG`. |
| `-OneFile` (por defecto) | Genera `dist\sentinel.exe`. |
| `-OneFile:$false` | Modo directorio: `dist\sentinel\sentinel.exe`. |
| `-Console` | Compila **con** consola visible (por defecto, sin consola). |
| `-Sign` | Firma el exe con Authenticode (ver sección 3). |

Variables de entorno admitidas (las fija el script):

* `SENTINEL_PYTHON`: ruta al intérprete si `python` no está en el `PATH`.
* `SENTINEL_ONEFILE`: `1` (por defecto) o `0` en el spec.
* `SENTINEL_CONSOLE`: `0` (por defecto) o `1` en el spec.
* `SENTINEL_TIMESTAMP_URL`: servidor de sello de tiempo para la firma.
* `SENTINEL_SIGNTOOL_PATH`: ruta explícita a `signtool.exe`.
* `SENTINEL_CERT_THUMBPRINT` / `SENTINEL_CERT_SUBJECT`: selectores del certificado.
* `SENTINEL_PRIVATE_KEY`: clave privada Ed25519 para firmar el manifiesto de datos.

También puedes compilar con consola editando el valor por defecto de `CONSOLE`
en `sentinel.spec`, o ejecutando directamente:

```powershell
$env:SENTINEL_CONSOLE = '1'
pyinstaller --noconfirm --clean packaging/sentinel.spec
```

En el modo sin consola (por defecto), PyInstaller deja `sys.stdout` y
`sys.stderr` a `None` en Windows. El runtime hook generado los redirige a
`NUL`, de modo que el smoke test valida el **código de salida** (0), pero no
muestra el texto de `--version`. Usa `-Console` si quieres ver esa salida.

## 3. Firma con certificado EV/OV

Instala el certificado en el almacén personal de Windows (para EV, el token
debe estar conectado; el PIN se solicitará interactivamente). No guardes la
contraseña ni el `.pfx` en el repositorio: el script solo selecciona el
certificado por subject o por huella.

```powershell
# Opción A: por nombre de sujeto
$env:SENTINEL_CERT_SUBJECT = "Mi Organización S.L."

# Opción B: por huella SHA-1 (tiene prioridad si ambas están definidas)
$env:SENTINEL_CERT_THUMBPRINT = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"

# Opcional: servidor de sello de tiempo
$env:SENTINEL_TIMESTAMP_URL = "http://timestamp.digicert.com"

.\packaging\build.ps1 -Sign
```

El script invoca:

```text
signtool sign /fd SHA256 /tr <timestamp> /td SHA256 (/n <subject> | /sha1 <thumbprint>) dist\sentinel.exe
```

El sello de tiempo es importante: mantiene la firma válida después de que
caduque el certificado. Para comprobar el resultado:

```powershell
signtool verify /pa /v dist\sentinel.exe
```

Ten en cuenta que un ejecutable recién firmado puede mostrar avisos de
SmartScreen hasta que acumule reputación; eso es independiente de que la firma
sea válida.

Con un certificado **autofirmado de prueba** la firma se aplica y se sella en
el tiempo, pero `signtool verify /pa` falla con «root not trusted» mientras la
CA no sea de confianza: es esperable. En este entorno se validó la cadena
completa añadiendo temporalmente el certificado al almacén `Root` de
`CurrentUser` con `certutil -user -addstore -f Root prueba.cer`;
`signtool verify /pa /v dist\sentinel.exe` devolvió `Successfully verified`
(1 archivo, 0 errores). El certificado se retiró justo después con
`certutil -user -delstore Root <thumbprint>` y se comprobó que no seguía en el
almacén. Para producción usa un certificado EV/OV de una CA pública: **no
confíes un certificado de prueba en un equipo real**. El procedimiento completo
de emisión, firma y reglas de AppLocker/WDAC está en
`docs/EV_OV_HANDOFF.md`.

## 4. Símbolos (PDB) opcionales

PyInstaller no crea un PDB nuevo: solo puede arrastrar los `.pdb` que ya
existan en tu instalación de Python y dependencias. Si necesitas símbolos para
depurar:

```powershell
.\packaging\build.ps1 -Configuration Debug -OneFile:$false -Console
```

En modo directorio (`-OneFile:$false`) es más sencillo conservar los PDB
disponibles junto a `dist\sentinel\sentinel.exe`. En `onefile` quedan dentro
del paquete y no se entregan por separado. **No distribuyas los PDB con el
producto final**: guárdalos en tu servidor de símbolos o en almacenamiento
interno.

## 5. La firma del exe NO sustituye la verificación Ed25519

La firma Authenticode y la verificación Ed25519 de las firmas de IOCs son dos
controles distintos y complementarios:

* **Authenticode** demuestra que `sentinel.exe` no fue modificado y que
  proviene de tu organización (cadena de confianza de Windows).
* **Ed25519** demuestra que `signatures.json` fue emitido por quien posee la
  clave privada y que no es una versión antigua (control de revisión).

Un atacante podría sustituir la base de firmas aunque el exe esté
correctamente firmado. Por tanto, en producción hay que actualizar siempre con
la clave pública de confianza:

```powershell
sentinel signatures update --url https://ejemplo.local/signatures.json --public-key public.pem
```

La clave privada Ed25519 **nunca** se incluye en el paquete ni en el exe.
La firma del binario no habilita ni sustituye este paso.

## 6. Solución de problemas

* `No se encontró sentinel/data/signatures.json`: el spec exige ese archivo;
  comprueba que ejecutas el script desde cualquier directorio pero con el
  proyecto íntegro en `C:\Users\marco\Mine\sentinel`.
* Avisos de `Hidden import ... not found`: son esperables para dependencias
  opcionales (`yara`, `watchdog`, `pywin32`, etc.) no instaladas en el entorno
  de compilación. Instala el extra correspondiente si quieres esa función en
  el exe.
* Si el smoke test falla en modo sin consola, recompila con `-Console` para ver
  el error real.
* Para usar otro intérprete: `$env:SENTINEL_PYTHON = "C:\ruta\.venv\Scripts\python.exe"`.

## Funciones disponibles en el exe

El ejecutable incluye el backend nativo de vigilancia (`ReadDirectoryChangesW`
vía `ctypes`), así que en Windows no necesita `watchdog` ni `pywin32` para
`sentinel monitor`. Las notificaciones usan un toast si se instala `winotify`
en el entorno de compilación; si no, se usa un cuadro de mensaje nativo. Para
instalar el servicio **desde el exe** no hace falta instalar el extra `service`
(`pywin32`) en el equipo de destino: el spec incluye los módulos necesarios.
Ese extra solo es necesario al ejecutar Sentinel desde Python o si el build se
hizo sin `pywin32` instalado. Sí se requiere elevación administrativa.

Verificación realizada en este entorno: `.\packaging\build.ps1 -Console -Sign`
generó `dist\sentinel.exe` (onefile, ~14 MB), aplicó una firma Authenticode de
prueba con sello de tiempo y el smoke test interno `--version` devolvió
`sentinel 0.1.0` con código de salida 0. La firma del manifiesto Ed25519 también
se validó en modo onedir. El exe incluye `pywin32`, así que soporta el servicio
(aunque instalarlo requiere elevación).

Limitación observada: al ejecutar el exe recién compilado desde una sesión
posterior, **Device Guard/Application Control lo bloqueó** por provenir de una CA
autofirmada no confiable (`cmd` devuelve 4551). Confiar el certificado en los
almacenes del usuario no fue suficiente. No es un fallo del spec ni de la firma:
para producción usa un certificado EV/OV reconocido por Windows. Las pruebas
funcionales finales se ejecutaron con la CLI de Python.
